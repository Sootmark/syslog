//! Linux syslog files: `/var/log/syslog`, `messages`, `auth.log`, `secure`,
//! `kern.log` and the like, as rsyslog, syslog-ng and sysklogd write them.
//!
//! Three line formats are read, each line on its own:
//!
//! - **classic** (RFC 3164 style): `Mar 11 22:55:31 host sshd[3]: message`.
//!   No year and no time zone: the time is a wall-clock time in the host's
//!   zone, unknown here. The year is inferred: lines are in order, so the
//!   year goes up whenever the month goes back, and the last line is dated
//!   in the year the file was last modified ([`Context::modified`]); without
//!   that the time is left unset, the text kept. An inferred year is marked
//!   on the entry.
//! - **RFC 3339** (rsyslog's high-precision default):
//!   `2020-05-31T00:00:45.698463+00:00 host systemd[1]: message`; ChromeOS
//!   writes a severity where the host would be.
//! - **RFC 5424**: `<14>1 2021-03-06T04:07:38.251280+00:00 host app procid
//!   msgid [structured data] message`.
//!
//! A line that starts with white space continues the previous message, as
//! does, in files of the two later formats, any line without a timestamp. A
//! classic line that can't be read is reported in `problems`, never fatal.
//!
//! [`auth`] tells what sshd, sudo, su, cron and the account tools recorded.

use std::net::IpAddr;

use common::time::{days_from_civil, Precision, Ts};

pub mod auth;

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const TICKS_PER_SECOND: i64 = 10_000_000;
/// Words ChromeOS writes where the host would be.
const SEVERITY_WORDS: [&str; 8] = [
    "EMERG", "ALERT", "CRIT", "ERR", "ERROR", "WARNING", "NOTICE", "INFO",
];
const DEBUG: &str = "DEBUG";

/// What the file's metadata says, for what its lines don't.
#[derive(Debug, Clone, Copy, Default)]
pub struct Context {
    /// When the file was last modified (UTC): the year of its last classic
    /// line.
    pub modified: Option<Ts>,
}

/// A line's format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// `Mar 11 22:55:31 …`: no year, no zone.
    Classic,
    /// `2020-05-31T00:00:45.698463+00:00 …`.
    Rfc3339,
    /// `<14>1 2021-03-06T04:07:38+00:00 …`.
    Rfc5424,
}

/// One entry (a line, and the lines continuing it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Line number of its first line, from 1.
    pub line: usize,
    /// Byte offset of its first line.
    pub offset: u64,
    /// Its format.
    pub format: Format,
    /// When it was written: UTC for RFC 3339 and 5424; a wall-clock time in
    /// an unknown zone for classic lines, `None` when the year couldn't be
    /// inferred or the date doesn't exist in it.
    pub time: Option<Ts>,
    /// The time as written.
    pub time_text: String,
    /// Whether the year was inferred (classic lines).
    pub year_inferred: bool,
    /// `<PRI>`: facility × 8 + severity, when written.
    pub priority: Option<u8>,
    /// The host, when written.
    pub host: Option<String>,
    /// The program (the tag before `[pid]:` or `:`), when written.
    pub program: Option<String>,
    /// The process id, when written.
    pub pid: Option<u32>,
    /// A severity word written in place of the host (ChromeOS).
    pub level: Option<String>,
    /// RFC 5424's message id.
    pub message_id: Option<String>,
    /// The message (continuation lines joined with `\n`).
    pub message: String,
}

impl Entry {
    /// The facility, from the priority (`4` auth, `10` authpriv, …).
    #[must_use]
    pub fn facility(&self) -> Option<u8> {
        self.priority.map(|p| p >> 3)
    }

    /// The severity, from the priority (`0` emergency … `7` debug).
    #[must_use]
    pub fn severity(&self) -> Option<u8> {
        self.priority.map(|p| p & 7)
    }
}

/// A file's entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entries {
    /// Entries in file order.
    pub entries: Vec<Entry>,
    /// Lines that couldn't be read, and dates that don't exist.
    pub problems: Vec<String>,
}

/// A classic time before its year is known.
#[derive(Debug, Clone, Copy)]
struct Clock {
    month: u32,
    day: u32,
    seconds: i64,
    ticks: i64,
    precision: Precision,
}

/// Read a syslog file.
#[must_use]
pub fn parse(data: &[u8], context: Context) -> Entries {
    let text = String::from_utf8_lossy(data);
    let mut entries: Vec<Entry> = Vec::new();
    let mut clocks: Vec<(usize, Clock)> = Vec::new();
    let mut problems = Vec::new();
    let mut offset = 0u64;
    for (index, raw) in text.split('\n').enumerate() {
        let line_offset = offset;
        offset += raw.len() as u64 + 1;
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.trim().is_empty() {
            continue;
        }
        // A line without a timestamp continues the previous message, unless
        // it looks like a timestamp that isn't one.
        let continues = line.starts_with([' ', '\t'])
            || !entries.is_empty() && !starts_with_timestamp(line) && !malformed_timestamp(line);
        if continues {
            if let Some(last) = entries.last_mut() {
                last.message.push('\n');
                last.message.push_str(line);
                continue;
            }
        }
        let number = index + 1;
        if let Some(entry) =
            rfc5424(line, number, line_offset).or_else(|| rfc3339(line, number, line_offset))
        {
            entries.push(entry);
        } else if let Some((entry, clock)) = classic(line, number, line_offset) {
            clocks.push((entries.len(), clock));
            entries.push(entry);
        } else {
            problems.push(format!("line {number}: not a syslog line"));
        }
    }
    date_classic(&mut entries, &clocks, context, &mut problems);
    Entries { entries, problems }
}

fn starts_with_timestamp(line: &str) -> bool {
    let line = strip_priority(line).1;
    let line = line.strip_prefix("1 ").unwrap_or(line);
    rfc3339_time(line.split(' ').next().unwrap_or("")).is_some()
        || line.split(' ').next().is_some_and(|w| MONTHS.contains(&w))
}

/// `Xxx dd HH:MM:SS`, with a word that isn't a month: a damaged line, not
/// a continuation.
fn malformed_timestamp(line: &str) -> bool {
    let mut words = line.split(' ').filter(|w| !w.is_empty());
    let (Some(month), Some(day), Some(clock)) = (words.next(), words.next(), words.next()) else {
        return false;
    };
    let clock = clock.as_bytes();
    month.len() == 3
        && month.bytes().all(|b| b.is_ascii_alphabetic())
        && day.len() <= 2
        && day.bytes().all(|b| b.is_ascii_digit())
        && clock.len() >= 8
        && clock[2] == b':'
        && clock[5] == b':'
}

/// `<PRI>` at the start of a line: the priority and the rest.
fn strip_priority(line: &str) -> (Option<u8>, &str) {
    if let Some(rest) = line.strip_prefix('<') {
        if let Some((digits, after)) = rest.split_once('>') {
            if (1..=3).contains(&digits.len()) {
                if let Ok(priority) = digits.parse::<u8>() {
                    if priority <= 191 {
                        return (Some(priority), after);
                    }
                }
            }
        }
    }
    (None, line)
}

/// An RFC 3339 time as UTC microseconds.
fn rfc3339_time(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let number = |range: std::ops::Range<usize>| text.get(range)?.parse::<i64>().ok();
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    let mut rest = &text[19..];
    let mut micros = 0i64;
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        micros = format!("{:0<6}", &fraction[..digits])[..6].parse().ok()?;
        rest = &fraction[digits..];
    }
    let offset_minutes = match rest {
        "Z" | "z" => 0,
        _ => {
            let (sign, rest) = match rest.as_bytes().first()? {
                b'+' => (1, &rest[1..]),
                b'-' => (-1, &rest[1..]),
                _ => return None,
            };
            let (h, m) = rest.split_once(':')?;
            sign * (h.parse::<i64>().ok()? * 60 + m.parse::<i64>().ok()?)
        }
    };
    let month = u32::try_from(month).ok()?;
    let day = u32::try_from(day).ok()?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second
        - offset_minutes * 60;
    Some(seconds * 1_000_000 + micros)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn utc(micros: i64) -> Ts {
    Ts::from_unix_micros(micros)
}

fn empty(line: usize, offset: u64, format: Format, time_text: &str, priority: Option<u8>) -> Entry {
    Entry {
        line,
        offset,
        format,
        time: None,
        time_text: time_text.to_owned(),
        year_inferred: false,
        priority,
        host: None,
        program: None,
        pid: None,
        level: None,
        message_id: None,
        message: String::new(),
    }
}

/// `<PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG`, `-` for nothing.
fn rfc5424(line: &str, number: usize, offset: u64) -> Option<Entry> {
    let (priority, rest) = strip_priority(line);
    let rest = rest.strip_prefix("1 ")?;
    let mut fields = rest.splitn(6, ' ');
    let time_text = fields.next()?;
    let micros = rfc3339_time(time_text)?;
    let nil = |value: &str| (value != "-").then(|| value.to_owned());
    let host = nil(fields.next()?);
    let program = nil(fields.next()?);
    let pid = fields.next().and_then(|p| p.parse().ok());
    let message_id = nil(fields.next().unwrap_or("-"));
    let mut message = fields.next().unwrap_or("");
    // Structured data: `-`, or `[…]` elements up to the message.
    if let Some(after) = message.strip_prefix('-') {
        message = after;
    } else if message.starts_with('[') {
        message = skip_structured_data(message);
    }
    let mut entry = empty(number, offset, Format::Rfc5424, time_text, priority);
    entry.time = Some(utc(micros));
    entry.host = host;
    entry.program = program;
    entry.pid = pid;
    entry.message_id = message_id;
    message.trim_start().clone_into(&mut entry.message);
    Some(entry)
}

fn skip_structured_data(text: &str) -> &str {
    let mut rest = text;
    while let Some(inner) = rest.strip_prefix('[') {
        let mut escaped = false;
        let mut in_quotes = false;
        let mut end = None;
        for (i, c) in inner.char_indices() {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_quotes = !in_quotes,
                ']' if !in_quotes => {
                    end = Some(i);
                    break;
                }
                _ => {}
            }
        }
        let Some(end) = end else { return "" };
        rest = &inner[end + 1..];
    }
    rest
}

/// `[<PRI>]TIMESTAMP [host|LEVEL] [tag[pid]:] message`.
fn rfc3339(line: &str, number: usize, offset: u64) -> Option<Entry> {
    let (priority, rest) = strip_priority(line);
    let (time_text, rest) = rest.split_once(' ').unwrap_or((rest, ""));
    let micros = rfc3339_time(time_text)?;
    let mut entry = empty(number, offset, Format::Rfc3339, time_text, priority);
    entry.time = Some(utc(micros));
    tail(rest, &mut entry);
    Some(entry)
}

/// `Mmm dd HH:MM:SS[.fff] [host] [tag[pid]:] message`.
fn classic(line: &str, number: usize, offset: u64) -> Option<(Entry, Clock)> {
    let (priority, stamp) = strip_priority(line);
    let rest = stamp;
    let month = MONTHS.iter().position(|m| rest.starts_with(m))? as u32 + 1;
    let rest = rest.get(3..)?.strip_prefix(' ')?;
    let rest = rest.trim_start_matches(' ');
    let (day, rest) = rest.split_once(' ')?;
    let day: u32 = day.parse().ok().filter(|d| (1..=31).contains(d))?;
    // `HH:MM:SS`, then maybe `.fff`.
    let hms = rest.get(..8)?;
    let mut rest = &rest[8..];
    let mut fraction = "";
    if let Some(after) = rest.strip_prefix('.') {
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        fraction = &after[..digits];
        rest = &after[digits..];
    }
    let mut parts = hms.split(':');
    let hour: i64 = parts.next()?.parse().ok()?;
    let minute: i64 = parts.next()?.parse().ok()?;
    let second: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some()
        || hour > 23
        || minute > 59
        || second > 60
        || hms.as_bytes()[2] != b':'
        || hms.as_bytes()[5] != b':'
    {
        return None;
    }
    let (ticks, precision) = if fraction.is_empty() {
        (0, Precision::Second)
    } else {
        let digits = fraction.len().min(7);
        let ticks: i64 = format!("{:0<7}", &fraction[..digits]).parse().ok()?;
        (
            ticks,
            if digits > 3 {
                Precision::Microsecond
            } else {
                Precision::Millisecond
            },
        )
    };
    let time_text = stamp[..stamp.len() - rest.len()].to_owned();
    let mut entry = empty(number, offset, Format::Classic, &time_text, priority);
    entry.year_inferred = true;
    // `Mmm dd HH:MM:SS: message` (no host, no tag).
    if let Some(message) = rest.strip_prefix(':') {
        message.trim_start().clone_into(&mut entry.message);
    } else {
        tail(rest.strip_prefix(' ')?, &mut entry);
    }
    let clock = Clock {
        month,
        day,
        seconds: hour * 3_600 + minute * 60 + second,
        ticks,
        precision,
    };
    Some((entry, clock))
}

/// What follows the time: a host (or a severity word), a tag, the message.
fn tail(rest: &str, entry: &mut Entry) {
    let rest = rest.trim_start_matches(' ');
    let (first, after) = rest.split_once(' ').unwrap_or((rest, ""));
    if let Some((program, pid)) = tag(first) {
        entry.program = Some(program);
        entry.pid = pid;
        after.trim_start().clone_into(&mut entry.message);
        return;
    }
    if SEVERITY_WORDS.contains(&first) || first == DEBUG {
        entry.level = Some(first.to_owned());
    } else {
        entry.host = Some(first.to_owned());
    }
    let after = after.trim_start_matches(' ');
    let (second, message) = after.split_once(' ').unwrap_or((after, ""));
    if let Some((program, pid)) = tag(second) {
        entry.program = Some(program);
        entry.pid = pid;
        message.trim_start().clone_into(&mut entry.message);
    } else {
        after.clone_into(&mut entry.message);
    }
}

/// `program[pid]:` or `program:`.
fn tag(word: &str) -> Option<(String, Option<u32>)> {
    let word = word.strip_suffix(':')?;
    if word.is_empty() || word.contains([':', ' ']) {
        return None;
    }
    if let Some((program, pid)) = word.strip_suffix(']').and_then(|w| w.split_once('[')) {
        return (!program.is_empty()).then(|| (program.to_owned(), pid.parse().ok()));
    }
    (!word.contains(['[', ']'])).then(|| (word.to_owned(), None))
}

/// Give classic entries their year: it goes up when the month goes back,
/// and the last one is in the year the file was last modified.
fn date_classic(
    entries: &mut [Entry],
    clocks: &[(usize, Clock)],
    context: Context,
    problems: &mut Vec<String>,
) {
    let Some(modified) = context.modified.and_then(|m| m.to_iso8601()) else {
        return;
    };
    let (Ok(reference_year), Ok(reference_month)) =
        (modified[..4].parse::<i64>(), modified[5..7].parse::<u32>())
    else {
        return;
    };
    let mut relative = Vec::with_capacity(clocks.len());
    let mut year = 0i64;
    let mut previous: Option<u32> = None;
    for (_, clock) in clocks {
        if previous.is_some_and(|p| clock.month < p) {
            year += 1;
        }
        previous = Some(clock.month);
        relative.push(year);
    }
    let (Some(&last_relative), Some(last)) = (relative.last(), clocks.last()) else {
        return;
    };
    let last_year = if last.1.month <= reference_month {
        reference_year
    } else {
        reference_year - 1
    };
    for ((index, clock), rel) in clocks.iter().zip(relative) {
        let year = last_year - (last_relative - rel);
        let entry = &mut entries[*index];
        if clock.day > days_in_month(year, clock.month) {
            problems.push(format!(
                "line {}: {} isn't a date in {year} (the inferred year)",
                entry.line, entry.time_text
            ));
            continue;
        }
        let days = days_from_civil(year, clock.month, clock.day);
        entry.time = Some(Ts::from_local_ticks(
            (days * 86_400 + clock.seconds) * TICKS_PER_SECOND + clock.ticks,
            clock.precision,
        ));
    }
}

/// An address as written (`192.0.2.60`, IPv6 in any form), normalised.
pub(crate) fn address(text: &str) -> Option<String> {
    text.parse::<IpAddr>().ok().map(|a| a.to_string())
}
