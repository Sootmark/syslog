//! plaso's syslog test files (Apache-2.0, `tests/fixtures/plaso/`), read as
//! plaso's own tests expect: how many entries and unreadable lines, what
//! each field holds, where the year rolls over, and what sshd and cron
//! recorded. plaso counts years from 0; here the last line is dated in the
//! year the file was last modified, so the same rollovers fall on real
//! years.

use std::fs;
use std::path::Path;

use common::time::Ts;
use syslog::auth::classify;
use syslog::{parse, Context, Format};

fn read(name: &str) -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/plaso")
            .join(name),
    )
    .unwrap()
}

/// Modified at noon UTC on 2026-12-01.
fn december_2026() -> Context {
    Context {
        modified: Some(Ts::from_unix_seconds(1_796_126_400)),
    }
}

fn time(entry: &syslog::Entry) -> String {
    entry.time.and_then(|t| t.to_iso8601()).unwrap_or_default()
}

#[test]
fn counts_as_plaso() {
    for (name, entries, problems) in [
        ("syslog", 16, 2), // a damaged line; and Feb 29 in a year that has none
        ("syslog_ssh.log", 10, 0),
        ("syslog_sshd_session.log", 8, 0),
        ("syslog_cron.log", 9, 0),
        ("syslog_osx", 2, 0),
        ("syslog_rsyslog", 5, 0),
        ("syslog_rsyslog_traditional", 8, 0),
        ("syslog_rsyslog_SysklogdFileFormat", 9, 0),
        ("syslog_rsyslog_SyslogProtocol23Format", 9, 0),
        ("syslog_chromeos", 8, 0),
    ] {
        let parsed = parse(&read(name), december_2026());
        assert_eq!(parsed.entries.len(), entries, "{name}");
        assert_eq!(
            parsed.problems.len(),
            problems,
            "{name}: {:?}",
            parsed.problems
        );
    }
}

#[test]
fn classic_lines_and_inferred_years() {
    let parsed = parse(&read("syslog"), december_2026());
    let first = &parsed.entries[0];
    assert_eq!(first.format, Format::Classic);
    assert_eq!(first.host.as_deref(), Some("myhostname.myhost.com"));
    assert_eq!(
        (first.program.as_deref(), first.pid),
        (Some("client"), Some(30840))
    );
    assert_eq!(first.message, "INFO No new content in ímynd.dd.");
    assert!(first.year_inferred);
    // Wall-clock time, zone unknown: no `Z`.
    assert_eq!(time(first), "2023-01-22T07:52:33.0000000");
    // plaso's year 1: the month went back (December → March).
    let fraction = parsed
        .entries
        .iter()
        .find(|e| e.message.contains("fractional value"))
        .unwrap();
    assert_eq!(time(fraction), "2024-03-23T23:01:18.1230000");
    // A line starting with white space continues the message.
    let multi = parsed
        .entries
        .iter()
        .find(|e| e.message.starts_with("This is a multi-line"))
        .unwrap();
    assert!(
        multi.message.ends_with("\n\tmany syslog parsers."),
        "{:?}",
        multi.message
    );
    // No host, no tag; a tag but no host.
    let repeated = parsed
        .entries
        .iter()
        .find(|e| e.message.contains("last message repeated"))
        .unwrap();
    assert_eq!(
        (repeated.host.as_deref(), repeated.program.as_deref()),
        (None, None)
    );
    let kernel = parsed
        .entries
        .iter()
        .find(|e| e.message.contains("want=65"))
        .unwrap();
    assert_eq!(
        (kernel.host.as_deref(), kernel.program.as_deref()),
        (None, Some("kernel"))
    );
    // The last line is in the year the file was last modified.
    assert_eq!(
        time(parsed.entries.last().unwrap()),
        "2026-11-18T08:31:20.0000000"
    );
    // Feb 29 doesn't exist in the inferred year: kept, untimed, reported.
    let leap = parsed
        .entries
        .iter()
        .find(|e| e.message.contains("leap year"))
        .unwrap();
    assert_eq!(leap.time, None);
    assert_eq!(leap.time_text, "Feb 29 01:15:43");
    // Without the file's modification time, classic lines stay untimed.
    let undated = parse(&read("syslog"), Context::default());
    assert!(undated.entries.iter().all(|e| e.time.is_none()));
}

#[test]
fn sshd_as_plaso() {
    let parsed = parse(&read("syslog_ssh.log"), december_2026());
    let events: Vec<_> = parsed.entries.iter().map(classify).collect();
    assert_eq!(events[0], None, "Server listening");
    let login = events[1].as_ref().unwrap();
    assert_eq!(login.action, "ssh login");
    assert_eq!(
        (
            login.user.as_deref(),
            login.source_ip.as_deref(),
            login.port
        ),
        (Some("plaso"), Some("192.168.0.1"), Some(59229))
    );
    assert_eq!(login.method.as_deref(), Some("publickey"));
    assert_eq!(
        login.fingerprint.as_deref(),
        Some("RSA 00:aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99")
    );
    // IPv6, normalised.
    assert_eq!(
        events[2].as_ref().unwrap().source_ip.as_deref(),
        Some("2001:db8:a0b:12f0::1")
    );
    let failed = events[3].as_ref().unwrap();
    assert_eq!(
        (failed.action, failed.port),
        ("ssh failed login", Some(8759))
    );
    let connection = events[4].as_ref().unwrap();
    assert_eq!(
        (connection.action, connection.source_ip.as_deref()),
        ("ssh connection", Some("188.124.3.41"))
    );
    let password = events[5].as_ref().unwrap();
    assert_eq!(
        (
            password.user.as_deref(),
            password.method.as_deref(),
            password.invalid_user
        ),
        (Some("root"), Some("password"), false)
    );
    assert_eq!(
        events[8].as_ref().unwrap().fingerprint.as_deref(),
        Some("RSA SHA256:5xyQ+PG1Z3CIiShclJ2iNya5TOdKDgE/HrOXr21IdOo")
    );
    let invalid = events[9].as_ref().unwrap();
    assert_eq!(
        (invalid.user.as_deref(), invalid.invalid_user, invalid.port),
        (Some("admin"), true, Some(35932))
    );

    let session = parse(&read("syslog_sshd_session.log"), december_2026());
    let events: Vec<_> = session.entries.iter().map(classify).collect();
    assert_eq!(session.entries[0].program.as_deref(), Some("sshd-session"));
    assert_eq!(
        events[0].as_ref().map(|e| (e.action, e.user.as_deref())),
        Some(("ssh failed login", Some("svc-backup")))
    );
    assert_eq!(
        events[2].as_ref().map(|e| (e.action, e.user.as_deref())),
        Some(("ssh login", Some("svc-backup")))
    );
    assert_eq!(events[5], None, "Received disconnect: a plain entry");
    assert_eq!(
        events[6].as_ref().map(|e| (e.action, e.user.as_deref())),
        Some(("ssh disconnect", Some("root")))
    );
}

#[test]
fn cron_commands() {
    let parsed = parse(&read("syslog_cron.log"), december_2026());
    let event = classify(&parsed.entries[1]).unwrap();
    assert_eq!(
        (event.action, event.user.as_deref()),
        ("cron command", Some("root"))
    );
    assert_eq!(
        event.command.as_deref(),
        Some("sleep $(( 1 * 60 )); touch /tmp/afile.txt")
    );
}

#[test]
fn rfc3339_and_rfc5424() {
    let rsyslog = parse(&read("syslog_rsyslog"), Context::default());
    let first = &rsyslog.entries[0];
    assert_eq!(first.format, Format::Rfc3339);
    assert_eq!(time(first), "2020-05-31T00:00:45.6984630Z");
    assert_eq!(
        (first.host.as_deref(), first.program.as_deref()),
        (Some("localhost"), Some("rsyslogd"))
    );
    assert!(!first.year_inferred);

    let chromeos = parse(&read("syslog_chromeos"), Context::default());
    let first = &chromeos.entries[0];
    // -07:00, in UTC.
    assert_eq!(time(first), "2016-10-25T19:37:23.2972650Z");
    assert_eq!(
        (first.level.as_deref(), first.host.as_deref()),
        (Some("INFO"), None)
    );
    assert_eq!(
        (first.program.as_deref(), first.pid),
        (Some("periodic_scheduler"), Some(13707))
    );

    let protocol = parse(
        &read("syslog_rsyslog_SyslogProtocol23Format"),
        Context::default(),
    );
    let debug = &protocol.entries[0];
    assert_eq!(debug.format, Format::Rfc5424);
    assert_eq!((debug.facility(), debug.severity()), (Some(1), Some(7)));
    assert_eq!(
        (debug.host.as_deref(), debug.program.as_deref(), debug.pid),
        (Some("hostname"), Some("log_tag"), None)
    );
    assert_eq!(debug.message_id.as_deref(), Some("123"));
    assert_eq!(debug.message, "this is debug");
    assert_eq!(
        protocol.entries[1].message,
        "this is info\nwith another line"
    );
}

mod damage {
    use proptest::prelude::*;

    proptest! {
        /// Any bytes: entries or problems, never a panic.
        #[test]
        fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..2_000)) {
            let _ = syslog::parse(&data, super::december_2026());
        }

        /// Real lines, damaged anywhere.
        #[test]
        fn damaged_lines(flips in proptest::collection::vec((0usize..1_500, any::<u8>()), 1..20)) {
            let mut data = super::read("syslog");
            for (at, byte) in flips {
                let len = data.len();
                data[at % len] = byte;
            }
            let parsed = syslog::parse(&data, super::december_2026());
            for entry in &parsed.entries {
                let _ = syslog::auth::classify(entry);
            }
        }
    }
}
