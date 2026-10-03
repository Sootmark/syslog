# syslog

Linux syslog files (`/var/log/syslog`, `messages`, `auth.log`, `secure`, `kern.log`, …) as rsyslog, syslog-ng and sysklogd write them, and what sshd, sudo, su, cron and the account tools recorded in them. One dependency, its sibling `sootmark-common` (times).

```toml
[dependencies]
sootmark-syslog = "0.1"
```

```rust
let context = syslog::Context { modified: Some(file_modified) };
let parsed = syslog::parse(&std::fs::read("/var/log/auth.log")?, context);
for entry in &parsed.entries {
    if let Some(event) = syslog::auth::classify(entry) {
        println!("{:?} {} {:?} from {:?}", entry.time, event.action, event.user, event.source_ip);
    }
}
```

## What you get

- `parse(bytes, context)`: every entry, each line read on its own in one of three formats:
  - **classic** (`Mar 11 22:55:31 host sshd[3]: …`): no year and no time zone. The time is a wall-clock time in the host's unknown zone, never passed off as UTC. The year is inferred and marked: lines are in order, so it goes up when the month goes back, and the last line is dated in the year the file was last modified (`Context::modified`). Without that, times are left unset and the text kept. A date that doesn't exist in the inferred year (Feb 29) is kept untimed and reported.
  - **RFC 3339** (rsyslog's high-precision default, `2020-05-31T00:00:45.698463+00:00 host …`), in UTC; ChromeOS's severity word in place of the host is kept as `level`.
  - **RFC 5424** (`<14>1 2021-03-06T04:07:38+00:00 host app procid msgid [sd] msg`): priority (facility and severity), message id, structured data skipped.
- Host, program, pid and message; lines without a host or a tag are read too; continuation lines are joined to their message. A line that looks like a timestamp but isn't one is reported in `problems`, never fatal.
- `auth::classify(entry)`: sshd logins, failed logins (invalid user flagged), invalid users, connections and disconnects, with the account, address (IPv6 normalised), port, method and key fingerprint; sudo (account, target, command), su, cron commands, PAM sessions opened, and accounts added, deleted, changed (group membership) and passwords changed. `auth::classify_message(program, message)` does the same for messages read elsewhere, such as the systemd journal.

Not yet: syslog's network forward format written to a file.

## How it's checked

- plaso's syslog test files (Apache-2.0, `tests/fixtures/plaso/`), as plaso's own tests expect them: entry and problem counts for every format, field values, the year rolling over where plaso's does, multi-line messages, and every sshd and cron field plaso checks.
- Unit tests for sudo, su, PAM and the account tools.
- Property tests: arbitrary bytes and real lines damaged anywhere give entries or problems, never a panic.

## Licence

MIT or Apache-2.0, at your option. The test files are plaso's, under the Apache licence 2.0.
