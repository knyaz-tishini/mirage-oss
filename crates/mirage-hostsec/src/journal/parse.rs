//! Pure parsers for sshd auth log messages.
//!
//! No `cfg` gate — compiles and tests on every target, including Windows.
//! Feed it the raw MESSAGE field from `journalctl -o cat` or any sshd log
//! line; it returns [`Some(AuthFailure)`] / [`Some(AuthSuccess)`] on a
//! recognised pattern and `None` for anything else (wrong kind, malformed IPs,
//! garbage).

use std::net::IpAddr;
use std::str::FromStr;

/// Classification of the authentication failure reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFailKind {
    /// `Failed password for <user> from <ip>` — valid existing user.
    FailedPassword,
    /// `Failed password for invalid user <u> from <ip>`
    /// or `Invalid user <u> from <ip>` — username not in passwd.
    InvalidUser,
    /// `Failed publickey for <user> from <ip>`.
    FailedPublickey,
}

/// A single sshd authentication failure event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFailure {
    /// Source address of the remote client.
    pub ip: IpAddr,
    /// What kind of failure occurred.
    pub kind: AuthFailKind,
    /// The username that was attempted, when present in the log line.
    pub user: Option<String>,
}

/// Parse a single sshd log line and extract auth failure information.
///
/// Recognised message shapes (case-sensitive, matching standard OpenSSH):
/// - `Failed password for <user> from <ip> port <n> ssh2`
/// - `Failed password for invalid user <user> from <ip> port ...`
/// - `Invalid user <user> from <ip> port ...`
/// - `Failed publickey for <user> from <ip> port ...`
///
/// Returns `None` for:
/// - Lines that do not contain any of these patterns.
/// - Lines where the token after ` from ` does not parse as a valid [`IpAddr`].
/// - Accepted/disconnected/informational lines.
///
/// The parser is tolerant of a leading timestamp/hostname prefix (e.g. from
/// `journalctl` without `-o cat`) by scanning for keywords anywhere in the line.
pub fn parse_auth_failure(msg: &str) -> Option<AuthFailure> {
    // Identify the failure kind and locate the "for <user>" segment.
    let (kind, after_for) = classify_and_split(msg)?;

    // SECURITY (misdirected-ban defense): the banned IP MUST be sshd's
    // structured peer field, never a substring of the attacker-controlled
    // username. sshd always appends `from <ip> port <n>` AFTER the username, so
    // a malicious username like `evil from 8.8.8.8 port 22 ssh2` embeds a fake
    // `from <ip>` that appears BEFORE the real suffix. We therefore scan the
    // WHOLE line and take the LAST `from <ip>` whose token parses AND is
    // followed by `port <digits>` (sshd's canonical structured field). The fake
    // loses because it is not last. Without this, an attacker picks which IP we
    // ban — a self-DoS that the fleet-collaborative block then amplifies.
    let ip = extract_peer_ip(msg)?;

    // `user` is best-effort metadata ONLY (attacker-controlled, never used for a
    // ban decision). Take the first token of the username segment.
    let user = after_for
        .split_whitespace()
        .next()
        .filter(|s| !s.is_empty() && *s != "from")
        .map(str::to_owned);

    Some(AuthFailure { ip, kind, user })
}

/// Extract the SSH client's real source IP from an sshd auth line.
///
/// Scans every ` from ` occurrence and keeps the LAST one whose next token is a
/// valid [`IpAddr`] followed by sshd's canonical ` port <digits>` field. This is
/// the structured peer address sshd appends after the (attacker-controlled)
/// username, so a `from <fake-ip> port <n>` embedded in a username cannot win.
/// Falls back to the last valid `from <ip>` with no port only if no canonical
/// match exists (tolerates exotic/old log formats — the real peer is still last).
fn extract_peer_ip(msg: &str) -> Option<IpAddr> {
    const MARKER: &str = " from ";
    let mut search = 0usize;
    let mut last_with_port: Option<IpAddr> = None;
    let mut last_any: Option<IpAddr> = None;
    while let Some(rel) = msg[search..].find(MARKER) {
        let abs = search + rel + MARKER.len();
        let mut toks = msg[abs..].split_whitespace();
        if let Some(ip_tok) = toks.next() {
            if let Ok(ip) = IpAddr::from_str(ip_tok) {
                last_any = Some(ip);
                let has_port = matches!(toks.next(), Some("port"))
                    && toks
                        .next()
                        .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
                if has_port {
                    last_with_port = Some(ip);
                }
            }
        }
        search = abs;
    }
    last_with_port.or(last_any)
}

/// Classify the line and return the slice starting just after "for " or "user ".
fn classify_and_split(msg: &str) -> Option<(AuthFailKind, &str)> {
    // "Failed password for ..." — covers both valid-user and invalid-user variants.
    if let Some(rest) = find_after(msg, "Failed password for ") {
        // Distinguish "Failed password for invalid user <u>" from "Failed password for <u>".
        if let Some(after_invalid) = find_after(rest, "invalid user ") {
            return Some((AuthFailKind::InvalidUser, after_invalid));
        }
        return Some((AuthFailKind::FailedPassword, rest));
    }

    // "Invalid user <u> from ..."
    if let Some(rest) = find_after(msg, "Invalid user ") {
        return Some((AuthFailKind::InvalidUser, rest));
    }

    // "Failed publickey for <u> from ..."
    if let Some(rest) = find_after(msg, "Failed publickey for ") {
        return Some((AuthFailKind::FailedPublickey, rest));
    }

    None
}

/// Return the slice of `haystack` that starts immediately after the first
/// occurrence of `needle`, or `None` if not found.
fn find_after<'a>(haystack: &'a str, needle: &str) -> Option<&'a str> {
    haystack
        .find(needle)
        .map(|pos| &haystack[pos + needle.len()..])
}

// ── auth-success parser ───────────────────────────────────────────────────────

/// Classification of a successful SSH authentication event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthSuccessKind {
    /// `Accepted publickey for <user> from <ip> ...`
    AcceptedPublickey,
    /// `Accepted password for <user> from <ip> ...`
    AcceptedPassword,
}

/// A single sshd authentication success event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSuccess {
    /// Source address of the remote client (injection-safe: always the
    /// structured peer field sshd appends, never a substring of the username).
    pub ip: IpAddr,
    /// What kind of success occurred.
    pub kind: AuthSuccessKind,
    /// The username as logged by sshd.  Best-effort — attacker-controlled and
    /// NOT security-load-bearing; the IP and key fingerprint are.
    pub user: Option<String>,
    /// The key fingerprint (`SHA256:…`) for publickey auth, `None` for
    /// password auth or when the fingerprint token is absent.
    pub key_fingerprint: Option<String>,
}

/// Parse a single sshd log line and extract auth-success information.
///
/// Recognised shapes (standard OpenSSH):
/// - `Accepted publickey for <user> from <ip> port <n> ssh2: <keytype> SHA256:<fp>`
/// - `Accepted password for <user> from <ip> port <n> ssh2`
///
/// Returns `None` for:
/// - Lines that do not start with `Accepted publickey` or `Accepted password`
///   (anywhere in the line, tolerating a leading journalctl timestamp prefix).
/// - Lines where no valid IP can be extracted.
/// - Failure / informational / garbage lines.
///
/// IP extraction reuses [`extract_peer_ip`] — the same injection-safe scan
/// used by [`parse_auth_failure`] — so a malicious username embedding a fake
/// `from <ip> port <n>` cannot misdirect the reported source address.
pub fn parse_auth_success(msg: &str) -> Option<AuthSuccess> {
    // Determine kind and locate the slice after "for ".
    let (kind, after_for) = classify_success(msg)?;

    // IP: injection-safe, reuse the same extractor as parse_auth_failure.
    let ip = extract_peer_ip(msg)?;

    // User: best-effort first token before the first " from ".
    // A malicious username may contain " from "; we stop at the first one.
    // This is intentionally best-effort — never used for a security decision.
    let user = after_for
        .find(" from ")
        .map(|pos| &after_for[..pos])
        .unwrap_or(after_for)
        .split_whitespace()
        .next()
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    // Key fingerprint: find "SHA256:" anywhere in the line, take the token.
    let key_fingerprint = if kind == AuthSuccessKind::AcceptedPublickey {
        msg.find("SHA256:")
            .map(|pos| {
                msg[pos..]
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_owned()
            })
            .filter(|s| !s.is_empty())
    } else {
        None
    };

    Some(AuthSuccess { ip, kind, user, key_fingerprint })
}

/// Classify a success line and return the slice immediately after "for ".
fn classify_success(msg: &str) -> Option<(AuthSuccessKind, &str)> {
    if let Some(rest) = find_after(msg, "Accepted publickey for ") {
        return Some((AuthSuccessKind::AcceptedPublickey, rest));
    }
    if let Some(rest) = find_after(msg, "Accepted password for ") {
        return Some((AuthSuccessKind::AcceptedPassword, rest));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn failed_password_valid_user() {
        let r = parse_auth_failure("Failed password for root from 192.0.2.5 port 51122 ssh2")
            .expect("should parse");
        assert_eq!(r.ip, v4(192, 0, 2, 5));
        assert_eq!(r.kind, AuthFailKind::FailedPassword);
        assert_eq!(r.user.as_deref(), Some("root"));
    }

    #[test]
    fn failed_password_invalid_user() {
        let r = parse_auth_failure(
            "Failed password for invalid user admin from 203.0.113.9 port 4 ssh2",
        )
        .expect("should parse");
        assert_eq!(r.ip, v4(203, 0, 113, 9));
        assert_eq!(r.kind, AuthFailKind::InvalidUser);
        assert_eq!(r.user.as_deref(), Some("admin"));
    }

    #[test]
    fn invalid_user_form() {
        let r = parse_auth_failure("Invalid user oracle from 198.51.100.7 port 2222")
            .expect("should parse");
        assert_eq!(r.ip, v4(198, 51, 100, 7));
        assert_eq!(r.kind, AuthFailKind::InvalidUser);
        assert_eq!(r.user.as_deref(), Some("oracle"));
    }

    #[test]
    fn failed_publickey() {
        let r =
            parse_auth_failure("Failed publickey for deploy from 192.0.2.10 port 1 ssh2")
                .expect("should parse");
        assert_eq!(r.ip, v4(192, 0, 2, 10));
        assert_eq!(r.kind, AuthFailKind::FailedPublickey);
        assert_eq!(r.user.as_deref(), Some("deploy"));
    }

    #[test]
    fn ipv6_case() {
        let r = parse_auth_failure("Failed password for root from 2001:db8::1 port 22 ssh2")
            .expect("should parse ipv6");
        assert_eq!(r.ip, v6("2001:db8::1"));
        assert_eq!(r.kind, AuthFailKind::FailedPassword);
    }

    #[test]
    fn accepted_password_is_none() {
        assert!(
            parse_auth_failure("Accepted password for root from 192.0.2.5 port 5 ssh2").is_none(),
            "accepted auth must not produce a failure event"
        );
    }

    #[test]
    fn garbage_line_is_none() {
        assert!(parse_auth_failure("totally random syslog garbage here").is_none());
    }

    #[test]
    fn non_ip_token_is_none() {
        assert!(
            parse_auth_failure("Failed password for root from notanip port 1 ssh2").is_none(),
            "non-parseable IP must return None"
        );
    }

    #[test]
    fn line_with_leading_timestamp_prefix() {
        // journalctl without -o cat may prepend "Jun 27 12:34:56 hostname sshd[123]:"
        let line = "Jun 27 12:34:56 myhost sshd[4321]: Failed password for ubuntu from 10.0.0.1 port 2049 ssh2";
        let r = parse_auth_failure(line).expect("should parse through prefix");
        assert_eq!(r.ip, v4(10, 0, 0, 1));
        assert_eq!(r.kind, AuthFailKind::FailedPassword);
        assert_eq!(r.user.as_deref(), Some("ubuntu"));
    }

    #[test]
    fn empty_line_is_none() {
        assert!(parse_auth_failure("").is_none());
    }

    // ── misdirected-ban injection defense ──────────────────────────────────

    #[test]
    fn username_embedding_fake_from_does_not_misdirect_ban() {
        // Attacker SSHes with username `evil from 8.8.8.8 port 22 ssh2`.
        // sshd logs the fake (from the username) THEN its real structured
        // suffix `from <real-ip> port <n>`. We must ban the REAL peer, not 8.8.8.8.
        let line = "Failed password for invalid user evil from 8.8.8.8 port 22 ssh2 \
                    from 203.0.113.66 port 44321 ssh2";
        let r = parse_auth_failure(line).expect("should parse");
        assert_eq!(r.ip, v4(203, 0, 113, 66), "must ban sshd's real peer, not the username-embedded IP");
        assert_ne!(r.ip, v4(8, 8, 8, 8));
    }

    #[test]
    fn username_embedding_fake_from_no_port_loses_to_real() {
        // Fake `from 1.2.3.4` with no `port` field, real suffix has port.
        let line = "Failed password for invalid user x from 1.2.3.4 from 198.51.100.9 port 22 ssh2";
        let r = parse_auth_failure(line).expect("should parse");
        assert_eq!(r.ip, v4(198, 51, 100, 9));
    }

    #[test]
    fn multiple_fake_froms_real_is_last() {
        let line = "Failed password for invalid user a from 1.1.1.1 from 2.2.2.2 \
                    from 192.0.2.200 port 1 ssh2";
        let r = parse_auth_failure(line).expect("should parse");
        assert_eq!(r.ip, v4(192, 0, 2, 200));
    }

    // ── parse_auth_success tests ──────────────────────────────────────────────

    #[test]
    fn accepted_publickey_full_line() {
        let line = "Accepted publickey for deploy from 203.0.113.10 port 54321 ssh2: ED25519 SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abc";
        let r = parse_auth_success(line).expect("should parse publickey success");
        assert_eq!(r.ip, v4(203, 0, 113, 10));
        assert_eq!(r.kind, AuthSuccessKind::AcceptedPublickey);
        assert_eq!(r.user.as_deref(), Some("deploy"));
        assert_eq!(
            r.key_fingerprint.as_deref(),
            Some("SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abc")
        );
    }

    #[test]
    fn accepted_password_success() {
        let line = "Accepted password for alice from 198.51.100.7 port 1024 ssh2";
        let r = parse_auth_success(line).expect("should parse password success");
        assert_eq!(r.ip, v4(198, 51, 100, 7));
        assert_eq!(r.kind, AuthSuccessKind::AcceptedPassword);
        assert_eq!(r.user.as_deref(), Some("alice"));
        assert!(r.key_fingerprint.is_none(), "password auth has no fingerprint");
    }

    #[test]
    fn accepted_publickey_injection_real_ip_wins() {
        // Attacker uses username containing a fake "from <ip> port <n>" to
        // misdirect the peer — the real sshd-appended suffix must win.
        let line = r#"Accepted publickey for "evil from 8.8.8.8 port 22 ssh2" from 203.0.113.5 port 40000 ssh2: ED25519 SHA256:abc"#;
        let r = parse_auth_success(line).expect("should parse");
        assert_eq!(
            r.ip,
            v4(203, 0, 113, 5),
            "must report sshd's real peer, not the username-embedded IP"
        );
        assert_ne!(r.ip, v4(8, 8, 8, 8));
    }

    #[test]
    fn failed_password_does_not_match_success() {
        let line = "Failed password for root from 192.0.2.5 port 51122 ssh2";
        assert!(
            parse_auth_success(line).is_none(),
            "failure line must not produce an AuthSuccess"
        );
    }

    #[test]
    fn plain_garbage_success_is_none() {
        assert!(parse_auth_success("totally random garbage line").is_none());
    }
}
