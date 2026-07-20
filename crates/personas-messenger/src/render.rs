//! Headless rendering: the accepted log as `petname(claimed): msg` lines
//! (workstream **d4**).
//!
//! The plan's M5 headless UI renders `petname(persona): message`, revocation
//! visible in the log, and a persona identicon (a later stretch — this is text
//! first). The important guarantees are honest ones, not cosmetic:
//!
//! - **A persona is never mistaken for an attributed messenger sender.** A pseudonym
//!   renders as its petname with a `~` sigil so it reads as a *cryptographic
//!   persona*, not a Signal account name (`SERVERLESS_PROTOCOL.md`, the UI-changes
//!   note in the plan: "distinct 'cryptographic persona' chrome").
//! - **The rendering gate is visible.** A post the replica later learns is from a
//!   since-banned persona is re-rendered **flagged**, not deleted (§5.4/§9) — the
//!   flag tells the truth about what the replica knew and when; deletion would be a
//!   covert-fork signal.
//! - **A failed proof never reaches here.** `Replica` only logs `Applied` records,
//!   so anything rendered has verified; nothing rendered is a persona a proof did
//!   not establish.

use personas_bulletin::replica::record::PollKind;
use personas_bulletin::replica::tally::{BAN_OPTION, Derived, KEEP_OPTION, LogEntry, Poll};

/// The sigil marking a pseudonymous author, so a persona petname is never read as a
/// messenger account name.
pub const PERSONA_SIGIL: &str = "~";
/// Shown in the author slot of an anonymous post.
pub const ANON_LABEL: &str = "(anonymous)";
/// Prefixes a post the replica later flagged as coming from a banned persona (§9).
pub const FLAG_PREFIX: &str = "⚠ [revoked persona] ";

/// Render the accepted chat log as display lines: one per post, in canonical order.
///
/// Scans, joins, and other non-post records are protocol machinery, not chat, so
/// they are omitted here — call [`render_entry`] directly if a debug view wants them.
pub fn render_log(log: &[LogEntry]) -> Vec<String> {
    log.iter().filter_map(render_entry).collect()
}

/// Render a single log entry, or `None` if it is not a chat post (a scan).
pub fn render_entry(entry: &LogEntry) -> Option<String> {
    if entry.kind != "Post" {
        return None;
    }
    let author = match &entry.author {
        Some(petname) => format!("{PERSONA_SIGIL}{petname}"),
        None => ANON_LABEL.to_string(),
    };
    let flag = if entry.flagged { FLAG_PREFIX } else { "" };
    Some(format!("{flag}{author}: {}", entry.body))
}

/// Render the open and recently-closed polls as status lines, newest tally first.
///
/// Read-only: this displays the tally the replica already derived (§8); it does not
/// decide anything. Ban polls show `bans/keeps`; ordinary polls show per-option
/// counts.
pub fn render_polls(derived: &Derived) -> Vec<String> {
    let mut lines: Vec<String> = derived
        .polls
        .iter()
        .map(|(eh, poll)| poll_line(eh, poll))
        .collect();
    // Deterministic display order (the map iterates arbitrarily): by poll id.
    lines.sort();
    lines
}

fn poll_line(eh: &personas_bulletin::replica::record::Eh, poll: &Poll) -> String {
    let id = &eh.to_string()[..12.min(eh.to_string().len())];
    let state = if poll.closed { "closed" } else { "open" };
    match poll.kind {
        PollKind::Ban => {
            let (yes, no) = poll.ban_tally();
            let verdict = if poll.closed {
                if yes > no { " → BANNED" } else { " → kept" }
            } else {
                ""
            };
            format!(
                "[poll {id} · ban · {state}] {} — {yes} ban / {no} keep{verdict}",
                poll.question
            )
        }
        PollKind::Standard => {
            let counts = poll.counts();
            let tally: Vec<String> = poll
                .options
                .iter()
                .enumerate()
                .map(|(i, opt)| format!("{opt}: {}", counts.get(&(i as u32)).copied().unwrap_or(0)))
                .collect();
            format!(
                "[poll {id} · {state}] {} — {}",
                poll.question,
                tally.join(", ")
            )
        }
    }
}

/// The two ban-poll option labels a client should offer, so a member's vote maps to
/// the [`BAN_OPTION`]/[`KEEP_OPTION`] the tally counts.
pub fn ban_poll_options() -> Vec<String> {
    let mut v = vec![String::new(); 2];
    v[BAN_OPTION as usize] = "ban".to_string();
    v[KEEP_OPTION as usize] = "keep".to_string();
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use personas_bulletin::replica::record::Eh;

    fn post(author: Option<&str>, body: &str, flagged: bool) -> LogEntry {
        LogEntry {
            eh: Eh([0; 32]),
            kind: "Post",
            author: author.map(|s| s.to_string()),
            body: body.to_string(),
            flagged,
        }
    }

    #[test]
    fn a_pseudonym_renders_with_the_persona_sigil() {
        let line = render_entry(&post(Some("brave-otter"), "hello", false)).unwrap();
        assert_eq!(line, "~brave-otter: hello");
    }

    #[test]
    fn an_anonymous_post_has_no_persona() {
        let line = render_entry(&post(None, "shh", false)).unwrap();
        assert_eq!(line, "(anonymous): shh");
    }

    #[test]
    fn a_flagged_post_is_marked_not_dropped() {
        let line = render_entry(&post(Some("calm-lynx"), "old news", true)).unwrap();
        assert!(
            line.starts_with(FLAG_PREFIX),
            "flagged, not deleted: {line}"
        );
        assert!(line.contains("old news"));
    }

    #[test]
    fn scans_are_omitted_from_the_chat_view() {
        let scan = LogEntry {
            eh: Eh([1; 32]),
            kind: "Scan",
            author: None,
            body: String::new(),
            flagged: false,
        };
        assert_eq!(render_entry(&scan), None);
        assert!(render_log(std::slice::from_ref(&scan)).is_empty());
    }
}
