//! Slack speaks in shortnames (`thumbsup`), the personas layer speaks in emoji (👍).
//!
//! `reactions.add` takes a *name*, never a codepoint, so every rating that reaches Slack
//! has to be translated. The table below is the one the as-a-service server has always
//! used (`emoji_to_slack_name` in `crypto_personas/server/src/helpers.rs`), lifted here
//! because it is Slack trivia and nothing above the transport should have to know it.
//!
//! The five entries are not arbitrary: 👍/👎 are the reputation signal, 🤬 flags hate
//! speech, and ❌/✅ are the ban-poll votes. Everything else is passed through untouched
//! if it already looks like a Slack name, so a caller can react with `:tada:` without this
//! crate having to know what `tada` is.

/// The Slack reaction name for an emoji, a Slack shortname, or one of the server's
/// legacy command words (`upvote`, `downvote`, `hatespeech`, `ban`, `not ban`).
///
/// `None` means "we have no idea what this is" — better to fail the send than to post the
/// literal string `unknown`, which is what the old handler did and which Slack rejects
/// with `invalid_name` anyway.
pub fn slack_reaction_name(emoji: &str) -> Option<String> {
    let emoji = emoji.trim();

    // Thumbs arrive with skin-tone modifiers appended (👍🏽), so match on the prefix.
    if emoji.starts_with('👍') {
        return Some("thumbsup".to_string());
    }
    if emoji.starts_with('👎') {
        return Some("thumbsdown".to_string());
    }

    let mapped = match emoji {
        "🤬" | "hatespeech" => Some("face_with_symbols_on_mouth"),
        "❌" | "ban" => Some("x"),
        "✅" | "not ban" | "no ban" => Some("white_check_mark"),
        "upvote" => Some("thumbsup"),
        "downvote" => Some("thumbsdown"),
        _ => None,
    };
    if let Some(name) = mapped {
        return Some(name.to_string());
    }

    // `:tada:` and `tada` are both already Slack's own vocabulary — and so is `+1`, which
    // is the name Slack itself reports for 👍 in `reaction_added` events, so a reaction
    // this crate emits can be handed straight back to `react()`.
    let bare = emoji.trim_matches(':');
    let is_slack_name = !bare.is_empty()
        && bare
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | ':'));
    is_slack_name.then(|| bare.to_string())
}

#[cfg(test)]
mod tests {
    use super::slack_reaction_name;

    #[test]
    fn maps_the_reputation_signals() {
        assert_eq!(slack_reaction_name("👍").as_deref(), Some("thumbsup"));
        assert_eq!(slack_reaction_name("👍🏽").as_deref(), Some("thumbsup"));
        assert_eq!(slack_reaction_name("👎").as_deref(), Some("thumbsdown"));
        assert_eq!(slack_reaction_name("❌").as_deref(), Some("x"));
    }

    #[test]
    fn round_trips_slack_names() {
        assert_eq!(slack_reaction_name("+1").as_deref(), Some("+1"));
        assert_eq!(slack_reaction_name(":tada:").as_deref(), Some("tada"));
        assert_eq!(slack_reaction_name("🦀"), None);
    }
}
