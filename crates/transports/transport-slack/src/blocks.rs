//! Block Kit layouts for the three things the personas layer posts: a persona message, a
//! standard poll, and a ban poll.
//!
//! # Why the poll has no buttons
//!
//! Block Kit could render one button per option, and the as-a-service server did exactly
//! that. But a vote in this system is proof-carrying — the voter proves they are an
//! unbanned member voting under a pseudonym derived from the poll's context — and a button
//! press carries no proof. The old server papered over that by spawning the `slack-client`
//! binary on every press, which meant every click voted as the one shared identity that
//! happened to live next to the server.
//!
//! Worse, the press itself is a deanonymization channel: it tells the server "Slack user U
//! clicked" *before* the pseudonymous proof arrives, so correlating the two by timing links
//! the pseudonym to the Slack account. That is precisely what the pseudonym exists to
//! prevent. So a poll renders as a *readable* message that shows its own id, and the member
//! votes from their own client, from their own machine, with their own key.

use slack_morphism::prelude::*;
use transport_api::{Poll, PollKind};

/// The button under a persona post that says "this was good".
pub const ACTION_FEEDBACK_POSITIVE: &str = "feedback_positive";
/// The button under a persona post that says "this was bad".
pub const ACTION_FEEDBACK_NEGATIVE: &str = "feedback_negative";

/// A persona's message, with the 👍/👎 feedback buttons under it.
///
/// These buttons stay, unlike the poll's. A rating is not a vote: it needs no proof, it is
/// tallied server-side against the callback the poster already committed to, and it reveals
/// only that a reader liked a post whose author is *already* a persona. Nothing about the
/// author's identity leaks by pressing it. (It is also the only rating path that works on
/// mobile clients that hide the reaction picker.)
pub fn persona_post(body: &str) -> SlackMessageContent {
    SlackMessageContent::new()
        .with_text(body.to_string())
        .with_blocks(slack_blocks![
            some_into(SlackSectionBlock::new().with_text(md!(body.to_string()))),
            some_into(SlackDividerBlock::new()),
            some_into(SlackActionsBlock::new(slack_blocks![
                some_into(
                    SlackBlockButtonElement::new(
                        SlackActionId(ACTION_FEEDBACK_POSITIVE.into()),
                        pt!("👍 Good Response")
                    )
                    .with_value("positive".into())
                ),
                some_into(
                    SlackBlockButtonElement::new(
                        SlackActionId(ACTION_FEEDBACK_NEGATIVE.into()),
                        pt!("👎 Bad Response")
                    )
                    .with_value("negative".into())
                )
            ])),
            some_into(SlackContextBlock::new(slack_blocks![some(md!(
                "Rate this response contribute to anonymous user reputation."
            ))]))
        ])
}

/// A poll, rendered as a question, its options, and the id you need in order to vote on it.
///
/// `body` is the [`Outgoing`](transport_api::Outgoing) body, which a ban poll uses as the
/// quoted text of the message under review and a standard poll ignores (its question block
/// already carries the text).
pub fn poll(poll: &Poll, body: &str) -> SlackMessageContent {
    let mut blocks = vec![SlackBlock::Header(SlackHeaderBlock {
        block_id: Some(SlackBlockId(poll.id.clone())),
        text: SlackBlockPlainTextOnly::from(SlackBlockPlainText::new(poll.question.clone())),
    })];

    if poll.kind == PollKind::Ban {
        // The moderation path: the group votes on revoking a persona. The message under
        // review is quoted, and its timestamp printed rather than left implicit, because a
        // voter is judging one specific post and the tally is what `AllowedToRevoke` will
        // later be asked to honour — the vote has to be attributable to a message a client
        // can independently look up.
        blocks.push(SlackBlock::Markdown(SlackMarkdownBlock {
            block_id: Some(SlackBlockId(format!("markdown_{}", poll.id))),
            text: body.to_string(),
        }));

        let target = poll
            .target
            .as_ref()
            .map(|t| t.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        blocks.push(SlackBlock::Context(SlackContextBlock {
            block_id: Some(SlackBlockId(format!("msg_ts_{}", poll.id))),
            elements: vec![SlackContextBlockElement::MarkDown(
                SlackBlockMarkDownText::new(format!(
                    ":hourglass_flowing_sand: *Timestamp of Message to Ban User:* {target}"
                )),
            )],
        }));
    }

    blocks.push(SlackBlock::Divider(SlackDividerBlock { block_id: None }));

    blocks.push(SlackBlock::Section(
        SlackSectionBlock::new().with_text(md!(options_list(poll))),
    ));

    blocks.push(SlackBlock::Context(SlackContextBlock {
        block_id: Some(SlackBlockId(format!("howto_{}", poll.id))),
        elements: vec![SlackContextBlockElement::MarkDown(
            SlackBlockMarkDownText::new(how_to_vote(poll)),
        )],
    }));

    SlackMessageContent::new()
        .with_text(poll.question.clone())
        .with_blocks(blocks)
}

fn options_list(poll: &Poll) -> String {
    poll.options
        .iter()
        .map(|opt| format!("• *{opt}*"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The poll id has to be *on screen*. It used to live only in a hidden `block_id`, which was
/// fine when a button press carried it back; now it is the handle a member types into their
/// own client, so a poll that doesn't show it cannot be voted on at all.
fn how_to_vote(poll: &Poll) -> String {
    format!(
        ":ballot_box_with_ballot: Poll id: `{}` — vote from your own client:\n\
         `personas slack-vote -i {} -v <option>`\n\
         _Your vote is a zero-knowledge proof, so it is cast from your machine, not by \
         clicking here._",
        poll.id, poll.id
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport_api::MessageId;

    fn a_poll(kind: PollKind) -> Poll {
        Poll {
            id: "vote_1739".into(),
            question: "Ban this user?".into(),
            options: vec!["Yes".into(), "No".into()],
            kind,
            target: Some(MessageId("1699999999.0001".into())),
        }
    }

    /// The regression this whole redesign exists to prevent.
    #[test]
    fn a_poll_renders_no_buttons() {
        for kind in [PollKind::Standard, PollKind::Ban] {
            let content = poll(&a_poll(kind), "the message under review");
            let blocks = content.blocks.expect("a poll has blocks");
            assert!(
                !blocks
                    .iter()
                    .any(|b| matches!(b, SlackBlock::Actions(_))),
                "a vote must not be castable by pressing a Slack button"
            );
        }
    }

    #[test]
    fn a_poll_shows_the_id_a_member_needs_to_vote() {
        let rendered = format!("{:?}", poll(&a_poll(PollKind::Standard), ""));
        assert!(
            rendered.contains("vote_1739"),
            "the poll id must be visible, not hidden in a block_id"
        );
    }

    #[test]
    fn a_persona_post_keeps_its_feedback_buttons() {
        let content = persona_post("hello");
        let blocks = content.blocks.expect("a post has blocks");
        assert!(
            blocks.iter().any(|b| matches!(b, SlackBlock::Actions(_))),
            "rating a post needs no proof, so the buttons stay"
        );
    }
}
