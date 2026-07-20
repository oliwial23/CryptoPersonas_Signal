//! The route table.
//!
//! **Every path here is load-bearing and none may be renamed.** The `bench/*.py` harness
//! drives the client, the client hardcodes these paths, and the two are how the paper's
//! numbers were produced. The handlers behind them have been rewritten; the paths have not
//! moved.
//!
//! They are grouped by what they do rather than by which messenger they belong to, because
//! the messenger turned out not to be a real distinction — `/api/x` and `/api/slack/x` differ
//! in which [`Channel`](crate::state::Channel) they touch and nothing else.

pub mod context;
pub mod interact;
pub mod moderation;
pub mod params;
pub mod polls;
pub mod post;

use axum::Router;
use axum::routing::{get, post as post_route};
use tower_http::limit::RequestBodyLimitLayer;

use crate::state::ServerLock;

pub fn router(state: ServerLock) -> Router {
    // A folded Nova proof is megabytes, so this one route lifts axum's default 2 MB cap.
    let folded_scan = Router::new()
        .route("/api/interact/foldscan", post_route(interact::fold_scan))
        .layer(RequestBodyLimitLayer::new(100 * 1024 * 1024));

    Router::new()
        .merge(folded_scan)
        // -- proving keys -------------------------------------------------------------
        .route(
            "/api/interaction/standard/proving_key",
            get(params::standard),
        )
        .route(
            "/api/interaction/standard/pseudo/proving_key",
            get(params::standard_pseudo),
        )
        .route(
            "/api/interaction/standard/pseudor/proving_key",
            get(params::standard_pseudor),
        )
        .route("/api/interaction/scan/proving_key", get(params::scan))
        .route("/api/interaction/fold/proving_key", get(params::fold))
        .route(
            "/api/interaction/fold/pre_proving_key",
            get(params::fold_pre),
        )
        .route(
            "/api/interaction/badge/request/proving_key",
            get(params::badge_request),
        )
        .route(
            "/api/user/arbitrary_pred_proving_key",
            get(params::pseudonym_pred),
        )
        .route(
            "/api/user/arbitrary_pred_proving_key2",
            get(params::authorship_pred),
        )
        .route(
            "/api/user/arbitrary_pred_proving_key3",
            get(params::badge_pred),
        )
        // -- the bulletin -------------------------------------------------------------
        .route("/api/user/pubkey", get(params::user_pubkey))
        .route("/api/user/bulletin", get(params::user_bulletin))
        .route("/api/user/join", post_route(interact::join))
        .route(
            "/api/callbacks/membership_pubkey",
            get(params::membership_pubkey),
        )
        .route(
            "/api/callbacks/nonmembership_pubkey",
            get(params::nonmembership_pubkey),
        )
        .route("/api/callbacks/bulletin", get(params::callback_bulletin))
        .route(
            "/api/callbacks/nmemb_bulletin",
            get(params::callback_nmemb_bulletin),
        )
        .route("/api/get_epoch", get(params::get_epoch))
        // -- interactions that do not relay -------------------------------------------
        .route("/api/interact/standard", post_route(interact::standard))
        .route("/api/interact/scan", post_route(interact::scan))
        .route(
            "/api/interact/arbitrary_pred",
            post_route(interact::arbitrary_pred),
        )
        // -- posting, over Signal ------------------------------------------------------
        .route("/api/jsonrpc", post_route(post::signal_anon))
        .route("/api/jsonrpc/pseudo", post_route(post::signal_pseudo))
        .route(
            "/api/jsonrpc/pseudo/rate",
            post_route(post::signal_pseudo_rate),
        )
        .route("/api/reply", post_route(post::signal_reply))
        .route("/api/reply/pseudo", post_route(post::signal_reply_pseudo))
        .route("/api/react", post_route(post::signal_react))
        .route("/api/authorship", post_route(post::signal_authorship))
        .route("/api/badges", post_route(post::signal_badges))
        // -- posting, over Slack -------------------------------------------------------
        .route("/api/slack/post/anon", post_route(post::slack_anon))
        .route("/api/slack/post/pseudo", post_route(post::slack_pseudo))
        .route(
            "/api/slack/post/pseudo/rate",
            post_route(post::slack_pseudo_rate),
        )
        .route("/api/slack/react", post_route(post::slack_react))
        .route(
            "/api/slack/request/badges",
            post_route(post::slack_request_badge),
        )
        .route(
            "/api/slack/claim/badges",
            post_route(post::slack_claim_badge),
        )
        .route(
            "/api/slack/claim/authorship",
            post_route(post::slack_authorship),
        )
        // -- polls ---------------------------------------------------------------------
        .route("/api/poll", post_route(polls::signal_poll))
        .route("/api/banpoll", post_route(polls::signal_ban_poll))
        .route("/api/vote", post_route(polls::signal_vote))
        .route("/api/votecount", post_route(polls::signal_count_votes))
        .route("/api/context", post_route(polls::signal_poll_context))
        .route("/api/slack/poll", post_route(polls::slack_poll))
        .route("/api/slack/banpoll", post_route(polls::slack_ban_poll))
        .route(
            "/api/slack/poll/context",
            post_route(polls::slack_poll_context),
        )
        .route(
            "/api/slack/poll/results",
            post_route(polls::slack_poll_results),
        )
        .route("/api/slack/vote", post_route(polls::slack_vote))
        // -- invoking callbacks --------------------------------------------------------
        .route("/api/ban", post_route(moderation::ban))
        .route("/api/reputation", post_route(moderation::reputation))
        .route(
            "/api/slack/reputation",
            post_route(moderation::slack_reputation),
        )
        .route("/api/approve/badge", post_route(moderation::approve_badge))
        .route("/api/epoch", get(moderation::update_epoch))
        .route("/api/cb", post_route(moderation::callback_for))
        .route("/api/slack_cb", post_route(moderation::slack_callback_for))
        .route("/api/cb/signal/all", get(moderation::pending_signal))
        .route("/api/cb/slack/all", get(moderation::pending_slack))
        .route("/api/cb/badge/requests", get(moderation::pending_badges))
        // -- thread contexts -----------------------------------------------------------
        .route(
            "/api/pseudo/new_thread_context",
            post_route(context::signal_new_thread),
        )
        .route(
            "/api/pseudo/get_all_contexts",
            get(context::signal_contexts),
        )
        .route(
            "/api/slack/pseudo/new_thread_context",
            post_route(context::slack_new_thread),
        )
        .route(
            "/api/slack/pseudo/get_all_contexts",
            get(context::slack_contexts),
        )
        .with_state(state)
}
