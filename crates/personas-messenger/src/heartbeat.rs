//! The settlement-heartbeat **cadence** (workstream **d5**).
//!
//! d3 built the barrier *mechanism* ([`Replica::advance_to`](personas_bulletin::replica::Replica)
//! settles due tickets, closes ban polls, re-pins the callback root) but deliberately
//! left it clock-free — "a barrier is an event, not a clock tick" (`D3_REPLICA_ENGINE.md`
//! §4). d5 is the clock: it decides *which barrier a record belongs to* and *when a
//! replica has reached a barrier*, from a shared time reference.
//!
//! # Why a shared reference, and which one
//!
//! Two replicas that ingest the same records must agree on each record's settlement
//! barrier, or they settle its ticket at different times and their callback roots fork
//! (`SERVERLESS_PROTOCOL.md` §5.2's determinism caveat). If each replica bucketed a
//! record by *its own* wall clock at the moment it happened to receive it, ordinary
//! delivery jitter across a barrier boundary would fork honest replicas.
//!
//! So the bucket is a function of the **service-assigned** receive timestamp
//! ([`Incoming::received_at`](transport_api::Incoming) — Signal's
//! `serverReceivedTimestamp`), which the provider stamps once and delivers identically
//! to every recipient. Every replica computes the identical record→barrier map, so the
//! convergence is **exact**. Crucially this is *not* the sender-set message id (§4): a
//! member cannot forge the provider's stamp, so it cannot backdate a record into an old
//! barrier. The stamp is only ever a coarse settlement clock — never the ordering
//! mechanism (that is prefix-order, §4) and never an input to proof acceptance.
//!
//! The one thing that still reads a *local* clock is [`Messenger::tick`](crate::Messenger::tick):
//! advancing "how far has *now* got" so tickets settle even with no traffic. That only
//! moves a monotone counter; it never re-assigns a record's bucket, so a skewed local
//! clock settles late at worst (bounded by `W`, self-healing), never at a barrier a peer
//! disagrees with (§5.2(a)).

/// The default settlement-barrier cadence in seconds (`SERVERLESS_PROTOCOL.md` §14,
/// `heartbeat_secs`).
pub const DEFAULT_HEARTBEAT_SECS: u64 = 60;

/// Maps service-assigned receive timestamps to barrier indices — the shared schedule
/// every replica in a group buckets records against (§14).
///
/// Two parameters, both shared across the group (like the genesis pin, established at
/// group creation and carried out of band):
///
/// - `genesis_ms`: the group's time anchor in milliseconds since the Unix epoch; barrier
///   0 begins here. Making buckets *relative* to an anchor keeps barrier indices small —
///   an absolute `ms / period` would be tens of millions, and the engine's rebuild loops
///   over `0..=current_barrier`.
/// - `period_ms`: one barrier's width, `heartbeat_secs * 1000`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Heartbeat {
    genesis_ms: u64,
    period_ms: u64,
}

impl Heartbeat {
    /// A heartbeat anchored at `genesis_ms` with barrier width `period_ms`. A zero
    /// period is clamped to 1 ms so bucketing never divides by zero.
    pub fn new(genesis_ms: u64, period_ms: u64) -> Self {
        Self {
            genesis_ms,
            period_ms: period_ms.max(1),
        }
    }

    /// A heartbeat with the cadence given in whole seconds (§14's `heartbeat_secs`).
    pub fn from_secs(genesis_ms: u64, heartbeat_secs: u64) -> Self {
        Self::new(genesis_ms, heartbeat_secs.saturating_mul(1000))
    }

    /// The barrier a message with service timestamp `received_at_ms` falls in.
    /// Saturating below the anchor so a stray pre-genesis stamp lands in barrier 0
    /// rather than underflowing.
    pub fn barrier_at(&self, received_at_ms: u64) -> u64 {
        received_at_ms.saturating_sub(self.genesis_ms) / self.period_ms
    }

    /// One barrier's width in milliseconds — what a wall-clock driver ticks on.
    pub fn period_ms(&self) -> u64 {
        self.period_ms
    }
}

impl Default for Heartbeat {
    /// Anchored at the epoch with the §14 default cadence. Suitable for tests and the
    /// in-process demo, which feed small `received_at` values; a live group sets a real
    /// `genesis_ms` so barrier indices stay small.
    fn default() -> Self {
        Self::from_secs(0, DEFAULT_HEARTBEAT_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_relative_to_the_anchor_and_period() {
        let hb = Heartbeat::new(1_000, 60_000);
        assert_eq!(hb.barrier_at(1_000), 0, "the anchor is barrier 0");
        assert_eq!(hb.barrier_at(60_999), 0, "still within the first period");
        assert_eq!(hb.barrier_at(61_000), 1, "one period on");
        assert_eq!(hb.barrier_at(181_000), 3);
    }

    #[test]
    fn pre_genesis_and_zero_period_do_not_panic() {
        let hb = Heartbeat::new(10_000, 0); // clamped to 1 ms
        assert_eq!(hb.barrier_at(5_000), 0, "a pre-anchor stamp saturates to 0");
        assert_eq!(hb.barrier_at(10_003), 3);
    }

    #[test]
    fn from_secs_matches_millis() {
        assert_eq!(Heartbeat::from_secs(0, 60), Heartbeat::new(0, 60_000));
    }
}
