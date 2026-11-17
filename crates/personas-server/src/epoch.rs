//! The epoch clock: the server turns its epoch on a public schedule, and on nothing else.
//!
//! The analyzed protocol's epochs are publicly computable, `epoch(now) = floor((now -
//! start) / length)`, from a published start and length (`PERSONAS_EPOCH_START`,
//! `PERSONAS_EPOCH_SECS`, a day by default). This used to be a route, `GET /api/epoch`,
//! that anyone could call, with no authentication: turning the epoch rotates the Privacy
//! Pass issuer key, so any caller could expire every unredeemed ticket. The route is gone.
//! A background task wakes at each boundary and turns the epoch, and `/api/get_epoch`
//! publishes the schedule so a client can check the server keeps to it.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use ark_ff::PrimeField;
use personas_core::schedule::{EpochSchedule, now_unix};

use crate::bench;
use crate::error::AppResult;
use crate::routes::privpass::{RotationCause, rotate_ticket_key};
use crate::state::{ServerLock, ServerState};

/// Where the server keeps the start it picked when none was configured.
const START_FILE: &str = "epoch_start";

/// The most epochs a start-up catch-up will turn. A day-long epoch reaches this in
/// thousands of years; a schedule that needs more is a misconfiguration (a start in
/// milliseconds, a one-second epoch from 1970), and turning that many times would only
/// look like a hang.
const MAX_CATCH_UP: u64 = 1_000_000;

/// The schedule this server keeps: the configured start, or else the server's first start,
/// persisted in `data_dir` so it survives restarts.
pub fn resolve_schedule(
    configured_start: Option<u64>,
    length: u64,
    data_dir: &Path,
) -> Result<EpochSchedule> {
    let start = match configured_start {
        Some(start) => {
            tracing::info!("epoch 0 starts at unix {start} (configured)");
            start
        }
        None => {
            let path = data_dir.join(START_FILE);
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    let start = text.trim().parse::<u64>().with_context(|| {
                        format!("{} does not hold unix seconds", path.display())
                    })?;
                    tracing::info!(
                        "epoch 0 starts at unix {start} (no PERSONAS_EPOCH_START; read from {})",
                        path.display()
                    );
                    start
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let start = now_unix();
                    std::fs::create_dir_all(data_dir)?;
                    std::fs::write(&path, format!("{start}\n"))
                        .with_context(|| format!("could not write {}", path.display()))?;
                    tracing::warn!(
                        "no PERSONAS_EPOCH_START: epoch 0 starts now, at unix {start}; \
                         saved to {} and kept across restarts",
                        path.display()
                    );
                    start
                }
                Err(e) => return Err(e).with_context(|| format!("could not read {}", path.display())),
            }
        }
    };
    let schedule = EpochSchedule::new(start, length);
    tracing::info!(
        "epochs last {length} s; the schedule puts us in epoch {}",
        schedule.current()
    );
    Ok(schedule)
}

/// The bulletin's epoch, as an integer.
pub fn bulletin_epoch(st: &ServerState) -> u64 {
    crate::bulletin::epoch(&st.db).into_bigint().as_ref()[0]
}

/// Bring the bulletin up to the schedule: turn it as many times as it is behind, then
/// rotate the ticket key once if the rotation log has no key for this epoch yet.
///
/// Turning `n` times rather than setting the epoch directly is what the route used to do,
/// one turn per call, and it is the only way zk-callbacks lets the epoch move: each turn
/// re-signs the nonmembership ranges, so after a restart (an empty callback bulletin, A1)
/// a catch-up of `n` turns costs `n` cheap signatures and ends in the same state a server
/// that had stayed up would be in. The key rotates once, not `n` times: the `n - 1`
/// intermediate keys would never be served, and one rotation per boundary crossed is
/// what a client checks for (at most one).
///
/// Returns how many times the epoch turned. Called at start-up and at each boundary,
/// always under the state write lock.
pub fn catch_up(st: &mut ServerState) -> AppResult<u64> {
    let target = st.schedule.current();
    let from = bulletin_epoch(st);
    let behind = target.saturating_sub(from);
    if behind > MAX_CATCH_UP {
        return Err(anyhow::anyhow!(
            "the schedule (start {}, {} s epochs) is {behind} epochs ahead of the bulletin; \
             refusing to turn that many times — check PERSONAS_EPOCH_START/_SECS",
            st.schedule.start,
            st.schedule.length
        )
        .into());
    }

    let mut rng = rand::thread_rng();
    for _ in 0..behind {
        let (_, start, millis) = bench::time(|| st.db.callback_bul.update_epoch(&mut rng));
        bench::epoch_updated(start, millis);
    }
    if st.privpass.rotations.last_turn() < Some(target) {
        rotate_ticket_key(st, RotationCause::Epoch(target))?;
    }
    if behind > 0 {
        tracing::info!("epoch turned {from} → {target}");
    }
    Ok(behind)
}

/// How long until unix time `at`, to the millisecond.
fn until(at: u64) -> Duration {
    let target = UNIX_EPOCH + Duration::from_secs(at);
    target
        .duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO)
}

/// Wake at each epoch boundary and turn the epoch.
///
/// Sleeps on the wall clock's idea of the next boundary and then re-reads the clock, so a
/// clock that jumps (NTP, a suspended VM) is caught up at the next wake rather than
/// trusted; a wake that comes early turns nothing and sleeps again.
pub fn spawn(state: ServerLock) {
    tokio::spawn(async move {
        loop {
            let next = {
                let st = state.read().await;
                st.schedule.boundary(st.schedule.current() + 1)
            };
            // Capped so a clock moved backwards is noticed within a minute.
            tokio::time::sleep(until(next).min(Duration::from_secs(60))).await;
            let mut st = state.write().await;
            if let Err(e) = catch_up(&mut st) {
                tracing::error!("could not turn the epoch: {e}");
            }
        }
    });
}
