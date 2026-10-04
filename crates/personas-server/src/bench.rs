//! Benchmark instrumentation, as the `bench/*.py` harness expects to find it.
//!
//! The client stamps the start of an operation before it sends; the server closes the
//! interval when the message lands. The file paths and field names are a wire format the
//! Python harness reads — `personas_core::timing` owns them.
//!
//! One behaviour change: a missing start-time stamp no longer fails the request. The old
//! handlers answered `409 Conflict` if `json_files/<label>/start_time.json` was absent, which
//! made posting with anything other than the benchmarked client — curl, a test, the mock
//! transport — an error. Instrumentation that cannot measure something should not prevent it
//! from happening.

use std::time::SystemTime;

use personas_core::timing::{append_timing_line_with_filename, load_start_time};

/// Close the end-to-end latency interval the client opened for `label`.
pub fn close_latency(label: &str) {
    let Ok(start) = load_start_time(label) else {
        tracing::debug!("no benchmark start time for {label}; not timing this request");
        return;
    };

    let Ok(elapsed) = start.elapsed() else {
        tracing::warn!("benchmark start time for {label} is in the future; clock skew?");
        return;
    };

    if let Err(e) =
        append_timing_line_with_filename(label, start, elapsed.as_millis(), "features")
    {
        tracing::warn!("could not write the latency timing for {label}: {e}");
    }
}

/// Record how long proof verification took.
pub fn verified(label: &str, start: SystemTime, millis: u128) {
    if let Err(e) = append_timing_line_with_filename(label, start, millis, "verify") {
        tracing::warn!("could not write the verify timing for {label}: {e}");
    }
}

/// Record how long invoking a callback took.
pub fn called(label: &str, start: SystemTime, millis: u128) {
    if let Err(e) = append_timing_line_with_filename(label, start, millis, "call") {
        tracing::warn!("could not write the call timing for {label}: {e}");
    }
}

/// Record how long an epoch update took.
pub fn epoch_updated(start: SystemTime, millis: u128) {
    if let Err(e) = append_timing_line_with_filename("rep", start, millis, "epoch") {
        tracing::warn!("could not write the epoch timing: {e}");
    }
}

/// Time an operation, returning what it produced and how long it took.
pub fn time<T>(f: impl FnOnce() -> T) -> (T, SystemTime, u128) {
    let start = SystemTime::now();
    let out = f();
    let millis = start.elapsed().map(|d| d.as_millis()).unwrap_or_default();
    (out, start, millis)
}
