//! Benchmark instrumentation, written to `json_files/<label>/*.jsonl`.
//!
//! Shared by the client and the server because an end-to-end latency spans both: the
//! client stamps [`save_start_time`] before it sends, and the server calls
//! [`load_start_time`] when the message lands to close the interval. The `bench/*.py`
//! harness reads the resulting `.jsonl` files, so the paths and field names here are
//! a wire format — do not rename them casually.

use serde_json::json;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn label_dir(label: &str) -> String {
    format!("json_files/{}", label)
}

fn append_line(label: &str, filename: &str, line: String) -> std::io::Result<()> {
    let dir = label_dir(label);
    fs::create_dir_all(&dir)?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(format!("{}/{}", dir, filename))?;

    writeln!(file, "{}", line)
}

fn millis_since_epoch(t: SystemTime) -> u128 {
    t.duration_since(UNIX_EPOCH)
        .expect("system clock is before the UNIX epoch")
        .as_millis()
}

/// Stamps the start of an operation that finishes on the other side of the network.
pub fn save_start_time(label: &str) -> std::io::Result<()> {
    let start_ms = millis_since_epoch(SystemTime::now());
    fs::create_dir_all(label_dir(label))?;
    fs::write(
        format!("{}/start_time.json", label_dir(label)),
        json!({ "start_ms": start_ms }).to_string(),
    )
}

/// Reads back the instant recorded by [`save_start_time`].
pub fn load_start_time(label: &str) -> std::io::Result<SystemTime> {
    let path = format!("{}/start_time.json", label_dir(label));
    let contents = fs::read_to_string(path)?;
    let val: serde_json::Value = serde_json::from_str(&contents)?;
    let start_ms = val["start_ms"].as_u64().expect("start_ms must be a u64");
    Ok(UNIX_EPOCH + Duration::from_millis(start_ms))
}

/// Appends a timing to `json_files/<label>/<filename>_timings.jsonl`.
pub fn append_timing_line_with_filename(
    label: &str,
    start: SystemTime,
    duration_ms: u128,
    filename: &str,
) -> std::io::Result<()> {
    let line = json!({
        "start_ms": millis_since_epoch(start),
        "duration_ms": duration_ms,
    })
    .to_string();

    append_line(label, &format!("{}_timings.jsonl", filename), line)
}

/// Appends a timing to `json_files/<label>/timings.jsonl`.
pub fn append_timing_line(
    label: &str,
    start: SystemTime,
    duration_ms: u128,
) -> std::io::Result<()> {
    let line = json!({
        "start_ms": millis_since_epoch(start),
        "duration_ms": duration_ms,
    })
    .to_string();

    append_line(label, "timings.jsonl", line)
}

/// Appends a timing tagged with the fold width `n`, so fold cost can be plotted
/// against the number of callbacks folded per step.
pub fn append_timing_line_fold(
    label: &str,
    start: SystemTime,
    duration_ms: u128,
    num_scans: usize,
    file_suffix: &str,
) -> std::io::Result<()> {
    let line = json!({
        "start_ms": millis_since_epoch(start),
        "duration_ms": duration_ms,
        "n": num_scans,
    })
    .to_string();

    append_line(label, &format!("{}_timings.jsonl", file_suffix), line)
}

/// Appends the size of a folded proof and of the payload carrying it.
pub fn append_proof_size_fold(
    label: &str,
    proof_size: usize,
    payload_size: usize,
    num_scans: usize,
    file_suffix: &str,
) -> std::io::Result<()> {
    let line = json!({
        "proof_size": proof_size,
        "payload_size": payload_size,
        "n": num_scans,
    })
    .to_string();

    append_line(label, &format!("{}.jsonl", file_suffix), line)
}
