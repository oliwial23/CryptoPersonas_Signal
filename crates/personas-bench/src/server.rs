//! `--server`: the same operations through the **server-based** implementation, with both
//! of its optimizations on — precomputed tickets (Privacy Pass) and folded scans — so the
//! two designs can be compared on one machine.
//!
//! This starts the real validation server (the `server` binary built beside this one, the
//! `local` profile: an in-process mock chat, no credentials) in a work directory, drives it
//! with the real client library (`personas-client`, what the `personas` CLI runs), and reads
//! back the timings both sides already write to `json_files/<label>/` (client proving,
//! server verification). It also times each HTTP round trip itself.
//!
//! Measured, per iteration:
//!
//!   post         prove each post: client proof, server verify, round trip
//!   pp_request   offline, per ticket: client proof, server verify + blind issuance,
//!                client unblind/verify of the issued ticket
//!   pp_post      redeem a ticket to post: client redemption, server check, round trip
//!   scan         answer K callbacks one proof at a time: per scan, client + server
//!   fold         answer the same K callbacks with one Nova-folded proof
//!
//! `--history N` first posts N proved messages from other members, so the server's
//! numbers are taken with N objects on its bulletin (they should not grow with it).
//!
//! `--server-url URL` drives a validation server that is already running instead of
//! starting one, which puts a real network between client and server. The server's own
//! timings are then on that server, so only the client's and the round trips are reported.
//! Credentials go in the URL (`https://user:password@host/validator/`). Each run adds to
//! that server's bulletin.
//!
//! `--load` measures capacity instead. Every post goes through this one server, so the
//! question is how many it handles at once: for each concurrency level it sends a batch of
//! prepared requests, that many at a time, and reports posts per second and latency.
//! Proved posts are proved first, one per member (a member's next proof needs its last on
//! the bulletin), so the clients' proving is not part of what is measured.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use personas_client::{ClientConfig, Namespace, PersonaClient};
use serde::Serialize;
use url::Url;

use crate::{Args, Summary, machine, micros, summarize};

/// Posts or ticket requests a member can make in one epoch: `k_max / W` (this build's
/// `NUM_INTS_BEFORE_SCAN - 1`). Members who would need more are replaced by fresh ones,
/// untimed.
const POSTS_PER_MEMBER: usize = personas_core::circuits::NUM_INTS_BEFORE_SCAN - 1;

/// Tickets per Privacy Pass request (this build's `PERSONAS_TICKET_BATCH`).
const TICKET_BATCH: usize = personas_core::privpass::TICKET_BATCH_SIZE;
/// Ticket requests one member makes before it would have to scan: each request counts
/// `TICKET_BATCH` interactions, and members stay within POSTS_PER_MEMBER of them.
const REQUESTS_PER_MEMBER: usize = if TICKET_BATCH > POSTS_PER_MEMBER {
    1
} else {
    POSTS_PER_MEMBER / TICKET_BATCH
};
/// Tickets one member holds after its requests.
const TICKETS_PER_MEMBER: usize = REQUESTS_PER_MEMBER * TICKET_BATCH;
/// The most `--load-requests`.
const MAX_LOAD_REQUESTS: usize = 128;

#[derive(Serialize)]
struct ServerOp {
    /// The client's own computation (proof, or ticket redemption), from `json_files`.
    client: Option<Summary>,
    /// The server's check (and, for a ticket request, blind issuance), from `json_files`.
    server: Option<Summary>,
    /// One HTTP request: the server's whole handling plus the local relay.
    round_trip: Option<Summary>,
    /// Client work after the response (unblinding a ticket), from `json_files`.
    #[serde(skip_serializing_if = "Option::is_none")]
    client_after: Option<Summary>,
    /// Mean size of the proof the client uploads, in bytes (scan and fold).
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_bytes: Option<f64>,
}

#[derive(Serialize)]
struct ServerReport {
    machine: crate::Machine,
    implementation: &'static str,
    /// Where the server was: `local` (started here) or `remote` (`--server-url`).
    target: &'static str,
    iterations: usize,
    warmup: usize,
    history: usize,
    /// Callbacks answered by `scan` and `fold`.
    callbacks: usize,
    fold_width: usize,
    /// Tickets issued per Privacy Pass request; `pp_request` times are per request.
    ticket_batch: usize,
    operations: std::collections::BTreeMap<String, ServerOp>,
}

/// One concurrency level of a load test.
#[derive(Serialize)]
struct LoadRun {
    op: &'static str,
    concurrency: usize,
    requests: usize,
    errors: usize,
    wall_s: f64,
    per_second: f64,
    latency: Option<Summary>,
}

#[derive(Serialize)]
struct LoadReport {
    machine: crate::Machine,
    target: &'static str,
    history: usize,
    runs: Vec<LoadRun>,
}

/// The server process, killed when dropped.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn post_json(http: &reqwest::blocking::Client, url: Url, proof: Vec<u8>) -> u64 {
    try_post_json(http, url, proof).unwrap_or_else(|e| panic!("{e}"))
}

/// The payload of every benchmark post: `try_post_json` sends message "bench" to "bench".
fn bench_post_payload() -> personas_core::F {
    personas_core::persona::server_post_payload("bench", None, "bench")
}

fn try_post_json(
    http: &reqwest::blocking::Client,
    url: Url,
    proof: Vec<u8>,
) -> Result<u64, String> {
    #[derive(Serialize)]
    struct PostRequest {
        message: String,
        group_id: String,
        proof: Vec<u8>,
    }
    let start = Instant::now();
    let res = http
        .post(url)
        .json(&PostRequest {
            message: "bench".into(),
            group_id: "bench".into(),
            proof,
        })
        .send()
        .map_err(|e| format!("post request failed: {e}"))?;
    let us = micros(start);
    if !res.status().is_success() {
        return Err(format!(
            "post rejected ({}): {}",
            res.status(),
            res.text().unwrap_or_default()
        ));
    }
    Ok(us)
}

/// The epoch length (seconds) of the server this bench starts, unless `--epoch-secs` says
/// otherwise. Long enough for the longest stretch the run has to finish inside one epoch
/// (a sweep and the folding member's posts; the folded scan), short enough that waiting
/// for a boundary costs little.
pub const DEFAULT_EPOCH_SECS: u64 = 120;

/// The longest the bench waits for a boundary on a server it did not start. A deployed
/// server's epochs last a day; run it with a short `PERSONAS_EPOCH_SECS` to bench it.
const MAX_REMOTE_EPOCH: u64 = 15 * 60;

/// Wait for the server's next epoch boundary. Nothing can turn the epoch on request any
/// more: it turns on the server's public schedule (`personas_core::schedule`), so this is
/// the bench's stand-in for the old turn. Returns once the server reports the new epoch,
/// so the next proof is made against it.
fn next_epoch(clock: &PersonaClient) {
    let epoch = clock
        .wait_for_next_epoch(Duration::from_secs(MAX_REMOTE_EPOCH))
        .unwrap_or_else(|e| panic!("{e:#}"));
    eprintln!("epoch {epoch}");
}

/// What posting tickets and folding need.
struct Ctx<'a> {
    clock: &'a PersonaClient,
    schedule: &'a personas_core::schedule::EpochSchedule,
    http: &'a reqwest::blocking::Client,
    jsonrpc: &'a Url,
    fold_url: &'a Url,
}

/// Post `k` tickets from `m`, at most its per-epoch allowance in each epoch. A member that
/// carries on into a later epoch must first bring its object up to it, with one (untimed)
/// fold of `depth` steps, as every member does at the start of an epoch; its unexpired
/// tickets stay outstanding, so a later fold still answers all `k`.
fn post_tickets(ctx: &Ctx, m: &PersonaClient, k: usize, depth: usize) {
    use ark_ff::PrimeField;
    let mut left = k;
    while left > 0 {
        let n = left.min(POSTS_PER_MEMBER);
        ensure_time_left(ctx.clock, ctx.schedule, BLOCK_SECS);
        let current = ctx.clock.epoch().expect("epoch");
        let ep = m.load_user().expect("user").data.ep;
        if ep.into_bigint() < current.into_bigint() {
            let proof = m.fold_to_depth(depth).expect("epoch fold failed");
            post_bytes(ctx.http, ctx.fold_url.clone(), proof);
        }
        for _ in 0..n {
            let proof = m.gen_cb_for_msg(bench_post_payload()).expect("post failed");
            post_json(ctx.http, ctx.jsonrpc.clone(), proof);
        }
        left -= n;
        if left > 0 {
            next_epoch(ctx.clock);
        }
    }
}

/// How much of an epoch one Privacy Pass member's requests and redemptions may take.
const PP_WINDOW_SECS: u64 = 60;

/// The longest one member's block of history posts can take, with room to spare on a slow
/// machine.
const BLOCK_SECS: u64 = 30;

/// Wait for the next boundary unless at least `secs` of the current epoch are left.
fn ensure_time_left(clock: &PersonaClient, schedule: &personas_core::schedule::EpochSchedule, secs: u64) {
    let now = personas_core::schedule::now_unix();
    let next = schedule.boundary(schedule.epoch_at(now) + 1);
    if next.saturating_sub(now) < secs {
        next_epoch(clock);
    }
}

fn post_bytes(http: &reqwest::blocking::Client, url: Url, body: Vec<u8>) -> u64 {
    let start = Instant::now();
    let res = http.post(url).body(body).send().expect("request failed");
    let us = micros(start);
    assert!(
        res.status().is_success(),
        "rejected: {}",
        res.text().unwrap_or_default()
    );
    us
}

/// The durations (ms) in `json_files/<label>/<file>`, dropping the first `skip`.
fn logged(label: &str, file: &str, skip: usize) -> Vec<u64> {
    let path = Path::new("json_files").join(label).join(file);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v["duration_ms"].as_f64())
        .map(|ms| (ms * 1000.0).round() as u64)
        .skip(skip)
        .collect()
}

fn start_server(repo: &Path, work: &Path, port: u16, epoch_secs: u64) -> Server {
    let data = work.join("server-data");
    // A fresh bulletin each run; keep only the (slow to generate) parameter cache.
    if let Ok(entries) = std::fs::read_dir(&data) {
        for e in entries.flatten() {
            if e.file_name() != "params" {
                let p = e.path();
                let _ = if p.is_dir() {
                    std::fs::remove_dir_all(&p)
                } else {
                    std::fs::remove_file(&p)
                };
            }
        }
    }
    std::fs::create_dir_all(&data).expect("cannot create the server data dir");
    let log = std::fs::File::create(work.join("server.log")).expect("cannot create server.log");
    // The server binary built beside this one (`cargo build --release --bin server`).
    let exe = std::env::current_exe().expect("no current executable");
    let child = Command::new(exe.with_file_name("server"))
        .current_dir(work)
        .env("PERSONAS_CONFIG", repo.join("deploy/profiles/local.toml"))
        .env("PERSONAS_BIND", format!("127.0.0.1:{port}"))
        .env("PERSONAS_DATA_DIR", &data)
        // Epoch 0 starts now, and epochs are short, so the run can wait for boundaries.
        .env(
            "PERSONAS_EPOCH_START",
            personas_core::schedule::now_unix().to_string(),
        )
        .env("PERSONAS_EPOCH_SECS", epoch_secs.to_string())
        // The bench times single-ticket scans as the per-callback baseline for folding.
        .env("PERSONAS_ALLOW_UNPADDED_SCAN", "1")
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("cannot start the server (cargo build --release --bin server)");
    Server(child)
}

fn wait_ready(api: &Url) {
    let http = reqwest::blocking::Client::new();
    let url = api.join("api/privpass/pubkey").unwrap();
    let start = Instant::now();
    // First start in a new data dir generates every key: minutes.
    while start.elapsed() < Duration::from_secs(3600) {
        if http
            .get(url.clone())
            .send()
            .is_ok_and(|r| r.status().is_success())
        {
            eprintln!("server up after {:.0}s", start.elapsed().as_secs_f64());
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("server did not come up; see server.log");
}

/// Hand `items` to `concurrency` workers and time the whole batch. `send` returns one
/// latency (or error) per request it made.
fn burst<T: Send>(
    op: &'static str,
    concurrency: usize,
    items: Vec<T>,
    send: impl Fn(T) -> Vec<Result<u64, String>> + Sync,
) -> LoadRun {
    let queue = Mutex::new(items);
    let results = Mutex::new((Vec::new(), 0usize));
    let start = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..concurrency {
            scope.spawn(|| {
                loop {
                    let item = queue.lock().unwrap().pop();
                    let Some(item) = item else { break };
                    let outcomes = send(item);
                    let mut results = results.lock().unwrap();
                    for outcome in outcomes {
                        match outcome {
                            Ok(us) => results.0.push(us),
                            Err(e) => {
                                if results.1 == 0 {
                                    eprintln!("{op}: first error: {e}");
                                }
                                results.1 += 1;
                            }
                        }
                    }
                }
            });
        }
    });
    let wall_s = start.elapsed().as_secs_f64();
    let (latencies, errors) = results.into_inner().unwrap();
    let run = LoadRun {
        op,
        concurrency,
        requests: latencies.len() + errors,
        errors,
        wall_s,
        per_second: latencies.len() as f64 / wall_s,
        latency: summarize(&latencies),
    };
    eprintln!(
        "{op} at concurrency {concurrency}: {:.1}/s, {errors} errors",
        run.per_second
    );
    run
}

fn run_load(
    args: &Args,
    member: &(impl Fn(&str) -> PersonaClient + Sync),
    http: &reqwest::blocking::Client,
    jsonrpc: &Url,
) -> Vec<LoadRun> {
    let total = args.load_requests;
    assert!(
        (1..=MAX_LOAD_REQUESTS).contains(&total),
        "--load-requests must be 1 to {MAX_LOAD_REQUESTS}"
    );
    let levels: Vec<usize> = args
        .load_concurrency
        .iter()
        .map(|&c| c.clamp(1, total))
        .collect();
    let members: Vec<PersonaClient> = (0..total).map(|i| member(&format!("load-{i}"))).collect();
    let mut runs = Vec::new();

    for &concurrency in &levels {
        let proofs: Vec<Vec<u8>> = members
            .iter()
            .map(|m| m.gen_cb_for_msg(bench_post_payload()).expect("post failed"))
            .collect();
        runs.push(burst("post", concurrency, proofs, |proof| {
            vec![try_post_json(http, jsonrpc.clone(), proof)]
        }));
    }

    // A member's ticket stash is one file, so each worker keeps to its own members, and
    // ticket requests count toward the interaction cap, so a worker that redeems more
    // than POSTS_PER_MEMBER tickets holds several members' stashes.
    for &concurrency in &levels {
        let per_worker = total / concurrency;
        let workers: Vec<Vec<(PersonaClient, usize)>> = (0..concurrency)
            .map(|w| {
                let mut stashes = Vec::new();
                let mut left = per_worker;
                while left > 0 {
                    let n = left.min(TICKETS_PER_MEMBER);
                    let m = member(&format!("load-pp-{concurrency}-{w}-{}", stashes.len()));
                    for _ in 0..n.div_ceil(TICKET_BATCH) {
                        m.privpass_request().expect("ticket request failed");
                    }
                    stashes.push((m, n));
                    left -= n;
                }
                stashes
            })
            .collect();
        runs.push(burst("pp_post", concurrency, workers, |stashes| {
            stashes
                .iter()
                .flat_map(|(m, n)| {
                    (0..*n).map(move |_| {
                        let start = Instant::now();
                        m.privpass_redeem_post("bench".into(), "bench".into(), None)
                            .map(|()| micros(start))
                            .map_err(|e| e.to_string())
                    })
                })
                .collect()
        }));
    }
    runs
}

fn write_report(out: &Path, report: &impl Serialize) {
    match serde_json::to_string_pretty(report) {
        Ok(json) => match std::fs::write(out, json) {
            Ok(()) => eprintln!("wrote {}", out.display()),
            Err(e) => eprintln!("could not write {}: {e}", out.display()),
        },
        Err(e) => eprintln!("could not serialize results: {e}"),
    }
}

pub fn run(args: &Args, work: &Path, callbacks: usize) {
    let repo = std::env::current_dir().expect("no working directory");
    let work = if work.is_absolute() {
        work.to_path_buf()
    } else {
        repo.join(work)
    };
    std::fs::create_dir_all(&work).expect("cannot create the work dir");
    let out = if args.out.is_absolute() {
        args.out.clone()
    } else {
        repo.join(&args.out)
    };
    let (api, _server, target) = match &args.server_url {
        Some(url) => {
            let mut api = url.clone();
            if !api.path().ends_with('/') {
                api.set_path(&format!("{}/", api.path()));
            }
            (api, None, "remote")
        }
        None => {
            let port = 3700;
            let api = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
            (api, Some(start_server(&repo, &work, port, args.epoch_secs)), "local")
        }
    };
    // Client and server write `json_files/` relative to their working directory.
    std::env::set_current_dir(&work).expect("cannot enter the work dir");
    wait_ready(&api);

    let clients_dir = work.join("clients");
    let _ = std::fs::remove_dir_all(&clients_dir);
    let member = |name: &str| {
        let pc = PersonaClient::new(ClientConfig::new(
            Namespace::Signal,
            api.clone(),
            clients_dir.join(name),
        ));
        pc.join("").expect("join failed");
        pc
    };
    // Longer than the default 30 s: a folded scan is megabytes to upload.
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(600))
        .build()
        .expect("cannot build the HTTP client");
    let jsonrpc = api.join("api/jsonrpc").unwrap();

    // A member must sweep before its first interaction in each epoch, so every stretch of
    // posting has to stay inside one epoch. Start each such stretch at a boundary.
    // Not a member: only reads the epoch and its schedule.
    let clock = PersonaClient::new(ClientConfig::new(
        Namespace::Signal,
        api.clone(),
        clients_dir.join("clock"),
    ));
    let schedule = clock.epoch_schedule().expect("could not read the epoch schedule");
    // The load test posts with each member once per concurrency level and never scans, so
    // it must stay inside one epoch: it wants long epochs, and waits for no boundary. The
    // full run waits for several boundaries, so it wants short ones.
    if !args.load && target == "remote" && schedule.length > MAX_REMOTE_EPOCH {
        panic!(
            "that server's epochs last {} s, and this run waits for several epoch boundaries; \
             run it with PERSONAS_EPOCH_SECS={DEFAULT_EPOCH_SECS} (no route can turn the epoch)",
            schedule.length
        );
    }
    if !args.load {
        next_epoch(&clock);
    }

    // --- history: other members' proved posts --------------------------------------------
    // Each history member posts its share in one block, started only with enough of the
    // epoch left to finish it: a member whose posts straddled a boundary would have to
    // scan first.
    if args.history > 0 {
        let start = Instant::now();
        let mut left = args.history;
        let mut k = 0;
        while left > 0 {
            let n = left.min(POSTS_PER_MEMBER);
            ensure_time_left(&clock, &schedule, BLOCK_SECS);
            let m = member(&format!("history-{k}"));
            for _ in 0..n {
                let proof = m.gen_cb_for_msg(bench_post_payload()).expect("history post failed");
                post_json(&http, jsonrpc.clone(), proof);
            }
            left -= n;
            k += 1;
        }
        eprintln!(
            "history: {} posts in {:.1}s",
            args.history,
            start.elapsed().as_secs_f64()
        );
        // The measured run below starts on a fresh epoch, as it does without history.
        if !args.load {
            next_epoch(&clock);
        }
    }
    let _ = std::fs::remove_dir_all("json_files");

    if args.load {
        let report = LoadReport {
            machine: machine(&args.label),
            target,
            history: args.history,
            runs: run_load(args, &member, &http, &jsonrpc),
        };
        println!(
            "\n{:<10}{:>12}{:>10}{:>8}{:>12}{:>12}{:>12}",
            "operation", "concurrency", "requests", "errors", "per second", "median ms", "p95 ms"
        );
        for r in &report.runs {
            let (median, p95) = r
                .latency
                .as_ref()
                .map_or((f64::NAN, f64::NAN), |s| (s.median_ms, s.p95_ms));
            println!(
                "{:<10}{:>12}{:>10}{:>8}{:>12.1}{:>12.1}{:>12.1}",
                r.op, r.concurrency, r.requests, r.errors, r.per_second, median, p95
            );
        }
        write_report(&out, &report);
        return;
    }

    let total = args.warmup + args.iters;
    // `--only` limits a server run to some operations; scan and fold always run.
    let wanted = |op: &str| args.only.as_ref().is_none_or(|o| o.iter().any(|w| w == op));
    let mut ops = std::collections::BTreeMap::new();

    if wanted("post") {
        // --- prove each post --------------------------------------------------------------------
        // A fresh poster every POSTS_PER_MEMBER posts: a member must scan before the
        // interaction cap, and scans are measured on their own below.
        let mut poster = member("poster-0");
        let mut rt = Vec::new();
        for i in 0..total {
            if i > 0 && i % POSTS_PER_MEMBER == 0 {
                poster = member(&format!("poster-{}", i / POSTS_PER_MEMBER));
            }
            let proof = poster
                .gen_cb_for_msg(bench_post_payload())
                .expect("post failed");
            rt.push(post_json(&http, jsonrpc.clone(), proof));
        }
        ops.insert(
            "post".to_string(),
            ServerOp {
                client: summarize(&logged("anon_msg", "timings.jsonl", args.warmup)),
                server: summarize(&logged("anon_msg", "verify_timings.jsonl", args.warmup)),
                round_trip: summarize(&rt[args.warmup..]),
                client_after: None,
                proof_bytes: None,
            },
        );
        eprintln!("post: done");
    }

    if wanted("vote") || wanted("merge_personas") || wanted("rep_at_least") {
        // --- every feature is a post: a vote, and posts with a claim (protocol version 5) ------
        // Each is an interaction that counts toward the cap, so members rotate like posters.
        // Three features below, `total` interactions each; interaction `n` overall is made by
        // member `n / POSTS_PER_MEMBER`.
        let posters: Vec<PersonaClient> = (0..(3 * total).div_ceil(POSTS_PER_MEMBER))
            .map(|k| {
                let m = member(&format!("feature-{k}"));
                // A second persona to merge with (join minted the first).
                m.gen_pseudo().expect("second persona");
                m
            })
            .collect();
        let feature = |i: usize| &posters[i / POSTS_PER_MEMBER];

        let mut rt = Vec::new();
        for i in 0..total {
            // A fresh poll each time: one ballot per member per poll.
            let poll: serde_json::Value = http
                .post(api.join("api/poll").unwrap())
                .json(&serde_json::json!({"message": format!("poll {i}"), "group_id": "bench"}))
                .send()
                .and_then(|r| r.error_for_status())
                .and_then(|r| r.json())
                .expect("open a poll");
            let timestamp = poll["timestamp"].as_u64().expect("the poll's id");
            let context: serde_json::Value = http
                .post(api.join("api/context").unwrap())
                .json(&serde_json::json!({"timestamp": timestamp}))
                .send()
                .and_then(|r| r.json())
                .expect("the poll's context");
            let context = personas_core::persona::field_from_str(
                context["context"].as_str().expect("context"),
            )
            .expect("a field element");
            let pc = feature(i);
            let claimed = pc.pseudo_for_poll(&context).expect("poll pseudonym");
            let payload = personas_core::persona::server_ballot_payload("signal", "upvote");
            let proof = pc
                .pseudo_proof_vote(claimed, context, payload)
                .expect("vote proof");
            let start = Instant::now();
            let res = http
                .post(api.join("api/vote").unwrap())
                .json(&serde_json::json!({
                    "group_id": "bench",
                    "emoji": "upvote",
                    "timestamp": timestamp,
                    "claimed": claimed.to_string(),
                    "proof": proof,
                }))
                .send()
                .expect("vote request");
            rt.push(micros(start));
            assert!(
                res.status().is_success(),
                "vote rejected: {}",
                res.text().unwrap_or_default()
            );
        }
        ops.insert(
            "vote".to_string(),
            ServerOp {
                client: summarize(&logged("pseudo_vote", "timings.jsonl", args.warmup)),
                server: summarize(&logged("pseudo_vote", "verify_timings.jsonl", args.warmup)),
                round_trip: summarize(&rt[args.warmup..]),
                client_after: None,
                proof_bytes: None,
            },
        );
        eprintln!("vote: done");

        for (k, (name, route, label)) in [
            ("merge_personas", "api/authorship", "author"),
            ("rep_at_least", "api/rep_at_least", "rep_at_least"),
        ]
        .into_iter()
        .enumerate()
        {
            let mut rt = Vec::new();
            for i in 0..total {
                let pc = feature((k + 1) * total + i);
                let payload = personas_core::persona::server_claim_payload("bench", "bench");
                let proof = match name {
                    "merge_personas" => pc.post_merge_personas(1, 2, payload),
                    // The member's own reputation, which it always meets.
                    _ => {
                        let rep: i64 = pc.reputation().expect("reputation").parse().unwrap_or(0);
                        pc.post_rep_at_least(1, rep, payload)
                    }
                }
                .expect("claim post proof");
                rt.push(post_json(&http, api.join(route).unwrap(), proof));
            }
            ops.insert(
                name.to_string(),
                ServerOp {
                    client: summarize(&logged(label, "timings.jsonl", args.warmup)),
                    server: summarize(&logged(label, "verify_timings.jsonl", args.warmup)),
                    round_trip: summarize(&rt[args.warmup..]),
                    client_after: None,
                    proof_bytes: None,
                },
            );
            eprintln!("{name}: done");
        }
    }

    if wanted("pp_post") || wanted("pp_request") {
        // --- Privacy Pass: request tickets offline, redeem them to post -------------------------
        // Ticket requests count toward the interaction cap too (TICKET_BATCH each): a fresh
        // member every REQUESTS_PER_MEMBER requests, and each redeems its own tickets.
        // One member at a time, all inside one epoch: its object must be from the epoch it
        // proves in, and the issuer key rotates at each boundary, expiring unredeemed
        // tickets. So each member joins, requests and redeems with PP_WINDOW_SECS of the
        // epoch left (large batches take seconds per request).
        let mut req_rt = Vec::new();
        let mut rt = Vec::new();
        let (mut requested, mut redeemed) = (0, 0);
        let mut k = 0;
        while requested < total {
            ensure_time_left(&clock, &schedule, PP_WINDOW_SECS.min(schedule.length / 2));
            let m = member(&format!("ticketed-{k}"));
            k += 1;
            let n = REQUESTS_PER_MEMBER.min(total - requested);
            for _ in 0..n {
                let start = Instant::now();
                m.privpass_request().expect("ticket request failed");
                req_rt.push(micros(start));
            }
            requested += n;
            for _ in 0..(n * TICKET_BATCH).min(total - redeemed) {
                let start = Instant::now();
                m.privpass_redeem_post("bench".into(), "bench".into(), None)
                    .expect("redemption failed");
                rt.push(micros(start));
                redeemed += 1;
            }
        }
        ops.insert(
            "pp_request".to_string(),
            ServerOp {
                client: summarize(&logged("pp_request", "timings.jsonl", args.warmup)),
                server: summarize(&logged("pp_issue", "verify_timings.jsonl", args.warmup)),
                round_trip: None,
                client_after: summarize(&logged("pp_unblind", "timings.jsonl", args.warmup)),
                proof_bytes: None,
            },
        );
        ops.insert(
            "pp_post".to_string(),
            ServerOp {
                client: summarize(&logged("pp_redeem", "timings.jsonl", args.warmup)),
                server: summarize(&logged("pp_redeem", "verify_timings.jsonl", args.warmup)),
                // The whole redeem call: load the ticket stash, redeem, request, save the stash.
                round_trip: summarize(&rt[args.warmup..]),
                client_after: None,
                proof_bytes: None,
            },
        );
        eprintln!("privacy pass: done");
    }

    // --- scanning K callbacks: one proof each, or one folded proof ----------------------
    // A fresh epoch for the scanning member's posts: the members above may have used up
    // the one they posted in.
    next_epoch(&clock);
    let scan_url = api.join("api/interact/scan").unwrap();
    let scanner = member("scanner");
    for _ in 0..callbacks {
        let proof = scanner
            .gen_cb_for_msg(bench_post_payload())
            .expect("post failed");
        post_json(&http, jsonrpc.clone(), proof);
    }
    // A sweep may start only once the object is from an earlier epoch (one sweep per epoch),
    // so the posts' epoch has to end before the member can scan their tickets.
    next_epoch(&clock);
    let mut rt = Vec::new();
    let mut scan_bytes = Vec::new();
    while scanner.outstanding_callbacks().unwrap() > 0 || scanner.is_scanning().unwrap() {
        let proof = scanner.scan().expect("scan failed");
        scan_bytes.push(proof.len() as f64);
        rt.push(post_bytes(&http, scan_url.clone(), proof));
        if !scanner.is_scanning().unwrap() {
            break;
        }
    }
    ops.insert(
        "scan".to_string(),
        ServerOp {
            client: summarize(&logged("scan", "timings.jsonl", 0)),
            server: summarize(&logged("scan", "verify_timings.jsonl", 0)),
            round_trip: summarize(&rt),
            client_after: None,
            proof_bytes: (!scan_bytes.is_empty())
                .then(|| scan_bytes.iter().sum::<f64>() / scan_bytes.len() as f64),
        },
    );
    eprintln!("scan: {} callbacks one by one", rt.len());

    let fold_url = api.join("api/interact/foldscan").unwrap();
    let ctx = Ctx { clock: &clock, schedule: &schedule, http: &http, jsonrpc: &jsonrpc, fold_url: &fold_url };
    let folder = member("folder");
    post_tickets(&ctx, &folder, callbacks, personas_core::fold::FOLD_DEPTH);
    next_epoch(&clock);
    let start = Instant::now();
    let proof = folder.fold().expect("fold failed");
    let client_total = micros(start);
    let fold_bytes = proof.len() as f64;
    let rt = post_bytes(&http, fold_url.clone(), proof);
    let steps = logged("fold", "step_timings.jsonl", 0);
    let randomize = logged("fold", "proof_timings.jsonl", 0);
    ops.insert(
        "fold".to_string(),
        ServerOp {
            // Everything the client does, keys fetched over loopback included.
            client: summarize(&[client_total]),
            server: summarize(&logged("fold", "verify_timings.jsonl", 0)),
            round_trip: summarize(&[rt]),
            client_after: None,
            proof_bytes: Some(fold_bytes),
        },
    );
    ops.insert(
        "fold_steps".to_string(),
        ServerOp {
            client: summarize(&steps),
            server: None,
            round_trip: None,
            client_after: summarize(&randomize),
            proof_bytes: None,
        },
    );
    eprintln!("fold: {callbacks} callbacks folded");

    // --- the fold sweep: the cost of a fold of each depth k ----------------------------------
    // A deployment folds exactly FOLD_DEPTH (= k_max) steps; this server, started in bench
    // mode, accepts any depth, so the cost can be measured as a function of k. Members with
    // k tickets each fold exactly k steps, so every step is a real one.
    for &k in &args.fold_sweep {
        let members: Vec<PersonaClient> =
            (0..args.iters).map(|i| member(&format!("sweep-{k}-{i}"))).collect();
        for m in &members {
            post_tickets(&ctx, m, k, k);
        }
        next_epoch(&clock);
        let (mut client, mut server, mut bytes, mut steps) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for m in &members {
            // The fold is proved for this epoch and must reach the server in it.
            ensure_time_left(&clock, &schedule, schedule.length / 2);
            let before_steps = logged("fold", "step_timings.jsonl", 0).len();
            let start = Instant::now();
            let proof = m.fold_to_depth(k).expect("fold failed");
            client.push(micros(start));
            bytes.push(proof.len() as f64);
            post_bytes(&http, fold_url.clone(), proof);
            if let Some(&v) = logged("fold", "verify_timings.jsonl", 0).last() {
                server.push(v);
            }
            steps.extend(logged("fold", "step_timings.jsonl", 0).into_iter().skip(before_steps));
        }
        ops.insert(
            format!("fold_k{k:03}"),
            ServerOp {
                client: summarize(&client),
                server: summarize(&server),
                round_trip: None,
                client_after: summarize(&steps),
                proof_bytes: Some(bytes.iter().sum::<f64>() / bytes.len().max(1) as f64),
            },
        );
        eprintln!("fold sweep: k = {k} done");
    }

    let report = ServerReport {
        machine: machine(&args.label),
        implementation: "server-based, Privacy Pass + folding",
        target,
        iterations: args.iters,
        warmup: args.warmup,
        history: args.history,
        callbacks,
        fold_width: personas_core::circuits::NUM_SCANS_PER_FOLD,
        ticket_batch: TICKET_BATCH,
        operations: ops,
    };
    let f = |s: &Option<Summary>| {
        s.as_ref()
            .map_or("—".into(), |s| format!("{:.2}", s.mean_ms))
    };
    println!(
        "\n{:<14}{:>12}{:>12}{:>14}{:>14}{:>14}",
        "operation", "client ms", "server ms", "round trip", "client after", "proof bytes"
    );
    for (name, op) in &report.operations {
        println!(
            "{name:<14}{:>12}{:>12}{:>14}{:>14}{:>14}",
            f(&op.client),
            f(&op.server),
            f(&op.round_trip),
            f(&op.client_after),
            op.proof_bytes.map_or("—".to_string(), |b| format!("{b:.0}"))
        );
    }
    write_report(&out, &report);
}

/// Where `--server` keeps the server's data and the clients' state between runs.
pub fn default_work_dir() -> PathBuf {
    PathBuf::from("target/server-bench")
}
