// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2745 (open-debt item 665) — an ORDERED GET/PUT script over ONE session.
//!
//! ## The property this exists to make observable
//!
//! A host that re-resolves a piece of live state PER REQUEST and one that
//! re-resolves it PER CONNECTION answer a one-shot client identically, because
//! each of that client's requests arrives on its own connection. Every foreign
//! client this tree can drive is one-shot — a stock zenoh-pico `z_get` has no
//! repeat flag, and wz-ap-demo's `--query` task emits exactly one Query — so
//! the two resolves have never been separable here.
//!
//! R2374 measured the consequence rather than arguing it: freezing the
//! `adminspace-read` permit beside `get_cfg`, which is precisely the defect
//! that atom's residual names, left all three Layer E6i tests GREEN. The
//! witnessed property was per-CONNECTION liveness, and the residual has been
//! exactly the gap between that and per-GET ever since.
//!
//! This binary closes the gap by holding ONE session and running a script the
//! caller writes in argv.
//!
//! ## Why a SCRIPT and not a three-step test
//!
//! The immediate need is GET -> PUT -> GET against the storage host's admin
//! permit. Writing that sequence in is what would make this a second one-shot,
//! and the same claim — "a live slice is re-read on every request" — is made
//! by the peer and router-hat hosts too. So the steps come off argv in order
//! and the binary neither knows nor cares what they mean:
//!
//! ```text
//! wz-e2e-admin-probe --connect <ADDR> --get <SELECTOR> \
//!     --put <KEY>=<VALUE> --get <SELECTOR>
//! ```
//!
//! Flags may repeat and their ARGV ORDER is the execution order. Everything
//! runs on the one session the harness opened.
//!
//! ## What it reports, and why the count is the report
//!
//! Each GET logs `STEP <i> GET '<sel>' FINAL replies=<n>`. The number is the
//! verdict a fixture reads: a permitted admin GET answers with one or more
//! replies and a denied one answers with the terminating Final alone, so
//! `replies=0` and `replies>=1` are the two states of the gate. Reporting the
//! COUNT rather than a "denied" boolean keeps this binary ignorant of what any
//! particular host's permit means — the fixture owns that reading.
//!
//! ⚠ A step ends on its FINAL, never on a timer. `codec-response-final` is
//! pinned for that reason: a count taken at a local timeout would be a count
//! of "replies that arrived in time", which is a different number that happens
//! to agree most of the time.

use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use wz::runtime_core::TimeSource;
use wz::runtime_tokio::session::{PublishOptions, QueryOptions};
use wz_e2e_harness::{run_initiator_e2e, run_main, AbortOnDrop};

const BINARY: &str = "wz-e2e-admin-probe";

/// Upper bound on how long ONE step waits for its Final before the script
/// gives up and says so. Not a step's normal end — a step ends on its Final
/// (see the module doc); this is what stops a wedged host from parking the
/// script forever with no line in the log saying why.
const STEP_FINAL_TIMEOUT_MS: u64 = 10_000;

fn main() -> ExitCode {
    let Some(args) = CliArgs::parse(std::env::args().skip(1)) else {
        eprintln!(
            "usage: {BINARY} --connect <ADDR> [--get <SELECTOR>] [--put <KEY>=<VALUE>] ...\n\
             \n\
             --get and --put may repeat; their ARGV ORDER is the execution order,\n\
             and every step runs on the ONE session this process opens."
        );
        return ExitCode::FAILURE;
    };
    let CliArgs { connect, steps } = args;

    run_main(
        BINARY,
        run_initiator_e2e(BINARY, connect, move |opened| {
            let session = opened.session.clone();
            let clock = opened.clock;
            // APPLICATION — the script is this binary's own workload, and it
            // must be a task rather than inline because each step awaits an
            // inbound Final that only the harness's drive loop can deliver.
            let scripted =
                wz::runtime_tokio::runtime_pool::WzRuntime::Application.spawn(async move {
                    run_script(session, clock, steps).await;
                });
            Ok::<_, std::io::Error>(AbortOnDrop(scripted))
        }),
    )
}

/// Execute the steps in order on the one open session.
///
/// Sequential BY CONSTRUCTION: the loop awaits each step's completion before
/// the next begins, which is the whole instrument. A concurrent script would
/// reintroduce exactly the ambiguity this binary exists to remove — "did the
/// second GET see the PUT?" has no answer if they raced.
async fn run_script(
    session: wz::runtime_tokio::session::TokioSession,
    clock: wz::runtime_tokio::runtime_impl::TokioTime,
    steps: Vec<Step>,
) {
    let total = steps.len();
    for (idx, step) in steps.into_iter().enumerate() {
        let n = idx + 1;
        match step {
            Step::Get(selector) => {
                if !run_get(&session, &clock, n, &selector).await {
                    log::error!("{BINARY}: SCRIPT ABORTED at step {n}");
                    return;
                }
            }
            Step::Put { key, value } => {
                match session.publish(&key, value.as_bytes(), PublishOptions::put()) {
                    Ok(_) => log::info!("{BINARY}: STEP {n} PUT '{key}'='{value}' emitted"),
                    Err(e) => {
                        log::error!("{BINARY}: STEP {n} PUT '{key}' failed: {e:?}");
                        log::error!("{BINARY}: SCRIPT ABORTED at step {n}");
                        return;
                    }
                }
            }
        }
    }
    log::info!("{BINARY}: SCRIPT COMPLETE steps={total}");
}

/// One GET, counted to its Final. Returns false when the step could not be
/// completed, which the caller turns into an aborted script rather than a
/// silently short one — a fixture that greps for `replies=` must never read a
/// step that did not run as a step that answered nothing.
async fn run_get(
    session: &wz::runtime_tokio::session::TokioSession,
    clock: &wz::runtime_tokio::runtime_impl::TokioTime,
    n: usize,
    selector: &str,
) -> bool {
    let replies = Arc::new(AtomicUsize::new(0));
    let (final_tx, final_rx) = tokio::sync::oneshot::channel::<()>();
    // `Mutex<Option<Sender>>`: the on_final callback is `Fn`, not `FnOnce`, so
    // the sender is TAKEN out on the first fire. A duplicate Final — which a
    // misbehaving responder may send — then finds `None` and is ignored rather
    // than panicking on a consumed channel.
    let final_tx = std::sync::Mutex::new(Some(final_tx));

    let replies_cb = replies.clone();
    let query = session.query(
        selector,
        QueryOptions::get(),
        move |reply| {
            let seen = replies_cb.fetch_add(1, Ordering::SeqCst) + 1;
            log::info!(
                "{BINARY}: STEP {n} GET reply #{seen} keyexpr='{}'",
                reply.keyexpr()
            );
        },
        move |rid| {
            log::info!("{BINARY}: STEP {n} GET final rid={rid}");
            if let Some(tx) = final_tx.lock().expect("final sender mutex").take() {
                let _ = tx.send(());
            }
        },
    );
    let _handle = match query {
        Ok(h) => h,
        Err(e) => {
            log::error!("{BINARY}: STEP {n} GET '{selector}' failed to issue: {e:?}");
            return false;
        }
    };
    log::info!("{BINARY}: STEP {n} GET '{selector}' issued");

    // The Final or the bound, whichever comes first. `clock.sleep` rather than
    // `tokio::time` so the wait uses the same TimeSource epoch the session and
    // the drive loop share.
    tokio::select! {
        _ = final_rx => {}
        _ = clock.sleep(STEP_FINAL_TIMEOUT_MS) => {
            log::error!(
                "{BINARY}: STEP {n} GET '{selector}' saw no Final within {STEP_FINAL_TIMEOUT_MS}ms"
            );
            return false;
        }
    }
    log::info!(
        "{BINARY}: STEP {n} GET '{selector}' FINAL replies={}",
        replies.load(Ordering::SeqCst)
    );
    true
}

/// One scripted operation. Ordered by argv position, not by kind.
enum Step {
    Get(String),
    Put { key: String, value: String },
}

/// `--connect <ADDR>` plus the ordered step list. `--connect` is mandatory and
/// may appear once; the step flags may repeat.
struct CliArgs {
    connect: String,
    steps: Vec<Step>,
}

impl CliArgs {
    fn parse(mut args: impl Iterator<Item = String>) -> Option<Self> {
        let mut connect = None;
        let mut steps = Vec::new();
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--connect" => {
                    if connect.is_some() {
                        return None;
                    }
                    connect = Some(args.next()?);
                }
                "--get" => steps.push(Step::Get(args.next()?)),
                "--put" => {
                    // `KEY=VALUE`, split on the FIRST `=`: a zenoh keyexpr
                    // cannot contain one, and a value may.
                    let spec = args.next()?;
                    let (key, value) = spec.split_once('=')?;
                    steps.push(Step::Put {
                        key: key.to_string(),
                        value: value.to_string(),
                    });
                }
                _ => return None,
            }
        }
        // A script with no steps would open a session, log nothing a fixture
        // can read, and exit 0 — the population-of-zero green this tree
        // refuses everywhere else.
        if steps.is_empty() {
            return None;
        }
        Some(Self {
            connect: connect?,
            steps,
        })
    }
}
