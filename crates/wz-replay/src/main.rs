// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y700 ([REDACTED-REQ] / [REDACTED-REQ] / [REDACTED-REQ]) — the replay binary.
//!
//! Everything except reading the file and printing is in the library beside it,
//! which is what lets the plan be tested without sending anything.
//!
//! ## Why the default is a DRY RUN
//!
//! This is the one tool in the analyzer that puts packets on a network, and a
//! replay of captured production traffic into the wrong deployment is not
//! recoverable. So printing the plan is what happens when no destination is
//! given, and it is the same value a live run plays — not a second computation
//! of it.

use std::process::ExitCode;

use wz_replay::{plan, render, Mutation, Schedule, Selection, Timing};

const USAGE: &str = "\
wz-replay -- re-publish a capture's samples into a new session

USAGE:
    wz-replay <capture> [options]

OPTIONS:
    --connect <locator>
                      DIAL this peer and actually publish the plan, e.g.
                      `tcp/127.0.0.1:7447`. Without it nothing is sent
    --keylog <file>   an NSS key log, so encrypted flows contribute samples
    --select <keyexpr>
                      replay only samples whose keyexpr matches. zenoh's own
                      dialect, so `demo/**` covers `demo/a`
    --side <A|B>      replay only one half of the conversation. A is the
                      direction `wz-analyze --fields` prints as A (low endpoint
                      to high); B is the reply half. Without it BOTH halves are
                      replayed, which re-publishes the peer's answers as though
                      this node had said them
    --timing <mode>   `declared` (default) spaces samples by --gap;
                      `capture` uses the interval the CAPTURE recorded, and
                      falls back to --gap for a pair with no capture time,
                      saying so per emission
    --gap <ms>        milliseconds between samples at speed 1.0 (default 100).
                      Under --timing capture this is the fallback
    --speed <factor>  play faster (>1) or slower (<1). Must be positive
    --max-gap <ms>    ceiling on any one delay (default 10000)
    --max-total <ms>  ceiling on the WHOLE plan. A plan over it is REFUSED
                      after being printed, never truncated
    --fuzz <spec>     mutate each payload before sending. One of:
                        flip:<bit>      flip one bit
                        truncate:<n>    keep the first n bytes
                        extend:<n>:<seed>
                        scramble:<seed>
    --dry-run         print the plan and send nothing. THE DEFAULT.
    --alert           do not replay: judge the capture and, when it is
                      INCOMPLETE, publish the verdict and its named reasons as
                      one sample. A complete capture publishes nothing, and the
                      page says so either way. Refuses the plan-shaping options,
                      which do not apply to a notification
    --alert-key <keyexpr>
                      where the alert goes (default `wz/alert`)

Exit: 0 the plan was produced (or played), 2 this tool failed.
";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let Some(path) = argv.first().filter(|a| !a.starts_with('-')) else {
        eprintln!("wz-replay: a capture file is required\n\n{USAGE}");
        return ExitCode::from(2);
    };
    let mut schedule = Schedule::default();
    let mut mutation = Mutation::None;
    let mut select: Option<String> = None;
    let mut side: Option<wz_session_core::passive::Direction> = None;
    let mut keylog: Option<String> = None;
    let mut connect: Option<String> = None;
    let mut alert = false;
    let mut alert_key: Option<String> = None;
    // R311y716 ([REDACTED-REQ]) — the plan-shaping options an alert must REFUSE. A
    // notification is not a replay: `--fuzz` has nothing to mutate, `--select`
    // nothing to select from, and `--speed` nothing to space out. Accepting
    // them silently would be the shape this workspace keeps paying for -- an
    // operator who typed one would believe it had an effect.
    let mut plan_shaping: Vec<&'static str> = Vec::new();

    let mut at = 1usize;
    while at < argv.len() {
        let arg = argv[at].as_str();
        let mut value = || {
            at += 1;
            argv.get(at).cloned()
        };
        let bad = |what: &str| {
            eprintln!("wz-replay: {what}\n\n{USAGE}");
            ExitCode::from(2)
        };
        for name in [
            "--select",
            "--side",
            "--timing",
            "--gap",
            "--max-gap",
            "--max-total",
            "--speed",
            "--fuzz",
        ] {
            if arg == name {
                plan_shaping.push(name);
            }
        }
        match arg {
            "--dry-run" => {}
            "--alert" => alert = true,
            "--alert-key" => match value() {
                Some(v) => alert_key = Some(v),
                None => return bad("--alert-key needs a key expression"),
            },
            "--keylog" => match value() {
                Some(v) => keylog = Some(v),
                None => return bad("--keylog needs a file"),
            },
            "--connect" => match value() {
                Some(v) => connect = Some(v),
                None => return bad("--connect needs a locator, e.g. tcp/127.0.0.1:7447"),
            },
            "--select" => match value() {
                Some(v) => select = Some(v),
                None => return bad("--select needs a keyexpr"),
            },
            // REFUSED rather than defaulted for an unknown letter: a reader who
            // typed `--side client` and got both halves replayed would believe
            // they had narrowed the run. The same rule `--payload-format`
            // applies to a format name this build cannot decode.
            "--side" => match value().as_deref().and_then(parse_side) {
                Some(v) => side = Some(v),
                None => return bad("--side needs A or B"),
            },
            // REFUSED for an unknown mode, on the rule `--side` and
            // `--payload-format` already settled: a reader who typed
            // `--timing real` and silently got the declared gaps would believe
            // they were replaying the capture's own pace.
            "--timing" => match value().as_deref() {
                Some("declared") => schedule.timing = Timing::Declared,
                Some("capture") => schedule.timing = Timing::Capture,
                _ => return bad("--timing needs `declared` or `capture`"),
            },
            "--gap" => match value().and_then(|v| v.parse().ok()) {
                Some(v) => schedule.gap_millis = v,
                None => return bad("--gap needs a whole number of milliseconds"),
            },
            "--max-gap" => match value().and_then(|v| v.parse().ok()) {
                Some(v) => schedule.max_gap_millis = Some(v),
                None => return bad("--max-gap needs a whole number of milliseconds"),
            },
            "--max-total" => match value().and_then(|v| v.parse().ok()) {
                Some(v) => schedule.max_total_millis = Some(v),
                None => return bad("--max-total needs a whole number of milliseconds"),
            },
            "--speed" => match value().and_then(|v| v.parse().ok()) {
                Some(v) => schedule.speed = v,
                None => return bad("--speed needs a number"),
            },
            "--fuzz" => match value().as_deref().and_then(parse_fuzz) {
                Some(v) => mutation = v,
                None => return bad("--fuzz needs one of flip:/truncate:/extend:/scramble:"),
            },
            other => return bad(&format!("unknown option `{other}`")),
        }
        at += 1;
    }

    if !alert && alert_key.is_some() {
        eprintln!(
            "wz-replay: --alert-key names where an alert goes and this run \
             raises none. Add --alert, or drop the key.\n\n{USAGE}"
        );
        return ExitCode::from(2);
    }
    if alert && !plan_shaping.is_empty() {
        eprintln!(
            "wz-replay: --alert does not replay, so {} shape{} nothing. \
             Drop {} or drop --alert.\n\n{USAGE}",
            plan_shaping.join(", "),
            if plan_shaping.len() == 1 { "s" } else { "" },
            if plan_shaping.len() == 1 {
                "it"
            } else {
                "them"
            }
        );
        return ExitCode::from(2);
    }
    let schedule = match schedule.checked() {
        Ok(schedule) => schedule,
        Err(why) => {
            eprintln!("wz-replay: {why}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let capture = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("wz-replay: {path}: {err}");
            return ExitCode::from(2);
        }
    };
    let keylog = match keylog.as_deref().map(std::fs::read) {
        None => None,
        Some(Ok(bytes)) => Some(bytes),
        Some(Err(err)) => {
            eprintln!("wz-replay: {}: {err}", keylog.unwrap_or_default());
            return ExitCode::from(2);
        }
    };
    // R311y716 ([REDACTED-REQ]) — the ALERT path, which is not a replay and takes its
    // own exit before one is planned. Extracting samples first would read the
    // capture a second way for a question that does not need them.
    if alert {
        return run_alert(
            &capture,
            keylog.as_deref(),
            alert_key
                .as_deref()
                .unwrap_or(wz_replay::alert::DEFAULT_KEYEXPR),
            connect.as_deref(),
            path,
        );
    }
    let samples = match wz_analyze::samples(&capture, keylog.as_deref()) {
        Ok(samples) => samples,
        Err(err) => {
            eprintln!("wz-replay: {path}: {err:?}");
            return ExitCode::from(2);
        }
    };
    let plan = plan(
        &samples,
        schedule,
        mutation,
        Selection {
            keyexpr: select.as_deref(),
            side,
        },
    );
    // R311y702 ([REDACTED-REQ]) — the plan is printed FIRST, whether or not it is
    // about to be played. An operator who is about to put captured traffic on a
    // live deployment should see exactly what is going out before it does, and
    // the value they read is the one that plays -- not a second rendering of a
    // second computation.
    print!("{}", render(&plan));
    // R311y704 — the whole-plan ceiling, checked AFTER the plan is printed and
    // BEFORE anything is sent. An operator who hits this must be able to see
    // the plan that was too long, which is the same reason `--dry-run` exists.
    if let Err(why) = plan.within(schedule) {
        eprintln!("wz-replay: {why}");
        return ExitCode::from(2);
    }
    let Some(connect) = connect else {
        return ExitCode::SUCCESS;
    };
    run_live(&connect, plan)
}

/// R311y716 ([REDACTED-REQ]) — judge the capture, print the verdict, and deliver it
/// when there is a destination and something to say.
///
/// The order is the one `--connect` established for a replay and it matters
/// more here: the page is printed BEFORE anything is published, so an operator
/// sees exactly what is about to land on their deployment's bus.
fn run_alert(
    capture: &[u8],
    keylog: Option<&[u8]>,
    key: &str,
    connect: Option<&str>,
    path: &str,
) -> ExitCode {
    // EVERY PLANE, and this is the whole correctness of the alert. The verdict
    // is only as wide as the planes the analysis built: `analyze` builds none
    // of the censuses, so a capture whose only shortfall is an unresolved
    // keyexpr reads as COMPLETE through it -- measured, on the first version of
    // this path. An alert that under-reports is worse than no alert, because
    // its silence is taken as an all-clear.
    let request = wz_analyze::Request {
        capture,
        keylog,
        format: wz_analyze::Format::Json,
        per_flow: false,
        per_message: false,
        messages_per_flow: None,
        quic_ports: &[],
        quic_cid_len: None,
        payload_rules: &[],
        census: wz_analyze::Census::all(),
        per_field: false,
        select: None,
    };
    let outcome = match wz_analyze::analyze_request(&request) {
        Ok((_rendered, outcome)) => outcome,
        Err(err) => {
            eprintln!("wz-replay: {path}: {err:?}");
            return ExitCode::from(2);
        }
    };
    let alert = wz_replay::alert::alert_for(&outcome, key);
    print!("{}", wz_replay::alert::render(alert.as_ref(), connect));
    match (alert, connect) {
        (Some(a), Some(to)) => run_live(to, wz_replay::alert::as_plan(&a)),
        // Nothing to send, or nowhere to send it. Both are ordinary outcomes
        // and neither is a failure of this tool; `render` above has already
        // told the operator which one happened.
        _ => ExitCode::SUCCESS,
    }
}

/// R311y702 — dial and play.
#[cfg(feature = "live")]
fn run_live(connect: &str, plan: wz_replay::Plan) -> ExitCode {
    let total = plan.emissions.len();
    match wz_replay::live::run(connect, plan) {
        Ok(sent) => {
            println!("replay: {sent} of {total} emission(s) sent to {connect}");
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("wz-replay: {why}");
            ExitCode::from(2)
        }
    }
}

/// A build without the session runtime REFUSES rather than printing the plan
/// and exiting zero.
///
/// The rule this workspace settled after measuring the alternative: a lower
/// layer that degrades silently when a feature is absent must be turned into a
/// REFUSAL at the layer a person types into. An operator who ran `--connect`
/// against a build with `live` off and got exit 0 plus a plan would have every
/// reason to believe their replay went out.
#[cfg(not(feature = "live"))]
fn run_live(connect: &str, _plan: wz_replay::Plan) -> ExitCode {
    eprintln!(
        "wz-replay: --connect {connect} needs the `live` feature, and this \
         binary was built without it. Nothing was sent. Rebuild with \
         `--features live` (it is on by default)."
    );
    ExitCode::from(2)
}

/// `A` / `B`, in either case. The letters the field listing prints.
fn parse_side(text: &str) -> Option<wz_session_core::passive::Direction> {
    match text {
        "A" | "a" => Some(wz_session_core::passive::Direction::A),
        "B" | "b" => Some(wz_session_core::passive::Direction::B),
        _ => None,
    }
}

/// `flip:12` / `truncate:4` / `extend:8:99` / `scramble:7`.
fn parse_fuzz(spec: &str) -> Option<Mutation> {
    let (kind, rest) = spec.split_once(':')?;
    match kind {
        "flip" => Some(Mutation::FlipBit {
            at: rest.parse().ok()?,
        }),
        "truncate" => Some(Mutation::Truncate {
            to: rest.parse().ok()?,
        }),
        "extend" => {
            let (count, seed) = rest.split_once(':')?;
            Some(Mutation::Extend {
                count: count.parse().ok()?,
                seed: seed.parse().ok()?,
            })
        }
        "scramble" => Some(Mutation::Scramble {
            seed: rest.parse().ok()?,
        }),
        _ => None,
    }
}
