// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-util`, the root of the crate and its logging (the first slice of the crate): upstream's
//! crate (`up_util`) and wz's (`wz_util`) run on the same scenarios, each in a process of its own,
//! results equal as text.
//!
//! Both keep process-global state: `zenoh_home` reads the environment once into a `lazy_static`,
//! and the logging functions set the one global subscriber of `tracing` (a second attempt is
//! ignored). So a scenario cannot run in the process of the test, where the other crate and the
//! other scenarios share it; each runs as a child of the test binary (`child_scenario` below,
//! which does nothing unless the parent asks for a scenario by environment variable) and the child
//! says what it saw on lines that begin with `RESULT`.
//!
//! * THE ZENOH HOME: the variable set, set to nothing, and not set (the home directory of the
//!   user, with the name of the directory under it).
//! * THE LOGGING CALLBACK: the records of events and of spans (the target, level, message, the
//!   attributes of each enclosing span in order, the fields recorded later, the thread name), those
//!   a filter keeps and those it drops, and a second initialisation that is ignored.
//! * THE LOGGING FROM THE ENVIRONMENT: which levels are enabled after each of the three
//!   initialisers with `RUST_LOG` unset, set to a level, to a directive for a target, and to
//!   something that is not a filter.
//! * THE MACRO that lists the enabled features.
//!
//! Nothing here differs between the two crates: this slice's departures are in the time range.

use std::process::Command;

const CRATE: &str = "WZ_UTIL_CRATE";
const SCENARIO: &str = "WZ_UTIL_SCENARIO";

macro_rules! process_cases {
    ($m:ident, $u:ident) => {
        mod $m {
            pub fn run(scenario: &str) {
                match scenario {
                    "home" => println!("RESULT home {:?}", $u::zenoh_home()),
                    "callback" => {
                        $u::init_log_with_callback(
                            |m| *m.level() <= tracing::Level::INFO,
                            |r: $u::LogRecord| {
                                println!(
                                    "RESULT record target={} level={} file={} line={} thread={:?} \
                                     message={:?} attributes={:?}",
                                    r.target,
                                    r.level,
                                    r.file.is_some(),
                                    r.line.is_some(),
                                    r.thread_name,
                                    r.message,
                                    r.attributes
                                )
                            },
                        );
                        // The second initialisation is ignored, whatever it would have kept.
                        $u::init_log_with_callback(|_| true, |_| println!("RESULT second ran"));
                        tracing::info!(target: "t", a = 1, b = "x", "hello {}", 5);
                        tracing::debug!(target: "t", "filtered out");
                        tracing::warn!(target: "other", "another target");
                        let outer = tracing::info_span!(
                            target: "t", "outer", k = 1, later = tracing::field::Empty
                        );
                        outer.record("later", 9);
                        outer.in_scope(|| {
                            let inner = tracing::warn_span!(target: "t", "inner", z = "q");
                            inner.in_scope(|| tracing::error!(target: "t", e = 2.5, "deep"));
                            tracing::trace!(target: "t", "filtered out too");
                            tracing::info!(target: "t", "between");
                        });
                        std::thread::Builder::new()
                            .name("worker".into())
                            .spawn(|| tracing::info!(target: "t", "from a named thread"))
                            .unwrap()
                            .join()
                            .unwrap();
                        std::thread::spawn(|| tracing::info!(target: "t", "from an unnamed one"))
                            .join()
                            .unwrap();
                    }
                    "env" | "env_or" | "test" => {
                        match scenario {
                            "env" => $u::try_init_log_from_env(),
                            "env_or" => $u::init_log_from_env_or("warn"),
                            _ => $u::init_log_test(),
                        }
                        println!(
                            "RESULT enabled error={} warn={} info={} debug={} trace={} \
                             other_debug={}",
                            tracing::enabled!(target: "t", tracing::Level::ERROR),
                            tracing::enabled!(target: "t", tracing::Level::WARN),
                            tracing::enabled!(target: "t", tracing::Level::INFO),
                            tracing::enabled!(target: "t", tracing::Level::DEBUG),
                            tracing::enabled!(target: "t", tracing::Level::TRACE),
                            tracing::enabled!(target: "other", tracing::Level::DEBUG)
                        );
                    }
                    other => panic!("no such scenario {other}"),
                }
            }
        }
    };
}

process_cases!(up, up_util);
process_cases!(wz, wz_util);

/// The scenario the parent asked for, run in this process. Without the variables it is a test that
/// passes, so a plain run of the binary does not run a scenario twice.
#[test]
fn child_scenario() {
    if let (Ok(krate), Ok(scenario)) = (std::env::var(CRATE), std::env::var(SCENARIO)) {
        match krate.as_str() {
            "up" => up::run(&scenario),
            "wz" => wz::run(&scenario),
            other => panic!("no such crate {other}"),
        }
    }
}

/// The lines a child of this binary printed for a scenario of one crate, under the environment
/// given: the variables to set and the ones to remove.
fn child(krate: &str, scenario: &str, set: &[(&str, &str)], remove: &[&str]) -> Vec<String> {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "--exact",
        "child_scenario",
        "--nocapture",
        "--test-threads=1",
    ])
    .env(CRATE, krate)
    .env(SCENARIO, scenario);
    for key in remove {
        cmd.env_remove(key);
    }
    for (key, value) in set {
        cmd.env(key, value);
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{krate} {scenario}: {:?}\n{}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // The harness prints `test child_scenario ... ` without a newline before the test runs, so the
    // first line of the child's own output continues that line: look for the marker in the line.
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter_map(|l| {
            l.find("RESULT ")
                .map(|at| l[at + "RESULT ".len()..].to_string())
        })
        .collect()
}

/// A scenario of both crates under one environment, asserted equal, and the lines.
fn both(scenario: &str, set: &[(&str, &str)], remove: &[&str]) -> Vec<String> {
    let (u, w) = (
        child("up", scenario, set, remove),
        child("wz", scenario, set, remove),
    );
    assert_eq!(u, w, "{scenario} {set:?} {remove:?}");
    assert!(!u.is_empty(), "{scenario} {set:?} printed nothing");
    u
}

#[test]
fn both_crates_find_the_zenoh_home_alike() {
    // Set: the path is the variable, as it is.
    let set = both("home", &[("ZENOH_HOME", "/zh/dir")], &["HOME"]);
    assert_eq!(set, vec![r#"home "/zh/dir""#.to_string()]);
    // Set to nothing: an empty path, not the default.
    let empty = both("home", &[("ZENOH_HOME", "")], &[]);
    assert_eq!(empty, vec![r#"home """#.to_string()]);
    // Not set: the home directory of the user and the name of the directory under it.
    let unset = both("home", &[("HOME", "/users/z")], &["ZENOH_HOME"]);
    assert_eq!(unset, vec![r#"home "/users/z/.zenoh""#.to_string()]);
    // Not set, and no HOME: the account database answers, the same for both.
    let none = both("home", &[], &["ZENOH_HOME", "HOME"]);
    assert!(none[0].ends_with(r#"/.zenoh""#), "{none:?}");
}

#[test]
fn both_crates_record_events_and_spans_alike() {
    let lines = both("callback", &[], &["RUST_LOG"]);
    // The events the filter keeps are recorded, in order, with what each enclosing span carried:
    // the records of `hello`, `another target` (the filter is on the level), the deep error with
    // the attributes of the outer span (including the one recorded later) and the inner one, the
    // event between, and the two threads.
    let records: Vec<&String> = lines.iter().filter(|l| l.starts_with("record")).collect();
    assert_eq!(records.len(), 6, "{lines:#?}");
    assert!(
        records[0].contains(r#"message=Some("hello 5")"#),
        "{records:#?}"
    );
    assert!(
        records[0].contains(r#"attributes=[("a", "1"), ("b", "\"x\"")]"#),
        "{records:#?}"
    );
    assert!(
        records[2].contains(r#"message=Some("deep")"#),
        "{records:#?}"
    );
    assert!(
        records[2].contains(r#"[("k", "1"), ("later", "9"), ("z", "\"q\""), ("e", "2.5")]"#),
        "{records:#?}"
    );
    assert!(records[3].contains(r#"("later", "9")"#), "{records:#?}");
    assert!(
        records[4].contains(r#"thread=Some("worker")"#),
        "{records:#?}"
    );
    assert!(records[5].contains("thread=None"), "{records:#?}");
    // The second initialisation never ran.
    assert!(
        !lines.iter().any(|l| l.contains("second ran")),
        "{lines:#?}"
    );
}

#[test]
fn both_crates_enable_the_same_levels_from_the_environment() {
    let mut matrix = std::collections::BTreeMap::new();
    // `RUST_LOG` unset, a level, a directive for one target, a level that is too fine to matter,
    // and something that is not a filter at all.
    for rust_log in [
        None,
        Some("info"),
        Some("debug"),
        Some("t=trace"),
        Some("error"),
        Some("=["),
    ] {
        for scenario in ["env", "env_or"] {
            let set: Vec<(&str, &str)> = rust_log.map(|v| ("RUST_LOG", v)).into_iter().collect();
            let remove: &[&str] = if rust_log.is_none() {
                &["RUST_LOG"]
            } else {
                &[]
            };
            let lines = both(scenario, &set, remove);
            matrix.insert((rust_log, scenario), lines[0].clone());
        }
    }
    // `try_init_log_from_env` with nothing set enables nothing, and with a level it enables that
    // level and the coarser ones.
    assert!(
        matrix[&(None, "env")].contains("error=false"),
        "{matrix:#?}"
    );
    assert!(
        matrix[&(Some("info"), "env")].contains("info=true debug=false"),
        "{matrix:#?}"
    );
    assert!(
        matrix[&(Some("t=trace"), "env")].contains("trace=true"),
        "{matrix:#?}"
    );
    assert!(
        matrix[&(Some("t=trace"), "env")].contains("other_debug=false"),
        "{matrix:#?}"
    );
    // The fallback of `init_log_from_env_or("warn")` is used when the variable is unset or is not
    // a filter.
    assert!(
        matrix[&(None, "env_or")].contains("warn=true info=false"),
        "{matrix:#?}"
    );
    assert!(
        matrix[&(Some("=["), "env_or")].contains("warn=true info=false"),
        "{matrix:#?}"
    );
    assert!(
        matrix[&(Some("debug"), "env_or")].contains("debug=true trace=false"),
        "{matrix:#?}"
    );
    // `init_log_test` keeps the level it fixes, whatever the environment says.
    let test = both("test", &[("RUST_LOG", "trace")], &[]);
    assert!(test[0].contains("info=true debug=false"), "{test:?}");
}

#[test]
#[allow(unexpected_cfgs)]
fn both_crates_expand_the_feature_macro_alike() {
    // The macro asks `cfg!` in the crate that calls it: neither feature is on in this test crate.
    let up = up_util::concat_enabled_features!(prefix = "zenoh", features = ["test", "other"]);
    let wz = wz_util::concat_enabled_features!(prefix = "zenoh", features = ["test", "other"]);
    assert_eq!(up, wz);
    assert_eq!(up, "");
    let up = up_util::concat_enabled_features!(prefix = "zenoh", features = []);
    let wz = wz_util::concat_enabled_features!(prefix = "zenoh", features = []);
    assert_eq!(up, wz);
    // The re-export it expands through is the same crate's.
    assert_eq!(
        up_util::__concatcp!("a", "b", 1u8),
        wz_util::__concatcp!("a", "b", 1u8)
    );
    assert_eq!(up_util::ZENOH_HOME_ENV_VAR, wz_util::ZENOH_HOME_ENV_VAR);
}

/// The control: the comparison is on what a child printed, so a scenario that differs gives lines
/// that differ.
#[test]
fn the_comparison_sees_a_scenario_that_differs() {
    let a = child("wz", "home", &[("ZENOH_HOME", "/a")], &[]);
    let b = child("wz", "home", &[("ZENOH_HOME", "/b")], &[]);
    assert_ne!(a, b);
    let info = child("wz", "env", &[("RUST_LOG", "info")], &[]);
    let debug = child("wz", "env", &[("RUST_LOG", "debug")], &[]);
    assert_ne!(info, debug);
}
