// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-runtime`: upstream's crate (`up_runtime`) and wz's (`wz_runtime`) given the same
//! `ZENOH_RUNTIME`, and what each makes of it held equal.
//!
//! The pool is a process-wide static configured once from the environment, so one process can show one
//! configuration. Each case therefore runs the test binary again as a CHILD with the variable set, the
//! child prints what both crates did, and the parent compares the two crates' lines. The child is one
//! of this file's own tests, selected by name and gated by `WZ_DIFFERENTIAL_CHILD`, so the same
//! source is the experiment on both sides.

use std::process::Command;

macro_rules! describe {
    ($label:literal, $rt:ident) => {{
        // The parameter of each role the crate read, and the name of the thread a task of that role
        // runs on (the role it is served by, after any handover).
        for zrt in $rt::ZRuntime::iter() {
            let p: &$rt::RuntimeParam = std::borrow::Borrow::borrow(&zrt);
            println!(
                "DIFF|{}|{zrt}|{}|{}|{:?}",
                $label, p.worker_threads, p.max_blocking_threads, p.handover
            );
            // The role's name only: a runtime with several workers runs the task on any of them,
            // `app-0` or `app-1`, so the number says nothing about the crate.
            let thread = zrt
                .spawn(async { std::thread::current().name().unwrap_or("?").to_string() })
                .await
                .unwrap();
            let served_by = thread.rsplit_once('-').map_or("?", |(role, _n)| role);
            println!("DIFF|{}|{zrt}|thread|{served_by}", $label);
        }
    }};
}

/// The child: print what each crate did, for the crate(s) `WZ_DIFFERENTIAL_ONLY` names. A test that is
/// not run as a child does nothing, so a plain `cargo test` does not run it.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn child_describes_the_pool() {
    if std::env::var_os("WZ_DIFFERENTIAL_CHILD").is_none() {
        return;
    }
    let only = std::env::var("WZ_DIFFERENTIAL_ONLY").unwrap_or_default();
    if only != "wz" {
        describe!("up", up_runtime);
    }
    if only != "up" {
        describe!("wz", wz_runtime);
    }
}

/// Run the child with `env` as `ZENOH_RUNTIME`: whether it succeeded and the `DIFF` lines it printed.
fn run_child(env: &str, only: &str) -> (bool, Vec<String>) {
    let out = Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            "child_describes_the_pool",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ZENOH_RUNTIME", env)
        .env("WZ_DIFFERENTIAL_CHILD", "1")
        .env("WZ_DIFFERENTIAL_ONLY", only)
        .output()
        .expect("the child runs");
    let lines = String::from_utf8_lossy(&out.stdout)
        .lines()
        // The first line follows libtest's own `test <name> ... ` on the same line.
        .filter_map(|l| {
            l.find("DIFF|")
                .map(|at| l[at + "DIFF|".len()..].to_string())
        })
        .collect();
    (out.status.success(), lines)
}

/// The lines of `crate_label`, without the label, in the order printed.
fn of(lines: &[String], crate_label: &str) -> Vec<String> {
    lines
        .iter()
        .filter_map(|l| {
            l.strip_prefix(&format!("{crate_label}|"))
                .map(str::to_string)
        })
        .collect()
}

const CONFIGURATIONS: &[&str] = &[
    // The empty configuration, and the one in the crate's own documentation.
    "()",
    "(rx: (handover: app), acc: (handover: app), app: (worker_threads: 2), tx: (max_blocking_threads: 1))",
    // A role with both fields, one with a handover only, and an explicit `None`.
    "(net: (worker_threads: 3, max_blocking_threads: 7))",
    "(tx: (handover: app))",
    "(app: (handover: None), rx: (worker_threads: 4))",
];

#[test]
fn both_crates_read_every_configuration_alike_and_serve_each_role_from_the_same_thread() {
    for env in CONFIGURATIONS {
        let (ok, lines) = run_child(env, "both");
        assert!(ok, "the child failed on `{env}`");
        let (up, wz) = (of(&lines, "up"), of(&lines, "wz"));
        assert_eq!(
            up.len(),
            10,
            "five roles, two lines each, for upstream on `{env}`: {up:?}"
        );
        assert_eq!(up, wz, "the two crates differ on `{env}`");
    }
}

#[test]
fn the_documented_configuration_hands_rx_and_acc_over_to_app() {
    // Not a comparison: what the comparison above agrees ON, for one case, so two crates that were
    // wrong the same way cannot pass for right.
    let (ok, lines) = run_child(CONFIGURATIONS[1], "wz");
    assert!(ok);
    let wz = of(&lines, "wz");
    assert!(wz.contains(&"app|2|50|None".to_string()), "{wz:?}");
    assert!(
        wz.contains(&"rx|2|50|Some(Application)".to_string()),
        "{wz:?}"
    );
    assert!(wz.contains(&"rx|thread|app".to_string()), "{wz:?}");
    assert!(wz.contains(&"tx|1|1|None".to_string()), "{wz:?}");
}

#[test]
fn an_invalid_configuration_stops_both_crates_at_first_use() {
    for env in ["(unknown: ())", "(app: (workers: 2))", "not ron"] {
        let (up_ok, _) = run_child(env, "up");
        let (wz_ok, _) = run_child(env, "wz");
        assert!(!up_ok, "upstream accepted `{env}`");
        assert!(!wz_ok, "wz accepted `{env}`, which upstream refuses");
    }
}
