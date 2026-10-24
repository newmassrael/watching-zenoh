// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A running wz router serves its capacity report (`docs/router-data-plane-scaling.md`
//! section 7.4) at `wz/@/<zid>/capacity`, outside upstream's admin space, behind the same
//! admin read permit.
//!
//! ## The properties
//!
//! - **It is served, and it is the node's own state.** A wz session GETs the key and the one
//!   reply is the JSON the report writes: the share the router was told, the limit the model
//!   derives from it and what set it, the sessions the router holds.
//! - **It does not move upstream's answers.** A GET for the router's admin root is answered
//!   from keys under `@/` and none of them is the report's, and a wildcard GET that stands for
//!   the whole admin space does not reach the report: the `wz` root is outside it.
//! - **It is gated like every admin leg.** With the read permit denied the same GET gets the
//!   terminating Final alone.
//!
//! Both ends are wz, so this file links no foreign implementation and carries no cross-impl
//! marker. The router is built with `adminspace-read`, which is what makes the permit the
//! flag's value and not a constant `true`; without it the denial below would fail and not pass
//! vacuously.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, spawn_on_ephemeral_port,
    wait_for_substring, wz_ap_demo_binary, wz_e2e_admin_probe_binary, ChildGuard,
};

/// How long the probe's whole script may take; it bounds each step itself.
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(30);

/// A router with `args`, and the key its capacity report is hosted at, scraped from the line the
/// router logs at registration (which is independent of the read permit).
fn spawn_router(label: &str, args: &[&str]) -> (ChildGuard, std::fs::File, u16, String, String) {
    let stderr = tempfile::tempfile().expect("tempfile for the router's stderr");
    let (router, mut log, port) = spawn_on_ephemeral_port(
        &wz_ap_demo_binary(),
        args,
        "router-hat: listening on 127.0.0.1:",
        label,
        stderr,
    );
    let captured = wait_for_substring(
        &mut log,
        "capacity report hosted at ",
        Duration::from_secs(10),
    )
    .unwrap_or_else(|c| panic!("{label} never hosted its capacity report within 10s\n{c}"));
    let key = captured
        .lines()
        .find_map(|l| l.split_once("capacity report hosted at "))
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("{label} log had no scrapeable capacity key"));
    let zid = key
        .strip_prefix("wz/@/")
        .and_then(|r| r.strip_suffix("/capacity"))
        .map(str::to_string)
        .unwrap_or_else(|| panic!("`{key}` is not wz/@/<zid>/capacity"));
    (router, log, port, key, zid)
}

/// Run the probe against `port` with `gets` in order on one session; its transcript.
fn probe(router: &mut ChildGuard, log: &mut std::fs::File, port: u16, gets: &[&str]) -> String {
    let p_stderr = tempfile::tempfile().expect("tempfile for the probe's stderr");
    let p_writer = p_stderr.try_clone().expect("dup the probe's stderr handle");
    let mut p_reader = p_stderr;
    let addr = format!("127.0.0.1:{port}");
    let mut args = vec!["--connect".to_string(), addr];
    for g in gets {
        args.push("--get".into());
        args.push((*g).to_string());
    }
    let mut child = ChildGuard::wrap(
        "wz-e2e-admin-probe",
        Command::new(wz_e2e_admin_probe_binary())
            .args(&args)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(p_writer))
            .spawn()
            .expect("spawn wz-e2e-admin-probe"),
    );
    let done = format!("SCRIPT COMPLETE steps={}", gets.len());
    let out = match wait_for_substring(&mut p_reader, &done, SCRIPT_TIMEOUT) {
        Ok(c) => c,
        Err(c) => {
            let host = read_captured(log);
            let _ = child.child_mut().kill();
            let _ = router.child_mut().kill();
            panic!("the probe never finished\n--- probe ---\n{c}\n--- router ---\n{host}");
        }
    };
    let _ = child.child_mut().kill();
    let _ = child.child_mut().wait();
    out
}

fn stop(mut router: ChildGuard) {
    let _ = router.child_mut().kill();
    let _ = router.child_mut().wait();
}

/// The keys the probe saw replies under for step `n`.
fn reply_keys(out: &str, n: usize) -> Vec<String> {
    let marker = format!("STEP {n} GET reply #");
    out.lines()
        .filter(|l| l.contains(&marker))
        .filter_map(|l| l.split_once("keyexpr='"))
        .filter_map(|(_, rest)| rest.split('\'').next())
        .map(str::to_string)
        .collect()
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,adminspace-router-linkstate,adminspace-read + wz-e2e-admin-probe); Layer E7g runs via --ignored"]
fn wz_router_hat_serves_its_capacity_report_beside_upstreams_admin_space() {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let (mut router, mut log, port, key, zid) = spawn_router(
        "router-hat told 1.32% of a core",
        &[
            "--router-hat",
            "127.0.0.1:0",
            "--max-sessions",
            "5000",
            "--cpu-share",
            "1.32",
        ],
    );
    let admin_root = format!("@/{zid}/router/**");
    let out = probe(
        &mut router,
        &mut log,
        port,
        &[&key, "wz/@/**", &admin_root, "@/**", "wz/**"],
    );
    stop(router);

    // 1 and 2: the report is served, to its own key and to a wildcard over the `@` space of `wz`.
    for n in [1, 2] {
        assert_eq!(
            reply_keys(&out, n),
            vec![key.clone()],
            "step {n}: one reply, under the report's key\n--- probe ---\n{out}"
        );
    }
    let body = out
        .lines()
        .find_map(|l| l.split_once("STEP 1 BODY #1 ").map(|(_, rest)| rest))
        .unwrap_or_else(|| panic!("no body in step 1\n--- probe ---\n{out}"));
    for fact in [
        "\"schema_version\":1,",
        "\"share_ppm\":13200,",
        "\"configured_max_sessions\":5000,",
        "\"limit\":1100,",
        "\"limiter\":\"liveness\",",
        "\"sessions_held\":1,",
        "\"lease_ms\":10000,",
        "\"lease_at_risk\":false,",
    ] {
        assert!(body.contains(fact), "the report lacks {fact}\n{body}");
    }

    // 3 and 4: upstream's admin space is answered from keys under `@/` and never from the report's;
    // the whole-space wildcard does not reach the `wz` root.
    for n in [3, 4] {
        let keys = reply_keys(&out, n);
        assert!(
            !keys.is_empty(),
            "step {n}: the admin space answers\n--- probe ---\n{out}"
        );
        assert!(
            keys.iter().all(|k| k.starts_with("@/")),
            "step {n}: every upstream admin reply is keyed under `@/`: {keys:?}"
        );
        assert!(
            !keys.contains(&key),
            "step {n}: the capacity report is not part of upstream's admin space"
        );
    }

    // 5: `wz/**` does not stand for the verbatim `@` chunk, as `**` does not stand for upstream's.
    assert!(
        reply_keys(&out, 5).is_empty(),
        "a wildcard does not reach into the verbatim `@` space\n--- probe ---\n{out}"
    );
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,adminspace-router-linkstate,adminspace-read + wz-e2e-admin-probe); Layer E7g runs via --ignored"]
fn wz_router_hat_answers_no_capacity_report_when_admin_read_is_denied() {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let (mut router, mut log, port, key, _zid) = spawn_router(
        "router-hat with the admin read permit denied",
        &["--router-hat", "127.0.0.1:0", "--no-admin-read"],
    );
    // The permit is the flag's value only with `adminspace-read` built in; say so before
    // trusting an absence.
    if let Err(c) = wait_for_substring(
        &mut log,
        "router-hat: adminspace read permit = false",
        Duration::from_secs(5),
    ) {
        stop(router);
        panic!("the read permit must be denied under --no-admin-read + adminspace-read\n{c}");
    }
    let out = probe(&mut router, &mut log, port, &[&key]);
    stop(router);
    assert!(
        out.contains(&format!("STEP 1 GET '{key}' FINAL replies=0")),
        "a denied read answers with the terminating Final alone\n--- probe ---\n{out}"
    );
}
