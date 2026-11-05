// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A running wz router serves its resource snapshot (`docs/observation-plane.md` M4) at
//! `wz/@/<zid>/snapshot`, beside its capacity report, outside upstream's admin space and behind the
//! same admin read permit.
//!
//! ## The properties
//!
//! - **It is served, and it is the node's own state.** A wz session GETs the key and the one
//!   reply is the JSON the snapshot writes: the layout version, the platform's readings where the
//!   host could take them and `null` where it could not (the heap, always, on this host), and how
//!   many messages the router's faces have received.
//! - **The count survives a link.** The first session that asked has gone when the second asks a
//!   period later, and the router's count has not fallen: what the first session's receive path
//!   counted is in the total beside what the second's has.
//! - **It does not move upstream's answers.** A GET for upstream's admin space is answered from
//!   keys under `@/` and none of them is the snapshot's, and a wildcard over the `wz` root does not
//!   reach into its verbatim `@` space.
//! - **It is gated like every admin leg.** With the read permit denied the same GET gets the
//!   terminating Final alone.
//!
//! Both ends are wz, so this file links no foreign implementation and carries no cross-impl marker.
//! The router is built with `adminspace-read`, which is what makes the permit the flag's value and
//! not a constant `true`; without it the denial below would fail and not pass vacuously.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, spawn_on_ephemeral_port,
    wait_for_substring, wz_ap_demo_binary, wz_e2e_admin_probe_binary, ChildGuard,
};

/// How long the probe's whole script may take; it bounds each step itself.
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(30);

/// The build's sampling period plus room: the snapshot a GET reads is taken once a period, so a
/// reader that wants a later one waits this long.
const PAST_THE_PERIOD: Duration = Duration::from_millis(1_000 + 600);

/// A router with `args`, and the key its snapshot is hosted at, scraped from the line the router
/// logs at registration (which is independent of the read permit).
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
        "resource snapshot hosted at ",
        Duration::from_secs(10),
    )
    .unwrap_or_else(|c| panic!("{label} never hosted its resource snapshot within 10s\n{c}"));
    let key = captured
        .lines()
        .find_map(|l| l.split_once("resource snapshot hosted at "))
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .map(str::to_string)
        .unwrap_or_else(|| panic!("{label} log had no scrapeable snapshot key"));
    let zid = key
        .strip_prefix("wz/@/")
        .and_then(|r| r.strip_suffix("/snapshot"))
        .map(str::to_string)
        .unwrap_or_else(|| panic!("`{key}` is not wz/@/<zid>/snapshot"));
    (router, log, port, key, zid)
}

/// Run the probe against `port` with `gets` in order on one session; its transcript. The probe
/// is gone when this returns, and so is its session.
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

/// The body of the first reply of step `n`.
fn body_of(out: &str, n: usize) -> String {
    let marker = format!("STEP {n} BODY #1 ");
    out.lines()
        .find_map(|l| l.split_once(&marker).map(|(_, rest)| rest.to_string()))
        .unwrap_or_else(|| panic!("no body in step {n}\n--- probe ---\n{out}"))
}

/// The unsigned number after `"name":` in a JSON document written by the snapshot, which has no
/// nesting that repeats a name.
fn number_of(json: &str, name: &str) -> Option<u64> {
    let key = format!("\"{name}\":");
    let at = json.find(&key)? + key.len();
    let digits: String = json[at..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,adminspace-router-linkstate,adminspace-read,resource-snapshot + wz-e2e-admin-probe); Layer E7g runs via --ignored"]
fn wz_router_hat_serves_its_resource_snapshot_beside_upstreams_admin_space() {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let (mut router, mut log, port, key, zid) = spawn_router(
        "router-hat serving its snapshot",
        &["--router-hat", "127.0.0.1:0"],
    );
    let admin_root = format!("@/{zid}/router/**");

    // The first session: the snapshot is served to its own key and to a wildcard over the `@`
    // space of `wz`, and upstream's admin space and `wz/**` do not meet it.
    let first = probe(
        &mut router,
        &mut log,
        port,
        &[&key, "wz/@/**", &admin_root, "@/**", "wz/**"],
    );
    for n in [1, 2] {
        let keys = reply_keys(&first, n);
        assert!(
            keys.contains(&key),
            "step {n}: the snapshot is served under its key: {keys:?}\n--- probe ---\n{first}"
        );
    }
    assert_eq!(
        reply_keys(&first, 1),
        vec![key.clone()],
        "step 1: one reply, under the snapshot's key"
    );
    let body = body_of(&first, 1);
    for fact in ["{\"version\":1,", "\"heap\":null,", "\"resource-snapshot\""] {
        assert!(body.contains(fact), "the snapshot lacks {fact}\n{body}");
    }
    if cfg!(target_os = "linux") {
        assert!(
            number_of(&body, "tasks").is_some_and(|tasks| tasks >= 1),
            "a Linux host counts its threads\n{body}"
        );
    }
    for n in [3, 4] {
        let keys = reply_keys(&first, n);
        assert!(
            !keys.is_empty(),
            "step {n}: the admin space answers\n--- probe ---\n{first}"
        );
        assert!(
            keys.iter().all(|k| k.starts_with("@/")),
            "step {n}: every upstream admin reply is keyed under `@/`: {keys:?}"
        );
        assert!(
            !keys.contains(&key),
            "step {n}: the snapshot is not part of upstream's admin space"
        );
    }
    assert!(
        reply_keys(&first, 5).is_empty(),
        "a wildcard over `wz` does not reach into the verbatim `@` space\n--- probe ---\n{first}"
    );

    // A period later, with the first session gone, the snapshot is a newer one, and the router has
    // counted the messages of both sessions: what the first received is in the total, which has
    // not fallen back to what the second has received alone.
    std::thread::sleep(PAST_THE_PERIOD);
    let second = probe(&mut router, &mut log, port, &[&key]);
    stop(router);
    let later = body_of(&second, 1);
    let sequence = number_of(&later, "sequence").expect("a sequence number");
    assert!(
        sequence >= 1,
        "a period on, the snapshot is a later one, not the first: {later}"
    );
    let messages = number_of(&later, "messages").expect("a message count");
    assert!(
        messages >= 2,
        "the router has received the handshakes of two sessions: {later}"
    );
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,adminspace-router-linkstate,adminspace-read,resource-snapshot + wz-e2e-admin-probe); Layer E7g runs via --ignored"]
fn wz_router_hat_answers_no_snapshot_when_admin_read_is_denied() {
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
