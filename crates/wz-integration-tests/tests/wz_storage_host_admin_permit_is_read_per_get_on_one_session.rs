// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2745 (open-debt item 665) — the `adminspace-read` permit is re-read on
//! every GET, witnessed on ONE session.
//!
//! ## The gap this closes, and why it is not the test next door
//!
//! `wz_storage_host_adminspace_read_permit_flips_over_the_wire` already drives
//! GRANT -> REVOKE -> RE-GRANT against this host with three pico `z_get`s and
//! two `z_put`s, and it is a real witness — of PER-CONNECTION liveness. A
//! stock pico `z_get` is a one-shot process, so each of those GETs arrives on
//! its own connection, and a host that resolved the permit once per connection
//! would answer all three exactly the same way.
//!
//! R2374 MEASURED that rather than arguing it: freezing the permit beside
//! `get_cfg` — precisely the defect the atom's residual names — left all three
//! of that lane's tests GREEN. The residual has been exactly the distance
//! between per-connection and per-GET ever since, and it is not academic here:
//! this host multi-accepts and serves many GETs on one client session, so a
//! per-connection resolve is the frozen permit again, scoped to a session.
//!
//! The instrument was missing, not the property. `wz-e2e-admin-probe` (R2745)
//! is that instrument: it DIALS, holds ONE session, and runs an ordered
//! GET -> PUT -> GET script on it.
//!
//! ## What makes this a per-GET witness
//!
//! One probe PROCESS, one session, one connection, and the permit revoked
//! between the two GETs on it. A host that captured the permit at setup
//! answers both GETs the same way; a host that re-read it at CONNECTION setup
//! also answers both the same way, because there is only one connection here
//! and it predates the revoke. Only a host that re-reads it per REQUEST can
//! answer the second GET differently — which is the whole of the distinction
//! the residual names.
//!
//! ## The population, not just the absence
//!
//! The first GET is the population: it must answer with at least one reply. An
//! absence asserted without it is satisfied by a host that answers nothing at
//! all — a session that never reached the admin surface, a selector that
//! matched nothing, a probe whose reply plane was compiled out. The test reads
//! BOTH counts off the probe's own `replies=` lines.
//!
//! ## Why the probe's count and not its verdict
//!
//! The probe reports `replies=<n>` and knows nothing about permits. What
//! `n == 0` MEANS on this host is this file's reading, which keeps the
//! instrument reusable for the peer and router-hat hosts that make the same
//! live-slice claim.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, graceful_terminate, read_captured, wait_for_substring,
    wz_ap_demo_binary, wz_e2e_admin_probe_binary, ChildGuard, PortReservation,
};

/// How long the probe's whole script may take. Generous against the host's
/// readiness and the two round trips; the probe bounds each STEP itself and
/// says so in its log, so a timeout here is a process that never finished
/// rather than a step that hung silently.
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(30);

// wz-proves: adminspace-read wz->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features adminspace-config-hotreload,adminspace-read,adminspace-write + wz-e2e-admin-probe); Layer E6j runs via --ignored"]
fn wz_storage_host_admin_read_permit_is_resolved_per_get_not_per_connection() {
    let demo = wz_ap_demo_binary();
    // The host must be the build that parses `--config-write-permit` and
    // compiles both gates in; an older binary would ignore the flag, refuse
    // the PUT, and the failure would read as "the permit never moved" rather
    // than "the binary is stale".
    assert_demo_binary_newer_than_sources(&demo);
    let probe = wz_e2e_admin_probe_binary();
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

    let h_stderr = tempfile::tempfile().expect("tempfile for storage-host stderr");
    let h_writer = h_stderr
        .try_clone()
        .expect("dup storage-host stderr handle");
    let mut h_reader = h_stderr;

    // Starts PERMISSIVE (no `--no-admin-read`): the wire takes the permit
    // away mid-session, which is the event the second GET must see.
    let mut h_child = ChildGuard::wrap(
        "wz-ap-demo storage host (--storage-host --config-write-permit)",
        Command::new(&demo)
            .arg("--storage-host")
            .arg(&addr)
            .arg("--config-write-permit")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(h_writer))
            .spawn()
            .expect("spawn wz-ap-demo storage host"),
    );

    let h_captured = match wait_for_substring(
        &mut h_reader,
        "adminspace config GET at ",
        Duration::from_secs(5),
    ) {
        Ok(c) => c,
        Err(c) => {
            let _ = h_child.child_mut().kill();
            let _ = h_child.child_mut().wait();
            panic!("storage host never registered its admin host within 5s\n--- host ---\n{c}");
        }
    };
    // Both gates ACTIVE and in the state this test needs, asserted rather than
    // assumed: with `adminspace-read` compiled out the permit line reads
    // `= true` whatever happens, and the revoke below would prove nothing.
    assert!(
        h_captured.contains("adminspace read permit = true"),
        "this host must START permissive\n--- host ---\n{h_captured}"
    );
    assert!(
        h_captured.contains("adminspace write permit = true"),
        "--config-write-permit must grant the write gate; without it the PUT below is \
         refused and the permit never moves\n--- host ---\n{h_captured}"
    );
    let config_key = h_captured
        .lines()
        .find_map(|l| {
            l.split_once("adminspace config GET at ")
                .map(|(_, rest)| rest.trim().to_string())
        })
        .expect("the storage host logged its admin config keyexpr");
    let root = config_key
        .strip_suffix("/config")
        .expect("config key ends with /config")
        .to_string();
    drop(port_res);

    // ── ONE probe process: GET, revoke, GET. All three on one session. ──
    let p_stderr = tempfile::tempfile().expect("tempfile for probe stderr");
    let p_writer = p_stderr.try_clone().expect("dup probe stderr handle");
    let mut p_reader = p_stderr;

    let mut p_child = ChildGuard::wrap(
        "wz-e2e-admin-probe (get -> revoke -> get on one session)",
        Command::new(&probe)
            .arg("--connect")
            .arg(&addr)
            .arg("--get")
            .arg(format!("{root}/**"))
            .arg("--put")
            .arg(format!("{root}/config/admin-read=false"))
            .arg("--get")
            .arg(format!("{root}/**"))
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(p_writer))
            .spawn()
            .expect("spawn wz-e2e-admin-probe"),
    );

    let p_captured =
        match wait_for_substring(&mut p_reader, "SCRIPT COMPLETE steps=3", SCRIPT_TIMEOUT) {
            Ok(c) => c,
            Err(c) => {
                let host = read_captured(&mut h_reader);
                let _ = p_child.child_mut().kill();
                let _ = p_child.child_mut().wait();
                let _ = h_child.child_mut().kill();
                let _ = h_child.child_mut().wait();
                panic!(
                    "the probe never finished its three-step script\n--- probe ---\n{c}\n\
                 --- host ---\n{host}"
                );
            }
        };

    // The host must have APPLIED the revoke. Read from the host rather than
    // inferred from the probe's PUT succeeding: a Push that left the probe and
    // a permit that moved are different facts, and only the second one makes
    // the second GET's count mean anything.
    let h_after = match wait_for_substring(
        &mut h_reader,
        "adminspace read permit set to false over the wire",
        Duration::from_secs(10),
    ) {
        Ok(c) => c,
        Err(c) => {
            let _ = p_child.child_mut().kill();
            let _ = p_child.child_mut().wait();
            let _ = h_child.child_mut().kill();
            let _ = h_child.child_mut().wait();
            panic!(
                "the host never applied the admin-read revoke the probe PUT\n--- host ---\n{c}\n\
                 --- probe ---\n{p_captured}"
            );
        }
    };

    let first = step_reply_count(&p_captured, 1);
    let third = step_reply_count(&p_captured, 3);

    graceful_terminate(p_child.child_mut(), Duration::from_secs(5));
    graceful_terminate(h_child.child_mut(), Duration::from_secs(5));

    // THE POPULATION. Without this the absence below is satisfied by a probe
    // that reached nothing.
    assert!(
        first >= 1,
        "the permissive host must serve its admin surface to the probe's FIRST GET, \
         or the second GET's absence is asserted against nothing\n--- probe ---\n{p_captured}\n\
         --- host ---\n{h_after}"
    );
    // THE WITNESS. Same session, same connection, permit revoked in between.
    assert_eq!(
        third, 0,
        "a GET issued AFTER the wire revoked the permit, ON THE SAME SESSION as the \
         first, must be denied. A non-zero count here is the permit being resolved \
         once per CONNECTION (or once per process) rather than per request — the \
         distinction open-debt item 665 exists for, and the one a one-shot pico \
         client cannot see.\n--- probe ---\n{p_captured}\n--- host ---\n{h_after}"
    );
}

/// The `replies=<n>` the probe printed for a given step.
///
/// PANICS rather than defaulting when the line is absent: a missing step line
/// means the script did not run that step, and reading that as `0` would turn
/// "the probe never asked" into "the host denied" — the same verdict from the
/// opposite cause, which is the failure mode this whole file is about.
fn step_reply_count(captured: &str, step: usize) -> usize {
    let needle = format!("STEP {step} GET ");
    let line = captured
        .lines()
        .filter(|l| l.contains(&needle) && l.contains("FINAL replies="))
        .next_back()
        .unwrap_or_else(|| {
            panic!("the probe logged no FINAL for step {step}\n--- probe ---\n{captured}")
        });
    line.rsplit_once("replies=")
        .map(|(_, n)| n.trim())
        .and_then(|n| n.parse::<usize>().ok())
        .unwrap_or_else(|| panic!("unparseable reply count in {line:?}"))
}
