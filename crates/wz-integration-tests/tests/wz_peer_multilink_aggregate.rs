// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y213 (transport-multilink S2 slice-3) — the DEMO-BINARY multilink proof:
//! the `--peer` mesh mode, built `--features transport-multilink` and driven with
//! `--max-links 2`, AGGREGATES two physical links to one peer zid into ONE logical
//! unicast session — the production-reachability counterpart to the library
//! `session_multilink_deploy_e2e` (which drives `peer_loop` directly with a
//! test forwarder). This is what makes §5.1 multilink reachable from a real binary,
//! not just a hand-built harness.
//!
//! Topology (both binaries `--features transport-multilink`, ephemeral ports read
//! back from each peer's listen log):
//!   - peer B: `--peer 127.0.0.1:0 --subscribe demo/mesh --max-links 2` — the
//!     ACCEPT-side. Binds first so A can dial it; aggregates the two INBOUND links
//!     A opens (second accept JOINs the first's session instead of registering a
//!     redundant face). Subscribes so the aggregated session carries real traffic.
//!   - peer A: `--peer 127.0.0.1:0 --connect <B>,<B> --publish demo/mesh
//!     --max-links 2` — the DIAL-side. `--connect <B>,<B>` (the same address twice;
//!     the peer-mode `--connect` list is not deduped) makes A dial B TWICE, so A
//!     aggregates its two OUTBOUND links, and publishes into the mesh.
//!
//! So BOTH sides aggregate: A joins its 2nd outbound dial onto the 1st, B joins its
//! 2nd inbound accept onto the 1st. Each logs the demo-owned `link AGGREGATED to
//! zid ... (live links now 2)` witness — the R311y213 `AcceptEvent::LinkAggregated`
//! event rendered by `log_face_event`. Without that event a joined link is silent
//! (it never fires `FaceUp`), so a 2-link session would be byte-indistinguishable
//! from single-link at the demo's log level; the witness is what makes the
//! aggregation OBSERVABLE from a black-box binary. The `received mesh data` witness
//! on B additionally proves the aggregated session carries application traffic, not
//! just that the links formed.
//!
//! NAMED BOUND (explicit, not silent): this e2e proves AGGREGATION reachability +
//! observability. It does NOT re-prove per-link AUTO-RE-ADD (R311y212). Re-add is
//! WIRED by the same knob — `--max-links > 1` populates the dial-endpoint retention
//! map and arms `schedule_multilink_redial`, with no separate switch — and its
//! behaviour is proven at the library level by `session_multilink_readd_e2e`. But a
//! 2-process BLACK-BOX demo has no lever to sever exactly ONE link of an aggregate
//! while the session survives (killing a process drops ALL its links → whole-session
//! teardown, which is not the partial-loss re-add path). Exercising re-add from the
//! binary would need a new single-link-sever affordance, out of this slice.
//!
//! Requires the binary built with `--features transport-multilink` (pulls
//! `routing-peer`, so `--peer` / `--publish` / `--subscribe` are available, plus the
//! aggregation wiring). run-ci's multilink demo lane builds it, then runs this test
//! via the `--ignored` gate like the other binary-dep e2es.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, listen_port, read_captured, wait_for_substring, wz_ap_demo_binary,
    ChildGuard,
};

/// Spawn a `--peer` demo on an ephemeral port and wait until it binds, then read
/// the bound port back from its listen log. Returns the guard, its stderr reader,
/// and the port. (Mirrors the `spawn_peer` helper in `wz_peer_data_forward`.)
fn spawn_peer(label: &str, args: &[&str]) -> (ChildGuard, File, u16) {
    let stderr = tempfile::tempfile().expect("tempfile for peer stderr");
    let writer = stderr.try_clone().expect("dup peer stderr handle");
    let mut reader = stderr;
    let mut guard = ChildGuard::wrap(
        label.to_string(),
        Command::new(wz_ap_demo_binary())
            .args(args)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {label}: {e}")),
    );
    let captured = wait_for_substring(
        &mut reader,
        "peer: listening on 127.0.0.1:",
        Duration::from_secs(5),
    )
    .unwrap_or_else(|c| {
        let _ = guard.child_mut().kill();
        let _ = guard.child_mut().wait();
        panic!(
            "{label} did not bind within 5s (is the binary built with \
             --features transport-multilink?)\n--- {label} stderr ---\n{c}"
        );
    });
    let port = listen_port(&captured);
    (guard, reader, port)
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features transport-multilink); run-ci multilink lane runs via --ignored"]
fn wz_peer_multilink_aggregates_two_links_into_one_session() {
    // B (accept-side subscriber, max_links=2) binds first so A can dial it twice.
    let (mut b_guard, mut b_reader, p_b) = spawn_peer(
        "peer-B",
        &[
            "--peer",
            "127.0.0.1:0",
            "--subscribe",
            "demo/mesh",
            "--max-links",
            "2",
        ],
    );
    let addr_b = format!("127.0.0.1:{p_b}");
    // A dials B TWICE (the same address, comma-separated, not deduped) so it opens
    // two outbound links to the one peer zid and aggregates them; --max-links 2 lets
    // both the dial (A) and the accept (B) sides hold two links in one session.
    let dial_twice = format!("{addr_b},{addr_b}");
    let (mut a_guard, mut a_reader, _p_a) = spawn_peer(
        "peer-A",
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &dial_twice,
            "--publish",
            "demo/mesh",
            "--max-links",
            "2",
        ],
    );

    // DETERMINISTIC sync on the aggregation witnesses THEMSELVES — not on a
    // downstream data event whose arrival only *timing-implies* aggregation. Waiting
    // for each side's `link AGGREGATED ... (live links now 2)` BEFORE shutdown gives a
    // happens-before: the witness is logged (so it is in the post-shutdown capture)
    // by construction, never resting on the establishment(ms) ≪ convergence(s) margin.
    // The `live links now 2` phrase is emitted ONLY by the R311y213 LinkAggregated
    // event (a joined link never fires FaceUp), so matching it is positive proof of
    // aggregation into ONE session rather than two independent sessions forming.
    // A joined its two OUTBOUND dials to B:
    let a_agg = wait_for_substring(&mut a_reader, "live links now 2", Duration::from_secs(15));
    // B joined the two INBOUND links from A (the accept-side twin):
    let b_agg = wait_for_substring(&mut b_reader, "live links now 2", Duration::from_secs(15));
    // Then confirm the aggregated session carries application traffic — logged AFTER
    // aggregation (it needs subscription convergence + a publish tick), so this wait
    // starts from B's reader position past the aggregation line above.
    let b_data = wait_for_substring(&mut b_reader, "received mesh data", Duration::from_secs(15));

    // Graceful-shutdown both, then read their FULL captured logs (seek-to-0) for the
    // diagnostics + the formal assertions.
    graceful_terminate(a_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(b_guard.child_mut(), Duration::from_secs(5));
    let a_captured = read_captured(&mut a_reader);
    let b_captured = read_captured(&mut b_reader);
    eprintln!("--- peer-A stderr ---\n{a_captured}");
    eprintln!("--- peer-B stderr ---\n{b_captured}");

    // Diagnostics printed; now assert. An Err from a sync above means the witness
    // never appeared within 15s — a genuine failure of the aggregation path, not a
    // flake (the phrase is deterministic, emitted once per join at establishment).
    a_agg.unwrap_or_else(|c| {
        panic!(
            "peer-A never aggregated its two outbound dials to B into one session \
             (no 'live links now 2')\n--- peer-A stderr ---\n{c}"
        )
    });
    b_agg.unwrap_or_else(|c| {
        panic!(
            "peer-B never aggregated the two inbound links from A into one session \
             (no 'live links now 2')\n--- peer-B stderr ---\n{c}"
        )
    });
    // CONFIRMING witness — the aggregated session carries application traffic: A's
    // published demo/mesh Put reached B's subscription over the 2-link session.
    b_data.unwrap_or_else(|c| {
        panic!(
            "peer-B never received A's published data within 15s — the aggregated \
             session did not carry the subscribed traffic\n--- peer-B stderr ---\n{c}"
        )
    });
    // Belt-and-suspenders on the full capture: the distinctive AGGREGATED marker is
    // present on BOTH sides (the waits above already gated on it; this re-checks the
    // seek-to-0 capture so a regression in either surface is caught).
    assert!(
        a_captured.contains("link AGGREGATED to zid"),
        "peer-A capture missing the aggregation marker\n--- peer-A stderr ---\n{a_captured}"
    );
    assert!(
        b_captured.contains("link AGGREGATED to zid"),
        "peer-B capture missing the aggregation marker\n--- peer-B stderr ---\n{b_captured}"
    );
}
