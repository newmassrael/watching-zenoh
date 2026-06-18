// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311qg — peer-MESH e2e: `wz-ap-demo --peer` DIALS a configured peer AND
//! accepts inbound, holding BOTH directions' faces at once (the `routing-peer`
//! catalog atom's foundation), distinct from the accept-only `--router` and the
//! one-shot `--listen` acceptor.
//!
//! Topology (all the `--features routing-peer` binary):
//!   - peer B: `--peer <addr_B>` with NO `--connect` — a pure acceptor (its dial
//!     set is empty), the dial target peer A reaches OUT to.
//!   - peer A: `--peer <addr_A> --connect <addr_B>` — dials B (its OUTBOUND mesh
//!     leg, face id 0, reserved before any accept) AND listens on addr_A.
//!   - client C: `--connect <addr_A> --key …` — a single-session initiator that
//!     dials A, so A ACCEPTS it (face id 1).
//!
//! Peer A therefore holds two faces from two SOURCES at once — one dialed
//! (to B), one accepted (from C) — so its shutdown summary reports `dialed 1,
//! accepted 1` and `peak 2 concurrent`. That dial+accept split is the property
//! a one-sided acceptor (`--router`) or one-sided dialer could never produce: it
//! is what makes A a mesh node. (Face id 0 is the dial because `peer_loop` seeds
//! the outbound dial into the open set before the accept loop assigns any id.)
//!
//! Requires the binary built with `--features routing-peer` (the `--peer` arg is
//! opt-in behind it; a default build rejects it — see
//! `wz_peer_reject_without_feature`). run-ci's Layer E builds the binary with
//! the feature so this test rides the same `--ignored` lane as the other
//! binary-dep e2es.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_substring, wz_ap_demo_binary, ChildGuard,
    PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer); Layer E runs via --ignored"]
fn wz_peer_holds_a_dialed_and_an_accepted_face() {
    let demo = wz_ap_demo_binary();
    // TWO ports under ONE lock (pick_pair): the guard carries port_b, plus a
    // bare port_a. Calling `pick()` twice on this thread would re-enter the
    // process-global port mutex and DEADLOCK (the reservation holds the guard
    // for its lifetime); `pick_pair` is the two-port API. Held until BOTH B and
    // A have bound, then dropped for parallel Layer E tests.
    let (port_res, port_a) = PortReservation::pick_pair();
    let port_b = port_res.port();
    let addr_b = format!("127.0.0.1:{port_b}");
    let addr_a = format!("127.0.0.1:{port_a}");

    // ── peer B: --peer with no --connect → a pure acceptor (the dial target) ──
    let b_stderr = tempfile::tempfile().expect("tempfile for peer-B stderr");
    let b_writer = b_stderr.try_clone().expect("dup peer-B stderr handle");
    let mut b_reader = b_stderr;
    let mut b_guard = ChildGuard::wrap(
        "wz-ap-demo peer-B (--peer)",
        Command::new(&demo)
            .arg("--peer")
            .arg(&addr_b)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(b_writer))
            .spawn()
            .expect("spawn wz-ap-demo peer-B"),
    );
    let b_bound = wait_for_substring(&mut b_reader, "peer: listening on", Duration::from_secs(5));
    if let Err(captured) = &b_bound {
        let _ = b_guard.child_mut().kill();
        let _ = b_guard.child_mut().wait();
        panic!(
            "peer-B did not log 'peer: listening on' within 5s (is the binary built with \
             --features routing-peer?)\n--- peer-B stderr ---\n{captured}"
        );
    }
    // Hold the port guard until peer A has also bound (both ports reserved).

    // ── peer A: dials B (outbound, face 0) AND listens on addr_A ──
    let a_stderr = tempfile::tempfile().expect("tempfile for peer-A stderr");
    let a_writer = a_stderr.try_clone().expect("dup peer-A stderr handle");
    let mut a_reader = a_stderr;
    let mut a_guard = ChildGuard::wrap(
        "wz-ap-demo peer-A (--peer --connect)",
        Command::new(&demo)
            .arg("--peer")
            .arg(&addr_a)
            .arg("--connect")
            .arg(&addr_b)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(a_writer))
            .spawn()
            .expect("spawn wz-ap-demo peer-A"),
    );
    let a_bound = wait_for_substring(&mut a_reader, "peer: listening on", Duration::from_secs(5));
    if let Err(captured) = &a_bound {
        let _ = a_guard.child_mut().kill();
        let _ = a_guard.child_mut().wait();
        let _ = b_guard.child_mut().kill();
        let _ = b_guard.child_mut().wait();
        panic!(
            "peer-A did not log 'peer: listening on' within 5s\n--- peer-A stderr ---\n{captured}"
        );
    }
    drop(port_res);

    // A's outbound dial to B reaches Established first — face id 0 is reserved for
    // the dial before any accept (peer_loop seeds it before the loop).
    let a_face0 = wait_for_substring(&mut a_reader, "peer: face 0 UP", Duration::from_secs(10));

    // ── client C: a single-session initiator that dials A (A accepts → face 1) ──
    let c_stderr = tempfile::tempfile().expect("tempfile for client-C stderr");
    let c_writer = c_stderr.try_clone().expect("dup client-C stderr handle");
    let mut c_reader: File = c_stderr;
    let mut c_guard = ChildGuard::wrap(
        "wz-ap-demo client-C (--connect)",
        Command::new(&demo)
            .arg("--connect")
            .arg(&addr_a)
            .arg("--key")
            .arg("demo/peer-mesh")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(c_writer))
            .spawn()
            .expect("spawn wz-ap-demo client-C"),
    );
    let c_dial = wait_for_substring(&mut c_reader, "connected to", Duration::from_secs(5));

    // A now holds BOTH faces: the dialed one (to B, id 0) and the accepted one
    // (from C, id 1). Waiting for both UP lines guarantees peak 2.
    let a_face1 = wait_for_substring(&mut a_reader, "peer: face 1 UP", Duration::from_secs(10));

    // Graceful-shutdown peer A → it logs its peer-loop summary, which carries
    // the convergence witness asserted below.
    graceful_terminate(a_guard.child_mut(), Duration::from_secs(5));
    let a_captured = read_captured(&mut a_reader);

    // Reap B and C (A's shutdown closed C's socket; B holds an idle face).
    let _ = c_guard.child_mut().kill();
    let _ = c_guard.child_mut().wait();
    let _ = b_guard.child_mut().kill();
    let _ = b_guard.child_mut().wait();
    let b_captured = read_captured(&mut b_reader);
    let c_captured = read_captured(&mut c_reader);
    eprintln!("--- peer-A stderr ---\n{a_captured}");
    eprintln!("--- peer-B stderr ---\n{b_captured}");
    eprintln!("--- client-C stderr ---\n{c_captured}");

    // Diagnostics first, then assert.
    a_face0.unwrap_or_else(|c| {
        panic!(
            "peer-A did not log 'face 0 UP' (outbound dial to B) within 10s\n--- peer-A ---\n{c}"
        )
    });
    c_dial.unwrap_or_else(|c| {
        panic!("client-C did not log 'connected to' within 5s\n--- client-C ---\n{c}\n--- peer-A ---\n{a_captured}")
    });
    a_face1.unwrap_or_else(|c| {
        panic!("peer-A did not log 'face 1 UP' (accepted from C) within 10s\n--- peer-A ---\n{c}")
    });

    // c3d-4 / R311rf — beyond HOLDING the face, peer A must INGEST peer B's
    // link-state flood: real topology convergence over the wire (the
    // OAM_LINKSTATE carrier through the live session transport), not just a held
    // face. With distinct per-peer zids (each derived from its listen port) the
    // routing graph keys correctly, so A learns B's node. The register-time
    // bootstrap (R311rf) delivers B's state at face-up — so by shutdown A's
    // ingest count is >= 1 and the peer-loop summary emits this witness, which
    // it does ONLY when ingested > 0 (a held-but-never-converged face omits it).
    // Asserting at shutdown (not mid-run) is robust: the bootstrap converges at
    // face-up, well before A is terminated, with no dependence on flood timing.
    assert!(
        a_captured.contains("learned mesh topology"),
        "peer-A summary must report 'learned mesh topology' — it held the face \
         to B but never INGESTED B's link-state flood (topology did not converge \
         over the wire)\n--- peer-A stderr ---\n{a_captured}"
    );

    assert!(
        a_captured.contains("peak 2 concurrent"),
        "peer-A summary must report peak 2 concurrent faces (held the dialed AND the \
         accepted face at once)\n--- peer-A stderr ---\n{a_captured}"
    );
    assert!(
        a_captured.contains("dialed 1, accepted 1"),
        "peer-A summary must report the dial+accept split (dialed 1, accepted 1)\n\
         --- peer-A stderr ---\n{a_captured}"
    );
    // R311rc (c3d-4) — SOURCE WITNESS (the anticipated upgrade): now that the
    // LinkState routing graph keys on the zid, each peer derives a DISTINCT zid
    // from its listen port (`0x7072` + port). So peer-A's face to B carries B's
    // distinct `7072…` zid — NOT A's own, NOT the old shared hardcode. A
    // wrong-source bug (logging the local zid, or all-share-one) would no longer
    // pass. (The single-session client C is not a `--peer`, so it keeps the
    // fixed demo zid `01020304`; A's face-1 log carries that, A's face-0 log
    // carries B's `7072…` — both distinct from A's own.)
    assert!(
        a_captured.contains("zid 7072"),
        "peer-A face-0 log must carry B's DISTINCT derived zid (7072…) — proving \
         the handshake surfaced the remote's id, not a shared hardcode\n\
         --- peer-A stderr ---\n{a_captured}"
    );
}
