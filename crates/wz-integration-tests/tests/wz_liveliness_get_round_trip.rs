// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! liveliness-get — wz↔wz end-to-end liveliness GET (snapshot) round-trip.
//!
//! Companion to `wz_liveliness_subscriber_round_trip.rs`. That test
//! exercises the FUTURE-streaming subscriber (ongoing Decl*Token fan-out);
//! this one exercises the one-shot CURRENT snapshot get
//! ([`Session::liveliness_get`]). The two share the declaration-plane wire
//! (Interest -> Declare(DeclToken) -> Declare(DeclFinal)) but differ in the
//! outer C/F bits: the subscriber sets FUTURE, the get sets CURRENT only.
//!
//! Wire-level flow:
//!   1. Acceptor: `wz-ap-demo --listen <addr> --declare-token demo/token`.
//!      Holds a `LivelinessToken` on `demo/token`. Its R283
//!      `LocalTokenRegistry` responds to inbound CURRENT liveliness
//!      Interests by replying with an `interest_id`-tagged
//!      `Declare(DeclToken)` per matching held token + a terminating
//!      `Declare(DeclFinal)`.
//!   2. Initiator: `wz-ap-demo --connect <addr> --liveliness-get demo/**`.
//!      Once Established, `liveliness_get_task` calls
//!      `Session::liveliness_get("demo/**", ...)`, emitting one
//!      `Interest(KE|TO|R|C)` (CURRENT, no FUTURE).
//!   3. The acceptor's `LocalTokenRegistry::respond_to_interest` matches
//!      `demo/token` against the `demo/**` pattern and replies with the
//!      interest_id-tagged DeclToken + DeclFinal.
//!   4. The initiator's `LivelinessGetRegistry::dispatch_declare`
//!      correlates the replies by interest_id, firing the get's `on_reply`
//!      (logged `LIVELINESS GET REPLY ... keyexpr='demo/token'`) then
//!      `on_final` (logged `LIVELINESS GET FINAL ...`) on the DeclFinal.
//!
//! Assertions gate every step:
//!   * Acceptor logs the outbound `DECLARED TOKEN id=0` line.
//!   * Initiator logs `LIVELINESS GET REPLY` with the resolved
//!     `keyexpr='demo/token'`, then `LIVELINESS GET FINAL`, in order.
//!
//! This proves the full requester-side vertical: the CURRENT Interest
//! emit (`build_interest_liveliness_get` + `send_interest_liveliness_get`),
//! the peer's responder, and the interest_id-correlated reply collection +
//! terminator on the requester (`LivelinessGetRegistry`). The byte-layout
//! of the Interest is locked separately by the
//! `build_interest_liveliness_get_emits_current_only_wire_bytes` unit test;
//! this end-to-end test cross-checks the full decode + dispatch path.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_substring, wz_ap_demo_binary, ChildGuard,
    PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo bin); Layer E runs via --ignored"]
fn wz_liveliness_get_round_trip_against_wz_acceptor() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let addr = format!("127.0.0.1:{port}");
    let token_keyexpr = "demo/token";
    let get_pattern = "demo/**";

    // ── wz acceptor: holds the LivelinessToken on demo/token and
    // responds to inbound CURRENT liveliness Interests via its
    // LocalTokenRegistry (R283 respond_to_interest). ─
    let acceptor_stderr = tempfile::tempfile().expect("tempfile for acceptor stderr");
    let acceptor_stderr_writer = acceptor_stderr
        .try_clone()
        .expect("dup acceptor stderr handle");
    let mut acceptor_stderr_reader = acceptor_stderr;

    let mut acceptor_child = ChildGuard::wrap(
        "wz-ap-demo acceptor (--listen --declare-token)",
        Command::new(&demo)
            .arg("--listen")
            .arg(&addr)
            .arg("--declare-token")
            .arg(token_keyexpr)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(acceptor_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --listen --declare-token"),
    );

    let bound = wait_for_substring(
        &mut acceptor_stderr_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = acceptor_child.child_mut().kill();
        let _ = acceptor_child.child_mut().wait();
        panic!(
            "wz-ap-demo --listen --declare-token did not log 'listening on' within 5s\n\
             --- captured acceptor stderr ---\n{captured}"
        );
    }
    drop(port_res);

    // ── wz initiator: issues a one-shot liveliness GET on demo/**. ─
    let initiator_stderr = tempfile::tempfile().expect("tempfile for initiator stderr");
    let initiator_stderr_writer = initiator_stderr
        .try_clone()
        .expect("dup initiator stderr handle");
    let mut initiator_stderr_reader = initiator_stderr;

    let mut initiator_child = ChildGuard::wrap(
        "wz-ap-demo initiator (--connect --liveliness-get)",
        Command::new(&demo)
            .arg("--connect")
            .arg(&addr)
            .arg("--liveliness-get")
            .arg(get_pattern)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(initiator_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect --liveliness-get"),
    );

    let dialed = wait_for_substring(
        &mut initiator_stderr_reader,
        "connected to",
        Duration::from_secs(5),
    );

    // The snapshot reply arrives after the initiator emits its CURRENT
    // Interest (Established-gated) and the acceptor's LocalTokenRegistry
    // responds. The acceptor's declare_task also emits a proactive
    // DeclToken, but the get reply is the interest_id-tagged one the
    // LivelinessGetRegistry correlates.
    let reply_substr = "LIVELINESS GET REPLY";
    let reply_captured = wait_for_substring(
        &mut initiator_stderr_reader,
        reply_substr,
        Duration::from_secs(10),
    );
    let final_substr = "LIVELINESS GET FINAL";
    let final_captured = wait_for_substring(
        &mut initiator_stderr_reader,
        final_substr,
        Duration::from_secs(5),
    );

    graceful_terminate(acceptor_child.child_mut(), Duration::from_secs(2));
    let _ = initiator_child.child_mut().kill();
    let _ = initiator_child.child_mut().wait();

    let acceptor_captured = read_captured(&mut acceptor_stderr_reader);
    let initiator_captured = read_captured(&mut initiator_stderr_reader);
    eprintln!("--- captured wz acceptor stderr ---\n{acceptor_captured}");
    eprintln!("--- captured wz initiator stderr ---\n{initiator_captured}");

    if let Err(c) = &dialed {
        panic!(
            "wz-ap-demo --connect did not log 'connected to' within 5s — initiator \
             TCP dial against {addr} failed.\n\
             --- captured initiator stderr ---\n{c}\n\
             --- captured acceptor stderr ---\n{acceptor_captured}"
        );
    }

    // Acceptor-side trace: declare_task logs DECLARED TOKEN once the
    // token is held (the source of the matching get reply).
    assert!(
        acceptor_captured.contains("DECLARED TOKEN id=0"),
        "acceptor stderr lacks 'DECLARED TOKEN id=0' — Session::declare_token \
         did not fire on the acceptor side.\n--- acceptor stderr ---\n{acceptor_captured}"
    );

    let reply_text = match reply_captured {
        Ok(c) => c,
        Err(c) => panic!(
            "wz initiator did not log '{reply_substr}' within 10s — the liveliness-get \
             round-trip regressed between the CURRENT Interest emit (initiator) and \
             LivelinessGetRegistry::dispatch_declare (initiator, on the acceptor's \
             interest_id-tagged DeclToken reply).\n\
             --- captured initiator stderr at deadline ---\n{c}\n\
             --- captured acceptor stderr at deadline ---\n{acceptor_captured}"
        ),
    };
    let expected_reply =
        format!("LIVELINESS GET REPLY filter='{get_pattern}' keyexpr='{token_keyexpr}'");
    assert!(
        reply_text.contains(&expected_reply),
        "initiator stderr missing expected GET REPLY line:\n  expected: {expected_reply}\n\
         --- initiator stderr ---\n{reply_text}"
    );

    let final_text = match final_captured {
        Ok(c) => c,
        Err(c) => panic!(
            "wz initiator did not log '{final_substr}' within 5s — the terminating \
             Declare(DeclFinal) was not collected by LivelinessGetRegistry \
             (on_final never fired).\n--- captured initiator stderr at deadline ---\n{c}\n\
             --- captured acceptor stderr ---\n{acceptor_captured}"
        ),
    };
    assert!(
        final_text.contains("LIVELINESS GET FINAL interest_id="),
        "initiator stderr missing expected GET FINAL line:\n--- initiator stderr ---\n{final_text}"
    );
}
