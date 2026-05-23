// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R282 — wz↔wz end-to-end LivelinessSubscriber round-trip test.
//!
//! Companion to `wz_remote_declare_round_trip.rs` (R121k-5 +
//! R278 graceful shutdown). That test exercises the generic
//! [`LivelinessRegistry`](wz_runtime_tokio::declare::LivelinessRegistry)
//! observer fan-out — every peer `Decl*Token` fires every installed
//! callback regardless of keyexpr. This test exercises the
//! keyexpr-filtered counterpart [`LivelinessSubscriberRegistry`]
//! (R280): only peer tokens whose resolved keyexpr matches the
//! subscriber's pattern fire the callback, and the sample carries
//! a typed `kind` discriminator (`PUT` for DeclToken arrival,
//! `DELETE` for UndeclToken arrival).
//!
//! Wire-level flow:
//!   1. Acceptor: `wz-ap-demo --listen <addr> --declare-token demo/token`.
//!      The acceptor's `declare_task` emits one `Declare(DeclToken)`
//!      once the session reaches Established. The
//!      [`Session::declare_token`](wz_runtime_tokio::session::Session::declare_token)
//!      call allocates `token_id = 0` (per-session counter, R277).
//!   2. Initiator: `wz-ap-demo --connect <addr> --liveliness-subscribe demo/**`.
//!      The initiator's `run_demo` calls
//!      `Session::declare_liveliness_subscriber("demo/**", ...)` BEFORE
//!      drive_session starts, registering a slot in
//!      [`LivelinessSubscriberRegistry`] keyed by `interest_id = 0` and
//!      emitting one `Interest(KE|TO|R|F)` frame at Established
//!      (`Session::declare_liveliness_subscriber` calls
//!      `SessionLinkActions::send_interest_liveliness_subscriber`).
//!   3. The acceptor's `Declare(DeclToken)` arrives at the initiator.
//!      `parse_frame_payload` decodes the envelope into
//!      `NetworkMessage::Declare(DeclToken{id=0, keyexpr=demo/token})`.
//!      [`ApplicationLayerObserver::dispatch_event`] fans the event
//!      into `liveliness_subscribers`, which matches `demo/token`
//!      against the `demo/**` pattern (`**` matches one chunk) and
//!      fires the wz-ap-demo PUT callback, logging
//!      `LIVELINESS SAMPLE PUT filter='demo/**' keyexpr='demo/token'
//!      token_id=0`.
//!   4. SIGTERM the acceptor (R278 graceful shutdown). The held
//!      `LivelinessToken` drops, emitting `Declare(UndeclToken{id=0})`
//!      on the wire. The initiator's
//!      [`LivelinessSubscriberRegistry::dispatch_declare`] looks up
//!      `peer_token_table[0] = "demo/token"`, fans a
//!      `LivelinessSampleKind::Delete` sample to every matching
//!      subscriber slot, and the callback logs
//!      `LIVELINESS SAMPLE DELETE filter='demo/**' keyexpr='demo/token'
//!      token_id=0`.
//!
//! Assertions gate every step:
//!   * Acceptor logs the outbound `DECLARED TOKEN` line.
//!   * Initiator logs PUT then DELETE in order with the same
//!     `token_id` value.
//!   * Wildcard pattern actually matches the literal keyexpr (the
//!     subscriber pattern `demo/**` covers the acceptor's
//!     `demo/token` per zenoh-pico `**` semantics).
//!
//! Why this test rather than a smaller in-process integration:
//! the cross-process path proves the OUTBOUND
//! `Session::declare_liveliness_subscriber` → wire-side `Interest`
//! emit AND the INBOUND `NetworkMessage::Interest` /
//! `NetworkMessage::Declare` decode + dispatch in one shot. A pure
//! in-process test would skip the wire encode/decode round-trip
//! and miss any regression on the Interest body shape byte-layout
//! (which the R279 unit tests already cover at the builder level,
//! but the end-to-end test cross-checks the full path).

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_substring, wz_ap_demo_binary, ChildGuard,
    PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo bin); Layer E runs via --ignored"]
fn wz_liveliness_subscriber_round_trip_against_wz_acceptor() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let addr = format!("127.0.0.1:{port}");
    let token_keyexpr = "demo/token";
    let subscribe_pattern = "demo/**";

    // ── wz acceptor: declares the LivelinessToken on demo/token. ─
    // The token's Drop emits Declare(UndeclToken) on SIGTERM-driven
    // graceful shutdown; that is the source of the initiator's
    // DELETE sample.
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

    // ── wz initiator: declares LivelinessSubscriber on demo/**. ─
    // The wildcard `**` covers the literal `demo/token` per zenoh-pico
    // keyexpr matching semantics. The wz-ap-demo binary's PUT/DELETE
    // callback logs to stderr as `LIVELINESS SAMPLE PUT/DELETE
    // filter=... keyexpr=... token_id=...`.
    let initiator_stderr = tempfile::tempfile().expect("tempfile for initiator stderr");
    let initiator_stderr_writer = initiator_stderr
        .try_clone()
        .expect("dup initiator stderr handle");
    let mut initiator_stderr_reader = initiator_stderr;

    let mut initiator_child = ChildGuard::wrap(
        "wz-ap-demo initiator (--connect --liveliness-subscribe)",
        Command::new(&demo)
            .arg("--connect")
            .arg(&addr)
            .arg("--liveliness-subscribe")
            .arg(subscribe_pattern)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(initiator_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect --liveliness-subscribe"),
    );

    let dialed = wait_for_substring(
        &mut initiator_stderr_reader,
        "connected to",
        Duration::from_secs(5),
    );

    // The PUT sample arrives at the initiator after the acceptor's
    // declare_task emits its DeclToken (acceptor side has a 100 ms
    // inter-emit gate inside declare_task; with only token declared
    // the first matching record arrives within ~200 ms of dial).
    let put_substr = "LIVELINESS SAMPLE PUT";
    let put_captured = wait_for_substring(
        &mut initiator_stderr_reader,
        put_substr,
        Duration::from_secs(10),
    );

    // Trigger graceful shutdown on the acceptor — the held
    // LivelinessToken's Drop emits Declare(UndeclToken{id=0}). The
    // initiator's LivelinessSubscriberRegistry::dispatch_declare
    // looks up `peer_token_table[0]` and fans the DELETE sample.
    graceful_terminate(acceptor_child.child_mut(), Duration::from_secs(2));

    let delete_substr = "LIVELINESS SAMPLE DELETE";
    let delete_captured = wait_for_substring(
        &mut initiator_stderr_reader,
        delete_substr,
        Duration::from_secs(5),
    );

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

    let put_text = match put_captured {
        Ok(c) => c,
        Err(c) => panic!(
            "wz initiator did not log '{put_substr}' within 10s — LivelinessSubscriber \
             round-trip regressed between DeclToken emit (acceptor side) and \
             LivelinessSubscriberRegistry::dispatch_declare (initiator side).\n\
             --- captured initiator stderr at deadline ---\n{c}\n\
             --- captured acceptor stderr at deadline ---\n{acceptor_captured}"
        ),
    };

    // PUT line shape: filter + keyexpr + token_id all present.
    let expected_put = format!(
        "LIVELINESS SAMPLE PUT filter='{subscribe_pattern}' keyexpr='{token_keyexpr}' token_id=0"
    );
    assert!(
        put_text.contains(&expected_put),
        "initiator stderr missing expected PUT line:\n  expected: {expected_put}\n\
         --- initiator stderr ---\n{put_text}"
    );

    // Acceptor-side trace: declare_task logs DECLARED TOKEN once
    // send_declare_token fires (the source of the matching PUT on
    // the initiator side).
    assert!(
        acceptor_captured.contains("DECLARED TOKEN id=0"),
        "acceptor stderr lacks 'DECLARED TOKEN id=0' — \
         Session::declare_token did not fire on the acceptor side.\n\
         --- acceptor stderr ---\n{acceptor_captured}"
    );

    // DELETE line shape: same filter + keyexpr + token_id as the
    // matching PUT. The keyexpr is resolved from the registry's
    // peer_token_table at UndeclToken arrival (UndeclToken carries
    // only id; the registry's bookkeeping is what makes the DELETE
    // sample's keyexpr equal the prior PUT's).
    let delete_text = match delete_captured {
        Ok(c) => c,
        Err(c) => panic!(
            "wz initiator did not log '{delete_substr}' within 5s — \
             LivelinessSubscriber DELETE path regressed. Likely causes: \
             (a) graceful shutdown UndeclToken not emitted (R278 path \
             regression); (b) LivelinessSubscriberRegistry peer_token_table \
             not populated on the prior DeclToken arrival; (c) the \
             UndeclToken's id resolution against peer_token_table failed; \
             (d) the wildcard pattern stopped matching the resolved \
             keyexpr.\n\
             --- captured initiator stderr at deadline ---\n{c}\n\
             --- captured acceptor stderr ---\n{acceptor_captured}"
        ),
    };
    let expected_delete = format!(
        "LIVELINESS SAMPLE DELETE filter='{subscribe_pattern}' keyexpr='{token_keyexpr}' token_id=0"
    );
    assert!(
        delete_text.contains(&expected_delete),
        "initiator stderr missing expected DELETE line:\n  expected: {expected_delete}\n\
         --- initiator stderr ---\n{delete_text}"
    );
}

