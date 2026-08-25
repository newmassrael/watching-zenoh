// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R121k-5 — wz↔wz inbound DECLARE 6 sub-types round-trip test.
//!
//! Pairs two wz-ap-demo instances on TCP loopback so the
//! `RemoteSubscriberRegistry` (R121k-2), `RemoteQueryableRegistry`
//! (R121k-3), and `LivelinessRegistry` (R121k-4) wiring landed
//! through the production observer (R121k-5) round-trips for every
//! inbound Decl arm — DeclSubscriber, DeclQueryable, DeclToken —
//! end-to-end on a real socket.
//!
//! Test flow:
//!   1. Pick a free TCP port.
//!   2. Spawn acceptor: `wz-ap-demo --listen <addr> \
//!         --key demo/sub --queryable demo/q --reply <text> \
//!         --declare-token demo/token`. The acceptor declares the
//!      subscriber + queryable through the REAL production routed declare
//!      path (`Session::declare_subscriber` / `declare_queryable`, R311ou /
//!      R311ow) plus a liveliness token, emitting one Decl of each kind once
//!      Established. Subscriber + Queryable entity ids are auto-allocated and
//!      parsed from the acceptor log + cross-referenced below (R311oy — the
//!      retired `--declare-subscriber` / `--declare-queryable` raw-emit hooks
//!      used hard-coded 1001 / 2001). Token id is auto-allocated by
//!      `SessionLinkActions::alloc_next_token_id`; the first call returns 0
//!      (per-session counter, independent of the sub / queryable id spaces).
//!   3. Wait up to 5s for the acceptor's stderr to contain
//!      "listening on" — bind succeeded.
//!   4. Spawn initiator: `wz-ap-demo --connect <addr> \
//!         --on-remote-subscriber-log --on-remote-queryable-log \
//!         --on-remote-liveliness-log`. The initiator installs
//!      a stderr-log callback on each of the three Remote* registries.
//!   5. Wait up to 5s for the initiator's stderr to contain
//!      "connected to" — dial succeeded.
//!   6. Wait up to 10s for the initiator's stderr to contain all three
//!      lines "REMOTE SUBSCRIBER DECLARED id=<auto> keyexpr='demo/sub'",
//!      "REMOTE QUERYABLE DECLARED id=<auto> keyexpr='demo/q'", and
//!      "REMOTE TOKEN DECLARED id=0 keyexpr='demo/token'" — proving
//!      the full path: TCP → stream envelope → Frame →
//!      parse_frame_payload → NetworkMessage::Declare →
//!      Remote*Registry → callback. The <auto> ids are cross-referenced
//!      against the acceptor's own DECLARED log (R311oy).
//!   7. Belt-and-suspenders id + keyexpr assertions so a regression
//!      on any of (id echo, keyexpr resolution, registry routing)
//!      localises here.
//!   8. R278 — SIGTERM the acceptor (the side holding the
//!      LivelinessToken) so its graceful-shutdown path runs:
//!      `shutdown_signal()` cancels `drive_session`, the held
//!      `LivelinessToken` drops, `Declare(UndeclToken)` emits on
//!      the wire, and the initiator's `LivelinessRegistry`
//!      callback logs `REMOTE TOKEN UNDECLARED id=0`. Assertion
//!      9 below gates that flow end-to-end.
//!   9. Wait for `REMOTE TOKEN UNDECLARED id=0` on initiator
//!      stderr (5 s budget) then SIGKILL the initiator.
//!
//! Why this consolidated test rather than three per-kind tests:
//! the three Remote* registries share the same observer fan-out and
//! the same FramePayload.messages slice in production — exercising
//! all three in one test confirms the parallel-dispatch contract
//! (R121k-4 declare::tests::three_registries_share_a_message_stream_independently
//! at the unit level) holds end-to-end. A regression on any one
//! kind localises through the per-line assertions below.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_substring, wz_ap_demo_binary, ChildGuard,
    PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo bin); Layer E runs via --ignored"]
fn wz_remote_declare_round_trip_against_wz_initiator() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let addr = format!("127.0.0.1:{port}");
    let sub_keyexpr = "demo/sub";
    let q_keyexpr = "demo/q";
    let token_keyexpr = "demo/token";
    // R311oy — `--queryable` requires `--reply`; the initiator never queries, so
    // this payload is unused on the wire, but the demo validates the pair.
    let reply_value = "demo-reply";

    // ── wz acceptor (R121d listener + R121k-5 declare emitter) ─
    let acceptor_stderr = tempfile::tempfile().expect("tempfile for acceptor stderr");
    let acceptor_stderr_writer = acceptor_stderr
        .try_clone()
        .expect("dup acceptor stderr handle");
    let mut acceptor_stderr_reader = acceptor_stderr;

    let mut acceptor_child = ChildGuard::wrap(
        "wz-ap-demo acceptor (--listen --key --queryable --declare-token)",
        Command::new(&demo)
            .arg("--listen")
            .arg(&addr)
            // R311oy — declare the subscriber + queryable through the REAL
            // production declare path (`--key` / `--queryable`, the routed
            // Session::declare_subscriber / declare_queryable that R311ou /
            // R311ow wired) instead of the retired low-level `--declare-subscriber`
            // / `--declare-queryable` raw-emit hooks. The wire `DeclSubscriber` /
            // `DeclQueryable` the initiator observes is identical; the entity ids
            // are now auto-allocated (parsed from the acceptor's own log below and
            // cross-referenced against the initiator echo), not hard-coded.
            .arg("--key")
            .arg(sub_keyexpr)
            .arg("--queryable")
            .arg(q_keyexpr)
            .arg("--reply")
            .arg(reply_value)
            .arg("--declare-token")
            .arg(token_keyexpr)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(acceptor_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --listen --key --queryable --declare-token"),
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
            "wz-ap-demo --listen --declare-* did not log 'listening on' within 5s\n\
             --- captured acceptor stderr ---\n{captured}"
        );
    }
    // R216 — acceptor bound, release the port-alloc mutex.
    drop(port_res);

    // ── wz initiator (R121f dialer + R121k-5 remote-log callbacks) ─
    let initiator_stderr = tempfile::tempfile().expect("tempfile for initiator stderr");
    let initiator_stderr_writer = initiator_stderr
        .try_clone()
        .expect("dup initiator stderr handle");
    let mut initiator_stderr_reader = initiator_stderr;

    let mut initiator_child = ChildGuard::wrap(
        "wz-ap-demo initiator (--connect --on-remote-*-log)",
        Command::new(&demo)
            .arg("--connect")
            .arg(&addr)
            .arg("--on-remote-subscriber-log")
            .arg("--on-remote-queryable-log")
            .arg("--on-remote-liveliness-log")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(initiator_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect --on-remote-*-log"),
    );

    let dialed = wait_for_substring(
        &mut initiator_stderr_reader,
        "connected to",
        Duration::from_secs(5),
    );

    // Wait for ALL THREE REMOTE * DECLARED lines (order-independent) BEFORE the
    // SIGTERM below, so the terminate cannot race a not-yet-arrived arm. R311ot:
    // all three outbound declares now emit synchronously pre-drive in run_demo
    // (subscriber → queryable → token), so they arrive in a deterministic order;
    // this wait stays order-independent on principle (it asserts presence, not
    // sequence). Each wait rescans the full accumulated capture; a missing arm
    // is reported precisely by the assertions below (with both captures).
    for decl in [
        "REMOTE SUBSCRIBER DECLARED",
        "REMOTE QUERYABLE DECLARED",
        "REMOTE TOKEN DECLARED",
    ] {
        if wait_for_substring(&mut initiator_stderr_reader, decl, Duration::from_secs(10)).is_err()
        {
            break;
        }
    }

    // R278 — graceful shutdown of the acceptor (the side holding the
    // LivelinessToken). SIGTERM triggers the `shutdown_signal()` arm
    // of wz-ap-demo's top-level `tokio::select!`, which cancels
    // `drive_session_until_terminal`, joins the spawned tasks, then
    // drops the held `LivelinessToken` BEFORE dropping `actions`.
    // The token's `Drop` impl emits `Declare(UndeclToken)` on the
    // wire; the initiator's `LivelinessRegistry` callback observes
    // it and logs `REMOTE TOKEN UNDECLARED id=0`. Hard SIGKILL
    // fallback caps the wait at 2 s so a wedged graceful path does
    // not block the test indefinitely.
    graceful_terminate(acceptor_child.child_mut(), Duration::from_secs(2));

    // Once the acceptor has exited gracefully (UndeclToken on the
    // wire), give the initiator a window to drain its inbound queue
    // and log the corresponding `REMOTE TOKEN UNDECLARED` line. 5 s
    // is generous — the actual interval is dominated by the TCP
    // stream drain + observer dispatch, both well under 100 ms in
    // local-loopback runs.
    let undecl_substr = "REMOTE TOKEN UNDECLARED";
    let undecl_captured = wait_for_substring(
        &mut initiator_stderr_reader,
        undecl_substr,
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

    // R311os — all three declares were gated above (waited before SIGTERM), so
    // this post-teardown snapshot contains every REMOTE * DECLARED line; assert
    // against it directly. (Pre-R311os this rebound the token-wait capture,
    // which — now the token is no longer last — would miss the later arms.)
    let final_text = &initiator_captured;

    // R311oy — the subscriber + queryable entity ids are auto-allocated by the
    // routed declare path (`--key` / `--queryable`), so parse them from the
    // acceptor's own DECLARED log and cross-reference the SAME id against the
    // initiator echo. This asserts the round-trip fidelity ("the id the acceptor
    // emitted is the id the initiator observed") more faithfully than the prior
    // hard-coded 1001 / 2001 constants, AND exercises the real production declare
    // path rather than the retired raw-emit hook. The parse-or-panic doubles as
    // the acceptor-side "outbound declare fired" gate (it replaces the former
    // `DECLARED SUBSCRIBER id=1001` / `DECLARED QUERYABLE id=2001` checks).
    let sub_id = extract_id_after(&acceptor_captured, "DECLARED ROUTED SUBSCRIBER id=")
        .unwrap_or_else(|| {
            panic!(
                "acceptor stderr lacks 'DECLARED ROUTED SUBSCRIBER id=' — \
                 Session::declare_subscriber (--key) did not emit.\n\
                 --- acceptor stderr ---\n{acceptor_captured}"
            )
        });
    let q_id = extract_id_after(&acceptor_captured, "DECLARED ROUTED QUERYABLE id=")
        .unwrap_or_else(|| {
            panic!(
                "acceptor stderr lacks 'DECLARED ROUTED QUERYABLE id=' — \
                 Session::declare_queryable (--queryable) did not emit.\n\
                 --- acceptor stderr ---\n{acceptor_captured}"
            )
        });

    // All three Decl arms must surface on the initiator side. The exact line
    // shape (id literal + keyexpr literal) catches both id-echo regressions and
    // keyexpr-resolution regressions in one assertion per arm.
    assert!(
        final_text.contains(&format!(
            "REMOTE SUBSCRIBER DECLARED id={sub_id} keyexpr='{sub_keyexpr}'"
        )),
        "initiator stderr missing 'REMOTE SUBSCRIBER DECLARED id={sub_id} \
         keyexpr={sub_keyexpr}' (the id the acceptor emitted) — \
         RemoteSubscriberRegistry dispatch regressed.\n\
         --- initiator stderr ---\n{final_text}"
    );
    assert!(
        final_text.contains(&format!(
            "REMOTE QUERYABLE DECLARED id={q_id} keyexpr='{q_keyexpr}'"
        )),
        "initiator stderr missing 'REMOTE QUERYABLE DECLARED id={q_id} \
         keyexpr={q_keyexpr}' (the id the acceptor emitted) — \
         RemoteQueryableRegistry dispatch regressed.\n\
         --- initiator stderr ---\n{final_text}"
    );
    // R277 — token id comes from `SessionLinkActions::alloc_next_token_id`, a
    // per-session AtomicU64 counter INDEPENDENT of the subscriber / queryable id
    // spaces, so it stays 0 even though `--key` / `--queryable` now allocate
    // their own entity ids first (R311oy).
    assert!(
        final_text.contains(&format!(
            "REMOTE TOKEN DECLARED id=0 keyexpr='{token_keyexpr}'"
        )),
        "initiator stderr missing REMOTE TOKEN DECLARED line — \
         LivelinessRegistry dispatch regressed.\n\
         --- initiator stderr ---\n{final_text}"
    );

    // Acceptor-side token trace: the demo logs "DECLARED TOKEN id=0" when
    // `Session::declare_token` fires. (The subscriber / queryable outbound-emit
    // gate is the parse-or-panic above.) Both sides land iff the round-trip
    // completed: the initiator REMOTE * DECLARED lines prove the INBOUND dispatch.
    assert!(
        acceptor_captured.contains("DECLARED TOKEN id=0"),
        "acceptor stderr lacks 'DECLARED TOKEN id=0' — \
         Session::declare_token did not fire.\n\
         --- acceptor stderr ---\n{acceptor_captured}"
    );

    // R278 — graceful-shutdown end-to-end gate. The acceptor's
    // `LivelinessToken::Drop` (R277 RAII) runs during the
    // `shutdown_signal()` -> drop(token) sequence under SIGTERM,
    // emitting `Declare(UndeclToken)` on the wire. The initiator's
    // `LivelinessRegistry` observer callback prints
    // `REMOTE TOKEN UNDECLARED id=0` (the `id=` value matches the
    // R277 auto-allocated token id from the DECLARED side). This
    // assertion is the only end-to-end gate on the R277 RAII
    // contract — the unit-level Drop test in
    // `wz-runtime-tokio/src/session.rs` covers the in-process
    // emission, this covers the cross-process wire path.
    let undecl_text = match undecl_captured {
        Ok(c) => c,
        Err(c) => panic!(
            "wz initiator did not log '{undecl_substr}' within 5 s — \
             R278 graceful-shutdown UndeclToken path regressed. Likely \
             causes: (a) shutdown_signal() not wired into the \
             tokio::select!; (b) LivelinessToken drop ordering moved \
             after drop(actions); (c) writer task drained before the \
             retraction frame was enqueued; (d) acceptor SIGTERM \
             handler not installed (failed signalfd setup).\n\
             --- captured initiator stderr at deadline ---\n{c}\n\
             --- captured acceptor stderr ---\n{acceptor_captured}"
        ),
    };
    assert!(
        undecl_text.contains("REMOTE TOKEN UNDECLARED id=0"),
        "initiator stderr missing 'REMOTE TOKEN UNDECLARED id=0' — \
         R278 LivelinessToken RAII Drop did not fire end-to-end.\n\
         --- initiator stderr ---\n{undecl_text}"
    );
}

/// R311oy — extract the `u64` immediately following the first occurrence of
/// `marker` in `haystack` (e.g. the entity id after
/// `"DECLARED ROUTED SUBSCRIBER id="`). Returns `None` if the marker is absent
/// or is not followed by an ASCII-digit run. Used to cross-reference the
/// acceptor's auto-allocated declare ids against the initiator's echo, now that
/// `--key` / `--queryable` allocate entity ids instead of the retired
/// hard-coded `--declare-subscriber` / `--declare-queryable` sentinels.
fn extract_id_after(haystack: &str, marker: &str) -> Option<u64> {
    let idx = haystack.find(marker)?;
    let rest = &haystack[idx + marker.len()..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}
