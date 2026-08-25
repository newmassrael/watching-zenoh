// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y352 — `scouting-static`, witnessed by a real zenoh-pico peer.
//!
//! ## Why the obvious test would have proven the wrong atom
//!
//! `scouting-static` is the static-mode alternative to dynamic discovery: a
//! configured list of peers, tried in order, first Established wins. The
//! natural-looking proof — "point wz at a configured address and watch it
//! connect" — binds to the WRONG code. The two entrypoints are asymmetrically
//! gated, and `session_open.rs:2244-2245` says so in as many words:
//!
//! - `open_session_static(&[String])` → `#[cfg(feature = "scouting-static")]`
//!   (`session_open.rs:2246`) — **the atom's code**.
//! - `open_session_at(&str)` → **UNGATED**, "since active scouting feeds it
//!   too" — the mode-agnostic per-locator bridge, and NOT this atom.
//!
//! A single-locator dial reaches Established through `open_session_at` whether
//! or not `scouting-static` was ever compiled, so it would have passed while
//! proving nothing about the atom. This is R311y347's finding again
//! (`get_matching_status` vs `declare_matching_listener`): read the cfg on BOTH
//! surfaces of a pair before writing the test, because the natural-looking
//! surface is not always the atom's.
//!
//! ## What is actually asserted, and why it cannot be vacuous
//!
//! The list is `[dead, pico]` and the dead entry is FIRST. That shape is the
//! atom: `open_session_static` synthesises the locator list
//! (`synth_static_locators`), tries each in order, logs and continues past a
//! failure, and returns the first Established. `open_session_at` takes ONE
//! locator and structurally cannot express it.
//!
//! So the test fails in both directions that matter. Delete the fallthrough loop
//! and only the dead locator is tried → `NoReachableLocator`, this test fails,
//! and every `open_session_at` proof still passes — R311y349's separability
//! discriminator, answered YES. Take the pico listener away and no locator ever
//! Establishes → also a failure. Neither arm can go green on an empty run.
//!
//! ## What makes pico the witness, and the honest boundary
//!
//! `record_established_at >= 1` on the returned session's trace is wz's OWN
//! counter, but what it counts is not wz's alone: Established is only reachable
//! by completing the 4-way handshake against the peer on the far end, and here
//! that peer is a real zenoh-pico `z_sub -m peer -l tcp/...` running its
//! `_zp_unicast_accept_task_fn` accept loop. A foreign implementation accepted
//! wz's InitSyn, answered InitAck/OpenAck, and wz's FSM agreed — that agreement
//! is the cross-impl content.
//!
//! `args.rs:92-102` is why this direction is the supported one: the R121f
//! initiator announces `Client` whatami precisely so a zenoh-pico `-m peer -l`
//! listener accepts it via the same well-trodden upstream path that
//! `wz_initiator_to_zsub` exercises. This test is that test's `scouting-static`
//! sibling — same foreign listener, same direction, but driven through the
//! atom's own gated entrypoint instead of the demo's ungated dial.
//!
//! THE BOUND, stated so it is not over-read: this proves the SELECTION half of
//! the atom (a dead-first static list lands its session on the next locator, and
//! a foreign peer accepts it). It does not prove a data plane on top of that
//! session — `pubsub-put` is `wz_initiator_to_zsub`'s claim and is not restated
//! here. The atom is which locator gets opened, not what flows afterwards.

use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::Duration;

use socket2::{Domain, Socket, Type};

use wz_integration_tests::common::{
    read_captured, wait_for_substring, zenoh_pico_cli_binary, ChildGuard, PortReservation,
};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::SessionInitParams;
use wz_runtime_tokio::session_open::{
    open_session_static, DialConfig, OpenError, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;

/// Poll-count cap on the open loop, mirroring the wz-only sibling
/// (`static_scout_open.rs`). The loop is bounded by iterations, not wall clock.
const ITER_CAP: usize = 64;

fn initiator_params() -> SessionInitParams {
    let mut p = fixture_session_init_params();
    p.zid = vec![0x01; 4];
    p
}

/// A loopback TCP address that is *deterministically* connection-refused.
///
/// Lifted from `wz-runtime-tokio/tests/static_scout_open.rs`, whose docs record
/// why the shape is what it is: `std::net::TcpListener::bind` always calls
/// `listen()`, so a std listener would ACCEPT and then hang the open loop, and
/// the older bind-then-drop pattern let the OS recycle the freed port to an
/// unrelated live listener under concurrent CI load. socket2 binds WITHOUT
/// listening: the reservation stands while the guard lives, and a connect to it
/// gets RST -> ECONNREFUSED.
fn refused_locator() -> (Socket, SocketAddr) {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).expect("socket");
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("parse bind addr");
    socket.bind(&bind.into()).expect("bind without listen");
    let addr = socket
        .local_addr()
        .expect("local_addr")
        .as_socket()
        .expect("ipv4 socket addr");
    (socket, addr)
}

// wz-proves: scouting-static wz->pico
#[test]
#[ignore = "binary-dep e2e (zenoh-pico z_sub CLI, peer-listen); Layer E runs via --ignored"]
fn static_scout_dead_first_list_establishes_on_pico_z_sub_peer_listen() {
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let pico_addr = format!("127.0.0.1:{port}");
    let pico_endpoint = format!("tcp/{pico_addr}");

    // ── zenoh-pico z_sub (peer-listen) ───────────────────────────
    // `stdbuf -oL -eL` forces line buffering: printf-to-pipe is block-buffered
    // on glibc, which would hide the readiness banner until z_sub exits.
    let z_sub_stdout = tempfile::tempfile().expect("tempfile for z_sub stdout");
    let z_sub_stdout_writer = z_sub_stdout.try_clone().expect("dup z_sub stdout handle");
    let mut z_sub_stdout_reader = z_sub_stdout;

    let mut z_sub_child = ChildGuard::wrap(
        "z_sub peer-listen (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub)
            .args(["-m", "peer", "-l", &pico_endpoint, "-k", "demo/**"])
            .stdout(Stdio::from(z_sub_stdout_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_sub via stdbuf"),
    );

    // THE FIXTURE OWNS ITS PRECONDITION: the run below can only mean what it
    // claims if pico is genuinely parked on the accept loop first. Otherwise a
    // refused SECOND locator would be indistinguishable from a working
    // fallthrough that found nothing, and the test would be asserting on a race.
    // `Press CTRL-C to quit` is z_sub's own post-`z_declare_subscriber` banner
    // (vendor/zenoh-pico/examples/unix/c11/z_sub.c).
    let listening = wait_for_substring(
        &mut z_sub_stdout_reader,
        "Press CTRL-C to quit",
        Duration::from_secs(5),
    );
    if let Err(captured) = &listening {
        let _ = z_sub_child.child_mut().kill();
        let _ = z_sub_child.child_mut().wait();
        panic!(
            "z_sub did not park accepting connections within 5s — peer-listen bind on \
             {pico_endpoint} failed.\n--- captured z_sub stdout ---\n{captured}"
        );
    }
    // pico owns the port now; release the allocator mutex.
    drop(port_res);

    // ── wz static-mode open: DEAD first, pico second ─────────────
    let (_dead_guard, dead) = refused_locator();
    let connect = vec![format!("tcp/{dead}"), pico_endpoint.clone()];

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build tokio runtime");

    let cfg = DialConfig::default();
    let opened = runtime.block_on(open_session_static(
        &connect,
        initiator_params(),
        &cfg,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    ));

    let z_sub_captured = read_captured(&mut z_sub_stdout_reader);
    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();

    let opened = match opened {
        Ok(o) => o,
        Err(e) => panic!(
            "open_session_static did not reach the pico peer. The list was \
             [tcp/{dead} (refused), {pico_endpoint} (pico z_sub)], so this is either the \
             fallthrough failing to skip the dead entry or pico refusing wz's Client-whatami \
             InitSyn. Got: {e:?}\n--- captured z_sub stdout ---\n{z_sub_captured}"
        ),
    };

    let established = opened.actions.trace_snapshot().record_established_at;
    assert!(
        established >= 1,
        "open_session_static returned Ok but the session never recorded Established \
         against pico's accept loop (record_established_at = {established}).\n\
         --- captured z_sub stdout ---\n{z_sub_captured}"
    );
}

/// The anti-vacuity twin, and it OWNS the precondition rather than borrowing it.
///
/// The test above only asserts that SOME locator in `[dead, pico]` Established. That
/// is the atom's claim only while the first entry genuinely cannot connect: if
/// `refused_locator` ever handed back a live address, the session would establish at
/// position 1, the fallthrough would never run, and the test would stay green while
/// proving nothing. Nothing up there detects that.
///
/// So this pins the precondition directly: the same helper, alone in the list, must
/// fail. R311y338's rule is why it lives HERE and not by reference to
/// `static_scout_open.rs`'s own exhaustion test — that test guards ITS copy of the
/// helper, and a fixture that borrows its silence from another crate's test survives
/// exactly until the copies drift.
///
/// `#[ignore]`d, which was NOT the first instinct and the gates were right. This test
/// spawns nothing, so "it needs no foreign binary, let it run everywhere" reads well —
/// but Layer C0 scopes its `#[test]` + `#[ignore]` discipline to the FILE, because
/// Layer C1's `cargo test --workspace` builds a fresh checkout where the pico CLI does
/// not exist yet, and it cannot tell which test in a binary-dep file is the harmless
/// one. Riding Layer E with the sibling is also where the guard belongs: it protects
/// that test's precondition, so it should run exactly where that test runs.
///
/// The `none` declaration below is honest, not an omission — A4-4 rejects a corpus
/// test that declares nothing, since a silent test makes the proof number
/// under-report. This one witnesses no atom BY DESIGN; it witnesses the fixture.
/// (The declaration is a `//` line, not this doc block: A4 parses the marker token
/// wherever it appears, so spelling it inside prose reads as a second, malformed
/// declaration. That is not hypothetical — this comment did exactly that.)
// wz-proves: none -- anti-vacuity guard for the sibling above; it pins that
// `refused_locator` still refuses, and witnesses no atom of its own.
#[test]
#[ignore = "rides Layer E with the sibling whose precondition it guards; Layer C0 scopes the #[ignore] discipline to the file"]
fn static_scout_dead_only_list_is_no_reachable() {
    let (_dead_guard, dead) = refused_locator();
    let connect = vec![format!("tcp/{dead}")];

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build tokio runtime");

    let cfg = DialConfig::default();
    let opened = runtime.block_on(open_session_static(
        &connect,
        initiator_params(),
        &cfg,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    ));

    let err = match opened {
        Err(e) => e,
        Ok(_) => panic!(
            "tcp/{dead} was supposed to be deterministically connection-refused, and it \
             ESTABLISHED. `refused_locator` is no longer refusing, so the sibling test's \
             dead-first list is now vacuous: it would establish at position 1 and never \
             exercise the fallthrough that is scouting-static's whole observable."
        ),
    };
    assert!(
        matches!(err, OpenError::NoReachableLocator),
        "a dead-only static list must exhaust to NoReachableLocator, got {err:?}"
    );
}
