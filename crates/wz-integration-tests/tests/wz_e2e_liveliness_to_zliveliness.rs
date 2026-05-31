// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Facade-subset behavioural e2e: liveliness-subscriber-only.
//!
//! Third sibling of `wz_e2e_pubsub_to_zsub.rs` (R311fg) /
//! `wz_e2e_queryable_to_zget.rs` (R311fh). Drives `wz-e2e-liveliness` —
//! a binary whose facade dependency pins EXACTLY the liveliness-
//! subscriber-only coherent subset (no pub/sub / query / token declare)
//! — against zenoh-pico's z_liveliness token declarer. It proves the
//! liveliness-subscriber data plane interoperates on the wire with a
//! foreign implementation when compiled in isolation, the behavioural
//! counterpart of the C4b declare/liveliness BUILD subset.
//!
//! Direction (deliberately the SUBSCRIBER, unlike the pubsub/queryable
//! siblings where wz is the data SOURCE): wz is the acceptor + liveliness
//! subscriber, zenoh-pico z_liveliness is the client + token declarer.
//! z_liveliness connects, declares its token, and pushes the
//! Declare(Token) to wz; wz's local liveliness-subscriber registry
//! matches it through the production poll loop
//! (drive_session_until_terminal -> observer -> liveliness registry ->
//! callback) and logs `LIVELINESS SAMPLE PUT ... keyexpr='<token>'`. The
//! reason for this direction is structural — wz's liveliness DECLARER
//! emits proactively with no peer-side Interest-response (R283 carry), so
//! wz=subscriber is the interop-coherent direction; see
//! `crates/wz-e2e-liveliness/Cargo.toml`.
//!
//! Harness note: unlike the pubsub/queryable siblings the witness is on
//! the WZ side (its env_logger stderr — a single-writer stream), not on
//! the foreign CLI's stdout, so this test is structurally immune to the
//! multi-thread foreign-stdout capture race that `wz_e2e_queryable_to_zget`
//! had to gate around. See `wz_publisher_to_zsub.rs` for the shared
//! per-step harness rationale (port reservation, line-buffered foreign
//! CLI via stdbuf, two-stage substring wait, captured-output-on-failure).

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_e2e_liveliness_binary, zenoh_pico_cli_binary, ChildGuard,
    PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (wz-e2e-liveliness + zenoh-pico CLI); Layer E2 runs via --ignored"]
fn wz_e2e_liveliness_round_trip_against_zenoh_pico_z_liveliness() {
    let bin = wz_e2e_liveliness_binary();
    let z_liveliness = zenoh_pico_cli_binary("z_liveliness");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let listen_addr = format!("127.0.0.1:{port}");
    let endpoint = format!("tcp/{listen_addr}");
    // wz subscribes to a multi-chunk wildcard; z_liveliness's literal
    // token keyexpr intersects it (the same shape as the wz<->wz
    // wz_liveliness_subscriber_round_trip test).
    let subscribe_pattern = "group1/**";
    let token_keyexpr = "group1/zenoh-pico";

    // ── wz-e2e-liveliness (acceptor + liveliness subscriber) ─
    let bin_stderr = tempfile::tempfile().expect("tempfile for binary stderr");
    let bin_stderr_writer = bin_stderr.try_clone().expect("dup binary stderr handle");
    let mut bin_stderr_reader = bin_stderr;

    let mut bin_child = ChildGuard::wrap(
        "wz-e2e-liveliness (--listen --subscribe)",
        Command::new(&bin)
            .arg("--listen")
            .arg(&listen_addr)
            .arg("--subscribe")
            .arg(subscribe_pattern)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(bin_stderr_writer))
            .spawn()
            .expect("spawn wz-e2e-liveliness"),
    );

    let bound = wait_for_substring(
        &mut bin_stderr_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = bin_child.child_mut().kill();
        let _ = bin_child.child_mut().wait();
        panic!(
            "wz-e2e-liveliness did not log 'listening on' within 5s\n\
             --- captured stderr ---\n{captured}"
        );
    }
    drop(port_res);

    // ── z_liveliness (client + token declarer) ───────────────
    let z_stdout = tempfile::tempfile().expect("tempfile for z_liveliness stdout");
    let z_stdout_writer = z_stdout
        .try_clone()
        .expect("dup z_liveliness stdout handle");
    let mut z_stdout_reader = z_stdout;

    let mut z_child = ChildGuard::wrap(
        "z_liveliness client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_liveliness)
            .args(["-k", token_keyexpr, "-e", &endpoint, "-m", "client"])
            .stdout(Stdio::from(z_stdout_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_liveliness via stdbuf"),
    );

    // Witness is on the WZ side: its liveliness-subscriber callback logs
    // `LIVELINESS SAMPLE PUT ...` once z_liveliness's Declare(Token)
    // reaches the subscriber registry through the production poll loop.
    let put_substr = "LIVELINESS SAMPLE PUT";
    let put = wait_for_substring(&mut bin_stderr_reader, put_substr, Duration::from_secs(10));

    let _ = z_child.child_mut().kill();
    let _ = z_child.child_mut().wait();
    let _ = bin_child.child_mut().kill();
    let _ = bin_child.child_mut().wait();

    let bin_captured = read_captured(&mut bin_stderr_reader);
    let z_captured = read_captured(&mut z_stdout_reader);
    eprintln!("--- captured wz-e2e-liveliness stderr ---\n{bin_captured}");
    eprintln!("--- captured z_liveliness stdout ---\n{z_captured}");

    let put_text = match put {
        Ok(c) => c,
        Err(c) => panic!(
            "wz-e2e-liveliness did not log '{put_substr}' within 10s — z_liveliness's \
             Declare(Token) did not reach the wz liveliness-subscriber callback.\n\
             --- captured wz-e2e-liveliness stderr at deadline ---\n{c}\n\
             --- captured z_liveliness stdout at deadline ---\n{z_captured}"
        ),
    };

    // The PUT sample line carries the resolved token keyexpr literal.
    // Assert it surfaces so a regression on inbound Declare(Token) decode
    // or the peer-keyexpr resolution localises here.
    assert!(
        put_text.contains(&format!("keyexpr='{token_keyexpr}'")),
        "wz logged 'LIVELINESS SAMPLE PUT' but the token keyexpr \
         '{token_keyexpr}' is missing — the subscriber fired but the resolved \
         literal drifted.\n--- captured wz-e2e-liveliness stderr ---\n{put_text}"
    );
    assert!(
        put_text.contains(&format!("filter='{subscribe_pattern}'")),
        "wz logged 'LIVELINESS SAMPLE PUT' but the subscribe filter \
         '{subscribe_pattern}' is missing — the callback's configured filter is not \
         surfacing through the stderr trace.\n--- captured wz-e2e-liveliness stderr ---\n{put_text}"
    );
}
