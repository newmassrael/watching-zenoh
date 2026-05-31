// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Facade-subset behavioural e2e: queryable-only.
//!
//! Sibling of `wz_e2e_pubsub_to_zsub.rs` (R311fg). That test drives
//! `wz-e2e-pubsub` (the pubsub-only subset binary) against zenoh-pico's
//! z_sub; this one drives `wz-e2e-queryable` — a binary whose facade
//! dependency pins EXACTLY the queryable-only coherent subset (no
//! pub/sub / declare / liveliness) — against zenoh-pico's z_get. It
//! proves the query/reply data plane interoperates on the wire with a
//! foreign implementation when compiled in isolation, the behavioural
//! counterpart of the C4b `queryable-only` BUILD subset.
//!
//! Direction (mirror of the pubsub e2e, where wz is the data SOURCE):
//! wz is the acceptor + queryable, zenoh-pico z_get is the client +
//! querier. z_get connects, sends a GET; the query reaches wz's local
//! QueryableRegistry through the production poll loop
//! (drive_session_until_terminal -> observer -> queryables -> callback),
//! the callback emits one Put-form Reply, and z_get's reply callback
//! prints `>> Received PUT ('<keyexpr>': '<value>')` on stdout. Hard
//! gate on that foreign-side line plus belt-and-suspenders substring
//! assertions on the resolved keyexpr literal + the configured reply
//! payload so a wire-shape regression on either side localises here.
//!
//! See `wz_publisher_to_zsub.rs` for the per-step harness rationale
//! (port reservation, line-buffered foreign-CLI stdout via stdbuf, the
//! two-stage substring wait, captured-output-on-failure).

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_e2e_queryable_binary, zenoh_pico_cli_binary, ChildGuard,
    PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (wz-e2e-queryable + zenoh-pico CLI); Layer E2 runs via --ignored"]
fn wz_e2e_queryable_round_trip_against_zenoh_pico_z_get() {
    let bin = wz_e2e_queryable_binary();
    let z_get = zenoh_pico_cli_binary("z_get");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let listen_addr = format!("127.0.0.1:{port}");
    let endpoint = format!("tcp/{listen_addr}");
    // wz queryable pattern is a multi-chunk wildcard; z_get's literal
    // query intersects it, exercising the peer-keyexpr resolution path
    // (the same shape as the wz<->wz wz_queryable_round_trip test).
    let queryable_pattern = "demo/**";
    let query_keyexpr = "demo/test";
    let reply_value = "hello-from-wz-queryable-subset";

    // ── wz-e2e-queryable (acceptor + queryable) ──────────────
    let bin_stderr = tempfile::tempfile().expect("tempfile for binary stderr");
    let bin_stderr_writer = bin_stderr.try_clone().expect("dup binary stderr handle");
    let mut bin_stderr_reader = bin_stderr;

    let mut bin_child = ChildGuard::wrap(
        "wz-e2e-queryable (--listen --queryable --reply)",
        Command::new(&bin)
            .arg("--listen")
            .arg(&listen_addr)
            .arg("--queryable")
            .arg(queryable_pattern)
            .arg("--reply")
            .arg(reply_value)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(bin_stderr_writer))
            .spawn()
            .expect("spawn wz-e2e-queryable"),
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
            "wz-e2e-queryable did not log 'listening on' within 5s\n\
             --- captured stderr ---\n{captured}"
        );
    }
    drop(port_res);

    // ── z_get (client + querier) ─────────────────────────────
    let z_get_stdout = tempfile::tempfile().expect("tempfile for z_get stdout");
    let z_get_stdout_writer = z_get_stdout.try_clone().expect("dup z_get stdout handle");
    let mut z_get_stdout_reader = z_get_stdout;

    let mut z_get_child = ChildGuard::wrap(
        "z_get client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_get)
            .args(["-k", query_keyexpr, "-e", &endpoint, "-m", "client"])
            .stdout(Stdio::from(z_get_stdout_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_get via stdbuf"),
    );

    // Gate ONLY on the reply witness, not on z_get's earlier
    // "Opening session" / "Sending Query" lines. z_get is a fast
    // burst-and-exit binary whose main thread and reply-callback thread
    // both write(2) to the same shared (non-O_APPEND) tempfile FD; the
    // resulting kernel-offset race clobbers the EARLIEST lines (an
    // empirical ~3% capture-corruption flake reproduced at 1/30 in the
    // bring-up sweep showed "Opening session..." overwritten while the
    // later ">> Received ..." witness lines survived intact). z_sub in
    // the pubsub sibling test stays alive so its writes are temporally
    // spread and rarely collide, which is why that test keeps the
    // "Opening session" pre-gate. Here the witness is the only line that
    // matters AND the only one resilient to the race: a z_get that fails
    // to open simply never prints ">> Received", so this wait's timeout
    // already subsumes the init-failure case the pre-gate used to cover.
    let received_substr = ">> Received";
    let received = wait_for_substring(
        &mut z_get_stdout_reader,
        received_substr,
        Duration::from_secs(10),
    );

    let _ = z_get_child.child_mut().kill();
    let _ = z_get_child.child_mut().wait();
    let _ = bin_child.child_mut().kill();
    let _ = bin_child.child_mut().wait();

    let bin_captured = read_captured(&mut bin_stderr_reader);
    let z_get_captured = read_captured(&mut z_get_stdout_reader);
    eprintln!("--- captured wz-e2e-queryable stderr ---\n{bin_captured}");
    eprintln!("--- captured z_get stdout ---\n{z_get_captured}");

    let received_text = match received {
        Ok(c) => c,
        Err(c) => panic!(
            "z_get did not log '{received_substr}' within 10s — wz-e2e-queryable's \
             Reply did not reach z_get's reply callback.\n\
             --- captured z_get stdout at deadline ---\n{c}\n\
             --- captured wz-e2e-queryable stderr at deadline ---\n{bin_captured}"
        ),
    };

    // z_get's reply callback logs e.g.
    //   ">> Received PUT ('demo/test': 'hello-from-wz-queryable-subset')"
    // Assert the resolved query keyexpr literal AND the configured reply
    // payload both surface so a regression on either (peer-keyexpr
    // resolution, reply wire shape) localises here.
    assert!(
        received_text.contains(query_keyexpr),
        "z_get captured the 'Received' line but the query keyexpr '{query_keyexpr}' is \
         missing — the queryable matched but the resolved literal drifted.\n\
         --- captured z_get stdout ---\n{received_text}"
    );
    assert!(
        received_text.contains(reply_value),
        "z_get captured the 'Received' line but the reply value '{reply_value}' is \
         missing — the queryable callback's payload did not reach z_get.\n\
         --- captured z_get stdout ---\n{received_text}"
    );

    // The wz side must have logged its queryable callback firing — proves
    // the inbound Request(Query) traversed every layer (TCP -> stream
    // envelope -> Frame -> parse_frame_payload -> NetworkMessage::Request
    // -> QueryableRegistry -> callback) under the queryable-only subset.
    assert!(
        bin_captured.contains("QUERYABLE FIRED"),
        "wz-e2e-queryable stderr lacks 'QUERYABLE FIRED' — z_get's reply printed but \
         the wz queryable callback trace is missing, which would mean the reply came \
         from somewhere other than the expected dispatch path.\n\
         --- captured wz-e2e-queryable stderr ---\n{bin_captured}"
    );
}
