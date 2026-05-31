// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Facade-subset behavioural e2e: liveliness-token DECLARER (R283).
//!
//! Symmetric sibling of `wz_e2e_liveliness_to_zliveliness.rs` (the
//! SUBSCRIBER side). Drives `wz-e2e-liveliness-token` — a binary pinning
//! EXACTLY the liveliness-token declarer subset — against zenoh-pico's
//! `z_get_liveliness` querier. It proves wz's R283 inbound-Interest
//! response interoperates on the wire with a foreign implementation.
//!
//! Why z_get_liveliness (a one-shot CURRENT liveliness GET) and not
//! z_sub_liveliness: a liveliness subscriber keeps a FUTURE subscription
//! that catches wz's PROACTIVE `Declare(DeclToken)` regardless of R283,
//! so it cannot isolate the interest-response. z_get_liveliness has NO
//! future subscription — its CURRENT query is satisfiable ONLY by an
//! interest_id-tagged reply, which is exactly what R283 emits. A
//! `>> Alive token` line therefore proves the R283 path specifically.
//! (zenoh-pico routes the proactive, interest_id-less declare to
//! `_z_liveliness_process_remote_token_declare` — subscriber callbacks —
//! which a pure get has none of; the get only resolves via
//! `_z_liveliness_pending_query_reply` on an interest_id-tagged declare.)
//!
//! The declarer binary declares its token SYNCHRONOUSLY before the drive
//! loop, so the token is registered before the querier's Interest is
//! processed — the deterministic ordering the one-shot get needs (see
//! `crates/wz-e2e-liveliness-token/Cargo.toml` for why wz-ap-demo's
//! background declare is too racy for this proof).
//!
//! See `wz_publisher_to_zsub.rs` for the shared harness rationale.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_e2e_liveliness_token_binary, zenoh_pico_cli_binary,
    ChildGuard, PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (wz-e2e-liveliness-token + zenoh-pico CLI); Layer E2 runs via --ignored"]
fn wz_e2e_liveliness_token_round_trip_against_zenoh_pico_z_get_liveliness() {
    let bin = wz_e2e_liveliness_token_binary();
    let z_get_liveliness = zenoh_pico_cli_binary("z_get_liveliness");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let listen_addr = format!("127.0.0.1:{port}");
    let endpoint = format!("tcp/{listen_addr}");
    let token_keyexpr = "group1/zenoh-pico";
    let query_pattern = "group1/**";

    // ── wz-e2e-liveliness-token (acceptor + token declarer) ──
    let bin_stderr = tempfile::tempfile().expect("tempfile for binary stderr");
    let bin_stderr_writer = bin_stderr.try_clone().expect("dup binary stderr handle");
    let mut bin_stderr_reader = bin_stderr;

    let mut bin_child = ChildGuard::wrap(
        "wz-e2e-liveliness-token (--listen --token)",
        Command::new(&bin)
            .arg("--listen")
            .arg(&listen_addr)
            .arg("--token")
            .arg(token_keyexpr)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(bin_stderr_writer))
            .spawn()
            .expect("spawn wz-e2e-liveliness-token"),
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
            "wz-e2e-liveliness-token did not log 'listening on' within 5s\n\
             --- captured stderr ---\n{captured}"
        );
    }
    drop(port_res);

    // ── z_get_liveliness (client + one-shot liveliness querier) ─
    let z_stdout = tempfile::tempfile().expect("tempfile for z_get_liveliness stdout");
    let z_stdout_writer = z_stdout
        .try_clone()
        .expect("dup z_get_liveliness stdout handle");
    let mut z_stdout_reader = z_stdout;

    let mut z_child = ChildGuard::wrap(
        "z_get_liveliness client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_get_liveliness)
            .args(["-k", query_pattern, "-e", &endpoint, "-m", "client"])
            .stdout(Stdio::from(z_stdout_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_get_liveliness via stdbuf"),
    );

    // The witness — z_get_liveliness's CURRENT query is satisfiable ONLY
    // by wz's R283 interest_id-tagged reply.
    let alive_substr = ">> Alive token";
    let alive = wait_for_substring(&mut z_stdout_reader, alive_substr, Duration::from_secs(10));

    let _ = z_child.child_mut().kill();
    let _ = z_child.child_mut().wait();
    let _ = bin_child.child_mut().kill();
    let _ = bin_child.child_mut().wait();

    let bin_captured = read_captured(&mut bin_stderr_reader);
    let z_captured = read_captured(&mut z_stdout_reader);
    eprintln!("--- captured wz-e2e-liveliness-token stderr ---\n{bin_captured}");
    eprintln!("--- captured z_get_liveliness stdout ---\n{z_captured}");

    let alive_text = match alive {
        Ok(c) => c,
        Err(c) => panic!(
            "z_get_liveliness did not log '{alive_substr}' within 10s — wz's R283 \
             interest-response did not satisfy the foreign CURRENT liveliness query.\n\
             --- captured z_get_liveliness stdout at deadline ---\n{c}\n\
             --- captured wz-e2e-liveliness-token stderr at deadline ---\n{bin_captured}"
        ),
    };

    // The alive line carries the resolved token keyexpr literal; assert it
    // so a regression on the held-token enumeration / interest-response
    // keyexpr build localises here.
    assert!(
        alive_text.contains(token_keyexpr),
        "z_get_liveliness logged an 'Alive token' line but the token keyexpr \
         '{token_keyexpr}' is missing — the interest-response fired but the resolved \
         literal drifted.\n--- captured z_get_liveliness stdout ---\n{alive_text}"
    );

    // Corroborate on the wz side that the declarer actually declared the
    // token (so the witness reflects the R283 path, not a foreign-side
    // artefact).
    assert!(
        bin_captured.contains("DECLARED TOKEN"),
        "wz-e2e-liveliness-token stderr lacks 'DECLARED TOKEN' — z_get_liveliness \
         reported an alive token but the wz declarer trace is missing.\n\
         --- captured wz-e2e-liveliness-token stderr ---\n{bin_captured}"
    );
}
