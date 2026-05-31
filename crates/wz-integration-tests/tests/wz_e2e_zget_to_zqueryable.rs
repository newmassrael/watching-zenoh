// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Facade-subset behavioural e2e: zget-reply-only (z_get initiator).
//!
//! Initiator-side MIRROR of `wz_e2e_queryable_to_zget.rs`. That test
//! drives `wz-e2e-queryable` (wz answers a foreign z_get); this one
//! drives `wz-e2e-zget` — a binary whose facade dependency pins EXACTLY
//! the z_get-initiator ("zget-reply-only") coherent subset (no
//! queryable / declare / pub/sub / liveliness) — against zenoh-pico's
//! `z_queryable`. It proves the getter half of the query/reply data
//! plane interoperates on the wire with a foreign implementation when
//! compiled in isolation, the behavioural counterpart of the C4b / C4c /
//! C1h `zget-reply-only` BUILD subset.
//!
//! Direction (mirror of the queryable e2e, where wz is the data SOURCE):
//! wz is the acceptor + getter, zenoh-pico `z_queryable` is the client +
//! answerer. z_queryable connects and declares a queryable; wz emits a
//! GET burst (`Session::query`), the query reaches z_queryable's handler
//! which prints `>> [Queryable handler] Received Query '<keyexpr>'` and
//! replies; the Response(Reply) + terminating ResponseFinal travel back
//! and route through wz's production poll loop
//! (drive_session_until_terminal -> observer -> ReplyRegistry ->
//! on_reply / on_final), firing wz's `ZGET REPLY RECEIVED` /
//! `ZGET FINAL RECEIVED` traces. Hard gate on both wz-side witness lines
//! plus belt-and-suspenders assertions on the resolved reply keyexpr
//! literal + the configured reply payload + the foreign-side
//! `Received Query` line so a wire-shape regression on either side
//! localises here.
//!
//! See `wz_publisher_to_zsub.rs` for the per-step harness rationale
//! (port reservation, line-buffered foreign-CLI stdout via stdbuf, the
//! two-stage substring wait, captured-output-on-failure). z_queryable is
//! long-running (loops until killed) like z_sub, so unlike the
//! burst-and-exit z_get its stdout writes are temporally spread and the
//! shared-FD offset race the queryable test documents does not apply.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_e2e_zget_binary, zenoh_pico_cli_binary, ChildGuard,
    PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (wz-e2e-zget + zenoh-pico CLI); Layer E2 runs via --ignored"]
fn wz_e2e_zget_round_trip_against_zenoh_pico_z_queryable() {
    let bin = wz_e2e_zget_binary();
    let z_queryable = zenoh_pico_cli_binary("z_queryable");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let listen_addr = format!("127.0.0.1:{port}");
    let endpoint = format!("tcp/{listen_addr}");
    // wz's GET is a literal; z_queryable declares a multi-chunk wildcard
    // that intersects it, exercising the peer-keyexpr resolution path
    // (the same shape as the wz<->wz wz_query_reply_round_trip test).
    let query_keyexpr = "demo/zget/test";
    let queryable_pattern = "demo/**";
    let reply_value = "reply-from-zenoh-pico-queryable";

    // ── wz-e2e-zget (acceptor + getter) ──────────────────────
    let bin_stderr = tempfile::tempfile().expect("tempfile for binary stderr");
    let bin_stderr_writer = bin_stderr.try_clone().expect("dup binary stderr handle");
    let mut bin_stderr_reader = bin_stderr;

    let mut bin_child = ChildGuard::wrap(
        "wz-e2e-zget (--listen --query)",
        Command::new(&bin)
            .arg("--listen")
            .arg(&listen_addr)
            .arg("--query")
            .arg(query_keyexpr)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(bin_stderr_writer))
            .spawn()
            .expect("spawn wz-e2e-zget"),
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
            "wz-e2e-zget did not log 'listening on' within 5s\n\
             --- captured stderr ---\n{captured}"
        );
    }
    drop(port_res);

    // ── z_queryable (client + answerer) ──────────────────────
    let z_q_stdout = tempfile::tempfile().expect("tempfile for z_queryable stdout");
    let z_q_stdout_writer = z_q_stdout
        .try_clone()
        .expect("dup z_queryable stdout handle");
    let mut z_q_stdout_reader = z_q_stdout;

    let mut z_q_child = ChildGuard::wrap(
        "z_queryable client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_queryable)
            .args([
                "-k",
                queryable_pattern,
                "-v",
                reply_value,
                "-e",
                &endpoint,
                "-m",
                "client",
            ])
            .stdout(Stdio::from(z_q_stdout_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_queryable via stdbuf"),
    );

    // wz emits a GET burst once Established (it cannot observe the peer's
    // queryable declare under the zget-reply-only subset, so it retries
    // until a reply lands). Gate on wz's reply + final witnesses, then on
    // z_queryable's "Received Query" foreign-side witness.
    let reply_recv = wait_for_substring(
        &mut bin_stderr_reader,
        "ZGET REPLY RECEIVED",
        Duration::from_secs(10),
    );
    let final_recv = wait_for_substring(
        &mut bin_stderr_reader,
        "ZGET FINAL RECEIVED",
        Duration::from_secs(10),
    );
    let received_query = wait_for_substring(
        &mut z_q_stdout_reader,
        "Received Query",
        Duration::from_secs(10),
    );

    let _ = z_q_child.child_mut().kill();
    let _ = z_q_child.child_mut().wait();
    let _ = bin_child.child_mut().kill();
    let _ = bin_child.child_mut().wait();

    let bin_captured = read_captured(&mut bin_stderr_reader);
    let z_q_captured = read_captured(&mut z_q_stdout_reader);
    eprintln!("--- captured wz-e2e-zget stderr ---\n{bin_captured}");
    eprintln!("--- captured z_queryable stdout ---\n{z_q_captured}");

    let reply_text = match reply_recv {
        Ok(c) => c,
        Err(c) => panic!(
            "wz-e2e-zget did not log 'ZGET REPLY RECEIVED' within 10s — the foreign \
             z_queryable's Reply did not reach wz's ReplyRegistry through the wire \
             dispatch path under the zget-reply-only subset.\n\
             --- captured wz-e2e-zget stderr at deadline ---\n{c}\n\
             --- captured z_queryable stdout at deadline ---\n{z_q_captured}"
        ),
    };
    let final_text = match final_recv {
        Ok(c) => c,
        Err(c) => panic!(
            "wz-e2e-zget did not log 'ZGET FINAL RECEIVED' within 10s — the \
             terminating ResponseFinal (codec-response-final) either never arrived \
             or the on_final callback did not fire.\n\
             --- captured wz-e2e-zget stderr at deadline ---\n{c}\n\
             --- captured z_queryable stdout at deadline ---\n{z_q_captured}"
        ),
    };
    if let Err(c) = &received_query {
        panic!(
            "z_queryable did not log 'Received Query' within 10s — wz's outbound \
             Request(Query) never reached the foreign queryable handler.\n\
             --- captured z_queryable stdout at deadline ---\n{c}\n\
             --- captured wz-e2e-zget stderr at deadline ---\n{bin_captured}"
        );
    }

    // wz's on_reply callback logs e.g.
    //   "ZGET REPLY RECEIVED rid=1 keyexpr='demo/zget/test' body=Put payload=\"reply-from-zenoh-pico-queryable\""
    // Assert the resolved query keyexpr literal AND the configured reply
    // payload both surface so a regression on either (peer-keyexpr
    // resolution, reply wire shape) localises here.
    assert!(
        reply_text.contains(query_keyexpr),
        "wz-e2e-zget captured 'ZGET REPLY RECEIVED' but the query keyexpr \
         '{query_keyexpr}' is missing — the reply matched but the resolved literal \
         drifted.\n--- captured wz-e2e-zget stderr ---\n{reply_text}"
    );
    assert!(
        reply_text.contains(reply_value),
        "wz-e2e-zget captured 'ZGET REPLY RECEIVED' but the reply value \
         '{reply_value}' is missing — the foreign queryable's payload did not \
         surface through the wire Response.\n--- captured wz-e2e-zget stderr ---\n{reply_text}"
    );
    assert!(
        reply_text.contains("body=Put"),
        "wz-e2e-zget 'ZGET REPLY RECEIVED' line lacks 'body=Put' — z_queryable's \
         z_query_reply is a Put-form reply, so InboundReplyBody::Put is expected.\n\
         --- captured wz-e2e-zget stderr ---\n{reply_text}"
    );

    // The foreign queryable's "Received Query" line must echo the resolved
    // query keyexpr — proves wz's outbound Query carried the literal the
    // queryable matched on.
    let received_query_text = received_query.expect("received_query Ok checked above");
    assert!(
        received_query_text.contains(query_keyexpr),
        "z_queryable logged 'Received Query' but without the query keyexpr \
         '{query_keyexpr}' — wz's outbound Query keyexpr drifted on the wire.\n\
         --- captured z_queryable stdout ---\n{received_query_text}"
    );

    // Belt-and-suspenders: the FINAL line proves the codec-response-final
    // terminator closed the reply chain (the whole reason the subset pins
    // codec-response-final).
    assert!(
        final_text.contains("ZGET FINAL RECEIVED"),
        "wz-e2e-zget final wait returned Ok but the captured text lacks the \
         marker — internal inconsistency.\n--- captured wz-e2e-zget stderr ---\n{final_text}"
    );
}
