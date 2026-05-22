// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R121f1 — foreign-interop initiator round-trip integration test.
//!
//! Drives the wz-ap-demo binary in `--connect` mode (initiator
//! role, R121f) against an external zenoh-pico `z_sub` CLI peer
//! running in `-m peer -l tcp/...` listening mode. Validates the
//! full role-symmetry matrix bottom-right cell that R121f could not
//! close (`wz initiator → foreign acceptor`) before the R121f1
//! patch-extension default landed.
//!
//! Why R121f deferred this scenario to a follow-up round: the
//! R121f initiator hit `Codec(NeedMoreBytes)` on the inbound
//! InitAck and the FSM closed at SentInitSyn → Closing. The R121f
//! authoring snapshot mis-diagnosed it as "zenoh-pico peer-listen
//! is non-response for Client-whatami InitSyn" and scoped the
//! integration test to wz↔wz only. The R121f1 root-cause
//! investigation walked the actual wire bytes via strace +
//! ZENOH_DEBUG=3 and pinpointed
//! `vendor/zenoh-pico/src/transport/unicast/transport.c:237-241`:
//! the accept-side size negotiation caps `iam._body._init._patch`
//! to the peer's announced value, but `_z_t_msg_make_init_ack`
//! has already set `_Z_FLAG_T_Z` on the InitAck header. When the
//! peer (wz) sends an InitSyn with no patch extension, zenoh-pico
//! caps `iam._patch = _Z_NO_PATCH (0)`, the encoder skips the
//! patch-ext emit, but the header's `Z=1` is now stale on the
//! wire — wz reads `Z=1` and expects ext bytes, runs out of
//! payload, surfaces `NeedMoreBytes`, the FSM closes.
//!
//! R121f1 fix: `SessionLinkActions::new` now seeds both Init ext
//! chains with the wire-spec-mandatory patch extension entry
//! (`_Z_MSG_EXT_ID_INIT_PATCH = 0x27`, body = VLE(1)). The
//! negotiation stays symmetric — zenoh-pico decodes `tmsg._patch
//! = 1`, the cap keeps `iam._patch = 1`, the InitAck wire carries
//! the patch-ext bytes alongside the `Z=1` header, and the wz
//! parser sees a self-consistent frame.
//!
//! Test flow:
//!   1. Pick a free TCP port (bind+drop dance).
//!   2. Spawn `z_sub -m peer -l tcp/127.0.0.1:<port> -k
//!      "demo/**"` with `stdbuf -oL -eL` line buffering on stdout
//!      so the `>> [Subscriber] Received` witness surfaces before
//!      the 10s deadline.
//!   3. Wait up to 5s for the z_sub stdout to contain
//!      `Press CTRL-C to quit` — proves z_sub finished its
//!      bind+listen+admin_space setup and is parked accepting
//!      connections.
//!   4. Spawn `wz-ap-demo --connect 127.0.0.1:<port> --publish
//!      demo/test --value <payload>`.
//!   5. Wait up to 5s for the wz stderr to log
//!      `connected to <addr>` — proves the dial succeeded.
//!   6. Wait up to 10s for the z_sub stdout to contain
//!      `>> [Subscriber] Received` AND `demo/test` AND the
//!      payload — proves the full 4-way handshake completed, the
//!      Established gate fired, the publisher_task emitted Push
//!      frames, and z_sub's receive resolver matched the
//!      literal-keyexpr against `demo/**` and fired the
//!      subscriber callback.
//!   7. SIGTERM both children + surface captured output on any
//!      failed assertion so a regression on either side
//!      localises.
//!
//! Together with the wz↔wz initiator test
//! (`wz_initiator_to_wz_acceptor.rs`) this closes the 2×2
//! role × direction matrix for the AP MVP pubsub demo.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenoh-pico CLI); Layer E runs via --ignored"]
fn wz_initiator_round_trip_against_zenoh_pico_z_sub_peer_listen() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let listen_addr = format!("127.0.0.1:{port}");
    let endpoint = format!("tcp/{listen_addr}");
    let publish_key = "demo/test";
    let sub_key = "demo/**";
    let publish_value = "hello-from-wz-initiator-r121f1";

    // ── zenoh-pico z_sub (peer-listen + subscriber) ──────────
    // `-m peer -l tcp/...` makes z_sub bind+listen on TCP and run
    // the unicast accept loop in `_zp_unicast_accept_task_fn`. The
    // -k flag declares the subscriber keyexpr pattern; we use
    // `demo/**` so the wildcard matcher accepts the publisher's
    // literal keyexpr `demo/test`.
    //
    // `stdbuf -oL -eL` forces line buffering on z_sub's stdout +
    // stderr. printf-to-pipe is block-buffered by default on
    // glibc, which would hide the `>> [Subscriber] Received`
    // witness line until z_sub exits; the test deadline would
    // then fire before the witness surfaces. Same gotcha pinned
    // by `feedback_foreign_peer_crash_diagnosis` carry.
    let z_sub_stdout = tempfile::tempfile().expect("tempfile for z_sub stdout");
    let z_sub_stdout_writer = z_sub_stdout.try_clone().expect("dup z_sub stdout handle");
    let mut z_sub_stdout_reader = z_sub_stdout;

    let mut z_sub_child = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_sub)
        .args(["-m", "peer", "-l", &endpoint, "-k", sub_key])
        .stdout(Stdio::from(z_sub_stdout_writer))
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn z_sub via stdbuf");

    // Wait for the peer-listen banner that proves z_sub is past
    // bind+listen+admin_space and parked waiting for connections.
    // `Press CTRL-C to quit...` is the upstream z_sub banner that
    // fires after `z_declare_subscriber` returns success
    // (`vendor/zenoh-pico/examples/unix/c11/z_sub.c:83`).
    let listening = wait_for_substring(
        &mut z_sub_stdout_reader,
        "Press CTRL-C to quit",
        Duration::from_secs(5),
    );
    if let Err(captured) = &listening {
        let _ = z_sub_child.kill();
        let _ = z_sub_child.wait();
        panic!(
            "z_sub did not park accepting connections within 5s — \
             peer-listen bind on {endpoint} failed.\n\
             --- captured z_sub stdout ---\n{captured}"
        );
    }
    // R216 — z_sub bound the port, release the alloc mutex.
    drop(port_res);

    // ── wz-ap-demo (R121f initiator + R121e publisher) ───────
    let wz_stderr = tempfile::tempfile().expect("tempfile for wz stderr");
    let wz_stderr_writer = wz_stderr.try_clone().expect("dup wz stderr handle");
    let mut wz_stderr_reader = wz_stderr;

    let mut wz_child = Command::new(&demo)
        .arg("--connect")
        .arg(&listen_addr)
        .arg("--publish")
        .arg(publish_key)
        .arg("--value")
        .arg(publish_value)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(wz_stderr_writer))
        .spawn()
        .expect("spawn wz-ap-demo --connect");

    // Two-stage wait. First the dial confirmation, then the
    // subscriber-received witness.
    let dialed = wait_for_substring(
        &mut wz_stderr_reader,
        "connected to",
        Duration::from_secs(5),
    );
    let received_substr = ">> [Subscriber] Received";
    let received = wait_for_substring(
        &mut z_sub_stdout_reader,
        received_substr,
        Duration::from_secs(10),
    );

    let _ = wz_child.kill();
    let _ = wz_child.wait();
    let _ = z_sub_child.kill();
    let _ = z_sub_child.wait();

    let wz_captured = read_captured(&mut wz_stderr_reader);
    let z_sub_captured = read_captured(&mut z_sub_stdout_reader);
    eprintln!("--- captured wz-ap-demo stderr ---\n{wz_captured}");
    eprintln!("--- captured z_sub stdout ---\n{z_sub_captured}");

    if let Err(c) = &dialed {
        panic!(
            "wz-ap-demo --connect did not log 'connected to' within 5s — \
             initiator TCP dial against {listen_addr} failed.\n\
             --- captured wz stderr ---\n{c}\n\
             --- captured z_sub stdout ---\n{z_sub_captured}"
        );
    }

    let received_text = match received {
        Ok(c) => c,
        Err(c) => panic!(
            "z_sub did not log '{received_substr}' within 10s — wz initiator handshake \
             or publisher Push emission regressed.\n\
             --- captured z_sub stdout at deadline ---\n{c}\n\
             --- captured wz stderr at deadline ---\n{wz_captured}"
        ),
    };

    // Belt-and-suspenders gates on the keyexpr + value substrings
    // so a partial-match (wrong payload, keyexpr drift) localises
    // here instead of being absorbed by the umbrella substring.
    assert!(
        received_text.contains(publish_key),
        "z_sub captured 'Received' but the publish keyexpr '{publish_key}' is missing.\n\
         --- captured z_sub stdout ---\n{received_text}"
    );
    assert!(
        received_text.contains(publish_value),
        "z_sub captured 'Received' but the publish value '{publish_value}' is missing.\n\
         --- captured z_sub stdout ---\n{received_text}"
    );
}
