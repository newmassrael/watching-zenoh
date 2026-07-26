// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y353 — `liveliness-get`, witnessed against a token a real zenoh-pico
//! declared and a real zenohd answered.
//!
//! ## Why this atom had no foreign witness, and why the recorded reason was wrong
//!
//! The carried blocker said `liveliness-get` needed "an ordering the demo can't
//! make". R311y353 built that knob, measured it, and the note is wrong TWICE
//! over — it was neither the blocker nor a requirement:
//!
//! 1. THE ORDERING WAS NOT THE BLOCKER. With the hold in place and a pico peer
//!    dialled DIRECTLY, the get still returns nothing — and pico's own source
//!    says why. `vendor/zenoh-pico/src/session/interest.c:533-535`:
//!
//!    ```c
//!    // Check transport type
//!    if (zn->_tp._type == _Z_TRANSPORT_UNICAST_TYPE) {
//!        return _Z_RES_OK;  // Nothing to do on unicast
//!    }
//!    ```
//!
//!    zenoh-pico NEVER answers an Interest on a unicast transport. Its whole
//!    responder — `_z_interest_send_decl_token` included — is reachable only on
//!    a multicast transport. This is not a build-flag gap: the CLI build has
//!    `Z_FEATURE_LIVELINESS 1` and `Z_FEATURE_INTEREST 1` (verified in the
//!    generated `config.h`), and pico's token declaration itself arrives fine.
//!    So a wz<->pico unicast witness for this atom is not late, it is impossible,
//!    and no demo knob was ever going to produce it.
//!
//! 2. THE ORDERING DID NOT EVEN NEED A KNOB. A fixture can start the token
//!    holder first and gate on its declaration banner, which is what this one
//!    does — and it passes with `--liveliness-get-after-ms` absent entirely
//!    (measured, not assumed). The hold below is kept as a TIMING MARGIN for a
//!    one-shot get, not as the ordering the note claimed; see [`GET_HOLD_MS`].
//!
//! ## The topology that DOES witness it, and why each of the three is load-bearing
//!
//! `pico ──token──> zenohd <──get── wz`
//!
//! zenohd is the full Rust router and answers a CURRENT liveliness Interest over
//! unicast, which is exactly what pico declines to do. So zenohd is not scenery
//! here: it is the responder. And pico is not scenery either — it is the ORIGIN
//! of the token, so the `demo/token/pico` keyexpr wz decodes was declared by a
//! foreign implementation, routed by a second one, and parsed by this atom's
//! code. Drop pico and the reply is zenohd echoing an empty world; drop zenohd
//! and there is no responder at all.
//!
//! ## What this claims, and what it does not
//!
//! It claims the GET half: wz emits a CURRENT liveliness Interest a foreign
//! router accepts, and decodes the token reply plus its terminating final. It
//! does not claim `liveliness-history` (the CURRENT replay on a *subscriber*,
//! a different declaration) nor `liveliness-token` (wz declaring its own).

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, spawn_zenohd_on_ephemeral_tcp, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard,
};

/// A TIMING MARGIN, and deliberately not described as more than that.
///
/// The ordering this fixture needs is owned by the banner gate below, not by this
/// hold: pico's token is declared before wz is spawned at all, and the test passes
/// with the hold removed. What the banner cannot prove is that ZENOHD REGISTERED
/// the token — it proves only that pico sent it. The get is one-shot, so unlike
/// the burst-driven siblings here (whose 5x200ms burst is what "covers the window
/// for the subscription to reach zenohd") it has no second chance to absorb that
/// propagation window. This covers it.
///
/// So: a margin against a race not observed, on a proof with no retry — not a fix
/// for a race that was. If it ever earns a stronger claim, that claim needs a
/// measurement, not this comment.
const GET_HOLD_MS: u64 = 1_500;

// The kind is `wz->zenohd` because that is the wire exchange the claim rests on:
// zenohd is the peer that answers the Interest. pico does not appear in the kind
// vocabulary and should not -- it is the token's ORIGIN, not wz's counterparty,
// and that is a fact about the reply's CONTENT (see the module docs) rather than
// about who wz spoke to. The file's `pico,zenohd` corpus category is derived from
// the binaries it spawns, and reports the pico leg on its own.
// wz-proves: liveliness-get wz->zenohd
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenohd + zenoh-pico z_liveliness CLI); Layer Z runs via --ignored"]
fn wz_liveliness_get_decodes_a_pico_token_answered_by_zenohd() {
    let demo = wz_ap_demo_binary();
    let z_liveliness = zenoh_pico_cli_binary("z_liveliness");
    // The filter is a wildcard and the token is a literal, so the reply asserted
    // below can only be the result of a real intersect against a real token --
    // not an echo of what wz asked for.
    let get_filter = "demo/**";
    let pico_token = "demo/token/pico";

    // ── zenohd: the router, and the only responder in this topology ──────────
    // R311y413 — the port is DISCOVERED from zenohd's own announcement; naming
    // one in advance is what let another process hold it and zenohd exit 255.
    let (mut zenohd, port) = spawn_zenohd_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    let endpoint = format!("tcp/127.0.0.1:{port}");

    // ── zenoh-pico z_liveliness: the foreign TOKEN ORIGIN, a client of zenohd ─
    let pico_stdout = tempfile::tempfile().expect("tempfile for z_liveliness stdout");
    let pico_stdout_writer = pico_stdout.try_clone().expect("dup z_liveliness handle");
    let mut pico_stdout_reader = pico_stdout;
    let mut pico_child = ChildGuard::wrap(
        "z_liveliness token holder (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_liveliness)
            .args(["-k", pico_token, "-e", &endpoint, "-m", "client"])
            .stdout(Stdio::from(pico_stdout_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_liveliness via stdbuf"),
    );

    // THE FIXTURE OWNS ITS PRECONDITION. This banner is z_liveliness's own line
    // AFTER `z_liveliness_declare_token` returns (examples/unix/c11/z_liveliness.c),
    // so it is the token EXISTING, not merely the process starting. Without this
    // gate the assertion below would be a race: an empty snapshot and a slow
    // token are indistinguishable from the reply side.
    let declared = wait_for_substring(
        &mut pico_stdout_reader,
        "Press CTRL-C to undeclare liveliness token",
        Duration::from_secs(10),
    );
    if let Err(captured) = &declared {
        let _ = pico_child.child_mut().kill();
        let _ = zenohd.child_mut().kill();
        panic!(
            "z_liveliness never declared its token within 10s, so there is nothing for \
             wz's snapshot to find and this test would prove nothing.\n\
             --- captured z_liveliness stdout ---\n{captured}"
        );
    }

    // ── wz-ap-demo: a client of zenohd that issues ONE liveliness snapshot ────
    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr.try_clone().expect("dup demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect zenohd --liveliness-get)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--liveliness-get")
            .arg(get_filter)
            .arg("--liveliness-get-after-ms")
            .arg(GET_HOLD_MS.to_string())
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --liveliness-get"),
    );

    // The assertion is the FULL reply line, filter and token both. A bare
    // "LIVELINESS GET REPLY" would pass on a reply carrying anything at all, and
    // matching only the filter would pass on wz echoing its own request back.
    // This form can only come from wz decoding a token that pico declared and
    // zenohd routed.
    let expected = format!("LIVELINESS GET REPLY filter='{get_filter}' keyexpr='{pico_token}'");
    let replied = wait_for_substring(&mut demo_stderr_reader, &expected, Duration::from_secs(20));

    // The terminating final is asserted too: a snapshot that never finals is a
    // hung get, not a served one, and the atom's surface is both halves.
    let finaled = wait_for_substring(
        &mut demo_stderr_reader,
        "LIVELINESS GET FINAL",
        Duration::from_secs(10),
    );

    let demo_captured = read_captured(&mut demo_stderr_reader);
    let pico_captured = read_captured(&mut pico_stdout_reader);
    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = pico_child.child_mut().kill();
    let _ = pico_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    if let Err(captured) = &replied {
        panic!(
            "wz's liveliness snapshot never decoded pico's token. Expected {expected:?} \
             -- pico declared '{pico_token}' to zenohd BEFORE the get was issued (its \
             banner was gated on above), and the get was held {GET_HOLD_MS}ms past \
             Established, so neither the token nor the ordering can explain this.\n\
             --- captured wz-ap-demo stderr ---\n{captured}\n\
             --- captured z_liveliness stdout ---\n{pico_captured}"
        );
    }
    if let Err(captured) = &finaled {
        panic!(
            "wz decoded the token reply but the get never finalled -- the snapshot is \
             hung, not served.\n--- captured wz-ap-demo stderr ---\n{captured}\n\
             --- full demo stderr ---\n{demo_captured}"
        );
    }
}
