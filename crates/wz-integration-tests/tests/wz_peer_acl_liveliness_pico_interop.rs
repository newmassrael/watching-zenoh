// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y459 — FOREIGN-INTEROP ACCESS CONTROL, LIVELINESS PLANE: real zenoh-pico
//! CLIs drive the three §5.16 message kinds R311y458 added arms for — a
//! `DeclareToken`, its `UndeclareToken`, and a token-carrying CURRENT `Interest`
//! — against a watching-zenoh routing peer running `--acl-deny secret/**`. The
//! peer denies all three on the denied keyexpr and admits all three on the
//! allowed one.
//!
//! ## Why this leg exists, and what it adds over the R311y368 `z_put` sibling
//!
//! Until R311y458 the §5.16 A4 witness was ONE pico `z_put` leg, i.e. the DATA
//! plane only. R311y458 made wz's governed set equal zenoh's by adding the three
//! undeclare kinds, the liveliness token, and the token-Interest — and every one
//! of those arms was pinned by wz's OWN unit tests, with nothing foreign driving
//! them. This leg is that missing witness: pico is the ENCODER (its C stack
//! builds the Declare, the Undeclare and the Interest on the wire), wz's ACL
//! interceptor decodes and adjudicates by subject + keyexpr.
//!
//! ## What each pico CLI actually emits, read from the vendored source
//!
//! Not inferred from the drop counts — the counts below are only credible
//! because the emitting code was read first:
//!
//! - `z_liveliness -k K -t N` declares a token on `K`, sleeps N seconds, then
//!   UNDECLARES it (`examples/unix/c11/z_liveliness.c`). Both messages carry the
//!   keyexpr: `_z_liveliness_send_declare_token` builds a `DeclToken` with an
//!   inline wireexpr and `_z_liveliness_send_undeclare_token` builds an
//!   `UndeclToken` with the wireexpr as its OPTIONAL ext
//!   (`src/net/liveliness.c:32-50`, `_z_make_undecl_token(id, &wireexpr)`). So
//!   the denied token costs TWO drops, one second apart, and the second one is
//!   what exercises the y458 undeclare arm through its `ext_wire_expr`.
//! - `z_get_liveliness -k K` sends EXACTLY ONE message: an `Interest` with
//!   `KEYEXPRS | TOKENS | RESTRICTED | CURRENT` and no subscriber declaration
//!   (`src/net/liveliness.c:314-362`). CURRENT-only is the mode wz maps to
//!   `AclMessage::LivelinessQuery`, so its single drop is attributable to the
//!   Interest arm and to nothing else.
//!
//! The one-second gap between the token's two drops is asserted structurally by
//! using `-t 1`; the measurement that established it used `-t 3` and saw the gap
//! move with it, which is how "the second drop is the undeclare" was settled
//! rather than assumed.
//!
//! ## Wire path and witness
//!
//! wz runs as a `--peer` LISTENing on tcp (its accept side is tcp-only), each
//! pico CLI dials it with `-m client`. The witness is the peer's own drop
//! counter (`interceptor dropped (N message(s))`) plus the data-push summary.
//! ALL allowed traffic runs FIRST and must leave the counter at zero — that is
//! the positive control, and it is stronger than a per-message one because it
//! proves the ACL is not simply dropping the whole liveliness plane.
//!
//! RED (the proof binds to the ACL code): before R311y458 none of these kinds
//! was governed, so every drop barrier here times out. Dropping only the
//! `AclMessage` additions makes the same three admit. Requires the binary built
//! with `--features routing-peer` (which pulls `access-acl`); Layer E6 builds
//! `routing-peer,adminspace-write`.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, listen_port, read_captured, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard,
};

/// Spawn a `--peer` demo on an ephemeral port and wait until it binds, then read
/// the bound port back from its listen log. The twin of the `z_put` ACL leg's
/// `spawn_peer` (`wz_peer_acl_pico_interop.rs`).
fn spawn_peer(label: &str, args: &[&str]) -> (ChildGuard, File, u16) {
    let stderr = tempfile::tempfile().expect("tempfile for peer stderr");
    let writer = stderr.try_clone().expect("dup peer stderr handle");
    let mut reader = stderr;
    let mut guard = ChildGuard::wrap(
        label.to_string(),
        Command::new(wz_ap_demo_binary())
            .args(args)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {label}: {e}")),
    );
    let captured = wait_for_substring(
        &mut reader,
        "peer: listening on 127.0.0.1:",
        Duration::from_secs(5),
    )
    .unwrap_or_else(|c| {
        let _ = guard.child_mut().kill();
        let _ = guard.child_mut().wait();
        panic!(
            "{label} did not bind within 5s (is the binary built with \
                     --features routing-peer?)\n--- {label} stderr ---\n{c}"
        );
    });
    let port = listen_port(&captured);
    (guard, reader, port)
}

/// Drive pico's `z_put` CLI at the wz peer — the SESSION-ALIVE control, so a
/// later non-arrival is the ACL and not a dead peer. Blocks until it exits.
fn pico_z_put(key: &str, value: &str, addr: &str) {
    let mut child = ChildGuard::wrap(
        format!("z_put client (zenoh-pico) {key}"),
        Command::new(zenoh_pico_cli_binary("z_put"))
            .args([
                "-k",
                key,
                "-v",
                value,
                "-e",
                &format!("tcp/{addr}"),
                "-m",
                "client",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_put"),
    );
    let _ = child.child_mut().wait();
}

/// Drive pico's `z_liveliness` CLI: declare a token on `key`, hold it one
/// second, undeclare it, exit. TWO governed messages, both carrying `key`.
/// Blocks until the CLI exits, so both have reached wz ingress on return.
fn pico_z_liveliness(key: &str, addr: &str) {
    let mut child = ChildGuard::wrap(
        format!("z_liveliness client (zenoh-pico) {key}"),
        Command::new(zenoh_pico_cli_binary("z_liveliness"))
            .args([
                "-k",
                key,
                "-t",
                "1",
                "-e",
                &format!("tcp/{addr}"),
                "-m",
                "client",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_liveliness"),
    );
    let _ = child.child_mut().wait();
}

/// Drive pico's `z_get_liveliness` CLI in the BACKGROUND — ONE token-carrying
/// CURRENT `Interest`, sent at session open. It is not awaited because the
/// example has no timeout flag and a DENIED get never receives its terminating
/// `DeclareFinal`, so it would sit out pico's internal timeout; the verdict is
/// observable at the peer the moment the Interest lands. The caller kills it.
fn pico_z_get_liveliness_bg(key: &str, addr: &str) -> ChildGuard {
    ChildGuard::wrap(
        format!("z_get_liveliness client (zenoh-pico) {key}"),
        Command::new(zenoh_pico_cli_binary("z_get_liveliness"))
            .args(["-k", key, "-e", &format!("tcp/{addr}"), "-m", "client"])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_get_liveliness"),
    )
}

/// leg (R311y459) — pico's liveliness CLIs against a wz peer denying
/// `secret/**`: the DeclareToken, its UndeclareToken and a token-carrying
/// CURRENT Interest are each dropped on the denied keyexpr, and each admitted on
/// the allowed one. pico is the encoder; the wz peer is the adjudicator.
// wz-proves: access-acl pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer + zenoh-pico z_liveliness / z_get_liveliness CLIs); Layer E6 runs via --ignored"]
fn wz_peer_acl_denies_pico_liveliness_token_and_get() {
    let (mut peer_guard, mut peer_reader, port) = spawn_peer(
        "acl-liveliness-peer",
        &[
            "--peer",
            "127.0.0.1:0",
            "--subscribe",
            "**",
            "--acl-deny",
            "secret/**",
        ],
    );
    let addr = format!("127.0.0.1:{port}");

    // ── POSITIVE CONTROL: every ALLOWED message first, and the counter must
    // still be at zero afterwards. A put proves the session and route work; the
    // allowed token (declare + undeclare) and the allowed get prove the ACL is
    // not simply dropping the liveliness plane wholesale, which a per-message
    // control could not distinguish.
    pico_z_put("public/x", "hello-public", &addr);
    let admitted = wait_for_substring(
        &mut peer_reader,
        "received mesh data",
        Duration::from_secs(15),
    );
    pico_z_liveliness("public/alive", &addr);
    let mut allowed_get = pico_z_get_liveliness_bg("public/**", &addr);
    std::thread::sleep(Duration::from_secs(2));
    let _ = allowed_get.child_mut().kill();
    let _ = allowed_get.child_mut().wait();

    // ── THE ATOM, one denied kind at a time so each barrier is attributable.
    // The token costs TWO drops: the DeclareToken at session open and the
    // UndeclareToken one second later (pico carries the keyexpr on both).
    pico_z_liveliness("secret/alive", &addr);
    let token_dropped = wait_for_substring(
        &mut peer_reader,
        "interceptor dropped (2 message(s))",
        Duration::from_secs(15),
    );

    // The token-carrying CURRENT Interest is pico's only message here, so the
    // third drop is the Interest arm and nothing else.
    let mut denied_get = pico_z_get_liveliness_bg("secret/**", &addr);
    let get_dropped = wait_for_substring(
        &mut peer_reader,
        "interceptor dropped (3 message(s))",
        Duration::from_secs(15),
    );
    let _ = denied_get.child_mut().kill();
    let _ = denied_get.child_mut().wait();

    graceful_terminate(peer_guard.child_mut(), Duration::from_secs(5));
    let captured = read_captured(&mut peer_reader);
    eprintln!("--- acl-liveliness-peer stderr ---\n{captured}");

    if let Err(c) = &admitted {
        panic!(
            "wz peer never admitted the ALLOWED public/x put within 15s (session \
             control) — the peer/session/route is broken, not the ACL.\n\
             --- acl-liveliness-peer stderr at deadline ---\n{c}"
        );
    }
    if let Err(c) = &token_dropped {
        panic!(
            "wz peer never reached 'interceptor dropped (2 message(s))' for the \
             DENIED secret/alive token within 15s — the §5.16 ACL did not govern \
             the DeclareToken and its UndeclareToken.\n\
             --- acl-liveliness-peer stderr at deadline ---\n{c}"
        );
    }
    if let Err(c) = &get_dropped {
        panic!(
            "wz peer never reached 'interceptor dropped (3 message(s))' for the \
             DENIED secret/** liveliness get within 15s — the §5.16 ACL did not \
             govern the token-carrying CURRENT Interest.\n\
             --- acl-liveliness-peer stderr at deadline ---\n{c}"
        );
    }
    // The session-alive control landed ...
    assert!(
        captured.contains("1 data push(es) received"),
        "expected exactly 1 admitted data push (the public/x put).\n\
         --- acl-liveliness-peer stderr ---\n{captured}"
    );
    // ... every ALLOWED liveliness message was admitted, so the FIRST drop can
    // only be the denied token: had the allowed token or get been dropped, the
    // counter would already have been past 1 before secret/alive ran.
    assert!(
        captured.contains("interceptor dropped (1 message(s))")
            && captured.contains("interceptor dropped (2 message(s))"),
        "expected the denied token to produce drops 1 and 2 (DeclareToken + \
         UndeclareToken).\n--- acl-liveliness-peer stderr ---\n{captured}"
    );
    // ... and nothing beyond the three denied messages entered the drop path.
    assert!(
        !captured.contains("interceptor dropped (4 message(s))"),
        "a 4th message was dropped: the ACL is denying more than the three \
         secret/** liveliness messages this leg sends.\n\
         --- acl-liveliness-peer stderr ---\n{captured}"
    );
}
