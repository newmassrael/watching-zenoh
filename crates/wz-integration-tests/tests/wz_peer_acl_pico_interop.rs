// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y368 — FOREIGN-INTEROP ACCESS CONTROL: a real zenoh-pico `z_put` CLI
//! publishes to a watching-zenoh routing peer that has §5.16 access control
//! enabled (`--acl-deny secret/**`), and the peer's ACL interceptor DROPS the
//! pico Put whose keyexpr matches the deny rule while ADMITTING the one that
//! does not.
//!
//! ## The atom, and why the positive control is in the same leg
//!
//! `access-acl`'s `F=` is not "a peer runs" — it is the §5.16 ACL INTERCEPTOR
//! consulted at the inbound relay-admission point (`admit_inbound`,
//! `linkstate_forward.rs`), which for `--acl-deny secret/**` builds an ingress
//! Deny rule over `secret/**` and drops any inbound Push whose keyexpr matches
//! (dropped = not counted in `data_seen`, not relayed, not dispatched). A test
//! that only showed `secret/x` NOT arriving could pass on a dead session; a test
//! that only showed `public/x` arriving would witness routing, not the ACL. So
//! ONE leg drives BOTH from pico against the SAME peer instance: `public/x` is
//! admitted (the positive control — the session and route work), `secret/x` is
//! dropped (the gate the atom IS). pico is the ENCODER on the wire — its C stack
//! builds both Puts, and wz's ACL interceptor decodes and adjudicates them by
//! subject (the pico peer's zid) and keyexpr.
//!
//! ## Wire path
//!
//! wz runs as a `--peer` LISTENing on tcp (its accept side is tcp-only), pico
//! `z_put -m client` dials it. The witness is the wz peer's OWN admit/drop
//! counters (`received mesh data (N push(es))` / `interceptor dropped (N
//! message(s))`) plus the graceful-shutdown data-push summary — a second
//! subscriber is not needed because the drop is observable at ingress.
//!
//! RED (proof binds to the ACL code): the same peer WITHOUT `--acl-deny` admits
//! `secret/x` too (`received mesh data (2 push(es))`, no `interceptor dropped`),
//! so the `interceptor dropped` barrier times out and the summary asserts fail.
//! Requires the binary built with `--features routing-peer` (which pulls
//! `access-acl`); Layer E6 builds `routing-peer,adminspace-write`.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, listen_port, read_captured, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard,
};

/// Spawn a `--peer` demo on an ephemeral port and wait until it binds, then read
/// the bound port back from its listen log. Mirrors `wz_peer_data_forward.rs`'s
/// `spawn_peer`. Returns the guard, its stderr reader, and the port.
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

/// Drive pico's `z_put` CLI (`-m client`) at the wz peer's tcp listener, encoding
/// a Put on `key` with `value`. pico ENCODES; wz's ACL interceptor decodes and
/// adjudicates. Blocks until the one-shot CLI exits (fire-and-forget: the Put
/// reaches wz ingress even with no matching subscriber).
fn pico_z_put(key: &str, value: &str, addr: &str) {
    let z_put = zenoh_pico_cli_binary("z_put");
    let mut child = ChildGuard::wrap(
        format!("z_put client (zenoh-pico) {key}"),
        Command::new(&z_put)
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

/// leg (R311y368) — a pico `z_put` to a wz peer's DENIED keyexpr is dropped by
/// the §5.16 ACL interceptor, while a `z_put` to an ALLOWED keyexpr is admitted.
/// pico is the encoder; the wz peer (`--acl-deny secret/**`) is the adjudicator.
// wz-proves: access-acl pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer + zenoh-pico z_put CLI); Layer E6 runs via --ignored"]
fn wz_peer_acl_denies_pico_zput_to_denied_keyexpr() {
    // The wz peer: ACL enabled, denying `secret/**` at ingress, subscribed to
    // everything so an ADMITTED put is counted as received mesh data.
    let (mut peer_guard, mut peer_reader, port) = spawn_peer(
        "acl-peer",
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

    // Positive control: pico Put on the ALLOWED key must be admitted (proves the
    // session + route work, so a later NON-arrival is the ACL, not a dead peer).
    pico_z_put("public/x", "hello-public", &addr);
    let admitted = wait_for_substring(
        &mut peer_reader,
        "received mesh data",
        Duration::from_secs(15),
    );

    // The atom: pico Put on the DENIED key must be dropped by the ACL interceptor.
    pico_z_put("secret/x", "hello-secret", &addr);
    let dropped = wait_for_substring(
        &mut peer_reader,
        "interceptor dropped",
        Duration::from_secs(15),
    );

    graceful_terminate(peer_guard.child_mut(), Duration::from_secs(5));
    let captured = read_captured(&mut peer_reader);
    eprintln!("--- acl-peer stderr ---\n{captured}");

    if let Err(c) = &admitted {
        panic!(
            "wz peer never admitted the ALLOWED public/x put within 15s (positive \
             control) — the peer/session/route is broken, not the ACL.\n\
             --- acl-peer stderr at deadline ---\n{c}"
        );
    }
    if let Err(c) = &dropped {
        panic!(
            "wz peer never logged 'interceptor dropped' for the DENIED secret/x \
             put within 15s — the §5.16 ACL did not fire (secret/** leaked).\n\
             --- acl-peer stderr at deadline ---\n{c}"
        );
    }
    // The §5.16 ingress ACL denied exactly the one secret/** Put ...
    assert!(
        captured.contains("interceptor dropped (1 message(s))"),
        "expected the ACL to drop exactly 1 message (the secret/x put).\n\
         --- acl-peer stderr ---\n{captured}"
    );
    // ... and admitted exactly the one public/x Put (positive control) ...
    assert!(
        captured.contains("1 data push(es) received"),
        "expected exactly 1 admitted data push (the public/x put).\n\
         --- acl-peer stderr ---\n{captured}"
    );
    // ... and the DENIED secret/x did NOT slip past to become a 2nd admitted push.
    assert!(
        !captured.contains("2 data push(es) received"),
        "the DENIED secret/x leaked past the §5.16 ACL and was admitted as a 2nd \
         data push.\n--- acl-peer stderr ---\n{captured}"
    );
}
