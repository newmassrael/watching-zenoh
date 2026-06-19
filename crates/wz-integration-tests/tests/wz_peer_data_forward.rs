// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ri / R311rs — c3c e2e: linkstate-peer SUBSCRIPTION-FILTERED mesh data
//! forwarding over a 3-peer LINE.
//!
//! Topology (all the `--features routing-peer` binary, ephemeral ports read
//! back from each peer's listen log):
//!   - peer C: `--peer 127.0.0.1:0 --subscribe demo/mesh` — the FAR SUBSCRIBER
//!     (2 hops from the publisher), declaring interest in the keyexpr.
//!   - peer B: `--peer 127.0.0.1:0 --connect <C>` — dials C (the transit hop;
//!     NOT a subscriber, it only relays toward C).
//!   - peer A: `--peer 127.0.0.1:0 --connect <B> --publish demo/mesh` — dials B
//!     AND originates data into the mesh.
//!
//! So the linkstate edges are A<->B and B<->C (a line A-B-C). C's subscription
//! floods C -> B -> A, so A LEARNS that C is interested in `demo/mesh`. Only
//! then does A's subscription-filtered route (c3c-3 atom4) forward the Put:
//! `directions_toward` the interested C picks A's child B, and B re-forwards to
//! ITS child C (re-stamping the routing-context NodeId). C therefore RECEIVES
//! data it has no direct link to the publisher for — the end-to-end proof that
//! the FULL c3c-3 chain works over real TCP: declare_subscription (c3c-3 atom3)
//! propagates interest A-ward, and the filtered data route (atom4) then delivers
//! C-ward. Without C's subscription the publisher's any-interest gate would
//! forward nothing.
//!
//! Requires the binary built with `--features routing-peer` (the `--peer` /
//! `--publish` / `--subscribe` args are opt-in behind it). run-ci's Layer E
//! builds it so this rides the same `--ignored` lane as the other binary-dep
//! e2es.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_substring, wz_ap_demo_binary, ChildGuard,
};

/// Parse the bound port from a peer's `listening on 127.0.0.1:<port>` log line
/// — the ephemeral-port read-back that lets the next peer dial this one without
/// a reserved-port allocation.
fn listen_port(captured: &str) -> u16 {
    let marker = "listening on 127.0.0.1:";
    let rest = captured
        .split(marker)
        .nth(1)
        .unwrap_or_else(|| panic!("no '{marker}' in:\n{captured}"));
    rest.chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap_or_else(|e| panic!("unparseable port after '{marker}': {e}\n{captured}"))
}

/// Spawn a `--peer` demo on an ephemeral port and wait until it binds, then read
/// the bound port back from its listen log. Returns the guard, its stderr
/// reader, and the port.
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

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer); Layer E runs via --ignored"]
fn wz_peer_mesh_forwards_subscribed_data_two_hops() {
    // C (far SUBSCRIBER) binds first so B can dial it; then B binds so A can
    // dial it. C declares interest in demo/mesh, which floods C -> B -> A.
    let (mut c_guard, mut c_reader, p_c) = spawn_peer(
        "peer-C",
        &["--peer", "127.0.0.1:0", "--subscribe", "demo/mesh"],
    );
    let addr_c = format!("127.0.0.1:{p_c}");
    let (mut b_guard, mut b_reader, p_b) =
        spawn_peer("peer-B", &["--peer", "127.0.0.1:0", "--connect", &addr_c]);
    let addr_b = format!("127.0.0.1:{p_b}");
    let (mut a_guard, mut a_reader, _p_a) = spawn_peer(
        "peer-A",
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &addr_b,
            "--publish",
            "demo/mesh",
        ],
    );

    // The FAR SUBSCRIBER C must RECEIVE A's published data — but only because
    // its subscription flooded A-ward and A's filtered route then forwarded
    // A -> B -> C (B re-stamping the routing-context NodeId for C). C has NO
    // direct link to A, so receiving this proves the full subscription-gated
    // multi-hop chain (declare propagate + filtered data route) over the wire.
    let c_data = wait_for_substring(&mut c_reader, "received mesh data", Duration::from_secs(15));

    // Graceful-shutdown all three, then read their captured logs.
    graceful_terminate(a_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(b_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(c_guard.child_mut(), Duration::from_secs(5));
    let a_captured = read_captured(&mut a_reader);
    let b_captured = read_captured(&mut b_reader);
    let c_captured = read_captured(&mut c_reader);
    eprintln!("--- peer-A stderr ---\n{a_captured}");
    eprintln!("--- peer-B stderr ---\n{b_captured}");
    eprintln!("--- peer-C stderr ---\n{c_captured}");

    // Diagnostics printed; now assert.
    c_data.unwrap_or_else(|c| {
        panic!(
            "peer-C (2 hops from the publisher) never logged 'received mesh data' within \
             15s — A's published data did not flood through B to C (multi-hop forward \
             did not reach the far peer)\n--- peer-C stderr ---\n{c}"
        )
    });
    // The publisher A must have LEARNED C's subscription — the declaration
    // flooded C -> B -> A — before its any-interest gate would forward anything.
    // This is the subscription half of the chain: without it, the filtered data
    // route never fires (so C's reception above is genuinely subscription-gated,
    // not a leftover broadcast).
    assert!(
        a_captured.contains("publisher learned subscriber interest"),
        "peer-A never learned C's subscription — the declaration did not flood \
         A-ward, so the subscription-filtered route could not enable the \
         publish\n--- peer-A stderr ---\n{a_captured}"
    );
    // The transit hop B must ALSO have received the data (it is what forwarded
    // it onward to C) — distinguishing a true two-hop relay from a fluke. B is
    // read AFTER shutdown, so this matches B's DETERMINISTIC shutdown-summary
    // witness (gated on data_seen > 0), not the in-run app-tick log B might be
    // SIGTERM'd before firing (R311rj — the prior in-run-only assertion was
    // flaky under load).
    assert!(
        b_captured.contains("received mesh data"),
        "peer-B (the transit hop) must have received and forwarded A's data\n\
         --- peer-B stderr ---\n{b_captured}"
    );
}
