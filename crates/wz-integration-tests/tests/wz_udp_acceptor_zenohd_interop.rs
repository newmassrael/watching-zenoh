// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y399 — §5.1 transport / §5.2 locator — CROSS-IMPL validation of the wz
//! UDP-DEMUX ACCEPTOR (`transport-link-udp`, zenohd->wz direction) — the FIRST
//! cross-impl proof of a structurally-DATAGRAM wz acceptor.
//!
//! The existing `wz_to_zenohd_router.rs` udp leg proves the wz udp DIALER (wz
//! `--connect udp/...` against zenohd's `udp/` listener — `transport-link-udp
//! wz->zenohd`). The REVERSE — a foreign peer DIALING a wz `udp/...` acceptor — had
//! no cross-impl proof: wz's UDP acceptor (`bind_udp_demux` -> `BoundListener::Udp`,
//! the pump-task demux that routes each datagram to its SOURCE's per-face channel)
//! landed in R311y382 and is proven wz<->wz (`udp_seam_e2e`), but no INDEPENDENT
//! impl had ever dialed it. This is that proof — the datagram sibling of the stream
//! acceptor cross-impl legs `wz_ws_acceptor_zenohd_interop` /
//! `wz_tls_acceptor_zenohd_interop` / `wz_unixsock_acceptor_zenohd_interop`.
//!
//! Vehicle: zenoh-pico HAS a udp client, but here the pico publisher attaches to
//! zenohd over TCP and ONLY the zenohd->wz hop is udp, so a real **zenohd** is the
//! foreign udp dialer under test. Topology (a STAR through zenohd):
//!
//!   pico `z_pub` --tcp--> zenohd --udp--> wz `--listen udp/127.0.0.1:0` (subscriber)
//!
//! zenohd DIALS the wz udp acceptor (`-e udp/<wz>`) and also listens on tcp for the
//! pico publisher; a pico `z_pub` on that tcp listener routes through zenohd and
//! ACROSS the udp link to the wz acceptor, whose subscriber fires. The pico
//! publisher never speaks udp to wz and never knows wz's udp address, so the wz
//! subscriber firing is a definitive witness that (1) wz accepted a real foreign
//! **udp** session (the zenohd dial completed the zenoh handshake over UDP
//! datagrams, demuxed by source) and (2) data crossed that udp link into wz.
//!
//! Discriminator: wz binds ONLY the `--listen udp/...` acceptor and NO TCP
//! listener, so the sole wz<->zenohd transport is udp — a fire is structurally
//! impossible over any non-udp path. The test ASSERTS the `(udp)` suffix on wz's
//! "listening on" line (the transport-specific positive witness, the udp analogue of
//! the ws "ws server upgrade" / tls "tls server handshake" siblings), and the
//! accepted peer is the datagram SOURCE (an IP address, the udp src the demux keyed
//! the face on). The delivery discriminator — a keyexpr mismatch never fires — is
//! the RED-capable delivery pin (author-witnessed RED, like the siblings).
//!
//! Feature-gate RED (as for the ws/tls/unixsock siblings, author-witnessed): a demo
//! built WITHOUT the udp transport rejects the `udp/` listen with a typed
//! `Unsupported` ("listen/accept is wired only for tcp; udp acceptor requires the
//! transport-link-udp feature", session_open.rs) — it never binds, so
//! `spawn_on_ephemeral_port` panics ("did not bind within 10s"). NOTE the
//! two-feature trap: the demo's default preset-ap-client enables udp via BOTH
//! `transport-link-udp` AND `locator-udp` (`locator-udp = ["transport-link-udp"]`),
//! so BOTH must be dropped to elide it — removing only `transport-link-udp` leaves
//! udp re-pulled through `locator-udp`. The wz facade deps `wz-runtime-tokio` with
//! `default-features = false`, so the runtime's default udp does not leak in and the
//! elision is fully expressible through facade flags.
//!
//! `#[ignore]` (binary-dep e2e): needs the reference `zenohd` (STOCK build — udp is
//! in zenoh's default features, no special oracle) AND the zenoh-pico CLI (`z_pub`).
//! Runs on the `--ignored` Layer Z lane; the `zenohd` substring in the fn name
//! keeps the default Layer E sweep's `--skip zenohd` from running it against an
//! arbitrary-feature binary. UDP is unreliable, so the publisher bursts (`z_pub -n
//! 30`) and the routed subscriber declaration is awaited before the burst
//! (no-flaky).

use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, spawn_on_ephemeral_port, spawn_publishing_zpub, spawn_zenohd_udp_dialer,
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary,
};

const SUB_FILTER: &str = "demo/udp/**";
const PUBLISH_KEY: &str = "demo/udp/acc";
const PUBLISH_VALUE: &str = "hello-udp-acceptor-via-zenohd";

/// pico `z_pub` -> zenohd (tcp) -> wz `--listen udp/...` (udp): a real zenohd dials
/// the wz UDP-demux acceptor, and a pico publisher's Put routes across that udp link
/// to the wz subscriber — the `transport-link-udp` atom's first cross-impl proof in
/// the zenohd->wz (acceptor) direction, and the first datagram-acceptor cross-impl.
// R311y422 — the SAME run is the locator atom's witness: the `--listen
// udp/...` string above is parsed by wz's OWN grammar (locator.rs Proto::Udp) before
// any socket exists, so a zenohd that connects proves wz read the foreign-
// facing locator form correctly. A4-5 containment is exempt for a
// FOUNDATIONAL atom (it names no cfg site), so this claim rests on that
// reading, not on the audit -- verified by hand at R311y422.
// wz-proves: transport-link-udp zenohd->wz
// wz-proves: locator-udp zenohd->wz
// wz-proves: session-unicast-open zenohd->wz
#[test]
#[ignore = "binary-dep e2e: needs zenohd (stock) + zenoh-pico z_pub; runs via --ignored"]
fn wz_udp_acceptor_receives_pico_put_via_zenohd() {
    let demo = wz_ap_demo_binary();
    let z_pub = zenoh_pico_cli_binary("z_pub");

    // wz acceptor: bind an EPHEMERAL udp port, subscribe on SUB_FILTER, hold no TCP
    // listener. `spawn_on_ephemeral_port` reads the bound port back from the "wz
    // accept: listening on 127.0.0.1:<port> (udp)" line (the "(udp)" suffix follows
    // the digits, so the port parse is unaffected) and PANICS if wz never binds (the
    // feature-gate discriminator: a demo whose `transport-link-udp` is compiled out
    // rejects the listen and never logs it).
    let wz_stderr = tempfile::tempfile().expect("tempfile for wz acceptor stderr");
    let (mut wz_guard, mut wz_reader, udp_port) = spawn_on_ephemeral_port(
        &demo,
        &["--listen", "udp/127.0.0.1:0", "--key", SUB_FILTER],
        "wz accept: listening on 127.0.0.1:",
        "wz udp acceptor",
        wz_stderr,
    );

    // zenohd DIALS the wz udp acceptor (`-e udp/127.0.0.1:<udp_port>`) + listens on
    // tcp for the pico publisher. A reserved tcp port (dropped just before zenohd
    // binds it) keeps parallel runs collision-free.
    let wz_udp_endpoint = format!("udp/127.0.0.1:{udp_port}");
    // R311y412 — the tcp port is DISCOVERED from zenohd's own announcement, not
    // reserved-then-released: the release opens a window in which any other process
    // can take the port, and zenohd then exits 255 before accepting (measured 5
    // failures in 210 runs of this lane under ephemeral-port churn).
    let (mut zenohd, tcp_port) = spawn_zenohd_udp_dialer(&wz_udp_endpoint);
    let tcp_endpoint = format!("tcp/127.0.0.1:{tcp_port}");

    // wz accepts the zenohd udp dial + completes the handshake, then (on Established)
    // declares its routed subscriber onto the accepted session, installing the route
    // on zenohd.
    let established = wait_for_substring(
        &mut wz_reader,
        "session Established",
        Duration::from_secs(10),
    );
    let declared = established.is_ok().then(|| {
        wait_for_substring(
            &mut wz_reader,
            "DECLARED ROUTED SUBSCRIBER",
            Duration::from_secs(10),
        )
    });

    // pico z_pub over TCP — after wz's routed subscriber declaration reached zenohd
    // (route installed); the 30x burst covers UDP loss + residual propagation lag.
    let z_pub_child = matches!(&declared, Some(Ok(_))).then(|| {
        spawn_publishing_zpub(
            &z_pub,
            PUBLISH_KEY,
            PUBLISH_VALUE,
            &tcp_endpoint,
            "zenohd-udp",
            || tempfile::tempfile().expect("tempfile for z_pub stdout"),
        )
    });

    let fired = wait_for_substring(&mut wz_reader, "SUBSCRIBER FIRED", Duration::from_secs(15));

    if let Some(mut c) = z_pub_child {
        let _ = c.child_mut().kill();
        let _ = c.child_mut().wait();
    }
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    let _ = wz_guard.child_mut().kill();
    let _ = wz_guard.child_mut().wait();

    let wz_captured = read_captured(&mut wz_reader);
    eprintln!("--- wz udp acceptor stderr ---\n{wz_captured}");

    // Positive transport witness (family symmetry with the ws "ws server upgrade" /
    // tls "tls server handshake" siblings): wz logged a `(udp)` acceptor listen line,
    // so the accepted session is genuinely over the udp-demux acceptor. Cheap because
    // wz binds ONLY udp — but it turns the transport into an assertion, not an
    // inference.
    assert!(
        wz_captured.contains("(udp)"),
        "wz never logged a '(udp)' acceptor listen line — the acceptor was not the udp \
         transport.\n--- wz stderr ---\n{wz_captured}"
    );

    established.unwrap_or_else(|c| {
        panic!(
            "wz acceptor never logged 'session Established' within 10s — zenohd's udp \
             dial did not complete the handshake with wz's demux acceptor.\n--- wz stderr ---\n{c}"
        )
    });
    declared
        .expect("the DECLARED-ROUTED-SUBSCRIBER wait runs once the session Established")
        .unwrap_or_else(|c| {
            panic!(
                "wz-ap-demo never logged 'DECLARED ROUTED SUBSCRIBER' within 10s of Established — \
                 the acceptor-side routed subscriber declare regressed.\n--- wz stderr ---\n{c}"
            )
        });
    let fired_text = fired.unwrap_or_else(|c| {
        panic!(
            "wz never logged 'SUBSCRIBER FIRED' within 15s — the pico Put did not route through \
             zenohd and across the udp link into wz's acceptor's subscriber.\n\
             --- wz stderr ---\n{c}"
        )
    });

    // The fired sample must carry the agreed keyexpr — a UNIQUE keyexpr only this
    // pico z_pub publishes, so the fire pins THIS Put crossing the udp link (a bare
    // "SUBSCRIBER FIRED" on nothing else could be a stale artifact). The exact
    // payload LENGTH is NOT asserted: `spawn_publishing_zpub` uses the zenoh-pico
    // `z_pub` example, which prefixes each sample with a `[ idx] ` counter, so the
    // wire payload is longer than PUBLISH_VALUE — the keyexpr uniqueness is the
    // discriminator (as in the sibling `wz_unixsock_acceptor_zenohd_interop`).
    assert!(
        fired_text.contains(PUBLISH_KEY),
        "the wz subscriber fired, but not on the routed keyexpr '{PUBLISH_KEY}'.\n{fired_text}"
    );
}
