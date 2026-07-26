// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y400 — §5.1 transport / §5.2 locator — CROSS-IMPL validation of the wz
//! VSOCK (AF_VSOCK) ACCEPTOR (`transport-link-vsock`, zenohd->wz direction), the
//! LAST remaining accept-direction cross-impl gap.
//!
//! wz's vsock ACCEPTOR arm (`bind_locator`'s `AnyLocator::Vsock` -> `BoundListener::Vsock`,
//! plus `accept_raw`'s direct wrap — no post-accept handshake, R311xj) is proven
//! wz<->wz by `wz_runtime_tokio::vsock_e2e`, but no INDEPENDENT impl had ever dialed
//! it. This is that proof — the AF_VSOCK sibling of
//! `wz_unixsock_acceptor_zenohd_interop` / `wz_ws_acceptor_zenohd_interop`.
//!
//! Vehicle: zenoh-pico has NO vsock client, so a real **zenohd** (built with
//! `zenoh/transport_vsock`) is the only available foreign vsock dialer. Topology (a
//! STAR through zenohd):
//!
//!   pico `z_pub` --tcp--> zenohd --vsock--> wz `--listen vsock/...` (subscriber)
//!
//! zenohd DIALS the wz vsock acceptor (`-e vsock/VMADDR_CID_LOCAL:<port>`) and also
//! listens on tcp for the pico publisher; a pico `z_pub` on that tcp listener routes
//! through zenohd and ACROSS the AF_VSOCK loopback link to the wz acceptor, whose
//! subscriber fires. The pico publisher never speaks vsock, so the wz subscriber
//! firing is a definitive witness that (1) wz accepted a real foreign **vsock**
//! session (the zenohd dial completed the zenoh handshake over AF_VSOCK) and (2) data
//! crossed that vsock link into wz. wz binds ONLY vsock (no TCP listener), so vsock is
//! the sole wz<->zenohd transport.
//!
//! Discriminator (binds to the vsock acceptor): a `wz-ap-demo` built WITHOUT the
//! `vsock` feature rejects a `vsock/...` listen with a typed `Unsupported` ("vsock
//! accept requires the transport-link-vsock feature on Linux") — the default preset
//! (preset-ap-client) carries tcp+udp but not vsock, so it does not pull
//! `wz/locator-vsock`; the acceptor never binds, there is no acceptor for zenohd to
//! dial, and the subscriber never fires. Only `--features
//! vsock` compiles the `BoundListener::Vsock` arm (which the facade closure
//! `locator-vsock = ["transport-link-vsock"]` pulls). The unique keyexpr the pico
//! z_pub uses pins THIS Put crossing the vsock link (a bare "SUBSCRIBER FIRED" on
//! nothing else could be a stale artifact).
//!
//! `#[ignore]` (binary-dep + host-capability e2e): needs a VSOCK-enabled `zenohd`
//! (the SEPARATE `target/zenohd-vsock/zenohd` source build — zenoh's default omits
//! `transport_vsock`), a `wz-ap-demo` built with `--features vsock`, the zenoh-pico
//! CLI (`z_pub`), AND — unlike the ws/tls/unixsock/udp acceptor legs — a
//! vsock-capable HOST: AF_VSOCK loopback (`VMADDR_CID_LOCAL`) needs the
//! `vsock_loopback` kernel module, ABSENT on the hosted CI runner (a bind returns
//! `EPERM`). So this is HOST-ONLY, exactly like `vsock_e2e`: it runs on a
//! vsock-capable host via the `--ignored` Layer Z lane, which SKIPs it when the vsock
//! oracle is absent (the hosted required job never provisions it). The `zenohd`
//! substring in the fn name keeps the default Layer E sweep's `--skip zenohd` from
//! running it against an arbitrary-feature binary.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, spawn_publishing_zpub, spawn_zenohd_vsock_dialer, wait_for_substring,
    wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
};

const SUB_FILTER: &str = "demo/vsock/**";
const PUBLISH_KEY: &str = "demo/vsock/acc";
const PUBLISH_VALUE: &str = "hello-vsock-acceptor-via-zenohd";

/// Parse the EPHEMERAL vsock port from the wz acceptor's
/// `wz accept: listening on <cid>:<port> (vsock)` line (the vsock analogue of the
/// IP-only [`wz_integration_tests::common::listen_port`], which greps `127.0.0.1:`).
/// wz binds `VMADDR_CID_LOCAL:VMADDR_PORT_ANY`, so the kernel assigns the port; zenohd
/// then dials `vsock/VMADDR_CID_LOCAL:<port>`. The `<cid>` half is discarded
/// (`rsplit(':')`) — only the assigned port matters for the dial. The port is a vsock
/// port, which is 32-bit (not a 16-bit TCP port — an ephemeral assignment is a large
/// u32, e.g. `955433689`), so this returns `Option<u32>`. Returns `None` if the
/// line/port is absent (the bound-failure path).
fn parse_vsock_listen_port(captured: &str) -> Option<u32> {
    let line = captured
        .lines()
        .find(|l| l.contains("(vsock)") && l.contains("listening on "))?;
    let after = line.split("listening on ").nth(1)?;
    let addr = after.split(" (vsock)").next()?; // "<cid>:<port>"
    addr.rsplit(':').next()?.trim().parse().ok()
}

/// pico `z_pub` -> zenohd (tcp) -> wz `--listen vsock/...` (vsock): a real zenohd
/// dials the wz AF_VSOCK acceptor, and a pico publisher's Put routes across that vsock
/// loopback link to the wz subscriber — the `transport-link-vsock` atom's first
/// cross-impl proof in the zenohd->wz (acceptor) direction, closing the last
/// accept-direction cross-impl gap.
// wz-proves: transport-link-vsock zenohd->wz
// wz-proves: session-unicast-open zenohd->wz
#[test]
#[ignore = "binary-dep + host-only e2e: needs vsock zenohd + wz-ap-demo[+vsock] + pico z_pub + AF_VSOCK loopback; runs via --ignored"]
fn wz_vsock_acceptor_receives_pico_put_via_zenohd() {
    let demo = wz_ap_demo_binary();
    let z_pub = zenoh_pico_cli_binary("z_pub");

    // wz is the vsock ACCEPTOR (`--listen vsock/VMADDR_CID_LOCAL:VMADDR_PORT_ANY`, an
    // EPHEMERAL kernel-assigned port on the loopback CID) + a routed subscriber on
    // SUB_FILTER.
    let wz_stderr = tempfile::tempfile().expect("tempfile for wz acceptor stderr");
    let wz_writer = wz_stderr.try_clone().expect("dup wz stderr handle");
    let mut wz_reader = wz_stderr;
    let mut wz = ChildGuard::wrap(
        "wz-ap-demo (--listen vsock --key)",
        Command::new(&demo)
            .arg("--listen")
            .arg("vsock/VMADDR_CID_LOCAL:VMADDR_PORT_ANY")
            .arg("--key")
            .arg(SUB_FILTER)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(wz_writer))
            .spawn()
            .expect("spawn wz-ap-demo --listen vsock --key"),
    );

    // The wz acceptor must be BOUND before zenohd dials. `bind_vsock` binds
    // SYNCHRONOUSLY before the "(vsock)" listen log, so the log — carrying the
    // ephemeral port — is the bound witness.
    let listening = wait_for_substring(&mut wz_reader, "(vsock)", Duration::from_secs(10));
    let port = listening
        .as_ref()
        .ok()
        .and_then(|c| parse_vsock_listen_port(c));

    // zenohd DIALS wz's vsock acceptor (`-e vsock/VMADDR_CID_LOCAL:<port>`) + listens
    // on tcp for pico. Spawned only after wz is bound (the port is known).
    // R311y412 — the tcp port is DISCOVERED from zenohd's own announcement (see
    // `spawn_zenohd_dialer_on_ephemeral_tcp`), so it exists only once the dialer is up.
    let (mut zenohd, tcp_port) =
        match port.map(|p| spawn_zenohd_vsock_dialer(&format!("vsock/VMADDR_CID_LOCAL:{p}"))) {
            Some((guard, tcp)) => (Some(guard), Some(tcp)),
            None => (None, None),
        };
    let tcp_endpoint = format!("tcp/127.0.0.1:{}", tcp_port.unwrap_or_default());

    // wz accepts the zenohd vsock dial + completes the handshake, then (on Established)
    // declares its routed subscriber onto the accepted session, installing the route
    // on zenohd.
    let established = zenohd.as_ref().map(|_| {
        wait_for_substring(
            &mut wz_reader,
            "session Established",
            Duration::from_secs(10),
        )
    });
    let declared = matches!(&established, Some(Ok(_))).then(|| {
        wait_for_substring(
            &mut wz_reader,
            "DECLARED ROUTED SUBSCRIBER",
            Duration::from_secs(10),
        )
    });

    // pico z_pub over TCP — after wz's routed subscriber declaration reached zenohd
    // (route installed); the 30x burst covers residual propagation lag (no-flaky).
    let z_pub_child = matches!(&declared, Some(Ok(_))).then(|| {
        spawn_publishing_zpub(
            &z_pub,
            PUBLISH_KEY,
            PUBLISH_VALUE,
            &tcp_endpoint,
            "zenohd-vsock",
            || tempfile::tempfile().expect("tempfile for z_pub stdout"),
        )
    });

    let fired = wait_for_substring(&mut wz_reader, "SUBSCRIBER FIRED", Duration::from_secs(15));

    if let Some(mut c) = z_pub_child {
        let _ = c.child_mut().kill();
        let _ = c.child_mut().wait();
    }
    if let Some(z) = zenohd.as_mut() {
        let _ = z.child_mut().kill();
        let _ = z.child_mut().wait();
    }
    let _ = wz.child_mut().kill();
    let _ = wz.child_mut().wait();

    let wz_captured = read_captured(&mut wz_reader);
    eprintln!("--- wz vsock acceptor stderr ---\n{wz_captured}");

    assert!(
        port.is_some(),
        "wz-ap-demo did not bind the vsock acceptor (its '(vsock)' listen line with a \
         parseable ephemeral port) within 10s — is `vsock_loopback` loaded and the demo \
         built with `--features vsock`?\n--- wz stderr ---\n{wz_captured}"
    );
    // Positive transport + accept witnesses (family parity with the udp/ws/tls acceptor
    // legs, which assert the transport tag explicitly): the demo logged the `(vsock)`
    // listen line AND accepted a foreign anonymous vsock peer — the definitive
    // zenohd->wz vsock ACCEPT witness (wz is listen-only, so an accepted peer is a real
    // inbound vsock session, never a wz dial).
    assert!(
        wz_captured.contains("(vsock)"),
        "wz never logged a '(vsock)' listen line — the acceptor did not bind vsock.\n\
         --- wz stderr ---\n{wz_captured}"
    );
    assert!(
        wz_captured.contains("accepted peer <anonymous vsock peer>"),
        "wz never logged accepting an anonymous vsock peer — zenohd's vsock dial was not \
         accepted as an inbound vsock session.\n--- wz stderr ---\n{wz_captured}"
    );
    established
        .expect("zenohd dialer was spawned once wz was bound")
        .unwrap_or_else(|c| {
            panic!(
                "wz acceptor never logged 'session Established' within 10s — zenohd's vsock \
                 dial did not complete the handshake with wz's acceptor.\n--- wz stderr ---\n{c}"
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
             zenohd and across the vsock link into wz's acceptor's subscriber.\n\
             --- wz stderr ---\n{c}"
        )
    });

    // The fired sample must carry the agreed keyexpr — a UNIQUE keyexpr only this pico
    // z_pub publishes, so the fire pins THIS Put crossing the vsock link. The exact
    // payload LENGTH is NOT asserted: `spawn_publishing_zpub` uses the zenoh-pico
    // `z_pub` example, which prefixes each sample with a `[ idx] ` counter, so the wire
    // payload is longer than PUBLISH_VALUE — the keyexpr uniqueness is the
    // discriminator (as in the sibling `wz_unixsock_acceptor_zenohd_interop`).
    assert!(
        fired_text.contains(PUBLISH_KEY),
        "the wz subscriber fired, but not on the routed keyexpr '{PUBLISH_KEY}'.\n{fired_text}"
    );
}
