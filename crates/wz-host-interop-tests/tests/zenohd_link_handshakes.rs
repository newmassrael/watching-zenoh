// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Two rows per link: the wz demo dials a stock `zenohd` over a link the host serves
//! and reaches Established (`wz_client_reaches_established_..._over_<link>`), and a wz
//! publisher on that link has its value delivered to a wz subscriber behind the same
//! router (`wz_publisher_reaches_a_subscriber_..._over_<link>`).
//!
//! What a host owes the router interop is not the whole corpus but the part of it
//! whose subject depends on the host, and the host-dependent surface of a transport
//! is its links. So the handshake rows here are the pure link handshakes of the
//! corpus's router file
//! (`wz_client_reaches_established_against_zenohd_over_{ws,udp,tls,quic,unixsock}`),
//! one assertion each, and the body is one function with the link as data, because
//! the corpus tests differ only in the router's listener, the locator the demo dials
//! and, for the two certificate links, the CA flag. The TCP handshake row is
//! `zenohd_handshake.rs`, which discovers its port instead of reserving a pair.
//!
//! The data rows exist because a handshake shows two parties agreeing on a session and
//! says nothing about what a session is for: a link's framing, batching and keep-alive
//! can break after Established, and a host's socket behaviour is what would break them.
//! The subscriber is always on the router's TCP listener, so the only thing that crosses
//! the link under test is the publisher's traffic; the TCP data row is therefore the
//! baseline the others are read against, and it lives here (`..._over_tcp`).
//!
//! The tests stay separate functions and not one loop over the table. Promotion from
//! observation to gate is per test and per host, after two consecutive green hosted
//! runs, and a loop would hide which link a red belongs to.
//!
//! A Unix socket is served on macOS and not on Windows, so its rows and tests are
//! `cfg(unix)`. Not here, with the reason: `unixpipe` and `vsock` need a router built
//! with a transport feature the default build omits.
//!
//! Opt-in (`#[ignore]`) and binary-dependent: the router is named with `WZ_ZENOHD_BIN`
//! and the demo is the one `cargo build -p wz-ap-demo` produced with the link features
//! (`ws,tls,quic,udp-reliable,quic-datagram,routing-peer`, and `unixsock` on a host that
//! serves it). `routing-peer` is the data rows' subscriber.

use std::fs::File;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

#[cfg(unix)]
use wz_integration_tests::common::spawn_zenohd_tcp_unixsock;
use wz_integration_tests::common::{
    read_captured, spawn_zenohd_dialer_on_ephemeral_tcp, spawn_zenohd_listeners,
    spawn_zenohd_tcp_quic, spawn_zenohd_tcp_tls, spawn_zenohd_tcp_udp, spawn_zenohd_tcp_ws,
    wait_for_substring, wait_for_zenohd_handshake_ready, wz_ap_demo_binary, zenohd_binary,
    ChildGuard, PortReservation,
};
use wz_runtime_tokio_test_support::localhost_cert_key_pem;

/// What a row needs to start a router and to dial it: the TCP port is the router's
/// readiness gate, the link port is the one under test, and the two certificate links
/// read the PEM pair the caller wrote.
struct Ctx {
    tcp_port: u16,
    link_port: u16,
    cert: String,
    key: String,
}

struct Link {
    /// The transport name the demo logs once it has dialed, which is what the test
    /// reads to know the link it asked for is the one it got.
    transport: &'static str,
    /// The demo's flag naming the CA to trust, for the links that carry a
    /// certificate. `None` for a link with no certificate.
    ca_flag: Option<&'static str>,
    /// Start a stock router listening on this link, and say which TCP port it also
    /// serves a plain client on. Every row's router serves TCP besides its link, and
    /// the data-plane test puts its subscriber there so that what crosses the link
    /// under test is the publisher's alone; for most rows the port is the one the
    /// caller reserved, and for one it is discovered from the router.
    spawn: fn(&Ctx) -> (ChildGuard, u16),
    /// The locator the demo is told to dial.
    connect: fn(&Ctx) -> String,
}

fn probe_stderr() -> File {
    tempfile::tempfile().expect("tempfile for readiness probe stderr")
}

fn router_over_ws(c: &Ctx) -> (ChildGuard, u16) {
    (
        spawn_zenohd_tcp_ws(c.tcp_port, c.link_port, probe_stderr),
        c.tcp_port,
    )
}

fn router_over_udp(c: &Ctx) -> (ChildGuard, u16) {
    (
        spawn_zenohd_tcp_udp(c.tcp_port, c.link_port, probe_stderr),
        c.tcp_port,
    )
}

fn router_over_tls(c: &Ctx) -> (ChildGuard, u16) {
    (
        spawn_zenohd_tcp_tls(c.tcp_port, c.link_port, &c.cert, &c.key, probe_stderr),
        c.tcp_port,
    )
}

fn router_over_quic(c: &Ctx) -> (ChildGuard, u16) {
    (
        spawn_zenohd_tcp_quic(c.tcp_port, c.link_port, &c.cert, &c.key, probe_stderr),
        c.tcp_port,
    )
}

/// Upstream's udp link has a reliable variant selected by `?rel=1` on the same
/// scheme, so the router listens on `udp/...?rel=1` and the demo dials it, and wz names
/// the variant `udp-reliable`.
fn router_over_udp_reliable(c: &Ctx) -> (ChildGuard, u16) {
    (
        spawn_zenohd_listeners(
            &[
                format!("tcp/127.0.0.1:{}", c.tcp_port),
                format!("udp/127.0.0.1:{}?rel=1", c.link_port),
            ],
            c.tcp_port,
            &format!("127.0.0.1:{}", c.tcp_port),
            probe_stderr,
        ),
        c.tcp_port,
    )
}

/// Upstream's quic link has a datagram variant selected by `?rel=0` on the same
/// scheme, and the listener reads its certificate from the same `transport.link.tls`
/// block as the reliable one. wz spells the variant as its own scheme, `quic-datagram/`.
/// The router's TCP listener is discovered, and the datagram listener is an extra one
/// on the reserved link port.
fn router_over_quic_datagram(c: &Ctx) -> (ChildGuard, u16) {
    let cfg_path = format!("{}.zenohd.json5", c.cert);
    let cfg = format!(
        "{{ transport: {{ link: {{ tls: {{ listen_private_key: {:?}, \
         listen_certificate: {:?} }} }} }} }}",
        c.key, c.cert
    );
    std::fs::write(&cfg_path, cfg).expect("write zenohd quic-datagram config");
    let (guard, tcp_port) = spawn_zenohd_dialer_on_ephemeral_tcp(
        &zenohd_binary(),
        "zenohd (reference router, quic-datagram)",
        None,
        &[format!("quic/127.0.0.1:{}?rel=0", c.link_port)],
        Some(&cfg_path),
    );
    wait_for_zenohd_handshake_ready(&format!("127.0.0.1:{tcp_port}"), probe_stderr);
    (guard, tcp_port)
}

/// A router on plain TCP and nothing else, the row whose subscriber and publisher
/// share a link: the data plane's baseline, against which a failure on another link is
/// a failure of that link.
fn router_over_tcp(c: &Ctx) -> (ChildGuard, u16) {
    (
        spawn_zenohd_listeners(
            &[format!("tcp/127.0.0.1:{}", c.tcp_port)],
            c.tcp_port,
            &format!("127.0.0.1:{}", c.tcp_port),
            probe_stderr,
        ),
        c.tcp_port,
    )
}

fn dial_tcp(c: &Ctx) -> String {
    format!("tcp/127.0.0.1:{}", c.tcp_port)
}

fn dial_ws(c: &Ctx) -> String {
    format!("ws/127.0.0.1:{}", c.link_port)
}

fn dial_udp(c: &Ctx) -> String {
    format!("udp/127.0.0.1:{}", c.link_port)
}

fn dial_tls(c: &Ctx) -> String {
    format!("tls/127.0.0.1:{}", c.link_port)
}

fn dial_quic(c: &Ctx) -> String {
    format!("quic/127.0.0.1:{}", c.link_port)
}

fn dial_udp_reliable(c: &Ctx) -> String {
    format!("udp/127.0.0.1:{}?rel=1", c.link_port)
}

fn dial_quic_datagram(c: &Ctx) -> String {
    format!("quic-datagram/127.0.0.1:{}", c.link_port)
}

/// The socket a Unix-socket row listens on, keyed on the reserved TCP port so
/// concurrent tests cannot collide. Short on purpose: `sun_path` holds about a hundred
/// bytes on macOS, and its temp directory is already fifty of them.
#[cfg(unix)]
fn unixsock_path(tcp_port: u16) -> PathBuf {
    std::env::temp_dir().join(format!("wzhi-us-{tcp_port}.sock"))
}

#[cfg(unix)]
fn router_over_unixsock(c: &Ctx) -> (ChildGuard, u16) {
    let sock = unixsock_path(c.tcp_port);
    (
        spawn_zenohd_tcp_unixsock(c.tcp_port, &sock.to_string_lossy(), probe_stderr),
        c.tcp_port,
    )
}

/// The locator has a double slash after the scheme when the path is absolute, the
/// shape zenoh's unixsock link expects.
#[cfg(unix)]
fn dial_unixsock(c: &Ctx) -> String {
    format!("unixsock-stream/{}", unixsock_path(c.tcp_port).display())
}

/// The Unix socket a test may leave, and its lock. A host without Unix sockets has
/// none, so the list is empty there and the call site has no `cfg`.
#[cfg(unix)]
fn socket_leftovers(tcp_port: u16) -> Vec<PathBuf> {
    let sock = unixsock_path(tcp_port);
    vec![PathBuf::from(format!("{}.lock", sock.display())), sock]
}

#[cfg(not(unix))]
fn socket_leftovers(_tcp_port: u16) -> Vec<PathBuf> {
    Vec::new()
}

const TCP: Link = Link {
    transport: "tcp",
    ca_flag: None,
    spawn: router_over_tcp,
    connect: dial_tcp,
};
const WS: Link = Link {
    transport: "ws",
    ca_flag: None,
    spawn: router_over_ws,
    connect: dial_ws,
};
const UDP: Link = Link {
    transport: "udp",
    ca_flag: None,
    spawn: router_over_udp,
    connect: dial_udp,
};
const TLS: Link = Link {
    transport: "tls",
    ca_flag: Some("--tls-ca"),
    spawn: router_over_tls,
    connect: dial_tls,
};
const QUIC: Link = Link {
    transport: "quic",
    ca_flag: Some("--quic-ca"),
    spawn: router_over_quic,
    connect: dial_quic,
};
const UDP_RELIABLE: Link = Link {
    transport: "udp-reliable",
    ca_flag: None,
    spawn: router_over_udp_reliable,
    connect: dial_udp_reliable,
};
const QUIC_DATAGRAM: Link = Link {
    transport: "quic-datagram",
    ca_flag: Some("--quic-ca"),
    spawn: router_over_quic_datagram,
    connect: dial_quic_datagram,
};
#[cfg(unix)]
const UNIXSOCK: Link = Link {
    transport: "unixsock",
    ca_flag: None,
    spawn: router_over_unixsock,
    connect: dial_unixsock,
};

/// What a test leaves on disk, removed when it ends however it ends: the certificate
/// and key of a certificate link, the router config written beside the certificate,
/// the Unix socket and its lock. The corpus removes them on the straight path only.
struct TestFiles(Vec<PathBuf>);

impl Drop for TestFiles {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// A stock router listening on one link and on TCP, and what the test that started it
/// has to keep alive: the files it wrote, which are removed when the rig is dropped.
struct Rig {
    zenohd: ChildGuard,
    ctx: Ctx,
    /// The TCP port a plain client reaches the router on (see [`Link::spawn`]).
    tcp_port: u16,
    _files: TestFiles,
}

/// Start the router a row needs: reserve its ports, write the certificate pair a
/// certificate link reads, and bring the router up on the link and on TCP.
fn bring_up(link: &Link) -> Rig {
    let (tcp_res, link_port) = PortReservation::pick_pair();
    let tcp_port = tcp_res.port();

    // Named for every link and written only by the two that carry a certificate; the
    // guard removes whatever exists, which for a link with no files is nothing.
    let dir = std::env::temp_dir();
    let transport = link.transport;
    let cert_path = dir.join(format!("wz-host-interop-{transport}-{tcp_port}.cert.pem"));
    let key_path = dir.join(format!("wz-host-interop-{transport}-{tcp_port}.key.pem"));
    let mut leftovers = vec![
        cert_path.clone(),
        key_path.clone(),
        PathBuf::from(format!("{}.zenohd.json5", cert_path.display())),
    ];
    leftovers.extend(socket_leftovers(tcp_port));
    let files = TestFiles(leftovers);
    if link.ca_flag.is_some() {
        let (cert_pem, key_pem) = localhost_cert_key_pem();
        std::fs::write(&cert_path, cert_pem).expect("write cert pem");
        std::fs::write(&key_path, key_pem).expect("write key pem");
    }
    let ctx = Ctx {
        tcp_port,
        link_port,
        cert: cert_path.to_string_lossy().into_owned(),
        key: key_path.to_string_lossy().into_owned(),
    };

    let (zenohd, router_tcp_port) = (link.spawn)(&ctx);
    drop(tcp_res);
    Rig {
        zenohd,
        ctx,
        tcp_port: router_tcp_port,
        _files: files,
    }
}

/// A capture file and a duplicate handle to write it through, as a spawned child gets.
fn capture(what: &str) -> (File, File) {
    let reader = tempfile::tempfile().unwrap_or_else(|e| panic!("tempfile for {what}: {e}"));
    let writer = reader
        .try_clone()
        .unwrap_or_else(|e| panic!("dup {what} handle: {e}"));
    (reader, writer)
}

fn handshake_over(link: &Link) {
    let demo = wz_ap_demo_binary();
    let transport = link.transport;
    let Rig {
        mut zenohd,
        ctx,
        _files,
        ..
    } = bring_up(link);

    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr
        .try_clone()
        .expect("dup wz-ap-demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut command = Command::new(&demo);
    command.arg("--connect").arg((link.connect)(&ctx));
    if let Some(flag) = link.ca_flag {
        command.arg(flag).arg(&ctx.cert);
    }
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect <link>/zenohd --publish)",
        command
            .arg("--publish")
            .arg("demo/zenohd")
            .arg("--value")
            .arg(format!("{transport}-handshake-probe"))
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect <link>/zenohd"),
    );

    let established = wait_for_substring(
        &mut demo_stderr_reader,
        "session Established",
        Duration::from_secs(10),
    );

    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    let demo_captured = read_captured(&mut demo_stderr_reader);
    if let Err(c) = &established {
        panic!(
            "wz-ap-demo did not log 'session Established' within 10s over {transport}: the \
             wz<->zenohd handshake did not interoperate on this host.\n\
             --- captured wz-ap-demo stderr ---\n{c}"
        );
    }
    // Witness the link. The router's listener for this link is on a port or a path of
    // its own and the TCP port is a separate one, so a TCP dial could not reach
    // Established here; but that is an inference, and the demo logs the transport it
    // dialed.
    let witness = format!("over {transport} transport");
    assert!(
        demo_captured.contains(&witness),
        "reached Established but the demo did not log '{witness}'.\n\
         --- captured wz-ap-demo stderr ---\n{demo_captured}"
    );
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
}

/// The key the data-plane rows publish and subscribe on.
const DATA_KEY: &str = "demo/host-interop-data";

/// A published value crosses a stock router: a wz PUBLISHER dials the router over the
/// link under test, a wz SUBSCRIBER on the router's plain TCP listener is handed it.
///
/// A handshake shows two parties agreeing on a session; this shows the link carrying
/// what a session is for, through a router that is not wz, which is the part of the
/// interop a link's framing, batching and keep-alive can break after Established.
///
/// The subscriber is a wz PEER (the demo's client mode only publishes) and sits on TCP
/// so that the only thing that crosses the link under test is the publisher's traffic;
/// if it were on the same link a failure could not be told from the subscriber's. It
/// declares first, and the publisher is started only after the subscriber has logged
/// the declaration, because the router forwards a publication to the subscribers it
/// knows when the message arrives and the demo's publisher emits one short burst.
fn data_over(link: &Link) {
    let demo = wz_ap_demo_binary();
    let transport = link.transport;
    let Rig {
        mut zenohd,
        ctx,
        tcp_port,
        _files,
    } = bring_up(link);

    let (mut sub_reader, sub_writer) = capture("wz-ap-demo subscriber stderr");
    let mut subscriber = ChildGuard::wrap(
        "wz-ap-demo (--peer --connect tcp/zenohd --subscribe)",
        Command::new(&demo)
            .arg("--peer")
            .arg("127.0.0.1:0")
            .arg("--connect")
            .arg(format!("127.0.0.1:{tcp_port}"))
            .arg("--subscribe")
            .arg(DATA_KEY)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(sub_writer))
            .spawn()
            .expect("spawn wz-ap-demo --peer --subscribe"),
    );
    let declared = wait_for_substring(
        &mut sub_reader,
        "declared subscriber",
        Duration::from_secs(10),
    );

    let (mut pub_reader, pub_writer) = capture("wz-ap-demo publisher stderr");
    let mut command = Command::new(&demo);
    command.arg("--connect").arg((link.connect)(&ctx));
    if let Some(flag) = link.ca_flag {
        command.arg(flag).arg(&ctx.cert);
    }
    let mut publisher = ChildGuard::wrap(
        "wz-ap-demo (--connect <link>/zenohd --publish)",
        command
            .arg("--publish")
            .arg(DATA_KEY)
            .arg("--value")
            .arg(format!("{transport}-data-probe"))
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(pub_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect <link>/zenohd --publish"),
    );
    let delivered = if declared.is_ok() {
        Some(wait_for_substring(
            &mut sub_reader,
            "received mesh data",
            Duration::from_secs(10),
        ))
    } else {
        None
    };

    for child in [&mut publisher, &mut subscriber, &mut zenohd] {
        let _ = child.child_mut().kill();
        let _ = child.child_mut().wait();
    }
    let sub_captured = read_captured(&mut sub_reader);
    let pub_captured = read_captured(&mut pub_reader);

    if declared.is_err() {
        panic!(
            "the subscriber never logged 'declared subscriber' on TCP within 10s, so nothing \
             here could be delivered over {transport}.\n--- captured subscriber stderr ---\n{sub_captured}"
        );
    }
    // Witness the link, as the handshake does: the publisher logs the transport it dialed.
    let witness = format!("over {transport} transport");
    assert!(
        pub_captured.contains(&witness),
        "the publisher did not log '{witness}', so the delivery below would not have crossed \
         the link under test.\n--- captured publisher stderr ---\n{pub_captured}"
    );
    if let Some(Err(c)) = &delivered {
        panic!(
            "the subscriber on TCP was handed nothing within 10s of a publisher over {transport}: \
             the link established and did not carry the value through a stock router.\n\
             --- captured publisher stderr ---\n{pub_captured}\n\
             --- captured subscriber stderr ---\n{c}"
        );
    }
    eprintln!("--- captured publisher stderr ---\n{pub_captured}");
    eprintln!("--- captured subscriber stderr ---\n{sub_captured}");
}

#[test]
#[ignore = "binary-dep e2e (zenohd router, ws); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_client_reaches_established_against_a_stock_zenohd_over_ws_on_this_host() {
    handshake_over(&WS);
}

#[test]
#[ignore = "binary-dep e2e (zenohd router, udp); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_client_reaches_established_against_a_stock_zenohd_over_udp_on_this_host() {
    handshake_over(&UDP);
}

#[test]
#[ignore = "binary-dep e2e (zenohd router, tls); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_client_reaches_established_against_a_stock_zenohd_over_tls_on_this_host() {
    handshake_over(&TLS);
}

#[test]
#[ignore = "binary-dep e2e (zenohd router, quic); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_client_reaches_established_against_a_stock_zenohd_over_quic_on_this_host() {
    handshake_over(&QUIC);
}

#[test]
#[ignore = "binary-dep e2e (zenohd router, udp-reliable); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_client_reaches_established_against_a_stock_zenohd_over_udp_reliable_on_this_host() {
    handshake_over(&UDP_RELIABLE);
}

#[test]
#[ignore = "binary-dep e2e (zenohd router, quic-datagram); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_client_reaches_established_against_a_stock_zenohd_over_quic_datagram_on_this_host() {
    handshake_over(&QUIC_DATAGRAM);
}

#[cfg(unix)]
#[test]
#[ignore = "binary-dep e2e (zenohd router, unixsock); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_client_reaches_established_against_a_stock_zenohd_over_unixsock_on_this_host() {
    handshake_over(&UNIXSOCK);
}

// The data-plane rows: the same links, one test each, for the reason the handshake
// rows are separate functions. TCP is a row here because the baseline of a data
// plane is the link every other row's subscriber uses.

#[test]
#[ignore = "binary-dep e2e (zenohd router, tcp); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_publisher_reaches_a_subscriber_through_a_stock_zenohd_over_tcp_on_this_host() {
    data_over(&TCP);
}

#[test]
#[ignore = "binary-dep e2e (zenohd router, ws); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_publisher_reaches_a_subscriber_through_a_stock_zenohd_over_ws_on_this_host() {
    data_over(&WS);
}

#[test]
#[ignore = "binary-dep e2e (zenohd router, udp); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_publisher_reaches_a_subscriber_through_a_stock_zenohd_over_udp_on_this_host() {
    data_over(&UDP);
}

#[test]
#[ignore = "binary-dep e2e (zenohd router, tls); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_publisher_reaches_a_subscriber_through_a_stock_zenohd_over_tls_on_this_host() {
    data_over(&TLS);
}

#[test]
#[ignore = "binary-dep e2e (zenohd router, quic); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_publisher_reaches_a_subscriber_through_a_stock_zenohd_over_quic_on_this_host() {
    data_over(&QUIC);
}

#[test]
#[ignore = "binary-dep e2e (zenohd router, udp-reliable); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_publisher_reaches_a_subscriber_through_a_stock_zenohd_over_udp_reliable_on_this_host() {
    data_over(&UDP_RELIABLE);
}

#[test]
#[ignore = "binary-dep e2e (zenohd router, quic-datagram); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_publisher_reaches_a_subscriber_through_a_stock_zenohd_over_quic_datagram_on_this_host() {
    data_over(&QUIC_DATAGRAM);
}

#[cfg(unix)]
#[test]
#[ignore = "binary-dep e2e (zenohd router, unixsock); set WZ_ZENOHD_BIN, run via the Platform interop job / --ignored"]
fn wz_publisher_reaches_a_subscriber_through_a_stock_zenohd_over_unixsock_on_this_host() {
    data_over(&UNIXSOCK);
}
