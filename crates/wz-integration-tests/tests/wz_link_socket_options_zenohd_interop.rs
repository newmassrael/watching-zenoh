// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2590 — the `bind` and `dscp` link keys, adjudicated by zenohd ON THE WIRE.
//!
//! Both keys change nothing a zenoh session can see. `bind` picks the local
//! address a dialing socket leaves from, and `dscp` the value in the IP TOS
//! byte of what it sends. So neither is witnessed by a session reaching
//! Established; a session over a wrongly bound or unmarked socket establishes
//! just the same. What each key controls is a HEADER field, and the observer
//! here reads exactly that, from a socket this test owns:
//!
//! - a TCP listener with `IP_RECVTOS`, whose accepted stream reports the peer's
//!   address and, through `IP_PKTOPTIONS`, the TOS of the segment that opened it
//!   (a dialer's `dscp` is set before it connects, so that segment carries it);
//! - a UDP socket with `IP_RECVTOS`, whose `recvmsg` reports both per datagram.
//!
//! The observer is plain libc (`common::next_datagram_tos_and_source_v4`,
//! `common::opening_segment_tos_v4`), shares no code with wz's socket layer, and
//! does not answer the zenoh handshake. Each implementation is started as a
//! DIALER at it: zenohd with `-e <locator>`, the wz demo with `--connect
//! <locator>`. The first thing either sends is what gets read.
//!
//! # The table, and what the adjudicator is for
//!
//! Every row runs zenohd first and asserts zenohd's observation equals the
//! value written in the row. Those values were measured against zenohd before
//! this file was written. The row then asserts wz's observation equals zenohd's.
//! A row whose zenohd half fails is a substrate that cannot show the key, and
//! its wz half would prove nothing, which is why the adjudicator goes first.
//!
//! Each key has a row without it next to a row with it, so an implementation
//! that ignores the key cannot match the row that has it.
//!
//! # Two rows record upstream behaviour, not the key's effect
//!
//! - `iface` together with `bind` is refused by upstream's unicast dials
//!   (`io/zenoh-links/zenoh-link-tcp/src/unicast.rs` @ `if let (Some(_), Some(_)) = (config.get(BIND_INTERFACE), config.get(BIND_SOCKET)) {`). The observer
//!   sees NOTHING within the budget from either implementation. A "nothing
//!   arrived" row alone could pass for a dead dialer, so each is paired with the
//!   `bind`-only row on the same scheme, which must arrive.
//! - `dscp` on QUIC does not reach the wire in EITHER implementation: both put
//!   `0x02` in the TOS byte with the key and without it. quinn writes the ECN
//!   codepoint per packet as a control message, and that replaces the socket's
//!   TOS. The row pins the observable, so a wz that diverged from zenohd there
//!   would still red, but it is not evidence that the key has an effect.

use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, next_datagram_tos_and_source_v4, opening_segment_tos_v4,
    read_captured, tos_recording_listener_v4, wz_ap_demo_binary, zenohd_binary, ChildGuard,
};
use wz_runtime_tokio_test_support::localhost_cert_key_pem;

/// Long enough for a dialer to start and send its first packet; the rows that
/// expect NOTHING spend all of it.
const BUDGET: Duration = Duration::from_secs(4);
/// The local address the `bind` rows name. Linux routes all of `127.0.0.0/8`
/// to `lo`, so it is bindable with no setup, and it differs from the
/// `127.0.0.1` a dial leaves from without the key.
const BIND_ADDR: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 7);
const DSCP: u8 = 0x28;

/// What the observer saw of the first thing a dialer sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    /// A packet from `source` whose IP TOS byte was `tos`.
    Packet { source: IpAddr, tos: u8 },
    /// Nothing arrived within [`BUDGET`].
    Nothing,
}

#[derive(Debug, Clone, Copy)]
enum Observer {
    Stream,
    Datagram,
}

#[derive(Debug, Clone, Copy)]
enum Dialer {
    Zenohd,
    Wz,
}

struct Row {
    /// The locator, with `{port}` standing for the observer's port.
    locator: &'static str,
    observer: Observer,
    /// What zenohd was measured to put on the wire.
    zenohd: Seen,
}

fn packet(source: Ipv4Addr, tos: u8) -> Seen {
    Seen::Packet {
        source: IpAddr::V4(source),
        tos,
    }
}

fn rows() -> Vec<Row> {
    use Observer::{Datagram, Stream};
    let lo = Ipv4Addr::LOCALHOST;
    vec![
        Row {
            locator: "tcp/127.0.0.1:{port}",
            observer: Stream,
            zenohd: packet(lo, 0),
        },
        Row {
            locator: "tcp/127.0.0.1:{port}#bind=127.0.0.7:0",
            observer: Stream,
            zenohd: packet(BIND_ADDR, 0),
        },
        Row {
            locator: "tcp/127.0.0.1:{port}#dscp=0x28",
            observer: Stream,
            zenohd: packet(lo, DSCP),
        },
        Row {
            locator: "tcp/127.0.0.1:{port}#iface=lo;bind=127.0.0.7:0",
            observer: Stream,
            zenohd: Seen::Nothing,
        },
        Row {
            locator: "tls/127.0.0.1:{port}#bind=127.0.0.7:0;dscp=0x28",
            observer: Stream,
            zenohd: packet(BIND_ADDR, DSCP),
        },
        Row {
            locator: "udp/127.0.0.1:{port}",
            observer: Datagram,
            zenohd: packet(lo, 0),
        },
        Row {
            locator: "udp/127.0.0.1:{port}#bind=127.0.0.7:0",
            observer: Datagram,
            zenohd: packet(BIND_ADDR, 0),
        },
        Row {
            locator: "udp/127.0.0.1:{port}#dscp=0x28",
            observer: Datagram,
            zenohd: packet(lo, DSCP),
        },
        Row {
            locator: "udp/127.0.0.1:{port}#iface=lo;bind=127.0.0.7:0",
            observer: Datagram,
            zenohd: Seen::Nothing,
        },
        Row {
            locator: "quic/127.0.0.1:{port}#bind=127.0.0.7:0",
            observer: Datagram,
            zenohd: packet(BIND_ADDR, 0x02),
        },
        Row {
            locator: "quic/127.0.0.1:{port}#dscp=0x28",
            observer: Datagram,
            zenohd: packet(lo, 0x02),
        },
        Row {
            locator: "quic/127.0.0.1:{port}#iface=lo;bind=127.0.0.7:0",
            observer: Datagram,
            zenohd: Seen::Nothing,
        },
    ]
}

/// The dialer's command. The wz demo needs a root CA to dial `tls/` and
/// `quic/` at all, so it gets one; the handshake never completes against this
/// observer, so the certificate is never checked against anything.
fn dialer_command(dialer: Dialer, locator: &str, ca: &Path) -> Command {
    match dialer {
        Dialer::Zenohd => {
            let mut cmd = Command::new(zenohd_binary());
            cmd.args([
                "--no-multicast-scouting",
                "-l",
                "tcp/127.0.0.1:0",
                "-e",
                locator,
            ]);
            cmd
        }
        Dialer::Wz => {
            let mut cmd = Command::new(wz_ap_demo_binary());
            cmd.args(["--connect", locator, "--key", "wz/link-socket"]);
            if locator.starts_with("tls/") {
                cmd.arg("--tls-ca").arg(ca);
            } else if locator.starts_with("quic/") {
                cmd.arg("--quic-ca").arg(ca);
            }
            cmd
        }
    }
}

/// Accept one connection on `listener`, or `None` if none arrives within
/// `budget`.
fn accept_within(
    listener: &std::net::TcpListener,
    budget: Duration,
) -> Option<(std::net::TcpStream, std::net::SocketAddr)> {
    listener
        .set_nonblocking(true)
        .expect("a non-blocking accept");
    let deadline = Instant::now() + budget;
    loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                stream.set_nonblocking(false).expect("a blocking stream");
                return Some((stream, peer));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("accept: {e}"),
        }
    }
}

/// Run one dialer against a fresh observer and return what it saw, together
/// with the dialer's own output for the failure message.
fn observe(dialer: Dialer, row: &Row, ca: &Path) -> (Seen, String) {
    let capture = tempfile::tempfile().expect("tempfile for the dialer's output");
    let mut log = capture.try_clone().expect("dup the capture handle");
    let spawn = |locator: String| {
        ChildGuard::wrap(
            format!("{dialer:?} dialing {locator}"),
            dialer_command(dialer, &locator, ca)
                .stdout(Stdio::from(capture.try_clone().expect("dup stdout")))
                .stderr(Stdio::from(capture.try_clone().expect("dup stderr")))
                .spawn()
                .unwrap_or_else(|e| panic!("spawn {dialer:?}: {e}")),
        )
    };
    let seen = match row.observer {
        Observer::Stream => {
            let listener = tos_recording_listener_v4();
            let port = listener.local_addr().expect("listener address").port();
            let child = spawn(row.locator.replace("{port}", &port.to_string()));
            // A dialer that refuses its locator never connects, and that is a
            // row's expected answer, so the accept is bounded rather than awaited.
            let seen = match accept_within(&listener, BUDGET) {
                None => Seen::Nothing,
                Some((mut stream, peer)) => {
                    stream
                        .set_read_timeout(Some(BUDGET))
                        .expect("a read timeout");
                    let mut first = [0u8; 4096];
                    let n = stream.read(&mut first).expect("read what the dialer sent");
                    assert!(n > 0, "the dialer connected and sent nothing");
                    Seen::Packet {
                        source: peer.ip(),
                        tos: opening_segment_tos_v4(&stream)
                            .expect("a received segment latched no IP_TOS"),
                    }
                }
            };
            drop(child);
            seen
        }
        Observer::Datagram => {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind the observer");
            let port = socket.local_addr().expect("observer address").port();
            let child = spawn(row.locator.replace("{port}", &port.to_string()));
            let seen = match next_datagram_tos_and_source_v4(&socket, BUDGET) {
                None => Seen::Nothing,
                Some((tos, source)) => Seen::Packet {
                    source: source.ip(),
                    tos,
                },
            };
            drop(child);
            seen
        }
    };
    (seen, read_captured(&mut log))
}

/// The CA file the wz demo is given for `tls/` and `quic/` rows.
fn write_ca() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("a directory for the CA file");
    let path = dir.path().join("ca.pem");
    let (cert_pem, _key_pem) = localhost_cert_key_pem();
    std::fs::write(&path, cert_pem).expect("write the CA file");
    (dir, path)
}

// The observer's own calibration: a plain std socket marked with a TOS it
// chose must read back as that TOS from both readers, and two different values
// must read back different, so a reader that reports a constant cannot pass the
// witness below.
// wz-proves: none -- calibrates the two libc TOS readers the witness uses; it
// spawns no implementation and witnesses no atom.
#[test]
fn the_tos_readers_report_what_a_plain_socket_set() {
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    let set_tos = |fd: i32, tos: i32| {
        // SAFETY: a plain setsockopt on a live descriptor with a live i32.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_TOS,
                (&tos as *const i32).cast(),
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        assert_eq!(
            rc,
            0,
            "setsockopt(IP_TOS): {}",
            std::io::Error::last_os_error()
        );
    };
    for tos in [0x10u8, 0x48] {
        let rx = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind a receiver");
        let tx = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 9), 0)).expect("bind a sender");
        set_tos(tx.as_raw_fd(), i32::from(tos));
        tx.send_to(b"calibration", rx.local_addr().unwrap())
            .expect("send");
        assert_eq!(
            next_datagram_tos_and_source_v4(&rx, Duration::from_secs(2)),
            Some((tos, tx.local_addr().unwrap())),
            "the datagram reader must report the TOS and source the sender used"
        );

        // The stream reader reports the TOS of the segment that OPENED the
        // stream, so the sender's TOS reads back when it was set before connect
        // and does not when it was set after. Both halves are asserted: the
        // second is what shows the reader is reading the SYN.
        for before_connect in [true, false] {
            let listener = tos_recording_listener_v4();
            let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
                .expect("a client socket");
            if before_connect {
                set_tos(socket.as_raw_fd(), i32::from(tos));
            }
            socket
                .connect(&listener.local_addr().unwrap().into())
                .expect("connect");
            if !before_connect {
                set_tos(socket.as_raw_fd(), i32::from(tos));
            }
            let mut client = std::net::TcpStream::from(socket);
            client.write_all(b"calibration").expect("write");
            let (mut accepted, _) = accept_within(&listener, Duration::from_secs(2))
                .expect("the in-process client connected before the accept, so it must be there");
            let mut buf = [0u8; 32];
            accepted
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert!(accepted.read(&mut buf).expect("read") > 0);
            assert_eq!(
                opening_segment_tos_v4(&accepted),
                Some(if before_connect { tos } else { 0 }),
                "the stream reader must report the TOS of the opening segment \
                 (set before connect: {before_connect})"
            );
        }
    }
}

// wz-proves: transport-link-tcp zenohd->wz partial
// wz-proves: transport-link-tls zenohd->wz partial
// wz-proves: transport-link-udp zenohd->wz partial
// wz-proves: transport-link-quic zenohd->wz partial
#[test]
#[ignore = "binary-dep e2e (zenohd + wz-ap-demo built with tls, quic); Layer Z runs via --ignored"]
fn bind_and_dscp_reach_the_wire_as_zenohd_puts_them() {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let (_ca_dir, ca) = write_ca();

    let mut failures = Vec::new();
    for row in rows() {
        let (by_zenohd, zenohd_log) = observe(Dialer::Zenohd, &row, &ca);
        if by_zenohd != row.zenohd {
            failures.push(format!(
                "{}: zenohd put {by_zenohd:?} where {:?} was measured, so this substrate \
                 cannot adjudicate the row\n--- zenohd ---\n{zenohd_log}",
                row.locator, row.zenohd
            ));
            continue;
        }
        let (by_wz, wz_log) = observe(Dialer::Wz, &row, &ca);
        if by_wz != by_zenohd {
            failures.push(format!(
                "{}: wz put {by_wz:?} where zenohd put {by_zenohd:?}\n--- wz ---\n{wz_log}",
                row.locator
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

/// The table's own shape: every refused row has an arriving `bind` row on the
/// same scheme, and every key has a row without it on the same scheme, so no
/// row's expectation can be met by a dialer that ignores its key.
// wz-proves: none -- checks the witness table's pairing; spawns nothing.
#[test]
fn every_row_has_its_control_row_on_the_same_scheme() {
    let rows = rows();
    let scheme = |locator: &str| locator.split('/').next().unwrap().to_string();
    for row in &rows {
        let s = scheme(row.locator);
        if row.zenohd == Seen::Nothing {
            assert!(
                rows.iter().any(|r| scheme(r.locator) == s
                    && r.locator.contains("bind=")
                    && !r.locator.contains("iface=")
                    && r.zenohd != Seen::Nothing),
                "{}: a refused row needs an arriving bind row on {s}",
                row.locator
            );
        }
        if row.locator.contains("bind=") && row.zenohd != Seen::Nothing {
            let Seen::Packet { source, .. } = row.zenohd else {
                unreachable!()
            };
            assert_eq!(source, IpAddr::V4(BIND_ADDR), "{}", row.locator);
        }
    }
    for s in ["tcp", "udp"] {
        let unkeyed = rows
            .iter()
            .find(|r| r.locator == format!("{s}/127.0.0.1:{{port}}"))
            .unwrap_or_else(|| panic!("{s} needs a row without any key"));
        for keyed in rows
            .iter()
            .filter(|r| scheme(r.locator) == s && r.locator.contains('#'))
        {
            assert_ne!(
                keyed.zenohd, unkeyed.zenohd,
                "{}: a keyed row must differ from the unkeyed one",
                keyed.locator
            );
        }
    }
}
