// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2050 (open-debt item 390, the JOIN half) — `walk_join_qos_body`, against a
//! multicast Join a stock zenohd actually broadcast.
//!
//! ## Why this half needed a different harness, not just a different config
//!
//! R2049 closed item 390's `shm` half and measured why the JOIN half could not
//! follow: upstream carries `ext_qos` on a Join only when
//! `next_sns.len() == Priority::NUM` (`multicast/link.rs:476-490`), which needs
//! a MULTICAST transport with `transport/multicast/qos/enabled`. Multicast is
//! UDP datagrams; `wire_tap::tap_proxy` is a TCP relay. The three witnesses
//! that share `ext_bodies` could not reach this body at all, and this tree had
//! no multicast datagram capture of any kind (measured: zero `join_multicast` /
//! `IP_ADD_MEMBERSHIP` sites).
//!
//! So this round built the missing piece rather than working around it:
//! `wire_tap::synthesise_multicast_pcap`, the datagram sibling of the TCP
//! synthesiser, beside it in the module whose whole reason is that the envelope
//! rules are ONE fact.
//!
//! ## The topology, and why nothing relays
//!
//! ```text
//!   zenohd -l udp/<group>:<port>#iface=lo  ──►  the group  ──►  this test's socket
//!        (stock zenoh, broadcasting Joins)                       (a plain UDP recv)
//! ```
//!
//! There is no proxy: a multicast group needs no relay, the test simply joins
//! it. That also makes this the only witness in the family where the capture is
//! ONE-directional and correctly so — a Join is an announcement, not an
//! exchange.
//!
//! ## What is graded, and it is the whole datagram path
//!
//! The recorded datagrams are wrapped as a pcap and handed to
//! `wz_capture::Dissection`, so this test exercises the analyzer's UDP flow
//! plane — L2 multicast MAC, IPv4, UDP, the datagram framing decision, the
//! zenoh observer — and not only the extension walker. That is deliberate:
//! feeding `dissect_transport_message` the bytes directly would have been
//! shorter and would have graded one function instead of the path a reader
//! actually opens a capture through.
//!
//! A decoded datagram message's `stream_offset` is the INDEX OF ITS PACKET
//! (`DatagramDissection::frames` says so: a datagram has no stream to be an
//! offset into). There is no `message_bytes` for a datagram flow — the
//! analyzer's own consumer resolves that coordinate by re-reading the packet
//! from the capture file — so this test resolves it the same way, against the
//! datagrams it recorded.
//!
//! ## The assertion: the per-priority table, by NAME and by ARITY
//!
//! `walk_join_qos_body` reads `Priority::NUM` pairs of VLEs and labels each
//! group with the BAND'S NAME rather than its discriminant. So the reading is
//! eight `priority_sn` groups whose labels are zenoh's eight priority names in
//! wire order — which is a claim about the ORDER of the table, not just its
//! size, and it is the fact a multicast diagnosis needs: which SN each band is
//! at.

use std::net::{Ipv4Addr, UdpSocket};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_capture::Dissection;
use wz_integration_tests::common::{zenohd_binary, ChildGuard, PortReservation};
use wz_integration_tests::ext_bodies::{collect, dump, Body, Depth, Reading, ENC_ZBUF};
use wz_integration_tests::wire_tap::synthesise_multicast_pcap;
use wz_session_core::passive::Direction;

/// The group zenoh's own multicast transport defaults to. Reused rather than
/// invented so the capture is the shape a real deployment produces.
const GROUP: [u8; 4] = [224, 0, 0, 224];

/// How long zenohd is given to broadcast, and how many Joins are enough.
///
/// `join_interval` is set to 500ms below, so four is about two seconds of wire
/// and leaves room for the first one to be missed while the socket settles.
const WANT_DATAGRAMS: usize = 3;
const RECV_BUDGET: Duration = Duration::from_secs(20);

/// zenoh's eight priority bands, in WIRE ORDER — the order the Join's table is
/// written in, and therefore the order the walker must report.
///
/// Held against `wz_session_core::qos::Priority::name`, which that module's own
/// test pins to the zenoh-pico constants. So this list has an adjudicator
/// behind it rather than being a transcription.
const PRIORITY_BANDS: &[&str] = &[
    "Control",
    "RealTime",
    "InteractiveHigh",
    "InteractiveLow",
    "DataHigh",
    "Data",
    "DataLow",
    "Background",
];

/// Spawn a stock zenohd that broadcasts multicast Joins carrying the qos table.
///
/// Both `--cfg`s are load-bearing. Without the multicast LISTEN endpoint there
/// is no multicast transport and no Join at all; without
/// `transport/multicast/qos/enabled` upstream takes the `next_sns[0]` branch and
/// the Join carries a single SN with NO `ext_qos`, which is the same wire this
/// witness would then be reading nothing out of.
fn spawn_multicast_zenohd(port: u16) -> ChildGuard {
    let group = Ipv4Addr::from(GROUP);
    let mut command = Command::new(zenohd_binary());
    command
        .arg("-l")
        .arg(format!("udp/{group}:{port}#iface=lo"))
        .arg("--rest-http-port")
        .arg("none")
        .arg("--no-multicast-scouting")
        .arg("--cfg")
        .arg("transport/multicast/qos/enabled:true")
        .arg("--cfg")
        .arg("transport/multicast/join_interval:500")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    ChildGuard::wrap(
        "zenohd (multicast Join broadcaster)",
        command
            .spawn()
            .expect("spawn zenohd on a multicast endpoint"),
    )
}

/// Join the group on loopback and record datagrams until `want` have arrived.
///
/// ⚠ `SO_REUSEADDR` IS LOAD-BEARING AND `std::net::UdpSocket` CANNOT SET IT.
/// zenohd has already bound this port to receive the group, and without the
/// option a second receiver on one multicast port gets NOTHING — the first run
/// of this test waited its whole budget and recorded zero datagrams for exactly
/// that reason, while a hand probe that set the option saw four. So the socket
/// is built through `socket2`, which this crate already carries.
fn record_group(port: u16, want: usize, budget: Duration) -> Vec<Vec<u8>> {
    let raw = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .expect("open a UDP socket");
    raw.set_reuse_address(true)
        .expect("SO_REUSEADDR, or zenohd keeps the group to itself");
    raw.bind(&std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())
        .expect("bind the multicast port");
    let socket: UdpSocket = raw.into();
    socket
        .join_multicast_v4(&Ipv4Addr::from(GROUP), &Ipv4Addr::LOCALHOST)
        .expect("join the group on loopback");
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set a read timeout so a silent wire cannot hang this test");
    let mut out = Vec::new();
    let mut buf = [0u8; 65_535];
    let deadline = Instant::now() + budget;
    while out.len() < want && Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((n, _)) if n > 0 => out.push(buf[..n].to_vec()),
            _ => continue,
        }
    }
    out
}

/// THE WITNESS: the multicast Join's qos table, read out of bytes a stock
/// zenohd broadcast.
///
/// The `zenohd` in the name is LOAD-BEARING: Layer C0's skip-token rule reads
/// the FUNCTION name, because that is what libtest's `--skip` matches.
// This grades the DISSECTOR on foreign bytes. wz's own `multicast_join`
// producer never runs here, so no atom of this tree is compiled in to be
// proven -- the judgement R2048 had to make after Layer A4 refused a claim
// whose feature was absent from the closure.
// wz-proves: none -- grades the dissector on foreign bytes; wz's multicast_join producer never runs
#[test]
#[ignore = "binary-dep e2e (zenohd on a multicast endpoint); Layer Ewirez runs via --ignored"]
fn the_join_qos_walker_reads_what_a_stock_zenohd_broadcast() {
    // ONE reservation, and the port is used for the multicast group rather than
    // for a TCP listener -- see `pick_pair`'s doc for why a second `pick` on
    // this thread would deadlock (R2049 paid for that).
    let reservation = PortReservation::pick();
    let port = reservation.port();

    let mut zenohd = spawn_multicast_zenohd(port);
    let datagrams = record_group(port, WANT_DATAGRAMS, RECV_BUDGET);
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    // ── ANTI-VACUITY FIRST ────────────────────────────────────────────────
    assert!(
        datagrams.len() >= WANT_DATAGRAMS,
        "the group carried {} datagram(s) and this test needs {WANT_DATAGRAMS}; \
         an empty or short capture satisfies every assertion below",
        datagrams.len()
    );

    let pcap = synthesise_multicast_pcap(&datagrams, port, GROUP, port);
    let dissection = Dissection::from_pcap(&pcap).expect("the synthesised pcap parses");

    // THE CAPTURE MUST BE CLEAN ON BOTH CHECKSUM AXES. R311y886 found this
    // module writing zeros for the TCP path under a comment claiming nothing
    // verified them; the datagram builder is new and gets the same guard rather
    // than the same assumption.
    let health = dissection.health();
    assert!(
        health.ip_checksum_valid > 0 && health.ip_checksum_invalid == 0,
        "the synthesised multicast pcap is not IPv4-checksum-clean \
         ({} valid / {} invalid) -- a harness that hands the analyzer a corrupt \
         capture makes every finding against it suspect",
        health.ip_checksum_valid,
        health.ip_checksum_invalid,
    );
    assert!(
        health.transport_checksum_valid > 0 && health.transport_checksum_invalid == 0,
        "the synthesised multicast pcap is not UDP-checksum-clean ({} valid / \
         {} invalid)",
        health.transport_checksum_valid,
        health.transport_checksum_invalid,
    );

    // ── THE ANALYZER'S DATAGRAM PLANE, NOT JUST THE WALKER ────────────────
    let flows = dissection.datagram_flows();
    assert_eq!(
        flows.len(),
        1,
        "one multicast group is one datagram flow; got {}",
        flows.len()
    );
    let flow = &flows[0];
    assert!(
        !flow.frames.is_empty(),
        "the analyzer opened the flow and decoded NO transport message out of \
         {} datagram(s) -- so what follows would be about nothing",
        datagrams.len()
    );

    // A datagram message's `stream_offset` is the index of its PACKET, and
    // there is no `message_bytes` for a datagram flow: the analyzer's own
    // consumer re-reads the packet from the file. This test holds the same
    // bytes, so it resolves the coordinate the same way. Distinct indices only,
    // because one datagram is one framing unit and dissecting it once per
    // decoded message would double-count a batch.
    let mut seen_packets: Vec<usize> = flow.frames.iter().map(|f| f.stream_offset).collect();
    seen_packets.sort_unstable();
    seen_packets.dedup();
    let mut bodies: Vec<Body> = Vec::new();
    for index in &seen_packets {
        let payload = datagrams.get(*index).unwrap_or_else(|| {
            panic!(
                "a frame names packet {index} and the capture has {} ",
                datagrams.len()
            )
        });
        let walked = wz_session_core::dissect::dissect_transport_message(payload, 0)
            .expect("a datagram this analyzer decoded is one this walker can dissect");
        collect(&walked, Direction::A, "?", Depth::Deep, &mut bodies);
    }
    eprintln!(
        "extension bodies a stock zenohd multicast Join put on the wire:\n{}",
        dump(&bodies)
    );

    // ── THE qos TABLE, BY NAME AND IN ORDER ───────────────────────────────
    let qos = bodies
        .iter()
        .filter(|b| b.carrier == "Join" && b.name == "qos")
        .find(|b| b.encoding == Some(ENC_ZBUF))
        .unwrap_or_else(|| {
            panic!(
                "no walked ZBuf `qos` body on a Join. Upstream only carries one \
                 when the multicast transport is QoS-enabled, so either the \
                 config above stopped working or the walker declined the \
                 body:\n{}",
                dump(&bodies)
            )
        });

    let bands: Vec<&str> = qos
        .read
        .iter()
        .filter(|(name, _)| name == "priority")
        .filter_map(|(_, r)| match r {
            Reading::Label(l) => Some(l.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        bands,
        PRIORITY_BANDS,
        "the Join's per-priority table was not read as zenoh's eight bands in \
         wire order. This is the assertion a multicast diagnosis rests on -- \
         which SN each band is at -- and a walker that read the pairs in the \
         wrong order, or read seven of them, reports a confidently wrong \
         answer: {}",
        qos.describe()
    );

    // Every band must carry BOTH sequence numbers. The band labels above come
    // from the walker's own loop counter, so they would be right even if the
    // VLEs behind them were not read at all; these are what say the table was
    // consumed rather than counted.
    for what in ["next_sn_reliable", "next_sn_best_effort"] {
        let n = qos.read.iter().filter(|(name, _)| name == what).count();
        assert_eq!(
            n,
            PRIORITY_BANDS.len(),
            "the table reports {n} `{what}` value(s) for {} band(s): {}",
            PRIORITY_BANDS.len(),
            qos.describe()
        );
    }
}
