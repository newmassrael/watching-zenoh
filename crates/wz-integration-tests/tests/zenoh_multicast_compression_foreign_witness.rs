// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `transport/multicast/compression/enabled`, against a stock zenohd at the pinned release.
//!
//! zenoh 1.10.2 reads the key into its multicast manager; 1.10.1 never did. A group whose
//! members state it carries every datagram as a batch: the one-byte `BatchHeader` in front,
//! the payload lz4-compressed when that is smaller. Multicast has no handshake to settle the
//! wrap, so the only evidence that wz reads and writes the same wire is a stock node on the
//! same group. Five witnesses:
//!
//! 1. what a compressing zenohd broadcasts is a batch wz unwraps into a JOIN
//!    (`a_stock_zenohd_beacons_a_compressing_group_as_batches`);
//! 2. the same zenohd without the key broadcasts the bare JOIN, so the key is what changed the
//!    wire and the first witness is not satisfied by a router that always wraps
//!    (`a_stock_zenohd_beacons_a_plain_group_as_bare_joins`);
//! 3. what a compressing wz member beacons is a batch zenohd unwraps: zenohd lists it as a
//!    member of the group, in its admin space
//!    (`a_stock_zenohd_admits_a_compressing_wz_member_and_not_a_plain_one`, whose second half
//!    is that a plain wz member that starts beside it is not listed);
//! 4. the converse, a compressing wz member of a group that does not compress is not listed
//!    (`a_stock_zenohd_of_a_plain_group_does_not_admit_a_compressing_wz_member`);
//! 5. the control, without which the two "not listed" above could be a harness that lists
//!    nobody: plain wz members of a plain group are listed
//!    (`a_stock_zenohd_admits_plain_wz_members_of_a_plain_group`).
//!
//! A member that sends over the host's default interface is heard by no zenohd that joined on
//! `lo`, and a JOIN whose batch size is not the link's is dropped by zenohd whatever else it
//! says; both are why the members below are built as they are.
//!
//! Opt-in (`#[ignore]`, run-ci Layer Ewirez): it needs a zenohd built at the pin, and a host
//! that delivers multicast on loopback. The test names carry `zenohd` because Layer C0's skip
//! rule reads the function name.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use tokio::net::{TcpStream, UdpSocket as TokioUdpSocket};

use wz_integration_tests::common::{
    spawn_zenohd_dialer_on_ephemeral_tcp_with_cfgs, zenohd_binary, ChildGuard, PortReservation,
};
use wz_runtime_tokio::multicast_glue::{
    drive_multicast_session, MulticastDriveConfig, MulticastLink, MulticastTxProducer,
};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{QueryOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{initiate_and_open_session, DialedLink, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio::UdpDriver;
use wz_runtime_tokio_test_support::zenohd_interop_session_init_params;
use wz_session_core::compression::decompress_batch;
use wz_session_core::multicast_dispatch::{MulticastConfig, MulticastDispatcher};
use wz_session_core::multicast_join::decode_join;
use wz_session_core::multicast_params::MulticastParams;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::WhatAmI;

/// The group zenoh's own multicast transport defaults to.
const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 224);

/// How many beacons are enough, and how long zenohd is given to send them.
const WANT_DATAGRAMS: usize = 3;
const RECV_BUDGET: Duration = Duration::from_secs(20);

/// The largest batch zenoh puts on a multicast link, which bounds what a batch unwraps to.
const MULTICAST_BATCH: usize = 8_192;

const ADMIN_SELECTOR: &str = "@/*/router";
const ITER_CAP: usize = 4096;

/// Spawn a stock zenohd that beacons on a multicast group, with or without
/// `transport/multicast/compression/enabled`.
///
/// Both `--cfg`s that are not the key under test are load-bearing: without the multicast LISTEN
/// endpoint there is no multicast transport and no JOIN at all, and the interval is short so
/// that three beacons are a second or two of wire.
fn spawn_beaconing_zenohd(port: u16, compression: bool) -> ChildGuard {
    let mut command = Command::new(zenohd_binary());
    command
        .arg("-l")
        .arg(format!("udp/{GROUP}:{port}#iface=lo"))
        .arg("--rest-http-port")
        .arg("none")
        .arg("--no-multicast-scouting")
        .arg("--cfg")
        .arg("transport/multicast/join_interval:500");
    if compression {
        command
            .arg("--cfg")
            .arg("transport/multicast/compression/enabled:true");
    }
    command.stdout(Stdio::null()).stderr(Stdio::null());
    ChildGuard::wrap(
        "zenohd (multicast JOIN broadcaster)",
        command
            .spawn()
            .expect("spawn zenohd on a multicast endpoint"),
    )
}

/// Join the group on loopback and record datagrams until `want` have arrived.
///
/// `SO_REUSEADDR` is load-bearing and `std::net::UdpSocket` cannot set it: zenohd has bound the
/// port to receive the group, and without the option a second receiver gets nothing.
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
        .join_multicast_v4(&GROUP, &Ipv4Addr::LOCALHOST)
        .expect("join the group on loopback");
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set a read timeout so a silent wire cannot hang this test");
    let mut out = Vec::new();
    let mut buf = [0u8; 65_535];
    let deadline = Instant::now() + budget;
    while out.len() < want && Instant::now() < deadline {
        if let Ok((n, _)) = socket.recv_from(&mut buf) {
            if n > 0 {
                out.push(buf[..n].to_vec());
            }
        }
    }
    out
}

/// What zenohd beacons on a group it was given, killed once `WANT_DATAGRAMS` are recorded.
fn beacons_of(compression: bool) -> Vec<Vec<u8>> {
    // One reservation, and its port is the group's: see `zenoh_join_qos_foreign_witness`.
    let reservation = PortReservation::pick();
    let port = reservation.port();
    let mut zenohd = spawn_beaconing_zenohd(port, compression);
    let datagrams = record_group(port, WANT_DATAGRAMS, RECV_BUDGET);
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    assert!(
        datagrams.len() >= WANT_DATAGRAMS,
        "the group carried {} datagram(s) and this test needs {WANT_DATAGRAMS}; an empty or \
         short capture satisfies every assertion that follows",
        datagrams.len()
    );
    datagrams
}

/// wz reads what a compressing zenohd beacons: each datagram is a batch, the header's bit says
/// whether the payload is compressed, and the batch holds a JOIN of one zenohd id.
// This grades wz's reading of foreign bytes: no wz producer runs, so no atom of this tree is
// compiled in to be proven.
// wz-proves: none -- grades wz's batch unwrap on foreign bytes; wz's multicast producer never runs
#[test]
#[ignore = "binary-dep e2e (zenohd on a multicast endpoint); Layer Ewirez runs via --ignored"]
fn a_stock_zenohd_beacons_a_compressing_group_as_batches() {
    let datagrams = beacons_of(true);
    let mut zids = Vec::new();
    for datagram in &datagrams {
        let batch = decompress_batch(datagram, MULTICAST_BATCH).unwrap_or_else(|| {
            panic!(
                "a datagram of a compressing group is not a batch wz can unwrap: {datagram:02x?}"
            )
        });
        let join = decode_join(&batch).unwrap_or_else(|| {
            panic!("the batch of a compressing group holds no JOIN: {batch:02x?}")
        });
        assert!(
            (1..=16).contains(&join.zid.len()),
            "a JOIN names a zenoh id of 1 to 16 bytes, got {}",
            join.zid.len()
        );
        zids.push(join.zid.to_vec());
    }
    assert!(
        zids.windows(2).all(|pair| pair[0] == pair[1]),
        "one zenohd is one announcer: {zids:02x?}"
    );
}

/// The same zenohd, without the key, beacons the bare JOIN: the key is what puts the header on
/// the wire, and a stock node that always wrapped would have satisfied the witness above.
// wz-proves: none -- grades wz's JOIN decode on foreign bytes; wz's multicast producer never runs
#[test]
#[ignore = "binary-dep e2e (zenohd on a multicast endpoint); Layer Ewirez runs via --ignored"]
fn a_stock_zenohd_beacons_a_plain_group_as_bare_joins() {
    let datagrams = beacons_of(false);
    for datagram in &datagrams {
        let join = decode_join(datagram).unwrap_or_else(|| {
            panic!("a datagram of a plain group is not a bare JOIN: {datagram:02x?}")
        });
        assert!((1..=16).contains(&join.zid.len()));
    }
}

/// A TX-only group member, as the loopback leg of the runtime builds one: an ephemeral-bound
/// socket targeting the group, which beacons and is admitted by the group's other members.
///
/// Its multicast interface is loopback, because zenohd joined the group on `lo` alone
/// (`#iface=lo`): a datagram this socket sent out of the host's default interface would be
/// heard by nobody that is listening on `lo`, and the member would never be listed whatever it
/// said.
async fn bind_member(port: u16) -> std::io::Result<UdpDriver> {
    let raw = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    raw.set_multicast_if_v4(&Ipv4Addr::LOCALHOST)?;
    raw.set_multicast_loop_v4(true)?;
    raw.bind(&std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())?;
    raw.set_nonblocking(true)?;
    let socket = TokioUdpSocket::from_std(raw.into())?;
    Ok(UdpDriver::from_socket(
        socket,
        SocketAddr::from((GROUP, port)),
    ))
}

/// A member's parameters. The batch size is the group's, which is zenoh's multicast one: a
/// zenohd drops a JOIN whose batch size is not the link's (`io/zenoh-transport/src/multicast/rx.rs`
/// @ `Unsupported Batch Size`), so a member of another size is never listed, whatever else it
/// states.
fn member_params(zid_byte: u8, compression: bool) -> MulticastParams {
    MulticastParams {
        whatami: WhatAmI::Peer,
        zid: vec![zid_byte; 4],
        lease_ms: 5_000,
        join_interval_ms: 100,
        seq_num_res: 0x02,
        req_id_res: 0x02,
        batch_size: MULTICAST_BATCH as u16,
        is_qos: false,
        compression,
        tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
        link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
    }
}

/// The text of what zenohd's admin space says about the router, asked through `session`: its
/// reply is a JSON document that lists every session of the router, a multicast member among
/// them as `{"peer": "<zid>", "group": ...}`.
async fn admin_text(session: &TokioSession) -> String {
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let answered = Arc::new(AtomicBool::new(false));
    let done = answered.clone();
    session
        .query(
            ADMIN_SELECTOR,
            QueryOptions::default(),
            move |reply| {
                let _ = tx.send(reply.payload().to_vec());
            },
            move |_rid| done.store(true, Ordering::SeqCst),
        )
        .expect("session A sends its admin query");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !answered.load(Ordering::SeqCst) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut text = String::new();
    while let Ok(payload) = rx.try_recv() {
        text.push_str(&String::from_utf8_lossy(&payload));
    }
    text.to_ascii_lowercase()
}

/// The zenoh id the member of `byte` names, as zenohd's admin space prints it: a byte repeated,
/// so the id reads the same whichever end zenohd prints first.
fn listed_peer(byte: u8) -> String {
    format!("\"peer\":\"{}\"", format!("{byte:02x}").repeat(4))
}

/// What zenohd's admin space lists, once two wz members have beaconed on its group for a
/// while. Each member is `(zid byte, compression)`; the group compresses or not as zenohd is
/// told. The first member must be listed, or this panics: a harness that listed nobody would
/// leave every "is not listed" below to be satisfied by a wire nothing was heard on.
async fn what_zenohd_lists(
    group_compresses: bool,
    first: (u8, bool),
    second: (u8, bool),
) -> String {
    let reservation = PortReservation::pick();
    let group_port = reservation.port();
    let mut cfgs = vec!["transport/multicast/join_interval:200"];
    if group_compresses {
        cfgs.push("transport/multicast/compression/enabled:true");
    }
    let (mut zenohd, tcp_port) = spawn_zenohd_dialer_on_ephemeral_tcp_with_cfgs(
        &zenohd_binary(),
        "zenohd (multicast group)",
        None,
        &[format!("udp/{GROUP}:{group_port}#iface=lo")],
        None,
        &cfgs,
    );

    // Session A, a client dialled to the router, reads its admin space.
    let stream = TcpStream::connect(("127.0.0.1", tcp_port))
        .await
        .expect("session A dials zenohd");
    let mut opened = initiate_and_open_session(
        DialedLink::Tcp(stream),
        zenohd_interop_session_init_params(),
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .expect("session A reaches Established against zenohd");
    let session_a = TokioSession::new(
        opened.actions.clone(),
        Arc::new(wz_runtime_tokio::sync::PlainMutex::new(
            ApplicationLayerObserver::new(),
        )),
        Arc::new(opened.clock),
    );
    let timeouts = SessionTimeouts::spec_defaults();
    let drive_a = {
        let session = session_a.clone();
        drive_session_until_terminal(
            &mut opened.inbound,
            &opened.actions,
            &mut opened.engine,
            None,
            &opened.clock,
            &timeouts,
            move |event| session.dispatch_iteration_event(event),
        )
    };

    // The two members, each a TX-only drive loop beaconing on the group.
    let clock = Arc::new(TokioTime::new());
    let first_params = member_params(first.0, first.1);
    let second_params = member_params(second.0, second.1);
    let mut first_link = MulticastLink::new(|| bind_member(group_port));
    let mut second_link = MulticastLink::new(|| bind_member(group_port));
    let mut first_dispatcher = MulticastDispatcher::<8>::new(MulticastConfig::new(5_000));
    let mut second_dispatcher = MulticastDispatcher::<8>::new(MulticastConfig::new(5_000));
    let first_producer = MulticastTxProducer::new();
    let second_producer = MulticastTxProducer::new();
    let drive_first = drive_multicast_session(
        &mut first_dispatcher,
        MulticastDriveConfig {
            params: &first_params,
            tick_ms: 10,
            max_iters: None,
        },
        &mut first_link,
        clock.as_ref(),
        |_| {},
        &first_producer,
    );
    // The second member starts once zenohd lists the first: from then on the group is known to
    // be heard, so what the second does not get is a reading of its beacon and not of a wire
    // nothing was listening on, and what it does to the group cannot reach the first's listing.
    let first_listed = AtomicBool::new(false);
    let drive_second = async {
        while !first_listed.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        drive_multicast_session(
            &mut second_dispatcher,
            MulticastDriveConfig {
                params: &second_params,
                tick_ms: 10,
                max_iters: None,
            },
            &mut second_link,
            clock.as_ref(),
            |_| {},
            &second_producer,
        )
        .await
    };

    let first_peer = listed_peer(first.0);
    let scenario = async {
        // zenohd lists the first member once it has read a beacon of it.
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let text = admin_text(&session_a).await;
            if text.contains(&first_peer) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "zenohd never listed the wz member {first_peer} (compression {}) of a group \
                 that {} compress; its admin space said: {text}",
                first.1,
                if group_compresses { "does" } else { "does not" }
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        first_listed.store(true, Ordering::SeqCst);
        // The second member beacons every 100 ms from now, and has a dozen beacons behind it
        // by the time zenohd is asked: if zenohd were going to read it, it would have.
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        admin_text(&session_a).await
    };

    let mut drive_a = Box::pin(drive_a);
    let mut drive_first = Box::pin(drive_first);
    let mut drive_second = Box::pin(drive_second);
    let text = tokio::select! {
        outcome = &mut drive_a => panic!("session A's drive loop ended: {outcome:?}"),
        outcome = &mut drive_first => panic!("the first member's loop ended: {outcome:?}"),
        outcome = &mut drive_second => panic!("the second member's loop ended: {outcome:?}"),
        text = scenario => text,
    };
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    text
}

/// The control: on a group that does not compress, zenohd lists plain wz members. A harness
/// that could not get a wz member listed at all would make the two witnesses below say
/// nothing, so this is the one that fails first when a parameter of the member is wrong.
// wz-proves: none -- the subject is zenohd's reading of wz's beacon; the admin query only reads it
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd on a multicast endpoint); Layer Ewirez runs via --ignored"]
async fn a_stock_zenohd_admits_plain_wz_members_of_a_plain_group() {
    let text = what_zenohd_lists(false, (0xd1, false), (0xd2, false)).await;
    assert!(
        text.contains(&listed_peer(0xd2)),
        "zenohd did not list the second plain member of a plain group: {text}"
    );
}

/// zenohd unwraps what a compressing wz member beacons: it lists that member in its admin
/// space, and does not list a plain wz member that beacons on the same group beside it. The
/// second half is what makes the first one a reading of the key and not of a router that
/// admits anything it hears: a plain JOIN is read behind a header it does not have, and is
/// dropped.
// wz-proves: none -- the subject is zenohd's reading of wz's beacon; the admin query only reads it
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd on a multicast endpoint); Layer Ewirez runs via --ignored"]
async fn a_stock_zenohd_admits_a_compressing_wz_member_and_not_a_plain_one() {
    // `what_zenohd_lists` returns only once zenohd has listed the compressing member, which is
    // the half of this witness that says zenohd reads wz's compressed beacon.
    let text = what_zenohd_lists(true, (0xd1, true), (0xd2, false)).await;
    assert!(
        !text.contains(&listed_peer(0xd2)),
        "zenohd listed a plain wz member of a compressing group: {text}"
    );
}

/// The converse: on a group that does not compress, zenohd lists a plain wz member and not a
/// compressing one, whose JOIN it reads as a bare JOIN behind a header it did not expect.
// wz-proves: none -- the subject is zenohd's reading of wz's beacon; the admin query only reads it
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd on a multicast endpoint); Layer Ewirez runs via --ignored"]
async fn a_stock_zenohd_of_a_plain_group_does_not_admit_a_compressing_wz_member() {
    let text = what_zenohd_lists(false, (0xd1, false), (0xd2, true)).await;
    assert!(
        !text.contains(&listed_peer(0xd2)),
        "zenohd listed a compressing wz member of a plain group: {text}"
    );
}
