// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-unicast",
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-frame"
))]

//! R311y578 (G1 + G2) — the whole passive path, from a capture FILE to
//! decoded zenoh messages.
//!
//! Two real wz nodes handshake over loopback TCP through a recording proxy.
//! The recorded byte streams are then packetised into a classic pcap file —
//! Ethernet, IPv4, TCP, with a real three-way handshake, a deliberately
//! RETRANSMITTED segment, and a deliberately REORDERED pair — and that file
//! is handed to [`Dissection`], which has no access to either node.
//!
//! The chain under test is every layer at once:
//!
//! ```text
//! pcap file -> packets -> Ethernet/IPv4/TCP -> flow reassembly -> passive decode
//! ```
//!
//! and the assertion is that the messages coming out the far end are the
//! handshake the two nodes actually performed, with each one attributable to
//! the packet that carried it.
//!
//! The retransmission and the reordering are not decoration. They are the two
//! failures that make a naive "concatenate the payloads" reassembler produce a
//! byte stream that is subtly wrong, and a subtly wrong byte stream decodes
//! into confident nonsense rather than into an error.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use wz_capture::link::LINKTYPE_ETHERNET;
use wz_capture::{pcap, Dissection};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::inbound::InboundFrame;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::passive::{Direction, SessionPhase};

const ITER_CAP: usize = 64;
const CLIENT_IP: [u8; 4] = [10, 0, 0, 1];
const SERVER_IP: [u8; 4] = [10, 0, 0, 2];
const CLIENT_PORT: u16 = 45000;
const SERVER_PORT: u16 = 7447;

type Tap = Arc<Mutex<Vec<u8>>>;

async fn pump<R, W>(mut src: R, mut dst: W, tap: Tap)
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = [0u8; 4096];
    loop {
        match src.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                tap.lock().expect("tap").extend_from_slice(&buf[..n]);
                if dst.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// Build one Ethernet + IPv4 + TCP packet. Checksums are left zero: nothing
/// in the dissection path verifies them, and a fixture that computed them
/// would be asserting a property no consumer reads.
fn packet(
    src: [u8; 4],
    sport: u16,
    dst: [u8; 4],
    dport: u16,
    seq: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&dport.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes());
    tcp.push(5 << 4);
    tcp.push(flags);
    tcp.extend_from_slice(&0xFFFFu16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(payload);

    let mut ip = vec![0x45u8, 0x00];
    ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.push(64);
    ip.push(6);
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    ip.extend_from_slice(&tcp);

    let mut eth = Vec::new();
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // dst mac
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]); // src mac
    eth.extend_from_slice(&0x0800u16.to_be_bytes());
    eth.extend_from_slice(&ip);
    eth
}

const PSH_ACK: u8 = 0x18;
const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;

/// Split a byte stream into `n` roughly-equal chunks, so the pcap carries the
/// stream across several segments rather than one giant one — which is what
/// makes reassembly a real step instead of a copy.
fn chunk(bytes: &[u8], n: usize) -> Vec<&[u8]> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let size = bytes.len().div_ceil(n).max(1);
    bytes.chunks(size).collect()
}

/// Run a real handshake through a recording proxy and return the two
/// directions' bytes.
async fn tapped_handshake() -> (Vec<u8>, Vec<u8>) {
    let acceptor_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind acceptor");
    let acceptor_addr = acceptor_listener.local_addr().expect("addr");
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_addr = proxy_listener.local_addr().expect("addr");

    let tap_a: Tap = Arc::new(Mutex::new(Vec::new()));
    let tap_b: Tap = Arc::new(Mutex::new(Vec::new()));
    let (pa, pb) = (Arc::clone(&tap_a), Arc::clone(&tap_b));
    let proxy = tokio::spawn(async move {
        let (client, _) = proxy_listener.accept().await.expect("proxy accept");
        let server = TcpStream::connect(acceptor_addr).await.expect("proxy dial");
        let (crd, cwr) = client.into_split();
        let (srd, swr) = server.into_split();
        tokio::join!(pump(crd, swr, pa), pump(srd, cwr, pb));
    });
    let acc = tokio::spawn(async move {
        let (stream, _peer) = acceptor_listener.accept().await.expect("accept");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
        accept_and_open_session(
            DialedLink::Tcp(stream),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor Established")
    });
    let locator = parse_any_locator(&format!("tcp/{proxy_addr}")).expect("locator");
    let mut params = fixture_session_init_params();
    params.zid = vec![0x01; 4];
    let init = connect_and_open_session(
        locator,
        params,
        &DialConfig::default(),
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .expect("initiator Established");
    let accepted = acc.await.expect("acceptor task");
    init.drain_to_close().await;
    accepted.drain_to_close().await;
    let _ = proxy.await;

    let a = tap_a.lock().expect("tap a").clone();
    let b = tap_b.lock().expect("tap b").clone();
    (a, b)
}

/// The full chain: a capture file in, the handshake out, every message
/// attributable to a packet — over a capture that contains a retransmission
/// and a reordering.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pcap_of_a_real_handshake_dissects_end_to_end() {
    let (a_bytes, b_bytes) = tapped_handshake().await;
    assert!(!a_bytes.is_empty() && !b_bytes.is_empty());

    // ── Packetise. A real three-way handshake first, so the reassembler
    //    learns each stream's ORIGIN from a SYN rather than from wherever the
    //    capture happened to start. ──
    let mut records: Vec<(u32, u32, Vec<u8>)> = Vec::new();
    let mut ts = 0u32;
    let mut push = |records: &mut Vec<(u32, u32, Vec<u8>)>, p: Vec<u8>| {
        ts += 1;
        records.push((0, ts, p));
    };
    push(
        &mut records,
        packet(
            CLIENT_IP,
            CLIENT_PORT,
            SERVER_IP,
            SERVER_PORT,
            1000,
            SYN,
            b"",
        ),
    );
    push(
        &mut records,
        packet(
            SERVER_IP,
            SERVER_PORT,
            CLIENT_IP,
            CLIENT_PORT,
            5000,
            SYN_ACK,
            b"",
        ),
    );

    // Client -> server, chunked, with the SECOND chunk RETRANSMITTED.
    let a_chunks = chunk(&a_bytes, 3);
    let mut seq = 1001u32;
    for (i, c) in a_chunks.iter().enumerate() {
        push(
            &mut records,
            packet(
                CLIENT_IP,
                CLIENT_PORT,
                SERVER_IP,
                SERVER_PORT,
                seq,
                PSH_ACK,
                c,
            ),
        );
        if i == 1 {
            // Byte-identical retransmission. A reassembler that appends it
            // inserts a duplicate run into the middle of the stream.
            push(
                &mut records,
                packet(
                    CLIENT_IP,
                    CLIENT_PORT,
                    SERVER_IP,
                    SERVER_PORT,
                    seq,
                    PSH_ACK,
                    c,
                ),
            );
        }
        seq = seq.wrapping_add(c.len() as u32);
    }

    // Server -> client, chunked, with the FIRST TWO chunks REORDERED.
    let b_chunks = chunk(&b_bytes, 3);
    let mut b_seqs = Vec::new();
    let mut s = 5001u32;
    for c in &b_chunks {
        b_seqs.push(s);
        s = s.wrapping_add(c.len() as u32);
    }
    let order: Vec<usize> = if b_chunks.len() >= 2 {
        let mut o: Vec<usize> = (0..b_chunks.len()).collect();
        o.swap(0, 1);
        o
    } else {
        (0..b_chunks.len()).collect()
    };
    for i in order {
        push(
            &mut records,
            packet(
                SERVER_IP,
                SERVER_PORT,
                CLIENT_IP,
                CLIENT_PORT,
                b_seqs[i],
                PSH_ACK,
                b_chunks[i],
            ),
        );
    }

    let borrowed: Vec<(u32, u32, &[u8])> = records
        .iter()
        .map(|(s, f, p)| (*s, *f, p.as_slice()))
        .collect();
    let file = pcap::write(LINKTYPE_ETHERNET, &borrowed);

    // ── Dissect. Nothing below has seen either node. ──
    let dissection = Dissection::from_pcap(&file).expect("the capture parses");
    assert_eq!(dissection.flows().len(), 1, "one TCP connection");
    assert!(
        dissection.skipped().is_empty(),
        "no packet was skipped: {:?}",
        dissection.skipped()
    );
    let flow = &dissection.flows()[0];

    // The reassembled streams must equal the tapped bytes EXACTLY. This is
    // where the retransmission and the reordering are actually judged: a
    // duplicated run or a transposed pair changes these vectors.
    assert_eq!(
        flow.assembler(Direction::A).stream(),
        a_bytes.as_slice(),
        "client->server reassembles to the tapped bytes despite the retransmission"
    );
    assert_eq!(
        flow.assembler(Direction::B).stream(),
        b_bytes.as_slice(),
        "server->client reassembles to the tapped bytes despite the reordering"
    );
    assert!(
        flow.assembler(Direction::A).synced_from_syn()
            && flow.assembler(Direction::B).synced_from_syn(),
        "both origins came from an observed SYN, so offset 0 is the stream's start"
    );
    assert_eq!(flow.assembler(Direction::A).held_segments(), 0);
    assert_eq!(flow.assembler(Direction::B).held_segments(), 0);

    // The zenoh layer read a handshake out of it.
    assert!(
        flow.frames.len() >= 4,
        "at least InitSyn/InitAck/OpenSyn/OpenAck, got {}",
        flow.frames.len()
    );
    assert!(
        flow.frames.iter().all(|f| f.frame.is_ok()),
        "every framed message decodes"
    );
    let ctx = flow.context();
    assert!(
        matches!(ctx.phase, SessionPhase::Established | SessionPhase::Closed),
        "the observer followed the session to Established, got {:?}",
        ctx.phase
    );
    assert_eq!(ctx.patch, Some(wz_session_core::extpatch::CURRENT_PATCH));
    assert!(ctx.negotiated());

    // Every decoded message is attributable to a PACKET. That is what makes
    // this a dissection rather than a decode.
    for f in &flow.frames {
        let pkt = flow
            .packet_for(f.direction, f.stream_offset)
            .unwrap_or_else(|| {
                panic!(
                    "frame at {:?}/{} maps to no packet",
                    f.direction, f.stream_offset
                )
            });
        assert!(
            pkt < records.len(),
            "the attributed packet index is inside the capture"
        );
    }

    // The FIRST message in each direction sits in the first data packet of
    // that direction, which the three-way handshake put at a known index.
    let first_a = flow
        .frames
        .iter()
        .find(|f| f.direction == Direction::A)
        .expect("a client-side frame");
    assert!(matches!(first_a.frame, Ok(InboundFrame::Init { .. })));
    assert_eq!(
        flow.packet_for(Direction::A, first_a.stream_offset),
        Some(2),
        "packets 0 and 1 are the SYN and SYN-ACK, so the first payload is packet 2"
    );
}

/// The NEGATIVE arm for the reassembler, and the reason the positive one is
/// not a tautology: feed the SAME capture with the retransmitted packet's
/// payload appended naively — i.e. simulate the bug — and the byte stream no
/// longer matches, which is what would have made the decode produce nonsense.
///
/// Rather than reach into the assembler, this drives the real one and asserts
/// the DIFFERENCE between the reassembled length and the sum of the payloads,
/// which is exactly the duplicate the naive path would have kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_retransmitted_payload_is_counted_once_not_twice() {
    let (a_bytes, _b) = tapped_handshake().await;
    let chunks = chunk(&a_bytes, 3);
    assert!(chunks.len() >= 2, "the tap is long enough to chunk");

    let mut records: Vec<(u32, u32, Vec<u8>)> = Vec::new();
    let mut ts = 0u32;
    let mut naive_total = 0usize;
    let mut push = |records: &mut Vec<(u32, u32, Vec<u8>)>, p: Vec<u8>| {
        ts += 1;
        records.push((0, ts, p));
    };
    push(
        &mut records,
        packet(
            CLIENT_IP,
            CLIENT_PORT,
            SERVER_IP,
            SERVER_PORT,
            1000,
            SYN,
            b"",
        ),
    );
    let mut seq = 1001u32;
    for (i, c) in chunks.iter().enumerate() {
        push(
            &mut records,
            packet(
                CLIENT_IP,
                CLIENT_PORT,
                SERVER_IP,
                SERVER_PORT,
                seq,
                PSH_ACK,
                c,
            ),
        );
        naive_total += c.len();
        if i == 1 {
            push(
                &mut records,
                packet(
                    CLIENT_IP,
                    CLIENT_PORT,
                    SERVER_IP,
                    SERVER_PORT,
                    seq,
                    PSH_ACK,
                    c,
                ),
            );
            naive_total += c.len();
        }
        seq = seq.wrapping_add(c.len() as u32);
    }

    let borrowed: Vec<(u32, u32, &[u8])> = records
        .iter()
        .map(|(s, f, p)| (*s, *f, p.as_slice()))
        .collect();
    let file = pcap::write(LINKTYPE_ETHERNET, &borrowed);
    let dissection = Dissection::from_pcap(&file).expect("parse");
    let flow = &dissection.flows()[0];

    assert_eq!(
        flow.assembler(Direction::A).len(),
        a_bytes.len(),
        "the stream is the tapped length"
    );
    assert!(
        naive_total > a_bytes.len(),
        "the fixture really does carry a duplicate: naive {naive_total} vs real {}",
        a_bytes.len()
    );
    assert_eq!(
        naive_total - a_bytes.len(),
        chunks[1].len(),
        "and the difference is exactly the retransmitted chunk"
    );
}

/// One Ethernet + IPv4 frame carrying `payload` as a PIECE of a fragmented
/// datagram, at `offset` bytes with the More-Fragments flag `more`.
fn ipv4_fragment(
    src: [u8; 4],
    dst: [u8; 4],
    ident: u16,
    offset: usize,
    more: bool,
    payload: &[u8],
) -> Vec<u8> {
    assert_eq!(
        offset % 8,
        0,
        "IP encodes the fragment offset in 8-byte units"
    );
    let flags_off = (offset as u16 / 8) | if more { 0x2000 } else { 0 };
    let mut ip = vec![0x45u8, 0x00];
    ip.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&ident.to_be_bytes());
    ip.extend_from_slice(&flags_off.to_be_bytes());
    ip.push(64);
    ip.push(17); // UDP
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    ip.extend_from_slice(payload);

    let mut eth = Vec::new();
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
    eth.extend_from_slice(&0x0800u16.to_be_bytes());
    eth.extend_from_slice(&ip);
    eth
}

/// R311y607 — the FRAGMENT half of the capture path, over a real capture FILE.
///
/// R311y606 built IP fragment reassembly and proved it in `wz-capture`'s unit
/// tests. What it did not do — and recorded as debt — is put a fragmented
/// datagram in a capture the whole chain reads: no corpus file contained one,
/// so outside those unit tests the reassembler never ran. `from_capture` ->
/// pcap parse -> Ethernet -> IPv4 reassembly -> UDP -> passive decode is a
/// longer path than `push_packet`, and the difference is exactly where a
/// reassembled datagram could be handed to the wrong strip.
///
/// The message is not invented: it is the FIRST message two real wz nodes sent
/// each other in `tapped_handshake`, lifted out of its stream envelope and put
/// in a datagram, which is what the same message looks like on a `udp/...`
/// link. So a decode that comes back wrong is wrong about traffic wz itself
/// produced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fragmented_datagram_in_a_capture_file_decodes_end_to_end() {
    let (a_bytes, _) = tapped_handshake().await;
    assert!(a_bytes.len() > 2, "the tap recorded a handshake");

    // Lift the first message out of the stream framing: zenoh's stream links
    // prefix each message with a 2-byte little-endian length, and a datagram
    // link carries the message with no prefix at all.
    let len = u16::from_le_bytes([a_bytes[0], a_bytes[1]]) as usize;
    assert!(
        len > 0 && 2 + len <= a_bytes.len(),
        "the first length prefix describes a message inside the tap"
    );
    let message = &a_bytes[2..2 + len];

    // Wrap it in UDP. The header's length field covers the WHOLE datagram,
    // which is precisely what a lone first fragment cannot satisfy — the
    // property R311y606 found the defect in.
    let mut udp = Vec::new();
    udp.extend_from_slice(&CLIENT_PORT.to_be_bytes());
    udp.extend_from_slice(&SERVER_PORT.to_be_bytes());
    udp.extend_from_slice(&((8 + message.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes());
    udp.extend_from_slice(message);

    // Split on an 8-byte boundary that leaves both pieces non-empty.
    let cut = 8.max((udp.len() / 2) & !7);
    assert!(cut < udp.len(), "the datagram is long enough to split");
    let first = ipv4_fragment(CLIENT_IP, SERVER_IP, 0x1D07, 0, true, &udp[..cut]);
    let rest = ipv4_fragment(CLIENT_IP, SERVER_IP, 0x1D07, cut, false, &udp[cut..]);

    // ── The pieces arrive OUT OF ORDER, which a network is free to do and a
    //    reassembler keyed on arrival rather than on offset would get wrong. ──
    let records: Vec<(u32, u32, &[u8])> = vec![(0, 1, &rest), (0, 2, &first)];
    let file = pcap::write(LINKTYPE_ETHERNET, &records);

    // `from_capture` rather than `from_pcap`: the sniffing entry point is the
    // one a consumer is meant to use, and it is a different code path.
    let dissection = Dissection::from_capture(&file).expect("the capture parses");

    assert_eq!(
        dissection.datagram_flows().len(),
        1,
        "the two pieces are ONE datagram flow, not two"
    );
    let flow = &dissection.datagram_flows()[0];
    assert_eq!(
        flow.frames.len(),
        1,
        "one datagram in, one message out: {:?}",
        flow.frames
    );
    assert!(
        matches!(flow.frames[0].frame, Ok(InboundFrame::Init { .. })),
        "the reassembled datagram decodes to the Init the nodes really sent: {:?}",
        flow.frames[0].frame
    );

    // The reassembly must be VISIBLE, not inferred from the decode working:
    // a build that quietly passed the last piece through alone could also
    // produce one frame, and the counter is what separates the two.
    let stats = dissection.fragment_stats();
    assert_eq!(stats.completed, 1, "exactly one chain completed: {stats:?}");
    assert_eq!(
        stats.pieces, 2,
        "both pieces went THROUGH the table rather than one bypassing it: {stats:?}"
    );
    assert_eq!(stats.malformed, 0, "nothing was refused: {stats:?}");

    // The lone FIRST piece must not be mistaken for a whole datagram — the
    // actual R311y606 defect, which had offset zero and so passed an
    // offset-only test. Fed alone, it is named as pending rather than decoded.
    let alone: Vec<(u32, u32, &[u8])> = vec![(0, 1, &first)];
    let partial = Dissection::from_capture(&pcap::write(LINKTYPE_ETHERNET, &alone))
        .expect("the capture parses");
    assert!(
        partial.datagram_flows().is_empty(),
        "a first fragment alone is not a datagram"
    );
    let partial_stats = partial.fragment_stats();
    assert_eq!(
        (partial_stats.pieces, partial_stats.completed),
        (1, 0),
        "it is HELD as a piece, not completed and not silently dropped: {partial_stats:?}"
    );
}
