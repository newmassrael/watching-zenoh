// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session table, graded against what the other documents already say.
//!
//! # The oracles, and why each is independent of the thing it grades
//!
//! * the ROWS are graded against the census (`nodes` and `links`) and the field
//!   document (`flows`), PARSED OUT OF THE DOCUMENTS and not read off the typed
//!   tables behind them, because a consumer holds the documents;
//! * the TOTALS are graded against numbers the FIXTURE knows: the builders below
//!   count the bytes they put on the wire and the messages they put in them, so
//!   the library is never asked what the library counted;
//! * the RETENTION claim is graded by running ONE capture twice, with and without
//!   a ceiling that discards most of it, and requiring the two tables to be
//!   EQUAL. A table that took anything from a retained list would differ.
//!
//! The captures are laid by builders that write real packets (Ethernet, IPv4,
//! TCP or UDP, real checksums) and the dissection reads them through
//! `Dissection::from_capture`, the constructor the C doors call.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use wz_session_core::json5::{self, Json5Value};
use wz_session_core::passive::{Direction, SessionPhase};
use wz_session_core::wire_const;

use crate::datagram_tests::{fill_ipv4_checksum, fill_tcp_checksum, udp_packet, udp_packet_v6};
use crate::link::LINKTYPE_ETHERNET;
use crate::session_table::{session_table, Cell, Encryption, SessionRow, Unstated, Why};
use crate::session_table_json::{refusal_json, session_table_json, Refusal};
use crate::{Dissection, DissectionLimits};

/// What a door that reads a container under a ceiling writes: the table, or the
/// refusal of bytes that do not read.
fn session_table_document(bytes: &[u8], limits: DissectionLimits) -> String {
    match Dissection::from_capture_bounded(bytes, limits) {
        Ok(d) => session_table_json(&d),
        Err(error) => refusal_json(error),
    }
}

const ZID_A: [u8; 4] = [0xA1; 4];
const ZID_B: [u8; 4] = [0xB2; 4];
const ZID_C: [u8; 4] = [0xC3; 4];
const ZID_D: [u8; 4] = [0xD4; 4];

/// The pcap file's seconds and microseconds for an instant in nanoseconds. A
/// whole number of microseconds on purpose: the classic format this writes holds
/// no finer unit, and a fixture that needed one would be testing the writer.
fn secs_usecs(at_ns: u64) -> (u32, u32) {
    (
        (at_ns / 1_000_000_000) as u32,
        ((at_ns % 1_000_000_000) / 1_000) as u32,
    )
}

/// The packets of one capture, in file order, and the file they make.
#[derive(Default, Clone)]
struct Packets {
    rows: Vec<(u32, u32, Vec<u8>)>,
}

impl Packets {
    fn push(&mut self, at_ns: u64, packet: Vec<u8>) {
        let (s, u) = secs_usecs(at_ns);
        self.rows.push((s, u, packet));
    }

    fn file(&self) -> Vec<u8> {
        let refs: Vec<(u32, u32, &[u8])> = self
            .rows
            .iter()
            .map(|(s, u, p)| (*s, *u, p.as_slice()))
            .collect();
        crate::pcap::write(LINKTYPE_ETHERNET, &refs)
    }

    fn dissect(&self) -> Dissection {
        Dissection::from_capture(&self.file()).expect("the capture reads")
    }
}

// ── the messages ───────────────────────────────────────────────────────────

/// An Init naming `zid`: the InitSyn, or the InitAck with an empty cookie.
fn init(zid: &[u8], ack: bool) -> Vec<u8> {
    let mut wire = vec![
        wire_const::T_MID_INIT | if ack { 0x20 } else { 0 },
        0x09,
        (((zid.len() as u8) - 1) << 4) | 0x02,
    ];
    wire.extend_from_slice(zid);
    if ack {
        wire.push(0);
    }
    wire
}

fn open(ack: bool) -> Vec<u8> {
    if ack {
        vec![0x22, 10, 0]
    } else {
        vec![0x02, 10, 0, 0]
    }
}

fn keepalive() -> Vec<u8> {
    vec![wire_const::T_MID_KEEP_ALIVE]
}

fn close() -> Vec<u8> {
    vec![0x03, 1]
}

/// The two-byte little-endian length a stream link puts in front of a message.
fn stream_unit(wire: &[u8]) -> Vec<u8> {
    let mut out = (wire.len() as u16).to_le_bytes().to_vec();
    out.extend_from_slice(wire);
    out
}

// ── the links ──────────────────────────────────────────────────────────────

const LOW: [u8; 4] = [10, 0, 0, 1];
const HIGH: [u8; 4] = [10, 0, 0, 2];
const SERVER_PORT: u16 = 7447;

fn tcp_segment(
    src: [u8; 4],
    sport: u16,
    dst: [u8; 4],
    dport: u16,
    seq: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&dport.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes());
    tcp.push(5 << 4);
    tcp.push(0x10);
    tcp.extend_from_slice(&64u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(payload);
    fill_tcp_checksum(src, dst, &mut tcp);
    let mut ip = vec![0x45u8, 0];
    ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    fill_ipv4_checksum(&mut ip);
    ip.extend_from_slice(&tcp);
    let mut eth = vec![0u8; 12];
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&ip);
    while eth.len() < 60 {
        eth.push(0);
    }
    eth
}

/// One TCP connection: the dialler (a client port) and the acceptor (7447).
struct Tcp {
    dialer: [u8; 4],
    acceptor: [u8; 4],
    sport: u16,
    seq: [u32; 2],
    /// Bytes this connection put in its stream, both directions.
    wire_bytes: u64,
    /// Messages it carried.
    messages: u64,
}

impl Tcp {
    /// `dialer_low`: the dialling end is the endpoint that sorts LOW, so its
    /// direction is `A`. Both arrangements matter: a reader that took "the
    /// initiator is direction A" for a rule would pass one and fail the other.
    fn new(dialer_low: bool, sport: u16) -> Self {
        let (dialer, acceptor) = if dialer_low { (LOW, HIGH) } else { (HIGH, LOW) };
        Tcp {
            dialer,
            acceptor,
            sport,
            seq: [1000, 5000],
            wire_bytes: 0,
            messages: 0,
        }
    }

    fn send(&mut self, out: &mut Packets, at_ns: u64, from_dialer: bool, wire: &[u8]) {
        let unit = stream_unit(wire);
        let seat = usize::from(!from_dialer);
        let (src, sport, dst, dport) = if from_dialer {
            (self.dialer, self.sport, self.acceptor, SERVER_PORT)
        } else {
            (self.acceptor, SERVER_PORT, self.dialer, self.sport)
        };
        out.push(
            at_ns,
            tcp_segment(src, sport, dst, dport, self.seq[seat], &unit),
        );
        self.seq[seat] += unit.len() as u32;
        self.wire_bytes += unit.len() as u64;
        self.messages += 1;
    }

    /// The four messages of a handshake, one microsecond apart from `at_ns`.
    fn handshake(&mut self, out: &mut Packets, at_ns: u64, dialer: &[u8], acceptor: &[u8]) {
        self.send(out, at_ns, true, &init(dialer, false));
        self.send(out, at_ns + 1_000, false, &init(acceptor, true));
        self.send(out, at_ns + 2_000, true, &open(false));
        self.send(out, at_ns + 3_000, false, &open(true));
    }
}

/// One UDP unicast flow: the dialler and the acceptor on 7447, one message per
/// datagram.
struct Udp {
    dialer: [u8; 4],
    acceptor: [u8; 4],
    sport: u16,
    wire_bytes: u64,
    messages: u64,
}

impl Udp {
    fn new(dialer_low: bool, sport: u16) -> Self {
        let (dialer, acceptor) = if dialer_low { (LOW, HIGH) } else { (HIGH, LOW) };
        Udp {
            dialer,
            acceptor,
            sport,
            wire_bytes: 0,
            messages: 0,
        }
    }

    fn send(&mut self, out: &mut Packets, at_ns: u64, from_dialer: bool, wire: &[u8]) {
        let packet = if from_dialer {
            udp_packet(self.dialer, self.sport, self.acceptor, SERVER_PORT, wire)
        } else {
            udp_packet(self.acceptor, SERVER_PORT, self.dialer, self.sport, wire)
        };
        out.push(at_ns, packet);
        self.wire_bytes += wire.len() as u64;
        self.messages += 1;
    }

    fn handshake(&mut self, out: &mut Packets, at_ns: u64, dialer: &[u8], acceptor: &[u8]) {
        self.send(out, at_ns, true, &init(dialer, false));
        self.send(out, at_ns + 1_000, false, &init(acceptor, true));
        self.send(out, at_ns + 2_000, true, &open(false));
        self.send(out, at_ns + 3_000, false, &open(true));
    }
}

const T0: u64 = 1_700_000_000_000_000_000;

// ── the fixtures ───────────────────────────────────────────────────────────

/// A TCP session from its start: a handshake, `n` keep-alives alternating.
fn tcp_session(dialer_low: bool, n: u64) -> (Packets, Tcp) {
    let mut out = Packets::default();
    let mut tcp = Tcp::new(dialer_low, 43210);
    tcp.handshake(&mut out, T0, &ZID_A, &ZID_B);
    for i in 0..n {
        tcp.send(&mut out, T0 + 10_000 + i * 1_000, i % 2 == 0, &keepalive());
    }
    (out, tcp)
}

fn udp_session(dialer_low: bool, n: u64) -> (Packets, Udp) {
    let mut out = Packets::default();
    let mut udp = Udp::new(dialer_low, 43210);
    udp.handshake(&mut out, T0, &ZID_A, &ZID_B);
    for i in 0..n {
        udp.send(&mut out, T0 + 10_000 + i * 1_000, i % 2 == 0, &keepalive());
    }
    (out, udp)
}

/// A TCP flow joined after its handshake: keep-alives and nothing else.
fn midstream_tcp(n: u64) -> (Packets, Tcp) {
    let mut out = Packets::default();
    let mut tcp = Tcp::new(true, 43210);
    for i in 0..n {
        tcp.send(&mut out, T0 + i * 1_000, i % 2 == 0, &keepalive());
    }
    (out, tcp)
}

/// A TLS record: content type, legacy version, big-endian length.
fn tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![content_type, 0x03, 0x03];
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A ClientHello carrying `random`, well formed enough for the recogniser.
fn client_hello(random: &[u8; 32]) -> Vec<u8> {
    let mut body = vec![0x03u8, 0x03];
    body.extend_from_slice(random);
    body.resize(0x30, 0);
    let mut handshake = vec![0x01u8, 0x00, 0x00, body.len() as u8];
    handshake.extend_from_slice(&body);
    let mut out = vec![0x16, 0x03, 0x01];
    out.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    out.extend_from_slice(&handshake);
    out
}

/// A client-side TLS flow: a ClientHello, then one packet per record in
/// `records`, all from the client. Returns the packets.
fn tls_flow(records: &[Vec<u8>]) -> Packets {
    let mut out = Packets::default();
    let mut seq = 1000u32;
    let mut at = T0;
    let hello = client_hello(&[7u8; 32]);
    let all = core::iter::once(&hello).chain(records.iter());
    for bytes in all {
        out.push(at, tcp_segment(LOW, 43210, HIGH, SERVER_PORT, seq, bytes));
        seq += bytes.len() as u32;
        at += 1_000;
    }
    out
}

/// The opener a test needs: a record is `content_type || plaintext`, so opening
/// one is a slice.
struct SliceOpener;

impl crate::tls::RecordOpener for SliceOpener {
    fn begin_flow(
        &mut self,
        _client_random: Option<&[u8; 32]>,
        _client_direction: Option<Direction>,
    ) -> Result<(), crate::tls::NotDecrypted> {
        Ok(())
    }

    fn open(
        &mut self,
        _direction: Direction,
        record: &crate::tls::EncryptedRecord,
    ) -> Option<crate::tls::OpenedRecord> {
        let body = record.bytes.get(5..)?;
        Some(crate::tls::OpenedRecord {
            content_type: *body.first()?,
            plaintext: body[1..].to_vec(),
        })
    }

    fn has_keys(&self, _direction: Direction) -> bool {
        true
    }
}

/// A protected record whose plaintext is `unit`, as [`SliceOpener`] opens it.
fn protected(unit: &[u8]) -> Vec<u8> {
    let mut body = vec![crate::tls::CT_APPLICATION_DATA];
    body.extend_from_slice(unit);
    tls_record(crate::tls::CT_APPLICATION_DATA, &body)
}

/// A QUIC version-1 Initial long header, which is all the recogniser needs to
/// name a flow QUIC: the first byte, the version, two connection ids.
fn quic_initial() -> Vec<u8> {
    let mut p = vec![
        0xC0, 0, 0, 0, 1, 4, 1, 2, 3, 4, 4, 5, 6, 7, 8, 0, 0x40, 0x10,
    ];
    p.resize(64, 0);
    p
}

fn quic_flow() -> Dissection {
    let mut d = Dissection::new();
    d.push_packet_at_nanos(
        LINKTYPE_ETHERNET,
        0,
        Some(T0),
        &udp_packet(LOW, 4433, HIGH, SERVER_PORT, &quic_initial()),
    );
    d.finish();
    assert!(
        d.datagram_flows()[0].quic.is_some(),
        "the fixture must be a QUIC flow or it proves nothing"
    );
    d
}

fn only(table: &crate::session_table::SessionTable) -> &SessionRow {
    assert_eq!(table.rows.len(), 1, "one row was expected: {table:?}");
    &table.rows[0]
}

fn zid_text(zid: &[u8]) -> String {
    wz_session_core::zid_hex::zid_to_zenoh_hex(zid)
}

// ── the cells of a clear session ───────────────────────────────────────────

/// ONE CLEAR SESSION: every cell stated, and the totals are the fixture's own.
#[test]
fn a_clear_tcp_session_is_one_row_with_every_cell_stated() {
    let (packets, tcp) = tcp_session(true, 6);
    let d = packets.dissect();
    let table = session_table(&d);
    let row = only(&table);

    assert_eq!(
        row.initiator.clone(),
        Ok(ZID_A.to_vec()),
        "the InitSyn's sender"
    );
    assert_eq!(
        row.acceptor.clone(),
        Ok(ZID_B.to_vec()),
        "the InitAck's sender"
    );
    assert_eq!(row.link.map(|k| k.name()), Ok("tcp"));
    assert_eq!(row.phase, Ok(SessionPhase::Established));
    assert_eq!(row.encryption, Encryption::Clear);
    assert_eq!(row.first_seen_ns, Ok(T0));
    assert_eq!(row.last_seen_ns, Ok(T0 + 10_000 + 5 * 1_000));
    // The fixture counted these, not the library.
    assert_eq!(
        row.frames,
        Ok(tcp.messages),
        "four handshake messages and six keep-alives"
    );
    assert_eq!(row.bytes, tcp.wire_bytes);
    assert_eq!(table.excluded, Default::default());
}

/// THE INITIATOR IS THE INITSYN's SENDER, NOT DIRECTION A. With the dialler on
/// the high endpoint the InitSyn travels in direction B, and the acceptor sorts
/// low.
#[test]
fn the_initiator_is_the_initsyn_sender_whichever_end_sorts_first() {
    for dialer_low in [true, false] {
        let (packets, _) = tcp_session(dialer_low, 2);
        let d = packets.dissect();
        let table = session_table(&d);
        let row = only(&table);
        assert_eq!(
            row.initiator.clone(),
            Ok(ZID_A.to_vec()),
            "dialer_low={dialer_low}"
        );
        assert_eq!(
            row.acceptor.clone(),
            Ok(ZID_B.to_vec()),
            "dialer_low={dialer_low}"
        );
    }
}

#[test]
fn a_clear_udp_session_counts_every_datagram_and_its_payload() {
    let (packets, udp) = udp_session(false, 5);
    let d = packets.dissect();
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(row.link.map(|k| k.name()), Ok("udp"));
    assert_eq!(row.initiator.clone(), Ok(ZID_A.to_vec()));
    assert_eq!(row.acceptor.clone(), Ok(ZID_B.to_vec()));
    assert_eq!(row.phase, Ok(SessionPhase::Established));
    assert_eq!(row.frames, Ok(udp.messages));
    assert_eq!(
        row.bytes, udp.wire_bytes,
        "a datagram flow counts the UDP payload of every datagram, and a datagram \
         is its own framing unit"
    );
}

/// A CLOSE ends the session, and the row says so.
#[test]
fn a_close_makes_the_phase_closed() {
    let (mut packets, mut tcp) = tcp_session(true, 1);
    tcp.send(&mut packets, T0 + 100_000, true, &close());
    let d = packets.dissect();
    let table = session_table(&d);
    assert_eq!(only(&table).phase, Ok(SessionPhase::Closed));
}

// ── what a capture that does not hold the handshake says ──────────────────

/// A CAPTURE THAT BEGAN AFTER THE HANDSHAKE: the cells it cannot state are
/// `null` and each is named, with its reason, in `unstated`.
#[test]
fn a_flow_joined_after_the_handshake_states_what_it_can_and_no_more() {
    let (packets, tcp) = midstream_tcp(7);
    let d = packets.dissect();
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(row.initiator, Err(Unstated::NotInCapture));
    assert_eq!(row.acceptor, Err(Unstated::NotInCapture));
    assert_eq!(
        row.phase,
        Ok(SessionPhase::Unseen),
        "no Init was seen, so the phase is the observer's `unseen`"
    );
    assert_eq!(
        row.encryption,
        Encryption::Clear,
        "zenoh messages decoded from the flow's own bytes"
    );
    assert_eq!(row.frames, Ok(7));
    assert_eq!(row.bytes, tcp.wire_bytes);
    assert_eq!(row.first_seen_ns, Ok(T0));

    let doc = session_table_json(&d);
    assert!(
        doc.contains(
            "\"unstated\":[{\"cell\":\"initiator\",\"reason\":\"not_in_capture\"},\
             {\"cell\":\"acceptor\",\"reason\":\"not_in_capture\"}]"
        ),
        "{doc}"
    );
    assert!(
        doc.contains("\"initiator\":null,\"acceptor\":null"),
        "{doc}"
    );
}

/// ONE INIT ALONE: the end that spoke is named, in the role its flag says, and
/// the other end is not invented.
#[test]
fn a_lone_initsyn_names_the_initiator_and_leaves_the_acceptor_unstated() {
    let mut out = Packets::default();
    let mut tcp = Tcp::new(true, 43210);
    tcp.send(&mut out, T0, true, &init(&ZID_A, false));
    let d = out.dissect();
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(row.initiator.clone(), Ok(ZID_A.to_vec()));
    assert_eq!(row.acceptor, Err(Unstated::NotInCapture));
    assert_eq!(row.phase, Ok(SessionPhase::HalfInit));
}

/// A lone InitAck is the mirror: the acceptor is named and the initiator is the
/// cell that is not in the capture.
#[test]
fn a_lone_initack_names_the_acceptor_and_leaves_the_initiator_unstated() {
    let mut out = Packets::default();
    let mut tcp = Tcp::new(true, 43210);
    tcp.send(&mut out, T0, false, &init(&ZID_B, true));
    let d = out.dissect();
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(row.initiator, Err(Unstated::NotInCapture));
    assert_eq!(row.acceptor.clone(), Ok(ZID_B.to_vec()));
}

/// TWO INITSYNS AND NO INITACK, which a conforming peer never sends and a
/// hand-built capture does (the repository's own multilink fixtures are two): the
/// Inits name two nodes and do not say who dialled, so neither role is stated and
/// the reason is `mixed`. The PAIR is still known, which is what groups the two
/// links of that fixture into one row.
#[cfg(feature = "fixtures")]
#[test]
fn two_initsyns_contradict_the_roles_and_still_name_the_pair() {
    let (d, _file) = crate::fixtures::multilink_declaring_on_the_later_link();
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(row.initiator, Err(Unstated::Mixed));
    assert_eq!(row.acceptor, Err(Unstated::Mixed));
    assert_eq!(row.links.len(), 2, "two links, one session");
    // The node plane's own count of sessions: the same fixture is ONE session
    // there too.
    assert_eq!(crate::node::session_grouping(&d).sessions(), 1);
}

// ── a session is a pair of zids, not a flow ────────────────────────────────

/// TWO LINKS OF ONE SESSION are one row, with the totals summed, the earliest
/// first instant and the latest last one.
#[test]
fn two_links_of_one_session_are_one_row_with_summed_totals() {
    let mut out = Packets::default();
    let mut first = Tcp::new(true, 43210);
    let mut second = Tcp::new(true, 43211);
    first.handshake(&mut out, T0, &ZID_A, &ZID_B);
    second.handshake(&mut out, T0 + 50_000, &ZID_A, &ZID_B);
    first.send(&mut out, T0 + 60_000, true, &keepalive());
    second.send(&mut out, T0 + 70_000, false, &keepalive());
    let d = out.dissect();
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(row.links.len(), 2);
    assert_eq!(row.initiator.clone(), Ok(ZID_A.to_vec()));
    assert_eq!(row.acceptor.clone(), Ok(ZID_B.to_vec()));
    assert_eq!(row.link.map(|k| k.name()), Ok("tcp"));
    assert_eq!(row.frames, Ok(first.messages + second.messages));
    assert_eq!(row.bytes, first.wire_bytes + second.wire_bytes);
    assert_eq!(row.first_seen_ns, Ok(T0));
    assert_eq!(row.last_seen_ns, Ok(T0 + 70_000));
}

/// THE PAIR IS UNORDERED. The second link of a session may be dialled from the
/// other end; it is the same session, and the row says the initiator is `mixed`
/// because the two links disagree about who dialled.
#[test]
fn a_link_dialled_from_the_other_end_joins_the_session_and_the_initiator_is_mixed() {
    let mut out = Packets::default();
    let mut first = Tcp::new(true, 43210);
    let mut second = Tcp::new(true, 43211);
    first.handshake(&mut out, T0, &ZID_A, &ZID_B);
    // The second link is dialled by B: B sends the InitSyn.
    second.handshake(&mut out, T0 + 50_000, &ZID_B, &ZID_A);
    let d = out.dissect();
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(row.links.len(), 2);
    assert_eq!(row.initiator, Err(Unstated::Mixed));
    assert_eq!(row.acceptor, Err(Unstated::Mixed));
}

/// TWO SESSIONS ARE TWO ROWS, and a session over two kinds of link says `mixed`
/// for the link.
#[test]
fn different_pairs_are_different_rows_and_different_link_kinds_are_mixed() {
    let mut out = Packets::default();
    let mut a = Tcp::new(true, 43210);
    a.handshake(&mut out, T0, &ZID_A, &ZID_B);
    let mut b = Udp::new(true, 43212);
    b.handshake(&mut out, T0 + 10_000, &ZID_C, &ZID_D);
    // The first session also has a UDP link.
    let mut c = Udp::new(true, 43213);
    c.handshake(&mut out, T0 + 20_000, &ZID_A, &ZID_B);
    let d = out.dissect();
    let table = session_table(&d);
    assert_eq!(table.rows.len(), 2);
    let ab = &table.rows[0];
    assert_eq!(ab.initiator.clone(), Ok(ZID_A.to_vec()));
    assert_eq!(ab.links.len(), 2);
    assert_eq!(ab.link, Err(Unstated::Mixed));
    let cd = &table.rows[1];
    assert_eq!(cd.initiator.clone(), Ok(ZID_C.to_vec()));
    assert_eq!(cd.link.map(|k| k.name()), Ok("udp"));
}

// ── a closed session beside an open one ────────────────────────────────────

/// A SESSION IS CLOSED WHEN EVERY LINK OF IT IS: one link closing while another
/// carries on is not the session closing.
#[test]
fn a_session_with_one_link_closed_is_still_established() {
    let mut out = Packets::default();
    let mut first = Tcp::new(true, 43210);
    let mut second = Tcp::new(true, 43211);
    first.handshake(&mut out, T0, &ZID_A, &ZID_B);
    second.handshake(&mut out, T0 + 10_000, &ZID_A, &ZID_B);
    first.send(&mut out, T0 + 20_000, true, &close());
    let d = out.dissect();
    let table = session_table(&d);
    assert_eq!(only(&table).phase, Ok(SessionPhase::Established));

    second.send(&mut out, T0 + 30_000, true, &close());
    let d = out.dissect();
    let table = session_table(&d);
    assert_eq!(only(&table).phase, Ok(SessionPhase::Closed));
}

// ── the totals are totals ──────────────────────────────────────────────────

/// A CAPTURE BIGGER THAN THE RETENTION CAP: the table's totals count everything,
/// the retained list counts the cap, and the TWO TABLES ARE EQUAL.
///
/// The ceiling discards the OLDEST messages, and the Init is the oldest message
/// of a flow, so a table built from the retained list would lose the session's
/// identity here and report a count that stops growing at the cap. Equality of
/// the whole table is the strongest statement available: every cell, not only
/// the ones this test thought of.
#[test]
fn a_ceiling_that_discards_most_of_a_session_moves_nothing_in_its_row() {
    let (packets, tcp) = tcp_session(true, 200);
    let file = packets.file();
    let unbounded = Dissection::from_capture(&file).expect("reads");
    let limits = DissectionLimits {
        frames_per_flow: Some(4),
        stream_bytes_per_direction: Some(16),
        ..DissectionLimits::default()
    };
    let bounded = Dissection::from_capture_bounded(&file, limits).expect("reads");

    // The ceiling bit, and the retained list is the cap and not the total: this
    // is what makes the equality below mean something.
    assert_eq!(bounded.flows()[0].frames.len(), 4, "the cap holds");
    assert_eq!(bounded.flows()[0].frames.produced(), tcp.messages);
    assert!(bounded.drops().frames > 0 && bounded.drops().stream_bytes > 0);

    let want = session_table(&unbounded);
    let got = session_table(&bounded);
    assert_eq!(
        got, want,
        "no cell of the row may depend on what was retained"
    );
    let row = only(&got);
    assert_eq!(
        row.frames,
        Ok(tcp.messages),
        "204 messages, of which 4 are held"
    );
    assert_eq!(row.bytes, tcp.wire_bytes);
    assert_eq!(
        row.initiator.clone(),
        Ok(ZID_A.to_vec()),
        "the Init is long gone from the list"
    );
    assert_eq!(row.first_seen_ns, Ok(T0));
}

/// A RETRANSMITTED SEGMENT IS COUNTED ONCE, in bytes and in messages: the
/// assembler deduplicates, and the table counts what it delivered.
#[test]
fn a_retransmitted_segment_is_not_counted_twice() {
    let (mut packets, mut tcp) = tcp_session(true, 0);
    // The keep-alive from the dialler at its current sequence number, sent twice.
    let seq_before = tcp.seq[0];
    tcp.send(&mut packets, T0 + 10_000, true, &keepalive());
    let unit = stream_unit(&keepalive());
    packets.push(
        T0 + 11_000,
        tcp_segment(
            tcp.dialer,
            tcp.sport,
            tcp.acceptor,
            SERVER_PORT,
            seq_before,
            &unit,
        ),
    );
    let d = packets.dissect();
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(
        row.frames,
        Ok(tcp.messages),
        "five messages, one of them sent twice"
    );
    assert_eq!(row.bytes, tcp.wire_bytes);
}

/// A DUPLICATED DATAGRAM IS COUNTED TWICE: a datagram link has no sequence to
/// deduplicate by, so each arrival is a message and its payload is bytes.
#[test]
fn a_duplicated_datagram_counts_each_arrival() {
    let (mut packets, mut udp) = udp_session(true, 0);
    udp.send(&mut packets, T0 + 10_000, true, &keepalive());
    // The same bytes again, as the capture would hold a duplicated datagram.
    let again = udp_packet(
        udp.dialer,
        udp.sport,
        udp.acceptor,
        SERVER_PORT,
        &keepalive(),
    );
    packets.push(T0 + 11_000, again);
    udp.wire_bytes += keepalive().len() as u64;
    udp.messages += 1;
    let d = packets.dissect();
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(row.frames, Ok(udp.messages));
    assert_eq!(row.bytes, udp.wire_bytes);
}

/// A segment ARRIVING OUT OF ORDER is reassembled and counted once.
#[test]
fn an_out_of_order_segment_is_reassembled_and_counted_once() {
    let (mut packets, mut tcp) = tcp_session(true, 0);
    // Two keep-alives from the dialler, the second sent first.
    let a = stream_unit(&keepalive());
    let seq_a = tcp.seq[0];
    let seq_b = seq_a + a.len() as u32;
    packets.push(
        T0 + 10_000,
        tcp_segment(tcp.dialer, tcp.sport, tcp.acceptor, SERVER_PORT, seq_b, &a),
    );
    packets.push(
        T0 + 11_000,
        tcp_segment(tcp.dialer, tcp.sport, tcp.acceptor, SERVER_PORT, seq_a, &a),
    );
    tcp.messages += 2;
    tcp.wire_bytes += 2 * a.len() as u64;
    let d = packets.dissect();
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(row.frames, Ok(tcp.messages));
    assert_eq!(row.bytes, tcp.wire_bytes);
}

// ── the clock ──────────────────────────────────────────────────────────────

/// THE INSTANTS ARE THE MINIMUM AND THE MAXIMUM, not the first and the last in
/// file order: a capture written by several interfaces is not in time order.
#[test]
fn the_instants_are_the_earliest_and_the_latest_whatever_the_file_order() {
    let (mut packets, mut tcp) = tcp_session(true, 0);
    // A packet written LAST that happened FIRST.
    tcp.send(&mut packets, T0 - 5_000, true, &keepalive());
    let d = packets.dissect();
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(row.first_seen_ns, Ok(T0 - 5_000));
    assert_eq!(row.last_seen_ns, Ok(T0 + 3_000));
}

/// A CAPTURE WITH NO CLOCK: the two instants are `null` and the reason is
/// `no_clock`, which is a different fact from a flow that was never seen.
#[test]
fn packets_with_no_timestamp_leave_both_instants_unstated() {
    let mut d = Dissection::new();
    let mut tcp = Tcp::new(true, 43210);
    let mut out = Packets::default();
    tcp.handshake(&mut out, T0, &ZID_A, &ZID_B);
    for (i, (_, _, packet)) in out.rows.iter().enumerate() {
        d.push_packet(LINKTYPE_ETHERNET, i, packet);
    }
    d.finish();
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(row.first_seen_ns, Err(Unstated::NoClock));
    assert_eq!(row.last_seen_ns, Err(Unstated::NoClock));
    assert_eq!(
        row.phase,
        Ok(SessionPhase::Established),
        "the clock is not the session"
    );
    let doc = session_table_json(&d);
    assert!(
        doc.contains("\"first_seen_ts_ns\":null,\"last_seen_ts_ns\":null"),
        "{doc}"
    );
    assert!(
        doc.contains(
            "{\"cell\":\"first_seen_ts_ns\",\"reason\":\"no_clock\"},\
             {\"cell\":\"last_seen_ts_ns\",\"reason\":\"no_clock\"}"
        ),
        "{doc}"
    );
}

/// THE INTEGER RULE: a nanosecond clock is past 2^53, so an instant is a STRING
/// of its digits, and a small one is a bare number.
#[test]
fn an_instant_past_two_to_the_53_is_a_string() {
    let (packets, _) = tcp_session(true, 0);
    let doc = session_table_json(&packets.dissect());
    assert!(
        doc.contains(&alloc::format!("\"first_seen_ts_ns\":\"{T0}\"")),
        "an instant of 1.7e18 is a string: {doc}"
    );
    // And a small one is a number: a file stamped near the epoch.
    let mut small = Packets::default();
    let mut tcp = Tcp::new(true, 43210);
    tcp.send(&mut small, 5_000_000, true, &keepalive());
    let doc = session_table_json(&small.dissect());
    assert!(doc.contains("\"first_seen_ts_ns\":5000000,"), "{doc}");
}

// ── encryption ─────────────────────────────────────────────────────────────

/// A TLS FLOW WITH NO KEYS: `encrypted_unreadable`, and the row states what it
/// can. The bytes are counted (they are ciphertext, and they are real), the
/// messages and the phase are not stated, and the identity is encrypted.
#[test]
fn a_tls_flow_is_encrypted_unreadable_and_states_its_bytes_and_nothing_inside() {
    let records = vec![
        tls_record(0x16, &[0x02, 0x00, 0x00, 0x28]),
        tls_record(crate::tls::CT_APPLICATION_DATA, &[0xAB; 40]),
        tls_record(crate::tls::CT_APPLICATION_DATA, &[0xCD; 800]),
    ];
    let packets = tls_flow(&records);
    let want_bytes: u64 =
        (client_hello(&[7u8; 32]).len() + records.iter().map(Vec::len).sum::<usize>()) as u64;
    let d = packets.dissect();
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(row.encryption, Encryption::EncryptedUnreadable);
    assert_eq!(row.initiator, Err(Unstated::Encrypted));
    assert_eq!(row.acceptor, Err(Unstated::Encrypted));
    assert_eq!(row.phase, Err(Unstated::Encrypted));
    assert_eq!(row.frames, Err(Unstated::Encrypted));
    assert_eq!(
        row.bytes, want_bytes,
        "ciphertext is real traffic and is counted"
    );
    assert_eq!(row.link.map(|k| k.name()), Ok("tcp"));
    assert_eq!(
        row.first_seen_ns,
        Ok(T0),
        "the clock does not depend on the content"
    );

    let doc = session_table_json(&d);
    for cell in ["initiator", "acceptor", "phase", "frames"] {
        assert!(
            doc.contains(&alloc::format!(
                "{{\"cell\":\"{cell}\",\"reason\":\"encrypted\"}}"
            )),
            "{cell}: {doc}"
        );
    }
}

/// A TLS FLOW THAT WAS DECRYPTED BEFORE THE TABLE WAS ASKED FOR: the session
/// inside is read, and the finding is `decrypted_tls`. The doors of this library
/// do not decrypt, so this is a dissection a caller prepared.
#[test]
fn a_decrypted_tls_flow_states_the_session_inside_it() {
    let client = |wire: &[u8]| protected(&stream_unit(wire));
    let records = vec![
        client(&init(&ZID_A, false)),
        client(&open(false)),
        client(&keepalive()),
    ];
    let packets = tls_flow(&records);
    let mut d = packets.dissect();
    let before = session_table(&d);
    assert_eq!(
        only(&before).encryption,
        Encryption::EncryptedUnreadable,
        "before: ciphertext"
    );

    d.decrypt_with(&mut SliceOpener);
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(row.encryption, Encryption::DecryptedTls);
    assert_eq!(row.frames, Ok(3), "an InitSyn, an OpenSyn and a keep-alive");
    assert_eq!(row.initiator.clone(), Ok(ZID_A.to_vec()));
    assert_eq!(
        row.acceptor,
        Err(Unstated::NotInCapture),
        "the acceptor never spoke"
    );
    assert!(row.phase.is_ok());
    assert_eq!(
        row.bytes,
        packets.dissect().flows()[0].residue().recovered,
        "the bytes of the flow are the ciphertext, decrypted or not"
    );
}

/// A QUIC FLOW NOBODY DECRYPTED is encrypted and unreadable; one whose streams
/// were recovered by a caller is `decrypted_quic`, and its session is read from
/// them.
#[test]
fn a_quic_flow_is_unreadable_until_a_caller_recovers_its_streams() {
    let mut d = quic_flow();
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(row.encryption, Encryption::EncryptedUnreadable);
    assert_eq!(row.link.map(|k| k.name()), Ok("udp"));
    assert_eq!(row.bytes, quic_initial().len() as u64);
    assert_eq!(row.frames, Err(Unstated::Encrypted));

    let flow = d.datagram_flows()[0].flow;
    d.feed_quic_stream(
        flow,
        Direction::A,
        0,
        false,
        &stream_unit(&init(&ZID_A, false)),
    );
    d.feed_quic_stream(
        flow,
        Direction::B,
        0,
        false,
        &stream_unit(&init(&ZID_B, true)),
    );
    d.feed_quic_stream(flow, Direction::A, 0, false, &stream_unit(&open(false)));
    d.feed_quic_stream(flow, Direction::B, 0, false, &stream_unit(&open(true)));
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(row.encryption, Encryption::DecryptedQuic);
    assert_eq!(row.initiator.clone(), Ok(ZID_A.to_vec()));
    assert_eq!(row.acceptor.clone(), Ok(ZID_B.to_vec()));
    assert_eq!(row.phase, Ok(SessionPhase::Established));
    assert_eq!(row.frames, Ok(4));
    assert_eq!(
        row.bytes,
        quic_initial().len() as u64,
        "the bytes of the flow are the UDP payload"
    );
}

/// A FLOW WITH BYTES AND NOTHING DECODED, and nothing that says it is encrypted:
/// `unknown`. It may be zenoh this reader could not read, or something else.
#[test]
fn a_flow_that_decodes_nothing_and_is_not_encrypted_is_unknown() {
    let mut out = Packets::default();
    out.push(
        T0,
        udp_packet(LOW, 5000, HIGH, 5001, &[0xFF, 0xEE, 0xDD, 0xCC]),
    );
    let d = out.dissect();
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(row.encryption, Encryption::Unknown);
    // Four junk bytes decode to ONE message of a MID this build does not know,
    // which the reader produced and did not understand: it is counted as a
    // message and it is not evidence that the bytes are zenoh.
    assert_eq!(row.frames, Ok(1));
    assert_eq!(row.bytes, 4);
    let kinds: Vec<&str> = d.datagram_flows()[0]
        .frames
        .iter()
        .filter_map(|f| f.frame.as_ref().ok().map(|k| k.kind_name()))
        .collect();
    assert_eq!(
        kinds,
        vec!["Unknown"],
        "the fixture is the Unknown the premise says"
    );
}

// ── flows that are not rows ────────────────────────────────────────────────

/// A MULTICAST GROUP HAS NO PAIR and is not a row: it is counted, with its
/// reason. A peer's Join names the sender only; the listeners are not named.
#[test]
fn a_multicast_group_is_counted_and_is_not_a_row() {
    let mut out = Packets::default();
    // Two transport messages to the scouting group's address: the destination
    // has no handshake, whatever the message is.
    for i in 0..2 {
        out.push(
            T0 + i * 1_000,
            udp_packet([10, 0, 0, 1], 7447, [224, 0, 0, 224], 7447, &keepalive()),
        );
    }
    let d = out.dissect();
    assert!(d.datagram_flows()[0].ingest.handshake_absent());
    let table = session_table(&d);
    assert!(table.rows.is_empty(), "{table:?}");
    assert_eq!(table.excluded.multicast_group, 1);
    assert_eq!(table.excluded.scouting_only, 0);
}

/// A FLOW THAT CARRIED ONLY DISCOVERY is counted, and a unicast answer to a
/// scout is one.
#[test]
fn a_flow_of_scouting_only_is_counted_and_is_not_a_row() {
    let mut out = Packets::default();
    out.push(
        T0,
        udp_packet(
            [10, 0, 0, 1],
            5000,
            [224, 0, 0, 224],
            7446,
            &crate::datagram_tests::scout_message(),
        ),
    );
    let d = out.dissect();
    let table = session_table(&d);
    assert!(table.rows.is_empty(), "{table:?}");
    assert_eq!(table.excluded.scouting_only, 1);
    assert_eq!(table.excluded.multicast_group, 0);
}

/// THE REPOSITORY'S RASWETH SAMPLE: pico's raweth link never has a handshake,
/// so its flow is a multicast group by the dissector's own rule.
#[test]
fn the_raweth_sample_has_no_session_rows() {
    let file = include_bytes!("../../../captures/raweth-transport-messages.pcap");
    let d = Dissection::from_capture(file).expect("reads");
    let table = session_table(&d);
    assert!(table.rows.is_empty(), "{table:?}");
    assert_eq!(table.excluded.multicast_group, 1);
}

// ── the serial line ────────────────────────────────────────────────────────

const SERIAL_LINKTYPE: u32 = 250;

/// A serial line: a link-level handshake, two Inits (the first interface to send
/// the bare INIT is the initiator), a keep-alive. Written through the repository's
/// own encoder, declared by link type.
fn serial_dissection() -> Dissection {
    use wz_session_core::serial_link::{encode_frame, SERIAL_FLAG_ACK, SERIAL_FLAG_INIT};
    let frames: Vec<(u32, Vec<u8>)> = vec![
        (0, encode_frame(SERIAL_FLAG_INIT, &[]).expect("encodes")),
        (
            1,
            encode_frame(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, &[]).expect("encodes"),
        ),
        (0, encode_frame(0, &init(&ZID_A, false)).expect("encodes")),
        (1, encode_frame(0, &init(&ZID_B, true)).expect("encodes")),
        (0, encode_frame(0, &keepalive()).expect("encodes")),
    ];
    let packets: Vec<(u32, u64, &[u8])> = frames
        .iter()
        .enumerate()
        .map(|(i, (iface, bytes))| (*iface, 1_000_000 + i as u64 * 100, bytes.as_slice()))
        .collect();
    let file = crate::pcapng::write(&[(SERIAL_LINKTYPE, 6), (SERIAL_LINKTYPE, 6)], &packets);
    Dissection::from_capture_declaring(&file, &[], &[SERIAL_LINKTYPE]).expect("reads")
}

/// A SERIAL LINE is one row: it has no addresses and so no flow to group, and its
/// handshake names both ends like any other.
#[test]
fn a_serial_line_is_one_row() {
    let d = serial_dissection();
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(row.link.map(|k| k.name()), Ok("serial"));
    assert_eq!(row.initiator.clone(), Ok(ZID_A.to_vec()));
    assert_eq!(row.acceptor.clone(), Ok(ZID_B.to_vec()));
    assert_eq!(
        row.frames,
        Ok(3),
        "two Inits and a keep-alive; the link-level handshake is not a zenoh message"
    );
    assert_eq!(row.encryption, Encryption::Clear);
    assert_eq!(row.bytes, d.serial_census().expect("a line").bytes as u64);
    assert!(
        row.first_seen_ns.is_ok(),
        "the serial path keeps the instant it used to discard"
    );
    assert_eq!(
        row.first_seen_ns,
        Ok(1_000_000 * 1_000),
        "pcapng ticks of 1 microsecond"
    );
}

// ── the document ───────────────────────────────────────────────────────────

/// Walk the document the way a consumer does.
fn parse(doc: &str) -> Json5Value {
    json5::parse(doc).unwrap_or_else(|e| panic!("the document is JSON: {e:?}\n{doc}"))
}

fn array<'a>(value: &'a Json5Value, path: &str) -> &'a [Json5Value] {
    match value.get(path) {
        Some(Json5Value::Array(items)) => items,
        other => panic!("{path} is not an array: {other:?}"),
    }
}

fn text<'a>(value: &'a Json5Value, path: &str) -> &'a str {
    match value.get(path) {
        Some(Json5Value::String(s)) => s,
        other => panic!("{path} is not a string: {other:?}"),
    }
}

fn is_null(value: &Json5Value, path: &str) -> bool {
    matches!(value.get(path), Some(Json5Value::Null))
}

/// THE DOCUMENT OF ONE CLEAR SESSION, read key by key.
#[test]
fn a_row_carries_every_key_and_the_cells_a_consumer_maps() {
    let (packets, tcp) = tcp_session(true, 2);
    let doc = session_table_json(&packets.dissect());
    let v = parse(&doc);
    assert_eq!(text(&v, "document/name"), "session_table");
    assert_eq!(v.get("ok"), Some(&Json5Value::Bool(true)));
    let rows = array(&v, "sessions");
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(text(row, "initiator"), zid_text(&ZID_A));
    assert_eq!(text(row, "acceptor"), zid_text(&ZID_B));
    assert_eq!(text(row, "link"), "tcp");
    assert_eq!(text(row, "phase"), "established");
    assert_eq!(text(row, "encrypted"), "clear");
    assert_eq!(
        row.get("frames"),
        Some(&Json5Value::Number(tcp.messages.to_string()))
    );
    assert_eq!(
        row.get("bytes"),
        Some(&Json5Value::Number(tcp.wire_bytes.to_string()))
    );
    assert!(array(row, "unstated").is_empty(), "every cell is stated");
    assert_eq!(array(row, "flows").len(), 1);
    // The flow object is the one every other document carries, with its own
    // `link` word: a consumer that joins reads it from here.
    let flow = &array(row, "flows")[0];
    assert_eq!(text(flow, "flow/link"), "tcp");
    assert_eq!(text(flow, "encrypted"), "clear");
    // The excluded array always names both reasons.
    let excluded = array(&v, "excluded");
    let whys: Vec<&str> = excluded.iter().map(|e| text(e, "why")).collect();
    let want: Vec<&str> = Why::all().iter().map(|w| w.name()).collect();
    assert_eq!(whys, want);
}

/// A cell is `null` EXACTLY WHEN `unstated` names it, in every row of every
/// fixture, and the reason it gives is one that cell can carry.
#[test]
fn a_cell_is_null_exactly_when_unstated_names_it_and_the_reason_is_one_it_can_carry() {
    let mut checked = 0usize;
    let mut reasons_seen: Vec<String> = Vec::new();
    for (name, doc) in every_fixture_document() {
        let v = parse(&doc);
        for row in array(&v, "sessions") {
            let named: BTreeMap<&str, &str> = array(row, "unstated")
                .iter()
                .map(|u| (text(u, "cell"), text(u, "reason")))
                .collect();
            for cell in Cell::all() {
                let null = is_null(row, cell.key());
                match named.get(cell.key()) {
                    Some(reason) => {
                        assert!(
                            null,
                            "{name}: {} is named unstated but carries a value",
                            cell.key()
                        );
                        assert!(
                            cell.reasons().iter().any(|r| r.name() == *reason),
                            "{name}: {} cannot carry {reason}",
                            cell.key()
                        );
                        reasons_seen.push((*reason).to_string());
                    }
                    None => assert!(
                        !null,
                        "{name}: {} is null and no unstated entry names it",
                        cell.key()
                    ),
                }
                checked += 1;
            }
            // Every key is present on every row, null or not.
            for key in [
                "initiator",
                "acceptor",
                "link",
                "phase",
                "encrypted",
                "first_seen_ts_ns",
                "last_seen_ts_ns",
                "frames",
                "bytes",
                "unstated",
                "flows",
            ] {
                assert!(row.get(key).is_some(), "{name}: row lacks {key}");
            }
        }
    }
    assert!(
        checked >= 7 * 10,
        "the population must be rows and not an empty loop: {checked}"
    );
    reasons_seen.sort();
    reasons_seen.dedup();
    assert_eq!(
        reasons_seen,
        Unstated::names(),
        "the fixtures must reach every reason word, or a word is declared that nothing measured"
    );
}

// ── refusals ───────────────────────────────────────────────────────────────

fn refusal_of(bytes: &[u8]) -> String {
    let doc = session_table_document(bytes, DissectionLimits::default());
    let v = parse(&doc);
    assert_eq!(v.get("ok"), Some(&Json5Value::Bool(false)), "{doc}");
    assert!(
        v.get("sessions").is_none(),
        "a refusal carries no rows: {doc}"
    );
    assert_eq!(text(&v, "document/name"), "session_table");
    text(&v, "refusal").to_string()
}

#[test]
fn a_container_that_does_not_read_is_a_refusal_with_a_closed_reason() {
    assert_eq!(
        refusal_of(b"this is not a capture at all, nor close"),
        "not_a_capture"
    );
    assert_eq!(refusal_of(&[]), "truncated");
    let (packets, _) = tcp_session(true, 3);
    let file = packets.file();
    assert_eq!(
        refusal_of(&file[..file.len() - 5]),
        "truncated",
        "cut inside the last record"
    );
    assert_eq!(
        refusal_of(&file[..10]),
        "truncated",
        "cut inside the file header"
    );
    let mut ng = crate::pcapng::write(
        &[(LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000, packets.rows[0].2.as_slice())],
    );
    // The section header's trailing length disagrees with its leading one.
    ng[24..28].copy_from_slice(&0xFFFFu32.to_le_bytes());
    assert_eq!(refusal_of(&ng), "damaged");
}

/// THE SAME FILE, UNCUT, READS: so each refusal above is the cut and not the
/// fixture.
#[test]
fn the_uncut_file_is_not_refused() {
    let (packets, _) = tcp_session(true, 3);
    let doc = session_table_document(&packets.file(), DissectionLimits::default());
    assert!(doc.contains("\"ok\":true"), "{doc}");
}

/// THE REFUSAL WORDS ARE THE READERS' ERRORS, ALL OF THEM: the mapping is
/// exhaustive, so this walks one example of every variant and asks which word it
/// is.
#[test]
fn every_reader_error_maps_to_one_of_the_three_words() {
    use crate::pcap::PcapError;
    use crate::pcapng::PcapngError;
    use crate::CaptureError;
    let errors = [
        CaptureError::Pcap(PcapError::TruncatedFileHeader),
        CaptureError::Pcap(PcapError::BadMagic(0)),
        CaptureError::Pcap(PcapError::LooksLikePcapNg),
        CaptureError::Pcap(PcapError::TruncatedRecordHeader { index: 0 }),
        CaptureError::Pcap(PcapError::TruncatedRecord {
            index: 0,
            claimed: 1,
            available: 0,
        }),
        CaptureError::Pcapng(PcapngError::Truncated { offset: 0 }),
        CaptureError::Pcapng(PcapngError::NotPcapng { found: 0 }),
        CaptureError::Pcapng(PcapngError::BadByteOrderMagic { found: 0 }),
        CaptureError::Pcapng(PcapngError::BadBlockLength {
            offset: 0,
            claimed: 0,
        }),
        CaptureError::Pcapng(PcapngError::LengthMismatch {
            offset: 0,
            leading: 0,
            trailing: 1,
        }),
        CaptureError::Pcapng(PcapngError::UnknownInterface {
            index: 0,
            interface_id: 0,
        }),
        CaptureError::Pcapng(PcapngError::BadCapturedLength {
            index: 0,
            claimed: 0,
            available: 0,
        }),
        CaptureError::Pcapng(PcapngError::SimplePacketWithoutInterface { index: 0 }),
    ];
    let mut seen: Vec<&str> = errors.iter().map(|e| Refusal::of(*e).name()).collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(
        seen,
        Refusal::names(),
        "every word is reached by some error"
    );
}

// ── the corpus ─────────────────────────────────────────────────────────────

/// Every fixture above that can be built through the file door, as `(name,
/// dissection, file)`, plus the repository's own sample captures.
fn corpus() -> Vec<(String, Dissection, Vec<u8>)> {
    let mut out: Vec<(String, Dissection, Vec<u8>)> = Vec::new();
    let mut add = |name: &str, packets: &Packets| {
        let file = packets.file();
        out.push((
            name.to_string(),
            Dissection::from_capture(&file).expect("reads"),
            file,
        ));
    };
    add("tcp clear, dialer low", &tcp_session(true, 6).0);
    add("tcp clear, dialer high", &tcp_session(false, 6).0);
    add("udp clear, dialer low", &udp_session(true, 6).0);
    add("udp clear, dialer high", &udp_session(false, 6).0);
    add("tcp mid-stream", &midstream_tcp(5).0);
    add(
        "tls unreadable",
        &tls_flow(&[tls_record(crate::tls::CT_APPLICATION_DATA, &[1; 30])]),
    );
    {
        let mut p = Packets::default();
        let mut a = Tcp::new(true, 43210);
        a.handshake(&mut p, T0, &ZID_A, &ZID_B);
        let mut b = Udp::new(true, 43212);
        b.handshake(&mut p, T0 + 10_000, &ZID_C, &ZID_D);
        let mut c = Udp::new(true, 43213);
        c.handshake(&mut p, T0 + 20_000, &ZID_A, &ZID_B);
        let mut lone = Tcp::new(false, 43214);
        lone.send(&mut p, T0 + 30_000, true, &init(&ZID_D, false));
        add("several sessions, several kinds", &p);
    }
    {
        let mut p = Packets::default();
        p.push(
            T0,
            udp_packet(LOW, 4433, HIGH, SERVER_PORT, &quic_initial()),
        );
        add("quic unreadable", &p);
    }
    {
        let mut p = Packets::default();
        let mut v6 = Packets::default();
        let src = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        v6.push(
            T0,
            udp_packet_v6(src, 43210, dst, SERVER_PORT, &init(&ZID_A, false)),
        );
        v6.push(
            T0 + 1_000,
            udp_packet_v6(dst, SERVER_PORT, src, 43210, &init(&ZID_B, true)),
        );
        p.rows.extend(v6.rows);
        add("udp over ipv6", &p);
    }
    for (name, bytes) in [
        (
            "sample: compressed session",
            &include_bytes!("../../../captures/compressed-session-refused-body.pcap")[..],
        ),
        (
            "sample: fragmented",
            &include_bytes!("../../../captures/fragmented-push-midsession-and-established.pcap")[..],
        ),
        (
            "sample: publisher",
            &include_bytes!("../../../captures/publisher-priority-encoding-timestamp.pcap")[..],
        ),
        (
            "sample: raweth",
            &include_bytes!("../../../captures/raweth-transport-messages.pcap")[..],
        ),
        (
            "sample: scouting",
            &include_bytes!("../../../captures/scout-and-hello-ipv4-ipv6.pcap")[..],
        ),
    ] {
        out.push((
            name.to_string(),
            Dissection::from_capture(bytes).expect("reads"),
            bytes.to_vec(),
        ));
    }
    #[cfg(feature = "fixtures")]
    {
        let (d, file) = crate::fixtures::multilink_declaring_on_the_later_link();
        out.push(("fixture: multilink".to_string(), d, file));
        let (d, file) = crate::fixtures::multilink_declaring_after_the_reference();
        out.push(("fixture: multilink, declared after".to_string(), d, file));
    }
    out
}

/// The documents of every fixture the file door can build, and of the ones a
/// caller prepares (decrypted TLS and QUIC, a serial line).
fn every_fixture_document() -> Vec<(String, String)> {
    let mut docs: Vec<(String, String)> = corpus()
        .iter()
        .map(|(name, d, _)| (name.clone(), session_table_json(d)))
        .collect();
    docs.push((
        "serial".to_string(),
        session_table_json(&serial_dissection()),
    ));
    docs.push((
        "decrypted tls".to_string(),
        session_table_json(&decrypted_tls()),
    ));
    docs.push((
        "decrypted quic".to_string(),
        session_table_json(&decrypted_quic()),
    ));
    docs.push(("no clock".to_string(), session_table_json(&no_clock())));
    docs.push(("mixed".to_string(), session_table_json(&mixed_roles())));
    docs
}

fn decrypted_tls() -> Dissection {
    let client = |wire: &[u8]| protected(&stream_unit(wire));
    let packets = tls_flow(&[client(&init(&ZID_A, false)), client(&keepalive())]);
    let mut d = packets.dissect();
    d.decrypt_with(&mut SliceOpener);
    d
}

fn decrypted_quic() -> Dissection {
    let mut d = quic_flow();
    let flow = d.datagram_flows()[0].flow;
    d.feed_quic_stream(
        flow,
        Direction::A,
        0,
        false,
        &stream_unit(&init(&ZID_A, false)),
    );
    d.feed_quic_stream(
        flow,
        Direction::B,
        0,
        false,
        &stream_unit(&init(&ZID_B, true)),
    );
    d
}

fn no_clock() -> Dissection {
    let mut d = Dissection::new();
    let mut tcp = Tcp::new(true, 43210);
    let mut out = Packets::default();
    tcp.handshake(&mut out, T0, &ZID_A, &ZID_B);
    for (i, (_, _, packet)) in out.rows.iter().enumerate() {
        d.push_packet(LINKTYPE_ETHERNET, i, packet);
    }
    d.finish();
    d
}

fn mixed_roles() -> Dissection {
    let mut out = Packets::default();
    let mut first = Tcp::new(true, 43210);
    let mut second = Tcp::new(true, 43211);
    first.handshake(&mut out, T0, &ZID_A, &ZID_B);
    second.handshake(&mut out, T0 + 50_000, &ZID_B, &ZID_A);
    out.dissect()
}

/// The population the carries gate renders: every fixture's document, and a
/// refusal of each kind.
pub(crate) fn documents_for_the_carries_gate() -> Vec<String> {
    let mut docs: Vec<String> = every_fixture_document()
        .into_iter()
        .map(|(_, d)| d)
        .collect();
    let (packets, _) = tcp_session(true, 2);
    let file = packets.file();
    docs.push(session_table_document(
        b"not a capture, and not close to one",
        DissectionLimits::default(),
    ));
    docs.push(session_table_document(
        &file[..file.len() - 5],
        DissectionLimits::default(),
    ));
    let mut ng = crate::pcapng::write(
        &[(LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000, packets.rows[0].2.as_slice())],
    );
    ng[24..28].copy_from_slice(&0xFFFFu32.to_le_bytes());
    docs.push(session_table_document(&ng, DissectionLimits::default()));
    docs
}

// ── the oracle: the census and the field document ──────────────────────────

fn flow_object(entry: &Json5Value) -> &Json5Value {
    entry.get("flow").expect("a flow entry carries its flow")
}

/// EVERY ROW AGREES WITH THE CENSUS AND THE FIELD DOCUMENT, for every capture in
/// the corpus.
///
/// * every flow of a row is a flow the field document lists, with the same link
///   word, and for a row of one readable flow the same phase word;
/// * the census's links, read out of its document, name the same pair of zids a
///   row names, and every census link's flow is inside a row that names them;
/// * the number of sessions the census's links come to equals the number of rows
///   that name both ends, so grouping is the census's grouping;
/// * the initiator is the zid the census gives the direction that sent the
///   InitSyn, found in the records themselves;
/// * `dropped_by_limits` is the group the census carries, from the one emitter;
/// * the totals equal what the retained lists and assemblers hold, which on an
///   unbounded read is everything.
#[test]
fn every_row_agrees_with_the_census_and_the_field_document() {
    let mut rows_checked = 0usize;
    let mut census_links_checked = 0usize;
    let mut phases_checked = 0usize;
    let mut initiators_checked = 0usize;
    for (name, d, file) in corpus() {
        let table_doc = parse(&session_table_json(&d));
        let census = parse(&crate::census_json::census_json(&d));
        let fields = parse(&crate::fields_json::fields_json(&d, &file, None, None));
        let rows = array(&table_doc, "sessions");

        // The field document's flows, both tables, by their flow object.
        let field_flows: Vec<&Json5Value> = array(&fields, "stream_flows")
            .iter()
            .chain(array(&fields, "datagram_flows").iter())
            .collect();
        let find_field = |flow: &Json5Value| -> Option<&Json5Value> {
            field_flows.iter().copied().find(|f| flow_object(f) == flow)
        };

        let nodes = array(&census, "nodes/nodes");
        let links = array(&census, "nodes/links");
        let zid_of = |index: &Json5Value| -> String {
            let Json5Value::Number(n) = index else {
                panic!("a node index")
            };
            let at: usize = n.parse().expect("an index");
            text(&nodes[at], "zid").to_string()
        };

        // 1. flows, link words and phase against the field document.
        for row in rows {
            rows_checked += 1;
            let flows = array(row, "flows");
            for flow in flows {
                let object = flow.get("flow").expect("a flow object");
                let field = find_field(object)
                    .unwrap_or_else(|| panic!("{name}: a row's flow is not in the field document"));
                assert_eq!(
                    text(flow, "flow/link"),
                    text(field, "flow/link"),
                    "{name}: the link word"
                );
                if flows.len() == 1 && !is_null(row, "phase") {
                    assert_eq!(
                        text(row, "phase"),
                        text(field, "context/phase"),
                        "{name}: the phase word, as `context.phase` says it"
                    );
                    phases_checked += 1;
                }
                if text(row, "encrypted") == "encrypted_unreadable" {
                    assert!(
                        is_null(row, "phase"),
                        "{name}: an unreadable flow states no phase"
                    );
                }
            }
            if flows.len() == 1 {
                assert_eq!(
                    text(row, "link"),
                    text(flows.first().unwrap(), "flow/link"),
                    "{name}"
                );
            }
        }

        // 2. the census's links against the rows' pairs.
        let mut census_pairs: Vec<(String, String)> = Vec::new();
        for link in links {
            census_links_checked += 1;
            let (a, b) = (
                zid_of(link.get("a").unwrap()),
                zid_of(link.get("b").unwrap()),
            );
            let flow = link.get("flow").expect("a link carries its flow");
            let row = rows
                .iter()
                .find(|r| {
                    array(r, "flows")
                        .iter()
                        .any(|f| f.get("flow") == Some(flow))
                })
                .unwrap_or_else(|| panic!("{name}: a census link's flow is in no row"));
            let (i, c) = (
                (!is_null(row, "initiator")).then(|| text(row, "initiator").to_string()),
                (!is_null(row, "acceptor")).then(|| text(row, "acceptor").to_string()),
            );
            if let (Some(i), Some(c)) = (&i, &c) {
                let mut pair = [i.clone(), c.clone()];
                let mut want = [a.clone(), b.clone()];
                pair.sort();
                want.sort();
                assert_eq!(
                    pair, want,
                    "{name}: the pair a row names is the pair the census link names"
                );
                initiators_checked += 1;
            }
            let mut key = [a, b];
            key.sort();
            let key = (key[0].clone(), key[1].clone());
            if !census_pairs.contains(&key) {
                census_pairs.push(key);
            }
        }
        // Rows grouped under a known pair: every census pair is ONE row. The
        // census counts a link where both ends sent an Init, and so does the
        // table, so the two numbers are the same number.
        let rows_per_pair: usize = census_pairs
            .iter()
            .map(|(x, y)| {
                rows.iter()
                    .filter(|r| {
                        array(r, "flows").iter().any(|f| {
                            links.iter().any(|l| {
                                l.get("flow") == f.get("flow") && {
                                    let mut p =
                                        [zid_of(l.get("a").unwrap()), zid_of(l.get("b").unwrap())];
                                    p.sort();
                                    (p[0].clone(), p[1].clone()) == (x.clone(), y.clone())
                                }
                            })
                        })
                    })
                    .count()
            })
            .sum();
        assert_eq!(
            rows_per_pair,
            census_pairs.len(),
            "{name}: one row per census session"
        );

        // 3. dropped_by_limits is the census's group, from one emitter.
        let group = crate::report::dropped_by_limits_json(&d);
        assert!(
            session_table_json(&d).contains(&alloc::format!("\"dropped_by_limits\":{group}")),
            "{name}"
        );

        // 4. the totals, against the lists and assemblers (unbounded: everything).
        let table = session_table(&d);
        for row in &table.rows {
            for link in &row.links {
                if let Some(f) = d.flows().iter().find(|f| f.flow == link.flow) {
                    let held = (f.low_to_high.retained_from()
                        + f.low_to_high.len()
                        + f.high_to_low.retained_from()
                        + f.high_to_low.len()) as u64;
                    assert_eq!(
                        link.bytes, held,
                        "{name}: a stream flow's bytes are its reassembled streams"
                    );
                    if let Ok(frames) = link.frames {
                        assert_eq!(
                            frames,
                            f.frames.len() as u64,
                            "{name}: frames on an unbounded read"
                        );
                    }
                }
            }
        }
    }
    assert!(
        rows_checked >= 12,
        "the corpus must produce rows: {rows_checked}"
    );
    assert!(
        census_links_checked >= 6,
        "and census links: {census_links_checked}"
    );
    assert!(
        phases_checked >= 6,
        "and phases to compare: {phases_checked}"
    );
    assert!(
        initiators_checked >= 6,
        "and pairs to compare: {initiators_checked}"
    );
}

/// THE INITIATOR IS THE INITSYN SENDER, derived from the records and the census:
/// the direction that sent the InitSyn, mapped to a zid by the node plane.
#[test]
fn the_initiator_equals_the_census_zid_of_the_direction_that_sent_the_initsyn() {
    let mut checked = 0usize;
    for dialer_low in [true, false] {
        let (packets, _) = tcp_session(dialer_low, 1);
        let d = packets.dissect();
        let census = crate::node::nodes(&d);
        let table = session_table(&d);
        let row = only(&table);
        for (flow, _origin, list) in d.message_lists_with_origin() {
            let syn = list.iter().find_map(|f| match &f.frame {
                Ok(wz_session_core::inbound::InboundFrame::Init { is_ack: false, .. }) => {
                    Some(f.direction)
                }
                _ => None,
            });
            let Some(direction) = syn else { continue };
            let zid = census
                .zid_on(&flow, direction)
                .expect("a link names both ends");
            assert_eq!(
                row.initiator.clone(),
                Ok(zid.to_vec()),
                "dialer_low={dialer_low}"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 2);
}

/// THE FLOW'S ENCRYPTION FINDING AND THE REPORT'S AGREE: a flow is
/// `encrypted_unreadable` exactly when the report's own list holds it, and
/// `decrypted_tls` exactly when that list's entry says it was decrypted.
#[test]
fn the_encryption_finding_is_the_reports() {
    let mut checked = 0usize;
    for d in [
        tls_flow(&[tls_record(crate::tls::CT_APPLICATION_DATA, &[1; 30])]).dissect(),
        decrypted_tls(),
        tcp_session(true, 2).0.dissect(),
    ] {
        let reported = d.encrypted_flows();
        for f in d.flows() {
            let in_report = f.encrypted();
            let table = session_table(&d);
            let row = table
                .rows
                .iter()
                .find(|r| r.links.iter().any(|l| l.flow == f.flow))
                .expect("the flow is a row");
            let want = match &in_report {
                None => Encryption::Clear,
                Some(e) if e.not_decrypted.is_none() => Encryption::DecryptedTls,
                Some(_) => Encryption::EncryptedUnreadable,
            };
            assert_eq!(row.encryption, want);
            assert_eq!(reported.len(), usize::from(in_report.is_some()));
            checked += 1;
        }
    }
    assert_eq!(checked, 3);
}

// ── vocabularies ───────────────────────────────────────────────────────────

/// EVERY CELL'S REASONS ARE A SUBSET OF THE FAMILY, and every reason is some
/// cell's, so the declared `reason` family is exactly what the cells can say.
#[test]
fn the_reason_family_is_exactly_the_union_of_what_the_cells_can_carry() {
    let mut union: Vec<&str> = Cell::all()
        .iter()
        .flat_map(|c| c.reasons().iter().map(|r| r.name()))
        .collect();
    union.sort_unstable();
    union.dedup();
    assert_eq!(union, Unstated::names());
    let mut keys: Vec<&str> = Cell::all().iter().map(|c| c.key()).collect();
    keys.sort_unstable();
    assert_eq!(keys, Cell::names());
}

/// THE DOCUMENT THE HEADER SHOWS IS THE DOCUMENT OF A REAL SESSION: the opening
/// of `wz_dissect.h`'s example, from the fixture it was written from.
#[test]
fn the_headers_example_is_the_document_of_a_real_session() {
    let (packets, tcp) = tcp_session(true, 6);
    assert_eq!(
        (tcp.messages, tcp.wire_bytes),
        (10, 48),
        "the example's numbers"
    );
    let doc = session_table_json(&packets.dissect());
    let want = "{\"document\":{\"name\":\"session_table\",\"revision\":2},\"ok\":true,\
                \"sessions\":[{\"initiator\":\"a1a1a1a1\",\"acceptor\":\"b2b2b2b2\",\
                \"link\":\"tcp\",\"phase\":\"established\",\"encrypted\":\"clear\",\
                \"first_seen_ts_ns\":\"1700000000000000000\",\
                \"last_seen_ts_ns\":\"1700000000000015000\",\
                \"frames\":10,\"bytes\":48,\"unstated\":[],\"flows\":[{\"flow\":{\"low\":";
    assert!(doc.starts_with(want), "{doc}");
    assert!(
        doc.contains(
            "\"link\":\"tcp\"},\"encrypted\":\"clear\",\"bytes\":48}]}],\"excluded\":\
             [{\"why\":\"multicast_group\",\"count\":0},{\"why\":\"scouting_only\",\"count\":0}],\
             \"dropped_by_limits\":{"
        ),
        "{doc}"
    );
}

// ── garbage in ─────────────────────────────────────────────────────────────

/// A generator that needs no crate and answers the same on every host, so a
/// failure is a number a person can re-run.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// DAMAGED AND GARBAGE CONTAINERS ARE DOCUMENTS, NEVER PANICS.
///
/// Every prefix of three real captures (a TCP session, a UDP session, a pcapng),
/// a few thousand of their bytes flipped, and pure garbage with and without a
/// valid magic in front, each through the door's own steps under both presets.
/// Whatever comes back must be a JSON document that says `ok` one way or the
/// other, and a refusal must carry one of the three words. A panic is a failed
/// test.
#[test]
fn damaged_and_garbage_containers_are_documents_and_never_panics() {
    let tcp = tcp_session(true, 6).0.file();
    let udp = udp_session(false, 6).0.file();
    let ng_frames: Vec<(u32, u64, Vec<u8>)> = udp_session(true, 3)
        .0
        .rows
        .iter()
        .enumerate()
        .map(|(i, (_, _, packet))| (0, 1_000 + i as u64, packet.clone()))
        .collect();
    let refs: Vec<(u32, u64, &[u8])> = ng_frames
        .iter()
        .map(|(i, t, p)| (*i, *t, p.as_slice()))
        .collect();
    let pcapng = crate::pcapng::write(&[(LINKTYPE_ETHERNET, 6)], &refs);

    let mut rng = Lcg(0x5E55_1011);
    let mut inputs: Vec<Vec<u8>> = Vec::new();
    for seed in [&tcp, &udp, &pcapng] {
        for cut in 0..seed.len() {
            inputs.push(seed[..cut].to_vec());
        }
        for _ in 0..900 {
            let mut bytes = seed.clone();
            for _ in 0..=rng.below(4) {
                let at = rng.below(bytes.len());
                bytes[at] ^= 1 << rng.below(8);
            }
            inputs.push(bytes);
        }
    }
    let pcap_magic = [
        0xD4, 0xC3, 0xB2, 0xA1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 1, 0, 0, 0,
    ];
    let ng_magic = [
        0x0A, 0x0D, 0x0D, 0x0A, 28, 0, 0, 0, 0x4D, 0x3C, 0x2B, 0x1A, 1, 0, 0, 0,
    ];
    for prefix in [&[][..], &pcap_magic[..], &ng_magic[..]] {
        for _ in 0..700 {
            let mut bytes = prefix.to_vec();
            for _ in 0..rng.below(300) {
                bytes.push(rng.below(256) as u8);
            }
            inputs.push(bytes);
        }
    }
    assert!(inputs.len() >= 4_000, "the population: {}", inputs.len());

    let (mut tables, mut refusals) = (0usize, 0usize);
    for (n, bytes) in inputs.iter().enumerate() {
        let limits = if n % 2 == 0 {
            DissectionLimits::default()
        } else {
            DissectionLimits::for_live_tap()
        };
        let doc = session_table_document(bytes, limits);
        let v = json5::parse(&doc).unwrap_or_else(|e| panic!("input {n}: not JSON ({e:?}): {doc}"));
        match v.get("ok") {
            Some(Json5Value::Bool(true)) => {
                assert!(v.get("sessions").is_some(), "input {n}: {doc}");
                tables += 1;
            }
            Some(Json5Value::Bool(false)) => {
                let word = text(&v, "refusal");
                assert!(Refusal::names().contains(&word), "input {n}: {word}");
                refusals += 1;
            }
            other => panic!("input {n}: `ok` is {other:?}"),
        }
    }
    // BOTH branches were reached, or the loop proved nothing about either.
    assert!(tables > 100, "readable inputs: {tables}");
    assert!(refusals > 1_000, "refused inputs: {refusals}");
}
