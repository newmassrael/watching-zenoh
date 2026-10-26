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
use crate::session_table::{
    session_table, AnnouncedVersion, Cell, Encryption, SessionRow, Unstated, Why, ZenohVerdict,
};
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
        _record: &crate::tls::EncryptedRecord,
        bytes: &[u8],
    ) -> Option<crate::tls::OpenedRecord> {
        let body = bytes.get(5..)?;
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
        .frames()
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
    // Two version headers, the Init roles and ten units read whole; the
    // keep-alives carry no SN, the fixture's cookie is empty, and its TCP opens
    // without a SYN, so its framing is not weighed.
    let zenoh = "\"zenoh\":\"yes\",\"announced_version\":\"own\",\
                 \"zenoh_evidence\":{\"log2_lr_millibits\":26607,\
                 \"log2_lr_no_millibits\":53597,\
                 \"yes_at_millibits\":20000,\"no_at_millibits\":-20000,\"model\":2,\
                 \"checks\":[{\"check\":\"init_roles\",\"strength\":\"handshake\",\
                 \"confirmed\":1,\"violated\":0,\"millibits\":983,\"no_millibits\":983,\
                 \"q_basis\":\"derived\",\"eps_basis\":\"measured\"},\
                 {\"check\":\"version_header\",\"strength\":\"header\",\
                 \"confirmed\":2,\"violated\":0,\"millibits\":15984,\"no_millibits\":15984,\
                 \"q_basis\":\"derived\",\"eps_basis\":\"measured\"},\
                 {\"check\":\"unit_reading\",\"strength\":\"unit\",\
                 \"confirmed\":10,\"violated\":0,\"millibits\":9640,\"no_millibits\":36630,\
                 \"q_basis\":\"measured\",\"eps_basis\":\"measured\"}]}";
    let want = alloc::format!(
        "{{\"document\":{{\"name\":\"session_table\",\"revision\":6}},\"ok\":true,\
         \"sessions\":[{{\"initiator\":\"a1a1a1a1\",\"acceptor\":\"b2b2b2b2\",\
         \"link\":\"tcp\",\"phase\":\"established\",\"encrypted\":\"clear\",\
         \"first_seen_ts_ns\":\"1700000000000000000\",\
         \"last_seen_ts_ns\":\"1700000000000015000\",\
         \"frames\":10,\"bytes\":48,{zenoh},\
         \"unit_readings\":{{\"explained\":{{\"units\":10,\"bytes\":28}},\
         \"residual\":{{\"units\":0,\"bytes\":0}},\
         \"undecoded\":{{\"units\":0,\"bytes\":0}}}},\"unstated\":[],\
         \"flows\":[{{\"flow\":{{\"low\":"
    );
    assert!(doc.starts_with(&want), "{doc}");
    assert!(
        doc.contains(&alloc::format!(
            "\"link\":\"tcp\"}},\"encrypted\":\"clear\",\"bytes\":48,{zenoh},\
             \"unit_readings\":{{\"explained\":{{\"units\":10,\"bytes\":28}},\
             \"residual\":{{\"units\":0,\"bytes\":0}},\
             \"undecoded\":{{\"units\":0,\"bytes\":0}}}}}}]}}],\
             \"excluded\":\
             [{{\"why\":\"multicast_group\",\"count\":0}},{{\"why\":\"scouting_only\",\"count\":0}}],\
             \"dropped_by_limits\":{{"
        )),
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

// ── whether a flow is zenoh ─────────────────────────────────────────────────

/// A deterministic stream of bytes, so a run that fails fails the same way again.
struct Noise(u64);

impl Noise {
    fn next(&mut self) -> u64 {
        // xorshift64
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

/// ARBITRARY UDP IS NOT ZENOH. Datagrams of random bytes, 1 to 200 long, to the
/// two zenoh ports and four others, each on a flow of its own: what a capture of
/// an ordinary network holds. They decode as zenoh messages and every flow is a
/// row; none is `yes`, none names a node, and none names an initiator or an
/// acceptor, because those come only from a message whose version byte is the
/// protocol's. One datagram is never enough to say `yes` or `no`: the largest
/// weight a single unit and its header can carry is below either threshold.
#[test]
fn arbitrary_udp_bytes_prove_no_flow_zenoh_and_name_no_node() {
    let mut noise = Noise(0x9E37_79B9_7F4A_7C15);
    let mut out = Packets::default();
    let ports = [7446u16, 7447, 5353, 443, 9999, 12345];
    for i in 0..300u64 {
        let len = 1 + (noise.next() % 200) as usize;
        let payload = noise.bytes(len);
        let dport = ports[(i % ports.len() as u64) as usize];
        out.push(
            T0 + i * 1_000,
            udp_packet(LOW, 20_000 + i as u16, HIGH, dport, &payload),
        );
    }
    let d = out.dissect();
    let table = session_table(&d);
    assert!(
        !table.rows.is_empty(),
        "the bytes decode and stand as rows; the fact is what says what they are"
    );
    for row in &table.rows {
        assert_eq!(word(row.evidence), ZenohVerdict::Undecided, "{row:?}");
        assert!(row.initiator.is_err() && row.acceptor.is_err(), "{row:?}");
    }
    for flow in d.datagram_flows() {
        assert_eq!(
            word(flow.zenoh_evidence()),
            ZenohVerdict::Undecided,
            "{:?}",
            flow.flow
        );
    }
    let census = crate::node::nodes(&d);
    assert!(
        census.nodes().is_empty(),
        "random bytes named nodes: {:?}",
        census.nodes()
    );
    // The population held what the claim measured: some datagrams began like
    // an Init, a Join, a Scout or a Hello, and were refused for their version.
    let foreign: u64 = d
        .datagram_flows()
        .iter()
        .map(|f| f.ingest.versions().foreign_version)
        .sum();
    assert!(foreign > 0, "no datagram reached the version byte");
}

/// A session whose handshake is in the capture is `yes`, in the row and in the
/// flow, and the document says so with what it rests on: two version headers,
/// the Init roles and six units read whole.
#[test]
fn a_session_with_its_handshake_is_zenoh() {
    use crate::zenoh_evidence::{model, Check};
    let (packets, _) = udp_session(true, 2);
    let d = packets.dissect();
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(word(row.evidence), ZenohVerdict::Yes);
    assert_eq!(row.versions.own_version, 2, "the InitSyn and the InitAck");
    assert_eq!(row.evidence.tally(Check::VersionHeader).confirmed, 2);
    assert_eq!(row.evidence.tally(Check::InitRoles).confirmed, 1);
    assert_eq!(row.evidence.tally(Check::UnitReading).confirmed, 6);
    let sum = model::VERSION_HEADER
        .times(2)
        .plus(model::INIT_ROLES_CONFIRMED)
        .plus(model::UNIT_EXPLAINED.times(6));
    assert_eq!(row.evidence.log2_lr_millibits(), sum.yes);
    assert_eq!(row.evidence.log2_lr_no_millibits(), sum.no);
    let doc = session_table_json(&d);
    let head = alloc::format!(
        "\"zenoh\":\"yes\",\"announced_version\":\"own\",\"zenoh_evidence\":\
         {{\"log2_lr_millibits\":{},\"log2_lr_no_millibits\":{},\"yes_at_millibits\":20000,\
         \"no_at_millibits\":-20000,\"model\":2,\"checks\":[{{\"check\":\"init_roles\"",
        sum.yes,
        sum.no
    );
    assert!(doc.contains(&head), "{head}\n{doc}");
}

/// THE COOKIE BINDS THE TWO DIRECTIONS. An OpenSyn that carries the cookie the
/// other direction's InitAck issued weighs eight bits a byte, up to 64, which
/// alone crosses the threshold; one that carries another cookie is a
/// violation, and the flow is no longer `yes` on its Inits alone.
#[test]
fn an_echoed_cookie_decides_and_a_different_one_is_a_violation() {
    use crate::zenoh_evidence::{model, Check};
    let cookie = [0x5Au8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
    let init_ack = |cookie: &[u8]| {
        let mut wire = init(&ZID_B, true);
        // `init` writes an empty cookie, so its length is the last byte.
        *wire.last_mut().expect("the cookie length") = cookie.len() as u8;
        wire.extend_from_slice(cookie);
        wire
    };
    let open_syn = |cookie: &[u8]| {
        let mut wire = vec![0x02, 10, 0, cookie.len() as u8];
        wire.extend_from_slice(cookie);
        wire
    };
    let read = |echoed: &[u8]| {
        let mut out = Packets::default();
        let mut udp = Udp::new(true, 43210);
        udp.send(&mut out, T0, false, &init_ack(&cookie));
        udp.send(&mut out, T0 + 1_000, true, &open_syn(echoed));
        only(&session_table(&out.dissect())).evidence
    };
    let echoed = read(&cookie);
    assert_eq!(
        echoed.tally(Check::CookieEcho),
        crate::zenoh_evidence::CheckTally {
            confirmed: 1,
            violated: 0,
            millibits: 8 * model::COOKIE_ECHO_PER_BYTE + model::COOKIE_ECHO_FIDELITY,
            no_millibits: 8 * model::COOKIE_ECHO_PER_BYTE + model::COOKIE_ECHO_FIDELITY,
        }
    );
    assert_eq!(word(echoed), ZenohVerdict::Yes);
    let mut other = cookie;
    other[3] ^= 0xFF;
    let differs = read(&other);
    assert_eq!(differs.tally(Check::CookieEcho).violated, 1);
    assert_eq!(word(differs), ZenohVerdict::Undecided);
}

/// A flow the capture joined after its handshake carries no Init. Three
/// keep-alives read whole are evidence, and not enough of it: `undecided`, with
/// the units that weighed.
#[test]
fn a_flow_joined_after_its_handshake_starts_undecided() {
    use crate::zenoh_evidence::Check;
    let (packets, _) = midstream_tcp(3);
    let table = session_table(&packets.dissect());
    let row = only(&table);
    assert_eq!(word(row.evidence), ZenohVerdict::Undecided);
    assert_eq!(row.evidence.tally(Check::UnitReading).confirmed, 3);
    assert_eq!(AnnouncedVersion::of(row.versions), AnnouncedVersion::None);
}

/// A FLOW JOINED MID-SESSION REACHES `yes` ON ITS SEQUENCE NUMBERS, with no ring
/// to judge them by: Frames whose SNs step by one on their conduit are what a
/// counter of another protocol rarely does by chance. Two such Frames in each
/// direction, and the flow is zenoh without an Init in the capture.
#[test]
fn a_flow_joined_mid_session_is_zenoh_on_its_sn_steps() {
    use crate::zenoh_evidence::Check;
    let frame = |sn: u8| vec![wire_const::T_MID_FRAME | 0x20, sn];
    let mut out = Packets::default();
    let mut tcp = Tcp::new(true, 43210);
    for (i, sn) in [40u8, 41, 42].into_iter().enumerate() {
        tcp.send(&mut out, T0 + i as u64 * 2_000, true, &frame(sn));
        tcp.send(
            &mut out,
            T0 + i as u64 * 2_000 + 1_000,
            false,
            &frame(sn + 60),
        );
    }
    let row = only(&session_table(&out.dissect())).clone();
    assert_eq!(
        row.evidence.tally(Check::SnFollows),
        crate::zenoh_evidence::CheckTally {
            confirmed: 4,
            violated: 0,
            millibits: 4 * crate::zenoh_evidence::model::SN_FOLLOWS.yes,
            no_millibits: 4 * crate::zenoh_evidence::model::SN_FOLLOWS.no,
        },
        "{row:?}"
    );
    assert_eq!(word(row.evidence), ZenohVerdict::Yes, "{row:?}");
    assert_eq!(AnnouncedVersion::of(row.versions), AnnouncedVersion::None);
}

/// An Init of another protocol version names nobody and folds nothing: the
/// flow announced a `foreign` version, its one unit did not decode, and its row
/// states no initiator.
#[test]
fn an_init_of_another_version_is_foreign_and_names_nobody() {
    let mut wire = init(&ZID_A, false);
    wire[1] = 0x08;
    let mut out = Packets::default();
    let mut udp = Udp::new(true, 43210);
    udp.send(&mut out, T0, true, &wire);
    let d = out.dissect();
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(
        AnnouncedVersion::of(row.versions),
        AnnouncedVersion::Foreign
    );
    assert_eq!(
        row.evidence
            .tally(crate::zenoh_evidence::Check::VersionHeader),
        crate::zenoh_evidence::CheckTally::default()
    );
    assert_eq!(word(row.evidence), ZenohVerdict::Undecided);
    assert_eq!(row.initiator, Err(Unstated::NotInCapture));
    assert!(crate::node::nodes(&d).nodes().is_empty());
}

/// An Init of the protocol's version that does NOT end where its datagram ends
/// is no version header and names nobody: random bytes that open like an Init
/// are followed by more random bytes, and a batch of zenoh messages is not. The
/// whole Init is a header and a unit read whole, which together are still
/// below the threshold: a lone header is `undecided`.
#[test]
fn an_init_followed_by_bytes_no_message_explains_proves_nothing() {
    use crate::zenoh_evidence::Check;
    let read = |wire: &[u8]| {
        let mut out = Packets::default();
        let mut udp = Udp::new(true, 43210);
        udp.send(&mut out, T0, true, wire);
        let d = out.dissect();
        let row = only(&session_table(&d)).clone();
        (
            word(row.evidence),
            row.evidence.tally(Check::VersionHeader).confirmed,
            row.initiator.is_ok(),
            crate::node::nodes(&d).nodes().len(),
        )
    };
    let whole = init(&ZID_A, false);
    assert_eq!(
        read(&whole),
        (ZenohVerdict::Undecided, 1, true, 1),
        "the control"
    );
    let mut trailed = whole.clone();
    // A reserved MID behind the Init: it decodes as nothing this reader can
    // measure, so the datagram is not read whole.
    trailed.extend_from_slice(&[0x1F, 0xAB, 0xCD]);
    assert_eq!(read(&trailed), (ZenohVerdict::Undecided, 0, false, 0));
}

/// A Scout of another protocol version on the scouting group names no node and
/// is no version header; the same Scout at the protocol's version is both.
#[test]
fn a_scout_of_another_version_names_no_node() {
    use crate::datagram_tests::SCOUT_GROUP;
    let scout = |version: u8| {
        let mut scout = wz_codecs::scout::Scout::new();
        scout.version = version;
        scout.set_what(0x03);
        scout.set_i(true);
        scout.set_zid_len_m1(3);
        scout.zid = Some(&ZID_C);
        let mut wire = vec![wire_const::S_MID_SCOUT];
        wire.extend_from_slice(&scout.encode_to_vec());
        wire
    };
    let census_of = |wire: &[u8]| {
        let mut out = Packets::default();
        out.push(T0, udp_packet(LOW, 43210, SCOUT_GROUP, 7446, wire));
        let d = out.dissect();
        let flow = &d.datagram_flows()[0];
        let headers = flow
            .zenoh_evidence()
            .tally(crate::zenoh_evidence::Check::VersionHeader)
            .confirmed;
        (
            crate::node::nodes(&d).nodes().len(),
            AnnouncedVersion::of(flow.ingest.versions()),
            headers,
        )
    };
    assert_eq!(census_of(&scout(0x09)), (1, AnnouncedVersion::Own, 1));
    assert_eq!(census_of(&scout(0x08)), (0, AnnouncedVersion::Foreign, 0));
    // And a Scout of the protocol's version with bytes behind it it does not
    // account for is not one.
    let mut trailed = scout(0x09);
    trailed.extend_from_slice(&[0xAB, 0xCD]);
    assert_eq!(census_of(&trailed), (0, AnnouncedVersion::None, 0));
}

fn word(evidence: crate::zenoh_evidence::ZenohEvidence) -> ZenohVerdict {
    ZenohVerdict::of(&evidence)
}

/// The word sets the documents declare are the enums'.
#[test]
fn the_declared_zenoh_words_are_the_enums() {
    use crate::zenoh_evidence::{Basis, Check, Strength};
    assert_eq!(
        crate::doc_revision::ZENOH_VERDICT_R43.to_vec(),
        ZenohVerdict::names()
    );
    assert_eq!(
        crate::doc_revision::ANNOUNCED_VERSION_R43.to_vec(),
        AnnouncedVersion::names()
    );
    assert_eq!(
        crate::doc_revision::ZENOH_CHECK_R46.to_vec(),
        Check::names()
    );
    assert_eq!(
        crate::doc_revision::ZENOH_STRENGTH_R43.to_vec(),
        Strength::names()
    );
    assert_eq!(
        crate::doc_revision::ZENOH_BASIS_R46.to_vec(),
        Basis::names()
    );
}

// ── how a flow's framing units read ───────────────────────────────────────

fn tally(units: u64, bytes: u64) -> wz_session_core::passive::UnitTally {
    wz_session_core::passive::UnitTally { units, bytes }
}

/// A flow joined after its handshake carries no Init. Every unit of it reads as
/// a message that accounts for every byte: the fixture knows it put seven
/// one-byte units in the stream. Seven keep-alives, and the framing where the
/// capture holds the stream's start, are not enough for `yes`. The unit at
/// which they would be is the model's: the framing's weight and one unit's,
/// against the threshold.
#[test]
fn a_flow_joined_after_its_handshake_reads_as_explained_units() {
    use crate::zenoh_evidence::model;
    let (packets, _) = midstream_tcp(7);
    let d = packets.dissect();
    let table = session_table(&d);
    let row = only(&table);
    assert_eq!(word(row.evidence), ZenohVerdict::Undecided);
    // What the stream's framing weighs, as the row says it: nothing when the
    // fixture's TCP opens without a SYN, whose start the capture does not hold.
    let held = row
        .evidence
        .tally(crate::zenoh_evidence::Check::StreamFraming)
        .millibits;
    let crossing = ((model::YES_AT - held) as u64).div_ceil(model::UNIT_EXPLAINED.yes as u64);
    for (units, want) in [
        (crossing - 1, ZenohVerdict::Undecided),
        (crossing, ZenohVerdict::Yes),
    ] {
        let (packets, _) = midstream_tcp(units);
        assert_eq!(
            word(only(&session_table(&packets.dissect())).evidence),
            want,
            "{units} units"
        );
    }
    assert_eq!(row.readings.explained, tally(7, 7));
    assert_eq!(row.readings.residual, tally(0, 0));
    assert_eq!(row.readings.undecoded, tally(0, 0));
    assert_eq!(row.links[0].readings, row.readings);
}

/// THE THREE CLASSES PARTITION THE UNITS. One datagram of each, on one flow:
/// an Init that is the whole datagram, an Init with a reserved MID behind it
/// (a known message, bytes left), and a datagram whose front is that reserved
/// MID (nothing explained). Each unit is in exactly one class, with its own
/// bytes.
#[test]
fn a_datagram_is_counted_in_exactly_one_class_with_its_own_bytes() {
    let whole = init(&ZID_A, false);
    let mut trailed = whole.clone();
    trailed.extend_from_slice(&[0x1F, 0xAB, 0xCD]);
    let junk = vec![0x1F, 0xAB, 0xCD];

    let mut out = Packets::default();
    let mut udp = Udp::new(true, 43210);
    udp.send(&mut out, T0, true, &whole);
    udp.send(&mut out, T0 + 1_000, true, &trailed);
    udp.send(&mut out, T0 + 2_000, true, &junk);
    let d = out.dissect();
    let table = session_table(&d);
    let readings = only(&table).readings;
    assert_eq!(readings.explained, tally(1, whole.len() as u64));
    assert_eq!(readings.residual, tally(1, trailed.len() as u64));
    assert_eq!(readings.undecoded, tally(1, junk.len() as u64));
    assert_eq!(readings.units(), 3);
}

/// A scouting datagram is a unit of one message: whole, with bytes behind it,
/// or of another version (a decode error at the front, so nothing explained).
#[test]
fn a_scouting_datagram_reads_as_a_unit_of_one_message() {
    use crate::datagram_tests::SCOUT_GROUP;
    let scout = |version: u8| {
        let mut scout = wz_codecs::scout::Scout::new();
        scout.version = version;
        scout.set_what(0x03);
        scout.set_i(true);
        scout.set_zid_len_m1(3);
        scout.zid = Some(&ZID_C);
        let mut wire = vec![wire_const::S_MID_SCOUT];
        wire.extend_from_slice(&scout.encode_to_vec());
        wire
    };
    let readings_of = |wire: &[u8]| {
        let mut out = Packets::default();
        out.push(T0, udp_packet(LOW, 43210, SCOUT_GROUP, 7446, wire));
        let d = out.dissect();
        d.datagram_flows()[0].ingest.readings()
    };
    let whole = scout(0x09);
    assert_eq!(readings_of(&whole).explained, tally(1, whole.len() as u64));
    let mut trailed = whole.clone();
    trailed.extend_from_slice(&[0xAB, 0xCD]);
    assert_eq!(
        readings_of(&trailed).residual,
        tally(1, trailed.len() as u64)
    );
    let foreign = scout(0x08);
    assert_eq!(
        readings_of(&foreign).undecoded,
        tally(1, foreign.len() as u64)
    );
}

/// A ROW READS AS ITS FLOWS TOGETHER, and a unit is a unit whichever link
/// carried it: the fixture counted the messages, one unit each.
#[test]
fn a_row_reads_as_the_sum_of_its_flows() {
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
    let together = row.links[0].readings.and(row.links[1].readings);
    assert_eq!(row.readings, together);
    assert_eq!(row.readings.units(), first.messages + second.messages);
    assert_eq!(row.readings.explained.units, row.readings.units());
}

// ── the selector's `zenoh` field ──────────────────────────────────────────

/// A numbering that gives list `n` the number `n`, as a document numbers its
/// lists.
struct ListNumbers;

impl crate::fields_json::RowCoordinates for ListNumbers {
    fn list_id(&self, list: usize) -> Option<u64> {
        Some(list as u64)
    }

    fn scouting_list_id(&self, _flow: &crate::link::FlowKey) -> Option<u64> {
        None
    }

    /// Every row is numbered, from 1, by the order its list produced it: the
    /// captures here have one list that holds rows.
    fn row_seq(&self, _list: usize, produced: u64) -> Option<u64> {
        Some(produced + 1)
    }
}

/// The word each row of the selection document carries for `selector`, in row
/// order.
fn selected_words(d: &Dissection, selector: &str) -> Vec<String> {
    let filter =
        crate::filter::Filter::parse(selector).unwrap_or_else(|e| panic!("{selector}: {e}"));
    let doc = crate::selection_json::selection_json_where_coordinated(d, &filter, &ListNumbers);
    doc.split("\"selected\":\"")
        .skip(1)
        .map(|s| s.split('"').next().unwrap_or_default().to_string())
        .collect()
}

fn count(words: &[String], word: &str) -> usize {
    words.iter().filter(|w| w.as_str() == word).count()
}

/// A SELECTOR READS THE FLOW'S WORD: every row of a session whose handshake is
/// in the capture is `yes`, and none is `undecided`.
#[test]
fn a_zenoh_term_selects_the_rows_of_a_flow_by_its_word() {
    let (packets, _) = udp_session(true, 2);
    let d = packets.dissect();
    // Four handshake messages and two keep-alives.
    let zenoh = selected_words(&d, "zenoh == yes");
    assert_eq!(zenoh.len(), 6);
    assert_eq!(count(&zenoh, "yes"), 6, "{zenoh:?}");
    assert_eq!(count(&selected_words(&d, "zenoh != yes"), "no"), 6);
    assert_eq!(count(&selected_words(&d, "zenoh == undecided"), "no"), 6);
    assert_eq!(
        count(&selected_words(&d, "zenoh in {undecided, no}"), "no"),
        6
    );
    assert_eq!(
        count(&selected_words(&d, "zenoh in {undecided, yes}"), "yes"),
        6
    );
}

/// TWO FLOWS, TWO WORDS: the rows of the flow the capture joined after its
/// handshake, two keep-alives, read `undecided`, and the rows of the session
/// with its handshake `yes`, in one capture and one selection.
#[test]
fn a_zenoh_term_tells_two_flows_of_one_capture_apart() {
    let mut out = Packets::default();
    let mut tcp = Tcp::new(true, 43210);
    tcp.send(&mut out, T0, true, &keepalive());
    tcp.send(&mut out, T0 + 1_000, false, &keepalive());
    let mut udp = Udp::new(true, 43211);
    udp.handshake(&mut out, T0 + 2_000, &ZID_A, &ZID_B);
    let d = out.dissect();
    let zenoh = selected_words(&d, "zenoh == yes");
    assert_eq!(zenoh.len(), 6, "{zenoh:?}");
    assert_eq!(count(&zenoh, "yes"), 4, "the handshake's four rows");
    assert_eq!(
        count(&zenoh, "no"),
        2,
        "the two keep-alives of the other flow"
    );
    let undecided = selected_words(&d, "zenoh == undecided");
    assert_eq!(count(&undecided, "yes"), 2);
    assert_eq!(count(&undecided, "no"), 4);
}

/// THE LIST OF WORDS IS THE LISTS' OWN: one per list of the enumeration, so a
/// list added to it cannot be left without a word.
#[test]
fn every_message_list_has_a_word() {
    let mut out = Packets::default();
    let mut tcp = Tcp::new(true, 43210);
    tcp.handshake(&mut out, T0, &ZID_A, &ZID_B);
    let mut udp = Udp::new(true, 43211);
    udp.send(&mut out, T0 + 10_000, true, &keepalive());
    let d = out.dissect();
    let words = d.list_zenoh_words();
    assert_eq!(words.len(), d.message_lists().count());
    assert!(words.iter().all(Option::is_some), "{words:?}");
    assert_eq!(words[0], Some(ZenohVerdict::Yes), "the stream flow");
    assert_eq!(
        words[1],
        Some(ZenohVerdict::Undecided),
        "the datagram flow of one bare keep-alive"
    );
}

/// A FLOW'S WORD MOVES WHEN ITS HANDSHAKE ARRIVES, and the since door says so:
/// the rows a cursor has passed read `undecided` until the two Inits are in the
/// capture, and are revised with the word they read before.
#[test]
fn the_arrival_of_an_init_revises_the_rows_a_cursor_passed() {
    let mut out = Packets::default();
    let mut udp = Udp::new(true, 43210);
    udp.send(&mut out, T0, true, &keepalive());
    udp.send(&mut out, T0 + 1_000, false, &keepalive());
    let before = out.dissect();
    udp.send(&mut out, T0 + 2_000, true, &init(&ZID_A, false));
    udp.send(&mut out, T0 + 3_000, false, &init(&ZID_B, true));
    let after = out.dissect();

    let filter = crate::filter::Filter::parse("zenoh == undecided").expect("compiles");
    let since = |d: &Dissection,
                 after_seq: u64,
                 through_seq: u64,
                 memory: &mut crate::selection_json::SelectionMemory| {
        crate::selection_json::selection_since_json_coordinated(
            d,
            &filter,
            &ListNumbers,
            crate::selection_json::SelectionWindow {
                after_seq,
                through_seq,
            },
            memory,
        )
    };
    let mut memory = crate::selection_json::SelectionMemory::default();
    let first = since(&before, 0, 2, &mut memory);
    assert_eq!(first.matches("\"selected\":\"yes\"").count(), 2, "{first}");
    let second = since(&after, 2, 3, &mut memory);
    let revised = second
        .split("\"revised\":[")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .unwrap_or_default();
    assert_eq!(
        revised.matches("\"was\":\"yes\"").count(),
        2,
        "both rows the cursor passed read another word now: {second}"
    );
    assert_eq!(
        revised.matches("\"selected\":\"no\"").count(),
        2,
        "{second}"
    );
}

/// The words are the closed set the verdict has, and a word outside it, or an
/// order the field does not admit, is refused at its own byte.
#[test]
fn a_zenoh_term_refuses_a_word_and_an_operator_it_does_not_have() {
    use crate::filter::FilterErrorKind;
    assert!(matches!(
        crate::filter::Filter::parse("zenoh == maybe")
            .map(|_| ())
            .expect_err("no such word")
            .kind,
        FilterErrorKind::UnknownValue { field: "zenoh", .. }
    ));
    assert!(crate::filter::Filter::parse("zenoh > yes").is_err());
    assert!(crate::filter::Filter::parse("zenoh == undecided").is_ok());
    assert!(crate::filter::Filter::parse("zenoh matches yes").is_err());
    // The words of the verdict before the sequential test are not words of it.
    for retired in ["proven", "unproven", "foreign_version", "mixed"] {
        let selector = alloc::format!("zenoh == {retired}");
        assert!(
            crate::filter::Filter::parse(&selector).is_err(),
            "{retired}"
        );
    }
}

// ── what the readings measure, on bytes that are and are not zenoh ────────

/// WHAT THE COUNT SEPARATES, MEASURED (2026-10-26), and what it does not.
///
/// 3000 seeded random datagrams of 1 to 1400 bytes, one per capture, read: 6.3%
/// `explained`, 9.5% `residual`, 84.2% `undecoded`, and every one `undecided`. The
/// `explained` ones are not short datagrams: they average 719 bytes, because a
/// `Frame` or a `Fragment` takes the rest of its datagram by construction, so a
/// random datagram whose first byte happens to be one of those two reads as a
/// whole unit. A single unit is therefore NOT evidence: one in sixteen random
/// datagrams reads `explained`. What separates the two is the SHARE over many
/// units, and the bound below holds that.
///
/// The bounds are the measurement with room, and a decoder that learned more
/// message kinds moves them, which is what this test is for: the claim a
/// consumer draws from the count is held to the measured population and not to
/// a belief about it.
#[test]
fn arbitrary_datagrams_mostly_do_not_read_as_explained() {
    let mut rng = Lcg(0xD1CE_5EED);
    let n = 3000u64;
    let (mut explained, mut undecoded, mut bytes, mut explained_bytes) = (0u64, 0u64, 0u64, 0u64);
    for _ in 0..n {
        let len = 1 + rng.below(1400);
        let wire: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let mut packets = Packets::default();
        let mut udp = Udp::new(true, 43210);
        udp.send(&mut packets, T0, true, &wire);
        let d = packets.dissect();
        let table = session_table(&d);
        let row = only(&table);
        assert_eq!(row.readings.units(), 1, "one datagram is one unit");
        assert_eq!(
            word(row.evidence),
            ZenohVerdict::Undecided,
            "one datagram decides nothing: {wire:02x?}"
        );
        explained += row.readings.explained.units;
        undecoded += row.readings.undecoded.units;
        bytes += wire.len() as u64;
        explained_bytes += row.readings.explained.bytes;
    }
    assert!(
        explained * 100 < n * 10,
        "{explained} of {n} random datagrams read explained, measured 189"
    );
    assert!(
        undecoded * 100 > n * 75,
        "{undecoded} of {n} random datagrams read undecoded, measured 2526"
    );
    assert!(
        explained_bytes * 100 < bytes * 10,
        "{explained_bytes} of {bytes} bytes read explained"
    );
}

/// HOW THE EXPLAINED SHARE OF ARBITRARY DATAGRAMS SPREADS WITH THE NUMBER OF
/// UNITS, MEASURED (2026-10-26): 600 seeded flows of `n` random datagrams each
/// (1 to 1400 bytes), the share being `explained` units over all units.
///
/// | n | mean | p95 | p99 | max | flows with share >= 0.5 |
/// |---|---|---|---|---|---|
/// | 1 | 0.052 | 1.00 | 1.00 | 1.00 | 31 of 600 |
/// | 2 | 0.054 | 0.50 | 0.50 | 1.00 | 64 |
/// | 3 | 0.065 | 0.33 | 0.67 | 1.00 | 8 |
/// | 5 | 0.067 | 0.20 | 0.40 | 0.60 | 2 |
/// | 10 | 0.061 | 0.20 | 0.30 | 0.40 | 0 |
/// | 20 | 0.057 | 0.15 | 0.20 | 0.30 | 0 |
/// | 50 | 0.063 | 0.12 | 0.16 | 0.24 | 0 |
///
/// The mean does not move with `n`: every datagram is an independent draw at
/// about one in sixteen. What moves is the spread, so a share is evidence of
/// zenoh only as far as the units behind it, and a session read unit after unit
/// as `explained` is at share 1.0 whatever `n` is. The bounds below are the
/// measured maxima with room, for the three counts a consumer is likely to
/// call enough.
#[test]
fn the_explained_share_of_arbitrary_datagrams_narrows_with_the_unit_count() {
    for (n, trials, bound) in [(10usize, 300usize, 0.6f64), (20, 300, 0.5), (50, 300, 0.4)] {
        let mut rng = Lcg(0xA11CE + n as u64);
        let mut widest = 0.0f64;
        for _ in 0..trials {
            let mut packets = Packets::default();
            let mut udp = Udp::new(true, 43210);
            for i in 0..n {
                let len = 1 + rng.below(1400);
                let wire: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                udp.send(&mut packets, T0 + i as u64 * 1_000, true, &wire);
            }
            let d = packets.dissect();
            let table = session_table(&d);
            let readings = only(&table).readings;
            assert_eq!(readings.units(), n as u64, "one unit per datagram");
            let share = readings.explained.units as f64 / n as f64;
            widest = widest.max(share);
        }
        assert!(
            widest < bound,
            "{trials} flows of {n} random datagrams reached an explained share of {widest}"
        );
    }
}

// ── structured datagrams that are not zenoh ───────────────────────────────

/// A DNS name in wire form: length-prefixed labels and the root.
fn dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn pick<'a, T>(rng: &mut Lcg, pool: &'a [T]) -> &'a T {
    &pool[rng.below(pool.len())]
}

fn hex_text(rng: &mut Lcg, digits: usize) -> String {
    (0..digits)
        .map(|_| char::from(b"0123456789abcdef"[rng.below(16)]))
        .collect()
}

fn rand_bytes(rng: &mut Lcg, len: usize) -> Vec<u8> {
    (0..len).map(|_| rng.next() as u8).collect()
}

/// DNS over UDP (53): alternating query and response, a fresh id per pair. A
/// query is one question, with an EDNS0 OPT record half the time; a response
/// echoes the question and answers it with one to four A, AAAA or TXT records
/// whose name is a compression pointer to the question.
fn dns_datagrams(rng: &mut Lcg, n: usize) -> Vec<(bool, Vec<u8>)> {
    const HOSTS: [&str; 8] = [
        "www", "mail", "api", "cdn", "ntp", "time", "update", "login",
    ];
    const ZONES: [&str; 6] = [
        "example.com",
        "ubuntu.com",
        "github.com",
        "pool.ntp.org",
        "googleapis.com",
        "ivis.ai",
    ];
    let mut out = Vec::new();
    let (mut id, mut name, mut qtype) = (0u16, Vec::new(), 1u16);
    for i in 0..n {
        let query = i % 2 == 0;
        if query {
            id = rng.next() as u16;
            let host = *pick(rng, &HOSTS);
            let zone = *pick(rng, &ZONES);
            name = dns_name(&alloc::format!("{host}.{zone}"));
            qtype = *pick(rng, &[1u16, 1, 28, 28, 15, 16, 12]);
        }
        let mut m = id.to_be_bytes().to_vec();
        if query {
            let additional = u16::from(rng.below(2) == 0);
            m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0]);
            m.extend_from_slice(&additional.to_be_bytes());
            m.extend_from_slice(&name);
            m.extend_from_slice(&qtype.to_be_bytes());
            m.extend_from_slice(&[0, 1]);
            if additional == 1 {
                m.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
            }
        } else {
            let answers = 1 + rng.below(4) as u16;
            m.extend_from_slice(&[0x81, 0x80, 0, 1]);
            m.extend_from_slice(&answers.to_be_bytes());
            m.extend_from_slice(&[0, 0, 0, 0]);
            m.extend_from_slice(&name);
            m.extend_from_slice(&qtype.to_be_bytes());
            m.extend_from_slice(&[0, 1]);
            for _ in 0..answers {
                let rdata = match qtype {
                    1 => rand_bytes(rng, 4),
                    28 => rand_bytes(rng, 16),
                    _ => {
                        let digits = 4 + rng.below(40);
                        let text = hex_text(rng, digits);
                        let mut r = vec![text.len() as u8];
                        r.extend_from_slice(text.as_bytes());
                        r
                    }
                };
                m.extend_from_slice(&[0xC0, 0x0C]);
                m.extend_from_slice(&qtype.to_be_bytes());
                m.extend_from_slice(&[0, 1]);
                m.extend_from_slice(&(rng.next() as u32 % 86_400).to_be_bytes());
                m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                m.extend_from_slice(&rdata);
            }
        }
        out.push((query, m));
    }
    out
}

/// mDNS (5353) as the host's avahi writes it: id 0 always. A query holds one to
/// three questions (PTR or ANY, the unicast-response bit now and then) and
/// sometimes known answers; a response holds one to four answer records and up
/// to three additional ones (SRV, TXT, A, AAAA) with the cache-flush bit.
fn mdns_datagrams(rng: &mut Lcg, n: usize) -> Vec<(bool, Vec<u8>)> {
    const SERVICES: [&str; 8] = [
        "_services._dns-sd._udp.local",
        "_http._tcp.local",
        "_googlecast._tcp.local",
        "_workstation._tcp.local",
        "_ssh._tcp.local",
        "_ipp._tcp.local",
        "_airplay._tcp.local",
        "_someip._udp.local",
    ];
    let record = |rng: &mut Lcg, kind: u16| -> Vec<u8> {
        let owner = if kind == 12 {
            dns_name(pick(rng, &SERVICES))
        } else {
            dns_name(&alloc::format!("host-{}.local", rng.below(40)))
        };
        let rdata = match kind {
            1 => rand_bytes(rng, 4),
            28 => rand_bytes(rng, 16),
            12 => dns_name(&alloc::format!(
                "inst-{}.{}",
                rng.below(40),
                pick(rng, &SERVICES)
            )),
            33 => {
                let mut r = vec![0, 0, 0, 0, 0x1F, 0x90];
                r.extend_from_slice(&dns_name(&alloc::format!("host-{}.local", rng.below(40))));
                r
            }
            _ => {
                let text = alloc::format!("txtvers=1 id={}", hex_text(rng, 12));
                let mut r = vec![text.len() as u8];
                r.extend_from_slice(text.as_bytes());
                r
            }
        };
        let mut m = owner;
        m.extend_from_slice(&kind.to_be_bytes());
        m.extend_from_slice(&[0x80, 0x01]);
        m.extend_from_slice(&(*pick(rng, &[120u32, 4500])).to_be_bytes());
        m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        m.extend_from_slice(&rdata);
        m
    };
    let mut out = Vec::new();
    for _ in 0..n {
        let from_dialer = rng.below(2) == 0;
        let mut m = vec![0, 0];
        if rng.below(2) == 0 {
            let questions = 1 + rng.below(3) as u16;
            let known = if rng.below(4) == 0 {
                rng.below(3) as u16
            } else {
                0
            };
            m.extend_from_slice(&[0, 0]);
            m.extend_from_slice(&questions.to_be_bytes());
            m.extend_from_slice(&[0, 0]);
            m.extend_from_slice(&known.to_be_bytes());
            m.extend_from_slice(&[0, 0, 0, 0]);
            for _ in 0..questions {
                m.extend_from_slice(&dns_name(pick(rng, &SERVICES)));
                m.extend_from_slice(&(*pick(rng, &[12u16, 12, 255])).to_be_bytes());
                m.extend_from_slice(&(*pick(rng, &[1u16, 0x8001])).to_be_bytes());
            }
            for _ in 0..known {
                m.extend_from_slice(&record(rng, 12));
            }
        } else {
            let answers = 1 + rng.below(4) as u16;
            let extra = rng.below(4) as u16;
            m.extend_from_slice(&[0x84, 0, 0, 0]);
            m.extend_from_slice(&answers.to_be_bytes());
            m.extend_from_slice(&[0, 0]);
            m.extend_from_slice(&extra.to_be_bytes());
            for _ in 0..answers {
                let kind = *pick(rng, &[12u16, 12, 33, 16, 1]);
                m.extend_from_slice(&record(rng, kind));
            }
            for _ in 0..extra {
                let kind = *pick(rng, &[33u16, 16, 1, 28]);
                m.extend_from_slice(&record(rng, kind));
            }
        }
        out.push((from_dialer, m));
    }
    out
}

/// SSDP (1900), text over UDP: an M-SEARCH from the dialer, answered by a 200
/// OK or announced by a NOTIFY, with a fresh USN, LOCATION and max-age each time.
fn ssdp_datagrams(rng: &mut Lcg, n: usize) -> Vec<(bool, Vec<u8>)> {
    let mut out = Vec::new();
    for i in 0..n {
        let uuid = alloc::format!(
            "uuid:{}-{}-{}-{}-{}",
            hex_text(rng, 8),
            hex_text(rng, 4),
            hex_text(rng, 4),
            hex_text(rng, 4),
            hex_text(rng, 12)
        );
        let target = *pick(
            rng,
            &[
                "ssdp:all",
                "upnp:rootdevice",
                "urn:schemas-upnp-org:device:MediaServer:1",
                "urn:dial-multiscreen-org:service:dial:1",
            ],
        );
        let location = alloc::format!(
            "http://192.168.{}.{}:{}/desc.xml",
            rng.below(256),
            rng.below(256),
            1024 + rng.below(60_000)
        );
        let age = *pick(rng, &[120u32, 1800, 3600]);
        let (from_dialer, text) = match (i % 3, rng.below(2)) {
            (0, _) => (
                true,
                alloc::format!(
                    "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: {}\r\nST: {target}\r\n\r\n",
                    1 + rng.below(5)
                ),
            ),
            (_, 0) => (
                false,
                alloc::format!(
                    "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age={age}\r\nEXT:\r\nLOCATION: {location}\r\nSERVER: Linux/5.15 UPnP/1.0 Dev/1.0\r\nST: {target}\r\nUSN: {uuid}::{target}\r\n\r\n"
                ),
            ),
            (_, _) => (
                false,
                alloc::format!(
                    "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age={age}\r\nLOCATION: {location}\r\nNT: {target}\r\nNTS: ssdp:alive\r\nSERVER: Linux/5.15 UPnP/1.0 Dev/1.0\r\nUSN: {uuid}::{target}\r\n\r\n"
                ),
            ),
        };
        out.push((from_dialer, text.into_bytes()));
    }
    out
}

/// NTP (123): 48 bytes, a client request (version 3 or 4, mode 3, only the
/// transmit time set) answered by a server reply (stratum 2 or 3, fresh
/// timestamps near the 2026 era).
fn ntp_datagrams(rng: &mut Lcg, n: usize) -> Vec<(bool, Vec<u8>)> {
    let era = |rng: &mut Lcg| -> Vec<u8> {
        let mut t = (0xEC00_0000u32 + rng.next() as u32 % 0x0100_0000)
            .to_be_bytes()
            .to_vec();
        t.extend_from_slice(&rand_bytes(rng, 4));
        t
    };
    let mut out = Vec::new();
    for i in 0..n {
        let client = i % 2 == 0;
        let mut m = vec![0u8; 48];
        if client {
            m[0] = *pick(rng, &[0x23u8, 0x23, 0x23, 0x1B]);
            m[40..48].copy_from_slice(&era(rng));
        } else {
            m[0] = *pick(rng, &[0x24u8, 0x24, 0x1C]);
            m[1] = *pick(rng, &[2u8, 3]);
            m[2] = 6;
            m[3] = 0xEC;
            m[4..8].copy_from_slice(&(rng.next() as u32 % 0x0001_0000).to_be_bytes());
            m[8..12].copy_from_slice(&(rng.next() as u32 % 0x0001_0000).to_be_bytes());
            m[12..16].copy_from_slice(&rand_bytes(rng, 4));
            for at in [16, 24, 32, 40] {
                m[at..at + 8].copy_from_slice(&era(rng));
            }
        }
        out.push((client, m));
    }
    out
}

/// CoAP (5683): a confirmable GET with a token of 0, 2, 4 or 8 bytes and a
/// Uri-Path, answered by an ACK 2.05 that echoes message id and token and
/// carries a JSON payload; one in four requests is a non-confirmable one.
fn coap_datagrams(rng: &mut Lcg, n: usize) -> Vec<(bool, Vec<u8>)> {
    let mut out = Vec::new();
    let (mut mid, mut token) = (0u16, Vec::new());
    for i in 0..n {
        let request = i % 2 == 0;
        let non = request && rng.below(4) == 0;
        if request {
            mid = rng.next() as u16;
            let len = *pick(rng, &[0usize, 2, 4, 8]);
            token = rand_bytes(rng, len);
        }
        let kind: u8 = if non {
            1
        } else if request {
            0
        } else {
            2
        };
        let mut m = vec![0x40 | kind << 4 | token.len() as u8];
        m.push(if request { 0x01 } else { 0x45 });
        m.extend_from_slice(&mid.to_be_bytes());
        m.extend_from_slice(&token);
        if request {
            let path = *pick(rng, &["sensors", "temp", "status", "light"]);
            m.push(0xB0 | path.len() as u8);
            m.extend_from_slice(path.as_bytes());
        } else {
            m.extend_from_slice(&[0xC1, 0x32, 0xFF]);
            let body = alloc::format!("{{\"t\":{}.{}}}", 10 + rng.below(30), rng.below(10));
            m.extend_from_slice(body.as_bytes());
        }
        out.push((request, m));
    }
    out
}

/// syslog (514) from the dialer only: RFC 3164 (`<PRI>Mon dd hh:mm:ss host
/// app[pid]: text`) or RFC 5424 (`<PRI>1 timestamp host app pid msgid - text`).
fn syslog_datagrams(rng: &mut Lcg, n: usize) -> Vec<(bool, Vec<u8>)> {
    const WORDS: [&str; 8] = [
        "started",
        "stopped",
        "connection",
        "accepted",
        "failed",
        "timeout",
        "session",
        "link",
    ];
    let mut out = Vec::new();
    for _ in 0..n {
        let pri = *pick(rng, &[13u32, 14, 30, 34, 38, 86, 134, 165]);
        let host = alloc::format!("ecu{}", rng.below(8));
        let app = *pick(
            rng,
            &["sshd", "systemd", "avahi-daemon", "kernel", "dhclient"],
        );
        let pid = 100 + rng.below(30_000);
        let text = alloc::format!(
            "{} {} {} {}",
            pick(rng, &WORDS),
            pick(rng, &WORDS),
            pick(rng, &WORDS),
            rng.below(1000)
        );
        let (h, m, s) = (rng.below(24), rng.below(60), rng.below(60));
        let line = if rng.below(2) == 0 {
            alloc::format!(
                "<{pri}>Oct {:>2} {h:02}:{m:02}:{s:02} {host} {app}[{pid}]: {text}",
                1 + rng.below(28)
            )
        } else {
            alloc::format!(
                "<{pri}>1 2026-10-{:02}T{h:02}:{m:02}:{s:02}Z {host} {app} {pid} ID{} - {text}",
                1 + rng.below(28),
                rng.below(100)
            )
        };
        out.push((true, line.into_bytes()));
    }
    out
}

/// A flow of structured datagrams on the protocol's own ports, dissected as a
/// capture file is: its `zenoh` word, `(explained, residual, undecoded)` units,
/// and the units.
fn read_structured_flow(
    datagrams: &[(bool, Vec<u8>)],
    sport: u16,
    dport: u16,
) -> (ZenohVerdict, u64, u64, u64, u64) {
    let mut packets = Packets::default();
    for (i, (from_dialer, wire)) in datagrams.iter().enumerate() {
        let packet = if *from_dialer {
            udp_packet(LOW, sport, HIGH, dport, wire)
        } else {
            udp_packet(HIGH, dport, LOW, sport, wire)
        };
        packets.push(T0 + i as u64 * 1_000, packet);
    }
    let d = packets.dissect();
    let table = session_table(&d);
    let row = only(&table);
    let readings = row.readings;
    (
        word(row.evidence),
        readings.explained.units,
        readings.residual.units,
        readings.undecoded.units,
        readings.units(),
    )
}

/// WHAT STRUCTURED, NON-ZENOH DATAGRAMS READ AS (measured 2026-10-26, answering
/// the question the random table above leaves open: structured bytes do not
/// read like random ones, since a protocol whose first byte is fixed reads the
/// same way every time).
///
/// The datagrams are GENERATED, not captured: each builder above writes the
/// protocol's real layout (field order, flags, lengths, name compression, text
/// headers) and draws the free fields (ids, tokens, hosts, addresses,
/// timestamps, record counts and kinds) from the seeded generator. Where the
/// protocol has two directions the flow alternates them as the protocol does
/// (query and reply, request and ACK), and mDNS picks the direction by chance
/// as a multicast group does. The ports are the protocol's own. A generator
/// holds a population's shape and not its real spread: a device whose first byte
/// differs from the one written here, or a vendor extension, reads differently,
/// so each row is what that layout reads as, not a measurement of every device
/// that speaks the protocol.
///
/// Per protocol, 600 seeded flows of `n` datagrams each, the share being
/// `explained` units over all units. Columns: mean, p95, p99, max, and the number
/// of the 600 flows at or above 0.5.
///
/// | n | mDNS | DNS | CoAP | NTP | SSDP, syslog |
/// |---|---|---|---|---|---|
/// | 1 | 0.185 / 1.00 / 1.00 / 1.00 / 111 | 0.060 / 1.00 / 1.00 / 1.00 / 36 | 0.002 / 0 / 0 / 1.00 / 1 | 0 / 0 / 0 / 0 / 0 | 0 |
/// | 2 | 0.158 / 0.50 / 1.00 / 1.00 / 171 | 0.066 / 1.00 / 1.00 / 1.00 / 42 | 0.120 / 0.50 / 0.50 / 0.50 / 144 | 0.012 / 0 / 0.50 / 0.50 / 14 | 0 |
/// | 3 | 0.166 / 0.67 / 0.67 / 1.00 / 43 | 0.067 / 0.67 / 0.67 / 1.00 / 39 | 0.082 / 0.33 / 0.33 / 0.33 / 0 | 0.010 / 0 / 0.33 / 0.33 / 0 | 0 |
/// | 5 | 0.168 / 0.40 / 0.60 / 0.80 / 22 | 0.081 / 0.40 / 0.40 / 0.80 / 6 | 0.103 / 0.40 / 0.40 / 0.40 / 0 | 0.008 / 0 / 0.20 / 0.20 / 0 | 0 |
/// | 10 | 0.164 / 0.40 / 0.40 / 0.50 / 5 | 0.078 / 0.40 / 0.40 / 0.60 / 2 | 0.135 / 0.30 / 0.40 / 0.50 / 1 | 0.012 / 0.10 / 0.10 / 0.20 / 0 | 0 |
/// | 20 | 0.164 / 0.30 / 0.35 / 0.45 / 0 | 0.070 / 0.20 / 0.30 / 0.30 / 0 | 0.129 / 0.25 / 0.30 / 0.40 / 0 | 0.011 / 0.05 / 0.10 / 0.15 / 0 | 0 |
/// | 50 | 0.160 / 0.24 / 0.30 / 0.32 / 0 | 0.071 / 0.16 / 0.20 / 0.28 / 0 | 0.132 / 0.20 / 0.24 / 0.26 / 0 | 0.010 / 0.04 / 0.06 / 0.06 / 0 | 0 |
///
/// Each cell reads mean / p95 / p99 / max / flows at or above 0.5 (SSDP and
/// syslog read every unit `undecoded`, 54600 of 54600 each, so their cell is
/// zero throughout). Over all 54600 datagrams of a protocol the three classes
/// split `explained` / `residual` / `undecoded` as: mDNS 8847 / 45753 / 0, DNS
/// 3926 / 5927 / 44747, CoAP 6929 / 11796 / 35875, NTP 575 / 38160 / 15865.
///
/// What it says against the random table (n = 10: mean 0.061, max 0.40):
///
/// * A flow of ten or more datagrams CAN reach a share of 0.5 on structured
///   bytes that are not zenoh: mDNS in 5 of 600 flows of ten, DNS in 2 (up to
///   0.60) and CoAP in 1. None does at twenty or more, where the widest is mDNS
///   at 0.45 (n = 20) and 0.32 (n = 50). So a sentence bounded by "ten units,
///   half read whole" is crossed by real protocols, and one bounded by twenty is
///   not, with a margin of 0.05 at its narrowest.
/// * The mean share is no better than random: mDNS and CoAP sit at 0.16 and
///   0.13 against random's 0.06. The mDNS id is always 0, so every datagram
///   starts with the same byte pair and reads the same way: 84% `residual`, 16%
///   `explained`, never `undecoded`. The unit count does not separate it from
///   zenoh as well as it separates random bytes.
/// * The share alone is no verdict, and the sequential test does not read it as
///   one: see `the_sequential_test_says_yes_to_no_generated_flow_of_another_protocol`.
#[test]
fn structured_datagrams_of_other_protocols_read_by_their_first_byte() {
    for (name, build, sport, dport) in structured_protocols() {
        let mut all = (0u64, 0u64, 0u64);
        let mut rows = Vec::new();
        for n in [1usize, 2, 3, 5, 10, 20, 50] {
            let mut rng = Lcg(0x57A7 + n as u64);
            let mut shares = Vec::new();
            for _ in 0..600 {
                let datagrams = build(&mut rng, n);
                let (_, e, r, u, units) = read_structured_flow(&datagrams, sport, dport);
                assert_eq!(units, n as u64, "{name}: one unit per datagram");
                all = (all.0 + e, all.1 + r, all.2 + u);
                shares.push(e as f64 / n as f64);
            }
            shares.sort_by(f64::total_cmp);
            let at = |q: f64| shares[((shares.len() as f64 * q).ceil() as usize).max(1) - 1];
            let mean = shares.iter().sum::<f64>() / shares.len() as f64;
            let over = shares.iter().filter(|s| **s >= 0.5).count();
            rows.push((n, mean, at(0.95), at(0.99), at(1.0), over));
        }
        // A failing bound prints the protocol's whole row set, so the table
        // above is regenerated from the message and not from a debugger.
        let rows_text = alloc::format!("{name}: {all:?}: {rows:?}");
        for (n, mean, _, _, max, over) in &rows {
            if *n >= 20 {
                assert!(
                    *max < 0.5,
                    "{name} reached a share of {max} at {n} datagrams: {rows_text}"
                );
            }
            assert!(*max <= 1.0 && *mean < 0.25, "{rows_text}");
            if *n == 10 {
                assert!(*max <= 0.7 && *over <= 30, "{rows_text}");
            }
        }
        match name {
            "ssdp" | "syslog" => assert_eq!(all.0 + all.1, 0, "text reads undecoded: {rows_text}"),
            "mdns" => {
                let ten = rows.iter().find(|r| r.0 == 10).unwrap();
                assert!(ten.5 >= 1, "mdns no longer reaches 0.5 at ten: {rows_text}");
                assert_eq!(all.2, 0, "{rows_text}");
            }
            _ => {}
        }
    }
}

/// The generated protocols, with the ports each speaks on.
type StructuredBuilder = fn(&mut Lcg, usize) -> Vec<(bool, Vec<u8>)>;
fn structured_protocols() -> [(&'static str, StructuredBuilder, u16, u16); 6] {
    [
        ("mdns", mdns_datagrams, 5353, 5353),
        ("ssdp", ssdp_datagrams, 43_210, 1900),
        ("dns", dns_datagrams, 43_210, 53),
        ("ntp", ntp_datagrams, 43_210, 123),
        ("coap", coap_datagrams, 43_210, 5683),
        ("syslog", syslog_datagrams, 43_210, 514),
    ]
}

/// THE SEQUENTIAL TEST OVER THE GENERATED CORPUS: the same 600 flows per
/// protocol and per length as the table above, read for their verdict.
///
/// No flow of any generated protocol is `yes`, at any length. This is the
/// corpus model 1's unit weights were taken from, so the result is the
/// composite null's bound holding on its own population and not a measurement
/// against protocols outside it.
///
/// Flows of the 600 that read `no`, measured 2026-10-26 (every other flow is
/// `undecided`; one or two datagrams never decide):
///
/// | n | mDNS | SSDP | DNS | NTP | CoAP | syslog |
/// |---|---|---|---|---|---|---|
/// | 3 | 349 | 600 | 521 | 582 | 452 | 600 |
/// | 5 | 486 | 600 | 507 | 600 | 557 | 600 |
/// | 10 | 600 | 600 | 599 | 600 | 600 | 600 |
/// | 20, 50 | 600 | 600 | 600 | 600 | 600 | 600 |
///
/// The bound held below is the measurement at twenty and fifty, where every
/// flow is `no`; the run prints the whole table.
#[test]
fn the_sequential_test_says_yes_to_no_generated_flow_of_another_protocol() {
    for (name, build, sport, dport) in structured_protocols() {
        let mut rows = Vec::new();
        let mut yes = 0u64;
        for n in [1usize, 2, 3, 5, 10, 20, 50] {
            let mut rng = Lcg(0x57A7 + n as u64);
            let (mut said_yes, mut said_no) = (0u64, 0u64);
            for _ in 0..600 {
                let (verdict, ..) = read_structured_flow(&build(&mut rng, n), sport, dport);
                said_yes += u64::from(verdict == ZenohVerdict::Yes);
                said_no += u64::from(verdict == ZenohVerdict::No);
            }
            yes += said_yes;
            rows.push((n, said_yes, said_no));
        }
        std::println!("{name} (n, yes, no) of 600: {rows:?}");
        assert_eq!(yes, 0, "{name} (n, yes, no): {rows:?}");
        for (n, _, said_no) in &rows {
            if *n >= 20 {
                assert_eq!(*said_no, 600, "{name} at {n} (n, yes, no): {rows:?}");
            }
        }
    }
}

/// THE ONE WAY STRUCTURED BYTES OF ANOTHER PROTOCOL WERE `proven` before the
/// sequential test (measured 2026-10-26, 2 of 4200 generated DNS flows, none of
/// the 4200 of any other protocol): a DNS id is two random bytes, and an id of
/// `0x6109` or `0x4709` writes a Scout or a Join header followed by the
/// protocol version, which the reader accepts. The datagram holds one such
/// header and nothing else of zenoh.
///
/// Under the test it is one header and one unit read whole, `2603 + 8000`
/// millibits, which is `undecided`: a lone header is not a session.
#[test]
fn a_dns_datagram_whose_id_reads_as_a_join_header_is_undecided() {
    for id in [0x6109u16, 0x4709] {
        let mut wire = id.to_be_bytes().to_vec();
        wire.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        wire.extend_from_slice(&dns_name("update.example.com"));
        wire.extend_from_slice(&[0, 1, 0, 1]);
        let (verdict, ..) = read_structured_flow(&[(true, wire)], 43_210, 53);
        assert_eq!(verdict, ZenohVerdict::Undecided, "id {id:#06x}");
    }
}

/// ARBITRARY BYTES ON A STREAM FORM NO UNIT AT ALL: the framing this reader
/// applies to a zenoh stream refuses a header no sender could have written, so
/// the bytes are skipped while it resynchronises and are not units. Five seeded
/// streams of forty random writes each count zero in every class, where a
/// session joined after its handshake counts every unit it carries.
#[test]
fn arbitrary_bytes_on_a_stream_form_no_unit() {
    for seed in 0..5u64 {
        let mut rng = Lcg(0xFEED + seed);
        let mut packets = Packets::default();
        let mut tcp = Tcp::new(true, 43210);
        for i in 0..40 {
            let len = 1 + rng.below(300);
            let wire: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            tcp.send(&mut packets, T0 + i * 1_000, true, &wire);
        }
        let d = packets.dissect();
        let table = session_table(&d);
        assert_eq!(
            only(&table).readings.units(),
            0,
            "seed {seed}: random stream bytes are not framing units"
        );
    }
    let (packets, _) = midstream_tcp(40);
    let d = packets.dissect();
    let table = session_table(&d);
    assert_eq!(only(&table).readings.explained.units, 40);
}

/// The repository's own captures, read for what they are: every flow whose
/// session the capture holds or joined mid-stream reads every unit as
/// explained, and the one capture of a COMPRESSED session reads two of its six
/// units as undecoded, because this reader refuses the compressed batch (with
/// the `compression` feature it reads one of them, and one stays undecoded). A real
/// zenoh session can read `undecoded`, which is why a unit is weighed and not
/// counted as a verdict: the compressed session is `yes` either way. Without
/// lz4 the two refused batches are not weighed at all, because a build that
/// cannot open lz4 refuses every lz4 batch; with it, the damaged one weighs
/// against the flow.
#[test]
fn the_repositorys_captures_read_as_what_they_are() {
    let read = |bytes: &[u8]| {
        let d = Dissection::from_capture(bytes).expect("the capture reads");
        d.datagram_flows()
            .iter()
            .map(|flow| (word(flow.zenoh_evidence()), flow.ingest.readings()))
            .collect::<Vec<_>>()
    };
    // A session joined after its handshake: two explained units and no Init,
    // `undecided`.
    let midsession = read(include_bytes!(
        "../../../captures/fragmented-push-midsession-and-established.pcap"
    ));
    let joined = midsession
        .iter()
        .find(|(verdict, _)| *verdict == ZenohVerdict::Undecided)
        .expect("the capture holds a flow it joined after the handshake");
    assert_eq!(joined.1.explained, tally(2, 144));
    assert_eq!(joined.1.units(), 2);

    // The raweth capture is seven units with one version header and one SN
    // break: about ten and a half bits for `yes`, which model 2 does not call
    // (model 1 did, on a unit weight the real mDNS of the corpus beats). A
    // unit read whole is weak evidence against a protocol that reads whole a
    // third of the time.
    for (name, bytes, want) in [
        (
            "publisher",
            &include_bytes!("../../../captures/publisher-priority-encoding-timestamp.pcap")[..],
            ZenohVerdict::Yes,
        ),
        (
            "raweth",
            &include_bytes!("../../../captures/raweth-transport-messages.pcap")[..],
            ZenohVerdict::Undecided,
        ),
    ] {
        for (verdict, readings) in read(bytes) {
            assert_eq!(verdict, want, "{name}");
            assert!(readings.units() > 0, "{name}");
            assert_eq!(readings.explained.units, readings.units(), "{name}");
        }
    }
    // Every flow of the scouting capture is one Scout or one Hello: a header and
    // a unit read whole, which is not a session, and the word is `undecided`.
    for (verdict, readings) in read(include_bytes!(
        "../../../captures/scout-and-hello-ipv4-ipv6.pcap"
    )) {
        assert_eq!(readings.units(), 1, "scouting");
        assert_eq!(readings.explained.units, 1, "scouting");
        assert_eq!(verdict, ZenohVerdict::Undecided, "scouting");
    }

    let compressed = read(include_bytes!(
        "../../../captures/compressed-session-refused-body.pcap"
    ));
    let flow = compressed.first().expect("one flow");
    assert_eq!(flow.0, ZenohVerdict::Yes);
    // Whether the batch is read depends on the reader's `compression` feature: off, the two
    // compressed units are refused and read `undecoded`; on, one of them reads and its bytes
    // are the decompressed ones.
    if cfg!(feature = "compression") {
        assert_eq!(flow.1.explained, tally(5, 289));
        assert_eq!(flow.1.undecoded, tally(1, 37));
    } else {
        assert_eq!(flow.1.explained, tally(4, 26));
        assert_eq!(flow.1.undecoded, tally(2, 74));
    }
    assert_eq!(flow.1.residual, tally(0, 0));
}

/// The document says it, on the row and on every flow of it, in the shape the
/// header declares.
#[test]
fn the_document_carries_the_readings_on_a_row_and_on_each_flow() {
    let (packets, _) = midstream_tcp(7);
    let d = packets.dissect();
    let doc = session_table_json(&d);
    let readings = "\"unit_readings\":{\"explained\":{\"units\":7,\"bytes\":7},\
                    \"residual\":{\"units\":0,\"bytes\":0},\
                    \"undecoded\":{\"units\":0,\"bytes\":0}}";
    assert_eq!(doc.matches(readings).count(), 2, "{doc}");
}
