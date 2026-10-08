// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2517 (open-debt item 713) — THE captures a consumer of this crate can be
//! graded against, as ONE definition.
//!
//! # Why this module exists
//!
//! Item 713 is about a keyexpr id declared on one link of a session and
//! referenced on the other. Every plane in this crate now resolves that
//! correctly, and each is graded by a fixture built inside its own `#[cfg(test)]`
//! module. `wz-analyze` renders the same dissections through two listings of its
//! own, and NOTHING grades those: measured, its 66 lib tests build no capture at
//! all and its 70 binary tests drive captures heavily while never once naming a
//! second link. That is the trap in its most convincing dress — not "nobody
//! tested it" but "everybody tested it on the shape that cannot fail".
//!
//! A guard there needs this crate's capture, and a `#[cfg(test)]` fixture cannot
//! cross a crate boundary. So the capture is defined HERE, once, and both sides
//! use it.
//!
//! # What is duplicated, and what deliberately is not
//!
//! The packet plumbing below — the IPv4 checksum, the UDP frame, the INIT wire —
//! is a second spelling of helpers that live in this crate's test modules. That
//! is accepted, and the alternative was weighed: widening those modules to
//! `#[cfg(any(test, feature = "fixtures"))]` drags their TESTS into ordinary
//! builds along with the `cfg(test)`-only scaffolding they lean on, which is a
//! larger and more fragile change than re-spelling fifty lines of byte layout.
//!
//! What is NOT duplicated is the thing that matters: the CAPTURE. Which links
//! exist, which one carries the declaration, and which packet order they go out
//! in are stated once, here. Two definitions of that is how two fixtures come to
//! disagree about which link is walked first, and then one of them quietly stops
//! testing what its name says.

use alloc::string::String;
use alloc::vec::Vec;

use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
use wz_codecs::wireexpr_local::WireexprLocal;

/// The low endpoint of every link these fixtures build.
const LOW: [u8; 4] = [10, 0, 0, 1];
/// The high endpoint — the peer that answers each handshake.
const HIGH: [u8; 4] = [10, 0, 0, 2];
/// The zid the dialling side names itself with.
const ZID_A: &[u8] = &[0xA1, 0xA1, 0xA1, 0xA1];
/// The zid the answering side names itself with.
const ZID_B: &[u8] = &[0xB2, 0xB2, 0xB2, 0xB2];

/// The keyexpr id these fixtures declare on one link and reference on the other.
pub const ALIAS_ID: u64 = 7;

/// The literal `ALIAS_ID` is bound to. A guard asserts a document names THIS.
pub const ALIAS_LITERAL: &str = "demo/temp";

/// One's-complement sum, for the IPv4 header checksum below.
fn ones_complement(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for part in parts {
        let mut chunks = part.chunks_exact(2);
        for c in &mut chunks {
            sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
        if let [last] = chunks.remainder() {
            sum += u32::from(u16::from_be_bytes([*last, 0]));
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// A UDP-over-IPv4-over-Ethernet frame carrying `payload`.
///
/// The IPv4 header checksum is real; the UDP one stays zero, which over IPv4 is
/// the sender declining to compute it (RFC 768) rather than a broken frame.
fn udp_packet(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut udp = Vec::new();
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes());
    udp.extend_from_slice(payload);

    let mut ip = alloc::vec![0x45u8, 0];
    ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let checksum = ones_complement(&[&ip]);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    ip.extend_from_slice(&udp);

    let mut eth = alloc::vec![0u8; 12];
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&ip);
    while eth.len() < 60 {
        eth.push(0);
    }
    eth
}

/// A transport INIT naming `zid` — one half of a handshake.
fn init_wire(zid: &[u8]) -> Vec<u8> {
    let mut wire = alloc::vec![
        wz_session_core::wire_const::T_MID_INIT,
        0x09,
        (((zid.len() as u8) - 1) << 4) | 0x02,
    ];
    wire.extend_from_slice(zid);
    wire
}

/// A `Frame` carrying one network record.
fn frame_carrying(record: &[u8]) -> Vec<u8> {
    let mut w = alloc::vec![wz_session_core::wire_const::T_MID_FRAME, 0x00];
    w.extend_from_slice(record);
    w
}

/// `M=1` — the id lives in the SENDER's own space.
fn sender_space(id: u64, suffix: Option<&'static str>) -> Wireexpr<'static> {
    Wireexpr {
        body: WireexprVariant::WireexprLocal(WireexprLocal {
            id,
            suffix_len: suffix.map(|s| s.len() as u64),
            suffix,
        }),
    }
}

/// A `DeclKexpr` binding `id` to `suffix` in the sender's space.
fn declare_kexpr(id: u64, suffix: &'static str) -> Vec<u8> {
    wz_codecs::declare::Declare {
        body: wz_codecs::declare::DeclareVariant::CodecZenohDeclKexpr(
            wz_codecs::decl_kexpr::DeclKexpr {
                header: wz_session_core::wire_const::D_MID_KEXPR
                    | wz_session_core::wire_const::FLAG_D_N,
                id,
                keyexpr: sender_space(0, Some(suffix)),
                extensions: None,
            },
        ),
        ..Default::default()
    }
    .encode_to_vec()
}

/// A `Push` under `keyexpr` carrying `payload`.
fn push(keyexpr: Wireexpr<'static>, payload: &'static [u8]) -> Vec<u8> {
    wz_codecs::push::Push {
        keyexpr,
        body: wz_codecs::push::PushVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
            payload_len: Some(payload.len() as u64),
            payload: Some(payload),
            ..Default::default()
        }),
        ..Default::default()
    }
    .encode_to_vec()
}

/// A two-sided handshake on one link, which is what makes it a LINK: A names
/// itself, then B does. One INIT proves nothing — see `crate::node`'s docs.
fn handshake(sport: u16, dport: u16) -> Vec<(bool, u16, u16, Vec<u8>)> {
    alloc::vec![
        (true, sport, dport, init_wire(ZID_A)),
        (false, sport, dport, init_wire(ZID_B)),
    ]
}

/// Build a capture out of `(from_low, sport, dport, record, framed)` rows, and
/// the pcap FILE those packets make.
///
/// The packet ORDER is the file order and the push index is the position in it,
/// which is what makes a re-read's `packet_index` agree with the first pass's.
fn capture(rows: &[(bool, u16, u16, Vec<u8>, bool)]) -> (crate::Dissection, Vec<u8>) {
    let mut d = crate::Dissection::new();
    let mut packets: Vec<Vec<u8>> = Vec::new();
    for (i, (from_low, sport, dport, record, framed)) in rows.iter().enumerate() {
        let wire = if *framed {
            frame_carrying(record)
        } else {
            record.clone()
        };
        let packet = if *from_low {
            udp_packet(LOW, *sport, HIGH, *dport, &wire)
        } else {
            udp_packet(HIGH, *dport, LOW, *sport, &wire)
        };
        d.push_packet(crate::link::LINKTYPE_ETHERNET, i, &packet);
        packets.push(packet);
    }
    d.finish();
    let refs: Vec<(u32, u32, &[u8])> = packets.iter().map(|p| (0u32, 0u32, p.as_slice())).collect();
    let file = crate::pcap::write(crate::link::LINKTYPE_ETHERNET, &refs);
    (d, file)
}

/// ONE session over TWO links, declaring `ALIAS_ID` on the link this crate walks
/// SECOND and referencing it on the one walked FIRST.
///
/// # The two orders this pulls apart, which is the whole fixture
///
/// On the WIRE the declaration comes FIRST — it is packet 4 and the reference is
/// packet 5 — so any reader honouring "a declaration names what follows it" must
/// resolve the reference. In the WALK it comes second, because
/// `Dissection::message_lists` yields the stream lists in `flows()` order and
/// this session's second link is the second row.
///
/// The flow order is FIXED by construction: both handshakes are pushed before
/// either link carries a record, so which link is walked first is a property of
/// this fixture and not of which port number is larger.
///
/// A reader that walks list by list has, for the flow it renders first, a
/// declaration that is still in the future — and reports the reference as
/// unresolved. That is item 713, as its consumer met it.
pub fn multilink_declaring_on_the_later_link() -> (crate::Dissection, Vec<u8>) {
    let mut rows: Vec<(bool, u16, u16, Vec<u8>, bool)> = Vec::new();
    for link in [(43210u16, 7447u16), (43211u16, 7447u16)] {
        for (from_low, sport, dport, wire) in handshake(link.0, link.1) {
            rows.push((from_low, sport, dport, wire, false));
        }
    }
    rows.push((
        true,
        43211,
        7447,
        declare_kexpr(ALIAS_ID, ALIAS_LITERAL),
        true,
    ));
    rows.push((
        true,
        43210,
        7447,
        push(sender_space(ALIAS_ID, None), &[0u8; 11]),
        true,
    ));
    capture(&rows)
}

/// The same capture with the two records SWAPPED: the reference goes out first
/// and its declaration only afterwards.
///
/// This is the OTHER half of the pair, and it grades the opposite error. A
/// reader that fixes the first fixture by absorbing every declaration up front
/// passes it and fails here, because absorbing ahead of rendering is exactly the
/// retroactive naming `crate::agg` refuses: a declaration must not name a
/// reference that preceded it. Only an ANCHORED binding
/// ([`crate::agg::KeyexprSpaces::at_packet`]) passes both.
pub fn multilink_declaring_after_the_reference() -> (crate::Dissection, Vec<u8>) {
    let mut rows: Vec<(bool, u16, u16, Vec<u8>, bool)> = Vec::new();
    for link in [(43210u16, 7447u16), (43211u16, 7447u16)] {
        for (from_low, sport, dport, wire) in handshake(link.0, link.1) {
            rows.push((from_low, sport, dport, wire, false));
        }
    }
    rows.push((
        true,
        43210,
        7447,
        push(sender_space(ALIAS_ID, None), &[0u8; 11]),
        true,
    ));
    rows.push((
        true,
        43211,
        7447,
        declare_kexpr(ALIAS_ID, ALIAS_LITERAL),
        true,
    ));
    capture(&rows)
}

/// An Ethernet/IPv4/TCP frame carrying `payload` at sequence number `seq`.
///
/// The IPv4 header checksum is real and the TCP one is left zero, so a reader
/// counts these segments in its transport-checksum tallies and decodes them
/// anyway; no fixture here reads that verdict. Padded to the 60-byte minimum.
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
    tcp.push(0x10); // ACK
    tcp.extend_from_slice(&64u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(payload);

    let mut ip = alloc::vec![0x45u8, 0];
    ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let checksum = ones_complement(&[&ip]);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    ip.extend_from_slice(&tcp);

    let mut eth = alloc::vec![0u8; 12];
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&ip);
    while eth.len() < 60 {
        eth.push(0);
    }
    eth
}

/// One message of a TCP stream: the two-byte little-endian length zenoh puts in
/// front of every transport message on a stream link, then the message.
fn stream_unit(wire: &[u8]) -> Vec<u8> {
    let mut out = (wire.len() as u16).to_le_bytes().to_vec();
    out.extend_from_slice(wire);
    out
}

/// [`chain_sequence_capture`]'s twin over a TCP STREAM link: one session that
/// carries `chains` completed fragment chains, one after the other, as the pcap
/// FILE.
///
/// A stream flow and a datagram flow are written by two different row loops, and
/// each carries its own chain fold, so a property of one is not a property of the
/// other. This is the capture that reaches the stream loop's.
pub fn stream_chain_sequence_capture(chains: usize) -> Vec<u8> {
    const ISN: u32 = 1000;
    const PORT: u16 = 43210;
    let record = push(sender_space(0, Some("chain/joined")), &[7u8; 8]);
    let split = record.len() / 2;
    let mut units = full_handshake()
        .into_iter()
        .map(|(from_low, wire)| (from_low, stream_unit(&wire)))
        .collect::<Vec<_>>();
    for chain in 0..chains {
        let sn = (2 * chain) as u8;
        units.push((
            true,
            stream_unit(&fragment_wire(sn, true, &record[..split])),
        ));
        units.push((
            true,
            stream_unit(&fragment_wire(sn + 1, false, &record[split..])),
        ));
    }
    // Each direction's sequence number advances by what that direction sent.
    let (mut low, mut high) = (ISN, ISN);
    let packets: Vec<Vec<u8>> = units
        .iter()
        .map(|(from_low, unit)| {
            let next = if *from_low { &mut low } else { &mut high };
            let seq = *next;
            *next += unit.len() as u32;
            if *from_low {
                tcp_segment(LOW, PORT, HIGH, 7447, seq, unit)
            } else {
                tcp_segment(HIGH, 7447, LOW, PORT, seq, unit)
            }
        })
        .collect();
    let refs: Vec<(u32, u32, &[u8])> = packets
        .iter()
        .enumerate()
        .map(|(i, p)| (0u32, (i as u32) * 1_000, p.as_slice()))
        .collect();
    crate::pcap::write(crate::link::LINKTYPE_ETHERNET, &refs)
}

/// When the segment that fills a gap arrives, in
/// [`multilink_declaration_behind_a_gap`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapFill {
    /// After the reference: the declaration is decoded LATER than a reference that
    /// followed it on the wire.
    AfterTheReference,
    /// Before the reference: the declaration is decoded first, as in order.
    BeforeTheReference,
    /// Never: the declaration is held until the reader gives up on the gap.
    Never,
}

/// ONE session over TWO TCP links whose declaration reaches the reader AFTER the
/// reference it names, although it was SENT before it.
///
/// # The two orders, again, and what this pulls apart
///
/// [`multilink_declaring_on_the_later_link`] separates the order a capture is
/// WALKED in from the order it was sent in. This separates the order it was sent
/// in from the order it was DECODED in, which UDP cannot: a datagram decodes the
/// moment it arrives. A TCP segment that arrives ahead of the one before it is
/// held until the gap fills, so the messages it carries are decoded LATER than
/// packets that arrived after it.
///
/// The declaration is the segment that arrives early. On the wire it is packet 4
/// and the reference on the other link is packet 5, so a reader honouring "a
/// declaration names what follows it" must resolve the reference — but the
/// declaration is not DECODED until packet 6 fills the gap, so a document taken
/// after packet 5 has to leave the reference unresolved and one taken after
/// packet 6 resolves it. That is the shape in which a row that was written once
/// reads differently later, and it is built here so a consumer can be graded on
/// it.
///
/// [`GapFill`] says when the packet that fills the gap arrives: after the
/// reference (the shape above), before it (the declaration is then decoded ahead
/// of the reference, as it is on every in-order capture, which is what a test of
/// a cursor that passes a declaration and writes the reference behind it needs),
/// or never, so the declaration stays held for as long as the reader waits and
/// only giving up on the gap (a feed being declared over) releases it.
///
/// `reference_in_a_chain` sends the reference as a completed FRAGMENT chain on
/// link 1 instead of as one `Frame`, so it reaches a reader as the row that
/// completed the chain and is read out of the JOINED buffer. That is a second
/// place a row consults the keyexpr table, and it has to be reachable to be
/// graded. Link 1 then opens with the whole four-message handshake, because a
/// chain is tracked only once an INIT-ACK has fixed the SN resolution.
///
/// # The packets, with `reference_in_a_chain == false`
///
/// 0. link 1, A to B: INIT (names A) 1. link 1, B to A: INIT (names B)
/// 2. link 2, A to B: INIT, which fixes the direction's first sequence number
///    3. link 2, B to A: INIT
/// 4. link 2, A to B: the DECLARATION, ahead of a KeepAlive that is not yet here
/// 5. link 1, A to B: the REFERENCE 6. link 2, A to B: that KeepAlive
///
/// With `reference_in_a_chain`, packets 0 and 1 are the whole handshake (four
/// packets) and the reference is two fragments. The KeepAlive is last under
/// [`GapFill::AfterTheReference`], directly after the declaration under
/// [`GapFill::BeforeTheReference`], and absent under [`GapFill::Never`].
pub fn multilink_declaration_behind_a_gap(fill: GapFill, reference_in_a_chain: bool) -> Vec<u8> {
    const ISN: u32 = 1000;
    const L1: u16 = 43210;
    const L2: u16 = 43211;
    // The next sequence number of each direction of each link, so the one
    // segment that is sent out of order is the only place a number is spelled.
    let mut next: Vec<((u16, bool), u32)> = Vec::new();
    let mut at = |port: u16, from_low: bool, len: usize| -> u32 {
        match next.iter_mut().find(|(key, _)| *key == (port, from_low)) {
            Some(slot) => {
                let seq = slot.1;
                slot.1 += len as u32;
                seq
            }
            None => {
                next.push(((port, from_low), ISN + len as u32));
                ISN
            }
        }
    };
    let segment = |port: u16, from_low: bool, seq: u32, unit: &[u8]| -> Vec<u8> {
        if from_low {
            tcp_segment(LOW, port, HIGH, 7447, seq, unit)
        } else {
            tcp_segment(HIGH, 7447, LOW, port, seq, unit)
        }
    };

    let init_a = stream_unit(&init_wire(ZID_A));
    let init_b = stream_unit(&init_wire(ZID_B));
    let keepalive = stream_unit(&[wz_session_core::wire_const::T_MID_KEEP_ALIVE]);
    let declaration = stream_unit(&frame_carrying(&declare_kexpr(ALIAS_ID, ALIAS_LITERAL)));
    let reference = push(sender_space(ALIAS_ID, None), &[0u8; 11]);

    let mut packets: Vec<Vec<u8>> = Vec::new();
    // Link 1's opening. A chain needs the whole handshake; a lone frame needs
    // only the two INITs that make the link a link.
    if reference_in_a_chain {
        for (from_low, wire) in full_handshake() {
            let unit = stream_unit(&wire);
            packets.push(segment(L1, from_low, at(L1, from_low, unit.len()), &unit));
        }
    } else {
        packets.push(segment(L1, true, at(L1, true, init_a.len()), &init_a));
        packets.push(segment(L1, false, at(L1, false, init_b.len()), &init_b));
    }
    // Link 2: both INITs, then the declaration one segment AHEAD of where the
    // stream has got to.
    packets.push(segment(L2, true, at(L2, true, init_a.len()), &init_a));
    packets.push(segment(L2, false, at(L2, false, init_b.len()), &init_b));
    let gap_at = at(L2, true, keepalive.len());
    packets.push(segment(
        L2,
        true,
        gap_at + keepalive.len() as u32,
        &declaration,
    ));
    if fill == GapFill::BeforeTheReference {
        packets.push(segment(L2, true, gap_at, &keepalive));
    }
    // The reference, on link 1.
    if reference_in_a_chain {
        let split = reference.len() / 2;
        for (sn, more, piece) in [
            (0u8, true, &reference[..split]),
            (1, false, &reference[split..]),
        ] {
            let unit = stream_unit(&fragment_wire(sn, more, piece));
            packets.push(segment(L1, true, at(L1, true, unit.len()), &unit));
        }
    } else {
        let unit = stream_unit(&frame_carrying(&reference));
        packets.push(segment(L1, true, at(L1, true, unit.len()), &unit));
    }
    if fill == GapFill::AfterTheReference {
        packets.push(segment(L2, true, gap_at, &keepalive));
    }
    let refs: Vec<(u32, u32, &[u8])> = packets
        .iter()
        .enumerate()
        .map(|(i, p)| (0u32, (i as u32) * 1_000, p.as_slice()))
        .collect();
    crate::pcap::write(crate::link::LINKTYPE_ETHERNET, &refs)
}

/// ONE unicast session over UDP whose only record arrives as a
/// COMPLETED fragment chain, as the pcap FILE, with the record it carries.
///
/// For a consumer of this crate that grades a door over the joined buffer: the
/// buffer the chain is joined in must equal the record that was split, and the
/// record is handed back so the comparison needs no knowledge of the split.
///
/// The handshake is the whole four-message exchange rather than
/// `handshake`'s two Inits: the chain is read on the ring the InitAck fixed,
/// the way a consumer reads a session whose handshake the capture holds. A
/// capture with no InitAck follows a chain only on steps of plain `+1`, and
/// says so in the field document's `context.sn_mask` being `null`.
pub fn completed_chain_capture() -> (Vec<u8>, Vec<u8>) {
    let record = push(sender_space(0, Some("chain/joined")), &[7u8; 8]);
    (chain_sequence_capture(1), record)
}

/// The four-message handshake half `chain_sequence_capture` and
/// `completed_chain_capture` open with: INIT, INIT-ACK, OPEN, OPEN-ACK.
///
/// Whole messages and not `handshake`'s two INITs, because a fragment chain is
/// tracked only once an INIT-ACK has fixed the SN resolution.
fn full_handshake() -> Vec<(bool, Vec<u8>)> {
    let init = |is_ack: bool| {
        let flags = if is_ack {
            wz_codecs::wire_const::FLAG_T_INIT_A
        } else {
            0
        };
        let mut wire = alloc::vec![flags | wz_session_core::wire_const::T_MID_INIT];
        let body = wz_codecs::init_body::InitBody {
            version: 0x09,
            cbyte: 0x31,
            zid: if is_ack { ZID_B } else { ZID_A },
            sn_res: None,
            batch_size: None,
            cookie_len: if is_ack { Some(0) } else { None },
            cookie: if is_ack { Some(&[]) } else { None },
        };
        wire.extend_from_slice(&body.encode_to_vec(0, u8::from(is_ack)));
        wire
    };
    let open = |is_ack: bool| {
        let flags = if is_ack {
            wz_codecs::wire_const::FLAG_T_OPEN_A
        } else {
            0
        };
        let mut wire = alloc::vec![flags | wz_session_core::wire_const::T_MID_OPEN];
        wire.extend_from_slice(
            &wz_codecs::open_body::OpenBody {
                lease: 10_000,
                initial_sn: 0,
                cookie_len: if is_ack { None } else { Some(0) },
                cookie: if is_ack { None } else { Some(&[]) },
            }
            .encode_to_vec(u8::from(is_ack)),
        );
        wire
    };
    alloc::vec![
        (true, init(false)),
        (false, init(true)),
        (true, open(false)),
        (false, open(true)),
    ]
}

/// One reliable-channel FRAGMENT with sequence number `sn`, carrying `piece`.
fn fragment_wire(sn: u8, more: bool, piece: &[u8]) -> Vec<u8> {
    let mut wire = alloc::vec![
        wz_session_core::wire_const::T_MID_FRAGMENT
            | wz_codecs::wire_const::FLAG_T_FRAGMENT_R
            | if more {
                wz_codecs::wire_const::FLAG_T_FRAGMENT_M
            } else {
                0
            },
        sn,
    ];
    wire.extend_from_slice(piece);
    wire
}

/// ONE unicast session over UDP that carries `chains` fragment chains, one after
/// the other, each completed, as the pcap FILE.
///
/// For a consumer that grades what a chain identity does over a run of chains: a
/// single chain cannot tell an identity counted from the start of the capture
/// from one counted from the first message still held, because both are 0. Each
/// chain is two fragments (`begun`, then `reassembled`) with the next chain's
/// sequence numbers continuing the reliable channel's.
pub fn chain_sequence_capture(chains: usize) -> Vec<u8> {
    chains_after(full_handshake(), chains)
}

/// [`completed_chain_capture`] with the handshake taken off the front: a capture
/// that began after it, so the reader never sees the InitAck and does not know
/// the sequence-number ring.
///
/// The same record, split the same way across two fragments whose numbers are
/// consecutive. A reader with no ring follows a chain on steps of plain `+1`, so
/// the chain completes and the record is joined as it is behind a handshake: the
/// fixture a consumer grades a mid-session capture against, with the record handed
/// back so the comparison needs no knowledge of the split.
pub fn completed_chain_capture_after_the_handshake() -> (Vec<u8>, Vec<u8>) {
    let record = push(sender_space(0, Some("chain/joined")), &[7u8; 8]);
    (chains_after(Vec::new(), 1), record)
}

/// `rows` (the messages a capture holds before its fragments, each with whether
/// the lower endpoint sent it), then `chains` completed two-fragment chains of
/// the record [`completed_chain_capture`] carries, as the pcap file.
fn chains_after(mut rows: Vec<(bool, Vec<u8>)>, chains: usize) -> Vec<u8> {
    let record = push(sender_space(0, Some("chain/joined")), &[7u8; 8]);
    let split = record.len() / 2;
    for chain in 0..chains {
        let sn = (2 * chain) as u8;
        rows.push((true, fragment_wire(sn, true, &record[..split])));
        rows.push((true, fragment_wire(sn + 1, false, &record[split..])));
    }
    let packets: Vec<Vec<u8>> = rows
        .iter()
        .map(|(from_low, wire)| {
            if *from_low {
                udp_packet(LOW, 43210, HIGH, 7447, wire)
            } else {
                udp_packet(HIGH, 7447, LOW, 43210, wire)
            }
        })
        .collect();
    let refs: Vec<(u32, u32, &[u8])> = packets.iter().map(|p| (0u32, 0u32, p.as_slice())).collect();
    crate::pcap::write(crate::link::LINKTYPE_ETHERNET, &refs)
}

/// The SHAPE both fixtures above claim, asserted rather than assumed.
///
/// A fixture that stopped building two flows, or two links, or one session,
/// would keep passing every guard written over it while grading nothing — the
/// zero-population failure in its quietest form. A consumer in another crate
/// cannot see any of that, so this is the assertion it calls first.
///
/// Returns `Err` with what it found, so a caller can put it in its own message.
pub fn check_shape(d: &crate::Dissection) -> Result<(), String> {
    use alloc::format;

    // DATAGRAM flows, and the distinction is load-bearing rather than
    // incidental: these links are UDP, so they land in `datagram_flows` and
    // `flows()` — the STREAM table — is empty. The first draft of this check
    // asked `flows()` and reported 0 for a capture that holds two perfectly good
    // links, which is the shape assertion catching its own author.
    //
    // It also fixes what "the later link" means for a reader: the walk yields
    // the stream lists first and the datagram lists after, so here both links
    // are in the datagram half and the second one is the later.
    if d.datagram_flows().len() != 2 {
        return Err(format!(
            "the fixture must build TWO datagram flows, one per link; it built \
             {} (and {} stream flow(s))",
            d.datagram_flows().len(),
            d.flows().len()
        ));
    }
    let census = crate::node::nodes(d);
    if census.links().len() != 2 {
        return Err(format!(
            "both links must have handshaked, or this is one link plus noise; \
             the census found {} link(s)",
            census.links().len()
        ));
    }
    let grouping = crate::node::SessionGrouping::of(&census);
    if grouping.sessions() != 1 {
        return Err(format!(
            "the two links must be ONE session — that is what makes a \
             declaration on one of them reach the other; the grouping found {}",
            grouping.sessions()
        ));
    }
    Ok(())
}

/// R2517 — the fixtures grade THEMSELVES here, because a consumer in another
/// crate cannot see whether the bytes it was handed carry the shape their names
/// claim. A fixture nobody checks is the zero-population hazard one layer down.
#[cfg(test)]
mod tests {
    use super::*;

    /// Both captures are what their names say: two flows, two handshaked links,
    /// one session. Without this a later edit could quietly build one link and
    /// every guard written over these would keep passing while grading nothing.
    #[test]
    fn both_fixtures_carry_the_shape_they_claim() {
        for (name, (d, file)) in [
            (
                "declaring_on_the_later_link",
                multilink_declaring_on_the_later_link(),
            ),
            (
                "declaring_after_the_reference",
                multilink_declaring_after_the_reference(),
            ),
        ] {
            check_shape(&d).unwrap_or_else(|why| panic!("{name}: {why}"));
            assert!(
                !file.is_empty(),
                "{name}: the pcap bytes are what a re-reading consumer needs"
            );
        }
    }

    /// THE PROPERTY, asked of this crate's own already-fixed plane: the pair
    /// pulls the two orders apart, and it does so in OPPOSITE directions.
    ///
    /// `crate::agg` resolves in capture order since R2508, so the first fixture
    /// must resolve — if it did not, the fixture would be building the ordinary
    /// shape and a consumer guard over it would prove nothing. The second must
    /// NOT resolve, because its declaration follows the reference; a fixture
    /// that resolved both would grade "does anything resolve" rather than "is
    /// the order respected".
    #[test]
    fn the_pair_resolves_in_opposite_directions() {
        let (later, _) = multilink_declaring_on_the_later_link();
        let rows = crate::agg::aggregate(&later);
        assert!(
            rows.rows().iter().any(|r| r.keyexpr == ALIAS_LITERAL),
            "the declaration went out BEFORE this reference, on the session's \
             other link, so a capture-ordered fold names it: {:?}",
            rows.rows().iter().map(|r| &r.keyexpr).collect::<Vec<_>>()
        );

        let (after, _) = multilink_declaring_after_the_reference();
        let rows = crate::agg::aggregate(&after);
        assert!(
            !rows.rows().iter().any(|r| r.keyexpr == ALIAS_LITERAL),
            "here the declaration FOLLOWS the reference, so nothing may name \
             it — a fixture that resolved this one would let a reader pass by \
             binding from the future: {:?}",
            rows.rows().iter().map(|r| &r.keyexpr).collect::<Vec<_>>()
        );
    }
}
