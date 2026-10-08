// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A fragment chain is reassembled by a reader that never saw the session's
//! sequence-number resolution.
//!
//! # The claim these tests hold
//!
//! A capture that begins after the handshake has no InitAck, so the reader does
//! not know the size of the sequence-number ring (`context.sn_mask` is `null`).
//! It used to read every Fragment of such a capture as
//! `fragment_without_resolution` and reassembled nothing. The ring decides one
//! thing about a chain: whether a step from one fragment to the next is
//! consecutive ACROSS A WRAP. A step of plain `+1` is consecutive on every ring,
//! so a chain whose steps are all `+1` needs no ring to be followed, and the
//! reader now follows it. A step that is not `+1` is one only a ring could judge,
//! so the chain ends as `unresolvable`, which is neither `out_of_order` (the
//! reader does not know that) nor silence.
//!
//! What is deliberately NOT claimed: `sn.verdict` stays `without_resolution`.
//! Reassembly's raw continuity says a continuation was the next integer; it does
//! not say the delivery was in order relative to a ring the reader never saw.
//!
//! # The fixtures
//!
//! Every capture is built here from this crate's own builders, over a TCP stream
//! (the shape the consumer measured) or UDP datagrams, with the same fragments on
//! both. The pieces are cut from a `Push` that `push_build` encodes, so a
//! reassembled chain is read back as the message it was cut from.
//!
//! The controls are the same fragments behind a handshake: where the InitAck
//! fixes the ring, the reader's answers must be what they were before this
//! change, and the tests below say which cells are allowed to differ and compare
//! the rest.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use wz_session_core::qos::Priority;

use crate::datagram_tests::{
    init_datagram, init_datagram_resolving, marker_chain, open_datagram, patch_offer, tcp_packet,
    tcp_packet_reverse, udp_packet, vle_bytes,
};
use crate::fields_json::fields_json;
use crate::link::LINKTYPE_ETHERNET;
use crate::Dissection;

/// The key and value length of the message the consumer's chains carried: a
/// 4096-byte value under this key encodes to 4120 bytes, cut into pieces of 245
/// (16 of them and a last one of 200), which is 17 fragments.
const ROBOT_KEY: &str = "demo/robots/1/pose";
const ROBOT_VALUE_LEN: usize = 4096;
const ROBOT_PIECE: usize = 245;
const ROBOT_FRAGMENTS: usize = 17;
const ROBOT_MESSAGE_LEN: usize = 4120;
/// Where the consumer's sequence numbers stood: 27 bits, far past what a 7 or a
/// 14-bit ring can carry.
const ROBOT_FIRST_SN: u64 = 109_926_136;

/// The QoS extension's id in a Fragment's extension space.
const FRAGMENT_QOS_EXT_ID: u8 = 0x01;

/// The `sn_res` byte of an Init announcing a 7-bit FrameSN ring and the default
/// 28-bit request-id ring: the smallest ring, where the step `127 -> 0` is a
/// wrap and on every wider ring is a gap.
/// The FrameSN code 0 is the low two bits, so only the request-id code shows.
const SN_RES_7_BIT: u8 = 0x02 << 2;

/// How the fragments travel.
#[derive(Clone, Copy, Debug)]
enum Link {
    /// A TCP stream, each message behind its two-byte length: the consumer's.
    Tcp,
    /// One UDP datagram per message.
    Udp,
}

/// What the capture holds BEFORE its fragments.
#[derive(Clone, Copy, Debug)]
enum Handshake {
    /// Nothing: the capture began after the handshake.
    None,
    /// The dialler's Init alone, offering the patch level that arms the chain
    /// markers: the patch is known and the InitAck never came.
    InitSynOnly,
    /// Both Inits (offering the patch level that arms the markers) and both
    /// Opens: the InitAck fixes the ring at the default 28 bits.
    Complete,
    /// Both Inits and both Opens with NO patch offer, so the markers stay off, as
    /// they do with no handshake at all: the one difference from [`Self::None`]
    /// is that the ring is known (28 bits).
    CompleteWithoutMarkers,
    /// As [`Self::CompleteWithoutMarkers`] with the ring the `sn_res` byte names.
    CompleteWithRing(u8),
}

impl Handshake {
    /// The messages, each with whether the lower endpoint sent it.
    fn messages(self) -> Vec<(bool, Vec<u8>)> {
        let patch = patch_offer(u64::from(wz_session_core::extpatch::CURRENT_PATCH));
        let both = |init: &dyn Fn(bool) -> Vec<u8>| {
            vec![
                (true, init(false)),
                (false, init(true)),
                (true, open_datagram(false)),
                (false, open_datagram(true)),
            ]
        };
        match self {
            Self::None => Vec::new(),
            Self::InitSynOnly => vec![(true, init_datagram(false, &patch))],
            Self::Complete => both(&|ack| init_datagram(ack, &patch)),
            Self::CompleteWithoutMarkers => both(&|ack| init_datagram(ack, &[])),
            Self::CompleteWithRing(sn_res) => both(&|ack| init_datagram_resolving(ack, sn_res)),
        }
    }
}

/// One Fragment, described by what a reader can tell apart.
#[derive(Clone)]
struct Frag {
    /// Whether the lower endpoint sent it: direction `a`.
    from_low: bool,
    reliable: bool,
    /// The `ext_qos` band, `None` for the default (no extension).
    priority: Option<Priority>,
    sn: u64,
    more: bool,
    /// Whether it carries the `First` chain-boundary marker.
    first: bool,
    piece: Vec<u8>,
}

impl Frag {
    /// A reliable, default-priority Fragment from the lower endpoint.
    fn new(sn: u64, more: bool, first: bool, piece: &[u8]) -> Self {
        Self {
            from_low: true,
            reliable: true,
            priority: None,
            sn,
            more,
            first,
            piece: piece.to_vec(),
        }
    }

    fn sent_by_high(mut self) -> Self {
        self.from_low = false;
        self
    }

    fn best_effort(mut self) -> Self {
        self.reliable = false;
        self
    }

    fn at(mut self, priority: Priority) -> Self {
        self.priority = Some(priority);
        self
    }

    /// The transport message: header, the VLE sequence number, the extension
    /// chain (QoS band first, then the `First` marker, in id order), the piece.
    fn wire(&self) -> Vec<u8> {
        let mut chain: Vec<Vec<u8>> = Vec::new();
        if let Some(priority) = self.priority {
            // `zextz64!(0x1, true)`: the QoS id, the z64 encoding and the
            // mandatory bit, whose single-byte body is the band. The header is
            // `frame_encode`'s `QOS_EXT_HEADER` (0x31), and the reader takes id
            // 0x1 of a Fragment's extension space for QoS (`inbound.rs`,
            // `ext_qos_priority`).
            let mut ext = vec![
                FRAGMENT_QOS_EXT_ID
                    | wz_session_core::ext_header::EXT_ENC_Z64
                    | wz_session_core::ext_header::EXT_FLAG_M,
            ];
            ext.extend_from_slice(&vle_bytes(u64::from(priority.wire_byte())));
            chain.push(ext);
        }
        if self.first {
            chain.push(marker_chain(true, false));
        }
        let last = chain.len().saturating_sub(1);
        let mut ext_bytes = Vec::new();
        for (i, entry) in chain.iter_mut().enumerate() {
            if i < last {
                entry[0] |= wz_session_core::ext_header::EXT_FLAG_Z;
            }
            ext_bytes.extend_from_slice(entry);
        }
        let mut header = wz_session_core::wire_const::T_MID_FRAGMENT;
        if self.reliable {
            header |= wz_codecs::wire_const::FLAG_T_FRAGMENT_R;
        }
        if self.more {
            header |= wz_codecs::wire_const::FLAG_T_FRAGMENT_M;
        }
        if !ext_bytes.is_empty() {
            header |= wz_codecs::wire_const::FLAG_T_Z;
        }
        let mut wire = vec![header];
        wire.extend_from_slice(&vle_bytes(self.sn));
        wire.extend_from_slice(&ext_bytes);
        wire.extend_from_slice(&self.piece);
        wire
    }
}

/// `message` cut into pieces of `piece_len`, as one chain with consecutive
/// sequence numbers from `first_sn`: the first carries `First`, the last has no
/// `more` flag.
fn chain_of(message: &[u8], piece_len: usize, first_sn: u64) -> Vec<Frag> {
    let pieces: Vec<&[u8]> = message.chunks(piece_len).collect();
    let count = pieces.len();
    pieces
        .into_iter()
        .enumerate()
        .map(|(i, piece)| Frag::new(first_sn + i as u64, i + 1 < count, i == 0, piece))
        .collect()
}

/// A `Push` of `value_len` bytes of `fill` under `key`, as the codec writes it.
fn push_of(key: &str, fill: u8, value_len: usize) -> Vec<u8> {
    wz_session_core::push_build::build_push_literal(key, &vec![fill; value_len])
        .expect("a literal put builds")
        .try_as_borrowed()
        .expect("a built push re-borrows")
        .encode_to_vec()
}

/// The consumer's message.
fn robot_push() -> Vec<u8> {
    let message = push_of(ROBOT_KEY, b'x', ROBOT_VALUE_LEN);
    assert_eq!(
        message.len(),
        ROBOT_MESSAGE_LEN,
        "the consumer's 4120 bytes"
    );
    message
}

/// The consumer's five closed chains: 17 fragments each, every sequence number
/// one more than the last, the chains back to back (the last of one and the first
/// of the next are `+1` apart too).
fn five_robot_chains() -> Vec<Frag> {
    let message = robot_push();
    let mut all = Vec::new();
    for chain in 0..5u64 {
        let one = chain_of(
            &message,
            ROBOT_PIECE,
            ROBOT_FIRST_SN + chain * ROBOT_FRAGMENTS as u64,
        );
        assert_eq!(one.len(), ROBOT_FRAGMENTS, "17 fragments to a chain");
        all.extend(one);
    }
    all
}

/// A TCP stream unit: the two-byte little-endian length, then the message.
fn stream_unit(wire: &[u8]) -> Vec<u8> {
    let mut out = (wire.len() as u16).to_le_bytes().to_vec();
    out.extend_from_slice(wire);
    out
}

/// The capture (as a dissection and as the pcap it was written from): the
/// handshake's messages, then the fragments in order.
fn capture(link: Link, handshake: Handshake, fragments: &[Frag]) -> (Dissection, Vec<u8>) {
    let mut messages = handshake.messages();
    messages.extend(fragments.iter().map(|f| (f.from_low, f.wire())));
    let mut d = Dissection::new();
    let mut packets: Vec<(u32, u32, Vec<u8>)> = Vec::new();
    // A TCP stream's next sequence number, per direction.
    let mut seq = [1000u32; 2];
    for (i, (from_low, wire)) in messages.iter().enumerate() {
        let packet = match link {
            Link::Udp if *from_low => udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, wire),
            Link::Udp => udp_packet([10, 0, 0, 2], 7447, [10, 0, 0, 1], 43210, wire),
            Link::Tcp => {
                let unit = stream_unit(wire);
                let side = usize::from(!*from_low);
                let packet = if *from_low {
                    tcp_packet(seq[side], &unit)
                } else {
                    tcp_packet_reverse(seq[side], &unit)
                };
                seq[side] += unit.len() as u32;
                packet
            }
        };
        d.push_packet(LINKTYPE_ETHERNET, i, &packet);
        packets.push((i as u32, 0, packet));
    }
    // The capture ends here, as every door that reads a whole file ends it: this
    // is where a chain still open is booked as abandoned.
    d.finish();
    let refs: Vec<(u32, u32, &[u8])> = packets
        .iter()
        .map(|(s, u, b)| (*s, *u, b.as_slice()))
        .collect();
    let file = crate::pcap::write(LINKTYPE_ETHERNET, &refs);
    (d, file)
}

/// Where the raw JSON value after a `"key":` ends: the balanced object or array,
/// or the scalar. A brace inside a string never opens a scope.
fn value_end(doc: &str, start: usize) -> usize {
    let bytes = doc.as_bytes();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut i = start;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            if c == b'\\' {
                i += 1;
            } else if c == b'"' {
                in_string = false;
                if depth == 0 {
                    return i + 1;
                }
            }
        } else {
            match c {
                b'"' => in_string = true,
                b'{' | b'[' => depth += 1,
                b'}' | b']' => {
                    if depth == 0 {
                        return i;
                    }
                    depth -= 1;
                    if depth == 0 {
                        return i + 1;
                    }
                }
                b',' if depth == 0 => return i,
                _ => {}
            }
        }
        i += 1;
    }
    bytes.len()
}

/// The raw JSON value after every `"key":` in `doc`, in document order: a row's
/// `above_transport`, `sn` or `chain` is read as the text it was written as.
fn values_of<'a>(doc: &'a str, key: &str) -> Vec<&'a str> {
    let needle = format!("\"{key}\":");
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(at) = doc[from..].find(&needle) {
        let start = from + at + needle.len();
        let end = value_end(doc, start);
        out.push(&doc[start..end]);
        from = end;
    }
    out
}

/// Every string value a `key` takes in `doc`, in document order.
fn words<'a>(doc: &'a str, key: &str) -> Vec<&'a str> {
    crate::doc_revision::json_string_values(doc)
        .into_iter()
        .filter(|(k, _)| *k == key)
        .map(|(_, v)| v)
        .collect()
}

/// How many entries of `list` are `word`.
fn count(list: &[&str], word: &str) -> usize {
    list.iter().filter(|w| **w == word).count()
}

/// One row's `chain` object as the document writes it.
fn chain_text(outcome: &str, reason: Option<&str>, chain_id: Option<u64>) -> String {
    let reason = reason.map_or(String::from("null"), |r| format!("\"{r}\""));
    let chain_id = chain_id.map_or(String::from("null"), |id| id.to_string());
    format!("{{\"outcome\":\"{outcome}\",\"reason\":{reason},\"chain_id\":{chain_id}}}")
}

/// The field document of a capture.
fn doc_of(d: &Dissection, file: &[u8]) -> String {
    fields_json(d, file, None, None)
}

/// The numbers every plane reports about the same capture, and the equalities the
/// repository already holds between them.
///
/// `puts` is the census's own count of `Push` records carrying a put; each is the
/// close of a chain here, so it is also the number of rows whose reassembled
/// message is a `Push` and the number of `yes` rows under `kind == put`. The
/// fragments the planes call unresolvable are the rows that read
/// `fragment_without_resolution`, and each is the end of one chain.
struct Planes {
    puts: usize,
    unresolvable: usize,
    chains: crate::agg::FragmentChains,
}

fn planes_agree(d: &Dissection, doc: &str) -> Planes {
    let table = crate::agg::aggregate(d);
    let gaps = table.gaps();
    let chains = table.chains();
    let puts: usize = table.rows().iter().map(|r| r.totals().puts).sum();

    // Every plane that counts an unresolvable fragment counts the same ones.
    assert_eq!(
        crate::exchange::exchanges(d)
            .unread()
            .unresolvable_fragments,
        gaps.unresolvable_fragments,
        "the exchange plane reads the same unresolvable fragments as the throughput plane"
    );
    assert_eq!(
        crate::payload::payloads(d).gaps().unresolvable_fragments,
        gaps.unresolvable_fragments,
        "the payload plane reads the same unresolvable fragments as the throughput plane"
    );
    let states = words(doc, "carried_state");
    assert_eq!(
        count(&states, "fragment_without_resolution"),
        gaps.unresolvable_fragments,
        "the census counts the rows the field document names, not a number beside them"
    );
    assert_eq!(
        chains.aborted_unresolvable, gaps.unresolvable_fragments,
        "each unresolvable fragment is the end of exactly one chain"
    );
    let chain_rows = values_of(doc, "chain");
    assert_eq!(
        chain_rows
            .iter()
            .filter(|c| c.contains("\"reason\":\"unresolvable\""))
            .count(),
        chains.aborted_unresolvable,
        "and the rows name that ending"
    );

    // The puts: the census, the rows that carry a reassembled Push, and the rows
    // a selector for puts picks.
    let pushes = values_of(doc, "above_transport")
        .iter()
        .filter(|a| a.contains("\"message\":\"Push\""))
        .count();
    assert_eq!(pushes, puts, "census puts against reassembled Push rows");
    let selected = crate::selection_json::tests::letters(d, "kind == put");
    assert_eq!(
        selected.chars().filter(|c| *c == 'Y').count(),
        puts,
        "census puts against `yes` rows under `kind == put`: {selected}"
    );
    // The `yes` rows are the closing rows, and no others.
    for (row, letter) in selected.chars().enumerate() {
        let closes = states.get(row).is_some_and(|s| *s == "reassembled");
        assert_eq!(
            letter == 'Y',
            closes && values_of(doc, "above_transport")[row].contains("\"message\":\"Push\""),
            "row {row}"
        );
    }
    Planes {
        puts,
        unresolvable: gaps.unresolvable_fragments,
        chains,
    }
}

/// THE CLAIM, in the consumer's shape: five closed chains of 17 consecutive
/// fragments, each a 4120-byte `Push`, in a capture that began after the
/// handshake. Each chain is reassembled.
#[test]
fn closed_chains_of_consecutive_fragments_reassemble_with_no_handshake_in_the_capture() {
    for link in [Link::Tcp, Link::Udp] {
        let (d, file) = capture(link, Handshake::None, &five_robot_chains());
        let doc = doc_of(&d, &file);

        let states = words(&doc, "carried_state");
        assert_eq!(states.len(), 85, "{link:?}: one row per fragment");
        assert_eq!(count(&states, "fragment"), 80, "{link:?}: {doc}");
        assert_eq!(count(&states, "reassembled"), 5, "{link:?}: {doc}");
        assert_eq!(
            count(&states, "fragment_without_resolution"),
            0,
            "{link:?}: no fragment is left unplaced"
        );

        // The ring is still unknown, and the verdict on every sequence number
        // says so: reassembly's raw continuity is not an in-order judgement.
        assert_eq!(
            values_of(&doc, "sn_mask"),
            vec!["null"],
            "{link:?}: the flow has no ring"
        );
        let verdicts = words(&doc, "verdict");
        assert_eq!(verdicts.len(), 85);
        assert_eq!(
            count(&verdicts, "without_resolution"),
            85,
            "{link:?}: sn.verdict is not claimed"
        );

        // Row i of chain k: begun, then continued, then reassembled, one
        // identity to a chain.
        let chains = values_of(&doc, "chain");
        assert_eq!(chains.len(), 85);
        for (i, text) in chains.iter().enumerate() {
            let (k, step) = ((i / ROBOT_FRAGMENTS) as u64, i % ROBOT_FRAGMENTS);
            let want = match step {
                0 => chain_text("begun", None, Some(k)),
                s if s + 1 == ROBOT_FRAGMENTS => chain_text("reassembled", None, Some(k)),
                _ => chain_text("continued", None, Some(k)),
            };
            assert_eq!(*text, want, "{link:?}: row {i}");
        }

        // The closing row carries the message the chain was cut from.
        let above = values_of(&doc, "above_transport");
        for close in (0..85).filter(|i| i % ROBOT_FRAGMENTS == ROBOT_FRAGMENTS - 1) {
            assert!(
                above[close].contains(&format!(
                    "\"message\":\"Push\",\"start\":0,\"end\":{ROBOT_MESSAGE_LEN},\"keyexpr\":\"{ROBOT_KEY}\""
                )),
                "{link:?}: row {close}: {}",
                above[close]
            );
        }

        let planes = planes_agree(&d, &doc);
        assert_eq!(planes.puts, 5, "{link:?}");
        assert_eq!(planes.unresolvable, 0, "{link:?}");
        assert_eq!(
            (
                planes.chains.begun,
                planes.chains.continued,
                planes.chains.completed
            ),
            (5, 75, 5),
            "{link:?}"
        );
        let census = crate::census_json::census_json(&d);
        assert!(
            census.contains("\"unresolvable_fragments\":0"),
            "{link:?}: {census}"
        );
    }
}

/// THE CONTROL: the same 85 fragments behind a handshake that arms the markers.
/// Where the ring is known the reader answers as it did before, and the two
/// captures differ in exactly the cells the contract says move.
///
/// Compared row by row: `above_transport` and `chain` are equal text, and
/// `sn.verdict` is the one cell that differs on a row, `without_resolution`
/// against `baseline` then `continuous`. What else differs is not a row's:
/// the flow's `context` (negotiated, patch, ring, batch size, version) and the
/// coordinates a row stands at, which the handshake's four messages shift.
#[test]
fn behind_a_handshake_the_same_fragments_read_alike_but_for_the_sn_verdict() {
    for link in [Link::Tcp, Link::Udp] {
        let fragments = five_robot_chains();
        let (without, without_file) = capture(link, Handshake::None, &fragments);
        let (with, with_file) = capture(link, Handshake::Complete, &fragments);
        let without_doc = doc_of(&without, &without_file);
        let with_doc = doc_of(&with, &with_file);

        // The four handshake rows come first and carry nothing above transport.
        let skip = Handshake::Complete.messages().len();
        let rows = |doc: &str, key: &str| -> Vec<String> {
            let all = values_of(doc, key);
            all[all.len() - 85..]
                .iter()
                .map(|s| String::from(*s))
                .collect()
        };
        for key in ["above_transport", "chain"] {
            let (a, b) = (rows(&without_doc, key), rows(&with_doc, key));
            assert_eq!(
                a, b,
                "{link:?}: `{key}` is the same with and without a ring"
            );
        }
        assert_eq!(
            values_of(&with_doc, "chain").len(),
            skip + 85,
            "{link:?}: the handshake rows come first, and carry no chain"
        );

        // The control reads what it always read, said outright and not only
        // by comparison: 80 fragments and 5 closes behind the handshake's rows.
        let with_states = words(&with_doc, "carried_state");
        assert_eq!(count(&with_states, "fragment"), 80, "{link:?}");
        assert_eq!(count(&with_states, "reassembled"), 5, "{link:?}");
        assert_eq!(count(&with_states, "nothing"), skip, "{link:?}");

        // The cell that moves.
        let with_verdicts = words(&with_doc, "verdict");
        assert_eq!(with_verdicts.len(), 85);
        assert_eq!(with_verdicts[0], "baseline", "{link:?}");
        assert_eq!(count(&with_verdicts, "continuous"), 84, "{link:?}");
        assert_eq!(
            count(&words(&without_doc, "verdict"), "without_resolution"),
            85
        );

        // The flow's context says which of the two it was.
        assert_eq!(values_of(&without_doc, "sn_mask"), vec!["null"]);
        assert_eq!(values_of(&with_doc, "sn_mask"), vec!["268435455"]);

        // And every plane agrees across the pair.
        let (p_without, p_with) = (
            planes_agree(&without, &without_doc),
            planes_agree(&with, &with_doc),
        );
        assert_eq!(
            (p_without.puts, p_without.unresolvable, p_without.chains),
            (p_with.puts, p_with.unresolvable, p_with.chains),
            "{link:?}"
        );
    }
}

/// A step that is not `+1` is one only a ring could judge: the chain ends as
/// `unresolvable`, the fragment that showed it stays `fragment_without_resolution`,
/// and the fragments after it start fresh. With the ring known, the same bytes
/// end the chain as `out_of_order`, and everything else reads alike.
///
/// The sequence: a chain whose third fragment is missing (`101 -> 103`), the rest
/// of that chain (`104`, `105`), then a whole chain. The markers are off in both
/// captures, so a fragment with no chain open begins one, whatever it carries:
/// the rest of the broken chain is read as a chain of its own, which is what
/// "start fresh" means when nothing marks a start.
#[test]
fn a_gap_ends_the_chain_as_unresolvable_and_a_later_chain_still_reassembles() {
    let broken = push_of("demo/broken", b'b', 80);
    let whole = push_of("demo/whole", b'w', 80);
    let pieces: Vec<&[u8]> = broken.chunks(broken.len().div_ceil(5)).collect();
    assert_eq!(pieces.len(), 5, "the broken message has a tail to show");
    let mut fragments = vec![
        Frag::new(100, true, true, pieces[0]),
        Frag::new(101, true, false, pieces[1]),
        // 102 never reached the capture.
        Frag::new(103, true, false, pieces[2]),
        Frag::new(104, true, false, pieces[3]),
        Frag::new(105, false, false, pieces[4]),
    ];
    fragments.extend(chain_of(&whole, 32, 200));

    for link in [Link::Tcp, Link::Udp] {
        let (d, file) = capture(link, Handshake::None, &fragments);
        let doc = doc_of(&d, &file);
        let states = words(&doc, "carried_state");
        let chains = values_of(&doc, "chain");
        // Rows: 0 begun, 1 continued, 2 the ending, 3 and 4 the tail of the broken
        // chain as a chain of its own (begun, reassembled as a message that does
        // not begin at a message), then the whole chain.
        assert_eq!(
            &states[..5],
            [
                "fragment",
                "fragment",
                "fragment_without_resolution",
                "fragment",
                "reassembled"
            ],
            "{link:?}: {doc}"
        );
        assert_eq!(
            chains[..5],
            [
                chain_text("begun", None, Some(0)),
                chain_text("continued", None, Some(0)),
                chain_text("aborted", Some("unresolvable"), Some(0)),
                chain_text("begun", None, Some(1)),
                chain_text("reassembled", None, Some(1)),
            ],
            "{link:?}"
        );
        assert_eq!(
            *states.last().expect("rows"),
            "reassembled",
            "{link:?}: the later chain closes"
        );
        assert!(
            values_of(&doc, "above_transport")
                .last()
                .expect("rows")
                .contains("\"message\":\"Push\""),
            "{link:?}: and it is a Push"
        );
        let planes = planes_agree(&d, &doc);
        assert_eq!(planes.puts, 1, "{link:?}: only the whole chain is a Push");
        assert_eq!(planes.unresolvable, 1, "{link:?}");
        assert_eq!(planes.chains.aborted_out_of_order, 0, "{link:?}");

        // The control: the ring is known (and the markers are off, as above).
        let (known, known_file) = capture(link, Handshake::CompleteWithoutMarkers, &fragments);
        let known_doc = doc_of(&known, &known_file);
        let skip = Handshake::CompleteWithoutMarkers.messages().len();
        let known_states = words(&known_doc, "carried_state");
        let known_chains = values_of(&known_doc, "chain");
        // The only row that differs is the ending, and it differs in both cells
        // the contract moves: the word, and the chain's reason.
        assert_eq!(known_states[skip + 2], "fragment", "{link:?}");
        assert_eq!(
            known_chains[skip + 2],
            chain_text("aborted", Some("out_of_order"), Some(0)),
            "{link:?}"
        );
        for row in (0..fragments.len()).filter(|r| *r != 2) {
            assert_eq!(known_states[skip + row], states[row], "{link:?}: row {row}");
            assert_eq!(known_chains[skip + row], chains[row], "{link:?}: row {row}");
        }
        let known_planes = planes_agree(&known, &known_doc);
        assert_eq!(known_planes.puts, planes.puts, "{link:?}");
        assert_eq!(known_planes.unresolvable, 0, "{link:?}");
        assert_eq!(known_planes.chains.aborted_out_of_order, 1, "{link:?}");
    }
}

/// THE STEP ONLY A RING CAN JUDGE: `127 -> 0` is the seam of a 7-bit ring and a
/// gap on every wider one. With no ring the reader cannot say which, so the chain
/// ends as `unresolvable`; with the 7-bit ring it continues and with the default
/// 28-bit ring it is `out_of_order`.
#[test]
fn a_step_across_the_seam_of_a_small_ring_is_judged_by_the_ring_and_by_nothing_else() {
    let message = push_of("demo/seam", b's', 90);
    let pieces: Vec<&[u8]> = message.chunks(24).collect();
    assert!(pieces.len() >= 4, "four pieces to cross the seam with");
    let fragments = vec![
        Frag::new(126, true, true, pieces[0]),
        Frag::new(127, true, false, pieces[1]),
        Frag::new(0, true, false, pieces[2]),
        Frag::new(1, false, false, pieces[3]),
    ];
    let rows_of = |handshake: Handshake| {
        let (d, file) = capture(Link::Tcp, handshake, &fragments);
        let doc = doc_of(&d, &file);
        let skip = handshake.messages().len();
        let chains: Vec<String> = values_of(&doc, "chain")
            .into_iter()
            .skip(skip)
            .map(String::from)
            .collect();
        let states: Vec<String> = words(&doc, "carried_state")
            .into_iter()
            .skip(skip)
            .map(String::from)
            .collect();
        (chains, states)
    };

    // No ring: the step is unresolvable. The fragment after it has no chain open
    // and, with the last piece's `more` clear, closes a chain of its own.
    let (chains, states) = rows_of(Handshake::None);
    assert_eq!(
        chains[2],
        chain_text("aborted", Some("unresolvable"), Some(0))
    );
    assert_eq!(states[2], "fragment_without_resolution");

    // The ring that makes it a wrap: the chain goes on and closes.
    let (chains, states) = rows_of(Handshake::CompleteWithRing(SN_RES_7_BIT));
    assert_eq!(chains[2], chain_text("continued", None, Some(0)));
    assert_eq!(chains[3], chain_text("reassembled", None, Some(0)));
    assert_eq!(states[3], "reassembled");

    // The default ring, on which the same step is a jump of 2^28 - 127.
    let (chains, states) = rows_of(Handshake::CompleteWithoutMarkers);
    assert_eq!(
        chains[2],
        chain_text("aborted", Some("out_of_order"), Some(0))
    );
    assert_eq!(states[2], "fragment");
}

/// The smallest chain: two fragments, closed. `begun`, then `reassembled`, and
/// the message is read.
#[test]
fn a_single_closed_two_fragment_chain_reassembles_with_no_ring() {
    let message = push_of("demo/pair", b'p', 40);
    let fragments = chain_of(&message, message.len().div_ceil(2), 5);
    assert_eq!(fragments.len(), 2);
    for link in [Link::Tcp, Link::Udp] {
        let (d, file) = capture(link, Handshake::None, &fragments);
        let doc = doc_of(&d, &file);
        assert_eq!(
            words(&doc, "carried_state"),
            ["fragment", "reassembled"],
            "{link:?}"
        );
        assert_eq!(
            values_of(&doc, "chain"),
            [
                chain_text("begun", None, Some(0)),
                chain_text("reassembled", None, Some(0))
            ],
            "{link:?}"
        );
        assert_eq!(planes_agree(&d, &doc).puts, 1, "{link:?}");
    }
}

/// Chains on different keys are different chains: two directions, two bands and
/// the two reliabilities, interleaved, each reassembled and none disturbing
/// another. One of them has a gap, and only that one ends unresolvable.
///
/// The key is `(direction, reliability, priority)`: the same keys the router
/// holds one chain under, and the keys `chain_id` is counted over.
#[test]
fn interleaved_chains_on_different_keys_do_not_disturb_one_another() {
    let make = |key: &str, fill: u8| push_of(key, fill, 60);
    let (msg_a, msg_b, msg_rt, msg_bg, msg_be) = (
        make("demo/a", b'a'),
        make("demo/b", b'b'),
        make("demo/rt", b'r'),
        make("demo/bg", b'g'),
        make("demo/be", b'e'),
    );
    // Four fragments to a chain, so each chain has two continuations to be
    // disturbed in.
    let cut = |m: &[u8]| m.len().div_ceil(4);
    let chain = |m: &[u8], sn: u64| chain_of(m, cut(m), sn);
    let (a, b) = (chain(&msg_a, 10), chain(&msg_b, 700));
    let rt: Vec<Frag> = chain(&msg_rt, 20)
        .into_iter()
        .map(|f| f.at(Priority::RealTime))
        .collect();
    let mut bg: Vec<Frag> = chain(&msg_bg, 900)
        .into_iter()
        .map(|f| f.at(Priority::Background))
        .collect();
    // The background chain loses its third fragment (SN 902).
    bg.remove(2);
    let be: Vec<Frag> = chain(&msg_be, 40)
        .into_iter()
        .map(Frag::best_effort)
        .collect();
    let b: Vec<Frag> = b.into_iter().map(Frag::sent_by_high).collect();
    for part in [&a, &b, &rt, &bg, &be] {
        assert!(part.len() >= 3, "a chain long enough to interleave in");
    }
    // One fragment of each in turn.
    let longest = [&a, &b, &rt, &bg, &be]
        .iter()
        .map(|p| p.len())
        .max()
        .expect("chains");
    let mut fragments = Vec::new();
    for i in 0..longest {
        for part in [&a, &b, &rt, &bg, &be] {
            if let Some(f) = part.get(i) {
                fragments.push(f.clone());
            }
        }
    }
    for link in [Link::Tcp, Link::Udp] {
        let (d, file) = capture(link, Handshake::None, &fragments);
        let doc = doc_of(&d, &file);
        let planes = planes_agree(&d, &doc);
        // The four chains with no gap each close with their own message, and
        // the background chain ends once, with nothing left of it.
        assert_eq!(planes.puts, 4, "{link:?}: {doc}");
        assert_eq!(planes.unresolvable, 1, "{link:?}");
        assert_eq!(planes.chains.completed, 4, "{link:?}");
        assert_eq!(planes.chains.aborted_unresolvable, 1, "{link:?}");
        let above = values_of(&doc, "above_transport");
        for key in ["demo/a", "demo/b", "demo/rt", "demo/be"] {
            assert_eq!(
                above
                    .iter()
                    .filter(|a| a.contains(&format!("\"keyexpr\":\"{key}\"")))
                    .count(),
                1,
                "{link:?}: {key} is reassembled once"
            );
        }
        assert!(
            !above.iter().any(|a| a.contains("demo/bg")),
            "{link:?}: the chain with the gap is never read as a message"
        );
        // Five chains were opened, and each has its own identity.
        let ids: Vec<&str> = values_of(&doc, "chain_id");
        let distinct = {
            let mut v: Vec<&&str> = ids.iter().filter(|i| **i != "null").collect();
            v.sort();
            v.dedup();
            v.len()
        };
        assert_eq!(distinct, 5, "{link:?}: one identity to a chain");
    }
}

/// The patch is known and the InitAck never came: the markers are ENFORCED (the
/// level says so) and the ring is still unknown.
///
/// A headless tail has no `First`, so it is refused whole, exactly as it is when
/// the ring is known; a marked chain is reassembled with no ring, and its
/// sequence numbers still read `without_resolution`.
#[test]
fn with_only_the_initsyn_the_markers_are_enforced_and_the_ring_is_still_unknown() {
    let tail_of = push_of("demo/tail", b't', 60);
    let whole = push_of("demo/head", b'h', 60);
    let mut fragments = vec![
        // The end of a chain this capture never saw the start of.
        Frag::new(50, true, false, &tail_of[10..30]),
        Frag::new(51, false, false, &tail_of[30..]),
    ];
    fragments.extend(chain_of(&whole, whole.len().div_ceil(3), 60));
    let (d, file) = capture(Link::Tcp, Handshake::InitSynOnly, &fragments);
    let doc = doc_of(&d, &file);

    let skip = Handshake::InitSynOnly.messages().len();
    let chains: Vec<&str> = values_of(&doc, "chain").into_iter().skip(skip).collect();
    assert_eq!(
        chains,
        [
            chain_text("refused", Some("missing_start_marker"), None),
            chain_text("refused", Some("missing_start_marker"), None),
            chain_text("begun", None, Some(0)),
            chain_text("continued", None, Some(0)),
            chain_text("reassembled", None, Some(0)),
        ],
        "{doc}"
    );
    assert_eq!(
        words(&doc, "carried_state")
            .into_iter()
            .skip(skip)
            .collect::<Vec<_>>(),
        [
            "fragment",
            "fragment",
            "fragment",
            "fragment",
            "reassembled"
        ]
    );
    assert_eq!(
        count(&words(&doc, "verdict"), "without_resolution"),
        5,
        "still no ring, so no verdict: {doc}"
    );
    // What the flow knows: the patch (one Init seen), no ring, not negotiated.
    assert_eq!(values_of(&doc, "sn_mask"), vec!["null"]);
    assert_eq!(values_of(&doc, "patch"), vec!["1"]);
    assert_eq!(values_of(&doc, "negotiated"), vec!["false"]);
    assert_eq!(planes_agree(&d, &doc).puts, 1);
}

/// A chain still open when the capture ends is abandoned, and COUNTED, on a flow
/// with no ring as on any other: the document's top-level `reassembly` group, and
/// no `chain_id` row that closes it. The flow with the handshake reads the same.
///
/// Before the router followed chains without a ring such a flow had no chain to
/// abandon, and the group read zero for a capture that ended mid-transfer.
#[test]
fn a_chain_left_open_at_the_end_of_a_capture_is_counted_with_no_handshake_too() {
    let message = push_of("demo/open", b'o', 60);
    let fragments = chain_of(&message, message.len().div_ceil(4), 30);
    assert_eq!(fragments.len(), 4);
    // The last fragment never reached the capture.
    let open = &fragments[..3];
    for handshake in [Handshake::None, Handshake::CompleteWithoutMarkers] {
        let (d, file) = capture(Link::Tcp, handshake, open);
        let doc = doc_of(&d, &file);
        let skip = handshake.messages().len();
        assert_eq!(
            words(&doc, "carried_state")
                .into_iter()
                .skip(skip)
                .collect::<Vec<_>>(),
            ["fragment", "fragment", "fragment"],
            "{handshake:?}"
        );
        let group = values_of(&doc, "reassembly");
        assert_eq!(group.len(), 1, "{handshake:?}: {doc}");
        assert!(
            group[0].contains("\"abandoned_at_end\":1"),
            "{handshake:?}: the open chain is counted: {}",
            group[0]
        );
        let planes = planes_agree(&d, &doc);
        assert_eq!(
            (
                planes.chains.begun,
                planes.chains.continued,
                planes.chains.completed
            ),
            (1, 2, 0),
            "{handshake:?}"
        );
        assert_eq!(planes.puts, 0, "{handshake:?}: nothing closed");
    }
}
