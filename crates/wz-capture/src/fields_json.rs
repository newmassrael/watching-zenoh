// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y855 — the FIELD layer over a whole capture: every message dissected
//! into the byte ranges it was decoded from.
//!
//! ## The walk this makes possible, which was documented and impossible
//!
//! `wz_dissect.h` has told a C consumer since R311y586 to "walk the flows, then
//! expand the messages you want with `wz_dissect_transport_message`". That walk
//! could not be performed. The summary reports per-flow frame COUNTS, so there
//! is nothing to enumerate messages by — and even holding a coordinate, a
//! caller could not slice the bytes out: a stream message lives in the
//! REASSEMBLED per-direction stream, which exists only inside this library. The
//! capture file a caller passed in does not contain the message contiguously.
//!
//! So the fix could not be "report offsets and let the caller slice". The walk
//! has to happen here, where the reassembly is, and hand back the trees.
//!
//! ## One coordinate space, and the row says which one
//!
//! Every span inside a tree is MESSAGE-RELATIVE — the walk is driven at base 0.
//! Where the message sits is on the row, once, because the three row producers
//! put three different kinds of number there:
//!
//! - a stream message carries `message_at`, a BYTE OFFSET into the direction's
//!   retained stream, so a span added to it is a capture coordinate;
//! - a datagram message carries `packet`, the INDEX of the packet in the file,
//!   which is not a byte offset and must not be added to anything.
//!
//! `offset_space` names which, so a reader never has to tell them apart by
//! inspection — they are small numbers all round.
//!
//! ## The walk is CHECKED against the session that framed it
//!
//! A tree is emitted only when the field walker's name for a message agrees
//! with the name the passive session gave it. A disagreement means the
//! coordinate this row was sliced at does not name the message the session
//! framed, and it is reported as a `declined` row with the reason rather than
//! dropped: R311y687 found a live misread this way (a batched unit's second
//! message walked as its first). Dropping the check to save work here would
//! give this surface a weaker guarantee than the command line's, which is the
//! divergence the two-renderings debt is about.
//!
//! ## Both halves, and the datagram half needs the file again
//!
//! A datagram flow retains no stream — its messages' bytes are packet payloads
//! — so the capture is parsed a SECOND time and each packet re-decapsulated.
//! That second read can disagree with the first, and every way it can is
//! counted rather than skipped: a `continue` there would drop rows and leave
//! the listing looking whole, which is the failure this whole layer exists to
//! end.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

use wz_session_core::dissect::to_json;
use wz_session_core::json::escape_into;
use wz_session_core::passive::{Direction, PassiveFrame};

use crate::census_json::{dir_name, push_flow};
use crate::payload_decode::{decode_payload, push_decoding, Declarations, KeyexprAt};

/// Every message in `capture`, dissected into fields.
///
/// `capture` is the same bytes `d` was built from; the datagram half needs them
/// again (see the module doc). `max_messages_per_flow` bounds each flow's
/// listing — `None` is unbounded, which is the shape that works for a test and
/// fails for a session, so a caller with a screen to fill should pass a bound.
///
/// R311y856 — `declarations` is the payload format mapping in force, or `None`
/// for a caller that declared nothing. A row gets a `payload_decode` object
/// only when a mapping exists, which is the rule the command line has followed
/// since R311y699: a reader who declared no format is not told about payloads
/// they did not ask about.
pub fn fields_json(
    d: &crate::Dissection,
    capture: &[u8],
    max_messages_per_flow: Option<usize>,
    declarations: Option<&Declarations<'_>>,
) -> String {
    // A map with no rules answers `NoRules` for every message, so it renders
    // nothing either way -- folded here so the row renderers ask one question
    // rather than two.
    let declarations = declarations.filter(|d| !d.is_empty());
    let mut out = String::from("{\"stream_flows\":[");
    for (i, flow) in d.flows().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_stream_flow(flow, max_messages_per_flow, declarations, &mut out);
    }
    out.push_str("],\"datagram_flows\":[");
    let reread = Reread::of(capture);
    for (i, flow) in d.datagram_flows().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_datagram_flow(
            flow,
            reread.as_ref(),
            max_messages_per_flow,
            declarations,
            &mut out,
        );
    }
    // Said rather than left to be inferred from empty datagram listings: a
    // capture this reader cannot parse a second time yields no datagram rows
    // for a reason that has nothing to do with the traffic.
    let _ = write!(out, "],\"capture_reread\":{}}}", reread.is_some());
    out
}

fn push_stream_flow(
    flow: &crate::FlowDissection,
    cap: Option<usize>,
    declarations: Option<&Declarations<'_>>,
    out: &mut String,
) {
    out.push_str("{\"flow\":");
    push_flow(&flow.flow, out);
    out.push_str(",\"messages\":[");
    let (mut shown, mut omitted, mut emitted) = (0usize, 0usize, 0usize);
    // R311y856 — folded in FRAME ORDER and before the cap bites, which is the
    // rule R311y701 settled for the same table: a keyexpr id resolves through
    // the bindings that were live when the message travelled, and a listing
    // that stopped absorbing where it stopped PRINTING would resolve later ids
    // against a table missing the declarations a held-back row carried.
    let mut spaces = crate::agg::KeyexprSpaces::new();
    for frame in &flow.frames {
        spaces.absorb_frame(frame);
        if cap.is_some_and(|c| shown >= c) {
            omitted += 1;
            continue;
        }
        shown += 1;
        if emitted > 0 {
            out.push(',');
        }
        emitted += 1;
        let assembler = flow.assembler(frame.direction);
        let at = message_at(frame);
        let _ = write!(
            out,
            "{{\"direction\":\"{}\",\"offset_space\":\"stream_byte\",\"message_at\":{at},",
            dir_name(frame.direction)
        );
        match message_bytes(assembler.stream(), assembler.retained_from(), frame) {
            Err(why) => push_declined(&why, out),
            Ok(bytes) => push_walk(bytes, frame, declarations.map(|d| (d, &spaces)), out),
        }
        out.push('}');
    }
    let _ = write!(out, "],\"shown\":{shown},\"omitted\":{omitted}}}");
}

fn push_datagram_flow(
    flow: &crate::DatagramDissection,
    reread: Option<&Reread>,
    cap: Option<usize>,
    declarations: Option<&Declarations<'_>>,
    out: &mut String,
) {
    out.push_str("{\"flow\":");
    push_flow(&flow.flow, out);
    out.push_str(",\"messages\":[");
    let (mut shown, mut omitted, mut emitted) = (0usize, 0usize, 0usize);
    let mut disagreed = 0usize;
    let mut named: Vec<(usize, &'static str)> = Vec::new();
    // The stream half's rule, unchanged: absorbed for every frame, ahead of
    // every reason this loop has for skipping one.
    let mut spaces = crate::agg::KeyexprSpaces::new();
    for frame in &flow.frames {
        spaces.absorb_frame(frame);
        // `stream_offset` names the PACKET here: a datagram link has no stream
        // for an offset to be into, so the field carries the only anchor there
        // is.
        let index = frame.stream_offset;
        let Some(file) = reread else {
            continue;
        };
        let Some(packet) = file.packet(index) else {
            note(&mut named, &mut disagreed, cap, index, "absent");
            continue;
        };
        let Ok(crate::link::Transport::Udp(datagram)) =
            crate::link::decapsulate(packet.link_type, packet.index, packet.data)
        else {
            note(&mut named, &mut disagreed, cap, index, "not_udp");
            continue;
        };
        // The second read's own coordinates, against the first read's. Three
        // axes rather than one boolean, because they fail for different reasons
        // and a reader chasing one of them needs to know which.
        let travels = if datagram.from_low {
            Direction::A
        } else {
            Direction::B
        };
        if datagram.flow != flow.flow {
            note(&mut named, &mut disagreed, cap, index, "flow");
            continue;
        }
        if travels != frame.direction {
            note(&mut named, &mut disagreed, cap, index, "direction");
            continue;
        }
        if datagram.packet_index != index {
            note(&mut named, &mut disagreed, cap, index, "index");
            continue;
        }
        let Some(message) = datagram.payload.get(frame.unit_offset..) else {
            note(&mut named, &mut disagreed, cap, index, "short_payload");
            continue;
        };
        if cap.is_some_and(|c| shown >= c) {
            omitted += 1;
            continue;
        }
        shown += 1;
        if emitted > 0 {
            out.push(',');
        }
        emitted += 1;
        let _ = write!(
            out,
            "{{\"direction\":\"{}\",\"offset_space\":\"packet\",\"packet\":{index},",
            dir_name(frame.direction)
        );
        push_walk(message, frame, declarations.map(|d| (d, &spaces)), out);
        out.push('}');
    }
    let _ = write!(
        out,
        "],\"shown\":{shown},\"omitted\":{omitted},\
         \"disagreements\":{{\"count\":{disagreed},\"named\":["
    );
    for (i, (at, why)) in named.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{{\"at\":{at},\"why\":\"{why}\"}}");
    }
    out.push_str("]}}");
}

/// Walk `bytes` and emit either the tree or the reason it was declined.
///
/// The walk is driven at base 0 so every span is message-relative; the row's
/// own coordinate says where the message sits (see the module doc).
///
/// R311y856 — `lens` is the payload mapping and the id table it resolves keyexprs
/// through, or `None` for a caller that declared no format. It rides ONE
/// argument because the two are one fact: a mapping with nothing to resolve
/// against would silently miss every message a running capture names by id.
///
/// The payload block hangs off a WALKED tree and never off a declined row: a
/// decline means the bytes are not the message the session framed, and decoding
/// a payload out of them would be a confident statement about bytes nobody
/// asked for -- the failure the decline itself exists to avoid.
fn push_walk(
    bytes: &[u8],
    frame: &PassiveFrame,
    lens: Option<(&Declarations<'_>, &crate::agg::KeyexprSpaces)>,
    out: &mut String,
) {
    match wz_session_core::dissect::dissect_transport_message(bytes, 0) {
        // The error type is `sce_forge_runtime`'s and is not re-exported here,
        // so it is rendered rather than named — a dependency this crate has no
        // reason to take on for one message string.
        Err(err) => {
            let mut why = String::from("the field walker refused these bytes: ");
            let _ = write!(why, "{err:?}");
            push_declined(&why, out);
        }
        Ok(field) => {
            let framed = message_name(frame);
            if walk_agrees(&field.name, &framed) {
                out.push_str("\"name\":");
                escape_into(&field.name, out);
                out.push_str(",\"fields\":");
                out.push_str(&to_json(&field));
                if let Some((declarations, spaces)) = lens {
                    let at = KeyexprAt::new(frame.direction, spaces);
                    out.push_str(",\"payload_decode\":");
                    push_decoding(&decode_payload(&field, declarations, at), out);
                }
            } else {
                let mut why = String::from("the session read these bytes as ");
                why.push_str(&framed);
                why.push_str(" and the field walker reads them as ");
                why.push_str(&field.name);
                why.push_str(
                    ", so the coordinate this row was sliced at does not name \
                     the message the session framed",
                );
                push_declined(&why, out);
            }
        }
    }
}

fn push_declined(why: &str, out: &mut String) {
    out.push_str("\"declined\":");
    escape_into(why, out);
}

fn note(
    named: &mut Vec<(usize, &'static str)>,
    count: &mut usize,
    cap: Option<usize>,
    at: usize,
    why: &'static str,
) {
    *count += 1;
    // The COUNT is exact and never approximate; the per-message detail is a
    // listing like any other here and takes the same ceiling.
    if cap.is_none_or(|c| named.len() < c) {
        named.push((at, why));
    }
}

/// Where a stream message begins: past the framing prefix, and past whatever of
/// the unit's batch stands ahead of it.
fn message_at(frame: &PassiveFrame) -> usize {
    frame.stream_offset + frame.prefix_width + frame.unit_offset
}

fn message_bytes<'a>(
    stream: &'a [u8],
    origin: usize,
    frame: &PassiveFrame,
) -> Result<&'a [u8], String> {
    if frame.stream_offset < origin {
        let mut why = String::from("bytes discarded to stay inside the retained stream (from ");
        let _ = write!(
            why,
            "{origin}, this message begins at {})",
            frame.stream_offset
        );
        return Err(why);
    }
    let body = (frame.stream_offset - origin) + frame.prefix_width;
    let end = body + frame.unit_len;
    if end > stream.len() {
        let mut why = String::from("the framing unit declares ");
        let _ = write!(
            why,
            "{} byte(s) and the retained stream holds {}",
            frame.unit_len,
            stream.len().saturating_sub(body)
        );
        return Err(why);
    }
    // The SAME sum the row's `message_at` is rendered from, so the offset a
    // reader is given is the offset these bytes were taken at.
    let start = message_at(frame) - origin;
    if start > end {
        let mut why = String::from("this message stands ");
        let _ = write!(
            why,
            "{} byte(s) into a unit of {}",
            frame.unit_offset, frame.unit_len
        );
        return Err(why);
    }
    Ok(&stream[start..end])
}

fn message_name(frame: &PassiveFrame) -> String {
    match &frame.frame {
        Ok(f) => f.kind_name().to_string(),
        // A message this reader could NOT decode is named as such rather than
        // omitted: a listing that shows only the successes is the silence this
        // layer exists to end.
        Err(e) => {
            let mut s = String::from("undecodable(");
            let _ = write!(s, "{e:?}");
            s.push(')');
            s
        }
    }
}

/// `Unknown` on either side is not a disagreement — neither reader claimed to
/// have named the message — and an undecodable frame has no name to compare.
fn walk_agrees(walked: &str, framed: &str) -> bool {
    walked == "Unknown"
        || framed == "Unknown"
        || framed.starts_with("undecodable(")
        || walked == framed
}

/// The capture, parsed a second time, in EITHER format.
///
/// Both, and that is not a convenience: reading only pcapng would tell a
/// classic `.pcap` holding datagram traffic that its packets could not be
/// re-read — a notice true about the code and false about the file.
enum Reread {
    Ng(crate::pcapng::PcapngFile),
    Classic(crate::pcap::PcapFile),
}

struct RereadPacket<'a> {
    link_type: u32,
    index: usize,
    data: &'a [u8],
}

impl Reread {
    fn of(capture: &[u8]) -> Option<Self> {
        if crate::pcapng::looks_like_pcapng(capture) {
            crate::pcapng::parse(capture).ok().map(Self::Ng)
        } else {
            crate::pcap::parse(capture).ok().map(Self::Classic)
        }
    }

    fn packet(&self, index: usize) -> Option<RereadPacket<'_>> {
        match self {
            Self::Ng(file) => file.packets.get(index).map(|p| RereadPacket {
                link_type: p.link_type,
                index: p.index,
                data: &p.data,
            }),
            Self::Classic(file) => file.packets.get(index).map(|p| RereadPacket {
                // One link type for the whole file, which is what a classic
                // pcap's header says and the reason it is not on the packet.
                link_type: file.link_type,
                index: p.index,
                data: &p.data,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datagram_tests::{tcp_packet, udp_packet};
    use crate::link::LINKTYPE_ETHERNET;
    use crate::Dissection;

    use alloc::vec;

    /// One framed KeepAlive: a two-byte length prefix and the message.
    fn framed_keepalive() -> Vec<u8> {
        vec![1, 0, wz_session_core::wire_const::T_MID_KEEP_ALIVE]
    }

    /// R311y855 — A STREAM MESSAGE CROSSES AS A TREE PLUS THE OFFSET IT WAS
    /// TAKEN AT, which is the pair that makes a span usable.
    ///
    /// A tree alone is not enough to highlight bytes in a capture: every span
    /// inside it is message-relative, so a reader needs the message's own
    /// coordinate AND to know which space that coordinate is in. Both are
    /// asserted here, and the `offset_space` is what stops a packet index and a
    /// byte offset being told apart by inspection.
    #[test]
    fn a_stream_message_carries_its_tree_and_the_offset_it_was_taken_at() {
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &framed_keepalive()));
        d.finish();

        let file = crate::pcap::write(
            1,
            &[(0, 0, tcp_packet(1000, &framed_keepalive()).as_slice())],
        );
        let json = fields_json(&d, &file, None, None);

        assert!(
            json.contains("\"offset_space\":\"stream_byte\""),
            "a stream row's number is a BYTE OFFSET and must say so: {json}"
        );
        assert!(
            json.contains("\"name\":\"KeepAlive\""),
            "the walker named the message: {json}"
        );
        assert!(
            json.contains("\"fields\":{\"name\":\"KeepAlive\""),
            "and handed back the TREE, which is what a span comes from: {json}"
        );
        // The framing prefix is 2 bytes, so the message begins at 2 -- not at
        // the unit's own offset. A `message_at` that pointed at the prefix
        // would put every span two bytes early, which is exactly the class of
        // error a coordinate is for.
        assert!(
            json.contains("\"message_at\":2"),
            "the offset must skip the framing prefix: {json}"
        );
        assert!(
            json.contains("\"shown\":1,\"omitted\":0"),
            "one message, none held back: {json}"
        );
    }

    /// R311y855 — THE BOUND HOLDS BACK ROWS AND SAYS HOW MANY.
    ///
    /// An unbounded listing over a session-sized capture is the shape the
    /// summary's own doc refuses. What matters is that the held-back rows are
    /// COUNTED: a listing that silently stopped would read as a capture that
    /// ended.
    #[test]
    fn the_bound_holds_rows_back_and_counts_them() {
        let mut stream = Vec::new();
        for _ in 0..5 {
            stream.extend_from_slice(&framed_keepalive());
        }
        let packet = tcp_packet(1000, &stream);
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &packet);
        d.finish();
        let file = crate::pcap::write(1, &[(0, 0, packet.as_slice())]);

        let all = fields_json(&d, &file, None, None);
        assert!(
            all.contains("\"shown\":5,\"omitted\":0"),
            "the unbounded arm must show every message, or the bound below \
             proves nothing: {all}"
        );

        let bounded = fields_json(&d, &file, Some(2), None);
        assert!(
            bounded.contains("\"shown\":2,\"omitted\":3"),
            "the bound must hold rows back AND count them: {bounded}"
        );
    }

    /// R311y855 — A DATAGRAM MESSAGE IS WALKED TOO, AND ITS NUMBER IS A PACKET
    /// INDEX RATHER THAN AN OFFSET.
    ///
    /// The datagram half is the one that needs the capture a second time, and
    /// it is the half a listing quietly omits when nobody looks: a flows() walk
    /// that names only the stream side is this crate's own recorded failure
    /// (R311y679, and three rounds after it).
    #[test]
    fn a_datagram_message_is_walked_and_its_number_is_a_packet_index() {
        let packet = udp_packet(
            [10, 0, 0, 1],
            43210,
            [10, 0, 0, 2],
            7447,
            &[wz_session_core::wire_const::T_MID_KEEP_ALIVE],
        );
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &packet);
        d.finish();
        let file = crate::pcap::write(1, &[(0, 0, packet.as_slice())]);

        let json = fields_json(&d, &file, None, None);
        assert!(
            json.contains("\"capture_reread\":true"),
            "the second read is what the datagram half runs on: {json}"
        );
        assert!(
            json.contains("\"offset_space\":\"packet\",\"packet\":0"),
            "a datagram row's number is a packet INDEX, and adding a span to it \
             would be meaningless: {json}"
        );
        assert!(
            json.contains("\"name\":\"KeepAlive\""),
            "the datagram half walks its messages, it does not merely count \
             them: {json}"
        );
        assert!(
            json.contains("\"disagreements\":{\"count\":0"),
            "and the two reads agreed about every one: {json}"
        );
    }

    /// R311y855 — A CAPTURE THIS READER CANNOT PARSE A SECOND TIME SAYS SO.
    ///
    /// The honesty valve on the row above. Handing back an empty datagram
    /// listing would read as "this capture had no datagram traffic", which is a
    /// statement about the capture made on the evidence of the reader.
    #[test]
    fn a_capture_that_cannot_be_reread_is_reported_rather_than_left_empty() {
        let packet = udp_packet(
            [10, 0, 0, 1],
            43210,
            [10, 0, 0, 2],
            7447,
            &[wz_session_core::wire_const::T_MID_KEEP_ALIVE],
        );
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &packet);
        d.finish();

        // The dissection is real and the BYTES handed to the walker are not a
        // capture at all, which is the only way to reach this arm.
        let json = fields_json(&d, b"not a capture file", None, None);
        assert!(
            json.contains("\"capture_reread\":false"),
            "the reader must admit it could not re-read the file: {json}"
        );
        assert!(
            json.contains("\"shown\":0"),
            "and show nothing rather than inventing rows: {json}"
        );
    }

    /// R311y855 — THE WALK IS CHECKED AGAINST THE SESSION, AND A DISAGREEMENT
    /// IS A NAMED DECLINE RATHER THAN A CONFIDENT TREE.
    ///
    /// This is the guarantee that must not be dropped in porting the field
    /// layer to a second surface. R311y687 found a live misread with it -- a
    /// batched unit's second message walked as its first -- and a tree emitted
    /// from a coordinate that names the wrong message is worse than no tree:
    /// it is a confident answer about bytes nobody asked about.
    ///
    /// Reached through the RETENTION cap, which is the shape that actually
    /// occurs: a bounded reader trims the stream behind it, so a message the
    /// session framed early has bytes nobody kept.
    ///
    /// The first cut used a truncated framing prefix instead and PASSED ON ZERO
    /// ROWS -- the session never framed that unit at all, so there was nothing
    /// to decline and the negative assertion held vacuously. Measured rather
    /// than reasoned: the fixture was dumped and its message list was empty.
    /// The assertions below are positive for that reason.
    #[test]
    fn a_row_the_stream_cannot_supply_is_declined_with_the_reason() {
        let mut stream = Vec::new();
        for _ in 0..40 {
            stream.extend_from_slice(&framed_keepalive());
        }
        let packet = tcp_packet(1000, &stream);
        let file = crate::pcap::write(1, &[(0, 0, packet.as_slice())]);

        // Keep far fewer bytes than the stream holds, so the early messages'
        // bytes are gone while their frames remain.
        let limits = crate::DissectionLimits {
            stream_bytes_per_direction: Some(16),
            ..Default::default()
        };
        let d = crate::Dissection::from_capture_bounded(&file, limits).expect("the capture reads");

        let json = fields_json(&d, &file, None, None);
        assert!(
            json.contains("\"declined\":\"bytes discarded to stay inside the retained stream"),
            "a message whose bytes were trimmed must be DECLINED with the \
             reason -- not dropped, and not walked from whatever happens to sit \
             at that offset now: {json}"
        );
        // And the listing is not ALL declines: messages still inside the window
        // walk. Without this the test would pass against an emitter that
        // declined everything, which is the same vacuity in the other
        // direction.
        assert!(
            json.contains("\"fields\":{\"name\":\"KeepAlive\""),
            "the messages still inside the retained window must still walk: {json}"
        );
    }

    /// R311y856 — A DECLARED FORMAT DECODES THE PAYLOAD IN *THIS* EMIT, which
    /// is what the C ABI links and could not do.
    ///
    /// # What makes this a discriminator rather than an observation
    ///
    /// Three arms over ONE capture, and the assertion is the DIFFERENCE between
    /// them, not that any single one printed something:
    ///
    /// - no declarations -> no `payload_decode` key at all. Without this arm a
    ///   renderer that always emitted a block would pass;
    /// - a rule that does not cover this topic -> `no_rule`, carrying the
    ///   keyexpr that WAS tested. Without this arm a renderer that decoded
    ///   every payload regardless of the mapping would pass, which is the
    ///   failure a schemaless decoder makes silently: run over the wrong topic
    ///   it does not fail, it produces fields;
    /// - the covering rule -> `decoded`, with the DECLARED name and spans in
    ///   the MESSAGE's coordinates.
    ///
    /// The span is the sharpest of the four claims. `Protobuf` hands back
    /// payload-relative offsets, so a walker that forgot to rebase would report
    /// `start: 0` -- a number that is in range, looks plausible beside every
    /// other span in the row, and points at the message header.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn a_declared_format_decodes_the_payload_and_the_spans_are_the_messages() {
        use crate::payload::formats::FormatMap;
        use crate::payload_decode::Declarations;

        // `{ 1: 150 }`, which the walker reads as one varint field spanning
        // three bytes of the PAYLOAD.
        let payload = [0x08u8, 0x96, 0x01];
        // A `Push` is a NETWORK message and rides inside a transport `Frame`;
        // the length prefix is the stream link's framing on top of that.
        let push = crate::datagram_tests::frame_carrying(
            &crate::payload::tests_support::push_declaring("demo/sensor", 0, &payload),
        );
        let mut framed = vec![push.len() as u8, 0];
        framed.extend_from_slice(&push);

        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &framed));
        d.finish();
        let file = crate::pcap::write(1, &[(0, 0, tcp_packet(1000, &framed).as_slice())]);

        let undeclared = fields_json(&d, &file, None, None);
        assert!(
            !undeclared.contains("payload_decode"),
            "a caller that declared nothing is told nothing about payloads: \
             {undeclared}"
        );

        let miss = FormatMap::new();
        let mut miss = miss;
        miss.declare("other/topic=protobuf")
            .expect("a literal pattern and a built-in format");
        let missed = fields_json(&d, &file, None, Some(&Declarations::new(&miss)));
        assert!(
            missed.contains(
                "\"payload_decode\":{\"state\":\"no_rule\",\
                             \"keyexpr\":\"demo/sensor\"}"
            ),
            "a rule that covers no topic here must say so AND name the keyexpr \
             it was tested against: {missed}"
        );

        let mut map = FormatMap::new();
        map.declare("demo/sensor=protobuf")
            .expect("a literal pattern and a built-in format");
        map.declare("demo/sensor:1=temperature")
            .expect("a field-name declaration");
        let declarations = Declarations::new(&map);
        let decoded = fields_json(&d, &file, None, Some(&declarations));

        let at = decoded
            .find("\"payload_decode\":")
            .unwrap_or_else(|| panic!("the row must carry a payload block: {decoded}"));
        let block = &decoded[at..];
        assert!(
            block.starts_with(
                "\"payload_decode\":{\"state\":\"decoded\",\"keyexpr\":\"demo/sensor\",\
                 \"format\":\"protobuf\",\"fields\":["
            ),
            "the covering rule must DECODE, naming the topic and the decoder: {block}"
        );
        assert!(
            block.contains("\"path\":\"1\",\"name\":\"temperature\",\"value\":\"varint 150\""),
            "the DECLARED name must be attached -- protobuf's wire format \
             carries none, so this is the only place one can come from: {block}"
        );

        // The rebase. The payload's three bytes are the LAST three of the
        // message, so a message-relative span ends where the message does and
        // begins three bytes earlier; `start: 0` is what a missing rebase
        // prints and it is in range.
        let end = push.len();
        let start = end - payload.len();
        assert!(
            block.contains(&alloc::format!("\"start\":{start},\"end\":{end}")),
            "the span must be in the MESSAGE's coordinates ({start}..{end}), \
             not the payload's (0..{}): {block}",
            payload.len()
        );

        // And the ledger saw both declarations apply, which is the half a
        // reader acts on when a rule binds nothing.
        assert!(
            declarations.unused().is_empty(),
            "both declarations applied: {:?}",
            declarations.unused()
        );
    }
}
