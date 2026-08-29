// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
/// again (see the module doc). `max_messages_shown_per_flow` bounds each flow's
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
    max_messages_shown_per_flow: Option<usize>,
    declarations: Option<&Declarations<'_>>,
) -> String {
    // A map with no rules answers `NoRules` for every message, so it renders
    // nothing either way -- folded here so the row renderers ask one question
    // rather than two.
    let declarations = declarations.filter(|d| !d.is_empty());
    // R2100 (open-debt item 509) — the document's own revision, first key. See
    // `doc_revision`; the census document opens the same way.
    let mut out = String::from("{");
    crate::doc_revision::envelope_into(crate::doc_revision::FIELDS, &mut out);
    out.push_str(",\"stream_flows\":[");
    for (i, flow) in d.flows().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_stream_flow(flow, max_messages_shown_per_flow, declarations, &mut out);
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
            max_messages_shown_per_flow,
            declarations,
            &mut out,
        );
    }
    // Said rather than left to be inferred from empty datagram listings: a
    // capture this reader cannot parse a second time yields no datagram rows
    // for a reason that has nothing to do with the traffic.
    let _ = write!(out, "],\"capture_reread\":{},", reread.is_some());
    // R311y917 (open-debt item 366) — WHAT A CEILING COST, in the document the
    // ceiling made short.
    //
    // The field layer was the one read plane with no way to be bounded, and
    // adding the door without this would have made it silent in the way
    // R311y885 measured for the census: a plane made short by an evicted flow
    // reads exactly like a quiet network. The group is the SAME rendering the
    // summary's health object and the census document carry
    // (`report::dropped_by_limits_json`), a second consumer rather than a
    // second rendering.
    //
    // Emitted STRUCTURALLY, for the reason that rendering's own doc gives:
    // every counter is zero for a dissection built without caps, and a
    // consumer that can only see the group when it is non-zero cannot tell
    // "no caps" from "caps that did not bite".
    out.push_str("\"dropped_by_limits\":");
    out.push_str(&crate::report::dropped_by_limits_json(d));
    out.push(',');
    // R311y875 — the run's misbound rules, AFTER every row producer, for the
    // reason `wz-analyze` places its unbound-declaration note there: this is a
    // fact about what the capture turned out to hold, and both producers above
    // decide it while they walk. Emitted even for a caller that declared
    // nothing, so the key is structural rather than conditional.
    crate::payload_decode::push_misbindings(declarations, &mut out);
    out.push('}');
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
            // Round 2029 (item 298) — TELL THE RULE RUN. The misbinding verdict
            // is reached inside `push_walk` below, so a message held back here
            // is one no rule was applied to: the tally beside the findings is
            // a floor from this point on. Both surfaces already emitted their
            // own `omitted` and nothing joined them, which is the item.
            if let Some(d) = declarations {
                d.note_unwalked();
            }
            continue;
        }
        shown += 1;
        if emitted > 0 {
            out.push(',');
        }
        emitted += 1;
        let at = message_at(frame);
        let _ = write!(
            out,
            // R311y919 — the word comes from `AnchorSpace` now, so this row and
            // the census planes cannot drift into two vocabularies for one fact.
            "{{\"direction\":\"{}\",\"offset_space\":\"{}\",\"message_at\":{at},",
            dir_name(frame.direction),
            crate::AnchorSpace::StreamBytes.name()
        );
        match flow.message_bytes(frame) {
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
            // Item 298 — the datagram half of the same join. Both listings cap,
            // so a fix on one of them would leave a capture of a UDP
            // deployment reporting exact counts it does not have.
            if let Some(d) = declarations {
                d.note_unwalked();
            }
            continue;
        }
        shown += 1;
        if emitted > 0 {
            out.push(',');
        }
        emitted += 1;
        let _ = write!(
            out,
            "{{\"direction\":\"{}\",\"offset_space\":\"{}\",\"packet\":{index},",
            dir_name(frame.direction),
            crate::AnchorSpace::PacketIndex.name()
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

/// Where a stream message begins, through the crate's one accessor.
///
/// R311y900 — the arithmetic and the slice that reads it used to live here,
/// private, and item 406 needed the slice from OUTSIDE the crate: a witness
/// asserting on a foreign implementation's field values cannot go through
/// this renderer's JSON without re-deriving what it is trying to judge. Both
/// moved to [`crate::FlowDissection`] and this file kept the two call sites.
fn message_at(frame: &PassiveFrame) -> usize {
    crate::FlowDissection::message_at(frame)
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

    /// R2100 (open-debt item 509) — THE FIELD DOCUMENT'S KEY SET IS PINNED
    /// AGAINST ITS REVISION.
    ///
    /// The census document got this at R311y923 and this one did not, which is
    /// half of what item 509 measured: `fields_json.rs` was named in the same
    /// breath as `census_json.rs` and had neither a revision nor a pin. A
    /// consumer of `wz_dissect_pcap_fields` had no way to be told a key had
    /// moved and the author had nothing that would notice.
    ///
    /// # The fixture is the RICH one, on purpose
    ///
    /// `census_json::tests::every_plane_capture_with_file` carries declares,
    /// interests, a Put, a Query and its closing Reply — so the document it
    /// produces reaches the row renderers rather than one KeepAlive's worth of
    /// them. A pin taken over a thin capture silently stops covering every key
    /// that capture never reaches, which is a gate that reads green while the
    /// keys it was written for go unwatched.
    ///
    /// ⚠ R2175 (open-debt item 552) — THE `declarations: None` READING WAS
    /// WRONG, and it is corrected here rather than argued with.
    ///
    /// This test used to drive the mapping argument as `None`, on the note that
    /// "a payload map is the operator's input, not the capture's, and the keys
    /// it adds belong to a revision that declares them". The first half is
    /// true; the second described something that had not happened. MEASURED:
    /// with a mapping supplied the document gains fifteen keys —
    /// `payload_decode`, `state`, `descriptor_bytes`, `under`, `wrong` and the
    /// rest — and revision 1 declared not one of them. So the subtree was
    /// emitted to consumers, pinned by nothing, and two rounds (R2025 item 285,
    /// R2170 item 546) added keys to it with no number moving. The pin's own
    /// paragraph above — "a pin taken over a thin capture silently stops
    /// covering every key that capture never reaches" — was true of this test.
    ///
    /// Both branches now, which is `wz-capi-dissect`'s ruling for the two
    /// verdict documents applied here: a pin over one branch leaves the other's
    /// keys unwatched, and that is a gate reading green over half a contract.
    /// The union is compared against `newest`, not against `FIELDS_R1_KEYS` by
    /// name — R2123's correction on the census, which this test had not had.
    ///
    /// Gated on `network-codecs` because the fixture is: without the decoders a
    /// Push inside a frame is an unknown MID, so the document would be pinned
    /// over a capture whose rows never rendered — a pin taken on a shape that
    /// only exists in that build.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn the_field_documents_key_set_is_pinned() {
        use crate::payload::formats::FormatMap;
        use crate::payload_decode::Declarations;
        let (d, file) =
            crate::census_json::fed_tests::every_plane_capture_with_file("demo/temp", None, false);
        let mut map = FormatMap::new();
        map.declare("demo/**=json").expect("a keyexpr pattern");
        let run = Declarations::new(&map);

        let mut seen: Vec<&str> = Vec::new();
        let with = fields_json(&d, &file, None, Some(&run));
        let without = fields_json(&d, &file, None, None);
        for doc in [&with, &without] {
            seen.extend(crate::doc_revision::key_set(doc));
        }
        seen.sort_unstable();
        seen.dedup();
        // A SUBSET, and the sibling test is what makes that sound: this fixture
        // reaches two of the eight decode states, so the arms it does not take
        // are pinned by `the_field_documents_payload_plane_is_pinned_over_every_arm`
        // instead. Asserting equality here would force this capture to produce
        // every arm, which is the fixture nobody can keep whole.
        let pinned: Vec<&str> = crate::doc_revision::newest(crate::doc_revision::FIELDS)
            .expect("the field document has a revision")
            .keys
            .to_vec();
        let stray: Vec<&&str> = seen.iter().filter(|k| !pinned.contains(k)).collect();
        assert!(
            stray.is_empty(),
            "the field document emits {stray:?}, which no revision declares; if that \
             is deliberate, APPEND a revision to `doc_revision::DOCUMENT_HISTORY` \
             carrying the new set — and if a key is going away, announce it in the \
             previous revision's `retiring` first"
        );
        assert!(
            seen.len() >= crate::doc_revision::FIELDS_R1_KEYS.len(),
            "this fixture reached {} keys, fewer than revision 1's own set; a pin \
             over a capture that stopped rendering is a gate measuring nothing",
            seen.len()
        );
    }

    /// R2175 (open-debt item 552) — THE PAYLOAD PLANE OF THIS DOCUMENT,
    /// RENDERED FROM ITS OWN TYPES RATHER THAN FROM WHATEVER A CAPTURE REACHED.
    ///
    /// # What the pin above could not see, measured
    ///
    /// `the_field_documents_key_set_is_pinned` drives `declarations: None`, on
    /// the reading that "a payload map is the operator's input, not the
    /// capture's". The consequence was not stated and is this: with a mapping
    /// supplied the document gains FIFTEEN keys — `payload_decode`, `state`,
    /// `descriptor_bytes` and the rest — and revision 1 pins none of them. So
    /// R2170 added `descriptor_bytes` to a shipped document and no revision
    /// moved, because no revision had ever covered the subtree it landed in.
    ///
    /// # Why the renderers and not a richer capture
    ///
    /// Eight `PayloadDecoding` states, three `RefusedUnder` and two `Misbound`
    /// are reachable by rendering the TYPE; making one capture produce all
    /// thirteen would be a fixture nobody can keep whole, and a fixture that
    /// stopped reaching an arm would take the arm's keys out of the pin
    /// silently — which is the failure this test exists to end. The walks
    /// (`PayloadDecoding::all`, `RefusedUnder::names`, `Misbound::names`) are
    /// each bound to an exhaustive match, so a variant added later joins this
    /// population at `cargo build` rather than when someone remembers.
    ///
    /// The union of the document AND the renderings, because neither alone is
    /// the document a consumer reads: the capture supplies the surrounding
    /// rows, the renderings supply the arms it did not take.
    #[cfg(feature = "network-codecs")]
    #[test]
    fn the_field_documents_payload_plane_is_pinned_over_every_arm() {
        use crate::doc_revision as rev;
        use crate::payload::formats::FormatMap;
        use crate::payload_decode::{
            push_decoding, push_misbinding, push_refusal, Declarations, Misbinding, Misbound,
            PayloadDecoding, RefusedUnder,
        };

        let (d, file) =
            crate::census_json::fed_tests::every_plane_capture_with_file("demo/temp", None, false);
        let mut map = FormatMap::new();
        map.declare("demo/**=json").expect("a keyexpr pattern");
        let run = Declarations::new(&map);

        let mut rendered = alloc::vec![fields_json(&d, &file, None, Some(&run))];
        let states = PayloadDecoding::all();
        assert_eq!(
            states.len(),
            PayloadDecoding::STATES.len(),
            "the variant walk and the word list must stay the same length, or this \
             population is short by however many arms the walk stopped at"
        );
        for state in &states {
            let mut out = String::new();
            push_decoding(state, &mut out);
            rendered.push(out);
        }
        // THE ONE SHAPE THE WALK CANNOT SUPPLY, and it is a discriminant walk's
        // structural limit rather than an omission. `PayloadDecoding::next`
        // builds each variant with EMPTY payloads — its own doc says the data
        // is furniture there — so the `Decoded` arm it yields carries no
        // decoded field, and `fields[]`'s own object never opens. `path` is
        // emitted only from inside it. Measured: without this the union is 51
        // keys and `path` is not one of them, so a key a consumer receives
        // would have been pinned by nothing for the second time in one
        // document.
        rendered.push({
            let mut out = String::new();
            push_decoding(
                &PayloadDecoding::Decoded {
                    keyexpr: String::from("demo/**"),
                    format: String::from("json"),
                    fields: alloc::vec![crate::payload::formats::PayloadField {
                        path: String::from("$.a"),
                        name: None,
                        value: String::from("1"),
                        start: 0,
                        end: 1,
                    }],
                    despite_encoding: None,
                },
                &mut out,
            );
            out
        });

        // Constructed rather than captured, for the reason the doc gives: the
        // WALK is the population, and each variant only has to be RENDERED for
        // its keys and its word to join the pin.
        for under in [
            RefusedUnder::Corroborated,
            RefusedUnder::Unclaimed,
            RefusedUnder::Refuted,
        ] {
            let mut out = String::new();
            push_refusal(
                &crate::payload_decode::Refusal {
                    keyexpr: String::from("demo/**"),
                    format: String::from("json"),
                    under,
                    samples: 1,
                    example: String::from("byte 0"),
                },
                &mut out,
            );
            rendered.push(out);
        }
        for wrong in [Misbound::Rule, Misbound::Publisher] {
            let mut out = String::new();
            push_misbinding(
                &Misbinding {
                    keyexpr: String::from("demo/**"),
                    format: String::from("json"),
                    declared: String::from("text/plain"),
                    wrong,
                    publisher: None,
                    samples: 1,
                },
                &mut out,
            );
            rendered.push(out);
        }
        // The two arms above are written out, so the count is asserted against
        // the walks that ARE compiler-bound: a fourth `RefusedUnder` or a third
        // `Misbound` fails here rather than quietly leaving its word unpinned.
        assert_eq!(
            RefusedUnder::names().len(),
            3,
            "a RefusedUnder arm was added"
        );
        assert_eq!(Misbound::names().len(), 2, "a Misbound arm was added");

        let mut seen: Vec<&str> = Vec::new();
        for doc in &rendered {
            seen.extend(rev::key_set(doc));
        }
        seen.sort_unstable();
        seen.dedup();
        let expected: Vec<&str> = rev::newest(rev::FIELDS)
            .expect("the field document has a revision")
            .keys
            .to_vec();
        assert_eq!(
            seen, expected,
            "the field document's key set moved once the payload plane is counted; \
             if that is deliberate, APPEND a revision to \
             `doc_revision::DOCUMENT_HISTORY` carrying the new set"
        );
    }

    /// R2175 (open-debt item 552) — A DECLARED VOCABULARY IS THE LIBRARY'S OWN,
    /// AND WIDENING ONE COSTS A REVISION.
    ///
    /// # The defect, restated as the thing this asserts
    ///
    /// R2170 added `not_on_the_wire` as an eighth `payload_decode.state` and
    /// the header says it REPLACES what used to be reported as `no_payload`.
    /// Same key, same document revision, a different answer about the same
    /// record. Nothing moved, and nothing could have: the key-set pin sees keys,
    /// and a consumer's `switch` reads the string inside one. The consuming
    /// surface that reported this found it while moving its own pin, not from
    /// any signal wz sent.
    ///
    /// # Why this compares against the WALK and not against a second list
    ///
    /// `PayloadDecoding::STATES`, `RefusedUnder::names` and `Misbound::names`
    /// are each bound to an exhaustive match, so they are what the library
    /// actually emits. The `DOCUMENT_HISTORY` row is a SNAPSHOT of that, written
    /// out per revision — see [`crate::doc_revision::ValueFamily::values`] for
    /// why it must not simply point at the constant. This test is the joint: a
    /// word added to a walk fails here, and the only way to pass is to append a
    /// revision that carries it, which is exactly the notice a consumer needs.
    ///
    /// The three arms are COLLECTED rather than asserted where they are read: an
    /// arm that panics leaves the later ones unmeasured, and unmeasured must not
    /// read as passed.
    #[test]
    fn the_declared_value_families_match_the_librarys_own_vocabularies() {
        use crate::doc_revision as rev;
        use crate::payload_decode::{Misbound, PayloadDecoding, RefusedUnder};

        let vocabulary = |document: &str, key: &str| -> (u32, Vec<&'static str>) {
            let newest = rev::newest(document).expect("the document has a revision");
            let family = newest
                .families
                .iter()
                .find(|f| f.key == key)
                .unwrap_or_else(|| {
                    panic!(
                        "the {document} document declares no family for {key:?}; a key \
                         a consumer switches on with no declared vocabulary is the \
                         whole of item 552"
                    )
                });
            (newest.revision, family.values.to_vec())
        };
        let sorted = |mut v: Vec<&'static str>| {
            v.sort_unstable();
            v
        };

        // Every family in the table, against the walk that produces its words.
        // BOTH documents, because the census carries five of the eight and a
        // gate over one document would leave the other's unwatched — the
        // half-a-contract shape `wz-capi-dissect`'s verdict pins already name.
        let mut failures: Vec<String> = Vec::new();
        let live: [(&str, &str, Vec<&'static str>); 8] = [
            (rev::FIELDS, "state", PayloadDecoding::STATES.to_vec()),
            (rev::FIELDS, "under", RefusedUnder::names()),
            (rev::FIELDS, "wrong", Misbound::names()),
            (rev::FIELDS, "offset_space", crate::AnchorSpace::names()),
            (
                rev::FIELDS,
                "direction",
                crate::census_json::direction_names(),
            ),
            (rev::CENSUS, "kind", crate::interest::InterestKind::names()),
            (rev::CENSUS, "mode", crate::interest::InterestMode::names()),
            (rev::CENSUS, "offset_space", crate::AnchorSpace::names()),
        ];
        for (document, key, words) in live {
            // A walk that came back empty would make the comparison below
            // trivially true, which is this workspace's most expensive
            // recurring defect in its smallest form.
            assert!(
                !words.is_empty(),
                "the walk for {document}.{key:?} produced no words"
            );
            let (revision, declared) = vocabulary(document, key);
            if declared != sorted(words.clone()) {
                failures.push(alloc::format!(
                    "{document}.{key}: the library emits {:?} and revision {revision} \
                     declares {declared:?}. A value vocabulary that widened without a \
                     revision is item 552 happening again: APPEND a revision to \
                     `doc_revision::DOCUMENT_HISTORY` carrying the new set, so a \
                     consumer pinned to the old one is told its switch is no longer \
                     exhaustive.",
                    sorted(words),
                ));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n\n"));

        // The `asker` / `declarer` pair carries the endpoint vocabulary too and
        // is checked here rather than in the table above, because listing one
        // walk under three keys would make the count read as three
        // independent facts. What IS asserted is that no family in either
        // document escaped the table: every declared family is either checked
        // above or shares a vocabulary constant with one that is.
        let census = rev::newest(rev::CENSUS).expect("a revision");
        let fields = rev::newest(rev::FIELDS).expect("a revision");
        let endpoints = sorted(crate::census_json::direction_names());
        for key in ["asker", "declarer"] {
            let (_, declared) = vocabulary(rev::CENSUS, key);
            assert_eq!(declared, endpoints, "census.{key}");
        }
        assert_eq!(
            census.families.len() + fields.families.len(),
            10,
            "a family was declared without joining this gate; every family in \
             either document must be held to a walk, or the one that is not is \
             a vocabulary that can widen in silence again"
        );
    }

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

    /// One framed `Frame` whose extension chain carries the mandatory transport
    /// QoS — `transport::frame::ext::QoS`, `zextz64!(0x1, true)`, so the header
    /// byte is the id, the MANDATORY flag and the `Z64` encoding.
    fn framed_frame_with_qos() -> Vec<u8> {
        let msg = vec![
            wz_session_core::wire_const::T_MID_FRAME | 0x80,
            0x01, // sn
            0x01 | 0x10 | 0x20,
            0x03, // the z64 body
        ];
        let mut out = vec![msg.len() as u8, 0];
        out.extend_from_slice(&msg);
        out
    }

    /// THE EXTENSION'S NAME REACHES THE CONSUMED SURFACE, not just the tree.
    ///
    /// `ext_name` is resolved down in the field walker, and a name that stopped
    /// there would be a finding with no plane: the analyzer's readers consume
    /// this JSON, so the label has to survive `to_json`'s rendering to be worth
    /// anything. That is what this asserts, and it also exercises the TRANSPORT
    /// carrier mapping, which the walker's own tests do not reach.
    ///
    /// The value matters as much as the presence: `0x1` is `qos` on a `Frame`
    /// and `qos` on an `Init` too, but a `Frame` declares it MANDATORY where
    /// `Init` does not, so a table that dropped that bit would name this nothing.
    #[test]
    fn an_extensions_name_reaches_the_json_a_reader_consumes() {
        let packet = tcp_packet(1000, &framed_frame_with_qos());
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &packet);
        d.finish();

        let file = crate::pcap::write(1, &[(0, 0, packet.as_slice())]);
        let json = fields_json(&d, &file, None, None);

        assert!(
            json.contains("\"name\":\"Frame\""),
            "the row must be a walked Frame, not a decline: {json}"
        );
        assert!(
            json.contains(
                "\"name\":\"ext_name\",\"start\":2,\"end\":3,\
                           \"kind\":\"label\",\"value\":\"qos\""
            ),
            "the extension must reach the reader NAMED, aliasing its header \
             byte's own span: {json}"
        );
        assert!(
            json.contains(
                "\"name\":\"ext_id\",\"start\":2,\"end\":3,\
                           \"kind\":\"bits\",\"value\":1"
            ),
            "and its id must be the four bits zenoh gives it, not five: {json}"
        );
        assert!(
            json.contains(
                "\"name\":\"m\",\"start\":2,\"end\":3,\
                           \"kind\":\"flag\",\"value\":true"
            ),
            "and the mandatory bit must be its own field: {json}"
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
    fn the_misbinding_counts_say_they_are_a_floor_when_a_cap_bit() {
        use crate::payload::formats::FormatMap;
        use crate::payload_decode::Declarations;

        // THREE samples on one topic, all under a rule that is wrong for them:
        // declared JSON, and the rule says protobuf. Three so a cap of one has
        // two messages to hold back.
        let payload = br#"{"a":1}"#;
        let mut framed = Vec::new();
        for _ in 0..3 {
            let push = crate::datagram_tests::frame_carrying(
                &crate::payload::tests_support::push_declaring("demo/sensor", 5, payload),
            );
            framed.push(push.len() as u8);
            framed.push(0);
            framed.extend_from_slice(&push);
        }
        let mut d = Dissection::new();
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &framed));
        d.finish();
        let file = crate::pcap::write(1, &[(0, 0, tcp_packet(1000, &framed).as_slice())]);

        let mut map = FormatMap::new();
        map.declare("demo/**=protobuf").expect("a keyexpr pattern");

        // UNCAPPED: every message walked, so the count beside the finding is
        // the whole answer.
        let whole = Declarations::new(&map);
        let out = fields_json(&d, &file, None, Some(&whole));
        assert_eq!(whole.unwalked(), 0, "nothing was held back: {out}");
        assert!(whole.counts_are_exact(), "so the counts are exact: {out}");
        assert!(
            out.contains("\"payload_mapping_counts_exact\":true"),
            "and the document says so: {out}"
        );
        // THE POPULATION. Without a finding to qualify, everything above and
        // below is true of an empty array.
        let found = whole.misbindings();
        assert_eq!(found.len(), 1, "one rule is misbound: {found:?}");
        assert_eq!(found[0].samples, 3, "over all three samples: {found:?}");

        // CAPPED AT ONE: two messages are never walked, so no rule is applied
        // to them and the count is a floor.
        let capped = Declarations::new(&map);
        let out = fields_json(&d, &file, Some(1), Some(&capped));
        assert_eq!(
            capped.unwalked(),
            2,
            "the cap held two messages back: {out}"
        );
        assert!(!capped.counts_are_exact());
        assert!(
            out.contains("\"payload_mapping_counts_exact\":false"),
            "and the document must SAY the counts are a floor -- this is item \
             298: {out}"
        );
        // ⚠ THE FINDING SURVIVES AND THE NUMBER DOES NOT. That asymmetry is
        // the whole reason the flag is worth having: a reader who saw
        // `samples: 1` with nothing beside it would take a three-sample
        // misbinding for a one-off.
        let found = capped.misbindings();
        assert_eq!(found.len(), 1, "the rule is still named: {found:?}");
        assert_eq!(found[0].samples, 1, "but the count is short: {found:?}");
    }

    /// ITEM 298, THE DATAGRAM DOOR — both listings cap, so both must say so.
    ///
    /// # Why this leg exists, as what happened rather than as a principle
    ///
    /// The stream witness above landed green, and removing the datagram
    /// listing's `note_unwalked` SURVIVED the whole suite. Four rounds running
    /// now, the first witness has been written against whichever door was
    /// convenient and the other has gone unasked — 2013 at `push_fragment`,
    /// 2014 at the reassembly door, 2019 at the space check, and this.
    ///
    /// A UDP deployment is not the exotic case here: multicast scouting and
    /// every `udp/...` link land in this listing, so a capture of one would
    /// have reported exact counts it did not have.
    #[test]
    fn the_datagram_listing_says_its_counts_are_a_floor_too() {
        use crate::payload::formats::FormatMap;
        use crate::payload_decode::Declarations;

        // Three samples on one topic, each its own datagram, all declared JSON
        // under a protobuf rule.
        let payload = br#"{"a":1}"#;
        let mut packets = Vec::new();
        for _ in 0..3 {
            packets.push(udp_packet(
                [10, 0, 0, 1],
                43210,
                [10, 0, 0, 2],
                7447,
                &crate::datagram_tests::frame_carrying(
                    &crate::payload::tests_support::push_declaring("demo/sensor", 5, payload),
                ),
            ));
        }
        let mut d = Dissection::new();
        for (i, p) in packets.iter().enumerate() {
            d.push_packet(LINKTYPE_ETHERNET, i, p);
        }
        d.finish();
        let refs: Vec<(u32, u32, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (i as u32, 0u32, p.as_slice()))
            .collect();
        let file = crate::pcap::write(1, &refs);

        let mut map = FormatMap::new();
        map.declare("demo/**=protobuf").expect("a keyexpr pattern");

        // THE POPULATION FIRST, on the uncapped run: without three misbound
        // samples in the DATAGRAM listing this leg is about nothing.
        let whole = Declarations::new(&map);
        let out = fields_json(&d, &file, None, Some(&whole));
        let found = whole.misbindings();
        assert_eq!(found.len(), 1, "one rule is misbound: {found:?}\n{out}");
        assert_eq!(found[0].samples, 3, "over all three: {found:?}");
        assert_eq!(whole.unwalked(), 0);

        let capped = Declarations::new(&map);
        let out = fields_json(&d, &file, Some(1), Some(&capped));
        assert_eq!(capped.unwalked(), 2, "the cap held two back: {out}");
        assert!(
            out.contains("\"payload_mapping_counts_exact\":false"),
            "the datagram listing must say its counts are a floor too: {out}"
        );
    }

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
                 \"despite_encoding\":null,\"format\":\"protobuf\",\"fields\":["
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
