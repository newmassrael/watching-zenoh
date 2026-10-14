// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE SINCE DOOR SAYS WHICH HELD ROWS MOVED.
//!
//! A row the since door wrote is held by its consumer from then on, and a cell of
//! it can read differently at a later state (`REVISABLE_ROW_CELLS`). These tests
//! drive one such state and hold what a consumer is owed: the row is written again,
//! whole, under `revised`, and when nothing could have moved the list is empty and
//! no comparison was made. Two kinds of fact are held: the DOCUMENT (the rows
//! listed, and equality with the plain since document everywhere else) and the
//! WORK ([`FieldsStats`], which counts comparisons, so a memory that compared at
//! every call fails even though its documents are right).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

use crate::datagram_tests::{
    frame_carrying, push, sender_space, tcp_packet_on, tcp_packet_reverse, udp_packet,
};
use crate::exchange::tests::{declare_kexpr, request_query, response_final, response_reply};
use crate::fields_json::{
    fields_json_since_coordinated, fields_json_since_remembering, FieldsMemory, RowCoordinates,
    Since,
};
use crate::link::LINKTYPE_ETHERNET;
use crate::Dissection;

const LOW: [u8; 4] = [10, 0, 0, 1];
const HIGH: [u8; 4] = [10, 0, 0, 2];
const ZID_A: &[u8] = &[0xA1, 0xA1, 0xA1, 0xA1];
const ZID_B: &[u8] = &[0xB2, 0xB2, 0xB2, 0xB2];

/// A live handle's numbering: a row is numbered the first time it is seen, from one
/// counter, so a row that arrives later is numbered higher whatever list it is in.
/// What names a list across the changes of the enumeration: its flow and origin,
/// and not its position, which moves when a stream flow appears.
type ListIdentity = (crate::link::FlowKey, crate::MessageListOrigin);

struct Numbered {
    seqs: RefCell<BTreeMap<(ListIdentity, u64), u64>>,
    /// The identity at each position of the enumeration as it stands.
    positions: RefCell<Vec<ListIdentity>>,
    /// A list's id, minted the first time the list is seen and never changed: a
    /// handle's ids name a list for good, which its position in the enumeration
    /// does not.
    list_ids: RefCell<BTreeMap<ListIdentity, u64>>,
    next: Cell<u64>,
}

impl Numbered {
    fn new() -> Self {
        Self {
            seqs: RefCell::new(BTreeMap::new()),
            positions: RefCell::new(Vec::new()),
            list_ids: RefCell::new(BTreeMap::new()),
            next: Cell::new(1),
        }
    }

    /// Number every row of `d` not yet numbered, in list order. Called after each
    /// packet, so the order is the order of arrival.
    fn observe(&self, d: &Dissection) {
        let mut positions = self.positions.borrow_mut();
        positions.clear();
        for (flow, origin, frames) in d.message_lists_with_origin() {
            positions.push((flow, origin));
            let minted = self.list_ids.borrow().len() as u64;
            self.list_ids
                .borrow_mut()
                .entry((flow, origin))
                .or_insert(minted);
            let first = frames.produced() - frames.len() as u64;
            for produced in first..frames.produced() {
                self.seqs
                    .borrow_mut()
                    .entry(((flow, origin), produced))
                    .or_insert_with(|| {
                        let seq = self.next.get();
                        self.next.set(seq + 1);
                        seq
                    });
            }
        }
    }

    /// The highest number issued: the cursor a consumer holds after a call.
    fn through(&self) -> u64 {
        self.next.get() - 1
    }
}

impl RowCoordinates for Numbered {
    fn list_id(&self, list: usize) -> Option<u64> {
        let identity = *self.positions.borrow().get(list)?;
        self.list_ids.borrow().get(&identity).copied()
    }

    fn scouting_list_id(&self, _flow: &crate::link::FlowKey) -> Option<u64> {
        None
    }

    fn row_seq(&self, list: usize, produced: u64) -> Option<u64> {
        let identity = *self.positions.borrow().get(list)?;
        self.seqs.borrow().get(&(identity, produced)).copied()
    }
}

fn init_wire(zid: &[u8]) -> Vec<u8> {
    let mut wire = alloc::vec![
        wz_session_core::wire_const::T_MID_INIT,
        0x09,
        (((zid.len() as u8) - 1) << 4) | 0x02,
    ];
    wire.extend_from_slice(zid);
    wire
}

/// The text of the array under `key`, brackets included.
fn array_of<'a>(doc: &'a str, key: &str) -> &'a str {
    let at = doc
        .find(&alloc::format!("\"{key}\":["))
        .unwrap_or_else(|| panic!("no {key} in {doc}"))
        + key.len()
        + 3;
    let mut depth = 0usize;
    for (i, c) in doc[at..].char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return &doc[at..at + i + 1];
                }
            }
            _ => {}
        }
    }
    panic!("{key} is not closed in {doc}");
}

struct Run {
    d: Dissection,
    packets: Vec<Vec<u8>>,
    numbering: Numbered,
    memory: FieldsMemory,
}

impl Run {
    fn new() -> Self {
        Self {
            d: Dissection::new(),
            packets: Vec::new(),
            numbering: Numbered::new(),
            memory: FieldsMemory::new(),
        }
    }

    fn udp(&mut self, from_low: bool, sport: u16, wire: &[u8]) {
        let packet = if from_low {
            udp_packet(LOW, sport, HIGH, 7447, wire)
        } else {
            udp_packet(HIGH, 7447, LOW, sport, wire)
        };
        self.d
            .push_packet(LINKTYPE_ETHERNET, self.packets.len(), &packet);
        self.packets.push(packet);
        self.numbering.observe(&self.d);
    }

    fn record(&mut self, from_low: bool, sport: u16, record: &[u8]) {
        self.udp(from_low, sport, &frame_carrying(record));
    }

    fn raw(&mut self, packet: Vec<u8>) {
        self.d
            .push_packet(LINKTYPE_ETHERNET, self.packets.len(), &packet);
        self.packets.push(packet);
        self.numbering.observe(&self.d);
    }

    fn messages(&self) -> u64 {
        self.d
            .message_lists()
            .map(|(_, frames)| frames.len() as u64)
            .sum()
    }

    /// The capture as a file, which the datagram rows are re-read from.
    fn file(&self) -> Vec<u8> {
        let rows: Vec<(u32, u32, &[u8])> = self
            .packets
            .iter()
            .map(|p| (0u32, 0u32, p.as_slice()))
            .collect();
        crate::pcap::write(LINKTYPE_ETHERNET, &rows)
    }

    /// The since document at `after`, through the memory.
    fn remembering(&mut self, key: &str, after: u64) -> String {
        let file = self.file();
        fields_json_since_remembering(
            &self.d,
            &file,
            None,
            key,
            &self.numbering,
            Since {
                after_seq: after,
                through_seq: self.numbering.through(),
            },
            &mut self.memory,
        )
    }

    /// The plain since document at `after`: no memory.
    fn plain(&self, after: u64) -> String {
        fields_json_since_coordinated(
            &self.d,
            &self.file(),
            None,
            &self.numbering,
            Since {
                after_seq: after,
                through_seq: self.numbering.through(),
            },
        )
    }
}

/// THE CASE THE LIST IS FOR. A declaration on one link and a reference on another
/// are two flows with nothing joining them until a handshake names their ends:
/// the reference is written unresolved, and when the handshakes arrive the two
/// links are one session, the declaration (stamped at an earlier packet) names the
/// reference, and the row a consumer holds is wrong. It is written again.
#[test]
fn a_handshake_that_joins_two_links_writes_the_unresolved_row_again() {
    let mut r = Run::new();
    r.record(true, 40000, &declare_kexpr(7, "demo/temp"));
    r.record(true, 41000, &push(sender_space(7, None), &[1u8; 12]));
    let first = r.remembering("", 0);
    assert_eq!(array_of(&first, "revised"), "[]", "{first}");
    let held = r.numbering.through();
    // The reference's row, as the consumer holds it: no key expression names it.
    let push_row = 2u64;
    assert!(
        first.contains(&alloc::format!("\"seq\":{push_row},")),
        "the reference row was not written: {first}"
    );

    // The handshakes of both links, in the order that makes them one session.
    r.udp(true, 40000, &init_wire(ZID_A));
    r.udp(false, 40000, &init_wire(ZID_B));
    r.udp(true, 41000, &init_wire(ZID_A));
    r.udp(false, 41000, &init_wire(ZID_B));
    let second = r.remembering("", held);
    // Apart from the rows written again, it is the plain since document.
    assert_eq!(without_revised(&second), r.plain(held));
    let revised = array_of(&second, "revised");
    assert!(
        revised.contains(&alloc::format!("\"seq\":{push_row},")),
        "the reference row is not written again: {second}"
    );
    assert!(
        revised.contains("demo/temp"),
        "the row written again must carry the key expression the join resolved: {revised}"
    );
    let stats = r.memory.stats();
    assert_eq!(stats.compared, 1, "{stats:?}");
    assert_eq!(stats.unchanged, 0, "{stats:?}");
    assert_eq!(stats.revised_rows, 1, "{stats:?}");

    // The rows the cursor lets through are the four handshake rows and nothing
    // else is in `revised` but the one reference row.
    assert_eq!(revised.matches("\"seq\":").count(), 1, "{revised}");

    // And a capture that only grew from here moves nothing and compares nothing.
    let after = r.numbering.through();
    r.record(true, 40000, &push(sender_space(7, None), &[2u8; 12]));
    let third = r.remembering("", after);
    assert_eq!(array_of(&third, "revised"), "[]", "{third}");
    let stats = r.memory.stats();
    assert_eq!((stats.compared, stats.unchanged), (1, 1), "{stats:?}");
}

/// A capture that only grows: every call finds the capture a prefix-extension of
/// the last, compares nothing, lists nothing, and writes exactly the plain since
/// document (the list is empty in both).
#[test]
fn a_capture_that_only_grows_compares_nothing_and_matches_the_plain_door() {
    let mut r = Run::new();
    r.udp(true, 40000, &init_wire(ZID_A));
    r.udp(false, 40000, &init_wire(ZID_B));
    let mut held = 0u64;
    let _ = r.remembering("", held);
    held = r.numbering.through();
    for round in 0..12u64 {
        r.record(
            true,
            40000,
            &push(sender_space(0, Some("demo/a")), &[round as u8; 12]),
        );
        let remembered = r.remembering("", held);
        let plain = r.plain(held);
        assert_eq!(
            remembered, plain,
            "round {round}: the memory changed a document it had nothing to add to"
        );
        assert_eq!(array_of(&remembered, "revised"), "[]");
        held = r.numbering.through();
    }
    let stats = r.memory.stats();
    assert_eq!(stats.compared, 0, "{stats:?}");
    assert_eq!(stats.unchanged, 12, "{stats:?}");
    assert_eq!(stats.revised_rows, 0, "{stats:?}");
}

/// ANTI-VACUITY for the work counter: a late handshake that moves no row still
/// makes the memory compare, so `compared` says the comparison ran and found
/// nothing, and `unchanged` does not.
#[test]
fn a_state_the_memory_cannot_vouch_for_is_compared_even_when_nothing_moved() {
    let mut r = Run::new();
    r.record(
        true,
        40000,
        &push(sender_space(0, Some("demo/a")), &[1u8; 12]),
    );
    r.record(
        true,
        40000,
        &push(sender_space(0, Some("demo/a")), &[2u8; 12]),
    );
    let _ = r.remembering("", 0);
    let held = r.numbering.through();
    // A handshake on the same link: the grouping changes, no held row reads
    // differently.
    r.udp(true, 40000, &init_wire(ZID_A));
    r.udp(false, 40000, &init_wire(ZID_B));
    let doc = r.remembering("", held);
    assert_eq!(array_of(&doc, "revised"), "[]", "{doc}");
    let stats = r.memory.stats();
    assert_eq!((stats.compared, stats.revised_rows), (1, 0), "{stats:?}");
}

/// A memory is for one declaration text: another empties it, and nothing it held
/// is listed after.
#[test]
fn another_declaration_text_empties_the_memory() {
    let mut r = Run::new();
    r.record(true, 40000, &declare_kexpr(7, "demo/temp"));
    r.record(true, 41000, &push(sender_space(7, None), &[1u8; 12]));
    let _ = r.remembering("one", 0);
    let held = r.numbering.through();
    r.udp(true, 40000, &init_wire(ZID_A));
    r.udp(false, 40000, &init_wire(ZID_B));
    r.udp(true, 41000, &init_wire(ZID_A));
    r.udp(false, 41000, &init_wire(ZID_B));
    // The same state that revised a row above, under another text.
    let doc = r.remembering("two", held);
    assert_eq!(array_of(&doc, "revised"), "[]", "{doc}");
    let stats = r.memory.stats();
    assert_eq!(
        (stats.compared, stats.unchanged, stats.revised_rows),
        (0, 0, 0),
        "{stats:?}"
    );
}

/// A stream message: its length as a little-endian u16, then the message.
fn framed(message: &[u8]) -> Vec<u8> {
    let mut out = (message.len() as u16).to_le_bytes().to_vec();
    out.extend_from_slice(message);
    out
}

/// The document with its `revised` list emptied, for comparing a document that
/// wrote rows again with the plain one, which never does.
fn without_revised(doc: &str) -> String {
    let list = array_of(doc, "revised");
    doc.replacen(&alloc::format!("\"revised\":{list}"), "\"revised\":[]", 1)
}

/// The record a session carries at step `i`: a put under the declared alias, a
/// query, its answer and its close, in turn.
fn record_at(i: u64) -> Vec<u8> {
    let rid = i / 4 + 1;
    match i % 4 {
        0 => push(sender_space(7, None), &[i as u8; 24]),
        1 => request_query(rid, sender_space(0, Some("demo/q"))),
        2 => response_reply(rid, sender_space(0, Some("demo/q")), b"ok"),
        _ => response_final(rid),
    }
}

/// THE WALK THAT CONTINUES. After a first document, each step of a growing session
/// is walked from where the last one stopped: the document is exactly the plain
/// since document, and the walk visited the messages that arrived and no others.
/// The equality is what makes the state kept between calls safe to trust; the
/// count is what makes it worth keeping, since a walk that began again every time
/// writes the same documents.
#[test]
fn a_walk_that_continues_visits_only_the_new_messages_and_writes_the_plain_document() {
    let mut r = Run::new();
    r.udp(true, 40000, &init_wire(ZID_A));
    r.udp(false, 40000, &init_wire(ZID_B));
    r.record(true, 40000, &declare_kexpr(7, "demo/temp"));
    let first = r.remembering("", 0);
    assert_eq!(first, r.plain(0), "the first document");
    let mut held = r.numbering.through();
    for i in 0..24u64 {
        let m0 = r.messages();
        r.record(i % 2 == 0, 40000, &record_at(i));
        let arrived = r.messages() - m0;
        assert!(arrived > 0, "step {i} produced no message");
        let before = r.memory.stats();
        let doc = r.remembering("", held);
        assert_eq!(
            doc,
            r.plain(held),
            "step {i}: the walk that continued wrote another document"
        );
        let after = r.memory.stats();
        assert_eq!(
            after.resumed - before.resumed,
            1,
            "step {i}: {before:?} then {after:?}"
        );
        assert_eq!(
            after.restarted - before.restarted,
            0,
            "step {i}: {before:?} then {after:?}"
        );
        assert_eq!(
            after.messages_walked - before.messages_walked,
            arrived,
            "step {i}: the walk must visit the {arrived} message(s) that arrived and no others"
        );
        held = r.numbering.through();
    }
}

/// The same, with a stream flow beside the datagram one: the stream walk keeps
/// its chain fold and its place in the capture order, and the table it resolves
/// against is the one the datagram flow's declaration went into.
#[test]
fn a_walk_over_a_stream_flow_and_a_datagram_flow_continues_and_equals_the_plain_document() {
    let mut r = Run::new();
    let (mut seq_low, mut seq_high) = (0u32, 0u32);
    let init_a = framed(&frame_carrying(&init_wire(ZID_A)));
    let init_b = framed(&frame_carrying(&init_wire(ZID_B)));
    r.raw(tcp_packet_on(1111, seq_low, &init_a));
    seq_low += init_a.len() as u32;
    r.raw(tcp_packet_reverse(seq_high, &init_b));
    seq_high += init_b.len() as u32;
    r.record(true, 40000, &declare_kexpr(7, "demo/temp"));
    let _ = r.remembering("", 0);
    let mut held = r.numbering.through();
    for i in 0..16u64 {
        let m0 = r.messages();
        let wire = framed(&frame_carrying(&record_at(i)));
        if i % 2 == 0 {
            r.raw(tcp_packet_on(1111, seq_low, &wire));
            seq_low += wire.len() as u32;
        } else {
            r.raw(tcp_packet_reverse(seq_high, &wire));
            seq_high += wire.len() as u32;
        }
        r.record(true, 40000, &push(sender_space(7, None), &[i as u8; 12]));
        let arrived = r.messages() - m0;
        let before = r.memory.stats();
        let doc = r.remembering("", held);
        assert_eq!(doc, r.plain(held), "step {i}");
        let after = r.memory.stats();
        assert_eq!(
            (
                after.resumed - before.resumed,
                after.restarted - before.restarted
            ),
            (1, 0),
            "step {i}: {before:?} then {after:?}"
        );
        assert_eq!(
            after.messages_walked - before.messages_walked,
            arrived,
            "step {i}"
        );
        held = r.numbering.through();
    }
}

/// A cursor BEHIND the last document's ceiling asks for rows the walk would have
/// skipped, so the walk begins again, and the document is still the plain one.
#[test]
fn a_cursor_behind_the_last_ceiling_walks_whole_and_still_equals() {
    let mut r = Run::new();
    r.udp(true, 40000, &init_wire(ZID_A));
    r.udp(false, 40000, &init_wire(ZID_B));
    let _ = r.remembering("", 0);
    for i in 0..6u64 {
        r.record(i % 2 == 0, 40000, &record_at(i));
        let held = r.numbering.through();
        let _ = r.remembering("", held - 1);
    }
    let held = r.numbering.through();
    r.record(true, 40000, &record_at(6));
    let before = r.memory.stats();
    let doc = r.remembering("", held - 3);
    assert_eq!(doc, r.plain(held - 3));
    let after = r.memory.stats();
    assert_eq!(
        (
            after.resumed - before.resumed,
            after.restarted - before.restarted
        ),
        (0, 1),
        "{before:?} then {after:?}"
    );
}

/// A stream flow appearing in front of the datagram lists moves the position the
/// walker keeps its state by: the walk begins again, and equals the plain document.
#[test]
fn a_new_stream_flow_begins_the_walk_again_and_it_still_equals() {
    let mut r = Run::new();
    r.udp(true, 40000, &init_wire(ZID_A));
    r.udp(false, 40000, &init_wire(ZID_B));
    r.record(true, 40000, &declare_kexpr(7, "demo/temp"));
    let _ = r.remembering("", 0);
    let mut held = r.numbering.through();
    r.record(true, 40000, &record_at(0));
    let _ = r.remembering("", held);
    held = r.numbering.through();
    r.raw(tcp_packet_on(
        2222,
        0,
        &framed(&frame_carrying(&record_at(1))),
    ));
    let before = r.memory.stats();
    let doc = r.remembering("", held);
    assert_eq!(doc, r.plain(held));
    let after = r.memory.stats();
    assert_eq!(
        after.restarted - before.restarted,
        1,
        "{before:?} then {after:?}"
    );
}

/// A ceiling on the frames a flow keeps trims its front, which renumbers the
/// positions the walker kept, so each trimmed step walks whole and still equals.
#[test]
fn a_trimmed_list_walks_whole_and_still_equals_the_plain_document() {
    let limits = crate::DissectionLimits {
        frames_per_flow: Some(6),
        ..crate::DissectionLimits::default()
    };
    let mut r = Run::new();
    r.d = Dissection::with_limits(limits);
    r.udp(true, 40000, &init_wire(ZID_A));
    r.udp(false, 40000, &init_wire(ZID_B));
    let _ = r.remembering("", 0);
    let mut held = r.numbering.through();
    for i in 0..14u64 {
        r.record(i % 2 == 0, 40000, &record_at(i));
        let doc = r.remembering("", held);
        // Apart from the rows written again. The trim takes the handshake out of
        // the list, so rows held before it read a different cause for an
        // unresolved reference afterwards (`no_declaration` while the session was
        // known, `no_session` once it is not), and that IS a held row that moved:
        // the plain door does not say so and this one does.
        assert_eq!(without_revised(&doc), r.plain(held), "step {i}");
        held = r.numbering.through();
    }
    let stats = r.memory.stats();
    assert!(stats.restarted > 1, "{stats:?}");
    assert!(
        stats.revised_rows > 0,
        "trimming the handshake away must have moved a held row: {stats:?}"
    );
}
