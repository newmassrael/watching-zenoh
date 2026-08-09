// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y613 (§1.1f) — the first AGGREGATION plane: per-keyexpr throughput.
//!
//! Every layer below this one answers a question about ONE message. A reader
//! asking "which keyexpr is this capture actually carrying, and how much" had
//! to write the fold itself, and the fold is not the easy part — resolving a
//! wire keyexpr is, and the crate had no home for it.
//!
//! ## Why the observer can resolve what a participant cannot
//!
//! A keyexpr id means nothing on its own: it indexes the id space of whoever
//! DECLARED it, and the `M` bit picks the space. A participant holds ONE of the
//! two tables — the peer's — so [`wz_session_core::wireexpr_resolve`] answers
//! `None` for an `M=0` reference rather than reading it out of the wrong space,
//! and that refusal is correct there (R311y604).
//!
//! An observer is in a different position, and it is the whole reason this
//! module can exist: it sees BOTH directions, so it can build BOTH spaces and
//! the `M` bit becomes a routing decision rather than a refusal.
//!
//! | travelling | `M` | names | resolved against |
//! |---|---|---|---|
//! | A→B | 1 (`WireexprLocal`) | the sender's space | A's table |
//! | A→B | 0 (`WireexprNonlocal`) | the receiver's space | B's table |
//! | either | — | `id == 0`: the suffix IS the keyexpr | no table |
//!
//! zenoh reaches the `M=0` row constantly rather than theoretically: when it
//! renders a keyexpr for a face it PREFERS the id the peer declared and stamps
//! it `Mapping::Receiver` (`dispatcher/resource.rs:625`). A capture of any
//! session where both sides declare is therefore full of references a
//! single-space resolver must refuse.
//!
//! ## What is never guessed
//!
//! A reference this table cannot resolve is COUNTED AND NAMED
//! ([`ThroughputTable::unresolved`]), never attributed to a keyexpr. Both sides
//! number their mappings from 1, so a wrong-space or stale read very likely
//! FINDS an entry and produces a confident, wrong row — which is worse than a
//! missing one, because a total that is quietly wrong is indistinguishable from
//! a total that is right.
//!
//! ## One pass, in capture order
//!
//! Declarations are absorbed as they travel and references resolve against the
//! table AS OF that moment. A second pass would resolve more references and
//! would be wrong to: ids are UNDECLARED and reused, so a late binding applied
//! backwards attributes traffic to a keyexpr that was not what the id meant
//! when the bytes went past. A reference that precedes its declaration is what
//! a capture started mid-session looks like, and it belongs in
//! [`ThroughputTable::unresolved`] rather than in a row.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use wz_session_core::network_message::{BatchParse, NetworkMessage};
use wz_session_core::passive::{Carried, Direction, PassiveFrame};

use wz_codecs::wireexpr::WireexprOwnedVariant;

/// What one keyexpr carried, on one side of one flow.
///
/// Counts and bytes are kept apart because they answer different questions: a
/// keyexpr with 10 000 empty Puts and one with a single 4 MiB Put are both
/// "traffic", and a plane that folded them into one number could not tell a
/// chatty control topic from a bulk one.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct KeyexprCounts {
    /// `Push` / `Request` carrying a `MsgPut`.
    pub puts: usize,
    /// `Push` / `Request` carrying a `MsgDel`.
    pub dels: usize,
    /// `Request` carrying a `Query`.
    pub queries: usize,
    /// `Response` carrying a `Reply`.
    pub replies: usize,
    /// `Response` carrying an `Err`.
    pub errs: usize,
    /// Application bytes carried under this keyexpr — the payload of every
    /// `MsgPut` and `Err` above.
    ///
    /// The payload BYTES PRESENT, not the VLE length the sender declared: a
    /// truncated or lying record must not be able to inflate a total, and the
    /// two disagreeing is itself a decode error the codec already reports.
    ///
    /// A `Query`'s parameters are deliberately NOT counted here. They are a
    /// selector, not data, and folding them in would make a busy query topic
    /// read as though it were publishing.
    pub payload_bytes: u64,
}

impl KeyexprCounts {
    /// Every record attributed to this keyexpr, whatever kind.
    pub fn messages(&self) -> usize {
        self.puts + self.dels + self.queries + self.replies + self.errs
    }

    /// `true` when nothing at all landed here.
    pub fn is_empty(&self) -> bool {
        self.messages() == 0 && self.payload_bytes == 0
    }

    fn add(&mut self, other: &KeyexprCounts) {
        self.puts += other.puts;
        self.dels += other.dels;
        self.queries += other.queries;
        self.replies += other.replies;
        self.errs += other.errs;
        self.payload_bytes += other.payload_bytes;
    }
}

/// One resolved keyexpr's row in the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyexprRow {
    /// The literal keyexpr, after alias resolution.
    pub keyexpr: String,
    /// Indexed by [`Direction`] — `[A→B, B→A]`.
    ///
    /// Kept split rather than summed because the direction is the difference
    /// between a publisher and a subscriber, and a per-keyexpr view that hid it
    /// could not tell which end of the capture is producing.
    pub per_direction: [KeyexprCounts; 2],
    /// Capture anchor of the first record attributed here, and of the last.
    /// A packet index on a datagram flow and a stream offset on a stream one —
    /// whatever [`PassiveFrame::stream_offset`] carries for that link.
    pub first_anchor: usize,
    /// See [`Self::first_anchor`].
    pub last_anchor: usize,
}

impl KeyexprRow {
    /// Both directions summed.
    pub fn totals(&self) -> KeyexprCounts {
        let mut t = self.per_direction[0];
        t.add(&self.per_direction[1]);
        t
    }
}

/// A wire reference this table refused to resolve, and how often it appeared.
///
/// Carried rather than counted in one lump, for the reason
/// [`crate::SkippedPacket`] is carried: "41 unresolved references" is not
/// actionable, and an id plus the space it named says whether the capture
/// started mid-session (one id, many references) or whether a declaration was
/// lost (many ids).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnresolvedAlias {
    /// WHOSE space the reference named, after the `M` bit was applied to the
    /// direction it travelled — not the direction it travelled in.
    pub space: Direction,
    /// The id that space had no binding for.
    pub id: u64,
    /// How many records referenced it.
    pub references: usize,
}

fn dir_index(d: Direction) -> usize {
    match d {
        Direction::A => 0,
        Direction::B => 1,
    }
}

/// The two keyexpr id spaces of ONE flow.
///
/// Public because a consumer walking frames itself — a live tap, a replay —
/// needs the same resolution without adopting [`ThroughputTable`]'s counters.
#[derive(Debug, Default, Clone)]
pub struct KeyexprSpaces {
    /// Indexed by [`Direction`]: the table of ids DECLARED by that side.
    tables: [BTreeMap<u64, String>; 2],
}

impl KeyexprSpaces {
    /// Two empty spaces.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve one wire keyexpr seen travelling in `direction`.
    ///
    /// `Ok(literal)` when it resolved, `Err(alias)` naming the space and id
    /// when it did not. Never a lookup in the space the `M` bit did not name.
    pub fn resolve(
        &self,
        direction: Direction,
        body: &WireexprOwnedVariant,
    ) -> Result<String, (Direction, u64)> {
        // The variant tag IS the mapping bit (`wireexpr_resolve`'s rule): our
        // codec's `WireexprLocal` is `M=1` — the SENDER's space, which for a
        // record travelling in `direction` is `direction`'s own — and
        // `WireexprNonlocal` is `M=0`, the RECEIVER's, which is the peer's.
        let (id, suffix, space) = match body {
            WireexprOwnedVariant::WireexprLocal(a) => (a.id, a.suffix.as_deref(), direction),
            WireexprOwnedVariant::WireexprNonlocal(a) => {
                (a.id, a.suffix.as_deref(), direction.peer())
            }
        };
        if id == 0 {
            // No mapping named at all: the suffix IS the keyexpr, on either
            // arm, consulting no table. This is the overwhelming majority of
            // wire keyexprs and must not be routed through a space.
            return Ok(suffix.unwrap_or("").to_string());
        }
        match self.tables[dir_index(space)].get(&id) {
            Some(base) => {
                let mut out = base.clone();
                if let Some(s) = suffix {
                    out.push_str(s);
                }
                Ok(out)
            }
            None => Err((space, id)),
        }
    }

    /// Absorb one `Declare` travelling in `direction` into the DECLARER's
    /// space.
    ///
    /// A `DeclKexpr`'s own keyexpr may itself be aliased, so it is resolved
    /// against the tables as they stand before being bound — the composition
    /// rule `wireexpr_resolve::absorb_keyexpr_into` uses, with the two-space
    /// resolver in place of the one-space one. An alias whose base does not
    /// resolve binds NOTHING: a half-known prefix would make every later
    /// reference to the new id confidently wrong.
    pub fn absorb(&mut self, direction: Direction, declare: &wz_codecs::declare::DeclareOwned) {
        use wz_codecs::declare::DeclareOwnedVariant;
        match &declare.body {
            DeclareOwnedVariant::CodecZenohDeclKexpr(d) => {
                // The id is minted in the SENDER's space regardless of the
                // mapping bit on the keyexpr it names.
                if let Ok(literal) = self.resolve(direction, &d.keyexpr.body) {
                    self.tables[dir_index(direction)].insert(d.id, literal);
                }
            }
            DeclareOwnedVariant::CodecZenohUndeclKexpr(u) => {
                self.tables[dir_index(direction)].remove(&u.id);
            }
            _ => {}
        }
    }

    /// How many ids each side currently has bound — `[A, B]`.
    pub fn bound(&self) -> [usize; 2] {
        [self.tables[0].len(), self.tables[1].len()]
    }
}

/// Per-keyexpr throughput over one or more flows.
///
/// Rows are global (a keyexpr string means the same thing wherever it appears)
/// while id spaces are per-flow, which is why [`Self::observe_flow`] is the
/// unit rather than a per-frame call: two sessions' id `3` are unrelated, and
/// one table across both would cross-resolve them.
#[derive(Debug, Default, Clone)]
pub struct ThroughputTable {
    rows: BTreeMap<String, KeyexprRow>,
    unresolved: BTreeMap<(usize, u64), UnresolvedAlias>,
    declarations: usize,
    undeclarations: usize,
    records: usize,
}

impl ThroughputTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one flow's frames in, in capture order, resolving against id spaces
    /// private to this flow.
    pub fn observe_flow(&mut self, frames: &[PassiveFrame]) {
        let mut spaces = KeyexprSpaces::new();
        for frame in frames {
            let anchor = frame.stream_offset;
            match &frame.carried {
                Carried::Batch(batch) => self.observe_batch(&mut spaces, frame, anchor, batch),
                #[cfg(feature = "reassembly")]
                Carried::Reassembled(batch) => {
                    self.observe_batch(&mut spaces, frame, anchor, batch)
                }
                _ => {}
            }
        }
    }

    fn observe_batch(
        &mut self,
        spaces: &mut KeyexprSpaces,
        frame: &PassiveFrame,
        anchor: usize,
        batch: &BatchParse,
    ) {
        for message in &batch.messages {
            self.observe_message(spaces, frame.direction, anchor, message);
        }
    }

    fn observe_message(
        &mut self,
        spaces: &mut KeyexprSpaces,
        direction: Direction,
        anchor: usize,
        message: &NetworkMessage,
    ) {
        // A DECLARE is absorbed and not counted: it declares a keyexpr, it does
        // not carry traffic under one, and counting it would put a row on every
        // topic a session merely named.
        if let NetworkMessage::Declare(d) = message {
            use wz_codecs::declare::DeclareOwnedVariant;
            match &d.body {
                DeclareOwnedVariant::CodecZenohDeclKexpr(_) => self.declarations += 1,
                DeclareOwnedVariant::CodecZenohUndeclKexpr(_) => self.undeclarations += 1,
                _ => {}
            }
            spaces.absorb(direction, d);
            return;
        }

        let Some((keyexpr_body, counts)) = classify(message) else {
            return;
        };
        self.records += 1;
        match spaces.resolve(direction, keyexpr_body) {
            Ok(keyexpr) => {
                let row = self.rows.entry(keyexpr.clone()).or_insert(KeyexprRow {
                    keyexpr,
                    per_direction: [KeyexprCounts::default(); 2],
                    first_anchor: anchor,
                    last_anchor: anchor,
                });
                row.per_direction[dir_index(direction)].add(&counts);
                row.last_anchor = anchor;
            }
            Err((space, id)) => {
                self.unresolved
                    .entry((dir_index(space), id))
                    .or_insert(UnresolvedAlias {
                        space,
                        id,
                        references: 0,
                    })
                    .references += 1;
            }
        }
    }

    /// Every resolved keyexpr, heaviest first.
    ///
    /// Ordered by payload bytes, then by record count, then by the keyexpr
    /// itself — the last tiebreak is what makes the order TOTAL, so two runs
    /// over the same capture cannot disagree.
    pub fn rows(&self) -> Vec<&KeyexprRow> {
        let mut rows: Vec<&KeyexprRow> = self.rows.values().collect();
        rows.sort_by(|a, b| {
            let (ta, tb) = (a.totals(), b.totals());
            tb.payload_bytes
                .cmp(&ta.payload_bytes)
                .then_with(|| tb.messages().cmp(&ta.messages()))
                .then_with(|| a.keyexpr.cmp(&b.keyexpr))
        });
        rows
    }

    /// One resolved keyexpr's row, if it has one.
    pub fn row(&self, keyexpr: &str) -> Option<&KeyexprRow> {
        self.rows.get(keyexpr)
    }

    /// References that named an id no space had bound, most-referenced first.
    ///
    /// A NON-EMPTY answer here is not a failure of this table — it is the part
    /// of the capture whose keyexpr genuinely is not in it, reported instead of
    /// guessed. A reader summing [`Self::rows`] and treating the total as the
    /// whole capture must consult this first.
    pub fn unresolved(&self) -> Vec<&UnresolvedAlias> {
        let mut out: Vec<&UnresolvedAlias> = self.unresolved.values().collect();
        out.sort_by(|a, b| {
            b.references
                .cmp(&a.references)
                .then_with(|| a.id.cmp(&b.id))
        });
        out
    }

    /// Records that carried a keyexpr but could not be attributed to one.
    pub fn unresolved_records(&self) -> usize {
        self.unresolved.values().map(|u| u.references).sum()
    }

    /// Keyexpr-carrying records seen, attributed or not — the denominator
    /// [`Self::unresolved_records`] is a fraction of.
    pub fn records(&self) -> usize {
        self.records
    }

    /// `DeclKexpr` / `UndeclKexpr` absorbed — `(declared, undeclared)`.
    pub fn declarations(&self) -> (usize, usize) {
        (self.declarations, self.undeclarations)
    }

    /// Application bytes across every resolved keyexpr.
    pub fn total_payload_bytes(&self) -> u64 {
        self.rows.values().map(|r| r.totals().payload_bytes).sum()
    }
}

/// Which counter a network record moves, and the keyexpr it moves it under.
///
/// `None` for every record that carries no keyexpr — `ResponseFinal` (a pure
/// correlation marker), `Oam`, `Interest`, `Unknown`. They are not silently
/// dropped: they never entered [`ThroughputTable::records`] either, so the
/// unresolved fraction stays a fraction of records that HAVE a keyexpr.
fn classify(message: &NetworkMessage) -> Option<(&WireexprOwnedVariant, KeyexprCounts)> {
    use wz_codecs::push::PushOwnedVariant;
    use wz_codecs::request::RequestOwnedVariant;
    use wz_codecs::response::ResponseOwnedVariant;

    let mut counts = KeyexprCounts::default();
    match message {
        NetworkMessage::Push(p) => {
            match &p.body {
                PushOwnedVariant::CodecZenohMsgPut(put)
                | PushOwnedVariant::Default { body: put, .. } => {
                    counts.puts = 1;
                    counts.payload_bytes = put.payload.as_slice().len() as u64;
                }
                PushOwnedVariant::CodecZenohMsgDel(_) => counts.dels = 1,
            }
            Some((&p.keyexpr.body, counts))
        }
        NetworkMessage::Request(r) => {
            match &r.body {
                RequestOwnedVariant::CodecZenohMsgPut(put) => {
                    counts.puts = 1;
                    counts.payload_bytes = put.payload.as_slice().len() as u64;
                }
                RequestOwnedVariant::CodecZenohMsgDel(_) => counts.dels = 1,
                RequestOwnedVariant::CodecZenohQuery(_) | RequestOwnedVariant::Default { .. } => {
                    counts.queries = 1
                }
            }
            Some((&r.keyexpr.body, counts))
        }
        NetworkMessage::Response(r) => {
            use wz_codecs::reply::ReplyOwnedVariant;
            match &r.body {
                ResponseOwnedVariant::CodecZenohReply(reply)
                | ResponseOwnedVariant::Default { body: reply, .. } => {
                    counts.replies = 1;
                    if let ReplyOwnedVariant::CodecZenohMsgPut(put)
                    | ReplyOwnedVariant::Default { body: put, .. } = &reply.body
                    {
                        counts.payload_bytes = put.payload.as_slice().len() as u64;
                    }
                }
                ResponseOwnedVariant::CodecZenohErr(err) => {
                    counts.errs = 1;
                    counts.payload_bytes = err.payload.as_slice().len() as u64;
                }
            }
            Some((&r.keyexpr.body, counts))
        }
        _ => None,
    }
}

/// Aggregate an entire [`crate::Dissection`] — every stream flow and every
/// datagram flow, each resolved against its own id spaces.
pub fn aggregate(dissection: &crate::Dissection) -> ThroughputTable {
    let mut table = ThroughputTable::new();
    for flow in dissection.flows() {
        table.observe_flow(&flow.frames);
    }
    for flow in dissection.datagram_flows() {
        table.observe_flow(&flow.frames);
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datagram_tests::udp_packet;
    use crate::link::LINKTYPE_ETHERNET;
    use crate::Dissection;

    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_local::WireexprLocal;
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;

    /// The two endpoints. `.1` sorts below `.2`, so `.1 -> .2` is
    /// [`Direction::A`] — asserted rather than assumed by
    /// [`the_directions_are_the_ones_this_module_thinks_they_are`].
    const LOW: [u8; 4] = [10, 0, 0, 1];
    const HIGH: [u8; 4] = [10, 0, 0, 2];

    /// `M=1` — the id lives in the SENDER's space.
    fn sender_space(id: u64, suffix: Option<&'static str>) -> Wireexpr<'static> {
        Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id,
                suffix_len: suffix.map(|s| s.len() as u64),
                suffix,
            }),
        }
    }

    /// `M=0` — the id lives in the RECEIVER's space. zenoh emits this shape as
    /// soon as the far side has declared anything (`resource.rs:625`).
    fn receiver_space(id: u64, suffix: Option<&'static str>) -> Wireexpr<'static> {
        Wireexpr {
            body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                id,
                suffix_len: suffix.map(|s| s.len() as u64),
                suffix,
            }),
        }
    }

    /// A `Push` carrying `payload` under `keyexpr`, built by the Push codec.
    ///
    /// The header is `Push::default().header` plus the `N` bit rather than a
    /// literal, so the MID the generated `Default` bakes cannot be lost here.
    fn push(keyexpr: Wireexpr<'static>, payload: &[u8]) -> Vec<u8> {
        let has_suffix = match &keyexpr.body {
            WireexprVariant::WireexprLocal(a) => a.suffix.is_some(),
            WireexprVariant::WireexprNonlocal(a) => a.suffix.is_some(),
        };
        let n_flag = if has_suffix { 0x20 } else { 0 };
        wz_codecs::push::Push {
            header: wz_codecs::push::Push::default().header | n_flag,
            keyexpr,
            body: wz_codecs::push::PushVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
                payload_len: payload.len() as u64,
                payload,
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// `DeclKexpr`: bind `id` to the literal `suffix` in the SENDER's space.
    fn declare_kexpr(id: u64, suffix: &'static str) -> Vec<u8> {
        wz_codecs::declare::Declare {
            body: wz_codecs::declare::DeclareVariant::CodecZenohDeclKexpr(
                wz_codecs::decl_kexpr::DeclKexpr {
                    header: wz_session_core::wire_const::D_MID_KEXPR
                        | wz_session_core::wire_const::FLAG_D_N,
                    id,
                    keyexpr: sender_space(0, Some(suffix)),
                },
            ),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// `UndeclKexpr`: drop `id` from the SENDER's space.
    fn undeclare_kexpr(id: u64) -> Vec<u8> {
        wz_codecs::declare::Declare {
            body: wz_codecs::declare::DeclareVariant::CodecZenohUndeclKexpr(
                wz_codecs::undecl_kexpr::UndeclKexpr {
                    header: wz_session_core::wire_const::D_MID_UNDECL_KEXPR,
                    id,
                },
            ),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// Push a list of `(from_low, record)` through a real dissection, one
    /// datagram per record, and aggregate the result.
    ///
    /// Deliberately the whole pipeline — packet bytes in, table out. A test
    /// that handed `observe_flow` a `Vec<PassiveFrame>` it built itself would
    /// pass on a build where `Dissection` never produces one.
    fn aggregate_datagrams(records: &[(bool, Vec<u8>)]) -> ThroughputTable {
        let mut d = Dissection::new();
        for (i, (from_low, record)) in records.iter().enumerate() {
            let wire = crate::datagram_tests::frame_carrying(record);
            let pkt = if *from_low {
                udp_packet(LOW, 43210, HIGH, 7447, &wire)
            } else {
                udp_packet(HIGH, 7447, LOW, 43210, &wire)
            };
            d.push_packet(LINKTYPE_ETHERNET, i, &pkt);
        }
        aggregate(&d)
    }

    /// The anchor every direction-sensitive assertion below rests on, asserted
    /// instead of assumed.
    #[test]
    fn the_directions_are_the_ones_this_module_thinks_they_are() {
        let mut d = Dissection::new();
        let wire =
            crate::datagram_tests::frame_carrying(&push(sender_space(0, Some("anchor")), b"x"));
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &udp_packet(LOW, 43210, HIGH, 7447, &wire),
        );
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &udp_packet(HIGH, 7447, LOW, 43210, &wire),
        );
        let frames = &d.datagram_flows()[0].frames;
        assert_eq!(frames[0].direction, Direction::A, "low -> high is A");
        assert_eq!(frames[1].direction, Direction::B, "high -> low is B");
    }

    /// §1.1f, the plane itself: a capture answers WHICH keyexpr carried the
    /// bytes and HOW MANY, ordered heaviest first.
    #[test]
    fn a_capture_says_which_keyexpr_carried_the_bytes() {
        let table = aggregate_datagrams(&[
            (true, push(sender_space(0, Some("home/temp")), &[0u8; 10])),
            (true, push(sender_space(0, Some("home/temp")), &[0u8; 20])),
            (true, push(sender_space(0, Some("home/light")), &[0u8; 4])),
            (false, push(sender_space(0, Some("home/temp")), &[0u8; 5])),
        ]);

        let rows = table.rows();
        assert_eq!(rows.len(), 2, "two distinct keyexprs");
        assert_eq!(rows[0].keyexpr, "home/temp", "heaviest first");
        assert_eq!(rows[1].keyexpr, "home/light");

        let temp = rows[0].totals();
        assert_eq!(temp.puts, 3);
        assert_eq!(temp.payload_bytes, 35, "10 + 20 + 5");
        assert_eq!(temp.messages(), 3);

        // The split is the point of keeping the two directions apart: one side
        // published 30 bytes and the other 5, and a summed-only view could not
        // say which end is the publisher.
        assert_eq!(rows[0].per_direction[0].payload_bytes, 30, "A->B");
        assert_eq!(rows[0].per_direction[1].payload_bytes, 5, "B->A");

        assert_eq!(table.total_payload_bytes(), 39);
        assert_eq!(table.records(), 4);
        assert_eq!(table.unresolved_records(), 0);
    }

    /// THE DISCRIMINATOR for this module's reason to exist.
    ///
    /// Both sides bind their own id `1`, to DIFFERENT keyexprs — so a resolver
    /// that reads the wrong space does not fail, it answers confidently and
    /// wrongly, which is the failure mode R311y604 named.
    ///
    /// The `M=0` reference is the one a participant cannot resolve at all
    /// (`wireexpr_resolve` returns `None` for it by design, holding only the
    /// peer's table). Here it must resolve, and to the space the bit names —
    /// the RECEIVER's — which for a record travelling B→A is A's.
    ///
    /// Three outcomes are therefore distinguishable, and only one passes:
    /// right space (`a/space/topic`), wrong space (`b/space/other`), no space
    /// (unresolved).
    #[test]
    fn the_mapping_bit_picks_the_space_and_the_observer_holds_both() {
        let table = aggregate_datagrams(&[
            // A binds id 1; B binds id 1 to something else entirely.
            (true, declare_kexpr(1, "a/space/topic")),
            (false, declare_kexpr(1, "b/space/other")),
            // A→B with M=1: the SENDER's space = A's.
            (true, push(sender_space(1, None), &[0u8; 7])),
            // B→A with M=0: the RECEIVER's space = A's, the SAME binding —
            // reached out of the far side's table, which is the thing a
            // participant-side resolver has no way to do.
            (false, push(receiver_space(1, None), &[0u8; 3])),
            // B→A with M=1: the SENDER's space = B's.
            (false, push(sender_space(1, None), &[0u8; 100])),
        ]);

        assert_eq!(
            table.unresolved_records(),
            0,
            "every reference named a space that was bound: {:?}",
            table.unresolved()
        );

        let a_topic = table
            .row("a/space/topic")
            .expect("the M=0 reference resolved out of the receiver's space");
        assert_eq!(a_topic.totals().puts, 2, "one M=1 from A, one M=0 from B");
        assert_eq!(a_topic.totals().payload_bytes, 10, "7 + 3");
        assert_eq!(a_topic.per_direction[0].puts, 1, "the A->B one");
        assert_eq!(a_topic.per_direction[1].puts, 1, "the B->A one");

        let b_other = table
            .row("b/space/other")
            .expect("B's own space still works");
        assert_eq!(b_other.totals().payload_bytes, 100);

        assert_eq!(table.declarations(), (2, 0));
    }

    /// A suffix composes onto the resolved base, on either arm.
    #[test]
    fn a_suffix_composes_onto_whichever_space_resolved() {
        let table = aggregate_datagrams(&[
            (true, declare_kexpr(4, "root")),
            (true, push(sender_space(4, Some("/leaf")), &[0u8; 1])),
            (false, push(receiver_space(4, Some("/leaf")), &[0u8; 1])),
        ]);
        let row = table.row("root/leaf").expect("both references landed here");
        assert_eq!(row.totals().puts, 2);
        assert_eq!(table.rows().len(), 1, "and nowhere else");
    }

    /// A reference to an id nobody bound is REPORTED, never attributed.
    ///
    /// The failure this forbids is not a missing row — it is a row that exists
    /// and is wrong. `records()` still counts it, so a reader can see that the
    /// rows do not cover the capture.
    #[test]
    fn an_unbound_alias_is_reported_rather_than_guessed() {
        let table = aggregate_datagrams(&[
            (true, declare_kexpr(1, "declared/one")),
            // id 9 was never declared by anyone.
            (true, push(sender_space(9, None), &[0u8; 50])),
            (true, push(sender_space(9, None), &[0u8; 50])),
        ]);

        assert_eq!(table.rows().len(), 0, "no row was invented");
        assert_eq!(table.total_payload_bytes(), 0);

        let unresolved = table.unresolved();
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].id, 9);
        assert_eq!(unresolved[0].space, Direction::A);
        assert_eq!(unresolved[0].references, 2);

        assert_eq!(table.records(), 2, "the records were seen");
        assert_eq!(table.unresolved_records(), 2, "and none of them attributed");
    }

    /// An UNDECLARE ends the binding, and a later reference to the freed id is
    /// unresolved rather than stale.
    ///
    /// The stale answer is the dangerous one: ids are reused, so a resolver
    /// that kept the old literal would keep attributing a live topic's traffic
    /// to a dead one, and every total would stay plausible.
    #[test]
    fn an_undeclared_id_stops_resolving_instead_of_going_stale() {
        let table = aggregate_datagrams(&[
            (true, declare_kexpr(2, "before/undeclare")),
            (true, push(sender_space(2, None), &[0u8; 8])),
            (true, undeclare_kexpr(2)),
            (true, push(sender_space(2, None), &[0u8; 8])),
        ]);

        let row = table.row("before/undeclare").expect("the first one landed");
        assert_eq!(row.totals().puts, 1, "and ONLY the first one");
        assert_eq!(row.totals().payload_bytes, 8);
        assert_eq!(table.unresolved_records(), 1, "the second is reported");
        assert_eq!(table.declarations(), (1, 1));
    }

    /// A binding that arrives AFTER the reference does not reach back for it.
    ///
    /// This is the single-pass rule, and it is a decision rather than a
    /// limitation: applying a late binding backwards attributes bytes to a
    /// keyexpr that is not what the id meant when they went past.
    #[test]
    fn a_late_declaration_does_not_resolve_earlier_traffic() {
        let table = aggregate_datagrams(&[
            (true, push(sender_space(3, None), &[0u8; 11])),
            (true, declare_kexpr(3, "late/binding")),
            (true, push(sender_space(3, None), &[0u8; 22])),
        ]);

        let row = table.row("late/binding").expect("the later one resolved");
        assert_eq!(row.totals().payload_bytes, 22);
        assert_eq!(table.unresolved_records(), 1, "the earlier one is reported");
    }

    /// A DECLARE is absorbed, not counted. A session that merely NAMES a
    /// hundred keyexprs must not produce a hundred rows of traffic.
    #[test]
    fn declaring_a_keyexpr_is_not_traffic_on_it() {
        let table = aggregate_datagrams(&[
            (true, declare_kexpr(1, "named/never/used")),
            (true, declare_kexpr(2, "also/never/used")),
        ]);
        assert_eq!(table.rows().len(), 0);
        assert_eq!(table.records(), 0, "a declaration carries no traffic");
        assert_eq!(table.declarations(), (2, 0));
    }

    /// A `DeclKexpr` whose own keyexpr is itself an alias composes against the
    /// table as it stands — zenoh's chained-declaration shape.
    #[test]
    fn a_declaration_may_itself_be_aliased() {
        let chained = wz_codecs::declare::Declare {
            body: wz_codecs::declare::DeclareVariant::CodecZenohDeclKexpr(
                wz_codecs::decl_kexpr::DeclKexpr {
                    header: wz_session_core::wire_const::D_MID_KEXPR
                        | wz_session_core::wire_const::FLAG_D_N,
                    id: 2,
                    // id 1's literal, plus a suffix.
                    keyexpr: sender_space(1, Some("/child")),
                },
            ),
            ..Default::default()
        };
        let table = aggregate_datagrams(&[
            (true, declare_kexpr(1, "parent")),
            (true, chained.encode_to_vec()),
            (true, push(sender_space(2, None), &[0u8; 6])),
        ]);
        let row = table.row("parent/child").expect("the chain composed");
        assert_eq!(row.totals().payload_bytes, 6);
        assert_eq!(table.unresolved_records(), 0);
    }

    /// The rows a stream flow produces are the same ones a datagram flow does,
    /// which is what makes `aggregate` a plane rather than a datagram feature.
    #[test]
    fn the_plane_reaches_a_stream_flow_too() {
        let mut d = Dissection::new();
        let mut stream = Vec::new();
        for record in [
            declare_kexpr(1, "stream/topic"),
            push(sender_space(1, None), &[0u8; 12]),
        ] {
            let wire = crate::datagram_tests::frame_carrying(&record);
            stream.extend_from_slice(&(wire.len() as u16).to_le_bytes());
            stream.extend_from_slice(&wire);
        }
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &crate::datagram_tests::tcp_packet(1000, &stream),
        );

        assert_eq!(d.flows().len(), 1, "a stream flow, not a datagram one");
        let table = aggregate(&d);
        let row = table.row("stream/topic").expect("resolved over a stream");
        assert_eq!(row.totals().payload_bytes, 12);
    }
}
