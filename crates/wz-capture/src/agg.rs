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
//! ([`crate::agg::ThroughputTable::unresolved`]), never attributed to a keyexpr. Both sides
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
//! [`crate::agg::ThroughputTable::unresolved`] rather than in a row.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use wz_session_core::network_message::{BatchParse, NetworkMessage};
use wz_session_core::passive::{Carried, Direction, PassiveFrame};

use wz_codecs::wireexpr::WireexprOwnedVariant;

use crate::filter::{Filter, RecordKind, RecordView, Selection, Truth};

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
    ///
    /// R311y637 (§1.1w) — this total is SHORT by an unknown amount whenever
    /// [`Self::unsized_payloads`] is non-zero. Read the two together.
    pub payload_bytes: u64,
    /// R311y637 (§1.1w) — records attributed here that CARRY a payload this
    /// build cannot size.
    ///
    /// Two cases, and every one of them reaches this counter through
    /// `Self::record_payload` rather than by assigning the byte total
    /// directly, so a third cannot arrive by writing a number the way the two
    /// below each once did:
    ///
    /// 1. A `Query` whose value rides the
    ///    [`QUERY_BODY`](wz_session_core::ext_header::body_ext_id::QUERY_BODY)
    ///    ext. The ext body is `encoding` followed by `payload`
    ///    (`zenoh-protocol-1.5.0/src/zenoh/mod.rs:205-210`), and this decoder
    ///    models it as one opaque ZBUF, so the application half of it cannot be
    ///    separated out. The bytes are REAL and their count is unknown.
    /// 2. R311y639 (§4.30) — a `MsgPut` or `Err` whose chain carries the
    ///    [`SHM`](wz_session_core::ext_header::body_ext_id::SHM) marker. That
    ///    marker means the payload slot holds a DESCRIPTOR and the data never
    ///    traversed the network at all, so no length on this wire is the
    ///    application's. Worse than a descriptor's own size being reported: the
    ///    marker also switches the field's FRAMING from `len || bytes` to a
    ///    slice sequence (`zenoh-codec-1.5.0/src/core/zbuf.rs:131-158`,
    ///    `Zenoh080Sliced`), so the figure this decoder had been reporting was
    ///    the SLICE COUNT — typically `1` — presented as a byte total.
    ///
    /// A record with NO such ext is not counted here: it carries what it
    /// carries, its number is a measurement, and conflating the two would make
    /// the honest zero unreadable — which is the whole defect this field exists
    /// to end.
    ///
    /// R311y646 (§4.34) — the SUM of the two fields below, kept because
    /// `payload_is_complete` and every existing reader ask exactly this
    /// question. Which of the two it was is the new answer, not a replacement.
    pub unsized_payloads: usize,
    /// R311y646 (§4.34) — records whose payload bytes are NOT IN THIS CAPTURE.
    ///
    /// The SHM case: the payload slot holds a descriptor and the data went
    /// through shared memory, so no number on this wire is the application's and
    /// none ever will be. A reader wanting those bytes needs a different capture
    /// point, not a better decoder.
    pub payloads_elsewhere: usize,
    /// R311y646 (§4.34) — records whose payload bytes ARE in this capture and
    /// could not be separated from what precedes them.
    ///
    /// The unresolvable-`Query`-body case: the ext holds `encoding` then the
    /// payload, and a body whose length prefix disagrees with the bytes behind
    /// it is not measured from its own claim. The distinction from
    /// [`Self::payloads_elsewhere`] is what a reader can DO about it — these
    /// bytes are in the file, and [`Self::unresolved_at_most_bytes`] bounds them.
    pub payloads_unresolved: usize,
    /// R311y646 (§4.28) — an UPPER BOUND on the application bytes the
    /// [`Self::payloads_unresolved`] records hold, read off the wire.
    ///
    /// NOT a measurement and never folded into [`Self::payload_bytes`]: it is
    /// what the enclosing ext could hold at most, so the true figure is this or
    /// less. Zero when there are no such records — and also the honest answer
    /// for a record whose enclosing bytes bound it at zero.
    ///
    /// The two totals answer different halves of one question: `payload_bytes`
    /// is a FLOOR on the application bytes this capture carried and
    /// `payload_bytes + unresolved_at_most_bytes` is a CEILING. Before this the
    /// reader had the floor and a count of records standing between it and any
    /// ceiling at all.
    pub unresolved_at_most_bytes: u64,
}

/// R311y646 (§4.28 / §4.34) — what one record's application payload amounts to,
/// as [`KeyexprCounts::record_payload`] is told it.
///
/// Three arms and not an `Option`, because "unknown" was two facts wearing one
/// name. R311y639 introduced the `Option` to stop a carrier reporting a
/// confident number for bytes it could not size; what it could not express is
/// that one of those carriers has NOTHING to measure here at any resolution
/// (the bytes went through shared memory) while the other has bytes present in
/// this very capture and merely no separation — and the wire says how many they
/// are at most.
#[cfg(feature = "network-codecs")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PayloadSize {
    /// `n` application bytes, measured.
    Measured(u64),
    /// The bytes did not traverse this network at all.
    Elsewhere,
    /// The bytes are here and unseparated; they number `at_most` or fewer.
    Unresolved { at_most: u64 },
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

    /// R311y637 (§1.1w) — `true` when [`Self::payload_bytes`] is the whole
    /// answer for this row rather than a floor.
    pub fn payload_is_complete(&self) -> bool {
        self.unsized_payloads == 0
    }

    /// R311y639 (§4.30) — the ONE door a payload measurement enters by.
    ///
    /// `Some(n)`: this record's slot held `n` application bytes, and that is a
    /// MEASUREMENT. `None`: the slot held something real whose size is not on
    /// this wire, so there is no number to add and the record is counted as the
    /// admission it is.
    ///
    /// It exists because the alternative had already failed twice in the same
    /// shape. Both R311y637's query value and this round's SHM descriptor were
    /// carriers whose payload is not the field it looks like, and both reached
    /// the totals as `counts.payload_bytes = <field>.len()` — a plain
    /// assignment that cannot express "unknown", so the arm that wrote it had
    /// no way to say so even had its author noticed. A third carrier arriving
    /// through this method must supply an `Option`, which is the question
    /// asked at the only moment the answer is available.
    ///
    /// Gated exactly as [`classify`]'s carrier arms are: with `network-codecs`
    /// off there is no arm left that can name a payload, so the door leads
    /// nowhere and an ungated one would be dead code the no-default lane fails
    /// on rather than a wider reach.
    /// R311y646 (§4.34) — the parameter is a [`PayloadSize`] and no longer an
    /// `Option`, so a carrier that cannot measure its payload must still say
    /// WHICH of the two unmeasurable states it is in and, where the bytes are
    /// present, what bounds them.
    #[cfg(feature = "network-codecs")]
    fn record_payload(&mut self, size: PayloadSize) {
        match size {
            PayloadSize::Measured(n) => self.payload_bytes += n,
            PayloadSize::Elsewhere => {
                self.unsized_payloads += 1;
                self.payloads_elsewhere += 1;
            }
            PayloadSize::Unresolved { at_most } => {
                self.unsized_payloads += 1;
                self.payloads_unresolved += 1;
                self.unresolved_at_most_bytes += at_most;
            }
        }
    }

    fn add(&mut self, other: &KeyexprCounts) {
        self.puts += other.puts;
        self.dels += other.dels;
        self.queries += other.queries;
        self.replies += other.replies;
        self.errs += other.errs;
        self.payload_bytes += other.payload_bytes;
        self.unsized_payloads += other.unsized_payloads;
        self.payloads_elsewhere += other.payloads_elsewhere;
        self.payloads_unresolved += other.payloads_unresolved;
        self.unresolved_at_most_bytes += other.unresolved_at_most_bytes;
    }
}

/// R311y642 (§1.1t) — one node of the keyexpr hierarchy, with the totals of
/// everything at or beneath it.
///
/// Built by [`ThroughputTable::subtrees`]. The root names the empty prefix and
/// carries the whole capture, so a consumer walking down from it never has to
/// special-case "no common prefix".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyexprSubtree {
    /// The full prefix this node names — `robot/1` for the node holding
    /// `robot/1/pose` and `robot/1/twist`. Empty at the root.
    pub prefix: String,
    /// Every record at or beneath this node.
    pub totals: KeyexprCounts,
    /// How many LITERAL keyexprs fold into it.
    ///
    /// The field that makes a node's weight readable: `rows == 1` is a leaf
    /// wearing a prefix's name and says nothing a row did not, while a heavy
    /// node with many rows is exactly the finding the flat list cannot show.
    pub rows: usize,
    /// Ordered as [`ThroughputTable::rows`] is: heaviest first, then by record
    /// count, then by prefix.
    pub children: Vec<KeyexprSubtree>,
}

impl KeyexprSubtree {
    fn new(prefix: String) -> Self {
        Self {
            prefix,
            totals: KeyexprCounts::default(),
            rows: 0,
            children: Vec::new(),
        }
    }

    /// Add one literal keyexpr's totals along its whole path from the root.
    ///
    /// Split on `/` and on nothing else. A zenoh keyexpr's separator is the one
    /// this crate resolves suffixes with, and inventing a second notion of
    /// "part of a key" here is how a rollup starts disagreeing with the rows it
    /// was folded from.
    fn insert(&mut self, keyexpr: &str, totals: &KeyexprCounts) {
        self.totals.add(totals);
        self.rows += 1;
        let Some((head, tail)) = split_segment(keyexpr) else {
            return;
        };
        let prefix = if self.prefix.is_empty() {
            head.to_string()
        } else {
            alloc::format!("{}/{}", self.prefix, head)
        };
        let child = match self.children.iter().position(|c| c.prefix == prefix) {
            Some(i) => &mut self.children[i],
            None => {
                self.children.push(KeyexprSubtree::new(prefix));
                self.children.last_mut().expect("just pushed")
            }
        };
        match tail {
            Some(rest) => child.insert(rest, totals),
            None => {
                child.totals.add(totals);
                child.rows += 1;
            }
        }
    }

    fn sort(&mut self) {
        self.children.sort_by(|a, b| {
            b.totals
                .payload_bytes
                .cmp(&a.totals.payload_bytes)
                .then_with(|| b.totals.messages().cmp(&a.totals.messages()))
                .then_with(|| a.prefix.cmp(&b.prefix))
        });
        for c in &mut self.children {
            c.sort();
        }
    }

    /// The heaviest node that stands for MORE THAN ONE literal keyexpr.
    ///
    /// The one line a reader of the flat ranking is missing: a node with a
    /// single row is a row they can already see, and the deepest such node is
    /// the most specific true statement about where the traffic is. `None` when
    /// every key in the capture is its own subtree, which is the honest answer
    /// for a flat key space rather than a root node dressed up as a finding.
    pub fn heaviest_shared(&self) -> Option<&KeyexprSubtree> {
        let mut best: Option<&KeyexprSubtree> = None;
        let mut stack = alloc::vec![self];
        while let Some(node) = stack.pop() {
            if !node.prefix.is_empty() && node.rows > 1 {
                let better = match best {
                    None => true,
                    Some(b) => {
                        (node.totals.payload_bytes, node.prefix.len())
                            > (b.totals.payload_bytes, b.prefix.len())
                    }
                };
                if better {
                    best = Some(node);
                }
            }
            for c in &node.children {
                stack.push(c);
            }
        }
        best
    }
}

/// `("robot", Some("1/pose"))` for `robot/1/pose`, `("pose", None)` for the
/// last segment, `None` for an empty key.
fn split_segment(keyexpr: &str) -> Option<(&str, Option<&str>)> {
    if keyexpr.is_empty() {
        return None;
    }
    Some(match keyexpr.split_once('/') {
        Some((head, rest)) => (head, Some(rest)),
        None => (keyexpr, None),
    })
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

/// R311y646 (§4.28 / §4.34) — the two reasons a payload went unmeasured, and
/// the bound on the half that is still in the capture.
///
/// One struct rather than three accessors, because the three numbers are only
/// meaningful together: `at_most_bytes` bounds `unresolved` records and says
/// nothing whatever about `elsewhere` ones, and a reader handed the bound alone
/// would have no way to know which population it covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnmeasuredPayloads {
    /// Records whose payload bytes never traversed this network (SHM).
    pub elsewhere: usize,
    /// Records whose payload bytes are in the capture and unseparated.
    pub unresolved: usize,
    /// Upper bound on the application bytes those `unresolved` records hold.
    pub at_most_bytes: u64,
}

impl UnmeasuredPayloads {
    /// `true` when every payload was measured, so the totals beside this are
    /// the whole answer rather than a floor.
    pub fn is_empty(&self) -> bool {
        self.elsewhere == 0 && self.unresolved == 0
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

/// R311y645 (§1.1n / §4.37 / §4.38) — a record's byte offset within the FRAMING
/// UNIT that carried it, or `None` when the capture holds no such coordinate.
///
/// THE ONE PLACE THIS IS COMPOSED, for the reason R311y639 made
/// `record_payload` one statement: the three planes each build their own
/// [`RecordView`] and each used to write `span.map(..).unwrap_or(0)` by hand.
/// Three copies of a coordinate is three chances for one of them to keep saying
/// `0` where the answer is "there is no offset", and a fabricated zero is
/// indistinguishable from the front of a unit.
///
/// Two absences fold into the same `None`, and both are real:
/// [`PassiveFrame::batch_offset`] is `None` when the batch's bytes were never on
/// the wire in that form, and `span` is `None` when the walk did not record
/// where this record stood.
///
/// THREE coordinates are added and each is measured by whoever owns it: where
/// the transport message stands in its unit, where the payload starts inside
/// that message, and where the record starts inside that payload. Dropping any
/// one of them still yields a plausible number, which is exactly why the two
/// tests below drive a fixture where all three differ.
pub(crate) fn record_unit_offset(
    frame: &PassiveFrame,
    span: Option<(usize, usize)>,
) -> Option<u64> {
    let batch_offset = frame.batch_offset?;
    let (record_offset, _) = span?;
    Some((frame.unit_offset + batch_offset + record_offset) as u64)
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
        self.resolve_parts(space, id, suffix)
    }

    /// R311y701 (PF2) — the same resolution, from the PARTS a reader has when
    /// it holds a walked field tree rather than a decoded message.
    ///
    /// `space` is the table the `M` bit named, already chosen by the caller —
    /// [`Self::resolve`] derives it from the codec variant, and a field-tree
    /// reader derives it from the `mapping` bit the walk records. Everything
    /// after that choice is one rule, in one place, because two copies of
    /// "prepend the base, then the suffix" is two chances to disagree about a
    /// keyexpr in a report whose whole output is keyexprs.
    pub fn resolve_parts(
        &self,
        space: Direction,
        id: u64,
        suffix: Option<&str>,
    ) -> Result<String, (Direction, u64)> {
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

    /// R311y701 (PF2) — fold ONE FRAME's keyexpr declarations in.
    ///
    /// # Why this lives here rather than in the reader that wants it
    ///
    /// The field layer in `wz-analyze` needs the same table to resolve a
    /// keyexpr id, and reaching it from there means matching on `Carried` — a
    /// enum whose variants are `#[cfg]`-gated on features this crate declares.
    /// R311y668 measured what that costs: an exhaustive match written outside
    /// the crate that owns the variants is not a mirror of it, and the arms
    /// silently differ per feature set. Written here, a new variant is an
    /// `E0004` on the round it lands.
    ///
    /// A frame carrying no readable batch contributes nothing, which is the
    /// right answer rather than a silence: an undecompressible batch may well
    /// have held a declaration, and the ids that declaration would have bound
    /// stay unresolved — reported by whoever counts unresolved references,
    /// never guessed at here.
    pub fn absorb_frame(&mut self, frame: &PassiveFrame) {
        let batch = match &frame.carried {
            Carried::Batch(batch) => batch,
            #[cfg(feature = "reassembly")]
            Carried::Reassembled(batch) => batch,
            Carried::Undecompressible => return,
            #[cfg(feature = "reassembly")]
            Carried::FragmentWithoutResolution => return,
            Carried::Nothing => return,
            #[cfg(feature = "reassembly")]
            Carried::Fragment(_) => return,
        };
        #[cfg(feature = "network-codecs")]
        for (message, _) in batch.records() {
            if let NetworkMessage::Declare(d) = message {
                self.absorb(frame.direction, d);
            }
        }
        // Without `network-codecs` there is no `Declare` variant to match, and
        // a build that cannot read one resolves only `id == 0` literals -- the
        // honest reach of that decoder, stated the way `observe_message` states
        // it one type over.
        #[cfg(not(feature = "network-codecs"))]
        let _ = batch;
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
/// while id spaces are per-flow, which is why [`Self::observe_flow_where`] is the
/// unit rather than a per-frame call: two sessions' id `3` are unrelated, and
/// one table across both would cross-resolve them.
#[derive(Debug, Default, Clone)]
pub struct ThroughputTable {
    rows: BTreeMap<String, KeyexprRow>,
    unresolved: BTreeMap<(usize, u64), UnresolvedAlias>,
    declarations: usize,
    undeclarations: usize,
    records: usize,
    unattributed: usize,
    unsized_payloads: usize,
    payloads_elsewhere: usize,
    payloads_unresolved: usize,
    unresolved_at_most_bytes: u64,
    /// R311y644 (§1.1p) — records whose SOURCE stamped them later than this
    /// observer saw them.
    ///
    /// Not a delay and not zero: proof that the publisher's clock and the
    /// capture host's are offset, which makes every `delay` figure in the same
    /// capture suspect. Without it a capture full of ahead-running publishers
    /// reports no measured delays and says nothing about why.
    source_ahead_of_observer: usize,
    /// R311y645 (§4.38) — records this table read that have NO byte offset into
    /// the capture.
    ///
    /// Their bytes were never contiguous on the wire (a reassembled fragment
    /// chain) or were never on it in that form at all (a decompressed batch), so
    /// there is no packet a reader can be pointed at. Counted here rather than
    /// left to `selection().undecided`, which only speaks about a selector that
    /// happened to carry an `offset` term: a reader who never wrote one still
    /// needs to know that part of this report cannot be located in the file.
    unlocatable_records: usize,
    /// R311y638 (§1.1r) — where the capture began, for the `elapsed` term.
    /// Set only by the whole-capture entry points, because only they have seen
    /// the whole capture; a caller folding flows by hand leaves it `None` and
    /// an `elapsed` term is undecidable rather than counted from a guess.
    capture_origin_ms: Option<u64>,
    gaps: ThroughputGaps,
    selection: Selection,
}

/// R311y614 (§1.4i) — traffic this table could not read AT ALL, as opposed to
/// traffic it read and could not attribute ([`crate::agg::ThroughputTable::unresolved`]).
///
/// Every other layer of this crate reports what it lost — a
/// [`SkipReason`](crate::link::SkipReason) per packet, a
/// [`DesyncReason`](wz_session_core::passive::DesyncReason) per direction, a
/// drop counter per dissection. The aggregation plane R311y613 added did not:
/// it walked `Carried::Batch` and `Reassembled`, ignored `BatchParse::halt`
/// entirely, and let every other `Carried` arm fall through a `_ => {}`. So a
/// capture whose batches half-decoded produced a table that was quietly short
/// and said nothing — the one failure mode this crate is built to refuse.
///
/// A NON-ZERO field here does not make [`ThroughputTable::rows`] wrong. It
/// makes them INCOMPLETE, which is a different claim and one a reader summing
/// them has to be able to see.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ThroughputGaps {
    /// Batches whose record walk stopped early ([`BatchParse::halt`]).
    ///
    /// Everything behind the halt was on the wire and is in no row. HOW MANY
    /// records that is cannot be known — the walk stopped because it could not
    /// tell where the next one began — which is why the honest companion figure
    /// is [`Self::unparsed_bytes`] rather than a record count.
    pub halted_batches: usize,
    /// Payload bytes inside halted batches that were never walked.
    pub unparsed_bytes: usize,
    /// Frames whose batch could not be produced at all: the session negotiated
    /// compression and the body did not decompress
    /// ([`Carried::Undecompressible`]).
    ///
    /// Counted separately from a halt because the loss is total rather than
    /// partial — the bytes were there and are unreadable.
    pub undecompressible_batches: usize,
    /// Fragments that arrived before this observer saw an InitAck, so no chain
    /// could be tracked and their eventual batch never existed
    /// ([`Carried::FragmentWithoutResolution`]). The ordinary cause is a
    /// capture that started mid-session.
    pub unresolvable_fragments: usize,
}

impl ThroughputGaps {
    /// `true` when this table's rows cover everything it was shown.
    pub fn is_clean(&self) -> bool {
        *self == Self::default()
    }
}

impl ThroughputTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// R311y616 (§1.1f) — the same fold, over the records a selector picks.
    ///
    /// ONE fold rather than a filtered copy beside the unfiltered one:
    /// R311y709 — there is now exactly ONE spelling of that. A
    /// `observe_flow(frames)` delegating to `observe_flow_where(frames,
    /// &Filter::any())` sat beside this method with zero callers anywhere in
    /// the workspace, while every production path reached the identity through
    /// [`aggregate`], which delegates to [`aggregate_where`] the same way one
    /// layer up. Two spellings of one delegation, one of them never exercised.
    ///
    /// ## What the filter does NOT touch
    ///
    /// DECLARATIONS are absorbed whatever the filter says, and that is load
    /// bearing rather than an oversight: a `DeclKexpr` binds the id every later
    /// reference resolves through, so skipping the ones a selector rejects
    /// would make the records it ACCEPTS unresolvable. The filter chooses what
    /// is COUNTED, never what is READ.
    ///
    /// Gap counters are likewise unfiltered. A halted batch is traffic nobody
    /// could read, so no predicate over its records can be evaluated — it stays
    /// in [`Self::gaps`], where a reader looking for what is missing will find
    /// it, rather than being quietly attributed to the selector.
    pub fn observe_flow_where(&mut self, frames: &[PassiveFrame], filter: &Filter) {
        let mut spaces = KeyexprSpaces::new();
        for frame in frames {
            let anchor = frame.stream_offset;
            match &frame.carried {
                Carried::Batch(batch) => {
                    self.observe_batch(&mut spaces, frame, anchor, batch, filter)
                }
                #[cfg(feature = "reassembly")]
                Carried::Reassembled(batch) => {
                    self.observe_batch(&mut spaces, frame, anchor, batch, filter)
                }
                // R311y614 (§1.4i) — the arms that carry traffic this table
                // cannot read are COUNTED. Matched by name rather than left to a
                // catch-all so a new `Carried` variant fails to compile here
                // instead of joining the silent set.
                Carried::Undecompressible => self.gaps.undecompressible_batches += 1,
                #[cfg(feature = "reassembly")]
                Carried::FragmentWithoutResolution => self.gaps.unresolvable_fragments += 1,
                // `Nothing` is a handshake / keepalive / unfeatured frame and
                // `Fragment` is a chain still in progress: neither is a batch
                // this table lost, so neither is a gap.
                Carried::Nothing => {}
                #[cfg(feature = "reassembly")]
                Carried::Fragment(_) => {}
            }
        }
    }

    fn observe_batch(
        &mut self,
        spaces: &mut KeyexprSpaces,
        frame: &PassiveFrame,
        anchor: usize,
        batch: &BatchParse,
        filter: &Filter,
    ) {
        if batch.halt.is_some() {
            self.gaps.halted_batches += 1;
            self.gaps.unparsed_bytes += batch.unparsed_bytes;
        }
        // R311y641 (§1.1n) — paired with the bytes each record came from, so
        // this plane can say WHERE a record was and not only that it was.
        for (message, span) in batch.records() {
            self.observe_message(spaces, frame, anchor, message, span, filter);
        }
    }

    fn observe_message(
        &mut self,
        spaces: &mut KeyexprSpaces,
        frame: &PassiveFrame,
        anchor: usize,
        message: &NetworkMessage,
        span: Option<(usize, usize)>,
        filter: &Filter,
    ) {
        let direction = frame.direction;
        // A DECLARE is absorbed and not counted: it declares a keyexpr, it does
        // not carry traffic under one, and counting it would put a row on every
        // topic a session merely named.
        //
        // R311y614 — gated, because `network-codecs` is switchable and the
        // variant does not exist without it. A build with the feature off
        // resolves only `id == 0` literals, which is the honest reach of a
        // decoder that cannot read a DECLARE.
        #[cfg(feature = "network-codecs")]
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

        let Some((keyexpr_body, counts, kind)) = classify(message) else {
            // R311y622 (§1.4h) — the SECOND DENOMINATOR. `classify` answers
            // `None` for every record that is not traffic under a keyexpr — a
            // `ResponseFinal` closing a query, an `Oam`, an `Interest`, and
            // every record at all in a build without the network codecs — and
            // until now each of those left this fold in silence. That made
            // `records()` a numerator with no denominator: a reader could not
            // tell a capture of 40 attributed records from one of 40 attributed
            // and 4000 unattributed, and both report the same rows.
            //
            // NOT a gap: nothing was lost. The record was read, named and
            // understood; it simply belongs in no row. `gaps()` is for traffic
            // this plane could not READ, and conflating the two would make a
            // healthy control-plane look like damage.
            self.unattributed += 1;
            return;
        };
        // R311y644 (§1.1p) — computed BEFORE the filter, since a `delay` term
        // has to be answerable at the same moment every other term is. The
        // clock-offset witness is counted here rather than inside the helper:
        // this is the plane that owns the capture-wide census.
        #[cfg(feature = "network-codecs")]
        let delay = match source_delay_ms(frame.observed_at_ms, source_timestamp(message)) {
            Ok(d) => d,
            Err(SourceAhead) => {
                self.source_ahead_of_observer += 1;
                None
            }
        };
        // Gated exactly as the two helpers are: without the network codecs there
        // is no body this build can read a source stamp out of, so the axis
        // declines for every record -- which is a smaller reach and not a wrong
        // answer.
        #[cfg(not(feature = "network-codecs"))]
        let delay = None;
        let resolved = spaces.resolve(direction, keyexpr_body);

        // R311y616 — the filter is asked AFTER resolution and BEFORE any
        // counter moves, because the answer depends on the resolved keyexpr and
        // because a record it rejects must leave no trace in the totals. An
        // undecidable record leaves no trace either, except in the one counter
        // whose whole job is to say the totals are not the whole answer.
        let view = RecordView {
            direction,
            keyexpr: resolved.as_ref().ok().map(|k| k.as_str()),
            kind,
            payload_bytes: sized_payload(&counts),
            unit_offset: record_unit_offset(frame, span),
            source_delay_ms: delay,
            observed_at_ms: frame.observed_at_ms,
            elapsed_ms: elapsed_since(self.capture_origin_ms, frame.observed_at_ms),
            // R311y636 (§1.1v) — this plane folds RECORDS, so it has no
            // exchange outcome to offer and says so. An outcome term over it is
            // undecidable, which is what puts the records in
            // `selection().undecided` rather than in an empty answer.
            outcome: None,
        };
        let truth = filter.matches(&view);
        self.selection.record(truth);
        if truth != Truth::Yes {
            return;
        }

        self.records += 1;
        // R311y645 (§4.38) — counted off the SAME value the selector was asked
        // about, so the census cannot say a record is locatable while the
        // `offset` term declines to speak about it.
        if view.unit_offset.is_none() {
            self.unlocatable_records += 1;
        }
        // R311y637 (§1.1w) — counted at the TABLE and not only on the row,
        // because a record whose keyexpr did not resolve has no row to carry
        // it and its unmeasured bytes are exactly as absent from
        // `total_payload_bytes` as an attributed one's.
        self.unsized_payloads += counts.unsized_payloads;
        // R311y646 (§4.28 / §4.34) — the same rule for the breakdown and the
        // ceiling: an unattributed record's unmeasured bytes are unmeasured
        // whatever row they failed to reach.
        self.payloads_elsewhere += counts.payloads_elsewhere;
        self.payloads_unresolved += counts.payloads_unresolved;
        self.unresolved_at_most_bytes += counts.unresolved_at_most_bytes;
        match resolved {
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
    /// R311y714 (§1.1f, [REDACTED-REQ]) — this keyexpr's share of the capture's
    /// application bytes, in truncated basis points.
    ///
    /// `None` when the capture carried no sized payload at all, which is a
    /// different statement from 0%: a capture whose payloads this build cannot
    /// SIZE has no denominator, and a zero would read as "this topic carried
    /// nothing" when the truth is "nothing here can be measured".
    ///
    /// The denominator is [`Self::total_payload_bytes`] — the bytes this plane
    /// could size, NOT the ceiling. `payload_bytes_ceiling` includes payloads
    /// that went elsewhere (shared memory) or could not be separated, and a
    /// share over it would shrink every topic's figure by an amount that has
    /// nothing to do with that topic.
    pub fn share_bp(&self, keyexpr: &str) -> Option<u32> {
        let total = self.total_payload_bytes();
        if total == 0 {
            return None;
        }
        let row = self.row(keyexpr)?;
        Some((row.totals().payload_bytes.saturating_mul(10_000) / total) as u32)
    }

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

    /// R311y642 (§1.1t) — the rows folded into the HIERARCHY their keyexprs
    /// already are, each node carrying the totals of everything beneath it.
    ///
    /// # The question a flat list cannot answer
    ///
    /// [`Self::rows`] totals per LITERAL keyexpr and orders by weight, which is
    /// the right answer to "which key carried the most" and the wrong one to
    /// "which part of the key space did". A publisher that splits one logical
    /// topic across a key per entity — `robot/1/pose`, `robot/2/pose`, ... , the
    /// ordinary zenoh idiom that `**` exists for — appears as N small rows and
    /// never as one large one. The subtree carrying most of the capture can
    /// therefore be absent from every ranking the report prints, and no amount
    /// of reading that ranking reveals it.
    ///
    /// A reader could group the flat list themselves. What they could not do is
    /// group it the way THIS crate splits a keyexpr, which is the reason the
    /// fold belongs here rather than in each consumer.
    ///
    /// Totals are INCLUSIVE: a node holds its own row (if a record was
    /// published on exactly that key) plus every descendant's. Children are
    /// ordered exactly as [`Self::rows`] is, so a reader moving between the two
    /// views does not have to hold two orderings in mind.
    pub fn subtrees(&self) -> KeyexprSubtree {
        let mut root = KeyexprSubtree::new(String::new());
        for row in self.rows.values() {
            root.insert(&row.keyexpr, &row.totals());
        }
        root.sort();
        root
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
    ///
    /// Under a filter this counts the SELECTED records: the ones in the rows.
    /// [`Self::selection`] holds the rest.
    pub fn records(&self) -> usize {
        self.records
    }

    /// R311y622 (§1.4h) — records this plane READ and does not attribute: a
    /// `ResponseFinal`, an `Oam`, an `Interest`, and every record at all in a
    /// build whose decoder cannot name the data plane.
    ///
    /// The companion denominator to [`Self::records`], and the reason it
    /// exists: rows summed against `records()` alone answer "of the traffic I
    /// attributed, how much did I attribute", which is a question that cannot
    /// come out badly. [`Self::walked_records`] is the honest whole.
    ///
    /// NOT a member of [`Self::gaps`]. Nothing here was lost — each record was
    /// read and understood and belongs in no row — and counting a healthy
    /// control plane as damage would make `is_clean` useless on every real
    /// capture.
    pub fn unattributed_records(&self) -> usize {
        self.unattributed
    }

    /// Every network record this plane walked: attributed, unattributed, and
    /// the declarations it absorbed.
    ///
    /// The one figure a reader can put under a row total without having to know
    /// which of four counters to add. `the_parts_account_for_every_record_
    /// walked` is what keeps it equal to its parts.
    pub fn walked_records(&self) -> usize {
        self.records + self.unattributed + self.declarations + self.undeclarations
    }

    /// R311y616 — what the filter did to the keyexpr-carrying records this
    /// table was shown.
    ///
    /// All-zero on a table that was never given frames, and
    /// `matched == records()` with nothing else on an unfiltered one — an
    /// identity filter rejects nothing and leaves nothing undecided, so a
    /// non-zero `undecided` always means a selector met a capture that could
    /// not answer it.
    pub fn selection(&self) -> Selection {
        self.selection
    }

    /// `DeclKexpr` / `UndeclKexpr` absorbed — `(declared, undeclared)`.
    pub fn declarations(&self) -> (usize, usize) {
        (self.declarations, self.undeclarations)
    }

    /// R311y637 (§1.1w) — records this table read whose payload it could not
    /// SIZE, so [`Self::total_payload_bytes`] is a floor rather than a total.
    ///
    /// Not a [`ThroughputGaps`] member on purpose: a gap there means traffic
    /// this plane could not READ, and these records were read, named and
    /// attributed. Only their byte contribution is unknown, which is a
    /// qualifier on ONE total rather than on the rows.
    pub fn unsized_payloads(&self) -> usize {
        self.unsized_payloads
    }

    /// R311y646 (§4.28 / §4.34) — WHY those payloads went unmeasured, and how
    /// many bytes the ones that are still in the capture come to at most.
    ///
    /// [`Self::unsized_payloads`] is the sum of the two counts, so a reader who
    /// only wants "is the total whole" keeps asking that. This answers the
    /// question a reader asks NEXT, and until now the report could not: whether
    /// the missing bytes are absent from the file (nothing will recover them
    /// here) or merely unseparated in it (a better decoder, or the bound below).
    pub fn unmeasured_payloads(&self) -> UnmeasuredPayloads {
        UnmeasuredPayloads {
            elsewhere: self.payloads_elsewhere,
            unresolved: self.payloads_unresolved,
            at_most_bytes: self.unresolved_at_most_bytes,
        }
    }

    /// R311y646 (§4.28) — the CEILING on the application bytes this capture
    /// carried, against [`Self::total_payload_bytes`]'s floor.
    ///
    /// Equal to the floor exactly when every payload was measured. The gap
    /// between them is what this reader admits it does not know, expressed in
    /// the same unit as the answer — which a count of records is not.
    ///
    /// Bounded only over the records whose bytes ARE here: an SHM descriptor's
    /// application bytes are on another machine and no ceiling read off this
    /// wire says anything about them, so `elsewhere` records widen neither end.
    pub fn payload_bytes_ceiling(&self) -> u64 {
        self.total_payload_bytes() + self.unresolved_at_most_bytes
    }

    /// R311y644 (§1.1p) — records whose source clock ran ahead of this
    /// observer's. Non-zero means the `delay` axis cannot be trusted for this
    /// capture, and it is the only thing that says so.
    pub fn source_ahead_of_observer(&self) -> usize {
        self.source_ahead_of_observer
    }

    /// R311y645 (§4.38) — records in this table that cannot be pointed at in
    /// the capture file, because their bytes were reassembled or decompressed
    /// rather than read where they lay.
    ///
    /// Not a [`ThroughputGaps`] member, for the reason [`Self::unsized_payloads`]
    /// is not one: nothing was lost. The record was read, named and attributed;
    /// only its LOCATION is absent, which qualifies what a reader can do with it
    /// rather than what the totals are worth.
    pub fn unlocatable_records(&self) -> usize {
        self.unlocatable_records
    }

    /// Application bytes across every resolved keyexpr.
    ///
    /// A FLOOR whenever [`Self::unsized_payloads`] is non-zero — read the two
    /// together, exactly as [`Self::records`] is read against
    /// [`Self::walked_records`].
    pub fn total_payload_bytes(&self) -> u64 {
        self.rows.values().map(|r| r.totals().payload_bytes).sum()
    }

    /// R311y614 (§1.4i) — traffic this table could not READ, and therefore
    /// could not put in any row.
    ///
    /// Consult it before treating [`Self::total_payload_bytes`] as the
    /// capture's total: a clean answer ([`ThroughputGaps::is_clean`]) is what
    /// makes the rows a complete account, and anything else is a short one.
    pub fn gaps(&self) -> ThroughputGaps {
        self.gaps
    }
}

/// Which counter a network record moves, the keyexpr it moves it under, and
/// what a filter should call it.
///
/// `None` for every record that carries no keyexpr — `ResponseFinal` (a pure
/// correlation marker), `Oam`, `Interest`, `Unknown`. They are not silently
/// dropped: they never entered [`ThroughputTable::records`] either, so the
/// unresolved fraction stays a fraction of records that HAVE a keyexpr.
///
/// R311y616 — the [`RecordKind`] is returned rather than re-derived from the
/// counts by the caller. The counts have exactly one field set and a reader
/// could infer the kind from that, but an inference is a second place the
/// classification lives, and the two would disagree the first time a record
/// moved two counters.
#[allow(clippy::type_complexity)]
/// R311y618 (§1.1q) — `pub(crate)` so the exchange and payload planes ask THIS
/// function what a record is instead of re-deriving the partition.
///
/// The kinds and the counters are one classification, and a second spelling of
/// it in another module is the copy that drifts: a reader writing `kind ==
/// reply` against the payload plane must get the same answer the throughput
/// plane would give for the same bytes, and the only way that cannot break is
/// for there to be one function.
/// R311y638 (§1.1r) — one record's capture-relative instant.
///
/// `None` when either end is missing, and the two absences are deliberately not
/// told apart: a record with no clock and a plane with no origin are both
/// "cannot be decided here". A record stamped BEFORE the origin would be a
/// contradiction rather than a negative interval, so it answers `None` too
/// instead of saturating to a confident zero.
pub(crate) fn elapsed_since(origin: Option<u64>, at: Option<u64>) -> Option<u64> {
    at?.checked_sub(origin?)
}

/// R311y637 (§1.1w) — one record's payload size as a filter must see it.
///
/// The single place the two representations meet, so the rule cannot be spelled
/// differently in the three planes that build a [`RecordView`]: a record with
/// an unsizable payload has NO byte figure at all, rather than the `0` that
/// [`KeyexprCounts::payload_bytes`] necessarily holds for it.
pub(crate) fn sized_payload(counts: &KeyexprCounts) -> Option<u64> {
    if counts.unsized_payloads > 0 {
        None
    } else {
        Some(counts.payload_bytes)
    }
}

/// R311y622 (§1.1o) — whether a zenoh-body ext chain carries the SHM marker,
/// meaning the payload slot holds a DESCRIPTOR and not the data.
///
/// Matched on the extension IDENTITY, mandatory bit included
/// (`zextunit!(0x2, true)`), not on the 4-bit id field. The id space is four
/// bits wide and zenoh reuses values across encodings deliberately, so an
/// id-only match would read an unrelated `0x2` entry as an SHM descriptor and
/// silence a payload this crate could have judged — the mirror of the defect
/// R311y505 measured on the establishment space.
///
/// Read through `ext_header`, which is UNCONDITIONAL, rather than through
/// `extshm`, which is gated on `transport-shm`. An observer must recognise ids
/// whose capability its own build cannot perform; that asymmetry is why the id
/// table lives where it does.
///
/// R311y639 (§4.30) — this lives in `agg` now, beside the classification it
/// shares a rule with, and [`crate::payload`] calls it here. It was private to
/// that module while the throughput plane, reading the same four carriers, did
/// not ask the question at all: one plane refusing to judge a descriptor as
/// data and another reporting its slot length as a byte total is two answers to
/// one question, which is exactly what a single function forecloses.
#[cfg(feature = "network-codecs")]
pub(crate) fn carries_shm_marker(
    extensions: Option<&[wz_codecs::ext_entry::ExtEntryOwned]>,
) -> bool {
    use wz_session_core::ext_header::{body_ext_id, ext_eid, EXT_FLAG_M};

    let want = ext_eid(body_ext_id::SHM | EXT_FLAG_M);
    extensions
        .unwrap_or(&[])
        .iter()
        .any(|e| ext_eid(e.header) == want)
}

/// R311y644 (§1.1p) — how long a record took to reach this observer, in ms.
///
/// # A one-way axis from a single tap
///
/// The exchange plane measures a ROUND TRIP: request out, reply back, both seen
/// at the same vantage point, so nothing about it separates the two legs. A
/// one-way figure normally needs two synchronised taps, which is why this axis
/// sat unbuilt.
///
/// It does not, for the records that carry a `Timestamp`. zenoh stamps a `Put`
/// or a `Del` at the SOURCE with an HLC word (`zenoh-protocol-1.5.0`
/// re-exports `uhlc::Timestamp`; the word's layout is
/// [`Ntp64`](wz_session_core::ntp64::Ntp64)), and the capture stamps the packet
/// on arrival. The difference is the time from the publisher stamping the value
/// to this observer seeing it — publisher-to-tap, which is the leg a reader
/// actually asks about when data is late.
///
/// # What it is NOT, and why the contradiction is a separate answer
///
/// The two clocks are DIFFERENT MACHINES and nothing here synchronises them, so
/// the figure carries the publisher-to-observer clock offset. A capture whose
/// publisher runs ahead therefore produces a stamp LATER than the arrival, and
/// that is not a negative delay — it is proof the offset is not zero, which
/// makes every other figure in the same capture suspect. It answers `None` and
/// is counted where a reader can see it
/// ([`ThroughputTable::source_ahead_of_observer`]), rather than saturating to a
/// confident `0`.
#[cfg(feature = "network-codecs")]
pub(crate) fn source_delay_ms(
    observed_at_ms: Option<u64>,
    timestamp: Option<&wz_codecs::timestamp::TimestampOwned>,
) -> Result<Option<u64>, SourceAhead> {
    let (Some(seen), Some(ts)) = (observed_at_ms, timestamp) else {
        return Ok(None);
    };
    let stamped = wz_session_core::ntp64::Ntp64::from_word(ts.time).to_millis();
    match u128::from(seen).checked_sub(stamped) {
        // The cast cannot lose: `stamped <= seen` and `seen` came from a u64.
        Some(d) => Ok(Some(d as u64)),
        None => Err(SourceAhead),
    }
}

/// R311y644 (§1.1p) — the source stamped a record LATER than this observer saw
/// it, so the two clocks are provably offset.
#[cfg(feature = "network-codecs")]
pub(crate) struct SourceAhead;

/// R311y639 (§4.30) — what one `MsgPut` / `Err` slot is worth to the totals.
///
/// The pair the carrier arms hand to [`KeyexprCounts::record_payload`], so the
/// SHM question is asked once for the four sites that carry a sizable slot
/// (`Push` Put, `Request` Put, `Reply` Put, `Err`) instead of at each of them.
#[cfg(feature = "network-codecs")]
fn measured_payload(
    payload: &[u8],
    extensions: Option<&[wz_codecs::ext_entry::ExtEntryOwned]>,
) -> PayloadSize {
    if carries_shm_marker(extensions) {
        // R311y646 (§4.34) — ELSEWHERE and not "unresolved with a bound": the
        // slot's own length bounds nothing about the application's bytes, which
        // never crossed this network. Offering the descriptor's width as a
        // ceiling would be the R311y639 defect in a politer form.
        PayloadSize::Elsewhere
    } else {
        PayloadSize::Measured(payload.len() as u64)
    }
}

/// R311y640 (§1.1w) — how many application bytes a `Query`'s VALUE ext holds.
///
/// The ext body is not opaque after all, which is what R311y637 recorded and
/// this round measured instead of inheriting. Upstream lays it out as `encoding`
/// then `pl: [u8;z32]` (`zenoh-protocol-1.5.0/src/zenoh/mod.rs:196-210`), so the
/// application payload carries its OWN length prefix inside the ext: the number
/// is literally on the wire, one sub-decode away, and reporting the record as
/// unmeasurable was a limit of this reader rather than of the wire.
///
/// `None` keeps the R311y637 behaviour for every body this cannot resolve — a
/// truncated ext, an encoding this build's codec cannot read, a declared length
/// that disagrees with the bytes present. The last is deliberate and matches
/// [`KeyexprCounts::payload_bytes`]'s own rule: a record whose z32 prefix claims
/// more (or fewer) bytes than follow it is lying or truncated, and a total must
/// not be inflated by a number no bytes back. Unmeasurable is the honest answer
/// there, not the declared figure.
/// R311y646 (§4.28) — every failing arm now carries a BOUND rather than a bare
/// absence. The bytes are in the capture whatever went wrong reading them, and
/// the enclosing structure says how many there are at most: the ext body itself
/// when the encoding will not decode, and what remains after the encoding when
/// the length prefix will not read or disagrees with the bytes behind it. Each
/// arm bounds with what it has actually reached, so the ceiling tightens as the
/// decode gets further rather than being one loose number for all three.
#[cfg(feature = "network-codecs")]
fn query_value_bytes(body: &[u8]) -> PayloadSize {
    let mut cursor = wz_codecs::SceCursor::new(body);
    // The encoding prefix is CONSUMED rather than inspected: its only job here
    // is to move the cursor to the length prefix. Reading it through the codec
    // instead of skipping a guessed width is what makes a schema-carrying
    // encoding (`packed_id & 1`, a name of its own length) come out right.
    if wz_codecs::encoding::Encoding::decode(&mut cursor).is_err() {
        return PayloadSize::Unresolved {
            at_most: body.len() as u64,
        };
    }
    // Snapshotted BEFORE the read: a VLE that runs out of bytes may leave the
    // cursor part-way through its own prefix, and a bound read off a cursor a
    // failed decode moved is a number about this reader's progress rather than
    // about the wire.
    let after_encoding = cursor.remaining() as u64;
    let Ok(declared) = cursor.read_vle_u64() else {
        return PayloadSize::Unresolved {
            at_most: after_encoding,
        };
    };
    let present = cursor.remaining() as u64;
    if declared == present {
        PayloadSize::Measured(declared)
    } else {
        PayloadSize::Unresolved { at_most: present }
    }
}

/// R311y637 (§1.1w) — does this `Query`'s ext chain carry a VALUE?
///
/// Matched on `(id, ZBUF body)` exactly as
/// [`decode_attachment_ext`](wz_session_core::attachment::decode_attachment_ext)
/// matches its own: the `ExtZbuf` arm IS the decode-time witness that the
/// header carried `ENC_ZBUF`, so no separate encoding test is needed. The id is
/// read from the named constant rather than spelled `0x03` here, because `0x03`
/// in this space is `Attachment` on a `Put` and this is a `Query`.
/// R311y640 — it returns the ext's BODY BYTES now rather than a bool, because
/// the presence and the size are one question asked at one place: a caller
/// holding the body can measure it, and a caller holding only `true` had no
/// choice but to report the record as unmeasurable.
#[cfg(feature = "network-codecs")]
fn query_body_bytes(extensions: Option<&[wz_codecs::ext_entry::ExtEntryOwned]>) -> Option<&[u8]> {
    extensions?.iter().find_map(|ext| {
        match (
            ext.ext_id() == wz_session_core::ext_header::body_ext_id::QUERY_BODY,
            &ext.body,
        ) {
            (true, wz_codecs::ext_entry::ExtEntryOwnedVariant::CodecZenohExtZbuf(z)) => {
                Some(wz_codecs::SceByteBuf::as_slice(&z.value))
            }
            _ => None,
        }
    })
}

/// R311y644 (§1.1p) — the SOURCE timestamp a record carries, if it carries one.
///
/// Only `Put` and `Del` do (`out/wz-codecs/msg_put.rs`, `msg_del.rs`; a `Query`,
/// a `Reply` envelope and an `Err` declare no timestamp field at all), and a
/// `Put` carries one only when its `T` flag was set. Extracted HERE rather than
/// in each plane for the reason [`classify`] is: three spellings of "which
/// records have a source clock" is three places for the answer to drift.
#[cfg(feature = "network-codecs")]
pub(crate) fn source_timestamp(
    message: &NetworkMessage,
) -> Option<&wz_codecs::timestamp::TimestampOwned> {
    use wz_codecs::push::PushOwnedVariant;
    use wz_codecs::reply::ReplyOwnedVariant;
    use wz_codecs::request::RequestOwnedVariant;
    use wz_codecs::response::ResponseOwnedVariant;
    match message {
        NetworkMessage::Push(p) => match &p.body {
            PushOwnedVariant::CodecZenohMsgPut(m) | PushOwnedVariant::Default { body: m, .. } => {
                m.timestamp.as_ref()
            }
            PushOwnedVariant::CodecZenohMsgDel(m) => m.timestamp.as_ref(),
        },
        NetworkMessage::Request(r) => match &r.body {
            RequestOwnedVariant::CodecZenohMsgPut(m) => m.timestamp.as_ref(),
            RequestOwnedVariant::CodecZenohMsgDel(m) => m.timestamp.as_ref(),
            _ => None,
        },
        NetworkMessage::Response(r) => match &r.body {
            ResponseOwnedVariant::CodecZenohReply(reply)
            | ResponseOwnedVariant::Default { body: reply, .. } => match &reply.body {
                ReplyOwnedVariant::CodecZenohMsgPut(m)
                | ReplyOwnedVariant::Default { body: m, .. } => m.timestamp.as_ref(),
                ReplyOwnedVariant::CodecZenohMsgDel(m) => m.timestamp.as_ref(),
            },
            ResponseOwnedVariant::CodecZenohErr(_) => None,
        },
        _ => None,
    }
}

pub(crate) fn classify(
    message: &NetworkMessage,
) -> Option<(&WireexprOwnedVariant, KeyexprCounts, RecordKind)> {
    #[cfg(feature = "network-codecs")]
    use wz_codecs::push::PushOwnedVariant;
    #[cfg(feature = "network-codecs")]
    use wz_codecs::request::RequestOwnedVariant;
    #[cfg(feature = "network-codecs")]
    use wz_codecs::response::ResponseOwnedVariant;

    // `unused` rather than `unused_mut`: with `network-codecs` off there is no
    // arm left that reads it, and the function correctly answers `None` for
    // every record — a decoder that cannot name a Push has no keyexpr to
    // attribute, which is a smaller reach and not a wrong one.
    #[allow(unused_mut, unused_variables)]
    let mut counts = KeyexprCounts::default();
    match message {
        #[cfg(feature = "network-codecs")]
        NetworkMessage::Push(p) => {
            let kind = match &p.body {
                PushOwnedVariant::CodecZenohMsgPut(put)
                | PushOwnedVariant::Default { body: put, .. } => {
                    counts.puts = 1;
                    counts.record_payload(measured_payload(
                        put.payload.as_slice(),
                        put.extensions.as_deref(),
                    ));
                    RecordKind::Put
                }
                PushOwnedVariant::CodecZenohMsgDel(_) => {
                    counts.dels = 1;
                    RecordKind::Del
                }
            };
            Some((&p.keyexpr.body, counts, kind))
        }
        #[cfg(feature = "network-codecs")]
        NetworkMessage::Request(r) => {
            let kind = match &r.body {
                RequestOwnedVariant::CodecZenohMsgPut(put) => {
                    counts.puts = 1;
                    counts.record_payload(measured_payload(
                        put.payload.as_slice(),
                        put.extensions.as_deref(),
                    ));
                    RecordKind::Put
                }
                RequestOwnedVariant::CodecZenohMsgDel(_) => {
                    counts.dels = 1;
                    RecordKind::Del
                }
                RequestOwnedVariant::CodecZenohQuery(q) => {
                    counts.queries = 1;
                    // R311y637 (§1.1w) — a query's VALUE is not a field of the
                    // message, it is an ext. Looking only at the body and
                    // reporting `0` was a confident answer to a question this
                    // decoder cannot answer; asking the chain separates the
                    // query that carries nothing (a real zero) from the one
                    // whose payload this build cannot measure.
                    // R311y640 (§1.1w) — the ext is asked for its BYTES, and
                    // those bytes are then asked for their size. R311y637 could
                    // only reach the first half and so reported every valued
                    // query as unmeasurable; the payload's own z32 prefix was on
                    // the wire inside the ext the whole time.
                    if let Some(body) = query_body_bytes(q.extensions.as_deref()) {
                        counts.record_payload(query_value_bytes(body));
                    }
                    RecordKind::Query
                }
                // The unknown request variant is decoded INTO a `Query` body by
                // the codec's declared default arm, but nothing says the bytes
                // were a query — so its chain is not read for a query body
                // either. It keeps the honest zero it always had.
                RequestOwnedVariant::Default { .. } => {
                    counts.queries = 1;
                    RecordKind::Query
                }
            };
            Some((&r.keyexpr.body, counts, kind))
        }
        #[cfg(feature = "network-codecs")]
        NetworkMessage::Response(r) => {
            use wz_codecs::reply::ReplyOwnedVariant;
            let kind = match &r.body {
                ResponseOwnedVariant::CodecZenohReply(reply)
                | ResponseOwnedVariant::Default { body: reply, .. } => {
                    counts.replies = 1;
                    // A reply carrying a `MsgPut` stays a REPLY here, and the
                    // choice is deliberate: the kinds partition the records
                    // exactly as the counters do, so `kind == reply` and
                    // `KeyexprCounts::replies` can never disagree about the
                    // same record. A reader after reply payloads writes
                    // `kind == reply and bytes > 0`, which is one term longer
                    // and never ambiguous.
                    if let ReplyOwnedVariant::CodecZenohMsgPut(put)
                    | ReplyOwnedVariant::Default { body: put, .. } = &reply.body
                    {
                        // The marker rides the INNER Put, not the `Reply`
                        // wrapper: upstream's `ReplyBody` IS `PushBody`
                        // (`zenoh-protocol-1.5.0/src/zenoh/reply.rs:53`) and the
                        // `Reply` itself declares no shm ext, so the chain to
                        // ask is the one this arm already holds.
                        counts.record_payload(measured_payload(
                            put.payload.as_slice(),
                            put.extensions.as_deref(),
                        ));
                    }
                    RecordKind::Reply
                }
                ResponseOwnedVariant::CodecZenohErr(err) => {
                    counts.errs = 1;
                    // An `Err` carries the shm ext in its own right —
                    // `zextunit!(0x2, true)`, the same identity on a different
                    // carrier (`zenoh-protocol-1.5.0/src/zenoh/err.rs:49-68`).
                    counts.record_payload(measured_payload(
                        err.payload.as_slice(),
                        err.extensions.as_deref(),
                    ));
                    RecordKind::Err
                }
            };
            Some((&r.keyexpr.body, counts, kind))
        }
        _ => None,
    }
}

/// Aggregate an entire [`crate::Dissection`] — every stream flow and every
/// datagram flow, each resolved against its own id spaces.
pub fn aggregate(dissection: &crate::Dissection) -> ThroughputTable {
    aggregate_where(dissection, &Filter::any())
}

/// R311y616 (§1.1f) — the same aggregation, over the records a selector picks.
///
/// The production entry point for [`crate::filter`]: a caller holding a
/// selector string parses it once and hands the compiled filter here, and the
/// table it gets back carries [`ThroughputTable::selection`] so the totals are
/// never read without the count of records the selector could not judge.
pub fn aggregate_where(dissection: &crate::Dissection, filter: &Filter) -> ThroughputTable {
    let mut table = ThroughputTable::new();
    // R311y638 (§1.1r) — the origin comes from the DISSECTION, which is the
    // only thing that has seen every packet. Set before the first fold, so no
    // record is judged against a half-known capture.
    table.capture_origin_ms = dissection.capture_origin_ms();
    // R311y721 — EVERY list this capture holds, through the dissection's own
    // enumeration. Naming the two flow tables here is what left this plane
    // blind to a serial line, which is in neither: see
    // `Dissection::message_lists`.
    for (_, frames) in dissection.message_lists() {
        table.observe_flow_where(frames, filter);
    }
    table
}

/// R311y621 (§1.1k) — what this plane can still do when the DECODER cannot
/// name the data plane.
///
/// Its own module, and the `not(...)` is the point: the tests below cannot be
/// asked of a build that HAS the network codecs, exactly as the module beside
/// them cannot be asked of a build that lacks them. Between the two, the plane
/// has an assertion in both worlds instead of only the one a default build
/// happens to be in.
#[cfg(all(test, not(feature = "network-codecs")))]
mod no_codec_tests {
    use super::*;
    use crate::datagram_tests::{frame_carrying, push, sender_space, udp_packet};
    use crate::link::LINKTYPE_ETHERNET;
    use crate::Dissection;

    /// THE ANSWER TO §1.1k, and it is not the one the register carried.
    ///
    /// The register said this build "resolves only `id == 0` literals". It
    /// resolves NOTHING: `classify` answers `None` for every record here,
    /// because the variants it matches do not exist without the codecs, so no
    /// keyexpr is ever reached and no row is ever created. The comment beside
    /// `observe_message` describing a literal-only reach is describing a path
    /// the `classify` guard in front of it makes unreachable.
    ///
    /// What the plane DOES do is the half worth gating: it reports the traffic
    /// as UNREAD. A record this build cannot name does not go quietly missing —
    /// it halts the batch walk, and the halt plus its unparsed byte count reach
    /// `gaps()`. So the degradation is a LOSS REPORT and not silence, which is
    /// the difference between a total a reader may trust and one they may not.
    #[test]
    fn a_build_without_the_network_codecs_reports_the_traffic_as_unread() {
        let record = push(sender_space(0, Some("demo/topic")), &[0u8; 12]);
        let wire = frame_carrying(&record);
        let mut d = Dissection::new();
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &wire),
        );

        let table = aggregate(&d);
        assert_eq!(
            table.records(),
            0,
            "no record can be named, so none may be counted"
        );
        assert!(table.rows().is_empty(), "and no row may be invented");
        assert_eq!(
            table.unresolved_records(),
            0,
            "an unresolved ALIAS is a record read and not attributed; \
             nothing here was read"
        );

        let gaps = table.gaps();
        assert!(
            !gaps.is_clean(),
            "the whole point: the shortfall must be visible"
        );
        assert_eq!(gaps.halted_batches, 1);
        assert!(
            gaps.unparsed_bytes >= record.len(),
            "the halt absorbs the record it could not name: {gaps:?}"
        );
        assert_eq!(gaps.undecompressible_batches, 0);
    }

    /// THE CONTROL: a build that cannot name the data plane still reads the
    /// TRANSPORT around it, so an empty capture is distinguishable from an
    /// unread one. Without this the assertion above would be satisfied by a
    /// plane that reported a halt for every frame ever.
    #[test]
    fn a_frame_carrying_nothing_is_not_reported_as_unread() {
        let wire = frame_carrying(&[]);
        let mut d = Dissection::new();
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &wire),
        );

        let table = aggregate(&d);
        assert!(
            table.gaps().is_clean(),
            "an empty batch is not a batch that could not be read: {:?}",
            table.gaps()
        );
        assert_eq!(table.records(), 0);
    }
}

// R311y614 — the whole module is gated, on the same rule the `Fragment` census
// entry follows for `reassembly`: these tests assert what a build WITH the
// network codecs does, and a build without them cannot be asked. Gating the
// module rather than each test keeps the two from drifting.
#[cfg(all(test, feature = "network-codecs"))]
pub(crate) mod tests {
    use super::*;
    use crate::datagram_tests::{push, push_stamped, sender_space, udp_packet};
    use crate::link::LINKTYPE_ETHERNET;
    use crate::Dissection;

    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;

    /// The two endpoints. `.1` sorts below `.2`, so `.1 -> .2` is
    /// [`Direction::A`] — asserted rather than assumed by
    /// [`the_directions_are_the_ones_this_module_thinks_they_are`].
    const LOW: [u8; 4] = [10, 0, 0, 1];
    const HIGH: [u8; 4] = [10, 0, 0, 2];

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

    /// A `Push` carrying a `MsgDel` under `keyexpr`.
    ///
    /// The second KIND on this plane, and it exists so a `kind` term has two
    /// answers to tell apart: a fixture of nothing but Puts cannot distinguish
    /// a view that reads the record's kind from one that hardwires it, because
    /// the hardwired guess would be right every time.
    fn push_del(keyexpr: Wireexpr<'static>) -> Vec<u8> {
        let has_suffix = match &keyexpr.body {
            WireexprVariant::WireexprLocal(a) => a.suffix.is_some(),
            WireexprVariant::WireexprNonlocal(a) => a.suffix.is_some(),
        };
        let n_flag = if has_suffix {
            wz_codecs::wire_const::FLAG_N_N
        } else {
            0
        };
        wz_codecs::push::Push {
            header: wz_codecs::push::Push::default().header | n_flag,
            keyexpr,
            body: wz_codecs::push::PushVariant::CodecZenohMsgDel(
                wz_codecs::msg_del::MsgDel::default(),
            ),
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

    /// R311y640 (§1.1w) — the ext body zenoh actually puts on the wire for a
    /// query's value: `encoding` then the payload as `[u8;z32]`
    /// (`zenoh-protocol-1.5.0/src/zenoh/mod.rs:196-210`).
    ///
    /// THE FIXTURE THIS REPLACES AGREED WITH THE DEFECT. R311y637 wrote the raw
    /// value bytes here as one opaque blob, because that round's reading was
    /// that the body could not be decomposed — so the sub-decoder added in
    /// R311y640 could never resolve it, and a test asserting "unmeasurable"
    /// passed for a reason that had nothing to do with the wire. The fixture
    /// must produce the shape the wire produces or the plane is being asked a
    /// different question -> [[feedback_a_fixture_can_make_a_defect_unreachable]].
    ///
    /// The length prefix is written with the runtime's own VLE writer rather
    /// than a hand-rolled byte, so the fixture and the reader cannot agree on a
    /// non-canonical encoding that no sender would emit.
    fn query_value_body(payload: &[u8]) -> alloc::vec::Vec<u8> {
        query_value_body_encoded(payload, None)
    }

    /// The same body with `schema` on its encoding, which makes the encoding
    /// prefix SEVERAL bytes wide.
    ///
    /// It exists because the bare form cannot tell a sub-decode from a guess:
    /// `packed_id: 0` with no schema encodes to exactly ONE byte, so a reader
    /// that skipped a hardcoded byte instead of decoding the encoding would land
    /// on the length prefix anyway and every assertion would hold. Measured, not
    /// argued -- that probe passed against the bare fixture alone
    /// -> [[feedback_a_fixture_can_make_a_defect_unreachable]].
    fn query_value_body_encoded(payload: &[u8], schema: Option<&str>) -> alloc::vec::Vec<u8> {
        use wz_codecs::SceSink;
        let mut body = wz_codecs::encoding::Encoding {
            // `zenoh_bytes` (id 0) when no schema, the encoding a value carries
            // when the application declared none. The LSB is the has-schema
            // flag, so setting it shifts the id and adds the two schema fields.
            packed_id: if schema.is_some() { 1 } else { 0 },
            schema_len: schema.map(|s| s.len() as u64),
            schema,
        }
        .encode_to_vec();
        wz_codecs::VecSink::new(&mut body)
            .write_vle_u64(payload.len() as u64)
            .expect("a Vec sink cannot overflow");
        body.extend_from_slice(payload);
        body
    }

    /// R311y637 (§1.1w) — a `Request` carrying a `Query`, optionally with the
    /// VALUE ext that carries its payload.
    ///
    /// The ext is built from the named id and the ZBUF arm rather than a
    /// literal `0x03` and a hand-set encoding nibble, so the fixture and the
    /// classifier cannot drift apart by agreeing on a wrong number: if
    /// `QUERY_BODY` were wrong, both would move together and this test would
    /// still pass — which is why the constant's own doc cites
    /// `zenoh-protocol-1.5.0/src/zenoh/query.rs:104` instead of asserting it
    /// here.
    pub(crate) fn request_query_valued(
        rid: u64,
        keyexpr: Wireexpr<'static>,
        value: Option<&'static [u8]>,
    ) -> Vec<u8> {
        request_query_ext(rid, keyexpr, value.map(query_value_body))
    }

    /// R311y640 (§1.1w) — a query whose VALUE ext is there and whose body this
    /// reader cannot resolve: the z32 prefix claims more bytes than follow it.
    ///
    /// The control the measurable case needs. Without it the axis would have
    /// collapsed from three-valued back to two: R311y637's `None` has to stay
    /// REACHABLE, or "unmeasurable" becomes a state nothing can produce and the
    /// distinction it exists for stops being tested.
    /// A valued query whose encoding carries a SCHEMA, so the prefix the
    /// sub-decoder must walk is wider than one byte.
    pub(crate) fn request_query_valued_with_schema(
        rid: u64,
        keyexpr: Wireexpr<'static>,
        value: &[u8],
    ) -> Vec<u8> {
        request_query_ext(
            rid,
            keyexpr,
            Some(query_value_body_encoded(value, Some("application/json"))),
        )
    }

    pub(crate) fn request_query_truncated(rid: u64, keyexpr: Wireexpr<'static>) -> Vec<u8> {
        use wz_codecs::SceSink;
        let mut body = wz_codecs::encoding::Encoding {
            packed_id: 0,
            schema_len: None,
            schema: None,
        }
        .encode_to_vec();
        wz_codecs::VecSink::new(&mut body)
            .write_vle_u64(99)
            .expect("a Vec sink cannot overflow");
        body.extend_from_slice(b"abc");
        request_query_ext(rid, keyexpr, Some(body))
    }

    /// A `Request` carrying a `Query`, optionally with `body` on the VALUE ext.
    fn request_query_ext(
        rid: u64,
        keyexpr: Wireexpr<'static>,
        value: Option<alloc::vec::Vec<u8>>,
    ) -> Vec<u8> {
        use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
        use wz_session_core::ext_header::{body_ext_id, EXT_ENC_ZBUF};
        let has_suffix = match &keyexpr.body {
            WireexprVariant::WireexprLocal(a) => a.suffix.is_some(),
            WireexprVariant::WireexprNonlocal(a) => a.suffix.is_some(),
        };
        let n_flag = if has_suffix {
            wz_codecs::wire_const::FLAG_N_N
        } else {
            0
        };
        // Built OWNED and projected back to the borrowed form, because the
        // borrowed `Query` holds a bounded (heapless) chain this crate has no
        // direct constructor for. `try_as_borrowed` is the codec's own
        // projection, so the fixture goes through the same narrowing a decode
        // does rather than around it.
        let borrowed_default = wz_codecs::query::Query::default();
        let mut owned: wz_codecs::query::QueryOwned = borrowed_default
            .try_into_owned_in()
            .expect("an empty query owns trivially");
        if let Some(body) = value {
            owned.extensions = Some(alloc::vec![ExtEntryOwned {
                header: body_ext_id::QUERY_BODY | EXT_ENC_ZBUF,
                body: ExtEntryOwnedVariant::CodecZenohExtZbuf(wz_codecs::ext_zbuf::ExtZbufOwned {
                    value_len: body.len() as u64,
                    value: wz_session_core::codec_owned::owned_bytes(&body)
                        .expect("the fixture value is within the owned bound"),
                }),
            }]);
            owned.header |= 0x80;
        }
        let query = owned.try_as_borrowed().expect("the chain is within bounds");
        // Bound rather than returned directly: the borrowed query points into
        // `owned`, which the tail expression would drop first.
        let encoded = wz_codecs::request::Request {
            header: wz_codecs::request::Request::default().header | n_flag,
            rid,
            keyexpr,
            body: wz_codecs::request::RequestVariant::CodecZenohQuery(query),
            ..Default::default()
        }
        .encode_to_vec();
        encoded
    }

    /// ANTI-VACUITY for everything below: the fixture really does put a query
    /// WITH a value and a query WITHOUT one on the wire, and they really are
    /// different bytes. Without this leg a build that dropped the ext on encode
    /// would make "the valued query is unsized" and "the bare query is zero"
    /// both true of the same record.
    #[test]
    fn the_fixture_puts_a_valued_query_and_a_bare_one_on_the_wire() {
        let valued = request_query_valued(1, sender_space(0, Some("demo/q")), Some(b"payload"));
        let bare = request_query_valued(1, sender_space(0, Some("demo/q")), None);
        assert_ne!(valued, bare, "the value ext must reach the wire");
        assert!(valued.len() > bare.len());
        let t = aggregate_datagrams(&[(true, valued)]);
        assert_eq!(t.records(), 1, "the valued query decodes as one record");
        assert_eq!(t.walked_records(), 1);
    }

    /// §1.1w. A query's value rides its ext chain, and R311y637 could see THAT
    /// it was there without seeing HOW BIG it was, so it reported the record as
    /// carrying an unmeasurable payload. R311y640 measures it: the ext body is
    /// `encoding` then the payload as `[u8;z32]`, so the number was on the wire
    /// the whole time, one sub-decode in.
    ///
    /// THREE legs, because the axis is three-valued and each state has to be
    /// reachable. A valued query is MEASURED. A bare query keeps its zero AS A
    /// MEASUREMENT — had the fix been "every query is known now", nothing would
    /// tell that zero from the one below. And a query whose body this reader
    /// cannot resolve stays UNMEASURABLE, which is the state R311y637 added and
    /// this round must not delete.
    #[test]
    fn a_querys_value_is_measured_and_an_unresolvable_body_still_is_not() {
        let valued = aggregate_datagrams(&[(
            true,
            request_query_valued(1, sender_space(0, Some("demo/q")), Some(b"payload")),
        )]);
        assert_eq!(
            valued.unsized_payloads(),
            0,
            "the payload's own length prefix is inside the ext"
        );
        assert_eq!(
            valued.total_payload_bytes(),
            b"payload".len() as u64,
            "and it is the application bytes, not the ext body"
        );
        let row = valued.row("demo/q").expect("the query has a row");
        assert!(row.totals().payload_is_complete());

        // THE LEG THAT SEPARATES A DECODE FROM A GUESS. The encoding here is
        // several bytes wide, so a reader that skipped a fixed width would read
        // the length prefix out of the middle of the schema name.
        let schema_valued = aggregate_datagrams(&[(
            true,
            request_query_valued_with_schema(3, sender_space(0, Some("demo/q")), b"payload"),
        )]);
        assert_eq!(schema_valued.unsized_payloads(), 0);
        assert_eq!(
            schema_valued.total_payload_bytes(),
            b"payload".len() as u64,
            "the encoding prefix is walked, not assumed to be one byte"
        );

        let truncated = aggregate_datagrams(&[(
            true,
            request_query_truncated(2, sender_space(0, Some("demo/q"))),
        )]);
        assert_eq!(
            truncated.unsized_payloads(),
            1,
            "a body claiming more bytes than follow it is not measured from its claim"
        );
        assert_eq!(truncated.total_payload_bytes(), 0);
        assert!(!truncated
            .row("demo/q")
            .expect("row")
            .totals()
            .payload_is_complete());

        let bare = aggregate_datagrams(&[(
            true,
            request_query_valued(2, sender_space(0, Some("demo/q")), None),
        )]);
        assert_eq!(
            bare.unsized_payloads(),
            0,
            "a query with no value carries nothing, and that is measured"
        );
        assert!(bare
            .row("demo/q")
            .expect("row")
            .totals()
            .payload_is_complete());
    }

    /// The consequence for a selector, across all three states of the axis.
    ///
    /// `bytes > 0` over a query carrying seven bytes now decides YES. It said
    /// `no` before R311y637 (a confident wrong answer) and `undecided` after it
    /// (an honest one this reader no longer has to give). The undecided state
    /// stays reachable through a body this reader genuinely cannot resolve, and
    /// the bare query is still decidably `no` — so each of the three is
    /// produced by a different record rather than asserted about the same one.
    #[test]
    fn a_bytes_term_decides_a_measured_query_and_declines_an_unresolvable_one() {
        let filter = Filter::parse("bytes > 0").expect("parses");
        let truncated = {
            let mut d = Dissection::new();
            let wire = crate::datagram_tests::frame_carrying(&request_query_truncated(
                9,
                sender_space(0, Some("demo/q")),
            ));
            d.push_packet(
                LINKTYPE_ETHERNET,
                0,
                &udp_packet(LOW, 43210, HIGH, 7447, &wire),
            );
            aggregate_where(&d, &filter).selection()
        };
        assert_eq!(
            truncated,
            Selection {
                matched: 0,
                rejected: 0,
                undecided: 1
            },
            "a body this reader cannot resolve is still real and unmeasured"
        );

        let valued = {
            let mut d = Dissection::new();
            let wire = crate::datagram_tests::frame_carrying(&request_query_valued(
                1,
                sender_space(0, Some("demo/q")),
                Some(b"payload"),
            ));
            d.push_packet(
                LINKTYPE_ETHERNET,
                0,
                &udp_packet(LOW, 43210, HIGH, 7447, &wire),
            );
            aggregate_where(&d, &filter).selection()
        };
        assert_eq!(
            valued,
            Selection {
                matched: 1,
                rejected: 0,
                undecided: 0
            },
            "seven bytes, and the wire said so"
        );

        let bare = {
            let mut d = Dissection::new();
            let wire = crate::datagram_tests::frame_carrying(&request_query_valued(
                2,
                sender_space(0, Some("demo/q")),
                None,
            ));
            d.push_packet(
                LINKTYPE_ETHERNET,
                0,
                &udp_packet(LOW, 43210, HIGH, 7447, &wire),
            );
            aggregate_where(&d, &filter).selection()
        };
        assert_eq!(bare.rejected, 1, "no value really is no bytes");
        assert!(bare.is_decisive());

        let put = aggregate_where(
            &{
                let mut d = Dissection::new();
                let wire = crate::datagram_tests::frame_carrying(&push(
                    sender_space(0, Some("demo/q")),
                    b"payload",
                ));
                d.push_packet(
                    LINKTYPE_ETHERNET,
                    0,
                    &udp_packet(LOW, 43210, HIGH, 7447, &wire),
                );
                d
            },
            &filter,
        )
        .selection();
        assert_eq!(put.matched, 1, "a sized payload still decides");
        assert!(put.is_decisive());
    }

    /// R311y639 (§4.30) — which body ext, if any, a fixture hangs on its
    /// carrier.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum BodyExt {
        /// No chain at all.
        None,
        /// `zextunit!(0x2, true)` — the SHM marker. The payload slot is a
        /// DESCRIPTOR and the data never crossed the network.
        ShmMarker,
        /// A ZBUF at the SAME 4-bit id with NO mandatory bit: a DIFFERENT
        /// extension that an id-only matcher would read as the marker above.
        /// The discriminator, in the R311y505 direction that silences a
        /// payload this crate could have measured.
        ForeignAtTheSameId,
    }

    impl BodyExt {
        fn entry(self) -> Option<wz_codecs::ext_entry::ExtEntry<'static>> {
            use wz_codecs::ext_entry::{ExtEntry, ExtEntryVariant};
            use wz_session_core::ext_header::{body_ext_id, EXT_ENC_ZBUF, EXT_FLAG_M};
            match self {
                BodyExt::None => None,
                BodyExt::ShmMarker => Some(ExtEntry {
                    header: body_ext_id::SHM | EXT_FLAG_M,
                    body: ExtEntryVariant::CodecZenohExtUnit(
                        wz_codecs::ext_unit::ExtUnit::default(),
                    ),
                }),
                BodyExt::ForeignAtTheSameId => Some(ExtEntry {
                    header: body_ext_id::SHM | EXT_ENC_ZBUF,
                    body: ExtEntryVariant::CodecZenohExtZbuf(wz_codecs::ext_zbuf::ExtZbuf {
                        value_len: 1,
                        value: &[0xAB],
                    }),
                }),
            }
        }
    }

    /// R311y639 (§4.30) — which of the four `classify` arms that hold a sizable
    /// slot is carrying it.
    ///
    /// One fixture across all four, because the defect was not in any one of
    /// them: each wrote its own `payload_bytes = <field>.len()` and each was
    /// equally unable to say "unknown". A per-carrier fixture would have let
    /// three of them stay wrong while the fourth was fixed.
    #[derive(Clone, Copy)]
    pub(crate) enum Carrier {
        Push,
        Request,
        Reply,
        Err,
    }

    /// A record carrying `payload` under `keyexpr`, in `carrier`, with `ext` on
    /// its zenoh-body chain.
    pub(crate) fn record_with_body_ext(
        carrier: Carrier,
        keyexpr: &'static str,
        payload: &'static [u8],
        ext: BodyExt,
    ) -> Vec<u8> {
        use wz_codecs::wire_const::{FLAG_N_N, FLAG_Z_ERR_Z, FLAG_Z_PUT_Z};
        let entry = ext.entry();
        let z_put = if entry.is_some() { FLAG_Z_PUT_Z } else { 0 };
        let put = wz_codecs::msg_put::MsgPut {
            header: wz_codecs::msg_put::MsgPut::default().header | z_put,
            extensions: entry.clone().map(|e| core::iter::once(e).collect()),
            payload_len: payload.len() as u64,
            payload,
            ..Default::default()
        };
        let kexpr = sender_space(0, Some(keyexpr));
        match carrier {
            Carrier::Push => wz_codecs::push::Push {
                header: wz_codecs::push::Push::default().header | FLAG_N_N,
                keyexpr: kexpr,
                body: wz_codecs::push::PushVariant::CodecZenohMsgPut(put),
                ..Default::default()
            }
            .encode_to_vec(),
            Carrier::Request => wz_codecs::request::Request {
                header: wz_codecs::request::Request::default().header | FLAG_N_N,
                rid: 11,
                keyexpr: kexpr,
                body: wz_codecs::request::RequestVariant::CodecZenohMsgPut(put),
                ..Default::default()
            }
            .encode_to_vec(),
            Carrier::Reply => wz_codecs::response::Response {
                header: wz_codecs::response::Response::default().header | FLAG_N_N,
                request_id: 11,
                keyexpr: kexpr,
                body: wz_codecs::response::ResponseVariant::CodecZenohReply(
                    wz_codecs::reply::Reply {
                        body: wz_codecs::reply::ReplyVariant::CodecZenohMsgPut(put),
                        ..Default::default()
                    },
                ),
                ..Default::default()
            }
            .encode_to_vec(),
            // The ERR carrier does NOT wrap a Put: it declares `encoding` and
            // `payload` as its own fields, and its own shm ext beside them.
            Carrier::Err => {
                let z_err = if entry.is_some() { FLAG_Z_ERR_Z } else { 0 };
                wz_codecs::response::Response {
                    header: wz_codecs::response::Response::default().header | FLAG_N_N,
                    request_id: 11,
                    keyexpr: kexpr,
                    body: wz_codecs::response::ResponseVariant::CodecZenohErr(
                        wz_codecs::err::Err {
                            header: wz_codecs::err::Err::default().header | z_err,
                            extensions: entry.map(|e| core::iter::once(e).collect()),
                            payload_len: payload.len() as u64,
                            payload,
                            ..Default::default()
                        },
                    ),
                    ..Default::default()
                }
                .encode_to_vec()
            }
        }
    }

    const CARRIERS: [(Carrier, &str); 4] = [
        (Carrier::Push, "push"),
        (Carrier::Request, "request"),
        (Carrier::Reply, "reply"),
        (Carrier::Err, "err"),
    ];

    /// ANTI-VACUITY for everything below. Each carrier really does put three
    /// DIFFERENT byte strings on the wire, and each really decodes as one
    /// record this plane attributes to the keyexpr.
    ///
    /// Without this leg an encoder that dropped the ext chain would make "the
    /// descriptor is unsized" and "the plain payload is measured" both true of
    /// one identical record, and a carrier whose ext broke the decode outright
    /// would look like a carrier that simply reported no bytes.
    #[test]
    fn each_carrier_puts_three_distinct_records_on_the_wire() {
        for (carrier, name) in CARRIERS {
            let shm = record_with_body_ext(carrier, "demo/shm", b"descriptor", BodyExt::ShmMarker);
            let foreign = record_with_body_ext(
                carrier,
                "demo/shm",
                b"descriptor",
                BodyExt::ForeignAtTheSameId,
            );
            let plain = record_with_body_ext(carrier, "demo/shm", b"descriptor", BodyExt::None);
            assert_ne!(shm, foreign, "{name}: the two exts must differ on the wire");
            assert_ne!(shm, plain, "{name}: the marker must reach the wire");
            for (bytes, which) in [(&shm, "shm"), (&foreign, "foreign"), (&plain, "plain")] {
                let t = aggregate_datagrams(&[(true, bytes.clone())]);
                assert_eq!(t.records(), 1, "{name}/{which}: one record");
                assert!(
                    t.row("demo/shm").is_some(),
                    "{name}/{which}: attributed to the keyexpr"
                );
            }
        }
    }

    /// §4.30, THE DEFECT, on all four carriers that hold a sizable slot.
    ///
    /// The SHM marker means the payload slot holds a DESCRIPTOR and the
    /// application's bytes never traversed the network at all
    /// (`zenoh-protocol-1.5.0/src/zenoh/put.rs:71-75`, `err.rs:49-68` —
    /// `zextunit!(0x2, true)`). This plane was reporting that slot's length as
    /// an application byte total: a confident number for a quantity no length
    /// on this wire holds. The [`crate::payload`] plane had refused to judge
    /// the same bytes since R311y622, so the two planes were answering one
    /// question two ways.
    ///
    /// The control leg is the whole test. A record with NO marker keeps its
    /// number and keeps it as a MEASUREMENT; had the fix been "a Put with any
    /// ext chain is unknown", this leg would fail.
    #[test]
    fn a_descriptor_slot_is_unsized_on_every_carrier_and_a_plain_one_is_measured() {
        for (carrier, name) in CARRIERS {
            let shm = aggregate_datagrams(&[(
                true,
                record_with_body_ext(carrier, "demo/shm", b"descriptor", BodyExt::ShmMarker),
            )]);
            assert_eq!(
                shm.unsized_payloads(),
                1,
                "{name}: the slot is a descriptor"
            );
            assert_eq!(
                shm.total_payload_bytes(),
                0,
                "{name}: a floor, and `unsized_payloads` is what says so"
            );
            assert!(!shm
                .row("demo/shm")
                .expect("row")
                .totals()
                .payload_is_complete());

            let plain = aggregate_datagrams(&[(
                true,
                record_with_body_ext(carrier, "demo/shm", b"descriptor", BodyExt::None),
            )]);
            assert_eq!(
                plain.unsized_payloads(),
                0,
                "{name}: no marker, so the bytes are the bytes"
            );
            assert_eq!(plain.total_payload_bytes(), b"descriptor".len() as u64);
            assert!(plain
                .row("demo/shm")
                .expect("row")
                .totals()
                .payload_is_complete());
        }
    }

    /// R311y646 (§4.28 / §4.34) — THE DEFECT: "unmeasured" was two facts under
    /// one name, and one of them has a number.
    ///
    /// An SHM descriptor and an unresolvable `Query` body both landed in
    /// `unsized_payloads`, and a reader could not tell them apart although what
    /// they should do about each is opposite. The descriptor's application bytes
    /// went through shared memory and are NOT IN THIS FILE at any resolution —
    /// a better decoder recovers nothing. The query's bytes are here, inside the
    /// ext, merely unseparated from the encoding ahead of them — and the ext's
    /// own extent bounds them, so the capture can state a ceiling.
    ///
    /// Both fixtures report ONE unsized payload, which is what makes them
    /// indistinguishable before the split and what this test pins first.
    #[test]
    fn an_absent_payload_and_an_unseparated_one_are_different_facts() {
        let shm = aggregate_datagrams(&[(
            true,
            record_with_body_ext(Carrier::Push, "demo/shm", b"descriptor", BodyExt::ShmMarker),
        )]);
        let unresolved = aggregate_datagrams(&[(
            true,
            request_query_truncated(2, sender_space(0, Some("demo/q"))),
        )]);

        // ANTI-VACUITY, and the shape of the old answer: the count both reports
        // is the same count.
        assert_eq!(shm.unsized_payloads(), 1);
        assert_eq!(unresolved.unsized_payloads(), 1);

        assert_eq!(
            shm.unmeasured_payloads(),
            UnmeasuredPayloads {
                elsewhere: 1,
                unresolved: 0,
                at_most_bytes: 0
            },
            "a descriptor's slot bounds NOTHING about the application's bytes"
        );
        assert_eq!(
            shm.payload_bytes_ceiling(),
            0,
            "so the ceiling is the floor: this capture says nothing about them"
        );

        let u = unresolved.unmeasured_payloads();
        assert_eq!((u.elsewhere, u.unresolved), (0, 1));
        // THE BOUND IS READ OFF THE WIRE, not invented: the fixture's ext body
        // is a one-byte encoding, a length prefix claiming 99, and three bytes
        // behind it. Three is what is present, and three is the ceiling.
        assert_eq!(
            u.at_most_bytes, 3,
            "the bytes behind the prefix, not the 99 the prefix claims"
        );
        assert_eq!(unresolved.total_payload_bytes(), 0, "the floor");
        assert_eq!(unresolved.payload_bytes_ceiling(), 3);

        // AND THE BOUND IS NOT A MEASUREMENT. `bytes == 3` would select this
        // record if the ceiling had been folded into the total; the axis is
        // still undecidable for it.
        let selected = aggregate_datagrams_where(
            &[(
                true,
                request_query_truncated(2, sender_space(0, Some("demo/q"))),
            )],
            "bytes == 3",
        );
        assert_eq!(
            selected.selection(),
            Selection {
                matched: 0,
                rejected: 0,
                undecided: 1
            },
            "a ceiling that answered a `bytes` term would be a measurement"
        );

        // THE CONTROL: a capture with nothing unmeasured reports the empty
        // census, and its ceiling IS its floor.
        let plain = aggregate_datagrams(&[(
            true,
            record_with_body_ext(Carrier::Push, "demo/plain", b"descriptor", BodyExt::None),
        )]);
        assert!(plain.unmeasured_payloads().is_empty());
        assert_eq!(
            plain.payload_bytes_ceiling(),
            plain.total_payload_bytes(),
            "a whole answer has no gap between its two ends"
        );
        assert_eq!(plain.total_payload_bytes(), b"descriptor".len() as u64);
    }

    /// THE DISCRIMINATOR. A body ext sharing the marker's 4-BIT ID FIELD and
    /// differing in its encoding bits is a DIFFERENT extension, and its record's
    /// payload is ordinary data this plane can measure.
    ///
    /// Matching on the id column alone would silence it — the R311y505 defect
    /// aimed the other way, and the leg that reds if this crate ever reaches for
    /// `ext_id` where it means `ext_eid`.
    #[test]
    fn a_body_ext_sharing_the_markers_id_field_leaves_the_payload_measured() {
        for (carrier, name) in CARRIERS {
            let foreign = aggregate_datagrams(&[(
                true,
                record_with_body_ext(
                    carrier,
                    "demo/shm",
                    b"descriptor",
                    BodyExt::ForeignAtTheSameId,
                ),
            )]);
            assert_eq!(
                foreign.unsized_payloads(),
                0,
                "{name}: a ZBUF at 0x2 with no mandatory bit is not the marker"
            );
            assert_eq!(
                foreign.total_payload_bytes(),
                b"descriptor".len() as u64,
                "{name}: and its payload is measurable data"
            );
        }
    }

    /// The consequence for a selector, and the leg that names the failure this
    /// axis ends: `bytes == 10` is the number the plane USED to report for a
    /// descriptor slot ten bytes long — a reader asking for records of exactly
    /// that size got the descriptor back as though it were the data.
    ///
    /// It is now UNDECIDED, not `no`: the record's payload is real and its size
    /// is not on this wire. Both controls matter — the same term over the
    /// foreign-ext record decides `yes`, and over a record whose slot really is
    /// a different length decides `no`, so the unknown is scoped to the record
    /// whose size is genuinely unavailable rather than smeared over the plane.
    #[test]
    fn a_bytes_term_over_a_descriptor_slot_is_undecided_rather_than_its_length() {
        let one = |record: Vec<u8>, selector: &str| {
            let mut d = Dissection::new();
            let wire = crate::datagram_tests::frame_carrying(&record);
            d.push_packet(
                LINKTYPE_ETHERNET,
                0,
                &udp_packet(LOW, 43210, HIGH, 7447, &wire),
            );
            let filter = Filter::parse(selector).expect("parses");
            aggregate_where(&d, &filter).selection()
        };
        for (carrier, name) in CARRIERS {
            assert_eq!(
                one(
                    record_with_body_ext(carrier, "demo/shm", b"descriptor", BodyExt::ShmMarker),
                    "bytes == 10"
                ),
                Selection {
                    matched: 0,
                    rejected: 0,
                    undecided: 1
                },
                "{name}: the descriptor's own length is not the payload's"
            );
            assert_eq!(
                one(
                    record_with_body_ext(
                        carrier,
                        "demo/shm",
                        b"descriptor",
                        BodyExt::ForeignAtTheSameId
                    ),
                    "bytes == 10"
                )
                .matched,
                1,
                "{name}: ten real bytes still decide yes"
            );
            assert_eq!(
                one(
                    record_with_body_ext(carrier, "demo/shm", b"short", BodyExt::None),
                    "bytes == 10"
                )
                .rejected,
                1,
                "{name}: five real bytes still decide no"
            );
        }
    }

    /// R311y638 (§1.1r) — the capture origin is the EARLIEST instant over every
    /// packet, not the first one handed in and not the first that decoded.
    ///
    /// Both properties are driven, and each has a failure the other would not
    /// catch: an out-of-order earlier packet must move the origin BACK, and a
    /// packet this reader cannot decapsulate at all must still count as part of
    /// the capture's timeline.
    #[test]
    fn the_capture_origin_is_the_earliest_instant_over_every_packet() {
        let record = push(sender_space(0, Some("demo/a")), b"x");
        let wire = crate::datagram_tests::frame_carrying(&record);
        let pkt = udp_packet(LOW, 43210, HIGH, 7447, &wire);

        let mut d = Dissection::new();
        assert_eq!(d.capture_origin_ms(), None, "an empty capture has no start");
        d.push_packet_at(LINKTYPE_ETHERNET, 0, Some(5_000), &pkt);
        d.push_packet_at(LINKTYPE_ETHERNET, 1, Some(5_200), &pkt);
        assert_eq!(d.capture_origin_ms(), Some(5_000));

        // Out of order, which pcapng produces across interfaces: the origin
        // moves BACK. A "first one handed in" origin would leave it at 5000 and
        // one capture would answer `elapsed` two ways depending on read order.
        d.push_packet_at(LINKTYPE_ETHERNET, 2, Some(4_900), &pkt);
        assert_eq!(d.capture_origin_ms(), Some(4_900));

        // A packet that decodes to NOTHING still started the clock. The control
        // is that it really is undecodable: it lands in `skipped`.
        let mut only_garbage = Dissection::new();
        only_garbage.push_packet_at(LINKTYPE_ETHERNET, 0, Some(1_000), &[0u8; 6]);
        assert_eq!(only_garbage.capture_origin_ms(), Some(1_000));
        assert_eq!(only_garbage.skipped().len(), 1, "the control: undecodable");
        assert!(only_garbage.datagram_flows().is_empty());
    }

    /// §1.1r, the point of the axis: `elapsed` is a window a person can type,
    /// and it selects the same records an absolute `time` window would — while
    /// `time` written with the SAME NUMBERS selects nothing.
    #[test]
    fn an_elapsed_window_selects_what_an_absolute_one_would_and_time_does_not() {
        use crate::exchange::tests as fx;
        // Three puts at 0ms, 100ms and 9000ms into a capture that begins at a
        // realistic epoch instant.
        const T0: u64 = 1_700_000_000_000;
        let d = fx::dissect(&[
            (
                true,
                Some(T0),
                push(sender_space(0, Some("demo/early")), b"a"),
            ),
            (
                true,
                Some(T0 + 100),
                push(sender_space(0, Some("demo/soon")), b"b"),
            ),
            (
                true,
                Some(T0 + 9_000),
                push(sender_space(0, Some("demo/late")), b"c"),
            ),
        ]);
        assert_eq!(d.capture_origin_ms(), Some(T0));

        let relative = aggregate_where(&d, &Filter::parse("elapsed < 5000").expect("parses"));
        let mut named: Vec<&str> = relative.rows().iter().map(|r| r.keyexpr.as_str()).collect();
        named.sort_unstable();
        assert_eq!(named, ["demo/early", "demo/soon"]);
        assert!(relative.selection().is_decisive());

        // The absolute window with the same shape picks the same two, which is
        // what makes `elapsed` a spelling of a real question rather than a new
        // one.
        let absolute = aggregate_where(
            &d,
            &Filter::parse(&alloc::format!("time < {}", T0 + 5_000)).expect("parses"),
        );
        assert_eq!(absolute.rows().len(), 2);

        // And the failure `elapsed` exists to end: the same NUMBERS read as an
        // absolute clock select nothing at all, silently.
        let naive = aggregate_where(&d, &Filter::parse("time < 5000").expect("parses"));
        assert_eq!(naive.rows().len(), 0);
        assert_eq!(naive.selection().rejected, 3);
    }

    /// A caller folding flows by hand never said where the capture began, so
    /// the axis is UNDECIDABLE there rather than counted from a guessed zero.
    ///
    /// The control is the same frames through the whole-capture entry point,
    /// which decides them — so this is the plane declining, not the term
    /// failing.
    #[test]
    fn a_hand_folded_plane_cannot_decide_an_elapsed_term() {
        use crate::exchange::tests as fx;
        const T0: u64 = 1_700_000_000_000;
        let d = fx::dissect(&[(
            true,
            Some(T0 + 10),
            push(sender_space(0, Some("demo/a")), b"a"),
        )]);
        let filter = Filter::parse("elapsed < 5000").expect("parses");

        let mut by_hand = ThroughputTable::new();
        for flow in d.datagram_flows() {
            by_hand.observe_flow_where(&flow.frames, &filter);
        }
        assert_eq!(by_hand.selection().undecided, 1);
        assert_eq!(by_hand.rows().len(), 0);

        let whole = aggregate_where(&d, &filter);
        assert_eq!(whole.selection().matched, 1, "the control");
        assert!(whole.selection().is_decisive());
    }

    /// Push a list of `(from_low, record)` through a real dissection, one
    /// datagram per record, and aggregate the result.
    ///
    /// Deliberately the whole pipeline — packet bytes in, table out. A test
    /// that handed `observe_flow_where` a `Vec<PassiveFrame>` it built itself would
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

    /// R311y614 (§1.4i) — a batch whose walk STOPPED is reported, not silently
    /// short.
    ///
    /// The fixture puts a good Push in front of a network MID no build
    /// dispatches, which is exactly the shape R311y613 measured on the whole
    /// data plane: the walk keeps what decoded, absorbs the rest verbatim and
    /// halts. The Push must still land in its row — a gap is not a reason to
    /// discard what WAS read — and the shortfall must be visible.
    #[test]
    fn a_halted_batch_is_reported_rather_than_quietly_short() {
        // `0x01` is outside the network MID space (0x19..=0x1F), so
        // `decode_one_record` cannot name it and the walk halts on it.
        let mut record = push(sender_space(0, Some("seen/before/the/halt")), &[0u8; 9]);
        let tail = [0x01u8, 0xAA, 0xBB, 0xCC];
        record.extend_from_slice(&tail);
        let table = aggregate_datagrams(&[(true, record)]);

        let row = table
            .row("seen/before/the/halt")
            .expect("what decoded before the halt is still attributed");
        assert_eq!(row.totals().payload_bytes, 9);

        let gaps = table.gaps();
        assert!(!gaps.is_clean(), "the shortfall must be visible at all");
        assert_eq!(gaps.halted_batches, 1);
        assert_eq!(
            gaps.unparsed_bytes,
            tail.len(),
            "the bytes the walk never read, measured off the halt offset"
        );
        assert_eq!(gaps.undecompressible_batches, 0);
        assert_eq!(gaps.unresolvable_fragments, 0);
    }

    /// R311y641 (§1.1n) — THE AXIS. A record's byte offset within its framing
    /// unit reaches the selector, and the SECOND message of a batch carries a
    /// non-zero one.
    ///
    /// The failure this ends: R311y631 taught this crate to walk a unit to its
    /// end, and everything it walked past the front could be told apart only by
    /// an ORDINAL (`batch_index`). A reader holding a record and the packet it
    /// came from still could not point at the bytes, so a finding could name a
    /// keyexpr and never a location. The walk had the number the whole time and
    /// threw it away.
    ///
    /// Driven through the production entry point on real packet bytes, so a
    /// build whose walk never produced a second record would fail the first
    /// assertion rather than quietly agree with the rest.
    ///
    /// R311y645 (§4.37) — the two literals moved and the test got STRONGER, not
    /// weaker. It used to expect the first record at `offset == 0` because the
    /// number was measured from the front of the `Frame`'s PAYLOAD, and this
    /// fixture puts that payload at unit offset 2. Both records are now placed
    /// against the front of the unit, so the assertion says where in the
    /// datagram the bytes are — which is what the term's name always claimed.
    #[test]
    fn a_records_offset_in_its_unit_reaches_the_selector() {
        // Two self-delimiting Pushes in ONE datagram: exactly the batch shape
        // both reference implementations emit and R311y631 taught this reader
        // to walk.
        let first = push(sender_space(0, Some("batch/first")), &[0u8; 4]);
        let second = push(sender_space(0, Some("batch/second")), &[0u8; 4]);
        let boundary = first.len();
        let mut unit = first;
        unit.extend_from_slice(&second);
        // What `aggregate_datagrams` wraps the batch in — read off the helper
        // rather than written as a literal, so a change to the envelope moves
        // this test's expectations with it instead of reddening it.
        let payload_at = crate::datagram_tests::frame_carrying(&[]).len();

        let all = aggregate_datagrams(&[(true, unit.clone())]);
        assert_eq!(all.records(), 2, "the walk must reach the second message");

        // ANTI-VACUITY: the boundary is a real number this test did not invent,
        // and the second message really does begin past the front.
        assert!(boundary > 0);
        assert!(payload_at > 0, "the frame's own header is ahead of them");

        let at_front = aggregate_datagrams_where(&[(true, unit.clone())], "offset == 0");
        assert_eq!(
            at_front.selection(),
            Selection {
                matched: 0,
                rejected: 2,
                undecided: 0
            },
            "byte 0 of the unit is the Frame's header, so NO record begins there"
        );

        let first_at = aggregate_datagrams_where(
            &[(true, unit.clone())],
            &alloc::format!("offset == {payload_at}"),
        );
        assert_eq!(first_at.selection().matched, 1);
        assert!(first_at.row("batch/first").is_some());
        assert!(
            first_at.row("batch/second").is_none(),
            "the second message does not begin where the first does"
        );

        // THE DECISIVE LEG: the offset is the message's own BOUNDARY, not an
        // ordinal wearing a byte's name. `offset == 1` would hold for a field
        // that merely counted messages, and it selects nothing.
        let ordinal = aggregate_datagrams_where(&[(true, unit.clone())], "offset == 1");
        assert_eq!(
            ordinal.selection().matched,
            0,
            "an ordinal would have matched here; a byte offset does not"
        );
        let exact = aggregate_datagrams_where(
            &[(true, unit)],
            &alloc::format!("offset == {}", payload_at + boundary),
        );
        assert_eq!(exact.selection().matched, 1);
        assert!(
            exact.row("batch/second").is_some(),
            "and it is the message that begins there"
        );
    }

    /// R311y642 (§1.1t) — THE DEFECT. A topic split across a key per entity is
    /// invisible to a ranking of literal keys, however heavy it is in total.
    ///
    /// The fixture is the ordinary zenoh idiom `**` exists for: four small keys
    /// under one prefix, and one unrelated key that is individually the biggest
    /// thing in the capture. The flat ranking therefore names the WRONG topic —
    /// not by a bug, but because it is answering "which key" when the reader
    /// asked "which part of the key space". Both numbers are asserted, so the
    /// test says what the two views disagree about rather than only that a tree
    /// exists.
    #[test]
    fn a_topic_split_across_keys_is_invisible_to_the_flat_ranking() {
        let mut records = alloc::vec::Vec::new();
        for i in 0..4u8 {
            let key: &'static str = match i {
                0 => "robot/1/pose",
                1 => "robot/2/pose",
                2 => "robot/3/pose",
                _ => "robot/4/pose",
            };
            records.push((true, push(sender_space(0, Some(key)), &[0u8; 10])));
        }
        records.push((true, push(sender_space(0, Some("logs")), &[0u8; 25])));
        let t = aggregate_datagrams(&records);

        // THE FLAT VIEW, asserted rather than assumed: the heaviest single key
        // is the unrelated one, and every `robot` key is below it.
        assert_eq!(
            t.rows().first().expect("rows").keyexpr,
            "logs",
            "the flat ranking's answer"
        );
        assert_eq!(
            t.row("robot/1/pose").expect("row").totals().payload_bytes,
            10
        );

        // THE HIERARCHY. `robot` carries 40 bytes over four keys, which no row
        // reports and no ordering of rows can surface.
        let tree = t.subtrees();
        let heavy = tree.heaviest_shared().expect("a shared prefix exists");
        assert_eq!(heavy.prefix, "robot");
        assert_eq!(heavy.totals.payload_bytes, 40);
        assert_eq!(heavy.rows, 4, "four literal keys fold into it");
        assert!(
            heavy.totals.payload_bytes > t.rows()[0].totals().payload_bytes,
            "the subtree outweighs the key the flat ranking names"
        );

        // THE ROOT IS THE WHOLE CAPTURE, so a consumer walking down never has to
        // special-case "no common prefix".
        assert_eq!(tree.totals.payload_bytes, 65);
        assert_eq!(tree.rows, 5);

        // A NODE STANDING FOR ONE KEY IS NOT A FINDING: `robot/1` holds exactly
        // one literal key and `heaviest_shared` must not name it, or the answer
        // would be a row the reader already had.
        assert!(
            tree.children.iter().any(|c| c.prefix == "robot"),
            "the prefix node exists"
        );
        let inner = tree
            .children
            .iter()
            .find(|c| c.prefix == "robot")
            .expect("robot node")
            .children
            .iter()
            .find(|c| c.prefix == "robot/1")
            .expect("robot/1 node");
        assert_eq!(inner.rows, 1);
    }

    /// R311y644 (§1.1p) — THE ONE-WAY AXIS. A record stamped at its source and
    /// seen here yields publisher-to-observer time, which no round-trip figure
    /// can be decomposed into.
    ///
    /// THE DECISIVE LEG IS THE THIRD STATE. A source stamp LATER than the
    /// arrival is not a delay of zero and not a negative one: it proves the two
    /// machines' clocks are offset, so the axis declines AND the capture says
    /// why. Clamping it to zero would have made an unsynchronised deployment
    /// report perfect delivery.
    #[test]
    fn a_stamped_record_yields_a_one_way_delay_and_an_ahead_clock_declines() {
        let seen_at = 1_700_000_005_000u64;

        // Stamped 250 ms before this observer saw it.
        let late = aggregate_datagrams_at(&[(
            true,
            Some(seen_at),
            push_stamped(sender_space(0, Some("demo/p")), b"x", seen_at - 250),
        )]);
        assert_eq!(late.source_ahead_of_observer(), 0);
        let picked = aggregate_datagrams_at_where(
            &[(
                true,
                Some(seen_at),
                push_stamped(sender_space(0, Some("demo/p")), b"x", seen_at - 250),
            )],
            "delay == 250",
        );
        assert_eq!(
            picked.selection(),
            Selection {
                matched: 1,
                rejected: 0,
                undecided: 0
            },
            "the axis is the difference between the two clocks' readings"
        );

        // THE CONTROL: an UNSTAMPED record cannot answer the term at all, and
        // that is Unknown rather than a delay of zero.
        let unstamped = aggregate_datagrams_at_where(
            &[(
                true,
                Some(seen_at),
                push(sender_space(0, Some("demo/p")), b"x"),
            )],
            "delay == 0",
        );
        assert_eq!(
            unstamped.selection(),
            Selection {
                matched: 0,
                rejected: 0,
                undecided: 1
            },
            "no source clock is not a delay of zero"
        );

        // THE DECISIVE LEG: the source's clock runs 500 ms AHEAD.
        let ahead_records = alloc::vec![(
            true,
            Some(seen_at),
            push_stamped(sender_space(0, Some("demo/p")), b"x", seen_at + 500),
        )];
        let ahead = aggregate_datagrams_at(&ahead_records);
        assert_eq!(
            ahead.source_ahead_of_observer(),
            1,
            "the offset is WITNESSED, not swallowed"
        );
        let ahead_sel = aggregate_datagrams_at_where(&ahead_records, "delay >= 0");
        assert_eq!(
            ahead_sel.selection().undecided,
            1,
            "and the axis declines rather than reporting a delay of zero"
        );
    }

    /// THE CONTROL for the test above: a FLAT key space has no shared prefix to
    /// report, and must say nothing rather than dress its own root up as one.
    ///
    /// Without this leg a `heaviest_shared` that always answered `Some(root)`
    /// would satisfy every assertion above.
    #[test]
    fn a_flat_key_space_names_no_subtree() {
        let t = aggregate_datagrams(&[
            (true, push(sender_space(0, Some("alpha")), &[0u8; 4])),
            (true, push(sender_space(0, Some("beta")), &[0u8; 4])),
        ]);
        let tree = t.subtrees();
        assert_eq!(tree.rows, 2, "both keys are in the tree");
        assert!(
            tree.heaviest_shared().is_none(),
            "two unrelated keys share no prefix worth reporting"
        );
    }

    /// THE CONTROL for the test above: an intact capture reports NO gap.
    ///
    /// Without it a `gaps()` that counted every batch would satisfy the
    /// assertions there and be useless — the same reason every recovery arm in
    /// this crate carries a control.
    #[test]
    fn an_intact_capture_reports_no_gap_at_all() {
        let table = aggregate_datagrams(&[
            (true, declare_kexpr(1, "intact/topic")),
            (true, push(sender_space(1, None), &[0u8; 5])),
            (
                false,
                push(sender_space(0, Some("intact/other")), &[0u8; 5]),
            ),
        ]);
        assert!(
            table.gaps().is_clean(),
            "a capture with nothing wrong reported {:?}",
            table.gaps()
        );
        assert_eq!(table.total_payload_bytes(), 10);
    }

    /// R311y621 (§1.4i) — a capture this build cannot DECOMPRESS is counted,
    /// not reported as a capture with nothing in it.
    ///
    /// `wz-capture` does not carry `transport-compression`, so every frame of a
    /// compression-negotiated session is a body it cannot open. The rows are
    /// then EMPTY, and empty rows are the one shape that reads identically to a
    /// silent session — which is the failure this whole counter exists to
    /// refuse. `records() == 0` is asserted BESIDE the counter for exactly that
    /// reason: it is the state a reader would otherwise misread.
    ///
    /// One field on the page: the other three gap counters are pinned at zero,
    /// so a plane that incremented the wrong one fails here rather than
    /// satisfying the assertion by accident.
    #[test]
    fn a_batch_this_build_cannot_decompress_is_counted_rather_than_missing() {
        let table = aggregate(&crate::datagram_tests::compressed_session_dissection());

        let gaps = table.gaps();
        assert_eq!(gaps.undecompressible_batches, 1);
        assert_eq!(gaps.halted_batches, 0);
        assert_eq!(gaps.unparsed_bytes, 0);
        assert_eq!(gaps.unresolvable_fragments, 0);
        assert!(!gaps.is_clean(), "the shortfall must be visible at all");
        assert_eq!(
            table.records(),
            0,
            "no record was readable, which is why the counter has to say so"
        );
    }

    /// R311y621 (§1.4i) — a capture that STARTED MID-SESSION reports the
    /// fragments it could never resolve.
    ///
    /// The observer saw no InitAck, so it has no SN resolution and refuses to
    /// pick a mask (one too wide reads a wraparound as a gap, one too narrow the
    /// reverse). The chain never becomes a batch. What must not happen is the
    /// table staying CLEAN: a reader summing rows from a capture that began in
    /// the middle would otherwise be told the total is the whole of it.
    #[cfg(feature = "reassembly")]
    #[test]
    fn a_fragment_with_no_resolution_is_counted_rather_than_dropped() {
        let table = aggregate(&crate::datagram_tests::midsession_fragment_dissection());

        let gaps = table.gaps();
        assert_eq!(gaps.unresolvable_fragments, 1);
        assert_eq!(gaps.undecompressible_batches, 0);
        assert_eq!(gaps.halted_batches, 0);
        assert_eq!(gaps.unparsed_bytes, 0);
        assert!(!gaps.is_clean(), "the shortfall must be visible at all");
        assert_eq!(table.records(), 0);
    }

    /// R311y622 (§1.4h) — THE SECOND DENOMINATOR. A record this plane read and
    /// does not attribute is COUNTED, so `records()` stops being a numerator
    /// with nothing under it.
    ///
    /// The failure this refuses is not loss, it is proportion. A capture of 2
    /// attributed records among 3 control-plane ones and a capture of 2 among
    /// 2000 produce the SAME rows and the same totals, and a reader summing the
    /// table has no way to tell which they are looking at.
    ///
    /// `gaps().is_clean()` is asserted here and it is the other half of the
    /// claim: an unattributed record is not damage. It was read, named and
    /// understood, and it belongs in no row — so folding it into the loss
    /// counters would make `is_clean` false on every healthy capture and the
    /// gap surface would stop meaning anything.
    #[test]
    fn a_record_that_belongs_in_no_row_is_counted_rather_than_dropped() {
        let table = aggregate_datagrams(&[
            (true, push(sender_space(0, Some("real/traffic")), &[0u8; 8])),
            // Three records that carry no traffic under a keyexpr: a query's
            // closing marker, a control envelope, and a discovery request.
            (
                false,
                wz_codecs::response_final::ResponseFinal {
                    request_id: 1,
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            (true, wz_codecs::oam::Oam::default().encode_to_vec()),
            (
                true,
                wz_codecs::interest::Interest {
                    interest_id: 1,
                    body: None,
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
        ]);

        assert_eq!(table.records(), 1, "one record carried traffic");
        assert_eq!(
            table.unattributed_records(),
            3,
            "and three were read and belong in no row"
        );
        assert!(
            table.gaps().is_clean(),
            "none of that is LOSS: {:?}",
            table.gaps()
        );
        assert_eq!(table.total_payload_bytes(), 8);
    }

    /// THE ACCOUNTING INVARIANT the denominator rests on: every record the plane
    /// walked is in exactly one of its four counters.
    ///
    /// Without it `walked_records` is a fifth number a reader has to trust. The
    /// fixture carries one of each category on purpose — attributed traffic, a
    /// declaration, an undeclaration and a record that belongs in no row — so a
    /// sum that forgot a term cannot come out right by accident.
    #[test]
    fn the_parts_account_for_every_record_walked() {
        let table = aggregate_datagrams(&[
            (true, declare_kexpr(1, "accounted/topic")),
            (true, push(sender_space(1, None), &[0u8; 4])),
            (true, undeclare_kexpr(1)),
            (true, wz_codecs::oam::Oam::default().encode_to_vec()),
        ]);

        let (declared, undeclared) = table.declarations();
        assert_eq!((declared, undeclared), (1, 1));
        assert_eq!(table.records(), 1);
        assert_eq!(table.unattributed_records(), 1);
        assert_eq!(
            table.walked_records(),
            table.records() + table.unattributed_records() + declared + undeclared,
            "the whole must be its parts"
        );
        assert_eq!(table.walked_records(), 4, "and the parts must be the wire");
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

    /// Push a list through the whole pipeline under a selector — the same
    /// packets-in / table-out path [`aggregate_datagrams`] drives, with the
    /// production filtered entry point at the end of it.
    fn aggregate_datagrams_where(records: &[(bool, Vec<u8>)], selector: &str) -> ThroughputTable {
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
        let filter = crate::filter::Filter::parse(selector).expect("the selector must compile");
        aggregate_where(&d, &filter)
    }

    /// The same pipeline over RAW framing units — the bytes of a datagram
    /// exactly as given, with no `Frame` wrapped around them.
    ///
    /// [`aggregate_datagrams_where`] beside it wraps every record in its own
    /// `Frame` and so can only ever produce a unit whose first record sits at a
    /// fixed distance from the front. A unit carrying a transport message
    /// AHEAD of the frame is the shape that tells a payload coordinate apart
    /// from a unit coordinate, and no helper here could build one.
    fn dissect_units(units: &[(bool, Vec<u8>)]) -> Dissection {
        let mut d = Dissection::new();
        for (i, (from_low, unit)) in units.iter().enumerate() {
            let pkt = if *from_low {
                udp_packet(LOW, 43210, HIGH, 7447, unit)
            } else {
                udp_packet(HIGH, 7447, LOW, 43210, unit)
            };
            d.push_packet(LINKTYPE_ETHERNET, i, &pkt);
        }
        d
    }

    fn aggregate_units_where(units: &[(bool, Vec<u8>)], selector: &str) -> ThroughputTable {
        let d = dissect_units(units);
        let filter = crate::filter::Filter::parse(selector).expect("the selector must compile");
        aggregate_where(&d, &filter)
    }

    /// R311y645 (§4.26 / §4.37) — THE THREE PLANES PLACE ONE RECORD AT ONE
    /// BYTE.
    ///
    /// The `offset` term has been in the language since R311y641 and only the
    /// throughput plane ever drove it. The other two build their own
    /// [`RecordView`] and each wrote the coordinate by hand, so a plane left
    /// behind by a change to the composition would keep answering with the old
    /// number and nothing would say so — the failure R311y618 measured on the
    /// selector's three planes and R311y639 measured on `payload_bytes`.
    ///
    /// One record, one capture, one selector, three planes. The record sits
    /// behind a KeepAlive so the unit coordinate and the payload coordinate
    /// differ; a plane still measuring from the front of the `Frame`'s payload
    /// answers `no` here while the others answer `yes`.
    #[test]
    fn the_three_planes_place_one_record_at_one_byte() {
        use crate::exchange::tests as fx;

        // A `Request` carrying a Put: traffic under a keyexpr (the throughput
        // plane), a payload to inspect (the payload plane) and the opening of
        // an exchange (the exchange plane) all in ONE record, so the three
        // answers are about the same bytes rather than about three fixtures.
        let request = fx::request_put(7, fx::sender_space(0, Some("demo/topic")), b"{}");
        let mut unit = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        unit.extend_from_slice(&crate::datagram_tests::frame_carrying(&request));
        let front_of_record = unit.len() - request.len();
        assert!(
            front_of_record > 0,
            "ANTI-VACUITY: the record must not begin at the front of the unit"
        );

        let d = dissect_units(&[
            (true, unit),
            (
                false,
                crate::datagram_tests::frame_carrying(&fx::response_final(7)),
            ),
        ]);
        let at = crate::filter::Filter::parse(&alloc::format!("offset == {front_of_record}"))
            .expect("parses");
        // The coordinate a plane measuring from the payload would answer with.
        let payload_relative = crate::filter::Filter::parse("offset == 0").expect("parses");

        let throughput = aggregate_where(&d, &at);
        assert_eq!(throughput.selection().matched, 1);
        assert!(throughput.row("demo/topic").is_some());
        assert_eq!(
            aggregate_where(&d, &payload_relative).selection().matched,
            0
        );

        let payloads = crate::payload::payloads_where(&d, &at);
        assert_eq!(payloads.selection().matched, 1);
        assert_eq!(payloads.payloads(), 1);
        assert_eq!(
            crate::payload::payloads_where(&d, &payload_relative)
                .selection()
                .matched,
            0
        );

        let exchanges = crate::exchange::exchanges_where(&d, &at);
        assert_eq!(exchanges.selection().matched, 1);
        assert_eq!(exchanges.requests(), 1);
        assert_eq!(
            crate::exchange::exchanges_where(&d, &payload_relative)
                .selection()
                .matched,
            0
        );
    }

    /// R311y645 (§1.1n / §4.37) — THE DEFECT: `offset` says "within the
    /// framing unit" and measures "within this `Frame`'s payload".
    ///
    /// The two coincide for every fixture this crate had, because every one of
    /// them puts exactly one `Frame` at the front of its own datagram. They
    /// come apart the moment a unit carries a transport message ahead of the
    /// frame — the `[KeepAlive][Frame]` shape R311y631 taught this reader to
    /// walk, and the one both reference implementations emit.
    ///
    /// What the reader loses is not precision, it is the meaning of the answer:
    /// `offset == 0` reads as "at the front of the unit" and selects every
    /// record that is merely first inside its own frame, however deep into the
    /// unit that frame begins.
    #[test]
    fn a_records_offset_is_measured_from_the_front_of_the_unit() {
        let record = push(sender_space(0, Some("behind/keepalive")), &[0u8; 4]);
        let mut unit = alloc::vec![wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        unit.extend_from_slice(&crate::datagram_tests::frame_carrying(&record));

        // ANTI-VACUITY: the record really does begin past the front, and the
        // distance is read off the fixture rather than asserted as a literal.
        let front_of_record = unit.len() - record.len();
        assert_eq!(
            front_of_record, 3,
            "one KeepAlive byte, then the Frame's header and sn"
        );

        let at_front = aggregate_units_where(&[(true, unit.clone())], "offset == 0");
        assert_eq!(
            at_front.selection().matched,
            0,
            "byte 0 of this unit is the KeepAlive, and a KeepAlive is not a record"
        );

        let exact = aggregate_units_where(
            &[(true, unit)],
            &alloc::format!("offset == {front_of_record}"),
        );
        assert_eq!(exact.selection().matched, 1);
        assert!(
            exact.row("behind/keepalive").is_some(),
            "and it is the record that begins there"
        );
    }

    /// R311y645 (§4.38) — a record REASSEMBLED out of fragments has no offset
    /// into the capture, and the term says so instead of reporting where the
    /// reader's own join buffer put it.
    ///
    /// The record is real, it is counted, and its keyexpr resolves — this is not
    /// a capture the plane failed to read. What does not exist is the
    /// coordinate: its bytes arrived in two pieces at two unrelated places in
    /// two different datagrams, so there is no single offset any of them begins
    /// at. The old field answered `0` here, which is a byte a reader can point
    /// at in a packet that never carried this record.
    ///
    /// THE CONTROL is the same record through the ordinary path, which decides
    /// the same term. Without it a plane that had simply stopped answering
    /// `offset` at all would satisfy every assertion here.
    #[cfg(feature = "reassembly")]
    #[test]
    fn a_reassembled_record_declines_the_offset_it_never_had() {
        let record = push(sender_space(0, Some("split/across")), &[0u8; 8]);
        let d = crate::datagram_tests::reassembled_record_dissection(&record);

        // ANTI-VACUITY: the chain really did complete and the record really is
        // in the table. A capture whose fragments never joined would leave the
        // selector nothing to be undecided about.
        let all = aggregate(&d);
        assert_eq!(all.records(), 1, "the fragment chain must complete");
        assert!(all.row("split/across").is_some());
        assert!(
            all.gaps().is_clean(),
            "nothing was lost -- only the coordinate is absent: {:?}",
            all.gaps()
        );

        // Any offset term at all, in either direction, is UNDECIDABLE. Two
        // comparisons that cannot both be false, so a plane answering `no`
        // rather than `unknown` fails one of them.
        for selector in ["offset == 0", "offset >= 0"] {
            let filtered = aggregate_where(&d, &Filter::parse(selector).expect("parses"));
            assert_eq!(
                filtered.selection(),
                Selection {
                    matched: 0,
                    rejected: 0,
                    undecided: 1
                },
                "{selector}: a reassembled record has no offset into the capture"
            );
            assert_eq!(filtered.rows().len(), 0);
        }

        // THE CONTROL: the same record, contiguous on the wire, decides both.
        let control = aggregate_datagrams_where(&[(true, record)], "offset >= 0");
        assert_eq!(control.selection().matched, 1);
        assert!(control.selection().is_decisive());
    }

    /// The same pipeline, with the instant each record was CAPTURED at.
    ///
    /// Deliberately through [`Dissection::push_packet_at`] rather than through
    /// hand-built frames: the clock a `time` term reads is one the packet
    /// source supplies, and a test that stamped `PassiveFrame`s itself would
    /// prove nothing about whether the stamp survives the walk to the filter.
    ///
    /// `None` does NOT mean "this record has no time" — the observer's clock is
    /// sticky, so an unstamped packet behind a stamped one inherits the stamp
    /// (`passive.rs:984`). A capture that must reach the filter with no time at
    /// all is therefore unstamped THROUGHOUT.
    /// The same stamped pipeline, unfiltered.
    fn aggregate_datagrams_at(records: &[(bool, Option<u64>, Vec<u8>)]) -> ThroughputTable {
        let mut d = Dissection::new();
        for (i, (from_low, ts, record)) in records.iter().enumerate() {
            let wire = crate::datagram_tests::frame_carrying(record);
            let pkt = if *from_low {
                udp_packet(LOW, 43210, HIGH, 7447, &wire)
            } else {
                udp_packet(HIGH, 7447, LOW, 43210, &wire)
            };
            d.push_packet_at(LINKTYPE_ETHERNET, i, *ts, &pkt);
        }
        aggregate(&d)
    }

    fn aggregate_datagrams_at_where(
        records: &[(bool, Option<u64>, Vec<u8>)],
        selector: &str,
    ) -> ThroughputTable {
        let mut d = Dissection::new();
        for (i, (from_low, ts, record)) in records.iter().enumerate() {
            let wire = crate::datagram_tests::frame_carrying(record);
            let pkt = if *from_low {
                udp_packet(LOW, 43210, HIGH, 7447, &wire)
            } else {
                udp_packet(HIGH, 7447, LOW, 43210, &wire)
            };
            d.push_packet_at(LINKTYPE_ETHERNET, i, *ts, &pkt);
        }
        let filter = crate::filter::Filter::parse(selector).expect("the selector must compile");
        aggregate_where(&d, &filter)
    }

    /// R311y616 (§1.1f), the plane end to end: a selector narrows the table to
    /// the traffic it names, and the records it left out are COUNTED rather
    /// than merely absent.
    ///
    /// Driven through `aggregate_where` on real packets, not through
    /// `Filter::matches` on a hand-built view: the filter unit tests already
    /// prove the language, and what this proves is that the aggregation plane
    /// asks it about the records the wire actually produced.
    #[cfg(feature = "filter-wildcards")]
    #[test]
    fn a_selector_narrows_the_table_and_says_what_it_left_out() {
        let records = alloc::vec![
            (true, push(sender_space(0, Some("home/temp")), &[0u8; 10])),
            (true, push(sender_space(0, Some("home/light")), &[0u8; 20])),
            (true, push(sender_space(0, Some("office/temp")), &[0u8; 40])),
        ];

        let all = aggregate_datagrams_where(&records, "");
        assert_eq!(all.rows().len(), 3, "the unfiltered baseline");
        assert_eq!(all.total_payload_bytes(), 70);
        assert_eq!(
            all.selection(),
            crate::filter::Selection {
                matched: 3,
                rejected: 0,
                undecided: 0
            },
            "an identity filter rejects nothing and leaves nothing undecided"
        );

        let home = aggregate_datagrams_where(&records, "key == home/**");
        assert_eq!(home.rows().len(), 2);
        assert_eq!(home.total_payload_bytes(), 30);
        assert_eq!(home.records(), 2, "records() counts the SELECTED records");
        assert!(home.row("office/temp").is_none(), "excluded");
        assert_eq!(
            home.selection(),
            crate::filter::Selection {
                matched: 2,
                rejected: 1,
                undecided: 0
            }
        );
        assert!(home.selection().is_decisive());

        // A second axis, to show the language reaches past the keyexpr: the
        // heavy records only.
        let heavy = aggregate_datagrams_where(&records, "bytes > 15");
        assert_eq!(heavy.rows().len(), 2);
        assert_eq!(heavy.total_payload_bytes(), 60);
        assert_eq!(heavy.selection().rejected, 1);
    }

    /// THE RULE, through the real pipeline: a record whose keyexpr this capture
    /// never bound is UNDECIDED under a `key` selector — not silently dropped,
    /// and not counted as a rejection either.
    ///
    /// The capture is the one a tap started mid-session produces: a reference
    /// to alias 4 whose `DeclKexpr` went past before the observer arrived.
    #[test]
    fn a_reference_the_capture_never_bound_is_undecided_rather_than_dropped() {
        let table = aggregate_datagrams_where(
            &[
                (true, declare_kexpr(1, "known/topic")),
                (true, push(sender_space(1, None), &[0u8; 10])),
                // Never declared: the capture began after its DeclKexpr.
                (true, push(sender_space(4, None), &[0u8; 99])),
            ],
            "key == known/topic",
        );

        assert_eq!(table.rows().len(), 1);
        assert_eq!(table.total_payload_bytes(), 10);
        let selection = table.selection();
        assert_eq!(selection.matched, 1);
        assert_eq!(
            selection.rejected, 0,
            "it was never judged, so never rejected"
        );
        assert_eq!(selection.undecided, 1);
        assert!(
            !selection.is_decisive(),
            "the reader must be able to see that the filter could not judge everything"
        );

        // And the undecided record is in NO other total either: it is not an
        // unresolved row of the selection, because the selection never took it.
        assert_eq!(table.records(), 1);
        assert_eq!(table.unresolved_records(), 0);
    }

    /// A DECLARE is absorbed whatever the filter says. Without this the filter
    /// would break the resolution the records it ACCEPTS depend on — a
    /// selector for `aliased/topic` would find nothing, because the declaration
    /// that binds the alias does not itself match by any wire keyexpr the
    /// filter can see.
    #[test]
    fn a_declaration_is_absorbed_even_when_the_selector_would_not_pick_it() {
        let table = aggregate_datagrams_where(
            &[
                (true, declare_kexpr(1, "aliased/topic")),
                (true, push(sender_space(1, None), &[0u8; 7])),
            ],
            "key == aliased/topic",
        );
        assert_eq!(
            table.row("aliased/topic").map(|r| r.totals().payload_bytes),
            Some(7),
            "the alias resolved, so the declaration was absorbed under the filter"
        );
        assert_eq!(table.declarations(), (1, 0), "and it was counted");
    }

    /// A gap belongs to the CAPTURE, not to the selection: a halted batch is
    /// traffic nobody could read, so no selector can have an opinion about it
    /// and it must stay visible however narrow the filter is.
    #[test]
    fn a_filter_cannot_hide_a_gap() {
        let mut truncated = push(sender_space(0, Some("gap/topic")), &[0u8; 40]);
        truncated.truncate(truncated.len() - 20);
        let table = aggregate_datagrams_where(
            &[
                (true, push(sender_space(0, Some("kept/topic")), &[0u8; 4])),
                (true, truncated),
            ],
            "key == kept/topic",
        );
        assert_eq!(table.rows().len(), 1, "the selector did narrow");
        assert!(
            table.gaps().halted_batches > 0,
            "the unreadable batch is still reported: {:?}",
            table.gaps()
        );
    }

    // R311y620 (§1.4k) — the fields a selector can name, each DRIVEN FROM THE
    // WIRE on this plane and each on its own page.
    //
    // The four below share one rule and it is why they are four tests and not
    // one: a page carrying several terms at once is satisfied by any of them,
    // so it gates none of them. R311y618 measured exactly that — a leg of
    // `is_complete` was deleted and 229 tests still passed — and the remedy is
    // to put ONE field on the stage at a time.
    //
    // They also do not restate the filter language: `filter.rs` already proves
    // what `kind == del` means against a hand-built `RecordView`. What is
    // unproven until here is that THIS plane hands the language a view built
    // out of the bytes that actually went past.

    /// A `kind` term, against a capture carrying both kinds on one keyexpr.
    ///
    /// One keyexpr deliberately: with the two kinds on different topics a
    /// narrowing by `kind` and a narrowing by `key` produce the same rows, and
    /// the test could not say which one the plane performed.
    #[test]
    fn the_throughput_view_answers_a_kind_term_off_the_wire() {
        let records = alloc::vec![
            (true, push(sender_space(0, Some("mixed/topic")), &[0u8; 30])),
            (true, push_del(sender_space(0, Some("mixed/topic")))),
        ];

        let dels = aggregate_datagrams_where(&records, "kind == del");
        let row = dels
            .row("mixed/topic")
            .expect("the Del is still attributed");
        assert_eq!(row.totals().dels, 1);
        assert_eq!(row.totals().puts, 0, "the Put was not admitted");
        assert_eq!(
            dels.total_payload_bytes(),
            0,
            "and its 30 bytes came with it"
        );
        assert_eq!(dels.selection().rejected, 1);

        // The complementary term, so a view that answered `Del` to everything
        // cannot satisfy the assertions above.
        let puts = aggregate_datagrams_where(&records, "kind == put");
        assert_eq!(
            puts.row("mixed/topic").expect("attributed").totals().puts,
            1
        );
        assert_eq!(puts.total_payload_bytes(), 30);
        assert_eq!(puts.selection().rejected, 1);
    }

    /// A `dir` term, against traffic on ONE keyexpr flowing both ways.
    ///
    /// The per-direction split is what makes this checkable without a second
    /// field: the surviving row must carry its bytes in the arm the term named
    /// and nothing in the other.
    #[test]
    fn the_throughput_view_answers_a_direction_term_off_the_wire() {
        let records = alloc::vec![
            (true, push(sender_space(0, Some("both/ways")), &[0u8; 11])),
            (false, push(sender_space(0, Some("both/ways")), &[0u8; 22])),
        ];

        let from_b = aggregate_datagrams_where(&records, "dir == b");
        let row = from_b.row("both/ways").expect("B's record survived");
        assert_eq!(row.per_direction[1].payload_bytes, 22, "B->A kept");
        assert_eq!(row.per_direction[0].payload_bytes, 0, "A->B dropped");
        assert_eq!(from_b.selection().rejected, 1);

        let from_a = aggregate_datagrams_where(&records, "dir == a");
        let row = from_a.row("both/ways").expect("A's record survived");
        assert_eq!(row.per_direction[0].payload_bytes, 11);
        assert_eq!(row.per_direction[1].payload_bytes, 0);
    }

    /// A `time` term, against a capture whose packets carry capture instants.
    ///
    /// The payload sizes are 1 / 2 / 4 so the surviving TOTAL names the
    /// surviving SUBSET uniquely — with three equal payloads a total of two
    /// records would not say WHICH two, and an off-by-one in the comparison
    /// would read as a pass.
    #[test]
    fn the_throughput_view_answers_a_time_term_off_the_wire() {
        let records = alloc::vec![
            (
                true,
                Some(1_000),
                push(sender_space(0, Some("clocked/topic")), &[0u8; 1])
            ),
            (
                true,
                Some(2_000),
                push(sender_space(0, Some("clocked/topic")), &[0u8; 2])
            ),
            (
                true,
                Some(3_000),
                push(sender_space(0, Some("clocked/topic")), &[0u8; 4])
            ),
        ];

        let late = aggregate_datagrams_at_where(&records, "time >= 2000");
        assert_eq!(late.total_payload_bytes(), 6, "the 2 and the 4, not the 1");
        assert_eq!(late.selection().matched, 2);
        assert_eq!(late.selection().rejected, 1);
        assert_eq!(
            late.selection().undecided,
            0,
            "the capture carried the fact"
        );

        let early = aggregate_datagrams_at_where(&records, "time < 2000");
        assert_eq!(early.total_payload_bytes(), 1, "and only the 1");
    }

    /// A capture with NO clock leaves a `time` term undecided — not false.
    ///
    /// This is the arm that keeps the one above from being free. A plane that
    /// substituted a plausible instant (the flow's `now_ms`, which is `0` until
    /// something advances it) would answer `time > 0` with a confident `No` for
    /// every record, and the reader would read "no traffic after time zero"
    /// off a capture that simply never said when anything happened.
    #[test]
    fn an_unclocked_capture_leaves_a_time_term_undecided() {
        let records = alloc::vec![
            (
                true,
                None,
                push(sender_space(0, Some("dark/topic")), &[0u8; 5])
            ),
            (
                true,
                None,
                push(sender_space(0, Some("dark/topic")), &[0u8; 6])
            ),
        ];

        // ANTI-VACUITY: the fixture does produce records, so an empty answer
        // below is the filter's doing and not the fixture's.
        let all = aggregate_datagrams_at_where(&records, "");
        assert_eq!(all.records(), 2);
        assert_eq!(all.total_payload_bytes(), 11);

        let asked = aggregate_datagrams_at_where(&records, "time > 0");
        assert_eq!(
            asked.selection(),
            crate::filter::Selection {
                matched: 0,
                rejected: 0,
                undecided: 2
            },
            "a question the capture cannot answer is not a No"
        );
        assert!(!asked.selection().is_decisive());
        assert_eq!(asked.rows().len(), 0, "and no row was invented");
    }

    /// R311y714 (§1.1f, [REDACTED-REQ]) — the topic shares are of the capture, and
    /// they add up.
    ///
    /// The occupancy half of [REDACTED-REQ] at the TOPIC axis, and the assertion that
    /// keeps it honest is the SUM: two keyexprs carrying all the traffic must
    /// account for all of it, less the truncation each share loses. A share
    /// computed against a per-row denominator would give every row 100% and
    /// pass any single-row test.
    ///
    /// R311y715 (§C G6) — and the fixture carries a THIRD record whose payload
    /// this build can only bound, because without one the two candidate
    /// denominators are the same number. `total_payload_bytes` is the sized
    /// floor and `payload_bytes_ceiling` adds what is merely unseparated; the
    /// doc above `share_bp` argues at length for the floor, and swapping the
    /// call to the ceiling left all 391 tests green. Three unresolved bytes is
    /// all it takes to make the argument a measurement.
    #[test]
    fn topic_shares_are_of_the_whole_and_sum_to_it() {
        let table = aggregate_datagrams(&[
            (true, push(sender_space(0, Some("home/temp")), &[0u8; 30])),
            (true, push(sender_space(0, Some("home/light")), &[0u8; 10])),
            (
                true,
                request_query_truncated(2, sender_space(0, Some("home/ask"))),
            ),
        ]);
        // ANTI-VACUITY: the two denominators must actually DIFFER here, or the
        // assertions below hold for either and pin neither.
        assert_eq!(table.total_payload_bytes(), 40, "the denominator");
        assert_eq!(
            table.payload_bytes_ceiling(),
            43,
            "and the ceiling this share is deliberately NOT taken against"
        );
        let shares: Vec<u32> = table
            .rows()
            .iter()
            .map(|r| {
                table
                    .share_bp(&r.keyexpr)
                    .expect("a sized capture has a total")
            })
            .collect();
        assert_eq!(
            shares,
            alloc::vec![7_500, 2_500, 0],
            "30 and 10 of 40, and the bounded record sizes nothing"
        );
        let sum: u32 = shares.iter().sum();
        assert!(
            (9_998..=10_000).contains(&sum),
            "the topics are the whole capture, less truncation: {shares:?}"
        );
    }

    /// R311y720 (§D M4) — THE COST OF THE THREE WALKS, MEASURED.
    ///
    /// # Why this exists and why it is `#[ignore]`d
    ///
    /// The register has carried M4 since R311y660 in this shape: "three planes
    /// walk the same frames three times -- cost UNMEASURED, so whether it is
    /// debt at all has to be measured first". Four rounds restated it and none
    /// measured it, because the harness was the missing piece: the planes are
    /// cheap per frame, so the answer only appears at a capture size no unit
    /// fixture has.
    ///
    /// So this is the harness. It builds a capture of `MESSAGES` records,
    /// times the dissection that reads it, then times each plane over the
    /// result, and prints the numbers. A wall-clock assertion would be flaky on
    /// a shared runner and would gate the wrong thing -- what the round needs is
    /// a NUMBER for the ledger, not a threshold. Run it with
    /// `cargo test -p wz-capture -- --ignored --nocapture m4_`.
    ///
    /// What the number decides: if the four plane walks together cost a small
    /// fraction of the parse that produced the frames, fusing them into one
    /// walk buys nothing and M4 is not debt. If they dominate, it is.
    #[test]
    #[ignore = "a measurement harness, not a gate: run with --ignored --nocapture"]
    fn m4_the_cost_of_walking_the_same_frames_four_times() {
        use std::time::Instant;

        const MESSAGES: usize = 20_000;
        // Enough distinct keyexprs that the plane's tables do real work rather
        // than folding everything onto one row -- a single-key capture would
        // measure a hash lookup, not the plane.
        const KEYS: [&str; 8] = [
            "home/temp",
            "home/light",
            "home/door",
            "car/speed",
            "car/rpm",
            "plant/line/1",
            "plant/line/2",
            "plant/line/3",
        ];

        let packets: alloc::vec::Vec<alloc::vec::Vec<u8>> = (0..MESSAGES)
            .map(|i| {
                let record = push(sender_space(0, Some(KEYS[i % KEYS.len()])), &[0u8; 32]);
                let wire = crate::datagram_tests::frame_carrying(&record);
                if i % 2 == 0 {
                    udp_packet(LOW, 43210, HIGH, 7447, &wire)
                } else {
                    udp_packet(HIGH, 7447, LOW, 43210, &wire)
                }
            })
            .collect();

        let start = Instant::now();
        let mut d = Dissection::new();
        for (i, pkt) in packets.iter().enumerate() {
            d.push_packet(LINKTYPE_ETHERNET, i, pkt);
        }
        let parse = start.elapsed();
        let decoded = d.decoded_messages();
        assert!(
            decoded >= MESSAGES,
            "the fixture must actually decode, or this measures nothing: {decoded}"
        );

        let start = Instant::now();
        let throughput = aggregate(&d);
        let t_throughput = start.elapsed();

        let start = Instant::now();
        let exchanges = crate::exchange::exchanges(&d);
        let t_exchanges = start.elapsed();

        let start = Instant::now();
        let payloads = crate::payload::payloads(&d);
        let t_payloads = start.elapsed();

        let start = Instant::now();
        let nodes = crate::node::nodes(&d);
        let t_nodes = start.elapsed();

        // THE NUMBER THE DECISION ACTUALLY TURNS ON, and it is measured rather
        // than argued: fusing four walks into one removes the ITERATION, never
        // the per-record work each plane does inside it. So iteration is timed
        // on its own -- a traversal of every frame list that touches each frame
        // and computes nothing.
        let start = Instant::now();
        let mut seen = 0usize;
        for _ in 0..4 {
            for flow in d.datagram_flows() {
                for frames in flow.frame_lists() {
                    for frame in frames {
                        seen += frame.stream_offset & 1;
                    }
                }
            }
        }
        let t_iteration = start.elapsed();
        core::hint::black_box(seen);

        let planes = t_throughput + t_exchanges + t_payloads + t_nodes;
        std::println!(
            "M4 over {decoded} decoded message(s):\n  \
             parse      {parse:?}\n  \
             throughput {t_throughput:?}  ({} row(s))\n  \
             exchanges  {t_exchanges:?}  ({} row(s))\n  \
             payloads   {t_payloads:?}\n  \
             nodes      {t_nodes:?}  ({} node(s))\n  \
             ---------- planes {planes:?} = {:.1}% of parse\n  \
             4x bare iteration {t_iteration:?} = {:.1}% of the plane time \
             (this is ALL that fusing the walks could save)",
            throughput.rows().len(),
            exchanges.rows().len(),
            nodes.nodes().len(),
            planes.as_secs_f64() / parse.as_secs_f64() * 100.0,
            t_iteration.as_secs_f64() / planes.as_secs_f64() * 100.0,
        );
        // The only ASSERTION is the one that keeps the print honest: a plane
        // that produced nothing measured nothing.
        assert!(
            !throughput.rows().is_empty() && payloads.payloads() > 0,
            "a plane with no rows measured an empty walk"
        );
    }
}
