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
    gaps: ThroughputGaps,
    selection: Selection,
}

/// R311y614 (§1.4i) — traffic this table could not read AT ALL, as opposed to
/// traffic it read and could not attribute ([`ThroughputTable::unresolved`]).
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

    /// Fold one flow's frames in, in capture order, resolving against id spaces
    /// private to this flow.
    pub fn observe_flow(&mut self, frames: &[PassiveFrame]) {
        self.observe_flow_where(frames, &Filter::any())
    }

    /// R311y616 (§1.1f) — the same fold, over the records a selector picks.
    ///
    /// ONE fold rather than a filtered copy beside the unfiltered one:
    /// [`Self::observe_flow`] passes [`Filter::any`], which is the identity, so
    /// the filtered and unfiltered paths cannot drift apart.
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
        for message in &batch.messages {
            self.observe_message(spaces, frame, anchor, message, filter);
        }
    }

    fn observe_message(
        &mut self,
        spaces: &mut KeyexprSpaces,
        frame: &PassiveFrame,
        anchor: usize,
        message: &NetworkMessage,
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
            return;
        };
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
            payload_bytes: counts.payload_bytes,
            observed_at_ms: frame.observed_at_ms,
        };
        let truth = filter.matches(&view);
        self.selection.record(truth);
        if truth != Truth::Yes {
            return;
        }

        self.records += 1;
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
    ///
    /// Under a filter this counts the SELECTED records: the ones in the rows.
    /// [`Self::selection`] holds the rest.
    pub fn records(&self) -> usize {
        self.records
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

    /// Application bytes across every resolved keyexpr.
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
                    counts.payload_bytes = put.payload.as_slice().len() as u64;
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
                    counts.payload_bytes = put.payload.as_slice().len() as u64;
                    RecordKind::Put
                }
                RequestOwnedVariant::CodecZenohMsgDel(_) => {
                    counts.dels = 1;
                    RecordKind::Del
                }
                RequestOwnedVariant::CodecZenohQuery(_) | RequestOwnedVariant::Default { .. } => {
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
                        counts.payload_bytes = put.payload.as_slice().len() as u64;
                    }
                    RecordKind::Reply
                }
                ResponseOwnedVariant::CodecZenohErr(err) => {
                    counts.errs = 1;
                    counts.payload_bytes = err.payload.as_slice().len() as u64;
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
    for flow in dissection.flows() {
        table.observe_flow_where(&flow.frames, filter);
    }
    for flow in dissection.datagram_flows() {
        table.observe_flow_where(&flow.frames, filter);
    }
    table
}

// R311y614 — the whole module is gated, on the same rule the `Fragment` census
// entry follows for `reassembly`: these tests assert what a build WITH the
// network codecs does, and a build without them cannot be asked. Gating the
// module rather than each test keeps the two from drifting.
#[cfg(all(test, feature = "network-codecs"))]
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
    ///
    /// R311y616 (§4.10) — and the `N` bit is now
    /// [`FLAG_N_N`](wz_codecs::wire_const::FLAG_N_N) rather than the number
    /// `0x20`, which is the other half of the same rule: a fixture that spells
    /// a flag as a literal is a byte string wearing a struct.
    fn push(keyexpr: Wireexpr<'static>, payload: &[u8]) -> Vec<u8> {
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
            body: wz_codecs::push::PushVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
                payload_len: payload.len() as u64,
                payload,
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
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
}
