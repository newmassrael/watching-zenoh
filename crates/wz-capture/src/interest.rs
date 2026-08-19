// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y869 (§1.1f) — the capture read as DECLARED INTEREST: who asked for
//! what, and whether the traffic in the capture is anything anybody asked for.
//!
//! # The question no other plane here can answer
//!
//! Every plane before this one folds RECORDS. [`crate::agg`] says which keyexpr
//! carried the bytes, [`crate::exchange`] pairs a query with its replies,
//! [`crate::node`] says which zids were talking. All four answer "what
//! happened". None of them can answer **"who wanted it"** — and on a pub/sub
//! bus that is the question a reader opens a capture with, because a publisher
//! shouting into a keyexpr no subscriber declared is a live deployment silently
//! doing nothing.
//!
//! zenoh puts the answer on the wire. A `DeclareSubscriber`, a
//! `DeclareQueryable` and a `DeclareToken` each name a keyexpr the declarer
//! wants, and this reader decoded all three the whole time and **threw them
//! away**: `KeyexprSpaces::absorb` matched `DeclKexpr` / `UndeclKexpr` and
//! ended in `_ => {}`, so six of the nine `Declare` arms left the fold in
//! silence. The declarations were in the capture, in the decode, and in no
//! output.
//!
//! # An interest is a PATTERN, which is why this plane needs a matcher
//!
//! A row in [`crate::agg`] is a literal keyexpr. A declaration usually is not:
//! `robot/**` is the ordinary zenoh idiom, and relating it to the `robot/1/pose`
//! a publisher actually used is keyexpr matching, not string equality. Doing
//! that by prefix would be a second, worse notion of "part of a key" beside the
//! one [`crate::filter`] already uses.
//!
//! So the join runs through [`wz_session_core::keyexpr_match`] — the SAME
//! matcher a wz router uses to decide where a sample goes. An analyzer's
//! "this subscriber covers that traffic" and a node's routing decision are then
//! one implementation, and cannot drift into disagreeing about a capture of the
//! node's own traffic.
//!
//! # A pattern this build cannot evaluate is UNDECIDABLE, never zero
//!
//! `filter-wildcards` is switchable, and with it off `**` stops being a
//! wildcard and becomes a chunk to compare literally. [`crate::filter`] turns
//! that into a PARSE REFUSAL because a selector a person typed must not quietly
//! mean something else. This plane cannot refuse — the declaration is on the
//! wire whether or not this build can read it — so it does the other half of
//! the same rule: such a declaration lands in
//! [`Coverage::undecidable`](crate::interest::Coverage::undecidable) and never
//! in [`Coverage::silent`](crate::interest::Coverage::silent). "Nobody
//! subscribed to this" and "this build cannot tell" are different findings and
//! only one of them is actionable.
//!
//! The same rule governs
//! [`Coverage::unclaimed`](crate::interest::Coverage::unclaimed): it is a floor
//! whenever any declaration was undecidable or unresolved, and
//! [`Coverage::unclaimed_exact`](crate::interest::Coverage::unclaimed_exact) is
//! how a reader learns which it is holding.
//!
//! (The paths are absolute because this module's `//!` block is merged with the
//! `///` on its `pub mod` declaration in `lib.rs`, and rustdoc then resolves
//! bare names in the CRATE ROOT's scope rather than in this module's — the same
//! reason every other plane's header here writes `crate::` paths.)
//!
//! # Withdrawals stay in the census
//!
//! An `UndeclareSubscriber` closes an interest; it does not erase that the
//! interest existed. A live registry would drop the row, and an observer must
//! not: "a subscriber was there for the first half of this capture" is the
//! finding, and a plane that reported only the surviving declarations would
//! describe the capture's last instant as though it were the whole of it.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use wz_session_core::network_message::NetworkMessage;
use wz_session_core::passive::{Carried, Direction, PassiveFrame};

use crate::agg::{KeyexprCounts, KeyexprSpaces, ThroughputTable};
use crate::link::FlowKey;

/// What a declaration asks for.
///
/// Three kinds and not one flag, because they are three different reasons to
/// want a keyexpr and a reader acts on them differently: a subscriber wants
/// samples PUSHED to it, a queryable offers to ANSWER queries on it, and a
/// liveliness token asserts that something EXISTS at it. A census that folded
/// them could not tell a topic nobody listens to from one nobody can query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InterestKind {
    /// `DeclareSubscriber` — samples pushed under a matching keyexpr are wanted.
    Subscriber,
    /// `DeclareQueryable` — queries under a matching keyexpr will be answered.
    Queryable,
    /// `DeclareToken` — a liveliness token asserted at this keyexpr.
    LivelinessToken,
}

impl InterestKind {
    /// The word both renderings print, so the text and the JSON cannot disagree
    /// about what a row is.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Subscriber => "subscriber",
            Self::Queryable => "queryable",
            Self::LivelinessToken => "liveliness_token",
        }
    }
}

/// One declaration this capture saw, and what became of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredInterest {
    /// Which of the three it is.
    pub kind: InterestKind,
    /// The side that DECLARED it — not the direction anything travelled in
    /// afterwards. A subscriber declared by A is A wanting traffic FROM B.
    pub declarer: Direction,
    /// The declaration id, in the declarer's own entity space. Meaningless
    /// without [`Self::flow`]: two sessions' id `3` are unrelated.
    pub id: u64,
    /// The keyexpr, resolved against the id spaces as they stood when the
    /// declaration went past. `None` when it named an alias this capture never
    /// saw bound — see [`Self::unresolved`].
    pub keyexpr: Option<String>,
    /// The `(space, id)` the keyexpr aliased, when it did not resolve.
    ///
    /// Present exactly when [`Self::keyexpr`] is `None`, and carried rather
    /// than dropped because it is a real finding: a capture that began after
    /// the `DeclKexpr` has a subscriber it cannot name, which is different from
    /// having no subscriber.
    pub unresolved: Option<(Direction, u64)>,
    /// The flow it was declared on.
    pub flow: FlowKey,
    /// Capture anchor of the declaration — whatever
    /// [`PassiveFrame::stream_offset`] carries for that link, as everywhere
    /// else in this crate.
    pub declared_at: usize,
    /// Anchor of the matching `Undeclare`, when one went past.
    pub withdrawn_at: Option<usize>,
}

impl DeclaredInterest {
    /// `true` while the capture never saw this interest withdrawn.
    pub fn is_open(&self) -> bool {
        self.withdrawn_at.is_none()
    }
}

/// What one declaration turned out to cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterestMatch {
    /// Index into [`InterestCensus::interests`].
    pub interest: usize,
    /// The literal keyexprs from [`ThroughputTable::rows`] this declaration
    /// matches, in the table's own order so a reader moving between the two
    /// views does not have to hold two orderings in mind.
    pub keys: Vec<String>,
    /// Everything those keys carried, summed.
    pub totals: KeyexprCounts,
}

/// The join between what was DECLARED and what was CARRIED.
///
/// Four populations rather than two, and the split is the deliverable: the two
/// interesting findings are a declaration that matched nothing and traffic no
/// declaration matched, and neither is readable unless the cases this build
/// could not judge are held apart from them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Coverage {
    /// Declarations that matched at least one traffic key, heaviest first.
    pub matched: Vec<InterestMatch>,
    /// Declarations this build EVALUATED and that matched nothing.
    ///
    /// The finding: somebody asked for a keyexpr and this capture carried
    /// nothing under it.
    pub silent: Vec<usize>,
    /// Declarations whose pattern this build's matcher cannot evaluate
    /// (`filter-wildcards` off, pattern containing `*`).
    ///
    /// NOT in [`Self::silent`] — see the module doc.
    pub undecidable: Vec<usize>,
    /// Declarations whose own keyexpr never resolved, so there is no pattern to
    /// evaluate at all.
    pub unresolved: Vec<usize>,
    /// Traffic keyexprs no declaration in this capture matches.
    ///
    /// A FLOOR unless [`Self::unclaimed_exact`] — an undecidable or unresolved
    /// declaration might have covered any of them.
    pub unclaimed: Vec<String>,
    /// Whether [`Self::unclaimed`] is the whole answer rather than a floor.
    pub unclaimed_exact: bool,
}

impl Coverage {
    /// Declarations this capture could judge — the denominator [`Self::silent`]
    /// is a numerator over.
    ///
    /// A reader handed `silent = 0` cannot tell "everything was subscribed" from
    /// "nothing could be judged", and this is the number that separates them.
    pub fn judged(&self) -> usize {
        self.matched.len() + self.silent.len()
    }
}

/// Every declaration this capture carried.
#[derive(Debug, Clone, Default)]
pub struct InterestCensus {
    interests: Vec<DeclaredInterest>,
    orphan_withdrawals: usize,
}

impl InterestCensus {
    /// An empty census.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every declaration, in the order the capture carried them.
    pub fn interests(&self) -> &[DeclaredInterest] {
        &self.interests
    }

    /// `Undeclare`s naming an id this capture never saw declared.
    ///
    /// Not an error and not zero-by-construction: a capture that begins
    /// mid-session sees withdrawals of declarations that went past before the
    /// tap started, and counting them is how a reader learns the declaration
    /// list is a floor rather than assuming it whole.
    pub fn orphan_withdrawals(&self) -> usize {
        self.orphan_withdrawals
    }

    /// How many of each kind were declared, `[subscriber, queryable, token]`.
    pub fn by_kind(&self) -> [usize; 3] {
        let mut out = [0usize; 3];
        for i in &self.interests {
            out[match i.kind {
                InterestKind::Subscriber => 0,
                InterestKind::Queryable => 1,
                InterestKind::LivelinessToken => 2,
            }] += 1;
        }
        out
    }

    /// Fold ONE flow's declarations in, resolving keyexprs against that flow's
    /// own id spaces.
    ///
    /// Per FLOW and not per capture, for the reason [`ThroughputTable`] states:
    /// id spaces are per session, so one table across two flows would
    /// cross-resolve them.
    pub fn observe_flow(&mut self, flow: &FlowKey, frames: &[PassiveFrame]) {
        let mut spaces = KeyexprSpaces::new();
        // The OPEN declaration per `(declarer, kind, id)`, as an index into
        // `self.interests`. Keyed on the kind as well as the id because zenoh
        // mints subscriber, queryable and token ids in separate spaces, and a
        // key without it would let a queryable's withdrawal close a
        // subscriber's declaration that happened to share a number.
        let mut open: BTreeMap<(usize, InterestKind, u64), usize> = BTreeMap::new();
        for frame in frames {
            let anchor = frame.stream_offset;
            let batch = match &frame.carried {
                Carried::Batch(batch) => batch,
                #[cfg(feature = "reassembly")]
                Carried::Reassembled(batch) => batch,
                // Named individually rather than caught, on `agg`'s rule: a new
                // `Carried` variant must fail to compile here instead of
                // joining the silent set. None of these carries a batch, so
                // none can carry a declaration.
                Carried::Undecompressible => continue,
                #[cfg(feature = "reassembly")]
                Carried::FragmentWithoutResolution => continue,
                Carried::Nothing => continue,
                #[cfg(feature = "reassembly")]
                Carried::Fragment(_) => continue,
            };
            for (message, _span) in batch.records() {
                let NetworkMessage::Declare(d) = message else {
                    continue;
                };
                self.observe_declare(&mut spaces, &mut open, flow, frame.direction, anchor, d);
            }
        }
    }

    fn observe_declare(
        &mut self,
        spaces: &mut KeyexprSpaces,
        open: &mut BTreeMap<(usize, InterestKind, u64), usize>,
        flow: &FlowKey,
        direction: Direction,
        anchor: usize,
        declare: &wz_codecs::declare::DeclareOwned,
    ) {
        use wz_codecs::declare::DeclareOwnedVariant as V;
        let dir = match direction {
            Direction::A => 0usize,
            Direction::B => 1usize,
        };
        // RESOLVED BEFORE ABSORBED. A `DeclKexpr` arriving in the same batch
        // binds an id every LATER reference resolves through, and reading the
        // tables after absorbing this message would let a declaration resolve
        // through a binding that had not yet gone past when it did.
        match &declare.body {
            V::CodecZenohDeclSubscriber(d) => {
                let resolved = spaces.resolve(direction, &d.keyexpr.body);
                self.push(
                    InterestKind::Subscriber,
                    direction,
                    d.id,
                    resolved,
                    flow,
                    anchor,
                );
                open.insert(
                    (dir, InterestKind::Subscriber, d.id),
                    self.interests.len() - 1,
                );
            }
            V::CodecZenohDeclQueryable(d) => {
                let resolved = spaces.resolve(direction, &d.keyexpr.body);
                self.push(
                    InterestKind::Queryable,
                    direction,
                    d.id,
                    resolved,
                    flow,
                    anchor,
                );
                open.insert(
                    (dir, InterestKind::Queryable, d.id),
                    self.interests.len() - 1,
                );
            }
            V::CodecZenohDeclToken(d) => {
                let resolved = spaces.resolve(direction, &d.keyexpr.body);
                self.push(
                    InterestKind::LivelinessToken,
                    direction,
                    d.id,
                    resolved,
                    flow,
                    anchor,
                );
                open.insert(
                    (dir, InterestKind::LivelinessToken, d.id),
                    self.interests.len() - 1,
                );
            }
            V::CodecZenohUndeclSubscriber(u) => {
                self.withdraw(open, dir, InterestKind::Subscriber, u.id, anchor)
            }
            V::CodecZenohUndeclQueryable(u) => {
                self.withdraw(open, dir, InterestKind::Queryable, u.id, anchor)
            }
            V::CodecZenohUndeclToken(u) => {
                self.withdraw(open, dir, InterestKind::LivelinessToken, u.id, anchor)
            }
            // The keyexpr-alias arms are `spaces`' business, and `DeclFinal` /
            // an unknown tag declare no interest.
            V::CodecZenohDeclKexpr(_)
            | V::CodecZenohUndeclKexpr(_)
            | V::CodecZenohDeclFinal(_)
            | V::Default { .. } => {}
        }
        // The alias tables, through the one absorber, so this plane and the
        // throughput plane resolve a keyexpr identically or not at all.
        spaces.absorb(direction, declare);
    }

    fn push(
        &mut self,
        kind: InterestKind,
        declarer: Direction,
        id: u64,
        resolved: Result<String, (Direction, u64)>,
        flow: &FlowKey,
        anchor: usize,
    ) {
        let (keyexpr, unresolved) = match resolved {
            Ok(k) => (Some(k), None),
            Err(alias) => (None, Some(alias)),
        };
        self.interests.push(DeclaredInterest {
            kind,
            declarer,
            id,
            keyexpr,
            unresolved,
            flow: *flow,
            declared_at: anchor,
            withdrawn_at: None,
        });
    }

    fn withdraw(
        &mut self,
        open: &mut BTreeMap<(usize, InterestKind, u64), usize>,
        dir: usize,
        kind: InterestKind,
        id: u64,
        anchor: usize,
    ) {
        match open.remove(&(dir, kind, id)) {
            Some(at) => self.interests[at].withdrawn_at = Some(anchor),
            None => self.orphan_withdrawals += 1,
        }
    }

    /// Join this census against the traffic [`ThroughputTable`] measured.
    ///
    /// The two must come from the SAME dissection — a coverage computed against
    /// another capture's table would be a confident answer about the wrong
    /// question. [`interests`] and [`crate::agg::aggregate`] both walk
    /// `Dissection::message_lists`, so a caller that built each from one
    /// dissection has them aligned by construction.
    pub fn coverage(&self, table: &ThroughputTable) -> Coverage {
        // The table's rows ONCE, in its own order. Held as the rows themselves
        // rather than as their keys, so a match reads the totals it just
        // matched instead of looking the key up a second time — two lookups is
        // two chances for the totals and the key list to be about different
        // rows.
        let rows = table.rows();
        let mut out = Coverage {
            unclaimed_exact: true,
            ..Coverage::default()
        };
        // Which rows SOME decidable declaration covered. Sized to the rows so a
        // capture with no declarations still walks them once.
        let mut claimed = alloc::vec![false; rows.len()];
        for (at, interest) in self.interests.iter().enumerate() {
            let Some(pattern) = interest.keyexpr.as_deref() else {
                out.unresolved.push(at);
                out.unclaimed_exact = false;
                continue;
            };
            if !pattern_is_decidable(pattern) {
                out.undecidable.push(at);
                out.unclaimed_exact = false;
                continue;
            }
            let chunks: Vec<&str> = pattern.split('/').collect();
            let mut keys = Vec::new();
            let mut totals = KeyexprCounts::default();
            for (i, row) in rows.iter().enumerate() {
                if !wz_session_core::keyexpr_match::keyexpr_pattern_matches(&chunks, &row.keyexpr) {
                    continue;
                }
                claimed[i] = true;
                keys.push(row.keyexpr.clone());
                totals.add(&row.totals());
            }
            if keys.is_empty() {
                out.silent.push(at);
            } else {
                out.matched.push(InterestMatch {
                    interest: at,
                    keys,
                    totals,
                });
            }
        }
        out.matched.sort_by(|a, b| {
            b.totals
                .payload_bytes
                .cmp(&a.totals.payload_bytes)
                .then_with(|| b.totals.messages().cmp(&a.totals.messages()))
                .then_with(|| a.interest.cmp(&b.interest))
        });
        for (i, row) in rows.iter().enumerate() {
            if !claimed[i] {
                out.unclaimed.push(row.keyexpr.clone());
            }
        }
        out
    }
}

/// Whether this build's matcher can evaluate `pattern` at all.
///
/// The mirror of [`crate::filter`]'s `WildcardUnsupported` refusal, arriving
/// for a pattern nobody typed: without `filter-wildcards` a `*` is compared
/// literally, so a declaration carrying one would be judged against a rule it
/// does not mean. Saying "cannot tell" is the one answer that is never wrong.
fn pattern_is_decidable(pattern: &str) -> bool {
    #[cfg(feature = "filter-wildcards")]
    {
        let _ = pattern;
        true
    }
    #[cfg(not(feature = "filter-wildcards"))]
    {
        !pattern.contains('*')
    }
}

/// Every declaration in `dissection`, over every flow it holds.
///
/// Through `message_lists` rather than the two flow tables by name, on
/// R311y721's rule: a serial line's declarations are in neither table, and a
/// plane naming them would report a serial deployment as having declared
/// nothing.
pub fn interests(dissection: &crate::Dissection) -> InterestCensus {
    let mut census = InterestCensus::new();
    for (flow, frames) in dissection.message_lists() {
        census.observe_flow(&flow, frames);
    }
    census
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datagram_tests::{frame_carrying, push, sender_space, udp_packet};
    use crate::link::LINKTYPE_ETHERNET;
    use crate::Dissection;

    use wz_session_core::declare_build;

    /// The two endpoints, as [`crate::agg`]'s fixtures name them: `.1` sorts
    /// below `.2`, so `.1 -> .2` is [`Direction::A`].
    const LOW: [u8; 4] = [10, 0, 0, 1];
    const HIGH: [u8; 4] = [10, 0, 0, 2];

    /// Every declaration builder below is the PRODUCTION one
    /// (`wz_session_core::declare_build`), and that is the whole point of this
    /// helper existing rather than a hand-laid byte string beside it: a test
    /// that builds its own DECLARE proves this plane can read the test's idea
    /// of one. This workspace has paid for that seven times.
    fn wire(records: &[(bool, Vec<u8>)]) -> Dissection {
        let mut d = Dissection::new();
        for (i, (from_low, record)) in records.iter().enumerate() {
            let unit = frame_carrying(record);
            let pkt = if *from_low {
                udp_packet(LOW, 43210, HIGH, 7447, &unit)
            } else {
                udp_packet(HIGH, 7447, LOW, 43210, &unit)
            };
            d.push_packet(LINKTYPE_ETHERNET, i, &pkt);
        }
        d
    }

    fn declare_sub(id: u64, keyexpr: &str) -> Vec<u8> {
        declare_build::build_declare_subscriber(id, 0, Some(keyexpr))
            .expect("the production builder must build a subscriber")
            .try_as_borrowed()
            .expect("and it must re-borrow")
            .encode_to_vec()
    }

    fn declare_sub_aliased(id: u64, mapping: u64, suffix: Option<&str>) -> Vec<u8> {
        declare_build::build_declare_subscriber(id, mapping, suffix)
            .expect("the production builder must build a subscriber")
            .try_as_borrowed()
            .expect("and it must re-borrow")
            .encode_to_vec()
    }

    fn declare_qbl(id: u64, keyexpr: &str) -> Vec<u8> {
        declare_build::build_declare_queryable(id, 0, Some(keyexpr))
            .expect("the production builder must build a queryable")
            .try_as_borrowed()
            .expect("and it must re-borrow")
            .encode_to_vec()
    }

    fn declare_token(id: u64, keyexpr: &str) -> Vec<u8> {
        declare_build::build_declare_token(id, 0, Some(keyexpr))
            .expect("the production builder must build a token")
            .try_as_borrowed()
            .expect("and it must re-borrow")
            .encode_to_vec()
    }

    fn undeclare_sub(id: u64) -> Vec<u8> {
        declare_build::build_undeclare_subscriber(id)
            .try_as_borrowed()
            .expect("re-borrow")
            .encode_to_vec()
    }

    /// Gated on the union of its CONSUMERS' cfgs rather than silenced with
    /// `allow(dead_code)`: its only caller is the aliased-declaration test,
    /// which needs a matcher to assert coverage.
    #[cfg(feature = "filter-wildcards")]
    fn declare_kexpr(id: u64, suffix: &str) -> Vec<u8> {
        declare_build::build_declare_kexpr(id, suffix)
            .expect("the production builder must build a kexpr binding")
            .try_as_borrowed()
            .expect("and it must re-borrow")
            .encode_to_vec()
    }

    /// R311y869 — THE DEFECT, end to end. A subscriber declaring the ordinary
    /// zenoh wildcard is on the wire, and until this plane existed the reader
    /// decoded it and dropped it on the floor.
    ///
    /// Three assertions and not one, because three separate things had to be
    /// true and any of them alone would be a weaker claim: the declaration is
    /// SEEN, it COVERS the traffic a prefix fold would have put in a different
    /// subtree, and the traffic it does NOT cover is named. The last one is
    /// what makes this a finding rather than a listing.
    ///
    /// Gated on the feature that makes the claim TRUE rather than written once
    /// and made vague. Without `filter-wildcards` this same fixture is the
    /// UNDECIDABLE case, which `no_wildcard_tests` below asserts on the same
    /// bytes — the pair is what stops the honest-unknown arm from being a
    /// branch no lane enters.
    #[cfg(feature = "filter-wildcards")]
    #[test]
    fn a_wildcard_subscriber_is_seen_and_covers_the_traffic_it_matches() {
        let d = wire(&[
            (true, declare_sub(1, "robot/**")),
            (
                false,
                push(sender_space(0, Some("robot/1/pose")), &[0u8; 10]),
            ),
            (
                false,
                push(sender_space(0, Some("robot/2/pose")), &[0u8; 20]),
            ),
            (false, push(sender_space(0, Some("logs/audit")), &[0u8; 40])),
        ]);
        let census = interests(&d);
        assert_eq!(census.interests().len(), 1, "the declaration is SEEN");
        let i = &census.interests()[0];
        assert_eq!(i.kind, InterestKind::Subscriber);
        assert_eq!(i.declarer, Direction::A, "LOW -> HIGH declared it");
        assert_eq!(i.keyexpr.as_deref(), Some("robot/**"));
        assert!(i.is_open(), "nothing withdrew it");

        let table = crate::agg::aggregate(&d);
        let cov = census.coverage(&table);
        assert_eq!(cov.matched.len(), 1, "and it covers something");
        let m = &cov.matched[0];
        assert_eq!(m.interest, 0);
        // THE WILDCARD IS EVALUATED, not prefix-compared: `robot/**` is not a
        // prefix of `robot/1/pose` in the subtree fold's sense, and a plane
        // that folded by segment equality would report zero here.
        // ORDERED AS THE TABLE IS, heaviest first — `robot/2/pose` carried 20
        // bytes and `robot/1/pose` 10 — so a reader moving between the keyexpr
        // plane and this one does not have to hold two orderings in mind.
        assert_eq!(m.keys, alloc::vec!["robot/2/pose", "robot/1/pose"]);
        assert_eq!(m.totals.puts, 2);
        assert_eq!(m.totals.payload_bytes, 30);

        // THE MIRROR FINDING: traffic nobody in this capture asked for.
        assert_eq!(cov.unclaimed, alloc::vec!["logs/audit"]);
        assert!(
            cov.unclaimed_exact,
            "every declaration was judged, so the list is the whole answer"
        );
        assert_eq!(cov.judged(), 1);
        assert!(cov.silent.is_empty());
    }

    /// R311y869 — a declaration that matched NOTHING is the finding a pub/sub
    /// reader opens a capture for, and it is reported as its own population
    /// rather than as an absence from `matched`.
    #[cfg(feature = "filter-wildcards")]
    #[test]
    fn a_declaration_nothing_was_published_under_is_its_own_finding() {
        let d = wire(&[
            (true, declare_sub(7, "sensor/**")),
            (
                false,
                push(sender_space(0, Some("robot/1/pose")), &[0u8; 10]),
            ),
        ]);
        let census = interests(&d);
        let cov = census.coverage(&crate::agg::aggregate(&d));
        assert!(cov.matched.is_empty());
        assert_eq!(cov.silent, alloc::vec![0usize]);
        assert_eq!(
            cov.judged(),
            1,
            "the denominator `silent` is a numerator over"
        );
        assert_eq!(cov.unclaimed, alloc::vec!["robot/1/pose"]);
        assert!(cov.unclaimed_exact);
    }

    /// R311y869 — a withdrawal CLOSES an interest and does not erase it, and
    /// the anchor it closed at is kept.
    ///
    /// The assertion that matters is the second: a live registry would have
    /// dropped the row, and a census that did would describe this capture as
    /// having had no subscriber at all.
    #[test]
    fn a_withdrawn_subscriber_stays_in_the_census_with_its_closing_anchor() {
        let d = wire(&[
            (true, declare_sub(3, "robot/**")),
            (
                false,
                push(sender_space(0, Some("robot/1/pose")), &[0u8; 10]),
            ),
            (true, undeclare_sub(3)),
        ]);
        let census = interests(&d);
        assert_eq!(census.interests().len(), 1, "STILL LISTED");
        let i = &census.interests()[0];
        assert!(!i.is_open(), "and closed");
        let closed = i.withdrawn_at.expect("the anchor of the undeclare");
        assert!(
            closed > i.declared_at,
            "the withdrawal is later in the capture than the declaration \
             ({closed} vs {})",
            i.declared_at
        );
        assert_eq!(census.orphan_withdrawals(), 0);
    }

    /// R311y869 — an `Undeclare` for an id this capture never saw declared is
    /// COUNTED, because it is exactly what a capture begun mid-session looks
    /// like and it makes the declaration list a floor.
    #[test]
    fn a_withdrawal_of_something_never_seen_declared_is_counted() {
        let d = wire(&[(true, undeclare_sub(11))]);
        let census = interests(&d);
        assert!(census.interests().is_empty());
        assert_eq!(census.orphan_withdrawals(), 1);
    }

    /// R311y869 — the three kinds are kept apart, and a withdrawal in one
    /// space cannot close a declaration in another.
    ///
    /// Driven with the SAME id on all three, which is the fixture that tells a
    /// keyed-by-kind registry from one keyed by id alone: with the id alone,
    /// the second declaration would overwrite the first's open slot and the
    /// undeclare would close the wrong row.
    #[test]
    fn the_three_kinds_share_an_id_without_sharing_a_registry() {
        let d = wire(&[
            (true, declare_sub(4, "a/**")),
            (true, declare_qbl(4, "b/**")),
            (true, declare_token(4, "c/**")),
            (true, undeclare_sub(4)),
        ]);
        let census = interests(&d);
        assert_eq!(census.by_kind(), [1, 1, 1]);
        let by = |k: InterestKind| {
            census
                .interests()
                .iter()
                .find(|i| i.kind == k)
                .expect("one of each")
        };
        assert!(
            !by(InterestKind::Subscriber).is_open(),
            "the subscriber is the one that was withdrawn"
        );
        assert!(by(InterestKind::Queryable).is_open());
        assert!(by(InterestKind::LivelinessToken).is_open());
        assert_eq!(by(InterestKind::Queryable).keyexpr.as_deref(), Some("b/**"));
        assert_eq!(
            by(InterestKind::LivelinessToken).keyexpr.as_deref(),
            Some("c/**")
        );
    }

    /// R311y869 — a declaration whose keyexpr is an ALIAS resolves through the
    /// same tables the throughput plane uses, so the two planes name one
    /// keyexpr identically or not at all.
    #[cfg(feature = "filter-wildcards")]
    #[test]
    fn an_aliased_declaration_resolves_through_the_shared_tables() {
        let d = wire(&[
            (true, declare_kexpr(5, "robot")),
            (true, declare_sub_aliased(1, 5, Some("/**"))),
            (
                false,
                push(sender_space(0, Some("robot/1/pose")), &[0u8; 8]),
            ),
        ]);
        let census = interests(&d);
        let i = census
            .interests()
            .iter()
            .find(|i| i.kind == InterestKind::Subscriber)
            .expect("the subscriber");
        assert_eq!(
            i.keyexpr.as_deref(),
            Some("robot/**"),
            "the alias's base plus the declaration's suffix"
        );
        let cov = census.coverage(&crate::agg::aggregate(&d));
        assert_eq!(cov.matched.len(), 1);
        assert_eq!(cov.matched[0].keys, alloc::vec!["robot/1/pose"]);
    }

    /// R311y869 — a declaration naming an alias this capture never saw bound
    /// is UNRESOLVED, and that makes `unclaimed` a floor rather than an answer.
    ///
    /// The second assertion is the one with teeth: reporting the traffic as
    /// unclaimed while holding a declaration that might have covered it is a
    /// confident zero, and this plane refuses to present one.
    #[test]
    fn a_declaration_on_an_unbound_alias_makes_the_answer_a_floor() {
        let d = wire(&[
            (true, declare_sub_aliased(1, 9, None)),
            (
                false,
                push(sender_space(0, Some("robot/1/pose")), &[0u8; 8]),
            ),
        ]);
        let census = interests(&d);
        assert_eq!(census.interests().len(), 1);
        let i = &census.interests()[0];
        assert!(i.keyexpr.is_none());
        assert_eq!(
            i.unresolved,
            Some((Direction::A, 9)),
            "the space and id it named"
        );
        let cov = census.coverage(&crate::agg::aggregate(&d));
        assert_eq!(cov.unresolved, alloc::vec![0usize]);
        assert!(cov.silent.is_empty(), "unjudgeable is not silent");
        assert_eq!(cov.unclaimed, alloc::vec!["robot/1/pose"]);
        assert!(
            !cov.unclaimed_exact,
            "a declaration this reader could not name might have covered it"
        );
    }

    /// R311y869 — the plane reaches BOTH sides. A queryable declared by the
    /// far end covers traffic the near end published, and the census says
    /// which side asked.
    #[cfg(feature = "filter-wildcards")]
    #[test]
    fn the_declarer_is_the_side_that_declared_and_not_the_side_that_published() {
        let d = wire(&[
            (false, declare_qbl(2, "svc/**")),
            (true, push(sender_space(0, Some("svc/status")), &[0u8; 5])),
        ]);
        let census = interests(&d);
        let i = &census.interests()[0];
        assert_eq!(i.declarer, Direction::B, "HIGH -> LOW declared it");
        let cov = census.coverage(&crate::agg::aggregate(&d));
        assert_eq!(cov.matched[0].keys, alloc::vec!["svc/status"]);
    }
}

/// R311y869 — what this plane says when the build's keyexpr matcher has no
/// wildcards.
///
/// Its own module and the `not(...)` is the point, on `agg::no_codec_tests`'
/// precedent: this assertion cannot be made of a build that HAS the feature,
/// and without it the honest-unknown arm would be a branch no lane ever
/// enters. Layer C1bt's `--no-default-features --features network-codecs` arm
/// is the one that runs it, and it is the ONLY build in this workspace where
/// `network-codecs` is on and `filter-wildcards` is off.
///
/// It drives the SAME FIXTURE the decidable test above does, which is what
/// makes the pair a discriminator rather than two unrelated assertions: the
/// identical bytes must produce a coverage in one build and an explicit "this
/// build cannot tell" in the other, and neither may produce a confident zero.
#[cfg(all(test, not(feature = "filter-wildcards")))]
mod no_wildcard_tests {
    use super::*;
    use crate::datagram_tests::{frame_carrying, push, sender_space, udp_packet};
    use crate::link::LINKTYPE_ETHERNET;
    use crate::Dissection;

    const LOW: [u8; 4] = [10, 0, 0, 1];
    const HIGH: [u8; 4] = [10, 0, 0, 2];

    /// A wildcard this build cannot evaluate is UNDECIDABLE, never silent —
    /// and the traffic it might have covered is not reported as unclaimed
    /// without saying so.
    #[test]
    fn a_wildcard_this_build_cannot_evaluate_is_undecidable_rather_than_silent() {
        let declare =
            wz_session_core::declare_build::build_declare_subscriber(1, 0, Some("robot/**"))
                .expect("the production builder")
                .try_as_borrowed()
                .expect("re-borrow")
                .encode_to_vec();
        let mut d = Dissection::new();
        let unit = frame_carrying(&declare);
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &udp_packet(LOW, 43210, HIGH, 7447, &unit),
        );
        let unit = frame_carrying(&push(sender_space(0, Some("robot/1/pose")), &[0u8; 10]));
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &udp_packet(HIGH, 7447, LOW, 43210, &unit),
        );

        let census = interests(&d);
        // The DECLARATION is still read: this build's limit is the matcher, not
        // the decoder, and a plane that stopped listing declarations would be
        // hiding a fact it holds.
        assert_eq!(census.interests().len(), 1);
        assert_eq!(census.interests()[0].keyexpr.as_deref(), Some("robot/**"));

        let cov = census.coverage(&crate::agg::aggregate(&d));
        assert_eq!(cov.undecidable, alloc::vec![0usize]);
        assert!(
            cov.silent.is_empty(),
            "'this build cannot tell' must never be reported as 'nobody \
             subscribed'"
        );
        assert!(cov.matched.is_empty());
        assert_eq!(cov.judged(), 0, "nothing was judged, and the count says so");
        assert!(
            !cov.unclaimed_exact,
            "the unclaimed list is a floor while a declaration is unjudged"
        );
    }
}
