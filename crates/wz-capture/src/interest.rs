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
//!
//! # The QUESTION, not only the answers
//!
//! zenoh's declaration exchange is interest-driven, and reading only the
//! declarations reads only one side of it. `zenoh-protocol`'s own message-flow
//! diagram (`network/interest.rs:34-100`) is the contract:
//!
//! ```text
//!     A                   B
//!     |     INTEREST      |
//!     |------------------>|  Mode: Current -- "send me your subscribers"
//!     |  DECL SUBSCRIBER  |
//!     |<------------------|  with interest_id set   -- SOLICITED
//!     |     DECL FINAL    |
//!     |<------------------|  with interest_id set   -- and that CLOSES it
//! ```
//!
//! Three facts fall out that no census of declarations alone can state. A
//! declaration is SOLICITED or spontaneous, and the `Declare` envelope's
//! `interest_id` is which. An answer is COMPLETE or truncated, and the
//! `DeclFinal` carrying that same id is what says so. And an `Interest` that
//! got nothing back at all is a finding about the PEER — discovery asked for
//! and never served — which is invisible in a plane that only counts answers.
//!
//! R311y841's rule governs the second of those and is the reason it is modelled
//! as a pair rather than as a flag: completeness is not a property of one side,
//! it is a property of the MATCH. So a request carries what became of it and a
//! declaration carries what asked for it, and neither is derived from the other.
//!
//! The correlation crosses the flow: an `Interest` travels A -> B and its
//! answers travel B -> A, so a `Declare` seen in `direction` with an
//! `interest_id` answers the request `direction.peer()` asked. Getting that
//! backwards would attribute every answer to the wrong side and still produce a
//! plausible-looking table.
//!
//! # An answer that names the question is not yet an answer TO it
//!
//! Counting the declarations that carry an `interest_id` says how many replies
//! came back; it does not say whether any of them was what was asked for. Both
//! restrictions an `Interest` carries can be missed:
//!
//! * the KIND bits — a router serves `S`, `Q` and `T` from three separate
//!   branches (`zenoh/src/net/routing/hat/router/interests.rs:60,71,82`), so a
//!   `DeclareQueryable` answering a subscribers-only ask is not one of them;
//! * the KEYEXPR — a current dump is filtered by `sub.matches(res)`
//!   (`hat/router/pubsub.rs:986`), so a declaration whose keyexpr cannot
//!   intersect the restriction is not one either.
//!
//! Upstream sends neither, which is what makes each a FINDING about the peer
//! rather than a shape to tolerate — and until it was checked, an interest
//! answered entirely with the wrong declarations read as an interest that had
//! been served. [`crate::interest::InterestRequest::mismatched`] is where they
//! land.
//!
//! The test is INTERSECTION, not the pattern-covers-a-literal matcher the
//! coverage join uses, because here BOTH sides are patterns: `demo/*/pose` is a
//! correct answer to a `demo/**` ask. And it inherits the undecidability rule
//! above — an answer this build cannot evaluate becomes
//! [`crate::interest::InterestRequest::unjudged_answers`] and never a
//! divergence, because "cannot tell" reported as "the peer is wrong" is the
//! worse of the two errors.

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

/// The mode an `Interest` was asked in.
///
/// The two header bits `C` and `F` in the order upstream writes them
/// (`zenoh-protocol/src/network/interest.rs:157-176`, `|Z|Mod|INTEREST|`).
/// Named rather than reported as two bools because the four combinations are
/// four different conversations, and `Final` in particular is not "neither" —
/// it is the asker CANCELLING an earlier id and it carries no body at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterestMode {
    /// `0b00` — cancels the asker's earlier interest of the same id.
    Final,
    /// `0b01` — send what you have now, then a `DeclFinal`.
    Current,
    /// `0b10` — send changes from now on, unsolicited.
    Future,
    /// `0b11` — both: the current dump, its `DeclFinal`, then the changes.
    CurrentFuture,
}

impl InterestMode {
    fn of(header: u8) -> Self {
        // 0x20 is C and 0x40 is F, which is how this crate's codec exposes the
        // two Mod bits (`out/wz-codecs/interest.rs`) and how upstream lays them
        // out. Read from the header rather than from the accessors so the
        // mapping is stated once, here, beside the enum it produces.
        match (header & 0x20 != 0, header & 0x40 != 0) {
            (false, false) => Self::Final,
            (true, false) => Self::Current,
            (false, true) => Self::Future,
            (true, true) => Self::CurrentFuture,
        }
    }

    /// The word both renderings print.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Final => "final",
            Self::Current => "current",
            Self::Future => "future",
            Self::CurrentFuture => "current_future",
        }
    }

    /// Whether this mode asks for a CURRENT dump, which is the half a
    /// `DeclFinal` terminates.
    ///
    /// The predicate `unclosed` is judged against: a `Future`-only interest is
    /// never answered by a `DeclFinal`, so counting it as unterminated would
    /// report every correct session as truncated.
    pub const fn expects_a_final(self) -> bool {
        matches!(self, Self::Current | Self::CurrentFuture)
    }
}

/// What an `Interest` asks about — the body's flag byte, named.
///
/// `A|M|N|R|T|Q|S|K` at `zenoh-protocol/src/network/interest.rs:249-257`. The
/// three the reader acts on are kept and the three that describe the KEYEXPR's
/// own encoding (`N`, `M`) or its presence (`R`) are folded into `restricted`
/// plus the resolved keyexpr beside it, because a reader asking "what did this
/// node want" is not asking how the keyexpr was framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InterestScope {
    /// `K` — keyexpr declarations (the alias bindings).
    pub keyexprs: bool,
    /// `S` — subscriber declarations.
    pub subscribers: bool,
    /// `Q` — queryable declarations.
    pub queryables: bool,
    /// `T` — liveliness token declarations.
    pub tokens: bool,
    /// `R` — restricted to the keyexpr beside it. When clear, the interest is
    /// for ALL key expressions and the keyexpr field is absent — which is a
    /// different statement from "the keyexpr did not resolve".
    pub restricted: bool,
    /// `A` — the replies SHOULD be aggregated.
    pub aggregate: bool,
}

impl InterestScope {
    fn of(header: u8) -> Self {
        Self {
            keyexprs: header & 0b0000_0001 != 0,
            subscribers: header & 0b0000_0010 != 0,
            queryables: header & 0b0000_0100 != 0,
            tokens: header & 0b0000_1000 != 0,
            restricted: header & 0b0001_0000 != 0,
            aggregate: header & 0b1000_0000 != 0,
        }
    }

    /// `true` when the interest names a declaration kind this plane tracks.
    ///
    /// Not "any bit set": `K` alone asks for keyexpr ALIAS bindings, which are
    /// `crate::agg`'s business and produce no `DeclaredInterest`. An interest
    /// for keyexprs only that receives no subscriber is correct, and a finding
    /// that said otherwise would fire on every session zenoh opens.
    pub const fn asks_for_a_declaration(self) -> bool {
        self.subscribers || self.queryables || self.tokens
    }
}

/// One `Interest` this capture saw, and what came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterestRequest {
    /// The side that ASKED. Its answers travel the other way.
    pub asker: Direction,
    /// The interest id, in the asker's own space.
    pub id: u64,
    /// The mode it was asked in.
    pub mode: InterestMode,
    /// What it asked about. `None` for [`InterestMode::Final`], which carries
    /// no body — absent rather than an all-false scope, because "cancel" asks
    /// for nothing rather than asking for none of the four.
    pub scope: Option<InterestScope>,
    /// The keyexpr it was restricted to, resolved. `None` both when the
    /// interest was unrestricted and when its alias did not resolve; the two
    /// are told apart by [`InterestScope::restricted`] and
    /// [`Self::unresolved`].
    pub keyexpr: Option<String>,
    /// The `(space, id)` an unresolved restriction named.
    pub unresolved: Option<(Direction, u64)>,
    /// The flow it was asked on.
    pub flow: FlowKey,
    /// Capture anchor of the `Interest`.
    pub asked_at: usize,
    /// R311y919 (open-debt item 452) — WHICH space `asked_at`, `closed_at` and
    /// `cancelled_at` are in. Found while testing item 452: the item named the
    /// declaration's two anchors and this plane carries three more.
    pub anchors: crate::AnchorSpace,
    /// Declarations seen carrying this id.
    ///
    /// The RAW count, deliberately: it is how many declarations claimed to
    /// answer this question, which is a different number from how many of them
    /// actually did. [`Self::mismatched`] and [`Self::unjudged_answers`] are
    /// the split, and keeping this one raw is what lets a reader see that the
    /// three disagree.
    pub answers: usize,
    /// Indices into [`InterestCensus::interests`] of answers this reader
    /// JUDGED to be outside what this request asked for.
    ///
    /// Upstream does not send these — the router answers an interest from the
    /// declarations that `matches` its restriction
    /// (`zenoh/src/net/routing/hat/router/pubsub.rs:986`) and only for the
    /// kinds its option bits named (`hat/router/interests.rs:60,71,82`) — so
    /// each one is a finding about the peer rather than furniture.
    pub mismatched: Vec<usize>,
    /// Answers this build could not judge either way.
    ///
    /// The same rule the coverage join runs under: an undecidable pattern, an
    /// alias that never resolved, or an interest carrying no body at all are
    /// "cannot tell", and folding them into [`Self::mismatched`] would report
    /// a confident divergence this reader did not observe.
    pub unjudged_answers: usize,
    /// Anchor of the `DeclFinal` that terminated the current dump.
    pub closed_at: Option<usize>,
    /// Anchor of the asker's own `Interest(Final)` for this id.
    pub cancelled_at: Option<usize>,
}

impl InterestRequest {
    /// Answers this reader judged to be within what was asked.
    ///
    /// The denominator [`Self::mismatched`] is a numerator over, and the
    /// number a reader handed `answers = 3` needs before concluding the peer
    /// served the question.
    pub fn answers_in_scope(&self) -> usize {
        self.answers - self.mismatched.len() - self.unjudged_answers
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
    /// R311y919 (open-debt item 452) — WHICH space the two anchors above are
    /// in. A byte offset within this flow's direction, or a packet index; the
    /// two are told apart nowhere else, and a reader handed a small integer
    /// cannot guess.
    pub anchors: crate::AnchorSpace,
    /// Round 2019 (item 270) — the space TOKEN, composed exactly as
    /// [`crate::agg`] composes a row's.
    ///
    /// [`Self::anchors`] says a byte offset from a packet index, which is what
    /// a READER needs. This says whether two such numbers count from the same
    /// origin, which is what a COMPARISON needs — and item 270's comparison is
    /// between this declaration's window and a traffic row's span. Two byte
    /// offsets in different directions of different flows are both
    /// `StreamBytes` and are not on one line.
    ///
    /// Both walks enumerate `Dissection::message_lists()` in the same order,
    /// which is why the two tokens are comparable at all; that shared order is
    /// the whole of the coupling and it is stated here so a round that changes
    /// either walk knows what it is breaking.
    pub(crate) space: usize,
    /// The `Interest` id this declaration answers, when the envelope carried
    /// one.
    ///
    /// `None` is a real answer and not a missing field: a `Future`-mode
    /// interest's later declarations are UNSOLICITED by contract, and so is
    /// every declaration on a session where nobody asked. Which of the two it
    /// is, is a question about the requests beside it.
    pub solicited_by: Option<u64>,
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
    ///
    /// ⚠ Round 2019 (item 270) — over ALL of [`Self::keys`], including any in
    /// [`Self::outside_window`]. It is what the PATTERN covers, not what the
    /// declaration was open for, and the three lists below are what a reader
    /// narrows it with. Left whole rather than filtered because a filtered
    /// total would silently change what every existing consumer reads.
    pub totals: KeyexprCounts,
    /// Round 2019 (item 270) — keys whose traffic lies ENTIRELY outside the
    /// window this declaration was open.
    ///
    /// THE FINDING this item is about: a subscriber declared and withdrawn
    /// inside the capture was credited with everything its pattern matched,
    /// including traffic that went past after it was gone. A key here is one
    /// the declaration cannot have been receiving.
    pub outside_window: Vec<String>,
    /// Keys whose span only PARTIALLY overlaps the window.
    ///
    /// The row's totals are then a CEILING for what this declaration covered:
    /// the row folds records from inside and outside the window and the fold
    /// keeps no per-record anchor to split them by. Reported rather than
    /// resolved, because resolving it means re-walking the capture per
    /// declaration and this plane is a join over two folds.
    pub partial_window: Vec<String>,
    /// Keys the window question could not be ASKED of.
    ///
    /// Two causes and both are honest: the row's anchors are in a different
    /// space from this declaration's (a byte offset in another direction is not
    /// on the same line), or the row is not `anchors_exact` and its span
    /// therefore does not cover all of its own records. Held apart from
    /// [`Self::outside_window`] on this crate's standing rule — "cannot tell"
    /// must never read as "did not happen".
    pub window_undecidable: Vec<String>,
}

/// Round 2019 (item 270) — how one traffic row's span sits against the window
/// one declaration was open for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowOverlap {
    /// Every record in the row is inside the window.
    Whole,
    /// The row spans the window's edge, so its totals include records from
    /// both sides and this fold cannot split them.
    Partial,
    /// The row's whole span is outside the window.
    Outside,
    /// The two are not on one line, so the question does not have an answer.
    Undecidable,
}

/// Round 2019 (item 270) — the comparison R311y869 said the material was there
/// for and R311y918 showed it was not.
///
/// # What has to be true before the numbers mean anything
///
/// Two things, and BOTH are refusals rather than defaults:
///
/// 1. The row and the declaration must be in the same coordinate space. A byte
///    offset within one direction of one flow and a byte offset within another
///    are both `StreamBytes` and share no origin — comparing them produces a
///    confident verdict about nothing. The `space` token is what settles it.
/// 2. The row must be `anchors_exact`. When it is not, the row folded records
///    from more than one space and its `[first, last]` pair does not cover all
///    of them, so "the row's span" is not a span this can test.
///
/// # The window
///
/// `[declared_at, withdrawn_at]`, and an OPEN declaration's window runs to the
/// end of the capture — `withdrawn_at: None` means the capture never saw it
/// closed, so nothing after `declared_at` is outside it.
///
/// ⚠ A declaration is not retroactive: traffic BEFORE `declared_at` is outside
/// the window just as much as traffic after a withdrawal. That direction is
/// the commoner one in a real capture, because a tap started mid-session sees
/// a `DeclareSubscriber` re-sent after traffic it was already receiving —
/// which is why this returns `Outside` rather than something that reads as an
/// error.
fn window_overlap(interest: &DeclaredInterest, row: &crate::agg::KeyexprRow) -> WindowOverlap {
    if row.space != interest.space || !row.anchors_exact {
        return WindowOverlap::Undecidable;
    }
    let (from, to) = (row.first_anchor, row.last_anchor);
    let open = interest.declared_at;
    let close = interest.withdrawn_at.unwrap_or(usize::MAX);
    if to < open || from > close {
        return WindowOverlap::Outside;
    }
    if from >= open && to <= close {
        return WindowOverlap::Whole;
    }
    WindowOverlap::Partial
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
    /// R311y919 (open-debt item 452) — the coordinate space of the list being
    /// walked, set once per [`Self::observe_flow`] and read where a declaration
    /// or a request records its anchor.
    ///
    /// On the census rather than in the two constructors' signatures: both are
    /// already `#[allow(clippy::too_many_arguments)]`, and this is a property of
    /// the WALK rather than of any one declaration.
    anchors: crate::AnchorSpace,
    /// Round 2019 (item 270) — which message list is being walked, set once per
    /// [`Self::observe_flow`]. Half of the space token; see
    /// [`Self::space_of`].
    list: usize,
    interests: Vec<DeclaredInterest>,
    requests: Vec<InterestRequest>,
    orphan_withdrawals: usize,
    orphan_answers: usize,
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

    /// Every `Interest`, in the order the capture carried them.
    pub fn requests(&self) -> &[InterestRequest] {
        &self.requests
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

    /// Declarations naming an `Interest` id this capture never saw asked.
    ///
    /// The same shape as [`Self::orphan_withdrawals`] and the same reading: a
    /// tap started after the question makes the request list a floor. It is
    /// counted rather than repaired, because inventing the request would make
    /// [`Self::unanswered`] answer about a question nobody saw.
    pub fn orphan_answers(&self) -> usize {
        self.orphan_answers
    }

    /// Requests that asked for a declaration kind and got NOTHING back.
    ///
    /// THE FINDING: a node asked its peer for the subscribers (or queryables,
    /// or tokens) it holds and the capture carries no answer at all. On a
    /// working session that is a peer holding none; on a broken one it is
    /// discovery that never happened, and either way it is the sentence a
    /// reader of a declaration list cannot construct.
    ///
    /// [`InterestMode::Final`] is excluded because it is a cancellation and
    /// asks for nothing, and so is an interest scoped to keyexpr aliases alone
    /// — see [`InterestScope::asks_for_a_declaration`].
    pub fn unanswered(&self) -> Vec<usize> {
        self.requests
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                r.mode != InterestMode::Final
                    && r.scope.is_some_and(InterestScope::asks_for_a_declaration)
                    && r.answers == 0
                    && r.closed_at.is_none()
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// Requests whose CURRENT dump was never terminated by a `DeclFinal`.
    ///
    /// The answer this capture holds for such a request is a FLOOR: more
    /// declarations were still to come when the capture ended, or the peer
    /// never finished. Judged only for the modes that expect a `DeclFinal` at
    /// all — a `Future`-only interest is terminated by nothing, and calling it
    /// unclosed would report every correct session as truncated.
    pub fn unclosed(&self) -> Vec<usize> {
        self.requests
            .iter()
            .enumerate()
            .filter(|(_, r)| r.mode.expects_a_final() && r.closed_at.is_none() && r.answers > 0)
            .map(|(i, _)| i)
            .collect()
    }

    /// Requests answered with declarations they did not ask for.
    ///
    /// THE FINDING a count of answers cannot reach: a peer that replies to a
    /// `demo/**` ask with an `other/thing` subscriber, or to a subscribers-only
    /// ask with a queryable, has answered the id and not the QUESTION — and
    /// every plane that counted the reply reported the exchange as served.
    /// Upstream sends neither (`hat/router/pubsub.rs:986`,
    /// `hat/router/interests.rs:60`), so each one is a divergence rather than
    /// a shape this reader must tolerate.
    ///
    /// Held apart from [`Self::unanswered`] on purpose: silence and a wrong
    /// answer are different facts about the peer, and a reader acts on them
    /// differently.
    pub fn mismatched(&self) -> Vec<usize> {
        self.requests
            .iter()
            .enumerate()
            .filter(|(_, r)| !r.mismatched.is_empty())
            .map(|(i, _)| i)
            .collect()
    }

    /// How many answers, over every request, this build could not judge.
    ///
    /// The floor under [`Self::mismatched`]: while this is non-zero, "no
    /// divergence was found" is not "the peer answered in scope".
    pub fn unjudged_answers(&self) -> usize {
        self.requests.iter().map(|r| r.unjudged_answers).sum()
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
    pub fn observe_flow(
        &mut self,
        flow: &FlowKey,
        frames: &[PassiveFrame],
        anchors: crate::AnchorSpace,
        // Round 2019 (item 270) — the list's index in
        // `Dissection::message_lists()`, which is what `crate::agg` already
        // takes for the same reason: it is half the space token, and without it
        // two directions of two different flows are one number.
        list: usize,
    ) {
        self.anchors = anchors;
        self.list = list;
        let mut spaces = KeyexprSpaces::new();
        // The OPEN declaration per `(declarer, kind, id)`, as an index into
        // `self.interests`. Keyed on the kind as well as the id because zenoh
        // mints subscriber, queryable and token ids in separate spaces, and a
        // key without it would let a queryable's withdrawal close a
        // subscriber's declaration that happened to share a number.
        let mut open: BTreeMap<(usize, InterestKind, u64), usize> = BTreeMap::new();
        // The live request per `(asker, id)`. Keyed on the ASKER and not on the
        // direction the message travelled: an `Interest` goes one way and its
        // answers come back the other, so a map keyed by the travelling
        // direction would credit every answer to the wrong side.
        let mut asked: BTreeMap<(usize, u64), usize> = BTreeMap::new();
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
                match message {
                    NetworkMessage::Declare(d) => self.observe_declare(
                        &mut spaces,
                        &mut open,
                        &mut asked,
                        flow,
                        frame.direction,
                        anchor,
                        d,
                    ),
                    NetworkMessage::Interest(i) => {
                        self.observe_interest(&spaces, &mut asked, flow, frame.direction, anchor, i)
                    }
                    _ => {}
                }
            }
        }
    }

    /// Fold one `Interest`: a new request, or the asker cancelling its own.
    fn observe_interest(
        &mut self,
        spaces: &KeyexprSpaces,
        asked: &mut BTreeMap<(usize, u64), usize>,
        flow: &FlowKey,
        direction: Direction,
        anchor: usize,
        interest: &wz_codecs::interest::InterestOwned,
    ) {
        let mode = InterestMode::of(interest.header);
        let dir = dir_index(direction);
        if mode == InterestMode::Final {
            // The asker stopping its OWN earlier interest. It carries no body,
            // so there is nothing to record beyond the closure — and recording
            // it as a fresh request would put a scope-less row in the list that
            // `unanswered` would then have to special-case.
            match asked.remove(&(dir, interest.interest_id)) {
                Some(at) => self.requests[at].cancelled_at = Some(anchor),
                // A cancellation for a question this capture never saw. Same
                // reading as an orphan answer: the tap started late.
                None => self.orphan_answers += 1,
            }
            return;
        }
        let scope = interest.body.as_ref().map(|b| InterestScope::of(b.header));
        // The restriction keyexpr travels in the ASKER's own message, so it
        // resolves exactly as a declaration's does — through the same tables,
        // with the mapping bit choosing the space.
        let resolved = interest
            .body
            .as_ref()
            .and_then(|b| b.keyexpr.as_ref())
            .map(|ke| spaces.resolve(direction, &ke.body));
        let (keyexpr, unresolved) = match resolved {
            Some(Ok(k)) => (Some(k), None),
            Some(Err(alias)) => (None, Some(alias)),
            None => (None, None),
        };
        self.requests.push(InterestRequest {
            asker: direction,
            id: interest.interest_id,
            mode,
            scope,
            keyexpr,
            unresolved,
            flow: *flow,
            asked_at: anchor,
            answers: 0,
            mismatched: Vec::new(),
            unjudged_answers: 0,
            closed_at: None,
            cancelled_at: None,
            anchors: self.anchors,
        });
        asked.insert((dir, interest.interest_id), self.requests.len() - 1);
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_declare(
        &mut self,
        spaces: &mut KeyexprSpaces,
        open: &mut BTreeMap<(usize, InterestKind, u64), usize>,
        asked: &mut BTreeMap<(usize, u64), usize>,
        flow: &FlowKey,
        direction: Direction,
        anchor: usize,
        declare: &wz_codecs::declare::DeclareOwned,
    ) {
        use wz_codecs::declare::DeclareOwnedVariant as V;
        let dir = dir_index(direction);
        // THE CORRELATION CROSSES THE FLOW. This declaration travels in
        // `direction`; the interest it answers was asked by the OTHER side.
        // Backwards, every answer would be credited to the peer that produced
        // it and the table would still look plausible.
        let solicited_by = declare.interest_id;
        let answering = solicited_by.and_then(|id| {
            let key = (dir_index(direction.peer()), id);
            match asked.get(&key) {
                Some(at) => Some(*at),
                None => {
                    self.orphan_answers += 1;
                    None
                }
            }
        });
        if let Some(at) = answering {
            // A `DeclFinal` TERMINATES the dump rather than being one of it,
            // so it closes the request without counting as an answer. Counting
            // it would make `answers` disagree with the number of declarations
            // in the list, which is the one thing that number must not do.
            if matches!(declare.body, V::CodecZenohDeclFinal(_)) {
                self.requests[at].closed_at = Some(anchor);
            } else {
                self.requests[at].answers += 1;
            }
        }
        // RESOLVED BEFORE ABSORBED. A `DeclKexpr` arriving in the same batch
        // binds an id every LATER reference resolves through, and reading the
        // tables after absorbing this message would let a declaration resolve
        // through a binding that had not yet gone past when it did.
        // The declaration this message declared, when it declared one. Held so
        // the scope judgement below runs from ONE place rather than once per
        // arm: a fourth declaration kind must then join the judgement by
        // construction instead of by somebody remembering the fourth call.
        let mut declared = None;
        match &declare.body {
            V::CodecZenohDeclSubscriber(d) => {
                let resolved = spaces.resolve(direction, &d.keyexpr.body);
                let at = self.push(
                    InterestKind::Subscriber,
                    direction,
                    d.id,
                    resolved,
                    flow,
                    anchor,
                    solicited_by,
                );
                open.insert((dir, InterestKind::Subscriber, d.id), at);
                declared = Some(at);
            }
            V::CodecZenohDeclQueryable(d) => {
                let resolved = spaces.resolve(direction, &d.keyexpr.body);
                let at = self.push(
                    InterestKind::Queryable,
                    direction,
                    d.id,
                    resolved,
                    flow,
                    anchor,
                    solicited_by,
                );
                open.insert((dir, InterestKind::Queryable, d.id), at);
                declared = Some(at);
            }
            V::CodecZenohDeclToken(d) => {
                let resolved = spaces.resolve(direction, &d.keyexpr.body);
                let at = self.push(
                    InterestKind::LivelinessToken,
                    direction,
                    d.id,
                    resolved,
                    flow,
                    anchor,
                    solicited_by,
                );
                open.insert((dir, InterestKind::LivelinessToken, d.id), at);
                declared = Some(at);
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
        // IS THIS AN ANSWER TO THE QUESTION IT NAMES? Counting it was never
        // the same as checking it — R311y841's rule, one layer further in:
        // completeness is a property of the MATCH, and so is correctness.
        if let (Some(request), Some(declaration)) = (answering, declared) {
            self.judge_answer(request, declaration);
        }
        // The alias tables, through the one absorber, so this plane and the
        // throughput plane resolve a keyexpr identically or not at all.
        spaces.absorb(direction, declare);
    }

    /// Decide whether one declaration is within what one request asked for.
    ///
    /// TWO AXES, because an interest restricts on two and a peer can miss
    /// either. The KIND axis is always decidable — the option bits are on the
    /// wire and the declaration's kind is the arm that decoded it — while the
    /// KEYEXPR axis inherits every "cannot tell" the coverage join has, and
    /// the two must not be folded: a queryable answering a subscriber-only ask
    /// is a divergence this reader observed, whichever wildcards it can read.
    ///
    /// The keyexpr test is INTERSECTION and not pattern-matching. Both sides
    /// are patterns here — a `demo/*/pose` subscriber is a correct answer to a
    /// `demo/**` ask and to a `demo/1/**` one — and upstream's own filter is
    /// `sub.matches(res)`, which is the intersect predicate
    /// ([`wz_session_core::keyexpr_match::keyexpr_intersects_target`]), not
    /// the covers-a-literal one the coverage join runs against traffic keys.
    /// Using the literal matcher here would report every wildcard declaration
    /// in a normal session as a divergence.
    fn judge_answer(&mut self, request: usize, declaration: usize) {
        let (kind, answer) = {
            let d = &self.interests[declaration];
            (d.kind, d.keyexpr.clone())
        };
        let r = &self.requests[request];
        // No body at all: there is no ask for this to be inside or outside of.
        let verdict = match r.scope {
            None => Verdict::Unjudged,
            Some(scope) => {
                let asked_for_this_kind = match kind {
                    InterestKind::Subscriber => scope.subscribers,
                    InterestKind::Queryable => scope.queryables,
                    InterestKind::LivelinessToken => scope.tokens,
                };
                if !asked_for_this_kind {
                    Verdict::Mismatched
                } else if !scope.restricted {
                    // `R` clear is an ask for ALL key expressions, so no
                    // keyexpr can fall outside it. Distinct from a restriction
                    // that failed to resolve, which is the arm below.
                    Verdict::InScope
                } else {
                    match (r.keyexpr.as_deref(), answer.as_deref()) {
                        (Some(ask), Some(got))
                            if pattern_is_decidable(ask) && pattern_is_decidable(got) =>
                        {
                            let ask_chunks: Vec<&str> = ask.split('/').collect();
                            if wz_session_core::keyexpr_match::keyexpr_intersects_target(
                                got,
                                &ask_chunks,
                            ) {
                                Verdict::InScope
                            } else {
                                Verdict::Mismatched
                            }
                        }
                        _ => Verdict::Unjudged,
                    }
                }
            }
        };
        match verdict {
            Verdict::InScope => {}
            Verdict::Mismatched => self.requests[request].mismatched.push(declaration),
            Verdict::Unjudged => self.requests[request].unjudged_answers += 1,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        kind: InterestKind,
        declarer: Direction,
        id: u64,
        resolved: Result<String, (Direction, u64)>,
        flow: &FlowKey,
        anchor: usize,
        solicited_by: Option<u64>,
    ) -> usize {
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
            solicited_by,
            anchors: self.anchors,
            // Round 2019 (item 270) — the DECLARER's direction, because that is
            // the direction the frame carrying this declaration travelled in,
            // and the offset above is an offset within it.
            space: self.space_of(declarer),
        });
        self.interests.len() - 1
    }

    /// Round 2019 (item 270) — the space token for one direction of the list
    /// being walked, composed exactly as [`crate::agg`] composes a row's.
    ///
    /// Written as its own function so the two compositions are one sentence
    /// apart rather than one file apart. If they ever disagree the comparison
    /// silently becomes "always undecidable", which is the quiet failure this
    /// whole item is about; `a_declarations_space_token_matches_the_rows` is
    /// the leg that would notice.
    fn space_of(&self, dir: Direction) -> usize {
        match self.anchors {
            crate::AnchorSpace::PacketIndex => 0,
            crate::AnchorSpace::StreamBytes => 1 + self.list * 2 + dir_index(dir),
        }
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
            let mut outside_window = Vec::new();
            let mut partial_window = Vec::new();
            let mut window_undecidable = Vec::new();
            for (i, row) in rows.iter().enumerate() {
                if !wz_session_core::keyexpr_match::keyexpr_pattern_matches(&chunks, &row.keyexpr) {
                    continue;
                }
                claimed[i] = true;
                keys.push(row.keyexpr.clone());
                totals.add(&row.totals());
                // Round 2019 (item 270) — WAS THIS DECLARATION OPEN WHEN THAT
                // TRAFFIC WENT PAST? The pattern match above answers "could it
                // have covered this key"; without this the two questions were
                // one, and a declaration withdrawn mid-capture was credited
                // with everything after it.
                match window_overlap(interest, row) {
                    WindowOverlap::Whole => {}
                    WindowOverlap::Partial => partial_window.push(row.keyexpr.clone()),
                    WindowOverlap::Outside => outside_window.push(row.keyexpr.clone()),
                    WindowOverlap::Undecidable => window_undecidable.push(row.keyexpr.clone()),
                }
            }
            if keys.is_empty() {
                out.silent.push(at);
            } else {
                out.matched.push(InterestMatch {
                    interest: at,
                    keys,
                    totals,
                    outside_window,
                    partial_window,
                    window_undecidable,
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

/// What one answer turned out to be, relative to the question it named.
///
/// Three and not a `bool`, for the reason [`Coverage`] has four populations:
/// an answer this build could not judge is not an answer it judged to be in
/// scope, and a plane that returned `false` for both would report the second
/// as a divergence and the first as nothing at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Within the kinds and the keyexpr the request asked for.
    InScope,
    /// Judged, and outside — the finding.
    Mismatched,
    /// Neither: an undecidable pattern, an unresolved alias, or no ask at all.
    Unjudged,
}

/// The index [`Direction`] stands at in this module's two-slot registries.
///
/// One spelling, so a registry keyed by the asker and one keyed by the
/// declarer cannot disagree about which slot is which.
fn dir_index(d: Direction) -> usize {
    match d {
        Direction::A => 0,
        Direction::B => 1,
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
    // Round 2019 (item 270) — `.enumerate()`, exactly as `agg::aggregate_where`
    // does. The two walks must agree on the list index or their space tokens
    // are not comparable, and they agree by walking the same enumeration of the
    // same iterator.
    for (list, (flow, anchors, frames)) in dissection.message_lists().enumerate() {
        census.observe_flow(&flow, frames, anchors, list);
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

    /// ITEM 270 — A WITHDRAWN DECLARATION IS NOT CREDITED WITH WHAT CAME
    /// AFTER IT.
    ///
    /// # The defect
    ///
    /// `coverage` joined a declaration to a traffic row by PATTERN alone. A
    /// subscriber declared and withdrawn inside the capture therefore covered
    /// everything its pattern matched, including traffic that went past when
    /// it was gone — the plane answered "could this have covered that key"
    /// while the page read as "this was receiving that".
    ///
    /// R311y869 said the material was on the rows already. R311y918 showed
    /// that was true and not enough: two anchors exist, and whether they can
    /// be COMPARED is a different question, answered only once both sides
    /// carry the space they count in. Round 2019 is the comparison.
    ///
    /// # The three arms, because "cannot tell" is not "did not happen"
    ///
    /// Traffic after the withdrawal is OUTSIDE. Traffic while the declaration
    /// was open is WHOLE and says nothing. And the leg below drives the pair
    /// together in one capture, so a fix that reported everything as outside
    /// would fail as loudly as one that reported nothing.
    #[test]
    fn traffic_after_a_withdrawal_is_not_covered_by_the_withdrawn_declaration() {
        let d = wire(&[
            // 0: opened, and it stays open for the whole capture.
            (true, declare_sub(1, "demo/open")),
            // 1: opened, 2: withdrawn.
            (true, declare_sub(2, "demo/gone")),
            (true, undeclare_sub(2)),
            // 3: traffic on the key the WITHDRAWN one matches, after it went.
            (false, push(sender_space(0, Some("demo/gone")), &[0u8; 4])),
            // 4: traffic on the key the OPEN one matches.
            (false, push(sender_space(0, Some("demo/open")), &[0u8; 4])),
        ]);

        let census = interests(&d);
        let table = crate::agg::aggregate(&d);
        // THE POPULATION FIRST. Two declarations and two keyexpr rows; a
        // capture short of either would make every claim below vacuous.
        assert_eq!(census.interests().len(), 2, "two declarations");
        assert_eq!(table.rows().len(), 2, "and two keys carried traffic");
        let cov = census.coverage(&table);
        assert_eq!(cov.matched.len(), 2, "both patterns match a row: {cov:?}");

        let by_key = |k: &str| {
            cov.matched
                .iter()
                .find(|m| census.interests()[m.interest].keyexpr.as_deref() == Some(k))
                .unwrap_or_else(|| panic!("no match for {k}: {cov:?}"))
        };

        let gone = by_key("demo/gone");
        assert_eq!(
            gone.outside_window,
            alloc::vec![String::from("demo/gone")],
            "the traffic went past after the withdrawal, so this declaration \
             cannot have been receiving it -- THIS IS ITEM 270: {gone:?}"
        );
        assert!(gone.partial_window.is_empty(), "{gone:?}");
        assert!(
            gone.window_undecidable.is_empty(),
            "a UDP capture anchors every record by packet index, so the \
             question IS askable here: {gone:?}"
        );

        // THE CONTROL, in the same capture: an open declaration's traffic is
        // inside its window and says nothing.
        let open = by_key("demo/open");
        assert!(
            open.outside_window.is_empty()
                && open.partial_window.is_empty()
                && open.window_undecidable.is_empty(),
            "a declaration still open at the end of the capture has no traffic \
             outside its window: {open:?}"
        );

        // AND `totals` IS UNCHANGED, deliberately. It is what the pattern
        // covers; narrowing it silently would move a number every existing
        // consumer reads.
        assert_eq!(gone.totals.messages(), 1, "{gone:?}");
    }

    /// ITEM 270, THE HALF THAT REFUSES — TWO BYTE OFFSETS IN DIFFERENT
    /// DIRECTIONS ARE NOT ON ONE LINE.
    ///
    /// # Why this leg exists, stated as what happened
    ///
    /// The window comparison landed with the packet-index witness above
    /// passing, and removing the SPACE check from `window_overlap` survived
    /// the whole suite. A surviving mutant is a leg nothing asks about, and
    /// this is that leg: a UDP capture anchors every record by packet index,
    /// so every space token is 0 and the check can never be wrong there.
    ///
    /// On a STREAM link the anchor is a byte offset within ONE DIRECTION, and
    /// the two directions count from different origins. R311y918 measured what
    /// ignoring that produces — a row reporting the span `[419, 0]`, an
    /// interval that cannot exist.
    ///
    /// # ⚠ And the answer this gives is mostly UNDECIDABLE, which is the point
    ///
    /// A subscriber declares in one direction and the traffic it subscribes to
    /// arrives in the other. On a stream link those are two spaces, so the
    /// window question genuinely cannot be asked of the ordinary case. Saying
    /// so is the deliverable; a comparison that answered anyway would be
    /// confident about nothing, which is the defect item 270 exists to end
    /// rather than to relocate.
    #[test]
    fn a_window_and_a_row_in_different_stream_directions_are_not_compared() {
        use crate::datagram_tests::{tcp_packet, tcp_packet_reverse};

        // One length-prefixed transport frame carrying `record`.
        let framed = |record: &[u8]| {
            let mut unit = alloc::vec![
                wz_session_core::wire_const::T_MID_FRAME
                    | wz_session_core::wire_const::FLAG_T_FRAME_R,
                0x00,
            ];
            unit.extend_from_slice(record);
            let mut out = (unit.len() as u16).to_le_bytes().to_vec();
            out.extend_from_slice(&unit);
            out
        };

        let mut d = Dissection::new();
        // A declares, in A's byte space.
        let decl = framed(&declare_sub(5, "demo/**"));
        d.push_packet(LINKTYPE_ETHERNET, 0, &tcp_packet(1000, &decl));
        // A publishes too, so ONE row is in A's space and decidable.
        let mine = framed(&push(sender_space(0, Some("demo/mine")), &[0u8; 4]));
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &tcp_packet(1000 + decl.len() as u32, &mine),
        );
        // B publishes: same flow, OTHER direction, other origin.
        let theirs = framed(&push(sender_space(0, Some("demo/theirs")), &[0u8; 4]));
        d.push_packet(LINKTYPE_ETHERNET, 2, &tcp_packet_reverse(2000, &theirs));
        d.finish();

        let census = interests(&d);
        let table = crate::agg::aggregate(&d);
        assert_eq!(census.interests().len(), 1, "one declaration");
        assert_eq!(
            table.rows().len(),
            2,
            "and TWO rows, one per direction -- without both this leg cannot \
             tell a refusal from an empty table: {:?}",
            table.rows()
        );

        let cov = census.coverage(&table);
        let m = cov.matched.first().expect("the pattern matches both rows");
        assert_eq!(m.keys.len(), 2, "{m:?}");
        assert_eq!(
            m.window_undecidable,
            alloc::vec![String::from("demo/theirs")],
            "the OTHER direction's row is anchored in another space and the \
             window cannot be judged against it: {m:?}"
        );
        assert!(
            m.outside_window.is_empty(),
            "and it is NOT reported as outside the window -- `cannot tell` \
             must never read as `did not happen`: {m:?}"
        );
        // The CONTROL, in the same capture: the declarer's own direction is
        // one space and IS judged.
        assert!(
            !m.window_undecidable.contains(&String::from("demo/mine")),
            "the declarer's own direction shares its space: {m:?}"
        );
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

    fn interest_subs(id: u64, current: bool, future: bool, keyexpr: &str) -> Vec<u8> {
        wz_session_core::interest_build::build_interest_subscribers(
            id,
            current,
            future,
            0,
            Some(keyexpr),
        )
        .expect("the production interest builder")
        .try_as_borrowed()
        .expect("re-borrow")
        .encode_to_vec()
    }

    fn interest_final(id: u64) -> Vec<u8> {
        wz_session_core::interest_build::build_interest_final(id)
            .try_as_borrowed()
            .expect("re-borrow")
            .encode_to_vec()
    }

    fn sub_reply(interest_id: u64, keyexpr: &str) -> Vec<u8> {
        declare_build::build_declare_subscriber_reply(interest_id, keyexpr)
            .expect("the production reply builder")
            .try_as_borrowed()
            .expect("re-borrow")
            .encode_to_vec()
    }

    fn final_reply(interest_id: u64) -> Vec<u8> {
        declare_build::build_declare_final_reply(interest_id)
            .try_as_borrowed()
            .expect("re-borrow")
            .encode_to_vec()
    }

    /// R311y870 — THE PAIR, and the assertion that the correlation crosses the
    /// flow rather than following it.
    ///
    /// A asks; B answers; B closes. Every message is built by the production
    /// builder that emits it, so this asserts the plane reads what wz sends.
    ///
    /// THE DISCRIMINATOR is `answers == 2`: a registry keyed on the direction
    /// the message TRAVELLED — the obvious way to write it — would look up B's
    /// answers under B's own id space, find nothing, and report `answers: 0`
    /// with two orphans, which is a plausible-looking table about the wrong
    /// side.
    #[test]
    fn an_interest_and_its_answers_are_paired_across_the_flow() {
        let d = wire(&[
            (true, interest_subs(9, true, false, "demo/**")),
            (false, sub_reply(9, "demo/a")),
            (false, sub_reply(9, "demo/b")),
            (false, final_reply(9)),
        ]);
        let census = interests(&d);

        assert_eq!(census.requests().len(), 1, "the QUESTION is seen");
        let r = &census.requests()[0];
        assert_eq!(r.asker, Direction::A, "LOW -> HIGH asked");
        assert_eq!(r.id, 9);
        assert_eq!(r.mode, InterestMode::Current);
        let scope = r.scope.expect("a non-Final interest carries a body");
        assert!(scope.subscribers, "it asked for subscribers");
        assert!(!scope.queryables && !scope.tokens);
        assert!(scope.restricted, "and restricted the ask to a keyexpr");
        assert_eq!(r.keyexpr.as_deref(), Some("demo/**"));
        assert_eq!(r.answers, 2, "BOTH answers are credited to the ASKER");
        assert!(r.closed_at.is_some(), "and the DeclFinal terminated it");
        assert_eq!(census.orphan_answers(), 0);

        // The declarations know what asked for them, which is the half a
        // census of declarations alone cannot state.
        assert_eq!(census.interests().len(), 2);
        for i in census.interests() {
            assert_eq!(i.solicited_by, Some(9), "every one of these was SOLICITED");
        }
        assert!(census.unanswered().is_empty());
        assert!(census.unclosed().is_empty());
        // R311y871 — and the answers were the ones asked for. The control arm
        // for the scope judgement: a check that fired on a correct exchange
        // would be worse than no check at all. Asserted in BOTH builds,
        // because "no divergence" is the claim that must survive the matcher
        // being absent.
        assert!(census.mismatched().is_empty());
        // What the two builds may honestly say differs, and saying so here is
        // what keeps this from being a claim one of them has not earned: with
        // a matcher `demo/**` is evaluated and both answers are IN SCOPE;
        // without one it is undecidable and the right answer is "cannot tell".
        #[cfg(feature = "filter-wildcards")]
        {
            assert_eq!(census.unjudged_answers(), 0);
            assert_eq!(r.answers_in_scope(), 2);
        }
        #[cfg(not(feature = "filter-wildcards"))]
        {
            assert_eq!(census.unjudged_answers(), 2);
            assert_eq!(r.answers_in_scope(), 0);
        }
    }

    /// R311y870 — an `Interest` nobody answered is THE finding about the peer,
    /// and it is not reachable from any count of declarations.
    #[test]
    fn an_interest_nobody_answered_is_its_own_finding() {
        let d = wire(&[(true, interest_subs(3, true, false, "demo/**"))]);
        let census = interests(&d);
        assert_eq!(census.requests().len(), 1);
        assert_eq!(census.requests()[0].answers, 0);
        assert_eq!(census.unanswered(), alloc::vec![0usize]);
        assert!(
            census.unclosed().is_empty(),
            "nothing was answered, so nothing is a truncated answer"
        );
    }

    /// R311y870 — a CURRENT dump with answers and no `DeclFinal` is a FLOOR,
    /// and it is a different finding from having no answer at all.
    ///
    /// Both populations are asserted, so a plane that folded the two would
    /// fail here rather than reporting one of them twice.
    #[test]
    fn a_current_dump_that_never_closed_is_a_floor_and_not_a_silence() {
        let d = wire(&[
            (true, interest_subs(4, true, false, "demo/**")),
            (false, sub_reply(4, "demo/a")),
        ]);
        let census = interests(&d);
        assert_eq!(census.requests()[0].answers, 1);
        assert!(census.requests()[0].closed_at.is_none());
        assert_eq!(census.unclosed(), alloc::vec![0usize]);
        assert!(
            census.unanswered().is_empty(),
            "it WAS answered; what is missing is the terminator"
        );
    }

    /// R311y870 — a FUTURE-only interest is terminated by nothing, so it is
    /// never `unclosed`.
    ///
    /// The discriminator for `expects_a_final`. Without it every correct
    /// future-mode session in every capture would be reported as truncated,
    /// which is the confident-wrong shape this plane exists to avoid.
    #[test]
    fn a_future_only_interest_is_not_reported_as_truncated() {
        let d = wire(&[
            (true, interest_subs(5, false, true, "demo/**")),
            // A future interest's declarations are UNSOLICITED by contract:
            // no interest_id on the envelope.
            (false, declare_sub(1, "demo/a")),
        ]);
        let census = interests(&d);
        assert_eq!(census.requests()[0].mode, InterestMode::Future);
        assert!(
            census.unclosed().is_empty(),
            "nothing terminates a future-mode interest"
        );
        assert_eq!(
            census.interests()[0].solicited_by,
            None,
            "and its declarations are unsolicited, which is not a missing field"
        );
        // It DID get something, so it is not unanswered either -- except that
        // the something carried no id, which is exactly why `unanswered` is
        // judged on `answers` and this arm pins the consequence.
        assert_eq!(census.unanswered(), alloc::vec![0usize]);
    }

    /// R311y870 — `Interest(Final)` cancels the ASKER's own earlier id, and is
    /// not a new request.
    #[test]
    fn an_interest_final_cancels_the_askers_own_request() {
        let d = wire(&[
            (true, interest_subs(6, true, true, "demo/**")),
            (false, sub_reply(6, "demo/a")),
            (false, final_reply(6)),
            (true, interest_final(6)),
        ]);
        let census = interests(&d);
        assert_eq!(
            census.requests().len(),
            1,
            "the Final is a closure, not a second question"
        );
        let r = &census.requests()[0];
        assert_eq!(r.mode, InterestMode::CurrentFuture);
        assert!(r.closed_at.is_some(), "the dump was terminated");
        assert!(r.cancelled_at.is_some(), "and the asker then stopped it");
        assert!(
            r.cancelled_at > r.closed_at,
            "in that order: {:?} then {:?}",
            r.closed_at,
            r.cancelled_at
        );
        assert_eq!(census.orphan_answers(), 0);
    }

    /// R311y870 — an answer naming a question this capture never saw is
    /// COUNTED, which is what a capture begun mid-session looks like.
    #[test]
    fn an_answer_to_a_question_this_capture_never_saw_is_counted() {
        let d = wire(&[(false, sub_reply(77, "demo/a"))]);
        let census = interests(&d);
        assert!(census.requests().is_empty());
        assert_eq!(census.orphan_answers(), 1);
        assert_eq!(
            census.interests()[0].solicited_by,
            Some(77),
            "the declaration still records what it claims to answer"
        );
    }

    /// R311y870 — an interest for keyexpr ALIASES alone is not "unanswered".
    ///
    /// The discriminator for `asks_for_a_declaration`. A `DeclKexpr` binds an
    /// alias and produces no `DeclaredInterest`, so an interest scoped to `K`
    /// can be perfectly served while this plane's `answers` stays 0 — and a
    /// finding that fired on it would fire on ordinary sessions.
    ///
    /// Hand-built, and that is the point rather than a shortcut: every wz
    /// builder in `interest_build` composes `KE | <kinds> | R | N | M`, so wz
    /// cannot emit this shape. An observer meets it from a PEER, and upstream
    /// can emit it (`InterestOptions::KEYEXPRS` is its own constant,
    /// `zenoh-protocol/src/network/interest.rs:249`).
    #[test]
    fn an_interest_for_keyexpr_aliases_alone_is_not_unanswered() {
        let interest = wz_codecs::interest::Interest {
            header: wz_session_core::wire_const::N_MID_INTEREST | 0x20,
            interest_id: 8,
            body: Some(wz_codecs::interest_body::InterestBody {
                header: 0b0000_0001,
                keyexpr: None,
            }),
            extensions: None,
        }
        .encode_to_vec();
        let d = wire(&[(true, interest)]);
        let census = interests(&d);
        let scope = census.requests()[0].scope.expect("a body");
        assert!(scope.keyexprs);
        assert!(!scope.asks_for_a_declaration());
        assert!(
            !scope.restricted,
            "R is clear, so the keyexpr's absence is the ask being unrestricted \
             rather than an alias that failed to resolve"
        );
        assert!(census.requests()[0].unresolved.is_none());
        assert!(
            census.unanswered().is_empty(),
            "an alias interest is served by DeclKexpr, which declares no interest"
        );
    }

    /// R311y870 — the four modes are read off the header the way upstream
    /// writes them, driven through the builders that emit each.
    #[test]
    fn the_four_interest_modes_are_read_the_way_upstream_writes_them() {
        for (current, future, expected) in [
            (true, false, InterestMode::Current),
            (false, true, InterestMode::Future),
            (true, true, InterestMode::CurrentFuture),
        ] {
            let d = wire(&[(true, interest_subs(1, current, future, "demo/**"))]);
            let census = interests(&d);
            assert_eq!(
                census.requests()[0].mode,
                expected,
                "C={current} F={future}"
            );
        }
        // The Final is built by its OWN builder, because passing both bits
        // clear to the others would emit a body the wire says is not there --
        // the trap `build_interest_subscribers` documents.
        let d = wire(&[(true, interest_final(1))]);
        let census = interests(&d);
        assert!(
            census.requests().is_empty(),
            "a Final for an unseen id is a closure with nothing to close"
        );
        assert_eq!(census.orphan_answers(), 1);
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

    fn qbl_reply(interest_id: u64, keyexpr: &str) -> Vec<u8> {
        declare_build::build_declare_queryable_reply(
            interest_id,
            keyexpr,
            wz_session_core::queryable_info::QueryableInfo::DEFAULT,
        )
        .expect("the production reply builder")
        .try_as_borrowed()
        .expect("re-borrow")
        .encode_to_vec()
    }

    /// A `Current` interest for subscribers with `R` CLEAR.
    ///
    /// Hand-built for the reason the keyexpr-alias interest below is: every
    /// builder in `interest_build` composes `KE | <kinds> | R | N | M`, so wz
    /// cannot emit an unrestricted interest and a fixture that asked it to
    /// would be testing the builder rather than the reader. Upstream emits one
    /// whenever `wire_expr` is `None` (`Interest::wire_expr: Option<..>`,
    /// `zenoh-protocol/src/network/interest.rs:143`), which is what an
    /// observer meets.
    fn interest_unrestricted(id: u64) -> Vec<u8> {
        wz_codecs::interest::Interest {
            header: wz_session_core::wire_const::N_MID_INTEREST | 0x20,
            interest_id: id,
            body: Some(wz_codecs::interest_body::InterestBody {
                header: 0b0000_0010,
                keyexpr: None,
            }),
            extensions: None,
        }
        .encode_to_vec()
    }

    /// R311y871 — THE DEFECT on the keyexpr axis. A peer answering a `demo/**`
    /// ask with an `other/thing` subscriber has answered the ID and not the
    /// QUESTION, and before this the plane reported the exchange as served.
    ///
    /// Measured before it was fixed: `answers == 1` and `unanswered()` empty,
    /// with nothing anywhere saying the answer was the wrong one. `answers`
    /// stays 1 here on purpose — the raw count is what a peer CLAIMED, and
    /// changing it would hide the divergence rather than name it.
    #[cfg(feature = "filter-wildcards")]
    #[test]
    fn an_answer_outside_the_restriction_is_a_finding_and_not_an_answer() {
        let d = wire(&[
            (true, interest_subs(9, true, false, "demo/**")),
            (false, sub_reply(9, "other/thing")),
            (false, final_reply(9)),
        ]);
        let census = interests(&d);
        let r = &census.requests()[0];
        assert_eq!(r.keyexpr.as_deref(), Some("demo/**"));
        assert_eq!(r.answers, 1, "the peer did send a declaration for this id");
        assert_eq!(
            r.mismatched,
            alloc::vec![0usize],
            "and it is the declaration at index 0 that was not asked for"
        );
        assert_eq!(r.unjudged_answers, 0, "the pattern was decidable");
        assert_eq!(r.answers_in_scope(), 0, "so NOTHING it asked for came back");
        assert_eq!(census.mismatched(), alloc::vec![0usize]);
        // The two findings stay apart: this peer did not stay silent, it
        // answered wrongly, and a reader acts on those differently.
        assert!(census.unanswered().is_empty());
        assert!(census.unclosed().is_empty(), "the dump WAS terminated");
    }

    /// R311y871 — THE DEFECT on the kind axis, which no keyexpr test reaches.
    ///
    /// A router serves `S`, `Q` and `T` from three separate branches
    /// (`hat/router/interests.rs:60,71,82`), so a queryable answering a
    /// subscribers-only ask is upstream doing something it does not do. This
    /// axis is decidable in EVERY build — the bits are on the wire — which is
    /// why it is not gated on the matcher feature.
    #[test]
    fn an_answer_of_a_kind_nobody_asked_for_is_a_finding() {
        let d = wire(&[
            (true, interest_subs(11, true, false, "demo/a")),
            (false, qbl_reply(11, "demo/a")),
        ]);
        let census = interests(&d);
        let r = &census.requests()[0];
        let scope = r.scope.expect("a body");
        assert!(scope.subscribers && !scope.queryables, "only S was asked");
        assert_eq!(census.interests()[0].kind, InterestKind::Queryable);
        // The keyexpr is a perfect match, so this fires on the kind alone --
        // which is the discriminator against a check that only compared keys.
        assert_eq!(census.interests()[0].keyexpr.as_deref(), Some("demo/a"));
        assert_eq!(r.mismatched, alloc::vec![0usize]);
        assert_eq!(r.answers_in_scope(), 0);
        assert_eq!(census.mismatched(), alloc::vec![0usize]);
    }

    /// R311y871 CONTROL — a wildcard DECLARATION answering a narrower ask is
    /// correct, and a check written with the wrong matcher would call it a
    /// divergence.
    ///
    /// THE DISCRIMINATOR for intersection over pattern-covers-a-literal:
    /// `demo/**` does not "cover" the literal string `demo/1/**`, but the two
    /// patterns intersect, and upstream's `sub.matches(res)` is the intersect
    /// predicate. A plane that reused the coverage join's matcher here would
    /// report every ordinary wildcard session as mismatched — a confident,
    /// plausible, wrong table.
    #[cfg(feature = "filter-wildcards")]
    #[test]
    fn a_wildcard_answer_that_merely_intersects_the_ask_is_in_scope() {
        let d = wire(&[
            (true, interest_subs(12, true, false, "demo/1/**")),
            (false, sub_reply(12, "demo/**")),
            (false, sub_reply(12, "demo/1/pose")),
            (false, final_reply(12)),
        ]);
        let census = interests(&d);
        let r = &census.requests()[0];
        assert_eq!(r.answers, 2);
        assert!(
            r.mismatched.is_empty(),
            "both intersect the ask: {:?}",
            r.mismatched
        );
        assert_eq!(r.unjudged_answers, 0);
        assert_eq!(r.answers_in_scope(), 2);
        assert!(census.mismatched().is_empty());
    }

    /// R311y871 CONTROL — an UNRESTRICTED interest (`R` clear) asks for every
    /// key expression, so no answer can be outside it.
    ///
    /// The arm that separates "asked for everything" from "asked for something
    /// this reader could not resolve": the first is in scope by construction,
    /// the second is unjudged, and both present as a `None` keyexpr.
    #[test]
    fn an_unrestricted_ask_puts_every_answer_in_scope() {
        let d = wire(&[
            (true, interest_unrestricted(13)),
            (false, sub_reply(13, "anything/at/all")),
        ]);
        let census = interests(&d);
        let r = &census.requests()[0];
        let scope = r.scope.expect("a body");
        assert!(!scope.restricted, "R is clear");
        assert!(r.keyexpr.is_none());
        assert!(r.unresolved.is_none(), "and no alias failed to resolve");
        assert!(r.mismatched.is_empty());
        assert_eq!(
            r.unjudged_answers, 0,
            "unrestricted is DECIDED, not unknown"
        );
        assert_eq!(r.answers_in_scope(), 1);
    }

    /// R311y871 — a restriction this reader cannot NAME leaves its answers
    /// UNJUDGED, and the census says so rather than reporting a clean bill of
    /// health.
    ///
    /// A capture begun after the `DeclKexpr` that bound the alias is the
    /// ordinary way to meet this, and it is the shape in which "no divergence
    /// found" would otherwise be indistinguishable from "nothing could be
    /// checked". The mirror case — an ANSWER whose alias did not resolve —
    /// takes the same arm, both halves of the pair being required before the
    /// keyexpr axis can be decided at all.
    #[test]
    fn a_restriction_this_reader_cannot_name_leaves_its_answers_unjudged() {
        let d = wire(&[
            // Restricted to alias 7 + "tail", and no `DeclKexpr` ever bound 7.
            (true, {
                wz_session_core::interest_build::build_interest_subscribers(
                    14,
                    true,
                    false,
                    7,
                    Some("tail"),
                )
                .expect("the production interest builder")
                .try_as_borrowed()
                .expect("re-borrow")
                .encode_to_vec()
            }),
            (false, sub_reply(14, "demo/a")),
        ]);
        let census = interests(&d);
        let r = &census.requests()[0];
        assert_eq!(r.answers, 1);
        assert!(r.keyexpr.is_none(), "the ask could not be named");
        assert_eq!(
            r.unresolved,
            Some((Direction::A, 7)),
            "and the space and id it named are carried"
        );
        assert!(
            r.mismatched.is_empty(),
            "an ask this reader cannot name judges nothing wrong"
        );
        assert_eq!(r.unjudged_answers, 1);
        assert_eq!(census.unjudged_answers(), 1);
        assert_eq!(
            r.answers_in_scope(),
            0,
            "and the in-scope count is not inflated by it"
        );
        assert!(census.mismatched().is_empty());
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

    /// R311y871 — the scope judgement obeys the same rule, and this is the arm
    /// that proves it is a rule rather than a sentence in a doc comment.
    ///
    /// The SAME exchange the wildcard build reports as in-scope must report
    /// here as unjudged: `demo/**` is not a pattern this build can evaluate, so
    /// "the peer answered correctly" is a claim it has not earned. The kind
    /// axis is decidable in every build and is asserted alongside, so a
    /// regression that made the whole judgement fall silent without the
    /// matcher would fail here instead of passing quietly.
    #[test]
    fn an_undecidable_ask_judges_its_answers_neither_way() {
        let interest = wz_session_core::interest_build::build_interest_subscribers(
            21,
            true,
            false,
            0,
            Some("demo/**"),
        )
        .expect("the production interest builder")
        .try_as_borrowed()
        .expect("re-borrow")
        .encode_to_vec();
        let reply = wz_session_core::declare_build::build_declare_subscriber_reply(21, "demo/a")
            .expect("the production reply builder")
            .try_as_borrowed()
            .expect("re-borrow")
            .encode_to_vec();
        let mut d = Dissection::new();
        let unit = frame_carrying(&interest);
        d.push_packet(
            LINKTYPE_ETHERNET,
            0,
            &udp_packet(LOW, 43210, HIGH, 7447, &unit),
        );
        let unit = frame_carrying(&reply);
        d.push_packet(
            LINKTYPE_ETHERNET,
            1,
            &udp_packet(HIGH, 7447, LOW, 43210, &unit),
        );

        let census = interests(&d);
        let r = &census.requests()[0];
        assert_eq!(r.answers, 1);
        assert!(
            r.mismatched.is_empty(),
            "'this build cannot evaluate the ask' is never 'the peer is wrong'"
        );
        assert_eq!(r.unjudged_answers, 1);
        assert_eq!(r.answers_in_scope(), 0);
        assert!(census.mismatched().is_empty());
    }
}
