// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y616 (§1.1f) — the FILTER LANGUAGE: the selector a reader types, turned
//! into a predicate over the records the aggregation planes fold.
//!
//! Every plane before this one answers "what is in this capture". The question
//! a reader actually arrives with is narrower — *what is in this capture ABOUT
//! `demo/**`*, *which queries took longer than a second*, *what is B sending
//! that A is not* — and until now the only way to ask it was to write the fold
//! by hand, which is the same reason [`crate::agg`] exists one layer down.
//!
//! ## The rule this module exists to enforce
//!
//! **A filter that cannot decide says so. It never answers `false`.**
//!
//! A capture is a partial observation by construction: a keyexpr may reference
//! an id whose declaration went past before the tap started, and a capture
//! format may carry no clock at all. A predicate over such a record has three
//! answers, not two, and collapsing the third into "no match" is the exact
//! fabrication this crate refuses everywhere else — the reader would see a
//! filtered total that is quietly short and indistinguishable from one that is
//! whole.
//!
//! So evaluation is Kleene's strong three-valued logic ([`crate::filter::Truth`]), and the
//! undecidable records are COUNTED ([`crate::filter::Selection::undecided`]) rather than
//! silently dropped. Three-valued and not merely "propagate unknown": `unknown
//! AND no` is `no`, because a record that fails the decidable half of a
//! conjunction is out whatever the missing field held. Only where the missing
//! field could still change the answer does the record become undecidable.
//!
//! ## The language
//!
//! ```text
//! filter := or
//! or     := and (("or" | "||") and)*
//! and    := unary (("and" | "&&") unary)*
//! unary  := ("not" | "!") unary | atom
//! atom   := "(" filter ")" | term
//! term   := field op value
//! ```
//!
//! | field | values | operators | undecidable when |
//! |---|---|---|---|
//! | `key` | a keyexpr pattern (`demo/**`) | `==` `!=` | the reference did not resolve |
//! | `dir` | `a` / `b`, either case | `==` `!=` | never |
//! | `kind` | `put` `del` `query` `reply` `err` | `==` `!=` | never |
//! | `bytes` | an integer | `==` `!=` `<` `<=` `>` `>=` | the record carries a payload this build cannot size |
//! | `time` | an integer, ms | `==` `!=` `<` `<=` `>` `>=` | the capture carried no clock |
//! | `elapsed` | an integer, ms since the capture began | `==` `!=` `<` `<=` `>` `>=` | no clock, or the plane was not told the origin |
//! | `offset` | an integer, bytes into the framing unit | `==` `!=` `<` `<=` `>` `>=` | never — every record was walked out of a unit |
//! | `delay` | an integer, ms from the source's stamp to arrival | `==` `!=` `<` `<=` `>` `>=` | no source clock, no arrival clock, or the source's clock is ahead |
//! | `zid` | the zid the record's sender announced, in zenoh's spelling, either case: all of it, or a prefix of eight or more digits | `==` `!=` | this capture never saw the sender name itself, or the value is a prefix that begins more than one zid of the capture |
//! | `replies` | an integer | `==` `!=` `<` `<=` `>` `>=` | the plane does not correlate exchanges |
//! | `errs` | an integer | `==` `!=` `<` `<=` `>` `>=` | as above |
//! | `first_reply` | an integer, ms | `==` `!=` `<` `<=` `>` `>=` | as above, or nothing answered, or no clock |
//! | `completion` | an integer, ms | `==` `!=` `<` `<=` `>` `>=` | as above, or it never closed |
//! | `closed` | `yes` / `no`, or `y` / `n` | `==` `!=` | the plane does not correlate exchanges |
//!
//! The table is the language's field list as it is WRITTEN. The list the
//! parser reads and the one an unknown-field refusal prints are one
//! declaration (`selector_fields!`), and a test holds this table to it by
//! offering the parser every name here.
//!
//! ## R311y636 (§1.1v) — the last five are about the OUTCOME, not the request
//!
//! Everything above the rule was a property of one record AS IT WENT PAST, so a
//! predicate could be answered the instant the record was decoded. The questions
//! a reader actually arrives with are not all of that shape: *which queries went
//! unanswered*, *which took longer than 100ms* are properties of how the
//! exchange TURNED OUT, and no amount of looking at the `Request` decides them.
//!
//! They are not a second language. They are the same one, and what moved is
//! WHEN the single verdict is taken: a plane that correlates exchanges now asks
//! the filter once per exchange **at its close** (or at the end of the flow, for
//! one that never closed), where the request's own fields are all still known
//! and the outcome's are known too. A selector built only from the first five
//! fields therefore gets exactly the verdict it always got — the answer cannot
//! depend on when a question about the request alone is asked.
//!
//! ## And on a plane that does not correlate exchanges, they are UNKNOWN
//!
//! [`crate::agg`] folds records, not exchanges; it has no `replies` to count for
//! the record in its hand. So [`crate::filter::RecordView::outcome`] is `None` there and every
//! outcome term is [`crate::filter::Truth::Unknown`] — the same answer, for the same reason, as
//! a `time` term over a capture with no clock. A reader who points `replies == 0`
//! at the throughput plane sees `undecided == seen` and has been told precisely
//! what happened: the question was well-formed and that plane cannot answer it.
//! Answering `no` would have produced an empty table indistinguishable from a
//! capture with no unanswered queries in it.
//!
//! ## The row documents ask two planes, and say which one answered
//!
//! The selection and field documents write the selector's word on each message
//! row, and a row's records are judged by the plane whose unit they are. A
//! `Request` and the `ResponseFinal` that closes it are an exchange, judged by
//! the exchange plane, so the outcome terms decide on those two rows and a
//! `ResponseFinal` answers every field as the request it closes does. A `Push`
//! and a `Response` are records, judged by the payload plane, where the outcome
//! terms are `undecided` as above. `kind` is the record's own on every row:
//! `kind == reply` picks a `Response` carrying a `Reply` whatever the reply
//! carries.
//!
//! ## R311y638 (§1.1r) — `elapsed` is the one a person can actually type
//!
//! `time` is the capture clock in absolute milliseconds, which is the right
//! thing to compare two captures on and the wrong thing to write by hand: a
//! reader wanting the first five seconds of a file has to look up its epoch
//! first. `elapsed` counts from
//! [`Dissection::capture_origin_ms`](crate::Dissection::capture_origin_ms), so
//! `elapsed < 5000` means what it looks like.
//!
//! It is a SECOND FIELD and not a second syntax on `time`, because the two
//! answer different questions and a reader must be able to see which one a
//! selector asked. The origin is the capture's earliest instant over every
//! PACKET, so a file that opens with traffic this reader cannot decode still
//! starts when the capture tool started.
//!
//! The origin reaches a plane only through the whole-capture entry points
//! ([`aggregate_where`](crate::agg::aggregate_where) and its siblings). A
//! caller folding flows by hand has not said where the capture began, so
//! `elapsed` is [`crate::filter::Truth::Unknown`] there — the same shape as a `time` term
//! over a capture with no clock, and for the same reason.
//!
//! `dir` is `a` / `b` and not `a2b` / `b2a` because
//! [`Direction`](wz_session_core::passive::Direction) is what the rest of the
//! crate says and a second vocabulary for one axis is a second thing to get
//! wrong.
//!
//! What the two words name is an ordering of endpoints and not a role: `a` is
//! the half that travels from a flow's lesser `(address, port)` endpoint
//! (`FlowKey::low`) to its greater, `b` the other. `dir == a` therefore picks
//! the ACCEPTOR's records whenever the acceptor sorts lower, which is the usual
//! shape of a router on a small port and a client on an ephemeral one, and the
//! initiator's when it does not. The language has no term for a role; a reader
//! that needs one reads it off the handshake, where the Init whose `a` flag is
//! clear is the initiator's.
//!
//! `key` matching is zenoh's own — `keyexpr_pattern_matches`, the matcher the
//! subscriber and queryable registries use — rather than a glob written here.
//! A filter language for zenoh traffic that did not speak zenoh's keyexpr
//! dialect would be a second dialect a reader has to learn, and it would
//! disagree with the router about `**` at exactly the interesting cases.
//!
//! ## A zid may be written as a PREFIX, and the CAPTURE decides what it names
//!
//! A reader takes a zid from a list that prints its first eight digits, so
//! `zid == cbf383be` has to mean something. The value is compared with the
//! zids the capture NAMES (the nodes of [`crate::node::NodeCensus`]), through
//! [`crate::filter::Filter::resolved_against`], by four rules.
//!
//! * A value of [`crate::filter::ZID_PREFIX_MIN_DIGITS`] (eight) or more digits that is
//!   a prefix of EXACTLY ONE of the capture's zids names that zid, and the
//!   selector then judges as if the whole zid had been written. A value of
//!   fewer digits is a whole value and is judged as the language always
//!   judged it: it names the zid it spells in full, or none.
//! * The prefix is compared with the zid's WRITTEN SPELLING, the one every
//!   document prints. Zenoh drops one leading zero nibble when it prints a
//!   zid, so a node whose top byte is below `0x10` is shown without it and the
//!   digits a reader copies are the first digits of THAT text, not of the
//!   zero-padded 32-digit form. Either case is read.
//! * A value that spells one of the capture's zids IN FULL names it, whatever
//!   else it is a prefix of. `a1a1a1a1` is the whole id of a node of four
//!   bytes and the first eight digits of another's, and the reader who typed
//!   all of a node's id has named that node: the comparison with a whole value
//!   keeps the behaviour it had.
//! * A prefix that begins TWO OR MORE of the capture's zids is AMBIGUOUS, and
//!   an ambiguous selector JUDGES NOTHING in that capture. `no` would be false
//!   (the reader may have meant either node, and each has records), so every
//!   record is [`crate::filter::Truth::Unknown`] and the selector as a whole is unjudged, not
//!   only the term: the terms around it do not rescue it. The refusal, with
//!   the candidates, is reported beside the verdict
//!   ([`crate::filter::ResolvedFilter::ambiguities`]).
//!
//! The judgement is per CAPTURE: the same text can be ambiguous in one capture
//! and unique in another, because the zids it is compared with are the ones
//! that capture names. A prefix that begins no zid names nothing, and is judged
//! as a whole value that no node announced.
//!
//! It is applied by the whole-capture entry points (they hold the node census),
//! the same shape as the capture origin `elapsed` needs. A caller folding
//! frames by hand has not said which zids the capture names, so for it a value
//! is only ever a whole value.
//!
//! ## Wildcards are a feature, and their absence is a REFUSAL
//!
//! `keyexpr_pattern_matches`' wildcard arms are per-capability features of
//! `wz-session-core`, and with them off a `**` token DEGRADES TO A LITERAL
//! CHUNK — `demo/**` quietly stops matching `demo/a` and matches the literal
//! chunk `**` instead. That degradation is right for an MCU client composing
//! its own matcher and catastrophic for a filter language, where it turns a
//! reader's selector into a silently empty answer.
//!
//! So this module refuses instead: with `filter-wildcards` off, a pattern
//! carrying `*` is a PARSE ERROR ([`crate::filter::FilterErrorKind::WildcardUnsupported`]).
//! The reader is told the build cannot answer their question, which is the one
//! outcome that is never a wrong answer.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use wz_session_core::keyexpr_match::keyexpr_pattern_matches;
use wz_session_core::passive::Direction;

/// Which counter a record moves — the record's kind as a filter can ask about
/// it.
///
/// Deliberately the NETWORK-level kinds and not the wire message names: a
/// reader asks for "the puts", and whether a put arrived inside a `Push` or
/// inside a `Request` is a routing detail of the sender's, not a property of
/// the traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    /// A `MsgPut`, in a `Push` or a `Request`.
    Put,
    /// A `MsgDel`.
    Del,
    /// A `Query`.
    Query,
    /// A `Reply`, whatever it carries — including one carrying a `MsgPut`.
    ///
    /// The kinds partition records exactly as
    /// [`KeyexprCounts`](crate::agg::KeyexprCounts) does, so `kind == reply`
    /// and the `replies` counter can never disagree about the same record. A
    /// reader after reply payloads asks `kind == reply and bytes > 0`.
    Reply,
    /// An `Err`.
    Err,
}

impl RecordKind {
    fn parse(word: &str) -> Option<Self> {
        Some(match word {
            "put" => Self::Put,
            "del" => Self::Del,
            "query" => Self::Query,
            "reply" => Self::Reply,
            "err" => Self::Err,
            _ => return None,
        })
    }
}

/// R311y636 (§1.1v) — how an exchange TURNED OUT, for the terms no `Request`
/// can answer.
///
/// Built by the plane that correlates exchanges ([`crate::exchange`]) at the
/// point the exchange is complete, which is the only point every field below is
/// a fact rather than a guess. Every interval is an `Option` for the reason the
/// rest of this crate keeps them so: an exchange nothing answered has no
/// first-reply interval AT ALL, and reporting `0` for it would put the fastest
/// possible number on the one exchange that never came back.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OutcomeView {
    /// `Response` records carrying a `Reply`.
    pub replies: u64,
    /// `Response` records carrying an `Err`.
    pub errs: u64,
    /// Request to first answer, in ms — `None` when nothing answered, when the
    /// capture carried no clock, or when the clock ran backwards across the
    /// pair.
    pub first_reply_ms: Option<u64>,
    /// Request to close, in ms — `None` for the same three reasons, plus the
    /// fourth: the exchange never closed.
    pub completion_ms: Option<u64>,
    /// Whether a `ResponseFinal` closed it. `false` covers both "the capture
    /// ended first" and "the rid was reused", which is what
    /// [`ExchangeTable::unclosed`](crate::exchange::ExchangeTable::unclosed)
    /// already counts as one thing.
    pub closed: bool,
}

/// One record, as a filter sees it.
///
/// Every optional field is optional for a REASON rather than for convenience,
/// and the reason is the same in each: the observation may not carry the fact. A
/// `None` here is what makes a term over that field undecidable instead of
/// false.
#[derive(Debug, Clone, Copy)]
pub struct RecordView<'a> {
    /// The direction the record travelled.
    pub direction: Direction,
    /// The resolved keyexpr, or `None` when the reference named an id no space
    /// had bound (see [`crate::agg::UnresolvedAlias`]).
    pub keyexpr: Option<&'a str>,
    /// What the record is.
    pub kind: RecordKind,
    /// Application payload bytes present in it, or `None` when the record
    /// carries a payload this build cannot SIZE.
    ///
    /// R311y637 (§1.1w) — `None` is not "no payload". A `Query`'s value rides
    /// an ext whose body is `encoding` then `payload`, and this decoder models
    /// that ext as one opaque ZBUF, so the application half cannot be
    /// separated out. `Some(0)` and `None` are different facts: the first is a
    /// record with nothing in it, the second is a record whose contents are
    /// real and unmeasured. Reporting the second as `0` made `bytes > 0`
    /// answer `no` about traffic that was there.
    pub payload_bytes: Option<u64>,
    /// The capture clock as of the frame that carried it, or `None` when the
    /// capture format carried no timestamp
    /// ([`PassiveFrame::observed_at_ms`](wz_session_core::passive::PassiveFrame::observed_at_ms)).
    pub observed_at_ms: Option<u64>,
    /// R311y638 (§1.1r) — milliseconds from the capture's first instant to
    /// this record's, or `None` when either end is unknown.
    ///
    /// `None` covers two different absences that a filter answers identically:
    /// this record had no clock, or the plane was never told where the capture
    /// began. Both mean the question cannot be decided HERE, which is the only
    /// thing a predicate needs to know.
    pub elapsed_ms: Option<u64>,
    /// R311y641 (§1.1n) — byte offset of this record's message within the
    /// framing unit that carried it, composed from
    /// [`PassiveFrame::unit_offset`](wz_session_core::passive::PassiveFrame::unit_offset),
    /// [`PassiveFrame::batch_offset`](wz_session_core::passive::PassiveFrame::batch_offset)
    /// and the record's own span within the batch.
    ///
    /// `0` is the front of a unit. Anything above it is a record a reader that
    /// treated a framing unit as ONE message would never have seen at all —
    /// which is what R311y631 measured and, until R311y641, could only report
    /// as an ordinal.
    ///
    /// R311y645 (§4.37 / §4.38) — an `Option`, and it was NOT one until this
    /// round, which is the whole of the defect. The number was the record's
    /// offset within its `Frame`'s PAYLOAD while the name said framing unit, so
    /// `offset == 0` selected every record that merely came first inside its own
    /// frame — however deep into the unit that frame began. `None` now covers
    /// the two cases where no wire coordinate exists at all: a batch
    /// decompressed out of an lz4 body and a batch reassembled from several
    /// fragments both index a buffer this reader built, and the old field
    /// reported those buffer offsets as capture ones.
    pub unit_offset: Option<u64>,
    /// R311y644 (§1.1p) — milliseconds from the SOURCE stamping this record to
    /// this observer seeing it, or `None` when the question cannot be answered
    /// here.
    ///
    /// `None` covers three absences a predicate answers identically: the record
    /// carries no source clock (a `Query`, an `Err`, a `Put` with its `T` flag
    /// clear), the capture carried no arrival clock, or the source's stamp is
    /// LATER than the arrival -- which is not a negative delay but proof the two
    /// machines' clocks are offset.
    pub source_delay_ms: Option<u64>,
    /// R311y636 (§1.1v) — the outcome of the exchange this record opened, or
    /// `None` on a plane that does not correlate exchanges.
    ///
    /// `None` is a statement about the PLANE and not about the traffic, which
    /// is why it makes the outcome terms undecidable rather than false: the
    /// throughput plane has not decided that this record's exchange had no
    /// replies, it has decided nothing at all about exchanges.
    pub outcome: Option<OutcomeView>,
    /// R2757 (open debt 790) — the ZID the node that SENT this record
    /// announced, or `None` where this capture never learned one.
    ///
    /// The answer comes from the node plane
    /// ([`crate::node::SessionGrouping`]), carried to the walk as a
    /// [`crate::node::ListContext`]. It is NOT re-derived here, and that is
    /// the same rule `crate::payload` states for `kind`: a second reading is a
    /// second spelling, and two spellings of one record's identity is how the
    /// planes come to disagree about who sent it.
    ///
    /// # What `None` means, and the one thing it does NOT mean
    ///
    /// A [`crate::node::ObservedLink`] exists only where BOTH ends named
    /// themselves with an INIT on one flow, so a capture that began
    /// mid-session has no link for its lists and every record on them answers
    /// `None` here. That is an honest absence — nobody announced an identity
    /// this capture could read — and it is the absence [`Self::keyexpr`]
    /// already spells.
    ///
    /// It does NOT mean "this record had no sender". Reporting a stand-in for
    /// one would put an identity on the wire that nobody sent, which is the
    /// line the consumer's own half-row rule draws from the other side.
    pub zid: Option<&'a [u8]>,
}

/// A three-valued answer.
///
/// [`Self::Unknown`] is not "probably not". It is "this capture does not carry
/// the fact this predicate needs", and it is a distinct outcome all the way out
/// to [`crate::filter::Selection::undecided`] so a reader can see how much of the capture the
/// filter could not speak about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Truth {
    /// The record matches.
    Yes,
    /// The record does not match.
    No,
    /// The capture does not carry what deciding would need.
    Unknown,
}

impl Truth {
    fn of(b: bool) -> Self {
        if b {
            Self::Yes
        } else {
            Self::No
        }
    }

    /// Kleene negation: the unknown stays unknown.
    fn not(self) -> Self {
        match self {
            Self::Yes => Self::No,
            Self::No => Self::Yes,
            Self::Unknown => Self::Unknown,
        }
    }
}

/// How the six comparisons are spelled, once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl Op {
    fn apply(self, lhs: u64, rhs: u64) -> bool {
        match self {
            Self::Eq => lhs == rhs,
            Self::Ne => lhs != rhs,
            Self::Lt => lhs < rhs,
            Self::Le => lhs <= rhs,
            Self::Gt => lhs > rhs,
            Self::Ge => lhs >= rhs,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
        }
    }
}

/// THE SELECTOR'S FIELDS, declared once.
///
/// The parser reads a field's name through [`Field::from_name`] and the
/// unknown-field refusal prints [`Field::ALL`], both out of this one list, so a
/// field cannot be accepted and go unnamed, or be named and refused. They were
/// three hand-written lists (the parser's `match`, the name table a value error
/// reads, and the refusal's sentence) and `zid` was in the first two and not the
/// third, which is the disagreement this replaces.
///
/// A macro rather than a table beside an enum, because the two halves have to
/// be written together: an enum variant with no row would be a field no text can
/// name, and a row with no variant a name the parser cannot act on.
macro_rules! selector_fields {
    ($($variant:ident => $name:literal,)+) => {
        /// A field of the selector language, as the parser reads it.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Field {
            $($variant,)+
        }

        impl Field {
            /// Every field, in the order the refusal lists them.
            const ALL: &'static [Field] = &[$(Field::$variant,)+];

            /// The word a selector writes for this field.
            const fn name(self) -> &'static str {
                match self {
                    $(Field::$variant => $name,)+
                }
            }
        }
    };
}

selector_fields! {
    Key => "key",
    Dir => "dir",
    Kind => "kind",
    Bytes => "bytes",
    Time => "time",
    Elapsed => "elapsed",
    Offset => "offset",
    Delay => "delay",
    Zid => "zid",
    Replies => "replies",
    Errs => "errs",
    FirstReply => "first_reply",
    Completion => "completion",
    Closed => "closed",
}

impl Field {
    /// The field a selector's word names, or `None` for a word the language
    /// does not have. The ONLY way text becomes a field.
    fn from_name(word: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|f| f.name() == word)
    }
}

/// The names of every field of the selector language, in the order the
/// unknown-field refusal prints them.
///
/// For a consumer that holds its own copy of the vocabulary (a header comment,
/// a completion list) to be held to the language by a test, and the walk the
/// refusal's sentence is built from, so the two cannot differ.
pub fn field_names() -> Vec<&'static str> {
    Field::ALL.iter().map(|f| f.name()).collect()
}

/// One comparison, already validated against its field's admissible operators.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Term {
    /// Pattern chunks, pre-split so evaluation does no parsing.
    Key {
        chunks: Vec<String>,
        negated: bool,
    },
    /// R2757 (open debt 790) — the ZID a record's sender announced.
    ///
    /// The wanted value is held as BYTES rather than as the hex the selector
    /// was written in, so evaluation does no parsing and — more to the point —
    /// so `a1a1a1a1` and `A1A1A1A1` are one term rather than two that never
    /// match each other. The record side is bytes already; making the written
    /// side bytes too is what puts the two on one axis.
    ///
    /// The text is kept as well, because what a value NAMES depends on the
    /// capture it is judged in: [`Filter::resolved_against`] reads it as a
    /// prefix of the capture's zids and replaces `want` by the zid it names.
    /// `written` is lower case, the case [`zid_to_zenoh_hex`] prints, and
    /// `span` is the byte range of the value token in the selector, which is
    /// where an ambiguity points.
    ///
    /// [`zid_to_zenoh_hex`]: wz_session_core::zid_hex::zid_to_zenoh_hex
    Zid {
        want: Vec<u8>,
        written: String,
        span: (usize, usize),
        negated: bool,
    },
    Dir {
        want: Direction,
        negated: bool,
    },
    Kind {
        want: RecordKind,
        negated: bool,
    },
    Bytes {
        op: Op,
        value: u64,
    },
    Time {
        op: Op,
        value: u64,
    },
    /// R311y638 (§1.1r) — the same comparison against the capture-relative
    /// clock.
    Elapsed {
        op: Op,
        value: u64,
    },
    /// R311y641 (§1.1n) — the byte-offset axis: where in its framing unit the
    /// record's message began.
    Offset {
        op: Op,
        value: u64,
    },
    /// R311y644 (§1.1p) -- the one-way axis: source stamp to observer arrival.
    Delay {
        op: Op,
        value: u64,
    },
    /// R311y636 (§1.1v) — the outcome axis. One variant per field rather than a
    /// `field: OutcomeField` discriminant carried alongside, so a new outcome
    /// field cannot be added without the match below failing to compile.
    Replies {
        op: Op,
        value: u64,
    },
    Errs {
        op: Op,
        value: u64,
    },
    FirstReply {
        op: Op,
        value: u64,
    },
    Completion {
        op: Op,
        value: u64,
    },
    Closed {
        want: bool,
        negated: bool,
    },
}

impl Term {
    fn eval(&self, record: &RecordView<'_>) -> Truth {
        match self {
            Self::Key { chunks, negated } => match record.keyexpr {
                // The undecidable case, and the one this module exists for: the
                // record HAS a keyexpr, the capture just never carried the
                // declaration that names it. Answering `no` would drop it from
                // the reader's total silently.
                None => Truth::Unknown,
                Some(target) => {
                    let refs: Vec<&str> = chunks.iter().map(|c| c.as_str()).collect();
                    Truth::of(keyexpr_pattern_matches(&refs, target) != *negated)
                }
            },
            // R2757 (open debt 790) — `None` is UNDECIDABLE and not `no`, for
            // the reason the `Key` arm above gives and one more that is this
            // axis's own.
            //
            // A record whose list carried no handshake HAS a sender; this
            // capture just never saw it name itself. Answering `no` would put
            // "we could not tell" and "it was somebody else" in one bucket,
            // and a reader asking `zid == x` would read a silent drop as a
            // measured exclusion. The consumer draws the same line from its
            // side: a half-row is a row whose value was not observed, not a
            // row whose value is absent.
            //
            // ⚠ AND `not zid == x` IS UNDECIDABLE TOO, which is why the
            // negation rides inside rather than wrapping the answer. Negating
            // an unknown gives an unknown: a record whose sender we cannot name
            // cannot be shown to be someone else either.
            // Compared in CANONICAL form. `want` came out of
            // `zenoh_hex_to_zid` and is length-trimmed; a wire zid from a peer
            // that padded it with trailing zero bytes prints as the same text
            // (`zid_to_zenoh_hex` zero-pads to 16), so it must select the same
            // node rather than a second one that reads alike.
            Self::Zid { want, negated, .. } => match record.zid {
                None => Truth::Unknown,
                Some(seen) => Truth::of(
                    (wz_session_core::zid_hex::canonical_zid(seen) == want.as_slice()) != *negated,
                ),
            },
            Self::Dir { want, negated } => {
                Truth::of((dir_index(record.direction) == dir_index(*want)) != *negated)
            }
            Self::Kind { want, negated } => Truth::of((record.kind == *want) != *negated),
            Self::Bytes { op, value } => match record.payload_bytes {
                // R311y637 (§1.1w) — the fifth undecidable case, and the one
                // that had been answering `no` instead: a payload this build
                // cannot size is not a payload of zero bytes.
                None => Truth::Unknown,
                Some(bytes) => Truth::of(op.apply(bytes, *value)),
            },
            Self::Time { op, value } => match record.observed_at_ms {
                // The second undecidable case: pcap carries a timestamp per
                // packet and a raw byte-stream fixture carries none, so a
                // `time` term over a clockless capture is a question this
                // observation cannot answer. R311y615 made this representable
                // by keeping the clock an `Option` all the way up.
                None => Truth::Unknown,
                Some(at) => Truth::of(op.apply(at, *value)),
            },
            // R311y638 (§1.1r) — undecidable for either of two reasons, and
            // deliberately not told apart: a record with no clock and a plane
            // with no origin both leave this question unanswerable here.
            Self::Elapsed { op, value } => match record.elapsed_ms {
                None => Truth::Unknown,
                Some(ms) => Truth::of(op.apply(ms, *value)),
            },
            // R311y645 (§4.37) — the fifth undecidable case, and it was decided
            // wrongly rather than left open until this round: a record walked
            // out of a decompressed or reassembled buffer has an offset into
            // that buffer and none into the capture, so the term declines
            // instead of reporting where the reader's own scratch space put it.
            Self::Offset { op, value } => match record.unit_offset {
                None => Truth::Unknown,
                Some(at) => Truth::of(op.apply(at, *value)),
            },
            // Undecidable for three different reasons the field's doc names,
            // and deliberately not told apart here: each means the question
            // cannot be answered about THIS record.
            Self::Delay { op, value } => match record.source_delay_ms {
                None => Truth::Unknown,
                Some(ms) => Truth::of(op.apply(ms, *value)),
            },
            // R311y636 (§1.1v). The third undecidable case, and the widest: a
            // plane with no exchange correlation carries no outcome at all, so
            // all five say so rather than guessing at a count of zero.
            Self::Replies { op, value } => match record.outcome {
                None => Truth::Unknown,
                Some(o) => Truth::of(op.apply(o.replies, *value)),
            },
            Self::Errs { op, value } => match record.outcome {
                None => Truth::Unknown,
                Some(o) => Truth::of(op.apply(o.errs, *value)),
            },
            // The fourth: an exchange nothing answered has no first-reply
            // interval, so `first_reply > 100` over it is not `no`. Saying `no`
            // would rank the query that never came back among the fast ones.
            // The question a reader means by that is `replies == 0`, and it is
            // decidable.
            Self::FirstReply { op, value } => match record.outcome.and_then(|o| o.first_reply_ms) {
                None => Truth::Unknown,
                Some(ms) => Truth::of(op.apply(ms, *value)),
            },
            Self::Completion { op, value } => match record.outcome.and_then(|o| o.completion_ms) {
                None => Truth::Unknown,
                Some(ms) => Truth::of(op.apply(ms, *value)),
            },
            Self::Closed { want, negated } => match record.outcome {
                None => Truth::Unknown,
                Some(o) => Truth::of((o.closed == *want) != *negated),
            },
        }
    }
}

// R2757 (open debt 790) — `dir_index` used to be spelled here TOO, identically.
// It now lives once, in `crate::agg`, which is where the per-direction pairs it
// indexes are defined; see that function's doc for why a duplicate of a rule
// with this consequence is worth removing rather than keeping in sync.
use crate::agg::dir_index;

/// R2757 (open debt 790) — a ZID as written in a selector, as the bytes a
/// record carries.
///
/// Bare hex in ZENOH'S spelling, no prefix and no separators, either case.
///
/// THE NOTATION IS THE ONE EVERY OTHER SURFACE PRINTS. It used to be
/// the wire order, byte by byte: `0a0b0c0d` meant the bytes `0a 0b 0c 0d`, an
/// even number of digits was required, and it matched what the field document
/// then printed, so a reader could lift a zid off a row into a selector. That
/// spelling is not the one zenohd logs or the one a config file's `id` takes:
/// zenoh prints the little-endian id read as a `u128`, so the same node was
/// `af0b5b89…` in the log and `584f1edb…` in the census. Both documents and this
/// notation now go through [`zid_to_zenoh_hex`] and its inverse, so what a
/// reader copies from a row, a report, a log line or a config is what a selector
/// takes.
///
/// What that changes for a selector typed against the old notation: a leading
/// `0` is refused, exactly as zenohd refuses it in an `id`, and an ODD number of
/// digits is now the ordinary case (`4030201` is a zid; zenoh strips the leading
/// zero nibble when it prints one). A stored `zid == 0a0b0c0d` therefore fails
/// LOUDLY instead of quietly selecting some other node.
///
/// Two departures from [`zenoh_hex_to_zid`], both deliberate because a selector
/// is typed by a reader and not loaded from a config: UPPERCASE is accepted (the
/// selector took either case before, and `A1A1A1A1` and `a1a1a1a1` are one
/// zid), and a leading `+` is not (upstream's config loader takes it as a quirk
/// of `from_str_radix`; nothing here should).
///
/// ⚠ THE EMPTY GUARD IS UNREACHABLE FROM THE PARSER, and it is kept anyway —
/// with the reason stated rather than left to look like a live arm. `zid ==`
/// with nothing after it is refused one level up, by the tokenizer, as
/// `UnexpectedEnd`; measured, not assumed. What the guard buys is that this
/// function is correct on its OWN terms for a second caller that does not come
/// through the grammar.
///
/// [`zid_to_zenoh_hex`]: wz_session_core::zid_hex::zid_to_zenoh_hex
/// [`zenoh_hex_to_zid`]: wz_session_core::zid_hex::zenoh_hex_to_zid
fn parse_zid(value: &str, at: usize) -> Result<Vec<u8>, FilterError> {
    let refuse = || FilterError {
        at,
        kind: FilterErrorKind::UnknownValue {
            field: "zid",
            value: value.to_string(),
        },
    };
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(refuse());
    }
    wz_session_core::zid_hex::zenoh_hex_to_zid(&value.to_ascii_lowercase()).ok_or_else(refuse)
}

/// The parsed expression tree.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    /// The empty filter — every record matches, nothing is undecidable.
    Any,
    /// A selector with a zid prefix that begins more than one zid of the
    /// capture it was resolved against: it judges NOTHING there. Built only by
    /// [`Filter::resolved_against`], never by the parser, so a selector as typed
    /// is never this.
    Ambiguous,
    Or(Vec<Node>),
    And(Vec<Node>),
    Not(alloc::boxed::Box<Node>),
    Term(Term),
}

impl Node {
    fn eval(&self, record: &RecordView<'_>) -> Truth {
        match self {
            Self::Any => Truth::Yes,
            // `no` from a selector whose meaning is not settled would be a
            // measurement of nothing, so the answer is the one that says the
            // record was not judged.
            Self::Ambiguous => Truth::Unknown,
            Self::Term(t) => t.eval(record),
            Self::Not(inner) => inner.eval(record).not(),
            // Kleene conjunction: one decided `No` settles it whatever the rest
            // could not decide. Short-circuiting on `No` is not an optimisation
            // here, it is the semantics — `unknown AND no` must be `no`.
            Self::And(nodes) => {
                let mut unknown = false;
                for n in nodes {
                    match n.eval(record) {
                        Truth::No => return Truth::No,
                        Truth::Unknown => unknown = true,
                        Truth::Yes => {}
                    }
                }
                if unknown {
                    Truth::Unknown
                } else {
                    Truth::Yes
                }
            }
            // The dual: one decided `Yes` settles a disjunction.
            Self::Or(nodes) => {
                let mut unknown = false;
                for n in nodes {
                    match n.eval(record) {
                        Truth::Yes => return Truth::Yes,
                        Truth::Unknown => unknown = true,
                        Truth::No => {}
                    }
                }
                if unknown {
                    Truth::Unknown
                } else {
                    Truth::No
                }
            }
        }
    }
}

/// A compiled selector.
///
/// Parsed once and evaluated per record — the pattern chunk split, the operator
/// dispatch and every value conversion happen at [`Filter::parse`], so the
/// per-record path is a tree walk with no text handling in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    root: Node,
}

impl Default for Filter {
    fn default() -> Self {
        Self::any()
    }
}

impl Filter {
    /// The filter that selects everything.
    ///
    /// The identity the unfiltered entry points pass, so there is ONE fold in
    /// the aggregation planes rather than a filtered one and an unfiltered copy
    /// that drift.
    pub fn any() -> Self {
        Self { root: Node::Any }
    }

    /// `true` when this filter selects everything — an empty selector, or the
    /// literal [`Filter::any`].
    pub fn is_any(&self) -> bool {
        self.root == Node::Any
    }

    /// Compile a selector.
    ///
    /// An empty (or all-whitespace) selector is [`Filter::any`]: the natural
    /// reading of "no filter given", and it keeps a caller wiring a command-line
    /// flag from having to special-case the empty string into a different code
    /// path.
    pub fn parse(source: &str) -> Result<Self, FilterError> {
        let tokens = lex(source)?;
        if tokens.is_empty() {
            return Ok(Self::any());
        }
        let mut parser = Parser {
            tokens: &tokens,
            at: 0,
            end: source.len(),
        };
        let root = parser.expression()?;
        if let Some(tok) = parser.peek() {
            return Err(FilterError {
                at: tok.at,
                kind: FilterErrorKind::TrailingInput,
            });
        }
        Ok(Self { root })
    }

    /// Decide one record.
    pub fn matches(&self, record: &RecordView<'_>) -> Truth {
        self.root.eval(record)
    }

    /// Read this selector against the zids ONE capture names, and say what its
    /// `zid` terms mean there.
    ///
    /// `zids` are the capture's nodes, in the order the capture first named
    /// them (a duplicate, or a spelling of one zid with trailing zero bytes, is
    /// one zid). The rules are the module's, under "A zid may be written as a
    /// PREFIX": a value of [`ZID_PREFIX_MIN_DIGITS`] or more digits that begins
    /// exactly one of them names it, one that spells one in full names that one,
    /// and one that begins two or more is ambiguous.
    ///
    /// The result is a NEW filter and `self` is untouched: a selector is text a
    /// reader typed and compiled once, and it may be judged against more than
    /// one capture, with a different answer in each.
    pub fn resolved_against<Z: AsRef<[u8]>>(&self, zids: &[Z]) -> ResolvedFilter {
        let named = NamedZids::of(zids);
        let mut ambiguities = Vec::new();
        let root = self.root.resolved(&named, &mut ambiguities);
        // An ambiguous term does not leave the REST of the selector standing:
        // `no` from the other terms would be a verdict on a question that was
        // not settled, so the whole filter judges nothing.
        let root = if ambiguities.is_empty() {
            root
        } else {
            Node::Ambiguous
        };
        ResolvedFilter {
            filter: Filter { root },
            ambiguities,
        }
    }
}

/// Fewest digits of a zid a selector's value may have to be read as a PREFIX.
///
/// Eight is what the capture's flow list prints of a zid, which is where the
/// digits come from. Below it a value is a whole zid and nothing else: seven
/// digits are a prefix of too many ids to be a name, and a short value that
/// happened to begin one node would change meaning when a second node joined
/// the capture.
pub const ZID_PREFIX_MIN_DIGITS: usize = 8;

/// A selector read against the zids of one capture: the filter to judge with,
/// and the terms that could not be read.
///
/// See [`Filter::resolved_against`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedFilter {
    filter: Filter,
    ambiguities: Vec<ZidAmbiguity>,
}

impl ResolvedFilter {
    /// The filter to judge this capture's records with.
    ///
    /// Every `zid` term names the zid it was resolved to. When
    /// [`Self::is_ambiguous`] it is a filter that judges NOTHING: every record
    /// is [`Truth::Unknown`].
    pub fn filter(&self) -> &Filter {
        &self.filter
    }

    /// `true` when a `zid` term began more than one of the capture's zids.
    pub fn is_ambiguous(&self) -> bool {
        !self.ambiguities.is_empty()
    }

    /// The terms that began more than one zid, in the order the selector writes
    /// them. Empty for a selector that is not ambiguous in this capture.
    pub fn ambiguities(&self) -> &[ZidAmbiguity] {
        &self.ambiguities
    }

    /// [`Self::ambiguities`], owned.
    pub fn into_ambiguities(self) -> Vec<ZidAmbiguity> {
        self.ambiguities
    }
}

/// One `zid` term whose value begins more than one zid of the capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZidAmbiguity {
    /// Byte offset of the value's first byte in the selector, the unit
    /// [`FilterError::at`] and [`LexedToken::start`] use.
    pub start: usize,
    /// Byte offset one past the value's last byte, as [`LexedToken::end`]. A
    /// quoted value's span includes both quotes, as its token's does.
    pub end: usize,
    /// The digits typed, lower case, which is how the documents print a zid.
    pub prefix: String,
    /// The zids of the capture the prefix begins, in the spelling the
    /// documents print and the order the capture first named them. Two or more.
    pub candidates: Vec<String>,
}

/// The `ambiguous_zid_prefixes` key a document that judged a selector writes
/// when it was ambiguous in the capture, with its leading comma, and NOTHING
/// when it was not: an absent key is how a document says there is no such
/// thing to report, and an empty array would say it looked and found none.
///
/// ONE writer for every document that carries the report, so the census and the
/// selection document cannot differ in the shape of what they say.
pub fn push_ambiguous_zid_prefixes(ambiguities: &[ZidAmbiguity], out: &mut String) {
    if ambiguities.is_empty() {
        return;
    }
    out.push_str(",\"ambiguous_zid_prefixes\":[");
    for (i, a) in ambiguities.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = fmt::Write::write_fmt(
            out,
            format_args!("{{\"start\":{},\"end\":{},\"prefix\":", a.start, a.end),
        );
        wz_session_core::json::escape_into(&a.prefix, out);
        out.push_str(",\"candidates\":[");
        for (j, candidate) in a.candidates.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            wz_session_core::json::escape_into(candidate, out);
        }
        out.push_str("]}");
    }
    out.push(']');
}

/// The zids ONE capture names, each beside the spelling the documents print.
struct NamedZids {
    /// `(canonical wire bytes, written spelling)`, one per distinct spelling, in
    /// the order the capture named them.
    entries: Vec<(Vec<u8>, String)>,
}

/// What a `zid` term's value names in one capture.
enum ZidResolution {
    /// The value is judged as written: it spells a zid in full, or it is too
    /// short to be a prefix, or it begins none.
    AsWritten,
    /// The value is a prefix that begins exactly one zid.
    Names(Vec<u8>),
    /// The value is a prefix that begins several: their spellings.
    Ambiguous(Vec<String>),
}

impl NamedZids {
    fn of<Z: AsRef<[u8]>>(zids: &[Z]) -> Self {
        let mut entries: Vec<(Vec<u8>, String)> = Vec::new();
        for zid in zids {
            let canonical = wz_session_core::zid_hex::canonical_zid(zid.as_ref());
            // Two byte strings that print alike are ONE zid to zenoh (the
            // printed form zero-pads to 16 bytes), so they are one here.
            let spelling = wz_session_core::zid_hex::zid_to_zenoh_hex(canonical);
            if !entries.iter().any(|(_, seen)| *seen == spelling) {
                entries.push((canonical.to_vec(), spelling));
            }
        }
        Self { entries }
    }

    /// `want` is the value parsed as a whole zid and `written` the digits it
    /// was typed with, lower case.
    fn resolve(&self, want: &[u8], written: &str) -> ZidResolution {
        // A whole value is checked FIRST, and it wins over any prefix reading:
        // the reader who typed every digit of a zid named it, and a selector
        // that did so before prefixes existed must keep its meaning.
        if self.entries.iter().any(|(zid, _)| zid == want) || written.len() < ZID_PREFIX_MIN_DIGITS
        {
            return ZidResolution::AsWritten;
        }
        // Against the SPELLING, which has dropped its leading zero nibble, and
        // not against the zero-padded 32-digit form the same id has.
        let begins: Vec<&(Vec<u8>, String)> = self
            .entries
            .iter()
            .filter(|(_, spelling)| spelling.starts_with(written))
            .collect();
        match begins.as_slice() {
            [] => ZidResolution::AsWritten,
            [(zid, _)] => ZidResolution::Names(zid.clone()),
            several => ZidResolution::Ambiguous(
                several
                    .iter()
                    .map(|(_, spelling)| spelling.clone())
                    .collect(),
            ),
        }
    }
}

impl Node {
    /// This tree with every `zid` term read against `named`, and the ones that
    /// could not be read recorded in `found`, left to right as the selector
    /// writes them.
    fn resolved(&self, named: &NamedZids, found: &mut Vec<ZidAmbiguity>) -> Node {
        match self {
            Self::Any => Self::Any,
            Self::Ambiguous => Self::Ambiguous,
            Self::Or(nodes) => Self::Or(nodes.iter().map(|n| n.resolved(named, found)).collect()),
            Self::And(nodes) => Self::And(nodes.iter().map(|n| n.resolved(named, found)).collect()),
            Self::Not(inner) => Self::Not(alloc::boxed::Box::new(inner.resolved(named, found))),
            Self::Term(Term::Zid {
                want,
                written,
                span,
                negated,
            }) => match named.resolve(want, written) {
                ZidResolution::AsWritten => self.clone(),
                ZidResolution::Names(zid) => Self::Term(Term::Zid {
                    want: zid,
                    written: written.clone(),
                    span: *span,
                    negated: *negated,
                }),
                ZidResolution::Ambiguous(candidates) => {
                    found.push(ZidAmbiguity {
                        start: span.0,
                        end: span.1,
                        prefix: written.clone(),
                        candidates,
                    });
                    self.clone()
                }
            },
            Self::Term(_) => self.clone(),
        }
    }
}

/// What a filter did to the records it was shown.
///
/// The accounting is the point rather than a diagnostic: `matched` alone is a
/// number a reader would take for "the traffic about `demo/**`", and it is only
/// that if `undecided` is zero. Carried on the table so the export plane can
/// put it in the document beside the totals it qualifies.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    /// Records the filter said yes to. These are the ones in the rows.
    pub matched: usize,
    /// Records the filter said no to.
    pub rejected: usize,
    /// Records the capture did not carry enough to decide.
    ///
    /// NOT in the rows, and not in `rejected` either: a reader asking "is this
    /// total the whole answer" has to be able to see the difference between a
    /// record that was excluded and a record that could not be judged.
    pub undecided: usize,
}

impl Selection {
    /// Every record the filter was shown.
    pub fn seen(&self) -> usize {
        self.matched + self.rejected + self.undecided
    }

    /// `true` when the filter decided every record it was shown.
    pub fn is_decisive(&self) -> bool {
        self.undecided == 0
    }

    /// Fold one verdict in.
    pub fn record(&mut self, truth: Truth) {
        match truth {
            Truth::Yes => self.matched += 1,
            Truth::No => self.rejected += 1,
            Truth::Unknown => self.undecided += 1,
        }
    }
}

/// Why a selector did not compile.
///
/// Carries the byte offset so a caller can point at the character rather than
/// reprinting the whole selector and leaving the reader to find it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterError {
    /// Byte offset into the source where the problem is, from `0` to the
    /// source's byte length inclusive.
    ///
    /// Every kind but one points AT the byte that is wrong. The exception is
    /// [`FilterErrorKind::UnexpectedEnd`]: the input ran out, so what is wrong
    /// is not a byte of it, and the position is the source's byte length, just
    /// past the last byte, where the next character belongs.
    pub at: usize,
    /// What went wrong.
    pub kind: FilterErrorKind,
}

/// The failure kinds, named rather than stringly-typed so a caller can branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterErrorKind {
    /// A character that cannot begin any token.
    UnexpectedChar(char),
    /// A quoted value with no closing quote.
    UnterminatedQuote,
    /// A field name this language does not have.
    UnknownField(String),
    /// A value this field does not admit (`kind == frobnicate`).
    UnknownValue { field: &'static str, value: String },
    /// An operator this field does not admit (`key >= x`).
    OperatorNotAdmitted {
        field: &'static str,
        op: &'static str,
    },
    /// An integer that did not parse, or overflowed `u64`.
    NotAnInteger(String),
    /// The selector ended in the middle of something. Its position is the
    /// source's byte length: see [`FilterError::at`].
    UnexpectedEnd,
    /// An operator was expected and something else was found.
    ExpectedOperator,
    /// A `(` with no `)`.
    UnclosedGroup,
    /// Input after the expression ended.
    TrailingInput,
    /// A wildcard pattern in a build whose matcher does not wildcard.
    ///
    /// A refusal and NOT a degraded match, for the reason this module's header
    /// gives: the alternative is a selector that silently means something else.
    WildcardUnsupported,
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at byte {}: ", self.at)?;
        match &self.kind {
            FilterErrorKind::UnexpectedChar(c) => write!(f, "unexpected character {c:?}"),
            FilterErrorKind::UnterminatedQuote => write!(f, "unterminated quoted value"),
            // The candidates are the table the parser reads, walked, and not a
            // sentence kept beside it: see `selector_fields!`.
            FilterErrorKind::UnknownField(name) => {
                write!(f, "unknown field {name:?} (known: ")?;
                for (i, field) in Field::ALL.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    f.write_str(field.name())?;
                }
                f.write_str(")")
            }
            FilterErrorKind::UnknownValue { field, value } => {
                write!(f, "{field} does not admit the value {value:?}")
            }
            FilterErrorKind::OperatorNotAdmitted { field, op } => {
                write!(f, "{field} does not admit the operator {op}")
            }
            FilterErrorKind::NotAnInteger(v) => write!(f, "{v:?} is not an unsigned integer"),
            FilterErrorKind::UnexpectedEnd => write!(f, "the selector ends here, unfinished"),
            FilterErrorKind::ExpectedOperator => write!(f, "expected a comparison operator"),
            FilterErrorKind::UnclosedGroup => write!(f, "unclosed ("),
            FilterErrorKind::TrailingInput => write!(f, "unexpected input after the expression"),
            FilterErrorKind::WildcardUnsupported => write!(
                f,
                "this build's keyexpr matcher has no wildcards, so a pattern \
                 containing '*' cannot be answered (feature `filter-wildcards`)"
            ),
        }
    }
}

/// One lexical token plus the byte span it covers.
///
/// `end` joined `at` so the span a token covers is the lexer's
/// answer rather than a consumer's re-derivation; see [`tokens`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    at: usize,
    end: usize,
    kind: TokenKind,
}

/// WHAT A LEXED TOKEN IS, as the closed set a consumer colours by.
///
/// The words are the lexer's own distinctions and no finer: `word` covers a
/// field name and an unquoted value alike, because telling those apart is the
/// parser's knowledge and the parser may never reach a token the lexer
/// produced (the verdict below carries tokens for a selector that failed).
/// `and` covers `and` and `&&`, `or` covers `or` and `||`, `not` covers `not`
/// and `!` — the span says which spelling was typed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenClass {
    /// An unquoted run of word characters that is not a keyword.
    Word,
    /// A quoted value, span including both quotes.
    Quoted,
    /// A comparison operator: `==` `!=` `<` `<=` `>` `>=`.
    Operator,
    /// `not` or `!`.
    Not,
    /// `and` or `&&`.
    And,
    /// `or` or `||`.
    Or,
    /// `(`.
    Open,
    /// `)`.
    Close,
}

impl TokenClass {
    /// The word the selector verdict writes under a token's `kind`.
    pub const fn word(self) -> &'static str {
        match self {
            Self::Word => "word",
            Self::Quoted => "quoted",
            Self::Operator => "operator",
            Self::Not => "not",
            Self::And => "and",
            Self::Or => "or",
            Self::Open => "open",
            Self::Close => "close",
        }
    }

    /// Every word [`Self::word`] can return. The exhaustive match in
    /// `Self::of` is what breaks when the lexer gains a token kind, and this
    /// list is what the declared value family is held to.
    pub fn names() -> Vec<&'static str> {
        [
            Self::Word,
            Self::Quoted,
            Self::Operator,
            Self::Not,
            Self::And,
            Self::Or,
            Self::Open,
            Self::Close,
        ]
        .into_iter()
        .map(Self::word)
        .collect()
    }

    fn of(kind: &TokenKind) -> Self {
        match kind {
            TokenKind::Word(_) => Self::Word,
            TokenKind::Quoted(_) => Self::Quoted,
            TokenKind::Op(_) => Self::Operator,
            TokenKind::Not => Self::Not,
            TokenKind::And => Self::And,
            TokenKind::Or => Self::Or,
            TokenKind::Open => Self::Open,
            TokenKind::Close => Self::Close,
        }
    }
}

/// One token as a consumer sees it: a BYTE span and a class.
///
/// `start..end` are byte offsets into the selector, the same unit as
/// [`FilterError::at`], so a caret and a colour run are placed by one rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LexedToken {
    /// Byte offset of the token's first byte.
    pub start: usize,
    /// Byte offset one past the token's last byte.
    pub end: usize,
    /// What the lexer took it for.
    pub class: TokenClass,
}

/// The selector verdict `wz_dissect_selector_diagnose` hands back, rendered
/// HERE rather than in the ABI crate.
///
/// Moved beside the revision that declares it. The document's
/// value family (`kind`) is declared in [`crate::doc_revision`], and the gate
/// that derives each family's carries verdict renders every document that
/// declares one. An emitter in another crate is one that gate cannot render,
/// so the verdict it checks would be a claim with no measurement behind it —
/// the shape `fields_json` and `census_json` already avoid by living here.
///
/// `{envelope,"ok":true,"tokens":[…]}`, or
/// `{envelope,"ok":false,"at":N,"message":"…","tokens":[…]}` with `at` a BYTE
/// offset: the byte that is wrong, or for a selector that ends unfinished its
/// byte length (see [`FilterError::at`]). The tokens close both branches, and
/// their spans do not depend on where the refusal is; see [`tokens`].
pub fn diagnose_json(expr: &str) -> String {
    let mut out = String::from("{");
    crate::doc_revision::envelope_into(crate::doc_revision::SELECTOR_DIAGNOSE, &mut out);
    match Filter::parse(expr) {
        Ok(_) => out.push_str(",\"ok\":true"),
        Err(e) => {
            let _ = fmt::Write::write_fmt(&mut out, format_args!(",\"ok\":false,\"at\":{}", e.at));
            out.push_str(",\"message\":");
            // The SAME escaper the census document uses: a message quotes the
            // operator's own text back (an unknown field name, a bad value), so
            // it carries whatever they typed.
            wz_session_core::json::escape_into(&e.to_string(), &mut out);
        }
    }
    out.push_str(",\"tokens\":[");
    for (i, t) in tokens(expr).into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "{{\"start\":{},\"end\":{},\"kind\":\"{}\"}}",
                t.start,
                t.end,
                t.class.word()
            ),
        );
    }
    out.push_str("]}");
    out
}

/// THE LEXER'S TOKENS, for a consumer that colours a selector.
///
/// The same walk [`Filter::parse`] runs, so a colouring and a verdict cannot
/// disagree about where a token begins. On a LEXICAL failure it returns every
/// token lexed before the failure and stops there: a selector being typed is
/// mostly well-formed, and colouring nothing because its last character is an
/// unclosed quote would make the colouring useless at exactly the moment it is
/// read. Where it stopped is [`Filter::parse`]'s `at`, not this function's to
/// repeat.
pub fn tokens(source: &str) -> Vec<LexedToken> {
    let mut out = Vec::new();
    // The error is deliberately dropped: it is the verdict's to report.
    let _ = lex_into(source, &mut out);
    out.into_iter()
        .map(|t| LexedToken {
            start: t.at,
            end: t.end,
            class: TokenClass::of(&t.kind),
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    Word(String),
    /// A quoted value — never re-read as a keyword, so `key == "or"` works.
    Quoted(String),
    Op(Op),
    Not,
    And,
    Or,
    Open,
    Close,
}

/// Characters that may appear unquoted in a word.
///
/// A superset of what a keyexpr chunk admits (`$*` for the substring DSL, `@`
/// for the admin prefix, `#`/`?` because a selector value is not always a
/// keyexpr) minus everything the grammar itself uses. Anything outside it is
/// still expressible — in quotes.
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric()
        || matches!(
            c,
            '/' | '*' | '$' | '-' | '_' | '.' | '@' | '#' | '?' | '%' | '+' | ':' | ','
        )
}

/// R2174 (open-debt item 551) — THE WALK IS OVER CHARACTERS, AND `at` STAYS A
/// BYTE OFFSET.
///
/// # What this replaced, and why it could not be patched in place
///
/// This function used to walk `source.as_bytes()` and turn each byte into a
/// `char` with `as`. That is not a UTF-8 decode, it is a LATIN-1
/// REINTERPRETATION: a UTF-8 lead byte `0xC2..=0xF4` becomes `'Â'..'ô'`, most
/// of which `char::is_alphanumeric` accepts, so the word scan stepped INTO a
/// multi-byte character; the continuation bytes `0x80..=0xBF` mostly are not,
/// so it stopped one byte in; and `&source[i..j]` then sliced off a char
/// boundary and PANICKED. Across `extern "C"` that panic could not even unwind
/// -- a consumer measured `abort`, exit 134, from
/// `wz_dissect_selector_diagnose`, the one door this header documents as the
/// one to call WHILE AN OPERATOR IS TYPING.
///
/// No local guard fixes that class. Rejecting high bytes in `is_word_char`
/// would have passed the reported Korean selectors and still mis-lexed `€`,
/// whose lead byte is alphanumeric while the character is not. The cast itself
/// is the defect, so the walk yields `char`s.
///
/// # `at` is unchanged, and that is a published contract
///
/// `wz_dissect.h` publishes `at` as a BYTE offset and a consumer places a caret
/// from it. So `i` remains a byte index into `source` -- it is advanced by
/// `len_utf8()` rather than by one -- and every `at` this emits still counts
/// bytes. Switching to character counts would have made slicing safe and moved
/// every caret in every selector containing a multi-byte character.
///
/// `i` is a char boundary at every iteration by construction: each arm below
/// advances by whole characters.
fn lex(source: &str) -> Result<Vec<Token>, FilterError> {
    let mut tokens = Vec::new();
    lex_into(source, &mut tokens)?;
    Ok(tokens)
}

/// The walk behind [`lex`], writing into `tokens` as it goes so that a caller
/// who wants what was lexed BEFORE a failure — [`tokens`], colouring a
/// half-typed selector — reads it from the same walk rather than a second one.
fn lex_into(source: &str, tokens: &mut Vec<Token>) -> Result<(), FilterError> {
    let mut i = 0usize;
    while i < source.len() {
        let c = source[i..]
            .chars()
            .next()
            .expect("i is below len and on a char boundary");
        let clen = c.len_utf8();
        if c.is_ascii_whitespace() {
            i += clen;
            continue;
        }
        let at = i;
        match c {
            '(' => {
                tokens.push(Token {
                    at,
                    end: at + clen,
                    kind: TokenKind::Open,
                });
                i += clen;
            }
            ')' => {
                tokens.push(Token {
                    at,
                    end: at + clen,
                    kind: TokenKind::Close,
                });
                i += clen;
            }
            '"' | '\'' => {
                let quote = c;
                let start = i + clen;
                // The quoted arm SURVIVED the old walk by accident -- no UTF-8
                // byte equals 0x22 or 0x27, so the byte scan happened to stop
                // exactly on the closing quote. It is walked by characters here
                // anyway: an accident that holds is still an accident, and the
                // next person to touch this loop should not have to rediscover
                // why the one above it was fatal and this one was not.
                let mut j = start;
                let mut closed = false;
                for ch in source[start..].chars() {
                    if ch == quote {
                        closed = true;
                        break;
                    }
                    j += ch.len_utf8();
                }
                if !closed {
                    return Err(FilterError {
                        at,
                        kind: FilterErrorKind::UnterminatedQuote,
                    });
                }
                tokens.push(Token {
                    at,
                    end: j + quote.len_utf8(),
                    kind: TokenKind::Quoted(source[start..j].to_string()),
                });
                i = j + quote.len_utf8();
            }
            '=' | '!' | '<' | '>' | '&' | '|' => {
                let two = source.get(i..i + 2).unwrap_or("");
                let (kind, width) = match (c, two) {
                    (_, "==") => (TokenKind::Op(Op::Eq), 2),
                    (_, "!=") => (TokenKind::Op(Op::Ne), 2),
                    (_, "<=") => (TokenKind::Op(Op::Le), 2),
                    (_, ">=") => (TokenKind::Op(Op::Ge), 2),
                    (_, "&&") => (TokenKind::And, 2),
                    (_, "||") => (TokenKind::Or, 2),
                    ('<', _) => (TokenKind::Op(Op::Lt), 1),
                    ('>', _) => (TokenKind::Op(Op::Gt), 1),
                    ('!', _) => (TokenKind::Not, 1),
                    // A lone `=`, `&` or `|`: named as the character it is
                    // rather than silently taken for the two-character form,
                    // which would make `a = b` mean something the reader did
                    // not write.
                    _ => {
                        return Err(FilterError {
                            at,
                            kind: FilterErrorKind::UnexpectedChar(c),
                        })
                    }
                };
                tokens.push(Token {
                    at,
                    end: at + width,
                    kind,
                });
                i += width;
            }
            c if is_word_char(c) => {
                let mut j = i;
                for ch in source[i..].chars() {
                    if !is_word_char(ch) {
                        break;
                    }
                    j += ch.len_utf8();
                }
                let word = &source[i..j];
                let kind = match word {
                    "and" => TokenKind::And,
                    "or" => TokenKind::Or,
                    "not" => TokenKind::Not,
                    _ => TokenKind::Word(word.to_string()),
                };
                tokens.push(Token { at, end: j, kind });
                i = j;
            }
            _ => {
                return Err(FilterError {
                    at,
                    kind: FilterErrorKind::UnexpectedChar(c),
                })
            }
        }
    }
    Ok(())
}

struct Parser<'a> {
    tokens: &'a [Token],
    at: usize,
    /// The byte length of the source: where an input that ran out is refused.
    end: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&'a Token> {
        self.tokens.get(self.at)
    }

    fn next(&mut self) -> Option<&'a Token> {
        let t = self.tokens.get(self.at);
        if t.is_some() {
            self.at += 1;
        }
        t
    }

    /// Where an input that RAN OUT is refused: just past its last byte.
    ///
    /// The start of the last token is where the thing the reader was typing
    /// began, and `UnexpectedEnd` is not about that thing. It says the selector
    /// stopped before it was finished, so the place that is wrong is the place
    /// the next character belongs. That is the byte length of the whole input,
    /// trailing whitespace included: the reader typed it, and the next
    /// character goes after it.
    fn end_offset(&self) -> usize {
        self.end
    }

    fn expression(&mut self) -> Result<Node, FilterError> {
        let mut nodes = alloc::vec![self.conjunction()?];
        while matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Or)) {
            self.at += 1;
            nodes.push(self.conjunction()?);
        }
        Ok(if nodes.len() == 1 {
            nodes.pop().expect("just checked length")
        } else {
            Node::Or(nodes)
        })
    }

    fn conjunction(&mut self) -> Result<Node, FilterError> {
        let mut nodes = alloc::vec![self.unary()?];
        while matches!(self.peek().map(|t| &t.kind), Some(TokenKind::And)) {
            self.at += 1;
            nodes.push(self.unary()?);
        }
        Ok(if nodes.len() == 1 {
            nodes.pop().expect("just checked length")
        } else {
            Node::And(nodes)
        })
    }

    fn unary(&mut self) -> Result<Node, FilterError> {
        if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Not)) {
            self.at += 1;
            return Ok(Node::Not(alloc::boxed::Box::new(self.unary()?)));
        }
        self.atom()
    }

    fn atom(&mut self) -> Result<Node, FilterError> {
        let open_at = match self.peek() {
            None => {
                return Err(FilterError {
                    at: self.end_offset(),
                    kind: FilterErrorKind::UnexpectedEnd,
                })
            }
            Some(t) => t.at,
        };
        if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Open)) {
            self.at += 1;
            let inner = self.expression()?;
            match self.next() {
                Some(Token {
                    kind: TokenKind::Close,
                    ..
                }) => Ok(inner),
                _ => Err(FilterError {
                    at: open_at,
                    kind: FilterErrorKind::UnclosedGroup,
                }),
            }
        } else {
            self.term()
        }
    }

    fn term(&mut self) -> Result<Node, FilterError> {
        let (field_at, field) = match self.next() {
            Some(Token {
                at,
                kind: TokenKind::Word(w),
                ..
            }) => (*at, w.clone()),
            Some(t) => {
                return Err(FilterError {
                    at: t.at,
                    kind: FilterErrorKind::UnknownField(describe_token(&t.kind)),
                })
            }
            None => {
                return Err(FilterError {
                    at: self.end_offset(),
                    kind: FilterErrorKind::UnexpectedEnd,
                })
            }
        };

        let (op_at, op) = match self.next() {
            Some(Token {
                at,
                kind: TokenKind::Op(op),
                ..
            }) => (*at, *op),
            Some(t) => {
                return Err(FilterError {
                    at: t.at,
                    kind: FilterErrorKind::ExpectedOperator,
                })
            }
            None => {
                return Err(FilterError {
                    at: self.end_offset(),
                    kind: FilterErrorKind::UnexpectedEnd,
                })
            }
        };

        let (value_at, value_end, value) = match self.next() {
            Some(Token {
                at,
                end,
                kind: TokenKind::Word(w) | TokenKind::Quoted(w),
            }) => (*at, *end, w.clone()),
            Some(t) => {
                return Err(FilterError {
                    at: t.at,
                    kind: FilterErrorKind::UnknownValue {
                        field: Field::from_name(&field).map_or("value", Field::name),
                        value: describe_token(&t.kind),
                    },
                })
            }
            None => {
                return Err(FilterError {
                    at: self.end_offset(),
                    kind: FilterErrorKind::UnexpectedEnd,
                })
            }
        };

        // The ONE place text becomes a field: a word the table does not hold is
        // refused here, so the `match` below can only ever see a field the
        // refusal's list names. An arm added to it for a word the table lacks
        // would be unreachable rather than a field the message omits.
        let Some(known) = Field::from_name(&field) else {
            return Err(FilterError {
                at: field_at,
                kind: FilterErrorKind::UnknownField(field),
            });
        };
        let term = match known {
            Field::Key => {
                let negated = equality_negation(op, known.name(), op_at)?;
                Term::Key {
                    chunks: compile_pattern(&value, value_at)?,
                    negated,
                }
            }
            // R2757 (open debt 790) — the node axis the consumer asked for.
            //
            // The notation is BARE HEX with no prefix and no separators, and
            // that is a measurement rather than a preference: the consuming
            // viewer renders a zid as exactly these characters, so a reader can
            // lift one off a row and drop it into a selector without
            // re-typing it. A `0x` prefix or a colon-separated form would have
            // made the two surfaces disagree about one value.
            //
            // "these characters" is ZENOH'S spelling now, and was the
            // wire order until a consumer found the census and the zenohd log
            // naming one node two ways. See `parse_zid` for what changed.
            //
            // The value is kept as the digits typed (lower case) beside the
            // bytes it parses to, because a value of eight digits or more may
            // be a PREFIX, and which zid a prefix names is the capture's to
            // say: see `Filter::resolved_against`.
            Field::Zid => {
                let negated = equality_negation(op, known.name(), op_at)?;
                Term::Zid {
                    want: parse_zid(&value, value_at)?,
                    written: value.to_ascii_lowercase(),
                    span: (value_at, value_end),
                    negated,
                }
            }
            Field::Dir => {
                let negated = equality_negation(op, known.name(), op_at)?;
                let want = match value.as_str() {
                    "a" | "A" => Direction::A,
                    "b" | "B" => Direction::B,
                    _ => {
                        return Err(FilterError {
                            at: value_at,
                            kind: FilterErrorKind::UnknownValue {
                                field: known.name(),
                                value,
                            },
                        })
                    }
                };
                Term::Dir { want, negated }
            }
            Field::Kind => {
                let negated = equality_negation(op, known.name(), op_at)?;
                let want = RecordKind::parse(&value).ok_or(FilterError {
                    at: value_at,
                    kind: FilterErrorKind::UnknownValue {
                        field: known.name(),
                        value: value.clone(),
                    },
                })?;
                Term::Kind { want, negated }
            }
            Field::Bytes => Term::Bytes {
                op,
                value: integer(&value, value_at)?,
            },
            Field::Time => Term::Time {
                op,
                value: integer(&value, value_at)?,
            },
            Field::Elapsed => Term::Elapsed {
                op,
                value: integer(&value, value_at)?,
            },
            Field::Offset => Term::Offset {
                op,
                value: integer(&value, value_at)?,
            },
            Field::Delay => Term::Delay {
                op,
                value: integer(&value, value_at)?,
            },
            Field::Replies => Term::Replies {
                op,
                value: integer(&value, value_at)?,
            },
            Field::Errs => Term::Errs {
                op,
                value: integer(&value, value_at)?,
            },
            Field::FirstReply => Term::FirstReply {
                op,
                value: integer(&value, value_at)?,
            },
            Field::Completion => Term::Completion {
                op,
                value: integer(&value, value_at)?,
            },
            Field::Closed => {
                let negated = equality_negation(op, known.name(), op_at)?;
                // `yes` / `no` and not `true` / `false`: the reader is asking
                // about what the capture showed, and this crate's own vocabulary
                // for a three-valued answer already spends `true`. A bare
                // `closed` with no value would have been shorter and would have
                // made `closed` the one field with a second grammar.
                let want = match value.as_str() {
                    "yes" | "y" => true,
                    "no" | "n" => false,
                    _ => {
                        return Err(FilterError {
                            at: value_at,
                            kind: FilterErrorKind::UnknownValue {
                                field: known.name(),
                                value,
                            },
                        })
                    }
                };
                Term::Closed { want, negated }
            }
        };
        Ok(Node::Term(term))
    }
}

/// `==` / `!=` only, answering whether the term is negated.
fn equality_negation(op: Op, field: &'static str, at: usize) -> Result<bool, FilterError> {
    match op {
        Op::Eq => Ok(false),
        Op::Ne => Ok(true),
        other => Err(FilterError {
            at,
            kind: FilterErrorKind::OperatorNotAdmitted {
                field,
                op: other.as_str(),
            },
        }),
    }
}

fn integer(value: &str, at: usize) -> Result<u64, FilterError> {
    value.parse::<u64>().map_err(|_| FilterError {
        at,
        kind: FilterErrorKind::NotAnInteger(value.to_string()),
    })
}

/// Split a keyexpr pattern into the chunks `keyexpr_pattern_matches` wants,
/// refusing what this build's matcher cannot answer.
fn compile_pattern(pattern: &str, at: usize) -> Result<Vec<String>, FilterError> {
    // The refusal, and it is deliberately at PARSE time rather than at match
    // time: a reader who typed a wildcard learns immediately that this build
    // cannot answer, instead of reading an empty table and concluding the
    // traffic was not there.
    #[cfg(not(feature = "filter-wildcards"))]
    if pattern.contains('*') {
        return Err(FilterError {
            at,
            kind: FilterErrorKind::WildcardUnsupported,
        });
    }
    let _ = at;
    Ok(pattern.split('/').map(|c| c.to_string()).collect())
}

fn describe_token(kind: &TokenKind) -> String {
    match kind {
        TokenKind::Word(w) | TokenKind::Quoted(w) => w.clone(),
        TokenKind::Op(op) => op.as_str().to_string(),
        TokenKind::Not => "not".to_string(),
        TokenKind::And => "and".to_string(),
        TokenKind::Or => "or".to_string(),
        TokenKind::Open => "(".to_string(),
        TokenKind::Close => ")".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view<'a>(
        direction: Direction,
        keyexpr: Option<&'a str>,
        kind: RecordKind,
        payload_bytes: u64,
        observed_at_ms: Option<u64>,
    ) -> RecordView<'a> {
        RecordView {
            direction,
            keyexpr,
            kind,
            payload_bytes: Some(payload_bytes),
            observed_at_ms,
            // R2757 (open debt 790) — `None`, on the same rule the line below
            // states for the capture origin: a helper's default should put a
            // new axis in its UNDECIDABLE state, so a pre-existing test that
            // says nothing about nodes keeps saying nothing. A test that means
            // to drive this axis writes `RecordView { zid: Some(..), ..view(..) }`
            // and is visibly the one that cares.
            zid: None,
            // The default is a plane that was never told the capture origin,
            // so every pre-existing test below drives the undecidable arm.
            elapsed_ms: None,
            unit_offset: Some(0),
            source_delay_ms: None,
            // The default is the NON-correlating plane, so every pre-existing
            // test below drives the view the throughput plane builds.
            outcome: None,
        }
    }

    fn put(keyexpr: Option<&str>) -> RecordView<'_> {
        view(Direction::A, keyexpr, RecordKind::Put, 10, Some(100))
    }

    /// The empty selector is the identity, and it decides everything —
    /// including the records every other filter would have to call
    /// undecidable.
    #[test]
    fn an_empty_selector_selects_everything_and_decides_it() {
        for source in ["", "   ", "\t\n"] {
            let f = Filter::parse(source).expect("empty parses");
            assert!(f.is_any(), "{source:?}");
            assert_eq!(f.matches(&put(Some("demo/a"))), Truth::Yes);
            // No keyexpr, no clock: still decided, because nothing is asked.
            assert_eq!(f.matches(&put(None)), Truth::Yes);
        }
        assert!(Filter::any().is_any());
    }

    /// THE RULE. A record whose keyexpr the capture never bound is UNKNOWN, not
    /// `No` — and the difference is visible in the accounting rather than only
    /// in the enum.
    #[test]
    fn a_record_whose_keyexpr_never_resolved_is_undecided_rather_than_rejected() {
        let f = Filter::parse("key == demo/a").expect("parses");
        assert_eq!(f.matches(&put(Some("demo/a"))), Truth::Yes);
        assert_eq!(f.matches(&put(Some("other/b"))), Truth::No);
        assert_eq!(f.matches(&put(None)), Truth::Unknown);

        let mut sel = Selection::default();
        sel.record(f.matches(&put(Some("demo/a"))));
        sel.record(f.matches(&put(Some("other/b"))));
        sel.record(f.matches(&put(None)));
        assert_eq!(sel.matched, 1);
        assert_eq!(sel.rejected, 1);
        assert_eq!(sel.undecided, 1);
        assert_eq!(sel.seen(), 3);
        assert!(!sel.is_decisive());
    }

    /// R2757 (open debt 790) — THE SAME RULE ON THE NODE AXIS, and it is the
    /// arm the integration witness in `crate::agg` cannot reach.
    ///
    /// That witness grades SELECTION over a real capture, so it sees the `Yes`
    /// and the absence of a match. It cannot tell `No` from `Unknown`, because
    /// both leave a record out of the count — which is exactly the confusion
    /// this arm exists to prevent, so it has to be graded here where the three
    /// answers are three values rather than one number.
    #[test]
    fn a_record_whose_node_never_named_itself_is_undecided_rather_than_rejected() {
        let f = Filter::parse("zid == a1a1a1a1").expect("parses");
        let with = |zid: Option<&'static [u8]>| RecordView {
            zid,
            ..put(Some("demo/a"))
        };

        assert_eq!(f.matches(&with(Some(&[0xA1; 4]))), Truth::Yes);
        assert_eq!(f.matches(&with(Some(&[0xB2; 4]))), Truth::No);
        // The record HAS a sender. This capture never saw it name itself.
        assert_eq!(f.matches(&with(None)), Truth::Unknown);

        let mut sel = Selection::default();
        sel.record(f.matches(&with(Some(&[0xA1; 4]))));
        sel.record(f.matches(&with(Some(&[0xB2; 4]))));
        sel.record(f.matches(&with(None)));
        assert_eq!(sel.matched, 1);
        assert_eq!(sel.rejected, 1);
        assert_eq!(sel.undecided, 1, "an unnamed node is not a rejected one");
        assert!(!sel.is_decisive());
    }

    /// R2757 — NEGATING AN UNKNOWN IS STILL UNKNOWN, which is the arm a
    /// negation applied OUTSIDE the term would get wrong.
    ///
    /// `not zid == x` asks "was this somebody else". A record whose sender this
    /// capture never saw cannot be shown to be somebody else any more than it
    /// can be shown to be `x`, so the honest answer is the same one. Had the
    /// negation wrapped the term's verdict instead of riding inside it, this
    /// record would have answered `Yes` — reporting every unidentified record
    /// as positively not the node asked about.
    #[test]
    fn negating_the_node_term_does_not_turn_an_unknown_into_an_answer() {
        let f = Filter::parse("not zid == a1a1a1a1").expect("parses");
        let with = |zid: Option<&'static [u8]>| RecordView {
            zid,
            ..put(Some("demo/a"))
        };

        assert_eq!(f.matches(&with(Some(&[0xB2; 4]))), Truth::Yes);
        assert_eq!(f.matches(&with(Some(&[0xA1; 4]))), Truth::No);
        assert_eq!(
            f.matches(&with(None)),
            Truth::Unknown,
            "an unnamed sender is not evidence of being a different sender"
        );
    }

    /// R2757 — THE WRITTEN FORM IS BYTES, so the two spellings of one zid are
    /// ONE term rather than two that never match each other.
    ///
    /// A selector holding the hex as a STRING would compare `a1a1a1a1` against
    /// a record's bytes by first rendering them, and every such rendering picks
    /// a case. Whichever it picked, the other spelling would silently select
    /// nothing — which reads as a measurement about the capture rather than
    /// about the notation.
    #[test]
    fn a_node_is_the_same_node_in_either_case_of_hex() {
        let lower = Filter::parse("zid == a1a1a1a1").expect("parses");
        let upper = Filter::parse("zid == A1A1A1A1").expect("parses");
        let record = RecordView {
            zid: Some(&[0xA1; 4]),
            ..put(Some("demo/a"))
        };
        assert_eq!(lower.matches(&record), Truth::Yes);
        assert_eq!(upper.matches(&record), Truth::Yes);
    }

    /// R2757 — WHAT THE NOTATION REFUSES, each for its own reason.
    ///
    /// Separate cases rather than one "malformed" assertion, because they are
    /// different mistakes: a `0x` or a colon form has brought a convention from
    /// another tool, a non-hex digit is a typo, and each refusal is BY NAME so
    /// the message says which term was wrong rather than only that something
    /// was.
    ///
    /// The list is zenoh's refusals now. An ODD digit count LEFT it
    /// (it is how zenoh prints a zid whose top nibble is zero, so `a1a1a1a` is a
    /// zid), and three spellings ARRIVED: a leading `0` (`01020304`, the old
    /// per-byte spelling of `1 2 3 4`, which zenohd refuses in an `id` and which
    /// would otherwise have quietly meant a DIFFERENT node), a leading `+` (an
    /// upstream quirk of the config loader that a selector should not take), and
    /// a value past 32 digits, which is more than the 16 bytes a zid can be.
    ///
    /// ⚠ EMPTY IS NOT IN THIS LIST, and finding out why corrected this term's
    /// own documentation. `zid ==` with nothing after it never reaches
    /// `parse_zid`: the TOKENIZER refuses it first, as `UnexpectedEnd`. That is
    /// a correct refusal from the right layer, so it is asserted below as the
    /// different thing it is rather than folded in here — and `parse_zid`'s
    /// empty guard is documented as unreachable-from-the-grammar instead of
    /// being presented as the arm that catches this.
    #[test]
    fn the_node_notation_refuses_what_it_cannot_read() {
        let too_long = alloc::format!("1{}", "0".repeat(32));
        for bad in [
            "0xa1a1a1a1",
            "a1a1a1ag",
            "a1:a1:a1:a1",
            "01020304",
            "0",
            "+1",
            too_long.as_str(),
        ] {
            let parsed = Filter::parse(&alloc::format!("zid == {bad}"));
            assert!(parsed.is_err(), "this notation must not parse: {bad:?}");
            let err = parsed.unwrap_err();
            assert!(
                matches!(err.kind, FilterErrorKind::UnknownValue { field: "zid", .. }),
                "and it must be refused BY NAME so a reader knows which term \
                 it was: {bad:?} gave {err:?}"
            );
        }
        // What LEFT the list: an odd digit count is an ordinary zid.
        assert!(
            Filter::parse("zid == a1a1a1a").is_ok(),
            "an odd number of digits is how zenoh prints a zid with a zero top nibble"
        );
    }

    /// THE SELECTOR TAKES THE SPELLING ZENOH PRINTS, not the wire
    /// order, judged on a zid that is NOT a palindrome.
    ///
    /// The record's zid is the wire bytes `01 02 03 04`. Zenoh prints that as
    /// `4030201` (the little-endian id read as a `u128`), and that is what the
    /// census, the field document and a zenohd log now all say, so it is what
    /// selects the node. The per-byte spelling `01020304` is REFUSED (leading
    /// zero), and its digits reversed byte by byte, `1020304`, is a well-formed
    /// zid that names a DIFFERENT node — which is the whole reason a spelling
    /// change is announced by revision rather than slipped in: the old text does
    /// not stop working, it starts meaning someone else.
    ///
    /// A palindromic fixture (`a1a1a1a1`, `0a0a0a0a`) reads the same both ways
    /// and cannot tell any of this apart; every other zid test in this file uses
    /// one, which is how the disagreement went unseen.
    #[test]
    fn the_selector_takes_zenohs_spelling_and_the_wire_order_names_another_node() {
        let record = RecordView {
            zid: Some(&[0x01, 0x02, 0x03, 0x04]),
            ..put(Some("demo/a"))
        };
        let zenoh = Filter::parse("zid == 4030201").expect("parses");
        assert_eq!(
            zenoh.matches(&record),
            Truth::Yes,
            "zenoh's spelling selects it"
        );

        let err =
            Filter::parse("zid == 01020304").expect_err("the per-byte spelling has a leading 0");
        assert!(
            matches!(err.kind, FilterErrorKind::UnknownValue { field: "zid", .. }),
            "{err:?}"
        );

        let other = Filter::parse("zid == 1020304").expect("a well-formed zid");
        assert_eq!(
            other.matches(&record),
            Truth::No,
            "the old text's digits, in zenoh's order, are a different node"
        );
    }

    /// A wire zid a peer PADDED with trailing zero bytes is the node
    /// its printed text names.
    ///
    /// `zid_to_zenoh_hex` zero-pads to 16 bytes, so `01 02 03 04` and
    /// `01 02 03 04 00 00` print as the same `4030201` and are one node to
    /// zenoh. The selector compares in canonical form so the record with the
    /// padding is selected by that text instead of by a second selector that
    /// reads alike. The unpadded record is judged in the same test, so a
    /// comparison that only ever trimmed the wrong side cannot pass.
    #[test]
    fn a_zid_padded_with_trailing_zero_bytes_is_the_node_its_text_names() {
        let f = Filter::parse("zid == 4030201").expect("parses");
        let padded = RecordView {
            zid: Some(&[0x01, 0x02, 0x03, 0x04, 0x00, 0x00]),
            ..put(Some("demo/a"))
        };
        let plain = RecordView {
            zid: Some(&[0x01, 0x02, 0x03, 0x04]),
            ..put(Some("demo/a"))
        };
        assert_eq!(f.matches(&padded), Truth::Yes);
        assert_eq!(f.matches(&plain), Truth::Yes);
    }

    /// R2757 — and the empty value is refused ONE LAYER UP, which is where it
    /// belongs: a term with no value at all is a grammar error, not a bad zid.
    #[test]
    fn a_node_term_with_no_value_is_a_grammar_error_and_not_a_bad_node() {
        let err = Filter::parse("zid ==").expect_err("an empty value must not parse");
        assert!(
            matches!(err.kind, FilterErrorKind::UnexpectedEnd),
            "the tokenizer refuses it before the zid notation is consulted: {err:?}"
        );
    }

    /// A capture with no clock cannot answer a `time` question, and says so.
    /// The consumer of R311y615's decision to keep the clock an `Option`.
    #[test]
    fn a_clockless_capture_cannot_decide_a_time_term() {
        let f = Filter::parse("time >= 500").expect("parses");
        assert_eq!(
            f.matches(&view(
                Direction::A,
                Some("k"),
                RecordKind::Put,
                0,
                Some(500)
            )),
            Truth::Yes
        );
        assert_eq!(
            f.matches(&view(
                Direction::A,
                Some("k"),
                RecordKind::Put,
                0,
                Some(499)
            )),
            Truth::No
        );
        assert_eq!(
            f.matches(&view(Direction::A, Some("k"), RecordKind::Put, 0, None)),
            Truth::Unknown
        );
    }

    /// Kleene, exhaustively, in the shape that makes it more than
    /// "unknown infects everything": a decided `No` beside an unknown is `No`,
    /// and a decided `Yes` beside an unknown in a disjunction is `Yes`.
    ///
    /// Written as a table over the THREE inputs each connective can see, so a
    /// future short-circuit that reorders the walk cannot change an answer
    /// without a red here.
    #[test]
    fn the_three_valued_connectives_follow_kleene_rather_than_infecting() {
        // `key == demo/a` is unknown on an unresolved record; `bytes` is always
        // decided. The pair gives every combination without a mock evaluator.
        let unresolved = put(None);
        let resolved_match = put(Some("demo/a"));

        // unknown AND no => No: the decided half settles it.
        let f = Filter::parse("key == demo/a and bytes > 1000").expect("parses");
        assert_eq!(f.matches(&unresolved), Truth::No);
        // unknown AND yes => Unknown: the missing half could still say no.
        let f = Filter::parse("key == demo/a and bytes > 1").expect("parses");
        assert_eq!(f.matches(&unresolved), Truth::Unknown);
        // unknown OR yes => Yes.
        let f = Filter::parse("key == demo/a or bytes > 1").expect("parses");
        assert_eq!(f.matches(&unresolved), Truth::Yes);
        // unknown OR no => Unknown.
        let f = Filter::parse("key == demo/a or bytes > 1000").expect("parses");
        assert_eq!(f.matches(&unresolved), Truth::Unknown);
        // NOT unknown => Unknown. A negation cannot manufacture a decision.
        let f = Filter::parse("not key == demo/a").expect("parses");
        assert_eq!(f.matches(&unresolved), Truth::Unknown);
        assert_eq!(f.matches(&resolved_match), Truth::No);
        // And the decided cases stay ordinary two-valued logic.
        let f = Filter::parse("bytes > 1 and bytes < 100").expect("parses");
        assert_eq!(f.matches(&resolved_match), Truth::Yes);
        let f = Filter::parse("bytes > 1 and bytes < 5").expect("parses");
        assert_eq!(f.matches(&resolved_match), Truth::No);
    }

    /// `and` binds tighter than `or`, and parentheses override it. Without this
    /// `a or b and c` is ambiguous and two readers get two different answers.
    #[test]
    fn conjunction_binds_tighter_than_disjunction_and_groups_override_it() {
        let a = view(Direction::A, Some("x"), RecordKind::Put, 5, Some(1));
        // `dir == b and bytes > 100` is false; the `or` arm decides.
        let f = Filter::parse("kind == put or dir == b and bytes > 100").expect("parses");
        assert_eq!(f.matches(&a), Truth::Yes);
        // Grouped the other way the whole thing is false.
        let f = Filter::parse("(kind == put or dir == b) and bytes > 100").expect("parses");
        assert_eq!(f.matches(&a), Truth::No);
        // `&&` / `||` / `!` are the same operators spelled differently.
        let f = Filter::parse("kind == put && !(dir == b)").expect("parses");
        assert_eq!(f.matches(&a), Truth::Yes);
    }

    /// Every field's vocabulary, driven rather than described.
    #[test]
    fn each_field_reads_the_axis_it_names() {
        let r = view(
            Direction::B,
            Some("demo/temp"),
            RecordKind::Query,
            42,
            Some(7),
        );
        for (source, expected) in [
            ("dir == b", Truth::Yes),
            ("dir == a", Truth::No),
            ("dir != a", Truth::Yes),
            ("kind == query", Truth::Yes),
            ("kind == put", Truth::No),
            ("kind != put", Truth::Yes),
            ("bytes == 42", Truth::Yes),
            ("bytes != 42", Truth::No),
            ("bytes <= 42", Truth::Yes),
            ("bytes < 42", Truth::No),
            ("bytes >= 42", Truth::Yes),
            ("bytes > 42", Truth::No),
            ("time == 7", Truth::Yes),
            ("key == demo/temp", Truth::Yes),
            ("key != demo/temp", Truth::No),
            ("key == demo/other", Truth::No),
        ] {
            assert_eq!(
                Filter::parse(source).expect(source).matches(&r),
                expected,
                "{source}"
            );
        }
    }

    /// R311y638 (§1.1r) — the capture-relative clock, and the point that it is
    /// a DIFFERENT question from `time` rather than a nicer spelling of it.
    #[test]
    fn the_elapsed_axis_reads_the_capture_relative_clock() {
        let mut r = view(
            Direction::A,
            Some("demo/a"),
            RecordKind::Put,
            10,
            Some(1_700_000_005_000),
        );
        r.elapsed_ms = Some(5_000);
        for (source, expected) in [
            ("elapsed == 5000", Truth::Yes),
            ("elapsed != 5000", Truth::No),
            ("elapsed < 5000", Truth::No),
            ("elapsed <= 5000", Truth::Yes),
            ("elapsed > 4999", Truth::Yes),
            ("elapsed >= 5001", Truth::No),
            // Both axes over one record, which is the whole reason there are
            // two: an absolute window AND an offset into the file.
            ("time > 1700000000000 and elapsed < 6000", Truth::Yes),
            ("time > 1700000000000 and elapsed < 4000", Truth::No),
        ] {
            assert_eq!(
                Filter::parse(source).expect(source).matches(&r),
                expected,
                "{source}"
            );
        }

        // A plane that was never told where the capture began cannot answer,
        // and says so. The CONTROL is that `time` over the same record still
        // decides — the unknown is scoped to the axis that needs the origin.
        let no_origin = view(
            Direction::A,
            Some("demo/a"),
            RecordKind::Put,
            10,
            Some(1_700_000_005_000),
        );
        assert_eq!(
            Filter::parse("elapsed < 5000")
                .expect("parses")
                .matches(&no_origin),
            Truth::Unknown
        );
        assert_eq!(
            Filter::parse("time > 1700000000000")
                .expect("parses")
                .matches(&no_origin),
            Truth::Yes
        );
    }

    /// R311y636 (§1.1v) — the outcome axis, driven the same way: every field,
    /// every operator, over an exchange whose outcome is fully known.
    ///
    /// The view is an exchange that got two replies and one error, first
    /// answered 30ms after the request and closed 50ms after it.
    #[test]
    fn each_outcome_field_reads_the_axis_it_names() {
        let mut r = view(
            Direction::A,
            Some("demo/temp"),
            RecordKind::Query,
            0,
            Some(1_000),
        );
        r.outcome = Some(OutcomeView {
            replies: 2,
            errs: 1,
            first_reply_ms: Some(30),
            completion_ms: Some(50),
            closed: true,
        });
        for (source, expected) in [
            ("replies == 2", Truth::Yes),
            ("replies != 2", Truth::No),
            ("replies > 0", Truth::Yes),
            ("replies < 2", Truth::No),
            ("replies >= 2", Truth::Yes),
            ("replies <= 1", Truth::No),
            ("errs == 1", Truth::Yes),
            ("errs == 0", Truth::No),
            ("first_reply == 30", Truth::Yes),
            ("first_reply > 100", Truth::No),
            ("first_reply < 100", Truth::Yes),
            ("completion == 50", Truth::Yes),
            ("completion >= 50", Truth::Yes),
            ("completion > 50", Truth::No),
            ("closed == yes", Truth::Yes),
            ("closed == no", Truth::No),
            ("closed != no", Truth::Yes),
            // The point of ONE language: a request-time term and an
            // outcome-time term compose in a single predicate.
            ("key == demo/temp and completion > 40", Truth::Yes),
            ("key == demo/temp and completion > 60", Truth::No),
        ] {
            assert_eq!(
                Filter::parse(source).expect(source).matches(&r),
                expected,
                "{source}"
            );
        }
    }

    /// THE §1.1v QUESTION, in the two shapes the debt named: *the exchange
    /// nobody answered* and *the exchange that took too long*.
    ///
    /// Both are decidable, and the control legs are what make that a claim: the
    /// answered exchange is rejected by the first selector and the fast one by
    /// the second, so neither is a predicate that admits everything.
    #[test]
    fn an_unanswered_exchange_and_a_slow_one_are_both_expressible() {
        let exchange = |replies: u64, first: Option<u64>, completion: Option<u64>| {
            let mut r = view(Direction::A, Some("demo/q"), RecordKind::Query, 0, Some(1));
            r.outcome = Some(OutcomeView {
                replies,
                errs: 0,
                first_reply_ms: first,
                completion_ms: completion,
                closed: completion.is_some(),
            });
            r
        };
        let silent = exchange(0, None, Some(2_000));
        let answered = exchange(3, Some(12), Some(20));
        let slow = exchange(1, Some(450), Some(460));

        let unanswered = Filter::parse("replies == 0").expect("parses");
        assert_eq!(unanswered.matches(&silent), Truth::Yes);
        assert_eq!(unanswered.matches(&answered), Truth::No);

        let sluggish = Filter::parse("first_reply > 100").expect("parses");
        assert_eq!(sluggish.matches(&slow), Truth::Yes);
        assert_eq!(sluggish.matches(&answered), Truth::No);
        // An exchange nothing answered has NO first-reply interval, so this
        // question is undecidable over it rather than false. Answering `no`
        // would have filed the query that never came back among the fast ones.
        assert_eq!(sluggish.matches(&silent), Truth::Unknown);
        // And that is why the two selectors are different questions: the
        // reader who wants both writes the disjunction, and gets it.
        let either = Filter::parse("first_reply > 100 or replies == 0").expect("parses");
        assert_eq!(either.matches(&silent), Truth::Yes);
        assert_eq!(either.matches(&slow), Truth::Yes);
        assert_eq!(either.matches(&answered), Truth::No);
    }

    /// The rule that keeps the outcome axis honest on the planes that do not
    /// have one: UNDECIDABLE, never false.
    ///
    /// `put(..)` is the view [`crate::agg`] builds — `outcome: None` — so this
    /// is the throughput plane's answer to an exchange question, and the
    /// conjunction leg is the one that matters: `kind == put` is decidably
    /// `Yes` there and the pair still comes out unknown, so a reader cannot be
    /// handed a short table that looks whole.
    #[test]
    fn a_plane_that_does_not_correlate_exchanges_cannot_decide_an_outcome_term() {
        let r = put(Some("demo/a"));
        for source in [
            "replies == 0",
            "replies > 3",
            "errs == 0",
            "first_reply < 5",
            "completion > 1",
            "closed == yes",
            "closed == no",
            "kind == put and replies == 0",
        ] {
            assert_eq!(
                Filter::parse(source).expect(source).matches(&r),
                Truth::Unknown,
                "{source}"
            );
        }
        // Kleene, not infection: a decidable `No` still settles the
        // conjunction even though the other half is unanswerable.
        assert_eq!(
            Filter::parse("kind == query and replies == 0")
                .expect("parses")
                .matches(&r),
            Truth::No
        );
        // And negation leaves it unknown rather than flipping it to yes.
        assert_eq!(
            Filter::parse("not replies == 0")
                .expect("parses")
                .matches(&r),
            Truth::Unknown
        );
    }

    /// The outcome fields are refused the same way every other field is when
    /// they are misused — by name, at the offending byte.
    #[test]
    fn the_outcome_fields_refuse_what_they_do_not_admit() {
        let err = Filter::parse("closed >= yes").expect_err("closed is not ordered");
        assert_eq!(
            err.kind,
            FilterErrorKind::OperatorNotAdmitted {
                field: "closed",
                op: ">="
            }
        );
        let err = Filter::parse("closed == maybe").expect_err("two-valued on the wire");
        assert_eq!(
            err.kind,
            FilterErrorKind::UnknownValue {
                field: "closed",
                value: "maybe".to_string()
            }
        );
        let err = Filter::parse("replies > two").expect_err("not an integer");
        assert!(matches!(err.kind, FilterErrorKind::NotAnInteger(_)));
        // The unknown-field message names the whole vocabulary, so a reader who
        // guessed `latency` is told what this language calls it.
        let err = Filter::parse("elapsed == maybe").expect_err("not an integer");
        assert!(matches!(err.kind, FilterErrorKind::NotAnInteger(_)));
        let err = Filter::parse("latency > 100").expect_err("no such field");
        assert_eq!(
            err.kind,
            FilterErrorKind::UnknownField("latency".to_string())
        );
        let rendered = err.to_string();
        for field in [
            "elapsed",
            "replies",
            "errs",
            "first_reply",
            "completion",
            "closed",
        ] {
            assert!(
                rendered.contains(field),
                "{field} missing from {rendered:?}"
            );
        }
    }

    /// A quoted value is never re-read as a keyword, so a keyexpr chunk called
    /// `or` is expressible. The one thing a bare-word lexer gets wrong.
    #[test]
    fn a_quoted_value_is_not_reread_as_a_keyword() {
        let f = Filter::parse("key == \"and\"").expect("parses");
        assert_eq!(f.matches(&put(Some("and"))), Truth::Yes);
        assert_eq!(f.matches(&put(Some("or"))), Truth::No);
        // Single quotes too, for the shell case.
        let f = Filter::parse("key == 'not'").expect("parses");
        assert_eq!(f.matches(&put(Some("not"))), Truth::Yes);
    }

    /// Malformed selectors are REFUSED with a position and a named reason —
    /// never accepted with a guessed meaning. Each row is a different failure
    /// path through the lexer and the parser.
    #[test]
    fn a_malformed_selector_is_refused_by_name_rather_than_guessed() {
        for (source, expected) in [
            (
                "frob == 1",
                FilterErrorKind::UnknownField("frob".to_string()),
            ),
            (
                "kind == frobnicate",
                FilterErrorKind::UnknownValue {
                    field: "kind",
                    value: "frobnicate".to_string(),
                },
            ),
            (
                "dir == c",
                FilterErrorKind::UnknownValue {
                    field: "dir",
                    value: "c".to_string(),
                },
            ),
            (
                "key >= demo",
                FilterErrorKind::OperatorNotAdmitted {
                    field: "key",
                    op: ">=",
                },
            ),
            (
                "bytes > many",
                FilterErrorKind::NotAnInteger("many".to_string()),
            ),
            ("bytes >", FilterErrorKind::UnexpectedEnd),
            ("bytes", FilterErrorKind::UnexpectedEnd),
            ("(bytes > 1", FilterErrorKind::UnclosedGroup),
            ("bytes > 1)", FilterErrorKind::TrailingInput),
            ("key == \"open", FilterErrorKind::UnterminatedQuote),
            ("bytes = 1", FilterErrorKind::UnexpectedChar('=')),
            ("bytes ~ 1", FilterErrorKind::UnexpectedChar('~')),
            ("bytes 1", FilterErrorKind::ExpectedOperator),
        ] {
            let err = Filter::parse(source).expect_err(source);
            assert_eq!(err.kind, expected, "{source}");
            assert!(err.at <= source.len(), "{source}: position out of range");
            // The rendering names the position, so a caller need not.
            let shown = alloc::format!("{err}");
            assert!(shown.starts_with("at byte "), "{shown}");
        }
    }

    /// An integer beyond `u64` is refused rather than wrapped — a filter that
    /// silently compared against a wrapped bound would be a wrong answer with
    /// no error attached.
    #[test]
    fn an_out_of_range_bound_is_refused_rather_than_wrapped() {
        let err = Filter::parse("bytes > 18446744073709551616").expect_err("overflows u64");
        assert!(matches!(err.kind, FilterErrorKind::NotAnInteger(_)));
    }

    /// The wildcard arm, in the build that HAS wildcards: `demo/**` speaks
    /// zenoh's dialect, matching the matcher the routers use rather than a
    /// second glob written here.
    #[cfg(feature = "filter-wildcards")]
    #[test]
    fn a_wildcard_pattern_matches_the_way_zenohs_own_matcher_does() {
        let f = Filter::parse("key == demo/**").expect("parses");
        assert_eq!(f.matches(&put(Some("demo/a"))), Truth::Yes);
        assert_eq!(f.matches(&put(Some("demo/a/b/c"))), Truth::Yes);
        assert_eq!(f.matches(&put(Some("demo"))), Truth::Yes);
        assert_eq!(f.matches(&put(Some("other/a"))), Truth::No);

        let f = Filter::parse("key == sensors/*/temp").expect("parses");
        assert_eq!(f.matches(&put(Some("sensors/1/temp"))), Truth::Yes);
        // A single `*` is exactly one chunk, as zenoh defines it.
        assert_eq!(f.matches(&put(Some("sensors/1/2/temp"))), Truth::No);
        // Unresolved is STILL unknown under a wildcard: a pattern that would
        // match everything does not get to decide a keyexpr nobody knows.
        assert_eq!(f.matches(&put(None)), Truth::Unknown);
    }

    /// The negative arm, and it is the whole justification for the feature: in
    /// a build whose matcher degrades `**` to a literal chunk, a wildcard
    /// selector is REFUSED. Without this the same selector would parse and
    /// quietly answer about a keyexpr literally named `**`.
    #[cfg(not(feature = "filter-wildcards"))]
    #[test]
    fn a_wildcard_pattern_is_refused_where_the_matcher_cannot_honour_it() {
        let err = Filter::parse("key == demo/**").expect_err("must refuse");
        assert_eq!(err.kind, FilterErrorKind::WildcardUnsupported);
        // A literal pattern still works — the refusal is scoped to what the
        // build cannot answer, not to the field.
        let f = Filter::parse("key == demo/a").expect("literals still parse");
        assert_eq!(f.matches(&put(Some("demo/a"))), Truth::Yes);
    }

    /// R2174 (open-debt item 551) — PARSING ARBITRARY UTF-8 ANSWERS; IT DOES
    /// NOT DIE.
    ///
    /// # Why a derived corpus and not the reported strings
    ///
    /// A consumer reported seven selectors that killed the process and this
    /// crate could have pinned exactly those seven. That is a regression list,
    /// and the item's own filing says why it is the wrong instrument: what was
    /// broken is a PROPERTY -- `lex` walked `source.as_bytes()` and cast each
    /// byte with `as char`, which is a Latin-1 reinterpretation, so EVERY
    /// multi-byte character was mis-lexed and the ones that panicked were
    /// simply the ones whose lead byte `is_alphanumeric()` happened to accept.
    /// Seven strings cannot separate "fixed" from "fixed for these seven".
    ///
    /// So the population is DERIVED: characters spanning every UTF-8 length
    /// and both sides of `is_word_char`, crossed with every POSITION the lexer
    /// has a different code path for. A build that lost the fix fails here
    /// whichever character it lost it for.
    ///
    /// # The oracle is "no panic", deliberately, and not a verdict per string
    ///
    /// Whether `key == 로봇` is ACCEPTED or REFUSED is a language decision the
    /// tests below make separately. What this one asserts is the thing the ABI
    /// promises and the defect broke: `parse` RETURNS. `Ok` and `Err` are both
    /// answers; an unwind across `extern "C"` is not one, and the consumer that
    /// filed this measured it as `abort`, exit 134, with no error code to read.
    #[test]
    fn parsing_any_utf8_answers_rather_than_dying() {
        // One character per UTF-8 length, on both sides of `is_word_char`, so
        // a fix that only handled the alphanumeric ones is still caught.
        let chars = [
            'a',         // 1 byte, word
            '=',         // 1 byte, grammar
            '\u{00A9}',  // 2 bytes, NOT alphanumeric  (©)
            '\u{00E9}',  // 2 bytes, alphanumeric      (é)
            '\u{20AC}',  // 3 bytes, NOT alphanumeric  (€)
            '\u{AC1C}',  // 3 bytes, alphanumeric      (개)
            '\u{1F916}', // 4 bytes, NOT alphanumeric (🤖)
            '\u{20BB7}', // 4 bytes, alphanumeric     (a CJK ext-B ideograph)
        ];
        // Every shape the lexer takes a different path for. `{}` is where the
        // character goes.
        let shapes = [
            "{}",
            "{} == 1",
            "key == {}",
            "key == a{}b",
            "key == {}/x",
            "bytes > 1 and key == {}",
            "key == \"{}\"", // quoted: the path that survives today
            "key == '{}'",
            "({})",
            "key == {}",
            "{}{}",
            "key =={}",
        ];

        let mut cases = 0usize;
        for c in chars {
            for shape in shapes {
                let selector = shape.replace("{}", &c.to_string());
                // The ASSERTION is that this call returns at all. A panic here
                // fails the test, which is exactly the defect's Rust-side face.
                let _ = Filter::parse(&selector);
                cases += 1;
            }
        }
        assert!(
            cases >= chars.len() * shapes.len(),
            "the corpus is derived from two lists; a population of {cases} \
             means one of them was emptied and this test measured nothing"
        );
    }

    /// R2174 (open-debt item 551) — AN UNQUOTED WORD CHARACTER IS THE SAME
    /// WORD, QUOTED OR NOT.
    ///
    /// `is_word_char` calls `char::is_alphanumeric`, not its `is_ascii_`
    /// sibling, so admitting non-ASCII letters unquoted is what this lexer was
    /// WRITTEN to do. It never did: `bytes[i] as char` meant the branch was
    /// only ever handed bytes 0..255, so the Unicode arm was unreachable code
    /// that looked live. Fixing the walk is what makes the author's own
    /// predicate mean what it says, and this test is what pins that the two
    /// spellings now agree rather than one of them being a second grammar.
    #[test]
    fn a_non_ascii_word_parses_to_the_same_filter_quoted_or_not() {
        let bare = Filter::parse("key == 로봇").expect("an unquoted word parses");
        let quoted = Filter::parse("key == \"로봇\"").expect("the quoted form parses");
        let sample = put(Some("로봇"));
        assert_eq!(bare.matches(&sample), Truth::Yes);
        assert_eq!(
            bare.matches(&sample),
            quoted.matches(&sample),
            "quoting a word must not change what it matches"
        );
        // And the quotes are still the escape hatch for what is NOT a word
        // character -- the sentence `is_word_char`'s own doc makes.
        let punctuation = Filter::parse("key == \"a b\"").expect("quoted space parses");
        assert_eq!(punctuation.matches(&put(Some("a b"))), Truth::Yes);
    }

    /// R2174 (open-debt item 551) — A REFUSAL NAMES THE CHARACTER THE OPERATOR
    /// TYPED, AND POINTS AT ITS FIRST BYTE.
    ///
    /// Two contracts in one test because a fix can satisfy either alone:
    ///
    ///   * the character. `bytes[i] as char` named the Latin-1 mojibake of the
    ///     LEAD BYTE, so `key == €` would have been refused citing `'â'` -- a
    ///     character the operator never typed and cannot find in their box;
    ///   * the offset. `wz_dissect.h` publishes `at` as a BYTE offset and a
    ///     consumer places a caret from it, so a fix that switched the walk to
    ///     character COUNTS to make slicing safe would move every caret in
    ///     every selector containing a multi-byte character.
    #[test]
    fn a_refusal_names_the_typed_character_at_its_byte_offset() {
        let err = Filter::parse("key == €").expect_err("€ is not a word character");
        assert_eq!(
            err.kind,
            FilterErrorKind::UnexpectedChar('€'),
            "the refusal must name what was typed, not a byte reinterpreted"
        );
        assert_eq!(err.at, "key == ".len(), "`at` is a BYTE offset");

        // And after a multi-byte character, so a byte offset and a character
        // count are different numbers here -- which is the whole point.
        let err = Filter::parse("key == 로봇 €").expect_err("still refused");
        assert_eq!(err.kind, FilterErrorKind::UnexpectedChar('€'));
        assert_eq!(
            err.at,
            "key == 로봇 ".len(),
            "a byte offset, which is 13 here and 9 if someone counted characters"
        );
    }

    /// Every class, every spelling, and the span each covers,
    /// written as the TEXT the span slices out so a wrong offset reads as the
    /// wrong substring rather than as a number.
    #[test]
    fn tokens_carry_the_byte_span_and_class_the_lexer_saw() {
        let src = "(key == 'a b') && not size>=3 || !x != \"로봇\" and y < 1 or z > 2";
        let got: Vec<(&str, &str)> = tokens(src)
            .into_iter()
            .map(|t| (&src[t.start..t.end], t.class.word()))
            .collect();
        assert_eq!(
            got,
            alloc::vec![
                ("(", "open"),
                ("key", "word"),
                ("==", "operator"),
                ("'a b'", "quoted"),
                (")", "close"),
                ("&&", "and"),
                ("not", "not"),
                ("size", "word"),
                (">=", "operator"),
                ("3", "word"),
                ("||", "or"),
                ("!", "not"),
                ("x", "word"),
                ("!=", "operator"),
                ("\"로봇\"", "quoted"),
                ("and", "and"),
                ("y", "word"),
                ("<", "operator"),
                ("1", "word"),
                ("or", "or"),
                ("z", "word"),
                (">", "operator"),
                ("2", "word"),
            ]
        );
        // Every class the family declares was reached, so the table above is
        // not silently narrower than the vocabulary it is evidence for.
        let mut reached: Vec<&str> = got.iter().map(|(_, c)| *c).collect();
        reached.sort_unstable();
        reached.dedup();
        let mut declared = TokenClass::names();
        declared.sort_unstable();
        assert_eq!(reached, declared);
    }

    /// A LEXICAL failure keeps what came before it. The verdict's
    /// `at` says where lexing stopped; the tokens are the part a colouring can
    /// still use, and they end before that offset.
    #[test]
    fn tokens_stop_at_a_lexical_failure_and_keep_what_came_before() {
        let src = "key == \"unterminated";
        let got = tokens(src);
        assert_eq!(
            got.iter().map(|t| &src[t.start..t.end]).collect::<Vec<_>>(),
            alloc::vec!["key", "=="]
        );
        let at = Filter::parse(src).expect_err("an open quote is refused").at;
        assert!(got.iter().all(|t| t.end <= at));

        // A PARSE failure is not a lexical one: every token is there.
        assert_eq!(tokens("key ==").len(), 2);
        assert!(tokens("").is_empty());
    }

    /// AN UNFINISHED SELECTOR IS REFUSED AT ITS END, not at the start of the
    /// last thing typed.
    ///
    /// `UnexpectedEnd` says the selector ended and needs more, so the place it
    /// points at is where the next character goes: the byte length of the
    /// input. It used to report where the LAST TOKEN began, so `demo` was
    /// refused at byte 0 and a caret drawn from `at` sat on a word that was
    /// complete. Whitespace after the last token counts, because the input
    /// ended after it and the next character goes after it too.
    ///
    /// The rows are one per place the parser can run out: a field with no
    /// operator, an operator with no value, a connective with nothing after
    /// it, a `not` with nothing to negate, and a group that is still open. The
    /// last row ends in text whose byte length differs from its character
    /// count, so a position counted in characters is a different number there.
    #[test]
    fn an_unfinished_selector_is_refused_at_the_end_of_its_input() {
        for (source, at) in [
            ("demo", 4),
            ("kind", 4),
            ("kind ==", 7),
            ("kind == ", 8),
            ("  kind ==  ", 11),
            ("bytes >", 7),
            ("key == a and", 12),
            ("key == a or ", 12),
            ("not", 3),
            ("not ", 4),
            ("(bytes > 1 and", 14),
            ("zid ==", 6),
            ("key == 로봇 and", "key == 로봇 and".len()),
        ] {
            // The table's own number is the byte length, so a row typed wrong
            // is a red here and not a position the test then agrees with.
            assert_eq!(at, source.len(), "{source:?}: the row's number");
            let err = Filter::parse(source).expect_err(source);
            assert_eq!(err.kind, FilterErrorKind::UnexpectedEnd, "{source:?}");
            assert_eq!(
                err.at, at,
                "{source:?}: the selector ended, so the position is the byte \
                 length of the input and not where its last token began"
            );
            assert!(
                alloc::format!("{err}").starts_with(&alloc::format!("at byte {at}: ")),
                "{source:?}: the rendering carries the same position"
            );
        }
    }

    /// Every refusal that is NOT an end of input keeps the position it had.
    ///
    /// The position of `UnexpectedEnd` moved and nothing else did, and that is
    /// a claim only a table of EXACT positions can hold: the other test in this
    /// file asserts `at <= len`, which a position moved to the end would also
    /// satisfy. Each row names the byte a caret belongs on.
    #[test]
    fn a_refusal_that_is_not_an_end_of_input_keeps_its_position() {
        for (source, kind, at) in [
            (
                "frob == 1",
                FilterErrorKind::UnknownField("frob".to_string()),
                0,
            ),
            (
                "bytes > 1 and frob == 1",
                FilterErrorKind::UnknownField("frob".to_string()),
                14,
            ),
            (
                "kind == frobnicate",
                FilterErrorKind::UnknownValue {
                    field: "kind",
                    value: "frobnicate".to_string(),
                },
                8,
            ),
            (
                "key >= demo",
                FilterErrorKind::OperatorNotAdmitted {
                    field: "key",
                    op: ">=",
                },
                4,
            ),
            (
                "bytes > many",
                FilterErrorKind::NotAnInteger("many".to_string()),
                8,
            ),
            ("(bytes > 1", FilterErrorKind::UnclosedGroup, 0),
            (
                "bytes > 1 and (kind == put",
                FilterErrorKind::UnclosedGroup,
                14,
            ),
            ("bytes > 1)", FilterErrorKind::TrailingInput, 9),
            ("key == \"open", FilterErrorKind::UnterminatedQuote, 7),
            ("bytes = 1", FilterErrorKind::UnexpectedChar('='), 6),
            ("bytes 1", FilterErrorKind::ExpectedOperator, 6),
        ] {
            let err = Filter::parse(source).expect_err(source);
            assert_eq!(err.kind, kind, "{source:?}");
            assert_eq!(err.at, at, "{source:?}");
        }
    }

    /// The diagnosis document reports the end position and leaves the token
    /// spans alone.
    ///
    /// `at` is one number and the tokens are `{start, end}` pairs in the same
    /// unit, so a consumer reading both sees a refusal that points just past
    /// the last token, which is what "the selector needs more" looks like. The
    /// token list is the lexer's and the lexer did not change: `demo` is still
    /// one word spanning `0..4`.
    #[test]
    fn the_diagnosis_places_an_unfinished_selector_past_its_last_token() {
        let doc = diagnose_json("demo");
        assert!(doc.contains("\"ok\":false,\"at\":4,"), "{doc}");
        assert!(
            doc.ends_with(",\"tokens\":[{\"start\":0,\"end\":4,\"kind\":\"word\"}]}"),
            "the token span is the lexer's and did not move: {doc}"
        );
        let doc = diagnose_json("kind == ");
        assert!(doc.contains("\"at\":8,"), "{doc}");
        assert!(
            doc.ends_with(
                ",\"tokens\":[{\"start\":0,\"end\":4,\"kind\":\"word\"},\
                 {\"start\":5,\"end\":7,\"kind\":\"operator\"}]}"
            ),
            "{doc}"
        );
    }

    /// The names the unknown-field refusal lists, read back out of its
    /// message.
    fn fields_the_refusal_names() -> Vec<String> {
        let message = Filter::parse("no_such_field == 1")
            .expect_err("an unknown field is refused")
            .to_string();
        let list = message
            .split("(known: ")
            .nth(1)
            .and_then(|rest| rest.strip_suffix(')'))
            .unwrap_or_else(|| panic!("the refusal lists its candidates: {message:?}"));
        list.split(", ").map(str::to_string).collect()
    }

    /// The fields the module's own table documents, read out of this file's
    /// header: the first cell of each row of the first table.
    fn fields_the_module_documents() -> Vec<String> {
        const SOURCE: &str = include_str!("filter.rs");
        SOURCE
            .lines()
            .take_while(|line| !line.starts_with("use "))
            .filter(|line| line.starts_with("//! | `"))
            .filter_map(|line| line.strip_prefix("//! | `")?.split('`').next())
            .map(str::to_string)
            .collect()
    }

    /// THE REFUSAL NAMES THE FIELDS THE PARSER ACCEPTS, AND NOTHING ELSE.
    ///
    /// A reader who typed a field the language does not have is told what it
    /// does have, and that sentence was a hand-written list beside the parser's
    /// own match: `zid` was accepted by the parser and missing from the
    /// message, so the one place that answers "what can I write" disagreed with
    /// the grammar.
    ///
    /// The set the parser accepts is MEASURED, by offering it names and asking
    /// whether it refuses each as an unknown field, and not read off the table
    /// the message is built from: a message and a table that agree with each
    /// other say nothing about a parser that moved. The names offered are every
    /// name either hand-written list carries (this module's own documentation
    /// table and the refusal itself) plus decoys a reader would plausibly try,
    /// so a field added to the parser alone, or to the message alone, changes
    /// one side of the comparison and not the other.
    #[test]
    fn the_unknown_field_refusal_names_exactly_the_fields_the_parser_accepts() {
        let named = fields_the_refusal_names();
        let documented = fields_the_module_documents();
        assert!(
            documented.len() >= 13 && named.len() >= 13,
            "anti-vacuity: both lists were read: {documented:?} {named:?}"
        );

        let mut offered: Vec<String> = named.iter().chain(documented.iter()).cloned().collect();
        offered.extend(
            [
                // The fields a consumer lists from its own use of the language,
                // which is where the omission was first seen: neither of the
                // two lists above carried `zid`, so a corpus built from them
                // alone could not have offered it.
                "key",
                "kind",
                "zid",
                "bytes",
                "elapsed",
                "latency",
                "size",
                "topic",
                "node",
                "sender",
                "source",
                "dst",
                "rate",
                "count",
                "len",
                "length",
                "name",
                "id",
                "seq",
                "ts",
                "timestamp",
                "qos",
                "priority",
                "Key",
                "KEY",
                "zid2",
                "keyexpr",
                "payload",
                "reply",
                "err",
                "closed_at",
            ]
            .map(str::to_string),
        );
        offered.sort();
        offered.dedup();

        let mut accepted: Vec<String> = offered
            .iter()
            .filter(|name| {
                !matches!(
                    Filter::parse(&alloc::format!("{name} == 1")),
                    Err(FilterError {
                        kind: FilterErrorKind::UnknownField(_),
                        ..
                    })
                )
            })
            .cloned()
            .collect();
        accepted.sort();
        let mut named_sorted = named.clone();
        named_sorted.sort();
        assert_eq!(
            accepted, named_sorted,
            "the parser accepts {accepted:?} and the refusal names {named_sorted:?}"
        );

        let mut documented_sorted = documented.clone();
        documented_sorted.sort();
        assert_eq!(
            accepted, documented_sorted,
            "the parser accepts {accepted:?} and this module's table documents \
             {documented_sorted:?}"
        );
    }
}
