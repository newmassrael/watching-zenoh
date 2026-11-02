// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Whether a flow's bytes are zenoh, as a sequential test over the invariants a
//! zenoh flow keeps (`docs/flow-zenoh-verdict.md`).
//!
//! # The test, and why it keeps two sums
//!
//! Each of the two sums is the logarithm of an e-process against the hypothesis
//! it rejects (models 3 and 4, `docs/flow-zenoh-verdict.md` §6.7, §6.9): the `yes` sum against
//! "not zenoh", read against [`crate::zenoh_evidence::model::YES_AT`], and the
//! `no` sum against "zenoh", read against
//! [`crate::zenoh_evidence::model::NO_AT`]. Each hypothesis is composite. What
//! the rejected one leaves unknown is taken at a bound on its likeliest, and what
//! the other one leaves unknown is mixed over a prior fixed in advance
//! ([`crate::zenoh_eprocess`]). Ville's inequality bounds the chance that a sum
//! EVER crosses its threshold, so the word of a flow is its FIRST crossing: it
//! latches there, with the packet it happened at, and the sums go on.
//!
//! # Counted at ingest, in the order it arrived
//!
//! Every observation enters when the packet that completes it is read
//! ([`crate::zenoh_evidence::ZenohEvidence::observe`]), for the reason
//! `session_table`'s module gives: a retention ceiling discards the oldest
//! messages, and the handshake is the oldest. The sums are kept in integers
//! ([`crate::zenoh_eprocess`]) and rounded toward the side each rejects, so a sum
//! never claims more than the real e-process does.
//!
//! Every link in this doc is fully qualified: it is merged with the `pub mod`
//! doc in `lib.rs` and resolved in the crate root.
//!
//! # What a weight claims
//!
//! Each side of each check names its [`crate::zenoh_evidence::Basis`]: a
//! probability derived from field widths, or one measured on the real captures
//! of `captures/corpus/`. A measured null chance is a statement against the
//! protocols the corpus holds and no others, and the document carries the basis
//! so that a consumer can say so.

use alloc::vec::Vec;

use crate::zenoh_eprocess::{
    ceil_millibits, floor_millibits, log2_null_sup, log2_sn_sup, Prior, Region, LOG_ERR_Q64,
    MAX_COUNT, ONE_Q64,
};
use crate::zenoh_mixture::LOG2_BREAK_NULL_Q64;

/// One kind of observation: the closed set the model weighs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Check {
    /// An OpenSyn carried the cookie the other direction's InitAck issued.
    CookieEcho,
    /// The two directions' Inits are an InitSyn and an InitAck.
    InitRoles,
    /// A data frame's SN was one step after the previous frame on its conduit
    /// ([`wz_session_core::passive::SnSteps`]).
    SnFollows,
    /// An admissible Init, Join, Scout or Hello, out of a framing unit read
    /// whole, announced the version this reader reads.
    VersionHeader,
    /// How a framing unit read ([`wz_session_core::passive::UnitReading`]).
    UnitReading,
    /// How a stream direction's framing was first judged: a unit framed, or
    /// the framing lost before one was
    /// ([`wz_session_core::passive::PassiveSession::first_framing`]).
    StreamFraming,
    /// The first byte of a datagram the link delimits names a transport
    /// message of this wire (model 4, `docs/flow-zenoh-verdict.md` §6.9).
    WireFront,
}

/// How far a datagram's bytes are known to be the ones its sender wrote: what
/// the zenoh side of [`Check::WireFront`] is derived from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrity {
    /// The transport checksum verified.
    Verified,
    /// No checksum was verified: none was carried, the link carries none, or a
    /// transmit offload left the field to the card.
    Unchecked,
}

/// How hard a check is to satisfy by chance, in the claim's terms: a handshake
/// binds two directions to each other, a state invariant binds a message to the
/// ones before it, a header binds a few bytes to a constant, and a unit reading
/// binds a unit's length to what decoded from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strength {
    /// Two directions agree about one handshake.
    Handshake,
    /// A message agrees with the messages before it.
    State,
    /// A message's header carries the constant zenoh writes there.
    Header,
    /// A unit's bytes are what its messages account for.
    Unit,
}

/// Where a probability of the model comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// From the widths of the fields the check compares.
    Derived,
    /// From the real captures of `captures/corpus/`
    /// ([`crate::zenoh_evidence::model::measured`]).
    Measured,
    /// Stated without a measurement; a corpus replaces it.
    Assumed,
}

impl Check {
    /// Every check, in the order the document lists them.
    pub const ALL: [Check; 7] = [
        Check::CookieEcho,
        Check::InitRoles,
        Check::SnFollows,
        Check::VersionHeader,
        Check::UnitReading,
        Check::StreamFraming,
        Check::WireFront,
    ];

    /// The word the document writes for this check.
    pub const fn name(self) -> &'static str {
        match self {
            Check::CookieEcho => "cookie_echo",
            Check::InitRoles => "init_roles",
            Check::SnFollows => "sn_follows",
            Check::VersionHeader => "version_header",
            Check::UnitReading => "unit_reading",
            Check::StreamFraming => "stream_framing",
            Check::WireFront => "wire_front",
        }
    }

    /// How hard the check is to satisfy by chance.
    pub const fn strength(self) -> Strength {
        match self {
            Check::CookieEcho | Check::InitRoles => Strength::Handshake,
            Check::SnFollows => Strength::State,
            Check::VersionHeader | Check::WireFront => Strength::Header,
            Check::UnitReading | Check::StreamFraming => Strength::Unit,
        }
    }

    /// Where the chance that a flow that is not zenoh satisfies the check comes
    /// from.
    pub const fn q_basis(self) -> Basis {
        match self {
            Check::CookieEcho | Check::InitRoles | Check::SnFollows | Check::VersionHeader => {
                Basis::Derived
            }
            Check::UnitReading | Check::StreamFraming | Check::WireFront => Basis::Measured,
        }
    }

    /// Where the chance that a zenoh flow fails the check comes from. The SN
    /// steps' break rate is the link's, so it is a prior fitted on the corpus's
    /// links for the `yes` sum and left free for the `no` sum; the wire's front
    /// is derived from what the wire allows and what reaches the capture
    /// altered (model 4); the others are a rate per group of zenoh captures.
    pub const fn eps_basis(self) -> Basis {
        match self {
            Check::WireFront => Basis::Derived,
            Check::SnFollows
            | Check::CookieEcho
            | Check::InitRoles
            | Check::VersionHeader
            | Check::UnitReading
            | Check::StreamFraming => Basis::Measured,
        }
    }

    /// Every word, sorted.
    pub fn names() -> Vec<&'static str> {
        let mut words: Vec<&'static str> = Self::ALL.iter().map(|c| c.name()).collect();
        words.sort_unstable();
        words
    }

    /// The words `eps_basis` is written with over every check, sorted: the
    /// vocabulary of that key, which is narrower than [`Basis`]'s.
    pub fn eps_basis_names() -> Vec<&'static str> {
        let mut words: Vec<&'static str> = Self::ALL.iter().map(|c| c.eps_basis().name()).collect();
        words.sort_unstable();
        words.dedup();
        words
    }
}

impl Strength {
    /// Every strength, from an exhaustive match.
    pub const ALL: [Strength; 4] = [
        Strength::Handshake,
        Strength::State,
        Strength::Header,
        Strength::Unit,
    ];

    /// The word the document writes for this strength.
    pub const fn name(self) -> &'static str {
        match self {
            Strength::Handshake => "handshake",
            Strength::State => "state",
            Strength::Header => "header",
            Strength::Unit => "unit",
        }
    }

    /// Every word, sorted.
    pub fn names() -> Vec<&'static str> {
        let mut words: Vec<&'static str> = Self::ALL.iter().map(|s| s.name()).collect();
        words.sort_unstable();
        words
    }
}

impl Basis {
    /// Every basis, from an exhaustive match.
    pub const ALL: [Basis; 3] = [Basis::Derived, Basis::Measured, Basis::Assumed];

    /// The word the document writes for this basis.
    pub const fn name(self) -> &'static str {
        match self {
            Basis::Derived => "derived",
            Basis::Measured => "measured",
            Basis::Assumed => "assumed",
        }
    }

    /// Every word, sorted.
    pub fn names() -> Vec<&'static str> {
        let mut words: Vec<&'static str> = Self::ALL.iter().map(|b| b.name()).collect();
        words.sort_unstable();
        words
    }
}

/// The model: its thresholds, the null chances derived from field widths, and
/// what the corpus gives it ([`crate::zenoh_evidence::model::Params`]).
pub mod model {
    use crate::zenoh_calibration_generated as generated;
    use crate::zenoh_eprocess::{Prior, Region};

    /// The model these sums are, written into the document so that a consumer
    /// can tell two models apart.
    pub const MODEL: u32 = 4;

    /// `log2` of the largest chance that a datagram whose transport checksum
    /// verified reaches the capture with its first byte altered: `2^-24`, the
    /// share of packets Stone and Partridge (2000) estimate pass the TCP
    /// checksum with their data altered, at its high end (one in sixteen
    /// million). Whatever an alteration does to the byte, it is at most this.
    pub const LOG2_ALTERED_VERIFIED: i128 = -24;

    /// `log2` of the largest chance that a datagram no checksum verified
    /// reaches the capture with its first byte altered: `2^-10`, the share of
    /// packets the same study found failing the TCP checksum after the link's
    /// CRC had passed, at its high end (one in 1,100).
    pub const LOG2_ALTERED_UNCHECKED: i128 = -10;

    /// `log2(1 / alpha)` with `alpha = 2^-20`: once the `yes` sum reaches it
    /// the flow is zenoh.
    pub const YES_AT: i64 = 20_000;

    /// `log2(beta)` with `beta = 2^-20`: once the `no` sum reaches it the flow
    /// is not zenoh.
    pub const NO_AT: i64 = -20_000;

    /// Per cookie byte matched, `log2(1 / 2^-8)`: an arbitrary byte equals a
    /// given one with chance `2^-8`.
    pub const COOKIE_ECHO_PER_BYTE: i64 = 8_000;

    /// The bytes a cookie match is counted for at most: 64 bits is decisive,
    /// and a cap keeps one observation from outweighing every other the flow
    /// can make.
    pub const COOKIE_ECHO_MAX_BYTES: i64 = 8;

    /// A check whose null chances are measured on the corpus: the unit
    /// readings and the stream framing.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Measured<const K: usize> {
        /// The zenoh side of the `yes` sum: a prior over a flow's own shares,
        /// centred on the zenoh files' Jeffreys estimate with a weight of one
        /// outcome.
        pub zenoh: Prior<K>,
        /// The zenoh side of the `no` sum: what the zenoh groups allow of a
        /// failure rate (every outcome but the first is a failure).
        pub region: Region,
        /// The null side of the `yes` sum: per outcome, `log2` of the largest
        /// one-sided 95% Clopper-Pearson bound over the null members, in Q64,
        /// rounded up.
        pub log2_null_bound: [i128; K],
        /// The null side of the `no` sum: per outcome, `log2` of the members'
        /// average Jeffreys share, in Q64, rounded down.
        pub log2_null_mean: [i128; K],
    }

    /// A check whose null chances are derived from field widths: the cookie
    /// echo, the Init roles and the version header.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Derived {
        /// The zenoh side of the `yes` sum, as [`Measured::zenoh`].
        pub zenoh: Prior<2>,
        /// The zenoh side of the `no` sum, as [`Measured::region`].
        pub region: Region,
    }

    /// The wire's front ([`crate::zenoh_evidence::Check::WireFront`]): its null
    /// side is measured, and its zenoh side is derived
    /// ([`LOG2_ALTERED_VERIFIED`], [`LOG2_ALTERED_UNCHECKED`]), so no region.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Front {
        /// The null side of the `yes` sum, as [`Measured::log2_null_bound`]:
        /// a front of this wire, a foreign one.
        pub log2_null_bound: [i128; 2],
        /// The null side of the `no` sum: a prior over a flow's own share of
        /// foreign fronts, centred on the null members' average Jeffreys share
        /// with a weight of one outcome.
        pub null: Prior<2>,
    }

    /// Everything the corpus gives the model, generated from it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Params {
        /// A unit read whole, residual, undecoded.
        pub units: Measured<3>,
        /// A stream direction's framing held, lost.
        pub framing: Measured<2>,
        /// A cookie echo matched, differing.
        pub cookie: Derived,
        /// Two Inits of opposite kinds, of one.
        pub roles: Derived,
        /// A version header of this reader's version, of another.
        pub versions: Derived,
        /// The zenoh side of the `yes` sum for the SN steps: a link's break rate
        /// as a Beta prior over the corpus's links (a step that follows is the
        /// first outcome).
        pub sn: Prior<2>,
        /// A datagram's front of this wire, foreign.
        pub front: Front,
    }

    /// The model the reader ships.
    pub const PARAMS: Params = generated::PARAMS;

    /// The counts of `captures/corpus/` the measured parameters are computed
    /// from, as a build that opens lz4 reads them. Generated: the file is
    /// `zenoh_calibration_generated.rs`, and a test holds it to the corpus.
    pub mod measured {
        /// One null protocol of the corpus.
        pub struct Member {
            /// Its file in `captures/corpus/`.
            pub file: &'static str,
            /// Its framing units: read whole, residual, undecoded.
            pub units: [u64; 3],
            /// Its stream directions: framing held, framing lost.
            pub framing: [u64; 2],
            /// Its datagrams' fronts: of this wire, foreign.
            pub front: [u64; 2],
        }

        // The null protocols (`NULL`, in the manifest's order) and the zenoh files'
        // counts: framing units read whole, residual, undecoded (`ZENOH_UNITS`);
        // stream directions captured from their start, framing held or lost
        // (`ZENOH_FRAMING`); cookie echoes matched or differing (`ZENOH_COOKIE`);
        // Init pairs of opposite kinds or of one (`ZENOH_ROLES`); version headers
        // of this reader's version or another (`ZENOH_VERSIONS`); datagram
        // fronts of this wire or foreign (`ZENOH_FRONT`, which the model does
        // not read: the zenoh side of the front is derived, and a foreign front
        // in a zenoh file would refute the derivation). A null member that
        // shows no observation of a check is not counted for it. What each
        // null protocol does to the stream reader is in
        // `docs/flow-zenoh-verdict.md` section 6.1.
        pub use crate::zenoh_calibration_generated::{
            NULL, ZENOH_COOKIE, ZENOH_FRAMING, ZENOH_FRONT, ZENOH_ROLES, ZENOH_UNITS,
            ZENOH_VERSIONS,
        };
    }
}

/// One observation the test weighs, as the ingest path makes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// An OpenSyn's cookie against the other direction's InitAck's: `Some` with
    /// the cookie's length when it matched, `None` when it differed.
    CookieEcho {
        /// The length of the cookie that matched.
        matched: Option<usize>,
    },
    /// Both directions' Inits are held: of opposite kinds, or of one.
    InitRoles {
        /// They are an InitSyn and an InitAck.
        opposite: bool,
    },
    /// SN steps of one link, counted together (the order of steps within a
    /// packet moves no sum: both sides are functions of the counts).
    SnSteps {
        /// The link the steps were on, as the caller numbers its links.
        link: u64,
        /// Steps that followed.
        follows: u64,
        /// Steps that broke.
        breaks: u64,
    },
    /// A version header read whole: this reader's version, or another.
    VersionHeader {
        /// It is this reader's.
        own: bool,
    },
    /// A framing unit read.
    UnitReading(wz_session_core::passive::UnitReading),
    /// A stream direction captured from its start had its framing judged.
    StreamFraming {
        /// It framed a unit before it lost its framing.
        held: bool,
    },
    /// The first byte of a datagram the link delimits, against the wire's
    /// transport message ids.
    WireFront {
        /// Its low five bits are a transport message id of this wire.
        own: bool,
        /// How far the byte is known to be the one the sender wrote.
        integrity: Integrity,
    },
}

/// One check's observations on a flow: how many confirmed it, how many violated
/// it, and what they came to in each sum, in millibits rounded toward the side
/// that sum rejects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CheckTally {
    /// Observations that confirmed the check.
    pub confirmed: u64,
    /// Observations that violated it.
    pub violated: u64,
    /// Their part of the `yes` sum.
    pub millibits: i64,
    /// Their part of the `no` sum.
    pub no_millibits: i64,
}

impl CheckTally {
    /// Whether anything was observed.
    pub fn observed(&self) -> bool {
        self.confirmed > 0 || self.violated > 0
    }
}

/// A value in Q64 bits with a bound on its error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Value {
    q: i128,
    err: i128,
}

impl Value {
    fn add(&mut self, q: i128, err: i128) {
        self.q = self.q.saturating_add(q);
        self.err = self.err.saturating_add(err);
    }

    fn yes(self) -> i64 {
        floor_millibits(self.q, self.err)
    }

    fn no(self) -> i64 {
        ceil_millibits(self.q, self.err)
    }
}

/// One check whose outcomes share a rate: its counts and its two values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RateCheck<const K: usize> {
    counts: [u64; K],
    yes: Value,
    no: Value,
}

impl<const K: usize> Default for RateCheck<K> {
    fn default() -> Self {
        Self {
            counts: [0; K],
            yes: Value::default(),
            no: Value::default(),
        }
    }
}

impl<const K: usize> RateCheck<K> {
    /// Outcome `o`, with the null side's `log2` chance of it in each sum. The
    /// zenoh side of the `yes` sum is `prior`'s predictive chance; of the `no`
    /// sum, one for the first outcome (a rate of zero is in every region) and
    /// `region`'s bound for a failure.
    fn step(&mut self, o: usize, prior: &Prior<K>, region: &Region, null_yes: i128, null_no: i128) {
        let t: u64 = self.counts.iter().sum();
        if t >= MAX_COUNT {
            return;
        }
        let failed: u64 = self.counts[1..].iter().sum();
        self.yes.add(
            prior.log2_predictive(&self.counts, o) - null_yes,
            2 * LOG_ERR_Q64,
        );
        let zenoh_no = if o == 0 {
            0
        } else {
            region.log2_sup_failure(failed, t)
        };
        self.no.add(zenoh_no - null_no, 2 * LOG_ERR_Q64);
        self.counts[o] += 1;
    }

    fn tally(&self) -> CheckTally {
        CheckTally {
            confirmed: self.counts[0],
            violated: self.counts[1..].iter().sum(),
            millibits: self.yes.yes(),
            no_millibits: self.no.no(),
        }
    }
}

/// The wire's front: its counts (of this wire, foreign) and its two values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct FrontCheck {
    counts: [u64; 2],
    yes: Value,
    no: Value,
}

impl FrontCheck {
    /// Outcome `o` (a front of this wire, foreign) of a datagram of
    /// `integrity`.
    ///
    /// The zenoh side is derived: a zenoh sender writes a transport message id
    /// of the wire there (or a batch header, whose value is one of them), so a
    /// foreign front is an alteration on the way, of chance at most `2^-a`
    /// whatever the sender, the release or the group ([`model::LOG2_ALTERED_VERIFIED`],
    /// [`model::LOG2_ALTERED_UNCHECKED`]). The `no` sum's zenoh side is that
    /// bound, and one for a front of the wire. The `yes` sum's is a prediction,
    /// which moves only how soon a word comes: a prior of weight one outcome
    /// centred on the bound, so that a flow of fronts of the wire costs the sum
    /// a few millionths of a bit and not a share of a bit each. The null side
    /// is the members' as measured: their largest share for the `yes` sum, a
    /// prior over the flow's own share for the `no` sum.
    fn step(&mut self, o: usize, integrity: Integrity, p: &model::Front) {
        let t: u64 = self.counts.iter().sum();
        if t >= MAX_COUNT {
            return;
        }
        let log2_altered = match integrity {
            Integrity::Verified => model::LOG2_ALTERED_VERIFIED,
            Integrity::Unchecked => model::LOG2_ALTERED_UNCHECKED,
        };
        // `log2_altered` is a whole number of bits, `-a`: the prior's weights are
        // `(2^a - 1) / 2^a` and `1 / 2^a`, and its predictive chance of `o` is
        // `(c_o 2^a + w_o) / ((t + 1) 2^a)`.
        let a = u32::try_from(-log2_altered).unwrap_or(64).min(64);
        let scale = 1u128 << a;
        let weight = if o == 0 { scale - 1 } else { 1 };
        let zenoh = crate::zenoh_eprocess::log2_ratio(
            u128::from(self.counts[o]) * scale + weight,
            (u128::from(t) + 1) * scale,
        );
        let null_yes = log2_null_sup(p.log2_null_bound[o], self.counts[o], t);
        self.yes.add(zenoh - null_yes, 2 * LOG_ERR_Q64);
        let zenoh_no = if o == 0 { 0 } else { log2_altered * ONE_Q64 };
        self.no.add(
            zenoh_no - p.null.log2_predictive(&self.counts, o),
            LOG_ERR_Q64,
        );
        self.counts[o] += 1;
    }

    fn tally(&self) -> CheckTally {
        CheckTally {
            confirmed: self.counts[0],
            violated: self.counts[1],
            millibits: self.yes.yes(),
            no_millibits: self.no.no(),
        }
    }
}

/// One link's SN steps: the break rate is the link's, so each link keeps its
/// own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SnLink {
    link: u64,
    /// Steps that followed, that broke.
    counts: [u64; 2],
    yes: Value,
    no: Value,
}

impl SnLink {
    /// `follows` and `breaks` more steps.
    fn steps(&mut self, prior: &Prior<2>, follows: u64, breaks: u64) {
        let room = |c: u64, n: u64| n.min(MAX_COUNT.saturating_sub(c));
        let breaks = room(self.counts[0] + self.counts[1], breaks);
        let follows = room(self.counts[0] + self.counts[1] + breaks, follows);
        // The null side: a step follows with chance 2^-8 (a varint equals a given
        // value at most that often) and breaks with the rest.
        let null_break = LOG2_BREAK_NULL_Q64;
        for (o, n, null) in [(1usize, breaks, null_break), (0, follows, -8 * ONE_Q64)] {
            for _ in 0..n {
                self.yes.add(
                    prior.log2_predictive(&self.counts, o) - null,
                    3 * LOG_ERR_Q64,
                );
                self.counts[o] += 1;
            }
        }
        // The `no` sum's zenoh side is the likeliest rate for the steps so far,
        // a function of the counts: computed again, not added to.
        let [f, b] = self.counts;
        let n = i128::from(f) + i128::from(b);
        self.no = Value {
            q: log2_sn_sup(f, b) + 8 * i128::from(f) * ONE_Q64 - i128::from(b) * null_break,
            err: (n + 1) * 3 * LOG_ERR_Q64,
        };
    }
}

/// The first crossing of a threshold, and what the sums read there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crossing {
    /// The capture-global index of the packet the crossing observation
    /// completed in.
    pub packet: u64,
    /// The `yes` sum was at or above [`model::YES_AT`].
    pub yes: bool,
    /// The `no` sum was at or below [`model::NO_AT`].
    pub no: bool,
}

/// A flow's observations, one tally per [`Check`], its two sums, its first
/// crossing and the extremes of each sum so far.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ZenohEvidence {
    units: RateCheck<3>,
    framing: RateCheck<2>,
    cookie: RateCheck<2>,
    roles: RateCheck<2>,
    versions: RateCheck<2>,
    front: FrontCheck,
    sn: Vec<SnLink>,
    crossing: Option<Crossing>,
    /// The largest and the smallest `yes` sum, then `no` sum, so far (the
    /// starting zero included).
    extremes: [i64; 4],
    /// Every observation in order, for the tests that read a flow again with
    /// other parameters.
    #[cfg(test)]
    pub(crate) log: Vec<(Observation, u64)>,
}

#[cfg(test)]
std::thread_local! {
    /// Whether evidence made on this thread keeps its observations in
    /// [`ZenohEvidence::log`]: only for the tests that read a flow again
    /// ([`recording`]), so that a test of what a dissection holds measures the
    /// reader and not a test's log.
    static RECORDS: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// Run `f` with the evidence made on this thread keeping its observations.
#[cfg(test)]
pub(crate) fn recording<T>(f: impl FnOnce() -> T) -> T {
    let was = RECORDS.with(|r| r.replace(true));
    let out = f();
    RECORDS.with(|r| r.set(was));
    out
}

impl ZenohEvidence {
    /// One observation, completed in the packet at `packet`, read with the
    /// model the reader ships.
    pub fn observe(&mut self, observation: Observation, packet: u64) {
        self.observe_with(observation, packet, &model::PARAMS);
    }

    /// One observation, read with `params`.
    pub fn observe_with(&mut self, observation: Observation, packet: u64, params: &model::Params) {
        #[cfg(test)]
        if RECORDS.with(core::cell::Cell::get) {
            self.log.push((observation, packet));
        }
        match observation {
            Observation::CookieEcho { matched } => {
                // A match is `2^-8` a byte by chance, up to the cap; a mismatch is
                // what arbitrary bytes nearly always are, chance one.
                let (o, null) = match matched {
                    Some(len) => {
                        let bytes = i128::try_from(len)
                            .unwrap_or(i128::MAX)
                            .min(i128::from(model::COOKIE_ECHO_MAX_BYTES));
                        (
                            0,
                            -bytes * i128::from(model::COOKIE_ECHO_PER_BYTE) / 1000 * ONE_Q64,
                        )
                    }
                    None => (1, 0),
                };
                let p = &params.cookie;
                self.cookie.step(o, &p.zenoh, &p.region, null, null);
            }
            Observation::InitRoles { opposite } => {
                // Two arbitrary Inits are of opposite kinds with chance one half.
                let p = &params.roles;
                let o = usize::from(!opposite);
                self.roles.step(o, &p.zenoh, &p.region, -ONE_Q64, -ONE_Q64);
            }
            Observation::VersionHeader { own } => {
                // A byte equals the version with chance 2^-8.
                let null = if own {
                    -8 * ONE_Q64
                } else {
                    LOG2_BREAK_NULL_Q64
                };
                let p = &params.versions;
                self.versions
                    .step(usize::from(!own), &p.zenoh, &p.region, null, null);
            }
            Observation::UnitReading(reading) => {
                use wz_session_core::passive::UnitReading;
                let o = match reading {
                    UnitReading::Explained => 0,
                    UnitReading::Residual => 1,
                    UnitReading::Undecoded => 2,
                };
                let p = &params.units;
                let t: u64 = self.units.counts.iter().sum();
                let null_yes = log2_null_sup(p.log2_null_bound[o], self.units.counts[o], t);
                self.units
                    .step(o, &p.zenoh, &p.region, null_yes, p.log2_null_mean[o]);
            }
            Observation::StreamFraming { held } => {
                let o = usize::from(!held);
                let p = &params.framing;
                let t: u64 = self.framing.counts.iter().sum();
                let null_yes = log2_null_sup(p.log2_null_bound[o], self.framing.counts[o], t);
                self.framing
                    .step(o, &p.zenoh, &p.region, null_yes, p.log2_null_mean[o]);
            }
            Observation::WireFront { own, integrity } => {
                self.front.step(usize::from(!own), integrity, &params.front);
            }
            Observation::SnSteps {
                link,
                follows,
                breaks,
            } => {
                if follows == 0 && breaks == 0 {
                    return;
                }
                let at = match self.sn.iter().position(|l| l.link == link) {
                    Some(at) => at,
                    None => {
                        self.sn.push(SnLink {
                            link,
                            counts: [0; 2],
                            yes: Value::default(),
                            no: Value::default(),
                        });
                        self.sn.len() - 1
                    }
                };
                self.sn[at].steps(&params.sn, follows, breaks);
            }
        }
        self.settle(packet);
    }

    /// The sums after an observation: the extremes move, and the first crossing
    /// latches.
    fn settle(&mut self, packet: u64) {
        let (yes, no) = (self.log2_lr_millibits(), self.log2_lr_no_millibits());
        let [yes_max, yes_min, no_max, no_min] = &mut self.extremes;
        *yes_max = (*yes_max).max(yes);
        *yes_min = (*yes_min).min(yes);
        *no_max = (*no_max).max(no);
        *no_min = (*no_min).min(no);
        let (crossed_yes, crossed_no) = (yes >= model::YES_AT, no <= model::NO_AT);
        if self.crossing.is_none() && (crossed_yes || crossed_no) {
            self.crossing = Some(Crossing {
                packet,
                yes: crossed_yes,
                no: crossed_no,
            });
        }
    }

    /// One check's tally.
    pub fn tally(&self, check: Check) -> CheckTally {
        match check {
            Check::CookieEcho => self.cookie.tally(),
            Check::InitRoles => self.roles.tally(),
            Check::VersionHeader => self.versions.tally(),
            Check::UnitReading => self.units.tally(),
            Check::StreamFraming => self.framing.tally(),
            Check::WireFront => self.front.tally(),
            Check::SnFollows => {
                let mut yes = Value::default();
                let mut no = Value::default();
                let (mut follows, mut breaks) = (0u64, 0u64);
                for l in &self.sn {
                    yes.add(l.yes.q, l.yes.err);
                    no.add(l.no.q, l.no.err);
                    follows = follows.saturating_add(l.counts[0]);
                    breaks = breaks.saturating_add(l.counts[1]);
                }
                CheckTally {
                    confirmed: follows,
                    violated: breaks,
                    millibits: yes.yes(),
                    no_millibits: no.no(),
                }
            }
        }
    }

    /// The `yes` sum now, in millibits: its checks' parts added.
    pub fn log2_lr_millibits(&self) -> i64 {
        Check::ALL
            .iter()
            .fold(0i64, |sum, &c| sum.saturating_add(self.tally(c).millibits))
    }

    /// The `no` sum now, in millibits: its checks' parts added.
    pub fn log2_lr_no_millibits(&self) -> i64 {
        Check::ALL.iter().fold(0i64, |sum, &c| {
            sum.saturating_add(self.tally(c).no_millibits)
        })
    }

    /// The first crossing of a threshold, or `None` while neither sum has
    /// crossed: the word of the flow, latched.
    pub fn crossing(&self) -> Option<Crossing> {
        self.crossing
    }

    /// The largest `yes` sum so far, the starting zero included.
    pub fn log2_lr_max_millibits(&self) -> i64 {
        self.extremes[0]
    }

    /// The smallest `yes` sum so far.
    pub fn log2_lr_min_millibits(&self) -> i64 {
        self.extremes[1]
    }

    /// The largest `no` sum so far.
    pub fn log2_lr_no_max_millibits(&self) -> i64 {
        self.extremes[2]
    }

    /// The smallest `no` sum so far.
    pub fn log2_lr_no_min_millibits(&self) -> i64 {
        self.extremes[3]
    }

    /// The unit readings weighed so far: read whole, residual, undecoded. A
    /// datagram whose front was foreign is not among them (its reading follows
    /// from its front).
    #[cfg(test)]
    pub(crate) fn unit_outcomes(&self) -> [u64; 3] {
        self.units.counts
    }

    /// Every observation made so far, in order, read again with `params`: the
    /// evidence those parameters would have given.
    #[cfg(test)]
    pub(crate) fn replayed_with(&self, params: &model::Params) -> ZenohEvidence {
        let mut out = ZenohEvidence::default();
        for &(observation, packet) in &self.log {
            out.observe_with(observation, packet, params);
        }
        out
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use wz_session_core::passive::UnitReading;

    /// Evidence that crossed `no`: datagrams whose verified fronts are foreign,
    /// until the sum crosses.
    pub(crate) fn crossed_no() -> ZenohEvidence {
        let mut e = ZenohEvidence::default();
        for packet in 0..4 {
            e.observe(
                Observation::WireFront {
                    own: false,
                    integrity: Integrity::Verified,
                },
                packet,
            );
            if e.crossing().is_some() {
                break;
            }
        }
        e
    }

    /// Evidence with every check observed both ways.
    pub(crate) fn every_check_both_ways() -> ZenohEvidence {
        let mut e = ZenohEvidence::default();
        for (packet, observation) in [
            Observation::CookieEcho { matched: Some(8) },
            Observation::CookieEcho { matched: None },
            Observation::InitRoles { opposite: true },
            Observation::InitRoles { opposite: false },
            Observation::SnSteps {
                link: 0,
                follows: 1,
                breaks: 1,
            },
            Observation::VersionHeader { own: true },
            Observation::VersionHeader { own: false },
            Observation::UnitReading(UnitReading::Explained),
            Observation::UnitReading(UnitReading::Residual),
            Observation::StreamFraming { held: true },
            Observation::StreamFraming { held: false },
            Observation::WireFront {
                own: true,
                integrity: Integrity::Verified,
            },
            Observation::WireFront {
                own: false,
                integrity: Integrity::Unchecked,
            },
        ]
        .into_iter()
        .enumerate()
        {
            e.observe(observation, packet as u64);
        }
        e
    }

    #[test]
    fn the_built_words_are_the_words_they_say() {
        let no = crossed_no();
        let c = no.crossing().expect("crossed");
        assert!(c.no && !c.yes, "{c:?}");
        for check in Check::ALL {
            let t = every_check_both_ways().tally(check);
            assert!(t.confirmed > 0 && t.violated > 0, "{check:?}");
        }
    }

    /// Nothing observed weighs nothing, and has not crossed.
    #[test]
    fn no_observation_weighs_nothing() {
        let e = ZenohEvidence::default();
        assert_eq!(e.log2_lr_millibits(), 0);
        assert_eq!(e.log2_lr_no_millibits(), 0);
        assert_eq!(e.crossing(), None);
        for c in Check::ALL {
            assert!(!e.tally(c).observed());
        }
    }

    /// The sums are their checks' parts added, every part rounded toward the
    /// side its sum rejects.
    #[test]
    fn the_sums_are_the_checks_parts_added() {
        let mut e = ZenohEvidence::default();
        e.observe(Observation::VersionHeader { own: true }, 0);
        e.observe(Observation::UnitReading(UnitReading::Explained), 0);
        e.observe(Observation::UnitReading(UnitReading::Undecoded), 1);
        e.observe(
            Observation::SnSteps {
                link: 0,
                follows: 3,
                breaks: 1,
            },
            1,
        );
        let parts: i64 = Check::ALL.iter().map(|&c| e.tally(c).millibits).sum();
        let no_parts: i64 = Check::ALL.iter().map(|&c| e.tally(c).no_millibits).sum();
        assert_eq!(e.log2_lr_millibits(), parts);
        assert_eq!(e.log2_lr_no_millibits(), no_parts);
        assert_eq!(e.tally(Check::UnitReading).confirmed, 1);
        assert_eq!(e.tally(Check::UnitReading).violated, 1);
        assert_eq!(e.tally(Check::SnFollows).confirmed, 3);
        assert_eq!(e.tally(Check::SnFollows).violated, 1);
        // A version header of this reader is about eight bits either way.
        let v = e.tally(Check::VersionHeader);
        assert!((7_900..8_000).contains(&v.millibits), "{v:?}");
        assert!(v.no_millibits >= 8_000, "{v:?}");
    }

    /// A matched cookie of eight bytes crosses `yes` at once, and the word
    /// stays where it latched while the sums move on: a failure of each of the
    /// other checks, each a rate the zenoh prior puts near zero, brings the
    /// `yes` sum back under its threshold.
    #[test]
    fn the_word_latches_at_the_first_crossing() {
        let mut e = ZenohEvidence::default();
        e.observe(Observation::UnitReading(UnitReading::Explained), 3);
        assert_eq!(e.crossing(), None);
        e.observe(Observation::CookieEcho { matched: Some(16) }, 7);
        let crossed = e.crossing().expect("64 bits cross");
        assert_eq!((crossed.packet, crossed.yes, crossed.no), (7, true, false));
        for (packet, observation) in [
            Observation::CookieEcho { matched: None },
            Observation::VersionHeader { own: false },
            Observation::InitRoles { opposite: false },
            Observation::UnitReading(UnitReading::Residual),
            Observation::StreamFraming { held: false },
        ]
        .into_iter()
        .enumerate()
        {
            e.observe(observation, 8 + packet as u64);
        }
        assert!(
            e.log2_lr_millibits() < model::YES_AT,
            "{}",
            e.log2_lr_millibits()
        );
        assert_eq!(e.crossing(), Some(crossed));
        assert!(e.log2_lr_max_millibits() >= 63_000);
        assert!(e.log2_lr_min_millibits() <= 0);
        assert!(e.log2_lr_no_max_millibits() >= 63_000);
    }

    /// The `no` sum never takes a broken step as evidence against zenoh: the
    /// break rate is the link's, and the zenoh side takes the flow's own.
    #[test]
    fn broken_steps_alone_never_count_against_zenoh() {
        let mut e = ZenohEvidence::default();
        for packet in 0..200 {
            e.observe(
                Observation::SnSteps {
                    link: 0,
                    follows: 0,
                    breaks: 1,
                },
                packet,
            );
        }
        assert!(
            e.log2_lr_no_millibits() >= 0,
            "{}",
            e.log2_lr_no_millibits()
        );
    }

    /// A foreign front weighs against zenoh by what the integrity of its bytes
    /// allows, and a front of the wire never raises the `yes` sum: some null
    /// protocol writes nothing else there.
    #[test]
    fn a_foreign_front_weighs_what_its_integrity_allows() {
        let front = |own, integrity| Observation::WireFront { own, integrity };
        let mut verified = ZenohEvidence::default();
        verified.observe(front(false, Integrity::Verified), 0);
        let mut unchecked = ZenohEvidence::default();
        unchecked.observe(front(false, Integrity::Unchecked), 0);
        let v = verified.tally(Check::WireFront).no_millibits;
        let u = unchecked.tally(Check::WireFront).no_millibits;
        // The zenoh side is the bound itself, the null side a share below one.
        assert!((-24_000..-14_000).contains(&v), "{v}");
        assert!((-10_000..-1_000).contains(&u), "{u}");
        assert!(crossed_no().crossing().is_some_and(|c| c.no && !c.yes));
        let mut own = ZenohEvidence::default();
        for packet in 0..10_000 {
            own.observe(front(true, Integrity::Verified), packet);
            own.observe(front(true, Integrity::Unchecked), packet);
        }
        let t = own.tally(Check::WireFront);
        assert!(t.millibits <= 0 && t.millibits > -50, "{t:?}");
        assert!(t.no_millibits >= 0, "{t:?}");
        assert_eq!((t.confirmed, t.violated), (20_000, 0));
    }

    /// Steps of two links are two rates: each link's likeliest is its own.
    #[test]
    fn each_link_keeps_its_own_steps() {
        let mut two = ZenohEvidence::default();
        two.observe(
            Observation::SnSteps {
                link: 1,
                follows: 50,
                breaks: 0,
            },
            0,
        );
        two.observe(
            Observation::SnSteps {
                link: 2,
                follows: 0,
                breaks: 50,
            },
            1,
        );
        let mut one = ZenohEvidence::default();
        one.observe(
            Observation::SnSteps {
                link: 1,
                follows: 50,
                breaks: 50,
            },
            0,
        );
        assert!(two.log2_lr_no_millibits() > one.log2_lr_no_millibits());
        assert_eq!(two.tally(Check::SnFollows).confirmed, 50);
        assert_eq!(two.tally(Check::SnFollows).violated, 50);
    }

    /// Reading the log again with the shipped parameters gives the same
    /// evidence.
    #[test]
    fn a_replay_with_the_same_parameters_is_the_same_evidence() {
        recording(|| {
            let mut e = ZenohEvidence::default();
            e.observe(Observation::InitRoles { opposite: true }, 1);
            e.observe(Observation::StreamFraming { held: true }, 2);
            e.observe(Observation::UnitReading(UnitReading::Residual), 3);
            e.observe(Observation::CookieEcho { matched: Some(8) }, 4);
            assert_eq!(e.log.len(), 4);
            assert_eq!(e.replayed_with(&model::PARAMS), e);
        });
    }

    /// The vocabularies are distinct words.
    #[test]
    fn the_words_are_distinct() {
        for words in [Check::names(), Strength::names(), Basis::names()] {
            let mut d = words.clone();
            d.dedup();
            assert_eq!(d, words);
        }
    }
}
