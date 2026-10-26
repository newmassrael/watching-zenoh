// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Whether a flow's bytes are zenoh, as a sequential probability ratio test
//! over the invariants a zenoh flow keeps (`docs/flow-zenoh-verdict.md`).
//!
//! # The test
//!
//! Every observation adds `log2(P(o | zenoh) / P(o | not zenoh))` to the flow's
//! log likelihood ratio, and the verdict reads the sum against two thresholds
//! fixed by the error rates ([`model::YES_AT`], [`model::NO_AT`]). The verdict
//! is read at every moment and not frozen at the first crossing: with true
//! conditional ratios, `2^L` is a nonnegative martingale under the null, and
//! Ville's inequality bounds the chance that it EVER reaches `1/alpha` by
//! `alpha`. A live tap reading the verdict after every packet is inside the
//! bound.
//!
//! # Counted at ingest, in whole millibits
//!
//! Each observation's weight is a whole number of millibits taken from
//! [`model`], so a sum is exact and does not depend on the order the
//! observations arrived in. The tallies are kept where the data arrives, for the
//! reason `session_table`'s module gives: a retention ceiling discards the
//! oldest messages, and the handshake is the oldest.
//!
//! # What a weight claims
//!
//! Each side of each check names its [`Basis`]: a probability derived from
//! field widths, one measured on the GENERATED corpus, or one assumed until a
//! measurement replaces it. A weight is a statement against the null protocols
//! its basis covers and no others, and the document carries the basis so that a
//! consumer can say so.

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
    /// An admissible Init, Join, Scout or Hello of the version this reader
    /// reads, out of a framing unit read whole.
    VersionHeader,
    /// How a framing unit read ([`wz_session_core::passive::UnitReading`]).
    UnitReading,
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
    /// The largest share any protocol of the generated corpus shows.
    Generated,
    /// Stated without a measurement; a corpus replaces it.
    Assumed,
    /// The check has no such side: it can only confirm.
    None,
}

impl Check {
    /// Every check, in the order the document lists them.
    pub const ALL: [Check; 5] = [
        Check::CookieEcho,
        Check::InitRoles,
        Check::SnFollows,
        Check::VersionHeader,
        Check::UnitReading,
    ];

    /// The word the document writes for this check.
    pub const fn name(self) -> &'static str {
        match self {
            Check::CookieEcho => "cookie_echo",
            Check::InitRoles => "init_roles",
            Check::SnFollows => "sn_follows",
            Check::VersionHeader => "version_header",
            Check::UnitReading => "unit_reading",
        }
    }

    /// How hard the check is to satisfy by chance.
    pub const fn strength(self) -> Strength {
        match self {
            Check::CookieEcho | Check::InitRoles => Strength::Handshake,
            Check::SnFollows => Strength::State,
            Check::VersionHeader => Strength::Header,
            Check::UnitReading => Strength::Unit,
        }
    }

    /// Where the chance that a flow that is not zenoh satisfies the check comes
    /// from.
    pub const fn q_basis(self) -> Basis {
        match self {
            Check::CookieEcho | Check::InitRoles | Check::SnFollows | Check::VersionHeader => {
                Basis::Derived
            }
            Check::UnitReading => Basis::Generated,
        }
    }

    /// Where the chance that a zenoh flow fails the check comes from.
    pub const fn eps_basis(self) -> Basis {
        match self {
            Check::VersionHeader => Basis::None,
            Check::CookieEcho | Check::InitRoles | Check::SnFollows | Check::UnitReading => {
                Basis::Assumed
            }
        }
    }

    /// Every word, sorted.
    pub fn names() -> alloc::vec::Vec<&'static str> {
        let mut words: alloc::vec::Vec<&'static str> = Self::ALL.iter().map(|c| c.name()).collect();
        words.sort_unstable();
        words
    }

    fn index(self) -> usize {
        match self {
            Check::CookieEcho => 0,
            Check::InitRoles => 1,
            Check::SnFollows => 2,
            Check::VersionHeader => 3,
            Check::UnitReading => 4,
        }
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
    pub fn names() -> alloc::vec::Vec<&'static str> {
        let mut words: alloc::vec::Vec<&'static str> = Self::ALL.iter().map(|s| s.name()).collect();
        words.sort_unstable();
        words
    }
}

impl Basis {
    /// Every basis, from an exhaustive match.
    pub const ALL: [Basis; 4] = [
        Basis::Derived,
        Basis::Generated,
        Basis::Assumed,
        Basis::None,
    ];

    /// The word the document writes for this basis.
    pub const fn name(self) -> &'static str {
        match self {
            Basis::Derived => "derived",
            Basis::Generated => "generated",
            Basis::Assumed => "assumed",
            Basis::None => "none",
        }
    }

    /// Every word, sorted.
    pub fn names() -> alloc::vec::Vec<&'static str> {
        let mut words: alloc::vec::Vec<&'static str> = Self::ALL.iter().map(|b| b.name()).collect();
        words.sort_unstable();
        words
    }
}

/// The weights of model 1, in millibits, each with the probabilities it is
/// computed from. `model_weights_are_their_stated_probabilities` recomputes
/// every one, so a literal cannot drift from its derivation.
pub mod model {
    /// The model these weights are, written into the document so that a
    /// consumer can tell two calibrations apart.
    pub const MODEL: u32 = 1;

    /// `log2(1 / alpha)` with `alpha = 2^-20`: at or above it the flow is zenoh.
    pub const YES_AT: i64 = 20_000;

    /// `log2(beta)` with `beta = 2^-20`: at or below it the flow is not zenoh.
    pub const NO_AT: i64 = -20_000;

    /// Per cookie byte matched, `log2(1 / 2^-8)`: an arbitrary byte equals a
    /// given one with chance `2^-8`.
    pub const COOKIE_ECHO_PER_BYTE: i64 = 8_000;

    /// The bytes a cookie match is counted for at most: 64 bits is decisive,
    /// and a cap keeps one observation from outweighing every other the flow
    /// can make.
    pub const COOKIE_ECHO_MAX_BYTES: i64 = 8;

    /// `log2(1 - 2^-10)`, the zenoh side of a cookie match: a zenoh OpenSyn
    /// fails to echo its InitAck's cookie with chance `2^-10` (assumed).
    pub const COOKIE_ECHO_FIDELITY: i64 = -1;

    /// `log2(2^-10 / 1)`: a cookie that differs. An arbitrary pair of byte
    /// strings differs with chance close to one.
    pub const COOKIE_ECHO_VIOLATED: i64 = -10_000;

    /// `log2((1 - 2^-10) / (1/2))`: two Inits of opposite kinds, which two
    /// arbitrary Inits are with chance one half.
    pub const INIT_ROLES_CONFIRMED: i64 = 999;

    /// `log2(2^-10 / (1/2))`: two Inits of the same kind.
    pub const INIT_ROLES_VIOLATED: i64 = -9_000;

    /// `log2((1 - 2^-4) / 2^-8)`: a frame one step after the last. A varint
    /// equals a given value with chance at most `2^-8`, and a zenoh frame
    /// breaks the step (loss, reordering, a duplicate) with chance `2^-4`
    /// (assumed).
    pub const SN_FOLLOWS: i64 = 7_907;

    /// `log2(2^-4 / (1 - 2^-8))`: a frame that is not one step after the last.
    pub const SN_BREAKS: i64 = -3_994;

    /// `log2(1 / 2^-8)`: the version byte of a message that names one.
    pub const VERSION_HEADER: i64 = 8_000;

    /// `log2((1 - 2 * 2^-7) / 0.16203)`: a unit read whole. The null share is
    /// the largest of the generated corpus, mDNS's 8847 of 54600 units.
    pub const UNIT_EXPLAINED: i64 = 2_603;

    /// `log2(2^-7 / 0.83797)`: a unit with bytes left over. mDNS's 45753 of
    /// 54600 units.
    pub const UNIT_RESIDUAL: i64 = -6_745;

    /// `log2(2^-7 / 1)`: a unit that did not decode. SSDP's and syslog's
    /// 54600 of 54600 units.
    pub const UNIT_UNDECODED: i64 = -7_000;
}

/// One check's observations on a flow: how many confirmed it, how many violated
/// it, and the millibits they came to together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CheckTally {
    /// Observations that confirmed the check.
    pub confirmed: u64,
    /// Observations that violated it.
    pub violated: u64,
    /// Their weights, summed.
    pub millibits: i64,
}

impl CheckTally {
    fn and(self, other: CheckTally) -> CheckTally {
        CheckTally {
            confirmed: self.confirmed.saturating_add(other.confirmed),
            violated: self.violated.saturating_add(other.violated),
            millibits: self.millibits.saturating_add(other.millibits),
        }
    }

    /// Whether anything was observed.
    pub fn observed(&self) -> bool {
        self.confirmed > 0 || self.violated > 0
    }
}

/// A flow's observations, one tally per [`Check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ZenohEvidence {
    tallies: [CheckTally; Check::ALL.len()],
}

impl ZenohEvidence {
    /// One check's tally.
    pub fn tally(&self, check: Check) -> CheckTally {
        self.tallies[check.index()]
    }

    /// An observation that confirmed `check`, weighing `millibits`.
    pub(crate) fn confirm(&mut self, check: Check, millibits: i64) {
        let t = &mut self.tallies[check.index()];
        t.confirmed = t.confirmed.saturating_add(1);
        t.millibits = t.millibits.saturating_add(millibits);
    }

    /// An observation that violated `check`, weighing `millibits`.
    pub(crate) fn violate(&mut self, check: Check, millibits: i64) {
        let t = &mut self.tallies[check.index()];
        t.violated = t.violated.saturating_add(1);
        t.millibits = t.millibits.saturating_add(millibits);
    }

    /// `count` observations of one kind at once, for a counter kept elsewhere
    /// (the SN steps a session counts).
    pub(crate) fn add(&mut self, check: Check, confirmed: u64, violated: u64, millibits: i64) {
        let t = &mut self.tallies[check.index()];
        *t = t.and(CheckTally {
            confirmed,
            violated,
            millibits,
        });
    }

    /// Two bodies of evidence together: a session's flows, or a flow's
    /// sessions.
    pub fn and(self, other: ZenohEvidence) -> ZenohEvidence {
        let mut out = self;
        for (held, more) in out.tallies.iter_mut().zip(other.tallies) {
            *held = held.and(more);
        }
        out
    }

    /// The log likelihood ratio, in millibits.
    pub fn log2_lr_millibits(&self) -> i64 {
        self.tallies
            .iter()
            .fold(0i64, |sum, t| sum.saturating_add(t.millibits))
    }
}

/// The weight of a cookie of `len` bytes matched: per byte, up to the cap,
/// with the zenoh side's fidelity.
pub(crate) fn cookie_echo_weight(len: usize) -> i64 {
    let bytes = i64::try_from(len)
        .unwrap_or(i64::MAX)
        .min(model::COOKIE_ECHO_MAX_BYTES);
    bytes * model::COOKIE_ECHO_PER_BYTE + model::COOKIE_ECHO_FIDELITY
}

/// The weight of one SN step: see [`model::SN_FOLLOWS`].
pub(crate) fn sn_steps_weight(steps: wz_session_core::passive::SnSteps) -> i64 {
    let w = |n: u64, each: i64| i64::try_from(n).unwrap_or(i64::MAX).saturating_mul(each);
    w(steps.follows, model::SN_FOLLOWS).saturating_add(w(steps.breaks, model::SN_BREAKS))
}

/// The weight of a unit that read as `reading`.
pub(crate) fn unit_reading_weight(reading: wz_session_core::passive::UnitReading) -> i64 {
    use wz_session_core::passive::UnitReading;
    match reading {
        UnitReading::Explained => model::UNIT_EXPLAINED,
        UnitReading::Residual => model::UNIT_RESIDUAL,
        UnitReading::Undecoded => model::UNIT_UNDECODED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `round(1000 * log2(x))`, the rule every weight is written by.
    fn millibits(x: f64) -> i64 {
        (1000.0 * x.log2()).round() as i64
    }

    /// Every weight is its stated probabilities, recomputed.
    #[test]
    fn model_weights_are_their_stated_probabilities() {
        let eps_handshake = 2f64.powi(-10);
        let eps_sn = 2f64.powi(-4);
        let eps_unit = 2f64.powi(-7);
        let byte = 2f64.powi(-8);
        assert_eq!(model::YES_AT, millibits(1.0 / 2f64.powi(-20)));
        assert_eq!(model::NO_AT, millibits(2f64.powi(-20)));
        assert_eq!(model::COOKIE_ECHO_PER_BYTE, millibits(1.0 / byte));
        assert_eq!(model::COOKIE_ECHO_FIDELITY, millibits(1.0 - eps_handshake));
        assert_eq!(model::COOKIE_ECHO_VIOLATED, millibits(eps_handshake));
        assert_eq!(
            model::INIT_ROLES_CONFIRMED,
            millibits((1.0 - eps_handshake) / 0.5)
        );
        assert_eq!(model::INIT_ROLES_VIOLATED, millibits(eps_handshake / 0.5));
        assert_eq!(model::SN_FOLLOWS, millibits((1.0 - eps_sn) / byte));
        assert_eq!(model::SN_BREAKS, millibits(eps_sn / (1.0 - byte)));
        assert_eq!(model::VERSION_HEADER, millibits(1.0 / byte));
        let units = 54_600.0;
        assert_eq!(
            model::UNIT_EXPLAINED,
            millibits((1.0 - 2.0 * eps_unit) / (8_847.0 / units))
        );
        assert_eq!(
            model::UNIT_RESIDUAL,
            millibits(eps_unit / (45_753.0 / units))
        );
        assert_eq!(model::UNIT_UNDECODED, millibits(eps_unit / 1.0));
    }

    /// A cookie match counts its bytes up to the cap, less the zenoh side's
    /// fidelity.
    #[test]
    fn a_cookie_match_weighs_its_bytes_up_to_the_cap() {
        assert_eq!(cookie_echo_weight(1), 7_999);
        assert_eq!(cookie_echo_weight(8), 63_999);
        assert_eq!(cookie_echo_weight(40), 63_999);
    }

    /// Evidence sums per check and over checks, and two bodies of it add.
    #[test]
    fn evidence_sums_per_check_and_over_checks() {
        let mut a = ZenohEvidence::default();
        a.confirm(Check::VersionHeader, model::VERSION_HEADER);
        a.violate(Check::UnitReading, model::UNIT_UNDECODED);
        let mut b = ZenohEvidence::default();
        b.confirm(Check::UnitReading, model::UNIT_EXPLAINED);
        let both = a.and(b);
        assert_eq!(
            both.tally(Check::UnitReading),
            CheckTally {
                confirmed: 1,
                violated: 1,
                millibits: model::UNIT_EXPLAINED + model::UNIT_UNDECODED
            }
        );
        assert_eq!(
            both.log2_lr_millibits(),
            model::VERSION_HEADER + model::UNIT_EXPLAINED + model::UNIT_UNDECODED
        );
        assert!(!both.tally(Check::CookieEcho).observed());
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
