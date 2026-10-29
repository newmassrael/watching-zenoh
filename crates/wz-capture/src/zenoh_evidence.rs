// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Whether a flow's bytes are zenoh, as a sequential probability ratio test
//! over the invariants a zenoh flow keeps (`docs/flow-zenoh-verdict.md`).
//!
//! # The test, and why it keeps two sums
//!
//! Every observation adds `log2(P(o | zenoh) / P(o | not zenoh))` to a log
//! likelihood ratio, and the verdict reads it against two thresholds fixed by
//! the error rates ([`crate::zenoh_evidence::model::YES_AT`],
//! [`crate::zenoh_evidence::model::NO_AT`]), at every moment and not frozen at
//! the first crossing: with true conditional ratios the ratio is a nonnegative
//! martingale, and Ville's inequality bounds the chance that it EVER reaches
//! its threshold.
//!
//! "Not zenoh" is a family of protocols, and one denominator cannot serve both
//! bounds. The false `yes` is bounded against every member at once when each
//! outcome's denominator is the LARGEST chance any member gives it; those
//! largest chances sum to more than one, so the same sum read for `no` bounds
//! nothing. The false `no` is bounded when the denominator is a proper
//! distribution, and any proper one serves; the average of the members' is
//! used. So each observation weighs twice ([`crate::zenoh_evidence::Weight`]):
//! the `yes` sum is read against `YES_AT`, the `no` sum against `NO_AT`, and a
//! flow whose two sums both cross is `undecided`.
//!
//! # Counted at ingest, in whole millibits
//!
//! Each weight is a whole number of millibits taken from
//! [`crate::zenoh_evidence::model`], so a sum is exact and does not depend on
//! the order the observations arrived in. The tallies are kept where the data
//! arrives, for the reason `session_table`'s module gives: a retention ceiling
//! discards the oldest messages, and the handshake is the oldest.
//!
//! Every link in this doc is fully qualified: it is merged with the `pub mod`
//! doc in `lib.rs` and resolved in the crate root.
//!
//! # What a weight claims
//!
//! Each side of each check names its [`crate::zenoh_evidence::Basis`]: a
//! probability derived from field widths, one measured on the real captures of
//! `captures/corpus/`, or one assumed until a measurement replaces it. A
//! measured null chance is a statement against the protocols the corpus holds
//! and no others, and the document carries the basis so that a consumer can
//! say so.

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
    pub const ALL: [Check; 6] = [
        Check::CookieEcho,
        Check::InitRoles,
        Check::SnFollows,
        Check::VersionHeader,
        Check::UnitReading,
        Check::StreamFraming,
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
        }
    }

    /// How hard the check is to satisfy by chance.
    pub const fn strength(self) -> Strength {
        match self {
            Check::CookieEcho | Check::InitRoles => Strength::Handshake,
            Check::SnFollows => Strength::State,
            Check::VersionHeader => Strength::Header,
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
            Check::UnitReading | Check::StreamFraming => Basis::Measured,
        }
    }

    /// Where the chance that a zenoh flow fails the check comes from.
    ///
    /// The SN steps stay assumed though the corpus counts them: how often a
    /// step breaks is a property of the LINK (what it loses and reorders), not
    /// of zenoh, so the assumed rate is the loss the test is built to tolerate,
    /// and the `zenoh-udp-loss*` captures, links dropping 1% to 20% each way,
    /// the `-reorder-` and `-dup-` captures and the TCP ones hold it to
    /// reading `yes` there.
    pub const fn eps_basis(self) -> Basis {
        match self {
            Check::SnFollows => Basis::Assumed,
            Check::CookieEcho
            | Check::InitRoles
            | Check::VersionHeader
            | Check::UnitReading
            | Check::StreamFraming => Basis::Measured,
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
            Check::StreamFraming => 5,
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
    pub fn names() -> alloc::vec::Vec<&'static str> {
        let mut words: alloc::vec::Vec<&'static str> = Self::ALL.iter().map(|b| b.name()).collect();
        words.sort_unstable();
        words
    }
}

/// One observation's weight in each of the test's two sums, in millibits: the
/// `yes` sum's against the largest chance any null protocol gives the outcome,
/// the `no` sum's against the members' average. A check whose null chance is
/// derived from field widths has one distribution for every member, and both
/// sums take the same weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Weight {
    /// In the sum read for `yes`.
    pub yes: i64,
    /// In the sum read for `no`.
    pub no: i64,
}

impl Weight {
    /// The same weight in both sums.
    pub const fn both(millibits: i64) -> Self {
        Self {
            yes: millibits,
            no: millibits,
        }
    }

    /// `n` observations of this weight.
    pub fn times(self, n: u64) -> Self {
        let n = i64::try_from(n).unwrap_or(i64::MAX);
        Self {
            yes: self.yes.saturating_mul(n),
            no: self.no.saturating_mul(n),
        }
    }

    /// Two weights together.
    pub fn plus(self, other: Self) -> Self {
        Self {
            yes: self.yes.saturating_add(other.yes),
            no: self.no.saturating_add(other.no),
        }
    }
}

/// The weights of model 2, in millibits, each with the probabilities it is
/// computed from. `model_weights_are_their_stated_probabilities` recomputes
/// every one, the measured ones from
/// [`crate::zenoh_evidence::model::measured`]'s counts, so a literal
/// cannot drift from its derivation, and the corpus test measures those counts
/// again from `captures/corpus/`.
pub mod model {
    use super::Weight;

    /// The model these weights are, written into the document so that a
    /// consumer can tell two calibrations apart.
    pub const MODEL: u32 = 2;

    /// `log2(1 / alpha)` with `alpha = 2^-20`: at or above it the `yes` sum
    /// says zenoh.
    pub const YES_AT: i64 = 20_000;

    /// `log2(beta)` with `beta = 2^-20`: at or below it the `no` sum says not
    /// zenoh.
    pub const NO_AT: i64 = -20_000;

    /// Per cookie byte matched, `log2(1 / 2^-8)`: an arbitrary byte equals a
    /// given one with chance `2^-8`.
    pub const COOKIE_ECHO_PER_BYTE: i64 = 8_000;

    /// The bytes a cookie match is counted for at most: 64 bits is decisive,
    /// and a cap keeps one observation from outweighing every other the flow
    /// can make.
    pub const COOKIE_ECHO_MAX_BYTES: i64 = 8;

    /// `log2(1 - e)`, the zenoh side of a cookie match: a zenoh OpenSyn fails
    /// to echo its InitAck's cookie with chance `e`, the bound of 0 failures
    /// in the corpus's 304 echoes ([`measured::ZENOH_COOKIE`]).
    pub const COOKIE_ECHO_FIDELITY: i64 = -14;

    /// `log2(e / 1)`: a cookie that differs. An arbitrary pair of byte strings
    /// differs with chance close to one.
    pub const COOKIE_ECHO_VIOLATED: Weight = Weight::both(-6_672);

    /// `log2((1 - e) / (1/2))`: two Inits of opposite kinds, which two
    /// arbitrary Inits are with chance one half; `e` the bound of 0 pairs of
    /// one kind in 306 ([`measured::ZENOH_ROLES`]).
    pub const INIT_ROLES_CONFIRMED: Weight = Weight::both(986);

    /// `log2(e / (1/2))`: two Inits of the same kind.
    pub const INIT_ROLES_VIOLATED: Weight = Weight::both(-5_682);

    /// `log2((1 - 2^-4) / 2^-8)`: a frame one step after the last. A varint
    /// equals a given value with chance at most `2^-8`, and a zenoh frame
    /// breaks the step (loss, reordering, a duplicate) with chance `2^-4`
    /// (assumed).
    pub const SN_FOLLOWS: Weight = Weight::both(7_907);

    /// `log2(2^-4 / (1 - 2^-8))`: a frame that is not one step after the last.
    pub const SN_BREAKS: Weight = Weight::both(-3_994);

    /// `log2((1 - e) / 2^-8)`: the version byte of a message that names one
    /// is this reader's. A byte equals it by chance `2^-8`, and a zenoh flow
    /// of this version names another with chance `e`, the bound of 0 in the
    /// corpus's 612 version headers ([`measured::ZENOH_VERSIONS`]).
    pub const VERSION_HEADER: Weight = Weight::both(7_993);

    /// `log2(e / (1 - 2^-8))`: it names another version. Model 1 weighed
    /// only the match, which bounds neither sum: an observation that can only
    /// confirm raises the `yes` sum's expectation under the null.
    pub const VERSION_FOREIGN: Weight = Weight::both(-7_672);

    /// A unit read whole. Zenoh: one less the two failures' bounds. `yes`:
    /// mDNS's bound, 13 of 36 units; `no`: the members' average.
    pub const UNIT_EXPLAINED: Weight = Weight {
        yes: 965,
        no: 3_983,
    };

    /// A unit with bytes left over. Zenoh: the bound of 0 in 6075 units;
    /// `yes`: QUIC's 22 of 22; `no`: the members' average.
    pub const UNIT_RESIDUAL: Weight = Weight {
        yes: -10_986,
        no: -9_618,
    };

    /// A unit that did not decode. Zenoh: as residual; `yes`: SSDP's 26 of
    /// 26; `no`: the members' average.
    pub const UNIT_UNDECODED: Weight = Weight {
        yes: -10_986,
        no: -10_122,
    };

    /// A stream direction, captured from its start, that framed a unit before
    /// it lost its framing. Zenoh: one less the bound of 0 lost in 300; `yes`:
    /// the bound of 0 held in 48, PostgreSQL's; `no`: the smoothed shares of
    /// the four members that lose it (MQTT, HTTP opening with another method,
    /// Redis, PostgreSQL), averaged.
    pub const FRAMING_HELD: Weight = Weight {
        yes: 4_032,
        no: 7_043,
    };

    /// A stream direction, captured from its start, that lost its framing
    /// before it framed a unit: bytes that are not zenoh's framing.
    pub const FRAMING_LOST: Weight = Weight {
        yes: -6_653,
        no: -6_642,
    };

    /// The counts of `captures/corpus/` the measured weights are computed
    /// from, as a build that opens lz4 reads them (2026-10-26).
    ///
    /// The rule (`docs/flow-zenoh-verdict.md` §6.2): for zenoh, each outcome a
    /// zenoh flow fails with takes the one-sided 95% Clopper-Pearson upper
    /// bound on its share, and the confirming outcome the rest. The `yes`
    /// sum's null chance of an outcome is the largest such upper bound over
    /// the members; the `no` sum's is the average over the members of each
    /// one's Jeffreys estimate (`(k + 1/2) / (n + K/2)` over `K` outcomes), a
    /// proper distribution. A member that shows no observation of a check is
    /// not counted for it.
    pub mod measured {
        /// One null protocol of the corpus.
        pub struct Member {
            /// Its file in `captures/corpus/`.
            pub file: &'static str,
            /// Its framing units: read whole, residual, undecoded.
            pub units: [u64; 3],
            /// Its stream directions: framing held, framing lost.
            pub framing: [u64; 2],
        }

        /// The null protocols.
        pub const NULL: [Member; 16] = [
            Member {
                file: "lan-dns.pcap",
                units: [26, 32, 320],
                framing: [0, 0],
            },
            Member {
                file: "lan-mdns.pcap",
                units: [13, 8, 15],
                framing: [0, 0],
            },
            Member {
                file: "lan-ssdp.pcap",
                units: [0, 0, 26],
                framing: [0, 0],
            },
            Member {
                file: "stack-mqtt.pcap",
                units: [6, 28, 7],
                framing: [0, 84],
            },
            Member {
                file: "stack-rtps.pcap",
                units: [0, 2, 147],
                framing: [0, 0],
            },
            Member {
                file: "stack-coap.pcap",
                units: [0, 24, 144],
                framing: [0, 0],
            },
            Member {
                file: "stack-someip.pcap",
                units: [0, 28, 278],
                framing: [0, 0],
            },
            Member {
                file: "stack-quic.pcap",
                units: [0, 22, 0],
                framing: [0, 0],
            },
            Member {
                file: "busylan-dhcp.pcap",
                units: [16, 98, 133],
                framing: [0, 0],
            },
            Member {
                file: "busylan-ntp.pcap",
                units: [5, 183, 0],
                framing: [0, 0],
            },
            Member {
                file: "busylan-wsd.pcap",
                units: [5, 12, 155],
                framing: [0, 0],
            },
            // No unit framed and no framing lost: a member that shows no
            // observation of a check is not counted for it. A flow whose
            // first bytes are `GET ` or `HTTP` is read as a WebSocket carrier
            // and one that opens with a TLS ClientHello as an encrypted one,
            // neither by the stream reader.
            Member {
                file: "stack-http.pcap",
                units: [0, 0, 0],
                framing: [0, 0],
            },
            Member {
                file: "stack-tls.pcap",
                units: [0, 0, 0],
                framing: [0, 0],
            },
            // Connections that open with another method reach the stream
            // reader, which takes `PO`, `PU` or `HE` for a length prefix: no
            // unit is framed and every one of the 50 directions loses its
            // framing.
            Member {
                file: "stack-http-post.pcap",
                units: [0, 0, 0],
                framing: [0, 50],
            },
            // Redis frames no unit and loses the framing of all 120 stream
            // directions; PostgreSQL frames 531 units, every one with bytes
            // left over, and loses 48 directions.
            Member {
                file: "stack-redis.pcap",
                units: [0, 0, 0],
                framing: [0, 120],
            },
            Member {
                file: "stack-postgres.pcap",
                units: [0, 531, 0],
                framing: [0, 48],
            },
        ];

        /// The zenoh files' framing units: read whole, residual, undecoded.
        pub const ZENOH_UNITS: [u64; 3] = [6_075, 0, 0];

        /// The zenoh files' stream directions captured from their start:
        /// framing held, framing lost.
        pub const ZENOH_FRAMING: [u64; 2] = [300, 0];

        /// The zenoh files' cookie echoes: matched, differing.
        pub const ZENOH_COOKIE: [u64; 2] = [304, 0];

        /// The zenoh files' Init pairs: of opposite kinds, of one kind.
        pub const ZENOH_ROLES: [u64; 2] = [306, 0];

        /// The zenoh files' version headers: this reader's, another.
        pub const ZENOH_VERSIONS: [u64; 2] = [612, 0];
    }
}

/// One check's observations on a flow: how many confirmed it, how many violated
/// it, and the millibits they came to together in each sum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CheckTally {
    /// Observations that confirmed the check.
    pub confirmed: u64,
    /// Observations that violated it.
    pub violated: u64,
    /// Their weights in the `yes` sum.
    pub millibits: i64,
    /// Their weights in the `no` sum.
    pub no_millibits: i64,
}

impl CheckTally {
    fn and(self, other: CheckTally) -> CheckTally {
        CheckTally {
            confirmed: self.confirmed.saturating_add(other.confirmed),
            violated: self.violated.saturating_add(other.violated),
            millibits: self.millibits.saturating_add(other.millibits),
            no_millibits: self.no_millibits.saturating_add(other.no_millibits),
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

    /// An observation that confirmed `check`.
    pub(crate) fn confirm(&mut self, check: Check, weight: Weight) {
        self.add(check, 1, 0, weight);
    }

    /// An observation that violated `check`.
    pub(crate) fn violate(&mut self, check: Check, weight: Weight) {
        self.add(check, 0, 1, weight);
    }

    /// Observations of one check at once, `weight` their sum, for a counter
    /// kept elsewhere (the SN steps a session counts).
    pub(crate) fn add(&mut self, check: Check, confirmed: u64, violated: u64, weight: Weight) {
        let t = &mut self.tallies[check.index()];
        *t = t.and(CheckTally {
            confirmed,
            violated,
            millibits: weight.yes,
            no_millibits: weight.no,
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

    /// The sum read for `yes`, in millibits.
    pub fn log2_lr_millibits(&self) -> i64 {
        self.tallies
            .iter()
            .fold(0i64, |sum, t| sum.saturating_add(t.millibits))
    }

    /// The sum read for `no`, in millibits.
    pub fn log2_lr_no_millibits(&self) -> i64 {
        self.tallies
            .iter()
            .fold(0i64, |sum, t| sum.saturating_add(t.no_millibits))
    }
}

/// The weight of a cookie of `len` bytes matched: per byte, up to the cap,
/// with the zenoh side's fidelity.
pub(crate) fn cookie_echo_weight(len: usize) -> Weight {
    let bytes = i64::try_from(len)
        .unwrap_or(i64::MAX)
        .min(model::COOKIE_ECHO_MAX_BYTES);
    Weight::both(bytes * model::COOKIE_ECHO_PER_BYTE + model::COOKIE_ECHO_FIDELITY)
}

/// The weight of a session's SN steps: see [`model::SN_FOLLOWS`].
pub(crate) fn sn_steps_weight(steps: wz_session_core::passive::SnSteps) -> Weight {
    model::SN_FOLLOWS
        .times(steps.follows)
        .plus(model::SN_BREAKS.times(steps.breaks))
}

/// The weight of a unit that read as `reading`.
pub(crate) fn unit_reading_weight(reading: wz_session_core::passive::UnitReading) -> Weight {
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
    use alloc::vec;
    use alloc::vec::Vec;

    /// `round(1000 * log2(x))`, the rule every weight is written by.
    fn millibits(x: f64) -> i64 {
        (1000.0 * x.log2()).round() as i64
    }

    /// `ln(n!)`, summed: every count here is a few hundred at most.
    fn ln_factorial(n: u64) -> f64 {
        (2..=n).map(|i| (i as f64).ln()).sum()
    }

    /// `P(X <= k)` for `X ~ Binomial(n, p)`, `0 < p < 1`.
    fn binomial_cdf(k: u64, n: u64, p: f64) -> f64 {
        (0..=k)
            .map(|i| {
                (ln_factorial(n) - ln_factorial(i) - ln_factorial(n - i)
                    + i as f64 * p.ln()
                    + (n - i) as f64 * (-p).ln_1p())
                .exp()
            })
            .sum()
    }

    /// The one-sided 95% Clopper-Pearson upper bound on a share of `k` in `n`:
    /// the `p` at which seeing `k` or fewer has chance 5%.
    fn upper_bound(k: u64, n: u64) -> f64 {
        if k >= n {
            return 1.0;
        }
        let (mut lo, mut hi) = (k as f64 / n as f64, 1.0f64);
        for _ in 0..200 {
            let mid = (lo + hi) / 2.0;
            if binomial_cdf(k, n, mid) > 0.05 {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        (lo + hi) / 2.0
    }

    /// Model 2's rule for one measured check whose zenoh outcome is index 0:
    /// the weights of every outcome, `yes` and `no`.
    fn measured_weights(zenoh: &[u64], members: &[&[u64]]) -> Vec<Weight> {
        let n1: u64 = zenoh.iter().sum();
        let k = zenoh.len();
        let mut p1: Vec<f64> = zenoh.iter().map(|&c| upper_bound(c, n1)).collect();
        p1[0] = 1.0 - p1[1..].iter().sum::<f64>();
        let seen: Vec<&&[u64]> = members
            .iter()
            .filter(|m| m.iter().sum::<u64>() > 0)
            .collect();
        (0..k)
            .map(|o| {
                let q_yes = seen
                    .iter()
                    .map(|m| upper_bound(m[o], m.iter().sum()))
                    .fold(0.0f64, f64::max);
                let q_no = seen
                    .iter()
                    .map(|m| (m[o] as f64 + 0.5) / (m.iter().sum::<u64>() as f64 + k as f64 / 2.0))
                    .sum::<f64>()
                    / seen.len() as f64;
                Weight {
                    yes: millibits(p1[o] / q_yes),
                    no: millibits(p1[o] / q_no),
                }
            })
            .collect()
    }

    /// Every weight is its stated probabilities, recomputed: the derived and
    /// assumed ones from theirs, the measured ones from the corpus counts.
    #[test]
    fn model_weights_are_their_stated_probabilities() {
        use model::measured;
        // A zenoh flow's chance of failing a check: the bound on its failures
        // in the corpus.
        let eps = |[ok, failed]: [u64; 2]| upper_bound(failed, ok + failed);
        let eps_cookie = eps(measured::ZENOH_COOKIE);
        let eps_roles = eps(measured::ZENOH_ROLES);
        let eps_version = eps(measured::ZENOH_VERSIONS);
        let eps_sn = 2f64.powi(-4);
        let byte = 2f64.powi(-8);
        assert_eq!(model::YES_AT, millibits(1.0 / 2f64.powi(-20)));
        assert_eq!(model::NO_AT, millibits(2f64.powi(-20)));
        assert_eq!(model::COOKIE_ECHO_PER_BYTE, millibits(1.0 / byte));
        assert_eq!(model::COOKIE_ECHO_FIDELITY, millibits(1.0 - eps_cookie));
        assert_eq!(
            model::COOKIE_ECHO_VIOLATED,
            Weight::both(millibits(eps_cookie))
        );
        assert_eq!(
            model::INIT_ROLES_CONFIRMED,
            Weight::both(millibits((1.0 - eps_roles) / 0.5))
        );
        assert_eq!(
            model::INIT_ROLES_VIOLATED,
            Weight::both(millibits(eps_roles / 0.5))
        );
        assert_eq!(
            model::SN_FOLLOWS,
            Weight::both(millibits((1.0 - eps_sn) / byte))
        );
        assert_eq!(
            model::SN_BREAKS,
            Weight::both(millibits(eps_sn / (1.0 - byte)))
        );
        assert_eq!(
            model::VERSION_HEADER,
            Weight::both(millibits((1.0 - eps_version) / byte))
        );
        assert_eq!(
            model::VERSION_FOREIGN,
            Weight::both(millibits(eps_version / (1.0 - byte)))
        );
        let units: Vec<&[u64]> = model::measured::NULL.iter().map(|m| &m.units[..]).collect();
        assert_eq!(
            measured_weights(&model::measured::ZENOH_UNITS, &units),
            vec![
                model::UNIT_EXPLAINED,
                model::UNIT_RESIDUAL,
                model::UNIT_UNDECODED
            ]
        );
        let framing: Vec<&[u64]> = model::measured::NULL
            .iter()
            .map(|m| &m.framing[..])
            .collect();
        assert_eq!(
            measured_weights(&model::measured::ZENOH_FRAMING, &framing),
            vec![model::FRAMING_HELD, model::FRAMING_LOST]
        );
    }

    /// The `no` sum's null is a proper distribution for every measured check,
    /// which is what bounds the false `no`, and the `yes` sum's is not, which
    /// is why there are two sums.
    #[test]
    fn the_no_sums_null_is_a_distribution_and_the_yes_sums_is_not() {
        let units: Vec<&[u64]> = model::measured::NULL.iter().map(|m| &m.units[..]).collect();
        let seen: Vec<&&[u64]> = units.iter().filter(|m| m.iter().sum::<u64>() > 0).collect();
        let jeffreys = |o: usize| {
            seen.iter()
                .map(|m| (m[o] as f64 + 0.5) / (m.iter().sum::<u64>() as f64 + 1.5))
                .sum::<f64>()
                / seen.len() as f64
        };
        let total: f64 = (0..3).map(jeffreys).sum();
        assert!((total - 1.0).abs() < 1e-12, "{total}");
        let largest: f64 = (0..3)
            .map(|o| {
                seen.iter()
                    .map(|m| upper_bound(m[o], m.iter().sum()))
                    .fold(0.0f64, f64::max)
            })
            .sum();
        assert!(largest > 2.0, "{largest}");
    }

    /// The Clopper-Pearson bound is the closed form where one exists.
    #[test]
    fn the_upper_bound_of_none_seen_is_the_closed_form() {
        let n = 346;
        let closed = 1.0 - 0.05f64.powf(1.0 / n as f64);
        assert!((upper_bound(0, n) - closed).abs() < 1e-12);
        assert_eq!(upper_bound(5, 5), 1.0);
    }

    /// A frame that repeats its SN while its unit reads whole moves the `yes`
    /// sum down, however many of them a flow holds: the `no` sum's unit weight
    /// is an average over the null protocols and can come to match the break's
    /// (it is within 12 millibits now), but the `yes` sum's is a bound and
    /// cannot, so a flow of such frames stays short of `yes`.
    #[test]
    fn a_unit_read_whole_on_a_broken_step_never_counts_toward_yes() {
        let sum = model::UNIT_EXPLAINED.yes + model::SN_BREAKS.yes;
        assert!(sum < 0, "{sum}");
    }

    /// A cookie match counts its bytes up to the cap, less the zenoh side's
    /// fidelity, the same in both sums.
    #[test]
    fn a_cookie_match_weighs_its_bytes_up_to_the_cap() {
        assert_eq!(cookie_echo_weight(1), Weight::both(7_986));
        assert_eq!(cookie_echo_weight(8), Weight::both(63_986));
        assert_eq!(cookie_echo_weight(40), Weight::both(63_986));
    }

    /// Evidence sums per check and over checks, in each sum, and two bodies of
    /// it add.
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
                millibits: model::UNIT_EXPLAINED.yes + model::UNIT_UNDECODED.yes,
                no_millibits: model::UNIT_EXPLAINED.no + model::UNIT_UNDECODED.no,
            }
        );
        assert_eq!(
            both.log2_lr_millibits(),
            model::VERSION_HEADER.yes + model::UNIT_EXPLAINED.yes + model::UNIT_UNDECODED.yes
        );
        assert_eq!(
            both.log2_lr_no_millibits(),
            model::VERSION_HEADER.no + model::UNIT_EXPLAINED.no + model::UNIT_UNDECODED.no
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
