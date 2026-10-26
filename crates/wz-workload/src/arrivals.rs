// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! When a stream sends: a rate written as a decimal, the gap it gives, and the periodic schedule.
//!
//! # A rate is a decimal, not a float
//!
//! A document writes `100` or `0.5` sends a second, and the gap is computed from those digits
//! exactly: a float would make `0.1` a different rate from the one written, and two readers of one
//! document would disagree on the last nanosecond. So [`Decimal`] holds the digits and [`gap_nanos`]
//! divides integers, rounding the gap down to the nanosecond.
//!
//! # The schedule is open-loop: intended times, kept whatever happens
//!
//! [`Arrivals`] is the sequence of intended send times and nothing else: the n-th send of a
//! periodic stream is due `n` gaps after the start, whatever the earlier sends cost (a source that
//! slept one gap after each send would run slower than its rate by the cost of every send). A send
//! that cannot be made at its time (a stalled link, a slow host, a timer coarser than a gap) is made
//! as soon as it can, and the ones behind it follow at once until the stream is back on its times:
//! the load offered is the plan's, never thinned to hide the delay. What the interpreter reports is
//! the delay itself, each send's start against its intended time, so a run that could not keep its
//! schedule says by how much. Dropping the sends whose time had passed would do the opposite: the
//! load would be lower than the plan's while the plan's rate was reported, and on a Poisson stream
//! the short gaps a coarse timer cannot hit would be the ones dropped, which changes the process.
//! This is the load generator's rule against coordinated omission.
//!
//! # The processes
//!
//! [`Process::Periodic`] is one send a gap; [`Process::Poisson`] draws exponential gaps from a seed
//! (the load of many independent clients); [`Process::Burst`] sends a batch back to back each gap.
//! All three are open loop: a send's lateness does not move the times after it. A closed loop,
//! where the next ask waits for the last answer, is a property of an asker and not a schedule of
//! times, so it is the asking role's (the driver's `query` with `think_ms`).

use crate::mutation::splitmix64;

/// A positive decimal as a document writes it: digits, optionally a point and more digits. No
/// sign, no exponent, no leading or trailing point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decimal {
    /// The digits without the point.
    mantissa: u64,
    /// How many of them are after the point.
    scale: u32,
}

/// Why text is not a [`Decimal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecimalError {
    /// Nothing, a sign, an exponent, a point with no digit on one side, or another character.
    NotDecimal,
    /// More significant digits than an exact 64-bit mantissa holds (more than 18).
    TooPrecise,
    /// Zero, which no rate and no speed can be.
    Zero,
}

impl core::fmt::Display for DecimalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotDecimal => write!(
                f,
                "must be a positive decimal: digits, and a point and digits if any"
            ),
            Self::TooPrecise => write!(f, "has more than 18 significant digits"),
            Self::Zero => write!(f, "must be greater than zero"),
        }
    }
}

/// The digits an exact `u64` mantissa always holds.
const MAX_DIGITS: usize = 18;

impl Decimal {
    /// Read `text` as a positive decimal.
    pub fn parse(text: &str) -> Result<Self, DecimalError> {
        let (whole, fraction) = match text.split_once('.') {
            Some((w, f)) => (w, f),
            None => (text, ""),
        };
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if !digits(whole) || (text.contains('.') && !digits(fraction)) {
            return Err(DecimalError::NotDecimal);
        }
        // Leading zeros of the whole part and trailing zeros of the fraction carry no precision.
        let fraction = fraction.trim_end_matches('0');
        let significant = whole.trim_start_matches('0').len() + fraction.len();
        if significant > MAX_DIGITS {
            return Err(DecimalError::TooPrecise);
        }
        let mut mantissa = 0u64;
        for b in whole.bytes().chain(fraction.bytes()) {
            mantissa = mantissa * 10 + u64::from(b - b'0');
        }
        if mantissa == 0 {
            return Err(DecimalError::Zero);
        }
        Ok(Self {
            mantissa,
            scale: fraction.len() as u32,
        })
    }

    /// The digits without the point.
    pub fn mantissa(&self) -> u64 {
        self.mantissa
    }

    /// How many digits are after the point.
    pub fn scale(&self) -> u32 {
        self.scale
    }
}

/// The shortest gap a rate may give: one microsecond, which is a million sends a second. A faster
/// rate is refused rather than rounded to a gap of zero, which would be "as fast as possible" under
/// a number that promised a rate.
pub const MIN_GAP_NANOS: u64 = 1_000;

/// Why a rate cannot be played.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateError {
    /// The gap it gives is shorter than [`MIN_GAP_NANOS`].
    TooFast { gap_nanos: u64 },
}

impl core::fmt::Display for RateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooFast { gap_nanos } => write!(
                f,
                "gives a gap of {gap_nanos} ns, shorter than {MIN_GAP_NANOS} ns: at most 1000000 a second"
            ),
        }
    }
}

/// The gap between two sends at `per_second` sends a second, in nanoseconds, rounded down: exactly
/// 10^9 * 10^scale / mantissa of the digits written.
pub fn gap_nanos(per_second: Decimal) -> Result<u64, RateError> {
    let numerator = 1_000_000_000u128 * 10u128.pow(per_second.scale);
    let gap = numerator / u128::from(per_second.mantissa);
    let gap = u64::try_from(gap).unwrap_or(u64::MAX);
    if gap < MIN_GAP_NANOS {
        return Err(RateError::TooFast { gap_nanos: gap });
    }
    Ok(gap)
}

/// When each send of a stream is due: the arrival process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Process {
    /// One send every `gap_nanos`.
    Periodic { gap_nanos: u64 },
    /// A Poisson process: the gaps are exponential with mean `mean_gap_nanos`, each
    /// `floor(mean_gap_nanos x -ln(1 - u))` where `u` is the top 53 bits of the next SplitMix64 word
    /// from `seed` over 2^53, so the same seed gives the same sends. The load of independent
    /// clients, which a fixed period does not model: its gaps cluster and spread.
    Poisson { mean_gap_nanos: u64, seed: u64 },
    /// `size` sends back to back, every `gap_nanos`: the shape of a sender that batches.
    Burst { size: u64, gap_nanos: u64 },
}

/// The intended send times of an arrival [`Process`], in nanoseconds after the start (see this
/// module's doc): a pure sequence, which no send's lateness moves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arrivals {
    process: Process,
    /// When the next send is due, in nanoseconds after the start.
    due: u64,
    /// The sends already made of the burst due now.
    in_burst: u64,
    /// The generator's state.
    state: u64,
}

impl Arrivals {
    /// The schedule of `process`, the first send due at the start. A gap or a burst of zero is
    /// taken as one.
    pub fn new(process: Process) -> Self {
        let process = match process {
            Process::Periodic { gap_nanos } => Process::Periodic {
                gap_nanos: gap_nanos.max(1),
            },
            Process::Poisson {
                mean_gap_nanos,
                seed,
            } => Process::Poisson {
                mean_gap_nanos: mean_gap_nanos.max(1),
                seed,
            },
            Process::Burst { size, gap_nanos } => Process::Burst {
                size: size.max(1),
                gap_nanos: gap_nanos.max(1),
            },
        };
        let state = match process {
            Process::Poisson { seed, .. } => seed,
            _ => 0,
        };
        Self {
            process,
            due: 0,
            in_burst: 0,
            state,
        }
    }

    /// When the next send is due, in nanoseconds after the start.
    pub fn due(&self) -> u64 {
        self.due
    }

    /// Move to the next send's intended time.
    pub fn advance(&mut self) {
        match self.process {
            Process::Periodic { gap_nanos } => self.due = self.due.saturating_add(gap_nanos),
            Process::Burst { size, gap_nanos } => {
                self.in_burst += 1;
                if self.in_burst == size {
                    self.in_burst = 0;
                    self.due = self.due.saturating_add(gap_nanos);
                }
            }
            Process::Poisson { mean_gap_nanos, .. } => {
                let gap = self.exponential(mean_gap_nanos);
                self.due = self.due.saturating_add(gap);
            }
        }
    }

    /// The next exponential gap of mean `mean`, from the generator.
    fn exponential(&mut self, mean: u64) -> u64 {
        let u = (splitmix64(&mut self.state) >> 11) as f64 / (1u64 << 53) as f64;
        let gap = mean as f64 * -libm::log(1.0 - u);
        // `as u64` truncates toward zero and saturates, which is the floor of a non-negative gap.
        gap as u64
    }

    /// The process this schedule follows.
    pub fn process(&self) -> Process {
        self.process
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_decimal_is_its_digits() {
        let d = Decimal::parse("0.5").unwrap();
        assert_eq!((d.mantissa(), d.scale()), (5, 1));
        let d = Decimal::parse("100").unwrap();
        assert_eq!((d.mantissa(), d.scale()), (100, 0));
        let d = Decimal::parse("007.250").unwrap();
        assert_eq!((d.mantissa(), d.scale()), (725, 2));
        for bad in [
            "", ".5", "5.", "-1", "+1", "1e3", "1.2.3", " 1", "0x10", "١",
        ] {
            assert_eq!(
                Decimal::parse(bad),
                Err(DecimalError::NotDecimal),
                "{bad:?}"
            );
        }
        assert_eq!(Decimal::parse("0"), Err(DecimalError::Zero));
        assert_eq!(Decimal::parse("0.000"), Err(DecimalError::Zero));
        assert_eq!(
            Decimal::parse("1234567890.123456789"),
            Err(DecimalError::TooPrecise)
        );
        assert!(Decimal::parse("123456789.123456789").is_ok());
    }

    /// The rates a downstream plan dials: 100 a second is 10 ms, half a second's rate is 2 s, a
    /// million is the floor and one more is refused.
    #[test]
    fn a_rate_gives_its_gap_exactly() {
        let gap = |t| gap_nanos(Decimal::parse(t).unwrap());
        assert_eq!(gap("100"), Ok(10_000_000));
        assert_eq!(gap("0.5"), Ok(2_000_000_000));
        assert_eq!(gap("3"), Ok(333_333_333));
        assert_eq!(gap("0.1"), Ok(10_000_000_000));
        assert_eq!(gap("1000000"), Ok(1_000));
        assert_eq!(gap("1000001"), Err(RateError::TooFast { gap_nanos: 999 }));
        assert_eq!(gap("0.000000000000000001"), Ok(u64::MAX));
    }

    fn times(process: Process, n: usize) -> std::vec::Vec<u64> {
        let mut s = Arrivals::new(process);
        (0..n)
            .map(|_| {
                let due = s.due();
                s.advance();
                due
            })
            .collect()
    }

    /// The n-th send is due n gaps after the start: absolute times, which nothing a send does moves.
    #[test]
    fn the_schedule_keeps_absolute_deadlines() {
        assert_eq!(
            times(Process::Periodic { gap_nanos: 10 }, 5),
            [0, 10, 20, 30, 40]
        );
        assert_eq!(times(Process::Periodic { gap_nanos: 0 }, 3), [0, 1, 2]);
    }

    #[test]
    fn a_burst_is_sent_back_to_back() {
        assert_eq!(
            times(
                Process::Burst {
                    size: 3,
                    gap_nanos: 10
                },
                7
            ),
            [0, 0, 0, 10, 10, 10, 20]
        );
    }

    /// The gaps are the definition's: the first three from seed 0 at a mean of one second, computed
    /// independently with the C library's `log`; the sample mean of many is the mean.
    #[test]
    fn a_poisson_process_draws_its_gaps_from_the_seed() {
        let first = times(
            Process::Poisson {
                mean_gap_nanos: 1_000_000_000,
                seed: 0,
            },
            4,
        );
        assert_eq!(first, [0, 2_148_241_359, 2_713_044_573, 2_739_833_998]);
        let mean = 1_000_000u64;
        let n = 200_000usize;
        let last = times(
            Process::Poisson {
                mean_gap_nanos: mean,
                seed: 7,
            },
            n + 1,
        )[n];
        let observed = last as f64 / n as f64;
        assert!(
            (observed / mean as f64 - 1.0).abs() < 0.01,
            "mean gap {observed}"
        );
    }
}
