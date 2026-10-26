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
//! # The periodic schedule is open-loop with absolute deadlines
//!
//! The n-th send is due `n` gaps after the start, whatever the earlier sends cost: a source that
//! slept one gap after each send would run slower than its rate by the cost of every send. And a
//! source that fell behind (a stalled link, a slow host) does not burst to catch up, which would
//! put load on the peer that no rate describes: it sends one and moves to the first deadline still
//! ahead, counting the deadlines it passed ([`Periodic::skipped`]), so a run that could not keep its
//! rate says so instead of reporting the rate it was asked for.

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

/// An open-loop periodic schedule of absolute deadlines (see this module's doc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Periodic {
    gap_nanos: u64,
    /// The index of the next deadline: the n-th is `n` gaps after the start.
    next: u64,
    /// The deadlines passed without a send.
    skipped: u64,
}

impl Periodic {
    /// A schedule of one send every `gap_nanos`, the first at the start.
    pub fn new(gap_nanos: u64) -> Self {
        Self {
            gap_nanos: gap_nanos.max(1),
            next: 0,
            skipped: 0,
        }
    }

    /// When the next send is due, in nanoseconds after the start.
    pub fn due(&self) -> u64 {
        self.next.saturating_mul(self.gap_nanos)
    }

    /// Record that the next send was made `elapsed` nanoseconds after the start. A send later than
    /// the deadline after its own moves the schedule to the first deadline still ahead, and the
    /// deadlines it passed are counted as skipped rather than sent in a burst.
    pub fn sent(&mut self, elapsed: u64) {
        let following = self.next + 1;
        let ahead = elapsed / self.gap_nanos + 1;
        if ahead > following {
            self.skipped += ahead - following;
            self.next = ahead;
        } else {
            self.next = following;
        }
    }

    /// The deadlines passed without a send.
    pub fn skipped(&self) -> u64 {
        self.skipped
    }

    /// The gap of this schedule, in nanoseconds.
    pub fn gap_nanos(&self) -> u64 {
        self.gap_nanos
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

    #[test]
    fn the_schedule_keeps_absolute_deadlines() {
        let mut s = Periodic::new(10);
        assert_eq!(s.due(), 0);
        s.sent(3); // a send that cost 3 ns does not move the next deadline
        assert_eq!(s.due(), 10);
        s.sent(12);
        assert_eq!((s.due(), s.skipped()), (20, 0));
        // Fell behind by more than two gaps: one send, the next deadline ahead, two counted.
        s.sent(45);
        assert_eq!((s.due(), s.skipped()), (50, 2));
        s.sent(50);
        assert_eq!((s.due(), s.skipped()), (60, 2));
    }
}
