// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The grammar of zenoh's `_time` selector parameter ([`crate::selector_params::TIME_RANGE_PARAM`]),
//! its resolution against "now", and the membership test: one reading for every wz crate.
//!
//! Two crates read the parameter. `wz-zenoh-util` is upstream zenoh-util's API, whose
//! `TimeRange` parses through [`parse_range`] and turns a [`RangeError`] back into upstream's
//! message; `wz-ext-pubsub` filters the advanced publisher's cache with it. Each held a grammar of
//! its own until 2026-11-19, and the two disagreed on a fixed start with a negative `;` duration.
//!
//! ## Grammar
//!
//! - range: `<[|]><start?>..<end?><[|]>`; omitting a side leaves it unbounded.
//! - duration: `<[|]><start>;<duration><[|]>`, which is `<start>..<start+duration>`. The start
//!   must be present.
//! - a bracket pointing INTO the range is inclusive, one pointing OUT is exclusive: `[a..b[`
//!   holds `a` and not `b`.
//! - a time is either `now(<-?><duration?>)` or an RFC3339 UTC timestamp, read as humantime's
//!   `parse_rfc3339_weak` reads it ([`parse_rfc3339_weak`]).
//! - a duration is a float of seconds, or a float with one of `u ms s m h d w`.
//!
//! ## Where this differs from upstream
//!
//! Upstream PANICS on inputs an attacker-chosen query parameter can reach: a bare `s` as a
//! duration (it reads past the front of the text), and a `;` duration added to a fixed start when
//! the duration is negative, not a number, infinite, or past what the instant type holds (it adds
//! with `Add`, which panics). Here a bare `s` is a refused duration ([`DurationError::Float`]); a
//! negative duration moves a fixed start back, as it already moves a `now(..)` start back
//! upstream, so the end lies before the start and the range holds nothing; and a sum no instant
//! holds is [`RangeError::EndUnrepresentable`].
//!
//! ## The instant type
//!
//! This crate has no clock and no `SystemTime`. The caller names its instant type through a
//! [`Clock`], and every sum is that type's own checked arithmetic, so the instants a range can
//! reach are exactly the ones the caller's type holds (a `SystemTime` holds a different span on
//! each platform).

use core::fmt;
use core::num::ParseFloatError;
use core::time::Duration;

const U_TO_SECS: f64 = 0.000001;
const MS_TO_SECS: f64 = 0.001;
const M_TO_SECS: f64 = 60.0;
const H_TO_SECS: f64 = M_TO_SECS * 60.0;
const D_TO_SECS: f64 = H_TO_SECS * 24.0;
const W_TO_SECS: f64 = D_TO_SECS * 7.0;

/// The last second of year 9999, the bound humantime's `parse_rfc3339_weak` enforces on a 64-bit
/// target.
const RFC3339_MAX_SECONDS: u64 = 253_402_300_800 - 1;

/// The instant type a caller reads ranges in, and its checked arithmetic.
pub trait Clock {
    /// An instant.
    type Instant: Copy + PartialOrd;
    /// The instant `since_epoch` after 1970-01-01T00:00:00Z. Called with no more than the end of
    /// year 9999, which every instant type a wz build reads ranges in holds.
    fn from_unix(since_epoch: Duration) -> Self::Instant;
    /// `at + by`, `None` where the instant type cannot hold it.
    fn checked_add(at: Self::Instant, by: Duration) -> Option<Self::Instant>;
    /// `at - by`, `None` where the instant type cannot hold it.
    fn checked_sub(at: Self::Instant, by: Duration) -> Option<Self::Instant>;
}

/// `at` moved by `secs` seconds, forward or back: `None` where the instant type cannot hold the
/// result, and where `secs` is not a number or is infinite.
pub fn add_secs<C: Clock>(at: C::Instant, secs: f64) -> Option<C::Instant> {
    if secs >= 0.0 {
        Duration::try_from_secs_f64(secs)
            .ok()
            .and_then(|d| C::checked_add(at, d))
    } else {
        Duration::try_from_secs_f64(-secs)
            .ok()
            .and_then(|d| C::checked_sub(at, d))
    }
}

/// One end of a range. A bracket pointing out of the range is exclusive.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Edge<T> {
    /// The end is part of the range.
    Inclusive(T),
    /// The end is the first instant outside the range.
    Exclusive(T),
    /// The range extends without limit in this direction.
    Unbounded,
}

/// A time as the selector spells it: an instant, or an offset from the moment the range is
/// evaluated.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TimeExpr<I> {
    /// An RFC3339 instant.
    Fixed(I),
    /// `now(<offset>)`, the offset in seconds (negative reaches into the past).
    Now {
        /// Seconds added to the evaluation instant.
        offset_secs: f64,
    },
}

/// A parsed `_time` range. `T` is a [`TimeExpr`] until the offsets are resolved and an instant
/// after.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct TimeRange<T> {
    /// The lower end.
    pub start: Edge<T>,
    /// The upper end.
    pub end: Edge<T>,
}

/// Why humantime's `parse_rfc3339_weak` refuses a timestamp, with its words.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Rfc3339Error {
    /// A number is outside its field's range, or the instant is past year 9999.
    OutOfRange,
    /// A byte where a digit is read is not one.
    InvalidDigit,
    /// The text does not have the shape of a timestamp.
    InvalidFormat,
}

impl fmt::Display for Rfc3339Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Rfc3339Error::OutOfRange => "numeric component is out of range",
            Rfc3339Error::InvalidDigit => "bad character where digit is expected",
            Rfc3339Error::InvalidFormat => "timestamp format is invalid",
        })
    }
}

impl core::error::Error for Rfc3339Error {}

/// Why a duration is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurationError<'a> {
    /// The duration is empty.
    Empty,
    /// The number before the unit (or the whole text, with no unit) is not a float.
    Float {
        /// The duration's whole text, unit included.
        text: &'a str,
        /// What the float reader said.
        error: ParseFloatError,
    },
}

/// Why a time is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeError<'a> {
    /// The time's whole text.
    pub text: &'a str,
    /// What was wrong with it.
    pub cause: TimeCause<'a>,
}

/// What was wrong with a refused time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeCause<'a> {
    /// The duration of a `now(..)`.
    Duration(DurationError<'a>),
    /// The timestamp.
    Instant(Rfc3339Error),
}

/// Why a range is refused, in the order upstream's parser looks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeError<'a> {
    /// Shorter than `[..]`.
    TooShort,
    /// The first character is neither `[` nor `]`.
    BadStart,
    /// The last character is neither `[` nor `]`.
    BadEnd,
    /// A side is not a time.
    Time(TimeError<'a>),
    /// The duration after `;` is not one.
    Duration(DurationError<'a>),
    /// A `;` range with no start.
    NoStart {
        /// The text between the brackets.
        inner: &'a str,
    },
    /// The start moved by the duration is an instant the caller's type cannot hold.
    EndUnrepresentable {
        /// The text between the brackets.
        inner: &'a str,
    },
    /// Neither `..` nor `;` separates the sides.
    NoSeparator {
        /// The text between the brackets.
        inner: &'a str,
    },
}

impl<I: Copy> TimeExpr<I> {
    /// The instant this expression names at `now`: `None` where an offset moves `now` past what
    /// the instant type holds.
    pub fn resolve_at<C: Clock<Instant = I>>(self, now: I) -> Option<I> {
        match self {
            TimeExpr::Fixed(t) => Some(t),
            TimeExpr::Now { offset_secs } => add_secs::<C>(now, offset_secs),
        }
    }

    /// This expression moved by `secs` seconds, forward or back: `None` where a fixed instant
    /// moves past what the instant type holds. An offset only adds.
    pub fn checked_add<C: Clock<Instant = I>>(self, secs: f64) -> Option<Self> {
        match self {
            TimeExpr::Fixed(t) => add_secs::<C>(t, secs).map(TimeExpr::Fixed),
            TimeExpr::Now { offset_secs } => Some(TimeExpr::Now {
                offset_secs: offset_secs + secs,
            }),
        }
    }
}

impl<I: Copy> Edge<TimeExpr<I>> {
    /// The end at `now`. An offset that lands outside what the instant type holds becomes an
    /// UNBOUNDED end, not an error and not a clamp: that is upstream's answer, and a clamp would
    /// turn `now(-1000000d)` used as an upper bound into "nothing".
    pub fn resolve_at<C: Clock<Instant = I>>(self, now: I) -> Edge<I> {
        match self {
            Edge::Inclusive(t) => t
                .resolve_at::<C>(now)
                .map_or(Edge::Unbounded, Edge::Inclusive),
            Edge::Exclusive(t) => t
                .resolve_at::<C>(now)
                .map_or(Edge::Unbounded, Edge::Exclusive),
            Edge::Unbounded => Edge::Unbounded,
        }
    }
}

impl<I: Copy> TimeRange<TimeExpr<I>> {
    /// The range at `now`.
    pub fn resolve_at<C: Clock<Instant = I>>(self, now: I) -> TimeRange<I> {
        TimeRange {
            start: self.start.resolve_at::<C>(now),
            end: self.end.resolve_at::<C>(now),
        }
    }
}

impl<I: Copy + PartialOrd> TimeRange<I> {
    /// Whether `instant` lies in the range.
    pub fn contains(&self, instant: I) -> bool {
        match self.start {
            Edge::Inclusive(t) if t > instant => return false,
            Edge::Exclusive(t) if t >= instant => return false,
            _ => {}
        }
        match self.end {
            Edge::Inclusive(t) => t >= instant,
            Edge::Exclusive(t) => t > instant,
            Edge::Unbounded => true,
        }
    }
}

/// Parse a `_time` value.
pub fn parse_range<C: Clock>(s: &str) -> Result<TimeRange<TimeExpr<C::Instant>>, RangeError<'_>> {
    // The shortest range is `[..]`.
    let len = s.len();
    if len < 4 {
        return Err(RangeError::TooShort);
    }
    let mut chars = s.chars();
    let inclusive_start = match chars.next() {
        Some('[') => true,
        Some(']') => false,
        _ => return Err(RangeError::BadStart),
    };
    let inclusive_end = match chars.last() {
        Some(']') => true,
        Some('[') => false,
        _ => return Err(RangeError::BadEnd),
    };
    // Both delimiters are ASCII, so these are char boundaries.
    let inner = &s[1..len - 1];
    if let Some((start, end)) = inner.split_once("..") {
        Ok(TimeRange {
            start: parse_edge::<C>(start, inclusive_start)?,
            end: parse_edge::<C>(end, inclusive_end)?,
        })
    } else if let Some((start, duration)) = inner.split_once(';') {
        // Upstream reads the start, then the duration, then asks whether there was a start.
        let start = parse_edge::<C>(start, inclusive_start)?;
        let secs = parse_duration(duration).map_err(RangeError::Duration)?;
        let end_time = match start {
            Edge::Inclusive(t) | Edge::Exclusive(t) => t
                .checked_add::<C>(secs)
                .ok_or(RangeError::EndUnrepresentable { inner })?,
            Edge::Unbounded => return Err(RangeError::NoStart { inner }),
        };
        let end = if inclusive_end {
            Edge::Inclusive(end_time)
        } else {
            Edge::Exclusive(end_time)
        };
        Ok(TimeRange { start, end })
    } else {
        Err(RangeError::NoSeparator { inner })
    }
}

fn parse_edge<C: Clock>(
    s: &str,
    inclusive: bool,
) -> Result<Edge<TimeExpr<C::Instant>>, RangeError<'_>> {
    if s.is_empty() {
        return Ok(Edge::Unbounded);
    }
    let t = parse_time::<C>(s).map_err(RangeError::Time)?;
    Ok(if inclusive {
        Edge::Inclusive(t)
    } else {
        Edge::Exclusive(t)
    })
}

/// Parse one time: `now(...)` or an RFC3339 UTC timestamp.
pub fn parse_time<C: Clock>(s: &str) -> Result<TimeExpr<C::Instant>, TimeError<'_>> {
    let parsed = if s.starts_with("now(") && s.ends_with(')') {
        let inner = &s[4..s.len() - 1];
        if inner.is_empty() {
            Ok(TimeExpr::Now { offset_secs: 0.0 })
        } else if let Some(magnitude) = inner.strip_prefix('-') {
            parse_duration(magnitude)
                .map(|f| TimeExpr::Now { offset_secs: -f })
                .map_err(TimeCause::Duration)
        } else {
            parse_duration(inner)
                .map(|f| TimeExpr::Now { offset_secs: f })
                .map_err(TimeCause::Duration)
        }
    } else {
        parse_rfc3339_weak(s)
            .map(|since_epoch| TimeExpr::Fixed(C::from_unix(since_epoch)))
            .map_err(TimeCause::Instant)
    };
    parsed.map_err(|cause| TimeError { text: s, cause })
}

/// A duration literal in seconds: a bare float, or a float followed by one of `u` (microseconds),
/// `ms`, `s`, `m`, `h`, `d`, `w`.
pub fn parse_duration(s: &str) -> Result<f64, DurationError<'_>> {
    let b = s.as_bytes();
    let n = b.len();
    if n == 0 {
        return Err(DurationError::Empty);
    }
    // Every unit is ASCII, so each slice below ends on a char boundary.
    match b[n - 1] {
        b'u' => s[..n - 1].parse::<f64>().map(|u| U_TO_SECS * u),
        // A lone `s` has nothing before the unit: upstream asks for the byte before it and
        // panics; here the whole text is read as a float, which it is not.
        b's' if n == 1 => s.parse::<f64>(),
        b's' if b[n - 2] == b'm' => s[..n - 2].parse::<f64>().map(|ms| MS_TO_SECS * ms),
        b's' => s[..n - 1].parse::<f64>(),
        b'm' => s[..n - 1].parse::<f64>().map(|m| M_TO_SECS * m),
        b'h' => s[..n - 1].parse::<f64>().map(|h| H_TO_SECS * h),
        b'd' => s[..n - 1].parse::<f64>().map(|d| D_TO_SECS * d),
        b'w' => s[..n - 1].parse::<f64>().map(|w| W_TO_SECS * w),
        _ => s.parse::<f64>(),
    }
    .map_err(|error| DurationError::Float { text: s, error })
}

/// humantime 2.4 `parse_rfc3339_weak`: an RFC3339-like UTC timestamp, as the time since
/// 1970-01-01T00:00:00Z, refused with the error humantime gives at the same check.
///
/// The quirks are kept because a selector that parses upstream has to parse here: the zone is not
/// validated beyond its position (`+` six bytes from the end ends the fraction), a leap second
/// `:60` reads as `:59`, the year is four digits from 1970 to 9999, and fractional digits past the
/// ninth are read and carry no weight.
pub fn parse_rfc3339_weak(s: &str) -> Result<Duration, Rfc3339Error> {
    if s.len() < "2018-02-14T00:28:07".len() {
        return Err(Rfc3339Error::InvalidFormat);
    }
    let b = s.as_bytes();
    if b[4] != b'-'
        || b[7] != b'-'
        || (b[10] != b'T' && b[10] != b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return Err(Rfc3339Error::InvalidFormat);
    }
    let two = |i: usize| -> Result<u64, Rfc3339Error> {
        let hi = (b[i] as char).to_digit(10);
        let lo = (b[i + 1] as char).to_digit(10);
        match (hi, lo) {
            (Some(hi), Some(lo)) => Ok(u64::from(hi * 10 + lo)),
            _ => Err(Rfc3339Error::InvalidDigit),
        }
    };
    let year = two(0)? * 100 + two(2)?;
    let month = two(5)?;
    let day = two(8)?;
    let hour = two(11)?;
    let minute = two(14)?;
    let mut second = two(17)?;

    if year < 1970 || hour > 23 || minute > 59 || second > 60 {
        return Err(Rfc3339Error::OutOfRange);
    }
    if second == 60 {
        second = 59;
    }

    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let (mut ydays, mdays) = match month {
        1 => (0, 31),
        2 if leap => (31, 29),
        2 => (31, 28),
        3 => (59, 31),
        4 => (90, 30),
        5 => (120, 31),
        6 => (151, 30),
        7 => (181, 31),
        8 => (212, 31),
        9 => (243, 30),
        10 => (273, 31),
        11 => (304, 30),
        12 => (334, 31),
        _ => return Err(Rfc3339Error::OutOfRange),
    };
    if day > mdays || day == 0 {
        return Err(Rfc3339Error::OutOfRange);
    }
    ydays += day - 1;
    if leap && month > 2 {
        ydays += 1;
    }

    let leap_years =
        ((year - 1) - 1968) / 4 - ((year - 1) - 1900) / 100 + ((year - 1) - 1600) / 400;
    let days = (year - 1970) * 365 + leap_years + ydays;
    let time = second + minute * 60 + hour * 3600;

    let mut nanos = 0u32;
    let mut mult = 100_000_000u32;
    if b.get(19) == Some(&b'.') {
        for idx in 20..b.len() {
            if b[idx] == b'Z' {
                if idx == b.len() - 1 {
                    break;
                }
                return Err(Rfc3339Error::InvalidDigit);
            } else if b[idx] == b'+' {
                // The start of `+00:00`, which must end the text.
                if idx == b.len() - 6 {
                    break;
                }
                return Err(Rfc3339Error::InvalidDigit);
            }
            let digit = (b[idx] as char)
                .to_digit(10)
                .ok_or(Rfc3339Error::InvalidDigit)?;
            nanos += mult * digit;
            mult /= 10;
        }
    } else if b.len() != 19 && (b.len() > 25 || (b[19] != b'Z' && &b[19..] != b"+00:00")) {
        return Err(Rfc3339Error::InvalidFormat);
    }

    let total_seconds = time + days * 86_400;
    if total_seconds > RFC3339_MAX_SECONDS {
        return Err(Rfc3339Error::OutOfRange);
    }
    // `nanos` is below 1e9: nine digits at most carry weight.
    Ok(Duration::new(total_seconds, nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clock whose instant is the time since the epoch, held in a `Duration`.
    enum Epoch {}

    impl Clock for Epoch {
        type Instant = Duration;
        fn from_unix(since_epoch: Duration) -> Duration {
            since_epoch
        }
        fn checked_add(at: Duration, by: Duration) -> Option<Duration> {
            at.checked_add(by)
        }
        fn checked_sub(at: Duration, by: Duration) -> Option<Duration> {
            at.checked_sub(by)
        }
    }

    fn at(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    fn time(s: &str) -> Option<TimeExpr<Duration>> {
        parse_time::<Epoch>(s).ok()
    }

    fn range(s: &str) -> Option<TimeRange<TimeExpr<Duration>>> {
        parse_range::<Epoch>(s).ok()
    }

    /// 2022-06-30T01:02:03Z, read independently of this module's own arithmetic:
    /// 2022-07-01T00:00:00Z is 1656633600, one day earlier is 1656547200, and the
    /// time of day adds 1*3600 + 2*60 + 3.
    const T_2022_06_30: u64 = 1_656_547_200 + 3_723;

    #[test]
    fn rfc3339_weak_reads_the_forms_upstream_reads() {
        assert_eq!(
            time("2022-06-30T01:02:03Z"),
            Some(TimeExpr::Fixed(at(T_2022_06_30)))
        );
        // No zone, a space for the T, and `+00:00` are the same instant.
        assert_eq!(time("2022-06-30T01:02:03"), time("2022-06-30T01:02:03Z"));
        assert_eq!(time("2022-06-30 01:02:03Z"), time("2022-06-30T01:02:03Z"));
        assert_eq!(
            time("2022-06-30T01:02:03+00:00"),
            time("2022-06-30T01:02:03Z")
        );
        // Fractional digits are nanoseconds, to the ninth place.
        assert_eq!(
            time("2022-06-30T01:02:03.226942997Z"),
            Some(TimeExpr::Fixed(
                at(T_2022_06_30) + Duration::from_nanos(226_942_997)
            ))
        );
        assert_eq!(
            time("2022-06-30T01:02:03.5Z"),
            Some(TimeExpr::Fixed(
                at(T_2022_06_30) + Duration::from_millis(500)
            ))
        );
        // A tenth digit is read and dropped.
        assert_eq!(
            time("2022-06-30T01:02:03.1234567891Z"),
            Some(TimeExpr::Fixed(
                at(T_2022_06_30) + Duration::from_nanos(123_456_789)
            ))
        );
        // Known epoch seconds for three round dates.
        assert_eq!(time("1970-01-01T00:00:00Z"), Some(TimeExpr::Fixed(at(0))));
        assert_eq!(
            time("2000-01-01T00:00:00Z"),
            Some(TimeExpr::Fixed(at(946_684_800)))
        );
        assert_eq!(
            time("2024-01-01T00:00:00Z"),
            Some(TimeExpr::Fixed(at(1_704_067_200)))
        );
        // A leap day, and the leap second that reads as :59.
        assert_eq!(
            time("2024-02-29T00:00:00Z"),
            Some(TimeExpr::Fixed(at(1_704_067_200 + 59 * 86_400)))
        );
        assert_eq!(time("2022-06-30T01:02:60Z"), time("2022-06-30T01:02:59Z"));
        // 9999-12-31T23:59:60Z is the last second (read as :59).
        assert!(time("9999-12-31T23:59:60Z").is_some());
        // Weak: a `Z` at byte 19 ends the check, whatever follows it within 25 bytes.
        assert_eq!(time("2022-06-30T01:02:03Zx"), time("2022-06-30T01:02:03Z"));
    }

    /// Each refusal is humantime's, at the check humantime makes it.
    #[test]
    fn rfc3339_weak_refuses_with_the_error_upstream_gives() {
        use Rfc3339Error::*;
        for (s, error) in [
            ("", InvalidFormat),
            ("1h", InvalidFormat),
            ("2020-11-05", InvalidFormat),
            ("2022/06/30T01:02:03Z", InvalidFormat),
            ("2022-06-30X01:02:03Z", InvalidFormat),
            ("2022-06-30T01:02:03+01:00x", InvalidFormat),
            ("2O22-06-30T01:02:03Z", InvalidDigit),
            ("2022-06-30T01:02:03.12x4Z", InvalidDigit),
            ("2022-06-30T01:02:03.5Zx", InvalidDigit),
            ("2022-06-30T01:02:03.5+01:00x", InvalidDigit),
            ("2022-13-01T00:00:00Z", OutOfRange),
            ("2022-00-10T00:00:00Z", OutOfRange),
            ("2022-02-30T00:00:00Z", OutOfRange),
            ("2023-02-29T00:00:00Z", OutOfRange),
            ("2022-06-00T00:00:00Z", OutOfRange),
            ("1969-12-31T23:59:59Z", OutOfRange),
            ("2022-06-30T24:00:00Z", OutOfRange),
            ("2022-06-30T01:60:00Z", OutOfRange),
            ("2022-06-30T01:02:61Z", OutOfRange),
        ] {
            assert_eq!(parse_rfc3339_weak(s), Err(error), "{s}");
        }
        // Ten thousand is not four digits: the shape is wrong before any number is read.
        assert_eq!(
            parse_rfc3339_weak("10000-01-01T00:00:00Z"),
            Err(InvalidFormat)
        );
        // humantime's words.
        assert_eq!(
            std::format!("{OutOfRange} / {InvalidDigit} / {InvalidFormat}"),
            "numeric component is out of range / bad character where digit is expected / \
             timestamp format is invalid"
        );
    }

    #[test]
    fn now_expressions_and_durations() {
        assert_eq!(time("now()"), Some(TimeExpr::Now { offset_secs: 0.0 }));
        assert_eq!(time("now(0)"), Some(TimeExpr::Now { offset_secs: 0.0 }));
        assert_eq!(
            time("now(123.45)"),
            Some(TimeExpr::Now {
                offset_secs: 123.45
            })
        );
        assert_eq!(
            time("now(1h)"),
            Some(TimeExpr::Now {
                offset_secs: 3600.0
            })
        );
        assert_eq!(
            time("now(-1h)"),
            Some(TimeExpr::Now {
                offset_secs: -3600.0
            })
        );
        // A leading `+` is part of the float, not a sign the grammar names.
        assert_eq!(time("now(+5s)"), Some(TimeExpr::Now { offset_secs: 5.0 }));
        for (lit, secs) in [
            ("1000u", 1e-3),
            ("2ms", 2e-3),
            ("1.5s", 1.5),
            ("2m", 120.0),
            ("1h", 3600.0),
            ("1d", 86_400.0),
            ("1w", 604_800.0),
            ("7", 7.0),
        ] {
            assert_eq!(parse_duration(lit), Ok(secs), "{lit}");
        }
        assert_eq!(parse_duration(""), Err(DurationError::Empty));
        for lit in ["xs", "s", "ms", "m", "1x", "--1s"] {
            assert!(
                matches!(parse_duration(lit), Err(DurationError::Float { text, .. }) if text == lit),
                "{lit:?}"
            );
        }
        // A refused `now(..)` names the whole time and the duration's own refusal.
        assert!(matches!(
            parse_time::<Epoch>("now(-1x)"),
            Err(TimeError {
                text: "now(-1x)",
                cause: TimeCause::Duration(DurationError::Float { text: "1x", .. })
            })
        ));
        // Not a time: no `now(`, no date.
        assert_eq!(time(""), None);
        assert_eq!(time("[;]"), None);
        assert_eq!(time("now(1h"), None);
    }

    #[test]
    fn ranges_parse_in_both_syntaxes() {
        use Edge::*;
        assert_eq!(
            range("[..]"),
            Some(TimeRange {
                start: Unbounded,
                end: Unbounded
            })
        );
        assert_eq!(
            range("[now(-1h)..now(1h)]"),
            Some(TimeRange {
                start: Inclusive(TimeExpr::Now {
                    offset_secs: -3600.0
                }),
                end: Inclusive(TimeExpr::Now {
                    offset_secs: 3600.0
                })
            })
        );
        assert_eq!(
            range("]now(-1h)..now(1h)["),
            Some(TimeRange {
                start: Exclusive(TimeExpr::Now {
                    offset_secs: -3600.0
                }),
                end: Exclusive(TimeExpr::Now {
                    offset_secs: 3600.0
                })
            })
        );
        // `;` is `start..start+duration`, the right bracket choosing the end's kind.
        assert_eq!(
            range("[now(-1h);30m]"),
            Some(TimeRange {
                start: Inclusive(TimeExpr::Now {
                    offset_secs: -3600.0
                }),
                end: Inclusive(TimeExpr::Now {
                    offset_secs: -1800.0
                })
            })
        );
        assert_eq!(
            range("]2022-06-30T01:02:03Z;1h["),
            Some(TimeRange {
                start: Exclusive(TimeExpr::Fixed(at(T_2022_06_30))),
                end: Exclusive(TimeExpr::Fixed(at(T_2022_06_30 + 3600)))
            })
        );
        // A negative duration moves a fixed start back as it moves a `now()` start back: the
        // end lies before the start.
        assert_eq!(
            range("[2022-06-30T01:02:03Z;-1h]"),
            Some(TimeRange {
                start: Inclusive(TimeExpr::Fixed(at(T_2022_06_30))),
                end: Inclusive(TimeExpr::Fixed(at(T_2022_06_30 - 3600)))
            })
        );
        assert_eq!(
            range("[now();-1h]"),
            Some(TimeRange {
                start: Inclusive(TimeExpr::Now { offset_secs: 0.0 }),
                end: Inclusive(TimeExpr::Now {
                    offset_secs: -3600.0
                })
            })
        );
        // `..` is looked for before `;`, as upstream does.
        assert!(range("[now(-1h)..now(1h);]").is_none());
    }

    /// Each refusal is the one upstream's parser reaches first.
    #[test]
    fn ranges_are_refused_in_upstreams_order() {
        fn refusal(s: &str) -> RangeError<'_> {
            parse_range::<Epoch>(s).unwrap_err()
        }
        assert_eq!(refusal(""), RangeError::TooShort);
        assert_eq!(refusal("[.]"), RangeError::TooShort);
        assert_eq!(refusal("now(-1h)"), RangeError::BadStart);
        assert_eq!(refusal("(now(-1h)..)"), RangeError::BadStart);
        assert_eq!(refusal("[now(-1h)..)"), RangeError::BadEnd);
        assert_eq!(
            refusal("[now(-1h)]"),
            RangeError::NoSeparator { inner: "now(-1h)" }
        );
        assert_eq!(refusal("[;1h]"), RangeError::NoStart { inner: ";1h" });
        assert_eq!(refusal("[;]"), RangeError::TooShort);
        // The duration is read before the start is asked for.
        assert!(matches!(
            refusal("[;x]"),
            RangeError::Duration(DurationError::Float { text: "x", .. })
        ));
        assert_eq!(
            refusal("[now(-1h);]"),
            RangeError::Duration(DurationError::Empty)
        );
        assert!(matches!(
            refusal("[now(-1h);1x]"),
            RangeError::Duration(DurationError::Float { text: "1x", .. })
        ));
        assert!(matches!(
            refusal("[now();s]"),
            RangeError::Duration(DurationError::Float { text: "s", .. })
        ));
        assert!(matches!(
            refusal("[bogus..]"),
            RangeError::Time(TimeError {
                text: "bogus",
                cause: TimeCause::Instant(Rfc3339Error::InvalidFormat)
            })
        ));
        assert!(matches!(
            refusal("[..bogus]"),
            RangeError::Time(TimeError { text: "bogus", .. })
        ));
        // A step back past the epoch is not an instant of this clock.
        assert_eq!(
            refusal("[1970-01-01T00:00:00Z;-1s]"),
            RangeError::EndUnrepresentable {
                inner: "1970-01-01T00:00:00Z;-1s"
            }
        );
        assert_eq!(
            refusal("[1970-01-01T00:00:00Z;nan]"),
            RangeError::EndUnrepresentable {
                inner: "1970-01-01T00:00:00Z;nan"
            }
        );
    }

    #[test]
    fn membership_follows_the_brackets() {
        let r = |s: &str, now: u64| range(s).unwrap().resolve_at::<Epoch>(at(now));
        let now = 1_000;
        let inside = r("[now(-10s)..now(10s)]", now);
        assert!(inside.contains(at(1_000)));
        assert!(inside.contains(at(990)));
        assert!(inside.contains(at(1_010)));
        assert!(!inside.contains(at(989)));
        assert!(!inside.contains(at(1_011)));
        // Exclusive ends drop the boundary instants.
        let open = r("]now(-10s)..now(10s)[", now);
        assert!(!open.contains(at(990)));
        assert!(!open.contains(at(1_010)));
        assert!(open.contains(at(991)));
        // A range in the past or the future holds nothing of the present.
        assert!(!r("[now(-2s)..now(-1s)]", now).contains(at(1_000)));
        assert!(!r("[now(1s)..now(2s)]", now).contains(at(1_000)));
        assert!(r("[now(-1m)..]", now).contains(at(1_000)));
        assert!(r("[..now(1m)]", now).contains(at(1_000)));
        // Both ends open holds everything, the epoch included.
        assert!(r("[..]", now).contains(at(0)));
        // A range whose end lies before its start holds nothing.
        let back = r("[2022-06-30T01:02:03Z;-1h]", now);
        for probe in [
            T_2022_06_30 - 3_601,
            T_2022_06_30 - 3_600,
            T_2022_06_30 - 1,
            T_2022_06_30,
            T_2022_06_30 + 1,
        ] {
            assert!(!back.contains(at(probe)), "{probe}");
        }
        // The duration form holds the same instants as the range it abbreviates.
        let dur = r("[2022-06-30T01:02:03Z;1h]", now);
        let rng = r("[2022-06-30T01:02:03Z..2022-06-30T02:02:03Z]", now);
        for probe in [
            T_2022_06_30 - 1,
            T_2022_06_30,
            T_2022_06_30 + 3_600,
            T_2022_06_30 + 3_601,
        ] {
            assert_eq!(dur.contains(at(probe)), rng.contains(at(probe)), "{probe}");
        }
    }

    /// An offset the instant type does not hold is an unbounded end. Read as a clamp it would
    /// turn an upper bound of `now(-1000000000d)` into "nothing", where upstream answers
    /// "everything".
    #[test]
    fn an_offset_out_of_range_is_unbounded_not_clamped() {
        let now = at(1_000);
        let far_past_end = range("[..now(-1e300d)]").unwrap().resolve_at::<Epoch>(now);
        assert_eq!(far_past_end.end, Edge::Unbounded);
        assert!(far_past_end.contains(at(1)));
        let far_future_start = range("[now(1e300d)..]").unwrap().resolve_at::<Epoch>(now);
        assert_eq!(far_future_start.start, Edge::Unbounded);
        // NaN is not a duration.
        assert_eq!(
            range("[now(nan)..]").map(|r| r.resolve_at::<Epoch>(now).start),
            Some(Edge::Unbounded)
        );
    }
}
