//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-util 1.10.2, file
// src/time_range.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

use std::{
    convert::{TryFrom, TryInto},
    fmt::Display,
    ops::Add,
    str::FromStr,
    time::{Duration, SystemTime},
};

use humantime::format_rfc3339;
use wz_session_core::time_range as grammar;
use zenoh_result::{zerror, ZError};

// The grammar (the range, the time, the duration and the RFC3339 timestamp) is
// `wz_session_core::time_range`, the one reading every wz crate makes of the `_time` parameter.
// What stays here is upstream's API over it: these types, their conversions, `Display` and `Add`,
// and upstream's error texts, rebuilt from the grammar's refusal with the same nesting of
// `zerror!` upstream builds, so a refused text reads as upstream's.

/// The wall clock's instant type and its checked arithmetic, for the grammar.
enum Wall {}

impl grammar::Clock for Wall {
    type Instant = SystemTime;
    fn from_unix(since_epoch: Duration) -> SystemTime {
        SystemTime::UNIX_EPOCH + since_epoch
    }
    fn checked_add(at: SystemTime, by: Duration) -> Option<SystemTime> {
        at.checked_add(by)
    }
    fn checked_sub(at: SystemTime, by: Duration) -> Option<SystemTime> {
        at.checked_sub(by)
    }
}

/// The structural representation of the Zenoh Time DSL, which may adopt one of two syntax:
/// - the "range" syntax: `<ldel: '[' | ']'><start: TimeExpr?>..<end: TimeExpr?><rdel: '[' | ']'>`
/// - the "duration" syntax: `<ldel: '[' | ']'><start: TimeExpr>;<duration: Duration><rdel: '[' | ']'>`, which is
///   equivalent to `<ldel><start>..<start+duration><rdel>`
///
/// Durations follow the `<duration: float><unit: "u", "ms", "s", "m", "h", "d", "w">` syntax.
///
/// Where [`TimeExpr`] itself may adopt one of two syntaxes:
/// - the "instant" syntax, which must be a UTC [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339) formatted timestamp.
/// - the "offset" syntax, which is written `now(<sign: '-'?><offset: Duration?>)`, and allows to specify a target instant as
///   an offset applied to an instant of evaluation. These offset are resolved at the evaluation site.
///
/// In range syntax, omitting `<start>` and/or `<end>` implies that the range is unbounded in that direction.
///
/// Exclusive bounds are represented by their respective delimiters pointing towards the exterior.
/// Interior bounds are represented by the opposite.
///
/// The comparison step for instants is the nanosecond, which makes exclusive and inclusive bounds extremely close.
/// The `[<start>..<end>[` pattern may however be useful to guarantee that a same timestamp never appears twice when
/// iteratively getting values for `[t0..t1[`, `[t1..t2[`, `[t2..t3[`...
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TimeRange<T = TimeExpr> {
    pub start: TimeBound<T>,
    pub end: TimeBound<T>,
}

impl TimeRange<TimeExpr> {
    /// Resolves the offset bounds in the range using `now` as reference.
    pub fn resolve_at(self, now: SystemTime) -> TimeRange<SystemTime> {
        TimeRange {
            start: self.start.resolve_at(now),
            end: self.end.resolve_at(now),
        }
    }

    /// Resolves the offset bounds in the range using [`SystemTime::now`] as reference.
    pub fn resolve(self) -> TimeRange<SystemTime> {
        self.resolve_at(SystemTime::now())
    }

    /// Returns `true` if the provided `instant` belongs to `self`.
    ///
    /// This method performs resolution with [`SystemTime::now`] if the bounds contain an "offset" time expression.
    /// If you intend on performing this check multiple times, it may be wiser to resolve `self` first, and use
    /// [`TimeRange::<SystemTime>::contains`] instead.
    pub fn contains(&self, instant: SystemTime) -> bool {
        let now = SystemTime::now();
        match &self.start.resolve_at(now) {
            TimeBound::Inclusive(t) if t > &instant => return false,
            TimeBound::Exclusive(t) if t >= &instant => return false,
            _ => {}
        }
        match &self.end.resolve_at(now) {
            TimeBound::Inclusive(t) => t >= &instant,
            TimeBound::Exclusive(t) => t > &instant,
            _ => true,
        }
    }
}

impl TimeRange<SystemTime> {
    /// Returns `true` if the provided `instant` belongs to `self`.
    pub fn contains(&self, instant: SystemTime) -> bool {
        match &self.start {
            TimeBound::Inclusive(t) if *t > instant => return false,
            TimeBound::Exclusive(t) if *t >= instant => return false,
            _ => {}
        }
        match &self.end {
            TimeBound::Inclusive(t) => *t >= instant,
            TimeBound::Exclusive(t) => *t > instant,
            _ => true,
        }
    }
}

impl From<TimeRange<SystemTime>> for TimeRange<TimeExpr> {
    fn from(value: TimeRange<SystemTime>) -> Self {
        TimeRange {
            start: value.start.into(),
            end: value.end.into(),
        }
    }
}

impl TryFrom<TimeRange<TimeExpr>> for TimeRange<SystemTime> {
    type Error = ();
    fn try_from(value: TimeRange<TimeExpr>) -> Result<Self, Self::Error> {
        Ok(TimeRange {
            start: value.start.try_into()?,
            end: value.end.try_into()?,
        })
    }
}

impl Display for TimeRange<TimeExpr> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.start {
            TimeBound::Inclusive(t) => write!(f, "[{t}..")?,
            TimeBound::Exclusive(t) => write!(f, "]{t}..")?,
            TimeBound::Unbounded => f.write_str("[..")?,
        }
        match &self.end {
            TimeBound::Inclusive(t) => write!(f, "{t}]"),
            TimeBound::Exclusive(t) => write!(f, "{t}["),
            TimeBound::Unbounded => f.write_str("]"),
        }
    }
}

impl Display for TimeRange<SystemTime> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.start {
            TimeBound::Inclusive(t) => write!(f, "[{}..", TimeExpr::Fixed(*t))?,
            TimeBound::Exclusive(t) => write!(f, "]{}..", TimeExpr::Fixed(*t))?,
            TimeBound::Unbounded => f.write_str("[..")?,
        }
        match &self.end {
            TimeBound::Inclusive(t) => write!(f, "{}]", TimeExpr::Fixed(*t)),
            TimeBound::Exclusive(t) => write!(f, "{}[", TimeExpr::Fixed(*t)),
            TimeBound::Unbounded => f.write_str("]"),
        }
    }
}

impl FromStr for TimeRange<TimeExpr> {
    type Err = ZError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // The end of a `;` range is the start moved by the duration. Upstream adds with the `Add`
        // operator, which panics for a duration that is negative, not a number, infinite or past
        // what a `SystemTime` holds, whatever the user wrote after the ';'. The grammar moves a
        // start back by a negative duration, as upstream moves a `now()` start, and refuses the
        // sums no `SystemTime` holds.
        let range = grammar::parse_range::<Wall>(s).map_err(|refusal| range_error(s, refusal))?;
        Ok(TimeRange {
            start: range.start.into(),
            end: range.end.into(),
        })
    }
}

impl From<grammar::TimeExpr<SystemTime>> for TimeExpr {
    fn from(value: grammar::TimeExpr<SystemTime>) -> Self {
        match value {
            grammar::TimeExpr::Fixed(t) => TimeExpr::Fixed(t),
            grammar::TimeExpr::Now { offset_secs } => TimeExpr::Now { offset_secs },
        }
    }
}

impl From<grammar::Edge<grammar::TimeExpr<SystemTime>>> for TimeBound<TimeExpr> {
    fn from(value: grammar::Edge<grammar::TimeExpr<SystemTime>>) -> Self {
        match value {
            grammar::Edge::Inclusive(t) => TimeBound::Inclusive(t.into()),
            grammar::Edge::Exclusive(t) => TimeBound::Exclusive(t.into()),
            grammar::Edge::Unbounded => TimeBound::Unbounded,
        }
    }
}

/// Upstream's error for a refused range `s`: the text upstream's parser builds at the check the
/// grammar refused at.
fn range_error(s: &str, refusal: grammar::RangeError<'_>) -> ZError {
    use grammar::RangeError;
    match refusal {
        RangeError::TooShort => zerror!("Invalid TimeRange: {}", s),
        RangeError::BadStart => zerror!("Invalid TimeRange (must start with '[' or ']'): {}", s),
        RangeError::BadEnd => zerror!("Invalid TimeRange (must end with '[' or ']'): {}", s),
        RangeError::Time(refusal) => time_error(refusal),
        RangeError::Duration(refusal) => duration_error(refusal),
        RangeError::NoStart { inner } => zerror!(
            r#"Invalid TimeRange (';' must contain a time and a duration)"): {}"#,
            inner
        ),
        RangeError::EndUnrepresentable { inner } => zerror!(
            "Invalid TimeRange (the end of a start and a duration cannot be represented): {}",
            inner
        ),
        RangeError::NoSeparator { inner } => zerror!(
            r#"Invalid TimeRange (must contain ".." or ";" as separator)"): {}"#,
            inner
        ),
    }
}

/// Upstream's error for a refused time: the cause's own error, inside the time's.
fn time_error(refusal: grammar::TimeError<'_>) -> ZError {
    let cause = match refusal.cause {
        grammar::TimeCause::Duration(refusal) => duration_error(refusal),
        grammar::TimeCause::Instant(refusal) => zerror!(refusal),
    };
    zerror!(r#"Invalid time "{}" ({})"#, refusal.text, cause)
}

/// Upstream's error for a refused duration.
fn duration_error(refusal: grammar::DurationError<'_>) -> ZError {
    match refusal {
        grammar::DurationError::Empty => zerror!(
            r#"Invalid duration: "" (expected format: <f64> (in seconds) or <f64><unit>. Accepted units: u, ms, s, m, h, d or w.)"#
        ),
        grammar::DurationError::Float { text, error } => {
            zerror!(r#"Invalid duration "{}" ({})"#, text, error)
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TimeBound<T> {
    Inclusive(T),
    Exclusive(T),
    Unbounded,
}

impl From<TimeBound<SystemTime>> for TimeBound<TimeExpr> {
    fn from(value: TimeBound<SystemTime>) -> Self {
        match value {
            TimeBound::Inclusive(t) => TimeBound::Inclusive(t.into()),
            TimeBound::Exclusive(t) => TimeBound::Exclusive(t.into()),
            TimeBound::Unbounded => TimeBound::Unbounded,
        }
    }
}

impl TryFrom<TimeBound<TimeExpr>> for TimeBound<SystemTime> {
    type Error = ();
    fn try_from(value: TimeBound<TimeExpr>) -> Result<Self, Self::Error> {
        Ok(match value {
            TimeBound::Inclusive(t) => TimeBound::Inclusive(t.try_into()?),
            TimeBound::Exclusive(t) => TimeBound::Exclusive(t.try_into()?),
            TimeBound::Unbounded => TimeBound::Unbounded,
        })
    }
}

impl TimeBound<TimeExpr> {
    /// Resolves `self` into a [`TimeBound<SystemTime>`], using `now` as a reference for offset expressions.
    /// If `self` is time boundary that cannot be represented as `SystemTime` (which means it’s not inside
    /// the bounds of the underlying data structure), then `TimeBound::Unbounded` is returned.
    pub fn resolve_at(self, now: SystemTime) -> TimeBound<SystemTime> {
        match self {
            TimeBound::Inclusive(t) => match t.checked_resolve_at(now) {
                Some(ts) => TimeBound::Inclusive(ts),
                None => TimeBound::Unbounded,
            },
            TimeBound::Exclusive(t) => match t.checked_resolve_at(now) {
                Some(ts) => TimeBound::Exclusive(ts),
                None => TimeBound::Unbounded,
            },
            TimeBound::Unbounded => TimeBound::Unbounded,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TimeExpr {
    Fixed(SystemTime),
    Now { offset_secs: f64 },
}

impl From<SystemTime> for TimeExpr {
    fn from(t: SystemTime) -> Self {
        Self::Fixed(t)
    }
}

impl TryFrom<TimeExpr> for SystemTime {
    type Error = ();
    fn try_from(value: TimeExpr) -> Result<Self, Self::Error> {
        match value {
            TimeExpr::Fixed(t) => Ok(t),
            TimeExpr::Now { .. } => Err(()),
        }
    }
}

impl TimeExpr {
    /// Resolves `self` into a [`SystemTime`], using `now` as a reference for offset expressions.
    ///
    ///# Panics
    ///
    /// This function may panic if the resulting point in time cannot be represented by the
    /// underlying data structure. See [`TimeExpr::checked_resolve_at`] for a version without panic.
    pub fn resolve_at(&self, now: SystemTime) -> SystemTime {
        self.checked_resolve_at(now).unwrap()
    }

    /// Resolves `self` into a [`SystemTime`], using `now` as a reference for offset expressions.
    /// If `self` is a `TimeExpr::Now{offset_secs}` and adding `offset_secs` to `now` results in a time
    /// that would be outside the bounds of the underlying data structure, `None` is returned.
    pub fn checked_resolve_at(&self, now: SystemTime) -> Option<SystemTime> {
        match self {
            TimeExpr::Fixed(t) => Some(*t),
            TimeExpr::Now { offset_secs } => grammar::add_secs::<Wall>(now, *offset_secs),
        }
    }
    /// Adds `duration` to `self`, returning `None` if `self` is a `Fixed(SystemTime)` and adding the duration is not possible
    /// because the result would be outside the bounds of the underlying data structure (see [`SystemTime::checked_add`]).
    /// Otherwise returns `Some(time_expr)`.
    pub fn checked_add(&self, duration: f64) -> Option<Self> {
        match self {
            Self::Fixed(time) => grammar::add_secs::<Wall>(*time, duration).map(Self::Fixed),
            Self::Now { offset_secs } => Some(Self::Now {
                offset_secs: offset_secs + duration,
            }),
        }
    }
    /// Subtracts `duration` from `self`, returning `None` if `self` is a `Fixed(SystemTime)` and subtracting the duration is not possible
    /// because the result would be outside the bounds of the underlying data structure (see [`SystemTime::checked_sub`]).
    /// Otherwise returns `Some(time_expr)`.
    pub fn checked_sub(&self, duration: f64) -> Option<Self> {
        match self {
            Self::Fixed(time) => grammar::add_secs::<Wall>(*time, -duration).map(Self::Fixed),
            Self::Now { offset_secs } => Some(Self::Now {
                offset_secs: offset_secs - duration,
            }),
        }
    }
}

impl Display for TimeExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimeExpr::Fixed(time) => {
                write!(f, "{}", format_rfc3339(*time))
            }
            TimeExpr::Now { offset_secs } => {
                if *offset_secs == 0.0 {
                    f.write_str("now()")
                } else {
                    write!(f, "now({offset_secs}s)")
                }
            }
        }
    }
}

impl FromStr for TimeExpr {
    type Err = ZError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        grammar::parse_time::<Wall>(s)
            .map(TimeExpr::from)
            .map_err(time_error)
    }
}

impl Add<f64> for TimeExpr {
    type Output = Self;
    fn add(self, duration: f64) -> Self {
        match self {
            Self::Fixed(time) => Self::Fixed(time + Duration::from_secs_f64(duration)),
            Self::Now { offset_secs } => Self::Now {
                offset_secs: offset_secs + duration,
            },
        }
    }
}

impl Add<f64> for &TimeExpr {
    type Output = TimeExpr;
    fn add(self, duration: f64) -> TimeExpr {
        match self {
            TimeExpr::Fixed(time) => TimeExpr::Fixed((*time) + Duration::from_secs_f64(duration)),
            TimeExpr::Now { offset_secs } => TimeExpr::Now {
                offset_secs: offset_secs + duration,
            },
        }
    }
}

/// Upstream's private duration reader, which upstream's tests below call: the grammar's, with
/// upstream's error.
#[cfg(test)]
fn parse_duration(s: &str) -> Result<f64, ZError> {
    grammar::parse_duration(s).map_err(duration_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_range_contains() {
        assert!("[now(-1s)..now(1s)]"
            .parse::<TimeRange>()
            .unwrap()
            .contains(SystemTime::now()));
        assert!(!"[now(-2s)..now(-1s)]"
            .parse::<TimeRange>()
            .unwrap()
            .contains(SystemTime::now()));
        assert!(!"[now(1s)..now(2s)]"
            .parse::<TimeRange>()
            .unwrap()
            .contains(SystemTime::now()));

        assert!("[now(-1m)..]"
            .parse::<TimeRange>()
            .unwrap()
            .contains(SystemTime::now()));
        assert!("[..now(1m)]"
            .parse::<TimeRange>()
            .unwrap()
            .contains(SystemTime::now()));

        assert!("[..]"
            .parse::<TimeRange>()
            .unwrap()
            .contains(SystemTime::UNIX_EPOCH));
        assert!("[..]"
            .parse::<TimeRange>()
            .unwrap()
            .contains(SystemTime::now()));

        assert!("[1970-01-01T00:00:00Z..]"
            .parse::<TimeRange>()
            .unwrap()
            .contains(SystemTime::UNIX_EPOCH));
        assert!("[..1970-01-01T00:00:00Z]"
            .parse::<TimeRange>()
            .unwrap()
            .contains(SystemTime::UNIX_EPOCH));
        assert!(!"]1970-01-01T00:00:00Z..]"
            .parse::<TimeRange>()
            .unwrap()
            .contains(SystemTime::UNIX_EPOCH));
        assert!(!"[..1970-01-01T00:00:00Z["
            .parse::<TimeRange>()
            .unwrap()
            .contains(SystemTime::UNIX_EPOCH));
    }

    #[test]
    fn test_parse_time_range() {
        use TimeBound::*;
        assert_eq!(
            "[..]".parse::<TimeRange>().unwrap(),
            TimeRange {
                start: Unbounded,
                end: Unbounded
            }
        );
        assert_eq!(
            "[now(-1h)..now(1h)]".parse::<TimeRange>().unwrap(),
            TimeRange {
                start: Inclusive(TimeExpr::Now {
                    offset_secs: -3600.0
                }),
                end: Inclusive(TimeExpr::Now {
                    offset_secs: 3600.0
                })
            }
        );
        assert_eq!(
            "]now(-1h)..now(1h)[".parse::<TimeRange>().unwrap(),
            TimeRange {
                start: Exclusive(TimeExpr::Now {
                    offset_secs: -3600.0
                }),
                end: Exclusive(TimeExpr::Now {
                    offset_secs: 3600.0
                })
            }
        );

        assert!("".parse::<TimeExpr>().is_err());
        assert!("[;]".parse::<TimeExpr>().is_err());
        assert!("[;1h]".parse::<TimeExpr>().is_err());
    }

    #[test]
    fn test_parse_time_expr() {
        assert_eq!(
            "2022-06-30T01:02:03.226942997Z"
                .parse::<TimeExpr>()
                .unwrap(),
            TimeExpr::Fixed(humantime::parse_rfc3339("2022-06-30T01:02:03.226942997Z").unwrap())
        );
        assert_eq!(
            "2022-06-30T01:02:03Z".parse::<TimeExpr>().unwrap(),
            TimeExpr::Fixed(humantime::parse_rfc3339("2022-06-30T01:02:03Z").unwrap())
        );
        assert_eq!(
            "2022-06-30T01:02:03".parse::<TimeExpr>().unwrap(),
            TimeExpr::Fixed(humantime::parse_rfc3339("2022-06-30T01:02:03Z").unwrap())
        );
        assert_eq!(
            "2022-06-30 01:02:03Z".parse::<TimeExpr>().unwrap(),
            TimeExpr::Fixed(humantime::parse_rfc3339("2022-06-30T01:02:03Z").unwrap())
        );
        assert_eq!(
            "now()".parse::<TimeExpr>().unwrap(),
            TimeExpr::Now { offset_secs: 0.0 }
        );
        assert_eq!(
            "now(0)".parse::<TimeExpr>().unwrap(),
            TimeExpr::Now { offset_secs: 0.0 }
        );
        assert_eq!(
            "now(123.45)".parse::<TimeExpr>().unwrap(),
            TimeExpr::Now {
                offset_secs: 123.45
            }
        );
        assert_eq!(
            "now(1h)".parse::<TimeExpr>().unwrap(),
            TimeExpr::Now {
                offset_secs: 3600.0
            }
        );
        assert_eq!(
            "now(-1h)".parse::<TimeExpr>().unwrap(),
            TimeExpr::Now {
                offset_secs: -3600.0
            }
        );

        assert!("".parse::<TimeExpr>().is_err());
        assert!("1h".parse::<TimeExpr>().is_err());
        assert!("2020-11-05".parse::<TimeExpr>().is_err());
    }

    #[test]
    fn test_add_time_expr() {
        let t = TimeExpr::Now { offset_secs: 0.0 };
        assert_eq!(
            t.checked_add(3600.0),
            Some(TimeExpr::Now {
                offset_secs: 3600.0
            })
        );
        assert_eq!(
            t.checked_add(-3600.0),
            Some(TimeExpr::Now {
                offset_secs: -3600.0
            })
        );
        assert_eq!(
            t.checked_sub(3600.0),
            Some(TimeExpr::Now {
                offset_secs: -3600.0
            })
        );
        assert_eq!(
            t.checked_sub(-3600.0),
            Some(TimeExpr::Now {
                offset_secs: 3600.0
            })
        );

        let t = TimeExpr::Fixed(SystemTime::UNIX_EPOCH);
        assert_eq!(
            t.checked_add(3600.0),
            Some(TimeExpr::Fixed(
                SystemTime::UNIX_EPOCH + Duration::from_secs_f64(3600.0)
            ))
        );
        assert_eq!(
            t.checked_add(-3600.0),
            Some(TimeExpr::Fixed(
                SystemTime::UNIX_EPOCH - Duration::from_secs_f64(3600.0)
            ))
        );
        assert_eq!(
            t.checked_sub(3600.0),
            Some(TimeExpr::Fixed(
                SystemTime::UNIX_EPOCH - Duration::from_secs_f64(3600.0)
            ))
        );
        assert_eq!(
            t.checked_sub(-3600.0),
            Some(TimeExpr::Fixed(
                SystemTime::UNIX_EPOCH + Duration::from_secs_f64(3600.0)
            ))
        );

        assert_eq!(t.checked_add(f64::MAX), None);
        assert_eq!(t.checked_sub(f64::MAX), None);
    }

    #[test]
    fn test_resolve_time_expr() {
        let now = SystemTime::now();

        assert_eq!(
            TimeExpr::Now { offset_secs: 0.0 }.checked_resolve_at(now),
            Some(now)
        );
        assert_eq!(
            TimeExpr::Now {
                offset_secs: f64::MAX
            }
            .checked_resolve_at(now),
            None
        );

        let t = TimeExpr::Fixed(SystemTime::UNIX_EPOCH);
        assert_eq!(t.checked_resolve_at(now), Some(SystemTime::UNIX_EPOCH));
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("0").unwrap(), 0.0);
        assert_eq!(parse_duration("1.2").unwrap(), 1.2);
        assert_eq!(parse_duration("1u").unwrap(), 0.000001);
        assert_eq!(parse_duration("2u").unwrap(), 0.000002);
        assert_eq!(parse_duration("1.5ms").unwrap(), 0.0015);
        assert_eq!(parse_duration("100ms").unwrap(), 0.1);
        assert_eq!(parse_duration("10s").unwrap(), 10.0);
        assert_eq!(parse_duration("0.5s").unwrap(), 0.5);
        assert_eq!(parse_duration("1.1m").unwrap(), 66.0);
        assert_eq!(parse_duration("1.5h").unwrap(), 5400.0);
        assert_eq!(parse_duration("1d").unwrap(), 86400.0);
        assert_eq!(parse_duration("1w").unwrap(), 604800.0);

        assert!(parse_duration("").is_err());
        assert!(parse_duration("1x").is_err());
        assert!(parse_duration("abcd").is_err());
        assert!(parse_duration("4mm").is_err());
        assert!(parse_duration("1h4m").is_err());
    }
}
