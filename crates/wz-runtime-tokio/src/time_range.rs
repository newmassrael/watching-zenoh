// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! zenoh's `_time` selector: the range grammar, its resolution against "now",
//! and the membership test.
//!
//! A port of zenoh-util `time_range.rs` @ `TimeRange` (the module the base
//! `zenoh` crate reaches through `Parameters::time_range`, so it is not an
//! adjunct of any one extension). It sits here, ungated, for the same reason:
//! the advanced publisher's cache and the C ABI's publication cache both read
//! one selector, and two readers of one grammar drift in a way neither one's own
//! tests can see.
//!
//! ## Grammar
//!
//! - range: `<[|]><start?>..<end?><[|]>`; omitting a side leaves it unbounded.
//! - duration: `<[|]><start>;<duration><[|]>`, which is `<start>..<start+duration>`.
//!   The start must be present.
//! - a bracket pointing INTO the range is inclusive, one pointing OUT is
//!   exclusive: `[a..b[` holds `a` and not `b`.
//! - a time is either `now(<-?><duration?>)` or an RFC3339 UTC timestamp, read by
//!   humantime's `parse_rfc3339_weak` (the `T` may be a space, the zone may be
//!   `Z`, `+00:00` or absent, fractional digits are any number of digits and
//!   the ones past the ninth are dropped).
//! - a duration is a float of seconds, or a float with one of `u ms s m h d w`.
//!
//! ## Where this deliberately differs from upstream
//!
//! Upstream PANICS on a few inputs that an attacker-chosen query parameter can
//! reach: a bare `s` as a duration, and a negative duration added to an absolute
//! start in the `;` form. A panic inside the cache's task is the cache dying, not
//! behaviour worth reproducing, so here those are INVALID ranges, which the
//! caller treats as no range (every sample replies), the same outcome upstream
//! gives any range that does not parse.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const U_TO_SECS: f64 = 0.000001;
const MS_TO_SECS: f64 = 0.001;
const M_TO_SECS: f64 = 60.0;
const H_TO_SECS: f64 = M_TO_SECS * 60.0;
const D_TO_SECS: f64 = H_TO_SECS * 24.0;
const W_TO_SECS: f64 = D_TO_SECS * 7.0;

/// The last second of year 9999, the bound `parse_rfc3339_weak` enforces on a
/// 64-bit target.
const RFC3339_MAX_SECONDS: u64 = 253_402_300_800 - 1;

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

/// A time as the selector spells it: an instant, or an offset from the moment the
/// range is evaluated.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TimeExpr {
    /// An RFC3339 instant.
    Fixed(SystemTime),
    /// `now(<offset>)`, the offset in seconds (negative reaches into the past).
    Now {
        /// Seconds added to the evaluation instant.
        offset_secs: f64,
    },
}

/// A parsed `_time` range. `T` is [`TimeExpr`] until the offsets are resolved
/// and [`SystemTime`] after.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct TimeRange<T = TimeExpr> {
    /// The lower end.
    pub start: Edge<T>,
    /// The upper end.
    pub end: Edge<T>,
}

impl TimeRange<TimeExpr> {
    /// Parse a `_time` value. `None` is a value upstream's parser rejects, and
    /// the caller then applies no time filter at all.
    pub fn parse(s: &str) -> Option<Self> {
        // The shortest range is `[..]`.
        let len = s.len();
        if len < 4 {
            return None;
        }
        let b = s.as_bytes();
        let inclusive_start = match b[0] {
            b'[' => true,
            b']' => false,
            _ => return None,
        };
        let inclusive_end = match b[len - 1] {
            b']' => true,
            b'[' => false,
            _ => return None,
        };
        // Both delimiters are ASCII, so these are char boundaries.
        let inner = &s[1..len - 1];
        if let Some((start, end)) = inner.split_once("..") {
            Some(TimeRange {
                start: parse_edge(start, inclusive_start)?,
                end: parse_edge(end, inclusive_end)?,
            })
        } else if let Some((start, duration)) = inner.split_once(';') {
            let start = parse_edge(start, inclusive_start)?;
            let secs = parse_duration(duration)?;
            let end_time = match &start {
                Edge::Inclusive(t) | Edge::Exclusive(t) => t.checked_add_secs(secs)?,
                Edge::Unbounded => return None,
            };
            let end = if inclusive_end {
                Edge::Inclusive(end_time)
            } else {
                Edge::Exclusive(end_time)
            };
            Some(TimeRange { start, end })
        } else {
            None
        }
    }

    /// Resolve the offsets against `now`. An offset that lands outside what a
    /// [`SystemTime`] holds becomes an UNBOUNDED end, not an error and not a
    /// clamp: that is upstream's answer, and a clamp would turn `now(-1000000d)`
    /// used as an upper bound into "nothing".
    pub fn resolve_at(self, now: SystemTime) -> TimeRange<SystemTime> {
        TimeRange {
            start: self.start.resolve_at(now),
            end: self.end.resolve_at(now),
        }
    }
}

impl TimeRange<SystemTime> {
    /// Whether `instant` lies in the range.
    pub fn contains(&self, instant: SystemTime) -> bool {
        match &self.start {
            Edge::Inclusive(t) if *t > instant => return false,
            Edge::Exclusive(t) if *t >= instant => return false,
            _ => {}
        }
        match &self.end {
            Edge::Inclusive(t) => *t >= instant,
            Edge::Exclusive(t) => *t > instant,
            Edge::Unbounded => true,
        }
    }

    /// Whether the instant an NTP64 timestamp word names lies in the range.
    pub fn contains_ntp64(&self, ntp64: u64) -> bool {
        self.contains(ntp64_to_system_time(ntp64))
    }
}

impl Edge<TimeExpr> {
    fn resolve_at(self, now: SystemTime) -> Edge<SystemTime> {
        match self {
            Edge::Inclusive(t) => t.resolve_at(now).map_or(Edge::Unbounded, Edge::Inclusive),
            Edge::Exclusive(t) => t.resolve_at(now).map_or(Edge::Unbounded, Edge::Exclusive),
            Edge::Unbounded => Edge::Unbounded,
        }
    }
}

impl TimeExpr {
    /// Parse one time: `now(...)` or an RFC3339 UTC timestamp.
    pub fn parse(s: &str) -> Option<Self> {
        if s.starts_with("now(") && s.ends_with(')') {
            let inner = &s[4..s.len() - 1];
            if inner.is_empty() {
                return Some(TimeExpr::Now { offset_secs: 0.0 });
            }
            // `-` is ASCII, so slicing after it is on a boundary.
            return match inner.as_bytes()[0] {
                b'-' => parse_duration(&inner[1..]).map(|f| TimeExpr::Now { offset_secs: -f }),
                _ => parse_duration(inner).map(|f| TimeExpr::Now { offset_secs: f }),
            };
        }
        parse_rfc3339_weak(s).map(TimeExpr::Fixed)
    }

    fn resolve_at(&self, now: SystemTime) -> Option<SystemTime> {
        match self {
            TimeExpr::Fixed(t) => Some(*t),
            TimeExpr::Now { offset_secs } => checked_duration_add(now, *offset_secs),
        }
    }

    /// `self + secs`, `None` where the sum cannot be held. (Upstream computes
    /// this with `Duration::from_secs_f64`, which panics on a negative number.)
    fn checked_add_secs(&self, secs: f64) -> Option<Self> {
        match self {
            TimeExpr::Fixed(t) => Duration::try_from_secs_f64(secs)
                .ok()
                .and_then(|d| t.checked_add(d))
                .map(TimeExpr::Fixed),
            TimeExpr::Now { offset_secs } => Some(TimeExpr::Now {
                offset_secs: offset_secs + secs,
            }),
        }
    }
}

fn checked_duration_add(t: SystemTime, secs: f64) -> Option<SystemTime> {
    if secs >= 0.0 {
        Duration::try_from_secs_f64(secs)
            .ok()
            .and_then(|d| t.checked_add(d))
    } else {
        Duration::try_from_secs_f64(-secs)
            .ok()
            .and_then(|d| t.checked_sub(d))
    }
}

fn parse_edge(s: &str, inclusive: bool) -> Option<Edge<TimeExpr>> {
    if s.is_empty() {
        Some(Edge::Unbounded)
    } else if inclusive {
        TimeExpr::parse(s).map(Edge::Inclusive)
    } else {
        TimeExpr::parse(s).map(Edge::Exclusive)
    }
}

/// A duration literal in seconds: a bare float, or a float followed by one of
/// `u` (microseconds), `ms`, `s`, `m`, `h`, `d`, `w`.
fn parse_duration(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    let n = b.len();
    if n == 0 {
        return None;
    }
    // Every suffix is ASCII, so each slice below ends on a char boundary.
    match b[n - 1] {
        b'u' => s[..n - 1].parse::<f64>().ok().map(|u| U_TO_SECS * u),
        b's' => {
            // A lone `s` has nothing to scale: upstream panics reading past the front.
            if n < 2 {
                None
            } else if b[n - 2] == b'm' {
                s[..n - 2].parse::<f64>().ok().map(|ms| MS_TO_SECS * ms)
            } else {
                s[..n - 1].parse::<f64>().ok()
            }
        }
        b'm' => s[..n - 1].parse::<f64>().ok().map(|m| M_TO_SECS * m),
        b'h' => s[..n - 1].parse::<f64>().ok().map(|h| H_TO_SECS * h),
        b'd' => s[..n - 1].parse::<f64>().ok().map(|d| D_TO_SECS * d),
        b'w' => s[..n - 1].parse::<f64>().ok().map(|w| W_TO_SECS * w),
        _ => s.parse::<f64>().ok(),
    }
}

/// humantime `parse_rfc3339_weak`: an RFC3339-like UTC timestamp.
///
/// The quirks are kept because a selector that parses upstream has to parse here:
/// the zone is not validated beyond its position (`+` anywhere six bytes from the
/// end ends the fraction), a leap second `:60` reads as `:59`, and the year is
/// four digits from 1970 to 9999.
fn parse_rfc3339_weak(s: &str) -> Option<SystemTime> {
    if s.len() < "2018-02-14T00:28:07".len() {
        return None;
    }
    let b = s.as_bytes();
    if b[4] != b'-'
        || b[7] != b'-'
        || (b[10] != b'T' && b[10] != b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let two = |i: usize| -> Option<u64> {
        let hi = (b[i] as char).to_digit(10)?;
        let lo = (b[i + 1] as char).to_digit(10)?;
        Some(u64::from(hi * 10 + lo))
    };
    let year = two(0)? * 100 + two(2)?;
    let month = two(5)?;
    let day = two(8)?;
    let hour = two(11)?;
    let minute = two(14)?;
    let mut second = two(17)?;

    if year < 1970 || hour > 23 || minute > 59 || second > 60 {
        return None;
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
        _ => return None,
    };
    if day > mdays || day == 0 {
        return None;
    }
    ydays += day - 1;
    if leap && month > 2 {
        ydays += 1;
    }

    let leap_years =
        ((year - 1) - 1968) / 4 - ((year - 1) - 1900) / 100 + ((year - 1) - 1600) / 400;
    let days = (year - 1970) * 365 + leap_years + ydays;
    let time = second + minute * 60 + hour * 3600;

    let mut nanos = 0u64;
    let mut mult = 100_000_000u64;
    if b.get(19) == Some(&b'.') {
        for idx in 20..b.len() {
            if b[idx] == b'Z' {
                if idx == b.len() - 1 {
                    break;
                }
                return None;
            } else if b[idx] == b'+' {
                // The start of `+00:00`, which must end the string.
                if idx == b.len() - 6 {
                    break;
                }
                return None;
            }
            nanos += mult * u64::from((b[idx] as char).to_digit(10)?);
            mult /= 10;
        }
    } else if b.len() != 19 && (b.len() > 25 || (b[19] != b'Z' && &b[19..] != b"+00:00")) {
        return None;
    }

    let total_seconds = time + days * 86_400;
    if total_seconds > RFC3339_MAX_SECONDS {
        return None;
    }
    // `nanos` is below 1e9 by construction (nine digits at most carry weight).
    Some(UNIX_EPOCH + Duration::new(total_seconds, nanos as u32))
}

/// The `_time` range a query's parameters carry, resolved against `now`.
///
/// `None` is "no time filter": the key is absent, or its value is not a range
/// zenoh's parser accepts (upstream's `time_range()` answers `Some(Err(_))` there
/// and its caches skip the filter on anything but `Some(Ok(_))`).
///
/// The key is found through the workspace's one parameter dialect
/// ([`wz_session_core::selector_params::param_value`]: pairs split on `;`, the
/// first `=` splits a pair, the first occurrence of a key wins). That split on
/// `;` is why a `[start;duration]` range does not survive in a parameter list:
/// the value reads `[start`, which is not a range. Upstream's `Parameters::get`
/// splits the same way, so the same selector is no range there either.
pub fn of_parameters(params: &str, now: SystemTime) -> Option<TimeRange<SystemTime>> {
    let value = wz_session_core::selector_params::param_value(params, "_time")?;
    TimeRange::parse(value).map(|range| range.resolve_at(now))
}

/// The instant an NTP64 word names, read as uhlc 0.8 reads it: the fraction
/// becomes nanoseconds rounded UP, so a whole number of nanoseconds survives the
/// round trip. A fraction near one second rounds to a full second, which
/// [`Duration::new`] carries.
pub fn ntp64_to_system_time(ntp64: u64) -> SystemTime {
    const FRAC_PER_SEC: u64 = 1 << 32;
    const NANO_PER_SEC: u64 = 1_000_000_000;
    let secs = ntp64 >> 32;
    let frac = ntp64 & (FRAC_PER_SEC - 1);
    let nanos = (frac * NANO_PER_SEC).div_ceil(FRAC_PER_SEC);
    UNIX_EPOCH + Duration::new(secs, nanos as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// 2022-06-30T01:02:03Z, read independently of this module's own arithmetic:
    /// 2022-07-01T00:00:00Z is 1656633600, one day earlier is 1656547200, and the
    /// time of day adds 1*3600 + 2*60 + 3.
    const T_2022_06_30: u64 = 1_656_547_200 + 3_723;

    #[test]
    fn rfc3339_weak_reads_the_forms_upstream_reads() {
        let t = |s: &str| TimeExpr::parse(s);
        assert_eq!(
            t("2022-06-30T01:02:03Z"),
            Some(TimeExpr::Fixed(at(T_2022_06_30)))
        );
        // No zone, a space for the T, and `+00:00` are the same instant.
        assert_eq!(t("2022-06-30T01:02:03"), t("2022-06-30T01:02:03Z"));
        assert_eq!(t("2022-06-30 01:02:03Z"), t("2022-06-30T01:02:03Z"));
        assert_eq!(t("2022-06-30T01:02:03+00:00"), t("2022-06-30T01:02:03Z"));
        // Fractional digits are nanoseconds, to the ninth place.
        assert_eq!(
            t("2022-06-30T01:02:03.226942997Z"),
            Some(TimeExpr::Fixed(
                at(T_2022_06_30) + Duration::from_nanos(226_942_997)
            ))
        );
        assert_eq!(
            t("2022-06-30T01:02:03.5Z"),
            Some(TimeExpr::Fixed(
                at(T_2022_06_30) + Duration::from_millis(500)
            ))
        );
        // A tenth digit is read and dropped.
        assert_eq!(
            t("2022-06-30T01:02:03.1234567891Z"),
            Some(TimeExpr::Fixed(
                at(T_2022_06_30) + Duration::from_nanos(123_456_789)
            ))
        );
        // Known epoch seconds for three round dates.
        assert_eq!(t("1970-01-01T00:00:00Z"), Some(TimeExpr::Fixed(UNIX_EPOCH)));
        assert_eq!(
            t("2000-01-01T00:00:00Z"),
            Some(TimeExpr::Fixed(at(946_684_800)))
        );
        assert_eq!(
            t("2024-01-01T00:00:00Z"),
            Some(TimeExpr::Fixed(at(1_704_067_200)))
        );
        // A leap day, and the leap second that reads as :59.
        assert_eq!(
            t("2024-02-29T00:00:00Z"),
            Some(TimeExpr::Fixed(at(1_704_067_200 + 59 * 86_400)))
        );
        assert_eq!(t("2022-06-30T01:02:60Z"), t("2022-06-30T01:02:59Z"));
    }

    #[test]
    fn rfc3339_weak_refuses_what_upstream_refuses() {
        for s in [
            "",
            "1h",
            "2020-11-05",
            "2022-13-01T00:00:00Z",
            "2022-00-10T00:00:00Z",
            "2022-02-30T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "2022-06-00T00:00:00Z",
            "1969-12-31T23:59:59Z",
            "2022-06-30T24:00:00Z",
            "2022-06-30T01:60:00Z",
            "2022-06-30T01:02:61Z",
            "2022/06/30T01:02:03Z",
            "2022-06-30X01:02:03Z",
            "2022-06-30T01:02:03.12x4Z",
            "2022-06-30T01:02:03.5Zx",
            "2022-06-30T01:02:03+01:00x",
            "9999-12-31T23:59:60Z",
        ] {
            // 9999-12-31T23:59:60Z is the last second (read as :59) and is the
            // one entry here that parses; it is asserted below, not refused.
            if s == "9999-12-31T23:59:60Z" {
                assert!(TimeExpr::parse(s).is_some(), "{s}");
                continue;
            }
            assert_eq!(TimeExpr::parse(s), None, "{s}");
        }
        // One second past year 9999 does not fit.
        assert_eq!(TimeExpr::parse("10000-01-01T00:00:00Z"), None);
    }

    #[test]
    fn now_expressions_and_durations() {
        let n = |s: &str| TimeExpr::parse(s);
        assert_eq!(n("now()"), Some(TimeExpr::Now { offset_secs: 0.0 }));
        assert_eq!(n("now(0)"), Some(TimeExpr::Now { offset_secs: 0.0 }));
        assert_eq!(
            n("now(123.45)"),
            Some(TimeExpr::Now {
                offset_secs: 123.45
            })
        );
        assert_eq!(
            n("now(1h)"),
            Some(TimeExpr::Now {
                offset_secs: 3600.0
            })
        );
        assert_eq!(
            n("now(-1h)"),
            Some(TimeExpr::Now {
                offset_secs: -3600.0
            })
        );
        // A leading `+` is part of the float, not a sign the grammar names.
        assert_eq!(n("now(+5s)"), Some(TimeExpr::Now { offset_secs: 5.0 }));
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
            assert_eq!(parse_duration(lit), Some(secs), "{lit}");
        }
        for lit in ["", "xs", "s", "ms", "m", "1x", "--1s"] {
            assert_eq!(parse_duration(lit), None, "{lit:?}");
        }
        // Not a time: no `now(`, no date.
        assert_eq!(n(""), None);
        assert_eq!(n("[;]"), None);
        assert_eq!(n("now(1h"), None);
    }

    #[test]
    fn ranges_parse_in_both_syntaxes() {
        use Edge::*;
        let r = |s: &str| TimeRange::parse(s);
        assert_eq!(
            r("[..]"),
            Some(TimeRange {
                start: Unbounded,
                end: Unbounded
            })
        );
        assert_eq!(
            r("[now(-1h)..now(1h)]"),
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
            r("]now(-1h)..now(1h)["),
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
            r("[now(-1h);30m]"),
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
            r("]2022-06-30T01:02:03Z;1h["),
            Some(TimeRange {
                start: Exclusive(TimeExpr::Fixed(at(T_2022_06_30))),
                end: Exclusive(TimeExpr::Fixed(at(T_2022_06_30 + 3600)))
            })
        );
        // Refused: no delimiter, no separator, a `;` with no start, a bad side.
        for s in [
            "",
            "[.]",
            "now(-1h)",
            "(now(-1h)..)",
            "[now(-1h)]",
            "[;1h]",
            "[;]",
            "[now(-1h);]",
            "[now(-1h);1x]",
            "[bogus..]",
            "[..bogus]",
            // The lone `s` upstream panics on, and a negative step from an instant.
            "[now();s]",
            "[2022-06-30T01:02:03Z;-1h]",
        ] {
            assert_eq!(TimeRange::parse(s), None, "{s:?}");
        }
        // `..` is looked for before `;`, as upstream does.
        assert!(TimeRange::parse("[now(-1h)..now(1h);]").is_none());
    }

    #[test]
    fn membership_follows_the_brackets() {
        let r = |s: &str, now: u64| TimeRange::parse(s).unwrap().resolve_at(at(now));
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
        assert!(r("[..]", now).contains(UNIX_EPOCH));
        // Absolute bounds, at the epoch.
        let t = |s: &str| TimeRange::parse(s).unwrap().resolve_at(at(now));
        assert!(t("[1970-01-01T00:00:00Z..]").contains(UNIX_EPOCH));
        assert!(t("[..1970-01-01T00:00:00Z]").contains(UNIX_EPOCH));
        assert!(!t("]1970-01-01T00:00:00Z..]").contains(UNIX_EPOCH));
        assert!(!t("[..1970-01-01T00:00:00Z[").contains(UNIX_EPOCH));
        // The duration form holds the same instants as the range it abbreviates.
        let dur = t("[2022-06-30T01:02:03Z;1h]");
        let rng = t("[2022-06-30T01:02:03Z..2022-06-30T02:02:03Z]");
        for probe in [
            T_2022_06_30 - 1,
            T_2022_06_30,
            T_2022_06_30 + 3_600,
            T_2022_06_30 + 3_601,
        ] {
            assert_eq!(dur.contains(at(probe)), rng.contains(at(probe)), "{probe}");
        }
    }

    /// An offset no `SystemTime` holds is an unbounded end. Read as a clamp it would
    /// turn an upper bound of `now(-1000000000d)` into "nothing", where upstream
    /// answers "everything".
    #[test]
    fn an_offset_out_of_range_is_unbounded_not_clamped() {
        let now = at(1_000);
        let far_past_end = TimeRange::parse("[..now(-1e300d)]")
            .unwrap()
            .resolve_at(now);
        assert_eq!(far_past_end.end, Edge::Unbounded);
        assert!(far_past_end.contains(at(1)));
        let far_future_start = TimeRange::parse("[now(1e300d)..]").unwrap().resolve_at(now);
        assert_eq!(far_future_start.start, Edge::Unbounded);
        // NaN is not a duration.
        assert_eq!(
            TimeRange::parse("[now(nan)..]").map(|r| r.resolve_at(now).start),
            Some(Edge::Unbounded)
        );
    }

    #[test]
    fn the_range_is_read_out_of_a_parameter_list_by_the_shared_dialect() {
        let now = at(1_000);
        // The shape wz's own history GET sends, and the one a zenoh advanced
        // subscriber sends: `;`-separated, ending in the bare `_anyke` flag.
        let r = of_parameters("_max=2;_time=[now(-30s)..];_anyke", now).unwrap();
        assert!(r.contains(at(970)));
        assert!(!r.contains(at(969)));
        // Absent, empty, or not a range: no filter at all.
        assert_eq!(of_parameters("_max=2;_anyke", now), None);
        assert_eq!(of_parameters("_time=", now), None);
        assert_eq!(of_parameters("_time=[bogus..]", now), None);
        assert_eq!(of_parameters("", now), None);
        // The first `_time` wins, as `Parameters::get` has it.
        let first = of_parameters("_time=[now(-30s)..];_time=[..]", now).unwrap();
        assert!(!first.contains(at(969)));
        // `;` ends a pair, so the duration form cannot ride in a parameter list:
        // the value is `[now(-1h)`, which is not a range, and nothing filters.
        assert_eq!(of_parameters("_time=[now(-1h);30m]", now), None);
    }

    #[test]
    fn ntp64_words_read_as_uhlc_reads_them() {
        assert_eq!(ntp64_to_system_time(0), UNIX_EPOCH);
        assert_eq!(ntp64_to_system_time(5u64 << 32), at(5));
        // Half a second is exactly 2^31 of the 2^32 fraction.
        assert_eq!(
            ntp64_to_system_time((5u64 << 32) | (1 << 31)),
            at(5) + Duration::from_millis(500)
        );
        // The smallest fraction rounds UP to a nanosecond (ceil(1e9 / 2^32) = 1).
        assert_eq!(
            ntp64_to_system_time(1),
            UNIX_EPOCH + Duration::from_nanos(1)
        );
        // The largest rounds up to a whole second, which carries.
        assert_eq!(ntp64_to_system_time(0xFFFF_FFFF), at(1));
        // A word past 2038 stays a positive instant (no signed cast to wrap).
        assert_eq!(ntp64_to_system_time(1u64 << 63), at(1 << 31));
    }

    #[test]
    fn contains_ntp64_is_contains_on_the_converted_word() {
        let range = TimeRange::parse("[now(-30s)..]")
            .unwrap()
            .resolve_at(at(100));
        assert!(range.contains_ntp64(80u64 << 32));
        assert!(range.contains_ntp64(70u64 << 32));
        assert!(!range.contains_ntp64(60u64 << 32));
        let past_2038 = at(1 << 31);
        let upper = TimeRange::parse("[..now(-1h)]")
            .unwrap()
            .resolve_at(past_2038);
        // An old sample passes an "older than an hour" window; a fresh one does not.
        assert!(upper.contains_ntp64((1u64 << 63) - (7_200u64 << 32)));
        assert!(!upper.contains_ntp64((1u64 << 63) - (60u64 << 32)));
    }
}
