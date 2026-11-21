// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! zenoh's `_time` selector in wall-clock time: the range a query carries, read with the
//! grammar of [`wz_session_core::time_range`] and resolved against a [`WallTime`].
//!
//! The advanced publisher's cache and the C ABI's publication cache both read one selector, and
//! two readers of one grammar drift in a way neither one's own tests can see; so the grammar, its
//! resolution and its membership test are wz-session-core's, which upstream zenoh-util's
//! `TimeRange` in wz-zenoh-util reads too. This module names the instant type ([`Wall`]), reads
//! the parameter out of a list, and reads a sample's NTP64 timestamp as an instant.
//!
//! A value upstream's parser refuses is no range at all here: the caller applies no time filter,
//! which is what upstream's caches do with a range they cannot read. Where upstream panics instead
//! of refusing, see the module docs of [`wz_session_core::time_range`].

use core::time::Duration;

use wz_session_core::time_range as grammar;

pub use grammar::Edge;

/// An instant of the wall clock: `std`'s `SystemTime` with `std`, and without it an
/// [`EpochTime`], which holds an instant as `SystemTime` does on a POSIX host.
#[cfg(feature = "std")]
pub type WallTime = std::time::SystemTime;
/// An instant of the wall clock: `std`'s `SystemTime` with `std`, and without it an
/// [`EpochTime`], which holds an instant as `SystemTime` does on a POSIX host.
#[cfg(not(feature = "std"))]
pub type WallTime = EpochTime;

/// The Unix epoch, as a [`WallTime`].
#[cfg(feature = "std")]
const EPOCH: WallTime = std::time::UNIX_EPOCH;
#[cfg(not(feature = "std"))]
const EPOCH: WallTime = EpochTime::UNIX_EPOCH;

/// A time as the selector spells it, its instant a [`WallTime`].
pub type TimeExpr = grammar::TimeExpr<WallTime>;

/// A parsed `_time` range: [`TimeExpr`] ends until resolved, [`WallTime`] ends after.
pub type TimeRange<T = TimeExpr> = grammar::TimeRange<T>;

/// The wall clock's instant type and its checked arithmetic, for the grammar.
pub enum Wall {}

impl grammar::Clock for Wall {
    type Instant = WallTime;
    fn from_unix(since_epoch: Duration) -> WallTime {
        after_epoch(since_epoch)
    }
    fn checked_add(at: WallTime, by: Duration) -> Option<WallTime> {
        at.checked_add(by)
    }
    fn checked_sub(at: WallTime, by: Duration) -> Option<WallTime> {
        at.checked_sub(by)
    }
}

/// `since` after the epoch. A time past what a [`WallTime`] holds panics, as `SystemTime`'s `+`
/// does.
fn after_epoch(since: Duration) -> WallTime {
    EPOCH
        .checked_add(since)
        .expect("overflow when adding duration to instant")
}

/// An instant of the wall clock without `std`: whole seconds from the Unix epoch, signed, and the
/// nanoseconds past them, which is how `SystemTime` holds one on a POSIX host. Its arithmetic is
/// that `SystemTime`'s, so a `_time` range resolves to the same bounds in either build, an instant
/// before 1970 included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EpochTime {
    secs: i64,
    /// Below one second, so that the derived order is the order in time.
    nanos: u32,
}

impl EpochTime {
    /// The Unix epoch.
    pub const UNIX_EPOCH: Self = Self { secs: 0, nanos: 0 };

    const NANOS_PER_SEC: u32 = 1_000_000_000;

    /// `by` later, or `None` past the last instant the seconds hold.
    pub fn checked_add(self, by: Duration) -> Option<Self> {
        let mut secs = self.secs.checked_add_unsigned(by.as_secs())?;
        let mut nanos = self.nanos + by.subsec_nanos();
        if nanos >= Self::NANOS_PER_SEC {
            nanos -= Self::NANOS_PER_SEC;
            secs = secs.checked_add(1)?;
        }
        Some(Self { secs, nanos })
    }

    /// `by` earlier, or `None` before the first instant the seconds hold.
    pub fn checked_sub(self, by: Duration) -> Option<Self> {
        let mut secs = self.secs.checked_sub_unsigned(by.as_secs())?;
        let nanos = if self.nanos >= by.subsec_nanos() {
            self.nanos - by.subsec_nanos()
        } else {
            secs = secs.checked_sub(1)?;
            self.nanos + Self::NANOS_PER_SEC - by.subsec_nanos()
        };
        Some(Self { secs, nanos })
    }
}

/// Parse a `_time` value. `None` is a value upstream's parser refuses, and the caller then applies
/// no time filter at all.
pub fn parse(s: &str) -> Option<TimeRange> {
    grammar::parse_range::<Wall>(s).ok()
}

/// The range at `now`. An offset that lands outside what a [`WallTime`] holds is an UNBOUNDED
/// end ([`grammar::Edge::resolve_at`]).
pub fn resolve(range: TimeRange, now: WallTime) -> TimeRange<WallTime> {
    range.resolve_at::<Wall>(now)
}

/// Whether the instant an NTP64 timestamp word names lies in `range`.
pub fn contains_ntp64(range: &TimeRange<WallTime>, ntp64: u64) -> bool {
    range.contains(ntp64_to_system_time(ntp64))
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
pub fn of_parameters(params: &str, now: WallTime) -> Option<TimeRange<WallTime>> {
    let value = wz_session_core::selector_params::param_value(
        params,
        wz_session_core::selector_params::TIME_RANGE_PARAM,
    )?;
    parse(value).map(|range| resolve(range, now))
}

/// The instant an NTP64 word names, read as uhlc 0.8 reads it: the fraction
/// becomes nanoseconds rounded UP, so a whole number of nanoseconds survives the
/// round trip. A fraction near one second rounds to a full second, which
/// [`Duration::new`] carries.
pub fn ntp64_to_system_time(ntp64: u64) -> WallTime {
    const FRAC_PER_SEC: u64 = 1 << 32;
    const NANO_PER_SEC: u64 = 1_000_000_000;
    let secs = ntp64 >> 32;
    let frac = ntp64 & (FRAC_PER_SEC - 1);
    let nanos = (frac * NANO_PER_SEC).div_ceil(FRAC_PER_SEC);
    after_epoch(Duration::new(secs, nanos as u32))
}

/// The grammar's own tests are wz-session-core's; these hold what this module adds: the wall
/// clock's limits, the parameter list and the NTP64 reading.
#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn r(s: &str, now: u64) -> TimeRange<SystemTime> {
        resolve(parse(s).unwrap(), at(now))
    }

    #[test]
    fn membership_follows_the_brackets_in_wall_clock_time() {
        let now = 1_000;
        let inside = r("[now(-10s)..now(10s)]", now);
        assert!(inside.contains(at(990)));
        assert!(inside.contains(at(1_010)));
        assert!(!inside.contains(at(989)));
        assert!(!inside.contains(at(1_011)));
        // Absolute bounds, at the epoch.
        assert!(r("[1970-01-01T00:00:00Z..]", now).contains(UNIX_EPOCH));
        assert!(r("[..1970-01-01T00:00:00Z]", now).contains(UNIX_EPOCH));
        assert!(!r("]1970-01-01T00:00:00Z..]", now).contains(UNIX_EPOCH));
        assert!(!r("[..1970-01-01T00:00:00Z[", now).contains(UNIX_EPOCH));
        // Both ends open holds everything, the epoch included.
        assert!(r("[..]", now).contains(UNIX_EPOCH));
    }

    /// A negative `;` duration from a fixed start is a range whose end lies before its start,
    /// which holds nothing, as `[now();-1h]` does; it was refused here, and so filtered nothing,
    /// until the grammar became one (2026-11-19).
    #[test]
    fn a_negative_step_from_an_instant_holds_nothing() {
        // 2022-06-30T01:02:03Z
        let t = 1_656_547_200 + 3_723;
        let back = r("[2022-06-30T01:02:03Z;-1h]", 0);
        assert_eq!(back.end, Edge::Inclusive(at(t - 3_600)));
        for probe in [t - 3_601, t - 3_600, t - 1, t, t + 1] {
            assert!(!back.contains(at(probe)), "{probe}");
        }
    }

    /// An offset no `SystemTime` holds is an unbounded end. Read as a clamp it would
    /// turn an upper bound of `now(-1000000000d)` into "nothing", where upstream
    /// answers "everything".
    #[test]
    fn an_offset_out_of_range_is_unbounded_not_clamped() {
        let far_past_end = r("[..now(-1e300d)]", 1_000);
        assert_eq!(far_past_end.end, Edge::Unbounded);
        assert!(far_past_end.contains(at(1)));
        let far_future_start = r("[now(1e300d)..]", 1_000);
        assert_eq!(far_future_start.start, Edge::Unbounded);
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
        let range = r("[now(-30s)..]", 100);
        assert!(contains_ntp64(&range, 80u64 << 32));
        assert!(contains_ntp64(&range, 70u64 << 32));
        assert!(!contains_ntp64(&range, 60u64 << 32));
        let upper = resolve(parse("[..now(-1h)]").unwrap(), at(1 << 31));
        // An old sample passes an "older than an hour" window; a fresh one does not.
        assert!(contains_ntp64(&upper, (1u64 << 63) - (7_200u64 << 32)));
        assert!(!contains_ntp64(&upper, (1u64 << 63) - (60u64 << 32)));
    }

    /// `SystemTime` on a POSIX host, read as the seconds and nanoseconds an [`EpochTime`] holds.
    #[cfg(unix)]
    fn mirror(at: SystemTime) -> EpochTime {
        match at.duration_since(UNIX_EPOCH) {
            Ok(after) => EpochTime {
                secs: after.as_secs() as i64,
                nanos: after.subsec_nanos(),
            },
            Err(before) => {
                let before = before.duration();
                if before.subsec_nanos() == 0 {
                    EpochTime {
                        secs: -(before.as_secs() as i64),
                        nanos: 0,
                    }
                } else {
                    EpochTime {
                        secs: -(before.as_secs() as i64) - 1,
                        nanos: 1_000_000_000 - before.subsec_nanos(),
                    }
                }
            }
        }
    }

    /// The instant without `std` adds and subtracts as `SystemTime` does, before the epoch, across
    /// a second's carry and at the ends of what the seconds hold.
    #[cfg(unix)]
    #[test]
    fn the_instant_without_std_is_system_time_arithmetic() {
        let bases = [
            UNIX_EPOCH,
            UNIX_EPOCH + Duration::new(1_000, 700_000_000),
            UNIX_EPOCH - Duration::new(1, 500_000_000),
            UNIX_EPOCH - Duration::from_secs(86_400),
        ];
        let steps = [
            Duration::ZERO,
            Duration::from_nanos(1),
            Duration::new(0, 400_000_000),
            Duration::new(2, 600_000_000),
            Duration::from_secs(3_600),
            Duration::MAX,
        ];
        for base in bases {
            let ours = mirror(base);
            for step in steps {
                assert_eq!(
                    ours.checked_add(step),
                    base.checked_add(step).map(mirror),
                    "{base:?} + {step:?}"
                );
                assert_eq!(
                    ours.checked_sub(step),
                    base.checked_sub(step).map(mirror),
                    "{base:?} - {step:?}"
                );
            }
        }
        assert!(mirror(UNIX_EPOCH - Duration::from_nanos(1)) < EpochTime::UNIX_EPOCH);
        assert!(EpochTime::UNIX_EPOCH < mirror(UNIX_EPOCH + Duration::from_nanos(1)));
    }
}
