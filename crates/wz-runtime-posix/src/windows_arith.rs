// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The pure arithmetic of the Windows host: the performance counter's ticks as the microseconds
//! the cooperative runtime's clock counts, and a `FILETIME` as the time since the Unix epoch the
//! session core's wall clock reads.
//!
//! Plain integers the Win32 calls return, with no Win32 in sight, so a Linux build compiles and
//! tests the rules and a Windows build uses them: a rule checked only on a Windows runner would
//! be checked once, at the end.

/// 100 ns `FILETIME` intervals between 1601-01-01 and 1970-01-01.
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
/// 100 ns `FILETIME` intervals in a second.
const FILETIME_PER_SECOND: u64 = 10_000_000;

/// The microseconds `ticks` performance-counter ticks make at `frequency` ticks a second. Whole
/// seconds and the remainder are converted apart, so a counter that has run for years does not
/// overflow the product a single multiplication would form. A counter that reads below zero, or
/// a host whose counter has no frequency, reads as time stood still rather than as a jump, which
/// the monotonic contract allows.
pub(crate) fn ticks_to_us(ticks: i64, frequency: i64) -> u64 {
    let (Ok(ticks), Ok(frequency)) = (u64::try_from(ticks), u64::try_from(frequency)) else {
        return 0;
    };
    if frequency == 0 {
        return 0;
    }
    let secs = ticks / frequency;
    let rest = ticks % frequency;
    secs.saturating_mul(1_000_000)
        .saturating_add(rest.saturating_mul(1_000_000) / frequency)
}

/// The seconds and nanoseconds since the Unix epoch of a `FILETIME` read as one 64-bit count of
/// 100 ns intervals since 1601: `None` for an instant before 1970, which a timestamp cannot carry
/// and which is refused rather than read as the epoch.
pub(crate) fn filetime_since_unix_epoch(intervals: u64) -> Option<(u64, u32)> {
    let since = intervals.checked_sub(FILETIME_UNIX_EPOCH)?;
    let secs = since / FILETIME_PER_SECOND;
    // Below 10^7 intervals of 100 ns, so below 10^9 nanoseconds and inside a `u32`.
    let nanos = ((since % FILETIME_PER_SECOND) * 100) as u32;
    Some((secs, nanos))
}

/// A `FILETIME`'s two 32-bit halves as the one count of 100 ns intervals they spell.
pub(crate) fn filetime_intervals(low: u32, high: u32) -> u64 {
    (u64::from(high) << 32) | u64::from(low)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_convert_to_microseconds_at_the_counters_frequency() {
        // The 10 MHz counter of current Windows: ten ticks a microsecond.
        assert_eq!(ticks_to_us(10, 10_000_000), 1);
        assert_eq!(ticks_to_us(25_000_000, 10_000_000), 2_500_000);
        // A frequency that does not divide a second evenly keeps the remainder's share.
        assert_eq!(ticks_to_us(3, 3_000_000), 1);
        assert_eq!(ticks_to_us(4_500_000, 3_000_000), 1_500_000);
    }

    #[test]
    fn a_counter_that_has_run_for_years_does_not_overflow() {
        // Ten years of a 10 MHz counter: the single product would be about 3.2e21, past u64.
        let ten_years = 10 * 365 * 24 * 3600 * 10_000_000_i64;
        assert_eq!(
            ticks_to_us(ten_years, 10_000_000),
            10 * 365 * 24 * 3600 * 1_000_000
        );
    }

    #[test]
    fn a_counter_without_a_frequency_or_below_zero_stands_still() {
        assert_eq!(ticks_to_us(1_000, 0), 0);
        assert_eq!(ticks_to_us(-1, 10_000_000), 0);
        assert_eq!(ticks_to_us(1_000, -1), 0);
    }

    #[test]
    fn a_filetime_reads_as_the_time_since_the_unix_epoch() {
        assert_eq!(filetime_since_unix_epoch(FILETIME_UNIX_EPOCH), Some((0, 0)));
        // 1.5 s and 300 ns past the epoch.
        assert_eq!(
            filetime_since_unix_epoch(FILETIME_UNIX_EPOCH + 15_000_003),
            Some((1, 500_000_300))
        );
        // 2001-09-09T01:46:40Z, the Unix time 1_000_000_000.
        assert_eq!(
            filetime_since_unix_epoch(FILETIME_UNIX_EPOCH + 1_000_000_000 * FILETIME_PER_SECOND),
            Some((1_000_000_000, 0))
        );
    }

    #[test]
    fn a_filetime_before_1970_is_refused() {
        assert_eq!(filetime_since_unix_epoch(FILETIME_UNIX_EPOCH - 1), None);
        assert_eq!(filetime_since_unix_epoch(0), None);
    }

    #[test]
    fn the_two_halves_of_a_filetime_spell_one_count() {
        assert_eq!(filetime_intervals(0, 0), 0);
        assert_eq!(filetime_intervals(1, 0), 1);
        assert_eq!(filetime_intervals(0, 1), 1 << 32);
        assert_eq!(filetime_intervals(u32::MAX, u32::MAX), u64::MAX);
    }
}
