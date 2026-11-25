// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Windows performance counter's ticks as the nanoseconds of the monotonic clock: plain
//! integers with no Win32 in sight, so a Linux build tests the rule a Windows build uses.

/// Nanoseconds in a second.
const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// The highest counter frequency whose conversion is exact: a remainder below it, times
/// `NANOS_PER_SECOND`, stays inside a `u64`. About 18.4 GHz, far above any counter Windows
/// reports (10 MHz on current hosts, the TSC's frequency on older ones).
#[cfg(test)]
const EXACT_UP_TO: u64 = u64::MAX / NANOS_PER_SECOND;

/// The nanoseconds `ticks` counter ticks make at `per_second` ticks a second. Whole seconds and
/// the remainder are scaled apart: the exact quotient of the 128-bit product for any frequency up
/// to `EXACT_UP_TO`, without the 128-bit division a 32-bit host runs as a long loop. A count past the `u64` of nanoseconds (584 years) wraps as that division's
/// truncation did. A counter that reads below zero, or one with no frequency, reads as time stood
/// still, which the monotonic contract allows.
pub(crate) fn ticks_to_ns(ticks: i64, per_second: i64) -> u64 {
    let (Ok(ticks), Ok(per_second)) = (u64::try_from(ticks), u64::try_from(per_second)) else {
        return 0;
    };
    if per_second == 0 {
        return 0;
    }
    let whole = ticks / per_second;
    let part = ticks % per_second;
    whole
        .wrapping_mul(NANOS_PER_SECOND)
        .wrapping_add(part.saturating_mul(NANOS_PER_SECOND) / per_second)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact conversion: one 128-bit product and division.
    fn wide(ticks: i64, per_second: i64) -> u64 {
        (u128::from(ticks as u64) * u128::from(NANOS_PER_SECOND) / u128::from(per_second as u64))
            as u64
    }

    #[test]
    fn ticks_convert_as_the_wide_division_did_at_every_frequency_up_to_the_bound() {
        let frequencies = [
            1,
            3,
            1_193_182,
            3_579_545,
            10_000_000,
            999_999_999,
            1_000_000_000,
            2_399_999_999,
            3_000_000_007,
            EXACT_UP_TO as i64,
        ];
        let counts = [
            0,
            1,
            2,
            9_999_999,
            10_000_000,
            10_000_001,
            1 << 31,
            (1 << 32) - 1,
            1 << 32,
            // Ten years of a 10 MHz counter: the plain 64-bit product would overflow.
            10 * 365 * 24 * 3600 * 10_000_000,
            i64::MAX / 2,
            i64::MAX - 1,
            i64::MAX,
        ];
        for per_second in frequencies {
            for ticks in counts {
                for ticks in [ticks, ticks.saturating_add(per_second - 1)] {
                    assert_eq!(
                        ticks_to_ns(ticks, per_second),
                        wide(ticks, per_second),
                        "{ticks} ticks at {per_second} a second"
                    );
                }
            }
        }
    }

    #[test]
    fn the_remainder_of_a_second_keeps_its_share() {
        // The 10 MHz counter of current Windows: a hundred nanoseconds a tick.
        assert_eq!(ticks_to_ns(1, 10_000_000), 100);
        assert_eq!(ticks_to_ns(25_000_003, 10_000_000), 2_500_000_300);
        // A frequency that does not divide a second evenly rounds the remainder's share down.
        assert_eq!(ticks_to_ns(1, 3), 333_333_333);
        assert_eq!(ticks_to_ns(5, 3), 1_666_666_666);
    }

    #[test]
    fn a_counter_without_a_frequency_or_below_zero_stands_still() {
        assert_eq!(ticks_to_ns(1_000, 0), 0);
        assert_eq!(ticks_to_ns(-1, 10_000_000), 0);
        assert_eq!(ticks_to_ns(1_000, -1), 0);
    }
}
