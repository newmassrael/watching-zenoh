// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The pure arithmetic of the Zephyr host layer: pico's `system/zephyr/system.c` clock rules over
//! the integers a `struct timespec` or a `struct timeval` holds, with no kernel in sight, so that a
//! host build tests what only an image runs (as `arith` is for the Windows layer).
//!
//! A reading is `(seconds, sub)`, where `sub` counts `sub_per_second` parts of a second: 1e9 for a
//! timespec's nanoseconds, 1e6 for a timeval's microseconds. Everything is computed in 64 bits,
//! where pico computes in a 32-bit `long` and overflows past 35 minutes of microseconds.

use super::Unit;

const NANOS_PER_SECOND: i64 = 1_000_000_000;

/// How many of `unit` make a second.
pub fn units_per_second(unit: Unit) -> i64 {
    match unit {
        Unit::Micro => 1_000_000,
        Unit::Milli => 1_000,
        Unit::Second => 1,
    }
}

/// The signed time from `then` to `now` in `unit`, saturating, with the sub-second difference
/// truncated toward zero as pico's division of a `long` is.
pub fn elapsed(now: (i64, i64), then: (i64, i64), sub_per_second: i64, unit: Unit) -> i64 {
    let per_second = units_per_second(unit);
    let whole = now.0.saturating_sub(then.0).saturating_mul(per_second);
    // A unit is never finer than the reading's parts, so the scale is one or more; a scale of
    // none would be a reading of no parts, which says nothing below a second.
    let scale = sub_per_second.checked_div(per_second).unwrap_or(0);
    let part = now.1.saturating_sub(then.1).checked_div(scale).unwrap_or(0);
    whole.saturating_add(part)
}

/// A negative time as none, as pico's monotonic `zp_clock_elapsed_*_since` clamp it.
pub fn clamped(elapsed: i64) -> u64 {
    elapsed.max(0).unsigned_abs()
}

/// A timespec reading `(seconds, nanoseconds)` moved FORWARD by `duration` of `unit`, with pico's
/// one carry: the nanoseconds start below a second and gain less than one.
pub fn advance(reading: (i64, i64), unit: Unit, duration: u64) -> (i64, i64) {
    let per_second = units_per_second(unit).unsigned_abs();
    // `units_per_second` is one or more, so neither division refuses.
    let whole = duration.checked_div(per_second).unwrap_or(0);
    let left = duration.checked_rem(per_second).unwrap_or(0);
    let scale = NANOS_PER_SECOND
        .unsigned_abs()
        .checked_div(per_second)
        .unwrap_or(0);
    // What is left of a second, in nanoseconds: below a second, so it is an `i64`.
    let part = left.wrapping_mul(scale);
    let mut secs = reading.0.saturating_add_unsigned(whole);
    // The reading's nanoseconds and `part` are each below a second, so their sum fits, and one
    // carry brings it back below a second.
    let mut nanos = reading.1.wrapping_add(part as i64);
    if nanos >= NANOS_PER_SECOND {
        secs = secs.saturating_add(1);
        nanos = nanos.wrapping_sub(NANOS_PER_SECOND);
    }
    (secs, nanos)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: i64 = 1_000_000_000;
    const US: i64 = 1_000_000;

    #[test]
    fn a_timespec_difference_is_read_in_each_unit() {
        let then = (10, 250_000_000);
        let now = (11, 750_000_000);
        assert_eq!(elapsed(now, then, NS, Unit::Micro), 1_500_000);
        assert_eq!(elapsed(now, then, NS, Unit::Milli), 1_500);
        assert_eq!(elapsed(now, then, NS, Unit::Second), 1);
    }

    #[test]
    fn the_sub_second_part_borrows_from_the_seconds() {
        assert_eq!(
            elapsed((2, 100_000_000), (1, 900_000_000), NS, Unit::Milli),
            200
        );
        assert_eq!(
            elapsed((2, 100_000), (1, 900_000), US, Unit::Micro),
            200_000
        );
    }

    #[test]
    fn a_reading_before_its_epoch_is_negative_and_clamps_to_none() {
        let back = elapsed((5, 0), (6, 0), NS, Unit::Milli);
        assert_eq!(back, -1_000);
        assert_eq!(clamped(back), 0);
        assert_eq!(clamped(1_234), 1_234);
    }

    #[test]
    fn a_difference_past_sixty_four_bits_saturates() {
        assert_eq!(elapsed((i64::MAX, 0), (0, 0), NS, Unit::Micro), i64::MAX);
    }

    #[test]
    fn a_timeval_is_read_in_microseconds() {
        assert_eq!(elapsed((10, 500_000), (9, 0), US, Unit::Milli), 1_500);
        assert_eq!(elapsed((10, 500_000), (9, 0), US, Unit::Micro), 1_500_000);
        assert_eq!(elapsed((10, 500_000), (9, 0), US, Unit::Second), 1);
    }

    #[test]
    fn advancing_carries_one_second_out_of_the_nanoseconds() {
        assert_eq!(
            advance((1, 999_000_000), Unit::Milli, 2),
            (2, 1_000_000),
            "999 ms and 2 ms carry into the next second"
        );
        assert_eq!(advance((0, 0), Unit::Milli, 1_500), (1, 500_000_000));
        assert_eq!(advance((0, 0), Unit::Micro, 2_000_001), (2, 1_000));
        assert_eq!(advance((5, 7), Unit::Second, 3), (8, 7));
    }
}
