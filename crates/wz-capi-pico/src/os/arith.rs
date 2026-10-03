// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The pure arithmetic of the Windows host layer: pico's `system/windows/system.c`
//! rules over the integers the Win32 calls return, with no Win32 in sight.
//!
//! zenoh-pico's results here are `unsigned long`, which is 32 bits on Windows (LLP64),
//! so every result in this file is a `u32` and the Windows backend returns it as the
//! `c_ulong` it is. Keeping the rules in a file a Linux build compiles and tests is
//! the point: a rule written from the C source and checked only on a Windows runner
//! would be checked once, at the end.

use super::Unit;

/// 100 ns `FILETIME` ticks between 1601-01-01 and 1970-01-01.
const FILETIME_UNIX_EPOCH: i64 = 116_444_736_000_000_000;
const TICKS_PER_SECOND: i64 = 10_000_000;
const TICKS_PER_MILLI: i64 = 10_000;

/// The longest finite block `SleepConditionVariableSRW` is asked for. `INFINITE` is
/// `u32::MAX`, so a deadline about 49.7 days away would otherwise read as "never time
/// out": pico's `(DWORD)remaining` has that edge, and wz clamps just below it.
pub const MAX_FINITE_WAIT_MS: u32 = u32::MAX - 1;

/// How many of `unit` make a second.
pub fn units_per_second(unit: Unit) -> f64 {
    match unit {
        Unit::Micro => 1_000_000.0,
        Unit::Milli => 1_000.0,
        Unit::Second => 1.0,
    }
}

/// Elapsed `unit`s between two performance-counter readings, in pico's own
/// arithmetic: a double product and quotient, the whole part, and zero when the
/// interval is not positive (`system.c:268-304`). A zero `frequency` is "hardware
/// without a counter", which pico reports as 0.
pub fn ticks_elapsed(instant: i64, epoch: i64, frequency: i64, unit: Unit) -> u32 {
    if frequency == 0 {
        return 0;
    }
    let mut elapsed = instant.wrapping_sub(epoch) as f64 * units_per_second(unit);
    elapsed /= frequency as f64;
    if elapsed > 0.0 {
        // A float-to-int `as` saturates, where the C cast is undefined above range.
        elapsed as u32
    } else {
        0
    }
}

/// The counter ticks `duration` `unit`s make (`system.c:324-358`): a double product
/// over the units per second, truncated.
pub fn ticks_advance(duration: u32, frequency: i64, unit: Unit) -> i64 {
    (f64::from(duration) * frequency as f64 / units_per_second(unit)) as i64
}

/// The milliseconds a wait until the counter reading `deadline` should block for,
/// given the reading `now` (`system.c:210-221`): the interval in milliseconds, zero
/// when `deadline` is not in the future, and never `INFINITE`.
pub fn remaining_millis(deadline: i64, now: i64, frequency: i64) -> u32 {
    let remaining = deadline.wrapping_sub(now) as f64 / frequency as f64 * 1000.0;
    if remaining > 0.0 {
        (remaining as u32).min(MAX_FINITE_WAIT_MS)
    } else {
        0
    }
}

/// The Unix seconds and the milliseconds of a `FILETIME`, which is what the CRT's
/// `ftime` reports as `time` and `millitm`.
pub fn unix_time_of_filetime(filetime: u64) -> (i64, u16) {
    let since_epoch = (filetime as i64).wrapping_sub(FILETIME_UNIX_EPOCH);
    (
        since_epoch.div_euclid(TICKS_PER_SECOND),
        (since_epoch.rem_euclid(TICKS_PER_SECOND) / TICKS_PER_MILLI) as u16,
    )
}

/// The `FILETIME` of whole Unix seconds, or `None` before 1601 or past what 64 bits
/// hold.
pub fn filetime_of_unix_secs(secs: i64) -> Option<u64> {
    let ticks = secs
        .checked_mul(TICKS_PER_SECOND)?
        .checked_add(FILETIME_UNIX_EPOCH)?;
    u64::try_from(ticks).ok()
}

/// Wall time as pico's `z_time_t` carries it for these rules: whole Unix seconds and
/// the milliseconds within the second.
pub type Stamp = (i64, u16);

/// Milliseconds elapsed on the wall clock (`system.c:377-383`), in the arithmetic of a
/// 32-bit `unsigned long`: the seconds difference is truncated, scaled by 1000 and
/// added to the signed millisecond difference, all wrapping. No clamp, so a stamp in
/// the future wraps to a huge value, which is upstream's behaviour and not a bug wz
/// repairs.
pub fn wall_elapsed_ms(now: Stamp, then: Stamp) -> u32 {
    let secs = now.0.wrapping_sub(then.0) as u32;
    let millis = i32::from(now.1) - i32::from(then.1);
    secs.wrapping_mul(1000).wrapping_add(millis as u32)
}

/// Microseconds elapsed on the wall clock: pico's is the milliseconds times 1000,
/// wrapping (`system.c:375`).
pub fn wall_elapsed_us(now: Stamp, then: Stamp) -> u32 {
    wall_elapsed_ms(now, then).wrapping_mul(1000)
}

/// Whole seconds elapsed on the wall clock (`system.c:385-391`).
pub fn wall_elapsed_s(now: Stamp, then: Stamp) -> u32 {
    now.0.wrapping_sub(then.0) as u32
}

/// How many bytes `%Y-%m-%dT%H:%M:%SZ` takes, terminator included: twenty characters
/// and the NUL.
pub const ISO_LOCAL_BYTES: usize = 21;

/// What `%Y-%m-%dT%H:%M:%SZ` renders, NUL-terminated. `None` when a field cannot be
/// written in the width the format gives it, which a real `SYSTEMTIME` never produces
/// below the year 10000.
pub fn format_iso(
    year: u16,
    month: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
) -> Option<[u8; ISO_LOCAL_BYTES]> {
    if year > 9999 || month > 99 || day > 99 || hour > 99 || minute > 99 || second > 99 {
        return None;
    }
    let two = |v: u16| [b'0' + (v / 10) as u8, b'0' + (v % 10) as u8];
    let (yh, yl) = (two(year / 100), two(year % 100));
    let (mo, d, h, mi, s) = (two(month), two(day), two(hour), two(minute), two(second));
    Some([
        yh[0], yh[1], yl[0], yl[1], b'-', mo[0], mo[1], b'-', d[0], d[1], b'T', h[0], h[1], b':',
        mi[0], mi[1], b':', s[0], s[1], b'Z', 0,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 10 MHz counter, which is what `QueryPerformanceFrequency` reports on current
    /// Windows hosts.
    const F: i64 = 10_000_000;

    #[test]
    fn elapsed_ticks_are_picos_floor_and_clamp() {
        // 1.5 s of ticks.
        assert_eq!(ticks_elapsed(15_000_000, 0, F, Unit::Milli), 1_500);
        assert_eq!(ticks_elapsed(15_000_000, 0, F, Unit::Micro), 1_500_000);
        assert_eq!(
            ticks_elapsed(15_000_000, 0, F, Unit::Second),
            1,
            "1.5 s truncates to 1, it does not round to 2"
        );
        // Backwards is clamped, not wrapped.
        assert_eq!(ticks_elapsed(0, 15_000_000, F, Unit::Milli), 0);
        assert_eq!(ticks_elapsed(7, 7, F, Unit::Micro), 0);
        // No counter: pico reports 0.
        assert_eq!(ticks_elapsed(15_000_000, 0, 0, Unit::Milli), 0);
        // Beyond what an `unsigned long` holds saturates instead of being undefined.
        assert_eq!(ticks_elapsed(i64::MAX, 0, F, Unit::Micro), u32::MAX);
    }

    #[test]
    fn advancing_by_a_duration_is_the_ticks_it_makes() {
        assert_eq!(ticks_advance(1_500, F, Unit::Milli), 15_000_000);
        assert_eq!(ticks_advance(2, F, Unit::Second), 20_000_000);
        assert_eq!(ticks_advance(2_500, F, Unit::Micro), 25_000);
        // A counter that is not a round number of ticks per microsecond truncates.
        assert_eq!(ticks_advance(3, 3_000_000, Unit::Second), 9_000_000);
        assert_eq!(ticks_advance(1, 3_000_000, Unit::Micro), 3);
        assert_eq!(ticks_advance(1, 1, Unit::Micro), 0);
    }

    #[test]
    fn a_condvar_deadline_becomes_a_finite_block_in_milliseconds() {
        assert_eq!(remaining_millis(1_500_000, 0, F), 150);
        // Not in the future: do not block.
        assert_eq!(remaining_millis(100, 100, F), 0);
        assert_eq!(remaining_millis(0, 1_500_000, F), 0);
        // Far enough away that the milliseconds would reach INFINITE: clamped below it.
        assert_eq!(remaining_millis(i64::MAX, 0, F), MAX_FINITE_WAIT_MS);
        assert_ne!(MAX_FINITE_WAIT_MS, u32::MAX, "INFINITE is u32::MAX");
    }

    #[test]
    fn a_filetime_is_the_unix_time_ftime_reports() {
        assert_eq!(unix_time_of_filetime(FILETIME_UNIX_EPOCH as u64), (0, 0));
        // 1.5 s after the epoch.
        let t = FILETIME_UNIX_EPOCH as u64 + 15_000_000;
        assert_eq!(unix_time_of_filetime(t), (1, 500));
        // The milliseconds drop the sub-millisecond ticks.
        assert_eq!(unix_time_of_filetime(t + 9_999), (1, 500));
        // Before 1970 the seconds are negative and the milliseconds still positive.
        assert_eq!(
            unix_time_of_filetime(FILETIME_UNIX_EPOCH as u64 - 5_000_000),
            (-1, 500)
        );
    }

    #[test]
    fn unix_seconds_round_trip_through_a_filetime() {
        for secs in [0_i64, 1, 1_790_000_000, -86_400] {
            let ft = filetime_of_unix_secs(secs).expect("representable");
            assert_eq!(unix_time_of_filetime(ft), (secs, 0));
        }
        assert_eq!(filetime_of_unix_secs(-12_000_000_000), None, "before 1601");
        assert_eq!(filetime_of_unix_secs(i64::MAX), None, "overflow");
    }

    #[test]
    fn wall_elapsed_follows_the_unsigned_long_arithmetic() {
        // 2 s and a negative millisecond difference: 1.35 s.
        let (now, then) = ((100, 250), (98, 900));
        assert_eq!(wall_elapsed_ms(now, then), 1_350);
        assert_eq!(wall_elapsed_us(now, then), 1_350_000);
        assert_eq!(wall_elapsed_s(now, then), 2, "whole seconds of the stamps");
        // A stamp in the future WRAPS rather than clamping to zero.
        let future = (now.0 + 3_600, now.1);
        assert!(wall_elapsed_s(now, future) > u32::MAX / 2);
        assert!(wall_elapsed_ms(now, future) > u32::MAX / 2);
    }

    #[test]
    fn the_local_time_renders_as_pico_formats_it() {
        let out = format_iso(2026, 10, 3, 9, 5, 7).expect("in range");
        assert_eq!(&out[..20], b"2026-10-03T09:05:07Z");
        assert_eq!(out[20], 0, "NUL-terminated");
        assert_eq!(out.len(), ISO_LOCAL_BYTES);
        assert_eq!(format_iso(10_000, 1, 1, 0, 0, 0), None);
        assert_eq!(format_iso(2026, 100, 1, 0, 0, 0), None);
    }
}
