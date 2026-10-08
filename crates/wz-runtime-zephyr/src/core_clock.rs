// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Does the core run at the clock the image was built for?
//!
//! A Zephyr image is built for ONE core clock (`CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC`,
//! from the board's devicetree) and everything timed is derived from it: the
//! kernel's tick is that many cycles of the system timer, a busy wait is a count of
//! cycles, a baud rate is a divider of a peripheral clock. Nothing in the kernel
//! checks that the silicon agrees. On a CYT4BF the Cortex-M7 cores do not bring the
//! clock tree up (Zephyr's clock driver returns early there); the CM0+ core has to,
//! and when it did not, the first boot of the admin node ran its M7 at the 8 MHz
//! oscillator where 350 MHz was assumed. Every wait lasted about 44 times what it
//! was asked to, the MAC driver's waits with them, and the node printed nothing for
//! minutes: no error, because nothing measured.
//!
//! So the image measures. A board hook reads the core's clock from the chip's
//! registers (`wz_core_clock_hz`, see [`crate::glue::core_clock_hz`]); this module
//! is the comparison and the words, with no kernel call, so they are tested on a
//! host.

use alloc::format;
use alloc::string::String;

/// How far the core clock may be from the one the image assumes, in parts per
/// thousand of the assumed clock, in either direction.
///
/// The reading is arithmetic on register values (a PLL's multiplier and dividers),
/// so it can differ from the assumed clock by the rounding of those dividers and
/// not by much more. 2 percent is wide enough for that and narrow enough to catch
/// every way a clock tree is actually wrong: a tree never brought up reads tens of
/// times too slow, and the smallest step of a wrong divider is a factor of two.
/// A core that is 2 percent off times nothing this image does by more than 2
/// percent, which is below the margin of every bound it keeps.
pub const TOLERANCE_PERMILLE: u32 = 20;

/// What a reading of the core clock says about the image's assumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreClock {
    /// The board gave no reading (0 Hz): it cannot read its clock, or the reading
    /// could not be evaluated. No verdict.
    Unreadable,
    /// The core runs at the assumed clock, within [`TOLERANCE_PERMILLE`].
    AsAssumed,
    /// The core runs faster or slower than assumed by more than the tolerance.
    Differs,
}

/// Compare the core's measured clock with the one the image assumes.
///
/// `actual_hz` is what the board hook read, 0 when the board cannot know;
/// `assumed_hz` is `CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC`.
pub const fn judge_core_clock(actual_hz: u32, assumed_hz: u32) -> CoreClock {
    if actual_hz == 0 {
        return CoreClock::Unreadable;
    }
    let (actual, assumed) = (actual_hz as u64, assumed_hz as u64);
    let off = actual.abs_diff(assumed);
    // `off / assumed <= TOLERANCE / 1000`, without a division and in 64 bits so
    // that neither side can overflow for any pair of clocks.
    if off * 1000 <= assumed * TOLERANCE_PERMILLE as u64 {
        CoreClock::AsAssumed
    } else {
        CoreClock::Differs
    }
}

/// What the startup does about the reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreClockOutcome {
    /// Say nothing: the board cannot read its clock and never claimed to. This is
    /// every emulated board, whose console must not change.
    Silent,
    /// Say this line and carry on.
    Report(String),
    /// Say this line and stop: the node would run with a time base that is not the
    /// one its waits and timeouts were written against.
    Stop(String),
}

/// The startup's decision for a reading of `actual_hz` against `assumed_hz`.
///
/// `board_reads_clock` says that this board HAS a hook that reads the clock. For
/// such a board a reading of 0 is a clock tree the hook could not evaluate and is
/// reported, because that is exactly the state in which the node cannot tell
/// whether its waits are the length they claim; for a board without one it is the
/// ordinary answer and nothing is said.
pub fn assess_core_clock(
    actual_hz: u32,
    assumed_hz: u32,
    board_reads_clock: bool,
) -> CoreClockOutcome {
    match judge_core_clock(actual_hz, assumed_hz) {
        CoreClock::Unreadable if board_reads_clock => CoreClockOutcome::Report(format!(
            "wz: core clock unknown (the board's reading gave 0 Hz; the image assumes {assumed_hz} Hz)"
        )),
        CoreClock::Unreadable => CoreClockOutcome::Silent,
        CoreClock::AsAssumed => CoreClockOutcome::Report(format!(
            "wz: core clock {actual_hz} Hz (the image assumes {assumed_hz} Hz)"
        )),
        CoreClock::Differs => CoreClockOutcome::Stop(format!(
            "wz: FAIL - the core runs at {actual_hz} Hz, the image assumes {assumed_hz} Hz; \
             start a CM0+ image that configures the clock tree"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC` of the CYT4BF M7 board (devicetree
    /// `clock-frequency` of its CPU node).
    const ASSUMED: u32 = 350_000_000;
    /// The tolerance in hertz at that clock: 2 percent of 350 MHz.
    const TOLERANCE_HZ: u32 = 7_000_000;

    #[test]
    fn the_stated_tolerance_is_two_percent() {
        assert_eq!(TOLERANCE_PERMILLE, 20);
        assert_eq!(ASSUMED / 1000 * TOLERANCE_PERMILLE, TOLERANCE_HZ);
    }

    #[test]
    fn a_core_at_the_assumed_clock_or_just_off_it_is_as_assumed() {
        assert_eq!(judge_core_clock(ASSUMED, ASSUMED), CoreClock::AsAssumed);
        // What the kit measured once the tree was up: 349.5 MHz, a 0.14 percent
        // difference that is the measurement's, not a fault.
        assert_eq!(judge_core_clock(349_500_000, ASSUMED), CoreClock::AsAssumed);
    }

    /// The incident: the tree never came up and the M7 ran at the 8 MHz oscillator.
    #[test]
    fn a_core_that_is_too_slow_differs() {
        assert_eq!(judge_core_clock(8_000_000, ASSUMED), CoreClock::Differs);
        assert_eq!(judge_core_clock(175_000_000, ASSUMED), CoreClock::Differs);
        assert_eq!(judge_core_clock(1, ASSUMED), CoreClock::Differs);
    }

    #[test]
    fn a_core_that_is_too_fast_differs() {
        assert_eq!(judge_core_clock(400_000_000, ASSUMED), CoreClock::Differs);
        assert_eq!(judge_core_clock(700_000_000, ASSUMED), CoreClock::Differs);
        assert_eq!(judge_core_clock(u32::MAX, ASSUMED), CoreClock::Differs);
    }

    /// Both edges are inclusive and the next hertz past either is not: the
    /// tolerance is applied in both directions and is exactly what is stated.
    #[test]
    fn the_tolerance_edges_are_inclusive_and_symmetric() {
        assert_eq!(
            judge_core_clock(ASSUMED - TOLERANCE_HZ, ASSUMED),
            CoreClock::AsAssumed,
            "the slow edge"
        );
        assert_eq!(
            judge_core_clock(ASSUMED - TOLERANCE_HZ - 1, ASSUMED),
            CoreClock::Differs,
            "one hertz slower than the slow edge"
        );
        assert_eq!(
            judge_core_clock(ASSUMED + TOLERANCE_HZ, ASSUMED),
            CoreClock::AsAssumed,
            "the fast edge"
        );
        assert_eq!(
            judge_core_clock(ASSUMED + TOLERANCE_HZ + 1, ASSUMED),
            CoreClock::Differs,
            "one hertz faster than the fast edge"
        );
    }

    /// The tolerance is a fraction of the ASSUMED clock, so it scales: the QEMU
    /// boards assume 25 MHz and the same fraction is 500 kHz there.
    #[test]
    fn the_tolerance_scales_with_the_assumed_clock() {
        assert_eq!(
            judge_core_clock(25_500_000, 25_000_000),
            CoreClock::AsAssumed
        );
        assert_eq!(judge_core_clock(25_500_001, 25_000_000), CoreClock::Differs);
        assert_eq!(
            judge_core_clock(24_500_000, 25_000_000),
            CoreClock::AsAssumed
        );
        assert_eq!(judge_core_clock(24_499_999, 25_000_000), CoreClock::Differs);
    }

    #[test]
    fn a_reading_of_zero_is_no_verdict_and_an_assumption_of_zero_is_not_matched() {
        assert_eq!(judge_core_clock(0, ASSUMED), CoreClock::Unreadable);
        assert_eq!(judge_core_clock(0, 0), CoreClock::Unreadable);
        assert_eq!(
            judge_core_clock(1, 0),
            CoreClock::Differs,
            "an image with no assumed clock matches no reading"
        );
    }

    #[test]
    fn the_comparison_cannot_overflow() {
        assert_eq!(judge_core_clock(u32::MAX, u32::MAX), CoreClock::AsAssumed);
        assert_eq!(judge_core_clock(u32::MAX, 1), CoreClock::Differs);
        assert_eq!(judge_core_clock(1, u32::MAX), CoreClock::Differs);
    }

    #[test]
    fn a_mismatch_stops_the_startup_with_the_one_line_a_lab_reads() {
        assert_eq!(
            assess_core_clock(8_000_000, ASSUMED, true),
            CoreClockOutcome::Stop(String::from(
                "wz: FAIL - the core runs at 8000000 Hz, the image assumes 350000000 Hz; \
                 start a CM0+ image that configures the clock tree"
            ))
        );
        // Too fast stops just the same, and a board without a hook that
        // nonetheless got a reading is held to it as well.
        assert!(matches!(
            assess_core_clock(700_000_000, ASSUMED, false),
            CoreClockOutcome::Stop(_)
        ));
    }

    #[test]
    fn a_match_reports_what_the_clock_was_and_carries_on() {
        assert_eq!(
            assess_core_clock(349_500_000, ASSUMED, true),
            CoreClockOutcome::Report(String::from(
                "wz: core clock 349500000 Hz (the image assumes 350000000 Hz)"
            ))
        );
    }

    /// An emulated board has no hook: no line, and certainly no stop, so its
    /// console is the one it had before the check existed.
    #[test]
    fn a_board_that_cannot_read_its_clock_says_nothing() {
        assert_eq!(
            assess_core_clock(0, 25_000_000, false),
            CoreClockOutcome::Silent
        );
    }

    /// A board WITH a hook that got nothing is not silent: that is the state in
    /// which nobody knows the node's time base, and it does not stop the node
    /// either, since an unevaluable tree is not a measured mismatch.
    #[test]
    fn a_board_with_a_hook_that_got_nothing_says_so_and_carries_on() {
        assert_eq!(
            assess_core_clock(0, ASSUMED, true),
            CoreClockOutcome::Report(String::from(
                "wz: core clock unknown (the board's reading gave 0 Hz; \
                 the image assumes 350000000 Hz)"
            ))
        );
    }
}
