// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The receiver's judgment of a protected frame: CRC, counter and timeout.
//!
//! `e2e_frame::open` says whether the CRC matched and what the counter field
//! holds. What a receiver makes of a SEQUENCE of frames needs state: the
//! last counter it accepted and when it last accepted one. That state is this
//! type, and it is pure: no clock, no I/O, no allocation. The caller passes the
//! instant of every reception, in milliseconds on a clock of its own, which is
//! also what makes the rules testable without waiting.
//!
//! # Scope of one judge
//!
//! One [`Judge`] is one STREAM: the counter of a sender is only comparable with
//! that sender's earlier counters. What a stream is, for a given deployment (a
//! message, a keyed instance of it, a publisher slot), is the caller's to
//! decide, and the caller keeps one judge per stream. A capture pipeline that
//! owns that keying comes later and is deliberately not behind this type.
//!
//! # The rules, in the order they apply to a reception
//!
//! 1. A frame whose CRC does not match is a CRC error. It is NOT judged for its
//!    counter, and it changes no state: neither the counter baseline nor the
//!    instant of the last valid reception.
//! 2. Otherwise, if no counter has been accepted yet, this one becomes the
//!    baseline with no error, whatever its value.
//! 3. Otherwise the step is `(counter - baseline) mod 2^width`:
//!    * 0 is a REPETITION: counter error, baseline and instant unchanged;
//!    * 1 to `max_gap` is fine, skipped counters included: baseline and
//!      instant move;
//!    * above `max_gap` is OUT OF RANGE: counter error, but the baseline and
//!      the instant move to this frame, so one lost run does not condemn every
//!      frame after it.
//! 4. The timeout is judged on every reception, and on a [`Judge::poll`] with
//!    no reception: it is an error when an earlier valid reception exists and
//!    `now - that instant > timeout_ms`.
//!
//! # Decisions not forced by the description of the rules
//!
//! * On a reception the timeout is judged against the instant of the PREVIOUS
//!   valid reception, before this one moves it. Judged after the move, a frame
//!   could never arrive late, and the only timeouts left would be the ones
//!   found by a poll.
//! * A clock reading earlier than the last valid instant counts as no time
//!   having passed, never as a wrapped-around huge gap.
//! * The output is three booleans, as a consumer reports them, plus
//!   [`CounterReason`], which tells a repetition from an out-of-range step for
//!   analysis. A consumer that reports only the booleans loses nothing.

use crate::e2e_crc::width_mask;

/// Why the counter was judged an error, for analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterReason {
    /// The counter was not judged an error, or was not judged at all.
    None,
    /// The step was zero: the same counter again.
    Repeat,
    /// The step was above the allowed gap.
    OutOfRange,
}

/// The verdict on one reception, or on one poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Judgment {
    /// The CRC did not match.
    pub crc_error: bool,
    /// The counter was a repetition or out of range.
    pub counter_error: bool,
    /// The silence since the last valid reception exceeded the limit.
    pub timeout_error: bool,
    /// What `counter_error` was; [`CounterReason::None`] whenever it is false.
    pub counter_reason: CounterReason,
}

/// What a judge is configured with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JudgeConfig {
    /// Width of the counter field, 1 to 8 bytes.
    pub counter_bytes: usize,
    /// The largest step that is not an error.
    pub max_gap: u64,
    /// The longest silence that is not an error.
    pub timeout_ms: u64,
}

/// A counter wider than the field it is said to come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterWidthError {
    /// The value given.
    pub counter: u64,
    /// The width the judge was configured with.
    pub counter_bytes: usize,
}

impl core::fmt::Display for CounterWidthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "the counter {} does not fit the judge's {}-byte counter",
            self.counter, self.counter_bytes
        )
    }
}

/// The state of one stream.
#[derive(Debug, Clone)]
pub struct Judge {
    config: JudgeConfig,
    baseline: Option<u64>,
    last_valid_ms: Option<u64>,
}

impl Judge {
    /// A judge that has seen nothing.
    pub fn new(config: JudgeConfig) -> Self {
        Self {
            config,
            baseline: None,
            last_valid_ms: None,
        }
    }

    /// The last counter accepted; `None` before the first.
    pub fn baseline(&self) -> Option<u64> {
        self.baseline
    }

    /// The instant of the last valid reception; `None` before the first.
    pub fn last_valid_ms(&self) -> Option<u64> {
        self.last_valid_ms
    }

    fn counter_mask(&self) -> u64 {
        width_mask((self.config.counter_bytes * 8) as u8)
    }

    fn timed_out(&self, now_ms: u64) -> bool {
        self.last_valid_ms
            .is_some_and(|last| now_ms.saturating_sub(last) > self.config.timeout_ms)
    }

    /// Judge one received frame: whether its CRC matched, the counter it
    /// carried, and the instant it arrived.
    ///
    /// Fails only when `counter` cannot be a value of the configured width,
    /// which means the caller mixed a frame of one profile with the judge of
    /// another.
    pub fn receive(
        &mut self,
        crc_ok: bool,
        counter: u64,
        now_ms: u64,
    ) -> Result<Judgment, CounterWidthError> {
        let mask = self.counter_mask();
        if counter & !mask != 0 {
            return Err(CounterWidthError {
                counter,
                counter_bytes: self.config.counter_bytes,
            });
        }
        // Against the previous valid instant, before this frame can move it.
        let timeout_error = self.timed_out(now_ms);

        if !crc_ok {
            return Ok(Judgment {
                crc_error: true,
                counter_error: false,
                timeout_error,
                counter_reason: CounterReason::None,
            });
        }

        let reason = match self.baseline {
            None => CounterReason::None,
            Some(baseline) => {
                let step = counter.wrapping_sub(baseline) & mask;
                if step == 0 {
                    CounterReason::Repeat
                } else if step <= self.config.max_gap {
                    CounterReason::None
                } else {
                    CounterReason::OutOfRange
                }
            }
        };
        if reason != CounterReason::Repeat {
            self.baseline = Some(counter);
            self.last_valid_ms = Some(now_ms);
        }
        Ok(Judgment {
            crc_error: false,
            counter_error: reason != CounterReason::None,
            timeout_error,
            counter_reason: reason,
        })
    }

    /// Judge the timeout alone, at an instant when nothing was received. It
    /// changes no state.
    pub fn poll(&self, now_ms: u64) -> Judgment {
        Judgment {
            crc_error: false,
            counter_error: false,
            timeout_error: self.timed_out(now_ms),
            counter_reason: CounterReason::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GAP: u64 = 10;
    const LIMIT: u64 = 1000;

    fn judge(counter_bytes: usize) -> Judge {
        Judge::new(JudgeConfig {
            counter_bytes,
            max_gap: GAP,
            timeout_ms: LIMIT,
        })
    }

    fn fine() -> Judgment {
        Judgment {
            crc_error: false,
            counter_error: false,
            timeout_error: false,
            counter_reason: CounterReason::None,
        }
    }

    fn rx(j: &mut Judge, crc_ok: bool, counter: u64, now: u64) -> Judgment {
        j.receive(crc_ok, counter, now).expect("the counter fits")
    }

    #[test]
    fn the_first_reception_sets_the_baseline_whatever_its_value() {
        for first in [0u64, 1, 0x1234, 0xFFFF] {
            let mut j = judge(2);
            assert_eq!(rx(&mut j, true, first, 5), fine(), "first = {first}");
            assert_eq!(j.baseline(), Some(first));
            assert_eq!(j.last_valid_ms(), Some(5));
        }
    }

    #[test]
    fn a_crc_error_is_not_judged_for_its_counter_and_changes_no_state() {
        let mut j = judge(2);
        rx(&mut j, true, 100, 10);
        // The counter is a repetition AND out of range in turn; neither is
        // reported, because a frame with a wrong CRC has no trustworthy counter.
        for counter in [100u64, 5000] {
            let v = rx(&mut j, false, counter, 20);
            assert_eq!(
                v,
                Judgment {
                    crc_error: true,
                    ..fine()
                }
            );
            assert_eq!(j.baseline(), Some(100), "the baseline stays");
            assert_eq!(j.last_valid_ms(), Some(10), "the valid instant stays");
        }
        // And the baseline it left is the one the next valid frame is judged by.
        assert_eq!(rx(&mut j, true, 101, 30), fine());
    }

    #[test]
    fn a_crc_error_before_any_valid_frame_leaves_the_stream_unstarted() {
        let mut j = judge(2);
        assert!(rx(&mut j, false, 7, 1).crc_error);
        assert_eq!((j.baseline(), j.last_valid_ms()), (None, None));
        // So the first VALID frame is still a first reception.
        assert_eq!(rx(&mut j, true, 900, 2), fine());
    }

    #[test]
    fn a_repetition_is_an_error_and_keeps_the_baseline_and_the_instant() {
        let mut j = judge(2);
        rx(&mut j, true, 50, 100);
        let v = rx(&mut j, true, 50, 200);
        assert_eq!(
            v,
            Judgment {
                counter_error: true,
                counter_reason: CounterReason::Repeat,
                ..fine()
            }
        );
        assert_eq!(j.baseline(), Some(50));
        assert_eq!(
            j.last_valid_ms(),
            Some(100),
            "a repetition is not a valid reception"
        );
        // The baseline survived, so the next step is measured from 50.
        assert_eq!(rx(&mut j, true, 51, 300), fine());
    }

    #[test]
    fn a_step_of_one_up_to_the_maximum_gap_is_fine_and_moves_the_baseline() {
        for step in 1..=GAP {
            let mut j = judge(2);
            rx(&mut j, true, 100, 0);
            assert_eq!(rx(&mut j, true, 100 + step, 10), fine(), "step {step}");
            assert_eq!(j.baseline(), Some(100 + step));
            assert_eq!(j.last_valid_ms(), Some(10));
        }
    }

    #[test]
    fn a_step_above_the_maximum_gap_is_out_of_range_and_moves_the_baseline() {
        let mut j = judge(2);
        rx(&mut j, true, 100, 0);
        let v = rx(&mut j, true, 100 + GAP + 1, 10);
        assert_eq!(
            v,
            Judgment {
                counter_error: true,
                counter_reason: CounterReason::OutOfRange,
                ..fine()
            }
        );
        assert_eq!(
            j.baseline(),
            Some(100 + GAP + 1),
            "the baseline follows the new value"
        );
        assert_eq!(
            j.last_valid_ms(),
            Some(10),
            "an out-of-range frame is a valid reception"
        );
        // Because it followed, the frame after it is judged from there.
        assert_eq!(rx(&mut j, true, 100 + GAP + 2, 20), fine());
    }

    #[test]
    fn the_step_wraps_at_the_width_of_the_counter_field() {
        // 0xFFFF then 0 is a step of one in a 2-byte counter.
        let mut j = judge(2);
        rx(&mut j, true, 0xFFFF, 0);
        assert_eq!(rx(&mut j, true, 0, 1), fine());
        // The largest wrapped step still allowed.
        let mut j = judge(2);
        rx(&mut j, true, 0xFFFE, 0);
        assert_eq!(rx(&mut j, true, (0xFFFE + GAP) & 0xFFFF, 1), fine());
        // One past it is out of range, across the wrap too.
        let mut j = judge(2);
        rx(&mut j, true, 0xFFFE, 0);
        let v = rx(&mut j, true, (0xFFFE + GAP + 1) & 0xFFFF, 1);
        assert_eq!(v.counter_reason, CounterReason::OutOfRange);
        // A 1-byte and an 8-byte counter wrap at their own widths.
        let mut j = judge(1);
        rx(&mut j, true, 0xFF, 0);
        assert_eq!(rx(&mut j, true, 0, 1), fine());
        let mut j = judge(8);
        rx(&mut j, true, u64::MAX, 0);
        assert_eq!(rx(&mut j, true, 0, 1), fine());
    }

    #[test]
    fn going_backwards_is_out_of_range_not_a_small_step() {
        let mut j = judge(2);
        rx(&mut j, true, 100, 0);
        let v = rx(&mut j, true, 99, 1);
        assert_eq!(v.counter_reason, CounterReason::OutOfRange);
    }

    #[test]
    fn a_counter_wider_than_the_field_is_refused_not_truncated() {
        let mut j = judge(2);
        assert_eq!(
            j.receive(true, 0x1_0000, 0),
            Err(CounterWidthError {
                counter: 0x1_0000,
                counter_bytes: 2
            })
        );
        assert_eq!(j.baseline(), None, "a refused call leaves no trace");
        assert!(
            j.receive(true, 0xFFFF, 0).is_ok(),
            "the control is accepted"
        );
    }

    #[test]
    fn no_timeout_before_a_valid_reception_exists() {
        let mut j = judge(2);
        // Any distance from zero, with no history, is not a timeout.
        assert!(!j.poll(u64::MAX).timeout_error);
        assert!(!rx(&mut j, true, 1, u64::MAX).timeout_error);
        // A CRC error has not made a history either.
        let mut j = judge(2);
        rx(&mut j, false, 1, 0);
        assert!(!j.poll(10 * LIMIT).timeout_error);
    }

    #[test]
    fn the_timeout_fires_only_when_the_silence_exceeds_the_limit() {
        let mut j = judge(2);
        rx(&mut j, true, 1, 5000);
        assert!(!j.poll(5000 + LIMIT - 1).timeout_error);
        assert!(
            !j.poll(5000 + LIMIT).timeout_error,
            "equal to the limit is not over it"
        );
        assert!(j.poll(5000 + LIMIT + 1).timeout_error);
    }

    #[test]
    fn a_poll_judges_the_timeout_without_a_reception_and_changes_nothing() {
        let mut j = judge(2);
        rx(&mut j, true, 1, 0);
        let v = j.poll(LIMIT + 1);
        assert_eq!(
            v,
            Judgment {
                timeout_error: true,
                ..fine()
            }
        );
        assert_eq!((j.baseline(), j.last_valid_ms()), (Some(1), Some(0)));
    }

    #[test]
    fn a_late_valid_frame_is_a_timeout_and_then_restarts_the_clock() {
        let mut j = judge(2);
        rx(&mut j, true, 1, 0);
        // Judged against the previous valid instant, then moved to this one.
        let v = rx(&mut j, true, 2, LIMIT + 1);
        assert_eq!(
            v,
            Judgment {
                timeout_error: true,
                ..fine()
            }
        );
        assert_eq!(j.last_valid_ms(), Some(LIMIT + 1));
        assert!(!rx(&mut j, true, 3, LIMIT + 2).timeout_error);
    }

    #[test]
    fn repetitions_and_crc_errors_do_not_move_the_instant_so_silence_keeps_growing() {
        let mut j = judge(2);
        rx(&mut j, true, 1, 0);
        // Frames keep arriving, none of them valid progress.
        rx(&mut j, true, 1, 400);
        rx(&mut j, false, 2, 800);
        let v = rx(&mut j, true, 1, LIMIT + 1);
        assert!(v.timeout_error, "the last valid reception was at 0");
        assert_eq!(v.counter_reason, CounterReason::Repeat);
        let v = rx(&mut j, false, 2, LIMIT + 2);
        assert!(v.crc_error && v.timeout_error);
        assert_eq!(j.last_valid_ms(), Some(0));
    }

    #[test]
    fn a_clock_that_goes_backwards_counts_as_no_time_passed() {
        let mut j = judge(2);
        rx(&mut j, true, 1, 10_000);
        assert!(!j.poll(0).timeout_error);
        assert!(!rx(&mut j, true, 2, 5).timeout_error);
    }

    #[test]
    fn the_gap_is_inclusive_for_every_counter_width() {
        for bytes in 1..=8usize {
            let mut j = Judge::new(JudgeConfig {
                counter_bytes: bytes,
                max_gap: 3,
                timeout_ms: LIMIT,
            });
            let top = if bytes == 8 {
                u64::MAX
            } else {
                (1u64 << (8 * bytes)) - 1
            };
            rx(&mut j, true, top - 1, 0);
            // top - 1 + 3 wraps past the top of the field.
            assert_eq!(
                rx(&mut j, true, (top - 1).wrapping_add(3) & top, 1),
                fine(),
                "{bytes} bytes: a step of 3 across the wrap"
            );
            let step4 = j.baseline().expect("set").wrapping_add(4) & top;
            assert_eq!(
                rx(&mut j, true, step4, 2).counter_reason,
                CounterReason::OutOfRange,
                "{bytes} bytes: a step of 4"
            );
        }
    }
}
