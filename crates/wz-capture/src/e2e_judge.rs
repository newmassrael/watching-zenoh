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
//! # The rules, in the order they apply to one reception
//!
//! The order is the specification's order of steps: the CRC, then the counter
//! with the state it moves, then the timeout.
//!
//! 1. **CRC.** A frame whose CRC does not match is a CRC error. It is NOT
//!    judged for its counter, and it changes no state: neither the counter
//!    baseline nor the instant of the last valid reception.
//! 2. **Counter and state**, for a frame whose CRC is fine. If no counter has
//!    been accepted yet, this one becomes the baseline with no error, whatever
//!    its value. Otherwise the step is `(counter - baseline) mod 2^width`:
//!    * 0 is a REPETITION: counter error, baseline and instant unchanged;
//!    * 1 to `max_gap` is fine, skipped counters included: baseline and
//!      instant move to this frame;
//!    * above `max_gap` is OUT OF RANGE: counter error, but the baseline and
//!      the instant move to this frame, so one lost run does not condemn every
//!      frame after it.
//! 3. **Timeout**, judged LAST, against the last-valid instant as it stands
//!    after step 2: an error when that instant exists and
//!    `now - instant > timeout_ms`. Two things follow, and both are contract:
//!    * **A valid reception clears its own timeout.** A valid frame, fine or
//!      out of range, has just moved the instant to now, so its timeout is
//!      false however long the silence before it was. That silence was a
//!      timeout while it lasted, and [`Judge::poll`] saw it; the frame that
//!      ends it is not itself late.
//!    * **A CRC error and a repetition move nothing**, so their timeout is
//!      judged against the PREVIOUS valid instant: true when the silence
//!      exceeds the limit.
//!
//! [`Judge::poll`] judges step 3 alone, at an instant when nothing was
//! received, and changes no state.
//!
//! # Output
//!
//! The judgment is three booleans, as a consumer reports them, plus
//! [`CounterReason`], which tells a repetition from an out-of-range step for
//! analysis. A fourth field, [`Judgment::silence_ms`], is INFORMATION ONLY and
//! changes the meaning of none of the booleans: it is the silence before this
//! reception (or poll), in milliseconds, measured from the instant a timeout is
//! judged against while nothing has moved it, that is from the last valid
//! reception, or before any valid reception from the armed instant (see
//! below), to this reception's instant, and taken before this reception could
//! move anything. It is `None` only when neither a valid reception nor an armed
//! instant exists. It exists to explain the timeout boolean, and it is what lets
//! a consumer still show "this valid frame came after 1500 ms of silence" beside
//! a timeout that is false. A consumer that reports only the booleans loses
//! nothing else.
//!
//! # A stream that never received can time out
//!
//! A receiver that starts a stream's silence clock at stream start, after its
//! own start delay, can find the stream silent although nothing ever arrived.
//! [`Judge::arm`] is that act: it sets the instant the silence is measured from
//! WITHOUT creating a valid-reception history. The counter baseline stays unset
//! (the first reception still sets it without a counter error),
//! [`Judge::last_valid_ms`] stays `None`, and [`Judge::poll`] and every CRC
//! error before the first valid frame are judged against the armed instant. The
//! first valid reception replaces it, as it replaces any earlier instant. Arming
//! twice keeps the EARLIER instant: a second start event must not push the
//! deadline out. Arming a stream that already has a valid reception changes
//! nothing, because its own history is the reference. Without `arm`, a stream
//! that never received is never judged. The silence field is measured from the
//! armed instant while there is no valid reception, so a timeout that is true
//! beside it is never unexplained: a CRC error 2000 ms after `arm` reports a
//! timeout and a silence of 2000, and so does a poll. The first valid frame
//! reports the silence it ended, and from then on the history is the reference.
//!
//! # A clock that goes backwards counts as no time passed
//!
//! A reading earlier than the instant it is compared with counts as no silence,
//! never as a wrapped-around huge gap. This is a DELIBERATE difference from a
//! receiver on a fixed-width device clock, which subtracts as an unsigned
//! integer and so turns a backwards step into an enormous gap. That is an
//! artifact of a fixed-width clock; the clock here is a capture's timestamp,
//! which can step backwards when captures are merged, and a merge must not read
//! as a timeout.

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
    /// The silence exceeded the limit, judged after this reception's own
    /// state update (see the module doc): false for every valid reception.
    pub timeout_error: bool,
    /// What `counter_error` was; [`CounterReason::None`] whenever it is false.
    pub counter_reason: CounterReason,
    /// The silence before this reception or poll, in milliseconds, from the
    /// instant the timeout is judged against while nothing has moved it: the
    /// last valid reception, or before any valid reception the armed instant.
    /// Taken before this reception moved anything; `None` only when neither
    /// exists. INFORMATION ONLY: it explains the timeout boolean and changes
    /// the meaning of none of the booleans.
    pub silence_ms: Option<u64>,
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
    /// The instant [`Judge::arm`] set, kept only until the first valid
    /// reception replaces it.
    armed_ms: Option<u64>,
}

impl Judge {
    /// A judge that has seen nothing.
    pub fn new(config: JudgeConfig) -> Self {
        Self {
            config,
            baseline: None,
            last_valid_ms: None,
            armed_ms: None,
        }
    }

    /// Start the stream's silence clock at `now_ms`, without any reception.
    ///
    /// Afterwards [`Judge::poll`], and a CRC error that arrives before any
    /// valid frame, are judged against this instant, so a stream that never
    /// received can time out. It creates no valid-reception history: the
    /// counter baseline and [`Judge::last_valid_ms`] stay `None`, and the first
    /// valid reception still sets the baseline without a counter error and
    /// replaces this instant.
    ///
    /// Arming twice keeps the earlier instant, and arming a stream that
    /// already has a valid reception changes nothing.
    pub fn arm(&mut self, now_ms: u64) {
        if self.last_valid_ms.is_none() && self.armed_ms.is_none() {
            self.armed_ms = Some(now_ms);
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

    /// The instant [`Judge::arm`] set, while no valid reception has replaced
    /// it; `None` otherwise.
    pub fn armed_ms(&self) -> Option<u64> {
        self.armed_ms
    }

    fn counter_mask(&self) -> u64 {
        width_mask((self.config.counter_bytes * 8) as u8)
    }

    /// The silence at `now_ms`, in milliseconds: from the last valid
    /// reception, or before any valid reception from the armed instant; `None`
    /// when neither exists. One measurement serves the timeout and the
    /// information field, so a timeout is never reported beside a silence that
    /// does not explain it.
    fn silence(&self, now_ms: u64) -> Option<u64> {
        self.last_valid_ms
            .or(self.armed_ms)
            .map(|from| now_ms.saturating_sub(from))
    }

    /// Whether the silence at `now_ms` exceeds the limit.
    fn timed_out(&self, now_ms: u64) -> bool {
        self.silence(now_ms)
            .is_some_and(|silence| silence > self.config.timeout_ms)
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
        // Taken before this frame can move anything: information only.
        let silence_ms = self.silence(now_ms);

        if !crc_ok {
            // Nothing moved, so the silence is judged against the previous
            // valid instant (or the armed one).
            return Ok(Judgment {
                crc_error: true,
                counter_error: false,
                timeout_error: self.timed_out(now_ms),
                counter_reason: CounterReason::None,
                silence_ms,
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
            self.armed_ms = None;
        }
        // The timeout is judged LAST, against the instant as it now stands: a
        // valid frame has just moved it to now, a repetition has not.
        Ok(Judgment {
            crc_error: false,
            counter_error: reason != CounterReason::None,
            timeout_error: self.timed_out(now_ms),
            counter_reason: reason,
            silence_ms,
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
            silence_ms: self.silence(now_ms),
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
            silence_ms: None,
        }
    }

    /// One reception, the whole judgment.
    fn rx_full(j: &mut Judge, crc_ok: bool, counter: u64, now: u64) -> Judgment {
        j.receive(crc_ok, counter, now).expect("the counter fits")
    }

    /// One reception with the information field blanked, so the tests of the
    /// four verdicts compare against [`fine`] without restating the silence.
    fn rx(j: &mut Judge, crc_ok: bool, counter: u64, now: u64) -> Judgment {
        Judgment {
            silence_ms: None,
            ..rx_full(j, crc_ok, counter, now)
        }
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
                silence_ms: Some(LIMIT + 1),
                ..fine()
            }
        );
        assert_eq!((j.baseline(), j.last_valid_ms()), (Some(1), Some(0)));
    }

    #[test]
    fn a_valid_frame_after_a_long_silence_clears_its_own_timeout() {
        let mut j = judge(2);
        rx(&mut j, true, 1, 0);
        // The silence was a timeout while it lasted, and a poll sees it ...
        assert!(j.poll(1500).timeout_error);
        // ... and the frame that ends it is not itself late: the timeout is
        // judged after the frame has moved the instant to now.
        let v = rx_full(&mut j, true, 2, 1500);
        assert_eq!(
            v,
            Judgment {
                silence_ms: Some(1500),
                ..fine()
            }
        );
        assert_eq!(j.last_valid_ms(), Some(1500));
        assert!(!j.poll(1500 + LIMIT).timeout_error, "the clock restarted");
        assert!(j.poll(1500 + LIMIT + 1).timeout_error);
    }

    #[test]
    fn an_out_of_range_step_after_3000_ms_is_a_counter_error_and_no_timeout() {
        let mut j = judge(2);
        rx(&mut j, true, 100, 0);
        let v = rx_full(&mut j, true, 100 + GAP + 1, 3000);
        assert_eq!(
            v,
            Judgment {
                counter_error: true,
                counter_reason: CounterReason::OutOfRange,
                silence_ms: Some(3000),
                ..fine()
            }
        );
        // It moved the baseline and the instant, so it cleared the silence.
        assert_eq!(j.last_valid_ms(), Some(3000));
        assert!(!j.poll(3000 + LIMIT).timeout_error);
    }

    #[test]
    fn a_crc_error_after_2000_ms_is_a_timeout_and_changes_no_state() {
        let mut j = judge(2);
        rx(&mut j, true, 1, 0);
        let v = rx_full(&mut j, false, 2, 2000);
        assert_eq!(
            v,
            Judgment {
                crc_error: true,
                timeout_error: true,
                silence_ms: Some(2000),
                ..fine()
            }
        );
        assert_eq!((j.baseline(), j.last_valid_ms()), (Some(1), Some(0)));
    }

    #[test]
    fn a_repetition_after_1500_ms_is_a_counter_error_and_a_timeout() {
        let mut j = judge(2);
        rx(&mut j, true, 5, 0);
        let v = rx_full(&mut j, true, 5, 1500);
        assert_eq!(
            v,
            Judgment {
                counter_error: true,
                timeout_error: true,
                counter_reason: CounterReason::Repeat,
                silence_ms: Some(1500),
                ..fine()
            }
        );
        // Nothing moved, so the silence is still measured from the first frame.
        assert_eq!((j.baseline(), j.last_valid_ms()), (Some(5), Some(0)));
        assert!(rx(&mut j, false, 6, 1600).timeout_error);
    }

    #[test]
    fn the_silence_before_a_reception_is_reported_on_every_kind_of_reception() {
        // No previous valid reception: nothing to report, whatever the kind.
        let mut j = judge(2);
        assert_eq!(rx_full(&mut j, false, 1, 700).silence_ms, None);
        assert_eq!(
            rx_full(&mut j, true, 1, 800),
            fine(),
            "the first-ever frame"
        );

        // From a first valid frame on, every kind reports its silence, and it
        // is measured from the last VALID frame: the CRC error and the
        // repetition below move nothing, so the 450 is from the frame at 250.
        let mut j = judge(2);
        rx(&mut j, true, 1, 100);
        let silence = |v: Judgment| v.silence_ms;
        assert_eq!(silence(rx_full(&mut j, true, 2, 250)), Some(150), "fine");
        assert_eq!(
            silence(rx_full(&mut j, false, 3, 400)),
            Some(150),
            "CRC error"
        );
        assert_eq!(
            silence(rx_full(&mut j, true, 2, 500)),
            Some(250),
            "repetition"
        );
        assert_eq!(
            silence(rx_full(&mut j, true, 2 + GAP + 1, 700)),
            Some(450),
            "out of range"
        );
        // And a poll reports the silence it is judging.
        assert_eq!(silence(j.poll(900)), Some(200));

        // Before any valid reception the silence is measured from the armed
        // instant, so a timeout is never reported beside nothing; without
        // `arm` there is nothing to measure from.
        let mut j = judge(2);
        j.arm(100);
        assert_eq!(
            silence(rx_full(&mut j, false, 1, 400)),
            Some(300),
            "CRC error before any valid frame"
        );
        assert_eq!(silence(j.poll(450)), Some(350), "poll");
        let mut j = judge(2);
        assert_eq!(silence(rx_full(&mut j, false, 1, 400)), None, "no arm");
        assert_eq!(silence(j.poll(450)), None, "no arm, poll");
    }

    #[test]
    fn the_information_changes_no_boolean() {
        // The same stream judged twice, once as it ran and once with the
        // information removed from every verdict, agrees on all four verdicts.
        let script: [(bool, u64, u64); 6] = [
            (true, 1, 0),
            (true, 2, 1500),
            (false, 3, 1600),
            (true, 2, 3200),
            (true, 40, 3300),
            (false, 41, 9000),
        ];
        let (mut a, mut b) = (judge(2), judge(2));
        // Both streams armed, so the field is present from the first frame.
        a.arm(0);
        b.arm(0);
        for (crc_ok, counter, now) in script {
            let full = rx_full(&mut a, crc_ok, counter, now);
            let blank = rx(&mut b, crc_ok, counter, now);
            assert_eq!(
                Judgment {
                    silence_ms: None,
                    ..full
                },
                blank
            );
        }
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
        // Deliberately not what a fixed-width device clock does: an unsigned
        // 32-bit subtraction would read this as a gap of about 4.29e9 ms.
        let v = j.poll(0);
        assert!(!v.timeout_error);
        assert_eq!(v.silence_ms, Some(0), "no time passed");
        // A CRC error is judged against the same instant, so it agrees.
        let v = rx_full(&mut j, false, 2, 5);
        assert!(v.crc_error && !v.timeout_error);
        assert_eq!(v.silence_ms, Some(0));
        assert!(!rx(&mut j, true, 2, 5).timeout_error);
    }

    #[test]
    fn an_armed_stream_that_never_received_times_out_on_poll() {
        let mut j = judge(2);
        j.arm(1000);
        assert!(
            !j.poll(1000 + 500).timeout_error,
            "+500 is inside the limit"
        );
        assert!(
            !j.poll(1000 + LIMIT).timeout_error,
            "equal to the limit is not over it"
        );
        assert!(j.poll(1000 + 1500).timeout_error, "+1500 is over it");
        // The silence is reported beside the timeout it explains, measured from
        // the armed instant ...
        let v = j.poll(1000 + 1500);
        assert_eq!(
            v,
            Judgment {
                timeout_error: true,
                silence_ms: Some(1500),
                ..fine()
            }
        );
        assert_eq!(j.poll(1000 + 500).silence_ms, Some(500));
        // ... and no valid-reception history was made: the counter baseline is
        // still unset.
        assert_eq!((j.baseline(), j.last_valid_ms()), (None, None));
        assert_eq!(j.armed_ms(), Some(1000));
    }

    #[test]
    fn without_arm_a_stream_that_never_received_is_never_judged() {
        let j = judge(2);
        assert!(!j.poll(0).timeout_error);
        assert!(!j.poll(u64::MAX).timeout_error);
        assert_eq!(j.armed_ms(), None);
    }

    #[test]
    fn the_first_valid_reception_replaces_the_armed_instant_and_clears_its_timeout() {
        let mut j = judge(2);
        j.arm(0);
        assert!(
            j.poll(1500).timeout_error,
            "the silence timed out while it lasted"
        );
        // The first frame still sets the baseline without a counter error, and
        // it reports the silence it ended, measured from the armed instant.
        let v = rx_full(&mut j, true, 0x1234, 1500);
        assert_eq!(
            v,
            Judgment {
                silence_ms: Some(1500),
                ..fine()
            },
            "no timeout, no counter error, the silence it ended"
        );
        assert_eq!(
            (j.baseline(), j.last_valid_ms()),
            (Some(0x1234), Some(1500))
        );
        assert_eq!(j.armed_ms(), None, "replaced");
        // From now on the stream's own history is the reference, for the
        // timeout and for the field alike.
        assert_eq!(rx_full(&mut j, true, 0x1235, 1700).silence_ms, Some(200));
        assert!(!j.poll(1700 + LIMIT).timeout_error);
        assert!(j.poll(1700 + LIMIT + 1).timeout_error);
    }

    #[test]
    fn a_crc_error_before_any_valid_frame_is_judged_against_the_armed_instant() {
        let mut j = judge(2);
        j.arm(0);
        let v = rx_full(&mut j, false, 7, 2000);
        assert_eq!(
            v,
            Judgment {
                crc_error: true,
                timeout_error: true,
                silence_ms: Some(2000),
                ..fine()
            }
        );
        // It changed no state: the stream is still armed and unstarted.
        assert_eq!(
            (j.baseline(), j.last_valid_ms(), j.armed_ms()),
            (None, None, Some(0))
        );
        // Inside the limit the same error is not a timeout.
        let mut j = judge(2);
        j.arm(0);
        let v = rx_full(&mut j, false, 7, 500);
        assert!(!v.timeout_error);
        assert_eq!(v.silence_ms, Some(500));
        // Without arm there is nothing to measure from.
        let mut j = judge(2);
        let v = rx_full(&mut j, false, 7, 5000);
        assert!(!v.timeout_error);
        assert_eq!(v.silence_ms, None);
    }

    #[test]
    fn arming_twice_keeps_the_earlier_instant() {
        let mut j = judge(2);
        j.arm(100);
        j.arm(900);
        assert_eq!(j.armed_ms(), Some(100));
        assert!(
            j.poll(100 + LIMIT + 1).timeout_error,
            "measured from the first"
        );
        assert!(!j.poll(100 + LIMIT).timeout_error);
    }

    #[test]
    fn arming_a_stream_that_already_has_a_valid_reception_changes_nothing() {
        let mut j = judge(2);
        rx(&mut j, true, 1, 0);
        j.arm(5000);
        assert_eq!(j.armed_ms(), None);
        assert_eq!(j.last_valid_ms(), Some(0));
        assert!(
            j.poll(LIMIT + 1).timeout_error,
            "still measured from the frame"
        );
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
