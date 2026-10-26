// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The pacing of a recorded sequence: the delay before each emission and where it came from.
//!
//! Moved from `wz-replay` (R311y700, R311y703, R311y704, Round 2441), which re-exports every item
//! here at the path it had. The meaning is unchanged: the first emission waits for nothing, a gap
//! is the declared one or the interval the capture recorded, it is divided by the speed and rounded
//! half away from zero, and the per-gap ceiling caps it.

/// R311y700 — how fast a recorded sequence is played back.
///
/// # The claim this doc used to make, and the measurement that refuted it
///
/// It said a capture's own per-message timing could not be reused: a sample carries a framing
/// coordinate rather than a clock, and on a stream link that coordinate is a byte offset, so there
/// was said to be no per-message time to scale. The reasoning is sound and the conclusion was
/// FALSE: `wz_capture::FlowDissection::packet_for` answers "which capture packet carried the byte
/// at this stream offset". R311y700 wrote the claim, R311y702 repeated it in a carry, and R311y703
/// refuted it by reading that surface instead of re-deriving the argument.
///
/// # So the schedule has a SOURCE
///
/// [`Timing::Declared`] is a gap this caller chose, scaled by a speed, and it remains the default:
/// the plan is the caller's contract and what an existing invocation does is not changed silently.
/// [`Timing::Capture`] uses the interval the capture recorded, falling back to the declared gap
/// where a pair of samples has no resolvable time, and every emission SAYS which it got
/// ([`TimingSource`]), because a run that mixed the two without saying so would report a timing it
/// did not reproduce.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Schedule {
    /// R311y703 — where each gap COMES FROM.
    pub timing: Timing,
    /// Milliseconds between consecutive samples at speed 1.0.
    ///
    /// Under [`Timing::Capture`] this is the FALLBACK, used for a pair of samples whose capture
    /// times could not be resolved.
    pub gap_millis: u64,
    /// The multiplier. 2.0 plays twice as fast (half the gaps); 0.5 half as fast. Zero and below
    /// are refused by [`Self::checked`] rather than producing an infinite or negative delay.
    pub speed: f64,
    /// A ceiling on any one delay, so a large gap and a slow speed cannot produce a replay that
    /// appears to hang.
    pub max_gap_millis: Option<u64>,
    /// R311y704 — a ceiling on the WHOLE plan, which nothing bounded.
    ///
    /// [`Self::max_gap_millis`] caps ONE delay. At capture pace a replay takes as long as the
    /// capture did, and a ten-thousand-sample file at that pace runs for hours with no surface
    /// saying so before it starts.
    ///
    /// REFUSES rather than truncates, which is the rule for every bound a person types: a plan
    /// silently cut to fit would send a prefix of the traffic under a name that promised all of it.
    pub max_total_millis: Option<u64>,
}

/// R311y703 — which clock a gap comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timing {
    /// Every gap is [`Schedule::gap_millis`]. The DEFAULT, and it stays the default deliberately:
    /// changing what an existing invocation does is not a change to make silently.
    Declared,
    /// Use the interval the CAPTURE recorded between consecutive samples, falling back to the
    /// declared gap for a pair that could not be resolved. Which one each emission got is a
    /// [`TimingSource`].
    Capture,
}

/// R311y703 — which clock ONE emission's delay came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingSource {
    /// The declared gap.
    Declared,
    /// The interval between this sample's capture time and the previous one's.
    Measured,
    /// The capture was asked for and could not answer: one of the two samples carried no
    /// resolvable capture time, so the declared gap was used.
    ///
    /// Distinct from [`Self::Declared`] on the rule this workspace applies to every gap counter: a
    /// fallback that reads like a choice hides the fact that a measurement was wanted and missing.
    Unmeasurable,
}

impl Default for Schedule {
    /// One sample every 100 ms at speed 1.0, capped at ten seconds, from the DECLARED gap.
    fn default() -> Self {
        Self {
            timing: Timing::Declared,
            gap_millis: 100,
            speed: 1.0,
            max_gap_millis: Some(10_000),
            // No whole-plan ceiling by default: a bound nobody asked for that refuses their capture
            // is worse than one they can reach for.
            max_total_millis: None,
        }
    }
}

/// Why a schedule was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleError {
    /// A speed of zero or less. Refused rather than clamped: a caller who typed a speed of 0 meant
    /// something, and neither "as fast as possible" nor "never" is obviously it.
    SpeedNotPositive,
    /// A speed that is not a number at all.
    SpeedNotFinite,
}

impl core::fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SpeedNotPositive => write!(f, "speed must be greater than zero"),
            Self::SpeedNotFinite => write!(f, "speed must be a finite number"),
        }
    }
}

impl Schedule {
    /// This schedule, if it is one that can be played.
    pub fn checked(self) -> Result<Self, ScheduleError> {
        if !self.speed.is_finite() {
            return Err(ScheduleError::SpeedNotFinite);
        }
        if self.speed <= 0.0 {
            return Err(ScheduleError::SpeedNotPositive);
        }
        Ok(self)
    }

    /// The delay BEFORE the sample at `index`. Zero for the first.
    ///
    /// Saturating rather than wrapping at every step: a gap and a speed a caller can type must not
    /// be able to produce a delay of nearly forever through an arithmetic edge.
    pub fn delay_before(&self, index: usize) -> u64 {
        self.delay_from(index, None).0
    }

    /// R311y703 — the delay before the sample at `index`, and WHERE it came from.
    ///
    /// `measured_gap` is the interval the capture recorded between this sample and the previous
    /// one, when both carried a resolvable time. The SPEED scales a measured gap exactly as it
    /// scales a declared one, and the ceiling applies to both, so a capture with an hour of silence
    /// in it cannot produce a replay that appears to hang.
    pub fn delay_from(&self, index: usize, measured_gap: Option<u64>) -> (u64, TimingSource) {
        if index == 0 {
            // The first emission waits for nothing, whichever clock is in play: a plan that slept
            // before its first sample would add a gap no capture contained.
            return (0, TimingSource::Declared);
        }
        let (base, source) = match (self.timing, measured_gap) {
            (Timing::Declared, _) => (self.gap_millis, TimingSource::Declared),
            (Timing::Capture, Some(gap)) => (gap, TimingSource::Measured),
            (Timing::Capture, None) => (self.gap_millis, TimingSource::Unmeasurable),
        };
        (self.scale(base), source)
    }

    /// A gap, scaled and capped.
    fn scale(&self, base: u64) -> u64 {
        let scaled = (base as f64) / self.speed;
        let millis = if scaled.is_finite() && scaled >= 0.0 {
            round_half_away(scaled)
        } else {
            u64::MAX
        };
        match self.max_gap_millis {
            Some(cap) => millis.min(cap),
            None => millis,
        }
    }
}

/// A finite, non-negative float rounded to the nearest integer, a half rounded away from zero, and
/// saturated at the type's bound: what `f64::round` followed by `as u64` gives, which is the rule
/// this pacing has always had, written without the `std` the method lives in.
///
/// Exact for every input: below 2^53 the truncation and the fraction are exact, and at or above it
/// every float is an integer, so the fraction is zero.
fn round_half_away(x: f64) -> u64 {
    // `as u64` truncates toward zero and saturates at the type's bounds.
    let whole = x as u64;
    if x - (whole as f64) >= 0.5 {
        whole.saturating_add(1)
    } else {
        whole
    }
}

/// Round 2441 (open-debt item 693) — the pacing WALK, over capture times alone.
///
/// # Why this is a type and not four lines inside a plan builder
///
/// It was four lines inside the replay tool's plan builder, and that is exactly as far as it could
/// travel: a caller holding capture times but no samples (every consumer of the C ABI) had to write
/// the walk again. A downstream product did, and reported it.
///
/// The walk is two coupled decisions, and the second is the one a second implementation gets
/// wrong:
///
///  * a gap is the SATURATING difference of two capture times, so a capture whose clock steps
///    backwards between two packets yields zero rather than an enormous gap from a wrapped
///    subtraction;
///  * a sample with NO capture time does not reset the anchor. The previous resolvable time
///    STICKS, so the pair after it measures across the hole rather than starting over.
///
/// # It is a WALK, not an indexed lookup
///
/// [`Schedule::delay_from`] takes an index and a gap the caller already computed; this owns both.
/// Feeding it in the wrong order gives a different answer, which is why the index is its own count.
#[derive(Debug, Clone)]
pub struct Pacing {
    schedule: Schedule,
    /// The last RESOLVABLE capture time seen, which is not the same as the previous sample's.
    previous_at: Option<u64>,
    /// How many emissions have been paced, which is the index [`Schedule::delay_from`] answers about.
    emitted: usize,
}

impl Pacing {
    /// A walk that has paced nothing yet.
    pub fn new(schedule: Schedule) -> Self {
        Self {
            schedule,
            previous_at: None,
            emitted: 0,
        }
    }

    /// Pace the NEXT emission, given the capture time of the sample carrying it, and say where its
    /// delay came from. `captured_at_millis` is `None` for a sample whose capture time could not
    /// be resolved.
    pub fn next(&mut self, captured_at_millis: Option<u64>) -> (u64, TimingSource) {
        let measured = match (self.previous_at, captured_at_millis) {
            (Some(prev), Some(now)) => Some(now.saturating_sub(prev)),
            _ => None,
        };
        let paced = self.schedule.delay_from(self.emitted, measured);
        self.previous_at = captured_at_millis.or(self.previous_at);
        self.emitted += 1;
        paced
    }

    /// How many emissions this walk has paced.
    pub fn emitted(&self) -> usize {
        self.emitted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn walk(schedule: Schedule, times: &[Option<u64>]) -> Vec<(u64, TimingSource)> {
        let mut pacing = Pacing::new(schedule);
        times.iter().map(|t| pacing.next(*t)).collect()
    }

    /// The rounding written without `std` is `f64::round` then `as u64`, on the halves, around
    /// them, at 2^53 and past the type's bound.
    #[test]
    fn the_rounding_is_the_standard_one() {
        let probes = [
            0.0,
            0.49999999999999994,
            0.5,
            1.5,
            2.5,
            2.4999,
            2.5001,
            99.5,
            1e15 + 0.5,
            4503599627370495.5,
            9007199254740992.0,
            9007199254740993.0,
            1.8446744073709552e19,
            1e30,
        ];
        for x in probes {
            assert_eq!(round_half_away(x), x.round() as u64, "{x}");
        }
        let mut state = 7u64;
        for _ in 0..10_000 {
            let x = (crate::mutation::splitmix64(&mut state) >> 11) as f64 / 1024.0;
            assert_eq!(round_half_away(x), x.round() as u64, "{x}");
        }
    }

    /// The vectors a downstream product holds for its wrapper of this walk.
    #[test]
    fn the_downstream_vectors_hold() {
        let declared = Schedule {
            gap_millis: 100,
            max_gap_millis: None,
            ..Schedule::default()
        };
        let three = [Some(0), Some(10), Some(20)];
        assert_eq!(
            walk(declared, &three),
            [
                (0, TimingSource::Declared),
                (100, TimingSource::Declared),
                (100, TimingSource::Declared)
            ]
        );
        let twice = Schedule {
            speed: 2.0,
            ..declared
        };
        assert_eq!(walk(twice, &three)[1].0, 50);
        let capture = Schedule {
            timing: Timing::Capture,
            gap_millis: 100,
            max_gap_millis: Some(500),
            ..Schedule::default()
        };
        assert_eq!(
            walk(capture, &[Some(0), Some(3_600_000)])[1],
            (500, TimingSource::Measured)
        );
        // A clock that steps back measures zero and becomes the reference; a sample with no clock
        // is unmeasurable and does not reset it.
        assert_eq!(
            walk(capture, &[Some(2000), Some(1000)])[1],
            (0, TimingSource::Measured)
        );
        assert_eq!(
            walk(capture, &[Some(1000), None, Some(1750)]),
            [
                (0, TimingSource::Declared),
                (100, TimingSource::Unmeasurable),
                (500, TimingSource::Measured)
            ]
        );
        let uncapped = Schedule {
            max_gap_millis: None,
            ..capture
        };
        assert_eq!(
            walk(uncapped, &[Some(1000), None, Some(1750)])[2],
            (750, TimingSource::Measured)
        );
    }

    #[test]
    fn a_speed_that_cannot_be_played_is_refused() {
        let at = |speed| {
            Schedule {
                speed,
                ..Schedule::default()
            }
            .checked()
        };
        assert_eq!(at(0.0), Err(ScheduleError::SpeedNotPositive));
        assert_eq!(at(-1.0), Err(ScheduleError::SpeedNotPositive));
        assert_eq!(at(f64::NAN), Err(ScheduleError::SpeedNotFinite));
        assert!(at(0.25).is_ok());
    }
}
