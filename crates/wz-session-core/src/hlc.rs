// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Hybrid Logical Clock arithmetic over a time-since-epoch port.
//!
//! zenoh's clock is `uhlc`, and the node clock of `wz-node-time` wraps it. Two things in `uhlc`
//! 0.8.2 keep that clock off the profiles that have no operating system. Its physical clock is a
//! plain `fn() -> NTP64` (`HLCBuilder::with_clock`), which carries no state, so a clock that the
//! application owns can reach it only through a process-wide static. And a refused remote
//! timestamp builds a `String` with `format!`, so the refusal allocates. This module is the same
//! arithmetic over [`EpochSource`], in one atomic word, with no allocation and no lock.
//!
//! ## The arithmetic is `uhlc`'s, not a new one
//!
//! A stamp is an NTP64 word whose low [`COUNTER_BITS`] bits are the logical counter, as in `uhlc`
//! (`CSIZE`). A reading is first cleared of those bits (`LMASK`).
//!
//! * [`HlcCore::new_timestamp`]: when the reading is above the last stamp's time part the stamp is
//!   the reading, otherwise the last stamp plus one.
//! * [`HlcCore::update_with_timestamp`]: a remote time more than `max_delta` ahead of the reading
//!   is refused. Otherwise the last stamp becomes the reading when that is the largest of the
//!   reading, the remote time and the last stamp, the remote time plus one when that is, and the
//!   last stamp plus one when that is.
//!
//! `wz-node-time` holds a differential test that drives this and `uhlc` over the same random clock
//! traces (a clock that steps back, freezes and jumps) and requires the same stamps and the same
//! refusals. That test, and not this prose, is what says the two agree.
//!
//! ## What differs, on purpose
//!
//! * The state is one `AtomicU64` advanced by compare-and-swap. `uhlc` holds the same word behind
//!   a lock.
//! * A refusal returns [`ForwardStepRefused`], which carries no text and allocates nothing.
//! * The last stamp plus one saturates at `u64::MAX` and does not wrap. A clock is not within
//!   2^60 stamps of that, so the two cannot be told apart by any run, and a saturating stamp stays
//!   monotonic where a wrapped one would not.

use crate::epoch::{EpochSource, EpochUnavailable};
use crate::ntp64::Ntp64;

// The same split `session_actions` uses: the host profile has the native 64-bit atomic, the
// `no_std` profile gets the critical-section one for the cores that have none.
#[cfg(not(feature = "no_std"))]
use core::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "no_std")]
use portable_atomic::{AtomicU64, Ordering};

/// Bits of the NTP64 word that hold the logical counter: `uhlc::CSIZE`.
pub const COUNTER_BITS: u32 = 4;

const COUNTER_MASK: u64 = (1u64 << COUNTER_BITS) - 1;

/// Mask of the time part of a word: `uhlc`'s `LMASK`.
const TIME_MASK: u64 = !COUNTER_MASK;

/// A remote timestamp is further ahead of the reading than the bound allows.
///
/// zenoh's `drop_future_timestamp` decides what the caller does with it; this only says it
/// happened. It carries no detail because the caller knows both words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardStepRefused;

/// The state of a Hybrid Logical Clock: the last stamp it produced or absorbed.
///
/// Zero is "no stamp yet", which `uhlc` also starts from.
#[derive(Debug, Default)]
pub struct HlcCore {
    last: AtomicU64,
}

impl HlcCore {
    /// A clock that has stamped nothing.
    pub const fn new() -> Self {
        Self {
            last: AtomicU64::new(0),
        }
    }

    /// The next stamp for a reading of `now`. Strictly above every earlier stamp of this clock,
    /// whatever `now` does, and never above `now`'s time part plus the counter it needed to stay
    /// above them.
    pub fn new_timestamp(&self, now: Ntp64) -> Ntp64 {
        let now = now.as_word() & TIME_MASK;
        let mut last = self.last.load(Ordering::Acquire);
        loop {
            let next = if now > (last & TIME_MASK) {
                now
            } else {
                last.saturating_add(1)
            };
            match self
                .last
                .compare_exchange_weak(last, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Ntp64::from_word(next),
                Err(seen) => last = seen,
            }
        }
    }

    /// Absorb a timestamp another node produced, so that this clock's next stamp is above it.
    ///
    /// Refused, and the clock unchanged, when `remote` is more than `max_delta` ahead of `now`.
    /// `max_delta` is an NTP64 span, as `uhlc`'s `get_delta()` is.
    pub fn update_with_timestamp(
        &self,
        now: Ntp64,
        remote: Ntp64,
        max_delta: Ntp64,
    ) -> Result<(), ForwardStepRefused> {
        let now = now.as_word() & TIME_MASK;
        let remote = remote.as_word();
        if remote > now && remote - now > max_delta.as_word() {
            return Err(ForwardStepRefused);
        }
        let mut last = self.last.load(Ordering::Acquire);
        loop {
            let max = now.max(remote).max(last);
            let next = if max == now {
                now
            } else if max == remote {
                remote.saturating_add(1)
            } else {
                last.saturating_add(1)
            };
            match self
                .last
                .compare_exchange_weak(last, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Ok(()),
                Err(seen) => last = seen,
            }
        }
    }

    /// The last stamp, or `None` before the first. For observation and tests; a reader that acts
    /// on it races the next stamp.
    pub fn last(&self) -> Option<Ntp64> {
        match self.last.load(Ordering::Acquire) {
            0 => None,
            word => Some(Ntp64::from_word(word)),
        }
    }
}

/// An [`HlcCore`] over the [`EpochSource`] that feeds it: the pair a node holds.
///
/// The source is read once per call, so a source that steps is seen exactly as `uhlc` sees its
/// `fn() -> NTP64`.
#[derive(Debug)]
pub struct Hlc<S> {
    core: HlcCore,
    source: S,
    max_delta: Ntp64,
}

impl<S: EpochSource> Hlc<S> {
    /// A clock over `source` that refuses a remote timestamp more than `max_delta` ahead of it.
    pub const fn new(source: S, max_delta: Ntp64) -> Self {
        Self {
            core: HlcCore::new(),
            source,
            max_delta,
        }
    }

    /// The next stamp, or [`EpochUnavailable`] when the source cannot say what time it is: no
    /// stamp is made from a clock that does not know the date.
    pub fn new_timestamp(&self) -> Result<Ntp64, EpochUnavailable> {
        Ok(self.core.new_timestamp(self.source.try_now_ntp64()?))
    }

    /// Absorb a remote timestamp. `Ok(Err(..))` is a refusal for being too far ahead;
    /// `Err(EpochUnavailable)` is a source that could not be read.
    pub fn update_with_timestamp(
        &self,
        remote: Ntp64,
    ) -> Result<Result<(), ForwardStepRefused>, EpochUnavailable> {
        let now = self.source.try_now_ntp64()?;
        Ok(self.core.update_with_timestamp(now, remote, self.max_delta))
    }

    /// The state, for observation.
    pub fn core(&self) -> &HlcCore {
        &self.core
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch::SinceEpoch;
    use core::cell::Cell;

    fn word(secs: u64, frac: u64) -> Ntp64 {
        Ntp64::from_word((secs << 32) | frac)
    }

    #[test]
    fn a_reading_above_the_last_stamp_is_the_stamp_with_its_counter_cleared() {
        let hlc = HlcCore::new();
        let stamp = hlc.new_timestamp(Ntp64::from_word(0x1234_5678_9abc_def7));
        assert_eq!(stamp.as_word(), 0x1234_5678_9abc_def0);
    }

    #[test]
    fn a_frozen_reading_counts_up_through_the_counter_bits_and_past_them() {
        let hlc = HlcCore::new();
        let now = word(1_700_000_000, 0);
        let mut previous = hlc.new_timestamp(now);
        for _ in 0..(3 * (COUNTER_MASK + 1)) {
            let next = hlc.new_timestamp(now);
            assert!(
                next > previous,
                "a stamp did not rise over a frozen reading"
            );
            previous = next;
        }
    }

    #[test]
    fn a_reading_that_steps_back_never_lowers_a_stamp() {
        let hlc = HlcCore::new();
        let first = hlc.new_timestamp(word(2_000, 0));
        let after_step = hlc.new_timestamp(word(1_000, 0));
        assert!(after_step > first);
    }

    #[test]
    fn a_remote_timestamp_within_the_bound_is_stamped_over() {
        let hlc = HlcCore::new();
        let now = word(1_000, 0);
        let delta = Ntp64::from_word(1 << 31);
        let remote = Ntp64::from_word(now.as_word() + (1 << 30));
        assert_eq!(hlc.update_with_timestamp(now, remote, delta), Ok(()));
        assert!(hlc.new_timestamp(now) > remote);
    }

    #[test]
    fn a_remote_timestamp_past_the_bound_is_refused_and_changes_nothing() {
        let hlc = HlcCore::new();
        let now = word(1_000, 0);
        let before = hlc.new_timestamp(now);
        let delta = Ntp64::from_word(1 << 30);
        let remote = Ntp64::from_word(now.as_word() + (1 << 31));
        assert_eq!(
            hlc.update_with_timestamp(now, remote, delta),
            Err(ForwardStepRefused)
        );
        assert_eq!(hlc.last(), Some(before));
    }

    #[test]
    fn the_last_stamp_saturates_and_does_not_wrap() {
        let hlc = HlcCore {
            last: AtomicU64::new(u64::MAX),
        };
        assert_eq!(hlc.new_timestamp(word(1, 0)).as_word(), u64::MAX);
    }

    struct Steppable(Cell<Option<SinceEpoch>>);

    impl EpochSource for Steppable {
        fn try_since_epoch(&self) -> Result<SinceEpoch, EpochUnavailable> {
            self.0.get().ok_or(EpochUnavailable)
        }
    }

    #[test]
    fn a_source_without_the_date_stamps_nothing() {
        let hlc = Hlc::new(Steppable(Cell::new(None)), Ntp64::from_word(1 << 30));
        assert_eq!(hlc.new_timestamp(), Err(EpochUnavailable));
        assert_eq!(hlc.core().last(), None);
        assert_eq!(hlc.update_with_timestamp(word(5, 0)), Err(EpochUnavailable));
    }

    #[test]
    fn the_pair_stamps_from_its_source() {
        let source = Steppable(Cell::new(Some(SinceEpoch {
            secs: 1_700_000_000,
            nanos: 0,
        })));
        let hlc = Hlc::new(source, Ntp64::from_word(1 << 30));
        let stamp = hlc.new_timestamp().expect("the source answers");
        assert_eq!(stamp.whole_secs(), 1_700_000_000);
    }
}
