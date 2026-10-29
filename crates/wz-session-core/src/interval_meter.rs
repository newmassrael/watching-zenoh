// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The message counter of a receive path that runs on several threads
//! (`docs/observation-plane.md` M4).
//!
//! A node receives on more than one thread, and every received message is to be counted and
//! spaced from the one before it, so the counter is on the hot path and shared. It takes no lock:
//! every field is an atomic, and a thread that observes a message does a fixed number of atomic
//! operations and never waits for another.
//!
//! # The same rules as the plain counter
//!
//! It takes the same step and the same rule as the single-thread
//! [`MessageStats`](crate::resource_snapshot::MessageStats): the bucket of an interval
//! ([`bucket_of`]), what is an interval at all ([`interval_between`]) and what is skew
//! ([`is_skew`]). A test drives the two over the same random traces and requires the same
//! readings.
//!
//! # What several threads change
//!
//! * The latest message is held in one atomic and moved by compare-and-swap, so an interval is
//!   always taken from the latest message that was stored, and the intervals chain through the
//!   latest messages, whatever the interleaving.
//! * A receiver reads the clock and then stores, and between the two another can store a later
//!   reading, so a message's reading can be a little behind the latest. That is skew
//!   ([`is_skew`]): the latest stays where it was and the message is counted and makes no interval.
//!   Counting it would put two spans in the histogram that no gap between messages made, one
//!   running backwards and the next inflated by the whole delay of the receiver.
//! * [`IntervalMeter::reading`] reads each field once, with no lock, so the fields can disagree by
//!   the messages in flight, at most one for each thread. Between messages they agree: the buckets
//!   and the messages that were not intervals add up to the messages less the first.
//!
//! # The cost
//!
//! A message costs one fetch-add, one compare-and-swap on the latest message, and, for an interval,
//! two fetch-adds, on a bucket and on the sum. They are measured, and the numbers are in
//! `docs/observation-plane.md` M4.

use crate::resource_snapshot::{bucket_of, interval_between, is_skew, MessageReading, MAX_BUCKETS};

#[cfg(not(feature = "no_std"))]
use core::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "no_std")]
use portable_atomic::{AtomicU64, Ordering};

/// Bit 32 of the last reading: set once there has been one. The reading is the low 32 bits.
const SEEN: u64 = 1 << 32;

/// The counter: `B` interval buckets, the sum of the intervals, and the messages seen.
///
/// Every count is 64 bits and is added to with one `fetch_add`: they do not wrap in the life of a
/// node (at a million messages a second a 64-bit count takes 584,000 years), so none of them
/// saturates or needs a check, and the sum of the intervals is at most the time that has passed.
#[derive(Debug)]
pub struct IntervalMeter<const B: usize> {
    counts: [AtomicU64; B],
    last: AtomicU64,
    interval_sum_us: AtomicU64,
    messages: AtomicU64,
}

impl<const B: usize> IntervalMeter<B> {
    /// A counter that has seen no message.
    pub const fn new() -> Self {
        assert!(
            B >= 1 && B <= MAX_BUCKETS,
            "a histogram has one to thirty-two buckets"
        );
        Self {
            counts: [const { AtomicU64::new(0) }; B],
            last: AtomicU64::new(0),
            interval_sum_us: AtomicU64::new(0),
            messages: AtomicU64::new(0),
        }
    }

    /// A message was seen at `now_us`. It is counted, and so is the interval since the one before
    /// it when that is an [`interval_between`] the two.
    #[inline]
    pub fn observe(&self, now_us: u32) {
        // A u64 does not wrap in the life of a node: at a million messages a second it takes
        // 584,000 years.
        self.messages.fetch_add(1, Ordering::Relaxed);
        // The latest message moves to this one unless this reading is skew, a little behind it.
        // The update that wins names the message before this one, so the intervals chain through
        // the latest messages and not through whichever thread stored last.
        let Ok(previous) = self
            .last
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |last| {
                if last & SEEN != 0 && is_skew(last as u32, now_us) {
                    None
                } else {
                    Some(SEEN | u64::from(now_us))
                }
            })
        else {
            return;
        };
        if previous & SEEN == 0 {
            return;
        }
        let Some(interval) = interval_between(previous as u32, now_us) else {
            return;
        };
        self.counts[bucket_of(interval, B)].fetch_add(1, Ordering::Relaxed);
        self.interval_sum_us
            .fetch_add(u64::from(interval), Ordering::Relaxed);
    }

    /// What has been counted. Each field is read once and with no lock, so they can disagree by
    /// the messages in flight.
    pub fn reading(&self) -> MessageReading<B> {
        let mut intervals = [0u64; B];
        for (out, count) in intervals.iter_mut().zip(&self.counts) {
            *out = count.load(Ordering::Relaxed);
        }
        MessageReading {
            messages: self.messages.load(Ordering::Relaxed),
            interval_sum_us: self.interval_sum_us.load(Ordering::Relaxed),
            intervals,
        }
    }
}

impl<const B: usize> Default for IntervalMeter<B> {
    fn default() -> Self {
        Self::new()
    }
}

/// The meter of a build: `SNAPSHOT_HISTOGRAM_BUCKETS` buckets.
pub type BuildIntervalMeter = IntervalMeter<{ crate::caps::SNAPSHOT_HISTOGRAM_BUCKETS }>;

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::resource_snapshot::MessageStats;
    use std::sync::atomic::AtomicU32;

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn the_meter_reads_what_the_plain_counter_reads_over_the_same_trace() {
        for seed in 1..=200u64 {
            let mut rng = Rng(seed.wrapping_mul(0x2545_F491_4F6C_DD1D) | 1);
            let meter = IntervalMeter::<24>::new();
            let mut stats = MessageStats::<24>::new();
            let mut now = rng.next() as u32;
            for _ in 0..500 {
                // Forward by a span of any magnitude, sometimes backwards, sometimes past half
                // the range: every kind of reading an interval can be or not be.
                now = match rng.next() % 8 {
                    0 => now.wrapping_sub((rng.next() % 1000) as u32),
                    1 => now
                        .wrapping_add(1 << 31)
                        .wrapping_add((rng.next() % 1000) as u32),
                    2 => now,
                    _ => now.wrapping_add((rng.next() % (1u64 << (rng.next() % 31))) as u32),
                };
                meter.observe(now);
                stats.observe(now);
            }
            assert_eq!(meter.reading(), stats.reading(), "seed {seed}");
        }
    }

    #[test]
    fn a_meter_that_has_seen_one_message_has_no_mean_and_the_first_interval_seeds_it() {
        let meter = IntervalMeter::<8>::new();
        assert_eq!(meter.reading().messages, 0);
        meter.observe(1000);
        let one = meter.reading();
        assert_eq!((one.messages, one.interval_sum_us), (1, 0));
        assert_eq!(one.intervals, [0; 8]);
        meter.observe(1100);
        let two = meter.reading();
        assert_eq!(two.interval_sum_us, 100);
        assert_eq!(two.intervals[6], 1, "100 microseconds is bucket 6");
    }

    #[test]
    fn a_skewed_message_is_counted_and_the_next_is_measured_from_the_latest() {
        let meter = IntervalMeter::<8>::new();
        meter.observe(1000);
        meter.observe(950);
        let skewed = meter.reading();
        assert_eq!(skewed.messages, 2);
        assert_eq!(skewed.intervals, [0; 8]);
        meter.observe(1060);
        let after = meter.reading();
        assert_eq!(
            after.intervals[5], 1,
            "60 microseconds, from 1000 and not from 950"
        );
        assert_eq!(
            after.interval_sum_us, 60,
            "the delayed message added nothing"
        );
    }

    /// Four threads read a shared clock, one microsecond a reading, and observe. A thread can be
    /// kept waiting between reading and storing, so its message is often behind the latest: skew.
    /// Every message must be counted, and no span may reach a high bucket, because the whole run is
    /// shorter than the skew limit and the clock moves by one a reading, so every real gap between
    /// the latest messages is a few microseconds. A delayed receiver counted as an interval would
    /// show as a span of thousands.
    #[test]
    fn under_several_threads_every_message_is_counted_and_a_delayed_receiver_makes_no_tail() {
        const THREADS: u32 = 4;
        const PER_THREAD: u32 = 100_000;
        let meter = IntervalMeter::<32>::new();
        let clock = AtomicU32::new(1_000);
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    for _ in 0..PER_THREAD {
                        meter.observe(clock.fetch_add(1, Ordering::Relaxed));
                    }
                });
            }
        });
        let reading = meter.reading();
        assert_eq!(reading.messages, u64::from(THREADS * PER_THREAD));
        let counted: u64 = reading.intervals.iter().sum();
        assert!(
            counted < reading.messages,
            "the first message has no interval"
        );
        let high: u64 = reading.intervals[4..].iter().sum();
        assert_eq!(
            high, 0,
            "a delayed receiver was counted as an interval: {reading:?}"
        );
        // Most messages are the latest when they are stored; the rest are skew.
        assert!(
            counted > reading.messages / 2,
            "{counted} of {}",
            reading.messages
        );
    }
}
