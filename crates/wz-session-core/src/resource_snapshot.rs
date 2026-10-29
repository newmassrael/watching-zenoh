// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A sampled view of a running node: what it spends and how its messages are spaced
//! (`docs/observation-plane.md` M4).
//!
//! A node has counters per lane and per reason and nothing that says, in one place, how loaded it
//! is. The [`Sampler`] takes a [`Snapshot`] on a period and keeps the latest, and the snapshot is a
//! fixed-layout record with a version, so a reader of an older image does not misread a newer one
//! and a reader of a newer image reads an older one.
//!
//! # What is measured and what is asked
//!
//! The library measures what it can know without the platform: how many messages it was told of and
//! how they were spaced (an [`IntervalHistogram`] and an exponentially weighted mean). What only the
//! platform knows (CPU use, heap in use and its high-water mark, how many tasks there are) it asks
//! for through a [`ResourceSource`], the way the clock is asked of an `EpochSource`. A source that
//! cannot answer one of them leaves it out, and the snapshot says it was not measured
//! ([`HAS_CPU`] and its siblings), so a reader can tell a node that uses no CPU from one nobody
//! measured.
//!
//! # No task, no timer
//!
//! The sampler reads no clock, starts no task and holds no timer. The host tells it the time on
//! every call, in microseconds on a counter that wraps at 2^32, and calls [`Sampler::poll`] on its
//! own cadence (the cooperative engine on every turn of its loop, a build with tasks from one of
//! its own). A sample is due when the period has passed ([`crate::wrapping_ticks::elapsed`], the
//! comparison the supervisor's deadlines also use). One sample is taken however many periods have
//! passed, and the next period counts from it.
//!
//! # The message interval
//!
//! A minimum, a maximum and a sum hide the tail of a distribution, and a histogram does not. The
//! buckets are on a base-2 scale: bucket 0 holds intervals of 0 and 1 microsecond and bucket `b` of
//! at least 1 holds `2^b` up to `2^(b+1) - 1`, the last bucket everything above. They are counted
//! in 32 bits and saturate, because a counter that wrapped would hide the load it exists to show.
//! The mean is exponentially weighted with a weight of 1/8, in fixed point with four fractional bits
//! and no division. An interval is the difference of two readings of the 32-bit counter, so one past
//! 2^32 microseconds (71 minutes) is not representable, and the first message after the sampler is
//! built has no interval.
//!
//! # The layout
//!
//! [`Snapshot::to_bytes`] writes little-endian bytes: a header of [`HEADER_SIZE`] bytes that begins
//! with the layout version, the total size and the bucket count, then the histogram. A later version
//! only appends fields, never moves one, so [`Snapshot::from_bytes`] reads the fields it knows from
//! a newer buffer and skips the rest by the size in the header. The version and the size are pinned
//! by a test, so a change to a field cannot pass without changing them.

use crate::wrapping_ticks::{elapsed, MAX_TIMEOUT_TICKS};

/// The layout version this code writes.
pub const LAYOUT_VERSION: u16 = 1;

/// Bytes before the histogram in the layout of [`LAYOUT_VERSION`].
pub const HEADER_SIZE: usize = 64;

/// The most buckets a histogram can have: an interval of 32 bits has a bucket for each bit.
pub const MAX_BUCKETS: usize = 32;

/// [`Snapshot::cpu_permille`] was measured.
pub const HAS_CPU: u8 = 1 << 0;
/// [`Snapshot::heap_in_use`] and [`Snapshot::heap_high_water`] were measured.
pub const HAS_HEAP: u8 = 1 << 1;
/// [`Snapshot::tasks`] was measured.
pub const HAS_TASKS: u8 = 1 << 2;

/// What the platform could say about the node now. A field left `None` was not measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceReading {
    /// How much of the time the CPU was busy since the last reading, in thousandths.
    pub cpu_permille: Option<u16>,
    /// Bytes on the heap in use, and the most there have been.
    pub heap: Option<HeapReading>,
    /// How many tasks the node runs.
    pub tasks: Option<u16>,
}

/// Heap use as the platform counts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeapReading {
    /// Bytes in use now.
    pub in_use: u64,
    /// The most bytes there have been in use.
    pub high_water: u64,
}

/// What the platform is asked for at each sample.
pub trait ResourceSource {
    /// What can be said about the node now.
    fn read(&mut self) -> ResourceReading;
}

/// The bucket an interval of `interval_us` microseconds falls in, in a histogram of `buckets`.
pub const fn bucket_of(interval_us: u32, buckets: usize) -> usize {
    let bit = if interval_us < 2 {
        0
    } else {
        (31 - interval_us.leading_zeros()) as usize
    };
    if bit < buckets {
        bit
    } else {
        buckets - 1
    }
}

/// How message intervals are spread, on a base-2 scale, in `B` buckets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntervalHistogram<const B: usize> {
    counts: [u32; B],
}

impl<const B: usize> IntervalHistogram<B> {
    /// An empty histogram.
    pub const fn new() -> Self {
        assert!(
            B >= 1 && B <= MAX_BUCKETS,
            "a histogram has one to thirty-two buckets"
        );
        Self { counts: [0; B] }
    }

    /// Count one interval.
    pub fn observe(&mut self, interval_us: u32) {
        let bucket = &mut self.counts[bucket_of(interval_us, B)];
        *bucket = bucket.saturating_add(1);
    }

    /// The count in each bucket.
    pub const fn counts(&self) -> &[u32; B] {
        &self.counts
    }
}

impl<const B: usize> Default for IntervalHistogram<B> {
    fn default() -> Self {
        Self::new()
    }
}

/// An exponentially weighted mean with a weight of 1/8, in fixed point with four fractional bits.
///
/// Each step moves the mean one eighth of the way to the new value, the step truncated, so the mean
/// is within half a microsecond of the exact recurrence and stalls when it is within 7/16 of a
/// microsecond of a constant input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ewma {
    mean_q4: u64,
    seeded: bool,
}

impl Ewma {
    /// Take one value in. The first value is the mean.
    pub fn observe(&mut self, value: u32) {
        let target = u64::from(value) << 4;
        if !self.seeded {
            self.mean_q4 = target;
            self.seeded = true;
        } else if target >= self.mean_q4 {
            self.mean_q4 += (target - self.mean_q4) >> 3;
        } else {
            self.mean_q4 -= (self.mean_q4 - target) >> 3;
        }
    }

    /// The mean times 16, so the fraction survives.
    pub const fn mean_q4(&self) -> u64 {
        self.mean_q4
    }
}

/// One sample of the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot<const B: usize> {
    /// Which sample this is, from 0 and wrapping: a reader that sees a number skipped knows it
    /// missed a sample.
    pub sequence: u32,
    /// The host's time at the sample, in microseconds on its wrapping counter.
    pub taken_at_us: u32,
    /// Which of the platform's fields were measured: [`HAS_CPU`], [`HAS_HEAP`], [`HAS_TASKS`].
    pub available: u8,
    /// CPU use in thousandths, or 0 when not measured.
    pub cpu_permille: u16,
    /// Tasks, or 0 when not measured.
    pub tasks: u16,
    /// Heap in use, or 0 when not measured.
    pub heap_in_use: u64,
    /// The most heap there has been in use, or 0 when not measured.
    pub heap_high_water: u64,
    /// The capabilities the image has, one bit each, as the host states them.
    pub features: u64,
    /// How many messages the sampler was told of.
    pub messages: u64,
    /// The exponentially weighted mean message interval, times 16.
    pub mean_interval_us_q4: u64,
    /// How the intervals between messages are spread.
    pub intervals: [u32; B],
}

/// Why a buffer is not a snapshot this reader can take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The buffer ends before the header does, or before its own declared size.
    TooShort,
    /// The version is 0, which no layout has.
    UnknownVersion,
    /// The size the header declares is less than this layout needs.
    SizeBelowLayout,
    /// The histogram has another number of buckets than the reader's.
    BucketsDiffer {
        /// What the buffer says.
        found: u8,
    },
}

/// The first bytes of any snapshot of any version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The layout version.
    pub version: u16,
    /// Bytes in the whole snapshot.
    pub size: u16,
    /// Buckets in its histogram.
    pub buckets: u8,
}

impl Header {
    /// Read the header of `bytes`, whatever its version and bucket count, to say what a reader
    /// would need to read the rest.
    pub fn peek(bytes: &[u8]) -> Result<Self, Refused> {
        if bytes.len() < 5 {
            return Err(Refused::TooShort);
        }
        let version = u16::from_le_bytes([bytes[0], bytes[1]]);
        if version == 0 {
            return Err(Refused::UnknownVersion);
        }
        Ok(Self {
            version,
            size: u16::from_le_bytes([bytes[2], bytes[3]]),
            buckets: bytes[4],
        })
    }
}

fn put(out: &mut [u8], at: usize, bytes: &[u8]) {
    out[at..at + bytes.len()].copy_from_slice(bytes);
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(word)
}

impl<const B: usize> Snapshot<B> {
    /// Bytes in the layout of [`LAYOUT_VERSION`] for `B` buckets.
    pub const SIZE: usize = HEADER_SIZE + 4 * B;

    /// Write the snapshot into `out`, which must hold [`Self::SIZE`] bytes. Returns how many were
    /// written, or `None` when `out` is too small, and then writes nothing.
    pub fn to_bytes(&self, out: &mut [u8]) -> Option<usize> {
        if out.len() < Self::SIZE {
            return None;
        }
        put(out, 0, &LAYOUT_VERSION.to_le_bytes());
        put(out, 2, &(Self::SIZE as u16).to_le_bytes());
        out[4] = B as u8;
        out[5] = self.available;
        put(out, 6, &self.cpu_permille.to_le_bytes());
        put(out, 8, &self.tasks.to_le_bytes());
        put(out, 10, &0u16.to_le_bytes());
        put(out, 12, &self.sequence.to_le_bytes());
        put(out, 16, &self.taken_at_us.to_le_bytes());
        put(out, 20, &0u32.to_le_bytes());
        put(out, 24, &self.heap_in_use.to_le_bytes());
        put(out, 32, &self.heap_high_water.to_le_bytes());
        put(out, 40, &self.features.to_le_bytes());
        put(out, 48, &self.messages.to_le_bytes());
        put(out, 56, &self.mean_interval_us_q4.to_le_bytes());
        for (index, count) in self.intervals.iter().enumerate() {
            put(out, HEADER_SIZE + 4 * index, &count.to_le_bytes());
        }
        Some(Self::SIZE)
    }

    /// Read a snapshot of this reader's bucket count from `bytes`. A buffer of a newer version is
    /// read for the fields this layout has, the rest skipped by the size its header declares.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Refused> {
        let header = Header::peek(bytes)?;
        if usize::from(header.buckets) != B {
            return Err(Refused::BucketsDiffer {
                found: header.buckets,
            });
        }
        if usize::from(header.size) < Self::SIZE {
            return Err(Refused::SizeBelowLayout);
        }
        if bytes.len() < usize::from(header.size) {
            return Err(Refused::TooShort);
        }
        let mut intervals = [0u32; B];
        for (index, count) in intervals.iter_mut().enumerate() {
            *count = u32_at(bytes, HEADER_SIZE + 4 * index);
        }
        Ok(Self {
            sequence: u32_at(bytes, 12),
            taken_at_us: u32_at(bytes, 16),
            available: bytes[5],
            cpu_permille: u16_at(bytes, 6),
            tasks: u16_at(bytes, 8),
            heap_in_use: u64_at(bytes, 24),
            heap_high_water: u64_at(bytes, 32),
            features: u64_at(bytes, 40),
            messages: u64_at(bytes, 48),
            mean_interval_us_q4: u64_at(bytes, 56),
            intervals,
        })
    }
}

/// The period is zero, or longer than a comparison over a wrapping counter can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeriodOutOfRange;

/// Takes a [`Snapshot`] on a period and keeps the latest.
#[derive(Debug, Clone)]
pub struct Sampler<const B: usize> {
    intervals: IntervalHistogram<B>,
    mean: Ewma,
    last_message_us: Option<u32>,
    messages: u64,
    period_us: u32,
    features: u64,
    last_sample_us: Option<u32>,
    sequence: u32,
    latest: Option<Snapshot<B>>,
}

impl<const B: usize> Sampler<B> {
    /// A sampler with a period of `period_us` microseconds, for an image whose capabilities are
    /// the bits of `features`. The period is at least 1 and at most [`MAX_TIMEOUT_TICKS`].
    pub fn new(period_us: u32, features: u64) -> Result<Self, PeriodOutOfRange> {
        if period_us == 0 || period_us > MAX_TIMEOUT_TICKS {
            return Err(PeriodOutOfRange);
        }
        Ok(Self {
            intervals: IntervalHistogram::new(),
            mean: Ewma::default(),
            last_message_us: None,
            messages: 0,
            period_us,
            features,
            last_sample_us: None,
            sequence: 0,
            latest: None,
        })
    }

    /// A message was seen at `now_us`. Counts it, and counts the interval since the one before.
    pub fn observe_message(&mut self, now_us: u32) {
        if let Some(last) = self.last_message_us {
            let interval = now_us.wrapping_sub(last);
            self.intervals.observe(interval);
            self.mean.observe(interval);
        }
        self.last_message_us = Some(now_us);
        self.messages = self.messages.saturating_add(1);
    }

    /// Take a sample if one is due at `now_us`: the first call, and then each time the period has
    /// passed since the last. Returns whether one was taken. `source` is asked only when it is.
    pub fn poll(&mut self, now_us: u32, source: &mut impl ResourceSource) -> bool {
        let due = match self.last_sample_us {
            None => true,
            Some(last) => elapsed(now_us, last, self.period_us),
        };
        if !due {
            return false;
        }
        let reading = source.read();
        let mut available = 0;
        if reading.cpu_permille.is_some() {
            available |= HAS_CPU;
        }
        if reading.heap.is_some() {
            available |= HAS_HEAP;
        }
        if reading.tasks.is_some() {
            available |= HAS_TASKS;
        }
        let heap = reading.heap.unwrap_or(HeapReading {
            in_use: 0,
            high_water: 0,
        });
        self.latest = Some(Snapshot {
            sequence: self.sequence,
            taken_at_us: now_us,
            available,
            cpu_permille: reading.cpu_permille.unwrap_or(0),
            tasks: reading.tasks.unwrap_or(0),
            heap_in_use: heap.in_use,
            heap_high_water: heap.high_water,
            features: self.features,
            messages: self.messages,
            mean_interval_us_q4: self.mean.mean_q4(),
            intervals: *self.intervals.counts(),
        });
        self.sequence = self.sequence.wrapping_add(1);
        self.last_sample_us = Some(now_us);
        true
    }

    /// The latest sample, or `None` before the first.
    pub fn latest(&self) -> Option<&Snapshot<B>> {
        self.latest.as_ref()
    }
}

// The limits of a build, checked where they are read so that a value the layout cannot hold stops
// the build and does not become a node that samples at the wrong period.
const _: () = {
    assert!(
        crate::caps::SNAPSHOT_HISTOGRAM_BUCKETS >= 1
            && crate::caps::SNAPSHOT_HISTOGRAM_BUCKETS <= MAX_BUCKETS,
        "SNAPSHOT_HISTOGRAM_BUCKETS is from 1 to 32"
    );
    assert!(
        crate::caps::SNAPSHOT_PERIOD_MS >= 1
            && crate::caps::SNAPSHOT_PERIOD_MS <= (MAX_TIMEOUT_TICKS / 1000) as usize,
        "SNAPSHOT_PERIOD_MS is from 1 to 2147483"
    );
};

/// The sampler a build has: `SNAPSHOT_HISTOGRAM_BUCKETS` buckets.
pub type BuildSampler = Sampler<{ crate::caps::SNAPSHOT_HISTOGRAM_BUCKETS }>;

impl BuildSampler {
    /// A sampler of the build's period, `SNAPSHOT_PERIOD_MS`, for an image whose capabilities are
    /// the bits of `features`.
    pub fn for_build(features: u64) -> Self {
        // The period was checked against the range above, where the limit is read.
        match Self::new(crate::caps::SNAPSHOT_PERIOD_MS as u32 * 1000, features) {
            Ok(sampler) => sampler,
            Err(PeriodOutOfRange) => unreachable!("checked at compile time"),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    struct Fixed(ResourceReading);

    impl ResourceSource for Fixed {
        fn read(&mut self) -> ResourceReading {
            self.0
        }
    }

    struct Counting {
        reads: u32,
    }

    impl ResourceSource for Counting {
        fn read(&mut self) -> ResourceReading {
            self.reads += 1;
            ResourceReading::default()
        }
    }

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
    fn an_interval_falls_in_the_bucket_of_its_highest_bit_and_the_last_takes_the_rest() {
        assert_eq!(bucket_of(0, 32), 0);
        assert_eq!(bucket_of(1, 32), 0);
        assert_eq!(bucket_of(2, 32), 1);
        assert_eq!(bucket_of(3, 32), 1);
        assert_eq!(bucket_of(4, 32), 2);
        assert_eq!(bucket_of(1023, 32), 9);
        assert_eq!(bucket_of(1024, 32), 10);
        assert_eq!(bucket_of(u32::MAX, 32), 31);
        assert_eq!(
            bucket_of(u32::MAX, 4),
            3,
            "the last bucket takes everything above"
        );
        assert_eq!(bucket_of(5, 1), 0);
    }

    /// The reference: the largest `k` with `2^k <= v`, found by trying each, and 0 below 2.
    fn reference_bucket(v: u32, buckets: usize) -> usize {
        let mut best = 0usize;
        for k in 1..32u32 {
            if u64::from(v) >= (1u64 << k) {
                best = k as usize;
            }
        }
        best.min(buckets - 1)
    }

    #[test]
    fn the_histogram_agrees_with_a_reference_over_a_recorded_trace() {
        fn run<const B: usize>(seed: u64) {
            let mut rng = Rng(seed | 1);
            let mut histogram = IntervalHistogram::<B>::new();
            let mut expected = [0u32; B];
            for _ in 0..5000 {
                // Intervals spread over many magnitudes, edges of buckets included.
                let magnitude = (rng.next() % 33) as u32;
                let base = if magnitude == 32 {
                    u32::MAX
                } else {
                    1u32 << magnitude
                };
                let interval = base.wrapping_add((rng.next() % 3) as u32).wrapping_sub(1);
                histogram.observe(interval);
                expected[reference_bucket(interval, B)] += 1;
            }
            assert_eq!(histogram.counts(), &expected, "B = {B}, seed {seed}");
            assert_eq!(histogram.counts().iter().sum::<u32>(), 5000);
        }
        for seed in 1..=20 {
            run::<1>(seed);
            run::<4>(seed);
            run::<24>(seed);
            run::<32>(seed);
        }
    }

    #[test]
    fn a_bucket_saturates_and_does_not_wrap() {
        let mut histogram = IntervalHistogram::<4> {
            counts: [u32::MAX; 4],
        };
        histogram.observe(0);
        histogram.observe(100);
        assert_eq!(histogram.counts(), &[u32::MAX; 4]);
    }

    #[test]
    fn the_mean_follows_the_exact_recurrence_to_within_half_a_microsecond() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut mean = Ewma::default();
        let mut exact = 0f64;
        for step in 0..20_000 {
            let value = (rng.next() % 1_000_000) as u32;
            mean.observe(value);
            exact = if step == 0 {
                f64::from(value)
            } else {
                exact + (f64::from(value) - exact) / 8.0
            };
            let ours = mean.mean_q4() as f64 / 16.0;
            assert!(
                (ours - exact).abs() < 0.6,
                "step {step}: {ours} against {exact}"
            );
        }
    }

    #[test]
    fn the_first_value_is_the_mean_and_a_constant_input_settles_near_it() {
        let mut mean = Ewma::default();
        mean.observe(1000);
        assert_eq!(mean.mean_q4(), 1000 * 16);
        for _ in 0..200 {
            mean.observe(2000);
        }
        let settled = mean.mean_q4() as f64 / 16.0;
        assert!(
            (2000.0 - settled).abs() < 7.0 / 16.0 + f64::EPSILON,
            "{settled}"
        );
    }

    #[test]
    fn the_first_poll_samples_at_once_and_then_each_period() {
        let mut sampler = Sampler::<8>::new(100, 0b101).unwrap();
        let mut source = Counting { reads: 0 };
        assert!(sampler.latest().is_none());
        assert!(sampler.poll(1_000, &mut source));
        assert!(!sampler.poll(1_099, &mut source));
        assert_eq!(
            source.reads, 1,
            "the source is asked only when a sample is taken"
        );
        assert!(sampler.poll(1_100, &mut source));
        // Several periods passed: one sample, and the next period counts from it.
        assert!(sampler.poll(9_000, &mut source));
        assert!(!sampler.poll(9_050, &mut source));
        assert!(sampler.poll(9_100, &mut source));
        assert_eq!(source.reads, 4);
        let latest = sampler.latest().unwrap();
        assert_eq!(
            (latest.sequence, latest.taken_at_us, latest.features),
            (3, 9_100, 0b101)
        );
    }

    #[test]
    fn a_period_is_counted_across_a_wrap_of_the_counter() {
        let mut sampler = Sampler::<8>::new(10, 0).unwrap();
        let mut source = Counting { reads: 0 };
        let start = u32::MAX - 5;
        assert!(sampler.poll(start, &mut source));
        assert!(!sampler.poll(3, &mut source), "9 ticks have passed");
        assert!(sampler.poll(4, &mut source), "10 ticks have passed");
    }

    #[test]
    fn a_field_the_platform_did_not_measure_is_marked_and_zero() {
        let mut sampler = Sampler::<8>::new(10, 0).unwrap();
        sampler.poll(0, &mut Fixed(ResourceReading::default()));
        let snapshot = sampler.latest().unwrap().clone();
        assert_eq!(snapshot.available, 0);
        assert_eq!(
            (
                snapshot.cpu_permille,
                snapshot.tasks,
                snapshot.heap_in_use,
                snapshot.heap_high_water
            ),
            (0, 0, 0, 0)
        );

        let measured = ResourceReading {
            cpu_permille: Some(0),
            heap: Some(HeapReading {
                in_use: 4096,
                high_water: 8192,
            }),
            tasks: None,
        };
        sampler.poll(10, &mut Fixed(measured));
        let snapshot = sampler.latest().unwrap();
        assert_eq!(snapshot.available, HAS_CPU | HAS_HEAP);
        assert_eq!(
            (snapshot.heap_in_use, snapshot.heap_high_water),
            (4096, 8192)
        );
        assert_eq!(snapshot.cpu_permille, 0, "measured as idle, not unmeasured");
    }

    #[test]
    fn message_intervals_are_counted_from_the_second_message_and_across_a_wrap() {
        let mut sampler = Sampler::<8>::new(10, 0).unwrap();
        sampler.observe_message(100);
        sampler.poll(0, &mut Counting { reads: 0 });
        let first = sampler.latest().unwrap();
        assert_eq!(first.messages, 1);
        assert_eq!(first.intervals, [0; 8], "the first message has no interval");

        sampler.observe_message(150);
        sampler.observe_message(u32::MAX - 1);
        sampler.observe_message(8);
        sampler.poll(100, &mut Counting { reads: 0 });
        let latest = sampler.latest().unwrap();
        assert_eq!(latest.messages, 4);
        // Intervals 50 (bucket 5), 4294967145 (last bucket) and 10 (bucket 3).
        assert_eq!(latest.intervals[5], 1);
        assert_eq!(latest.intervals[7], 1);
        assert_eq!(latest.intervals[3], 1);
    }

    #[test]
    fn a_period_of_nothing_or_past_the_range_is_refused() {
        assert_eq!(Sampler::<8>::new(0, 0).err(), Some(PeriodOutOfRange));
        assert_eq!(
            Sampler::<8>::new(MAX_TIMEOUT_TICKS + 1, 0).err(),
            Some(PeriodOutOfRange)
        );
        assert!(Sampler::<8>::new(MAX_TIMEOUT_TICKS, 0).is_ok());
    }

    #[test]
    fn the_layout_version_and_size_are_pinned() {
        // A change to a field of the layout must change these, and the version with them.
        assert_eq!(LAYOUT_VERSION, 1);
        assert_eq!(HEADER_SIZE, 64);
        assert_eq!(Snapshot::<24>::SIZE, 160);
        assert_eq!(Snapshot::<1>::SIZE, 68);
        assert_eq!(Snapshot::<32>::SIZE, 192);
    }

    fn sample_snapshot() -> Snapshot<4> {
        Snapshot {
            sequence: 7,
            taken_at_us: 0xDEAD_BEEF,
            available: HAS_CPU | HAS_TASKS,
            cpu_permille: 731,
            tasks: 12,
            heap_in_use: 1 << 40,
            heap_high_water: (1 << 40) + 5,
            features: 0xF0F0_0F0F_1234_5678,
            messages: u64::MAX - 3,
            mean_interval_us_q4: 123_456,
            intervals: [1, 2, 3, u32::MAX],
        }
    }

    #[test]
    fn a_snapshot_is_read_back_as_it_was_written() {
        let snapshot = sample_snapshot();
        let mut bytes = [0u8; Snapshot::<4>::SIZE];
        assert_eq!(snapshot.to_bytes(&mut bytes), Some(Snapshot::<4>::SIZE));
        assert_eq!(
            &bytes[..5],
            &[1, 0, 80, 0, 4],
            "version 1, 80 bytes, 4 buckets"
        );
        assert_eq!(Snapshot::<4>::from_bytes(&bytes), Ok(snapshot));
    }

    #[test]
    fn a_buffer_too_small_to_write_into_is_left_alone() {
        let mut bytes = [0xAAu8; Snapshot::<4>::SIZE - 1];
        assert_eq!(sample_snapshot().to_bytes(&mut bytes), None);
        assert!(bytes.iter().all(|byte| *byte == 0xAA));
    }

    #[test]
    fn a_reader_refuses_what_is_not_a_snapshot_it_can_take() {
        let mut bytes = [0u8; Snapshot::<4>::SIZE];
        sample_snapshot().to_bytes(&mut bytes);

        assert_eq!(
            Snapshot::<4>::from_bytes(&bytes[..4]),
            Err(Refused::TooShort)
        );
        assert_eq!(
            Snapshot::<4>::from_bytes(&bytes[..Snapshot::<4>::SIZE - 1]),
            Err(Refused::TooShort),
            "shorter than its own declared size"
        );
        assert_eq!(
            Snapshot::<8>::from_bytes(&bytes),
            Err(Refused::BucketsDiffer { found: 4 })
        );

        let mut zero_version = bytes;
        zero_version[0] = 0;
        assert_eq!(
            Snapshot::<4>::from_bytes(&zero_version),
            Err(Refused::UnknownVersion)
        );

        let mut short_size = bytes;
        short_size[2] = 70;
        assert_eq!(
            Snapshot::<4>::from_bytes(&short_size),
            Err(Refused::SizeBelowLayout)
        );
    }

    #[test]
    fn a_newer_version_is_read_for_the_fields_this_reader_knows() {
        let snapshot = sample_snapshot();
        let mut v1 = [0u8; Snapshot::<4>::SIZE];
        snapshot.to_bytes(&mut v1);

        // A later layout only appends: version 2, 16 more bytes, the same fields where they were.
        let mut v2: Vec<u8> = v1.to_vec();
        v2[0] = 2;
        let size = (v2.len() + 16) as u16;
        v2[2..4].copy_from_slice(&size.to_le_bytes());
        v2.extend_from_slice(&[0xEE; 16]);

        assert_eq!(Snapshot::<4>::from_bytes(&v2), Ok(snapshot));
        assert_eq!(Header::peek(&v2).unwrap().version, 2);
    }

    #[test]
    fn the_build_sampler_has_the_builds_buckets_and_period() {
        let mut sampler = BuildSampler::for_build(0);
        let mut source = Counting { reads: 0 };
        assert!(sampler.poll(0, &mut source));
        let period_us = crate::caps::SNAPSHOT_PERIOD_MS as u32 * 1000;
        assert!(!sampler.poll(period_us - 1, &mut source));
        assert!(sampler.poll(period_us, &mut source));
        assert_eq!(
            sampler.latest().unwrap().intervals.len(),
            crate::caps::SNAPSHOT_HISTOGRAM_BUCKETS
        );
    }
}
