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
//! how they were spaced (an [`IntervalHistogram`] and the sum of the intervals). What only the
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
//! A minimum, a maximum and a mean hide the tail of a distribution, and a histogram does not. The
//! buckets are on a base-2 scale: bucket 0 holds intervals of 0 and 1 microsecond and bucket `b` of
//! at least 1 holds `2^b` up to `2^(b+1) - 1`, the last bucket everything above.
//!
//! The counters are cumulative and 64 bits wide, and the snapshot carries the sum of the intervals
//! beside them, the form a histogram has everywhere: a reader takes two snapshots and the
//! difference of their sums over the difference of their bucket totals is the exact mean interval
//! of the time between them, over any window it chooses. A counter that saturated would stop
//! counting after 71 minutes at a million messages a second in one bucket, and one that wrapped at
//! 32 bits would need the reader to know it had; 64 bits do neither in the life of a node.
//!
//! An interval is the difference of two readings of the 32-bit counter
//! ([`interval_between`]) from the latest message before it: the first message has none, and a span
//! of 2^31 microseconds (35 minutes) or more is not counted as an interval, because nothing could
//! tell it from a counter that went round. Two receivers on two threads can store their readings
//! out of order, and a reading a little behind the latest ([`is_skew`]) leaves the latest where it
//! was and is only counted, so that a delayed receiver does not put a span in the histogram that no
//! gap between messages made.
//!
//! # Who counts the messages
//!
//! The sampler does not: it is handed what the counter has seen. A host with one thread to count on
//! uses [`MessageStats`]. The receive path of a node runs on several threads, and counts with the
//! lock-free `IntervalMeter` (`interval_meter`), which takes the same step and the same rule.
//!
//! # The layout
//!
//! [`Snapshot::to_bytes`] writes little-endian bytes: a header of [`HEADER_SIZE`] bytes that begins
//! with the layout version, the total size and the bucket count, then the histogram. A later version
//! only appends fields, never moves one, so [`Snapshot::from_bytes`] reads the fields it knows from
//! a newer buffer and skips the rest by the size in the header. The version and the size are pinned
//! by a test, so a change to a field cannot pass without changing them.

use crate::wrapping_ticks::{elapsed, until_due, MAX_TIMEOUT_TICKS};

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
/// [`Snapshot::events_dropped`] was measured: the host has an event ring and said how many events
/// it refused.
pub const HAS_EVENTS: u8 = 1 << 3;

/// The bits of [`Snapshot::features`], one for each instrument of the observation plane an image
/// can have (`docs/observation-plane.md`). A bit is assigned once and never moved or reused, and a
/// reader ignores the bits it does not know, which is how an image with a later instrument is read
/// by an older reader. The host sets the bits of the instruments it was built with.
///
/// The bits are the declaration's (`observation_bit` of each capability in `deploy/wz-config.toml`),
/// generated into `feature_bits_generated.rs` and bound to names here, so the layout's promise and
/// the capability it names are one fact in one place and `wz_config.py --check` fails a bit that
/// was changed in one and not the other.
pub mod feature_bits {
    use crate::feature_bits_generated as generated;

    /// The clock the program registers (`clock-source`).
    pub const CLOCK_SOURCE: u64 = generated::CLOCK_SOURCE;
    /// The event ring (`event-ring`).
    pub const EVENT_RING: u64 = generated::EVENT_RING;
    /// The supervisor (`supervision`).
    pub const SUPERVISION: u64 = generated::SUPERVISION;
    /// This snapshot (`resource-snapshot`).
    pub const RESOURCE_SNAPSHOT: u64 = generated::RESOURCE_SNAPSHOT;

    /// Each bit and the capability it names, in bit order.
    pub const NAMES: [(u64, &str); generated::NAMES.len()] = generated::NAMES;
}

/// What the platform could say about the node now. A field left `None` was not measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceReading {
    /// How much of the time the CPU was busy since the last reading, in thousandths.
    pub cpu_permille: Option<u16>,
    /// Bytes on the heap in use, and the most there have been.
    pub heap: Option<HeapReading>,
    /// How many tasks the node runs.
    pub tasks: Option<u16>,
    /// How many events the node's event ring refused because it was full. Not the platform's to
    /// say: the host that holds the ring fills it in after the platform's source has answered, so
    /// the snapshot states the ring's loss in the one place a reader looks at a node's load.
    pub events_dropped: Option<u32>,
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
    counts: [u64; B],
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
    pub const fn counts(&self) -> &[u64; B] {
        &self.counts
    }
}

impl<const B: usize> Default for IntervalHistogram<B> {
    fn default() -> Self {
        Self::new()
    }
}

/// How far behind the latest reading a message's own reading can be and still be skew: 2^20
/// microseconds, about a second.
pub const SKEW_LIMIT_US: u32 = 1 << 20;

/// The span from `previous` to `now`, both microsecond readings of a counter that wraps at 2^32,
/// or `None` when it is not an interval.
///
/// A span of 2^31 microseconds (35 minutes) or more is not one: the comparison cannot tell it from
/// a counter that went round. A span that runs backwards is not one either; it is skew
/// ([`is_skew`]) or it is the same unmeasurable span seen from the other side. The message is
/// counted whether or not it made an interval.
pub const fn interval_between(previous: u32, now: u32) -> Option<u32> {
    let span = now.wrapping_sub(previous);
    if span > MAX_TIMEOUT_TICKS {
        None
    } else {
        Some(span)
    }
}

/// Whether `now` is a reading taken a little before `previous`, by no more than [`SKEW_LIMIT_US`].
///
/// A receiver reads the clock and then stores the reading, and between the two another receiver on
/// another thread can store a later one. The message of the first is then not the latest, and it
/// is neither the start nor the end of an interval: counting it would put two spans in the
/// histogram that no gap between messages produced, one running backwards and the next inflated by
/// the whole delay. So the latest reading stays the previous one and the skewed message is only
/// counted.
///
/// Only a small step back is skew. A reading far behind is what a counter that went round after a
/// long silence looks like, and treating it as skew would make the counter ignore every message
/// until it came round again, so that one starts afresh.
pub const fn is_skew(previous: u32, now: u32) -> bool {
    let behind = previous.wrapping_sub(now);
    behind != 0 && behind <= SKEW_LIMIT_US
}

/// What was seen of the messages since the counter began: how many, how they were spaced, and the
/// sum of the intervals. All of it is cumulative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageReading<const B: usize> {
    /// How many messages were counted.
    pub messages: u64,
    /// The sum of the intervals counted, in microseconds. Over the total of the buckets it is the
    /// mean interval; the difference of two readings' sums over the difference of their totals is
    /// the mean over the time between them.
    pub interval_sum_us: u64,
    /// How the intervals between messages are spread.
    pub intervals: [u64; B],
}

impl<const B: usize> MessageReading<B> {
    /// A reading of a counter that has seen nothing, and the identity of [`Self::merge`].
    pub const fn empty() -> Self {
        Self {
            messages: 0,
            interval_sum_us: 0,
            intervals: [0; B],
        }
    }

    /// Add another counter's reading to this one: a node that receives on several links holds a
    /// counter for each and reports the total. Each field is a sum of counts, so the sum of the
    /// readings is what one counter over all the links would have read, except at the first
    /// message of each link, which has no interval in either. The counts saturate and never
    /// wrap, though a 64-bit count does not reach the top in the life of a node.
    pub fn merge(&mut self, other: &Self) {
        self.messages = self.messages.saturating_add(other.messages);
        self.interval_sum_us = self.interval_sum_us.saturating_add(other.interval_sum_us);
        for (mine, theirs) in self.intervals.iter_mut().zip(&other.intervals) {
            *mine = mine.saturating_add(*theirs);
        }
    }
}

impl<const B: usize> Default for MessageReading<B> {
    fn default() -> Self {
        Self::empty()
    }
}

/// The message reading of a build: `SNAPSHOT_HISTOGRAM_BUCKETS` buckets.
pub type BuildMessageReading = MessageReading<{ crate::caps::SNAPSHOT_HISTOGRAM_BUCKETS }>;

/// What a node's receive paths have counted in all, when its transports come and go.
///
/// A node counts the messages of each transport it holds, a link to a peer or a joined group, and a
/// transport that ends takes its counter with it. A reader of the snapshot takes windows by
/// subtracting two readings, so the node's reading must never fall when a transport ends, or a
/// window would be negative. The ledger keeps what ended transports had counted
/// ([`Self::retire`]) and adds it to what the live ones read now ([`Self::total`]).
///
/// The one rule is the caller's to keep, and it is the whole of why this type exists: a transport
/// is retired in the same step, under the same lock, that removes it from the set `total` is asked
/// about, so that a reader sees its count in the retired total or among the live readings and
/// never in both or in neither. Every host that holds transports does that once, in one place per
/// kind of transport, and every host's total is this type's, so the invariant is tested here and
/// not once for each host.
#[derive(Debug, Clone, Default)]
pub struct ReceiveLedger<const B: usize> {
    retired: MessageReading<B>,
}

impl<const B: usize> ReceiveLedger<B> {
    /// A ledger no transport has ended in.
    pub const fn new() -> Self {
        Self {
            retired: MessageReading::empty(),
        }
    }

    /// A transport has ended having counted `gone`: it is in the total from now on without being
    /// among the live readings.
    pub fn retire(&mut self, gone: &MessageReading<B>) {
        self.retired.merge(gone);
    }

    /// What the retired transports counted, and the live ones read now: the node's reading.
    pub fn total(&self, live: impl IntoIterator<Item = MessageReading<B>>) -> MessageReading<B> {
        let mut total = self.retired.clone();
        for reading in live {
            total.merge(&reading);
        }
        total
    }
}

/// The ledger of a build.
pub type BuildReceiveLedger = ReceiveLedger<{ crate::caps::SNAPSHOT_HISTOGRAM_BUCKETS }>;

/// The message statistics of a host with one thread to count on: the plain accumulator, with no
/// atomics. A host whose receivers run on several threads counts with an `IntervalMeter` instead.
#[derive(Debug, Clone)]
pub struct MessageStats<const B: usize> {
    histogram: IntervalHistogram<B>,
    interval_sum_us: u64,
    last_us: Option<u32>,
    messages: u64,
}

impl<const B: usize> MessageStats<B> {
    /// No message seen.
    pub const fn new() -> Self {
        Self {
            histogram: IntervalHistogram::new(),
            interval_sum_us: 0,
            last_us: None,
            messages: 0,
        }
    }

    /// A message was seen at `now_us`. It is counted, and so is the interval since the latest
    /// message when that is an [`interval_between`] the two. A reading that is [`is_skew`] leaves
    /// the latest message where it was.
    pub fn observe(&mut self, now_us: u32) {
        self.messages = self.messages.saturating_add(1);
        let Some(last) = self.last_us else {
            self.last_us = Some(now_us);
            return;
        };
        if is_skew(last, now_us) {
            return;
        }
        if let Some(interval) = interval_between(last, now_us) {
            self.histogram.observe(interval);
            self.interval_sum_us = self.interval_sum_us.saturating_add(u64::from(interval));
        }
        self.last_us = Some(now_us);
    }

    /// What has been counted.
    pub fn reading(&self) -> MessageReading<B> {
        MessageReading {
            messages: self.messages,
            interval_sum_us: self.interval_sum_us,
            intervals: *self.histogram.counts(),
        }
    }
}

impl<const B: usize> Default for MessageStats<B> {
    fn default() -> Self {
        Self::new()
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
    /// Which of the fields were measured: [`HAS_CPU`], [`HAS_HEAP`], [`HAS_TASKS`],
    /// [`HAS_EVENTS`].
    pub available: u8,
    /// How many events the node's event ring refused because it was full, or 0 when not measured.
    /// Bytes 20 to 24 of the record, which version 1 first wrote as zero: a snapshot written
    /// before this field has [`HAS_EVENTS`] clear and reads as not measured, so the layout version
    /// is the same.
    pub events_dropped: u32,
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
    /// How many messages the counter was told of, since it began.
    pub messages: u64,
    /// The sum of the message intervals counted, in microseconds, since the counter began.
    pub interval_sum_us: u64,
    /// How the intervals between messages are spread, since the counter began.
    pub intervals: [u64; B],
}

impl<const B: usize> Snapshot<B> {
    /// Write this snapshot as one JSON object, for a reader that wants text: the admin space.
    ///
    /// A part the platform did not measure is `null`, not 0, so a node that uses no CPU is told
    /// from one nobody measured. `features` names the instruments of [`feature_bits`] the image
    /// has and leaves out a bit this code does not know. The histogram is the counts of the
    /// buckets in order, bucket `i` holding the intervals of `2^i` microseconds up to but not
    /// including `2^(i+1)`, and the last one everything longer; with `interval_sum_us` and
    /// `messages` it gives the mean, and two snapshots give the mean of the time between them.
    pub fn write_json(&self, out: &mut impl core::fmt::Write) -> core::fmt::Result {
        write!(
            out,
            "{{\"version\":{},\"sequence\":{},\"taken_at_us\":{}",
            LAYOUT_VERSION, self.sequence, self.taken_at_us
        )?;
        if self.available & HAS_CPU != 0 {
            write!(out, ",\"cpu_permille\":{}", self.cpu_permille)?;
        } else {
            out.write_str(",\"cpu_permille\":null")?;
        }
        if self.available & HAS_TASKS != 0 {
            write!(out, ",\"tasks\":{}", self.tasks)?;
        } else {
            out.write_str(",\"tasks\":null")?;
        }
        if self.available & HAS_HEAP != 0 {
            write!(
                out,
                ",\"heap\":{{\"in_use\":{},\"high_water\":{}}}",
                self.heap_in_use, self.heap_high_water
            )?;
        } else {
            out.write_str(",\"heap\":null")?;
        }
        if self.available & HAS_EVENTS != 0 {
            write!(out, ",\"events_dropped\":{}", self.events_dropped)?;
        } else {
            out.write_str(",\"events_dropped\":null")?;
        }
        out.write_str(",\"features\":[")?;
        let mut first = true;
        for (bit, name) in feature_bits::NAMES {
            if self.features & bit != 0 {
                if !first {
                    out.write_char(',')?;
                }
                first = false;
                write!(out, "\"{name}\"")?;
            }
        }
        write!(
            out,
            "],\"messages\":{},\"interval_sum_us\":{},\"intervals\":[",
            self.messages, self.interval_sum_us
        )?;
        for (i, count) in self.intervals.iter().enumerate() {
            if i != 0 {
                out.write_char(',')?;
            }
            write!(out, "{count}")?;
        }
        out.write_str("]}")
    }
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
    pub const SIZE: usize = HEADER_SIZE + 8 * B;

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
        put(out, 20, &self.events_dropped.to_le_bytes());
        put(out, 24, &self.heap_in_use.to_le_bytes());
        put(out, 32, &self.heap_high_water.to_le_bytes());
        put(out, 40, &self.features.to_le_bytes());
        put(out, 48, &self.messages.to_le_bytes());
        put(out, 56, &self.interval_sum_us.to_le_bytes());
        for (index, count) in self.intervals.iter().enumerate() {
            put(out, HEADER_SIZE + 8 * index, &count.to_le_bytes());
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
        let mut intervals = [0u64; B];
        for (index, count) in intervals.iter_mut().enumerate() {
            *count = u64_at(bytes, HEADER_SIZE + 8 * index);
        }
        Ok(Self {
            sequence: u32_at(bytes, 12),
            taken_at_us: u32_at(bytes, 16),
            events_dropped: u32_at(bytes, 20),
            available: bytes[5],
            cpu_permille: u16_at(bytes, 6),
            tasks: u16_at(bytes, 8),
            heap_in_use: u64_at(bytes, 24),
            heap_high_water: u64_at(bytes, 32),
            features: u64_at(bytes, 40),
            messages: u64_at(bytes, 48),
            interval_sum_us: u64_at(bytes, 56),
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
            period_us,
            features,
            last_sample_us: None,
            sequence: 0,
            latest: None,
        })
    }

    /// Take a sample if one is due at `now_us`: the first call, and then each time the period has
    /// passed since the last. Returns whether one was taken. `messages` is what the message
    /// counter has seen, a [`MessageStats`] or an `IntervalMeter` read; `source` is asked only
    /// when a sample is taken.
    pub fn poll(
        &mut self,
        now_us: u32,
        source: &mut impl ResourceSource,
        messages: impl FnOnce() -> MessageReading<B>,
    ) -> bool {
        if !self.is_due(now_us) {
            return false;
        }
        let reading = source.read();
        self.take(now_us, reading, messages());
        true
    }

    /// Whether a sample is due at `now_us`: the first time asked, and then each time the period
    /// has passed since the last one taken. A host that asks its platform for a reading outside
    /// its own lock asks this first, then [`Self::take`]s what the platform answered.
    pub fn is_due(&self, now_us: u32) -> bool {
        match self.last_sample_us {
            None => true,
            Some(last) => elapsed(now_us, last, self.period_us),
        }
    }

    /// How many microseconds until a sample is due at `now_us`: 0 when one is due, the whole
    /// period right after one was taken. A host that sleeps between polls sleeps this long and
    /// polls once, and so takes a sample on the period however long its own loop takes, which a
    /// timer of the same period does not: it ticks a little less than a period after a sample that
    /// was taken a little after its tick, finds none due, and waits out another whole period.
    pub fn until_due_us(&self, now_us: u32) -> u32 {
        match self.last_sample_us {
            None => 0,
            Some(last) => until_due(now_us, last, self.period_us),
        }
    }

    /// Record a sample taken at `now_us` from what the platform and the message counter read,
    /// whether or not one was due: the caller has asked [`Self::is_due`].
    pub fn take(&mut self, now_us: u32, reading: ResourceReading, messages: MessageReading<B>) {
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
        if reading.events_dropped.is_some() {
            available |= HAS_EVENTS;
        }
        let heap = reading.heap.unwrap_or(HeapReading {
            in_use: 0,
            high_water: 0,
        });
        self.latest = Some(Snapshot {
            sequence: self.sequence,
            taken_at_us: now_us,
            available,
            events_dropped: reading.events_dropped.unwrap_or(0),
            cpu_permille: reading.cpu_permille.unwrap_or(0),
            tasks: reading.tasks.unwrap_or(0),
            heap_in_use: heap.in_use,
            heap_high_water: heap.high_water,
            features: self.features,
            messages: messages.messages,
            interval_sum_us: messages.interval_sum_us,
            intervals: messages.intervals,
        });
        self.sequence = self.sequence.wrapping_add(1);
        self.last_sample_us = Some(now_us);
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
            let mut expected = [0u64; B];
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
            assert_eq!(histogram.counts().iter().sum::<u64>(), 5000);
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
            counts: [u64::MAX; 4],
        };
        histogram.observe(0);
        histogram.observe(100);
        assert_eq!(histogram.counts(), &[u64::MAX; 4]);
    }

    #[test]
    fn merged_readings_are_the_sum_of_two_links_and_the_empty_reading_is_the_identity() {
        let mut a = MessageStats::<8>::new();
        let mut b = MessageStats::<8>::new();
        for now in [0u32, 100, 200, 5_000] {
            a.observe(now);
        }
        for now in [7u32, 1_007] {
            b.observe(now);
        }
        let mut total = MessageReading::<8>::empty();
        total.merge(&a.reading());
        total.merge(&b.reading());
        assert_eq!(total.messages, 6);
        assert_eq!(total.interval_sum_us, 100 + 100 + 4_800 + 1_000);
        // Four intervals, one fewer than the messages of each link: 3 and 1.
        assert_eq!(total.intervals.iter().sum::<u64>(), 4);
        let mut same = a.reading();
        same.merge(&MessageReading::empty());
        assert_eq!(same, a.reading());
        let mut full = MessageReading::<8>::empty();
        full.messages = u64::MAX;
        full.merge(&b.reading());
        assert_eq!(
            full.messages,
            u64::MAX,
            "a count saturates and does not wrap"
        );
    }

    #[test]
    fn two_readings_give_the_exact_mean_interval_of_the_time_between_them() {
        // 1000 messages 10 microseconds apart, then 1000 messages 300 apart.
        let mut stats = MessageStats::<24>::new();
        let mut now = 0u32;
        stats.observe(now);
        for _ in 0..1000 {
            now += 10;
            stats.observe(now);
        }
        let first = stats.reading();
        for _ in 0..1000 {
            now += 300;
            stats.observe(now);
        }
        let second = stats.reading();

        let total = |reading: &MessageReading<24>| reading.intervals.iter().sum::<u64>();
        // Over the whole run and over the second half alone, exactly, with no approximation.
        assert_eq!(
            second.interval_sum_us / total(&second),
            (10_000 + 300_000) / 2000
        );
        assert_eq!(
            (second.interval_sum_us - first.interval_sum_us) / (total(&second) - total(&first)),
            300,
            "the mean of the window between two readings"
        );
        assert_eq!(second.messages, 2001);
        assert_eq!(
            total(&second),
            2000,
            "every message but the first made an interval"
        );
    }

    #[test]
    fn the_first_poll_samples_at_once_and_then_each_period() {
        let mut sampler = Sampler::<8>::new(100, 0b101).unwrap();
        let mut source = Counting { reads: 0 };
        assert!(sampler.latest().is_none());
        assert!(sampler.poll(1_000, &mut source, no_messages));
        assert!(!sampler.poll(1_099, &mut source, no_messages));
        assert_eq!(
            source.reads, 1,
            "the source is asked only when a sample is taken"
        );
        assert!(sampler.poll(1_100, &mut source, no_messages));
        // Several periods passed: one sample, and the next period counts from it.
        assert!(sampler.poll(9_000, &mut source, no_messages));
        assert!(!sampler.poll(9_050, &mut source, no_messages));
        assert!(sampler.poll(9_100, &mut source, no_messages));
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
        assert!(sampler.poll(start, &mut source, no_messages));
        assert!(
            !sampler.poll(3, &mut source, no_messages),
            "9 ticks have passed"
        );
        assert!(
            sampler.poll(4, &mut source, no_messages),
            "10 ticks have passed"
        );
    }

    #[test]
    fn a_field_the_platform_did_not_measure_is_marked_and_zero() {
        let mut sampler = Sampler::<8>::new(10, 0).unwrap();
        sampler.poll(0, &mut Fixed(ResourceReading::default()), no_messages);
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
            events_dropped: None,
        };
        sampler.poll(10, &mut Fixed(measured), no_messages);
        let snapshot = sampler.latest().unwrap();
        assert_eq!(snapshot.available, HAS_CPU | HAS_HEAP);
        assert_eq!(
            (snapshot.heap_in_use, snapshot.heap_high_water),
            (4096, 8192)
        );
        assert_eq!(snapshot.cpu_permille, 0, "measured as idle, not unmeasured");
    }

    fn no_messages<const B: usize>() -> MessageReading<B> {
        MessageStats::<B>::new().reading()
    }

    #[test]
    fn the_sampler_takes_the_message_reading_it_is_handed_at_the_sample() {
        let mut sampler = Sampler::<8>::new(10, 0).unwrap();
        let mut stats = MessageStats::<8>::new();
        stats.observe(100);
        stats.observe(150);
        sampler.poll(0, &mut Counting { reads: 0 }, || stats.reading());
        let first = sampler.latest().unwrap();
        assert_eq!(first.messages, 2);
        assert_eq!(first.intervals[5], 1, "50 microseconds is bucket 5");
        assert_eq!(first.interval_sum_us, 50);
    }

    #[test]
    fn the_reading_is_asked_for_only_when_a_sample_is_taken() {
        let mut sampler = Sampler::<8>::new(100, 0).unwrap();
        let mut asked = 0;
        sampler.poll(0, &mut Counting { reads: 0 }, || {
            asked += 1;
            no_messages()
        });
        sampler.poll(50, &mut Counting { reads: 0 }, || {
            asked += 1;
            no_messages()
        });
        assert_eq!(asked, 1);
    }

    #[test]
    fn message_intervals_are_counted_from_the_second_message_and_across_a_wrap() {
        let mut stats = MessageStats::<8>::new();
        stats.observe(100);
        let first = stats.reading();
        assert_eq!(first.messages, 1);
        assert_eq!(first.intervals, [0; 8], "the first message has no interval");

        stats.observe(150);
        assert_eq!(
            stats.reading().intervals[5],
            1,
            "50 microseconds is bucket 5"
        );

        // Across the wrap of the counter: 10 microseconds, then 16.
        let mut stats = MessageStats::<8>::new();
        stats.observe(u32::MAX - 20);
        stats.observe(u32::MAX - 10);
        stats.observe(5);
        let latest = stats.reading();
        assert_eq!(latest.messages, 3);
        assert_eq!(latest.intervals[3], 1, "10 microseconds is bucket 3");
        assert_eq!(latest.intervals[4], 1, "16 microseconds is bucket 4");
        assert_eq!(latest.intervals.iter().sum::<u64>(), 2);
    }

    #[test]
    fn what_is_an_interval_what_is_skew_and_what_is_neither() {
        assert_eq!(interval_between(100, 150), Some(50));
        assert_eq!(
            interval_between(u32::MAX - 4, 5),
            Some(10),
            "across the wrap"
        );
        assert_eq!(interval_between(7, 7), Some(0));
        assert_eq!(
            interval_between(0, MAX_TIMEOUT_TICKS),
            Some(MAX_TIMEOUT_TICKS)
        );
        assert_eq!(interval_between(0, MAX_TIMEOUT_TICKS + 1), None);

        // Skew: a reading a little behind the latest, by at most about a second.
        assert_eq!(interval_between(200, 150), None, "backwards by 50");
        assert!(is_skew(200, 150));
        assert!(is_skew(5, u32::MAX - 4), "behind across the wrap");
        assert!(is_skew(SKEW_LIMIT_US, 0));
        assert!(!is_skew(SKEW_LIMIT_US + 1, 0), "further behind is not skew");
        assert!(!is_skew(7, 7), "the same reading is not behind");
        assert!(!is_skew(100, 150), "forward is not behind");
    }

    #[test]
    fn a_skewed_message_is_counted_and_leaves_the_latest_where_it_was() {
        let mut stats = MessageStats::<8>::new();
        stats.observe(1000);
        // A receiver was delayed: its reading is 50 behind the latest.
        stats.observe(950);
        let skewed = stats.reading();
        assert_eq!(skewed.messages, 2, "the message is counted");
        assert_eq!(skewed.intervals, [0; 8], "and makes no interval");
        // The next message is measured from the latest, 1000, and not from the delayed 950, so no
        // inflated span appears.
        stats.observe(1060);
        let after = stats.reading();
        assert_eq!(after.intervals[5], 1, "60 microseconds is bucket 5");
        assert_eq!(
            after.interval_sum_us, 60,
            "the delayed message added nothing"
        );
        assert_eq!(after.intervals.iter().sum::<u64>(), 1);
    }

    #[test]
    fn after_a_long_silence_the_counter_starts_afresh_and_does_not_ignore_what_follows() {
        let mut stats = MessageStats::<8>::new();
        stats.observe(1000);
        // 35 minutes and a little: not an interval, and not skew either (it is far behind seen the
        // other way), so the latest becomes this message.
        let long_after = 1000u32.wrapping_add(MAX_TIMEOUT_TICKS).wrapping_add(500);
        stats.observe(long_after);
        assert_eq!(stats.reading().intervals, [0; 8]);
        // And the messages that follow are measured from it.
        stats.observe(long_after.wrapping_add(10));
        let reading = stats.reading();
        assert_eq!(reading.intervals[3], 1, "10 microseconds is bucket 3");
        assert_eq!(reading.messages, 3);
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
        assert_eq!(Snapshot::<24>::SIZE, 256);
        assert_eq!(Snapshot::<1>::SIZE, 72);
        assert_eq!(Snapshot::<32>::SIZE, 320);
    }

    fn sample_snapshot() -> Snapshot<4> {
        Snapshot {
            sequence: 7,
            taken_at_us: 0xDEAD_BEEF,
            available: HAS_CPU | HAS_TASKS,
            events_dropped: 0,
            cpu_permille: 731,
            tasks: 12,
            heap_in_use: 1 << 40,
            heap_high_water: (1 << 40) + 5,
            features: 0xF0F0_0F0F_1234_5678,
            messages: u64::MAX - 3,
            interval_sum_us: 123_456,
            intervals: [1, 2, 3, u64::MAX],
        }
    }

    #[test]
    fn the_json_names_what_was_measured_and_nulls_what_was_not() {
        let mut text = std::string::String::new();
        sample_snapshot().write_json(&mut text).unwrap();
        // `features` is 0xF0F0_0F0F_1234_5678: of the bits this code names only bit 3 is set, and
        // the bits it does not know are left out and not guessed at.
        assert_eq!(
            text,
            "{\"version\":1,\"sequence\":7,\"taken_at_us\":3735928559,\
             \"cpu_permille\":731,\"tasks\":12,\"heap\":null,\"events_dropped\":null,\
             \"features\":[\"resource-snapshot\"],\
             \"messages\":18446744073709551612,\"interval_sum_us\":123456,\
             \"intervals\":[1,2,3,18446744073709551615]}"
        );
        let mut all = sample_snapshot();
        all.available = HAS_CPU | HAS_HEAP | HAS_TASKS;
        all.features = 0;
        all.messages = 0;
        text.clear();
        all.write_json(&mut text).unwrap();
        assert!(
            text.contains("\"heap\":{\"in_use\":1099511627776,\"high_water\":1099511627781}"),
            "{text}"
        );
        assert!(text.contains("\"features\":[]"), "{text}");
    }

    /// The invariant the ledger exists for, over every order of three things a node does: a
    /// transport counts a message, a transport ends, a transport begins. The total never falls,
    /// and it is always what every transport that ever lived counted, so a window taken between
    /// two readings is never negative and never double counts a transport that ended mid-window.
    #[test]
    fn the_total_never_falls_when_a_transport_ends_and_is_what_every_transport_counted() {
        for seed in 1..=300u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let mut ledger = ReceiveLedger::<8>::new();
            let mut live: Vec<MessageStats<8>> = Vec::new();
            let mut observed = 0u64;
            let mut clock = 0u32;
            let mut last_total = 0u64;
            for _ in 0..200 {
                match rng.next() % 5 {
                    0 => live.push(MessageStats::new()),
                    1 if !live.is_empty() => {
                        let at = (rng.next() as usize) % live.len();
                        ledger.retire(&live.remove(at).reading());
                    }
                    _ if !live.is_empty() => {
                        let at = (rng.next() as usize) % live.len();
                        clock = clock.wrapping_add((rng.next() % 5_000) as u32);
                        live[at].observe(clock);
                        observed += 1;
                    }
                    _ => {}
                }
                let total = ledger.total(live.iter().map(MessageStats::reading));
                assert!(
                    total.messages >= last_total,
                    "seed {seed}: the total fell from {last_total} to {}",
                    total.messages
                );
                last_total = total.messages;
                // Every message any transport was told of is in the total once, whether its
                // transport is still live or has ended: counted by the test itself, and not by
                // the code under test.
                assert_eq!(total.messages, observed, "seed {seed}");
            }
        }
    }

    #[test]
    fn the_time_until_a_sample_is_due_counts_down_from_the_period_and_survives_a_wrap() {
        let mut sampler = Sampler::<4>::new(1000, 0).unwrap();
        assert_eq!(
            sampler.until_due_us(7),
            0,
            "the first sample is due at once"
        );
        sampler.take(100, ResourceReading::default(), MessageReading::empty());
        assert_eq!(
            sampler.until_due_us(100),
            1000,
            "a whole period right after one"
        );
        assert_eq!(sampler.until_due_us(400), 700);
        assert_eq!(sampler.until_due_us(1099), 1);
        assert_eq!(sampler.until_due_us(1100), 0, "due exactly at the period");
        assert_eq!(sampler.until_due_us(5000), 0);
        // Across a wrap of the counter: a sample at 2^32 - 200 is due 1000 on, at 800.
        let mut wrapped = Sampler::<4>::new(1000, 0).unwrap();
        wrapped.take(
            u32::MAX - 199,
            ResourceReading::default(),
            MessageReading::empty(),
        );
        assert_eq!(
            wrapped.until_due_us(400),
            400,
            "600 of the 1000 have passed"
        );
        assert!(wrapped.is_due(800) && wrapped.until_due_us(800) == 0);
    }

    #[test]
    fn the_rings_loss_count_rides_in_the_reserved_word_and_only_counts_when_it_was_measured() {
        let mut snapshot = sample_snapshot();
        snapshot.available |= HAS_EVENTS;
        snapshot.events_dropped = 0x0102_0304;
        let mut bytes = [0u8; Snapshot::<4>::SIZE];
        snapshot.to_bytes(&mut bytes).unwrap();
        assert_eq!(&bytes[20..24], &[4, 3, 2, 1], "little-endian at byte 20");
        assert_eq!(
            bytes[..5],
            [1, 0, 96, 0, 4],
            "the layout is still version 1"
        );
        assert_eq!(Snapshot::<4>::from_bytes(&bytes), Ok(snapshot.clone()));
        let mut text = std::string::String::new();
        snapshot.write_json(&mut text).unwrap();
        assert!(text.contains("\"events_dropped\":16909060,"), "{text}");
        // What an older writer produced, zero there and the bit clear, reads as not measured.
        bytes[20..24].fill(0);
        bytes[5] &= !HAS_EVENTS;
        let older = Snapshot::<4>::from_bytes(&bytes).unwrap();
        assert_eq!((older.available & HAS_EVENTS, older.events_dropped), (0, 0));
        text.clear();
        older.write_json(&mut text).unwrap();
        assert!(text.contains("\"events_dropped\":null,"), "{text}");
    }

    #[test]
    fn the_sampler_marks_the_ring_loss_measured_only_when_the_host_gave_it() {
        let mut sampler = Sampler::<4>::new(1000, 0).unwrap();
        sampler.take(0, ResourceReading::default(), MessageReading::empty());
        let first = sampler.latest().unwrap();
        assert_eq!((first.available & HAS_EVENTS, first.events_dropped), (0, 0));
        let told = ResourceReading {
            events_dropped: Some(5),
            ..ResourceReading::default()
        };
        sampler.take(1000, told, MessageReading::empty());
        let second = sampler.latest().unwrap();
        assert_eq!(
            (second.available & HAS_EVENTS, second.events_dropped),
            (HAS_EVENTS, 5)
        );
        let none = ResourceReading {
            events_dropped: Some(0),
            ..ResourceReading::default()
        };
        sampler.take(2000, none, MessageReading::empty());
        assert_eq!(
            sampler.latest().unwrap().available & HAS_EVENTS,
            HAS_EVENTS,
            "a ring that lost nothing is measured, not absent"
        );
    }

    #[test]
    fn the_feature_bits_are_single_distinct_bits_with_distinct_names() {
        let mut seen = 0u64;
        for (bit, name) in feature_bits::NAMES {
            assert_eq!(bit.count_ones(), 1, "{name} is one bit");
            assert_eq!(seen & bit, 0, "{name} reuses a bit");
            seen |= bit;
        }
        let mut names = feature_bits::NAMES.map(|(_, name)| name);
        names.sort_unstable();
        assert!(names.windows(2).all(|pair| pair[0] != pair[1]));
        // Pinned: a bit is assigned once, so moving one is a change of layout, not of code.
        assert_eq!(feature_bits::CLOCK_SOURCE, 1);
        assert_eq!(feature_bits::EVENT_RING, 2);
        assert_eq!(feature_bits::SUPERVISION, 4);
        assert_eq!(feature_bits::RESOURCE_SNAPSHOT, 8);
    }

    /// The macro a crate states its features word with reads the features of the crate it is
    /// expanded in. Here that is this crate, which has three of the four capabilities as
    /// features: each is in the word exactly when it is on, and the fourth, which it has no
    /// feature for (the ring is `wz-node-time`'s), is off.
    #[test]
    fn a_crates_features_word_follows_the_features_the_crate_has() {
        let word = crate::built_feature_bits!();
        assert_eq!(
            word & feature_bits::RESOURCE_SNAPSHOT != 0,
            cfg!(feature = "resource-snapshot")
        );
        assert_eq!(
            word & feature_bits::SUPERVISION != 0,
            cfg!(feature = "supervision")
        );
        assert_eq!(
            word & feature_bits::CLOCK_SOURCE != 0,
            cfg!(feature = "clock-source")
        );
        assert_eq!(word & feature_bits::EVENT_RING, 0);
    }

    #[test]
    fn a_snapshot_is_read_back_as_it_was_written() {
        let snapshot = sample_snapshot();
        let mut bytes = [0u8; Snapshot::<4>::SIZE];
        assert_eq!(snapshot.to_bytes(&mut bytes), Some(Snapshot::<4>::SIZE));
        assert_eq!(
            &bytes[..5],
            &[1, 0, 96, 0, 4],
            "version 1, 96 bytes, 4 buckets"
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
        assert!(sampler.poll(0, &mut source, no_messages));
        let period_us = crate::caps::SNAPSHOT_PERIOD_MS as u32 * 1000;
        assert!(!sampler.poll(period_us - 1, &mut source, no_messages));
        assert!(sampler.poll(period_us, &mut source, no_messages));
        assert_eq!(
            sampler.latest().unwrap().intervals.len(),
            crate::caps::SNAPSHOT_HISTOGRAM_BUCKETS
        );
    }
}
