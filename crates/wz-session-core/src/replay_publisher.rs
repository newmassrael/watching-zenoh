// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The replay cache of a publisher: the frames it last sent of each instance of a message, as it
//! sent them, answered to a subscriber that asks for them.
//!
//! # The ring
//!
//! Each instance of the message keeps a ring of `depth` frames. A frame is recorded BEFORE it is
//! sent and whether or not the send then succeeds, exactly as it is sent (a protection header in
//! front of the payload is part of it), with the time the caller gives and a sequence number the
//! cache counts across every instance. A ring that is full gives up its oldest frame.
//!
//! # An answer
//!
//! An answer begins with a snapshot of every ring: the frames are listed in ascending (time,
//! instance, sequence) order, over all instances, and the caller replies with them in that order,
//! then sends the final. A frame recorded after the snapshot is not in the answer: it is live. An
//! empty cache answers no frame, only the final. How a frame becomes replies (one reply per frame,
//! or the pieces of a segment profile) is the caller's, by the `replay-reply-shape` policy.
//!
//! # Holding the sends while an answer is served
//!
//! Under the `replay-serve-holds-sends` policy, a send of the message that comes while an answer
//! is in progress is held, so no newer frame reaches a subscriber before the replay that precedes
//! it. A PERIODIC send keeps only the latest frame of its instance; an EVENT send goes to a queue
//! of `max(1, depth / 2)` frames which, when full, gives up its oldest. Once the last answer is
//! over the held frames go out oldest first (by sequence), and a send that comes while they go
//! out is held behind them. The phases are the `replay_serving` machine
//! (`sources/session/replay_serving.scxml`): Idle, Serving, Releasing. Under the policy's `off`,
//! nothing is held, and a send goes out at once in every phase.
//!
//! # What is the host's
//!
//! The cache performs no I/O and reads no clock. Its storage is one byte area the caller gives,
//! [`Shape::storage_bytes`] long, which the cache writes when it is made and owns for its life:
//! the rings, the queue of deferred events and the cell of the latest periodic frame of each
//! instance, each cell a little-endian header and room for one frame. The tables are keyed by
//! instance and by sequence, which a statechart cannot hold; they are this sans-I/O host, and the
//! machine says only when sends are held and when they are released.

use sce_rust_runtime::helpers::session_id::SessionId;
use sce_rust_runtime::Engine;

use crate::duty_outbox::{Duties, DutyOutbox};
use crate::replay_serving::{ReplayServingActions, ReplayServingEvent, ReplayServingPolicy};

/// Where the cache stands: Idle, Serving an answer, or Releasing the sends it held.
pub use crate::replay_serving::ReplayServingState as Phase;

/// The id the serving machine is built under (SCE ADR 0045: the host gives a machine its id). A
/// constant, so the generated constructor never refuses it.
const SERVING_SESSION_ID: SessionId = sce_rust_runtime::session_id!("wz-replay-serving");

/// The header of a ring cell: time (u64), sequence (u64), length (u32), flags (u32).
const RING_HEADER: usize = 24;
/// The header of a deferred event's cell: sequence (u64), instance (u32), length plus one (u32,
/// 0 for a free cell).
const DEFER_HEADER: usize = 16;
/// The header of an instance's latest periodic cell: sequence (u64), length (u32), flags (u32).
const LATEST_HEADER: usize = 16;

/// A cell's flag: it holds a frame.
const FULL: u32 = 1;

/// How a cache is laid out: its depth, its instances and the longest frame it keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    /// How many frames each instance's ring keeps, 1 to the `REPLAY_DEPTH_MAX` the cache is made
    /// under.
    pub depth: usize,
    /// How many instances the message has, at least 1.
    pub instances: usize,
    /// The longest frame the cache keeps, in bytes, at least 1.
    pub frame_max: usize,
}

impl Shape {
    /// How many event sends the queue of held sends keeps: `max(1, depth / 2)`.
    pub fn deferral_capacity(&self) -> usize {
        (self.depth / 2).max(1)
    }

    /// How many bytes of storage a cache of this shape takes, or `None` when the count overflows.
    pub fn storage_bytes(&self) -> Option<usize> {
        let ring = self
            .instances
            .checked_mul(self.depth)?
            .checked_mul(RING_HEADER.checked_add(self.frame_max)?)?;
        let deferred = self
            .deferral_capacity()
            .checked_mul(DEFER_HEADER.checked_add(self.frame_max)?)?;
        let latest = self
            .instances
            .checked_mul(LATEST_HEADER.checked_add(self.frame_max)?)?;
        ring.checked_add(deferred)?.checked_add(latest)
    }

    /// How many ring cells there are: one per frame every instance keeps.
    pub fn ring_cells(&self) -> usize {
        self.instances.saturating_mul(self.depth)
    }

    // The cells' widths and offsets below are terms of `storage_bytes`, which a cache is made
    // only when it does not overflow: the saturating forms are the exact ones.
    fn ring_cell(&self) -> usize {
        RING_HEADER.saturating_add(self.frame_max)
    }

    fn defer_cell(&self) -> usize {
        DEFER_HEADER.saturating_add(self.frame_max)
    }

    fn latest_cell(&self) -> usize {
        LATEST_HEADER.saturating_add(self.frame_max)
    }
}

/// Why a cache could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateRefused {
    /// A depth of 0, or past the `REPLAY_DEPTH_MAX` the cache is made under.
    DepthOutOfRange,
    /// No instance.
    NoInstance,
    /// A longest frame of 0 bytes, or of 2^32 - 1 bytes or more.
    FrameMaxOutOfRange,
    /// The shape's storage overflows a `usize`, or its instances a 32-bit count.
    TooLarge,
    /// The storage given is shorter than [`Shape::storage_bytes`].
    StorageShort,
}

/// Why a frame was not recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordRefused {
    /// There is no instance of that number; nothing was recorded.
    NoSuchInstance,
    /// The frame is longer than the cache's longest; nothing was recorded.
    FrameTooLong,
}

/// What kind of send a frame is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendKind {
    /// One of a message sent on a period: while sends are held only the latest of its instance
    /// is kept.
    Periodic,
    /// One sent when something happened: while sends are held it is deferred to the queue.
    Event,
}

/// What the caller does with a frame it recorded through [`ReplayPublisher::send`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatch {
    /// Send it now.
    Now,
    /// A periodic frame held as its instance's latest.
    Held {
        /// Whether a held frame of the same instance was replaced, and will not go out.
        replaced: bool,
    },
    /// An event frame deferred to the queue.
    Deferred {
        /// Whether the queue was full and gave up its oldest frame for it.
        overwrote: bool,
    },
}

/// What the cache counts, each saturating.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Frames recorded.
    pub recorded: u64,
    /// Deferred event frames given up: the queue was full, or the frame did not fit the buffer
    /// it was released into.
    pub deferred_overwritten: u64,
    /// Held periodic frames that will not go out: replaced by a later one of their instance, or
    /// too long for the buffer they were released into.
    pub periodic_replaced: u64,
    /// Answers begun.
    pub answers: u64,
}

struct ServingBinding {
    duties: DutyOutbox,
}

impl ServingBinding {
    const HOLD_SENDS: u8 = 1 << 0;
}

impl ReplayServingActions for ServingBinding {
    const REALIZATION: ::sce_rust_runtime::ActionRealization =
        ::sce_rust_runtime::ActionRealization::Performs;

    fn hold_sends(&mut self) {
        self.duties.record(Self::HOLD_SENDS);
    }

    // The release is the host's loop over what it held (`ReplayPublisher::next_held`), which
    // runs only in `Releasing`; the phase is what it reads, so the duty itself carries nothing.
    fn release_sends(&mut self) {}
}

// The cells lie inside the storage `new` measured, so the reads and writes below find their
// bytes; one that did not would read 0 and write nothing, as a free cell.

fn read_u64(bytes: &[u8], at: usize) -> u64 {
    bytes
        .get(at..)
        .and_then(|rest| rest.first_chunk::<8>())
        .map_or(0, |word| u64::from_le_bytes(*word))
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    bytes
        .get(at..)
        .and_then(|rest| rest.first_chunk::<4>())
        .map_or(0, |word| u32::from_le_bytes(*word))
}

fn write_u64(bytes: &mut [u8], at: usize, value: u64) {
    if let Some(word) = bytes
        .get_mut(at..)
        .and_then(|rest| rest.first_chunk_mut::<8>())
    {
        *word = value.to_le_bytes();
    }
}

fn write_u32(bytes: &mut [u8], at: usize, value: u32) {
    if let Some(word) = bytes
        .get_mut(at..)
        .and_then(|rest| rest.first_chunk_mut::<4>())
    {
        *word = value.to_le_bytes();
    }
}

/// The `len` bytes at `at`.
fn read_bytes(bytes: &[u8], at: usize, len: usize) -> &[u8] {
    bytes
        .get(at..)
        .and_then(|rest| rest.get(..len))
        .unwrap_or_default()
}

/// `frame` written at `at`.
fn write_bytes(bytes: &mut [u8], at: usize, frame: &[u8]) {
    if let Some(cell) = bytes
        .get_mut(at..)
        .and_then(|rest| rest.get_mut(..frame.len()))
    {
        cell.copy_from_slice(frame);
    }
}

/// The key an answer orders its frames by.
type OrderKey = (u64, usize, u64);

/// The replay cache of one message, over the caller's storage.
pub struct ReplayPublisher<'a> {
    storage: &'a mut [u8],
    shape: Shape,
    holds_sends: bool,
    /// Whether the sends are held now: from an answer's start to the end of the release.
    holding: bool,
    answers_in_progress: usize,
    next_seq: u64,
    counts: Counts,
    engine: Engine<ReplayServingPolicy<ServingBinding>>,
}

impl<'a> ReplayPublisher<'a> {
    /// A cache of `shape` over `storage`, empty. `depth_max` is the `REPLAY_DEPTH_MAX` of the
    /// session limits the cache is made under, and `holds_sends` the `replay-serve-holds-sends`
    /// policy of that session's snapshot. A refusal writes none of `storage`.
    pub fn new(
        storage: &'a mut [u8],
        shape: Shape,
        depth_max: crate::limit_binding::Quota,
        holds_sends: bool,
    ) -> Result<Self, CreateRefused> {
        if shape.depth == 0 || !depth_max.admits(shape.depth) {
            return Err(CreateRefused::DepthOutOfRange);
        }
        if shape.instances == 0 {
            return Err(CreateRefused::NoInstance);
        }
        if shape.frame_max == 0 || shape.frame_max >= u32::MAX as usize {
            return Err(CreateRefused::FrameMaxOutOfRange);
        }
        let need = shape.storage_bytes().ok_or(CreateRefused::TooLarge)?;
        if u32::try_from(shape.instances).is_err() {
            return Err(CreateRefused::TooLarge);
        }
        let Some(area) = storage.get_mut(..need) else {
            return Err(CreateRefused::StorageShort);
        };
        area.fill(0);
        let mut engine = Engine::new(ReplayServingPolicy::new_with_checked_session_id(
            SERVING_SESSION_ID,
            ServingBinding {
                duties: DutyOutbox::default(),
            },
        ));
        // W3C SCXML 3.3: enter the initial `Idle` leaf, which asks for nothing.
        engine.initialize().unwrap_or_else(|never| match never {});
        let _ = engine.policy().actions().duties.take();
        Ok(Self {
            storage,
            shape,
            holds_sends,
            holding: false,
            answers_in_progress: 0,
            next_seq: 0,
            counts: Counts::default(),
            engine,
        })
    }

    fn drive(&mut self, event: ReplayServingEvent) -> Duties {
        self.engine.process_event(event);
        self.engine.policy().actions().duties.take()
    }

    /// Where the cache stands.
    pub fn phase(&self) -> Phase {
        self.engine.get_current_state()
    }

    /// The shape the cache was made with.
    pub fn shape(&self) -> Shape {
        self.shape
    }

    /// Whether the cache holds the message's sends while it answers (the policy it was made
    /// under).
    pub fn holds_sends(&self) -> bool {
        self.holds_sends
    }

    /// What the cache counted.
    pub fn counts(&self) -> Counts {
        self.counts
    }

    fn u64_at(&self, at: usize) -> u64 {
        read_u64(self.storage, at)
    }

    fn u32_at(&self, at: usize) -> u32 {
        read_u32(self.storage, at)
    }

    fn ring_at(&self, cell: usize) -> usize {
        cell.saturating_mul(self.shape.ring_cell())
    }

    /// Where the queue of deferred events starts, past the rings.
    fn defer_base(&self) -> usize {
        self.shape
            .ring_cells()
            .saturating_mul(self.shape.ring_cell())
    }

    fn defer_at(&self, slot: usize) -> usize {
        self.defer_base()
            .saturating_add(slot.saturating_mul(self.shape.defer_cell()))
    }

    fn latest_at(&self, instance: usize) -> usize {
        self.defer_base()
            .saturating_add(
                self.shape
                    .deferral_capacity()
                    .saturating_mul(self.shape.defer_cell()),
            )
            .saturating_add(instance.saturating_mul(self.shape.latest_cell()))
    }

    /// The instance ring cell `cell` belongs to; `depth` is at least 1 from `new` on.
    fn instance_of_cell(&self, cell: usize) -> usize {
        cell.checked_div(self.shape.depth).unwrap_or(0)
    }

    fn ring_full(&self, cell: usize) -> bool {
        self.u32_at(self.ring_at(cell).saturating_add(20)) & FULL != 0
    }

    fn ring_seq(&self, cell: usize) -> u64 {
        self.u64_at(self.ring_at(cell).saturating_add(8))
    }

    /// The key an answer orders a ring cell by: (time, instance, sequence).
    fn order_key(&self, cell: usize) -> OrderKey {
        (
            self.u64_at(self.ring_at(cell)),
            self.instance_of_cell(cell),
            self.ring_seq(cell),
        )
    }

    /// The length of the frame a deferred slot holds; `None` for a free slot, whose word is 0.
    fn defer_len(&self, slot: usize) -> Option<usize> {
        (self.u32_at(self.defer_at(slot).saturating_add(12)) as usize).checked_sub(1)
    }

    fn defer_seq(&self, slot: usize) -> u64 {
        self.u64_at(self.defer_at(slot))
    }

    fn latest_held(&self, instance: usize) -> bool {
        self.u32_at(self.latest_at(instance).saturating_add(12)) & FULL != 0
    }

    /// Record `frame`, sent at `time` on instance `instance`, and give its sequence number. The
    /// oldest frame of a full ring is given up for it.
    pub fn record(
        &mut self,
        instance: usize,
        time: u64,
        frame: &[u8],
    ) -> Result<u64, RecordRefused> {
        if instance >= self.shape.instances {
            return Err(RecordRefused::NoSuchInstance);
        }
        if frame.len() > self.shape.frame_max {
            return Err(RecordRefused::FrameTooLong);
        }
        let first = instance.saturating_mul(self.shape.depth);
        let last = first.saturating_add(self.shape.depth);
        // An empty cell if the ring has one, else the one of the lowest sequence, the oldest.
        let empty = (first..last).find(|&cell| !self.ring_full(cell));
        let cell = match empty {
            Some(cell) => cell,
            None => (first..last)
                .min_by_key(|&cell| self.ring_seq(cell))
                .unwrap_or(first),
        };
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let at = self.ring_at(cell);
        let bytes = &mut *self.storage;
        write_u64(bytes, at, time);
        write_u64(bytes, at.saturating_add(8), seq);
        // The length is below `frame_max`, which `new` holds under 2^32 - 1.
        write_u32(bytes, at.saturating_add(16), frame.len() as u32);
        write_u32(bytes, at.saturating_add(20), FULL);
        write_bytes(bytes, at.saturating_add(RING_HEADER), frame);
        self.counts.recorded = self.counts.recorded.saturating_add(1);
        Ok(seq)
    }

    /// Record `frame` as [`ReplayPublisher::record`] does, and say whether it goes out now or is
    /// held: held only while an answer is in progress or the held frames are going out, and only
    /// under the `replay-serve-holds-sends` policy.
    pub fn send(
        &mut self,
        instance: usize,
        time: u64,
        frame: &[u8],
        kind: SendKind,
    ) -> Result<Dispatch, RecordRefused> {
        let seq = self.record(instance, time, frame)?;
        if !self.holding {
            return Ok(Dispatch::Now);
        }
        Ok(match kind {
            SendKind::Periodic => {
                let replaced = self.latest_held(instance);
                let at = self.latest_at(instance);
                let bytes = &mut *self.storage;
                write_u64(bytes, at, seq);
                write_u32(bytes, at.saturating_add(8), frame.len() as u32);
                write_u32(bytes, at.saturating_add(12), FULL);
                write_bytes(bytes, at.saturating_add(LATEST_HEADER), frame);
                if replaced {
                    self.counts.periodic_replaced = self.counts.periodic_replaced.saturating_add(1);
                }
                Dispatch::Held { replaced }
            }
            SendKind::Event => {
                let capacity = self.shape.deferral_capacity();
                let free = (0..capacity).find(|&slot| self.defer_len(slot).is_none());
                let (slot, overwrote) = match free {
                    Some(slot) => (slot, false),
                    None => {
                        let oldest = (0..capacity)
                            .min_by_key(|&slot| self.defer_seq(slot))
                            .unwrap_or(0);
                        (oldest, true)
                    }
                };
                let at = self.defer_at(slot);
                let bytes = &mut *self.storage;
                write_u64(bytes, at, seq);
                // The instance is below `instances`, which `new` holds to 32 bits.
                write_u32(bytes, at.saturating_add(8), instance as u32);
                // Below `frame_max`, itself below 2^32 - 1: the length plus one fits.
                write_u32(
                    bytes,
                    at.saturating_add(12),
                    (frame.len() as u32).saturating_add(1),
                );
                write_bytes(bytes, at.saturating_add(DEFER_HEADER), frame);
                if overwrote {
                    self.counts.deferred_overwritten =
                        self.counts.deferred_overwritten.saturating_add(1);
                }
                Dispatch::Deferred { overwrote }
            }
        })
    }

    /// How many frames are held: deferred events and latest periodic frames.
    pub fn held(&self) -> usize {
        let deferred = (0..self.shape.deferral_capacity())
            .filter(|&slot| self.defer_len(slot).is_some())
            .count();
        let latest = (0..self.shape.instances)
            .filter(|&instance| self.latest_held(instance))
            .count();
        deferred.saturating_add(latest)
    }

    /// How many frames the rings hold.
    pub fn len(&self) -> usize {
        (0..self.shape.ring_cells())
            .filter(|&cell| self.ring_full(cell))
            .count()
    }

    /// Whether the rings hold no frame.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// An answer begins: write into `order` the ring cells of every frame the cache holds, in
    /// ascending (time, instance, sequence) order, and give how many. `order` has room for
    /// [`Shape::ring_cells`]; a shorter one is given the first frames of that order that fit.
    /// The frames stay readable through [`ReplayPublisher::frame`] until the next record, so a
    /// caller that sends them after it lets go of the cache copies them first.
    ///
    /// Every answer that begins is ended by [`ReplayPublisher::end_answer`].
    pub fn begin_answer(&mut self, order: &mut [usize]) -> usize {
        self.answers_in_progress = self.answers_in_progress.saturating_add(1);
        self.counts.answers = self.counts.answers.saturating_add(1);
        if self
            .drive(ReplayServingEvent::AnswerBegun)
            .has(ServingBinding::HOLD_SENDS)
        {
            self.holding = self.holds_sends;
        }
        let mut listed = 0usize;
        let mut last: Option<OrderKey> = None;
        // Each pass takes the smallest key past the last one listed: at most one ring per
        // instance, and no allocation.
        for slot in order.iter_mut() {
            let next = (0..self.shape.ring_cells())
                .filter(|&cell| self.ring_full(cell))
                .map(|cell| (self.order_key(cell), cell))
                .filter(|(key, _)| match last {
                    None => true,
                    Some(last) => *key > last,
                })
                .min_by_key(|(key, _)| *key);
            let Some((key, cell)) = next else {
                break;
            };
            *slot = cell;
            listed = listed.saturating_add(1);
            last = Some(key);
        }
        listed
    }

    /// The frame a ring cell holds; empty for a cell that holds none or a cell the cache does not
    /// have.
    pub fn frame(&self, cell: usize) -> &[u8] {
        if cell >= self.shape.ring_cells() || !self.ring_full(cell) {
            return &[];
        }
        let at = self.ring_at(cell);
        let len = self.u32_at(at.saturating_add(16)) as usize;
        read_bytes(self.storage, at.saturating_add(RING_HEADER), len)
    }

    /// The instance a ring cell belongs to; `None` for a cell the cache does not have.
    pub fn instance_of(&self, cell: usize) -> Option<usize> {
        if cell < self.shape.ring_cells() {
            Some(self.instance_of_cell(cell))
        } else {
            None
        }
    }

    /// An answer that [`ReplayPublisher::begin_answer`] began is over: its final was sent, or it
    /// was given up. When it was the last one in progress the held frames start going out, through
    /// [`ReplayPublisher::next_held`]. An end with no answer in progress changes nothing.
    pub fn end_answer(&mut self) {
        if self.answers_in_progress == 0 {
            return;
        }
        self.answers_in_progress = self.answers_in_progress.saturating_sub(1);
        if self.answers_in_progress == 0 {
            let _ = self.drive(ReplayServingEvent::AnswerEnded);
        }
    }

    /// While the held frames go out: copy the oldest held frame into `out` and give its length,
    /// or, once none is left, end the release and give `None`. In any other phase it gives `None`
    /// and moves nothing. A frame longer than `out` is given up (counted as its kind is) so that
    /// the release always ends; an `out` of the cache's longest frame never gives one up.
    pub fn next_held(&mut self, out: &mut [u8]) -> Option<usize> {
        if self.phase() != Phase::Releasing {
            return None;
        }
        loop {
            let deferred = (0..self.shape.deferral_capacity())
                .filter(|&slot| self.defer_len(slot).is_some())
                .map(|slot| (self.defer_seq(slot), false, slot))
                .min_by_key(|(seq, _, _)| *seq);
            let latest = (0..self.shape.instances)
                .filter(|&instance| self.latest_held(instance))
                .map(|instance| (self.u64_at(self.latest_at(instance)), true, instance))
                .min_by_key(|(seq, _, _)| *seq);
            let oldest = match (deferred, latest) {
                (Some(d), Some(l)) => Some(if d.0 <= l.0 { d } else { l }),
                (one, None) | (None, one) => one,
            };
            let Some((_, periodic, index)) = oldest else {
                self.holding = false;
                let _ = self.drive(ReplayServingEvent::Released);
                return None;
            };
            let (at, header, len) = if periodic {
                let at = self.latest_at(index);
                (
                    at,
                    LATEST_HEADER,
                    self.u32_at(at.saturating_add(8)) as usize,
                )
            } else {
                let at = self.defer_at(index);
                (at, DEFER_HEADER, self.defer_len(index).unwrap_or(0))
            };
            // Free the cell: the flags of a latest cell and the length of a deferred one share
            // the word at 12.
            write_u32(self.storage, at.saturating_add(12), 0);
            if len > out.len() {
                if periodic {
                    self.counts.periodic_replaced = self.counts.periodic_replaced.saturating_add(1);
                } else {
                    self.counts.deferred_overwritten =
                        self.counts.deferred_overwritten.saturating_add(1);
                }
                continue;
            }
            let held = read_bytes(self.storage, at.saturating_add(header), len);
            if let Some(into) = out.get_mut(..held.len()) {
                into.copy_from_slice(held);
            }
            return Some(len);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// The `REPLAY_DEPTH_MAX` a session made with nothing stated holds.
    const DEPTH_MAX: crate::limit_binding::Quota =
        crate::limits::SessionLimits::BUILD.replay_depth_max();

    fn shape(depth: usize, instances: usize, frame_max: usize) -> Shape {
        Shape {
            depth,
            instances,
            frame_max,
        }
    }

    fn storage(shape: Shape) -> Vec<u8> {
        vec![0xA5; shape.storage_bytes().unwrap()]
    }

    /// The frames an answer gives, in order.
    fn answer(cache: &mut ReplayPublisher<'_>) -> Vec<Vec<u8>> {
        let mut order = vec![usize::MAX; cache.shape().ring_cells()];
        let n = cache.begin_answer(&mut order);
        let frames = order[..n]
            .iter()
            .map(|&cell| cache.frame(cell).to_vec())
            .collect();
        cache.end_answer();
        frames
    }

    /// Every held frame the release hands out, until it ends.
    fn drain(cache: &mut ReplayPublisher<'_>) -> Vec<Vec<u8>> {
        let mut out = vec![0u8; cache.shape().frame_max];
        let mut sent = Vec::new();
        while let Some(len) = cache.next_held(&mut out) {
            sent.push(out[..len].to_vec());
        }
        sent
    }

    #[test]
    fn the_storage_is_the_rings_the_queue_and_one_latest_cell_per_instance() {
        let s = shape(4, 3, 10);
        assert_eq!(s.deferral_capacity(), 2);
        assert_eq!(
            s.storage_bytes(),
            Some(3 * 4 * (24 + 10) + 2 * (16 + 10) + 3 * (16 + 10))
        );
        assert_eq!(shape(1, 1, 1).deferral_capacity(), 1, "never below one");
        assert_eq!(shape(3, 1, 1).deferral_capacity(), 1);
        assert_eq!(shape(usize::MAX, 2, 1).storage_bytes(), None);
    }

    #[test]
    fn a_cache_is_refused_by_name_for_each_bad_shape() {
        let mut bytes = vec![0u8; 4096];
        assert_eq!(
            ReplayPublisher::new(&mut bytes, shape(0, 1, 4), DEPTH_MAX, false).err(),
            Some(CreateRefused::DepthOutOfRange)
        );
        assert_eq!(
            ReplayPublisher::new(
                &mut bytes,
                shape(crate::caps::REPLAY_DEPTH_MAX + 1, 1, 4),
                DEPTH_MAX,
                false
            )
            .err(),
            Some(CreateRefused::DepthOutOfRange)
        );
        assert_eq!(
            ReplayPublisher::new(&mut bytes, shape(1, 0, 4), DEPTH_MAX, false).err(),
            Some(CreateRefused::NoInstance)
        );
        assert_eq!(
            ReplayPublisher::new(&mut bytes, shape(1, 1, 0), DEPTH_MAX, false).err(),
            Some(CreateRefused::FrameMaxOutOfRange)
        );
        let s = shape(1, 2, 8);
        let mut short = vec![0u8; s.storage_bytes().unwrap() - 1];
        assert_eq!(
            ReplayPublisher::new(&mut short, s, DEPTH_MAX, false).err(),
            Some(CreateRefused::StorageShort)
        );
    }

    #[test]
    fn an_empty_cache_answers_no_frame() {
        let s = shape(2, 2, 4);
        let mut bytes = storage(s);
        let mut cache = ReplayPublisher::new(&mut bytes, s, DEPTH_MAX, false).unwrap();
        assert!(cache.is_empty());
        assert!(answer(&mut cache).is_empty());
        assert_eq!(cache.phase(), Phase::Releasing, "the answer is over");
        assert!(drain(&mut cache).is_empty());
        assert_eq!(cache.phase(), Phase::Idle);
    }

    /// The order is (time, instance, sequence) over every instance: an older frame of a later
    /// instance comes before a newer one of an earlier instance, and two frames of one time are
    /// told apart by instance, then by sequence.
    #[test]
    fn an_answer_lists_every_instance_in_time_instance_sequence_order() {
        let s = shape(3, 2, 4);
        let mut bytes = storage(s);
        let mut cache = ReplayPublisher::new(&mut bytes, s, DEPTH_MAX, false).unwrap();
        cache.record(0, 30, b"a30").unwrap();
        cache.record(1, 10, b"b10").unwrap();
        cache.record(0, 20, b"a20").unwrap();
        cache.record(1, 20, b"b20").unwrap();
        cache.record(0, 20, b"a2x").unwrap();
        assert_eq!(
            answer(&mut cache),
            vec![
                b"b10".to_vec(),
                b"a20".to_vec(),
                b"a2x".to_vec(),
                b"b20".to_vec(),
                b"a30".to_vec()
            ]
        );
    }

    #[test]
    fn a_full_ring_gives_up_its_oldest_frame_and_only_its_own() {
        let s = shape(2, 2, 4);
        let mut bytes = storage(s);
        let mut cache = ReplayPublisher::new(&mut bytes, s, DEPTH_MAX, false).unwrap();
        cache.record(1, 1, b"keep").unwrap();
        cache.record(0, 2, b"old").unwrap();
        cache.record(0, 3, b"mid").unwrap();
        cache.record(0, 4, b"new").unwrap();
        assert_eq!(
            answer(&mut cache),
            vec![b"keep".to_vec(), b"mid".to_vec(), b"new".to_vec()]
        );
        assert_eq!(cache.record(2, 5, b"x"), Err(RecordRefused::NoSuchInstance));
        assert_eq!(
            cache.record(0, 5, b"12345"),
            Err(RecordRefused::FrameTooLong)
        );
        assert_eq!(
            cache.counts().recorded,
            4,
            "a refused frame is not recorded"
        );
    }

    /// The snapshot is the ring as it stood when the answer began: a frame recorded after it is
    /// not in it, even while the answer is still being sent.
    #[test]
    fn an_answer_is_the_snapshot_taken_when_it_began() {
        let s = shape(4, 1, 4);
        let mut bytes = storage(s);
        let mut cache = ReplayPublisher::new(&mut bytes, s, DEPTH_MAX, false).unwrap();
        cache.record(0, 1, b"one").unwrap();
        cache.record(0, 2, b"two").unwrap();
        let mut order = vec![0; s.ring_cells()];
        let n = cache.begin_answer(&mut order);
        let before: Vec<Vec<u8>> = order[..n]
            .iter()
            .map(|&cell| cache.frame(cell).to_vec())
            .collect();
        cache.record(0, 3, b"thr").unwrap();
        cache.end_answer();
        assert_eq!(n, 2);
        assert_eq!(before, vec![b"one".to_vec(), b"two".to_vec()]);
        assert_eq!(answer(&mut cache).len(), 3, "the next answer has it");
    }

    #[test]
    fn a_short_order_lists_the_first_frames_of_the_order() {
        let s = shape(3, 2, 4);
        let mut bytes = storage(s);
        let mut cache = ReplayPublisher::new(&mut bytes, s, DEPTH_MAX, false).unwrap();
        cache.record(1, 5, b"b5").unwrap();
        cache.record(0, 9, b"a9").unwrap();
        cache.record(0, 1, b"a1").unwrap();
        cache.record(1, 3, b"b3").unwrap();
        let mut order = [usize::MAX; 2];
        let n = cache.begin_answer(&mut order);
        cache.end_answer();
        assert_eq!(n, 2);
        assert_eq!(cache.frame(order[0]), b"a1");
        assert_eq!(cache.frame(order[1]), b"b3");
        assert_eq!(cache.instance_of(order[1]), Some(1));
        assert_eq!(cache.instance_of(s.ring_cells()), None);
    }

    #[test]
    fn with_the_policy_off_no_send_is_held_even_while_an_answer_is_in_progress() {
        let s = shape(2, 1, 4);
        let mut bytes = storage(s);
        let mut cache = ReplayPublisher::new(&mut bytes, s, DEPTH_MAX, false).unwrap();
        let mut order = vec![0; s.ring_cells()];
        cache.begin_answer(&mut order);
        assert_eq!(cache.phase(), Phase::Serving);
        assert_eq!(
            cache.send(0, 1, b"p", SendKind::Periodic),
            Ok(Dispatch::Now)
        );
        assert_eq!(cache.send(0, 2, b"e", SendKind::Event), Ok(Dispatch::Now));
        cache.end_answer();
        assert!(drain(&mut cache).is_empty());
        assert_eq!(cache.held(), 0);
    }

    /// Held: the latest periodic frame of each instance, and the events in a queue of
    /// max(1, depth/2) that gives up its oldest. They go out oldest first once the last answer is
    /// over, and not while any answer is still out.
    #[test]
    fn with_the_policy_on_the_sends_wait_for_the_answer_and_go_out_oldest_first() {
        let s = shape(4, 2, 4);
        let mut bytes = storage(s);
        let mut cache = ReplayPublisher::new(&mut bytes, s, DEPTH_MAX, true).unwrap();
        assert_eq!(cache.send(0, 1, b"now", SendKind::Event), Ok(Dispatch::Now));
        let mut order = vec![0; s.ring_cells()];
        cache.begin_answer(&mut order);
        // A second subscriber asks while the first answer is still out.
        cache.begin_answer(&mut order);
        assert_eq!(
            cache.send(0, 2, b"p0a", SendKind::Periodic),
            Ok(Dispatch::Held { replaced: false })
        );
        assert_eq!(
            cache.send(1, 3, b"e1", SendKind::Event),
            Ok(Dispatch::Deferred { overwrote: false })
        );
        assert_eq!(
            cache.send(0, 4, b"p0b", SendKind::Periodic),
            Ok(Dispatch::Held { replaced: true })
        );
        assert_eq!(
            cache.send(1, 5, b"e2", SendKind::Event),
            Ok(Dispatch::Deferred { overwrote: false })
        );
        assert_eq!(
            cache.send(0, 6, b"e3", SendKind::Event),
            Ok(Dispatch::Deferred { overwrote: true }),
            "a queue of depth/2 = 2 gives up its oldest, e1"
        );
        assert_eq!(cache.held(), 3);
        cache.end_answer();
        assert_eq!(cache.phase(), Phase::Serving, "one answer is still out");
        let mut out = [0u8; 4];
        assert_eq!(
            cache.next_held(&mut out),
            None,
            "nothing goes out while serving"
        );
        cache.end_answer();
        assert_eq!(cache.phase(), Phase::Releasing);
        assert_eq!(
            drain(&mut cache),
            vec![b"p0b".to_vec(), b"e2".to_vec(), b"e3".to_vec()]
        );
        assert_eq!(cache.phase(), Phase::Idle);
        assert_eq!(
            cache.send(0, 8, b"aft", SendKind::Periodic),
            Ok(Dispatch::Now)
        );
        let counts = cache.counts();
        assert_eq!(counts.deferred_overwritten, 1);
        assert_eq!(counts.periodic_replaced, 1);
        assert_eq!(counts.answers, 2);
        assert_eq!(counts.recorded, 7, "every send is recorded, held or not");
    }

    #[test]
    fn a_send_during_the_release_waits_behind_what_is_held() {
        let s = shape(6, 1, 4);
        let mut bytes = storage(s);
        let mut cache = ReplayPublisher::new(&mut bytes, s, DEPTH_MAX, true).unwrap();
        let mut order = vec![0; s.ring_cells()];
        cache.begin_answer(&mut order);
        cache.send(0, 1, b"e1", SendKind::Event).unwrap();
        cache.send(0, 2, b"e2", SendKind::Event).unwrap();
        cache.end_answer();
        let mut out = [0u8; 4];
        let len = cache.next_held(&mut out).unwrap();
        assert_eq!(&out[..len], b"e1");
        assert_eq!(
            cache.send(0, 3, b"e3", SendKind::Event),
            Ok(Dispatch::Deferred { overwrote: false })
        );
        assert_eq!(drain(&mut cache), vec![b"e2".to_vec(), b"e3".to_vec()]);
        assert_eq!(cache.phase(), Phase::Idle);
    }

    #[test]
    fn a_new_answer_during_the_release_holds_the_rest_again() {
        let s = shape(2, 1, 4);
        let mut bytes = storage(s);
        let mut cache = ReplayPublisher::new(&mut bytes, s, DEPTH_MAX, true).unwrap();
        let mut order = vec![0; s.ring_cells()];
        cache.begin_answer(&mut order);
        cache.send(0, 1, b"e1", SendKind::Event).unwrap();
        cache.end_answer();
        assert_eq!(cache.phase(), Phase::Releasing);
        cache.begin_answer(&mut order);
        assert_eq!(cache.phase(), Phase::Serving);
        let mut out = [0u8; 4];
        assert_eq!(cache.next_held(&mut out), None);
        assert_eq!(cache.held(), 1, "the held frame waits for the new answer");
        cache.end_answer();
        assert_eq!(drain(&mut cache), vec![b"e1".to_vec()]);
        assert_eq!(cache.phase(), Phase::Idle);
    }

    #[test]
    fn a_held_frame_too_long_for_the_buffer_is_given_up_and_the_release_still_ends() {
        let s = shape(2, 1, 4);
        let mut bytes = storage(s);
        let mut cache = ReplayPublisher::new(&mut bytes, s, DEPTH_MAX, true).unwrap();
        let mut order = vec![0; s.ring_cells()];
        cache.begin_answer(&mut order);
        cache.send(0, 1, b"long", SendKind::Event).unwrap();
        cache.end_answer();
        let mut out = [0u8; 2];
        assert_eq!(cache.next_held(&mut out), None);
        assert_eq!(cache.phase(), Phase::Idle);
        assert_eq!(cache.counts().deferred_overwritten, 1);
    }

    #[test]
    fn an_end_with_no_answer_changes_nothing() {
        let s = shape(1, 1, 1);
        let mut bytes = storage(s);
        let mut cache = ReplayPublisher::new(&mut bytes, s, DEPTH_MAX, true).unwrap();
        cache.end_answer();
        assert_eq!(cache.phase(), Phase::Idle);
        assert_eq!(cache.send(0, 0, b"x", SendKind::Event), Ok(Dispatch::Now));
    }
}
