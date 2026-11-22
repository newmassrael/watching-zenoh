// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Reception supervision per stream: whether a periodic stream keeps arriving, judged against a
//! deadline of its own, and told once per loss.
//!
//! A stream is one message, of one instance, from one sender. A receiver that knows the period of
//! a stream gives it a deadline of `period x factor`, tells the supervisor each time the stream is
//! received, and polls. A stream not received for longer than its deadline is LOST: the loss is
//! told once (an edge, not a level), and the stream's error count and the node's count each go up
//! by one, held at [`ERROR_CEILING`] rather than wrapping.
//!
//! # When anything is judged
//!
//! Nothing is judged until a start delay has passed since the first poll that had a clock, and
//! then only while a condition the application supplies holds. The two gates are the
//! [`stream_activation`](crate::stream_activation) machine (`sources/session/stream_activation.scxml`).
//! Each time they open together, every stream that can time out has its deadline counted again
//! from that poll and every error count is reset, so the time the gates were shut is never charged
//! to a stream, and a stream that never arrived times out one deadline after the activation.
//!
//! A stream can time out once it has been received, or from the start when it is AWAITED: its
//! sender is known and is expected to send it, so its silence is a loss whether or not anything
//! ever came. A stream that is not awaited (an instance a sender may never use) is supervised
//! only after its first reception.
//!
//! # Senders that are absent
//!
//! The application may mark a sender absent (a device the deployment does not fit). Every stream
//! of that sender is then not judged, and a loss it was in is withdrawn without being told, until
//! the sender is marked present again, which counts its streams' deadlines from that moment. A
//! sender is an opaque number the caller gives each stream; the supervisor only compares it.
//!
//! # What is the host's
//!
//! The supervisor reads no clock, starts no task and calls no callback but the one a poll is
//! given. Time is a tick count of a monotonic source in 32 bits that wraps, handed to every call
//! that needs it as `Option<u32>`: `None` when the source cannot say what time it is. A poll
//! without a clock judges nothing and shuts the gates, so the next poll with one activates again
//! and re-bases; a reception without a clock is dated by the next poll that has one.
//!
//! The table of streams is the caller's storage: a slice of [`StreamSlot`] the supervisor
//! initialises and owns for its life, and, when the `e2e-supervision-notify` policy is
//! `last-value`, a byte area of one cell per stream for the last payload, which a loss hands back
//! so that a receiver that delivers a value with the loss has one. The number of streams is
//! bounded by the storage and by the streams its creator lends it from the runtime's
//! `E2E_SUPERVISED_STREAMS`, at most the build's (`crate::process_limits::ProcessRows`).
//!
//! The table is keyed by stream, one row each, which a statechart cannot hold; it is this sans-I/O
//! host, and the machine says only when the table is re-based. The deadline comparison is the
//! generated `tick_elapsed` ([`crate::wrapping_ticks`]).

use sce_rust_runtime::helpers::session_id::SessionId;
use sce_rust_runtime::Engine;

use crate::duty_outbox::{Duties, DutyOutbox};
use crate::stream_activation::{
    StreamActivationActions, StreamActivationEvent, StreamActivationPolicy,
};
use crate::wrapping_ticks::{elapsed, MAX_TIMEOUT_TICKS};

/// Whether a loss carries the stream's last payload: the `e2e-supervision-notify` policy itself.
/// `StatusOnly` tells the stream and its counts; `LastValue` also hands back the payload the
/// stream last carried.
pub use crate::policy::E2eSupervisionNotify as Notify;

/// Where the two gates stand: not yet clocked, delaying, inactive or active.
pub use crate::stream_activation::StreamActivationState as Phase;

/// The id the activation machine is built under (SCE ADR 0045: the host gives a machine its id).
/// A constant, so the generated constructor never refuses it.
const ACTIVATION_SESSION_ID: SessionId = sce_rust_runtime::session_id!("wz-stream-activation");

/// The longest deadline a stream can have. A deadline is passed when MORE than it has elapsed,
/// which is the generated comparison of at least one tick more, so one tick is kept below the
/// longest span [`elapsed`] can tell from a counter that went round.
pub const MAX_DEADLINE_TICKS: u32 = MAX_TIMEOUT_TICKS - 1;

/// The count at which an error count stops: a count that wrapped would read as a stream that
/// recovered.
pub const ERROR_CEILING: u8 = u8::MAX;

// The deadline is an SCE `algorithm` document (`sources/algorithms/stream_deadline.scxml`),
// committed at `out/wz-session-core/` and `include!`-ed from there (regenerated by
// `scripts/regen-codegen.sh`).
mod generated {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-session-core",
        "/stream_deadline.rs"
    ));
}

/// The deadline of a stream of `period` ticks that may miss `factor` periods: their product, or
/// `None` when either is 0 or the product is longer than [`MAX_DEADLINE_TICKS`].
pub fn deadline(period: u32, factor: u16) -> Option<u32> {
    generated::stream_deadline(period, factor)
}

/// Whether more than `deadline` ticks have passed from `base` to `now`, both readings of a counter
/// that wraps at 2^32. `deadline` is at most [`MAX_DEADLINE_TICKS`], which [`deadline`] holds.
pub fn deadline_passed(now: u32, base: u32, deadline: u32) -> bool {
    elapsed(now, base, deadline + 1)
}

/// One row of the stream table, in the caller's storage. Its layout is fixed (`repr(C)`, five
/// 32-bit words) so a C caller can size the storage from its header.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamSlot {
    base: u32,
    deadline: u32,
    sender: u32,
    value_len: u32,
    errors: u8,
    flags: u8,
    reserved: u16,
}

impl StreamSlot {
    /// A row that holds no stream.
    pub const EMPTY: Self = Self {
        base: 0,
        deadline: 0,
        sender: 0,
        value_len: 0,
        errors: 0,
        flags: 0,
        reserved: 0,
    };
}

/// Expected from the start: its sender is known, so a silence is a loss before any reception.
const AWAITED: u8 = 1 << 0;
/// Received at least once.
const RECEIVED: u8 = 1 << 1;
/// `base` is the instant the deadline counts from.
const BASED: u8 = 1 << 2;
/// The last event that moves `base` had no clock; the next poll with one dates it.
const UNDATED: u8 = 1 << 3;
/// The loss was told, and nothing has cleared it since.
const TIMED_OUT: u8 = 1 << 4;
/// Its sender is marked absent.
const EXCLUDED: u8 = 1 << 5;
/// Its value cell holds the last payload.
const HAS_VALUE: u8 = 1 << 6;

/// Why a supervisor could not be made over the storage it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateRefused {
    /// The start delay is longer than [`MAX_TIMEOUT_TICKS`].
    DelayOutOfRange,
    /// Under [`Notify::LastValue`], a value cell of 0 bytes: no payload could be kept.
    NoValueCell,
    /// Under [`Notify::LastValue`], a value cell longer than a 32-bit length.
    ValueCellTooLarge,
    /// Under [`Notify::LastValue`], fewer value bytes than one cell for every stream the table
    /// holds.
    ValueStorageShort,
}

/// Why a stream could not be added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddRefused {
    /// The period or the factor is 0, or their product is longer than [`MAX_DEADLINE_TICKS`].
    DeadlineOutOfRange,
    /// The table holds as many streams as its storage or the streams it was lent.
    Full,
}

/// Why a reception was not recorded in full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveRefused {
    /// There is no stream of that number; nothing was recorded.
    NoSuchStream,
    /// Under [`Notify::LastValue`], the payload is longer than the value cell. The reception is
    /// recorded; the value is not kept, and the one before it is forgotten, so a loss never hands
    /// back a payload older than the last reception.
    ValueTooLong,
}

/// No stream was added with that sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownSender;

/// One loss, as a poll tells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Loss<'v> {
    /// The number [`StreamSupervisor::add`] gave the stream.
    pub stream: usize,
    /// The sender the stream was added with.
    pub sender: u32,
    /// The stream's error count, this loss included.
    pub errors: u8,
    /// The node's error count, this loss included.
    pub node_errors: u8,
    /// Under [`Notify::LastValue`], the payload the stream last carried; `None` under
    /// [`Notify::StatusOnly`], and when no payload was kept since the stream was added.
    pub value: Option<&'v [u8]>,
}

struct ActivationBinding {
    duties: DutyOutbox,
}

impl ActivationBinding {
    const BEGIN_DELAY: u8 = 1 << 0;
    const ACTIVATE: u8 = 1 << 1;
}

impl StreamActivationActions for ActivationBinding {
    const REALIZATION: ::sce_rust_runtime::ActionRealization =
        ::sce_rust_runtime::ActionRealization::Performs;

    fn begin_delay(&mut self) {
        self.duties.record(Self::BEGIN_DELAY);
    }

    fn activate(&mut self) {
        self.duties.record(Self::ACTIVATE);
    }
}

/// The streams a receiver supervises, over the caller's storage.
pub struct StreamSupervisor<'a> {
    slots: &'a mut [StreamSlot],
    values: &'a mut [u8],
    cell: usize,
    capacity: usize,
    count: usize,
    engine: Engine<StreamActivationPolicy<ActivationBinding>>,
    start_delay: u32,
    delay_from: u32,
    condition: bool,
    node_errors: u8,
    notify: Notify,
}

impl<'a> StreamSupervisor<'a> {
    /// A supervisor of no stream yet, over `slots` and, under [`Notify::LastValue`], `values`
    /// cut into cells of `value_cell` bytes, one per stream. It judges nothing until
    /// `start_delay` ticks after the first poll that has a clock, and the condition holds until
    /// the application says otherwise. Under [`Notify::StatusOnly`] `values` and `value_cell`
    /// are not read, and may be empty and 0. It holds at most `streams`, the rows its creator lends
    /// it from the runtime's `E2E_SUPERVISED_STREAMS` (`crate::process_limits::ProcessRows`),
    /// whatever the storage holds beyond them.
    pub fn new(
        slots: &'a mut [StreamSlot],
        values: &'a mut [u8],
        value_cell: usize,
        start_delay: u32,
        notify: Notify,
        streams: usize,
    ) -> Result<Self, CreateRefused> {
        if start_delay > MAX_TIMEOUT_TICKS {
            return Err(CreateRefused::DelayOutOfRange);
        }
        let capacity = slots.len().min(streams);
        let cell = match notify {
            Notify::StatusOnly => 0,
            Notify::LastValue => {
                if value_cell == 0 {
                    return Err(CreateRefused::NoValueCell);
                }
                if u32::try_from(value_cell).is_err() {
                    return Err(CreateRefused::ValueCellTooLarge);
                }
                match capacity.checked_mul(value_cell) {
                    Some(need) if values.len() >= need => value_cell,
                    _ => return Err(CreateRefused::ValueStorageShort),
                }
            }
        };
        slots.fill(StreamSlot::EMPTY);
        let mut engine = Engine::new(StreamActivationPolicy::new_with_checked_session_id(
            ACTIVATION_SESSION_ID,
            ActivationBinding {
                duties: DutyOutbox::default(),
            },
        ));
        // W3C SCXML 3.3: enter the initial `Unclocked` leaf, which asks for nothing.
        engine.initialize().unwrap_or_else(|never| match never {});
        let _ = engine.policy().actions().duties.take();
        Ok(Self {
            slots,
            values,
            cell,
            capacity,
            count: 0,
            engine,
            start_delay,
            delay_from: 0,
            condition: true,
            node_errors: 0,
            notify,
        })
    }

    fn drive(&mut self, event: StreamActivationEvent) -> Duties {
        self.engine.process_event(event);
        self.engine.policy().actions().duties.take()
    }

    /// Where the two gates stand.
    pub fn phase(&self) -> Phase {
        self.engine.get_current_state()
    }

    /// How many streams the table holds.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the table holds no stream.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// How many streams the table can hold: its storage, at most the streams it was lent.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// What a loss carries.
    pub fn notify(&self) -> Notify {
        self.notify
    }

    /// Supervise a stream of `period` ticks that may miss `factor` periods, sent by `sender`, and
    /// give its number. An `awaited` stream can time out before its first reception. A stream of a
    /// sender marked absent is absent with it. The stream's deadline counts from the next poll
    /// that has a clock, and again from each activation.
    pub fn add(
        &mut self,
        period: u32,
        factor: u16,
        sender: u32,
        awaited: bool,
    ) -> Result<usize, AddRefused> {
        let deadline = deadline(period, factor).ok_or(AddRefused::DeadlineOutOfRange)?;
        if self.count >= self.capacity {
            return Err(AddRefused::Full);
        }
        let absent = self.slots[..self.count]
            .iter()
            .any(|slot| slot.sender == sender && slot.flags & EXCLUDED != 0);
        let mut flags = 0;
        if awaited {
            flags |= AWAITED | UNDATED;
        }
        if absent {
            flags |= EXCLUDED;
        }
        let index = self.count;
        self.slots[index] = StreamSlot {
            deadline,
            sender,
            flags,
            ..StreamSlot::EMPTY
        };
        self.count += 1;
        Ok(index)
    }

    /// Stream `stream` was received at `now` (`None` when the clock could not say), carrying
    /// `payload`, which is kept under [`Notify::LastValue`] and not read otherwise. A loss the
    /// stream was in is over, and its deadline counts from this reception.
    pub fn received(
        &mut self,
        stream: usize,
        now: Option<u32>,
        payload: &[u8],
    ) -> Result<(), ReceiveRefused> {
        if stream >= self.count {
            return Err(ReceiveRefused::NoSuchStream);
        }
        let slot = &mut self.slots[stream];
        slot.flags |= RECEIVED;
        slot.flags &= !TIMED_OUT;
        rebase(slot, now);
        if self.notify == Notify::StatusOnly {
            return Ok(());
        }
        let start = stream * self.cell;
        if payload.len() > self.cell {
            slot.flags &= !HAS_VALUE;
            slot.value_len = 0;
            return Err(ReceiveRefused::ValueTooLong);
        }
        self.values[start..start + payload.len()].copy_from_slice(payload);
        // The cell is at most a 32-bit length (`new`), so the payload's length fits.
        slot.value_len = payload.len() as u32;
        slot.flags |= HAS_VALUE;
        Ok(())
    }

    /// Whether the application's condition holds. It is read by every poll, as a level: the
    /// streams are re-based only when it comes to hold while the start delay has passed.
    pub fn set_condition(&mut self, holds: bool) {
        self.condition = holds;
    }

    /// Mark `sender` present or absent at `now`. Its streams are not judged while it is absent,
    /// and a loss one of them was in is withdrawn without being told; once present again, each
    /// that can time out counts its deadline from `now` (from the next poll with a clock when
    /// `now` is `None`). The error counts are left as they are. Marking a sender what it already
    /// is changes nothing.
    pub fn set_sender_present(
        &mut self,
        sender: u32,
        present: bool,
        now: Option<u32>,
    ) -> Result<(), UnknownSender> {
        let mut found = false;
        for slot in self.slots[..self.count]
            .iter_mut()
            .filter(|slot| slot.sender == sender)
        {
            found = true;
            let absent = slot.flags & EXCLUDED != 0;
            if absent != present {
                continue;
            }
            slot.flags &= !TIMED_OUT;
            if present {
                slot.flags &= !EXCLUDED;
                if can_time_out(slot) {
                    rebase(slot, now);
                }
            } else {
                slot.flags |= EXCLUDED;
            }
        }
        if found {
            Ok(())
        } else {
            Err(UnknownSender)
        }
    }

    /// The error count of stream `stream`, or `None` when there is none of that number.
    pub fn stream_errors(&self, stream: usize) -> Option<u8> {
        self.slots[..self.count].get(stream).map(|slot| slot.errors)
    }

    /// Whether stream `stream` is in a loss that was told and has not ended, or `None` when there
    /// is none of that number.
    pub fn is_lost(&self, stream: usize) -> Option<bool> {
        self.slots[..self.count]
            .get(stream)
            .map(|slot| slot.flags & TIMED_OUT != 0)
    }

    /// The node's error count: one for every loss told since the last activation.
    pub fn node_errors(&self) -> u8 {
        self.node_errors
    }

    /// Look at every stream at `now` (`None` when the clock could not say) and tell `on_loss`
    /// once for each stream whose deadline has newly passed. Returns how many it told.
    pub fn poll(&mut self, now: Option<u32>, on_loss: impl FnMut(Loss<'_>)) -> usize {
        let Some(now) = now else {
            // A poll that cannot date anything shuts the gates: the time it covers is not
            // charged, because the next poll with a clock activates again and re-bases.
            self.drive(StreamActivationEvent::ConditionFails);
            return 0;
        };
        for slot in self.slots[..self.count]
            .iter_mut()
            .filter(|slot| slot.flags & UNDATED != 0)
        {
            rebase(slot, Some(now));
        }
        if self
            .drive(StreamActivationEvent::ClockSeen)
            .has(ActivationBinding::BEGIN_DELAY)
        {
            self.delay_from = now;
        }
        if self.phase() == Phase::Delaying && elapsed(now, self.delay_from, self.start_delay) {
            self.drive(StreamActivationEvent::DelayOver);
        }
        let level = if self.condition {
            StreamActivationEvent::ConditionHolds
        } else {
            StreamActivationEvent::ConditionFails
        };
        if self.drive(level).has(ActivationBinding::ACTIVATE) {
            self.activate(now);
        }
        if self.phase() != Phase::Active {
            return 0;
        }
        self.judge(now, on_loss)
    }

    /// The gates opened at `now`: every stream that can time out counts its deadline from here,
    /// and every error count starts again from 0.
    fn activate(&mut self, now: u32) {
        self.node_errors = 0;
        for slot in &mut self.slots[..self.count] {
            slot.errors = 0;
            slot.flags &= !TIMED_OUT;
            if can_time_out(slot) {
                rebase(slot, Some(now));
            }
        }
    }

    fn judge(&mut self, now: u32, mut on_loss: impl FnMut(Loss<'_>)) -> usize {
        let mut told = 0;
        let last_value = self.notify == Notify::LastValue;
        for (index, slot) in self.slots[..self.count].iter_mut().enumerate() {
            if slot.flags & (EXCLUDED | TIMED_OUT) != 0
                || slot.flags & BASED == 0
                || !deadline_passed(now, slot.base, slot.deadline)
            {
                continue;
            }
            slot.flags |= TIMED_OUT;
            slot.errors = slot.errors.saturating_add(1);
            self.node_errors = self.node_errors.saturating_add(1);
            told += 1;
            let value = if last_value && slot.flags & HAS_VALUE != 0 {
                let start = index * self.cell;
                Some(&self.values[start..start + slot.value_len as usize])
            } else {
                None
            };
            on_loss(Loss {
                stream: index,
                sender: slot.sender,
                errors: slot.errors,
                node_errors: self.node_errors,
                value,
            });
        }
        told
    }
}

/// Whether a stream is one whose silence is a loss: awaited, or received at least once.
fn can_time_out(slot: &StreamSlot) -> bool {
    slot.flags & (AWAITED | RECEIVED) != 0
}

/// Count the stream's deadline from `now`, or from the next poll with a clock when it is `None`.
fn rebase(slot: &mut StreamSlot, now: Option<u32>) {
    match now {
        Some(now) => {
            slot.base = now;
            slot.flags |= BASED;
            slot.flags &= !UNDATED;
        }
        None => slot.flags |= UNDATED,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    /// What one poll told, owned, so a test can look at it after the poll.
    #[derive(Debug, PartialEq, Eq)]
    struct Told {
        stream: usize,
        sender: u32,
        errors: u8,
        node_errors: u8,
        value: Option<Vec<u8>>,
    }

    fn poll(supervisor: &mut StreamSupervisor<'_>, now: u32) -> Vec<Told> {
        poll_at(supervisor, Some(now))
    }

    fn poll_at(supervisor: &mut StreamSupervisor<'_>, now: Option<u32>) -> Vec<Told> {
        let mut told = Vec::new();
        let count = supervisor.poll(now, |loss| {
            told.push(Told {
                stream: loss.stream,
                sender: loss.sender,
                errors: loss.errors,
                node_errors: loss.node_errors,
                value: loss.value.map(<[u8]>::to_vec),
            });
        });
        assert_eq!(count, told.len(), "a poll counts what it told");
        told
    }

    fn streams(told: &[Told]) -> Vec<usize> {
        told.iter().map(|loss| loss.stream).collect()
    }

    /// The streams a supervisor is lent where the runtime states nothing.
    const BUILD_STREAMS: usize = crate::process_limits::ProcessRows::BUILD.e2e_supervised_streams;

    /// A supervisor with no start delay, telling the status only.
    fn status_only(slots: &mut [StreamSlot]) -> StreamSupervisor<'_> {
        StreamSupervisor::new(slots, &mut [], 0, 0, Notify::StatusOnly, BUILD_STREAMS).unwrap()
    }

    #[test]
    fn a_slot_is_five_words_as_the_c_header_sizes_it() {
        assert_eq!(core::mem::size_of::<StreamSlot>(), 20);
        assert_eq!(core::mem::align_of::<StreamSlot>(), 4);
    }

    #[test]
    fn a_deadline_is_the_period_times_the_factor_inside_the_range() {
        assert_eq!(deadline(7, 3), Some(21));
        assert_eq!(deadline(0, 3), None);
        assert_eq!(deadline(7, 0), None);
        assert_eq!(deadline(MAX_DEADLINE_TICKS, 1), Some(MAX_DEADLINE_TICKS));
        assert_eq!(deadline(MAX_DEADLINE_TICKS, 2), None);
        assert_eq!(deadline(u32::MAX, u16::MAX), None);
    }

    /// The arithmetic the document states, in the standard library's words: the product in 64
    /// bits, absent at 0 and past the longest deadline.
    fn deadline_oracle(period: u32, factor: u16) -> Option<u32> {
        let product = u64::from(period) * u64::from(factor);
        if product == 0 || product > u64::from(MAX_DEADLINE_TICKS) {
            return None;
        }
        u32::try_from(product).ok()
    }

    /// The generated deadline is the oracle's over the edges of both ranges and the bound the
    /// document writes as a number, so a document whose bound drifted from
    /// [`MAX_DEADLINE_TICKS`] is seen here.
    #[test]
    fn the_generated_deadline_is_the_product_in_range_over_a_sweep() {
        let periods = [
            0,
            1,
            2,
            3,
            7,
            1_000,
            65_535,
            65_536,
            32_768,
            MAX_DEADLINE_TICKS / 2,
            MAX_DEADLINE_TICKS / 2 + 1,
            MAX_DEADLINE_TICKS - 1,
            MAX_DEADLINE_TICKS,
            MAX_DEADLINE_TICKS + 1,
            MAX_TIMEOUT_TICKS,
            u32::MAX - 1,
            u32::MAX,
        ];
        let factors = [0, 1, 2, 3, 255, 256, 32_767, 32_768, u16::MAX - 1, u16::MAX];
        for &period in &periods {
            for &factor in &factors {
                assert_eq!(
                    deadline(period, factor),
                    deadline_oracle(period, factor),
                    "{period} x {factor}"
                );
            }
        }
        // The products on either side of the bound, reached through factors above 1.
        let bound = u64::from(MAX_DEADLINE_TICKS);
        for factor in [2u16, 3, 7, 1_000, u16::MAX] {
            let below = u32::try_from(bound / u64::from(factor)).unwrap();
            for period in [below, below + 1] {
                assert_eq!(
                    deadline(period, factor),
                    deadline_oracle(period, factor),
                    "{period} x {factor}"
                );
            }
        }
    }

    #[test]
    fn a_deadline_passes_when_more_than_it_has_elapsed_across_a_wrap() {
        assert!(!deadline_passed(121, 100, 21));
        assert!(deadline_passed(122, 100, 21));
        // The counter went round: 21 ticks from 2^32 - 10 is 11, 22 is 12.
        assert!(!deadline_passed(11, u32::MAX - 9, 21));
        assert!(deadline_passed(12, u32::MAX - 9, 21));
        assert!(!deadline_passed(MAX_DEADLINE_TICKS, 0, MAX_DEADLINE_TICKS));
        assert!(deadline_passed(MAX_TIMEOUT_TICKS, 0, MAX_DEADLINE_TICKS));
    }

    #[test]
    fn a_loss_is_told_once_and_again_only_after_a_reception() {
        let mut slots = [StreamSlot::EMPTY; 2];
        let mut supervisor = status_only(&mut slots);
        let stream = supervisor.add(7, 3, 0x5EED, true).unwrap();
        assert!(poll(&mut supervisor, 0).is_empty());
        assert_eq!(supervisor.phase(), Phase::Active);

        assert!(
            poll(&mut supervisor, 21).is_empty(),
            "21 ticks is the deadline, not past it"
        );
        assert_eq!(
            poll(&mut supervisor, 22),
            [Told {
                stream,
                sender: 0x5EED,
                errors: 1,
                node_errors: 1,
                value: None
            }]
        );
        assert!(poll(&mut supervisor, 23).is_empty(), "an edge, not a level");
        assert!(poll(&mut supervisor, 500).is_empty());
        assert_eq!(supervisor.is_lost(stream), Some(true));

        supervisor.received(stream, Some(600), b"").unwrap();
        assert_eq!(supervisor.is_lost(stream), Some(false));
        assert!(poll(&mut supervisor, 621).is_empty());
        assert_eq!(streams(&poll(&mut supervisor, 622)), [stream]);
        assert_eq!(supervisor.stream_errors(stream), Some(2));
        assert_eq!(supervisor.node_errors(), 2);
    }

    #[test]
    fn an_activation_rebases_so_a_stream_never_received_times_out_one_deadline_after_it() {
        let mut slots = [StreamSlot::EMPTY; 2];
        let mut supervisor = status_only(&mut slots);
        let awaited = supervisor.add(10, 2, 1, true).unwrap();
        let unawaited = supervisor.add(10, 2, 1, false).unwrap();
        supervisor.set_condition(false);
        for now in [0, 100, 1000] {
            assert!(poll(&mut supervisor, now).is_empty(), "inactive at {now}");
        }
        assert_eq!(supervisor.phase(), Phase::Inactive);

        supervisor.set_condition(true);
        assert!(poll(&mut supervisor, 1000).is_empty());
        assert_eq!(supervisor.phase(), Phase::Active);
        assert!(
            poll(&mut supervisor, 1020).is_empty(),
            "the silence before the activation is not charged"
        );
        assert_eq!(streams(&poll(&mut supervisor, 1021)), [awaited]);
        assert!(
            poll(&mut supervisor, 9000).is_empty(),
            "never received, never awaited"
        );
        assert_eq!(supervisor.is_lost(unawaited), Some(false));

        // Once received it can time out, and is re-based by the next activation as well.
        supervisor.received(unawaited, Some(9000), b"").unwrap();
        supervisor.set_condition(false);
        assert!(poll(&mut supervisor, 9100).is_empty());
        supervisor.set_condition(true);
        assert!(poll(&mut supervisor, 9200).is_empty());
        assert!(poll(&mut supervisor, 9220).is_empty());
        let mut told = streams(&poll(&mut supervisor, 9221));
        told.sort_unstable();
        assert_eq!(told, [awaited, unawaited]);
    }

    #[test]
    fn nothing_is_judged_before_the_start_delay_from_the_first_poll_with_a_clock() {
        let mut slots = [StreamSlot::EMPTY; 1];
        let mut supervisor = StreamSupervisor::new(
            &mut slots,
            &mut [],
            0,
            500,
            Notify::StatusOnly,
            BUILD_STREAMS,
        )
        .unwrap();
        let stream = supervisor.add(10, 1, 3, true).unwrap();
        assert_eq!(supervisor.phase(), Phase::Unclocked);
        assert!(poll_at(&mut supervisor, None).is_empty());
        assert_eq!(
            supervisor.phase(),
            Phase::Unclocked,
            "a poll without a clock"
        );

        assert!(poll(&mut supervisor, 1000).is_empty());
        assert_eq!(supervisor.phase(), Phase::Delaying);
        assert!(poll(&mut supervisor, 1499).is_empty());
        assert_eq!(supervisor.phase(), Phase::Delaying, "499 of 500 ticks");
        assert!(poll(&mut supervisor, 1500).is_empty());
        assert_eq!(supervisor.phase(), Phase::Active);
        assert!(poll(&mut supervisor, 1510).is_empty());
        assert_eq!(streams(&poll(&mut supervisor, 1511)), [stream]);
    }

    #[test]
    fn a_start_delay_across_a_wrap_of_the_clock_is_counted_modulo_the_counter() {
        let mut slots = [StreamSlot::EMPTY; 1];
        let mut supervisor = StreamSupervisor::new(
            &mut slots,
            &mut [],
            0,
            100,
            Notify::StatusOnly,
            BUILD_STREAMS,
        )
        .unwrap();
        supervisor.add(10, 1, 3, true).unwrap();
        assert!(poll(&mut supervisor, u32::MAX - 49).is_empty());
        assert!(poll(&mut supervisor, 49).is_empty());
        assert_eq!(supervisor.phase(), Phase::Delaying);
        assert!(poll(&mut supervisor, 50).is_empty());
        assert_eq!(supervisor.phase(), Phase::Active);
    }

    #[test]
    fn an_absent_sender_is_excluded_until_present_and_then_counted_from_that_moment() {
        let mut slots = [StreamSlot::EMPTY; 3];
        let mut supervisor = status_only(&mut slots);
        let of_seven = supervisor.add(10, 1, 7, true).unwrap();
        let of_nine = supervisor.add(10, 1, 9, true).unwrap();
        assert!(poll(&mut supervisor, 0).is_empty());

        assert_eq!(supervisor.set_sender_present(7, false, Some(0)), Ok(()));
        assert_eq!(
            supervisor.set_sender_present(42, false, Some(0)),
            Err(UnknownSender)
        );
        let later_of_seven = supervisor.add(10, 1, 7, true).unwrap();
        assert_eq!(streams(&poll(&mut supervisor, 11)), [of_nine]);
        assert!(poll(&mut supervisor, 100).is_empty());

        assert_eq!(supervisor.set_sender_present(7, true, Some(200)), Ok(()));
        assert!(poll(&mut supervisor, 210).is_empty());
        let mut told = streams(&poll(&mut supervisor, 211));
        told.sort_unstable();
        assert_eq!(told, [of_seven, later_of_seven]);
        assert_eq!(supervisor.stream_errors(of_nine), Some(1), "left as it was");
    }

    #[test]
    fn marking_a_lost_stream_absent_withdraws_the_loss_and_keeps_its_count() {
        let mut slots = [StreamSlot::EMPTY; 1];
        let mut supervisor = status_only(&mut slots);
        let stream = supervisor.add(10, 1, 7, true).unwrap();
        assert!(poll(&mut supervisor, 0).is_empty());
        assert_eq!(streams(&poll(&mut supervisor, 11)), [stream]);
        supervisor.set_sender_present(7, false, Some(20)).unwrap();
        assert_eq!(supervisor.is_lost(stream), Some(false));
        assert_eq!(supervisor.stream_errors(stream), Some(1));
        // Marking it absent again is not a change: it does not move what the first did.
        supervisor.set_sender_present(7, false, Some(30)).unwrap();
        supervisor.set_sender_present(7, true, Some(40)).unwrap();
        // Present again, and present a second time is not a re-base either.
        supervisor.set_sender_present(7, true, Some(45)).unwrap();
        assert!(poll(&mut supervisor, 50).is_empty());
        assert_eq!(streams(&poll(&mut supervisor, 51)), [stream]);
        assert_eq!(supervisor.stream_errors(stream), Some(2));
    }

    #[test]
    fn the_error_counts_stop_at_the_ceiling() {
        let mut slots = [StreamSlot::EMPTY; 1];
        let mut supervisor = status_only(&mut slots);
        let stream = supervisor.add(10, 1, 1, true).unwrap();
        assert!(poll(&mut supervisor, 0).is_empty());
        let mut now = 0u32;
        for _ in 0..300 {
            now += 11;
            assert_eq!(poll(&mut supervisor, now).len(), 1);
            supervisor.received(stream, Some(now), b"").unwrap();
        }
        assert_eq!(supervisor.stream_errors(stream), Some(ERROR_CEILING));
        assert_eq!(supervisor.node_errors(), ERROR_CEILING);
    }

    #[test]
    fn the_node_count_is_every_loss_of_every_stream() {
        let mut slots = [StreamSlot::EMPTY; 2];
        let mut supervisor = status_only(&mut slots);
        let first = supervisor.add(10, 1, 1, true).unwrap();
        let second = supervisor.add(20, 1, 2, true).unwrap();
        assert!(poll(&mut supervisor, 0).is_empty());
        let told = poll(&mut supervisor, 11);
        assert_eq!((told[0].stream, told[0].node_errors), (first, 1));
        let told = poll(&mut supervisor, 21);
        assert_eq!((told[0].stream, told[0].node_errors), (second, 2));
        assert_eq!(supervisor.stream_errors(first), Some(1));
        assert_eq!(supervisor.stream_errors(second), Some(1));
    }

    #[test]
    fn a_condition_that_fails_tells_nothing_and_its_return_resets_the_counts() {
        let mut slots = [StreamSlot::EMPTY; 1];
        let mut supervisor = status_only(&mut slots);
        let stream = supervisor.add(10, 1, 1, true).unwrap();
        assert!(poll(&mut supervisor, 0).is_empty());
        assert_eq!(streams(&poll(&mut supervisor, 11)), [stream]);

        supervisor.received(stream, Some(20), b"").unwrap();
        supervisor.set_condition(false);
        assert!(poll(&mut supervisor, 25).is_empty());
        assert_eq!(supervisor.phase(), Phase::Inactive);
        for now in [31, 100, 1000] {
            assert!(poll(&mut supervisor, now).is_empty(), "inactive at {now}");
        }
        assert_eq!(
            supervisor.stream_errors(stream),
            Some(1),
            "kept while inactive"
        );

        supervisor.set_condition(true);
        assert!(poll(&mut supervisor, 2000).is_empty());
        assert_eq!(supervisor.stream_errors(stream), Some(0));
        assert_eq!(supervisor.node_errors(), 0);
        assert!(poll(&mut supervisor, 2010).is_empty());
        assert_eq!(poll(&mut supervisor, 2011)[0].errors, 1);
    }

    #[test]
    fn a_poll_without_a_clock_shuts_the_gates_and_the_next_with_one_rebases() {
        let mut slots = [StreamSlot::EMPTY; 1];
        let mut supervisor = status_only(&mut slots);
        let stream = supervisor.add(10, 1, 1, true).unwrap();
        assert!(poll(&mut supervisor, 0).is_empty());
        assert!(poll_at(&mut supervisor, None).is_empty());
        assert_eq!(supervisor.phase(), Phase::Inactive);
        assert!(
            poll(&mut supervisor, 500).is_empty(),
            "the clockless gap is not charged"
        );
        assert_eq!(supervisor.phase(), Phase::Active);
        assert_eq!(streams(&poll(&mut supervisor, 511)), [stream]);
    }

    #[test]
    fn a_reception_without_a_clock_is_dated_by_the_next_poll_that_has_one() {
        let mut slots = [StreamSlot::EMPTY; 1];
        let mut supervisor = status_only(&mut slots);
        let stream = supervisor.add(10, 1, 1, false).unwrap();
        assert!(poll(&mut supervisor, 0).is_empty());
        supervisor.received(stream, None, b"").unwrap();
        assert!(poll(&mut supervisor, 300).is_empty(), "dated at 300");
        assert!(poll(&mut supervisor, 310).is_empty());
        assert_eq!(streams(&poll(&mut supervisor, 311)), [stream]);
    }

    #[test]
    fn under_last_value_a_loss_hands_back_the_last_payload_and_a_long_one_is_refused() {
        let mut slots = [StreamSlot::EMPTY; 2];
        let mut values = [0u8; 8];
        let mut supervisor = StreamSupervisor::new(
            &mut slots,
            &mut values,
            4,
            0,
            Notify::LastValue,
            BUILD_STREAMS,
        )
        .unwrap();
        let kept = supervisor.add(10, 1, 1, true).unwrap();
        let never = supervisor.add(10, 1, 2, true).unwrap();
        assert!(poll(&mut supervisor, 0).is_empty());
        supervisor.received(kept, Some(0), &[0xC4, 0x51]).unwrap();
        supervisor
            .received(kept, Some(0), &[0x0D, 0xE7, 0x9A])
            .unwrap();
        let told = poll(&mut supervisor, 11);
        assert_eq!(told.len(), 2);
        assert_eq!(told[0].stream, kept);
        assert_eq!(told[0].value.as_deref(), Some(&[0x0D, 0xE7, 0x9A][..]));
        assert_eq!(told[1].stream, never);
        assert_eq!(told[1].value, None, "nothing was ever received");

        assert_eq!(
            supervisor.received(kept, Some(20), &[1, 2, 3, 4, 5]),
            Err(ReceiveRefused::ValueTooLong)
        );
        assert!(
            poll(&mut supervisor, 30).is_empty(),
            "the reception counted though its value was refused"
        );
        let told = poll(&mut supervisor, 31);
        assert_eq!(told[0].value, None, "the older value is not handed back");
    }

    #[test]
    fn under_status_only_no_payload_is_read_or_handed_back() {
        let mut slots = [StreamSlot::EMPTY; 1];
        let mut supervisor = status_only(&mut slots);
        assert_eq!(supervisor.notify(), Notify::StatusOnly);
        let stream = supervisor.add(10, 1, 1, true).unwrap();
        assert!(poll(&mut supervisor, 0).is_empty());
        assert_eq!(supervisor.received(stream, Some(0), &[9; 64]), Ok(()));
        assert_eq!(poll(&mut supervisor, 11)[0].value, None);
    }

    #[test]
    fn storage_and_ranges_that_cannot_be_held_are_refused_by_name() {
        let mut slots = [StreamSlot::EMPTY; 2];
        assert_eq!(
            StreamSupervisor::new(&mut slots, &mut [], 0, 0, Notify::LastValue, BUILD_STREAMS)
                .err(),
            Some(CreateRefused::NoValueCell)
        );
        let mut values = [0u8; 7];
        assert_eq!(
            StreamSupervisor::new(
                &mut slots,
                &mut values,
                4,
                0,
                Notify::LastValue,
                BUILD_STREAMS
            )
            .err(),
            Some(CreateRefused::ValueStorageShort)
        );
        assert_eq!(
            StreamSupervisor::new(
                &mut slots,
                &mut [],
                0,
                MAX_TIMEOUT_TICKS + 1,
                Notify::StatusOnly,
                BUILD_STREAMS
            )
            .err(),
            Some(CreateRefused::DelayOutOfRange)
        );

        let mut supervisor = status_only(&mut slots);
        assert_eq!(
            supervisor.add(0, 1, 1, true),
            Err(AddRefused::DeadlineOutOfRange)
        );
        assert_eq!(
            supervisor.add(1, 0, 1, true),
            Err(AddRefused::DeadlineOutOfRange)
        );
        assert_eq!(supervisor.add(10, 1, 1, true), Ok(0));
        assert_eq!(supervisor.add(10, 1, 1, true), Ok(1));
        assert_eq!(supervisor.add(10, 1, 1, true), Err(AddRefused::Full));
        assert_eq!(
            supervisor.received(2, Some(0), b""),
            Err(ReceiveRefused::NoSuchStream)
        );
        assert_eq!(supervisor.stream_errors(2), None);
        assert_eq!(supervisor.is_lost(2), None);
    }

    #[test]
    fn the_table_holds_at_most_the_builds_limit_whatever_the_storage() {
        let mut slots = [StreamSlot::EMPTY; crate::caps::E2E_SUPERVISED_STREAMS + 1];
        let mut supervisor = status_only(&mut slots);
        assert_eq!(supervisor.capacity(), crate::caps::E2E_SUPERVISED_STREAMS);
        for _ in 0..crate::caps::E2E_SUPERVISED_STREAMS {
            supervisor.add(10, 1, 1, false).unwrap();
        }
        assert_eq!(supervisor.add(10, 1, 1, false), Err(AddRefused::Full));
        assert_eq!(supervisor.len(), crate::caps::E2E_SUPERVISED_STREAMS);
    }

    /// A runtime that lends fewer streams than the storage holds: the table holds that many, and
    /// the next is refused as a full table with nothing added.
    #[test]
    fn the_table_holds_the_streams_it_was_lent_whatever_the_storage() {
        let mut slots = [StreamSlot::EMPTY; 4];
        let mut supervisor =
            StreamSupervisor::new(&mut slots, &mut [], 0, 0, Notify::StatusOnly, 2).unwrap();
        assert_eq!(supervisor.capacity(), 2);
        assert_eq!(supervisor.add(10, 1, 1, false), Ok(0));
        assert_eq!(supervisor.add(10, 1, 1, false), Ok(1));
        assert_eq!(supervisor.add(10, 1, 1, false), Err(AddRefused::Full));
        assert_eq!(supervisor.len(), 2);
        assert_eq!(supervisor.stream_errors(2), None);
    }

    /// Under last-value the value area is needed for the streams lent, not for all the storage.
    #[test]
    fn the_value_area_is_needed_for_the_streams_lent() {
        let mut slots = [StreamSlot::EMPTY; 4];
        let mut values = [0u8; 8];
        let supervisor =
            StreamSupervisor::new(&mut slots, &mut values, 4, 0, Notify::LastValue, 2).unwrap();
        assert_eq!(supervisor.capacity(), 2);
    }

    #[test]
    fn storage_reused_from_an_earlier_table_is_cleared() {
        let mut slots = [StreamSlot::EMPTY; 1];
        {
            let mut supervisor = status_only(&mut slots);
            supervisor.add(10, 1, 1, true).unwrap();
        }
        {
            let supervisor = status_only(&mut slots);
            assert!(supervisor.is_empty());
        }
        assert_eq!(slots, [StreamSlot::EMPTY]);
    }
}
