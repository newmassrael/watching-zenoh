// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The replay cache of a subscriber: it asks each publisher of a message for what it last sent,
//! as the publisher appears, and orders the answers against the live samples.
//!
//! # Asking
//!
//! A publisher APPEARS when its replay queryable (the message's key plus the suffix the
//! deployment states) is declared: the host hears it through the declaration watch, with the zenoh
//! id of the node that declared it, and tells [`ReplaySubscriber::appeared`]. Each publisher is
//! asked once, by one query addressed to it; a publisher that is declared again on another link
//! is not asked again, and one that left (its queryable undeclared) and comes back is. At most
//! `quota` queries are in flight at once (the querier's own bound, `QUERIER_MAX_PENDING_QUERIES`,
//! or less); a publisher that appears while the quota is used waits, and is asked as a query ends.
//!
//! # The round
//!
//! The queries of the publishers that appear together make a ROUND, the `replay_round` machine
//! (`sources/session/replay_round.scxml`): Idle until a publisher is asked, Asking, Answering once
//! a reply came, then Live once every query of the round has ended, or Abandoned when a deadline
//! passes first. Both deadlines are the caller's data: the PROGRESS deadline is counted again from
//! every reply, the ROUND deadline from the round's start (and, before any publisher was asked,
//! from the subscriber's creation). A reply of an abandoned round's query is LATE: it is not
//! judged. A publisher asked once the subscriber is live starts a round of its own.
//!
//! # Live samples against the replay
//!
//! Under `replay-live-before-answer = deliver` a live sample is handed on as it arrives, and the
//! replies interleave with it: the receiving judge drops a reply that is behind what it judged
//! (wz-app-frame `replay_admission`). Under `hold-back` the live samples that arrive before the
//! first round is over are HELD, in a store the caller sizes, and released after that round's
//! last reply, in the order they arrived: when every query of the round ended, when a deadline
//! abandoned it, or when the store has no room for the next one (which abandons the round rather
//! than drop a sample). The bound of the hold is therefore the round deadline and the store, never
//! nothing. Later rounds hold nothing: the subscriber is live by then.
//!
//! # What is the host's
//!
//! The subscriber performs no I/O, judges no frame and reads no clock: time is a tick count of a
//! monotonic source in 32 bits that wraps, handed to each call as `Option<u32>` (`None` when the
//! source cannot say; a deadline counted from such a moment counts from the next poll that has a
//! clock). The table of publishers and the store of held samples are the caller's storage, which
//! the subscriber initialises and owns for its life. The table is keyed by publisher, which a
//! statechart cannot hold; it is this sans-I/O host, and the machine says when the round ends.
//! The deadline comparison is the generated `tick_elapsed` ([`crate::wrapping_ticks`]).

use sce_rust_runtime::helpers::session_id::SessionId;
use sce_rust_runtime::Engine;

use crate::duty_outbox::{Duties, DutyOutbox};
use crate::replay_round::{ReplayRoundActions, ReplayRoundEvent, ReplayRoundPolicy};
use crate::session_zid::ZID_MAX;
use crate::wrapping_ticks::{elapsed, MAX_TIMEOUT_TICKS};

/// How live samples are ordered against the replay: the `replay-live-before-answer` policy.
pub use crate::policy::ReplayLiveBeforeAnswer as LiveBeforeAnswer;

/// Where the round stands.
pub use crate::replay_round::ReplayRoundState as Phase;

/// The id the round machine is built under (SCE ADR 0045: the host gives a machine its id). A
/// constant, so the generated constructor never refuses it.
const ROUND_SESSION_ID: SessionId = sce_rust_runtime::session_id!("wz-replay-round");

/// The header of a held sample's cell: its length (u32, little-endian).
const HELD_HEADER: usize = 4;

/// One row of the table of publishers, in the caller's storage. Its layout is fixed (`repr(C)`,
/// 32 bytes) so a C caller can size the storage from its header.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublisherSlot {
    declaration: u64,
    zid: [u8; ZID_MAX],
    zid_len: u8,
    state: u8,
    flags: u8,
    reserved: u8,
    reserved2: u32,
}

impl PublisherSlot {
    /// A row that holds no publisher.
    pub const EMPTY: Self = Self {
        declaration: 0,
        zid: [0; ZID_MAX],
        zid_len: 0,
        state: FREE,
        flags: 0,
        reserved: 0,
        reserved2: 0,
    };

    fn zid(&self) -> &[u8] {
        &self.zid[..usize::from(self.zid_len)]
    }
}

/// The row holds no publisher.
const FREE: u8 = 0;
/// The publisher appeared and waits for room in the quota.
const WAITING: u8 = 1;
/// Its query is in flight.
const ASKED: u8 = 2;
/// Its query ended.
const ANSWERED: u8 = 3;

/// Its query belongs to a round that was abandoned: its replies are late.
const ABANDONED: u8 = 1 << 0;
/// Its queryable was undeclared: it is asked again when it comes back.
const GONE: u8 = 1 << 1;

/// The two deadlines of a round, in ticks, each 1 to [`MAX_TIMEOUT_TICKS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadlines {
    /// How long a round waits for its next reply.
    pub progress: u32,
    /// How long a round lasts at most.
    pub round: u32,
}

/// Why a subscriber could not be made over the storage it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateRefused {
    /// No row for a publisher.
    NoSlots,
    /// A quota of 0: no query could ever go out.
    NoQuota,
    /// A deadline of 0, or past [`MAX_TIMEOUT_TICKS`].
    DeadlineOutOfRange,
    /// Under `hold-back`, a store with no room for one sample of `held_cell` bytes, or a cell of
    /// 0 bytes.
    NoHoldStore,
    /// Under `hold-back`, a cell of 2^32 bytes or more.
    HoldCellTooLarge,
}

/// Why a publisher's appearance was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppearRefused {
    /// The zenoh id is empty or longer than a zenoh id: the declaration named no node.
    NoZid,
    /// Every row holds a publisher that has not left.
    Full,
}

/// What the host does with a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyFate {
    /// Judge it, and deliver it as a replay.
    Judge,
    /// Drop it: its query belongs to an abandoned round, or to no row in flight.
    Late,
}

/// What the host does with a live sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveFate {
    /// Hand it on, after every held sample [`ReplaySubscriber::pop_released`] still gives.
    Deliver,
    /// It is held, and given back by [`ReplaySubscriber::pop_released`] once the round is over.
    Held,
}

/// What the subscriber counts, each saturating.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Replies of an abandoned round's query.
    pub late_replies: u64,
    /// Replies of no query in flight.
    pub unknown_replies: u64,
    /// Live samples held back.
    pub held: u64,
    /// Publishers not taken because every row was in use.
    pub table_full: u64,
    /// Rounds abandoned.
    pub abandoned: u64,
}

struct RoundBinding {
    duties: DutyOutbox,
}

impl RoundBinding {
    const BEGIN_ROUND: u8 = 1 << 0;
    const PROGRESS: u8 = 1 << 1;
    const ABANDON: u8 = 1 << 2;
    const GO_LIVE: u8 = 1 << 3;
}

impl ReplayRoundActions for RoundBinding {
    const REALIZATION: ::sce_rust_runtime::ActionRealization =
        ::sce_rust_runtime::ActionRealization::Performs;

    fn begin_round(&mut self) {
        self.duties.record(Self::BEGIN_ROUND);
    }

    fn progress(&mut self) {
        self.duties.record(Self::PROGRESS);
    }

    fn abandon(&mut self) {
        self.duties.record(Self::ABANDON);
    }

    fn go_live(&mut self) {
        self.duties.record(Self::GO_LIVE);
    }
}

/// One deadline: where it counts from, if anywhere.
#[derive(Clone, Copy, Debug, Default)]
struct Mark {
    base: Option<u32>,
    /// It was armed at a moment the clock could not tell; the next poll with a clock dates it.
    undated: bool,
}

impl Mark {
    fn arm(&mut self, now: Option<u32>) {
        match now {
            Some(now) => {
                self.base = Some(now);
                self.undated = false;
            }
            None => {
                self.base = None;
                self.undated = true;
            }
        }
    }

    fn date(&mut self, now: u32) {
        if self.undated {
            self.base = Some(now);
            self.undated = false;
        }
    }

    /// Whether `limit` ticks have passed from the base to `now`; never when it has no base.
    fn passed(&self, now: u32, limit: u32) -> bool {
        self.base.is_some_and(|base| elapsed(now, base, limit))
    }
}

/// The subscriber's side of the replay cache, over the caller's storage.
pub struct ReplaySubscriber<'a> {
    slots: &'a mut [PublisherSlot],
    held: &'a mut [u8],
    /// The longest sample a held cell keeps.
    held_cell: usize,
    /// How many cells the store holds.
    held_cells: usize,
    held_head: usize,
    held_count: usize,
    deadlines: Deadlines,
    quota: usize,
    in_flight: usize,
    progress: Mark,
    round: Mark,
    live: LiveBeforeAnswer,
    /// The first round is over: nothing is held any more.
    released: bool,
    counts: Counts,
    engine: Engine<ReplayRoundPolicy<RoundBinding>>,
}

impl<'a> ReplaySubscriber<'a> {
    /// A subscriber that has asked no one, over `slots` (one row per publisher it can tell) and,
    /// under [`LiveBeforeAnswer::HoldBack`], `held`, cut into cells of `held_cell` bytes plus a
    /// four-byte header (under `deliver` `held` and `held_cell` are not read, and may be empty
    /// and 0). At most `quota` queries are in flight. The round deadline counts from `now`.
    pub fn new(
        slots: &'a mut [PublisherSlot],
        held: &'a mut [u8],
        held_cell: usize,
        deadlines: Deadlines,
        quota: usize,
        live: LiveBeforeAnswer,
        now: Option<u32>,
    ) -> Result<Self, CreateRefused> {
        if slots.is_empty() {
            return Err(CreateRefused::NoSlots);
        }
        if quota == 0 {
            return Err(CreateRefused::NoQuota);
        }
        let in_range = |ticks: u32| ticks != 0 && ticks <= MAX_TIMEOUT_TICKS;
        if !in_range(deadlines.progress) || !in_range(deadlines.round) {
            return Err(CreateRefused::DeadlineOutOfRange);
        }
        let held_cells = match live {
            LiveBeforeAnswer::Deliver => 0,
            LiveBeforeAnswer::HoldBack => {
                if u32::try_from(held_cell).is_err() {
                    return Err(CreateRefused::HoldCellTooLarge);
                }
                let cells = held.len() / (HELD_HEADER + held_cell);
                if held_cell == 0 || cells == 0 {
                    return Err(CreateRefused::NoHoldStore);
                }
                cells
            }
        };
        slots.fill(PublisherSlot::EMPTY);
        let mut engine = Engine::new(ReplayRoundPolicy::new_with_checked_session_id(
            ROUND_SESSION_ID,
            RoundBinding {
                duties: DutyOutbox::default(),
            },
        ));
        // W3C SCXML 3.3: enter the initial `Idle` leaf, which asks for nothing.
        engine.initialize().unwrap_or_else(|never| match never {});
        let _ = engine.policy().actions().duties.take();
        let mut round = Mark::default();
        round.arm(now);
        Ok(Self {
            slots,
            held,
            held_cell,
            held_cells,
            held_head: 0,
            held_count: 0,
            deadlines,
            quota,
            in_flight: 0,
            progress: Mark::default(),
            round,
            live,
            released: false,
            counts: Counts::default(),
            engine,
        })
    }

    /// Drive the machine with `event` at `now`, and perform what it asked.
    fn drive(&mut self, event: ReplayRoundEvent, now: Option<u32>) {
        self.engine.process_event(event);
        let duties: Duties = self.engine.policy().actions().duties.take();
        if duties.has(RoundBinding::BEGIN_ROUND) {
            self.progress.arm(now);
            self.round.arm(now);
        }
        if duties.has(RoundBinding::PROGRESS) {
            self.progress.arm(now);
        }
        if duties.has(RoundBinding::ABANDON) {
            self.counts.abandoned = self.counts.abandoned.saturating_add(1);
            for slot in self.slots.iter_mut().filter(|slot| slot.state == ASKED) {
                slot.flags |= ABANDONED;
            }
            self.released = true;
        }
        if duties.has(RoundBinding::GO_LIVE) {
            self.released = true;
        }
    }

    /// Where the round stands.
    pub fn phase(&self) -> Phase {
        self.engine.get_current_state()
    }

    /// How live samples are ordered against the replay.
    pub fn live_before_answer(&self) -> LiveBeforeAnswer {
        self.live
    }

    /// What the subscriber counted.
    pub fn counts(&self) -> Counts {
        self.counts
    }

    /// How many queries are in flight, those of an abandoned round included.
    pub fn in_flight(&self) -> usize {
        self.in_flight
    }

    /// How many live samples are held.
    pub fn held(&self) -> usize {
        self.held_count
    }

    /// The zenoh id of the publisher a row holds; empty for a free row or one the table does not
    /// have.
    pub fn zid(&self, slot: usize) -> &[u8] {
        match self.slots.get(slot) {
            Some(row) if row.state != FREE => row.zid(),
            _ => &[],
        }
    }

    /// Whether live samples are held now: under `hold-back`, until the first round is over.
    pub fn holding(&self) -> bool {
        self.live == LiveBeforeAnswer::HoldBack
            && !self.released
            && matches!(self.phase(), Phase::Idle | Phase::Asking | Phase::Answering)
    }

    /// A publisher's replay queryable was declared, under `declaration`, by the node `zid`, at
    /// `now`. Gives the row to ask now, if the quota has room for one (the caller asks it and
    /// tells [`ReplaySubscriber::query_ended`] when the query ends, whatever the way); `None`
    /// when nothing is to be asked now: the publisher waits for room, or it is being asked or
    /// was asked already.
    pub fn appeared(
        &mut self,
        zid: &[u8],
        declaration: u64,
        now: Option<u32>,
    ) -> Result<Option<usize>, AppearRefused> {
        if zid.is_empty() || zid.len() > ZID_MAX {
            return Err(AppearRefused::NoZid);
        }
        let known = self
            .slots
            .iter()
            .position(|row| row.state != FREE && row.zid() == zid);
        match known {
            Some(index) => {
                let row = &mut self.slots[index];
                row.declaration = declaration;
                let back = row.state == ANSWERED && row.flags & GONE != 0;
                row.flags &= !GONE;
                if !back {
                    return Ok(None);
                }
                row.state = WAITING;
            }
            None => {
                // A free row, or the row of a publisher that was answered and has left.
                let reusable = |row: &PublisherSlot| {
                    row.state == FREE || (row.state == ANSWERED && row.flags & GONE != 0)
                };
                let Some(index) = self.slots.iter().position(reusable) else {
                    self.counts.table_full = self.counts.table_full.saturating_add(1);
                    return Err(AppearRefused::Full);
                };
                let mut row = PublisherSlot::EMPTY;
                row.declaration = declaration;
                row.zid[..zid.len()].copy_from_slice(zid);
                // At most `ZID_MAX` bytes, checked above.
                row.zid_len = zid.len() as u8;
                row.state = WAITING;
                self.slots[index] = row;
            }
        }
        Ok(self.next_ask(now))
    }

    /// The publisher declared under `declaration` undeclared its replay queryable at `now`. One
    /// that waited to be asked is forgotten; one being asked, or answered, is asked again when it
    /// comes back. A declaration no row holds changes nothing.
    pub fn gone(&mut self, declaration: u64, now: Option<u32>) {
        let Some(index) = self
            .slots
            .iter()
            .position(|row| row.state != FREE && row.declaration == declaration)
        else {
            return;
        };
        let row = &mut self.slots[index];
        if row.state == WAITING {
            *row = PublisherSlot::EMPTY;
            self.check_done(now);
        } else {
            row.flags |= GONE;
        }
    }

    /// The next row to ask, if the quota has room and a publisher waits; it is in flight from
    /// here. A publisher asked while no round is open starts one.
    pub fn next_ask(&mut self, now: Option<u32>) -> Option<usize> {
        if self.in_flight >= self.quota {
            return None;
        }
        let index = self.slots.iter().position(|row| row.state == WAITING)?;
        if !matches!(self.phase(), Phase::Asking | Phase::Answering) {
            self.drive(ReplayRoundEvent::PublisherAppeared, now);
        }
        let row = &mut self.slots[index];
        row.state = ASKED;
        row.flags &= !ABANDONED;
        self.in_flight += 1;
        Some(index)
    }

    /// A reply of the query of row `slot` arrived at `now`.
    pub fn reply(&mut self, slot: usize, now: Option<u32>) -> ReplyFate {
        let Some(row) = self.slots.get(slot) else {
            self.counts.unknown_replies = self.counts.unknown_replies.saturating_add(1);
            return ReplyFate::Late;
        };
        if row.state != ASKED {
            self.counts.unknown_replies = self.counts.unknown_replies.saturating_add(1);
            return ReplyFate::Late;
        }
        if row.flags & ABANDONED != 0 {
            self.counts.late_replies = self.counts.late_replies.saturating_add(1);
            return ReplyFate::Late;
        }
        self.drive(ReplayRoundEvent::ReplyArrived, now);
        ReplyFate::Judge
    }

    /// The query of row `slot` ended at `now`: its final came, it timed out, its session closed,
    /// or it was never sent. Gives the next row to ask, as [`ReplaySubscriber::next_ask`] does.
    /// A row not in flight changes nothing but may still be given a waiting publisher's room.
    pub fn query_ended(&mut self, slot: usize, now: Option<u32>) -> Option<usize> {
        if let Some(row) = self.slots.get_mut(slot) {
            if row.state == ASKED {
                row.state = ANSWERED;
                row.flags &= !ABANDONED;
                self.in_flight -= 1;
            }
        }
        let next = self.next_ask(now);
        self.check_done(now);
        next
    }

    /// The round is over when no publisher waits and no query of it is in flight.
    fn check_done(&mut self, now: Option<u32>) {
        if !matches!(self.phase(), Phase::Asking | Phase::Answering) {
            return;
        }
        let open = self
            .slots
            .iter()
            .any(|row| row.state == WAITING || (row.state == ASKED && row.flags & ABANDONED == 0));
        if !open {
            self.drive(ReplayRoundEvent::QueriesDone, now);
        }
    }

    /// A live sample arrived. Held while [`ReplaySubscriber::holding`]; one the store has no
    /// room for abandons the round instead, which releases what was held, so it is delivered after
    /// them.
    pub fn live(&mut self, sample: &[u8]) -> LiveFate {
        if !self.holding() {
            return LiveFate::Deliver;
        }
        if sample.len() > self.held_cell || self.held_count >= self.held_cells {
            self.drive(ReplayRoundEvent::HoldFull, None);
            return LiveFate::Deliver;
        }
        let cell = (self.held_head + self.held_count) % self.held_cells;
        let at = cell * (HELD_HEADER + self.held_cell);
        // At most `held_cell`, which `new` holds to 32 bits.
        self.held[at..at + HELD_HEADER].copy_from_slice(&(sample.len() as u32).to_le_bytes());
        self.held[at + HELD_HEADER..at + HELD_HEADER + sample.len()].copy_from_slice(sample);
        self.held_count += 1;
        self.counts.held = self.counts.held.saturating_add(1);
        LiveFate::Held
    }

    /// Once the first round is over: copy the oldest held sample into `out` and give its length;
    /// `None` while the round holds them, and once none is left. `out` has room for the cell
    /// size the subscriber was made with; a sample longer than `out` is skipped.
    pub fn pop_released(&mut self, out: &mut [u8]) -> Option<usize> {
        if !self.released {
            return None;
        }
        while self.held_count > 0 {
            let at = self.held_head * (HELD_HEADER + self.held_cell);
            let mut word = [0u8; HELD_HEADER];
            word.copy_from_slice(&self.held[at..at + HELD_HEADER]);
            let len = u32::from_le_bytes(word) as usize;
            self.held_head = (self.held_head + 1) % self.held_cells;
            self.held_count -= 1;
            if len <= out.len() {
                out[..len].copy_from_slice(&self.held[at + HELD_HEADER..at + HELD_HEADER + len]);
                return Some(len);
            }
        }
        None
    }

    /// Look at the deadlines at `now` (`None` when the clock could not say, which judges
    /// nothing): a deadline armed without a clock counts from here, and a round whose progress or
    /// round deadline has passed is abandoned (before any publisher, the subscriber goes live).
    /// Gives whether this poll ended the round.
    pub fn poll(&mut self, now: Option<u32>) -> bool {
        let Some(at) = now else {
            return false;
        };
        self.progress.date(at);
        self.round.date(at);
        let passed = match self.phase() {
            Phase::Idle => self.round.passed(at, self.deadlines.round),
            Phase::Asking | Phase::Answering => {
                self.progress.passed(at, self.deadlines.progress)
                    || self.round.passed(at, self.deadlines.round)
            }
            Phase::Abandoned | Phase::Live => false,
        };
        if passed {
            self.drive(ReplayRoundEvent::DeadlinePassed, now);
        }
        passed
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec;
    use std::vec::Vec;

    const A: &[u8] = &[0xc1, 0x0a];
    const B: &[u8] = &[0xc1, 0x0b, 0x77];
    const DEADLINES: Deadlines = Deadlines {
        progress: 50,
        round: 400,
    };

    struct Store {
        slots: Vec<PublisherSlot>,
        held: Vec<u8>,
    }

    impl Store {
        fn new(rows: usize, held_cells: usize, cell: usize) -> Self {
            Self {
                slots: vec![PublisherSlot::EMPTY; rows],
                held: vec![0; held_cells * (HELD_HEADER + cell)],
            }
        }

        fn subscriber(
            &mut self,
            cell: usize,
            quota: usize,
            live: LiveBeforeAnswer,
        ) -> ReplaySubscriber<'_> {
            ReplaySubscriber::new(
                &mut self.slots,
                &mut self.held,
                cell,
                DEADLINES,
                quota,
                live,
                Some(0),
            )
            .expect("the store is made for it")
        }
    }

    fn released(sub: &mut ReplaySubscriber<'_>) -> Vec<Vec<u8>> {
        let mut out = [0u8; 8];
        let mut got = Vec::new();
        while let Some(len) = sub.pop_released(&mut out) {
            got.push(out[..len].to_vec());
        }
        got
    }

    #[test]
    fn a_publisher_row_has_the_layout_a_c_caller_sizes() {
        assert_eq!(core::mem::size_of::<PublisherSlot>(), 32);
        assert_eq!(core::mem::align_of::<PublisherSlot>(), 8);
    }

    #[test]
    fn a_subscriber_is_refused_by_name_for_each_bad_store() {
        let mut slots = [PublisherSlot::EMPTY; 2];
        let mut held = [0u8; 16];
        let make = |slots: &mut [PublisherSlot],
                    held: &mut [u8],
                    cell: usize,
                    deadlines: Deadlines,
                    quota: usize,
                    live: LiveBeforeAnswer| {
            ReplaySubscriber::new(slots, held, cell, deadlines, quota, live, None).err()
        };
        let deliver = LiveBeforeAnswer::Deliver;
        let hold = LiveBeforeAnswer::HoldBack;
        assert_eq!(
            make(&mut [], &mut held, 0, DEADLINES, 1, deliver),
            Some(CreateRefused::NoSlots)
        );
        assert_eq!(
            make(&mut slots, &mut held, 0, DEADLINES, 0, deliver),
            Some(CreateRefused::NoQuota)
        );
        let zero = Deadlines {
            progress: 0,
            round: 1,
        };
        assert_eq!(
            make(&mut slots, &mut held, 0, zero, 1, deliver),
            Some(CreateRefused::DeadlineOutOfRange)
        );
        let past = Deadlines {
            progress: 1,
            round: MAX_TIMEOUT_TICKS + 1,
        };
        assert_eq!(
            make(&mut slots, &mut held, 0, past, 1, deliver),
            Some(CreateRefused::DeadlineOutOfRange)
        );
        assert_eq!(
            make(&mut slots, &mut held, 0, DEADLINES, 1, hold),
            Some(CreateRefused::NoHoldStore),
            "a cell of 0 bytes"
        );
        assert_eq!(
            make(&mut slots, &mut held, 13, DEADLINES, 1, hold),
            Some(CreateRefused::NoHoldStore),
            "16 bytes hold no cell of 4 + 13"
        );
        assert_eq!(make(&mut slots, &mut held, 12, DEADLINES, 1, hold), None);
        assert_eq!(
            make(&mut slots, &mut [], 0, DEADLINES, 1, deliver),
            None,
            "deliver reads no store"
        );
    }

    #[test]
    fn each_publisher_is_asked_once_and_a_round_ends_when_every_query_ended() {
        let mut store = Store::new(4, 0, 0);
        let mut sub = store.subscriber(0, 4, LiveBeforeAnswer::Deliver);
        assert_eq!(sub.phase(), Phase::Idle);
        assert_eq!(sub.appeared(A, 10, Some(5)), Ok(Some(0)));
        assert_eq!(sub.phase(), Phase::Asking);
        assert_eq!(sub.zid(0), A);
        assert_eq!(
            sub.appeared(A, 11, Some(6)),
            Ok(None),
            "the same node declared again (another link) is not asked again"
        );
        assert_eq!(sub.reply(0, Some(7)), ReplyFate::Judge);
        assert_eq!(sub.phase(), Phase::Answering);
        assert_eq!(sub.query_ended(0, Some(8)), None);
        assert_eq!(sub.phase(), Phase::Live);
        assert_eq!(sub.in_flight(), 0);
        assert_eq!(sub.reply(0, Some(9)), ReplyFate::Late, "no query in flight");
        assert_eq!(sub.counts().unknown_replies, 1);
    }

    /// Two publishers appearing at different times: the second, once the first round is over,
    /// starts a round of its own; one that left and came back is asked again.
    #[test]
    fn a_publisher_that_appears_later_starts_its_own_round_and_one_that_returns_is_asked_again() {
        let mut store = Store::new(2, 0, 0);
        let mut sub = store.subscriber(0, 2, LiveBeforeAnswer::Deliver);
        assert_eq!(sub.appeared(A, 1, Some(0)), Ok(Some(0)));
        sub.query_ended(0, Some(1));
        assert_eq!(sub.phase(), Phase::Live);
        assert_eq!(sub.appeared(B, 2, Some(100)), Ok(Some(1)));
        assert_eq!(sub.phase(), Phase::Asking);
        assert_eq!(sub.zid(1), B);
        sub.query_ended(1, Some(101));
        assert_eq!(sub.phase(), Phase::Live);

        sub.gone(1, Some(102));
        assert_eq!(sub.appeared(A, 3, Some(103)), Ok(Some(0)), "A came back");
        assert_eq!(sub.phase(), Phase::Asking);
        sub.query_ended(0, Some(104));
        assert_eq!(
            sub.appeared(A, 4, Some(105)),
            Ok(None),
            "A answered and never left"
        );
        assert_eq!(sub.appeared(&[], 5, None), Err(AppearRefused::NoZid));
        assert_eq!(sub.appeared(&[1; 17], 5, None), Err(AppearRefused::NoZid));
    }

    #[test]
    fn a_full_table_refuses_a_new_publisher_and_reuses_the_row_of_one_that_left() {
        let mut store = Store::new(1, 0, 0);
        let mut sub = store.subscriber(0, 1, LiveBeforeAnswer::Deliver);
        assert_eq!(sub.appeared(A, 1, Some(0)), Ok(Some(0)));
        assert_eq!(sub.appeared(B, 2, Some(0)), Err(AppearRefused::Full));
        assert_eq!(sub.counts().table_full, 1);
        sub.query_ended(0, Some(1));
        sub.gone(1, Some(2));
        assert_eq!(sub.appeared(B, 3, Some(3)), Ok(Some(0)));
        assert_eq!(sub.zid(0), B);
    }

    #[test]
    fn the_quota_bounds_the_queries_in_flight_and_a_waiting_publisher_is_asked_as_one_ends() {
        let mut store = Store::new(3, 0, 0);
        let mut sub = store.subscriber(0, 1, LiveBeforeAnswer::Deliver);
        assert_eq!(sub.appeared(A, 1, Some(0)), Ok(Some(0)));
        assert_eq!(sub.appeared(B, 2, Some(0)), Ok(None), "the quota is used");
        assert_eq!(sub.in_flight(), 1);
        assert_eq!(sub.query_ended(0, Some(1)), Some(1), "B's turn");
        assert_eq!(sub.phase(), Phase::Asking, "the round waits for B");
        assert_eq!(sub.query_ended(1, Some(2)), None);
        assert_eq!(sub.phase(), Phase::Live);
    }

    #[test]
    fn a_publisher_that_leaves_before_it_is_asked_is_forgotten() {
        let mut store = Store::new(2, 0, 0);
        let mut sub = store.subscriber(0, 1, LiveBeforeAnswer::Deliver);
        sub.appeared(A, 1, Some(0)).unwrap();
        assert_eq!(sub.appeared(B, 2, Some(0)), Ok(None));
        sub.gone(2, Some(1));
        assert_eq!(sub.zid(1), &[] as &[u8]);
        assert_eq!(sub.query_ended(0, Some(2)), None);
        assert_eq!(sub.phase(), Phase::Live);
    }

    /// The progress deadline is counted again from each reply; when it passes, the round is
    /// abandoned, its query's later replies are late, and the subscriber is live.
    #[test]
    fn a_round_whose_replies_stop_is_abandoned_at_the_progress_deadline() {
        let mut store = Store::new(2, 0, 0);
        let mut sub = store.subscriber(0, 2, LiveBeforeAnswer::Deliver);
        sub.appeared(A, 1, Some(100)).unwrap();
        assert!(!sub.poll(Some(149)), "49 ticks: not yet");
        assert_eq!(sub.reply(0, Some(140)), ReplyFate::Judge);
        assert!(!sub.poll(Some(189)), "counted again from the reply at 140");
        assert!(sub.poll(Some(190)), "50 ticks after the last reply");
        assert_eq!(sub.phase(), Phase::Abandoned);
        assert_eq!(sub.reply(0, Some(191)), ReplyFate::Late);
        assert_eq!(sub.counts().late_replies, 1);
        assert_eq!(sub.counts().abandoned, 1);
        assert_eq!(sub.query_ended(0, Some(192)), None);
        assert_eq!(sub.in_flight(), 0);
        assert_eq!(sub.phase(), Phase::Abandoned);
    }

    #[test]
    fn a_round_that_keeps_answering_is_abandoned_at_the_round_deadline() {
        let mut store = Store::new(1, 0, 0);
        let mut sub = store.subscriber(0, 1, LiveBeforeAnswer::Deliver);
        sub.appeared(A, 1, Some(1000)).unwrap();
        let mut now = 1000;
        while now < 1399 {
            now += 40;
            assert_eq!(sub.reply(0, Some(now)), ReplyFate::Judge);
            if now < 1400 {
                assert!(
                    !sub.poll(Some(now)),
                    "at {now} the round has not lasted 400"
                );
            }
        }
        assert!(sub.poll(Some(1400)), "400 ticks after the round began");
        assert_eq!(sub.phase(), Phase::Abandoned);
    }

    #[test]
    fn a_deadline_armed_without_a_clock_counts_from_the_next_poll_that_has_one() {
        let mut store = Store::new(1, 0, 0);
        let mut sub = store.subscriber(0, 1, LiveBeforeAnswer::Deliver);
        sub.appeared(A, 1, None).unwrap();
        assert!(!sub.poll(None), "a poll without a clock judges nothing");
        assert!(!sub.poll(Some(5000)), "dated here");
        assert!(!sub.poll(Some(5049)));
        assert!(sub.poll(Some(5050)));
    }

    /// A deadline across the wrap of the 32-bit tick counter is the ordinary case.
    #[test]
    fn a_deadline_runs_across_the_wrap_of_the_tick_counter() {
        let mut store = Store::new(1, 0, 0);
        let mut sub = store.subscriber(0, 1, LiveBeforeAnswer::Deliver);
        sub.appeared(A, 1, Some(u32::MAX - 10)).unwrap();
        assert!(!sub.poll(Some(38)), "49 ticks across the wrap");
        assert!(sub.poll(Some(39)));
    }

    #[test]
    fn under_deliver_a_live_sample_is_never_held() {
        let mut store = Store::new(1, 0, 0);
        let mut sub = store.subscriber(0, 1, LiveBeforeAnswer::Deliver);
        assert_eq!(sub.live(b"x"), LiveFate::Deliver);
        sub.appeared(A, 1, Some(0)).unwrap();
        assert_eq!(sub.live(b"y"), LiveFate::Deliver);
        assert_eq!(sub.held(), 0);
    }

    /// Under hold-back the live samples wait for the first round and are released after its last
    /// reply, in the order they came; a later round holds nothing.
    #[test]
    fn under_hold_back_live_samples_wait_for_the_first_round_and_come_out_in_order() {
        let mut store = Store::new(2, 4, 8);
        let mut sub = store.subscriber(8, 2, LiveBeforeAnswer::HoldBack);
        assert_eq!(
            sub.live(b"l0"),
            LiveFate::Held,
            "held before anyone is asked"
        );
        sub.appeared(A, 1, Some(1)).unwrap();
        assert_eq!(sub.live(b"l1"), LiveFate::Held);
        assert_eq!(sub.reply(0, Some(2)), ReplyFate::Judge);
        assert_eq!(sub.live(b"l2"), LiveFate::Held);
        let mut out = [0u8; 8];
        assert_eq!(
            sub.pop_released(&mut out),
            None,
            "the round still holds them"
        );
        sub.query_ended(0, Some(3));
        assert_eq!(sub.phase(), Phase::Live);
        assert!(!sub.holding());
        assert_eq!(
            released(&mut sub),
            vec![b"l0".to_vec(), b"l1".to_vec(), b"l2".to_vec()]
        );
        assert_eq!(sub.live(b"l3"), LiveFate::Deliver);
        sub.appeared(B, 2, Some(4)).unwrap();
        assert_eq!(sub.phase(), Phase::Asking);
        assert_eq!(
            sub.live(b"l4"),
            LiveFate::Deliver,
            "a later round holds nothing"
        );
        assert_eq!(sub.counts().held, 3);
    }

    #[test]
    fn under_hold_back_a_full_store_abandons_the_round_rather_than_drop_a_sample() {
        let mut store = Store::new(1, 2, 4);
        let mut sub = store.subscriber(4, 1, LiveBeforeAnswer::HoldBack);
        sub.appeared(A, 1, Some(0)).unwrap();
        assert_eq!(sub.live(b"a"), LiveFate::Held);
        assert_eq!(sub.live(b"b"), LiveFate::Held);
        assert_eq!(sub.live(b"c"), LiveFate::Deliver, "no room: the round ends");
        assert_eq!(sub.phase(), Phase::Abandoned);
        assert_eq!(released(&mut sub), vec![b"a".to_vec(), b"b".to_vec()]);
        assert_eq!(sub.reply(0, Some(1)), ReplyFate::Late);
    }

    #[test]
    fn under_hold_back_a_sample_longer_than_a_cell_ends_the_round_too() {
        let mut store = Store::new(1, 2, 4);
        let mut sub = store.subscriber(4, 1, LiveBeforeAnswer::HoldBack);
        assert_eq!(sub.live(b"ok"), LiveFate::Held);
        assert_eq!(sub.live(b"toolong"), LiveFate::Deliver);
        assert_eq!(sub.phase(), Phase::Live, "no one was asked: live");
        assert_eq!(released(&mut sub), vec![b"ok".to_vec()]);
    }

    /// The hold is bounded by the round deadline even when no publisher ever appears.
    #[test]
    fn under_hold_back_no_publisher_at_all_releases_at_the_round_deadline() {
        let mut store = Store::new(1, 2, 4);
        let mut sub = store.subscriber(4, 1, LiveBeforeAnswer::HoldBack);
        assert_eq!(sub.live(b"x"), LiveFate::Held);
        assert!(!sub.poll(Some(399)));
        assert!(sub.poll(Some(400)));
        assert_eq!(sub.phase(), Phase::Live);
        assert_eq!(released(&mut sub), vec![b"x".to_vec()]);
    }
}
