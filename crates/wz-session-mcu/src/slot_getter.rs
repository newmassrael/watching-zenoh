// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The client node as a GETTER, written once for every platform: it asks the same query again and
//! again, keeping up to a number of them pending at once, and keeps the round trip of each in a
//! table the image declares. `slot_node` runs it with [`GetterLayer`] (the session's application
//! layer that asks) and [`GetterApp`] (what the loop does each round); a platform supplies the
//! clock, the table's size and a [`GetterReport`] (where the figures go and what ends the run).
//!
//! A query is asked the moment the session is established and again each time one has ended (its
//! final, or its deadline), so the number in flight stays at the asked number until the count is
//! reached. Two ways of asking, to measure what the second costs:
//!
//! - **in the event** (the default): the session's own application layer asks, inside its event,
//!   the instant a place is free. The time of a query is read when it is asked and when its final
//!   reaches the sink, both inside that event.
//! - **through the mailbox** ([`Ask::mailbox`]): the program's main loop, which is not the
//!   session's event, leaves the query in a [`GetMailbox`] and wakes the session's loop; the layer
//!   takes it on its next event. The time of a query starts when it is left, so it includes the
//!   wait for that event.
//!
//! The sink is a small value naming the query's slot in the [`Plan`]: the pending table keeps a
//! copy of the sink, and the state a reply changes lives in the `static` the image declares. Nothing
//! here allocates.
//!
//! # Time
//!
//! A round trip is read from the platform's [`ClockSource`] when the query is taken and when it
//! ends, so its resolution is the clock's: a kernel tick on the Zephyr image, a microsecond on
//! the host.

use core::cell::Cell;
use core::mem::MaybeUninit;
use core::ops::ControlFlow;

use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::ClockSource;
use wz_session_core::reply_sink::{ReplyKind, ReplySink, ReplyView};
use wz_session_core::sample::QosLevel;
use wz_session_core::slot_observer::{ObserverCell, ObserverSinks, Requesters};

use crate::app_layer::{GetError, GetRequest, NoReplies, SessionEvents, SlotDispatch};
use crate::get_mailbox::GetMailbox;
use crate::slot_client::DocumentSinks;
use crate::slot_node::{NodeApp, NodeHandle, SessionLayer};

/// What the node is told to do: the query, how many times, how it is asked.
#[derive(Debug, Clone, Copy)]
pub struct Ask {
    /// The key expression to ask.
    pub key: &'static str,
    /// How many queries in all, the warm-up included.
    pub count: u32,
    /// How long a query may stay pending, in milliseconds (0 is the default).
    pub timeout_ms: u32,
    /// How many of the first queries are not timed.
    pub warmup: u32,
    /// How many queries are pending at once (from 1 to the plan's `INFLIGHT`).
    pub inflight: u32,
    /// Whether the main loop leaves the queries in the mailbox.
    pub mailbox: bool,
}

/// The figures a run ends with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// Queries asked.
    pub issued: u32,
    /// Queries ended (a final, or a deadline).
    pub finished: u32,
    /// Replies that carried data.
    pub replies: u32,
    /// Error replies.
    pub errors: u32,
    /// Queries that ended at their deadline.
    pub timeouts: u32,
    /// Attempts that were refused (a full table, a refused write), the mailbox's included.
    pub refused: u32,
    /// Bytes of reply payload.
    pub payload_bytes: u64,
    /// Round trips kept.
    pub timed: usize,
    /// The shortest of them, in microseconds.
    pub min_us: u32,
    /// The median.
    pub median_us: u32,
    /// The 99th percentile.
    pub p99_us: u32,
    /// The longest.
    pub max_us: u32,
    /// From the first query being asked to the last one ending, warm-up included.
    pub elapsed_us: u64,
}

impl Summary {
    /// Whether every query was answered and none timed out, was an error or was refused.
    pub fn is_clean(&self) -> bool {
        self.errors == 0 && self.timeouts == 0 && self.replies >= self.finished
    }
}

/// Where a run stands: queries asked, ended, replies, error replies, refused attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    /// Queries asked.
    pub issued: u32,
    /// Queries ended.
    pub finished: u32,
    /// Replies that carried data.
    pub replies: u32,
    /// Error replies.
    pub errors: u32,
    /// Attempts refused.
    pub refused: u32,
}

/// What the node was asked to do and what has happened, in one `static`.
///
/// `SAMPLES` is how many round trips it keeps (more queries are asked but not timed), `INFLIGHT`
/// the most it holds pending at once and `ROWS` the rows of the mailbox (0 is a node that does not
/// ask through one). The pending table of a session needs one row more than `INFLIGHT`: the row a
/// late final of the last still holds.
///
/// # Where it lives
///
/// Every initial value is zero bytes (the key is an `Option`, the last refusal is left
/// uninitialised until there is one), so a `static` of it is placed in `.bss`: one non-zero byte in
/// it would move the whole round-trip table to `.data`, which costs its bytes in RAM and in flash.
/// The mailbox is not zero when it has rows (an empty row is an `Option` whose niche is not zero),
/// which is why a node on a small board has none.
pub struct Plan<C: 'static, const SAMPLES: usize, const INFLIGHT: usize, const ROWS: usize> {
    key: Cell<Option<&'static str>>,
    count: Cell<u32>,
    timeout_ms: Cell<u32>,
    warmup: Cell<u32>,
    inflight: Cell<u32>,
    mailbox_on: Cell<bool>,
    /// The slots of the queries not yet ended, as bits: a slot is the index the sink carries.
    busy: Cell<u8>,
    outstanding: Cell<u32>,
    issued: Cell<u32>,
    finished: Cell<u32>,
    replies: Cell<u32>,
    errors: Cell<u32>,
    refused: Cell<u32>,
    payload_bytes: Cell<u64>,
    timeouts: Cell<u32>,
    first_us: Cell<u64>,
    last_us: Cell<u64>,
    /// Why the last attempt was refused; valid once `refused` is not zero.
    last_refusal: Cell<MaybeUninit<GetError>>,
    started_us: [Cell<u64>; INFLIGHT],
    rtt_us: [Cell<u32>; SAMPLES],
    mailbox: GetMailbox<PlanSink<C, SAMPLES, INFLIGHT, ROWS>, ROWS>,
}

// SAFETY: the profile's rule: one thread runs the program, and the sink, the events and the main
// loop that write the plan all run in its one loop.
unsafe impl<C, const SAMPLES: usize, const INFLIGHT: usize, const ROWS: usize> Sync
    for Plan<C, SAMPLES, INFLIGHT, ROWS>
{
}

impl<C, const SAMPLES: usize, const INFLIGHT: usize, const ROWS: usize>
    Plan<C, SAMPLES, INFLIGHT, ROWS>
where
    C: ClockSource + Default + 'static,
{
    /// A plan that asks nothing.
    pub const fn new() -> Self {
        assert!(INFLIGHT >= 1 && INFLIGHT <= 8, "INFLIGHT is from 1 to 8");
        Self {
            key: Cell::new(None),
            count: Cell::new(0),
            timeout_ms: Cell::new(0),
            warmup: Cell::new(0),
            // Zero reads as one (`in_flight`): a one here would move the whole plan to `.data`.
            inflight: Cell::new(0),
            mailbox_on: Cell::new(false),
            busy: Cell::new(0),
            outstanding: Cell::new(0),
            issued: Cell::new(0),
            finished: Cell::new(0),
            replies: Cell::new(0),
            errors: Cell::new(0),
            refused: Cell::new(0),
            payload_bytes: Cell::new(0),
            timeouts: Cell::new(0),
            first_us: Cell::new(0),
            last_us: Cell::new(0),
            last_refusal: Cell::new(MaybeUninit::uninit()),
            started_us: [const { Cell::new(0) }; INFLIGHT],
            rtt_us: [const { Cell::new(0) }; SAMPLES],
            mailbox: GetMailbox::new(),
        }
    }

    /// Set what the node is to ask. A mailbox that has no rows is not used, whatever was asked:
    /// the queries are asked in the event, which is what [`uses_mailbox`](Self::uses_mailbox)
    /// then says.
    pub fn set(&self, ask: &Ask) {
        self.key.set(Some(ask.key));
        self.count.set(ask.count);
        self.timeout_ms.set(ask.timeout_ms);
        self.warmup.set(ask.warmup);
        self.inflight.set(ask.inflight.clamp(1, INFLIGHT as u32));
        self.mailbox_on.set(ask.mailbox && ROWS > 0);
    }

    /// Whether the node was asked to get at all.
    pub fn is_set(&self) -> bool {
        self.count.get() != 0
    }

    /// Whether the queries go through the mailbox.
    pub fn uses_mailbox(&self) -> bool {
        self.mailbox_on.get()
    }

    /// Whether every query asked for has ended.
    pub fn is_done(&self) -> bool {
        self.is_set() && self.finished.get() >= self.count.get()
    }

    /// How many queries may be pending at once: what was asked, and one for a plan not yet asked.
    fn in_flight(&self) -> u32 {
        self.inflight.get().max(1)
    }

    /// The lowest slot no query holds, if the node may have one more in flight.
    fn free_slot(&self) -> Option<u8> {
        if self.issued.get() >= self.count.get() || self.outstanding.get() >= self.in_flight() {
            return None;
        }
        (0..INFLIGHT as u8).find(|slot| self.busy.get() & (1 << slot) == 0)
    }

    /// A query takes `slot`: counted as asked, timed from now.
    fn take(&self, slot: u8) {
        let now_us = C::default().now_us();
        if self.issued.get() == 0 {
            self.first_us.set(now_us);
        }
        self.started_us[slot as usize].set(now_us);
        self.busy.set(self.busy.get() | (1 << slot));
        self.outstanding.set(self.outstanding.get() + 1);
        self.issued.set(self.issued.get() + 1);
    }

    /// A query that was taken was not asked after all: nothing is pending and nothing was sent.
    fn give_back(&self, slot: u8, why: GetError) {
        self.release(slot);
        self.refused.set(self.refused.get() + 1);
        self.last_refusal.set(MaybeUninit::new(why));
    }

    /// A taken slot goes back with its count: the query was never asked.
    fn release(&self, slot: u8) {
        self.busy.set(self.busy.get() & !(1 << slot));
        self.outstanding.set(self.outstanding.get() - 1);
        self.issued.set(self.issued.get() - 1);
    }

    /// The request of the next query.
    fn request(&self) -> GetRequest<'static> {
        GetRequest {
            keyexpr: self.key.get().unwrap_or(""),
            parameters: b"",
            // The peer's default, as `z_get` with its default options and pico's example ask: no
            // consolidation flag on the wire.
            consolidation: None,
            target: None,
            timeout_ms: self.timeout_ms.get(),
            qos: QosLevel::DEFAULT,
        }
    }

    /// Leave as many queries in the mailbox as there are places free, from the main loop. How many
    /// were left: the caller wakes the session's loop when it is not none.
    pub fn top_up(&'static self) -> u32 {
        let mut left = 0;
        while let Some(slot) = self.free_slot() {
            self.take(slot);
            let sink = PlanSink { plan: self, slot };
            if self.mailbox.post(&self.request(), sink).is_err() {
                // The mailbox has no room: a place is free in the plan and not in the mailbox,
                // which the layer's next event makes right. Try again then.
                self.release(slot);
                break;
            }
            left += 1;
        }
        left
    }

    /// A reply arrived for a query in flight.
    fn reply(&self, view: &dyn ReplyView) {
        if view.kind() == ReplyKind::Err {
            self.errors.set(self.errors.get() + 1);
        } else {
            self.replies.set(self.replies.get() + 1);
            self.payload_bytes
                .set(self.payload_bytes.get() + view.payload().len() as u64);
        }
    }

    /// The query in `slot` ended.
    fn end(&self, slot: u8, timed_out: bool) {
        let now_us = C::default().now_us();
        if let Some(timed_at) = self.finished.get().checked_sub(self.warmup.get()) {
            if let Some(cell) = self.rtt_us.get(timed_at as usize) {
                let elapsed = now_us.saturating_sub(self.started_us[slot as usize].get());
                cell.set(u32::try_from(elapsed).unwrap_or(u32::MAX));
            }
        }
        if timed_out {
            self.timeouts.set(self.timeouts.get() + 1);
        }
        self.last_us.set(now_us);
        self.finished.set(self.finished.get() + 1);
        self.busy.set(self.busy.get() & !(1 << slot));
        self.outstanding
            .set(self.outstanding.get().saturating_sub(1));
    }

    /// Why the last attempt was refused, if one was.
    pub fn last_refusal(&self) -> Option<GetError> {
        if self.refused.get() == 0 {
            return None;
        }
        // SAFETY: `refused` moves from zero only in `give_back`, after it stored the reason.
        Some(unsafe { self.last_refusal.get().assume_init() })
    }

    /// Where the run stands.
    pub fn progress(&self) -> Progress {
        Progress {
            issued: self.issued.get(),
            finished: self.finished.get(),
            replies: self.replies.get(),
            errors: self.errors.get(),
            refused: self.refused.get(),
        }
    }

    /// The figures of the run. Sorts the timed round trips in place, so it is called once, when
    /// the run is over.
    pub fn summary(&self) -> Summary {
        let timed = (self.finished.get().saturating_sub(self.warmup.get()) as usize).min(SAMPLES);
        // SAFETY of the cast: `Cell<u32>` has the layout of a `u32`, and nothing else reads the
        // table while the loop is here: the run is over.
        let samples: &mut [u32] =
            unsafe { core::slice::from_raw_parts_mut(self.rtt_us.as_ptr() as *mut u32, timed) };
        samples.sort_unstable();
        let at = |per_mille: usize| -> u32 {
            if samples.is_empty() {
                0
            } else {
                samples[(samples.len() * per_mille / 1000).min(samples.len() - 1)]
            }
        };
        Summary {
            issued: self.issued.get(),
            finished: self.finished.get(),
            replies: self.replies.get(),
            errors: self.errors.get(),
            timeouts: self.timeouts.get(),
            // Counting what the mailbox refused for good, which the plan counts as in flight.
            refused: self.refused.get() + self.mailbox.rejected(),
            payload_bytes: self.payload_bytes.get(),
            timed,
            min_us: at(0),
            median_us: at(500),
            p99_us: at(990),
            max_us: samples.last().copied().unwrap_or(0),
            elapsed_us: self.last_us.get().saturating_sub(self.first_us.get()),
        }
    }
}

impl<C, const SAMPLES: usize, const INFLIGHT: usize, const ROWS: usize> Default
    for Plan<C, SAMPLES, INFLIGHT, ROWS>
where
    C: ClockSource + Default + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

/// The sink of every query this node asks: the slot of the query in its [`Plan`], whose state is
/// the `static`'s.
pub struct PlanSink<C: 'static, const SAMPLES: usize, const INFLIGHT: usize, const ROWS: usize> {
    plan: &'static Plan<C, SAMPLES, INFLIGHT, ROWS>,
    slot: u8,
}

impl<C, const SAMPLES: usize, const INFLIGHT: usize, const ROWS: usize> Clone
    for PlanSink<C, SAMPLES, INFLIGHT, ROWS>
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<C, const SAMPLES: usize, const INFLIGHT: usize, const ROWS: usize> Copy
    for PlanSink<C, SAMPLES, INFLIGHT, ROWS>
{
}

impl<C, const SAMPLES: usize, const INFLIGHT: usize, const ROWS: usize> ReplySink
    for PlanSink<C, SAMPLES, INFLIGHT, ROWS>
where
    C: ClockSource + Default + 'static,
{
    fn on_reply(&mut self, reply: &dyn ReplyView) {
        self.plan.reply(reply);
    }

    fn on_final(&mut self, _rid: u64) {
        self.plan.end(self.slot, false);
    }

    /// An expired query ends with a timeout, which is counted and not delivered as a reply: the
    /// default would hand the sink a synthetic error first.
    fn on_timeout(&mut self, _rid: u64) {
        self.plan.end(self.slot, true);
    }
}

/// The requests a session of this node holds: the pending queries, and no liveliness get.
pub type Requests<C, const SAMPLES: usize, const INFLIGHT: usize, const ROWS: usize> =
    Requesters<PlanSink<C, SAMPLES, INFLIGHT, ROWS>, NoReplies>;

/// The application layer of a getter session: the node's dispatch, and the queries asked as soon as
/// a place is free (in the event), or the mailbox taken (mailbox mode).
pub struct GetterEvents<C, K, const SAMPLES: usize, const INFLIGHT: usize, const ROWS: usize>
where
    C: ClockSource + Default + 'static,
    K: ObserverSinks + 'static,
{
    inner: SlotDispatch<C, PlanSink<C, SAMPLES, INFLIGHT, ROWS>, NoReplies, K>,
    plan: &'static Plan<C, SAMPLES, INFLIGHT, ROWS>,
}

/// What a getter's sessions report to: the node's dispatch with the pending queries it asks.
pub struct GetterLayer<C: 'static, const SAMPLES: usize, const INFLIGHT: usize, const ROWS: usize> {
    plan: &'static Plan<C, SAMPLES, INFLIGHT, ROWS>,
}

impl<C: 'static, const SAMPLES: usize, const INFLIGHT: usize, const ROWS: usize>
    GetterLayer<C, SAMPLES, INFLIGHT, ROWS>
{
    /// The layer of a node that asks as `plan` says.
    pub const fn new(plan: &'static Plan<C, SAMPLES, INFLIGHT, ROWS>) -> Self {
        Self { plan }
    }
}

impl<C, const SAMPLES: usize, const INFLIGHT: usize, const ROWS: usize> SessionLayer<C>
    for GetterLayer<C, SAMPLES, INFLIGHT, ROWS>
where
    C: ClockSource + Default + 'static,
{
    type Events = GetterEvents<C, DocumentSinks, SAMPLES, INFLIGHT, ROWS>;

    fn events(
        &mut self,
        observer: &'static ObserverCell<DocumentSinks>,
        handle: &SessionHandle<C>,
    ) -> Self::Events {
        GetterEvents {
            inner: SlotDispatch::new(
                observer,
                handle.clone(),
                Requests::<C, SAMPLES, INFLIGHT, ROWS>::new(),
            ),
            plan: self.plan,
        }
    }
}

impl<C, K, const SAMPLES: usize, const INFLIGHT: usize, const ROWS: usize> SessionEvents
    for GetterEvents<C, K, SAMPLES, INFLIGHT, ROWS>
where
    C: ClockSource + Default + 'static,
    K: ObserverSinks + 'static,
{
    fn on_event(&mut self, event: wz_session_core::driver_loop::IterationEvent<'_>) {
        self.inner.on_event(event);
        let plan = self.plan;
        if plan.uses_mailbox() {
            // What the main loop left; it also wakes the loop when it leaves something.
            self.inner.drain_mailbox(&plan.mailbox);
            return;
        }
        // A query is asked when the session can send it and a place is free.
        while self.inner.is_established() {
            let Some(slot) = plan.free_slot() else {
                return;
            };
            plan.take(slot);
            match self.inner.get(&plan.request(), PlanSink { plan, slot }) {
                Ok(_) => {}
                Err(why) => {
                    // Refused: nothing is pending and nothing was sent. It is counted and the
                    // next event asks again, so a session that has just lost its transport does
                    // not end the run with a query that was never asked. The last reason is
                    // kept, because a count alone cannot tell a full table from a refused write.
                    plan.give_back(slot, why);
                    return;
                }
            }
        }
    }
}

/// Where a getter's figures go and what its end does: the platform's console, and the exit code of
/// a process or the continuing of a firmware.
pub trait GetterReport {
    /// A line of where the run stands, called about once a second while the node was asked to get.
    fn progress(&mut self, progress: &Progress, last_refusal: Option<GetError>);

    /// Every query ended: the run's figures. `Break(code)` ends the node with that exit code; a
    /// firmware that has nowhere to exit to continues and keeps answering.
    fn done(&mut self, summary: &Summary) -> ControlFlow<i32>;
}

/// What the getter does each round of the node's loop: says where it is once a second, reports
/// when every query it was asked to make has ended, and, in mailbox mode, leaves what is due in the
/// mailbox and wakes the session's loop to take it.
pub struct GetterApp<C, R, const SAMPLES: usize, const INFLIGHT: usize, const ROWS: usize>
where
    C: 'static,
{
    plan: &'static Plan<C, SAMPLES, INFLIGHT, ROWS>,
    report: R,
    progress_at_ms: u64,
    reported: bool,
}

impl<C, R, const SAMPLES: usize, const INFLIGHT: usize, const ROWS: usize>
    GetterApp<C, R, SAMPLES, INFLIGHT, ROWS>
where
    C: 'static,
{
    /// The application of a node that asks as `plan` says and reports to `report`.
    pub const fn new(plan: &'static Plan<C, SAMPLES, INFLIGHT, ROWS>, report: R) -> Self {
        Self {
            plan,
            report,
            progress_at_ms: 0,
            reported: false,
        }
    }
}

impl<C, R, const SAMPLES: usize, const INFLIGHT: usize, const ROWS: usize> NodeApp
    for GetterApp<C, R, SAMPLES, INFLIGHT, ROWS>
where
    C: ClockSource + Default + 'static,
    R: GetterReport,
{
    fn after_tick(&mut self, now_ms: u64, node: &dyn NodeHandle) -> ControlFlow<i32> {
        let plan = self.plan;
        if self.reported {
            return ControlFlow::Continue(());
        }
        // A getter says where it is once a second, so a run that does not end can be told from
        // one that is slow.
        if plan.is_set() && now_ms >= self.progress_at_ms {
            self.progress_at_ms = now_ms + 1_000;
            self.report.progress(&plan.progress(), plan.last_refusal());
        }
        // A getter is done when every query it was asked to make has ended, and says how they went.
        // It says so once: a firmware that goes on answering is not asked again.
        if plan.is_done() {
            self.reported = true;
            return self.report.done(&plan.summary());
        }
        // Mailbox mode: this loop is not the session's event, so what it asks it leaves, and wakes
        // the session's loop to take it.
        if plan.uses_mailbox() && node.is_established() && plan.top_up() > 0 {
            node.wake();
        }
        ControlFlow::Continue(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::get_mailbox::Disposition;
    use alloc::boxed::Box;
    use core::cell::Cell as StdCell;
    use wz_session_core::registry_error::RegisterError;

    std::thread_local! {
        static NOW_US: StdCell<u64> = const { StdCell::new(0) };
    }

    /// A clock the test moves by hand; each test runs on a thread of its own.
    #[derive(Default, Clone, Copy)]
    struct TestClock;

    impl ClockSource for TestClock {
        fn now_us(&self) -> u64 {
            NOW_US.with(StdCell::get)
        }
    }

    fn at(us: u64) {
        NOW_US.with(|now| now.set(us));
    }

    type TestPlan = Plan<TestClock, 8, 3, 2>;

    fn plan(count: u32, warmup: u32, inflight: u32) -> &'static TestPlan {
        let plan: &'static TestPlan = Box::leak(Box::new(Plan::new()));
        plan.set(&Ask {
            key: "demo/k",
            count,
            timeout_ms: 0,
            warmup,
            inflight,
            mailbox: false,
        });
        at(0);
        plan
    }

    #[test]
    fn a_plan_that_was_not_asked_asks_nothing() {
        let plan: &'static TestPlan = Box::leak(Box::new(Plan::new()));
        assert!(!plan.is_set());
        assert!(!plan.is_done());
        assert_eq!(plan.free_slot(), None);
    }

    #[test]
    fn a_plan_whose_inflight_was_never_set_holds_one_query_at_a_time() {
        // The number is zero bytes until it is set, which is what keeps the plan in `.bss`.
        let plan: &'static TestPlan = Box::leak(Box::new(Plan::new()));
        plan.count.set(3);
        assert_eq!(plan.free_slot(), Some(0));
        plan.take(0);
        assert_eq!(plan.free_slot(), None);
    }

    #[test]
    fn no_more_are_in_flight_than_were_asked_for_and_slots_are_the_lowest_free() {
        let plan = plan(10, 0, 2);
        assert_eq!(plan.free_slot(), Some(0));
        plan.take(0);
        assert_eq!(plan.free_slot(), Some(1));
        plan.take(1);
        // Two are pending: no third.
        assert_eq!(plan.free_slot(), None);
        plan.end(0, false);
        // The slot that ended is the lowest free again.
        assert_eq!(plan.free_slot(), Some(0));
    }

    #[test]
    fn the_inflight_asked_is_held_to_the_plans_rows() {
        let plan = plan(10, 0, 100);
        for _ in 0..3 {
            let slot = plan.free_slot().unwrap();
            plan.take(slot);
        }
        // 3 is the plan's INFLIGHT.
        assert_eq!(plan.free_slot(), None);
    }

    #[test]
    fn nothing_more_is_asked_once_the_count_is_reached() {
        let plan = plan(2, 0, 3);
        plan.take(0);
        plan.take(1);
        assert_eq!(plan.free_slot(), None);
        plan.end(0, false);
        plan.end(1, false);
        // Both asked and ended: done, and still nothing to ask.
        assert_eq!(plan.free_slot(), None);
        assert!(plan.is_done());
    }

    #[test]
    fn a_query_that_was_not_asked_after_all_is_given_back_with_its_reason() {
        let plan = plan(2, 0, 2);
        assert_eq!(plan.last_refusal(), None);
        plan.take(0);
        let why = GetError::Register(RegisterError::TableFull);
        plan.give_back(0, why);
        let progress = plan.progress();
        assert_eq!(progress.issued, 0);
        assert_eq!(progress.refused, 1);
        assert_eq!(plan.last_refusal(), Some(why));
        // The slot and the count are back: it is asked again.
        assert_eq!(plan.free_slot(), Some(0));
    }

    #[test]
    fn the_warm_up_is_asked_and_not_timed() {
        let plan = plan(3, 1, 1);
        for (start, end) in [(0u64, 100u64), (100, 150), (150, 270)] {
            at(start);
            plan.take(0);
            at(end);
            plan.end(0, false);
        }
        let s = plan.summary();
        assert_eq!((s.issued, s.finished, s.timed), (3, 3, 2));
        // 50 us and 120 us; the 100 us of the warm-up is not among them.
        assert_eq!((s.min_us, s.max_us), (50, 120));
        assert_eq!(s.elapsed_us, 270);
    }

    #[test]
    fn the_median_and_the_tail_are_read_from_the_sorted_round_trips() {
        let plan = plan(5, 0, 1);
        let mut clock = 0;
        for rtt in [500u64, 100, 300, 200, 400] {
            at(clock);
            plan.take(0);
            clock += rtt;
            at(clock);
            plan.end(0, false);
        }
        let s = plan.summary();
        assert_eq!(s.timed, 5);
        assert_eq!((s.min_us, s.median_us, s.max_us), (100, 300, 500));
        assert_eq!(s.p99_us, 500);
    }

    #[test]
    fn a_timeout_is_counted_and_ends_the_query() {
        let plan = plan(1, 0, 1);
        plan.take(0);
        plan.end(0, true);
        let s = plan.summary();
        assert_eq!((s.finished, s.timeouts), (1, 1));
        assert!(!s.is_clean());
    }

    #[test]
    fn more_queries_than_the_table_keeps_are_asked_and_not_timed() {
        // 8 samples; ten queries, none of them warm-up.
        let plan = plan(10, 0, 1);
        for _ in 0..10 {
            plan.take(0);
            plan.end(0, false);
        }
        let s = plan.summary();
        assert_eq!((s.finished, s.timed), (10, 8));
    }

    #[test]
    fn the_mailbox_is_used_only_by_a_plan_that_has_rows() {
        let ask = Ask {
            key: "demo/k",
            count: 4,
            timeout_ms: 0,
            warmup: 0,
            inflight: 2,
            mailbox: true,
        };
        let with: &'static TestPlan = Box::leak(Box::new(Plan::new()));
        with.set(&ask);
        assert!(with.uses_mailbox());
        let without: &'static Plan<TestClock, 8, 3, 0> = Box::leak(Box::new(Plan::new()));
        without.set(&ask);
        // Asked for and not available: the queries are asked in the event.
        assert!(!without.uses_mailbox());
        assert!(without.is_set());
    }

    #[test]
    fn the_main_loop_leaves_as_many_queries_as_there_are_places() {
        let plan = plan(5, 0, 2);
        plan.mailbox_on.set(true);
        // Two places in flight, two rows: both are left; none more until one ends.
        assert_eq!(plan.top_up(), 2);
        assert_eq!(plan.mailbox.waiting(), 2);
        assert_eq!(plan.top_up(), 0);
        // The session's layer takes both rows: the rows are free, the places are not (those two
        // queries are pending), so nothing more is left.
        plan.mailbox.drain(|_, _| Disposition::Asked);
        assert_eq!(plan.mailbox.waiting(), 0);
        assert_eq!(plan.top_up(), 0);
        plan.end(0, false);
        assert_eq!(plan.top_up(), 1);
        assert_eq!(plan.progress().issued, 3);
    }

    #[test]
    fn a_place_is_not_taken_while_the_mailbox_still_holds_the_rows() {
        let plan = plan(5, 0, 2);
        plan.mailbox_on.set(true);
        assert_eq!(plan.top_up(), 2);
        // A query ended before the layer took the rows: a place is free and no row is.
        plan.end(0, false);
        assert_eq!(plan.top_up(), 0);
        assert_eq!(plan.progress().issued, 2);
    }

    #[test]
    fn a_full_mailbox_gives_the_place_back_to_try_again() {
        // Three places in flight and two rows: the third query is not left, and its place stays free.
        let plan = plan(5, 0, 3);
        plan.mailbox_on.set(true);
        assert_eq!(plan.top_up(), 2);
        assert_eq!(plan.progress().issued, 2);
        assert_eq!(plan.free_slot(), Some(2));
    }

    #[test]
    fn a_clean_run_answers_every_query() {
        let plan = plan(1, 0, 1);
        plan.take(0);
        plan.replies.set(1);
        plan.end(0, false);
        assert!(plan.summary().is_clean());
    }

    struct Recorder {
        progress: u32,
        done: u32,
        exit: ControlFlow<i32>,
    }

    impl GetterReport for Recorder {
        fn progress(&mut self, _progress: &Progress, _last_refusal: Option<GetError>) {
            self.progress += 1;
        }

        fn done(&mut self, _summary: &Summary) -> ControlFlow<i32> {
            self.done += 1;
            self.exit
        }
    }

    struct Handle;

    impl NodeHandle for Handle {
        fn is_established(&self) -> bool {
            true
        }

        fn wake(&self) {}
    }

    fn app(
        plan: &'static TestPlan,
        exit: ControlFlow<i32>,
    ) -> GetterApp<TestClock, Recorder, 8, 3, 2> {
        GetterApp::new(
            plan,
            Recorder {
                progress: 0,
                done: 0,
                exit,
            },
        )
    }

    #[test]
    fn progress_is_said_once_a_second_and_only_for_a_node_that_was_asked() {
        let unasked: &'static TestPlan = Box::leak(Box::new(Plan::new()));
        let mut quiet = app(unasked, ControlFlow::Continue(()));
        let _ = quiet.after_tick(5_000, &Handle);
        assert_eq!(quiet.report.progress, 0);

        let mut app = app(plan(5, 0, 1), ControlFlow::Continue(()));
        for ms in [0, 500, 999] {
            let _ = app.after_tick(ms, &Handle);
        }
        // The first round says it; the next two are inside the second.
        assert_eq!(app.report.progress, 1);
        let _ = app.after_tick(1_000, &Handle);
        assert_eq!(app.report.progress, 2);
    }

    #[test]
    fn the_end_is_reported_once_and_its_code_is_the_platforms() {
        let plan = plan(1, 0, 1);
        plan.take(0);
        plan.end(0, false);

        let mut exiting = app(plan, ControlFlow::Break(7));
        assert_eq!(exiting.after_tick(0, &Handle), ControlFlow::Break(7));
        // A firmware that continues is not asked again.
        let mut staying = app(plan, ControlFlow::Continue(()));
        assert_eq!(staying.after_tick(0, &Handle), ControlFlow::Continue(()));
        assert_eq!(
            staying.after_tick(10_000, &Handle),
            ControlFlow::Continue(())
        );
        assert_eq!(staying.report.done, 1);
        assert_eq!(staying.report.progress, 1);
    }
}
