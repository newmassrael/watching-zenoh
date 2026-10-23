// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The node as a GETTER: it asks the same query again and again, keeping up to `--inflight`
//! of them pending at once, and keeps the round trip of each in a table this file declares.
//!
//! A query is asked the moment the session is established and again each time one has ended (its
//! final, or its deadline), so the number in flight stays at `--inflight` until the count is
//! reached. Two ways of asking, to measure what the second costs:
//!
//! - **in the event** (the default): the session's own application layer asks, inside its event,
//!   the instant a place is free. The time of a query is read when it is asked and when its final
//!   reaches the sink, both inside that event.
//! - **through the mailbox** (`--mailbox`): the program's main loop, which is not the session's
//!   event, leaves the query in a [`GetMailbox`] and wakes the session's loop; the layer takes it
//!   on its next event. The time of a query starts when it is left, so it includes the wait for
//!   that event.
//!
//! The sink is a small value naming the query's slot in [`PLAN`]: the pending table keeps a copy of
//! the sink, and the state a reply changes lives in the `static`. Nothing here allocates.

use core::cell::Cell;
use core::ops::ControlFlow;

use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::ClockSource;
use wz_runtime_posix::glue::log_args;
use wz_session_core::reply_sink::{ReplyKind, ReplySink, ReplyView};
use wz_session_core::sample::QosLevel;
use wz_session_core::slot_observer::{ObserverCell, ObserverSinks, Requesters};
use wz_session_mcu::app_layer::{GetError, GetRequest, NoReplies, SessionEvents, SlotDispatch};
use wz_session_mcu::get_mailbox::GetMailbox;
use wz_session_mcu::slot_client::DocumentSinks;
use wz_session_mcu::slot_node::{NodeApp, NodeHandle, SessionLayer};

use crate::Clock;

/// The round trips the node keeps: more queries than this are asked but not timed.
pub const SAMPLES: usize = 4096;

/// The most queries in flight at once: the mailbox's rows and the plan's slots.
pub const MAX_INFLIGHT: usize = 8;

/// Where the program's main loop leaves the queries of `--mailbox`.
pub static MAILBOX: GetMailbox<PlanSink, MAX_INFLIGHT> = GetMailbox::new();

/// What the node was asked to do and what has happened, in one `static`.
pub struct Plan {
    key: Cell<&'static str>,
    count: Cell<u32>,
    timeout_ms: Cell<u32>,
    warmup: Cell<u32>,
    inflight: Cell<u32>,
    mailbox: Cell<bool>,
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
    last_refusal: Cell<Option<GetError>>,
    started_us: [Cell<u64>; MAX_INFLIGHT],
    rtt_us: [Cell<u32>; SAMPLES],
}

// SAFETY: the profile's rule: one thread runs the program, and the sink, the events and the main
// loop that write the plan all run in its one loop.
unsafe impl Sync for Plan {}

pub static PLAN: Plan = Plan {
    key: Cell::new(""),
    count: Cell::new(0),
    timeout_ms: Cell::new(0),
    warmup: Cell::new(0),
    inflight: Cell::new(1),
    mailbox: Cell::new(false),
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
    last_refusal: Cell::new(None),
    started_us: [const { Cell::new(0) }; MAX_INFLIGHT],
    rtt_us: [const { Cell::new(0) }; SAMPLES],
};

/// The figures a run ends with.
pub struct Summary {
    pub issued: u32,
    pub finished: u32,
    pub replies: u32,
    pub errors: u32,
    pub timeouts: u32,
    pub refused: u32,
    pub payload_bytes: u64,
    pub timed: usize,
    pub min_us: u32,
    pub median_us: u32,
    pub p99_us: u32,
    pub max_us: u32,
    /// From the first query being asked to the last one ending, warm-up included.
    pub elapsed_us: u64,
}

/// What the node is told to do: the query, how many times, how it is asked.
pub struct Ask {
    pub key: &'static str,
    pub count: u32,
    pub timeout_ms: u32,
    pub warmup: u32,
    pub inflight: u32,
    pub mailbox: bool,
}

impl Plan {
    /// Set what the node is to ask.
    pub fn set(&self, ask: &Ask) {
        self.key.set(ask.key);
        self.count.set(ask.count);
        self.timeout_ms.set(ask.timeout_ms);
        self.warmup.set(ask.warmup);
        self.inflight
            .set(ask.inflight.clamp(1, MAX_INFLIGHT as u32));
        self.mailbox.set(ask.mailbox);
    }

    /// Whether the node was asked to get at all.
    pub fn is_set(&self) -> bool {
        self.count.get() != 0
    }

    /// Whether the queries go through the mailbox.
    pub fn uses_mailbox(&self) -> bool {
        self.mailbox.get()
    }

    /// Whether every query asked for has ended.
    pub fn is_done(&self) -> bool {
        self.is_set() && self.finished.get() >= self.count.get()
    }

    /// The lowest slot no query holds, if the node may have one more in flight.
    fn free_slot(&self) -> Option<u8> {
        if self.issued.get() >= self.count.get() || self.outstanding.get() >= self.inflight.get() {
            return None;
        }
        (0..MAX_INFLIGHT as u8).find(|slot| self.busy.get() & (1 << slot) == 0)
    }

    /// A query takes `slot`: counted as asked, timed from now.
    fn take(&self, slot: u8) {
        let now_us = Clock::default().now_us();
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
        self.busy.set(self.busy.get() & !(1 << slot));
        self.outstanding.set(self.outstanding.get() - 1);
        self.issued.set(self.issued.get() - 1);
        self.refused.set(self.refused.get() + 1);
        self.last_refusal.set(Some(why));
    }

    /// The request of the next query, in `slot`.
    fn request(&self) -> GetRequest<'static> {
        GetRequest {
            keyexpr: self.key.get(),
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
    pub fn top_up(&self) -> u32 {
        let mut left = 0;
        while let Some(slot) = self.free_slot() {
            self.take(slot);
            if MAILBOX.post(&self.request(), PlanSink { slot }).is_err() {
                // The mailbox has no room: a place is free in the plan and not in the mailbox,
                // which the layer's next event makes right. Try again then.
                self.busy.set(self.busy.get() & !(1 << slot));
                self.outstanding.set(self.outstanding.get() - 1);
                self.issued.set(self.issued.get() - 1);
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
        let now_us = Clock::default().now_us();
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
        self.last_refusal.get()
    }

    /// Where the run stands: queries issued, ended, replies, error replies, refused attempts.
    pub fn progress(&self) -> (u32, u32, u32, u32, u32) {
        (
            self.issued.get(),
            self.finished.get(),
            self.replies.get(),
            self.errors.get(),
            self.refused.get(),
        )
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
            refused: self.refused.get() + MAILBOX.rejected(),
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

/// The sink of every query this node asks: the slot of the query in [`PLAN`], whose state is the
/// `static`'s.
#[derive(Clone, Copy, Default)]
pub struct PlanSink {
    slot: u8,
}

impl ReplySink for PlanSink {
    fn on_reply(&mut self, reply: &dyn ReplyView) {
        PLAN.reply(reply);
    }

    fn on_final(&mut self, _rid: u64) {
        PLAN.end(self.slot, false);
    }

    /// An expired query ends with a timeout, which is counted and not delivered as a reply: the
    /// default would hand the sink a synthetic error first.
    fn on_timeout(&mut self, _rid: u64) {
        PLAN.end(self.slot, true);
    }
}

/// The requests a session of this node holds: the pending queries, and no liveliness get.
pub type Requests = Requesters<PlanSink, NoReplies>;

/// The application layer of a getter session: the node's dispatch, and the queries asked as soon as
/// a place is free (in the event), or the mailbox taken (`--mailbox`).
pub struct GetterEvents<K: ObserverSinks + 'static> {
    inner: SlotDispatch<Clock, PlanSink, NoReplies, K>,
}

impl<K: ObserverSinks + 'static> GetterEvents<K> {
    pub fn new(inner: SlotDispatch<Clock, PlanSink, NoReplies, K>) -> Self {
        Self { inner }
    }
}

/// What a getter's sessions report to: the node's dispatch with the pending queries it asks.
pub struct GetterLayer;

impl SessionLayer<Clock> for GetterLayer {
    type Events = GetterEvents<DocumentSinks>;

    fn events(
        &mut self,
        observer: &'static ObserverCell<DocumentSinks>,
        handle: &SessionHandle<Clock>,
    ) -> Self::Events {
        GetterEvents::new(SlotDispatch::new(observer, handle.clone(), Requests::new()))
    }
}

/// What the getter does each round of the node's loop: says where it is once a second, ends the run
/// when every query it was asked to make has ended, and, for `--mailbox`, leaves what is due in the
/// mailbox and wakes the session's loop to take it.
pub struct GetterApp {
    progress_at_ms: u64,
}

impl GetterApp {
    pub const fn new() -> Self {
        Self { progress_at_ms: 0 }
    }
}

impl NodeApp for GetterApp {
    fn after_tick(&mut self, now_ms: u64, node: &dyn NodeHandle) -> ControlFlow<i32> {
        // A getter says where it is once a second, so a run that does not end can be told from
        // one that is slow.
        if PLAN.is_set() && now_ms >= self.progress_at_ms {
            self.progress_at_ms = now_ms + 1_000;
            let s = PLAN.progress();
            log_args(format_args!(
                "HOST-WZ-GET progress issued={} finished={} replies={} errors={} refused={} \
                 last_refusal={:?}",
                s.0,
                s.1,
                s.2,
                s.3,
                s.4,
                PLAN.last_refusal()
            ));
        }
        // A getter ends when every query it was asked to make has ended, and says how they went.
        if PLAN.is_done() {
            return ControlFlow::Break(crate::report_gets());
        }
        // `--mailbox`: this loop is not the session's event, so what it asks it leaves, and wakes
        // the session's loop to take it.
        if PLAN.uses_mailbox() && node.is_established() && PLAN.top_up() > 0 {
            node.wake();
        }
        ControlFlow::Continue(())
    }
}

impl<K: ObserverSinks + 'static> SessionEvents for GetterEvents<K> {
    fn on_event(&mut self, event: wz_session_core::driver_loop::IterationEvent<'_>) {
        self.inner.on_event(event);
        let plan = &PLAN;
        if plan.uses_mailbox() {
            // What the main loop left; it also wakes the loop when it leaves something.
            self.inner.drain_mailbox(&MAILBOX);
            return;
        }
        // A query is asked when the session can send it and a place is free.
        while self.inner.is_established() {
            let Some(slot) = plan.free_slot() else {
                return;
            };
            plan.take(slot);
            match self.inner.get(&plan.request(), PlanSink { slot }) {
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
