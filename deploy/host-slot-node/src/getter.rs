// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The node as a GETTER: it asks the same query again and again, one at a time, and keeps the
//! round trip of each in a table this file declares.
//!
//! A query is issued the moment the session is established and again the moment the last one
//! ended (its final, or its deadline), so there is never more than one in flight. The time a query
//! takes is read from the clock when it is issued and when its final arrives; both happen inside
//! the session's own event, so the figure is what the application layer of this node sees, from
//! the request being written to the final being delivered to its sink.
//!
//! The sink is a unit type that writes into [`PLAN`]: the pending table keeps a copy of the sink,
//! and the state a reply changes lives in the `static`. Nothing here allocates.

use core::cell::Cell;

use wz_runtime_coop::ClockSource;
use wz_session_core::reply_sink::{ReplyKind, ReplySink, ReplyView};
use wz_session_core::sample::QosLevel;
use wz_session_core::slot_observer::{ObserverSinks, Requesters};
use wz_session_mcu::app_layer::{GetError, GetRequest, NoReplies, SessionEvents, SlotDispatch};

use crate::Clock;

/// The round trips the node keeps: more queries than this are asked but not timed.
pub const SAMPLES: usize = 4096;

/// What the node was asked to do and what has happened, in one `static`.
pub struct Plan {
    key: Cell<&'static str>,
    count: Cell<u32>,
    timeout_ms: Cell<u32>,
    warmup: Cell<u32>,
    issued: Cell<u32>,
    finished: Cell<u32>,
    replies: Cell<u32>,
    errors: Cell<u32>,
    refused: Cell<u32>,
    payload_bytes: Cell<u64>,
    timeouts: Cell<u32>,
    started_us: Cell<u64>,
    in_flight: Cell<bool>,
    last_refusal: Cell<Option<GetError>>,
    rtt_us: [Cell<u32>; SAMPLES],
}

// SAFETY: the profile's rule: one thread runs the program, and the sink and the events that write
// the plan run inside its one loop.
unsafe impl Sync for Plan {}

pub static PLAN: Plan = Plan {
    key: Cell::new(""),
    count: Cell::new(0),
    timeout_ms: Cell::new(0),
    warmup: Cell::new(0),
    issued: Cell::new(0),
    finished: Cell::new(0),
    replies: Cell::new(0),
    errors: Cell::new(0),
    refused: Cell::new(0),
    payload_bytes: Cell::new(0),
    timeouts: Cell::new(0),
    started_us: Cell::new(0),
    in_flight: Cell::new(false),
    last_refusal: Cell::new(None),
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
}

impl Plan {
    /// Ask for `count` queries of `key`, each pending at most `timeout_ms` (zero is the default).
    /// The first `warmup` of them are asked and answered but not timed: they are the ones that
    /// pay for the first touch of every page and the router's first route.
    pub fn set(&self, key: &'static str, count: u32, timeout_ms: u32, warmup: u32) {
        self.key.set(key);
        self.count.set(count);
        self.timeout_ms.set(timeout_ms);
        self.warmup.set(warmup);
    }

    /// Whether the node was asked to get at all.
    pub fn is_set(&self) -> bool {
        self.count.get() != 0
    }

    /// Whether every query asked for has ended.
    pub fn is_done(&self) -> bool {
        self.is_set() && self.finished.get() >= self.count.get()
    }

    /// A reply arrived for the query in flight.
    fn reply(&self, view: &dyn ReplyView) {
        if view.kind() == ReplyKind::Err {
            self.errors.set(self.errors.get() + 1);
        } else {
            self.replies.set(self.replies.get() + 1);
            self.payload_bytes
                .set(self.payload_bytes.get() + view.payload().len() as u64);
        }
    }

    /// The query in flight ended.
    fn end(&self, timed_out: bool) {
        let now_us = Clock::default().now_us();
        if let Some(timed_at) = self.finished.get().checked_sub(self.warmup.get()) {
            if let Some(cell) = self.rtt_us.get(timed_at as usize) {
                let elapsed = now_us.saturating_sub(self.started_us.get());
                cell.set(u32::try_from(elapsed).unwrap_or(u32::MAX));
            }
        }
        if timed_out {
            self.timeouts.set(self.timeouts.get() + 1);
        }
        self.finished.set(self.finished.get() + 1);
        self.in_flight.set(false);
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
            refused: self.refused.get(),
            payload_bytes: self.payload_bytes.get(),
            timed,
            min_us: at(0),
            median_us: at(500),
            p99_us: at(990),
            max_us: samples.last().copied().unwrap_or(0),
        }
    }
}

/// The sink of every query this node asks: a unit, because the state is [`PLAN`]'s.
#[derive(Clone, Copy, Default)]
pub struct PlanSink;

impl ReplySink for PlanSink {
    fn on_reply(&mut self, reply: &dyn ReplyView) {
        PLAN.reply(reply);
    }

    fn on_final(&mut self, _rid: u64) {
        PLAN.end(false);
    }

    /// An expired query ends with a timeout, which is counted and not delivered as a reply: the
    /// default would hand the sink a synthetic error first.
    fn on_timeout(&mut self, _rid: u64) {
        PLAN.end(true);
    }
}

/// The requests a session of this node holds: the pending queries, and no liveliness get.
pub type Requests = Requesters<PlanSink, NoReplies>;

/// The application layer of a getter session: the node's dispatch, and the next query asked as
/// soon as the last one ended.
pub struct GetterEvents<K: ObserverSinks + 'static> {
    inner: SlotDispatch<Clock, PlanSink, NoReplies, K>,
}

impl<K: ObserverSinks + 'static> GetterEvents<K> {
    pub fn new(inner: SlotDispatch<Clock, PlanSink, NoReplies, K>) -> Self {
        Self { inner }
    }
}

impl<K: ObserverSinks + 'static> SessionEvents for GetterEvents<K> {
    fn on_event(&mut self, event: wz_session_core::driver_loop::IterationEvent<'_>) {
        self.inner.on_event(event);
        // A query is asked when the session can send it and the last one is over.
        let plan = &PLAN;
        if plan.in_flight.get()
            || plan.issued.get() >= plan.count.get()
            || !self.inner.is_established()
        {
            return;
        }
        let request = GetRequest {
            keyexpr: plan.key.get(),
            parameters: b"",
            // The peer's default, as `z_get` with its default options and pico's example ask: no
            // consolidation flag on the wire.
            consolidation: None,
            target: None,
            timeout_ms: plan.timeout_ms.get(),
            qos: QosLevel::DEFAULT,
        };
        plan.started_us.set(Clock::default().now_us());
        plan.in_flight.set(true);
        match self.inner.get(&request, PlanSink) {
            Ok(_) => plan.issued.set(plan.issued.get() + 1),
            Err(why) => {
                // Refused: nothing is pending and nothing was sent. It is counted and the next
                // event asks again, so a session that has just lost its transport does not end
                // the run with a query that was never asked. The last reason is kept, because a
                // count alone cannot tell a full table from a refused write.
                plan.in_flight.set(false);
                plan.refused.set(plan.refused.get() + 1);
                plan.last_refusal.set(Some(why));
            }
        }
    }
}
