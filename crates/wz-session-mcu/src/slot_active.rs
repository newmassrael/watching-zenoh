// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The application layer of a session of a node that DOES something on its own: what a node that only
//! answers does ([`SlotDispatch`]), and then the puts and the queries that are due.
//!
//! The layer is one, and the behaviours are data: a node's publishers
//! ([`Publication`]) and queriers ([`Query`]) are arrays the image states, and this layer gives each its
//! own [`Schedule`] and sends what is due. After it has dispatched what the iteration brought it asks
//! each schedule, sends each due put (`send_push_literal`) and asks each due query, and tells the
//! drive loop the earliest moment it needs to be awake next
//! ([`set_app_wake_deadline_ms`](wz_session_core::session_actions::SessionLinkActions::set_app_wake_deadline_ms)),
//! which the loop budgets its wait by with the transport's own: the earliest of the next put, the
//! next query and the deadline of a query still pending. Nothing runs on the program's main loop and
//! nothing is left in a mailbox, so the cadence is the session's.
//!
//! A query is asked with the sink of its reply ([`ReplyLatest`]), so
//! the layer is built with `query-get` for a node that has queriers and without it for one that has
//! none; a node built without it holds no querier (`Q` is 0).
//!
//! The schedules are per session and live in the session's task cell, which the image sizes for them
//! and for the pending table; a session that is lost starts over with the next one.
//!
//! This module does not link `alloc`.

use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::ClockSource;
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::send_wire_error::SendWireError;
use wz_session_core::slot_observer::{ObserverCell, Requesters};

use crate::app_layer::{NoReplies, SessionEvents, SlotDispatch};
use crate::slot_client::DocumentSinks;
use crate::slot_node::SessionLayer;
use crate::slot_publisher::{Publication, PublishCounts};
use crate::slot_schedule::{Outcome, Schedule};

#[cfg(feature = "query-get")]
use crate::app_layer::{GetError, GetRequest};
#[cfg(feature = "query-get")]
use crate::slot_querier::{Query, QueryState, ReplyLatest};
#[cfg(feature = "query-get")]
use wz_session_core::registry_error::RegisterError;

/// What the replies of a session's own queries are delivered to.
#[cfg(feature = "query-get")]
type Replies = ReplyLatest;
/// A node built without `query-get` asks nothing.
#[cfg(not(feature = "query-get"))]
type Replies = NoReplies;

/// The application layer of one session of a node with `P` publishers and `Q` queriers.
pub struct ActiveEvents<C: ClockSource + 'static, const P: usize, const Q: usize> {
    inner: SlotDispatch<C, Replies, NoReplies, DocumentSinks>,
    handle: SessionHandle<C>,
    publications: [Publication; P],
    counts: &'static PublishCounts<P>,
    puts: Schedule<P>,
    #[cfg(feature = "query-get")]
    queries: [Query; Q],
    #[cfg(feature = "query-get")]
    state: &'static QueryState<Q>,
    #[cfg(feature = "query-get")]
    asks: Schedule<Q>,
}

impl<C: ClockSource + 'static, const P: usize, const Q: usize> SessionEvents
    for ActiveEvents<C, P, Q>
{
    fn on_event(&mut self, event: IterationEvent<'_>) {
        self.inner.on_event(event);
        if P == 0 && Q == 0 {
            return;
        }
        if !self.handle.is_established() {
            self.puts.disarm();
            #[cfg(feature = "query-get")]
            self.asks.disarm();
            self.handle.set_app_wake_deadline_ms(None);
            return;
        }
        let now_ms = wz_runtime_core::TimeSource::now_monotonic_ms(&self.handle.clock);
        let (handle, counts) = (&self.handle, self.counts);
        let next_put = self
            .puts
            .poll(now_ms, &self.publications, |at, publication| {
                match handle.send_push_literal(publication.key, publication.body.as_bytes(), true) {
                    Ok(()) => {
                        counts.record_sent(at);
                        Outcome::Sent
                    }
                    Err(SendWireError::TransportUnavailable) => Outcome::Retry,
                    Err(_) => {
                        counts.record_refused(at);
                        Outcome::Refused
                    }
                }
            });
        #[cfg(feature = "query-get")]
        let (next_ask, pending) = {
            let (inner, state) = (&mut self.inner, self.state);
            let next = self.asks.poll(now_ms, &self.queries, |at, query| {
                let request = GetRequest {
                    keyexpr: query.key,
                    parameters: &[],
                    consolidation: None,
                    target: None,
                    timeout_ms: query.timeout_ms,
                    qos: wz_session_core::sample::QosLevel::DEFAULT,
                };
                match inner.get(&request, ReplyLatest::new(state, at)) {
                    Ok(_) => {
                        state.record_asked(at);
                        Outcome::Sent
                    }
                    // No free pending row now, or the session is between transports: both pass.
                    Err(GetError::Register(RegisterError::TableFull))
                    | Err(GetError::Send(SendWireError::TransportUnavailable)) => Outcome::Retry,
                    Err(_) => {
                        state.record_refused(at);
                        Outcome::Refused
                    }
                }
            });
            (next, self.inner.next_get_deadline_ms())
        };
        #[cfg(not(feature = "query-get"))]
        let (next_ask, pending): (Option<u64>, Option<u64>) = (None, None);
        self.handle
            .set_app_wake_deadline_ms([next_put, next_ask, pending].into_iter().flatten().min());
    }
}

/// The layer of a node that publishes `publications` and asks `queries`.
pub struct Active<const P: usize, const Q: usize> {
    /// What it puts, and how often.
    pub publications: [Publication; P],
    /// Where the puts are counted.
    pub counts: &'static PublishCounts<P>,
    /// What it asks, and how often.
    #[cfg(feature = "query-get")]
    pub queries: [Query; Q],
    /// Where the replies are kept and the queries counted.
    #[cfg(feature = "query-get")]
    pub state: &'static QueryState<Q>,
}

impl<C: ClockSource + 'static, const P: usize, const Q: usize> SessionLayer<C> for Active<P, Q> {
    type Events = ActiveEvents<C, P, Q>;

    fn events(
        &mut self,
        observer: &'static ObserverCell<DocumentSinks>,
        handle: &SessionHandle<C>,
    ) -> Self::Events {
        ActiveEvents {
            inner: SlotDispatch::new(
                observer,
                handle.clone(),
                Requesters::<Replies, NoReplies>::new(),
            ),
            handle: handle.clone(),
            publications: self.publications,
            counts: self.counts,
            puts: Schedule::new(),
            #[cfg(feature = "query-get")]
            queries: self.queries,
            #[cfg(feature = "query-get")]
            state: self.state,
            #[cfg(feature = "query-get")]
            asks: Schedule::new(),
        }
    }
}
