// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2953 (open-debt item 836) — a query that outlives its handler.
//!
//! Upstream's `Query` carries the route it answers on (`QueryInner::primitives`:
//! the face a remote query came in on, or the session itself for a query the
//! session asked of itself), and dropping its last clone sends the
//! `ResponseFinal` along that route (`zenoh/src/api/queryable.rs` @
//! `impl Drop for QueryInner {`). A handler that keeps the query — a zenoh-c
//! `z_query_clone`, a pico `z_query_take_from_loaned`, a channel handler —
//! therefore keeps the GET open until it lets go, whichever side asked.
//!
//! [`HeldQuery`] is that shape for this runtime: taking one HOLDS the query's
//! Final ([`Session::hold_query`]), [`HeldQuery::reply`] answers on the query's
//! own route, and dropping it releases the hold, emitting the Final if the
//! dispatch already owed it. Before R2953 the hold existed only for a wire
//! query and each C ABI carried its own wire-only responder, so a query a
//! session asked of ITSELF could be kept but not waited for: its local Final
//! went out as soon as the handlers returned, and a later reply had no route.

use super::*;

use wz_session_core::query::QueryResponder;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::reply_acceptance::ReplyKeyExpr;
use wz_session_core::reply_stage::ReplyStage;
use wz_session_core::sample::QosLevel;

/// A query kept past its handler: it answers on the route the query came in
/// on, and its `ResponseFinal` is owed until it is dropped. Built by
/// [`Session::hold_query`]; each one is its own hold, so a query held twice
/// stays open until both are dropped.
///
/// The route is the transport's ([`TransportState::reply_route`]): the link for a unicast
/// session, the group for a multicast one, so a query that came over a group is kept and
/// answered the same way (open-debt item 913).
pub struct HeldQuery<
    R: SessionRuntime = TokioRuntime,
    T: TimeSource = TokioTime,
    Tp: TransportState<R, T> = Unicast,
> {
    session: Session<R, T, Tp>,
    key: FinalKey,
    keyexpr: String,
    accept: ReplyKeyExpr,
    qos: QosLevel,
}

// `hold_query` keeps a clone of the session, and a session is `Clone` when its transport's
// payload is (both transports' are), so that one method carries the bound.
impl<R: SessionRuntime, T: TimeSource, Tp: TransportState<R, T>> Session<R, T, Tp>
where
    <Tp as TransportState<R, T>>::Payload: Clone,
{
    /// Keep the query `view` describes past its handler; see [`HeldQuery`].
    ///
    /// MUST be called from inside the queryable handler, which is what makes
    /// the ordering well defined: every handler job of a drain batch runs
    /// before that batch's terminator jobs (the wire dispatch's staged Final,
    /// and a local GET's), so a hold taken there is always visible to the job
    /// it must suppress. Taken afterwards, it is a lost race — the Final has
    /// already gone and the requester has closed.
    pub fn hold_query(&self, view: &dyn QueryView) -> HeldQuery<R, T, Tp> {
        let key = FinalKey {
            rid: view.rid(),
            local: view.is_local(),
        };
        if let Ok(mut map) = self.final_holds.lock() {
            map.entry(key).or_default().holds += 1;
        }
        HeldQuery {
            session: self.clone(),
            key,
            keyexpr: view.keyexpr().to_owned(),
            // The same derivation the in-dispatch responder makes, from the
            // same parameters, so a held reply is admitted exactly as an
            // immediate one would be.
            accept: view
                .parameters()
                .and_then(|bytes| core::str::from_utf8(bytes).ok())
                .map_or(ReplyKeyExpr::MatchingQuery, ReplyKeyExpr::from_parameters),
            qos: view.qos(),
        }
    }
}

impl<R: SessionRuntime, T: TimeSource, Tp: TransportState<R, T>> Session<R, T, Tp> {
    /// Route replies a held query produced: onto the wire for a query that
    /// came in on it, into this session's own pending GET for a query it asked
    /// of itself. A local reply lands as the in-dispatch local leg's does, and
    /// its fires are drained under this session's [`LocalDeliveryDrain`].
    fn deliver_held_replies(&self, key: FinalKey, replies: ReplyStage) {
        if key.local {
            R::with_mutex_mut(&self.observer, |observer| {
                for reply in replies {
                    let inbound: crate::reply::InboundReply = reply.into();
                    observer.replies.deliver_local_reply(&inbound);
                }
            });
            self.drain_or_wake_local();
        } else {
            let route = Tp::reply_route(&self.transport);
            for reply in replies {
                route.send_reply(reply);
            }
        }
    }

    /// Hold the Final of a LOCAL query for as long as one of its deferred
    /// handler jobs has not yet delivered its replies; see [`HandlerJobHold`].
    ///
    /// Taken by the queryable's staging sink, which runs inside the loopback
    /// window of the query that matched it, so the hold exists before the
    /// query's own terminator can be consulted.
    pub(super) fn hold_for_handler_job(&self, rid: u64) -> HandlerJobHold<R, T, Tp> {
        let key = FinalKey { rid, local: true };
        if let Ok(mut map) = self.final_holds.lock() {
            map.entry(key).or_default().holds += 1;
        }
        HandlerJobHold {
            session: self.downgrade(),
            key,
            settled: false,
        }
    }

    /// Release one hold, and emit the query's `ResponseFinal` if this was the
    /// last one and the dispatch already owed it.
    ///
    /// Callable from ANY thread: the map is never held across the emit. If the
    /// Final was not yet DUE (the release beat the terminator job), the entry
    /// is simply gone and that job finds no hold and emits normally — both
    /// orders end with exactly one Final.
    fn release_query_final(&self, key: FinalKey) {
        self.release_query_final_in(key, true);
    }

    /// [`Self::release_query_final`] for a release made at the end of a deferred job, which
    /// STAGES the Final and leaves it to the drain loop that is running the job.
    ///
    /// A job runs inside [`DeferredFireQueue::drain`], whose loop takes what the job staged once
    /// the job has returned, in order. Draining here as well would run the requester's fires, its
    /// reply callbacks among them, inside the call of the handler's cell: a callback that asks a
    /// get of the same queryable and waits for it then finds the cell mid-call, and its call is
    /// parked behind the one that is waiting. The release that follows a job a second thread
    /// took (the thread that asked finalised and handed the Final to the hold) is the one that
    /// ran there.
    ///
    /// [`DeferredFireQueue::drain`]: wz_session_core::deferred_fire::DeferredFireQueue::drain
    fn release_query_final_staged(&self, key: FinalKey) {
        self.release_query_final_in(key, false);
    }

    /// The release itself; `drain` says whether the fires it stages are run before it returns
    /// (under a [`LocalDeliveryDrain::Caller`] session) or are left to the loop that is running.
    fn release_query_final_in(&self, key: FinalKey, drain: bool) {
        let due = match self.final_holds.lock() {
            Ok(mut map) => {
                let Some(hold) = map.get_mut(&key) else {
                    return;
                };
                hold.holds = hold.holds.saturating_sub(1);
                if hold.holds > 0 {
                    return;
                }
                let due = hold.due.then_some(hold.qos);
                map.remove(&key);
                due
            }
            Err(_) => return,
        };
        let Some(qos) = due else {
            return;
        };
        if key.local {
            // The local GET's Final, owed since its handlers returned. Staged
            // like every other local fire, so it runs after the replies this
            // holder already delivered.
            let observer = self.observer.clone();
            self.fires.stage(Box::new(move || {
                R::with_mutex_mut(&observer, |observer| {
                    observer.replies.deliver_local_final(key.rid);
                });
            }));
            if drain {
                self.drain_or_wake_local();
            } else if let (LocalDeliveryDrain::DriveTask, Some(wake)) =
                (self.local_delivery, &self.local_stage_wake)
            {
                // The drive task is not the loop that is running: it is owed its wake.
                wake.notify_one();
            }
        } else {
            Tp::reply_route(&self.transport).send_final(key.rid, qos);
        }
    }

    /// Run what a held local query staged, under this session's
    /// [`LocalDeliveryDrain`]: here for `Caller`, on the drive task (woken)
    /// for `DriveTask`.
    fn drain_or_wake_local(&self) {
        match self.local_delivery {
            LocalDeliveryDrain::Caller => {
                self.drain_deferred_fires();
            }
            LocalDeliveryDrain::DriveTask => {
                if let Some(wake) = &self.local_stage_wake {
                    wake.notify_one();
                }
            }
        }
    }
}

impl<R: SessionRuntime, T: TimeSource, Tp: TransportState<R, T>> HeldQuery<R, T, Tp> {
    /// The request id the query carries.
    pub fn rid(&self) -> u64 {
        self.key.rid
    }

    /// Whether this session asked the query of itself.
    pub fn is_local(&self) -> bool {
        self.key.local
    }

    /// The key expression the query was asked under.
    pub fn keyexpr(&self) -> &str {
        &self.keyexpr
    }

    /// The query's own QoS, which a reply inherits.
    pub fn qos(&self) -> QosLevel {
        self.qos
    }

    /// Answer the query now: `answer` writes replies into a responder built as
    /// the in-dispatch one is (the query's keyexpr, acceptance policy and QoS),
    /// and they go out on the query's own route.
    pub fn reply(&self, answer: impl FnOnce(&mut dyn ReplyOut)) {
        let mut replies = ReplyStage::new();
        {
            let mut responder = QueryResponder::new(
                self.key.rid,
                self.keyexpr.clone(),
                self.accept,
                self.qos,
                &mut replies,
            );
            answer(&mut responder);
        }
        self.session.deliver_held_replies(self.key, replies);
    }
}

impl<R: SessionRuntime, T: TimeSource, Tp: TransportState<R, T>> Drop for HeldQuery<R, T, Tp> {
    fn drop(&mut self) {
        self.session.release_query_final(self.key);
    }
}

/// A [`HeldQuery`] that does not name its transport, as [`TokioQueryHolder::hold_query`]
/// makes it: the one type a C ABI keeps in an escaped query.
#[non_exhaustive]
pub enum TokioHeldQuery {
    /// Held on a unicast session.
    Unicast(HeldQuery),
    /// Held on a group.
    #[cfg(feature = "transport-multicast")]
    Group(HeldQuery<TokioRuntime, TokioTime, Multicast>),
}

impl TokioHeldQuery {
    /// The request id the query carries.
    pub fn rid(&self) -> u64 {
        match self {
            Self::Unicast(held) => held.rid(),
            #[cfg(feature = "transport-multicast")]
            Self::Group(held) => held.rid(),
        }
    }

    /// Whether the session asked the query of itself.
    pub fn is_local(&self) -> bool {
        match self {
            Self::Unicast(held) => held.is_local(),
            #[cfg(feature = "transport-multicast")]
            Self::Group(held) => held.is_local(),
        }
    }

    /// The key expression the query was asked under.
    pub fn keyexpr(&self) -> &str {
        match self {
            Self::Unicast(held) => held.keyexpr(),
            #[cfg(feature = "transport-multicast")]
            Self::Group(held) => held.keyexpr(),
        }
    }

    /// The query's own QoS, which a reply inherits.
    pub fn qos(&self) -> QosLevel {
        match self {
            Self::Unicast(held) => held.qos(),
            #[cfg(feature = "transport-multicast")]
            Self::Group(held) => held.qos(),
        }
    }

    /// Answer the query now, on its own route; see [`HeldQuery::reply`].
    pub fn reply(&self, answer: impl FnOnce(&mut dyn ReplyOut)) {
        match self {
            Self::Unicast(held) => held.reply(answer),
            #[cfg(feature = "transport-multicast")]
            Self::Group(held) => held.reply(answer),
        }
    }
}

/// The hold a local query's deferred handler job keeps on the query's own
/// `ResponseFinal`, released when the job has delivered its replies.
///
/// A local GET's Final may not leave before the replies of the handlers it
/// matched, and "after my own drain" does not say that: the local plane has
/// more than one drainer (the thread that asked, and the drive task, which
/// also empties it), so a job taken by one of them is still running while the
/// other finds the queue empty and finalises. Measured on the zenoh-c ABI, a
/// handler that sent four replies was heard in full by 59 asks and by none of
/// the next 2941; libzenohc answers all 3000, because its handler runs on the
/// asking thread and its replies precede its final by construction.
///
/// The job holds the Final instead, which is the shape [`HeldQuery`] already
/// gave a handler that keeps its query: the terminator then finds a hold and
/// leaves the Final to the last releaser, whichever thread that is, and a
/// release that beats the terminator leaves nothing for it to defer to. Both
/// orders end with exactly one Final, after the replies.
///
/// The guard is moved INTO the job's closure, so it is released wherever that
/// closure ends: after the handler's replies are delivered, or unrun when the
/// listener was undeclared first, or while unwinding from a panicking handler.
pub(super) struct HandlerJobHold<
    R: SessionRuntime = TokioRuntime,
    T: TimeSource = TokioTime,
    Tp: TransportState<R, T> = Unicast,
> {
    session: WeakSession<R, T, Tp>,
    key: FinalKey,
    /// Whether the hold has been released already, by [`Self::release_within_job`].
    settled: bool,
}

impl<R: SessionRuntime, T: TimeSource, Tp: TransportState<R, T>> HandlerJobHold<R, T, Tp> {
    /// Release the hold at the end of the job that took it: the Final it owes is STAGED, and the
    /// loop that is running the job takes it once the job has returned (see
    /// [`Session::release_query_final_staged`]). Dropped any other way, the hold releases and
    /// runs what it staged, as a held query that is let go of does.
    pub(super) fn release_within_job(mut self) {
        self.settled = true;
        if let Some(session) = self.session.upgrade() {
            session.release_query_final_staged(self.key);
        }
    }
}

impl<R: SessionRuntime, T: TimeSource, Tp: TransportState<R, T>> Drop for HandlerJobHold<R, T, Tp> {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        // A session already gone has no GET left to terminate.
        if let Some(session) = self.session.upgrade() {
            session.release_query_final(self.key);
        }
    }
}
