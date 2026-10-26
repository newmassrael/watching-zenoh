// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The answering end of a query on the cooperative engine.
//!
//! ## Every query is held
//!
//! A C callback never runs under the session's lock (decision D8), and the observer calls a
//! queryable from inside its dispatch, which runs under it. So the queryable the engine registers
//! with the observer only copies the query out ([`OwnedQuery`]) and HOLDS its `ResponseFinal`
//! ([`FinalHolds`]); the C callback runs when the deliveries are handed out, writes its replies
//! into a responder built as the dispatch's would have been, and the replies go out on the query's
//! link before the hold is let go. The dispatch's own Final for that request id waits for the last
//! hold, so it never overtakes a reply. That is the order zenoh-pico keeps by answering in its read
//! task before the Final (`vendor/zenoh-pico/src/session/queryable.c` @
//! `_z_trigger_queryables_impl`), and zenoh keeps by sending the Final when the last `Query` is
//! dropped (`zenoh/src/api/queryable.rs` @ `impl Drop for QueryInner {`).
//!
//! A query the callback keeps ([`CoopHolder::hold_query`]) is one hold more, released when the C
//! program drops it; until then it answers on its own link.
//!
//! ## A query belongs to its link
//!
//! Each link the session dials has a GENERATION. A query is held and answered under the
//! generation of the link it came in on, and a reply or a Final goes out only while that link is
//! the session's: a router that asked on a link since lost will never read the answer, and a new
//! router never asked.

use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
#[cfg(feature = "local-queryable")]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;
use portable_atomic::AtomicU64;

#[allow(unused_imports)]
use crate::prelude::*;

use wz_capi_port::os::{self, Mutex, ThreadId};
use wz_capi_port::sync::Lock;
use wz_capi_port::{HeldQuery, QblId, QueryHolder};
use wz_runtime_coop::session_drive::SessionLinks;
use wz_runtime_coop::ClockSource;
use wz_session_core::query::QueryResponder;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::reply_acceptance::ReplyKeyExpr;
use wz_session_core::reply_stage::ReplyStage;
use wz_session_core::sample::{EncodingHint, QosLevel, SourceInfo};

use super::{lock, CoopEngine};

/// A query copied out of the dispatch that delivered it, for a callback that runs after.
pub(super) struct OwnedQuery {
    keyexpr: String,
    parameters: Option<Vec<u8>>,
    payload: Option<Vec<u8>>,
    attachment: Option<Vec<u8>>,
    encoding: Option<EncodingHint>,
    source_info: Option<SourceInfo>,
    rid: u64,
    qos: QosLevel,
}

impl OwnedQuery {
    pub(super) fn of(view: &dyn QueryView) -> Self {
        Self {
            keyexpr: view.keyexpr().to_owned(),
            parameters: view.parameters().map(<[u8]>::to_vec),
            payload: view.payload().map(<[u8]>::to_vec),
            attachment: view.attachment().map(<[u8]>::to_vec),
            encoding: view.encoding().cloned(),
            source_info: view.source_info().cloned(),
            rid: view.rid(),
            qos: view.qos(),
        }
    }

    pub(super) fn rid(&self) -> u64 {
        self.rid
    }

    /// A responder for this query's replies, staging them in `replies`.
    pub(super) fn responder<'a>(&self, replies: &'a mut ReplyStage) -> QueryResponder<'a> {
        responder_for(
            self.rid,
            &self.keyexpr,
            self.parameters.as_deref(),
            self.qos,
            replies,
        )
    }
}

impl QueryView for OwnedQuery {
    fn keyexpr(&self) -> &str {
        &self.keyexpr
    }
    fn parameters(&self) -> Option<&[u8]> {
        self.parameters.as_deref()
    }
    fn attachment(&self) -> Option<&[u8]> {
        self.attachment.as_deref()
    }
    fn source_info(&self) -> Option<&SourceInfo> {
        self.source_info.as_ref()
    }
    fn payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }
    fn encoding(&self) -> Option<&EncodingHint> {
        self.encoding.as_ref()
    }
    fn rid(&self) -> u64 {
        self.rid
    }
    fn qos(&self) -> QosLevel {
        self.qos
    }
}

/// The responder the dispatch would have built for a query: its key, the replies its parameters
/// accept (`_anyke` admits any key), its QoS.
fn responder_for<'a>(
    rid: u64,
    keyexpr: &str,
    parameters: Option<&[u8]>,
    qos: QosLevel,
    replies: &'a mut ReplyStage,
) -> QueryResponder<'a> {
    let accept = parameters
        .and_then(|bytes| core::str::from_utf8(bytes).ok())
        .map_or(ReplyKeyExpr::MatchingQuery, ReplyKeyExpr::from_parameters);
    QueryResponder::new(rid, keyexpr.to_owned(), accept, qos, replies)
}

/// One request's Final, held while a callback or a kept query may still answer it.
struct FinalHold {
    generation: u64,
    rid: u64,
    holds: usize,
    /// The QoS of the Final the dispatch owes, once it owes one.
    due: Option<QosLevel>,
}

/// The Finals held open, by the link generation and request id they answer.
#[derive(Default)]
pub(super) struct FinalHolds(Vec<FinalHold>);

impl FinalHolds {
    /// One hold more on the Final of `rid` on link `generation`.
    pub(super) fn take(&mut self, generation: u64, rid: u64) {
        match self
            .0
            .iter_mut()
            .find(|h| h.generation == generation && h.rid == rid)
        {
            Some(hold) => hold.holds += 1,
            None => self.0.push(FinalHold {
                generation,
                rid,
                holds: 1,
                due: None,
            }),
        }
    }

    /// The dispatch owes the Final of `rid`: `true` when nothing holds it, so it goes out now,
    /// `false` when it waits for the last hold.
    pub(super) fn owe(&mut self, generation: u64, rid: u64, qos: QosLevel) -> bool {
        match self
            .0
            .iter_mut()
            .find(|h| h.generation == generation && h.rid == rid)
        {
            Some(hold) => {
                hold.due = Some(qos);
                false
            }
            None => true,
        }
    }

    /// Let go of one hold: the Final's QoS when it was owed and this was the last hold.
    pub(super) fn release(&mut self, generation: u64, rid: u64) -> Option<QosLevel> {
        let at = self
            .0
            .iter()
            .position(|h| h.generation == generation && h.rid == rid)?;
        let hold = &mut self.0[at];
        hold.holds = hold.holds.saturating_sub(1);
        if hold.holds > 0 {
            return None;
        }
        self.0.swap_remove(at).due
    }
}

/// The generation a query asked by the session's OWN get is held and answered under: no link ever
/// has it, since the first link's is `1`, so a reply or a Final under it goes to the get's pending
/// entry and never to a link (`local-queryable`).
#[cfg(feature = "local-queryable")]
pub(super) const LOCAL_QUERY: u64 = 0;

/// What the queryable plane shares between the session's state, its dispatch, the observer's
/// queryables and the queries a C program keeps.
#[derive(Default)]
pub(super) struct QueryPlane {
    /// The generation of the link the session dialled last, which every query arrives on.
    pub(super) generation: AtomicU64,
    /// Set while the session hands its own get to its queryables, under the session's lock: the
    /// queries that arrive meanwhile are the get's, not the link's (`local-queryable`).
    #[cfg(feature = "local-queryable")]
    asking: AtomicBool,
    pub(super) holds: Mutex<FinalHolds>,
    /// The queries waiting for their callbacks, in the order they arrived: the queryable they
    /// matched, the query, and the generation of its link.
    pub(super) queries: Mutex<VecDeque<(QblId, OwnedQuery, u64)>>,
}

impl QueryPlane {
    /// What the observer's queryable `id` does with a query: copy it out and hold its Final.
    pub(super) fn arrive(&self, id: QblId, view: &dyn QueryView) {
        let generation = self.arriving_on();
        lock(&self.holds).take(generation, view.rid());
        lock(&self.queries).push_back((id, OwnedQuery::of(view), generation));
    }

    /// The generation a query arriving now belongs to.
    fn arriving_on(&self) -> u64 {
        #[cfg(feature = "local-queryable")]
        if self.asking.load(Ordering::Acquire) {
            return LOCAL_QUERY;
        }
        self.generation.load(Ordering::Acquire)
    }

    /// Run `ask`, the session handing its own get to its queryables, with what arrives meanwhile
    /// taken as the get's.
    #[cfg(feature = "local-queryable")]
    pub(super) fn asking_locally<R>(&self, ask: impl FnOnce() -> R) -> R {
        self.asking.store(true, Ordering::Release);
        let result = ask();
        self.asking.store(false, Ordering::Release);
        result
    }
}

/// The query each thread's callback is answering now: the thread, its engine (by address), the
/// generation of its link and its request id, the innermost of a thread last. One set for the
/// process, as the thread-local slot it replaces was one per thread across every engine: a
/// callback that steps another session and answers that session's query from inside its own
/// answers the inner one until it returns, and a hold is taken only on the innermost. Kept here
/// rather than in a thread-local because an MCU kernel gives a Rust image none.
static ANSWERING: Lock<Vec<(ThreadId, usize, u64, u64)>> = Lock::new(Vec::new());

/// This thread answers a query, from [`Self::enter`] to drop.
pub(super) struct Answering {
    thread: ThreadId,
}

impl Answering {
    pub(super) fn enter(engine: usize, generation: u64, rid: u64) -> Self {
        let thread = os::current();
        ANSWERING.with(|a| a.push((thread, engine, generation, rid)));
        Self { thread }
    }

    /// The query this thread answers innermost: its engine, generation and request id.
    fn innermost() -> Option<(usize, u64, u64)> {
        let thread = os::current();
        ANSWERING.with(|a| {
            a.iter()
                .rev()
                .find(|(t, ..)| *t == thread)
                .map(|&(_, engine, generation, rid)| (engine, generation, rid))
        })
    }
}

impl Drop for Answering {
    fn drop(&mut self) {
        let thread = self.thread;
        ANSWERING.with(|a| {
            if let Some(innermost) = a.iter().rposition(|(t, ..)| *t == thread) {
                a.remove(innermost);
            }
        });
    }
}

/// The session as a queryable's callbacks hold queries through ([`QueryHolder`]).
pub(super) struct CoopHolder<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> {
    pub(super) engine: Weak<CoopEngine<L, C>>,
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> QueryHolder for CoopHolder<L, C> {
    fn hold_query(&self, view: &dyn QueryView) -> Box<dyn HeldQuery> {
        let answering = Answering::innermost();
        let held = self.engine.upgrade().and_then(|engine| {
            let (at, generation, rid) = answering?;
            // Only the query this thread is answering, of this engine, can be held: a hold taken
            // anywhere else would come after the Final it was meant to keep.
            if at != Arc::as_ptr(&engine) as usize || rid != view.rid() {
                return None;
            }
            lock(&engine.plane.holds).take(generation, rid);
            Some((generation, rid))
        });
        Box::new(CoopHeld {
            engine: self.engine.clone(),
            held,
            keyexpr: view.keyexpr().to_owned(),
            parameters: view.parameters().map(<[u8]>::to_vec),
            qos: view.qos(),
        })
    }

    fn session_closed(&self) -> bool {
        self.engine
            .upgrade()
            .map_or(true, |engine| super::SessionEngine::is_closed(&*engine))
    }
}

/// A query a C program keeps past its callback ([`HeldQuery`]). `held` is the generation and
/// request id of the hold it took, `None` for one taken outside a callback, which holds nothing
/// and answers nothing.
struct CoopHeld<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> {
    engine: Weak<CoopEngine<L, C>>,
    held: Option<(u64, u64)>,
    keyexpr: String,
    parameters: Option<Vec<u8>>,
    qos: QosLevel,
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> HeldQuery for CoopHeld<L, C> {
    fn reply(&self, answer: &mut dyn FnMut(&mut dyn ReplyOut)) {
        let (Some((generation, rid)), Some(engine)) = (self.held, self.engine.upgrade()) else {
            return;
        };
        let mut replies = ReplyStage::new();
        {
            let mut responder = responder_for(
                rid,
                &self.keyexpr,
                self.parameters.as_deref(),
                self.qos,
                &mut replies,
            );
            answer(&mut responder);
        }
        engine.answer(generation, rid, replies, false);
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> Drop for CoopHeld<L, C> {
    fn drop(&mut self) {
        if let (Some((generation, rid)), Some(engine)) = (self.held, self.engine.upgrade()) {
            engine.answer(generation, rid, ReplyStage::new(), true);
        }
    }
}
