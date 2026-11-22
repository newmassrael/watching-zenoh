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
//! `z_result_t _z_trigger_queryables(`), and zenoh keeps by sending the Final when the last `Query` is
//! dropped (`zenoh/src/api/queryable.rs` @ `impl Drop for QueryInner {`).
//!
//! A query the callback keeps ([`CoopHolder::hold_query`]) is one hold more, released when the C
//! program drops it; until then it answers on its own link.
//!
//! The session's own get is the exception to the copy (`local-queryable`): the queryables it
//! matched are noted ([`QueryPlane::take_asked`]) and the get hands each of them its own view
//! ([`OwnGet`]) once the session's lock is let go, inside the call. Only a queryable whose callback
//! the asking thread is inside of has the query copied, to be handed when that callback returns.
//!
//! The holds are rows of a fixed table, as many as the session's `MAX_PENDING_FINALS`. A query that
//! arrives when every row is taken is not handed to a callback: nothing holds its Final, so the
//! dispatch sends it at once, and the query is counted. The asker hears the end of an answer with
//! no reply rather than nothing.
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
use wz_session_core::bounded::{BoundedVec, Static};
use wz_session_core::caps;
use wz_session_core::query::QueryResponder;
#[cfg(feature = "local-queryable")]
use wz_session_core::query_options::QueryOptions;
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
    rid: wz_session_core::wire_id::RequestId,
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
    fn rid(&self) -> wz_session_core::wire_id::RequestId {
        self.rid
    }
    fn qos(&self) -> QosLevel {
        self.qos
    }
}

/// The responder the dispatch would have built for a query: its key, the replies its parameters
/// accept (`_anyke` admits any key), its QoS.
pub(super) fn responder_for<'a>(
    rid: wz_session_core::wire_id::RequestId,
    keyexpr: &str,
    parameters: Option<&[u8]>,
    qos: QosLevel,
    replies: &'a mut ReplyStage,
) -> QueryResponder<'a> {
    let accept = ReplyKeyExpr::from_parameter_bytes(parameters);
    QueryResponder::new(rid, keyexpr.to_owned(), accept, qos, replies)
}

/// One request's Final, held while a callback or a kept query may still answer it.
struct FinalHold {
    generation: u64,
    rid: wz_session_core::wire_id::RequestId,
    holds: usize,
    /// The QoS of the Final the dispatch owes, once it owes one.
    due: Option<QosLevel>,
}

/// The Finals held open, by the link generation and request id they answer: one row for each
/// query a callback is still to answer or a C program keeps, at most `rows` of them, the value of
/// `MAX_PENDING_FINALS` the session's open resolved under the build's. The table is the plane's
/// own and fixed in size, as the plane is shared with what answers outside the session's lock.
pub(super) struct FinalHolds {
    holds: BoundedVec<FinalHold, { caps::MAX_PENDING_FINALS }, Static>,
    rows: usize,
}

impl FinalHolds {
    /// No Final held, and room for the Finals of `rows` queries.
    pub(super) fn holding(rows: usize) -> Self {
        Self {
            holds: BoundedVec::new_static(),
            rows,
        }
    }

    /// One hold more on the Final of `rid` on link `generation`: `false`, holding nothing, when no
    /// hold of that query is open and every row is taken.
    pub(super) fn take(
        &mut self,
        generation: u64,
        rid: wz_session_core::wire_id::RequestId,
    ) -> bool {
        if let Some(hold) = self
            .holds
            .iter_mut()
            .find(|h| h.generation == generation && h.rid == rid)
        {
            hold.holds += 1;
            return true;
        }
        self.holds.len() < self.rows
            && self
                .holds
                .push(FinalHold {
                    generation,
                    rid,
                    holds: 1,
                    due: None,
                })
                .is_ok()
    }

    /// The dispatch owes the Final of `rid`: `true` when nothing holds it, so it goes out now,
    /// `false` when it waits for the last hold.
    pub(super) fn owe(
        &mut self,
        generation: u64,
        rid: wz_session_core::wire_id::RequestId,
        qos: QosLevel,
    ) -> bool {
        match self
            .holds
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
    pub(super) fn release(
        &mut self,
        generation: u64,
        rid: wz_session_core::wire_id::RequestId,
    ) -> Option<QosLevel> {
        let at = self
            .holds
            .iter()
            .position(|h| h.generation == generation && h.rid == rid)?;
        let hold = &mut self.holds[at];
        hold.holds = hold.holds.saturating_sub(1);
        if hold.holds > 0 {
            return None;
        }
        self.holds.remove(at).due
    }
}

/// The generation a query asked by the session's OWN get is held and answered under: no link ever
/// has it, since the first link's is `1`, so a reply or a Final under it goes to the get's pending
/// entry and never to a link (`local-queryable`).
#[cfg(feature = "local-queryable")]
pub(super) const LOCAL_QUERY: u64 = 0;

/// The row of the plane's held Finals a get of the session's own takes before any of its legs is
/// issued, so the session's queryables are asked all or none: a session with no row free refuses
/// the get before anything is sent. Let go of at drop unless [`Self::release`] lets go of it.
#[cfg(feature = "local-queryable")]
pub(super) struct OwnFinalHold<'a> {
    holds: Option<&'a Mutex<FinalHolds>>,
    rid: wz_session_core::wire_id::RequestId,
}

#[cfg(feature = "local-queryable")]
impl<'a> OwnFinalHold<'a> {
    /// The row for the get of the session's own whose request id is `rid`: `None` when every row
    /// of `holds` is taken.
    pub(super) fn take(
        holds: &'a Mutex<FinalHolds>,
        rid: wz_session_core::wire_id::RequestId,
    ) -> Option<Self> {
        lock(holds).take(LOCAL_QUERY, rid).then_some(Self {
            holds: Some(holds),
            rid,
        })
    }

    pub(super) fn rid(&self) -> wz_session_core::wire_id::RequestId {
        self.rid
    }

    /// Let go of the row's hold: the Final's QoS when it was owed and no queryable asked holds it.
    pub(super) fn release(mut self) -> Option<QosLevel> {
        let holds = self.holds.take()?;
        lock(holds).release(LOCAL_QUERY, self.rid)
    }
}

#[cfg(feature = "local-queryable")]
impl Drop for OwnFinalHold<'_> {
    fn drop(&mut self) {
        if let Some(holds) = self.holds.take() {
            // Owed nothing yet: the get it was taken for issued no leg to the session.
            lock(holds).release(LOCAL_QUERY, self.rid);
        }
    }
}

/// The session's own get as each of its queryables is shown it: the get's own key and options,
/// read where they lie. What it shows is what the loopback body the wire builder makes of the same
/// options carries (`QueryOptions::loopback_query`): the parameters and the attachment when not
/// empty, and the value when its payload is not empty or its encoding is not the default one.
#[cfg(feature = "local-queryable")]
pub(super) struct OwnGet<'a> {
    keyexpr: &'a str,
    opts: &'a QueryOptions,
    /// The value's encoding when the get carries a value and states no encoding of its own.
    default_encoding: Option<EncodingHint>,
    carries_value: bool,
    rid: wz_session_core::wire_id::RequestId,
    qos: QosLevel,
}

#[cfg(feature = "local-queryable")]
impl<'a> OwnGet<'a> {
    pub(super) fn of(
        keyexpr: &'a str,
        opts: &'a QueryOptions,
        rid: wz_session_core::wire_id::RequestId,
    ) -> Self {
        let payload = opts.payload.as_deref().unwrap_or_default();
        let stated = opts
            .encoding
            .as_ref()
            .is_some_and(|encoding| encoding.packed_id >> 1 != 0 || encoding.schema.is_some());
        let carries_value = !payload.is_empty() || stated;
        Self {
            keyexpr,
            opts,
            default_encoding: (carries_value && opts.encoding.is_none())
                .then(EncodingHint::default),
            carries_value,
            rid,
            qos: opts.qos.unwrap_or(QosLevel::DEFAULT),
        }
    }
}

#[cfg(feature = "local-queryable")]
impl QueryView for OwnGet<'_> {
    fn keyexpr(&self) -> &str {
        self.keyexpr
    }
    fn parameters(&self) -> Option<&[u8]> {
        self.opts
            .parameters
            .as_deref()
            .filter(|parameters| !parameters.is_empty())
    }
    fn attachment(&self) -> Option<&[u8]> {
        self.opts
            .attachment
            .as_deref()
            .filter(|attachment| !attachment.is_empty())
    }
    fn source_info(&self) -> Option<&SourceInfo> {
        self.opts.source_info.as_ref()
    }
    fn payload(&self) -> Option<&[u8]> {
        self.carries_value
            .then(|| self.opts.payload.as_deref().unwrap_or_default())
    }
    fn encoding(&self) -> Option<&EncodingHint> {
        if !self.carries_value {
            return None;
        }
        self.opts
            .encoding
            .as_ref()
            .or(self.default_encoding.as_ref())
    }
    fn rid(&self) -> wz_session_core::wire_id::RequestId {
        self.rid
    }
    fn is_local(&self) -> bool {
        true
    }
    fn qos(&self) -> QosLevel {
        self.qos
    }
}

/// What the queryable plane shares between the session's state, its dispatch, the observer's
/// queryables and the queries a C program keeps.
pub(super) struct QueryPlane {
    /// The generation of the link dialled last: each link is given the next.
    pub(super) generation: AtomicU64,
    /// The generation of the link whose frame is being dispatched, which the queries that arrive
    /// meanwhile belong to. A session with several faces has several links, each dispatching in its
    /// own turn, so a query cannot be told its link by the last one dialled.
    pub(super) arriving: AtomicU64,
    /// Set while the session hands its own get to its queryables, under the session's lock: the
    /// queries that arrive meanwhile are the get's, not the link's (`local-queryable`).
    #[cfg(feature = "local-queryable")]
    asking: AtomicBool,
    pub(super) holds: Mutex<FinalHolds>,
    /// The queries waiting for their callbacks, in the order they arrived: the queryable they
    /// matched, the query, and the generation of its link.
    pub(super) queries: Mutex<VecDeque<(QblId, OwnedQuery, u64)>>,
    /// The queries that found no row to hold their Final and were answered with it at once.
    unheld: AtomicU64,
    /// The queryables the session's own get matched while it was asked, in the order the
    /// registry met them: the get hands them its own view once the session's lock is let go, so
    /// nothing of the query is copied (`local-queryable`).
    #[cfg(feature = "local-queryable")]
    asked: Mutex<Asked>,
}

/// The queryables of the session one of its own gets reached, as many as the session can declare.
#[cfg(feature = "local-queryable")]
pub(super) type Asked = BoundedVec<QblId, { caps::MAX_QUERYABLES }, Static>;

impl QueryPlane {
    /// A plane that holds the Finals of at most `rows` queries at once ([`FinalHolds`]).
    pub(super) fn holding(rows: usize) -> Self {
        Self {
            generation: AtomicU64::new(0),
            arriving: AtomicU64::new(0),
            #[cfg(feature = "local-queryable")]
            asking: AtomicBool::new(false),
            holds: Mutex::new(FinalHolds::holding(rows)),
            queries: Mutex::new(VecDeque::new()),
            unheld: AtomicU64::new(0),
            #[cfg(feature = "local-queryable")]
            asked: Mutex::new(BoundedVec::new_static()),
        }
    }

    /// What the observer's queryable `id` does with a query: copy it out and hold its Final. A
    /// query no row can hold is not handed to a callback: nothing holds its Final, so the dispatch
    /// that owes it sends it at once and the asker is not left without an end. It is counted.
    pub(super) fn arrive(&self, id: QblId, view: &dyn QueryView) {
        let generation = self.arriving_on();
        if !lock(&self.holds).take(generation, view.rid()) {
            self.unheld.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // The session's own get is handed to the queryables it matched by the get itself, from its
        // own view, so this notes only which; one past the list waits as a link's query does.
        #[cfg(feature = "local-queryable")]
        if generation == LOCAL_QUERY && lock(&self.asked).push(id).is_ok() {
            return;
        }
        lock(&self.queries).push_back((id, OwnedQuery::of(view), generation));
    }

    /// The queryables the session's own get matched while it was asked, the list left empty.
    #[cfg(feature = "local-queryable")]
    pub(super) fn take_asked(&self) -> Asked {
        core::mem::replace(&mut *lock(&self.asked), BoundedVec::new_static())
    }

    /// The generation a query arriving now belongs to.
    fn arriving_on(&self) -> u64 {
        #[cfg(feature = "local-queryable")]
        if self.asking.load(Ordering::Acquire) {
            return LOCAL_QUERY;
        }
        self.arriving.load(Ordering::Acquire)
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
static ANSWERING: Lock<Vec<(ThreadId, usize, u64, wz_session_core::wire_id::RequestId)>> =
    Lock::new(Vec::new());

/// This thread answers a query, from [`Self::enter`] to drop.
pub(super) struct Answering {
    thread: ThreadId,
}

impl Answering {
    pub(super) fn enter(
        engine: usize,
        generation: u64,
        rid: wz_session_core::wire_id::RequestId,
    ) -> Self {
        let thread = os::current();
        ANSWERING.with(|a| a.push((thread, engine, generation, rid)));
        Self { thread }
    }

    /// The query this thread answers innermost: its engine, generation and request id.
    fn innermost() -> Option<(usize, u64, wz_session_core::wire_id::RequestId)> {
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
            // The query is being answered, so its Final is held already and this takes no row.
            lock(&engine.plane.holds)
                .take(generation, rid)
                .then_some((generation, rid))
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

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
    /// How many queries found no row to hold their Final and were answered with it at once.
    #[cfg(test)]
    pub(crate) fn queries_unheld(&self) -> u64 {
        self.plane.unheld.load(Ordering::Relaxed)
    }
}

/// A query a C program keeps past its callback ([`HeldQuery`]). `held` is the generation and
/// request id of the hold it took, `None` for one taken outside a callback, which holds nothing
/// and answers nothing.
struct CoopHeld<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> {
    engine: Weak<CoopEngine<L, C>>,
    held: Option<(u64, wz_session_core::wire_id::RequestId)>,
    keyexpr: String,
    parameters: Option<Vec<u8>>,
    qos: QosLevel,
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> HeldQuery for CoopHeld<L, C> {
    fn reply(&self, answer: &mut dyn FnMut(&mut dyn ReplyOut)) {
        let (Some((generation, rid)), Some(engine)) = (self.held, self.engine.upgrade()) else {
            return;
        };
        let mut replies = ReplyStage::held_to(engine.reply_bounds);
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
