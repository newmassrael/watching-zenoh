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
//! arrives when every row is taken is refused and counted: it is not handed to a callback, and
//! nothing answers it, not even a Final, as zenoh-pico refuses a query it cannot build.
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
use wz_session_core::query_sink::{QueryView, ReplyError, ReplyOut};
use wz_session_core::reply_acceptance::ReplyKeyExpr;
use wz_session_core::reply_stage::{ReplyParts, StagesReplies};
use wz_session_core::sample::{EncodingHint, QosLevel, SourceInfo};

use super::queued::Queued;
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
    replies: &'a mut dyn StagesReplies,
) -> QueryResponder<'a> {
    let accept = ReplyKeyExpr::from_parameter_bytes(parameters);
    QueryResponder::new(rid, keyexpr.to_owned(), accept, qos, replies)
}

/// Where a query's replies go as its queryable makes them: each one onto the link the query came in
/// on, written into the link's transmit slot under the session's lock
/// ([`ResponseSink::send_reply_parts`](wz_session_core::response_sink::ResponseSink)), or to the
/// session's own get. Nothing is staged, as zenoh-pico stages nothing: `z_query_reply` sends its
/// reply at the call (`vendor/zenoh-pico/src/net/primitives.c` @
/// `if (_z_send_n_msg(zn, &z_msg, Z_RELIABILITY_RELIABLE, Z_CONGESTION_CONTROL_BLOCK, NULL) != _Z_RES_OK) {`),
/// so a query is answered with no buffer of its replies and as many replies as its queryable makes;
/// the payload bound the session states (`MAX_REPLY_PAYLOAD_BYTES`) still refuses a longer one.
/// The query's Final follows when its hold is let go of ([`CoopEngine::answer`]).
pub(super) struct Onward<'a, L: SessionLinks + 'static, C: ClockSource + Clone + 'static> {
    engine: &'a CoopEngine<L, C>,
    generation: u64,
}

impl<'a, L: SessionLinks + 'static, C: ClockSource + Clone + 'static> Onward<'a, L, C> {
    /// The replies to a query that came in under `generation`.
    pub(super) fn to(engine: &'a CoopEngine<L, C>, generation: u64) -> Self {
        Self { engine, generation }
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> StagesReplies
    for Onward<'_, L, C>
{
    fn stage_reply(&mut self, parts: ReplyParts<'_>) -> Result<(), ReplyError> {
        self.engine.send_reply(self.generation, parts)
    }
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
/// `MAX_PENDING_FINALS` the session's open resolved under the build's (the deploy `limits` key
/// `pending_finals`), as the Finals a dispatch owes are held to. A request that would need a row
/// the table has no room for is REFUSED before its callback runs: it is not copied out, nothing
/// answers it and no Final is sent for it, as zenoh-pico refuses a query it cannot build
/// (`vendor/zenoh-pico/src/session/queryable.c` @ `z_result_t _z_trigger_queryables(`, which
/// returns before any callback and sends no Final) and as the session's own stage refuses a
/// request it cannot owe a Final for (`wz_session_core::caps::MAX_PENDING_FINALS`). The table is
/// the plane's own and fixed in size, as the plane is shared with what answers outside the
/// session's lock.
pub(super) struct FinalHolds {
    holds: BoundedVec<FinalHold, { caps::MAX_PENDING_FINALS }, Static>,
    rows: usize,
    /// The requests refused for want of a row in the dispatch now running, whose Final that
    /// dispatch owes and must not send. A request that reached a queryable owes its Final in the
    /// same dispatch, so [`Self::owe`] takes each out before the dispatch ends; a dispatch owes no
    /// more Finals than the build's `MAX_PENDING_FINALS`, which bounds this list as it does the
    /// rows.
    refused: BoundedVec<
        (u64, wz_session_core::wire_id::RequestId),
        { caps::MAX_PENDING_FINALS },
        Static,
    >,
}

impl FinalHolds {
    /// No Final held, and room for the Finals of `rows` queries.
    pub(super) fn holding(rows: usize) -> Self {
        Self {
            holds: BoundedVec::new_static(),
            rows,
            refused: BoundedVec::new_static(),
        }
    }

    /// One hold more on the Final of `rid` on link `generation`: `false`, holding nothing and
    /// noting nothing, when no hold of that query is open and every row is taken.
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

    /// A query of the dispatch now running reaches a queryable: one hold more on its Final, or
    /// `false` when the request was refused already or no row is left for it, which refuses it
    /// for the rest of the dispatch so its Final is never sent ([`Self::owe`]).
    pub(super) fn admit(
        &mut self,
        generation: u64,
        rid: wz_session_core::wire_id::RequestId,
    ) -> bool {
        // A request refused once stays refused for the rest of its dispatch, so a second
        // queryable it matches does not answer what the first could not.
        if self.refused.contains(&(generation, rid)) {
            return false;
        }
        if self.take(generation, rid) {
            return true;
        }
        // The list cannot be full while every refusal it holds is owed by the running dispatch;
        // were it, the request would still run no callback, and its Final would go out at once.
        let _ = self.refused.push((generation, rid));
        false
    }

    /// The dispatch owes the Final of `rid`: `true` when nothing holds it, so it goes out now,
    /// `false` when it waits for the last hold or the request was refused, whose Final is never
    /// sent.
    pub(super) fn owe(
        &mut self,
        generation: u64,
        rid: wz_session_core::wire_id::RequestId,
        qos: QosLevel,
    ) -> bool {
        if let Some(at) = self
            .refused
            .iter()
            .position(|&refused| refused == (generation, rid))
        {
            self.refused.remove(at);
            return false;
        }
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
        // The table's lock is let go of before a hold is made, and a hold is made only for a row
        // taken: a hold's drop locks the table to give its row back, so one dropped under the
        // lock would wait on it, and one made for a refused row would give back a row it never
        // took.
        let taken = lock(holds).take(LOCAL_QUERY, rid);
        taken.then(|| Self {
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
    pub(super) queries: Queued<VecDeque<(QblId, OwnedQuery, u64)>>,
    /// The arrivals refused for want of a row to hold their Final: one for each queryable a
    /// refused query reached, none of whose callbacks ran.
    refused: AtomicU64,
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
            queries: Queued::new(VecDeque::new()),
            refused: AtomicU64::new(0),
            #[cfg(feature = "local-queryable")]
            asked: Mutex::new(BoundedVec::new_static()),
        }
    }

    /// What the observer's queryable `id` does with a query: copy it out and hold its Final, or,
    /// with no row left for its Final, refuse it ([`FinalHolds::admit`]): no callback runs for it,
    /// nothing answers it and it is counted.
    pub(super) fn arrive(&self, id: QblId, view: &dyn QueryView) {
        let generation = self.arriving_on();
        if !lock(&self.holds).admit(generation, view.rid()) {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // The session's own get is handed to the queryables it matched by the get itself, from its
        // own view, so this notes only which; one past the list waits as a link's query does.
        #[cfg(feature = "local-queryable")]
        if generation == LOCAL_QUERY && lock(&self.asked).push(id).is_ok() {
            return;
        }
        self.queries
            .lock()
            .push_back((id, OwnedQuery::of(view), generation));
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
    /// How many arrivals at a queryable were refused for want of a row to hold their Final.
    #[cfg(test)]
    pub(crate) fn queries_refused(&self) -> u64 {
        self.plane.refused.load(Ordering::Relaxed)
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
        let mut onward = Onward::to(&engine, generation);
        {
            let mut responder = responder_for(
                rid,
                &self.keyexpr,
                self.parameters.as_deref(),
                self.qos,
                &mut onward,
            );
            answer(&mut responder);
        }
        engine.answer(generation, rid, false);
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> Drop for CoopHeld<L, C> {
    fn drop(&mut self) {
        if let (Some((generation, rid)), Some(engine)) = (self.held, self.engine.upgrade()) {
            engine.answer(generation, rid, true);
        }
    }
}

#[cfg(all(test, feature = "std", feature = "local-queryable"))]
mod tests {
    //! The row of the plane's held Finals a get of the session's own takes, refused when every
    //! row is taken.
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    /// Run `body` on a thread of its own and wait at most five seconds for what it returns: a take
    /// that waits on the lock it holds fails here by name instead of holding the run for ever.
    fn within_five_seconds<R: Send + 'static>(
        what: &str,
        body: impl FnOnce() -> R + Send + 'static,
    ) -> R {
        let (done, outcome) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(body());
        });
        outcome
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("{what} did not return within five seconds"))
    }

    /// A table of one row refuses a second get's row and returns at once, leaving the first row
    /// held; once the first is let go of, the row takes the next. The CONTROL is the first take.
    #[test]
    fn a_full_table_refuses_the_row_and_keeps_the_one_held() {
        let (first, refused, still_full, next) = within_five_seconds("a refused take", || {
            let holds = Mutex::new(FinalHolds::holding(1));
            let first = OwnFinalHold::take(&holds, 1);
            let refused = OwnFinalHold::take(&holds, 2).is_none();
            let still_full = OwnFinalHold::take(&holds, 3).is_none();
            let held = first.is_some();
            drop(first);
            let next = OwnFinalHold::take(&holds, 4).is_some();
            (held, refused, still_full, next)
        });
        assert!(first, "CONTROL: the one row is taken");
        assert!(refused, "every row taken: refused");
        assert!(still_full, "the refusal gave back no row it never took");
        assert!(next, "the row the first let go of takes the next");
    }
}

#[cfg(all(test, feature = "std"))]
mod refusal_tests {
    //! A request no row can hold is refused at each queryable of its dispatch, with its Final.
    use super::*;

    /// With its one row taken, the table refuses a second request, which stays refused for the
    /// rest of its dispatch though a row comes free, and whose Final the dispatch does not send;
    /// that Final spends the refusal, so the request is weighed afresh after. The CONTROL is the
    /// first request, held, whose Final waits for its hold.
    #[test]
    fn a_request_no_row_holds_is_refused_with_its_final() {
        let mut holds = FinalHolds::holding(1);
        assert!(
            holds.admit(1, 7),
            "CONTROL: the one row holds the first request"
        );
        assert!(!holds.admit(1, 8), "every row taken: refused");
        assert!(
            !holds.owe(1, 7, QosLevel::DEFAULT),
            "CONTROL: the held request's Final waits for its hold"
        );
        assert!(
            holds.release(1, 7).is_some(),
            "CONTROL: the last hold let go sends the Final owed"
        );
        assert!(
            !holds.admit(1, 8),
            "refused for the rest of its dispatch, though a row is free"
        );
        assert!(
            !holds.owe(1, 8, QosLevel::DEFAULT),
            "the refused request's Final is not sent"
        );
        assert!(
            holds.admit(1, 8),
            "the refusal spent, the free row holds it"
        );
        assert!(
            holds.release(1, 8).is_none(),
            "nothing owed yet for the request held afresh"
        );
    }

    /// A hold taken outside a dispatch (a get of the session's own) and refused notes no
    /// refusal: the Final of that request id is not withheld from the dispatch that owes it.
    #[test]
    fn a_refused_take_withholds_no_final() {
        let mut holds = FinalHolds::holding(1);
        assert!(holds.take(0, 1), "CONTROL: the one row is taken");
        assert!(!holds.take(0, 2), "every row taken: refused");
        assert!(
            holds.owe(0, 2, QosLevel::DEFAULT),
            "a refused take noted nothing, so the Final goes out"
        );
    }
}
