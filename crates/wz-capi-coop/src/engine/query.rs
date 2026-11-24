// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The answering end of a query on the cooperative engine.
//!
//! ## Every query is held
//!
//! A C callback never runs under the session's lock (decision D8), and the observer asks a
//! queryable from inside its dispatch, which runs under it. So a query that reaches a queryable's
//! row ([`QueryableRow`]) only begins a call on the row, is held in the session's round of
//! deliveries where its parts lie (`crate::round`) and HOLDS its `ResponseFinal` in the session
//! core's query plane ([`wz_session_core::query_plane`]); the C callback runs when the deliveries
//! are handed out, writes its replies into a responder built as the dispatch's would have been,
//! and the replies go out on the query's link before the hold is let go. The dispatch's own Final for that request id waits for the last
//! hold, so it never overtakes a reply. That is the order zenoh-pico keeps by answering in its read
//! task before the Final (`vendor/zenoh-pico/src/session/queryable.c` @
//! `z_result_t _z_trigger_queryables(`), and zenoh keeps by sending the Final when the last `Query` is
//! dropped (`zenoh/src/api/queryable.rs` @ `impl Drop for QueryInner {`).
//!
//! A query the callback keeps ([`QueryHolder::keep_query`]) is one hold more, released when the C
//! program lets it go; until then it answers on its own link. Its row keeps what a reply is built
//! from beside the key (the replies its parameters accept and its QoS); the program's copy keeps
//! the key and the parameters and hands the key to each reply, so a keep takes no memory of the
//! session but the row and copies nothing onto the heap.
//!
//! The session's own get is the exception to the round (`local-queryable`): the queryables it
//! matched are noted by the plane and the get hands each of them its own view ([`OwnGet`]) once
//! the session's lock is let go, inside the call. Nothing of the query is copied: a queryable
//! whose callback the asking thread is inside of is called there too, as zenoh-pico calls it.
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

use alloc::sync::{Arc, Weak};
use core::ptr::NonNull;

#[allow(unused_imports)]
use crate::prelude::*;

use wz_capi_port::os::{self, ThreadId};
use wz_capi_port::sync::Lock;
use wz_capi_port::{HeldQueryId, QblId, QueryHolder, QueryableSink, Refusal, WireHolds};

use wz_runtime_coop::session_drive::SessionLinks;
use wz_runtime_coop::ClockSource;
use wz_session_core::named_key::NamedKey;
use wz_session_core::query::QueryResponder;
#[cfg(feature = "local-queryable")]
use wz_session_core::query_options::QueryOptionsOf;
use wz_session_core::query_sink::{QueryView, ReplyError, ReplyOut};
use wz_session_core::reply_acceptance::ReplyKeyExpr;
use wz_session_core::reply_stage::{ReplyParts, StagesReplies};
use wz_session_core::row_callback::{CallLatch, RowCallback};
use wz_session_core::sample::QosLevel;
#[cfg(feature = "local-queryable")]
use wz_session_core::sample::{EncodingHint, SourceInfo};
use wz_session_mcu::dial::McuActions;

use crate::round::CoopCalls;

use super::{key_on_link, CoopEngine};

/// One of the session's own queryables, as a row of the session's tables holds it: the row keeps
/// the key the queryable answers for, whether it answers for the whole of it, the declaration its
/// key is named by, which it holds, and what its retraction names, and this everything else the
/// session knows of it, its callback among it.
/// The queryable is that one row (`docs/c-abi-architecture.md`, P1), and so is its callback's life
/// (P11): a call is begun on the row's latch as a query arrives, under the session's lock, and
/// ended once the query was handed to the callback, or dropped unhanded, with no lock held; an
/// undeclared row is let go of by whoever ends its last call.
pub(crate) struct QueryableRow {
    /// What the ABI's key held besides the declaration the tables' row holds: the declaration the
    /// retraction names and an object of the ABI's, which go with the row, let go of with no lock
    /// of the session held.
    holds: WireHolds,
    /// The program's callback, called where the row lies through a shared borrow, with the holder
    /// of the face each query came in on; a refused declaration lets it go with the row.
    sink: QueryableSink,
    /// How many calls of the callback are owed, and whether the queryable was undeclared.
    latch: CallLatch,
}

impl super::RowHolds for QueryableRow {
    fn into_holds(self) -> WireHolds {
        self.holds
    }
}

impl QueryableRow {
    /// A queryable keeping `holds`, answering through `sink`.
    pub(crate) fn new(holds: WireHolds, sink: QueryableSink) -> Self {
        Self {
            holds,
            sink,
            latch: CallLatch::new(),
        }
    }

    /// Hand `query` to the callback, its replies made through `responder` and its holds taken
    /// through `holder`, unless the queryable was undeclared since the call was begun: the one
    /// place a query is handed to a queryable's callback.
    fn ask(&self, query: &dyn QueryView, responder: &mut dyn ReplyOut, holder: &dyn QueryHolder) {
        if self.latch.retired() {
            return;
        }
        self.sink.call(query, responder, holder);
    }

    /// Declare queryable `id`, the id its row in the tables holds, on `key`, answering for the
    /// whole of it when `complete`, over `actions`: whether the link took it.
    pub(super) fn declare<C: ClockSource + 'static>(
        id: QblId,
        key: NamedKey<'_>,
        complete: bool,
        actions: &McuActions<C>,
    ) -> bool {
        actions
            .send_declare_queryable(id, key_on_link(actions, key), complete)
            .is_ok()
    }

    /// Retract queryable `id` over `actions`, naming its key as `names` says (the declaration's
    /// id and the rest of the key) when its declaration asked to. Read off the row before it is
    /// undeclared, as a subscriber's is.
    pub(super) fn retract<C: ClockSource + 'static>(
        id: QblId,
        names: Option<(wz_session_core::wire_id::ExprId, &str)>,
        actions: &McuActions<C>,
    ) {
        match names {
            Some((mapping, suffix)) => {
                actions.send_undeclare_queryable_naming(u64::from(id), mapping, suffix)
            }
            None => actions.send_undeclare_queryable(u64::from(id)),
        }
    }
}

/// A call of a queryable's callback, begun on its row's latch: where the row lies.
pub(crate) struct QueryableRowCall(NonNull<QueryableRow>);

impl RowCallback for QueryableRow {
    type Call = QueryableRowCall;

    const READS_ROW_IN_PLACE: bool = true;

    fn begin(&self) -> Option<QueryableRowCall> {
        self.latch
            .begin()
            .then(|| QueryableRowCall(NonNull::from(self)))
    }

    unsafe fn end(call: QueryableRowCall) -> bool {
        // SAFETY: the caller's: the row has not moved since the call began and is still in its
        // table, which keeps it until its last call ended.
        unsafe { call.0.as_ref() }.latch.end()
    }

    fn retire(&self) -> bool {
        self.latch.retire()
    }

    fn drained(&self) -> bool {
        self.latch.drained()
    }
}

/// A call of a queryable's callback the session began under its lock as a query arrived: where its
/// row lies, and nothing else, since the row whose last call it ends is found by its latch. Neither
/// copied nor dropped unended: each is ended once ([`Self::end`]), or its row would keep its slot
/// for good.
#[must_use = "a call is ended, or its row is never let go of"]
pub(crate) struct QueryableCall {
    call: QueryableRowCall,
}

// SAFETY: a call reaches its row through a shared borrow alone, and of the row it reads only what
// no one writes after the declaration (its id) and what is made for threads: its latch, and its
// callback, which is `Send + Sync` and called through a shared borrow. The row lies in the session's arena, which
// the tables never move a row in, until its last call ended.
unsafe impl Send for QueryableCall {}

impl QueryableCall {
    /// A call begun on `row`'s latch, under the session's lock as a query arrives: `None` past the
    /// most calls the latch counts, which hands the row nothing.
    pub(super) fn begin(row: &QueryableRow) -> Option<Self> {
        RowCallback::begin(row).map(|call| Self { call })
    }

    /// The row, where it lies.
    fn row(&self) -> &QueryableRow {
        // SAFETY: the row lies where the call began until its last call ended, and this one has
        // not.
        unsafe { self.call.0.as_ref() }
    }

    /// Whether the queryable was undeclared since the call was begun: its callback is handed
    /// nothing more.
    pub(super) fn retired(&self) -> bool {
        self.row().latch.retired()
    }

    /// Hand `query` to the queryable's callback, its replies made through `responder` and its
    /// holds taken through `holder`.
    pub(super) fn ask(
        &self,
        query: &dyn QueryView,
        responder: &mut dyn ReplyOut,
        holder: &dyn QueryHolder,
    ) {
        self.row().ask(query, responder, holder);
    }

    /// End the call: `true` when it was the last call of an undeclared queryable, whose row the
    /// session's walk of its tables then lets go of (`SessionTables::release_drained_queryable`).
    pub(crate) fn end(self) -> bool {
        // SAFETY: the row lies where the call began (the tables never move a row) and keeps its
        // slot until its last call ended, which this one is not yet; a call ends with no lock held
        // (`CallLatch::ENDS_HELD` is asserted false where the rows are chosen).
        unsafe { <QueryableRow as RowCallback>::end(self.call) }
    }
}

#[cfg(test)]
impl QueryableCall {
    /// A call begun on `row`: what a test hands the round as the dispatch would.
    pub(crate) fn begun(row: &QueryableRow) -> Self {
        Self::begin(row).expect("a live row begins a call")
    }
}

/// The responder the dispatch would have built for a query: its key, the replies its parameters
/// accept (`_anyke` admits any key), its QoS.
pub(super) fn responder_for<'a>(
    rid: wz_session_core::wire_id::RequestId,
    keyexpr: &'a str,
    parameters: Option<&[u8]>,
    qos: QosLevel,
    replies: &'a mut dyn StagesReplies,
) -> QueryResponder<'a> {
    let accept = ReplyKeyExpr::from_parameter_bytes(parameters);
    // The key is borrowed where the query lies for as long as its callback runs: nothing of it is
    // copied to answer.
    QueryResponder::borrowing(rid, keyexpr, accept, qos, replies)
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

/// What the end of a turn of an answer lets go of ([`CoopEngine::answer`]).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Release {
    /// One hold of the query's Final: its callback returned.
    Hold,
    /// One keep of the query, and its hold: the program let the query go.
    Kept,
}

/// The engine's query plane ([`wz_session_core::query_plane`]): the Finals its queryables still
/// owe, the generation of each link's queries and the calls the session's own get begins, under
/// the port's locks. The plane is shared with what answers outside the session's lock, and
/// everything that shares it lies in the engine, which a kept query reaches by a weak handle
/// alone, so none of them reads a row of its held Finals after the arena that lent them went.
pub(super) type QueryPlane = wz_session_core::query_plane::QueryPlane<CoopCalls>;

pub(crate) use wz_session_core::query_plane::{FinalHold, RefusedFinal};
pub(super) use wz_session_core::query_plane::{FinalHolds, HeldFinals, RefusedFinals};

#[cfg(feature = "local-queryable")]
pub(super) use wz_session_core::query_plane::LOCAL_QUERY;

/// The row of the plane's held Finals a get of the session's own takes before any of its legs is
/// issued.
#[cfg(feature = "local-queryable")]
pub(super) type OwnFinalHold<'a> = wz_session_core::query_plane::OwnFinalHold<'a, CoopCalls>;

/// The calls begun on the queryables of the session one of its own gets reached, held in the get's
/// own frame: `MAX_QUERYABLES` row addresses and a length (808 bytes on a 64-bit target and 404 on
/// a 32-bit one at the build's default of 100 queryables), nested at most `MAX_PENDING_FINALS`
/// deep.
#[cfg(feature = "local-queryable")]
pub(super) type Asked = wz_session_core::query_plane::Asked<CoopCalls>;

// A call is a row's address alone; the stack cost stated on `Asked` holds while it stays so.
#[cfg(feature = "local-queryable")]
const _: () = assert!(core::mem::size_of::<QueryableCall>() <= core::mem::size_of::<usize>());

/// The session's own get as each of its queryables is shown it: the get's own key and options,
/// read where they lie. What it shows is what the loopback body the wire builder makes of the same
/// options carries (`QueryOptions::loopback_query`): the parameters and the attachment when not
/// empty, and the value when its payload is not empty or its encoding is not the default one.
#[cfg(feature = "local-queryable")]
pub(super) struct OwnGet<'a> {
    keyexpr: &'a str,
    opts: &'a QueryOptionsOf<'a>,
    /// The parameters as the get sends them (`QueryOptionsOf::sent_parameters`): the options' own
    /// bytes, copied only for a get that appends the reply-keyexpr-any flag to stated ones.
    parameters: Option<alloc::borrow::Cow<'a, [u8]>>,
    /// The value's encoding as the view hands it to a queryable of the session: the one the get
    /// states, else the default one when it carries a value. A view hands an encoding out as a
    /// hint, so a lent one is copied for the session's own queryables.
    encoding: Option<EncodingHint>,
    carries_value: bool,
    rid: wz_session_core::wire_id::RequestId,
    qos: QosLevel,
}

#[cfg(feature = "local-queryable")]
impl<'a> OwnGet<'a> {
    pub(super) fn of(
        keyexpr: &'a str,
        opts: &'a QueryOptionsOf<'a>,
        rid: wz_session_core::wire_id::RequestId,
    ) -> Self {
        let payload = opts.payload.as_deref().unwrap_or_default();
        let stated = opts.encoding.as_ref().map(|encoding| encoding.view());
        let names_one = |encoding: wz_session_core::sample::EncodingRef<'_>| {
            encoding.packed_id >> 1 != 0 || encoding.schema.is_some()
        };
        let carries_value = !payload.is_empty() || stated.is_some_and(names_one);
        Self {
            keyexpr,
            opts,
            parameters: opts.sent_parameters(),
            encoding: carries_value.then(|| {
                stated
                    .map(|encoding| encoding.to_hint())
                    .unwrap_or_default()
            }),
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
        self.parameters
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
        self.encoding.as_ref()
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

/// A plane that holds the Finals of at most `rows` queries at once, in rows lent from an arena
/// the test leaks.
#[cfg(test)]
pub(super) fn leaked_plane(rows: usize) -> QueryPlane {
    use wz_session_core::bounded::Arena;
    let held = Arena::table_bytes::<FinalHold>(rows).expect("rows the address space holds");
    let refused = Arena::table_bytes::<RefusedFinal>(rows).expect("rows the address space holds");
    let arena: &'static mut crate::arena::SessionArena = Box::leak(Box::new(
        crate::arena::SessionArena::of_bytes(
            held.saturating_add(refused),
            &crate::arena::AllocatorMemory,
        )
        .expect("the host has the memory"),
    ));
    let mut lend = arena.lender();
    let holds = FinalHolds::over(lend.table(rows), lend.table(rows));
    lend.finish().expect("the arena has the rows");
    QueryPlane::over(holds)
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
    fn keep_query(&self, view: &dyn QueryView) -> Result<Option<HeldQueryId>, Refusal> {
        let engine = self.engine.upgrade().ok_or(Refusal::Closed)?;
        let Some((at, generation, rid)) = Answering::innermost() else {
            return Ok(None);
        };
        // Only the query this thread is answering, of this engine, can be kept: a hold taken
        // anywhere else would come after the Final it was meant to keep.
        if at != Arc::as_ptr(&engine) as usize || rid != view.rid() {
            return Ok(None);
        }
        engine.keep(generation, view)
    }

    fn session_closed(&self) -> bool {
        self.engine
            .upgrade()
            .is_none_or(|engine| super::SessionEngine::is_closed(&*engine))
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
    /// How many arrivals at a queryable were refused for want of a row to hold their Final.
    #[cfg(test)]
    pub(crate) fn queries_refused(&self) -> u64 {
        self.plane.refused()
    }

    /// Keep the query `view` describes, which this thread's callback answers under link
    /// `generation` and whose row its call holds: the row keeps what its replies are built from
    /// beside its key, which the caller keeps, and one hold more of its Final. A query kept already
    /// is kept once more. Refused, holding nothing, as [`QueryHolder::keep_query`] says.
    fn keep(&self, generation: u64, view: &dyn QueryView) -> Result<Option<HeldQueryId>, Refusal> {
        if super::SessionEngine::is_closed(self) {
            return Err(Refusal::Closed);
        }
        let id = HeldQueryId {
            generation,
            rid: view.rid(),
        };
        self.plane.with_holds(|holds| {
            if let Some(again) = holds.keep_again(generation, id.rid) {
                return again.map(|_| Some(id)).map_err(|_| Refusal::TableFull);
            }
            let answer = (
                ReplyKeyExpr::from_parameter_bytes(view.parameters()),
                view.qos(),
            );
            if holds.keep(generation, id.rid, answer) {
                Ok(Some(id))
            } else {
                Err(Refusal::TableFull)
            }
        })
    }

    /// Answer the kept query `id`, whose key is `key`, with what `answer` writes
    /// ([`super::SessionEngine::reply_held`]). The reply holds a keep of its own while it answers,
    /// so a release of the caller's keep from another thread meanwhile sends no Final before it.
    pub(super) fn reply_kept(
        &self,
        id: HeldQueryId,
        key: &str,
        answer: &mut dyn FnMut(&mut dyn ReplyOut),
    ) {
        if super::SessionEngine::is_closed(self) {
            return;
        }
        let kept = self
            .plane
            .with_holds(|holds| holds.keep_again(id.generation, id.rid));
        let Some(Ok((accept, qos))) = kept else {
            return;
        };
        let mut onward = Onward::to(self, id.generation);
        {
            let mut responder = QueryResponder::borrowing(id.rid, key, accept, qos, &mut onward);
            answer(&mut responder);
        }
        self.answer(id.generation, id.rid, Release::Kept);
    }
}

#[cfg(all(test, feature = "std"))]
mod round_tests {
    //! A link's query held in the session's round of deliveries: handed to the queryable it reached
    //! with its parts read where they lie, its call ended by the round.
    use super::*;
    use crate::round::AnswersQueries;
    use wz_capi_port::WireKey;

    /// What the test's engine stand-in was asked to answer: each query's key, its parameters and
    /// where they lie, the generation it came in under, and its encoding's packed id with where
    /// its schema lies.
    type Noted = std::sync::Mutex<Vec<(String, Option<Vec<u8>>, usize, u64, Option<(u32, usize)>)>>;

    /// An engine stand-in that notes what it is asked to answer.
    struct Noting(Noted);

    impl AnswersQueries<CoopCalls> for Noting {
        fn answer_query(&self, _call: &QueryableCall, query: &dyn QueryView, generation: u64) {
            self.0.lock().unwrap().push((
                query.keyexpr().to_owned(),
                query.parameters().map(<[u8]>::to_vec),
                query
                    .parameters()
                    .map_or(0, |parameters| parameters.as_ptr() as usize),
                generation,
                query.encoding_parts().map(|(packed_id, schema)| {
                    (
                        packed_id,
                        schema.map_or(0, |schema| schema.as_ptr() as usize),
                    )
                }),
            ));
        }
    }

    /// A query whose key, parameters and encoding lie where the test lends them.
    struct Asked<'d> {
        key: &'d str,
        parameters: &'d [u8],
        encoding: Option<(u32, Option<&'d [u8]>)>,
    }

    impl QueryView for Asked<'_> {
        fn keyexpr(&self) -> &str {
            self.key
        }

        fn parameters(&self) -> Option<&[u8]> {
            Some(self.parameters)
        }

        fn attachment(&self) -> Option<&[u8]> {
            None
        }

        fn encoding_parts(&self) -> Option<(u32, Option<&[u8]>)> {
            self.encoding
        }

        fn rid(&self) -> wz_session_core::wire_id::RequestId {
            3
        }

        fn qos(&self) -> QosLevel {
            QosLevel::DEFAULT
        }
    }

    /// A queryable's row, boxed so it lies where it is while a call of it runs.
    fn row() -> Box<QueryableRow> {
        Box::new(QueryableRow::new(
            WireKey::literal().into_holds(),
            QueryableSink::shared(|_, _, _| {}),
        ))
    }

    /// The datagram a query of key `demo/q` and parameters `a=1` lies in.
    const DATAGRAM: [u8; 10] = *b"demo/q?a=1";

    /// A query that lies in a lent datagram is held in the round and handed, on its delivery, to
    /// the engine that answers it, its key, parameters and encoding's schema read where they lie
    /// and its link's generation with it; the round ends its call, so the row has none running
    /// after. Turned red by a round that copies the query's parts, drops its encoding or keeps
    /// its call.
    #[test]
    fn a_query_is_handed_where_its_parts_lie_and_its_call_ended() {
        let datagram = DATAGRAM;
        let key = core::str::from_utf8(&datagram[..6]).expect("a key");
        let round = crate::round::leaked(4);
        let noting = Arc::new(Noting(Noted::default()));
        // Made of the stand-in's own type, then unsized where the round takes it.
        let answering: Weak<Noting> = Arc::downgrade(&noting);
        round.answer_queries_with(answering);
        let row = row();
        // SAFETY (each call): this thread is the round's one writer, and the datagram outlives it.
        unsafe { round.set_lending(Some(&datagram[..])) };
        // The schema is a range of the datagram as a frame's would be: here, its key's first part.
        let asked = Asked {
            key,
            parameters: &datagram[7..],
            encoding: Some((0x0B, Some(&datagram[..4]))),
        };
        assert!(unsafe { round.offer_query(QueryableCall::begun(&row), &asked, 7) });
        unsafe { round.set_lending(None) };
        unsafe { round.seal() };
        assert!(round.deliver());
        assert_eq!(
            *noting.0.lock().unwrap(),
            [(
                "demo/q".to_owned(),
                Some(b"a=1".to_vec()),
                datagram[7..].as_ptr() as usize,
                7,
                Some((0x0B, datagram.as_ptr() as usize))
            )],
            "handed where its parameters and schema lie, under its link's generation"
        );
        assert!(row.retire(), "the round ended the call");
    }

    /// The CONTROL: a round no engine answers through hands the query to none, and ends its call
    /// all the same.
    #[test]
    fn a_round_no_engine_answers_through_ends_the_call_unhanded() {
        let datagram = DATAGRAM;
        let key = core::str::from_utf8(&datagram[..6]).expect("a key");
        let round = crate::round::leaked(4);
        let row = row();
        // SAFETY (each call): this thread is the round's one writer, and the datagram outlives it.
        unsafe { round.set_lending(Some(&datagram[..])) };
        let asked = Asked {
            key,
            parameters: &datagram[7..],
            encoding: None,
        };
        assert!(unsafe { round.offer_query(QueryableCall::begun(&row), &asked, 7) });
        unsafe { round.set_lending(None) };
        unsafe { round.seal() };
        assert!(round.deliver());
        assert!(row.retire(), "the round ended the call");
    }
}
