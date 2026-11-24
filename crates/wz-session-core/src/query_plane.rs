// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The answering end of the session's queries: the Finals its queryables still owe, the
//! generation of the link each query belongs to, and the calls a get of the session's own hands
//! its queryables.
//!
//! ## Every query is held
//!
//! A callback of the program never runs under the session's lock (decision D8), and a query
//! reaches a queryable from inside the session's dispatch, which runs under it. So a query that
//! reaches a queryable only begins a call on its row, is held in the session's round of
//! deliveries where its parts lie ([`Round::offer_query`]) and HOLDS its `ResponseFinal`
//! ([`FinalHolds`]); the callback runs when the deliveries are handed out, its replies go out on
//! the query's link, and the hold is let go of after them. The dispatch's own Final for that
//! request id waits for the last hold, so it never overtakes a reply. That is the order zenoh-pico
//! keeps by answering in its read task before the Final
//! (`vendor/zenoh-pico/src/session/queryable.c` @ `z_result_t _z_trigger_queryables(`), and zenoh
//! keeps by sending the Final when the last `Query` is dropped
//! (`zenoh/src/api/queryable.rs` @ `impl Drop for QueryInner {`). A query the program keeps past
//! its callback is one hold more, released when the program lets it go.
//!
//! The holds are rows of a fixed table, as many as the session's `MAX_PENDING_FINALS`. A query
//! that arrives when every row is taken is refused and counted: it is not handed to a callback,
//! and nothing answers it, not even a Final, as zenoh-pico refuses a query it cannot build.
//!
//! The session's own get is the exception to the round, where the engine's own queryables answer
//! its gets ([`PlaneCalls::LocalAnswers`]): the calls begun on the queryables it matched are
//! noted ([`QueryPlane::take_asked`]) and the get hands each of them its own view once the
//! session's lock is let go, inside the call, so nothing of the query is copied.
//!
//! ## A query belongs to its link
//!
//! Each link the session dials has a GENERATION ([`QueryPlane::next_generation`]). A query is
//! held and answered under the generation of the link it came in on, and a reply or a Final goes
//! out only while that link is the session's: a router that asked on a link since lost will never
//! read the answer, and a new router never asked.

use core::sync::atomic::{AtomicBool, Ordering};
// The split `round` uses: the host profile has the native atomics, the `no_std` profile gets the
// critical-section ones for the cores that have none.
#[cfg(not(feature = "no_std"))]
use core::sync::atomic::AtomicU64;
#[cfg(feature = "no_std")]
use portable_atomic::AtomicU64;

use crate::bounded::{BoundedVec, Lent, Static};
use crate::caps;
use crate::plane_lock::LockFamily;
use crate::query_sink::QueryView;
use crate::reply_acceptance::ReplyKeyExpr;
use crate::round::{PlaneCalls, Round, RoundCalls};
use crate::sample::QosLevel;
use crate::session_tables::Presence;
use crate::wire_id::RequestId;

/// One request's Final, held while a callback or a kept query may still answer it.
pub struct FinalHold {
    generation: u64,
    rid: RequestId,
    holds: usize,
    /// The QoS of the Final the dispatch owes, once it owes one.
    due: Option<QosLevel>,
    /// What the session keeps of the query while a program keeps it past its callback.
    kept: Option<KeptQuery>,
}

/// What the session keeps of a query a program keeps past its callback: what a reply to it is
/// built from beside its key, which the program's copy keeps and hands to each reply, and how many
/// of its row's holds are keeps.
struct KeptQuery {
    /// The replies the query's parameters accept.
    accept: ReplyKeyExpr,
    qos: QosLevel,
    keeps: usize,
}

/// What a reply to a kept query is built from beside its key: the replies it accepts and its QoS.
pub type KeptAnswer = (ReplyKeyExpr, QosLevel);

/// A keep refused: the query's holds are as many as a count holds, and nothing was taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HoldsFull;

/// The Finals held open, by the link generation and request id they answer: one row for each
/// query a callback is still to answer or a program keeps, as many as it was lent, the value of
/// `MAX_PENDING_FINALS` the session's open resolved under the build's (the deploy `limits` key
/// `pending_finals`), as the Finals a dispatch owes are held to. A request that would need a row
/// the table has no room for is REFUSED before its callback runs: it is not copied out, nothing
/// answers it and no Final is sent for it, as zenoh-pico refuses a query it cannot build
/// (`vendor/zenoh-pico/src/session/queryable.c` @ `z_result_t _z_trigger_queryables(`, which
/// returns before any callback and sends no Final) and as the session's own stage refuses a
/// request it cannot owe a Final for ([`caps::MAX_PENDING_FINALS`]). The table is lent from the
/// session's arena at its open, and let go of before the arena is given back
/// ([`QueryPlane::let_go`]).
#[derive(Default)]
pub struct FinalHolds {
    holds: HeldFinals,
    /// The requests refused for want of a row in the dispatch now running, whose Final that
    /// dispatch owes and must not send. A request that reached a queryable owes its Final in the
    /// same dispatch, so [`Self::owe`] takes each out before the dispatch ends; a dispatch owes no
    /// more Finals than the session's `MAX_PENDING_FINALS`, which sizes this list as it does the
    /// rows.
    refused: RefusedFinals,
}

/// A request refused for want of a row: the link generation and the request id it came with.
pub type RefusedFinal = (u64, RequestId);

/// The rows the Finals held lie in, lent from the session's arena.
pub type HeldFinals = BoundedVec<FinalHold, { caps::MAX_PENDING_FINALS }, Lent>;

/// The rows the requests refused in the running dispatch lie in, lent from the session's arena.
pub type RefusedFinals = BoundedVec<RefusedFinal, { caps::MAX_PENDING_FINALS }, Lent>;

impl FinalHolds {
    /// No Final held, in `holds` and `refused`, rows the session's arena lent, as many of each
    /// as the queries whose Finals it holds at once.
    pub fn over(holds: HeldFinals, refused: RefusedFinals) -> Self {
        Self { holds, refused }
    }

    /// The row of the Final of `rid` on link `generation`.
    fn row(&mut self, generation: u64, rid: RequestId) -> Option<&mut FinalHold> {
        self.holds
            .iter_mut()
            .find(|h| h.generation == generation && h.rid == rid)
    }

    /// One hold more on the Final of `rid` on link `generation`: `false`, holding nothing and
    /// noting nothing, when no hold of that query is open and every row is taken, or when its
    /// holds are as many as a count holds.
    pub fn take(&mut self, generation: u64, rid: RequestId) -> bool {
        if let Some(hold) = self.row(generation, rid) {
            let Some(holds) = hold.holds.checked_add(1) else {
                return false;
            };
            hold.holds = holds;
            return true;
        }
        self.holds
            .push(FinalHold {
                generation,
                rid,
                holds: 1,
                due: None,
                kept: None,
            })
            .is_ok()
    }

    /// One keep more of the query of `rid` on link `generation`, which a program keeps already,
    /// and one hold more of its Final, with what its replies are built from: `None` when the query
    /// is not kept, and refused with [`HoldsFull`], taking nothing, when its holds are as many as
    /// a count holds.
    pub fn keep_again(
        &mut self,
        generation: u64,
        rid: RequestId,
    ) -> Option<Result<KeptAnswer, HoldsFull>> {
        let hold = self.row(generation, rid)?;
        let kept = hold.kept.as_mut()?;
        let (Some(holds), Some(keeps)) = (hold.holds.checked_add(1), kept.keeps.checked_add(1))
        else {
            return Some(Err(HoldsFull));
        };
        hold.holds = holds;
        kept.keeps = keeps;
        Some(Ok((kept.accept, kept.qos)))
    }

    /// The first keep of the query of `rid` on link `generation`, whose callback runs and so holds
    /// its row, its replies built as `answer` says: one hold more of its Final. `false`, keeping
    /// nothing, when no row holds the query, it is kept already, or its holds are as many as a
    /// count holds.
    pub fn keep(&mut self, generation: u64, rid: RequestId, answer: KeptAnswer) -> bool {
        let Some(hold) = self.row(generation, rid) else {
            return false;
        };
        let (None, Some(holds)) = (&hold.kept, hold.holds.checked_add(1)) else {
            return false;
        };
        hold.holds = holds;
        hold.kept = Some(KeptQuery {
            accept: answer.0,
            qos: answer.1,
            keeps: 1,
        });
        true
    }

    /// Let go of one keep of the query of `rid` on link `generation`, and of its hold: the row
    /// forgets the query with the last keep, and answers the Final's QoS when it was owed and
    /// this was the row's last hold. A query not kept lets go of nothing.
    pub fn release_kept(&mut self, generation: u64, rid: RequestId) -> Option<QosLevel> {
        let (at, hold) = self
            .holds
            .iter_mut()
            .enumerate()
            .find(|(_, h)| h.generation == generation && h.rid == rid)?;
        let kept = hold.kept.as_mut()?;
        kept.keeps = kept.keeps.saturating_sub(1);
        if kept.keeps == 0 {
            hold.kept = None;
        }
        hold.holds = hold.holds.saturating_sub(1);
        if hold.holds > 0 {
            return None;
        }
        self.holds.remove(at).due
    }

    /// A query of the dispatch now running reaches a queryable: one hold more on its Final, or
    /// `false` when the request was refused already or no row is left for it, which refuses it
    /// for the rest of the dispatch so its Final is never sent ([`Self::owe`]).
    pub fn admit(&mut self, generation: u64, rid: RequestId) -> bool {
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
    pub fn owe(&mut self, generation: u64, rid: RequestId, qos: QosLevel) -> bool {
        if let Some(at) = self
            .refused
            .iter()
            .position(|&refused| refused == (generation, rid))
        {
            self.refused.remove(at);
            return false;
        }
        match self.row(generation, rid) {
            Some(hold) => {
                hold.due = Some(qos);
                false
            }
            None => true,
        }
    }

    /// Let go of one hold: the Final's QoS when it was owed and this was the last hold.
    pub fn release(&mut self, generation: u64, rid: RequestId) -> Option<QosLevel> {
        let (at, hold) = self
            .holds
            .iter_mut()
            .enumerate()
            .find(|(_, h)| h.generation == generation && h.rid == rid)?;
        hold.holds = hold.holds.saturating_sub(1);
        if hold.holds > 0 {
            return None;
        }
        self.holds.remove(at).due
    }
}

/// The generation a query asked by the session's OWN get is held and answered under: no link ever
/// has it ([`QueryPlane::next_generation`] steps over it), so a reply or a Final under it goes to
/// the get's pending entry and never to a link.
pub const LOCAL_QUERY: u64 = 0;

/// The row of the plane's held Finals a get of the session's own takes before any of its legs is
/// issued, so the session's queryables are asked all or none: a session with no row free refuses
/// the get before anything is sent. Let go of at drop unless [`Self::release`] lets go of it.
pub struct OwnFinalHold<'a, C: PlaneCalls> {
    plane: Option<&'a QueryPlane<C>>,
    rid: RequestId,
}

impl<'a, C: PlaneCalls> OwnFinalHold<'a, C> {
    /// The row for the get of the session's own whose request id is `rid`: `None` when every row
    /// of `plane`'s held Finals is taken.
    pub fn take(plane: &'a QueryPlane<C>, rid: RequestId) -> Option<Self> {
        // The table's lock is let go of before a hold is made, and a hold is made only for a row
        // taken: a hold's drop locks the table to give its row back, so one dropped under the
        // lock would wait on it, and one made for a refused row would give back a row it never
        // took.
        let taken = plane.with_holds(|holds| holds.take(LOCAL_QUERY, rid));
        taken.then(|| Self {
            plane: Some(plane),
            rid,
        })
    }

    /// The request id of the get the row was taken for.
    pub fn rid(&self) -> RequestId {
        self.rid
    }

    /// Let go of the row's hold: the Final's QoS when it was owed and no queryable asked holds it.
    pub fn release(mut self) -> Option<QosLevel> {
        let plane = self.plane.take()?;
        plane.with_holds(|holds| holds.release(LOCAL_QUERY, self.rid))
    }
}

impl<C: PlaneCalls> Drop for OwnFinalHold<'_, C> {
    fn drop(&mut self) {
        if let Some(plane) = self.plane.take() {
            // Owed nothing yet: the get it was taken for issued no leg to the session.
            let rid = self.rid;
            plane.with_holds(|holds| holds.release(LOCAL_QUERY, rid));
        }
    }
}

/// The calls begun on the queryables of the session one of its own gets reached, as many as the
/// session can declare.
///
/// A fixed array the get takes out of the plane whole and holds in its own frame while it hands
/// the calls out with no lock held ([`QueryPlane::take_asked`]), so it takes no heap after the
/// open; its cost is stack: `MAX_QUERYABLES` calls and a length. A queryable's callback that asks a
/// get of its own session from inside the call holds a second one in a frame above the first, and
/// so on: each get nested so holds a row of the plane's held Finals until its calls are handed
/// ([`FinalHolds`]), so the nesting is at most the session's `MAX_PENDING_FINALS` deep, and the
/// get past it is refused before it asks. Shared rows of the arena would hand a nested get's calls
/// to the round when they overflow, which reorders the calls zenoh-pico makes inline, so the frame
/// keeps its own.
pub type Asked<C> = BoundedVec<<C as RoundCalls>::Queryable, { caps::MAX_QUERYABLES }, Static>;

/// What a plane whose session's own queryables answer its gets keeps of the get being asked.
struct LocalAsking<C: PlaneCalls> {
    /// Set while the session hands its own get to its queryables, under the session's lock: the
    /// queries that arrive meanwhile are the get's, not the link's.
    asking: AtomicBool,
    /// The queryables the session's own get matched while it was asked, in the order the
    /// registry met them: the get hands them its own view once the session's lock is let go, so
    /// nothing of the query is copied.
    asked: <C::Queues as LockFamily>::Lock<Asked<C>>,
}

impl<C: PlaneCalls> Default for LocalAsking<C> {
    fn default() -> Self {
        Self {
            asking: AtomicBool::new(false),
            asked: C::Queues::new(BoundedVec::new_static()),
        }
    }
}

/// What the queryable plane shares between the session's state, its dispatch, the queryables'
/// deliveries and the queries a program keeps.
pub struct QueryPlane<C: PlaneCalls> {
    /// The generation of the link dialled last: each link is given the next.
    generation: AtomicU64,
    /// The generation of the link whose frame is being dispatched, which the queries that arrive
    /// meanwhile belong to. A session with several faces has several links, each dispatching in its
    /// own turn, so a query cannot be told its link by the last one dialled.
    arriving: AtomicU64,
    holds: <C::Queues as LockFamily>::Lock<FinalHolds>,
    /// The arrivals refused for want of a row to hold their Final: one for each queryable a
    /// refused query reached, none of whose callbacks ran.
    refused: AtomicU64,
    /// The get of the session's own being asked, where its own queryables answer its gets.
    local: <C::LocalAnswers as Presence>::Table<LocalAsking<C>>,
}

impl<C: PlaneCalls> QueryPlane<C> {
    /// A plane that holds the Finals of its queries in `holds` ([`FinalHolds`]), rows the
    /// session's arena lent.
    pub fn over(holds: FinalHolds) -> Self {
        Self {
            generation: AtomicU64::new(0),
            arriving: AtomicU64::new(0),
            holds: C::Queues::new(holds),
            refused: AtomicU64::new(0),
            local: <C::LocalAnswers as Presence>::empty::<LocalAsking<C>>(),
        }
    }

    /// The generation the next link, or the next join of a group, answers its queries under: the
    /// counter's next value. The counter wraps as `fetch_add` does, and a value equal to
    /// [`LOCAL_QUERY`], which names the session's own queries and no link's, is stepped over.
    pub fn next_generation(&self) -> u64 {
        loop {
            let generation = self
                .generation
                .fetch_add(1, Ordering::AcqRel)
                .wrapping_add(1);
            if generation != LOCAL_QUERY {
                return generation;
            }
        }
    }

    /// The queries that arrive from here on belong to the link of `generation`, whose frame is
    /// being dispatched.
    pub fn set_arriving(&self, generation: u64) {
        self.arriving.store(generation, Ordering::Release);
    }

    /// `f` on the Finals held, with their lock held for the length of the call.
    pub fn with_holds<R>(&self, f: impl FnOnce(&mut FinalHolds) -> R) -> R {
        C::Queues::with(&self.holds, f)
    }

    /// How many arrivals at a queryable were refused for want of a row to hold their Final.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Let go of the rows the held Finals lie in before the arena that lent them is given back:
    /// what the session's last handle does, once its round ended the calls its records held. No
    /// query is held after it: a kept query reaches the plane only through the engine, which is
    /// being let go of.
    pub fn let_go(&self) {
        let lent = self.with_holds(core::mem::take);
        drop(lent);
    }

    /// What a query that reached a queryable does: hold its Final and begin a call on the
    /// queryable's row (`begin`, which a row past the most calls its latch counts answers with
    /// none), the query held in `round` where its parts lie ([`Round::offer_query`]); or, with no
    /// row left for its Final, be refused ([`FinalHolds::admit`]) before any call is begun: no
    /// callback runs for it, nothing answers it and it is counted.
    ///
    /// # Safety
    /// The caller holds the session's lock, as [`Round::offer_query`] asks: a query arrives from
    /// the session's dispatch.
    pub unsafe fn arrive(
        &self,
        round: &Round<C>,
        begin: impl FnOnce() -> Option<C::Queryable>,
        view: &dyn QueryView,
    ) {
        let generation = self.arriving_on();
        let rid = view.rid();
        if !self.with_holds(|holds| holds.admit(generation, rid)) {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // A row handed nothing gives the hold back, and the query owes its Final as one that
        // reached no queryable.
        let Some(call) = begin() else {
            self.with_holds(|holds| holds.release(generation, rid));
            return;
        };
        // The session's own get is handed to the queryables it matched by the get itself, from its
        // own view, so this notes only which; one past the list waits as a link's query does.
        let call = match <C::LocalAnswers as Presence>::get::<LocalAsking<C>>(&self.local) {
            Some(local) if generation == LOCAL_QUERY => {
                match C::Queues::with(&local.asked, |asked| asked.push(call)) {
                    Ok(()) => return,
                    Err(full) => full.0,
                }
            }
            _ => call,
        };
        // A link's query is held in the round of deliveries, read where its parts lie, and handed
        // to the callback in the order it came among the records; one the round has no room for
        // owes its Final as one that reached no queryable.
        // SAFETY: the caller's contract.
        if !unsafe { round.offer_query(call, view, generation) } {
            self.with_holds(|holds| holds.release(generation, rid));
        }
    }

    /// The queryables the session's own get matched while it was asked, the list left empty; none
    /// where the session's own queryables answer none of its gets.
    pub fn take_asked(&self) -> Asked<C> {
        match <C::LocalAnswers as Presence>::get::<LocalAsking<C>>(&self.local) {
            Some(local) => C::Queues::with(&local.asked, |asked| {
                core::mem::replace(asked, BoundedVec::new_static())
            }),
            None => BoundedVec::new_static(),
        }
    }

    /// The generation a query arriving now belongs to.
    fn arriving_on(&self) -> u64 {
        let asking = <C::LocalAnswers as Presence>::get::<LocalAsking<C>>(&self.local)
            .is_some_and(|local| local.asking.load(Ordering::Acquire));
        if asking {
            LOCAL_QUERY
        } else {
            self.arriving.load(Ordering::Acquire)
        }
    }

    /// Run `ask`, the session handing its own get to its queryables, with what arrives meanwhile
    /// taken as the get's; where the session's own queryables answer none of its gets, `ask` runs
    /// and what arrives is the link's.
    pub fn asking_locally<R>(&self, ask: impl FnOnce() -> R) -> R {
        let Some(local) = <C::LocalAnswers as Presence>::get::<LocalAsking<C>>(&self.local) else {
            return ask();
        };
        local.asking.store(true, Ordering::Release);
        let result = ask();
        local.asking.store(false, Ordering::Release);
        result
    }
}

#[cfg(test)]
mod tests;
