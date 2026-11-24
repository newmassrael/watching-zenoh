// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The requesting end of the session's gets, as its deliveries hand out what they are owed.
//!
//! What the session's registry hands a leg's pending entry happens under the session's lock, and a
//! callback of the program never runs there, so the entry's sink ([`LegSink`]) hands each reply
//! on to be called after the lock: to the thread that made it, for an answer of the session's own
//! queryables ([`PlaneCalls::LocalAnswers`]); to the session's round of deliveries
//! ([`crate::round`]) otherwise. What the entry's consolidation held to its end waits in the rows
//! it was held in, due ([`LegHold`]), and what the entry gave up whole in the plane's held table;
//! the leg's end is said when the entry is dropped (its Final, its deadline, its cancellation, the
//! loss of its link) by a guard the sink owns, with the request id of the timeout that ended it
//! when one did. The deliveries hand them out with no lock held, the end once the round has handed
//! every reply held before it and the held table every reply held, as the drop of the leg's
//! callback, which is how a program learns its get is over.
//!
//! The ends wait in a table the session's arena lent ([`EndedLegs`]), a row for each get the
//! session's tables of pending gets can hold. A leg ends when its row in those tables goes, and the
//! deliveries that follow every step take every end out, so the ends waiting never outnumber the
//! rows; a leg the session ends itself (cancelled, or never sent) drops its callback where it ends
//! it and leaves no end waiting ([`GetPlane::forget_end`]).
//!
//! A leg's callback lies in a row of the plane's ([`LegRows`]), lent by the arena too, held by
//! count: by the leg's entry, then by its end, by each record of the round that owes it a reply,
//! and by a thread that captured it. Each is a copy of the row's place ([`LegId`]), so no holder
//! shares the callback by allocation, and the last count given back hands the callback out of the
//! row, to be dropped where no lock is held.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;
// The split `round` uses: the host profile has the native atomics, the `no_std` profile gets the
// critical-section ones for the cores that have none.
#[cfg(not(feature = "no_std"))]
use core::sync::atomic::AtomicU32;
#[cfg(feature = "no_std")]
use portable_atomic::AtomicU32;

use crate::bounded::{BoundedVec, Lent};
use crate::placed::PlacedRef;
use crate::plane_lock::{LockFamily, Pending, Queued};
use crate::reply::InboundReply;
use crate::reply_hold::{HeldReplies, HeldReply, HoldRefused, ReplyHold};
use crate::reply_sink::{ReplySink, ReplyView};
use crate::round::{LegHolders, PlaneCalls, Round};
use crate::session_tables::Presence;
use crate::timestamp_visibility::HiddenReplyTimestamp;
use crate::wire_id::RequestId;

/// What the get plane is made of in an engine's own types, beyond what its planes share: a leg is
/// the place of its callback's row ([`LegId`]), and the engine names how a callback is called.
/// Whether the session's own queryables answer its gets, which takes the callback of the leg the
/// answer reaches ([`GetPlane::capture`]), and the locks of the plane's queues ([`Queued`]) are
/// the planes' ([`PlaneCalls`]).
pub trait GetCalls: PlaneCalls<Leg = LegId> {
    /// Hand `reply` to `callback`.
    fn call(callback: &Self::ReplyCallback, reply: &dyn ReplyView);

    /// Whether the calling thread holds a session's lock, where the engine can tell: a debug
    /// build checks that no leg's callback is let go of there.
    fn holds_a_session() -> bool;
}

/// The end of one leg: the leg, the request id of the timeout that ended it, which its callback is
/// handed after every reply held before it (none for a leg that did not time out), and the row of
/// its callback, of which the end holds a count past the entry that owned it: whoever takes the end
/// out gives that count back ([`LegHolders::release`]), with no lock held.
pub struct Ended {
    leg: u64,
    timed_out: Option<RequestId>,
    row: LegId,
}

impl Ended {
    /// The leg that ended.
    pub fn leg(&self) -> u64 {
        self.leg
    }

    /// The request id of the timeout that ended the leg, if one did.
    pub fn timed_out(&self) -> Option<RequestId> {
        self.timed_out
    }

    /// The row of the leg's callback, of which the end holds a count.
    pub fn row(&self) -> LegId {
        self.row
    }
}

/// The place of a leg's row in the plane's rows ([`LegRows`]). Copied only by a holder of a count
/// of the row, and the row is not given to another leg before its last count is given back, so
/// the place names this leg's row for as long as any copy of it is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegId(u32);

impl LegId {
    /// The first row's place: what a test of a round holds a leg of its own by.
    pub const FIRST: Self = Self(0);

    /// The row's index in its table; past every table where the address space is narrower than
    /// an id, which names no row then.
    fn at(self) -> usize {
        usize::try_from(self.0).unwrap_or(usize::MAX)
    }
}

/// A leg's callback in its row, whether the replies it is handed show their timestamps
/// (`entity-timestamp-opt-in`), and how many hold it. The count is changed under the plane's lock
/// alone, and is a word of its own so that a caller that read the row's place under that lock can
/// call the callback after it with no write to the bytes it reads.
pub struct LegRow<C: GetCalls> {
    callback: C::ReplyCallback,
    shows_timestamp: bool,
    holders: AtomicU32,
}

impl<C: GetCalls> LegRow<C> {
    /// Hand `reply` to the callback, its timestamp hidden unless the leg shows it.
    fn call(&self, reply: &dyn ReplyView) {
        if self.shows_timestamp {
            C::call(&self.callback, reply);
        } else {
            C::call(&self.callback, &HiddenReplyTimestamp(reply));
        }
    }
}

/// The rows of the legs' callbacks, a row for each get the session's tables of pending gets hold at
/// once, lent by the session's arena; a row is reused once its last count is given back.
pub struct LegRows<C: GetCalls> {
    rows: BoundedVec<Option<LegRow<C>>, { usize::MAX }, Lent>,
}

impl<C: GetCalls> Default for LegRows<C> {
    fn default() -> Self {
        Self {
            rows: BoundedVec::default(),
        }
    }
}

impl<C: GetCalls> LegRows<C> {
    /// A table over the rows `rows` an arena lent.
    pub fn over(rows: BoundedVec<Option<LegRow<C>>, { usize::MAX }, Lent>) -> Self {
        Self { rows }
    }

    /// Keep the callback `mint` makes, shown timestamps when `shows_timestamp`, in a free row,
    /// held once: its place, or `None`, with nothing minted, when every row is held.
    fn open(
        &mut self,
        mint: &mut dyn FnMut() -> C::ReplyCallback,
        shows_timestamp: bool,
    ) -> Option<LegId> {
        let at = match self.rows.iter().position(Option::is_none) {
            Some(at) => at,
            None => {
                self.rows.push(None).ok()?;
                self.rows.len().saturating_sub(1)
            }
        };
        let id = LegId(u32::try_from(at).ok()?);
        let slot = self.rows.get_mut(at)?;
        *slot = Some(LegRow {
            callback: mint(),
            shows_timestamp,
            holders: AtomicU32::new(1),
        });
        Some(id)
    }

    /// The row `leg` names, while it holds one.
    fn row(&self, leg: LegId) -> Option<&LegRow<C>> {
        self.rows.get(leg.at())?.as_ref()
    }

    /// One more count of `leg`'s row: `false` when it names none.
    fn hold(&self, leg: LegId) -> bool {
        let Some(row) = self.row(leg) else {
            return false;
        };
        row.holders.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Give back one count of `leg`'s row: the callback, taken out of the row, when it was the
    /// last count, for the caller to drop with no lock held.
    fn release(&mut self, leg: LegId) -> Option<C::ReplyCallback> {
        let last = self.row(leg)?.holders.fetch_sub(1, Ordering::Relaxed) == 1;
        if !last {
            return None;
        }
        let row = self.rows.get_mut(leg.at())?.take()?;
        Some(row.callback)
    }
}

/// The legs whose entries went and whose callbacks are still to be dropped, a row for each get the
/// session's tables of pending gets hold (see the module).
pub struct EndedLegs {
    legs: BoundedVec<Ended, { usize::MAX }, Lent>,
}

impl EndedLegs {
    /// A table over the rows `legs` an arena lent.
    pub fn over(legs: BoundedVec<Ended, { usize::MAX }, Lent>) -> Self {
        Self { legs }
    }

    /// A leg ended: its callback is to be dropped.
    fn note(&mut self, ended: Ended) {
        let kept = self.legs.push(ended);
        debug_assert!(
            kept.is_ok(),
            "the ends waiting outnumber the rows of the tables of pending gets"
        );
    }

    /// The end of a leg whose callback is still to be dropped, if any.
    fn take(&mut self) -> Option<Ended> {
        self.legs.pop()
    }

    /// Leg `leg`'s end was decided where it ended: its end, taken out for that caller to let go
    /// of with no lock held, and nothing left to do for it here.
    fn forget(&mut self, leg: u64) -> Option<Ended> {
        let at = self.legs.iter().position(|ended| ended.leg == leg)?;
        Some(self.legs.remove(at))
    }
}

impl Pending for EndedLegs {
    fn is_pending(&self) -> bool {
        !self.legs.is_empty()
    }
}

/// Whether a thread that holds the session's lock takes the callback the answer it makes reaches
/// ([`GetPlane::capture`]): the leg it reached first, once one did.
enum Capture {
    Off,
    On(Option<LegId>),
}

/// The capture of a plane whose session's own queryables answer its gets, under the engine's lock.
struct Capturing<C: GetCalls>(<C::Locks as LockFamily>::Lock<Capture>);

impl<C: GetCalls> Default for Capturing<C> {
    fn default() -> Self {
        Self(C::Locks::new(Capture::Off))
    }
}

/// What the get plane shares between the session's state, the registry's reply sinks and the
/// deliveries.
pub struct GetPlane<C: GetCalls> {
    /// The legs that ended, handed out after the replies queued before them.
    ended: Queued<C::Queues, EndedLegs>,
    /// The replies the entries of legs held to their ends, each with its leg, in the order they
    /// gave them up: handed to the leg's callback before its end, and before its timeout.
    held: Queued<C::Queues, VecDeque<(u64, InboundReply)>>,
    /// The replies the gets that consolidate hold to their Finals, each tagged with its leg
    /// ([`LegHold`]): rows the session's arena lent, shared by every get of the session and
    /// reached only from the sinks, under the session's lock.
    replies: <C::Locks as LockFamily>::Lock<HeldReplies<u64, Lent>>,
    /// The legs' callbacks, each held by count (see the module).
    legs: <C::Locks as LockFamily>::Lock<LegRows<C>>,
    /// Whether a thread that holds the session's lock takes the callback the answer it makes
    /// reaches ([`Self::capture`]), where the session's own queryables answer its gets.
    capture: <C::LocalAnswers as Presence>::Table<Capturing<C>>,
}

impl<C: GetCalls> GetPlane<C> {
    /// A plane with nothing ended, its ends waiting in `ended`, the replies its gets hold in
    /// `replies` and its legs' callbacks in `legs`.
    pub fn new(ended: EndedLegs, replies: HeldReplies<u64, Lent>, legs: LegRows<C>) -> Self {
        Self {
            ended: Queued::new(ended),
            held: Queued::new(VecDeque::new()),
            replies: C::Locks::new(replies),
            legs: C::Locks::new(legs),
            capture: <C::LocalAnswers as Presence>::empty::<Capturing<C>>(),
        }
    }

    /// Take out, instead of queueing, the callback of the leg the replies handed to the sinks from
    /// here on reach, until [`Self::captured`]: how the thread that makes an answer of the
    /// session's own queryables, holding the session's lock, learns what to call to hand it the
    /// answer itself once it lets go. A plane whose session answers none of its own gets captures
    /// nothing.
    pub fn capture(&self) {
        if let Some(capturing) = self.capturing() {
            C::Locks::with(&capturing.0, |capture| *capture = Capture::On(None));
        }
    }

    /// The row of the callback the replies since [`Self::capture`] reached, with a count of it the
    /// caller gives back once it handed the answer; what is handed after this is queued again.
    pub fn captured(&self) -> Option<LegId> {
        let capturing = self.capturing()?;
        C::Locks::with(&capturing.0, |capture| {
            match core::mem::replace(capture, Capture::Off) {
                Capture::On(found) => found,
                Capture::Off => None,
            }
        })
    }

    /// The capture, where the session's own queryables answer its gets.
    fn capturing(&self) -> Option<&Capturing<C>> {
        <C::LocalAnswers as Presence>::get::<Capturing<C>>(&self.capture)
    }

    /// Whether leg `leg`'s callback was taken out for the thread that captures, with a count of
    /// its row: one leg's, the first a reply reached. A second leg reached under the same capture
    /// is queued, so nothing is lost.
    fn captures(&self, leg: LegId) -> bool {
        let Some(capturing) = self.capturing() else {
            return false;
        };
        C::Locks::with(&capturing.0, |capture| match capture {
            Capture::On(slot) if slot.is_none() && self.hold_row(leg) => {
                *slot = Some(leg);
                true
            }
            _ => false,
        })
    }

    /// Keep the callback `mint` makes in a row of the plane's, held once, for the leg's entry:
    /// its place, or `None`, with nothing minted, when every row is held, which a session refuses
    /// as a table of pending gets with no row. Asked under the session's lock, so the callback is
    /// minted there as it was before it had a row.
    pub fn open_leg(
        &self,
        mint: &mut dyn FnMut() -> C::ReplyCallback,
        shows_timestamp: bool,
    ) -> Option<LegId> {
        C::Locks::with(&self.legs, |legs| legs.open(mint, shows_timestamp))
    }

    /// Let go of every end, every held reply and every leg's row before the arena that lent them
    /// is given back: what the session's last handle does, once its round gave back the counts its
    /// records held and its entries are gone. A callback still in a row is dropped here.
    pub fn let_go(&self) {
        while let Some(ended) = self.take_end() {
            self.forget_due(ended.leg);
            drop(self.release_row(ended.row));
        }
        drop(self.take_all_held());
        drop(C::Locks::with(&self.legs, core::mem::take));
        self.ended
            .with(|ends| *ends = EndedLegs::over(BoundedVec::default()));
    }

    /// Whether a leg's end waits to be handed out, read without the lock.
    pub fn ends_pending(&self) -> bool {
        self.ended.is_pending()
    }

    /// The end of a leg whose callback is still to be dropped, taken out, if any.
    pub fn take_end(&self) -> Option<Ended> {
        self.ended.with(EndedLegs::take)
    }

    /// Leg `leg`'s end, decided where it ended (cancelled, or never sent): taken out for that
    /// caller to let go of with no lock held, and left for no delivery.
    pub fn forget_end(&self, leg: u64) -> Option<Ended> {
        self.ended.with(|ends| ends.forget(leg))
    }

    /// Keep `reply`, held to its end, for leg `leg`, after what it holds already.
    fn keep_held(&self, leg: u64, reply: InboundReply) {
        self.held.with(|held| held.push_back((leg, reply)));
    }

    /// The first reply leg `leg`'s entry held to its end, taken out; `None` once there is
    /// nothing. Read without the lock while nothing is held.
    pub fn take_held(&self, leg: u64) -> Option<InboundReply> {
        if !self.held.is_pending() {
            return None;
        }
        self.held.with(|held| {
            let at = held.iter().position(|(of, _)| *of == leg)?;
            held.remove(at).map(|(_, held)| held)
        })
    }

    /// Everything held for every leg, taken out: the session is closed.
    pub fn take_all_held(&self) -> VecDeque<(u64, InboundReply)> {
        self.held.with(core::mem::take)
    }

    /// The next reply leg `leg`'s consolidation made due at its end, taken out of its row for the
    /// caller to hand to the leg's callback with no lock held ([`LegHold`]); `None` once there is
    /// none.
    pub fn take_due(&self, leg: u64) -> Option<HeldReply<u64, Lent>> {
        C::Locks::with(&self.replies, |replies| replies.take(leg))
    }

    /// Let go of every reply leg `leg` holds, due or not: a leg ended with nothing handed.
    pub fn forget_due(&self, leg: u64) {
        C::Locks::with(&self.replies, |replies| replies.forget(leg));
    }

    /// [`LegHolders::hold`], which the plane's own capture takes too.
    fn hold_row(&self, leg: LegId) -> bool {
        C::Locks::with(&self.legs, |legs| legs.hold(leg))
    }

    /// [`LegHolders::release`], which the plane's own let-go gives back too.
    fn release_row(&self, leg: LegId) -> Option<C::ReplyCallback> {
        let callback = C::Locks::with(&self.legs, |legs| legs.release(leg));
        debug_assert!(
            callback.is_none() || !C::holds_a_session(),
            "a leg's callback is let go of under a session's lock"
        );
        callback
    }
}

impl<C: GetCalls> LegHolders<C> for GetPlane<C>
where
    Self: Send + Sync,
{
    fn hold(&self, leg: LegId) -> bool {
        self.hold_row(leg)
    }

    fn call(&self, leg: LegId, reply: &dyn ReplyView) {
        let row = C::Locks::with(&self.legs, |legs| legs.row(leg).map(NonNull::from));
        if let Some(row) = row {
            // SAFETY: the caller holds a count of the row, so it is not taken out of its place,
            // and a lent table never moves its rows: it lies there until that count is given
            // back. The callback is read through a shared borrow and called with no lock held,
            // and the one word of the row the lock's holders write is atomic.
            unsafe { row.as_ref() }.call(reply);
        }
    }

    fn release(&self, leg: LegId) -> Option<C::ReplyCallback> {
        self.release_row(leg)
    }
}

/// The end of a leg, said once: when the pending entry that owns it is dropped, with the timeout
/// that ended it, which the entry's sink was told of before its drop.
struct LegEnd<C: GetCalls> {
    leg: u64,
    timed_out: Option<RequestId>,
    /// The entry's count of the leg's row, which the end holds from the entry's drop on.
    row: LegId,
    plane: Arc<GetPlane<C>>,
}

impl<C: GetCalls> Drop for LegEnd<C> {
    fn drop(&mut self) {
        let ended = Ended {
            leg: self.leg,
            timed_out: self.timed_out,
            row: self.row,
        };
        self.plane.ended.with(|ends| ends.note(ended));
    }
}

/// The sink of leg `leg`'s pending entry, holding a count of the row of the leg's callback. A
/// reply the session's own queryables made while the plane captures is the thread's that made it,
/// which hands it to the callback once it lets go of the session ([`GetPlane::capture`]); any
/// other is held for the callback in the session's round of deliveries ([`Round::offer_reply`]).
/// What the entry's consolidation held to its end waits in the plane's held table
/// ([`GetPlane::take_held`]), and the timeout of a leg that timed out in the leg's end
/// ([`Ended`]). The sink's drop is the leg's end: the Final says nothing more, as the registry
/// drops the entry once its Finals are in. The end holds the entry's count of the row past the
/// entry ([`Ended`]), so the entry's drop, under the session's lock, never lets the callback go.
pub struct LegSink<C: GetCalls> {
    leg: u64,
    round: PlacedRef<Round<C>>,
    end: LegEnd<C>,
}

impl<C: GetCalls> LegSink<C> {
    /// The sink of leg `leg`, handing what it is handed to the callback in `row`, of which it
    /// takes over the count [`GetPlane::open_leg`] took, and the replies the round holds for it
    /// to the session's round `round`.
    ///
    /// # Safety
    /// The sink is handed its replies by the holder of the session's lock alone, as
    /// [`Round::offer_reply`] asks of its caller: the engine registers it in the session's tables
    /// of pending gets, which it reaches under that lock. The round's owner outlives the sink, as
    /// [`crate::placed::Placed::share`] asks of every handle.
    pub unsafe fn new(
        leg: u64,
        row: LegId,
        plane: &Arc<GetPlane<C>>,
        round: PlacedRef<Round<C>>,
    ) -> Self {
        Self {
            leg,
            round,
            end: LegEnd {
                leg,
                timed_out: None,
                row,
                plane: Arc::clone(plane),
            },
        }
    }
}

impl<C: GetCalls> ReplySink for LegSink<C> {
    fn on_reply(&mut self, reply: &dyn ReplyView) {
        if self.end.plane.captures(self.end.row) {
            return;
        }
        // SAFETY: the contract of `Self::new`: the sink is handed a reply under the session's
        // lock.
        unsafe { self.round.offer_reply(self.end.row, reply) };
    }

    fn on_final(&mut self, _rid: RequestId) {}

    fn on_timeout(&mut self, rid: RequestId) {
        self.end.timed_out = Some(rid);
    }

    fn on_reply_owned(&mut self, reply: InboundReply) {
        self.end.plane.keep_held(self.leg, reply);
    }
}

/// What a consolidating get holds of its replies until its Final: rows of the session's
/// ([`GetPlane::take_due`]), tagged with the leg, so a held reply is copied into the session's
/// memory and takes none of its own. A full table refuses the reply, as a fixed room does, and
/// counts it. At the get's end (its Final, or its deadline) the replies it held are DUE: they stay
/// in their rows and are handed to the leg's callback from there once the session's lock is let go,
/// before the leg's end, so none of them is copied into the round of deliveries, which has no place
/// for a part that lies in a row. A leg that ends with replies held and none due (cancelled, or its
/// face gone) lets them go.
pub struct LegHold<C: GetCalls> {
    leg: u64,
    plane: Arc<GetPlane<C>>,
    /// Whether the get's end made what it holds due.
    due: bool,
}

impl<C: GetCalls> LegHold<C> {
    /// The hold of leg `leg` in `plane`'s rows.
    pub fn new(leg: u64, plane: &Arc<GetPlane<C>>) -> Self {
        Self {
            leg,
            plane: Arc::clone(plane),
            due: false,
        }
    }
}

impl<C: GetCalls> ReplyHold for LegHold<C> {
    fn displaces(&self, reply: &dyn ReplyView) -> bool {
        C::Locks::with(&self.plane.replies, |replies| {
            replies.of(self.leg).displaces(reply)
        })
    }

    fn hold(&mut self, reply: &dyn ReplyView, whole: bool) -> Result<(), HoldRefused> {
        let leg = self.leg;
        C::Locks::with(&self.plane.replies, |replies| {
            replies.of(leg).hold(reply, whole)
        })
    }

    /// The get ended: what it holds is due, and stays in its rows for the leg's callback to be
    /// handed it with no lock held ([`GetPlane::take_due`]). Nothing is handed to `each`, which
    /// would hold it in the round of deliveries.
    fn drain(&mut self, _each: &mut dyn FnMut(&dyn ReplyView)) {
        self.due = true;
    }
}

impl<C: GetCalls> Drop for LegHold<C> {
    fn drop(&mut self) {
        // What is due waits for the leg's end; what the get held with none due goes with it.
        if !self.due {
            let leg = self.leg;
            C::Locks::with(&self.plane.replies, |replies| replies.forget(leg));
        }
    }
}

#[cfg(test)]
mod tests;
