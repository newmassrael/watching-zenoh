// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The requesting end of the session's gets, as its deliveries hand out what they are owed.
//!
//! What the session's registry hands a leg's pending entry happens under the session's lock, and a
//! callback of the program never runs there, so the entry's sink ([`LegSink`]) hands each reply
//! on to be called after the lock: to the thread that holds the lock, for an answer of the
//! session's own queryables and for every reply where the read hands each record out as it is read
//! ([`PlaneCalls::Captures`]); to the session's round of deliveries ([`crate::round`])
//! otherwise. An engine that captures every reply it hands a get keeps no round for them
//! ([`EveryReplyCaptured`]). What the entry's consolidation held to its end waits in the rows
//! it was held in, due ([`LegHold`]), and what the entry gave up whole in the plane's held table;
//! the leg's end is said when the entry is dropped (its Final, its deadline, its cancellation, the
//! loss of its link) by a guard the sink owns, with the request id of the timeout that ended it
//! when one did. The deliveries hand them out with no lock held, the end once the round has handed
//! every reply held before it and the held table every reply held, as the drop of the leg's
//! callback, which is how a program learns its get is over.
//!
//! The ends wait in a table of the plane's ([`EndedLegs`]). An end is written where nothing can be
//! answered (the drop of its leg's entry), so the row it is written in is set aside where a refusal
//! is answered: at the leg's open, which a session refuses as a get with no row. The table so bounds
//! the legs the session holds at once, a row for each, set aside or written; a leg the session ends
//! itself (cancelled, or never sent) drops its callback where it ends it and leaves no end waiting
//! ([`GetPlane::forget_end`]).
//!
//! A get's callback lies in a row of the plane's ([`LegRows`]), minted at its first leg and shared
//! by every leg after it ([`AskedGet`]), held by count: by the asker while it issues the legs, by
//! each leg's entry, then by that leg's end, by each record of the round that owes it a reply, and
//! by a thread that captured it. Each is a copy of the row's place ([`LegId`]), so no holder shares
//! the callback by allocation, and the last count given back hands the callback out of the row, to
//! be dropped where no lock is held: the get is over once its last leg ended and its asker let go.
//!
//! The plane's tables are of the policy its engine names ([`RoundCalls::TablePolicy`]): rows the
//! session's arena lent or its region placed, or rows each table takes at its first value.
//!
//! [`LegSink`]: crate::get_plane::LegSink
//! [`EveryReplyCaptured`]: crate::get_plane::EveryReplyCaptured
//! [`PlaneCalls::Captures`]: crate::round::PlaneCalls::Captures
//! [`LegHold`]: crate::get_plane::LegHold
//! [`EndedLegs`]: crate::get_plane::EndedLegs
//! [`GetPlane::forget_end`]: crate::get_plane::GetPlane::forget_end
//! [`LegRows`]: crate::get_plane::LegRows
//! [`LegId`]: crate::get_plane::LegId
//! [`AskedGet`]: crate::get_plane::AskedGet
//! [`RoundCalls::TablePolicy`]: crate::round::RoundCalls::TablePolicy

use alloc::collections::VecDeque;
use core::ptr::{addr_of_mut, NonNull};
use core::sync::atomic::Ordering;
// The split `round` uses: the host profile has the native atomics, the `no_std` profile gets the
// critical-section ones for the cores that have none.
#[cfg(not(feature = "no_std"))]
use core::sync::atomic::AtomicU32;
#[cfg(feature = "no_std")]
use portable_atomic::AtomicU32;

use crate::bounded::{BoundedVec, Storage, Taken};
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
    /// What names the fan a get was asked under, which a cancellation ends every leg of.
    type Fan: Copy + PartialEq;

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

/// The place of a get's row in the plane's rows ([`LegRows`]), which each of its legs names. Copied
/// only by a holder of a count of the row, and the row is not given to another get before its last
/// count is given back, so the place names this get's row for as long as any copy of it is used.
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

/// A get's callback in its row, whether the replies it is handed show their timestamps
/// (`entity-timestamp-opt-in`), the fan it was asked under, and how many hold it: the get as its
/// asker holds it, of which each leg's entry in its face's table is the wire's part. The count
/// is changed under the plane's lock alone, and is a word of its own so that a caller that read the
/// row's place under that lock can call the callback after it with no write to the bytes it reads.
pub struct LegRow<C: GetCalls> {
    callback: C::ReplyCallback,
    shows_timestamp: bool,
    fan: Option<C::Fan>,
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

/// The rows of the gets' callbacks, a row for each get whose legs or asker hold it, of the plane's
/// policy; a row is reused once its last count is given back.
pub struct LegRows<C: GetCalls> {
    rows: BoundedVec<Option<LegRow<C>>, { usize::MAX }, C::TablePolicy>,
}

impl<C: GetCalls> Default for LegRows<C> {
    fn default() -> Self {
        Self {
            rows: BoundedVec::default(),
        }
    }
}

impl<C: GetCalls> LegRows<C> {
    /// A table over `rows`: rows an arena lent or a region placed, or a count of them the table
    /// takes at its first leg.
    pub fn over(rows: BoundedVec<Option<LegRow<C>>, { usize::MAX }, C::TablePolicy>) -> Self {
        Self { rows }
    }

    /// Keep the callback `mint` makes, shown timestamps when `shows_timestamp`, of a get asked
    /// under `fan`, in a free row, held once: its place, or `None`, with nothing minted, when
    /// every row is held.
    fn open(
        &mut self,
        mint: &mut dyn FnMut() -> C::ReplyCallback,
        shows_timestamp: bool,
        fan: Option<C::Fan>,
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
            fan,
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

/// The ends of the legs whose entries went, each to be handed out, and a row set aside for the end
/// of each leg still held (see the module), of the policy `P`: the table bounds the legs the session
/// holds at once.
pub struct EndedLegs<P: Storage> {
    legs: BoundedVec<Ended, { usize::MAX }, P>,
    /// The legs held whose ends are still to be written, each with a free row set aside.
    owed: usize,
}

impl<P: Storage> EndedLegs<P> {
    /// A table over `legs`: rows an arena lent or a region placed, or a count of them the table
    /// takes at the first leg's open.
    pub fn over(legs: BoundedVec<Ended, { usize::MAX }, P>) -> Self {
        Self { legs, owed: 0 }
    }

    /// Set a row aside for the end of one more leg, the table's rows taken now where the policy
    /// takes them at its first value: what a leg's open asks, where a refusal is answered
    /// ([`GetPlane::open_leg`]). `false` when every row is written or set aside already.
    fn set_aside(&mut self) -> bool {
        // Only a policy that takes a table's rows at its first value has a room to make; on every
        // other the rows are there already.
        if matches!(P::TAKEN, Taken::AtFirstUse) && !self.legs.make_room() {
            return false;
        }
        if self.legs.free_slots() <= self.owed {
            return false;
        }
        self.owed += 1;
        true
    }

    /// Give back the row set aside for a leg that was not held after all.
    fn give_back(&mut self) {
        self.owed = self.owed.saturating_sub(1);
    }

    /// A leg ended: its count of its get's row is to be given back. Its row is there: its open set
    /// one aside, which no other end or leg took since.
    fn note(&mut self, ended: Ended) {
        self.owed = self.owed.saturating_sub(1);
        let kept = self.legs.push(ended);
        debug_assert!(
            kept.is_ok(),
            "an end finds the row its leg's open set aside"
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

impl<P: Storage> Pending for EndedLegs<P> {
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

/// The capture of a plane that keeps one ([`PlaneCalls::Captures`]), under the engine's lock.
struct Capturing<C: GetCalls>(<C::Locks as LockFamily>::Lock<Capture>);

impl<C: GetCalls> Capturing<C> {
    /// A capture that takes nothing, made in `at` with its lock.
    ///
    /// # Safety
    /// As for [`LockFamily::init_at`], of a `Self`.
    unsafe fn init_at(at: NonNull<Self>) {
        // SAFETY: the caller's contract, for the one field.
        unsafe {
            C::Locks::init_at(
                NonNull::new_unchecked(addr_of_mut!((*at.as_ptr()).0)),
                |capture| capture.write(Capture::Off),
            );
        }
    }
}

/// What the get plane shares between the session's state, the registry's reply sinks and the
/// deliveries.
pub struct GetPlane<C: GetCalls> {
    /// The legs that ended, handed out after the replies queued before them.
    ended: Queued<C::Queues, EndedLegs<C::TablePolicy>>,
    /// The replies the entries of legs held to their ends, each with its leg, in the order they
    /// gave them up: handed to the leg's callback before its end, and before its timeout.
    held: Queued<C::Queues, VecDeque<(u64, InboundReply)>>,
    /// The replies the gets that consolidate hold to their Finals, each tagged with its leg
    /// ([`LegHold`]): rows of the plane's policy, shared by every get of the session and reached
    /// only from the sinks, under the session's lock.
    replies: <C::Locks as LockFamily>::Lock<HeldReplies<u64, C::TablePolicy>>,
    /// The legs' callbacks, each held by count (see the module).
    legs: <C::Locks as LockFamily>::Lock<LegRows<C>>,
    /// Whether a thread that holds the session's lock takes the callback the reply it hands the
    /// sinks reaches ([`Self::capture`]), where the plane keeps a capture.
    capture: <C::Captures as Presence>::Table<Capturing<C>>,
}

impl<C: GetCalls> GetPlane<C> {
    /// A plane with nothing ended, its ends waiting in `ended`, the replies its gets hold in
    /// `replies` and its gets' callbacks in `legs`, made in `at` with its locks. `ended` bounds the
    /// legs held at once, a row set aside for each at its open.
    ///
    /// # Safety
    /// `at` is valid for writes of a `Self` and aligned for it, and what it held is overwritten
    /// without being dropped. The plane is not moved from `at` until it is dropped there.
    pub unsafe fn init_at(
        at: NonNull<Self>,
        ended: EndedLegs<C::TablePolicy>,
        replies: HeldReplies<u64, C::TablePolicy>,
        legs: LegRows<C>,
    ) {
        const {
            assert!(
                <C::TablePolicy as Storage>::ROWS_STAY_APART,
                "a leg's callback is called where its row lies, the rows' lock let go of"
            )
        };
        let at = at.as_ptr();
        // SAFETY: `at` is valid for writes of a `Self` that stays there (the caller's contract),
        // so each field is too, and each is written once.
        unsafe {
            Queued::init_at(NonNull::new_unchecked(addr_of_mut!((*at).ended)), |queue| {
                queue.write(ended)
            });
            Queued::init_at(NonNull::new_unchecked(addr_of_mut!((*at).held)), |queue| {
                queue.write(VecDeque::new())
            });
            C::Locks::init_at(
                NonNull::new_unchecked(addr_of_mut!((*at).replies)),
                |held| held.write(replies),
            );
            C::Locks::init_at(NonNull::new_unchecked(addr_of_mut!((*at).legs)), |rows| {
                rows.write(legs)
            });
            <C::Captures as Presence>::init_at::<Capturing<C>>(
                NonNull::new_unchecked(addr_of_mut!((*at).capture)),
                |capturing| Capturing::init_at(capturing),
            );
        }
    }

    /// Take out, instead of queueing, the callback of the leg the replies handed to the sinks from
    /// here on reach, until [`Self::captured`]: how the thread that makes an answer of the
    /// session's own queryables, or the read that hands a peer's reply out as it is read, holding
    /// the session's lock, learns what to call to hand it the reply itself once it lets go. A plane
    /// that keeps no capture ([`PlaneCalls::Captures`]) captures nothing.
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

    /// The capture, where the plane keeps one.
    fn capturing(&self) -> Option<&Capturing<C>> {
        <C::Captures as Presence>::get::<Capturing<C>>(&self.capture)
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

    /// Keep the callback `mint` makes, of a get asked under `fan`, in a row of the plane's, held
    /// once, for its first leg's entry, a row of the ends set aside for that leg: its place, or
    /// `None`, with nothing minted, when every row is held or set aside or a table the leg needs
    /// cannot take its rows, which a session refuses as a table of pending gets with no row. Asked
    /// under the session's lock, so the callback is minted there as it was before it had a row.
    fn open_leg(
        &self,
        mint: &mut dyn FnMut() -> C::ReplyCallback,
        shows_timestamp: bool,
        fan: Option<C::Fan>,
    ) -> Option<LegId> {
        // The leg's end is written by the drop of its entry, which can answer no refusal, so its
        // row is set aside here, before the leg is kept.
        if !self.ended.with(EndedLegs::set_aside) {
            return None;
        }
        let row = C::Locks::with(&self.legs, |legs| legs.open(mint, shows_timestamp, fan));
        if row.is_none() {
            self.ended.with(EndedLegs::give_back);
        }
        row
    }

    /// One more count of the get's row `row`, for a later leg's entry, a row of the ends set aside
    /// for that leg: `false`, with nothing held, when every row of the ends is written or set aside,
    /// or `row` names none.
    fn join_leg(&self, row: LegId) -> bool {
        if !self.ended.with(EndedLegs::set_aside) {
            return false;
        }
        let held = self.hold_row(row);
        if !held {
            self.ended.with(EndedLegs::give_back);
        }
        held
    }

    /// Whether the row `leg` names is the row of a get asked under `fan`: what a cancellation of
    /// the fan asks of each pending entry's sink to find the legs it ends ([`LegSink::row`]).
    pub fn in_fan(&self, leg: LegId, fan: C::Fan) -> bool {
        C::Locks::with(&self.legs, |legs| {
            legs.row(leg).is_some_and(|row| row.fan == Some(fan))
        })
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
    pub fn take_due(&self, leg: u64) -> Option<HeldReply<u64, C::TablePolicy>> {
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
            // and the rows lie apart from the table and never move (`Storage::ROWS_STAY_APART`,
            // asserted of the plane's policy where it is made): it lies there until that count is
            // given back. The callback is read through a shared borrow and called with no lock held,
            // and the one word of the row the lock's holders write is atomic.
            unsafe { row.as_ref() }.call(reply);
        }
    }

    fn release(&self, leg: LegId) -> Option<C::ReplyCallback> {
        self.release_row(leg)
    }
}

/// A get as its asker holds it while it issues the get's legs: its callback, minted into a row of
/// the plane's at the first leg ([`Self::leg`]), and a count of that row for each leg after it, so
/// every leg of the get hands its replies to the one callback. The asker holds a count of its own
/// from the first leg until it is dropped, so a leg that ends while the next is issued never lets
/// the callback go, nor its row be another get's, before the get has issued every leg. Dropped with
/// no lock held, as its count may be the last.
pub struct AskedGet<'p, C: GetCalls> {
    plane: &'p GetPlane<C>,
    /// The get's row, once its first leg opened it, of which the asker holds a count.
    row: Option<LegId>,
}

impl<'p, C: GetCalls> AskedGet<'p, C> {
    /// A get of `plane`'s with no leg yet.
    pub fn new(plane: &'p GetPlane<C>) -> Self {
        Self { plane, row: None }
    }

    /// The row of the get's callback, with a count of it for one more leg's entry, whose sink takes
    /// that count over ([`LegSink::new`]), and a row of the ends set aside for the leg's end. At the
    /// first leg the row is opened, the callback `mint` makes in it, showing timestamps when
    /// `shows_timestamp`, of a get asked under `fan`, and the asker takes its own count; a later
    /// leg mints nothing. `None`, with nothing minted or held, when the rows or the ends have no
    /// room for the leg, which a session refuses as a table of pending gets with no row. Asked
    /// under the session's lock.
    pub fn leg(
        &mut self,
        mint: &mut dyn FnMut() -> C::ReplyCallback,
        shows_timestamp: bool,
        fan: Option<C::Fan>,
    ) -> Option<LegId> {
        if let Some(row) = self.row {
            return self.plane.join_leg(row).then_some(row);
        }
        let row = self.plane.open_leg(mint, shows_timestamp, fan)?;
        // The asker's own count, of a row just opened under the same lock, so it is there.
        if self.plane.hold_row(row) {
            self.row = Some(row);
        }
        Some(row)
    }
}

impl<C: GetCalls> Drop for AskedGet<'_, C> {
    fn drop(&mut self) {
        if let Some(row) = self.row {
            drop(self.plane.release_row(row));
        }
    }
}

/// The end of a leg, said once: when the pending entry that owns it is dropped, with the timeout
/// that ended it, which the entry's sink was told of before its drop.
struct LegEnd<C: GetCalls> {
    leg: u64,
    timed_out: Option<RequestId>,
    /// The entry's count of the leg's row, which the end holds from the entry's drop on.
    row: LegId,
    plane: PlacedRef<GetPlane<C>>,
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

/// Where a leg's sink hands a reply no thread captured ([`GetPlane::capture`]), for the leg's
/// callback to be handed it once the session's lock is let go of.
pub trait UncapturedReplies<C: GetCalls> {
    /// Hand `reply` on for the callback in row `leg`.
    ///
    /// # Safety
    /// The caller holds the session's lock, as [`Round::offer_reply`] asks of its caller.
    unsafe fn offer(&self, leg: LegId, reply: &dyn ReplyView);
}

/// The session's round of deliveries holds the reply for the leg's callback.
impl<C: GetCalls> UncapturedReplies<C> for PlacedRef<Round<C>> {
    unsafe fn offer(&self, leg: LegId, reply: &dyn ReplyView) {
        // SAFETY: the caller holds the session's lock, as this trait's contract says.
        unsafe { self.offer_reply(leg, reply) };
    }
}

/// Where a leg's sink hands a reply no thread captured, for an engine that captures every reply
/// it hands its gets, each under a capture of its own: the read that hands each record out as it
/// is read captures the get a peer's reply answers, and the thread that answers a get of the
/// session's own queryables the get its answer reaches. A reply reaches one get, so each capture
/// takes it, and the sink keeps no handle of a round, which such an engine need not keep. A reply
/// handed to a sink outside a capture is a defect of the engine: a debug build stops there.
#[derive(Clone, Copy, Debug, Default)]
pub struct EveryReplyCaptured;

impl<C: GetCalls> UncapturedReplies<C> for EveryReplyCaptured {
    unsafe fn offer(&self, _leg: LegId, _reply: &dyn ReplyView) {
        debug_assert!(false, "a reply reached a leg's sink outside a capture");
    }
}

/// The sink of leg `leg`'s pending entry, holding a count of the row of the leg's callback. A
/// reply the session's own queryables made while the plane captures is the thread's that made it,
/// which hands it to the callback once it lets go of the session ([`GetPlane::capture`]); any
/// other is handed to `U`, the session's round of deliveries ([`Round::offer_reply`]) unless
/// the engine captures every reply ([`EveryReplyCaptured`]).
/// What the entry's consolidation held to its end waits in the plane's held table
/// ([`GetPlane::take_held`]), and the timeout of a leg that timed out in the leg's end
/// ([`Ended`]). The sink's drop is the leg's end: the Final says nothing more, as the registry
/// drops the entry once its Finals are in. The end holds the entry's count of the row past the
/// entry ([`Ended`]), so the entry's drop, under the session's lock, never lets the callback go.
pub struct LegSink<C: GetCalls, U: UncapturedReplies<C> = PlacedRef<Round<C>>> {
    leg: u64,
    uncaptured: U,
    end: LegEnd<C>,
}

impl<C: GetCalls, U: UncapturedReplies<C>> LegSink<C, U> {
    /// The sink of leg `leg`, handing what it is handed to the callback in `row`, of which it
    /// takes over the count [`AskedGet::leg`] took, and the replies no thread captured to
    /// `uncaptured`.
    ///
    /// # Safety
    /// The sink is handed its replies by the holder of the session's lock alone, as
    /// [`UncapturedReplies::offer`] asks of its caller: the engine registers it in the session's
    /// tables of pending gets, which it reaches under that lock. The owners of the plane and of
    /// what `uncaptured` hands replies to outlive the sink, whose drop writes its end into the
    /// plane, as [`crate::placed::Placed::share`] asks of every handle.
    pub unsafe fn new(leg: u64, row: LegId, plane: PlacedRef<GetPlane<C>>, uncaptured: U) -> Self {
        Self {
            leg,
            uncaptured,
            end: LegEnd {
                leg,
                timed_out: None,
                row,
                plane,
            },
        }
    }

    /// The leg the sink is the entry's of.
    pub fn leg(&self) -> u64 {
        self.leg
    }

    /// The row of the leg's callback, of which the sink holds a count: what names the get the leg
    /// belongs to ([`GetPlane::in_fan`]).
    pub fn row(&self) -> LegId {
        self.end.row
    }
}

impl<C: GetCalls, U: UncapturedReplies<C>> ReplySink for LegSink<C, U> {
    fn on_reply(&mut self, reply: &dyn ReplyView) {
        if self.end.plane.captures(self.end.row) {
            return;
        }
        // SAFETY: the contract of `Self::new`: the sink is handed a reply under the session's
        // lock.
        unsafe { self.uncaptured.offer(self.end.row, reply) };
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
    plane: PlacedRef<GetPlane<C>>,
    /// Whether the get's end made what it holds due.
    due: bool,
}

impl<C: GetCalls> LegHold<C> {
    /// The hold of leg `leg` in `plane`'s rows, whose owner outlives the hold, whose drop lets go
    /// of what it still holds there ([`crate::placed::Placed::share`]).
    pub fn new(leg: u64, plane: PlacedRef<GetPlane<C>>) -> Self {
        Self {
            leg,
            plane,
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
