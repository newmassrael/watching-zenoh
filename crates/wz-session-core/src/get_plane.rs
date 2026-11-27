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
//! ([`EveryReplyCaptured`]).
//!
//! A get is one row of the plane's ([`LegRows`]): its callback, minted at its first leg and
//! shared by every leg after it ([`AskedGet`]), and the count of what stands of it, its legs'
//! entries and its asker while it issues them. The get consolidates as one: what the entries of
//! its legs hold back is held in the plane's rows under the get's row, shared by every leg
//! ([`LegHold`]).
//! A leg's end (its Final, its deadline, the loss of its link) is said when its entry is dropped,
//! by a guard the sink owns; the get's end is said by whichever of its legs and its asker stands
//! last, with the request id of the timeout that ended that leg when one did, as zenoh flushes a
//! query at its last Final (`zenoh/src/api/session.rs` @ `if query.nb_final == 0 {`). The
//! deliveries hand it out with no lock held, once the round has handed every reply held before
//! it: what the get held back, the timeout, and then the drop of its callback, which is how a
//! program learns its get is over.
//!
//! The ends wait in a table of the plane's ([`EndedLegs`]), one for each get. An end is written
//! where nothing can be answered (the drop of the last leg's entry), so the row it is written in is
//! set aside where a refusal is answered: at the get's first leg, which a session refuses as a get
//! with no row. A get the session ends itself (cancelled) lets go of what it held and leaves no end
//! waiting ([`GetPlane::forget_end`]).
//!
//! The get's row is held by count: by its asker while it issues the legs, by each leg's entry, by
//! its end, by each record of the round that owes it a reply, and by a thread that captured it. Each
//! is a copy of the row's place ([`LegId`]), so no holder shares the callback by allocation, and the
//! last count given back hands the callback out of the row, to be dropped where no lock is held.
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

/// The end of one get: the request id of the timeout that ended the leg that stood last, which its
/// callback is handed after every reply held before it (none for a get that did not time out), and
/// the row of its callback, of which the end holds a count past the leg or the asker that stood last:
/// whoever takes the end out gives that count back ([`LegHolders::release`]), with no lock held.
pub struct Ended {
    timed_out: Option<RequestId>,
    row: LegId,
}

impl Ended {
    /// The request id of the timeout that ended the get, if one did.
    pub fn timed_out(&self) -> Option<RequestId> {
        self.timed_out
    }

    /// The row of the get's callback, of which the end holds a count.
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
    /// What stands of the get: its legs whose entries are held, and its asker while it issues
    /// them. Changed under the plane's lock alone, a word of its own as the count is.
    standing: AtomicU32,
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
    /// under `fan`, in a free row, held and standing twice, for the get's first leg and its asker:
    /// its place, or `None`, with nothing minted, when every row is held.
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
            holders: AtomicU32::new(2),
            standing: AtomicU32::new(2),
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

    /// One more leg of the get in `leg`'s row, which holds a count of it and stands: `false` when
    /// it names none.
    fn join(&self, leg: LegId) -> bool {
        let Some(row) = self.row(leg) else {
            return false;
        };
        row.holders.fetch_add(1, Ordering::Relaxed);
        row.standing.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// A leg or the asker of the get in `leg`'s row no longer stands: `true` when it stood last,
    /// whose count of the row then passes to the get's end; otherwise its count is given back
    /// here, which is never the last, as what still stands holds one.
    fn leave(&self, leg: LegId) -> bool {
        let Some(row) = self.row(leg) else {
            return false;
        };
        if row.standing.fetch_sub(1, Ordering::Relaxed) == 1 {
            return true;
        }
        let held = row.holders.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(held > 1, "what still stands of a get holds its row");
        false
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

/// The ends of the gets whose last leg or asker went, each to be handed out, and a row set aside for
/// the end of each get still standing (see the module), of the policy `P`: the table bounds the gets
/// the session holds at once.
pub struct EndedLegs<P: Storage> {
    legs: BoundedVec<Ended, { usize::MAX }, P>,
    /// The gets standing whose ends are still to be written, each with a free row set aside.
    owed: usize,
}

impl<P: Storage> EndedLegs<P> {
    /// A table over `legs`: rows an arena lent or a region placed, or a count of them the table
    /// takes at the first get's open.
    pub fn over(legs: BoundedVec<Ended, { usize::MAX }, P>) -> Self {
        Self { legs, owed: 0 }
    }

    /// Set a row aside for the end of one more get, the table's rows taken now where the policy
    /// takes them at its first value: what a get's first leg asks, where a refusal is answered
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
        // Below the table's free rows, which a `usize` counts, so the count never saturates.
        self.owed = self.owed.saturating_add(1);
        true
    }

    /// Give back the row set aside for a get whose first leg was not held after all.
    fn give_back(&mut self) {
        self.owed = self.owed.saturating_sub(1);
    }

    /// A get ended: its count of its row is to be given back. Its row is there: its first leg set
    /// one aside, which no other end or get took since.
    fn note(&mut self, ended: Ended) {
        self.owed = self.owed.saturating_sub(1);
        let kept = self.legs.push(ended);
        debug_assert!(
            kept.is_ok(),
            "an end finds the row its get's first leg set aside"
        );
    }

    /// The end of a get whose count of its row is still to be given back, if any.
    fn take(&mut self) -> Option<Ended> {
        self.legs.pop()
    }

    /// The get in row `row` was ended by the session itself: its end, if its last leg or its asker
    /// wrote one, taken out for that caller to let go of with no lock held, and nothing left to do
    /// for it here.
    fn forget(&mut self, row: LegId) -> Option<Ended> {
        let at = self.legs.iter().position(|ended| ended.row == row)?;
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
    /// The gets that ended, handed out after the replies queued before them.
    ended: Queued<C::Queues, EndedLegs<C::TablePolicy>>,
    /// The replies the gets that consolidate hold to their ends, each tagged with its get's row
    /// ([`LegHold`]): rows of the plane's policy, shared by every get of the session and reached
    /// only from the sinks, under the session's lock.
    replies: <C::Locks as LockFamily>::Lock<HeldReplies<LegId, C::TablePolicy>>,
    /// The gets' callbacks, each held by count (see the module).
    legs: <C::Locks as LockFamily>::Lock<LegRows<C>>,
    /// Whether a thread that holds the session's lock takes the callback the reply it hands the
    /// sinks reaches ([`Self::capture`]), where the plane keeps a capture.
    capture: <C::Captures as Presence>::Table<Capturing<C>>,
}

impl<C: GetCalls> GetPlane<C> {
    /// A plane with nothing ended, its ends waiting in `ended`, the replies its gets hold in
    /// `replies` and its gets' callbacks in `legs`, made in `at` with its locks. `ended` bounds the
    /// gets held at once, a row set aside for each at its first leg.
    ///
    /// # Safety
    /// `at` is valid for writes of a `Self` and aligned for it, and what it held is overwritten
    /// without being dropped. The plane is not moved from `at` until it is dropped there.
    pub unsafe fn init_at(
        at: NonNull<Self>,
        ended: EndedLegs<C::TablePolicy>,
        replies: HeldReplies<LegId, C::TablePolicy>,
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
    /// and standing for its first leg's entry and for its asker, a row of the ends set aside for the
    /// get: its place, or `None`, with nothing minted, when every row is held or set aside or a table
    /// the get needs cannot take its rows, which a session refuses as a table of pending gets with
    /// no row. Asked under the session's lock, so the callback is minted there as it was before it
    /// had a row.
    fn open_leg(
        &self,
        mint: &mut dyn FnMut() -> C::ReplyCallback,
        shows_timestamp: bool,
        fan: Option<C::Fan>,
    ) -> Option<LegId> {
        // The get's end is written by whatever of it stands last, the drop of a leg's entry among
        // them, which can answer no refusal, so its row is set aside here, before the get is kept.
        if !self.ended.with(EndedLegs::set_aside) {
            return None;
        }
        let row = C::Locks::with(&self.legs, |legs| legs.open(mint, shows_timestamp, fan));
        if row.is_none() {
            self.ended.with(EndedLegs::give_back);
        }
        row
    }

    /// One more leg of the get in row `row`, holding a count of it and standing: `false` when
    /// `row` names none.
    fn join_leg(&self, row: LegId) -> bool {
        C::Locks::with(&self.legs, |legs| legs.join(row))
    }

    /// A leg or the asker of the get in row `row` no longer stands; when it stood last the get
    /// ended, its end written with its count of the row and `timed_out`, the timeout that ended
    /// that leg if one did, into the row its first leg set aside.
    fn stand_down(&self, row: LegId, timed_out: Option<RequestId>) {
        if C::Locks::with(&self.legs, |legs| legs.leave(row)) {
            self.ended.with(|ends| ends.note(Ended { timed_out, row }));
        }
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
            self.forget_due(ended.row);
            drop(self.release_row(ended.row));
        }
        drop(C::Locks::with(&self.legs, core::mem::take));
        self.ended
            .with(|ends| *ends = EndedLegs::over(BoundedVec::default()));
    }

    /// Whether a get's end waits to be handed out, read without the lock.
    pub fn ends_pending(&self) -> bool {
        self.ended.is_pending()
    }

    /// The end of a get whose count of its row is still to be given back, taken out, if any.
    pub fn take_end(&self) -> Option<Ended> {
        self.ended.with(EndedLegs::take)
    }

    /// The end of the get in row `row`, decided by the session itself (cancelled), if its last leg
    /// or its asker wrote one: taken out for that caller to let go of with no lock held, and left
    /// for no delivery.
    pub fn forget_end(&self, row: LegId) -> Option<Ended> {
        self.ended.with(|ends| ends.forget(row))
    }

    /// The next reply the get in row `row` held back over its legs, taken out of its row for the
    /// caller to hand to the get's callback with no lock held, at the get's end ([`LegHold`]);
    /// `None` once there is none.
    pub fn take_due(&self, row: LegId) -> Option<HeldReply<LegId, C::TablePolicy>> {
        C::Locks::with(&self.replies, |replies| replies.take(row))
    }

    /// Let go of every reply the get in row `row` holds back: a get ended with nothing handed.
    pub fn forget_due(&self, row: LegId) {
        C::Locks::with(&self.replies, |replies| replies.forget(row));
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
/// the plane's at the first leg ([`Self::leg`]), which every leg after it joins, so every leg of
/// the get hands its replies to the one callback and holds back into the one consolidation. The
/// asker holds a count of the row and stands from the first leg until it is dropped, so a leg that
/// ends while the next is issued never ends the get, nor lets its row be another get's, before the
/// get has issued every leg; dropped last, it writes the get's end. Dropped with no lock held.
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
    /// that count over ([`LegSink::new`]) and stands for the leg until the entry is dropped. At the
    /// first leg the row is opened, the callback `mint` makes in it, showing timestamps when
    /// `shows_timestamp`, of a get asked under `fan`, the asker standing in it too, and a row of
    /// the ends set aside for the get's end; a later leg mints nothing. `None`, with nothing
    /// minted or held, when the rows or the ends have no room for the get, which a session refuses
    /// as a table of pending gets with no row. Asked under the session's lock.
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
        self.row = Some(row);
        Some(row)
    }
}

impl<C: GetCalls> Drop for AskedGet<'_, C> {
    fn drop(&mut self) {
        if let Some(row) = self.row {
            self.plane.stand_down(row, None);
        }
    }
}

/// The end of a leg, said once: when the pending entry that owns it is dropped, with the timeout
/// that ended it, which the entry's sink was told of before its drop. The leg no longer stands; when
/// it stood last the get's end is written.
struct LegEnd<C: GetCalls> {
    timed_out: Option<RequestId>,
    /// The entry's count of the get's row, given back as the leg ends or passed to the get's end.
    row: LegId,
    plane: PlacedRef<GetPlane<C>>,
}

impl<C: GetCalls> Drop for LegEnd<C> {
    fn drop(&mut self) {
        self.plane.stand_down(self.row, self.timed_out);
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

/// The sink of a leg's pending entry, holding a count of the row of its get's callback. A reply
/// the session's own queryables made while the plane captures is the thread's that made it, which
/// hands it to the callback once it lets go of the session ([`GetPlane::capture`]); any other is
/// handed to `U`, the session's round of deliveries ([`Round::offer_reply`]) unless the engine
/// captures every reply ([`EveryReplyCaptured`]). The sink's drop is the leg's end: the
/// Final says nothing more, as the registry drops the entry once its Finals are in, and the leg no
/// longer stands; the timeout of a leg that timed out goes with it, to the get's end when the leg
/// stood last ([`Ended`]). The entry's count of the row is given back there, or passed to the
/// get's end, so the entry's drop, under the session's lock, never lets the callback go.
pub struct LegSink<C: GetCalls, U: UncapturedReplies<C> = PlacedRef<Round<C>>> {
    uncaptured: U,
    end: LegEnd<C>,
}

impl<C: GetCalls, U: UncapturedReplies<C>> LegSink<C, U> {
    /// The sink of a leg of the get in `row`, handing what it is handed to the get's callback, of
    /// which it takes over the count [`AskedGet::leg`] took, and the replies no thread captured to
    /// `uncaptured`.
    ///
    /// # Safety
    /// The sink is handed its replies by the holder of the session's lock alone, as
    /// [`UncapturedReplies::offer`] asks of its caller: the engine registers it in the session's
    /// tables of pending gets, which it reaches under that lock. The owners of the plane and of
    /// what `uncaptured` hands replies to outlive the sink, whose drop writes into the plane, as
    /// [`crate::placed::Placed::share`] asks of every handle.
    pub unsafe fn new(row: LegId, plane: PlacedRef<GetPlane<C>>, uncaptured: U) -> Self {
        Self {
            uncaptured,
            end: LegEnd {
                timed_out: None,
                row,
                plane,
            },
        }
    }

    /// The row of the get's callback, of which the sink holds a count: what names the get the leg
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
}

/// What a consolidating get holds of its replies until its end: rows of the session's
/// ([`GetPlane::take_due`]), tagged with the get's row, so every leg of the get holds back into one
/// consolidation, as zenoh holds a query's replies over every Final
/// (`zenoh/src/api/session.rs` @ `if query.nb_final == 0 {`), and a held reply is copied into
/// the session's memory and takes none of its own. A full table refuses the reply, as a fixed
/// room does, and counts it. A leg's Final or deadline makes nothing due by itself: what the get
/// holds stays in its rows until its end ([`Ended`]), when it is handed to the get's callback from
/// there with no lock held, so none of it is copied into the round of deliveries, which has no
/// place for a part that lies in a row.
/// A get the session ends itself (cancelled) lets go of it ([`GetPlane::forget_due`]).
pub struct LegHold<C: GetCalls> {
    row: LegId,
    plane: PlacedRef<GetPlane<C>>,
}

impl<C: GetCalls> LegHold<C> {
    /// The hold of a leg of the get in `row`, in `plane`'s rows, whose owner outlives the hold
    /// ([`crate::placed::Placed::share`]).
    pub fn new(row: LegId, plane: PlacedRef<GetPlane<C>>) -> Self {
        Self { row, plane }
    }
}

impl<C: GetCalls> ReplyHold for LegHold<C> {
    fn displaces(&self, reply: &dyn ReplyView) -> bool {
        C::Locks::with(&self.plane.replies, |replies| {
            replies.of(self.row).displaces(reply)
        })
    }

    fn hold(&mut self, reply: &dyn ReplyView, whole: bool) -> Result<(), HoldRefused> {
        let row = self.row;
        C::Locks::with(&self.plane.replies, |replies| {
            replies.of(row).hold(reply, whole)
        })
    }

    /// A leg's Final or deadline: the get's held replies stay in its rows for its end, which hands
    /// them to its callback with no lock held ([`GetPlane::take_due`]). Nothing is handed to `each`,
    /// which would hold it in the round of deliveries.
    fn drain(&mut self, _each: &mut dyn FnMut(&dyn ReplyView)) {}
}

#[cfg(test)]
mod tests;
