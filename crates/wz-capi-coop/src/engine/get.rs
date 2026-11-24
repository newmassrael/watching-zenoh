// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The requesting end of a query on the cooperative engine.
//!
//! A get is asked of the one peer the session's link reaches, so it has one leg and owes one
//! Final; the session asks no queryable of its own, as zenoh-pico's default build asks none
//! (`Z_FEATURE_LOCAL_QUERYABLE` 0). Its pending entry is session-core's, registered with the
//! observer under the request id the link's actions allocate, with the deadline, the accepted
//! reply keys and the consolidation `QueryOptions` reads, as the tokio engine registers its own.
//!
//! What the observer hands the entry's sink happens under the session's lock, and a C callback
//! never runs there (decision D8), so the sink ([`LegSink`]) hands each reply on to be called
//! after the lock: to the thread that made it, for an answer of the session's own queryables; to
//! the session's round of deliveries otherwise (`crate::round`), read where it lies in a datagram a
//! link lends. What the entry's consolidation held to its end waits in the rows it was held in,
//! due, and what the entry gave up whole in the plane's held table, and the leg's END is said when
//! the entry is dropped (its Final, its deadline, its cancellation, the loss of its link) by a
//! guard the sink owns, with the request id of the
//! timeout that ended it when one did. The deliveries hand them out with no lock held, the end once
//! the round has handed every reply held before it and the held table every reply held, as the
//! drop of the leg's callback, which is how a C program learns its get is over.
//!
//! The ends wait in a table the session's arena lent ([`EndedLegs`]), a row for each get the
//! session's tables of pending gets can hold. A leg ends when its row in those tables goes, and the
//! deliveries that follow every step take every end out, so the ends waiting never outnumber the
//! rows; a leg the session ends itself (cancelled, or never sent) drops its callback where it ends
//! it and leaves no end waiting.
//!
//! A leg's callback lies in a row of the plane's ([`LegRows`]), lent by the arena too, held by
//! count: by the leg's entry, then by its end, by each record of the round that owes it a reply,
//! and by a thread that captured it. Each is a copy of the row's place ([`LegId`]), so no holder
//! shares the callback by allocation, and the last count given back hands the callback out of the
//! row, to be dropped where no lock is held.

use alloc::sync::Arc;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;

use portable_atomic::AtomicU32;

use wz_session_core::bounded::{BoundedVec, Lent};

use alloc::collections::VecDeque;

use wz_capi_port::cancellation::FanKey;
use wz_capi_port::sync::{Lock, SessionHeld};
use wz_capi_port::ReplyCallback;
use wz_session_core::reply::InboundReply;
use wz_session_core::reply_hold::{HeldReplies, HeldReply, HoldRefused, ReplyHold};
use wz_session_core::reply_sink::{ReplySink, ReplyView};
use wz_session_core::timestamp_visibility::HiddenReplyTimestamp;
use wz_session_core::wire_id::RequestId;

use crate::round::{LegHolders, Round};

use super::queued::{Pending, Queued};

/// The end of one leg: the leg, the request id of the timeout that ended it, which its callback is
/// handed after every reply held before it (none for a leg that did not time out), and the row of
/// its callback, of which the end holds a count past the entry that owned it: whoever takes the end
/// out gives that count back (`LegHolders::release`), with no lock held.
pub(crate) struct Ended {
    pub(super) leg: u64,
    pub(super) timed_out: Option<RequestId>,
    pub(super) row: LegId,
}

/// The place of a leg's row in the plane's rows ([`LegRows`]). Copied only by a holder of a count
/// of the row, and the row is not given to another leg before its last count is given back, so
/// the place names this leg's row for as long as any copy of it is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LegId(u32);

impl LegId {
    /// The first row's place: what a test of the round holds a leg of its own by.
    #[cfg(test)]
    pub(crate) const FIRST: Self = Self(0);

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
pub(crate) struct LegRow {
    callback: ReplyCallback,
    shows_timestamp: bool,
    holders: AtomicU32,
}

impl LegRow {
    /// Hand `reply` to the callback, its timestamp hidden unless the leg shows it.
    fn call(&self, reply: &dyn ReplyView) {
        if self.shows_timestamp {
            self.callback.call(reply);
        } else {
            self.callback.call(&HiddenReplyTimestamp(reply));
        }
    }
}

/// The rows of the legs' callbacks, a row for each get the session's tables of pending gets hold at
/// once (`GetTables::legs`), lent by the session's arena; a row is reused once its last count is
/// given back.
#[derive(Default)]
pub(crate) struct LegRows {
    rows: BoundedVec<Option<LegRow>, { usize::MAX }, Lent>,
}

impl LegRows {
    /// A table over the rows `rows` an arena lent.
    pub(crate) fn over(rows: BoundedVec<Option<LegRow>, { usize::MAX }, Lent>) -> Self {
        Self { rows }
    }

    /// Keep the callback `mint` makes, shown timestamps when `shows_timestamp`, in a free row,
    /// held once: its place, or `None`, with nothing minted, when every row is held.
    fn open(
        &mut self,
        mint: &mut dyn FnMut() -> ReplyCallback,
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
    fn row(&self, leg: LegId) -> Option<&LegRow> {
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
    fn release(&mut self, leg: LegId) -> Option<ReplyCallback> {
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
pub(super) struct EndedLegs {
    legs: BoundedVec<Ended, { usize::MAX }, Lent>,
}

impl EndedLegs {
    /// A table over the rows `legs` an arena lent.
    pub(super) fn over(legs: BoundedVec<Ended, { usize::MAX }, Lent>) -> Self {
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
    pub(super) fn take(&mut self) -> Option<Ended> {
        self.legs.pop()
    }

    /// Leg `leg`'s end was decided where it ended: its end, taken out for that caller to let go
    /// of with no lock held, and nothing left to do for it here.
    pub(super) fn forget(&mut self, leg: u64) -> Option<Ended> {
        let at = self.legs.iter().position(|ended| ended.leg == leg)?;
        Some(self.legs.remove(at))
    }
}

impl Pending for EndedLegs {
    fn is_pending(&self) -> bool {
        !self.legs.is_empty()
    }
}

/// What the get plane shares between the session's state, the observer's reply sinks and the
/// deliveries.
pub(super) struct GetPlane {
    /// The legs that ended, handed out after the replies queued before them.
    pub(super) ended: Queued<EndedLegs>,
    /// The replies the entries of legs held to their ends, each with its leg, in the order they
    /// gave them up: handed to the leg's callback before its end, and before its timeout.
    held: Queued<VecDeque<(u64, InboundReply)>>,
    /// The replies the gets that consolidate hold to their Finals, each tagged with its leg
    /// ([`LegHold`]): rows the session's arena lent (`MAX_PENDING_REPLIES`), shared by every get
    /// of the session and reached only from the sinks, under the session's lock.
    replies: Lock<HeldReplies<u64, Lent>>,
    /// The legs' callbacks, each held by count (see the module).
    legs: Lock<LegRows>,
    /// Whether a thread that holds the session's lock takes the callback the answer it makes
    /// reaches ([`Self::capture`]).
    #[cfg(feature = "local-queryable")]
    capture: Lock<Capture>,
}

impl GetPlane {
    /// A plane with nothing ended, its ends waiting in `ended`, the replies its gets hold in
    /// `replies` and its legs' callbacks in `legs`.
    pub(super) fn new(ended: EndedLegs, replies: HeldReplies<u64, Lent>, legs: LegRows) -> Self {
        Self {
            ended: Queued::new(ended),
            held: Queued::new(VecDeque::new()),
            replies: Lock::new(replies),
            legs: Lock::new(legs),
            #[cfg(feature = "local-queryable")]
            capture: Lock::new(Capture::Off),
        }
    }

    /// Take out, instead of queueing, the callback of the leg the replies handed to the sinks from
    /// here on reach, until [`Self::captured`]: how the thread that makes an answer of the
    /// session's own queryables, holding the session's lock, learns what to call to hand it the
    /// answer itself once it lets go.
    #[cfg(feature = "local-queryable")]
    pub(super) fn capture(&self) {
        self.capture.with(|capture| *capture = Capture::On(None));
    }

    /// The row of the callback the replies since [`Self::capture`] reached, with a count of it the
    /// caller gives back once it handed the answer; what is handed after this is queued again.
    #[cfg(feature = "local-queryable")]
    pub(super) fn captured(&self) -> Option<LegId> {
        self.capture
            .with(|capture| match core::mem::replace(capture, Capture::Off) {
                Capture::On(found) => found,
                Capture::Off => None,
            })
    }

    /// Whether leg `leg`'s callback was taken out for the thread that captures, with a count of
    /// its row: one leg's, the first a reply reached. A second leg reached under the same capture
    /// is queued, so nothing is lost.
    #[cfg(feature = "local-queryable")]
    fn captures(&self, leg: LegId) -> bool {
        self.capture.with(|capture| match capture {
            Capture::On(slot) if slot.is_none() && self.hold(leg) => {
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
    pub(super) fn open_leg(
        &self,
        mint: &mut dyn FnMut() -> ReplyCallback,
        shows_timestamp: bool,
    ) -> Option<LegId> {
        self.legs.with(|legs| legs.open(mint, shows_timestamp))
    }

    /// Let go of every end, every held reply and every leg's row before the arena that lent them
    /// is given back: what the session's last handle does, once its round gave back the counts its
    /// records held and its entries are gone. A callback still in a row is dropped here.
    pub(super) fn let_go(&self) {
        loop {
            let next = self.ended.lock().take();
            let Some(ended) = next else {
                break;
            };
            self.forget_due(ended.leg);
            drop(self.release(ended.row));
        }
        drop(self.take_all_held());
        drop(self.legs.with(core::mem::take));
        *self.ended.lock() = EndedLegs::over(BoundedVec::default());
    }

    /// Keep `reply`, held to its end, for leg `leg`, after what it holds already.
    fn keep_held(&self, leg: u64, reply: InboundReply) {
        self.held.lock().push_back((leg, reply));
    }

    /// The first reply leg `leg`'s entry held to its end, taken out; `None` once there is
    /// nothing. Read without the lock while nothing is held.
    pub(super) fn take_held(&self, leg: u64) -> Option<InboundReply> {
        if !self.held.is_pending() {
            return None;
        }
        let mut held = self.held.lock();
        let at = held.iter().position(|(of, _)| *of == leg)?;
        held.remove(at).map(|(_, held)| held)
    }

    /// Everything held for every leg, taken out: the session is closed.
    pub(super) fn take_all_held(&self) -> VecDeque<(u64, InboundReply)> {
        core::mem::take(&mut *self.held.lock())
    }

    /// The next reply leg `leg`'s consolidation made due at its end, taken out of its row for the
    /// caller to hand to the leg's callback with no lock held ([`LegHold`]); `None` once there is
    /// none.
    pub(super) fn take_due(&self, leg: u64) -> Option<HeldReply<u64, Lent>> {
        self.replies.with(|replies| replies.take(leg))
    }

    /// Let go of every reply leg `leg` holds, due or not: a leg ended with nothing handed.
    pub(super) fn forget_due(&self, leg: u64) {
        self.replies.with(|replies| replies.forget(leg));
    }
}

impl LegHolders for GetPlane {
    fn hold(&self, leg: LegId) -> bool {
        self.legs.with(|legs| legs.hold(leg))
    }

    fn call(&self, leg: LegId, reply: &dyn ReplyView) {
        let row = self.legs.with(|legs| legs.row(leg).map(NonNull::from));
        if let Some(row) = row {
            // SAFETY: the caller holds a count of the row, so it is not taken out of its place,
            // and a lent table never moves its rows: it lies there until that count is given
            // back. The callback is read through a shared borrow and called with no lock held,
            // and the one word of the row the lock's holders write is atomic.
            unsafe { row.as_ref() }.call(reply);
        }
    }

    fn release(&self, leg: LegId) -> Option<ReplyCallback> {
        let callback = self.legs.with(|legs| legs.release(leg));
        debug_assert!(
            callback.is_none() || !SessionHeld::any_here(),
            "a leg's callback is let go of under a session's lock"
        );
        callback
    }
}

/// A leg the session has pending, with the key of the fan that cancels it when a token can: a row
/// of a table the session's arena lent, one for each get its tables of pending gets hold.
pub(crate) type PendingGet = wz_session_core::pending_get::PendingGet<FanKey>;
pub(super) use wz_session_core::pending_get::GetKind;

/// The end of a leg, said once: when the pending entry that owns it is dropped, with the timeout
/// that ended it, which the entry's sink was told of before its drop.
struct LegEnd {
    leg: u64,
    timed_out: Option<RequestId>,
    /// The entry's count of the leg's row, which the end holds from the entry's drop on.
    row: LegId,
    plane: Arc<GetPlane>,
}

impl Drop for LegEnd {
    fn drop(&mut self) {
        self.plane.ended.lock().note(Ended {
            leg: self.leg,
            timed_out: self.timed_out,
            row: self.row,
        });
    }
}

/// Whether the session's own queryables answer a get of the session now, on the thread that holds
/// the session's lock: the callback of the leg the answer reaches is taken out, for that thread
/// to hand it the answer once it lets go of the lock ([`GetPlane::capture`]).
#[cfg(feature = "local-queryable")]
enum Capture {
    Off,
    On(Option<LegId>),
}

/// The sink of leg `leg`'s pending entry, holding a count of the row of the leg's callback. A
/// reply the session's own
/// queryables made while the plane captures is the thread's that made it, which hands it to the
/// callback once it lets go of the session ([`GetPlane::capture`]); any other is held for the
/// callback in the session's round of deliveries (`Round::offer_reply`). What the entry's
/// consolidation held to its end waits in the plane's held table ([`GetPlane::take_held`]), and the
/// timeout of a leg that timed out in the leg's end ([`Ended`]). The sink's drop is the leg's end:
/// the Final says nothing more, as the registry drops the entry once its Finals are in. The end
/// holds the entry's count of the row past the entry ([`Ended`]), so the entry's drop, under the
/// session's lock, never lets the callback go.
pub(crate) struct LegSink {
    leg: u64,
    round: Arc<Round>,
    end: LegEnd,
}

impl LegSink {
    /// The sink of leg `leg`, handing what it is handed to the callback in `row`, of which it
    /// takes over the count [`GetPlane::open_leg`] took.
    pub(super) fn new(leg: u64, row: LegId, plane: &Arc<GetPlane>, round: &Arc<Round>) -> Self {
        Self {
            leg,
            round: Arc::clone(round),
            end: LegEnd {
                leg,
                timed_out: None,
                row,
                plane: Arc::clone(plane),
            },
        }
    }
}

impl ReplySink for LegSink {
    fn on_reply(&mut self, reply: &dyn ReplyView) {
        #[cfg(feature = "local-queryable")]
        if self.end.plane.captures(self.end.row) {
            return;
        }
        // SAFETY: the registry hands its sinks a reply under the session's lock.
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
/// ([`GetPlane::replies`]), tagged with the leg, so a held reply is copied into the session's
/// memory and takes none of its own. A full table refuses the reply, as a fixed room does, and
/// counts it. At the get's end (its Final, or its deadline) the replies it held are DUE: they stay
/// in their rows and are handed to the leg's callback from there once the session's lock is let go
/// ([`GetPlane::take_due`]), before the leg's end, so none of them is copied into the round of
/// deliveries, which has no place for a part that lies in a row. A leg that ends with replies held
/// and none due (cancelled, or its face gone) lets them go.
pub(crate) struct LegHold {
    leg: u64,
    plane: Arc<GetPlane>,
    /// Whether the get's end made what it holds due.
    due: bool,
}

impl LegHold {
    /// The hold of leg `leg` in `plane`'s rows.
    pub(super) fn new(leg: u64, plane: &Arc<GetPlane>) -> Self {
        Self {
            leg,
            plane: Arc::clone(plane),
            due: false,
        }
    }
}

impl ReplyHold for LegHold {
    fn displaces(&self, reply: &dyn ReplyView) -> bool {
        self.plane
            .replies
            .with(|replies| replies.of(self.leg).displaces(reply))
    }

    fn hold(&mut self, reply: &dyn ReplyView, whole: bool) -> Result<(), HoldRefused> {
        let leg = self.leg;
        self.plane
            .replies
            .with(|replies| replies.of(leg).hold(reply, whole))
    }

    /// The get ended: what it holds is due, and stays in its rows for the leg's callback to be
    /// handed it with no lock held ([`GetPlane::take_due`]). Nothing is handed to `each`, which
    /// would hold it in the round of deliveries.
    fn drain(&mut self, _each: &mut dyn FnMut(&dyn ReplyView)) {
        self.due = true;
    }
}

impl Drop for LegHold {
    fn drop(&mut self) {
        // What is due waits for the leg's end; what the get held with none due goes with it.
        if !self.due {
            let leg = self.leg;
            self.plane.replies.with(|replies| replies.forget(leg));
        }
    }
}

#[cfg(test)]
mod tests {
    //! The ends of the legs wait in rows an arena lent, each handed out once.
    use super::*;
    use crate::arena::{AllocatorMemory, SessionArena};
    use core::ffi::c_void;
    use core::sync::atomic::AtomicUsize;

    /// A table of ends and the arena it was lent from, the table first so it goes before the memory
    /// it lies in.
    struct Held {
        ends: EndedLegs,
        _arena: SessionArena,
    }

    /// A table of `rows` ends over an arena of its own.
    fn ended(rows: usize) -> Held {
        let mut arena =
            SessionArena::of_bytes(1 << 12, &AllocatorMemory).expect("the host has the memory");
        let legs = arena
            .arena_mut()
            .lend(rows)
            .expect("the arena has the rows");
        Held {
            ends: EndedLegs::over(legs),
            _arena: arena,
        }
    }

    /// A reply of key `key` and payload `payload`.
    struct Answer {
        key: &'static str,
        payload: &'static [u8],
    }

    impl ReplyView for Answer {
        fn rid(&self) -> RequestId {
            4
        }
        fn keyexpr(&self) -> &str {
            self.key
        }
        fn kind(&self) -> wz_session_core::reply_sink::ReplyKind {
            wz_session_core::reply_sink::ReplyKind::Put
        }
        fn payload(&self) -> &[u8] {
            self.payload
        }
        fn err_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
            None
        }
    }

    /// Each leg's hold keeps its replies in the plane's rows apart from another leg's, hands them
    /// out whole at its drain, refuses one past the rows, and lets go of what it still holds when
    /// it goes.
    #[test]
    fn a_legs_hold_keeps_its_replies_in_the_planes_rows() {
        let mut arena =
            SessionArena::of_bytes(1 << 16, &AllocatorMemory).expect("the host has the memory");
        let legs = arena.arena_mut().lend(4).expect("the arena has the rows");
        let replies = HeldReplies::lent(arena.arena_mut(), 2).expect("the arena has the rows");
        let plane = Arc::new(GetPlane::new(
            EndedLegs::over(legs),
            replies,
            LegRows::default(),
        ));
        let (mut one, mut two) = (LegHold::new(1, &plane), LegHold::new(2, &plane));
        let first = Answer {
            key: "demo/a",
            payload: b"first",
        };
        assert_eq!(one.hold(&first, true), Ok(()));
        assert_eq!(
            two.hold(
                &Answer {
                    key: "demo/a",
                    payload: b"other",
                },
                true
            ),
            Ok(())
        );
        assert_eq!(
            one.hold(
                &Answer {
                    key: "demo/b",
                    payload: b"past",
                },
                true
            ),
            Err(HoldRefused::Full),
            "two rows hold two replies"
        );
        let mut drained = std::vec::Vec::new();
        one.drain(&mut |reply| drained.push(reply.payload().to_vec()));
        assert!(
            drained.is_empty(),
            "the end hands nothing on: what it held is due in its rows"
        );
        drop(one);
        drop(two);
        assert_eq!(
            plane.replies.with(|replies| replies.len()),
            1,
            "a leg that goes with nothing due lets go of what it held; a due one keeps it"
        );
        let due = plane.take_due(1).expect("the due reply");
        assert_eq!(due.payload(), b"first", "a leg is handed its own");
        assert!(plane.take_due(1).is_none());
        assert!(plane.replies.with(|replies| replies.is_empty()));
    }

    /// What a test's leg callback was handed, and how often it was let go of.
    #[derive(Default)]
    struct Seen {
        calls: AtomicUsize,
        drops: AtomicUsize,
    }

    /// The call of a callback [`counted`] makes.
    ///
    /// # Safety
    /// `context` is a `Seen` that outlives the callback.
    unsafe fn seen_call(context: *mut c_void, _reply: &dyn ReplyView) {
        // SAFETY: the caller's contract.
        unsafe { &*context.cast::<Seen>() }
            .calls
            .fetch_add(1, Ordering::SeqCst);
    }

    /// The drop of a callback [`counted`] makes.
    ///
    /// # Safety
    /// As [`seen_call`]'s.
    unsafe fn seen_drop(context: *mut c_void) {
        // SAFETY: the caller's contract.
        unsafe { &*context.cast::<Seen>() }
            .drops
            .fetch_add(1, Ordering::SeqCst);
    }

    /// A C program's leg callback that counts its calls and its drop in `seen`.
    fn counted(seen: &Seen) -> ReplyCallback {
        let context = core::ptr::from_ref(seen).cast_mut().cast::<c_void>();
        // SAFETY: each test keeps `seen` past every callback it makes of it, and its counters are
        // atomic.
        unsafe { ReplyCallback::raw(seen_call, context, Some(seen_drop)) }
    }

    /// A plane whose legs' callbacks and ends have `rows` rows, lent by `arena`, which the test
    /// keeps past the plane.
    fn plane(arena: &mut SessionArena, rows: usize) -> Arc<GetPlane> {
        let ends = arena
            .arena_mut()
            .lend(rows)
            .expect("the arena has the rows");
        let legs = arena
            .arena_mut()
            .lend(rows)
            .expect("the arena has the rows");
        let replies = HeldReplies::lent(arena.arena_mut(), 1).expect("the arena has the rows");
        Arc::new(GetPlane::new(
            EndedLegs::over(ends),
            replies,
            LegRows::over(legs),
        ))
    }

    /// A reply a test hands a leg.
    const REPLY: Answer = Answer {
        key: "demo/a",
        payload: b"a",
    };

    /// A leg's row holds its callback, called through it, until the last count is given back,
    /// which hands the callback out to be dropped by the one that gave it back; a row given back
    /// is held and called by none.
    #[test]
    fn a_legs_row_holds_its_callback_until_its_last_count() {
        let mut arena =
            SessionArena::of_bytes(1 << 14, &AllocatorMemory).expect("the host has the memory");
        let plane = plane(&mut arena, 2);
        let seen = Seen::default();
        let row = plane
            .open_leg(&mut || counted(&seen), true)
            .expect("a row is free");
        assert!(plane.hold(row), "a record's count of it");
        plane.call(row, &REPLY);
        assert_eq!(seen.calls.load(Ordering::SeqCst), 1);
        assert!(
            plane.release(row).is_none(),
            "the entry's count is still held"
        );
        assert_eq!(seen.drops.load(Ordering::SeqCst), 0);
        let last = plane.release(row);
        assert!(last.is_some(), "the last count hands the callback out");
        assert_eq!(
            seen.drops.load(Ordering::SeqCst),
            0,
            "handed out, not dropped in the row"
        );
        drop(last);
        assert_eq!(seen.drops.load(Ordering::SeqCst), 1);
        assert!(!plane.hold(row), "a row given back is held by none");
        plane.call(row, &REPLY);
        assert_eq!(
            seen.calls.load(Ordering::SeqCst),
            1,
            "a row given back calls nothing"
        );
    }

    /// A leg that finds every row held is refused before its callback is minted, and a row given
    /// back is the next leg's.
    #[test]
    fn a_leg_past_the_rows_mints_no_callback_and_a_row_given_back_is_reused() {
        let mut arena =
            SessionArena::of_bytes(1 << 14, &AllocatorMemory).expect("the host has the memory");
        let plane = plane(&mut arena, 1);
        let (first, second) = (Seen::default(), Seen::default());
        let row = plane
            .open_leg(&mut || counted(&first), true)
            .expect("one row");
        let mut minted = 0;
        let refused = plane.open_leg(
            &mut || {
                minted += 1;
                counted(&second)
            },
            true,
        );
        assert_eq!(refused, None, "one row holds one leg");
        assert_eq!(minted, 0, "refused before its callback is minted");
        drop(plane.release(row));
        assert_eq!(first.drops.load(Ordering::SeqCst), 1);
        let again = plane.open_leg(&mut || counted(&second), true);
        assert_eq!(again, Some(row), "the row given back is the next leg's");
        drop(plane.release(row));
        assert_eq!(second.drops.load(Ordering::SeqCst), 1);
    }

    /// The plane let go of before its arena gives back the count an end waiting holds and drops
    /// every callback a row still holds, and holds no row after.
    #[test]
    fn a_plane_let_go_drops_the_callbacks_its_rows_and_ends_still_hold() {
        let mut arena =
            SessionArena::of_bytes(1 << 14, &AllocatorMemory).expect("the host has the memory");
        let plane = plane(&mut arena, 2);
        let (ended, open) = (Seen::default(), Seen::default());
        let one = plane
            .open_leg(&mut || counted(&ended), true)
            .expect("a row");
        let two = plane.open_leg(&mut || counted(&open), true).expect("a row");
        plane.ended.lock().note(Ended {
            leg: 1,
            timed_out: None,
            row: one,
        });
        plane.let_go();
        assert_eq!(
            (
                ended.drops.load(Ordering::SeqCst),
                open.drops.load(Ordering::SeqCst)
            ),
            (1, 1)
        );
        assert!(!plane.hold(two), "the rows are let go of");
        assert!(plane.ended.lock().take().is_none());
    }

    /// A reply the session's own queryables answer while the plane captures hands the capturing
    /// thread the first leg it reached with a count of its row, which keeps the callback past
    /// the entry's count until the thread gives it back.
    #[cfg(feature = "local-queryable")]
    #[test]
    fn a_captured_leg_keeps_a_count_of_its_row_for_the_capturing_thread() {
        let mut arena =
            SessionArena::of_bytes(1 << 14, &AllocatorMemory).expect("the host has the memory");
        let plane = plane(&mut arena, 2);
        let seen = Seen::default();
        let row = plane.open_leg(&mut || counted(&seen), true).expect("a row");
        plane.capture();
        assert!(plane.captures(row));
        assert!(!plane.captures(row), "one leg for each capture");
        assert_eq!(plane.captured(), Some(row));
        assert!(plane.release(row).is_none(), "the capture's count");
        let last = plane.release(row);
        assert!(last.is_some(), "the entry's count was the last");
        drop(last);
        assert_eq!(seen.drops.load(Ordering::SeqCst), 1);
    }

    /// The end of leg `leg`, which no timeout ended.
    fn end(leg: u64) -> Ended {
        ended_by(leg, None)
    }

    /// The end of leg `leg`, which the timeout of `rid` ended when there is one.
    fn ended_by(leg: u64, timed_out: Option<RequestId>) -> Ended {
        Ended {
            leg,
            timed_out,
            row: LegId(0),
        }
    }

    /// What an end says: its leg and the timeout that ended it.
    fn said(ended: Option<Ended>) -> Option<(u64, Option<RequestId>)> {
        ended.map(|ended| (ended.leg, ended.timed_out))
    }

    /// Each end noted is taken once, and an end its leg's maker handled itself is taken out by
    /// that maker, once, and not by the deliveries.
    #[test]
    fn each_end_is_taken_once_and_a_forgotten_one_never() {
        let mut held = ended(3);
        let ends = &mut held.ends;
        ends.note(end(1));
        ends.note(end(2));
        ends.note(end(3));
        assert_eq!(
            said(ends.forget(2)),
            Some((2, None)),
            "taken out by its maker"
        );
        assert!(ends.forget(2).is_none(), "and only once");
        let mut taken = [ends.take(), ends.take(), ends.take()].map(|e| e.map(|e| e.leg));
        taken.sort();
        assert_eq!(taken, [None, Some(1), Some(3)]);
    }

    /// The end of a leg a timeout ended keeps the timeout's request id to its delivery, and one
    /// that ended otherwise keeps none.
    #[test]
    fn an_end_keeps_the_timeout_that_ended_its_leg() {
        let mut held = ended(2);
        let ends = &mut held.ends;
        ends.note(ended_by(5, Some(9)));
        assert_eq!(said(ends.take()), Some((5, Some(9))));
        ends.note(end(6));
        assert_eq!(
            said(ends.take()),
            Some((6, None)),
            "CONTROL: a final ends with none"
        );
    }

    /// A table lent no rows is the defect the plan rules out: the end is not kept, and a debug
    /// build stops there.
    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic(expected = "the ends waiting outnumber")
    )]
    fn an_end_past_the_rows_is_a_defect() {
        let mut held = ended(0);
        let ends = &mut held.ends;
        ends.note(end(1));
        assert!(ends.take().is_none());
    }
}
