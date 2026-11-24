// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The engine's round of deliveries ([`wz_session_core::round`]): the calls its records owe and
//! the kinds of record it keeps, as the engine's build names them ([`CoopCalls`]), the room one
//! record a session is handed can take of it, and the gates that hold each link back while the
//! round has not that room (decision Q4).

use alloc::sync::Arc;

use wz_runtime_coop::session_drive::{SessionDatagramLink, WaitOn};
use wz_session_core::limit_binding::Quota;
use wz_session_core::limits::SessionLimits;
use wz_session_core::link::{LostCause, RxFrame};
use wz_session_core::plane_lock::LockFamily;
use wz_session_core::round::{PlaneCalls, RoundCall, RoundCalls, SampleCall};
use wz_session_core::sink::SampleView;

#[cfg(feature = "query")]
use crate::engine::LegId;
#[cfg(feature = "liveliness")]
use crate::engine::LivelinessCall;
#[cfg(feature = "queryable")]
use crate::engine::QueryableCall;
use crate::engine::SubscriberCall;
#[cfg(feature = "query")]
use wz_capi_port::ReplyCallback;
#[cfg(feature = "liveliness")]
use wz_session_core::declare::liveliness_sample::LivelinessSample;

#[cfg(feature = "queryable")]
pub(crate) use wz_session_core::round::AnswersQueries;
#[cfg(feature = "query")]
pub(crate) use wz_session_core::round::LegHolders;
pub(crate) use wz_session_core::round::{ReadRoom, RoundRows};
pub use wz_session_core::round::{RoundCounts, RoundRowCounts};

/// The engine's round of deliveries.
pub(crate) type Round = wz_session_core::round::Round<CoopCalls>;

/// The bytes of one record of the engine's round.
pub(crate) const RECORD_BYTES: usize = RoundRows::<CoopCalls>::RECORD_BYTES;

/// The bytes of one callback a record of the engine's round owes.
pub(crate) const CALLBACK_BYTES: usize = RoundRows::<CoopCalls>::CALLBACK_BYTES;

// Each call the engine's records owe is a row's address alone, so a callback row is that and its
// tag: what the round's callbacks cost in the session's arena stays two words a row.
const _: () = assert!(
    CALLBACK_BYTES <= core::mem::size_of::<usize>().saturating_mul(2),
    "a callback a record owes is a row's address and its tag"
);

// A call is a row's address alone; the stack cost the round states of the calls the session's own
// put is handed (`wz_session_core::round::Captured`) holds while it stays so.
#[cfg(feature = "local-subscriber")]
const _: () = assert!(core::mem::size_of::<SubscriberCall>() <= core::mem::size_of::<usize>());

/// The most subscribers one record of a session reaches: a sample's, of the `subscribers` it
/// holds, or a token's, of the `liveliness` subscribers it holds (none in a build without
/// liveliness), whichever is more.
const fn most_subscribers(subscribers: usize, liveliness: usize) -> usize {
    let liveliness = if cfg!(feature = "liveliness") {
        liveliness
    } else {
        0
    };
    if liveliness > subscribers {
        liveliness
    } else {
        subscribers
    }
}

/// What one record of a session whose limits are `limits` can take of its round ([`ReadRoom`]):
/// an entry, and a callback for each subscriber it reaches, under the build's `SUBS` and `LIVE`.
pub(crate) fn read_room<const SUBS: usize, const LIVE: usize>(limits: &SessionLimits) -> ReadRoom {
    let subscribers = limits
        .max_subscriptions()
        .lent_under(Quota::at_most(SUBS))
        .unwrap_or(SUBS);
    let most = most_subscribers(subscribers, session_liveliness::<LIVE>(limits));
    ReadRoom {
        // A reply owes its leg's callback, whatever the session's subscribers.
        callbacks: most.max(1),
    }
}

/// The liveliness subscribers the session's `limits` admit, under `LIVE`, the build's value: a value
/// over it counts as the build's, which the open refuses. What a record of a token owes a callback
/// to at most, and so what the round's callbacks are asked for ([`read_room`]) and a retraction
/// asks of them.
pub(crate) fn session_liveliness<const LIVE: usize>(limits: &SessionLimits) -> usize {
    limits
        .max_liveliness_subscriptions()
        .lent_under(Quota::at_most(LIVE))
        .unwrap_or(LIVE)
}

/// The calls the engine's round owes and the kinds of record it keeps: each kind of row the
/// engine's build keeps none of has the call [`Infallible`](core::convert::Infallible) and a
/// record kind of no size.
pub(crate) enum CoopCalls {}

impl RoundCalls for CoopCalls {
    type Subscriber = SubscriberCall;
    #[cfg(feature = "liveliness")]
    type Liveliness = LivelinessCall;
    #[cfg(not(feature = "liveliness"))]
    type Liveliness = core::convert::Infallible;
    #[cfg(feature = "queryable")]
    type Queryable = QueryableCall;
    #[cfg(not(feature = "queryable"))]
    type Queryable = core::convert::Infallible;
    #[cfg(feature = "query")]
    type Leg = LegId;
    #[cfg(not(feature = "query"))]
    type Leg = core::convert::Infallible;
    #[cfg(feature = "query")]
    type ReplyCallback = ReplyCallback;
    #[cfg(not(feature = "query"))]
    type ReplyCallback = core::convert::Infallible;
    #[cfg(feature = "liveliness")]
    type Tokens = wz_session_core::session_tables::Present;
    #[cfg(not(feature = "liveliness"))]
    type Tokens = wz_session_core::session_tables::Absent;
    #[cfg(feature = "query")]
    type Replies = wz_session_core::session_tables::Present;
    #[cfg(not(feature = "query"))]
    type Replies = wz_session_core::session_tables::Absent;
    #[cfg(feature = "queryable")]
    type Queries = wz_session_core::session_tables::Present;
    #[cfg(not(feature = "queryable"))]
    type Queries = wz_session_core::session_tables::Absent;
    #[cfg(feature = "local-subscriber")]
    type Capture = wz_session_core::session_tables::Present;
    #[cfg(not(feature = "local-subscriber"))]
    type Capture = wz_session_core::session_tables::Absent;
    #[cfg(feature = "group")]
    type Group = wz_session_core::session_tables::Present;
    #[cfg(not(feature = "group"))]
    type Group = wz_session_core::session_tables::Absent;
    type Locks = CoopSyncLocks;
    #[cfg(all(test, feature = "std"))]
    type Tally = Handed;
    #[cfg(not(all(test, feature = "std")))]
    type Tally = ();
}

impl PlaneCalls for CoopCalls {
    #[cfg(feature = "local-queryable")]
    type LocalAnswers = wz_session_core::session_tables::Present;
    #[cfg(not(feature = "local-queryable"))]
    type LocalAnswers = wz_session_core::session_tables::Absent;
    type Queues = crate::engine::CoopLocks;
}

/// The port's lock, as the lock the round keeps what answers its queries under.
pub(crate) enum CoopSyncLocks {}

impl LockFamily for CoopSyncLocks {
    type Lock<T> = wz_capi_port::sync::Lock<T>;

    fn new<T>(value: T) -> Self::Lock<T> {
        wz_capi_port::sync::Lock::new(value)
    }

    fn with<T, R>(lock: &Self::Lock<T>, f: impl FnOnce(&mut T) -> R) -> R {
        lock.with(f)
    }
}

impl RoundCall for SubscriberCall {
    fn end(self) -> bool {
        SubscriberCall::end(self)
    }
}

impl SampleCall for SubscriberCall {
    fn same_row(&self, other: &Self) -> bool {
        SubscriberCall::same_row(self, other)
    }

    fn hand(&self, sample: &dyn SampleView) {
        SubscriberCall::hand(self, sample);
    }
}

#[cfg(feature = "liveliness")]
impl RoundCall for LivelinessCall {
    fn end(self) -> bool {
        LivelinessCall::end(self)
    }
}

#[cfg(feature = "liveliness")]
impl wz_session_core::round::TokenCall for LivelinessCall {
    fn same_row(&self, other: &Self) -> bool {
        LivelinessCall::same_row(self, other)
    }

    fn hand(&self, sample: LivelinessSample<'_>) {
        LivelinessCall::hand(self, sample);
    }
}

#[cfg(feature = "queryable")]
impl RoundCall for QueryableCall {
    fn end(self) -> bool {
        QueryableCall::end(self)
    }
}

/// The rounds the engine's round handed out, the samples in them, and of those the ones read
/// where their datagram lies, which the tests count.
#[cfg(all(test, feature = "std"))]
#[derive(Default)]
pub(crate) struct Handed {
    rounds: core::sync::atomic::AtomicUsize,
    samples: core::sync::atomic::AtomicUsize,
    lent: core::sync::atomic::AtomicUsize,
}

#[cfg(all(test, feature = "std"))]
impl Handed {
    /// How many rounds were handed out since the round was made.
    pub(crate) fn rounds(&self) -> usize {
        self.rounds.load(core::sync::atomic::Ordering::SeqCst)
    }

    /// How many samples the rounds handed out held.
    pub(crate) fn samples(&self) -> usize {
        self.samples.load(core::sync::atomic::Ordering::SeqCst)
    }

    /// How many samples were handed where their datagram lies.
    pub(crate) fn lent(&self) -> usize {
        self.lent.load(core::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(all(test, feature = "std"))]
impl wz_session_core::round::RoundTally for Handed {
    fn handed(&self, count: impl FnOnce() -> (usize, usize)) {
        use core::sync::atomic::Ordering::SeqCst;
        let (samples, lent) = count();
        self.rounds.fetch_add(1, SeqCst);
        self.samples.fetch_add(samples, SeqCst);
        self.lent.fetch_add(lent, SeqCst);
    }
}

/// The tables of a round holding `events` records at once, lent from an arena the test leaks, so
/// it outlives the round.
#[cfg(test)]
fn leaked_rows(events: usize) -> RoundRows<CoopCalls> {
    use crate::arena::{AllocatorMemory, SessionArena};
    use wz_session_core::bounded::ARENA_ALIGN;
    use wz_session_core::caps;

    let counts = RoundRowCounts {
        records: events,
        callbacks: caps::DELIVERY_LANE_CALLBACKS,
        longest_key: caps::MAX_KEYEXPR_BYTES,
    };
    // Each table on a span of its own, rounded up to the next start of one.
    let bytes_of_rows = events * RECORD_BYTES
        + counts.callbacks * CALLBACK_BYTES
        + counts.key_bytes()
        + 3 * ARENA_ALIGN;
    let arena: &'static mut SessionArena = alloc::boxed::Box::leak(alloc::boxed::Box::new(
        SessionArena::of_bytes(bytes_of_rows, &AllocatorMemory).expect("the host has the memory"),
    ));
    RoundRows::lent(arena.arena_mut(), counts).expect("the arena has the rows")
}

/// A round holding `events` records at once, its tables lent from an arena the test leaks.
#[cfg(test)]
pub(crate) fn leaked(events: usize) -> Arc<Round> {
    Round::shared_over(leaked_rows(events))
}

/// The group twin of [`RoundGate`]: whether the round has the room one record of a group can
/// take (`room`, decision Q4), asked before each datagram of the group and before each further
/// message and record of one its transport keeps, and holds nothing lent. While it has not, what
/// the members send waits in the group's socket.
///
/// # Safety
/// The gate it answers is asked by the session's step alone, under the session's lock, as the
/// group's transport is driven.
#[cfg(feature = "group")]
pub(crate) unsafe fn takes_a_group_read(
    round: Arc<Round>,
    room: ReadRoom,
) -> impl Fn() -> bool + 'static {
    // SAFETY: the caller's contract: the session's lock is held whenever this is asked.
    move || !round.owes() && !round.lends_a_datagram() && unsafe { round.has_room(room) }
}

/// `pump`, which gives the session nothing while the round has not the room one record can take
/// (`room`, decision Q4), nor while a record lies in the datagram a link lent: not the next
/// datagram, and not the next record of one the link keeps. What the peer sends meanwhile waits in
/// the link, and the transport's flow control carries the wait back to it.
pub(crate) struct RoundGate<P> {
    pump: P,
    round: Arc<Round>,
    room: ReadRoom,
}

impl<P> RoundGate<P> {
    /// `pump`, gated by `round` for the room `room` of one of its records.
    ///
    /// # Safety
    /// Asked by the session's step alone, which holds the session's lock.
    pub(crate) unsafe fn new(pump: P, round: Arc<Round>, room: ReadRoom) -> Self {
        Self { pump, round, room }
    }

    /// The link this gate stands before, as the engine admits it through the gates (`listen`).
    #[cfg(feature = "listen")]
    pub(crate) fn pump(&self) -> &P {
        &self.pump
    }

    /// Whether the round has the room of a record, and nothing a source outside the gate owes is
    /// still to come before it.
    fn has_room(&self) -> bool {
        // SAFETY: asked by the session's step alone, under the session's lock (`Self::new`).
        !self.round.owes() && unsafe { self.round.has_room(self.room) }
    }

    /// Whether the link is held back from receiving: a record lies in the datagram it lent last
    /// (the next receive may write where it lies), or the round has not the room of a record. A
    /// link that is not held back may be read, so the buffer of a rejoined message the round kept
    /// and no longer reads is given back first: the chain a fragment read now starts finds it free.
    fn shut(&self) -> bool {
        if self.round.lends_a_datagram() || !self.has_room() {
            return true;
        }
        // SAFETY: asked by the session's step alone, under the session's lock (`Self::new`).
        unsafe { self.round.settle() };
        false
    }
}

impl<P: SessionDatagramLink> SessionDatagramLink for RoundGate<P> {
    /// A link whose datagram a record is read from is not serviced: its stack may read the next
    /// datagram into the buffer the record lies in.
    fn service(&self) {
        if !self.round.lends_a_datagram() {
            self.pump.service()
        }
    }

    fn service_within(&self, max_wait_ms: u64) {
        if !self.round.lends_a_datagram() {
            self.pump.service_within(max_wait_ms)
        }
    }

    fn uses_wake_budget(&self) -> bool {
        self.pump.uses_wake_budget()
    }

    fn try_recv(&self) -> Option<RxFrame> {
        if self.shut() {
            return None;
        }
        self.pump.try_recv()
    }

    /// The datagram is lent to the session's step; a link that leaves it where it lies until it
    /// is next asked to receive tells the round where it lies while it is lent, so a record of it
    /// may be read there.
    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        if self.shut() {
            return false;
        }
        if !self.pump.lends_until_next_receive() {
            return self.pump.recv_with(f);
        }
        self.pump.recv_with(&mut |datagram: &[u8]| {
            // SAFETY: a link's gate is asked by the session's step alone, under the session's
            // lock (`Self::new`), and the link leaves the bytes where they lie until it is next
            // asked to receive or to be serviced, which it is not while a record lies there.
            unsafe { self.round.set_lending(Some(datagram)) };
            f(datagram);
            // SAFETY: as above.
            unsafe { self.round.set_lending(None) };
        })
    }

    /// A link that ended is told to the session after what it queued before the end was read, and
    /// what it queued is held back: the end waits with it.
    fn lost(&self) -> Option<LostCause> {
        if self.shut() {
            return None;
        }
        self.pump.lost()
    }

    fn holds_input(&self) -> bool {
        self.pump.holds_input()
    }

    #[cfg(feature = "listen")]
    fn waits_for_buffer(&self) -> bool {
        self.pump.waits_for_buffer()
    }

    // The gate holds back input only: what the session owes the stack is written whatever it
    // holds, and the owner's wait wakes for it.
    fn owes_write(&self) -> bool {
        self.pump.owes_write()
    }

    // What the session owes the stack is written whatever the round holds, as `owes_write` says.
    #[cfg(feature = "listen")]
    fn write_owed_now(&self) {
        self.pump.write_owed_now()
    }

    /// The rest of a datagram already read is held back with the link's next one while the round
    /// has not the room of a record. A record lying in the datagram does not hold the rest back:
    /// it lies where the rest does, and the records after it join it.
    fn takes_input(&self) -> bool {
        self.has_room() && self.pump.takes_input()
    }

    fn keeps_input(&self) -> bool {
        self.pump.keeps_input()
    }

    fn keep(&self) {
        self.pump.keep()
    }

    fn input_wait(&self) -> Option<WaitOn> {
        self.pump.input_wait()
    }

    // The gate holds back input only: what the session sends goes out while the round is full.
    fn room_wait(&self) -> Option<WaitOn> {
        self.pump.room_wait()
    }
}
