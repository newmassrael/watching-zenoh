// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The engine's round of deliveries ([`wz_session_core::round`]), of the calls and kinds of record
//! the engine's build names (`crate::calls`): the room one record a session is handed can take of
//! it, and the gates that hold each link back while the round has not that room (decision Q4).

#[cfg(any(feature = "listen", feature = "group"))]
use core::cell::Cell;

// What a link is gated through: the round's gate.
use wz_runtime_coop::session_drive::{SessionDatagramLink, WaitOn};
#[cfg(wz_round)]
use wz_session_core::limit_binding::Quota;
#[cfg(wz_round)]
use wz_session_core::limits::SessionLimits;
use wz_session_core::link::{LostCause, RxFrame};
#[cfg(test)]
use wz_session_core::placed::Placed;
#[cfg(any(test, wz_round))]
use wz_session_core::placed::PlacedRef;

#[cfg(feature = "local-subscriber")]
use crate::engine::SubscriberCall;

#[cfg(all(feature = "queryable", any(test, wz_round)))]
pub(crate) use wz_session_core::round::AnswersQueries;
#[cfg(any(test, wz_round))]
pub(crate) use wz_session_core::round::ReadRoom;
pub(crate) use wz_session_core::round::RoundRows;
pub use wz_session_core::round::{RoundCounts, RoundRowCounts};

use crate::calls::CoopCalls;

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
#[cfg(wz_round)]
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
#[cfg(wz_round)]
pub(crate) fn read_room<const SUBS: usize, const LIVE: usize>(limits: &SessionLimits) -> ReadRoom {
    let subscribers = limits
        .max_subscriptions()
        .lent_under(Quota::at_most(SUBS))
        .unwrap_or(SUBS);
    let most = most_subscribers(subscribers, session_liveliness::<LIVE>(limits))
        .max(session_watches(limits));
    ReadRoom {
        // A reply owes its leg's callback, whatever the session's subscribers.
        callbacks: most.max(1),
    }
}

/// The declaration watches the session's `limits` admit, under the build's: what a record of what a
/// peer declared owes a callback to at most. None in a build without the watch.
#[cfg(wz_round)]
fn session_watches(limits: &SessionLimits) -> usize {
    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    {
        limits
            .max_decl_watches()
            .lent_under(Quota::at_most(wz_session_core::caps::MAX_DECL_WATCHES))
            .unwrap_or(wz_session_core::caps::MAX_DECL_WATCHES)
    }
    #[cfg(not(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    )))]
    {
        let _ = limits;
        0
    }
}

/// The liveliness subscribers the session's `limits` admit, under `LIVE`, the build's value: a value
/// over it counts as the build's, which the open refuses. What a record of a token owes a callback
/// to at most, and so what the round's callbacks are asked for ([`read_room`]) and a retraction
/// asks of them.
#[cfg(wz_round)]
pub(crate) fn session_liveliness<const LIVE: usize>(limits: &SessionLimits) -> usize {
    limits
        .max_liveliness_subscriptions()
        .lent_under(Quota::at_most(LIVE))
        .unwrap_or(LIVE)
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

/// A round holding `events` records at once, placed with its tables in an arena the test leaks,
/// its owner leaked too: never dropped, so every handle of it stays good, and the caller may change
/// the round through it before it shares any.
#[cfg(test)]
pub(crate) fn leaked_placed(events: usize) -> &'static mut Placed<Round> {
    use crate::arena::{AllocatorMemory, SessionArena};
    use wz_session_core::bounded::ARENA_ALIGN;
    use wz_session_core::caps;

    let counts = RoundRowCounts {
        records: events,
        callbacks: caps::DELIVERY_LANE_CALLBACKS,
        longest_key: caps::MAX_KEYEXPR_BYTES,
    };
    // Each table and the round on a span of its own, rounded up to the next start of one.
    let bytes = events * RECORD_BYTES
        + counts.callbacks * CALLBACK_BYTES
        + counts.key_bytes::<crate::form::CoopForm>()
        + core::mem::size_of::<Round>()
        + 4 * ARENA_ALIGN;
    let arena: &'static mut SessionArena = alloc::boxed::Box::leak(alloc::boxed::Box::new(
        SessionArena::of_bytes(bytes, &AllocatorMemory).expect("the host has the memory"),
    ));
    let rows = RoundRows::lent(arena.arena_mut(), counts).expect("the arena has the rows");
    let placed = Round::placed_over(arena.arena_mut(), rows).expect("the arena has the round");
    alloc::boxed::Box::leak(alloc::boxed::Box::new(placed))
}

/// A handle of a round holding `events` records at once, placed by [`leaked_placed`].
#[cfg(test)]
pub(crate) fn leaked(events: usize) -> PlacedRef<Round> {
    // SAFETY: the owner is leaked, so never dropped, and nothing reaches it but this handle.
    unsafe { leaked_placed(events).share() }
}

/// The group twin of [`RoundGate`]: whether the round has the room one record of a group can
/// take (`room`, decision Q4), asked before each datagram of the group and before each further
/// message and record of one its transport keeps, and holds nothing lent. While it has not, what
/// the members send waits in the group's socket.
///
/// # Safety
/// The gate it answers is asked by the session's step alone, under the session's lock, as the
/// group's transport is driven, and `round`'s owner outlives it (`Placed::share`).
#[cfg(feature = "group")]
pub(crate) unsafe fn takes_a_group_read(
    round: PlacedRef<Round>,
    room: ReadRoom,
) -> impl Fn() -> bool + 'static {
    // SAFETY: the caller's contract: the session's lock is held whenever this is asked.
    move || !round.owes() && !round.lends_a_datagram() && unsafe { round.has_room(room) }
}

/// `pump`, which gives the session nothing while the round has not the room one record can take
/// (`room`, decision Q4), nor while a record lies in the datagram a link lent: not the next
/// datagram, and not the next record of one the link keeps. What the peer sends meanwhile waits in
/// the link, and the transport's flow control carries the wait back to it. A build whose read
/// hands each record out as it is read puts no link behind it (`engine::direct`).
#[cfg(any(test, wz_round))]
pub(crate) struct RoundGate<P> {
    pump: P,
    round: PlacedRef<Round>,
    room: ReadRoom,
    /// What the link's owner last learned of its stack: a session of several links reads only
    /// the stacks that may hold input, where one link alone has nothing to pass over.
    #[cfg(any(feature = "listen", feature = "group"))]
    stack: Cell<Stack>,
}

/// What a gate knows of its link's stack ([`RoundGate`]).
#[cfg(any(feature = "listen", feature = "group"))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stack {
    /// No wait of the owner's looked at it: a link that waits in its own loop, read at every
    /// step, since no wait would tell when it has input again.
    Unwaited,
    /// A wait found input in it, or the session's links moved since it gave nothing: read it.
    Look,
    /// It gave nothing when last read, or a wait found nothing in it, and the links have not
    /// moved since: a step passes over it.
    Quiet,
}

#[cfg(any(test, wz_round))]
impl<P> RoundGate<P> {
    /// `pump`, gated by `round` for the room `room` of one of its records.
    ///
    /// # Safety
    /// Asked by the session's step alone, which holds the session's lock, and `round`'s owner
    /// outlives the gate (`Placed::share`).
    pub(crate) unsafe fn new(pump: P, round: PlacedRef<Round>, room: ReadRoom) -> Self {
        Self {
            pump,
            round,
            room,
            #[cfg(any(feature = "listen", feature = "group"))]
            stack: Cell::new(Stack::Unwaited),
        }
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

#[cfg(any(feature = "listen", feature = "group"))]
#[cfg(any(test, wz_round))]
impl<P: SessionDatagramLink> RoundGate<P> {
    /// What a wait over the link's input found in its stack, `ready` or not, or, `true`, that the
    /// session's links moved (`FaceSession::input_seen`).
    pub(crate) fn input_seen(&self, ready: bool) {
        self.stack
            .set(if ready { Stack::Look } else { Stack::Quiet });
    }

    /// Whether this step passes over the link's stack: nothing was there when it was last read or
    /// waited on, and the links have not moved since. Input the link took from its stack already
    /// is read whatever the stack held.
    fn passes_over(&self) -> bool {
        self.stack.get() == Stack::Quiet && !self.pump.holds_input()
    }

    /// The link gave nothing: a stack its owner waits on is passed over until a wait finds input
    /// there or the links move. Each link of a session of several would otherwise be asked its
    /// stack at every step, for one input on one of them.
    fn gave_nothing(&self) {
        if self.stack.get() == Stack::Look {
            self.stack.set(Stack::Quiet);
        }
    }
}

#[cfg(any(test, wz_round))]
impl<P: SessionDatagramLink> RoundGate<P> {
    /// Lend the link's next datagram to `f`. A link that leaves it where it lies until it is next
    /// asked to receive tells the round where it lies while it is lent, so a record of it may be
    /// read there.
    // Always inlined: the receive is its one caller.
    #[inline(always)]
    fn lend(&self, f: &mut dyn FnMut(&[u8])) -> bool {
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
}

#[cfg(any(test, wz_round))]
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
        #[cfg(any(feature = "listen", feature = "group"))]
        {
            if self.passes_over() {
                return None;
            }
            let frame = self.pump.try_recv();
            if frame.is_none() {
                self.gave_nothing();
            }
            frame
        }
        #[cfg(not(any(feature = "listen", feature = "group")))]
        {
            self.pump.try_recv()
        }
    }

    /// The datagram is lent to the session's step; a link that leaves it where it lies until it
    /// is next asked to receive tells the round where it lies while it is lent, so a record of it
    /// may be read there.
    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        if self.shut() {
            return false;
        }
        #[cfg(any(feature = "listen", feature = "group"))]
        {
            if self.passes_over() {
                return false;
            }
            let received = self.lend(f);
            if !received {
                self.gave_nothing();
            }
            received
        }
        #[cfg(not(any(feature = "listen", feature = "group")))]
        {
            self.lend(f)
        }
    }

    /// A link that ended is told to the session after what it queued before the end was read, and
    /// what it queued is held back: the end waits with it.
    fn lost(&self) -> Option<LostCause> {
        if self.shut() {
            return None;
        }
        self.pump.lost()
    }

    // What the link dropped was dropped whatever the gate holds back: it is counted as it is.
    fn take_rx_dropped(&self) -> usize {
        self.pump.take_rx_dropped()
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

    fn lends_until_next_receive(&self) -> bool {
        self.pump.lends_until_next_receive()
    }

    fn input_wait(&self) -> Option<WaitOn> {
        self.pump.input_wait()
    }

    // The gate holds back input only: what the session sends goes out while the round is full.
    fn room_wait(&self) -> Option<WaitOn> {
        self.pump.room_wait()
    }
}
