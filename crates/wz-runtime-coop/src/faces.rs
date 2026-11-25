// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The faces of a session as its driver holds them: each face's link and where it stands (up, in
//! its handshake, dialled, waiting to be dialled again, standing by), the dials under way, the
//! ports the session listens on, and the wait a read makes on all of them before it steps the
//! session.
//!
//! What a link means to the protocol (its handshake, what is declared over it, what its loss takes
//! with it) is the session's. A [`LinkSupervisor`] reads what has happened to a face's link as the
//! input of the face's life (`wz_session_core::link_life`), which decides what the session does
//! about it; it asks the session of a link only
//! what [`FaceSession`] names. So the driver owns the facts of the links (their tasks and their
//! waits) once, and the session owns what it declared over them once
//! (`docs/c-abi-architecture.md`, P1 and P2).
//!
//! Every table here is reserved when the supervisor is made, for as many faces, ports and waits as
//! the session's open admits, and none grows after: a face or a dial past the room is refused
//! (P3).

use alloc::vec::Vec;
use core::mem::MaybeUninit;
use core::ops::Deref;

#[cfg(feature = "session-unicast-accept")]
use wz_session_core::bounded::Static;
use wz_session_core::bounded::{push_text, BoundedVec, Lent};
use wz_session_core::caps;
use wz_session_core::close_reason::CloseReason;
use wz_session_core::driver_loop::DriverOutcome;
use wz_session_core::link_life::{LinkInput, LinkPhase, LinkRole, UnicastLink};
use wz_session_core::locator_directory::LocatorText;
use wz_session_core::session_zid::SessionZid;
use wz_session_core::zid_hex::same_zid;

use crate::link_cells::{CellRc, CountKind, FaceHeld, FaceParts, OneTask};
use crate::session_drive::{
    LinkOpenError, LinkWait, LinkWaits, Locator, OpenedLink, PendingDial, SessionDatagramLink,
    SessionLinks, WaitOn,
};
use crate::sync::{AtSeat, FacePlace, Lend, LockKind, SeatOf};
use crate::CoopLocalJoinHandle;
use core::sync::atomic::{fence, AtomicU32, Ordering};

/// The number a session knows one of its faces by.
pub type FaceId = u64;

/// How long a read waits, at most, before it asks a dial under way again, in milliseconds: the
/// stack gives no wait for a connection being made, so the dial is looked at on this tick.
pub const DIAL_LOOK_MS: u64 = 1;

/// What the driver asks of the session's half of a link.
pub trait FaceSession {
    /// Whether the link's handshake has completed.
    fn established(&self) -> bool;

    /// The node the link reaches, as far as the link knows it; `None` before it is told. Read in
    /// place: a link is taken, and its node asked, after the session's open.
    fn node(&self) -> Option<SessionZid>;

    /// The link ends: an established peer is told so.
    fn end(&self);

    /// The reason of the Close the link's peer sent, once it sent one.
    fn close_reason(&self) -> Option<CloseReason>;

    /// What a wait over the link's input found in its stack, `ready` or not, or, `true`, that the
    /// session's links moved since ([`LinkSupervisor::links_moved`]). Told only of a link its
    /// owner waits on. A link whose step passes over a stack that gave nothing reads it again once
    /// told `true`, so a step reads only the stacks a wait found input in. The provided form
    /// keeps nothing: the link is read at every step.
    #[cfg(any(feature = "listen", feature = "group"))]
    fn input_seen(&self, ready: bool) {
        let _ = ready;
    }
}

/// One face as the session keeps it: the face's number and its link, beside whatever else the
/// session keeps of the face. The supervisor reads and replaces the link alone.
pub trait FaceRecord<N: CountKind = OneTask> {
    /// What the face holds of its link while the link is up or in its handshake ([`FaceWire`]):
    /// the link's parts themselves ([`Wire`]), or a handle on the place they lie in apart from
    /// the session's state.
    type Wire: FaceWire;

    /// What the drive loop pumps for the face's link, which a dial under way makes.
    type Pump;

    /// A dial under way of the face's link ([`SessionLinks::Dial`]).
    type Dial: PendingDial<Self::Pump, N>;

    /// The face's number.
    fn id(&self) -> FaceId;

    /// The face's link.
    fn link(&self) -> &Link<Self::Wire, Self::Dial>;

    /// The face's link, to replace.
    fn link_mut(&mut self) -> &mut Link<Self::Wire, Self::Dial>;

    /// The life of the face's link: where it stands, the one state of it the session keeps.
    fn life(&self) -> &UnicastLink;

    /// The life of the face's link, to give an input.
    fn life_mut(&mut self) -> &mut UnicastLink;

    /// The face's link while it is established: what the session's sends go through.
    fn up(&self) -> Option<&Self::Wire> {
        if self.life().phase() == LinkPhase::Up {
            self.link().wire()
        } else {
            None
        }
    }
}

/// What the supervisor reads of a face's link while it is up or in its handshake, and how it ends
/// it: the session's half of it ([`FaceSession`]), the end of its session ([`LinkEnd`]), and
/// what its owner waits on for its input and its room.
pub trait FaceWire: FaceSession {
    /// Whether the link's session has ended.
    fn finished(&self) -> bool;

    /// End the link's session, whatever it is doing.
    fn abort(&self);

    /// Whether the link holds input it has already taken from its stack.
    fn holds_input(&self) -> bool;

    /// Whether the link owes its stack the rest of a frame it was handed.
    fn owes_write(&self) -> bool;

    /// Whether the link has input in its stack it cannot read until another link gives a receive
    /// buffer back.
    fn waits_for_buffer(&self) -> bool;

    /// What a wait for the link's input waits on, when its stack gives one.
    fn input_wait(&self) -> Option<WaitOn>;

    /// What a wait for room on the link waits on, when its stack gives one.
    fn room_wait(&self) -> Option<WaitOn>;

    /// Have the link write what it owes its stack, as far as the stack takes it now.
    #[cfg(feature = "session-unicast-accept")]
    fn write_owed_now(&self);

    /// Tell an established peer the link ends ([`FaceSession::end`]); a link not established
    /// is told nothing.
    fn close(&self) {
        if self.established() {
            self.end();
        }
    }
}

/// How a face's owner tells that the session of a link ended, and ends it ([`Wire`]). A
/// link whose session runs as a task of the session's set ends with its task ([`TaskEnd`]); a
/// link whose session its owner steps itself ends as the owner's last step of it said, and is
/// let go of by the owner once no step of it is under way.
pub trait LinkEnd {
    /// Whether the link's session has ended.
    fn finished(&self) -> bool;

    /// End the link's session, whatever it is doing. One a step of its owner is running ends
    /// once that step has returned.
    fn abort(&self);
}

/// The end of a link whose session runs as a task of the session's set: the task's handle.
pub type TaskEnd = CoopLocalJoinHandle<DriverOutcome>;

impl LinkEnd for TaskEnd {
    fn finished(&self) -> bool {
        self.is_finished()
    }

    fn abort(&self) {
        CoopLocalJoinHandle::abort(self);
    }
}

/// One link of a face: the session's half of it (`S`), how its session ends (`E`, [`LinkEnd`]),
/// the link as the session's step reads it, and what its owner waits on for its input and its
/// room, read off the link when it is made. It reads as the session's half (`Deref`): what the
/// session sends over the link is that half's.
pub struct Wire<S, E = TaskEnd, N: CountKind = OneTask> {
    session: S,
    end: E,
    link: CellRc<dyn SessionDatagramLink, N>,
    input: Option<WaitOn>,
    room: Option<WaitOn>,
}

/// Whether `link` has input in its stack it cannot read until another link gives a receive buffer
/// back (`SessionDatagramLink::waits_for_buffer`): never in a build that only dials, whose links
/// read into buffers of their own.
fn waits_for_buffer<N: CountKind>(link: &CellRc<dyn SessionDatagramLink, N>) -> bool {
    #[cfg(feature = "session-unicast-accept")]
    {
        link.waits_for_buffer()
    }
    #[cfg(not(feature = "session-unicast-accept"))]
    {
        let _ = link;
        false
    }
}

impl<S, E: LinkEnd, N: CountKind> Wire<S, E, N> {
    /// The link whose session half is `session`, ended by `end`: `link` is what the session's
    /// step reads, behind whatever gates the session put on it, and `input_wait` and `room_wait`
    /// what its owner waits on for its input and its room, read off the link without the gates
    /// ([`SessionDatagramLink::input_wait`], [`SessionDatagramLink::room_wait`]).
    pub fn new(
        session: S,
        end: E,
        link: CellRc<dyn SessionDatagramLink, N>,
        input_wait: Option<WaitOn>,
        room_wait: Option<WaitOn>,
    ) -> Self {
        Self {
            session,
            end,
            link,
            input: input_wait,
            room: room_wait,
        }
    }

    /// Whether the link's session has ended ([`LinkEnd::finished`]).
    pub fn finished(&self) -> bool {
        self.end.finished()
    }

    /// End the link's session ([`LinkEnd::abort`]).
    pub fn abort(&self) {
        self.end.abort();
    }

    /// Whether the link holds input it has already taken from its stack.
    pub fn holds_input(&self) -> bool {
        self.link.holds_input()
    }

    /// Whether the link owes its stack the rest of a frame it was handed.
    pub fn owes_write(&self) -> bool {
        self.link.owes_write()
    }

    /// What a wait for room on the link waits on, when its stack gives one.
    pub fn room_wait(&self) -> Option<WaitOn> {
        self.room
    }
}

impl<S, E, N: CountKind> Deref for Wire<S, E, N> {
    type Target = S;

    fn deref(&self) -> &S {
        &self.session
    }
}

impl<S: FaceSession, E, N: CountKind> FaceSession for Wire<S, E, N> {
    fn established(&self) -> bool {
        self.session.established()
    }

    fn node(&self) -> Option<SessionZid> {
        self.session.node()
    }

    fn end(&self) {
        self.session.end();
    }

    fn close_reason(&self) -> Option<CloseReason> {
        self.session.close_reason()
    }

    #[cfg(any(feature = "listen", feature = "group"))]
    fn input_seen(&self, ready: bool) {
        self.session.input_seen(ready);
    }
}

impl<S: FaceSession, E: LinkEnd, N: CountKind> FaceWire for Wire<S, E, N> {
    fn finished(&self) -> bool {
        self.end.finished()
    }

    fn abort(&self) {
        self.end.abort();
    }

    fn holds_input(&self) -> bool {
        self.link.holds_input()
    }

    fn owes_write(&self) -> bool {
        self.link.owes_write()
    }

    fn waits_for_buffer(&self) -> bool {
        waits_for_buffer(&self.link)
    }

    fn input_wait(&self) -> Option<WaitOn> {
        self.input
    }

    fn room_wait(&self) -> Option<WaitOn> {
        self.room
    }

    #[cfg(feature = "session-unicast-accept")]
    fn write_owed_now(&self) {
        self.link.write_owed_now();
    }
}

/// A face's link through which the session's half of the link is lent to a send: the session
/// itself where the face's record holds it ([`Wire`]), or a try of the place that holds it apart
/// from the session's state ([`FaceAt`]). The send is `Send`, since the place may be one another
/// thread lent last, and it is never waited for: what it could not send is owed ([`Self::owe`]).
pub trait LendsSession: FaceWire {
    /// The session's half of the link.
    type Session;

    /// `f` on the session when it is reached now; [`Lend::Held`], with `f` not run, while
    /// another holder has the link's place, and [`Lend::Empty`] while the place holds no session.
    fn try_session<U: Send>(&self, f: impl FnOnce(&Self::Session) -> U + Send) -> Lend<U>;

    /// Owe the link's parts `debts` ([`FaceSite::owe`]): what a send found held.
    fn owe(&self, debts: u32);
}

impl<S: FaceSession, E: LinkEnd, N: CountKind> LendsSession for Wire<S, E, N> {
    type Session = S;

    fn try_session<U: Send>(&self, f: impl FnOnce(&S) -> U + Send) -> Lend<U> {
        Lend::Lent(f(&self.session))
    }

    // The session lies in the record, under the session's lock with the caller: never held by
    // another, so a send never owes it anything.
    fn owe(&self, _debts: u32) {}
}

/// The parts of one face's link that the face's place holds ([`FaceSite`]), read as the link's
/// wire while the link is up or in its handshake, and paid what handles on the link owed them.
pub trait WireParts: FaceParts {
    /// The wire the parts hold.
    type Wire: FaceWire;

    /// The parts' wire, while they hold one.
    fn wire(&self) -> Option<&Self::Wire>;

    /// Pay `owed`, debts the parts define (bits within [`PARTS_DEBTS`], never none) that were
    /// owed to the place while it was held ([`FaceSite::owe`]), with the parts lent. Takes no
    /// lock of the session: the place's holder may hold that lock, or wait for it while it holds
    /// the place, so a debt that needs the session's state is marked in the parts, and the
    /// holder that finds the mark carries it out under that lock.
    fn pay(&mut self, owed: u32);
}

/// Parts of a face's link that a send writes through a part of their own (the actions' send path
/// and the link's sink), apart from the part a read borrows: what a send seated by the read
/// ([`FaceSite::lend_seating`]) or lent the parts writes ([`FaceSite::send`]).
pub trait SendParts: WireParts {
    /// The part a send writes.
    type Tx;

    /// The part a send writes of these parts.
    fn tx(&mut self) -> &mut Self::Tx;

    /// The wire `tx` holds, where the send part is the parts' wire: what a lend of the link's
    /// session made through this thread's seat reaches ([`FaceAt`]'s
    /// [`LendsSession::try_session`]). `None` while it holds none, or where the send part is
    /// not the wire.
    fn wire_of(tx: &Self::Tx) -> Option<&Self::Wire>;
}

/// The bit of a site's debts that is its link's close: told through the wire's own close
/// ([`FaceWire::close`]), so why the link closes is the wire's to say, and nowhere else.
const CLOSE_OWED: u32 = 1 << 31;

/// The bits of a site's debts its parts define, and are paid ([`WireParts::pay`]).
pub const PARTS_DEBTS: u32 = CLOSE_OWED - 1;

/// A face's place for the parts of its link, apart from the session's state, and what the
/// handles on the link ([`FaceAt`]) and the session owe it: a close, and the parts' own debts,
/// owed by whoever could not lend the place because another holder had it. Every lend of the
/// parts goes through [`Self::lend`] or [`Self::try_lend`], which pay what is owed before they
/// let go of the place, so a debt is paid once, by whichever holder pays it.
pub struct FaceSite<K: LockKind, P: WireParts> {
    place: FacePlace<K, FaceHeld<P>>,
    /// What is owed to the parts the place holds: [`PARTS_DEBTS`] bits and [`CLOSE_OWED`].
    owed: AtomicU32,
}

impl<K: LockKind, P: WireParts> FaceSite<K, P> {
    /// A place that holds no parts yet, owing nothing.
    pub fn empty() -> Self {
        Self {
            place: FacePlace::empty(),
            owed: AtomicU32::new(0),
        }
    }

    /// Put `parts` in the place, as the face's link is made, and answer the parts it held. What
    /// was owed to the link the place held is not the new link's.
    pub fn hold(&self, parts: FaceHeld<P>) -> Option<FaceHeld<P>> {
        self.owed.store(0, Ordering::SeqCst);
        self.place.hold(parts)
    }

    /// Take the parts out of the place, as the face goes; `None` when it held none.
    pub fn take(&self) -> Option<FaceHeld<P>> {
        self.place.take()
    }

    /// Lend the parts to `f`, waiting for whatever holds the place now ([`FacePlace::lend`]),
    /// and pay what is owed before letting go. `None`, with `f` not run, while the place holds
    /// no parts.
    pub fn lend<U>(&self, f: impl FnOnce(&mut FaceHeld<P>) -> U) -> Option<U> {
        let answer = self.place.lend(|held| {
            let answer = f(held);
            self.pay(held);
            answer
        });
        self.pay_after();
        answer
    }

    /// [`Self::lend`], with the place's seat for the parts' send part ([`SeatOf`]): the holder
    /// seats that part once it reaches it in the parts, so a send this thread makes while the
    /// part is seated (a callback of what the holder hands out) writes it with no lend.
    pub fn lend_seating<U>(
        &self,
        f: impl FnOnce(&mut FaceHeld<P>, SeatOf<'_, K, P::Tx>) -> U,
    ) -> Option<U>
    where
        P: SendParts,
    {
        let seat = self.place.seat_of::<P::Tx>();
        self.lend(|held| f(held, seat))
    }

    /// Send on the link: through the send part this thread seated ([`Self::lend_seating`]),
    /// else by a lend of the parts that waits for whatever holds the place now ([`Self::lend`]),
    /// paying what is owed as it lets go. `f` and its answer are `Send`, as every lend of the
    /// parts' own is ([`FaceHeld::lend`]), so no handle on a cell of the link leaves through it.
    /// `None`, with `f` not run, while the place holds no parts, or for a send inside a send
    /// through the seat, which a debug build fails.
    pub fn send<U: Send>(&self, f: impl FnOnce(&mut P::Tx) -> U + Send) -> Option<U>
    where
        P: SendParts,
    {
        // SAFETY: the place's seats are made by `Self::lend_seating` alone, each over `P::Tx`.
        match unsafe { self.place.at_seat_of::<P::Tx>() } {
            AtSeat::Taken(mut taken) => Some(f(taken.tx())),
            AtSeat::InUse => None,
            AtSeat::None => self.lend(|held| held.lend(|parts| f(parts.tx()))),
        }
    }

    /// [`Self::lend`] that waits for nothing ([`FacePlace::try_lend`]).
    pub fn try_lend<U>(&self, f: impl FnOnce(&mut FaceHeld<P>) -> U) -> Lend<U> {
        let answer = self.place.try_lend(|held| {
            let answer = f(held);
            self.pay(held);
            answer
        });
        self.pay_after();
        answer
    }

    /// Owe the parts `debts`, bits within [`PARTS_DEBTS`] ([`WireParts::pay`]): paid at once
    /// when the place is free now, else by its holder as it lets go, the calling thread's own
    /// hold included. Debts owed again before they are paid are paid as one; debts owed to a place
    /// that holds no parts are let go of, as there is no link to owe them to.
    pub fn owe(&self, debts: u32) {
        debug_assert_eq!(
            debts & CLOSE_OWED,
            0,
            "a debt of the parts in the bit of the site's close"
        );
        self.owe_bits(debts & PARTS_DEBTS);
    }

    /// Close the link: owed, and paid at once when the place is lent now, else by its holder
    /// as it lets go. Two closes owed before one is paid are told as one.
    fn close_or_owe(&self) {
        self.owe_bits(CLOSE_OWED);
    }

    /// Owe `bits` of the debt word, and pay them now when the place is free.
    fn owe_bits(&self, bits: u32) {
        if bits == 0 {
            return;
        }
        self.owed.fetch_or(bits, Ordering::SeqCst);
        // A read of this thread seated in the place holds it, and pays as it lets go: the try is
        // left to a thread that stands in no seat, so a kind whose try is its take never nests.
        if self.place.seated_here() {
            return;
        }
        // Paid as the try lets go, or, the place held, by the holder or by the try's look after;
        // a place with no parts has no link to owe them to.
        if let Lend::Empty = self.try_lend(|_| ()) {
            self.owed.fetch_and(!bits, Ordering::SeqCst);
        }
    }

    /// Pay what is owed through `held`, which the caller holds lent from this site: the one
    /// place a debt is paid, so each is paid once. Every lend pays as it lets go; a holder that
    /// acts on what its parts were paid pays first, so that it acts on the debts owed until then.
    pub fn pay(&self, held: &mut FaceHeld<P>) {
        let owed = self.owed.swap(0, Ordering::SeqCst);
        if owed != 0 {
            held.lend(move |parts| pay_parts(parts, owed));
        }
    }

    /// Pay a debt that came after the holder paid and before it let go: neither the holder, which
    /// looked before the debt, nor its debtor, whose try found the place held, would pay it.
    #[inline]
    fn pay_after(&self) {
        // A kind no other thread holds (`LockKind::WAITS`) owes nothing between the holder's pay
        // and its let go: its one thread is the holder's, inside neither.
        if !K::WAITS {
            return;
        }
        // Orders the holder's let go before its look, and the debtor's debt before its try: one
        // of the two sees the other's write, so a debt is never left with neither to pay it.
        fence(Ordering::SeqCst);
        if self.owed.load(Ordering::SeqCst) != 0 {
            let _ = self.place.try_lend(|held| self.pay(held));
        }
    }
}

/// Pay `owed` to `parts`: their own debts, then the close, through their wire when they hold one
/// ([`FaceWire::close`]), last, so the debts are paid to the link they were owed to.
fn pay_parts<P: WireParts>(parts: &mut P, owed: u32) {
    let debts = owed & PARTS_DEBTS;
    if debts != 0 {
        parts.pay(debts);
    }
    if let Some(wire) = parts.wire().filter(|_| owed & CLOSE_OWED != 0) {
        wire.close();
    }
}

/// A face's link whose parts lie in a face's place ([`FaceSite`]), apart from the session's
/// state: what the face's record holds while the link is up or in its handshake, holding no
/// handle on the parts.
///
/// The supervisor reads it under the session's lock, which never waits on a face, so each read
/// tries the place and waits for nothing: a place another thread holds, or one that holds no
/// wire, reads as a link that holds no input, owes no write, is not established, names no node
/// and no Close, and is told nothing; its next look reads it again. A close it cannot tell then is
/// owed to the place's holder, which tells it before letting go. A wait on the link's input and
/// room is read off the link once, when it is made, and how its session ends is read and asked
/// through its end (`E`), with no lend of the place.
pub struct FaceAt<K: LockKind, P: WireParts, E: LinkEnd> {
    site: core::ptr::NonNull<FaceSite<K, P>>,
    end: E,
    input: Option<WaitOn>,
    room: Option<WaitOn>,
}

impl<K: LockKind, P: WireParts, E: LinkEnd> FaceAt<K, P, E> {
    /// The link whose parts lie in `site`, ended by `end`, waited on by `input` for its input
    /// and by `room` for its room.
    ///
    /// # Safety
    ///
    /// `site` lives, at the address it has now, for as long as the handle does. A read made
    /// inside a lend of `site` reads the link as quiet: inside a read seated in the place by its
    /// seat, elsewhere by the place found held, which a kind whose try is its take
    /// ([`crate::sync::ConfinedOwner::TRIED_INSIDE`]) never finds, so no such read is made there.
    pub unsafe fn new(
        site: &FaceSite<K, P>,
        end: E,
        input: Option<WaitOn>,
        room: Option<WaitOn>,
    ) -> Self {
        Self {
            site: core::ptr::NonNull::from(site),
            end,
            input,
            room,
        }
    }

    /// The site the parts lie in.
    fn site(&self) -> &FaceSite<K, P> {
        // SAFETY: the site outlives the handle where it was when the handle was made
        // (`Self::new`'s contract).
        unsafe { self.site.as_ref() }
    }

    /// `f` on the wire of the parts when the place lends them now, else `absent`.
    fn read<U: Send>(&self, absent: U, f: impl FnOnce(&P::Wire) -> U + Send) -> U {
        let site = self.site();
        // A read of this thread seated in the place holds it: tried, a kind whose try is its take
        // would lend the parts a second time.
        if site.place.seated_here() {
            return absent;
        }
        match site.try_lend(|held| held.lend(|parts| parts.wire().map(f))) {
            Lend::Lent(Some(answer)) => answer,
            Lend::Lent(None) | Lend::Empty | Lend::Held => absent,
        }
    }
}

impl<K: LockKind, P: WireParts, E: LinkEnd> FaceSession for FaceAt<K, P, E> {
    fn established(&self) -> bool {
        self.read(false, |wire| wire.established())
    }

    fn node(&self) -> Option<SessionZid> {
        self.read(None, |wire| wire.node())
    }

    /// Told as a close ([`FaceWire::close`]): the end of an established link, owed to the
    /// place's holder when another thread holds it.
    fn end(&self) {
        self.site().close_or_owe();
    }

    fn close_reason(&self) -> Option<CloseReason> {
        self.read(None, |wire| wire.close_reason())
    }

    #[cfg(any(feature = "listen", feature = "group"))]
    fn input_seen(&self, ready: bool) {
        self.read((), move |wire| wire.input_seen(ready));
    }
}

impl<K: LockKind, P: WireParts, E: LinkEnd> FaceWire for FaceAt<K, P, E> {
    fn finished(&self) -> bool {
        self.end.finished()
    }

    fn abort(&self) {
        self.end.abort();
    }

    fn holds_input(&self) -> bool {
        self.read(false, |wire| wire.holds_input())
    }

    fn owes_write(&self) -> bool {
        self.read(false, |wire| wire.owes_write())
    }

    fn waits_for_buffer(&self) -> bool {
        self.read(false, |wire| wire.waits_for_buffer())
    }

    fn input_wait(&self) -> Option<WaitOn> {
        self.input
    }

    fn room_wait(&self) -> Option<WaitOn> {
        self.room
    }

    /// The establishment is read by the holder that tells the close, so a link another thread
    /// holds now is closed once it lets go, as far as it is established then.
    fn close(&self) {
        self.site().close_or_owe();
    }

    #[cfg(feature = "session-unicast-accept")]
    fn write_owed_now(&self) {
        self.read((), |wire| wire.write_owed_now());
    }
}

/// A send made inside the holder's own step on this thread (a callback of what the holder hands
/// out) reaches the session through the send part the holder seated ([`FaceSite::lend_seating`]),
/// with no try of the place the holder holds; any other tries the place.
impl<K: LockKind, P: SendParts, E: LinkEnd> LendsSession for FaceAt<K, P, E>
where
    P::Wire: LendsSession,
{
    type Session = <P::Wire as LendsSession>::Session;

    fn try_session<U: Send>(&self, f: impl FnOnce(&Self::Session) -> U + Send) -> Lend<U> {
        let site = self.site();
        // SAFETY: the place's seats are made by `FaceSite::lend_seating` alone, each over `P::Tx`.
        match unsafe { site.place.at_seat_of::<P::Tx>() } {
            AtSeat::Taken(mut taken) => {
                P::wire_of(taken.tx()).map_or(Lend::Empty, |wire| wire.try_session(f))
            }
            AtSeat::InUse => Lend::Held,
            AtSeat::None => match site
                .try_lend(|held| held.lend(|parts| parts.wire().map(|wire| wire.try_session(f))))
            {
                Lend::Lent(Some(lent)) => lent,
                Lend::Lent(None) | Lend::Empty => Lend::Empty,
                Lend::Held => Lend::Held,
            },
        }
    }

    fn owe(&self, debts: u32) {
        self.site().owe(debts);
    }
}

/// What a face holds for its link: nothing, a dial under way, or the link a dial made or a port
/// gave. Where the link stands (dialled, in its handshake, up, waiting, standing by) is the face's
/// life's alone ([`FaceRecord::life`]); this is the I/O that life asks for. A dial under way is
/// held in its face's link, so a face has one dial at most and the faces' table is the dials'
/// table too.
pub enum Link<W, D> {
    /// No link: not dialled yet, between two dials, waiting to dial again, or standing by.
    Idle,
    /// A dial under way, asked at each move of the face ([`Dial::answer`]).
    Dialing(Dial<D>),
    /// A link in its handshake or established: the session's sends go through it once it is up.
    Wire(W),
}

impl<W, D> Link<W, D> {
    /// The link's wire while it is in its handshake or up.
    pub fn wire(&self) -> Option<&W> {
        match self {
            Link::Wire(wire) => Some(wire),
            _ => None,
        }
    }
}

/// The texts of the endpoints a session dials and listens on, each written once when the session
/// opens into a row of the memory it reserved then (`docs/c-abi-architecture.md`, P1 and P3):
/// a dial or a port names its endpoint by its row, and nothing copies the text after the open.
/// The dial rows are at most the build's `MAX_STATIC_CONNECT`, and the listen rows at most its
/// `MAX_ADMIN_LOCATORS`, the listening locators a node holds, which the session's plan holds each
/// count to before it lends the rows; each row at most `MAX_LOCATOR_LEN` bytes.
pub struct EndpointTexts {
    dial: EndpointRows,
    listen: EndpointRows,
}

/// The rows of one role's endpoint texts ([`EndpointTexts`]). The two roles' tables are one type,
/// bounded by the larger of their two limits, so one body writes and reads either.
pub type EndpointRows = BoundedVec<LocatorText, ENDPOINT_TEXT_ROWS, Lent>;

/// The most rows of either role's endpoint texts a build lends: the larger of
/// `MAX_STATIC_CONNECT` and `MAX_ADMIN_LOCATORS`.
pub const ENDPOINT_TEXT_ROWS: usize = if caps::MAX_STATIC_CONNECT > caps::MAX_ADMIN_LOCATORS {
    caps::MAX_STATIC_CONNECT
} else {
    caps::MAX_ADMIN_LOCATORS
};

/// Which of a session's endpoints a text is: one it dials, or one it listens on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointRole {
    /// An endpoint the session dials.
    Dial,
    /// An endpoint the session listens on.
    Listen,
}

/// Why an endpoint's text has no row ([`EndpointTexts::write`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointTextRefused {
    /// The text is longer than a row, `MAX_LOCATOR_LEN` bytes; `len` is its length.
    TooLong {
        /// The text's length in bytes.
        len: usize,
    },
    /// Every row the session reserved for its endpoints holds one already.
    Full,
}

impl EndpointTexts {
    /// The texts of a session whose open lent `dial` for its endpoints to dial and `listen` for
    /// those to listen on, none written yet.
    pub fn over(dial: EndpointRows, listen: EndpointRows) -> Self {
        Self { dial, listen }
    }

    /// Write the text of the next endpoint of `role`, in the order the session dials them or
    /// listens on them: its place, which a dial names it by ([`DialEndpoint::Listed`]) or a port
    /// by (`DialEndpoint::Port`, with `listen`).
    #[inline(never)]
    pub fn write(&mut self, role: EndpointRole, text: &str) -> Result<usize, EndpointTextRefused> {
        let rows = match role {
            EndpointRole::Dial => &mut self.dial,
            EndpointRole::Listen => &mut self.listen,
        };
        // One copy, all or nothing, and not heapless's append of a byte at a time.
        let mut row = LocatorText::new();
        push_text(&mut row, text).map_err(|_| EndpointTextRefused::TooLong { len: text.len() })?;
        let at = rows.len();
        rows.push(row).map_err(|_| EndpointTextRefused::Full)?;
        Ok(at)
    }

    /// [`Self::write`] of an endpoint to dial.
    #[inline]
    pub fn write_dial(&mut self, text: &str) -> Result<usize, EndpointTextRefused> {
        self.write(EndpointRole::Dial, text)
    }

    /// [`Self::write`] of an endpoint to listen on.
    #[inline]
    pub fn write_listen(&mut self, text: &str) -> Result<usize, EndpointTextRefused> {
        self.write(EndpointRole::Listen, text)
    }

    /// The text of the endpoint of `role` at `at`; empty past the last.
    #[inline(never)]
    pub fn text(&self, role: EndpointRole, at: usize) -> &str {
        let rows = match role {
            EndpointRole::Dial => &self.dial,
            EndpointRole::Listen => &self.listen,
        };
        rows.get(at).map_or("", LocatorText::as_str)
    }

    /// The text of the endpoint to dial at `at`; empty past the last.
    #[inline]
    pub fn dial_text(&self, at: usize) -> &str {
        self.text(EndpointRole::Dial, at)
    }

    /// The text of the endpoint to listen on at `at`; empty past the last.
    #[inline]
    pub fn listen_text(&self, at: usize) -> &str {
        self.text(EndpointRole::Listen, at)
    }

    /// How many endpoints the session dials.
    pub fn dials(&self) -> usize {
        self.dial.len()
    }

    /// How many endpoints the session listens on.
    pub fn listens(&self) -> usize {
        self.listen.len()
    }
}

/// Which endpoint a dial reaches: one of the session's own to dial, by its row; one of those it
/// listens on, by its row, for a link taken off that port; or one named by whoever asked for the
/// dial after the open, its text held by the dial alone. None allocates. A build without
/// `listen` takes no port and dials no face beside the dial role's, so its endpoint is a row
/// alone: every dial, link and refusal that carries one moves a word, not a text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialEndpoint {
    /// The endpoint to dial in this row of the session's texts.
    Listed(usize),
    /// The endpoint to listen on in this row of the session's texts.
    #[cfg(feature = "listen")]
    Port(usize),
    /// An endpoint named apart from the session's texts.
    #[cfg(feature = "listen")]
    Named(LocatorText),
}

impl DialEndpoint {
    /// The endpoint's text, read in `texts`, the session's; a row past the last reads empty.
    pub fn text<'a>(&'a self, texts: &'a EndpointTexts) -> &'a str {
        match self {
            DialEndpoint::Listed(at) => texts.dial_text(*at),
            #[cfg(feature = "listen")]
            DialEndpoint::Port(at) => texts.listen_text(*at),
            #[cfg(feature = "listen")]
            DialEndpoint::Named(text) => text,
        }
    }
}

/// A face's dial under way: the endpoint it dials, and the network's answer still to come, the
/// stack's own dial `D` held by value.
pub struct Dial<D> {
    endpoint: DialEndpoint,
    pending: D,
}

impl<D> Dial<D> {
    /// The dial `pending` of `endpoint`.
    pub fn new(endpoint: DialEndpoint, pending: D) -> Self {
        Self { endpoint, pending }
    }

    /// The endpoint dialled.
    pub fn endpoint(&self) -> &DialEndpoint {
        &self.endpoint
    }

    /// Let go of the dial, with what it held for its link, keeping the endpoint it dialled.
    pub fn into_endpoint(self) -> DialEndpoint {
        self.endpoint
    }

    /// Ask the dial whether its link is made: the link, the refusal, or `None` while it is still
    /// being made. What a session's driver reads of a dial at each move of its face
    /// ([`LinkSupervisor::read_face`]).
    pub fn answer<P, N: CountKind>(&mut self) -> Option<Result<OpenedLink<P, N>, LinkOpenError>>
    where
        D: PendingDial<P, N>,
    {
        self.pending.poll()
    }
}

/// The answer of a face's dial under way: the link it made, the refusal, or `None` while it is
/// still being made.
pub type DialAnswer<P, N = OneTask> = Option<Result<OpenedLink<P, N>, LinkOpenError>>;

/// What a session reads of a face at a step ([`LinkSupervisor::read_face`]): its role, where its
/// link stands, and what it did since. The answer of its dial, kept for the link it made, is
/// written where the reader asked for it, so a step that reads an established face moves no
/// room for a link it does not have.
pub struct FaceRead {
    /// Which face it is: the dial role's, or one taken besides.
    pub role: LinkRole,
    /// What the face's link came to since it was last read, as its life's input.
    pub input: LinkInput,
}

/// Why the handshake of a face ended ([`LinkSupervisor::handshake_end`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeEnd {
    /// The peer sent a Close, with this reason.
    Closed(CloseReason),
    /// The link's task ended with no Close.
    Ended,
    /// The handshake was still under way when it was given up.
    NoAnswerInTime,
}

/// A port the session listens on, and the row of the endpoint its links are stated for, when the
/// session states one. A build without `listen` opens no port, so it holds none of them.
#[cfg(feature = "listen")]
struct Listening<P, N: CountKind> {
    listener: alloc::boxed::Box<dyn crate::session_drive::LinkListener<P, N>>,
    endpoint: Option<usize>,
    /// What the port gave the last read's wait to wait on, when the port is asked for a
    /// connection only once a wait found it ready (`LinkListener::asked_when_ready`); `None` for
    /// a port asked at every step.
    on: Option<WaitOn>,
    /// Whether a wait found the port ready since it last had no connection to give.
    ready: bool,
}

/// What a link taken off a port came to ([`LinkSupervisor::accept_at`]).
#[cfg(feature = "listen")]
pub enum Accepted<P, N: CountKind = OneTask> {
    /// A connection, with the endpoint its port is stated for.
    Link(OpenedLink<P, N>, Option<DialEndpoint>),
    /// No connection waits on the port now, no wait found it ready since it last had none, or the
    /// stack had nothing left to take one with.
    Idle,
    /// The port is broken for good, and let go of.
    Broken,
}

/// Put `wait` in `waits` within the room reserved for it, or say there was none: the buffer is
/// never grown, so a read after the open allocates nothing.
fn put_wait(waits: &mut Vec<LinkWait>, wait: LinkWait) -> bool {
    let len = waits.len();
    let Some(row) = waits.spare_capacity_mut().first_mut() else {
        return false;
    };
    row.write(wait);
    // SAFETY: the row past the last one was written just above, and lies within the capacity.
    // A spare row exists, so `len` is below the capacity and one more does not overflow.
    unsafe { waits.set_len(len.saturating_add(1)) };
    true
}

/// What a read waits for before it steps the session, with nothing of the session held.
pub enum IdleWait {
    /// Nothing: a link holds input already, or its own loop waits for it.
    None,
    /// The next input of any of these links, or the next connection on any of these ports, or
    /// room on a link that asks for it as well, or a wake of their stack's waited on beside them,
    /// for at most `ms` milliseconds.
    Input {
        /// The links, ports and wakes waited on.
        on: Vec<LinkWait>,
        /// The longest the wait takes.
        ms: u32,
    },
    /// Nothing to wait on: the next dial, or the next look at a port that gives no wait, for at
    /// most this many milliseconds.
    Sleep(u32),
    /// Another read waits on the links with the session's buffer: wait for it to hand the buffer
    /// back ([`LinkSupervisor::waited`]), for at most this many milliseconds. A caller that hears
    /// of no hand-back sleeps for as long.
    Behind(u32),
}

impl IdleWait {
    /// Wait on the links and ports with `waits`, the waits of their stack
    /// ([`SessionLinks::waits`]), sleeping with `sleep` (milliseconds) where there is nothing to
    /// wait on. The wait keeps the session's buffer it was made in, for the session to take back
    /// ([`LinkSupervisor::waited`]): in a build with ports or groups, holding the entries the
    /// stack found ready ([`LinkWaits::wait_ready`]), which only such a build reads; in one
    /// without, as it was made. Out of line: a session's open and each of its reads wait.
    #[inline(never)]
    pub fn wait(&mut self, waits: &impl LinkWaits, sleep: impl FnOnce(u32)) {
        match self {
            IdleWait::None => {}
            IdleWait::Input { on, ms } => {
                #[cfg(any(feature = "listen", feature = "group"))]
                {
                    let ready = waits.wait_ready(on, *ms);
                    on.truncate(ready);
                }
                #[cfg(not(any(feature = "listen", feature = "group")))]
                waits.wait(on, *ms);
            }
            IdleWait::Sleep(ms) | IdleWait::Behind(ms) => sleep(*ms),
        }
    }
}

/// What a publish that waits for an outbound slot waits on ([`LinkSupervisor::owing_waits`]), in
/// the publishing thread's own frame: publishes on several threads may wait at once, each with
/// nothing of the session held, so none shares a buffer of the session's, and none takes one of
/// the heap. A link owes its stack the rest of a frame only from an outbound slot it holds, so the
/// links that owe are at most the build's `TX_POOL_SLOTS`, and at most the faces a session holds
/// (`MAX_FACES` and the dial role's): a publish waits for a slot only while the slots are fewer.
#[cfg(feature = "session-unicast-accept")]
pub type OwingWaits = BoundedVec<LinkWait, OWING_WAITS, Static>;

/// The room of [`OwingWaits`]: the fewer of the build's outbound slots and its faces.
#[cfg(feature = "session-unicast-accept")]
const OWING_WAITS: usize = {
    let faces = caps::MAX_FACES.saturating_add(1);
    if caps::TX_POOL_SLOTS < faces {
        caps::TX_POOL_SLOTS
    } else {
        faces
    }
};

/// The faces of a session by their places, as its [`LinkSupervisor`] keeps them: the dial role's
/// face at the first place, which is never taken out, and the faces taken beside it each at a
/// place it keeps until it is taken out. The table is made whole when the supervisor is, and none
/// grows after. A session that only dials holds its dial role's face alone, and its table is one
/// face with no places to walk; one that takes faces beside it keeps a place for each.
pub trait FacePlaces<F> {
    /// Whether the table holds faces beside the dial role's. One that does not holds that face
    /// alone, so every face it is asked of is read in that role (`LinkSupervisor::read_face`).
    const TAKES: bool;

    /// The table whose dial role's face is `dial`, at the first place, with `places` places in
    /// all (one at least) where the table keeps more than one.
    fn with_dial(dial: F, places: usize) -> Self;

    /// How many places the table has, held or free.
    fn places(&self) -> usize;

    /// The face at place `at`, while one holds it.
    fn get(&self, at: usize) -> Option<&F>;

    /// The face at place `at`, while one holds it, to change.
    fn get_mut(&mut self, at: usize) -> Option<&mut F>;

    /// The faces in the order of their places, the dial role's first.
    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a F>
    where
        F: 'a;

    /// [`Self::iter`], to change each face.
    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut F>
    where
        F: 'a;

    /// Each face with its place, in the order of their places.
    fn placed<'a>(&'a self) -> impl Iterator<Item = (usize, &'a F)>
    where
        F: 'a;

    /// [`Self::placed`], to change each face.
    fn placed_mut<'a>(&'a mut self) -> impl Iterator<Item = (usize, &'a mut F)>
    where
        F: 'a;

    /// The free place `at`, to put a face in or build one in where it lies; `None` at the dial
    /// role's place, at a place another face holds, and past the table.
    fn vacant(&mut self, at: usize) -> Option<VacantPlace<'_, F>>;

    /// Drop the face at `at` where it lies, its place free from then: whether one was there. The
    /// dial role's is never dropped.
    fn free(&mut self, at: usize) -> bool;

    /// Take out every face but the dial role's.
    fn keep_dial_only(&mut self);
}

/// The faces of a session that takes faces beside its dial role's: a place for each, held or
/// free, made at the open for as many as the session holds at once and never grown. Only the
/// places up to the last one held are kept in the row, the others reserved behind it, so every
/// walk over the faces ends at the last face and passes over no free place past it: a session
/// that keeps places for many faces and holds one or two walks one or two at each step.
pub struct ManyFaces<F> {
    faces: Vec<TablePlace<F>>,
    places: usize,
}

/// A place of [`ManyFaces`]: a face or none, in storage the face is built in where it lies, so
/// a face whose largest part is built in place ([`VacantPlace::fill`]) is moved by nothing.
struct TablePlace<F> {
    held: bool,
    face: MaybeUninit<F>,
}

impl<F> TablePlace<F> {
    /// A place no face holds.
    fn free() -> Self {
        Self {
            held: false,
            face: MaybeUninit::uninit(),
        }
    }

    /// A place that holds `face`.
    fn holding(face: F) -> Self {
        Self {
            held: true,
            face: MaybeUninit::new(face),
        }
    }

    /// The face the place holds.
    fn get(&self) -> Option<&F> {
        // SAFETY: `held` is set only once the face is written whole (`holding`,
        // `VacantPlace::put`, `VacantPlace::fill`), and cleared only where it is dropped.
        self.held.then(|| unsafe { self.face.assume_init_ref() })
    }

    /// The face the place holds, to change.
    fn get_mut(&mut self) -> Option<&mut F> {
        if !self.held {
            return None;
        }
        // SAFETY: as `get`.
        Some(unsafe { self.face.assume_init_mut() })
    }

    /// Drop the face the place holds, where it lies: whether one was there.
    fn clear(&mut self) -> bool {
        if !core::mem::take(&mut self.held) {
            return false;
        }
        // SAFETY: `held` was set, so the face is whole (`get`); it is cleared before the drop,
        // so the face is dropped once.
        unsafe { self.face.assume_init_drop() };
        true
    }
}

impl<F> Drop for TablePlace<F> {
    fn drop(&mut self) {
        self.clear();
    }
}

/// A free place of a face table ([`FacePlaces::vacant`]), to put a face in or build one in where
/// it lies. A place left with no face stays free.
pub struct VacantPlace<'a, F> {
    held: &'a mut bool,
    face: &'a mut MaybeUninit<F>,
}

impl<'a, F> VacantPlace<'a, F> {
    /// Put `face` in the place.
    pub fn put(self, face: F) -> &'a mut F {
        let face = self.face.write(face);
        *self.held = true;
        face
    }

    /// Build a face in the place with `make`, which writes it whole where it lies and lends it,
    /// so no caller moves it. `None`, the place left free, when `make` lends a face it did not
    /// build in the place it was given: safe code lends the place only once it has written it.
    pub fn fill(self, make: impl FnOnce(&mut MaybeUninit<F>) -> &mut F) -> Option<&'a mut F> {
        let at: *const F = self.face.as_ptr();
        let made = make(self.face);
        if !core::ptr::eq(made, at) {
            return None;
        }
        *self.held = true;
        Some(made)
    }
}

impl<F> FacePlaces<F> for ManyFaces<F> {
    const TAKES: bool = true;

    fn with_dial(dial: F, places: usize) -> Self {
        let places = places.max(1);
        let mut faces = Vec::with_capacity(places);
        faces.push(TablePlace::holding(dial));
        Self { faces, places }
    }

    fn places(&self) -> usize {
        self.places
    }

    fn get(&self, at: usize) -> Option<&F> {
        self.faces.get(at)?.get()
    }

    fn get_mut(&mut self, at: usize) -> Option<&mut F> {
        self.faces.get_mut(at)?.get_mut()
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a F>
    where
        F: 'a,
    {
        self.faces.iter().filter_map(TablePlace::get)
    }

    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut F>
    where
        F: 'a,
    {
        self.faces.iter_mut().filter_map(TablePlace::get_mut)
    }

    fn placed<'a>(&'a self) -> impl Iterator<Item = (usize, &'a F)>
    where
        F: 'a,
    {
        self.faces
            .iter()
            .enumerate()
            .filter_map(|(at, place)| Some((at, place.get()?)))
    }

    fn placed_mut<'a>(&'a mut self) -> impl Iterator<Item = (usize, &'a mut F)>
    where
        F: 'a,
    {
        self.faces
            .iter_mut()
            .enumerate()
            .filter_map(|(at, place)| Some((at, place.get_mut()?)))
    }

    fn vacant(&mut self, at: usize) -> Option<VacantPlace<'_, F>> {
        if at == 0 || at >= self.places {
            return None;
        }
        // The free places up to `at` join the row; the room for every place was reserved by
        // `with_dial`, so none allocates. A place left with no face is trimmed with the next
        // face that goes.
        if at >= self.faces.len() {
            self.faces
                .resize_with(at.saturating_add(1), TablePlace::free);
        }
        let place = self.faces.get_mut(at)?;
        if place.held {
            return None;
        }
        Some(VacantPlace {
            held: &mut place.held,
            face: &mut place.face,
        })
    }

    fn free(&mut self, at: usize) -> bool {
        if at == 0 {
            return false;
        }
        let Some(place) = self.faces.get_mut(at) else {
            return false;
        };
        let freed = place.clear();
        // The row ends at the last place still held, the dial role's at the least.
        let held = self
            .faces
            .iter()
            .rposition(|place| place.held)
            .map_or(1, |last| last.saturating_add(1));
        self.faces.truncate(held);
        freed
    }

    fn keep_dial_only(&mut self) {
        self.faces.truncate(1);
    }
}

/// The face of a session that only dials: its dial role's face, always held and never taken
/// out. No face is put beside it, so there is no place to walk, none free and none to look up:
/// every walk over the faces is one face, and the first place is the only one.
pub struct OneFace<F> {
    face: F,
}

impl<F> FacePlaces<F> for OneFace<F> {
    const TAKES: bool = false;

    fn with_dial(dial: F, _places: usize) -> Self {
        Self { face: dial }
    }

    fn places(&self) -> usize {
        1
    }

    fn get(&self, at: usize) -> Option<&F> {
        (at == 0).then_some(&self.face)
    }

    fn get_mut(&mut self, at: usize) -> Option<&mut F> {
        (at == 0).then_some(&mut self.face)
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a F>
    where
        F: 'a,
    {
        core::iter::once(&self.face)
    }

    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut F>
    where
        F: 'a,
    {
        core::iter::once(&mut self.face)
    }

    fn placed<'a>(&'a self) -> impl Iterator<Item = (usize, &'a F)>
    where
        F: 'a,
    {
        core::iter::once((0, &self.face))
    }

    fn placed_mut<'a>(&'a mut self) -> impl Iterator<Item = (usize, &'a mut F)>
    where
        F: 'a,
    {
        core::iter::once((0, &mut self.face))
    }

    fn vacant(&mut self, _at: usize) -> Option<VacantPlace<'_, F>> {
        None
    }

    fn free(&mut self, _at: usize) -> bool {
        false
    }

    fn keep_dial_only(&mut self) {}
}

/// A session's faces, dials and ports over the network `L`, each face kept as the session's
/// record `F` at a place of its own in the table `P`. The first place is the dial role's face's,
/// which is never taken out.
pub struct LinkSupervisor<L: SessionLinks<N>, F, P = ManyFaces<F>, N: CountKind = OneTask> {
    links: L,
    /// The faces by their places, the table made whole at the open for as many places as the
    /// session holds faces at and never grown: a face keeps the place it was put at until it is
    /// taken out, so its place names it for that whole time, and the session names the face's
    /// other tables by the same place. A place no face holds is free for the next.
    faces: P,
    #[cfg(feature = "listen")]
    listeners: Vec<Listening<L::Pump, N>>,
    /// The one buffer a read's waits are gathered in, reserved at the open for every link, port
    /// and wake a read waits on at once; `None` while a read waits with it, so that a read on
    /// another thread then makes no buffer of its own after the open.
    waits: Option<Vec<LinkWait>>,
    next_face: FaceId,
    /// How often a face or a port was reached to be changed, or a port came to be asked: what a
    /// session that moved its links on compares, to move them again only once one may have
    /// changed ([`Self::moves`]). Wraps; only its change is read.
    moves: u32,
    /// The node the dial role's face stands by for while another face holds it: read where its
    /// handshake ended, kept until no other face holds the node. Only the dial role stands by.
    #[cfg(feature = "listen")]
    stood_by: Option<SessionZid>,
    /// How often a face's link was put in, brought up or ended, or a face placed or taken out:
    /// equal at two reads, the faces whose links are up and how each names what it sends are as
    /// they were ([`Self::generation`]). A reach of a face to change what the session keeps of
    /// it, which each step makes, does not count. Wraps; only its change is read.
    generation: u64,
    /// The record each face is kept as, which the table `P` holds, and how its links' handles
    /// are counted (`N`), which a build without `listen` names in no field: the supervisor
    /// names both.
    records: core::marker::PhantomData<fn() -> (F, N)>,
}

impl<
        L: SessionLinks<N>,
        F: FaceRecord<N, Pump = L::Pump, Dial = L::Dial>,
        P: FacePlaces<F>,
        N: CountKind,
    > LinkSupervisor<L, F, P, N>
{
    /// The faces of a session over `links`, `dial` the dial role's at the first place: `places`
    /// places in all (one at least, the dial role's), each face with a dial under way at most, and
    /// `waits` waits a read makes at once, reserved now; `None` when the heap refuses that room,
    /// which an open answers as it answers an arena that cannot be reserved. The ports are the
    /// open's, taken as it listens (`listen`). Faces taken after are numbered from 1.
    pub fn new(links: L, dial: F, places: usize, waits: usize) -> Option<Self> {
        let mut room = Vec::new();
        room.try_reserve_exact(waits).ok()?;
        Some(Self {
            links,
            faces: P::with_dial(dial, places),
            #[cfg(feature = "listen")]
            listeners: Vec::new(),
            waits: Some(room),
            next_face: 1,
            moves: 0,
            generation: 0,
            #[cfg(feature = "listen")]
            stood_by: None,
            records: core::marker::PhantomData,
        })
    }

    /// The network the links are opened on.
    pub fn links(&self) -> &L {
        &self.links
    }

    /// How many places the table has, held or free.
    pub fn places(&self) -> usize {
        self.faces.places()
    }

    /// Whether the table holds faces beside the dial role's ([`FacePlaces::TAKES`]): what only
    /// such a face does, going with its link, and what the dial role's does for a node such a face
    /// holds, standing by, are never asked of a session whose table holds the dial role's alone.
    pub fn takes_faces(&self) -> bool {
        P::TAKES
    }

    /// The face at place `at`, while one holds it.
    pub fn face(&self, at: usize) -> Option<&F> {
        self.faces.get(at)
    }

    /// The face at place `at`, while one holds it, to change what the session keeps of it.
    pub fn face_mut(&mut self, at: usize) -> Option<&mut F> {
        self.moved();
        self.faces.get_mut(at)
    }

    /// The faces in the order of their places, the dial role's first.
    pub fn faces(&self) -> impl Iterator<Item = &F> {
        self.faces.iter()
    }

    /// The faces in the order of their places, to change what the session keeps of each.
    pub fn faces_mut(&mut self) -> impl Iterator<Item = &mut F> {
        self.moved();
        self.faces.iter_mut()
    }

    /// Each face with its place, in the order of their places.
    pub fn placed(&self) -> impl Iterator<Item = (usize, &F)> {
        self.faces.placed()
    }

    /// The table of the faces by their places, for a walk that names a face by its place.
    pub fn places_mut(&mut self) -> &mut P {
        self.moved();
        &mut self.faces
    }

    /// The count of the reaches of a face or a port to change it, and of the ports that came to
    /// be asked, since the session began: equal at two reads, no face and no port was changed
    /// through the supervisor between them, and a face's link moved on only by its task, whose
    /// end the session's runtime counts (`CoopLocalSet::tasks_ended`).
    pub fn moves(&self) -> u32 {
        self.moves
    }

    /// Count one reach of a face or a port to change it ([`Self::moves`]).
    fn moved(&mut self) {
        self.moves = self.moves.wrapping_add(1);
    }

    /// The count of the changes of the faces' links since the session began: what a send planned
    /// over the links that were up reads to know the plan still holds. Equal at two reads, no
    /// face's link was put in, brought up or ended, and no face placed or taken out, between them.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Count one change of the faces' links ([`Self::generation`]).
    fn regenerated(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }

    /// Whether a port is to be asked for a connection at the next step: one asked at every step,
    /// or one a wait found ready (`accept_at`). Never in a build without `listen`, which holds
    /// no port.
    pub fn ports_to_ask(&self) -> bool {
        #[cfg(feature = "listen")]
        {
            self.listeners
                .iter()
                .any(|listening| listening.on.is_none() || listening.ready)
        }
        #[cfg(not(feature = "listen"))]
        {
            false
        }
    }

    /// How many places a face holds, the dial role's among them.
    pub fn held(&self) -> usize {
        self.faces().count()
    }

    /// The number the next face taken is known by.
    pub fn next_face_id(&self) -> FaceId {
        self.next_face
    }

    /// The number [`Self::next_face_id`] answered is taken.
    pub fn advance_face_id(&mut self) {
        self.next_face = self.next_face.saturating_add(1);
    }

    /// Put `face` at the free place `at`, which it keeps until it is dropped; handed back at
    /// the dial role's place, at a place another face holds, and past the table.
    pub fn place_face(&mut self, at: usize, face: F) -> Result<(), F> {
        match self.vacant_place(at) {
            Some(place) => {
                place.put(face);
                Ok(())
            }
            None => Err(face),
        }
    }

    /// The free place `at`, to build a face in where it lies ([`VacantPlace::fill`]), which it
    /// keeps until it is dropped; `None` at the dial role's place, at a place another face holds,
    /// and past the table.
    pub fn vacant_place(&mut self, at: usize) -> Option<VacantPlace<'_, F>> {
        self.moved();
        self.regenerated();
        self.faces.vacant(at)
    }

    /// Drop the face at `at` where it lies, its place free from then: the number it was known by.
    /// The dial role's, at the first, is never dropped. No other face moves.
    pub fn drop_face(&mut self, at: usize) -> Option<FaceId> {
        self.moved();
        self.regenerated();
        let id = self.faces.get(at)?.id();
        self.faces.free(at).then_some(id)
    }

    /// Begin a dial of `to`, which the network answers later.
    /// Out of line: the stack's dial of each protocol is put together here, not in its caller.
    #[inline(never)]
    pub fn begin_dial(&self, to: Locator) -> Result<L::Dial, LinkOpenError> {
        self.links.begin_initiator(to)
    }

    /// Listen on `at`, whose links are stated for the endpoint in row `endpoint` of the session's
    /// texts when the session states one.
    #[cfg(feature = "listen")]
    pub fn listen(&mut self, at: Locator, endpoint: Option<usize>) -> Result<(), LinkOpenError> {
        let listener = self.links.open_listener(at)?;
        self.moved();
        self.listeners.push(Listening {
            listener,
            endpoint,
            on: None,
            ready: false,
        });
        Ok(())
    }

    /// Whether the session listens on any port: never in a build without `listen`.
    pub fn listens(&self) -> bool {
        #[cfg(feature = "listen")]
        {
            !self.listeners.is_empty()
        }
        #[cfg(not(feature = "listen"))]
        {
            false
        }
    }

    /// The locator each port is bound to, with the port the stack chose where 0 was asked for.
    #[cfg(feature = "listen")]
    pub fn listening(&self) -> impl Iterator<Item = Locator> + '_ {
        self.listeners
            .iter()
            .map(|listening| listening.listener.local())
    }

    /// Take a connection off the port at `at`: `None` past the last port. A port broken for good
    /// is let go of, so the port after it is then at `at`.
    #[cfg(feature = "listen")]
    pub fn accept_at(&mut self, at: usize) -> Option<Accepted<L::Pump, N>> {
        let listening = self.listeners.get_mut(at)?;
        // A port a wait names is asked only once a wait found it ready: under a stream of input
        // a step a batch would otherwise ask the stack for a connection that is not there.
        if listening.on.is_some() && !listening.ready {
            return Some(Accepted::Idle);
        }
        Some(match listening.listener.accept() {
            Ok(Some(opened)) => Accepted::Link(opened, listening.endpoint.map(DialEndpoint::Port)),
            Ok(None) => {
                listening.ready = false;
                Accepted::Idle
            }
            // The connection still waits on the port, which the next step asks again.
            Err(LinkOpenError::Exhausted) => Accepted::Idle,
            Err(_) => {
                self.listeners.remove(at);
                Accepted::Broken
            }
        })
    }

    /// Give the face at `at` the link `link`, in place of the one it holds, which is let go of.
    pub fn put_link(&mut self, at: usize, link: Link<F::Wire, L::Dial>) {
        self.regenerated();
        if let Some(face) = self.face_mut(at) {
            *face.link_mut() = link;
        }
    }

    /// Let go of the dial of the face at `at`, which is over: the endpoint it dialled, moved out of
    /// the dial, which the refusal or the link's session names. `None` for a face that held no
    /// dial, whose link is left as it is, and for one past the table. Out of line: a dial that
    /// answered and one that failed are each ended here.
    #[inline(never)]
    pub fn end_dial(&mut self, at: usize) -> Option<DialEndpoint> {
        let link = self.face_mut(at)?.link_mut();
        // Only the endpoint is moved out, and the dial it leaves is let go of where it lies: a
        // link moved out whole is copied to the caller's frame, and its dial again, at each place
        // this is inlined.
        let Link::Dialing(dial) = link else {
            return None;
        };
        let endpoint = core::mem::replace(&mut dial.endpoint, DialEndpoint::Listed(0));
        *link = Link::Idle;
        Some(endpoint)
    }

    /// Ask the dial `pending` of `endpoint`, begun for the face at `at`, once. A dial the network
    /// has not answered yet is put in the face where it lies, and `None` is handed back; one
    /// answered at once is let go of, before its link is opened, and its answer is handed back,
    /// the face keeping what it held. A dial for a face past the table is let go of. The time the
    /// dial is given up at is its face's life's, read once the ask returned, so a host whose ask
    /// blocks (a refused loopback connect on Windows) does not spend the dial's time on it.
    pub fn ask_dial(
        &mut self,
        at: usize,
        endpoint: DialEndpoint,
        mut pending: L::Dial,
    ) -> DialAnswer<L::Pump, N> {
        // A dial that answered has handed out all it held (the socket, the link's buffers, the
        // program's link), and keeps only handles that own nothing, so it is let go of here with
        // nothing to observe: every stack's dial takes those out as it answers.
        if let Some(answer) = pending.poll() {
            return Some(answer);
        }
        // Written into the face from the dial this frame holds, and not handed back through the
        // transport and the session's dial, each of which would move it once more.
        self.put_link(at, Link::Dialing(Dial::new(endpoint, pending)));
        None
    }

    /// The face at `at`, whose handshake completed, holds its link up: the link it holds is the
    /// one its handshake ran over, and is now one the session's sends go through, a change of the
    /// faces' links ([`Self::generation`]). A face past the table changes nothing.
    pub fn establish(&mut self, at: usize) {
        if self.face(at).is_some() {
            self.regenerated();
        }
    }

    /// Whether a face other than `id` holds the node `zid` or brings a link to it up: its link is
    /// up or in its handshake, and reaches that node.
    pub fn node_is_held(&self, zid: &[u8], id: FaceId) -> bool {
        self.faces().any(|face| {
            face.id() != id
                && face
                    .link()
                    .wire()
                    .and_then(|wire| wire.node())
                    .is_some_and(|node| same_zid(node.as_slice(), zid))
        })
    }

    /// Whether a face's link holds input it has already taken from its stack.
    pub fn holds_input(&self) -> bool {
        self.faces()
            .any(|face| face.link().wire().is_some_and(FaceWire::holds_input))
    }

    /// What the face at `at`, numbered `id`, holds: its role, and what its link came to since it
    /// was last read at `now_us`, as the input its life takes. The answer of a dial under way is
    /// asked here; once it answers, the dial is let go of, its answer written to `answer` and the
    /// endpoint it dialled to `dialled`, kept there for the link it made. A handshake that
    /// completed is read as established even when its link ended after. A face past the table
    /// reads as one taken besides the dial role's whose link moved nothing. The role is the
    /// place's: the first is the dial role's, placed by [`Self::new`] and never dropped
    /// ([`Self::drop_face`]). A table of the dial role's face alone reads every place in that role,
    /// and holds no other face to hold a node.
    // Out of line, so its caller reads the role as a value and takes one path for either role.
    #[inline(never)]
    pub fn read_face(
        &mut self,
        at: usize,
        id: FaceId,
        now_us: u64,
        answer: &mut DialAnswer<L::Pump, N>,
        dialled: &mut Option<DialEndpoint>,
    ) -> FaceRead {
        // A session that takes no face besides its dial has the dial role alone: a place past the
        // first holds a departed face's tomb there, which never moves.
        #[cfg(feature = "listen")]
        let role = if at == 0 || !P::TAKES {
            LinkRole::Dial
        } else {
            LinkRole::Taken
        };
        #[cfg(not(feature = "listen"))]
        let role = LinkRole::Dial;
        let Some(face) = self.face_mut(at) else {
            return FaceRead {
                role,
                input: LinkInput::Tick,
            };
        };
        let phase = face.life().phase();
        let asked = match face.link_mut() {
            Link::Dialing(dial) => dial.answer(),
            _ => None,
        };
        if let Some(answered) = asked {
            let input = if answered.is_ok() {
                LinkInput::DialMade
            } else {
                LinkInput::DialRefused
            };
            *answer = Some(answered);
            if let Link::Dialing(dial) = core::mem::replace(face.link_mut(), Link::Idle) {
                *dialled = Some(dial.into_endpoint());
            }
            return FaceRead { role, input };
        }
        // An established link and one in its handshake read their wire's end by one look; only
        // the handshake's has an establishment to report, and only its end can find the node it
        // reached held by another face.
        let (input, over) = match (face.link().wire(), phase) {
            (Some(wire), LinkPhase::Handshaking { deadline_us, .. }) => {
                if wire.established() {
                    (LinkInput::Established, false)
                } else if wire.finished() {
                    (LinkInput::Ended, true)
                } else {
                    (LinkInput::Tick, now_us >= deadline_us)
                }
            }
            (Some(wire), _) if wire.finished() => (LinkInput::Ended, false),
            _ => (LinkInput::Tick, false),
        };
        #[cfg(feature = "listen")]
        let input = self.read_node(at, id, role, phase, input, over);
        #[cfg(not(feature = "listen"))]
        let _ = (id, over);
        FaceRead { role, input }
    }

    /// What the node the dial role's face reached makes of its input `input`: a handshake that is
    /// over (`over`) at a node another face holds stands the face by for it, and a face standing
    /// by dials again once no other face holds the node. Only a table that takes faces besides
    /// the dial role's has another face to hold a node.
    #[cfg(feature = "listen")]
    fn read_node(
        &mut self,
        at: usize,
        id: FaceId,
        role: LinkRole,
        phase: LinkPhase,
        input: LinkInput,
        over: bool,
    ) -> LinkInput {
        if role != LinkRole::Dial || !P::TAKES {
            return input;
        }
        if over {
            if let Some(node) = self.held_node(at, id) {
                self.stood_by = Some(node);
                return LinkInput::HeldElsewhere;
            }
        }
        if phase == LinkPhase::Held
            && !self
                .stood_by
                .is_some_and(|node| self.node_is_held(node.as_slice(), id))
        {
            return LinkInput::NodeFree;
        }
        input
    }

    /// The node the link of the face at `at`, numbered `id`, reached, when another face holds
    /// that node or brings a link to it up: what the dial role's face stands by for once its
    /// handshake is over. Read before the link's task is ended.
    pub fn held_node(&self, at: usize, id: FaceId) -> Option<SessionZid> {
        let node = self.face(at)?.link().wire()?.node()?;
        if !self.node_is_held(node.as_slice(), id) {
            return None;
        }
        Some(node)
    }

    /// Why the handshake of the face at `at` ended: the Close its peer sent, its task's end, or
    /// its deadline. A face that holds no link ended with it.
    pub fn handshake_end(&self, at: usize) -> HandshakeEnd {
        match self.face(at).and_then(|face| face.link().wire()) {
            Some(wire) => match (wire.close_reason(), wire.finished()) {
                (Some(reason), _) => HandshakeEnd::Closed(reason),
                (None, true) => HandshakeEnd::Ended,
                (None, false) => HandshakeEnd::NoAnswerInTime,
            },
            None => HandshakeEnd::Ended,
        }
    }

    /// End the task of the link of the face at `at`, if it holds one.
    /// Out of line: a face's poll and the bring-up of a link end a link in three places.
    #[inline(never)]
    pub fn abort_link(&self, at: usize) {
        if let Some(wire) = self.face(at).and_then(|face| face.link().wire()) {
            wire.abort();
        }
    }

    /// Have every face's link write what it owes its stack, as far as the stack takes it now, so
    /// a link whose stack has room by now gives back the outbound slot its frame held.
    #[cfg(feature = "session-unicast-accept")]
    pub fn write_owed_now(&self) {
        for wire in self.faces().filter_map(|face| face.link().wire()) {
            wire.write_owed_now();
        }
    }

    /// What a publish that waits for an outbound slot waits on: each face's link that owes its
    /// stack the rest of a frame, for its room and its input. A link whose stack gives no wait is
    /// not in it.
    #[cfg(feature = "session-unicast-accept")]
    pub fn owing_waits(&self) -> OwingWaits {
        let mut waits = OwingWaits::new_static();
        let owing = self
            .faces()
            .filter_map(|face| face.link().wire())
            .filter(|wire| wire.owes_write())
            .filter_map(|wire| wire.input_wait());
        for on in owing {
            let pushed = waits.push(LinkWait::input_or_room(on));
            // Each link that owes holds one of the pool's slots, so more never owe than
            // `OWING_WAITS`: one past it is a link that owes with no slot, which a test build
            // names rather than wait on fewer links than owe.
            debug_assert!(
                pushed.is_ok(),
                "more links owe a write than the outbound slots they hold ({OWING_WAITS})"
            );
            if pushed.is_err() {
                break;
            }
        }
        waits
    }

    /// What a read waits for, for at most `most` milliseconds: the input of every link that
    /// holds none already and gives a wait, a connection on every port that gives one, and
    /// `others` after them; no wait at all when a link holds input. A link that owes its stack the
    /// rest of a frame is waited on for room as well. A link that waits in its own loop, or a port
    /// that gives no wait, bounds the wait at a look; a face bounds it at the time its link stands
    /// to be looked at again ([`UnicastLink::wake_at`]): a dial under way or waiting at its
    /// next look, a handshake at its deadline. `beside`, a wake of the stack's (the program's word
    /// that the session's clock moved on), ends whatever wait the links make, a sleep to the next
    /// dial among them; it makes no wait where they make none. `now_us` reads the clock, which
    /// only a face with such a time asks, once. A read that finds another read waiting with the
    /// session's buffer waits for it to be handed back instead, for `most` at the longest
    /// ([`IdleWait::Behind`]): the links are that read's, whose step reads what arrives on them,
    /// and a second wait on them would need a buffer of the heap.
    pub fn idle_wait(
        &mut self,
        most: u32,
        now_us: &mut dyn FnMut() -> u64,
        others: impl IntoIterator<Item = LinkWait>,
        beside: Option<LinkWait>,
    ) -> IdleWait {
        let Some(mut waits) = self.waits.take() else {
            return if most > 0 {
                IdleWait::Behind(most)
            } else {
                IdleWait::None
            };
        };
        let mut holds = false;
        // A wait past the room the open reserved is not made: the read looks again at once rather
        // than grow the buffer after the open.
        let mut look_again = false;
        let mut own_loop = false;
        let mut dial_left_ms: Option<u64> = None;
        let mut now = None;
        let mut read_now = || *now.get_or_insert_with(&mut *now_us);
        for face in self.faces.iter() {
            // The soonest a face's link is to be looked at again bounds the wait.
            let life = face.life();
            let wake = match life.phase() {
                LinkPhase::Up | LinkPhase::Idle | LinkPhase::Held | LinkPhase::Closed => None,
                _ => life.wake_at(read_now()),
            };
            if let Some(wake_us) = wake {
                let left_ms = wake_us.saturating_sub(read_now()).saturating_div(1000);
                dial_left_ms = Some(dial_left_ms.map_or(left_ms, |held| held.min(left_ms)));
            }
            match face.link() {
                Link::Wire(wire) => {
                    if wire.holds_input() {
                        holds = true;
                    } else if wire.waits_for_buffer() {
                        // Its input waits in the stack until another link gives a receive
                        // buffer back, which that link's own input wakes the read for.
                    } else if let Some(on) = wire.input_wait() {
                        let wait = if wire.owes_write() {
                            LinkWait::input_or_room(on)
                        } else {
                            LinkWait::input(on)
                        };
                        look_again |= !put_wait(&mut waits, wait);
                    } else {
                        own_loop = true;
                    }
                }
                // A face waiting, dialling or standing by brings no input of its own: its time,
                // read above, is what wakes the read for it.
                Link::Idle | Link::Dialing(_) => {}
            }
        }
        if holds {
            waits.clear();
            self.waits = Some(waits);
            return IdleWait::None;
        }
        // Asked at each wait: a listener whose own work is under way (a WebSocket handshake) or
        // that takes no connection now gives no wait on its port until that changes.
        #[cfg(feature = "listen")]
        for listening in &mut self.listeners {
            let on = listening.listener.input_wait();
            let was = listening.on;
            listening.on = on.filter(|_| listening.listener.asked_when_ready());
            if listening.on.is_none() && was.is_some() {
                self.moves = self.moves.wrapping_add(1);
            }
            match on {
                Some(on) => {
                    if !put_wait(&mut waits, LinkWait::input(on)) {
                        // No wait can find a port ready that the read has no room to wait on:
                        // it is asked at every look until a read has room for it.
                        if listening.on.take().is_some() {
                            self.moves = self.moves.wrapping_add(1);
                        }
                        look_again = true;
                    }
                }
                None => look_again = true,
            }
        }
        for other in others {
            look_again |= !put_wait(&mut waits, other);
        }
        let most = match dial_left_ms {
            Some(left) => u32::try_from(left).map_or(most, |left| left.min(most)),
            None => most,
        };
        let ms = match (waits.is_empty(), look_again) {
            // A port that gives no wait is looked at again after a bounded sleep.
            (true, true) if most > 0 => Some(most.min(1)),
            (true, _) => match dial_left_ms {
                Some(_) if most > 0 => Some(most),
                _ => None,
            },
            (false, _) if most > 0 => Some(if own_loop || look_again {
                most.min(1)
            } else {
                most
            }),
            _ => None,
        };
        // A sleep a wake beside it ends is a wait on the wake.
        if let (Some(_), Some(wake)) = (ms, beside) {
            // Refused, the wait still ends at its bound, which is no longer than the sleep.
            put_wait(&mut waits, wake);
        }
        match ms {
            Some(ms) if !waits.is_empty() => IdleWait::Input { on: waits, ms },
            // A wait that takes no buffer leaves it here.
            ms => {
                waits.clear();
                self.waits = Some(waits);
                ms.map_or(IdleWait::None, IdleWait::Sleep)
            }
        }
    }

    /// Take back a read's wait, once made ([`IdleWait::wait`]), mark each port it found ready, and
    /// tell each link its owner waits on whether it found input in its stack
    /// (`FaceSession::input_seen`, with `listen` or `group`): the session's buffer of its
    /// waits, which the wait took whole ([`Self::idle_wait`]).
    /// Out of line: the open's steps and each read hand their wait back.
    #[inline(never)]
    pub fn waited(&mut self, wait: IdleWait) {
        if let IdleWait::Input { mut on, .. } = wait {
            // What the wait left in the buffer is what it found ready (`IdleWait::wait`).
            // A link the wait did not look at (one that held input, or waited for a buffer) is
            // told it found nothing all the same: what it holds is read whatever it is told,
            // and the next wait or move reads its stack.
            #[cfg(any(feature = "listen", feature = "group"))]
            for wire in self.faces().filter_map(|face| face.link().wire()) {
                if let Some(port) = wire.input_wait() {
                    wire.input_seen(on.iter().any(|ready| ready.on == port));
                }
            }
            #[cfg(feature = "listen")]
            for listening in &mut self.listeners {
                if listening
                    .on
                    .is_some_and(|port| on.iter().any(|ready| ready.on == port))
                {
                    listening.ready = true;
                    self.moves = self.moves.wrapping_add(1);
                }
            }
            on.clear();
            self.waits = Some(on);
        }
    }

    /// The session's links moved: each link its owner waits on reads its stack at its next step,
    /// whatever a wait found there before. A run of steps that makes no wait (a group's burst,
    /// what a link took in one receive) passes over a stack that gave nothing until the move
    /// that ends it, so no link waits longer than a move for its input to be read.
    #[cfg(any(feature = "listen", feature = "group"))]
    pub fn links_moved(&self) {
        for wire in self.faces().filter_map(|face| face.link().wire()) {
            if wire.input_wait().is_some() {
                wire.input_seen(true);
            }
        }
    }

    /// Let go of every dial under way, whose connection is then not made, and of every port.
    pub fn end_dials_and_ports(&mut self) {
        for face in self.faces_mut() {
            let link = face.link_mut();
            if let Link::Dialing(_) = link {
                *link = Link::Idle;
            }
        }
        #[cfg(feature = "listen")]
        self.listeners.clear();
    }

    /// End every face's link, whatever it is doing, telling an established peer so, after
    /// `each` is shown the face. Each face's life is closed, which lets go of what it held; the
    /// dial role's face stays, with no link and no redial; the others go.
    pub fn end_faces(&mut self, mut each: impl FnMut(&mut F)) {
        self.regenerated();
        for face in self.faces_mut() {
            each(face);
            // A close asks to let go of the dial or the link, which is what follows here for
            // every face alike, so its effects are not read; it reads no time.
            let _ = face.life_mut().input(LinkInput::Close, 0);
            let link = core::mem::replace(face.link_mut(), Link::Idle);
            if let Link::Wire(wire) = link {
                wire.close();
                wire.abort();
            }
        }
        self.faces.keep_dial_only();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::rc::Rc;
    use alloc::vec;
    use core::cell::Cell;
    use core::sync::atomic::Ordering;
    use wz_session_core::link::RxFrame;

    use crate::session_drive::LinkListener;
    use crate::{ClockSource, CoopLocalSet, CoopRuntime};

    struct Still;

    impl ClockSource for Still {
        fn now_us(&self) -> u64 {
            0
        }
    }

    /// A session's half of a link: whether it is established, the node it reached, how often it
    /// was ended, and what it was last told of its stack.
    struct Session {
        established: bool,
        node: Option<SessionZid>,
        ended: Rc<Cell<u32>>,
        closed: Option<CloseReason>,
        #[cfg(any(feature = "listen", feature = "group"))]
        seen: Rc<Cell<Option<bool>>>,
    }

    impl FaceSession for Session {
        fn established(&self) -> bool {
            self.established
        }

        fn node(&self) -> Option<SessionZid> {
            self.node
        }

        fn end(&self) {
            self.ended.set(self.ended.get() + 1);
        }

        fn close_reason(&self) -> Option<CloseReason> {
            self.closed
        }

        #[cfg(any(feature = "listen", feature = "group"))]
        fn input_seen(&self, ready: bool) {
            self.seen.set(Some(ready));
        }
    }

    type TestLink = Link<Wire<Session>, Answer>;

    struct TestFace {
        id: FaceId,
        link: TestLink,
        life: UnicastLink,
    }

    /// The life of a test face's link: the dial role's over two endpoints, not opened yet.
    fn idle_life() -> UnicastLink {
        life_in(&[])
    }

    /// The dial role's life over two endpoints, a dial and its handshake given ten seconds and
    /// the endpoints dialled again 5 ms after none answered, moved by `inputs` at time 0.
    fn life_in(inputs: &[LinkInput]) -> UnicastLink {
        let times = wz_session_core::link_life::LinkTimes {
            open_timeout_ms: 10_000,
            redial_ms: Some(5),
            dial_look_ms: DIAL_LOOK_MS,
            accept_timeout_ms: 1,
        };
        let mut life = UnicastLink::new(times, LinkRole::Dial, 2);
        for input in inputs {
            let _ = life.input(*input, 0);
        }
        life
    }

    /// A life waiting until 5 ms to dial again: up once, lost, then both endpoints refused.
    fn backing_off() -> UnicastLink {
        life_in(&[
            LinkInput::Open,
            LinkInput::DialMade,
            LinkInput::HandshakeBegun,
            LinkInput::Established,
            LinkInput::Ended,
            LinkInput::DialRefused,
            LinkInput::DialRefused,
        ])
    }

    /// A life standing by for a node another face held when its handshake ended.
    #[cfg(feature = "listen")]
    fn standing_by() -> UnicastLink {
        life_in(&[
            LinkInput::Open,
            LinkInput::DialMade,
            LinkInput::HandshakeBegun,
            LinkInput::HeldElsewhere,
        ])
    }

    /// Give the dial role's face of `faces` the life `life`.
    fn set_life<L: SessionLinks<Pump = Rc<Quiet>, Dial = Answer>>(
        faces: &mut LinkSupervisor<L, TestFace>,
        life: UnicastLink,
    ) {
        faces.face_mut(0).expect("the dial role's face").life = life;
    }

    impl FaceRecord for TestFace {
        type Wire = Wire<Session>;
        type Pump = Rc<Quiet>;
        type Dial = Answer;

        fn id(&self) -> FaceId {
            self.id
        }

        fn link(&self) -> &TestLink {
            &self.link
        }

        fn link_mut(&mut self) -> &mut TestLink {
            &mut self.link
        }

        fn life(&self) -> &UnicastLink {
            &self.life
        }

        fn life_mut(&mut self) -> &mut UnicastLink {
            &mut self.life
        }
    }

    /// A link that reads nothing, holding input or not.
    struct Quiet {
        holds: bool,
    }

    impl SessionDatagramLink for Quiet {
        fn service(&self) {}

        fn try_recv(&self) -> Option<RxFrame> {
            None
        }

        fn holds_input(&self) -> bool {
            self.holds
        }
    }

    /// A network that opens nothing: the dials of these tests are made by hand.
    struct Net;

    impl SessionLinks for Net {
        type Pump = Rc<Quiet>;
        type Dial = Answer;
        type Waits = crate::session_drive::NoWaits;

        fn waits(&self) -> Self::Waits {
            crate::session_drive::NoWaits
        }

        fn open_acceptor(&self, _port: u16) -> Result<OpenedLink<Rc<Quiet>>, LinkOpenError> {
            Err(LinkOpenError::Unsupported)
        }

        fn open_initiator(&self, _to: Locator) -> Result<OpenedLink<Rc<Quiet>>, LinkOpenError> {
            Err(LinkOpenError::Unsupported)
        }

        fn open_listener(
            &self,
            _at: Locator,
        ) -> Result<Box<dyn LinkListener<Rc<Quiet>>>, LinkOpenError> {
            Ok(Box::new(Busy(Cell::new(0))))
        }
    }

    /// A network whose ports are each waited on by `Socket(9)` and never hold a connection: how
    /// often one was asked for a connection, and whether its ports are asked only when ready.
    #[cfg(feature = "listen")]
    struct Ports(Rc<Cell<u32>>, bool);

    #[cfg(feature = "listen")]
    impl SessionLinks for Ports {
        type Pump = Rc<Quiet>;
        type Dial = Answer;
        type Waits = crate::session_drive::NoWaits;

        fn waits(&self) -> Self::Waits {
            crate::session_drive::NoWaits
        }

        fn open_acceptor(&self, _port: u16) -> Result<OpenedLink<Rc<Quiet>>, LinkOpenError> {
            Err(LinkOpenError::Unsupported)
        }

        fn open_initiator(&self, _to: Locator) -> Result<OpenedLink<Rc<Quiet>>, LinkOpenError> {
            Err(LinkOpenError::Unsupported)
        }

        fn open_listener(
            &self,
            _at: Locator,
        ) -> Result<Box<dyn LinkListener<Rc<Quiet>>>, LinkOpenError> {
            Ok(Box::new(Empty(self.0.clone(), self.1)))
        }
    }

    /// A port waited on by `Socket(9)` that holds no connection, counting each time it is asked,
    /// and asked only when ready as `.1` says.
    #[cfg(feature = "listen")]
    struct Empty(Rc<Cell<u32>>, bool);

    #[cfg(feature = "listen")]
    impl LinkListener<Rc<Quiet>> for Empty {
        fn local(&self) -> Locator {
            Locator::tcp(core::net::SocketAddr::from(([127, 0, 0, 1], 7447)))
        }

        fn accept(&self) -> Result<Option<OpenedLink<Rc<Quiet>>>, LinkOpenError> {
            self.0.set(self.0.get() + 1);
            Ok(None)
        }

        fn input_wait(&self) -> Option<WaitOn> {
            Some(WaitOn::Socket(9))
        }

        fn asked_when_ready(&self) -> bool {
            self.1
        }
    }

    /// The waits of a stack that found none of what it waited on ready.
    #[cfg(feature = "listen")]
    struct NoneReady;

    #[cfg(feature = "listen")]
    impl LinkWaits for NoneReady {
        fn wait(&self, _on: &[LinkWait], _timeout_ms: u32) {}

        fn wait_ready(&self, _on: &mut [LinkWait], _timeout_ms: u32) -> usize {
            0
        }

        fn wait_room(&self, _on: WaitOn, _timeout_us: u64) -> bool {
            true
        }
    }

    /// A port that gives a wait the first time it is asked and none after, as one whose own work
    /// came under way: how often it was asked.
    struct Busy(Cell<u32>);

    impl LinkListener<Rc<Quiet>> for Busy {
        fn local(&self) -> Locator {
            Locator::tcp(core::net::SocketAddr::from(([0, 0, 0, 0], 7447)))
        }

        fn accept(&self) -> Result<Option<OpenedLink<Rc<Quiet>>>, LinkOpenError> {
            Ok(None)
        }

        fn input_wait(&self) -> Option<WaitOn> {
            let asked = self.0.get();
            self.0.set(asked + 1);
            (asked == 0).then_some(WaitOn::Socket(7))
        }
    }

    /// A dial that answers `.0` the first time it is asked, and nothing after, counting each ask
    /// in `.1` when it is given a count.
    struct Answer(
        Option<Result<OpenedLink<Rc<Quiet>>, LinkOpenError>>,
        Option<Rc<Cell<u32>>>,
    );

    impl PendingDial<Rc<Quiet>> for Answer {
        fn poll(&mut self) -> Option<Result<OpenedLink<Rc<Quiet>>, LinkOpenError>> {
            if let Some(asks) = &self.1 {
                asks.set(asks.get() + 1);
            }
            self.0.take()
        }
    }

    impl From<OpenedLink<Rc<Quiet>>> for Answer {
        fn from(opened: OpenedLink<Rc<Quiet>>) -> Self {
            Answer(Some(Ok(opened)), None)
        }
    }

    /// A face dialling `endpoint` with a dial that answers `answer`.
    fn dialing(
        endpoint: DialEndpoint,
        answer: Option<Result<OpenedLink<Rc<Quiet>>, LinkOpenError>>,
    ) -> TestLink {
        Link::Dialing(Dial::new(endpoint, Answer(answer, None)))
    }

    fn session(established: bool, node: Option<&[u8]>) -> Session {
        Session {
            established,
            node: node.map(|zid| SessionZid::new(zid).expect("a zid")),
            ended: Rc::new(Cell::new(0)),
            closed: None,
            #[cfg(any(feature = "listen", feature = "group"))]
            seen: Rc::new(Cell::new(None)),
        }
    }

    /// A wire whose task has ended when `finished`, over a link that holds input when `holds`.
    fn wire(
        local: &CoopLocalSet<Still>,
        session: Session,
        holds: bool,
        finished: bool,
    ) -> Wire<Session> {
        let task = local.spawn_local(async { DriverOutcome::Terminated });
        if finished {
            local.run_until_idle();
        }
        let link = CellRc::try_boxed(Quiet { holds })
            .expect("the heap has room")
            .into_link();
        let (input_wait, room_wait) = (link.input_wait(), link.room_wait());
        Wire::new(session, task, link, input_wait, room_wait)
    }

    /// The end of a link its owner steps itself: finished once its last step said so, and asked
    /// to end by an abort it keeps for the owner.
    #[derive(Default)]
    struct HeldEnd {
        finished: Cell<bool>,
        aborted: Cell<bool>,
    }

    impl LinkEnd for Rc<HeldEnd> {
        fn finished(&self) -> bool {
            self.finished.get()
        }

        fn abort(&self) {
            self.aborted.set(true);
        }
    }

    /// A wire reads its link's end through the end it was made with, whichever it is: a task's
    /// handle, or the end of a link whose session its owner steps itself. Turned red by a wire
    /// that reads or ends a task of its own beside the end it was given.
    #[test]
    fn a_wire_ends_its_link_by_the_end_it_was_made_with() {
        let end = Rc::new(HeldEnd::default());
        let link = CellRc::try_boxed(Quiet { holds: false })
            .expect("the heap has room")
            .into_link();
        let (input_wait, room_wait) = (link.input_wait(), link.room_wait());
        let wire = Wire::new(
            session(true, None),
            Rc::clone(&end),
            link,
            input_wait,
            room_wait,
        );
        assert!(!wire.finished(), "CONTROL: a link whose session runs");
        end.finished.set(true);
        assert!(wire.finished(), "the wire read the end it was given");
        assert!(!end.aborted.get(), "CONTROL: nothing ended the link yet");
        wire.abort();
        assert!(
            end.aborted.get(),
            "the wire's abort reached the end it was given"
        );
    }

    /// A link its owner waits on by `on`, owing its stack a write when `owes`.
    struct Waited {
        on: WaitOn,
        owes: bool,
    }

    impl SessionDatagramLink for Waited {
        fn service(&self) {}

        fn try_recv(&self) -> Option<RxFrame> {
            None
        }

        fn owes_write(&self) -> bool {
            self.owes
        }

        fn input_wait(&self) -> Option<WaitOn> {
            Some(self.on)
        }
    }

    /// An established wire over a link waited on by `on`, owing a write when `owes`.
    fn waited_wire(local: &CoopLocalSet<Still>, on: WaitOn, owes: bool) -> Wire<Session> {
        let task = local.spawn_local(async { DriverOutcome::Terminated });
        let link = CellRc::try_boxed(Waited { on, owes })
            .expect("the heap has room")
            .into_link();
        let (input_wait, room_wait) = (link.input_wait(), link.room_wait());
        Wire::new(session(true, None), task, link, input_wait, room_wait)
    }

    /// What a wait of a stack was asked last: how many entries, for how long.
    #[derive(Default)]
    struct Asked {
        entries: core::sync::atomic::AtomicUsize,
        ms: core::sync::atomic::AtomicU32,
    }

    impl LinkWaits for Asked {
        fn wait(&self, on: &[LinkWait], timeout_ms: u32) {
            self.entries.store(on.len(), Ordering::Relaxed);
            self.ms.store(timeout_ms, Ordering::Relaxed);
        }

        fn wait_room(&self, _on: WaitOn, _timeout_us: u64) -> bool {
            true
        }
    }

    fn supervisor(link: TestLink, faces: usize) -> LinkSupervisor<Net, TestFace> {
        LinkSupervisor::new(
            Net,
            TestFace {
                id: 100,
                link,
                life: idle_life(),
            },
            faces,
            2,
        )
        .expect("the heap holds two waits")
    }

    /// What a face holds of a link whose parts lie apart from it: a handle that reads and ends
    /// the link as the parts answer, which it is told here.
    struct ApartWire {
        holds: bool,
        finished: bool,
        aborted: Rc<Cell<u32>>,
        /// The ends the link was told, counted by whichever thread tells one.
        ended: alloc::sync::Arc<core::sync::atomic::AtomicU32>,
    }

    impl FaceSession for ApartWire {
        fn established(&self) -> bool {
            true
        }

        fn node(&self) -> Option<SessionZid> {
            None
        }

        fn end(&self) {
            self.ended.fetch_add(1, Ordering::SeqCst);
        }

        fn close_reason(&self) -> Option<CloseReason> {
            None
        }
    }

    impl FaceWire for ApartWire {
        fn finished(&self) -> bool {
            self.finished
        }

        fn abort(&self) {
            self.aborted.set(self.aborted.get() + 1);
        }

        fn holds_input(&self) -> bool {
            self.holds
        }

        fn owes_write(&self) -> bool {
            false
        }

        fn waits_for_buffer(&self) -> bool {
            false
        }

        fn input_wait(&self) -> Option<WaitOn> {
            None
        }

        fn room_wait(&self) -> Option<WaitOn> {
            None
        }

        #[cfg(feature = "session-unicast-accept")]
        fn write_owed_now(&self) {}
    }

    struct ApartFace {
        id: FaceId,
        link: Link<ApartWire, Answer>,
        life: UnicastLink,
    }

    impl FaceRecord for ApartFace {
        type Wire = ApartWire;
        type Pump = Rc<Quiet>;
        type Dial = Answer;

        fn id(&self) -> FaceId {
            self.id
        }

        fn link(&self) -> &Link<ApartWire, Answer> {
            &self.link
        }

        fn link_mut(&mut self) -> &mut Link<ApartWire, Answer> {
            &mut self.link
        }

        fn life(&self) -> &UnicastLink {
            &self.life
        }

        fn life_mut(&mut self) -> &mut UnicastLink {
            &mut self.life
        }
    }

    /// A face whose link is held as a handle of the record's own kind, not as the link's parts,
    /// is read and ended through that handle alone. Turned red by a supervisor that reads a
    /// face's input or end off a `Wire`'s fields rather than through `FaceWire`.
    #[test]
    fn a_face_whose_link_lies_apart_is_read_and_ended_through_its_handle() {
        let aborted = Rc::new(Cell::new(0));
        let apart = |holds, finished| ApartWire {
            holds,
            finished,
            aborted: Rc::clone(&aborted),
            ended: alloc::sync::Arc::default(),
        };
        let dial = ApartFace {
            id: 100,
            link: Link::Wire(apart(false, false)),
            life: idle_life(),
        };
        let mut faces: LinkSupervisor<Net, ApartFace> =
            LinkSupervisor::new(Net, dial, 1, 2).expect("the heap holds two waits");
        assert!(!faces.holds_input(), "CONTROL: a link that holds no input");
        faces.put_link(0, Link::Wire(apart(true, true)));
        assert!(faces.holds_input(), "the handle's input read");
        let (mut answer, mut dialled) = (None, None);
        let read = faces.read_face(0, 100, 0, &mut answer, &mut dialled);
        assert!(read.input == LinkInput::Ended, "the handle's end read");
        assert_eq!(aborted.get(), 0, "CONTROL: nothing ended the link yet");
        faces.end_faces(|_| {});
        assert_eq!(aborted.get(), 1, "the handle ended the link");
    }

    /// The owner of what a confined face's place holds in the tests below: one test's thread.
    struct TestOwner;

    // SAFETY: every value of a `Confined<TestOwner>` kind is made and reached by the one thread
    // of the test that made it.
    unsafe impl crate::sync::ConfinedOwner for TestOwner {}

    /// The parts of a face's link in a face's place: its wire, while it holds one, and the sum of
    /// the debts it was paid.
    struct ApartParts(Option<ApartWire>, Ended);

    // SAFETY: the parts' `Rc` is reached by the thread of the test that made them alone; another
    // thread of a test reaches the parts only to tell their wire an end or pay them a debt, which
    // it counts in an atomic. Nothing of them is bound to a thread.
    unsafe impl FaceParts for ApartParts {}

    impl WireParts for ApartParts {
        type Wire = ApartWire;

        fn wire(&self) -> Option<&ApartWire> {
            self.0.as_ref()
        }

        fn pay(&mut self, owed: u32) {
            self.1.fetch_add(owed, Ordering::SeqCst);
        }
    }

    /// The parts' send part: the sum their debts are paid into, which a test's send adds to too.
    impl SendParts for ApartParts {
        type Tx = Ended;

        fn tx(&mut self) -> &mut Ended {
            &mut self.1
        }

        // The send part is a count, not the wire.
        fn wire_of(_tx: &Ended) -> Option<&ApartWire> {
            None
        }
    }

    /// The parts of a face's link whose send part is its wire, as a session's are where a read
    /// steps its one link itself.
    struct SeatedParts(Option<ApartWire>);

    // SAFETY: the parts' `Rc` is reached by the thread of the test that made them alone. Nothing
    // of them is bound to a thread.
    unsafe impl FaceParts for SeatedParts {}

    impl WireParts for SeatedParts {
        type Wire = ApartWire;

        fn wire(&self) -> Option<&ApartWire> {
            self.0.as_ref()
        }

        fn pay(&mut self, _owed: u32) {}
    }

    impl SendParts for SeatedParts {
        type Tx = Option<ApartWire>;

        fn tx(&mut self) -> &mut Option<ApartWire> {
            &mut self.0
        }

        fn wire_of(tx: &Option<ApartWire>) -> Option<&ApartWire> {
            tx.as_ref()
        }
    }

    /// The count of the ends a test's link was told.
    type Ended = alloc::sync::Arc<core::sync::atomic::AtomicU32>;

    /// Parts holding an established wire that holds input, its aborts counted in `aborted` and
    /// its ends in `ended`.
    fn held_parts(aborted: &Rc<Cell<u32>>, ended: &Ended) -> FaceHeld<ApartParts> {
        paying_parts(aborted, ended, &Ended::default())
    }

    /// [`held_parts`] whose debts paid are summed in `paid`.
    fn paying_parts(aborted: &Rc<Cell<u32>>, ended: &Ended, paid: &Ended) -> FaceHeld<ApartParts> {
        let parts = ApartParts(
            Some(ApartWire {
                holds: true,
                finished: false,
                aborted: Rc::clone(aborted),
                ended: alloc::sync::Arc::clone(ended),
            }),
            alloc::sync::Arc::clone(paid),
        );
        // SAFETY: no handle on a cell of the parts lives outside them.
        unsafe { FaceHeld::gathered(parts) }
    }

    /// The parts' debts are paid at once to a free place; owed while the place is held, the
    /// calling thread's own lend included, they are paid once as it lets go, each bit once
    /// however often it was owed, with a close owed beside them told through the wire and never
    /// handed to the parts; a holder pays them inside its lend when it asks; and debts owed to an
    /// empty place are not paid to the parts held after. Turned red by a debt paid twice or not
    /// at all (`FaceSite::pay`, `owe_bits`), the close's bit handed to `WireParts::pay`, or debts
    /// of an empty place kept for the next link.
    #[test]
    fn the_parts_debts_are_paid_once_by_the_holder_and_the_close_through_the_wire() {
        let (aborted, ended, paid) = (Rc::new(Cell::new(0)), Ended::default(), Ended::default());
        let site = FaceSite::<crate::sync::Confined<TestOwner>, ApartParts>::empty();
        assert!(site.hold(paying_parts(&aborted, &ended, &paid)).is_none());
        // SAFETY: the site outlives the handle, in this frame.
        let at = unsafe { FaceAt::new(&site, Rc::new(HeldEnd::default()), None, None) };
        site.owe(1);
        assert_eq!(
            paid.load(Ordering::SeqCst),
            1,
            "paid at once to a free place"
        );
        let inside = site.lend(|_| {
            site.owe(2);
            site.owe(2);
            site.owe(4);
            at.close();
            (paid.load(Ordering::SeqCst), ended.load(Ordering::SeqCst))
        });
        assert_eq!(inside, Some((1, 0)), "nothing paid while the place is held");
        assert_eq!(
            paid.load(Ordering::SeqCst),
            1 + 2 + 4,
            "the parts' debts paid once each, without the close's bit"
        );
        assert_eq!(
            ended.load(Ordering::SeqCst),
            1,
            "the close told through the wire"
        );
        let asked = site.lend(|held| {
            site.owe(8);
            site.pay(held);
            paid.load(Ordering::SeqCst)
        });
        assert_eq!(
            asked,
            Some(7 + 8),
            "a holder pays when it asks, inside its lend"
        );
        assert_eq!(
            paid.load(Ordering::SeqCst),
            15,
            "and not again as it lets go"
        );
        assert!(site.take().is_some());
        site.owe(16);
        assert_eq!(
            site.owed.load(Ordering::SeqCst),
            0,
            "a debt owed to an empty place is let go of"
        );
        let next = Ended::default();
        assert!(site.hold(paying_parts(&aborted, &ended, &next)).is_none());
        assert!(site.lend(|_| ()).is_some());
        assert_eq!(
            next.load(Ordering::SeqCst),
            0,
            "a debt owed to an empty place is not the next link's"
        );
    }

    impl LendsSession for ApartWire {
        type Session = Self;

        fn try_session<U: Send>(&self, f: impl FnOnce(&Self) -> U + Send) -> Lend<U> {
            Lend::Lent(f(self))
        }

        fn owe(&self, _debts: u32) {}
    }

    /// A send reaches the session of a link whose parts lie in a face's place through a try of
    /// the place: lent while the place is free, held inside the place's own lend, where what it
    /// could not send is owed and paid as that lend lets go, and empty once the place holds no
    /// parts. Turned red by a send that waits for the place, reads a held place as lent, or an
    /// `owe` that does not reach the site.
    #[test]
    fn a_send_tries_the_place_of_its_link_and_owes_what_it_found_held() {
        let (aborted, ended, paid) = (Rc::new(Cell::new(0)), Ended::default(), Ended::default());
        let site = FaceSite::<crate::sync::Confined<TestOwner>, ApartParts>::empty();
        // SAFETY: the site outlives the handle, in this frame.
        let at = unsafe { FaceAt::new(&site, Rc::new(HeldEnd::default()), None, None) };
        assert_eq!(at.try_session(|wire| wire.holds), Lend::Empty);
        assert!(site.hold(paying_parts(&aborted, &ended, &paid)).is_none());
        assert_eq!(at.try_session(|wire| wire.holds), Lend::Lent(true));
        let inside = site.lend(|_| {
            let found = at.try_session(|wire| wire.holds);
            if found == Lend::Held {
                at.owe(2);
            }
            found
        });
        assert_eq!(inside, Some(Lend::Held));
        assert_eq!(
            paid.load(Ordering::SeqCst),
            2,
            "what the send found held paid as the lend let go"
        );
    }

    /// A debt of the parts in the bit of the site's close fails a debug build: the close is the
    /// site's to tell, through the wire. Turned red by an `owe` that takes the close's bit.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "the bit of the site's close")]
    fn a_debt_in_the_bit_of_the_close_fails_a_debug_build() {
        let site = FaceSite::<crate::sync::Confined<TestOwner>, ApartParts>::empty();
        site.owe(1 << 31);
    }

    /// A link whose parts lie in a face's place is read through a lend of the place, and its end
    /// through the end it was made with, with no lend; an empty place reads as a quiet link and
    /// keeps no close owed to it. Turned red by a handle that reads its end or its waits off the
    /// parts, reads an empty place as anything but quiet, or a close owed to an empty place told
    /// to the link held after; or by a read inside the place's own lend that reaches the parts
    /// (`OwnerHeld::try_with`), or a close made there that is not owed to that lend.
    #[test]
    fn a_link_in_a_faces_place_is_read_through_the_place() {
        let (aborted, ended) = (Rc::new(Cell::new(0)), Ended::default());
        let site = FaceSite::<crate::sync::Confined<TestOwner>, ApartParts>::empty();
        let end = Rc::new(HeldEnd::default());
        // SAFETY: the site outlives the handle, in this frame.
        let at = unsafe { FaceAt::new(&site, Rc::clone(&end), Some(WaitOn::Socket(3)), None) };
        assert!(!at.holds_input(), "an empty place reads as no input");
        assert!(!at.established(), "and as no link established");
        at.close();
        assert!(
            matches!(at.input_wait(), Some(WaitOn::Socket(3))),
            "the wait the handle was made with"
        );
        assert!(site.hold(held_parts(&aborted, &ended)).is_none());
        assert!(at.holds_input(), "the parts' wire read through the place");
        assert!(at.established(), "as is its session");
        assert!(site.lend(|_| ()).is_some());
        assert_eq!(
            ended.load(Ordering::SeqCst),
            0,
            "no close kept for an empty place"
        );
        at.close();
        assert_eq!(
            ended.load(Ordering::SeqCst),
            1,
            "a close told through a free place"
        );
        let inside = site.lend(|_| {
            at.close();
            (at.holds_input(), ended.load(Ordering::SeqCst))
        });
        assert_eq!(
            inside,
            Some((false, 1)),
            "a read inside the place's own lend reads as quiet, and its close is owed"
        );
        assert_eq!(
            ended.load(Ordering::SeqCst),
            2,
            "the close owed inside the lend told as it let go"
        );
        assert!(!at.finished(), "CONTROL: a link whose session runs");
        end.finished.set(true);
        assert!(at.finished(), "the end read with no lend");
        at.abort();
        assert!(end.aborted.get(), "the abort reached the end");
        assert_eq!(aborted.get(), 0, "and not the parts' wire");
        assert!(site.take().is_some());
        assert!(!at.holds_input(), "a place emptied reads as no input");
    }

    /// A link whose place another thread holds reads as a quiet link at once, waiting for
    /// nothing, and as its parts once that thread lets go of the place. Turned red by a read that
    /// waits for the place (the test then never ends), or reads it held as holding input.
    #[cfg(feature = "host-lock")]
    #[test]
    fn a_link_another_thread_holds_reads_as_quiet_and_waits_for_nothing() {
        extern crate std;
        use std::sync::Barrier;
        let (aborted, ended) = (Rc::new(Cell::new(0)), Ended::default());
        let site = FaceSite::<crate::sync::Shared, ApartParts>::empty();
        assert!(site.hold(held_parts(&aborted, &ended)).is_none());
        // SAFETY: the site outlives the handle, in this frame.
        let at = unsafe { FaceAt::new(&site, Rc::new(HeldEnd::default()), None, None) };
        assert!(
            at.holds_input(),
            "CONTROL: a place no thread holds lends its parts"
        );
        let (taken, done) = (Barrier::new(2), Barrier::new(2));
        std::thread::scope(|scope| {
            scope.spawn(|| {
                site.lend(|_| {
                    taken.wait();
                    done.wait();
                });
            });
            taken.wait();
            assert!(
                !at.holds_input(),
                "a place another thread holds reads as no input"
            );
            assert!(!at.established(), "and as no link established");
            done.wait();
        });
        assert!(at.holds_input(), "its parts once the place is let go of");
    }

    /// A send on a link whose parts lie in a face's place writes the parts' send part: through
    /// the seat the place's holder stands in on the sending thread, with no lend and leaving what
    /// is owed to the holder's let go; by a lend that waits for another thread that holds the
    /// place, after that thread's own write; and not at all while the place holds no parts.
    /// Turned red by a seated send that lends the place (the test's thread then waits on its own
    /// lend), a seated send that pays the holder's debts, or a send that does not wait.
    #[cfg(feature = "host-lock")]
    #[test]
    fn a_send_writes_through_the_holders_seat_else_waits_for_the_place() {
        extern crate std;
        use std::sync::Barrier;
        let (aborted, ended, sent) = (Rc::new(Cell::new(0)), Ended::default(), Ended::default());
        let site = FaceSite::<crate::sync::Shared, ApartParts>::empty();
        assert_eq!(
            site.send(|tx| tx.fetch_add(1, Ordering::SeqCst)),
            None,
            "an empty place takes no send"
        );
        assert!(site.hold(paying_parts(&aborted, &ended, &sent)).is_none());
        assert_eq!(
            site.send(|tx| tx.fetch_add(10, Ordering::SeqCst)),
            Some(0),
            "a free place is lent to the send"
        );
        let (site_ref, sent_ref) = (&site, &sent);
        let seated = site.lend_seating(|held, seat| {
            site_ref.owe(2);
            held.lend(move |parts| {
                seat.seat(&mut parts.1, || {
                    let took = site_ref.send(|tx| tx.fetch_add(100, Ordering::SeqCst));
                    (took, sent_ref.load(Ordering::SeqCst))
                })
            })
        });
        assert_eq!(
            seated,
            Some((Some(10), 110)),
            "the seated send wrote the part at once, and paid nothing"
        );
        assert_eq!(
            sent.load(Ordering::SeqCst),
            112,
            "the debt owed inside paid as the holder let go"
        );
        let taken = Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                site.lend(|held| {
                    taken.wait();
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    held.lend(|parts| parts.1.fetch_add(5, Ordering::SeqCst))
                });
            });
            taken.wait();
            assert_eq!(
                site.send(|tx| tx.fetch_add(1000, Ordering::SeqCst)),
                Some(117),
                "the send waited for the holder, and wrote after it"
            );
        });
        assert_eq!(sent.load(Ordering::SeqCst), 1117);
    }

    /// A lend of the link's session made inside the holder's seated step on the holder's thread
    /// reaches the wire through the seat, with no try of the place the holder holds; inside the
    /// holder's lend with no seat it finds the link held. Turned red by a `try_session` that does
    /// not look at the seat first (the seated lend then finds the place held), or one that reads
    /// the seat of a thread that stands in none.
    #[cfg(feature = "host-lock")]
    #[test]
    fn a_lend_of_the_session_in_the_seated_step_reaches_the_wire_through_the_seat() {
        let site = FaceSite::<crate::sync::Shared, SeatedParts>::empty();
        let wire = ApartWire {
            holds: true,
            finished: false,
            aborted: Rc::new(Cell::new(0)),
            ended: Ended::default(),
        };
        // SAFETY: no handle on a cell of the parts lives outside them.
        assert!(site
            .hold(unsafe { FaceHeld::gathered(SeatedParts(Some(wire))) })
            .is_none());
        let site_ref = &site;
        // SAFETY: the site outlives the handle, in this frame.
        let at = unsafe { FaceAt::new(site_ref, Rc::new(HeldEnd::default()), None, None) };
        assert_eq!(
            at.try_session(|wire| wire.holds),
            Lend::Lent(true),
            "CONTROL: a free place is tried and lent"
        );
        let unseated = site.lend(|_| at.try_session(|wire| wire.holds));
        assert_eq!(
            unseated,
            Some(Lend::Held),
            "the holder's own lend with no seat finds the link held"
        );
        let seated = site.lend_seating(|held, seat| {
            held.lend(move |parts| {
                seat.seat(&mut parts.0, || {
                    // SAFETY: the site outlives the handle, in this closure.
                    let at =
                        unsafe { FaceAt::new(site_ref, Rc::new(HeldEnd::default()), None, None) };
                    at.try_session(|wire| wire.holds)
                })
            })
        });
        assert_eq!(
            seated,
            Some(Lend::Lent(true)),
            "the seated step's lend reached the wire through the seat"
        );
    }

    /// The owner of what a face's place holds in the test below, which reaches the place inside
    /// its hold only through the handle on it, from inside the holder's seat.
    struct SeatOwner;

    // SAFETY: every value of a `Confined<SeatOwner>` kind is made and reached by the one thread of
    // the test that made it, and the place is reached inside its hold only by the handle's reads,
    // lends and debts made in the holder's seat, which look at the seat before they try the place.
    unsafe impl crate::sync::ConfinedOwner for SeatOwner {
        const TRIED_INSIDE: bool = false;
    }

    /// Where the place's try is its take (`ConfinedOwner::TRIED_INSIDE`), the handle reached
    /// inside the holder's seated step tries nothing: its read reads the link as quiet, its lend
    /// of the session goes through the seat, and its close is owed to the holder, told once as it
    /// lets go. Outside the step each is lent at once. Turned red, in a debug build by the mark of
    /// the hold, by a read or a debt that tries the place before it looks at the seat
    /// (`FaceAt::read`, `FaceSite::owe_bits`), and by a close told inside the step.
    #[test]
    fn a_place_whose_try_is_its_take_is_reached_in_its_step_through_the_seat_alone() {
        let ended = Ended::default();
        let site = FaceSite::<crate::sync::Confined<SeatOwner>, SeatedParts>::empty();
        let wire = ApartWire {
            holds: true,
            finished: false,
            aborted: Rc::new(Cell::new(0)),
            ended: alloc::sync::Arc::clone(&ended),
        };
        // SAFETY: no handle on a cell of the parts lives outside them.
        assert!(site
            .hold(unsafe { FaceHeld::gathered(SeatedParts(Some(wire))) })
            .is_none());
        let (site_ref, ended_ref) = (&site, &ended);
        // SAFETY: the site outlives the handle, in this frame.
        let at = unsafe { FaceAt::new(site_ref, Rc::new(HeldEnd::default()), None, None) };
        assert!(at.holds_input(), "CONTROL: a free place is lent at once");
        assert_eq!(at.try_session(|wire| wire.holds), Lend::Lent(true));
        let seated = site.lend_seating(|held, seat| {
            held.lend(move |parts| {
                seat.seat(&mut parts.0, || {
                    // SAFETY: the site outlives the handle, in this closure.
                    let at =
                        unsafe { FaceAt::new(site_ref, Rc::new(HeldEnd::default()), None, None) };
                    at.close();
                    (
                        at.holds_input(),
                        at.try_session(|wire| wire.holds),
                        ended_ref.load(Ordering::SeqCst),
                    )
                })
            })
        });
        assert_eq!(
            seated,
            Some((false, Lend::Lent(true), 0)),
            "inside the step: read as quiet, the session lent through the seat, the close owed"
        );
        assert_eq!(
            ended.load(Ordering::SeqCst),
            1,
            "the close owed inside the step told once, as the step let go"
        );
        assert!(
            at.holds_input(),
            "the place lent again once the step let go"
        );
    }

    /// A face whose link lies in a face's place, kept by the supervisor.
    #[cfg(feature = "host-lock")]
    struct SiteFace {
        id: FaceId,
        link: Link<FaceAt<crate::sync::Shared, ApartParts, Rc<HeldEnd>>, Answer>,
        life: UnicastLink,
    }

    #[cfg(feature = "host-lock")]
    impl FaceRecord for SiteFace {
        type Wire = FaceAt<crate::sync::Shared, ApartParts, Rc<HeldEnd>>;
        type Pump = Rc<Quiet>;
        type Dial = Answer;

        fn id(&self) -> FaceId {
            self.id
        }

        fn link(&self) -> &Link<Self::Wire, Answer> {
            &self.link
        }

        fn link_mut(&mut self) -> &mut Link<Self::Wire, Answer> {
            &mut self.link
        }

        fn life(&self) -> &UnicastLink {
            &self.life
        }

        fn life_mut(&mut self) -> &mut UnicastLink {
            &mut self.life
        }
    }

    /// The faces ended while a read holds a face's place: the face's link is aborted at once and
    /// its close owed, told exactly once as the read lets go of the place, and not again at a
    /// later lend. Turned red by a debt not paid (`FaceSite::pay`), paid twice, or a close told
    /// through a wait on the held place (the test then never ends).
    #[cfg(feature = "host-lock")]
    #[test]
    fn a_close_owed_while_a_read_holds_the_face_is_told_once_as_it_lets_go() {
        extern crate std;
        use std::sync::Barrier;
        let (aborted, ended) = (Rc::new(Cell::new(0)), Ended::default());
        let site = FaceSite::<crate::sync::Shared, ApartParts>::empty();
        assert!(site.hold(held_parts(&aborted, &ended)).is_none());
        let end = Rc::new(HeldEnd::default());
        // SAFETY: the site outlives the handle, in this frame.
        let at = unsafe { FaceAt::new(&site, Rc::clone(&end), None, None) };
        let dial = SiteFace {
            id: 100,
            link: Link::Wire(at),
            life: idle_life(),
        };
        let mut faces: LinkSupervisor<Net, SiteFace> =
            LinkSupervisor::new(Net, dial, 1, 2).expect("the heap holds two waits");
        let (taken, done) = (Barrier::new(2), Barrier::new(2));
        std::thread::scope(|scope| {
            scope.spawn(|| {
                site.lend(|_| {
                    taken.wait();
                    done.wait();
                });
            });
            taken.wait();
            faces.end_faces(|_| {});
            assert!(end.aborted.get(), "the link aborted at once, with no lend");
            assert_eq!(
                ended.load(Ordering::SeqCst),
                0,
                "no close told while the read holds the face"
            );
            done.wait();
        });
        assert_eq!(
            ended.load(Ordering::SeqCst),
            1,
            "the close told once, as the read let go"
        );
        assert!(site.lend(|_| ()).is_some());
        assert_eq!(
            ended.load(Ordering::SeqCst),
            1,
            "and not again at a later lend"
        );
    }

    /// A reach of a face to change it is counted, and a look at one is not: what a session that
    /// left its links settled compares to move them again. A supervisor with no port has none to
    /// ask. Turned red by a mutable reach that counts nothing (`face_mut`, `put_link`), or a look
    /// that counts one (`face`, `faces`).
    #[test]
    fn a_change_of_a_face_is_counted_and_a_look_is_not() {
        let mut faces = supervisor(Link::Idle, 2);
        assert!(!faces.ports_to_ask(), "no port, none to ask");
        assert!(!faces.listens(), "no port is listened on");
        let before = faces.moves();
        assert!(faces.face(0).is_some());
        assert_eq!(faces.faces().count(), 1);
        assert_eq!(faces.moves(), before, "a look changes nothing");
        faces.put_link(0, Link::Idle);
        let put = faces.moves();
        assert_ne!(put, before, "a link put in is a change");
        assert!(faces.face_mut(0).is_some());
        assert_ne!(faces.moves(), put, "a reach to change a face is a change");
    }

    /// The links' generation moves at each change of a face's link and of the faces held, and at
    /// nothing else: not at a reach of a face to change what the session keeps of it, nor at the
    /// read of a face each step makes. Turned red by a generation that moves at `face_mut`,
    /// `faces_mut` or `read_face`, or one that stays at `put_link`, `establish`, `place_face`,
    /// `drop_face` or `end_faces`.
    #[test]
    fn the_links_generation_moves_at_a_change_of_a_link_alone() {
        let mut faces = supervisor(Link::Idle, 2);
        let start = faces.generation();
        assert!(faces.face_mut(0).is_some());
        assert_eq!(faces.faces_mut().count(), 1);
        let _ = faces.read_face(0, 0, 100, &mut None, &mut None);
        assert_eq!(
            faces.generation(),
            start,
            "a reach and a read change no link"
        );
        let mut seen = start;
        let mut moved = |faces: &LinkSupervisor<Net, TestFace>, what: &str| {
            assert_ne!(faces.generation(), seen, "{what} is a change");
            seen = faces.generation();
        };
        faces.put_link(0, Link::Idle);
        moved(&faces, "a link put in");
        faces.establish(0);
        moved(&faces, "a link brought up");
        let other = TestFace {
            life: idle_life(),
            id: 1,
            link: Link::Idle,
        };
        assert!(faces.place_face(1, other).is_ok());
        moved(&faces, "a face placed");
        assert_eq!(faces.drop_face(1), Some(1));
        moved(&faces, "a face dropped");
        faces.end_faces(|_| {});
        moved(&faces, "the links ended");
    }

    /// A dial answers what its network answered once, and names the endpoint it reaches.
    #[test]
    fn a_dial_answers_once_and_names_its_endpoint() {
        let mut dial = Dial::new(
            DialEndpoint::Listed(1),
            Answer(Some(Err(LinkOpenError::Refused)), None),
        );
        assert_eq!(dial.endpoint(), &DialEndpoint::Listed(1));
        assert!(matches!(dial.answer(), Some(Err(LinkOpenError::Refused))));
        assert!(dial.answer().is_none(), "answered once");
    }

    /// Another face holds a node while its link to it is up, and a face never holds one for
    /// itself; once that face goes, no face holds the node.
    #[cfg(feature = "listen")]
    #[test]
    fn a_node_is_held_by_another_face_while_its_link_is_up() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
        let node = [7u8, 1];
        let mut faces = supervisor(Link::Idle, 2);
        let other = TestFace {
            life: idle_life(),
            id: 1,
            link: Link::Wire(wire(&local, session(true, Some(&node)), false, false)),
        };
        assert!(faces.place_face(1, other).is_ok());
        assert!(faces.node_is_held(&node, 100));
        assert!(
            !faces.node_is_held(&node, 1),
            "a face does not hold the node for itself"
        );
        assert!(faces.drop_face(1).is_some());
        assert!(!faces.node_is_held(&node, 100));
    }

    /// A face is read as the input its life takes: a dial's answer once, its dial then let go of
    /// and its endpoint handed over; a handshake's establishment before its end; an established
    /// link's end; and nothing for a face whose link moved, or one past the table. Turned red by a
    /// read that keeps an answered dial in the face, or reads an ended handshake that completed
    /// as ended.
    #[test]
    fn a_face_is_read_as_the_input_its_life_takes() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
        let mut faces = supervisor(
            dialing(DialEndpoint::Listed(0), Some(Err(LinkOpenError::Refused))),
            2,
        );
        let (mut answer, mut dialled) = (None, None);
        let read = faces.read_face(0, 100, 0, &mut answer, &mut dialled);
        assert_eq!(read.input, LinkInput::DialRefused);
        assert!(matches!(answer, Some(Err(LinkOpenError::Refused))));
        assert_eq!(dialled, Some(DialEndpoint::Listed(0)));
        assert!(
            matches!(dial(&faces).link, Link::Idle),
            "the dial is let go of"
        );
        let again = faces.read_face(0, 100, 0, &mut None, &mut None);
        assert_eq!(again.input, LinkInput::Tick, "answered once");

        // The dial role's life is walked to its handshake, as the session's carrying out does.
        let face = faces.face_mut(0).expect("the dial role's face");
        let _ = face.life.input(LinkInput::Open, 0);
        let _ = face.life.input(LinkInput::DialMade, 0);
        let _ = face.life.input(LinkInput::HandshakeBegun, 0);
        faces.put_link(
            0,
            Link::Wire(wire(&local, session(true, None), false, true)),
        );
        let read = faces.read_face(0, 100, 0, &mut None, &mut None);
        assert_eq!(read.input, LinkInput::Established, "before its end");

        let face = faces.face_mut(0).expect("the dial role's face");
        let _ = face.life.input(LinkInput::Established, 0);
        assert_eq!(face.life.phase(), LinkPhase::Up);
        let read = faces.read_face(0, 100, 0, &mut None, &mut None);
        assert_eq!(
            read.input,
            LinkInput::Ended,
            "an established link that ended"
        );
        faces.put_link(
            0,
            Link::Wire(wire(&local, session(true, None), false, false)),
        );
        let read = faces.read_face(0, 100, 0, &mut None, &mut None);
        assert_eq!(read.input, LinkInput::Tick);

        let past = faces.read_face(9, 9, 0, &mut None, &mut None);
        assert_eq!(past.input, LinkInput::Tick, "past the table");
    }
    /// A face is read in the role of its row: the first, which the table never lets go of, is the
    /// dial role's, and any other, or one past the table, one taken besides. Turned red by a role
    /// read off anything but the row.
    #[test]
    fn a_face_is_read_in_the_role_of_its_row() {
        let mut faces = supervisor(Link::Idle, 2);
        let taken = TestFace {
            life: idle_life(),
            id: 1,
            link: Link::Idle,
        };
        assert!(faces.place_face(1, taken).is_ok());
        assert_eq!(
            faces.read_face(0, 100, 0, &mut None, &mut None).role,
            LinkRole::Dial
        );
        #[cfg(feature = "listen")]
        {
            assert_eq!(
                faces.read_face(1, 1, 0, &mut None, &mut None).role,
                LinkRole::Taken
            );
            assert_eq!(
                faces.read_face(9, 9, 0, &mut None, &mut None).role,
                LinkRole::Taken
            );
        }
        // Without `listen` no face is taken besides the dial: a place past the first holds only a
        // departed face's tomb, read in the one role there is.
        #[cfg(not(feature = "listen"))]
        {
            assert_eq!(
                faces.read_face(1, 1, 0, &mut None, &mut None).role,
                LinkRole::Dial
            );
            assert_eq!(
                faces.read_face(9, 9, 0, &mut None, &mut None).role,
                LinkRole::Dial
            );
        }
    }

    /// A table of the dial role's face alone reads every place in that role, so a step of such a
    /// session never names a face to remove; a dial role's face that stands by finds no node held,
    /// as no other face is there to hold one. Turned red by a role read off the place in such a
    /// table.
    #[test]
    fn a_table_of_one_face_reads_every_place_in_the_dial_role() {
        #[cfg(feature = "listen")]
        let link = Link::Idle;
        #[cfg(not(feature = "listen"))]
        let link = Link::Idle;
        let mut faces: LinkSupervisor<Net, TestFace, OneFace<TestFace>> = LinkSupervisor::new(
            Net,
            TestFace {
                id: 100,
                link,
                life: idle_life(),
            },
            2,
            2,
        )
        .expect("the heap holds two waits");
        assert!(!faces.takes_faces());
        assert!(
            supervisor(Link::Idle, 2).takes_faces(),
            "CONTROL: a table of many faces takes them"
        );
        assert_eq!(
            faces.read_face(0, 100, 0, &mut None, &mut None).role,
            LinkRole::Dial
        );
        assert_eq!(
            faces.read_face(1, 1, 0, &mut None, &mut None).role,
            LinkRole::Dial
        );
        #[cfg(feature = "listen")]
        assert_eq!(
            faces.read_face(0, 100, 0, &mut None, &mut None).input,
            LinkInput::Tick
        );
    }

    /// A dial that is over is let go of and hands over the endpoint it dialled, its own text
    /// whole, the face waiting from then; a face that held no dial waits all the same and hands
    /// none, and a face past the table is left as it is.
    #[test]
    fn an_ended_dial_hands_over_its_endpoint_and_its_face_waits() {
        #[cfg(feature = "listen")]
        let named = DialEndpoint::Named(LocatorText::try_from("tcp/1.2.3.4:1").expect("a row"));
        #[cfg(not(feature = "listen"))]
        let named = DialEndpoint::Listed(3);
        let mut faces = supervisor(dialing(named.clone(), None), 2);
        assert_eq!(faces.end_dial(0), Some(named));
        assert!(matches!(dial(&faces).link, Link::Idle));

        faces.put_link(0, Link::Idle);
        assert_eq!(faces.end_dial(0), None, "no dial, no endpoint");
        assert!(matches!(dial(&faces).link, Link::Idle));

        assert_eq!(faces.end_dial(5), None, "past the table");
        assert!(matches!(dial(&faces).link, Link::Idle));
    }

    /// A dial is asked once where it is put: one under way is put in the face, and one answered
    /// at once is handed back with its answer, the face keeping the dial it held. Turned red by an
    /// answered dial put in the face, or one under way handed back and not put there.
    #[test]
    fn a_dial_under_way_is_put_in_its_face_and_one_answered_is_handed_back() {
        let asks = Rc::new(Cell::new(0));
        let mut faces = supervisor(Link::Idle, 1);
        let answered = faces.ask_dial(0, DialEndpoint::Listed(2), Answer(None, Some(asks.clone())));
        assert!(answered.is_none(), "the dial is under way");
        assert_eq!(asks.get(), 1, "asked once");
        match &dial(&faces).link {
            Link::Dialing(dial) => assert_eq!(dial.endpoint(), &DialEndpoint::Listed(2)),
            _ => panic!("the face holds the dial under way"),
        }

        let answered = faces.ask_dial(
            0,
            DialEndpoint::Listed(0),
            Answer(Some(Err(LinkOpenError::Refused)), Some(asks.clone())),
        );
        assert!(matches!(answered, Some(Err(LinkOpenError::Refused))));
        assert_eq!(asks.get(), 2, "asked once more");
        assert!(
            matches!(
                &dial(&faces).link,
                Link::Dialing(dial) if dial.endpoint() == &DialEndpoint::Listed(2)
            ),
            "an answered dial is not put in the face"
        );
    }

    /// The node a face's handshake reached is the one it stands by for only while another face
    /// reaches it; a face with no link, or one past the table, reached none.
    #[test]
    fn a_face_stands_by_for_its_node_only_while_another_face_reaches_it() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
        let node = [7u8, 1];
        let mut faces = supervisor(
            Link::Wire(wire(&local, session(false, Some(&node)), false, false)),
            2,
        );
        assert!(
            faces.held_node(0, 100).is_none(),
            "no other face reaches it"
        );
        let other = TestFace {
            life: idle_life(),
            id: 1,
            link: Link::Wire(wire(&local, session(true, Some(&node)), false, false)),
        };
        assert!(faces.place_face(1, other).is_ok());
        assert!(faces.held_node(0, 100) == Some(held_node()));
        assert!(faces.drop_face(1).is_some());
        assert!(faces.held_node(0, 100).is_none());
        faces.put_link(0, Link::Idle);
        assert!(faces.held_node(0, 100).is_none(), "a face with no link");
        assert!(faces.held_node(9, 100).is_none(), "a face past the table");
    }

    /// The dial role's handshake that ends at a node another face holds is read as held
    /// elsewhere, and its life stands by; while the other face holds the node nothing moves it,
    /// and once that face goes the node is read as free. CONTROL: with no other face, the same
    /// end is read as ended. Turned red by a stand-by left to a link the life no longer holds.
    #[cfg(feature = "listen")]
    #[test]
    fn the_dial_role_stands_by_while_another_face_holds_its_node() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
        let node = [7u8, 1];
        let mut faces = supervisor(
            Link::Wire(wire(&local, session(false, Some(&node)), false, true)),
            2,
        );
        set_life(
            &mut faces,
            life_in(&[
                LinkInput::Open,
                LinkInput::DialMade,
                LinkInput::HandshakeBegun,
            ]),
        );
        assert_eq!(
            faces.read_face(0, 100, 0, &mut None, &mut None).input,
            LinkInput::Ended,
            "CONTROL: no other face holds the node"
        );
        let other = TestFace {
            life: idle_life(),
            id: 1,
            link: Link::Wire(wire(&local, session(true, Some(&node)), false, false)),
        };
        assert!(faces.place_face(1, other).is_ok());
        let read = faces.read_face(0, 100, 0, &mut None, &mut None);
        assert_eq!(read.input, LinkInput::HeldElsewhere);
        let face = faces.face_mut(0).expect("the dial role's face");
        assert!(face.life.input(read.input, 0).end_handshake());
        assert_eq!(face.life.phase(), LinkPhase::Held);
        faces.put_link(0, Link::Idle);
        assert_eq!(
            faces.read_face(0, 100, 0, &mut None, &mut None).input,
            LinkInput::Tick,
            "the other face holds the node still"
        );
        assert!(faces.drop_face(1).is_some());
        assert_eq!(
            faces.read_face(0, 100, 0, &mut None, &mut None).input,
            LinkInput::NodeFree
        );
    }

    /// A handshake that ended names the Close its peer sent, else the end of its task, else the
    /// deadline it is given up at; ending the link's task is what makes it the second.
    #[test]
    fn a_handshake_end_names_the_close_the_task_end_or_the_deadline() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
        let opening = |session| Link::Wire(wire(&local, session, false, false));
        let closed = Session {
            closed: Some(CloseReason::Generic),
            ..session(false, None)
        };
        let mut faces = supervisor(opening(closed), 1);
        assert_eq!(
            faces.handshake_end(0),
            HandshakeEnd::Closed(CloseReason::Generic)
        );
        faces.put_link(0, opening(session(false, None)));
        assert_eq!(faces.handshake_end(0), HandshakeEnd::NoAnswerInTime);
        faces.abort_link(0);
        assert_eq!(faces.handshake_end(0), HandshakeEnd::Ended);
        faces.put_link(0, Link::Idle);
        faces.abort_link(0);
        assert_eq!(faces.handshake_end(0), HandshakeEnd::Ended, "no link");
        faces.abort_link(9);
        assert_eq!(
            faces.handshake_end(9),
            HandshakeEnd::Ended,
            "past the table"
        );
    }

    /// The node a face that stands by holds in these tests.
    fn held_node() -> SessionZid {
        SessionZid::new(&[7, 1]).expect("a zid")
    }

    /// The dial role's face, at the first place.
    fn dial(faces: &LinkSupervisor<Net, TestFace>) -> &TestFace {
        faces
            .face(0)
            .expect("the dial role's face holds the first place")
    }

    /// The table takes a face only at a free place within it, never at the dial role's, and
    /// gives up no face at the dial role's place.
    #[test]
    fn the_table_takes_no_face_past_its_room_and_never_gives_up_the_dial_role() {
        let mut faces = supervisor(Link::Idle, 2);
        let face = |id| TestFace {
            life: idle_life(),
            id,
            link: Link::Idle,
        };
        assert!(faces.place_face(1, face(1)).is_ok());
        assert!(matches!(
            faces.place_face(2, face(2)),
            Err(TestFace { id: 2, .. })
        ));
        assert!(
            matches!(faces.place_face(1, face(3)), Err(TestFace { id: 3, .. })),
            "a place a face holds"
        );
        assert!(
            matches!(faces.place_face(0, face(4)), Err(TestFace { id: 4, .. })),
            "the dial role's place"
        );
        assert!(faces.drop_face(0).is_none(), "the dial role's face stays");
        assert!(faces.drop_face(2).is_none(), "past the table");
        assert_eq!(faces.drop_face(1), Some(1));
        assert!(faces.drop_face(1).is_none(), "the place is free");
        assert_eq!(faces.next_face_id(), 1);
        faces.advance_face_id();
        assert_eq!(faces.next_face_id(), 2);
    }

    /// A face keeps its place while a face before it is taken out, and the next face takes the
    /// free place it was put at: no face moves. Turned red by a table that closes the gap a face
    /// left (the faces after it moved down a place).
    #[test]
    fn a_face_keeps_its_place_while_another_is_taken_out() {
        let mut faces = supervisor(Link::Idle, 4);
        let face = |id| TestFace {
            life: idle_life(),
            id,
            link: Link::Idle,
        };
        assert!(faces.place_face(1, face(1)).is_ok());
        assert!(faces.place_face(2, face(2)).is_ok());
        assert_eq!(faces.held(), 3);
        assert_eq!(faces.drop_face(1), Some(1));
        assert_eq!(faces.face(2).map(|face| face.id), Some(2), "it stays");
        assert!(faces.face(1).is_none());
        assert_eq!(faces.held(), 2);
        assert!(faces.place_face(1, face(3)).is_ok());
        let placed: Vec<(usize, FaceId)> = faces.placed().map(|(at, face)| (at, face.id)).collect();
        assert_eq!(placed, [(0, 100), (1, 3), (2, 2)]);
        assert_eq!(faces.places(), 4);
    }

    /// The texts of a session lent `dials` rows to dial and `listens` to listen on, in a test's
    /// own memory, none written.
    fn lent_texts(dials: usize, listens: usize) -> EndpointTexts {
        use core::ptr::NonNull;
        use wz_session_core::bounded::Arena;

        const BYTES: usize = 4096;
        #[repr(C, align(16))]
        struct Memory([u8; BYTES]);

        let memory: &'static mut Memory = Box::leak(Box::new(Memory([0; BYTES])));
        // SAFETY: the memory is leaked, so it outlives the arena and every row it lends; it is
        // aligned as an arena's spans start, BYTES long, and used by nothing else.
        let mut arena = unsafe { Arena::over(NonNull::from(memory).cast::<u8>(), BYTES) };
        EndpointTexts::over(
            arena.lend(dials).expect("the memory holds the dial rows"),
            arena
                .lend(listens)
                .expect("the memory holds the listen rows"),
        )
    }

    /// The texts of a session that dials `dials` and listens on `listens`, as an open writes
    /// them.
    fn texts(dials: &[&str], listens: &[&str]) -> EndpointTexts {
        let mut texts = lent_texts(dials.len(), listens.len());
        for text in dials {
            texts.write_dial(text).expect("a row for each");
        }
        for text in listens {
            texts.write_listen(text).expect("a row for each");
        }
        texts
    }

    /// An endpoint reads as the row its dial or its port names, or as its own text; a row past
    /// the last reads empty.
    #[test]
    fn an_endpoint_reads_from_its_row_or_its_own_text() {
        let texts = texts(&["udp/10.0.0.1:7447"], &["tcp/0.0.0.0:7447"]);
        assert_eq!(DialEndpoint::Listed(0).text(&texts), "udp/10.0.0.1:7447");
        assert_eq!(
            DialEndpoint::Listed(1).text(&texts),
            "",
            "past the dial rows"
        );
        #[cfg(feature = "listen")]
        {
            assert_eq!(DialEndpoint::Port(0).text(&texts), "tcp/0.0.0.0:7447");
            assert_eq!(
                DialEndpoint::Port(1).text(&texts),
                "",
                "past the listen rows"
            );
            assert_eq!(
                DialEndpoint::Named(LocatorText::try_from("tcp/1.2.3.4:1").expect("a row"))
                    .text(&texts),
                "tcp/1.2.3.4:1"
            );
        }
    }

    /// A build that takes no port and dials no face beside the dial role's names an endpoint by
    /// its row alone, so a dial, a link and the endpoint a dial hands over carry a word and no
    /// text. Turned red by a variant that holds a text left in that build.
    #[cfg(not(feature = "listen"))]
    #[test]
    fn an_endpoint_of_a_build_that_only_dials_is_a_row() {
        assert_eq!(
            core::mem::size_of::<DialEndpoint>(),
            core::mem::size_of::<usize>()
        );
        assert!(core::mem::size_of::<Option<DialEndpoint>>() <= 2 * core::mem::size_of::<usize>());
    }

    /// A text is written in the next row and answered with its place; one longer than a row is
    /// refused by its length, and one past the rows the open lent as full, neither taking a row.
    #[test]
    fn an_endpoint_text_takes_the_next_row_or_is_refused() {
        let mut texts = lent_texts(2, 1);
        assert_eq!(texts.write_dial("udp/10.0.0.1:7447"), Ok(0));
        assert_eq!(texts.write_dial("tcp/10.0.0.2:7447"), Ok(1));
        assert_eq!(
            texts.write_dial("tcp/10.0.0.3:7447"),
            Err(EndpointTextRefused::Full),
            "past the rows lent"
        );
        assert_eq!(texts.dials(), 2);
        assert_eq!(texts.dial_text(1), "tcp/10.0.0.2:7447");
        let long = "a".repeat(caps::MAX_LOCATOR_LEN + 1);
        assert_eq!(
            texts.write_listen(&long),
            Err(EndpointTextRefused::TooLong { len: long.len() })
        );
        assert_eq!(texts.listens(), 0, "a refused text takes no row");
        let exact = "a".repeat(caps::MAX_LOCATOR_LEN);
        assert_eq!(
            texts.write_listen(&exact),
            Ok(0),
            "a text of a row's length fits"
        );
    }

    /// A read asks each port for its wait when it waits, not once when the port opened: a port
    /// that gives none now is looked at again after a bounded sleep. Turned red by a wait read
    /// once at the listen and kept.
    #[cfg(feature = "listen")]
    #[test]
    fn a_read_asks_each_port_for_its_wait_at_each_wait() {
        let mut faces = supervisor(Link::Idle, 1);
        faces
            .listen(
                Locator::tcp(core::net::SocketAddr::from(([0, 0, 0, 0], 7447))),
                None,
            )
            .expect("a port");
        match faces.idle_wait(10, &mut || 0u64, [], None) {
            IdleWait::Input { on, ms } => {
                assert_eq!(on, [LinkWait::input(WaitOn::Socket(7))]);
                assert_eq!(ms, 10);
                faces.waited(IdleWait::Input { on, ms });
            }
            _ => panic!("the port's wait"),
        }
        assert!(matches!(
            faces.idle_wait(10, &mut || 0u64, [], None),
            IdleWait::Sleep(1)
        ));
    }

    /// A read sleeps to the end of a wait to dial again, and to the next look of a dial under way
    /// when its deadline is later; a face standing by gives no time, and its read takes none
    /// from the clock. A link holding input makes no wait. Turned red by a wake read off the link
    /// and not off the face's life.
    #[test]
    fn a_read_sleeps_to_the_next_dial_and_does_not_wait_on_held_input() {
        let mut clock_reads = 0;
        let mut now = || {
            clock_reads += 1;
            1_000u64
        };
        let mut faces = supervisor(Link::Idle, 1);
        set_life(&mut faces, backing_off());
        assert_eq!(
            faces.face(0).map(|face| face.life.phase()),
            Some(LinkPhase::Backoff { until_us: 5_000 })
        );
        assert!(matches!(
            faces.idle_wait(10, &mut now, [], None),
            IdleWait::Sleep(4)
        ));
        // A dial under way is looked at again on the next look, its deadline being later.
        faces.put_link(0, dialing(DialEndpoint::Listed(0), None));
        set_life(
            &mut faces,
            life_in(&[LinkInput::Open, LinkInput::DialPending]),
        );
        assert!(matches!(
            faces.idle_wait(10, &mut now, [], None),
            IdleWait::Sleep(1)
        ));
        #[cfg(feature = "listen")]
        {
            faces.put_link(0, Link::Idle);
            set_life(&mut faces, standing_by());
            let before = clock_reads;
            assert!(matches!(
                faces.idle_wait(
                    10,
                    &mut || {
                        clock_reads += 1;
                        1_000u64
                    },
                    [],
                    None
                ),
                IdleWait::None
            ));
            assert_eq!(clock_reads, before, "a face standing by reads no clock");
        }

        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
        faces.put_link(
            0,
            Link::Wire(wire(&local, session(true, None), true, false)),
        );
        assert!(faces.holds_input());
        assert!(matches!(
            faces.idle_wait(10, &mut || 0u64, [], None),
            IdleWait::None
        ));
    }

    /// A read waits on each link's handle, for its input, and for its room as well while it owes
    /// its stack a write; what is waited on beside the links (a group's input) follows them.
    /// Turned red by a link that owes and is waited on for its input alone, or one that does not
    /// owe and wakes its owner on room.
    #[test]
    fn a_read_waits_on_each_links_handle_and_on_its_room_while_it_owes() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
        let group = LinkWait::input(WaitOn::Socket(9));
        for (owes, first) in [
            (false, LinkWait::input(WaitOn::Socket(3))),
            (true, LinkWait::input_or_room(WaitOn::Socket(3))),
        ] {
            let mut faces = supervisor(Link::Wire(waited_wire(&local, WaitOn::Socket(3), owes)), 1);
            match faces.idle_wait(10, &mut || 0u64, [group], None) {
                IdleWait::Input { on, ms } => {
                    assert_eq!(on, [first, group], "owes {owes}");
                    assert_eq!(ms, 10);
                }
                _ => panic!("a wait on the link and the group"),
            }
        }
    }

    /// A wait tells each link its owner waits on whether it found input in the link's stack, and a
    /// move tells each that its stack is read again; a link that waits in its own loop is told
    /// nothing, nor is any link by a read that made no wait. Turned red by a wait that tells a link
    /// it found nothing in that it found input (each link read at every step again), by one that
    /// tells a link it found input in that it found none (its input not read until a move), by a
    /// move that leaves a link quiet (a stack a run of steps without a wait passed over not read
    /// again), or by a link of its own loop told it is quiet.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[test]
    fn a_wait_tells_each_waited_link_what_it_found_and_a_move_reads_them_all() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
        let waited = |session: Session, on: WaitOn| -> TestLink {
            let task = local.spawn_local(async { DriverOutcome::Terminated });
            let link = CellRc::try_boxed(Waited { on, owes: false })
                .expect("the heap has room")
                .into_link();
            let (input_wait, room_wait) = (link.input_wait(), link.room_wait());
            Link::Wire(Wire::new(session, task, link, input_wait, room_wait))
        };
        let (found, empty, own) = (
            session(true, None),
            session(true, None),
            session(true, None),
        );
        let (found_seen, empty_seen, own_seen) =
            (found.seen.clone(), empty.seen.clone(), own.seen.clone());
        let mut faces = supervisor(waited(found, WaitOn::Socket(3)), 3);
        let empty = TestFace {
            life: idle_life(),
            id: 1,
            link: waited(empty, WaitOn::Socket(4)),
        };
        assert!(faces.place_face(1, empty).is_ok());
        let own = TestFace {
            life: idle_life(),
            id: 2,
            link: Link::Wire(wire(&local, own, false, false)),
        };
        assert!(faces.place_face(2, own).is_ok());
        let seen = || (found_seen.get(), empty_seen.get(), own_seen.get());

        faces.waited(IdleWait::None);
        faces.waited(IdleWait::Sleep(1));
        assert_eq!(
            seen(),
            (None, None, None),
            "a read that made no wait tells nothing"
        );
        faces.waited(IdleWait::Input {
            on: vec![LinkWait::input(WaitOn::Socket(3))],
            ms: 10,
        });
        assert_eq!(
            seen(),
            (Some(true), Some(false), None),
            "the link found ready reads its stack, the other not, and the own loop's is not told"
        );
        faces.links_moved();
        assert_eq!(
            seen(),
            (Some(true), Some(true), None),
            "a move reads every waited link's stack again"
        );
    }

    /// A read with more to wait on than the open reserved room for waits on what fits and looks
    /// again at once, and the buffer is not grown: what did not fit is looked at after a bound of
    /// a millisecond, not missed for the whole wait. CONTROL: the same read with room for both
    /// waits on both for as long as it was asked. Turned red by a wait past the room that grows the
    /// buffer, or by one dropped without bounding the wait.
    #[test]
    fn a_read_past_its_reserved_room_looks_again_and_grows_nothing() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
        let first = LinkWait::input(WaitOn::Socket(3));
        let group = LinkWait::input(WaitOn::Socket(9));
        for (room, waited, ms) in [(2, vec![first, group], 10), (1, vec![first], 1)] {
            let link = Link::Wire(waited_wire(&local, WaitOn::Socket(3), false));
            let mut faces: LinkSupervisor<Net, TestFace> = LinkSupervisor::new(
                Net,
                TestFace {
                    id: 100,
                    link,
                    life: idle_life(),
                },
                1,
                room,
            )
            .expect("the heap holds the waits");
            match faces.idle_wait(10, &mut || 0u64, [group], None) {
                IdleWait::Input { on, ms: bound } => {
                    assert_eq!(on, waited, "room {room}");
                    assert_eq!(bound, ms, "room {room}");
                    assert_eq!(on.capacity(), room, "the buffer is not grown");
                }
                _ => panic!("a wait on the link, room {room}"),
            }
        }
    }

    /// What a publish that waits for a slot waits on is each link that owes its stack a write, for
    /// its input and its room, and gathering it allocates nothing: it lies in the publishing
    /// thread's frame. CONTROL: a link that owes nothing is not in it. Turned red by waits
    /// gathered into a buffer of the heap.
    #[cfg(feature = "session-unicast-accept")]
    #[test]
    fn a_publish_gathers_the_links_owing_a_write_without_allocating() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
        let mut faces = supervisor(Link::Wire(waited_wire(&local, WaitOn::Socket(3), true)), 3);
        let quiet = TestFace {
            life: idle_life(),
            id: 1,
            link: Link::Wire(waited_wire(&local, WaitOn::Socket(4), false)),
        };
        assert!(faces.place_face(1, quiet).is_ok());
        let owing = TestFace {
            life: idle_life(),
            id: 2,
            link: Link::Wire(waited_wire(&local, WaitOn::Socket(5), true)),
        };
        assert!(faces.place_face(2, owing).is_ok());
        let (waits, made) = crate::table_tests::allocations(|| faces.owing_waits());
        assert_eq!(made, 0, "gathering the waits allocates nothing");
        let owe = [
            LinkWait::input_or_room(WaitOn::Socket(3)),
            LinkWait::input_or_room(WaitOn::Socket(5)),
        ];
        assert_eq!(
            *waits,
            owe[..OWING_WAITS.min(owe.len())],
            "the links that owe, for their input and their room"
        );
    }

    /// More links owing a write than `OWING_WAITS` is a link that owes with no outbound slot of
    /// the pool, which a test build names. Turned red by a gathering that cuts the waits short in
    /// silence.
    #[cfg(all(feature = "session-unicast-accept", debug_assertions))]
    #[test]
    #[should_panic(expected = "more links owe a write than the outbound slots they hold")]
    fn more_links_owing_than_the_slots_they_hold_is_named_in_a_test_build() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
        let past = OWING_WAITS.saturating_add(1);
        let mut faces = supervisor(
            Link::Wire(waited_wire(&local, WaitOn::Socket(3), true)),
            past,
        );
        for id in 1..past {
            let owing = TestFace {
                life: idle_life(),
                id: FaceId::try_from(id).unwrap_or(FaceId::MAX),
                link: Link::Wire(waited_wire(&local, WaitOn::Socket(3 + id), true)),
            };
            assert!(faces.place_face(id, owing).is_ok(), "room for each face");
        }
        let _ = faces.owing_waits();
    }

    /// A wait on links is the stack's for the whole time, and leaves in its buffer what the stack
    /// found ready: every entry, for a stack that cannot tell. Turned red by a wait that bounds
    /// the links' wait short of its time.
    #[test]
    fn a_wait_on_links_is_the_stacks_for_the_whole_time() {
        let link = LinkWait::input(WaitOn::Socket(3));
        let asked = Asked::default();
        let mut wait = IdleWait::Input {
            on: vec![link],
            ms: 10,
        };
        wait.wait(&asked, |_| panic!("no sleep"));
        assert_eq!(asked.entries.load(Ordering::Relaxed), 1);
        assert_eq!(asked.ms.load(Ordering::Relaxed), 10);
        assert!(matches!(wait, IdleWait::Input { ref on, .. } if *on == [link]));
    }

    /// A wait asks its stack which entries were ready only in a build that reads them (`listen`
    /// or `group`), and leaves those alone in its buffer; a build without either asks for the
    /// plain wait and leaves the buffer as it was made. Turned red by an arm that asks the other
    /// call, or a build without ports that cuts its buffer to what was found ready.
    #[test]
    fn a_wait_asks_which_entries_were_ready_only_where_they_are_read() {
        /// Counts each kind of wait; its stack finds nothing ready.
        #[derive(Default)]
        struct Counted {
            plain: core::sync::atomic::AtomicU32,
            ready: core::sync::atomic::AtomicU32,
        }

        impl LinkWaits for Counted {
            fn wait(&self, _on: &[LinkWait], _timeout_ms: u32) {
                self.plain.fetch_add(1, Ordering::Relaxed);
            }

            fn wait_ready(&self, _on: &mut [LinkWait], _timeout_ms: u32) -> usize {
                self.ready.fetch_add(1, Ordering::Relaxed);
                0
            }

            fn wait_room(&self, _on: WaitOn, _timeout_us: u64) -> bool {
                true
            }
        }

        let link = LinkWait::input(WaitOn::Socket(3));
        let stack = Counted::default();
        let mut wait = IdleWait::Input {
            on: vec![link],
            ms: 10,
        };
        wait.wait(&stack, |_| panic!("no sleep"));
        let IdleWait::Input { on, .. } = wait else {
            panic!("the wait keeps its buffer");
        };
        let asked = (
            stack.plain.load(Ordering::Relaxed),
            stack.ready.load(Ordering::Relaxed),
        );
        if cfg!(any(feature = "listen", feature = "group")) {
            assert_eq!(asked, (0, 1), "the wait that tells what was ready");
            assert!(on.is_empty(), "nothing was found ready");
        } else {
            assert_eq!(asked, (1, 0), "the plain wait");
            assert_eq!(on, [link], "the buffer as it was made");
        }
    }

    /// The looks at a port a test of `accept_at` makes, its port asked only when ready as
    /// `when_ready` says: one before any wait, three after a wait that found nothing ready, three
    /// after one whose stack cannot tell. How often the port was asked.
    #[cfg(feature = "listen")]
    fn asks_of_a_port(when_ready: bool) -> u32 {
        let asked = Rc::new(Cell::new(0));
        let mut faces: LinkSupervisor<Ports, TestFace> = LinkSupervisor::new(
            Ports(asked.clone(), when_ready),
            TestFace {
                life: idle_life(),
                id: 100,
                link: Link::Idle,
            },
            1,
            2,
        )
        .expect("the heap holds two waits");
        faces
            .listen(
                Locator::tcp(core::net::SocketAddr::from(([127, 0, 0, 1], 7447))),
                None,
            )
            .expect("the port is bound");
        assert!(matches!(faces.accept_at(0), Some(Accepted::Idle)));
        let mut wait = faces.idle_wait(10, &mut || 0u64, [], None);
        assert!(
            matches!(wait, IdleWait::Input { ref on, .. } if *on == [LinkWait::input(WaitOn::Socket(9))]),
            "the read waits on the port"
        );
        wait.wait(&NoneReady, |_| panic!("no sleep"));
        faces.waited(wait);
        for _ in 0..3 {
            assert!(matches!(faces.accept_at(0), Some(Accepted::Idle)));
        }
        let mut wait = faces.idle_wait(10, &mut || 0u64, [], None);
        wait.wait(&crate::session_drive::NoWaits, |_| panic!("no sleep"));
        faces.waited(wait);
        for _ in 0..3 {
            assert!(matches!(faces.accept_at(0), Some(Accepted::Idle)));
        }
        asked.get()
    }

    /// A port asked only when ready is asked for a connection once before any wait names it, and
    /// after that only once a wait found it ready, until it answers that it has none: a step a
    /// batch asks the stack nothing. CONTROL: a port that is not so is asked at every look.
    /// Turned red by a step that asks every port (the readiness test taken out of `accept_at`),
    /// or a wait that marks a port it did not find ready.
    #[cfg(feature = "listen")]
    #[test]
    fn a_port_is_asked_for_a_connection_only_after_a_wait_found_it_ready() {
        assert_eq!(
            asks_of_a_port(true),
            2,
            "once before any wait, none after a wait that found nothing, once after one that did"
        );
        assert_eq!(asks_of_a_port(false), 7, "CONTROL: asked at every look");
    }

    /// A port asked only when ready that the read has no room to wait on is asked at every look:
    /// no wait can find it ready, and the read does not grow its buffer for it. CONTROL: with room
    /// for its wait, a wait that found nothing ready leaves it unasked
    /// (`a_port_is_asked_for_a_connection_only_after_a_wait_found_it_ready`). Turned red by a port
    /// left to a wait the read made no room for, which is then never asked.
    #[cfg(feature = "listen")]
    #[test]
    fn a_port_its_read_has_no_room_to_wait_on_is_asked_at_every_look() {
        let asked = Rc::new(Cell::new(0));
        let mut faces: LinkSupervisor<Ports, TestFace> = LinkSupervisor::new(
            Ports(asked.clone(), true),
            TestFace {
                life: idle_life(),
                id: 100,
                link: Link::Idle,
            },
            1,
            0,
        )
        .expect("the heap holds no wait");
        faces
            .listen(
                Locator::tcp(core::net::SocketAddr::from(([127, 0, 0, 1], 7447))),
                None,
            )
            .expect("the port is bound");
        let wait = faces.idle_wait(10, &mut || 0u64, [], None);
        assert!(
            !matches!(wait, IdleWait::Input { .. }),
            "the read has no room to wait on the port"
        );
        faces.waited(wait);
        for _ in 0..3 {
            assert!(matches!(faces.accept_at(0), Some(Accepted::Idle)));
        }
        assert_eq!(asked.get(), 3, "the port is asked at every look");
    }
    /// A wake beside the links joins the wait they make, after them; a sleep to the next dial
    /// becomes a wait on the wake for the same time; and where they make no wait, it makes none.
    /// CONTROL: without it the same faces sleep. Turned red by a wake that is left out of a
    /// sleep, which the program's word could then not end, or one that makes a wait of its own.
    #[test]
    fn a_wake_beside_the_links_joins_their_wait_and_makes_none_of_its_own() {
        let wake = LinkWait::input(WaitOn::Wake(5));
        let mut faces = supervisor(Link::Idle, 1);
        set_life(&mut faces, backing_off());
        assert!(
            matches!(
                faces.idle_wait(10, &mut || 1_000u64, [], None),
                IdleWait::Sleep(4)
            ),
            "CONTROL: a sleep to the next dial"
        );
        match faces.idle_wait(10, &mut || 1_000u64, [], Some(wake)) {
            IdleWait::Input { on, ms } => {
                assert_eq!(on, [wake]);
                assert_eq!(ms, 4, "the sleep's time");
            }
            _ => panic!("a sleep beside a wake waits on it"),
        }
        #[cfg(feature = "listen")]
        {
            set_life(&mut faces, standing_by());
            assert!(
                matches!(
                    faces.idle_wait(10, &mut || 0u64, [], Some(wake)),
                    IdleWait::None
                ),
                "the wake made a wait of its own"
            );
        }

        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
        let link = LinkWait::input(WaitOn::Socket(3));
        let mut faces = supervisor(Link::Wire(waited_wire(&local, WaitOn::Socket(3), false)), 1);
        match faces.idle_wait(10, &mut || 0u64, [], Some(wake)) {
            IdleWait::Input { on, ms } => {
                assert_eq!(on, [link, wake], "the wake after the links");
                assert_eq!(ms, 10);
            }
            _ => panic!("a wait on the link and the wake"),
        }
    }

    /// A read on another thread while one waits with the session's buffer waits for it to be
    /// handed back and allocates nothing, and the buffer handed back serves the next read whole.
    /// CONTROL: the first read waits on the link. Turned red by a second read that gathers its
    /// waits into a buffer of its own, which after the open is one of the heap.
    #[test]
    fn a_read_while_another_waits_with_the_buffer_waits_behind_and_allocates_nothing() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
        let link = LinkWait::input(WaitOn::Socket(3));
        let mut faces = supervisor(Link::Wire(waited_wire(&local, WaitOn::Socket(3), false)), 1);
        let first = faces.idle_wait(10, &mut || 0u64, [], None);
        assert!(
            matches!(first, IdleWait::Input { ref on, ms: 10 } if *on == [link]),
            "CONTROL: the first read waits on the link"
        );
        let (second, made) =
            crate::table_tests::allocations(|| faces.idle_wait(10, &mut || 0u64, [], None));
        assert!(
            matches!(second, IdleWait::Behind(10)),
            "the second waits for the buffer"
        );
        assert_eq!(made, 0, "the second read makes no buffer");
        assert!(
            matches!(faces.idle_wait(0, &mut || 0u64, [], None), IdleWait::None),
            "a read with no time to wait does not sleep"
        );
        faces.waited(first);
        let (third, made) =
            crate::table_tests::allocations(|| faces.idle_wait(10, &mut || 0u64, [], None));
        assert!(
            matches!(third, IdleWait::Input { ref on, ms: 10 } if *on == [link]),
            "the buffer handed back waits on the link again"
        );
        assert_eq!(made, 0, "the buffer handed back is the one reserved");
    }

    #[test]
    fn ending_lets_dials_go_first_then_tells_established_peers_and_keeps_the_dial_role() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
        let mut faces = supervisor(dialing(DialEndpoint::Listed(0), None), 3);
        faces.end_dials_and_ports();
        assert!(
            matches!(dial(&faces).link, Link::Idle),
            "a dial under way is let go of"
        );
        let up = session(true, None);
        let up_ended = up.ended.clone();
        let opening = session(false, None);
        let opening_ended = opening.ended.clone();
        faces.put_link(0, Link::Wire(wire(&local, up, false, false)));
        let other = TestFace {
            life: idle_life(),
            id: 1,
            link: Link::Wire(wire(&local, opening, false, false)),
        };
        assert!(faces.place_face(1, other).is_ok());
        let mut shown = 0;
        faces.end_faces(|_| shown += 1);
        assert_eq!(shown, 2);
        assert_eq!(up_ended.get(), 1, "an established peer is told");
        assert_eq!(opening_ended.get(), 0, "a handshake under way is not");
        assert_eq!(faces.held(), 1);
        assert!(faces.face(1).is_none(), "the others go");
        assert_eq!(faces.places(), 3, "their places stay, free");
        assert!(matches!(dial(&faces).link, Link::Idle));
    }

    /// Put `face` at the place `at` of `table`, as [`LinkSupervisor::place_face`] puts it.
    fn put<F, P: FacePlaces<F>>(table: &mut P, at: usize, face: F) -> Result<(), F> {
        match table.vacant(at) {
            Some(place) => {
                place.put(face);
                Ok(())
            }
            None => Err(face),
        }
    }

    /// A face is built where its place lies and dropped there: the face a maker writes in its
    /// place is the one the place holds, a maker that lends a face it did not build there leaves
    /// the place free, and a face freed, or one the table still holds when it goes, is dropped
    /// once.
    ///
    /// # Control
    ///
    /// A `fill` that held a place whatever its maker lent reds the assertion on place 2; a `free`
    /// or a drop of the table that left the face undropped reds the counts.
    #[test]
    fn a_face_is_built_where_its_place_lies_and_dropped_there() {
        let dial = Rc::new(0_u32);
        let one = Rc::new(1_u32);
        let mut table = ManyFaces::with_dial(Rc::clone(&dial), 3);
        let made = table
            .vacant(1)
            .and_then(|place| place.fill(|slot| slot.write(Rc::clone(&one))))
            .map(|face| **face);
        assert_eq!(made, Some(1), "the face built in its place is lent");
        assert_eq!(
            Rc::strong_count(&one),
            2,
            "the place holds the face it built"
        );
        assert!(table.vacant(1).is_none(), "a place built in is held");
        let elsewhere = table
            .vacant(2)
            .and_then(|place| place.fill(|_| Box::leak(Box::new(Rc::new(7_u32)))));
        assert!(elsewhere.is_none(), "a face built elsewhere is not placed");
        assert!(table.get(2).is_none(), "its place stays free");
        assert!(table.free(1), "the face at place 1 goes");
        assert_eq!(
            Rc::strong_count(&one),
            1,
            "a face freed is dropped where it lay"
        );
        assert!(!table.free(1), "a free place frees nothing");
        assert_eq!(put(&mut table, 2, Rc::clone(&one)), Ok(()));
        drop(table);
        assert_eq!(
            Rc::strong_count(&one),
            1,
            "the table's drop drops what it holds"
        );
        assert_eq!(Rc::strong_count(&dial), 1, "the dial role's face with it");
    }

    /// A table of many faces keeps the dial role's at the first place for good, puts a face at a
    /// free place only, and walks the held places alone, each with its place.
    ///
    /// # Control
    ///
    /// A `put` that took the dial role's place, or a `free` that gave it up, reds the first
    /// assertions; a walk that read the free places reds the `placed` list.
    #[test]
    fn a_table_of_many_faces_keeps_each_face_at_its_place() {
        let mut table = ManyFaces::with_dial(10_u32, 3);
        assert_eq!(table.places(), 3);
        assert_eq!(
            put(&mut table, 0, 11),
            Err(11),
            "the dial role's place is never put"
        );
        assert!(!table.free(0), "the dial role's face is never taken");
        assert_eq!(put(&mut table, 2, 12), Ok(()));
        assert_eq!(
            put(&mut table, 2, 13),
            Err(13),
            "a held place is not put again"
        );
        assert_eq!(put(&mut table, 3, 14), Err(14), "past the table");
        assert_eq!(table.placed().collect::<Vec<_>>(), [(0, &10), (2, &12)]);
        assert_eq!(table.get(1), None, "a free place holds no face");
        assert!(table.free(2));
        assert_eq!(put(&mut table, 1, 15), Ok(()));
        table.keep_dial_only();
        assert_eq!(table.iter().collect::<Vec<_>>(), [&10]);
        assert_eq!(table.places(), 3, "the places stay, free");
    }

    /// A table of many faces walks its places up to the last one held and no further: a face put
    /// at a far place brings the free places before it into the walk, and the walk ends at the
    /// last face again once that face is taken out or every face but the dial role's goes. The
    /// places reserved past the row stay, and a face put at the last of them takes no memory.
    ///
    /// # Control
    ///
    /// A `take` that left the row as long as it was (no `truncate`) reds the row's length after
    /// the face at place 4 is taken out.
    #[test]
    fn a_table_of_many_faces_walks_its_places_up_to_the_last_face_held() {
        let mut table = ManyFaces::with_dial(10_u32, 11);
        let room = table.faces.capacity();
        assert_eq!(
            table.faces.len(),
            1,
            "the dial role's place alone is walked"
        );
        assert_eq!(put(&mut table, 4, 14), Ok(()));
        assert_eq!(table.faces.len(), 5, "the walk reaches the face at place 4");
        assert_eq!(put(&mut table, 1, 11), Ok(()));
        assert_eq!(
            table.faces.len(),
            5,
            "a face before the last does not lengthen the walk"
        );
        assert!(table.free(4));
        assert_eq!(
            table.faces.len(),
            2,
            "the walk ends at the face at place 1 again"
        );
        assert_eq!(table.placed().collect::<Vec<_>>(), [(0, &10), (1, &11)]);
        assert_eq!(table.get(4), None, "a place past the walk holds no face");
        assert!(!table.free(4), "nor is one taken from it");
        assert_eq!(put(&mut table, 10, 20), Ok(()), "the last place is put");
        assert_eq!(put(&mut table, 11, 21), Err(21), "past the table");
        assert_eq!(
            table.faces.capacity(),
            room,
            "no place was added to the room reserved"
        );
        table.keep_dial_only();
        assert_eq!(
            table.faces.len(),
            1,
            "the dial role's place alone is walked again"
        );
        assert_eq!(table.places(), 11, "the places stay, free");
    }

    /// The face of a session that only dials is its dial role's alone, at the one place, whatever
    /// count of places the open names: nothing is put beside it, it is never taken, and every walk
    /// reads it once.
    ///
    /// # Control
    ///
    /// A `get` that answered past the first place, or a `put` that kept its face, reds the
    /// assertions on place 1.
    #[test]
    fn a_table_of_one_face_holds_its_dial_role_alone() {
        let mut table = OneFace::with_dial(10_u32, 4);
        assert_eq!(table.places(), 1, "one place, whatever the open counts");
        assert_eq!(table.get(0), Some(&10));
        assert_eq!(table.get(1), None, "no place past the first");
        assert_eq!(put(&mut table, 1, 11), Err(11), "no face is put beside it");
        assert!(!table.free(0), "the dial role's face is never taken");
        if let Some(face) = table.get_mut(0) {
            *face = 12;
        }
        table.keep_dial_only();
        assert_eq!(table.placed().collect::<Vec<_>>(), [(0, &12)]);
        assert_eq!(table.iter_mut().count(), 1);
        assert_eq!(
            table.placed_mut().map(|(at, _)| at).collect::<Vec<_>>(),
            [0]
        );
    }
}
