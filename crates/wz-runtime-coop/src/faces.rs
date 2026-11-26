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
use core::mem::{ManuallyDrop, MaybeUninit};
use core::ops::Deref;

use wz_session_core::bounded::{push_text, BoundedVec, Lent, Static};
use wz_session_core::caps;
use wz_session_core::close_reason::CloseReason;
use wz_session_core::driver_loop::DriverOutcome;
use wz_session_core::link_life::{LinkInput, LinkPhase, LinkRole, UnicastLink};
use wz_session_core::locator_directory::LocatorText;
#[cfg(feature = "resource-snapshot")]
use wz_session_core::resource_snapshot::{BuildMessageReading, BuildReceiveLedger};
use wz_session_core::session_zid::{SessionZid, ZID_MAX};
use wz_session_core::zid_hex::same_zid;

use crate::dial::{Begun, HostWalk};
use crate::link_cells::{CellRc, CountKind, FaceHeld, FaceParts, OneTask};
#[cfg(feature = "listen")]
use crate::session_drive::Locator;
use crate::session_drive::{
    LinkOpenError, LinkWait, LinkWaits, OpenedLink, PendingDial, SessionDatagramLink, SessionLinks,
    WaitOn,
};
use crate::sync::{FacePlace, HoldKind, Lend, LockKind, PlaceHold};
use crate::transport::TransportRefusal;
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

    /// `resource-snapshot` — what the link's receive path has counted: its transport messages and
    /// how they were spaced, cumulative. Required, so no session of a link is left out of the
    /// session's reading by a provided zero.
    #[cfg(feature = "resource-snapshot")]
    fn message_reading(&self) -> BuildMessageReading;
}

/// `resource-snapshot` — a handle on what one link's receive path counts, which a handle on the
/// place of the link's parts keeps apart from that place ([`FaceAt::counted_by`]): read with no
/// lend of the place, so a place another holder has, or one already emptied, still reads what the
/// link counted, and the session's reading neither falls for a moment nor loses a link it lets go
/// of.
#[cfg(feature = "resource-snapshot")]
pub trait MessageCount {
    /// What the link's receive path has counted, cumulative.
    fn reading(&self) -> BuildMessageReading;
}

/// `resource-snapshot` — what the session of the link `link` holds has counted, while it holds
/// one: a link counts from the moment it is put in, its handshake included, until it is let go of.
#[cfg(feature = "resource-snapshot")]
fn counted<W: FaceSession, D>(link: &Link<W, D>) -> Option<BuildMessageReading> {
    link.wire().map(FaceSession::message_reading)
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

    /// What a read's wait reads of the link ([`WireLook`]), in one look: a handle whose every
    /// read takes a hold of the link's place reads the three facts under one hold.
    fn look(&self) -> WireLook {
        if self.holds_input() {
            WireLook::HoldsInput
        } else if self.waits_for_buffer() {
            WireLook::WaitsForBuffer
        } else if self.owes_write() {
            WireLook::OwesWrite
        } else {
            WireLook::Quiet
        }
    }

    /// Tell an established peer the link ends ([`FaceSession::end`]); a link not established
    /// is told nothing.
    fn close(&self) {
        if self.established() {
            self.end();
        }
    }
}

/// What a read's wait reads of a link ([`FaceWire::look`]): the first of these that holds, in
/// the order the wait takes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireLook {
    /// The link holds input it has already taken from its stack: the read waits for nothing.
    HoldsInput,
    /// Its stack holds input it cannot read until another link gives a receive buffer back.
    WaitsForBuffer,
    /// It owes its stack the rest of a frame: waited on for its room as well as its input.
    OwesWrite,
    /// None of these: waited on for its input alone.
    Quiet,
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

    #[cfg(feature = "resource-snapshot")]
    fn message_reading(&self) -> BuildMessageReading {
        self.session.message_reading()
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

    /// `resource-snapshot` — what a handle on the parts' place keeps of what their link counts
    /// ([`FaceAt::counted_by`]).
    #[cfg(feature = "resource-snapshot")]
    type Count: MessageCount;

    /// Pay `owed`, debts the parts define (bits within [`PARTS_DEBTS`], never none) that were
    /// owed to the place while it was held ([`FaceSite::owe`]), with the parts lent. Takes no
    /// lock of the session: the place's holder may hold that lock, or wait for it while it holds
    /// the place, so a debt that needs the session's state is marked in the parts, and the
    /// holder that finds the mark carries it out under that lock.
    fn pay(&mut self, owed: u32);
}

/// Parts of a face's link that a send writes through a part of their own (the actions' send path
/// and the link's sink), apart from the part a read borrows: what a send held as a value writes
/// ([`FaceSite::hold_send`]).
pub trait SendParts: WireParts {
    /// The part a send writes.
    type Tx;

    /// The part a send writes of these parts.
    fn tx(&mut self) -> &mut Self::Tx;
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
/// let go of the place, so a debt is paid once, by whichever holder pays it. Beside the place lie
/// the facts of its link that are read with no lend of it ([`SiteFacts`]), cleared whenever the
/// place is given a link or emptied of one, by whoever holds the face's read.
pub struct FaceSite<K: LockKind, P: WireParts> {
    place: FacePlace<K, FaceHeld<P>>,
    /// What is owed to the parts the place holds: [`PARTS_DEBTS`] bits and [`CLOSE_OWED`].
    owed: AtomicU32,
    /// What the link the place holds is read to be, apart from the place.
    facts: SiteFacts,
}

impl<K: LockKind, P: WireParts> FaceSite<K, P> {
    /// A place that holds no parts yet, owing nothing.
    pub fn empty() -> Self {
        Self {
            place: FacePlace::empty(),
            owed: AtomicU32::new(0),
            facts: SiteFacts::new(),
        }
    }

    /// The facts of the place's link that are read with no lend of the place.
    pub fn facts(&self) -> &SiteFacts {
        &self.facts
    }

    /// Put `parts` in the place, as the face's link is made, and answer the parts it held. What
    /// was owed to the link the place held is not the new link's, nor is what it was read to be.
    pub fn hold(&self, parts: FaceHeld<P>) -> Option<FaceHeld<P>> {
        self.place.with_place(|place| {
            self.owed.store(0, Ordering::SeqCst);
            self.facts.clear();
            place.replace(parts)
        })
    }

    /// Take the parts out of the place, as the face goes; `None` when it held none. The facts of
    /// the link go with it.
    pub fn take(&self) -> Option<FaceHeld<P>> {
        self.place.with_place(|place| {
            self.facts.clear();
            place.take()
        })
    }

    /// [`Self::hold`] that waits for nothing: the parts the place held, or `parts` handed back
    /// while another thread holds the place or the calling thread is inside a hold of it
    /// ([`FacePlace::try_with_place`]). A holder of the session's lock changes a face's link
    /// through here, since a holder of the place may wait for that lock.
    pub fn try_hold(&self, parts: FaceHeld<P>) -> Result<Option<FaceHeld<P>>, FaceHeld<P>> {
        let mut carried = Some(parts);
        let held = self.place.try_with_place(|place| {
            self.owed.store(0, Ordering::SeqCst);
            self.facts.clear();
            carried.take().and_then(|parts| place.replace(parts))
        });
        match (held, carried) {
            // Not run: the parts are still the caller's.
            (None, Some(parts)) => Err(parts),
            (held, _) => Ok(held.flatten()),
        }
    }

    /// [`Self::take`] that waits for nothing: the parts the place held, [`Lend::Empty`] when it
    /// held none, and [`Lend::Held`] while another thread holds the place or the calling thread is
    /// inside a hold of it ([`FacePlace::try_with_place`]).
    pub fn try_take(&self) -> Lend<FaceHeld<P>> {
        match self.place.try_with_place(Option::take) {
            None => Lend::Held,
            Some(None) => Lend::Empty,
            Some(Some(parts)) => {
                self.facts.clear();
                Lend::Lent(parts)
            }
        }
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

    /// Tell the place's facts what a write through `held`, the parts lent from this site, begun
    /// at `mark` ([`SiteFacts::write_mark`]), left: whether the link owes its stack a write now
    /// ([`SiteFacts::wrote`]). Every holder that may write the link tells it as it lets go.
    #[inline]
    pub fn tell_written(&self, mark: WriteMark, held: &mut FaceHeld<P>) {
        let owes = held.lend(|parts| parts.wire().is_some_and(FaceWire::owes_write));
        self.facts.wrote(mark, owes);
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
        // Paid as the try lets go, or, the place held, by the holder or by the try's look after;
        // a place with no parts has no link to owe them to.
        if let Lend::Empty = self.try_lend(|_| ()) {
            self.owed.fetch_and(!bits, Ordering::SeqCst);
        }
    }

    /// Pay what is owed through `held`, which the caller holds lent from this site: the one
    /// place a debt is paid, so each is paid once. Every lend pays as it lets go; a holder that
    /// acts on what its parts were paid pays first, so that it acts on the debts owed until then.
    #[inline]
    pub fn pay(&self, held: &mut FaceHeld<P>) {
        let owed = self.take_owed();
        if owed != 0 {
            pay_held(held, owed, &self.facts);
        }
    }

    /// What is owed, the debt word left owing nothing: a read, and only for a word that owes a
    /// swap, or where no other thread reaches the site's values ([`LockKind::WAITS`] false, the
    /// kind's own contract) a write, so a lend that finds nothing owed writes nothing and takes
    /// no read-modify-write.
    // The read may miss a debt another thread owes as it is made: that debt came after this pay,
    // as one owed between the pay and the let go does, and the holder's look as it lets go
    // (`Self::pay_after`) is what pays either, its fence ordering it against the debtor's try
    // whatever this read saw. A debt the read sees is taken by the swap whole, with any bit owed
    // after the read.
    #[inline(always)]
    fn take_owed(&self) -> u32 {
        let owed = self.owed.load(Ordering::Relaxed);
        if owed == 0 {
            return 0;
        }
        if K::WAITS {
            return self.owed.swap(0, Ordering::SeqCst);
        }
        self.owed.store(0, Ordering::Relaxed);
        owed
    }

    /// Pay a debt that came after the holder paid and before it let go: neither the holder, which
    /// looked before the debt, nor its debtor, whose try found the place held, would pay it.
    #[inline]
    fn pay_after(&self) {
        // Orders the holder's let go before its look, and the debtor's debt before its try: one
        // of the two sees the other's write, so a debt is never left with neither to pay it. A
        // kind whose values no other thread reaches has its one thread's order for both, and no
        // fence.
        let owed = if K::WAITS {
            fence(Ordering::SeqCst);
            self.owed.load(Ordering::SeqCst)
        } else {
            self.owed.load(Ordering::Relaxed)
        };
        if owed != 0 {
            self.pay_late();
        }
    }

    /// The try that pays a debt found after the holder let go ([`Self::pay_after`]). Out of line
    /// and cold: every lend of a site looks at the debt word as it lets go, and only a debt owed
    /// in that window takes the place again, so each lend keeps inline only its look.
    #[cold]
    #[inline(never)]
    fn pay_late(&self) {
        let _ = self.place.try_lend(|held| self.pay(held));
    }
}

impl<K: HoldKind, P: SendParts> FaceSite<K, P> {
    /// A send on the link as a value ([`SiteSend`]): a hold of the parts that waits for whatever
    /// holds the place now and pays what is owed as it drops, as a lend of them does. `None`
    /// while the place holds no parts.
    ///
    /// # Safety
    ///
    /// What [`FaceHeld::lend`]'s `Send` bounds keep is the caller's to keep while it holds the
    /// send: no handle on a cell of the link made from the send part outlives the send, and no
    /// handle made outside the parts is put into them.
    // Out of line, as the send's drop is: every operation's hold of a face and every leg of a
    // publish take the place through this one body.
    #[inline(never)]
    pub unsafe fn hold_send(&self) -> Option<SiteSend<'_, K, P>> {
        let held = ManuallyDrop::new(self.place.hold_lent()?);
        // Taken once the place is held, so the count it marks is of the writes before this one.
        let mark = self.facts.write_mark();
        Some(SiteSend {
            site: self,
            held,
            mark,
        })
    }
}

/// A send on a face's link held as a value ([`FaceSite::hold_send`]): the parts, held until the
/// send drops and then paid what was owed meanwhile, as a lend of them is.
pub struct SiteSend<'a, K: HoldKind, P: SendParts> {
    site: &'a FaceSite<K, P>,
    /// Let go of in the send's drop, once the debts owed are paid.
    held: ManuallyDrop<PlaceHold<'a, K, FaceHeld<P>>>,
    /// The count of the link's writes as the send took the place ([`FaceSite::tell_written`]).
    mark: WriteMark,
}

impl<K: HoldKind, P: SendParts> SiteSend<'_, K, P> {
    /// The send part; `None` only for parts the place no longer holds, which a hold never finds.
    pub fn tx(&mut self) -> Option<&mut P::Tx> {
        let place: &mut Option<FaceHeld<P>> = &mut self.held;
        // SAFETY: what a lend's `Send` bounds keep is the holder's to keep while it holds the send
        // (`FaceSite::hold_send`'s contract).
        place
            .as_mut()
            .map(|parts| unsafe { parts.parts_mut() }.tx())
    }
}

impl<K: HoldKind, P: SendParts> Drop for SiteSend<'_, K, P> {
    // Out of line: every send held as a value lets the place go through this one body.
    #[inline(never)]
    fn drop(&mut self) {
        let place: &mut Option<FaceHeld<P>> = &mut self.held;
        if let Some(parts) = place.as_mut() {
            self.site.pay(parts);
            self.site.tell_written(self.mark, parts);
        }
        // SAFETY: the hold is let go of here alone, once, and is not reached after: the send is
        // being dropped.
        unsafe { ManuallyDrop::drop(&mut self.held) };
        self.site.pay_after();
    }
}

/// Pay `owed`, never none, to the parts `held` holds ([`FaceSite::pay`]). Out of line and cold:
/// a debt is owed only where a send or a close found the place held, so every lend of a site
/// shares this one body and keeps inline only its look at the debt word.
#[cold]
#[inline(never)]
// A debt paid may write the link (a close tells its peer), so what it left owed is told to the
// site's facts as a send's is (`FaceSite::tell_written`).
fn pay_held<P: WireParts>(held: &mut FaceHeld<P>, owed: u32, facts: &SiteFacts) {
    let mark = facts.write_mark();
    let owes = held.lend(move |parts| {
        pay_parts(parts, owed);
        parts.wire().is_some_and(FaceWire::owes_write)
    });
    facts.wrote(mark, owes);
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

/// What the read of a face's link tells of it ([`SiteFacts::tell`]) as it last stepped the link's
/// receive: what a handle on the face's place ([`FaceAt`]) reads of the link with no lend of the
/// place.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadFacts {
    /// Whether the link's handshake has completed ([`FaceSession::established`]).
    pub established: bool,
    /// Whether the link holds input it has already taken from its stack
    /// ([`FaceWire::holds_input`]).
    pub holds_input: bool,
    /// Whether the link's stack holds input it cannot read until another link gives a receive
    /// buffer back ([`FaceWire::waits_for_buffer`]).
    pub waits_for_buffer: bool,
    /// The reason of the Close the link's session staged ([`FaceSession::close_reason`]).
    pub close_reason: Option<CloseReason>,
}

/// The bit of a read's word that is its link's establishment ([`ReadFacts::established`]).
const READ_ESTABLISHED: u32 = 1;
/// The bit of a read's word that is the input its link holds ([`ReadFacts::holds_input`]).
const READ_HOLDS_INPUT: u32 = 1 << 1;
/// The bit of a read's word that is its link's wait for a buffer
/// ([`ReadFacts::waits_for_buffer`]).
const READ_WAITS_FOR_BUFFER: u32 = 1 << 2;
/// Where a read's word holds its link's Close: one past the reason's code, none at zero.
const READ_CLOSE_SHIFT: u32 = 8;

/// Every Close a read's word names, at its code ([`close_code`]).
const CLOSE_REASONS: [CloseReason; 8] = [
    CloseReason::Generic,
    CloseReason::Unsupported,
    CloseReason::Invalid,
    CloseReason::MaxSessions,
    CloseReason::MaxLinks,
    CloseReason::Expired,
    CloseReason::Unresponsive,
    CloseReason::ConnectionToSelf,
];

/// The code of `reason` in a read's word: its place in [`CLOSE_REASONS`]. A match, so a reason
/// added to the session's set is a build error here until the table holds it too.
fn close_code(reason: CloseReason) -> u32 {
    match reason {
        CloseReason::Generic => 0,
        CloseReason::Unsupported => 1,
        CloseReason::Invalid => 2,
        CloseReason::MaxSessions => 3,
        CloseReason::MaxLinks => 4,
        CloseReason::Expired => 5,
        CloseReason::Unresponsive => 6,
        CloseReason::ConnectionToSelf => 7,
    }
}

impl ReadFacts {
    /// What the read tells of `link`, the link it steps, whose session is `established` and
    /// staged the Close `close_reason`.
    pub fn of_link<N: CountKind>(
        link: &CellRc<dyn SessionDatagramLink, N>,
        established: bool,
        close_reason: Option<CloseReason>,
    ) -> Self {
        Self {
            established,
            holds_input: link.holds_input(),
            waits_for_buffer: waits_for_buffer(link),
            close_reason,
        }
    }

    /// The facts as one word, written at once.
    fn word(self) -> u32 {
        let mut word = 0;
        if self.established {
            word |= READ_ESTABLISHED;
        }
        if self.holds_input {
            word |= READ_HOLDS_INPUT;
        }
        if self.waits_for_buffer {
            word |= READ_WAITS_FOR_BUFFER;
        }
        if let Some(reason) = self.close_reason {
            word |= close_code(reason).saturating_add(1) << READ_CLOSE_SHIFT;
        }
        word
    }

    /// The facts `word` holds ([`Self::word`]).
    fn of_word(word: u32) -> Self {
        let close = (word >> READ_CLOSE_SHIFT) & 0xff;
        Self {
            established: word & READ_ESTABLISHED != 0,
            holds_input: word & READ_HOLDS_INPUT != 0,
            waits_for_buffer: word & READ_WAITS_FOR_BUFFER != 0,
            close_reason: close
                .checked_sub(1)
                .and_then(|code| CLOSE_REASONS.get(code as usize))
                .copied(),
        }
    }
}

/// The words a link's node is kept in ([`SiteFacts::node`]).
const NODE_WORDS: usize = ZID_MAX / 4;

// A node's bytes fill its words whole.
const _: () = assert!(NODE_WORDS * 4 == ZID_MAX);

/// The count of a link's writes a writer read as it began ([`SiteFacts::write_mark`]): what it
/// tells the facts it drained up to when it leaves nothing owed ([`SiteFacts::wrote`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteMark(u32);

/// The facts of a face's link that a handle on the face's place ([`FaceAt`]) reads with no lend
/// of the place, since a send may hold the place while it waits for its link's room. Each has its
/// own rule of who writes it, so no write is lost to another:
///
/// - the read's word ([`ReadFacts`]): written whole, after each step of the link's receive, by
///   the holder of the face's read alone, who also clears the facts as the place is given a link
///   or emptied of one ([`FaceSite::hold`], [`FaceSite::take`]);
/// - whether the link owes its stack a write: two counts, as a producer's and a consumer's. Whoever
///   leaves bytes owed on the link (a send under the place, or the read's step outside it) moves
///   `written` on, and whoever leaves nothing owed sets `drained` to the count of `written` it
///   read before it wrote ([`Self::write_mark`], [`Self::wrote`]). The link owes a write while
///   the two differ;
/// - the node the link reached: told once per link by the read ([`Self::tell_node`]), and read
///   whole or not at all, as a sequence count guards its words across the change of the place's
///   link.
pub struct SiteFacts {
    /// The read's word ([`ReadFacts::word`]).
    read: AtomicU32,
    /// How many writes left bytes owed on the link.
    written: AtomicU32,
    /// The count of `written` the last writer that left nothing owed read as it began.
    drained: AtomicU32,
    /// Even while the node's words are whole, odd while the read writes them.
    node_seq: AtomicU32,
    /// The node's length, 0 for none.
    node_len: AtomicU32,
    /// The node's bytes, zero past its length.
    node_bytes: [AtomicU32; NODE_WORDS],
    /// Whether a teller is in (`Self::one_teller`): a debug build's check of the read's rule.
    #[cfg(debug_assertions)]
    telling: core::sync::atomic::AtomicBool,
}

impl SiteFacts {
    /// The facts of no link: not established, holding nothing, owing nothing, naming no node.
    fn new() -> Self {
        Self {
            read: AtomicU32::new(0),
            written: AtomicU32::new(0),
            drained: AtomicU32::new(0),
            node_seq: AtomicU32::new(0),
            node_len: AtomicU32::new(0),
            node_bytes: core::array::from_fn(|_| AtomicU32::new(0)),
            #[cfg(debug_assertions)]
            telling: core::sync::atomic::AtomicBool::new(false),
        }
    }

    /// What the face's read last told of the link.
    #[inline]
    pub fn read(&self) -> ReadFacts {
        ReadFacts::of_word(self.read.load(Ordering::Acquire))
    }

    /// Tell `facts` of the link: by the holder of the face's read alone, after a step of the
    /// link's receive.
    #[inline]
    pub fn tell(&self, facts: ReadFacts) {
        let _one = self.one_teller();
        self.read.store(facts.word(), Ordering::Release);
    }

    /// The node the link reached, once the read told it; `None` before, and while the place's
    /// link is changed.
    pub fn node(&self) -> Option<SessionZid> {
        let seq = self.node_seq.load(Ordering::Acquire);
        if seq & 1 != 0 {
            return None;
        }
        let len = self.node_len.load(Ordering::Relaxed) as usize;
        let mut bytes = [0u8; ZID_MAX];
        for (word, chunk) in self.node_bytes.iter().zip(bytes.chunks_exact_mut(4)) {
            chunk.copy_from_slice(&word.load(Ordering::Relaxed).to_ne_bytes());
        }
        // Orders the reads of the words before the second read of the count: a word written by a
        // change begun after the first read is seen only with that change's count.
        fence(Ordering::Acquire);
        if self.node_seq.load(Ordering::Relaxed) != seq {
            return None;
        }
        SessionZid::new(bytes.get(..len)?).ok()
    }

    /// Whether the read told the link's node yet: read by the read itself, which tells it once.
    #[inline]
    pub fn has_node(&self) -> bool {
        self.node_len.load(Ordering::Relaxed) != 0
    }

    /// Tell the node the link reached: by the holder of the face's read alone, once for each
    /// link the place is given.
    pub fn tell_node(&self, node: &SessionZid) {
        let _one = self.one_teller();
        debug_assert!(!self.has_node(), "a link's node is told once");
        self.write_node(node.as_slice());
    }

    /// The count of the link's writes as a writer begins ([`Self::wrote`]).
    #[inline]
    pub fn write_mark(&self) -> WriteMark {
        WriteMark(self.written.load(Ordering::Acquire))
    }

    /// What a write begun at `mark` left: the link owes its stack a write (`owes`), counted as
    /// one more write left owed, or it owes nothing, and every write counted up to `mark` was
    /// drained. A write counted after `mark` stays owed, whichever of the two writers is last.
    #[inline]
    pub fn wrote(&self, mark: WriteMark, owes: bool) {
        if owes {
            self.written.fetch_add(1, Ordering::Release);
        } else {
            debug_assert!(
                self.written.load(Ordering::Relaxed).wrapping_sub(mark.0) <= u32::MAX / 2,
                "a write's mark is a count its own site's writes reached"
            );
            self.drained.store(mark.0, Ordering::Release);
        }
    }

    /// Whether the link owes its stack the rest of what it was handed: a write left owed that no
    /// writer drained since.
    #[inline]
    pub fn owes_write(&self) -> bool {
        self.drained.load(Ordering::Acquire) != self.written.load(Ordering::Acquire)
    }

    /// The facts of no link, as the place is given a link or emptied of one: by the holder of
    /// the face's read.
    fn clear(&self) {
        let _one = self.one_teller();
        self.read.store(0, Ordering::Release);
        if self.has_node() {
            self.write_node(&[]);
        }
        self.drained
            .store(self.written.load(Ordering::Acquire), Ordering::Release);
    }

    /// Write `node`'s bytes, none for no node, inside an odd count, so a reader reads them whole
    /// or reads none (`Self::node`).
    fn write_node(&self, node: &[u8]) {
        let mut bytes = [0u8; ZID_MAX];
        let len = node.len().min(ZID_MAX);
        if let (Some(into), Some(from)) = (bytes.get_mut(..len), node.get(..len)) {
            into.copy_from_slice(from);
        }
        let seq = self.node_seq.load(Ordering::Relaxed);
        self.node_seq.store(seq.wrapping_add(1), Ordering::Relaxed);
        // Orders the odd count before the words: a reader that sees a word of this write sees
        // the count moved, and reads none.
        fence(Ordering::Release);
        for (word, chunk) in self.node_bytes.iter().zip(bytes.chunks_exact(4)) {
            if let Ok(four) = <[u8; 4]>::try_from(chunk) {
                word.store(u32::from_ne_bytes(four), Ordering::Relaxed);
            }
        }
        self.node_len.store(len as u32, Ordering::Relaxed);
        self.node_seq.store(seq.wrapping_add(2), Ordering::Release);
    }

    /// The one teller of the read's facts: a debug build fails a second teller that comes in
    /// while one is in, which a teller other than the holder of the face's read would be.
    #[inline(always)]
    fn one_teller(&self) -> OneTeller<'_> {
        #[cfg(debug_assertions)]
        {
            let other = self.telling.swap(true, Ordering::Acquire);
            debug_assert!(
                !other,
                "a face's read facts are told by the holder of its read alone"
            );
            OneTeller {
                telling: &self.telling,
            }
        }
        #[cfg(not(debug_assertions))]
        {
            OneTeller {
                _of: core::marker::PhantomData,
            }
        }
    }
}

/// A teller of a site's read facts, in for as long as it lives (`SiteFacts::one_teller`).
struct OneTeller<'a> {
    #[cfg(debug_assertions)]
    telling: &'a core::sync::atomic::AtomicBool,
    #[cfg(not(debug_assertions))]
    _of: core::marker::PhantomData<&'a SiteFacts>,
}

#[cfg(debug_assertions)]
impl Drop for OneTeller<'_> {
    fn drop(&mut self) {
        self.telling.store(false, Ordering::Release);
    }
}

/// A face's link whose parts lie in a face's place ([`FaceSite`]), apart from the session's
/// state: what the face's record holds while the link is up or in its handshake, holding no
/// handle on the parts.
///
/// The supervisor reads it under the session's lock, which never waits on a face, and a send may
/// hold the place while it waits for its link's room, so each fact of the link is read off the
/// place's facts ([`SiteFacts`]), which the face's read tells, with no lend of the place: a place
/// that holds no wire reads as a link that holds no input, owes no write, is not established and
/// names no node and no Close. What the handle asks of the link (a close, a write of what it
/// owes) tries the place and waits for nothing; a close it cannot tell then is owed to the
/// place's holder, which tells it before letting go. A wait on the link's input and room is read
/// off the link once, when it is made, and how its session ends is read and asked through its end
/// (`E`), with no lend of the place. What the link counted is read through the count the handle
/// keeps (`resource-snapshot`), with no lend of the place either.
pub struct FaceAt<K: LockKind, P: WireParts, E: LinkEnd> {
    site: core::ptr::NonNull<FaceSite<K, P>>,
    end: E,
    input: Option<WaitOn>,
    room: Option<WaitOn>,
    /// `resource-snapshot` — what the link counts, kept with the handle ([`Self::counted_by`]).
    #[cfg(feature = "resource-snapshot")]
    count: Option<P::Count>,
}

impl<K: LockKind, P: WireParts, E: LinkEnd> FaceAt<K, P, E> {
    /// The link whose parts lie in `site`, ended by `end`, waited on by `input` for its input
    /// and by `room` for its room.
    ///
    /// # Safety
    ///
    /// `site` lives, at the address it has now, for as long as the handle does. What the handle
    /// asks of the link inside a lend of `site` finds the place held, on every kind (a kind whose
    /// own try cannot see it has the lend marked in the place, [`FacePlace::try_lend`]), and is
    /// owed or not done.
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
            #[cfg(feature = "resource-snapshot")]
            count: None,
        }
    }

    /// `resource-snapshot` — the handle, reading what its link counted through `count`, which it
    /// keeps until it goes: the session retires a link it lets go of by this reading, which a
    /// place held by another holder, or emptied before the handle goes, would read as nothing. A
    /// handle made with no count reads nothing counted.
    #[cfg(feature = "resource-snapshot")]
    #[must_use]
    pub fn counted_by(mut self, count: P::Count) -> Self {
        self.count = Some(count);
        self
    }

    /// The end the link's session is ended by: where each face's end lies in its face, what
    /// names the face whose place the handle reaches.
    pub fn end(&self) -> &E {
        &self.end
    }

    /// The site the parts lie in.
    fn site(&self) -> &FaceSite<K, P> {
        // SAFETY: the site outlives the handle where it was when the handle was made
        // (`Self::new`'s contract).
        unsafe { self.site.as_ref() }
    }

    /// What the face's read last told of the link ([`SiteFacts::read`]).
    #[inline(always)]
    fn facts(&self) -> ReadFacts {
        self.site().facts().read()
    }

    /// `f` on the wire of the parts when the place lends them now, through the one body of the
    /// lend (`Self::lend_wire`); nothing while another holder has the place.
    #[cfg(feature = "session-unicast-accept")]
    #[inline(always)]
    fn act(&self, f: impl Fn(&P::Wire) + Send) {
        let _ = self.lend_wire(&mut ActOn(f));
    }

    /// `on` on the wire of the parts when the place lends them now, by a try of the place that
    /// waits for nothing, telling the place's facts what the lend left owed on the link
    /// ([`FaceSite::tell_written`]). What the lend came to; `on` ran only where it is
    /// [`Lend::Lent`]. Out of line, and handed `on` by reference, so every act of a handle and
    /// every lend of the link's session it makes, whatever its answer, goes through one body of
    /// the try and its pay.
    #[inline(never)]
    fn lend_wire(&self, on: &mut (dyn OnWire<P::Wire> + Send)) -> Lend<()> {
        let site = self.site();
        let lent = site.try_lend(|held| {
            let mark = site.facts().write_mark();
            let lent = held.lend(|parts| {
                let wire = parts.wire()?;
                on.on(wire);
                Some(())
            });
            site.tell_written(mark, held);
            lent
        });
        match lent {
            Lend::Lent(Some(())) => Lend::Lent(()),
            Lend::Lent(None) | Lend::Empty => Lend::Empty,
            Lend::Held => Lend::Held,
        }
    }
}

/// What a handle runs on the wire of the parts as the place lends them (`FaceAt::lend_wire`).
/// A trait of one method, so the one body of the lend reaches it through a vtable that carries
/// no `call_once` shim beside it, as a closure's would.
trait OnWire<W> {
    /// Run on `wire`.
    fn on(&mut self, wire: &W);
}

/// An act on the wire (`FaceAt::act`).
#[cfg(feature = "session-unicast-accept")]
struct ActOn<F>(F);

#[cfg(feature = "session-unicast-accept")]
impl<W, F: Fn(&W)> OnWire<W> for ActOn<F> {
    fn on(&mut self, wire: &W) {
        (self.0)(wire);
    }
}

/// A lend of the session of the wire to `f`, run once, and what it came to (`FaceAt`'s
/// `LendsSession::try_session`).
struct LendInto<F, U> {
    f: Option<F>,
    answer: Option<Lend<U>>,
}

impl<W, U, F> OnWire<W> for LendInto<F, U>
where
    W: LendsSession,
    U: Send,
    F: FnOnce(&W::Session) -> U + Send,
{
    fn on(&mut self, wire: &W) {
        if let Some(f) = self.f.take() {
            self.answer = Some(wire.try_session(f));
        }
    }
}

impl<K: LockKind, P: WireParts, E: LinkEnd> FaceSession for FaceAt<K, P, E> {
    fn established(&self) -> bool {
        self.facts().established
    }

    fn node(&self) -> Option<SessionZid> {
        self.site().facts().node()
    }

    /// Told as a close ([`FaceWire::close`]): the end of an established link, owed to the
    /// place's holder when another thread holds it.
    fn end(&self) {
        self.site().close_or_owe();
    }

    fn close_reason(&self) -> Option<CloseReason> {
        self.facts().close_reason
    }

    // What a wait found is not told: a link whose parts lie in a place is stepped by the face's
    // read where it lies, which reads its input at every step, so the provided form, which keeps
    // nothing, is the handle's, and a wait lends nothing of the place.

    /// Read through the count the handle keeps ([`Self::counted_by`]), with no lend of the place.
    #[cfg(feature = "resource-snapshot")]
    fn message_reading(&self) -> BuildMessageReading {
        self.count
            .as_ref()
            .map_or_else(BuildMessageReading::empty, MessageCount::reading)
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
        self.facts().holds_input
    }

    fn owes_write(&self) -> bool {
        self.site().facts().owes_write()
    }

    fn waits_for_buffer(&self) -> bool {
        self.facts().waits_for_buffer
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
        self.act(|wire| wire.write_owed_now());
    }

    /// The three facts in one read of the word the face's read told, and of the place's counts
    /// of its writes; a place that holds no wire looks quiet.
    fn look(&self) -> WireLook {
        let facts = self.facts();
        if facts.holds_input {
            WireLook::HoldsInput
        } else if facts.waits_for_buffer {
            WireLook::WaitsForBuffer
        } else if self.owes_write() {
            WireLook::OwesWrite
        } else {
            WireLook::Quiet
        }
    }
}

/// A send reaches the session by a try of the place, which waits for nothing: inside a lend of
/// the place on the calling thread, the holder's own, it finds the place held.
impl<K: LockKind, P: WireParts, E: LinkEnd> LendsSession for FaceAt<K, P, E>
where
    P::Wire: LendsSession,
{
    type Session = <P::Wire as LendsSession>::Session;

    fn try_session<U: Send>(&self, f: impl FnOnce(&Self::Session) -> U + Send) -> Lend<U> {
        let mut lend = LendInto {
            f: Some(f),
            answer: None,
        };
        match (self.lend_wire(&mut lend), lend.answer) {
            (Lend::Lent(()), Some(answer)) => answer,
            (Lend::Held, _) => Lend::Held,
            _ => Lend::Empty,
        }
    }

    fn owe(&self, debts: u32) {
        self.site().owe(debts);
    }
}

/// What a face holds for its link: nothing, a dial under way, or the link a dial made or a port
/// gave. Where the link stands (dialled, in its handshake, up, waiting, standing by) is the face's
/// life's alone ([`FaceRecord::life`]); this is the I/O that life asks for. A dial under way lies
/// apart from the face, in the one row of the faces' dials its place has, which the link names
/// ([`DialRow`]): a face has one dial at most, and its link is no larger than a handle on a
/// link's place whatever it holds.
pub enum Link<W, D> {
    /// No link: not dialled yet, between two dials, waiting to dial again, or standing by.
    Idle,
    /// A dial under way, in the row it names, asked at each move of the face ([`Dial::answer`]).
    Dialing(DialRow<D>),
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

/// Where a face's dial under way lies ([`Link::Dialing`]): the row of the faces' dials at the
/// face's place, which its supervisor keeps beside the faces' table, one row for each place. Only
/// the supervisor makes one, as it writes a dial into the row ([`LinkSupervisor::put_dial`]), so
/// a link that names a row has a dial there; the dial's type is the row's.
pub struct DialRow<D> {
    at: usize,
    dial: core::marker::PhantomData<fn() -> D>,
}

/// The dials under way of a session's faces: a row for each place of the faces' table, reserved
/// with it and never grown, each holding the dial of the face at that place while that face dials.
/// A dial (its endpoint's text and the addresses its host resolved to) is far larger than a handle
/// on a link's place, so it lies here and not in the face's link, and the room is the same: one
/// dial for each place either way.
struct DialPlaces<D> {
    rows: Vec<Option<Dial<D>>>,
}

impl<D> DialPlaces<D> {
    /// A row for each of `places` places, none holding a dial; `None` when the heap refuses the
    /// room.
    fn reserved(places: usize) -> Option<Self> {
        let mut rows = Vec::new();
        rows.try_reserve_exact(places).ok()?;
        rows.resize_with(places, || None);
        Some(Self { rows })
    }

    /// Write `dial` into the row of the place `at`, in place of the one it held, which is let go
    /// of: the row, which the face's link names from then. `None` past the table, the dial let go
    /// of.
    #[inline]
    fn put(&mut self, at: usize, dial: Dial<D>) -> Option<DialRow<D>> {
        *self.rows.get_mut(at)? = Some(dial);
        Some(DialRow {
            at,
            dial: core::marker::PhantomData,
        })
    }

    /// The dial in `row`.
    #[inline]
    fn get(&self, row: &DialRow<D>) -> Option<&Dial<D>> {
        self.rows.get(row.at)?.as_ref()
    }

    /// The dial in `row`, to ask.
    #[inline]
    fn get_mut(&mut self, row: &DialRow<D>) -> Option<&mut Dial<D>> {
        self.rows.get_mut(row.at)?.as_mut()
    }

    /// Let go of the dial in `row`, which is over: the endpoint it dialled. Only the endpoint is
    /// moved out, and the dial it leaves is let go of where it lies: a dial moved out whole would
    /// be copied to the caller's frame.
    #[inline]
    fn end(&mut self, row: &DialRow<D>) -> Option<DialEndpoint> {
        let place = self.rows.get_mut(row.at)?;
        let endpoint = core::mem::replace(&mut place.as_mut()?.endpoint, DialEndpoint::Listed(0));
        *place = None;
        Some(endpoint)
    }

    /// Let go of the dial in the row of the place `at`, if it holds one.
    #[inline]
    fn let_go(&mut self, at: usize) {
        if let Some(place) = self.rows.get_mut(at) {
            *place = None;
        }
    }

    /// Let go of every dial.
    fn let_go_all(&mut self) {
        for place in &mut self.rows {
            *place = None;
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

/// A face's dial under way: the endpoint it dials, the network's answer still to come, the
/// stack's own dial `D` held by value, and the addresses of a named host it passes to when that
/// one is refused ([`HostWalk`]).
pub struct Dial<D> {
    endpoint: DialEndpoint,
    pending: D,
    walk: HostWalk,
}

impl<D> Dial<D> {
    /// The dial `pending` of `endpoint`, with no address to pass to.
    pub fn new(endpoint: DialEndpoint, pending: D) -> Self {
        Self::begun(endpoint, Begun::alone(pending))
    }

    /// The dial `begun` of `endpoint`, with the addresses it passes to.
    pub fn begun(endpoint: DialEndpoint, begun: Begun<D>) -> Self {
        Self {
            endpoint,
            pending: begun.pending,
            walk: begun.walk,
        }
    }

    /// The endpoint dialled.
    pub fn endpoint(&self) -> &DialEndpoint {
        &self.endpoint
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

    /// [`Self::answer`], where a refusal passes the dial to the next address of its host on
    /// `links` while one is left: the dial is then under way again, `None` is answered, and the
    /// next address is asked at the next step, as a dial just begun is. The refusal of the last
    /// address tried is the dial's. A link made is answered as it comes. Out of line: a face's
    /// read, a dial asked once as it begins and a face's dial asked by its own slot
    /// ([`LinkSupervisor::answer_face_dial`]) share it.
    #[inline(never)]
    pub fn answer_on<N: CountKind, L>(&mut self, links: &L) -> DialAnswer<L::Pump, N>
    where
        L: SessionLinks<N, Dial = D>,
        D: PendingDial<L::Pump, N>,
    {
        match self.pending.poll() {
            Some(Err(refused)) => match self.walk.pass_on::<N, L>(links, refused) {
                // The refused dial has handed out all it held, so it is let go of as the next is
                // put in its place.
                Ok(next) => {
                    self.pending = next;
                    None
                }
                Err(last) => Some(Err(last)),
            },
            answer => answer,
        }
    }
}

/// The answer of a face's dial under way: the link it made, the refusal, or `None` while it is
/// still being made.
pub type DialAnswer<P, N = OneTask> = Option<Result<OpenedLink<P, N>, LinkOpenError>>;

/// What a face's dial asked where it lies in the face answered
/// ([`LinkSupervisor::answer_face_dial`]): the link it made or the refusal, with the endpoint it
/// dialled.
pub type FaceDialAnswer<P, N = OneTask> = (Result<OpenedLink<P, N>, LinkOpenError>, DialEndpoint);

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

/// What a read of one face alone waits on ([`LinkSupervisor::lone_waits`]), in the reading
/// thread's own frame for the whole run of such reads: the face's link, each port and a wake of
/// the stack's. A session with more ports than its room leaves has its faces read whole.
pub type LoneWaits = BoundedVec<LinkWait, LONE_WAITS, Static>;

/// The room of [`LoneWaits`].
const LONE_WAITS: usize = 8;

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
    /// The dials under way of the faces, a row at each place of `faces`, named by the link of
    /// the face that dials (`DialPlaces`).
    dials: DialPlaces<L::Dial>,
    #[cfg(feature = "listen")]
    listeners: Vec<Listening<L::Pump, N>>,
    /// The one buffer a read's waits are gathered in, reserved at the open for every link, port
    /// and wake a read waits on at once; `None` while a read waits with it, so that a read on
    /// another thread then makes no buffer of its own after the open. Empty whenever it is here:
    /// each way it comes back empties it ([`Self::idle_wait`], [`Self::waited`]), so a read
    /// gathers into it what it waits on now and nothing a read before it waited on.
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
    /// `resource-snapshot` — what the links let go of had counted when they went, retired in the
    /// step that lets each go, so the session's reading never falls when a link does
    /// ([`Self::message_reading`]).
    #[cfg(feature = "resource-snapshot")]
    receive_ledger: BuildReceiveLedger,
}

impl<
        L: SessionLinks<N>,
        F: FaceRecord<N, Pump = L::Pump, Dial = L::Dial>,
        P: FacePlaces<F>,
        N: CountKind,
    > LinkSupervisor<L, F, P, N>
{
    /// The faces of a session over `links`, `dial` the dial role's at the first place: `places`
    /// places in all (one at least, the dial role's), each with a row for the dial under way of
    /// the face at it, and `waits` waits a read makes at once, reserved now; `None` when the heap
    /// refuses that room, which an open answers as it answers an arena that cannot be reserved.
    /// The ports are the open's, taken as it listens (`listen`). Faces taken after are numbered
    /// from 1.
    pub fn new(links: L, dial: F, places: usize, waits: usize) -> Option<Self> {
        let mut room = Vec::new();
        room.try_reserve_exact(waits).ok()?;
        let faces = P::with_dial(dial, places);
        let dials = DialPlaces::reserved(faces.places())?;
        Some(Self {
            links,
            faces,
            dials,
            #[cfg(feature = "listen")]
            listeners: Vec::new(),
            waits: Some(room),
            next_face: 1,
            moves: 0,
            generation: 0,
            #[cfg(feature = "listen")]
            stood_by: None,
            records: core::marker::PhantomData,
            #[cfg(feature = "resource-snapshot")]
            receive_ledger: BuildReceiveLedger::new(),
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

    /// `resource-snapshot` — what the receive paths of the faces' links have counted, those held
    /// now and those let go of, as one reading that only grows: a reader takes windows by
    /// subtracting two readings. Asked under the lock the links are let go of under, a link that
    /// goes is in the retired total or among the links held, never in both or in neither.
    #[cfg(feature = "resource-snapshot")]
    pub fn message_reading(&self) -> BuildMessageReading {
        self.receive_ledger
            .total(self.faces.iter().filter_map(|face| counted(face.link())))
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
        // Read before the face goes, and retired only if it went: the dial role's never does.
        #[cfg(feature = "resource-snapshot")]
        let gone = self.faces.get(at).and_then(|face| counted(face.link()));
        let freed = self.faces.free(at);
        // The face's dial, if it dialled, goes with it: the next face at the place has none.
        if freed {
            self.dials.let_go(at);
        }
        #[cfg(feature = "resource-snapshot")]
        if let Some(gone) = gone.filter(|_| freed) {
            self.receive_ledger.retire(&gone);
        }
        freed.then_some(id)
    }

    /// Begin a dial of `endpoint` over these links, which the network answers later: of the
    /// address it names, or of the first address of the host it names that the network begins,
    /// the rest kept for the dial to pass to ([`crate::dial`]). [`TransportRefusal::Unreachable`]
    /// when the endpoint does not read, names a host no dial of a name reaches over these links,
    /// or the network refuses every address at once.
    // Always inlined: the dial's one body is `crate::dial::begin`, out of line and cold.
    #[inline(always)]
    pub fn begin_dial(&self, endpoint: &str) -> Result<Begun<L::Dial>, TransportRefusal> {
        crate::dial::begin::<N, L>(endpoint, &self.links)
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

    /// Give the face at `at` the link `link`, in place of the one it holds, which is let go of:
    /// a dial it held is let go of in its row.
    pub fn put_link(&mut self, at: usize, link: Link<F::Wire, L::Dial>) {
        self.regenerated();
        self.moved();
        if let Some(face) = self.faces.get_mut(at) {
            #[cfg(feature = "resource-snapshot")]
            if let Some(gone) = counted(face.link()) {
                self.receive_ledger.retire(&gone);
            }
            if let Link::Dialing(row) = core::mem::replace(face.link_mut(), link) {
                self.dials.let_go(row.at);
            }
        }
    }

    /// Give the face at `at` the dial `dial`, under way, in place of the link it holds, which is
    /// let go of: the dial is written into the face's row of the dials, which its link names from
    /// then. A dial for a face past the table is let go of.
    pub fn put_dial(&mut self, at: usize, dial: Dial<L::Dial>) {
        self.put_link(at, Link::Idle);
        let Some(face) = self.faces.get_mut(at) else {
            return;
        };
        if let Some(row) = self.dials.put(at, dial) {
            *face.link_mut() = Link::Dialing(row);
        }
    }

    /// The dial under way of the face at `at`, in its row of the dials: `None` for a face that
    /// holds no dial and for one past the table.
    pub fn face_dial(&self, at: usize) -> Option<&Dial<L::Dial>> {
        match self.faces.get(at)?.link() {
            Link::Dialing(row) => self.dials.get(row),
            _ => None,
        }
    }

    /// Let go of the dial of the face at `at`, which is over: the endpoint it dialled, moved out of
    /// the dial, which the refusal or the link's session names. `None` for a face that held no
    /// dial, whose link is left as it is, and for one past the table. Out of line: a dial that
    /// answered and one that failed are each ended here.
    #[inline(never)]
    pub fn end_dial(&mut self, at: usize) -> Option<DialEndpoint> {
        self.moved();
        let link = self.faces.get_mut(at)?.link_mut();
        let Link::Dialing(row) = link else {
            return None;
        };
        let endpoint = self.dials.end(row);
        *link = Link::Idle;
        endpoint
    }

    /// Ask the dial `pending` of `endpoint`, begun for the face at `at`, once. A dial the network
    /// has not answered yet is put in the face's row of the dials ([`Self::put_dial`]), and
    /// `None` is handed back; one answered at once is let go of, before its link is opened, and
    /// its answer is handed back, the face keeping what it held. A dial for a face past the table
    /// is let go of. The time the dial is given up at is its face's life's, read once the ask
    /// returned, so a host whose ask blocks (a refused loopback connect on Windows) does not spend
    /// the dial's time on it.
    pub fn ask_dial(
        &mut self,
        at: usize,
        endpoint: DialEndpoint,
        begun: Begun<L::Dial>,
    ) -> DialAnswer<L::Pump, N> {
        // A dial that answered has handed out all it held (the socket, the link's buffers, the
        // program's link), and keeps only handles that own nothing, so it is let go of here with
        // nothing to observe: every stack's dial takes those out as it answers. One refused at
        // once has passed to its host's next address already, which is the dial put in the face.
        let mut dial = Dial::begun(endpoint, begun);
        if let Some(answer) = dial.answer_on::<N, L>(&self.links) {
            return Some(answer);
        }
        // Written into the face's row from the dial this frame holds, and not handed back through
        // the transport and the session's dial, each of which would move it once more.
        self.put_dial(at, dial);
        None
    }

    /// Ask the dial under way in the face at `at` once over these links ([`Dial::answer_on`]),
    /// where it lies: a refused address passes it to its host's next. Once the network answered,
    /// the dial is let go of, the face holds no link, and the answer is handed back with the
    /// endpoint it dialled. `None` while the network has not answered, and for a face that holds
    /// no dial or lies past the table.
    pub fn answer_face_dial(&mut self, at: usize) -> Option<FaceDialAnswer<L::Pump, N>> {
        self.moved();
        // The faces apart from the links, so that a refused address can begin its host's next on
        // the links while its face is held.
        let links = &self.links;
        let link = self.faces.get_mut(at)?.link_mut();
        let Link::Dialing(row) = link else {
            return None;
        };
        let answer = self.dials.get_mut(row)?.answer_on::<N, L>(links)?;
        let endpoint = self.dials.end(row)?;
        *link = Link::Idle;
        Some((answer, endpoint))
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
        // The faces apart from the links, so that a refused dial can begin its next address on
        // the links while its face is held.
        self.moved();
        let links = &self.links;
        let Some(face) = self.faces.get_mut(at) else {
            return FaceRead {
                role,
                input: LinkInput::Tick,
            };
        };
        let phase = face.life().phase();
        let asked = match face.link() {
            Link::Dialing(row) => self
                .dials
                .get_mut(row)
                .and_then(|dial| dial.answer_on::<N, L>(links)),
            _ => None,
        };
        if let Some(answered) = asked {
            let input = if answered.is_ok() {
                LinkInput::DialMade
            } else {
                LinkInput::DialRefused
            };
            *answer = Some(answered);
            if let Link::Dialing(row) = core::mem::replace(face.link_mut(), Link::Idle) {
                *dialled = self.dials.end(&row);
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

    /// The reading of the node a face's link reached that [`Self::read_face`] makes, for an
    /// owner that reads each face's link itself and tells its life what it read: `input`, read
    /// off the face at `at`, numbered `id`, in `phase`, `over` once its handshake is over. The
    /// dial role's face stands by for a node another face holds and dials again once none does; a
    /// taken face's input is as it came.
    #[cfg(feature = "listen")]
    pub fn read_dial_node(
        &mut self,
        at: usize,
        id: FaceId,
        phase: LinkPhase,
        input: LinkInput,
        over: bool,
    ) -> LinkInput {
        let role = if at == 0 || !P::TAKES {
            LinkRole::Dial
        } else {
            LinkRole::Taken
        };
        self.read_node(at, id, role, phase, input, over)
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

    /// What a read of the face at place `at` alone waits on: its link's input first, then a
    /// connection on each port, then `beside` (a wake of the stack's). Made once for a run of
    /// such reads and kept for its whole length, none of it written anew a wait. `None` where a
    /// wait on these alone would miss what a wait over the whole session finds
    /// ([`Self::idle_wait`]): the face's link is not [`WireLook::Quiet`] or waits in its own
    /// loop, a port gives no wait or the link's own (a datagram port its faces share), or the
    /// entries are more than [`LoneWaits`] holds.
    pub fn lone_waits(&self, at: usize, beside: Option<LinkWait>) -> Option<LoneWaits> {
        let wire = self.faces.get(at)?.link().wire()?;
        if wire.look() != WireLook::Quiet {
            return None;
        }
        let own = wire.input_wait()?;
        let mut waits = LoneWaits::new_static();
        waits.push(LinkWait::input(own)).ok()?;
        #[cfg(feature = "listen")]
        for listening in &self.listeners {
            let on = listening
                .listener
                .input_wait()
                .filter(|_| listening.listener.asked_when_ready())?;
            if on == own {
                return None;
            }
            waits.push(LinkWait::input(on)).ok()?;
        }
        if let Some(wake) = beside {
            waits.push(wake).ok()?;
        }
        Some(waits)
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
        debug_assert!(
            waits.is_empty(),
            "the session's buffer of waits came back emptied"
        );
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
                Link::Wire(wire) => match wire.look() {
                    WireLook::HoldsInput => holds = true,
                    // Its input waits in the stack until another link gives a receive buffer
                    // back, which that link's own input wakes the read for.
                    WireLook::WaitsForBuffer => {}
                    look => match wire.input_wait() {
                        Some(on) => {
                            let wait = if look == WireLook::OwesWrite {
                                LinkWait::input_or_room(on)
                            } else {
                                LinkWait::input(on)
                            };
                            look_again |= !put_wait(&mut waits, wait);
                        }
                        None => own_loop = true,
                    },
                },
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

    /// Take back a read's wait ([`IdleWait::wait`]), mark each port it found ready, and tell each
    /// link its owner waits on whether it found input in its stack (`FaceSession::input_seen`,
    /// with `listen` or `group`): the session's buffer of its waits, which the wait took whole
    /// ([`Self::idle_wait`]), emptied here whether the wait was made or not, so the next read
    /// waits on what it gathers alone. Out of line: the open's steps and each read hand their
    /// wait back.
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
        self.dials.let_go_all();
        #[cfg(feature = "listen")]
        self.listeners.clear();
    }

    /// End every face's link, whatever it is doing, telling an established peer so, after
    /// `each` is shown the face. Each face's life is closed, which lets go of what it held; the
    /// dial role's face stays, with no link and no redial; the others go.
    pub fn end_faces(&mut self, mut each: impl FnMut(&mut F)) {
        self.regenerated();
        self.moved();
        for face in self.faces.iter_mut() {
            each(face);
            // A close asks to let go of the dial or the link, which is what follows here for
            // every face alike, so its effects are not read; it reads no time.
            let _ = face.life_mut().input(LinkInput::Close, 0);
            let link = core::mem::replace(face.link_mut(), Link::Idle);
            if let Link::Wire(wire) = link {
                #[cfg(feature = "resource-snapshot")]
                self.receive_ledger.retire(&wire.message_reading());
                wire.close();
                wire.abort();
            }
        }
        self.faces.keep_dial_only();
        self.dials.let_go_all();
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

    use crate::session_drive::{LinkListener, Locator};
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
        /// How many transport messages the link's receive path has counted.
        #[cfg(feature = "resource-snapshot")]
        messages: Rc<Cell<u64>>,
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

        #[cfg(feature = "resource-snapshot")]
        fn message_reading(&self) -> BuildMessageReading {
            BuildMessageReading {
                messages: self.messages.get(),
                ..BuildMessageReading::empty()
            }
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

    /// What a dial of one address of [`Hosts`] comes to.
    #[derive(Clone, Copy)]
    enum Says {
        /// Begun, and refused when it is asked: a connection refused once under way.
        Refused,
        /// Begun, and not answered yet.
        UnderWay,
        /// Refused before it is begun.
        RefusedAtOnce,
    }

    /// A network whose dial of each address comes to what `says` holds for it, recording the
    /// addresses it was asked to dial.
    struct Hosts {
        says: alloc::vec::Vec<(core::net::SocketAddr, Says)>,
        dialled: core::cell::RefCell<alloc::vec::Vec<core::net::SocketAddr>>,
    }

    impl Hosts {
        fn new(says: &[(core::net::SocketAddr, Says)]) -> Self {
            Self {
                says: says.to_vec(),
                dialled: core::cell::RefCell::new(alloc::vec::Vec::new()),
            }
        }
    }

    impl SessionLinks for Hosts {
        type Pump = Rc<Quiet>;
        type Dial = Answer;
        type Waits = crate::session_drive::NoWaits;

        const RESOLVES: bool = true;

        /// The addresses of the host as its resolver answers them, at the name's port.
        fn resolve(
            &self,
            name: &crate::locator_text::NamedHost<'_>,
            found: &mut [core::net::SocketAddr],
        ) -> usize {
            let mut count = 0;
            for (place, (at, _)) in found.iter_mut().zip(&self.says) {
                *place = core::net::SocketAddr::new(at.ip(), name.port());
                count += 1;
            }
            count
        }

        fn waits(&self) -> Self::Waits {
            crate::session_drive::NoWaits
        }

        fn open_acceptor(&self, _port: u16) -> Result<OpenedLink<Rc<Quiet>>, LinkOpenError> {
            Err(LinkOpenError::Unsupported)
        }

        fn open_initiator(&self, _to: Locator) -> Result<OpenedLink<Rc<Quiet>>, LinkOpenError> {
            Err(LinkOpenError::Unsupported)
        }

        fn begin_initiator(&self, to: Locator) -> Result<Answer, LinkOpenError> {
            let at = to.as_ip().expect("an IP locator").at;
            self.dialled.borrow_mut().push(at);
            let says = self
                .says
                .iter()
                .find(|(answered, _)| answered.ip() == at.ip())
                .map(|(_, says)| *says);
            match says {
                Some(Says::Refused) => Ok(Answer(Some(Err(LinkOpenError::Refused)), None)),
                Some(Says::UnderWay) => Ok(Answer(None, None)),
                Some(Says::RefusedAtOnce) | None => Err(LinkOpenError::Unsupported),
            }
        }
    }

    /// A named host's dial begun on `hosts` (`crate::dial::begin`): its first address the
    /// network begins, and the rest; or why none began.
    fn named_dial(hosts: &Hosts) -> Result<Dial<Answer>, TransportRefusal> {
        crate::dial::begin::<OneTask, Hosts>("tcp/router.example:7447", hosts)
            .map(|begun| Dial::begun(DialEndpoint::Listed(0), begun))
    }

    /// Why a dial was refused, read off the refusal of its endpoint; `None` for a dial begun.
    fn refused<T>(dial: Result<T, TransportRefusal>) -> Option<crate::transport::Refusal> {
        match dial {
            Err(TransportRefusal::Unreachable(refused)) => Some(refused.why),
            _ => None,
        }
    }

    /// The loopback addresses a name stands for, IPv6 first as a resolver sorts them.
    fn loopbacks() -> (core::net::SocketAddr, core::net::SocketAddr) {
        (
            core::net::SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 1], 7447)),
            core::net::SocketAddr::from(([127, 0, 0, 1], 7447)),
        )
    }

    /// A dial of a host whose first address is refused once under way passes to the next address
    /// in the order the resolver answered, and is under way again; the address refused at once
    /// is passed over the same way. Turned red by a refused address ending the dial while another
    /// is left (`Dial::answer_on`), or by an address dialled out of its order or twice
    /// (`HostWalk::pass_on`).
    #[test]
    fn a_dial_refused_later_passes_to_the_hosts_next_address() {
        let (v6, v4) = loopbacks();
        let hosts = Hosts::new(&[(v6, Says::Refused), (v4, Says::UnderWay)]);
        let Ok(mut dial) = named_dial(&hosts) else {
            panic!("the first address is begun");
        };
        assert!(
            dial.answer_on::<OneTask, Hosts>(&hosts).is_none(),
            "under way at the second"
        );
        assert_eq!(*hosts.dialled.borrow(), vec![v6, v4]);
        assert_eq!(dial.walk.left(), 0);

        let hosts = Hosts::new(&[(v6, Says::RefusedAtOnce), (v4, Says::UnderWay)]);
        let Ok(mut dial) = named_dial(&hosts) else {
            panic!("the second address is begun");
        };
        assert!(dial.answer_on::<OneTask, Hosts>(&hosts).is_none());
        assert_eq!(*hosts.dialled.borrow(), vec![v6, v4], "each address once");
    }

    /// A dial of a host every address of which is refused answers one refusal, once, at the step
    /// that asks the last address it dialled, each address dialled in turn; a host no address of
    /// which begins is no dial, refused as its last address was. Turned red by a refusal for each
    /// address, or one answered before the last address was tried.
    #[test]
    fn a_dial_whose_every_address_is_refused_answers_one_refusal() {
        use crate::transport::Refusal;

        let (v6, v4) = loopbacks();
        let hosts = Hosts::new(&[(v6, Says::Refused), (v4, Says::Refused)]);
        let Ok(mut dial) = named_dial(&hosts) else {
            panic!("the first address is begun");
        };
        assert!(
            dial.answer_on::<OneTask, Hosts>(&hosts).is_none(),
            "the first refusal passes the dial to the second address"
        );
        assert_eq!(*hosts.dialled.borrow(), vec![v6, v4]);
        assert!(matches!(
            dial.answer_on::<OneTask, Hosts>(&hosts),
            Some(Err(LinkOpenError::Refused))
        ));
        assert_eq!(
            *hosts.dialled.borrow(),
            vec![v6, v4],
            "no address dialled twice"
        );
        assert!(
            dial.answer_on::<OneTask, Hosts>(&hosts).is_none(),
            "answered once"
        );

        let hosts = Hosts::new(&[(v6, Says::RefusedAtOnce), (v4, Says::RefusedAtOnce)]);
        assert_eq!(
            refused(named_dial(&hosts)),
            Some(Refusal::Link(LinkOpenError::Unsupported)),
            "no address begins"
        );
        assert_eq!(*hosts.dialled.borrow(), vec![v6, v4]);
    }

    /// A dial of an address is the network's dial of it, with no address to pass to; a host that
    /// resolves to no address is refused as a link the other end did not take, which a later
    /// dial may find; a `tls/` host is refused by the locator before the resolver is asked, and
    /// a host over links without a resolver too, through the faces' own entry, with no dial asked
    /// of the network. Each refusal names the endpoint it refuses. Turned red by an address dialled
    /// as a name, by a host of no address begun or refused for good, by a name dialled that no
    /// dial of a name reaches, or by a refusal that names no endpoint (`crate::dial::begin`).
    #[test]
    fn a_dial_begins_at_an_address_or_refuses_a_name_it_cannot_reach() {
        use crate::locator_text::DialRefused;
        use crate::transport::Refusal;

        let (_, v4) = loopbacks();
        let hosts = Hosts::new(&[(v4, Says::UnderWay)]);
        let Ok(begun) = crate::dial::begin::<OneTask, Hosts>("tcp/127.0.0.1:7447", &hosts) else {
            panic!("an address is dialled");
        };
        assert_eq!(begun.walk.left(), 0, "an address has none to pass to");
        assert_eq!(*hosts.dialled.borrow(), vec![v4]);

        let nowhere = Hosts::new(&[]);
        assert_eq!(
            refused(named_dial(&nowhere)),
            Some(Refusal::Link(LinkOpenError::Refused))
        );
        assert!(nowhere.dialled.borrow().is_empty());

        let hosts = Hosts::new(&[(v4, Says::UnderWay)]);
        let tls = crate::dial::begin::<OneTask, Hosts>("tls/router.example:7447", &hosts);
        let Err(TransportRefusal::Unreachable(refusal)) = tls else {
            panic!("a tls/ host is refused");
        };
        assert_eq!(refusal.endpoint.as_str(), "tls/router.example:7447");
        assert_eq!(
            refusal.why,
            Refusal::Locator(DialRefused::PeerNamedByAddress)
        );
        assert!(hosts.dialled.borrow().is_empty(), "no dial of a tls/ host");

        let faces = supervisor(Link::Idle, 1);
        assert_eq!(
            refused(faces.begin_dial("tcp/router.example:7447")),
            Some(Refusal::Locator(DialRefused::NoResolver))
        );
    }

    /// A dial of `endpoint` that answers `answer`, for a face to be given
    /// ([`LinkSupervisor::put_dial`]).
    fn dialing(
        endpoint: DialEndpoint,
        answer: Option<Result<OpenedLink<Rc<Quiet>>, LinkOpenError>>,
    ) -> Dial<Answer> {
        Dial::new(endpoint, Answer(answer, None))
    }

    fn session(established: bool, node: Option<&[u8]>) -> Session {
        Session {
            established,
            node: node.map(|zid| SessionZid::new(zid).expect("a zid")),
            ended: Rc::new(Cell::new(0)),
            closed: None,
            #[cfg(any(feature = "listen", feature = "group"))]
            seen: Rc::new(Cell::new(None)),
            #[cfg(feature = "resource-snapshot")]
            messages: Rc::new(Cell::new(0)),
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
        owes: bool,
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

        #[cfg(feature = "resource-snapshot")]
        fn message_reading(&self) -> BuildMessageReading {
            BuildMessageReading::empty()
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
            self.owes
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
            owes: false,
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

        #[cfg(feature = "resource-snapshot")]
        type Count = Ended;

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
    }

    /// The count of the ends a test's link was told.
    type Ended = alloc::sync::Arc<core::sync::atomic::AtomicU32>;

    /// A count a test bumps as a link's receive path would, read as the messages it counted.
    #[cfg(feature = "resource-snapshot")]
    impl MessageCount for Ended {
        fn reading(&self) -> BuildMessageReading {
            BuildMessageReading {
                messages: u64::from(self.load(Ordering::SeqCst)),
                ..BuildMessageReading::empty()
            }
        }
    }

    /// `resource-snapshot` — a handle on a face's place reads what its link counted through the
    /// count it keeps, with no lend of the place: while the place is held, the reading's own
    /// thread's lend included, and once the place was emptied, it reads the link's count, never
    /// nothing; a handle made with no count reads nothing. Turned red by a reading made through a
    /// lend of the place (`FaceAt::message_reading`), which reads nothing in both cases, so a
    /// link let go of then would be retired as having counted nothing.
    #[cfg(feature = "resource-snapshot")]
    #[test]
    fn a_faces_count_is_read_with_no_lend_of_its_place() {
        let (aborted, ended) = (Rc::new(Cell::new(0)), Ended::default());
        let site = FaceSite::<crate::sync::Confined<TestOwner>, ApartParts>::empty();
        assert!(site.hold(held_parts(&aborted, &ended)).is_none());
        // SAFETY: the site outlives both handles, in this frame.
        let bare = unsafe { FaceAt::new(&site, Rc::new(HeldEnd::default()), None, None) };
        let counted = Ended::default();
        // SAFETY: as above.
        let at = unsafe { FaceAt::new(&site, Rc::new(HeldEnd::default()), None, None) }
            .counted_by(Ended::clone(&counted));
        counted.store(3, Ordering::SeqCst);
        assert_eq!(bare.message_reading().messages, 0, "CONTROL: no count kept");
        assert_eq!(at.message_reading().messages, 3, "the place free");
        let inside = site.lend(|_| at.message_reading().messages);
        assert_eq!(
            inside,
            Some(3),
            "the place held by the reading's own thread"
        );
        assert!(site.take().is_some());
        counted.store(5, Ordering::SeqCst);
        assert_eq!(at.message_reading().messages, 5, "the place emptied");
    }

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
                owes: false,
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

    /// A debt that came in the window after a holder paid and before it let go is paid by the
    /// look the holder makes as it lets go, through a try of the place, which is free by then;
    /// with nothing owed, the look takes no lend. So for a kind no other thread reaches, whose
    /// look is made with no fence and whose pay takes no swap, and for a kind of a lock of the
    /// value's own. Turned red by a look that leaves the debt unpaid (`FaceSite::pay_after` not
    /// reaching `FaceSite::pay_late`, for either kind), one that pays when nothing is owed, or a
    /// pay that leaves the word owing (`FaceSite::take_owed`).
    #[test]
    fn a_debt_owed_after_the_holder_paid_is_paid_as_it_lets_go() {
        a_late_debt_is_paid_once::<crate::sync::Confined<TestOwner>>();
        #[cfg(feature = "host-lock")]
        a_late_debt_is_paid_once::<crate::sync::Shared>();
    }

    /// [`a_debt_owed_after_the_holder_paid_is_paid_as_it_lets_go`] on a site of kind `K`.
    fn a_late_debt_is_paid_once<K: LockKind>() {
        let (aborted, ended, paid) = (Rc::new(Cell::new(0)), Ended::default(), Ended::default());
        let site = FaceSite::<K, ApartParts>::empty();
        assert!(site.hold(paying_parts(&aborted, &ended, &paid)).is_none());
        site.pay_after();
        assert_eq!(
            paid.load(Ordering::SeqCst),
            0,
            "CONTROL: nothing owed, nothing paid"
        );
        // The debtor's bit, written while the holder had paid and not yet let go.
        site.owed.store(4, Ordering::SeqCst);
        site.pay_after();
        assert_eq!(paid.load(Ordering::SeqCst), 4, "the late debt is paid once");
        assert_eq!(site.owed.load(Ordering::SeqCst), 0, "and owed no more");
    }

    /// A change of a site that waits for nothing: a try of the place takes the parts out or puts
    /// new ones in while the place is free, and finds it held inside the calling thread's own lend,
    /// which it leaves as it found it, the parts it could not put handed back. So for a kind no
    /// other thread reaches and for a kind of a lock of the value's own. Turned red by a try that
    /// waits for the place (`FacePlace::try_with_place` taking the lock), reads a held place as
    /// free, or loses the parts it could not put (`FaceSite::try_hold`).
    #[test]
    fn a_site_changed_by_a_try_finds_a_held_place_and_hands_the_parts_back() {
        a_site_is_changed_by_a_try::<crate::sync::Confined<TestOwner>>();
        #[cfg(feature = "host-lock")]
        a_site_is_changed_by_a_try::<crate::sync::Shared>();
    }

    /// [`a_site_changed_by_a_try_finds_a_held_place_and_hands_the_parts_back`] on a site of kind
    /// `K`.
    fn a_site_is_changed_by_a_try<K: LockKind>() {
        let (aborted, ended, paid) = (Rc::new(Cell::new(0)), Ended::default(), Ended::default());
        let site = FaceSite::<K, ApartParts>::empty();
        assert!(
            matches!(site.try_take(), Lend::Empty),
            "an empty place gives nothing up"
        );
        assert!(
            matches!(
                site.try_hold(paying_parts(&aborted, &ended, &paid)),
                Ok(None)
            ),
            "a free place takes the parts"
        );
        let inside = site.lend(|_| {
            let taken = matches!(site.try_take(), Lend::Held);
            let next = paying_parts(&aborted, &ended, &paid);
            (taken, site.try_hold(next).is_err())
        });
        assert_eq!(
            inside,
            Some((true, true)),
            "a place inside its own lend is found held, and the parts handed back"
        );
        assert!(
            matches!(site.try_take(), Lend::Lent(_)),
            "a free place gives its parts up"
        );
        assert!(
            site.take().is_none(),
            "CONTROL: the try left the place empty"
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

    /// A send held as a value reaches the parts' send part, holds the place until it drops, and
    /// pays what was owed meanwhile as it lets go; an empty place holds none. Turned red by a held
    /// send that leaves a debt unpaid or pays it while it holds the parts (`SiteSend`'s drop), or
    /// a hold that leaves the place free.
    #[test]
    fn a_send_held_as_a_value_pays_what_was_owed_as_it_drops() {
        let (aborted, ended, paid) = (Rc::new(Cell::new(0)), Ended::default(), Ended::default());
        let site = FaceSite::<crate::sync::Confined<TestOwner>, ApartParts>::empty();
        // SAFETY: the test keeps no handle of the parts past a send.
        assert!(
            unsafe { site.hold_send() }.is_none(),
            "an empty place holds no send"
        );
        assert!(site.hold(paying_parts(&aborted, &ended, &paid)).is_none());
        {
            // SAFETY: as above.
            let mut send = unsafe { site.hold_send() }.expect("a free place is held");
            send.tx()
                .expect("the held parts' send part")
                .fetch_add(10, Ordering::SeqCst);
            site.owe(2);
            assert_eq!(
                paid.load(Ordering::SeqCst),
                10,
                "nothing paid while the send holds the parts"
            );
            assert_eq!(
                site.try_lend(|_| ()),
                Lend::Held,
                "the place held meanwhile"
            );
        }
        assert_eq!(
            paid.load(Ordering::SeqCst),
            12,
            "the debt paid as the send let go"
        );
        assert_eq!(
            site.try_lend(|_| ()),
            Lend::Lent(()),
            "the place free again"
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

    /// A link whose parts lie in a face's place is read off the facts its read told the place, with
    /// no lend of the place, and its end through the end it was made with; an empty place, and a
    /// place given a link or emptied of one, reads as a quiet link that names no node and no
    /// Close, and keeps no close owed to it. Turned red by a handle that reads a fact off the
    /// parts' wire (the wire here holds input and is established, and the read told nothing
    /// yet), by facts that outlive the place's link (`FaceSite::hold` or `FaceSite::take` with
    /// no clear), by a close owed to an empty place told to the link held after, or by a close
    /// made inside the place's own lend that is not owed to that lend.
    #[test]
    fn a_link_in_a_faces_place_is_read_off_the_facts_its_read_told() {
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
        assert!(
            !at.holds_input(),
            "a link its read told nothing of holds no input, whatever its wire holds"
        );
        assert!(!at.established(), "and is not established");
        let node = SessionZid::from_array([7, 1]);
        site.facts().tell(ReadFacts {
            established: true,
            holds_input: true,
            waits_for_buffer: false,
            close_reason: Some(CloseReason::Expired),
        });
        site.facts().tell_node(&node);
        assert!(at.holds_input(), "the input the read told");
        assert!(at.established(), "the establishment the read told");
        assert_eq!(at.close_reason(), Some(CloseReason::Expired));
        assert!(at.node() == Some(node), "the node the read told");
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
            (
                at.holds_input(),
                at.node() == Some(node),
                ended.load(Ordering::SeqCst),
            )
        });
        assert_eq!(
            inside,
            Some((true, true, 1)),
            "a read inside the place's own lend reads the facts told, and its close is owed"
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
        assert!(!at.established(), "and as no link established");
        assert!(at.node().is_none(), "naming no node");
        assert_eq!(at.close_reason(), None, "and no Close");
    }

    /// A link's look reads the first of its facts in the order a wait takes them, and through a
    /// face's place reads them off the facts its read told and the place's counts of the writes
    /// left owed, inside the place's own lend too. Turned red by a look that reads an owed write
    /// ahead of held input (`FaceWire::look`), or a handle's look that reads the parts' wire or
    /// tries the place (`FaceAt::look`).
    #[test]
    fn a_links_look_reads_its_first_fact_off_its_places_facts() {
        let wire = |holds, owes| ApartWire {
            holds,
            owes,
            finished: false,
            aborted: Rc::new(Cell::new(0)),
            ended: Ended::default(),
        };
        assert_eq!(wire(true, true).look(), WireLook::HoldsInput);
        assert_eq!(wire(false, true).look(), WireLook::OwesWrite);
        assert_eq!(wire(false, false).look(), WireLook::Quiet);
        let site = FaceSite::<crate::sync::Confined<TestOwner>, ApartParts>::empty();
        // SAFETY: the site outlives the handle, in this frame.
        let at = unsafe { FaceAt::new(&site, Rc::new(HeldEnd::default()), None, None) };
        assert_eq!(at.look(), WireLook::Quiet, "an empty place looks quiet");
        let parts = ApartParts(Some(wire(true, true)), Ended::default());
        // SAFETY: no handle on a cell of the parts lives outside them.
        assert!(site.hold(unsafe { FaceHeld::gathered(parts) }).is_none());
        assert_eq!(
            at.look(),
            WireLook::Quiet,
            "a link its read told nothing of looks quiet, whatever its wire says"
        );
        let facts = site.facts();
        facts.wrote(facts.write_mark(), true);
        assert_eq!(at.look(), WireLook::OwesWrite, "a write left owed");
        assert_eq!(
            site.lend(|_| at.look()),
            Some(WireLook::OwesWrite),
            "looked at inside the place's own lend too"
        );
        facts.tell(ReadFacts {
            waits_for_buffer: true,
            ..ReadFacts::default()
        });
        assert_eq!(
            at.look(),
            WireLook::WaitsForBuffer,
            "a wait for a buffer ahead of an owed write"
        );
        facts.tell(ReadFacts {
            holds_input: true,
            waits_for_buffer: true,
            ..ReadFacts::default()
        });
        assert_eq!(at.look(), WireLook::HoldsInput, "held input ahead of both");
        facts.wrote(facts.write_mark(), false);
        facts.tell(ReadFacts::default());
        assert_eq!(
            at.look(),
            WireLook::Quiet,
            "the owed write drained, and nothing held"
        );
    }

    /// Every fact a read tells is read back as it was told, each Close by its own code, and a
    /// word told over another replaces it whole. Turned red by a word that shares a bit between
    /// two facts, or a code that names another reason (`close_code` out of step with
    /// `CLOSE_REASONS`).
    #[test]
    fn a_reads_word_holds_every_fact_it_was_told() {
        let facts = SiteFacts::new();
        assert_eq!(facts.read(), ReadFacts::default(), "CONTROL: nothing told");
        for (code, reason) in CLOSE_REASONS.iter().enumerate() {
            assert_eq!(close_code(*reason) as usize, code, "{reason:?} at its code");
            for bits in 0..8u32 {
                let told = ReadFacts {
                    established: bits & 1 != 0,
                    holds_input: bits & 2 != 0,
                    waits_for_buffer: bits & 4 != 0,
                    close_reason: Some(*reason),
                };
                facts.tell(told);
                assert_eq!(facts.read(), told);
            }
        }
        facts.tell(ReadFacts::default());
        assert_eq!(
            facts.read(),
            ReadFacts::default(),
            "a word told over another"
        );
    }

    /// A link's node is read once its read told it, and as none once the place is given another
    /// link or emptied, until the read tells that link's. Turned red by a clear that leaves the
    /// node (`SiteFacts::clear`), or a node read off words a change left half written.
    #[test]
    fn a_links_node_is_read_once_told_and_goes_with_its_link() {
        let (aborted, ended) = (Rc::new(Cell::new(0)), Ended::default());
        let site = FaceSite::<crate::sync::Confined<TestOwner>, ApartParts>::empty();
        let (first, second) = (
            SessionZid::from_array([1; 16]),
            SessionZid::from_array([9, 8, 7]),
        );
        assert!(site.facts().node().is_none(), "CONTROL: none told");
        assert!(site.hold(held_parts(&aborted, &ended)).is_none());
        site.facts().tell_node(&first);
        assert!(site.facts().node() == Some(first), "the node told");
        assert!(site.hold(held_parts(&aborted, &ended)).is_some());
        assert!(site.facts().node().is_none(), "a new link names none yet");
        site.facts().tell_node(&second);
        assert!(site.facts().node() == Some(second), "the new link's node");
        assert!(site.take().is_some());
        assert!(site.facts().node().is_none(), "an emptied place names none");
    }

    /// A send that leaves its link owing a write tells the place's facts so as it lets go, and one
    /// that leaves nothing owed tells them that what was owed as it began was drained. Turned red
    /// by a send's drop that tells nothing (`FaceSite::tell_written` left out of `SiteSend`'s
    /// drop), or a link given to the place that keeps the last link's debt.
    #[test]
    fn a_send_tells_its_place_what_it_left_owed_as_it_lets_go() {
        let site = FaceSite::<crate::sync::Confined<TestOwner>, ApartParts>::empty();
        let owing = |owes| {
            let parts = ApartParts(
                Some(ApartWire {
                    holds: false,
                    owes,
                    finished: false,
                    aborted: Rc::new(Cell::new(0)),
                    ended: Ended::default(),
                }),
                Ended::default(),
            );
            // SAFETY: no handle on a cell of the parts lives outside them.
            unsafe { FaceHeld::gathered(parts) }
        };
        assert!(site.hold(owing(true)).is_none());
        assert!(
            !site.facts().owes_write(),
            "CONTROL: a link given to the place owes nothing yet"
        );
        {
            // SAFETY: the test keeps no handle of the parts past the send.
            let _send = unsafe { site.hold_send() }.expect("a free place is held");
        }
        assert!(site.facts().owes_write(), "the write the send left owed");
        assert!(site.hold(owing(false)).is_some());
        assert!(
            !site.facts().owes_write(),
            "a new link owes nothing of the last"
        );
        site.facts().wrote(site.facts().write_mark(), true);
        {
            // SAFETY: as above.
            let _send = unsafe { site.hold_send() }.expect("a free place is held");
        }
        assert!(
            !site.facts().owes_write(),
            "a send that left nothing owed drained what was owed as it began"
        );
    }

    /// A debt paid to the parts tells the place's facts what the payment left owed on the link,
    /// as a send does, since a close it tells writes the link. Turned red by a payment that tells
    /// nothing (`pay_held`).
    #[test]
    fn a_debt_paid_tells_its_place_what_it_left_owed() {
        let site = FaceSite::<crate::sync::Confined<TestOwner>, ApartParts>::empty();
        let parts = ApartParts(
            Some(ApartWire {
                holds: false,
                owes: true,
                finished: false,
                aborted: Rc::new(Cell::new(0)),
                ended: Ended::default(),
            }),
            Ended::default(),
        );
        // SAFETY: no handle on a cell of the parts lives outside them.
        assert!(site.hold(unsafe { FaceHeld::gathered(parts) }).is_none());
        assert!(site.lend(|_| ()).is_some());
        assert!(
            !site.facts().owes_write(),
            "CONTROL: a lend that pays nothing tells nothing"
        );
        site.owe(1);
        assert!(
            site.facts().owes_write(),
            "the debt paid at once left the link owing"
        );
    }

    /// A write left owed while a drain is under way stays owed once the drain ends, and a drain
    /// begun after it clears it: the counts keep a write that a single flag would lose to the
    /// drain's clear. Turned red by a drain that sets the count it reads as it ends rather than
    /// as it began, or a write left owed that does not move its count.
    #[test]
    fn a_write_left_owed_during_a_drain_stays_owed() {
        let facts = SiteFacts::new();
        let drain = facts.write_mark();
        facts.wrote(facts.write_mark(), true);
        facts.wrote(drain, false);
        assert!(
            facts.owes_write(),
            "the write left owed after the drain began"
        );
        let later = facts.write_mark();
        facts.wrote(later, false);
        assert!(!facts.owes_write(), "a drain begun after it");
    }

    /// Two threads writing one link, one leaving writes owed and one draining, as a send under the
    /// place and the read's step outside it do, lose no count, and end owing a write exactly
    /// when the last drain began before the last write left owed. Turned red by a count of the
    /// writes moved by a load and a store (a lost write), or a drain that stores what it reads as
    /// it ends.
    #[cfg(feature = "host-lock")]
    #[test]
    fn two_writers_of_a_link_end_with_its_last_owed_write_kept() {
        extern crate std;
        use std::sync::atomic::AtomicBool as Flag;
        const WRITES: u32 = 20_000;
        for _ in 0..8 {
            let facts = SiteFacts::new();
            let writing = Flag::new(true);
            let last_drain = std::thread::scope(|scope| {
                let drains = scope.spawn(|| {
                    let mut last = None;
                    while writing.load(Ordering::Acquire) {
                        let mark = facts.write_mark();
                        facts.wrote(mark, false);
                        last = Some(mark);
                    }
                    last
                });
                for _ in 0..WRITES {
                    facts.wrote(facts.write_mark(), true);
                }
                writing.store(false, Ordering::Release);
                drains.join().expect("the drains end")
            });
            assert_eq!(
                facts.written.load(Ordering::SeqCst),
                WRITES,
                "no write left owed is lost"
            );
            assert_eq!(
                facts.owes_write(),
                last_drain != Some(WriteMark(WRITES)),
                "owed exactly while the last drain began before the last write"
            );
        }
    }

    /// A read of a link's facts takes nothing of the face's place, so a send that tries the place
    /// while another thread reads the link over and over never finds it held: a droppable send is
    /// dropped behind a send alone. Turned red by a fact read through a lend of the place, whose
    /// lends the tries then meet.
    #[cfg(feature = "host-lock")]
    #[test]
    fn a_read_of_a_links_facts_never_holds_its_place_against_a_send() {
        extern crate std;
        use std::sync::atomic::AtomicBool as Flag;
        let (aborted, ended) = (Rc::new(Cell::new(0)), Ended::default());
        let site = FaceSite::<crate::sync::Shared, ApartParts>::empty();
        assert!(site.hold(held_parts(&aborted, &ended)).is_none());
        site.facts().tell(ReadFacts {
            established: true,
            ..ReadFacts::default()
        });
        let reading = Flag::new(true);
        let held = std::thread::scope(|scope| {
            scope.spawn(|| {
                // SAFETY: the site outlives the handle, in this scope.
                let at = unsafe { FaceAt::new(&site, Rc::new(HeldEnd::default()), None, None) };
                while reading.load(Ordering::Acquire) {
                    let _ = (at.look(), at.established(), at.node(), at.close_reason());
                }
            });
            let held = (0..20_000)
                .filter(|_| site.try_lend(|_| ()) == Lend::Held)
                .count();
            reading.store(false, Ordering::Release);
            held
        });
        assert_eq!(held, 0, "no try of the place met a read of its link");
    }

    /// A link whose place another thread holds reads the facts its read told at once, waiting for
    /// nothing, as it does once that thread lets go of the place. Turned red by a read that waits
    /// for the place (the test then never ends), or one that reads a held place as quiet.
    #[cfg(feature = "host-lock")]
    #[test]
    fn a_link_another_thread_holds_reads_its_told_facts_and_waits_for_nothing() {
        extern crate std;
        use std::sync::Barrier;
        let (aborted, ended) = (Rc::new(Cell::new(0)), Ended::default());
        let site = FaceSite::<crate::sync::Shared, ApartParts>::empty();
        assert!(site.hold(held_parts(&aborted, &ended)).is_none());
        site.facts().tell(ReadFacts {
            established: true,
            holds_input: true,
            ..ReadFacts::default()
        });
        // SAFETY: the site outlives the handle, in this frame.
        let at = unsafe { FaceAt::new(&site, Rc::new(HeldEnd::default()), None, None) };
        assert!(at.holds_input(), "CONTROL: a place no thread holds");
        let (taken, done) = (Barrier::new(2), Barrier::new(2));
        std::thread::scope(|scope| {
            scope.spawn(|| {
                site.lend(|_| {
                    taken.wait();
                    done.wait();
                });
            });
            taken.wait();
            let read = (at.holds_input(), at.established());
            done.wait();
            assert_eq!(
                read,
                (true, true),
                "a place another thread holds reads the facts told"
            );
        });
        assert!(at.holds_input(), "and once the place is let go of");
    }

    /// A second teller of a link's read facts while one is in fails a debug build: the facts have
    /// one writer, the holder of the face's read. Turned red by a tell that does not go through
    /// the one teller (`SiteFacts::one_teller`).
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "told by the holder of its read alone")]
    fn a_second_teller_of_a_links_facts_fails_a_debug_build() {
        let facts = SiteFacts::new();
        let _first = facts.one_teller();
        facts.tell(ReadFacts::default());
    }

    /// A drain told to a count the link's writes never reached fails a debug build: a mark is
    /// read off its own site's count. Turned red by a `SiteFacts::wrote` that stores any mark.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "a count its own site's writes reached")]
    fn a_drain_to_a_count_never_written_fails_a_debug_build() {
        let facts = SiteFacts::new();
        facts.wrote(WriteMark(5), false);
    }

    /// A link's node told twice fails a debug build: it is told once for each link the place is
    /// given. Turned red by a `SiteFacts::tell_node` that writes over a node told.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "a link's node is told once")]
    fn a_links_node_told_twice_fails_a_debug_build() {
        let facts = SiteFacts::new();
        let node = SessionZid::from_array([3]);
        facts.tell_node(&node);
        facts.tell_node(&node);
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

    /// `resource-snapshot` — the reading of a session's links never falls: a link counts from when
    /// it is put in, its handshake included, and what it counted stays once it is let go of (put
    /// over, its face dropped, the links ended), read no more after that. Turned red by a reading
    /// of the links held alone (a retire left out of `put_link`, `drop_face` or `end_faces`), by
    /// a link let go of still read, or by a retire at a drop that was refused.
    #[cfg(feature = "resource-snapshot")]
    #[test]
    fn the_message_reading_keeps_what_the_links_let_go_of_had_counted() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
        let counting = |messages: u64| {
            let session = session(true, None);
            session.messages.set(messages);
            let counter = Rc::clone(&session.messages);
            (Link::Wire(wire(&local, session, false, false)), counter)
        };
        let mut faces = supervisor(Link::Idle, 2);
        assert_eq!(
            faces.message_reading().messages,
            0,
            "no link, nothing counted"
        );

        let (first, first_count) = counting(3);
        faces.put_link(0, first);
        assert_eq!(faces.message_reading().messages, 3, "a link put in counts");
        first_count.set(5);
        assert_eq!(faces.message_reading().messages, 5, "read as it counts");

        faces.put_link(0, Link::Idle);
        assert_eq!(
            faces.message_reading().messages,
            5,
            "what a link let go of counted stays"
        );
        first_count.set(9);
        assert_eq!(
            faces.message_reading().messages,
            5,
            "and the link is read no more"
        );

        let (second, _) = counting(2);
        faces.put_link(0, second);
        let (taken, _) = counting(4);
        let taken = TestFace {
            id: 1,
            link: taken,
            life: idle_life(),
        };
        assert!(faces.place_face(1, taken).is_ok());
        assert_eq!(faces.message_reading().messages, 11);
        assert_eq!(faces.drop_face(1), Some(1));
        assert_eq!(
            faces.message_reading().messages,
            11,
            "a dropped face's link stays counted"
        );
        assert_eq!(
            faces.drop_face(0),
            None,
            "CONTROL: the dial role's face is never dropped"
        );
        assert_eq!(
            faces.message_reading().messages,
            11,
            "so its link is not retired beside being held"
        );

        faces.end_faces(|_| {});
        assert!(faces.faces().all(|face| face.link().wire().is_none()));
        assert_eq!(
            faces.message_reading().messages,
            11,
            "the links ended stay counted"
        );
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
        let mut faces = supervisor(Link::Idle, 2);
        faces.put_dial(
            0,
            dialing(DialEndpoint::Listed(0), Some(Err(LinkOpenError::Refused))),
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
        assert!(faces.face_dial(0).is_none(), "and its row with it");
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
        let mut faces = supervisor(Link::Idle, 2);
        faces.put_dial(0, dialing(named.clone(), None));
        assert_eq!(faces.end_dial(0), Some(named));
        assert!(matches!(dial(&faces).link, Link::Idle));
        assert!(faces.face_dial(0).is_none(), "the row is let go of");

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
        let answered = faces.ask_dial(
            0,
            DialEndpoint::Listed(2),
            Begun::alone(Answer(None, Some(asks.clone()))),
        );
        assert!(answered.is_none(), "the dial is under way");
        assert_eq!(asks.get(), 1, "asked once");
        assert!(matches!(dial(&faces).link, Link::Dialing(_)));
        assert_eq!(
            faces.face_dial(0).map(Dial::endpoint),
            Some(&DialEndpoint::Listed(2)),
            "the face holds the dial under way"
        );

        let answered = faces.ask_dial(
            0,
            DialEndpoint::Listed(0),
            Begun::alone(Answer(
                Some(Err(LinkOpenError::Refused)),
                Some(asks.clone()),
            )),
        );
        assert!(matches!(answered, Some(Err(LinkOpenError::Refused))));
        assert_eq!(asks.get(), 2, "asked once more");
        assert_eq!(
            faces.face_dial(0).map(Dial::endpoint),
            Some(&DialEndpoint::Listed(2)),
            "an answered dial is not put in the face"
        );
    }

    /// A dial under way is asked where it lies in its face: unanswered, it stays there; answered,
    /// it is let go of, the face holds no link, and the answer is handed back with the endpoint it
    /// dialled. A face that holds no dial and one past the table answer nothing, and nothing is
    /// asked of them. Turned red by an answered dial left in its face, or by one taken out of it
    /// while the network has not answered (`LinkSupervisor::answer_face_dial`).
    #[test]
    fn a_dial_is_answered_where_it_lies_in_its_face() {
        let asks = Rc::new(Cell::new(0));
        let under_way = Answer(None, Some(asks.clone()));
        let mut faces = supervisor(Link::Idle, 1);
        faces.put_dial(0, Dial::new(DialEndpoint::Listed(1), under_way));
        assert!(
            faces.answer_face_dial(0).is_none(),
            "the network has not answered"
        );
        assert_eq!(asks.get(), 1, "asked once");
        assert_eq!(
            faces.face_dial(0).map(Dial::endpoint),
            Some(&DialEndpoint::Listed(1)),
            "a dial under way stays in its face"
        );

        let refused = Answer(Some(Err(LinkOpenError::Refused)), Some(asks.clone()));
        faces.put_dial(0, Dial::new(DialEndpoint::Listed(2), refused));
        let Some((answer, endpoint)) = faces.answer_face_dial(0) else {
            panic!("the network answered");
        };
        assert!(matches!(answer, Err(LinkOpenError::Refused)));
        assert_eq!(endpoint, DialEndpoint::Listed(2), "the endpoint it dialled");
        assert_eq!(asks.get(), 2, "asked once more");
        assert!(
            matches!(dial(&faces).link, Link::Idle),
            "an answered dial is let go of"
        );
        assert!(faces.face_dial(0).is_none(), "with its row");

        assert!(faces.answer_face_dial(0).is_none(), "no dial, no answer");
        assert!(faces.answer_face_dial(5).is_none(), "past the table");
        assert_eq!(asks.get(), 2, "nothing asked of a face that holds no dial");
    }

    /// A face's dial lies in its place's row of the dials, and the row is emptied when the face
    /// goes: the stack's dial is let go of with the face, and a link put in over a dial lets it go
    /// as well; a dial given to a face past the table is let go of at once. CONTROL: the dial
    /// role's row holds no dial of the other face. Turned red by a dropped face whose dial stays in
    /// its row (`LinkSupervisor::drop_face`), or a link put over a dial that leaves the dial there
    /// (`LinkSupervisor::put_link`).
    #[test]
    fn a_faces_dial_row_is_emptied_when_the_face_goes() {
        let held = Rc::new(Cell::new(0));
        let under_way = || Answer(None, Some(held.clone()));
        let mut faces = supervisor(Link::Idle, 2);
        let other = TestFace {
            life: idle_life(),
            id: 1,
            link: Link::Idle,
        };
        assert!(faces.place_face(1, other).is_ok());
        faces.put_dial(1, Dial::new(DialEndpoint::Listed(1), under_way()));
        assert_eq!(
            faces.face_dial(1).map(Dial::endpoint),
            Some(&DialEndpoint::Listed(1)),
            "the dial lies in the face's row"
        );
        assert!(faces.face_dial(0).is_none(), "CONTROL: the dial role's row");
        assert_eq!(Rc::strong_count(&held), 2, "the row holds the stack's dial");

        assert_eq!(faces.drop_face(1), Some(1));
        assert_eq!(
            Rc::strong_count(&held),
            1,
            "the stack's dial is let go of with its face"
        );
        let next = TestFace {
            life: idle_life(),
            id: 2,
            link: Link::Idle,
        };
        assert!(faces.place_face(1, next).is_ok());
        assert!(faces.face_dial(1).is_none(), "the next face holds no dial");

        faces.put_dial(0, Dial::new(DialEndpoint::Listed(0), under_way()));
        assert_eq!(Rc::strong_count(&held), 2);
        faces.put_link(0, Link::Idle);
        assert_eq!(Rc::strong_count(&held), 1, "a link put in lets the dial go");
        assert!(faces.face_dial(0).is_none());

        faces.put_dial(5, Dial::new(DialEndpoint::Listed(0), under_way()));
        assert_eq!(Rc::strong_count(&held), 1, "no row past the table");
        assert_eq!(held.get(), 0, "no dial was asked");
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

    /// An owner that reads each face's link itself has the node of the dial role's face read as
    /// `read_face` reads it: a handshake over at a node another face holds is held elsewhere, the
    /// face that stands by is told the node is free once no face holds it, and a taken face's
    /// input is as it came. CONTROL: with no other face the end is read as it came. Turned red by
    /// a reading that takes the face at the first place for a taken one, or reads a taken face's
    /// node as the dial role's.
    #[cfg(feature = "listen")]
    #[test]
    fn an_owner_that_reads_its_links_itself_reads_the_dial_roles_node_as_read_face_does() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
        let node = [7u8, 1];
        let mut faces = supervisor(
            Link::Wire(wire(&local, session(false, Some(&node)), false, true)),
            2,
        );
        let handshaking = LinkPhase::Handshaking {
            row: 0,
            deadline_us: 0,
        };
        assert_eq!(
            faces.read_dial_node(0, 100, handshaking, LinkInput::Ended, true),
            LinkInput::Ended,
            "CONTROL: no other face holds the node"
        );
        let other = TestFace {
            life: idle_life(),
            id: 1,
            link: Link::Wire(wire(&local, session(true, Some(&node)), false, false)),
        };
        assert!(faces.place_face(1, other).is_ok());
        assert_eq!(
            faces.read_dial_node(1, 1, handshaking, LinkInput::Ended, true),
            LinkInput::Ended,
            "a taken face's input is as it came"
        );
        assert_eq!(
            faces.read_dial_node(0, 100, handshaking, LinkInput::Ended, true),
            LinkInput::HeldElsewhere
        );
        faces.put_link(0, Link::Idle);
        assert_eq!(
            faces.read_dial_node(0, 100, LinkPhase::Held, LinkInput::Tick, false),
            LinkInput::Tick,
            "the other face holds the node still"
        );
        assert!(faces.drop_face(1).is_some());
        assert_eq!(
            faces.read_dial_node(0, 100, LinkPhase::Held, LinkInput::Tick, false),
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
    /// when its deadline is later, and reads the clock once at most however often its faces need
    /// the time; a face standing by gives no time, and its read takes none from the clock. A link
    /// holding input makes no wait. The reads are counted for each read alone. Turned red by a
    /// wake read off the link and not off the face's life, or by a read that asks the clock again
    /// at each use of the time.
    #[test]
    fn a_read_sleeps_to_the_next_dial_and_does_not_wait_on_held_input() {
        let reads = Cell::new(0u32);
        let mut now = || {
            reads.set(reads.get() + 1);
            1_000u64
        };
        // The wait one read makes, and how often that read asked the clock.
        let mut read = |faces: &mut LinkSupervisor<Net, TestFace>| {
            reads.set(0);
            let wait = faces.idle_wait(10, &mut now, [], None);
            (wait, reads.get())
        };
        let mut faces = supervisor(Link::Idle, 1);
        set_life(&mut faces, backing_off());
        assert_eq!(
            faces.face(0).map(|face| face.life.phase()),
            Some(LinkPhase::Backoff { until_us: 5_000 })
        );
        assert!(
            matches!(read(&mut faces), (IdleWait::Sleep(4), 1)),
            "a face waiting to dial again"
        );
        faces.put_dial(0, dialing(DialEndpoint::Listed(0), None));
        set_life(
            &mut faces,
            life_in(&[LinkInput::Open, LinkInput::DialPending]),
        );
        assert!(
            matches!(read(&mut faces), (IdleWait::Sleep(1), 1)),
            "a dial under way is looked at again on the next look, its deadline being later"
        );
        #[cfg(feature = "listen")]
        {
            faces.put_link(0, Link::Idle);
            set_life(&mut faces, standing_by());
            assert!(
                matches!(read(&mut faces), (IdleWait::None, 0)),
                "a face standing by reads no clock"
            );
        }

        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
        faces.put_link(
            0,
            Link::Wire(wire(&local, session(true, None), true, false)),
        );
        assert!(faces.holds_input());
        assert!(
            matches!(read(&mut faces), (IdleWait::None, _)),
            "a link that holds input"
        );
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
                // The wait is handed back, as a read does, so the next read has the buffer.
                faces.waited(IdleWait::Input { on, ms });
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
        let mut faces = supervisor(Link::Idle, 3);
        faces.put_dial(0, dialing(DialEndpoint::Listed(0), None));
        faces.end_dials_and_ports();
        assert!(
            matches!(dial(&faces).link, Link::Idle),
            "a dial under way is let go of"
        );
        assert!(faces.face_dial(0).is_none(), "with its row");
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
