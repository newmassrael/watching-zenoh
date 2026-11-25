// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The faces of a session as its driver holds them: each face's link and where it stands (up, in
//! its handshake, dialled, waiting to be dialled again, standing by), the dials under way, the
//! ports the session listens on, and the wait a read makes on all of them before it steps the
//! session.
//!
//! What a link means to the protocol (its handshake, what is declared over it, what its loss takes
//! with it) is the session's. A [`LinkSupervisor`] decides what has happened to a face's link
//! ([`crate::face_life`]) and hands that back, and the session acts on it; it asks the session of a link only
//! what [`FaceSession`] names. So the driver owns the facts of the links (their tasks and their
//! waits) once, and the session owns what it declared over them once
//! (`docs/c-abi-architecture.md`, P1 and P2).
//!
//! Every table here is reserved when the supervisor is made, for as many faces, ports and waits as
//! the session's open admits, and none grows after: a face or a dial past the room is refused
//! (P3).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ops::Deref;

#[cfg(feature = "session-unicast-accept")]
use wz_session_core::bounded::Static;
use wz_session_core::bounded::{push_text, BoundedVec, Lent};
use wz_session_core::caps;
use wz_session_core::close_reason::CloseReason;
use wz_session_core::driver_loop::DriverOutcome;
use wz_session_core::locator_directory::LocatorText;
use wz_session_core::session_zid::SessionZid;
use wz_session_core::zid_hex::same_zid;

use crate::face_life::{FaceRole, Phase, Signals};
use crate::link_cells::CellRc;
use crate::session_drive::{
    LinkListener, LinkOpenError, LinkWait, LinkWaits, Locator, OpenedLink, PendingDial,
    SessionDatagramLink, SessionLinks, WaitOn,
};
use crate::CoopLocalJoinHandle;

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
pub trait FaceRecord {
    /// The session's half of the face's link.
    type Session: FaceSession;

    /// What the drive loop pumps for the face's link, which a dial under way makes.
    type Pump;

    /// A dial under way of the face's link ([`SessionLinks::Dial`]).
    type Dial: PendingDial<Self::Pump>;

    /// The face's number.
    fn id(&self) -> FaceId;

    /// The face's link.
    fn link(&self) -> &Link<Self::Session, Self::Dial>;

    /// The face's link, to replace.
    fn link_mut(&mut self) -> &mut Link<Self::Session, Self::Dial>;
}

/// One link of a face: the session's half of it (`S`), the task that runs it, the link as the
/// session's step reads it, and what its owner waits on for its input and its room, read off the
/// link when it is made. It reads as the session's half (`Deref`): what the session sends over
/// the link is that half's.
pub struct Wire<S> {
    session: S,
    task: CoopLocalJoinHandle<DriverOutcome>,
    link: CellRc<dyn SessionDatagramLink>,
    input: Option<WaitOn>,
    room: Option<WaitOn>,
}

/// Whether `link` has input in its stack it cannot read until another link gives a receive buffer
/// back (`SessionDatagramLink::waits_for_buffer`): never in a build that only dials, whose links
/// read into buffers of their own.
fn waits_for_buffer(link: &CellRc<dyn SessionDatagramLink>) -> bool {
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

impl<S> Wire<S> {
    /// The link whose session half is `session`, run by `task`: `link` is what the session's
    /// step reads, behind whatever gates the session put on it, and `input_wait` and `room_wait`
    /// what its owner waits on for its input and its room, read off the link without the gates
    /// ([`SessionDatagramLink::input_wait`], [`SessionDatagramLink::room_wait`]).
    pub fn new(
        session: S,
        task: CoopLocalJoinHandle<DriverOutcome>,
        link: CellRc<dyn SessionDatagramLink>,
        input_wait: Option<WaitOn>,
        room_wait: Option<WaitOn>,
    ) -> Self {
        Self {
            session,
            task,
            link,
            input: input_wait,
            room: room_wait,
        }
    }

    /// Whether the link's task has ended.
    pub fn finished(&self) -> bool {
        self.task.is_finished()
    }

    /// End the link's task.
    pub fn abort(&self) {
        self.task.abort();
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

impl<S> Deref for Wire<S> {
    type Target = S;

    fn deref(&self) -> &S {
        &self.session
    }
}

/// A face's link: up, in its handshake, being dialled, waiting to be dialled, or standing by. A
/// dial under way is held in its face's link, so a face has one dial at most and the faces' table
/// is the dials' table too.
pub enum Link<S, D> {
    /// Established: the session's sends go through it.
    Up(Wire<S>),
    /// A handshake under way, given up at `deadline_us`. The dial role's face has dialled the
    /// endpoint before `next` and goes on to the one after; another face holds a link it dialled
    /// once or took off a port, and is removed when the handshake fails.
    Opening {
        /// The link in its handshake.
        wire: Wire<S>,
        /// The endpoint the dial role dials next when this one fails.
        next: usize,
        /// When the handshake is given up.
        deadline_us: u64,
    },
    /// A dial under way, given up at `deadline_us`, as is the handshake that follows it.
    Dialing {
        /// The dial, asked at each move of the face ([`Dial::answer`]).
        dial: Dial<D>,
        /// The endpoint the dial role dials next when this one fails.
        next: usize,
        /// When the dial is given up.
        deadline_us: u64,
    },
    /// Lost, or no endpoint answered: the endpoints are dialled again at `at_us`.
    Waiting {
        /// When the endpoints are dialled again.
        at_us: u64,
    },
    /// The dial role's face, whose link reached the node `zid` while another face holds that
    /// node or brings a link to it up: it stands by, and is dialled again once no other face has
    /// the node. Only a session that takes faces besides its dial (`listen`) has another face.
    #[cfg(feature = "listen")]
    Held {
        /// The node the link reached.
        zid: SessionZid,
    },
}

impl<S, D> Link<S, D> {
    /// The link's wire while it is up or in its handshake.
    pub fn wire(&self) -> Option<&Wire<S>> {
        match self {
            Link::Up(wire) | Link::Opening { wire, .. } => Some(wire),
            _ => None,
        }
    }

    /// Where the link stands, without the wire and the dial it holds: what the face's value
    /// decides on (`face_life`).
    pub fn phase(&self) -> Phase {
        match self {
            Link::Up(_) => Phase::Up,
            Link::Opening {
                next, deadline_us, ..
            } => Phase::Opening {
                next: *next,
                deadline_us: *deadline_us,
            },
            Link::Dialing {
                next, deadline_us, ..
            } => Phase::Dialing {
                next: *next,
                deadline_us: *deadline_us,
            },
            Link::Waiting { at_us } => Phase::Waiting { at_us: *at_us },
            #[cfg(feature = "listen")]
            Link::Held { zid } => Phase::Held { node: *zid },
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
    /// by ([`DialEndpoint::Port`]).
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
/// dial after the open, its text held by the dial alone. None allocates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialEndpoint {
    /// The endpoint to dial in this row of the session's texts.
    Listed(usize),
    /// The endpoint to listen on in this row of the session's texts.
    Port(usize),
    /// An endpoint named apart from the session's texts.
    Named(LocatorText),
}

impl DialEndpoint {
    /// The endpoint's text, read in `texts`, the session's; a row past the last reads empty.
    pub fn text<'a>(&'a self, texts: &'a EndpointTexts) -> &'a str {
        match self {
            DialEndpoint::Listed(at) => texts.dial_text(*at),
            DialEndpoint::Port(at) => texts.listen_text(*at),
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
    /// (`face_life::Signals::dial`).
    pub fn answer<P>(&mut self) -> Option<Result<OpenedLink<P>, LinkOpenError>>
    where
        D: PendingDial<P>,
    {
        self.pending.poll()
    }
}

/// The answer of a face's dial under way: the link it made, the refusal, or `None` while it is
/// still being made.
pub type DialAnswer<P> = Option<Result<OpenedLink<P>, LinkOpenError>>;

/// What a session reads of a face at a step ([`LinkSupervisor::read_face`]): its role, where its
/// link stands, and what it did since. The answer of its dial, kept for the link it made, is
/// written where the reader asked for it, so a step that reads an established face moves no
/// room for a link it does not have.
pub struct FaceRead {
    /// Which face it is: the dial role's, or one taken besides.
    pub role: FaceRole,
    /// Where the face's link stands.
    pub phase: Phase,
    /// What the link did since the face was last read.
    pub signals: Signals,
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
/// session states one.
struct Listening<P> {
    listener: Box<dyn LinkListener<P>>,
    endpoint: Option<usize>,
    /// What the port gave the last read's wait to wait on, when the port is asked for a
    /// connection only once a wait found it ready (`LinkListener::asked_when_ready`); `None` for
    /// a port asked at every step.
    on: Option<WaitOn>,
    /// Whether a wait found the port ready since it last had no connection to give.
    ready: bool,
}

/// What a link taken off a port came to ([`LinkSupervisor::accept_at`]).
pub enum Accepted<P> {
    /// A connection, with the endpoint its port is stated for.
    Link(OpenedLink<P>, Option<DialEndpoint>),
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
    /// wait on. The wait keeps the session's buffer it was made in, holding the entries the stack
    /// found ready ([`LinkWaits::wait_ready`]), for the session to take back
    /// ([`LinkSupervisor::waited`]). Out of line: a session's open and each of its
    /// reads wait.
    #[inline(never)]
    pub fn wait(&mut self, waits: &impl LinkWaits, sleep: impl FnOnce(u32)) {
        match self {
            IdleWait::None => {}
            IdleWait::Input { on, ms } => {
                let ready = waits.wait_ready(on, *ms);
                on.truncate(ready);
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

    /// Put `face` at the free place `at`; handed back at the dial role's place, at a place
    /// another face holds, and past the table.
    fn put(&mut self, at: usize, face: F) -> Result<(), F>;

    /// Take the face at `at` out, its place free from then; the dial role's is never taken.
    fn take(&mut self, at: usize) -> Option<F>;

    /// Take out every face but the dial role's.
    fn keep_dial_only(&mut self);
}

/// The faces of a session that takes faces beside its dial role's: a place for each, held or
/// free, made at the open for as many as the session holds at once and never grown. Only the
/// places up to the last one held are kept in the row, the others reserved behind it, so every
/// walk over the faces ends at the last face and passes over no free place past it: a session
/// that keeps places for many faces and holds one or two walks one or two at each step.
pub struct ManyFaces<F> {
    faces: Vec<Option<F>>,
    places: usize,
}

impl<F> FacePlaces<F> for ManyFaces<F> {
    const TAKES: bool = true;

    fn with_dial(dial: F, places: usize) -> Self {
        let places = places.max(1);
        let mut faces = Vec::with_capacity(places);
        faces.push(Some(dial));
        Self { faces, places }
    }

    fn places(&self) -> usize {
        self.places
    }

    fn get(&self, at: usize) -> Option<&F> {
        self.faces.get(at)?.as_ref()
    }

    fn get_mut(&mut self, at: usize) -> Option<&mut F> {
        self.faces.get_mut(at)?.as_mut()
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a F>
    where
        F: 'a,
    {
        self.faces.iter().flatten()
    }

    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut F>
    where
        F: 'a,
    {
        self.faces.iter_mut().flatten()
    }

    fn placed<'a>(&'a self) -> impl Iterator<Item = (usize, &'a F)>
    where
        F: 'a,
    {
        self.faces
            .iter()
            .enumerate()
            .filter_map(|(at, face)| Some((at, face.as_ref()?)))
    }

    fn placed_mut<'a>(&'a mut self) -> impl Iterator<Item = (usize, &'a mut F)>
    where
        F: 'a,
    {
        self.faces
            .iter_mut()
            .enumerate()
            .filter_map(|(at, face)| Some((at, face.as_mut()?)))
    }

    fn put(&mut self, at: usize, face: F) -> Result<(), F> {
        if at == 0 || at >= self.places {
            return Err(face);
        }
        // The free places up to `at` join the row; the room for every place was reserved by
        // `with_dial`, so none allocates.
        if at >= self.faces.len() {
            self.faces.resize_with(at.saturating_add(1), || None);
        }
        match self.faces.get_mut(at) {
            Some(place) if place.is_none() => {
                *place = Some(face);
                Ok(())
            }
            _ => Err(face),
        }
    }

    fn take(&mut self, at: usize) -> Option<F> {
        if at == 0 {
            return None;
        }
        let face = self.faces.get_mut(at)?.take();
        // The row ends at the last place still held, the dial role's at the least.
        let held = self
            .faces
            .iter()
            .rposition(Option::is_some)
            .map_or(1, |last| last.saturating_add(1));
        self.faces.truncate(held);
        face
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

    fn put(&mut self, _at: usize, face: F) -> Result<(), F> {
        Err(face)
    }

    fn take(&mut self, _at: usize) -> Option<F> {
        None
    }

    fn keep_dial_only(&mut self) {}
}

/// A session's faces, dials and ports over the network `L`, each face kept as the session's
/// record `F` at a place of its own in the table `P`. The first place is the dial role's face's,
/// which is never taken out.
pub struct LinkSupervisor<L: SessionLinks, F, P = ManyFaces<F>> {
    links: L,
    /// The faces by their places, the table made whole at the open for as many places as the
    /// session holds faces at and never grown: a face keeps the place it was put at until it is
    /// taken out, so its place names it for that whole time, and the session names the face's
    /// other tables by the same place. A place no face holds is free for the next.
    faces: P,
    listeners: Vec<Listening<L::Pump>>,
    /// The one buffer a read's waits are gathered in, reserved at the open for every link, port
    /// and wake a read waits on at once; `None` while a read waits with it, so that a read on
    /// another thread then makes no buffer of its own after the open.
    waits: Option<Vec<LinkWait>>,
    next_face: FaceId,
    /// How often a face or a port was reached to be changed, or a port came to be asked: what a
    /// session that moved its links on compares, to move them again only once one may have
    /// changed ([`Self::moves`]). Wraps; only its change is read.
    moves: u32,
    /// The record each face is kept as: the table `P` holds it, the supervisor names it.
    records: core::marker::PhantomData<fn() -> F>,
}

impl<L: SessionLinks, F: FaceRecord<Pump = L::Pump, Dial = L::Dial>, P: FacePlaces<F>>
    LinkSupervisor<L, F, P>
{
    /// The faces of a session over `links`, `dial` the dial role's at the first place: `places`
    /// places in all (one at least, the dial role's), each face with a dial under way at most, and
    /// `waits` waits a read makes at once, reserved now; `None` when the heap refuses that room,
    /// which an open answers as it answers an arena that cannot be reserved. The ports are the
    /// open's, taken as it listens ([`Self::listen`]). Faces taken after are numbered from 1.
    pub fn new(links: L, dial: F, places: usize, waits: usize) -> Option<Self> {
        let mut room = Vec::new();
        room.try_reserve_exact(waits).ok()?;
        Some(Self {
            links,
            faces: P::with_dial(dial, places),
            listeners: Vec::new(),
            waits: Some(room),
            next_face: 1,
            moves: 0,
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

    /// Whether a port is to be asked for a connection at the next step: one asked at every step,
    /// or one a wait found ready ([`Self::accept_at`]).
    pub fn ports_to_ask(&self) -> bool {
        self.listeners
            .iter()
            .any(|listening| listening.on.is_none() || listening.ready)
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

    /// Put `face` at the free place `at`, which it keeps until it is taken out; handed back at
    /// the dial role's place, at a place another face holds, and past the table.
    pub fn place_face(&mut self, at: usize, face: F) -> Result<(), F> {
        self.moved();
        self.faces.put(at, face)
    }

    /// Take the face at `at` out of the table, its place free from then; the dial role's, at the
    /// first, is never taken. No other face moves.
    pub fn take_face(&mut self, at: usize) -> Option<F> {
        self.moved();
        self.faces.take(at)
    }

    /// Begin a dial of `to`, which the network answers later.
    /// Out of line: the stack's dial of each protocol is put together here, not in its caller.
    #[inline(never)]
    pub fn begin_dial(&self, to: Locator) -> Result<L::Dial, LinkOpenError> {
        self.links.begin_initiator(to)
    }

    /// Listen on `at`, whose links are stated for the endpoint in row `endpoint` of the session's
    /// texts when the session states one.
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

    /// Whether the session listens on any port.
    pub fn listens(&self) -> bool {
        !self.listeners.is_empty()
    }

    /// The locator each port is bound to, with the port the stack chose where 0 was asked for.
    pub fn listening(&self) -> impl Iterator<Item = Locator> + '_ {
        self.listeners
            .iter()
            .map(|listening| listening.listener.local())
    }

    /// Take a connection off the port at `at`: `None` past the last port. A port broken for good
    /// is let go of, so the port after it is then at `at`.
    pub fn accept_at(&mut self, at: usize) -> Option<Accepted<L::Pump>> {
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
    pub fn put_link(&mut self, at: usize, link: Link<F::Session, L::Dial>) {
        if let Some(face) = self.face_mut(at) {
            *face.link_mut() = link;
        }
    }

    /// Let go of the dial of the face at `at`, which is over, the face waiting from `at_us`: the
    /// endpoint it dialled, moved out of the dial, which the refusal or the link's session names.
    /// `None` for a face that held no dial, which waits all the same, and for one past the table.
    pub fn end_dial(&mut self, at: usize, at_us: u64) -> Option<DialEndpoint> {
        let link = self.face_mut(at)?.link_mut();
        match core::mem::replace(link, Link::Waiting { at_us }) {
            Link::Dialing { dial, .. } => Some(dial.into_endpoint()),
            _ => None,
        }
    }

    /// The face at `at`, whose handshake completed, holds its link up.
    pub fn establish(&mut self, at: usize) {
        let Some(face) = self.face_mut(at) else {
            return;
        };
        let link = face.link_mut();
        if let Link::Opening { .. } = link {
            if let Link::Opening { wire, .. } = core::mem::replace(link, Link::Waiting { at_us: 0 })
            {
                *link = Link::Up(wire);
            }
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
            .any(|face| face.link().wire().is_some_and(Wire::holds_input))
    }

    /// What the face at `at`, numbered `id`, holds: its role, where its link stands and what it
    /// did since (`Signals`); the answer of a dial under way is asked here and written to `answer`,
    /// kept there for the link it made, which is left as it was for a face with no dial. A face past the table reads as one taken besides the dial role's that waits
    /// with no time to dial again. The role is the place's: the first is the dial role's, placed
    /// by [`Self::new`] and never taken out ([`Self::take_face`]). A table of the dial role's face
    /// alone reads every place in that role, and holds no other face to hold a node.
    // Out of line, so its caller reads the role as a value and takes one path for either role.
    #[inline(never)]
    pub fn read_face(
        &mut self,
        at: usize,
        id: FaceId,
        answer: &mut DialAnswer<L::Pump>,
    ) -> FaceRead {
        // A session that takes no face besides its dial has the dial role alone: a place past the
        // first holds a departed face's tomb there, which never moves.
        #[cfg(feature = "listen")]
        let role = if at == 0 || !P::TAKES {
            FaceRole::Dial
        } else {
            FaceRole::Taken
        };
        #[cfg(not(feature = "listen"))]
        let role = FaceRole::Dial;
        let phase = self
            .face(at)
            .map_or(Phase::Waiting { at_us: u64::MAX }, |face| {
                face.link().phase()
            });
        let mut signals = Signals::default();
        match self.face_mut(at).map(|face| face.link_mut()) {
            Some(Link::Dialing { dial, .. }) => {
                *answer = dial.answer();
                signals.dial = answer.as_ref().map(Result::is_ok);
            }
            // An established link and one in its handshake read their wire's end by one look; only
            // the handshake's has an establishment to report.
            Some(link) => {
                if let Some(wire) = link.wire() {
                    signals.ended = wire.finished();
                    signals.established =
                        matches!(link, Link::Opening { .. }) && wire.established();
                }
            }
            None => {}
        }
        #[cfg(feature = "listen")]
        if let Phase::Held { node } = &phase {
            signals.node_held = P::TAKES && self.node_is_held(node.as_slice(), id);
        }
        #[cfg(not(feature = "listen"))]
        let _ = id;
        FaceRead {
            role,
            phase,
            signals,
        }
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
            wire.link.write_owed_now();
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
            .filter_map(|wire| wire.input);
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
    /// to be looked at again (`face_life::Phase::wake_at`): a dial under way or waiting at its
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
            if let Some(wake_us) = face.link().phase().wake_at(&mut read_now) {
                let left_ms = wake_us.saturating_sub(read_now()).saturating_div(1000);
                dial_left_ms = Some(dial_left_ms.map_or(left_ms, |held| held.min(left_ms)));
            }
            match face.link() {
                Link::Up(wire) | Link::Opening { wire, .. } => {
                    if wire.link.holds_input() {
                        holds = true;
                    } else if waits_for_buffer(&wire.link) {
                        // Its input waits in the stack until another link gives a receive
                        // buffer back, which that link's own input wakes the read for.
                    } else if let Some(on) = wire.input {
                        let wait = if wire.link.owes_write() {
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
                Link::Waiting { .. } | Link::Dialing { .. } => {}
                #[cfg(feature = "listen")]
                Link::Held { .. } => {}
            }
        }
        if holds {
            waits.clear();
            self.waits = Some(waits);
            return IdleWait::None;
        }
        // Asked at each wait: a listener whose own work is under way (a WebSocket handshake) or
        // that takes no connection now gives no wait on its port until that changes.
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
                if let Some(port) = wire.input {
                    wire.session
                        .input_seen(on.iter().any(|ready| ready.on == port));
                }
            }
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
            if wire.input.is_some() {
                wire.session.input_seen(true);
            }
        }
    }

    /// Let go of every dial under way, whose connection is then not made, and of every port.
    pub fn end_dials_and_ports(&mut self) {
        for face in self.faces_mut() {
            let link = face.link_mut();
            if let Link::Dialing { .. } = link {
                *link = Link::Waiting { at_us: u64::MAX };
            }
        }
        self.listeners.clear();
    }

    /// End every face's link, whatever it is doing, telling an established peer so, after
    /// `each` is shown the face. The dial role's face stays, with no link and no redial; the
    /// others go.
    pub fn end_faces(&mut self, mut each: impl FnMut(&mut F)) {
        for face in self.faces_mut() {
            each(face);
            let link = core::mem::replace(face.link_mut(), Link::Waiting { at_us: u64::MAX });
            if let Link::Up(wire) | Link::Opening { wire, .. } = link {
                if wire.established() {
                    wire.end();
                }
                wire.abort();
            }
        }
        self.faces.keep_dial_only();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::rc::Rc;
    use alloc::vec;
    use core::cell::Cell;
    use core::sync::atomic::Ordering;
    use wz_session_core::link::RxFrame;

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

    type TestLink = Link<Session, Answer>;

    struct TestFace {
        id: FaceId,
        link: TestLink,
    }

    impl FaceRecord for TestFace {
        type Session = Session;
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
    struct Ports(Rc<Cell<u32>>, bool);

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
    struct Empty(Rc<Cell<u32>>, bool);

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
    struct NoneReady;

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

    /// A dial that answers `answer` the first time it is asked, and nothing after.
    struct Answer(Option<Result<OpenedLink<Rc<Quiet>>, LinkOpenError>>);

    impl PendingDial<Rc<Quiet>> for Answer {
        fn poll(&mut self) -> Option<Result<OpenedLink<Rc<Quiet>>, LinkOpenError>> {
            self.0.take()
        }
    }

    impl From<OpenedLink<Rc<Quiet>>> for Answer {
        fn from(opened: OpenedLink<Rc<Quiet>>) -> Self {
            Answer(Some(Ok(opened)))
        }
    }

    /// A face dialling `endpoint` with a dial that answers `answer`.
    fn dialing(
        endpoint: DialEndpoint,
        answer: Option<Result<OpenedLink<Rc<Quiet>>, LinkOpenError>>,
        next: usize,
        deadline_us: u64,
    ) -> TestLink {
        Link::Dialing {
            dial: Dial::new(endpoint, Answer(answer)),
            next,
            deadline_us,
        }
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
        LinkSupervisor::new(Net, TestFace { id: 100, link }, faces, 2)
            .expect("the heap holds two waits")
    }

    /// A reach of a face to change it is counted, and a look at one is not: what a session that
    /// left its links settled compares to move them again. A supervisor with no port has none to
    /// ask. Turned red by a mutable reach that counts nothing (`face_mut`, `put_link`), or a look
    /// that counts one (`face`, `faces`).
    #[test]
    fn a_change_of_a_face_is_counted_and_a_look_is_not() {
        let mut faces = supervisor(Link::Waiting { at_us: 5 }, 2);
        assert!(!faces.ports_to_ask(), "no port, none to ask");
        let before = faces.moves();
        assert!(faces.face(0).is_some());
        assert_eq!(faces.faces().count(), 1);
        assert_eq!(faces.moves(), before, "a look changes nothing");
        faces.put_link(0, Link::Waiting { at_us: 9 });
        let put = faces.moves();
        assert_ne!(put, before, "a link put in is a change");
        assert!(faces.face_mut(0).is_some());
        assert_ne!(faces.moves(), put, "a reach to change a face is a change");
    }

    /// A dial answers what its network answered once, and names the endpoint it reaches.
    #[test]
    fn a_dial_answers_once_and_names_its_endpoint() {
        let mut dial = Dial::new(
            DialEndpoint::Listed(1),
            Answer(Some(Err(LinkOpenError::Refused))),
        );
        assert_eq!(dial.endpoint(), &DialEndpoint::Listed(1));
        assert!(matches!(dial.answer(), Some(Err(LinkOpenError::Refused))));
        assert!(dial.answer().is_none(), "answered once");
    }

    /// A link in its handshake is brought up once the handshake completed; one up already stays.
    #[test]
    fn an_opening_link_is_brought_up() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::new(&runtime);
        let mut faces = supervisor(
            Link::Opening {
                wire: wire(&local, session(true, None), false, false),
                next: 3,
                deadline_us: 50,
            },
            1,
        );
        faces.establish(0);
        assert!(matches!(dial(&faces).link, Link::Up(_)), "brought up");
        faces.establish(0);
        assert!(matches!(dial(&faces).link, Link::Up(_)), "and stays up");
    }

    /// Another face holds a node while its link to it is up, and a face never holds one for
    /// itself; once that face goes, no face holds the node.
    #[cfg(feature = "listen")]
    #[test]
    fn a_node_is_held_by_another_face_while_its_link_is_up() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::new(&runtime);
        let node = [7u8, 1];
        let mut faces = supervisor(Link::Held { zid: held_node() }, 2);
        let other = TestFace {
            id: 1,
            link: Link::Up(wire(&local, session(true, Some(&node)), false, false)),
        };
        assert!(faces.place_face(1, other).is_ok());
        assert!(faces.node_is_held(&node, 100));
        assert!(
            !faces.node_is_held(&node, 1),
            "a face does not hold the node for itself"
        );
        assert!(faces.take_face(1).is_some());
        assert!(!faces.node_is_held(&node, 100));
    }

    /// A face is read as its link stands: a dial's answer is asked once and kept, a link in its
    /// handshake says whether it completed, a face that stands by finds its node held by a face
    /// that reaches it, and a face past the table reads as one waiting with no time to dial again.
    #[test]
    fn a_face_is_read_as_its_link_stands() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::new(&runtime);
        let mut faces = supervisor(
            dialing(
                DialEndpoint::Listed(0),
                Some(Err(LinkOpenError::Refused)),
                1,
                50,
            ),
            2,
        );
        let mut answer = None;
        let read = faces.read_face(0, 100, &mut answer);
        assert!(matches!(answer, Some(Err(LinkOpenError::Refused))));
        assert_eq!(read.signals.dial, Some(false));
        let mut again_answer = None;
        let again = faces.read_face(0, 100, &mut again_answer);
        assert!(again_answer.is_none(), "a dial is asked once");
        assert_eq!(again.signals.dial, None);

        let node = [7u8, 1];
        let opening = TestFace {
            id: 1,
            link: Link::Opening {
                wire: wire(&local, session(true, Some(&node)), false, false),
                next: 0,
                deadline_us: 50,
            },
        };
        assert!(faces.place_face(1, opening).is_ok());
        let mut answer = None;
        let read = faces.read_face(1, 1, &mut answer);
        assert_eq!(
            read.phase,
            Phase::Opening {
                next: 0,
                deadline_us: 50
            }
        );
        assert!(read.signals.established);
        assert!(!read.signals.ended);
        assert!(answer.is_none(), "a handshake's face writes no answer");
        // An established link reads its wire's end and reports no establishment: only a
        // handshake's link has one to report.
        faces.put_link(
            1,
            Link::Up(wire(&local, session(true, Some(&node)), false, false)),
        );
        let up = faces.read_face(1, 1, &mut None);
        assert_eq!(up.phase, Phase::Up);
        assert!(!up.signals.established);
        assert!(!up.signals.ended);

        #[cfg(feature = "listen")]
        {
            faces.put_link(0, Link::Held { zid: held_node() });
            assert!(faces.read_face(0, 100, &mut None).signals.node_held);
            assert!(
                !faces.read_face(0, 1, &mut None).signals.node_held,
                "a face does not hold the node for itself"
            );
        }

        let mut answer = None;
        let past = faces.read_face(9, 9, &mut answer);
        assert_eq!(past.phase, Phase::Waiting { at_us: u64::MAX });
        assert_eq!(past.signals, Signals::default());
        assert!(answer.is_none());
    }

    /// A face is read in the role of its row: the first, which the table never lets go of, is the
    /// dial role's, and any other, or one past the table, one taken besides. Turned red by a role
    /// read off anything but the row.
    #[test]
    fn a_face_is_read_in_the_role_of_its_row() {
        let mut faces = supervisor(Link::Waiting { at_us: 0 }, 2);
        let taken = TestFace {
            id: 1,
            link: Link::Waiting { at_us: 0 },
        };
        assert!(faces.place_face(1, taken).is_ok());
        assert_eq!(faces.read_face(0, 100, &mut None).role, FaceRole::Dial);
        #[cfg(feature = "listen")]
        {
            assert_eq!(faces.read_face(1, 1, &mut None).role, FaceRole::Taken);
            assert_eq!(faces.read_face(9, 9, &mut None).role, FaceRole::Taken);
        }
        // Without `listen` no face is taken besides the dial: a place past the first holds only a
        // departed face's tomb, read in the one role there is.
        #[cfg(not(feature = "listen"))]
        {
            assert_eq!(faces.read_face(1, 1, &mut None).role, FaceRole::Dial);
            assert_eq!(faces.read_face(9, 9, &mut None).role, FaceRole::Dial);
        }
    }

    /// A table of the dial role's face alone reads every place in that role, so a step of such a
    /// session never names a face to remove; a dial role's face that stands by finds no node held,
    /// as no other face is there to hold one. Turned red by a role read off the place in such a
    /// table.
    #[test]
    fn a_table_of_one_face_reads_every_place_in_the_dial_role() {
        #[cfg(feature = "listen")]
        let link = Link::Held { zid: held_node() };
        #[cfg(not(feature = "listen"))]
        let link = Link::Waiting { at_us: 0 };
        let mut faces: LinkSupervisor<Net, TestFace, OneFace<TestFace>> =
            LinkSupervisor::new(Net, TestFace { id: 100, link }, 2, 2)
                .expect("the heap holds two waits");
        assert!(!faces.takes_faces());
        assert!(
            supervisor(Link::Waiting { at_us: 0 }, 2).takes_faces(),
            "CONTROL: a table of many faces takes them"
        );
        assert_eq!(faces.read_face(0, 100, &mut None).role, FaceRole::Dial);
        assert_eq!(faces.read_face(1, 1, &mut None).role, FaceRole::Dial);
        #[cfg(feature = "listen")]
        assert!(!faces.read_face(0, 100, &mut None).signals.node_held);
    }

    /// A dial that is over is let go of and hands over the endpoint it dialled, its own text
    /// whole, the face waiting from then; a face that held no dial waits all the same and hands
    /// none, and a face past the table is left as it is.
    #[test]
    fn an_ended_dial_hands_over_its_endpoint_and_its_face_waits() {
        let named = DialEndpoint::Named(LocatorText::try_from("tcp/1.2.3.4:1").expect("a row"));
        let mut faces = supervisor(dialing(named.clone(), None, 1, 50), 2);
        assert_eq!(faces.end_dial(0, 7), Some(named));
        assert!(matches!(dial(&faces).link, Link::Waiting { at_us: 7 }));

        faces.put_link(0, Link::Waiting { at_us: 3 });
        assert_eq!(faces.end_dial(0, 9), None, "no dial, no endpoint");
        assert!(matches!(dial(&faces).link, Link::Waiting { at_us: 9 }));

        assert_eq!(faces.end_dial(5, 11), None, "past the table");
        assert!(matches!(dial(&faces).link, Link::Waiting { at_us: 9 }));
    }

    /// The node a face's handshake reached is the one it stands by for only while another face
    /// reaches it; a face with no link, or one past the table, reached none.
    #[test]
    fn a_face_stands_by_for_its_node_only_while_another_face_reaches_it() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::new(&runtime);
        let node = [7u8, 1];
        let mut faces = supervisor(
            Link::Opening {
                wire: wire(&local, session(false, Some(&node)), false, false),
                next: 0,
                deadline_us: 50,
            },
            2,
        );
        assert!(
            faces.held_node(0, 100).is_none(),
            "no other face reaches it"
        );
        let other = TestFace {
            id: 1,
            link: Link::Up(wire(&local, session(true, Some(&node)), false, false)),
        };
        assert!(faces.place_face(1, other).is_ok());
        assert!(faces.held_node(0, 100) == Some(held_node()));
        assert!(faces.take_face(1).is_some());
        assert!(faces.held_node(0, 100).is_none());
        faces.put_link(0, Link::Waiting { at_us: 0 });
        assert!(faces.held_node(0, 100).is_none(), "a face with no link");
        assert!(faces.held_node(9, 100).is_none(), "a face past the table");
    }

    /// A handshake that ended names the Close its peer sent, else the end of its task, else the
    /// deadline it is given up at; ending the link's task is what makes it the second.
    #[test]
    fn a_handshake_end_names_the_close_the_task_end_or_the_deadline() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::new(&runtime);
        let opening = |session| Link::Opening {
            wire: wire(&local, session, false, false),
            next: 0,
            deadline_us: 50,
        };
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
        faces.put_link(0, Link::Waiting { at_us: 0 });
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
        let mut faces = supervisor(Link::Waiting { at_us: 0 }, 2);
        let face = |id| TestFace {
            id,
            link: Link::Waiting { at_us: 0 },
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
        assert!(faces.take_face(0).is_none(), "the dial role's face stays");
        assert!(faces.take_face(2).is_none(), "past the table");
        assert_eq!(faces.take_face(1).map(|face| face.id), Some(1));
        assert!(faces.take_face(1).is_none(), "the place is free");
        assert_eq!(faces.next_face_id(), 1);
        faces.advance_face_id();
        assert_eq!(faces.next_face_id(), 2);
    }

    /// A face keeps its place while a face before it is taken out, and the next face takes the
    /// free place it was put at: no face moves. Turned red by a table that closes the gap a face
    /// left (the faces after it moved down a place).
    #[test]
    fn a_face_keeps_its_place_while_another_is_taken_out() {
        let mut faces = supervisor(Link::Waiting { at_us: 0 }, 4);
        let face = |id| TestFace {
            id,
            link: Link::Waiting { at_us: 0 },
        };
        assert!(faces.place_face(1, face(1)).is_ok());
        assert!(faces.place_face(2, face(2)).is_ok());
        assert_eq!(faces.held(), 3);
        assert_eq!(faces.take_face(1).map(|face| face.id), Some(1));
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
    #[test]
    fn a_read_asks_each_port_for_its_wait_at_each_wait() {
        let mut faces = supervisor(Link::Waiting { at_us: u64::MAX }, 1);
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

    #[test]
    fn a_read_sleeps_to_the_next_dial_and_does_not_wait_on_held_input() {
        let mut clock_reads = 0;
        let mut now = || {
            clock_reads += 1;
            1_000u64
        };
        let mut faces = supervisor(Link::Waiting { at_us: 5_000 }, 1);
        assert!(matches!(
            faces.idle_wait(10, &mut now, [], None),
            IdleWait::Sleep(4)
        ));
        faces.put_link(0, dialing(DialEndpoint::Listed(0), None, 0, 0));
        assert!(matches!(
            faces.idle_wait(10, &mut now, [], None),
            IdleWait::Sleep(1)
        ));
        #[cfg(feature = "listen")]
        {
            faces.put_link(0, Link::Held { zid: held_node() });
            assert!(matches!(
                faces.idle_wait(10, &mut now, [], None),
                IdleWait::None
            ));
        }
        assert_eq!(clock_reads, 1, "only the waiting face read the clock");

        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::new(&runtime);
        faces.put_link(0, Link::Up(wire(&local, session(true, None), true, false)));
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
        let local = CoopLocalSet::new(&runtime);
        let group = LinkWait::input(WaitOn::Socket(9));
        for (owes, first) in [
            (false, LinkWait::input(WaitOn::Socket(3))),
            (true, LinkWait::input_or_room(WaitOn::Socket(3))),
        ] {
            let mut faces = supervisor(Link::Up(waited_wire(&local, WaitOn::Socket(3), owes)), 1);
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
        let local = CoopLocalSet::new(&runtime);
        let waited = |session: Session, on: WaitOn| -> TestLink {
            let task = local.spawn_local(async { DriverOutcome::Terminated });
            let link = CellRc::try_boxed(Waited { on, owes: false })
                .expect("the heap has room")
                .into_link();
            let (input_wait, room_wait) = (link.input_wait(), link.room_wait());
            Link::Up(Wire::new(session, task, link, input_wait, room_wait))
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
            id: 1,
            link: waited(empty, WaitOn::Socket(4)),
        };
        assert!(faces.place_face(1, empty).is_ok());
        let own = TestFace {
            id: 2,
            link: Link::Up(wire(&local, own, false, false)),
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
        let local = CoopLocalSet::new(&runtime);
        let first = LinkWait::input(WaitOn::Socket(3));
        let group = LinkWait::input(WaitOn::Socket(9));
        for (room, waited, ms) in [(2, vec![first, group], 10), (1, vec![first], 1)] {
            let link = Link::Up(waited_wire(&local, WaitOn::Socket(3), false));
            let mut faces: LinkSupervisor<Net, TestFace> =
                LinkSupervisor::new(Net, TestFace { id: 100, link }, 1, room)
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
        let local = CoopLocalSet::new(&runtime);
        let mut faces = supervisor(Link::Up(waited_wire(&local, WaitOn::Socket(3), true)), 3);
        let quiet = TestFace {
            id: 1,
            link: Link::Up(waited_wire(&local, WaitOn::Socket(4), false)),
        };
        assert!(faces.place_face(1, quiet).is_ok());
        let owing = TestFace {
            id: 2,
            link: Link::Up(waited_wire(&local, WaitOn::Socket(5), true)),
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
        let local = CoopLocalSet::new(&runtime);
        let past = OWING_WAITS.saturating_add(1);
        let mut faces = supervisor(Link::Up(waited_wire(&local, WaitOn::Socket(3), true)), past);
        for id in 1..past {
            let owing = TestFace {
                id: FaceId::try_from(id).unwrap_or(FaceId::MAX),
                link: Link::Up(waited_wire(&local, WaitOn::Socket(3 + id), true)),
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

    /// The looks at a port a test of `accept_at` makes, its port asked only when ready as
    /// `when_ready` says: one before any wait, three after a wait that found nothing ready, three
    /// after one whose stack cannot tell. How often the port was asked.
    fn asks_of_a_port(when_ready: bool) -> u32 {
        let asked = Rc::new(Cell::new(0));
        let mut faces: LinkSupervisor<Ports, TestFace> = LinkSupervisor::new(
            Ports(asked.clone(), when_ready),
            TestFace {
                id: 100,
                link: Link::Waiting { at_us: u64::MAX },
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
    #[test]
    fn a_port_its_read_has_no_room_to_wait_on_is_asked_at_every_look() {
        let asked = Rc::new(Cell::new(0));
        let mut faces: LinkSupervisor<Ports, TestFace> = LinkSupervisor::new(
            Ports(asked.clone(), true),
            TestFace {
                id: 100,
                link: Link::Waiting { at_us: u64::MAX },
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
        let mut faces = supervisor(Link::Waiting { at_us: 5_000 }, 1);
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
            faces.put_link(0, Link::Held { zid: held_node() });
            assert!(
                matches!(
                    faces.idle_wait(10, &mut || 0u64, [], Some(wake)),
                    IdleWait::None
                ),
                "the wake made a wait of its own"
            );
        }

        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::new(&runtime);
        let link = LinkWait::input(WaitOn::Socket(3));
        let mut faces = supervisor(Link::Up(waited_wire(&local, WaitOn::Socket(3), false)), 1);
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
        let local = CoopLocalSet::new(&runtime);
        let link = LinkWait::input(WaitOn::Socket(3));
        let mut faces = supervisor(Link::Up(waited_wire(&local, WaitOn::Socket(3), false)), 1);
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

    /// A read that waits on more than the open reserved room for is named in a test build.
    /// Turned red by a wait that grows the buffer after the open in silence.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "a read waited on more than the open reserved room for")]
    fn a_read_past_the_reserved_room_is_named_in_a_test_build() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::new(&runtime);
        let mut faces = supervisor(Link::Up(waited_wire(&local, WaitOn::Socket(3), false)), 1);
        let others = [
            LinkWait::input(WaitOn::Socket(4)),
            LinkWait::input(WaitOn::Socket(5)),
        ];
        let _ = faces.idle_wait(10, &mut || 0u64, others, None);
    }

    #[test]
    fn ending_lets_dials_go_first_then_tells_established_peers_and_keeps_the_dial_role() {
        let runtime = CoopRuntime::try_new(Still).expect("the heap has room");
        let local = CoopLocalSet::new(&runtime);
        let mut faces = supervisor(dialing(DialEndpoint::Listed(0), None, 1, 10), 3);
        faces.end_dials_and_ports();
        assert!(
            matches!(dial(&faces).link, Link::Waiting { at_us: u64::MAX }),
            "a dial under way is let go of"
        );
        let up = session(true, None);
        let up_ended = up.ended.clone();
        let opening = session(false, None);
        let opening_ended = opening.ended.clone();
        faces.put_link(0, Link::Up(wire(&local, up, false, false)));
        let other = TestFace {
            id: 1,
            link: Link::Opening {
                wire: wire(&local, opening, false, false),
                next: 0,
                deadline_us: 0,
            },
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
        assert!(matches!(
            dial(&faces).link,
            Link::Waiting { at_us: u64::MAX }
        ));
    }

    /// A table of many faces keeps the dial role's at the first place for good, puts a face at a
    /// free place only, and walks the held places alone, each with its place.
    ///
    /// # Control
    ///
    /// A `put` that took the dial role's place, or a `take` that gave it up, reds the first
    /// assertions; a walk that read the free places reds the `placed` list.
    #[test]
    fn a_table_of_many_faces_keeps_each_face_at_its_place() {
        let mut table = ManyFaces::with_dial(10_u32, 3);
        assert_eq!(table.places(), 3);
        assert_eq!(
            table.put(0, 11),
            Err(11),
            "the dial role's place is never put"
        );
        assert_eq!(table.take(0), None, "the dial role's face is never taken");
        assert_eq!(table.put(2, 12), Ok(()));
        assert_eq!(table.put(2, 13), Err(13), "a held place is not put again");
        assert_eq!(table.put(3, 14), Err(14), "past the table");
        assert_eq!(table.placed().collect::<Vec<_>>(), [(0, &10), (2, &12)]);
        assert_eq!(table.get(1), None, "a free place holds no face");
        assert_eq!(table.take(2), Some(12));
        assert_eq!(table.put(1, 15), Ok(()));
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
        assert_eq!(table.put(4, 14), Ok(()));
        assert_eq!(table.faces.len(), 5, "the walk reaches the face at place 4");
        assert_eq!(table.put(1, 11), Ok(()));
        assert_eq!(
            table.faces.len(),
            5,
            "a face before the last does not lengthen the walk"
        );
        assert_eq!(table.take(4), Some(14));
        assert_eq!(
            table.faces.len(),
            2,
            "the walk ends at the face at place 1 again"
        );
        assert_eq!(table.placed().collect::<Vec<_>>(), [(0, &10), (1, &11)]);
        assert_eq!(table.get(4), None, "a place past the walk holds no face");
        assert_eq!(table.take(4), None, "nor is one taken from it");
        assert_eq!(table.put(10, 20), Ok(()), "the last place is put");
        assert_eq!(table.put(11, 21), Err(21), "past the table");
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
        assert_eq!(table.put(1, 11), Err(11), "no face is put beside it");
        assert_eq!(table.take(0), None, "the dial role's face is never taken");
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
