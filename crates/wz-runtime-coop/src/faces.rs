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
#[cfg(feature = "resource-snapshot")]
use wz_session_core::resource_snapshot::{BuildMessageReading, BuildReceiveLedger};
use wz_session_core::session_zid::SessionZid;
use wz_session_core::zid_hex::same_zid;

use crate::link_cells::{CellRc, CountKind, OneTask};
use crate::session_drive::{
    LinkOpenError, LinkWait, LinkWaits, Locator, OpenedLink, PendingDial, SessionDatagramLink,
    SessionLinks, WaitOn,
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

    /// `resource-snapshot` — what the link's receive path has counted: its transport messages and
    /// how they were spaced, cumulative. Required, so no session of a link is left out of the
    /// session's reading by a provided zero.
    #[cfg(feature = "resource-snapshot")]
    fn message_reading(&self) -> BuildMessageReading;
}

/// `resource-snapshot` — what the session of the link `link` holds has counted, while it holds
/// one: a link counts from the moment it is put in, its handshake included, until it is let go of.
#[cfg(feature = "resource-snapshot")]
fn counted<S: FaceSession, D, E, N: CountKind>(
    link: &Link<S, D, E, N>,
) -> Option<BuildMessageReading> {
    link.wire().map(|wire| wire.session.message_reading())
}

/// One face as the session keeps it: the face's number and its link, beside whatever else the
/// session keeps of the face. The supervisor reads and replaces the link alone.
pub trait FaceRecord<N: CountKind = OneTask> {
    /// The session's half of the face's link.
    type Session: FaceSession;

    /// What the drive loop pumps for the face's link, which a dial under way makes.
    type Pump;

    /// A dial under way of the face's link ([`SessionLinks::Dial`]).
    type Dial: PendingDial<Self::Pump, N>;

    /// The face's number.
    fn id(&self) -> FaceId;

    /// How the session of the face's link ends ([`LinkEnd`]): a task's handle, or the end of a
    /// link whose session the owner steps itself.
    type End: LinkEnd;

    /// The face's link.
    fn link(&self) -> &Link<Self::Session, Self::Dial, Self::End, N>;

    /// The face's link, to replace.
    fn link_mut(&mut self) -> &mut Link<Self::Session, Self::Dial, Self::End, N>;

    /// The life of the face's link: where it stands, the one state of it the session keeps.
    fn life(&self) -> &UnicastLink;

    /// The life of the face's link, to give an input.
    fn life_mut(&mut self) -> &mut UnicastLink;

    /// The face's link while it is established: what the session's sends go through.
    fn up(&self) -> Option<&Wire<Self::Session, Self::End, N>> {
        if self.life().phase() == LinkPhase::Up {
            self.link().wire()
        } else {
            None
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

/// What a face holds for its link: nothing, a dial under way, or the link a dial made or a port
/// gave. Where the link stands (dialled, in its handshake, up, waiting, standing by) is the face's
/// life's alone ([`FaceRecord::life`]); this is the I/O that life asks for. A dial under way is
/// held in its face's link, so a face has one dial at most and the faces' table is the dials'
/// table too.
pub enum Link<S, D, E = TaskEnd, N: CountKind = OneTask> {
    /// No link: not dialled yet, between two dials, waiting to dial again, or standing by.
    Idle,
    /// A dial under way, asked at each move of the face ([`Dial::answer`]).
    Dialing(Dial<D>),
    /// A link in its handshake or established: the session's sends go through it once it is up.
    Wire(Wire<S, E, N>),
}

impl<S, D, E, N: CountKind> Link<S, D, E, N> {
    /// The link's wire while it is in its handshake or up.
    pub fn wire(&self) -> Option<&Wire<S, E, N>> {
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
    faces: Vec<FacePlace<F>>,
    places: usize,
}

/// A place of [`ManyFaces`]: a face or none, in storage the face is built in where it lies, so
/// a face whose largest part is built in place ([`VacantPlace::fill`]) is moved by nothing.
struct FacePlace<F> {
    held: bool,
    face: MaybeUninit<F>,
}

impl<F> FacePlace<F> {
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

impl<F> Drop for FacePlace<F> {
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
        faces.push(FacePlace::holding(dial));
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
        self.faces.iter().filter_map(FacePlace::get)
    }

    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut F>
    where
        F: 'a,
    {
        self.faces.iter_mut().filter_map(FacePlace::get_mut)
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
                .resize_with(at.saturating_add(1), FacePlace::free);
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
        #[cfg(feature = "resource-snapshot")]
        if let Some(gone) = gone.filter(|_| freed) {
            self.receive_ledger.retire(&gone);
        }
        freed.then_some(id)
    }

    /// Begin a dial of `to`, which the network answers later.
    /// Out of line: the stack's dial of each protocol is put together here, not in its caller.
    #[inline(never)]
    pub fn begin_dial(&self, to: Locator) -> Result<L::Dial, LinkOpenError> {
        self.links.begin_initiator(to)
    }

    /// The addresses the network resolves `host` to, each at `port`, written to the front of
    /// `found`: how many (`SessionLinks::resolve`).
    pub fn resolve(&self, host: &str, port: u16, found: &mut [core::net::SocketAddr]) -> usize {
        self.links.resolve(host, port, found)
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
    pub fn put_link(&mut self, at: usize, link: Link<F::Session, L::Dial, F::End, N>) {
        self.regenerated();
        self.moved();
        if let Some(face) = self.faces.get_mut(at) {
            #[cfg(feature = "resource-snapshot")]
            if let Some(gone) = counted(face.link()) {
                self.receive_ledger.retire(&gone);
            }
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
            .any(|face| face.link().wire().is_some_and(Wire::holds_input))
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
                Link::Wire(wire) => {
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
                if let Some(port) = wire.input {
                    wire.session
                        .input_seen(on.iter().any(|ready| ready.on == port));
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
            if wire.input.is_some() {
                wire.session.input_seen(true);
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
        self.moved();
        for face in self.faces.iter_mut() {
            each(face);
            // A close asks to let go of the dial or the link, which is what follows here for
            // every face alike, so its effects are not read; it reads no time.
            let _ = face.life_mut().input(LinkInput::Close, 0);
            let link = core::mem::replace(face.link_mut(), Link::Idle);
            if let Link::Wire(wire) = link {
                #[cfg(feature = "resource-snapshot")]
                self.receive_ledger.retire(&wire.session.message_reading());
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

    type TestLink = Link<Session, Answer>;

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
        type Session = Session;
        type Pump = Rc<Quiet>;
        type Dial = Answer;
        type End = TaskEnd;

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
        faces.put_link(0, dialing(DialEndpoint::Listed(0), None));
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
