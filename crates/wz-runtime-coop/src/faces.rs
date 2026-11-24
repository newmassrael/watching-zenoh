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

use wz_session_core::bounded::{BoundedVec, Lent};
use wz_session_core::caps;
use wz_session_core::driver_loop::DriverOutcome;
use wz_session_core::locator_directory::LocatorText;
use wz_session_core::session_zid::SessionZid;
use wz_session_core::zid_hex::same_zid;

use crate::face_life::Phase;
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

    /// The node the link reaches, as far as the link knows it; `None` before it is told.
    fn node(&self) -> Option<Vec<u8>>;

    /// The link ends: an established peer is told so.
    fn end(&self);
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
    /// the node.
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
                dial,
                next,
                deadline_us,
            } => Phase::Dialing {
                endpoint: dial.endpoint().clone(),
                next: *next,
                deadline_us: *deadline_us,
            },
            Link::Waiting { at_us } => Phase::Waiting { at_us: *at_us },
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
        let row = LocatorText::try_from(text)
            .map_err(|_| EndpointTextRefused::TooLong { len: text.len() })?;
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

/// A port the session listens on, the wait for a connection on it, and the row of the endpoint
/// its links are stated for, when the session states one.
struct Listening<P> {
    listener: Box<dyn LinkListener<P>>,
    input: Option<WaitOn>,
    endpoint: Option<usize>,
}

/// What a link taken off a port came to ([`LinkSupervisor::accept_at`]).
pub enum Accepted<P> {
    /// A connection, with the endpoint its port is stated for.
    Link(OpenedLink<P>, Option<DialEndpoint>),
    /// No connection waits on the port now, or the stack had nothing left to take one with.
    Idle,
    /// The port is broken for good, and let go of.
    Broken,
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
}

impl IdleWait {
    /// Wait on the links and ports with `waits`, the waits of their stack
    /// ([`SessionLinks::waits`]), sleeping with `sleep` (milliseconds) where there is nothing to
    /// wait on. The wait keeps what it was made of, emptied, for the session to hand back
    /// ([`LinkSupervisor::waited`]). Out of line: a session's open and each of its reads wait.
    #[inline(never)]
    pub fn wait(&mut self, waits: &impl LinkWaits, sleep: impl FnOnce(u32)) {
        match self {
            IdleWait::None => {}
            IdleWait::Input { on, ms } => {
                waits.wait(on, *ms);
                on.clear();
            }
            IdleWait::Sleep(ms) => sleep(*ms),
        }
    }
}

/// A session's faces, dials and ports over the network `L`, each face kept as the session's
/// record `F`. The first face is the dial role's, which is never removed.
pub struct LinkSupervisor<L: SessionLinks, F> {
    links: L,
    /// The faces, reserved for as many as the session admits: its capacity is the room, and a
    /// face past it is refused, never grown into.
    faces: Vec<F>,
    listeners: Vec<Listening<L::Pump>>,
    waits: Vec<LinkWait>,
    next_face: FaceId,
}

impl<L: SessionLinks, F: FaceRecord<Pump = L::Pump, Dial = L::Dial>> LinkSupervisor<L, F> {
    /// The faces of a session over `links`, `dial` the dial role's: room for `faces` faces in
    /// all (one at least, the dial role's), each with a dial under way at most, and `waits` waits
    /// a read makes at once, reserved now. The ports are the open's, taken as it listens
    /// ([`Self::listen`]). Faces taken after are numbered from 1.
    pub fn new(links: L, dial: F, faces: usize, waits: usize) -> Self {
        let mut table = Vec::with_capacity(faces.max(1));
        table.push(dial);
        Self {
            links,
            faces: table,
            listeners: Vec::new(),
            waits: Vec::with_capacity(waits),
            next_face: 1,
        }
    }

    /// The network the links are opened on.
    pub fn links(&self) -> &L {
        &self.links
    }

    /// The faces, the dial role's first.
    pub fn faces(&self) -> &[F] {
        &self.faces
    }

    /// The faces, to change what the session keeps of each.
    pub fn faces_mut(&mut self) -> &mut [F] {
        &mut self.faces
    }

    /// The number the next face taken is known by.
    pub fn next_face_id(&self) -> FaceId {
        self.next_face
    }

    /// The number [`Self::next_face_id`] answered is taken.
    pub fn advance_face_id(&mut self) {
        self.next_face = self.next_face.saturating_add(1);
    }

    /// Add `face`, or hand it back when every face the table was reserved for is taken.
    pub fn push_face(&mut self, face: F) -> Result<(), F> {
        if self.faces.len() >= self.faces.capacity() {
            return Err(face);
        }
        self.faces.push(face);
        Ok(())
    }

    /// Take the face at `at` out of the table; the dial role's, the first, is never taken.
    pub fn remove_face(&mut self, at: usize) -> Option<F> {
        (at > 0 && at < self.faces.len()).then(|| self.faces.remove(at))
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
        let input = listener.input_wait();
        self.listeners.push(Listening {
            listener,
            input,
            endpoint,
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
        let listening = self.listeners.get(at)?;
        Some(match listening.listener.accept() {
            Ok(Some(opened)) => Accepted::Link(opened, listening.endpoint.map(DialEndpoint::Port)),
            Ok(None) | Err(LinkOpenError::Exhausted) => Accepted::Idle,
            Err(_) => {
                self.listeners.remove(at);
                Accepted::Broken
            }
        })
    }

    /// Give the face at `at` the link `link`, in place of the one it holds, which is let go of.
    pub fn put_link(&mut self, at: usize, link: Link<F::Session, L::Dial>) {
        if let Some(face) = self.faces.get_mut(at) {
            *face.link_mut() = link;
        }
    }

    /// The face at `at`, whose handshake completed, holds its link up.
    pub fn establish(&mut self, at: usize) {
        let Some(face) = self.faces.get_mut(at) else {
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
        self.faces.iter().any(|face| {
            face.id() != id
                && face
                    .link()
                    .wire()
                    .and_then(|wire| wire.node())
                    .is_some_and(|node| same_zid(&node, zid))
        })
    }

    /// Whether a face's link holds input it has already taken from its stack.
    pub fn holds_input(&self) -> bool {
        self.faces
            .iter()
            .any(|face| face.link().wire().is_some_and(Wire::holds_input))
    }

    /// Have every face's link write what it owes its stack, as far as the stack takes it now, so
    /// a link whose stack has room by now gives back the outbound slot its frame held.
    #[cfg(feature = "session-unicast-accept")]
    pub fn write_owed_now(&self) {
        for wire in self.faces.iter().filter_map(|face| face.link().wire()) {
            wire.link.write_owed_now();
        }
    }

    /// What a publish that waits for an outbound slot waits on: each face's link that owes its
    /// stack the rest of a frame, for its room and its input. A link whose stack gives no wait is
    /// not in it.
    #[cfg(feature = "session-unicast-accept")]
    pub fn owing_waits(&self) -> Vec<LinkWait> {
        self.faces
            .iter()
            .filter_map(|face| face.link().wire())
            .filter(|wire| wire.owes_write())
            .filter_map(|wire| wire.input)
            .map(LinkWait::input_or_room)
            .collect()
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
    /// only a face with such a time asks, once.
    pub fn idle_wait(
        &mut self,
        most: u32,
        now_us: &mut dyn FnMut() -> u64,
        others: impl IntoIterator<Item = LinkWait>,
        beside: Option<LinkWait>,
    ) -> IdleWait {
        let mut holds = false;
        let mut waits = core::mem::take(&mut self.waits);
        let mut own_loop = false;
        let mut dial_left_ms: Option<u64> = None;
        let mut now = None;
        let mut read_now = || *now.get_or_insert_with(&mut *now_us);
        for face in &self.faces {
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
                        if wire.link.owes_write() {
                            waits.push(LinkWait::input_or_room(on));
                        } else {
                            waits.push(LinkWait::input(on));
                        }
                    } else {
                        own_loop = true;
                    }
                }
                // A face waiting, dialling or standing by brings no input of its own: its time,
                // read above, is what wakes the read for it.
                Link::Waiting { .. } | Link::Dialing { .. } | Link::Held { .. } => {}
            }
        }
        if holds {
            waits.clear();
            self.waits = waits;
            return IdleWait::None;
        }
        let mut look_again = false;
        for listening in &self.listeners {
            match listening.input {
                Some(on) => waits.push(LinkWait::input(on)),
                None => look_again = true,
            }
        }
        waits.extend(others);
        let most = match dial_left_ms {
            Some(left) => u32::try_from(left).map_or(most, |left| left.min(most)),
            None => most,
        };
        // A sleep a wake beside it ends is a wait on the wake.
        let sleep = |ms: u32, waits: &mut Vec<LinkWait>| match beside {
            Some(on) => {
                waits.push(on);
                IdleWait::Input {
                    on: core::mem::take(waits),
                    ms,
                }
            }
            None => IdleWait::Sleep(ms),
        };
        let wait = match (waits.is_empty(), look_again) {
            // A port that gives no wait is looked at again after a bounded sleep.
            (true, true) if most > 0 => sleep(most.min(1), &mut waits),
            (true, _) => match dial_left_ms {
                Some(_) if most > 0 => sleep(most, &mut waits),
                _ => IdleWait::None,
            },
            (false, _) if most > 0 => {
                waits.extend(beside);
                let most = if own_loop || look_again {
                    most.min(1)
                } else {
                    most
                };
                IdleWait::Input {
                    on: core::mem::take(&mut waits),
                    ms: most,
                }
            }
            _ => IdleWait::None,
        };
        // A wait that took no buffer leaves it here.
        waits.clear();
        self.waits = waits;
        wait
    }

    /// Take back a read's wait, once made ([`IdleWait::wait`]): the buffer of its waits, which
    /// the wait took whole ([`Self::idle_wait`]), the larger of it and the one held kept. Out of
    /// line: the open's steps and each read hand their wait back.
    #[inline(never)]
    pub fn waited(&mut self, wait: IdleWait) {
        match wait {
            // The larger of the two buffers stays here.
            IdleWait::Input { on: spare, .. } => {
                if spare.capacity() > self.waits.capacity() {
                    self.waits = spare;
                }
            }
            IdleWait::None | IdleWait::Sleep(_) => {}
        }
    }

    /// Let go of every dial under way, whose connection is then not made, and of every port.
    pub fn end_dials_and_ports(&mut self) {
        for face in &mut self.faces {
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
        for face in &mut self.faces {
            each(face);
            let link = core::mem::replace(face.link_mut(), Link::Waiting { at_us: u64::MAX });
            if let Link::Up(wire) | Link::Opening { wire, .. } = link {
                if wire.established() {
                    wire.end();
                }
                wire.abort();
            }
        }
        self.faces.truncate(1);
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

    /// A session's half of a link: whether it is established, the node it reached, and how often
    /// it was ended.
    struct Session {
        established: bool,
        node: Option<Vec<u8>>,
        ended: Rc<Cell<u32>>,
    }

    impl FaceSession for Session {
        fn established(&self) -> bool {
            self.established
        }

        fn node(&self) -> Option<Vec<u8>> {
            self.node.clone()
        }

        fn end(&self) {
            self.ended.set(self.ended.get() + 1);
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
            node: node.map(<[u8]>::to_vec),
            ended: Rc::new(Cell::new(0)),
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
        let link = CellRc::boxed(Quiet { holds }).into_link();
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
        let link = CellRc::boxed(Waited { on, owes }).into_link();
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
        let runtime = CoopRuntime::new(Still);
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
        assert!(matches!(faces.faces()[0].link, Link::Up(_)), "brought up");
        faces.establish(0);
        assert!(matches!(faces.faces()[0].link, Link::Up(_)), "and stays up");
    }

    /// Another face holds a node while its link to it is up, and a face never holds one for
    /// itself; once that face goes, no face holds the node.
    #[test]
    fn a_node_is_held_by_another_face_while_its_link_is_up() {
        let runtime = CoopRuntime::new(Still);
        let local = CoopLocalSet::new(&runtime);
        let node = [7u8, 1];
        let mut faces = supervisor(Link::Held { zid: held_node() }, 2);
        let other = TestFace {
            id: 1,
            link: Link::Up(wire(&local, session(true, Some(&node)), false, false)),
        };
        assert!(faces.push_face(other).is_ok());
        assert!(faces.node_is_held(&node, 100));
        assert!(
            !faces.node_is_held(&node, 1),
            "a face does not hold the node for itself"
        );
        assert!(faces.remove_face(1).is_some());
        assert!(!faces.node_is_held(&node, 100));
    }

    /// The node a face that stands by holds in these tests.
    fn held_node() -> SessionZid {
        SessionZid::new(&[7, 1]).expect("a zid")
    }

    #[test]
    fn the_table_takes_no_face_past_its_room_and_never_gives_up_the_dial_role() {
        let mut faces = supervisor(Link::Waiting { at_us: 0 }, 2);
        let face = |id| TestFace {
            id,
            link: Link::Waiting { at_us: 0 },
        };
        assert!(faces.push_face(face(1)).is_ok());
        assert!(matches!(
            faces.push_face(face(2)),
            Err(TestFace { id: 2, .. })
        ));
        assert!(faces.remove_face(0).is_none(), "the dial role's face stays");
        assert!(faces.remove_face(2).is_none(), "past the table");
        assert_eq!(faces.remove_face(1).map(|face| face.id), Some(1));
        assert_eq!(faces.next_face_id(), 1);
        faces.advance_face_id();
        assert_eq!(faces.next_face_id(), 2);
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
        faces.put_link(0, Link::Held { zid: held_node() });
        assert!(matches!(
            faces.idle_wait(10, &mut now, [], None),
            IdleWait::None
        ));
        assert_eq!(clock_reads, 1, "only the waiting face read the clock");

        let runtime = CoopRuntime::new(Still);
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
        let runtime = CoopRuntime::new(Still);
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

    /// A wait on links is the stack's for the whole time, and leaves its buffer emptied.
    /// Turned red by a wait that bounds the links' wait short of its time.
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
        assert!(matches!(wait, IdleWait::Input { ref on, .. } if on.is_empty()));
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
        faces.put_link(0, Link::Held { zid: held_node() });
        assert!(
            matches!(
                faces.idle_wait(10, &mut || 0u64, [], Some(wake)),
                IdleWait::None
            ),
            "the wake made a wait of its own"
        );

        let runtime = CoopRuntime::new(Still);
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

    #[test]
    fn ending_lets_dials_go_first_then_tells_established_peers_and_keeps_the_dial_role() {
        let runtime = CoopRuntime::new(Still);
        let local = CoopLocalSet::new(&runtime);
        let mut faces = supervisor(dialing(DialEndpoint::Listed(0), None, 1, 10), 3);
        faces.end_dials_and_ports();
        assert!(
            matches!(faces.faces()[0].link, Link::Waiting { at_us: u64::MAX }),
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
        assert!(faces.push_face(other).is_ok());
        let mut shown = 0;
        faces.end_faces(|_| shown += 1);
        assert_eq!(shown, 2);
        assert_eq!(up_ended.get(), 1, "an established peer is told");
        assert_eq!(opening_ended.get(), 0, "a handshake under way is not");
        assert_eq!(faces.faces().len(), 1);
        assert!(matches!(
            faces.faces()[0].link,
            Link::Waiting { at_us: u64::MAX }
        ));
    }
}
