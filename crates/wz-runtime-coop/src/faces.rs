// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The faces of a session as its driver holds them: each face's link and where it stands (up, in
//! its handshake, dialled, waiting to be dialled again, standing by), the dials under way, the
//! ports the session listens on, and the wait a read makes on all of them before it steps the
//! session.
//!
//! What a link means to the protocol (its handshake, what is declared over it, what its loss takes
//! with it) is the session's. A [`LinkSupervisor`] decides what has happened to a face's link
//! ([`Moved`]) and hands that back, and the session acts on it; it asks the session of a link only
//! what [`FaceSession`] names. So the driver owns the facts of the links (their tasks, their
//! waits, their buffers' leases) once, and the session owns what it declared over them once
//! (`docs/c-abi-architecture.md`, P1 and P2).
//!
//! Every table here is reserved when the supervisor is made, for as many faces, ports and waits as
//! the session's open admits, and none grows after: a face or a dial past the room is refused
//! (P3).

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::Deref;

use wz_session_core::driver_loop::DriverOutcome;
use wz_session_core::zid_hex::same_zid;

use crate::session_drive::{
    wait_any, AndRoom, LinkListener, LinkOpenError, LinkReadiness, LinkWritability, Locator,
    OpenedLink, PendingDial, RxLease, SessionDatagramLink, SessionLinks,
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
/// session's step reads it and as its owner's read is lent its buffer, and the waits its owner
/// makes for its input and its room. It reads as the session's half (`Deref`): what the session
/// sends over the link is that half's.
pub struct Wire<S> {
    session: S,
    task: CoopLocalJoinHandle<DriverOutcome>,
    link: Rc<dyn SessionDatagramLink>,
    ungated: Rc<dyn SessionDatagramLink>,
    readiness: Option<Arc<dyn LinkReadiness>>,
    writability: Option<Arc<dyn LinkWritability>>,
}

impl<S> Wire<S> {
    /// The link whose session half is `session`, run by `task`: `link` is what the session's
    /// step reads, behind whatever gates the session put on it, and `ungated` the same link
    /// without them, which lends its owner's read the receive buffer.
    pub fn new(
        session: S,
        task: CoopLocalJoinHandle<DriverOutcome>,
        link: Rc<dyn SessionDatagramLink>,
        ungated: Rc<dyn SessionDatagramLink>,
        readiness: Option<Arc<dyn LinkReadiness>>,
        writability: Option<Arc<dyn LinkWritability>>,
    ) -> Self {
        Self {
            session,
            task,
            link,
            ungated,
            readiness,
            writability,
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

    /// The wait for room on the link, when its stack gives one.
    pub fn writability(&self) -> Option<&Arc<dyn LinkWritability>> {
        self.writability.as_ref()
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
        /// The dial, asked at each move of the face ([`LinkSupervisor::advance`]).
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
        zid: Vec<u8>,
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
}

/// Which endpoint a dial reaches: one of the session's own list, by its place there, or one named
/// by whoever asked for the dial. A dial of the list carries no copy of its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialEndpoint {
    /// The endpoint at this place of the session's list.
    Listed(usize),
    /// An endpoint named apart from the list.
    Named(String),
}

impl DialEndpoint {
    /// The endpoint's text: `listed` is the session's list; a place past it reads empty.
    pub fn text<'a>(&'a self, listed: &'a [String]) -> &'a str {
        match self {
            DialEndpoint::Listed(at) => listed.get(*at).map_or("", String::as_str),
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
}

/// A port the session listens on, the wait for a connection on it, and the endpoint its links are
/// stated for, when the session states one.
struct Listening<P> {
    listener: Box<dyn LinkListener<P>>,
    readiness: Option<Arc<dyn LinkReadiness>>,
    endpoint: Option<String>,
}

/// What became of a face's link when it was moved on ([`LinkSupervisor::advance`]). The link stays
/// where it is, in its face: the session reads it there and replaces it when it acts.
pub enum Moved<P> {
    /// Nothing for the session to do.
    Stays,
    /// The link was up and its task ended.
    Lost,
    /// The link's handshake completed.
    Established,
    /// The link's task ended, or its deadline passed, before its handshake completed; `next` is
    /// the endpoint the dial role goes on to.
    HandshakeOver {
        /// The endpoint the dial role dials next.
        next: usize,
    },
    /// The face's dial was answered, or its deadline passed unanswered (`answer` `None`). The
    /// dial is let go of, with what it held for its link, and the face waits from now until the
    /// session gives it a link.
    DialOver {
        /// The network's answer.
        answer: Option<Result<OpenedLink<P>, LinkOpenError>>,
        /// The endpoint dialled.
        endpoint: DialEndpoint,
        /// The endpoint the dial role dials next.
        next: usize,
        /// When the dial, and the handshake after it, are given up.
        deadline_us: u64,
    },
    /// The face is to be dialled again now: its wait is over, or the node it stood by for is no
    /// other face's any more.
    Due,
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
    /// The next input of any of these links, or the next connection on any of these ports, for
    /// at most this many milliseconds.
    Input(Vec<Arc<dyn LinkReadiness>>, u32),
    /// The next input of the one link waited on, read into that link's own buffer by a read that
    /// waits in itself for at most this many milliseconds, as zenoh-pico's read task waits in its
    /// socket's `recv` (`vendor/zenoh-pico/src/transport/unicast/read.c` @
    /// `_z_unicast_client_read`).
    Read(FaceId, RxLease, u32),
    /// Nothing to wait on: the next dial, or the next look at a port that gives no wait, for at
    /// most this many milliseconds.
    Sleep(u32),
}

impl IdleWait {
    /// Wait, sleeping with `sleep` (milliseconds) where there is nothing to wait on. The wait
    /// keeps what it was made of, emptied, and what its read brought, for the session to hand
    /// back ([`LinkSupervisor::waited`]). Out of line: a session's open and each of its reads
    /// wait.
    #[inline(never)]
    pub fn wait(&mut self, sleep: impl FnOnce(u32)) {
        match self {
            IdleWait::None => {}
            IdleWait::Input(waits, ms) => {
                wait_any(waits, *ms);
                waits.clear();
            }
            IdleWait::Read(_, lease, ms) => lease.read(*ms),
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
    waits: Vec<Arc<dyn LinkReadiness>>,
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
    pub fn begin_dial(&self, to: Locator) -> Result<L::Dial, LinkOpenError> {
        self.links.begin_initiator(to)
    }

    /// Listen on `at`, whose links are stated for `endpoint` when the session states one.
    pub fn listen(&mut self, at: Locator, endpoint: Option<String>) -> Result<(), LinkOpenError> {
        let listener = self.links.open_listener(at)?;
        let readiness = listener.readiness().map(Arc::from);
        self.listeners.push(Listening {
            listener,
            readiness,
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
            Ok(Some(opened)) => {
                Accepted::Link(opened, listening.endpoint.clone().map(DialEndpoint::Named))
            }
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

    /// Move the link of the face at `at` on at `now_us`: what became of it. The link stays in its
    /// face whatever became of it, for the session to read and replace, but for a dial that is over,
    /// which is let go of here ([`Moved::DialOver`]).
    pub fn advance(&mut self, at: usize, now_us: u64) -> Moved<L::Pump> {
        let Some(face) = self.faces.get(at) else {
            return Moved::Stays;
        };
        let id = face.id();
        match face.link() {
            Link::Up(wire) if wire.finished() => Moved::Lost,
            Link::Opening { wire, .. } if wire.established() => Moved::Established,
            Link::Opening {
                wire,
                next,
                deadline_us,
            } if wire.finished() || now_us >= *deadline_us => Moved::HandshakeOver { next: *next },
            Link::Dialing { .. } => self.ask_dial(at, now_us),
            Link::Waiting { at_us } if now_us >= *at_us => Moved::Due,
            Link::Held { zid } if !self.node_is_held(zid, id) => Moved::Due,
            _ => Moved::Stays,
        }
    }

    /// Ask the dial of the face at `at` whether its link is made: [`Moved::Stays`] while it is
    /// still being made before its deadline, and once it is answered or its deadline has passed,
    /// the answer, with the dial let go of and the face waiting from `now_us`.
    fn ask_dial(&mut self, at: usize, now_us: u64) -> Moved<L::Pump> {
        let Some(face) = self.faces.get_mut(at) else {
            return Moved::Stays;
        };
        let link = face.link_mut();
        let Link::Dialing {
            dial,
            next,
            deadline_us,
        } = &mut *link
        else {
            return Moved::Stays;
        };
        let answer = dial.pending.poll();
        if answer.is_none() && now_us < *deadline_us {
            return Moved::Stays;
        }
        let (next, deadline_us) = (*next, *deadline_us);
        let endpoint = core::mem::replace(&mut dial.endpoint, DialEndpoint::Listed(0));
        // The dial is let go of now, with what it held for its link (a socket, the link's
        // buffers), before the face is dialled anew.
        *link = Link::Waiting { at_us: now_us };
        Moved::DialOver {
            answer,
            endpoint,
            next,
            deadline_us,
        }
    }

    /// The face at `at`, whose handshake completed ([`Moved::Established`]), holds its link up.
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

    /// What a read waits for, for at most `most` milliseconds: the input of every link that
    /// holds none already and gives a wait, a connection on every port that gives one, and
    /// `others` after them; no wait at all when a link holds input. A link that owes its stack the
    /// rest of a frame is waited on for room as well. A link that waits in its own loop, or a port
    /// that gives no wait, bounds the wait at a look; a dial under way or waiting bounds it at its
    /// next look. The one link waited on, alone, is read in place of the wait when `may_lend` says
    /// a buffer may be lent and the link lends one. `now_us` reads the clock, which only a face
    /// waiting to be dialled asks.
    pub fn idle_wait(
        &mut self,
        most: u32,
        now_us: &mut dyn FnMut() -> u64,
        may_lend: impl Fn() -> bool,
        others: impl IntoIterator<Item = Arc<dyn LinkReadiness>>,
    ) -> IdleWait {
        let mut holds = false;
        let mut waits = core::mem::take(&mut self.waits);
        let mut own_loop = false;
        let mut dial_left_ms = None;
        let mut read_face = None;
        for (at, face) in self.faces.iter().enumerate() {
            match face.link() {
                Link::Up(wire) | Link::Opening { wire, .. } => {
                    if wire.link.holds_input() {
                        holds = true;
                    } else if wire.link.waits_for_buffer() {
                        // Its input waits in the stack until another link gives a receive
                        // buffer back, which that link's own input wakes the read for.
                    } else if let Some(ready) = &wire.readiness {
                        if wire.link.owes_write() {
                            waits.push(AndRoom::of(ready.clone()));
                        } else {
                            waits.push(ready.clone());
                            read_face = Some(at);
                        }
                    } else {
                        own_loop = true;
                    }
                }
                Link::Waiting { at_us } => {
                    dial_left_ms = Some(at_us.saturating_sub(now_us()).saturating_div(1000));
                }
                // A dial under way gives no wait of its own here: it is asked again after a look.
                Link::Dialing { .. } => dial_left_ms = Some(DIAL_LOOK_MS),
                // Nothing to wait for until the face that holds the node is lost, which is
                // another face's link.
                Link::Held { .. } => {}
            }
        }
        if holds {
            waits.clear();
            self.waits = waits;
            return IdleWait::None;
        }
        let mut look_again = false;
        for listening in &self.listeners {
            match &listening.readiness {
                Some(ready) => waits.push(ready.clone()),
                None => look_again = true,
            }
        }
        waits.extend(others);
        let most = match dial_left_ms {
            Some(left) => u32::try_from(left).map_or(most, |left| left.min(most)),
            None => most,
        };
        let wait = match (waits.is_empty(), look_again) {
            // A port that gives no wait is looked at again after a bounded sleep.
            (true, true) if most > 0 => IdleWait::Sleep(most.min(1)),
            (true, _) => match dial_left_ms {
                Some(_) if most > 0 => IdleWait::Sleep(most),
                _ => IdleWait::None,
            },
            (false, _) if most > 0 => {
                let lent = match (read_face, waits.len(), own_loop || look_again) {
                    (Some(at), 1, false) if may_lend() => self.lend_rx_at(at),
                    _ => None,
                };
                let most = if own_loop || look_again {
                    most.min(1)
                } else {
                    most
                };
                match lent {
                    Some((face, lease)) => IdleWait::Read(face, lease, most),
                    None => IdleWait::Input(core::mem::take(&mut waits), most),
                }
            }
            _ => IdleWait::None,
        };
        // A wait that took no buffer leaves it here.
        waits.clear();
        self.waits = waits;
        wait
    }

    /// The lease of the receive buffer of the link of the face at `at`, for a read's wait to be
    /// made in the read of that link, with the face's number; `None` from a link that gives none.
    fn lend_rx_at(&self, at: usize) -> Option<(FaceId, RxLease)> {
        let held = self.faces.get(at)?;
        let lease = held.link().wire()?.ungated.lend_rx()?;
        Some((held.id(), lease))
    }

    /// Take back a read's wait, once made ([`IdleWait::wait`]): the buffer of its waits, which
    /// the wait took whole ([`Self::idle_wait`]), the larger of it and the one held kept, and the
    /// lease its read was made in, landed on
    /// the link of the face that lent it. A lease whose face has gone, or holds another link by
    /// now, is let go of.
    pub fn waited(&mut self, wait: IdleWait) {
        match wait {
            // A wait made of more than the buffer (the program's clock word beside it) leaves the
            // larger of the two here.
            IdleWait::Input(spare, _) => {
                if spare.capacity() > self.waits.capacity() {
                    self.waits = spare;
                }
            }
            IdleWait::Read(face, lease, _) => {
                if let Some(wire) = self
                    .faces
                    .iter()
                    .find(|held| held.id() == face)
                    .and_then(|held| held.link().wire())
                {
                    wire.ungated.land_rx(lease);
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
    use core::cell::Cell;
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
        let link: Rc<dyn SessionDatagramLink> = Rc::new(Quiet { holds });
        Wire::new(session, task, link.clone(), link, None, None)
    }

    fn supervisor(link: TestLink, faces: usize) -> LinkSupervisor<Net, TestFace> {
        LinkSupervisor::new(Net, TestFace { id: 100, link }, faces, 2)
    }

    #[test]
    fn a_waiting_face_stays_until_its_time_and_is_then_due() {
        let mut faces = supervisor(Link::Waiting { at_us: 100 }, 1);
        assert!(matches!(faces.advance(0, 99), Moved::Stays));
        assert!(
            matches!(faces.faces()[0].link, Link::Waiting { at_us: 100 }),
            "the link stays as it was"
        );
        assert!(matches!(faces.advance(0, 100), Moved::Due));
        assert!(
            matches!(faces.advance(1, 100), Moved::Stays),
            "no face there"
        );
    }

    #[test]
    fn a_dial_is_asked_until_its_deadline_and_then_let_go_of_with_its_endpoint() {
        let mut faces = supervisor(dialing(DialEndpoint::Listed(1), None, 2, 10), 1);
        assert!(
            matches!(faces.advance(0, 5), Moved::Stays),
            "not answered yet"
        );
        assert!(matches!(faces.faces()[0].link, Link::Dialing { .. }));
        assert!(matches!(
            faces.advance(0, 10),
            Moved::DialOver {
                answer: None,
                endpoint: DialEndpoint::Listed(1),
                next: 2,
                deadline_us: 10,
            }
        ));
        assert!(
            matches!(faces.faces()[0].link, Link::Waiting { at_us: 10 }),
            "the dial was let go of"
        );
    }

    #[test]
    fn a_refused_dial_is_answered_at_once_whatever_its_deadline() {
        let named = DialEndpoint::Named(String::from("tcp/[::1]:7447"));
        let refused = Some(Err(LinkOpenError::Refused));
        let mut faces = supervisor(dialing(named, refused, 1, 1_000), 1);
        match faces.advance(0, 0) {
            Moved::DialOver {
                answer: Some(Err(LinkOpenError::Refused)),
                endpoint,
                ..
            } => assert_eq!(endpoint.text(&[]), "tcp/[::1]:7447"),
            _ => panic!("the refusal is the answer"),
        }
    }

    #[test]
    fn a_link_is_lost_established_or_over_as_its_task_and_handshake_say() {
        let runtime = CoopRuntime::new(Still);
        let local = CoopLocalSet::new(&runtime);
        let mut faces = supervisor(Link::Up(wire(&local, session(true, None), false, false)), 1);
        assert!(matches!(faces.advance(0, 0), Moved::Stays), "running");
        faces.put_link(0, Link::Up(wire(&local, session(true, None), false, true)));
        assert!(matches!(faces.advance(0, 0), Moved::Lost));
        assert!(
            matches!(faces.faces()[0].link, Link::Up(_)),
            "a lost link stays for the session to read"
        );
        let opening = |established, finished| Link::Opening {
            wire: wire(&local, session(established, None), false, finished),
            next: 3,
            deadline_us: 50,
        };
        faces.put_link(0, opening(true, false));
        assert!(matches!(faces.advance(0, 0), Moved::Established));
        faces.establish(0);
        assert!(matches!(faces.faces()[0].link, Link::Up(_)), "brought up");
        faces.put_link(0, opening(false, false));
        assert!(
            matches!(faces.advance(0, 49), Moved::Stays),
            "before its deadline"
        );
        assert!(matches!(
            faces.advance(0, 50),
            Moved::HandshakeOver { next: 3 }
        ));
        faces.put_link(0, opening(false, true));
        assert!(matches!(
            faces.advance(0, 0),
            Moved::HandshakeOver { next: 3 }
        ));
    }

    #[test]
    fn a_face_stands_by_while_another_holds_its_node() {
        let runtime = CoopRuntime::new(Still);
        let local = CoopLocalSet::new(&runtime);
        let node = [7u8, 1];
        let mut faces = supervisor(Link::Held { zid: node.to_vec() }, 2);
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
        assert!(matches!(faces.advance(0, 0), Moved::Stays));
        assert!(faces.remove_face(1).is_some());
        assert!(matches!(faces.advance(0, 0), Moved::Due));
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

    #[test]
    fn an_endpoint_reads_from_the_list_or_its_own_text() {
        let listed = [String::from("udp/10.0.0.1:7447")];
        assert_eq!(DialEndpoint::Listed(0).text(&listed), "udp/10.0.0.1:7447");
        assert_eq!(DialEndpoint::Listed(1).text(&listed), "", "past the list");
        assert_eq!(
            DialEndpoint::Named(String::from("tcp/1.2.3.4:1")).text(&listed),
            "tcp/1.2.3.4:1"
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
            faces.idle_wait(10, &mut now, || true, []),
            IdleWait::Sleep(4)
        ));
        faces.put_link(0, dialing(DialEndpoint::Listed(0), None, 0, 0));
        assert!(matches!(
            faces.idle_wait(10, &mut now, || true, []),
            IdleWait::Sleep(1)
        ));
        faces.put_link(0, Link::Held { zid: Vec::new() });
        assert!(matches!(
            faces.idle_wait(10, &mut now, || true, []),
            IdleWait::None
        ));
        assert_eq!(clock_reads, 1, "only the waiting face read the clock");

        let runtime = CoopRuntime::new(Still);
        let local = CoopLocalSet::new(&runtime);
        faces.put_link(0, Link::Up(wire(&local, session(true, None), true, false)));
        assert!(faces.holds_input());
        assert!(matches!(
            faces.idle_wait(10, &mut || 0u64, || true, []),
            IdleWait::None
        ));
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
