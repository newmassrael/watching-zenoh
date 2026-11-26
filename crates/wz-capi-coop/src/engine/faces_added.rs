// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The faces a session adds beside the dial role's, a link taken off a port or one it dials
//! besides: a build that listens (`listen`), whose faces' peers share the session's pools. A
//! session that only dials holds its dial role's face alone, and its text has none of this.

use super::*;
use wz_runtime_coop::faces::Dial;
// The work form's engine names these for every build; a read that steps each face where it lies
// names them here.
#[cfg(not(wz_round))]
use wz_session_core::link_life::{LinkInput, LinkPhase};
use wz_session_core::locator_directory::LocatorText;

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> Core<L, C> {
    /// Give a link taken off a port a face, and run its session as the acceptor. A link that
    /// arrives when the session holds as many faces as `max_faces`, or has as many handshakes
    /// under way as `accept_pending`, is closed unread: its peer learns the node is full from the
    /// close, where one left queued would wait for a handshake that never starts.
    #[cfg(wz_round)]
    pub(super) fn accept_face(
        &mut self,
        opened: OpenedLink<L::Pump, LinkCount>,
        endpoint: Option<DialEndpoint>,
    ) {
        if !self.takes_a_face() {
            return;
        }
        let id = self.transport.links.next_face_id();
        // The tables first: the link's task dispatches to them from its first step. A link past
        // the sets the open lent is closed unread, as one past `max_faces` is.
        let Ok(held) = self.session.registry.add_face(id) else {
            return;
        };
        let Ok(wire) = self.open_wire(id, opened, SessionRole::Acceptor, endpoint.as_ref()) else {
            self.session.registry.remove_face(held);
            return;
        };
        self.transport.links.advance_face_id();
        // The handshake is given up at the acceptor's whole-handshake bound (`link_times`); the
        // session's own timer in the state machine is the same bound and ends the task, so
        // whichever is first removes the face.
        let at = held.at();
        if self.push_face(held, Link::Wire(wire), 0) {
            let now_us = self.clock.now_us();
            if let Some(face) = self.transport.links.face_mut(at) {
                // A taken link's handshake asks for nothing of the session.
                let _ = face.life.input(LinkInput::Taken, now_us);
            }
        }
    }

    /// Give a link taken off a port a face of its own whose link the read that took it makes in
    /// the face's place itself (`CoopEngine::accept_links`): the face's tables and its record,
    /// with no link yet, at a free row of the face table, whose place is handed back. `None`, the
    /// link closed unread as a build whose links are tasks closes it, when the session holds as
    /// many faces as `max_faces` admits, as many handshakes as `accept_pending`, or no set of
    /// tables or place left.
    #[cfg(not(wz_round))]
    pub(super) fn take_face(&mut self) -> Option<usize> {
        if !self.takes_a_face() {
            return None;
        }
        let id = self.transport.links.next_face_id();
        let held = self.session.registry.add_face(id).ok()?;
        self.transport.links.advance_face_id();
        let at = held.at();
        self.push_face(held, Link::Idle, 0).then_some(at)
    }

    /// Whether a link taken off a port may take a face now: fewer handshakes of taken links under
    /// way than `accept_pending`, and room for a face beside the dial role's (`Self::faces_full`).
    fn takes_a_face(&mut self) -> bool {
        let pending = self
            .transport
            .links
            .faces()
            .filter(|face| {
                face.id != DIAL_FACE && matches!(face.life.phase(), LinkPhase::Handshaking { .. })
            })
            .count();
        pending < self.config.accept_pending && !self.faces_full()
    }

    /// Whether the table holds as many faces as `max_faces` admits beside the dial role's, a place
    /// kept for a departed face's tomb counted among them. Such a place is given up first: a face
    /// that comes outweighs a departure owed to a listener's replay (`told`).
    fn faces_full(&mut self) -> bool {
        #[cfg(feature = "connectivity")]
        if self.transport.links.held() > self.config.max_faces {
            self.give_up_a_departure();
        }
        self.transport.links.held() > self.config.max_faces
    }

    /// Add a face whose link is `link` at the place its tables were lent at (`held`): a dial
    /// under way or a handshake. It is told the session's declarations at the session's pace, as
    /// every face is. Its life is one taken beside the dial role's, over `endpoints` endpoints of
    /// its own, not opened yet. A place the table has no room at, which the callers refuse before
    /// they make the face, lets the face go with its tables: whether the face was placed.
    fn push_face(
        &mut self,
        held: HeldFace,
        link: Link<FaceLink<C, L>, L::Dial>,
        endpoints: usize,
    ) -> bool {
        let times = self.link_times();
        let Some(place) = self.transport.links.vacant_place(held.at()) else {
            if let Some(wire) = link.wire() {
                wire.abort();
            }
            self.session.registry.remove_face(held);
            return false;
        };
        // The face is built in its place, its life where it lies (`Face::make_in`), which lends
        // the place it was given, so the table holds it.
        let placed = place
            .fill(|place| Face::make_in(place, held.id(), link, times, LinkRole::Taken, endpoints))
            .is_some();
        if !placed {
            self.session.registry.remove_face(held);
        }
        placed
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
    /// Dial `endpoint` as a face of its own, beside the dial role's, and return the id it is
    /// known by. What the session declares is declared over it once its handshake completes (the
    /// session steps it as it does the first face's), what is declared after goes to it too, a
    /// publish and a get reach its peer, and what its peer declares counts with the others'. It
    /// is dialled once: a link that is lost or never completes takes the face with it, where the
    /// dial role's face is dialled again. [`OpenError::Unreachable`] when the session is closed,
    /// the endpoint's text is longer than `MAX_LOCATOR_LEN`, the session holds as many faces as
    /// `max_faces` admits, or the endpoint is not reached.
    pub fn attach_face(&self, endpoint: &str) -> Result<u64, OpenError> {
        let Some(mut guard) = self.live() else {
            return Err(OpenError::Unreachable(EndpointRefusal::new(
                endpoint,
                Refusal::SessionClosed,
            )));
        };
        let core = &mut guard.0;
        // The dial keeps the endpoint's text as its own, in a row's length, as the open keeps the
        // config's: no memory of the heap after the open.
        let Ok(named) = LocatorText::try_from(endpoint) else {
            return Err(OpenError::Unreachable(EndpointRefusal::new(
                endpoint,
                Refusal::TextTooLong,
            )));
        };
        // A face past `max_faces` would have no buffers: the arena holds the links of as many
        // faces as the config admits, and an accepted link past them is closed unread.
        if core.faces_full() {
            return Err(OpenError::Unreachable(EndpointRefusal::new(
                endpoint,
                Refusal::FacesFull,
            )));
        }
        let id = core.transport.links.next_face_id();
        // The tables first: the link's task dispatches to them from its first step.
        let Ok(held) = core.session.registry.add_face(id) else {
            return Err(OpenError::Unreachable(EndpointRefusal::new(
                endpoint,
                Refusal::FacesFull,
            )));
        };
        // The dial is begun here and asked at each step, as the dial role's is: the session is
        // held here, and a connection is not waited for while it is.
        let pending = match core.transport.begin_dial(endpoint) {
            Ok(pending) => pending,
            Err(refused) => {
                core.session.registry.remove_face(held);
                return Err(refused.into());
            }
        };
        core.transport.links.advance_face_id();
        let at = held.at();
        // Its life dials its one endpoint once: the dial begun above is that dial, under way, and
        // its answer is asked at the steps that follow.
        if core.push_face(
            held,
            Link::Dialing(Dial::new(DialEndpoint::Named(named), pending)),
            1,
        ) {
            // The read turns the face from its next turn on, which takes the dial into its place.
            #[cfg(not(wz_round))]
            self.direct.hold_face(at, true);
            let now_us = core.now_us();
            if let Some(face) = core.transport.links.face_mut(at) {
                let _ = face.life.input(LinkInput::Open, now_us);
                let _ = face.life.input(LinkInput::DialPending, now_us);
            }
        }
        Ok(id)
    }
}
