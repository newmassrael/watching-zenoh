// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The faces a session adds beside the dial role's, a link taken off a port or one it dials
//! besides: a build that listens (`listen`), whose faces' peers share the session's pools. A
//! session that only dials holds its dial role's face alone, and its text has none of this.

use super::*;

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> Core<L, C> {
    /// Give a link taken off a port a face, and run its session as the acceptor. A link that
    /// arrives when the session holds as many faces as `max_faces`, or has as many handshakes
    /// under way as `accept_pending`, is closed unread: its peer learns the node is full from the
    /// close, where one left queued would wait for a handshake that never starts.
    pub(super) fn accept_face(
        &mut self,
        opened: OpenedLink<L::Pump>,
        endpoint: Option<DialEndpoint>,
    ) {
        let pending = self
            .links
            .faces()
            .iter()
            .filter(|face| face.id != DIAL_FACE && matches!(face.link, Link::Opening { .. }))
            .count();
        if self.links.faces().len() > self.config.max_faces || pending >= self.config.accept_pending
        {
            return;
        }
        let id = self.links.next_face_id();
        // The tables first: the link's task dispatches to them from its first step. A link past
        // the sets the open lent is closed unread, as one past `max_faces` is.
        if self.registry.borrow_mut().add_face(id).is_err() {
            return;
        }
        let Ok(wire) = self.open_wire(id, opened, SessionRole::Acceptor, endpoint.as_ref()) else {
            self.registry.borrow_mut().remove_face(id);
            return;
        };
        self.links.advance_face_id();
        // The handshake is the acceptor's whole-handshake bound; the session's own timer in the
        // state machine is the same bound and ends the task, so whichever is first removes the face.
        let deadline_us = self.clock.now_us().saturating_add(
            self.config
                .timeouts
                .accepting_inactivity_ms
                .saturating_mul(1000),
        );
        self.push_face(
            id,
            Link::Opening {
                wire,
                next: 0,
                deadline_us,
            },
        );
    }

    /// Add a face whose link is `link`: a dial under way or a handshake. It is told the session's
    /// declarations at the pace the dial role's face is. Every face the open admits has its place
    /// in the table; one past them, which the callers refuse before they make it, is let go of
    /// with its tables.
    fn push_face(&mut self, id: FaceId, link: Link<LinkSession<C>, L::Dial>) {
        let pacing = self.dial().replay.pacing();
        let face = Face {
            id,
            link,
            replay: Replay::with_pacing(pacing),
        };
        if let Err(face) = self.links.push_face(face) {
            if let Some(wire) = face.link.wire() {
                wire.abort();
            }
            self.registry.borrow_mut().remove_face(face.id);
        }
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
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
        if core.links.faces().len() > core.config.max_faces {
            return Err(OpenError::Unreachable(EndpointRefusal::new(
                endpoint,
                Refusal::FacesFull,
            )));
        }
        let id = core.links.next_face_id();
        // The tables first: the link's task dispatches to them from its first step.
        if core.registry.borrow_mut().add_face(id).is_err() {
            return Err(OpenError::Unreachable(EndpointRefusal::new(
                endpoint,
                Refusal::FacesFull,
            )));
        }
        // The dial is begun here and asked at each step, as the dial role's is: the session is
        // held here, and a connection is not waited for while it is.
        let pending = match core.begin_dial(endpoint) {
            Ok(pending) => pending,
            Err(refused) => {
                core.registry.borrow_mut().remove_face(id);
                return Err(refused);
            }
        };
        core.links.advance_face_id();
        let deadline_us = core.open_deadline_us();
        core.push_face(
            id,
            Link::Dialing {
                dial: Dial::new(DialEndpoint::Named(named), pending),
                next: 0,
                deadline_us,
            },
        );
        Ok(id)
    }
}
