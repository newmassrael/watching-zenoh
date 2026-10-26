// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The faces of the session, as a connectivity plane watches them.
//!
//! The session holds one face, the link it dialled: it is up from the handshake that completed
//! to the link's loss, and a link dialled again is another face with the same peer's identity
//! perhaps. A watcher is told of each coming and going ([`FacePlane::happened`]), and the
//! sinks run where the session hands out its callbacks, with no lock held, so one that reaches
//! back into the session (a transport listener that lists the transports) finds it free.
//!
//! What a watcher is told is queued only while one watches: the face the open brought up is not
//! announced to a watcher that came after it, which reads the faces that stand
//! (`face_snapshots`) for its history, as zenoh-pico's listener does.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use wz_capi_port::os::Mutex;

use wz_session_core::face::{FaceEventKind, FaceEventSink, FaceSnapshot};

use super::lock;

/// The watchers of the session's faces and the events waiting for them.
#[derive(Default)]
pub(super) struct FacePlane {
    watchers: Mutex<Vec<(u64, FaceEventSink)>>,
    next_watcher: AtomicU64,
    events: Mutex<VecDeque<(FaceEventKind, FaceSnapshot)>>,
}

impl FacePlane {
    /// Tell `sink` of each face event from now on, under the id that stops it.
    pub(super) fn watch(&self, sink: FaceEventSink) -> u64 {
        let id = self.next_watcher.fetch_add(1, Ordering::AcqRel) + 1;
        lock(&self.watchers).push((id, sink));
        id
    }

    /// Stop watcher `id`: `true` when one was registered under it.
    pub(super) fn unwatch(&self, id: u64) -> bool {
        let mut watchers = lock(&self.watchers);
        let before = watchers.len();
        watchers.retain(|(held, _)| *held != id);
        watchers.len() != before
    }

    /// Whether anything watches, which is whether an event is worth the snapshot it carries.
    pub(super) fn watched(&self) -> bool {
        !lock(&self.watchers).is_empty()
    }

    /// Queue a face event for the watchers, to be handed out with the session's other
    /// deliveries.
    pub(super) fn happened(&self, kind: FaceEventKind, snapshot: FaceSnapshot) {
        lock(&self.events).push_back((kind, snapshot));
    }

    /// The next event to hand out, in the order they happened.
    pub(super) fn next_event(&self) -> Option<(FaceEventKind, FaceSnapshot)> {
        lock(&self.events).pop_front()
    }

    /// The watchers as they stand, cloned out of their lock: a sink may undeclare a watcher.
    pub(super) fn sinks(&self) -> Vec<FaceEventSink> {
        lock(&self.watchers)
            .iter()
            .map(|(_, sink)| Arc::clone(sink))
            .collect()
    }
}
