// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The requesting end of a query on the cooperative engine.
//!
//! A get is asked of the one peer the session's link reaches, so it has one leg and owes one
//! Final; the session asks no queryable of its own, as zenoh-pico's default build asks none
//! (`Z_FEATURE_LOCAL_QUERYABLE` 0). Its pending entry is session-core's, registered with the
//! observer under the request id the link's actions allocate, with the deadline, the accepted
//! reply keys and the consolidation `QueryOptions` reads, as the tokio engine registers its own.
//!
//! What the observer hands the entry's sink happens under the session's lock, and a C callback
//! never runs there (decision D8), so the sink only queues: an owned copy of each reply, and the
//! leg's END when the entry is dropped (its Final, its deadline, its cancellation, the loss of its
//! link), said by a guard the sink owns. The deliveries hand both out with no lock held, the end
//! as the drop of the leg's callback, which is how a C program learns its get is over.

use alloc::collections::VecDeque;
use alloc::sync::Arc;

use wz_capi_port::os::Mutex;

use wz_session_core::reply::InboundReply;
use wz_session_core::reply_sink::{BoxedReplySink, ReplyView};

use super::lock;
use super::registry::{FaceId, Registry};

/// What a get leg's sink queued, in the order it happened.
///
/// Nearly every event is a reply and a leg ends once, so a slot sized for the reply wastes
/// nothing a boxed reply would save, and boxing would cost each reply an allocation.
#[allow(clippy::large_enum_variant)]
pub(super) enum GetEvent {
    /// A reply for the leg's callback.
    Reply(u64, InboundReply),
    /// The leg is over: its callback is dropped.
    End(u64),
}

/// What the get plane shares between the session's state, the observer's reply sinks and the
/// deliveries.
#[derive(Default)]
pub(super) struct GetPlane {
    pub(super) events: Mutex<VecDeque<GetEvent>>,
}

/// Which of the observer's registries a pending leg's entry is in.
#[derive(Clone, Copy)]
pub(super) enum GetKind {
    /// A query: its entry is under its request id, and its peer owes a Final.
    Query,
    /// A liveliness snapshot: its entry is under its Interest id, and its peer owes a DeclFinal.
    #[cfg(feature = "liveliness-get")]
    Liveliness,
}

/// A leg the session has pending: the face it was asked of, the id its callback is held under,
/// and the id its entry is registered with (a request id or an Interest id, as its kind says).
pub(super) struct PendingGet {
    pub(super) face: FaceId,
    pub(super) leg: u64,
    pub(super) rid: u64,
    pub(super) kind: GetKind,
}

impl PendingGet {
    /// Drop this leg's entry from its face's pending gets, which ends the leg (its sink's guard
    /// says so). A face the session no longer holds took its entries with it.
    pub(super) fn unregister(&self, registry: &mut Registry) {
        let Some(face) = registry.face_mut(self.face) else {
            return;
        };
        match self.kind {
            GetKind::Query => {
                face.gets.replies.unregister(self.rid);
            }
            #[cfg(feature = "liveliness-get")]
            GetKind::Liveliness => {
                face.gets.liveliness_gets.unregister(self.rid);
            }
        }
    }
}

/// The end of a leg, said once: when the pending entry that owns it is dropped.
struct LegEnd {
    leg: u64,
    plane: Arc<GetPlane>,
}

impl Drop for LegEnd {
    fn drop(&mut self) {
        lock(&self.plane.events).push_back(GetEvent::End(self.leg));
    }
}

/// The sink of leg `leg`'s pending entry: each reply is queued as an owned copy, and the entry's
/// drop queues the leg's end. The Final itself says nothing more: the registry drops the entry
/// once its Finals are in, which is the end.
pub(super) fn reply_sink(leg: u64, plane: &Arc<GetPlane>) -> BoxedReplySink {
    let replies = Arc::clone(plane);
    let end = LegEnd {
        leg,
        plane: Arc::clone(plane),
    };
    BoxedReplySink::new(
        move |view: &dyn ReplyView| {
            lock(&replies.events).push_back(GetEvent::Reply(leg, InboundReply::from_view(view)));
        },
        move |_rid| {
            // Owned by this closure so it is dropped with the sink.
            let _ = &end;
        },
    )
}
