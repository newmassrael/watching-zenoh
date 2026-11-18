// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a face is at run time, apart from what the tables say about it.
//!
//! [`FaceRuntime`] is the state of a face that is not a version of the tables: the session behind
//! it, the messages held for its link, the waker of its gate and the numbers of the declarations
//! sent to it. The data path writes it under the read guard, each member under a lock of the
//! face's own, and a face has one of each whichever version of the tables routed a message to it,
//! so it is shared by every version that holds the face (`docs/router-table-snapshots.md`,
//! section 3 (b)).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::declaration_ids::DeclarationIds;
use super::egress::Queues;
use super::Zid;
use crate::session_glue::SessionLinkActions;
use crate::sync::PlainMutex;

/// The state of one face that the data path writes, shared by every version of the tables that
/// holds the face.
pub(super) struct FaceRuntime {
    /// The session behind the face: every message routed to it is sent through this.
    pub(super) actions: Arc<SessionLinkActions>,
    /// The messages this face, as a DESTINATION, has not taken yet: held in order until its link
    /// has room, so that a face that stopped reading costs the faces that do not feed it
    /// nothing (see [`egress`](super::egress)).
    pub(super) held: Queues,
    /// What this face, as a SOURCE, waits on while it is gated
    /// ([`FaceForwarder::read_gate`](crate::accept_loop::FaceForwarder::read_gate)): the pass that
    /// takes its last gate away wakes it, once, with a stored permit, and no other face's release
    /// or link's room does.
    pub(super) gate_wake: Arc<tokio::sync::Notify>,
    /// The ids this node gave the declarations it sent to the face, when the face keeps them by
    /// id ([`declaration_ids`](super::declaration_ids)).
    pub(super) declaration_ids: PlainMutex<DeclarationIds>,
    /// Whether a chain of fragments is being sent to this face, as a DESTINATION, off the
    /// router's threads, in each lane ([`egress`](super::egress), indexed by `Lane::index`):
    /// while it is, what is routed to the face in that lane is held behind it, so that it keeps
    /// its place in the order.
    pub(super) chain_in_flight: Arc<[core::sync::atomic::AtomicBool; 2]>,
    /// Whether the face this runtime was made for has left the tables: set by `deregister`, and by
    /// a `register` that replaces the face under its id, never cleared. A route that holds the
    /// runtime outlives the version it was computed from, and reads this before it sends, so a
    /// face that left is not sent to through a route kept from before it left.
    closed: AtomicBool,
}

impl FaceRuntime {
    /// The runtime of a face that has just registered: nothing held, no gate, no declaration
    /// numbered yet, no chain being sent, open.
    pub(super) fn new(actions: Arc<SessionLinkActions>) -> Self {
        Self {
            actions,
            held: Queues::default(),
            gate_wake: Arc::new(tokio::sync::Notify::new()),
            declaration_ids: PlainMutex::new(DeclarationIds::default()),
            chain_in_flight: Arc::new([
                core::sync::atomic::AtomicBool::new(false),
                core::sync::atomic::AtomicBool::new(false),
            ]),
            closed: AtomicBool::new(false),
        }
    }

    /// Mark the face gone: nothing is sent to it through a route that holds this runtime after.
    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Whether the face has left the tables ([`close`](Self::close)).
    pub(super) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

/// What a send to a face reads of it: its runtime and its peer's routing zid, both fixed for as
/// long as the face is up. A send that reads nothing else takes this rather than the face's
/// routing facts, so that a route that holds the face's runtime sends the way a lookup in the
/// face table does, without the facts a version holds (the face's aliases among them).
#[derive(Clone, Copy)]
pub(super) struct SendFace<'a> {
    pub(super) runtime: &'a FaceRuntime,
    pub(super) peer_zid: Option<Zid>,
}
