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

use std::sync::Arc;

use super::declaration_ids::DeclarationIds;
use super::egress::Queues;
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
}

impl FaceRuntime {
    /// The runtime of a face that has just registered: nothing held, no gate, no declaration
    /// numbered yet.
    pub(super) fn new(actions: Arc<SessionLinkActions>) -> Self {
        Self {
            actions,
            held: Queues::default(),
            gate_wake: Arc::new(tokio::sync::Notify::new()),
            declaration_ids: PlainMutex::new(DeclarationIds::default()),
        }
    }
}
