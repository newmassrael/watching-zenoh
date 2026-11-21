// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The seam between the client node and a plane it holds beside its sessions.
//!
//! A node's sessions are the dialled and the accepted ones ([`crate::slot_client`]); a PLANE is
//! something else the node takes part in that is not a session with anyone, and today it is the
//! multicast group (`slot_group`, which is `group`'s). The node knows a plane only by these two traits, so a
//! build with no plane names none of its code ([`NoPlane`] is the plane of a node that has none),
//! and the plane is given to the node as a value, as the acceptor is, rather than the node growing
//! a field and a feature for each.
//!
//! This module does not link `alloc`.

use wz_runtime_coop::{ClockSource, CoopRuntime};
use wz_session_core::limits::SessionLimits;
use wz_session_core::policy::SessionPolicy;
use wz_session_core::slot_observer::ObserverCell;

use crate::slot_client::DocumentSinks;

/// What the node hands a plane when the node starts: the runtime the plane's tasks run on, the
/// observer the plane's events are fanned to, the zid the node advertises, and the snapshots the
/// node's sessions are made with.
pub struct PlaneContext<'a, C: ClockSource + 'static> {
    /// The runtime of the node.
    pub runtime: CoopRuntime<C>,
    /// The observer the node's sessions dispatch to; a plane's events go to it too.
    pub observer: &'static ObserverCell<DocumentSinks>,
    /// The node's zenoh id.
    pub zid: &'a [u8],
    /// The value of every policy the node's machines read: the snapshot the node's creator
    /// resolved, which a plane's sessions are made with as the node's own are.
    pub policy: &'a SessionPolicy,
    /// The value of every limit the node's tables are held to: the snapshot the node's creator
    /// resolved, which a plane's tables are held to as the node's sessions' are. Where the build
    /// allows each limit one value it holds no byte.
    pub limits: SessionLimits,
}

/// A plane as the image states it, before the node starts it.
pub trait Plane<C: ClockSource + 'static>: Sized {
    /// The plane once it has started.
    type Running: PlaneRunning;

    /// Start the plane in `context`.
    fn start(self, context: PlaneContext<'_, C>) -> Self::Running;
}

/// A running plane, ticked once a round of the node's loop.
pub trait PlaneRunning {
    /// Advance the plane to `now_ms`.
    fn tick(&mut self, now_ms: u64);
}

/// The plane of a node that has none: nothing starts and nothing ticks.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPlane;

impl<C: ClockSource + 'static> Plane<C> for NoPlane {
    type Running = NoPlane;

    fn start(self, _context: PlaneContext<'_, C>) -> NoPlane {
        NoPlane
    }
}

impl PlaneRunning for NoPlane {
    fn tick(&mut self, _now_ms: u64) {}
}
