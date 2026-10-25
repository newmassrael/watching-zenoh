// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a session reports of the peers it holds: one `FaceSnapshot` for each established
//! transport and a `LinkSnapshot` for each physical link under it, and the `FaceEventKind`
//! a watcher is told when a face comes up or goes down.
//!
//! The model is the session's, not an engine's: it is read off a session's own
//! `SessionLinkActions`, so an engine that holds a session builds its snapshots the same way
//! and an ABI that reports them (a connectivity plane, an admin space) names none.
//!
//! Every field is READ off the face, never defaulted into a plausible-looking value:
//! `interfaces` keeps the three-state answer of a link's subject (resolved, resolved-empty,
//! undetermined) rather than flattening a failed lookup to an empty set the way upstream does,
//! and `kind` is `None` for a driver that cannot name itself. An ABI decides how to spell
//! "unknown", and can only do that honestly if the unknown survives to it.
//!
//! The names are plain code and not links on purpose: rustdoc reads a module's first paragraph
//! in its parent's scope as well, where these items are not named.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::link::LinkKind;
#[cfg(feature = "session-unicast")]
use {
    crate::link::SessionRuntime, crate::session_actions::SessionLinkActions,
    wz_runtime_core::TimeSource,
};

/// One PHYSICAL link of an established face.
#[derive(Debug, Clone)]
pub struct LinkSnapshot {
    /// This end's locator.
    pub src: String,
    /// The peer end's locator.
    pub dst: String,
    /// The KIND of link, or `None` when the driver cannot say.
    pub kind: Option<LinkKind>,
    /// The NICs this link's local address sits on, with `None` meaning "could not be
    /// determined" — see [`crate::link::LinkSubject`].
    pub interfaces: Option<Vec<String>>,
    /// The negotiated outbound frame budget, clamped into the `u16` both upstreams report.
    pub mtu: u16,
    /// The group a member of a joined group is reached through, `None` on a unicast link.
    pub group: Option<GroupLink>,
}

/// The group under a group member's link, in the two spellings the two upstreams report it
/// by: each ABI picks its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupLink {
    /// The group's locator, which zenoh reports as the link's `group`
    /// (`io/zenoh-link-commons/src/lib.rs` @ `group: Some(link.get_dst().to_owned()),`).
    pub locator: String,
    /// The endpoint the session joined it by, its socket keys included, which zenoh-pico
    /// reports as the link's `src` (`vendor/zenoh-pico/src/transport/multicast/rx.c` @
    /// `entry->common._link_src = _z_endpoint_to_string(&ztm->_common._link->_endpoint);`).
    pub endpoint: String,
}

/// One ESTABLISHED face, plus the links under it.
///
/// The transport half is the identity and the negotiated booleans a transport value carries;
/// the links are carried alongside rather than inside because a transport outlives any one of
/// its links.
#[derive(Debug, Clone)]
pub struct FaceSnapshot {
    /// The peer's zid.
    pub zid: [u8; 16],
    /// The peer's role as the raw 2-bit INIT wire form.
    pub whatami: u8,
    /// Whether QoS was negotiated on this transport.
    pub is_qos: bool,
    /// Whether this is a multicast transport: `false` for a unicast face, `true` for a member
    /// of a group the session joined, which both upstreams report as a transport of its own.
    pub is_multicast: bool,
    /// Whether SHM was negotiated on this transport. Reported on every build: the FACT is one
    /// a session can state either way, and gating the field would make an ABI's shape decide
    /// what the session is allowed to know.
    pub is_shm: bool,
    /// This face's physical links, one entry each.
    pub links: Vec<LinkSnapshot>,
}

#[cfg(feature = "session-unicast")]
impl FaceSnapshot {
    /// Snapshot the face a session's `actions` are the end of, or `None` when its INIT has not
    /// populated the identity slots yet.
    ///
    /// The `None` is the half-open case, and it is a REFUSAL rather than a default: a transport
    /// reported with a zero zid is a peer an application can neither match nor dial.
    pub fn of_actions<R: SessionRuntime, T: TimeSource>(
        actions: &SessionLinkActions<R, T>,
    ) -> Option<Self> {
        let peer = actions.peer_zid()?;
        let whatami = actions.peer_whatami_wire()?;
        let mut zid = [0u8; 16];
        let n = peer.len().min(16);
        zid[..n].copy_from_slice(&peer[..n]);
        let subject = actions.link_subject().cloned();
        let mtu = u16::try_from(actions.negotiated_batch_mtu()).unwrap_or(u16::MAX);
        let links = actions
            .link_endpoints_all()
            .into_iter()
            .map(|e| LinkSnapshot {
                src: String::from(e.src.as_str()),
                dst: String::from(e.dst.as_str()),
                kind: subject.as_ref().and_then(|s| s.kind),
                interfaces: subject.as_ref().and_then(|s| s.interfaces.clone()),
                mtu,
                group: None,
            })
            .collect();
        // A build without `transport-qos` never negotiates the ext, so `false` is the MEASURED
        // answer there rather than a stand-in: there is no conduit split to report. `is_qos`
        // itself is gated, so this is also the only spelling that compiles in both
        // configurations.
        #[cfg(feature = "transport-qos")]
        let is_qos = actions.is_qos();
        #[cfg(not(feature = "transport-qos"))]
        let is_qos = false;
        // Same shape, same reason, for the SHM ext.
        #[cfg(feature = "transport-shm")]
        let is_shm = actions.is_shm();
        #[cfg(not(feature = "transport-shm"))]
        let is_shm = false;
        Some(Self {
            zid,
            whatami,
            is_qos,
            is_multicast: false,
            is_shm,
            links,
        })
    }
}

/// Which way a face moved: the input to the kind an event of a transport or a link carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaceEventKind {
    /// The face reached Established.
    Up,
    /// The face left the live set.
    Down,
}

/// A face-lifecycle observer.
///
/// `Arc` rather than `Box` because a registry clones the sink list OUT of its lock before it
/// invokes any of them: a sink may reach code that re-enters the registry.
pub type FaceEventSink = Arc<dyn Fn(FaceEventKind, &FaceSnapshot) + Send + Sync>;
