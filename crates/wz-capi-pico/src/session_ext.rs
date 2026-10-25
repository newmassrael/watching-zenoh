// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a pico C session carries that the ABI-neutral core has no place for.
//!
//! The C handle (`PicoSessionHandle`) holds the engine's session beside ONE
//! value of this ABI's own, built at the open, so everything this ABI keeps per
//! session lives in this one struct (`docs/capi-pico-on-coop-engine.md`,
//! decision D7):
//!
//! - the session's ROLE, which is decided by the C config (`Z_CONFIG_MODE_KEY`,
//!   and a `listen` config forces peer) and which nothing downstream of the open
//!   can recover — a face records the PEER's role, not ours;
//! - the session's CLOCK, for the same reason: it is built once at the open;
//! - with `connectivity`, the session's CONNECTIVITY listeners, which pico keeps in
//!   the session itself (`vendor/zenoh-pico/src/api/connectivity.c` @
//!   `_z_connectivity_transport_listener_intmap_insert(&session->_connectivity_transport_event_listeners, id,`)
//!   and which therefore live exactly as long as it does;
//! - with `admin-space`, the session's ADMIN SPACE, which pico also keeps in the
//!   session (`_admin_space_queryable_id`) and clears with it.

#[cfg(feature = "connectivity")]
use std::sync::Arc;

#[cfg(feature = "advanced")]
use wz_capi_core::runtime::node_clock::{NodeHlc, TimestampingEnabled};
#[cfg(feature = "connectivity")]
use wz_capi_port::SessionEngine;
use wz_session_core::WhatAmI;

#[cfg(feature = "connectivity")]
use crate::connectivity::Connectivity;

/// This session's pico-side state; see the module doc.
pub(crate) struct PicoSessionExt {
    /// The session's own role — pico's `zn->_mode`.
    pub(crate) mode: WhatAmI,
    /// The session's clock, which the advanced plane's publisher stamps with.
    #[cfg(feature = "advanced")]
    pub(crate) hlc: NodeHlc,
    /// The transport and link listeners a C program declared on this session.
    #[cfg(feature = "connectivity")]
    pub(crate) connectivity: Arc<Connectivity>,
    /// The engine whose faces this session's connectivity hub watches, and the id it
    /// watches under, so the watch can be dropped with the session.
    #[cfg(feature = "connectivity")]
    watch: (Arc<dyn SessionEngine>, u64),
    /// Whether the admin space runs, and what it reports as the transport's link.
    #[cfg(feature = "admin-space")]
    pub(crate) admin_space: crate::admin_space::AdminSpaceSlot,
}

impl PicoSessionExt {
    /// A session of role `mode` and identity `zid`; with the connectivity plane, over the faces
    /// of `engine`, the engine that runs it.
    ///
    /// The clock STAMPS whatever the role, which is pico's: its timestamps come
    /// from the session's own clock and zid unconditionally
    /// (`vendor/zenoh-pico/src/net/session.c` @ `_z_timestamp_t z_timestamp_new`
    /// calls no configuration), where zenoh's node clock exists only for a
    /// router by default. An advanced publisher that stamps timestamps — a cache
    /// without miss detection — is refused on a clock that does not exist, so
    /// the clock a pico session has is the one it must be given.
    ///
    /// The connectivity hub is registered with the engine's faces HERE, once, and
    /// not per listener: pico dispatches a peer's arrival or departure to every
    /// listener itself, in an order of its own (see `Connectivity`), and a
    /// registration per listener would leave that order to the engine.
    pub(crate) fn new(
        mode: WhatAmI,
        zid: &[u8],
        #[cfg(feature = "connectivity")] engine: &Arc<dyn SessionEngine>,
    ) -> Self {
        #[cfg(feature = "connectivity")]
        let connectivity = Connectivity::new();
        #[cfg(feature = "connectivity")]
        let watch_id = {
            let sink = Arc::clone(&connectivity);
            engine.watch_faces(Arc::new(move |kind, snapshot| {
                sink.on_face_event(kind, snapshot);
            }))
        };
        // Without the advanced plane nothing stamps, so there is no clock to build.
        #[cfg(not(feature = "advanced"))]
        let _ = zid;
        Self {
            mode,
            #[cfg(feature = "advanced")]
            hlc: NodeHlc::for_node(zid, mode, TimestampingEnabled::all(true)),
            #[cfg(feature = "connectivity")]
            connectivity,
            #[cfg(feature = "connectivity")]
            watch: (Arc::clone(engine), watch_id),
            #[cfg(feature = "admin-space")]
            admin_space: crate::admin_space::AdminSpaceSlot::new(None),
        }
    }

    /// The same session, whose admin space reports `transport_endpoint` (the
    /// locator the session was opened on) as its transport's link.
    #[cfg(feature = "admin-space")]
    pub(crate) fn with_transport_endpoint(mut self, transport_endpoint: Option<String>) -> Self {
        self.admin_space = crate::admin_space::AdminSpaceSlot::new(transport_endpoint);
        self
    }
}

#[cfg(feature = "connectivity")]
impl Drop for PicoSessionExt {
    /// Stop watching, then let go of every listener: their C contexts are
    /// released no later than the session is, which is when pico clears the
    /// session's listener maps.
    fn drop(&mut self) {
        let (engine, id) = &self.watch;
        engine.unwatch_faces(*id);
        self.connectivity.shutdown();
    }
}
