// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a pico C session carries that the ABI-neutral core has no place for.
//!
//! [`SessionState::set_abi_extension`] takes ONE value, once, right after the
//! open, so everything this ABI keeps per session lives in this one struct:
//!
//! - the session's ROLE, which is decided by the C config (`Z_CONFIG_MODE_KEY`,
//!   and a `listen` config forces peer) and which nothing downstream of the open
//!   can recover — a face records the PEER's role, not ours;
//! - the session's CLOCK, for the same reason: it is built once at the open;
//! - the session's CONNECTIVITY listeners, which pico keeps in the session
//!   itself (`vendor/zenoh-pico/src/api/connectivity.c` @
//!   `_z_connectivity_transport_listener_intmap_insert(&session->_connectivity_transport_event_listeners, id,`)
//!   and which therefore live exactly as long as it does.

use std::sync::Arc;

use wz_capi_core::faces::SharedSession;
use wz_runtime_tokio::node_clock::{NodeHlc, TimestampingEnabled};
use wz_runtime_tokio::session_glue::WhatAmI;

use crate::connectivity::Connectivity;

/// This session's pico-side state; see the module doc.
pub(crate) struct PicoSessionExt {
    /// The session's own role — pico's `zn->_mode`.
    pub(crate) mode: WhatAmI,
    /// The session's clock.
    pub(crate) hlc: NodeHlc,
    /// The transport and link listeners a C program declared on this session.
    pub(crate) connectivity: Arc<Connectivity>,
    /// The face registry this session's connectivity hub watches, and the id it
    /// watches under, so the watch can be dropped with the session.
    watch: (Arc<SharedSession>, u64),
}

impl PicoSessionExt {
    /// A session of role `mode` and identity `zid` over `shared`.
    ///
    /// The clock STAMPS whatever the role, which is pico's: its timestamps come
    /// from the session's own clock and zid unconditionally
    /// (`vendor/zenoh-pico/src/net/session.c` @ `_z_timestamp_t z_timestamp_new`
    /// calls no configuration), where zenoh's node clock exists only for a
    /// router by default. An advanced publisher that stamps timestamps — a cache
    /// without miss detection — is refused on a clock that does not exist, so
    /// the clock a pico session has is the one it must be given.
    ///
    /// The connectivity hub is registered with the face registry HERE, once, and
    /// not per listener: pico dispatches a peer's arrival or departure to every
    /// listener itself, in an order of its own (see [`Connectivity`]), and a
    /// registration per listener would leave that order to the registry.
    pub(crate) fn new(mode: WhatAmI, zid: &[u8], shared: &Arc<SharedSession>) -> Self {
        let connectivity = Connectivity::new();
        let sink = Arc::clone(&connectivity);
        let watch_id = shared.watch_faces(Arc::new(move |kind, snapshot| {
            sink.on_face_event(kind, snapshot);
        }));
        Self {
            mode,
            hlc: NodeHlc::for_node(zid, mode, TimestampingEnabled::all(true)),
            connectivity,
            watch: (Arc::clone(shared), watch_id),
        }
    }
}

impl Drop for PicoSessionExt {
    /// Stop watching, then let go of every listener: their C contexts are
    /// released no later than the session is, which is when pico clears the
    /// session's listener maps.
    fn drop(&mut self) {
        let (shared, id) = &self.watch;
        shared.unwatch_faces(*id);
        self.connectivity.shutdown();
    }
}
