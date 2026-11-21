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
//! - the LAST TIME the session gave, a program (`z_timestamp_new`) or its
//!   advanced publisher, which pico keeps in the session (`_last_timestamp`) so
//!   that the session's stamps strictly increase whichever clock they were read
//!   from;
//! - with `connectivity`, the session's CONNECTIVITY listeners, which pico keeps in
//!   the session itself (`vendor/zenoh-pico/src/api/connectivity.c` @
//!   `_z_connectivity_transport_listener_intmap_insert(&session->_connectivity_transport_event_listeners, id,`)
//!   and which therefore live exactly as long as it does;
//! - with `admin-space`, the session's ADMIN SPACE, which pico also keeps in the
//!   session (`_admin_space_queryable_id`) and clears with it.

#[cfg(feature = "connectivity")]
use alloc::sync::Arc;

#[cfg(feature = "connectivity")]
use wz_capi_port::SessionEngine;
#[cfg(any(feature = "advanced", feature = "clock-source"))]
use wz_node_time::node_clock::{NodeHlc, TimestampingEnabled};
use wz_session_core::limits::SessionLimits;
use wz_session_core::policy::SessionPolicy;
use wz_session_core::WhatAmI;

#[cfg(feature = "connectivity")]
use crate::connectivity::Connectivity;

/// This session's pico-side state; see the module doc.
pub(crate) struct PicoSessionExt {
    /// The session's own role — pico's `zn->_mode`.
    pub(crate) mode: WhatAmI,
    /// The session's clock, which the advanced plane's publisher stamps with, and which
    /// `z_timestamp_new` stamps with once a clock source is registered.
    #[cfg(any(feature = "advanced", feature = "clock-source"))]
    pub(crate) hlc: NodeHlc,
    /// Every time this session gives, through `z_timestamp_new` and through its advanced
    /// publisher: the last one given, which the session's clock learns.
    pub(crate) time: crate::last_timestamp::SessionTime,
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
    /// The policies the session runs under, as its open resolved them: what a door that takes a
    /// statement a policy governs admits it by (`wz_ext_get_to_peer`, the one such door today).
    #[cfg(feature = "query")]
    pub(crate) policy: SessionPolicy,
    /// The session limits the session runs under, as its open resolved them: what the door that
    /// reports the session's facts reads the bound of a querier from.
    #[cfg(feature = "query")]
    pub(crate) limits: SessionLimits,
}

impl PicoSessionExt {
    /// A session of role `mode` and identity `zid`, under `policy` and `limits`, the snapshots its
    /// open resolved; with the connectivity plane, over the faces of `engine`, the engine that runs
    /// it.
    ///
    /// The clock STAMPS whatever the role, which is pico's: its timestamps come
    /// from the session's own clock and zid unconditionally
    /// (`vendor/zenoh-pico/src/api/api.c` @ `z_result_t z_timestamp_new(`
    /// reads no configuration), where zenoh's node clock exists only for a
    /// router by default. An advanced publisher that stamps timestamps — a cache
    /// without miss detection — is refused on a clock that does not exist, so
    /// the clock a pico session has is the one it must be given.
    ///
    /// The connectivity hub is registered with the engine's faces HERE, once, and
    /// not per listener: pico dispatches a peer's arrival or departure to every
    /// listener itself, in an order of its own (see `Connectivity`), and a
    /// registration per listener would leave that order to the engine.
    ///
    /// Its clock may have been refused (`UHLC_MAX_DELTA_MS` states a bound the clock does not
    /// honour): the open asks `clock_refused` and refuses such a session, which would stamp
    /// nothing in place of the clock pico always gives one. Dropping it lets go of the watch.
    pub(crate) fn new(
        mode: WhatAmI,
        zid: &[u8],
        policy: SessionPolicy,
        limits: SessionLimits,
        #[cfg(feature = "connectivity")] engine: &Arc<dyn SessionEngine>,
    ) -> Self {
        // The snapshot is read by the clock and by a door a policy governs: a build with neither
        // a clock nor `query` reads none of it.
        #[cfg(not(any(feature = "query", feature = "advanced", feature = "clock-source")))]
        let _ = policy;
        // The limits are read by the door that reports the session's facts alone.
        #[cfg(not(feature = "query"))]
        let _ = limits;
        #[cfg(feature = "connectivity")]
        let connectivity = Connectivity::new();
        #[cfg(feature = "connectivity")]
        let watch_id = {
            let sink = Arc::clone(&connectivity);
            engine.watch_faces(Arc::new(move |kind, snapshot| {
                sink.on_face_event(kind, snapshot);
            }))
        };
        // Without the advanced plane or a registrable clock nothing stamps, so there is no clock to
        // build.
        #[cfg(not(any(feature = "advanced", feature = "clock-source")))]
        let _ = zid;
        #[cfg(any(feature = "advanced", feature = "clock-source"))]
        let hlc = NodeHlc::for_node_by(zid, mode, TimestampingEnabled::all(true), &policy);
        #[cfg(any(feature = "advanced", feature = "clock-source"))]
        let time = crate::last_timestamp::SessionTime::new().learned_by(hlc.clone());
        #[cfg(not(any(feature = "advanced", feature = "clock-source")))]
        let time = crate::last_timestamp::SessionTime::new();
        Self {
            mode,
            #[cfg(any(feature = "advanced", feature = "clock-source"))]
            hlc,
            time,
            #[cfg(feature = "connectivity")]
            connectivity,
            #[cfg(feature = "connectivity")]
            watch: (Arc::clone(engine), watch_id),
            #[cfg(feature = "admin-space")]
            admin_space: crate::admin_space::AdminSpaceSlot::new(None),
            #[cfg(feature = "query")]
            policy,
            #[cfg(feature = "query")]
            limits,
        }
    }

    /// Why the session's clock was refused (`NodeHlc::clock_refused`): the bound
    /// `UHLC_MAX_DELTA_MS` states is one the clock does not honour. `None` for a clock that was
    /// built. The open refuses a session for which this is `Some`.
    #[cfg(any(feature = "advanced", feature = "clock-source"))]
    pub(crate) fn clock_refused(&self) -> Option<&wz_node_time::node_clock::MaxDeltaRefused> {
        self.hlc.clock_refused()
    }

    /// The session was closed: let go of its connectivity listeners, which runs their closures'
    /// `drop(context)` now and not when the session handle is dropped. A closed session
    /// delivers nothing, and pico clears its listener maps in `z_close`.
    pub(crate) fn close_listeners(&self) {
        #[cfg(feature = "connectivity")]
        self.connectivity.shutdown();
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

#[cfg(all(
    test,
    feature = "engine-tokio",
    any(feature = "advanced", feature = "clock-source")
))]
mod tests {
    use super::*;
    #[cfg(feature = "connectivity")]
    use wz_capi_core::faces::SharedSession;
    #[cfg(feature = "connectivity")]
    use wz_capi_core::runtime::runtime_impl::TokioTime;
    use wz_node_time::node_clock::DataStamp;
    use wz_session_core::policy::ClockQualityStamping;

    const ZID: [u8; 16] = [0x2d; 16];

    /// The session's pico state under `policy`, as its open makes it.
    fn ext_under(policy: SessionPolicy) -> PicoSessionExt {
        #[cfg(feature = "connectivity")]
        {
            let shared = Arc::new(
                SharedSession::new(TokioTime::new(), ZID.into(), policy)
                    .expect("test host entropy"),
            );
            PicoSessionExt::new(
                WhatAmI::Peer,
                &ZID,
                policy,
                SessionLimits::defaults(),
                &shared.as_engine(),
            )
        }
        #[cfg(not(feature = "connectivity"))]
        {
            PicoSessionExt::new(WhatAmI::Peer, &ZID, policy, SessionLimits::defaults())
        }
    }

    /// The session's clock stamps by the `clock-quality-stamping` value of the snapshot its open
    /// resolved: no reference is reported for it, so it withholds the stamp of data exactly when
    /// the value is `trusted-only`.
    #[test]
    fn the_sessions_clock_stamps_by_the_snapshot_it_is_handed() {
        let mut built = 0;
        for value in [
            ClockQualityStamping::Always,
            ClockQualityStamping::TrustedOnly,
        ] {
            let mut policy = SessionPolicy::defaults();
            if policy.select_clock_quality_stamping(value).is_err() {
                continue;
            }
            let ext = ext_under(policy);
            assert_eq!(
                ext.hlc.data_stamp() == DataStamp::Withheld,
                value == ClockQualityStamping::TrustedOnly,
                "{}",
                value.id()
            );
            built += 1;
        }
        assert!(built >= 1, "the build's domain holds at least its default");
    }
}
