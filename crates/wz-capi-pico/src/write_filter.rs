// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! zenoh-pico's WRITE FILTER, for a publisher and a querier.
//!
//! Every pico publisher and querier creates one at declare
//! (`vendor/zenoh-pico/src/net/filtering.c` @ `_z_write_filter_create`): it asks
//! the peers, through an Interest on the entity's own key, whether anything
//! there would receive what it sends, and from then on its put, delete or get
//! is SENT only while some peer has said yes. It is created in the state
//! ACTIVE, which reads as "nothing matches", so an entity with no peer yet
//! sends nothing and says `Z_OK`.
//!
//! wz's session layer asks the same question through its matching Interest
//! (`SharedSession::declare_write_filter`); this module is the pico half — WHEN
//! to ask and HOW, which are the C library's rules and not the session's:
//!
//! - A CLIENT always asks, and asks for aggregated answers.
//! - A PEER asks only while some peer of its own is a router, and without the
//!   aggregate bit; otherwise it asks nothing and learns what peers volunteer.
//!
//! (`vendor/zenoh-pico/src/net/primitives.c` @ `_z_add_interest`, and the flag
//! composition in `_z_write_filter_create`.) Both are read at DECLARE time and
//! not again, as upstream reads them.
//!
//! ⚠ TWO DIVERGENCES ARE NOT REPRODUCED, both upstream's, both wz doing less,
//! and both measured by the peer legs of `pico_keyexpr_declaration_twice_and_diff`
//! (R2968), which pin each from both sides and compare everything else whole:
//!
//! - A pico peer that asked never sends the `Interest(Final)` —
//!   `_z_remove_interest` sends it for a client (or multicast) only — so the
//!   router keeps the interest until the session closes. wz retracts it, which
//!   no program can observe and which costs the peer nothing to hold. Copying it
//!   would be copying a leak.
//! - A pico peer's filter is opened by ANY matching declaration the session
//!   already holds, of either kind: `_z_interest_replay_declare` replays them
//!   without regard to what the filter counts. A subscriber the peer declared
//!   therefore opens a querier's filter, and pico sends a Query nothing can
//!   answer. wz opens a querier's filter on queryables only, as zenoh does. The
//!   replay is kind-blind for a peer alone: a client's interest is aggregate,
//!   and an aggregate replay matches on key equality.
//!
//! What IS reproduced, and is what a peer's mode changes on the wire: whether it
//! asks at all (above), and that its subscriber and queryable retractions name
//! the key they were held on, which a client's do not
//! (`DeclaredKeyexpr::retraction_naming`).

use std::sync::{Arc, Mutex, PoisonError};

#[cfg(feature = "advanced")]
use wz_capi_core::faces::SharedSession;
#[cfg(feature = "advanced")]
use wz_capi_core::runtime::node_clock::NodeHlc;
use wz_capi_port::{FilterId, FilterPlane, FilteredPut, MatchId, MatchingSink, WireKey};
use wz_session_core::declare_form::InterestForm;
use wz_session_core::WhatAmI;

use crate::keyexpr::DeclaredKeyexpr;
use crate::session::{engine_of, Engine, PicoSessionHandle};

/// This session's own role: pico's `zn->_mode`, kept in the handle at open
/// ([`crate::session_ext::PicoSessionExt`]) because nothing downstream of the
/// open can recover it.
pub(crate) fn session_mode(handle: &PicoSessionHandle) -> WhatAmI {
    handle.ext.mode
}

/// What an entity needs of the session it is declared on, OWNED: the key table
/// and the role.
///
/// A declaring entry point borrows the session handle out of the C handle for
/// the length of its call, and that is all it needs. A composite that declares
/// more entities later — an advanced publisher beaconing from a task, say — has
/// to keep what it declares them with, and the borrowed state cannot be kept. So
/// the two facts every declaration reads are lifted out: the registry the key
/// declarations and the entities live in, and the role the write filter and the
/// retractions follow.
///
/// The registry is held twice while the cooperative engine grows
/// (`docs/capi-pico-on-coop-engine.md`): as the port's [`Engine`], which is all the
/// client surface (keys, publishers, subscribers, matching, write filters) may
/// name, and as the tokio engine's own registry for the capability the port does
/// not carry yet (the advanced plane). A build without it has the port alone,
/// which is what the client surface measures as.
#[derive(Clone)]
pub(crate) struct PicoSession {
    pub(crate) engine: Arc<Engine>,
    #[cfg(feature = "advanced")]
    pub(crate) shared: Arc<SharedSession>,
    pub(crate) mode: WhatAmI,
    /// The session's clock — `NodeHlc::disabled()` for a session this ABI did
    /// not open, which no C entry point can hand it. Read by the advanced plane alone, whose
    /// publisher stamps with it.
    #[cfg(feature = "advanced")]
    pub(crate) hlc: NodeHlc,
}

impl PicoSession {
    /// The session behind a borrowed handle.
    pub(crate) fn of(handle: &PicoSessionHandle) -> Self {
        Self {
            engine: engine_of(handle),
            // A build with the advanced plane runs every session on the tokio engine: the
            // cooperative engine's build does not compile it (decision D4).
            #[cfg(feature = "advanced")]
            shared: handle
                .tokio()
                .expect("a build with the advanced plane opens every session on the tokio engine")
                .shared
                .clone(),
            mode: session_mode(handle),
            #[cfg(feature = "advanced")]
            hlc: handle.ext.hlc.clone(),
        }
    }
}

/// A publisher's or querier's write filter, and the matching listeners declared on it.
/// Dropping it retracts the listeners, then the filter, which releases the Interest it took.
///
/// A matching listener is the filter's: pico registers its callback on the entity's
/// filter (`vendor/zenoh-pico/src/api/api.c` @
/// `ret = _z_matching_listener_register(&_listener_id, _Z_RC_IN_VAL(&sess_rc), &querier->_filter.ctx,`),
/// so it counts what the filter counts, and goes when the filter goes. A background
/// listener, which has no handle, goes with it too.
///
/// Declared BEFORE the entity's key in the owning struct, so the Interest is
/// retracted while the declaration it names still stands — upstream's order
/// (`_z_undeclare_publisher` clears the filter, then the key).
pub(crate) struct WriteFilter {
    shared: Arc<Engine>,
    id: FilterId,
    /// What the filter counts, and on which key: what each of its listeners counts.
    plane: FilterPlane,
    keyexpr: String,
    count_local: bool,
    listeners: Mutex<Vec<MatchId>>,
}

impl WriteFilter {
    /// Create the filter for an entity whose own key is `key`. `count_local` is pico's
    /// `ctx->allow_local`: the session's own subscribers or queryables count too, which
    /// they do for an entity whose destination admits session-local traffic in a build
    /// with the local switch (`vendor/zenoh-pico/src/net/filtering.c` @
    /// `_z_write_filter_session_register`).
    pub(crate) fn declare(
        session: &PicoSession,
        plane: FilterPlane,
        key: &DeclaredKeyexpr,
        count_local: bool,
    ) -> Self {
        let shared = session.engine.clone();
        // The key goes on the wire as the entity's own declaration: its id and the rest of
        // the key, or the literal when nothing covers it.
        let wire = key.wire(&*shared);
        let ask = interest_form(&shared, session.mode, key, &wire);
        let keyexpr = key.literal().to_owned();
        let id = shared.declare_write_filter(plane, keyexpr.clone(), &wire, ask, count_local);
        Self {
            shared,
            id,
            plane,
            keyexpr,
            count_local,
            listeners: Mutex::new(Vec::new()),
        }
    }

    /// Declare a matching listener on this filter (pico `_z_matching_listener_register` on
    /// the entity's filter): `sink` is told whether what the filter counts matches, now and
    /// each time that changes. The listener is retracted with the filter, or before it by
    /// its id. The engine is handed back with the id, for a handle that retracts it.
    pub(crate) fn declare_matching_listener(&self, sink: MatchingSink) -> (Arc<Engine>, MatchId) {
        let id = self.shared.declare_matching_listener(
            self.plane,
            self.keyexpr.clone(),
            sink,
            self.count_local,
        );
        self.listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(id);
        (self.shared.clone(), id)
    }

    /// pico `_z_write_filter_active`: `true` when nothing has said it matches,
    /// which is when the entity must send nothing.
    pub(crate) fn active(&self) -> bool {
        self.shared.write_filter_active(self.id)
    }

    /// Whether the filter keeps a put, a delete or a get from being sent: [`Self::active`],
    /// unless the session holds a multicast group, where pico sends whatever the filter says
    /// (the engine's `write_filter_holds_back`). A matching status still reads
    /// [`Self::active`].
    pub(crate) fn holds_back(&self) -> bool {
        self.shared.write_filter_holds_back(self.id)
    }

    /// [`Self::active`] followed by a plain put on a declared key, in one step of the
    /// registry (the engine's `put_plain_filtered`).
    pub(crate) fn put_plain(
        &self,
        keyexpr: &str,
        mapping_id: u64,
        payload: &[u8],
        params: &wz_session_core::publish_options::PlainPutParams,
    ) -> FilteredPut {
        self.shared
            .put_plain_filtered(self.id, keyexpr, mapping_id, payload, params)
    }
}

/// Retracting on DROP reaches every path that releases the entity: `z_undeclare_*` and
/// `z_*_drop` alike. Retracting a listener its handle already retracted does nothing.
impl Drop for WriteFilter {
    fn drop(&mut self) {
        // Taken out first, so no lock is held while a listener goes: releasing its last
        // `MatchingSink` runs the C `drop(context)`, which may re-enter the session.
        let listeners = std::mem::take(
            self.listeners
                .get_mut()
                .unwrap_or_else(PoisonError::into_inner),
        );
        for id in listeners {
            self.shared.undeclare_matching_listener(id);
        }
        self.shared.undeclare_write_filter(self.id);
    }
}

/// How the entity's Interest is put, or `None` for none — pico's rules, see the
/// module doc.
fn interest_form(
    shared: &Arc<Engine>,
    mode: WhatAmI,
    key: &DeclaredKeyexpr,
    wire: &WireKey,
) -> Option<InterestForm> {
    let client = mode == WhatAmI::Client;
    if !client && !shared.has_router_peer() {
        return None;
    }
    let (mapping_id, suffix) = if wire.mapping_id == 0 {
        (0, Some(key.literal().to_owned()))
    } else {
        (wire.mapping_id, wire.suffix.clone())
    };
    Some(InterestForm {
        mapping_id,
        suffix,
        aggregate: client,
    })
}
