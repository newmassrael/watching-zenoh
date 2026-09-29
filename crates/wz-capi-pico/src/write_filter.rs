// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! ⚠ ONE DIVERGENCE IS NOT REPRODUCED, and it is upstream's: a pico peer that
//! asked never sends the `Interest(Final)` — `_z_remove_interest` sends it for a
//! client (or multicast) only — so the router keeps the interest until the
//! session closes. wz retracts it, which no program can observe and which costs
//! the peer nothing to hold. A peer-mode differential would name the difference,
//! and the leg that adds one decides whether to pin it or to mirror the leak.

use std::sync::Arc;

use wz_capi_core::drive::SessionState;
use wz_capi_core::faces::{FilterId, FilterPlane, SharedSession};
use wz_runtime_tokio::session::InterestForm;
use wz_runtime_tokio::session_glue::WhatAmI;

use crate::keyexpr::DeclaredKeyexpr;

/// This session's own role — pico's `zn->_mode`.
///
/// Attached to the session at open ([`SessionState::set_abi_extension`]) because
/// the role is decided by the C config (`Z_CONFIG_MODE_KEY`, and a `listen`
/// config forces peer) and nothing downstream of the open can recover it: a
/// face records the PEER's role, not ours.
pub(crate) struct PicoSessionMode(pub(crate) WhatAmI);

/// A publisher's or querier's write filter. Dropping it retracts the filter,
/// which releases the Interest it took.
///
/// Declared BEFORE the entity's key in the owning struct, so the Interest is
/// retracted while the declaration it names still stands — upstream's order
/// (`_z_undeclare_publisher` clears the filter, then the key).
pub(crate) struct WriteFilter {
    shared: Arc<SharedSession>,
    id: FilterId,
}

impl WriteFilter {
    /// Create the filter for an entity whose own key is `key`.
    pub(crate) fn declare(state: &SessionState, plane: FilterPlane, key: &DeclaredKeyexpr) -> Self {
        let shared = state.shared.clone();
        let mode = state
            .abi_extension::<PicoSessionMode>()
            .map(|m| m.0)
            .unwrap_or(WhatAmI::Client);
        let ask = interest_form(&shared, mode, key);
        let id = shared.declare_write_filter(plane, key.literal().to_owned(), ask);
        Self { shared, id }
    }

    /// pico `_z_write_filter_active`: `true` when nothing has said it matches,
    /// which is when the entity must send nothing.
    pub(crate) fn active(&self) -> bool {
        self.shared.write_filter_active(self.id)
    }
}

impl Drop for WriteFilter {
    fn drop(&mut self) {
        self.shared.undeclare_write_filter(self.id);
    }
}

/// How the entity's Interest is put, or `None` for none — pico's rules, see the
/// module doc.
fn interest_form(
    shared: &Arc<SharedSession>,
    mode: WhatAmI,
    key: &DeclaredKeyexpr,
) -> Option<InterestForm> {
    let client = mode == WhatAmI::Client;
    if !client && !shared.has_router_peer() {
        return None;
    }
    // The key goes on the wire as the entity's own declaration: its id and the
    // rest of the key, or the literal when nothing covers it.
    let wire = key.wire(shared);
    let (mapping_id, suffix) = if wire.mapping_id == 0 {
        (0, Some(key.literal().to_owned()))
    } else {
        (wire.mapping_id, wire.suffix)
    };
    Some(InterestForm {
        mapping_id,
        suffix,
        aggregate: client,
    })
}
