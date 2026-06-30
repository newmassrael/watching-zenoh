// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "routing-namespace",
    feature = "declare-keyexpr",
    feature = "transport-unicast"
))]

//! §5.21 routing-namespace — the LIVE `DeclareKeyExpr` alias-definition egress
//! seam (R311y106 session-review finding).
//!
//! The high-level aliased publish/query optimization (`publish_aliased` /
//! `query_aliased` / `*_auto`) requires the app to first declare a keyexpr alias
//! via `SessionLinkActions::send_declare_keyexpr`. That alias DEFINITION is
//! dispatched directly (a `dispatch_declare`, below the unicast egress arm), so
//! it must be re-decorated at the seam — otherwise the peer registers the BARE
//! keyexpr and a subsequent aliased `Push`/`Request` (which the decorator passes
//! through unchanged, id != 0) resolves at the peer to the bare keyexpr, leaking
//! the aliased publish OUTSIDE the namespace. This was the exact asymmetry the
//! session review caught: the reconnect REPLAY of this same declaration was
//! namespaced, but the LIVE original was not.
//!
//! This drives the actions seam directly (a recording link driver, no socket):
//! install a namespace, `send_declare_keyexpr(5, "zenoh/alias")`, and assert the
//! emitted wire `DeclareKeyExpr` carries the NAMESPACED keyexpr. It fails (bare
//! keyexpr) if the live alias-definition egress is absent.

use std::sync::Arc;

use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::new_session_actions;
use wz_runtime_tokio_test_support::{fixture_params_with_zid, LifecycleRecordingDriver};
use wz_session_core::keyexpr_prefix::OwnedNonWildKeyExpr;

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn live_keyexpr_alias_definition_ships_namespaced() {
    let driver = Arc::new(LifecycleRecordingDriver::default());
    let actions = new_session_actions(
        driver.clone(),
        fixture_params_with_zid(0x01),
        TokioTime::new(),
    );

    actions.set_namespace(OwnedNonWildKeyExpr::new("myns").expect("valid namespace"));

    // Declare a keyexpr alias as the aliased high-level API requires the app to.
    actions
        .send_declare_keyexpr(5, "zenoh/alias")
        .expect("declare keyexpr alias");

    let sends = driver.snapshot().sends;
    assert!(
        sends
            .iter()
            .any(|(bytes, _)| contains_subslice(bytes, b"myns/zenoh/alias")),
        "the LIVE alias DEFINITION ships the namespaced keyexpr myns/zenoh/alias; \
         got {} frame(s) — a bare keyexpr would leak aliased publishes outside the namespace",
        sends.len(),
    );
}
