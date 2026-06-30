// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "routing-namespace",
    feature = "session-reconnect",
    feature = "declare-subscriber",
    feature = "transport-unicast"
))]

//! §5.21 routing-namespace — the reconnect declaration-replay EGRESS seam
//! (R311y106 implementation-panel finding).
//!
//! The LIVE declare path is namespaced at the unicast `Tp::send_network_message`
//! arm, and the reconnect declaration cache stores the BARE (application)
//! keyexpr. On reconnect the supervisor REUSES the same `SessionLinkActions`
//! (only the link is swapped, via `SwappableLink`), so the installed namespace
//! survives — but `replay_one` re-emits the cached declares via a DIRECT
//! `dispatch_declare` that bypasses the egress arm. Without the replay-side
//! decorator (`replay_namespace_declare`) the replayed declare would ship
//! un-namespaced, and a namespaced peer would silently drop it — so after a
//! reconnect the session's remote subscriptions would stop being honored.
//!
//! This test drives the actions seam directly (a recording link driver, no
//! socket): install a namespace, cache a BARE subscriber declaration as the live
//! high-level `declare_subscriber` does, then `replay_declarations` as a
//! reconnect would — and assert the replayed wire carries the NAMESPACED keyexpr.
//! It fails (bare keyexpr on the wire) if the replay-side egress is absent.

use std::sync::Arc;

use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::new_session_actions;
use wz_runtime_tokio_test_support::{fixture_params_with_zid, LifecycleRecordingDriver};
use wz_session_core::keyexpr_prefix::OwnedNonWildKeyExpr;

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn reconnect_replay_re_decorates_the_cached_declare() {
    let driver = Arc::new(LifecycleRecordingDriver::default());
    let actions = new_session_actions(
        driver.clone(),
        fixture_params_with_zid(0x01),
        TokioTime::new(),
    );

    // Install the namespace (survives reconnect — the actions bundle is reused).
    actions.set_namespace(OwnedNonWildKeyExpr::new("myns").expect("valid namespace"));

    // Cache a subscriber declaration with the BARE keyexpr — exactly what the
    // live `Session::declare_subscriber` caches AFTER its egress-namespaced wire
    // emit (`session/mod.rs` `cache_subscriber_declaration`).
    actions.cache_subscriber_declaration(10, 0, Some("zenoh/sub"));

    // Replay the cache as the reconnect supervisor does after a re-handshake.
    let replayed = actions.replay_declarations().expect("replay succeeds");
    assert_eq!(replayed, 1, "exactly the one cached declaration replays");

    // The replayed declare must ship the NAMESPACED keyexpr — proving the replay
    // seam re-applies the egress decorator (the cache held only the bare form).
    let sends = driver.snapshot().sends;
    assert!(
        sends
            .iter()
            .any(|(bytes, _)| contains_subslice(bytes, b"myns/zenoh/sub")),
        "the replayed DeclareSubscriber carries the namespaced keyexpr myns/zenoh/sub; \
         got {} frame(s) — a bare keyexpr means the reconnect-replay egress is missing",
        sends.len(),
    );
}
