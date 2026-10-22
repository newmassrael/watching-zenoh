// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(feature = "transport-link-ws")]

//! The `ws/` link through the pico C ABI: a session listening on a `ws/` endpoint receives a
//! sample put by a session that dialled it.
//!
//! zenoh-pico builds this link under `Z_FEATURE_LINK_WS` (default 0), and this crate's twin is
//! `transport-link-ws`, off by default, so the file compiles only where that feature is on.
//! The refusal in a build without it is the runtime's typed `Unsupported` at bind and dial,
//! which `wz-runtime-tokio`'s `session_open` tests hold; it is not asserted here because a
//! workspace build can turn the runtime's backend on through another crate.
//!
//! RED reproduction: drop `wz-runtime-tokio/transport-link-ws` from this crate's
//! `transport-link-ws` feature and from `wz-capi-core`'s (the runtime backend is then compiled
//! out in a `-p wz-capi-pico` build), and the listener's `z_open` fails at bind.

mod link_roundtrip;

use link_roundtrip::{payloads_across, PAYLOAD};
use wz_runtime_tokio_test_support::free_port;

#[test]
fn a_sample_crosses_a_ws_link_between_two_pico_sessions() {
    let endpoint = format!("ws/127.0.0.1:{}", free_port());
    let received = payloads_across(&endpoint, &endpoint);
    assert_eq!(
        received.first().map(Vec::as_slice),
        Some(PAYLOAD.to_bytes()),
        "nothing, or something else, reached the ws listener's subscriber: {received:?}"
    );
}
