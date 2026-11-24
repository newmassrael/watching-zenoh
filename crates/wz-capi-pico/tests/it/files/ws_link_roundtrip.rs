// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(feature = "transport-link-ws")]

//! The `ws/` link through the pico C ABI: a session listening on a `ws/` endpoint receives a
//! sample put by a session that dialled it.
//!
//! zenoh-pico builds this link under `Z_FEATURE_LINK_WS` (default 0), and this crate's twin is
//! `transport-link-ws`, off by default and on either engine: the tokio engine's WebSocket link,
//! or on the cooperative engine WebSocket links over the host's TCP beside its sockets. A
//! cooperative build without it fails the open of a `ws/` endpoint (`ws_link_refused`).
//!
//! RED reproduction: on the cooperative engine, open the session over its sockets' links alone
//! (drop `coop_host::with_ws` from `open_on_coop` in `src/session.rs`), and the listener's
//! `z_open` fails, its `ws/` locator refused as `Unsupported`; on the tokio engine, drop
//! `wz-runtime-tokio/transport-link-ws` from `wz-capi-core`'s `transport-link-ws`.

// One sample across each forwarded link; each file is also `cfg`'d on its link feature.
#![cfg(feature = "peer")]

use crate::link_roundtrip::{payloads_across, PAYLOAD};
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
