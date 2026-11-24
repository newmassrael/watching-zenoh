// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "transport-link-unixpipe", target_os = "linux"))]

//! The `unixpipe/` link through the pico C ABI: a session listening on a base path receives a
//! sample put by a session that dialled the same path, over the pair of named FIFOs the dial
//! reserved and the listener confirmed.
//!
//! zenoh-pico has no such link; this crate carries zenoh's under `transport-link-unixpipe`, off
//! by default and on either engine: the tokio engine's unixpipe link, or on the cooperative engine
//! the host's named FIFOs beside its sockets. A cooperative build without it refuses the scheme
//! (`unixpipe_link_refused`).
//!
//! The base path is short on purpose: the cooperative engine holds a base path in a row of
//! `MAX_LOCATOR_LEN` bytes less `unixpipe/` and the longest suffix of an end's FIFO, so a path
//! under a long temporary directory would be refused before anything is opened.
//!
//! RED reproduction: on the cooperative engine, open the session over its sockets' links alone
//! (drop `coop_host::with_unixpipe` from `open_on_coop` in `src/session.rs`), and the
//! listener's `z_open` fails, its `unixpipe/` locator refused as `Unsupported`; on the tokio
//! engine, drop `wz-runtime-tokio/transport-link-unixpipe` from `wz-capi-core`'s
//! `transport-link-unixpipe`.

#![cfg(feature = "peer")]

use crate::link_roundtrip::{payloads_across, PAYLOAD};

#[test]
fn a_sample_crosses_a_unixpipe_link_between_two_pico_sessions() {
    let endpoint = format!("unixpipe//tmp/wzpr{}", std::process::id());
    let received = payloads_across(&endpoint, &endpoint);
    assert_eq!(
        received.first().map(Vec::as_slice),
        Some(PAYLOAD.to_bytes()),
        "nothing, or something else, reached the unixpipe listener's subscriber: {received:?}"
    );
}
