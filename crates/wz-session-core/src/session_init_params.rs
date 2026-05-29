// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ej — per-deploy session handshake parameters lifted from
//! `wz-runtime-tokio::session_glue`.
//!
//! `SessionInitParams` is the bundle of codec field values that drive
//! the 4-way handshake + close (version / whatami / zid / resolutions /
//! batch size / lease / cookie + signing key). It is a pure owned value
//! type — alloc-gated (it holds `Vec<u8>` zid + cookie and a
//! [`crate::signing_key::SigningKey`]) with no codec / async / tokio
//! coupling, so it belongs on the runtime-agnostic side: an MCU profile
//! drives the session FSM with the same typed params as the tokio AP
//! profile. This move was unblocked by R311ei lifting `SigningKey` into
//! this crate (the field's type now resolves here). `session_glue.rs`
//! keeps a `pub use` re-export so the `crate::session_glue::SessionInitParams`
//! callsites (the `SessionLinkActions::params` field, `session.rs`,
//! `wz-ap-demo`, and the `fixture_session_init_params` test-support
//! builder) resolve unchanged. A DP3 leaf out of `session_glue.rs`.

use alloc::vec::Vec;

use crate::signing_key::SigningKey;

/// Per-deploy parameters that drive the codec field values for the
/// 4-way handshake + close. Production callers source these from
/// `deploy.yaml`; tests pass fixed values for reproducible wire bytes.
#[derive(Debug, Clone)]
pub struct SessionInitParams {
    /// Protocol version (zenoh: 0x05 at the time of writing).
    pub version: u8,
    /// API-form whatami: `0x01` Router, `0x02` Peer, `0x04` Client.
    /// The codec packs the wire-form 2-bit field per
    /// `_z_whatami_to_uint8` (transport.c:31-37).
    pub whatami: u8,
    /// ZenohID — 1..=16 bytes. The codec encodes the length in the
    /// high 4 bits of `cbyte` as `zid_len - 1`.
    pub zid: Vec<u8>,
    /// Sequence-number resolution (0..=3 → 8 / 16 / 32 / 64-bit).
    pub seq_num_res: u8,
    /// Request-id resolution (0..=3).
    pub req_id_res: u8,
    /// Per-link batch size (bytes). Transport.h documents 1..=65535.
    pub batch_size: u16,
    /// Lease duration. The `lease_in_seconds` flag below picks the
    /// unit; the value itself is VLE-encoded inside the open body.
    pub lease: u64,
    /// `_Z_FLAG_T_OPEN_T` semantics: when true the wire encodes the
    /// `lease` field as seconds (set the flag); when false it
    /// encodes milliseconds (clear the flag).
    pub lease_in_seconds: bool,
    /// Initial sequence number for the reliable channel (VLE-encoded
    /// inside the open body).
    pub initial_sn: u64,
    /// Cookie material exchanged on the InitAck → OpenSyn echo path.
    ///
    /// On the Initiator side this is the bytes received in the
    /// peer's InitAck; the Initiator re-emits them verbatim in the
    /// OpenSyn frame so the peer can MAC-verify ownership of the
    /// session start.
    ///
    /// On the Accepting side this MUST be generated via
    /// `generate_cookie_hmac_sha256(cookie_signing_key, peer_zid)`
    /// per RFC §5.M. The integration test fixture matches this
    /// path so the wire bytes are reproducible across runs.
    pub cookie: Vec<u8>,

    /// Per-process secret key used by the Accepting side to MAC the
    /// outbound cookie. Constructed via `SigningKey::new(bytes)` so
    /// length validation (>= 32 bytes per RFC §5.M) + drop-time
    /// zeroize are enforced by the type. Initiator side does not
    /// consume this field; the cookie value flows inbound from the
    /// peer's InitAck instead.
    pub cookie_signing_key: SigningKey,
}

// `SessionInitParams` carries no test-only methods. The deterministic
// fixture builder (formerly `for_test`) lives in the
// `wz-runtime-tokio-test-support` sibling crate (R71) so production
// builds carry no test-only code path. `SessionInitParams`
// intentionally has no `Default` impl — production callers MUST source
// every field from `deploy.yaml` (or another configured source), and
// the fixture stays behind the test-support crate boundary.
