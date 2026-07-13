// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop test — `push` codec (§5 PUSH network
//! envelope; R90 wz-side authoring, R102 Layer 3 byte-compare).
//!
//! First Layer 3 fixture in the R101 rollout that spans a composite
//! envelope shape:
//!
//!   - header byte (MID + N + M + Z flags)
//!   - wireexpr embed (id VLE + parent.N-gated suffix)
//!   - Z-gated ext-chain (qos / timestamp slots — upstream encoder)
//!   - peek-byte variant body (msg_put / msg_del)
//!
//! Scope (R102 first cut, R106 M-flag baking): default state — no
//! extensions, no keyexpr suffix, msg_put inner body with empty
//! payload, mapping=LOCAL ⇒ M flag set in header. Wire shape is
//! [0x5D, 0x00 (wireexpr.id VLE 0), 0x01 (msg_put header MID 0x01),
//! 0x00 (msg_put.payload_len VLE 0)] = 4 bytes (header byte 0x5D =
//! MID 0x1D | M flag at bit 6).
//!
//! Why this matters: wz `Push::default()` defaults the inner-body
//! variant to `CodecZenohMsgPut(MsgPut::default())` per R88 variant-
//! default-uniformity; R106 additionally bakes `M=1` into the header
//! default so a freshly-built Push carries the same M flag that
//! zenoh-pico's `_z_push_encode` derives from
//! `_z_wireexpr_is_local(&_key)` when `_key._mapping = 0` (LOCAL,
//! the natural default). zenoh-pico's `_z_push_encode` reaches the
//! same wire bytes when the fixture sets
//! `_body._is_put = true` (so the encoder picks the PUT branch) AND
//! `_qos._val = 5` (so `has_qos_ext = (val != _Z_N_QOS_DEFAULT._val)`
//! evaluates to false — the extern const lives in zenoh-pico's
//! definitions/network.c L22 with `._val = 5`). The `_key._mapping`
//! field stays at its zero-init default of 0 (LOCAL); the encoder's
//! `is_local` check then sets M=1, matching the R106-baked wz
//! default.

use wz_codecs::push::Push;
use zenoh_pico_sys::{
    _z_bytes_from_buf, _z_bytes_t, _z_id_t, _z_n_msg_push_t, _z_push_encode, _z_slice_t,
    _z_timestamp_t, _z_wbuf_clear, _z_wbuf_make, _z_wbuf_to_zbuf, _z_zbuf_clear,
};

fn zenoh_pico_encode_push_default() -> Vec<u8> {
    // SAFETY: bindgen surfaces `_z_n_msg_push_t` as a struct whose
    // union member `_body._body` (the put / del variant) is opaque
    // bytes. Zero-init via `Default` produces a `_z_n_msg_push_t`
    // where `_qos._val = 0` (NOT the upstream default of 5) and
    // `_body._is_put = false` (would select the del branch). Both
    // must be patched. `_key._mapping = 0 = _Z_KEYEXPR_MAPPING_LOCAL`
    // is now the natural default that matches wz: the encoder's
    // `_z_wireexpr_is_local(&_key)` check sets M=1, and R106 bakes
    // the same M=1 into wz Push::default()'s header.
    unsafe {
        let mut wbf = _z_wbuf_make(64, false);
        let mut msg = _z_n_msg_push_t::default();
        // Match _Z_N_QOS_DEFAULT._val = 5 (definitions/network.c
        // L22) so the encoder's
        // `has_qos_ext = (qos._val != _Z_N_QOS_DEFAULT._val)` check
        // evaluates false and no qos extension is emitted.
        msg._qos._val = 5;
        // Default zenoh-pico zero-init has `_is_put = false` which
        // would route to the DEL branch (header MID 0x02). wz
        // Push::default()'s body defaults to MsgPut so we patch
        // here to match.
        msg._body._is_put = true;
        let ret = _z_push_encode(&mut wbf, &msg);
        assert_eq!(ret, 0, "_z_push_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

// wz-proves: codec-push codec-parity partial
#[test]
fn layer3_push_default_byte_equivalent() {
    let wz = Push::default().encode_to_vec();
    let pico = zenoh_pico_encode_push_default();
    assert_eq!(
        wz, pico,
        "default Push must match zenoh-pico byte-for-byte; \
         wz={wz:02x?} pico={pico:02x?}"
    );
    assert_eq!(
        wz,
        &[0x5D, 0x00, 0x01, 0x00],
        "default wire form: [push_header (MID 0x1D | M flag), wireexpr.id_vle, msg_put_header, payload_len_vle]"
    );
}

// ── R311y263 — a METADATA-BEARING Push, byte-compared against zenoh-pico ──────
//
// Every existing Push compare in this file drives the DEFAULT (no-flag) shape, and the
// same is true of layer3_msg_put. So the body-level metadata slots -- the T-flag
// timestamp (the NTP64 word) and the attachment ext -- had a live wire witness (a real
// pico z_sub_attachment prints them, R311y208/y209) but NO byte-level differential
// against pico's own C encoder. Those are different proofs: the live test shows pico can
// DECODE what wz emits; this one shows wz emits what pico would ENCODE, bit for bit,
// including the flag positions and the ext-chain ordering a decoder is permitted to be
// lenient about.
//
// It also drives the PRODUCTION builder (`build_push_literal_with_meta` -- the SSOT
// `Session::publish` routes through), not a hand-assembled codec struct, so the claim
// binds to the code the atoms are defined as: `attachment-bytes` gates
// `encode_attachment_ext` / `serialize_kv_attachment` (wz-session-core/src/attachment.rs)
// and the builder calls straight into it.

/// A zenoh-pico Push carrying a literal keyexpr, a body-level NTP64 timestamp and an
/// attachment ext -- the shape `build_push_literal_with_meta` emits.
fn zenoh_pico_encode_push_with_meta(
    keyexpr: &str,
    payload: &[u8],
    ts_time: u64,
    ts_zid: &[u8],
    attachment: &[u8],
) -> Vec<u8> {
    // SAFETY: same wbuf-extract path as `zenoh_pico_encode_push_default`. `_key._suffix`
    // borrows the caller's `&str` for the duration of the encode (the encoder only READS
    // it, and a zeroed delete-context is pico's own "not owned" sentinel). The `_body`
    // union is dereferenced as `_put`, the arm selected by the explicit `_is_put = true`.
    // `_z_bytes_from_buf` initialises the zeroed `_z_bytes_t` in place and copies.
    unsafe {
        let mut wbf = _z_wbuf_make(256, false);
        let mut msg = _z_n_msg_push_t::default();
        msg._qos._val = 5;
        msg._body._is_put = true;
        msg._key._suffix._slice = _z_slice_t {
            len: keyexpr.len(),
            start: keyexpr.as_ptr(),
            _delete_context: core::mem::zeroed(),
        };
        // Body-level timestamp (the P_T flag): pico's `_z_timestamp_t` carries the NTP64
        // word plus the zid the stamp was minted under.
        let mut id = _z_id_t { id: [0u8; 16] };
        id.id[..ts_zid.len()].copy_from_slice(ts_zid);
        msg._body._body._put._commons._timestamp = _z_timestamp_t {
            valid: true,
            id,
            time: ts_time,
        };
        let mut payload_bytes: _z_bytes_t = core::mem::zeroed();
        let rc = _z_bytes_from_buf(&mut payload_bytes, payload.as_ptr(), payload.len());
        assert_eq!(rc, 0, "_z_bytes_from_buf failed (payload)");
        msg._body._body._put._payload = payload_bytes;
        let mut att_bytes: _z_bytes_t = core::mem::zeroed();
        let rc = _z_bytes_from_buf(&mut att_bytes, attachment.as_ptr(), attachment.len());
        assert_eq!(rc, 0, "_z_bytes_from_buf failed (attachment)");
        msg._body._body._put._attachment = att_bytes;
        let ret = _z_push_encode(&mut wbf, &msg);
        assert_eq!(ret, 0, "_z_push_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

/// wz's production `build_push_literal_with_meta` must emit the same bytes as
/// zenoh-pico's `_z_push_encode` for a Put carrying a body timestamp + an attachment.
///
/// `time-ntp64` is `partial` here, deliberately: this proves the word's CODEC (both sides
/// put the same 8 distinct bytes on the wire in the same place), but NOT its
/// CONSTRUCTION -- and the two implementations DISAGREE there. zenoh-pico's composer adds
/// one tick that zenoh's own uhlc does not (`layer3_ntp64.rs` pins it), so the same
/// instant is labelled one tick apart. The codec agreeing does not make the atom whole.
// wz-proves: codec-push codec-parity partial
// wz-proves: pubsub-timestamp codec-parity partial
// wz-proves: time-ntp64 codec-parity partial
// wz-proves: attachment-bytes codec-parity partial
// wz-proves: pubsub-attachment codec-parity partial
#[test]
fn layer3_push_with_timestamp_and_attachment_byte_equivalent() {
    use wz_session_core::metadata::PushMetadata;
    use wz_session_core::push_build::build_push_literal_with_meta;
    use wz_session_core::sample::TimestampHint;

    const KEYEXPR: &str = "demo/meta";
    const PAYLOAD: &[u8] = b"meta-bearing-put";
    const ATTACHMENT: &[u8] = b"att-blob";
    // Eight DISTINCT bytes: any byte-order, offset or width error in the NTP64 word
    // codec changes the wire and the compare fails.
    const TS_TIME: u64 = 0x0102_0304_0506_0708;
    const TS_ZID: &[u8] = &[0xAA, 0xBB, 0xCC];

    let owned = build_push_literal_with_meta(
        KEYEXPR,
        PAYLOAD,
        &PushMetadata {
            timestamp: Some(TimestampHint {
                time: TS_TIME,
                zid: TS_ZID.to_vec(),
            }),
            attachment: Some(ATTACHMENT.to_vec()),
            ..Default::default()
        },
    )
    .expect("wz meta-bearing push builds");
    let wz = owned
        .try_as_borrowed()
        .expect("borrow the owned push")
        .encode_to_vec();
    let pico = zenoh_pico_encode_push_with_meta(KEYEXPR, PAYLOAD, TS_TIME, TS_ZID, ATTACHMENT);

    assert_ne!(
        pico,
        zenoh_pico_encode_push_default(),
        "anti-vacuity: the timestamp + attachment must actually reach the wire, else both \
         sides could agree by emitting the bare default envelope"
    );
    assert_eq!(
        wz, pico,
        "a Push carrying a body timestamp + attachment must match zenoh-pico \
         byte-for-byte; wz={wz:02x?} pico={pico:02x?}"
    );
}
