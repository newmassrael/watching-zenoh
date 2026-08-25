// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop test — `request` codec (§5 REQUEST network
//! envelope; R90 wz-side authoring, R108a mid-defect fix, R108b
//! Layer 3 byte-compare).
//!
//! Closes the application-layer envelope wire-interop debt at 6/6
//! MIDs. REQUEST is the most-ext-rich envelope in the post-R90 set
//! (5 ext slots in `_z_n_msg_request_t`: qos / timestamp / target /
//! budget / timeout) plus an inner-body variant whose declared
//! default arm (R88 variant-default-uniformity) selects `Query` —
//! a separate codec with its own header, gates, and ext chain.
//!
//! Three reasons the wire matches on default state with only two
//! fixture patches:
//!
//! 1. zenoh-pico's `_z_n_msg_request_needed_exts` only marks
//!    `ext_qos` as needed by default (it compares `_val` against
//!    the `_Z_N_QOS_DEFAULT` sentinel of 5; zero-init's val of 0
//!    differs from 5, so qos is on). The other 4 ext checks all
//!    evaluate false for the zero-init message. Patch `_ext_qos._val
//!    = 5` and `exts.n` drops to 0 → the envelope's Z flag stays
//!    clear and no ext slot is emitted.
//! 2. `_z_query_encode` (message.c:394) sets the inner Q_C flag from
//!    `_consolidation != Z_CONSOLIDATION_MODE_DEFAULT`. Zero-init's
//!    `_consolidation = 0 = Z_CONSOLIDATION_MODE_NONE` differs from
//!    the AUTO sentinel (-1). Patch `_consolidation = -1` to keep
//!    Q_C clear.
//! 3. `_tag = _Z_REQUEST_QUERY` (= 0, first enum variant) is the
//!    zero-init default, which routes the encoder into
//!    `_z_query_encode(wbf, &msg->_body._query)` — exactly the
//!    branch wz Request's R88 default arm picks.
//!
//! Wire shape: `[0x5C, 0x00, 0x00, 0x03]` = 4 bytes =
//! request_header (MID 0x1C | M flag, R106 baking; M=1 set by pico
//! encoder via `_z_wireexpr_is_local` when `_key._mapping = 0`) +
//! rid VLE 0 + wireexpr.id VLE 0 (no suffix) + query inner header
//! (MID 0x03, all Q_C/Q_P/Z flags clear).

use wz_codecs::request::Request;
use zenoh_pico_sys::{
    _z_bytes_from_buf, _z_bytes_t, _z_n_msg_request_t, _z_request_encode, _z_slice_t,
    _z_wbuf_clear, _z_wbuf_make, _z_wbuf_to_zbuf, _z_zbuf_clear,
};

fn zenoh_pico_encode_request_default() -> Vec<u8> {
    // SAFETY: standard wbuf-extract path. The two field writes
    // (`_ext_qos._val` and `_body._query._consolidation`) target
    // primitive members exposed by bindgen as plain struct fields;
    // no union-discriminant invariant is touched. The `_body`
    // member is a `__bindgen_ty_*` union, but we only access the
    // `_query` arm — which is also the arm selected by the
    // zero-init `_tag = 0 = _Z_REQUEST_QUERY`, so this access is
    // sound under the C-side memory layout.
    unsafe {
        let mut wbf = _z_wbuf_make(64, false);
        let mut msg = _z_n_msg_request_t::default();
        // (1) qos default sentinel — see layer3_push.rs comment.
        //     `_Z_N_QOS_DEFAULT._val = 5` in definitions/network.c
        //     L22; zero-init's `_val = 0` triggers
        //     `needed_exts.ext_qos = true` → wire emits the qos ext
        //     slot. Patching to 5 keeps the envelope ext chain
        //     empty (envelope Z stays clear).
        msg._ext_qos._val = 5;
        // (2) query inner consolidation default — same shape as
        //     R105 reply consolidation. Z_CONSOLIDATION_MODE_DEFAULT
        //     equals AUTO (-1); zero-init's NONE (0) differs, so
        //     `_z_query_encode` sets Q_C and emits an extra byte.
        //     Patch to -1 keeps the inner header at bare 0x03.
        msg._body._query._consolidation = -1;
        let ret = _z_request_encode(&mut wbf, &msg);
        assert_eq!(ret, 0, "_z_request_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

// wz-proves: codec-request codec-parity partial
#[test]
fn layer3_request_default_byte_equivalent() {
    let wz = Request::default().encode_to_vec();
    let pico = zenoh_pico_encode_request_default();
    assert_eq!(
        wz, pico,
        "default REQUEST must match zenoh-pico byte-for-byte; \
         wz={wz:02x?} pico={pico:02x?}"
    );
    assert_eq!(
        wz,
        &[0x5C, 0x00, 0x00, 0x03],
        "default wire form: request_hdr (MID 0x1C | M flag) + rid + ke.id + query_hdr (MID 0x03)"
    );
}

// R311y248 — encode a default REQUEST(Query) carrying a VALUE ext (id 0x03) via
// zenoh-pico. Identical to the default builder above except `_ext_value.payload`
// is set from `payload`: `_z_msg_query_required_extensions.body` then flips true
// (`_z_bytes_check(payload)`), so `_z_query_encode` sets the inner Q_Z (0x80)
// flag and emits the `ENC_ZBUF | 0x03` value ext = `_z_value_encode` =
// `zsize(total) || encoding || payload`. The encoding stays zero-init (id 0, no
// schema) so `_z_encoding_encode` writes a single `0x00`.
fn zenoh_pico_encode_request_query_value(payload: &[u8]) -> Vec<u8> {
    // SAFETY: same wbuf-extract path as `zenoh_pico_encode_request_default`.
    // `_z_bytes_from_buf` initialises the zeroed `_z_bytes_t` in place and
    // copies `payload`; `_ext_value.payload` is a plain struct member on the
    // `_query` union arm selected by the zero-init `_tag = _Z_REQUEST_QUERY`.
    unsafe {
        let mut wbf = _z_wbuf_make(64, false);
        let mut msg = _z_n_msg_request_t::default();
        msg._ext_qos._val = 5;
        msg._body._query._consolidation = -1;
        let mut payload_bytes: _z_bytes_t = core::mem::zeroed();
        let rc = _z_bytes_from_buf(&mut payload_bytes, payload.as_ptr(), payload.len());
        assert_eq!(rc, 0, "_z_bytes_from_buf failed");
        msg._body._query._ext_value.payload = payload_bytes;
        let ret = _z_request_encode(&mut wbf, &msg);
        assert_eq!(ret, 0, "_z_request_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

/// Layer 3 byte-parity for the Query VALUE ext (Q_B / Q_E, R311y248): wz's
/// production `RequestQueryBuilder::query_value(payload, default-encoding)` must
/// emit the same bytes as zenoh-pico's `_z_request_encode` with
/// `_ext_value.payload` set — proving the value ext (header `0x43`, the
/// ExtZbuf/pico-`zsize` length prefix, `encoding || payload` body) and the inner
/// Q_Z (0x80) flag compose byte-for-byte on the wire.
// wz-proves: codec-request codec-parity partial
// wz-proves: query-value codec-parity partial
#[test]
fn layer3_request_query_value_byte_equivalent() {
    use wz_session_core::request_build::RequestQueryBuilder;
    use wz_session_core::sample::EncodingHint;

    const PAYLOAD: &[u8] = b"the-query-value";
    let owned = RequestQueryBuilder::new(0, 0, None)
        .query_value(
            PAYLOAD,
            EncodingHint {
                packed_id: 0,
                schema: None,
            },
        )
        .build()
        .expect("wz query-value request builds");
    let wz = owned
        .try_as_borrowed()
        .expect("borrow the owned request")
        .encode_to_vec();
    let pico = zenoh_pico_encode_request_query_value(PAYLOAD);
    assert_eq!(
        wz, pico,
        "REQUEST(Query) with a VALUE ext must match zenoh-pico byte-for-byte; \
         wz={wz:02x?} pico={pico:02x?}"
    );
    // Explicit wire lock (secondary to the live-FFI compare): base
    // [0x5C, 0x00, 0x00] + query_hdr 0x83 (MID 0x03 | Q_Z 0x80) + value ext
    // [0x43 (ENC_ZBUF|0x03), 0x10 (zsize = 1 enc byte + 15 payload), 0x00
    // (default encoding), then the 15 payload bytes].
    let mut expected = std::vec![0x5C_u8, 0x00, 0x00, 0x83, 0x43, 0x10, 0x00];
    expected.extend_from_slice(PAYLOAD);
    assert_eq!(wz, expected, "value-ext wire layout locked");
}

// ── R311y261 — the QUERY KNOBS, byte-compared against zenoh-pico ──────────────
//
// R311y248 proved the Query VALUE ext. The other five knobs the zenoh Query/Request
// wire carries had never been checked against a foreign encoder at all: the two
// REQUEST-level exts (`_ext_target` id 0x05, `_ext_timeout_ms` id 0x07) and the three
// QUERY-body fields (`_consolidation` behind the Q_C flag, `_parameters` behind Q_P,
// and the `_ext_attachment` ext). Each is an independent chance for wz and zenoh-pico
// to disagree about a flag bit, an ext id, or a length prefix -- and a disagreement is
// invisible locally: wz's own round-trip tests would still pass while a real pico
// queryable silently ignored (or mis-read) the knob.
//
// zenoh-pico's defaults are the reason each knob is a DISCRIMINATING witness: the
// encoder only emits an ext when its value differs from the sentinel
// (`_z_n_msg_request_needed_exts` / `_z_msg_query_required_extensions`), so a wz that
// dropped a knob would emit the bare 4-byte default envelope and the compare fails.

/// A zenoh-pico `_z_n_msg_request_t` carrying exactly one Query knob.
///
/// Collapsing the five cases into one patch-set keeps the unsafe surface to a single
/// audited block instead of five near-duplicates.
#[derive(Default)]
struct PicoQueryKnobs<'a> {
    /// `z_query_target_t`; sentinel `Z_QUERY_TARGET_BEST_MATCHING = 0`.
    target: Option<u32>,
    /// `_ext_timeout_ms`; sentinel 0 (absent).
    timeout_ms: Option<u64>,
    /// `z_consolidation_mode_t`; sentinel `Z_CONSOLIDATION_MODE_DEFAULT = AUTO = -1`.
    consolidation: Option<i32>,
    /// Query-body `_parameters` (Q_P flag).
    parameters: Option<&'a [u8]>,
    /// Query-body `_ext_attachment`.
    attachment: Option<&'a [u8]>,
}

fn zenoh_pico_encode_request_query_knobs(k: &PicoQueryKnobs<'_>) -> Vec<u8> {
    // SAFETY: same wbuf-extract path as `zenoh_pico_encode_request_default`, with the
    // same two default patches. `_parameters` is a plain `_z_slice_t { len, start,
    // _delete_context }` that the ENCODER only READS -- it is borrowed from the caller's
    // slice for the duration of `_z_request_encode` and never dropped by pico (we do not
    // call `_z_n_msg_request_clear`), so a zeroed delete-context is correct here.
    // `_z_bytes_from_buf` initialises the zeroed `_z_bytes_t` in place and copies.
    unsafe {
        let mut wbf = _z_wbuf_make(128, false);
        let mut msg = _z_n_msg_request_t::default();
        msg._ext_qos._val = 5;
        msg._body._query._consolidation = k
            .consolidation
            .unwrap_or(zenoh_pico_sys::z_consolidation_mode_t_Z_CONSOLIDATION_MODE_DEFAULT);
        if let Some(t) = k.target {
            msg._ext_target = t;
        }
        if let Some(ms) = k.timeout_ms {
            msg._ext_timeout_ms = ms;
        }
        if let Some(p) = k.parameters {
            msg._body._query._parameters = _z_slice_t {
                len: p.len(),
                start: p.as_ptr(),
                _delete_context: core::mem::zeroed(),
            };
        }
        let mut att_bytes: _z_bytes_t = core::mem::zeroed();
        if let Some(a) = k.attachment {
            let rc = _z_bytes_from_buf(&mut att_bytes, a.as_ptr(), a.len());
            assert_eq!(rc, 0, "_z_bytes_from_buf failed");
            msg._body._query._ext_attachment = att_bytes;
        }
        let ret = _z_request_encode(&mut wbf, &msg);
        assert_eq!(ret, 0, "_z_request_encode failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let bytes = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);
        bytes
    }
}

/// wz's `RequestQueryBuilder::request_target(All)` must encode the REQUEST-level target
/// ext byte-for-byte as zenoh-pico's `_ext_target = Z_QUERY_TARGET_ALL`.
// wz-proves: query-target codec-parity partial
// wz-proves: codec-request codec-parity partial
#[test]
fn layer3_request_target_byte_equivalent() {
    use wz_session_core::query_mode::QueryTarget;
    use wz_session_core::request_build::RequestQueryBuilder;

    for (wz_target, pico_target) in [
        (
            QueryTarget::All,
            zenoh_pico_sys::z_query_target_t_Z_QUERY_TARGET_ALL,
        ),
        (
            QueryTarget::AllComplete,
            zenoh_pico_sys::z_query_target_t_Z_QUERY_TARGET_ALL_COMPLETE,
        ),
    ] {
        let owned = RequestQueryBuilder::new(0, 0, None)
            .request_target(wz_target)
            .build()
            .expect("wz target request builds");
        let wz = owned
            .try_as_borrowed()
            .expect("borrow the owned request")
            .encode_to_vec();
        let pico = zenoh_pico_encode_request_query_knobs(&PicoQueryKnobs {
            target: Some(pico_target),
            ..Default::default()
        });
        assert_ne!(
            pico,
            zenoh_pico_encode_request_default(),
            "anti-vacuity: the target ext must actually reach the wire, else wz and pico \
             would agree by both emitting nothing"
        );
        assert_eq!(
            wz, pico,
            "REQUEST target ext ({wz_target:?}) must match zenoh-pico byte-for-byte; \
             wz={wz:02x?} pico={pico:02x?}"
        );
    }
}

/// wz's `RequestQueryBuilder::request_timeout_ms` must encode the REQUEST-level timeout
/// ext byte-for-byte as zenoh-pico's `_ext_timeout_ms`.
// wz-proves: query-timeout codec-parity partial
// wz-proves: codec-request codec-parity partial
#[test]
fn layer3_request_timeout_byte_equivalent() {
    use wz_session_core::request_build::RequestQueryBuilder;

    // A one-byte VLE (1) and a multi-byte one (5000) — the ext's length prefix is where
    // a zint-vs-zint64 disagreement would surface.
    for timeout_ms in [1_u64, 5_000, 4_294_967_296] {
        let owned = RequestQueryBuilder::new(0, 0, None)
            .request_timeout_ms(timeout_ms)
            .build()
            .expect("wz timeout request builds");
        let wz = owned
            .try_as_borrowed()
            .expect("borrow the owned request")
            .encode_to_vec();
        let pico = zenoh_pico_encode_request_query_knobs(&PicoQueryKnobs {
            timeout_ms: Some(timeout_ms),
            ..Default::default()
        });
        assert_ne!(
            pico,
            zenoh_pico_encode_request_default(),
            "anti-vacuity: the timeout ext must actually reach the wire"
        );
        assert_eq!(
            wz, pico,
            "REQUEST timeout ext ({timeout_ms} ms) must match zenoh-pico byte-for-byte; \
             wz={wz:02x?} pico={pico:02x?}"
        );
    }
}

/// wz's `RequestQueryBuilder::consolidation` must produce zenoh-pico's Query
/// SHAPE — same length, same Q_C flag, same field position — and must differ
/// from it in EXACTLY ONE BYTE: the mode value, which wz numbers one higher
/// because it follows zenoh and pico does not.
///
/// # Why this test asserts a difference where it used to assert equality
///
/// R311y837 measured the field on both reference planes by execution
/// (`query_consolidation_wire_byte_divergence.rs`): asked for the same logical
/// mode, a stock zenohd wrote `3` and a stock zenoh-pico wrote `2`. The two
/// upstreams genuinely disagree, and pico is the one that is off — it encodes
/// its API enum raw while its `AUTO = -1` sentinel is never written, so every
/// mode lands one slot below zenoh's `Auto=0 / None=1 / Monotonic=2 / Latest=3`.
/// wz follows zenoh, because zenoh-protocol defines this wire and a zenohd is
/// the router a deployment has.
///
/// So byte-equality with pico is no longer the property wz wants, and asserting
/// it would pin pico's defect. What this test pins instead is STRICTLY STRONGER
/// than the old equality was for everything except the one value: every other
/// byte still has to match the foreign encoder, the divergence has to be exactly
/// one byte wide, and its magnitude has to be exactly the one-slot shift the
/// measurement explains. A wz that regressed to pico's numbering reds here; so
/// does a wz that moved the field, resized it, or dropped the flag.
// wz-proves: query-consolidation codec-parity partial
// wz-proves: codec-request codec-parity partial
#[test]
fn layer3_request_consolidation_diverges_from_zenoh_pico_by_exactly_one_slot() {
    use wz_session_core::query_mode::ConsolidationMode;
    use wz_session_core::request_build::RequestQueryBuilder;

    // AUTO (-1) is pico's sentinel and emits nothing, so the three explicit modes are
    // exactly the discriminating set.
    for (wz_mode, pico_mode) in [
        (
            ConsolidationMode::None,
            zenoh_pico_sys::z_consolidation_mode_t_Z_CONSOLIDATION_MODE_NONE,
        ),
        (
            ConsolidationMode::Monotonic,
            zenoh_pico_sys::z_consolidation_mode_t_Z_CONSOLIDATION_MODE_MONOTONIC,
        ),
        (
            ConsolidationMode::Latest,
            zenoh_pico_sys::z_consolidation_mode_t_Z_CONSOLIDATION_MODE_LATEST,
        ),
    ] {
        let owned = RequestQueryBuilder::new(0, 0, None)
            .consolidation(wz_mode)
            .build()
            .expect("wz consolidation request builds");
        let wz = owned
            .try_as_borrowed()
            .expect("borrow the owned request")
            .encode_to_vec();
        let pico = zenoh_pico_encode_request_query_knobs(&PicoQueryKnobs {
            consolidation: Some(pico_mode),
            ..Default::default()
        });
        assert_ne!(
            pico,
            zenoh_pico_encode_request_default(),
            "anti-vacuity: the Q_C flag + mode byte must actually reach the wire"
        );
        assert_eq!(
            wz.len(),
            pico.len(),
            "the divergence is a VALUE, not a shape: wz must encode the same \
             number of bytes as zenoh-pico for mode {wz_mode:?}; \
             wz={wz:02x?} pico={pico:02x?}"
        );
        let differing: Vec<usize> = wz
            .iter()
            .zip(pico.iter())
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            differing.len(),
            1,
            "exactly one byte may differ from zenoh-pico for mode {wz_mode:?} — \
             every other byte of the Request/Query envelope is still parity; \
             wz={wz:02x?} pico={pico:02x?} differing={differing:?}"
        );
        let at = differing[0];
        assert_eq!(
            pico[at], pico_mode as u8,
            "the differing byte must be the CONSOLIDATION field: zenoh-pico wrote \
             its API enum there, so pico[{at}] must equal the mode it was asked \
             for; wz={wz:02x?} pico={pico:02x?}"
        );
        assert_eq!(
            wz[at],
            pico[at] + 1,
            "wz numbers this field one slot above zenoh-pico, because zenoh's \
             enum carries Auto in slot 0 and pico's -1 sentinel is never written \
             (measured on both planes by query_consolidation_wire_byte_divergence); \
             wz={wz:02x?} pico={pico:02x?}"
        );
        assert_eq!(
            wz[at],
            wz_mode.wire_byte(),
            "and that byte is exactly what ConsolidationMode::wire_byte returns \
             for {wz_mode:?} — the builder must not re-derive the mapping"
        );
    }
}

/// wz's `RequestQueryBuilder::parameters` must set the Query-body Q_P flag and the
/// length-prefixed selector-parameter slice byte-for-byte as zenoh-pico's `_parameters`.
// wz-proves: query-selector-parameters codec-parity partial
// wz-proves: codec-request codec-parity partial
#[test]
fn layer3_request_parameters_byte_equivalent() {
    use wz_session_core::request_build::RequestQueryBuilder;

    for params in [&b"k=v"[..], b"_time=[now(-1h)..now()];k=v"] {
        let owned = RequestQueryBuilder::new(0, 0, None)
            .parameters(params)
            .build()
            .expect("wz parameters request builds");
        let wz = owned
            .try_as_borrowed()
            .expect("borrow the owned request")
            .encode_to_vec();
        let pico = zenoh_pico_encode_request_query_knobs(&PicoQueryKnobs {
            parameters: Some(params),
            ..Default::default()
        });
        assert_ne!(
            pico,
            zenoh_pico_encode_request_default(),
            "anti-vacuity: the Q_P flag + parameters slice must actually reach the wire"
        );
        assert_eq!(
            wz, pico,
            "Query selector parameters must match zenoh-pico byte-for-byte; \
             wz={wz:02x?} pico={pico:02x?}"
        );
    }
}

/// wz's `RequestQueryBuilder::query_attachment` must encode the Query-body attachment
/// ext byte-for-byte as zenoh-pico's `_ext_attachment`.
// wz-proves: query-attachment codec-parity partial
// wz-proves: codec-request codec-parity partial
#[test]
fn layer3_request_attachment_byte_equivalent() {
    use wz_session_core::request_build::RequestQueryBuilder;

    // 1 byte, a mid-size blob, and the wz codec's declared ceiling
    // (`QUERY_EXT_ZBUF_MAX_LEN` = 32) — the ext is length-prefixed, so the boundary is
    // where a length-encoding disagreement would surface. Empty is not a case: the
    // setter panics on it by contract (pico's encoder clears the ext on empty).
    let max_len = wz_session_core::request_build::QUERY_EXT_ZBUF_MAX_LEN;
    let ceiling = vec![0xA5_u8; max_len];
    for attachment in [&b"a"[..], b"query-attachment-bytes", &ceiling] {
        let owned = RequestQueryBuilder::new(0, 0, None)
            .query_attachment(attachment)
            .build()
            .expect("wz attachment request builds");
        let wz = owned
            .try_as_borrowed()
            .expect("borrow the owned request")
            .encode_to_vec();
        let pico = zenoh_pico_encode_request_query_knobs(&PicoQueryKnobs {
            attachment: Some(attachment),
            ..Default::default()
        });
        assert_ne!(
            pico,
            zenoh_pico_encode_request_default(),
            "anti-vacuity: the attachment ext must actually reach the wire"
        );
        assert_eq!(
            wz,
            pico,
            "Query attachment ext ({} bytes) must match zenoh-pico byte-for-byte; \
             wz={wz:02x?} pico={pico:02x?}",
            attachment.len()
        );
    }
}

/// The CONVERSE of the five knob tests, and the cheapest real gap they left open.
///
/// Every knob test asserts "wz emits what pico emits WHEN THE KNOB IS SET". None of them
/// asserted the other direction: that `RequestQueryBuilder` with NO knob set emits what
/// pico emits when nothing is set. Without this, a builder that spuriously wrote a
/// sentinel-valued ext (a target of 0, a Q_C byte for the absent mode, an empty-params
/// Q_P) would emit bytes zenoh-pico never emits -- a real pico queryable would mis-decode
/// -- and not one test in the suite would fail. `layer3_request_default_byte_equivalent`
/// does not cover it: that drives the raw `Request::default()` CODEC STRUCT, not the
/// production builder.
// wz-proves: codec-request codec-parity partial
#[test]
fn layer3_request_builder_default_emits_no_spurious_ext() {
    use wz_session_core::request_build::RequestQueryBuilder;

    let owned = RequestQueryBuilder::new(0, 0, None)
        .build()
        .expect("wz knob-less request builds");
    let wz = owned
        .try_as_borrowed()
        .expect("borrow the owned request")
        .encode_to_vec();
    assert_eq!(
        wz,
        zenoh_pico_encode_request_default(),
        "a knob-less RequestQueryBuilder must emit exactly zenoh-pico's default envelope; \
         any extra byte is an ext pico would not send and may mis-decode; \
         wz={wz:02x?}"
    );
}
