// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Outbound pub/sub `Push` network-message builders.
//!
//! The `build_push_*` family constructs the `PushOwned` codec struct for
//! the four publish shapes (literal / DECLARE-aliased keyexpr × Put / Del)
//! plus their metadata-bearing `_with_meta` counterparts (timestamp,
//! encoding, source_info, attachment, qos). Pure wz-codecs constructors —
//! no runtime / no FSM coupling; the transport-`Frame` envelope is applied
//! separately by `frame_encode::encode_frame_with_push`.
//!
//! Hoisted from `wz-runtime-tokio::session_glue` so both runtime profiles
//! share one Push-builder SSOT — the MCU `#![no_std]` profile cannot
//! depend on the tokio crate. Owned `Vec` output, so alloc-gated; the
//! whole module is `codec-push`-gated at the `lib.rs` declaration, and the
//! per-field metadata branches are further gated on their `pubsub-*`
//! features so an arbitrary publish subset carries only the encode paths
//! it composes.

use alloc::vec::Vec;

use sce_forge_runtime::codec::CodecError;
use wz_codecs::wire_const;

use wz_codecs::ext_entry::ExtEntryOwned;
use wz_codecs::msg_del::MsgDelOwned;
use wz_codecs::msg_put::MsgPutOwned;
use wz_codecs::push::{PushOwned, PushOwnedVariant};
use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};
use wz_codecs::wireexpr_local::WireexprLocalOwned;

use crate::metadata::PushMetadata;

// `ExtEntryOwnedVariant` is named only by the source_info (ZBuf) and qos
// (ZInt) construction branches; gate the import to their union so a
// codec-push subset without those metadata features carries no unused
// import.
#[cfg(feature = "pubsub-source-info")]
use crate::source_info_ext::encode_source_info_ext_entry;
#[cfg(any(
    feature = "pubsub-source-info",
    feature = "pubsub-priority",
    feature = "pubsub-congestion-control",
    feature = "pubsub-express"
))]
use wz_codecs::ext_entry::ExtEntryOwnedVariant;
#[cfg(any(
    feature = "pubsub-priority",
    feature = "pubsub-congestion-control",
    feature = "pubsub-express"
))]
use wz_codecs::ext_zint::ExtZint;

/// R121e — build a `Push` network-message with a literal keyexpr
/// (id=0 + inline suffix) and a `Put` body carrying `value` as
/// payload bytes.
///
/// Wire-spec sourcing:
///
/// * `WireexprLocal { id: 0, suffix: Some(s) }` encodes as "the
///   keyexpr IS the literal string `s`, no DECLARE alias
///   indirection". `id = 0` is the Zenoh sentinel for "no
///   declared mapping" (zenoh-pico
///   `include/zenoh-pico/api/types.h::_z_keyexpr_set_no_id` path);
///   zenoh-pico's session-receive resolver
///   (`_z_session_recv_push`) treats id=0 + suffix=Some as the
///   literal-keyexpr path with no table lookup. This is the
///   simplest publisher shape — DECLARE-aliased Push (id != 0,
///   prior DeclKexpr to assign id → suffix) is a follow-up
///   optimisation for repeated-keyexpr traffic and is not on the
///   AP MVP critical path.
///
/// * `Push.header` carries:
///   - bits 0..4: MID = `N_MID_PUSH` (0x1D, network.h:34).
///   - bit 5:     `N` flag = 1 (suffix carrier present).
///   - bit 6:     `M` flag — derived from the WireexprLocal arm
///     at encode time (push.rs:189 `_derived_header`); MUST NOT
///     be set here.
///   - bit 7:     `Z` flag = 0 (no Push-level extensions for the
///     MVP path).
///
/// * `MsgPut` body carries:
///   - `header` = 0x01 (msg_put MID, no timestamp / encoding /
///     ext flags — payload-only Put per network.c:118).
///   - `payload_len` = `value.len()` VLE-encoded.
///   - `payload` = the application bytes.
///
/// Pure builder — no I/O, no FSM state coupling. Mirrors the
/// shape of `encode_init` / `encode_open` / `encode_close`.
///
/// R311h — gated on `codec-push` (return type is the gated
/// `wz_codecs::push::Push`; principled exemption from the
/// signature-stability sweep per `feedback_signature_stability`).
pub fn build_push_literal(keyexpr_suffix: &str, value: &[u8]) -> Result<PushOwned, CodecError> {
    let payload_len = value.len() as u64;
    Ok(PushOwned {
        // `N_MID_PUSH | N_flag(0x20)` — M flag derives from the
        // WireexprLocal arm at encode time (push.rs:189).
        header: wire_const::N_MID_PUSH | 0x20,
        keyexpr: literal_wireexpr(keyexpr_suffix)?,
        extensions: None,
        body: PushOwnedVariant::CodecZenohMsgPut(MsgPutOwned {
            header: 0x01,
            timestamp: None,
            encoding: None,
            extensions: None,
            payload_len,
            payload: crate::codec_owned::owned_bytes(value)?,
        }),
    })
}

/// Build a literal (`id == 0`) keyexpr `Wireexpr` carrying `suffix` verbatim —
/// the un-aliased wire form [`build_push_literal`] embeds, factored out as the
// `literal_wireexpr` (the SSOT literal-`Wireexpr` constructor) was relocated to
// the codec-agnostic [`wireexpr_build`](crate::wireexpr_build) module so the
// Request forward path can reuse it without the Push codec. Re-exported so the
// Push builders below (and any external `push_build::literal_wireexpr` caller)
// keep working unchanged.
pub use crate::wireexpr_build::literal_wireexpr;

/// Re-express a `Push`'s keyexpr as the literal `suffix` (c3c-3 B1 normalize):
/// set the keyexpr to a literal ([`literal_wireexpr`]) AND the header's `N`
/// (suffix-present, `0x20`) bit, which a literal keyexpr always carries. The two
/// MUST stay in sync — a clear `N` bit with a suffix-bearing wireexpr drops the
/// peer's decoder into an offset-shifted read of the following `MsgPut` header.
/// The linkstate forwarder calls this on the outbound carrier so a downstream
/// link (no shared alias table) receives a self-contained literal Push, even
/// when the inbound was a pure-aliased Push whose `N` bit was clear.
pub fn set_push_keyexpr_literal(push: &mut PushOwned, suffix: &str) -> Result<(), CodecError> {
    crate::wireexpr_build::set_literal_keyexpr_fields(&mut push.keyexpr, &mut push.header, suffix)
}

/// R121g — build a `Push` network-message that references a peer-
/// declared keyexpr mapping. Mirror of [`build_push_literal`] for
/// the DECLARE-aliased path: instead of carrying the full literal
/// suffix on every Push, the publisher first sends a
/// `Declare(DeclKexpr)` (via `build_declare_kexpr` / the
/// `send_declare_keyexpr` action) that registers `id` → "demo/test",
/// then emits subsequent Pushes carrying only that `id` (and
/// optionally a per-Push suffix appended to the declared prefix).
///
/// Wire-spec sourcing:
///
/// * `WireexprLocal { id: N, suffix: None }` — pure aliased Push.
///   The peer (z_sub) consults its keyexpr table built from prior
///   inbound `DeclKexpr` records (zenoh-pico's
///   `_z_session_recv_declaration` path) and resolves `id=N` to the
///   declared keyexpr. This is the bandwidth-efficient shape for
///   repeated-keyexpr publishers.
///
/// * `WireexprLocal { id: N, suffix: Some(s) }` — composite. The
///   peer concatenates its declared prefix with `s` to form the
///   effective keyexpr. Used when one DECLARE establishes a prefix
///   (e.g. `myhouse/sensors/`) and many publishers add per-sensor
///   suffixes (`temp`, `humidity`) without redeclaring.
///
/// Panics if `mapping_id == 0` — id zero is the literal-keyexpr
/// sentinel (`build_push_literal`'s arm). The split keeps the two
/// shapes apart at the API surface so a caller cannot silently
/// invert them.
pub fn build_push_aliased(
    mapping_id: u64,
    suffix: Option<&str>,
    value: &[u8],
) -> Result<PushOwned, CodecError> {
    assert!(
        mapping_id != 0,
        "build_push_aliased requires a non-zero mapping id; use build_push_literal for id=0",
    );
    let suffix_len = suffix.map(|s| s.len() as u64);
    let suffix_string = suffix.map(crate::codec_owned::owned_string).transpose()?;
    let payload_len = value.len() as u64;
    // Push.header.N (bit 5, 0x20) is the "suffix carrier present"
    // flag: set when the WireexprLocal carries a non-None suffix,
    // clear for a pure-aliased Push (`suffix=None`). The peer's
    // wireexpr decoder reads this bit to decide whether to expect
    // `VLE(suffix_len) + suffix bytes` after the id; an out-of-sync
    // N flag drops the codec into an offset-shifted read of the
    // following MsgPut header, which the peer surfaces as
    // `Unknown message type received` (zenoh-pico
    // `_z_network_message_decode` MID switch on a stale byte).
    let n_flag = if suffix.is_some() { 0x20u8 } else { 0x00u8 };
    Ok(PushOwned {
        header: wire_const::N_MID_PUSH | n_flag,
        keyexpr: WireexprOwned {
            body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                id: mapping_id,
                suffix_len,
                suffix: suffix_string,
            }),
        },
        extensions: None,
        body: PushOwnedVariant::CodecZenohMsgPut(MsgPutOwned {
            header: 0x01,
            timestamp: None,
            encoding: None,
            extensions: None,
            payload_len,
            payload: crate::codec_owned::owned_bytes(value)?,
        }),
    })
}

/// R219 — build a literal-keyexpr `Push` whose body is a `MsgDel`
/// (delete-keyexpr signal) instead of `MsgPut`. Mirror of
/// [`build_push_literal`] for the deletion-of-resource path that
/// zenoh-pico emits on `z_delete` (`vendor/zenoh-pico/src/api/api.c`
/// `z_delete` → `_z_write` with `Z_SAMPLE_KIND_DELETE`).
///
/// Wire-shape differences from [`build_push_literal`]:
///
/// * `MsgDel` body carries:
///   - `header` = 0x02 (msg_del MID, no timestamp / ext flags
///     — payload-less Del per network.c:118 mapping table).
///   - No `payload_len` / `payload` fields — `MsgDel` is a marker
///     message; the keyexpr identifies the resource being deleted.
/// * Push.header N flag (0x20) is set the same as the literal-keyexpr
///   Put path; M flag derives at encode time from the WireexprLocal
///   arm selection.
///
/// Subscriber-side observation: zenoh-pico's `_z_trigger_subscriptions`
/// fires the registered callback with `z_sample_kind = DELETE`. The
/// stock `z_sub` example does not surface the kind in its printout
/// (only the keyexpr + payload), so an integration test against
/// `z_sub` sees the Del as a `Received` line with an empty value
/// substring — distinguishable from a Put-with-empty-value only by
/// the wz-side codec round-trip witness.
pub fn build_push_del_literal(keyexpr_suffix: &str) -> Result<PushOwned, CodecError> {
    let suffix_len = keyexpr_suffix.len() as u64;
    Ok(PushOwned {
        // `N_MID_PUSH | N_flag(0x20)` — M flag derives from the
        // WireexprLocal arm at encode time (push.rs:189). Identical
        // header shape to the Put path; only the inner body MID
        // (0x02 vs 0x01) and the absence of payload bytes differ
        // on the wire.
        header: wire_const::N_MID_PUSH | 0x20,
        keyexpr: WireexprOwned {
            body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                id: 0,
                suffix_len: Some(suffix_len),
                suffix: Some(crate::codec_owned::owned_string(keyexpr_suffix)?),
            }),
        },
        extensions: None,
        body: PushOwnedVariant::CodecZenohMsgDel(MsgDelOwned {
            header: 0x02,
            timestamp: None,
            extensions: None,
        }),
    })
}

/// R311qd — re-key a `Push` for forwarding to a peer that has no expr-id
/// mapping for the source's keyexpr (the router data-plane re-literalization,
/// [`crate::routing`]). If the Push already carries a literal (`id == 0`)
/// keyexpr it is decodable by any peer as-is and returned verbatim (body +
/// metadata preserved, exact bytes); otherwise it is cloned and re-keyed to
/// `keyexpr` as a literal (`id == 0`), preserving the Put/Del body and setting
/// the Push N flag.
///
/// This is the wire-layer SSOT for that operation: the literal-keyexpr
/// construction and the N-flag bit live here next to [`build_push_literal`]
/// (the only other place that builds a literal-keyexpr Push header), so the
/// routing kernel that forwards stays free of wire-format knowledge.
pub fn reliteralize_push(push: &PushOwned, keyexpr: &str) -> Result<PushOwned, CodecError> {
    // Already literal → any peer decodes it without a mapping; forward verbatim.
    if push_keyexpr_is_literal(push) {
        return Ok(push.clone());
    }
    let mut fwd = push.clone();
    fwd.keyexpr = WireexprOwned {
        body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
            id: 0,
            suffix_len: Some(keyexpr.len() as u64),
            suffix: Some(crate::codec_owned::owned_string(keyexpr)?),
        }),
    };
    // Push.header N flag (0x20, "suffix carrier present") — set because the
    // re-literalized keyexpr now carries a suffix (an aliased source had it
    // clear). Same header bit `build_push_literal` sets; M derives at encode.
    fwd.header |= 0x20;
    Ok(fwd)
}

/// Whether a Push's keyexpr is a literal (`id == 0`) — decodable by any peer
/// without an expr-id mapping. The forward fast-path predicate for
/// [`reliteralize_push`].
fn push_keyexpr_is_literal(push: &PushOwned) -> bool {
    match &push.keyexpr.body {
        WireexprOwnedVariant::WireexprLocal(arm) => arm.id == 0,
        WireexprOwnedVariant::WireexprNonlocal(arm) => arm.id == 0,
    }
}

/// R219 — build a DECLARE-aliased `Push` whose body is `MsgDel`.
/// Mirror of [`build_push_aliased`] for the deletion path. Same
/// aliased-keyexpr precondition as the Put variant: the peer must
/// have absorbed a `Declare(DeclKexpr(mapping_id, ...))` earlier
/// so its keyexpr table can resolve the id.
///
/// Panics if `mapping_id == 0` — id zero is the literal-keyexpr
/// sentinel ([`build_push_del_literal`]'s arm). The split keeps
/// the two shapes apart at the API surface so a caller cannot
/// silently invert them.
pub fn build_push_del_aliased(
    mapping_id: u64,
    suffix: Option<&str>,
) -> Result<PushOwned, CodecError> {
    assert!(
        mapping_id != 0,
        "build_push_del_aliased requires a non-zero mapping id; use build_push_del_literal for id=0",
    );
    let suffix_len = suffix.map(|s| s.len() as u64);
    let suffix_string = suffix.map(crate::codec_owned::owned_string).transpose()?;
    // Same N-flag derivation as build_push_aliased: bit 5 set when
    // a per-Push suffix tail is present, cleared for the
    // pure-aliased shape. The flag has identical decoder semantics
    // regardless of the inner body MID (Put vs Del).
    let n_flag = if suffix.is_some() { 0x20u8 } else { 0x00u8 };
    Ok(PushOwned {
        header: wire_const::N_MID_PUSH | n_flag,
        keyexpr: WireexprOwned {
            body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                id: mapping_id,
                suffix_len,
                suffix: suffix_string,
            }),
        },
        extensions: None,
        body: PushOwnedVariant::CodecZenohMsgDel(MsgDelOwned {
            header: 0x02,
            timestamp: None,
            extensions: None,
        }),
    })
}

/// R233 — build the body-level extension chain (`source_info` +
/// `attachment`) for a `MsgPut` or `MsgDel`. Returns `None` when
/// both fields are absent so the caller can leave
/// `MsgPut.extensions` / `MsgDel.extensions` as `None` and avoid
/// emitting an empty `<u8;ZBuf>` chain. Z chain-continuation flags
/// on the produced entries are NOT pre-set — the SCE-emitted
/// `MsgPut::encode` / `MsgDel::encode` iterate the chain and the
/// surrounding wire serializer applies the Z bit at the right
/// position via the per-entry codec emit.
fn build_body_extensions(
    source_info: Option<&crate::sample::SourceInfo>,
    attachment: Option<&[u8]>,
) -> Result<Option<Vec<ExtEntryOwned>>, CodecError> {
    let mut exts: Vec<ExtEntryOwned> = Vec::new();
    // Push source_info ext (id 0x01) — gated on `pubsub-source-info` so a
    // codec-push subset that does not compose source identification carries
    // no source_info encode path. The subscriber-side decode is gated on
    // the same feature (pubsub.rs), so off-subset both ends agree the wire
    // carries no source_info. M flag stays clear (informational); Z chain
    // bit applied below.
    #[cfg(feature = "pubsub-source-info")]
    if let Some(si) = source_info {
        let prefix = si.zid_prefix();
        if !prefix.is_empty() {
            // The full-entry SSOT (header ENC_ZBUF|0x01 + ExtZbuf wrap). The
            // empty-prefix skip stays here — a body that knows no source omits
            // the ext. Z chain-continuation bit applied by apply_chain_z_bits
            // below.
            exts.push(encode_source_info_ext_entry(prefix, si.eid, si.sn)?);
        }
    }
    #[cfg(not(feature = "pubsub-source-info"))]
    let _ = source_info;
    // Push attachment ext (id 0x03) — gated on `pubsub-attachment` so a
    // codec-push subset that does not compose attachments carries no
    // attachment encode path. The ext wire shape lives in the
    // wz-session-core `attachment` SSOT module (selected by
    // pubsub-attachment). M flag stays clear (informational); Z chain bit
    // applied below.
    #[cfg(feature = "pubsub-attachment")]
    if let Some(bytes) = attachment {
        exts.push(crate::attachment::encode_attachment_ext(
            crate::attachment::ATTACHMENT_EXT_ID_PUSH,
            bytes,
        )?);
    }
    #[cfg(not(feature = "pubsub-attachment"))]
    let _ = attachment;
    if exts.is_empty() {
        return Ok(None);
    }
    crate::ext_nodeid::apply_chain_z_bits(&mut exts);
    Ok(Some(exts))
}

// R233 / R311ru — the per-entry chain-continuation `Z`-bit normalisation that
// `MsgPut`/`MsgDel`/`Push::encode` rely on (the author owns Z; the SCE-emitted
// encoders do not flip it) now lives in the shared `crate::ext_nodeid` SSOT,
// consolidated with the two routing-context modules that re-implemented it.

/// R233 — build the outer Push extension chain (currently only QoS).
/// Returns `None` when no outer extension is requested so the caller
/// can leave `Push.extensions = None` and clear the Push-header Z
/// bit. zenoh-pico mirror: `_z_n_msg_encode_push` outer-ext switch
/// at network.c — qos lands on the outer chain, source_info /
/// attachment on the body chain (`_z_push_body_encode_extensions`).
fn build_push_outer_extensions(qos: Option<crate::sample::QosLevel>) -> Option<Vec<ExtEntryOwned>> {
    let mut exts: Vec<ExtEntryOwned> = Vec::new();
    // Push outer QoS ext (id 0x01) — gated on any of the three QoS-byte
    // features (the single ext byte packs priority / congestion-control /
    // express). The subscriber-side decode is gated on the same `any(...)`
    // (pubsub.rs), so off-subset both ends agree the wire carries no QoS.
    #[cfg(any(
        feature = "pubsub-priority",
        feature = "pubsub-congestion-control",
        feature = "pubsub-express"
    ))]
    if let Some(q) = qos {
        exts.push(ExtEntryOwned {
            // ENC_ZINT(0x20) | id_qos(0x01). No M flag — qos is
            // informational per zenoh-pico `_z_n_msg_encode_push`
            // outer-chain emit (network.c).
            header: 0x20 | 0x01,
            body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint {
                value: q.raw as u64,
            }),
        });
    }
    #[cfg(not(any(
        feature = "pubsub-priority",
        feature = "pubsub-congestion-control",
        feature = "pubsub-express"
    )))]
    let _ = qos;
    if exts.is_empty() {
        return None;
    }
    crate::ext_nodeid::apply_chain_z_bits(&mut exts);
    Some(exts)
}

/// R311fx — SSOT for the `pubsub-timestamp` send-side gate. The inline
/// `MsgPut` / `MsgDel` timestamp field is the single place a caller-set
/// timestamp reaches the wire, so the "is a timestamp emitted" policy
/// lives here once rather than being re-stated at each Put/Del builder
/// (sibling of [`build_body_extensions`], which is the one gate-point
/// for the ext-based metadata). When `pubsub-timestamp` is off the
/// result is forced `None` so the `_Z_FLAG_Z_*_T` (0x20) header bit the
/// builders OR in stays clear and no timestamp is serialised. The param
/// keeps the builders' signatures stable across the toggle.
fn gated_timestamp_field(
    timestamp: Option<&crate::sample::TimestampHint>,
) -> Result<Option<wz_codecs::timestamp::TimestampOwned>, CodecError> {
    #[cfg(feature = "pubsub-timestamp")]
    {
        timestamp.map(|t| t.to_codec().try_into_owned()).transpose()
    }
    #[cfg(not(feature = "pubsub-timestamp"))]
    {
        let _ = timestamp;
        Ok(None)
    }
}

/// SSOT for the `pubsub-encoding` send-side gate. The inline `MsgPut`
/// encoding field is the single place a caller-set encoding reaches the
/// wire (Put only; `MsgDel` has no encoding slot per zenoh-pico
/// `_z_msg_del_t`), so the "is an encoding emitted" policy lives here
/// once — sibling of [`gated_timestamp_field`]. When `pubsub-encoding`
/// is off the result is forced `None` so the `_Z_FLAG_Z_P_E` (0x40)
/// header bit the builder ORs in stays clear and no encoding is
/// serialised. The param keeps the builder's signature stable across
/// the toggle.
fn gated_encoding_field(
    encoding: Option<&crate::sample::EncodingHint>,
) -> Result<Option<wz_codecs::encoding::EncodingOwned>, CodecError> {
    #[cfg(feature = "pubsub-encoding")]
    {
        encoding.map(|e| e.to_codec().try_into_owned()).transpose()
    }
    #[cfg(not(feature = "pubsub-encoding"))]
    {
        let _ = encoding;
        Ok(None)
    }
}

/// R233 — build a `MsgPut` body carrying caller-set metadata
/// (timestamp, encoding, source_info, attachment). Sets the
/// `_Z_FLAG_Z_P_T` (0x20) and `_Z_FLAG_Z_P_E` (0x40) header bits to
/// signal the optional inline fields to the peer decoder.
/// Extensions are attached as a body-level chain via
/// [`build_body_extensions`]; the SCE-emitted `MsgPut::encode`
/// surfaces them per zenoh-pico's
/// `_z_push_body_encode_extensions` order.
fn build_msg_put_with_meta(
    payload: &[u8],
    timestamp: Option<&crate::sample::TimestampHint>,
    encoding: Option<&crate::sample::EncodingHint>,
    source_info: Option<&crate::sample::SourceInfo>,
    attachment: Option<&[u8]>,
) -> Result<MsgPutOwned, CodecError> {
    let payload_len = payload.len() as u64;
    let extensions = build_body_extensions(source_info, attachment)?;
    let mut put = MsgPutOwned {
        header: 0x01,
        timestamp: gated_timestamp_field(timestamp)?,
        encoding: gated_encoding_field(encoding)?,
        extensions,
        payload_len,
        payload: crate::codec_owned::owned_bytes(payload)?,
    };
    // `MsgPutOwned` is read-only (no `set_*` write accessors —
    // those live on the borrowed view per the owned-encode-omitted
    // SCE policy), so the header flag bits are OR'd directly. Bit
    // masks match `MsgPut::set_t/set_e/set_z` (0x20/0x40/0x80).
    if put.timestamp.is_some() {
        put.header |= 0x20;
    }
    if put.encoding.is_some() {
        put.header |= 0x40;
    }
    if put.extensions.is_some() {
        put.header |= 0x80;
    }
    Ok(put)
}

/// R233 — build a `MsgDel` body carrying caller-set metadata
/// (timestamp, source_info, attachment). zenoh-pico's `_z_msg_del_t`
/// carries no encoding slot, so `encoding` is intentionally absent
/// from the parameter list — the loopback path drops opts.encoding
/// for Del kind in `crate::session::build_loopback_sample` and the
/// wire path drops it here, keeping wire-vs-loopback parity. Sets
/// the `_Z_FLAG_Z_D_T` (0x20) header bit when a timestamp is
/// attached.
fn build_msg_del_with_meta(
    timestamp: Option<&crate::sample::TimestampHint>,
    source_info: Option<&crate::sample::SourceInfo>,
    attachment: Option<&[u8]>,
) -> Result<MsgDelOwned, CodecError> {
    let extensions = build_body_extensions(source_info, attachment)?;
    let mut del = MsgDelOwned {
        header: 0x02,
        timestamp: gated_timestamp_field(timestamp)?,
        extensions,
    };
    // `MsgDelOwned` is read-only; OR the header flag bits directly
    // (masks match `MsgDel::set_t/set_z` — 0x20/0x80).
    if del.timestamp.is_some() {
        del.header |= 0x20;
    }
    if del.extensions.is_some() {
        del.header |= 0x80;
    }
    Ok(del)
}

/// R233 — metadata-bearing counterpart of [`build_push_literal`].
/// Routes timestamp / encoding into the inline `MsgPut` fields,
/// source_info / attachment into the body extension chain, and qos
/// into the outer Push extension chain. The Push-header Z bit (0x80)
/// is OR'd when an outer extension is present.
pub fn build_push_literal_with_meta(
    keyexpr_suffix: &str,
    value: &[u8],
    meta: &PushMetadata,
) -> Result<PushOwned, CodecError> {
    let outer_exts = build_push_outer_extensions(meta.qos);
    let z_flag = if outer_exts.is_some() { 0x80u8 } else { 0x00u8 };
    Ok(PushOwned {
        header: wire_const::N_MID_PUSH | 0x20 | z_flag,
        keyexpr: WireexprOwned {
            body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                id: 0,
                suffix_len: Some(keyexpr_suffix.len() as u64),
                suffix: Some(crate::codec_owned::owned_string(keyexpr_suffix)?),
            }),
        },
        extensions: outer_exts,
        body: PushOwnedVariant::CodecZenohMsgPut(build_msg_put_with_meta(
            value,
            meta.timestamp.as_ref(),
            meta.encoding.as_ref(),
            meta.source_info.as_ref(),
            meta.attachment.as_deref(),
        )?),
    })
}

/// transport-shm — build a `MsgPut` whose PAYLOAD is the SHM descriptor (not the
/// data bytes) and whose body ext chain carries the `ext_shm` 0x2 marker
/// (`crate::extshm`). The parallel of [`build_msg_put_with_meta`] for the SHM
/// swap: the data lives in the shared segment, the wire carries only the
/// descriptor + the marker that tells the RX to resolve it. The chain always has
/// at least the marker, so the Z header bit (0x80) is always set.
#[cfg(feature = "transport-shm")]
fn build_msg_put_shm(
    descriptor: &crate::extshm::ShmDescriptor,
    timestamp: Option<&crate::sample::TimestampHint>,
    encoding: Option<&crate::sample::EncodingHint>,
    source_info: Option<&crate::sample::SourceInfo>,
    attachment: Option<&[u8]>,
) -> Result<MsgPutOwned, CodecError> {
    let descriptor_bytes = crate::extshm::encode_shm_descriptor(descriptor);
    let payload_len = descriptor_bytes.len() as u64;
    // Reuse the source_info / attachment SSOT, then append the 0x2 marker and
    // re-normalise the chain-continuation Z bits over the full chain.
    let mut exts = build_body_extensions(source_info, attachment)?.unwrap_or_default();
    exts.push(crate::extshm::encode_shm_marker_ext());
    crate::ext_nodeid::apply_chain_z_bits(&mut exts);
    let mut put = MsgPutOwned {
        header: 0x01,
        timestamp: gated_timestamp_field(timestamp)?,
        encoding: gated_encoding_field(encoding)?,
        extensions: Some(exts),
        payload_len,
        payload: crate::codec_owned::owned_bytes(&descriptor_bytes)?,
    };
    if put.timestamp.is_some() {
        put.header |= 0x20;
    }
    if put.encoding.is_some() {
        put.header |= 0x40;
    }
    // The body ext chain always carries the marker, so Z (0x80) is always set.
    put.header |= 0x80;
    Ok(put)
}

/// transport-shm — the SHM counterpart of [`build_push_literal_with_meta`]: the
/// Put carries the descriptor + the 0x2 marker. Used by `publish_shm` when the
/// session has negotiated SHM.
#[cfg(feature = "transport-shm")]
pub fn build_push_shm_literal(
    keyexpr_suffix: &str,
    descriptor: &crate::extshm::ShmDescriptor,
    meta: &PushMetadata,
) -> Result<PushOwned, CodecError> {
    let outer_exts = build_push_outer_extensions(meta.qos);
    let z_flag = if outer_exts.is_some() { 0x80u8 } else { 0x00u8 };
    Ok(PushOwned {
        header: wire_const::N_MID_PUSH | 0x20 | z_flag,
        keyexpr: WireexprOwned {
            body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                id: 0,
                suffix_len: Some(keyexpr_suffix.len() as u64),
                suffix: Some(crate::codec_owned::owned_string(keyexpr_suffix)?),
            }),
        },
        extensions: outer_exts,
        body: PushOwnedVariant::CodecZenohMsgPut(build_msg_put_shm(
            descriptor,
            meta.timestamp.as_ref(),
            meta.encoding.as_ref(),
            meta.source_info.as_ref(),
            meta.attachment.as_deref(),
        )?),
    })
}

/// R233 — metadata-bearing counterpart of [`build_push_aliased`].
pub fn build_push_aliased_with_meta(
    mapping_id: u64,
    suffix: Option<&str>,
    value: &[u8],
    meta: &PushMetadata,
) -> Result<PushOwned, CodecError> {
    assert!(
        mapping_id != 0,
        "build_push_aliased_with_meta requires a non-zero mapping id; \
         use build_push_literal_with_meta for id=0",
    );
    let outer_exts = build_push_outer_extensions(meta.qos);
    let z_flag = if outer_exts.is_some() { 0x80u8 } else { 0x00u8 };
    let suffix_len = suffix.map(|s| s.len() as u64);
    let suffix_string = suffix.map(crate::codec_owned::owned_string).transpose()?;
    let n_flag = if suffix.is_some() { 0x20u8 } else { 0x00u8 };
    Ok(PushOwned {
        header: wire_const::N_MID_PUSH | n_flag | z_flag,
        keyexpr: WireexprOwned {
            body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                id: mapping_id,
                suffix_len,
                suffix: suffix_string,
            }),
        },
        extensions: outer_exts,
        body: PushOwnedVariant::CodecZenohMsgPut(build_msg_put_with_meta(
            value,
            meta.timestamp.as_ref(),
            meta.encoding.as_ref(),
            meta.source_info.as_ref(),
            meta.attachment.as_deref(),
        )?),
    })
}

/// R233 — metadata-bearing counterpart of [`build_push_del_literal`].
/// `encoding` is dropped silently because `_z_msg_del_t` carries no
/// encoding slot — the loopback path enforces the same projection
/// in `crate::session::build_loopback_sample`.
pub fn build_push_del_literal_with_meta(
    keyexpr_suffix: &str,
    meta: &PushMetadata,
) -> Result<PushOwned, CodecError> {
    let outer_exts = build_push_outer_extensions(meta.qos);
    let z_flag = if outer_exts.is_some() { 0x80u8 } else { 0x00u8 };
    Ok(PushOwned {
        header: wire_const::N_MID_PUSH | 0x20 | z_flag,
        keyexpr: WireexprOwned {
            body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                id: 0,
                suffix_len: Some(keyexpr_suffix.len() as u64),
                suffix: Some(crate::codec_owned::owned_string(keyexpr_suffix)?),
            }),
        },
        extensions: outer_exts,
        body: PushOwnedVariant::CodecZenohMsgDel(build_msg_del_with_meta(
            meta.timestamp.as_ref(),
            meta.source_info.as_ref(),
            meta.attachment.as_deref(),
        )?),
    })
}

/// R233 — metadata-bearing counterpart of [`build_push_del_aliased`].
pub fn build_push_del_aliased_with_meta(
    mapping_id: u64,
    suffix: Option<&str>,
    meta: &PushMetadata,
) -> Result<PushOwned, CodecError> {
    assert!(
        mapping_id != 0,
        "build_push_del_aliased_with_meta requires a non-zero mapping id; \
         use build_push_del_literal_with_meta for id=0",
    );
    let outer_exts = build_push_outer_extensions(meta.qos);
    let z_flag = if outer_exts.is_some() { 0x80u8 } else { 0x00u8 };
    let suffix_len = suffix.map(|s| s.len() as u64);
    let suffix_string = suffix.map(crate::codec_owned::owned_string).transpose()?;
    let n_flag = if suffix.is_some() { 0x20u8 } else { 0x00u8 };
    Ok(PushOwned {
        header: wire_const::N_MID_PUSH | n_flag | z_flag,
        keyexpr: WireexprOwned {
            body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                id: mapping_id,
                suffix_len,
                suffix: suffix_string,
            }),
        },
        extensions: outer_exts,
        body: PushOwnedVariant::CodecZenohMsgDel(build_msg_del_with_meta(
            meta.timestamp.as_ref(),
            meta.source_info.as_ref(),
            meta.attachment.as_deref(),
        )?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    // .wire() + Push::decode are named only by the two `_with_meta` round-trip
    // tests, which both construct every metadata field, so they gate on the
    // full metadata feature set; vec! (timestamp tests' zid literal) gates on
    // pubsub-timestamp.
    use crate::frame_encode::encode_frame_with_push;
    use crate::inbound::{parse_inbound, InboundFrame};
    use crate::network_message::{parse_frame_payload, NetworkMessage};
    #[cfg(feature = "pubsub-timestamp")]
    use alloc::vec;
    #[cfg(all(
        feature = "pubsub-attachment",
        feature = "pubsub-timestamp",
        feature = "pubsub-encoding",
        feature = "pubsub-source-info",
        any(
            feature = "pubsub-priority",
            feature = "pubsub-congestion-control",
            feature = "pubsub-express"
        )
    ))]
    use wz_codecs::push::Push;
    #[cfg(all(
        feature = "pubsub-attachment",
        feature = "pubsub-timestamp",
        feature = "pubsub-encoding",
        feature = "pubsub-source-info",
        any(
            feature = "pubsub-priority",
            feature = "pubsub-congestion-control",
            feature = "pubsub-express"
        )
    ))]
    use wz_codecs_test_support::TestWire;
    // QosLevel + TimestampHint are named ungated by push_metadata_is_empty;
    // EncodingHint / SourceInfo only by the pubsub-gated encoding / source-info
    // coverage tests, so they narrow to those features.
    #[cfg(feature = "pubsub-encoding")]
    use crate::sample::EncodingHint;
    #[cfg(feature = "pubsub-source-info")]
    use crate::sample::SourceInfo;
    use crate::sample::{QosLevel, TimestampHint};

    /// transport-shm — the TX swap: `build_push_shm_literal` carries the SHM
    /// DESCRIPTOR as the Put payload (not data bytes) and the 0x2 ext_shm marker
    /// on the body ext chain. The deterministic wire-form proof (the live
    /// is_shm-gated publish_shm path is proven end-to-end by shm_e2e).
    #[cfg(feature = "transport-shm")]
    #[test]
    fn build_push_shm_literal_carries_descriptor_and_marker() {
        let descriptor = crate::extshm::ShmDescriptor {
            segment_id: 0x1234,
            length: 4096,
            generation: 0,
        };
        let meta = PushMetadata::default();
        let push = build_push_shm_literal("demo/shm", &descriptor, &meta).expect("build shm push");
        let put = match &push.body {
            PushOwnedVariant::CodecZenohMsgPut(put) => put,
            _ => panic!("expected a MsgPut body"),
        };
        assert_eq!(
            crate::extshm::decode_shm_descriptor(put.payload.as_slice()),
            Some(descriptor),
            "the Put payload field is the SHM descriptor, not data bytes"
        );
        let exts = put.extensions.as_deref().unwrap_or(&[]);
        assert!(
            crate::extshm::body_has_shm_marker(exts),
            "the Put body carries the ext_shm 0x2 marker"
        );
    }

    #[cfg(all(feature = "codec-push", feature = "pubsub-timestamp"))]
    #[test]
    fn build_msg_put_with_meta_sets_timestamp_field_and_t_flag() {
        let ts = TimestampHint {
            time: 0xDEAD_BEEF_CAFE_BABE,
            zid: vec![0xAA, 0xBB],
        };
        let put = build_msg_put_with_meta(b"payload", Some(&ts), None, None, None).unwrap();
        assert!(put.timestamp.is_some(), "set_t routes through Option");
        assert_eq!(put.timestamp.as_ref().unwrap().time, 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(
            put.timestamp.as_ref().unwrap().zid.as_slice(),
            &[0xAA, 0xBB]
        );
        assert!(put.t(), "T flag must be set when timestamp is attached");
        assert!(!put.e(), "E flag must remain clear when encoding is absent");
        assert!(!put.z(), "Z flag must remain clear without body extensions");
    }

    #[cfg(all(feature = "codec-push", feature = "pubsub-encoding"))]
    #[test]
    fn build_msg_put_with_meta_sets_encoding_field_and_e_flag() {
        let enc = EncodingHint {
            packed_id: 13,
            schema: Some("application/json".into()),
        };
        let put = build_msg_put_with_meta(b"payload", None, Some(&enc), None, None).unwrap();
        assert!(put.encoding.is_some());
        assert_eq!(put.encoding.as_ref().unwrap().packed_id, 13);
        assert_eq!(
            put.encoding.as_ref().unwrap().schema.as_deref(),
            Some("application/json")
        );
        // schema_len round-trips from the original schema's byte length.
        assert_eq!(
            put.encoding.as_ref().unwrap().schema_len,
            Some("application/json".len() as u64)
        );
        assert!(put.e(), "E flag must be set when encoding is attached");
        assert!(
            !put.t(),
            "T flag must remain clear when timestamp is absent"
        );
    }

    #[cfg(all(feature = "codec-push", feature = "pubsub-source-info"))]
    #[test]
    fn build_msg_put_with_meta_attaches_source_info_ext_and_sets_z_flag() {
        let si = SourceInfo::new(&[0x11, 0x22, 0x33, 0x44], 7, 42);
        let put = build_msg_put_with_meta(b"payload", None, None, Some(&si), None).unwrap();
        let exts = put.extensions.as_deref().expect("body ext chain populated");
        assert_eq!(exts.len(), 1);
        // source_info ext: ENC_ZBUF(0x40) | ext_id(0x01) — M and Z bits
        // are NOT pre-set; Z bit application happens at codec emit time.
        assert_eq!(exts[0].header & 0x4F, 0x41);
        assert!(
            put.z(),
            "Z flag must be set when body extensions are present"
        );
        if let ExtEntryOwnedVariant::CodecZenohExtZbuf(z) = &exts[0].body {
            // First byte of source_info payload is `(zidlen - 1) << 4`.
            assert_eq!(z.value[0], (4 - 1) << 4);
            assert_eq!(&z.value[1..5], &[0x11, 0x22, 0x33, 0x44]);
        } else {
            panic!("source_info must use ExtZbuf body");
        }
    }

    #[cfg(all(
        feature = "codec-push",
        feature = "pubsub-attachment",
        feature = "pubsub-source-info"
    ))]
    #[test]
    fn build_msg_put_with_meta_attaches_attachment_ext_after_source_info() {
        // Both source_info + attachment together — order matters: pico's
        // _z_push_body_encode_extensions emits source_info before
        // attachment so the chain position must mirror that ordering.
        let si = SourceInfo::new(&[0xDE, 0xAD], 7, 0);
        let put =
            build_msg_put_with_meta(b"payload", None, None, Some(&si), Some(b"attach-payload"))
                .unwrap();
        let exts = put.extensions.as_deref().expect("body ext chain populated");
        assert_eq!(exts.len(), 2, "source_info + attachment = 2 entries");
        assert_eq!(exts[0].header & 0x4F, 0x41, "source_info first");
        assert_eq!(exts[1].header & 0x4F, 0x43, "attachment second");
        if let ExtEntryOwnedVariant::CodecZenohExtZbuf(z) = &exts[1].body {
            assert_eq!(z.value, b"attach-payload");
        } else {
            panic!("attachment must use ExtZbuf body");
        }
    }

    #[test]
    fn build_msg_put_with_meta_leaves_extensions_none_on_empty_inputs() {
        let put = build_msg_put_with_meta(b"payload", None, None, None, None).unwrap();
        assert!(put.extensions.is_none());
        assert!(!put.z(), "Z flag must remain clear with no extensions");
        assert!(!put.t(), "T flag clear with no timestamp");
        assert!(!put.e(), "E flag clear with no encoding");
    }

    #[cfg(all(feature = "codec-push", feature = "pubsub-timestamp"))]
    #[test]
    fn build_msg_del_with_meta_carries_timestamp_but_not_encoding_param() {
        // The MsgDel builder's parameter list intentionally has no
        // encoding slot — _z_msg_del_t has no encoding field on the
        // wire. This test pins that the API forbids a caller from
        // accidentally attaching encoding to a Del wire form.
        let ts = TimestampHint {
            time: 0x0102_0304_0506_0708,
            zid: vec![0x99],
        };
        let del = build_msg_del_with_meta(Some(&ts), None, None).unwrap();
        assert!(del.timestamp.is_some());
        assert!(del.t(), "T flag set when Del carries timestamp");
        assert!(!del.z(), "Z flag clear with no extensions");
    }

    #[cfg(all(
        feature = "codec-push",
        any(
            feature = "pubsub-priority",
            feature = "pubsub-congestion-control",
            feature = "pubsub-express"
        )
    ))]
    #[test]
    fn build_push_outer_extensions_emits_qos_with_zint_body() {
        let exts = build_push_outer_extensions(Some(QosLevel::from_raw(0b0001_1010)))
            .expect("qos populates outer chain");
        assert_eq!(exts.len(), 1);
        // ENC_ZINT(0x20) | id_qos(0x01); no M, no Z (single ext).
        assert_eq!(exts[0].header & 0x2F, 0x21);
        if let ExtEntryOwnedVariant::CodecZenohExtZint(z) = &exts[0].body {
            assert_eq!(z.value, 0b0001_1010);
        } else {
            panic!("qos must use ExtZint body");
        }
    }

    #[test]
    fn build_push_outer_extensions_returns_none_without_qos() {
        assert!(build_push_outer_extensions(None).is_none());
    }

    /// `build_push_literal` populates the Push struct with the
    /// header / wireexpr / msg_put shape the wire-spec calls for:
    /// `N_MID_PUSH | N_flag` in the header (M derives at encode),
    /// `WireexprLocal { id=0, suffix=Some(s) }` for the literal
    /// keyexpr, and `MsgPut` with the supplied payload bytes.
    #[test]
    fn build_push_literal_shapes_struct_for_literal_keyexpr() {
        let push = build_push_literal("demo/test", b"hello").unwrap();
        // header bits: N_MID_PUSH (0x1D) | N flag (0x20) = 0x3D.
        // M flag (0x40) is set at encode time, not on the struct.
        assert_eq!(
            push.header, 0x3D,
            "Push.header must carry N_MID_PUSH (0x1D) | N flag (0x20); M derives at encode"
        );
        match &push.keyexpr.body {
            WireexprOwnedVariant::WireexprLocal(arm) => {
                assert_eq!(arm.id, 0, "literal-keyexpr path uses id=0 sentinel");
                assert_eq!(
                    arm.suffix.as_deref(),
                    Some("demo/test"),
                    "suffix must carry the literal keyexpr string"
                );
                assert_eq!(
                    arm.suffix_len,
                    Some(9),
                    "suffix_len must match suffix.len() so the encoder emits the VLE width"
                );
            }
            WireexprOwnedVariant::WireexprNonlocal(_) => {
                panic!("literal-keyexpr path must select the WireexprLocal arm (M=1)")
            }
        }
        match &push.body {
            PushOwnedVariant::CodecZenohMsgPut(put) => {
                assert_eq!(put.header, 0x01, "MsgPut header MID = 0x01 with no flags");
                assert_eq!(
                    put.payload, b"hello",
                    "MsgPut.payload carries the application bytes verbatim"
                );
                assert_eq!(
                    put.payload_len, 5,
                    "MsgPut.payload_len must match payload.len() for the VLE writer"
                );
                assert!(put.timestamp.is_none(), "no timestamp flag on the MVP path");
                assert!(put.encoding.is_none(), "no encoding flag on the MVP path");
                assert!(
                    put.extensions.is_none(),
                    "no MsgPut-level extensions on the MVP path"
                );
            }
            other => panic!(
                "MVP build_push_literal must emit MsgPut body, got {:?}",
                match other {
                    PushOwnedVariant::CodecZenohMsgDel(_) => "MsgDel",
                    PushOwnedVariant::Default { .. } => "Default",
                    PushOwnedVariant::CodecZenohMsgPut(_) => unreachable!(),
                }
            ),
        }
        assert!(
            push.extensions.is_none(),
            "no Push-level extensions on the MVP path"
        );
    }

    /// R121g — `build_push_aliased` produces a `WireexprLocal`
    /// with the non-zero mapping id, while `build_push_literal`
    /// produces id=0 + inline suffix. The aliased Push is the
    /// efficient repeated-keyexpr shape that follows a peer-side
    /// `DeclKexpr` registration.
    #[test]
    fn build_push_aliased_carries_non_zero_id_with_optional_suffix() {
        let pure = build_push_aliased(7, None, b"hello").unwrap();
        match &pure.keyexpr.body {
            WireexprOwnedVariant::WireexprLocal(w) => {
                assert_eq!(w.id, 7, "pure aliased Push id must equal mapping_id");
                assert_eq!(w.suffix, None, "pure aliased Push must omit suffix");
                assert_eq!(w.suffix_len, None, "pure aliased Push must omit suffix_len");
            }
            _ => panic!("build_push_aliased must produce a WireexprLocal arm"),
        }
        match &pure.body {
            PushOwnedVariant::CodecZenohMsgPut(p) => {
                assert_eq!(p.payload.as_slice(), b"hello");
                assert_eq!(p.payload_len, 5);
            }
            _ => panic!("build_push_aliased must wrap a MsgPut body"),
        }

        let composite = build_push_aliased(7, Some("tail"), b"hi").unwrap();
        match &composite.keyexpr.body {
            WireexprOwnedVariant::WireexprLocal(w) => {
                assert_eq!(w.id, 7);
                assert_eq!(w.suffix.as_deref(), Some("tail"));
                assert_eq!(w.suffix_len, Some(4));
            }
            _ => panic!("composite aliased Push must produce a WireexprLocal arm"),
        }
    }

    /// R121g — `build_push_aliased` rejects `mapping_id == 0` so a
    /// caller cannot silently produce a literal-keyexpr Push via
    /// the aliased entry point.
    #[test]
    #[should_panic(expected = "build_push_aliased requires a non-zero mapping id")]
    fn build_push_aliased_rejects_zero_mapping_id() {
        let _ = build_push_aliased(0, Some("demo"), b"");
    }

    /// R219 — `build_push_del_literal` produces a literal-keyexpr
    /// Push whose body is the `MsgDel` arm (inner header 0x02,
    /// no payload, no timestamp / extensions). The outer Push
    /// header + WireexprLocal shape match the Put literal path.
    #[test]
    fn build_push_del_literal_shapes_struct_for_literal_keyexpr() {
        let push = build_push_del_literal("demo/test").unwrap();
        assert_eq!(
            push.header, 0x3D,
            "Push.header must carry N_MID_PUSH (0x1D) | N flag (0x20) — same as the Put literal path"
        );
        match &push.keyexpr.body {
            WireexprOwnedVariant::WireexprLocal(arm) => {
                assert_eq!(arm.id, 0, "literal-keyexpr path uses id=0 sentinel");
                assert_eq!(
                    arm.suffix.as_deref(),
                    Some("demo/test"),
                    "suffix must carry the literal keyexpr string"
                );
                assert_eq!(
                    arm.suffix_len,
                    Some(9),
                    "suffix_len must match suffix.len() for the VLE writer"
                );
            }
            WireexprOwnedVariant::WireexprNonlocal(_) => {
                panic!("literal-keyexpr path must select the WireexprLocal arm (M=1)")
            }
        }
        match &push.body {
            PushOwnedVariant::CodecZenohMsgDel(del) => {
                assert_eq!(del.header, 0x02, "MsgDel header MID = 0x02 with no flags");
                assert!(
                    del.timestamp.is_none(),
                    "MVP Del path emits no timestamp flag"
                );
                assert!(
                    del.extensions.is_none(),
                    "MVP Del path emits no MsgDel-level extensions"
                );
            }
            other => panic!(
                "build_push_del_literal must emit MsgDel body, got {:?}",
                match other {
                    PushOwnedVariant::CodecZenohMsgPut(_) => "MsgPut",
                    PushOwnedVariant::Default { .. } => "Default",
                    PushOwnedVariant::CodecZenohMsgDel(_) => unreachable!(),
                }
            ),
        }
        assert!(
            push.extensions.is_none(),
            "no Push-level extensions on the MVP path"
        );
    }

    /// R219 — `build_push_del_aliased` produces a DECLARE-aliased
    /// Push whose body is the `MsgDel` arm. Both pure-aliased
    /// (suffix=None) and composite-aliased (suffix=Some) shapes are
    /// exercised so the N-flag derivation matches the Put aliased
    /// path. The MsgDel body content is identical across shapes.
    #[test]
    fn build_push_del_aliased_carries_non_zero_id_with_optional_suffix() {
        let pure = build_push_del_aliased(7, None).unwrap();
        assert_eq!(
            pure.header,
            wire_const::N_MID_PUSH,
            "pure aliased Push (no suffix) must clear the N flag",
        );
        match &pure.keyexpr.body {
            WireexprOwnedVariant::WireexprLocal(w) => {
                assert_eq!(w.id, 7, "pure aliased Push id must equal mapping_id");
                assert_eq!(w.suffix, None, "pure aliased Push must omit suffix");
                assert_eq!(w.suffix_len, None, "pure aliased Push must omit suffix_len");
            }
            _ => panic!("build_push_del_aliased must produce a WireexprLocal arm"),
        }
        match &pure.body {
            PushOwnedVariant::CodecZenohMsgDel(d) => {
                assert_eq!(d.header, 0x02);
            }
            _ => panic!("build_push_del_aliased must wrap a MsgDel body"),
        }

        let composite = build_push_del_aliased(7, Some("tail")).unwrap();
        assert_eq!(
            composite.header,
            wire_const::N_MID_PUSH | 0x20,
            "composite aliased Push (suffix present) must set the N flag",
        );
        match &composite.keyexpr.body {
            WireexprOwnedVariant::WireexprLocal(w) => {
                assert_eq!(w.id, 7);
                assert_eq!(w.suffix.as_deref(), Some("tail"));
                assert_eq!(w.suffix_len, Some(4));
            }
            _ => panic!("composite aliased Push must produce a WireexprLocal arm"),
        }
        match &composite.body {
            PushOwnedVariant::CodecZenohMsgDel(d) => {
                assert_eq!(d.header, 0x02);
            }
            _ => panic!("composite aliased Push must wrap a MsgDel body"),
        }
    }

    /// R219 — `build_push_del_aliased` rejects `mapping_id == 0` so
    /// a caller cannot silently produce a literal-keyexpr Del Push
    /// via the aliased entry point.
    #[test]
    #[should_panic(expected = "build_push_del_aliased requires a non-zero mapping id")]
    fn build_push_del_aliased_rejects_zero_mapping_id() {
        let _ = build_push_del_aliased(0, Some("demo"));
    }

    /// R219 — round-trip the literal-keyexpr Del path through
    /// `encode_frame_with_push` + `parse_inbound` so the wz
    /// receive-side parser surfaces the `MsgDel` inner body
    /// (not `MsgPut`) on the decoded `Push`. Establishes the wire-
    /// shape witness that pairs with the e2e zenoh-pico interop
    /// test — z_sub's printout cannot distinguish Del from
    /// empty-Put, so the codec-level round-trip is the definitive
    /// proof that the wz-side encoder emits the Del MID.
    #[test]
    fn build_push_del_literal_round_trips_through_frame_decode_as_msg_del() {
        let push = build_push_del_literal("demo/test").unwrap();
        let wire = encode_frame_with_push(/*sn=*/ 0, push, /*reliable=*/ true);
        let parsed = parse_inbound(&wire).expect("parse_inbound on Del-bearing Frame");
        let payload = match parsed {
            InboundFrame::Frame { payload, .. } => payload,
            _ => panic!("expected Frame variant from parse_inbound"),
        };
        let messages =
            parse_frame_payload(&payload).expect("parse_frame_payload on Del-bearing Frame");
        assert_eq!(
            messages.len(),
            1,
            "Frame must carry exactly one Push record after round-trip"
        );
        match &messages[0] {
            NetworkMessage::Push(p) => match &p.body {
                PushOwnedVariant::CodecZenohMsgDel(d) => {
                    assert_eq!(
                        d.header, 0x02,
                        "round-tripped MsgDel must preserve its MID byte"
                    );
                }
                other => panic!(
                    "round-tripped Push body must be MsgDel, got {:?}",
                    match other {
                        PushOwnedVariant::CodecZenohMsgPut(_) => "MsgPut",
                        PushOwnedVariant::Default { .. } => "Default",
                        PushOwnedVariant::CodecZenohMsgDel(_) => unreachable!(),
                    }
                ),
            },
            _ => panic!("expected NetworkMessage::Push from round-trip"),
        }
    }

    #[test]
    fn push_metadata_is_empty_returns_true_only_when_all_fields_none() {
        let empty = PushMetadata::default();
        assert!(empty.is_empty());

        let with_ts = PushMetadata {
            timestamp: Some(TimestampHint::default()),
            ..Default::default()
        };
        assert!(!with_ts.is_empty());

        let with_qos = PushMetadata {
            qos: Some(QosLevel::from_raw(0)),
            ..Default::default()
        };
        assert!(!with_qos.is_empty());
    }

    #[cfg(any(
        feature = "pubsub-priority",
        feature = "pubsub-congestion-control",
        feature = "pubsub-express"
    ))]
    #[test]
    fn build_push_literal_with_meta_sets_push_header_z_bit_when_qos_attached() {
        let meta = PushMetadata {
            qos: Some(QosLevel::from_raw(0x10)),
            ..Default::default()
        };
        let push = build_push_literal_with_meta("home/temp", b"22.5", &meta).unwrap();
        // Push.header bit 7 (0x80) = Z chain-continuation for outer
        // extensions. Must be set when an outer extension is present.
        assert_eq!(push.header & 0x80, 0x80);
        assert!(push.extensions.is_some());
        // No body metadata → MsgPut.extensions stays None.
        if let PushOwnedVariant::CodecZenohMsgPut(put) = &push.body {
            assert!(put.extensions.is_none());
            assert!(!put.z(), "MsgPut Z stays clear without body extensions");
        } else {
            panic!("CodecZenohMsgPut variant expected");
        }
    }

    #[cfg(all(
        feature = "pubsub-attachment",
        feature = "pubsub-timestamp",
        feature = "pubsub-encoding",
        feature = "pubsub-source-info",
        any(
            feature = "pubsub-priority",
            feature = "pubsub-congestion-control",
            feature = "pubsub-express"
        )
    ))]
    #[test]
    fn build_push_literal_with_meta_round_trips_through_codec_encode_decode() {
        // End-to-end: build → encode_to_vec → decode → field equality.
        // Validates that the wire form survives SCE's encode/decode
        // path with every metadata field set, not just that the
        // in-memory Push struct shape is correct.
        let meta = PushMetadata {
            timestamp: Some(TimestampHint {
                time: 0x1122_3344_5566_7788,
                zid: vec![0xAA, 0xBB, 0xCC],
            }),
            encoding: Some(EncodingHint {
                packed_id: 5,
                schema: Some("text/plain".into()),
            }),
            source_info: Some(SourceInfo::new(&[0x01, 0x02, 0x03, 0x04], 7, 42)),
            attachment: Some(b"attach".to_vec()),
            qos: Some(QosLevel::from_raw(0b0001_1010)),
        };
        let push = build_push_literal_with_meta("home/temp", b"payload", &meta).unwrap();
        let encoded = push.wire();

        // Decode back via SCE-emitted cursor path. wz-codecs re-exports
        // SceCursor through the runtime crate; use the same path the
        // dispatcher takes when handling wire-arrived frames.
        let mut cursor = sce_forge_runtime::codec::SceCursor::new(&encoded);
        let decoded = Push::decode(&mut cursor)
            .expect("Push round-trip decode")
            .try_into_owned()
            .unwrap();

        // Outer Push extensions: qos must round-trip.
        let outer = decoded
            .extensions
            .as_deref()
            .expect("outer ext chain present");
        assert_eq!(outer.len(), 1);
        if let ExtEntryOwnedVariant::CodecZenohExtZint(z) = &outer[0].body {
            assert_eq!(z.value, 0b0001_1010);
        } else {
            panic!("qos outer ext must decode to ExtZint");
        }

        // Inner MsgPut: timestamp/encoding/extensions round-trip.
        if let PushOwnedVariant::CodecZenohMsgPut(put) = &decoded.body {
            let ts = put.timestamp.as_ref().expect("timestamp round-trips");
            assert_eq!(ts.time, 0x1122_3344_5566_7788);
            assert_eq!(ts.zid.as_slice(), &[0xAA, 0xBB, 0xCC]);
            let enc = put.encoding.as_ref().expect("encoding round-trips");
            assert_eq!(enc.packed_id, 5);
            assert_eq!(enc.schema.as_deref(), Some("text/plain"));
            let body_exts = put.extensions.as_deref().expect("body ext chain present");
            assert_eq!(body_exts.len(), 2, "source_info + attachment");
            // Use the runtime's dispatcher projection to validate the
            // bytes resolve back to the original metadata.
            let si = crate::sample::extract_source_info(body_exts)
                .expect("source_info round-trips through wire");
            assert_eq!(si.zid_len, 4);
            assert_eq!(si.zid_prefix(), &[0x01, 0x02, 0x03, 0x04][..]);
            assert_eq!(si.eid, 7);
            assert_eq!(si.sn, 42);
            let att = crate::attachment::decode_attachment_ext(
                body_exts,
                crate::attachment::ATTACHMENT_EXT_ID_PUSH,
            )
            .map(<[u8]>::to_vec)
            .expect("attachment round-trips through wire");
            assert_eq!(att, b"attach");
        } else {
            panic!("CodecZenohMsgPut variant expected");
        }
    }

    // Constructs every PushMetadata field (incl. encoding / source_info /
    // qos) to prove the Del wire form DROPS encoding, so it gates on all of
    // those features even though the encoding is intentionally not emitted.
    #[cfg(all(
        feature = "pubsub-attachment",
        feature = "pubsub-timestamp",
        feature = "pubsub-encoding",
        feature = "pubsub-source-info",
        any(
            feature = "pubsub-priority",
            feature = "pubsub-congestion-control",
            feature = "pubsub-express"
        )
    ))]
    #[test]
    fn build_push_del_literal_with_meta_round_trips_metadata_minus_encoding() {
        // Del path: timestamp + source_info + attachment + qos must
        // round-trip; encoding has no parameter slot so the wire form
        // cannot carry it. Mirrors the loopback path's projection.
        let meta = PushMetadata {
            timestamp: Some(TimestampHint {
                time: 0xAABB_CCDD,
                zid: vec![0x42],
            }),
            encoding: Some(EncodingHint {
                packed_id: 99,
                schema: Some("ignored".into()),
            }),
            source_info: Some(SourceInfo::new(&[0xDE, 0xAD], 1, 2)),
            attachment: Some(b"del-att".to_vec()),
            qos: Some(QosLevel::from_raw(0x10)),
        };
        let push = build_push_del_literal_with_meta("home/temp", &meta).unwrap();
        let encoded = push.wire();
        let mut cursor = sce_forge_runtime::codec::SceCursor::new(&encoded);
        let decoded = Push::decode(&mut cursor)
            .expect("Push(MsgDel) round-trip")
            .try_into_owned()
            .unwrap();

        if let PushOwnedVariant::CodecZenohMsgDel(del) = &decoded.body {
            assert_eq!(del.timestamp.as_ref().unwrap().time, 0xAABB_CCDD);
            let body_exts = del.extensions.as_deref().expect("body ext chain present");
            // Del bodies carry source_info + attachment but NOT encoding.
            assert_eq!(body_exts.len(), 2);
            let si = crate::sample::extract_source_info(body_exts).unwrap();
            assert_eq!(si.eid, 1);
            assert_eq!(si.sn, 2);
            let att = crate::attachment::decode_attachment_ext(
                body_exts,
                crate::attachment::ATTACHMENT_EXT_ID_PUSH,
            )
            .map(<[u8]>::to_vec)
            .unwrap();
            assert_eq!(att, b"del-att");
        } else {
            panic!("CodecZenohMsgDel variant expected");
        }
    }

    #[test]
    fn reliteralize_push_passes_a_literal_keyexpr_through_verbatim() {
        // A literal (id=0) source is decodable by any peer as-is; reliteralize
        // returns it verbatim and IGNORES the passed keyexpr (the fast path).
        let literal = build_push_literal("demo/test", b"hi").unwrap();
        let fwd = reliteralize_push(&literal, "ignored/keyexpr").unwrap();
        assert_eq!(
            fwd, literal,
            "a literal source is forwarded verbatim, the keyexpr arg ignored"
        );
    }

    #[test]
    fn reliteralize_push_re_keys_an_aliased_keyexpr_to_a_literal() {
        // An aliased (id=9, no suffix) Put — its Push header has the N flag CLEAR.
        let aliased = build_push_aliased(9, None, b"hi").unwrap();
        assert_eq!(
            aliased.header,
            wire_const::N_MID_PUSH,
            "aliased source carries the N flag clear (no suffix)"
        );

        let fwd = reliteralize_push(&aliased, "home/temp").unwrap();

        match &fwd.keyexpr.body {
            WireexprOwnedVariant::WireexprLocal(arm) => {
                assert_eq!(arm.id, 0, "re-literalized to the id=0 sentinel");
                assert_eq!(arm.suffix.as_deref(), Some("home/temp"));
                assert_eq!(arm.suffix_len, Some(9));
            }
            WireexprOwnedVariant::WireexprNonlocal(_) => {
                panic!("re-literalize must select the WireexprLocal arm")
            }
        }
        // N flag SET (suffix now present), same header bit build_push_literal uses.
        assert_eq!(
            fwd.header,
            wire_const::N_MID_PUSH | 0x20,
            "N flag set after re-literalize (the keyexpr now carries a suffix)"
        );
        // The Put body is preserved verbatim through the re-key.
        match &fwd.body {
            PushOwnedVariant::CodecZenohMsgPut(put) => {
                assert_eq!(put.payload, b"hi", "payload preserved through re-key");
            }
            _ => panic!("MsgPut body expected"),
        }
    }
}
