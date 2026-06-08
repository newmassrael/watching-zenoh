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
use crate::source_info_ext::encode_source_info_ext_body;
#[cfg(any(
    feature = "pubsub-source-info",
    feature = "pubsub-priority",
    feature = "pubsub-congestion-control",
    feature = "pubsub-express"
))]
use wz_codecs::ext_entry::ExtEntryOwnedVariant;
#[cfg(feature = "pubsub-source-info")]
use wz_codecs::ext_zbuf::ExtZbufOwned;
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
#[cfg(feature = "codec-push")]
pub fn build_push_literal(keyexpr_suffix: &str, value: &[u8]) -> Result<PushOwned, CodecError> {
    let suffix_len = keyexpr_suffix.len() as u64;
    let payload_len = value.len() as u64;
    Ok(PushOwned {
        // `N_MID_PUSH | N_flag(0x20)` — M flag derives from the
        // WireexprLocal arm at encode time (push.rs:189).
        header: wire_const::N_MID_PUSH | 0x20,
        keyexpr: WireexprOwned {
            body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                id: 0,
                suffix_len: Some(suffix_len),
                suffix: Some(crate::codec_bound::bounded_string(keyexpr_suffix)?),
            }),
        },
        extensions: None,
        body: PushOwnedVariant::CodecZenohMsgPut(MsgPutOwned {
            header: 0x01,
            timestamp: None,
            encoding: None,
            extensions: None,
            payload_len,
            payload: crate::codec_bound::bounded_bytes(value)?,
        }),
    })
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
#[cfg(feature = "codec-push")]
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
    let suffix_string = suffix.map(crate::codec_bound::bounded_string).transpose()?;
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
            payload: crate::codec_bound::bounded_bytes(value)?,
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
#[cfg(feature = "codec-push")]
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
                suffix: Some(crate::codec_bound::bounded_string(keyexpr_suffix)?),
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
#[cfg(feature = "codec-push")]
pub fn build_push_del_aliased(
    mapping_id: u64,
    suffix: Option<&str>,
) -> Result<PushOwned, CodecError> {
    assert!(
        mapping_id != 0,
        "build_push_del_aliased requires a non-zero mapping id; use build_push_del_literal for id=0",
    );
    let suffix_len = suffix.map(|s| s.len() as u64);
    let suffix_string = suffix.map(crate::codec_bound::bounded_string).transpose()?;
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
#[cfg(feature = "codec-push")]
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
            let body_bytes = encode_source_info_ext_body(prefix, si.eid, si.sn);
            exts.push(ExtEntryOwned {
                // ENC_ZBUF(0x40) | id_source_info(0x01). No M flag —
                // source_info is informational (zenoh-pico
                // `_z_msg_ext_t._source_info` emit at
                // message.c:_z_push_body_encode_extensions has no M
                // bit). Z chain-continuation bit applied below.
                header: 0x40 | 0x01,
                body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                    value_len: body_bytes.len() as u64,
                    value: crate::codec_bound::bounded_bytes(&body_bytes)?,
                }),
            });
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
    apply_chain_z_bits(&mut exts);
    Ok(Some(exts))
}

/// R233 — set the `Z` (chain-continuation, 0x80) bit on every
/// `ExtEntry` in a chain except the last. The SCE-emitted
/// `MsgPut::encode` / `MsgDel::encode` / `Push::encode` paths iterate
/// the extension `Vec` and call each entry's own `encode` without
/// adjusting the chain-continuation bit; the author owns Z. Mirrors
/// the explicit flip pattern in `encode_ext_chain` (used for
/// transport-message chains) so body / outer Push chains share the
/// same invariant. Single-entry chains keep Z=0 (terminator).
#[cfg(feature = "codec-push")]
fn apply_chain_z_bits(entries: &mut [ExtEntryOwned]) {
    if entries.is_empty() {
        return;
    }
    let last = entries.len() - 1;
    for (i, entry) in entries.iter_mut().enumerate() {
        if i == last {
            entry.header &= !0x80;
        } else {
            entry.header |= 0x80;
        }
    }
}

/// R233 — build the outer Push extension chain (currently only QoS).
/// Returns `None` when no outer extension is requested so the caller
/// can leave `Push.extensions = None` and clear the Push-header Z
/// bit. zenoh-pico mirror: `_z_n_msg_encode_push` outer-ext switch
/// at network.c — qos lands on the outer chain, source_info /
/// attachment on the body chain (`_z_push_body_encode_extensions`).
#[cfg(feature = "codec-push")]
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
    apply_chain_z_bits(&mut exts);
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
#[cfg(feature = "codec-push")]
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
#[cfg(feature = "codec-push")]
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
#[cfg(feature = "codec-push")]
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
        payload: crate::codec_bound::bounded_bytes(payload)?,
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
#[cfg(feature = "codec-push")]
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
#[cfg(feature = "codec-push")]
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
                suffix: Some(crate::codec_bound::bounded_string(keyexpr_suffix)?),
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

/// R233 — metadata-bearing counterpart of [`build_push_aliased`].
#[cfg(feature = "codec-push")]
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
    let suffix_string = suffix.map(crate::codec_bound::bounded_string).transpose()?;
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
#[cfg(feature = "codec-push")]
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
                suffix: Some(crate::codec_bound::bounded_string(keyexpr_suffix)?),
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
#[cfg(feature = "codec-push")]
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
    let suffix_string = suffix.map(crate::codec_bound::bounded_string).transpose()?;
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
    // no_std crate: the `vec!` macro is not in the prelude. Only the
    // `pubsub-timestamp` tests build a `zid: vec![..]`, so gate to match.
    #[cfg(feature = "pubsub-encoding")]
    use crate::sample::EncodingHint;
    #[cfg(any(
        feature = "pubsub-priority",
        feature = "pubsub-congestion-control",
        feature = "pubsub-express"
    ))]
    use crate::sample::QosLevel;
    #[cfg(feature = "pubsub-source-info")]
    use crate::sample::SourceInfo;
    #[cfg(feature = "pubsub-timestamp")]
    use crate::sample::TimestampHint;
    #[cfg(feature = "pubsub-timestamp")]
    use alloc::vec;

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

    #[cfg(feature = "codec-push")]
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

    #[cfg(feature = "codec-push")]
    #[test]
    fn build_push_outer_extensions_returns_none_without_qos() {
        assert!(build_push_outer_extensions(None).is_none());
    }
}
