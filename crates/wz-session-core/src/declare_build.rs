// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Outbound DECLARE / UNDECLARE network-message builders.
//!
//! The `build_declare_*` family constructs the `DeclareOwned` codec struct
//! for keyexpr-mapping / subscriber / queryable / liveliness-token
//! declarations (Local and Nonlocal wireexpr arms), the `build_undeclare_*`
//! family the matching id-based retractions, and `build_declare_final` the
//! sequence terminator. Pure wz-codecs constructors — no runtime / no FSM
//! coupling; the transport-`Frame` envelope is applied separately by
//! `frame_encode::encode_frame_with_declare`.
//!
//! Hoisted from `wz-runtime-tokio::session_glue` so both runtime profiles
//! share one DECLARE-builder SSOT — the MCU `#![no_std]` profile cannot
//! depend on the tokio crate. Owned `Vec` output, so alloc-gated; the whole
//! module is `codec-declare`-gated at the `lib.rs` declaration.
//!
//! Distinct from the `declare` module (the application-layer remote-
//! declaration *registries*): this module is the outbound *encode* side.

use sce_forge_runtime::codec::CodecError;
use wz_codecs::wire_const;

use wz_codecs::decl_final::DeclFinal;
use wz_codecs::decl_kexpr::DeclKexprOwned;
use wz_codecs::decl_queryable::DeclQueryableOwned;
use wz_codecs::decl_subscriber::DeclSubscriberOwned;
use wz_codecs::decl_token::DeclTokenOwned;
use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant};
use wz_codecs::undecl_kexpr::UndeclKexpr;
use wz_codecs::undecl_queryable::UndeclQueryableOwned;
use wz_codecs::undecl_subscriber::UndeclSubscriberOwned;
use wz_codecs::undecl_token::UndeclTokenOwned;
use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};
use wz_codecs::wireexpr_local::WireexprLocalOwned;
use wz_codecs::wireexpr_nonlocal::WireexprNonlocalOwned;

/// R121g — build a `Declare` network-message that registers a
/// literal-keyexpr mapping. The peer's inbound dispatch
/// (zenoh-pico's `_z_session_recv_declaration` →
/// `_z_register_resource`) inserts `mapping_id → suffix` into its
/// local keyexpr table, after which any inbound Push with
/// `WireexprLocal { id: mapping_id, suffix: None }` resolves to the
/// declared literal.
///
/// Wire shape (per
/// `vendor/zenoh-pico/src/protocol/codec/declarations.c:52-63`):
///
/// ```text
///   [DeclKexpr.header = _Z_DECL_KEXPR_MID(0x00)
///                       | (suffix.is_some() ? _Z_DECL_KEXPR_FLAG_N(0x20) : 0)
///                       | (WireexprLocal ? B5-ν derived 0x40 : 0)]
///   VLE(mapping_id)
///   WireexprLocal.encode (id VLE + optional suffix_len VLE + suffix bytes)
/// ```
///
/// Wrapped in a `Declare` envelope with the network MID header
/// `N_MID_DECLARE (0x1E)`, no `interest_id`, no extensions.
///
/// Panics if `mapping_id == 0` — id zero is reserved as the
/// literal-keyexpr sentinel and a DECLARE with id=0 has no
/// table-population semantics in zenoh-pico.
pub fn build_declare_kexpr(mapping_id: u64, suffix: &str) -> Result<DeclareOwned, CodecError> {
    assert!(
        mapping_id != 0,
        "build_declare_kexpr requires a non-zero mapping id; id=0 is the literal-keyexpr sentinel",
    );
    let suffix_len = Some(suffix.len() as u64);
    Ok(DeclareOwned {
        // `N_MID_DECLARE (0x1E)` — no I (interest_id), no Z
        // (extensions); the MVP wires only the unsolicited
        // mapping-population shape that zenoh-pico emits on
        // `z_declare_keyexpr` without an Interest reply context.
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohDeclKexpr(DeclKexprOwned {
            // Inner DeclKexpr header MUST carry `_Z_DECL_KEXPR_FLAG_N
            // (0x20)` when the keyexpr has a suffix string, per
            // `vendor/zenoh-pico/src/protocol/codec/declarations.c:52-58`.
            // The peer (zenoh-pico) gates the wireexpr suffix decode
            // on this bit (declarations.c:185); a missing N flag
            // drops the codec into an offset-shifted read of the
            // next message, surfaced as `Unknown message type
            // received` by `_z_network_message_decode`. The wz codec
            // does not auto-derive this flag from suffix presence —
            // author must set it explicitly.
            //
            // Inner arm = `WireexprLocal` (semantically correct: the
            // declared keyexpr lives in the local mapping table).
            // R121h-pre — SCE vendor pin e10619d3's B5-ν ownership
            // invert moved the wireexpr arm dispatch decision to the
            // parent's `<sce:import>` site
            // (sources/codecs/decl_kexpr.scxml). DeclKexpr deliberately
            // omits the `<sce:variant-dispatch>` child because its
            // header has no flag at bit 6 — the wireexpr arm choice
            // is a type-level refinement only and no parent derive
            // bit is emitted. The pre-R121h-pre WireexprNonlocal
            // workaround (used to suppress the codegen's spurious
            // 0x40 OR under the leaf-owned `tag="parent.M"` regime)
            // has retired with this pin bump.
            header: wire_const::D_MID_KEXPR | wire_const::FLAG_D_N, // DeclKexpr MID(0x00) + N
            id: mapping_id,
            keyexpr: WireexprOwned {
                body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                    id: 0,
                    suffix_len,
                    suffix: Some(crate::codec_owned::owned_string(suffix)?),
                }),
            },
        }),
    })
}

/// R121i — build a `Declare` network-message that registers a
/// subscriber on the peer for `(keyexpr_mapping_id, keyexpr_suffix)`.
/// Mirrors zenoh-pico `_z_decl_subscriber_encode` +
/// `_z_decl_commons_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/declarations.c:65-84`.
///
/// Wire shape (after the `N_MID_DECLARE` envelope header):
///
/// ```text
///   [DeclSubscriber.header = _Z_DECL_SUBSCRIBER_MID (0x02)
///                            | (suffix.is_some() ? 0x20 : 0)
///                            | (codegen-derived: 0x40 from parent.M
///                              dispatch on the wireexpr import,
///                              always set under the wz convention of
///                              Local-arm wireexpr)]
///   VLE(subscriber_id)
///   wireexpr.encode  (id VLE + optional suffix_len VLE + suffix bytes)
/// ```
///
/// The 0x40 M bit is NOT set in the author-supplied header here —
/// the SCE codegen ORs it in at encode time based on the
/// `<sce:variant-dispatch flag="header.M"/>` declared on the
/// wireexpr `<sce:import>` in `sources/codecs/decl_subscriber.scxml`
/// (post-R121h-pre B5-ν ownership invert). The N bit (0x20) IS
/// author-supplied because it gates wireexpr suffix presence — wz
/// codecs do not auto-derive that from the wireexpr field at emit
/// time (zenoh-pico's `_z_decl_commons_encode` reads the suffix
/// presence and sets N; wz mirrors this in the build helper rather
/// than in codegen).
///
/// The wireexpr arm is always `WireexprLocal` here — under the
/// R121h-pre invert + wireexpr.scxml `default="true"` on the
/// wireexpr_local arm, this also drives the codegen-derived M bit
/// in the parent header. `WireexprNonlocal` (literal-only) is
/// reserved for future Interest/Reply paths.
///
/// Convention (matches `build_push_aliased` / [`build_declare_kexpr`]):
///   - `keyexpr_mapping_id == 0, suffix = Some(s)`: literal — the
///     subscribed keyexpr is `s` itself (the peer parses VLE(0) +
///     VLE(len) + suffix bytes; id=0 is the wz literal-sentinel).
///   - `keyexpr_mapping_id == N, suffix = None`: alias — the
///     subscribed keyexpr is the peer's mapping for `N`.
///   - `keyexpr_mapping_id == N, suffix = Some(s)`: compound — the
///     subscribed keyexpr is mapping `N`'s prefix + `s`.
pub fn build_declare_subscriber(
    subscriber_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Result<DeclareOwned, CodecError> {
    let suffix_len = keyexpr_suffix.map(|s| s.len() as u64);
    let suffix_string = keyexpr_suffix
        .map(crate::codec_owned::owned_string)
        .transpose()?;
    let n_flag = if keyexpr_suffix.is_some() {
        0x20u8
    } else {
        0x00u8
    };
    Ok(DeclareOwned {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohDeclSubscriber(DeclSubscriberOwned {
            // MID 0x02 (decl_subscriber) + N gate; M is codegen-
            // derived (see fn-level doc comment).
            header: wire_const::D_MID_SUBSCRIBER | n_flag,
            id: subscriber_id,
            keyexpr: WireexprOwned {
                body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                    id: keyexpr_mapping_id,
                    suffix_len,
                    suffix: suffix_string,
                }),
            },
        }),
    })
}

/// R121i-b — build a `Declare` network-message that registers a
/// queryable on the peer for `(keyexpr_mapping_id, keyexpr_suffix)`.
/// Mirrors zenoh-pico `_z_decl_queryable_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/declarations.c:105-118`,
/// with `_z_decl_commons_encode` (declarations.c:65-80) providing the
/// shared `[header | id | wireexpr]` body.
///
/// AP MVP scope: the wz codec emits the `has_info_ext = false` shape
/// (no `_Z_MSG_EXT_ENC_ZINT | 0x01` `ExtQueryableInfo` tail). zenoh-
/// pico produces the same byte sequence when both `complete = false`
/// and `distance = 0`, which is the default `_z_queryable_infos_t`
/// shipped by `z_query_consolidation_default`. A future round (R121j)
/// that needs `complete = true` or non-zero `distance` will add a
/// separate `build_declare_queryable_with_info` helper carrying the
/// extra `Z` ext bytes; this helper's wire-byte contract for the
/// no-ext shape is pinned by the byte-compare test below.
///
/// Wire shape (after the `N_MID_DECLARE` envelope header):
///
/// ```text
///   [DeclQueryable.header = _Z_DECL_QUERYABLE_MID (0x04)
///                            | (suffix.is_some() ? 0x20 : 0)
///                            | (codegen-derived: 0x40 from parent.M
///                              dispatch on the wireexpr import,
///                              always set under the wz convention of
///                              Local-arm wireexpr)]
///   VLE(queryable_id)
///   wireexpr.encode  (id VLE + optional suffix_len VLE + suffix bytes)
/// ```
///
/// The codegen-derived M bit follows the same convention as
/// [`build_declare_subscriber`]: `<sce:variant-dispatch
/// flag="header.M"/>` on the wireexpr `<sce:import>` in
/// `sources/codecs/decl_queryable.scxml` (post-R121h-pre B5-ν
/// ownership invert) ORs 0x40 in for the `WireexprLocal` arm. The
/// author-supplied header carries the MID + optional N (suffix gate);
/// M is derived at encode time.
///
/// `keyexpr_mapping_id` / `keyexpr_suffix` convention mirrors
/// [`build_declare_subscriber`]:
///   - `(0, Some(s))`: literal — the queried keyexpr is `s` itself
///     (id=0 is the wz literal-sentinel).
///   - `(N, None)`: alias — the queried keyexpr is the peer's
///     mapping for `N`.
///   - `(N, Some(s))`: compound — alias `N`'s prefix + `s`.
pub fn build_declare_queryable(
    queryable_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Result<DeclareOwned, CodecError> {
    let suffix_len = keyexpr_suffix.map(|s| s.len() as u64);
    let suffix_string = keyexpr_suffix
        .map(crate::codec_owned::owned_string)
        .transpose()?;
    let n_flag = if keyexpr_suffix.is_some() {
        0x20u8
    } else {
        0x00u8
    };
    Ok(DeclareOwned {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohDeclQueryable(DeclQueryableOwned {
            // MID 0x04 (_Z_DECL_QUERYABLE_MID per
            // vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/declarations.h:32)
            // + N gate; M is codegen-derived.
            header: wire_const::D_MID_QUERYABLE | n_flag,
            id: queryable_id,
            keyexpr: WireexprOwned {
                body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                    id: keyexpr_mapping_id,
                    suffix_len,
                    suffix: suffix_string,
                }),
            },
            // R311ui: no QueryableInfo ext by default (zenoh DEFAULT { complete:
            // false, distance: 0 }) — Z stays clear, byte-identical no-ext wire.
            extensions: None,
        }),
    })
}

/// R311uj — stamp a [`QueryableInfo`](crate::queryable_info::QueryableInfo) onto
/// a built `Declare(DeclQueryable)`: the producer seam for
/// QueryTarget::BestMatching (a complete queryable, or one at a known distance,
/// advertises it so a relay can prefer the nearest complete one). zenoh's
/// omit-on-DEFAULT — the DEFAULT `{ complete: false, distance: 0 }` leaves the
/// body ext-free (header `Z` clear, byte-identical to the no-info builder
/// output), any other value rides the body's `Z`-gated ext chain (R311ui
/// capacity). Returns whether an ext is now present; a no-op `false` if `declare`
/// is not a DeclQueryable. The post-build twin of `set_declare_source` (the
/// envelope routing-context ext setter), here on the BODY's ext chain.
#[cfg(feature = "codec-declare")]
pub fn set_declare_queryable_info(
    declare: &mut DeclareOwned,
    info: crate::queryable_info::QueryableInfo,
) -> bool {
    let DeclareOwnedVariant::CodecZenohDeclQueryable(d) = &mut declare.body else {
        return false;
    };
    let present = crate::queryable_info::set_queryable_info(&mut d.extensions, info);
    // Sync the body header's message-level Z bit to chain presence via the SSOT
    // helper (MESSAGE_FLAG_Z — the body HEADER bit, distinct from the per-entry
    // EXT_FLAG_Z: for a single ext the header Z is set while that ext's own Z is
    // clear).
    crate::ext_nodeid::sync_header_z(&mut d.header, present);
    present
}

/// R121i-b — build a `Declare` network-message that registers a
/// liveliness token on the peer for `(keyexpr_mapping_id,
/// keyexpr_suffix)`. Mirrors zenoh-pico `_z_decl_token_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/declarations.c:123-126`
/// (a thin `_z_decl_commons_encode` wrapper with `has_extensions =
/// false`).
///
/// Liveliness tokens are unconditionally zero-tail: the zenoh-pico
/// encoder has no extension surface at all (compare to DeclQueryable's
/// `ExtQueryableInfo`), so this builder's emit shape is byte-stable
/// for every `(id, mapping, suffix)` input.
///
/// Wire shape (after the `N_MID_DECLARE` envelope header):
///
/// ```text
///   [DeclToken.header = _Z_DECL_TOKEN_MID (0x06)
///                        | (suffix.is_some() ? 0x20 : 0)
///                        | (codegen-derived: 0x40 from parent.M
///                          dispatch on the wireexpr import)]
///   VLE(token_id)
///   wireexpr.encode
/// ```
///
/// Same M-bit derivation contract as [`build_declare_subscriber`] /
/// [`build_declare_queryable`]: `<sce:variant-dispatch
/// flag="header.M"/>` on the wireexpr import in
/// `sources/codecs/decl_token.scxml`. The wireexpr arm is always
/// `WireexprLocal` here; `WireexprNonlocal` is reserved for future
/// Interest / Reply paths (R121j+).
///
/// `keyexpr_mapping_id` / `keyexpr_suffix` convention matches the
/// other DECLARE builders (literal / alias / compound).
pub fn build_declare_token(
    token_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Result<DeclareOwned, CodecError> {
    let suffix_len = keyexpr_suffix.map(|s| s.len() as u64);
    let suffix_string = keyexpr_suffix
        .map(crate::codec_owned::owned_string)
        .transpose()?;
    let n_flag = if keyexpr_suffix.is_some() {
        0x20u8
    } else {
        0x00u8
    };
    Ok(DeclareOwned {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohDeclToken(DeclTokenOwned {
            // MID 0x06 (_Z_DECL_TOKEN_MID per
            // vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/declarations.h:34)
            // + N gate; M is codegen-derived.
            header: wire_const::D_MID_TOKEN | n_flag,
            id: token_id,
            keyexpr: WireexprOwned {
                body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                    id: keyexpr_mapping_id,
                    suffix_len,
                    suffix: suffix_string,
                }),
            },
        }),
    })
}

// ─── R121i-d: WireexprNonlocal-arm DECLARE builders ──────────────────
//
// Companions to `build_declare_subscriber` / `build_declare_queryable`
// / `build_declare_token` for the M=0 case (the wire byte that
// `vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/network.h:63`
// dubs `_Z_FLAG_N_..._M`, derived at the wireexpr `<sce:import>` from
// the variant arm — Local → 0x40 OR, Nonlocal → no OR).
//
// Encoder-perspective locality (sources/codecs/wireexpr.scxml docblock
// + zenoh-pico `_z_wireexpr_is_local` at core.h:182):
//
//   M = 1 (Local arm)    sender's wireexpr was rooted in the sender's
//                        own mapping table — i.e. wz declared the
//                        keyexpr's mapping_id itself.
//   M = 0 (Nonlocal arm) sender's wireexpr was rooted in the *peer's*
//                        mapping table — i.e. wz is referring to a
//                        mapping_id that was DeclKexpr'd by the peer
//                        and registered into wz's peer-keyexpr table.
//
// Use case (the gap these builders close — without them wz could not
// emit DECLARE traffic that references peer-declared mappings, which
// is the cross-validation surface that AP MVP inbound parsing
// (R121j-5+) will trigger). Pre-R121i-d, the four DECLARE builders
// hard-coded the WireexprLocal arm, so a wz acceptor that received a
// peer's DeclKexpr could not in turn DeclSubscriber against that
// peer's id without the codegen-derived M bit silently emitting M=1
// (wrong direction — would tell the peer "I own this mapping" when
// in fact the peer owns it).
//
// `build_declare_kexpr` (the mapping-population variant) deliberately
// has *no* `_nonlocal` companion: DeclKexpr's purpose is the sender
// installing a (id, literal) pair *into its own* mapping table; the
// inner wireexpr is the literal itself (id=0 + suffix sentinel), and
// encoder-perspective locality is by definition Local. A
// `build_declare_kexpr_nonlocal` would mean "I am declaring a mapping
// owned by you" — semantically void; zenoh-pico has no such encoder
// path and the peer would reject it (declarations.c:52 sets M=1 via
// the unconditional `_z_wireexpr_is_local(LOCAL)=true` of the
// freshly-built `_z_wireexpr_t`).
//
// `id == 0` rejection: in the Nonlocal arm, mapping_id 0 is also
// nonsense — zenoh-pico's `_Z_KEYEXPR_MAPPING_LOCAL` sentinel is
// `(uintptr_t)0` (core.h:151), so a remote-mapped id=0 would refer
// to "the peer's literal-sentinel slot" which has no table entry.
// Each `_nonlocal` builder panics on id=0 with the same shape as
// `build_declare_kexpr_rejects_zero_mapping_id`.

/// R121i-d — build a `Declare(DeclSubscriber)` that registers a
/// subscriber on the peer for a keyexpr rooted in the *peer's*
/// mapping table (M=0 wire arm). Mirror of [`build_declare_subscriber`]
/// for the Nonlocal case; see the module-level docblock above for the
/// encoder-perspective locality semantics.
///
/// `keyexpr_mapping_id` is the peer-declared mapping id; `keyexpr_suffix`
/// is the optional tail concatenated to that mapping's literal at the
/// peer (`None` = pure alias, `Some(s)` = composite). Panics on
/// `keyexpr_mapping_id == 0` (literal-sentinel inversion is not
/// representable in the Nonlocal arm — use [`build_declare_subscriber`]
/// with `(0, Some(s))` for literal subscriptions).
///
/// Wire shape after the `N_MID_DECLARE` envelope (mirror of the Local
/// builder's wire shape with the M-bit derivation flipped):
///
/// ```text
///   [DeclSubscriber.header = _Z_DECL_SUBSCRIBER_MID (0x02)
///                            | (suffix.is_some() ? 0x20 : 0)
///                            | (codegen-derived: 0x00 from Nonlocal
///                              arm dispatch on the wireexpr import)]
///   VLE(subscriber_id)
///   wireexpr.encode  (id VLE + optional suffix_len VLE + suffix bytes)
/// ```
pub fn build_declare_subscriber_nonlocal(
    subscriber_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Result<DeclareOwned, CodecError> {
    assert!(
        keyexpr_mapping_id != 0,
        "build_declare_subscriber_nonlocal requires a non-zero mapping id; \
         id=0 is the literal-keyexpr sentinel, which is only representable \
         in the Local arm — call build_declare_subscriber instead",
    );
    let suffix_len = keyexpr_suffix.map(|s| s.len() as u64);
    let suffix_string = keyexpr_suffix
        .map(crate::codec_owned::owned_string)
        .transpose()?;
    let n_flag = if keyexpr_suffix.is_some() {
        0x20u8
    } else {
        0x00u8
    };
    Ok(DeclareOwned {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohDeclSubscriber(DeclSubscriberOwned {
            header: wire_const::D_MID_SUBSCRIBER | n_flag,
            id: subscriber_id,
            keyexpr: WireexprOwned {
                body: WireexprOwnedVariant::WireexprNonlocal(WireexprNonlocalOwned {
                    id: keyexpr_mapping_id,
                    suffix_len,
                    suffix: suffix_string,
                }),
            },
        }),
    })
}

/// R121i-d — build a `Declare(DeclQueryable)` for a keyexpr rooted in
/// the peer's mapping table (M=0 wire arm). Mirror of
/// [`build_declare_queryable`] for the Nonlocal case. The id=0
/// rejection rule from [`build_declare_subscriber_nonlocal`] applies
/// identically. Emit follows the `has_info_ext = false` shape
/// (default-state `_z_queryable_infos_t`); a future round adding
/// `complete` / `distance` will introduce a separate
/// `build_declare_queryable_nonlocal_with_info` helper.
pub fn build_declare_queryable_nonlocal(
    queryable_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Result<DeclareOwned, CodecError> {
    assert!(
        keyexpr_mapping_id != 0,
        "build_declare_queryable_nonlocal requires a non-zero mapping id; \
         id=0 is the literal-keyexpr sentinel — call build_declare_queryable instead",
    );
    let suffix_len = keyexpr_suffix.map(|s| s.len() as u64);
    let suffix_string = keyexpr_suffix
        .map(crate::codec_owned::owned_string)
        .transpose()?;
    let n_flag = if keyexpr_suffix.is_some() {
        0x20u8
    } else {
        0x00u8
    };
    Ok(DeclareOwned {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohDeclQueryable(DeclQueryableOwned {
            header: wire_const::D_MID_QUERYABLE | n_flag,
            id: queryable_id,
            keyexpr: WireexprOwned {
                body: WireexprOwnedVariant::WireexprNonlocal(WireexprNonlocalOwned {
                    id: keyexpr_mapping_id,
                    suffix_len,
                    suffix: suffix_string,
                }),
            },
            // R311ui: no QueryableInfo ext by default (backward-compat no-ext wire).
            extensions: None,
        }),
    })
}

/// R121i-d — build a `Declare(DeclToken)` for a keyexpr rooted in the
/// peer's mapping table (M=0 wire arm). Mirror of
/// [`build_declare_token`] for the Nonlocal case. Same id=0 rejection
/// rule as the other `_nonlocal` builders. DeclToken has no extension
/// surface at all, so the no-ext byte-stability contract is preserved.
pub fn build_declare_token_nonlocal(
    token_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Result<DeclareOwned, CodecError> {
    assert!(
        keyexpr_mapping_id != 0,
        "build_declare_token_nonlocal requires a non-zero mapping id; \
         id=0 is the literal-keyexpr sentinel — call build_declare_token instead",
    );
    let suffix_len = keyexpr_suffix.map(|s| s.len() as u64);
    let suffix_string = keyexpr_suffix
        .map(crate::codec_owned::owned_string)
        .transpose()?;
    let n_flag = if keyexpr_suffix.is_some() {
        0x20u8
    } else {
        0x00u8
    };
    Ok(DeclareOwned {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohDeclToken(DeclTokenOwned {
            header: wire_const::D_MID_TOKEN | n_flag,
            id: token_id,
            keyexpr: WireexprOwned {
                body: WireexprOwnedVariant::WireexprNonlocal(WireexprNonlocalOwned {
                    id: keyexpr_mapping_id,
                    suffix_len,
                    suffix: suffix_string,
                }),
            },
        }),
    })
}

/// R121i-c — build a `Declare(UndeclKexpr)` network-message that
/// retracts a previously declared keyexpr-mapping (id) on the peer.
/// Mirrors zenoh-pico `_z_undecl_kexpr_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/declarations.c:86-89`.
///
/// Wire shape (after the `N_MID_DECLARE` envelope header):
///
/// ```text
///   [UndeclKexpr.header = _Z_UNDECL_KEXPR_MID (0x01)]
///   VLE(mapping_id)
/// ```
///
/// UndeclKexpr has no wireexpr body and no Z-ext surface (unlike the
/// other three Undecl_* variants below): the retraction is purely
/// id-based because the peer already has the (id -> keyexpr) entry
/// from a prior `Declare(DeclKexpr)`. The Z bit is bit-7 of the
/// header and is left clear by every conformant zenoh-pico
/// emit — wz mirrors that contract.
pub fn build_undeclare_kexpr(mapping_id: u64) -> DeclareOwned {
    DeclareOwned {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohUndeclKexpr(UndeclKexpr {
            header: wire_const::D_MID_UNDECL_KEXPR,
            id: mapping_id,
        }),
    }
}

/// R121i-c — build a `Declare(UndeclSubscriber)` network-message that
/// retracts a previously declared subscription (id) on the peer.
/// Mirrors zenoh-pico `_z_undecl_subscriber_encode` /
/// `_z_undecl_encode(has_keyexpr_ext = false)` at
/// `vendor/zenoh-pico/src/protocol/codec/declarations.c:90-103`.
///
/// This builds the NO-EXT (id-only) retraction shape — peers route an id-only
/// undeclare by id alone. The keyexpr-carrying SOURCED form (the SCXML DOES model
/// the optional `_z_decl_ext_keyexpr_encode` tail; the ext chain now exists) is the
/// separate [`build_undeclare_subscriber_with_keyexpr`] below; this id-only contract
/// stays byte-stable.
///
/// Wire shape:
///
/// ```text
///   [UndeclSubscriber.header = _Z_UNDECL_SUBSCRIBER_MID (0x03)]
///   VLE(subscriber_id)
/// ```
pub fn build_undeclare_subscriber(subscriber_id: u64) -> DeclareOwned {
    DeclareOwned {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohUndeclSubscriber(UndeclSubscriberOwned {
            header: wire_const::D_MID_UNDECL_SUBSCRIBER,
            id: subscriber_id,
            // Z=0 id-only retraction: no ext_keyexpr. The keyexpr-carrying
            // sourced form is build_undeclare_subscriber_with_keyexpr (below).
            extensions: None,
        }),
    }
}

/// c3c-3 debt A1 — build a SOURCED `Declare(UndeclareSubscriber)` that retracts
/// a subscription identified by its LITERAL keyexpr. The linkstate-peer twin of
/// the sourced `DeclareSubscriber` (`build_declare_subscriber(0, 0, Some(ke))`):
/// zenoh retracts a sourced subscription by keyexpr, not id (`id == 0`,
/// "Sourced subscriptions do not use ids" — zenoh
/// `send_forget_sourced_subscription_to_net_children`), carrying the keyexpr in
/// the `ext_keyexpr` extension (`UndeclareSubscriber { id, ext_wire_expr }`).
/// The `id` is 0 and the inner declaration header sets `Z` (bit 7) to flag the
/// ext chain; the keyexpr ext is built by the
/// [`declare_ext_keyexpr`](crate::declare_ext_keyexpr) SSOT. Fallible only by
/// that SSOT's profile-generic signature (the `alloc` owned carrier is
/// unbounded, so a literal keyexpr is never length-rejected).
pub fn build_undeclare_subscriber_with_keyexpr(keyexpr: &str) -> Result<DeclareOwned, CodecError> {
    let ext = crate::declare_ext_keyexpr::build_ext_keyexpr(keyexpr)?;
    Ok(DeclareOwned {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohUndeclSubscriber(UndeclSubscriberOwned {
            // Z (bit 7): the inner declaration carries an extension chain.
            header: wire_const::D_MID_UNDECL_SUBSCRIBER | 0x80,
            id: 0, // sourced subscriptions use no id; the keyexpr is the identity
            extensions: Some(alloc::vec![ext]),
        }),
    })
}

/// R121i-c — build a `Declare(UndeclQueryable)` network-message that
/// retracts a previously declared queryable (id) on the peer. Same
/// no-ext shape contract as [`build_undeclare_subscriber`]; mirrors
/// zenoh-pico `_z_undecl_queryable_encode` /
/// `_z_undecl_encode(has_keyexpr_ext = false)` at
/// `vendor/zenoh-pico/src/protocol/codec/declarations.c:120-122`.
///
/// Wire shape:
///
/// ```text
///   [UndeclQueryable.header = _Z_UNDECL_QUERYABLE_MID (0x05)]
///   VLE(queryable_id)
/// ```
pub fn build_undeclare_queryable(queryable_id: u64) -> DeclareOwned {
    DeclareOwned {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohUndeclQueryable(UndeclQueryableOwned {
            header: wire_const::D_MID_UNDECL_QUERYABLE,
            id: queryable_id,
            // Z=0 id-only retraction: no ext_keyexpr. The keyexpr-carrying
            // sourced form is build_undeclare_queryable_with_keyexpr (below).
            extensions: None,
        }),
    }
}

/// Build a SOURCED `Declare(UndeclareQueryable)` that retracts a queryable
/// identified by its LITERAL keyexpr — the query-plane twin of
/// [`build_undeclare_subscriber_with_keyexpr`]. zenoh retracts a sourced
/// queryable by keyexpr, not id (`id == 0`), carrying the keyexpr in the
/// `ext_wire_expr` extension (zenoh `UndeclareQueryable { id, ext_wire_expr }`,
/// `commons/zenoh-protocol/src/network/declare.rs:520-523`). The `id` is 0 and
/// the inner declaration header sets `Z` (bit 7) to flag the ext chain; the
/// keyexpr ext is built by the
/// [`declare_ext_keyexpr`](crate::declare_ext_keyexpr) SSOT (identical wire to
/// the subscriber retraction, only the inner MID differs — 0x05 vs 0x03).
/// Fallible only by that SSOT's profile-generic signature (the `alloc` owned
/// carrier is unbounded, so a literal keyexpr is never length-rejected).
pub fn build_undeclare_queryable_with_keyexpr(keyexpr: &str) -> Result<DeclareOwned, CodecError> {
    let ext = crate::declare_ext_keyexpr::build_ext_keyexpr(keyexpr)?;
    Ok(DeclareOwned {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohUndeclQueryable(UndeclQueryableOwned {
            // Z (bit 7): the inner declaration carries an extension chain.
            header: wire_const::D_MID_UNDECL_QUERYABLE | 0x80,
            id: 0, // sourced queryables use no id; the keyexpr is the identity
            extensions: Some(alloc::vec![ext]),
        }),
    })
}

/// R121i-c — build a `Declare(UndeclToken)` network-message that
/// retracts a previously declared liveliness token (id) on the peer.
/// Same no-ext shape contract as [`build_undeclare_subscriber`];
/// mirrors zenoh-pico `_z_undecl_token_encode` /
/// `_z_undecl_encode(has_keyexpr_ext = false)` at
/// `vendor/zenoh-pico/src/protocol/codec/declarations.c:128-130`.
///
/// Wire shape:
///
/// ```text
///   [UndeclToken.header = _Z_UNDECL_TOKEN_MID (0x07)]
///   VLE(token_id)
/// ```
pub fn build_undeclare_token(token_id: u64) -> DeclareOwned {
    DeclareOwned {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohUndeclToken(UndeclTokenOwned {
            header: wire_const::D_MID_UNDECL_TOKEN,
            id: token_id,
            // Z=0 id-only retraction: no ext_keyexpr. The keyexpr-carrying
            // sourced form is build_undeclare_token_with_keyexpr (below).
            extensions: None,
        }),
    }
}

/// Build a SOURCED `Declare(UndeclareToken)` that retracts a liveliness token
/// identified by its LITERAL keyexpr — the token twin of
/// [`build_undeclare_subscriber_with_keyexpr`] /
/// [`build_undeclare_queryable_with_keyexpr`]. zenoh retracts a sourced token by
/// keyexpr, not id (`id == 0`), carrying the keyexpr in the `ext_wire_expr`
/// extension (zenoh `UndeclareToken { id, ext_wire_expr }`,
/// `hat/router/token.rs:930-933`). The `id` is 0 and the inner declaration
/// header sets `Z` (bit 7) to flag the ext chain; the keyexpr ext is built by the
/// [`declare_ext_keyexpr`](crate::declare_ext_keyexpr) SSOT (identical wire to the
/// subscriber/queryable retraction, only the inner MID differs — 0x07). Fallible
/// only by that SSOT's profile-generic signature (the `alloc` owned carrier is
/// unbounded, so a literal keyexpr is never length-rejected).
pub fn build_undeclare_token_with_keyexpr(keyexpr: &str) -> Result<DeclareOwned, CodecError> {
    let ext = crate::declare_ext_keyexpr::build_ext_keyexpr(keyexpr)?;
    Ok(DeclareOwned {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohUndeclToken(UndeclTokenOwned {
            // Z (bit 7): the inner declaration carries an extension chain.
            header: wire_const::D_MID_UNDECL_TOKEN | 0x80,
            id: 0, // sourced tokens use no id; the keyexpr is the identity
            extensions: Some(alloc::vec![ext]),
        }),
    })
}

/// R121i-c — build a `Declare(DeclFinal)` marker that terminates a
/// declaration sequence on the wire. Mirrors zenoh-pico
/// `_z_decl_final_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/declarations.c:131-135`:
/// a single-byte `0x1A` marker with no body, no id, no ext.
///
/// DeclFinal is used by zenoh-pico as the sentinel that signals the
/// end of an Interest-driven declaration batch (router → peer
/// replay). For the unsolicited DECLARE outbound path the wz AP MVP
/// uses (R121g+), DeclFinal is not strictly required, but the helper
/// is provided so the future Interest/Reply path (R121j+) has the
/// terminator builder ready when it needs to close a multi-DECLARE
/// reply sequence.
///
/// Wire shape: `[N_MID_DECLARE, 0x1A]` — exactly two bytes.
pub fn build_declare_final() -> DeclareOwned {
    DeclareOwned {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohDeclFinal(DeclFinal {
            header: wire_const::D_MID_FINAL,
        }),
    }
}

/// Stamp the interest-response coupling onto a built `DeclareOwned`: the envelope
/// `I` flag ([`wire_const::FLAG_N_DECLARE_I`]) AND `interest_id = Some(id)` — BOTH,
/// always together. The encoder emits the id VLE iff `interest_id.is_some()` and
/// the decoder reads it iff the header `I` bit is set, so a builder that set one
/// without the other would short-read the frame on the peer. Keeping the pair in
/// one place makes that desync unrepresentable — a future reply builder cannot set
/// half of it (the `unrepresentable > test` principle). The SSOT for the three
/// `build_declare_*_reply` builders below.
fn stamp_interest_reply(declare: &mut DeclareOwned, interest_id: u64) {
    declare.header |= wire_const::FLAG_N_DECLARE_I;
    declare.interest_id = Some(interest_id);
}

/// R311y141 — the interest-response `Declare(DeclSubscriber)` reply: a
/// `DeclareSubscriber` stamped with the soliciting `interest_id` — the CURRENT
/// dump a router sends back per matching remote subscription
/// (`hat/router/pubsub.rs::declare_sub_interest`). Two wire couplings a plain
/// [`build_declare_subscriber`] does NOT carry, and BOTH are required: the
/// envelope `I` flag ([`wire_const::FLAG_N_DECLARE_I`]) AND `interest_id =
/// Some(id)`. The encoder emits the id VLE iff `interest_id.is_some()` and the
/// decoder reads it iff the header `I` bit is set, so setting one without the
/// other short-reads the frame on the peer.
///
/// The reply keyexpr is the literal `keyexpr` (mapping id 0 + full suffix). For
/// an AGGREGATE interest the caller MUST pass the interest's OWN keyexpr, not a
/// matched subscription's: zenoh-pico associates an aggregate interest's replies
/// by `_z_keyexpr_equals` (`session/interest.c`), not intersect, so a
/// concrete-subscription keyexpr would silently fail to match. The subscriber
/// `id` is 0 (a current-dump sub carries no id — zenoh `make_sub_id` = 0 for
/// non-future).
pub fn build_declare_subscriber_reply(
    interest_id: u64,
    keyexpr: &str,
) -> Result<DeclareOwned, CodecError> {
    let mut declare = build_declare_subscriber(0, 0, Some(keyexpr))?;
    stamp_interest_reply(&mut declare, interest_id);
    Ok(declare)
}

/// R311y146 — the interest-response `Declare(DeclSubscriber)` reply of a FUTURE
/// (C+F) interest, carrying a NON-ZERO subscriber id. The plain
/// [`build_declare_subscriber_reply`] hardcodes id 0 (zenoh `make_sub_id` = 0 for a
/// non-future interest); a FUTURE interest instead allocates a per-`(face, reply
/// keyexpr)` id (zenoh `make_sub_id`'s `mode.future()` branch inserts into
/// `face_hat.local_subs`), so the SAME id can be REUSED on a redundant re-declare
/// (pico dedups a `(decl_id, peer)` target, `net/filtering.c`) and later carried on
/// the unsolicited FUTURE push of the same keyexpr. Same `I`-flag + `interest_id`
/// coupling and same aggregate-keyexpr contract as [`build_declare_subscriber_reply`].
pub fn build_declare_subscriber_reply_with_id(
    interest_id: u64,
    subscriber_id: u64,
    keyexpr: &str,
) -> Result<DeclareOwned, CodecError> {
    let mut declare = build_declare_subscriber(subscriber_id, 0, Some(keyexpr))?;
    stamp_interest_reply(&mut declare, interest_id);
    Ok(declare)
}

/// R311y174 — the interest-response `Declare(DeclToken)` reply: a `DeclareToken`
/// stamped with the soliciting `interest_id` — the CURRENT dump a router sends back
/// per matching held liveliness token (zenoh `declare_token_interest`). The token
/// twin of [`build_declare_subscriber_reply`], routed through the SAME
/// [`stamp_interest_reply`] I-flag + interest_id SSOT. Kept in this (ungated)
/// `declare_build` module — NOT `declare::local_token::build_token_reply`, which is
/// gated behind the `liveliness-token` feature — so the router `routing-token-tables`
/// plane pulls no liveliness-token dependency. The token `id` is 0 (a current-dump
/// token carries no id — zenoh `make_token_id` = 0 for a non-future interest).
pub fn build_declare_token_reply(
    interest_id: u64,
    keyexpr: &str,
) -> Result<DeclareOwned, CodecError> {
    let mut declare = build_declare_token(0, 0, Some(keyexpr))?;
    stamp_interest_reply(&mut declare, interest_id);
    Ok(declare)
}

/// R311y174 — the interest-response `Declare(DeclToken)` reply of a FUTURE (C+F)
/// interest, carrying a NON-ZERO token id (zenoh `make_token_id`'s `mode.future()`
/// branch) so the id is REUSED on the later unsolicited FUTURE push of the same
/// keyexpr. Same `I`-flag + `interest_id` coupling as [`build_declare_token_reply`].
pub fn build_declare_token_reply_with_id(
    interest_id: u64,
    token_id: u64,
    keyexpr: &str,
) -> Result<DeclareOwned, CodecError> {
    let mut declare = build_declare_token(token_id, 0, Some(keyexpr))?;
    stamp_interest_reply(&mut declare, interest_id);
    Ok(declare)
}

/// R311y141 — the interest-response `Declare(DeclQueryable)` reply: the
/// query-plane twin of [`build_declare_subscriber_reply`]. Additionally folds
/// the matched queryables' [`QueryableInfo`] onto the body ext chain (via
/// [`set_declare_queryable_info`]): a `Z_QUERY_TARGET_ALL_COMPLETE` querier's
/// write-filter deactivates ONLY on a reply carrying `complete = true`
/// (zenoh-pico `net/filtering.c`), so an aggregate reply must carry the MERGED
/// completeness rather than dropping it to the DEFAULT `{ complete: false }`.
/// Same `I`-flag + `interest_id` coupling and same aggregate-keyexpr contract as
/// the subscriber reply.
pub fn build_declare_queryable_reply(
    interest_id: u64,
    keyexpr: &str,
    info: crate::queryable_info::QueryableInfo,
) -> Result<DeclareOwned, CodecError> {
    let mut declare = build_declare_queryable(0, 0, Some(keyexpr))?;
    set_declare_queryable_info(&mut declare, info);
    stamp_interest_reply(&mut declare, interest_id);
    Ok(declare)
}

/// R311y150 — the interest-response `Declare(DeclQueryable)` reply of a FUTURE
/// (C+F) interest, carrying a NON-ZERO queryable id — the query-plane twin of
/// [`build_declare_subscriber_reply_with_id`]. The plain
/// [`build_declare_queryable_reply`] hardcodes id 0; a FUTURE interest instead
/// allocates a per-`(face, reply keyexpr)` id so the SAME id can be REUSED on the
/// later value-aware FUTURE push of the same keyexpr (a completeness flip
/// `false -> true` re-declares the SAME `(decl_id, peer)` target pico keys its
/// write-filter on, `net/filtering.c:202`). Same `I`-flag + `interest_id` coupling
/// and same folded-[`QueryableInfo`] contract as [`build_declare_queryable_reply`].
pub fn build_declare_queryable_reply_with_id(
    interest_id: u64,
    queryable_id: u64,
    keyexpr: &str,
    info: crate::queryable_info::QueryableInfo,
) -> Result<DeclareOwned, CodecError> {
    let mut declare = build_declare_queryable(queryable_id, 0, Some(keyexpr))?;
    set_declare_queryable_info(&mut declare, info);
    stamp_interest_reply(&mut declare, interest_id);
    Ok(declare)
}

/// R311y150 — the UNSOLICITED FUTURE `Declare(DeclQueryable)` push: a
/// `DeclareQueryable` carrying a NON-ZERO queryable id + the folded
/// [`QueryableInfo`], with `interest_id: None` and NO `I` flag (an unsolicited
/// declare, NOT an interest reply — the query-plane twin of the subscriber future
/// push's plain `build_declare_subscriber(id, 0, Some(ke))`). Distinct from
/// [`build_declare_queryable_with_info`](crate::declare_build) callers that force
/// id 0: the push MUST carry the interned non-zero id so pico updates the existing
/// `(decl_id, peer)` write-filter target in place on a value-aware re-push.
pub fn build_declare_queryable_with_id_info(
    queryable_id: u64,
    keyexpr: &str,
    info: crate::queryable_info::QueryableInfo,
) -> Result<DeclareOwned, CodecError> {
    let mut declare = build_declare_queryable(queryable_id, 0, Some(keyexpr))?;
    set_declare_queryable_info(&mut declare, info);
    Ok(declare)
}

/// R311y141 — the interest-response terminator: a `Declare(DeclFinal)` stamped
/// with `interest_id`, the single `DeclFinal` a router sends after the CURRENT
/// dump to close the interest (`hat/router/interests.rs`). The `interest_id` is
/// MANDATORY here (unlike the unsolicited [`build_declare_final`]): zenoh-pico
/// HARD-ERRORS on a `DeclFinal` with no interest_id
/// (`_Z_ERR_MESSAGE_ZENOH_DECLARATION_UNKNOWN`, `transport/unicast/rx.c`), and
/// that error propagates up the frame reader. Both the `I` flag and the id field
/// are set (see [`build_declare_subscriber_reply`] for the coupling).
pub fn build_declare_final_reply(interest_id: u64) -> DeclareOwned {
    let mut declare = build_declare_final();
    stamp_interest_reply(&mut declare, interest_id);
    declare
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use wz_codecs_test_support::TestWire;

    /// R121g — `build_declare_kexpr` wraps a `DeclKexpr` registering
    /// `mapping_id -> suffix` in a `Declare` envelope with the
    /// network MID header and no interest_id / no extensions.
    /// R121h-pre — under the SCE e10619d3 B5-ν ownership invert, the
    /// inner DeclKexpr carries the literal suffix via the
    /// `WireexprLocal` arm (semantically correct: the declared
    /// keyexpr lives in the local mapping table); DeclKexpr's
    /// `<sce:import>` site omits `<sce:variant-dispatch>` so no
    /// parent derive bit is emitted at bit 6.
    #[test]
    fn build_declare_kexpr_wraps_decl_kexpr_with_literal_suffix() {
        let declare = build_declare_kexpr(7, "demo/test").unwrap();
        assert_eq!(
            declare.header,
            wire_const::N_MID_DECLARE,
            "Declare header must carry N_MID_DECLARE with no flag bits set",
        );
        assert!(
            declare.interest_id.is_none(),
            "MVP DECLARE has no interest_id"
        );
        assert!(
            declare.extensions.is_none(),
            "MVP DECLARE has no extensions"
        );
        match &declare.body {
            DeclareOwnedVariant::CodecZenohDeclKexpr(dk) => {
                assert_eq!(dk.id, 7, "DeclKexpr.id must equal mapping_id argument");
                assert_eq!(
                    dk.header, 0x20,
                    "DeclKexpr.header must carry _Z_DECL_KEXPR_FLAG_N (0x20)"
                );
                match &dk.keyexpr.body {
                    WireexprOwnedVariant::WireexprLocal(w) => {
                        assert_eq!(
                            w.id, 0,
                            "inner Wireexpr.id is the literal-keyexpr sentinel 0"
                        );
                        assert_eq!(w.suffix.as_deref(), Some("demo/test"));
                        assert_eq!(w.suffix_len, Some(9));
                    }
                    _ => panic!(
                        "DeclKexpr.keyexpr must use the WireexprLocal arm under \
                         the SCE e10619d3 B5-ν invert (the parent's <sce:import> \
                         site omits <sce:variant-dispatch>, so no parent derive \
                         bit is emitted regardless of which arm is selected)"
                    ),
                }
            }
            _ => panic!("build_declare_kexpr must produce a CodecZenohDeclKexpr variant"),
        }
    }

    /// R121g — Wire-byte regression gate: the bytes emitted by
    /// `build_declare_kexpr(7, "demo/test").wire()` must equal
    /// zenoh-pico's `_z_decl_kexpr_encode` output for the same
    /// arguments. Authored as a byte-literal compare so a future
    /// codegen drift on either DeclKexpr.header derivation or
    /// WireexprNonlocal encoding shape surfaces immediately.
    ///
    /// Expected wire bytes from zenoh-pico
    /// (`vendor/zenoh-pico/src/protocol/codec/declarations.c:52-63`):
    ///   - DeclKexpr.header = `_Z_DECL_KEXPR_MID(0) | _Z_DECL_KEXPR_FLAG_N(0x20)` = `0x20`
    ///   - VLE(id=7) = `0x07`
    ///   - wireexpr.id VLE(0) = `0x00`
    ///   - wireexpr.suffix string = VLE(9) + 9 bytes of "demo/test"
    #[test]
    fn build_declare_kexpr_emits_zenoh_pico_compatible_wire_bytes() {
        let declare = build_declare_kexpr(7, "demo/test").unwrap();
        let outer = declare.wire();
        // Skip the outer Declare envelope header (0x1E) — that
        // single byte is the wz Declare codec's own emit; the rest
        // is the DeclKexpr inner body. The byte-compare gate sits
        // on the inner body so a regression in either the inner
        // header derivation OR the wireexpr body emit fires.
        let mut expected = vec![
            wire_const::N_MID_DECLARE, // outer Declare 0x1E
            0x20,                      // DeclKexpr.header = _Z_DECL_KEXPR_FLAG_N
            0x07,                      // VLE(mapping_id=7)
            0x00,                      // wireexpr.id VLE(0)
            0x09,                      // suffix_len VLE(9)
        ];
        expected.extend_from_slice(b"demo/test");
        assert_eq!(
            outer, expected,
            "build_declare_kexpr wire bytes must match zenoh-pico's \
             _z_decl_kexpr_encode output byte-for-byte"
        );
    }

    /// R121g — `build_declare_kexpr` rejects `mapping_id == 0` to
    /// keep the literal-keyexpr sentinel out of the DECLARE table.
    #[test]
    #[should_panic(expected = "build_declare_kexpr requires a non-zero mapping id")]
    fn build_declare_kexpr_rejects_zero_mapping_id() {
        let _ = build_declare_kexpr(0, "demo/test");
    }

    /// R121i — `build_declare_subscriber` produces a Declare envelope
    /// carrying a `DeclSubscriber` inner body whose author-supplied
    /// header carries the MID + optional N (suffix gate) but NOT the
    /// M flag (codegen-derived from parent.M dispatch). Three shapes
    /// exercise the three semantic cases: pure-alias (id=N + None),
    /// composite (id=N + Some), and literal (id=0 + Some).
    #[test]
    fn build_declare_subscriber_wraps_decl_subscriber_in_declare_envelope() {
        // Case 1 — pure alias to a peer-declared mapping (suffix=None).
        let alias = build_declare_subscriber(5, 7, None).unwrap();
        assert_eq!(
            alias.header,
            wire_const::N_MID_DECLARE,
            "Declare envelope header must carry N_MID_DECLARE",
        );
        match &alias.body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => {
                assert_eq!(d.id, 5, "DeclSubscriber.id must equal subscriber_id");
                assert_eq!(
                    d.header, 0x02,
                    "header carries MID only; N clear (no suffix) and M is codegen-derived"
                );
                match &d.keyexpr.body {
                    WireexprOwnedVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 7, "Wireexpr.id must equal keyexpr_mapping_id");
                        assert!(w.suffix.is_none(), "alias case has no suffix");
                        assert!(w.suffix_len.is_none());
                    }
                    _ => panic!("DeclSubscriber.keyexpr must use WireexprLocal arm"),
                }
            }
            _ => panic!("build_declare_subscriber must produce CodecZenohDeclSubscriber"),
        }

        // Case 2 — composite: alias N + tail suffix.
        let composite = build_declare_subscriber(5, 7, Some("tail")).unwrap();
        match &composite.body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => {
                assert_eq!(
                    d.header, 0x22,
                    "header MID 0x02 | N(0x20) when suffix present"
                );
                match &d.keyexpr.body {
                    WireexprOwnedVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 7);
                        assert_eq!(w.suffix.as_deref(), Some("tail"));
                        assert_eq!(w.suffix_len, Some(4));
                    }
                    _ => panic!("composite must use WireexprLocal arm"),
                }
            }
            _ => panic!(),
        }

        // Case 3 — literal: id=0 sentinel + suffix carries the keyexpr.
        let literal = build_declare_subscriber(5, 0, Some("demo/test")).unwrap();
        match &literal.body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => {
                assert_eq!(d.header, 0x22, "literal case still sets N (suffix present)");
                match &d.keyexpr.body {
                    WireexprOwnedVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 0, "literal sentinel id=0");
                        assert_eq!(w.suffix.as_deref(), Some("demo/test"));
                    }
                    _ => panic!("literal must use WireexprLocal arm"),
                }
            }
            _ => panic!(),
        }
    }

    /// R121i — Wire-byte regression gate: the bytes emitted by
    /// `build_declare_subscriber(5, 7, None).wire()` must equal
    /// zenoh-pico's `_z_decl_subscriber_encode` /
    /// `_z_decl_commons_encode` output for the same arguments
    /// (vendor/zenoh-pico/src/protocol/codec/declarations.c:65-84
    ///   + the `_z_wireexpr_encode` invocation at declarations.c:84).
    ///
    /// Three vectors lock the three semantic cases (alias /
    /// composite / literal) so a future codegen regression on either
    /// header derivation, wireexpr arm choice, or the M-bit emit
    /// path fires immediately.
    #[test]
    fn build_declare_subscriber_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — pure alias (subscriber_id=5, mapping_id=7, no
        // suffix). Wire shape (per declarations.c):
        //   outer Declare header 0x1E (N_MID_DECLARE)
        //   DeclSubscriber.header = MID(0x02) | M(0x40) = 0x42
        //                            (M=1 codegen-derived from
        //                             Local arm via the
        //                             <sce:variant-dispatch
        //                             flag="header.M"/> import-site
        //                             declaration in
        //                             decl_subscriber.scxml)
        //   VLE(subscriber_id=5)     = 0x05
        //   wireexpr Local id=7 only = 0x07
        let alias = build_declare_subscriber(5, 7, None).unwrap();
        let alias_wire = alias.wire();
        let alias_expected = vec![
            wire_const::N_MID_DECLARE, // 0x1E
            0x42,                      // MID(0x02) | M(0x40)
            0x05,                      // VLE(subscriber_id=5)
            0x07,                      // wireexpr.id VLE(7)
        ];
        assert_eq!(
            alias_wire, alias_expected,
            "alias-case wire bytes must match zenoh-pico reference"
        );

        // Case 2 — composite (id=7 + tail "abc"):
        //   DeclSubscriber.header = MID | N | M = 0x62
        //   VLE(5) = 0x05
        //   wireexpr.id VLE(7) = 0x07
        //   suffix_len VLE(3) = 0x03
        //   suffix bytes = "abc"
        let composite = build_declare_subscriber(5, 7, Some("abc")).unwrap();
        let composite_wire = composite.wire();
        let mut composite_expected = vec![
            wire_const::N_MID_DECLARE,
            0x62, // MID | N | M
            0x05,
            0x07,
            0x03,
        ];
        composite_expected.extend_from_slice(b"abc");
        assert_eq!(
            composite_wire, composite_expected,
            "composite-case wire bytes must match zenoh-pico reference"
        );

        // Case 3 — literal (id=0 + suffix "demo/test"):
        //   DeclSubscriber.header = MID | N | M = 0x62
        //   VLE(5) = 0x05
        //   wireexpr.id VLE(0) = 0x00
        //   suffix_len VLE(9) = 0x09
        //   suffix bytes = "demo/test"
        let literal = build_declare_subscriber(5, 0, Some("demo/test")).unwrap();
        let literal_wire = literal.wire();
        let mut literal_expected = vec![wire_const::N_MID_DECLARE, 0x62, 0x05, 0x00, 0x09];
        literal_expected.extend_from_slice(b"demo/test");
        assert_eq!(
            literal_wire, literal_expected,
            "literal-case wire bytes must match zenoh-pico reference"
        );
    }

    /// R121i-b — `build_declare_queryable` produces a Declare envelope
    /// carrying a `DeclQueryable` inner body. Mirror of the
    /// DeclSubscriber structural test, with MID swap 0x02 → 0x04 and
    /// the `WireexprLocal` arm preserved (M-bit codegen-derivation
    /// path identical).
    #[test]
    fn build_declare_queryable_wraps_decl_queryable_in_declare_envelope() {
        // Case 1 — pure alias to a peer-declared mapping (suffix=None).
        let alias = build_declare_queryable(9, 7, None).unwrap();
        assert_eq!(
            alias.header,
            wire_const::N_MID_DECLARE,
            "Declare envelope header must carry N_MID_DECLARE",
        );
        match &alias.body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => {
                assert_eq!(d.id, 9, "DeclQueryable.id must equal queryable_id");
                assert_eq!(
                    d.header, 0x04,
                    "header carries MID 0x04 only; N clear (no suffix), M codegen-derived"
                );
                match &d.keyexpr.body {
                    WireexprOwnedVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 7, "Wireexpr.id must equal keyexpr_mapping_id");
                        assert!(w.suffix.is_none(), "alias case has no suffix");
                        assert!(w.suffix_len.is_none());
                    }
                    _ => panic!("DeclQueryable.keyexpr must use WireexprLocal arm"),
                }
            }
            _ => panic!("build_declare_queryable must produce CodecZenohDeclQueryable"),
        }

        // Case 2 — composite: alias N + tail suffix.
        let composite = build_declare_queryable(9, 7, Some("tail")).unwrap();
        match &composite.body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => {
                assert_eq!(
                    d.header, 0x24,
                    "header MID 0x04 | N(0x20) when suffix present"
                );
                match &d.keyexpr.body {
                    WireexprOwnedVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 7);
                        assert_eq!(w.suffix.as_deref(), Some("tail"));
                        assert_eq!(w.suffix_len, Some(4));
                    }
                    _ => panic!("composite must use WireexprLocal arm"),
                }
            }
            _ => panic!(),
        }

        // Case 3 — literal: id=0 sentinel + suffix carries the keyexpr.
        let literal = build_declare_queryable(9, 0, Some("demo/test")).unwrap();
        match &literal.body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => {
                assert_eq!(d.header, 0x24, "literal case still sets N (suffix present)");
                match &d.keyexpr.body {
                    WireexprOwnedVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 0, "literal sentinel id=0");
                        assert_eq!(w.suffix.as_deref(), Some("demo/test"));
                    }
                    _ => panic!("literal must use WireexprLocal arm"),
                }
            }
            _ => panic!(),
        }
    }

    #[test]
    fn a_declare_queryable_carries_a_typed_queryable_info_across_the_wire() {
        // R311uj: the typed QueryableInfo producer + accessor over the R311ui
        // wire capacity, with zenoh's EXACT z64 packing (complete @ bit 0,
        // distance << 8). Build -> stamp info -> wire -> decode -> read it back.
        use crate::queryable_info::{read_queryable_info, QueryableInfo};
        use sce_forge_runtime::codec::SceCursor;
        use wz_codecs::declare::Declare;

        let info = QueryableInfo {
            complete: true,
            distance: 3,
        };
        let mut declare = build_declare_queryable(9, 0, Some("demo/q")).unwrap();
        assert!(
            set_declare_queryable_info(&mut declare, info),
            "a non-default QueryableInfo rides the body ext chain",
        );

        let bytes = declare.wire();
        let mut cursor = SceCursor::new(&bytes);
        let decoded = Declare::decode(&mut cursor)
            .and_then(|x| x.try_into_owned())
            .expect("decode declare");
        let DeclareOwnedVariant::CodecZenohDeclQueryable(d) = &decoded.body else {
            panic!("body must survive as a DeclQueryable");
        };
        assert_eq!(
            read_queryable_info(d.extensions.as_ref()),
            info,
            "the typed QueryableInfo survived the wire round-trip (zenoh-exact packing)",
        );

        // DEFAULT info leaves the body ext-free (Z clear) — omit-on-DEFAULT, the
        // byte-identical no-info shape.
        let mut plain = build_declare_queryable(9, 0, Some("demo/q")).unwrap();
        assert!(
            !set_declare_queryable_info(&mut plain, QueryableInfo::DEFAULT),
            "DEFAULT omits the ext",
        );
        let DeclareOwnedVariant::CodecZenohDeclQueryable(dp) = &plain.body else {
            panic!("expected a DeclQueryable body");
        };
        assert!(dp.extensions.is_none(), "DEFAULT carries no ext");
        assert_eq!(dp.header & 0x80, 0, "DEFAULT keeps the body Z bit clear");
    }

    /// R121i-b — Wire-byte regression gate: the bytes emitted by
    /// `build_declare_queryable(...).wire()` must equal zenoh-pico's
    /// `_z_decl_queryable_encode` output for the no-info-ext shape
    /// (vendor/zenoh-pico/src/protocol/codec/declarations.c:105-118
    ///   with `has_info_ext = false` short-circuit at line 109).
    ///
    /// MID differs from DeclSubscriber (0x02 → 0x04) but the rest of
    /// the wire (id VLE + wireexpr body + M-bit OR convention) is
    /// identical — these three vectors lock the same alias /
    /// composite / literal trio. The `has_info_ext = true` variant
    /// (future ExtQueryableInfo tail) is out of scope for this round.
    #[test]
    fn build_declare_queryable_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — pure alias (queryable_id=9, mapping_id=7, no
        // suffix). Wire shape:
        //   outer Declare header 0x1E (N_MID_DECLARE)
        //   DeclQueryable.header = MID(0x04) | M(0x40) = 0x44
        //   VLE(queryable_id=9)  = 0x09
        //   wireexpr Local id=7  = 0x07
        let alias = build_declare_queryable(9, 7, None).unwrap();
        let alias_wire = alias.wire();
        let alias_expected = vec![
            wire_const::N_MID_DECLARE, // 0x1E
            0x44,                      // MID(0x04) | M(0x40)
            0x09,                      // VLE(queryable_id=9)
            0x07,                      // wireexpr.id VLE(7)
        ];
        assert_eq!(
            alias_wire, alias_expected,
            "DeclQueryable alias-case wire bytes must match zenoh-pico reference"
        );

        // Case 2 — composite (id=7 + tail "abc"):
        //   DeclQueryable.header = MID | N | M = 0x64
        //   VLE(9) = 0x09
        //   wireexpr.id VLE(7) = 0x07
        //   suffix_len VLE(3) = 0x03
        //   suffix bytes = "abc"
        let composite = build_declare_queryable(9, 7, Some("abc")).unwrap();
        let composite_wire = composite.wire();
        let mut composite_expected = vec![
            wire_const::N_MID_DECLARE,
            0x64, // MID | N | M
            0x09,
            0x07,
            0x03,
        ];
        composite_expected.extend_from_slice(b"abc");
        assert_eq!(
            composite_wire, composite_expected,
            "DeclQueryable composite-case wire bytes must match zenoh-pico reference"
        );

        // Case 3 — literal (id=0 + suffix "demo/test"):
        //   DeclQueryable.header = MID | N | M = 0x64
        //   VLE(9) = 0x09
        //   wireexpr.id VLE(0) = 0x00
        //   suffix_len VLE(9) = 0x09
        //   suffix bytes = "demo/test"
        let literal = build_declare_queryable(9, 0, Some("demo/test")).unwrap();
        let literal_wire = literal.wire();
        let mut literal_expected = vec![wire_const::N_MID_DECLARE, 0x64, 0x09, 0x00, 0x09];
        literal_expected.extend_from_slice(b"demo/test");
        assert_eq!(
            literal_wire, literal_expected,
            "DeclQueryable literal-case wire bytes must match zenoh-pico reference"
        );
    }

    /// R121i-b — `build_declare_token` produces a Declare envelope
    /// carrying a `DeclToken` inner body. Mirror of the DeclSubscriber
    /// / DeclQueryable structural test, with MID swap to 0x06.
    #[test]
    fn build_declare_token_wraps_decl_token_in_declare_envelope() {
        // Case 1 — pure alias.
        let alias = build_declare_token(11, 7, None).unwrap();
        match &alias.body {
            DeclareOwnedVariant::CodecZenohDeclToken(d) => {
                assert_eq!(d.id, 11, "DeclToken.id must equal token_id");
                assert_eq!(
                    d.header, 0x06,
                    "header carries MID 0x06 only; N clear, M codegen-derived"
                );
                match &d.keyexpr.body {
                    WireexprOwnedVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 7);
                        assert!(w.suffix.is_none());
                    }
                    _ => panic!("DeclToken.keyexpr must use WireexprLocal arm"),
                }
            }
            _ => panic!("build_declare_token must produce CodecZenohDeclToken"),
        }

        // Case 2 — composite.
        let composite = build_declare_token(11, 7, Some("tail")).unwrap();
        match &composite.body {
            DeclareOwnedVariant::CodecZenohDeclToken(d) => {
                assert_eq!(d.header, 0x26, "header MID 0x06 | N(0x20)");
                match &d.keyexpr.body {
                    WireexprOwnedVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 7);
                        assert_eq!(w.suffix.as_deref(), Some("tail"));
                    }
                    _ => panic!(),
                }
            }
            _ => panic!(),
        }

        // Case 3 — literal.
        let literal = build_declare_token(11, 0, Some("demo/test")).unwrap();
        match &literal.body {
            DeclareOwnedVariant::CodecZenohDeclToken(d) => {
                assert_eq!(d.header, 0x26);
                match &d.keyexpr.body {
                    WireexprOwnedVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 0);
                        assert_eq!(w.suffix.as_deref(), Some("demo/test"));
                    }
                    _ => panic!(),
                }
            }
            _ => panic!(),
        }
    }

    /// R121i-b — Wire-byte regression gate: the bytes emitted by
    /// `build_declare_token(...).wire()` must equal zenoh-pico's
    /// `_z_decl_token_encode` output
    /// (vendor/zenoh-pico/src/protocol/codec/declarations.c:123-126).
    ///
    /// DeclToken's encode is a pure `_z_decl_commons_encode(has_ext =
    /// false)` wrapper — no extension surface at all. The three
    /// vectors lock the alias / composite / literal trio with MID
    /// 0x06.
    #[test]
    fn build_declare_token_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — pure alias (token_id=11, mapping_id=7, no suffix).
        let alias = build_declare_token(11, 7, None).unwrap();
        let alias_wire = alias.wire();
        let alias_expected = vec![
            wire_const::N_MID_DECLARE, // 0x1E
            0x46,                      // MID(0x06) | M(0x40)
            0x0B,                      // VLE(token_id=11)
            0x07,                      // wireexpr.id VLE(7)
        ];
        assert_eq!(
            alias_wire, alias_expected,
            "DeclToken alias-case wire bytes must match zenoh-pico reference"
        );

        // Case 2 — composite (id=7 + tail "abc").
        let composite = build_declare_token(11, 7, Some("abc")).unwrap();
        let composite_wire = composite.wire();
        let mut composite_expected = vec![
            wire_const::N_MID_DECLARE,
            0x66, // MID(0x06) | N | M
            0x0B,
            0x07,
            0x03,
        ];
        composite_expected.extend_from_slice(b"abc");
        assert_eq!(
            composite_wire, composite_expected,
            "DeclToken composite-case wire bytes must match zenoh-pico reference"
        );

        // Case 3 — literal (id=0 + suffix "demo/test").
        let literal = build_declare_token(11, 0, Some("demo/test")).unwrap();
        let literal_wire = literal.wire();
        let mut literal_expected = vec![wire_const::N_MID_DECLARE, 0x66, 0x0B, 0x00, 0x09];
        literal_expected.extend_from_slice(b"demo/test");
        assert_eq!(
            literal_wire, literal_expected,
            "DeclToken literal-case wire bytes must match zenoh-pico reference"
        );
    }

    /// R121i-d — Wire-byte regression gate for
    /// `build_declare_subscriber_nonlocal`. Mirror of the Local-arm
    /// byte-compare with the M-bit OR convention flipped: the
    /// codegen-derived `_derived_header` at the wireexpr import site
    /// is 0x00 for the Nonlocal arm (decl_subscriber.scxml +
    /// wireexpr.scxml `<sce:arm value="0x00" type="wireexpr_nonlocal"/>`),
    /// so the emitted DeclSubscriber.header carries MID + N only, no
    /// M bit. Three vectors lock the alias / composite / multi-byte
    /// VLE boundary cases (literal id=0 is rejected by the builder so
    /// is exercised in the `_rejects_zero_mapping_id` panic test
    /// below, not here).
    #[test]
    fn build_declare_subscriber_nonlocal_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — pure alias to peer's mapping 7 (no suffix).
        //   DeclSubscriber.header = MID(0x02) | M(0x00) = 0x02
        let alias = build_declare_subscriber_nonlocal(5, 7, None).unwrap();
        assert_eq!(
            alias.wire(),
            vec![
                wire_const::N_MID_DECLARE, // 0x1E outer
                0x02,                      // MID only, no N, no M
                0x05,                      // VLE(subscriber_id=5)
                0x07,                      // wireexpr.id VLE(7)
            ],
            "DeclSubscriber Nonlocal alias-case wire bytes must match \
             zenoh-pico reference (M bit clear)",
        );

        // Case 2 — composite: peer's mapping 7 + tail "abc".
        //   DeclSubscriber.header = MID | N | M(=0) = 0x22
        let composite = build_declare_subscriber_nonlocal(5, 7, Some("abc")).unwrap();
        let mut composite_expected = vec![
            wire_const::N_MID_DECLARE,
            0x22, // MID | N, no M
            0x05,
            0x07,
            0x03,
        ];
        composite_expected.extend_from_slice(b"abc");
        assert_eq!(
            composite.wire(),
            composite_expected,
            "DeclSubscriber Nonlocal composite-case wire bytes must \
             match zenoh-pico reference",
        );

        // Case 3 — multi-byte VLE boundary on the peer's mapping id
        // (id=200 crosses the 7-bit VLE boundary; first byte = 0xC8,
        // second byte = 0x01). Pure alias to lock the VLE writer
        // regression surface on the Nonlocal arm.
        let large = build_declare_subscriber_nonlocal(5, 200, None).unwrap();
        assert_eq!(
            large.wire(),
            vec![
                wire_const::N_MID_DECLARE,
                0x02,
                0x05,
                0xC8, // VLE(200) low 7 + cont bit
                0x01, // VLE(200) high byte
            ],
            "DeclSubscriber Nonlocal multi-byte VLE id wire bytes \
             must match zenoh-pico reference",
        );

        // Inner-arm sanity check — must be Nonlocal, not Local.
        match &alias.body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => match &d.keyexpr.body {
                WireexprOwnedVariant::WireexprNonlocal(w) => {
                    assert_eq!(w.id, 7);
                    assert!(w.suffix.is_none());
                }
                _ => panic!(
                    "build_declare_subscriber_nonlocal must produce a \
                         WireexprNonlocal arm"
                ),
            },
            _ => panic!("expected CodecZenohDeclSubscriber"),
        }
    }

    #[test]
    #[should_panic(expected = "build_declare_subscriber_nonlocal requires a non-zero mapping id")]
    fn build_declare_subscriber_nonlocal_rejects_zero_mapping_id() {
        let _ = build_declare_subscriber_nonlocal(5, 0, Some("demo/test"));
    }

    /// R121i-d — Wire-byte regression gate for
    /// `build_declare_queryable_nonlocal`. Mirror of the Local-arm
    /// byte-compare with MID swap 0x02 → 0x04 and the M-bit OR
    /// convention flipped to 0x00. No-info-ext shape (default-state
    /// `_z_queryable_infos_t`); a future round adding `complete` /
    /// `distance` will introduce a separate
    /// `build_declare_queryable_nonlocal_with_info` byte-compare.
    #[test]
    fn build_declare_queryable_nonlocal_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — pure alias.
        let alias = build_declare_queryable_nonlocal(9, 7, None).unwrap();
        assert_eq!(
            alias.wire(),
            vec![
                wire_const::N_MID_DECLARE,
                0x04, // MID only, no N, no M
                0x09,
                0x07,
            ],
            "DeclQueryable Nonlocal alias-case wire bytes must match \
             zenoh-pico reference",
        );

        // Case 2 — composite.
        let composite = build_declare_queryable_nonlocal(9, 7, Some("abc")).unwrap();
        let mut composite_expected = vec![
            wire_const::N_MID_DECLARE,
            0x24, // MID | N, no M
            0x09,
            0x07,
            0x03,
        ];
        composite_expected.extend_from_slice(b"abc");
        assert_eq!(
            composite.wire(),
            composite_expected,
            "DeclQueryable Nonlocal composite-case wire bytes must match \
             zenoh-pico reference",
        );

        // Case 3 — multi-byte VLE boundary on the peer's mapping id.
        let large = build_declare_queryable_nonlocal(9, 200, None).unwrap();
        assert_eq!(
            large.wire(),
            vec![wire_const::N_MID_DECLARE, 0x04, 0x09, 0xC8, 0x01,],
            "DeclQueryable Nonlocal multi-byte VLE id wire bytes must \
             match zenoh-pico reference",
        );

        match &alias.body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => match &d.keyexpr.body {
                WireexprOwnedVariant::WireexprNonlocal(w) => {
                    assert_eq!(w.id, 7);
                    assert!(w.suffix.is_none());
                }
                _ => panic!(
                    "build_declare_queryable_nonlocal must produce a \
                         WireexprNonlocal arm"
                ),
            },
            _ => panic!("expected CodecZenohDeclQueryable"),
        }
    }

    #[test]
    #[should_panic(expected = "build_declare_queryable_nonlocal requires a non-zero mapping id")]
    fn build_declare_queryable_nonlocal_rejects_zero_mapping_id() {
        let _ = build_declare_queryable_nonlocal(9, 0, Some("demo/test"));
    }

    /// R121i-d — Wire-byte regression gate for
    /// `build_declare_token_nonlocal`. Mirror of the Local-arm byte-
    /// compare with MID swap to 0x06 and the M-bit OR flipped to 0x00.
    /// DeclToken has no extension surface — emit is byte-stable for
    /// every `(id, mapping, suffix)` input in either arm.
    #[test]
    fn build_declare_token_nonlocal_emits_zenoh_pico_compatible_wire_bytes() {
        let alias = build_declare_token_nonlocal(11, 7, None).unwrap();
        assert_eq!(
            alias.wire(),
            vec![
                wire_const::N_MID_DECLARE,
                0x06, // MID only, no N, no M
                0x0B, // VLE(token_id=11)
                0x07,
            ],
            "DeclToken Nonlocal alias-case wire bytes must match \
             zenoh-pico reference",
        );

        let composite = build_declare_token_nonlocal(11, 7, Some("abc")).unwrap();
        let mut composite_expected = vec![
            wire_const::N_MID_DECLARE,
            0x26, // MID | N, no M
            0x0B,
            0x07,
            0x03,
        ];
        composite_expected.extend_from_slice(b"abc");
        assert_eq!(
            composite.wire(),
            composite_expected,
            "DeclToken Nonlocal composite-case wire bytes must match \
             zenoh-pico reference",
        );

        let large = build_declare_token_nonlocal(11, 200, None).unwrap();
        assert_eq!(
            large.wire(),
            vec![wire_const::N_MID_DECLARE, 0x06, 0x0B, 0xC8, 0x01,],
            "DeclToken Nonlocal multi-byte VLE id wire bytes must match \
             zenoh-pico reference",
        );

        match &alias.body {
            DeclareOwnedVariant::CodecZenohDeclToken(d) => match &d.keyexpr.body {
                WireexprOwnedVariant::WireexprNonlocal(w) => {
                    assert_eq!(w.id, 7);
                    assert!(w.suffix.is_none());
                }
                _ => panic!(
                    "build_declare_token_nonlocal must produce a \
                         WireexprNonlocal arm"
                ),
            },
            _ => panic!("expected CodecZenohDeclToken"),
        }
    }

    #[test]
    #[should_panic(expected = "build_declare_token_nonlocal requires a non-zero mapping id")]
    fn build_declare_token_nonlocal_rejects_zero_mapping_id() {
        let _ = build_declare_token_nonlocal(11, 0, Some("demo/test"));
    }

    /// R121i-c — `build_undeclare_kexpr` produces a `Declare`
    /// envelope carrying an `UndeclKexpr` body. Two vectors lock both
    /// the single-byte VLE id case and the multi-byte VLE boundary
    /// (id >= 128) so a future codegen drift on the VLE writer
    /// surfaces immediately. Reference: zenoh-pico
    /// `_z_undecl_kexpr_encode` at declarations.c:86-89 —
    /// `[header(_Z_UNDECL_KEXPR_MID=0x01), VLE(id)]`, no Z ext, no
    /// wireexpr body.
    #[test]
    fn build_undeclare_kexpr_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — single-byte VLE id (id=42 fits in 7 bits).
        let small = build_undeclare_kexpr(42);
        let small_wire = small.wire();
        let small_expected = vec![
            wire_const::N_MID_DECLARE, // 0x1E outer
            0x01,                      // _Z_UNDECL_KEXPR_MID
            0x2A,                      // VLE(42) single byte
        ];
        assert_eq!(
            small_wire, small_expected,
            "UndeclKexpr small-id wire bytes must match zenoh-pico reference"
        );

        // Case 2 — multi-byte VLE id (id=200 crosses the 7-bit
        // boundary; first byte = 0xC8 (low 7 bits 0x48 + cont 0x80),
        // second byte = 0x01).
        let large = build_undeclare_kexpr(200);
        let large_wire = large.wire();
        let large_expected = vec![
            wire_const::N_MID_DECLARE,
            0x01,
            0xC8, // (200 & 0x7F) | 0x80
            0x01, // 200 >> 7
        ];
        assert_eq!(
            large_wire, large_expected,
            "UndeclKexpr multi-byte VLE id wire bytes must match zenoh-pico reference"
        );

        // Inner-arm sanity check on the small-id case.
        match &small.body {
            DeclareOwnedVariant::CodecZenohUndeclKexpr(d) => {
                assert_eq!(d.header, 0x01, "header carries MID only; Z (bit-7) clear");
                assert_eq!(d.id, 42);
            }
            _ => panic!("build_undeclare_kexpr must produce CodecZenohUndeclKexpr"),
        }
    }

    /// R121i-c — `build_undeclare_subscriber` produces a `Declare`
    /// envelope carrying an `UndeclSubscriber` body in the no-ext
    /// shape (Z bit clear). Reference: zenoh-pico
    /// `_z_undecl_subscriber_encode` -> `_z_undecl_encode(.., has_keyexpr_ext=false)`
    /// at declarations.c:90-103. The keyexpr-carrying SOURCED form is
    /// `build_undeclare_subscriber_with_keyexpr` (c3c-3 debt A1); this id-only
    /// no-ext contract is locked by the two vectors below.
    #[test]
    fn build_undeclare_subscriber_emits_zenoh_pico_compatible_wire_bytes() {
        let small = build_undeclare_subscriber(42);
        let small_wire = small.wire();
        assert_eq!(
            small_wire,
            vec![
                wire_const::N_MID_DECLARE,
                0x03, // _Z_UNDECL_SUBSCRIBER_MID
                0x2A, // VLE(42)
            ],
            "UndeclSubscriber small-id wire bytes must match zenoh-pico reference",
        );

        let large = build_undeclare_subscriber(200);
        let large_wire = large.wire();
        assert_eq!(
            large_wire,
            vec![wire_const::N_MID_DECLARE, 0x03, 0xC8, 0x01,],
            "UndeclSubscriber multi-byte VLE id wire bytes must match zenoh-pico reference",
        );

        match &small.body {
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(d) => {
                assert_eq!(d.header, 0x03);
                assert_eq!(d.id, 42);
            }
            _ => panic!("build_undeclare_subscriber must produce CodecZenohUndeclSubscriber"),
        }
    }

    /// c3c-3 debt A1 — `build_undeclare_subscriber_with_keyexpr` emits the
    /// SOURCED retraction wire: `id == 0`, the inner header carries `Z`, and the
    /// keyexpr rides the `ext_keyexpr` ZBuf extension. Byte-parity against
    /// zenoh-pico `_z_undecl_subscriber_encode` ->
    /// `_z_undecl_encode(.., has_keyexpr_ext=true)` -> `_z_decl_ext_keyexpr_encode`
    /// (declarations.c:38-50 + 90-103) for the local literal "demo/sub".
    #[test]
    fn build_undeclare_subscriber_with_keyexpr_emits_zenoh_pico_compatible_wire_bytes() {
        let d = build_undeclare_subscriber_with_keyexpr("demo/sub").unwrap();
        let wire = d.wire();
        let mut expected = vec![
            wire_const::N_MID_DECLARE, // 0x1E outer Declare envelope
            0x83,                      // UndeclSubscriber MID 0x03 | Z (ext chain present)
            0x00,                      // VLE(id 0) — sourced subscriptions use no id
            0x5f,                      // ext_keyexpr header: ENC_ZBUF 0x40 | M 0x10 | id 0x0f
            0x0A,                      // ZBuf len VLE(10) = inner_header(1) + VLE(0)(1) + 8 suffix
            0x03,                      // inner_header: is_local(2) | has_suffix(1)
            0x00,                      // VLE(mapping id 0) — literal sentinel
        ];
        expected.extend_from_slice(b"demo/sub");
        assert_eq!(
            wire, expected,
            "sourced UndeclareSubscriber + ext_keyexpr wire must match zenoh-pico",
        );
    }

    /// c3c-3 debt A1 — the stamped `ext_keyexpr` survives the Declare codec
    /// encode -> decode: a transit linkstate peer recovers the retracted keyexpr
    /// from the decoded body (the wire path the forwarder drives). The Declare
    /// extension path was never exercised for UndeclSubscriber before this round
    /// (every build_undeclare_* used the no-ext shape).
    #[test]
    fn undeclare_subscriber_keyexpr_round_trips_through_the_wire() {
        use crate::declare_ext_keyexpr::read_ext_keyexpr;
        use sce_forge_runtime::codec::SceCursor;
        use wz_codecs::declare::Declare;

        let d = build_undeclare_subscriber_with_keyexpr("demo/sub").unwrap();
        let bytes = d.wire();
        let mut cursor = SceCursor::new(&bytes);
        let decoded = Declare::decode(&mut cursor)
            .and_then(|x| x.try_into_owned())
            .expect("decode declare");
        match &decoded.body {
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(u) => {
                assert_eq!(u.id, 0, "sourced retraction carries no id");
                assert_eq!(
                    read_ext_keyexpr(u.extensions.as_ref()),
                    Some("demo/sub"),
                    "ext_keyexpr survived the wire round-trip",
                );
            }
            _ => panic!("decoded body must be UndeclSubscriber"),
        }
    }

    /// The token twin of
    /// [`build_undeclare_subscriber_with_keyexpr_emits_zenoh_pico_compatible_wire_bytes`]:
    /// a sourced `UndeclareToken` (id 0, Z=1) carrying the retracted keyexpr in the
    /// ext_keyexpr chain — the wire the router floods on a native token retraction.
    /// Only the inner MID differs from the subscriber (0x07 vs 0x03).
    #[test]
    fn build_undeclare_token_with_keyexpr_emits_zenoh_pico_compatible_wire_bytes() {
        let d = build_undeclare_token_with_keyexpr("live/tok").unwrap();
        let wire = d.wire();
        let mut expected = vec![
            wire_const::N_MID_DECLARE, // 0x1E outer Declare envelope
            0x87,                      // UndeclToken MID 0x07 | Z (ext chain present)
            0x00,                      // VLE(id 0) — sourced tokens use no id
            0x5f,                      // ext_keyexpr header: ENC_ZBUF 0x40 | M 0x10 | id 0x0f
            0x0A,                      // ZBuf len VLE(10) = inner_header(1) + VLE(0)(1) + 8 suffix
            0x03,                      // inner_header: is_local(2) | has_suffix(1)
            0x00,                      // VLE(mapping id 0) — literal sentinel
        ];
        expected.extend_from_slice(b"live/tok");
        assert_eq!(
            wire, expected,
            "sourced UndeclareToken + ext_keyexpr wire must match zenoh-pico",
        );
    }

    /// The token twin of [`undeclare_subscriber_keyexpr_round_trips_through_the_wire`]:
    /// the stamped ext_keyexpr survives the Declare encode -> decode, so a transit
    /// linkstate peer recovers the retracted token keyexpr from the decoded body
    /// (the wire path RouterForwarder::withdraw_token drives).
    #[test]
    fn undeclare_token_keyexpr_round_trips_through_the_wire() {
        use crate::declare_ext_keyexpr::read_ext_keyexpr;
        use sce_forge_runtime::codec::SceCursor;
        use wz_codecs::declare::Declare;

        let d = build_undeclare_token_with_keyexpr("live/tok").unwrap();
        let bytes = d.wire();
        let mut cursor = SceCursor::new(&bytes);
        let decoded = Declare::decode(&mut cursor)
            .and_then(|x| x.try_into_owned())
            .expect("decode declare");
        match &decoded.body {
            DeclareOwnedVariant::CodecZenohUndeclToken(u) => {
                assert_eq!(u.id, 0, "sourced retraction carries no id");
                assert_eq!(
                    read_ext_keyexpr(u.extensions.as_ref()),
                    Some("live/tok"),
                    "ext_keyexpr survived the wire round-trip",
                );
            }
            _ => panic!("decoded body must be UndeclToken"),
        }
    }

    /// R121i-c — `build_undeclare_queryable` produces a `Declare`
    /// envelope carrying an `UndeclQueryable` body in the no-ext
    /// shape. MID = 0x05 (_Z_UNDECL_QUERYABLE_MID); rest matches
    /// `_z_undecl_encode` shape from declarations.c:120-122.
    #[test]
    fn build_undeclare_queryable_emits_zenoh_pico_compatible_wire_bytes() {
        let small = build_undeclare_queryable(42);
        assert_eq!(
            small.wire(),
            vec![
                wire_const::N_MID_DECLARE,
                0x05, // _Z_UNDECL_QUERYABLE_MID
                0x2A,
            ],
            "UndeclQueryable small-id wire bytes must match zenoh-pico reference",
        );

        let large = build_undeclare_queryable(200);
        assert_eq!(
            large.wire(),
            vec![wire_const::N_MID_DECLARE, 0x05, 0xC8, 0x01,],
            "UndeclQueryable multi-byte VLE id wire bytes must match zenoh-pico reference",
        );

        match &small.body {
            DeclareOwnedVariant::CodecZenohUndeclQueryable(d) => {
                assert_eq!(d.header, 0x05);
                assert_eq!(d.id, 42);
            }
            _ => panic!("build_undeclare_queryable must produce CodecZenohUndeclQueryable"),
        }
    }

    /// `build_undeclare_queryable_with_keyexpr` emits the SOURCED retraction
    /// wire: `id == 0`, the inner header carries `Z`, and the keyexpr rides the
    /// `ext_keyexpr` ZBuf extension. Byte-identical to the subscriber retraction
    /// (`build_undeclare_subscriber_with_keyexpr`) except the inner MID (0x05 vs
    /// 0x03) — the query-plane twin of the c3c-3 debt A1 wire, verified against
    /// zenoh `UndeclareQueryable.ext_wire_expr` + zenoh-pico
    /// `_z_decl_ext_keyexpr_encode` (declarations.c:38-50 + 90-103).
    #[test]
    fn build_undeclare_queryable_with_keyexpr_emits_zenoh_pico_compatible_wire_bytes() {
        let d = build_undeclare_queryable_with_keyexpr("demo/qbl").unwrap();
        let wire = d.wire();
        let mut expected = vec![
            wire_const::N_MID_DECLARE, // 0x1E outer Declare envelope
            0x85,                      // UndeclQueryable MID 0x05 | Z (ext chain present)
            0x00,                      // VLE(id 0) — sourced queryables use no id
            0x5f,                      // ext_keyexpr header: ENC_ZBUF 0x40 | M 0x10 | id 0x0f
            0x0A,                      // ZBuf len VLE(10) = inner_header(1) + VLE(0)(1) + 8 suffix
            0x03,                      // inner_header: is_local(2) | has_suffix(1)
            0x00,                      // VLE(mapping id 0) — literal sentinel
        ];
        expected.extend_from_slice(b"demo/qbl");
        assert_eq!(
            wire, expected,
            "sourced UndeclareQueryable + ext_keyexpr wire must match zenoh-pico",
        );
    }

    /// The stamped `ext_keyexpr` survives the Declare codec encode -> decode: a
    /// transit linkstate peer recovers the retracted keyexpr from the decoded
    /// `UndeclQueryable` body (the wire path the forwarder drives for the
    /// cross-tier qabl retraction). The query-plane twin of
    /// [`undeclare_subscriber_keyexpr_round_trips_through_the_wire`].
    #[test]
    fn undeclare_queryable_keyexpr_round_trips_through_the_wire() {
        use crate::declare_ext_keyexpr::read_ext_keyexpr;
        use sce_forge_runtime::codec::SceCursor;
        use wz_codecs::declare::Declare;

        let d = build_undeclare_queryable_with_keyexpr("demo/qbl").unwrap();
        let bytes = d.wire();
        let mut cursor = SceCursor::new(&bytes);
        let decoded = Declare::decode(&mut cursor)
            .and_then(|x| x.try_into_owned())
            .expect("decode declare");
        match &decoded.body {
            DeclareOwnedVariant::CodecZenohUndeclQueryable(u) => {
                assert_eq!(u.id, 0, "sourced retraction carries no id");
                assert_eq!(
                    read_ext_keyexpr(u.extensions.as_ref()),
                    Some("demo/qbl"),
                    "ext_keyexpr survived the wire round-trip",
                );
            }
            _ => panic!("decoded body must be UndeclQueryable"),
        }
    }

    /// R121i-c — `build_undeclare_token` produces a `Declare`
    /// envelope carrying an `UndeclToken` body in the no-ext shape.
    /// MID = 0x07 (_Z_UNDECL_TOKEN_MID); rest matches the
    /// `_z_undecl_encode` shape from declarations.c:128-130.
    #[test]
    fn build_undeclare_token_emits_zenoh_pico_compatible_wire_bytes() {
        let small = build_undeclare_token(42);
        assert_eq!(
            small.wire(),
            vec![
                wire_const::N_MID_DECLARE,
                0x07, // _Z_UNDECL_TOKEN_MID
                0x2A,
            ],
            "UndeclToken small-id wire bytes must match zenoh-pico reference",
        );

        let large = build_undeclare_token(200);
        assert_eq!(
            large.wire(),
            vec![wire_const::N_MID_DECLARE, 0x07, 0xC8, 0x01,],
            "UndeclToken multi-byte VLE id wire bytes must match zenoh-pico reference",
        );

        match &small.body {
            DeclareOwnedVariant::CodecZenohUndeclToken(d) => {
                assert_eq!(d.header, 0x07);
                assert_eq!(d.id, 42);
            }
            _ => panic!("build_undeclare_token must produce CodecZenohUndeclToken"),
        }
    }

    /// R121i-c — `build_declare_final` produces a `Declare` envelope
    /// carrying a single-byte `DeclFinal` marker. Reference: zenoh-
    /// pico `_z_decl_final_encode` at declarations.c:131-135 —
    /// `[header(_Z_DECL_FINAL_MID=0x1A)]`, no body, no id, no ext.
    /// The full wire is exactly 2 bytes (`N_MID_DECLARE` outer +
    /// `DeclFinal.header` inner); the byte-compare locks both.
    #[test]
    fn build_declare_final_emits_two_byte_marker() {
        let declare = build_declare_final();
        let wire = declare.wire();
        assert_eq!(
            wire,
            vec![
                wire_const::N_MID_DECLARE, // 0x1E outer
                0x1A,                      // _Z_DECL_FINAL_MID inner
            ],
            "DeclFinal wire must equal [N_MID_DECLARE, _Z_DECL_FINAL_MID]",
        );

        match &declare.body {
            DeclareOwnedVariant::CodecZenohDeclFinal(d) => {
                assert_eq!(
                    d.header, 0x1A,
                    "DeclFinal.header must equal _Z_DECL_FINAL_MID"
                );
            }
            _ => panic!("build_declare_final must produce CodecZenohDeclFinal"),
        }
    }

    /// R311y141 — the interest-response subscriber reply stamps BOTH the envelope
    /// `I` flag (0x20) and `interest_id`, keyed on the literal keyexpr (id 0 +
    /// suffix). The peer reads the id iff the header `I` bit is set, so both must
    /// travel together; the leading wire bytes assert exactly that coupling.
    #[test]
    fn build_declare_subscriber_reply_stamps_interest_id_and_i_flag() {
        let declare = build_declare_subscriber_reply(5, "demo/key").unwrap();
        assert_eq!(
            declare.header,
            wire_const::N_MID_DECLARE | wire_const::FLAG_N_DECLARE_I,
            "reply envelope must set the I flag (0x20) atop N_MID_DECLARE",
        );
        assert_eq!(
            declare.interest_id,
            Some(5),
            "reply must echo the received interest id"
        );
        match &declare.body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(d) => {
                assert_eq!(d.id, 0, "a current-dump sub uses id 0 (zenoh make_sub_id)");
                match &d.keyexpr.body {
                    WireexprOwnedVariant::WireexprLocal(w) => {
                        assert_eq!(w.id, 0, "literal-keyexpr sentinel 0");
                        assert_eq!(w.suffix.as_deref(), Some("demo/key"));
                    }
                    _ => panic!("reply keyexpr must be the literal WireexprLocal form"),
                }
            }
            _ => panic!("build_declare_subscriber_reply must produce a DeclSubscriber"),
        }
        // Wire lead: 0x3E (N_MID_DECLARE 0x1E | I 0x20), then interest_id VLE(5).
        let outer = declare.wire();
        assert_eq!(
            &outer[..2],
            &[0x3E, 0x05],
            "the I-flagged envelope + interest_id varint must lead the wire",
        );
    }

    /// R311y141 — the interest terminator. The `interest_id` is MANDATORY (pico
    /// hard-errors on a DeclFinal without it), so the wire is exactly
    /// `[0x3E, VLE(id), 0x1A]` — unlike the unsolicited two-byte
    /// `build_declare_final` (`[0x1E, 0x1A]`).
    #[test]
    fn build_declare_final_reply_stamps_interest_id_and_i_flag() {
        let declare = build_declare_final_reply(9);
        assert_eq!(
            declare.header,
            wire_const::N_MID_DECLARE | wire_const::FLAG_N_DECLARE_I,
        );
        assert_eq!(declare.interest_id, Some(9));
        assert_eq!(
            declare.wire(),
            vec![0x3E, 0x09, 0x1A],
            "envelope+I, interest_id VLE(9), DeclFinal MID (0x1A)",
        );
    }

    /// R311y141 — the query-plane reply carries the `I`+id coupling AND a
    /// non-DEFAULT `QueryableInfo` on the body ext chain: a
    /// `Z_QUERY_TARGET_ALL_COMPLETE` querier's write-filter deactivates only on a
    /// reply with `complete = true`, so the info must NOT collapse to DEFAULT.
    #[test]
    fn build_declare_queryable_reply_stamps_id_and_carries_complete() {
        let declare = build_declare_queryable_reply(
            3,
            "query/svc",
            crate::queryable_info::QueryableInfo::local(true),
        )
        .unwrap();
        assert_eq!(
            declare.header,
            wire_const::N_MID_DECLARE | wire_const::FLAG_N_DECLARE_I,
        );
        assert_eq!(declare.interest_id, Some(3));
        match &declare.body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(d) => {
                assert_eq!(d.id, 0);
                assert!(
                    d.extensions.is_some(),
                    "a complete=true QueryableInfo must ride the body ext chain",
                );
            }
            _ => panic!("build_declare_queryable_reply must produce a DeclQueryable"),
        }
    }
}
