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
use wz_codecs::undecl_queryable::UndeclQueryable;
use wz_codecs::undecl_subscriber::UndeclSubscriber;
use wz_codecs::undecl_token::UndeclToken;
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
#[cfg(feature = "codec-declare")]
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
                    suffix: Some(crate::codec_bound::bounded_string(suffix)?),
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
#[cfg(feature = "codec-declare")]
pub fn build_declare_subscriber(
    subscriber_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Result<DeclareOwned, CodecError> {
    let suffix_len = keyexpr_suffix.map(|s| s.len() as u64);
    let suffix_string = keyexpr_suffix
        .map(crate::codec_bound::bounded_string)
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
#[cfg(feature = "codec-declare")]
pub fn build_declare_queryable(
    queryable_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Result<DeclareOwned, CodecError> {
    let suffix_len = keyexpr_suffix.map(|s| s.len() as u64);
    let suffix_string = keyexpr_suffix
        .map(crate::codec_bound::bounded_string)
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
        }),
    })
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
#[cfg(feature = "codec-declare")]
pub fn build_declare_token(
    token_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Result<DeclareOwned, CodecError> {
    let suffix_len = keyexpr_suffix.map(|s| s.len() as u64);
    let suffix_string = keyexpr_suffix
        .map(crate::codec_bound::bounded_string)
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
#[cfg(feature = "codec-declare")]
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
        .map(crate::codec_bound::bounded_string)
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
#[cfg(feature = "codec-declare")]
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
        .map(crate::codec_bound::bounded_string)
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
        }),
    })
}

/// R121i-d — build a `Declare(DeclToken)` for a keyexpr rooted in the
/// peer's mapping table (M=0 wire arm). Mirror of
/// [`build_declare_token`] for the Nonlocal case. Same id=0 rejection
/// rule as the other `_nonlocal` builders. DeclToken has no extension
/// surface at all, so the no-ext byte-stability contract is preserved.
#[cfg(feature = "codec-declare")]
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
        .map(crate::codec_bound::bounded_string)
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
#[cfg(feature = "codec-declare")]
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
/// AP MVP scope: the wz UndeclSubscriber codec emits the no-ext
/// shape only. The wz codegen for UndeclSubscriber does not model
/// the optional `_z_decl_ext_keyexpr_encode` tail (declarations.c:38-50)
/// — the SCXML stops at `id`. Peers route undeclare by id alone, so
/// the ext is purely informational at this layer (used by routers for
/// cross-validation). Future rounds that need the ext_keyexpr surface
/// extend `sources/codecs/undecl_subscriber.scxml` with the optional
/// ext field + add a separate `build_undeclare_subscriber_with_keyexpr`
/// helper; the no-ext contract here stays byte-stable.
///
/// Wire shape:
///
/// ```text
///   [UndeclSubscriber.header = _Z_UNDECL_SUBSCRIBER_MID (0x03)]
///   VLE(subscriber_id)
/// ```
#[cfg(feature = "codec-declare")]
pub fn build_undeclare_subscriber(subscriber_id: u64) -> DeclareOwned {
    DeclareOwned {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohUndeclSubscriber(UndeclSubscriber {
            header: wire_const::D_MID_UNDECL_SUBSCRIBER,
            id: subscriber_id,
        }),
    }
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
#[cfg(feature = "codec-declare")]
pub fn build_undeclare_queryable(queryable_id: u64) -> DeclareOwned {
    DeclareOwned {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohUndeclQueryable(UndeclQueryable {
            header: wire_const::D_MID_UNDECL_QUERYABLE,
            id: queryable_id,
        }),
    }
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
#[cfg(feature = "codec-declare")]
pub fn build_undeclare_token(token_id: u64) -> DeclareOwned {
    DeclareOwned {
        header: wire_const::N_MID_DECLARE,
        interest_id: None,
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohUndeclToken(UndeclToken {
            header: wire_const::D_MID_UNDECL_TOKEN,
            id: token_id,
        }),
    }
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
#[cfg(feature = "codec-declare")]
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
