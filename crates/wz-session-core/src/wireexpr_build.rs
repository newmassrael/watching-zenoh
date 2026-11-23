// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Shared `Wireexpr` constructors — codec-agnostic keyexpr building used by
//! every message that carries a keyexpr (Push, Request, Declare).
//!
//! [`literal_wireexpr`] is the SSOT the linkstate forwarder uses to NORMALIZE
//! an inbound aliased keyexpr back to a literal before forwarding a message
//! onward (c3c-3 B1): a downstream link does not share the inbound link's
//! keyexpr-alias table, so an aliased id would be unresolvable there. It built
//! Pushes originally (it lived in `push_build`); relocated here, gated only on
//! `alloc`, so the Request forward path (`set_request_keyexpr_literal`) can
//! reuse the SAME constructor without pulling in the Push codec.

use sce_forge_runtime::codec::{Bounded, CodecError};
use wz_codecs::wireexpr::{WireexprFrom, WireexprOwned, WireexprOwnedVariant};
use wz_codecs::wireexpr_local::{WireexprLocalOwned, WireexprLocalSuffixField};

/// A literal `Wireexpr` carrying `suffix` (mapping id 0 — the literal
/// sentinel). The codec-agnostic SSOT a forwarder re-expresses an aliased
/// keyexpr through before it crosses a link that does not share the inbound
/// alias table (c3c-3 B1). Fallible by the suffix's bound: `LengthOutOfRange`
/// past the `u16` length the protocol gives a suffix, and `CapacityExceeded`
/// past what the profile stores of one.
///
/// Generic over the storage profile (R3011): Push, Request and Response build
/// theirs at the wire profile and Declare at the default, and the profile is
/// the one the caller's field names.
pub fn literal_wireexpr<S: for<'x> WireexprFrom<'x>>(
    suffix: &str,
) -> Result<WireexprOwned<S>, CodecError> {
    let text = Bounded::new(suffix).ok_or(CodecError::LengthOutOfRange)?;
    Ok(WireexprOwned {
        body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
            id: 0,
            suffix_len: Some(suffix.len() as u64),
            suffix: Some(text.store::<S, WireexprLocalSuffixField>()?),
        }),
    })
}

/// A `Wireexpr` naming `id` and, when there is one, `suffix` after it: in the sender's space
/// (`M=1`, `WireexprLocal`) when `sender_mapping`, in the receiver's (`M=0`, `WireexprNonlocal`)
/// otherwise. Refused by the suffix's bound as [`literal_wireexpr`] is.
#[cfg(feature = "shared-key-ids")]
pub fn aliased_wireexpr<S: for<'x> WireexprFrom<'x>>(
    id: crate::wire_id::ExprId,
    suffix: Option<&str>,
    sender_mapping: bool,
) -> Result<WireexprOwned<S>, CodecError> {
    let text = suffix
        .map(|s| Bounded::new(s).ok_or(CodecError::LengthOutOfRange))
        .transpose()?;
    let suffix_len = suffix.map(|s| s.len() as u64);
    let body = if sender_mapping {
        WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
            id,
            suffix_len,
            suffix: text
                .map(|t| t.store::<S, WireexprLocalSuffixField>())
                .transpose()?,
        })
    } else {
        WireexprOwnedVariant::WireexprNonlocal(
            wz_codecs::wireexpr_nonlocal::WireexprNonlocalOwned {
                id,
                suffix_len,
                suffix: text
                    .map(|t| {
                        t.store::<S, wz_codecs::wireexpr_nonlocal::WireexprNonlocalSuffixField>()
                    })
                    .transpose()?,
            },
        )
    };
    Ok(WireexprOwned { body })
}

/// The `Wireexpr` naming `key` in the sender's space (`M=1`, `WireexprLocal`): its id, and the text
/// after the id with its length. What every builder of a message that names a key writes it
/// through, so the id `0` with no text, which names no key, is not a key any of them can be
/// handed. Refused by the text's bound as [`literal_wireexpr`] is.
pub fn key_wireexpr<S: for<'x> WireexprFrom<'x>>(
    key: crate::wire_key::WireKey<'_>,
) -> Result<WireexprOwned<S>, CodecError> {
    let suffix = key.suffix();
    let text = suffix
        .map(|s| Bounded::new(s).ok_or(CodecError::LengthOutOfRange))
        .transpose()?;
    Ok(WireexprOwned {
        body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
            id: key.id(),
            suffix_len: suffix.map(|s| s.len() as u64),
            suffix: text
                .map(|t| t.store::<S, WireexprLocalSuffixField>())
                .transpose()?,
        }),
    })
}

/// The header bits a message naming `key` carries for it: [`NAMED_FLAG`] when text follows the id.
pub const fn key_flags(key: crate::wire_key::WireKey<'_>) -> u8 {
    if key.suffix().is_some() {
        NAMED_FLAG
    } else {
        0
    }
}

/// The network-message header `N` (Named — suffix present) bit, uniform across
/// Push / Request / Response (zenoh `{push,request,response}::flag::N = 1 << 5`).
/// A literal keyexpr (a suffix) always carries it.
pub const NAMED_FLAG: u8 = 0x20;

/// Re-express a message's keyexpr fields as the literal `suffix` — the SSOT
/// behind `set_{push,request,response}_keyexpr_literal`: set the `keyexpr` field
/// to a literal ([`literal_wireexpr`]) AND the header's [`NAMED_FLAG`], which a
/// literal keyexpr always carries. The two MUST stay in sync — a clear `N` with a
/// suffix-bearing wireexpr offset-shifts the peer's decode of the following body.
/// Takes the two fields by `&mut` (disjoint borrows of the message struct) so the
/// per-message wrappers are a one-line delegation with no duplicated logic.
pub fn set_literal_keyexpr_fields<S: for<'x> WireexprFrom<'x>>(
    keyexpr: &mut WireexprOwned<S>,
    header: &mut u8,
    suffix: &str,
) -> Result<(), CodecError> {
    *keyexpr = literal_wireexpr(suffix)?;
    *header |= NAMED_FLAG;
    Ok(())
}
