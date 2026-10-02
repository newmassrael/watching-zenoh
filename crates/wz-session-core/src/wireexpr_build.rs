// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

use sce_forge_runtime::codec::{CodecError, CodecStorage, SceStr};
use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};
use wz_codecs::wireexpr_local::WireexprLocalOwned;

/// A literal `Wireexpr` carrying `suffix` (mapping id 0 — the literal
/// sentinel). The codec-agnostic SSOT a forwarder re-expresses an aliased
/// keyexpr through before it crosses a link that does not share the inbound
/// alias table (c3c-3 B1). Fallible only by the owned-string copy.
///
/// Generic over the storage profile (R3011): Push, Request and Response build
/// theirs at the wire profile and Declare at the default, and the profile is
/// the one the caller's field names.
pub fn literal_wireexpr<S: CodecStorage>(suffix: &str) -> Result<WireexprOwned<S>, CodecError> {
    Ok(WireexprOwned {
        body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
            id: 0,
            suffix_len: Some(suffix.len() as u64),
            suffix: Some(<S::Str<128> as SceStr>::from_view(suffix)?),
        }),
    })
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
pub fn set_literal_keyexpr_fields<S: CodecStorage>(
    keyexpr: &mut WireexprOwned<S>,
    header: &mut u8,
    suffix: &str,
) -> Result<(), CodecError> {
    *keyexpr = literal_wireexpr(suffix)?;
    *header |= NAMED_FLAG;
    Ok(())
}
