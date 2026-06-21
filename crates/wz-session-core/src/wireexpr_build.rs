// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

use sce_forge_runtime::codec::CodecError;
use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};
use wz_codecs::wireexpr_local::WireexprLocalOwned;

/// A literal `Wireexpr` carrying `suffix` (mapping id 0 — the literal
/// sentinel). The codec-agnostic SSOT a forwarder re-expresses an aliased
/// keyexpr through before it crosses a link that does not share the inbound
/// alias table (c3c-3 B1). Fallible only by the owned-string copy
/// ([`owned_string`](crate::codec_owned::owned_string)).
pub fn literal_wireexpr(suffix: &str) -> Result<WireexprOwned, CodecError> {
    Ok(WireexprOwned {
        body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
            id: 0,
            suffix_len: Some(suffix.len() as u64),
            suffix: Some(crate::codec_owned::owned_string(suffix)?),
        }),
    })
}
