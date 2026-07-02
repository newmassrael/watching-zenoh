// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R310.5a / R311di-13 — `resolve_wireexpr` peer-keyexpr-table lookup.
//!
//! Free-standing helper shared by the application-layer remote-
//! declaration registries (`RemoteSubscriberRegistry`,
//! `RemoteQueryableRegistry`, `LivelinessRegistry`,
//! `LivelinessSubscriberRegistry`). Mirrors the resolver inside
//! `wz-runtime-tokio::pubsub::SubscriberRegistry` so the four sibling
//! registries don't need a reference back to that registry to compose
//! a literal keyexpr from a Wireexpr + the peer mapping table.

use alloc::string::{String, ToString};

use hashbrown::HashMap;

use wz_codecs::wireexpr::WireexprOwnedVariant;

/// Resolve a `Wireexpr` to its literal keyexpr string using a peer
/// mapping table.
///
/// Composition rule (mirrors zenoh-pico
/// `_z_keyexpr_resolve_in_keyexprs_map`):
/// - `id == 0` → suffix verbatim (no table lookup).
/// - `id != 0` → `table[id] + suffix` (table-base prefix + optional
///   per-message suffix).
///
/// Returns `None` when `id != 0` and the table has no entry for
/// the id (the peer references a mapping it never declared). The
/// caller decides whether to skip the dispatch (preferred, the
/// declaration is incomplete) or surface the half-truth (currently
/// no caller does the latter).
/// Whether `body` is the EMPTY wire keyexpr (`id == 0` with no — or an empty —
/// suffix): zenoh's `WireExpr::empty()`, carried by keyexpr-less replies such
/// as the synthesized timeout `Err` (`build_response_err_empty`). A relay MUST
/// NOT route such a message through [`resolve_wireexpr`] (which returns `None`
/// for it — an empty keyexpr resolves to nothing) but pass it through with only
/// the rid rewritten, exactly as zenoh's `route_send_response` forwards a reply
/// with NO keyexpr resolution at all (`dispatcher/queries.rs:595-635`).
pub fn wireexpr_is_empty(body: &WireexprOwnedVariant) -> bool {
    let (id, suffix_opt) = match body {
        WireexprOwnedVariant::WireexprLocal(arm) => (arm.id, arm.suffix.as_deref()),
        WireexprOwnedVariant::WireexprNonlocal(arm) => (arm.id, arm.suffix.as_deref()),
    };
    id == 0 && suffix_opt.map_or(true, str::is_empty)
}

pub fn resolve_wireexpr(
    body: &WireexprOwnedVariant,
    table: &HashMap<u64, String>,
) -> Option<String> {
    let (id, suffix_opt) = match body {
        WireexprOwnedVariant::WireexprLocal(arm) => (arm.id, arm.suffix.as_deref()),
        WireexprOwnedVariant::WireexprNonlocal(arm) => (arm.id, arm.suffix.as_deref()),
    };
    if id == 0 {
        suffix_opt.map(str::to_string)
    } else {
        let base = table.get(&id)?.clone();
        Some(match suffix_opt {
            Some(s) => {
                let mut out = base;
                out.push_str(s);
                out
            }
            None => base,
        })
    }
}
