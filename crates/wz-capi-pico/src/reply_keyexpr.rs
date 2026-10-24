// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The reply-keyexpr policy a query carries, which both ends of a query read: the requester
//! (`get`, `querier`) writes it, the responder (`queryable`) reads it.
//!
//! It is here and not in either half so that a build with only one of the two planes still
//! has it, and a build with neither does not.

use std::ffi::c_int;

/// pico `z_reply_keyexpr_t` (`api/constants.h:288-290`): the reply-keyexpr
/// policy a query accepts.
pub type z_reply_keyexpr_t = c_int;
/// pico `Z_REPLY_KEYEXPR_ANY` — accept replies on any key (`constants.h:289`).
pub const Z_REPLY_KEYEXPR_ANY: z_reply_keyexpr_t = 0;
/// pico `Z_REPLY_KEYEXPR_MATCHING_QUERY` — accept only replies whose key
/// intersects the query's (`constants.h:290`).
pub const Z_REPLY_KEYEXPR_MATCHING_QUERY: z_reply_keyexpr_t = 1;

/// pico's `_anyke` selector-parameter key (`Z_SELECTOR_QUERY_MATCH`,
/// `~/zenoh-pico/include/zenoh-pico/api/constants.h:18`).
pub(crate) const ANYKE_PARAM: &[u8] = b"_anyke";

/// pico's selector-parameter list separator (`_Z_QUERY_PARAMS_LIST_SEPARATOR`,
/// `~/zenoh-pico/include/zenoh-pico/utils/query_params.h`).
pub(crate) const PARAM_SEPARATOR: u8 = b';';

/// Whether a query's selector parameters carry the `_anyke` key — pico's
/// [`_z_parameters_has_anyke`](https://github.com/eclipse-zenoh/zenoh-pico)
/// (`src/utils/query_params.c:46-70`), ported chunk-boundary rules and all.
///
/// This is how the RESPONDER learns `_anyke`: it is not a wire field but a
/// SELECTOR PARAMETER. The querier's `accept_replies = Z_REPLY_KEYEXPR_ANY`
/// makes the sender append `_anyke` to the parameter list
/// (`src/protocol/codec/message.c:399-423`), and on reception `_implicit_anyke`
/// is unconditionally false — pico's own comment says the flag "is signaled by
/// the presence of the _anyke key in the parameters list, which is parsed
/// later" (`codec/message.c:488-490`). So the responder-side derivation
/// reduces to exactly this parse:
/// `dst->_anyke = implicit_anyke || _z_parameters_has_anyke(...)`
/// (`include/zenoh-pico/net/query.h:104`) with `implicit_anyke == false`.
///
/// The boundary checks are load-bearing and are why this is a real parse rather
/// than a substring search: `_anyke` must start the list or follow a `;`, and
/// must end the list or precede a `;`. Without them a parameter such as
/// `no_anyke` or `_anykey=1` would be read as the flag.
pub(crate) fn parameters_has_anyke(parameters: &[u8]) -> bool {
    let mut start = 0usize;
    while start <= parameters.len() {
        let Some(offset) = parameters[start..]
            .windows(ANYKE_PARAM.len())
            .position(|window| window == ANYKE_PARAM)
        else {
            return false;
        };
        let pos = start + offset;
        let end = pos + ANYKE_PARAM.len();
        let left_ok = pos == 0 || parameters[pos - 1] == PARAM_SEPARATOR;
        let right_ok = end == parameters.len() || parameters[end] == PARAM_SEPARATOR;
        if left_ok && right_ok {
            return true;
        }
        start = end + 1;
    }
    false
}

/// Whether `reply` is covered by the query — zenoh's `reply ⊆ query` contract as
/// pico enforces it: `!query->_anyke && !_z_declared_keyexpr_intersects(...)`
/// → `_Z_ERR_KEYEXPR_NOT_MATCH` (`~/zenoh-pico/src/net/primitives.c:437-440`).
///
/// INTERSECTION, never string equality. The query keyexpr a queryable is asked
/// under is routinely a PATTERN (a queryable declared on `a/**` sees the
/// querier's `a/**`), while its replies carry CONCRETE keys — so equality would
/// reject the ordinary wildcard case, not an edge case. Routed through the one
/// matching SSOT ([`wz_session_core::keyexpr_match`](wz_session_core::keyexpr_match))
/// rather than re-derived.
///
/// R311y833 — the intersection half now DELEGATES to
/// [`wz_session_core::reply_acceptance::reply_keyexpr_intersects`] rather than
/// re-deriving it. The rule was correct here and absent from the native
/// runtime, which is the asymmetry y833 removed: one codebase had two getters
/// with opposite default behaviour because this function was `pub(crate)` and
/// structurally unreachable from `Session::query`. It stays as the RESPONDER
/// gate pico spells at `vendor/zenoh-pico/src/net/primitives.c:438` — a
/// different seam from the requester gate, kept because pico enforces both.
pub(crate) fn reply_keyexpr_is_covered(query_keyexpr: &str, reply: &str, anyke: bool) -> bool {
    if anyke {
        return true;
    }
    wz_session_core::reply_acceptance::reply_keyexpr_intersects(query_keyexpr, reply)
}
