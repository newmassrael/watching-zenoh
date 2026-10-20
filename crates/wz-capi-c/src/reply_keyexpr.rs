// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The rule that decides whether a reply's key is one the query allows, and the reading of the
//! `_anyke` parameter that waives it.
//!
//! Its own module, not part of [`crate::query`], because both ends of a query apply it: the
//! answering end before it queues a reply, and the requesting end ([`crate::get`]) before it
//! accepts one. A build with only one of the two keeps the rule.

use wz_runtime_tokio::reply_acceptance;

/// Whether `reply` is covered by the query — zenoh's `reply ⊆ query` contract.
///
/// INTERSECTION, never string equality. The keyexpr a queryable is asked under
/// is routinely a PATTERN while its replies carry CONCRETE keys, so equality
/// would reject the ordinary wildcard case rather than an edge case. Shared
/// with the RECEIVE gate in [`crate::get`] so the two halves agree.
///
/// R2306 (open-debt item 156) routed it through the workspace SSOT
/// [`reply_acceptance::reply_keyexpr_intersects`], which is what the sibling
/// `wz-capi-pico` twin has called since R311y833. The body this replaced split
/// both sides on `/` and called the matcher itself — the same answer today, and
/// a second place for it to stop being the same answer tomorrow.
pub(crate) fn reply_keyexpr_is_covered(query_keyexpr: &str, reply: &str, anyke: bool) -> bool {
    if anyke {
        return true;
    }
    reply_acceptance::reply_keyexpr_intersects(query_keyexpr, reply)
}

/// Whether the selector asks for replies under ANY key (`_anyke`).
///
/// # R2306 (open-debt item 156) — THIS WAS A THIRD PARSER, AND IT WAS WRONG
///
/// One token had three readers and only two were ever compared: the workspace
/// SSOT ([`selector_params::has_param`], zenoh's rules), `wz-capi-pico`'s
/// byte-boundary port of pico's rules, and this one. This one split the
/// parameter list on `&`.
///
/// zenoh's separator is `;` — `LIST_SEPARATOR: char = ';'`
/// (`commons/zenoh-protocol/src/core/parameters.rs`
/// @ `LIST_SEPARATOR: char = ';'`, at the pinned checkout) — and
/// `reply_key_expr_any()` is `contains_key("_anyke")` over that split
/// (`zenoh/src/api/selector.rs` @ `fn reply_key_expr_any`). So it was found
/// ONLY when it was the
/// entire parameter string. `_max=5;_anyke` read as no-`_anyke`, and the
/// coverage gate above then DROPPED replies the querier had explicitly asked
/// for — silently, on both the responder side (`QueryMarshal`) and the receive
/// side (`crate::get`). wz's own GETs emit exactly that shape:
/// `wz-runtime-tokio`'s history selector builds `_max=2;_time=[…];_anyke`.
///
/// It calls [`ReplyKeyExpr::from_parameters`], not the parameter reader under
/// it, because that enum IS the question — "which reply-keyexpr mode does this
/// selector express" — and its own doc already names both references it has to
/// agree with. Reaching past it to `selector_params::has_param` would make this
/// crate the second place that knows `_anyke` is how the mode travels.
///
/// The SSOT is session-core's rather than pico's because this ABI mirrors
/// zenoh-c, whose queries are zenoh's `Query` and whose `_anyke` is read by
/// zenoh's `Parameters`. `wz-capi-pico` keeps its own for the same reason in
/// reverse: pico's `_z_parameters_has_anyke` has no key/value semantics, and
/// porting zenoh's there would be the mirror of this defect.
pub(crate) fn parameters_has_anyke(parameters: &[u8]) -> bool {
    std::str::from_utf8(parameters).is_ok_and(|text| {
        reply_acceptance::ReplyKeyExpr::from_parameters(text) == reply_acceptance::ReplyKeyExpr::Any
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `reply ⊆ query` gate is an INTERSECTION, so a wildcard query admits
    /// a concrete reply — the ordinary case, which string equality would
    /// reject.
    #[test]
    fn the_reply_gate_intersects_rather_than_compares() {
        assert!(reply_keyexpr_is_covered("demo/**", "demo/a/b", false));
        assert!(reply_keyexpr_is_covered("demo/*", "demo/a", false));
        assert!(!reply_keyexpr_is_covered("demo/a", "other/a", false));
        // `_anyke` waives the gate entirely, which is what it is for.
        assert!(reply_keyexpr_is_covered("demo/a", "other/a", true));
    }

    /// `_anyke` is recognised both bare and with a value, and NOT as a prefix
    /// of some other field — `_anykey=1` is a different selector.
    ///
    /// R2306 (open-debt item 156) — THE SEPARATOR IS `;`, and the version of
    /// this test that shipped before said `&`. It said so because it was
    /// written from the code beside it rather than from zenoh, and the code
    /// split on `&`; the two agreed with each other and with nothing else.
    /// Upstream's rule is cited where the parser is; this test only has to
    /// state it. wz's own GETs emit that
    /// spelling too — `wz-runtime-tokio`'s history selector builds
    /// `_max=2;_time=[now(-30s)..];_anyke`.
    ///
    /// So the shipped parser found the flag ONLY when it was the whole
    /// parameter string: any real multi-parameter selector read as "no
    /// `_anyke`", and the coverage gate then dropped replies the querier had
    /// explicitly asked for.
    #[test]
    fn anyke_is_read_off_the_selector_exactly() {
        assert!(parameters_has_anyke(b"_anyke"));
        assert!(parameters_has_anyke(b"_anyke=true"));
        assert!(!parameters_has_anyke(b"_anykey=1"));
        assert!(!parameters_has_anyke(b""));
        // The separator zenoh actually uses, in every position.
        assert!(parameters_has_anyke(b"a=1;_anyke;b=2"));
        assert!(parameters_has_anyke(b"_max=5;_anyke"));
        assert!(parameters_has_anyke(b"_anyke;_max=5"));
        assert!(parameters_has_anyke(b"_max=2;_time=[now(-30s)..];_anyke"));
        // And `&` is NOT a separator, so a field spelled with one is one field.
        assert!(!parameters_has_anyke(b"a=1&_anyke&b=2"));
    }
}
