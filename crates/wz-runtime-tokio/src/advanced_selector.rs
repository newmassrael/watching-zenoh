// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y442 — the advanced-pubsub SELECTOR-PARAMETER dialect SSOT: the list
//! separator and the `_anyke` reply-keyexpr token shared by the `@adv` cache
//! (which PARSES `_sn` / `_max` / `_time` out of an inbound query's parameters)
//! and the advanced subscriber (which BUILDS the recovery / history GET
//! selectors). The exact sibling of [`crate::advanced_ke`], and it exists for
//! the same reason: before this module the two sides hand-wrote their own
//! notion of the dialect — the cache split on `&`, the subscriber joined on
//! `&` — so it had no source of truth and both had drifted from upstream in
//! the same direction, which is precisely why no wz<->wz test could see it.
//!
//! ## The separator is `;`, not `&`
//!
//! zenoh's `Parameters` is a `;`-separated key-value list
//! (`LIST_SEPARATOR: char = ';'`, `commons/zenoh-protocol/src/core/parameters.rs:32`;
//! `iter()` splits on it at `:47-51`), and zenoh-pico agrees
//! (`_Z_QUERY_PARAMS_LIST_SEPARATOR ";"`,
//! `vendor/zenoh-pico/include/zenoh-pico/utils/query_params.h:34`). wz's own
//! C-API path already spelled it correctly (`PARAM_SEPARATOR: u8 = b';'`,
//! `wz-capi-pico/src/query.rs:118`) — the runtime path is what diverged.
//!
//! The `&` form is not a harmless spelling difference. A wz history GET
//! carrying both knobs went out as `_max=5&_time=[now(-10s)..]`; zenoh reads
//! that as ONE parameter whose key is `_max` and whose value is
//! `5&_time=[now(-10s)..]`, so `.parse::<u32>()` fails and the cap is dropped —
//! silently, and in the over-return direction, which is the direction a test is
//! least likely to notice. The same happens in reverse when a real zenoh
//! subscriber queries a wz cache.
//!
//! ## `_anyke` is what makes an `@adv` reply legal at all
//!
//! An advanced cache replies under the CACHED SAMPLE's own keyexpr
//! (`demo/example/adv`), while the history GET is addressed to the `@adv`
//! namespace (`demo/example/**/@adv/**`). Those do not intersect. zenoh's
//! responder REFUSES such a reply unless the querier opted in:
//! `Query::_reply_sample` bails with "Attempted to reply on `X`, which does not
//! intersect with query `Y`" unless `_accepts_any_replies()`
//! (`zenoh/src/api/queryable.rs:278-287`), and that flag is nothing but the
//! presence of the `_anyke` parameter (`Parameters::reply_key_expr_any`,
//! `zenoh/src/api/selector.rs:191-194`, keyed by
//! `REPLY_KEY_EXPR_ANY_SEL_PARAM: &str = "_anyke"` at `:144`). zenoh-ext's own
//! advanced subscriber therefore sets `.accept_replies(ReplyKeyExpr::Any)` on
//! every one of its GETs (`zenoh-ext/src/advanced_subscriber.rs:637`, `:744`,
//! `:807`, `:883`, `:947`, `:1009`, `:1138`), which inserts the token
//! (`zenoh/src/api/builders/query.rs:287-294`).
//!
//! Measured against the real oracle before this module existed: a
//! `z_advanced_pub` cache holding 5 samples answered a wz history GET with 5
//! bails and 0 replies, while zenoh's own `z_advanced_sub` against the same
//! cache received all of them. wz was not failing to parse the history — it was
//! never being sent any.
//!
//! Note the sibling asymmetry this closes: wz's C-API path already emitted the
//! token (`ANYKE_PARAM`, `wz-capi-pico/src/query.rs:114`, appended in
//! `wz-capi-pico/src/get.rs:820-835`), so the rule was known in this codebase
//! and lost on the runtime path.
//!
//! ## Scope
//!
//! This module governs what wz SENDS and how wz PARSES. It deliberately does
//! not make the wz `@adv` queryable ENFORCE the gate the way zenoh's responder
//! does — wz's cache replies to a non-`_anyke` query where zenoh would refuse.
//! That is a fail-OPEN divergence on the responder side, recorded rather than
//! folded in here, because turning a fail-open check closed is a behaviour
//! change for every existing wz querier and belongs in its own round.

/// The selector parameter-list separator (zenoh `LIST_SEPARATOR`,
/// `commons/zenoh-protocol/src/core/parameters.rs:32`; pico
/// `_Z_QUERY_PARAMS_LIST_SEPARATOR`, `query_params.h:34`).
pub(crate) const PARAM_LIST_SEPARATOR: char = ';';

/// The reply-keyexpr-any token (zenoh `REPLY_KEY_EXPR_ANY_SEL_PARAM`,
/// `zenoh/src/api/selector.rs:144`; pico `_Z_QUERY_PARAMS_KEY_ANYKE`,
/// `query_params.h:31`). Carried as a BARE token with no `=value`, which is how
/// zenoh serializes it: `set_reply_key_expr_any` inserts an EMPTY value
/// (`selector.rs:179-181`) and `Parameters`' Display renders a valueless entry
/// as the key alone — see zenoh's own round-trip expectation
/// `"_anyke;_filter;_time=[now(-2s)..now(2s)];_timetrick"` (`selector.rs:381`).
#[cfg(any(
    feature = "ext-pubsub-advanced-recovery",
    feature = "ext-pubsub-advanced-history"
))]
pub(crate) const ANYKE_PARAM: &str = "_anyke";

/// Look a `key=value` selector parameter up out of a raw parameter list,
/// splitting on the upstream separator. `None` when the key is absent.
///
/// A valueless token (`_anyke`) has no `=` and therefore never matches a keyed
/// lookup, which is correct: it is a flag, not a value.
#[cfg(feature = "ext-pubsub-advanced-cache")]
pub(crate) fn param_value<'a>(params: &'a str, key: &str) -> Option<&'a str> {
    params.split(PARAM_LIST_SEPARATOR).find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then_some(v)
    })
}

/// Build a GET selector parameter list from `parts` (each already `key=value`),
/// always terminated by the bare [`ANYKE_PARAM`] flag.
///
/// `_anyke` is unconditional rather than caller-controlled because every GET wz
/// issues into the `@adv` namespace is answered under a cached sample's own
/// keyexpr, so every one of them needs it — exactly as zenoh-ext sets
/// `ReplyKeyExpr::Any` on all of its. An empty `parts` yields the bare flag.
#[cfg(any(
    feature = "ext-pubsub-advanced-recovery",
    feature = "ext-pubsub-advanced-history"
))]
pub(crate) fn adv_get_params(parts: &[String]) -> String {
    let mut out = String::new();
    for part in parts {
        out.push_str(part);
        out.push(PARAM_LIST_SEPARATOR);
    }
    out.push_str(ANYKE_PARAM);
    out
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "ext-pubsub-advanced-cache")]
    use super::param_value;
    #[cfg(any(
        feature = "ext-pubsub-advanced-recovery",
        feature = "ext-pubsub-advanced-history"
    ))]
    use super::{adv_get_params, ANYKE_PARAM};

    /// The multi-parameter case the `&` dialect got wrong. Under `&` the FIRST
    /// key parses with a corrupted value (`5;_time=...`) and every later key is
    /// invisible, so both knobs are silently lost; this pins the upstream `;`
    /// reading of the exact string a real zenoh subscriber sends.
    #[cfg(feature = "ext-pubsub-advanced-cache")]
    #[test]
    fn param_value_reads_the_upstream_semicolon_list() {
        let zenoh_shaped = "_max=5;_time=[now(-10s)..];_anyke";
        assert_eq!(param_value(zenoh_shaped, "_max"), Some("5"));
        assert_eq!(param_value(zenoh_shaped, "_time"), Some("[now(-10s)..]"));
        assert_eq!(param_value(zenoh_shaped, "_sn"), None);
    }

    /// A single parameter is separator-independent, which is why the `&` bug
    /// survived: the recovery GET only ever carries `_sn`, so it read correctly
    /// under either dialect and the defect lived entirely in the history path.
    #[cfg(feature = "ext-pubsub-advanced-cache")]
    #[test]
    fn param_value_reads_a_lone_parameter() {
        assert_eq!(param_value("_sn=7..12", "_sn"), Some("7..12"));
    }

    /// The bare flag is not a keyed lookup and must not answer one.
    #[cfg(feature = "ext-pubsub-advanced-cache")]
    #[test]
    fn param_value_ignores_the_valueless_anyke_flag() {
        assert_eq!(param_value("_anyke", "_anyke"), None);
        assert_eq!(param_value("_max=3;_anyke", "_max"), Some("3"));
    }

    #[cfg(any(
        feature = "ext-pubsub-advanced-recovery",
        feature = "ext-pubsub-advanced-history"
    ))]
    #[test]
    fn adv_get_params_joins_on_semicolon_and_always_carries_anyke() {
        assert_eq!(adv_get_params(&[]), ANYKE_PARAM);
        assert_eq!(
            adv_get_params(&["_sn=7..".to_string()]),
            "_sn=7..;_anyke".to_string()
        );
        assert_eq!(
            adv_get_params(&["_max=5".to_string(), "_time=[now(-3s)..]".to_string()]),
            "_max=5;_time=[now(-3s)..];_anyke".to_string()
        );
    }

    /// Round-trip: what the subscriber BUILDS is what the cache READS. The two
    /// sides drifted apart precisely because nothing tied them together.
    #[cfg(all(
        feature = "ext-pubsub-advanced-cache",
        any(
            feature = "ext-pubsub-advanced-recovery",
            feature = "ext-pubsub-advanced-history"
        )
    ))]
    #[test]
    fn built_params_parse_back_through_the_cache_reader() {
        let built = adv_get_params(&["_max=5".to_string(), "_time=[now(-3s)..]".to_string()]);
        assert_eq!(param_value(&built, "_max"), Some("5"));
        assert_eq!(param_value(&built, "_time"), Some("[now(-3s)..]"));
    }
}
