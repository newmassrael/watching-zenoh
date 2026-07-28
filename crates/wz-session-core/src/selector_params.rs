// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y442 — the zenoh SELECTOR-PARAMETER dialect, as ONE definition for every
//! wz crate that reads or writes a selector.
//!
//! A selector's parameter list is `;`-separated with `=` between key and value
//! (`LIST_SEPARATOR` / `FIELD_SEPARATOR`,
//! `commons/zenoh-protocol/src/core/parameters.rs:32-33`), and zenoh-pico agrees
//! (`_Z_QUERY_PARAMS_LIST_SEPARATOR ";"`,
//! `vendor/zenoh-pico/include/zenoh-pico/utils/query_params.h:34`).
//!
//! ## Why this lives in the shared crate and not next to one consumer
//!
//! The defect R311y442 fixed was not "one function used the wrong character". It
//! was that the dialect had NO definition, so each site invented one and they
//! drifted independently — the `@adv` cache split on `&`, the `@adv` subscriber
//! joined on `&`, and neither could see the other was wrong because they agreed
//! with each other. The first fix put a definition next to the `@adv` code, which
//! left the SAME bug live one crate away in the REST bridge
//! (`wz-rest/src/bridge.rs`, found in review). A per-consumer SSOT is not an SSOT;
//! this module is the crate both consumers already depend on.
//!
//! `wz-capi-pico` keeps its own byte-level spellings (`PARAM_SEPARATOR: u8`,
//! `ANYKE_PARAM: &[u8]`, `wz-capi-pico/src/query.rs:114-118`) because its whole
//! surface is `&[u8]` at an FFI boundary rather than `&str`, and it does not
//! depend on this crate. Those were already CORRECT — the C-API path is where the
//! right spelling survived while the runtime path lost it.
//!
//! ## `_anyke`
//!
//! An advanced cache replies under the CACHED SAMPLE's own keyexpr, which does not
//! intersect the `@adv` keyexpr the GET is addressed to. zenoh's responder refuses
//! such a reply unless the querier opted in: `Query::_reply_sample` bails unless
//! `_accepts_any_replies()` (`zenoh/src/api/queryable.rs:278-287`), and that is
//! exactly the presence of this token (`Parameters::reply_key_expr_any`,
//! `zenoh/src/api/selector.rs:191-194`).
//!
//! `_anyke` is an opt-OUT of the RESPONDER's guard, not a licence to accept
//! anything: upstream pairs it with a local `key_expr.intersects(reply.key_expr())`
//! in every one of its GET callbacks. A caller that emits the token owes that
//! filter — see `wz-runtime-tokio::advanced_subscriber::issue_recovery_get`.

use alloc::string::String;

/// The parameter-list separator (zenoh `LIST_SEPARATOR`; pico
/// `_Z_QUERY_PARAMS_LIST_SEPARATOR`).
pub const PARAM_LIST_SEPARATOR: char = ';';

/// The key/value separator (zenoh `FIELD_SEPARATOR`, `parameters.rs:33`).
pub const PARAM_FIELD_SEPARATOR: char = '=';

/// The reply-keyexpr-any token (zenoh `REPLY_KEY_EXPR_ANY_SEL_PARAM`,
/// `zenoh/src/api/selector.rs:144`; pico `_Z_QUERY_PARAMS_KEY_ANYKE`,
/// `query_params.h:31`). Carried as a BARE token: `set_reply_key_expr_any`
/// inserts an EMPTY value (`selector.rs:179-181`) and a valueless entry renders
/// as the key alone — see zenoh's own round-trip expectation
/// `"_anyke;_filter;_time=[now(-2s)..now(2s)];_timetrick"` (`selector.rs:381`).
pub const ANYKE_PARAM: &str = "_anyke";

/// Trim the trailing separators zenoh strips when a receiver builds its
/// `Parameters` from an owned string (`trim_end_matches` over
/// `;` / `=` / `|`, `parameters.rs:359-366`; the queryable side goes through that
/// owned path, `zenoh/src/api/session.rs:2441`).
///
/// Without it `_max=5|` reads as the value `5|`, which fails to parse and drops
/// the cap — silently, and in the over-return direction.
fn trim_trailing(params: &str) -> &str {
    params.trim_end_matches([PARAM_LIST_SEPARATOR, PARAM_FIELD_SEPARATOR, '|'])
}

/// Whether `key` is present at all, with or without a value.
///
/// This is zenoh's `contains_key`, and it is the ONLY correct way to read a
/// valueless flag such as [`ANYKE_PARAM`]: upstream's split yields `(key, "")`
/// for a segment with no `=` (`parameters.rs:36-44`), so a flag IS a key with an
/// empty value rather than a segment with no key.
pub fn has_param(params: &str, key: &str) -> bool {
    trim_trailing(params)
        .split(PARAM_LIST_SEPARATOR)
        .filter(|p| !p.is_empty())
        .any(|kv| split_kv(kv).0 == key)
}

/// The value bound to `key`, or `None` when the key is absent.
///
/// A valueless key yields `Some("")`, matching zenoh's `get`
/// (`parameters.rs:36-51`) rather than the "no `=` means no key" reading — that
/// difference is invisible for `_sn` / `_max` / `_time` (an empty value fails
/// their parses exactly as a missing key does) but it is the semantic every
/// future reader inherits, and it is what makes [`has_param`] expressible.
/// First occurrence wins, as upstream's `find` does.
pub fn param_value<'a>(params: &'a str, key: &str) -> Option<&'a str> {
    trim_trailing(params)
        .split(PARAM_LIST_SEPARATOR)
        .filter(|p| !p.is_empty())
        .map(split_kv)
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

/// zenoh's `split_once`: everything before the first `=` is the key, everything
/// after is the value, and NO `=` means an empty value (`parameters.rs:36-44`).
fn split_kv(kv: &str) -> (&str, &str) {
    match kv.split_once(PARAM_FIELD_SEPARATOR) {
        Some((k, v)) => (k, v),
        None => (kv, ""),
    }
}

/// Join `parts` (each already `key=value`) into a parameter list.
pub fn join_params(parts: &[String]) -> String {
    let mut out = String::new();
    for part in parts {
        if !out.is_empty() {
            out.push(PARAM_LIST_SEPARATOR);
        }
        out.push_str(part);
    }
    out
}

/// [`join_params`] plus the bare [`ANYKE_PARAM`] flag: the selector shape every
/// GET into the `@adv` namespace needs, since all of them are answered under a
/// cached sample's own keyexpr. An empty `parts` yields the bare flag.
pub fn anyke_params(parts: &[String]) -> String {
    let mut out = join_params(parts);
    if !out.is_empty() {
        out.push(PARAM_LIST_SEPARATOR);
    }
    out.push_str(ANYKE_PARAM);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    /// The multi-parameter case the `&` dialect got wrong: under `&` the FIRST
    /// key parses with a corrupted value and every later key is invisible.
    #[test]
    fn reads_the_upstream_semicolon_list() {
        let s = "_max=5;_time=[now(-10s)..];_anyke";
        assert_eq!(param_value(s, "_max"), Some("5"));
        assert_eq!(param_value(s, "_time"), Some("[now(-10s)..]"));
        assert_eq!(param_value(s, "_sn"), None);
    }

    /// A lone parameter is separator-independent, which is why the `&` bug
    /// survived: the recovery GET carries only `_sn`.
    #[test]
    fn reads_a_lone_parameter() {
        assert_eq!(param_value("_sn=7..12", "_sn"), Some("7..12"));
    }

    /// R311y442 review (REVIEWER 1, finding 4) — a valueless key is a key with an
    /// EMPTY value, not an absent key. The earlier reading returned `None` here
    /// and its doc asserted that was correct; it is upstream's model inverted,
    /// and it made the flag unreadable through the value accessor.
    #[test]
    fn a_valueless_key_has_an_empty_value_not_no_value() {
        assert_eq!(param_value("_anyke", "_anyke"), Some(""));
        assert_eq!(param_value("_max=3;_anyke", "_anyke"), Some(""));
        assert_eq!(param_value("_max=3;_anyke", "_max"), Some("3"));
        assert!(has_param("_max=3;_anyke", "_anyke"));
        assert!(!has_param("_max=3", "_anyke"));
        // The substring traps a naive `contains` would fall into.
        assert!(!has_param("no_anyke;x=1", "_anyke"));
        assert!(!has_param("_anykey=1", "_anyke"));
    }

    /// R311y442 review (REVIEWER 1, finding 5) — zenoh trims trailing `;`/`=`/`|`
    /// when a receiver builds Parameters from an owned string. Without the trim
    /// `_max=5|` reads as `5|`, fails to parse, and drops the cap.
    #[test]
    fn trailing_separators_are_trimmed_like_upstream() {
        assert_eq!(param_value("_max=5|", "_max"), Some("5"));
        assert_eq!(param_value("_max=5=", "_max"), Some("5"));
        assert_eq!(param_value("_max=5;", "_max"), Some("5"));
        assert_eq!(param_value("_max=5;;", "_max"), Some("5"));
    }

    /// A value may itself contain `=`; only the FIRST one splits.
    #[test]
    fn only_the_first_field_separator_splits() {
        assert_eq!(param_value("_p=x=y;_q=1", "_p"), Some("x=y"));
        assert_eq!(param_value("_p=x=y;_q=1", "_q"), Some("1"));
    }

    /// First occurrence wins, as upstream's `find` does.
    #[test]
    fn duplicate_keys_take_the_first() {
        assert_eq!(param_value("_max=1;_max=2", "_max"), Some("1"));
    }

    #[test]
    fn builds_the_upstream_shapes() {
        assert_eq!(join_params(&[]), "");
        assert_eq!(anyke_params(&[]), ANYKE_PARAM);
        assert_eq!(anyke_params(&["_sn=7..".to_string()]), "_sn=7..;_anyke");
        assert_eq!(
            anyke_params(&["_max=5".to_string(), "_time=[now(-3s)..]".to_string()]),
            "_max=5;_time=[now(-3s)..];_anyke"
        );
    }

    /// Round-trip: what a querier BUILDS is what a responder READS. The two sides
    /// drifted apart precisely because nothing tied them together.
    #[test]
    fn built_params_parse_back() {
        let built = anyke_params(&["_max=5".to_string(), "_time=[now(-3s)..]".to_string()]);
        assert_eq!(param_value(&built, "_max"), Some("5"));
        assert_eq!(param_value(&built, "_time"), Some("[now(-3s)..]"));
        assert!(has_param(&built, ANYKE_PARAM));
    }
}
