// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The verdicts on a TEXT somebody typed: a declaration block, and one key
//! expression.
//!
//! Rendered HERE and not in the ABI crate, on the rule
//! [`crate::filter::diagnose_json`] states for the selector verdict: the value
//! families these documents declare are held to their walks by a gate in this
//! crate, and an emitter in another crate is one that gate cannot render, so the
//! verdict it checks would be a claim with no measurement behind it.
//!
//! ## One judgement behind two doors
//!
//! A key expression reaches the library through three doors: a declaration line
//! (`<keyexpr>=<format>`), `wz_dissect_keyexpr_diagnose`, and the C drop-in's
//! `z_view_keyexpr_from_str`. They used to be three opinions, and a consumer
//! building a pattern editor on the first was told a pattern was fine that the
//! last refuses. All three ask
//! [`wz_session_core::keyexpr_canon::validate_keyexpr`] now, and the two
//! documents below write its answer through one function
//! (`push_refusal`), so `chunk`, `offset` and `reason` are one spelling.

use alloc::format;
use alloc::string::{String, ToString};

#[cfg(feature = "keyexpr-relation")]
use crate::doc_revision::KEYEXPR_RELATE;
use crate::doc_revision::{
    envelope_into, DECLARATIONS_DIAGNOSE, DECLARATIONS_MATCH, KEYEXPR_DIAGNOSE,
};
use crate::payload::formats::FormatMap;
use wz_session_core::json::escape_into;
use wz_session_core::keyexpr_canon::{validate_keyexpr, KeyexprRefusal};

/// The verdict `wz_dissect_declarations_diagnose` hands back.
///
/// `{envelope,"ok":true,"installed":N,"lines":[…]}`, or
/// `{envelope,"ok":false,"line":N,"text":"…","message":"…"}` with, when the
/// line's KEY is not a key expression, `"pattern"`, `"chunk"`, `"offset"` and
/// `"reason"` after the message. `line` counts every line of `declarations`
/// from 0, blank ones included.
///
/// Each entry of `lines` is `{"line":N,"kind":"…"}` plus `"pattern"` (the key as
/// READ, quotes removed) for the two kinds that have a key and `"rule_index"`
/// for a format rule. See [`crate::doc_revision`] for the revision this is.
pub fn declarations_diagnose_json(declarations: &str) -> String {
    let mut out = String::from("{");
    envelope_into(DECLARATIONS_DIAGNOSE, &mut out);
    let mut map = FormatMap::new();
    match map.declare_all_described(declarations) {
        Ok(read) => {
            out.push_str(&format!(
                ",\"ok\":true,\"installed\":{},\"lines\":[",
                read.len()
            ));
            for (i, (line, declared)) in read.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&format!(
                    "{{\"line\":{line},\"kind\":\"{}\"",
                    declared.kind.word()
                ));
                if let Some(pattern) = &declared.pattern {
                    out.push_str(",\"pattern\":");
                    escape_into(pattern, &mut out);
                }
                if let Some(index) = declared.rule_index {
                    out.push_str(&format!(",\"rule_index\":{index}"));
                }
                out.push('}');
            }
            out.push_str("]}");
        }
        Err(bad) => {
            out.push_str(",\"ok\":false");
            push_declaration_refusal(&bad, &mut out);
            out.push('}');
        }
    }
    out
}

/// The keys of a refused declaration text, after `"ok":false`: `line`, `text`,
/// `message`, and, when the line's KEY is not a key expression, `pattern`,
/// `chunk`, `offset` and `reason`.
///
/// Written once for the two documents that carry a declaration's refusal
/// (`declarations_diagnose` and `declarations_match`), so a consumer that holds
/// both reads one spelling.
fn push_declaration_refusal(bad: &crate::payload::formats::DeclarationError, out: &mut String) {
    out.push_str(&format!(",\"line\":{}", bad.line));
    out.push_str(",\"text\":");
    // The SAME escaper the rest of this ABI's documents use: the line is
    // the operator's own text, quoted back so a UI can point at it
    // without holding the input a second time.
    escape_into(&bad.text, out);
    out.push_str(",\"message\":");
    escape_into(&bad.error.to_string(), out);
    // A key that is not a key expression says where, from the same
    // refusal `keyexpr_diagnose_json` writes. Any other refusal carries
    // none of these four keys.
    if let Some((pattern, refusal)) = bad.error.keyexpr_refusal() {
        out.push_str(",\"pattern\":");
        escape_into(pattern, out);
        push_refusal(refusal, out);
    }
}

/// The verdict `wz_dissect_keyexpr_diagnose` hands back.
///
/// `{envelope,"ok":true}`, or
/// `{envelope,"ok":false,"chunk":N,"offset":N,"reason":"…","message":"…"}`: the
/// first place `keyexpr` stops being a key expression, `chunk` counted from 0
/// and `offset` in BYTES.
pub fn keyexpr_diagnose_json(keyexpr: &str) -> String {
    let mut out = String::from("{");
    envelope_into(KEYEXPR_DIAGNOSE, &mut out);
    match validate_keyexpr(keyexpr) {
        Ok(()) => out.push_str(",\"ok\":true"),
        Err(refusal) => {
            out.push_str(",\"ok\":false");
            push_refusal(&refusal, &mut out);
            out.push_str(",\"message\":");
            escape_into(&refusal.to_string(), &mut out);
        }
    }
    out.push('}');
    out
}

/// The two sides of [`keyexpr_relate_json`], the words of its `which`.
pub const RELATE_SIDES: [&str; 2] = ["a", "b"];

/// The relation of two key expressions, which set one covers of the other, WITHOUT
/// a capture and without a declaration line: the verdict `wz_dissect_keyexpr_relate`
/// hands back.
///
/// `{envelope,"ok":true,"includes":B,"intersects":B}`: `includes` is true when `a`
/// includes `b`, that is every key `b` matches is also matched by `a`, so
/// `demo/**` includes `demo/a` and `demo/a` does not include `demo/**`.
/// `intersects` is true when some key is matched by both, and it is symmetric.
/// What `a` includes it also intersects, so `includes` is never true beside a
/// false `intersects`.
///
/// A refusal is `{envelope,"ok":false,"which":"a"|"b",chunk,offset,reason,
/// "message"}`: the first of the two texts, `a` before `b`, that is not a key
/// expression, in the words `keyexpr_diagnose_json` gives. Both texts are judged
/// by the one validator before either relation is asked, so the relation is only
/// ever computed over keys that are canonical, which is what the matcher
/// assumes.
///
/// The two relations are the engines the C drop-in's `z_keyexpr_includes` and
/// `z_keyexpr_intersects` ask, over the chunks of each text, so this door, the
/// drop-in and a router's own matching cannot differ about an overlap.
#[cfg(feature = "keyexpr-relation")]
pub fn keyexpr_relate_json(a: &str, b: &str) -> String {
    use alloc::vec::Vec;
    use wz_session_core::keyexpr_match::{keyexpr_includes_patterns, keyexpr_intersect_patterns};

    let mut out = String::from("{");
    envelope_into(KEYEXPR_RELATE, &mut out);
    for (side, text) in [("a", a), ("b", b)] {
        if let Err(refusal) = validate_keyexpr(text) {
            out.push_str(&format!(",\"ok\":false,\"which\":\"{side}\""));
            push_refusal(&refusal, &mut out);
            out.push_str(",\"message\":");
            escape_into(&refusal.to_string(), &mut out);
            out.push('}');
            return out;
        }
    }
    let a_chunks: Vec<&str> = a.split('/').collect();
    let b_chunks: Vec<&str> = b.split('/').collect();
    out.push_str(&format!(
        ",\"ok\":true,\"includes\":{},\"intersects\":{}}}",
        keyexpr_includes_patterns(&a_chunks, &b_chunks),
        keyexpr_intersect_patterns(&a_chunks, &b_chunks)
    ));
    out
}

/// The words of the `which` of [`declarations_match_json`]'s refusal.
pub const MATCH_REFUSALS: [&str; 2] = ["declarations", "keyexpr"];

/// Which format rule of a declaration text covers a key, by the decoder's own
/// judgement: the verdict `wz_dissect_declarations_match` hands back.
///
/// `{envelope,"ok":true,"covered":false}` when no rule covers `keyexpr`, or
/// `{envelope,"ok":true,"covered":true,"matched":{"index":N,"pattern":"…",
/// "format":"…","schema":S}}`: the FIRST format rule, in the order they are
/// tried, that covers the key, which is the rule a field row reports as
/// `matched_rule` and the one whose format decodes the payload. `matched` is
/// written only beside `"covered":true`: no top-level key of a document is ever
/// `null`, because a top-level `null` is how a plane absent from a build reads,
/// and "no rule covers this key" is an answer. `index` counts the format rules from 0 (it is the `rule_index` a
/// `declarations_diagnose` line carries), `pattern` is the rule's key expression
/// as read, `format` the name of the decoder or the described format or the
/// end-to-end profile it points at, and `schema` the body schema an
/// end-to-end rule names, or `null` for every other rule and for an end-to-end
/// rule that names none.
///
/// The answer comes from [`FormatMap::matching_rule`], the function the capture's
/// decode asks for every sample, so a consumer that picks a mapping with this
/// and one that decodes a capture cannot disagree about an overlap.
///
/// The key is a LITERAL key: it must be a key expression and must carry no
/// wildcard, because the decoder is asked about the key a sample was published
/// on. A key with a `*` is refused rather than matched as a pattern, which would
/// answer a different question.
///
/// A refusal is `{envelope,"ok":false,"which":W,…}`. `declarations`: the text
/// does not install, and the keys are the ones `declarations_diagnose` writes for
/// the same refusal (`line`, `text`, `message`, and for a refused key `pattern`,
/// `chunk`, `offset`, `reason`). `keyexpr`: `message`, `chunk` and `offset`, and
/// `reason` when the key is not a key expression at all (the words of
/// `keyexpr_diagnose`); a key that is one but carries a wildcard has no `reason`,
/// and its `chunk` and `offset` point at the first `*`.
pub fn declarations_match_json(declarations: &str, keyexpr: &str) -> String {
    let mut out = String::from("{");
    envelope_into(DECLARATIONS_MATCH, &mut out);
    let mut map = FormatMap::new();
    if let Err(bad) = map.declare_all_described(declarations) {
        out.push_str(",\"ok\":false,\"which\":\"declarations\"");
        push_declaration_refusal(&bad, &mut out);
        out.push('}');
        return out;
    }
    if let Err(refusal) = validate_keyexpr(keyexpr) {
        out.push_str(",\"ok\":false,\"which\":\"keyexpr\"");
        push_refusal(&refusal, &mut out);
        out.push_str(",\"message\":");
        escape_into(&refusal.to_string(), &mut out);
        out.push('}');
        return out;
    }
    if let Some(offset) = keyexpr.find('*') {
        let chunk = keyexpr[..offset].matches('/').count();
        out.push_str(&format!(
            ",\"ok\":false,\"which\":\"keyexpr\",\"chunk\":{chunk},\"offset\":{offset},\
             \"message\":"
        ));
        escape_into(
            &format!(
                "`{keyexpr}` carries a wildcard at byte {offset}: a rule is matched against \
                 the key a sample was published on, which is a literal key"
            ),
            &mut out,
        );
        out.push('}');
        return out;
    }
    match map.matching_rule(keyexpr) {
        None => out.push_str(",\"ok\":true,\"covered\":false"),
        Some(found) => {
            out.push_str(",\"ok\":true,\"covered\":true,\"matched\":");
            out.push_str(&format!("{{\"index\":{},\"pattern\":", found.rule.index));
            escape_into(&found.rule.pattern, &mut out);
            out.push_str(",\"format\":");
            escape_into(found.format.name(), &mut out);
            out.push_str(",\"schema\":");
            match map.e2e_for_keyexpr(keyexpr).and_then(|m| m.format.schema()) {
                Some(schema) => escape_into(schema, &mut out),
                None => out.push_str("null"),
            }
            out.push('}');
        }
    }
    out.push('}');
    out
}

/// The `chunk`, `offset` and `reason` keys of a refused key expression, written
/// once for the two documents that carry them.
///
/// The declaration verdict and the key-expression verdict both name the first
/// place a text stops being a key expression, and a consumer joins them by
/// equality; the invariant that was broken was one door accepting what the
/// other refuses. One writer is what keeps the two spellings from drifting.
fn push_refusal(refusal: &KeyexprRefusal, out: &mut String) {
    out.push_str(&format!(
        ",\"chunk\":{},\"offset\":{},\"reason\":\"{}\"",
        refusal.chunk,
        refusal.offset,
        refusal.fault.word()
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc_revision::object_scopes;
    use alloc::vec::Vec;

    /// The raw value of `key` in the document's own (outermost) object.
    fn top<'a>(doc: &'a str, key: &str) -> Option<&'a str> {
        object_scopes(doc)
            .into_iter()
            .next()?
            .into_iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v)
    }

    /// The fifteen patterns a consumer put to the declaration door and to the C
    /// drop-in, which disagreed on six of them.
    const FIFTEEN: [&str; 15] = [
        "demo//pose",
        "a?b",
        "**x",
        "/demo",
        "demo/",
        "demo/**",
        "demo/*/pose",
        "demo/robots/1/pose",
        "demo/$*/pose",
        "demo/**/**",
        "a/**/b/**",
        "a/*/**",
        "**/a",
        "a$*b",
        "a*b",
    ];

    /// THE INVARIANT THAT WAS BROKEN: one door accepted what the other refused.
    ///
    /// Every pattern is put to the key-expression door and, as `pattern=format`,
    /// to the declaration door, and the two must agree on the verdict AND on the
    /// place: `chunk`, `offset` and `reason` byte for byte. The population is the
    /// consumer's own fifteen, six of which the declaration door used to accept
    /// while the drop-in's constructor refuses them.
    ///
    /// `filter-wildcards`, because without it the declaration door answers a
    /// wildcard pattern with a different refusal (it has no matcher for it) and
    /// the two doors are not asking the same question.
    #[cfg(feature = "filter-wildcards")]
    #[test]
    fn a_key_expression_gets_the_same_verdict_from_both_doors() {
        let mut refused = 0usize;
        for pattern in FIFTEEN {
            let direct = keyexpr_diagnose_json(pattern);
            let line = declarations_diagnose_json(&format!("{pattern}=protobuf"));
            let ok = top(&direct, "ok").expect("ok");
            assert_eq!(
                top(&line, "ok"),
                Some(ok),
                "{pattern:?}: the doors disagree about whether it is a key expression\n\
                 {direct}\n{line}"
            );
            if ok == "false" {
                refused += 1;
                for key in ["chunk", "offset", "reason"] {
                    assert_eq!(
                        top(&line, key),
                        top(&direct, key),
                        "{pattern:?}: the doors disagree about `{key}`\n{direct}\n{line}"
                    );
                }
                // The declaration door also quotes the key back as read.
                let shown = format!("{pattern:?}");
                assert_eq!(top(&line, "pattern"), Some(shown.as_str()), "{line}");
            }
        }
        // Eight of the fifteen are refused, and a comparison over zero refusals
        // would pass for the wrong reason.
        assert_eq!(refused, 8, "{refused} of the fifteen were refused");
    }

    /// The verdicts themselves, so the agreement above is not two doors agreeing
    /// on the same wrong answer: upstream accepts `a$*b`, `a/*/**`, `**/a` and
    /// `a/**/b/**`, and refuses the rest of the eight.
    #[test]
    fn the_key_expression_door_gives_upstreams_verdict_on_the_fifteen() {
        let accepted: Vec<&str> = FIFTEEN
            .iter()
            .copied()
            .filter(|p| top(&keyexpr_diagnose_json(p), "ok") == Some("true"))
            .collect();
        assert_eq!(
            accepted,
            [
                "demo/**",
                "demo/*/pose",
                "demo/robots/1/pose",
                "a/**/b/**",
                "a/*/**",
                "**/a",
                "a$*b"
            ]
        );
        let verdict = keyexpr_diagnose_json("demo//pose");
        assert_eq!(top(&verdict, "chunk"), Some("1"), "{verdict}");
        assert_eq!(top(&verdict, "offset"), Some("5"), "{verdict}");
        assert_eq!(
            top(&verdict, "reason"),
            Some("\"empty_chunk\""),
            "{verdict}"
        );
        assert!(
            verdict.starts_with("{\"document\":{\"name\":\"keyexpr_diagnose\",\"revision\":1}"),
            "{verdict}"
        );
    }

    /// THE QUOTING HOLE: `a\=b=protobuf`, `a\:b=protobuf` and `a:b=protobuf`
    /// all reported `installed: 1` and none said which kind it was.
    #[test]
    fn a_line_says_which_kind_it_was_read_as() {
        let kind_and_pattern = |line: &str| {
            let doc = declarations_diagnose_json(line);
            assert_eq!(top(&doc, "ok"), Some("true"), "{line}: {doc}");
            let lines = top(&doc, "lines").expect("lines");
            let entry = object_scopes(lines).into_iter().next().expect("one line");
            let get = |k: &str| {
                entry
                    .iter()
                    .find(|(key, _)| *key == k)
                    .map(|(_, v)| String::from(*v))
            };
            (get("kind"), get("pattern"), get("rule_index"))
        };
        // A rule about the key `a=b`, the `=` quoted.
        assert_eq!(
            kind_and_pattern("a\\=b=protobuf"),
            (
                Some(String::from("\"format_rule\"")),
                Some(String::from("\"a=b\"")),
                Some(String::from("0"))
            )
        );
        // A rule about the key `a:b`, the `:` quoted.
        assert_eq!(
            kind_and_pattern("a\\:b=protobuf"),
            (
                Some(String::from("\"format_rule\"")),
                Some(String::from("\"a:b\"")),
                Some(String::from("0"))
            )
        );
        // The same characters with the colon BARE: a name for path `b` under `a`.
        assert_eq!(
            kind_and_pattern("a:b=protobuf"),
            (
                Some(String::from("\"field_name\"")),
                Some(String::from("\"a\"")),
                None
            )
        );
        assert_eq!(
            kind_and_pattern("#profile=a:u8"),
            (Some(String::from("\"format_definition\"")), None, None)
        );
    }

    /// `rule_index` counts the FORMAT RULES, from 0, in the order of the text,
    /// whatever else sits between them.
    #[test]
    fn a_rules_index_counts_rules_and_nothing_between_them() {
        let doc = declarations_diagnose_json(
            "demo/a=protobuf\n\ndemo/a:1=name\n#profile=a:u8\ndemo/b=profile\ndemo/c=json",
        );
        assert_eq!(top(&doc, "installed"), Some("5"), "{doc}");
        let lines = top(&doc, "lines").expect("lines");
        let seen: Vec<(&str, Option<&str>)> = object_scopes(lines)
            .into_iter()
            .map(|entry| {
                let get = |k: &str| entry.iter().find(|(key, _)| *key == k).map(|(_, v)| *v);
                (get("line").expect("line"), get("rule_index"))
            })
            .collect();
        // Line 1 is blank and is skipped, but counted: the numbers index the text.
        assert_eq!(
            seen,
            [
                ("0", Some("0")),
                ("2", None),
                ("3", None),
                ("4", Some("1")),
                ("5", Some("2")),
            ]
        );
    }

    /// An unquoted `:` or `=` in a KEY is refused by name, and quoting it makes
    /// the same key install.
    #[test]
    fn a_key_with_a_bare_separator_is_refused_and_quoting_it_installs() {
        for (line, separator, offset) in [("a:b:c=x", ':', 1), ("a=b=protobuf", '=', 1)] {
            let doc = declarations_diagnose_json(line);
            assert_eq!(top(&doc, "ok"), Some("false"), "{line}: {doc}");
            let message = top(&doc, "message").expect("message");
            assert!(
                message.contains(&format!("`{separator}` at byte {offset}")),
                "{line}: {message}"
            );
            // Not a key-expression refusal, so none of its four keys.
            assert_eq!(top(&doc, "reason"), None, "{doc}");
        }
        for line in ["a\\:b:c=x", "a\\=b=protobuf"] {
            let doc = declarations_diagnose_json(line);
            assert_eq!(top(&doc, "ok"), Some("true"), "{line}: {doc}");
        }
    }

    /// A refusal that is not about a key carries none of the four keys, and the
    /// line index still counts the text.
    #[test]
    fn a_refusal_that_is_not_about_a_key_names_the_line_and_nothing_more() {
        let doc = declarations_diagnose_json("demo/a=protobuf\nnot a declaration");
        assert_eq!(top(&doc, "ok"), Some("false"), "{doc}");
        assert_eq!(top(&doc, "line"), Some("1"), "{doc}");
        for key in ["pattern", "chunk", "offset", "reason"] {
            assert_eq!(top(&doc, key), None, "{key}: {doc}");
        }
    }

    /// The relation of `a` to `b` as `(includes, intersects)`, from the document.
    #[cfg(feature = "keyexpr-relation")]
    fn related(a: &str, b: &str) -> (bool, bool) {
        let doc = keyexpr_relate_json(a, b);
        assert_eq!(top(&doc, "ok"), Some("true"), "{a} {b}: {doc}");
        let bit = |key: &str| match top(&doc, key) {
            Some("true") => true,
            Some("false") => false,
            other => panic!("{key} is {other:?} in {doc}"),
        };
        (bit("includes"), bit("intersects"))
    }

    /// THE RELATION, in the direction it is asked: `includes` is about `a`
    /// holding `b` and not the other way, and `intersects` is symmetric. Every
    /// row is also asked with the arguments swapped, so a relation that swapped
    /// them, or read `includes` off the wrong engine, fails on the pair where
    /// the two directions differ.
    #[cfg(feature = "keyexpr-relation")]
    #[test]
    fn a_key_expression_relates_to_another_in_the_direction_it_is_asked() {
        // (a, b, a includes b, b includes a, they intersect)
        let rows = [
            ("demo/**", "demo/a", true, false, true),
            ("demo/*", "demo/a", true, false, true),
            ("demo/a", "demo/a", true, true, true),
            ("demo/a", "demo/b", false, false, false),
            ("demo/*", "demo/a/b", false, false, false),
            ("demo/**", "demo/*/x", true, false, true),
            ("**", "demo/a", true, false, true),
            ("demo/a$*", "demo/abc", true, false, true),
            ("demo/*/x", "demo/y/*", false, false, true),
        ];
        let mut asymmetric = 0usize;
        for (a, b, a_has_b, b_has_a, meet) in rows {
            assert_eq!(related(a, b), (a_has_b, meet), "{a} against {b}");
            assert_eq!(related(b, a), (b_has_a, meet), "{b} against {a}");
            if a_has_b != b_has_a {
                asymmetric += 1;
            }
        }
        // Five of the nine are not symmetric in `includes`; a table of nothing but
        // symmetric pairs would pass a swapped argument order.
        assert_eq!(asymmetric, 5);
    }

    /// A REFUSAL NAMES THE TEXT, `a` before `b`, and goes through the one
    /// validator, so its place is the key-expression door's own.
    #[cfg(feature = "keyexpr-relation")]
    #[test]
    fn a_refused_text_is_named_and_a_comes_before_b() {
        let doc = keyexpr_relate_json("demo//a", "demo/b");
        assert_eq!(top(&doc, "ok"), Some("false"), "{doc}");
        assert_eq!(top(&doc, "which"), Some("\"a\""), "{doc}");
        let alone = keyexpr_diagnose_json("demo//a");
        for key in ["chunk", "offset", "reason", "message"] {
            assert_eq!(top(&doc, key), top(&alone, key), "{key}: {doc}");
        }
        let doc = keyexpr_relate_json("demo/a", "a?b");
        assert_eq!(top(&doc, "which"), Some("\"b\""), "{doc}");
        assert_eq!(top(&doc, "reason"), Some("\"sharp_or_question_mark\""));
        // Both refused: the first is the one reported.
        let doc = keyexpr_relate_json("a?b", "demo//a");
        assert_eq!(top(&doc, "which"), Some("\"a\""), "{doc}");
        // No relation is written beside a refusal.
        for key in ["includes", "intersects"] {
            assert_eq!(top(&doc, key), None, "{key}: {doc}");
        }
    }

    /// The match answered as `(index, pattern, format, schema)`, or `None`.
    fn matched(declarations: &str, key: &str) -> Option<(String, String, String, String)> {
        let doc = declarations_match_json(declarations, key);
        assert_eq!(
            top(&doc, "ok"),
            Some("true"),
            "{declarations:?} {key}: {doc}"
        );
        let covered = top(&doc, "covered").expect("covered");
        if covered == "false" {
            assert_eq!(top(&doc, "matched"), None, "{doc}");
            return None;
        }
        assert_eq!(covered, "true", "{doc}");
        let found = top(&doc, "matched").expect("matched");
        let entry = object_scopes(found).into_iter().next().expect("an object");
        let get = |k: &str| {
            entry
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| String::from(*v))
                .unwrap_or_else(|| panic!("no {k} in {found}"))
        };
        Some((get("index"), get("pattern"), get("format"), get("schema")))
    }

    /// THE FIRST RULE THAT COVERS THE KEY WINS, in the order they are written,
    /// whichever is the more specific: that is the decoder's rule, and a consumer
    /// that asked "longest pattern" would pick a different mapping on an overlap.
    /// The same text with its two rules swapped must give the other answer.
    ///
    /// `filter-wildcards`, because the general rule is a wildcard pattern and a
    /// build without the matcher refuses that text before any key is judged
    /// (the twin below asserts that refusal in the build that has it).
    #[cfg(feature = "filter-wildcards")]
    #[test]
    fn the_first_covering_rule_wins_and_swapping_the_rules_swaps_the_answer() {
        let general_first = "demo/**=protobuf\ndemo/a=json";
        let specific_first = "demo/a=json\ndemo/**=protobuf";
        let want = |index: &str, pattern: &str, format: &str| {
            Some((
                String::from(index),
                format!("{pattern:?}"),
                format!("{format:?}"),
                String::from("null"),
            ))
        };
        assert_eq!(
            matched(general_first, "demo/a"),
            want("0", "demo/**", "protobuf")
        );
        assert_eq!(
            matched(specific_first, "demo/a"),
            want("0", "demo/a", "json")
        );
        // A key only the general rule covers is the general rule in both.
        assert_eq!(
            matched(general_first, "demo/b"),
            want("0", "demo/**", "protobuf")
        );
        assert_eq!(
            matched(specific_first, "demo/b"),
            want("1", "demo/**", "protobuf")
        );
    }

    /// `index` counts the FORMAT RULES: a name or a definition between two rules
    /// does not move it, which is the `rule_index` the declaration verdict gives.
    #[test]
    fn the_index_is_the_rule_index_the_declaration_verdict_reports() {
        let text = "demo/a=protobuf\ndemo/a:1=name\n#profile=a:u8\ndemo/b=profile\ndemo/c=json";
        let (index, ..) = matched(text, "demo/c").expect("covered");
        assert_eq!(index, "2");
        let verdict = declarations_diagnose_json(text);
        let lines = top(&verdict, "lines").expect("lines");
        let last_rule: Vec<&str> = object_scopes(lines)
            .into_iter()
            .filter_map(|e| e.iter().find(|(k, _)| *k == "rule_index").map(|(_, v)| *v))
            .collect();
        assert_eq!(last_rule, ["0", "1", "2"], "{verdict}");
    }

    /// No rule covering the key is an answer, not a refusal.
    #[test]
    fn a_key_no_rule_covers_matches_nothing() {
        assert_eq!(matched("demo/a=json", "other/x"), None);
        assert_eq!(matched("", "demo/a"), None);
    }

    /// An end-to-end rule reports the profile as its format and the body schema
    /// the rule names; one that names none reports `null`.
    #[test]
    fn an_end_to_end_rule_reports_its_profile_and_its_body_schema() {
        // One line, as a declaration is: a profile definition and two rules that
        // name it, one with a body schema and one without.
        let text = "#demo-a={\"name\":\"demo-a\",\"fields\":[{\"name\":\"kind\",\"bytes\":1},\
             {\"name\":\"crc\",\"bytes\":2},{\"name\":\"counter\",\"bytes\":1},\
             {\"name\":\"length\",\"bytes\":2}],\
             \"crc\":{\"field\":\"crc\",\"width\":16,\"poly\":\"0x1021\",\"init\":\"0xFFFF\",\
             \"refin\":false,\"refout\":false,\"xorout\":0,\
             \"cover\":[\"kind\",\"@payload\",\"counter\",\"length\"]},\
             \"length\":{\"field\":\"length\",\"counts\":\"frame\"},\
             \"counter\":{\"field\":\"counter\",\"max_gap\":4,\"timeout_ms\":100}}\n\
             demo/p=demo-a@pkg.Pose\ndemo/q=demo-a";
        let (_, _, format, schema) = matched(text, "demo/p").expect("covered");
        assert_eq!(
            (format.as_str(), schema.as_str()),
            ("\"demo-a\"", "\"pkg.Pose\"")
        );
        let (_, _, format, schema) = matched(text, "demo/q").expect("covered");
        assert_eq!((format.as_str(), schema.as_str()), ("\"demo-a\"", "null"));
    }

    /// THE KEY IS A LITERAL KEY. A key with a wildcard is refused and not matched
    /// as a pattern, and a key that is not a key expression says why with the
    /// key-expression door's words. The two have different keys: the wildcard has
    /// no `reason`.
    ///
    /// The declaration text is a LITERAL pattern on purpose: the refusal under
    /// test belongs to the key, and a wildcard pattern would make the text itself
    /// refuse in a build without `filter-wildcards`, which is a different door's
    /// answer and not the one asserted here.
    #[test]
    fn a_wildcard_key_is_refused_and_a_malformed_one_says_why() {
        let wild = declarations_match_json("demo/a=protobuf", "demo/*");
        assert_eq!(top(&wild, "ok"), Some("false"), "{wild}");
        assert_eq!(top(&wild, "which"), Some("\"keyexpr\""), "{wild}");
        assert_eq!(top(&wild, "chunk"), Some("1"), "{wild}");
        assert_eq!(top(&wild, "offset"), Some("5"), "{wild}");
        assert_eq!(top(&wild, "reason"), None, "{wild}");
        assert_eq!(top(&wild, "matched"), None, "{wild}");
        assert_eq!(top(&wild, "covered"), None, "{wild}");

        let bad = declarations_match_json("demo/a=protobuf", "demo//a");
        assert_eq!(top(&bad, "which"), Some("\"keyexpr\""), "{bad}");
        assert_eq!(top(&bad, "reason"), Some("\"empty_chunk\""), "{bad}");
        let alone = keyexpr_diagnose_json("demo//a");
        for key in ["chunk", "offset"] {
            assert_eq!(top(&bad, key), top(&alone, key), "{key}: {bad}");
        }
    }

    /// WITHOUT THE WILDCARD MATCHER a wildcard pattern in the text is refused as a
    /// declaration, whatever the key is, and the answer names the feature that
    /// would make it answerable.
    #[cfg(not(feature = "filter-wildcards"))]
    #[test]
    fn a_wildcard_pattern_is_refused_as_a_declaration_without_the_matcher() {
        let doc = declarations_match_json("demo/**=protobuf", "demo/a");
        assert_eq!(top(&doc, "ok"), Some("false"), "{doc}");
        assert_eq!(top(&doc, "which"), Some("\"declarations\""), "{doc}");
        assert!(doc.contains("filter-wildcards"), "{doc}");
        assert_eq!(top(&doc, "covered"), None, "{doc}");
    }

    /// A DECLARATION TEXT THAT DOES NOT INSTALL is refused with the keys the
    /// declaration verdict writes for the same text, and is judged BEFORE the key.
    #[test]
    fn a_declaration_text_that_does_not_install_is_refused_as_the_declaration_door_does() {
        for text in ["not a declaration", "demo//a=protobuf"] {
            let doc = declarations_match_json(text, "demo/a");
            let diag = declarations_diagnose_json(text);
            assert_eq!(top(&doc, "which"), Some("\"declarations\""), "{doc}");
            for key in [
                "line", "text", "message", "pattern", "chunk", "offset", "reason",
            ] {
                assert_eq!(
                    top(&doc, key),
                    top(&diag, key),
                    "{text:?} {key}\n{doc}\n{diag}"
                );
            }
        }
        // A bad key beside a bad text: the text is the one reported.
        let doc = declarations_match_json("not a declaration", "demo//a");
        assert_eq!(top(&doc, "which"), Some("\"declarations\""), "{doc}");
    }
}
