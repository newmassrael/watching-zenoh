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

use crate::doc_revision::{envelope_into, DECLARATIONS_DIAGNOSE, KEYEXPR_DIAGNOSE};
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
            out.push_str(&format!(",\"ok\":false,\"line\":{}", bad.line));
            out.push_str(",\"text\":");
            // The SAME escaper the rest of this ABI's documents use: the line is
            // the operator's own text, quoted back so a UI can point at it
            // without holding the input a second time.
            escape_into(&bad.text, &mut out);
            out.push_str(",\"message\":");
            escape_into(&bad.error.to_string(), &mut out);
            // A key that is not a key expression says where, from the same
            // refusal `keyexpr_diagnose_json` writes. Any other refusal carries
            // none of these four keys.
            if let Some((pattern, refusal)) = bad.error.keyexpr_refusal() {
                out.push_str(",\"pattern\":");
                escape_into(pattern, &mut out);
                push_refusal(refusal, &mut out);
            }
            out.push('}');
        }
    }
    out
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
}
