// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y842 — the READ direction of [`json`](crate::json), which had only ever
//! emitted.
//!
//! ## Why a parser at all
//!
//! A stock zenoh node is configured by a JSON5 document (`zenohd -c
//! <file>.json5`), and an operator replacing a zenoh node already has that
//! file. Until this module wz could only ever WRITE one
//! (`wz_runtime_tokio::zenoh_config::ZenohNodeConfig::to_json5`), so the
//! config an operator holds was not an input to anything — every wz setting
//! arrived as a bespoke command-line flag. A drop-in that cannot read the
//! deployment's own configuration is not a drop-in.
//!
//! ## Why hand-rolled, and why numbers stay text
//!
//! No `serde_json` / `json5` dependency: this crate is `no_std` + `alloc` and
//! carries its own emitters for the same reason. The consequence that matters
//! is in `Json5Value::Number`, which holds the number's SOURCE TEXT rather
//! than an `f64`. A config carries `batch_size: 65535` and `lease: 10000`, and
//! those are a `u16` and a `u64` at the far end; routing them through a binary
//! float would make the parser the place where an exact integer could be lost,
//! on a target where floats may not exist at all. The consumer parses the text
//! into the type it actually wants, which is also the only place that knows
//! what that type is.
//!
//! ## What "JSON5" means here
//!
//! The subset zenoh's own configs use, which is what the reference file
//! documents: `//` and `/* */` comments, unquoted (identifier) object keys,
//! single-quoted strings, and trailing commas. Everything outside that subset
//! is REFUSED with an offset rather than guessed at — a config parser that
//! silently accepts what it does not understand is how an operator ends up
//! running a node that ignored half its own file.
//!
//! Strict JSON is a subset of JSON5, so this also reads the output of
//! `Json5Value`'s own emitters and of `to_json5`.
//!
//! (Both names above are CODE SPANS rather than intra-doc links, and
//! deliberately: this module is `alloc`-gated, and a link from a cfg-gated
//! module doc to its own item does not resolve under the doc-link budget lane's
//! feature set — measured at 273 -> 275 when they were written as links. The
//! budget is the wrong thing to move; see the pre-push gate's own note.)

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// A parsed JSON5 document node.
///
/// `Object` keeps its entries as an ordered `Vec` rather than a map: a config
/// document's key order is meaningful to a human diffing it against the
/// reference, and a duplicate key is a defect this type can still represent
/// (and [`Json5Value::get`] resolves last-wins, which is what every JSON
/// reader does).
///
/// `Eq` as well as `PartialEq` (R2802): every variant holds text, a bool or
/// more of itself -- `Number` keeps its SOURCE TEXT, not a float -- so the
/// derived equality is already total, and a config type that carries a value
/// (`StorageConfig::volume_cfg`) keeps the `Eq` it had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json5Value {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// A number, held as its SOURCE TEXT — see the module doc. Decimal, hex
    /// (`0x1f`), a leading sign and an exponent all reach the consumer
    /// verbatim.
    Number(String),
    /// A string, with escapes already resolved.
    String(String),
    /// An array.
    Array(Vec<Json5Value>),
    /// An object, in source order.
    Object(Vec<(String, Json5Value)>),
}

/// Why a document could not be read. R2824: defined with the lexer, which has
/// no allocator and is where every error is raised.
pub use crate::json5_lex::Json5Error;
use crate::json5_lex::{Json5Keyword, Json5Str, Lexer};

impl Json5Value {
    /// The value at a `/`-separated leaf path, or `None` if any step is absent
    /// or not an object. `""` addresses the root.
    pub fn get(&self, path: &str) -> Option<&Json5Value> {
        let mut cur = self;
        if path.is_empty() {
            return Some(cur);
        }
        for step in path.split('/') {
            let Json5Value::Object(entries) = cur else {
                return None;
            };
            // Last-wins on a duplicate key, matching every JSON reader.
            cur = entries
                .iter()
                .rev()
                .find(|(k, _)| k == step)
                .map(|(_, v)| v)?;
        }
        Some(cur)
    }

    /// Every LEAF path in this document, in `a/b/c` form, sorted.
    ///
    /// A leaf is anything that is not a non-empty object: a scalar, an array,
    /// and an EMPTY object (which has no leaves under it but is still a thing
    /// the document said). This is the shape a coverage census compares
    /// against an upstream document's own key set.
    ///
    /// The ROOT is never a path, even when it is itself a leaf: `{}` and `5`
    /// both yield NOTHING rather than one empty string. A caller partitioning
    /// these against a known-key set would otherwise have to special-case an
    /// empty document, and the one that did not treated `{}` as an unknown key
    /// (measured, on the first run of the config reader's own tests).
    pub fn leaf_paths(&self) -> Vec<String> {
        let mut out: Vec<String> = self.leaf_entries().into_iter().map(|(p, _)| p).collect();
        out.sort();
        out
    }

    /// Every leaf of this document as `(path, value)`, in DOCUMENT ORDER.
    ///
    /// The same walk [`leaf_paths`](Self::leaf_paths) reports, carrying the
    /// value it found instead of only where it was. That difference is
    /// load-bearing rather than a convenience: a caller holding only the paths
    /// has to look each one back up with [`get`](Self::get), which SPLITS on
    /// `/` — so a leaf whose own key CONTAINS a slash (`{"connect/endpoints":
    /// [...]}`, the flat spelling a C caller's `Z_CONFIG_*` keys are written
    /// in) yields a path that then resolves to nothing. The walk knows the
    /// value; a re-lookup has to guess how the path was spelled, and the two
    /// spellings are indistinguishable once joined.
    ///
    /// Order is the document's, not sorted, because a caller loading these into
    /// a store wants last-wins on a duplicate to mean the same thing it means in
    /// [`get`](Self::get) — the LAST one written.
    pub fn leaf_entries(&self) -> Vec<(String, &Json5Value)> {
        let mut out = Vec::new();
        self.walk_leaves(&mut String::new(), &mut out);
        out
    }

    fn walk_leaves<'a>(&'a self, prefix: &mut String, out: &mut Vec<(String, &'a Json5Value)>) {
        match self {
            Json5Value::Object(entries) if !entries.is_empty() => {
                for (k, v) in entries {
                    let restore = prefix.len();
                    if !prefix.is_empty() {
                        prefix.push('/');
                    }
                    prefix.push_str(k);
                    v.walk_leaves(prefix, out);
                    prefix.truncate(restore);
                }
            }
            _ => {
                if !prefix.is_empty() {
                    out.push((prefix.clone(), self));
                }
            }
        }
    }

    /// This value as JSON5 TEXT — the inverse of [`parse`], and what makes it
    /// one is the property `parse(v.to_json5_text()) == Ok(v)` rather than a
    /// resemblance.
    ///
    /// COMPACT, with no whitespace between tokens, because the caller this
    /// exists for is a machine: a config door handing ONE value back across a C
    /// ABI, which would otherwise have to strip layout it never asked for. The
    /// document a HUMAN reads is `ZenohNodeConfig::to_json5`'s job — it lays
    /// out zenoh's own key order and carries its comments — and the two are
    /// different products rather than two spellings of one.
    ///
    /// Strings and object keys go through [`crate::json::escape_into`], the
    /// workspace's one JSON string escaper, rather than a local `format!`: an
    /// emitter that hand-rolls its escaping is precisely what that module's
    /// header was written to prevent, and a config value can carry any byte a
    /// caller wrote. `Number` is emitted as the SOURCE TEXT it holds, so `0x1f`
    /// comes back as `0x1f` — the parser kept the spelling exactly so a re-emit
    /// would not have to invent one.
    pub fn to_json5_text(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, Numbers::Source);
        out
    }

    /// This value as STRICT JSON (R2804): [`to_json5_text`](Self::to_json5_text)
    /// with every number respelled the way JSON spells it.
    ///
    /// The two differ only in numbers, and only for the spellings JSON5 admits
    /// and JSON does not -- a leading `+`, a hex literal, a bare leading or
    /// trailing `.`, a leading zero. Carried verbatim into a document a JSON
    /// reader parses, one of those makes the whole document unreadable; the
    /// admin plane's storage bodies are such documents, and upstream renders
    /// the same config through `serde_json`, which only ever writes decimal.
    /// So a JSON body takes this, and a caller that hands a value back as JSON5
    /// keeps the source spelling.
    pub fn to_json_text(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, Numbers::Json);
        out
    }

    fn write(&self, out: &mut String, numbers: Numbers) {
        match self {
            Json5Value::Null => out.push_str("null"),
            Json5Value::Bool(true) => out.push_str("true"),
            Json5Value::Bool(false) => out.push_str("false"),
            Json5Value::Number(text) => match numbers {
                Numbers::Source => out.push_str(text),
                Numbers::Json => write_json_number(text, out),
            },
            Json5Value::String(text) => crate::json::escape_into(text, out),
            Json5Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out, numbers);
                }
                out.push(']');
            }
            Json5Value::Object(entries) => {
                out.push('{');
                for (i, (key, value)) in entries.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    crate::json::escape_into(key, out);
                    out.push(':');
                    value.write(out, numbers);
                }
                out.push('}');
            }
        }
    }
}

/// How [`Json5Value::write`] spells a number: as the document wrote it, or as
/// JSON requires.
#[derive(Clone, Copy)]
enum Numbers {
    Source,
    Json,
}

/// A number the parser accepted, respelled as JSON: no `+`, hex as decimal, a
/// `0` before a bare leading `.` and after a bare trailing one, no leading
/// zeros. The value is unchanged in every case -- this moves spelling, never
/// magnitude. A hex literal too wide for 128 bits has no exact JSON integer
/// here, and is written as the JSON STRING of its source text rather than as a
/// number rounded on the way.
fn write_json_number(text: &str, out: &mut String) {
    let (negative, body) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        match u128::from_str_radix(hex, 16) {
            Ok(n) => {
                if negative && n != 0 {
                    out.push('-');
                }
                out.push_str(&n.to_string());
            }
            Err(_) => crate::json::escape_into(text, out),
        }
        return;
    }
    let (mantissa, exponent) = match body.find(['e', 'E']) {
        Some(at) => body.split_at(at),
        None => (body, ""),
    };
    let (int, frac) = match mantissa.split_once('.') {
        Some((int, frac)) => (int, Some(frac)),
        None => (mantissa, None),
    };
    let int = int.trim_start_matches('0');
    if negative {
        out.push('-');
    }
    out.push_str(if int.is_empty() { "0" } else { int });
    if let Some(frac) = frac {
        out.push('.');
        out.push_str(if frac.is_empty() { "0" } else { frac });
    }
    out.push_str(exponent);
}

/// Read a JSON5 document.
///
/// Trailing content after the top-level value is an error: a config file with
/// a second document glued on is a mistake, not two configs.
pub fn parse(input: &str) -> Result<Json5Value, Json5Error> {
    let mut p = Parser {
        lex: Lexer::new(input),
    };
    p.lex.skip_trivia()?;
    let value = p.value()?;
    p.lex.skip_trivia()?;
    if !p.lex.at_end() {
        return Err(p.lex.err("end of document"));
    }
    Ok(value)
}

/// The TREE BUILDER. R2824: every scan is the lexer's (`json5_lex`), which a
/// no-heap reader walks too; what is left here is only the part that needs a
/// heap — collecting members and elements, and decoding strings into `String`.
struct Parser<'a> {
    lex: Lexer<'a>,
}

impl Parser<'_> {
    fn value(&mut self) -> Result<Json5Value, Json5Error> {
        match self.lex.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"' | b'\'') => {
                let s = self.lex.string()?;
                Ok(Json5Value::String(decode(&s)?))
            }
            Some(_) if self.lex.at_number() => {
                Ok(Json5Value::Number(self.lex.number()?.to_string()))
            }
            Some(_) => Ok(match self.lex.keyword()? {
                Json5Keyword::True => Json5Value::Bool(true),
                Json5Keyword::False => Json5Value::Bool(false),
                Json5Keyword::Null => Json5Value::Null,
            }),
            None => Err(self.lex.err("a value")),
        }
    }

    fn object(&mut self) -> Result<Json5Value, Json5Error> {
        self.lex.bump(); // '{'
        let mut entries = Vec::new();
        loop {
            self.lex.skip_trivia()?;
            match self.lex.peek() {
                Some(b'}') => {
                    self.lex.bump();
                    return Ok(Json5Value::Object(entries));
                }
                None => return Err(self.lex.err("} closing an object")),
                _ => {}
            }
            let key = decode(&self.lex.member_name()?)?;
            self.lex.skip_trivia()?;
            self.lex.expect(b':', ": after a member name")?;
            self.lex.skip_trivia()?;
            let value = self.value()?;
            entries.push((key, value));
            self.lex.skip_trivia()?;
            match self.lex.peek() {
                Some(b',') => self.lex.bump(),
                Some(b'}') => {}
                _ => return Err(self.lex.err(", or } after a member")),
            }
        }
    }

    fn array(&mut self) -> Result<Json5Value, Json5Error> {
        self.lex.bump(); // '['
        let mut items = Vec::new();
        loop {
            self.lex.skip_trivia()?;
            match self.lex.peek() {
                Some(b']') => {
                    self.lex.bump();
                    return Ok(Json5Value::Array(items));
                }
                None => return Err(self.lex.err("] closing an array")),
                _ => {}
            }
            items.push(self.value()?);
            self.lex.skip_trivia()?;
            match self.lex.peek() {
                Some(b',') => self.lex.bump(),
                Some(b']') => {}
                _ => return Err(self.lex.err(", or ] after an element")),
            }
        }
    }
}

/// A scanned string into a `String`. The scan checked the text, so the only
/// failure left would be the destination's, and `String` does not run out.
fn decode(s: &Json5Str<'_>) -> Result<String, Json5Error> {
    let mut out = String::new();
    s.decode_into(&mut out)?;
    Ok(out)
}

/// Parse a [`Json5Value::Number`]'s source text as a `u64`, honouring a `0x`
/// prefix and a redundant leading `+`.
///
/// Separate from the parser on purpose (see the module doc): the type belongs
/// to the consumer, and this is the shared implementation of the one the
/// config surface needs. `None` for a non-integer, a negative, or an overflow.
pub fn number_as_u64(text: &str) -> Option<u64> {
    let body = text.strip_prefix('+').unwrap_or(text);
    if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    body.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn obj(v: &Json5Value) -> &Vec<(String, Json5Value)> {
        match v {
            Json5Value::Object(e) => e,
            other => panic!("not an object: {other:?}"),
        }
    }

    #[test]
    fn strict_json_is_a_json5_subset() {
        let v = parse(r#"{"a": 1, "b": [true, false, null], "c": {"d": "x"}}"#).unwrap();
        assert_eq!(v.get("a"), Some(&Json5Value::Number("1".into())));
        assert_eq!(
            v.get("b"),
            Some(&Json5Value::Array(vec![
                Json5Value::Bool(true),
                Json5Value::Bool(false),
                Json5Value::Null
            ]))
        );
        assert_eq!(v.get("c/d"), Some(&Json5Value::String("x".into())));
    }

    #[test]
    fn the_four_json5_affordances_a_zenoh_config_uses() {
        // Bare keys, single quotes, trailing commas, and both comment forms —
        // the reference DEFAULT_CONFIG.json5 uses every one of them.
        let v = parse(
            r#"
            /// a doc comment
            {
              mode: 'peer', // line comment
              /* block
                 comment */
              listen: { endpoints: ["tcp/127.0.0.1:7447",], },
            }
            "#,
        )
        .unwrap();
        assert_eq!(v.get("mode"), Some(&Json5Value::String("peer".into())));
        assert_eq!(
            v.get("listen/endpoints"),
            Some(&Json5Value::Array(vec![Json5Value::String(
                "tcp/127.0.0.1:7447".into()
            )]))
        );
    }

    #[test]
    fn numbers_keep_their_source_text_so_an_integer_is_never_a_float() {
        let v = parse("{a: 65535, b: 18446744073709551615, c: 0x1f, d: -3, e: 1.5e3}").unwrap();
        // The u64 max round-trips exactly; through an f64 it would not.
        assert_eq!(
            v.get("b"),
            Some(&Json5Value::Number("18446744073709551615".into()))
        );
        assert_eq!(number_as_u64("18446744073709551615"), Some(u64::MAX));
        assert_eq!(number_as_u64("65535"), Some(65_535));
        assert_eq!(number_as_u64("0x1f"), Some(31));
        assert_eq!(number_as_u64("-3"), None);
        assert_eq!(number_as_u64("1.5e3"), None);
        assert_eq!(v.get("c"), Some(&Json5Value::Number("0x1f".into())));
        assert_eq!(v.get("d"), Some(&Json5Value::Number("-3".into())));
        assert_eq!(v.get("e"), Some(&Json5Value::Number("1.5e3".into())));
    }

    #[test]
    fn escapes_resolve_including_a_surrogate_pair_and_a_line_continuation() {
        let v = parse("{a: \"x\\ny\\u00e9\\uD83D\\uDE00\\\n z\"}").unwrap();
        assert_eq!(
            v.get("a"),
            Some(&Json5Value::String("x\ny\u{e9}\u{1F600} z".into()))
        );
    }

    #[test]
    fn a_duplicate_key_is_last_wins_and_both_are_still_recorded() {
        let v = parse("{a: 1, a: 2}").unwrap();
        assert_eq!(v.get("a"), Some(&Json5Value::Number("2".into())));
        assert_eq!(obj(&v).len(), 2);
    }

    #[test]
    fn leaf_paths_treats_an_empty_object_as_a_leaf() {
        let v = parse("{a: {b: 1, c: [1,2]}, plugins: {}}").unwrap();
        assert_eq!(v.leaf_paths(), vec!["a/b", "a/c", "plugins"]);
        // ... but the ROOT is not a path, however leaf-like it is. A caller
        // partitioning these against a known-key set would otherwise see `{}`
        // as an unknown key called "".
        assert!(parse("{}").unwrap().leaf_paths().is_empty());
        assert!(parse("5").unwrap().leaf_paths().is_empty());
    }

    #[test]
    fn what_it_refuses_it_refuses_at_an_offset_rather_than_guessing() {
        // Each of these is a shape a silent parser would paper over.
        for (src, at) in [
            ("{a: 1} {b: 2}", 7), // a second document glued on
            ("{a: 1", 5),         // unterminated object
            ("{1a: 2}", 1),       // a key that is not an identifier
            ("{a: 0x}", 4),       // a hex prefix with no digits
            ("{a: -}", 4),        // a sign with no number
            ("{a: 1e}", 4),       // an exponent with no digits
            ("{a: NaN}", 4),      // JSON5 allows it; a config must not
            ("{a: \"x\\q\"}", 7), // an unknown escape (offset is the escape CHAR)
            ("{a: /* open", 4),   // an unterminated block comment
            ("{a: 1,, b: 2}", 6), // a hole in a member list
        ] {
            let e = parse(src).unwrap_err();
            assert_eq!(e.offset, at, "{src:?} -> {e}");
        }
    }

    #[test]
    fn get_returns_none_rather_than_panicking_on_a_path_through_a_scalar() {
        let v = parse("{a: 1}").unwrap();
        assert_eq!(v.get("a/b"), None);
        assert_eq!(v.get("nope"), None);
        assert_eq!(v.get(""), Some(&v));
    }

    /// The variant a node IS, named by an EXHAUSTIVE match so a variant added
    /// to the enum cannot slip past the coverage assertion below by simply not
    /// being thought of.
    fn variant_of(v: &Json5Value) -> &'static str {
        match v {
            Json5Value::Null => "Null",
            Json5Value::Bool(_) => "Bool",
            Json5Value::Number(_) => "Number",
            Json5Value::String(_) => "String",
            Json5Value::Array(_) => "Array",
            Json5Value::Object(_) => "Object",
        }
    }

    /// Every variant occurring anywhere in `v`, itself included.
    fn variants_reached(v: &Json5Value, out: &mut Vec<&'static str>) {
        out.push(variant_of(v));
        match v {
            Json5Value::Array(items) => items.iter().for_each(|i| variants_reached(i, out)),
            Json5Value::Object(entries) => {
                entries.iter().for_each(|(_, i)| variants_reached(i, out));
            }
            _ => {}
        }
    }

    /// R2303 (open-debt item 636) — [`Json5Value::to_json5_text`] is the
    /// parser's INVERSE, asserted as the round trip rather than against a
    /// transcribed string.
    ///
    /// A transcription would have frozen this author's idea of the output —
    /// where the spaces go, whether a key is quoted — none of which is the
    /// contract. The contract is that the text re-reads as the same value, and
    /// only a re-parse can say so.
    ///
    /// The witness carries EVERY variant, and the test proves that rather than
    /// claiming it: an exhaustive `match` names the variants and the walk
    /// counts the ones the document actually reached, so a variant added to the
    /// enum fails to compile in `variant_of` and a variant merely FORGOTTEN in
    /// the witness fails here. An emitter is a per-variant surface, so a
    /// witness missing one leaves that one entirely ungated — which is how
    /// `null` and an object value came to re-render as the STRINGS `"null"` and
    /// `"{...}"` in this workspace's C config store.
    #[test]
    fn to_json5_text_is_the_parsers_inverse_over_every_variant() {
        let src = r#"{
            nothing: null,
            yes: true,
            no: false,
            int: 65535,
            hex: 0x1f,
            exp: -1.5e3,
            plain: "tcp/127.0.0.1:7447",
            awkward: "a \" b \\ c \n d é",
            empty_list: [],
            mixed: [{kind: "current_exe_parent", value: null}, ".", 7],
            empty_object: {},
            nested: {deep: {deeper: ["x"]}},
        }"#;
        let parsed = parse(src).expect("the witness must parse");

        let mut reached = Vec::new();
        variants_reached(&parsed, &mut reached);
        for variant in ["Null", "Bool", "Number", "String", "Array", "Object"] {
            assert!(
                reached.contains(&variant),
                "the witness reaches no {variant}, so the emitter's {variant} arm is ungated"
            );
        }

        let text = parsed.to_json5_text();
        let reparsed =
            parse(&text).unwrap_or_else(|e| panic!("re-emit does not re-read: {e}\n{text}"));
        assert_eq!(
            reparsed, parsed,
            "the round trip changed the value:\n{text}"
        );

        // And it is STABLE, not merely equal once: a second pass over the
        // emitter's own output must produce the same bytes, which is what a
        // consumer diffing two configs relies on.
        assert_eq!(reparsed.to_json5_text(), text);
    }

    /// A string value is ESCAPED by the emitter, not pasted.
    ///
    /// Separate from the round trip above because a paste-through emitter can
    /// still round-trip: `"a\"b"` emitted raw produces text that fails to parse
    /// — caught there — but a value whose escape merely CHANGES form would not
    /// be. This pins the escaper is the shared one, by its output.
    #[test]
    fn to_json5_text_escapes_a_string_rather_than_pasting_it() {
        let v = Json5Value::String(String::from("a\"b\\c\nd"));
        assert_eq!(v.to_json5_text(), "\"a\\\"b\\\\c\\nd\"");
    }

    /// R2804 — every number spelling this parser admits and JSON does not is
    /// respelled, value unchanged, and one JSON already allows is left alone.
    /// The inputs are PARSED, not constructed, so each is a spelling this
    /// reader really accepts; the JSON5 emitter keeps every one as written.
    #[test]
    fn to_json_text_respells_json5_only_numbers_as_json() {
        for (json5, json) in [
            ("+1", "1"),
            ("0x1f", "31"),
            ("-0X10", "-16"),
            ("-0x0", "0"),
            (".5", "0.5"),
            ("5.", "5.0"),
            ("007", "7"),
            ("-007.50", "-7.50"),
            ("1.e5", "1.0e5"),
            ("+.5E-3", "0.5E-3"),
            ("0", "0"),
            ("-0", "-0"),
            ("12.25e+2", "12.25e+2"),
        ] {
            let v = parse(json5).unwrap_or_else(|e| panic!("{json5}: {e}"));
            assert_eq!(v.to_json_text(), json, "{json5}");
            assert_eq!(v.to_json5_text(), json5, "the JSON5 spelling survives");
        }
        // Inside structure too, and nothing but numbers moves.
        let v = parse("{ a: [0x10, 'x', +2], b: null }").unwrap();
        assert_eq!(v.to_json_text(), r#"{"a":[16,"x",2],"b":null}"#);
        // A hex literal no 128-bit integer holds is kept exact, as a string.
        let wide = alloc::format!("0x1{}", "0".repeat(32));
        assert_eq!(
            parse(&wide).unwrap().to_json_text(),
            alloc::format!("\"{wide}\"")
        );
    }
}
