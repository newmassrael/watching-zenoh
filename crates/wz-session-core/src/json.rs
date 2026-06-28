// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Minimal JSON string-literal serializer — the SSOT escaper the hand-rolled
//! (no `serde_json`) admin/config JSON emitters share.
//!
//! R311y50 — hoisted out of `adminspace::push_json_str` so it is NOT duplicated
//! by `crate::config`-side emitters: a correctness-bearing escaper must live in
//! ONE place, else a future fix (surrogate handling, `\b`/`\f`) silently desyncs
//! the two §5.23 admin-JSON surfaces. `alloc`-only (`String` + `core::fmt::Write`),
//! ungated by any cfg so every emitter can reach it regardless of which admin /
//! routing feature pulled it in.

use alloc::string::String;

/// Push `s` onto `out` as a correct JSON string literal: a leading `"`, each
/// character RFC-8259-escaped (`"` `\` `\n` `\r` `\t`, and any control char
/// `< 0x20` as `\u00XX`), then a trailing `"`. The emitter stays a correct JSON
/// string serializer rather than a `format!` a stray byte could corrupt — the
/// admin/config payloads can carry untrusted bytes (e.g. a config-write PUT's
/// keyexpr), so escaping is mandatory, not cosmetic.
pub fn escape_into(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use core::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Push a JSON array of escaped strings — `["a","b",...]` — onto `out`. The SSOT
/// for the admin/config JSON string-array idiom: the bracket + comma-separator
/// bookkeeping is correctness-bearing (a missed comma/bracket corrupts the JSON)
/// exactly as [`escape_into`] is, so it lives in ONE place rather than being
/// hand-rolled per emit site (R311y60 — the `to_admin_json` / `local_data`
/// emitters re-derived this 5×; consolidated here). Each item is escaped via
/// [`escape_into`]. An empty iterator yields `[]`.
pub fn push_str_array<I, S>(items: I, out: &mut String)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    out.push('[');
    for (i, item) in items.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        escape_into(item.as_ref(), out);
    }
    out.push(']');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn str_array_emits_escaped_comma_joined_brackets() {
        let mut out = String::new();
        push_str_array(["a/b", "c\"d"], &mut out);
        assert_eq!(out, r#"["a/b","c\"d"]"#);
    }

    #[test]
    fn str_array_empty_is_brackets() {
        let mut out = String::new();
        push_str_array(core::iter::empty::<&str>(), &mut out);
        assert_eq!(out, "[]");
        // Works over owned String items too (the deny_key_exprs / config shape).
        let mut owned = String::new();
        push_str_array([String::from("x")], &mut owned);
        assert_eq!(owned, r#"["x"]"#);
    }

    #[test]
    fn escapes_quote_backslash_newline_and_control_chars() {
        // Quote, backslash, the named whitespace escapes, and a raw control char
        // (U+0001 -> ) all become valid JSON escapes; plain chars pass.
        let mut out = String::new();
        escape_into("q\"b\\n\nt\tc\u{0001}z", &mut out);
        assert_eq!(out, "\"q\\\"b\\\\n\\nt\\tc\\u0001z\"");
    }

    #[test]
    fn a_plain_keyexpr_round_trips_unescaped() {
        let mut out = String::new();
        escape_into("mesh/data/**", &mut out);
        assert_eq!(out, "\"mesh/data/**\"");
    }
}
