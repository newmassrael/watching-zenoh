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

#[cfg(test)]
mod tests {
    use super::*;

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
