// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
/// character RFC-8259-escaped (all FIVE of §7's short forms — `"` `\` `\n`
/// `\r` `\t` `\b` `\f` — and any other control char `< 0x20` as `\u00XX`),
/// then a trailing `"`. The emitter stays a correct JSON string serializer
/// rather than a `format!` a stray byte could corrupt — the admin/config
/// payloads can carry untrusted bytes (e.g. a config-write PUT's keyexpr), so
/// escaping is mandatory, not cosmetic.
///
/// # R311y921 (open-debt item 379) — `\b` and `\f` arrived, and the module doc
/// above had already named them
///
/// That doc says a future fix "(surrogate handling, `\b`/`\f`) silently
/// desyncs the two §5.23 admin-JSON surfaces" if the escaper is duplicated. It
/// was duplicated — not in the two surfaces it warned about, but in
/// `wz-capture::report`, which grew its own content-only escaper WITH the two
/// short forms while this one folded them into the generic arm. Both are
/// correct JSON and both parse, so the well-formedness guard R311y920 added
/// could never see it: the divergence is in the BYTES, not the grammar.
///
/// Merged here rather than there because the richer behaviour is the RFC's own
/// and because this is the one every other emitter already calls. The change
/// moves two characters' bytes on every surface that uses it — ``
/// becomes `\b` — which no reader can tell apart and no test in this workspace
/// pinned.
pub fn escape_into(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // R311y921 — the other two short forms RFC 8259 §7 defines. They
            // were `` / `` here and `\b` / `\f` in the report
            // writer, which is the whole of item 379.
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
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

/// The largest integer every JSON reader holds exactly: 2^53 - 1.
///
/// RFC 8259 §6 leaves the range of a number to the reader, and the readers that
/// matter are IEEE-754 doubles: JavaScript's `JSON.parse`, Qt's `toDouble()`.
/// A double holds every integer up to 2^53 and cannot tell 2^53 from 2^53 + 1,
/// so 2^53 - 1 is the last value a bare number names unambiguously. RFC 7493
/// (I-JSON) §2.2 draws the same line and says what to do beyond it: send the
/// integer as a string.
pub const MAX_EXACT_INTEGER: u64 = (1 << 53) - 1;

/// Push `v` onto `out` as the JSON value of an unsigned 64-bit integer: a bare
/// number up to [`MAX_EXACT_INTEGER`], the same digits in a string beyond it.
///
/// # Why a string and not a number, and why at 2^53
///
/// A bare 64-bit integer is a value some readers cannot hold. A reader on
/// doubles loses the low bits above 2^53 and says nothing; a reader on `int64`
/// is exact to 2^63 and then falls back to its default, which Qt's
/// `toInteger()` does. Both fail silently, and a wrong number is worse than a
/// missing one. A string cannot be misread as a number: a reader either asks
/// for the digits or finds that it asked for the wrong type.
///
/// The line is 2^53, not 2^63, because it must be the one that is safe for the
/// narrowest reader: a boundary at 2^63 would leave every double-based consumer
/// reading `2^53 + 1` as `2^53` and no way for the writer to know.
///
/// # Where it applies
///
/// Wherever a document carries a `u64` whose range is not bounded by something
/// the host can hold: a protocol field's value, and a nanosecond instant since
/// 1970 (about 1.7e18 today, past 2^53 and far under 2^63). Counters and offsets
/// stay bare numbers because they count things that live in memory or on a disk.
pub fn u64_into(v: u64, out: &mut String) {
    use core::fmt::Write as _;
    if v <= MAX_EXACT_INTEGER {
        let _ = write!(out, "{v}");
    } else {
        let _ = write!(out, "\"{v}\"");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The boundary is 2^53 - 1, spelled out as the number a JavaScript reader
    /// calls `Number.MAX_SAFE_INTEGER`, not read back from [`MAX_EXACT_INTEGER`]:
    /// a pin that follows its subject is not a pin. Both neighbours are checked,
    /// so an off-by-one in either direction reddens.
    #[test]
    fn a_u64_is_a_number_up_to_two_to_the_53_minus_1_and_a_string_beyond() {
        for (v, expected) in [
            (0u64, "0"),
            (1, "1"),
            (9_007_199_254_740_990, "9007199254740990"),
            (9_007_199_254_740_991, "9007199254740991"),
            (9_007_199_254_740_992, "\"9007199254740992\""),
            (9_007_199_254_740_993, "\"9007199254740993\""),
            (1_700_000_000_000_000_000, "\"1700000000000000000\""),
            (i64::MAX as u64, "\"9223372036854775807\""),
            (i64::MAX as u64 + 1, "\"9223372036854775808\""),
            (u64::MAX, "\"18446744073709551615\""),
        ] {
            let mut got = String::new();
            u64_into(v, &mut got);
            assert_eq!(got, expected, "writing {v}");
        }
    }

    /// R311y921 (open-debt item 379) — EVERY ESCAPE RFC 8259 §7 REQUIRES, in
    /// the form the RFC names, checked one character at a time.
    ///
    /// Moved here from `wz-capture::report` in the round that merged that
    /// module's private escaper into this one: a pin travels with the code it
    /// pins, and this is now the only implementation in the workspace. Checked
    /// against the RFC's spelling rather than against this writer's own output,
    /// which is the difference between a table and a snapshot.
    #[test]
    fn every_character_json_requires_escaping_is_escaped_as_the_rfc_names_it() {
        for (input, expected) in [
            ("plain", "\"plain\""),
            ("with\"quote", "\"with\\\"quote\""),
            ("back\\slash", "\"back\\\\slash\""),
            ("new\nline", "\"new\\nline\""),
            ("carriage\rreturn", "\"carriage\\rreturn\""),
            ("tab\there", "\"tab\\there\""),
            ("bs\u{08}", "\"bs\\b\""),
            ("ff\u{0C}", "\"ff\\f\""),
            ("nul\u{00}", "\"nul\\u0000\""),
            ("esc\u{1B}", "\"esc\\u001b\""),
            ("unit\u{1F}", "\"unit\\u001f\""),
            // Above 0x1F nothing is required, including non-ASCII: valid UTF-8
            // is valid JSON, and escaping it would be a second encoding of the
            // same bytes.
            ("공간/온도", "\"공간/온도\""),
            ("space here", "\"space here\""),
        ] {
            let mut got = String::new();
            escape_into(input, &mut got);
            assert_eq!(got, expected, "escaping {input:?}");
        }
    }

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
