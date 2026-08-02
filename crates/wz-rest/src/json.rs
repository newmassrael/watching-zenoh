// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Hand-rolled JSON output + base64 (ZERO `serde_json` / `base64` dependency —
//! the same "manual JSON" choice wz-session-core already makes for its
//! adminspace `AdminLocalData`). The output shape mirrors zenoh's REST plugin
//! `JSONSample` (`{key, value, encoding, timestamp}`).
//!
//! String escaping routes through the wz SSOT escaper
//! [`wz_session_core::json::escape_into`] (a correctness-bearing escaper must
//! live in ONE place — the adminspace uses the same one).
//!
//! ## `value` is ENCODING-driven, not UTF-8-driven (R311y501)
//!
//! [`payload_to_json`] reproduces zenoh's `payload_to_json`
//! (`plugins/zenoh-plugin-rest/src/lib.rs:122-147`) branch for branch:
//!
//! | encoding | payload | `value` |
//! |---|---|---|
//! | (any) | empty | `null` |
//! | `application/json` / `text/json` / `text/json5`, NO schema | valid JSON | the JSON, EMBEDDED |
//! | ditto | invalid JSON | base64 string |
//! | `zenoh/string` / `text/plain`, NO schema | valid UTF-8 | the string |
//! | ditto | invalid UTF-8 | base64 string |
//! | anything else (incl. any schema-bearing encoding) | — | base64 string |
//!
//! Each row is MEASURED against a live `libzenoh_plugin_rest.so`, not inferred:
//! the schema-bearing row is why the JSON/string arms test `has_schema` — zenoh
//! matches `&Encoding::APPLICATION_JSON`, a value whose `schema` is `None`, so
//! `application/json;charset=utf-8` falls to the base64 arm. The prior wz rule
//! (UTF-8 → string, else base64) agreed with zenoh on `text/plain` and on the
//! empty payload and diverged on every other row.
//!
//! The JSON-embedding arm re-emits through [`compact_json`], a strict RFC 8259
//! validator that strips insignificant whitespace and passes tokens through
//! verbatim. Compaction is REQUIRED, not cosmetic: an SSE `data:` line is
//! newline-delimited, so an embedded payload containing a raw newline would
//! break the event framing. Verbatim tokens mean wz does not reproduce
//! `serde_json`'s f64 round-trip of exotic number literals (`1e2` stays `1e2`
//! where zenoh renders `100.0`); both are the same JSON value, and a parsing
//! consumer cannot tell them apart.
//!
//! ## `timestamp` (R311y501)
//!
//! Rendered as zenoh's `uhlc::Timestamp` Display — `<ntp64>/<zid-hex>` — via
//! the SSOT [`wz_session_core::zid_hex::zid_to_zenoh_hex`]. `null` when the
//! sample carries none. Both the SSE (`SampleView`) and query (`ReplyView`,
//! since R311y321) paths expose an inline body timestamp; the older claim in
//! this file that the query path "genuinely carries no timestamp accessor" was
//! true when written and is not any more.

use wz_session_core::encoding::{encoding_to_mime, mime_for_id};
use wz_session_core::json::escape_into;
use wz_session_core::sample::{EncodingHint, TimestampHint};
use wz_session_core::zid_hex::zid_to_zenoh_hex;

/// Encoding ids whose payload zenoh embeds as nested JSON
/// (`Encoding::{APPLICATION_JSON, TEXT_JSON, TEXT_JSON5}`).
const JSON_IDS: [u16; 3] = [
    wz_session_core::encoding::ID_APPLICATION_JSON,
    6,  // text/json
    11, // text/json5
];
/// Encoding ids whose payload zenoh renders as a bare UTF-8 string
/// (`Encoding::{ZENOH_STRING, TEXT_PLAIN}`).
const STRING_IDS: [u16; 2] = [
    wz_session_core::encoding::ID_ZENOH_STRING,
    wz_session_core::encoding::ID_TEXT_PLAIN,
];

/// Recursion cap for [`compact_json`]. This parser runs on attacker-supplied
/// bytes from the network, so nesting is bounded rather than trusted to the
/// stack; `serde_json` defaults to the same order of magnitude (128).
const MAX_JSON_DEPTH: usize = 128;

/// Standard base64 (RFC 4648) with `=` padding. (wz-session-core has no shared
/// base64 — its only `base64` dependency is TLS-gated in wz-runtime-tokio — so
/// this small encoder stays local rather than widening that dep.)
pub fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// A payload's JSON *value* under zenoh's encoding-driven rule. `encoding_id` /
/// `has_schema` are the decoded encoding hint (`None` = no hint at all, which
/// is zenoh's default `zenoh/bytes` and lands on the base64 arm). See the
/// module docs for the branch table this reproduces.
pub fn payload_to_json(payload: &[u8], encoding: Option<(u16, bool)>) -> String {
    if payload.is_empty() {
        return "null".to_string();
    }
    let base64_string = |bytes: &[u8]| {
        let mut out = String::new();
        escape_into(&base64_encode(bytes), &mut out);
        out
    };
    // A schema-bearing encoding is never one of the named zenoh constants, so
    // it takes the catch-all base64 arm (measured: `application/json;charset=
    // utf-8` renders base64, not embedded JSON).
    let (id, has_schema) = match encoding {
        Some(e) => e,
        None => return base64_string(payload),
    };
    if has_schema {
        return base64_string(payload);
    }
    if JSON_IDS.contains(&id) {
        // Encoding says JSON but the bytes are not — zenoh warns and falls back
        // to base64 rather than emitting a malformed document.
        return compact_json(payload).unwrap_or_else(|| base64_string(payload));
    }
    if STRING_IDS.contains(&id) {
        return match std::str::from_utf8(payload) {
            Ok(s) => {
                let mut out = String::new();
                escape_into(s, &mut out);
                out
            }
            Err(_) => base64_string(payload),
        };
    }
    base64_string(payload)
}

/// A sample's MIME rendering, with zenoh's DEFAULT for an absent hint.
///
/// R311y501 — an absent hint is not an absent encoding: on the wire the `MsgPut`
/// E-flag is simply unset, and zenoh's `Sample::encoding()` then reads the
/// `Encoding` default, `zenoh/bytes`. wz rendered the empty string, so an
/// unencoded sample came out `"encoding":""` where the reference emits
/// `"encoding":"zenoh/bytes"` (measured on a real DELETE sample). Used for both
/// the JSON `encoding` field and the `?_raw` Content-Type, which upstream also
/// takes straight off `sample.encoding()` (`to_raw_response`, lib.rs:219-235).
pub fn mime_or_default(encoding: Option<&EncodingHint>) -> String {
    match encoding {
        Some(e) => encoding_to_mime(e),
        None => mime_for_id(wz_session_core::encoding::ID_ZENOH_BYTES)
            .unwrap_or_default()
            .to_string(),
    }
}

/// A sample's `timestamp` field: zenoh's `uhlc::Timestamp` Display
/// (`<ntp64>/<zid-hex>`) as a JSON string, or `null` when unstamped.
pub fn timestamp_json(ts: Option<&TimestampHint>) -> String {
    match ts {
        None => "null".to_string(),
        Some(ts) => {
            let mut out = String::new();
            escape_into(
                &format!("{}/{}", ts.time, zid_to_zenoh_hex(&ts.zid)),
                &mut out,
            );
            out
        }
    }
}

/// One `{"key":..,"value":..,"encoding":..,"timestamp":..}` object. `key` and
/// `encoding` are escaped via the SSOT escaper; `value_json` (from
/// [`payload_to_json`]) and `timestamp_json` (from [`timestamp_json`]) are
/// pre-rendered JSON values.
pub fn sample_object(key: &str, value_json: &str, encoding: &str, timestamp_json: &str) -> String {
    let mut out = String::from("{\"key\":");
    escape_into(key, &mut out);
    out.push_str(",\"value\":");
    out.push_str(value_json);
    out.push_str(",\"encoding\":");
    escape_into(encoding, &mut out);
    out.push_str(",\"timestamp\":");
    out.push_str(timestamp_json);
    out.push('}');
    out
}

/// Validate `input` as one complete RFC 8259 JSON document and re-emit it with
/// insignificant whitespace stripped, or `None` if it is not valid JSON (or not
/// UTF-8, or nests deeper than [`MAX_JSON_DEPTH`]).
///
/// Tokens — strings, numbers, literals — are copied VERBATIM; only structural
/// whitespace is dropped. See the module docs for why compaction is required
/// and what verbatim tokens mean for parity.
pub fn compact_json(input: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(input).ok()?;
    let mut parser = Compactor {
        bytes: text.as_bytes(),
        pos: 0,
        out: String::with_capacity(text.len()),
    };
    parser.skip_ws();
    parser.value(0)?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return None; // trailing garbage
    }
    Some(parser.out)
}

/// The [`compact_json`] cursor. Every `fn` returns `Option<()>`, `None` meaning
/// "not valid JSON" — the caller turns that into the base64 fallback.
struct Compactor<'a> {
    bytes: &'a [u8],
    pos: usize,
    out: String,
}

impl Compactor<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Consume `b` if it is next, emitting it.
    fn eat(&mut self, b: u8) -> Option<()> {
        if self.peek()? != b {
            return None;
        }
        self.pos += 1;
        self.out.push(b as char);
        Some(())
    }

    /// Drop the JSON insignificant-whitespace run at the cursor (never emitted
    /// — this is the whole point of compaction).
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Option<()> {
        if depth > MAX_JSON_DEPTH {
            return None;
        }
        match self.peek()? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => self.string(),
            b't' => self.literal("true"),
            b'f' => self.literal("false"),
            b'n' => self.literal("null"),
            _ => self.number(),
        }
    }

    fn object(&mut self, depth: usize) -> Option<()> {
        self.eat(b'{')?;
        self.skip_ws();
        if self.peek()? == b'}' {
            return self.eat(b'}');
        }
        loop {
            self.skip_ws();
            self.string()?; // member name
            self.skip_ws();
            self.eat(b':')?;
            self.skip_ws();
            self.value(depth + 1)?;
            self.skip_ws();
            match self.peek()? {
                b',' => {
                    self.eat(b',')?;
                }
                b'}' => return self.eat(b'}'),
                _ => return None,
            }
        }
    }

    fn array(&mut self, depth: usize) -> Option<()> {
        self.eat(b'[')?;
        self.skip_ws();
        if self.peek()? == b']' {
            return self.eat(b']');
        }
        loop {
            self.skip_ws();
            self.value(depth + 1)?;
            self.skip_ws();
            match self.peek()? {
                b',' => {
                    self.eat(b',')?;
                }
                b']' => return self.eat(b']'),
                _ => return None,
            }
        }
    }

    /// A JSON string: SCAN to validate, then emit the whole span verbatim (it
    /// is already valid JSON text, so re-escaping it would be both redundant
    /// and a second place for the escaper to disagree with the SSOT one).
    ///
    /// The scan is byte-wise and still UTF-8-safe: the whole input was
    /// validated at entry, and no multi-byte sequence can contain `"`, `\` or a
    /// control byte (continuation bytes are all `0x80..=0xbf`). Rejecting raw
    /// control characters is what guarantees a re-emitted string can never
    /// carry a bare newline into an SSE `data:` line.
    fn string(&mut self) -> Option<()> {
        let start = self.pos;
        if self.peek()? != b'"' {
            return None;
        }
        self.pos += 1;
        loop {
            match self.peek()? {
                b'"' => {
                    self.pos += 1;
                    break;
                }
                b'\\' => {
                    self.pos += 1;
                    let esc = self.peek()?;
                    self.pos += 1;
                    match esc {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {}
                        b'u' => {
                            for _ in 0..4 {
                                if !self.peek()?.is_ascii_hexdigit() {
                                    return None;
                                }
                                self.pos += 1;
                            }
                        }
                        _ => return None,
                    }
                }
                // Raw control characters are illegal unescaped in JSON.
                0x00..=0x1f => return None,
                _ => self.pos += 1,
            }
        }
        self.out
            .push_str(std::str::from_utf8(&self.bytes[start..self.pos]).ok()?);
        Some(())
    }

    fn literal(&mut self, word: &str) -> Option<()> {
        if !self.bytes[self.pos..].starts_with(word.as_bytes()) {
            return None;
        }
        self.pos += word.len();
        self.out.push_str(word);
        Some(())
    }

    /// `-? (0 | [1-9][0-9]*) ('.' [0-9]+)? ([eE] [+-]? [0-9]+)?`, verbatim.
    fn number(&mut self) -> Option<()> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek()? {
            b'0' => self.pos += 1,
            b'1'..=b'9' => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return None,
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return None;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return None;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        self.out
            .push_str(std::str::from_utf8(&self.bytes[start..self.pos]).ok()?);
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    const TEXT_PLAIN: Option<(u16, bool)> = Some((4, false));
    const JSON: Option<(u16, bool)> = Some((5, false));
    const OCTET_STREAM: Option<(u16, bool)> = Some((3, false));

    /// Every row of the module-doc branch table, each pinned to the byte string
    /// a live `libzenoh_plugin_rest.so` was MEASURED emitting for that input.
    #[test]
    fn payload_to_json_matches_the_measured_zenoh_branches() {
        // Empty -> null, whatever the encoding.
        assert_eq!(payload_to_json(b"", TEXT_PLAIN), "null");
        assert_eq!(payload_to_json(b"", None), "null");
        // text/plain -> bare string; invalid UTF-8 -> base64.
        assert_eq!(payload_to_json(b"hello", TEXT_PLAIN), "\"hello\"");
        assert_eq!(payload_to_json(b"a\"b", TEXT_PLAIN), "\"a\\\"b\"");
        assert_eq!(payload_to_json(&[0xff, 0xfe], TEXT_PLAIN), "\"//4=\"");
        // application/json -> EMBEDDED; non-JSON bytes -> base64.
        assert_eq!(
            payload_to_json(b"{\"a\":1,\"b\":[2,3]}", JSON),
            "{\"a\":1,\"b\":[2,3]}"
        );
        assert_eq!(payload_to_json(b"not-json", JSON), "\"bm90LWpzb24=\"");
        // A schema-bearing JSON encoding is NOT Encoding::APPLICATION_JSON, so
        // it takes the base64 arm (`application/json;charset=utf-8`).
        assert_eq!(
            payload_to_json(b"{\"c\":9}", Some((5, true))),
            "\"eyJjIjo5fQ==\""
        );
        // Anything else -> base64, even when the bytes are valid UTF-8. This is
        // the row the old UTF-8-driven rule got wrong.
        assert_eq!(payload_to_json(b"hello", OCTET_STREAM), "\"aGVsbG8=\"");
        // No encoding hint at all == zenoh's default zenoh/bytes -> base64.
        assert_eq!(payload_to_json(b"hello", None), "\"aGVsbG8=\"");
    }

    /// Whitespace (newlines included — the SSE framing requirement) is stripped;
    /// tokens survive verbatim; malformed input is rejected so the caller can
    /// fall back to base64 rather than emit a broken document.
    #[test]
    fn compact_json_strips_whitespace_and_rejects_malformed() {
        assert_eq!(
            compact_json(b"{\n  \"a\" : 1 }").as_deref(),
            Some("{\"a\":1}")
        );
        assert_eq!(
            compact_json(b" [ 1 , \"x\" , null ] ").as_deref(),
            Some("[1,\"x\",null]")
        );
        assert_eq!(compact_json(b"{}").as_deref(), Some("{}"));
        assert_eq!(
            compact_json("\"\u{d55c}\"".as_bytes()).as_deref(),
            Some("\"\u{d55c}\"")
        );
        assert_eq!(compact_json(b"\"a\\nb\"").as_deref(), Some("\"a\\nb\""));
        assert_eq!(compact_json(b"-1.5e-3").as_deref(), Some("-1.5e-3"));
        // Rejections.
        assert_eq!(compact_json(b"not-json"), None);
        assert_eq!(compact_json(b"{\"a\":1}trailing"), None);
        assert_eq!(compact_json(b"{\"a\":}"), None);
        assert_eq!(compact_json(b"[1,]"), None);
        assert_eq!(compact_json(b"01"), None);
        assert_eq!(compact_json(b"\"raw\nnewline\""), None);
        assert_eq!(compact_json(&[0xff, 0xfe]), None);
    }

    /// The depth cap is a real refusal, not a stack overflow.
    #[test]
    fn compact_json_bounds_nesting() {
        let deep = format!("{}{}", "[".repeat(500), "]".repeat(500));
        assert_eq!(compact_json(deep.as_bytes()), None);
    }

    /// zenoh's `uhlc::Timestamp` Display — `<ntp64>/<zid-hex>`.
    #[test]
    fn timestamp_json_renders_zenoh_display() {
        assert_eq!(timestamp_json(None), "null");
        let ts = TimestampHint {
            time: 7669276098242084704,
            zid: vec![0x1a, 0x2b, 0x3c],
        };
        assert_eq!(timestamp_json(Some(&ts)), "\"7669276098242084704/3c2b1a\"");
    }

    #[test]
    fn sample_object_shape() {
        assert_eq!(
            sample_object("demo/k", "\"v\"", "text/plain", "null"),
            "{\"key\":\"demo/k\",\"value\":\"v\",\"encoding\":\"text/plain\",\"timestamp\":null}"
        );
        assert_eq!(
            sample_object("demo/k", "{\"a\":1}", "application/json", "\"7/ab\""),
            "{\"key\":\"demo/k\",\"value\":{\"a\":1},\"encoding\":\"application/json\",\"timestamp\":\"7/ab\"}"
        );
    }
}
