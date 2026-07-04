// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Hand-rolled JSON output + base64 (ZERO `serde_json` / `base64` dependency —
//! the same "manual JSON" choice wz-session-core already makes for its
//! adminspace `AdminLocalData`). The output shape mirrors zenoh's REST plugin
//! `JSONSample` (`{key, value, encoding, timestamp}`).
//!
//! String escaping routes through the wz SSOT escaper
//! [`wz_session_core::json::escape_into`] (a correctness-bearing escaper must
//! live in ONE place — the adminspace uses the same one). Documented fidelity
//! deltas vs zenoh: `timestamp` is always `null` — the GET/query path's
//! `ReplyView` genuinely carries no timestamp accessor, while the SSE path's
//! `SampleView` DOES carry one, so rendering the real SSE-sample timestamp
//! (matching zenoh's uhlc datetime string) is a deferred follow-up, not a
//! surface limitation. A non-empty `value` is always a JSON *string* (base64
//! for non-UTF-8 payloads) rather than zenoh's nested-JSON embedding for
//! JSON-encoded payloads — a minimal-but-safe choice that can never emit
//! invalid JSON. An empty payload renders `null` (zenoh parity).

use wz_session_core::json::escape_into;

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

/// Render a payload as a JSON *value*: an empty payload is `null` (zenoh
/// parity); a UTF-8 payload is an escaped JSON string; a non-UTF-8 payload is
/// its base64 as a JSON string.
pub fn value_string(payload: &[u8]) -> String {
    if payload.is_empty() {
        return "null".to_string();
    }
    let mut out = String::new();
    match std::str::from_utf8(payload) {
        Ok(s) => escape_into(s, &mut out),
        Err(_) => escape_into(&base64_encode(payload), &mut out),
    }
    out
}

/// One `{"key":..,"value":..,"encoding":..,"timestamp":null}` object. `key` and
/// `encoding` are escaped via the SSOT escaper; `value_json` is a pre-rendered
/// JSON value (from [`value_string`]).
pub fn sample_object(key: &str, value_json: &str, encoding: &str) -> String {
    let mut out = String::from("{\"key\":");
    escape_into(key, &mut out);
    out.push_str(",\"value\":");
    out.push_str(value_json);
    out.push_str(",\"encoding\":");
    escape_into(encoding, &mut out);
    out.push_str(",\"timestamp\":null}");
    out
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

    #[test]
    fn value_string_null_utf8_binary() {
        assert_eq!(value_string(b""), "null");
        assert_eq!(value_string(b"hello"), "\"hello\"");
        assert_eq!(value_string(b"a\"b"), "\"a\\\"b\"");
        // Invalid UTF-8 falls back to a base64 string.
        assert_eq!(
            value_string(&[0xff, 0xfe]),
            format!("\"{}\"", base64_encode(&[0xff, 0xfe]))
        );
    }

    #[test]
    fn sample_object_shape() {
        assert_eq!(
            sample_object("demo/k", "\"v\"", "text/plain"),
            "{\"key\":\"demo/k\",\"value\":\"v\",\"encoding\":\"text/plain\",\"timestamp\":null}"
        );
    }
}
