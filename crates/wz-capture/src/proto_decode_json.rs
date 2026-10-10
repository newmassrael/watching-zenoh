// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The JSON rendering of a typed decoding ([`crate::proto_decode`]): the
//! listing of a message's fields, as the documents that carry one write it.
//!
//! It lives beside the reader, as [`crate::proto_encode_json`] lives beside the
//! writer: one rendering, so a second document that carries a decoded message
//! does not get to invent another.
//!
//! # One field
//!
//! ```text
//! {"number":1,"name":"x","type":"sint32","offset":16,"bytes":2,"value":-3}
//! {"number":4,"name":"inner","type":"demo.Inner","offset":25,"bytes":13,
//!  "fields":[{"number":1,"name":"ratio","type":"double",...,"value":0.5}, ...]}
//! {"number":9,"offset":40,"bytes":2,"wire_type":"varint","value":7}
//! ```
//!
//! * `offset` and `bytes` place the field in the bytes the document is about:
//!   its tag and value, or one element of a packed run.
//! * A message, and an entry of a map field, has `fields` in place of `value`:
//!   the listing of its own fields, a map entry's being `key` and `value`.
//! * A field the schema does not know has `wire_type` (`varint`, `i64`, `len`,
//!   `i32`), which no other field carries, and no `name` and no `type`: the
//!   documents that carry a listing write a key that does not apply as ABSENT
//!   and never `null`. Its `value` is the raw value of that wire type, an
//!   unsigned integer or, for `len`, the bytes.
//!
//! # A value is written as protobuf's JSON mapping writes it
//!
//! The form [`crate::proto_encode`] READS, so a value taken out of a decoding
//! can be given back to the writer as it stands: an integer is a JSON number,
//! and the digits in a string past 2^53 - 1 by the integer rule every document
//! here keeps; `float` and `double` are a JSON number, or `"NaN"`,
//! `"Infinity"` and `"-Infinity"`; `bool` is `true` or `false`; `string` is a
//! string; `bytes` is standard base64 with padding; an enum value is its name,
//! or its number when the enum has no name for it.

use alloc::string::String;
use core::fmt::{self, Write as _};

use wz_session_core::json::{escape_into, u64_into, MAX_EXACT_INTEGER};

use crate::proto_decode::{DecodedField, Unknown, Value};

/// The fields of a message as a JSON array, each placed at `base` plus its own
/// offset.
pub(crate) fn push_fields(fields: &[DecodedField], base: usize, out: &mut String) {
    out.push('[');
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_field(field, base, out);
    }
    out.push(']');
}

fn push_field(field: &DecodedField, base: usize, out: &mut String) {
    let _ = write!(out, "{{\"number\":{}", field.number);
    if let Some(name) = &field.name {
        out.push_str(",\"name\":");
        escape_into(name, out);
    }
    if let Some(ty) = &field.ty {
        out.push_str(",\"type\":");
        escape_into(ty, out);
    }
    let _ = write!(
        out,
        ",\"offset\":{},\"bytes\":{}",
        base + field.start,
        field.end - field.start
    );
    push_value(&field.value, base, out);
    out.push('}');
}

/// What follows a field's place: `fields` for a message, `wire_type` and the
/// raw `value` for a field the schema does not know, and `value` otherwise.
fn push_value(value: &Value, base: usize, out: &mut String) {
    match value {
        Value::Message(fields) => {
            out.push_str(",\"fields\":");
            push_fields(fields, base, out);
            return;
        }
        Value::Unknown(raw) => {
            out.push_str(",\"wire_type\":\"");
            out.push_str(raw.wire_type());
            out.push('"');
        }
        _ => {}
    }
    out.push_str(",\"value\":");
    match value {
        Value::Signed(v) => push_integer(i128::from(*v), out),
        Value::Unsigned(v) => push_integer(i128::from(*v), out),
        Value::Float(v) => push_float(*v, f64::from(*v), out),
        Value::Double(v) => push_float(*v, *v, out),
        Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
        Value::Text(text) => escape_into(text, out),
        Value::Bytes(bytes) | Value::Unknown(Unknown::Len(bytes)) => push_base64(bytes, out),
        Value::Enum { number, name } => match name {
            Some(name) => escape_into(name, out),
            None => push_integer(i128::from(*number), out),
        },
        Value::Unknown(Unknown::Varint(v) | Unknown::Fixed64(v)) => {
            push_integer(i128::from(*v), out);
        }
        Value::Unknown(Unknown::Fixed32(v)) => push_integer(i128::from(*v), out),
        // Written above, with its own key.
        Value::Message(_) => {}
    }
}

/// An integer of any protobuf type, by the integer rule: a bare number while
/// every JSON reader holds it exactly, the digits in a string beyond.
///
/// The one place a decoded integer is written, so the non-negative half takes
/// the workspace's integer door and the negative half mirrors it at the same
/// line.
fn push_integer(v: i128, out: &mut String) {
    match u64::try_from(v) {
        Ok(v) => u64_into(v, out),
        Err(_) if v.unsigned_abs() <= u128::from(MAX_EXACT_INTEGER) => {
            let _ = write!(out, "{v}");
        }
        Err(_) => {
            let _ = write!(out, "\"{v}\"");
        }
    }
}

/// `float` or `double`: the three strings the JSON mapping has for the values
/// a JSON number cannot be, else a number in the shortest spelling that reads
/// back to the same value of its own width (Rust's formatting of `v` is that
/// spelling), with an exponent outside the range a plain decimal is short in.
/// `-0.0` keeps its sign (`-0`). `wide` is `v` as a `double`, to classify it.
fn push_float<F: fmt::Display + fmt::LowerExp>(v: F, wide: f64, out: &mut String) {
    if wide.is_nan() {
        out.push_str("\"NaN\"");
    } else if wide.is_infinite() {
        out.push_str(if wide > 0.0 {
            "\"Infinity\""
        } else {
            "\"-Infinity\""
        });
    } else {
        let magnitude = wide.abs();
        if magnitude == 0.0 || (1e-6..1e21).contains(&magnitude) {
            let _ = write!(out, "{v}");
        } else {
            let _ = write!(out, "{v:e}");
        }
    }
}

/// Standard base64 (RFC 4648 section 4) with padding, quoted.
fn push_base64(bytes: &[u8], out: &mut String) {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    out.push('"');
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i)) as usize & 0x3f]));
            } else {
                out.push('=');
            }
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn rendered(f: impl Fn(&mut String)) -> String {
        let mut out = String::new();
        f(&mut out);
        out
    }

    /// The integer line is 2^53 - 1 on both sides of zero, spelled out rather
    /// than read back from the constant.
    #[test]
    fn an_integer_is_a_number_inside_the_exact_range_and_a_string_outside() {
        for (v, want) in [
            (0_i128, "0"),
            (-1, "-1"),
            (9_007_199_254_740_991, "9007199254740991"),
            (9_007_199_254_740_992, "\"9007199254740992\""),
            (-9_007_199_254_740_991, "-9007199254740991"),
            (-9_007_199_254_740_992, "\"-9007199254740992\""),
            (i128::from(i64::MIN), "\"-9223372036854775808\""),
            (i128::from(u64::MAX), "\"18446744073709551615\""),
        ] {
            assert_eq!(rendered(|o| push_integer(v, o)), want, "{v}");
        }
    }

    #[test]
    fn a_float_is_the_shortest_number_or_one_of_three_strings() {
        let value = |v: Value| {
            rendered(|o| push_value(&v, 0, o))
                .strip_prefix(",\"value\":")
                .expect("a scalar is a value")
                .to_string()
        };
        let d = |v: f64| value(Value::Double(v));
        let f = |v: f32| value(Value::Float(v));
        assert_eq!(d(0.5), "0.5");
        assert_eq!(d(-2.25), "-2.25");
        assert_eq!(d(0.1), "0.1");
        assert_eq!(f(0.1), "0.1");
        assert_eq!(d(-0.0), "-0");
        assert_eq!(d(1e300), "1e300");
        assert_eq!(d(1e-7), "1e-7");
        assert_eq!(d(123_456.0), "123456");
        assert_eq!(f(f32::MAX), "3.4028235e38");
        assert_eq!(d(f64::NAN), "\"NaN\"");
        assert_eq!(f(f32::INFINITY), "\"Infinity\"");
        assert_eq!(d(f64::NEG_INFINITY), "\"-Infinity\"");
    }

    /// RFC 4648 section 10's test vectors.
    #[test]
    fn bytes_are_standard_base64_with_padding() {
        for (bytes, want) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(
                rendered(|o| push_base64(bytes.as_bytes(), o)),
                alloc::format!("\"{want}\"")
            );
        }
        assert_eq!(
            rendered(|o| push_base64(&[0x01, 0x02, 0xff], o)),
            "\"AQL/\""
        );
    }
}
