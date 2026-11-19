// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A JSON document written again as CBOR (RFC 8949), the same document in
//! another encoding.
//!
//! # Why the binary form is the JSON document's, and not a second writer's
//!
//! The field document's rows are written by one writer (`crate::fields_json`),
//! and every fact on a row is read off the walk there. A consumer that lists
//! thousands of rows a second pays for the TEXT of a row twice: once to write
//! its numbers and escapes, and again to parse them. A binary door is what it
//! asks for, and the facts on a row are the reason the document exists. A
//! second writer that put the same facts into a binary layout would be a second
//! derivation of each of them, and the two would agree by hope.
//!
//! So the binary form is this conversion of the document the one writer wrote:
//! RFC 8949 §6.2's mapping of JSON onto CBOR, with nothing added or dropped. An
//! object is a map whose keys are text strings, an array an array, a string a
//! text string, `true` / `false` / `null` the simple values 21 / 20 / 22, an
//! integer an integer, and any other number a float. A reader that knows the
//! JSON document knows this one key for key, and the document's own revision
//! (`document.revision`) is the revision of both.
//!
//! # Preferred serialization
//!
//! Every length and integer head takes the fewest bytes that hold it, and every
//! container has a definite length (RFC 8949 §4.1). A float is written as the
//! shortest of half, single and double that holds its value exactly.
//!
//! The text is read once. A container's head is written as one byte when it
//! opens, which is the whole head of any container of fewer than 24 members,
//! and completed when it closes; a container of 24 members or more has its head
//! widened there, the bytes after it moved once. An earlier form read the text
//! twice, counting every container's members before writing, and the counting
//! pass cost nearly as much as the writing one.
//!
//! # What it refuses
//!
//! Text that is not one JSON value (RFC 8259) with nothing but whitespace
//! around it, a string escape that does not name a Unicode scalar value (a lone
//! surrogate), and a number that does not fit a double. Nesting deeper than
//! [`MAX_DEPTH`] is refused rather than recursed into. Refusal says where.

use alloc::vec::Vec;

// The reader is `wz_session_core::doc_out::cbor::of_json_into`, the one reader of
// the mapping: it encodes through the same head, number and float primitives the
// document writers' own CBOR encoding (`DocOut` / `CborOut`) writes with, and a
// value a model holds as JSON text is written by it too
// (`DocOut::json_value`).
#[cfg(test)]
use wz_session_core::doc_out::cbor::{float, FLOAT_HALF, MAJOR_TEXT};
pub use wz_session_core::doc_out::cbor::{Refused, MAX_DEPTH};

/// `text`, one JSON value, as one CBOR data item.
///
/// # Errors
///
/// [`Refused`] for text that is not one JSON value; see the module doc.
pub fn cbor_of_json(text: &str) -> Result<Vec<u8>, Refused> {
    // The field document's binary form is about three quarters of its text, so
    // the text's length is room enough without a second allocation.
    let mut out = Vec::with_capacity(text.len());
    wz_session_core::doc_out::cbor::of_json_into(text, &mut out)?;
    Ok(out)
}

/// The compact JSON text of one CBOR data item of the kinds [`cbor_of_json`]
/// writes: the other direction of the same mapping.
///
/// For a reader of the binary form that wants the text back (a log, a test that
/// holds a door's bytes to its document), and for this crate's tests, which hold
/// every conversion to the text it came from. A string is escaped by the field
/// writer's own escaper and an integer written in decimal, so a document the field
/// writer wrote reads back byte for byte; a float is written in Rust's shortest
/// round-trip spelling, which is the number and may not be the spelling it came
/// from.
///
/// # Errors
///
/// [`Refused`] for bytes that are not one item of those kinds, whole: a byte
/// string, a tag, an indefinite length, a simple value other than the three, a
/// text string that is not UTF-8, a truncated item, nesting past [`MAX_DEPTH`],
/// or bytes after the item.
pub fn json_of_cbor(bytes: &[u8]) -> Result<alloc::string::String, Refused> {
    let mut out = alloc::string::String::new();
    let mut at = 0;
    json_item(bytes, &mut at, 0, &mut out)?;
    if at != bytes.len() {
        return Err(Refused {
            at,
            why: "bytes follow the item",
        });
    }
    Ok(out)
}

/// The `width` big-endian bytes at `*at`, as a number.
fn be_bytes(bytes: &[u8], at: &mut usize, width: usize) -> Result<u64, Refused> {
    let slice = bytes.get(*at..*at + width).ok_or(Refused {
        at: *at,
        why: "the bytes end inside an item",
    })?;
    *at += width;
    Ok(slice.iter().fold(0u64, |n, &b| (n << 8) | u64::from(b)))
}

/// A head's argument; `*at` is at the head.
fn head_argument(bytes: &[u8], at: &mut usize) -> Result<u64, Refused> {
    let start = *at;
    let info = bytes[*at] & 0x1F;
    *at += 1;
    match info {
        0..=23 => Ok(u64::from(info)),
        24 => be_bytes(bytes, at, 1),
        25 => be_bytes(bytes, at, 2),
        26 => be_bytes(bytes, at, 4),
        27 => be_bytes(bytes, at, 8),
        _ => Err(Refused {
            at: start,
            why: "an indefinite or reserved length",
        }),
    }
}

fn json_item(
    bytes: &[u8],
    at: &mut usize,
    depth: usize,
    out: &mut alloc::string::String,
) -> Result<(), Refused> {
    use core::fmt::Write as _;
    let start = *at;
    let refuse = |why| Err(Refused { at: start, why });
    let Some(&first) = bytes.get(*at) else {
        return refuse("the bytes end where an item belongs");
    };
    match first >> 5 {
        0 => {
            let n = head_argument(bytes, at)?;
            let _ = write!(out, "{n}");
        }
        1 => {
            let n = head_argument(bytes, at)?;
            let _ = write!(out, "-{}", u128::from(n) + 1);
        }
        3 => {
            let len = head_argument(bytes, at)?;
            let end = usize::try_from(len)
                .ok()
                .and_then(|len| at.checked_add(len))
                .filter(|&end| end <= bytes.len());
            let Some(end) = end else {
                return refuse("the bytes end inside a text string");
            };
            let Ok(text) = core::str::from_utf8(&bytes[*at..end]) else {
                return refuse("a text string that is not UTF-8");
            };
            wz_session_core::json::escape_into(text, out);
            *at = end;
        }
        major @ (4 | 5) => {
            if depth == MAX_DEPTH {
                return refuse("nested deeper than MAX_DEPTH");
            }
            let n = head_argument(bytes, at)?;
            let (open, close) = if major == 4 { ('[', ']') } else { ('{', '}') };
            out.push(open);
            for i in 0..n {
                if i > 0 {
                    out.push(',');
                }
                if major == 5 {
                    if bytes.get(*at).map(|b| b >> 5) != Some(3) {
                        return Err(Refused {
                            at: *at,
                            why: "a map key that is not a text string",
                        });
                    }
                    json_item(bytes, at, depth + 1, out)?;
                    out.push(':');
                }
                json_item(bytes, at, depth + 1, out)?;
            }
            out.push(close);
        }
        7 => {
            *at += 1;
            let value = match first & 0x1F {
                20 => {
                    out.push_str("false");
                    return Ok(());
                }
                21 => {
                    out.push_str("true");
                    return Ok(());
                }
                22 => {
                    out.push_str("null");
                    return Ok(());
                }
                25 => value_of_half(be_bytes(bytes, at, 2)? as u16),
                26 => f64::from(f32::from_bits(be_bytes(bytes, at, 4)? as u32)),
                27 => f64::from_bits(be_bytes(bytes, at, 8)?),
                _ => return refuse("a simple value JSON has no word for"),
            };
            if !value.is_finite() {
                return refuse("a float JSON has no number for");
            }
            let _ = write!(out, "{value:?}");
        }
        _ => return refuse("a byte string or a tag, which JSON has no form for"),
    }
    Ok(())
}

/// The value of an IEEE 754 half, exactly: a normal half's fields widen into a
/// single's (the exponent rebiased from 15 to 127, the mantissa shifted up by 13),
/// and a subnormal one is its mantissa times 2^-24, which a single holds exactly.
/// Bit arithmetic rather than `powi`, which this `no_std` crate does not have.
fn value_of_half(bits: u16) -> f64 {
    let sign = u32::from(bits & 0x8000) << 16;
    let exponent = u32::from((bits >> 10) & 0x1F);
    let mantissa = u32::from(bits & 0x3FF);
    let single = match exponent {
        0 => {
            // 2^-24 is the single 0x3380_0000.
            let magnitude = mantissa as f32 * f32::from_bits(0x3380_0000);
            f32::from_bits(magnitude.to_bits() | sign)
        }
        31 => f32::from_bits(sign | 0x7F80_0000 | (mantissa << 13)),
        _ => f32::from_bits(sign | ((exponent + 127 - 15) << 23) | (mantissa << 13)),
    };
    f64::from(single)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| alloc::format!("{b:02x}")).collect()
    }

    fn encoded(text: &str) -> String {
        hex(&cbor_of_json(text).expect("the text is one JSON value"))
    }

    /// RFC 8949 Appendix A, every example whose diagnostic notation is also a
    /// JSON value, against the RFC's own bytes.
    #[test]
    fn the_rfc_examples_are_written_as_the_rfc_writes_them() {
        for (json, cbor) in [
            ("0", "00"),
            ("1", "01"),
            ("10", "0a"),
            ("23", "17"),
            ("24", "1818"),
            ("25", "1819"),
            ("100", "1864"),
            ("1000", "1903e8"),
            ("1000000", "1a000f4240"),
            ("1000000000000", "1b000000e8d4a51000"),
            ("18446744073709551615", "1bffffffffffffffff"),
            ("-18446744073709551616", "3bffffffffffffffff"),
            ("-1", "20"),
            ("-10", "29"),
            ("-100", "3863"),
            ("-1000", "3903e7"),
            ("0.0", "f90000"),
            ("-0.0", "f98000"),
            ("1.0", "f93c00"),
            ("1.1", "fb3ff199999999999a"),
            ("1.5", "f93e00"),
            ("65504.0", "f97bff"),
            ("100000.0", "fa47c35000"),
            ("3.4028234663852886e+38", "fa7f7fffff"),
            ("1.0e+300", "fb7e37e43c8800759c"),
            ("5.960464477539063e-8", "f90001"),
            ("0.00006103515625", "f90400"),
            ("-4.0", "f9c400"),
            ("-4.1", "fbc010666666666666"),
            ("false", "f4"),
            ("true", "f5"),
            ("null", "f6"),
            ("\"\"", "60"),
            ("\"a\"", "6161"),
            ("\"IETF\"", "6449455446"),
            ("\"\\\"\\\\\"", "62225c"),
            ("\"\\u00fc\"", "62c3bc"),
            ("\"\\u6c34\"", "63e6b0b4"),
            ("\"\\ud800\\udd51\"", "64f0908591"),
            ("[]", "80"),
            ("[1,2,3]", "83010203"),
            ("[1,[2,3],[4,5]]", "8301820203820405"),
            (
                "[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25]",
                "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
            ),
            ("{}", "a0"),
            ("{\"a\":1,\"b\":[2,3]}", "a26161016162820203"),
            ("[\"a\",{\"b\":\"c\"}]", "826161a161626163"),
            (
                "{\"a\":\"A\",\"b\":\"B\",\"c\":\"C\",\"d\":\"D\",\"e\":\"E\"}",
                "a56161614161626142616361436164614461656145",
            ),
        ] {
            assert_eq!(encoded(json), cbor, "{json}");
        }
    }

    /// Whitespace anywhere JSON allows it changes nothing, and every escape the
    /// field document's escaper writes reads back as the character it escaped.
    #[test]
    fn whitespace_and_the_writers_escapes_read_as_the_characters() {
        assert_eq!(
            encoded(" { \"a\" : [ 1 , true ] , \"b\" :null } "),
            encoded("{\"a\":[1,true],\"b\":null}")
        );
        let mut text = String::new();
        let original = "q\"b\\n\nr\rt\tb\u{08}f\u{0C}c\u{01}/é水𐅑";
        wz_session_core::json::escape_into(original, &mut text);
        let mut expected = alloc::vec![MAJOR_TEXT | 24, original.len() as u8];
        expected.extend_from_slice(original.as_bytes());
        assert_eq!(cbor_of_json(&text), Ok(expected));
    }

    /// A container's length is the count of its members, past the inline range
    /// and in a nested container that opens after a long one.
    #[test]
    fn every_container_has_the_length_of_its_own_members() {
        let long: String = {
            let items: Vec<String> = (0..300).map(|i| alloc::format!("{i}")).collect();
            alloc::format!("[[{}],{{\"k\":[7]}}]", items.join(","))
        };
        let bytes = cbor_of_json(&long).expect("one value");
        // Outer array of two, then an array of 300: head 0x99 0x01 0x2c.
        assert_eq!(&bytes[..4], &[0x82, 0x99, 0x01, 0x2c]);
        // The map after it holds one pair whose value is an array of one.
        let tail = &bytes[bytes.len() - 5..];
        assert_eq!(tail, &[0xa1, 0x61, b'k', 0x81, 0x07]);
    }

    /// A container's head is completed when it closes, so every width a count can
    /// take is written at each edge of it: the inline range and one-, two- and
    /// four-byte arguments, for an array and for a map, inside a map with a member
    /// after it so the bytes moved by a widened head are seen in place. The
    /// expected head is spelled out here rather than taken from the writer.
    #[test]
    fn a_head_completed_at_the_close_takes_every_width_at_each_edge() {
        fn spelled(major: u8, n: usize) -> Vec<u8> {
            match n {
                0..=23 => alloc::vec![major | n as u8],
                24..=0xff => alloc::vec![major | 24, n as u8],
                0x100..=0xffff => {
                    let mut v = alloc::vec![major | 25];
                    v.extend_from_slice(&(n as u16).to_be_bytes());
                    v
                }
                _ => {
                    let mut v = alloc::vec![major | 26];
                    v.extend_from_slice(&(n as u32).to_be_bytes());
                    v
                }
            }
        }
        for n in [0usize, 23, 24, 255, 256, 65_535, 65_536] {
            let items: Vec<&str> = (0..n).map(|_| "0").collect();
            let text = alloc::format!("{{\"a\":[{}],\"b\":1}}", items.join(","));
            let mut expected = alloc::vec![0xa2, 0x61, b'a'];
            expected.extend(spelled(0x80, n));
            expected.extend(core::iter::repeat_n(0x00, n));
            expected.extend([0x61, b'b', 0x01]);
            assert_eq!(cbor_of_json(&text), Ok(expected), "an array of {n}");

            let pairs: Vec<String> = (0..n).map(|i| alloc::format!("\"{i}\":0")).collect();
            let text = alloc::format!("[{{{}}},1]", pairs.join(","));
            let mut expected = alloc::vec![0x82];
            expected.extend(spelled(0xa0, n));
            for i in 0..n {
                let key = alloc::format!("{i}");
                expected.extend(spelled(0x60, key.len()));
                expected.extend_from_slice(key.as_bytes());
                expected.push(0x00);
            }
            expected.push(0x01);
            assert_eq!(cbor_of_json(&text), Ok(expected), "a map of {n}");
        }
    }

    /// Each kind of malformed text is refused, at the byte where it goes wrong.
    #[test]
    fn text_that_is_not_one_json_value_is_refused_where_it_goes_wrong() {
        for (text, at) in [
            ("", 0),
            ("[1,]", 3),
            ("{\"a\" 1}", 5),
            ("{1:2}", 1),
            ("[1 2]", 3),
            ("\"abc", 4),
            ("\"\\x\"", 3),
            ("\"\\ud800\"", 7),
            ("\"\\udc00\"", 7),
            ("01", 1),
            ("-", 1),
            ("1.", 2),
            ("1e", 2),
            ("1e400", 0),
            ("tru", 0),
            ("[1] 2", 4),
            ("\"a\u{01}\"", 2),
        ] {
            assert_eq!(cbor_of_json(text).map_err(|r| r.at), Err(at), "{text:?}");
        }
        let deep = "[".repeat(MAX_DEPTH + 1);
        assert_eq!(
            cbor_of_json(&deep).map_err(|r| r.why),
            Err("nested deeper than MAX_DEPTH")
        );
    }

    /// Every half: each of the 2^16 bit patterns that is finite reads back, as
    /// a double, to a value this writer writes in those same two bytes.
    #[test]
    fn every_finite_half_is_written_as_that_half() {
        for bits in 0u16..=u16::MAX {
            if bits & 0x7C00 == 0x7C00 {
                continue;
            }
            let v = half_value(bits);
            let mut out = Vec::new();
            float(v, &mut out);
            assert_eq!(
                out,
                [FLOAT_HALF, (bits >> 8) as u8, bits as u8],
                "{bits:#06x}"
            );
        }
    }

    /// The value of a half, by RFC 8949 Appendix D's decoder.
    fn half_value(bits: u16) -> f64 {
        let exponent = i32::from((bits >> 10) & 0x1F);
        let mantissa = f64::from(bits & 0x3FF);
        let magnitude = if exponent == 0 {
            mantissa * 2f64.powi(-24)
        } else {
            (mantissa + 1024.0) * 2f64.powi(exponent - 25)
        };
        if bits & 0x8000 != 0 {
            -magnitude
        } else {
            magnitude
        }
    }

    /// The other direction reads back what this one wrote: every RFC example
    /// whose JSON spelling is the one the reader writes, the writer's escapes,
    /// and every finite half against the oracle above.
    #[test]
    fn the_text_reads_back_from_the_bytes() {
        for json in [
            "0",
            "23",
            "24",
            "1000000000000",
            "18446744073709551615",
            "-1",
            "-1000",
            "-18446744073709551616",
            "1.5",
            "1.1",
            "-4.1",
            "100000.0",
            "1e300",
            "false",
            "true",
            "null",
            "\"\"",
            "\"\\\"\\\\\"",
            "[]",
            "[1,[2,3],[4,5]]",
            "{}",
            "{\"a\":1,\"b\":[2,3]}",
            "[\"a\",{\"b\":\"c\"}]",
        ] {
            let bytes = cbor_of_json(json).expect("one value");
            let back = json_of_cbor(&bytes).expect("one item");
            let again = cbor_of_json(&back).expect("one value");
            assert_eq!(again, bytes, "{json} read back as {back}");
        }
        let mut text = String::new();
        wz_session_core::json::escape_into("q\"b\\n\nr\u{01}é水𐅑", &mut text);
        assert_eq!(
            json_of_cbor(&cbor_of_json(&text).expect("one value")),
            Ok(text)
        );
        for bits in 0u16..=u16::MAX {
            if bits & 0x7C00 == 0x7C00 {
                continue;
            }
            let read =
                json_of_cbor(&[FLOAT_HALF, (bits >> 8) as u8, bits as u8]).expect("a finite half");
            assert_eq!(
                read.parse::<f64>().map(f64::to_bits),
                Ok(half_value(bits).to_bits()),
                "{bits:#06x}"
            );
        }
    }

    /// What JSON has no form for, and what is not whole, is refused where it is.
    #[test]
    fn bytes_that_are_not_one_item_of_these_kinds_are_refused_where_they_are() {
        for (bytes, at) in [
            (&[][..], 0),
            (&[0x40][..], 0),
            (&[0xc0, 0x00][..], 0),
            (&[0x9f, 0xff][..], 0),
            (&[0xf7][..], 0),
            (&[0xf9, 0x7c, 0x00][..], 0),
            (&[0x62, 0xff, 0xfe][..], 0),
            (&[0x63, b'a'][..], 0),
            (&[0x19, 0x01][..], 1),
            (&[0xa1, 0x01, 0x02][..], 1),
            (&[0x01, 0x02][..], 1),
        ] {
            assert_eq!(
                json_of_cbor(bytes).map_err(|r| r.at),
                Err(at),
                "{bytes:02x?}"
            );
        }
        let mut deep = alloc::vec![0x81u8; MAX_DEPTH + 1];
        deep.push(0x00);
        assert_eq!(
            json_of_cbor(&deep).map_err(|r| r.why),
            Err("nested deeper than MAX_DEPTH")
        );
    }
}
