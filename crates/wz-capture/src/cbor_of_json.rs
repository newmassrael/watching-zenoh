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
//! shortest of half, single and double that holds its value exactly. Lengths
//! are known before a container is written because the text is read twice: once
//! to count the members of every container, in the order they open, and once to
//! write.
//!
//! # What it refuses
//!
//! Text that is not one JSON value (RFC 8259) with nothing but whitespace
//! around it, a string escape that does not name a Unicode scalar value (a lone
//! surrogate), and a number that does not fit a double. Nesting deeper than
//! [`MAX_DEPTH`] is refused rather than recursed into. Refusal says where.

use alloc::vec::Vec;

/// Deeper nesting is refused. The field document nests a few levels below a
/// row; this bounds a malformed text, not a real one.
pub const MAX_DEPTH: usize = 256;

/// Why the text was refused, and the byte offset it was refused at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    /// Byte offset into the text.
    pub at: usize,
    /// What was wrong there.
    pub why: &'static str,
}

/// `text`, one JSON value, as one CBOR data item.
///
/// # Errors
///
/// [`Refused`] for text that is not one JSON value; see the module doc.
pub fn cbor_of_json(text: &str) -> Result<Vec<u8>, Refused> {
    let mut counts = Vec::new();
    let mut count = Reader::new(text.as_bytes(), Pass::Count(&mut counts));
    count.document()?;
    let mut out = Vec::with_capacity(text.len() / 2);
    let mut write = Reader::new(
        text.as_bytes(),
        Pass::Write {
            counts: &counts,
            next: 0,
            out: &mut out,
            scratch: Vec::new(),
        },
    );
    write.document()?;
    Ok(out)
}

/// The two readings of the text: counting the members of each container, and
/// writing with those counts.
enum Pass<'a> {
    /// Each container's member count (pairs for an object), in the order the
    /// containers open.
    Count(&'a mut Vec<u64>),
    Write {
        counts: &'a [u64],
        /// The next container's place in `counts`.
        next: usize,
        out: &'a mut Vec<u8>,
        /// A string's unescaped bytes, before its length is written.
        scratch: Vec<u8>,
    },
}

/// CBOR major types, shifted into the head byte's top three bits.
const MAJOR_UNSIGNED: u8 = 0 << 5;
const MAJOR_NEGATIVE: u8 = 1 << 5;
const MAJOR_TEXT: u8 = 3 << 5;
const MAJOR_ARRAY: u8 = 4 << 5;
const MAJOR_MAP: u8 = 5 << 5;
const MAJOR_SIMPLE: u8 = 7 << 5;

const SIMPLE_FALSE: u8 = MAJOR_SIMPLE | 20;
const SIMPLE_TRUE: u8 = MAJOR_SIMPLE | 21;
const SIMPLE_NULL: u8 = MAJOR_SIMPLE | 22;
const FLOAT_HALF: u8 = MAJOR_SIMPLE | 25;
const FLOAT_SINGLE: u8 = MAJOR_SIMPLE | 26;
const FLOAT_DOUBLE: u8 = MAJOR_SIMPLE | 27;

/// One pass over the text.
struct Reader<'t, 'p> {
    text: &'t [u8],
    at: usize,
    depth: usize,
    pass: Pass<'p>,
}

impl<'t, 'p> Reader<'t, 'p> {
    fn new(text: &'t [u8], pass: Pass<'p>) -> Self {
        Self {
            text,
            at: 0,
            depth: 0,
            pass,
        }
    }

    fn refuse<T>(&self, why: &'static str) -> Result<T, Refused> {
        Err(Refused { at: self.at, why })
    }

    fn document(&mut self) -> Result<(), Refused> {
        self.skip_space();
        self.value()?;
        self.skip_space();
        if self.at != self.text.len() {
            return self.refuse("text follows the value");
        }
        Ok(())
    }

    fn skip_space(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.text.get(self.at) {
            self.at += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }

    fn expect(&mut self, byte: u8, why: &'static str) -> Result<(), Refused> {
        if self.peek() == Some(byte) {
            self.at += 1;
            Ok(())
        } else {
            self.refuse(why)
        }
    }

    fn literal(&mut self, word: &[u8], head: u8) -> Result<(), Refused> {
        if self.text[self.at..].starts_with(word) {
            self.at += word.len();
            self.byte(head);
            Ok(())
        } else {
            self.refuse("not a JSON value")
        }
    }

    fn value(&mut self) -> Result<(), Refused> {
        match self.peek() {
            Some(b'{') => self.container(b'}', MAJOR_MAP),
            Some(b'[') => self.container(b']', MAJOR_ARRAY),
            Some(b'"') => self.string(),
            Some(b't') => self.literal(b"true", SIMPLE_TRUE),
            Some(b'f') => self.literal(b"false", SIMPLE_FALSE),
            Some(b'n') => self.literal(b"null", SIMPLE_NULL),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => self.refuse("not a JSON value"),
            None => self.refuse("the text ends where a value belongs"),
        }
    }

    /// An object (`close` is `}`, members are `"key": value`) or an array.
    fn container(&mut self, close: u8, major: u8) -> Result<(), Refused> {
        if self.depth == MAX_DEPTH {
            return self.refuse("nested deeper than MAX_DEPTH");
        }
        self.depth += 1;
        self.at += 1;
        let place = self.open(major);
        let mut members = 0u64;
        self.skip_space();
        if self.peek() == Some(close) {
            self.at += 1;
        } else {
            loop {
                self.skip_space();
                if major == MAJOR_MAP {
                    if self.peek() != Some(b'"') {
                        return self.refuse("an object's key is not a string");
                    }
                    self.string()?;
                    self.skip_space();
                    self.expect(b':', "a key is not followed by ':'")?;
                    self.skip_space();
                }
                self.value()?;
                members += 1;
                self.skip_space();
                match self.peek() {
                    Some(b',') => self.at += 1,
                    Some(c) if c == close => {
                        self.at += 1;
                        break;
                    }
                    _ => return self.refuse("a member is not followed by ',' or the close"),
                }
            }
        }
        self.close(place, members);
        self.depth -= 1;
        Ok(())
    }

    /// Opens a container: the count pass keeps a place for its count, the write
    /// pass writes its head from the count kept there.
    fn open(&mut self, major: u8) -> usize {
        match &mut self.pass {
            Pass::Count(counts) => {
                counts.push(0);
                counts.len() - 1
            }
            Pass::Write {
                counts, next, out, ..
            } => {
                let place = *next;
                *next += 1;
                head(major, counts[place], out);
                place
            }
        }
    }

    fn close(&mut self, place: usize, members: u64) {
        if let Pass::Count(counts) = &mut self.pass {
            counts[place] = members;
        }
    }

    fn byte(&mut self, b: u8) {
        if let Pass::Write { out, .. } = &mut self.pass {
            out.push(b);
        }
    }

    /// Where the run of plain string bytes from `from` ends: the first quote,
    /// backslash or control byte, or the end of the text.
    fn run_end(&self, from: usize) -> usize {
        self.text[from..]
            .iter()
            .position(|&b| b == b'"' || b == b'\\' || b < 0x20)
            .map_or(self.text.len(), |p| from + p)
    }

    /// A string, unescaped into a text string.
    fn string(&mut self) -> Result<(), Refused> {
        self.at += 1;
        // Most strings hold no escape: they are copied as they stand, with the
        // length their run already gave.
        let start = self.at;
        let end = self.run_end(start);
        if self.text.get(end) == Some(&b'"') {
            self.at = end + 1;
            if let Pass::Write { out, .. } = &mut self.pass {
                head(MAJOR_TEXT, (end - start) as u64, out);
                out.extend_from_slice(&self.text[start..end]);
            }
            return Ok(());
        }
        let writing = matches!(self.pass, Pass::Write { .. });
        let mut scratch = match &mut self.pass {
            Pass::Write { scratch, .. } => core::mem::take(scratch),
            Pass::Count(_) => Vec::new(),
        };
        scratch.clear();
        let result = self.string_body(writing, &mut scratch);
        if let Pass::Write {
            out, scratch: kept, ..
        } = &mut self.pass
        {
            if result.is_ok() {
                head(MAJOR_TEXT, scratch.len() as u64, out);
                out.extend_from_slice(&scratch);
            }
            *kept = scratch;
        }
        result
    }

    fn string_body(&mut self, writing: bool, into: &mut Vec<u8>) -> Result<(), Refused> {
        loop {
            // The run of bytes up to the next quote, escape or control byte is
            // copied as it stands: the text is UTF-8 already.
            let start = self.at;
            self.at = self.run_end(start);
            if writing {
                into.extend_from_slice(&self.text[start..self.at]);
            }
            match self.peek() {
                Some(b'"') => {
                    self.at += 1;
                    return Ok(());
                }
                Some(b'\\') => {
                    self.at += 1;
                    let c = self.escape()?;
                    if writing {
                        let mut buf = [0u8; 4];
                        into.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                    }
                }
                Some(_) => return self.refuse("a control byte inside a string"),
                None => return self.refuse("the text ends inside a string"),
            }
        }
    }

    /// The character an escape names; `self.at` is past the backslash.
    fn escape(&mut self) -> Result<char, Refused> {
        let Some(b) = self.peek() else {
            return self.refuse("the text ends inside an escape");
        };
        self.at += 1;
        Ok(match b {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{08}',
            b'f' => '\u{0C}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let first = self.hex4()?;
                let code = if (0xD800..0xDC00).contains(&first) {
                    // A high surrogate names a character only with the low one
                    // that follows it.
                    if !self.text[self.at..].starts_with(b"\\u") {
                        return self.refuse("a high surrogate with no low one after it");
                    }
                    self.at += 2;
                    let low = self.hex4()?;
                    if !(0xDC00..0xE000).contains(&low) {
                        return self.refuse("a high surrogate with no low one after it");
                    }
                    0x10000 + ((first - 0xD800) << 10) + (low - 0xDC00)
                } else {
                    first
                };
                match char::from_u32(code) {
                    Some(c) => c,
                    None => return self.refuse("an escape names no Unicode scalar value"),
                }
            }
            _ => return self.refuse("not a JSON escape"),
        })
    }

    fn hex4(&mut self) -> Result<u32, Refused> {
        let Some(digits) = self.text.get(self.at..self.at + 4) else {
            return self.refuse("the text ends inside a \\u escape");
        };
        let mut v = 0u32;
        for &d in digits {
            let n = match d {
                b'0'..=b'9' => d - b'0',
                b'a'..=b'f' => d - b'a' + 10,
                b'A'..=b'F' => d - b'A' + 10,
                _ => return self.refuse("a \\u escape is not four hex digits"),
            };
            v = (v << 4) | u32::from(n);
        }
        self.at += 4;
        Ok(v)
    }

    /// A number: an integer when it has no fraction and no exponent and fits
    /// CBOR's 65-bit integer range, a float otherwise.
    fn number(&mut self) -> Result<(), Refused> {
        let start = self.at;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return self.refuse("a number has no digits"),
        }
        let mut integral = true;
        if self.peek() == Some(b'.') {
            integral = false;
            self.at += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return self.refuse("a fraction has no digits");
            }
            self.digits();
        }
        if let Some(b'e' | b'E') = self.peek() {
            integral = false;
            self.at += 1;
            if let Some(b'+' | b'-') = self.peek() {
                self.at += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return self.refuse("an exponent has no digits");
            }
            self.digits();
        }
        let Pass::Write { out, .. } = &mut self.pass else {
            return Ok(());
        };
        // The text is ASCII digits and signs by construction above.
        let spelled = core::str::from_utf8(&self.text[start..self.at]).unwrap_or("");
        let digits = spelled.strip_prefix('-').unwrap_or(spelled);
        if integral {
            // Nineteen digits always fit a u64 (10^19 - 1 < 2^64), which is every
            // integer the field document writes as a number; longer ones parse.
            let magnitude = if digits.len() <= 19 {
                Some(
                    digits
                        .bytes()
                        .fold(0u64, |n, d| n * 10 + u64::from(d - b'0')),
                )
            } else {
                digits.parse::<u64>().ok()
            };
            if let Some(magnitude) = magnitude {
                match (negative, magnitude) {
                    (false, n) => head(MAJOR_UNSIGNED, n, out),
                    // `-0` is the integer 0; CBOR's negative head holds -1 - n.
                    (true, 0) => head(MAJOR_UNSIGNED, 0, out),
                    (true, n) => head(MAJOR_NEGATIVE, n - 1, out),
                }
                return Ok(());
            }
            // -2^64 is the one magnitude past u64 that a negative head holds.
            if negative && digits == "18446744073709551616" {
                head(MAJOR_NEGATIVE, u64::MAX, out);
                return Ok(());
            }
        }
        match spelled.parse::<f64>() {
            Ok(v) if v.is_finite() => {
                float(v, out);
                Ok(())
            }
            _ => Err(Refused {
                at: start,
                why: "a number that does not fit a double",
            }),
        }
    }

    fn digits(&mut self) {
        while let Some(b'0'..=b'9') = self.peek() {
            self.at += 1;
        }
    }
}

/// A head: `major` with argument `n`, in the fewest bytes (RFC 8949 §3).
fn head(major: u8, n: u64, out: &mut Vec<u8>) {
    if n < 24 {
        out.push(major | n as u8);
    } else if let Ok(n) = u8::try_from(n) {
        out.extend_from_slice(&[major | 24, n]);
    } else if let Ok(n) = u16::try_from(n) {
        out.push(major | 25);
        out.extend_from_slice(&n.to_be_bytes());
    } else if let Ok(n) = u32::try_from(n) {
        out.push(major | 26);
        out.extend_from_slice(&n.to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// A finite float in the shortest of half, single and double that holds it
/// exactly (RFC 8949 §4.1).
fn float(v: f64, out: &mut Vec<u8>) {
    let single = v as f32;
    if f64::from(single) != v {
        out.push(FLOAT_DOUBLE);
        out.extend_from_slice(&v.to_bits().to_be_bytes());
        return;
    }
    match half_of(single) {
        Some(half) => {
            out.push(FLOAT_HALF);
            out.extend_from_slice(&half.to_be_bytes());
        }
        None => {
            out.push(FLOAT_SINGLE);
            out.extend_from_slice(&single.to_bits().to_be_bytes());
        }
    }
}

/// The IEEE 754 half that holds `v` exactly, if one does. `v` is finite.
fn half_of(v: f32) -> Option<u16> {
    let bits = v.to_bits();
    let sign = ((bits >> 16) & 0x8000) as u16;
    let exponent = ((bits >> 23) & 0xFF) as i32;
    let mantissa = bits & 0x7F_FFFF;
    if exponent == 0 && mantissa == 0 {
        return Some(sign);
    }
    if exponent == 0 {
        // A single's subnormal is below every half.
        return None;
    }
    let unbiased = exponent - 127;
    if (-14..=15).contains(&unbiased) {
        // A normal half keeps ten mantissa bits.
        if mantissa & 0x1FFF != 0 {
            return None;
        }
        return Some(sign | (((unbiased + 15) as u16) << 10) | (mantissa >> 13) as u16);
    }
    if (-24..-14).contains(&unbiased) {
        // A subnormal half is m * 2^-24 with m below 1024. The single is
        // whole * 2^(unbiased - 23), so m = whole * 2^(unbiased + 1): a shift
        // right by -1 - unbiased, from 14 to 23, that must drop no set bit.
        let whole = mantissa | 0x80_0000;
        let shift = (-1 - unbiased) as u32;
        if whole & ((1 << shift) - 1) != 0 {
            return None;
        }
        return Some(sign | (whole >> shift) as u16);
    }
    None
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
}
