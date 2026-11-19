// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ONE DOCUMENT, TWO ENCODINGS: the seam a document writer writes its keys and
//! values through, and the two encodings behind it.
//!
//! # Why a writer says what it writes and not how it is spelled
//!
//! The dissection documents were written as JSON text, and the binary door of
//! one of them converted that text to CBOR afterwards. The conversion was one
//! derivation of every fact (the writer's), but it paid for each fact three
//! times: the writer spelled it, the converter parsed the spelling, and the
//! converter wrote it again. A writer that says `key`, `uint`, `text` to a
//! [`DocOut`] writes each fact once, in whichever encoding the door wants, and
//! it is still the one writer: [`JsonOut`] and [`CborOut`] hold no fact of
//! their own, only a spelling.
//!
//! # The two encodings are one document
//!
//! [`CborOut`] writes exactly the bytes RFC 8949 §6.2's mapping of
//! [`JsonOut`]'s text gives, under the preferred serialization of §4.1: an
//! object is a map of text keys with a definite length, an array an array, a
//! string a text string, `true` / `false` / `null` the simple values 21 / 20 /
//! 22, an integer an integer in the fewest bytes, and any other number the
//! shortest of half, single and double that holds it exactly. That is the
//! mapping `wz-capture`'s `cbor_of_json` converter implements, and it encodes
//! through the primitives of [`cbor`] here, so the converter applied to the JSON
//! encoding and this writer agree byte for byte by construction; the tests of
//! that crate hold every document of the corpus to it.
//!
//! What either encoding says about a value is the WRITER's choice and not the
//! sink's: a `u64` written with [`DocOut::uint`] is a bare number in both, and
//! one written with [`DocOut::uint_exact`] is the digits in a string past
//! 2^53 - 1 in both ([`crate::json::u64_into`]'s rule), because the reader of
//! the binary form reads the same document the text reader does.
//!
//! # Separators
//!
//! A writer never spells a comma. [`JsonOut`] puts one before every member
//! after the first; [`CborOut`] counts the members instead and completes the
//! container's head when it closes. A container's head is written as one byte
//! when it opens, which is the whole head of any container of fewer than 24
//! members, and widened when it closes with the bytes after it moved once.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Write as _;

/// The structured writer a document is written through. See the module doc.
///
/// A key is written before every member of a map; a map's members and an
/// array's elements are values, and a container is a value. A writer that
/// breaks that order writes a malformed document in either encoding, which is
/// what the tests of each document hold it to.
pub trait DocOut: Default {
    /// What a finished writer holds: the encoded document, or the one item it
    /// was used to encode.
    type Done;

    /// The encoded bytes, and the writer let go.
    fn finish(self) -> Self::Done;

    /// Opens a map (a JSON object).
    fn open_map(&mut self);
    /// Closes the innermost open map.
    fn close_map(&mut self);
    /// Opens an array.
    fn open_array(&mut self);
    /// Closes the innermost open array.
    fn close_array(&mut self);

    /// The key of the next member of the innermost map, as text.
    fn key(&mut self, key: &str);

    /// A text string.
    fn text(&mut self, s: &str);
    /// A text string formatted from `args`.
    fn text_fmt(&mut self, args: fmt::Arguments<'_>);
    /// A text string of `bytes` in lowercase hex, two digits each.
    fn hex(&mut self, bytes: &[u8]);

    /// An unsigned integer, as a bare number whatever its size.
    fn uint(&mut self, v: u64);
    /// A signed integer, as a bare number.
    fn int(&mut self, v: i64);
    /// An integer of up to 128 bits, as a bare number. The binary form holds one
    /// past CBOR's integer range as the float that is nearest to it, as the
    /// mapping of its JSON spelling does.
    fn int_wide(&mut self, v: i128);
    /// A number spelled as JSON spells one (RFC 8259 §6): an integer without
    /// fraction or exponent, or any other number, which is a float.
    fn number(&mut self, spelled: &str);
    /// [`Self::number`] spelled by `args`.
    fn number_fmt(&mut self, args: fmt::Arguments<'_>);
    /// `true` or `false`.
    fn bool(&mut self, v: bool);
    /// `null`.
    fn null(&mut self);

    /// Begins the next element of the innermost array whose own encoding is
    /// wanted, and returns where it begins: [`Self::written_since`] from there,
    /// once the element is written, is that element and nothing else.
    fn begin_item(&mut self) -> usize;
    /// The bytes written since `mark`.
    fn written_since(&self, mark: usize) -> &[u8];
    /// One element of the innermost array that a writer of this kind finished
    /// as a whole ([`Self::finish`] of a writer that wrote one value).
    fn splice(&mut self, item: &Self::Done);

    /// An unsigned integer under the exact-integer rule: a bare number up to
    /// [`crate::json::MAX_EXACT_INTEGER`], its digits in a string beyond.
    fn uint_exact(&mut self, v: u64) {
        if v <= crate::json::MAX_EXACT_INTEGER {
            self.uint(v);
        } else {
            self.text_fmt(format_args!("{v}"));
        }
    }

    /// [`Self::uint`] of `v`, or `null`.
    fn opt_uint(&mut self, v: Option<u64>) {
        match v {
            Some(v) => self.uint(v),
            None => self.null(),
        }
    }

    /// [`Self::text`] of `s`, or `null`.
    fn opt_text(&mut self, s: Option<&str>) {
        match s {
            Some(s) => self.text(s),
            None => self.null(),
        }
    }

    /// [`Self::bool`] of `v`, or `null`.
    fn opt_bool(&mut self, v: Option<bool>) {
        match v {
            Some(v) => self.bool(v),
            None => self.null(),
        }
    }
}

/// THE JSON ENCODING: compact RFC 8259 text, with no whitespace, written into a
/// `String`.
#[derive(Debug, Default)]
pub struct JsonOut {
    out: String,
    /// A value was the last thing written in the innermost container, so the
    /// next member is separated from it by a comma.
    after_value: bool,
}

impl JsonOut {
    /// A writer over `out`, whose next value is the first of its container (or
    /// follows a key `out` already ends with).
    pub fn over(out: String) -> Self {
        Self {
            out,
            after_value: false,
        }
    }

    /// Writes one value with `write` onto the end of `out`, which ends where a
    /// value belongs: after a key, an opening bracket, or a comma. The bridge for
    /// a text writer that hands a value to a [`DocOut`] writer.
    pub fn value_onto(out: &mut String, write: impl FnOnce(&mut Self)) {
        let mut json = Self::over(core::mem::take(out));
        write(&mut json);
        *out = json.out;
    }

    /// Writes members of an object with `write` onto the end of `out`, which
    /// ends inside that object after a member: each key `write` writes is
    /// separated from what precedes it. The bridge for a text writer that
    /// hands the rest of an object's members to a [`DocOut`] writer.
    pub fn members_onto(out: &mut String, write: impl FnOnce(&mut Self)) {
        let mut json = Self {
            out: core::mem::take(out),
            after_value: true,
        };
        write(&mut json);
        *out = json.out;
    }

    /// The text written so far.
    pub fn as_str(&self) -> &str {
        &self.out
    }

    fn separate(&mut self) {
        if self.after_value {
            self.out.push(',');
        }
    }

    fn quoted(&mut self, s: &str) {
        // The escape table is `crate::json`'s; a string with nothing in it to
        // escape, which is nearly every string a document writes, is copied.
        if s.bytes().any(|b| b == b'"' || b == b'\\' || b < 0x20) {
            crate::json::escape_into(s, &mut self.out);
        } else {
            self.out.reserve(s.len() + 2);
            self.out.push('"');
            self.out.push_str(s);
            self.out.push('"');
        }
    }
}

impl DocOut for JsonOut {
    type Done = String;

    fn finish(self) -> String {
        self.out
    }

    fn open_map(&mut self) {
        self.separate();
        self.out.push('{');
        self.after_value = false;
    }

    fn close_map(&mut self) {
        self.out.push('}');
        self.after_value = true;
    }

    fn open_array(&mut self) {
        self.separate();
        self.out.push('[');
        self.after_value = false;
    }

    fn close_array(&mut self) {
        self.out.push(']');
        self.after_value = true;
    }

    fn key(&mut self, key: &str) {
        self.separate();
        self.quoted(key);
        self.out.push(':');
        self.after_value = false;
    }

    fn text(&mut self, s: &str) {
        self.separate();
        self.quoted(s);
        self.after_value = true;
    }

    fn text_fmt(&mut self, args: fmt::Arguments<'_>) {
        self.separate();
        self.out.push('"');
        let _ = crate::json::JsonStringBody(&mut self.out).write_fmt(args);
        self.out.push('"');
        self.after_value = true;
    }

    fn hex(&mut self, bytes: &[u8]) {
        self.separate();
        self.out.reserve(bytes.len() * 2 + 2);
        self.out.push('"');
        for &b in bytes {
            self.out.push(cbor::HEX_DIGITS[usize::from(b >> 4)] as char);
            self.out
                .push(cbor::HEX_DIGITS[usize::from(b & 0x0f)] as char);
        }
        self.out.push('"');
        self.after_value = true;
    }

    fn uint(&mut self, v: u64) {
        self.separate();
        let _ = write!(self.out, "{v}");
        self.after_value = true;
    }

    fn int(&mut self, v: i64) {
        self.separate();
        let _ = write!(self.out, "{v}");
        self.after_value = true;
    }

    fn int_wide(&mut self, v: i128) {
        self.separate();
        let _ = write!(self.out, "{v}");
        self.after_value = true;
    }

    fn number(&mut self, spelled: &str) {
        self.separate();
        self.out.push_str(spelled);
        self.after_value = true;
    }

    fn number_fmt(&mut self, args: fmt::Arguments<'_>) {
        self.separate();
        let _ = self.out.write_fmt(args);
        self.after_value = true;
    }

    fn bool(&mut self, v: bool) {
        self.separate();
        self.out.push_str(if v { "true" } else { "false" });
        self.after_value = true;
    }

    fn null(&mut self) {
        self.separate();
        self.out.push_str("null");
        self.after_value = true;
    }

    fn begin_item(&mut self) -> usize {
        self.separate();
        self.after_value = false;
        self.out.len()
    }

    fn written_since(&self, mark: usize) -> &[u8] {
        &self.out.as_bytes()[mark..]
    }

    fn splice(&mut self, item: &String) {
        self.separate();
        self.out.push_str(item);
        self.after_value = true;
    }
}

/// THE CBOR ENCODING (RFC 8949), under preferred serialization, written into a
/// `Vec<u8>`. See the module doc for the mapping it shares with the JSON one.
#[derive(Debug, Default)]
pub struct CborOut {
    out: Vec<u8>,
    /// Every open container, innermost last: where its head is and how many
    /// members it has so far (a map counts a key and its value as one).
    open: Vec<Open>,
    /// A formatted string or number, before its length is known.
    scratch: String,
}

#[derive(Debug, Clone, Copy)]
struct Open {
    place: usize,
    major: u8,
    members: u64,
}

impl CborOut {
    /// A writer with room for `bytes` before it grows.
    pub fn with_capacity(bytes: usize) -> Self {
        Self {
            out: Vec::with_capacity(bytes),
            ..Self::default()
        }
    }

    /// Counts the value about to be written as a member of the innermost
    /// array. A map's member was counted at its key.
    fn element(&mut self) {
        if let Some(top) = self.open.last_mut() {
            if top.major == cbor::MAJOR_ARRAY {
                top.members += 1;
            }
        }
    }

    fn open(&mut self, major: u8) {
        self.element();
        self.open.push(Open {
            place: cbor::open_head(major, &mut self.out),
            major,
            members: 0,
        });
    }

    fn close(&mut self) {
        if let Some(open) = self.open.pop() {
            cbor::close_head(open.place, open.major, open.members, &mut self.out);
        }
    }

    fn text_bytes(&mut self, bytes: &[u8]) {
        cbor::head(cbor::MAJOR_TEXT, bytes.len() as u64, &mut self.out);
        self.out.extend_from_slice(bytes);
    }
}

impl DocOut for CborOut {
    type Done = Vec<u8>;

    fn finish(self) -> Vec<u8> {
        self.out
    }

    fn open_map(&mut self) {
        self.open(cbor::MAJOR_MAP);
    }

    fn close_map(&mut self) {
        self.close();
    }

    fn open_array(&mut self) {
        self.open(cbor::MAJOR_ARRAY);
    }

    fn close_array(&mut self) {
        self.close();
    }

    fn key(&mut self, key: &str) {
        if let Some(top) = self.open.last_mut() {
            top.members += 1;
        }
        self.text_bytes(key.as_bytes());
    }

    fn text(&mut self, s: &str) {
        self.element();
        self.text_bytes(s.as_bytes());
    }

    fn text_fmt(&mut self, args: fmt::Arguments<'_>) {
        self.element();
        let mut scratch = core::mem::take(&mut self.scratch);
        scratch.clear();
        let _ = scratch.write_fmt(args);
        self.text_bytes(scratch.as_bytes());
        self.scratch = scratch;
    }

    fn hex(&mut self, bytes: &[u8]) {
        self.element();
        cbor::head(cbor::MAJOR_TEXT, bytes.len() as u64 * 2, &mut self.out);
        self.out.reserve(bytes.len() * 2);
        for &b in bytes {
            self.out.push(cbor::HEX_DIGITS[usize::from(b >> 4)]);
            self.out.push(cbor::HEX_DIGITS[usize::from(b & 0x0f)]);
        }
    }

    fn uint(&mut self, v: u64) {
        self.element();
        cbor::head(cbor::MAJOR_UNSIGNED, v, &mut self.out);
    }

    fn int(&mut self, v: i64) {
        self.element();
        cbor::int(i128::from(v), &mut self.out);
    }

    fn int_wide(&mut self, v: i128) {
        self.element();
        if !cbor::int(v, &mut self.out) {
            // Past CBOR's integers: the JSON spelling's nearest double, which is
            // what the mapping of that spelling writes.
            let mut scratch = core::mem::take(&mut self.scratch);
            scratch.clear();
            let _ = write!(scratch, "{v}");
            cbor::number(&scratch, &mut self.out);
            self.scratch = scratch;
        }
    }

    fn number(&mut self, spelled: &str) {
        self.element();
        cbor::number(spelled, &mut self.out);
    }

    fn number_fmt(&mut self, args: fmt::Arguments<'_>) {
        self.element();
        let mut scratch = core::mem::take(&mut self.scratch);
        scratch.clear();
        let _ = scratch.write_fmt(args);
        cbor::number(&scratch, &mut self.out);
        self.scratch = scratch;
    }

    fn bool(&mut self, v: bool) {
        self.element();
        self.out.push(if v {
            cbor::SIMPLE_TRUE
        } else {
            cbor::SIMPLE_FALSE
        });
    }

    fn null(&mut self) {
        self.element();
        self.out.push(cbor::SIMPLE_NULL);
    }

    fn begin_item(&mut self) -> usize {
        self.out.len()
    }

    fn written_since(&self, mark: usize) -> &[u8] {
        &self.out[mark..]
    }

    fn splice(&mut self, item: &Vec<u8>) {
        self.element();
        self.out.extend_from_slice(item);
    }
}

/// The CBOR primitives both [`CborOut`] and `wz-capture`'s JSON-to-CBOR
/// converter encode through, so the two cannot spell a head, an integer or a
/// float differently.
pub mod cbor {
    use alloc::vec::Vec;

    /// CBOR major types, shifted into the head byte's top three bits.
    pub const MAJOR_UNSIGNED: u8 = 0 << 5;
    #[allow(missing_docs)]
    pub const MAJOR_NEGATIVE: u8 = 1 << 5;
    #[allow(missing_docs)]
    pub const MAJOR_TEXT: u8 = 3 << 5;
    #[allow(missing_docs)]
    pub const MAJOR_ARRAY: u8 = 4 << 5;
    #[allow(missing_docs)]
    pub const MAJOR_MAP: u8 = 5 << 5;
    #[allow(missing_docs)]
    pub const MAJOR_SIMPLE: u8 = 7 << 5;

    /// The simple values and float heads of major type 7.
    pub const SIMPLE_FALSE: u8 = MAJOR_SIMPLE | 20;
    #[allow(missing_docs)]
    pub const SIMPLE_TRUE: u8 = MAJOR_SIMPLE | 21;
    #[allow(missing_docs)]
    pub const SIMPLE_NULL: u8 = MAJOR_SIMPLE | 22;
    #[allow(missing_docs)]
    pub const FLOAT_HALF: u8 = MAJOR_SIMPLE | 25;
    #[allow(missing_docs)]
    pub const FLOAT_SINGLE: u8 = MAJOR_SIMPLE | 26;
    #[allow(missing_docs)]
    pub const FLOAT_DOUBLE: u8 = MAJOR_SIMPLE | 27;

    pub(crate) const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

    /// A head: `major` with argument `n`, in the fewest bytes (RFC 8949 §3).
    pub fn head(major: u8, n: u64, out: &mut Vec<u8>) {
        let mut wide = [0u8; 9];
        let len = head_into(major, n, &mut wide);
        out.extend_from_slice(&wide[..len]);
    }

    /// The head of `major` with argument `n`, into `wide`; returns how many of
    /// its bytes it took.
    pub fn head_into(major: u8, n: u64, wide: &mut [u8; 9]) -> usize {
        if n < 24 {
            wide[0] = major | n as u8;
            1
        } else if let Ok(n) = u8::try_from(n) {
            wide[0] = major | 24;
            wide[1] = n;
            2
        } else if let Ok(n) = u16::try_from(n) {
            wide[0] = major | 25;
            wide[1..3].copy_from_slice(&n.to_be_bytes());
            3
        } else if let Ok(n) = u32::try_from(n) {
            wide[0] = major | 26;
            wide[1..5].copy_from_slice(&n.to_be_bytes());
            5
        } else {
            wide[0] = major | 27;
            wide[1..9].copy_from_slice(&n.to_be_bytes());
            9
        }
    }

    /// Opens a container: its head's first byte, holding no count yet. Returns
    /// where that byte is, for [`close_head`].
    pub fn open_head(major: u8, out: &mut Vec<u8>) -> usize {
        let place = out.len();
        out.push(major);
        place
    }

    /// Completes the head [`open_head`] put at `place` with the container's
    /// count. Under 24 the count fits the byte already there; past it, the
    /// argument bytes go in after that byte and the members written since move
    /// along by their width.
    pub fn close_head(place: usize, major: u8, members: u64, out: &mut Vec<u8>) {
        let mut wide = [0u8; 9];
        let len = head_into(major, members, &mut wide);
        out[place] = wide[0];
        if len > 1 {
            out.splice(place + 1..place + 1, wide[1..len].iter().copied());
        }
    }

    /// `v` as a CBOR integer, when it is in CBOR's range (-2^64 ..= 2^64 - 1);
    /// `false` and nothing written when it is not.
    pub fn int(v: i128, out: &mut Vec<u8>) -> bool {
        if let Ok(n) = u64::try_from(v) {
            head(MAJOR_UNSIGNED, n, out);
            true
        } else if let Ok(n) = u64::try_from(-1 - v) {
            head(MAJOR_NEGATIVE, n, out);
            true
        } else {
            false
        }
    }

    /// A number spelled as JSON spells one, which the caller has checked
    /// against RFC 8259 §6's grammar: an integer when it has no fraction and no
    /// exponent and fits CBOR's 65-bit integer range, a float otherwise.
    /// Returns `false`, having written nothing, for a number that does not fit
    /// a double.
    pub fn number(spelled: &str, out: &mut Vec<u8>) -> bool {
        let negative = spelled.starts_with('-');
        let digits = spelled.strip_prefix('-').unwrap_or(spelled);
        let integral = !digits.bytes().any(|b| matches!(b, b'.' | b'e' | b'E'));
        if integral {
            // Nineteen digits always fit a u64 (10^19 - 1 < 2^64), which is every
            // integer a document writes as a number; longer ones parse.
            let magnitude = if digits.len() <= 19 {
                Some(
                    digits
                        .bytes()
                        .fold(0u64, |n, d| n * 10 + u64::from(d.wrapping_sub(b'0'))),
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
                return true;
            }
            // -2^64 is the one magnitude past u64 that a negative head holds.
            if negative && digits == "18446744073709551616" {
                head(MAJOR_NEGATIVE, u64::MAX, out);
                return true;
            }
        }
        match spelled.parse::<f64>() {
            Ok(v) if v.is_finite() => {
                float(v, out);
                true
            }
            _ => false,
        }
    }

    /// A finite float in the shortest of half, single and double that holds it
    /// exactly (RFC 8949 §4.1).
    pub fn float(v: f64, out: &mut Vec<u8>) {
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
    pub fn half_of(v: f32) -> Option<u16> {
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
}
