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

    /// The encoding's name (`json`, `cbor`): what a memory of written rows is
    /// keyed by, since the same row is other bytes in the other encoding.
    const ENCODING: &'static str;

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
    /// One value a model holds as its JSON text (RFC 8259), written as the
    /// value that text spells: [`JsonOut`] writes the text, [`CborOut`] the
    /// mapping of it ([`cbor::of_json_into`], the one reader of the mapping).
    ///
    /// The text must be one JSON value, which a model that holds a value so
    /// made with a JSON writer. [`CborOut`] writes `null` for text that is not,
    /// where [`JsonOut`] would have copied it: the encodings could disagree only
    /// over text no writer of this workspace makes.
    fn json_value(&mut self, text: &str);
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
            self.out.reserve(s.len().saturating_add(2));
            self.out.push('"');
            self.out.push_str(s);
            self.out.push('"');
        }
    }
}

impl DocOut for JsonOut {
    type Done = String;
    const ENCODING: &'static str = "json";

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
        self.out
            .reserve(bytes.len().saturating_mul(2).saturating_add(2));
        self.out.push('"');
        for &b in bytes {
            let [high, low] = cbor::hex_pair(b);
            self.out.push(char::from(high));
            self.out.push(char::from(low));
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

    fn json_value(&mut self, text: &str) {
        self.separate();
        self.out.push_str(text);
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
        self.out.as_bytes().get(mark..).unwrap_or_default()
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
                top.members = top.members.saturating_add(1);
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
    const ENCODING: &'static str = "cbor";

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
            top.members = top.members.saturating_add(1);
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
        cbor::head(
            cbor::MAJOR_TEXT,
            (bytes.len() as u64).saturating_mul(2),
            &mut self.out,
        );
        self.out.reserve(bytes.len().saturating_mul(2));
        for &b in bytes {
            self.out.extend_from_slice(&cbor::hex_pair(b));
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

    fn json_value(&mut self, text: &str) {
        self.element();
        let mark = self.out.len();
        if cbor::of_json_into(text, &mut self.out).is_err() {
            self.out.truncate(mark);
            self.out.push(cbor::SIMPLE_NULL);
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
        self.out.get(mark..).unwrap_or_default()
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

    /// The two lowercase hex digits of `b`, high first.
    pub(crate) fn hex_pair(b: u8) -> [u8; 2] {
        // Both nibbles are below 16, so neither read misses.
        let digit = |nibble: u8| HEX_DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0');
        [digit(b >> 4), digit(b & 0x0f)]
    }

    /// A head: `major` with argument `n`, in the fewest bytes (RFC 8949 §3).
    pub fn head(major: u8, n: u64, out: &mut Vec<u8>) {
        let mut wide = [0u8; 9];
        let len = head_into(major, n, &mut wide);
        out.extend_from_slice(wide.get(..len).unwrap_or(&wide));
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
        let Some(first) = out.get_mut(place) else {
            return;
        };
        *first = wide[0];
        // `place` holds a byte, so the place after it is at most the end.
        let after = place.saturating_add(1);
        if let Some(argument) = wide.get(1..len) {
            out.splice(after..after, argument.iter().copied());
        }
    }

    /// `v` as a CBOR integer, when it is in CBOR's range (-2^64 ..= 2^64 - 1);
    /// `false` and nothing written when it is not.
    pub fn int(v: i128, out: &mut Vec<u8>) -> bool {
        if let Ok(n) = u64::try_from(v) {
            head(MAJOR_UNSIGNED, n, out);
            true
        } else if let Ok(n) = u64::try_from(!v) {
            // `!v` is `-1 - v`, CBOR's negative argument, and never overflows.
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
                        // Nineteen digits fit, so neither step wraps.
                        .fold(0u64, |n, d| {
                            n.wrapping_mul(10)
                                .wrapping_add(u64::from(d.wrapping_sub(b'0')))
                        }),
                )
            } else {
                digits.parse::<u64>().ok()
            };
            if let Some(magnitude) = magnitude {
                match (negative, magnitude) {
                    (false, n) => head(MAJOR_UNSIGNED, n, out),
                    // `-0` is the integer 0; CBOR's negative head holds -1 - n.
                    (true, 0) => head(MAJOR_UNSIGNED, 0, out),
                    (true, n) => head(MAJOR_NEGATIVE, n.saturating_sub(1), out),
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
        // `exponent` is a byte, so its unbiased value and the rebias below are small.
        let unbiased = exponent.wrapping_sub(127);
        if (-14..=15).contains(&unbiased) {
            // A normal half keeps ten mantissa bits.
            if mantissa & 0x1FFF != 0 {
                return None;
            }
            return Some(
                sign | ((unbiased.wrapping_add(15) as u16) << 10) | (mantissa >> 13) as u16,
            );
        }
        if (-24..-14).contains(&unbiased) {
            // A subnormal half is m * 2^-24 with m below 1024. The single is
            // whole * 2^(unbiased - 23), so m = whole * 2^(unbiased + 1): a shift
            // right by -1 - unbiased, from 14 to 23, that must drop no set bit.
            let whole = mantissa | 0x80_0000;
            // `!unbiased` is `-1 - unbiased`, from 14 to 23 here.
            let shift = (!unbiased) as u32;
            if whole & (1u32 << shift).wrapping_sub(1) != 0 {
                return None;
            }
            return Some(sign | (whole >> shift) as u16);
        }
        None
    }

    /// Deeper nesting is refused by [`of_json_into`]. A document nests a few
    /// levels below a row; this bounds a malformed text, not a real one.
    pub const MAX_DEPTH: usize = 256;

    /// Why [`of_json_into`] refused a text, and the byte offset it was refused
    /// at.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Refused {
        /// Byte offset into the text.
        pub at: usize,
        /// What was wrong there.
        pub why: &'static str,
    }

    /// `text`, one JSON value (RFC 8259) with nothing but whitespace around
    /// it, appended to `out` as one CBOR data item: RFC 8949 §6.2's mapping
    /// under the preferred serialization the module doc states, through the
    /// same head, number and float primitives [`super::CborOut`] writes with.
    /// The one reader of that mapping: `wz-capture`'s converter is this, and
    /// so is [`super::DocOut::json_value`] of a value held as its JSON text.
    ///
    /// The text is read once. A container's head is written as one byte when
    /// it opens and completed when it closes, the bytes after it moved once
    /// when it has 24 members or more.
    ///
    /// # Errors
    ///
    /// [`Refused`] for text that is not one JSON value, a string escape that
    /// does not name a Unicode scalar value (a lone surrogate), a number that
    /// does not fit a double, and nesting deeper than [`MAX_DEPTH`]; `out` may
    /// then hold part of the item.
    pub fn of_json_into(text: &str, out: &mut Vec<u8>) -> Result<(), Refused> {
        let mut reader = Reader {
            text: text.as_bytes(),
            at: 0,
            depth: 0,
            out,
            scratch: Vec::new(),
        };
        reader.document()
    }

    /// The one pass over the text, and where it writes.
    struct Reader<'t, 'o> {
        text: &'t [u8],
        at: usize,
        depth: usize,
        out: &'o mut Vec<u8>,
        /// A string's unescaped bytes, before its length is written.
        scratch: Vec<u8>,
    }

    impl<'t> Reader<'t, '_> {
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
                self.advance(1);
            }
        }

        /// Move past `n` bytes the reader has just looked at.
        fn advance(&mut self, n: usize) {
            self.at = self.at.saturating_add(n);
        }

        /// The text from where the reader is.
        fn rest(&self) -> &'t [u8] {
            self.text.get(self.at..).unwrap_or_default()
        }

        fn peek(&self) -> Option<u8> {
            self.text.get(self.at).copied()
        }

        fn consume(&mut self, byte: u8, why: &'static str) -> Result<(), Refused> {
            if self.peek() == Some(byte) {
                self.advance(1);
                Ok(())
            } else {
                self.refuse(why)
            }
        }

        fn literal(&mut self, word: &[u8], head: u8) -> Result<(), Refused> {
            if self.rest().starts_with(word) {
                self.advance(word.len());
                self.out.push(head);
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
            // Below `MAX_DEPTH`, checked above.
            self.depth = self.depth.saturating_add(1);
            self.advance(1);
            let place = open_head(major, self.out);
            let mut members = 0u64;
            self.skip_space();
            if self.peek() == Some(close) {
                self.advance(1);
            } else {
                loop {
                    self.skip_space();
                    if major == MAJOR_MAP {
                        if self.peek() != Some(b'"') {
                            return self.refuse("an object's key is not a string");
                        }
                        self.string()?;
                        self.skip_space();
                        self.consume(b':', "a key is not followed by ':'")?;
                        self.skip_space();
                    }
                    self.value()?;
                    members = members.saturating_add(1);
                    self.skip_space();
                    match self.peek() {
                        Some(b',') => self.advance(1),
                        Some(c) if c == close => {
                            self.advance(1);
                            break;
                        }
                        _ => return self.refuse("a member is not followed by ',' or the close"),
                    }
                }
            }
            close_head(place, major, members, self.out);
            self.depth = self.depth.saturating_sub(1);
            Ok(())
        }

        /// Where the run of plain string bytes from `from` ends: the first
        /// quote, backslash or control byte, or the end of the text.
        fn run_end(&self, from: usize) -> usize {
            self.text
                .get(from..)
                .and_then(|rest| {
                    rest.iter()
                        .position(|&b| b == b'"' || b == b'\\' || b < 0x20)
                })
                .map_or(self.text.len(), |p| from.saturating_add(p))
        }

        /// A string, unescaped into a text string.
        fn string(&mut self) -> Result<(), Refused> {
            self.advance(1);
            // Most strings hold no escape: they are copied as they stand, with
            // the length their run already gave.
            let start = self.at;
            let end = self.run_end(start);
            if self.text.get(end) == Some(&b'"') {
                self.at = end.saturating_add(1);
                let run = self.text.get(start..end).unwrap_or_default();
                head(MAJOR_TEXT, run.len() as u64, self.out);
                self.out.extend_from_slice(run);
                return Ok(());
            }
            let mut scratch = core::mem::take(&mut self.scratch);
            scratch.clear();
            let result = self.string_body(&mut scratch);
            if result.is_ok() {
                head(MAJOR_TEXT, scratch.len() as u64, self.out);
                self.out.extend_from_slice(&scratch);
            }
            self.scratch = scratch;
            result
        }

        fn string_body(&mut self, into: &mut Vec<u8>) -> Result<(), Refused> {
            loop {
                // The run of bytes up to the next quote, escape or control byte
                // is copied as it stands: the text is UTF-8 already.
                let start = self.at;
                self.at = self.run_end(start);
                into.extend_from_slice(self.text.get(start..self.at).unwrap_or_default());
                match self.peek() {
                    Some(b'"') => {
                        self.advance(1);
                        return Ok(());
                    }
                    Some(b'\\') => {
                        self.advance(1);
                        let c = self.escape()?;
                        let mut buf = [0u8; 4];
                        into.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
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
            self.advance(1);
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
                        // A high surrogate names a character only with the low
                        // one that follows it.
                        if !self.rest().starts_with(b"\\u") {
                            return self.refuse("a high surrogate with no low one after it");
                        }
                        self.advance(2);
                        let low = self.hex4()?;
                        if !(0xDC00..0xE000).contains(&low) {
                            return self.refuse("a high surrogate with no low one after it");
                        }
                        // The two ranges just checked make the masks the offsets into
                        // them, and the sum at most 0x10FFFF.
                        (((first & 0x3FF) << 10) | (low & 0x3FF)).wrapping_add(0x1_0000)
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
            let Some(digits) = self.rest().get(..4) else {
                return self.refuse("the text ends inside a \\u escape");
            };
            let mut v = 0u32;
            for &d in digits {
                let Some(n) = char::from(d).to_digit(16) else {
                    return self.refuse("a \\u escape is not four hex digits");
                };
                v = (v << 4) | n;
            }
            self.advance(4);
            Ok(v)
        }

        /// A number, checked against RFC 8259 §6's grammar and then written by
        /// [`number`].
        fn number(&mut self) -> Result<(), Refused> {
            let start = self.at;
            if self.peek() == Some(b'-') {
                self.advance(1);
            }
            match self.peek() {
                Some(b'0') => self.advance(1),
                Some(b'1'..=b'9') => self.digits(),
                _ => return self.refuse("a number has no digits"),
            }
            if self.peek() == Some(b'.') {
                self.advance(1);
                if !matches!(self.peek(), Some(b'0'..=b'9')) {
                    return self.refuse("a fraction has no digits");
                }
                self.digits();
            }
            if let Some(b'e' | b'E') = self.peek() {
                self.advance(1);
                if let Some(b'+' | b'-') = self.peek() {
                    self.advance(1);
                }
                if !matches!(self.peek(), Some(b'0'..=b'9')) {
                    return self.refuse("an exponent has no digits");
                }
                self.digits();
            }
            // ASCII digits and signs by construction above.
            let spelled = core::str::from_utf8(self.text.get(start..self.at).unwrap_or_default())
                .unwrap_or("");
            if number(spelled, self.out) {
                Ok(())
            } else {
                Err(Refused {
                    at: start,
                    why: "a number that does not fit a double",
                })
            }
        }

        fn digits(&mut self) {
            while let Some(b'0'..=b'9') = self.peek() {
                self.advance(1);
            }
        }
    }
}
