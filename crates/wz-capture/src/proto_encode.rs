// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Field VALUES, as JSON, turned into protobuf wire bytes by the types a
//! `.proto` schema gives them.
//!
//! ## What this is for
//!
//! [`crate::proto_schema`] turns a schema into the NAMES of a message's fields,
//! so a payload that arrives can be read. This is the other direction, the one a
//! sender needs: a person fills in the fields of a message, and the bytes that
//! carry them must be built. A consumer that built them itself would hold a
//! second writer of the wire format beside the one reader, and two writers
//! disagree exactly where the format is unusual: a `sint32` is zigzagged and an
//! `int32` is not, a negative `int32` is ten bytes, a proto3 field at its default
//! is absent, a packed field is one length-delimited run. This is the one writer.
//!
//! The schema is read by the same reader, from the same list of files, under the
//! same rules ([`crate::proto_schema`]: imports are matched by name, nothing is
//! read from a disk). What is added here is a message to build, `root_message`,
//! and the values.
//!
//! ## The values: protobuf's JSON mapping
//!
//! The values are one JSON object, keyed by field, in the mapping the protobuf
//! documentation calls the canonical JSON encoding ("ProtoJSON") -- the form a
//! person or another tool is most likely to already hold:
//!
//! * a field is written under its name as the `.proto` file spells it (`sensor_id`)
//!   or under its JSON name, which is that name in lowerCamelCase (`sensorId`)
//!   unless the field sets `json_name`. Naming the same field twice, in either
//!   form, is refused, and so is a key that is no field;
//! * a message is an object; a repeated field is an array; a `map` is an object
//!   whose keys are the map keys written as strings (`"7"`, `"true"`);
//! * `int32`, `uint32`, `sint32`, `fixed32`, `sfixed32` and the 64-bit kinds are
//!   a JSON number or a decimal string, and the string is how a 64-bit value
//!   survives a reader that holds numbers as doubles. A number must be an
//!   integer (`1.0` and `1e3` are accepted, `1.5` is not) and fit the type, as
//!   a `(nanopb).int_size` written in the schema narrows it for the varint
//!   kinds ([`crate::proto_range`]: a `uint32` under `IS_8` takes 0 to 255,
//!   because nanopb's decoder refuses what its C integer cannot hold). A
//!   string is digits with an optional sign (`"-5"`, `"007"`) and nothing else:
//!   `"1.0"` and `"1e3"` are refused, as protobuf's own parser refuses them, and
//!   so is a minus sign in a string for an unsigned type, even on a zero
//!   (`"-0"`);
//! * `float` and `double` are a number, a decimal string, or one of the strings
//!   `"NaN"`, `"Infinity"` and `"-Infinity"`; a finite value that does not fit a
//!   `float` is refused rather than turned into infinity;
//! * `bool` is `true` or `false`; `string` is a string; `bytes` is a base64
//!   string, in the standard or the URL-safe alphabet (not both in one string),
//!   with or without padding;
//! * an enum is the NAME of one of its values or an integer (a JSON number, or a
//!   string of digits, which a name cannot be); a proto2 enum is closed, so an
//!   integer that is none of its values is refused, where a proto3 enum takes
//!   any `int32`;
//! * `null` means "not set" for a field and is refused as an array element or a
//!   map value, where there is nothing to leave out.
//!
//! The text is read by the workspace's one JSON reader
//! ([`wz_session_core::json5`]), which reads JSON5, so comments, trailing commas
//! and unquoted keys are admitted, as they are by the end-to-end doors; a number
//! is then held to strict JSON (`0x10` and `+1` are refused). Nesting deeper than
//! [`MAX_VALUES_DEPTH`] levels is refused before the tree is built, because the
//! reader recurses once per level.
//!
//! The well-known types (`Timestamp`, `Duration`, `Any`, the wrappers, `Struct`)
//! have a special JSON form in the mapping, a string or a bare value. This
//! library does not carry them (see [`crate::proto_schema`]), and a message of
//! one of those names is written from its fields like any other, as an object.
//! Handed the special form, the error says so.
//!
//! ## The bytes
//!
//! The bytes are written by the workspace's one protobuf writer
//! (`wz_app_frame::proto_write`), the one a program's payload set field by
//! field writes through too, so the two cannot write one message apart. This
//! module reads the values and judges each against its field; the writer turns
//! a judged value into bytes, holding an integer to nanopb's range
//! (`Narrowing::NanopbIntSize`).
//!
//! * Fields are written in ascending field NUMBER, whatever the order in the
//!   file or in the JSON. Each field is written once.
//! * A proto3 singular field that is not in a oneof, not `optional` and not a
//!   message is written only when its value is not the default: `0`, `false`, the
//!   empty string, the empty bytes, the first enum value's number zero, and a
//!   float or double whose bits are all zero -- so `-0.0` IS written. That is
//!   how `protoc` 3.21.12 writes it; `protoc` 3.12.4 compares the value with zero
//!   and omits it, and the door does not follow it, so the sign survives. No
//!   source in this tree says which release changed it. The oracle in
//!   `wz-integration-tests` decides by running the judge, not by its version. A
//!   field with presence is written whenever the JSON gives
//!   it: a message field (a proto3 message field has presence), a member of a
//!   oneof, an `optional` field and a `required` one, in either syntax.
//!   Giving two members of one oneof is refused. A missing `required` field is
//!   refused.
//! * A repeated field of a numeric, `bool` or enum type is one length-delimited
//!   run of its elements ("packed") in proto3, unless it sets `[packed = false]`,
//!   and one tag per element in proto2, unless it sets `[packed = true]`. A
//!   repeated string, bytes or message field is one tag per element. An empty
//!   array writes nothing.
//! * A map is a repeated field of entry messages whose key is field 1 and whose
//!   value is field 2, both always written, the entries in ascending key order
//!   (numeric for integer keys, `false` before `true`, byte order for strings),
//!   so the same values always give the same bytes. An integer key is a string
//!   of digits with an optional sign, and a key written twice, in whatever
//!   spelling (`"1"`, `"+1"` and `"01"` are one key), is refused.
//! * `int32` and an enum are a varint of the sign-extended value (a negative one
//!   is ten bytes), `sint32` and `sint64` are zigzag, `fixed32`, `sfixed32` and
//!   `float` are four bytes little-endian, `fixed64`, `sfixed64` and `double` are
//!   eight.
//!
//! ## What is refused
//!
//! A `group` field, and an `extension` addressed as `"[pkg.ext]"`: groups are
//! written with the deprecated group markers, which the payload reader cannot
//! read back, and an extension is no field of the message it extends. Both are
//! refused where the JSON NAMES them, not where the schema holds them, so a
//! message with a group that the values leave out is written as usual. Anything
//! else the JSON gets wrong is refused with the place and the type that was
//! expected; nothing is converted by guessing (a string where a number belongs, a
//! number that is not an integer where one is needed, a name that is no field).
//!
//! A `json_name` or `packed` option the writer cannot act on (a `json_name` that
//! is not a string, a `packed` that is not `true` or `false`, `[packed = true]`
//! on a string) is a schema error, blamed at the option's value like any other
//! place in a file. `json_name` is judged for every field of a message the
//! values reach, because it decides which keys that message answers to; `packed`
//! only for a field the values name.
//!
//! A varint integer field whose `(nanopb).int_size` cannot be read refuses every
//! value given for it, as a VALUE error at that value: the range nanopb would
//! hold it to is not known, and writing a value that a receiver may refuse is
//! the outcome the range exists to prevent.
//!
//! ## Where it differs from libprotobuf's own JSON parser
//!
//! MEASURED against `JsonToBinaryString` of libprotobuf 3.21.12 over 309
//! inputs (the 28 messages `wz-integration-tests` holds to `protoc --encode`
//! and 281 more written to be awkward), 284 of which both read to the same
//! message or both refuse (the bytes differ, since that parser writes in JSON
//! order, writes defaults and does not pack, so the comparison was on what
//! `protoc --decode` makes of each). The 25 that differ are all places where
//! this writer says no and that parser makes something up, except one where it
//! is the other way round. The probe is not part of the repository.
//!
//! * a `bool` given as a string (`"true"`, and also `"True"` and `"yes"`), and a
//!   `bool` map key other than `"true"` and `"false"`;
//! * a scalar for a repeated field (it wraps one), a `null` array element (it
//!   drops it) and a `null` map value (it writes the default);
//! * a field or a map key given twice (it writes both), which here is an error
//!   because the same name cannot mean two values;
//! * a float string that is not JSON number grammar (`".5"`, `"1."`, `"+1.5"`,
//!   `"0x10"`: it reads them as `strtod` does) and the number token `5.`;
//! * an integer for a closed proto2 enum that none of its values has;
//! * the other way round, this reader admits JSON5 (comments, single quotes,
//!   unquoted keys), which that parser refuses.
//!
//! Where both accept, they agree on the message: every integer, float, string,
//! base64 and enum form the module documentation lists was run through both.
//!
//! ## Where the first problem is found
//!
//! The first problem is the only one reported, in this order: an argument
//! (`root_file`, a duplicate file name), the schema ([`crate::proto_schema`]'s
//! order), the root message, whether the values are JSON, and then the values
//! from the top down, in the order the JSON is written. The place of a problem
//! with the values is an RFC 6901 JSON pointer, `/readings/2/celsius`, the form
//! the end-to-end doors use, and a text that is not JSON gives the byte offset
//! instead.
//!
//! ## Bounds
//!
//! The output is at most [`MAX_ENCODED_BYTES`]; work is linear in the text of
//! the values and of the schema, except that a message with `n` fields keeps a
//! table of its `2n` spellings. Recursive messages are fine here: the values are
//! finite, so unlike the declarations the recursion ends where the JSON does.
//!
//! ## The seam for the end-to-end wrap
//!
//! [`encode_message`] takes the schema files, the root file, the root message and
//! the values text, and returns the bytes: everything a door that wraps a body in
//! a protection header needs from this module, and nothing about a header. That
//! door passes the same four arguments and reads the bytes it gets back as its
//! payload. [`encode_tree`] is the same writer for a door whose values arrive as
//! one member of a larger JSON text and so are already a tree
//! ([`crate::e2e_body`] is that door's reader).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use wz_session_core::json5::{self, Json5Value};
use wz_session_core::json5_lex::{Json5Error, Lexer};

use wz_app_frame::proto_write::{self, Narrowing, PackedRefusal, Wire};

use crate::proto_nanopb::IntSize;
use crate::proto_parse::{Label, OptionValue, ScalarKind, Syntax};
use crate::proto_range::{value_range, RangeRefusal, RangeSource, ValueRange};
use crate::proto_schema::{FieldKind, Fld, Linker, MapValueKind, Msg, ProtoDiagnostic, ProtoFile};

/// The most bytes a message may encode to.
pub const MAX_ENCODED_BYTES: usize = 4 * 1024 * 1024;

/// How deeply the values may nest. A message inside a message is one level for
/// the object, and a repeated or map field adds one more for the array or the
/// object of entries, so this admits about thirty messages deep: far more than
/// the payload reader walks (eight) or `protoc` compiles (thirty-one levels of
/// nested definitions).
pub const MAX_VALUES_DEPTH: usize = 64;

/// Why bytes could not be built, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The schema, or an argument about it, was refused: the same diagnostic
    /// [`crate::proto_schema::declarations_from_proto`] gives.
    Schema(ProtoDiagnostic),
    /// The values text is not JSON, and this is the byte where reading stopped.
    Syntax {
        /// Offset into the values text.
        offset: usize,
        /// What the reader expected there.
        expected: &'static str,
    },
    /// The values are JSON and do not fit the schema.
    Value(ValueError),
}

/// A value that does not fit its field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValueError {
    /// An RFC 6901 JSON pointer to the place in the values: empty for the whole
    /// text, `/readings/2/celsius` for a value inside it.
    pub path: String,
    /// The full name of the schema field the value was for (`pkg.Reading.celsius`),
    /// absent when the problem is about a message as a whole.
    pub field: Option<String>,
    /// What would have been accepted there, in a sentence.
    pub expected: Option<String>,
    /// What is wrong, in a sentence.
    pub reason: String,
}

impl fmt::Display for EncodeError {
    /// The one-line form: the schema diagnostic's own line, `values at byte N:
    /// ...` for text that is not JSON, and `values {path}: {reason}` for a value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema(d) => write!(f, "{d}"),
            Self::Syntax { offset, expected } => write!(
                f,
                "values at byte {offset}: the text is not JSON: expected {expected}"
            ),
            Self::Value(v) if v.path.is_empty() => write!(f, "values: {}", v.reason),
            Self::Value(v) => write!(f, "values {}: {}", v.path, v.reason),
        }
    }
}

/// Build the wire bytes of the message `root_message` whose fields are the JSON
/// object `values`.
///
/// `files` and `root_file` are read as [`crate::proto_schema::declarations_from_proto`]
/// reads them, and `root_message` is a full name including the package. See the
/// module documentation for the mapping, the bytes and the order problems are
/// found in.
///
/// # Errors
///
/// An [`EncodeError`] for the first problem found.
pub fn encode_message(
    root_message: &str,
    files: &[ProtoFile<'_>],
    root_file: usize,
    values: &str,
) -> Result<Vec<u8>, EncodeError> {
    let linker = Linker::read(files, root_file).map_err(EncodeError::Schema)?;
    let root = linker
        .root_message(root_message, root_file)
        .map_err(EncodeError::Schema)?;
    let tree = read_values(values)?;
    write_linked(&linker, root, &tree)
}

/// Build the wire bytes of the message `root_message` from `values`, a tree the
/// caller already holds: the entry for a caller whose values are one member of
/// a larger JSON text, such as the end-to-end wrap door, whose description
/// carries the body beside the header's values.
///
/// The arguments and the order problems are found in are [`encode_message`]'s,
/// less the step that reads the text: the schema, the root message, then the
/// values from the top down. The place a [`ValueError`] names is a JSON pointer
/// into `values`, so a caller that found the tree under a key of its own
/// prefixes the pointer with that key's. The error is never
/// [`EncodeError::Syntax`], because no text is read here.
///
/// The caller bounds the nesting of the text it builds the tree from, as
/// [`encode_message`] does for its own: the writer recurses once per level of
/// the tree, and [`MAX_VALUES_DEPTH`] is the bound it was written for.
///
/// # Errors
///
/// An [`EncodeError`] for the first problem found.
pub fn encode_tree(
    root_message: &str,
    files: &[ProtoFile<'_>],
    root_file: usize,
    values: &Json5Value,
) -> Result<Vec<u8>, EncodeError> {
    let linker = Linker::read(files, root_file).map_err(EncodeError::Schema)?;
    let root = linker
        .root_message(root_message, root_file)
        .map_err(EncodeError::Schema)?;
    write_linked(&linker, root, values)
}

/// The bytes of message `root` of a linked schema, from a tree.
fn write_linked(
    linker: &Linker<'_, '_>,
    root: usize,
    tree: &Json5Value,
) -> Result<Vec<u8>, EncodeError> {
    let mut encoder = Encoder {
        schema: linker,
        tables: (0..linker.msgs.len()).map(|_| None).collect(),
    };
    encoder.message(root, tree, "")
}

/// The values text as a tree, or where it stops being JSON.
fn read_values(text: &str) -> Result<Json5Value, EncodeError> {
    let syntax = |e: Json5Error| EncodeError::Syntax {
        offset: e.offset,
        expected: e.expected,
    };
    // The bounded walk first: it checks the whole grammar and refuses a nesting
    // past the bound without recursing beyond it, which the tree builder below
    // does not do for itself.
    let mut lexer = Lexer::new(text);
    lexer.skip_trivia().map_err(syntax)?;
    lexer.skip_value(MAX_VALUES_DEPTH).map_err(syntax)?;
    json5::parse(text).map_err(syntax)
}

// ---- the wire ------------------------------------------------------------

/// The integers this writer holds a value to: nanopb's, so that a value a
/// receiver that links nanopb would refuse is refused here, at its place in the
/// values, and not by that receiver.
const NARROWING: Narrowing = Narrowing::NanopbIntSize;

// ---- JSON numbers --------------------------------------------------------

/// A JSON number or a decimal string, taken apart.
struct Decimal<'t> {
    negative: bool,
    int_digits: &'t str,
    frac_digits: &'t str,
    exponent: i64,
}

/// Read `text` as strict JSON number grammar, `-?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)?`.
///
/// Stricter than the JSON5 reader's own number scan, which also admits hex, a
/// leading `+`, a bare `.5` and `5.`: none of those is a protobuf JSON number.
fn decimal(text: &str) -> Option<Decimal<'_>> {
    let bytes = text.as_bytes();
    let mut at = 0;
    let negative = bytes.first() == Some(&b'-');
    if negative {
        at += 1;
    }
    let int_start = at;
    while bytes.get(at).is_some_and(u8::is_ascii_digit) {
        at += 1;
    }
    let int_digits = &text[int_start..at];
    if int_digits.is_empty() || (int_digits.len() > 1 && int_digits.starts_with('0')) {
        return None;
    }
    let mut frac_digits = "";
    if bytes.get(at) == Some(&b'.') {
        at += 1;
        let start = at;
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        frac_digits = &text[start..at];
        if frac_digits.is_empty() {
            return None;
        }
    }
    let mut exponent = 0i64;
    if matches!(bytes.get(at), Some(b'e' | b'E')) {
        at += 1;
        let negative_exponent = bytes.get(at) == Some(&b'-');
        if matches!(bytes.get(at), Some(b'-' | b'+')) {
            at += 1;
        }
        let start = at;
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        if at == start {
            return None;
        }
        for d in text[start..at].bytes() {
            // Saturating: an exponent this large is out of range for every type
            // here, and the digit count test below says so.
            exponent = exponent
                .saturating_mul(10)
                .saturating_add(i64::from(d - b'0'));
        }
        if negative_exponent {
            exponent = -exponent;
        }
    }
    (at == bytes.len()).then_some(Decimal {
        negative,
        int_digits,
        frac_digits,
        exponent,
    })
}

/// Why a number is not an integer a field can hold.
enum IntegerError {
    NotAnInteger,
    OutOfRange,
}

/// The exact integer `d` denotes, or why it is none.
///
/// Done on the digits and not through a float, so a 64-bit value keeps all its
/// bits: `18446744073709551615` is exact, where a double would round it.
fn integer_value(d: &Decimal<'_>) -> Result<i128, IntegerError> {
    // At most 30 digits are ever held, well inside `i128`; a number with more
    // significant digits than that is out of range for every 64-bit kind.
    const MAX_DIGITS: usize = 30;
    let mut digits = String::with_capacity(d.int_digits.len() + d.frac_digits.len());
    digits.push_str(d.int_digits);
    digits.push_str(d.frac_digits);
    let significant = digits.trim_start_matches('0');
    if significant.is_empty() {
        return Ok(0);
    }
    let scale = d.exponent - d.frac_digits.len() as i64;
    let magnitude: &str;
    let zeros: usize;
    if scale >= 0 {
        if scale > MAX_DIGITS as i64 || significant.len() + scale as usize > MAX_DIGITS {
            return Err(IntegerError::OutOfRange);
        }
        magnitude = significant;
        zeros = scale as usize;
    } else {
        let drop = scale.unsigned_abs();
        if drop >= significant.len() as u64 {
            return Err(IntegerError::NotAnInteger);
        }
        let (kept, dropped) = significant.split_at(significant.len() - drop as usize);
        if dropped.bytes().any(|b| b != b'0') {
            return Err(IntegerError::NotAnInteger);
        }
        if kept.len() > MAX_DIGITS {
            return Err(IntegerError::OutOfRange);
        }
        magnitude = kept;
        zeros = 0;
    }
    let mut value: i128 = 0;
    for b in magnitude.bytes() {
        value = value * 10 + i128::from(b - b'0');
    }
    for _ in 0..zeros {
        value *= 10;
    }
    Ok(if d.negative { -value } else { value })
}

/// The integer a string denotes when it is `[+-]?[0-9]+`: a sign is allowed and
/// so are leading zeros, which a JSON number would not have. `None` for any
/// other text, and for one with more significant digits than any 64-bit kind
/// holds (it is out of range for all of them, and the range check says so).
fn string_integer(text: &str) -> Option<i128> {
    let (negative, digits) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let significant = digits.trim_start_matches('0');
    // Wide of the 64-bit range and narrow of `i128`'s: past this it is out of
    // range for every kind and the exact value is of no use.
    if significant.len() > 30 {
        return Some(if negative { i128::MIN } else { i128::MAX });
    }
    let magnitude = significant
        .bytes()
        .fold(0i128, |v, b| v * 10 + i128::from(b - b'0'));
    Some(if negative { -magnitude } else { magnitude })
}

/// Base64, either alphabet (not both in one string), padding optional.
fn base64_decode(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    let padding = bytes.iter().rev().take_while(|&&b| b == b'=').count();
    if padding > 2 {
        return Err(format!(
            "{padding} padding characters; a base64 group has at most two"
        ));
    }
    let body = &bytes[..bytes.len() - padding];
    // The characters first, so that a space or a newline is called what it is
    // and not a length that comes out wrong because of it.
    if let Some((i, &b)) = body
        .iter()
        .enumerate()
        .find(|(_, b)| !(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_')))
    {
        return Err(format!(
            "byte {b:#04x} at index {i} is not a base64 character"
        ));
    }
    if padding > 0 && !bytes.len().is_multiple_of(4) {
        return Err(String::from(
            "padding is present but the text is not a whole number of four-character groups",
        ));
    }
    let standard = body.iter().any(|b| matches!(b, b'+' | b'/'));
    let url_safe = body.iter().any(|b| matches!(b, b'-' | b'_'));
    if standard && url_safe {
        return Err(String::from(
            "the standard alphabet (+ /) and the URL-safe alphabet (- _) are mixed in one string",
        ));
    }
    if body.len() % 4 == 1 {
        return Err(String::from(
            "one character left over after the last whole group: not a valid length",
        ));
    }
    let mut out = Vec::with_capacity(body.len() / 4 * 3 + 2);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for (i, &b) in body.iter().enumerate() {
        let sextet = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => {
                return Err(format!(
                    "byte {b:#04x} at index {i} is not a base64 character"
                ))
            }
        };
        accumulator = (accumulator << 6) | u32::from(sextet);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    if accumulator != 0 {
        return Err(String::from(
            "the last character carries bits beyond the data: not the canonical encoding",
        ));
    }
    Ok(out)
}

/// protoc's default JSON name for a field: each `_` is dropped and the letter
/// after it is upper-cased (`descriptor.cc`, `ToJsonName`).
pub(crate) fn default_json_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut upper = false;
    for c in name.chars() {
        if c == '_' {
            upper = true;
        } else if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// `path` with one more step: an object member's name, escaped (RFC 6901).
fn child(path: &str, key: &str) -> String {
    let mut out = String::from(path);
    out.push('/');
    for c in key.chars() {
        match c {
            '~' => out.push_str("~0"),
            '/' => out.push_str("~1"),
            c => out.push(c),
        }
    }
    out
}

fn describe(value: &Json5Value) -> &'static str {
    match value {
        Json5Value::Null => "null",
        Json5Value::Bool(_) => "a boolean",
        Json5Value::Number(_) => "a number",
        Json5Value::String(_) => "a string",
        Json5Value::Array(_) => "an array",
        Json5Value::Object(_) => "an object",
    }
}

/// A map key, ordered the way the entries are written.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum MapKey {
    /// Every integer kind and `bool`, as the number the wire carries.
    Number(i128),
    Text(String),
}

// ---- the encoder ---------------------------------------------------------

/// Where a value is, for the diagnostics that blame it.
struct Place<'p> {
    path: &'p str,
    /// The field the value is for.
    field: &'p str,
    /// The integers a value here may be, or why there is no such range: judged
    /// once per field by [`crate::proto_range`], so the writer refuses exactly
    /// what the description document says the field cannot hold.
    range: Result<ValueRange, RangeRefusal>,
}

/// The spellings a message's fields answer to, built the first time the message
/// is written.
type Spellings = BTreeMap<String, Vec<usize>>;

struct Encoder<'l, 'f, 'a> {
    schema: &'l Linker<'f, 'a>,
    /// Per message, filled on first use: building it can fail on a malformed
    /// `json_name`, which only matters to a message the values reach.
    tables: Vec<Option<Spellings>>,
}

/// A JSON member resolved to the field it is for.
struct Member<'v> {
    field: usize,
    key: &'v str,
    value: &'v Json5Value,
}

impl Encoder<'_, '_, '_> {
    fn msg(&self, idx: usize) -> &Msg {
        &self.schema.msgs[idx]
    }

    fn value_error(
        &self,
        path: &str,
        field: Option<&str>,
        expected: Option<String>,
        reason: impl Into<String>,
    ) -> EncodeError {
        EncodeError::Value(ValueError {
            path: String::from(path),
            field: field.map(String::from),
            expected,
            reason: reason.into(),
        })
    }

    fn schema_error(&self, file: usize, pos: crate::proto_lex::Pos, reason: String) -> EncodeError {
        EncodeError::Schema(ProtoDiagnostic::at(self.schema.name_of(file), pos, reason))
    }

    fn field_name(&self, msg: usize, f: &Fld) -> String {
        format!("{}.{}", self.msg(msg).full_name, f.name)
    }

    /// The option `name` of a field, if the field sets it.
    fn option<'g>(f: &'g Fld, name: &str) -> Option<&'g crate::proto_parse::FieldOption> {
        f.options.iter().find(|o| o.name == name)
    }

    /// The JSON name `f` answers to besides its own name.
    fn json_name(&self, msg: usize, f: &Fld) -> Result<String, EncodeError> {
        match Self::option(f, "json_name") {
            None => Ok(default_json_name(&f.name)),
            Some(o) => match &o.value {
                OptionValue::Str(name) => Ok(name.clone()),
                _ => Err(self.schema_error(
                    self.msg(msg).file,
                    o.value_pos,
                    String::from("the option `json_name` takes a string"),
                )),
            },
        }
    }

    fn ensure_table(&mut self, msg: usize) -> Result<(), EncodeError> {
        if self.tables[msg].is_some() {
            return Ok(());
        }
        let mut table: Spellings = BTreeMap::new();
        for (i, f) in self.msg(msg).fields.iter().enumerate() {
            let json = self.json_name(msg, f)?;
            for spelling in [f.name.clone(), json] {
                let entry = table.entry(spelling).or_default();
                if !entry.contains(&i) {
                    entry.push(i);
                }
            }
        }
        self.tables[msg] = Some(table);
        Ok(())
    }

    /// Match every member of the object to the field it names.
    fn resolve<'v>(
        &mut self,
        msg: usize,
        entries: &'v [(String, Json5Value)],
        path: &str,
    ) -> Result<Vec<Member<'v>>, EncodeError> {
        self.ensure_table(msg)?;
        let table = self.tables[msg].as_ref();
        let message = self.msg(msg);
        let mut members: Vec<Member<'v>> = Vec::with_capacity(entries.len());
        for (key, value) in entries {
            let here = child(path, key);
            if key.starts_with('[') && key.ends_with(']') {
                return Err(self.value_error(
                    &here,
                    None,
                    None,
                    format!(
                        "`{key}` names an extension of `{}`; extensions are not supported here",
                        message.full_name
                    ),
                ));
            }
            let found = table.and_then(|t| t.get(key.as_str()));
            let field = match found.map(Vec::as_slice) {
                Some([only]) => *only,
                Some(several) => {
                    let names: Vec<&str> = several
                        .iter()
                        .map(|&i| message.fields[i].name.as_str())
                        .collect();
                    return Err(self.value_error(
                        &here,
                        None,
                        None,
                        format!(
                            "`{key}` is the name of several fields of `{}` ({}), so it does not \
                             say which one is meant",
                            message.full_name,
                            names.join(", ")
                        ),
                    ));
                }
                None => {
                    let mut names: Vec<&str> =
                        message.fields.iter().map(|f| f.name.as_str()).collect();
                    names.truncate(32);
                    return Err(self.value_error(
                        &here,
                        None,
                        Some(format!(
                            "one of the fields of `{}`: {}",
                            message.full_name,
                            names.join(", ")
                        )),
                        format!("`{}` has no field `{key}`", message.full_name),
                    ));
                }
            };
            if let Some(first) = members.iter().find(|m| m.field == field) {
                return Err(self.value_error(
                    &here,
                    Some(&format!(
                        "{}.{}",
                        message.full_name, message.fields[field].name
                    )),
                    None,
                    format!(
                        "the field `{}` is given twice: as `{}` and as `{key}`",
                        message.fields[field].name, first.key
                    ),
                ));
            }
            members.push(Member { field, key, value });
        }
        Ok(members)
    }

    /// The bytes of the message `msg` whose fields `value` gives.
    fn message(
        &mut self,
        msg: usize,
        value: &Json5Value,
        path: &str,
    ) -> Result<Vec<u8>, EncodeError> {
        let Json5Value::Object(entries) = value else {
            let name = self.msg(msg).full_name.clone();
            let mut reason = format!(
                "expected an object for the message `{name}`, found {}",
                describe(value)
            );
            if name.starts_with("google.protobuf.") {
                reason.push_str(
                    "; this library writes a well-known type from its fields, as an object, \
                     and does not read its special JSON form",
                );
            }
            return Err(self.value_error(
                path,
                None,
                Some(format!("a JSON object for `{name}`")),
                reason,
            ));
        };
        // A null leaves the field out, as if it were not written. (The key was
        // resolved first, so a null under a key that is no field is still refused.)
        let mut members: Vec<Member<'_>> = self
            .resolve(msg, entries, path)?
            .into_iter()
            .filter(|m| !matches!(m.value, Json5Value::Null))
            .collect();

        // At most one member of a oneof.
        let mut taken: BTreeMap<usize, usize> = BTreeMap::new();
        for m in &members {
            let f = &self.msg(msg).fields[m.field];
            if let Some(oneof) = f.oneof {
                if let Some(&earlier) = taken.get(&oneof) {
                    return Err(self.value_error(
                        &child(path, m.key),
                        Some(&self.field_name(msg, f)),
                        None,
                        format!(
                            "`{}` is in the oneof `{}` of `{}`, which already has `{}` set; \
                             a oneof holds one field",
                            f.name,
                            self.msg(msg).oneofs[oneof],
                            self.msg(msg).full_name,
                            self.msg(msg).fields[earlier].name
                        ),
                    ));
                }
                taken.insert(oneof, m.field);
            }
        }
        // A proto2 `required` field must be there.
        for (i, f) in self.msg(msg).fields.iter().enumerate() {
            if f.label == Label::Required && !members.iter().any(|m| m.field == i) {
                return Err(self.value_error(
                    path,
                    Some(&self.field_name(msg, f)),
                    Some(format!("a value for the required field `{}`", f.name)),
                    format!(
                        "the required field `{}` of `{}` is missing",
                        f.name,
                        self.msg(msg).full_name
                    ),
                ));
            }
        }

        // Ascending field number, whatever the order written.
        members.sort_by_key(|m| self.msg(msg).fields[m.field].number);
        let mut out = Vec::new();
        for m in &members {
            self.field(msg, m, path, &mut out)?;
            if out.len() > MAX_ENCODED_BYTES {
                return Err(self.value_error(
                    &child(path, m.key),
                    None,
                    None,
                    format!("the message encodes to more than {MAX_ENCODED_BYTES} bytes"),
                ));
            }
        }
        Ok(out)
    }

    /// Append one field, tags included.
    fn field(
        &mut self,
        msg: usize,
        member: &Member<'_>,
        path: &str,
        out: &mut Vec<u8>,
    ) -> Result<(), EncodeError> {
        let here = child(path, member.key);
        let (number, kind, label, presence, name, range, file) = {
            let message = self.msg(msg);
            let f = &message.fields[member.field];
            (
                f.number,
                f.kind,
                f.label,
                proto_write::has_presence(message, f),
                self.field_name(msg, f),
                NARROWING.field_range(self.schema, message, f),
                message.file,
            )
        };
        let place = Place {
            path: &here,
            field: &name,
            range,
        };
        match kind {
            FieldKind::Group => Err(self.value_error(
                &here,
                Some(&name),
                None,
                "a group field cannot be written: a group is delimited by the deprecated \
                 start-group and end-group markers, which this library does not write",
            )),
            FieldKind::Map { key, value } => {
                self.map(number, file, key, value, member.value, &place, out)
            }
            _ if label == Label::Repeated => {
                self.repeated(msg, member.field, number, kind, member.value, &place, out)
            }
            _ => {
                let wire = self.single(kind, member.value, &place)?;
                proto_write::put_singular(out, number, presence, &wire);
                Ok(())
            }
        }
    }

    /// One non-repeated value of a field of this kind.
    fn single(
        &mut self,
        kind: FieldKind,
        value: &Json5Value,
        place: &Place<'_>,
    ) -> Result<Wire<'static>, EncodeError> {
        match kind {
            FieldKind::Scalar(scalar) => self.scalar(scalar, value, place),
            FieldKind::Enum(e) => self.enum_value(e, value, place),
            FieldKind::Message(inner) => {
                let bytes = self.message(inner, value, place.path)?;
                Ok(Wire::delimited(bytes))
            }
            FieldKind::Group | FieldKind::Map { .. } => Err(self.value_error(
                place.path,
                Some(place.field),
                None,
                "internal: a group or a map reached the single-value path",
            )),
        }
    }

    // ---- repeated and map ------------------------------------------------

    /// Whether the repeated field is written packed, by the writer's rule; a
    /// `packed` it cannot act on is a schema error at the option's value.
    fn packed(&self, msg: usize, f: &Fld) -> Result<bool, EncodeError> {
        let file = self.msg(msg).file;
        proto_write::packed(self.msg(msg), f).map_err(|refusal| match refusal {
            PackedRefusal::NotPackable(option) => self.schema_error(
                file,
                option.value_pos,
                format!(
                    "`[packed = true]` can only be set on a repeated field of a numeric, bool \
                     or enum type; `{}` is not",
                    f.name
                ),
            ),
            PackedRefusal::NotABool(option) => self.schema_error(
                file,
                option.value_pos,
                String::from("the option `packed` takes `true` or `false`"),
            ),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn repeated(
        &mut self,
        msg: usize,
        field: usize,
        number: u64,
        kind: FieldKind,
        value: &Json5Value,
        place: &Place<'_>,
        out: &mut Vec<u8>,
    ) -> Result<(), EncodeError> {
        let Json5Value::Array(items) = value else {
            return Err(self.value_error(
                place.path,
                Some(place.field),
                Some(String::from("an array: the field is repeated")),
                format!("expected an array, found {}", describe(value)),
            ));
        };
        let packed = self.packed(msg, &self.msg(msg).fields[field])?;
        let mut wires: Vec<Wire<'static>> = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            let at = format!("{}/{i}", place.path);
            if matches!(item, Json5Value::Null) {
                return Err(self.value_error(
                    &at,
                    Some(place.field),
                    None,
                    "null is not an element: there is nothing to leave out of an array",
                ));
            }
            wires.push(self.single(
                kind,
                item,
                &Place {
                    path: &at,
                    field: place.field,
                    range: place.range,
                },
            )?);
        }
        proto_write::put_repeated(out, number, packed, &wires);
        Ok(())
    }

    /// A map field written in file `file`, whose entries' key and value take
    /// their ranges from that file's options alone.
    #[allow(clippy::too_many_arguments)]
    fn map(
        &mut self,
        number: u64,
        file: usize,
        key: ScalarKind,
        value: MapValueKind,
        json: &Json5Value,
        place: &Place<'_>,
        out: &mut Vec<u8>,
    ) -> Result<(), EncodeError> {
        let Json5Value::Object(entries) = json else {
            return Err(self.value_error(
                place.path,
                Some(place.field),
                Some(String::from("an object: the field is a map")),
                format!("expected an object, found {}", describe(json)),
            ));
        };
        let key_range = NARROWING.map_entry_range(self.schema, file, key);
        let (value_kind, entry_value_range) = match value {
            MapValueKind::Scalar(s) => (
                FieldKind::Scalar(s),
                NARROWING.map_entry_range(self.schema, file, s),
            ),
            MapValueKind::Enum(e) => (FieldKind::Enum(e), Err(RangeRefusal::Enum)),
            MapValueKind::Message(m) => (FieldKind::Message(m), Err(RangeRefusal::NotAnInteger)),
        };
        let mut sorted: BTreeMap<MapKey, Vec<u8>> = BTreeMap::new();
        for (text, item) in entries {
            let at = child(place.path, text);
            if matches!(item, Json5Value::Null) {
                return Err(self.value_error(
                    &at,
                    Some(place.field),
                    None,
                    "null is not a map value: there is nothing to leave out of a map",
                ));
            }
            let key_place = Place {
                path: &at,
                field: place.field,
                range: key_range,
            };
            let (ordering, key_wire) = self.map_key(key, text, &key_place)?;
            let value_place = Place {
                path: &at,
                field: place.field,
                range: entry_value_range,
            };
            let value_wire = self.single(value_kind, item, &value_place)?;
            let entry = proto_write::map_entry(&key_wire, &value_wire);
            if sorted.insert(ordering, entry).is_some() {
                return Err(self.value_error(
                    &at,
                    Some(place.field),
                    None,
                    format!("the map key `{text}` is given twice"),
                ));
            }
        }
        for entry in sorted.into_values() {
            proto_write::put_field(out, number, &Wire::delimited(entry));
        }
        Ok(())
    }

    /// A map key from the text of the object member that holds it.
    fn map_key(
        &self,
        kind: ScalarKind,
        text: &str,
        place: &Place<'_>,
    ) -> Result<(MapKey, Wire<'static>), EncodeError> {
        match kind {
            ScalarKind::String => Ok((
                MapKey::Text(String::from(text)),
                Wire::delimited(text.as_bytes().to_vec()),
            )),
            ScalarKind::Bool => match text {
                "true" => Ok((MapKey::Number(1), Wire::Varint(1))),
                "false" => Ok((MapKey::Number(0), Wire::Varint(0))),
                _ => Err(self.value_error(
                    place.path,
                    Some(place.field),
                    Some(String::from(
                        "a bool map key: the string \"true\" or \"false\"",
                    )),
                    format!("`{text}` is not a bool map key"),
                )),
            },
            _ => {
                let number = Self::bounds(kind, place.range)
                    .and_then(|range| Self::integer(kind, range, text, true))
                    .map_err(|reason| {
                        self.value_error(
                            place.path,
                            Some(place.field),
                            Some(format!(
                                "a {} map key, written as a string of digits",
                                kind.keyword()
                            )),
                            reason,
                        )
                    })?;
                Ok((MapKey::Number(number), Wire::integer(kind, number)))
            }
        }
    }

    /// The integer `text` denotes, if it is one and `kind` can hold it.
    ///
    /// `text` is the source text of a JSON number, which may carry a fraction or
    /// an exponent as long as the value is whole (`1.0`, `1e3`), or, when
    /// `from_string`, the contents of a JSON string, which is digits with an
    /// optional sign and nothing else: protobuf's JSON mapping reads a string
    /// as an integer in the 64-bit sense, and `"1.0"` or `"1e3"` is not one.
    /// (`protobuf`'s own parser agrees; MEASURED against libprotobuf 3.21.12.)
    ///
    /// `range` is the field's judged range ([`Self::bounds`]), which a nanopb
    /// `int_size` may have narrowed below the type's.
    fn integer(
        kind: ScalarKind,
        range: ValueRange,
        text: &str,
        from_string: bool,
    ) -> Result<i128, String> {
        let ValueRange { low, high, source } = range;
        // A string for an unsigned type takes no minus sign, not even on a zero
        // (`"-0"`); a JSON number `-0` is the number zero and is read as one.
        // Both are as libprotobuf 3.21.12 reads them, MEASURED.
        if low == 0 && from_string && text.starts_with('-') {
            return Err(format!(
                "`{text}` is out of range for {}: an unsigned type takes no minus sign",
                kind.keyword()
            ));
        }
        let integer = if from_string {
            string_integer(text).ok_or_else(|| {
                format!("`{text}` is not a decimal integer: a string of digits with an optional sign is needed")
            })?
        } else {
            let Some(parts) = decimal(text) else {
                return Err(format!(
                    "`{text}` is not a decimal integer: a plain JSON number or a string of digits \
                     is needed"
                ));
            };
            match integer_value(&parts) {
                Ok(v) => v,
                Err(IntegerError::NotAnInteger) => {
                    return Err(format!("`{text}` is not an integer"))
                }
                Err(IntegerError::OutOfRange) => return Err(format!("`{text}` is out of range")),
            }
        };
        if integer < low || integer > high {
            return Err(match source {
                RangeSource::Type => format!("`{text}` is out of range for {}", kind.keyword()),
                // The type admits the value and nanopb's decoder would not, so
                // the sentence names the option and the range it leaves.
                RangeSource::NanopbIntSize { .. } => format!(
                    "`{text}` is out of range for {}: {low} to {high}",
                    Self::type_phrase(kind, range)
                ),
            });
        }
        Ok(integer)
    }

    /// The range an integer of `kind` at a place is held to, or the sentence
    /// that refuses every value there because the range cannot be known.
    fn bounds(
        kind: ScalarKind,
        judged: Result<ValueRange, RangeRefusal>,
    ) -> Result<ValueRange, String> {
        match judged {
            Ok(range) => Ok(range),
            Err(RangeRefusal::UnmodelledOption) => Err(format!(
                "the field's nanopb options (an int_size this reader cannot read, or a \
                 type_override) leave unknown the range of the values nanopb takes for \
                 this {}, so no value is written",
                kind.keyword()
            )),
            // Not reached for an integer kind, whose place always carries a
            // range or the refusal above; the type is the honest bound if it is.
            Err(RangeRefusal::NotAnInteger | RangeRefusal::Enum | RangeRefusal::Map) => {
                ValueRange::of_type(kind).ok_or_else(|| {
                    format!(
                        "internal: an integer was asked of a {}, which holds none",
                        kind.keyword()
                    )
                })
            }
        }
    }

    /// The type a range is the range of: the keyword, and the nanopb option
    /// beside it when the option narrowed it.
    fn type_phrase(kind: ScalarKind, range: ValueRange) -> String {
        match range.source {
            RangeSource::Type => String::from(kind.keyword()),
            RangeSource::NanopbIntSize { bits } => {
                format!("{} with (nanopb).int_size = IS_{bits}", kind.keyword())
            }
        }
    }

    // ---- scalars ---------------------------------------------------------

    fn expected_scalar(kind: ScalarKind, judged: Result<ValueRange, RangeRefusal>) -> String {
        match kind {
            ScalarKind::Double | ScalarKind::Float => format!(
                "{}: a JSON number, a decimal string, or one of the strings \"NaN\", \
                 \"Infinity\" and \"-Infinity\"",
                kind.keyword()
            ),
            ScalarKind::Bool => String::from("bool: true or false"),
            ScalarKind::String => String::from("string: a JSON string"),
            ScalarKind::Bytes => String::from(
                "bytes: a base64 string, standard or URL-safe alphabet, padding optional",
            ),
            _ => match Self::bounds(kind, judged) {
                Ok(range) => format!(
                    "{}: an integer from {} to {}, as a JSON number or a decimal string",
                    Self::type_phrase(kind, range),
                    range.low,
                    range.high
                ),
                Err(_) => format!(
                    "{}: an integer in the range nanopb takes for the field, which its \
                     nanopb options leave unknown",
                    kind.keyword()
                ),
            },
        }
    }

    fn scalar(
        &self,
        kind: ScalarKind,
        value: &Json5Value,
        place: &Place<'_>,
    ) -> Result<Wire<'static>, EncodeError> {
        let bad = |reason: String| {
            self.value_error(
                place.path,
                Some(place.field),
                Some(Self::expected_scalar(kind, place.range)),
                reason,
            )
        };
        match kind {
            ScalarKind::Bool => match value {
                Json5Value::Bool(b) => Ok(Wire::Varint(u64::from(*b))),
                other => Err(bad(format!(
                    "expected true or false, found {}",
                    describe(other)
                ))),
            },
            ScalarKind::String => match value {
                Json5Value::String(s) => Ok(Wire::delimited(s.as_bytes().to_vec())),
                other => Err(bad(format!("expected a string, found {}", describe(other)))),
            },
            ScalarKind::Bytes => match value {
                Json5Value::String(s) => base64_decode(s)
                    .map(Wire::delimited)
                    .map_err(|why| bad(format!("not valid base64: {why}"))),
                other => Err(bad(format!(
                    "expected a base64 string, found {}",
                    describe(other)
                ))),
            },
            ScalarKind::Float | ScalarKind::Double => {
                let text = match value {
                    Json5Value::Number(t) => t.as_str(),
                    Json5Value::String(t) => t.as_str(),
                    other => {
                        return Err(bad(format!(
                            "expected a number or a string, found {}",
                            describe(other)
                        )))
                    }
                };
                self.float(kind, text, matches!(value, Json5Value::String(_)))
                    .map_err(bad)
            }
            _ => {
                let text = match value {
                    Json5Value::Number(t) => t.as_str(),
                    Json5Value::String(t) => t.as_str(),
                    other => {
                        return Err(bad(format!(
                            "expected a number or a decimal string, found {}",
                            describe(other)
                        )))
                    }
                };
                Self::bounds(kind, place.range)
                    .and_then(|range| {
                        Self::integer(kind, range, text, matches!(value, Json5Value::String(_)))
                    })
                    .map(|v| Wire::integer(kind, v))
                    .map_err(bad)
            }
        }
    }

    /// `float` or `double` from the text of a JSON number or string.
    fn float(
        &self,
        kind: ScalarKind,
        text: &str,
        from_string: bool,
    ) -> Result<Wire<'static>, String> {
        let single = kind == ScalarKind::Float;
        if from_string {
            let special = match text {
                "NaN" => Some(f64::NAN),
                "Infinity" => Some(f64::INFINITY),
                "-Infinity" => Some(f64::NEG_INFINITY),
                _ => None,
            };
            if let Some(v) = special {
                return Ok(if single {
                    Wire::Fixed32((v as f32).to_bits())
                } else {
                    Wire::Fixed64(v.to_bits())
                });
            }
        }
        if decimal(text).is_none() {
            return Err(format!(
                "`{text}` is not a decimal number: a plain JSON number, a string of one, or \
                 \"NaN\", \"Infinity\", \"-Infinity\" is needed"
            ));
        }
        // Parsed at the type's own width, so the nearest value to the decimal is
        // chosen once and not by way of a double.
        if single {
            match text.parse::<f32>() {
                Ok(v) if v.is_finite() => Ok(Wire::Fixed32(v.to_bits())),
                _ => Err(format!("`{text}` is out of range for float")),
            }
        } else {
            match text.parse::<f64>() {
                Ok(v) if v.is_finite() => Ok(Wire::Fixed64(v.to_bits())),
                _ => Err(format!("`{text}` is out of range for double")),
            }
        }
    }

    fn enum_value(
        &self,
        e: usize,
        value: &Json5Value,
        place: &Place<'_>,
    ) -> Result<Wire<'static>, EncodeError> {
        let info = &self.schema.enums[e];
        let names: Vec<&str> = info.values.iter().map(|(n, _)| n.as_str()).collect();
        let expected = format!(
            "enum `{}`: the name of one of its values ({}), or an integer",
            info.full_name,
            names.join(", ")
        );
        let bad = |reason: String| {
            self.value_error(
                place.path,
                Some(place.field),
                Some(expected.clone()),
                reason,
            )
        };
        // An enum's number is an int32 whatever `int_size` the schema sets: the
        // values it may hold are the enum's own, which are judged below.
        let int32 = Self::bounds(
            ScalarKind::Int32,
            value_range(ScalarKind::Int32, IntSize::Default),
        )
        .map_err(bad)?;
        // Whether the number came from the text of the JSON and not from a name
        // in the schema: only a number can be one the enum does not have.
        let mut written_as_number = true;
        let number = match value {
            Json5Value::String(name) => {
                if let Some((_, number)) = info.values.iter().find(|(n, _)| n == name) {
                    written_as_number = false;
                    *number
                } else if string_integer(name).is_some() {
                    // A name cannot be digits, so a string of digits is a number
                    // and cannot be a misspelt name; protobuf's own parser reads
                    // it the same way.
                    Self::integer(ScalarKind::Int32, int32, name, true).map_err(bad)?
                } else {
                    return Err(bad(format!(
                        "`{name}` is not a value of the enum `{}`",
                        info.full_name
                    )));
                }
            }
            Json5Value::Number(text) => {
                Self::integer(ScalarKind::Int32, int32, text, false).map_err(bad)?
            }
            other => {
                return Err(bad(format!(
                    "expected a value name or an integer, found {}",
                    describe(other)
                )))
            }
        };
        // The schema's own number for a name can be out of range too, which
        // `protoc` refuses and the reader of the schema does not judge.
        if number < i128::from(i32::MIN) || number > i128::from(i32::MAX) {
            return Err(bad(format!(
                "{number} is out of range for an enum, which is an int32"
            )));
        }
        // A proto2 enum is closed: a number that names none of its values is
        // not a value of it.
        if written_as_number
            && info.syntax == Syntax::Proto2
            && !info.values.iter().any(|(_, n)| *n == number)
        {
            return Err(bad(format!(
                "{number} is none of the values of `{}`, and a proto2 enum is closed",
                info.full_name
            )));
        }
        Ok(Wire::Varint(number as i64 as u64))
    }
}
