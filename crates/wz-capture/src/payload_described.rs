// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2114 (open-debt item 237) — a payload format a deployment DESCRIBES, in
//! the declaration dialect, instead of implementing in Rust.
//!
//! ## The gap this closes
//!
//! [`crate::payload::formats::PayloadFormat`] is an extension point and its own
//! doc says so: "a consumer implements [it] for a proprietary format without
//! patching this crate". True for a Rust consumer. A deployment that LINKS the
//! C ABI had no way in at all -- to see its own format it had to build this
//! workspace, which is a capability gap on the axis this project is measured
//! by. [`crate::payload_builtin`]'s own header names the case: an AUTOSAR E2E
//! profile is "a CRC, a counter and a data id at offsets the PROFILE fixes",
//! and the profile table belongs to the deployment rather than to this tree.
//!
//! ## Why data and not a function pointer
//!
//! The obvious shape -- let the caller register a decoder callback -- is
//! REFUSED, and not for taste. `wz_dissect.h`'s memory rule is the ABI's whole
//! contract and it says "no callbacks run": a callback is the caller's control
//! flow executing inside this library, on a stack this library owns. Closing
//! this item with one would have silently voided the header's contract to gain
//! a feature.
//!
//! What crosses instead is TEXT, through the door that already takes text
//! (`wz_dissect_pcap_fields_with_payloads`) and is already validated without a
//! capture by `wz_dissect_declarations_diagnose`. Data can be versioned,
//! diagnosed and refused; it has no lifetime and no stack. The two surfaces
//! gain the capability with no new symbol and no new flag, which is what the
//! register item asked for.
//!
//! ## What it can and cannot describe
//!
//! A FIXED RECORD: named fields at fixed widths, in order, with an optional
//! `rest` at the end for a variable tail. That is what a profile table is. It
//! is deliberately not a general grammar -- no conditionals, no lengths read
//! from the payload, no repetition -- because each of those is a small
//! interpreter, and an interpreter reached from a C string is a much larger
//! promise than "your record has these fields at these offsets".
//!
//! A record whose bytes do not account exactly is a FINDING rather than a
//! quiet success: trailing bytes the layout never claimed come back as
//! [`PayloadFormatError::Malformed`], because a short description over a long
//! record renders a clean-looking decode of the wrong thing.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::payload::formats::{PayloadField, PayloadFormat, PayloadFormatError};

/// One field's width and how its bytes are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An unsigned integer of this many bytes, little-endian.
    UnsignedLe(usize),
    /// An unsigned integer of this many bytes, big-endian.
    UnsignedBe(usize),
    /// A two's-complement signed integer of this many bytes, little-endian.
    SignedLe(usize),
    /// A two's-complement signed integer of this many bytes, big-endian.
    SignedBe(usize),
    /// An IEEE-754 float of this many bytes (4 or 8), little-endian.
    FloatLe(usize),
    /// An IEEE-754 float of this many bytes (4 or 8), big-endian.
    FloatBe(usize),
    /// Exactly this many raw bytes, rendered as hex.
    Bytes(usize),
    /// Every byte left, rendered as hex. Only legal as the LAST field.
    Rest,
}

impl Kind {
    /// The bytes this field takes, or `None` for [`Kind::Rest`], whose width is
    /// a property of the payload rather than of the layout.
    fn width(self) -> Option<usize> {
        match self {
            Self::UnsignedLe(n)
            | Self::UnsignedBe(n)
            | Self::SignedLe(n)
            | Self::SignedBe(n)
            | Self::FloatLe(n)
            | Self::FloatBe(n)
            | Self::Bytes(n) => Some(n),
            Self::Rest => None,
        }
    }
}

/// Every fixed-width type spelling, with the kind it selects.
///
/// A TABLE and not a `match`, because it is also the population three tests
/// sweep: that every spelling decodes, that every spelling round-trips through
/// [`DescribedFormat::layout_text`], and that no two spellings collide. A
/// `match` arm added without a test is exactly the shape this workspace keeps
/// paying for.
pub const TYPES: &[(&str, Kind)] = &[
    ("u8", Kind::UnsignedLe(1)),
    ("i8", Kind::SignedLe(1)),
    ("u16le", Kind::UnsignedLe(2)),
    ("u16be", Kind::UnsignedBe(2)),
    ("i16le", Kind::SignedLe(2)),
    ("i16be", Kind::SignedBe(2)),
    ("u32le", Kind::UnsignedLe(4)),
    ("u32be", Kind::UnsignedBe(4)),
    ("i32le", Kind::SignedLe(4)),
    ("i32be", Kind::SignedBe(4)),
    ("u64le", Kind::UnsignedLe(8)),
    ("u64be", Kind::UnsignedBe(8)),
    ("i64le", Kind::SignedLe(8)),
    ("i64be", Kind::SignedBe(8)),
    ("f32le", Kind::FloatLe(4)),
    ("f32be", Kind::FloatBe(4)),
    ("f64le", Kind::FloatLe(8)),
    ("f64be", Kind::FloatBe(8)),
    ("rest", Kind::Rest),
];

/// The item separator inside a layout.
const ITEM_SEP: char = ',';
/// What separates a field's name from its type.
const TYPE_SEP: char = ':';

/// Characters a described field's NAME may not carry.
///
/// The layout is a value in a grammar that already reserves `=` and the escape
/// character, and it carries its own two separators. Rather than nest a second
/// quoting level inside a quoted value -- two escapers over one string, which
/// is how a round trip stops being provable -- a name that would need quoting
/// is REFUSED by spelling. A field name is an identifier a deployment chooses,
/// so this costs it nothing it wanted.
const NAME_FORBIDDEN: &[char] = &[ITEM_SEP, TYPE_SEP, '=', '\\', ' ', '\t'];

/// Why a layout could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutError {
    /// The layout has no fields. A format that decodes nothing would report
    /// every payload as `0 byte(s) after the last described field`, which
    /// blames the traffic for an empty declaration.
    NoFields,
    /// An item with no `:` between a name and a type.
    NoType(String),
    /// The name half is empty.
    EmptyName,
    /// The name carries a character the layout grammar reserves.
    NameNotSpellable(String),
    /// Two fields with the same name. Refused because the name IS the path a
    /// reader keys on, and two rows answering to one path make a document
    /// nobody can index.
    DuplicateName(String),
    /// A type spelling this build does not know.
    NoSuchType(String),
    /// `rest` appeared somewhere other than last, where its width would have to
    /// be guessed from fields that come after it.
    RestNotLast,
    /// `bytesN` with an N that is not a positive decimal number.
    BadByteCount(String),
}

impl core::fmt::Display for LayoutError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoFields => write!(f, "a described format needs at least one field"),
            Self::NoType(item) => write!(
                f,
                "`{item}` is not a field -- expected `<name>{TYPE_SEP}<type>`"
            ),
            Self::EmptyName => write!(f, "a field with no name"),
            Self::NameNotSpellable(name) => write!(
                f,
                "the field name `{name}` carries a character the layout \
                 reserves (one of `{ITEM_SEP}`, `{TYPE_SEP}`, `=`, a backslash \
                 or a space)"
            ),
            Self::DuplicateName(name) => write!(
                f,
                "two fields are both named `{name}`, and the name is the path a \
                 reader keys on"
            ),
            Self::NoSuchType(t) => write!(
                f,
                "`{t}` is not a field type (they are: {}, and bytesN)",
                type_names().join(", ")
            ),
            Self::RestNotLast => write!(
                f,
                "`rest` takes every byte left, so it can only be the last field"
            ),
            Self::BadByteCount(n) => write!(f, "`bytes{n}` needs a positive byte count"),
        }
    }
}

/// Every type spelling, for a refusal that can say what IS available.
fn type_names() -> Vec<&'static str> {
    TYPES.iter().map(|(name, _)| *name).collect()
}

/// R2114 (open-debt item 237) — the type spellings THIS BUILD reads, as one
/// line, for a consumer that has to write a layout before it can decode
/// anything.
///
/// DERIVED from [`TYPES`] and rendered once, so the command line's help, the C
/// ABI's catalogue and every refusal are one fact rather than three copies. It
/// is the same shape `crate::link::readable_link_types_line` has, for the same
/// question: what can you read?
pub fn readable_field_types_line() -> String {
    type_names().join(", ")
}

/// One described field: what it is called and how its bytes are read.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Item {
    name: String,
    kind: Kind,
    /// The spelling the operator wrote, kept so [`DescribedFormat::layout_text`]
    /// writes back what was declared rather than a canonical form of it.
    spelling: String,
}

/// A payload format a deployment DESCRIBED rather than implemented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescribedFormat {
    name: String,
    items: Vec<Item>,
}

impl DescribedFormat {
    /// Read a layout, or say why not.
    ///
    /// `name` is the format's name as a rule will refer to it; `layout` is the
    /// comma-separated `name:type` list.
    pub fn parse(name: &str, layout: &str) -> Result<Self, LayoutError> {
        let mut items: Vec<Item> = Vec::new();
        for raw in layout.split(ITEM_SEP) {
            let (field, spelling) = raw.split_once(TYPE_SEP).ok_or_else(|| {
                // An item with no separator at all is a different mistake from
                // one with an unknown type, and a reader acts differently on
                // each: the first is a typo in the LAYOUT and the second is a
                // question about this build.
                LayoutError::NoType(raw.to_owned())
            })?;
            if field.is_empty() {
                return Err(LayoutError::EmptyName);
            }
            if field.contains(NAME_FORBIDDEN) {
                return Err(LayoutError::NameNotSpellable(field.to_owned()));
            }
            if items.iter().any(|i| i.name == field) {
                return Err(LayoutError::DuplicateName(field.to_owned()));
            }
            let kind = kind_of(spelling)?;
            if items.iter().any(|i| i.kind == Kind::Rest) {
                return Err(LayoutError::RestNotLast);
            }
            items.push(Item {
                name: field.to_owned(),
                kind,
                spelling: spelling.to_owned(),
            });
        }
        if items.is_empty() {
            return Err(LayoutError::NoFields);
        }
        Ok(Self {
            name: name.to_owned(),
            items,
        })
    }

    /// The layout, written the way it was declared.
    ///
    /// The mirror of [`DescribedFormat::parse`], for the same reason
    /// `crate::payload::formats::declaration_text` is the mirror of the
    /// declaration parser: the spelling has ONE definition, so a declaration
    /// reported back to a reader is a line that reads back as itself.
    pub fn layout_text(&self) -> String {
        let mut out = String::new();
        for (at, item) in self.items.iter().enumerate() {
            if at > 0 {
                out.push(ITEM_SEP);
            }
            out.push_str(&item.name);
            out.push(TYPE_SEP);
            out.push_str(&item.spelling);
        }
        out
    }

    /// How many fields this layout describes.
    pub fn field_count(&self) -> usize {
        self.items.len()
    }
}

/// The kind a type spelling selects.
fn kind_of(spelling: &str) -> Result<Kind, LayoutError> {
    if let Some((_, kind)) = TYPES.iter().find(|(name, _)| *name == spelling) {
        return Ok(*kind);
    }
    if let Some(count) = spelling.strip_prefix("bytes") {
        let n: usize = count
            .parse()
            .map_err(|_| LayoutError::BadByteCount(count.to_owned()))?;
        if n == 0 {
            return Err(LayoutError::BadByteCount(count.to_owned()));
        }
        return Ok(Kind::Bytes(n));
    }
    Err(LayoutError::NoSuchType(spelling.to_owned()))
}

/// Render one field's bytes.
///
/// `bytes.len()` is the width the walk already checked, so every arm here reads
/// exactly what it was handed and none of them can be short.
fn render(kind: Kind, bytes: &[u8]) -> String {
    let unsigned = |be: bool| -> u64 {
        let mut v: u64 = 0;
        if be {
            for b in bytes {
                v = (v << 8) | u64::from(*b);
            }
        } else {
            for b in bytes.iter().rev() {
                v = (v << 8) | u64::from(*b);
            }
        }
        v
    };
    // Sign-extend from the field's own width rather than from 64 bits: a
    // one-byte 0xff is -1 and not 255, and the shift pair is what says so.
    let signed = |be: bool| -> i64 {
        let raw = unsigned(be);
        let bits = bytes.len() * 8;
        if bits >= 64 {
            raw as i64
        } else {
            let shift = 64 - bits;
            ((raw << shift) as i64) >> shift
        }
    };
    match kind {
        Kind::UnsignedLe(_) => format!("{}", unsigned(false)),
        Kind::UnsignedBe(_) => format!("{}", unsigned(true)),
        Kind::SignedLe(_) => format!("{}", signed(false)),
        Kind::SignedBe(_) => format!("{}", signed(true)),
        Kind::FloatLe(4) => format!("{}", f32::from_bits(unsigned(false) as u32)),
        Kind::FloatBe(4) => format!("{}", f32::from_bits(unsigned(true) as u32)),
        Kind::FloatLe(_) => format!("{}", f64::from_bits(unsigned(false))),
        Kind::FloatBe(_) => format!("{}", f64::from_bits(unsigned(true))),
        Kind::Bytes(_) | Kind::Rest => hex(bytes),
    }
}

/// Raw bytes, lowercase, no separator -- the spelling the rest of this crate's
/// documents already use for an opaque run.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

impl PayloadFormat for DescribedFormat {
    fn name(&self) -> &str {
        &self.name
    }

    /// Walk the record.
    ///
    /// The declared field NAME becomes the [`PayloadField::path`], which is the
    /// same choice the JSON walk makes: a document that names its own members
    /// has those names AS the path. [`PayloadField::name`] stays `None`, so the
    /// invariant that a decoder never fills it holds here too -- a declared
    /// rename still comes only from `FormatMap::field_name`.
    fn decode(&self, payload: &[u8]) -> Result<Vec<PayloadField>, PayloadFormatError> {
        let mut out = Vec::with_capacity(self.items.len());
        let mut at = 0usize;
        for item in &self.items {
            let width = match item.kind.width() {
                Some(n) => n,
                None => payload.len() - at,
            };
            let end = match at.checked_add(width) {
                Some(end) if end <= payload.len() => end,
                _ => return Err(PayloadFormatError::Truncated(at)),
            };
            out.push(PayloadField {
                path: item.name.clone(),
                name: None,
                value: render(item.kind, &payload[at..end]),
                start: at,
                end,
            });
            at = end;
        }
        if at != payload.len() {
            return Err(PayloadFormatError::Malformed {
                at,
                why: format!(
                    "{} byte(s) after the last described field -- describe them \
                     or end the layout with a `rest` field",
                    payload.len() - at
                ),
            });
        }
        Ok(out)
    }

    /// A described format DECLINES to name its encodings.
    ///
    /// Not an oversight and not a default taken by omission: the deployment
    /// that wrote the layout is the only one who knows what its publishers
    /// label these bytes, and a guess here would veto a correct rule. Declining
    /// is the behaviour a rule has without this trait method, which is what a
    /// reader who wrote a rule asked for.
    fn encodings(&self) -> Option<&[&str]> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn a_fixed_record_decodes_with_its_declared_names_as_paths() {
        let f = DescribedFormat::parse("profile", "temp:u16le,humidity:u8").expect("a layout");
        let fields = f.decode(&[0x2c, 0x01, 0x41]).expect("a record");
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].path, "temp");
        assert_eq!(fields[0].value, "300");
        assert_eq!((fields[0].start, fields[0].end), (0, 2));
        assert_eq!(fields[1].path, "humidity");
        assert_eq!(fields[1].value, "65");
        assert_eq!((fields[1].start, fields[1].end), (2, 3));
        // The invariant the trait states: a decoder never invents a name.
        assert!(fields.iter().all(|f| f.name.is_none()));
    }

    #[test]
    fn endianness_is_read_from_the_spelling_and_not_from_the_host() {
        let le = DescribedFormat::parse("le", "v:u32le").expect("a layout");
        let be = DescribedFormat::parse("be", "v:u32be").expect("a layout");
        let bytes = [0x00, 0x00, 0x01, 0x00];
        assert_eq!(le.decode(&bytes).expect("le")[0].value, "65536");
        assert_eq!(be.decode(&bytes).expect("be")[0].value, "256");
    }

    #[test]
    fn a_signed_field_extends_from_its_own_width() {
        // 0xff is -1 as an i8 and 255 as a u8. A sign extension from 64 bits
        // rather than from the FIELD's width is the way to get this wrong, and
        // it renders 255 for both.
        let f = DescribedFormat::parse("s", "a:i8,b:u8").expect("a layout");
        let fields = f.decode(&[0xff, 0xff]).expect("a record");
        assert_eq!(fields[0].value, "-1");
        assert_eq!(fields[1].value, "255");
    }

    #[test]
    fn a_float_is_read_as_ieee_754_and_not_as_its_bits() {
        let f = DescribedFormat::parse("f", "t:f32le").expect("a layout");
        let fields = f.decode(&1.5f32.to_le_bytes()).expect("a record");
        assert_eq!(fields[0].value, "1.5");
    }

    #[test]
    fn a_short_payload_is_truncated_at_the_field_that_ran_out() {
        let f = DescribedFormat::parse("p", "a:u8,b:u32le").expect("a layout");
        assert_eq!(
            f.decode(&[0x01, 0x02]),
            Err(PayloadFormatError::Truncated(1))
        );
    }

    #[test]
    fn bytes_after_the_last_field_are_a_finding_and_not_a_clean_decode() {
        // The dangerous shape: a layout SHORTER than the record decodes every
        // field it names and looks right. Nothing in those fields is wrong,
        // and the reader is looking at the wrong record.
        let f = DescribedFormat::parse("p", "a:u8").expect("a layout");
        let err = f.decode(&[0x01, 0x02, 0x03]).expect_err("trailing bytes");
        match err {
            PayloadFormatError::Malformed { at, why } => {
                assert_eq!(at, 1);
                assert!(why.contains("2 byte(s) after"), "{why}");
            }
            other => panic!("expected a malformed finding, got {other:?}"),
        }
    }

    #[test]
    fn a_rest_field_accounts_for_a_variable_tail() {
        let f = DescribedFormat::parse("p", "a:u8,tail:rest").expect("a layout");
        let fields = f.decode(&[0x01, 0xde, 0xad]).expect("a record");
        assert_eq!(fields[1].value, "dead");
        assert_eq!((fields[1].start, fields[1].end), (1, 3));
        // And an EMPTY tail is a zero-length field rather than a refusal: the
        // record accounted for every byte, which is what the layout claimed.
        let fields = f.decode(&[0x01]).expect("a record with no tail");
        assert_eq!(fields[1].value, "");
        assert_eq!((fields[1].start, fields[1].end), (1, 1));
    }

    #[test]
    fn rest_is_refused_anywhere_but_last() {
        assert_eq!(
            DescribedFormat::parse("p", "tail:rest,a:u8"),
            Err(LayoutError::RestNotLast)
        );
    }

    #[test]
    fn every_type_spelling_decodes_and_the_population_is_the_table() {
        assert!(!TYPES.is_empty(), "a sweep over nothing is green");
        for (spelling, kind) in TYPES {
            let f = DescribedFormat::parse("t", &format!("v:{spelling}")).expect(spelling);
            let width = kind.width().unwrap_or(3);
            let bytes = vec![0u8; width];
            let fields = f
                .decode(&bytes)
                .unwrap_or_else(|e| panic!("{spelling}: {e:?}"));
            assert_eq!(fields.len(), 1, "{spelling}");
            assert_eq!((fields[0].start, fields[0].end), (0, width), "{spelling}");
        }
    }

    #[test]
    fn every_type_spelling_round_trips_through_the_layout_text() {
        for (spelling, _) in TYPES {
            let text = format!("v:{spelling}");
            let f = DescribedFormat::parse("t", &text).expect(spelling);
            assert_eq!(f.layout_text(), text, "{spelling}");
        }
        let f = DescribedFormat::parse("t", "a:u8,b:bytes4").expect("a layout");
        assert_eq!(f.layout_text(), "a:u8,b:bytes4");
    }

    #[test]
    fn no_two_type_spellings_collide() {
        let mut seen: Vec<&str> = type_names();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len(), "a spelling is listed twice: {seen:?}");
    }

    #[test]
    fn a_layout_refuses_what_it_cannot_read_back() {
        assert_eq!(
            DescribedFormat::parse("p", ""),
            Err(LayoutError::NoType(String::new()))
        );
        assert_eq!(
            DescribedFormat::parse("p", "novalue"),
            Err(LayoutError::NoType("novalue".into()))
        );
        assert_eq!(
            DescribedFormat::parse("p", ":u8"),
            Err(LayoutError::EmptyName)
        );
        assert_eq!(
            DescribedFormat::parse("p", "a:u8,a:u8"),
            Err(LayoutError::DuplicateName("a".into()))
        );
        assert_eq!(
            DescribedFormat::parse("p", "a:u24le"),
            Err(LayoutError::NoSuchType("u24le".into()))
        );
        assert_eq!(
            DescribedFormat::parse("p", "a:bytes0"),
            Err(LayoutError::BadByteCount("0".into()))
        );
        assert_eq!(
            DescribedFormat::parse("p", "a:bytesx"),
            Err(LayoutError::BadByteCount("x".into()))
        );
    }

    #[test]
    fn a_described_format_declines_to_name_encodings() {
        // Stated as an assertion because the alternative -- guessing -- would
        // veto a correct rule for a deployment whose publishers label bytes in
        // a way this tree has never seen.
        let f = DescribedFormat::parse("p", "a:u8").expect("a layout");
        assert!(f.encodings().is_none());
    }

    #[test]
    fn the_format_answers_to_the_name_it_was_declared_under() {
        let f = DescribedFormat::parse("e2e-profile-1", "crc:u16be,counter:u8,data:rest")
            .expect("a layout");
        assert_eq!(f.name(), "e2e-profile-1");
        assert_eq!(f.field_count(), 3);
    }
}
