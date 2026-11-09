// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The integers a field of a `.proto` schema may hold: the ONE place that range
//! is judged, for the encoder that refuses a value outside it
//! ([`crate::proto_encode`]) and the description document that shows it
//! ([`crate::proto_describe_json`]).
//!
//! ## Why the type is not the whole answer
//!
//! A protobuf integer type has a range of its own (`uint32` holds 0 to
//! 2^32 - 1), and it is the range the wire format and every protobuf library
//! accept. A firmware that links nanopb stores the field in a C integer whose
//! width the `int_size` option chooses: `uint32` with `(nanopb).int_size = IS_8`
//! is a `uint8_t`, and nanopb's decoder (`pb_dec_varint` in `pb_decode.c`) refuses
//! a value that does not fit the integer it stores into, with `integer too large`.
//! A value the type admits and the C integer does not is accepted by the sender
//! and refused by the receiver, so the range here is the narrower of the two and
//! the sender is the one told.
//!
//! ## The rule
//!
//! * The varint integers (`int32`, `int64`, `uint32`, `uint64`, `sint32`,
//!   `sint64`) under `IS_8`, `IS_16`, `IS_32` or `IS_64` are held to the C type
//!   nanopb's generator gives them: `intN_t` for the signed four and `uintN_t` for
//!   the unsigned two, intersected with the type's own range. The source is
//!   `nanopb_int_size` only where that narrowed the range: `int32` under `IS_64`
//!   is still the `int32` range, since the value on the wire was an `int32` before
//!   it was a C integer, and its source is `type`.
//! * The fixed-width integers (`fixed32`, `fixed64`, `sfixed32`, `sfixed64`) are
//!   not in the generator's `int_size` table, so the option does not change them.
//! * An `int_size` this reader cannot read gives no range for a varint integer
//!   (`unmodelled_option`): nanopb's own generator would not accept the schema, and
//!   a range claimed for it would be a guess.
//! * A field that holds no integer has no range, and says which kind of field it
//!   is: `map` (its key and value are entry fields, each with a range of its own
//!   that the encoder applies), `enum` (an enum's values are its names and
//!   numbers, listed beside it), and `not_an_integer` for every other type.
//!
//! Only the options written in the `.proto` are read, by the one merger
//! [`crate::proto_nanopb`] keeps for the nanopb size; a separate `.options` file is
//! not.

use crate::proto_nanopb::{field_int_size, map_entry_int_size, IntSize};
use crate::proto_parse::ScalarKind;
use crate::proto_schema::{FieldKind, Fld, Linker, Msg};

/// Where a field's range comes from: the words of `source`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeSource {
    /// The protobuf type alone.
    Type,
    /// The type narrowed by the nanopb `int_size` in force, `bits` wide.
    NanopbIntSize {
        /// The width the option names: 8, 16 or 32 (64 narrows no type).
        bits: u8,
    },
}

impl RangeSource {
    /// The word the document carries.
    pub fn word(self) -> &'static str {
        match self {
            Self::Type => "type",
            Self::NanopbIntSize { .. } => "nanopb_int_size",
        }
    }
}

/// The words of `source`, one per [`RangeSource`] variant in the order it declares
/// them: the list a document's value family is held to.
pub fn source_words() -> [&'static str; 2] {
    [
        RangeSource::Type.word(),
        RangeSource::NanopbIntSize { bits: 8 }.word(),
    ]
}

/// The inclusive range of integers a field may hold, and where it comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueRange {
    /// The least value, included.
    pub low: i128,
    /// The greatest value, included.
    pub high: i128,
    pub source: RangeSource,
}

/// Why a field has no integer range: the words of `value_range_refusal`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeRefusal {
    /// A floating point, `bool`, `string`, `bytes` or message field.
    NotAnInteger,
    /// An enum field: its values are the enum's own.
    Enum,
    /// A map field: its key and value are the fields that hold integers.
    Map,
    /// The field is a varint integer whose `int_size` cannot be read.
    UnmodelledOption,
}

impl RangeRefusal {
    /// Every refusal, in the order [`refusal_words`] lists them.
    pub const ALL: [Self; 4] = [
        Self::NotAnInteger,
        Self::Enum,
        Self::Map,
        Self::UnmodelledOption,
    ];

    /// The word the document carries.
    pub fn word(self) -> &'static str {
        match self {
            Self::NotAnInteger => "not_an_integer",
            Self::Enum => "enum",
            Self::Map => "map",
            Self::UnmodelledOption => "unmodelled_option",
        }
    }
}

/// The words of `value_range_refusal`, one per [`RangeRefusal`], in its order.
pub fn refusal_words() -> [&'static str; 4] {
    RangeRefusal::ALL.map(RangeRefusal::word)
}

impl ValueRange {
    /// The range of `kind` by its type alone, `None` for a kind that holds no
    /// integer.
    pub(crate) fn of_type(kind: ScalarKind) -> Option<Self> {
        type_range(kind).map(|(low, high)| Self {
            low,
            high,
            source: RangeSource::Type,
        })
    }
}

/// The inclusive range an integer kind holds by its protobuf type.
pub(crate) fn type_range(kind: ScalarKind) -> Option<(i128, i128)> {
    Some(match kind {
        ScalarKind::Int32 | ScalarKind::Sint32 | ScalarKind::Sfixed32 => {
            (i128::from(i32::MIN), i128::from(i32::MAX))
        }
        ScalarKind::Int64 | ScalarKind::Sint64 | ScalarKind::Sfixed64 => {
            (i128::from(i64::MIN), i128::from(i64::MAX))
        }
        ScalarKind::Uint32 | ScalarKind::Fixed32 => (0, i128::from(u32::MAX)),
        ScalarKind::Uint64 | ScalarKind::Fixed64 => (0, i128::from(u64::MAX)),
        ScalarKind::Double
        | ScalarKind::Float
        | ScalarKind::Bool
        | ScalarKind::String
        | ScalarKind::Bytes => return None,
    })
}

/// The range a value of `kind` is held to under the nanopb `int_size` in force.
pub(crate) fn value_range(kind: ScalarKind, int_size: IntSize) -> Result<ValueRange, RangeRefusal> {
    let of_type = ValueRange::of_type(kind).ok_or(RangeRefusal::NotAnInteger)?;
    let signed = match kind {
        ScalarKind::Int32 | ScalarKind::Int64 | ScalarKind::Sint32 | ScalarKind::Sint64 => true,
        ScalarKind::Uint32 | ScalarKind::Uint64 => false,
        // The generator's `int_size` table has no entry for the fixed widths.
        _ => return Ok(of_type),
    };
    let bits = match int_size {
        IntSize::Default => return Ok(of_type),
        IntSize::Unreadable => return Err(RangeRefusal::UnmodelledOption),
        IntSize::Bits(bits) => bits,
    };
    // The merger gives only the four widths the option has; anything else is a
    // width this rule has no C type for.
    if !matches!(bits, 8 | 16 | 32 | 64) {
        return Err(RangeRefusal::UnmodelledOption);
    }
    let (c_low, c_high) = if signed {
        let half = 1i128 << (bits - 1);
        (-half, half - 1)
    } else {
        (0, (1i128 << bits) - 1)
    };
    let low = of_type.low.max(c_low);
    let high = of_type.high.min(c_high);
    if (low, high) == (of_type.low, of_type.high) {
        return Ok(of_type);
    }
    Ok(ValueRange {
        low,
        high,
        source: RangeSource::NanopbIntSize { bits },
    })
}

/// The range of the values of `field` of `msg`, or why it has none. The one
/// judgement the encoder and the description document share.
pub(crate) fn field_range(
    linker: &Linker<'_, '_>,
    msg: &Msg,
    field: &Fld,
) -> Result<ValueRange, RangeRefusal> {
    match field.kind {
        FieldKind::Scalar(kind) => value_range(kind, field_int_size(linker, msg, field)),
        FieldKind::Enum(_) => Err(RangeRefusal::Enum),
        FieldKind::Map { .. } => Err(RangeRefusal::Map),
        FieldKind::Message(_) | FieldKind::Group => Err(RangeRefusal::NotAnInteger),
    }
}

/// The range of the key or the value, of scalar `kind`, of an entry of a map
/// written in file `file`, by the file's options alone.
pub(crate) fn map_entry_range(
    linker: &Linker<'_, '_>,
    file: usize,
    kind: ScalarKind,
) -> Result<ValueRange, RangeRefusal> {
    value_range(kind, map_entry_int_size(linker, file))
}
