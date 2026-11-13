// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The STRUCTURAL REPORT of a transport message's bytes: for every field its
//! name, where it sits, how wide it is, what kind of field it is, and what value
//! keeps it that wide.
//!
//! # Why it is derived from the dissector and not laid out by hand
//!
//! The question this answers is a caller's: "I want to change this field and
//! not move the ones around it — which bytes?". A table of offsets typed beside
//! the builder would be a second understanding of the format, and it would be
//! right only for the messages its author remembered. The report is read OFF THE
//! BYTES instead: the message is dissected by the walker every reader of this
//! library uses (`wz_session_core::dissect::dissect_transport_message`), and
//! each leaf of the tree it returns becomes a row. An offset or a width is
//! therefore whatever the reader finds, for any message the reader can read —
//! including the ones the builder cannot be asked for.
//!
//! What the tree does not say is classified, and the classification is a CLOSED
//! table: the [`Kind`] of a field (length, sequence number, reserved, flag,
//! other), whether its integer is a VLE or a fixed width, which row a length
//! counts, and which bits of a carrier byte a flag or a sub-field owns. Every
//! entry is held against the generated codecs' own field lists, and against the
//! dissector, by the tests in `transport_build_tests`: a name the walker emits
//! that the table does not know is a [`LayoutError::Unclassified`], never a
//! default.
//!
//! # What a row is
//!
//! * a LEAF of the tree that owns bytes (`header`, `version`, `cookie_len`, `sn`
//!   ...), at its span;
//! * a bit-field or flag that ALIASES a carrier byte (`mid`, `z`, `r`, `whatami`,
//!   `zid_len` ...), at the carrier's span, with the `bit_mask` it owns in it;
//! * a RESERVED row for every bit of a carrier byte that no field of the message
//!   owns, derived as the complement of the bits the other rows own, so it moves
//!   with the table and cannot be typed;
//! * the stream length prefix, when the framing has one, relative to the unit.
//!
//! A network message carried in a Frame is ONE row (`payload`): the report is of
//! the transport message, and the carried bytes are the caller's. The one
//! exception is asked for by name: given an end-to-end profile
//! ([`layout_under`]), the report adds the rows of the protected frame each
//! carried message's payload holds, INSIDE the `payload` row (`within`), so a
//! caller that mutates a frame's CRC or counter finds them as it finds a
//! sequence number. Those rows do not tile the body; the `payload` row does.
//!
//! # What a replacement needs
//!
//! A caller that replaces a field writes `value` into `width` bytes at `offset`:
//! little-endian for a fixed field, VLE for a VLE field (any value in `min..=max`
//! encodes in exactly `width` bytes), and into `bit_mask` of the carrier byte for
//! a bit-field (`stored` is what those bits hold now, and `min..=max` what they
//! can hold). The test
//! `a_replacement_made_from_the_report_alone_changes_only_that_field` does
//! exactly that for every row of every message.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use wz_codecs::ext_entry::ExtEntry;
use wz_codecs::init_body::InitBody;
use wz_codecs::wire_const;
use wz_session_core::dissect::{dissect_transport_message, Field, FieldValue, MessageName, Span};
use wz_session_core::transport_compose::{
    vle_range, vle_width, Framing, SN_RES_FRAME_MASK, SN_RES_REQUEST_ID_MASK,
};

use crate::e2e_profile::{Cover, Profile, PAYLOAD};
use crate::payload_decode::{payload_slot, SlotSpan};

/// What a field IS to someone who wants to change it.
///
/// A closed vocabulary of five. `Other` is a word a field is GIVEN, never a
/// default for a name the table does not know (see [`LayoutError::Unclassified`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A field whose value is a count of bytes that follow (`cookie_len`, an
    /// extension's `value_len`, the stream prefix) or one less than such a count
    /// (`zid_len`).
    Length,
    /// A sequence number (`sn`, `initial_sn`): a position on a ring a handshake
    /// sized.
    SequenceNumber,
    /// Bits the format sets aside and writes zero.
    Reserved,
    /// A single bit that says a part is present or a variant is taken.
    Flag,
    /// A value computed over other bytes of the message, which a receiver
    /// computes again and compares: a protected frame's CRC.
    Checksum,
    /// Every other field.
    Other,
}

impl Kind {
    /// Every kind, in the order the vocabulary lists them.
    pub const ALL: [Kind; 6] = [
        Kind::Length,
        Kind::SequenceNumber,
        Kind::Reserved,
        Kind::Flag,
        Kind::Checksum,
        Kind::Other,
    ];

    /// The word the document prints for this kind.
    pub const fn word(self) -> &'static str {
        match self {
            Kind::Length => "length",
            Kind::SequenceNumber => "sequence_number",
            Kind::Reserved => "reserved",
            Kind::Flag => "flag",
            Kind::Checksum => "checksum",
            Kind::Other => "other",
        }
    }

    /// The kinds a transport message's own rows take: every kind but
    /// [`Kind::Checksum`], which only a protected frame's header has. The
    /// build door builds transport messages, so these are its words.
    pub const TRANSPORT: [Kind; 5] = [
        Kind::Length,
        Kind::SequenceNumber,
        Kind::Reserved,
        Kind::Flag,
        Kind::Other,
    ];

    /// Every word [`Self::word`] can return, walked.
    pub fn names() -> Vec<&'static str> {
        Kind::ALL.iter().map(|k| k.word()).collect()
    }

    /// The words of [`Self::TRANSPORT`], walked.
    pub fn transport_names() -> Vec<&'static str> {
        Kind::TRANSPORT.iter().map(|k| k.word()).collect()
    }
}

/// How a row's integer is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// A fixed number of bytes (a byte string is fixed at the width it has in
    /// this message), or a bit range inside one.
    Fixed,
    /// A variable-length integer: `width` bytes now, and `min..=max` is every
    /// value that would take the same number.
    Vle,
    /// A fixed number of bytes holding an integer most significant byte
    /// first: a protected frame's header field. `Fixed` integers of the
    /// transport message are least significant byte first.
    BigEndian,
}

impl Encoding {
    /// Every encoding, in the order the vocabulary lists them.
    pub const ALL: [Encoding; 3] = [Encoding::Fixed, Encoding::Vle, Encoding::BigEndian];

    /// The word the document prints for this encoding.
    pub const fn word(self) -> &'static str {
        match self {
            Encoding::Fixed => "fixed",
            Encoding::Vle => "vle",
            Encoding::BigEndian => "big_endian",
        }
    }

    /// The encodings a transport message's own rows take: every encoding but
    /// [`Encoding::BigEndian`], which only a protected frame's header has.
    pub const TRANSPORT: [Encoding; 2] = [Encoding::Fixed, Encoding::Vle];

    /// Every word [`Self::word`] can return, walked.
    pub fn names() -> Vec<&'static str> {
        Encoding::ALL.iter().map(|e| e.word()).collect()
    }

    /// The words of [`Self::TRANSPORT`], walked.
    pub fn transport_names() -> Vec<&'static str> {
        Encoding::TRANSPORT.iter().map(|e| e.word()).collect()
    }
}

/// What a row's `offset` counts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelativeTo {
    /// The first byte of the unit as written to the link: only the stream
    /// length prefix is placed this way.
    Unit,
    /// The first byte of the transport message (its header), behind any prefix.
    Body,
}

impl RelativeTo {
    /// Every origin, in the order the vocabulary lists them.
    pub const ALL: [RelativeTo; 2] = [RelativeTo::Unit, RelativeTo::Body];

    /// The word the document prints for this origin.
    pub const fn word(self) -> &'static str {
        match self {
            RelativeTo::Unit => "unit",
            RelativeTo::Body => "body",
        }
    }

    /// Every word [`Self::word`] can return, walked.
    pub fn names() -> Vec<&'static str> {
        RelativeTo::ALL.iter().map(|r| r.word()).collect()
    }
}

/// One field of the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The dissector's name for the field, qualified with its place in an
    /// extension chain (`extensions[1].value`); unique within a report.
    pub name: String,
    /// What the field is.
    pub kind: Kind,
    /// The byte offset of the field, counted from [`Self::relative_to`].
    pub offset: usize,
    /// The field's width in bytes; for a bit-field, the width of its carrier.
    pub width: usize,
    /// What `offset` counts from.
    pub relative_to: RelativeTo,
    /// Fixed or VLE.
    pub encoding: Encoding,
    /// The integer the field holds, or `None` for a byte string.
    pub value: Option<u64>,
    /// The smallest value that keeps the field as it is: the bottom of the VLE
    /// bucket, or 0.
    pub min: Option<u64>,
    /// The largest value that keeps the field as it is: the top of the VLE
    /// bucket, the largest value of the fixed width, or of the bit range.
    pub max: Option<u64>,
    /// For a bit-field or flag, the bits of the carrier byte it owns.
    pub bit_mask: Option<u8>,
    /// For a bit-field or flag, the name of the row that owns the carrier byte.
    pub carrier: Option<String>,
    /// For a bit-field or flag, what its bits hold, shifted down: the number to
    /// write back, which for `zid_len` is one less than the length it reads as.
    pub stored: Option<u64>,
    /// For a length, the row (or `body`) whose bytes it counts.
    pub measures: Option<String>,
    /// For a sequence number, the largest value its ring holds, when the caller
    /// named the ring.
    pub ring_max: Option<u64>,
    /// For a sequence number, the width of the VLE at `ring_max`: the widest
    /// this field can become in that session.
    pub ring_max_width: Option<usize>,
    /// For a row INSIDE another row's bytes, that row's name: a protected
    /// frame is within the `payload` that carries it, and its header fields and
    /// body are within the frame. `None` for a row of the transport message,
    /// and those are the rows that tile the body.
    pub within: Option<String>,
    /// For a row whose bytes a checksum is computed over, the checksum row's
    /// name: replacing this row's value makes that checksum wrong unless it is
    /// computed again.
    pub covered_by: Option<String>,
}

/// Why a report could not be derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutError {
    /// The bytes do not dissect as a transport message this report covers.
    Unreadable(String),
    /// The bytes read as a transport message whose fields this report does not
    /// classify: `Join`, `Oam`, or a message id the transport space does not
    /// name. The report covers [`COVERED_MESSAGES`] and nothing else, and says
    /// so by refusing the rest, never by a guess at what their fields are.
    NotCovered {
        /// The dissector's name for the message (`Join`, `Oam`, `Unknown`).
        name: String,
        /// The message id, the low five bits of the first byte.
        mid: u8,
    },
    /// The dissector emitted a name the classification table does not hold.
    Unclassified {
        /// The dissector's name for it.
        name: String,
    },
    /// The rows do not tile the body: some bytes belong to no row.
    Untiled {
        /// The first byte no row covers.
        at: usize,
    },
    /// A VLE whose bytes are not the shortest encoding of its value, which
    /// would make `min..=max` a lie about its width.
    NonCanonicalVle {
        /// The row.
        name: String,
        /// The bytes it occupies.
        width: usize,
        /// The shortest width of its value.
        canonical: usize,
    },
}

/// `commons/zenoh-protocol/src/common/mod.rs` @ `pub const HEADER_BITS: u8 = 5;`:
/// a header's message id is its low `HEADER_BITS` bits.
const MID_MASK: u8 = 0x1F;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    Init,
    Open,
    Close,
    KeepAlive,
    Frame,
    Fragment,
    ExtEntry,
}

/// Every scope, so the tests that hold the table walk it.
#[cfg(test)]
const SCOPES: [Scope; 7] = [
    Scope::Init,
    Scope::Open,
    Scope::Close,
    Scope::KeepAlive,
    Scope::Frame,
    Scope::Fragment,
    Scope::ExtEntry,
];

/// The transport messages the report covers, by the words the dissector names
/// them with: `scope_of` is the one table, and a test holds this list to it.
pub const COVERED_MESSAGES: [&str; 6] = ["Init", "Open", "Close", "KeepAlive", "Frame", "Fragment"];

fn scope_of(root: &str) -> Option<Scope> {
    Some(match MessageName::named(root)? {
        MessageName::Init => Scope::Init,
        MessageName::Open => Scope::Open,
        MessageName::Close => Scope::Close,
        MessageName::KeepAlive => Scope::KeepAlive,
        MessageName::Frame => Scope::Frame,
        MessageName::Fragment => Scope::Fragment,
        _ => return None,
    })
}

/// One bit-range of a carrier byte that a row owns.
#[derive(Clone, Copy)]
struct AliasSpec {
    name: &'static str,
    mask: u8,
    kind: Kind,
    /// For a length held in bits, the row it counts.
    measures: Option<&'static str>,
}

const fn alias(name: &'static str, mask: u8, kind: Kind) -> AliasSpec {
    AliasSpec {
        name,
        mask,
        kind,
        measures: None,
    }
}

/// The header byte's rows for each message. The flag masks are `wire_const`'s,
/// which the generated codecs' flag-inputs are built from; the message id mask
/// is upstream's.
fn header_aliases(scope: Scope) -> Vec<AliasSpec> {
    let mid = alias("mid", MID_MASK, Kind::Other);
    let z = alias("z", wire_const::FLAG_T_Z, Kind::Flag);
    match scope {
        Scope::Init => alloc::vec![
            mid,
            z,
            alias("a", wire_const::FLAG_T_INIT_A, Kind::Flag),
            alias("s", wire_const::FLAG_T_INIT_S, Kind::Flag),
        ],
        Scope::Open => alloc::vec![
            mid,
            z,
            alias("a", wire_const::FLAG_T_OPEN_A, Kind::Flag),
            alias("t", wire_const::FLAG_T_OPEN_T, Kind::Flag),
        ],
        Scope::Close => alloc::vec![mid, z, alias("s", wire_const::FLAG_T_CLOSE_S, Kind::Flag)],
        Scope::KeepAlive => alloc::vec![mid, z],
        Scope::Frame => alloc::vec![mid, z, alias("r", wire_const::FLAG_T_FRAME_R, Kind::Flag)],
        Scope::Fragment => alloc::vec![
            mid,
            z,
            alias("r", wire_const::FLAG_T_FRAGMENT_R, Kind::Flag),
            alias("m", wire_const::FLAG_T_FRAGMENT_M, Kind::Flag),
        ],
        Scope::ExtEntry => ext_aliases(),
    }
}

/// An extension entry's header: the masks come from the generated `ExtEntry`
/// codec's own setters, which write only the bits they own.
fn ext_aliases() -> Vec<AliasSpec> {
    fn probe(set: impl FnOnce(&mut ExtEntry<'static>)) -> u8 {
        let mut entry = ExtEntry::default();
        set(&mut entry);
        entry.header
    }
    alloc::vec![
        alias("ext_id", probe(|e| e.set_ext_id(0xFF)), Kind::Other),
        alias("m", probe(|e| e.set_m(true)), Kind::Flag),
        alias("encoding", probe(|e| e.set_enc(0xFF)), Kind::Other),
        alias("z", probe(|e| e.set_z(true)), Kind::Flag),
    ]
}

/// The INIT `cbyte`: the masks come from the generated `InitBody` codec's
/// setters. `zid_len` stores the length minus one.
fn cbyte_aliases() -> Vec<AliasSpec> {
    let mut whatami = InitBody::default();
    whatami.set_whatami(0xFF);
    let mut zid_len = InitBody::default();
    zid_len.set_zid_len_m1(0xFF);
    alloc::vec![
        alias("whatami", whatami.cbyte, Kind::Other),
        AliasSpec {
            name: "zid_len",
            mask: zid_len.cbyte,
            kind: Kind::Length,
            measures: Some("zid"),
        },
    ]
}

/// The INIT `sn_res`: the two resolutions, from the writer's own packing.
fn sn_res_aliases() -> Vec<AliasSpec> {
    alloc::vec![
        alias("sn_res_frame_sn", SN_RES_FRAME_MASK, Kind::Other),
        alias("sn_res_request_id", SN_RES_REQUEST_ID_MASK, Kind::Other),
    ]
}

/// A leaf the dissector emits, classified. `encoding` is what an INTEGER leaf
/// of this name is; a byte string is always fixed at its width.
#[derive(Clone, Copy)]
pub(crate) struct LeafSpec {
    pub(crate) name: &'static str,
    pub(crate) kind: Kind,
    pub(crate) encoding: Encoding,
    pub(crate) measures: Option<&'static str>,
}

const fn leaf(
    name: &'static str,
    kind: Kind,
    encoding: Encoding,
    measures: Option<&'static str>,
) -> LeafSpec {
    LeafSpec {
        name,
        kind,
        encoding,
        measures,
    }
}

/// THE CLOSED TABLE. Every leaf name the dissector emits for the eight messages
/// this report covers, and for an extension entry, with what it is.
///
/// Held against the generated codecs' field lists (every field of `InitBody`,
/// `OpenBody`, `Close`, `Frame`, `Fragment` and `StreamEnvelope` has a name here
/// or a declared rename) and against the dissector (every name it emits over the
/// corpus is here, and every name here is emitted) by `transport_build_tests`.
pub(crate) const LEAVES: &[LeafSpec] = &[
    leaf("header", Kind::Other, Encoding::Fixed, None),
    leaf("version", Kind::Other, Encoding::Fixed, None),
    leaf("cbyte", Kind::Other, Encoding::Fixed, None),
    leaf("zid", Kind::Other, Encoding::Fixed, None),
    leaf("sn_res", Kind::Other, Encoding::Fixed, None),
    leaf("batch_size", Kind::Other, Encoding::Fixed, None),
    leaf("cookie_len", Kind::Length, Encoding::Vle, Some("cookie")),
    leaf("cookie", Kind::Other, Encoding::Fixed, None),
    leaf("lease", Kind::Other, Encoding::Vle, None),
    leaf("initial_sn", Kind::SequenceNumber, Encoding::Vle, None),
    leaf("reason", Kind::Other, Encoding::Fixed, None),
    leaf("sn", Kind::SequenceNumber, Encoding::Vle, None),
    leaf("payload", Kind::Other, Encoding::Fixed, None),
    leaf("value_len", Kind::Length, Encoding::Vle, Some("value")),
    leaf("value", Kind::Other, Encoding::Vle, None),
];

/// What the dissector emits beside a bit-field that is a READING of it and not
/// a field of the message: the reading's name and the bit-field it reads.
///
/// `whatami_name` is the role word the `whatami` code means. It aliases the
/// cbyte as the code does and owns none of its bits, so a caller who wants
/// another role writes the code, which is a row. The report skips a reading
/// only when the carrier it aliases has the field it reads; the table is closed
/// as [`LEAVES`] is, and `transport_build_tests` holds that every reading here
/// is emitted beside a row of its field and that nothing else is skipped.
pub(crate) const READINGS: &[(&str, &str)] = &[("whatami_name", "whatami")];

/// Whether `name`, emitted at `carrier`, is a reading of one of its bit-fields.
fn reads_a_field_of(name: &str, carrier: Option<&Carrier>) -> bool {
    READINGS.iter().any(|(reading, of)| {
        *reading == name && carrier.is_some_and(|c| c.aliases.iter().any(|a| a.name == *of))
    })
}

fn leaf_spec(name: &str) -> Result<&'static LeafSpec, LayoutError> {
    LEAVES
        .iter()
        .find(|l| l.name == name)
        .ok_or_else(|| unclassified(name))
}

/// The rows a carrier byte can have, by the leaf that carries it.
fn aliases_of_carrier(leaf_name: &str, scope: Scope) -> Option<Vec<AliasSpec>> {
    match leaf_name {
        "header" => Some(header_aliases(scope)),
        "cbyte" => Some(cbyte_aliases()),
        "sn_res" => Some(sn_res_aliases()),
        _ => None,
    }
}

/// A carrier byte whose bit-fields are being collected.
struct Carrier {
    name: String,
    span: Span,
    byte: u8,
    aliases: Vec<AliasSpec>,
    covered: u8,
}

fn unclassified(name: &str) -> LayoutError {
    LayoutError::Unclassified {
        name: String::from(name),
    }
}

/// The largest value `width` bytes hold; saturates at 8 bytes.
fn fixed_max(width: usize) -> u64 {
    if width >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * width)) - 1
    }
}

struct Report {
    ring_max: Option<u64>,
    rows: Vec<Row>,
}

impl Report {
    /// A row for bits of a carrier byte: a flag, a sub-field, or the reserved
    /// remainder.
    fn push_bits(
        &mut self,
        name: String,
        kind: Kind,
        carrier: &Carrier,
        mask: u8,
        reading: Option<u64>,
        measures: Option<String>,
    ) {
        let shift = mask.trailing_zeros();
        let stored = u64::from((carrier.byte & mask) >> shift);
        self.rows.push(Row {
            name,
            kind,
            offset: carrier.span.start,
            width: carrier.span.len(),
            relative_to: RelativeTo::Body,
            encoding: Encoding::Fixed,
            value: Some(reading.unwrap_or(stored)),
            min: Some(0),
            max: Some(u64::from(mask >> shift)),
            bit_mask: Some(mask),
            carrier: Some(carrier.name.clone()),
            stored: Some(stored),
            measures,
            ring_max: None,
            ring_max_width: None,
            within: None,
            covered_by: None,
        });
    }

    /// The reserved row of a carrier: every bit no alias of it owns.
    fn flush(&mut self, carrier: Option<Carrier>) {
        let Some(carrier) = carrier else { return };
        let reserved = !carrier.covered;
        if reserved != 0 {
            let name = format!("{}_reserved", carrier.name);
            self.push_bits(name, Kind::Reserved, &carrier, reserved, None, None);
        }
    }

    /// A row that owns bytes. `integer` is `Some` for a field the dissector
    /// read as a number.
    fn push_bytes(
        &mut self,
        prefix: &str,
        spec: &LeafSpec,
        span: Span,
        integer: Option<u64>,
    ) -> Result<(), LayoutError> {
        let name = format!("{prefix}{}", spec.name);
        let width = span.len();
        let encoding = if integer.is_some() {
            spec.encoding
        } else {
            Encoding::Fixed
        };
        let (min, max) = match (integer, encoding) {
            (None, _) => (None, None),
            // No transport leaf is big-endian, and one would hold the same
            // range of values in its width as a little-endian one.
            (Some(_), Encoding::Fixed | Encoding::BigEndian) => (Some(0), Some(fixed_max(width))),
            (Some(v), Encoding::Vle) => {
                let canonical = vle_width(v);
                let bucket = if canonical == width {
                    vle_range(width)
                } else {
                    None
                };
                let Some((lo, hi)) = bucket else {
                    return Err(LayoutError::NonCanonicalVle {
                        name,
                        width,
                        canonical,
                    });
                };
                (Some(lo), Some(hi))
            }
        };
        let ring = if spec.kind == Kind::SequenceNumber && encoding == Encoding::Vle {
            self.ring_max
        } else {
            None
        };
        self.rows.push(Row {
            name,
            kind: spec.kind,
            offset: span.start,
            width,
            relative_to: RelativeTo::Body,
            encoding,
            value: integer,
            min,
            max,
            bit_mask: None,
            carrier: None,
            stored: None,
            measures: spec.measures.map(|m| format!("{prefix}{m}")),
            ring_max: ring,
            ring_max_width: ring.map(vle_width),
            within: None,
            covered_by: None,
        });
        Ok(())
    }
}

/// Walk one level of the tree: a message's children, or an extension entry's.
fn level(
    report: &mut Report,
    children: &[Field],
    scope: Scope,
    prefix: &str,
) -> Result<(), LayoutError> {
    let in_entry = scope == Scope::ExtEntry;
    let mut carrier: Option<Carrier> = None;
    // After an extension's `value_len`, the next child IS the body, whatever
    // the walker named it or decoded it into.
    let mut body_next = false;
    for child in children {
        let name: &str = &child.name;
        let reading = match &child.value {
            FieldValue::Bits(v) => Some(Some(*v)),
            FieldValue::Flag(b) => Some(Some(u64::from(*b))),
            FieldValue::Label(_) => Some(None),
            _ => None,
        };
        if let Some(reading) = reading {
            // A bit-field or flag of the carrier byte just read.
            let here = carrier.as_ref().filter(|c| c.span == child.span);
            let found = here.and_then(|c| c.aliases.iter().find(|a| a.name == name).copied());
            let reads_one = reads_a_field_of(name, here);
            match (found, carrier.as_mut()) {
                (Some(spec), Some(c)) => {
                    c.covered |= spec.mask;
                    let row_name = format!("{prefix}{}", spec.name);
                    let measures = spec.measures.map(|m| format!("{prefix}{m}"));
                    report.push_bits(row_name, spec.kind, c, spec.mask, reading, measures);
                }
                // What an extension's walker reads out of its body (`ext_name`,
                // `priority`, ...) is not a field of the entry.
                _ if in_entry => {}
                // The word a code means, beside the code's own row.
                _ if reads_one => {}
                _ => return Err(unclassified(name)),
            }
            continue;
        }

        report.flush(carrier.take());
        if body_next {
            // The span is the whole of the body however the walker decoded it.
            body_next = false;
            report.push_bytes(prefix, leaf_spec("value")?, child.span, None)?;
            continue;
        }
        match &child.value {
            FieldValue::Nested(entries) if name == "extensions" => {
                // The walker emits this group only for a message whose Z flag
                // is set, and reads an empty chain when no byte is left to
                // read one from. The flag says an entry follows, so bytes that
                // end there are a message cut short and not one with no
                // extensions: the report refuses them rather than describe a Z
                // that points at nothing.
                if entries.is_empty() {
                    return Err(LayoutError::Unreadable(String::from(
                        "the Z flag announces an extension chain and no byte follows it",
                    )));
                }
                for (i, entry) in entries.iter().enumerate() {
                    let FieldValue::Nested(parts) = &entry.value else {
                        return Err(unclassified(&entry.name));
                    };
                    let inner = format!("{prefix}extensions[{i}].");
                    level(report, parts, Scope::ExtEntry, &inner)?;
                }
            }
            FieldValue::Nested(_) if name == "payload" => {
                report.push_bytes(prefix, leaf_spec("payload")?, child.span, None)?;
            }
            FieldValue::Nested(_) => return Err(unclassified(name)),
            value => {
                let spec = leaf_spec(name)?;
                let integer = match value {
                    FieldValue::Uint(v) => Some(*v),
                    _ => None,
                };
                report.push_bytes(prefix, spec, child.span, integer)?;
                if in_entry && name == "value_len" {
                    body_next = true;
                }
                if let (Some(aliases), Some(byte)) = (aliases_of_carrier(name, scope), integer) {
                    carrier = Some(Carrier {
                        name: format!("{prefix}{name}"),
                        span: child.span,
                        byte: byte as u8,
                        aliases,
                        covered: 0,
                    });
                }
            }
        }
    }
    report.flush(carrier.take());
    Ok(())
}

/// The stream length prefix as a row, relative to the unit, read from the bytes
/// the unit starts with: a prefix that disagrees with the body is reported as it
/// stands, never as it should be.
fn prefix_row(head: &[u8]) -> Row {
    let width = head.len();
    let announced = head
        .iter()
        .rev()
        .fold(0u64, |acc, byte| acc << 8 | u64::from(*byte));
    Row {
        name: String::from("unit_length"),
        kind: Kind::Length,
        offset: 0,
        width,
        relative_to: RelativeTo::Unit,
        encoding: Encoding::Fixed,
        value: Some(announced),
        min: Some(0),
        max: Some(fixed_max(width)),
        bit_mask: None,
        carrier: None,
        stored: None,
        measures: Some(String::from("body")),
        ring_max: None,
        ring_max_width: None,
        within: None,
        covered_by: None,
    }
}

/// The report of a `unit` as `framing` wrote it: the prefix it starts with, if
/// the framing has one, and the transport message behind it.
///
/// The whole report is read from the unit's own bytes, the prefix included, so
/// it describes what is on the wire and not what the writer meant to put there.
///
/// `ring_max` is the largest sequence number the session's ring holds, when the
/// caller named the ring; the sequence-number rows then say it, and the widest
/// their VLE can become.
pub fn layout(
    unit: &[u8],
    framing: Framing,
    ring_max: Option<u64>,
) -> Result<Vec<Row>, LayoutError> {
    layout_under(unit, framing, ring_max, None)
}

/// [`layout`], and when `e2e` names a profile, the rows of the protected frame
/// each message a `Frame` carries holds under that profile (see
/// [`e2e_frame_rows`]).
///
/// The transport rows are the same rows [`layout`] gives, in the same order;
/// the frame rows follow them. They do not take part in the tiling of the body,
/// because they lie inside the `payload` row, which does.
pub fn layout_under(
    unit: &[u8],
    framing: Framing,
    ring_max: Option<u64>,
    e2e: Option<&Profile>,
) -> Result<Vec<Row>, LayoutError> {
    let prefix = framing.prefix_bytes();
    if unit.len() < prefix {
        return Err(LayoutError::Unreadable(format!(
            "a unit of {} bytes has no room for the {prefix}-byte prefix of the {} framing",
            unit.len(),
            framing.name()
        )));
    }
    let (head, body) = unit.split_at(prefix);
    let root = dissect_transport_message(body, 0)
        .map_err(|e| LayoutError::Unreadable(format!("{e:?}")))?;
    let scope = scope_of(&root.name).ok_or_else(|| LayoutError::NotCovered {
        name: String::from(&*root.name),
        // The dissector read a header byte to name the message at all.
        mid: body.first().map_or(0, |h| h & MID_MASK),
    })?;
    let FieldValue::Nested(children) = &root.value else {
        return Err(unclassified(&root.name));
    };
    let mut report = Report {
        ring_max,
        rows: Vec::new(),
    };
    if prefix > 0 {
        report.rows.push(prefix_row(head));
    }
    level(&mut report, children, scope, "")?;

    // The rows that own bytes tile the body, in order, with no gap.
    let mut next = 0usize;
    for row in &report.rows {
        if row.relative_to != RelativeTo::Body || row.carrier.is_some() {
            continue;
        }
        if row.offset != next {
            return Err(LayoutError::Untiled { at: next });
        }
        next += row.width;
    }
    if next != body.len() {
        return Err(LayoutError::Untiled { at: next });
    }
    if let (Some(profile), Scope::Frame) = (e2e, scope) {
        e2e_frame_rows(&mut report.rows, children, body, profile);
    }
    Ok(report.rows)
}

/// The rows of the protected frame that each message of a `Frame` carries,
/// read under `profile`, appended to `rows`.
///
/// A message is read when its payload slot is the body's `payload` leaf (not
/// the slices or the descriptor of shared memory) and holds at least the
/// profile's header. For the message at index `i` of the Frame's `payload`
/// group, which is the index of its entry in the field document's `carried`:
///
/// * `carried[i].e2e`, the frame, `within` the transport `payload` row;
/// * one row per header field of the profile, `carried[i].e2e.<field>`,
///   `within` the frame, `big_endian`, with the integer AS WRITTEN (a field's
///   `xor` is not undone, so `value` is what a replacement writes back). The
///   CRC field is a `checksum`, the length field a `length` that `measures`
///   the frame, the counter a `sequence_number`, every other field `other`.
///   A split field is one row: its parts are bits of the integer, and the
///   profile, not the report, names them;
/// * `carried[i].e2e.@payload`, the bytes after the header, named by the word
///   the profile's own `cover` list names them by ([`PAYLOAD`]); a field's name
///   is letters, digits, `_`, `-` and `.`, so no field row can take it.
///
/// Every row the profile's CRC is computed over carries the CRC row's name in
/// `covered_by`, in the profile's own cover list. Replacing such a value and
/// not the CRC is a frame whose CRC fails; replacing it and keeping the CRC
/// right is the wrap door's (`e2e_json::wrap_document`), which builds the frame
/// again from its values, and the frame row says where it goes.
///
/// The rows say where the fields ARE if the payload is a frame under this
/// profile; they do not say that it is one. Which messages a profile covers is
/// a fact of the key, which one unit does not always hold.
pub fn e2e_frame_rows(rows: &mut Vec<Row>, children: &[Field], body: &[u8], profile: &Profile) {
    let Some(carried) = children.iter().find_map(|c| match &c.value {
        FieldValue::Nested(messages) if &*c.name == "payload" => Some(messages),
        _ => None,
    }) else {
        return;
    };
    let fields = profile.fields();
    let crc = profile.crc();
    for (i, message) in carried.iter().enumerate() {
        let Some(slot) = payload_slot(message) else {
            continue;
        };
        if slot.span_of != SlotSpan::Payload
            || slot.end > body.len()
            || slot.end.saturating_sub(slot.start) < profile.header_bytes()
        {
            continue;
        }
        let frame = format!("carried[{i}].e2e");
        let crc_row = format!("{frame}.{}", fields[crc.field].name);
        let covered = |cover: Cover| crc.cover.contains(&cover).then(|| crc_row.clone());
        let bare = |name: String, offset: usize, width: usize, within: &str| Row {
            name,
            kind: Kind::Other,
            offset,
            width,
            relative_to: RelativeTo::Body,
            encoding: Encoding::Fixed,
            value: None,
            min: None,
            max: None,
            bit_mask: None,
            carrier: None,
            stored: None,
            measures: None,
            ring_max: None,
            ring_max_width: None,
            within: Some(String::from(within)),
            covered_by: None,
        };
        rows.push(bare(
            frame.clone(),
            slot.start,
            slot.end - slot.start,
            "payload",
        ));
        for (index, field) in fields.iter().enumerate() {
            let at = slot.start + field.offset;
            let written = body[at..at + field.bytes]
                .iter()
                .fold(0u64, |acc, byte| acc << 8 | u64::from(*byte));
            let kind = if index == crc.field {
                Kind::Checksum
            } else if index == profile.length().field {
                Kind::Length
            } else if index == profile.counter().field {
                Kind::SequenceNumber
            } else {
                Kind::Other
            };
            rows.push(Row {
                kind,
                encoding: Encoding::BigEndian,
                value: Some(written),
                min: Some(0),
                max: Some(fixed_max(field.bytes)),
                measures: (kind == Kind::Length).then(|| frame.clone()),
                covered_by: covered(Cover::Field(index)),
                ..bare(format!("{frame}.{}", field.name), at, field.bytes, &frame)
            });
        }
        let header = profile.header_bytes();
        rows.push(Row {
            covered_by: covered(Cover::Payload),
            ..bare(
                format!("{frame}.{PAYLOAD}"),
                slot.start + header,
                slot.end - slot.start - header,
                &frame,
            )
        });
    }
}

/// Every leaf name in the classification table, for the tests that hold it
/// against the codecs and against the dissector.
#[cfg(test)]
pub(crate) fn classified_leaf_names() -> Vec<&'static str> {
    LEAVES.iter().map(|l| l.name).collect()
}

/// Every bit-field name the table holds, over every carrier and scope.
#[cfg(test)]
pub(crate) fn classified_alias_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = Vec::new();
    for scope in SCOPES {
        names.extend(header_aliases(scope).iter().map(|a| a.name));
    }
    names.extend(cbyte_aliases().iter().map(|a| a.name));
    names.extend(sn_res_aliases().iter().map(|a| a.name));
    names.sort_unstable();
    names.dedup();
    names
}
