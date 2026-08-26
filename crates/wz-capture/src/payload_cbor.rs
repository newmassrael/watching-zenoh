// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y914 (open-debt items 433 and 434) — CBOR, walked into its own fields.
//!
//! # The silence this ends
//!
//! `application/cbor` is entry 8 of the wire table
//! (`wz_codecs::encoding_ids::ENCODING_ID_TO_STR`), and until this round it was
//! in exactly the position `application/json` was in before R311y909, only
//! worse. [`crate::payload::shape_of`] answered [`crate::payload::Shape::Binary`]
//! for it, which has a consequence one step further on than a missing decoder:
//! [`crate::payload::inspect`] returns `Opaque` for binary, `Opaque` is
//! consistent-with-anything, and so `payload_decode::judge_claim` could
//! never REFUTE a `application/cbor` label. A label that is not refuted vetoes
//! the operator's rule. So the symptom was not "cbor bodies are shown as a byte
//! count" — it was "a rule cannot be applied to a cbor topic at all".
//!
//! # One grammar, two outputs
//!
//! The same shape [`crate::payload`]'s JSON scanner uses, and for the same
//! reason: [`scan_cbor`] answers well-formed-or-where for `inspect`, and
//! [`walk_cbor`] runs the identical walk with an emitter attached and hands back
//! the rows. Two readers would let this crate hold two opinions about what CBOR
//! is, and the plane above could then call a payload well-formed that the plane
//! below refused.
//!
//! # What is checked, and what RFC 8949 calls it
//!
//! RFC 8949 §1.2 separates WELL-FORMED (the encoding can be walked) from VALID
//! (the content obeys the further rules). This walk enforces well-formedness in
//! full — §3's head encoding, §3.2.3's chunked strings, §3.3's simple values,
//! the reserved additional-information values — and it enforces ONE validity
//! rule beyond that: a major-type-3 text string must be UTF-8 (§3.1). That is
//! deliberate and it is the same judgement item 432 made for JSON: a capture is
//! by definition not a closed ecosystem, and a text string whose bytes are not
//! UTF-8 is a finding rather than a rendering problem.
//!
//! §5.6's prohibition on DUPLICATE MAP KEYS is REPORTED but not enforced, and
//! the difference is the point. R311y914 declined to look at all, because
//! detecting it means holding every key of every map and that path runs over
//! every payload in a capture; item 441 was registered against that silence and
//! R311y916 pays it in the one place the cost is warranted. The map's own row
//! now carries `, N duplicate key(s)`, and the walk still does not call the
//! document malformed — a duplicate is invalid CBOR that is nonetheless
//! perfectly well-formed CBOR, so refusing it would make
//! [`crate::payload::inspect`] refute an `application/cbor` label over bytes
//! that really are CBOR. The set is taken only when rows are being emitted;
//! [`scan_cbor`] has nowhere to put the answer and does not pay for it.
//!
//! # Paths: the decision item 434 asked for
//!
//! JSON keys are always text, so R311y910's rule — the key's source text, with
//! `.` and `\` escaped by `\` — covers every path a JSON document can produce.
//! CBOR map keys are ARBITRARY DATA ITEMS (§2.1), so that rule runs out, and
//! item 434 was registered as the design question a decoder must answer before
//! it is written, because writing it first freezes the answer in code.
//!
//! The two naive candidates both collide, which is what made it a question:
//! a positional index (`$.0`) collides with the text key `"0"`, and a marker
//! (`$.#1`) collides with the text key `"#1"`. Widening the escape set for CBOR
//! only would give this crate TWO path syntaxes, and one syntax shared with the
//! protobuf walk's `2.1` form is why the separator is a `.` at all.
//!
//! THE ANSWER IS THAT THE ESCAPE ALPHABET IS ALREADY CLOSED, so a disjoint
//! namespace exists without widening anything. R311y910's rule emits `\` in
//! exactly one position: immediately before a `.` or a `\`. Therefore a segment
//! whose first character is `\` and whose second is neither of those CANNOT be
//! produced by any text key — the text key `\i5` arrives as `\\i5`. That free
//! space is where the non-text keys go, one letter each:
//!
//! | key | segment | e.g. |
//! |---|---|---|
//! | integer (major 0/1) | `\i<decimal>` | `\i5`, `\i-3` |
//! | byte string (major 2, definite) | `\b<lowercase hex>` | `\b01ff` |
//! | float (major 7, 25/26/27) | `\f<value>` | `\f1\.5` |
//! | simple (major 7, 20-24) | `\s<word>` | `\strue`, `\snull` |
//! | anything else | `\x<byte offset>` | `\x17` |
//!
//! R311y916 (item 442) took one more letter out of that free space: `\e`, the
//! document a tag 24 byte string spells. It is not a key form — it is the one
//! place a segment names something the wire carries INSIDE another item.
//!
//! `\x` is the honest arm rather than the lazy one. A key that is a container, a
//! tag, or an indefinite-length string has no NAME to be called by — an operator
//! writing `--payload-name` needs a segment that is stable across messages, and
//! a nested map key is not that. So those get a locator instead: the key's byte
//! offset, which is unique within the document and findable in the capture, and
//! which says by its shape that it is a position rather than a name.
//!
//! A tag's content is reached the same way (`\t`), so a tagged value nests like
//! everything else instead of needing an arm of its own.
//!
//! # What it gives, and what it cannot
//!
//! Kinds, values, byte spans, and paths for every item in the document. Like
//! JSON it also gives names where the wire carries them, and like JSON those
//! arrive in the PATH — [`crate::payload::formats::PayloadField::name`] stays
//! `None`, because its contract is "the DECLARED name" and a decoder filling it
//! would make one field mean two provenances.
//!
//! What it cannot give is meaning for a TAG it does not know. RFC 8949 §3.4
//! registers a few (0/1 date-time, 2/3 bignum, 24 embedded CBOR) and IANA holds
//! the rest; this walk reports the tag NUMBER and walks the item under it. It
//! does not decode a bignum into a number, which is the rule this crate applies
//! to protobuf's missing field names: a decoder that invented the answer would
//! be the worst kind of wrong on a plane whose whole output is findings.
//!
//! TAG 24 IS THE EXCEPTION, AND ITEM 442 IS WHY IT IS NOT AN INCONSISTENCY.
//! §3.4.5.1 does not say what the tag 24 content MEANS — it says what the
//! content IS, "a byte string containing an encoded CBOR data item". That is a
//! statement about the encoding, so [`Walk::embedded`] walks it and invents
//! nothing, which is the argument item 433 used to open CBOR in the first
//! place. A bignum needs a reading and gets none; an embedded document needs a
//! walk and this module already has one. The two were one sentence in this doc
//! until R311y916, and that sentence was wrong about which of them is which.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::payload::formats::PayloadField;

/// Where a walk stopped, and why, in the shape `crate::payload` already uses.
pub(crate) type CborErr = (usize, &'static str);

/// The nine things a CBOR data item can be.
///
/// Major types 0-6 plus the two halves of major type 7, which RFC 8949 splits by
/// additional information: 20-24 are the simple values and 25-27 the floats. A
/// reader acts differently on those two, so they are two kinds here rather than
/// one called `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborKind {
    /// Major type 0 — an unsigned integer.
    Unsigned,
    /// Major type 1 — a negative integer.
    Negative,
    /// Major type 2 — a byte string.
    Bytes,
    /// Major type 3 — a text string, which this walk has checked is UTF-8.
    Text,
    /// Major type 4 — an array.
    Array,
    /// Major type 5 — a map.
    Map,
    /// Major type 6 — a tag, wrapping one item.
    Tag,
    /// Major type 7, additional information 20-24 — `false`, `true`, `null`,
    /// `undefined`, or another simple value.
    Simple,
    /// Major type 7, additional information 25-27 — a half, single or double.
    Float,
}

impl CborKind {
    /// The word a row leads with.
    ///
    /// A TOTAL match rather than a `_ =>` fallback, on this crate's rule for
    /// wire-name functions: a tenth kind must be named here rather than
    /// silently rendered as whichever string happened to be the default.
    pub const fn word(self) -> &'static str {
        match self {
            CborKind::Unsigned => "unsigned",
            CborKind::Negative => "negative",
            CborKind::Bytes => "bytes",
            CborKind::Text => "text",
            CborKind::Array => "array",
            CborKind::Map => "map",
            CborKind::Tag => "tag",
            CborKind::Simple => "simple",
            CborKind::Float => "float",
        }
    }
}

/// What one CBOR payload turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CborSummary {
    /// The kind of the one top-level data item.
    pub top_level: CborKind,
    /// Deepest container nesting reached.
    pub depth: usize,
}

/// Guard against a document whose nesting would recurse this walk off the
/// stack, matching `crate::payload::MAX_JSON_DEPTH` because the constraint is
/// the same one: this crate also builds for the MCU profiles.
pub(crate) const MAX_CBOR_DEPTH: usize = 128;

/// The root path, shared with the JSON walk so a reader holds one syntax.
const CBOR_ROOT_PATH: &str = "$";

/// The separator between path segments — the protobuf walk's `2.1` and the JSON
/// walk's `$.a.b` use it too, which is the whole reason it is a `.`.
const CBOR_PATH_SEP: char = '.';

/// R311y910 (item 431) — what a `.` or a `\` inside a TEXT key is written with.
///
/// The same character and the same rule as the JSON walk, deliberately: this
/// walk is the second consumer of that decision and re-spelling it would make
/// one rule two.
const CBOR_PATH_ESCAPE: char = '\\';

/// RFC 8949 §3.4.5.1 — the tag whose byte string IS an encoded CBOR data item.
const TAG_EMBEDDED_CBOR: u64 = 24;

/// R311y925 (item 448) — every reserved leading form a path segment may take,
/// as SHIPPING code rather than as a list in a test.
///
/// The letters live in the free space item 434 found: a segment beginning `\`
/// followed by anything other than `.` or `\` cannot be produced by a text key,
/// because R311y910's rule emits `\` in exactly those two positions.
///
/// It is an enum and not a table of constants because of what item 448
/// measured: the declared list was `#[cfg(test)]` and nothing shipping was
/// bound to it, so a walker that began emitting a new form touched no list at
/// all. The corpus gate then said nothing in EITHER direction -- the new letter
/// was not observed (no payload makes that shape) and not declared (nobody had
/// to declare it). A round proved it: an eighth form added here passed a green
/// suite.
///
/// Now the set the gate compares against is derived from these variants, so a
/// new form is declared the moment it can be written, and its absence from
/// `PATH_CORPUS` is a FAILURE rather than a silence. The residue, stated rather
/// than hidden: this makes the registered road the easy one, it does not make a
/// raw `"\\q"` literal impossible. Catching that needs a source lint over
/// escape literals, which is the shape item 400 warns decays.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Reserved {
    /// A byte-string key, rendered as hex.
    Bytes,
    /// The document encoded INSIDE a tag 24 byte string. Distinct from
    /// [`Reserved::Tag`]: `\t` is the tag's content and `\e` is the document
    /// that content spells, and the byte string exists on the wire either way.
    Embedded,
    /// A floating-point key.
    Float,
    /// An integer key.
    Int,
    /// A simple value, named where RFC 8949 names one and numbered otherwise.
    Simple,
    /// The content of a tagged item.
    Tag,
    /// A key whose interior this build does not walk, anchored by its offset.
    Opaque,
}

impl Reserved {
    /// The letter this form claims. Exhaustive on purpose: a new variant does
    /// not compile until it has one, which is the half of the enforcement that
    /// bites in a shipping build.
    pub(crate) const fn letter(self) -> char {
        match self {
            Reserved::Bytes => 'b',
            Reserved::Embedded => 'e',
            Reserved::Float => 'f',
            Reserved::Int => 'i',
            Reserved::Simple => 's',
            Reserved::Tag => 't',
            Reserved::Opaque => 'x',
        }
    }

    /// This form's segment, with `body` after the letter.
    ///
    /// R2125 (open-debt item 463) — returns a [`Segment`], which is the only
    /// thing a path accepts. The construction moved into `path_builder` so
    /// that this is a door into the reserved namespace rather than one way of
    /// spelling it.
    fn segment(self, body: &str) -> Segment {
        Segment::reserved(self, body)
    }

    /// The variant after this one, so the set can be WALKED rather than
    /// transcribed. Exhaustive too, so a new variant must be given a place in
    /// the chain before the tests compile -- the second layer, because a letter
    /// alone would leave the new form out of the set the gate compares.
    #[cfg(test)]
    pub(crate) const fn next(self) -> Option<Self> {
        match self {
            Reserved::Bytes => Some(Reserved::Embedded),
            Reserved::Embedded => Some(Reserved::Float),
            Reserved::Float => Some(Reserved::Int),
            Reserved::Int => Some(Reserved::Simple),
            Reserved::Simple => Some(Reserved::Tag),
            Reserved::Tag => Some(Reserved::Opaque),
            Reserved::Opaque => None,
        }
    }

    /// Every reserved letter, in chain order.
    #[cfg(test)]
    pub(crate) fn letters() -> alloc::vec::Vec<char> {
        let mut out = alloc::vec::Vec::new();
        let mut cursor = Some(Reserved::Bytes);
        while let Some(form) = cursor {
            out.push(form.letter());
            cursor = form.next();
        }
        out
    }
}

/// R2125 (open-debt item 463) — THE PATH, WHICH ONLY A [`Segment`] MAY ENTER.
///
/// # What this closes, and why it is a type and not a lint
///
/// R311y925 routed all seven producers through [`Reserved`] and said so in its
/// own doc: "it does not make a raw `\"\\\\q\"` literal impossible. Catching
/// that needs a source lint over escape literals, which is the shape item 400
/// warns decays." Item 463 is that residue, and the lint it describes needs an
/// exclusion list -- `segment()` itself, the test expectations -- which is
/// exactly the filter item 400 says is statically bound to nothing.
///
/// So the bypass is made UNWRITABLE instead of watched. The inner `String` is
/// private to `path_builder`, so no code in this module -- not the walker, not
/// a future arm -- can push bytes into a path. The only doors are
/// [`Segment::reserved`], whose letter comes from the enum, and
/// [`Segment::text`], which ESCAPES its input: `Segment::text("\\q")` yields a
/// text segment spelling a backslash, never the reserved form. A new reserved
/// shape has to go through [`Reserved`], where declaring it is what makes it
/// writable.
///
/// MEASURED before this existed: a `push_str("\\q")` sitting in shipping code,
/// behind a condition `PATH_CORPUS` never satisfies, left 605 tests green.
/// That is item 463's claim exactly -- the corpus gate is the only judge, and
/// a producer the corpus does not reach is invisible to it in both directions.
mod path_builder {
    use super::{Reserved, CBOR_PATH_ESCAPE, CBOR_PATH_SEP};
    use alloc::string::String;

    /// One path segment, already in its final spelling.
    ///
    /// Constructible ONLY by the two functions below, which is the whole of the
    /// enforcement: a `&str` is not a `Segment`, so a literal cannot be pushed.
    /// `Ord` so item 441's duplicate-key set can hold segments: §5.6 equality
    /// is decided on the SEGMENT, which is derived from the value, not on the
    /// encoding.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub(super) struct Segment(String);

    impl Segment {
        /// A reserved segment: the escape, the form's declared letter, `body`.
        ///
        /// The letter is [`Reserved::letter`] and cannot be anything else,
        /// which is why this door needs no validation.
        pub(super) fn reserved(form: Reserved, body: &str) -> Self {
            let mut out = String::with_capacity(2 + body.len());
            out.push(CBOR_PATH_ESCAPE);
            out.push(form.letter());
            out.push_str(body);
            Self(out)
        }

        /// A segment from TEXT, escaped by R311y910's rule.
        ///
        /// The escaping is what makes this door safe rather than merely
        /// convenient: text that begins `\q` comes out as a segment spelling a
        /// literal backslash, so the reserved namespace cannot be entered
        /// through here by accident or on purpose.
        pub(super) fn text(s: &str) -> Self {
            let mut out = String::new();
            for c in s.chars() {
                if c == CBOR_PATH_SEP || c == CBOR_PATH_ESCAPE {
                    out.push(CBOR_PATH_ESCAPE);
                }
                out.push(c);
            }
            Self(out)
        }

        #[cfg(test)]
        pub(super) fn as_str(&self) -> &str {
            &self.0
        }
    }

    /// A path under construction. Grows only by [`Segment`], shrinks only to a
    /// mark it handed out.
    #[derive(Debug, Default, Clone)]
    pub(super) struct Path(String);

    impl Path {
        pub(super) fn len(&self) -> usize {
            self.0.len()
        }

        pub(super) fn push(&mut self, segment: &Segment) {
            self.0.push(CBOR_PATH_SEP);
            self.0.push_str(&segment.0);
        }

        pub(super) fn truncate(&mut self, mark: usize) {
            self.0.truncate(mark);
        }

        pub(super) fn as_str(&self) -> &str {
            &self.0
        }
    }

    impl From<&str> for Path {
        /// The ROOT only. A path starts as `$` and every later byte arrives as
        /// a segment.
        fn from(root: &str) -> Self {
            Self(String::from(root))
        }
    }
}

use path_builder::{Path, Segment};

/// The rows a walk is building, or `None` when it is only validating.
struct Emit {
    fields: Vec<PayloadField>,
    path: Path,
}

/// How a data item would render as a MAP KEY.
///
/// Produced as a by-product of walking the item, not by re-reading its bytes
/// afterwards. The difference matters: a re-read would need an arm for a failure
/// the walk has already ruled out, and a fallback nothing can reach reads as a
/// case that happens (R311y910's own note, in `push_key`).
#[derive(Clone, Copy)]
enum KeyForm<'a> {
    /// Major 0 or 1. `i128` because major 1's range reaches `-2^64`.
    Int(i128),
    /// Major 2, definite length — the content bytes.
    Bytes(&'a [u8]),
    /// Major 3, definite length — the content, already validated as UTF-8.
    Text(&'a str),
    /// Major 7, 20-23 — the word for it.
    Simple(&'static str),
    /// Major 7, 24 — a simple value with no assigned word.
    SimpleOther(u8),
    /// Major 7, 25-27.
    Float(f64),
    /// A container, a tag, or an indefinite-length string: something with no
    /// name to be called by.
    Opaque,
}

/// One item's head: the initial byte's two fields and the argument that follows.
#[derive(Clone, Copy)]
struct Head {
    major: u8,
    /// The additional information, 0-31.
    ai: u8,
    /// The argument the head encodes, or 0 for the indefinite form.
    arg: u64,
    /// Additional information 31 — the length follows as chunks or items until
    /// a break.
    indefinite: bool,
}

/// Is `bytes` one well-formed CBOR data item, and nothing after it?
pub(crate) fn scan_cbor(bytes: &[u8]) -> Result<CborSummary, CborErr> {
    scan(bytes, None).map(|(summary, _)| summary)
}

/// The same walk, with the rows.
pub(crate) fn walk_cbor(bytes: &[u8]) -> Result<Vec<PayloadField>, CborErr> {
    let emit = Emit {
        fields: Vec::new(),
        path: Path::from(CBOR_ROOT_PATH),
    };
    let (_, emit) = scan(bytes, Some(emit))?;
    Ok(emit.expect("the walk was handed an emitter").fields)
}

fn scan(bytes: &[u8], emit: Option<Emit>) -> Result<(CborSummary, Option<Emit>), CborErr> {
    let mut s = Walk {
        b: bytes,
        i: 0,
        depth: 0,
        max_depth: 0,
        emit,
    };
    let (top, _) = s.item()?;
    if s.i != s.b.len() {
        // RFC 8949 §5.1: a CBOR data item is ONE item. Trailing bytes are what
        // a `application/cbor` label over a stream of items looks like, and
        // naming it here is what lets `inspect` refute the label -- the whole
        // reason item 433's symptom was "no rule can be applied".
        return Err((s.i, "trailing input after the one top-level data item"));
    }
    Ok((
        CborSummary {
            top_level: top,
            depth: s.max_depth,
        },
        s.emit,
    ))
}

struct Walk<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
    max_depth: usize,
    emit: Option<Emit>,
}

/// The reserved additional-information values, named once.
const RESERVED_AI: &str = "additional information 28, 29 and 30 are reserved";

impl<'a> Walk<'a> {
    fn byte(&mut self) -> Result<u8, CborErr> {
        let b = *self
            .b
            .get(self.i)
            .ok_or((self.i, "the payload ends here"))?;
        self.i += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborErr> {
        let end = self
            .i
            .checked_add(n)
            .ok_or((self.i, "a length that overflows"))?;
        let raw = self
            .b
            .get(self.i..end)
            .ok_or((self.i, "the payload ends inside this item"))?;
        self.i = end;
        Ok(raw)
    }

    /// Read one item's head, advancing past its argument bytes.
    ///
    /// A `break` (major 7, ai 31) is a head like any other here; the callers
    /// that may accept one check for it, and the ones that may not report it.
    fn head(&mut self) -> Result<Head, CborErr> {
        let at = self.i;
        let initial = self.byte()?;
        let major = initial >> 5;
        let ai = initial & 0x1f;
        let (arg, indefinite) = match ai {
            0..=23 => (u64::from(ai), false),
            24 => (u64::from(self.byte()?), false),
            25 => {
                let raw = self.take(2)?;
                (u64::from(u16::from_be_bytes([raw[0], raw[1]])), false)
            }
            26 => {
                let raw = self.take(4)?;
                (
                    u64::from(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]])),
                    false,
                )
            }
            27 => {
                let raw = self.take(8)?;
                (
                    u64::from_be_bytes([
                        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                    ]),
                    false,
                )
            }
            31 => {
                // RFC 8949 §3.2: only the four container-ish majors may say
                // "indefinite", and major 7 ai 31 is the break that ends one.
                if !matches!(major, 2 | 3 | 4 | 5 | 7) {
                    return Err((at, "an indefinite length on a type that has no end marker"));
                }
                (0, true)
            }
            _ => return Err((at, RESERVED_AI)),
        };
        Ok(Head {
            major,
            ai,
            arg,
            indefinite,
        })
    }

    /// Reserve this item's row so a container lands ABOVE its children, the
    /// order the JSON and protobuf walks already emit in.
    fn reserve(&mut self) -> Option<usize> {
        let e = self.emit.as_mut()?;
        let at = e.fields.len();
        e.fields.push(PayloadField {
            path: String::new(),
            name: None,
            value: String::new(),
            start: 0,
            end: 0,
        });
        Some(at)
    }

    /// Write the reserved row, now that the item's extent and rendering are
    /// known.
    fn fill(&mut self, slot: Option<usize>, start: usize, value: String) {
        let Some(slot) = slot else { return };
        let end = self.i;
        let Some(e) = self.emit.as_mut() else { return };
        e.fields[slot] = PayloadField {
            path: String::from(e.path.as_str()),
            name: None,
            value,
            start,
            end,
        };
    }

    /// Extend the path by one segment, returning the mark to truncate back to.
    fn push(&mut self, segment: &Segment) -> Option<usize> {
        let e = self.emit.as_mut()?;
        let mark = e.path.len();
        e.path.push(segment);
        Some(mark)
    }

    fn pop(&mut self, mark: Option<usize>) {
        if let (Some(mark), Some(e)) = (mark, self.emit.as_mut()) {
            e.path.truncate(mark);
        }
    }

    /// Walk one data item. Returns its kind and, for a caller that needs to name
    /// it, how it would render as a map key.
    fn item(&mut self) -> Result<(CborKind, KeyForm<'a>), CborErr> {
        let start = self.i;
        let slot = self.reserve();
        let h = self.head()?;
        if h.major == 7 && h.indefinite {
            // A break with no container to close. Reported at the break's own
            // offset because that is the byte a reader has to look at.
            return Err((start, "a break outside an indefinite-length item"));
        }
        let (kind, form, value) = match h.major {
            0 => (
                CborKind::Unsigned,
                KeyForm::Int(i128::from(h.arg)),
                format!("unsigned {}", h.arg),
            ),
            1 => {
                // RFC 8949 §3.1: the encoded argument n stands for -1-n, so the
                // reachable minimum is -2^64 and does not fit an i64.
                let v = -1i128 - i128::from(h.arg);
                (CborKind::Negative, KeyForm::Int(v), format!("negative {v}"))
            }
            2 => {
                let (form, value) = self.string_body(&h, start, false)?;
                (CborKind::Bytes, form, value)
            }
            3 => {
                let (form, value) = self.string_body(&h, start, true)?;
                (CborKind::Text, form, value)
            }
            4 => {
                let (n, indef) = self.array_body(&h, start)?;
                (
                    CborKind::Array,
                    KeyForm::Opaque,
                    format!("array {n} element(s){}", indef_note(indef)),
                )
            }
            5 => {
                let (n, indef, dup) = self.map_body(&h, start)?;
                (
                    CborKind::Map,
                    KeyForm::Opaque,
                    format!("map {n} pair(s){}{}", indef_note(indef), dup_note(dup)),
                )
            }
            6 => {
                self.tagged(start, h.arg)?;
                (CborKind::Tag, KeyForm::Opaque, format!("tag {}", h.arg))
            }
            7 => self.seven(&h, start)?,
            // Three bits hold eight values and all eight are matched above, so
            // there is no arm for this to be. Stated as an error rather than an
            // `unreachable!` because a panic in a walk over attacker-influenced
            // bytes is the one outcome this crate refuses everywhere else.
            _ => return Err((start, "a major type outside 0-7")),
        };
        self.fill(slot, start, value);
        Ok((kind, form))
    }

    /// Major 2 and 3. `text` selects the UTF-8 requirement and the rendering.
    fn string_body(
        &mut self,
        h: &Head,
        start: usize,
        text: bool,
    ) -> Result<(KeyForm<'a>, String), CborErr> {
        if !h.indefinite {
            let len =
                usize::try_from(h.arg).map_err(|_| (start, "a length wider than this host"))?;
            let at = self.i;
            let raw = self.take(len)?;
            if !text {
                return Ok((KeyForm::Bytes(raw), format!("bytes {len} byte(s)")));
            }
            let s = core::str::from_utf8(raw).map_err(|e| {
                (
                    at + e.valid_up_to(),
                    "not UTF-8, which RFC 8949 §3.1 requires",
                )
            })?;
            return Ok((KeyForm::Text(s), format!("text {s:?}")));
        }
        // RFC 8949 §3.2.3 — the chunks of an indefinite-length string must
        // themselves be DEFINITE strings of the SAME major type. A nested
        // indefinite chunk, or a chunk of the other type, is not well-formed.
        let mut total = 0usize;
        loop {
            let chunk_at = self.i;
            let c = self.head()?;
            if c.major == 7 && c.indefinite {
                break;
            }
            if c.major != h.major || c.indefinite {
                return Err((
                    chunk_at,
                    "a chunk of an indefinite-length string must be a definite string of the same type",
                ));
            }
            let len =
                usize::try_from(c.arg).map_err(|_| (chunk_at, "a length wider than this host"))?;
            let at = self.i;
            let raw = self.take(len)?;
            if h.major == 3 {
                // Per chunk, which is what §3.2.3 requires: each chunk is its
                // own text string, so each must be UTF-8 on its own. A
                // multi-byte character split across two chunks is therefore
                // malformed rather than something to stitch.
                core::str::from_utf8(raw).map_err(|e| {
                    (
                        at + e.valid_up_to(),
                        "not UTF-8, which RFC 8949 §3.1 requires",
                    )
                })?;
            }
            total += len;
        }
        let word = if text { "text" } else { "bytes" };
        Ok((
            KeyForm::Opaque,
            format!("{word} {total} byte(s), indefinite"),
        ))
    }

    /// Major 4. Returns how many elements were walked and whether it was the
    /// indefinite form.
    fn array_body(&mut self, h: &Head, start: usize) -> Result<(usize, bool), CborErr> {
        self.enter(start)?;
        let mut n = 0usize;
        if h.indefinite {
            loop {
                if self.at_break()? {
                    break;
                }
                let mark = self.push(&Segment::text(&format!("{n}")));
                let r = self.item();
                self.pop(mark);
                r?;
                n += 1;
            }
        } else {
            let count =
                usize::try_from(h.arg).map_err(|_| (start, "a count wider than this host"))?;
            while n < count {
                let mark = self.push(&Segment::text(&format!("{n}")));
                let r = self.item();
                self.pop(mark);
                r?;
                n += 1;
            }
        }
        self.leave();
        Ok((n, h.indefinite))
    }

    /// Major 5. Each pair is a key item and a value item; the key becomes the
    /// value's path segment and gets no row of its own, which is the rule the
    /// JSON walk follows for the same reason (the key is not lost — it IS the
    /// last segment of the path).
    ///
    /// # R311y916 (item 441) — the duplicate count
    ///
    /// RFC 8949 §5.6 makes a map with two equal keys INVALID, and the third
    /// return value is how many pairs arrived on a key already seen. Compared
    /// on the PATH SEGMENT, which is the right comparison twice over: §5.6's
    /// equality is over §2's generic data model rather than over the encoding,
    /// and the segment is derived from the value, so `1` in its immediate form
    /// and `1` in its one-byte form come out equal though their bytes do not.
    /// What it cannot compare is a key with no name — a container key gets a
    /// `\x<offset>` locator, unique by construction, so two identical container
    /// keys are not counted and a test pins that gap rather than hiding it.
    ///
    /// The cost item 441 named is real and is paid here rather than argued
    /// away: one set per open container, holding the key segments this walk
    /// already builds. It is taken only when rows are being emitted, because on
    /// the validation path (`scan_cbor`, which every payload in a capture runs
    /// through) there is no row for the answer to land on.
    fn map_body(&mut self, h: &Head, start: usize) -> Result<(usize, bool, usize), CborErr> {
        self.enter(start)?;
        let mut n = 0usize;
        let mut dup = 0usize;
        let mut seen = self.emit.as_ref().map(|_| BTreeSet::new());
        let definite = if h.indefinite {
            None
        } else {
            Some(usize::try_from(h.arg).map_err(|_| (start, "a count wider than this host"))?)
        };
        loop {
            match definite {
                Some(count) if n >= count => break,
                None if self.at_break()? => break,
                _ => {}
            }
            let segment = self.key_segment()?;
            if let Some(seen) = seen.as_mut() {
                if !seen.insert(segment.clone()) {
                    dup += 1;
                }
            }
            let mark = self.push(&segment);
            let r = self.item();
            self.pop(mark);
            r?;
            n += 1;
        }
        self.leave();
        Ok((n, h.indefinite, dup))
    }

    /// Major 6 — the tag's one item, walked under `\t` with the depth
    /// accounted for, and for tag 24 the DOCUMENT that item spells.
    ///
    /// The re-entry is not an interpretation of the tag: RFC 8949 §3.4.5.1 says
    /// the content of tag 24 is "a byte string containing an encoded CBOR data
    /// item", which is a statement about the ENCODING and needs no schema. Tag
    /// 2's bignum is the other kind and still gets none — rendering its bytes
    /// as a number is a reading, and this crate does not read.
    fn tagged(&mut self, start: usize, tag: u64) -> Result<(), CborErr> {
        self.enter(start)?;
        let mark = self.push(&Reserved::Tag.segment(""));
        let walked = self.item();
        // Only a DEFINITE major 2 answers `KeyForm::Bytes`, which is exactly the
        // case that can be re-entered: the content is then a contiguous slice of
        // the buffer, so the offsets the sub-walk reports are still offsets into
        // the capture. `self.i` is the end of the tag's one item, so the content
        // start is that minus its length.
        let span = match (&walked, tag) {
            (Ok((_, KeyForm::Bytes(raw))), TAG_EMBEDDED_CBOR) => Some((self.i - raw.len(), self.i)),
            _ => None,
        };
        if let Some((from, to)) = span {
            self.embedded(from, to);
        }
        self.pop(mark);
        walked?;
        self.leave();
        Ok(())
    }

    /// R311y916 (item 442) — walk the document a tag 24 byte string spells.
    ///
    /// # Why the buffer is narrowed rather than copied
    ///
    /// `start..end` is a slice of the ORIGINAL bytes, so the sub-walk runs over
    /// `self.b` with its end moved in. Every offset it reports therefore stays
    /// an offset into the capture, which is the only kind of span a reader of
    /// this crate can act on — a row whose span means something else is worse
    /// than an absent row. It also shares the depth counter, so nesting through
    /// tag 24 cannot buy an attacker a fresh budget for the price of a wrapper.
    ///
    /// # Why a failure never reaches the outer walk
    ///
    /// The decision item 442 asked for. §3.4.5.1's requirement is a VALIDITY
    /// rule about the content, and the outer document's ENCODING is well-formed
    /// whatever the byte string holds — R311y914 drew this crate's line between
    /// the two and this is the same line. So a sub-walk that fails drops its
    /// partial rows, leaves one row saying where it stopped, and the outer walk
    /// carries on. The precedent is the protobuf walk's `text_like` fallback: a
    /// sub-decode that fails describes what it found rather than condemning
    /// what carried it.
    fn embedded(&mut self, start: usize, end: usize) {
        let mark = self.push(&Reserved::Embedded.segment(""));
        let outcome = match self.enter(start) {
            Err(e) => Err(e),
            Ok(()) => {
                let rows = self.emit.as_ref().map(|e| e.fields.len());
                let outer_b = self.b;
                let outer_i = self.i;
                self.b = &self.b[..end];
                self.i = start;
                let walked = match self.item() {
                    Err(e) => Err(e),
                    Ok(_) if self.i == end => Ok(()),
                    // The same rule `scan` applies to the outer document, and
                    // for the same reason: §3.4.5.1 says "an encoded CBOR data
                    // item", singular.
                    Ok(_) => Err((self.i, "trailing input after the one top-level data item")),
                };
                self.b = outer_b;
                self.i = outer_i;
                self.leave();
                if walked.is_err() {
                    if let (Some(rows), Some(e)) = (rows, self.emit.as_mut()) {
                        e.fields.truncate(rows);
                    }
                }
                walked
            }
        };
        if let Err((at, why)) = outcome {
            self.note(
                start,
                end,
                format!("not an embedded document: {why} at byte {at}"),
            );
        }
        self.pop(mark);
    }

    /// One row at the current path that no item reserved — what the walk found
    /// where an item was expected.
    fn note(&mut self, start: usize, end: usize, value: String) {
        let Some(e) = self.emit.as_mut() else { return };
        let path = String::from(e.path.as_str());
        e.fields.push(PayloadField {
            path,
            name: None,
            value,
            start,
            end,
        });
    }

    /// Major 7 — the simple values and the floats.
    fn seven(
        &mut self,
        h: &Head,
        start: usize,
    ) -> Result<(CborKind, KeyForm<'a>, String), CborErr> {
        match h.ai {
            0..=19 => Ok((
                CborKind::Simple,
                KeyForm::SimpleOther(h.arg as u8),
                format!("simple({})", h.arg),
            )),
            20 => Ok((
                CborKind::Simple,
                KeyForm::Simple("false"),
                String::from("bool false"),
            )),
            21 => Ok((
                CborKind::Simple,
                KeyForm::Simple("true"),
                String::from("bool true"),
            )),
            22 => Ok((
                CborKind::Simple,
                KeyForm::Simple("null"),
                String::from("null"),
            )),
            23 => Ok((
                CborKind::Simple,
                KeyForm::Simple("undefined"),
                String::from("undefined"),
            )),
            24 => {
                // RFC 8949 §3.3: the one-byte form must not encode a value
                // below 32, because those have the immediate form above.
                if h.arg < 32 {
                    return Err((start, "a one-byte simple value below 32"));
                }
                Ok((
                    CborKind::Simple,
                    KeyForm::SimpleOther(h.arg as u8),
                    format!("simple({})", h.arg),
                ))
            }
            25 => {
                let v = f16_to_f64(h.arg as u16);
                Ok((CborKind::Float, KeyForm::Float(v), format!("float {v}")))
            }
            26 => {
                let v = f64::from(f32::from_bits(h.arg as u32));
                Ok((CborKind::Float, KeyForm::Float(v), format!("float {v}")))
            }
            27 => {
                let v = f64::from_bits(h.arg);
                Ok((CborKind::Float, KeyForm::Float(v), format!("float {v}")))
            }
            // 28-30 were refused in `head`, and 31 is the break `item` catches
            // before this is reached. Named rather than defaulted, so a reader
            // does not have to prove the gap is empty.
            _ => Err((start, RESERVED_AI)),
        }
    }

    /// Walk a map key without emitting a row for it, and render it as a path
    /// segment. See the module doc for why each form looks the way it does.
    fn key_segment(&mut self) -> Result<Segment, CborErr> {
        let at = self.i;
        // The emitter is set aside rather than branched on: a key is validated
        // exactly as any other item, and suppressing the row here is what keeps
        // `item` free of a "am I a key" parameter it would have to thread
        // through every arm.
        let saved = self.emit.take();
        let walked = self.item();
        self.emit = saved;
        let (_, form) = walked?;
        Ok(match form {
            KeyForm::Text(s) => Segment::text(s),
            KeyForm::Int(v) => Reserved::Int.segment(&alloc::format!("{v}")),
            KeyForm::Bytes(raw) => {
                let mut hex = String::new();
                for b in raw {
                    hex.push_str(&alloc::format!("{b:02x}"));
                }
                Reserved::Bytes.segment(&hex)
            }
            // R311y916 (item 443) — ESCAPED, because `format!("{v}")` puts a `.`
            // in every float that has a fractional part, and an unescaped
            // separator inside a segment is the collision item 434 exists to
            // prevent: `$.\f1.5` would otherwise be both `{1.5: _}` and
            // `{1.0: {"5": _}}`. The other reserved forms render digits, hex or
            // a fixed word and need nothing.
            KeyForm::Float(v) => Reserved::Float.segment(&escape_segment(&alloc::format!("{v}"))),
            KeyForm::Simple(word) => Reserved::Simple.segment(word),
            KeyForm::SimpleOther(n) => Reserved::Simple.segment(&alloc::format!("{n}")),
            KeyForm::Opaque => Reserved::Opaque.segment(&alloc::format!("{at}")),
        })
    }

    /// Is the next byte a break? Consumes it when it is.
    fn at_break(&mut self) -> Result<bool, CborErr> {
        match self.b.get(self.i) {
            Some(0xff) => {
                self.i += 1;
                Ok(true)
            }
            Some(_) => Ok(false),
            None => Err((self.i, "an indefinite-length item with no break")),
        }
    }

    fn enter(&mut self, start: usize) -> Result<(), CborErr> {
        self.depth += 1;
        if self.depth > MAX_CBOR_DEPTH {
            return Err((start, "nested deeper than this reader walks"));
        }
        if self.depth > self.max_depth {
            self.max_depth = self.depth;
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }
}

/// `, indefinite` when it was, and nothing when it was not — a wire fact a
/// reader comparing two captures will want.
fn indef_note(indefinite: bool) -> &'static str {
    if indefinite {
        ", indefinite"
    } else {
        ""
    }
}

/// R311y910's rule, in one place: a `.` or a `\` going INTO a path segment is
/// written with a leading `\`.
///
/// R311y916 (item 443) made this a function rather than a loop inside the text
/// arm of `key_segment`, because the float arm needed the same rule and did not
/// have it — a rendering with a `.` in it re-opened item 434's collision from
/// inside the reserved namespace. Any arm that puts a RENDERED value into a
/// segment goes through here.
fn escape_segment(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c == CBOR_PATH_SEP || c == CBOR_PATH_ESCAPE {
            out.push(CBOR_PATH_ESCAPE);
        }
        out.push(c);
    }
    out
}

/// R311y916 (item 441) — `, N duplicate key(s)` when RFC 8949 §5.6 was broken,
/// and nothing at all when it was not.
///
/// Absent rather than `, 0 duplicate key(s)` for the reason every other note in
/// this module is absent when it has nothing to say: a row a reader scans for
/// findings should carry only what was found.
fn dup_note(duplicates: usize) -> String {
    if duplicates == 0 {
        String::new()
    } else {
        format!(", {duplicates} duplicate key(s)")
    }
}

/// The Appendix A vectors this module is gated against, as (hex, what RFC 8949
/// calls it, the top-level kind).
///
/// RFC 8949 Appendix A is the format's OWN table of encoded values — the closest
/// thing to a foreign witness available for a wire format whose reference
/// implementations this workspace does not vendor. Copied from the RFC rather
/// than produced by this decoder, which is the property that matters: a table
/// this walk generated would agree with itself no matter what it did.
#[cfg(test)]
const RFC8949_APPENDIX_A: &[(&[u8], &str, CborKind)] = &[
    (&[0x00], "0", CborKind::Unsigned),
    (&[0x01], "1", CborKind::Unsigned),
    (&[0x0a], "10", CborKind::Unsigned),
    (&[0x17], "23", CborKind::Unsigned),
    (&[0x18, 0x18], "24", CborKind::Unsigned),
    (&[0x18, 0x64], "100", CborKind::Unsigned),
    (&[0x19, 0x03, 0xe8], "1000", CborKind::Unsigned),
    (
        &[0x1a, 0x00, 0x0f, 0x42, 0x40],
        "1000000",
        CborKind::Unsigned,
    ),
    (
        &[0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00],
        "1000000000000",
        CborKind::Unsigned,
    ),
    (
        &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        "18446744073709551615",
        CborKind::Unsigned,
    ),
    (&[0x20], "-1", CborKind::Negative),
    (&[0x29], "-10", CborKind::Negative),
    (&[0x38, 0x63], "-100", CborKind::Negative),
    (&[0x39, 0x03, 0xe7], "-1000", CborKind::Negative),
    (
        &[0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        "-18446744073709551616",
        CborKind::Negative,
    ),
    (&[0xf9, 0x00, 0x00], "0.0", CborKind::Float),
    (&[0xf9, 0x80, 0x00], "-0.0", CborKind::Float),
    (&[0xf9, 0x3c, 0x00], "1.0", CborKind::Float),
    (
        &[0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a],
        "1.1",
        CborKind::Float,
    ),
    (&[0xf9, 0x3e, 0x00], "1.5", CborKind::Float),
    (&[0xf9, 0x7b, 0xff], "65504.0", CborKind::Float),
    (&[0xfa, 0x47, 0xc3, 0x50, 0x00], "100000.0", CborKind::Float),
    (&[0xf9, 0x00, 0x01], "5.960464477539063e-8", CborKind::Float),
    (&[0xf9, 0x04, 0x00], "0.00006103515625", CborKind::Float),
    (&[0xf9, 0xc4, 0x00], "-4.0", CborKind::Float),
    (&[0xf9, 0x7c, 0x00], "Infinity", CborKind::Float),
    (&[0xf9, 0x7e, 0x00], "NaN", CborKind::Float),
    (&[0xf4], "false", CborKind::Simple),
    (&[0xf5], "true", CborKind::Simple),
    (&[0xf6], "null", CborKind::Simple),
    (&[0xf7], "undefined", CborKind::Simple),
    (&[0xf0], "simple(16)", CborKind::Simple),
    (&[0xf8, 0xff], "simple(255)", CborKind::Simple),
    (
        &[
            0xc0, 0x74, 0x32, 0x30, 0x31, 0x33, 0x2d, 0x30, 0x33, 0x2d, 0x32, 0x31, 0x54, 0x32,
            0x30, 0x3a, 0x30, 0x34, 0x3a, 0x30, 0x30, 0x5a,
        ],
        "0(\"2013-03-21T20:04:00Z\")",
        CborKind::Tag,
    ),
    (
        &[0xc1, 0x1a, 0x51, 0x4b, 0x67, 0xb0],
        "1(1363896240)",
        CborKind::Tag,
    ),
    (
        &[0xd7, 0x44, 0x01, 0x02, 0x03, 0x04],
        "23(h'01020304')",
        CborKind::Tag,
    ),
    // R311y916 (item 442) — Appendix A's tag 24 vector, which the table had
    // been missing. Its byte string is Appendix A's own `"IETF"` vector, so
    // this row is the RFC saying that the content of a tag 24 IS a document.
    (
        &[0xd8, 0x18, 0x45, 0x64, 0x49, 0x45, 0x54, 0x46],
        "24(h'6449455446')",
        CborKind::Tag,
    ),
    (&[0x40], "h''", CborKind::Bytes),
    (
        &[0x44, 0x01, 0x02, 0x03, 0x04],
        "h'01020304'",
        CborKind::Bytes,
    ),
    (&[0x60], "\"\"", CborKind::Text),
    (&[0x61, 0x61], "\"a\"", CborKind::Text),
    (&[0x64, 0x49, 0x45, 0x54, 0x46], "\"IETF\"", CborKind::Text),
    (&[0x62, 0x22, 0x5c], "\"\\\"\\\\\"", CborKind::Text),
    (&[0x62, 0xc3, 0xbc], "\"\\u00fc\"", CborKind::Text),
    (&[0x80], "[]", CborKind::Array),
    (&[0x83, 0x01, 0x02, 0x03], "[1, 2, 3]", CborKind::Array),
    (
        &[0x83, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05],
        "[1, [2, 3], [4, 5]]",
        CborKind::Array,
    ),
    (&[0xa0], "{}", CborKind::Map),
    (
        &[0xa2, 0x01, 0x02, 0x03, 0x04],
        "{1: 2, 3: 4}",
        CborKind::Map,
    ),
    (
        &[0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x82, 0x02, 0x03],
        "{\"a\": 1, \"b\": [2, 3]}",
        CborKind::Map,
    ),
    (
        &[0x82, 0x61, 0x61, 0xa1, 0x61, 0x62, 0x61, 0x63],
        "[\"a\", {\"b\": \"c\"}]",
        CborKind::Array,
    ),
    (
        &[0x5f, 0x42, 0x01, 0x02, 0x43, 0x03, 0x04, 0x05, 0xff],
        "(_ h'0102', h'030405')",
        CborKind::Bytes,
    ),
    (
        &[
            0x7f, 0x65, 0x73, 0x74, 0x72, 0x65, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x67, 0xff,
        ],
        "(_ \"strea\", \"ming\")",
        CborKind::Text,
    ),
    (&[0x9f, 0xff], "[_ ]", CborKind::Array),
    (
        &[0x9f, 0x01, 0x82, 0x02, 0x03, 0x9f, 0x04, 0x05, 0xff, 0xff],
        "[_ 1, [2, 3], [_ 4, 5]]",
        CborKind::Array,
    ),
    (
        &[
            0xbf, 0x61, 0x61, 0x01, 0x61, 0x62, 0x9f, 0x02, 0x03, 0xff, 0xff,
        ],
        "{_ \"a\": 1, \"b\": [_ 2, 3]}",
        CborKind::Map,
    ),
    (
        &[
            0xbf, 0x63, 0x46, 0x75, 0x6e, 0xf5, 0x63, 0x41, 0x6d, 0x74, 0x21, 0xff,
        ],
        "{_ \"Fun\": true, \"Amt\": -2}",
        CborKind::Map,
    ),
];

/// RFC 8949 Appendix F — encodings that are NOT well-formed, and the reason each
/// one is the interesting kind of broken.
///
/// A decoder is only as good as what it REFUSES, and every entry here is a
/// shape a permissive walk accepts: a reserved head, a truncated argument, a
/// container that promises more than it holds, a break with nothing to close, a
/// chunk of the wrong type inside an indefinite string, a simple value in the
/// form the RFC forbids, and a second data item after the first.
#[cfg(test)]
const NOT_WELL_FORMED: &[(&[u8], &str)] = &[
    (&[0x1c], "additional information 28 is reserved"),
    (&[0x1d], "additional information 29 is reserved"),
    (&[0x1e], "additional information 30 is reserved"),
    (&[0x18], "a one-byte argument with no byte after it"),
    (&[0x19, 0x01], "a two-byte argument with one byte"),
    (&[0x62, 0x61], "a two-byte text string with one byte"),
    (&[0x81], "an array of one with no element"),
    (&[0xa1, 0x00], "a map of one pair with no value"),
    (&[0xff], "a break with nothing to close"),
    (&[0x9f, 0x01], "an indefinite array with no break"),
    (
        &[0xbf, 0x61, 0x61],
        "an indefinite map with no value or break",
    ),
    (
        &[0x5f, 0x00, 0xff],
        "an indefinite byte string whose chunk is an integer",
    ),
    (
        &[0x7f, 0x41, 0x00, 0xff],
        "an indefinite text string whose chunk is a byte string",
    ),
    (
        &[0x5f, 0x5f, 0x40, 0xff, 0xff],
        "an indefinite byte string nested in one",
    ),
    (&[0xf8, 0x00], "a one-byte simple value below 32"),
    (&[0x61, 0xff], "a text string that is not UTF-8"),
    (&[0x00, 0x00], "a second data item after the first"),
    (&[0x9f], "an indefinite array that just ends"),
    (&[0x1f], "an indefinite length on an integer"),
];

/// IEEE 754 binary16 to binary64, by bit pattern.
///
/// Built rather than borrowed for two reasons that both matter here: `f16` is
/// not stable, and the arithmetic route (`frac * 2f64.powi(-24)`) needs `powi`,
/// which is `std`. This crate builds `no_std` for the MCU profiles, and
/// [`f64::from_bits`] is `core`.
fn f16_to_f64(bits: u16) -> f64 {
    let sign = u64::from(bits >> 15) << 63;
    let exp = (bits >> 10) & 0x1f;
    let frac = u64::from(bits & 0x03ff);
    match exp {
        // Zero and the subnormals.
        0 => {
            if frac == 0 {
                return f64::from_bits(sign);
            }
            // A subnormal half is `frac * 2^-24`. Normalising it means shifting
            // the fraction up until its implicit bit is set, and paying for each
            // shift in the exponent.
            let mut m = frac;
            let mut e = -14i32;
            while m & 0x0400 == 0 {
                m <<= 1;
                e -= 1;
            }
            m &= 0x03ff;
            f64::from_bits(sign | (((e + 1023) as u64) << 52) | (m << 42))
        }
        // Infinity and the NaNs keep their payload, shifted into place.
        0x1f => f64::from_bits(sign | (0x7ffu64 << 52) | (frac << 42)),
        _ => {
            let e = i32::from(exp) - 15 + 1023;
            f64::from_bits(sign | ((e as u64) << 52) | (frac << 42))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// R2125 (open-debt item 463) — THE TEXT DOOR CANNOT ENTER THE RESERVED
    /// NAMESPACE, WHATEVER TEXT GOES THROUGH IT.
    ///
    /// # Why this rather than a lint over escape literals
    ///
    /// Item 463 is R311y925's own stated residue: routing the seven producers
    /// through [`Reserved`] made the registered road easy and left
    /// `push_str("\\q")` writable. Its candidate was a source sweep for escape
    /// literals with `segment()` and the test expectations excluded -- and item
    /// 448 had already noted that the exclusion list is exactly the filter item
    /// 400 warns is bound to nothing.
    ///
    /// MEASURED before the change: a `push_str("\\q")` in the walker, behind a
    /// condition `PATH_CORPUS` never satisfies, left 605 tests green. So the
    /// corpus gate is the only judge and it cannot see a producer it does not
    /// reach -- in either direction, which is item 448's finding restated.
    ///
    /// The bypass is now UNWRITABLE: `Path` holds a private `String` in a child
    /// module, so nothing in this file can push bytes into a path, and the only
    /// two doors are the enum's and this one. THAT half is held by the
    /// compiler. What this test holds is the other half -- that the text door
    /// escapes rather than admits.
    ///
    /// # The population is derived, and it includes a letter nobody declared
    ///
    /// The declared letters come from [`Reserved::letters`]. An UNDECLARED one
    /// is added, because the interesting input is the form a future round
    /// invents: if `text` admitted it, the namespace would be enterable by a
    /// shape no gate is watching for.
    #[test]
    fn the_text_door_cannot_enter_the_reserved_namespace() {
        let declared = Reserved::letters();
        assert!(
            !declared.is_empty(),
            "no reserved letters at all; the population is empty and nothing \
             below is measuring anything"
        );
        let undeclared = ('a'..='z')
            .find(|c| !declared.contains(c))
            .expect("the alphabet is wider than the reserved set");

        let mut probes = declared.clone();
        probes.push(undeclared);
        for letter in probes {
            let raw = alloc::format!("{CBOR_PATH_ESCAPE}{letter}body");
            let through_text = Segment::text(&raw);
            assert_ne!(
                through_text.as_str(),
                raw,
                "text beginning `\\{letter}` came out of the text door \
                 unescaped, so a caller can spell a reserved segment with a \
                 string -- which is the bypass item 463 is about"
            );
            let doubled = alloc::format!("{CBOR_PATH_ESCAPE}{CBOR_PATH_ESCAPE}");
            assert!(
                through_text.as_str().starts_with(&doubled),
                "the text door must escape a leading escape: {:?}",
                through_text.as_str()
            );
        }

        // THE CONTROL, in this same test. Without it a `text` that escaped
        // everything into oblivion would satisfy every assertion above while
        // the reserved namespace had become unreachable by ANY door.
        let mut cursor = Some(Reserved::Bytes);
        let mut reached = 0usize;
        while let Some(form) = cursor {
            let seg = form.segment("body");
            assert!(
                seg.as_str()
                    .starts_with(&alloc::format!("{CBOR_PATH_ESCAPE}{}", form.letter())),
                "the reserved door must still produce {form:?}'s form: {:?}",
                seg.as_str()
            );
            reached += 1;
            cursor = form.next();
        }
        assert_eq!(
            reached,
            declared.len(),
            "the control walked {reached} form(s) and the set declares {}",
            declared.len()
        );
    }

    /// R311y914 — EVERY APPENDIX A VECTOR IS WELL-FORMED, and its top-level kind
    /// is the one the RFC's own diagnostic notation says.
    ///
    /// The vectors come from RFC 8949 Appendix A, not from this walk, which is
    /// the property that makes the gate mean anything: a corpus this decoder
    /// produced would agree with whatever the decoder did.
    #[test]
    fn every_appendix_a_vector_is_well_formed_with_the_kind_the_rfc_says() {
        assert!(
            !RFC8949_APPENDIX_A.is_empty(),
            "a gate over nothing is green"
        );
        for (bytes, diagnostic, kind) in RFC8949_APPENDIX_A {
            let summary = scan_cbor(bytes).unwrap_or_else(|(at, why)| {
                panic!("RFC 8949 spells this `{diagnostic}` and byte {at} says {why}")
            });
            assert_eq!(
                summary.top_level, *kind,
                "`{diagnostic}` is a {kind:?} in the RFC and a {:?} here",
                summary.top_level
            );
        }
    }

    /// R311y914 — AND NONE OF APPENDIX F'S IS.
    ///
    /// The half a permissive walk fails. Each entry names the shape it is, so a
    /// red here says which rule stopped holding rather than only that one did.
    #[test]
    fn no_appendix_f_encoding_is_accepted() {
        assert!(!NOT_WELL_FORMED.is_empty(), "a gate over nothing is green");
        for (bytes, what) in NOT_WELL_FORMED {
            let got = scan_cbor(bytes);
            assert!(
                got.is_err(),
                "{what} was accepted as well-formed CBOR: {got:?}"
            );
        }
    }

    /// R311y914 — THE VALIDATOR AND THE WALK ARE ONE GRAMMAR.
    ///
    /// The claim `crate::payload_builtin::Cbor`'s doc makes, asserted rather
    /// than stated: `inspect` uses [`scan_cbor`] and the decoder uses
    /// [`walk_cbor`], so a divergence would let the plane above call a payload
    /// well-formed that the plane below refused. Both directions, and the
    /// OFFSET too — a second reader that failed at a different byte is the same
    /// defect in a form a boolean would miss.
    #[test]
    fn the_validator_and_the_walk_agree_on_every_vector_and_every_offset() {
        for (bytes, diagnostic, _) in RFC8949_APPENDIX_A {
            assert!(
                walk_cbor(bytes).is_ok(),
                "`{diagnostic}` validates and does not walk"
            );
        }
        for (bytes, what) in NOT_WELL_FORMED {
            match (scan_cbor(bytes), walk_cbor(bytes)) {
                (Err(a), Err(b)) => assert_eq!(
                    a, b,
                    "{what} is refused at two different bytes by the two readers"
                ),
                (a, b) => panic!("{what}: the two readers disagree -- {a:?} vs {b:?}"),
            }
        }
    }

    /// R311y914 (item 434) — A NON-TEXT MAP KEY AND A TEXT KEY THAT SPELLS IT
    /// GET DIFFERENT PATHS.
    ///
    /// # The witness item 434 asked for
    ///
    /// This is the collision the item was registered to prevent, and it is why
    /// the decoder could not simply be written first: `{5: "a", "5": "b"}` is
    /// legal CBOR with two DISTINCT keys, and a naive path scheme gives both
    /// `$.5`. A `--payload-name` declaration matches a path by string equality,
    /// so a collision here renames a field the operator never meant.
    ///
    /// The second half is the sharper one. The escape namespace is only disjoint
    /// if a TEXT key cannot spell it, so the text key `\i5` — which is what an
    /// adversary or an unlucky schema would use — must arrive as something else.
    /// It does: R311y910's rule doubles the backslash.
    #[test]
    fn a_non_text_key_and_the_text_key_that_spells_it_do_not_collide() {
        // {5: "a", "5": "b"}
        let both = &[0xa2, 0x05, 0x61, 0x61, 0x61, 0x35, 0x61, 0x62];
        let walked = walk_cbor(both).expect("a two-pair map");
        let paths: Vec<&str> = walked.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["$", "$.\\i5", "$.5"],
            "the integer key 5 and the text key \"5\" must not share a path"
        );

        // {"\i5": 1} -- the text key that spells the integer form.
        let spelled = &[0xa1, 0x63, 0x5c, 0x69, 0x35, 0x01];
        let fields = walk_cbor(spelled).expect("a one-pair map");
        let seen: Vec<&str> = fields.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            seen,
            vec!["$", "$.\\\\i5"],
            "a text key holding a backslash must double it, or it lands in the \
             namespace reserved for the keys that have no name"
        );
    }

    /// R311y916 (item 443) — A FLOAT KEY MUST NOT SPELL A PATH SEPARATOR.
    ///
    /// # Found by writing item 443's gate, not by reading
    ///
    /// Item 434's namespace works because every reserved form is a `\` followed
    /// by a letter and a rendering that contains no unescaped separator. The
    /// float form did not hold up its half: `format!("{v}")` for `1.5` puts a
    /// `.` INSIDE the segment, so the path `$.\f1.5` parses as two segments and
    /// means two different documents —
    ///
    /// * `{1.5: 1}` — one pair, whose key is a float, and
    /// * `{1.0: {"5": 1}}` — a float key holding a map, since `1.0` renders `1`.
    ///
    /// That is exactly the collision item 434 was registered to prevent,
    /// re-entered through the escape hatch rather than the front door, and it
    /// had been live since R311y914 with a test asserting the broken form. The
    /// fix is the rule that was already there: a rendering going into a segment
    /// gets `.` and `\` escaped, whichever arm builds it.
    #[test]
    fn a_float_key_does_not_spell_a_path_separator() {
        let leaf = |bytes: &[u8]| {
            walk_cbor(bytes)
                .expect("a map")
                .last()
                .expect("a leaf row")
                .path
                .clone()
        };
        // {1.5: 1}
        let flat = leaf(&[0xa1, 0xf9, 0x3e, 0x00, 0x01]);
        // {1.0: {"5": 1}} -- 1.0 renders as `1`, and then the `.` is the separator.
        let nested = leaf(&[0xa1, 0xf9, 0x3c, 0x00, 0xa1, 0x61, 0x35, 0x01]);
        assert_eq!(
            flat, "$.\\f1\\.5",
            "the `.` inside a float's rendering is escaped like any other"
        );
        assert_eq!(nested, "$.\\f1.5", "and here the `.` really is a separator");
        assert_ne!(
            flat, nested,
            "two different documents must not share a path"
        );
    }

    /// R311y916 (item 441) — A MAP WITH A DUPLICATE KEY SAYS SO, at the map.
    ///
    /// # The symptom item 441 registered
    ///
    /// RFC 8949 §5.6 makes a map with two equal keys INVALID, and until this
    /// round nothing here looked. The cost is not abstract: the duplicate
    /// arrives as two rows with the SAME path, and a `--payload-name`
    /// declaration matches a path by string equality, so it renames both. That
    /// is the accident items 431 and 434 were opened to prevent, with the
    /// publisher as the cause rather than the path syntax.
    ///
    /// # Why the count sits on the container's row
    ///
    /// The duplicate pairs are already visible as two identical paths — what
    /// was missing is anything NAMING it. The map's own row is where a reader
    /// looking at those two rows goes next, it is one row rather than one per
    /// duplicate, and it leaves the field rows exactly as they were.
    #[test]
    fn a_map_with_a_duplicate_key_reports_it_on_the_maps_own_row() {
        // {"a": 1, "a": 2}
        let body = &[0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02];
        let fields = walk_cbor(body).expect("a two-pair map");
        assert_eq!(
            fields[0].value, "map 2 pair(s), 1 duplicate key(s)",
            "the map names what §5.6 makes it"
        );
        let paths: Vec<&str> = fields.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["$", "$.a", "$.a"],
            "and the pairs are still both there, at the path they share"
        );
    }

    /// R311y916 (item 441) — TWO ENCODINGS OF ONE KEY ARE ONE KEY.
    ///
    /// The discriminator against the detector a byte comparison would give.
    /// §5.6's equality is over the GENERIC DATA MODEL (§2), not over the
    /// encoding, so `1` written as the immediate form and `1` written as the
    /// one-byte form are the same key — and their heads share no byte. This
    /// walk compares the PATH SEGMENT, which is derived from the value, so it
    /// gets this right for the same reason item 434's namespace works.
    #[test]
    fn one_key_encoded_two_ways_is_still_a_duplicate() {
        // {1: 1, 1: 2} with the second key in the one-byte form.
        let body = &[0xa2, 0x01, 0x01, 0x18, 0x01, 0x02];
        let fields = walk_cbor(body).expect("a two-pair map");
        assert_eq!(fields[0].value, "map 2 pair(s), 1 duplicate key(s)");
    }

    /// R311y916 (item 441) — AND TWO KEYS THAT ONLY LOOK ALIKE ARE TWO KEYS.
    ///
    /// The other half, without which the check would fire on the legal document
    /// item 434 was registered about. A false "invalid" on a well-formed
    /// publisher's traffic is worse than the silence this replaces.
    #[test]
    fn a_map_whose_keys_differ_only_by_type_has_no_duplicate() {
        // {5: "a", "5": "b"} -- an integer key and a text key.
        let body = &[0xa2, 0x05, 0x61, 0x61, 0x61, 0x35, 0x61, 0x62];
        let fields = walk_cbor(body).expect("a two-pair map");
        assert_eq!(
            fields[0].value, "map 2 pair(s)",
            "the integer 5 and the text \"5\" are different keys in §2's data model"
        );
    }

    /// R311y916 (item 441) — WHAT THIS CHECK CANNOT SEE, pinned rather than
    /// left to be discovered.
    ///
    /// A key with no name gets a `\x<offset>` segment, and an offset is unique
    /// by construction — so two IDENTICAL container keys are two different
    /// segments and this check does not count them. That is a real gap in
    /// §5.6 coverage and it is asserted here so a later reader finds it stated
    /// instead of assuming the check is total.
    #[test]
    fn duplicate_container_keys_are_not_counted_and_that_is_pinned() {
        // {[]: 1, []: 2} -- the same key twice, by §2's data model.
        let body = &[0xa2, 0x80, 0x01, 0x80, 0x02];
        let fields = walk_cbor(body).expect("a two-pair map");
        assert_eq!(
            fields[0].value, "map 2 pair(s)",
            "a locator-keyed pair is outside what segment equality can compare"
        );
    }

    /// R311y916 (item 441) — A DUPLICATE IS COUNTED AT ITS OWN MAP.
    ///
    /// The count is per container, so a nested map's problem does not surface
    /// on the outer map's row where a reader would look for the wrong pairs.
    #[test]
    fn a_nested_maps_duplicate_stays_on_the_nested_map() {
        // {"o": {"a": 1, "a": 2}}
        let body = &[0xa1, 0x61, 0x6f, 0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02];
        let fields = walk_cbor(body).expect("a nested map");
        let seen: Vec<(&str, &str)> = fields
            .iter()
            .map(|f| (f.path.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(
            seen,
            vec![
                ("$", "map 1 pair(s)"),
                ("$.o", "map 2 pair(s), 1 duplicate key(s)"),
                ("$.o.a", "unsigned 1"),
                ("$.o.a", "unsigned 2"),
            ],
            "the outer map has one pair and no duplicate; the inner one owns both"
        );
    }

    /// R311y914 (item 434) — EVERY NON-TEXT KEY FORM, one path each.
    ///
    /// The table in the module doc, asserted. `\x` carries the key's byte
    /// OFFSET rather than a rendering, because a container key has no name an
    /// operator could write down — and the offset is what makes two of them
    /// distinct within one document.
    #[test]
    fn each_non_text_key_form_gets_the_segment_the_module_documents() {
        let cases: &[(&[u8], &str, &str)] = &[
            (&[0xa1, 0x05, 0x01], "$.\\i5", "an unsigned key"),
            (&[0xa1, 0x24, 0x01], "$.\\i-5", "a negative key"),
            (
                &[0xa1, 0x42, 0x01, 0xff, 0x01],
                "$.\\b01ff",
                "a byte-string key",
            ),
            (
                &[0xa1, 0xf9, 0x3e, 0x00, 0x01],
                "$.\\f1\\.5",
                "a half-float key, whose own `.` is escaped (item 443)",
            ),
            (&[0xa1, 0xf5, 0x01], "$.\\strue", "a boolean key"),
            (&[0xa1, 0xf6, 0x01], "$.\\snull", "a null key"),
            (&[0xa1, 0xf0, 0x01], "$.\\s16", "an unnamed simple key"),
            (
                &[0xa1, 0x81, 0x01, 0x02],
                "$.\\x1",
                "an array key, which has no name",
            ),
            (
                &[0xa1, 0x5f, 0x41, 0x01, 0xff, 0x02],
                "$.\\x1",
                "an indefinite byte-string key, whose source text is not one run",
            ),
        ];
        for (bytes, want, what) in cases {
            let fields = walk_cbor(bytes).unwrap_or_else(|e| panic!("{what}: {e:?}"));
            let child = fields
                .iter()
                .find(|f| f.path != "$")
                .unwrap_or_else(|| panic!("{what} produced no value row"));
            assert_eq!(child.path, *want, "{what} got the wrong segment");
        }
    }

    /// R311y914 — TWO CONTAINER KEYS IN ONE MAP STAY DISTINCT.
    ///
    /// The `\x<offset>` form is a locator, and a locator that repeated would be
    /// no better than the collision item 434 was registered for. Asserted as a
    /// SET rather than by counting rows, which is this workspace's own rule:
    /// two equal paths and one missing row give the same count.
    #[test]
    fn two_container_keys_in_one_map_do_not_share_a_locator() {
        // {[1]: 1, [2]: 2}
        let body = &[0xa2, 0x81, 0x01, 0x01, 0x81, 0x02, 0x02];
        let fields = walk_cbor(body).expect("a two-pair map");
        let mut locators: Vec<&str> = fields
            .iter()
            .filter(|f| f.path.starts_with("$.\\x"))
            .map(|f| f.path.as_str())
            .collect();
        locators.sort_unstable();
        locators.dedup();
        assert_eq!(
            locators.len(),
            2,
            "two container keys must get two locators, got {:?}",
            fields.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
    }

    /// R311y914 — A DOCUMENT IS WALKED INTO ITS ITEMS, with the path that names
    /// each and the bytes it came from.
    ///
    /// The witness for item 433, in the shape the JSON walk's own witness has:
    /// containers stand above their children so the listing reads top-down, and
    /// a span is the item's own bytes rather than an approximation.
    #[test]
    fn a_cbor_document_is_walked_into_its_items_with_paths_and_spans() {
        // {"a": 1, "b": [true, null]}
        //  0  1 2  3  4 5  6  7  8
        let body = &[0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x82, 0xf5, 0xf6];
        let fields = walk_cbor(body).expect("a CBOR map");
        let seen: Vec<(&str, &str, usize, usize)> = fields
            .iter()
            .map(|f| (f.path.as_str(), f.value.as_str(), f.start, f.end))
            .collect();
        assert_eq!(
            seen,
            vec![
                ("$", "map 2 pair(s)", 0, 9),
                ("$.a", "unsigned 1", 3, 4),
                ("$.b", "array 2 element(s)", 6, 9),
                ("$.b.0", "bool true", 7, 8),
                ("$.b.1", "null", 8, 9),
            ],
            "every item gets a row, rooted at `$`, containers above their \
             children"
        );
        // A key gets no row of its own -- it IS the last segment of the path,
        // which is the rule the JSON walk follows for the same reason.
        assert!(
            !fields.iter().any(|f| f.start == 1),
            "the key at byte 1 must not have a row: {fields:?}"
        );
    }

    /// R311y914 — AN INDEFINITE-LENGTH CONTAINER SAYS SO, and its element count
    /// is what was actually walked.
    ///
    /// Both halves matter to a reader: the count is the content and the
    /// indefinite marker is the ENCODING, and two captures that differ only in
    /// the marker are a real difference between two publishers.
    #[test]
    fn an_indefinite_container_reports_its_form_and_its_real_count() {
        // [_ 1, 2]
        let body = &[0x9f, 0x01, 0x02, 0xff];
        let fields = walk_cbor(body).expect("an indefinite array");
        assert_eq!(fields[0].value, "array 2 element(s), indefinite");
        assert_eq!((fields[0].start, fields[0].end), (0, 4));
        // (_ "strea", "ming") -- the chunks are the encoding and the length is
        // the content. The row must not claim to hold the text: the chunks are
        // not one contiguous run, which is exactly why such a KEY is `\x`.
        let chunked = &[
            0x7f, 0x65, 0x73, 0x74, 0x72, 0x65, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x67, 0xff,
        ];
        let fields = walk_cbor(chunked).expect("an indefinite text string");
        assert_eq!(fields[0].value, "text 9 byte(s), indefinite");
    }

    /// R311y914 — A TAG IS REPORTED AND ITS CONTENT IS WALKED, not interpreted.
    ///
    /// Tag 0 is a date-time string and tag 1 an epoch number; this walk says
    /// which tag and then walks the item, and the test pins that it does NOT
    /// render either as a date. A decoder that invented the interpretation would
    /// be the failure the protobuf built-in's absent field names avoid.
    #[test]
    fn a_tag_is_named_and_its_item_walked_under_its_own_segment() {
        // 1(1363896240)
        let body = &[0xc1, 0x1a, 0x51, 0x4b, 0x67, 0xb0];
        let fields = walk_cbor(body).expect("a tagged item");
        let seen: Vec<(&str, &str)> = fields
            .iter()
            .map(|f| (f.path.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(
            seen,
            vec![("$", "tag 1"), ("$.\\t", "unsigned 1363896240")],
            "the tag is a row and its content is a child, uninterpreted"
        );
    }

    /// R311y916 (item 442) — TAG 24'S BYTE STRING IS A DOCUMENT, AND IT IS
    /// WALKED.
    ///
    /// # Why this one tag and not the rest
    ///
    /// RFC 8949 §3.4.5.1 says the tag 24 content is "a byte string containing
    /// an encoded CBOR data item". That is a structural statement, not a
    /// semantic one, so re-entering it invents nothing — the same argument that
    /// made item 433 open CBOR at all. A bignum is the other kind: rendering
    /// tag 2's bytes as a number is an INTERPRETATION, and the module doc's
    /// refusal there still stands.
    ///
    /// # The witness
    ///
    /// `24(h'6449455446')` is RFC 8949 Appendix A's own tag 24 vector, and the
    /// bytes it wraps are Appendix A's `"IETF"` vector. So the assertion below
    /// is that walking the inner bytes gives what the RFC says the inner bytes
    /// are — a witness this decoder did not write.
    #[test]
    fn tag_24s_embedded_document_is_walked_rather_than_counted() {
        // 24(h'6449455446')
        let body = &[0xd8, 0x18, 0x45, 0x64, 0x49, 0x45, 0x54, 0x46];
        let fields = walk_cbor(body).expect("a tag 24 item");
        let seen: Vec<(&str, &str)> = fields
            .iter()
            .map(|f| (f.path.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(
            seen,
            vec![
                ("$", "tag 24"),
                ("$.\\t", "bytes 5 byte(s)"),
                ("$.\\t.\\e", "text \"IETF\""),
            ],
            "the embedded document is a child of the byte string that carries it"
        );
        let inner = fields.last().expect("the embedded row");
        assert_eq!(
            (inner.start, inner.end),
            (3, 8),
            "the embedded rows carry OUTER offsets, so a reader can find them in the capture"
        );
    }

    /// R311y916 (item 442) — BYTES THAT ARE NOT A DOCUMENT ARE A FINDING ABOUT
    /// THE CONTENT, NOT A MALFORMED OUTER DOCUMENT.
    ///
    /// The decision item 442 asked for. The outer encoding is well-formed
    /// whatever the byte string holds — §3.4.5.1's requirement is a VALIDITY
    /// rule about the content, and this crate's line between the two is
    /// R311y914's. So the walk reports the outer document as good, says at its
    /// own path why the inner one was not walked, and emits no partial rows for
    /// it. The precedent is the protobuf walk's `text_like` fallback: a
    /// sub-decode that fails describes what it found rather than condemning
    /// what carried it.
    #[test]
    fn a_tag_24_whose_bytes_are_not_a_document_leaves_the_outer_walk_good() {
        // 24(h'ff') — a break byte, which is not a document at all.
        let body = &[0xd8, 0x18, 0x41, 0xff];
        assert!(
            scan_cbor(body).is_ok(),
            "the outer document's encoding is well-formed whatever the bytes hold"
        );
        let fields = walk_cbor(body).expect("a tag 24 item");
        let seen: Vec<(&str, &str)> = fields
            .iter()
            .map(|f| (f.path.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(
            seen,
            vec![
                ("$", "tag 24"),
                ("$.\\t", "bytes 1 byte(s)"),
                (
                    "$.\\t.\\e",
                    "not an embedded document: a break outside an indefinite-length item at byte 3"
                ),
            ],
            "the failure is named at the position it happened, with no partial rows"
        );
    }

    /// R311y916 (item 442) — TRAILING BYTES INSIDE THE BYTE STRING ARE NOT A
    /// DOCUMENT EITHER.
    ///
    /// §3.4.5.1 says "an encoded CBOR data item", singular, and the outer walk
    /// already refuses a second top-level item for the same reason (`scan`).
    /// Asserted separately because a walk that stopped at the first item would
    /// pass the test above and silently drop the rest of the byte string.
    #[test]
    fn a_tag_24_holding_two_items_is_not_an_embedded_document() {
        // 24(h'0101') — two unsigned items in the byte string.
        let body = &[0xd8, 0x18, 0x42, 0x01, 0x01];
        let fields = walk_cbor(body).expect("a tag 24 item");
        let last = fields.last().expect("the embedded row");
        assert_eq!(
            last.value,
            "not an embedded document: trailing input after the one top-level data item at byte 4",
            "a second item inside the byte string is refused where the outer walk refuses one"
        );
    }

    /// R311y916 (item 442) — AND THE INDEFINITE FORM IS NOT RE-ENTERED, on
    /// purpose.
    ///
    /// An indefinite-length byte string's content is the CONCATENATION of its
    /// chunks, so the document only exists in a buffer this walk would have to
    /// build — and every offset in it would then be an offset into that buffer
    /// rather than into the capture. The rows this crate emits are findable
    /// byte spans; a row whose span means something else is worse than an
    /// absent row. `\b` draws this line for map keys already.
    #[test]
    fn an_indefinite_byte_string_under_tag_24_is_left_as_bytes() {
        // 24(_ h'64', h'49455446') — the same "IETF" document, chunked.
        let body = &[
            0xd8, 0x18, 0x5f, 0x41, 0x64, 0x44, 0x49, 0x45, 0x54, 0x46, 0xff,
        ];
        let fields = walk_cbor(body).expect("a tag 24 item");
        let seen: Vec<&str> = fields.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            seen,
            vec!["$", "$.\\t"],
            "no embedded row: the content is not a contiguous slice of the capture"
        );
    }

    /// R311y916 (item 442) — THE EMBEDDED WALK IS INSIDE THE DEPTH BOUND, so a
    /// document that nests through tag 24 cannot outrun it.
    ///
    /// The bound is a guard over attacker-influenced bytes, and a sub-walk that
    /// started its own count would hand an attacker `MAX_CBOR_DEPTH` levels per
    /// wrapper for the price of three bytes. Built by wrapping a document that
    /// is already at the bound, so the failure is the recursion and not the
    /// arithmetic.
    #[test]
    fn tag_24_nesting_cannot_outrun_the_depth_bound() {
        let mut inner: Vec<u8> = core::iter::repeat_n(0x81u8, MAX_CBOR_DEPTH)
            .chain(core::iter::once(0x00))
            .collect();
        assert!(
            scan_cbor(&inner).is_ok(),
            "the inner document is at the bound"
        );
        let len = u8::try_from(inner.len()).expect("a short fixture");
        let mut body: Vec<u8> = vec![0xd8, 0x18, 0x58, len];
        body.append(&mut inner);
        let fields = walk_cbor(&body).expect("the outer document is still well-formed");
        let last = fields.last().expect("the embedded row");
        assert!(
            last.value
                .starts_with("not an embedded document: nested deeper than this reader walks"),
            "the bound is shared with the outer walk, not restarted: {}",
            last.value
        );
    }

    /// R311y914 — THE HALF-FLOAT CONVERSION IS THE RFC'S, including the two arms
    /// a bit-pattern version gets wrong.
    ///
    /// Appendix A's float vectors are the witness. The subnormal (`0xf90001`)
    /// and the smallest normal (`0xf90400`) are the arms that fail when the
    /// implicit bit is mishandled, and they are the reason this is asserted on
    /// VALUES rather than on the rendered row: `format!` would hide a small
    /// error in a long decimal.
    #[test]
    fn the_half_float_conversion_matches_the_rfcs_own_values() {
        assert_eq!(f16_to_f64(0x0000), 0.0);
        assert!(f16_to_f64(0x8000).is_sign_negative());
        assert_eq!(f16_to_f64(0x8000), 0.0);
        assert_eq!(f16_to_f64(0x3c00), 1.0);
        assert_eq!(f16_to_f64(0x3e00), 1.5);
        assert_eq!(f16_to_f64(0x7bff), 65504.0);
        assert_eq!(f16_to_f64(0xc400), -4.0);
        assert_eq!(f16_to_f64(0x0001), 5.960_464_477_539_063e-8);
        assert_eq!(f16_to_f64(0x0400), 0.000_061_035_156_25);
        assert!(f16_to_f64(0x7c00).is_infinite() && f16_to_f64(0x7c00).is_sign_positive());
        assert!(f16_to_f64(0xfc00).is_infinite() && f16_to_f64(0xfc00).is_sign_negative());
        assert!(f16_to_f64(0x7e00).is_nan());
    }

    /// R311y914 — A DOCUMENT NESTED PAST THE BOUND IS REPORTED, not a stack
    /// overflow.
    ///
    /// The payload is attacker-influenced bytes, so the bound is the same kind
    /// of guard the JSON scanner and the protobuf walk carry. Asserted with a
    /// document AT the bound as well as one past it, because a bound that
    /// refuses the legal depth is the other way to get this wrong.
    #[test]
    fn nesting_past_the_bound_is_reported_and_the_bound_itself_is_walked() {
        let at_bound: Vec<u8> = core::iter::repeat_n(0x81u8, MAX_CBOR_DEPTH)
            .chain(core::iter::once(0x00))
            .collect();
        assert!(
            scan_cbor(&at_bound).is_ok(),
            "a document at the bound must still walk"
        );
        let past: Vec<u8> = core::iter::repeat_n(0x81u8, MAX_CBOR_DEPTH + 1)
            .chain(core::iter::once(0x00))
            .collect();
        let (_, why) = scan_cbor(&past).expect_err("past the bound must be refused");
        assert_eq!(why, "nested deeper than this reader walks");
    }
}
