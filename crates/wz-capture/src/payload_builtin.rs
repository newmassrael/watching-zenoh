// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y856 — the payload format decoders this workspace SHIPS, beside the map
//! that selects them.
//!
//! ## Why they are here and not in the command line
//!
//! R311y699 put them in `wz-analyze`, the composition root, on the rule that
//! this crate has zero third-party dependencies because its decode path builds
//! for the MCU profiles and "a format decoder is exactly the kind of thing that
//! grows one". The rule is right; it did not describe the decoder it excluded.
//! [`Protobuf`] is a hand-written walk over base-128 varints and takes no
//! dependency at all.
//!
//! What the misplacement cost was MEASURED by `analysis_surface_parity.py`: the
//! C ABI — the surface a product LINKS — could not decode a payload, because
//! the registry it would have to name lived in a binary it must not depend on
//! (`wz-analyze` pulls `wz-tls-record`, and through it `ring`). The seam it was
//! told to reach, [`crate::payload::formats::FormatMap`], was public with
//! nothing on that side able to build one. Moving the decoder beside the map is
//! what R311y851 did for the census emit, for the same reason: one
//! implementation beside the type, and neither consumer owning it.
//!
//! ## Private module, public through `formats`
//!
//! Nothing outside names `crate::payload_builtin`; the items are re-exported by
//! [`crate::payload::formats`], where the trait and the map are. A caller reads
//! one module and the file boundary stays an authoring convenience rather than
//! a second place to look.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::payload::formats::{PayloadField, PayloadFormat, PayloadFormatError};

/// The protobuf WIRE FORMAT, walked without a schema.
///
/// # Why this one is the built-in, and what it can honestly claim
///
/// nanopb emits protobuf's wire format, and that format is
/// self-describing enough to walk with no `.proto` at all: every field
/// carries its number and one of four wire types, and each wire type
/// determines its own length. So a reader gets field numbers, wire types,
/// values and BYTE SPANS — the structure — without anyone shipping a
/// schema.
///
/// What it cannot give is NAMES: field 3 is field 3, not `temperature`.
/// Said plainly rather than papered over, because a decoder that invented
/// names would be the worst kind of wrong on a plane whose whole output is
/// findings.
///
/// # Why not an `e2e` built-in beside it
///
/// An AUTOSAR E2E profile is a CRC, a counter and a data id at offsets the
/// PROFILE fixes, and this machine's sources carry neither the profile
/// table nor the CRC polynomial — a grep for `0x1021` / `crc16` across
/// every crate returns nothing. This workspace's own rule (R311y695) is
/// that a constant a module cannot check is one it must not carry, so `e2e`
/// is a format a deployment supplies through the seam rather than one
/// invented here from memory.
pub struct Protobuf;

/// The four wire types of protobuf, and what each one's length is.
fn wire_type_name(ty: u64) -> Option<&'static str> {
    match ty {
        0 => Some("varint"),
        1 => Some("i64"),
        2 => Some("len"),
        5 => Some("i32"),
        _ => None,
    }
}

/// One base-128 varint, advancing `at`.
fn varint(bytes: &[u8], at: &mut usize) -> Result<u64, PayloadFormatError> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let start = *at;
    loop {
        let byte = *bytes.get(*at).ok_or(PayloadFormatError::Truncated(start))?;
        *at += 1;
        // Ten groups of seven bits is 70, so the tenth byte may only carry
        // the one bit left of a u64. A longer run is malformed rather than
        // silently truncated -- the shift would panic in debug and wrap the
        // value in release, which is the pair of behaviours a decoder over
        // adversarial bytes must not have.
        if shift >= 64 {
            return Err(PayloadFormatError::Malformed {
                at: start,
                why: String::from("a varint longer than ten bytes"),
            });
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

/// R311y701 (PF3) — how deep a nested walk goes before it stops walking.
///
/// A payload is attacker-influenced bytes and a length-delimited field can
/// name another one forever, so the recursion is bounded like every other
/// walk in this workspace. Eight is past any hand-written schema this
/// analyzer is pointed at, and what sits below it is not silently dropped —
/// the field says the nesting went further than this reader walks.
const MAX_NESTING: usize = 8;

/// Is this run of bytes TEXT rather than a nested message?
///
/// # Why the question is asked this way, and what it cannot settle
///
/// Protobuf's wire format does not distinguish a string, a nested message
/// and a blob: all three are wire type 2, and the ambiguity is IN THE
/// FORMAT rather than in this reader. So there is no rule that is right
/// every time and the choice is which mistake to make.
///
/// Valid UTF-8 with no control characters is a strong signal for a string
/// and a weak one for a message: a nested message begins with a tag byte,
/// and the overwhelming majority of tags (any field with a varint under a
/// small number, any 64-bit or 32-bit field) put a control byte or a
/// non-UTF-8 byte in the first two positions. "Parses as protobuf" is by
/// contrast very permissive — two bytes like `"Px"` parse cleanly as field
/// 10 varint 120 — so trying the parse first would rename short strings as
/// messages far more often than this rule hides a message.
fn text_like(raw: &[u8]) -> Option<&str> {
    let text = core::str::from_utf8(raw).ok()?;
    if text.is_empty() {
        return None;
    }
    text.chars()
        .all(|c| !c.is_control() || c == '\n' || c == '\t' || c == '\r')
        .then_some(text)
}

/// Walk `payload`, whose first byte sits at `base` in the message this
/// decoding will be rendered against, appending to `out` under `prefix`.
///
/// R311y701 — `base` and `prefix` are what make the recursion honest. A
/// nested field's span must be in the SAME coordinate space as its parent's
/// or a reader cannot line the two up, and its path must name the route to
/// it (`2.1`) rather than restart at `1` — a listing with two fields called
/// `1` says nothing about where either lives.
fn walk(
    payload: &[u8],
    base: usize,
    depth: usize,
    prefix: &str,
    out: &mut Vec<PayloadField>,
) -> Result<(), PayloadFormatError> {
    let mut at = 0usize;
    while at < payload.len() {
        let start = at;
        let tag = varint(payload, &mut at).map_err(|e| rebase(e, base))?;
        let number = tag >> 3;
        let wire = tag & 0x07;
        let Some(kind) = wire_type_name(wire) else {
            // Wire types 3 and 4 are the deprecated group markers and 6
            // and 7 are unassigned. A reader that stepped over one
            // would not know where it ends, so this stops -- the same
            // rule the QUIC frame walk follows for an unknown type.
            return Err(PayloadFormatError::Malformed {
                at: base + start,
                why: format!("wire type {wire} has no length rule"),
            });
        };
        if number == 0 {
            // Field number zero is invalid in every protobuf version,
            // and it is what a run of zero bytes decodes to -- which is
            // the single most likely thing to be under a WRONG mapping.
            return Err(PayloadFormatError::NotThisFormat);
        }
        let path = if prefix.is_empty() {
            format!("{number}")
        } else {
            format!("{prefix}.{number}")
        };
        // The children of a nested field are collected into their own
        // vector so the PARENT row can be pushed before them: a listing
        // reads top-down, and a walk that pushed as it went would put
        // `2.1` above `2`.
        let mut children = Vec::new();
        let value = match wire {
            0 => {
                let v = varint(payload, &mut at).map_err(|e| rebase(e, base))?;
                format!("{v}")
            }
            1 | 5 => {
                let width = if wire == 1 { 8 } else { 4 };
                let end = at
                    .checked_add(width)
                    .ok_or(PayloadFormatError::Truncated(base + at))?;
                let raw = payload
                    .get(at..end)
                    .ok_or(PayloadFormatError::Truncated(base + at))?;
                at = end;
                format!(
                    "0x{}",
                    raw.iter()
                        .rev()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                )
            }
            _ => {
                let len = varint(payload, &mut at).map_err(|e| rebase(e, base))? as usize;
                let body = at;
                let end = at
                    .checked_add(len)
                    .ok_or(PayloadFormatError::Truncated(base + at))?;
                let raw = payload
                    .get(at..end)
                    .ok_or(PayloadFormatError::Truncated(base + at))?;
                at = end;
                // Rendered as text when it IS text, because a
                // length-delimited field is a string as often as it is
                // a nested message and a reader should not have to
                // decode hex to find out.
                match text_like(raw) {
                    Some(text) => format!("{text:?}"),
                    // R311y701 (PF3) — otherwise it may be a NESTED
                    // MESSAGE, which nesting is common enough in real
                    // schemas that stopping here showed a reader one
                    // layer of their own data.
                    None if depth >= MAX_NESTING => {
                        format!("{len} byte(s), nested deeper than this reader walks")
                    }
                    None => {
                        // A TRY, and a failure falls back rather than
                        // rejecting the message: these bytes may simply be
                        // a blob, and a blob is not a malformed message.
                        // The whole sub-buffer must be consumed and yield
                        // at least one field, or "it parsed" would be a
                        // statement about a prefix.
                        match walk(raw, base + body, depth + 1, &path, &mut children) {
                            Ok(()) if !children.is_empty() => {
                                format!("{} field(s)", children.len())
                            }
                            _ => {
                                children.clear();
                                format!("{len} byte(s)")
                            }
                        }
                    }
                }
            }
        };
        out.push(PayloadField {
            path,
            // R311y720 (PF4) — ALWAYS `None` here, and it is a statement
            // rather than a placeholder: protobuf's wire format carries no
            // names, so this decoder has none to give. The declaration
            // fills it in, in `decode_payload`.
            name: None,
            value: format!("{kind} {value}"),
            start: base + start,
            end: base + at,
        });
        out.append(&mut children);
    }
    Ok(())
}

/// Move an error's offset into the outer payload's coordinates.
fn rebase(err: PayloadFormatError, base: usize) -> PayloadFormatError {
    match err {
        PayloadFormatError::Truncated(at) => PayloadFormatError::Truncated(base + at),
        other => other,
    }
}

impl PayloadFormat for Protobuf {
    fn name(&self) -> &str {
        "protobuf"
    }

    /// R311y873 — the ONE table name protobuf bytes are declared under.
    ///
    /// Not `application/octet-stream` beside it, and the omission is the
    /// decision rather than an oversight. A publisher that said
    /// `octet-stream` said "these are bytes and I am claiming nothing more",
    /// which is a claim this rule does not contradict; folding it in here
    /// would make the list mean "encodings a protobuf body might wear" instead
    /// of "encodings that AGREE with this rule", and every entry that means
    /// nothing weakens the ones that mean something.
    ///
    /// The silent default is not listed either, and must not be: `zenoh/bytes`
    /// is what a publisher that set no encoding gets — the nanopb deployment
    /// this decoder exists for — and it is admitted by
    /// `payload_decode::decode_payload` as an ABSENCE of a claim
    /// rather than as a member of this set. Listing it here would say the
    /// publisher claimed protobuf when it claimed nothing.
    fn encodings(&self) -> Option<&[&str]> {
        Some(&["application/protobuf"])
    }

    fn decode(&self, payload: &[u8]) -> Result<Vec<PayloadField>, PayloadFormatError> {
        if payload.is_empty() {
            // An empty payload is not a protobuf message this reader can
            // vouch for; it is also not malformed. Saying NotThisFormat
            // sends the reader to their mapping, which is where an empty
            // payload under a protobuf rule usually comes from.
            return Err(PayloadFormatError::NotThisFormat);
        }
        let mut out = Vec::new();
        walk(payload, 0, 0, "", &mut out)?;
        Ok(out)
    }
}

/// R311y909 — JSON, walked into its own fields.
///
/// # The silence this ends
///
/// [`crate::payload`]'s opening sentence is that "a capture of a fleet
/// publishing JSON was, to this tool, a capture of some bytes", and the plane
/// it introduced closed half of that: a payload declaring `application/json`
/// gets a VERDICT — the bytes parsed, or they did not and here is where. The
/// other half stayed open for the whole of that track. The reader was told the
/// document is well-formed and was then handed its length, because the FIELD
/// layer had exactly one decoder and it was protobuf.
///
/// That gap had a sharp edge, and the trait beside this one names it:
/// [`PayloadFormat::encodings`] exists because a `demo/**=protobuf` rule
/// "walked a JSON body with a varint reader". Every mechanism for that
/// collision — the encodings set, the claim adjudication, the misbinding tally
/// — was built while the format on one side of it did not exist, so a reader
/// whose fleet publishes JSON could only ever be told which rule NOT to apply.
///
/// # One grammar, not two
///
/// The walk is `crate::payload::walk_json` (a code span and not a link, on this
/// crate's own rule: that item is crate-private, and a link to it from a public
/// doc is what Layer C1bz counts), which is the SAME scanner
/// [`crate::payload::inspect`] validates with, running with an emitter
/// attached. A decoder with its own reading of RFC 8259 would let this crate
/// hold two opinions about what JSON is, and the plane above would then be able
/// to call a document well-formed that the plane below refused.
///
/// # What it gives, and what it cannot
///
/// Field paths, kinds, values and byte spans, for every value in the document.
/// Unlike protobuf it also gives NAMES, because JSON carries them — but they
/// arrive in the PATH rather than in
/// [`crate::payload::formats::PayloadField::name`], which is reserved for a
/// deployment's own declaration. See `crate::payload::walk_json` for why, and
/// for the one path ambiguity this leaves.
pub struct Json;

impl PayloadFormat for Json {
    fn name(&self) -> &str {
        "json"
    }

    /// The table names whose declared SHAPE is JSON, and no others.
    ///
    /// Kept honest by `the_json_builtin_claims_exactly_the_tables_json_shapes`
    /// below rather than by this list being read carefully: the set is derived
    /// from `crate::payload::shape_of`, which is where `application/json5`,
    /// `application/json-seq` and `application/jsonpath` are already decided
    /// NOT to be JSON — json5 admits comments and trailing commas a strict
    /// scanner rejects, a json-seq body is several documents with a separator,
    /// and a jsonpath body is a query rather than a document. Restating that
    /// judgement here would be a second place for it to drift.
    fn encodings(&self) -> Option<&[&str]> {
        Some(&["application/json", "text/json"])
    }

    fn decode(&self, payload: &[u8]) -> Result<Vec<PayloadField>, PayloadFormatError> {
        if payload.is_empty() {
            // Same answer `Protobuf` gives, for the same reason: an empty
            // payload is not a JSON document and is also not malformed, and
            // `NotThisFormat` sends the reader to their mapping.
            return Err(PayloadFormatError::NotThisFormat);
        }
        crate::payload::walk_json(payload).map_err(|(at, why)| {
            // The scanner's own two failures map onto two of the three
            // answers, and WHICH one is the reader's next move. A document
            // that ran out is a capture question; one that broke at a byte
            // that is inside it is a sender question. `NotThisFormat` is not
            // reachable from here on purpose: bytes that are not JSON at all
            // fail at offset 0, which is a malformed document rather than a
            // mapping mistake -- and the mapping question is already answered
            // one level up, by the encodings set above.
            if at >= payload.len() {
                PayloadFormatError::Truncated(at)
            } else {
                PayloadFormatError::Malformed {
                    at,
                    why: String::from(why),
                }
            }
        })
    }
}

/// R311y914 (open-debt items 433, 434) — CBOR, walked into its own fields.
///
/// # The silence this ends
///
/// `application/cbor` was in the position `application/json` held before
/// R311y909 and one step worse. `crate::payload::shape_of` answered
/// [`crate::payload::Shape::Binary`] for it, `Binary` makes
/// [`crate::payload::inspect`] answer `Opaque`, and `Opaque` agrees with every
/// claim — so `payload_decode::judge_claim` could not refute an
/// `application/cbor` label, and an unrefuted label VETOES the operator's rule.
/// The symptom was therefore not "a cbor body is shown as a byte count" but "no
/// rule can be applied to a cbor topic", which is strictly worse than having no
/// decoder at all.
///
/// # One grammar, not two
///
/// The walk is `crate::payload_cbor::walk_cbor` (a code span and not a link, on
/// this crate's own rule: that item is crate-private, and a link to it from a
/// public doc is what Layer C1bz counts), the SAME scanner
/// [`crate::payload::inspect`] validates with. A decoder with its own reading of
/// RFC 8949 would let this crate call a payload well-formed that the plane below
/// refused.
///
/// # What it gives, and what it cannot
///
/// Kinds, values, byte spans and paths for every data item. Names arrive in the
/// PATH, as JSON's do and for the same reason. What it does not do is interpret
/// a TAG: the number is reported and the item under it is walked, but a bignum
/// is not turned into a number and tag 24's embedded document is not re-entered.
/// That is the rule this crate already applies to protobuf's absent field names
/// — a decoder that invented the answer would be the worst kind of wrong on a
/// plane whose whole output is findings.
pub struct Cbor;

impl PayloadFormat for Cbor {
    fn name(&self) -> &str {
        "cbor"
    }

    /// The one table name whose declared shape is CBOR.
    ///
    /// Kept honest by `the_cbor_builtin_claims_exactly_the_tables_cbor_shapes`
    /// below rather than by this list being read carefully — the same guard the
    /// JSON built-in has, against the same drift.
    fn encodings(&self) -> Option<&[&str]> {
        Some(&["application/cbor"])
    }

    fn decode(&self, payload: &[u8]) -> Result<Vec<PayloadField>, PayloadFormatError> {
        if payload.is_empty() {
            // The answer `Json` and `Protobuf` both give: an empty payload is
            // not a document and is also not malformed, and `NotThisFormat`
            // sends the reader to their mapping.
            return Err(PayloadFormatError::NotThisFormat);
        }
        crate::payload_cbor::walk_cbor(payload).map_err(|(at, why)| {
            // The same two-of-three split the JSON built-in makes, and for the
            // same reason: a document that ran out is a capture question, one
            // that broke at a byte inside it is a sender question.
            // `NotThisFormat` is unreachable from here on purpose — bytes that
            // are not CBOR at all fail at an offset inside them, and the mapping
            // question is answered one level up by the encodings set.
            if at >= payload.len() {
                PayloadFormatError::Truncated(at)
            } else {
                PayloadFormatError::Malformed {
                    at,
                    why: String::from(why),
                }
            }
        })
    }
}

/// The format a name selects, or `None` for a name this build has no
/// decoder for.
///
/// A refusal rather than a fallback: a reader who typed `--payload-format
/// 'demo/**=protobufff'` and got the bytes rendered as hex would think
/// their rule was live.
pub fn builtin(name: &str) -> Option<&'static dyn PayloadFormat> {
    match name {
        "cbor" => Some(&Cbor),
        "json" => Some(&Json),
        "protobuf" => Some(&Protobuf),
        _ => None,
    }
}

/// Every built-in name, for the usage text and for a refusal that can say
/// what IS available.
pub const BUILTIN_NAMES: &[&str] = &["cbor", "json", "protobuf"];

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// R311y873 — EVERY BUILT-IN NAMES ITS ENCODINGS, and every name it gives
    /// is one the wire table answers to.
    ///
    /// # Why this is a gate and not a review note
    ///
    /// [`PayloadFormat::encodings`] defaults to `None` so a consumer's
    /// proprietary format keeps compiling across a version bump. That default
    /// is an opt-out from the contradiction check, and a built-in added here
    /// later takes it by SAYING NOTHING — the check would be off for that
    /// format and every test of it would still pass, because what it guards
    /// against is traffic no fixture has. This crate's own rule for that shape
    /// is R311y860's: a member in no class must fall out of a total something
    /// asserts, rather than be caught by whoever reads the diff.
    ///
    /// The second half is the sharper one. A name is matched against
    /// `ENCODING_ID_TO_STR` by string equality, so `application/protobuff`
    /// would be in no table entry, agree with no sample, and quietly refuse
    /// every payload the rule covers — a total silencing that reads exactly
    /// like "no traffic matched".
    #[test]
    fn every_builtin_names_encodings_the_wire_table_answers_to() {
        use wz_codecs::encoding_ids::ENCODING_ID_TO_STR;
        assert!(!BUILTIN_NAMES.is_empty(), "a gate over nothing is green");
        for name in BUILTIN_NAMES {
            let format = builtin(name).expect("a listed built-in resolves");
            let encodings = format
                .encodings()
                .unwrap_or_else(|| panic!("built-in `{name}` names no encoding"));
            assert!(
                !encodings.is_empty(),
                "built-in `{name}` names an EMPTY encoding set, which agrees \
                 with nothing and silences the rule"
            );
            for declared in encodings {
                assert!(
                    ENCODING_ID_TO_STR.contains(declared),
                    "built-in `{name}` names `{declared}`, which is in no \
                     entry of the wire encoding table"
                );
            }
        }
    }

    /// R311y909 — EVERY LISTED NAME RESOLVES TO THE FORMAT THAT WEARS IT.
    ///
    /// [`BUILTIN_NAMES`] is what the usage text and every refusal read, and
    /// [`builtin`] is what a rule actually binds. They are two hand-written
    /// lists of the same fact, so a name added to one and not the other is the
    /// ordinary way this drifts: listed-but-unresolvable makes the usage text
    /// offer a format `--payload-format` then refuses, and resolvable-but-
    /// unlisted makes a working format invisible to the reader who would use
    /// it. The third assertion is the one a `match` arm typo needs: a name that
    /// resolves to the WRONG decoder passes both of the others.
    #[test]
    fn every_listed_builtin_resolves_to_the_format_that_wears_its_name() {
        for name in BUILTIN_NAMES {
            let format = builtin(name).unwrap_or_else(|| {
                panic!("`{name}` is listed as a built-in and resolves to nothing")
            });
            assert_eq!(
                format.name(),
                *name,
                "`{name}` resolves to a decoder that calls itself \
                 `{}` -- one of the two spellings is wrong",
                format.name()
            );
        }
        // And the list is a SET, because a duplicate would render twice in the
        // usage text and read as two formats.
        let mut sorted: Vec<&str> = BUILTIN_NAMES.to_vec();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(
            before,
            sorted.len(),
            "a name is listed twice: {BUILTIN_NAMES:?}"
        );
    }

    /// R311y916 (item 443) — the letters a path segment may begin with after a
    /// `\`, declared in one place.
    ///
    /// `i` integer, `b` byte string, `f` float, `s` simple value, `x` locator,
    /// `t` a tag's content, `e` the document inside a tag 24. Every one of them
    /// is `crate::payload_cbor`'s today, and the constant lives HERE rather
    /// than there because the namespace belongs to the PATH SYNTAX, which every
    /// built-in shares — a fourth format that wanted a reserved segment would
    /// come to this list, and the gate below is what makes it have to.
    /// R311y925 (item 448) — WALKED out of the shipping enum, not transcribed.
    ///
    /// It used to be the literal list `['b', 'e', 'f', 'i', 's', 't', 'x']`,
    /// and item 448's measurement is why it is not one any more: nothing
    /// shipping was bound to it, so an eighth form added to the walker touched
    /// no list, was never observed by the corpus, and passed a green suite. A
    /// probe confirmed that before this changed -- 19 tests passed with a new
    /// reserved letter live in the code.
    ///
    /// Derived, the two directions swap roles usefully. A new form is declared
    /// the moment it can be written, and the assertion below then FAILS until
    /// `PATH_CORPUS` carries a payload that produces it, which is the direction
    /// that was silent.
    fn reserved_path_letters() -> Vec<char> {
        crate::payload_cbor::Reserved::letters()
    }

    /// R311y916 (item 443) — payloads that MAKE each built-in emit its paths.
    ///
    /// The population is [`BUILTIN_NAMES`] and the gate refuses a name with no
    /// entry here, which is the half that matters: a fourth format added later
    /// cannot join by saying nothing, and this workspace has paid for the
    /// "a lane nobody runs" shape often enough to write it down.
    const PATH_CORPUS: &[(&str, &[u8], &str)] = &[
        (
            "cbor",
            &[
                0xa5, 0x05, 0x01, 0x42, 0x01, 0xff, 0x02, 0xf9, 0x3e, 0x00, 0x03, 0xf5, 0x04, 0x80,
                0x05,
            ],
            "{5: 1, h'01ff': 2, 1.5: 3, true: 4, []: 5} -- the key forms",
        ),
        (
            "cbor",
            &[0xd8, 0x18, 0x45, 0x64, 0x49, 0x45, 0x54, 0x46],
            "24(h'6449455446') -- a tag and the document inside it",
        ),
        (
            "cbor",
            &[0xa2, 0x61, 0x2e, 0x01, 0x61, 0x5c, 0x02],
            "{\".\": 1, \"\\\\\": 2} -- text keys that are ONLY the escape characters",
        ),
        (
            "json",
            br#"{"a.b":1,"\\":2,"c":[3]}"#,
            "keys carrying a separator and an escape, and an array index",
        ),
        (
            "protobuf",
            &[0x12, 0x02, 0x08, 0x07],
            "a length-delimited field holding a message -- the `2.1` form",
        ),
    ];

    /// Split a path on the separators that are SEPARATORS, honouring the one
    /// escape rule this crate has.
    fn path_segments(path: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut chars = path.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    cur.push(c);
                    if let Some(next) = chars.next() {
                        cur.push(next);
                    }
                }
                '.' => out.push(core::mem::take(&mut cur)),
                _ => cur.push(c),
            }
        }
        out.push(cur);
        out
    }

    /// R311y916 (item 443) — EVERY BUILT-IN'S PATH SEGMENTS STAY INSIDE THE
    /// RESERVED NAMESPACE, run rather than reasoned.
    ///
    /// # The invariant, and why prose was not enough
    ///
    /// R311y914 (item 434) answered "what path does a non-text map key get?"
    /// with "the escape alphabet is already closed": R311y910's rule emits `\`
    /// only before a `.` or a `\`, so a segment beginning `\` followed by
    /// anything else cannot come from a text key, and that free space is where
    /// the reserved forms live. The whole design rests on that one sentence and
    /// NOTHING CHECKED IT — each walk's own tests only look at their own
    /// output. Item 443 was registered for that, as a sibling of item 438: an
    /// invariant that lives in prose is re-derived by whoever edits next.
    ///
    /// It was not hypothetical. Writing this gate is what found the float form
    /// emitting `\f1.5` — an UNESCAPED separator inside a reserved segment,
    /// live since R311y914, which made `{1.5: 1}` and `{1.0: {"5": 1}}` share a
    /// path. See `payload_cbor::tests::a_float_key_does_not_spell_a_path_separator`.
    ///
    /// # Both directions
    ///
    /// A letter observed but not declared is a form that slipped in without
    /// coming to this list. A letter declared but not observed is a corpus that
    /// stopped exercising a form, which is how a gate quietly becomes a gate
    /// over nothing — so the assertion is on the SET, not on a count.
    #[test]
    fn every_builtins_path_segments_stay_inside_the_reserved_namespace() {
        assert!(!BUILTIN_NAMES.is_empty(), "a gate over nothing is green");
        let mut reserved_seen: Vec<char> = Vec::new();
        let mut escaped_text_seen: Vec<char> = Vec::new();
        for name in BUILTIN_NAMES {
            let entries: Vec<&(&str, &[u8], &str)> =
                PATH_CORPUS.iter().filter(|(n, _, _)| n == name).collect();
            assert!(
                !entries.is_empty(),
                "built-in `{name}` has no PATH_CORPUS entry, so this gate says \
                 nothing at all about the paths it emits"
            );
            let format = builtin(name).expect("a listed built-in resolves");
            for (_, bytes, what) in entries {
                let fields = format
                    .decode(bytes)
                    .unwrap_or_else(|e| panic!("`{name}` corpus `{what}` did not decode: {e:?}"));
                assert!(
                    !fields.is_empty(),
                    "`{name}` corpus `{what}` produced no rows, so it exercises no path"
                );
                for field in &fields {
                    for segment in path_segments(&field.path) {
                        let mut chars = segment.chars();
                        if chars.next() != Some('\\') {
                            continue;
                        }
                        let letter = chars.next().unwrap_or_else(|| {
                            panic!(
                                "`{name}` corpus `{what}` emitted a lone `\\` as a whole \
                                 segment in `{}`",
                                field.path
                            )
                        });
                        if letter == '.' || letter == '\\' {
                            // A text key whose first character needed escaping.
                            escaped_text_seen.push(letter);
                            continue;
                        }
                        assert!(
                            reserved_path_letters().contains(&letter),
                            "`{name}` corpus `{what}` emitted the segment `{segment}` in \
                             `{}`, and `\\{letter}` is in no declared form -- either the \
                             form is new and belongs in `payload_cbor::Reserved`, or a text \
                             key reached the reserved namespace unescaped",
                            field.path
                        );
                        reserved_seen.push(letter);
                    }
                }
            }
        }
        reserved_seen.sort_unstable();
        reserved_seen.dedup();
        let mut declared = reserved_path_letters();
        declared.sort_unstable();
        assert_eq!(
            reserved_seen, declared,
            "the corpus and the walker's own namespace disagree: a form the \
             walker can write and no payload produces is a form nothing tests"
        );
        escaped_text_seen.sort_unstable();
        escaped_text_seen.dedup();
        assert_eq!(
            escaped_text_seen,
            vec!['.', '\\'],
            "the corpus must also carry the LEGAL `\\`-leading segments, or the \
             check above is only ever asked the easy question"
        );
    }

    /// R311y916 (item 443) — pairs of documents that a path syntax with a hole
    /// in it would give the SAME path.
    ///
    /// The namespace check above cannot see this class, and saying so is why
    /// this list exists: an unescaped `.` INSIDE a reserved segment splits into
    /// two segments that both look perfectly legal (`\f1` and `5`), so nothing
    /// about the segments alone is wrong. What is wrong is that a second
    /// document reaches the same string.
    const PATH_COLLISION_CORPUS: &[(&str, &[u8], &[u8], &str)] = &[
        (
            "cbor",
            &[0xa1, 0xf9, 0x3e, 0x00, 0x01],
            &[0xa1, 0xf9, 0x3c, 0x00, 0xa1, 0x61, 0x35, 0x01],
            "{1.5: 1} vs {1.0: {\"5\": 1}} -- a float rendering carries a `.`",
        ),
        (
            "cbor",
            &[0xa1, 0x05, 0x61, 0x61],
            &[0xa1, 0x61, 0x35, 0x61, 0x62],
            "{5: \"a\"} vs {\"5\": \"b\"} -- item 434's own collision",
        ),
        (
            "cbor",
            &[0xa1, 0x63, 0x5c, 0x69, 0x35, 0x01],
            &[0xa1, 0x05, 0x01],
            "{\"\\\\i5\": 1} vs {5: 1} -- a text key spelling a reserved form",
        ),
        (
            "json",
            br#"{"a.b":1}"#,
            br#"{"a":{"b":1}}"#,
            "a dotted key vs the nesting it would otherwise mean",
        ),
    ];

    /// R311y916 (item 443) — TWO DIFFERENT DOCUMENTS NEVER SHARE A LEAF PATH.
    ///
    /// # Why this is the second half of item 443 and not a duplicate of it
    ///
    /// A `--payload-name` declaration matches a path by string equality, so a
    /// path that two documents can produce renames a field the operator never
    /// meant — that is the harm the reserved namespace exists to prevent, and
    /// the namespace check is a PROXY for it. This is the harm itself. The
    /// float form is the proof the proxy was not enough: `\f1.5` passes a check
    /// on segment letters and collides anyway.
    ///
    /// The LEAF is compared rather than the whole row list, deliberately. The
    /// two documents differ in shape, so their lists differ even when the leaves
    /// collide, and a list comparison would have called the float defect green.
    #[test]
    fn no_two_documents_in_the_collision_corpus_share_a_leaf_path() {
        assert!(
            !PATH_COLLISION_CORPUS.is_empty(),
            "a gate over nothing is green"
        );
        for (name, left, right, what) in PATH_COLLISION_CORPUS {
            let format = builtin(name).expect("a listed built-in resolves");
            let leaf = |bytes: &[u8]| -> String {
                format
                    .decode(bytes)
                    .unwrap_or_else(|e| panic!("`{name}` collision case `{what}`: {e:?}"))
                    .last()
                    .unwrap_or_else(|| panic!("`{name}` collision case `{what}` produced no rows"))
                    .path
                    .clone()
            };
            assert_ne!(
                leaf(left),
                leaf(right),
                "`{name}`: {what} -- two documents reach one path, so a \
                 `--payload-name` declaration for it renames both"
            );
        }
    }

    /// R311y909 — THE JSON BUILT-IN CLAIMS EXACTLY THE TABLE ENTRIES THIS
    /// CRATE ALREADY CALLS JSON, derived rather than re-read.
    ///
    /// # Why derived
    ///
    /// `crate::payload::shape_of` is where this crate decides what a declared
    /// encoding CLAIMS, and it already rules that `application/json5`,
    /// `application/json-seq` and `application/jsonpath` are not JSON. The
    /// format's `encodings()` is a second statement of the same judgement, and
    /// R311y873's own lesson beside it is that a hand-kept list of table names
    /// drifts silently: a name in no entry agrees with no sample and quietly
    /// refuses every payload, which reads exactly like "no traffic matched".
    ///
    /// So the gate does not re-read the table by eye. It asks `shape_of` for
    /// every entry the wire table has and requires the claimed set to be
    /// exactly the JSON-shaped ones. An upstream entry added later that
    /// `shape_of` calls JSON reds here on the round it lands, and a claim this
    /// crate does not consider JSON reds too.
    #[test]
    fn the_json_builtin_claims_exactly_the_shapes_this_crate_calls_json() {
        use wz_codecs::encoding_ids::ENCODING_ID_TO_STR;
        let mut shaped: Vec<&str> = ENCODING_ID_TO_STR
            .iter()
            .copied()
            .filter(|name| matches!(crate::payload::shape_of(name), crate::payload::Shape::Json))
            .collect();
        shaped.sort_unstable();
        assert!(
            !shaped.is_empty(),
            "the table names no JSON shape at all, so this gate would be green \
             over an empty set"
        );
        let mut claimed: Vec<&str> = Json.encodings().expect("json names its encodings").to_vec();
        claimed.sort_unstable();
        assert_eq!(
            claimed, shaped,
            "the `json` built-in and `shape_of` disagree about which declared \
             encodings are JSON documents"
        );
    }

    /// R311y914 (item 433) — THE CBOR BUILT-IN CLAIMS EXACTLY THE TABLE ENTRIES
    /// THIS CRATE CALLS CBOR, derived rather than re-read.
    ///
    /// The same gate the JSON built-in has, against the same drift and for a
    /// sharper reason here: the wire table has one cbor entry today, and an
    /// upstream `application/cbor-seq` would be a SEQUENCE of data items, which
    /// this walk refuses by design (it requires exactly one). Whichever way that
    /// lands, it must land as a red on the round it arrives rather than as a
    /// silent contradiction between two hand-kept lists.
    #[test]
    fn the_cbor_builtin_claims_exactly_the_shapes_this_crate_calls_cbor() {
        use wz_codecs::encoding_ids::ENCODING_ID_TO_STR;
        let mut shaped: Vec<&str> = ENCODING_ID_TO_STR
            .iter()
            .copied()
            .filter(|name| matches!(crate::payload::shape_of(name), crate::payload::Shape::Cbor))
            .collect();
        shaped.sort_unstable();
        assert!(
            !shaped.is_empty(),
            "the table names no CBOR shape at all, so this gate would be green \
             over an empty set"
        );
        let mut claimed: Vec<&str> = Cbor.encodings().expect("cbor names its encodings").to_vec();
        claimed.sort_unstable();
        assert_eq!(
            claimed, shaped,
            "the `cbor` built-in and `shape_of` disagree about which declared \
             encodings are CBOR documents"
        );
    }

    /// R311y914 — THE CBOR BUILT-IN IS REACHED THROUGH THE TRAIT, with the
    /// spans a reader keys on.
    ///
    /// `payload_cbor`'s own tests gate the grammar; this one gates the SEAM —
    /// that `--payload-format 'demo/**=cbor'` resolves to a decoder that returns
    /// rows, and that an empty payload takes the `NotThisFormat` arm the other
    /// two built-ins take rather than being called malformed.
    #[test]
    fn the_cbor_builtin_decodes_through_the_trait_and_declines_an_empty_body() {
        let format = builtin("cbor").expect("`cbor` is a built-in");
        // {"a": [1, 2]}
        let body = &[0xa1, 0x61, 0x61, 0x82, 0x01, 0x02];
        let decoded = format.decode(body).expect("a CBOR map");
        let rows: Vec<(&str, &str)> = decoded
            .iter()
            .map(|f| (f.path.as_str(), f.value.as_str()))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("$", "map 1 pair(s)"),
                ("$.a", "array 2 element(s)"),
                ("$.a.0", "unsigned 1"),
                ("$.a.1", "unsigned 2"),
            ]
        );
        assert_eq!(
            format.decode(&[]),
            Err(PayloadFormatError::NotThisFormat),
            "an empty payload is a mapping question, not a malformed document"
        );
    }

    /// R311y909 — A JSON DOCUMENT IS WALKED INTO ITS VALUES, each with the
    /// path that names it and the bytes it was decoded from.
    ///
    /// The witness for the whole round: before it, a payload declaring
    /// `application/json` was told it parsed and then handed to the reader as
    /// a length. Containers stand above their children so the listing reads
    /// top-down, which is the order the protobuf walk already emits in.
    #[test]
    fn a_json_document_is_walked_into_its_values_with_paths_and_spans() {
        //             0         1         2
        //             0123456789012345678901 2
        let body = br#"{"a":1,"b":[true,null]}"#;
        let fields = Json.decode(body).expect("a JSON document");
        let seen: Vec<(&str, &str, usize, usize)> = fields
            .iter()
            .map(|f| (f.path.as_str(), f.value.as_str(), f.start, f.end))
            .collect();
        assert_eq!(
            seen,
            vec![
                ("$", "object 2 member(s)", 0, 23),
                ("$.a", "number 1", 5, 6),
                ("$.b", "array 2 element(s)", 11, 22),
                ("$.b.0", "bool true", 12, 16),
                ("$.b.1", "null", 17, 21),
            ],
            "every value gets a row, rooted at `$`, containers above their \
             children"
        );
        // The spans are the reader's coordinate into the capture, so they must
        // be the bytes and not an approximation of them.
        for f in &fields {
            assert!(
                f.end <= body.len() && f.start < f.end,
                "a row's span must be inside the payload: {f:?}"
            );
        }
        assert_eq!(&body[5..6], b"1");
        assert_eq!(&body[12..16], b"true");
    }

    /// R311y909 — A MEMBER'S SPAN IS ITS VALUE AND NOT ITS KEY.
    ///
    /// The rule is on `crate::payload::walk_json` and this is what tells it
    /// apart from the plausible alternative: spanning `"a":1` would make the
    /// row start at byte 1 rather than byte 5. An array element has no key, so
    /// the member-wide span would give the same field two meanings depending on
    /// what contained it.
    #[test]
    fn a_members_span_is_its_value_and_not_the_key_in_front_of_it() {
        let body = br#"{"a":1}"#;
        let fields = Json.decode(body).expect("a JSON document");
        let member = fields
            .iter()
            .find(|f| f.path == "$.a")
            .expect("the member has a row");
        assert_eq!(
            (member.start, member.end),
            (5, 6),
            "the span is the value's own bytes: {member:?}"
        );
        assert_ne!(member.start, 1, "and NOT the key's");
    }

    /// R311y909 — THE NAME IS IN THE PATH AND NEVER IN `name`.
    ///
    /// JSON carries its own member names, which is exactly the reason to state
    /// the invariant: `PayloadField::name` means "the DECLARED name, from
    /// `FormatMap::field_name`", and a decoder filling it in would make one
    /// field carry two provenances. The wire's name goes where the wire put it.
    #[test]
    fn a_json_decoder_never_fills_in_the_declared_name_field() {
        let fields = Json
            .decode(br#"{"sensor":{"temp":21.5}}"#)
            .expect("a JSON document");
        assert!(
            fields.iter().all(|f| f.name.is_none()),
            "the decoder must leave `name` for the declaration: {fields:?}"
        );
        let leaf = fields
            .iter()
            .find(|f| f.value == "number 21.5")
            .expect("the leaf is walked");
        assert_eq!(
            leaf.path, "$.sensor.temp",
            "and the wire's own names are the route to it"
        );
    }

    /// R311y909 — a body that BREAKS says where, and one that RUNS OUT says
    /// so differently.
    ///
    /// Three answers exist and a reader acts differently on each
    /// (`PayloadFormatError`'s own doc). A truncation is a capture question —
    /// re-capture with a bigger snaplen — and a broken byte inside the document
    /// is a sender question. Told apart by whether the stop is AT the end.
    #[test]
    fn a_json_body_that_breaks_says_where_and_one_that_runs_out_says_so() {
        assert_eq!(
            Json.decode(br#"{"a":}"#),
            Err(PayloadFormatError::Malformed {
                at: 5,
                why: String::from("not a JSON value"),
            }),
            "a byte inside the document that is not a value is the sender's"
        );
        assert_eq!(
            Json.decode(br#"{"a":"#),
            Err(PayloadFormatError::Truncated(5)),
            "a document that ends mid-value is the capture's"
        );
        assert_eq!(
            Json.decode(br#"{"a":1}x"#),
            Err(PayloadFormatError::Malformed {
                at: 7,
                why: String::from("trailing input after the top-level value"),
            }),
            "and a second document behind the first is neither -- it is bytes \
             the sender put there"
        );
        assert_eq!(
            Json.decode(b""),
            Err(PayloadFormatError::NotThisFormat),
            "an empty payload sends the reader to their mapping"
        );
    }

    /// R311y909 — THE DECODER AND THE VALIDATOR ARE ONE READER.
    ///
    /// `crate::payload::inspect` publishes a verdict about a declared JSON
    /// payload and this decoder opens it. Two readings of RFC 8259 would let
    /// the plane above call a document well-formed that the plane below
    /// refuses — a disagreement inside one report, which is the worst shape a
    /// finding can take.
    ///
    /// It is one grammar today by construction, so what this asserts is that it
    /// STAYS one: the corpus covers the rules a second reader gets wrong (a
    /// leading zero, a bare control character in a string, a trailing comma,
    /// the depth bound) and requires the two entry points to agree on the
    /// OFFSET as well as on the verdict.
    #[test]
    fn the_json_decoder_and_the_json_validator_never_disagree() {
        let deep_ok = nested_json(crate::payload::MAX_JSON_DEPTH);
        let deep_over = nested_json(crate::payload::MAX_JSON_DEPTH + 1);
        let corpus: Vec<Vec<u8>> = vec![
            br#"{"a":1}"#.to_vec(),
            br#"[]"#.to_vec(),
            br#"{}"#.to_vec(),
            br#""text""#.to_vec(),
            br#"01"#.to_vec(),
            br#"{"a":1,}"#.to_vec(),
            br#"[1,2,]"#.to_vec(),
            b"\"a\nb\"".to_vec(),
            br#"tru"#.to_vec(),
            br#"1e"#.to_vec(),
            br#"-"#.to_vec(),
            deep_ok,
            deep_over,
        ];
        for body in &corpus {
            let walked = Json.decode(body);
            let validated = crate::payload::json_wellformed(body);
            assert_eq!(
                walked.is_ok(),
                validated.is_ok(),
                "the two readers disagree about {:?}: walk={walked:?} \
                 validate={validated:?}",
                String::from_utf8_lossy(body)
            );
            if let (Err(err), Err((at, _))) = (&walked, &validated) {
                let walked_at = match err {
                    PayloadFormatError::Truncated(at) => *at,
                    PayloadFormatError::Malformed { at, .. } => *at,
                    PayloadFormatError::NotThisFormat => continue,
                };
                assert_eq!(
                    walked_at,
                    *at,
                    "the two readers stop at different bytes in {:?}",
                    String::from_utf8_lossy(body)
                );
            }
        }
    }

    /// `depth` nested arrays around a `0`.
    fn nested_json(depth: usize) -> Vec<u8> {
        let mut out = vec![b'['; depth];
        out.push(b'0');
        out.resize(out.len() + depth, b']');
        out
    }

    /// R311y910 (open-debt item 432) — A BODY THAT IS NOT UTF-8 IS NOT A JSON
    /// TEXT, AND IS REFUSED WITH THE OFFSET RATHER THAN WALKED.
    ///
    /// # What this replaces, and why it was worse than a missing check
    ///
    /// R311y909 shipped this test asserting the opposite: the walk ACCEPTED
    /// `{"\xFF":1}` and called the member `$.<not-utf8>`. That was the honest
    /// rendering of what the scanner then did, and the scanner was wrong. RFC
    /// 8259 §8.1 makes UTF-8 part of what a JSON text is, so `inspect` was
    /// answering `Verdict::Json` -- "it parsed" -- about bytes that are not
    /// JSON, and `payload_decode::judge_claim` uses exactly that verdict to
    /// decide whether a publisher's `application/json` label survives being
    /// weighed against its own bytes. A surviving label VETOES the operator's
    /// rule, so the reader could be argued out of decoding a topic by a body
    /// this reader should have refuted.
    ///
    /// The offset is the first invalid byte, which is where the Text arm of
    /// `inspect` has always pointed for the same failure -- so the two shapes
    /// this module recognises now answer the same way.
    #[test]
    fn a_body_that_is_not_utf8_is_refused_at_the_byte_that_is_not() {
        let body = [b'{', b'"', 0xFF, b'"', b':', b'1', b'}'];
        assert_eq!(
            Json.decode(&body),
            Err(PayloadFormatError::Malformed {
                at: 2,
                why: String::from("not UTF-8, which RFC 8259 requires of a JSON text"),
            }),
            "byte 2 is the 0xFF, and a sender put it there"
        );
        // The SAME document with the byte replaced by a real character walks,
        // so the refusal is about the encoding and not about the shape. `0xFF`
        // is `U+00FF`, which in UTF-8 is two bytes -- so this is the same
        // CHARACTER the document above tried to carry as one raw byte.
        let ok = "{\"\u{00FF}\":1}".as_bytes();
        let fields = Json.decode(ok).expect("the same character, encoded");
        assert!(
            fields.iter().any(|f| f.value == "number 1"),
            "the control: {fields:?}"
        );
        // And a NON-ASCII key that IS valid UTF-8 keeps its own name, which is
        // the case a blanket ASCII check would have broken.
        let utf8 = "{\"온도\":1}".as_bytes();
        let fields = Json.decode(utf8).expect("valid UTF-8 is JSON");
        assert!(
            fields.iter().any(|f| f.path == "$.온도"),
            "a multi-byte key is a name, not a failure: {fields:?}"
        );
    }

    /// R311y910 (open-debt item 431) — A DOTTED KEY AND A NESTED MEMBER GET
    /// DIFFERENT PATHS.
    ///
    /// # The discriminator, and why the obvious test is not it
    ///
    /// Asserting `$.a\.b` for `{"a.b":1}` alone would pass over an emitter that
    /// escaped EVERYTHING, or one that escaped nothing and happened to be read
    /// by a lenient assertion. The pair is the test: the two documents must
    /// produce DIFFERENT paths, and the nested one must be unchanged from what
    /// R311y909 already emitted — an escape that also fired on the separator
    /// between segments would have broken every existing path.
    ///
    /// The third document is the escape escaping itself, which is the collision
    /// one level down that an escape scheme usually misses.
    #[test]
    fn a_dotted_key_and_a_nested_member_do_not_collide_on_one_path() {
        let dotted = Json.decode(br#"{"a.b":1}"#).expect("a JSON document");
        let nested = Json.decode(br#"{"a":{"b":1}}"#).expect("a JSON document");

        let leaf = |fields: &[PayloadField]| -> String {
            fields
                .iter()
                .find(|f| f.value == "number 1")
                .expect("the leaf is walked")
                .path
                .clone()
        };
        let (d, n) = (leaf(&dotted), leaf(&nested));
        assert_ne!(d, n, "the two documents must not share a path");
        assert_eq!(d, r"$.a\.b", "a `.` in a key is escaped");
        assert_eq!(
            n, "$.a.b",
            "and nesting is UNCHANGED, which is the half an over-eager escape would break"
        );

        // The escape escapes itself, which is the collision one level down.
        // A path segment is the key's SOURCE text (the rule string VALUES
        // already follow), so `{"a\\.b":1}` has the two-character run `\\` in
        // its key and each of those doubles, then the `.` is escaped: five
        // backslashes and a dot. Unpretty and REVERSIBLE, which is the property
        // that matters -- an operator can write this path and get one field.
        let backslash = Json.decode(br#"{"a\\.b":1}"#).expect("a JSON document");
        assert_eq!(
            leaf(&backslash),
            r"$.a\\\\\.b",
            "the key's own backslashes double and its dot is still escaped"
        );
    }

    /// R311y701 (PF3) — A NESTED MESSAGE IS WALKED, and its fields carry
    /// the ROUTE to them and spans in the OUTER payload's coordinates.
    ///
    /// Before this round wire type 2 was rendered as text or as a byte
    /// count, so a reader whose schema nests — which real schemas do — saw
    /// exactly one layer of their own data and no sign there was more.
    #[test]
    fn a_nested_message_is_walked_and_its_paths_name_the_route() {
        // { 1: 150, 2: { 1: 7, 2: "in" } }
        let inner = [0x08u8, 0x07, 0x12, 0x02, b'i', b'n'];
        let mut outer = vec![0x08u8, 0x96, 0x01, 0x12, inner.len() as u8];
        outer.extend_from_slice(&inner);

        let fields = Protobuf.decode(&outer).expect("a protobuf message");
        let seen: Vec<(&str, &str, usize, usize)> = fields
            .iter()
            .map(|f| (f.path.as_str(), f.value.as_str(), f.start, f.end))
            .collect();
        assert_eq!(
            seen,
            vec![
                ("1", "varint 150", 0, 3),
                // The parent is rendered as a COUNT of what is under it and
                // stands ABOVE its children, so the listing reads top-down.
                ("2", "len 2 field(s)", 3, 11),
                // R311y677's rule, one layer in: the inner spans are in the
                // outer payload's space, so a reader can line them up
                // against the bytes. `5` is where the nested body begins.
                ("2.1", "varint 7", 5, 7),
                ("2.2", "len \"in\"", 7, 11),
            ],
            "the walk must reach the nested fields and name the route to them"
        );
    }

    /// R311y701 (PF3) — TWO layers, because one does not test the rebase.
    ///
    /// MEASURED: dropping the accumulated `base` from the recursive call
    /// left the one-layer test above GREEN, and it has to — at the top
    /// level `base` is zero, so `base + body` and `body` are the same
    /// number. The offset only diverges from the second layer down, which
    /// is where a probe put it and where this witness now sits.
    #[test]
    fn a_span_two_layers_in_is_still_in_the_outer_payloads_coordinates() {
        // { 1: { 1: { 1: 7 } } }
        let innermost = [0x08u8, 0x07];
        let mid = [0x0Au8, innermost.len() as u8, innermost[0], innermost[1]];
        let mut outer = vec![0x0Au8, mid.len() as u8];
        outer.extend_from_slice(&mid);

        let fields = Protobuf.decode(&outer).expect("a protobuf message");
        let seen: Vec<(&str, usize, usize)> = fields
            .iter()
            .map(|f| (f.path.as_str(), f.start, f.end))
            .collect();
        assert_eq!(
            seen,
            vec![("1", 0, 6), ("1.1", 2, 6), ("1.1.1", 4, 6)],
            "each layer's body begins two bytes past its parent's, and the \
             offsets ACCUMULATE"
        );
    }

    /// R311y701 (PF3) — bytes that are NOT a message fall back rather than
    /// rejecting the whole payload.
    ///
    /// A length-delimited field is a string, a message OR a blob, and the
    /// wire format does not say which. A recursion that treated "does not
    /// parse" as malformed would refuse every payload carrying a JPEG.
    #[test]
    fn a_length_field_that_is_not_a_message_falls_back_to_its_byte_count() {
        // Field 1, four bytes that start with a valid-looking tag and then
        // run out: `0x08` says field 1 varint and nothing follows it.
        let blob = [0xFFu8, 0xD8, 0xFF, 0x08];
        let mut outer = vec![0x0Au8, blob.len() as u8];
        outer.extend_from_slice(&blob);

        let fields = Protobuf.decode(&outer).expect("still a protobuf message");
        assert_eq!(
            fields.len(),
            1,
            "the blob contributes no children: {fields:?}"
        );
        assert_eq!(fields[0].value, "len 4 byte(s)");
    }

    /// R311y701 (PF3) — text still wins over a nested parse, and the rule
    /// that makes that safe is stated on [`text_like`].
    ///
    /// `"Px"` parses cleanly as field 10 varint 120. It is a string, and a
    /// walker that tried the parse first would rename it.
    #[test]
    fn printable_bytes_are_text_even_when_they_would_parse_as_a_message() {
        let mut outer = vec![0x0Au8, 2];
        outer.extend_from_slice(b"Px");
        let fields = Protobuf.decode(&outer).expect("a protobuf message");
        assert_eq!(fields[0].value, "len \"Px\"");
        assert_eq!(fields.len(), 1, "and nothing was walked into it");

        // The control-character half of the rule, which is what lets a
        // nested message through: the same two bytes with a control byte in
        // front are not text.
        assert!(text_like(b"Px").is_some());
        assert!(text_like(&[0x08, 0x07]).is_none());
    }

    /// R311y701 (PF3) — the depth bound is REPORTED rather than silently
    /// stopping, the rule every bound in this workspace answers to.
    #[test]
    fn nesting_past_the_bound_says_so_rather_than_going_quiet() {
        // MAX_NESTING + 1 layers, each one field 1 wrapping the next, with
        // a two-byte non-text leaf so no layer is mistaken for a string.
        let mut body = vec![0x08u8, 0x07];
        for _ in 0..=MAX_NESTING {
            let mut wrapped = vec![0x0Au8, body.len() as u8];
            wrapped.extend_from_slice(&body);
            body = wrapped;
        }
        let fields = Protobuf.decode(&body).expect("a protobuf message");
        let deepest = fields.last().expect("at least one field");
        assert!(
            deepest
                .value
                .contains("nested deeper than this reader walks"),
            "the bottom of the walk says the bound bit: {fields:?}"
        );
        // And the bound is the one declared, counted by path depth.
        assert_eq!(
            deepest.path.matches('.').count(),
            MAX_NESTING,
            "the walk went exactly as deep as it says it does: {fields:?}"
        );
    }
}
