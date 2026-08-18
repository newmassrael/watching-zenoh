// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y856 — APPLYING a payload declaration to one walked message: find the
//! key expression and the payload it was published under, pick the rule that
//! covers it, decode, and rebase the spans.
//!
//! ## Why this is here and not in the command line
//!
//! Every piece of it was in `wz-analyze` and reachable only by running a
//! terminal. The C ABI — the surface a product LINKS — had
//! [`crate::payload::formats::FormatMap`] in its dependency graph, no decoder
//! to put in one, and no code that would consult it if it had. That is the
//! `analysis_surface_parity.py` OPEN DEBT this round pays, and the shape of the
//! payment is R311y851's: the implementation moves beside the type, and neither
//! consumer owns it.
//!
//! ## What stays in the command line
//!
//! The RENDERING. [`PayloadDecoding`] is the answer; how it is spelled for a
//! person reading a terminal, and which flag a reader should go fix, are
//! properties of that surface and stay there.

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;

use wz_session_core::dissect::{Field, FieldValue};
use wz_session_core::passive::Direction;

use crate::agg::KeyexprSpaces;
use crate::payload::formats::{Declaration, DeclarationId, FormatMap, PayloadField, PayloadFormat};

/// R311y726 — THE DECLARATIONS IN FORCE FOR ONE RUN, and which of them applied.
///
/// # Why this is not on the map
///
/// R311y725 answered "which declarations bound nothing" by putting a
/// `Cell<bool>` beside every rule inside [`FormatMap`]. It worked and it put
/// the wrong fact in the wrong place: a `FormatMap` is what the reader
/// DECLARED, which does not change while a capture is walked, and "was this
/// rule ever selected" is a fact about ONE walk. Merged, the two mean a map
/// cannot be consulted twice as if it were fresh, and two analyses sharing
/// declarations would read each other's marks.
///
/// So the map went back to being configuration and this type owns the run. It
/// borrows the map, forwards the two questions the field layer asks, and
/// remembers the handle each answer came back with. `RefCell` and not `&mut`
/// because the field layer's rendering path is threaded with shared borrows
/// several calls deep — a `&mut` would have to be carried through every row
/// renderer, and the row renderers have nothing to do with this.
pub struct Declarations<'a> {
    map: &'a FormatMap<'a>,
    used: RefCell<BTreeSet<DeclarationId>>,
}

impl<'a> Declarations<'a> {
    /// A fresh ledger over `map`, with nothing applied yet.
    pub fn new(map: &'a FormatMap<'a>) -> Self {
        Self {
            map,
            used: RefCell::new(BTreeSet::new()),
        }
    }

    /// Whether any rule was installed — the map's own question, forwarded so a
    /// caller holding this type does not have to reach past it.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Whether any field NAME was declared, forwarded for the same reason.
    pub fn has_names(&self) -> bool {
        self.map.has_names()
    }

    /// The format for this keyexpr, RECORDING that the rule applied.
    pub fn for_keyexpr(&self, keyexpr: &str) -> Option<&'a dyn PayloadFormat> {
        let (id, format) = self.map.for_keyexpr(keyexpr)?;
        self.used.borrow_mut().insert(id);
        Some(format)
    }

    /// The declared name for this path, RECORDING that the declaration applied.
    pub fn field_name(&self, keyexpr: &str, path: &str) -> Option<String> {
        let (id, name) = self.map.field_name(keyexpr, path)?;
        self.used.borrow_mut().insert(id);
        Some(name.to_string())
    }

    /// The declarations this run never applied.
    ///
    /// Answerable only after a walk, and that is a property of the question
    /// rather than a caveat: before one, nothing has applied and the honest
    /// answer is "all of them".
    pub fn unused(&self) -> Vec<Declaration> {
        let used = self.used.borrow();
        self.map
            .declarations()
            .into_iter()
            .filter(|d| !used.contains(&d.id))
            .collect()
    }
}

/// R311y701 (PF2) — what a keyexpr id is resolved AGAINST.
///
/// The two halves a `WireExpr` needs and a field tree alone does not carry:
/// which side sent this message, and what that flow has declared so far.
#[derive(Clone, Copy)]
pub struct KeyexprAt<'a> {
    direction: Direction,
    spaces: &'a KeyexprSpaces,
}

impl<'a> KeyexprAt<'a> {
    /// A row travelling `direction`, resolved against `spaces`.
    ///
    /// A constructor rather than public fields, because the pair is one fact:
    /// a caller that could supply one without the other could hand over a
    /// direction with nothing to resolve against.
    pub fn new(direction: Direction, spaces: &'a KeyexprSpaces) -> Self {
        Self { direction, spaces }
    }
}

/// What became of one message's payload under the declarations in force.
///
/// # Why every non-decode is a named answer rather than silence
///
/// A rule that did not fire and a rule that fired and found nothing look
/// identical in an empty listing, and they send a reader to opposite places:
/// one is a mapping to fix, the other is traffic to look at. The keyexpr that
/// was TESTED is carried for the same reason — a reader whose rule covers
/// `demo/**` needs to see that this message's keyexpr was `other/thing` before
/// they start doubting the decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadDecoding {
    /// No rules at all. Renders nothing: a reader who declared no format is not
    /// told about payloads they did not ask about.
    NoRules,
    /// This message carries no payload field. Not every zenoh message does.
    NoPayload,
    /// The keyexpr is a numeric id with no suffix on the wire, so no rule can
    /// be tested against it at all.
    ///
    /// Said rather than skipped: this is the ordinary shape of a capture that
    /// began after the declarations, and a reader whose rules silently cover
    /// nothing would blame the rules.
    KeyexprUnresolved,
    /// A keyexpr, and no rule covers it.
    NoRule(String),
    /// Decoded, and the fields with spans in the MESSAGE's coordinates.
    Decoded {
        /// The key expression the rule was matched against.
        keyexpr: String,
        /// The decoder that read it.
        format: String,
        /// The fields, rebased into the message's coordinate space.
        fields: Vec<PayloadField>,
    },
    /// The format was applied and refused.
    Refused {
        /// The key expression the rule was matched against.
        keyexpr: String,
        /// The decoder that refused.
        format: String,
        /// What it said.
        why: String,
    },
}

/// The keyexpr of the `WireExpr` under `field`, RESOLVED.
///
/// # R311y701 (PF2) — why the suffix alone was not the answer
///
/// This read the `suffix` text and stopped, on the note that the id-to-path
/// table lived in another plane. Two things were wrong with that.
///
/// The first is a silence: a capture that began AFTER the declarations names
/// every keyexpr by id alone, which is the ordinary shape of a capture taken
/// from a running system. Every rule then matched nothing and the listing said
/// `keyexpr_unresolved` for each message — honest, and useless.
///
/// The second is worse and was not noticed when that note was written: a
/// message carrying BOTH an id and a suffix has the id's base PREPENDED to the
/// suffix, so reading the suffix alone reported `/temp` for a record published
/// under `demo/sensor/temp`. That is a wrong keyexpr rather than a missing one,
/// and a rule keyed on `demo/**` silently did not fire on traffic it covers.
///
/// The resolution itself is [`KeyexprSpaces::resolve_parts`], never a second
/// copy of the rule.
pub fn subtree_keyexpr(field: &Field, at: KeyexprAt<'_>) -> Option<String> {
    if field.name == "keyexpr" {
        if let FieldValue::Nested(parts) = &field.value {
            let mut id = 0u64;
            let mut mapping = 0u64;
            let mut suffix: Option<&str> = None;
            for part in parts {
                match (part.name.as_ref(), &part.value) {
                    ("id", FieldValue::Uint(v)) => id = *v,
                    ("mapping", FieldValue::Bits(v)) => mapping = *v,
                    ("suffix", FieldValue::Text(text)) => suffix = Some(text),
                    _ => {}
                }
            }
            // The `M` bit names the table: 1 is the SENDER's space, which for a
            // message travelling this way is this direction's own, and 0 is the
            // receiver's. `KeyexprSpaces::resolve` derives the same choice from
            // the codec variant; this derives it from the bit the walk records,
            // and both hand the same question to one resolver.
            let space = if mapping == 1 {
                at.direction
            } else {
                at.direction.peer()
            };
            return at
                .spaces
                .resolve_parts(space, id, suffix)
                .ok()
                .filter(|k| !k.is_empty());
        }
    }
    if let FieldValue::Nested(children) = &field.value {
        return children.iter().find_map(|c| subtree_keyexpr(c, at));
    }
    None
}

/// The payload BYTES anywhere under `field`.
///
/// Bytes and not a group: a `Frame`'s `payload` is a walked sub-structure and a
/// message's is the application's own bytes, and only the second is something a
/// format decodes.
pub fn subtree_payload_bytes(field: &Field) -> Option<&Field> {
    if field.name == "payload" && matches!(field.value, FieldValue::Bytes(_)) {
        return Some(field);
    }
    if let FieldValue::Nested(children) = &field.value {
        return children.iter().find_map(subtree_payload_bytes);
    }
    None
}

/// R311y699 — the keyexpr and the payload OF ONE MESSAGE.
///
/// # Why this is not two `find` calls
///
/// `Field::find` is first-match-by-name over the whole tree, and its own doc
/// warns that a group sharing a leaf's name SHADOWS it. Both names collide
/// here: a `Frame`'s body is a group called `payload`, so `find("payload")`
/// returns the whole batch rather than the `MsgPut`'s bytes. MEASURED — the
/// first version of this function decoded a Frame's payload group and the rule
/// never fired.
///
/// Worse than the shadowing is what two independent lookups would MEAN. A
/// batch carries several messages; taking the first keyexpr and the first
/// payload bytes anywhere under it would pair a keyexpr with a payload the
/// sender never put under it, and the rule would decode the wrong bytes while
/// naming the right topic. So the pair is found INNERMOST-FIRST inside one
/// subtree: the node returned is the smallest one holding both.
pub fn keyexpr_and_payload<'a>(field: &'a Field, at: KeyexprAt<'_>) -> Option<(String, &'a Field)> {
    if let FieldValue::Nested(children) = &field.value {
        for child in children {
            if let Some(found) = keyexpr_and_payload(child, at) {
                return Some(found);
            }
        }
    }
    let keyexpr = subtree_keyexpr(field, at)?;
    let payload = subtree_payload_bytes(field)?;
    Some((keyexpr, payload))
}

/// Apply the mapping to one walked message.
pub fn decode_payload(field: &Field, map: &Declarations<'_>, at: KeyexprAt<'_>) -> PayloadDecoding {
    if map.is_empty() {
        return PayloadDecoding::NoRules;
    }
    let Some((keyexpr, payload)) = keyexpr_and_payload(field, at) else {
        // Either there is no payload under any keyexpr, or the only keyexpr is
        // a numeric id. The two are told apart by asking again for each half.
        return if subtree_payload_bytes(field).is_none() {
            PayloadDecoding::NoPayload
        } else {
            PayloadDecoding::KeyexprUnresolved
        };
    };
    let FieldValue::Bytes(bytes) = &payload.value else {
        return PayloadDecoding::NoPayload;
    };
    let Some(format) = map.for_keyexpr(&keyexpr) else {
        return PayloadDecoding::NoRule(keyexpr);
    };
    match format.decode(bytes) {
        Ok(mut fields) => {
            // The spans arrive PAYLOAD-relative and every other span in this
            // listing is MESSAGE-relative (R311y677). Rebasing here is the only
            // place that knows the payload's own offset, and leaving the two
            // spaces mixed in one listing is the defect R311y677 measured.
            let base = payload.span.start;
            for f in &mut fields {
                f.start += base;
                f.end += base;
                // R311y720 (PF4) — and the DECLARED name, where the deployment
                // gave one for this path under this keyexpr. Attached here
                // because this is the one place that holds both the resolved
                // keyexpr and the decoded paths; the decoder has the paths and
                // no keyexpr, and the map has neither until now.
                f.name = map.field_name(&keyexpr, &f.path);
            }
            PayloadDecoding::Decoded {
                keyexpr,
                format: format.name().to_string(),
                fields,
            }
        }
        Err(why) => PayloadDecoding::Refused {
            keyexpr,
            format: format.name().to_string(),
            why: why.to_string(),
        },
    }
}

/// R311y856 — the machine-readable rendering of one decoding, written ONCE.
///
/// # Why this is not left to each surface
///
/// It already had been. `wz-analyze` spelled these five states into JSON and
/// the C ABI had no payload block at all, so the moment the ABI grew one there
/// would have been two renderings of one value -- which is the standing
/// `debt-census-emit-two-renderings` and exactly what R311y851 refused to add a
/// third case of. The state vocabulary is a contract with a consumer that
/// branches on it; a second copy is a second contract that drifts.
///
/// The TEXT rendering stays in the command line. How a person reading a
/// terminal is told which flag to go fix is a property of that surface.
pub fn push_decoding(decoding: &PayloadDecoding, out: &mut String) {
    use wz_session_core::json::escape_into;
    match decoding {
        // A caller is expected to skip the block entirely for this state -- a
        // reader who declared nothing is not told about payloads they did not
        // ask about. Rendered rather than unreachable so this function is total
        // over the type: an `unreachable!` here would make a caller's ordering
        // mistake a panic in a library a C consumer links.
        PayloadDecoding::NoRules => out.push_str("{\"state\":\"no_rules\"}"),
        PayloadDecoding::NoPayload => out.push_str("{\"state\":\"no_payload\"}"),
        PayloadDecoding::KeyexprUnresolved => {
            out.push_str("{\"state\":\"keyexpr_unresolved\"}");
        }
        PayloadDecoding::NoRule(keyexpr) => {
            out.push_str("{\"state\":\"no_rule\",\"keyexpr\":");
            escape_into(keyexpr, out);
            out.push('}');
        }
        PayloadDecoding::Refused {
            keyexpr,
            format,
            why,
        } => {
            out.push_str("{\"state\":\"refused\",\"keyexpr\":");
            escape_into(keyexpr, out);
            out.push_str(",\"format\":");
            escape_into(format, out);
            out.push_str(",\"why\":");
            escape_into(why, out);
            out.push('}');
        }
        PayloadDecoding::Decoded {
            keyexpr,
            format,
            fields,
        } => {
            out.push_str("{\"state\":\"decoded\",\"keyexpr\":");
            escape_into(keyexpr, out);
            out.push_str(",\"format\":");
            escape_into(format, out);
            out.push_str(",\"fields\":[");
            for (i, f) in fields.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str("{\"path\":");
                escape_into(&f.path, out);
                // R311y720 (PF4) — `name` is present with a `null` rather than
                // absent when no declaration covers the path, on the structural
                // rule the rest of this JSON follows: a consumer must never have
                // to test for a key to learn that a fact is unknown.
                out.push_str(",\"name\":");
                match &f.name {
                    Some(name) => escape_into(name, out),
                    None => out.push_str("null"),
                }
                out.push_str(",\"value\":");
                escape_into(&f.value, out);
                out.push_str(",\"start\":");
                out.push_str(&f.start.to_string());
                out.push_str(",\"end\":");
                out.push_str(&f.end.to_string());
                out.push('}');
            }
            out.push_str("]}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::formats::FormatMap;
    use alloc::vec;

    /// R311y856 — A DECLARATION THAT BOUND NOTHING IS STILL REPORTED, and the
    /// ledger belongs to the RUN rather than to the map.
    ///
    /// Both halves, because either alone passes on a wrong build. A ledger that
    /// recorded nothing would report both rules unused and look right on the
    /// first assertion's sibling; a ledger that lived on the map would report
    /// the second run's `other/b` correctly and quietly carry the first run's
    /// mark for `demo/a` — which is precisely the defect R311y726 moved this
    /// type out of `FormatMap` to end, and the reason a map must be consultable
    /// twice as if it were fresh.
    #[test]
    fn a_declaration_that_binds_nothing_is_still_reported() {
        let mut map = FormatMap::new();
        map.declare("demo/a=protobuf").expect("a literal pattern");
        map.declare("other/b=protobuf").expect("a literal pattern");

        let run = Declarations::new(&map);
        assert!(run.for_keyexpr("demo/a").is_some(), "the rule covers it");
        let left = run.unused();
        let unused: Vec<&str> = left.iter().map(|d| d.text.as_str()).collect();
        assert_eq!(
            unused,
            vec!["other/b"],
            "the rule that met no traffic is the one a reader must be told about"
        );

        // The SAME map, a second run: nothing has applied yet.
        let fresh = Declarations::new(&map);
        assert_eq!(
            fresh.unused().len(),
            2,
            "a map is configuration and does not remember a previous walk"
        );
    }

    /// R311y856 — the emit is TOTAL over the type, including the state a caller
    /// is expected to skip.
    ///
    /// `NoRules` renders rather than panicking: an `unreachable!` here would
    /// turn a caller's ordering mistake into a panic inside a library a C
    /// consumer links, which is a worse failure than an odd-looking document.
    #[test]
    fn every_state_renders_and_none_of_them_panics() {
        let states = [
            PayloadDecoding::NoRules,
            PayloadDecoding::NoPayload,
            PayloadDecoding::KeyexprUnresolved,
            PayloadDecoding::NoRule(String::from("demo/\"quoted\"")),
            PayloadDecoding::Refused {
                keyexpr: String::from("demo/a"),
                format: String::from("protobuf"),
                why: String::from("these bytes are not this format"),
            },
        ];
        for state in &states {
            let mut out = String::new();
            push_decoding(state, &mut out);
            assert!(
                out.starts_with("{\"state\":\"") && out.ends_with('}'),
                "every state renders one object: {out}"
            );
        }
        // And the keyexpr is ESCAPED rather than pasted: it is text off the
        // wire, and a quote in it would end the JSON string early.
        let mut out = String::new();
        push_decoding(&states[3], &mut out);
        assert!(
            out.contains(r#""demo/\"quoted\"""#),
            "a keyexpr carrying a quote must be escaped: {out}"
        );
    }
}
