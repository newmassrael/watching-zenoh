// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Reading a flow's `context` object back into what a single-message reader
//! needs from it.
//!
//! # The direction this adds
//!
//! The field document WRITES each flow's session context
//! (`fields_json::push_context`: `phase`, `negotiated`, `lowlatency`,
//! `compression`, `qos`, `patch`, `sn_mask`, `batch_size`, `version`). A caller
//! that holds that object and wants ONE message of the flow read in its light
//! had no way to hand it back, so the message door read every message as if no
//! session existed. This module is the reader of the object the writer beside
//! it produces, and it sits in this crate and not in the door's crate for that
//! reason: the writer and its reader change together or not at all, and the
//! round-trip test below holds them to it.
//!
//! # What is read, and what is deliberately not
//!
//! Two keys decide how a message reads: `negotiated` and `lowlatency`. Both
//! must be present and of the right type, and a context that lacks one or
//! types it wrongly is REFUSED, because a misspelt key would otherwise read as
//! "unknown" and the caller would get the context-free answer it was trying to
//! leave behind, with nothing to say so.
//!
//! Every other key is IGNORED whatever its value. They belong to the same
//! object and a caller hands the whole object over, but none of them changes
//! which bytes belong to which field of a message, and checking the type of a
//! key this reader does not use would make the reader refuse a document only
//! because a key it never reads has been retyped. See
//! [`wz_session_core::dissect::MessageContext`] for why each is absent from
//! the reading.
//!
//! `negotiated: false` makes every capability unknown, whatever `lowlatency`
//! says: the writer emits `null` there, and a `true` beside `negotiated:
//! false` is the identity element of the fold that starts every capability
//! true, not an agreement ([`wz_session_core::passive::FlowContext::negotiated`]).
//!
//! The text is read by wz's JSON5 reader, which reads all of JSON; a caller
//! sending JSON is unaffected by what JSON5 adds.

use alloc::string::String;
use wz_session_core::dissect::MessageContext;
use wz_session_core::json5::{self, Json5Value};

/// Why a context text was not accepted.
///
/// A named reason rather than a bare failure, so a caller (and a test) can say
/// which key was wrong. The C door collapses all of them into one code on the
/// rule that a context is produced by code and a malformed one is the caller's
/// bug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextRefusal {
    /// The text is not a JSON document; `detail` is the reader's own message.
    NotJson {
        /// Where the reader stopped and what it expected there.
        detail: String,
    },
    /// The document is valid but its top level is not an object.
    NotAnObject,
    /// A key this reader needs is absent.
    MissingKey(&'static str),
    /// A key this reader needs has a value of another type.
    WrongType {
        /// The key.
        key: &'static str,
        /// What type it must have.
        wanted: &'static str,
    },
}

/// Read the `context` object of one flow of a field document.
///
/// `text` is the object itself (`{"phase":"closed","negotiated":true,...}`),
/// the value of a flow's `context` key, and not the document around it.
pub fn read_flow_context(text: &str) -> Result<MessageContext, ContextRefusal> {
    let document = json5::parse(text).map_err(|err| {
        use core::fmt::Write as _;
        let mut detail = String::new();
        let _ = write!(detail, "{err}");
        ContextRefusal::NotJson { detail }
    })?;
    if !matches!(document, Json5Value::Object(_)) {
        return Err(ContextRefusal::NotAnObject);
    }
    let negotiated = match document.get("negotiated") {
        Some(Json5Value::Bool(negotiated)) => *negotiated,
        Some(_) => {
            return Err(ContextRefusal::WrongType {
                key: "negotiated",
                wanted: "a boolean",
            })
        }
        None => return Err(ContextRefusal::MissingKey("negotiated")),
    };
    let lowlatency = match document.get("lowlatency") {
        Some(Json5Value::Bool(lowlatency)) => Some(*lowlatency),
        Some(Json5Value::Null) => None,
        Some(_) => {
            return Err(ContextRefusal::WrongType {
                key: "lowlatency",
                wanted: "a boolean or null",
            })
        }
        None => return Err(ContextRefusal::MissingKey("lowlatency")),
    };
    Ok(MessageContext {
        lowlatency: lowlatency.filter(|_| negotiated),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lowlatency_of(text: &str) -> Option<bool> {
        read_flow_context(text)
            .unwrap_or_else(|why| panic!("{text} was refused: {why:?}"))
            .lowlatency
    }

    #[test]
    fn a_negotiated_capability_is_read_as_the_boolean_it_is() {
        assert_eq!(
            lowlatency_of(r#"{"negotiated":true,"lowlatency":true}"#),
            Some(true)
        );
        assert_eq!(
            lowlatency_of(r#"{"negotiated":true,"lowlatency":false}"#),
            Some(false)
        );
    }

    /// The writer emits `null` for every capability until both Inits were seen,
    /// and a caller who sends `null` is saying it does not know.
    #[test]
    fn an_unnegotiated_context_knows_nothing() {
        assert_eq!(
            lowlatency_of(r#"{"negotiated":false,"lowlatency":null}"#),
            None
        );
        assert_eq!(
            lowlatency_of(r#"{"negotiated":true,"lowlatency":null}"#),
            None,
            "a negotiated session whose capability the caller does not give is unknown"
        );
    }

    /// `true` beside `negotiated: false` is the fold's starting value and not an
    /// agreement, so it must not turn the reading on.
    #[test]
    fn lowlatency_without_a_negotiation_is_not_an_agreement() {
        assert_eq!(
            lowlatency_of(r#"{"negotiated":false,"lowlatency":true}"#),
            None
        );
    }

    #[test]
    fn keys_this_reader_does_not_use_are_not_checked() {
        // Unknown keys, and known ones of a type the writer does not give them:
        // none of them is read, so none of them can refuse the document.
        let text = r#"{"phase":7,"negotiated":true,"lowlatency":true,"compression":"x",
            "qos":[1],"patch":{},"sn_mask":"268435455","batch_size":null,"future":1}"#;
        assert_eq!(lowlatency_of(text), Some(true));
    }

    #[test]
    fn a_missing_key_is_refused_by_name() {
        assert_eq!(
            read_flow_context(r#"{"lowlatency":true}"#),
            Err(ContextRefusal::MissingKey("negotiated"))
        );
        assert_eq!(
            read_flow_context(r#"{"negotiated":true}"#),
            Err(ContextRefusal::MissingKey("lowlatency"))
        );
        assert_eq!(
            read_flow_context("{}"),
            Err(ContextRefusal::MissingKey("negotiated"))
        );
    }

    #[test]
    fn a_key_of_the_wrong_type_is_refused_by_name() {
        for (text, key, wanted) in [
            (
                r#"{"negotiated":"true","lowlatency":true}"#,
                "negotiated",
                "a boolean",
            ),
            (
                r#"{"negotiated":1,"lowlatency":true}"#,
                "negotiated",
                "a boolean",
            ),
            (
                r#"{"negotiated":null,"lowlatency":true}"#,
                "negotiated",
                "a boolean",
            ),
            (
                r#"{"negotiated":true,"lowlatency":"true"}"#,
                "lowlatency",
                "a boolean or null",
            ),
            (
                r#"{"negotiated":true,"lowlatency":1}"#,
                "lowlatency",
                "a boolean or null",
            ),
        ] {
            assert_eq!(
                read_flow_context(text),
                Err(ContextRefusal::WrongType { key, wanted }),
                "{text}"
            );
        }
    }

    #[test]
    fn text_that_is_not_a_context_object_is_refused() {
        assert!(matches!(
            read_flow_context(""),
            Err(ContextRefusal::NotJson { .. })
        ));
        assert!(matches!(
            read_flow_context(r#"{"negotiated":true"#),
            Err(ContextRefusal::NotJson { .. })
        ));
        for text in ["true", "null", "7", r#""negotiated""#, "[]"] {
            assert_eq!(
                read_flow_context(text),
                Err(ContextRefusal::NotAnObject),
                "{text}"
            );
        }
    }

    /// The reader is the other half of the writer, so it is held to the writer's
    /// OUTPUT and not to a literal this file wrote: contexts the fold really
    /// produced, as `fields_json` emits them.
    ///
    /// `FlowContext`'s capability cells are private to the fold, so there is no
    /// way to fabricate a negotiated one here and no wish for one: each session
    /// is driven through real Init, Open and Close messages, for every
    /// combination of the three unit offers each side can make (LowLatency,
    /// Compression, QoS), at each stage a flow can be read in. The expected
    /// value is derived twice: from the offers (negotiated means both sides
    /// offered it) and from the fold's own accessor, and the reader has to equal
    /// both.
    #[test]
    fn it_reads_back_what_the_field_document_writes() {
        use alloc::collections::BTreeSet;
        use alloc::format;
        use alloc::vec;
        use alloc::vec::Vec;
        use wz_session_core::passive::{Direction, PassiveSession, SessionPhase};

        // The unit extensions an Init can offer, in the order of the bits of an
        // offer mask: LowLatency (id 5), Compression (id 6), QoS (id 1).
        const OFFERS: [u8; 3] = [0x05, 0x06, 0x01];
        let framed = |body: &[u8]| {
            let mut wire = (body.len() as u16).to_le_bytes().to_vec();
            wire.extend_from_slice(body);
            wire
        };
        // An Init: header (Z when it carries a chain), version, a one-byte-zid
        // cbyte, the zid, an empty cookie when it is the acknowledgement, then
        // the chain with the continuation bit on all but the last entry.
        let init = |ack: bool, offered: u8| {
            let ids: Vec<u8> = OFFERS
                .iter()
                .enumerate()
                .filter(|(bit, _)| offered & (1 << bit) != 0)
                .map(|(_, id)| *id)
                .collect();
            let z = if ids.is_empty() { 0 } else { 0x80 };
            let mut body = if ack {
                vec![0x21 | z, 9, 2, 2, 0]
            } else {
                vec![0x01 | z, 9, 2, 1]
            };
            for (i, id) in ids.iter().enumerate() {
                body.push(if i + 1 < ids.len() { id | 0x80 } else { *id });
            }
            framed(&body)
        };
        let drive = |session: &mut PassiveSession, direction: Direction, wire: &[u8]| {
            session.push(direction, wire);
            session
                .next_frame(direction)
                .expect("a message the fixture wrote");
        };
        let after_inits = |a: u8, b: u8| {
            let mut session = PassiveSession::new();
            drive(&mut session, Direction::A, &init(false, a));
            drive(&mut session, Direction::B, &init(true, b));
            session
        };

        let mut seen = BTreeSet::new();
        let mut checked = 0usize;
        let mut check = |session: &PassiveSession, expected: Option<bool>, stage: &str| {
            let context = session.context();
            assert_eq!(context.lowlatency(), expected, "{stage}: the fold itself");
            let mut written = String::new();
            crate::fields_json::push_context(&context, &mut written);
            let object = written
                .strip_prefix(",\"context\":")
                .unwrap_or_else(|| panic!("the writer's shape moved: {written}"));
            assert_eq!(
                read_flow_context(object),
                Ok(MessageContext {
                    lowlatency: expected
                }),
                "{stage}: {object}"
            );
            seen.insert(expected);
            checked += 1;
        };

        check(&PassiveSession::new(), None, "nothing seen");
        // A flow that begins at its Close is Closed and negotiated nothing, which
        // a phase-keyed reading of the document would get wrong.
        let mut closed_alone = PassiveSession::new();
        drive(&mut closed_alone, Direction::A, &framed(&[0x03, 1]));
        assert_eq!(closed_alone.context().phase, SessionPhase::Closed);
        check(&closed_alone, None, "a Close and nothing before it");

        for a in 0u8..8 {
            for b in 0u8..8 {
                let agreed = Some(a & 1 != 0 && b & 1 != 0);
                let stage = |what: &str| format!("A offers {a:03b}, B offers {b:03b}, {what}");

                let mut one_init = PassiveSession::new();
                drive(&mut one_init, Direction::A, &init(false, a));
                check(&one_init, None, &stage("one Init"));

                check(&after_inits(a, b), agreed, &stage("both Inits"));

                let mut opened = after_inits(a, b);
                drive(&mut opened, Direction::A, &framed(&[0x02, 10, 0, 0]));
                drive(&mut opened, Direction::B, &framed(&[0x22, 10, 0]));
                assert_eq!(opened.context().phase, SessionPhase::Established);
                check(&opened, agreed, &stage("established"));

                // The capabilities survive a Close: the phase moves, the
                // negotiation is a fact about what was SEEN.
                let mut closed = after_inits(a, b);
                drive(&mut closed, Direction::A, &framed(&[0x03, 1]));
                assert_eq!(closed.context().phase, SessionPhase::Closed);
                check(&closed, agreed, &stage("closed after the Inits"));
            }
        }
        assert_eq!(checked, 2 + 64 * 4, "the matrix must have run in full");
        assert_eq!(
            seen,
            BTreeSet::from([None, Some(false), Some(true)]),
            "the matrix must reach every answer, or it checked nothing"
        );
    }
}
