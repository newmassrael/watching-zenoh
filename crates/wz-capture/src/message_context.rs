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
    /// OUTPUT and not to a literal this file wrote: every phase, every
    /// capability combination, as `fields_json` really emits them.
    #[test]
    fn it_reads_back_what_the_field_document_writes() {
        use wz_session_core::passive::{FlowContext, SessionPhase};

        let mut checked = 0usize;
        for phase in [
            SessionPhase::Unseen,
            SessionPhase::HalfInit,
            SessionPhase::InitComplete,
            SessionPhase::Established,
            SessionPhase::Closed,
        ] {
            for lowlatency in [false, true] {
                for compression in [false, true] {
                    for qos in [false, true] {
                        let context = FlowContext {
                            phase,
                            lowlatency,
                            compression,
                            qos,
                            patch: Some(1),
                            ..FlowContext::default()
                        };
                        let mut written = String::new();
                        crate::fields_json::push_context(&context, &mut written);
                        let object = written
                            .strip_prefix(",\"context\":")
                            .unwrap_or_else(|| panic!("the writer's shape moved: {written}"));
                        let expected = MessageContext {
                            lowlatency: context.negotiated().then_some(lowlatency),
                        };
                        assert_eq!(
                            read_flow_context(object),
                            Ok(expected),
                            "{phase:?} lowlatency={lowlatency}: {object}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 5 * 2 * 2 * 2, "the matrix must have run in full");
    }
}
