// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Facts a row's field tree holds that its row now says without the tree.
//!
//! # Why the row says them
//!
//! The `row_facts` document is the field document without its trees, for a
//! reader that lists rows and walks a tree only for the one it picks. Such a
//! reader still needed five things it could only read off a tree: a `Frame` or
//! `Fragment` row's transport header (its `sn`, `r` and `m`), the id a
//! declaration declares, the extensions the walker names no extension for, a
//! sample's timestamp and which payload node a `payload` slot spans. Each is
//! read here from the tree, by the tree's own shape, so the row and the tree
//! cannot disagree: these functions are the only reader, and the field
//! document's row keys are written from what they answer.

use alloc::vec::Vec;

use wz_session_core::dissect::{Field, FieldValue, MessageName};

/// A `Frame` or `Fragment` row's transport header, as its tree holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportHeader {
    /// The header's sequence number.
    pub sn: u64,
    /// The `R` flag: the message went on the reliable channel.
    pub reliable: bool,
    /// The `M` flag of a `Fragment`: more fragments follow. `None` on a
    /// `Frame`, which has no such flag.
    pub more: Option<bool>,
}

/// A direct child of `field` by name.
fn child<'a>(field: &'a Field, name: &str) -> Option<&'a Field> {
    match &field.value {
        FieldValue::Nested(children) => children.iter().find(|c| c.name == name),
        _ => None,
    }
}

fn flag_of(field: &Field, name: &str) -> Option<bool> {
    match child(field, name)?.value {
        FieldValue::Flag(set) => Some(set),
        _ => None,
    }
}

fn uint_of(field: &Field, name: &str) -> Option<u64> {
    match child(field, name)?.value {
        FieldValue::Uint(value) => Some(value),
        _ => None,
    }
}

/// The transport header of a row whose message is a `Frame` or a `Fragment`,
/// and `None` for any other message: no other transport message carries a
/// sequence number in its header.
///
/// `more` is `Some` exactly on a `Fragment`, because only its header has the
/// flag; a `Frame` with the bit set has it reserved, and the walker records no
/// `m` there.
pub fn transport_header(row: &Field) -> Option<TransportHeader> {
    let fragment = row.name == MessageName::Fragment.name();
    if !fragment && row.name != MessageName::Frame.name() {
        return None;
    }
    Some(TransportHeader {
        sn: uint_of(row, "sn")?,
        reliable: flag_of(row, "r")?,
        more: if fragment {
            Some(flag_of(row, "m")?)
        } else {
            None
        },
    })
}

/// The ids of every extension in `row`'s tree that the walker names no
/// extension for, in walk order: the transport header's chain, every network
/// message's and every body's.
///
/// An extension is one `ext` node; it carries `ext_name` when the walker knows
/// the id in the chain it was read from, and not otherwise. A tree is walked
/// once and each node is one extension, so no id is listed twice for the same
/// extension; two extensions with the same id are listed twice.
pub fn unnamed_extensions(row: &Field) -> Vec<u64> {
    let mut ids = Vec::new();
    collect_unnamed(row, &mut ids);
    ids
}

fn collect_unnamed(field: &Field, ids: &mut Vec<u64>) {
    let FieldValue::Nested(children) = &field.value else {
        return;
    };
    if field.name == "ext" && child(field, "ext_name").is_none() {
        if let Some(FieldValue::Bits(id)) = child(field, "ext_id").map(|f| &f.value) {
            ids.push(*id);
        }
    }
    for c in children {
        collect_unnamed(c, ids);
    }
}

/// The id a declaration declares: the `id` of a message's body that holds both
/// an `id` and a `keyexpr` (`DeclareKeyExpr`, `DeclareSubscriber`,
/// `DeclareQueryable`, `DeclareToken`). `None` for every other body, an
/// undeclaration among them: it names an id it does not declare.
pub fn declared_id(message: &Field) -> Option<u64> {
    let body = message.body_field()?;
    child(body, "keyexpr")?;
    uint_of(body, "id")
}

/// The NTP64 time of the timestamp a message's body carries: the `time` of the
/// first `timestamp` under the body that is not inside an extension chain.
/// That is the sample's own timestamp on a `Put` or a `Del`, including the one
/// a `Reply` nests; an extension's timestamp (a query's, a network message's)
/// is another fact and is not this one. `None` when the body carries none.
pub fn body_timestamp(message: &Field) -> Option<u64> {
    find_body_timestamp(message.body_field()?)
}

fn find_body_timestamp(field: &Field) -> Option<u64> {
    let FieldValue::Nested(children) = &field.value else {
        return None;
    };
    if field.name == "timestamp" {
        return uint_of(field, "time");
    }
    children
        .iter()
        .filter(|c| c.name != "extensions")
        .find_map(find_body_timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use wz_session_core::dissect::Span;

    fn node(name: &'static str, value: FieldValue) -> Field {
        Field {
            name: name.into(),
            span: Span { start: 0, end: 1 },
            value,
        }
    }

    fn nested(name: &'static str, children: Vec<Field>) -> Field {
        node(name, FieldValue::Nested(children))
    }

    fn ext(id: u64, named: bool) -> Field {
        let mut fields = vec![node("ext_id", FieldValue::Bits(id))];
        if named {
            fields.push(node("ext_name", FieldValue::Label("qos".into())));
        }
        nested("ext", fields)
    }

    /// Only an extension with no `ext_name` is listed, at any depth, in walk
    /// order, once each.
    #[test]
    fn the_unnamed_extensions_are_the_ones_without_a_name_in_walk_order() {
        let row = nested(
            "Frame",
            vec![
                nested("extensions", vec![ext(1, true), ext(0x0B, false)]),
                nested(
                    "payload",
                    vec![nested(
                        "Push",
                        vec![nested("extensions", vec![ext(0x0C, false), ext(2, true)])],
                    )],
                ),
            ],
        );
        assert_eq!(unnamed_extensions(&row), [0x0B, 0x0C]);
        assert!(unnamed_extensions(&nested("KeepAlive", vec![])).is_empty());
    }

    /// A `Frame`'s header has no `M` flag; a `Fragment`'s does; no other
    /// message has a transport header.
    #[test]
    fn a_frame_has_no_more_flag_and_a_fragment_has_one() {
        let header = |name: &'static str, m: Option<bool>| {
            let mut fields = vec![
                node("r", FieldValue::Flag(true)),
                node("sn", FieldValue::Uint(u64::MAX)),
            ];
            if let Some(m) = m {
                fields.push(node("m", FieldValue::Flag(m)));
            }
            nested(name, fields)
        };
        let frame = transport_header(&header("Frame", None)).expect("a Frame");
        assert_eq!(
            frame,
            TransportHeader {
                sn: u64::MAX,
                reliable: true,
                more: None
            }
        );
        let fragment = transport_header(&header("Fragment", Some(true))).expect("a Fragment");
        assert_eq!(fragment.more, Some(true));
        assert_eq!(transport_header(&header("Join", None)), None);
    }

    /// A declaration declares its id; an undeclaration names one and declares
    /// nothing; a sample's timestamp is its body's, not an extension's.
    #[test]
    fn a_declaration_declares_its_id_and_a_body_states_its_own_timestamp() {
        let mid = || node("mid", FieldValue::Bits(2));
        let declare = nested(
            "Declare",
            vec![nested(
                "DeclareSubscriber",
                vec![
                    mid(),
                    node("id", FieldValue::Uint(7)),
                    nested("keyexpr", vec![]),
                ],
            )],
        );
        assert_eq!(declared_id(&declare), Some(7));
        let undeclare = nested(
            "Declare",
            vec![nested(
                "UndeclareSubscriber",
                vec![mid(), node("id", FieldValue::Uint(7))],
            )],
        );
        assert_eq!(declared_id(&undeclare), None);
        let stamp = |t| nested("timestamp", vec![node("time", FieldValue::Uint(t))]);
        let reply = nested(
            "Response",
            vec![nested(
                "Reply",
                vec![
                    mid(),
                    nested("extensions", vec![stamp(1)]),
                    nested("Put", vec![mid(), stamp(9)]),
                ],
            )],
        );
        assert_eq!(body_timestamp(&reply), Some(9));
        let unstamped = nested(
            "Push",
            vec![
                nested("extensions", vec![stamp(1)]),
                nested("Put", vec![mid()]),
            ],
        );
        assert_eq!(body_timestamp(&unstamped), None);
    }
}
