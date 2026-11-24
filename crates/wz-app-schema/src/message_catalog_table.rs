// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A message catalog as static tables, for an image that links its catalog instead of reading it.
//!
//! The generator (`scripts/lib/message_catalog.py`) turns a catalog document into one `const`
//! [`Table`] of these rows; a host reads the same document at run time with
//! `wz_app_frame::message_catalog::Catalog::parse`. The rows are the catalog's resolved form:
//! every reference a document makes by name (a node, a profile) is an index here, and every number
//! is the value it stands for. Nothing in this module allocates, so an image without an allocator
//! links the tables as they are.
//!
//! The rows judge nothing. A table is accepted when the catalog reader accepts it:
//! `wz_app_frame::message_catalog::Catalog::from_table` turns it back into a document and runs
//! every rule the reader runs on a text, and the generator writes that test beside each table it
//! emits. So a fixed-memory image and a host that read one catalog hold the same messages by the
//! same rules, and there is one implementation of the rules that depend on a profile.
//!
//! The protection profiles and the header values stay JSON text: the profile is the
//! `e2e_profile` document and is read where a sender or a receiver is made.

/// The bounds a catalog is read against: the limits of the same names, the messages as the runtime
/// lends them and the rest as the build states them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// How many messages one catalog declares (`MESSAGE_CATALOG_ENTRIES`).
    pub messages: usize,
    /// The deepest replay a message may keep (`REPLAY_DEPTH_MAX`).
    pub replay_depth_max: usize,
    /// How many senders one message may bind receiver slots to (`E2E_SENDER_SLOTS`).
    pub sender_slots: usize,
    /// How many fields one message's instance key names (`INSTANCE_KEY_FIELDS`).
    pub key_fields: usize,
    /// How many instances one message's instance key tells apart, the product of the lengths of
    /// its fields' lists of values (`INSTANCES_PER_MESSAGE`).
    pub instances: usize,
}

/// One node of the deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeRow {
    /// Its name, which the messages' publisher, subscriber and sender lists use.
    pub name: &'static str,
    /// The address the profile's derived fields are computed from, when the catalog states one.
    pub address: Option<u64>,
}

/// A named profile document, as JSON text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocumentRow {
    /// The name the messages refer to it by.
    pub name: &'static str,
    /// The document.
    pub text: &'static str,
}

/// How a message is protected end to end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectionRow {
    /// The index of its profile in [`Table::e2e_profiles`].
    pub profile: u16,
    /// The header values, as the values text of `e2e_frame::Values::parse`.
    pub values: &'static str,
}

/// A sender a receiver of the message binds a slot to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderRow {
    /// The index of the sending node in [`Table::nodes`].
    pub node: u16,
    /// The sender identity its frames' header carries.
    pub id: u64,
}

/// One value an instance-key field may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyValue {
    /// An integer or an enumeration's number.
    Number(u64),
    /// A string, or an enumeration's name.
    Text(&'static str),
}

/// One payload field of a message's instance key and the values it may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyFieldRow {
    /// The field, as the payload's schema names it.
    pub field: &'static str,
    /// The values it may take, in the order the instances are numbered by.
    pub values: &'static [KeyValue],
}

/// How the reception of a periodic message is supervised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisionRow {
    /// How many periods a stream may miss before it is lost.
    pub factor: u16,
    /// Whether a stream can be lost before its first reception.
    pub awaited: bool,
}

/// One message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageRow {
    /// The key expression it is published on.
    pub key_expr: &'static str,
    /// Its message id.
    pub id: u32,
    /// The indices of the nodes that publish it.
    pub publishers: &'static [u16],
    /// The indices of the nodes that subscribe to it.
    pub subscribers: &'static [u16],
    /// Its period; `None` for a message sent on an event.
    pub period_ms: Option<u32>,
    /// Its protection; `None` for a message sent as it is.
    pub protection: Option<ProtectionRow>,
    /// The senders a receiver binds its slots to; empty for one stream.
    pub senders: &'static [SenderRow],
    /// The fields of its instance key; empty for a message of one instance.
    pub instance_key: &'static [KeyFieldRow],
    /// How many of its last frames a publisher keeps; `None` for no replay.
    pub replay_depth: Option<u32>,
    /// Its supervision; `None` for a message whose reception is not supervised.
    pub supervision: Option<SupervisionRow>,
    /// The index of its segment profile in [`Table::segment_profiles`]; `None` when it is never cut.
    pub segment_profile: Option<u16>,
}

/// A whole catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Table {
    /// The nodes, in the catalog's order.
    pub nodes: &'static [NodeRow],
    /// The end-to-end protection profiles.
    pub e2e_profiles: &'static [DocumentRow],
    /// The segment profiles.
    pub segment_profiles: &'static [DocumentRow],
    /// The delay after the first poll that has a clock before any message is supervised.
    pub supervision_start_delay_ms: u32,
    /// The messages, in the catalog's order.
    pub messages: &'static [MessageRow],
}

#[cfg(test)]
mod tests {
    use super::{
        DocumentRow, KeyFieldRow, KeyValue, Limits, MessageRow, NodeRow, ProtectionRow, SenderRow,
        SupervisionRow, Table,
    };

    /// A catalog that uses every kind of row, as the generator writes one: a constant, which a
    /// row that held anything on the heap could not be.
    const CATALOG: Table = Table {
        nodes: &[
            NodeRow {
                name: "north",
                address: Some(0x7A100),
            },
            NodeRow {
                name: "south",
                address: None,
            },
        ],
        e2e_profiles: &[DocumentRow {
            name: "p",
            text: "{}",
        }],
        segment_profiles: &[DocumentRow {
            name: "s",
            text: "{}",
        }],
        supervision_start_delay_ms: 750,
        messages: &[MessageRow {
            key_expr: "demo/pose",
            id: 401,
            publishers: &[0],
            subscribers: &[1],
            period_ms: Some(40),
            protection: Some(ProtectionRow {
                profile: 0,
                values: "{}",
            }),
            senders: &[SenderRow { node: 0, id: 7 }],
            instance_key: &[KeyFieldRow {
                field: "side",
                values: &[KeyValue::Number(1), KeyValue::Text("left")],
            }],
            replay_depth: Some(6),
            supervision: Some(SupervisionRow {
                factor: 4,
                awaited: true,
            }),
            segment_profile: Some(0),
        }],
    };

    const LIMITS: Limits = Limits {
        messages: 1,
        replay_depth_max: 6,
        sender_slots: 1,
        key_fields: 1,
        instances: 2,
    };

    #[test]
    fn a_whole_catalog_is_a_constant_of_static_rows() {
        let message = &CATALOG.messages[0];
        assert_eq!(
            CATALOG.nodes[usize::from(message.publishers[0])].name,
            "north"
        );
        assert_eq!(
            CATALOG.nodes[usize::from(message.subscribers[0])].address,
            None
        );
        assert_eq!(message.instance_key[0].values.len(), LIMITS.instances);
        assert_eq!(message.replay_depth, Some(6));
        assert_eq!(CATALOG.messages.len(), LIMITS.messages);
    }
}
