// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A MESSAGE CATALOG: one declaration of the messages a deployment's nodes exchange, read and
//! judged once, from which the other application-frame pieces are made.
//!
//! # What a catalog states
//!
//! ```text
//! {
//!   nodes: [{name: 'north', address: '0x0007A100'}, {name: 'south'}],
//!   e2e_profiles: {'demo-a': { ...an e2e_profile document... }},
//!   segment_profiles: {'split-a': { ...a segment_profile document... }},
//!   supervision: {start_delay_ms: 750},
//!   messages: [
//!     {key_expr: 'demo/pose', id: 401, publishers: ['north'], subscribers: ['south'],
//!      period_ms: 40,
//!      protection: {profile: 'demo-a', values: {ident: {group: 21, msg: 300}}},
//!      supervision: {factor: 4, awaited: true}},
//!     {key_expr: 'demo/map', id: 402, publishers: ['south'], subscribers: ['north'],
//!      replay_depth: 6, segment_profile: 'split-a'},
//!   ],
//! }
//! ```
//!
//! Each message names the nodes that publish and subscribe to it; a node's address, when stated,
//! is what the profile's derived header fields of its frames are computed from. A message with a
//! period is periodic, one without is sent on an event. `protection` names an e2e profile and
//! gives the header values (every field but the CRC, the length and the counter). `senders` binds
//! a receiver's slots to the listed publishers' sender identities. `instance_key` names the
//! payload fields that tell instances apart and the values each may take, at most
//! `INSTANCE_KEY_FIELDS` fields making at most `INSTANCES_PER_MESSAGE` instances; it is carried
//! as data.
//! `replay_depth` is how many of its last frames a publisher keeps; `supervision` the factor of
//! the reception deadline, and the catalog's `supervision.start_delay_ms` the start delay every
//! supervisor of the deployment has. `segment_profile` names the profile a sample larger than a
//! frame is cut by.
//!
//! # One set of rules, two paths
//!
//! The shape (which members each object has, which are required, the type and range of each
//! value, the refusal each rule is named by) is stated once, in `deploy/message-catalog.schema.json`.
//! This reader is held to its members and refusal words by a unit test; the generator of a
//! fixed-memory image's tables (`scripts/lib/message_catalog.py`) interprets it, and both run the
//! one corpus of refused catalogs (`catalog/refusals.json5` of this crate). The rules that depend
//! on what a profile says (the profile documents themselves, whether the header values build a
//! frame for each node, whether the profile's message cell can carry the senders) are this
//! reader's alone: the generator's tables are read back through [`Catalog::from_table`], which
//! runs every rule of this module on them, in a test the generator writes beside the tables.
//!
//! Every refusal is named ([`RefusalKind`]) and carries a JSON pointer to the place.
//!
//! # Where the rules run
//!
//! The reading, the shape and every rule that relates one part of a catalog to another are
//! `wz_app_schema::catalog_plan`'s, run once, when a catalog is handed over, in the crate built for
//! size; the types it resolves a catalog into are re-exported here at the paths they had. The rules
//! that depend on a profile are this module's: the reader asks them at the place in the reading
//! where each is reported, so a catalog is refused for the same first reason as before the split,
//! and judging a protection makes the very senders and receivers [`Catalog::sender`] and
//! [`Catalog::receiver`] make.
//!
//! # What the catalog makes
//!
//! [`Catalog::sender`], [`Catalog::receiver`] and [`Catalog::supervision_rows`] make, for one
//! message and one node, the sender, the receiving judge and the rows a reception supervisor is
//! given: the same values a program would hand those pieces by hand, read from the catalog.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use wz_app_schema::catalog_plan::{read_catalog, CatalogJudge, CatalogPlan, ProtectionRefusal};
use wz_session_core::json5::Json5Value;

use crate::e2e_frame::Values;
use crate::e2e_profile::{read_json, DocError, Pointer, Profile};
use crate::e2e_receiver::{Keying, NewError, Receiver};
use crate::e2e_stream_sender::{SendError, SenderOptions, StreamSender};
use crate::message_catalog_table::{
    DocumentRow, KeyValue as KeyValueRow, Limits, MessageRow, Table,
};
use crate::segment_profile::SegmentProfile;

pub use wz_app_schema::catalog_plan::{
    Document, KeyField, KeyValue, Message, Node, Protection, Refusal, RefusalKind, Sender,
    Supervision, MAX_CATALOG_JSON_DEPTH, MAX_DEADLINE_MS, MAX_NUMBERED, MAX_START_DELAY_MS, SHAPES,
};

/// One row a reception supervisor is given for a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamRow {
    /// The message's period.
    pub period_ms: u32,
    /// The periods a stream may miss.
    pub factor: u16,
    /// The sending node of the stream, as the number the supervisor marks absent and present: the
    /// node's index in the catalog.
    pub sender: u32,
    /// Whether the stream can be lost before its first reception.
    pub awaited: bool,
}

/// Why a piece could not be made from a catalog entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandleError {
    /// A message the catalog does not have.
    NoSuchMessage,
    /// A node the catalog does not have.
    NoSuchNode,
    /// The node does not publish the message.
    NotPublisher,
    /// The node does not subscribe to the message.
    NotSubscriber,
    /// The message is not protected.
    Unprotected,
    /// The message's reception is not supervised.
    NotSupervised,
    /// The profile or the values, which the catalog accepted, refused again.
    Document(DocError),
    /// The sender refused its values.
    Sender(SendError),
    /// The receiver refused its values or keying.
    Receiver(NewError),
}

impl core::fmt::Display for HandleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoSuchMessage => f.write_str("the catalog has no such message"),
            Self::NoSuchNode => f.write_str("the catalog has no such node"),
            Self::NotPublisher => f.write_str("the node does not publish the message"),
            Self::NotSubscriber => f.write_str("the node does not subscribe to the message"),
            Self::Unprotected => f.write_str("the message is not protected"),
            Self::NotSupervised => f.write_str("the message's reception is not supervised"),
            Self::Document(e) => write!(f, "{e}"),
            Self::Sender(e) => write!(f, "{e}"),
            Self::Receiver(e) => write!(f, "{e}"),
        }
    }
}

/// A catalog read and judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalog {
    plan: CatalogPlan,
}

/// The header values of a protected message for one node: the node's address in place of an
/// `@address` the values do not state.
fn values_for(tree: &Json5Value, node: &Node) -> Result<Values, DocError> {
    let values = Values::from_tree(tree, &[])?;
    Ok(match (values.stated_address(), node.address) {
        (None, Some(address)) => values.address(address),
        _ => values,
    })
}

/// How a receiver of `message` keeps its streams: one per listed sender, else one.
fn keying(message: &Message) -> Keying {
    if message.senders.is_empty() {
        Keying::Indexed { streams: 1 }
    } else {
        Keying::Senders {
            slots: message.senders.len(),
            bound: Some(message.senders.iter().map(|s| s.id).collect()),
        }
    }
}

/// The rules of a catalog that depend on what a profile says, which the catalog's reader asks:
/// each profile read by its reader, and a protected message's sender made for every node that
/// publishes it and its receiver for every node that subscribes to it.
struct Judge;

/// The header values refused for `node`.
fn refused_for(node: &Node, error: &dyn core::fmt::Display) -> ProtectionRefusal {
    ProtectionRefusal::Values(format!("for `{}`: {error}", node.name))
}

impl CatalogJudge for Judge {
    fn e2e_profile(&self, tree: &Json5Value) -> Result<(), String> {
        Profile::from_tree(tree)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn segment_profile(&self, tree: &Json5Value) -> Result<(), String> {
        SegmentProfile::from_tree(tree)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn protection(
        &self,
        profile: &Json5Value,
        message: &Message,
        nodes: &[Node],
        sender_slots: usize,
    ) -> Result<(), ProtectionRefusal> {
        let Some(protection) = &message.protection else {
            return Ok(());
        };
        let profile =
            Profile::from_tree(profile).map_err(|e| ProtectionRefusal::Profile(e.to_string()))?;
        for &node in &message.publishers {
            let node = &nodes[node];
            let values = values_for(&protection.values, node).map_err(|e| refused_for(node, &e))?;
            StreamSender::new(profile.clone(), values, SenderOptions::default())
                .map_err(|e| refused_for(node, &e))?;
        }
        // A message no node subscribes to is still judged as a receiver would judge it: one with
        // no address of its own.
        let no_address = Node {
            name: String::new(),
            address: None,
        };
        let subscribers = message.subscribers.iter().map(|&n| &nodes[n]);
        let unsubscribed = message.subscribers.is_empty().then_some(&no_address);
        for node in subscribers.chain(unsubscribed) {
            let values = values_for(&protection.values, node).map_err(|e| refused_for(node, &e))?;
            match Receiver::new(
                profile.clone(),
                &values,
                keying(message),
                None,
                sender_slots,
            ) {
                Ok(_) => {}
                Err(NewError::NoSenderInCell | NewError::BadBoundList) => {
                    return Err(ProtectionRefusal::SendersUnsupported);
                }
                Err(e) => return Err(refused_for(node, &e)),
            }
        }
        Ok(())
    }
}

impl Catalog {
    /// Read and judge a catalog from its JSON5 text.
    pub fn parse(text: &str, limits: Limits) -> Result<Self, Refusal> {
        Self::from_tree(&read_catalog(text)?, limits)
    }

    /// Judge a catalog document already read.
    pub fn from_tree(root: &Json5Value, limits: Limits) -> Result<Self, Refusal> {
        CatalogPlan::read(root, limits, &Judge).map(|plan| Self { plan })
    }

    /// Judge a generator's tables: the table turned back into a catalog document and read by
    /// every rule [`Catalog::from_tree`] runs.
    pub fn from_table(table: &Table, limits: Limits) -> Result<Self, Refusal> {
        Self::from_tree(&table_document(table)?, limits)
    }

    /// The nodes, in the catalog's order.
    pub fn nodes(&self) -> &[Node] {
        self.plan.nodes()
    }

    /// The index of the node called `name`.
    pub fn node_index(&self, name: &str) -> Option<usize> {
        self.nodes().iter().position(|n| n.name == name)
    }

    /// The e2e profiles.
    pub fn e2e_profiles(&self) -> &[Document] {
        self.plan.e2e_profiles()
    }

    /// The segment profiles.
    pub fn segment_profiles(&self) -> &[Document] {
        self.plan.segment_profiles()
    }

    /// The start delay every supervisor of the deployment has; 0 when the catalog states none.
    pub fn supervision_start_delay_ms(&self) -> u32 {
        self.plan.supervision_start_delay_ms()
    }

    /// The messages, in the catalog's order.
    pub fn messages(&self) -> &[Message] {
        self.plan.messages()
    }

    /// The index of the message put on `key_expr`.
    pub fn find_key_expr(&self, key_expr: &str) -> Option<usize> {
        self.messages().iter().position(|m| m.key_expr == key_expr)
    }

    /// The index of the message of `id`.
    pub fn find_id(&self, id: u32) -> Option<usize> {
        self.messages().iter().position(|m| m.id == id)
    }

    /// The e2e profile at `index`, read.
    pub fn e2e_profile(&self, index: usize) -> Result<Profile, DocError> {
        match self.e2e_profiles().get(index) {
            Some(document) => Profile::from_tree(&document.tree),
            None => Err(DocError::invalid("", "the catalog has no such e2e profile")),
        }
    }

    /// The segment profile at `index`, read.
    pub fn segment_profile(&self, index: usize) -> Result<SegmentProfile, DocError> {
        match self.segment_profiles().get(index) {
            Some(document) => SegmentProfile::from_tree(&document.tree),
            None => Err(DocError::invalid(
                "",
                "the catalog has no such segment profile",
            )),
        }
    }

    fn entry(&self, message: usize, node: usize) -> Result<(&Message, &Node), HandleError> {
        let message = self
            .messages()
            .get(message)
            .ok_or(HandleError::NoSuchMessage)?;
        let node = self.nodes().get(node).ok_or(HandleError::NoSuchNode)?;
        Ok((message, node))
    }

    /// The protection of `message` as `node` sends or receives it: the profile and the values.
    fn protected(&self, message: &Message, node: &Node) -> Result<(Profile, Values), HandleError> {
        let protection = message
            .protection
            .as_ref()
            .ok_or(HandleError::Unprotected)?;
        let profile = self
            .e2e_profile(protection.profile)
            .map_err(HandleError::Document)?;
        let values = values_for(&protection.values, node).map_err(HandleError::Document)?;
        Ok((profile, values))
    }

    /// The sender `node` protects `message` with, made as `options` says.
    pub fn sender(
        &self,
        message: usize,
        node: usize,
        options: SenderOptions,
    ) -> Result<StreamSender, HandleError> {
        let (entry, of) = self.entry(message, node)?;
        if !entry.publishers.contains(&node) {
            return Err(HandleError::NotPublisher);
        }
        let (profile, values) = self.protected(entry, of)?;
        StreamSender::new(profile, values, options).map_err(HandleError::Sender)
    }

    /// The receiving judge `node` judges `message` with: one slot per listed sender, bound to its
    /// identity, else one stream. `slot_limit` is the most sender slots the build allows.
    pub fn receiver(
        &self,
        message: usize,
        node: usize,
        slot_limit: usize,
    ) -> Result<Receiver, HandleError> {
        let (entry, of) = self.entry(message, node)?;
        if !entry.subscribers.contains(&node) {
            return Err(HandleError::NotSubscriber);
        }
        let (profile, values) = self.protected(entry, of)?;
        Receiver::new(profile, &values, keying(entry), None, slot_limit)
            .map_err(HandleError::Receiver)
    }

    /// The rows a reception supervisor of `node` is given for `message`, in the order of the
    /// receiver's slots: one per listed sender, else one for the stream, whose sender is the
    /// message's first publisher.
    pub fn supervision_rows(
        &self,
        message: usize,
        node: usize,
    ) -> Result<Vec<StreamRow>, HandleError> {
        let (entry, _) = self.entry(message, node)?;
        if !entry.subscribers.contains(&node) {
            return Err(HandleError::NotSubscriber);
        }
        let (Some(supervision), Some(period_ms)) = (entry.supervision, entry.period_ms) else {
            return Err(HandleError::NotSupervised);
        };
        let row = |sender: usize| StreamRow {
            period_ms,
            factor: supervision.factor,
            // A node's index is below `MAX_NUMBERED`, which the catalog holds to 16 bits.
            sender: sender as u32,
            awaited: supervision.awaited,
        };
        Ok(if entry.senders.is_empty() {
            alloc::vec![row(entry.publishers[0])]
        } else {
            entry.senders.iter().map(|s| row(s.node)).collect()
        })
    }
}

fn number(value: impl Into<u64>) -> Json5Value {
    Json5Value::Number(value.into().to_string())
}

fn text(value: &str) -> Json5Value {
    Json5Value::String(String::from(value))
}

fn member(key: &str, value: Json5Value) -> (String, Json5Value) {
    (String::from(key), value)
}

/// A table's document of profiles: each read from its text.
fn table_documents(
    rows: &[DocumentRow],
    at: &Pointer<'_>,
    invalid: RefusalKind,
) -> Result<Json5Value, Refusal> {
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let tree = read_json(row.text)
            .map_err(|e| Refusal::new(invalid, &at.key(row.name), e.to_string()))?;
        entries.push(member(row.name, tree));
    }
    Ok(Json5Value::Object(entries))
}

/// The names of the nodes a table's list numbers.
fn table_nodes(table: &Table, list: &[u16], at: &Pointer<'_>) -> Result<Json5Value, Refusal> {
    let mut out = Vec::with_capacity(list.len());
    for (j, &index) in list.iter().enumerate() {
        let Some(node) = table.nodes.get(usize::from(index)) else {
            return Err(Refusal::new(
                RefusalKind::UnknownNode,
                &at.index(j),
                format!("the table has no node {index}"),
            ));
        };
        out.push(text(node.name));
    }
    Ok(Json5Value::Array(out))
}

/// A generator's table as the catalog document it was generated from, up to spelling: the
/// numbers in decimal and every member a row holds a value for.
fn table_document(table: &Table) -> Result<Json5Value, Refusal> {
    let mut root = Vec::new();
    let nodes = table
        .nodes
        .iter()
        .map(|node| {
            let mut entries = alloc::vec![member("name", text(node.name))];
            if let Some(address) = node.address {
                entries.push(member("address", number(address)));
            }
            Json5Value::Object(entries)
        })
        .collect();
    root.push(member("nodes", Json5Value::Array(nodes)));
    if !table.e2e_profiles.is_empty() {
        root.push(member(
            "e2e_profiles",
            table_documents(
                table.e2e_profiles,
                &Pointer::text("/e2e_profiles"),
                RefusalKind::E2eProfileInvalid,
            )?,
        ));
    }
    if !table.segment_profiles.is_empty() {
        root.push(member(
            "segment_profiles",
            table_documents(
                table.segment_profiles,
                &Pointer::text("/segment_profiles"),
                RefusalKind::SegmentProfileInvalid,
            )?,
        ));
    }
    if table.supervision_start_delay_ms != 0 {
        root.push(member(
            "supervision",
            Json5Value::Object(alloc::vec![member(
                "start_delay_ms",
                number(table.supervision_start_delay_ms)
            )]),
        ));
    }
    let messages_at = Pointer::text("/messages");
    let mut messages = Vec::with_capacity(table.messages.len());
    for (i, row) in table.messages.iter().enumerate() {
        messages.push(table_message(table, row, &messages_at.index(i))?);
    }
    root.push(member("messages", Json5Value::Array(messages)));
    Ok(Json5Value::Object(root))
}

fn table_message(table: &Table, row: &MessageRow, at: &Pointer<'_>) -> Result<Json5Value, Refusal> {
    let mut entries = alloc::vec![
        member("key_expr", text(row.key_expr)),
        member("id", number(row.id)),
        member(
            "publishers",
            table_nodes(table, row.publishers, &at.key("publishers"))?
        ),
        member(
            "subscribers",
            table_nodes(table, row.subscribers, &at.key("subscribers"))?
        ),
    ];
    if let Some(period) = row.period_ms {
        entries.push(member("period_ms", number(period)));
    }
    if let Some(protection) = row.protection {
        let here = at.key("protection");
        let Some(profile) = table.e2e_profiles.get(usize::from(protection.profile)) else {
            return Err(Refusal::new(
                RefusalKind::UnknownE2eProfile,
                &here.key("profile"),
                format!("the table has no e2e profile {}", protection.profile),
            ));
        };
        let values = read_json(protection.values).map_err(|e| {
            Refusal::new(
                RefusalKind::ValuesInvalid,
                &here.key("values"),
                e.to_string(),
            )
        })?;
        entries.push(member(
            "protection",
            Json5Value::Object(alloc::vec![
                member("profile", text(profile.name)),
                member("values", values),
            ]),
        ));
    }
    if !row.senders.is_empty() {
        let here = at.key("senders");
        let mut senders = Vec::with_capacity(row.senders.len());
        for (j, sender) in row.senders.iter().enumerate() {
            let Some(node) = table.nodes.get(usize::from(sender.node)) else {
                let item = here.index(j);
                return Err(Refusal::new(
                    RefusalKind::UnknownNode,
                    &item.key("node"),
                    format!("the table has no node {}", sender.node),
                ));
            };
            senders.push(Json5Value::Object(alloc::vec![
                member("node", text(node.name)),
                member("id", number(sender.id)),
            ]));
        }
        entries.push(member("senders", Json5Value::Array(senders)));
    }
    if !row.instance_key.is_empty() {
        let fields = row
            .instance_key
            .iter()
            .map(|field| {
                let values = field
                    .values
                    .iter()
                    .map(|value| match value {
                        KeyValueRow::Number(n) => number(*n),
                        KeyValueRow::Text(t) => text(t),
                    })
                    .collect();
                Json5Value::Object(alloc::vec![
                    member("field", text(field.field)),
                    member("values", Json5Value::Array(values)),
                ])
            })
            .collect();
        entries.push(member("instance_key", Json5Value::Array(fields)));
    }
    if let Some(depth) = row.replay_depth {
        entries.push(member("replay_depth", number(depth)));
    }
    if let Some(supervision) = row.supervision {
        entries.push(member(
            "supervision",
            Json5Value::Object(alloc::vec![
                member("factor", number(supervision.factor)),
                member("awaited", Json5Value::Bool(supervision.awaited)),
            ]),
        ));
    }
    if let Some(index) = row.segment_profile {
        let Some(profile) = table.segment_profiles.get(usize::from(index)) else {
            return Err(Refusal::new(
                RefusalKind::UnknownSegmentProfile,
                &at.key("segment_profile"),
                format!("the table has no segment profile {index}"),
            ));
        };
        entries.push(member("segment_profile", text(profile.name)));
    }
    Ok(Json5Value::Object(entries))
}

/// The bounds of a runtime that states nothing: the messages its `MESSAGE_CATALOG_ENTRIES` lends a
/// catalog at the build's value, and the rest as [`limits_with_messages`] reads them.
pub fn build_limits() -> Limits {
    limits_with_messages(
        wz_session_core::process_limits::ProcessRows::BUILD.message_catalog_entries,
    )
}

/// The bounds a catalog is read against: `messages`, the messages the runtime's
/// `MESSAGE_CATALOG_ENTRIES` lends one catalog under the build's value
/// (`wz_session_core::process_limits::ProcessRows`), and this build's `REPLAY_DEPTH_MAX`,
/// `E2E_SENDER_SLOTS`, `INSTANCE_KEY_FIELDS` and `INSTANCES_PER_MESSAGE`.
pub fn limits_with_messages(messages: usize) -> Limits {
    Limits {
        messages,
        replay_depth_max: wz_session_core::caps::REPLAY_DEPTH_MAX,
        sender_slots: wz_session_core::caps::E2E_SENDER_SLOTS,
        key_fields: wz_session_core::caps::INSTANCE_KEY_FIELDS,
        instances: wz_session_core::caps::INSTANCES_PER_MESSAGE,
    }
}
