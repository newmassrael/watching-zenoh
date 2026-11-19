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
//! payload fields that tell instances apart and the values each may take; it is carried as data.
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
//! # What the catalog makes
//!
//! [`Catalog::sender`], [`Catalog::receiver`] and [`Catalog::supervision_rows`] make, for one
//! message and one node, the sender, the receiving judge and the rows a reception supervisor is
//! given: the same values a program would hand those pieces by hand, read from the catalog.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use wz_session_core::json5::{self, Json5Value};
use wz_session_core::json5_lex::{Json5Error, Lexer};
use wz_session_core::keyexpr_canon::validate_keyexpr;

use crate::e2e_frame::Values;
use crate::e2e_profile::{at, child, describe, read_json, DocError, Profile, MAX_JSON_DEPTH};
use crate::e2e_receiver::{Keying, NewError, Receiver};
use crate::e2e_stream_sender::{SendError, SenderOptions, StreamSender};
use crate::message_catalog_table::{KeyValue as KeyValueRow, Limits, MessageRow, Table};
use crate::segment_profile::SegmentProfile;

/// Deepest nesting a catalog may have: a profile document's own depth, under the catalog and its
/// `e2e_profiles` object.
pub const MAX_CATALOG_JSON_DEPTH: usize = MAX_JSON_DEPTH + 2;

/// The longest deadline a supervisor holds, in milliseconds: a period times its factor above this
/// is refused, as the reception supervisor refuses it.
pub const MAX_DEADLINE_MS: u64 = 2_147_483_646;

/// The longest start delay a supervisor holds, in milliseconds.
pub const MAX_START_DELAY_MS: u64 = 2_147_483_647;

/// How many nodes, or profiles of one kind, a catalog numbers: a table names each by a `u16`.
pub const MAX_NUMBERED: usize = u16::MAX as usize;

/// Why a catalog was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    /// The text is not JSON5, or nests deeper than [`MAX_CATALOG_JSON_DEPTH`].
    Syntax,
    /// An object member the catalog does not have.
    UnknownField,
    /// An object member stated twice.
    DuplicateField,
    /// A required member absent.
    MissingField,
    /// A value of another type than its member's, or an unsigned integer in another spelling.
    WrongType,
    /// A number outside its member's range, or more of something than a table numbers.
    ValueOutOfRange,
    /// A name with a character a name has not, empty, or longer than 64 bytes.
    InvalidName,
    /// An empty list or text where one is required.
    Empty,
    /// A node named twice, in the nodes or in one list of a message.
    DuplicateNode,
    /// A node name no node has.
    UnknownNode,
    /// A key expression that is not a literal key.
    KeyExpr,
    /// Two messages on one key expression.
    DuplicateKeyExpr,
    /// Two messages of one id.
    DuplicateId,
    /// A period of 0.
    PeriodZero,
    /// A period times its supervision factor above [`MAX_DEADLINE_MS`].
    DeadlineOutOfRange,
    /// A supervised message that states no period.
    SupervisionWithoutPeriod,
    /// A replay depth of 0 or above the build's `REPLAY_DEPTH_MAX`.
    ReplayDepthOutOfRange,
    /// More messages than the build's `MESSAGE_CATALOG_ENTRIES`.
    TooManyMessages,
    /// A protection that names no e2e profile of the catalog.
    UnknownE2eProfile,
    /// A segment profile reference that names no segment profile of the catalog.
    UnknownSegmentProfile,
    /// Senders on a message that is not protected.
    SendersWithoutProtection,
    /// A sender that is not a publisher of its message.
    SenderNotPublisher,
    /// A sender node or identity stated twice for one message.
    DuplicateSender,
    /// More senders than the build's `E2E_SENDER_SLOTS`.
    TooManySenders,
    /// An instance key and senders on one message.
    InstanceKeyWithSenders,
    /// A field of an instance key, or a value of one field, stated twice.
    DuplicateInstanceKey,
    /// An e2e profile the profile reader refuses.
    E2eProfileInvalid,
    /// A segment profile the segment profile reader refuses.
    SegmentProfileInvalid,
    /// Header values the profile refuses for a node that publishes or subscribes to the message.
    ValuesInvalid,
    /// Senders under a profile whose message cell names no sender, or an identity its sender part
    /// cannot hold.
    SendersUnsupportedByProfile,
}

impl RefusalKind {
    /// Every refusal, in the order of the schema's `x-wz-refusals`.
    pub const ALL: [Self; 30] = [
        Self::Syntax,
        Self::UnknownField,
        Self::DuplicateField,
        Self::MissingField,
        Self::WrongType,
        Self::ValueOutOfRange,
        Self::InvalidName,
        Self::Empty,
        Self::DuplicateNode,
        Self::UnknownNode,
        Self::KeyExpr,
        Self::DuplicateKeyExpr,
        Self::DuplicateId,
        Self::PeriodZero,
        Self::DeadlineOutOfRange,
        Self::SupervisionWithoutPeriod,
        Self::ReplayDepthOutOfRange,
        Self::TooManyMessages,
        Self::UnknownE2eProfile,
        Self::UnknownSegmentProfile,
        Self::SendersWithoutProtection,
        Self::SenderNotPublisher,
        Self::DuplicateSender,
        Self::TooManySenders,
        Self::InstanceKeyWithSenders,
        Self::DuplicateInstanceKey,
        Self::E2eProfileInvalid,
        Self::SegmentProfileInvalid,
        Self::ValuesInvalid,
        Self::SendersUnsupportedByProfile,
    ];

    /// The word a machine reads, the schema's and the generator's: snake case, one per refusal.
    pub const fn word(self) -> &'static str {
        match self {
            Self::Syntax => "syntax",
            Self::UnknownField => "unknown_field",
            Self::DuplicateField => "duplicate_field",
            Self::MissingField => "missing_field",
            Self::WrongType => "wrong_type",
            Self::ValueOutOfRange => "value_out_of_range",
            Self::InvalidName => "invalid_name",
            Self::Empty => "empty",
            Self::DuplicateNode => "duplicate_node",
            Self::UnknownNode => "unknown_node",
            Self::KeyExpr => "key_expr",
            Self::DuplicateKeyExpr => "duplicate_key_expr",
            Self::DuplicateId => "duplicate_id",
            Self::PeriodZero => "period_zero",
            Self::DeadlineOutOfRange => "deadline_out_of_range",
            Self::SupervisionWithoutPeriod => "supervision_without_period",
            Self::ReplayDepthOutOfRange => "replay_depth_out_of_range",
            Self::TooManyMessages => "too_many_messages",
            Self::UnknownE2eProfile => "unknown_e2e_profile",
            Self::UnknownSegmentProfile => "unknown_segment_profile",
            Self::SendersWithoutProtection => "senders_without_protection",
            Self::SenderNotPublisher => "sender_not_publisher",
            Self::DuplicateSender => "duplicate_sender",
            Self::TooManySenders => "too_many_senders",
            Self::InstanceKeyWithSenders => "instance_key_with_senders",
            Self::DuplicateInstanceKey => "duplicate_instance_key",
            Self::E2eProfileInvalid => "e2e_profile_invalid",
            Self::SegmentProfileInvalid => "segment_profile_invalid",
            Self::ValuesInvalid => "values_invalid",
            Self::SendersUnsupportedByProfile => "senders_unsupported_by_profile",
        }
    }
}

/// A refused catalog: the rule, where, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The rule.
    pub kind: RefusalKind,
    /// An RFC 6901 JSON pointer to the place: empty for the document itself.
    pub path: String,
    /// The reason, as a sentence.
    pub reason: String,
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.path.is_empty() {
            write!(f, "{}: {}", self.kind.word(), self.reason)
        } else {
            write!(f, "{} at {}: {}", self.kind.word(), self.path, self.reason)
        }
    }
}

fn refuse(kind: RefusalKind, path: &str, reason: impl Into<String>) -> Refusal {
    Refusal {
        kind,
        path: String::from(path),
        reason: reason.into(),
    }
}

/// The members of each object the catalog reads, and those required, by the schema's `$defs`
/// name. The schema's own lists are held equal to these by a unit test.
pub const SHAPES: [(&str, &[&str], &[&str]); 8] = [
    (
        "catalog",
        &[
            "nodes",
            "e2e_profiles",
            "segment_profiles",
            "supervision",
            "messages",
        ],
        &["nodes", "messages"],
    ),
    ("node", &["name", "address"], &["name"]),
    (
        "catalog_supervision",
        &["start_delay_ms"],
        &["start_delay_ms"],
    ),
    (
        "message",
        &[
            "key_expr",
            "id",
            "publishers",
            "subscribers",
            "period_ms",
            "protection",
            "senders",
            "instance_key",
            "replay_depth",
            "supervision",
            "segment_profile",
        ],
        &["key_expr", "id", "publishers", "subscribers"],
    ),
    ("protection", &["profile", "values"], &["profile", "values"]),
    ("sender", &["node", "id"], &["node", "id"]),
    ("key_field", &["field", "values"], &["field", "values"]),
    ("message_supervision", &["factor", "awaited"], &["factor"]),
];

/// The members and the required members of the object `def` of [`SHAPES`].
fn shape(def: &str) -> (&'static [&'static str], &'static [&'static str]) {
    SHAPES
        .iter()
        .find(|(name, _, _)| *name == def)
        .map(|(_, members, required)| (*members, *required))
        .unwrap_or((&[], &[]))
}

type Entries = [(String, Json5Value)];

fn object<'a>(value: &'a Json5Value, path: &str) -> Result<&'a Entries, Refusal> {
    match value {
        Json5Value::Object(entries) => Ok(entries),
        other => Err(refuse(
            RefusalKind::WrongType,
            path,
            format!("expected an object, found {}", describe(other)),
        )),
    }
}

fn array<'a>(value: &'a Json5Value, path: &str) -> Result<&'a [Json5Value], Refusal> {
    match value {
        Json5Value::Array(items) => Ok(items),
        other => Err(refuse(
            RefusalKind::WrongType,
            path,
            format!("expected an array, found {}", describe(other)),
        )),
    }
}

fn string<'a>(value: &'a Json5Value, path: &str) -> Result<&'a str, Refusal> {
    match value {
        Json5Value::String(text) => Ok(text),
        other => Err(refuse(
            RefusalKind::WrongType,
            path,
            format!("expected a string, found {}", describe(other)),
        )),
    }
}

fn boolean(value: &Json5Value, path: &str) -> Result<bool, Refusal> {
    match value {
        Json5Value::Bool(b) => Ok(*b),
        other => Err(refuse(
            RefusalKind::WrongType,
            path,
            format!("expected true or false, found {}", describe(other)),
        )),
    }
}

/// Refuse a member twice: a repeat that resolved silently would make a typo read as a choice.
fn check_distinct(entries: &Entries, path: &str) -> Result<(), Refusal> {
    for (i, (key, _)) in entries.iter().enumerate() {
        if entries[..i].iter().any(|(earlier, _)| earlier == key) {
            return Err(refuse(
                RefusalKind::DuplicateField,
                &child(path, key),
                format!("the member `{key}` is stated twice"),
            ));
        }
    }
    Ok(())
}

/// The object at `path`, whose members are those of the schema's `def`: an unknown member, a
/// repeated one and a missing required one are refused, in that order.
fn members<'a>(value: &'a Json5Value, path: &str, def: &str) -> Result<&'a Entries, Refusal> {
    let entries = object(value, path)?;
    let (allowed, required) = shape(def);
    for (key, _) in entries {
        if !allowed.contains(&key.as_str()) {
            return Err(refuse(
                RefusalKind::UnknownField,
                &child(path, key),
                format!(
                    "unknown member `{key}` (allowed here: {})",
                    allowed.join(", ")
                ),
            ));
        }
    }
    check_distinct(entries, path)?;
    for key in required {
        if get(entries, key).is_none() {
            return Err(refuse(
                RefusalKind::MissingField,
                path,
                format!("the member `{key}` is required"),
            ));
        }
    }
    Ok(entries)
}

fn get<'a>(entries: &'a Entries, key: &str) -> Option<&'a Json5Value> {
    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// What [`present`] answers for a member that is not there, which [`members`] has ruled out.
static ABSENT: Json5Value = Json5Value::Null;

/// A required member, which [`members`] has already found.
fn present<'a>(entries: &'a Entries, key: &str) -> &'a Json5Value {
    get(entries, key).unwrap_or(&ABSENT)
}

fn is_plain_decimal(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text.len() == 1 || !text.starts_with('0'))
}

/// An unsigned integer as the catalog writes one: a plain decimal number, or a string of decimal
/// or `0x` hex digits. Another spelling is [`RefusalKind::WrongType`]; digits that do not fit in
/// 64 bits are [`RefusalKind::ValueOutOfRange`].
fn uint(value: &Json5Value, path: &str) -> Result<u64, Refusal> {
    fn too_large(path: &str, text: &str) -> Refusal {
        refuse(
            RefusalKind::ValueOutOfRange,
            path,
            format!("`{text}` does not fit in 64 bits"),
        )
    }
    match value {
        Json5Value::Number(text) if is_plain_decimal(text) => {
            text.parse().map_err(|_| too_large(path, text))
        }
        Json5Value::Number(text) => Err(refuse(
            RefusalKind::WrongType,
            path,
            format!(
                "`{text}` is not a plain unsigned decimal number: write hexadecimal as a string \
                 such as \"0x1f\""
            ),
        )),
        Json5Value::String(text) => {
            if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                if !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return u64::from_str_radix(hex, 16).map_err(|_| too_large(path, text));
                }
            } else if is_plain_decimal(text) {
                return text.parse().map_err(|_| too_large(path, text));
            }
            Err(refuse(
                RefusalKind::WrongType,
                path,
                format!("`{text}` is not decimal digits, nor `0x` and hex digits"),
            ))
        }
        other => Err(refuse(
            RefusalKind::WrongType,
            path,
            format!(
                "expected an unsigned integer (a number, or a string of decimal or 0x hex \
                 digits), found {}",
                describe(other)
            ),
        )),
    }
}

/// The refusals of the two ends of a range.
#[derive(Clone, Copy)]
struct Ends {
    below: RefusalKind,
    above: RefusalKind,
}

const PLAIN: Ends = Ends {
    below: RefusalKind::ValueOutOfRange,
    above: RefusalKind::ValueOutOfRange,
};

/// An unsigned integer from `min` to `max`.
fn bounded(value: &Json5Value, path: &str, min: u64, max: u64, ends: Ends) -> Result<u64, Refusal> {
    let v = uint(value, path)?;
    if v < min {
        return Err(refuse(ends.below, path, format!("{v} is below {min}")));
    }
    if v > max {
        return Err(refuse(ends.above, path, format!("{v} is above {max}")));
    }
    Ok(v)
}

fn name(value: &Json5Value, path: &str) -> Result<String, Refusal> {
    let text = string(value, path)?;
    check_name(text, path)?;
    Ok(String::from(text))
}

fn check_name(text: &str, path: &str) -> Result<(), Refusal> {
    let fits = !text.is_empty()
        && text.len() <= 64
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    if fits {
        Ok(())
    } else {
        Err(refuse(
            RefusalKind::InvalidName,
            path,
            format!("`{text}` is not a name: letters, digits, `_`, `-` and `.`, 1 to 64 bytes"),
        ))
    }
}

/// A literal key: a key expression with no wildcard, which a publisher can put on.
fn check_key_expr(text: &str, path: &str) -> Result<(), Refusal> {
    if let Err(refusal) = validate_keyexpr(text) {
        return Err(refuse(
            RefusalKind::KeyExpr,
            path,
            format!("`{text}` is not a key expression: {refusal}"),
        ));
    }
    if text.contains('*') || text.contains('$') {
        return Err(refuse(
            RefusalKind::KeyExpr,
            path,
            format!("`{text}` is a pattern: a message is put on a literal key"),
        ));
    }
    Ok(())
}

/// The workspace's JSON reader over a catalog, bounded as a profile's is.
fn read_catalog(text: &str) -> Result<Json5Value, Refusal> {
    let syntax = |e: Json5Error| {
        refuse(
            RefusalKind::Syntax,
            "",
            format!("not JSON5 at byte {}: expected {}", e.offset, e.expected),
        )
    };
    let mut lexer = Lexer::new(text);
    lexer.skip_trivia().map_err(syntax)?;
    lexer.skip_value(MAX_CATALOG_JSON_DEPTH).map_err(syntax)?;
    json5::parse(text).map_err(syntax)
}

/// One node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Its name.
    pub name: String,
    /// Its address, when the catalog states one.
    pub address: Option<u64>,
}

/// A named profile document, as the catalog holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    /// The name the messages refer to it by.
    pub name: String,
    /// The document, with the spelling of its numbers as written.
    pub tree: Json5Value,
}

impl Document {
    /// The document as JSON text, numbers spelled as written: what the profile readers take.
    pub fn text(&self) -> String {
        self.tree.to_json5_text()
    }
}

/// How a message is protected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protection {
    /// Its profile, an index into [`Catalog::e2e_profiles`].
    pub profile: usize,
    /// The header values, as written.
    pub values: Json5Value,
}

/// A sender a receiver binds a slot to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sender {
    /// The sending node, an index into [`Catalog::nodes`].
    pub node: usize,
    /// The sender identity its frames carry.
    pub id: u64,
}

/// One value an instance-key field may take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyValue {
    /// An unsigned integer.
    Number(u64),
    /// A string.
    Text(String),
}

/// One field of an instance key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyField {
    /// The payload field.
    pub field: String,
    /// The values it may take.
    pub values: Vec<KeyValue>,
}

/// How the reception of a message is supervised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Supervision {
    /// How many periods a stream may miss.
    pub factor: u16,
    /// Whether a stream can be lost before its first reception.
    pub awaited: bool,
}

/// One message, resolved: every reference an index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The literal key it is put on.
    pub key_expr: String,
    /// Its id.
    pub id: u32,
    /// The nodes that publish it.
    pub publishers: Vec<usize>,
    /// The nodes that subscribe to it.
    pub subscribers: Vec<usize>,
    /// Its period; `None` for an event message.
    pub period_ms: Option<u32>,
    /// Its protection.
    pub protection: Option<Protection>,
    /// The senders its receivers bind their slots to; empty for one stream.
    pub senders: Vec<Sender>,
    /// Its instance key; empty for one instance.
    pub instance_key: Vec<KeyField>,
    /// How many of its last frames a publisher keeps.
    pub replay_depth: Option<u32>,
    /// Its supervision.
    pub supervision: Option<Supervision>,
    /// Its segment profile, an index into [`Catalog::segment_profiles`].
    pub segment_profile: Option<usize>,
}

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
    nodes: Vec<Node>,
    e2e_profiles: Vec<Document>,
    segment_profiles: Vec<Document>,
    start_delay_ms: u32,
    messages: Vec<Message>,
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

/// The documents of a profile map, each judged by `judge`.
fn documents(
    value: Option<&Json5Value>,
    path: &str,
    invalid: RefusalKind,
    judge: fn(&str) -> Result<(), DocError>,
) -> Result<Vec<Document>, Refusal> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let entries = object(value, path)?;
    check_distinct(entries, path)?;
    if entries.len() > MAX_NUMBERED {
        return Err(refuse(
            RefusalKind::ValueOutOfRange,
            path,
            format!("at most {MAX_NUMBERED} profiles of one kind"),
        ));
    }
    let mut out = Vec::with_capacity(entries.len());
    for (key, tree) in entries {
        let here = child(path, key);
        check_name(key, &here)?;
        object(tree, &here)?;
        judge(&tree.to_json5_text()).map_err(|e| refuse(invalid, &here, e.to_string()))?;
        out.push(Document {
            name: key.clone(),
            tree: tree.clone(),
        });
    }
    Ok(out)
}

fn judge_e2e(text: &str) -> Result<(), DocError> {
    Profile::parse(text).map(|_| ())
}

fn judge_segment(text: &str) -> Result<(), DocError> {
    SegmentProfile::parse(text).map(|_| ())
}

/// The nodes a message's list names, each once.
fn node_list(
    value: &Json5Value,
    path: &str,
    nodes: &[Node],
    may_be_empty: bool,
) -> Result<Vec<usize>, Refusal> {
    let items = array(value, path)?;
    if items.is_empty() && !may_be_empty {
        return Err(refuse(RefusalKind::Empty, path, "the list names no node"));
    }
    let mut names = Vec::with_capacity(items.len());
    for (j, item) in items.iter().enumerate() {
        names.push(string(item, &at(path, j))?);
    }
    let mut out: Vec<usize> = Vec::with_capacity(names.len());
    for (j, wanted) in names.iter().enumerate() {
        let here = at(path, j);
        let Some(index) = nodes.iter().position(|n| n.name == *wanted) else {
            return Err(refuse(
                RefusalKind::UnknownNode,
                &here,
                format!("no node is named `{wanted}`"),
            ));
        };
        if out.contains(&index) {
            return Err(refuse(
                RefusalKind::DuplicateNode,
                &here,
                format!("`{wanted}` is named twice"),
            ));
        }
        out.push(index);
    }
    Ok(out)
}

impl Catalog {
    /// Read and judge a catalog from its JSON5 text.
    pub fn parse(text: &str, limits: Limits) -> Result<Self, Refusal> {
        Self::from_tree(&read_catalog(text)?, limits)
    }

    /// Judge a catalog document already read.
    pub fn from_tree(root: &Json5Value, limits: Limits) -> Result<Self, Refusal> {
        let entries = members(root, "", "catalog")?;

        let nodes = Self::read_nodes(present(entries, "nodes"))?;
        let e2e_profiles = documents(
            get(entries, "e2e_profiles"),
            "/e2e_profiles",
            RefusalKind::E2eProfileInvalid,
            judge_e2e,
        )?;
        let segment_profiles = documents(
            get(entries, "segment_profiles"),
            "/segment_profiles",
            RefusalKind::SegmentProfileInvalid,
            judge_segment,
        )?;
        let start_delay_ms = match get(entries, "supervision") {
            None => 0,
            Some(value) => {
                let path = "/supervision";
                let body = members(value, path, "catalog_supervision")?;
                bounded(
                    present(body, "start_delay_ms"),
                    &child(path, "start_delay_ms"),
                    0,
                    MAX_START_DELAY_MS,
                    PLAIN,
                )? as u32
            }
        };

        let mut catalog = Self {
            nodes,
            e2e_profiles,
            segment_profiles,
            start_delay_ms,
            messages: Vec::new(),
        };
        let path = "/messages";
        let items = array(present(entries, "messages"), path)?;
        if items.len() > limits.messages {
            return Err(refuse(
                RefusalKind::TooManyMessages,
                path,
                format!(
                    "{} messages, and the build's MESSAGE_CATALOG_ENTRIES is {}",
                    items.len(),
                    limits.messages
                ),
            ));
        }
        for (i, item) in items.iter().enumerate() {
            let message = catalog.read_message(item, &at(path, i), limits)?;
            catalog.messages.push(message);
        }
        Ok(catalog)
    }

    fn read_nodes(value: &Json5Value) -> Result<Vec<Node>, Refusal> {
        let path = "/nodes";
        let items = array(value, path)?;
        if items.is_empty() {
            return Err(refuse(
                RefusalKind::Empty,
                path,
                "a catalog has at least one node",
            ));
        }
        if items.len() > MAX_NUMBERED {
            return Err(refuse(
                RefusalKind::ValueOutOfRange,
                path,
                format!("at most {MAX_NUMBERED} nodes"),
            ));
        }
        let mut out: Vec<Node> = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            let here = at(path, i);
            let body = members(item, &here, "node")?;
            let name_path = child(&here, "name");
            let node_name = name(present(body, "name"), &name_path)?;
            let address = match get(body, "address") {
                Some(value) => Some(bounded(
                    value,
                    &child(&here, "address"),
                    0,
                    u64::MAX,
                    PLAIN,
                )?),
                None => None,
            };
            if out.iter().any(|n| n.name == node_name) {
                return Err(refuse(
                    RefusalKind::DuplicateNode,
                    &name_path,
                    format!("a node is already named `{node_name}`"),
                ));
            }
            out.push(Node {
                name: node_name,
                address,
            });
        }
        Ok(out)
    }

    /// One message at `path`: its shape, then the rules that relate it to the rest.
    fn read_message(
        &self,
        value: &Json5Value,
        path: &str,
        limits: Limits,
    ) -> Result<Message, Refusal> {
        let body = members(value, path, "message")?;
        let key_path = child(path, "key_expr");
        let key_expr = String::from(string(present(body, "key_expr"), &key_path)?);
        check_key_expr(&key_expr, &key_path)?;
        let id_path = child(path, "id");
        let id = bounded(present(body, "id"), &id_path, 0, u32::MAX.into(), PLAIN)? as u32;
        let publishers = node_list(
            present(body, "publishers"),
            &child(path, "publishers"),
            &self.nodes,
            false,
        )?;
        let subscribers = node_list(
            present(body, "subscribers"),
            &child(path, "subscribers"),
            &self.nodes,
            true,
        )?;
        let period_ms = match get(body, "period_ms") {
            Some(value) => Some(bounded(
                value,
                &child(path, "period_ms"),
                1,
                u32::MAX.into(),
                Ends {
                    below: RefusalKind::PeriodZero,
                    above: RefusalKind::ValueOutOfRange,
                },
            )? as u32),
            None => None,
        };
        let protection = match get(body, "protection") {
            Some(value) => Some(self.read_protection(value, &child(path, "protection"))?),
            None => None,
        };
        let senders = match get(body, "senders") {
            Some(value) => self.read_senders(value, &child(path, "senders"), limits)?,
            None => Vec::new(),
        };
        let instance_key = match get(body, "instance_key") {
            Some(value) => read_instance_key(value, &child(path, "instance_key"))?,
            None => Vec::new(),
        };
        let replay_depth = match get(body, "replay_depth") {
            Some(value) => Some(bounded(
                value,
                &child(path, "replay_depth"),
                1,
                limits.replay_depth_max as u64,
                Ends {
                    below: RefusalKind::ReplayDepthOutOfRange,
                    above: RefusalKind::ReplayDepthOutOfRange,
                },
            )? as u32),
            None => None,
        };
        let supervision = match get(body, "supervision") {
            Some(value) => Some(read_supervision(value, &child(path, "supervision"))?),
            None => None,
        };
        let segment_profile = match get(body, "segment_profile") {
            Some(value) => {
                let here = child(path, "segment_profile");
                let wanted = string(value, &here)?;
                let Some(index) = self.segment_profiles.iter().position(|d| d.name == wanted)
                else {
                    return Err(refuse(
                        RefusalKind::UnknownSegmentProfile,
                        &here,
                        format!("no segment profile is named `{wanted}`"),
                    ));
                };
                Some(index)
            }
            None => None,
        };

        if self.messages.iter().any(|m| m.key_expr == key_expr) {
            return Err(refuse(
                RefusalKind::DuplicateKeyExpr,
                &key_path,
                format!("another message is put on `{key_expr}`"),
            ));
        }
        if self.messages.iter().any(|m| m.id == id) {
            return Err(refuse(
                RefusalKind::DuplicateId,
                &id_path,
                format!("another message has the id {id}"),
            ));
        }
        if let Some(supervision) = supervision {
            let Some(period) = period_ms else {
                return Err(refuse(
                    RefusalKind::SupervisionWithoutPeriod,
                    &child(path, "supervision"),
                    "only a periodic message has a reception deadline",
                ));
            };
            let deadline = u64::from(period) * u64::from(supervision.factor);
            if deadline > MAX_DEADLINE_MS {
                return Err(refuse(
                    RefusalKind::DeadlineOutOfRange,
                    &child(&child(path, "supervision"), "factor"),
                    format!("the deadline {deadline} ms is above {MAX_DEADLINE_MS} ms"),
                ));
            }
        }
        if !senders.is_empty() {
            let senders_path = child(path, "senders");
            if protection.is_none() {
                return Err(refuse(
                    RefusalKind::SendersWithoutProtection,
                    &senders_path,
                    "a receiver tells senders apart by the protection header",
                ));
            }
            for (j, sender) in senders.iter().enumerate() {
                if !publishers.contains(&sender.node) {
                    return Err(refuse(
                        RefusalKind::SenderNotPublisher,
                        &child(&at(&senders_path, j), "node"),
                        format!(
                            "`{}` does not publish the message",
                            self.nodes[sender.node].name
                        ),
                    ));
                }
            }
            if !instance_key.is_empty() {
                return Err(refuse(
                    RefusalKind::InstanceKeyWithSenders,
                    &child(path, "instance_key"),
                    "a message keeps its streams by sender or by instance, not both",
                ));
            }
        }

        let message = Message {
            key_expr,
            id,
            publishers,
            subscribers,
            period_ms,
            protection,
            senders,
            instance_key,
            replay_depth,
            supervision,
            segment_profile,
        };
        self.judge_protection(&message, path, limits)?;
        Ok(message)
    }

    fn read_protection(&self, value: &Json5Value, path: &str) -> Result<Protection, Refusal> {
        let body = members(value, path, "protection")?;
        let profile_path = child(path, "profile");
        let wanted = string(present(body, "profile"), &profile_path)?;
        let values = present(body, "values");
        object(values, &child(path, "values"))?;
        let Some(profile) = self.e2e_profiles.iter().position(|d| d.name == wanted) else {
            return Err(refuse(
                RefusalKind::UnknownE2eProfile,
                &profile_path,
                format!("no e2e profile is named `{wanted}`"),
            ));
        };
        Ok(Protection {
            profile,
            values: values.clone(),
        })
    }

    fn read_senders(
        &self,
        value: &Json5Value,
        path: &str,
        limits: Limits,
    ) -> Result<Vec<Sender>, Refusal> {
        let items = array(value, path)?;
        if items.is_empty() {
            return Err(refuse(RefusalKind::Empty, path, "the list names no sender"));
        }
        if items.len() > limits.sender_slots {
            return Err(refuse(
                RefusalKind::TooManySenders,
                path,
                format!(
                    "{} senders, and the build's E2E_SENDER_SLOTS is {}",
                    items.len(),
                    limits.sender_slots
                ),
            ));
        }
        let mut read = Vec::with_capacity(items.len());
        for (j, item) in items.iter().enumerate() {
            let here = at(path, j);
            let body = members(item, &here, "sender")?;
            let node = String::from(string(present(body, "node"), &child(&here, "node"))?);
            let id = bounded(present(body, "id"), &child(&here, "id"), 0, u64::MAX, PLAIN)?;
            read.push((node, id));
        }
        let mut out: Vec<Sender> = Vec::with_capacity(read.len());
        for (j, (wanted, id)) in read.iter().enumerate() {
            let here = at(path, j);
            let Some(node) = self.nodes.iter().position(|n| n.name == *wanted) else {
                return Err(refuse(
                    RefusalKind::UnknownNode,
                    &child(&here, "node"),
                    format!("no node is named `{wanted}`"),
                ));
            };
            if out.iter().any(|s| s.node == node || s.id == *id) {
                return Err(refuse(
                    RefusalKind::DuplicateSender,
                    &here,
                    format!("`{wanted}` or the identity {id} is stated twice"),
                ));
            }
            out.push(Sender { node, id: *id });
        }
        Ok(out)
    }

    /// The rules that depend on what the profile says: the header values build a frame for every
    /// publisher and give every subscriber its expected identifier, and the profile's message cell
    /// can carry the senders.
    fn judge_protection(
        &self,
        message: &Message,
        path: &str,
        limits: Limits,
    ) -> Result<(), Refusal> {
        let Some(protection) = &message.protection else {
            return Ok(());
        };
        let values_path = child(&child(path, "protection"), "values");
        let invalid = |reason: String| refuse(RefusalKind::ValuesInvalid, &values_path, reason);
        let profile = self
            .e2e_profile(protection.profile)
            .map_err(|e| refuse(RefusalKind::E2eProfileInvalid, &values_path, e.to_string()))?;
        for &node in &message.publishers {
            let node = &self.nodes[node];
            let values = values_for(&protection.values, node)
                .map_err(|e| invalid(format!("for `{}`: {e}", node.name)))?;
            StreamSender::new(profile.clone(), values, SenderOptions::default())
                .map_err(|e| invalid(format!("for `{}`: {e}", node.name)))?;
        }
        let no_address = Node {
            name: String::new(),
            address: None,
        };
        let receivers: Vec<&Node> = if message.subscribers.is_empty() {
            alloc::vec![&no_address]
        } else {
            message
                .subscribers
                .iter()
                .map(|&n| &self.nodes[n])
                .collect()
        };
        for node in receivers {
            let values = values_for(&protection.values, node)
                .map_err(|e| invalid(format!("for `{}`: {e}", node.name)))?;
            match Receiver::new(
                profile.clone(),
                &values,
                keying(message),
                None,
                limits.sender_slots,
            ) {
                Ok(_) => {}
                Err(NewError::NoSenderInCell | NewError::BadBoundList) => {
                    return Err(refuse(
                        RefusalKind::SendersUnsupportedByProfile,
                        &child(path, "senders"),
                        "the profile's message cell names no sender part, or the part cannot \
                         hold every identity",
                    ));
                }
                Err(e) => return Err(invalid(format!("for `{}`: {e}", node.name))),
            }
        }
        Ok(())
    }

    /// Judge a generator's tables: the table turned back into a catalog document and read by
    /// every rule [`Catalog::from_tree`] runs.
    pub fn from_table(table: &Table, limits: Limits) -> Result<Self, Refusal> {
        Self::from_tree(&table_document(table)?, limits)
    }

    /// The nodes, in the catalog's order.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// The index of the node called `name`.
    pub fn node_index(&self, name: &str) -> Option<usize> {
        self.nodes.iter().position(|n| n.name == name)
    }

    /// The e2e profiles.
    pub fn e2e_profiles(&self) -> &[Document] {
        &self.e2e_profiles
    }

    /// The segment profiles.
    pub fn segment_profiles(&self) -> &[Document] {
        &self.segment_profiles
    }

    /// The start delay every supervisor of the deployment has; 0 when the catalog states none.
    pub fn supervision_start_delay_ms(&self) -> u32 {
        self.start_delay_ms
    }

    /// The messages, in the catalog's order.
    pub fn messages(&self) -> &[Message] {
        &self.messages
    }

    /// The index of the message put on `key_expr`.
    pub fn find_key_expr(&self, key_expr: &str) -> Option<usize> {
        self.messages.iter().position(|m| m.key_expr == key_expr)
    }

    /// The index of the message of `id`.
    pub fn find_id(&self, id: u32) -> Option<usize> {
        self.messages.iter().position(|m| m.id == id)
    }

    /// The e2e profile at `index`, read.
    pub fn e2e_profile(&self, index: usize) -> Result<Profile, DocError> {
        match self.e2e_profiles.get(index) {
            Some(document) => Profile::parse(&document.text()),
            None => Err(DocError::invalid("", "the catalog has no such e2e profile")),
        }
    }

    /// The segment profile at `index`, read.
    pub fn segment_profile(&self, index: usize) -> Result<SegmentProfile, DocError> {
        match self.segment_profiles.get(index) {
            Some(document) => SegmentProfile::parse(&document.text()),
            None => Err(DocError::invalid(
                "",
                "the catalog has no such segment profile",
            )),
        }
    }

    fn entry(&self, message: usize, node: usize) -> Result<(&Message, &Node), HandleError> {
        let message = self
            .messages
            .get(message)
            .ok_or(HandleError::NoSuchMessage)?;
        let node = self.nodes.get(node).ok_or(HandleError::NoSuchNode)?;
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

fn read_supervision(value: &Json5Value, path: &str) -> Result<Supervision, Refusal> {
    let body = members(value, path, "message_supervision")?;
    let factor = bounded(
        present(body, "factor"),
        &child(path, "factor"),
        1,
        u16::MAX.into(),
        PLAIN,
    )? as u16;
    let awaited = match get(body, "awaited") {
        Some(value) => boolean(value, &child(path, "awaited"))?,
        None => true,
    };
    Ok(Supervision { factor, awaited })
}

fn read_instance_key(value: &Json5Value, path: &str) -> Result<Vec<KeyField>, Refusal> {
    let items = array(value, path)?;
    if items.is_empty() {
        return Err(refuse(
            RefusalKind::Empty,
            path,
            "the instance key names no field",
        ));
    }
    let mut out: Vec<KeyField> = Vec::with_capacity(items.len());
    for (j, item) in items.iter().enumerate() {
        let here = at(path, j);
        let body = members(item, &here, "key_field")?;
        let field_path = child(&here, "field");
        let field = String::from(string(present(body, "field"), &field_path)?);
        if field.is_empty() {
            return Err(refuse(
                RefusalKind::Empty,
                &field_path,
                "the field is not named",
            ));
        }
        let values_path = child(&here, "values");
        let listed = array(present(body, "values"), &values_path)?;
        if listed.is_empty() {
            return Err(refuse(
                RefusalKind::Empty,
                &values_path,
                "the field takes no value",
            ));
        }
        let mut values: Vec<KeyValue> = Vec::with_capacity(listed.len());
        for (k, item) in listed.iter().enumerate() {
            let value_path = at(&values_path, k);
            let value = match item {
                Json5Value::String(text) => KeyValue::Text(text.clone()),
                other => KeyValue::Number(uint(other, &value_path)?),
            };
            if values.contains(&value) {
                return Err(refuse(
                    RefusalKind::DuplicateInstanceKey,
                    &value_path,
                    "the value is listed twice",
                ));
            }
            values.push(value);
        }
        if out.iter().any(|f| f.field == field) {
            return Err(refuse(
                RefusalKind::DuplicateInstanceKey,
                &field_path,
                format!("the field `{field}` is named twice"),
            ));
        }
        out.push(KeyField { field, values });
    }
    Ok(out)
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
    rows: &[crate::message_catalog_table::DocumentRow],
    path: &str,
    invalid: RefusalKind,
) -> Result<Json5Value, Refusal> {
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let tree = read_json(row.text)
            .map_err(|e| refuse(invalid, &child(path, row.name), e.to_string()))?;
        entries.push(member(row.name, tree));
    }
    Ok(Json5Value::Object(entries))
}

/// The names of the nodes a table's list numbers.
fn table_nodes(table: &Table, list: &[u16], path: &str) -> Result<Json5Value, Refusal> {
    let mut out = Vec::with_capacity(list.len());
    for (j, &index) in list.iter().enumerate() {
        let Some(node) = table.nodes.get(usize::from(index)) else {
            return Err(refuse(
                RefusalKind::UnknownNode,
                &at(path, j),
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
                "/e2e_profiles",
                RefusalKind::E2eProfileInvalid,
            )?,
        ));
    }
    if !table.segment_profiles.is_empty() {
        root.push(member(
            "segment_profiles",
            table_documents(
                table.segment_profiles,
                "/segment_profiles",
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
    let mut messages = Vec::with_capacity(table.messages.len());
    for (i, row) in table.messages.iter().enumerate() {
        messages.push(table_message(table, row, &at("/messages", i))?);
    }
    root.push(member("messages", Json5Value::Array(messages)));
    Ok(Json5Value::Object(root))
}

fn table_message(table: &Table, row: &MessageRow, path: &str) -> Result<Json5Value, Refusal> {
    let mut entries = alloc::vec![
        member("key_expr", text(row.key_expr)),
        member("id", number(row.id)),
        member(
            "publishers",
            table_nodes(table, row.publishers, &child(path, "publishers"))?
        ),
        member(
            "subscribers",
            table_nodes(table, row.subscribers, &child(path, "subscribers"))?
        ),
    ];
    if let Some(period) = row.period_ms {
        entries.push(member("period_ms", number(period)));
    }
    if let Some(protection) = row.protection {
        let here = child(path, "protection");
        let Some(profile) = table.e2e_profiles.get(usize::from(protection.profile)) else {
            return Err(refuse(
                RefusalKind::UnknownE2eProfile,
                &child(&here, "profile"),
                format!("the table has no e2e profile {}", protection.profile),
            ));
        };
        let values = read_json(protection.values).map_err(|e| {
            refuse(
                RefusalKind::ValuesInvalid,
                &child(&here, "values"),
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
        let here = child(path, "senders");
        let mut senders = Vec::with_capacity(row.senders.len());
        for (j, sender) in row.senders.iter().enumerate() {
            let Some(node) = table.nodes.get(usize::from(sender.node)) else {
                return Err(refuse(
                    RefusalKind::UnknownNode,
                    &child(&at(&here, j), "node"),
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
            return Err(refuse(
                RefusalKind::UnknownSegmentProfile,
                &child(path, "segment_profile"),
                format!("the table has no segment profile {index}"),
            ));
        };
        entries.push(member("segment_profile", text(profile.name)));
    }
    Ok(Json5Value::Object(entries))
}

/// The bounds of this build: its `MESSAGE_CATALOG_ENTRIES`, `REPLAY_DEPTH_MAX` and
/// `E2E_SENDER_SLOTS`.
pub fn build_limits() -> Limits {
    Limits {
        messages: wz_session_core::caps::MESSAGE_CATALOG_ENTRIES,
        replay_depth_max: wz_session_core::caps::REPLAY_DEPTH_MAX,
        sender_slots: wz_session_core::caps::E2E_SENDER_SLOTS,
    }
}
