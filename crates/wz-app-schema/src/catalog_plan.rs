// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The READER of a message catalog: its document read, every rule of its shape and of the
//! references inside it judged, in the order a refusal is reported, and the catalog resolved into
//! plain data ([`CatalogPlan`]).
//!
//! The rules that depend on what a profile says (the profile documents themselves, whether the
//! header values build a frame for each node, whether the profile's message cell can carry the
//! senders) are asked of a [`CatalogJudge`] at the place in the reading where each is reported, so
//! the first refusal of a catalog does not depend on who judges the profiles. The application
//! frame's catalog (`wz_app_frame::message_catalog`) is that judge, since judging a protection
//! makes the senders and the receivers a node runs; it re-exports what this module declares at its
//! own paths.
//!
//! A reader walks the document with a [`Pointer`], so a catalog that is accepted writes no path
//! out, and a refusal writes the one it names.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use wz_session_core::json5::{self, Json5Value};
use wz_session_core::json5_lex::{Json5Error, Lexer};
use wz_session_core::keyexpr_canon::validate_keyexpr;

use crate::json_doc::{describe, Entries, Pointer, MAX_JSON_DEPTH};
use crate::message_catalog_table::Limits;

/// Deepest nesting a catalog may have: a profile document's own depth ([`MAX_JSON_DEPTH`]),
/// under the catalog and its `e2e_profiles` object.
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
    /// More messages than the `MESSAGE_CATALOG_ENTRIES` it is read under.
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
    /// An instance key of more fields than the build's `INSTANCE_KEY_FIELDS`.
    TooManyKeyFields,
    /// An instance key whose lists of values make more instances than the build's
    /// `INSTANCES_PER_MESSAGE`.
    TooManyInstances,
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
    pub const ALL: [Self; 32] = [
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
        Self::TooManyKeyFields,
        Self::TooManyInstances,
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
            Self::TooManyKeyFields => "too_many_key_fields",
            Self::TooManyInstances => "too_many_instances",
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

impl Refusal {
    /// The refusal of the rule `kind` at `at`, for `reason`.
    pub fn new(kind: RefusalKind, at: &Pointer<'_>, reason: String) -> Self {
        Self {
            kind,
            path: at.render(),
            reason,
        }
    }
}

/// A refusal whose reason does not depend on the document.
fn fixed(kind: RefusalKind, at: &Pointer<'_>, reason: &str) -> Refusal {
    Refusal::new(kind, at, String::from(reason))
}

/// A value of another type than its member's: `expected` names the type wanted.
fn wrong_type(at: &Pointer<'_>, expected: &str, found: &Json5Value) -> Refusal {
    Refusal::new(
        RefusalKind::WrongType,
        at,
        format!("expected {expected}, found {}", describe(found)),
    )
}

fn object<'v>(value: &'v Json5Value, at: &Pointer<'_>) -> Result<&'v Entries, Refusal> {
    match value {
        Json5Value::Object(entries) => Ok(entries),
        other => Err(wrong_type(at, "an object", other)),
    }
}

fn array<'v>(value: &'v Json5Value, at: &Pointer<'_>) -> Result<&'v [Json5Value], Refusal> {
    match value {
        Json5Value::Array(items) => Ok(items),
        other => Err(wrong_type(at, "an array", other)),
    }
}

fn string<'v>(value: &'v Json5Value, at: &Pointer<'_>) -> Result<&'v str, Refusal> {
    match value {
        Json5Value::String(text) => Ok(text),
        other => Err(wrong_type(at, "a string", other)),
    }
}

fn boolean(value: &Json5Value, at: &Pointer<'_>) -> Result<bool, Refusal> {
    match value {
        Json5Value::Bool(b) => Ok(*b),
        other => Err(wrong_type(at, "true or false", other)),
    }
}

/// Refuse a member twice: a repeat that resolved silently would make a typo read as a choice.
fn check_distinct(entries: &Entries, at: &Pointer<'_>) -> Result<(), Refusal> {
    for (i, (key, _)) in entries.iter().enumerate() {
        if entries[..i].iter().any(|(earlier, _)| earlier == key) {
            return Err(Refusal::new(
                RefusalKind::DuplicateField,
                &at.key(key),
                format!("the member `{key}` is stated twice"),
            ));
        }
    }
    Ok(())
}

/// The object at `at`, whose members are those of the schema's `def`: an unknown member, a
/// repeated one and a missing required one are refused, in that order.
fn members<'v>(value: &'v Json5Value, at: &Pointer<'_>, def: &str) -> Result<&'v Entries, Refusal> {
    let entries = object(value, at)?;
    let (allowed, required) = shape(def);
    for (key, _) in entries {
        if !allowed.contains(&key.as_str()) {
            return Err(Refusal::new(
                RefusalKind::UnknownField,
                &at.key(key),
                format!(
                    "unknown member `{key}` (allowed here: {})",
                    allowed.join(", ")
                ),
            ));
        }
    }
    check_distinct(entries, at)?;
    for key in required {
        if get(entries, key).is_none() {
            return Err(Refusal::new(
                RefusalKind::MissingField,
                at,
                format!("the member `{key}` is required"),
            ));
        }
    }
    Ok(entries)
}

fn get<'v>(entries: &'v Entries, key: &str) -> Option<&'v Json5Value> {
    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// What [`present`] answers for a member that is not there, which [`members`] has ruled out.
static ABSENT: Json5Value = Json5Value::Null;

/// A required member, which [`members`] has already found.
fn present<'v>(entries: &'v Entries, key: &str) -> &'v Json5Value {
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
fn uint(value: &Json5Value, at: &Pointer<'_>) -> Result<u64, Refusal> {
    fn too_large(at: &Pointer<'_>, text: &str) -> Refusal {
        Refusal::new(
            RefusalKind::ValueOutOfRange,
            at,
            format!("`{text}` does not fit in 64 bits"),
        )
    }
    match value {
        Json5Value::Number(text) if is_plain_decimal(text) => {
            text.parse().map_err(|_| too_large(at, text))
        }
        Json5Value::Number(text) => Err(Refusal::new(
            RefusalKind::WrongType,
            at,
            format!(
                "`{text}` is not a plain unsigned decimal number: write hexadecimal as a string \
                 such as \"0x1f\""
            ),
        )),
        Json5Value::String(text) => {
            if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                if !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return u64::from_str_radix(hex, 16).map_err(|_| too_large(at, text));
                }
            } else if is_plain_decimal(text) {
                return text.parse().map_err(|_| too_large(at, text));
            }
            Err(Refusal::new(
                RefusalKind::WrongType,
                at,
                format!("`{text}` is not decimal digits, nor `0x` and hex digits"),
            ))
        }
        other => Err(Refusal::new(
            RefusalKind::WrongType,
            at,
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
fn bounded(
    value: &Json5Value,
    at: &Pointer<'_>,
    min: u64,
    max: u64,
    ends: Ends,
) -> Result<u64, Refusal> {
    let v = uint(value, at)?;
    if v < min {
        return Err(Refusal::new(ends.below, at, format!("{v} is below {min}")));
    }
    if v > max {
        return Err(Refusal::new(ends.above, at, format!("{v} is above {max}")));
    }
    Ok(v)
}

fn name(value: &Json5Value, at: &Pointer<'_>) -> Result<String, Refusal> {
    let text = string(value, at)?;
    check_name(text, at)?;
    Ok(String::from(text))
}

fn check_name(text: &str, at: &Pointer<'_>) -> Result<(), Refusal> {
    let fits = !text.is_empty()
        && text.len() <= 64
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    if fits {
        Ok(())
    } else {
        Err(Refusal::new(
            RefusalKind::InvalidName,
            at,
            format!("`{text}` is not a name: letters, digits, `_`, `-` and `.`, 1 to 64 bytes"),
        ))
    }
}

/// A literal key: a key expression with no wildcard, which a publisher can put on.
fn check_key_expr(text: &str, at: &Pointer<'_>) -> Result<(), Refusal> {
    if let Err(refusal) = validate_keyexpr(text) {
        return Err(Refusal::new(
            RefusalKind::KeyExpr,
            at,
            format!("`{text}` is not a key expression: {refusal}"),
        ));
    }
    if text.contains('*') || text.contains('$') {
        return Err(Refusal::new(
            RefusalKind::KeyExpr,
            at,
            format!("`{text}` is a pattern: a message is put on a literal key"),
        ));
    }
    Ok(())
}

/// A catalog's text read by the workspace's JSON reader, bounded as a profile's is: a text that is
/// not JSON5, or nests deeper than [`MAX_CATALOG_JSON_DEPTH`], is [`RefusalKind::Syntax`].
pub fn read_catalog(text: &str) -> Result<Json5Value, Refusal> {
    let syntax = |e: Json5Error| {
        Refusal::new(
            RefusalKind::Syntax,
            &Pointer::text(""),
            format!("not JSON5 at byte {}: expected {}", e.offset, e.expected),
        )
    };
    let mut lexer = Lexer::new(text);
    lexer.skip_trivia().map_err(syntax)?;
    lexer.skip_value(MAX_CATALOG_JSON_DEPTH).map_err(syntax)?;
    json5::parse(text).map_err(syntax)
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
    /// The document as JSON5 text, numbers spelled as written: the text a profile reader reads
    /// as it reads [`Self::tree`].
    pub fn text(&self) -> String {
        self.tree.to_json5_text()
    }
}

/// How a message is protected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protection {
    /// Its profile, an index into [`CatalogPlan::e2e_profiles`].
    pub profile: usize,
    /// The header values, as written.
    pub values: Json5Value,
}

/// A sender a receiver binds a slot to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sender {
    /// The sending node, an index into [`CatalogPlan::nodes`].
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
    /// Its segment profile, an index into [`CatalogPlan::segment_profiles`].
    pub segment_profile: Option<usize>,
}

/// The rules of a catalog that depend on what a profile says, asked by [`CatalogPlan::read`] at
/// the place in the reading where each is reported. Each answer is the reason of a refusal, as a
/// sentence; the reader names the rule and the place.
pub trait CatalogJudge {
    /// Whether the e2e profile document `tree` is one the profile reader accepts.
    fn e2e_profile(&self, tree: &Json5Value) -> Result<(), String>;

    /// Whether the segment profile document `tree` is one the segment profile reader accepts.
    fn segment_profile(&self, tree: &Json5Value) -> Result<(), String>;

    /// Whether `message`, which is protected, can be sent and received under `profile`, its
    /// e2e profile document: its header values build a frame for every node that publishes it and
    /// give every node that subscribes to it (or, when none does, a node with no address) its
    /// expected header, and the profile's message cell can carry its senders within
    /// `sender_slots`. `nodes` are the catalog's, which the message's lists index.
    fn protection(
        &self,
        profile: &Json5Value,
        message: &Message,
        nodes: &[Node],
        sender_slots: usize,
    ) -> Result<(), ProtectionRefusal>;
}

/// Why a [`CatalogJudge`] refused a message's protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionRefusal {
    /// The profile reader refuses the profile, for this reason.
    Profile(String),
    /// The header values are refused for a node, for this reason.
    Values(String),
    /// The profile's message cell names no sender part, or the part cannot hold every identity.
    SendersUnsupported,
}

/// A catalog read and judged: every reference an index, every number the value it stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogPlan {
    nodes: Vec<Node>,
    e2e_profiles: Vec<Document>,
    segment_profiles: Vec<Document>,
    start_delay_ms: u32,
    messages: Vec<Message>,
}

/// The documents of a profile map, each judged by `judge`.
///
/// A profile is judged on its tree: the catalog is read under [`MAX_CATALOG_JSON_DEPTH`], two
/// levels above a profile's own bound, so the tree is one the profile's text reader would read
/// whole, and its numbers keep the spelling they were written with.
fn documents(
    value: Option<&Json5Value>,
    at: &Pointer<'_>,
    invalid: RefusalKind,
    judge: &dyn Fn(&Json5Value) -> Result<(), String>,
) -> Result<Vec<Document>, Refusal> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let entries = object(value, at)?;
    check_distinct(entries, at)?;
    if entries.len() > MAX_NUMBERED {
        return Err(Refusal::new(
            RefusalKind::ValueOutOfRange,
            at,
            format!("at most {MAX_NUMBERED} profiles of one kind"),
        ));
    }
    let mut out = Vec::with_capacity(entries.len());
    for (key, tree) in entries {
        let here = at.key(key);
        check_name(key, &here)?;
        object(tree, &here)?;
        judge(tree).map_err(|reason| Refusal::new(invalid, &here, reason))?;
        out.push(Document {
            name: key.clone(),
            tree: tree.clone(),
        });
    }
    Ok(out)
}

/// The nodes a message's list names, each once.
fn node_list(
    value: &Json5Value,
    at: &Pointer<'_>,
    nodes: &[Node],
    may_be_empty: bool,
) -> Result<Vec<usize>, Refusal> {
    let items = array(value, at)?;
    if items.is_empty() && !may_be_empty {
        return Err(fixed(RefusalKind::Empty, at, "the list names no node"));
    }
    let mut names = Vec::with_capacity(items.len());
    for (j, item) in items.iter().enumerate() {
        names.push(string(item, &at.index(j))?);
    }
    let mut out: Vec<usize> = Vec::with_capacity(names.len());
    for (j, wanted) in names.iter().enumerate() {
        let Some(index) = nodes.iter().position(|n| n.name == *wanted) else {
            return Err(Refusal::new(
                RefusalKind::UnknownNode,
                &at.index(j),
                format!("no node is named `{wanted}`"),
            ));
        };
        if out.contains(&index) {
            return Err(Refusal::new(
                RefusalKind::DuplicateNode,
                &at.index(j),
                format!("`{wanted}` is named twice"),
            ));
        }
        out.push(index);
    }
    Ok(out)
}

impl CatalogPlan {
    /// Read and judge a catalog document, asking `judge` the rules that depend on a profile.
    pub fn read(
        root: &Json5Value,
        limits: Limits,
        judge: &dyn CatalogJudge,
    ) -> Result<Self, Refusal> {
        let entries = members(root, &Pointer::text(""), "catalog")?;

        let nodes = read_nodes(present(entries, "nodes"))?;
        let e2e_profiles = documents(
            get(entries, "e2e_profiles"),
            &Pointer::text("/e2e_profiles"),
            RefusalKind::E2eProfileInvalid,
            &|tree| judge.e2e_profile(tree),
        )?;
        let segment_profiles = documents(
            get(entries, "segment_profiles"),
            &Pointer::text("/segment_profiles"),
            RefusalKind::SegmentProfileInvalid,
            &|tree| judge.segment_profile(tree),
        )?;
        let start_delay_ms = match get(entries, "supervision") {
            None => 0,
            Some(value) => {
                let at = Pointer::text("/supervision");
                let body = members(value, &at, "catalog_supervision")?;
                bounded(
                    present(body, "start_delay_ms"),
                    &at.key("start_delay_ms"),
                    0,
                    MAX_START_DELAY_MS,
                    PLAIN,
                )? as u32
            }
        };

        let mut plan = Self {
            nodes,
            e2e_profiles,
            segment_profiles,
            start_delay_ms,
            messages: Vec::new(),
        };
        let at = Pointer::text("/messages");
        let items = array(present(entries, "messages"), &at)?;
        if items.len() > limits.messages {
            return Err(Refusal::new(
                RefusalKind::TooManyMessages,
                &at,
                format!(
                    "{} messages, and the MESSAGE_CATALOG_ENTRIES it is read under is {}",
                    items.len(),
                    limits.messages
                ),
            ));
        }
        for (i, item) in items.iter().enumerate() {
            let message = plan.read_message(item, &at.index(i), limits, judge)?;
            plan.messages.push(message);
        }
        Ok(plan)
    }

    /// One message at `at`: its shape, then the rules that relate it to the rest, then the rules
    /// `judge` answers for its protection.
    fn read_message(
        &self,
        value: &Json5Value,
        at: &Pointer<'_>,
        limits: Limits,
        judge: &dyn CatalogJudge,
    ) -> Result<Message, Refusal> {
        let body = members(value, at, "message")?;
        let key_at = at.key("key_expr");
        let key_expr = String::from(string(present(body, "key_expr"), &key_at)?);
        check_key_expr(&key_expr, &key_at)?;
        let id_at = at.key("id");
        let id = bounded(present(body, "id"), &id_at, 0, u32::MAX.into(), PLAIN)? as u32;
        let publishers = node_list(
            present(body, "publishers"),
            &at.key("publishers"),
            &self.nodes,
            false,
        )?;
        let subscribers = node_list(
            present(body, "subscribers"),
            &at.key("subscribers"),
            &self.nodes,
            true,
        )?;
        let period_ms = match get(body, "period_ms") {
            Some(value) => Some(bounded(
                value,
                &at.key("period_ms"),
                1,
                u32::MAX.into(),
                Ends {
                    below: RefusalKind::PeriodZero,
                    above: RefusalKind::ValueOutOfRange,
                },
            )? as u32),
            None => None,
        };
        let protection_at = at.key("protection");
        let protection = match get(body, "protection") {
            Some(value) => Some(self.read_protection(value, &protection_at)?),
            None => None,
        };
        let senders_at = at.key("senders");
        let senders = match get(body, "senders") {
            Some(value) => self.read_senders(value, &senders_at, limits)?,
            None => Vec::new(),
        };
        let instance_key_at = at.key("instance_key");
        let instance_key = match get(body, "instance_key") {
            Some(value) => read_instance_key(value, &instance_key_at, limits)?,
            None => Vec::new(),
        };
        let replay_depth = match get(body, "replay_depth") {
            Some(value) => Some(bounded(
                value,
                &at.key("replay_depth"),
                1,
                limits.replay_depth_max as u64,
                Ends {
                    below: RefusalKind::ReplayDepthOutOfRange,
                    above: RefusalKind::ReplayDepthOutOfRange,
                },
            )? as u32),
            None => None,
        };
        let supervision_at = at.key("supervision");
        let supervision = match get(body, "supervision") {
            Some(value) => Some(read_supervision(value, &supervision_at)?),
            None => None,
        };
        let segment_profile = match get(body, "segment_profile") {
            Some(value) => {
                let here = at.key("segment_profile");
                let wanted = string(value, &here)?;
                let Some(index) = self.segment_profiles.iter().position(|d| d.name == wanted)
                else {
                    return Err(Refusal::new(
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
            return Err(Refusal::new(
                RefusalKind::DuplicateKeyExpr,
                &key_at,
                format!("another message is put on `{key_expr}`"),
            ));
        }
        if self.messages.iter().any(|m| m.id == id) {
            return Err(Refusal::new(
                RefusalKind::DuplicateId,
                &id_at,
                format!("another message has the id {id}"),
            ));
        }
        if let Some(supervision) = supervision {
            let Some(period) = period_ms else {
                return Err(fixed(
                    RefusalKind::SupervisionWithoutPeriod,
                    &supervision_at,
                    "only a periodic message has a reception deadline",
                ));
            };
            let deadline = u64::from(period) * u64::from(supervision.factor);
            if deadline > MAX_DEADLINE_MS {
                return Err(Refusal::new(
                    RefusalKind::DeadlineOutOfRange,
                    &supervision_at.key("factor"),
                    format!("the deadline {deadline} ms is above {MAX_DEADLINE_MS} ms"),
                ));
            }
        }
        if !senders.is_empty() {
            if protection.is_none() {
                return Err(fixed(
                    RefusalKind::SendersWithoutProtection,
                    &senders_at,
                    "a receiver tells senders apart by the protection header",
                ));
            }
            for (j, sender) in senders.iter().enumerate() {
                if !publishers.contains(&sender.node) {
                    let item = senders_at.index(j);
                    return Err(Refusal::new(
                        RefusalKind::SenderNotPublisher,
                        &item.key("node"),
                        format!(
                            "`{}` does not publish the message",
                            self.nodes[sender.node].name
                        ),
                    ));
                }
            }
            if !instance_key.is_empty() {
                return Err(fixed(
                    RefusalKind::InstanceKeyWithSenders,
                    &instance_key_at,
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
        if let Some(protection) = &message.protection {
            let values_at = protection_at.key("values");
            judge
                .protection(
                    &self.e2e_profiles[protection.profile].tree,
                    &message,
                    &self.nodes,
                    limits.sender_slots,
                )
                .map_err(|refusal| match refusal {
                    ProtectionRefusal::Profile(reason) => {
                        Refusal::new(RefusalKind::E2eProfileInvalid, &values_at, reason)
                    }
                    ProtectionRefusal::Values(reason) => {
                        Refusal::new(RefusalKind::ValuesInvalid, &values_at, reason)
                    }
                    ProtectionRefusal::SendersUnsupported => fixed(
                        RefusalKind::SendersUnsupportedByProfile,
                        &senders_at,
                        "the profile's message cell names no sender part, or the part cannot \
                         hold every identity",
                    ),
                })?;
        }
        Ok(message)
    }

    fn read_protection(&self, value: &Json5Value, at: &Pointer<'_>) -> Result<Protection, Refusal> {
        let body = members(value, at, "protection")?;
        let profile_at = at.key("profile");
        let wanted = string(present(body, "profile"), &profile_at)?;
        let values = present(body, "values");
        object(values, &at.key("values"))?;
        let Some(profile) = self.e2e_profiles.iter().position(|d| d.name == wanted) else {
            return Err(Refusal::new(
                RefusalKind::UnknownE2eProfile,
                &profile_at,
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
        at: &Pointer<'_>,
        limits: Limits,
    ) -> Result<Vec<Sender>, Refusal> {
        let items = array(value, at)?;
        if items.is_empty() {
            return Err(fixed(RefusalKind::Empty, at, "the list names no sender"));
        }
        if items.len() > limits.sender_slots {
            return Err(Refusal::new(
                RefusalKind::TooManySenders,
                at,
                format!(
                    "{} senders, and the build's E2E_SENDER_SLOTS is {}",
                    items.len(),
                    limits.sender_slots
                ),
            ));
        }
        let mut read = Vec::with_capacity(items.len());
        for (j, item) in items.iter().enumerate() {
            let here = at.index(j);
            let body = members(item, &here, "sender")?;
            let node = string(present(body, "node"), &here.key("node"))?;
            let id = bounded(present(body, "id"), &here.key("id"), 0, u64::MAX, PLAIN)?;
            read.push((node, id));
        }
        let mut out: Vec<Sender> = Vec::with_capacity(read.len());
        for (j, &(wanted, id)) in read.iter().enumerate() {
            let here = at.index(j);
            let Some(node) = self.nodes.iter().position(|n| n.name == wanted) else {
                return Err(Refusal::new(
                    RefusalKind::UnknownNode,
                    &here.key("node"),
                    format!("no node is named `{wanted}`"),
                ));
            };
            if out.iter().any(|s| s.node == node || s.id == id) {
                return Err(Refusal::new(
                    RefusalKind::DuplicateSender,
                    &here,
                    format!("`{wanted}` or the identity {id} is stated twice"),
                ));
            }
            out.push(Sender { node, id });
        }
        Ok(out)
    }

    /// The nodes, in the catalog's order.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
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
}

fn read_nodes(value: &Json5Value) -> Result<Vec<Node>, Refusal> {
    let at = Pointer::text("/nodes");
    let items = array(value, &at)?;
    if items.is_empty() {
        return Err(fixed(
            RefusalKind::Empty,
            &at,
            "a catalog has at least one node",
        ));
    }
    if items.len() > MAX_NUMBERED {
        return Err(Refusal::new(
            RefusalKind::ValueOutOfRange,
            &at,
            format!("at most {MAX_NUMBERED} nodes"),
        ));
    }
    let mut out: Vec<Node> = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let here = at.index(i);
        let body = members(item, &here, "node")?;
        let name_at = here.key("name");
        let node_name = name(present(body, "name"), &name_at)?;
        let address = match get(body, "address") {
            Some(value) => Some(bounded(value, &here.key("address"), 0, u64::MAX, PLAIN)?),
            None => None,
        };
        if out.iter().any(|n| n.name == node_name) {
            return Err(Refusal::new(
                RefusalKind::DuplicateNode,
                &name_at,
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

fn read_supervision(value: &Json5Value, at: &Pointer<'_>) -> Result<Supervision, Refusal> {
    let body = members(value, at, "message_supervision")?;
    let factor = bounded(
        present(body, "factor"),
        &at.key("factor"),
        1,
        u16::MAX.into(),
        PLAIN,
    )? as u16;
    let awaited = match get(body, "awaited") {
        Some(value) => boolean(value, &at.key("awaited"))?,
        None => true,
    };
    Ok(Supervision { factor, awaited })
}

/// The instance key at `at`, within the build's `INSTANCE_KEY_FIELDS` and
/// `INSTANCES_PER_MESSAGE` as `limits` states them: the bounds a keyer of the message is made
/// under, so a catalog cannot declare an instance key its nodes would refuse to key by.
fn read_instance_key(
    value: &Json5Value,
    at: &Pointer<'_>,
    limits: Limits,
) -> Result<Vec<KeyField>, Refusal> {
    let items = array(value, at)?;
    if items.is_empty() {
        return Err(fixed(
            RefusalKind::Empty,
            at,
            "the instance key names no field",
        ));
    }
    if items.len() > limits.key_fields {
        return Err(Refusal::new(
            RefusalKind::TooManyKeyFields,
            at,
            format!(
                "{} fields, and the build's INSTANCE_KEY_FIELDS is {}",
                items.len(),
                limits.key_fields
            ),
        ));
    }
    let mut out: Vec<KeyField> = Vec::with_capacity(items.len());
    for (j, item) in items.iter().enumerate() {
        let here = at.index(j);
        let body = members(item, &here, "key_field")?;
        let field_at = here.key("field");
        let field = String::from(string(present(body, "field"), &field_at)?);
        if field.is_empty() {
            return Err(fixed(
                RefusalKind::Empty,
                &field_at,
                "the field is not named",
            ));
        }
        let values_at = here.key("values");
        let listed = array(present(body, "values"), &values_at)?;
        if listed.is_empty() {
            return Err(fixed(
                RefusalKind::Empty,
                &values_at,
                "the field takes no value",
            ));
        }
        let mut values: Vec<KeyValue> = Vec::with_capacity(listed.len());
        for (k, item) in listed.iter().enumerate() {
            let value_at = values_at.index(k);
            let value = match item {
                Json5Value::String(text) => KeyValue::Text(text.clone()),
                other => KeyValue::Number(uint(other, &value_at)?),
            };
            if values.contains(&value) {
                return Err(fixed(
                    RefusalKind::DuplicateInstanceKey,
                    &value_at,
                    "the value is listed twice",
                ));
            }
            values.push(value);
        }
        if out.iter().any(|f| f.field == field) {
            return Err(Refusal::new(
                RefusalKind::DuplicateInstanceKey,
                &field_at,
                format!("the field `{field}` is named twice"),
            ));
        }
        out.push(KeyField { field, values });
    }
    let instances = out
        .iter()
        .try_fold(1usize, |product, f| product.checked_mul(f.values.len()))
        .filter(|&product| product <= limits.instances);
    if instances.is_none() {
        return Err(Refusal::new(
            RefusalKind::TooManyInstances,
            at,
            format!(
                "the lists of values make more instances than the build's \
                 INSTANCES_PER_MESSAGE, {}",
                limits.instances
            ),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use wz_session_core::json5::Json5Value;

    use super::{
        read_catalog, CatalogJudge, CatalogPlan, Message, Node, ProtectionRefusal, Refusal,
        RefusalKind,
    };
    use crate::message_catalog_table::Limits;

    const LIMITS: Limits = Limits {
        messages: 4,
        replay_depth_max: 4,
        sender_slots: 2,
        key_fields: 2,
        instances: 8,
    };

    /// A judge that refuses every e2e profile with `profile` and every protection with
    /// `protection`, when they are set, and accepts everything else.
    struct Stub {
        profile: Option<&'static str>,
        protection: Option<ProtectionRefusal>,
    }

    const ACCEPTS: Stub = Stub {
        profile: None,
        protection: None,
    };

    impl CatalogJudge for Stub {
        fn e2e_profile(&self, _tree: &Json5Value) -> Result<(), String> {
            self.profile
                .map_or(Ok(()), |reason| Err(String::from(reason)))
        }

        fn segment_profile(&self, _tree: &Json5Value) -> Result<(), String> {
            Ok(())
        }

        fn protection(
            &self,
            _profile: &Json5Value,
            _message: &Message,
            _nodes: &[Node],
            _sender_slots: usize,
        ) -> Result<(), ProtectionRefusal> {
            self.protection.clone().map_or(Ok(()), Err)
        }
    }

    fn read(text: &str, judge: &Stub) -> Result<CatalogPlan, Refusal> {
        CatalogPlan::read(&read_catalog(text).expect("JSON5"), LIMITS, judge)
    }

    const PROTECTED: &str = "{nodes: [{name: 'north'}, {name: 'south'}], e2e_profiles: {p: {}}, \
         messages: [{key_expr: 'k/one', id: 1, publishers: ['north'], subscribers: ['south'], \
         protection: {profile: 'p', values: {}}}]}";

    #[test]
    fn an_accepted_catalog_holds_every_reference_as_an_index() {
        let plan = read(PROTECTED, &ACCEPTS).expect("accepted");
        assert_eq!(plan.nodes().len(), 2);
        assert_eq!(plan.e2e_profiles()[0].name, "p");
        let message = &plan.messages()[0];
        assert_eq!(message.publishers, [0]);
        assert_eq!(message.subscribers, [1]);
        assert_eq!(message.protection.as_ref().map(|p| p.profile), Some(0));
    }

    #[test]
    fn a_profile_the_judge_refuses_is_reported_before_any_message() {
        // The message names a node no node is: the profile comes first in the reading.
        let text = "{nodes: [{name: 'north'}], e2e_profiles: {p: {}}, \
             messages: [{key_expr: 'k', id: 1, publishers: ['nobody'], subscribers: []}]}";
        let judge = Stub {
            profile: Some("the profile is wrong"),
            protection: None,
        };
        let refusal = read(text, &judge).expect_err("refused");
        assert_eq!(refusal.kind, RefusalKind::E2eProfileInvalid);
        assert_eq!(refusal.path, "/e2e_profiles/p");
        assert_eq!(refusal.reason, "the profile is wrong");
        assert_eq!(
            read(text, &ACCEPTS).expect_err("refused").kind,
            RefusalKind::UnknownNode
        );
    }

    #[test]
    fn each_protection_refusal_is_named_at_its_place() {
        let cases = [
            (
                ProtectionRefusal::Profile(String::from("profile")),
                RefusalKind::E2eProfileInvalid,
                "/messages/0/protection/values",
                "profile",
            ),
            (
                ProtectionRefusal::Values(String::from("values")),
                RefusalKind::ValuesInvalid,
                "/messages/0/protection/values",
                "values",
            ),
            (
                ProtectionRefusal::SendersUnsupported,
                RefusalKind::SendersUnsupportedByProfile,
                "/messages/0/senders",
                "the profile's message cell names no sender part, or the part cannot hold every \
                 identity",
            ),
        ];
        for (answer, kind, path, reason) in cases {
            let judge = Stub {
                profile: None,
                protection: Some(answer),
            };
            let refusal = read(PROTECTED, &judge).expect_err("refused");
            assert_eq!((refusal.kind, refusal.path.as_str()), (kind, path));
            assert_eq!(refusal.reason, reason);
        }
    }

    #[test]
    fn a_protection_is_judged_after_the_rules_of_its_own_message() {
        // The second message repeats the first one's key: that is reported, and the judge, which
        // would refuse its protection, is not asked first.
        let text = "{nodes: [{name: 'north'}], e2e_profiles: {p: {}}, messages: [\
             {key_expr: 'k', id: 1, publishers: ['north'], subscribers: []}, \
             {key_expr: 'k', id: 2, publishers: ['north'], subscribers: [], \
              protection: {profile: 'p', values: {}}}]}";
        let judge = Stub {
            profile: None,
            protection: Some(ProtectionRefusal::SendersUnsupported),
        };
        let refusal = read(text, &judge).expect_err("refused");
        assert_eq!(refusal.kind, RefusalKind::DuplicateKeyExpr);
        assert_eq!(refusal.path, "/messages/1/key_expr");
    }
}
