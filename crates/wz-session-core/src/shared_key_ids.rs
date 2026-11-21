// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Key ids every node of a deployment shares: a dictionary, fixed ahead of time, that numbers key
//! expressions, so a message or a declaration may name its key by the id without a
//! `DeclareKeyExpr` first.
//!
//! # What the dictionary is on the wire
//!
//! zenoh numbers a key expression in the space of whoever declared it, and the `M` bit of a
//! wireexpr says which of a link's two spaces an id is in: set, the sender's; clear, the
//! receiver's. A dictionary every node of the deployment holds is a space both ends of every link
//! share, so an id it holds names the same key whichever bit carries it. A node sends such an id
//! with `M=1`, as it sends an id it declared, and declares nothing; the node that receives it
//! finds the key in its own copy. A stock peer has no copy, which is why every value of the
//! `key-wire-form` policy but `declared` is a deployment's explicit choice.
//!
//! # The rules it states once
//!
//! * An id the dictionary holds is reserved in this node's own space: the node declares no key
//!   expression under it ([`KeyIds::next_free_id`]), so an `M=0` id the dictionary holds cannot
//!   name anything else.
//! * A receiver reads an id in the space its `M` bit names first, as it does without the
//!   dictionary, and in the dictionary only when that space does not hold it
//!   (`MappingSpaces::with_shared` in `wireexpr_resolve`). A peer's own declaration of an id is
//!   read before the dictionary, so a peer that declares as upstream does is read as it always
//!   was, and the two declared spaces are still never read for each other.
//! * How a sender names a key is the `key-wire-form` policy ([`key_wire`]): `declared` is
//!   upstream's ([`KeyWire::Declared`], the sender does what it does without a dictionary),
//!   `literal` is the whole key, and `shared` is the cheapest of the dictionary's id, an id and
//!   the rest of the key, and the literal ([`KeyIds::shared_wire`]).
//! * Under `shared` a peer that announced itself a router is sent the declared form: a router
//!   keeps the mappings it was declared, and the dictionary is its peers' and clients'.
//! * A key with a wildcard chunk is sent by an id only when the dictionary holds that exact
//!   pattern, and is never cut into an id and a rest: a pattern is matched as a whole by whoever
//!   reads it, and the dictionary numbers the patterns a deployment uses as entries of their own.
//!   Without its exact entry it goes as the literal.
//! * Under `shared` a reply on the key of a query that came by an id of the dictionary mirrors
//!   the query ([`reply_key`]): the same id and rest, the `M` bit flipped, since the id is in the
//!   requester's space and the requester is the receiver of the reply. A link keeps the key form
//!   of such a query until its `Final` ([`LinkKeys`]); every other reply names its key whole.
//! * The form is the session's, and an endpoint the configuration dials or listens on may be
//!   stated a form of its own ([`LinkKeyForms`]): each link names its keys in the form of the
//!   endpoint it was dialled to or taken on.
//!
//! # Where it lives
//!
//! The dictionary is data an open is handed ([`KeyIdsAtOpen`]), held on the heap and shared by
//! every link of the session ([`SharedKeyIds`]); the session's `MAX_SHARED_KEY_IDS`
//! ([`crate::limits::SessionLimits`]) bounds how many entries an open may hand it
//! ([`KeyIdsAtOpen::check_limits`]). An image with no allocator has no dictionary yet.
//!
//! A configuration document states it as `wz/key-ids`, read with the rest of the document's `wz`
//! member (`crate::policy_document`), whose refusals it shares ([`crate::policy_document::KeyIdsReason`]).
//! What an open's caller states beside the document is composed over it
//! ([`KeyIdsAtOpen::over`]), as the policies are.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::json5::{number_as_u64, Json5Value};
use crate::keyexpr_canon::{validate_keyexpr, KeyexprRefusal};
use crate::keyexpr_match::is_wild;
use crate::limit_binding::Quota;
use crate::limits::SessionLimits;
use crate::policy::KeyWireForm;
use crate::policy_document::{KeyIdsReason, Origin, Reason, Refusal, Refusals};
use crate::wire_id::ExprId;

#[cfg(not(target_has_atomic = "ptr"))]
compile_error!(
    "the `shared-key-ids` feature of wz-session-core needs a target with atomic pointers: \
     a session's links share one dictionary through an `Arc`"
);

/// The dictionary as a session's links hold it: one copy, shared.
pub type SharedKeyIds = alloc::sync::Arc<KeyIds>;

/// Why a dictionary, or a form that needs one, was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyIdsRefused {
    /// More entries than the session's `MAX_SHARED_KEY_IDS` admits.
    TooMany {
        /// How many entries were given.
        stated: usize,
        /// How many the session's limit admits.
        limit: usize,
    },
    /// The entry at `at`, counted from 0 in the order given, names id 0, which is the literal's.
    ZeroId {
        /// The entry's place in the order given.
        at: usize,
    },
    /// Two entries name the same id.
    DuplicateId {
        /// The id named twice.
        id: ExprId,
    },
    /// Two entries name the same key.
    DuplicateKey {
        /// The key named twice.
        key: String,
    },
    /// The entry at `at` names a text that is not a canonical key expression.
    NotAKeyExpr {
        /// The entry's place in the order given.
        at: usize,
        /// Where and why the text stops being one.
        refusal: KeyexprRefusal,
    },
    /// The form is `shared`, for the session or for a link, and no dictionary was given.
    SharedWithoutDictionary,
    /// Two link statements name the same locator.
    DuplicateLink {
        /// The locator named twice.
        locator: String,
    },
}

impl fmt::Display for KeyIdsRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooMany { stated, limit } => write!(
                f,
                "the key-id dictionary has {stated} entries and the session's limit is {limit} \
                 (MAX_SHARED_KEY_IDS)"
            ),
            Self::ZeroId { at } => write!(
                f,
                "entry {at} of the key-id dictionary names id 0, which no key may have"
            ),
            Self::DuplicateId { id } => {
                write!(f, "the key-id dictionary names id {id} twice")
            }
            Self::DuplicateKey { key } => {
                write!(f, "the key-id dictionary names the key {key:?} twice")
            }
            Self::NotAKeyExpr { at, refusal } => write!(
                f,
                "entry {at} of the key-id dictionary is not a canonical key expression \
                 ({:?} at byte {})",
                refusal.fault, refusal.offset
            ),
            Self::SharedWithoutDictionary => f.write_str(
                "the key-wire form is `shared` and the session was given no key-id dictionary",
            ),
            Self::DuplicateLink { locator } => write!(
                f,
                "the key-wire form of the link {locator:?} is stated twice"
            ),
        }
    }
}

impl core::error::Error for KeyIdsRefused {}

/// One fault of a dictionary's entries, borrowed from them: the rules of a dictionary stated once,
/// for [`KeyIds::new`], which refuses the first, and for the reader of a document's
/// `wz/key-ids`, which reports each ([`read_document_member`]). How many entries a session may
/// hold is not a rule of the entries but of the session's limits ([`KeyIds::within`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault<'a> {
    ZeroId {
        at: usize,
    },
    NotAKeyExpr {
        at: usize,
        key: &'a str,
        refusal: KeyexprRefusal,
    },
    DuplicateId {
        id: ExprId,
    },
    DuplicateKey {
        key: &'a str,
    },
}

impl<'a> Fault<'a> {
    /// The fault as an open's door refuses it.
    fn refused(self) -> KeyIdsRefused {
        match self {
            Self::ZeroId { at } => KeyIdsRefused::ZeroId { at },
            Self::NotAKeyExpr { at, refusal, .. } => KeyIdsRefused::NotAKeyExpr { at, refusal },
            Self::DuplicateId { id } => KeyIdsRefused::DuplicateId { id },
            Self::DuplicateKey { key } => KeyIdsRefused::DuplicateKey {
                key: String::from(key),
            },
        }
    }

    /// The fault as a document's reader reports it.
    fn reason(self) -> KeyIdsReason<'a> {
        match self {
            Self::ZeroId { at } => KeyIdsReason::ZeroId { at },
            Self::NotAKeyExpr { at, key, refusal } => {
                KeyIdsReason::NotAKeyExpr { at, key, refusal }
            }
            Self::DuplicateId { id } => KeyIdsReason::DuplicateId { id },
            Self::DuplicateKey { key } => KeyIdsReason::DuplicateKey { key },
        }
    }
}

/// Each fault of the entries of a dictionary, those read whole, each with its place among them,
/// its id and its key: each entry's own faults in their order (id 0, then a key that is not a
/// canonical key expression), then each id and each key named more than once, ascending, once
/// each. An id 0 named twice is refused as id 0 and not again as a duplicate.
pub(crate) fn dictionary_faults<'a>(
    entries: &[(usize, ExprId, &'a str)],
    mut report: impl FnMut(Fault<'a>),
) {
    for &(at, id, key) in entries {
        if id == 0 {
            report(Fault::ZeroId { at });
        }
        if let Err(refusal) = validate_keyexpr(key) {
            report(Fault::NotAKeyExpr { at, key, refusal });
        }
    }
    let mut ids: Vec<ExprId> = entries
        .iter()
        .map(|&(_, id, _)| id)
        .filter(|id| *id != 0)
        .collect();
    ids.sort_unstable();
    for (index, pair) in ids.windows(2).enumerate() {
        let repeated = pair[0] == pair[1];
        if repeated && (index == 0 || ids[index - 1] != pair[0]) {
            report(Fault::DuplicateId { id: pair[0] });
        }
    }
    let mut keys: Vec<&'a str> = entries.iter().map(|&(_, _, key)| key).collect();
    keys.sort_unstable();
    for (index, pair) in keys.windows(2).enumerate() {
        let repeated = pair[0] == pair[1];
        if repeated && (index == 0 || keys[index - 1] != pair[0]) {
            report(Fault::DuplicateKey { key: pair[0] });
        }
    }
}

/// One entry: an id and the key it names.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    id: ExprId,
    key: String,
}

/// The dictionary: key expressions numbered ahead of time, the same on every node of a deployment.
///
/// Built once and read only. Both reads are binary searches: an id to its key (what a receiver
/// asks) and a key to its id (what a sender asks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyIds {
    /// Ascending by id.
    entries: Vec<Entry>,
    /// Indexes into `entries`, ascending by the bytes of their keys.
    by_key: Vec<usize>,
}

impl KeyIds {
    /// The dictionary of `entries`, each an id and the key it names. Refused when an id is 0 or
    /// named twice, when a key is named twice, and when a key is not a canonical key expression;
    /// the order the entries are given in does not matter. How many entries a session may be
    /// handed is its limits', judged when the dictionary is handed over ([`Self::within`]).
    pub fn new<'a>(
        entries: impl IntoIterator<Item = (ExprId, &'a str)>,
    ) -> Result<Self, KeyIdsRefused> {
        let given: Vec<(usize, ExprId, &str)> = entries
            .into_iter()
            .enumerate()
            .map(|(at, (id, key))| (at, id, key))
            .collect();
        let mut first = None;
        dictionary_faults(&given, |fault| {
            first.get_or_insert(fault);
        });
        if let Some(fault) = first {
            return Err(fault.refused());
        }
        let mut rows: Vec<Entry> = given
            .into_iter()
            .map(|(_, id, key)| Entry {
                id,
                key: String::from(key),
            })
            .collect();
        rows.sort_unstable_by_key(|entry| entry.id);
        let mut by_key: Vec<usize> = (0..rows.len()).collect();
        by_key.sort_unstable_by(|a, b| rows[*a].key.as_bytes().cmp(rows[*b].key.as_bytes()));
        Ok(Self {
            entries: rows,
            by_key,
        })
    }

    /// Whether a session whose `MAX_SHARED_KEY_IDS` is `quota` may hold the dictionary: refused
    /// as [`KeyIdsRefused::TooMany`] when it has more entries than the quota admits.
    pub fn within(&self, quota: Quota) -> Result<(), KeyIdsRefused> {
        if quota.admits(self.len()) {
            return Ok(());
        }
        Err(KeyIdsRefused::TooMany {
            stated: self.len(),
            // A quota that refuses a count has a bound.
            limit: quota.most().unwrap_or(usize::MAX),
        })
    }

    /// Each entry, its id and its key, ascending by id.
    pub fn iter(&self) -> impl Iterator<Item = (ExprId, &str)> + '_ {
        self.entries
            .iter()
            .map(|entry| (entry.id, entry.key.as_str()))
    }

    /// How many entries the dictionary holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the dictionary holds no entry.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The key `id` names, or `None` when the dictionary does not hold it.
    pub fn key_of(&self, id: ExprId) -> Option<&str> {
        self.entries
            .binary_search_by_key(&id, |entry| entry.id)
            .ok()
            .map(|at| self.entries[at].key.as_str())
    }

    /// The id of `key`, or `None` when the dictionary does not hold it. The key is compared as it
    /// is written: a key is in the dictionary when its text is.
    pub fn id_of(&self, key: &str) -> Option<ExprId> {
        self.by_key
            .binary_search_by(|at| self.entries[*at].key.as_bytes().cmp(key.as_bytes()))
            .ok()
            .map(|place| self.entries[self.by_key[place]].id)
    }

    /// Whether `id` is one of the dictionary's, and so not one this node may declare a key
    /// expression under.
    pub fn reserves(&self, id: ExprId) -> bool {
        self.key_of(id).is_some()
    }

    /// The first id from `from` on that the dictionary does not hold: the id a node that holds
    /// the dictionary declares its next key expression under. `None` when `from` is 0 (a spent
    /// counter) or every id from it on is the dictionary's.
    pub fn next_free_id(&self, from: ExprId) -> Option<ExprId> {
        let mut id = from;
        loop {
            if id == 0 {
                return None;
            }
            if !self.reserves(id) {
                return Some(id);
            }
            id = id.checked_add(1)?;
        }
    }

    /// The longest entry that covers a prefix of `key` up to one of its `/`, and the rest of the
    /// key from that `/` on. A wildcard key has none (see the module documentation).
    fn longest_prefix<'k>(&self, key: &'k str) -> Option<(ExprId, &'k str)> {
        if is_wild(key) {
            return None;
        }
        let bytes = key.as_bytes();
        let mut end = bytes.len();
        while let Some(slash) = bytes[..end].iter().rposition(|byte| *byte == b'/') {
            // `/` is one byte of UTF-8, so both halves are on a character boundary.
            if let Some(id) = self.id_of(&key[..slash]) {
                return Some((id, &key[slash..]));
            }
            end = slash;
        }
        None
    }

    /// How `key` goes on the wire under `shared`: whichever of its id, an id and the rest of the
    /// key, and the literal costs the fewest bytes of wireexpr, the id first and the literal last
    /// when two cost the same.
    pub fn shared_wire<'k>(&self, key: &'k str) -> KeyWire<'k> {
        let literal = literal_cost(key);
        if let Some(id) = self.id_of(key) {
            if id_cost(id, None) <= literal {
                return KeyWire::Shared { id, suffix: None };
            }
        }
        match self.longest_prefix(key) {
            Some((id, rest)) if id_cost(id, Some(rest)) <= literal => KeyWire::Shared {
                id,
                suffix: Some(rest),
            },
            _ => KeyWire::Literal,
        }
    }
}

/// How a sender names a key on the wire to one peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyWire<'k> {
    /// As the sender names it without a dictionary: the key expression it declared, or the
    /// literal. This is upstream's form, and the bytes are the ones a build without the
    /// dictionary sends.
    Declared,
    /// The whole key, under id 0.
    Literal,
    /// The dictionary's id with `M=1`, and the rest of the key after the entry when the entry
    /// covers a prefix of it. No declaration precedes it.
    Shared {
        /// The dictionary's id.
        id: ExprId,
        /// The rest of the key, from the `/` after the entry; `None` when the entry is the key.
        suffix: Option<&'k str>,
    },
}

/// How `key` goes on the wire to a peer under `form`, the `key-wire-form` policy's value for the
/// link to it. `peer_is_router` is what the peer announced at its handshake: a router is sent the
/// declared form under `shared`.
pub fn key_wire<'k>(
    form: KeyWireForm,
    ids: &KeyIds,
    key: &'k str,
    peer_is_router: bool,
) -> KeyWire<'k> {
    match form {
        KeyWireForm::Declared => KeyWire::Declared,
        KeyWireForm::Literal => KeyWire::Literal,
        KeyWireForm::Shared if peer_is_router => KeyWire::Declared,
        KeyWireForm::Shared => ids.shared_wire(key),
    }
}

/// Whether a session may open under `form` with the dictionary `ids`: `shared` needs one, and the
/// other two do not.
pub fn check_open(form: KeyWireForm, ids: Option<&KeyIds>) -> Result<(), KeyIdsRefused> {
    match (form, ids) {
        (KeyWireForm::Shared, None) => Err(KeyIdsRefused::SharedWithoutDictionary),
        _ => Ok(()),
    }
}

/// The key a request was sent under, as it arrived: its id (0 for a literal), the rest of the key
/// after the id, and its `M` bit (`sender_mapping`: the id is in the requester's space).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestKey<'k> {
    /// The id, 0 for a literal.
    pub id: ExprId,
    /// What followed the id.
    pub suffix: Option<&'k str>,
    /// The `M` bit: set when the id is in the sender's space.
    pub sender_mapping: bool,
}

/// How a reply names its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyKey<'k> {
    /// The whole key, under id 0: what a reply carries without the dictionary.
    Literal,
    /// The request's id and rest, with the `M` bit the reply's sender gives it.
    Mirrored {
        /// The request's id.
        id: ExprId,
        /// The rest of the key after the id, as the request carried it.
        suffix: Option<&'k str>,
        /// The reply's `M` bit, the request's flipped.
        sender_mapping: bool,
    },
}

/// How a reply on `reply` to a request on `query_key` names its key under `form`, the
/// `key-wire-form` policy's value for the link the request came on.
///
/// Under `shared` a reply on the query's own key repeats the request's form: an id in the
/// requester's space, which the requester sent with `M=1` as the space of the sender and reads
/// back with `M=0` as the space of the receiver. Any other reply, a request sent as the literal,
/// and every other form keep the literal.
pub fn reply_key<'k>(
    form: KeyWireForm,
    request: RequestKey<'_>,
    query_key: &str,
    reply: &'k str,
) -> ReplyKey<'k> {
    if form != KeyWireForm::Shared || request.id == 0 || reply != query_key {
        return ReplyKey::Literal;
    }
    // The request's rest is the tail of the query's key, which is the reply's key.
    let rest_len = request.suffix.map_or(0, str::len);
    let Some(rest) = reply
        .len()
        .checked_sub(rest_len)
        .and_then(|start| reply.get(start..))
    else {
        return ReplyKey::Literal;
    };
    ReplyKey::Mirrored {
        id: request.id,
        suffix: (!rest.is_empty()).then_some(rest),
        sender_mapping: !request.sender_mapping,
    }
}

/// The `key-wire-form` of each link of a session: the session's value, and the links whose value
/// a deployment states apart from it, each named by its locator as the configuration writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkKeyForms {
    session: KeyWireForm,
    links: Vec<(String, KeyWireForm)>,
}

impl LinkKeyForms {
    /// The forms of a session whose links take `session` but those `links` name. Refused when a
    /// locator is named twice, or when any of the forms is `shared` and `ids` is `None`.
    pub fn new(
        session: KeyWireForm,
        links: Vec<(String, KeyWireForm)>,
        ids: Option<&KeyIds>,
    ) -> Result<Self, KeyIdsRefused> {
        check_open(session, ids)?;
        for (at, (locator, form)) in links.iter().enumerate() {
            check_open(*form, ids)?;
            if links[..at].iter().any(|(other, _)| other == locator) {
                return Err(KeyIdsRefused::DuplicateLink {
                    locator: locator.clone(),
                });
            }
        }
        Ok(Self { session, links })
    }

    /// The form of the link to `locator`: the one stated for it, or the session's. A link whose
    /// locator is not known takes the session's.
    pub fn form_of(&self, locator: Option<&str>) -> KeyWireForm {
        locator
            .and_then(|locator| {
                self.links
                    .iter()
                    .find(|(stated, _)| stated == locator)
                    .map(|(_, form)| *form)
            })
            .unwrap_or(self.session)
    }

    /// Every link at `session`, no link stated apart and nothing checked: the forms of a session
    /// opened with no key ids, whose open refuses `shared` before any link exists.
    pub fn session_only(session: KeyWireForm) -> Self {
        Self {
            session,
            links: Vec::new(),
        }
    }

    /// The session's form, which a link no statement names takes.
    pub fn session(&self) -> KeyWireForm {
        self.session
    }

    /// Whether any link of the session may name a key otherwise than upstream does: a form other
    /// than `declared`, for the session or for a link.
    pub fn departs_from_declared(&self) -> bool {
        self.session != KeyWireForm::Declared
            || self
                .links
                .iter()
                .any(|(_, form)| *form != KeyWireForm::Declared)
    }
}

/// What a session is opened with: the dictionary, when it is given one, and the links whose
/// key-wire form a deployment states apart from the session's (`wz_ext_config_key_wire_form_for`),
/// each named by the locator the configuration dials or listens on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyIdsAtOpen {
    /// The dictionary.
    pub ids: Option<SharedKeyIds>,
    /// The links' own forms, by locator.
    pub links: Vec<(String, KeyWireForm)>,
}

impl KeyIdsAtOpen {
    /// The forms of the session's links when the session's own form is `session`: refused as
    /// [`LinkKeyForms::new`] refuses.
    pub fn forms(&self, session: KeyWireForm) -> Result<LinkKeyForms, KeyIdsRefused> {
        LinkKeyForms::new(session, self.links.clone(), self.ids.as_deref())
    }

    /// Whether a session opened under `limits` may be handed the dictionary: refused as
    /// [`KeyIds::within`] refuses it under the session's `MAX_SHARED_KEY_IDS`. No dictionary is
    /// within every limit.
    pub fn check_limits(&self, limits: &SessionLimits) -> Result<(), KeyIdsRefused> {
        match self.ids.as_deref() {
            Some(ids) => ids.within(limits.max_shared_key_ids()),
            None => Ok(()),
        }
    }

    /// State `form` for the link to `locator`, in place of a form stated for it before.
    pub fn set_link(&mut self, locator: &str, form: KeyWireForm) {
        self.links.retain(|(stated, _)| stated != locator);
        self.links.push((String::from(locator), form));
    }

    /// What the open's caller states (`self`) over what the configuration document states
    /// (`document`), the order the policies are composed in: the caller's dictionary in place of
    /// the document's when the caller states one, and the form the caller states for an endpoint
    /// in place of the document's for the same endpoint. What the caller does not state is the
    /// document's.
    pub fn over(&self, document: KeyIdsAtOpen) -> KeyIdsAtOpen {
        let mut composed = document;
        if let Some(ids) = &self.ids {
            composed.ids = Some(ids.clone());
        }
        for (locator, form) in &self.links {
            composed.set_link(locator, *form);
        }
        composed
    }
}

/// The two lists of `wz/key-ids`, by the paths a refusal names them with.
const DICTIONARY: &str = "wz/key-ids/dictionary";
const LINKS: &str = "wz/key-ids/links";

/// The key ids the `wz/key-ids` member `value` of a document states, each refusal of it pushed
/// onto `refusals` as the document's ([`KeyIdsReason`]): the reader of the `wz` member
/// (`crate::policy_document`) calls it, so a refused part of the member refuses the document as
/// a refused policy does. `in_domain` is the build's domain of `key-wire-form`
/// ([`form_in_domain`]). What it returns is the caller's to drop when a refusal was pushed.
///
/// `dictionary` is a list of `{ id, key }` and `links` a list of `{ locator, form }`; either may
/// be left out. An empty dictionary is no dictionary, as the door that hands one over with no
/// entry takes one back.
pub(crate) fn read_document_member<'a>(
    value: &'a Json5Value,
    in_domain: impl Fn(KeyWireForm) -> bool,
    refusals: &mut Refusals<'a>,
) -> KeyIdsAtOpen {
    let mut read = KeyIdsAtOpen::default();
    let Json5Value::Object(members) = value else {
        refusals.push(Refusal {
            layer: Origin::Document,
            reason: Reason::NotAnObject {
                member: "wz/key-ids",
            },
        });
        return read;
    };
    let (mut dictionary, mut links) = (false, false);
    for (key, value) in members {
        match key.as_str() {
            "dictionary" => {
                if dictionary {
                    refusals.push(Refusal {
                        layer: Origin::Document,
                        reason: Reason::MemberStatedTwice { member: DICTIONARY },
                    });
                }
                dictionary = true;
                read.ids = read_dictionary(value, refusals);
            }
            "links" => {
                if links {
                    refusals.push(Refusal {
                        layer: Origin::Document,
                        reason: Reason::MemberStatedTwice { member: LINKS },
                    });
                }
                links = true;
                read.links = read_links(value, &in_domain, refusals);
            }
            other => refuse(refusals, KeyIdsReason::UnknownMember { member: other }),
        }
    }
    read
}

/// `reason` pushed onto `refusals` as the document's.
fn refuse<'a>(refusals: &mut Refusals<'a>, reason: KeyIdsReason<'a>) {
    refusals.push(Refusal {
        layer: Origin::Document,
        reason: Reason::KeyIds(reason),
    });
}

/// The dictionary `wz/key-ids/dictionary` states, or `None` when it states no entry or a
/// refusal of it was pushed.
fn read_dictionary<'a>(value: &'a Json5Value, refusals: &mut Refusals<'a>) -> Option<SharedKeyIds> {
    let Json5Value::Array(items) = value else {
        refuse(refusals, KeyIdsReason::NotAnArray { member: DICTIONARY });
        return None;
    };
    let found_before = refusals.found();
    let mut entries: Vec<(usize, ExprId, &'a str)> = Vec::with_capacity(items.len());
    for (at, item) in items.iter().enumerate() {
        let Some((id, key)) = two_fields(DICTIONARY, at, item, ["id", "key"], refusals) else {
            continue;
        };
        let id = match id {
            Json5Value::Number(text) => {
                number_as_u64(text).and_then(|number| ExprId::try_from(number).ok())
            }
            _ => None,
        };
        if id.is_none() {
            refuse(refusals, KeyIdsReason::NotAnId { at });
        }
        let key = match key {
            Json5Value::String(text) => Some(text.as_str()),
            _ => {
                refuse(
                    refusals,
                    KeyIdsReason::NotAString {
                        member: DICTIONARY,
                        at,
                        field: "key",
                    },
                );
                None
            }
        };
        if let (Some(id), Some(key)) = (id, key) {
            entries.push((at, id, key));
        }
    }
    // How many entries the document may state is the limit it resolves to, which the resolution
    // judges once the limits are composed (`crate::policy_document`).
    dictionary_faults(&entries, |fault| refuse(refusals, fault.reason()));
    if refusals.found() != found_before || entries.is_empty() {
        return None;
    }
    KeyIds::new(entries.iter().map(|&(_, id, key)| (id, key)))
        .ok()
        .map(alloc::sync::Arc::new)
}

/// The endpoints' forms `wz/key-ids/links` states, in its order.
fn read_links<'a>(
    value: &'a Json5Value,
    in_domain: &impl Fn(KeyWireForm) -> bool,
    refusals: &mut Refusals<'a>,
) -> Vec<(String, KeyWireForm)> {
    let mut links = Vec::new();
    let Json5Value::Array(items) = value else {
        refuse(refusals, KeyIdsReason::NotAnArray { member: LINKS });
        return links;
    };
    let mut stated: Vec<&'a str> = Vec::with_capacity(items.len());
    for (at, item) in items.iter().enumerate() {
        let Some((locator, form)) = two_fields(LINKS, at, item, ["locator", "form"], refusals)
        else {
            continue;
        };
        let locator = match locator {
            Json5Value::String(text) if text.is_empty() => {
                refuse(refusals, KeyIdsReason::EmptyLocator { at });
                None
            }
            Json5Value::String(text) => Some(text.as_str()),
            _ => {
                refuse(
                    refusals,
                    KeyIdsReason::NotAString {
                        member: LINKS,
                        at,
                        field: "locator",
                    },
                );
                None
            }
        };
        let form = match form {
            Json5Value::String(text) => Some(text.as_str()),
            _ => {
                refuse(
                    refusals,
                    KeyIdsReason::NotAString {
                        member: LINKS,
                        at,
                        field: "form",
                    },
                );
                None
            }
        };
        let (Some(locator), Some(form)) = (locator, form) else {
            continue;
        };
        if stated.contains(&locator) {
            refuse(refusals, KeyIdsReason::LinkStatedTwice { locator });
            continue;
        }
        stated.push(locator);
        match key_wire_form_named(form) {
            None => refuse(refusals, KeyIdsReason::UnknownForm { locator, form }),
            Some(named) if !in_domain(named) => {
                refuse(refusals, KeyIdsReason::FormOutsideDomain { locator, form });
            }
            Some(named) => links.push((String::from(locator), named)),
        }
    }
    links
}

/// The two fields `names` of entry `at` of the list `member`, or `None` with each refusal of
/// its shape pushed: an entry that is not an object, a field it lacks, a field the entries of
/// the list do not have, a field stated twice.
fn two_fields<'a>(
    member: &'static str,
    at: usize,
    item: &'a Json5Value,
    names: [&'static str; 2],
    refusals: &mut Refusals<'a>,
) -> Option<(&'a Json5Value, &'a Json5Value)> {
    let Json5Value::Object(fields) = item else {
        refuse(refusals, KeyIdsReason::EntryNotAnObject { member, at });
        return None;
    };
    let mut found: [Option<&'a Json5Value>; 2] = [None, None];
    let mut whole = true;
    for (field, value) in fields {
        match names.iter().position(|name| *name == field.as_str()) {
            Some(index) if found[index].is_some() => {
                refuse(
                    refusals,
                    KeyIdsReason::FieldStatedTwice {
                        member,
                        at,
                        field: names[index],
                    },
                );
                whole = false;
            }
            Some(index) => found[index] = Some(value),
            None => {
                refuse(
                    refusals,
                    KeyIdsReason::UnknownField {
                        member,
                        at,
                        field: field.as_str(),
                    },
                );
                whole = false;
            }
        }
    }
    for (name, value) in names.into_iter().zip(found) {
        if value.is_none() {
            refuse(
                refusals,
                KeyIdsReason::MissingField {
                    member,
                    at,
                    field: name,
                },
            );
        }
    }
    match found {
        [Some(first), Some(second)] if whole => Some((first, second)),
        _ => None,
    }
}

/// The value of `key-wire-form` the text names, as the declaration spells it.
pub fn key_wire_form_named(text: &str) -> Option<KeyWireForm> {
    [
        KeyWireForm::Declared,
        KeyWireForm::Shared,
        KeyWireForm::Literal,
    ]
    .into_iter()
    .find(|form| form.id() == text)
}

/// Whether the build's domain of `key-wire-form` allows `form`: what a statement of the value
/// for one link is held to, as a statement for the session is.
/// It reads the domain the build narrowed the policy to, not the build's default value.
pub fn form_in_domain(form: KeyWireForm) -> bool {
    <KeyWireForm as crate::policy_binding::PolicyValue>::DOMAIN.contains(form)
}

/// The key form a request arrived under, kept until its `Final` for the replies that mirror it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NotedRequest {
    id: ExprId,
    suffix: Option<String>,
    sender_mapping: bool,
}

/// What one link knows of the key ids: the dictionary, the link's key-wire form, and the key form
/// of the queries it is answering. Held by the link's session, installed by the engine that opened
/// it before the link carries anything.
#[derive(Debug, Clone)]
pub struct LinkKeys {
    ids: Option<SharedKeyIds>,
    form: KeyWireForm,
    requests: Vec<(crate::wire_id::RequestId, NotedRequest)>,
    /// How many queries the link remembers the key form of at once: a query that is never ended
    /// gives way to the newest, so a peer cannot grow the table. The peer's queries, not this
    /// node's, so a limit of its own and not `MAX_PENDING_QUERIES`.
    noted_requests: usize,
}

impl LinkKeys {
    /// A link that holds `ids`, names keys as `form` says, and remembers the key form of at most
    /// `noted_requests` queries, the session's `LINK_NOTED_REQUESTS`
    /// ([`crate::limits::SessionLimits::link_noted_requests`]). `0` is read as 1, the least the
    /// declaration's range allows.
    pub fn new(ids: Option<SharedKeyIds>, form: KeyWireForm, noted_requests: usize) -> Self {
        Self {
            ids,
            form,
            requests: Vec::new(),
            noted_requests: noted_requests.max(1),
        }
    }

    /// The dictionary, when the link holds one.
    pub fn ids(&self) -> Option<&KeyIds> {
        self.ids.as_deref()
    }

    /// The dictionary as the session's links share it, when the link holds one.
    pub fn shared_ids(&self) -> Option<&SharedKeyIds> {
        self.ids.as_ref()
    }

    /// The link's key-wire form.
    pub fn form(&self) -> KeyWireForm {
        self.form
    }

    /// How the link names `key` to its peer, which `peer_is_router` says it announced itself as.
    /// With no dictionary the shared form cannot be the link's (its open refused it), so the
    /// answer is the literal or the declared form.
    pub fn key_wire<'k>(&self, key: &'k str, peer_is_router: bool) -> KeyWire<'k> {
        match self.ids.as_deref() {
            Some(ids) => key_wire(self.form, ids, key, peer_is_router),
            None if self.form == KeyWireForm::Literal => KeyWire::Literal,
            None => KeyWire::Declared,
        }
    }

    /// Keep the key form of the request `rid` that arrived as `(id, suffix)` with the mapping bit
    /// `sender_mapping`, when a reply to it may mirror it: the link's form is `shared`, the peer
    /// is no router and the id is one of the dictionary's. The oldest kept gives way once the
    /// link keeps as many as it was made with ([`Self::new`]).
    pub fn note_request(
        &mut self,
        rid: crate::wire_id::RequestId,
        id: ExprId,
        suffix: Option<&str>,
        sender_mapping: bool,
        peer_is_router: bool,
    ) {
        if self.form != KeyWireForm::Shared || peer_is_router || id == 0 {
            return;
        }
        if !self.ids.as_deref().is_some_and(|ids| ids.reserves(id)) {
            return;
        }
        self.requests.retain(|(noted, _)| *noted != rid);
        if self.requests.len() >= self.noted_requests {
            self.requests.remove(0);
        }
        self.requests.push((
            rid,
            NotedRequest {
                id,
                suffix: suffix.map(String::from),
                sender_mapping,
            },
        ));
    }

    /// How a reply on `reply` to the request `rid` names its key: mirrored ([`reply_key`]) when
    /// the request was kept and `reply` is the key it named, the dictionary's entry followed by
    /// its rest; the literal otherwise.
    pub fn reply_key<'r>(&self, rid: crate::wire_id::RequestId, reply: &'r str) -> ReplyKey<'r> {
        let Some(ids) = self.ids.as_deref() else {
            return ReplyKey::Literal;
        };
        let Some((_, noted)) = self.requests.iter().find(|(kept, _)| *kept == rid) else {
            return ReplyKey::Literal;
        };
        let Some(base) = ids.key_of(noted.id) else {
            return ReplyKey::Literal;
        };
        let rest = noted.suffix.as_deref().unwrap_or("");
        let named = reply.len() == base.len() + rest.len()
            && reply.starts_with(base)
            && reply.ends_with(rest);
        if !named {
            return ReplyKey::Literal;
        }
        let request = RequestKey {
            id: noted.id,
            suffix: noted.suffix.as_deref(),
            sender_mapping: noted.sender_mapping,
        };
        reply_key(self.form, request, reply, reply)
    }

    /// The request `rid` is ended: its key form is not kept any more.
    pub fn forget_request(&mut self, rid: crate::wire_id::RequestId) {
        self.requests.retain(|(noted, _)| *noted != rid);
    }
}

/// The bytes a VLE of `value` takes on the wire: seven bits of it per byte.
const fn vle_len(value: u64) -> usize {
    let mut len = 1;
    let mut rest = value >> 7;
    while rest != 0 {
        len += 1;
        rest >>= 7;
    }
    len
}

/// The bytes of a wireexpr that names `key` as the literal: id 0, the length, the text.
fn literal_cost(key: &str) -> usize {
    vle_len(0) + vle_len(key.len() as u64) + key.len()
}

/// The bytes of a wireexpr that names `id`, and `rest` after it when there is one.
fn id_cost(id: ExprId, rest: Option<&str>) -> usize {
    vle_len(u64::from(id)) + rest.map_or(0, |rest| vle_len(rest.len() as u64) + rest.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    /// A synthetic dictionary: a pattern, a key that is a prefix of others, and a key below it.
    fn dictionary() -> KeyIds {
        KeyIds::new([(17, "lab/*/beta"), (9, "lab/rig"), (3, "lab/rig/alpha")])
            .expect("a valid dictionary")
    }

    #[test]
    fn an_id_reads_as_its_key_and_a_key_as_its_id() {
        let ids = dictionary();
        assert_eq!(ids.len(), 3);
        assert_eq!(ids.key_of(3), Some("lab/rig/alpha"));
        assert_eq!(ids.key_of(9), Some("lab/rig"));
        assert_eq!(ids.key_of(17), Some("lab/*/beta"));
        assert_eq!(ids.key_of(4), None, "an id no entry names");
        assert_eq!(ids.id_of("lab/rig"), Some(9));
        assert_eq!(ids.id_of("lab/*/beta"), Some(17));
        assert_eq!(
            ids.id_of("lab/rig/"),
            None,
            "a key is in the dictionary when its text is"
        );
    }

    #[test]
    fn a_dictionary_is_refused_for_each_fault_by_name() {
        assert_eq!(
            KeyIds::new([(1, "lab/a"), (0, "lab/b")]),
            Err(KeyIdsRefused::ZeroId { at: 1 })
        );
        assert_eq!(
            KeyIds::new([(5, "lab/a"), (5, "lab/b")]),
            Err(KeyIdsRefused::DuplicateId { id: 5 })
        );
        assert_eq!(
            KeyIds::new([(5, "lab/a"), (6, "lab/a")]),
            Err(KeyIdsRefused::DuplicateKey {
                key: "lab/a".to_string()
            })
        );
        assert!(matches!(
            KeyIds::new([(5, "lab/a"), (6, "lab//b")]),
            Err(KeyIdsRefused::NotAKeyExpr { at: 1, .. })
        ));
        assert!(matches!(
            KeyIds::new([(5, "lab/**/*")]),
            Err(KeyIdsRefused::NotAKeyExpr { at: 0, .. }),
        ));
    }

    #[test]
    fn a_dictionary_over_the_quota_a_session_holds_is_refused_and_one_at_it_is_not() {
        let three = KeyIds::new([(1, "lab/a"), (2, "lab/b"), (3, "lab/c")]).expect("valid");
        assert_eq!(
            three.within(Quota::at_most(2)),
            Err(KeyIdsRefused::TooMany {
                stated: 3,
                limit: 2
            })
        );
        assert_eq!(
            three.within(Quota::at_most(3)),
            Ok(()),
            "CONTROL: as many entries as the quota is not too many"
        );
        assert_eq!(three.within(Quota::UNBOUNDED), Ok(()));
    }

    #[test]
    fn a_node_declares_under_no_id_of_the_dictionary() {
        let ids = KeyIds::new([(1, "lab/a"), (2, "lab/b"), (4, "lab/c")]).expect("valid");
        assert_eq!(ids.next_free_id(1), Some(3));
        assert_eq!(ids.next_free_id(3), Some(3));
        assert_eq!(ids.next_free_id(4), Some(5));
        assert_eq!(ids.next_free_id(0), None, "a spent counter stays spent");
        let top = KeyIds::new([(u16::MAX, "lab/top")]).expect("valid");
        assert_eq!(
            top.next_free_id(u16::MAX),
            None,
            "no id is left past the last"
        );
        assert_eq!(top.next_free_id(u16::MAX - 1), Some(u16::MAX - 1));
    }

    #[test]
    fn a_key_the_dictionary_holds_goes_as_its_id_alone() {
        assert_eq!(
            dictionary().shared_wire("lab/rig/alpha"),
            KeyWire::Shared {
                id: 3,
                suffix: None
            }
        );
    }

    #[test]
    fn a_key_below_an_entry_goes_as_the_longest_entrys_id_and_the_rest() {
        let ids = KeyIds::new([(2, "lab"), (9, "lab/rig")]).expect("valid");
        assert_eq!(
            ids.shared_wire("lab/rig/gamma/x"),
            KeyWire::Shared {
                id: 9,
                suffix: Some("/gamma/x")
            }
        );
        assert_eq!(
            ids.shared_wire("lab/other"),
            KeyWire::Shared {
                id: 2,
                suffix: Some("/other")
            }
        );
    }

    #[test]
    fn an_entry_covers_a_prefix_only_up_to_a_chunk_boundary() {
        assert_eq!(
            dictionary().shared_wire("lab/rigger/x"),
            KeyWire::Literal,
            "`lab/rig` is not a chunk of `lab/rigger`"
        );
    }

    #[test]
    fn a_wildcard_key_goes_by_id_only_as_an_exact_entry() {
        let ids = dictionary();
        assert_eq!(
            ids.shared_wire("lab/*/beta"),
            KeyWire::Shared {
                id: 17,
                suffix: None
            }
        );
        assert_eq!(
            ids.shared_wire("lab/rig/*"),
            KeyWire::Literal,
            "a pattern is not cut into `lab/rig` and `/*`"
        );
        assert_eq!(ids.shared_wire("lab/rig/**"), KeyWire::Literal);
    }

    #[test]
    fn the_cheaper_of_an_id_and_the_literal_is_sent() {
        // `a/b` as the literal is 1 + 1 + 3 = 5 bytes; id 20000 takes three bytes of VLE, and
        // with the rest `/b` (1 + 2) the id form is 6.
        let wide = KeyIds::new([(20000, "a")]).expect("valid");
        assert_eq!(wide.shared_wire("a/b"), KeyWire::Literal);
        // Id 5 takes one byte: 1 + 1 + 2 = 4, cheaper than 5.
        let narrow = KeyIds::new([(5, "a")]).expect("valid");
        assert_eq!(
            narrow.shared_wire("a/b"),
            KeyWire::Shared {
                id: 5,
                suffix: Some("/b")
            }
        );
        // An exact entry of three bytes of id against a one-byte key's literal of three: a tie,
        // which the id takes.
        let tie = KeyIds::new([(20000, "a")]).expect("valid");
        assert_eq!(
            tie.shared_wire("a"),
            KeyWire::Shared {
                id: 20000,
                suffix: None
            }
        );
    }

    #[test]
    fn a_key_the_dictionary_does_not_cover_goes_as_the_literal() {
        assert_eq!(dictionary().shared_wire("elsewhere/x"), KeyWire::Literal);
    }

    #[test]
    fn each_value_of_the_policy_picks_its_form() {
        let ids = dictionary();
        let key = "lab/rig/alpha";
        assert_eq!(
            key_wire(KeyWireForm::Declared, &ids, key, false),
            KeyWire::Declared
        );
        assert_eq!(
            key_wire(KeyWireForm::Literal, &ids, key, false),
            KeyWire::Literal
        );
        assert_eq!(
            key_wire(KeyWireForm::Shared, &ids, key, false),
            KeyWire::Shared {
                id: 3,
                suffix: None
            }
        );
        assert_eq!(
            key_wire(KeyWireForm::Shared, &ids, key, true),
            KeyWire::Declared,
            "a router keeps the mappings it was declared"
        );
        assert_eq!(
            key_wire(KeyWireForm::Literal, &ids, key, true),
            KeyWire::Literal,
            "the literal reads the same at a router"
        );
    }

    #[test]
    fn only_the_shared_form_needs_a_dictionary_to_open() {
        let ids = dictionary();
        assert_eq!(
            check_open(KeyWireForm::Shared, None),
            Err(KeyIdsRefused::SharedWithoutDictionary)
        );
        assert_eq!(check_open(KeyWireForm::Shared, Some(&ids)), Ok(()));
        assert_eq!(check_open(KeyWireForm::Declared, None), Ok(()));
        assert_eq!(check_open(KeyWireForm::Literal, None), Ok(()));
    }

    #[test]
    fn a_reply_on_the_querys_key_mirrors_the_request_with_the_bit_flipped() {
        let request = RequestKey {
            id: 9,
            suffix: Some("/gamma"),
            sender_mapping: true,
        };
        assert_eq!(
            reply_key(
                KeyWireForm::Shared,
                request,
                "lab/rig/gamma",
                "lab/rig/gamma"
            ),
            ReplyKey::Mirrored {
                id: 9,
                suffix: Some("/gamma"),
                sender_mapping: false
            }
        );
        let receivers = RequestKey {
            sender_mapping: false,
            suffix: None,
            ..request
        };
        assert_eq!(
            reply_key(KeyWireForm::Shared, receivers, "lab/rig", "lab/rig"),
            ReplyKey::Mirrored {
                id: 9,
                suffix: None,
                sender_mapping: true
            }
        );
    }

    #[test]
    fn a_reply_keeps_the_literal_wherever_it_cannot_mirror() {
        let request = RequestKey {
            id: 9,
            suffix: Some("/gamma"),
            sender_mapping: true,
        };
        assert_eq!(
            reply_key(
                KeyWireForm::Shared,
                request,
                "lab/rig/gamma",
                "lab/rig/delta"
            ),
            ReplyKey::Literal,
            "a reply on another key"
        );
        assert_eq!(
            reply_key(
                KeyWireForm::Declared,
                request,
                "lab/rig/gamma",
                "lab/rig/gamma"
            ),
            ReplyKey::Literal,
            "upstream's form replies as wz always has"
        );
        assert_eq!(
            reply_key(
                KeyWireForm::Literal,
                request,
                "lab/rig/gamma",
                "lab/rig/gamma"
            ),
            ReplyKey::Literal
        );
        let literal = RequestKey {
            id: 0,
            suffix: Some("lab/rig/gamma"),
            sender_mapping: true,
        };
        assert_eq!(
            reply_key(
                KeyWireForm::Shared,
                literal,
                "lab/rig/gamma",
                "lab/rig/gamma"
            ),
            ReplyKey::Literal,
            "a literal request keeps a literal reply"
        );
    }

    #[test]
    fn a_link_takes_its_stated_form_and_every_other_the_sessions() {
        let ids = dictionary();
        let forms = LinkKeyForms::new(
            KeyWireForm::Shared,
            vec![("tcp/192.0.2.7:7447".to_string(), KeyWireForm::Literal)],
            Some(&ids),
        )
        .expect("valid forms");
        assert_eq!(
            forms.form_of(Some("tcp/192.0.2.7:7447")),
            KeyWireForm::Literal
        );
        assert_eq!(
            forms.form_of(Some("tcp/192.0.2.8:7447")),
            KeyWireForm::Shared
        );
        assert_eq!(forms.form_of(None), KeyWireForm::Shared);
    }

    #[test]
    fn link_forms_are_refused_by_name() {
        assert_eq!(
            LinkKeyForms::new(
                KeyWireForm::Declared,
                vec![("tcp/192.0.2.7:7447".to_string(), KeyWireForm::Shared)],
                None,
            ),
            Err(KeyIdsRefused::SharedWithoutDictionary),
            "a link may not be shared with no dictionary either"
        );
        let ids = dictionary();
        assert_eq!(
            LinkKeyForms::new(
                KeyWireForm::Declared,
                vec![
                    ("tcp/192.0.2.7:7447".to_string(), KeyWireForm::Shared),
                    ("tcp/192.0.2.7:7447".to_string(), KeyWireForm::Literal),
                ],
                Some(&ids),
            ),
            Err(KeyIdsRefused::DuplicateLink {
                locator: "tcp/192.0.2.7:7447".to_string()
            })
        );
    }

    #[test]
    fn a_vle_takes_seven_bits_a_byte() {
        assert_eq!(vle_len(0), 1);
        assert_eq!(vle_len(127), 1);
        assert_eq!(vle_len(128), 2);
        assert_eq!(vle_len(16383), 2);
        assert_eq!(vle_len(16384), 3);
        assert_eq!(vle_len(u64::from(u16::MAX)), 3);
    }
}

/// The receive path's reading of an id only the dictionary holds, on both mapping bits and in the
/// resolver's heap and bounded forms (`crate::wireexpr_resolve`).
#[cfg(test)]
mod resolve_tests {
    use super::*;
    use crate::codec_owned::owned_string;
    use crate::wireexpr_resolve::{
        resolve_declared_keyexpr, resolve_wireexpr_in, resolve_wireexpr_into, KeyexprBuf,
        MappingSpaces,
    };
    use alloc::string::ToString;
    use hashbrown::HashMap;
    use wz_codecs::wireexpr::WireexprOwnedVariant;
    use wz_codecs::wireexpr_local::WireexprLocalOwned;
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocalOwned;

    /// `M=1`: the id is in the sender's space.
    fn sender_mapped(id: ExprId, suffix: Option<&str>) -> WireexprOwnedVariant {
        WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
            id,
            suffix_len: suffix.map(|s| s.len() as u64),
            suffix: suffix.map(owned_string).transpose().expect("suffix fits"),
        })
    }

    /// `M=0`: the id is in the receiver's space.
    fn receiver_mapped(id: ExprId, suffix: Option<&str>) -> WireexprOwnedVariant {
        WireexprOwnedVariant::WireexprNonlocal(WireexprNonlocalOwned {
            id,
            suffix_len: suffix.map(|s| s.len() as u64),
            suffix: suffix.map(owned_string).transpose().expect("suffix fits"),
        })
    }

    fn dictionary() -> KeyIds {
        KeyIds::new([(40, "lab/rig"), (41, "lab/rig/alpha")]).expect("a valid dictionary")
    }

    #[test]
    fn an_id_only_the_dictionary_holds_resolves_on_either_bit() {
        let ids = dictionary();
        let (peer, own) = (HashMap::new(), HashMap::<ExprId, String>::new());
        let spaces = MappingSpaces::with_own(&peer, &own).with_shared(&ids);
        for body in [sender_mapped(41, None), receiver_mapped(41, None)] {
            assert_eq!(
                resolve_wireexpr_in(&body, spaces).as_deref(),
                Some("lab/rig/alpha")
            );
        }
        for body in [
            sender_mapped(40, Some("/gamma")),
            receiver_mapped(40, Some("/gamma")),
        ] {
            assert_eq!(
                resolve_wireexpr_in(&body, spaces).as_deref(),
                Some("lab/rig/gamma"),
                "an id and the rest of the key compose as a declared one does"
            );
        }
    }

    #[test]
    fn without_the_dictionary_the_same_ids_resolve_to_nothing() {
        let (peer, own) = (HashMap::new(), HashMap::<ExprId, String>::new());
        let spaces = MappingSpaces::with_own(&peer, &own);
        for body in [
            sender_mapped(41, None),
            receiver_mapped(41, None),
            sender_mapped(40, Some("/gamma")),
        ] {
            assert_eq!(
                resolve_wireexpr_in(&body, spaces),
                None,
                "an undeclared id is refused as upstream refuses it"
            );
        }
    }

    #[test]
    fn a_declared_id_is_read_before_the_dictionary_and_never_across_spaces() {
        let ids = dictionary();
        let mut peer = HashMap::new();
        peer.insert(41u64, "peer/declared".to_string());
        let mut own = HashMap::<ExprId, String>::new();
        own.insert(40, "ours/declared".to_string());
        let spaces = MappingSpaces::with_own(&peer, &own).with_shared(&ids);
        assert_eq!(
            resolve_wireexpr_in(&sender_mapped(41, None), spaces).as_deref(),
            Some("peer/declared"),
            "the peer's declaration of the id wins"
        );
        assert_eq!(
            resolve_wireexpr_in(&receiver_mapped(40, None), spaces).as_deref(),
            Some("ours/declared"),
            "our declaration of the id wins"
        );
        assert_eq!(
            resolve_wireexpr_in(&receiver_mapped(41, None), spaces).as_deref(),
            Some("lab/rig/alpha"),
            "M=0 does not read the peer's 41: our space lacks it, so the dictionary answers"
        );
    }

    #[test]
    fn an_id_the_dictionary_does_not_hold_still_resolves_to_nothing() {
        let ids = dictionary();
        let (peer, own) = (HashMap::new(), HashMap::<ExprId, String>::new());
        let spaces = MappingSpaces::with_own(&peer, &own).with_shared(&ids);
        assert_eq!(resolve_wireexpr_in(&sender_mapped(42, None), spaces), None);
        assert_eq!(
            resolve_wireexpr_in(&receiver_mapped(42, None), spaces),
            None
        );
    }

    #[test]
    fn the_bounded_form_answers_as_the_heap_form() {
        let ids = dictionary();
        let (peer, own) = (HashMap::new(), HashMap::<ExprId, String>::new());
        let spaces = MappingSpaces::with_own(&peer, &own).with_shared(&ids);
        let mut out = KeyexprBuf::new();
        let alone = sender_mapped(41, None);
        assert_eq!(
            resolve_wireexpr_into(&alone, spaces, &mut out),
            Ok(Some("lab/rig/alpha"))
        );
        let ours = receiver_mapped(40, Some("/gamma"));
        assert_eq!(
            resolve_wireexpr_into(&ours, spaces, &mut out),
            Ok(Some("lab/rig/gamma"))
        );
        let theirs = sender_mapped(40, Some("/gamma"));
        assert_eq!(
            resolve_wireexpr_into(&theirs, spaces, &mut out),
            Ok(Some("lab/rig/gamma"))
        );
        let unknown = receiver_mapped(42, None);
        assert_eq!(resolve_wireexpr_into(&unknown, spaces, &mut out), Ok(None));
    }

    #[test]
    fn a_keyexpr_declared_on_a_dictionary_id_binds_the_dictionarys_key() {
        let ids = dictionary();
        let (peer, own) = (HashMap::new(), HashMap::<ExprId, String>::new());
        let spaces = MappingSpaces::with_own(&peer, &own).with_shared(&ids);
        assert_eq!(
            resolve_declared_keyexpr(&sender_mapped(40, Some("/delta")), spaces).as_deref(),
            Some("lab/rig/delta")
        );
        assert_eq!(
            resolve_declared_keyexpr(
                &sender_mapped(40, Some("/delta")),
                MappingSpaces::with_own(&peer, &own)
            ),
            None,
            "CONTROL: without the dictionary the scope names nothing"
        );
    }
}

/// One link's knowledge of the key ids: the form it names keys in, and the queries it keeps for
/// the replies that mirror them.
#[cfg(test)]
mod link_keys_tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::sync::Arc;
    use alloc::vec;

    /// The queries a link of these tests remembers, more than any of them notes.
    const NOTED: usize = 8;

    fn dictionary() -> SharedKeyIds {
        Arc::new(KeyIds::new([(40, "lab/rig"), (41, "lab/rig/alpha")]).expect("valid"))
    }

    #[test]
    fn a_link_names_a_key_by_its_own_form() {
        let shared = LinkKeys::new(Some(dictionary()), KeyWireForm::Shared, NOTED);
        assert_eq!(
            shared.key_wire("lab/rig/alpha", false),
            KeyWire::Shared {
                id: 41,
                suffix: None
            }
        );
        assert_eq!(
            shared.key_wire("lab/rig/alpha", true),
            KeyWire::Declared,
            "a router is told the declared form"
        );
        let literal = LinkKeys::new(None, KeyWireForm::Literal, NOTED);
        assert_eq!(literal.key_wire("lab/rig/alpha", false), KeyWire::Literal);
        let declared = LinkKeys::new(Some(dictionary()), KeyWireForm::Declared, NOTED);
        assert_eq!(declared.key_wire("lab/rig/alpha", false), KeyWire::Declared);
    }

    #[test]
    fn a_kept_query_is_mirrored_on_its_own_key_until_it_ends() {
        let mut keys = LinkKeys::new(Some(dictionary()), KeyWireForm::Shared, NOTED);
        keys.note_request(7, 40, Some("/gamma"), true, false);
        assert_eq!(
            keys.reply_key(7, "lab/rig/gamma"),
            ReplyKey::Mirrored {
                id: 40,
                suffix: Some("/gamma"),
                sender_mapping: false
            }
        );
        assert_eq!(
            keys.reply_key(7, "lab/rig/delta"),
            ReplyKey::Literal,
            "a reply on another key"
        );
        assert_eq!(
            keys.reply_key(8, "lab/rig/gamma"),
            ReplyKey::Literal,
            "another query"
        );
        keys.forget_request(7);
        assert_eq!(
            keys.reply_key(7, "lab/rig/gamma"),
            ReplyKey::Literal,
            "an ended query is not kept"
        );
    }

    #[test]
    fn only_a_query_by_a_dictionary_id_on_a_shared_link_from_no_router_is_kept() {
        let mut keys = LinkKeys::new(Some(dictionary()), KeyWireForm::Shared, NOTED);
        keys.note_request(1, 0, Some("lab/rig/alpha"), true, false);
        keys.note_request(2, 99, None, true, false);
        keys.note_request(3, 41, None, true, true);
        for rid in [1, 2, 3] {
            assert_eq!(keys.reply_key(rid, "lab/rig/alpha"), ReplyKey::Literal);
        }
        let mut literal = LinkKeys::new(Some(dictionary()), KeyWireForm::Literal, NOTED);
        literal.note_request(4, 41, None, true, false);
        assert_eq!(literal.reply_key(4, "lab/rig/alpha"), ReplyKey::Literal);
        keys.note_request(5, 41, None, false, false);
        assert_eq!(
            keys.reply_key(5, "lab/rig/alpha"),
            ReplyKey::Mirrored {
                id: 41,
                suffix: None,
                sender_mapping: true
            },
            "CONTROL: a query by a dictionary id is kept, its bit turned"
        );
    }

    #[test]
    fn the_queries_kept_are_bounded_by_the_oldest_giving_way() {
        let mut keys = LinkKeys::new(Some(dictionary()), KeyWireForm::Shared, 3);
        for rid in 0..=3 {
            keys.note_request(rid, 41, None, true, false);
        }
        assert_eq!(keys.reply_key(0, "lab/rig/alpha"), ReplyKey::Literal);
        for rid in 1..=3 {
            assert_ne!(keys.reply_key(rid, "lab/rig/alpha"), ReplyKey::Literal);
        }
    }

    #[test]
    fn a_link_made_to_remember_no_query_remembers_one() {
        let mut keys = LinkKeys::new(Some(dictionary()), KeyWireForm::Shared, 0);
        keys.note_request(1, 41, None, true, false);
        assert_ne!(keys.reply_key(1, "lab/rig/alpha"), ReplyKey::Literal);
        keys.note_request(2, 41, None, true, false);
        assert_eq!(keys.reply_key(1, "lab/rig/alpha"), ReplyKey::Literal);
        assert_ne!(keys.reply_key(2, "lab/rig/alpha"), ReplyKey::Literal);
    }

    #[test]
    fn the_forms_stated_for_links_replace_one_another_and_a_name_reads_as_its_value() {
        let mut at_open = KeyIdsAtOpen {
            ids: Some(dictionary()),
            links: vec![],
        };
        at_open.set_link("tcp/192.0.2.7:7447", KeyWireForm::Literal);
        at_open.set_link("tcp/192.0.2.7:7447", KeyWireForm::Shared);
        assert_eq!(
            at_open.links,
            [("tcp/192.0.2.7:7447".to_string(), KeyWireForm::Shared)]
        );
        let forms = at_open.forms(KeyWireForm::Declared).expect("valid");
        assert!(forms.departs_from_declared());
        assert_eq!(
            forms.form_of(Some("tcp/192.0.2.7:7447")),
            KeyWireForm::Shared
        );
        assert!(!LinkKeyForms::session_only(KeyWireForm::Declared).departs_from_declared());
        assert_eq!(key_wire_form_named("literal"), Some(KeyWireForm::Literal));
        assert_eq!(key_wire_form_named("shared"), Some(KeyWireForm::Shared));
        assert_eq!(key_wire_form_named("declared"), Some(KeyWireForm::Declared));
        assert_eq!(key_wire_form_named("Shared"), None);
        assert!(form_in_domain(KeyWireForm::Declared));
    }
}

/// A reply that mirrors its query, as the bytes the link carries: the id and the rest, and the
/// header bits the decoder reads the space and the rest's presence from.
#[cfg(all(test, feature = "codec-response"))]
mod reply_frame_tests {
    use crate::network_message::{parse_frame_payload, NetworkMessage};
    use crate::response_build::{build_response_reply_literal, set_response_keyexpr_aliased};
    use crate::wireexpr_resolve::id_and_suffix;
    use wz_codecs::wireexpr::WireexprOwnedVariant;
    use wz_codecs_test_support::TestWire;

    fn decoded(bytes: &[u8]) -> crate::wire::ResponseOwned {
        let mut parsed = parse_frame_payload(bytes).expect("the response parses");
        match parsed.pop() {
            Some(NetworkMessage::Response(response)) => *response,
            _ => panic!("one response"),
        }
    }

    #[test]
    fn a_mirrored_reply_carries_the_id_and_the_rest_in_the_receivers_space() {
        let mut response = build_response_reply_literal(7, "lab/rig/gamma", b"answer").unwrap();
        set_response_keyexpr_aliased(&mut response, 40, Some("/gamma"), false).unwrap();
        let bytes = response.wire();
        assert_eq!(bytes[0] & 0x60, 0x20, "N set and M clear");
        let back = decoded(&bytes);
        assert!(matches!(
            back.keyexpr.body,
            WireexprOwnedVariant::WireexprNonlocal(_)
        ));
        assert_eq!(id_and_suffix(&back.keyexpr.body), (40, Some("/gamma")));
    }

    #[test]
    fn a_mirrored_reply_by_the_id_alone_in_the_senders_space_has_no_rest() {
        let mut response = build_response_reply_literal(7, "lab/rig/alpha", b"answer").unwrap();
        set_response_keyexpr_aliased(&mut response, 41, None, true).unwrap();
        let bytes = response.wire();
        assert_eq!(bytes[0] & 0x60, 0x40, "N clear and M set");
        let back = decoded(&bytes);
        assert!(matches!(
            back.keyexpr.body,
            WireexprOwnedVariant::WireexprLocal(_)
        ));
        assert_eq!(id_and_suffix(&back.keyexpr.body), (41, None));
    }
}

/// A subscriber of a session that holds the dictionary hears a put sent by a dictionary id with
/// no declaration; the same put to a session without it is dropped.
#[cfg(all(test, feature = "pubsub-put"))]
mod registry_tests {
    use super::*;
    use crate::network_message::NetworkMessage;
    use crate::pubsub::SubscriberRegistry;
    use crate::push_build::build_push_aliased;
    use crate::sample::Reliability;
    use crate::sink::SampleView;
    use alloc::boxed::Box;
    use alloc::string::ToString;
    use std::sync::{Arc, Mutex};

    fn dictionary() -> SharedKeyIds {
        Arc::new(KeyIds::new([(40, "lab/rig"), (41, "lab/rig/alpha")]).expect("valid"))
    }

    /// A registry with one subscriber on `lab/rig/**`, and the keys it hears.
    fn listening() -> (
        SubscriberRegistry<crate::sink::BoxedSink>,
        Arc<Mutex<alloc::vec::Vec<String>>>,
    ) {
        let mut registry = SubscriberRegistry::new();
        let heard = Arc::new(Mutex::new(alloc::vec::Vec::new()));
        let into = heard.clone();
        registry
            .register("lab/rig/**", move |sample: &dyn SampleView| {
                into.lock().unwrap().push(sample.keyexpr().to_string());
            })
            .expect("no quota is stated on this table");
        (registry, heard)
    }

    fn push_by_id(
        registry: &mut SubscriberRegistry<crate::sink::BoxedSink>,
        id: ExprId,
        suffix: Option<&str>,
    ) {
        let push = build_push_aliased(id, suffix, b"value").expect("a push");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
    }

    #[test]
    fn a_put_by_a_dictionary_id_reaches_the_subscriber_with_no_declaration() {
        let (mut registry, heard) = listening();
        registry.set_shared_key_ids(dictionary());
        push_by_id(&mut registry, 41, None);
        push_by_id(&mut registry, 40, Some("/gamma"));
        assert_eq!(*heard.lock().unwrap(), ["lab/rig/alpha", "lab/rig/gamma"]);
    }

    #[test]
    fn a_session_without_the_dictionary_drops_the_undeclared_id() {
        let (mut registry, heard) = listening();
        push_by_id(&mut registry, 41, None);
        assert!(heard.lock().unwrap().is_empty());
        registry.set_shared_key_ids(dictionary());
        registry.clear_shared_key_ids();
        push_by_id(&mut registry, 41, None);
        assert!(
            heard.lock().unwrap().is_empty(),
            "a released dictionary answers nothing"
        );
    }
}

#[cfg(test)]
mod document_tests {
    use super::*;
    use crate::json5::parse;
    use crate::limit_binding::LimitSpec;
    use crate::policy::SessionPolicy;
    use crate::policy_document::{resolve_document, statements_from_json5};
    use alloc::format;
    use alloc::string::ToString;
    use alloc::sync::Arc;
    use alloc::vec;

    /// The key-id refusals the reader of the `wz` member found in `tree`, in their order; a
    /// refusal of another kind fails the test.
    fn key_id_reasons(tree: &Json5Value) -> Vec<KeyIdsReason<'_>> {
        statements_from_json5(tree)
            .expect_err("the member is refused")
            .iter()
            .map(|refusal| match refusal.reason {
                Reason::KeyIds(reason) => reason,
                other => panic!("not a key-id refusal: {other:?}"),
            })
            .collect()
    }

    /// `member` as the `wz/key-ids` of a document.
    fn document(member: &str) -> Json5Value {
        parse(&format!(r#"{{ wz: {{ "key-ids": {member} }} }}"#)).expect("JSON5")
    }

    fn dictionary_of(entries: &[(ExprId, &str)]) -> Option<SharedKeyIds> {
        Some(Arc::new(
            KeyIds::new(entries.iter().copied()).expect("a valid dictionary"),
        ))
    }

    fn links_of(links: &[(&str, KeyWireForm)]) -> Vec<(String, KeyWireForm)> {
        links
            .iter()
            .map(|(locator, form)| (locator.to_string(), *form))
            .collect()
    }

    #[test]
    fn the_member_is_read_into_the_dictionary_and_the_endpoints_forms() {
        let tree = document(
            r#"{
                dictionary: [ { id: 40, key: "lab/rig" }, { key: "lab/rig/alpha", id: 0x29 } ],
                links: [
                    { locator: "tcp/192.0.2.7:7447", form: "literal" },
                    { form: "declared", locator: "udp/192.0.2.8:7447" },
                ],
            }"#,
        );
        let read = statements_from_json5(&tree).expect("well formed");
        assert_eq!(
            read.key_ids,
            KeyIdsAtOpen {
                ids: dictionary_of(&[(40, "lab/rig"), (41, "lab/rig/alpha")]),
                links: links_of(&[
                    ("tcp/192.0.2.7:7447", KeyWireForm::Literal),
                    ("udp/192.0.2.8:7447", KeyWireForm::Declared),
                ]),
            }
        );
        assert!(
            resolve_document(SessionPolicy::defaults(), &tree).is_ok(),
            "the policies resolve beside the member"
        );
    }

    #[test]
    fn a_member_that_states_nothing_reads_as_no_key_ids() {
        for member in ["{}", "{ dictionary: [] }", "{ links: [] }"] {
            let read = statements_from_json5(&document(member))
                .expect("well formed")
                .key_ids;
            assert_eq!(read, KeyIdsAtOpen::default(), "{member}");
        }
        let tree = parse(r#"{ wz: { policies: {} } }"#).unwrap();
        assert_eq!(
            statements_from_json5(&tree).expect("well formed").key_ids,
            KeyIdsAtOpen::default(),
            "a document with no member states no key ids"
        );
    }

    /// Each rule of the dictionary and of the links, refused by its name.
    #[test]
    fn each_fault_of_the_member_is_refused_by_name() {
        let endpoint = "tcp/192.0.2.7:7447";
        let not_canonical = validate_keyexpr("lab//a").expect_err("not canonical");
        let cases: [(&str, Vec<KeyIdsReason<'static>>); 6] = [
            (
                r#"{ dictionary: [ { id: 0, key: "lab/a" } ] }"#,
                vec![KeyIdsReason::ZeroId { at: 0 }],
            ),
            (
                r#"{ dictionary: [ { id: 5, key: "lab/a" }, { id: 5, key: "lab/b" } ] }"#,
                vec![KeyIdsReason::DuplicateId { id: 5 }],
            ),
            (
                r#"{ dictionary: [ { id: 5, key: "lab/a" }, { id: 6, key: "lab/a" } ] }"#,
                vec![KeyIdsReason::DuplicateKey { key: "lab/a" }],
            ),
            (
                r#"{ dictionary: [ { id: 5, key: "lab//a" } ] }"#,
                vec![KeyIdsReason::NotAKeyExpr {
                    at: 0,
                    key: "lab//a",
                    refusal: not_canonical,
                }],
            ),
            (
                r#"{ links: [ { locator: "tcp/192.0.2.7:7447", form: "Literal" } ] }"#,
                vec![KeyIdsReason::UnknownForm {
                    locator: endpoint,
                    form: "Literal",
                }],
            ),
            (
                r#"{ links: [ { locator: "tcp/192.0.2.7:7447", form: "literal" },
                              { locator: "tcp/192.0.2.7:7447", form: "declared" } ] }"#,
                vec![KeyIdsReason::LinkStatedTwice { locator: endpoint }],
            ),
        ];
        for (member, expected) in cases {
            let tree = document(member);
            assert_eq!(key_id_reasons(&tree), expected, "{member}");
        }
    }

    /// The reasons `resolve_document` refuses `tree` for, in their order.
    fn resolution_reasons(tree: &Json5Value) -> Vec<Reason<'_>> {
        resolve_document(SessionPolicy::defaults(), tree)
            .expect_err("the document is refused")
            .iter()
            .map(|refusal| refusal.reason)
            .collect()
    }

    /// A `wz/key-ids` member whose dictionary names ids `1..=count`.
    fn dictionary_member(count: usize) -> String {
        let entries: Vec<String> = (1..=count)
            .map(|id| format!(r#"{{ id: {id}, key: "lab/k{id}" }}"#))
            .collect();
        format!("{{ dictionary: [ {} ] }}", entries.join(", "))
    }

    /// With no limit stated the dictionary is held to the build's `MAX_SHARED_KEY_IDS`, by the
    /// resolution, which knows the limit; the reader of the member alone does not count.
    #[test]
    fn a_dictionary_over_the_builds_limit_is_refused_by_name() {
        let limit = crate::caps::MAX_SHARED_KEY_IDS;
        if limit >= usize::from(ExprId::MAX) {
            // Every id a wireexpr has fits: no dictionary of distinct ids is over the limit.
            return;
        }
        let tree = document(&dictionary_member(limit + 1));
        assert!(statements_from_json5(&tree).is_ok());
        assert_eq!(
            resolution_reasons(&tree),
            [Reason::KeyIds(KeyIdsReason::TooMany {
                stated: limit + 1,
                limit
            })]
        );
        let at = document(&dictionary_member(limit));
        assert!(
            resolve_document(SessionPolicy::defaults(), &at).is_ok(),
            "CONTROL: as many entries as the limit"
        );
    }

    /// A document that states `MAX_SHARED_KEY_IDS` holds its own dictionary to that value: past
    /// it the document is refused by name, at it the dictionary is read.
    #[test]
    fn a_dictionary_over_the_limit_its_document_states_is_refused_by_name() {
        let stated = |limit: usize, count: usize| {
            parse(&format!(
                r#"{{ wz: {{ limits: {{ MAX_SHARED_KEY_IDS: {limit} }}, "key-ids": {} }} }}"#,
                dictionary_member(count)
            ))
            .expect("JSON5")
        };
        let over = stated(2, 3);
        if crate::limits::MaxSharedKeyIds::DOMAIN.is_singleton() {
            // A build that keeps the build's value alone refuses the statement itself.
            assert!(resolve_document(SessionPolicy::defaults(), &over).is_err());
            return;
        }
        assert_eq!(
            resolution_reasons(&over),
            [Reason::KeyIds(KeyIdsReason::TooMany {
                stated: 3,
                limit: 2
            })]
        );
        let at = resolve_document(SessionPolicy::defaults(), &stated(3, 3))
            .expect("as many entries as the limit the document states");
        assert_eq!(
            at.limits.session.max_shared_key_ids(),
            Quota::at_most(3),
            "the session the document opens holds the limit it states"
        );
    }

    #[test]
    fn a_form_the_domain_leaves_out_is_refused_and_the_others_kept() {
        let tree = parse(
            r#"{ links: [ { locator: "tcp/192.0.2.7:7447", form: "shared" },
                          { locator: "tcp/192.0.2.8:7447", form: "literal" } ] }"#,
        )
        .unwrap();
        let mut refusals = Refusals::new();
        let read = read_document_member(&tree, |form| form != KeyWireForm::Shared, &mut refusals);
        let reasons: Vec<Reason<'_>> = refusals.iter().map(|refusal| refusal.reason).collect();
        assert_eq!(
            reasons,
            [Reason::KeyIds(KeyIdsReason::FormOutsideDomain {
                locator: "tcp/192.0.2.7:7447",
                form: "shared",
            })]
        );
        assert_eq!(
            read.links,
            links_of(&[("tcp/192.0.2.8:7447", KeyWireForm::Literal)])
        );
    }

    /// The reader holds a form to the build's own domain of `key-wire-form`.
    #[test]
    fn the_build_domain_decides_each_form() {
        for form in [
            KeyWireForm::Declared,
            KeyWireForm::Shared,
            KeyWireForm::Literal,
        ] {
            let id = form.id();
            let tree = document(&format!(
                r#"{{ dictionary: [ {{ id: 40, key: "lab/rig" }} ],
                     links: [ {{ locator: "tcp/192.0.2.7:7447", form: "{id}" }} ] }}"#
            ));
            if form_in_domain(form) {
                assert!(statements_from_json5(&tree).is_ok(), "{id}");
            } else {
                assert_eq!(
                    key_id_reasons(&tree),
                    [KeyIdsReason::FormOutsideDomain {
                        locator: "tcp/192.0.2.7:7447",
                        form: id,
                    }],
                    "{id}"
                );
            }
        }
    }

    #[test]
    fn each_fault_of_shape_is_refused_by_name() {
        let cases: [(&str, Vec<KeyIdsReason<'static>>); 10] = [
            (
                r#"{ colour: "blue" }"#,
                vec![KeyIdsReason::UnknownMember { member: "colour" }],
            ),
            (
                "{ dictionary: {} }",
                vec![KeyIdsReason::NotAnArray { member: DICTIONARY }],
            ),
            (
                r#"{ links: "tcp/192.0.2.7:7447" }"#,
                vec![KeyIdsReason::NotAnArray { member: LINKS }],
            ),
            (
                "{ dictionary: [ 40 ] }",
                vec![KeyIdsReason::EntryNotAnObject {
                    member: DICTIONARY,
                    at: 0,
                }],
            ),
            (
                "{ dictionary: [ { id: 40 } ] }",
                vec![KeyIdsReason::MissingField {
                    member: DICTIONARY,
                    at: 0,
                    field: "key",
                }],
            ),
            (
                r#"{ dictionary: [ { id: 40, key: "lab/a", note: "x" } ] }"#,
                vec![KeyIdsReason::UnknownField {
                    member: DICTIONARY,
                    at: 0,
                    field: "note",
                }],
            ),
            (
                r#"{ dictionary: [ { id: 40, id: 41, key: "lab/a" } ] }"#,
                vec![KeyIdsReason::FieldStatedTwice {
                    member: DICTIONARY,
                    at: 0,
                    field: "id",
                }],
            ),
            (
                r#"{ dictionary: [ { id: 70000, key: "lab/a" }, { id: -1, key: "lab/b" },
                                   { id: "40", key: "lab/c" }, { id: 1.5, key: 7 } ] }"#,
                vec![
                    KeyIdsReason::NotAnId { at: 0 },
                    KeyIdsReason::NotAnId { at: 1 },
                    KeyIdsReason::NotAnId { at: 2 },
                    KeyIdsReason::NotAnId { at: 3 },
                    KeyIdsReason::NotAString {
                        member: DICTIONARY,
                        at: 3,
                        field: "key",
                    },
                ],
            ),
            (
                r#"{ links: [ { locator: "", form: "literal" } ] }"#,
                vec![KeyIdsReason::EmptyLocator { at: 0 }],
            ),
            (
                "{ links: [ { locator: 7, form: true } ] }",
                vec![
                    KeyIdsReason::NotAString {
                        member: LINKS,
                        at: 0,
                        field: "locator",
                    },
                    KeyIdsReason::NotAString {
                        member: LINKS,
                        at: 0,
                        field: "form",
                    },
                ],
            ),
        ];
        for (member, expected) in cases {
            let tree = document(member);
            assert_eq!(key_id_reasons(&tree), expected, "{member}");
        }
    }

    /// Every refusal the reader of the `wz` member found in `tree`, in their order.
    fn reasons_of(tree: &Json5Value) -> Vec<Reason<'_>> {
        statements_from_json5(tree)
            .expect_err("refused")
            .iter()
            .map(|refusal| refusal.reason)
            .collect()
    }

    #[test]
    fn a_member_stated_twice_or_of_the_wrong_kind_is_refused() {
        let twice = parse(r#"{ wz: { "key-ids": {}, "key-ids": {} } }"#).unwrap();
        assert_eq!(
            reasons_of(&twice),
            [Reason::MemberStatedTwice {
                member: "wz/key-ids"
            }]
        );
        let list_twice = document("{ dictionary: [], dictionary: [] }");
        assert_eq!(
            reasons_of(&list_twice),
            [Reason::MemberStatedTwice { member: DICTIONARY }]
        );
        let not_an_object = document("[]");
        assert_eq!(
            reasons_of(&not_an_object),
            [Reason::NotAnObject {
                member: "wz/key-ids"
            }]
        );
    }

    /// A refused member refuses the whole document, with every refusal of the policies beside
    /// it, in the one list the document's reader reports.
    #[test]
    fn a_refused_member_refuses_the_document_beside_the_policies() {
        let tree = parse(
            r#"{ wz: { policies: { "no-such-policy": "on" },
                       "key-ids": { dictionary: [ { id: 0, key: "lab/a" } ] } } }"#,
        )
        .unwrap();
        let refusals = resolve_document(SessionPolicy::defaults(), &tree).unwrap_err();
        let reasons: Vec<Reason<'_>> = refusals.iter().map(|refusal| refusal.reason).collect();
        assert_eq!(
            reasons,
            [
                Reason::KeyIds(KeyIdsReason::ZeroId { at: 0 }),
                Reason::UnknownPolicy {
                    policy: "no-such-policy",
                    value: "on"
                },
            ]
        );
        assert!(
            refusals
                .iter()
                .all(|refusal| refusal.layer == Origin::Document),
            "{refusals}"
        );
        assert_eq!(
            format!("{}", refusals.iter().next().expect("one")),
            "the document states id 0 in entry 0 of `wz/key-ids/dictionary`, and no key may \
             have it"
        );
    }

    #[test]
    fn the_dictionary_rules_report_every_fault_and_the_door_the_first() {
        let entries = [
            (0, 0, "lab//a"),
            (1, 5, "lab/b"),
            (2, 5, "lab/b"),
            (3, 5, "lab/c"),
        ];
        let mut found = Vec::new();
        dictionary_faults(&entries, |fault| found.push(fault));
        assert_eq!(
            found,
            [
                Fault::ZeroId { at: 0 },
                Fault::NotAKeyExpr {
                    at: 0,
                    key: "lab//a",
                    refusal: validate_keyexpr("lab//a").expect_err("not canonical"),
                },
                Fault::DuplicateId { id: 5 },
                Fault::DuplicateKey { key: "lab/b" },
            ],
            "an id named three times is reported once"
        );
        assert_eq!(
            KeyIds::new(entries.iter().map(|&(_, id, key)| (id, key))),
            Err(KeyIdsRefused::ZeroId { at: 0 })
        );
    }

    #[test]
    fn the_callers_statements_go_over_the_documents() {
        let document = KeyIdsAtOpen {
            ids: dictionary_of(&[(40, "lab/rig")]),
            links: links_of(&[
                ("tcp/192.0.2.7:7447", KeyWireForm::Literal),
                ("tcp/192.0.2.8:7447", KeyWireForm::Shared),
            ]),
        };
        assert_eq!(
            KeyIdsAtOpen::default().over(document.clone()),
            document,
            "a caller that states nothing leaves the document's"
        );
        let door = KeyIdsAtOpen {
            ids: dictionary_of(&[(7, "lab/other")]),
            links: links_of(&[("tcp/192.0.2.8:7447", KeyWireForm::Declared)]),
        };
        let composed = door.over(document.clone());
        assert_eq!(
            composed.ids, door.ids,
            "the caller's dictionary replaces it"
        );
        assert_eq!(
            composed.links,
            links_of(&[
                ("tcp/192.0.2.7:7447", KeyWireForm::Literal),
                ("tcp/192.0.2.8:7447", KeyWireForm::Declared),
            ]),
            "the caller's form of an endpoint replaces the document's for that endpoint alone"
        );
        let links_only = KeyIdsAtOpen {
            ids: None,
            links: links_of(&[("tcp/192.0.2.9:7447", KeyWireForm::Literal)]),
        };
        let composed = links_only.over(document.clone());
        assert_eq!(
            composed.ids, document.ids,
            "no dictionary stated keeps the document's"
        );
        assert_eq!(composed.links.len(), 3);
    }
}
