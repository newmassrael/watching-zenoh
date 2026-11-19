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
//! * Under `shared` a reply on the query's own key may mirror the request ([`reply_key`]): the
//!   same id and rest, the `M` bit flipped, since the id is in the requester's space and the
//!   requester is the receiver of the reply. The engines' reply path carries the reply's key as
//!   text and so sends it whole; a requester that holds the dictionary reads either form.
//!
//! # Where it lives
//!
//! The dictionary is data an open is handed, held on the heap and shared by every link of the
//! session ([`SharedKeyIds`]); [`crate::caps::MAX_SHARED_KEY_IDS`] bounds how many entries an
//! open may hand it. An image with no allocator has no dictionary yet.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::keyexpr_canon::{validate_keyexpr, KeyexprRefusal};
use crate::keyexpr_match::is_wild;
use crate::policy::KeyWireForm;
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
    /// More entries than the limit the dictionary is built under.
    TooMany {
        /// How many entries were given.
        stated: usize,
        /// How many the limit allows.
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
                "the key-id dictionary has {stated} entries and the limit is {limit} \
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
    /// The dictionary of `entries`, each an id and the key it names, under the build's limit
    /// ([`crate::caps::MAX_SHARED_KEY_IDS`]).
    pub fn new<'a>(
        entries: impl IntoIterator<Item = (ExprId, &'a str)>,
    ) -> Result<Self, KeyIdsRefused> {
        Self::with_limit(entries, crate::caps::MAX_SHARED_KEY_IDS)
    }

    /// [`Self::new`] under `limit` entries. Refused when there are more, when an id is 0 or
    /// named twice, when a key is named twice, and when a key is not a canonical key expression;
    /// the order the entries are given in does not matter.
    pub fn with_limit<'a>(
        entries: impl IntoIterator<Item = (ExprId, &'a str)>,
        limit: usize,
    ) -> Result<Self, KeyIdsRefused> {
        let given: Vec<(ExprId, &str)> = entries.into_iter().collect();
        if given.len() > limit {
            return Err(KeyIdsRefused::TooMany {
                stated: given.len(),
                limit,
            });
        }
        let mut rows = Vec::with_capacity(given.len());
        for (at, (id, key)) in given.into_iter().enumerate() {
            if id == 0 {
                return Err(KeyIdsRefused::ZeroId { at });
            }
            validate_keyexpr(key).map_err(|refusal| KeyIdsRefused::NotAKeyExpr { at, refusal })?;
            rows.push(Entry {
                id,
                key: String::from(key),
            });
        }
        rows.sort_unstable_by_key(|entry| entry.id);
        if let Some(pair) = rows.windows(2).find(|pair| pair[0].id == pair[1].id) {
            return Err(KeyIdsRefused::DuplicateId { id: pair[0].id });
        }
        let mut by_key: Vec<usize> = (0..rows.len()).collect();
        by_key.sort_unstable_by(|a, b| rows[*a].key.as_bytes().cmp(rows[*b].key.as_bytes()));
        if let Some(pair) = by_key
            .windows(2)
            .find(|pair| rows[pair[0]].key == rows[pair[1]].key)
        {
            return Err(KeyIdsRefused::DuplicateKey {
                key: rows[pair[0]].key.clone(),
            });
        }
        Ok(Self {
            entries: rows,
            by_key,
        })
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
        assert_eq!(
            KeyIds::with_limit([(1, "lab/a"), (2, "lab/b"), (3, "lab/c")], 2),
            Err(KeyIdsRefused::TooMany {
                stated: 3,
                limit: 2
            })
        );
        assert!(
            KeyIds::with_limit([(1, "lab/a"), (2, "lab/b")], 2).is_ok(),
            "CONTROL: as many entries as the limit is not too many"
        );
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
        registry.register("lab/rig/**", move |sample: &dyn SampleView| {
            into.lock().unwrap().push(sample.keyexpr().to_string());
        });
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
