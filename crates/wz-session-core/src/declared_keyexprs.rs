// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The key expressions a session declared, each by the id it gave it: the session's own id
//! space, the one a received message names with `M=0` and a sent one with `M=1`
//! ([`OwnMappingSpace`]).
//!
//! One fact with one owner. A session that declares through one link (the AP engine's) keeps the
//! table on that link and records each declaration as the link sends it (`LinkKeyexprs::Held`).
//! A session of several links (the cooperative engine's) keeps one table for all of them, and its
//! links keep none and read none (`LinkKeyexprs::Session`): every link is told the same
//! declarations under the same ids, so a table per link would be a copy of the session's, and a
//! link that read the session's would reach into the session from under its send. Such a
//! session names each key it sends itself (`crate::named_key::NamedKey`), and reads a peer's
//! `M=0` key from its own tables.
//!
//! The table is written over a storage policy ([`Storage`]): the growable policy's rows are a
//! hash map of strings, the fixed and the lent policies' are bounded at
//! [`caps::MAX_DECLARED_KEYEXPRS`], and the lent policy's keys are blocks of the session's key
//! arena ([`KeyRef`](crate::key_arena::KeyRef)), so a row is a few words whatever its key's length.

#[cfg(feature = "alloc")]
use alloc::string::String;

use crate::bounded::{CapacityFull, KeyBacking, KeyMaker, KeyUnkept, Profile, Storage};
use crate::caps;
use crate::id_map::{IdMap, KeyText};
use crate::wire_id::ExprId;
use crate::wireexpr_resolve::{KeyexprBuf, OwnMappingSpace};

/// The key expressions a session declared, by the id it gave each, in the storage policy `P`.
pub struct DeclaredKeyexprs<P: Storage = Profile> {
    ids: <P as Storage>::Ids<KeyText<P>, { caps::MAX_DECLARED_KEYEXPRS }>,
    keys: P::Keys,
}

/// Why a declaration was not recorded ([`DeclaredKeyexprs::record`]). Nothing of it was kept and
/// the table holds what it held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyexprUnrecorded {
    /// The key was not kept: longer than a row holds, or no room is left where the policy keeps
    /// its keys.
    Key(KeyUnkept),
    /// The table holds as many ids as its policy allows, and the id is a new one.
    TableFull,
}

impl<P: Storage> Default for DeclaredKeyexprs<P> {
    fn default() -> Self {
        Self::keeping_keys_in(P::Keys::default())
    }
}

impl<P: Storage> DeclaredKeyexprs<P> {
    /// An empty table whose rows keep their keys in `keys`: the session's key arena on the lent
    /// policy, nothing on the policies whose key is its own text.
    pub fn keeping_keys_in(keys: P::Keys) -> Self {
        Self {
            ids: Default::default(),
            keys,
        }
    }

    /// Record that the session declared `literal` under `id`. An id already recorded is bound to
    /// `literal` in its place, as a peer that is told an id again takes the later key.
    pub fn record(&mut self, id: ExprId, literal: &str) -> Result<(), KeyexprUnrecorded> {
        let key = self.keys.key(literal).map_err(KeyexprUnrecorded::Key)?;
        match self.ids.bind(u64::from(id), key) {
            Ok(_) => Ok(()),
            Err(CapacityFull(_)) => Err(KeyexprUnrecorded::TableFull),
        }
    }

    /// Forget the declaration under `id`: whether there was one. Its key is let go of with it.
    pub fn forget(&mut self, id: ExprId) -> bool {
        self.ids.unbind(u64::from(id)).is_some()
    }

    /// The key expression the session declared under `id`.
    pub fn literal(&self, id: ExprId) -> Option<&str> {
        self.ids.find(u64::from(id)).map(|key| key.as_str())
    }

    /// How many declarations are recorded.
    pub fn len(&self) -> usize {
        self.ids.count()
    }

    /// Whether none is.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<P: Storage> OwnMappingSpace for DeclaredKeyexprs<P> {
    #[cfg(feature = "alloc")]
    fn resolve_own_mapping(&self, id: ExprId) -> Option<String> {
        self.literal(id).map(String::from)
    }

    // The literal goes from the row into the caller's buffer, with no `String` in between.
    fn append_own_mapping(
        &self,
        id: ExprId,
        out: &mut KeyexprBuf,
    ) -> Option<Result<(), CapacityFull<()>>> {
        self.literal(id).map(|literal| out.push_str(literal))
    }
}

/// Where one link reads the key expressions its session declared.
#[cfg(all(feature = "alloc", feature = "session-unicast"))]
pub(crate) enum LinkKeyexprs {
    /// The link keeps them, recorded as it sends each declaration and forgotten as it sends each
    /// retraction: the session declares through this link alone.
    Held(DeclaredKeyexprs<crate::bounded::Heap>),
    /// The session keeps them for every link it has and records them itself; the link records
    /// nothing and reads nothing of them.
    Session,
}

#[cfg(all(feature = "alloc", feature = "session-unicast"))]
impl Default for LinkKeyexprs {
    fn default() -> Self {
        Self::Held(DeclaredKeyexprs::default())
    }
}

#[cfg(all(feature = "alloc", feature = "session-unicast"))]
impl LinkKeyexprs {
    /// The link sent a declaration of `literal` under `id`.
    #[cfg(feature = "declare-keyexpr")]
    pub(crate) fn sent_declaration(&mut self, id: ExprId, literal: &str) {
        match self {
            // The growable policy refuses no key and no row.
            Self::Held(table) => {
                let _ = table.record(id, literal);
            }
            Self::Session => {}
        }
    }

    /// The link sent the retraction of the declaration under `id`.
    #[cfg(all(feature = "declare-keyexpr", feature = "declare-undeclare"))]
    pub(crate) fn sent_retraction(&mut self, id: ExprId) {
        match self {
            Self::Held(table) => {
                table.forget(id);
            }
            Self::Session => {}
        }
    }

    /// The table the link keeps, when it keeps one.
    pub(crate) fn held(&self) -> Option<&DeclaredKeyexprs<crate::bounded::Heap>> {
        match self {
            Self::Held(table) => Some(table),
            Self::Session => None,
        }
    }

    /// The space the link reads: its own table, or none where the session keeps the table.
    pub(crate) fn space(&self) -> Option<&dyn OwnMappingSpace> {
        match self {
            Self::Held(table) => Some(table),
            Self::Session => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A declaration is read back by its id, a second one under the same id takes its place, and
    /// a forgotten one reads nothing, on the growable policy and on the fixed one alike.
    fn records_reads_and_forgets<P: Storage>() {
        let mut table = DeclaredKeyexprs::<P>::default();
        assert!(table.is_empty());
        assert_eq!(table.record(7, "home/a"), Ok(()));
        assert_eq!(table.record(8, "home/b"), Ok(()));
        assert_eq!(table.literal(7), Some("home/a"));
        assert_eq!(table.literal(9), None, "an id never declared");
        assert_eq!(table.record(7, "home/c"), Ok(()));
        assert_eq!(
            table.literal(7),
            Some("home/c"),
            "the later key takes the id"
        );
        assert_eq!(table.len(), 2);
        assert!(table.forget(7));
        assert!(!table.forget(7), "forgotten once");
        assert_eq!(table.literal(7), None);
        assert_eq!(table.literal(8), Some("home/b"));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn the_growable_table_records_reads_and_forgets() {
        records_reads_and_forgets::<crate::bounded::Heap>();
    }

    #[test]
    fn the_fixed_table_records_reads_and_forgets() {
        records_reads_and_forgets::<crate::bounded::Static>();
    }

    /// The fixed table refuses a new id past `MAX_DECLARED_KEYEXPRS`, and a key longer than a row
    /// holds, keeping what it held; an id it holds is rebound without room.
    #[test]
    fn the_fixed_table_refuses_past_its_rows_and_its_key() {
        let mut table = DeclaredKeyexprs::<crate::bounded::Static>::default();
        let ids =
            ExprId::try_from(caps::MAX_DECLARED_KEYEXPRS).expect("the build's rows fit an id");
        for id in 1..=ids {
            assert_eq!(table.record(id, "k"), Ok(()), "id {id} fits");
        }
        assert_eq!(
            table.record(ids + 1, "k"),
            Err(KeyexprUnrecorded::TableFull)
        );
        assert_eq!(table.record(1, "again"), Ok(()), "a held id needs no row");
        assert_eq!(table.len(), caps::MAX_DECLARED_KEYEXPRS);
        let long = "k".repeat(caps::MAX_KEYEXPR_BYTES + 1);
        assert_eq!(
            table.record(1, &long),
            Err(KeyexprUnrecorded::Key(KeyUnkept::TooLong))
        );
        assert_eq!(
            table.literal(1),
            Some("again"),
            "a refused key changes nothing"
        );
    }

    /// The table answers as the session's own space: an id it holds is appended to the
    /// resolver's buffer, one it does not is no answer.
    #[test]
    fn the_table_is_the_own_space() {
        let mut table = DeclaredKeyexprs::<crate::bounded::Static>::default();
        assert_eq!(table.record(3, "demo/x"), Ok(()));
        let mut out = KeyexprBuf::default();
        assert!(matches!(
            table.append_own_mapping(3, &mut out),
            Some(Ok(()))
        ));
        assert_eq!(&*out, "demo/x");
        assert!(table.append_own_mapping(4, &mut out).is_none());
    }

    /// A link that keeps its table records what it sends and forgets what it retracts; a link
    /// whose session keeps the table records nothing and reads the session's.
    #[cfg(all(
        feature = "session-unicast",
        feature = "declare-keyexpr",
        feature = "declare-undeclare"
    ))]
    #[test]
    fn a_link_records_only_where_it_keeps_the_table() {
        let mut held = LinkKeyexprs::default();
        held.sent_declaration(5, "home/temp");
        assert_eq!(held.held().and_then(|t| t.literal(5)), Some("home/temp"));
        let mut out = KeyexprBuf::default();
        assert!(matches!(
            held.space()
                .and_then(|space| space.append_own_mapping(5, &mut out)),
            Some(Ok(()))
        ));
        held.sent_retraction(5);
        assert_eq!(held.held().and_then(|t| t.literal(5)), None);

        // A link whose session keeps the table records nothing it sends and reads nothing.
        let mut kept = LinkKeyexprs::Session;
        kept.sent_declaration(9, "home/link");
        assert!(kept.held().is_none(), "the link keeps no table");
        assert!(kept.space().is_none(), "nor reads the session's");
        kept.sent_retraction(9);
        assert!(kept.held().is_none());
    }
}
