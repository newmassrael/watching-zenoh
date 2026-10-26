// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The read-only table of a closed key set (`docs/closed-key-set.md`): every key an image handles,
//! numbered, and for each key the entities a message on it reaches.
//!
//! # What it is
//!
//! An image that knows its keys when it is built declares them once. The build derives, from that
//! declaration, the answers the receive path would otherwise compute from text: a [`KeyId`] for
//! every key, and for every key and every [`EntityKind`] the [`Selection`] of entities whose
//! pattern intersects it. This module is the table and the reads of it; it counts and indexes
//! only. It reads no clock, allocates nothing and owns no memory: the arrays are `static`, written
//! by `scripts/lib/wz_key_set.py`, and [`KeyCatalogue`] borrows them.
//!
//! # The rules it states once
//!
//! * Keys are sorted by their bytes and unique, and a [`KeyId`] is a key's place in that order, so
//!   [`KeyCatalogue::find_exact`] is a binary search and a key's id does not depend on the order
//!   the keys were declared in.
//! * A selection is one entity kind's entities, in entity order, with no repeat.
//! * An entity is a kind and a key, declared once. An [`EntityId`] is its row in the entity table,
//!   and the rows ascend by kind and then key, so [`KeyCatalogue::find_entity`] is a binary search.
//! * A text that is not in the table is [`None`], which is what a closed image refuses; this
//!   module does not decide what a refusal does.
//! * What a selection contains is the intersection the glob matcher answers
//!   ([`crate::keyexpr_match::keyexpr_intersects_text`]); the model test of
//!   `tests/key_catalogue_model.rs` compares every selection of a generated table with it.
//!
//! # A bad table is a build error
//!
//! [`KeyCatalogue::new`] is a `const fn` that checks every property above, so a table the generator
//! wrote wrongly stops the build that contains it, and a [`KeyCatalogue`] that exists is one whose
//! reads cannot go out of range. [`KeyCatalogue::try_new`] is the same check that answers with the
//! reason, for a test.

/// How many [`EntityKind`]s there are: the width of a key's row of the selection table.
pub const KINDS: usize = 5;

/// What an entity is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntityKind {
    /// Puts samples on a key.
    Publisher,
    /// Receives the samples on the keys its pattern intersects.
    Subscriber,
    /// Answers the queries on the keys its pattern intersects.
    Queryable,
    /// Asks queries on the keys its pattern intersects.
    Querier,
    /// A liveliness token.
    LivelinessToken,
}

impl EntityKind {
    /// Every kind, in index order.
    pub const ALL: [EntityKind; KINDS] = [
        EntityKind::Publisher,
        EntityKind::Subscriber,
        EntityKind::Queryable,
        EntityKind::Querier,
        EntityKind::LivelinessToken,
    ];

    /// The kind's place in [`Self::ALL`], which is its column in the selection table.
    pub const fn index(self) -> usize {
        match self {
            EntityKind::Publisher => 0,
            EntityKind::Subscriber => 1,
            EntityKind::Queryable => 2,
            EntityKind::Querier => 3,
            EntityKind::LivelinessToken => 4,
        }
    }
}

/// A key of the set: its place in the sorted key table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(u16);

impl KeyId {
    /// The key at `index` of the table. A value no table has is refused by the table's reads, not
    /// here.
    pub const fn new(index: u16) -> Self {
        Self(index)
    }

    /// The key's place in the sorted key table.
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// An entity of the image: its row in the entity table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntityId(u16);

impl EntityId {
    /// The entity at `index` of the table.
    pub const fn new(index: u16) -> Self {
        Self(index)
    }

    /// The entity's row in the entity table.
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// One row of the entity table: what an entity is and the key it is declared on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntityRow {
    /// What the entity is.
    pub kind: EntityKind,
    /// The key its pattern is: the entity's pattern is that key's text.
    pub key: KeyId,
}

impl EntityRow {
    /// A row for an entity of `kind` declared on `key`.
    pub const fn new(kind: EntityKind, key: KeyId) -> Self {
        Self { kind, key }
    }
}

/// The entities one key and one kind reach: a view into the table, in entity order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection<'a> {
    members: &'a [EntityId],
}

impl<'a> Selection<'a> {
    /// How many entities are selected.
    pub const fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether no entity is selected.
    pub const fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The selected entities, in entity order.
    pub const fn as_slice(&self) -> &'a [EntityId] {
        self.members
    }

    /// The selected entities, in entity order.
    pub fn iter(&self) -> impl Iterator<Item = EntityId> + 'a {
        self.members.iter().copied()
    }

    /// Whether `entity` is selected.
    pub fn contains(&self, entity: EntityId) -> bool {
        self.members.binary_search(&entity).is_ok()
    }
}

/// Why a table is not one: the first property it breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableError {
    /// More keys, or more entities, than a `u16` numbers.
    TooLarge,
    /// A key's end is before the previous key's, or past the end of the text.
    KeyEnds,
    /// A key is empty, or does not end where a character does.
    KeyText,
    /// Two neighbouring keys are not in strictly rising byte order.
    KeyOrder,
    /// The selection offsets are not one more than the number of cells, do not start at 0, fall,
    /// or do not end at the number of members.
    Offsets,
    /// An entity's key is not a key of the table.
    EntityKey,
    /// The entities are not strictly ascending by kind and then key, which is what
    /// [`KeyCatalogue::find_entity`] searches on and what makes an entity declared once.
    EntityOrder,
    /// A selection names an entity that is not in the table, or names kinds mixed, or repeats or
    /// reorders entities.
    Members,
}

impl TableError {
    /// The reason in words, for the build error a bad table is.
    pub const fn describe(self) -> &'static str {
        match self {
            TableError::TooLarge => "a key catalogue holds at most 65535 keys and 65535 entities",
            TableError::KeyEnds => "a key catalogue's key ends are not rising within the text",
            TableError::KeyText => "a key catalogue's key is empty or splits a character",
            TableError::KeyOrder => "a key catalogue's keys are not strictly sorted by their bytes",
            TableError::Offsets => "a key catalogue's selection offsets do not cover its members",
            TableError::EntityKey => "a key catalogue's entity names a key that is not in it",
            TableError::EntityOrder => {
                "a key catalogue's entities are not strictly ascending by kind and key"
            }
            TableError::Members => {
                "a key catalogue's selection names an unknown, repeated, misordered or foreign entity"
            }
        }
    }
}

/// The table of a closed key set. See the module note.
///
/// The five slices are the generated arrays:
///
/// * `text` is every key's bytes joined in key order, and `ends[i]` is where key `i` ends in it
///   (it starts where key `i - 1` ends, the first at 0);
/// * `offsets` has `keys * KINDS + 1` entries, and the selection of key `k` and kind `c` is
///   `members[offsets[k * KINDS + c]..offsets[k * KINDS + c + 1]]`;
/// * `entities` is the entity table.
#[derive(Debug, Clone, Copy)]
pub struct KeyCatalogue<'a> {
    text: &'a str,
    ends: &'a [u16],
    offsets: &'a [u16],
    members: &'a [EntityId],
    entities: &'a [EntityRow],
}

impl<'a> KeyCatalogue<'a> {
    /// The table over the generated arrays, or why they are not one.
    pub const fn try_new(
        text: &'a str,
        ends: &'a [u16],
        offsets: &'a [u16],
        members: &'a [EntityId],
        entities: &'a [EntityRow],
    ) -> Result<Self, TableError> {
        let table = Self {
            text,
            ends,
            offsets,
            members,
            entities,
        };
        match table.check() {
            Ok(()) => Ok(table),
            Err(error) => Err(error),
        }
    }

    /// The table over the generated arrays. A bad table panics, and in a `const` it stops the
    /// build, which is where the generated one is built.
    pub const fn new(
        text: &'a str,
        ends: &'a [u16],
        offsets: &'a [u16],
        members: &'a [EntityId],
        entities: &'a [EntityRow],
    ) -> Self {
        match Self::try_new(text, ends, offsets, members, entities) {
            Ok(table) => table,
            Err(error) => panic!("{}", error.describe()),
        }
    }

    /// How many keys the set has.
    pub const fn key_count(&self) -> usize {
        self.ends.len()
    }

    /// How many entities the image declares.
    pub const fn entity_count(&self) -> usize {
        self.entities.len()
    }

    /// The key's text. The empty text for an id that is not in the table.
    pub fn text(&self, key: KeyId) -> &'a str {
        match self.span(key.index()) {
            Some((start, end)) => self.text.get(start..end).unwrap_or(""),
            None => "",
        }
    }

    /// Whether the key is a pattern (it has a wildcard) and not one concrete key.
    pub fn is_wildcard(&self, key: KeyId) -> bool {
        crate::keyexpr_match::is_wild(self.text(key))
    }

    /// The id of the key spelled exactly `text`: `None` when `text` is not a key of the set, which
    /// is the answer a closed image refuses on. Text is compared as it lies; nothing is split.
    pub fn find_exact(&self, text: &str) -> Option<KeyId> {
        let target = text.as_bytes();
        let mut low = 0usize;
        let mut high = self.ends.len();
        while low < high {
            let middle = low + (high - low) / 2;
            let (start, end) = self.span(middle)?;
            let key = self.text.as_bytes().get(start..end)?;
            match key.cmp(target) {
                core::cmp::Ordering::Equal => return Some(KeyId::new(u16::try_from(middle).ok()?)),
                core::cmp::Ordering::Less => low = middle + 1,
                core::cmp::Ordering::Greater => high = middle,
            }
        }
        None
    }

    /// The entity at `entity`, or `None` for an id that is not in the table.
    pub fn entity(&self, entity: EntityId) -> Option<EntityRow> {
        self.entities.get(entity.index()).copied()
    }

    /// The entity of `kind` declared on exactly `key`, if the image declares one: the question a
    /// local declaration asks, where [`Self::selection`] answers the one a message asks. A binary
    /// search, since entities are ascending by kind and then key.
    pub fn find_entity(&self, kind: EntityKind, key: KeyId) -> Option<EntityId> {
        let (mut low, mut high) = (0usize, self.entities.len());
        while low < high {
            let middle = low + (high - low) / 2;
            let row = self.entities.get(middle)?;
            let order = (row.kind.index(), row.key.index()).cmp(&(kind.index(), key.index()));
            match order {
                core::cmp::Ordering::Equal => {
                    return Some(EntityId::new(u16::try_from(middle).ok()?))
                }
                core::cmp::Ordering::Less => low = middle + 1,
                core::cmp::Ordering::Greater => high = middle,
            }
        }
        None
    }

    /// The entities of `kind` whose pattern intersects `key`, in entity order: two reads of the
    /// offsets and one slice. Empty for an id that is not in the table.
    pub fn selection(&self, key: KeyId, kind: EntityKind) -> Selection<'a> {
        let cell = key.index() * KINDS + kind.index();
        let members = match (self.offsets.get(cell), self.offsets.get(cell + 1)) {
            (Some(&from), Some(&to)) if key.index() < self.ends.len() => self
                .members
                .get(usize::from(from)..usize::from(to))
                .unwrap_or(&[]),
            _ => &[],
        };
        Selection { members }
    }

    /// Where key `index` starts and ends in the text.
    fn span(&self, index: usize) -> Option<(usize, usize)> {
        let end = usize::from(*self.ends.get(index)?);
        let start = match index {
            0 => 0,
            _ => usize::from(*self.ends.get(index - 1)?),
        };
        Some((start, end))
    }

    /// Every property of the module note, in the order [`TableError`] lists them.
    const fn check(&self) -> Result<(), TableError> {
        let keys = self.ends.len();
        if keys > u16::MAX as usize
            || self.entities.len() > u16::MAX as usize
            || self.text.len() > u16::MAX as usize
        {
            return Err(TableError::TooLarge);
        }
        if let Err(error) = self.check_keys() {
            return Err(error);
        }
        if let Err(error) = self.check_entities() {
            return Err(error);
        }
        self.check_selections()
    }

    const fn check_keys(&self) -> Result<(), TableError> {
        let bytes = self.text.as_bytes();
        let mut index = 0;
        let mut start = 0usize;
        while index < self.ends.len() {
            let end = self.ends[index] as usize;
            if end < start || end > bytes.len() {
                return Err(TableError::KeyEnds);
            }
            if end == start {
                return Err(TableError::KeyText);
            }
            let (head, _) = bytes.split_at(end);
            let (_, key) = head.split_at(start);
            if core::str::from_utf8(key).is_err() {
                return Err(TableError::KeyText);
            }
            if index > 0 {
                let previous_end = start;
                let previous_start = if index == 1 {
                    0
                } else {
                    self.ends[index - 2] as usize
                };
                let (head, _) = bytes.split_at(previous_end);
                let (_, previous) = head.split_at(previous_start);
                if !bytes_less(previous, key) {
                    return Err(TableError::KeyOrder);
                }
            }
            start = end;
            index += 1;
        }
        if start != bytes.len() {
            return Err(TableError::KeyEnds);
        }
        Ok(())
    }

    const fn check_entities(&self) -> Result<(), TableError> {
        let mut index = 0;
        while index < self.entities.len() {
            if self.entities[index].key.index() >= self.ends.len() {
                return Err(TableError::EntityKey);
            }
            if index > 0 {
                let (before, this) = (self.entities[index - 1], self.entities[index]);
                let ascending = before.kind.index() < this.kind.index()
                    || (before.kind.index() == this.kind.index()
                        && before.key.index() < this.key.index());
                if !ascending {
                    return Err(TableError::EntityOrder);
                }
            }
            index += 1;
        }
        Ok(())
    }

    const fn check_selections(&self) -> Result<(), TableError> {
        let cells = self.ends.len() * KINDS;
        if self.offsets.len() != cells + 1
            || self.offsets[0] != 0
            || self.offsets[cells] as usize != self.members.len()
        {
            return Err(TableError::Offsets);
        }
        let mut cell = 0;
        while cell < cells {
            let from = self.offsets[cell] as usize;
            let to = self.offsets[cell + 1] as usize;
            if to < from || to > self.members.len() {
                return Err(TableError::Offsets);
            }
            let kind = cell % KINDS;
            let mut at = from;
            while at < to {
                let member = self.members[at].index();
                if member >= self.entities.len() || self.entities[member].kind.index() != kind {
                    return Err(TableError::Members);
                }
                if at > from && self.members[at - 1].index() >= member {
                    return Err(TableError::Members);
                }
                at += 1;
            }
            cell += 1;
        }
        Ok(())
    }
}

/// Whether `a` sorts strictly before `b` by bytes, which `Ord` on slices is not in a `const`.
const fn bytes_less(a: &[u8], b: &[u8]) -> bool {
    let mut i = 0;
    while i < a.len() && i < b.len() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
        i += 1;
    }
    a.len() < b.len()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // Three keys, "a", "a/b" and "a/*", sorted by bytes: "a" < "a/*" < "a/b" ('*' is 0x2A, 'b' is
    // 0x62). Entities: 0 a publisher on "a/b", 1 a subscriber on "a/*" and 2 a queryable on "a".
    const TEXT: &str = "aa/*a/b";
    const ENDS: [u16; 3] = [1, 4, 7];
    const ENTITIES: [EntityRow; 3] = [
        EntityRow::new(EntityKind::Publisher, KeyId::new(2)),
        EntityRow::new(EntityKind::Subscriber, KeyId::new(1)),
        EntityRow::new(EntityKind::Queryable, KeyId::new(0)),
    ];
    // A key's cells are publisher, subscriber, queryable, querier, token. What each holds:
    //   key 0 "a":   [] [] [2] [] []
    //   key 1 "a/*": [0] [1] [] [] []   (the publisher on "a/b" intersects "a/*")
    //   key 2 "a/b": [0] [1] [] [] []
    const OFFSETS: [u16; 16] = [0, 0, 0, 1, 1, 1, 2, 3, 3, 3, 3, 4, 5, 5, 5, 5];
    const MEMBERS: [EntityId; 5] = [
        EntityId::new(2),
        EntityId::new(0),
        EntityId::new(1),
        EntityId::new(0),
        EntityId::new(1),
    ];
    /// The three-key table of these tests, for the tests of what is built on a catalogue.
    pub(crate) const TABLE: KeyCatalogue<'static> =
        KeyCatalogue::new(TEXT, &ENDS, &OFFSETS, &MEMBERS, &ENTITIES);

    fn rebuilt(
        text: &str,
        ends: &[u16],
        offsets: &[u16],
        members: &[EntityId],
    ) -> Result<usize, TableError> {
        KeyCatalogue::try_new(text, ends, offsets, members, &ENTITIES).map(|t| t.key_count())
    }

    #[test]
    fn reads_what_the_arrays_say() {
        assert_eq!(TABLE.key_count(), 3);
        assert_eq!(TABLE.entity_count(), 3);
        assert_eq!(TABLE.text(KeyId::new(0)), "a");
        assert_eq!(TABLE.text(KeyId::new(1)), "a/*");
        assert_eq!(TABLE.text(KeyId::new(2)), "a/b");
        assert!(!TABLE.is_wildcard(KeyId::new(0)));
        assert!(TABLE.is_wildcard(KeyId::new(1)));
        let selected = TABLE.selection(KeyId::new(2), EntityKind::Subscriber);
        assert_eq!(selected.as_slice(), &[EntityId::new(1)]);
        assert!(selected.contains(EntityId::new(1)));
        assert!(!selected.contains(EntityId::new(0)));
        assert_eq!(
            TABLE.selection(KeyId::new(2), EntityKind::Publisher).len(),
            1
        );
        assert!(TABLE
            .selection(KeyId::new(0), EntityKind::Subscriber)
            .is_empty());
        assert_eq!(
            TABLE.entity(EntityId::new(1)),
            Some(EntityRow::new(EntityKind::Subscriber, KeyId::new(1)))
        );
    }

    #[test]
    fn find_exact_is_the_inverse_of_text() {
        for index in 0..TABLE.key_count() {
            let id = KeyId::new(index as u16);
            assert_eq!(TABLE.find_exact(TABLE.text(id)), Some(id));
        }
        assert_eq!(TABLE.find_exact("a/c"), None);
        assert_eq!(TABLE.find_exact(""), None);
        assert_eq!(TABLE.find_exact("a/"), None);
        assert_eq!(TABLE.find_exact("b"), None);
    }

    #[test]
    fn an_id_outside_the_table_reads_as_nothing() {
        let outside = KeyId::new(3);
        assert_eq!(TABLE.text(outside), "");
        assert!(TABLE.selection(outside, EntityKind::Subscriber).is_empty());
        assert_eq!(TABLE.entity(EntityId::new(3)), None);
    }

    #[test]
    fn a_table_that_breaks_a_property_is_refused_by_that_property() {
        assert_eq!(
            rebuilt("aa/*a/b", &[1, 7, 4], &OFFSETS, &MEMBERS),
            Err(TableError::KeyEnds)
        );
        // Text that no key owns, and a key that ends past the text.
        assert_eq!(
            rebuilt("aa/*a/bb", &[1, 4, 7], &OFFSETS, &MEMBERS),
            Err(TableError::KeyEnds)
        );
        assert_eq!(
            rebuilt("aa/*a/b", &[1, 4, 9], &OFFSETS, &MEMBERS),
            Err(TableError::KeyEnds)
        );
        assert_eq!(
            rebuilt("aa/*a/b", &[1, 1, 7], &OFFSETS, &MEMBERS),
            Err(TableError::KeyText)
        );
        // "a/b" before "a/*": not sorted.
        assert_eq!(
            rebuilt("aa/ba/*", &[1, 4, 7], &OFFSETS, &MEMBERS),
            Err(TableError::KeyOrder)
        );
        // The same key twice.
        assert_eq!(
            rebuilt("aaa", &[1, 2, 3], &OFFSETS, &MEMBERS),
            Err(TableError::KeyOrder)
        );
        assert_eq!(
            rebuilt(TEXT, &ENDS, &OFFSETS[..15], &MEMBERS),
            Err(TableError::Offsets)
        );
        // A member the offsets do not reach.
        assert_eq!(
            rebuilt(TEXT, &ENDS, &OFFSETS, &MEMBERS[..3]),
            Err(TableError::Offsets)
        );
        // Entity 1 is a subscriber: not a publisher's member (key 1's publisher cell).
        assert_eq!(
            rebuilt(
                TEXT,
                &ENDS,
                &OFFSETS,
                &[
                    EntityId::new(2),
                    EntityId::new(1),
                    EntityId::new(1),
                    EntityId::new(0),
                    EntityId::new(1)
                ]
            ),
            Err(TableError::Members)
        );
        // Entity 9 is not in the table.
        assert_eq!(
            rebuilt(
                TEXT,
                &ENDS,
                &OFFSETS,
                &[
                    EntityId::new(2),
                    EntityId::new(9),
                    EntityId::new(1),
                    EntityId::new(0),
                    EntityId::new(1)
                ]
            ),
            Err(TableError::Members)
        );
        assert_eq!(
            KeyCatalogue::try_new(
                TEXT,
                &ENDS,
                &OFFSETS,
                &MEMBERS,
                &[
                    EntityRow::new(EntityKind::Publisher, KeyId::new(3)),
                    ENTITIES[1],
                    ENTITIES[2]
                ]
            )
            .map(|t| t.key_count()),
            Err(TableError::EntityKey)
        );
    }

    #[test]
    fn a_selection_that_repeats_or_reorders_is_refused() {
        // Two subscribers (entities 1 and 2) give one cell two members.
        const ENTITIES_TWO: [EntityRow; 4] = [
            EntityRow::new(EntityKind::Publisher, KeyId::new(2)),
            EntityRow::new(EntityKind::Subscriber, KeyId::new(1)),
            EntityRow::new(EntityKind::Subscriber, KeyId::new(2)),
            EntityRow::new(EntityKind::Queryable, KeyId::new(0)),
        ];
        // Key 0 queryable [3]; key 1 publisher [0] and subscriber [a, b]; key 2 the same.
        let offsets: [u16; 16] = [0, 0, 0, 1, 1, 1, 2, 4, 4, 4, 4, 5, 7, 7, 7, 7];
        let keys_of = |first: u16, second: u16| {
            let members = [
                EntityId::new(3),
                EntityId::new(0),
                EntityId::new(first),
                EntityId::new(second),
                EntityId::new(0),
                EntityId::new(1),
                EntityId::new(2),
            ];
            KeyCatalogue::try_new(TEXT, &ENDS, &offsets, &members, &ENTITIES_TWO)
                .map(|table| table.key_count())
        };
        assert_eq!(keys_of(1, 2), Ok(3));
        assert_eq!(keys_of(2, 1), Err(TableError::Members));
        assert_eq!(keys_of(1, 1), Err(TableError::Members));
    }

    #[test]
    fn an_entity_is_found_by_its_kind_and_key() {
        let key = |text: &str| TABLE.find_exact(text).expect("a key of the table");
        assert_eq!(
            TABLE.find_entity(EntityKind::Publisher, key("a/b")),
            Some(EntityId::new(0))
        );
        assert_eq!(
            TABLE.find_entity(EntityKind::Subscriber, key("a/*")),
            Some(EntityId::new(1))
        );
        assert_eq!(
            TABLE.find_entity(EntityKind::Queryable, key("a")),
            Some(EntityId::new(2))
        );
        // The key is in the set, and this role is not declared on it.
        assert_eq!(TABLE.find_entity(EntityKind::Subscriber, key("a/b")), None);
        assert_eq!(TABLE.find_entity(EntityKind::Publisher, key("a")), None);
        assert_eq!(TABLE.find_entity(EntityKind::Querier, key("a")), None);
        assert_eq!(
            TABLE.find_entity(EntityKind::Publisher, KeyId::new(9)),
            None
        );
    }

    #[test]
    fn entities_out_of_order_or_repeated_are_refused() {
        let with = |entities: &[EntityRow]| {
            KeyCatalogue::try_new(TEXT, &ENDS, &OFFSETS, &MEMBERS, entities)
                .map(|table| table.entity_count())
        };
        // A subscriber before a publisher, and the same entity twice.
        assert_eq!(
            with(&[ENTITIES[1], ENTITIES[0], ENTITIES[2]]),
            Err(TableError::EntityOrder)
        );
        assert_eq!(
            with(&[ENTITIES[0], ENTITIES[1], ENTITIES[1]]),
            Err(TableError::EntityOrder)
        );
    }

    #[test]
    fn an_empty_set_is_a_table() {
        let table = KeyCatalogue::try_new("", &[], &[0], &[], &[]).expect("empty table");
        assert_eq!(table.key_count(), 0);
        assert_eq!(table.find_exact("a"), None);
    }
}
