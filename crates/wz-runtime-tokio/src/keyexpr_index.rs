// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A persistent index of members by keyexpr: which of the members stored under keyexprs may meet a
//! keyexpr a declaration names, found without trying every stored keyexpr.
//!
//! The router's interest stores answered "which faces asked for something this declaration meets"
//! by trying every face's every interest, so each declaration cost as many tries as faces were up
//! (`docs/router-table-snapshots.md`, sections 6.3 and 7). This index answers it from a trie of
//! keyexpr chunks, the structure upstream's resource tree and its `KeTree`s are
//! (`commons/zenoh-keyexpr/src/keyexpr_tree/mod.rs` @ `Key Expression Trees (KeTrees)`): a key is
//! the path of its chunks from the root, and a query walks only the branches its own chunks can
//! meet.
//!
//! The index is the FILTER half of filter and refine (the shape spatial indexes take, Orenstein
//! 1986; Guttman 1984): [`KeyexprIndex::intersecting`] yields every member whose keyexpr can
//! intersect the query, and may yield more; the caller refines each with the exact matcher it used
//! before (`wz_session_core::keyexpr_match::keyexpr_intersects_target`). The walk prunes only by
//! what holds under every keyexpr feature: a chunk with no `*` meets only the same chunk, and a
//! `**` on either side may stand for any number of chunks. The exact rules (verbatim `@` chunks,
//! `$*` within a chunk, a feature turned off that makes `*` a literal) stay in the matcher, so the
//! answer after the refine is the answer the full scan gave, under every configuration.
//!
//! A node keeps its literal children apart from its wild ones (a chunk holding a `*`), so a query
//! chunk with no `*` follows one literal child by hash and every wild child, and never the other
//! literals: a query of a key with no wildcard against keys with none costs the key's depth.
//!
//! Persistent, as the tables that hold it are: every map in a node is a [`PersistentMap`], so a
//! copy shares the index and a write copies the nodes on the path to what it changes
//! (`docs/router-table-snapshots.md`, phase 6). A write reads its path first and writes nothing
//! when it would change nothing.

use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;

use wz_session_core::keyexpr_match::is_wild;

use crate::persistent_map::{PersistentMap, PersistentSet};

/// The chunk that stands for any number of chunks, on either side.
const ANY_CHUNKS: &str = "**";

/// A persistent index of members of type `M` by keyexpr. See the module documentation.
pub(crate) struct KeyexprIndex<M> {
    root: IndexNode<M>,
    len: usize,
}

/// A node: the members stored under the keyexpr its path spells, and its children by chunk.
struct IndexNode<M> {
    members: PersistentSet<M>,
    /// Children whose chunk holds no `*`.
    literal: PersistentMap<Box<str>, IndexNode<M>>,
    /// Children whose chunk holds a `*`: `*`, `**`, or a chunk with `$*` in it.
    wild: PersistentMap<Box<str>, IndexNode<M>>,
}

impl<M> Clone for IndexNode<M> {
    fn clone(&self) -> Self {
        Self {
            members: self.members.clone(),
            literal: self.literal.clone(),
            wild: self.wild.clone(),
        }
    }
}

impl<M> Default for IndexNode<M> {
    fn default() -> Self {
        Self {
            members: PersistentSet::default(),
            literal: PersistentMap::new(),
            wild: PersistentMap::new(),
        }
    }
}

impl<M> IndexNode<M> {
    fn is_empty(&self) -> bool {
        self.members.is_empty() && self.literal.is_empty() && self.wild.is_empty()
    }

    fn children(&self) -> impl Iterator<Item = &IndexNode<M>> + '_ {
        self.literal.values().chain(self.wild.values())
    }

    fn child(&self, chunk: &str) -> Option<&IndexNode<M>> {
        if is_wild(chunk) {
            self.wild.get(chunk)
        } else {
            self.literal.get(chunk)
        }
    }
}

impl<M: Hash + Eq + Clone> IndexNode<M> {
    /// The children map `chunk` belongs in, for writing.
    fn children_mut(&mut self, chunk: &str) -> &mut PersistentMap<Box<str>, IndexNode<M>> {
        if is_wild(chunk) {
            &mut self.wild
        } else {
            &mut self.literal
        }
    }

    /// Take `member` out of the node `chunks` lead to, which holds it, and drop every node the
    /// removal leaves empty on the way back.
    fn remove_below(&mut self, chunks: &[&str], member: &M) {
        let Some((head, rest)) = chunks.split_first() else {
            let removed = self.members.remove(member);
            debug_assert!(removed, "the read found the member here");
            return;
        };
        let children = self.children_mut(head);
        let emptied = {
            let child = children
                .get_mut(*head)
                .expect("the read found the path to the member");
            child.remove_below(rest, member);
            child.is_empty()
        };
        if emptied {
            children.remove(*head);
        }
    }
}

impl<M> KeyexprIndex<M> {
    /// An empty index.
    pub(crate) fn new() -> Self {
        Self {
            root: IndexNode::default(),
            len: 0,
        }
    }

    /// How many members the index holds: what the tests compare with the stores that index.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Whether the index holds no member.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Every member stored under a keyexpr that may intersect `keyexpr`, each once, and possibly
    /// some whose keyexpr does not: the caller refines each with the exact matcher (see the module
    /// documentation).
    pub(crate) fn intersecting(&self, keyexpr: &str) -> Vec<&M> {
        self.walk(keyexpr).found
    }

    fn walk<'q>(&self, keyexpr: &'q str) -> Walk<'_, 'q, M> {
        let chunks: Vec<&str> = keyexpr.split('/').collect();
        let mut walk = Walk {
            chunks,
            seen: HashSet::new(),
            found: Vec::new(),
        };
        walk.visit(&self.root, 0);
        walk
    }
}

impl<M: Hash + Eq> KeyexprIndex<M> {
    /// Whether `member` is stored under `keyexpr`.
    pub(crate) fn contains(&self, keyexpr: &str, member: &M) -> bool {
        let mut node = &self.root;
        for chunk in keyexpr.split('/') {
            match node.child(chunk) {
                Some(child) => node = child,
                None => return false,
            }
        }
        node.members.contains(member)
    }
}

impl<M: Hash + Eq + Clone> KeyexprIndex<M> {
    /// Store `member` under `keyexpr`, saying whether it was not there. A member already there
    /// writes nothing.
    pub(crate) fn insert(&mut self, keyexpr: &str, member: M) -> bool {
        if self.contains(keyexpr, &member) {
            return false;
        }
        let mut node = &mut self.root;
        for chunk in keyexpr.split('/') {
            node = node
                .children_mut(chunk)
                .get_mut_or_default(Box::from(chunk));
        }
        let added = node.members.insert(member);
        debug_assert!(added, "the read did not find the member");
        self.len += 1;
        true
    }

    /// Take `member` out from under `keyexpr`, saying whether it was there. A member not there
    /// writes nothing.
    pub(crate) fn remove(&mut self, keyexpr: &str, member: &M) -> bool {
        if !self.contains(keyexpr, member) {
            return false;
        }
        let chunks: Vec<&str> = keyexpr.split('/').collect();
        self.root.remove_below(&chunks, member);
        self.len -= 1;
        true
    }
}

impl<M> Default for KeyexprIndex<M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<M> Clone for KeyexprIndex<M> {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            len: self.len,
        }
    }
}

impl<M> fmt::Debug for KeyexprIndex<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyexprIndex")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// One query's walk: the query's chunks, the states already visited, and the members found.
///
/// A state is a node and how many of the query's chunks the path to it has consumed. A `**` on
/// either side lets one node be reached at several positions and one position at several nodes;
/// visiting each state once bounds the walk by the nodes times the positions, and finds each
/// member once, since a member lives in one node and is taken only where the query is consumed.
struct Walk<'i, 'q, M> {
    chunks: Vec<&'q str>,
    seen: HashSet<(*const IndexNode<M>, usize)>,
    found: Vec<&'i M>,
}

impl<'i, M> Walk<'i, '_, M> {
    fn visit(&mut self, node: &'i IndexNode<M>, at: usize) {
        if !self.seen.insert((node as *const IndexNode<M>, at)) {
            return;
        }
        // A stored `**` stands for none or any number of the query's remaining chunks.
        if let Some(any) = node.wild.get(ANY_CHUNKS) {
            for next in at..=self.chunks.len() {
                self.visit(any, next);
            }
        }
        let Some(&head) = self.chunks.get(at) else {
            self.found.extend(node.members.iter());
            return;
        };
        if head == ANY_CHUNKS {
            // The query's `**` stands for none of what follows, or for the next stored chunk and
            // possibly more.
            self.visit(node, at + 1);
            for child in node.children() {
                self.visit(child, at);
            }
        } else if is_wild(head) {
            // A wild chunk may meet any one stored chunk.
            for child in node.children() {
                self.visit(child, at + 1);
            }
        } else {
            // A chunk with no `*` meets the same chunk and the wild ones.
            if let Some(child) = node.literal.get(head) {
                self.visit(child, at + 1);
            }
            for child in node.wild.values() {
                self.visit(child, at + 1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashMap};
    use wz_session_core::keyexpr_match::keyexpr_intersects_target;

    /// A small deterministic generator (xorshift64*), so that a failing sequence replays.
    struct Draw(u64);

    impl Draw {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        /// A keyexpr of one to four chunks, drawn from chunks that exercise every rule the
        /// matcher has: literals, `*`, `**`, `$*` within a chunk, and a verbatim chunk.
        fn keyexpr(&mut self) -> String {
            const CHUNKS: [&str; 9] = ["a", "b", "c", "*", "**", "x$*", "$*y", "@v", "@w"];
            let depth = 1 + self.next() % 4;
            (0..depth)
                .map(|_| CHUNKS[(self.next() % CHUNKS.len() as u64) as usize])
                .collect::<Vec<_>>()
                .join("/")
        }
    }

    fn exact(query: &str, target: &str) -> bool {
        let chunks: Vec<&str> = target.split('/').collect();
        keyexpr_intersects_target(query, &chunks)
    }

    /// Every `(keyexpr, member)` the index holds, read off its nodes.
    fn stored(index: &KeyexprIndex<u32>) -> BTreeSet<(String, u32)> {
        fn collect(
            node: &IndexNode<u32>,
            path: &mut Vec<String>,
            out: &mut BTreeSet<(String, u32)>,
        ) {
            for member in node.members.iter() {
                out.insert((path.join("/"), *member));
            }
            for (chunk, child) in node.literal.iter().chain(node.wild.iter()) {
                assert!(!child.is_empty(), "an empty node is kept below {path:?}");
                assert_eq!(is_wild(chunk), node.wild.contains_key(&**chunk));
                path.push(chunk.to_string());
                collect(child, path, out);
                path.pop();
            }
        }
        let mut out = BTreeSet::new();
        collect(&index.root, &mut Vec::new(), &mut out);
        out
    }

    /// Drive the index and a plain map of members to keyexprs through the same random inserts and
    /// removals, and after each step require: the same members held, and for random queries every
    /// member the exact matcher accepts among the found ones, each found once.
    #[test]
    fn the_index_finds_every_member_the_full_scan_finds() {
        for seed in 1..=8u64 {
            let mut draw = Draw(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let mut index: KeyexprIndex<u32> = KeyexprIndex::new();
            let mut model: HashMap<u32, String> = HashMap::new();
            let mut kept: Vec<(KeyexprIndex<u32>, HashMap<u32, String>)> = Vec::new();
            for step in 0..600 {
                let member = (draw.next() % 48) as u32;
                if draw.next() % 3 == 0 {
                    let held = model.remove(&member);
                    let keyexpr = held.clone().unwrap_or_else(|| draw.keyexpr());
                    assert_eq!(index.remove(&keyexpr, &member), held.is_some());
                } else if let std::collections::hash_map::Entry::Vacant(slot) = model.entry(member)
                {
                    let keyexpr = draw.keyexpr();
                    assert!(index.insert(&keyexpr, member));
                    assert!(
                        !index.insert(&keyexpr, member),
                        "a second insert adds nothing"
                    );
                    slot.insert(keyexpr);
                }
                assert_eq!(index.len(), model.len());
                let want: BTreeSet<(String, u32)> =
                    model.iter().map(|(m, k)| (k.clone(), *m)).collect();
                assert_eq!(stored(&index), want, "seed {seed} step {step}");
                for _ in 0..6 {
                    let query = draw.keyexpr();
                    let found = index.intersecting(&query);
                    let unique: BTreeSet<u32> = found.iter().map(|m| **m).collect();
                    assert_eq!(
                        unique.len(),
                        found.len(),
                        "a member found twice for {query}"
                    );
                    for (member, target) in &model {
                        if exact(&query, target) {
                            assert!(
                                unique.contains(member),
                                "seed {seed} step {step}: {query} meets {target} of {member}, \
                                 which the index did not find"
                            );
                        }
                    }
                }
                if step % 50 == 0 {
                    kept.push((index.clone(), model.clone()));
                }
            }
            // A copy is not moved by writes to the index it was copied from.
            for (copy, model) in kept {
                let want: BTreeSet<(String, u32)> =
                    model.iter().map(|(m, k)| (k.clone(), *m)).collect();
                assert_eq!(stored(&copy), want);
            }
        }
    }

    /// A query of a key with no wildcard, among keys with none, visits the key's own path and
    /// finds only the members stored under that very key.
    #[test]
    fn a_literal_query_among_literal_keys_walks_its_own_path() {
        let mut index: KeyexprIndex<u32> = KeyexprIndex::new();
        for i in 0..20_000u32 {
            index.insert(&format!("mesh/dev_{i}"), i);
        }
        index.insert("mesh/dev_7", 1_000_000);
        let walk = index.walk("mesh/dev_7");
        let found: BTreeSet<u32> = walk.found.iter().map(|m| **m).collect();
        assert_eq!(found, BTreeSet::from([7, 1_000_000]));
        assert_eq!(walk.seen.len(), 3, "the root, `mesh` and `mesh/dev_7`");
    }

    /// A stored wildcard is found by a literal query beside the literal key it meets, and the
    /// other literal keys are not walked.
    #[test]
    fn a_literal_query_walks_the_wild_branches_and_its_own_literal_only() {
        let mut index: KeyexprIndex<u32> = KeyexprIndex::new();
        for i in 0..1_000u32 {
            index.insert(&format!("mesh/dev_{i}"), i);
        }
        index.insert("mesh/*", 2_000);
        index.insert("**", 3_000);
        index.insert("mesh/**/x", 4_000);
        let walk = index.walk("mesh/dev_7");
        let found: BTreeSet<u32> = walk.found.iter().map(|m| **m).collect();
        assert!(found.is_superset(&BTreeSet::from([7, 2_000, 3_000])));
        assert!(found.iter().all(|m| *m >= 1_000 || *m == 7));
        assert!(walk.seen.len() < 16, "visited {}", walk.seen.len());
    }

    /// A wildcard query finds every key under the prefix it names and none outside it.
    #[test]
    fn a_wildcard_query_walks_only_the_prefix_it_names() {
        let mut index: KeyexprIndex<u32> = KeyexprIndex::new();
        for i in 0..1_000u32 {
            index.insert(&format!("a/{i}"), i);
            index.insert(&format!("b/{i}"), 10_000 + i);
        }
        let found: BTreeSet<u32> = index.intersecting("a/**").into_iter().copied().collect();
        assert_eq!(found, (0..1_000).collect());
    }

    /// A write to a copy of a large index leaves the copied index as it was, and removing the
    /// last member under a branch drops the branch.
    #[test]
    fn a_write_to_a_copy_leaves_the_original_and_prunes_empty_branches() {
        let mut index: KeyexprIndex<u32> = KeyexprIndex::new();
        for i in 0..10_000u32 {
            index.insert(&format!("k/{}/{}", i % 100, i), i);
        }
        let mut copy = index.clone();
        assert!(copy.remove("k/7/7", &7));
        assert!(copy.insert("k/7/new", 99_999));
        assert!(index.contains("k/7/7", &7));
        assert!(!index.contains("k/7/new", &99_999));
        assert!(!copy.contains("k/7/7", &7));
        assert_eq!((index.len(), copy.len()), (10_000, 10_000));
        let mut alone: KeyexprIndex<u32> = KeyexprIndex::new();
        alone.insert("p/q/r", 1);
        assert!(alone.remove("p/q/r", &1));
        assert!(alone.root.is_empty() && alone.is_empty());
        assert!(!alone.remove("p/q/r", &1));
    }
}
