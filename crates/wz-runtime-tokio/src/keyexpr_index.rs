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
//! before (`wz_session_core::keyexpr_match::keyexpr_intersects`). The walk prunes only by
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
//! (`docs/router-table-snapshots.md`, phase 6). A removal reads its path first and writes nothing
//! when it would change nothing. An insertion finds or makes its path in the one walk: a member
//! already there adds nothing, though that walk copies its path out of a version that shares it,
//! and no caller inserts a member it holds.
//!
//! A removal that leaves its node with no member and no child keeps the node, for a member that
//! comes back to the same key: a key declared and withdrawn again and again is the common churn,
//! and dropping its path each time made the next declaration build it again. Such nodes are
//! counted, and once there are more of them than [`dead_bound`] allows for the members held, one
//! sweep prunes every empty branch. So the nodes past what the members need are at most that
//! bound times a key's depth, and the sweep's cost, a read of the index and a write of the
//! branches it prunes, is spread over the removals that filled the bound. An index left with no
//! member drops every node at once. Upstream drops a resource as its last holder goes, by count
//! (`zenoh/src/net/routing/dispatcher/resource.rs` @ `if Arc::strong_count(res) <= 3 && res.children.is_empty() {`);
//! a persistent index pays a path copy for every node it drops, which is what the sweep spreads.

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
    /// The nodes a removal left with no member and no child, kept for a member that comes back
    /// (see the module documentation): exactly the empty leaves of the tree.
    dead: usize,
}

/// The fewest empty leaves an index keeps before it sweeps, whatever the members it holds.
const DEAD_FLOOR: usize = 64;

/// How many empty leaves an index of `len` members keeps before one sweep prunes them all: as
/// many as its members, and [`DEAD_FLOOR`] at the least, so that the nodes kept for nothing are
/// bounded by the members held and a sweep comes once per that many removals.
fn dead_bound(len: usize) -> usize {
    len.max(DEAD_FLOOR)
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

    /// Whether an empty node is in this subtree, this node included: what a sweep has to prune.
    fn holds_empty(&self) -> bool {
        self.is_empty() || self.children().any(IndexNode::holds_empty)
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

    /// Take `member` out of the node `chunks` lead to, which holds it, keeping every node, and say
    /// whether that node is left an empty leaf.
    fn remove_below(&mut self, chunks: &[&str], member: &M) -> bool {
        let Some((head, rest)) = chunks.split_first() else {
            let removed = self.members.remove(member);
            debug_assert!(removed, "the read found the member here");
            return self.is_empty();
        };
        self.children_mut(head)
            .get_mut(*head)
            .expect("the read found the path to the member")
            .remove_below(rest, member)
    }

    /// Drop every empty node below this one, children first, so that a node left with nothing
    /// once its children went goes too. Only the branches that hold an empty node are written,
    /// so a sweep copies those paths out of a shared version and no other.
    fn prune(&mut self) {
        let chunks: Vec<Box<str>> = self
            .literal
            .iter()
            .chain(self.wild.iter())
            .filter(|(_, child)| child.holds_empty())
            .map(|(chunk, _)| chunk.clone())
            .collect();
        for chunk in chunks {
            let children = self.children_mut(&chunk);
            let emptied = {
                let child = children
                    .get_mut(&*chunk)
                    .expect("the chunk was read off this node");
                child.prune();
                child.is_empty()
            };
            if emptied {
                children.remove(&*chunk);
            }
        }
    }
}

impl<M> KeyexprIndex<M> {
    /// An empty index.
    pub(crate) fn new() -> Self {
        Self {
            root: IndexNode::default(),
            len: 0,
            dead: 0,
        }
    }

    /// How many members the index holds: what the tests compare with the stores that index.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Whether the index holds no member: one read, which is how a store that holds no future
    /// interest answers a declaration without walking anything.
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Every member stored under a keyexpr that may intersect `keyexpr`, each once, and possibly
    /// some whose keyexpr does not: the caller refines each with the exact matcher (see the module
    /// documentation).
    pub(crate) fn intersecting(&self, keyexpr: &str) -> Vec<&M> {
        // An empty index answers without splitting the query or walking a node.
        if self.len == 0 {
            return Vec::new();
        }
        self.walk(keyexpr).found
    }

    /// [`intersecting`](Self::intersecting) while it finds `most` members or fewer, and `None`, its
    /// walk stopped, once it has found more: for a caller that has a cheaper way to the answer
    /// past that many, a scan of every member it holds elsewhere. A walk visits states, a set of
    /// them kept, and costs more a member found than a scan costs a member tried.
    pub(crate) fn intersecting_within(&self, keyexpr: &str, most: usize) -> Option<Vec<&M>> {
        if self.len == 0 {
            return Some(Vec::new());
        }
        let walk = self.walk_within(keyexpr, most);
        (!walk.over).then_some(walk.found)
    }

    fn walk<'q>(&self, keyexpr: &'q str) -> Walk<'_, 'q, M> {
        self.walk_within(keyexpr, usize::MAX)
    }

    fn walk_within<'q>(&self, keyexpr: &'q str, most: usize) -> Walk<'_, 'q, M> {
        let chunks: Vec<&str> = keyexpr.split('/').collect();
        let mut walk = Walk {
            chunks,
            seen: HashSet::new(),
            found: Vec::new(),
            most,
            over: false,
        };
        walk.visit(&self.root, 0);
        walk
    }
}

impl<M: Hash + Eq> KeyexprIndex<M> {
    /// Whether `member` is stored under `keyexpr`. The tests' view of the index: since an
    /// insertion walks its path once and a removal reads through `holds_at`, no write asks it.
    #[cfg(test)]
    pub(crate) fn contains(&self, keyexpr: &str, member: &M) -> bool {
        self.holds_at(keyexpr.split('/'), member)
    }

    /// Whether `member` is stored under the keyexpr `chunks` spell.
    fn holds_at<'c>(&self, chunks: impl IntoIterator<Item = &'c str>, member: &M) -> bool {
        let mut node = &self.root;
        for chunk in chunks {
            match node.child(chunk) {
                Some(child) => node = child,
                None => return false,
            }
        }
        node.members.contains(member)
    }
}

impl<M: Hash + Eq + Clone> KeyexprIndex<M> {
    /// Store `member` under `keyexpr`, saying whether it was not there: one walk of the chunks
    /// finds or makes the path (see the module documentation).
    pub(crate) fn insert(&mut self, keyexpr: &str, member: M) -> bool {
        let mut node = &mut self.root;
        // An empty leaf the path passes through or ends at takes a child or the member, and is
        // empty no more. A path holds at most one, as an empty leaf has no child to go on to.
        let mut revives = false;
        let mut made = false;
        let mut below_root = false;
        for chunk in keyexpr.split('/') {
            // A node this walk made a step ago is empty too, and is no empty leaf of the tree.
            revives |= below_root && !made && node.is_empty();
            below_root = true;
            made = false;
            // Found by the chunk's text: a chunk some key already holds allocates nothing.
            node = node.children_mut(chunk).get_mut_or_insert_by(
                chunk,
                || Box::from(chunk),
                || {
                    made = true;
                    IndexNode::default()
                },
            );
        }
        revives |= !made && node.is_empty();
        let added = node.members.insert(member);
        if added {
            self.len += 1;
        }
        if revives {
            debug_assert!(self.dead > 0, "an empty leaf of the tree is counted");
            self.dead = self.dead.saturating_sub(1);
        }
        added
    }

    /// Take `member` out from under `keyexpr`, saying whether it was there. A member not there
    /// writes nothing. The keyexpr is split once, for the read and the removal. The node it leaves
    /// empty is kept, and swept with the others past [`dead_bound`] (see the module
    /// documentation).
    pub(crate) fn remove(&mut self, keyexpr: &str, member: &M) -> bool {
        let chunks: Vec<&str> = keyexpr.split('/').collect();
        if !self.holds_at(chunks.iter().copied(), member) {
            return false;
        }
        let left_empty = self.root.remove_below(&chunks, member);
        self.len -= 1;
        if self.len == 0 {
            self.root = IndexNode::default();
            self.dead = 0;
        } else if left_empty {
            self.dead += 1;
            if self.dead > dead_bound(self.len) {
                self.root.prune();
                self.dead = 0;
            }
        }
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
            dead: self.dead,
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
    /// The most members the walk finds before it stops ([`KeyexprIndex::intersecting_within`]).
    most: usize,
    /// Whether it found more than `most`, and stopped.
    over: bool,
}

impl<'i, M> Walk<'i, '_, M> {
    fn visit(&mut self, node: &'i IndexNode<M>, at: usize) {
        if self.over || !self.seen.insert((node as *const IndexNode<M>, at)) {
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
            self.over = self.found.len() > self.most;
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
    use wz_session_core::keyexpr_match::keyexpr_intersects;

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
        keyexpr_intersects(query, target)
    }

    /// The nodes from `node` down, `node` included.
    fn nodes(node: &IndexNode<u32>) -> usize {
        1 + node.children().map(nodes).sum::<usize>()
    }

    /// The empty nodes below `node`. Each is a leaf, as a node with a child is not empty.
    fn empty_leaves(node: &IndexNode<u32>) -> usize {
        node.children()
            .map(|child| usize::from(child.is_empty()) + empty_leaves(child))
            .sum()
    }

    /// A key declared and withdrawn again and again keeps its path and counts one empty leaf at
    /// the most; many keys withdrawn leave no more empty leaves than the bound allows, and the
    /// nodes held for nothing stay within it, where a node per key withdrawn would pile up.
    #[test]
    fn the_nodes_kept_for_nothing_stay_within_the_bound() {
        let mut index: KeyexprIndex<u32> = KeyexprIndex::new();
        assert!(index.insert("keep/me", 0));
        for _ in 0..1_000 {
            assert!(index.insert("demo/beside/admin", 1));
            assert!(index.remove("demo/beside/admin", &1));
            assert!(index.dead <= 1, "the one key's leaf is counted once");
        }
        for i in 0..10_000u32 {
            let keyexpr = format!("churn/{i}/x");
            assert!(index.insert(&keyexpr, i + 10));
            assert!(index.remove(&keyexpr, &(i + 10)));
            assert!(index.dead <= dead_bound(index.len()));
            assert_eq!(empty_leaves(&index.root), index.dead);
            assert!(
                nodes(&index.root) <= 16 + 3 * dead_bound(index.len()),
                "{} nodes after {i} keys withdrawn",
                nodes(&index.root)
            );
        }
        assert_eq!(index.intersecting("**"), [&0], "the member kept is found");
        assert!(index.remove("keep/me", &0));
        assert_eq!(
            nodes(&index.root),
            1,
            "an index left with no member keeps no node"
        );
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
                assert_eq!(
                    empty_leaves(&index.root),
                    index.dead,
                    "every empty leaf is counted, seed {seed} step {step}"
                );
                assert!(
                    index.dead <= dead_bound(index.len()),
                    "the empty leaves stay within the bound, seed {seed} step {step}"
                );
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

    /// A bounded walk answers what the full walk answers while it finds no more than its bound,
    /// and stops with no answer once it finds more. Turned red by a bounded walk that answers past
    /// its bound, or loses a member within it.
    #[test]
    fn a_bounded_walk_answers_within_its_bound_and_stops_past_it() {
        let mut index: KeyexprIndex<u32> = KeyexprIndex::new();
        for i in 0..100u32 {
            index.insert(&format!("a/{i}"), i);
        }
        index.insert("b/x", 1_000);
        let full: BTreeSet<u32> = index.intersecting("a/**").into_iter().copied().collect();
        assert_eq!(full.len(), 100);
        let within: BTreeSet<u32> = index
            .intersecting_within("a/**", 100)
            .expect("100 members are within a bound of 100")
            .into_iter()
            .copied()
            .collect();
        assert_eq!(within, full);
        assert!(
            index.intersecting_within("a/**", 99).is_none(),
            "100 members are past a bound of 99"
        );
        assert!(
            index.intersecting_within("b/x", 0).is_none(),
            "one member is past a bound of none"
        );
        assert_eq!(
            index.intersecting_within("c/x", 0).map(|found| found.len()),
            Some(0),
            "a walk that finds nothing answers"
        );
    }

    /// An empty index answers a query with nothing, before anything is stored and after the last
    /// member left.
    #[test]
    fn an_empty_index_answers_nothing() {
        let mut index: KeyexprIndex<u32> = KeyexprIndex::new();
        assert!(index.intersecting("**").is_empty());
        assert!(index.insert("a/b", 1));
        assert_eq!(index.intersecting("**"), [&1]);
        assert!(index.remove("a/b", &1));
        assert!(index.intersecting("**").is_empty());
    }

    /// An insertion of a member already held adds nothing and says so; a removal of one not held,
    /// under a path held or not, takes nothing.
    #[test]
    fn an_insertion_of_a_member_held_adds_nothing_and_a_removal_of_one_not_held_takes_nothing() {
        let mut index: KeyexprIndex<u32> = KeyexprIndex::new();
        assert!(index.insert("a/b", 1));
        assert!(!index.insert("a/b", 1), "the member is held already");
        assert_eq!(index.len(), 1);
        assert_eq!(index.intersecting("a/b"), [&1]);
        assert!(!index.remove("a/c", &1), "a path not held");
        assert!(!index.remove("a/b", &2), "a member not held");
        assert_eq!(index.len(), 1);
        assert!(index.contains("a/b", &1));
        assert!(index.remove("a/b", &1));
        assert!(index.is_empty() && index.root.is_empty());
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
