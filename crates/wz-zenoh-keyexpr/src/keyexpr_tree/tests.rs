// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The tree's own rules, one assertion each, and the relational iterators held to the relations of
//! the key expressions themselves over generated trees. The comparison with upstream's trees is
//! `conformance/differential`.

use alloc::{collections::BTreeSet, string::ToString, vec::Vec};

use rand::{rngs::StdRng, SeedableRng};

use super::{
    impls::{HashMapProvider, KeyedSetProvider, VecSetProvider},
    support::{NonWild, UnknownWildness},
    *,
};
use crate::key_expr::fuzzer::KeyExprFuzzer;

fn ke(s: &str) -> &keyexpr {
    keyexpr::new(s).unwrap()
}

fn sample_tree() -> KeBoxTree<i32> {
    let mut tree = KeBoxTree::new();
    for (key, weight) in [
        ("a/b", 0),
        ("a/b/c", 1),
        ("a/b/d", 2),
        ("a/e", 3),
        ("a/@f", 4),
    ] {
        assert_eq!(tree.insert(ke(key), weight), None);
    }
    tree
}

#[test]
fn a_tree_holds_the_weights_it_was_given_and_the_nodes_between() {
    let mut tree = sample_tree();
    assert_eq!(tree.weight_at(ke("a/b/c")), Some(&1));
    assert_eq!(tree.weight_at(ke("a")), None);
    assert!(tree.node(ke("a")).is_some());
    assert!(tree.node(ke("x")).is_none());
    assert_eq!(tree.insert(ke("a/b"), 10), Some(0));
    assert_eq!(tree.weight_at(ke("a/b")), Some(&10));
    *tree.weight_at_mut(ke("a/e")).unwrap() += 1;
    assert_eq!(tree.weight_at(ke("a/e")), Some(&4));
    let node = tree.node(ke("a/b/c")).unwrap();
    assert_eq!(node.keyexpr().as_str(), "a/b/c");
    assert_eq!(node.parent().unwrap().keyexpr().as_str(), "a/b");
}

#[test]
fn the_whole_tree_is_iterated_parents_first() {
    let tree = sample_tree();
    let keys: Vec<_> = tree.tree_iter().map(|n| n.keyexpr().to_string()).collect();
    let at = |k: &str| keys.iter().position(|x| x == k).unwrap();
    assert_eq!(keys.len(), 6);
    assert!(at("a") < at("a/b") && at("a/b") < at("a/b/c") && at("a/b") < at("a/b/d"));
    let pairs: BTreeSet<_> = tree
        .key_value_pairs()
        .map(|(k, v)| (k.to_string(), *v))
        .collect();
    assert_eq!(pairs.len(), 5);
    assert!(pairs.contains(&("a/b/d".to_string(), 2)));
    let depths: Vec<_> = tree
        .tree_iter()
        .with_depth()
        .map(|(d, _)| d.get())
        .collect();
    assert_eq!(depths.iter().filter(|d| **d == 1).count(), 1);
    assert_eq!(depths.iter().max(), Some(&3));
}

#[test]
fn removing_and_pruning() {
    let mut tree = sample_tree();
    assert_eq!(tree.remove(ke("a/b")), Some(0));
    assert!(tree.node(ke("a/b")).is_some(), "a node with children stays");
    assert_eq!(tree.weight_at(ke("a/b")), None);
    assert_eq!(tree.remove(ke("a/b/c")), Some(1));
    assert!(tree.node(ke("a/b/c")).is_none(), "a leaf goes");
    assert_eq!(tree.remove(ke("a/b/d")), Some(2));
    tree.prune();
    assert!(tree.node(ke("a/b")).is_none());
    assert!(tree.node(ke("a/e")).is_some());
    assert_eq!(tree.remove(ke("nope")), None);
}

/// Hold the three relational iterators of a tree type to the relations over every node of a
/// generated tree, for each of a set of generated queries.
macro_rules! check_against_the_relations {
    ($tree:ty, $seed:expr) => {{
        let mut rng = StdRng::seed_from_u64($seed);
        let mut tree = <$tree>::default();
        for (n, k) in KeyExprFuzzer(&mut rng).take(120).enumerate() {
            tree.insert(&k, n as u32);
        }
        let nodes: Vec<_> = tree.tree_iter().map(|n| n.keyexpr()).collect();
        assert!(
            nodes.len() > 120,
            "the generated tree has {} nodes",
            nodes.len()
        );
        for q in KeyExprFuzzer(&mut rng).take(80) {
            let want = |f: &dyn Fn(&keyexpr, &keyexpr) -> bool| -> BTreeSet<alloc::string::String> {
                nodes
                    .iter()
                    .filter(|n| f(n, &q))
                    .map(|n| n.to_string())
                    .collect()
            };
            let got: BTreeSet<_> = tree
                .intersecting_nodes(&q)
                .map(|n| n.keyexpr().to_string())
                .collect();
            assert_eq!(got, want(&|n, q| n.intersects(q)), "intersecting `{q}`");
            let got: BTreeSet<_> = tree
                .included_nodes(&q)
                .map(|n| n.keyexpr().to_string())
                .collect();
            assert_eq!(got, want(&|n, q| q.includes(n)), "included by `{q}`");
            let got: BTreeSet<_> = tree
                .nodes_including(&q)
                .map(|n| n.keyexpr().to_string())
                .collect();
            assert_eq!(got, want(&|n, q| n.includes(q)), "including `{q}`");
        }
    }};
}

#[test]
fn relational_iterators_agree_with_the_relations_over_every_node() {
    check_against_the_relations!(KeBoxTree<u32, bool, KeyedSetProvider>, 11);
    check_against_the_relations!(KeBoxTree<u32, bool, VecSetProvider>, 12);
    check_against_the_relations!(KeBoxTree<u32, bool, HashMapProvider>, 13);
    check_against_the_relations!(KeBoxTree<u32, UnknownWildness, KeyedSetProvider>, 14);
}

/// `**` matches no verbatim chunk, so `<node>/**` is not a test for descendants: a verbatim
/// descendant under a node is reached by the query that names it.
#[test]
fn verbatim_descendants_are_reached_under_plain_and_double_wild_nodes() {
    let mut tree: KeBoxTree<i32> = KeBoxTree::new();
    tree.insert(ke("**/@a"), 1);
    tree.insert(ke("p/@v"), 2);
    tree.insert(ke("**/b"), 3);
    let found = |q: &str| -> BTreeSet<_> {
        tree.intersecting_nodes(ke(q))
            .filter_map(|n| n.weight().copied())
            .collect()
    };
    assert_eq!(found("**/b/aa/aa/@a"), BTreeSet::from([1]));
    assert_eq!(found("p/@v"), BTreeSet::from([2]));
    assert_eq!(found("@a"), BTreeSet::from([1]));
    assert_eq!(found("b"), BTreeSet::from([3]));
    assert_eq!(
        found("p/*"),
        BTreeSet::from([3]),
        "`**/b` is met, `p/@v` is not: `*` is not verbatim"
    );
}

#[test]
fn a_nonwild_tree_refuses_a_wild_key_and_a_tree_remembers_wildness() {
    let mut tree: KeBoxTree<i32, NonWild, KeyedSetProvider> = KeBoxTree::default();
    tree.insert(ke("a/b"), 1);
    assert!(std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
        tree.insert(ke("a/*"), 2);
    }))
    .is_err());
    let mut tree: KeBoxTree<i32> = KeBoxTree::new();
    tree.insert(ke("a/*"), 1);
    assert_eq!(
        tree.intersecting_nodes(ke("a/b")).count(),
        1,
        "the node `a/*` and not its parent `a`"
    );
    tree.prune_where(|n| n.weight().is_some());
    assert!(tree.node(ke("a/*")).is_none());
}

#[test]
fn a_tree_has_the_default_parts_and_a_debug_form() {
    let tree: KeBoxTree<i32> = KeBoxTree::default();
    assert_eq!(tree.tree_iter().count(), 0);
    let text = alloc::format!("{tree:?}");
    assert!(text.contains("KeBoxTree"), "{text}");
}
