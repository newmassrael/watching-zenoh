// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The tree's own rules, one assertion each, and the relational iterators held to the relations of
//! the key expressions themselves over generated trees. The comparison with upstream's trees is
//! `conformance/differential`.

use alloc::{collections::BTreeSet, string::ToString, vec::Vec};

use rand::{rngs::StdRng, SeedableRng};
use token_cell::prelude::{TokenCellTrait, TokenTrait};

use super::{
    arc_tree::Tokenized,
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

fn arc_sample() -> (KeArcTree<i32>, DefaultToken) {
    let (tree, mut token): (KeArcTree<i32>, _) = KeArcTree::new().unwrap();
    for (key, weight) in [
        ("a/b", 0),
        ("a/b/c", 1),
        ("a/b/d", 2),
        ("a/e", 3),
        ("a/@f", 4),
    ] {
        assert_eq!(tree.insert(&mut token, ke(key), weight), None);
    }
    (tree, token)
}

#[test]
fn a_shared_tree_holds_the_weights_it_was_given_through_its_token() {
    let (tree, mut token) = arc_sample();
    assert_eq!(tree.node(&token, ke("a/b/c")).unwrap().weight(), Some(&1));
    assert_eq!(tree.node(&token, ke("a")).unwrap().weight(), None);
    assert!(tree.node(&token, ke("x")).is_none());
    assert_eq!(tree.insert(&mut token, ke("a/b"), 10), Some(0));
    assert_eq!(tree.node(&token, ke("a/b")).unwrap().weight(), Some(&10));
    let mut node = tree.node_mut(&mut token, ke("a/e")).unwrap();
    *node.weight_mut().unwrap() += 1;
    assert_eq!(tree.node(&token, ke("a/e")).unwrap().weight(), Some(&4));
    let node = tree.node(&token, ke("a/b/c")).unwrap();
    assert_eq!(node.keyexpr().as_str(), "a/b/c");
    assert_eq!(
        node.parent()
            .unwrap()
            .upgrade()
            .unwrap()
            .try_borrow(&token)
            .unwrap()
            .chunk()
            .as_str(),
        "b"
    );
    let keys: BTreeSet<_> = tree
        .tree_iter(&token)
        .map(|n| n.keyexpr().to_string())
        .collect();
    assert_eq!(keys.len(), 6);
    // The four weighted nodes under `a`; `**` does not match the verbatim `@f`.
    assert_eq!(tree.intersecting_keys(&token, ke("a/**")).count(), 4);
}

#[test]
fn a_token_that_is_not_the_trees_is_refused() {
    let (tree, _token) = arc_sample();
    let (_other, other_token): (KeArcTree<i32>, _) = KeArcTree::new().unwrap();
    assert!(std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
        tree.node(&other_token, ke("a/b"));
    }))
    .is_err());
    // A pair built by hand from a cell and a token of another tree is refused at its first use.
    let (tree, token) = arc_sample();
    let (_other, other_token): (KeArcTree<i32>, _) = KeArcTree::new().unwrap();
    let node = tree.node(&token, ke("a/b")).unwrap().0;
    let forged = Tokenized(node, &other_token);
    assert!(std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
        let _ = forged.weight();
    }))
    .is_err());
}

#[test]
fn a_node_held_after_its_tree_is_dropped_is_a_zombie_and_has_no_key() {
    let (tree, token) = arc_sample();
    let held = tree.node(&token, ke("a/b/c")).unwrap().0.clone();
    assert!(!held.try_borrow(&token).unwrap().is_zombie());
    drop(tree);
    let node = held.try_borrow(&token).unwrap();
    assert!(node.is_zombie());
    assert!(std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| node.keyexpr())).is_err());
}

#[test]
fn pruning_leaves_a_node_something_else_holds_and_keeps_the_wildness_it_has() {
    let (mut tree, mut token): (KeArcTree<i32>, _) = KeArcTree::new().unwrap();
    tree.insert(&mut token, ke("a/*"), 1);
    let held = tree.node(&token, ke("a/*")).unwrap().0.clone();
    assert_eq!(tree.remove(&mut token, ke("a/*")), Some(1));
    tree.prune(&mut token);
    assert!(
        tree.node(&token, ke("a/*")).is_some(),
        "a held node is not pruned"
    );
    // A query with no wildcard is answered by a lookup unless the tree may hold a wild key; the
    // node that is still there must be found, as it is by a tree with nothing held.
    assert_eq!(tree.intersecting_nodes(&token, ke("a/b")).count(), 1);
    drop(held);
    tree.prune(&mut token);
    assert!(tree.node(&token, ke("a/*")).is_none());
    assert_eq!(tree.intersecting_nodes(&token, ke("a/b")).count(), 0);
}

#[test]
fn a_shared_tree_is_iterated_and_changed_through_its_mutable_iterators() {
    let (tree, mut token) = arc_sample();
    for mut node in tree.intersecting_nodes_mut(&mut token, ke("a/**")) {
        if let Some(w) = node.weight_mut() {
            *w += 100;
        }
    }
    let pairs: BTreeSet<_> = tree
        .tree_iter(&token)
        .filter_map(|n| n.weight().map(|w| (n.keyexpr().to_string(), *w)))
        .collect();
    assert!(pairs.contains(&("a/b/d".to_string(), 102)), "{pairs:?}");
    // `a/**` does not include the verbatim `a/@f`, so that weight is the one that did not move.
    assert!(pairs.contains(&("a/@f".to_string(), 4)), "{pairs:?}");
    for mut node in tree.tree_iter_mut(&mut token) {
        if let Some(w) = node.weight_mut() {
            *w = 0;
        }
    }
    assert!(tree
        .tree_iter(&token)
        .all(|n| n.weight().is_none_or(|w| *w == 0)));
}

macro_rules! check_a_shared_tree_against_the_relations {
    ($tree:ty, $seed:expr) => {{
        let mut rng = StdRng::seed_from_u64($seed);
        let mut token = DefaultToken::new().unwrap();
        let tree = <$tree>::with_token(&token);
        for (n, k) in KeyExprFuzzer(&mut rng).take(120).enumerate() {
            tree.insert(&mut token, &k, n as u32);
        }
        let nodes: Vec<_> = tree.tree_iter(&token).map(|n| n.keyexpr()).collect();
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
                .intersecting_nodes(&token, &q)
                .map(|n| n.keyexpr().to_string())
                .collect();
            assert_eq!(got, want(&|n, q| n.intersects(q)), "intersecting `{q}`");
            let got: BTreeSet<_> = tree
                .included_nodes(&token, &q)
                .map(|n| n.keyexpr().to_string())
                .collect();
            assert_eq!(got, want(&|n, q| q.includes(n)), "included by `{q}`");
            let got: BTreeSet<_> = tree
                .nodes_including(&token, &q)
                .map(|n| n.keyexpr().to_string())
                .collect();
            assert_eq!(got, want(&|n, q| n.includes(q)), "including `{q}`");
        }
    }};
}

#[test]
fn a_shared_trees_relational_iterators_agree_with_the_relations_over_every_node() {
    check_a_shared_tree_against_the_relations!(
        KeArcTree<u32, DefaultToken, bool, KeyedSetProvider>,
        21
    );
    check_a_shared_tree_against_the_relations!(
        KeArcTree<u32, DefaultToken, bool, VecSetProvider>,
        22
    );
    check_a_shared_tree_against_the_relations!(
        KeArcTree<u32, DefaultToken, UnknownWildness, HashMapProvider>,
        23
    );
}

#[test]
fn a_tree_has_the_default_parts_and_a_debug_form() {
    let tree: KeBoxTree<i32> = KeBoxTree::default();
    assert_eq!(tree.tree_iter().count(), 0);
    let text = alloc::format!("{tree:?}");
    assert!(text.contains("KeBoxTree"), "{text}");
}
