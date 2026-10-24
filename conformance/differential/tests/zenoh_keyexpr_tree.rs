// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-keyexpr`, key expression trees: upstream's crate (`up_keyexpr`) and wz's (`wz_keyexpr`)
//! given the same operations on a `KeBoxTree`, observations equal.
//!
//! A scenario builds a tree from generated key expressions, observes it, removes some, observes it,
//! adds to the weights of the nodes that intersect a few queries through the mutable iterator,
//! observes it, prunes it, and observes it once more. An observation is everything a caller can ask
//! of the tree: the weight and the node at every probe, the set of all nodes with their weights,
//! parents and depths, the key-value pairs, and for every query the nodes that intersect it, are
//! included by it and include it. The ORDER of an iteration is not part of the contract (the module
//! documents only that a parent comes before its children), so every iteration is compared as a set.
//!
//! Each of the five children providers a tree can be built on is run on its own seeds, and a
//! control confirms the comparison can fail: the same scenario with one key left out of one side
//! is seen to differ.

use std::collections::BTreeSet;

use rand::{rngs::StdRng, Rng, SeedableRng};

/// The chunks key expressions are made of: plain ones, one that is verbatim, each wildcard, and the
/// two spellings of a chunk with `$*` inside (no run of them, which upstream's canonizer cannot fold).
const CHUNKS: &[&str] = &["a", "b", "c", "ab", "@v", "*", "**", "a$*", "$*c"];

/// A key expression that is canon and valid in both crates, which must agree on that.
fn canon_in_both(s: &str) -> bool {
    let up = up_keyexpr::keyexpr::new(s).is_ok();
    let wz = wz_keyexpr::keyexpr::new(s).is_ok();
    assert_eq!(
        up, wz,
        "the crates disagree on whether `{s}` is a key expression"
    );
    up
}

fn generated_keys(rng: &mut StdRng, count: usize, wild: bool) -> Vec<String> {
    let mut keys = Vec::new();
    while keys.len() < count {
        let len = rng.gen_range(1..=4);
        let key = (0..len)
            .map(|_| CHUNKS[rng.gen_range(0..CHUNKS.len())])
            .collect::<Vec<_>>()
            .join("/");
        if (wild || !key.contains('*')) && canon_in_both(&key) {
            keys.push(key);
        }
    }
    keys
}

/// One observation of a tree, as plain values both crates' trees can be reduced to.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
struct Observation {
    /// Every node: key expression, weight, its parent's key expression, depth.
    nodes: BTreeSet<(String, Option<i32>, Option<String>, usize)>,
    pairs: BTreeSet<(String, i32)>,
    /// For each probe: the weight at it, and the key expression of the node there.
    probes: Vec<(Option<i32>, Option<String>)>,
    /// For each query: the nodes that intersect it, are included by it, include it.
    relations: Vec<[BTreeSet<(String, Option<i32>)>; 3]>,
}

/// The values a scenario returns besides its observations.
#[derive(Debug, PartialEq, Eq, Default)]
struct Scenario {
    /// What each insertion replaced.
    replaced: Vec<Option<i32>>,
    /// What each removal took.
    removed: Vec<Option<i32>>,
    observed: Vec<Observation>,
}

/// The body of a scenario for one tree type, expanded inside a module that has the crate's names.
macro_rules! scenario_body {
    ($tree:ty, $keys:expr, $removals:expr, $probes:expr, $queries:expr) => {{
        fn ke(s: &str) -> &keyexpr {
            keyexpr::new(s).unwrap()
        }
        let observe = |tree: &$tree| -> Observation {
            let mut o = Observation::default();
            for (depth, node) in tree.tree_iter().with_depth() {
                o.nodes.insert((
                    node.keyexpr().to_string(),
                    node.weight().copied(),
                    node.parent().map(|p| p.keyexpr().to_string()),
                    depth.get(),
                ));
            }
            for (k, w) in tree.key_value_pairs() {
                o.pairs.insert((k.to_string(), *w));
            }
            for p in $probes {
                o.probes.push((
                    tree.weight_at(ke(p)).copied(),
                    tree.node(ke(p)).map(|n| n.keyexpr().to_string()),
                ));
            }
            for q in $queries {
                let q = ke(q);
                let set = |it: &mut dyn Iterator<Item = (String, Option<i32>)>| -> BTreeSet<_> {
                    it.collect()
                };
                o.relations.push([
                    set(&mut tree
                        .intersecting_nodes(q)
                        .map(|n| (n.keyexpr().to_string(), n.weight().copied()))),
                    set(&mut tree
                        .included_nodes(q)
                        .map(|n| (n.keyexpr().to_string(), n.weight().copied()))),
                    set(&mut tree
                        .nodes_including(q)
                        .map(|n| (n.keyexpr().to_string(), n.weight().copied()))),
                ]);
            }
            o
        };
        let mut out = Scenario::default();
        let mut tree = <$tree>::default();
        for (n, k) in $keys.iter().enumerate() {
            out.replaced.push(tree.insert(ke(k), n as i32));
        }
        out.observed.push(observe(&tree));
        for k in $removals {
            out.removed.push(tree.remove(ke(k)));
        }
        out.observed.push(observe(&tree));
        for q in $queries.iter().take(8) {
            for node in tree.intersecting_nodes_mut(ke(q)) {
                if let Some(w) = node.weight_mut() {
                    *w += 1000;
                }
            }
        }
        out.observed.push(observe(&tree));
        tree.prune();
        out.observed.push(observe(&tree));
        out
    }};
}

macro_rules! tree_cases {
    ($name:ident, $ke:ident) => {
        mod $name {
            use super::{Observation, Scenario};
            use std::collections::BTreeSet;
            use $ke::{
                keyexpr,
                keyexpr_tree::{
                    impls::{HashMapProvider, KeyedSetProvider, VecSetProvider},
                    support::{NonWild, UnknownWildness},
                    *,
                },
            };

            pub fn keyed_set(k: &[String], r: &[String], p: &[String], q: &[String]) -> Scenario {
                scenario_body!(KeBoxTree<i32, bool, KeyedSetProvider>, k, r, p, q)
            }
            pub fn vec_set(k: &[String], r: &[String], p: &[String], q: &[String]) -> Scenario {
                scenario_body!(KeBoxTree<i32, bool, VecSetProvider>, k, r, p, q)
            }
            pub fn hash_map(k: &[String], r: &[String], p: &[String], q: &[String]) -> Scenario {
                scenario_body!(KeBoxTree<i32, bool, HashMapProvider>, k, r, p, q)
            }
            pub fn unknown_wildness(
                k: &[String],
                r: &[String],
                p: &[String],
                q: &[String],
            ) -> Scenario {
                scenario_body!(KeBoxTree<i32, UnknownWildness, KeyedSetProvider>, k, r, p, q)
            }
            pub fn non_wild(k: &[String], r: &[String], p: &[String], q: &[String]) -> Scenario {
                scenario_body!(KeBoxTree<i32, NonWild, KeyedSetProvider>, k, r, p, q)
            }

            /// Whether a non-wild tree built from `keys` is told it holds a wild key.
            pub fn non_wild_refuses(key: &str) -> bool {
                let result = std::panic::catch_unwind(|| {
                    let mut tree: KeBoxTree<i32, NonWild, KeyedSetProvider> = KeBoxTree::default();
                    tree.insert(keyexpr::new(key).unwrap(), 0);
                });
                result.is_err()
            }
        }
    };
}

tree_cases!(up, up_keyexpr);
tree_cases!(wz, wz_keyexpr);

/// What one scenario is given: the keys to insert, those to remove (some absent), probes, queries.
struct Input {
    keys: Vec<String>,
    removals: Vec<String>,
    probes: Vec<String>,
    queries: Vec<String>,
}

fn input(seed: u64, wild: bool) -> Input {
    let mut rng = StdRng::seed_from_u64(seed);
    let keys = generated_keys(&mut rng, 60, wild);
    // Half of the removals are of keys that were inserted, half of others, so both outcomes occur.
    let mut removals: Vec<String> = keys.iter().step_by(3).cloned().collect();
    removals.extend(generated_keys(&mut rng, 12, wild));
    let mut probes = keys.clone();
    probes.extend(generated_keys(&mut rng, 40, wild));
    let queries = generated_keys(&mut rng, 70, true);
    Input {
        keys,
        removals,
        probes,
        queries,
    }
}

fn run(which: fn(&[String], &[String], &[String], &[String]) -> Scenario, i: &Input) -> Scenario {
    which(&i.keys, &i.removals, &i.probes, &i.queries)
}

/// How much a scenario's observations hold, so that equality of empty things is not a pass.
fn weight_of(s: &Scenario) -> (usize, usize) {
    let nodes = s.observed.iter().map(|o| o.nodes.len()).sum();
    let related = s
        .observed
        .iter()
        .flat_map(|o| o.relations.iter())
        .map(|r| r.iter().map(BTreeSet::len).sum::<usize>())
        .sum();
    (nodes, related)
}

macro_rules! agree {
    ($name:ident, $which:ident, $wild:expr, $seeds:expr) => {
        #[test]
        fn $name() {
            let (mut nodes, mut related) = (0, 0);
            for seed in $seeds {
                let i = input(seed, $wild);
                let (u, w) = (run(up::$which, &i), run(wz::$which, &i));
                assert_eq!(u.replaced, w.replaced, "insertions, seed {seed}");
                assert_eq!(u.removed, w.removed, "removals, seed {seed}");
                for (stage, (a, b)) in u.observed.iter().zip(&w.observed).enumerate() {
                    assert_eq!(a, b, "observation {stage}, seed {seed}");
                }
                let (n, r) = weight_of(&w);
                nodes += n;
                related += r;
            }
            // Over 20 scenarios of 60 keys, four observations each, the comparison saw real trees
            // (removal and pruning shrink them, and a tree of non-wild keys has the fewest nodes)
            // and real answers to the queries.
            assert!(nodes > 20 * 4 * 30, "{nodes} nodes observed");
            assert!(related > 5000, "{related} related nodes observed");
        }
    };
}

agree!(keyed_set_trees_agree, keyed_set, true, 100..120);
agree!(vec_set_trees_agree, vec_set, true, 200..220);
agree!(hash_map_trees_agree, hash_map, true, 300..320);
agree!(
    unknown_wildness_trees_agree,
    unknown_wildness,
    true,
    400..420
);
agree!(non_wild_trees_agree, non_wild, false, 500..520);

#[test]
fn a_non_wild_tree_refuses_a_wild_key_in_both_crates() {
    for key in ["a/*", "**", "a/**/b", "a$*"] {
        assert!(up::non_wild_refuses(key), "upstream accepted `{key}`");
        assert!(wz::non_wild_refuses(key), "wz accepted `{key}`");
    }
    for key in ["a", "a/b/c", "@v/a"] {
        assert!(
            !up::non_wild_refuses(key) && !wz::non_wild_refuses(key),
            "`{key}`"
        );
    }
}

/// The control: the comparison is made on observations, so a tree that differs in one key must
/// differ in them. Both are the wz crate here, one given a key fewer.
#[test]
fn the_comparison_sees_a_tree_that_lacks_one_key() {
    let i = input(100, true);
    let full = run(wz::keyed_set, &i);
    let mut short = Input {
        keys: i.keys[1..].to_vec(),
        removals: i.removals.clone(),
        probes: i.probes.clone(),
        queries: i.queries.clone(),
    };
    let lacking = run(wz::keyed_set, &short);
    assert_ne!(full.observed, lacking.observed);
    // And a tree whose weights are shifted differs in the pairs but not in the nodes' keys.
    short.keys = i.keys.clone();
    short.keys.reverse();
    let reversed = run(wz::keyed_set, &short);
    assert_ne!(full.observed[0].pairs, reversed.observed[0].pairs);
}
