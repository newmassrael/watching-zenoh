// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-collections`: upstream's crate (`up_collections`) and wz's (`wz_collections`) given the
//! same sequences of operations, states equal after each.
//!
//! Each container is driven by 200 seeded sequences of 60 operations, generated once and fed to
//! both crates, and a transcript of what each operation returned and what the container then held
//! is compared line by line: for `SingleOrVec` its elements, length, last element and `Debug`
//! text; for `SingleOrBoxHashSet` its sorted elements and the results of `insert`, `replace`,
//! `remove`, `contains`, `get` and `drain`; for `IntHashMap` which form it is in (a public fact of
//! the enum), the length of its vector, its entries in key order, and what the iterators and
//! `entry` did; for the two bounded buffers every result and the length, fullness and capacity.
//! Operations are resolved against the length of the container as they run, so none panics.
//!
//! Upstream is wrong in four places and wz follows the documented definition there. Each is a
//! class that is counted and held on both sides, not copied, and the main comparisons leave the
//! operations that reach it out:
//! * `IntHashMap::clear` in the dense form does not reset the count of items, so `len` goes on
//!   reporting the entries it had, and the decision to fall back to a hash map reads that count;
//! * `SingleOrBoxHashSet::drain` leaves an empty hash set that `is_empty` does not call empty;
//! * `SingleOrBoxHashSet::insert` of an equal value replaces the value held when the set holds one
//!   element and keeps it when it holds more;
//! * `RingBuffer::push_force` on a queue of capacity zero stores the element and loses count.

use rand::{rngs::StdRng, Rng, SeedableRng};

const SEQUENCES: u64 = 200;
const LENGTH: usize = 60;

/// An operation of a sequence, with the numbers it will be resolved against the container with.
#[derive(Debug, Clone, Copy)]
enum Op {
    Push(u8),
    Insert(usize, u8),
    Truncate(usize),
    Clear,
    Drain(usize, usize),
    DrainFrom(usize),
    SetAt(usize, u8),
    Extend(u8, u8),
    Remove(u8),
    Replace(u8),
    Contains(u8),
    Take,
    Entry(u8, u32),
    BumpAll,
    DoubleValues,
}

fn sequence(seed: u64, ops: &[fn(&mut StdRng) -> Op]) -> Vec<Op> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..LENGTH)
        .map(|_| ops[rng.gen_range(0..ops.len())](&mut rng))
        .collect()
}

macro_rules! containers {
    ($name:ident, $c:ident) => {
        mod $name {
            use std::fmt::Write as _;

            use $c::{
                int_hash_map::IntHashMap, ring_buffer::RingBuffer,
                single_or_box_hashset::SingleOrBoxHashSet, single_or_vec::SingleOrVec,
                stack_buffer::StackBuffer, IntHashSet,
            };

            use super::Op;

            pub fn vec_run(ops: &[Op]) -> Vec<String> {
                let mut s: SingleOrVec<u8> = SingleOrVec::empty();
                let mut out = Vec::new();
                for op in ops {
                    let mut line = String::new();
                    let len = s.len();
                    match *op {
                        Op::Push(v) => s.push(v),
                        Op::Insert(at, v) => s.insert(at % (len + 1), v),
                        Op::Truncate(n) => s.truncate(n % (len + 2)),
                        Op::Clear => s.clear(),
                        Op::Drain(a, b) => {
                            let a = a % (len + 1);
                            let b = a + b % (len - a + 1);
                            let drained: Vec<u8> = s.drain(a..b).collect();
                            write!(line, "drained {drained:?} ").unwrap();
                        }
                        Op::DrainFrom(a) => {
                            let drained: Vec<u8> = s.drain(a % (len + 1)..).collect();
                            write!(line, "drained {drained:?} ").unwrap();
                        }
                        Op::SetAt(i, v) => {
                            if len > 0 {
                                s[i % len] = v;
                            }
                        }
                        Op::Extend(n, v) => s.extend((0..n % 4).map(|k| v.wrapping_add(k))),
                        _ => {}
                    }
                    write!(
                        line,
                        "{s:?} len={} empty={} last={:?} first={:?} slice={:?}",
                        s.len(),
                        s.is_empty(),
                        s.last(),
                        s.get(0),
                        s.as_ref()
                    )
                    .unwrap();
                    out.push(line);
                }
                // Every sequence ends by consuming a copy of the container and comparing it.
                out.push(format!(
                    "{:?} eq={}",
                    s.clone().into_iter().collect::<Vec<_>>(),
                    s == s.clone()
                ));
                out
            }

            pub fn set_run(ops: &[Op]) -> Vec<String> {
                let mut s: SingleOrBoxHashSet<u8> = SingleOrBoxHashSet::new();
                let mut out = Vec::new();
                for op in ops {
                    let mut line = String::new();
                    match *op {
                        Op::Push(v) => write!(line, "insert {} ", s.insert(v % 12)).unwrap(),
                        Op::Replace(v) => write!(line, "replace {:?} ", s.replace(v % 12)).unwrap(),
                        Op::Remove(v) => write!(line, "remove {} ", s.remove(&(v % 12))).unwrap(),
                        Op::Contains(v) => {
                            let v = v % 12;
                            write!(line, "contains {} get {:?} ", s.contains(&v), s.get(&v))
                                .unwrap();
                        }
                        Op::Clear => s.clear(),
                        Op::Extend(n, v) => s.extend((0..n % 4).map(|k| (v + k) % 12)),
                        _ => {}
                    }
                    let mut sorted: Vec<u8> = s.iter().copied().collect();
                    sorted.sort_unstable();
                    write!(line, "{sorted:?} len={}", s.len()).unwrap();
                    out.push(line);
                }
                let other: SingleOrBoxHashSet<u8> = (0..6).collect();
                out.push(format!(
                    "disjoint={} subset={} superset={} eq={}",
                    s.is_disjoint(&other),
                    s.is_subset(&other),
                    s.is_superset(&other),
                    s == other
                ));
                out
            }

            /// The hash set drained: what it returns, its length, and whether it calls itself empty.
            pub fn drained(values: &[u8]) -> (Vec<u8>, usize, bool) {
                let mut s: SingleOrBoxHashSet<u8> = values.iter().copied().collect();
                let mut taken: Vec<u8> = s.drain().collect();
                taken.sort_unstable();
                (taken, s.len(), s.is_empty())
            }

            /// Equal values with different tags, inserted in turn; the tags that are read back.
            pub fn duplicates(keys: &[u8]) -> Vec<(u8, usize)> {
                #[derive(Debug)]
                struct Keyed(u8, usize);
                impl PartialEq for Keyed {
                    fn eq(&self, other: &Self) -> bool {
                        self.0 == other.0
                    }
                }
                impl Eq for Keyed {}
                impl std::hash::Hash for Keyed {
                    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                        self.0.hash(state);
                    }
                }
                let mut s = SingleOrBoxHashSet::new();
                for (tag, key) in keys.iter().enumerate() {
                    s.insert(Keyed(*key, tag));
                }
                let mut read: Vec<(u8, usize)> = s.iter().map(|k| (k.0, k.1)).collect();
                read.sort_unstable();
                read
            }

            pub fn map_run(ops: &[Op]) -> Vec<String> {
                let mut m: IntHashMap<u8, u32> = IntHashMap::new();
                let mut counter = 0u32;
                let mut out = Vec::new();
                for op in ops {
                    let mut line = String::new();
                    counter += 1;
                    match *op {
                        Op::Push(k) => write!(line, "insert {:?} ", m.insert(k, counter)).unwrap(),
                        Op::Remove(k) => write!(line, "remove {:?} ", m.remove(&k)).unwrap(),
                        Op::Contains(k) => {
                            write!(line, "get {:?} has {} ", m.get(&k), m.contains_key(&k))
                                .unwrap();
                        }
                        Op::Entry(k, v) => {
                            *m.entry(k).or_insert_with(|| v) += 1;
                        }
                        Op::SetAt(k, v) => {
                            if let Some(slot) = m.get_mut(&(k as u8)) {
                                *slot = u32::from(v);
                            }
                        }
                        Op::BumpAll => m.iter_mut().for_each(|(_, v)| *v += 1),
                        Op::DoubleValues => m.values_mut().for_each(|v| *v *= 2),
                        _ => {}
                    }
                    out.push(format!("{line}{}", map_state(&m)));
                }
                out
            }

            fn map_state(m: &IntHashMap<u8, u32>) -> String {
                let mut entries: Vec<(u8, u32)> = m.iter().map(|(k, v)| (*k, *v)).collect();
                entries.sort_unstable();
                let mut values: Vec<u32> = m.values().copied().collect();
                values.sort_unstable();
                let form = match m {
                    IntHashMap::Vec { vec, items } => format!("vec[{}] items={items}", vec.len()),
                    IntHashMap::Map(_) => "map".to_string(),
                };
                format!(
                    "{form} len={} empty={} {entries:?} {values:?}",
                    m.len(),
                    m.is_empty()
                )
            }

            /// The entries of the map after `keys` were inserted and then it was cleared and
            /// filled again: what it holds, how many it says it holds, and the form it is in.
            pub fn cleared(keys: &[u8]) -> (Vec<(u8, u32)>, usize, bool) {
                let mut m: IntHashMap<u8, u32> = IntHashMap::new();
                for (n, k) in keys.iter().enumerate() {
                    m.insert(*k, n as u32);
                }
                m.clear();
                for (n, k) in keys.iter().take(3).enumerate() {
                    m.insert(*k, 100 + n as u32);
                }
                let mut entries: Vec<(u8, u32)> = m.iter().map(|(k, v)| (*k, *v)).collect();
                entries.sort_unstable();
                (entries, m.len(), matches!(m, IntHashMap::Vec { .. }))
            }

            pub fn int_set_run(keys: &[u8]) -> Vec<String> {
                let mut s: IntHashSet<u8> = IntHashSet::new();
                keys.iter()
                    .map(|k| format!("{} {}", s.contains(k), s.insert(*k)))
                    .collect()
            }

            pub fn ring_run(capacity: usize, ops: &[Op]) -> Vec<String> {
                let mut q: RingBuffer<u8> = RingBuffer::new(capacity);
                let mut out = Vec::new();
                for op in ops {
                    let mut line = String::new();
                    match *op {
                        Op::Push(v) => write!(line, "push {:?} ", q.push(v)).unwrap(),
                        Op::Replace(v) => write!(line, "force {:?} ", q.push_force(v)).unwrap(),
                        Op::Take => write!(line, "pull {:?} ", q.pull()).unwrap(),
                        _ => {}
                    }
                    write!(
                        line,
                        "len={} empty={} full={} cap={}",
                        q.len(),
                        q.is_empty(),
                        q.is_full(),
                        q.capacity()
                    )
                    .unwrap();
                    out.push(line);
                }
                out
            }

            pub fn stack_run(capacity: usize, ops: &[Op]) -> Vec<String> {
                let mut s: StackBuffer<u8> = StackBuffer::new(capacity);
                let mut out = Vec::new();
                for op in ops {
                    let mut line = String::new();
                    match *op {
                        Op::Push(v) => write!(line, "push {:?} ", s.push(v)).unwrap(),
                        Op::Take => write!(line, "pop {:?} ", s.pop()).unwrap(),
                        _ => {}
                    }
                    write!(
                        line,
                        "len={} empty={} full={} cap={}",
                        s.len(),
                        s.is_empty(),
                        s.is_full(),
                        s.capacity()
                    )
                    .unwrap();
                    out.push(line);
                }
                out
            }

            /// A queue of no room, forced into: what comes back, then its length and emptiness.
            pub fn forced_into_nothing() -> (Option<u8>, usize, bool) {
                let mut q: RingBuffer<u8> = RingBuffer::new(0);
                let back = q.push_force(7);
                (back, q.len(), q.is_empty())
            }
        }
    };
}

containers!(up, up_collections);
containers!(wz, wz_collections);

fn vec_ops() -> Vec<fn(&mut StdRng) -> Op> {
    vec![
        |r| Op::Push(r.gen()),
        |r| Op::Push(r.gen()),
        |r| Op::Insert(r.gen_range(0..8), r.gen()),
        |r| Op::Truncate(r.gen_range(0..8)),
        |_| Op::Clear,
        |r| Op::Drain(r.gen_range(0..8), r.gen_range(0..8)),
        |r| Op::DrainFrom(r.gen_range(0..8)),
        |r| Op::SetAt(r.gen_range(0..8), r.gen()),
        |r| Op::Extend(r.gen(), r.gen()),
    ]
}

fn set_ops() -> Vec<fn(&mut StdRng) -> Op> {
    vec![
        |r| Op::Push(r.gen_range(0..12)),
        |r| Op::Push(r.gen_range(0..12)),
        |r| Op::Push(r.gen_range(0..12)),
        |r| Op::Remove(r.gen_range(0..12)),
        |r| Op::Remove(r.gen_range(0..12)),
        |r| Op::Replace(r.gen_range(0..12)),
        |r| Op::Contains(r.gen_range(0..12)),
        |r| Op::Extend(r.gen(), r.gen_range(0..12)),
    ]
}

/// The operations of the map that do not clear it: keys that are mostly dense, some far out.
fn map_ops() -> Vec<fn(&mut StdRng) -> Op> {
    fn key(r: &mut StdRng) -> u8 {
        if r.gen_range(0..10) == 0 {
            r.gen()
        } else {
            r.gen_range(0..20)
        }
    }
    vec![
        |r| Op::Push(key(r)),
        |r| Op::Push(key(r)),
        |r| Op::Remove(key(r)),
        |r| Op::Contains(key(r)),
        |r| Op::Entry(key(r), r.gen_range(0..50)),
        |r| Op::SetAt(usize::from(key(r)), r.gen()),
        |_| Op::BumpAll,
        |_| Op::DoubleValues,
    ]
}

fn buffer_ops() -> Vec<fn(&mut StdRng) -> Op> {
    vec![
        |r| Op::Push(r.gen()),
        |r| Op::Push(r.gen()),
        |r| Op::Replace(r.gen()),
        |_| Op::Take,
    ]
}

/// Run `f` for both crates over every seed and require the transcripts equal, returning how many
/// lines were compared so that a comparison of nothing is not a pass.
fn compare(
    ops: &[fn(&mut StdRng) -> Op],
    seed_base: u64,
    up: impl Fn(&[Op]) -> Vec<String>,
    wz: impl Fn(&[Op]) -> Vec<String>,
) -> usize {
    let mut lines = 0;
    for seed in seed_base..seed_base + SEQUENCES {
        let ops = sequence(seed, ops);
        let (a, b) = (up(&ops), wz(&ops));
        assert_eq!(a.len(), b.len(), "seed {seed}");
        for (i, (x, y)) in a.iter().zip(&b).enumerate() {
            assert_eq!(
                x,
                y,
                "seed {seed}, line {i}, after {:?}",
                &ops[..i.min(ops.len())]
            );
        }
        lines += a.len();
    }
    lines
}

#[test]
fn both_crates_hold_a_sequence_alike_through_every_operation() {
    let lines = compare(&vec_ops(), 1000, up::vec_run, wz::vec_run);
    assert!(lines > 10_000, "{lines} lines");
}

#[test]
fn both_crates_hold_a_set_alike_through_every_operation() {
    let lines = compare(&set_ops(), 2000, up::set_run, wz::set_run);
    assert!(lines > 10_000, "{lines} lines");
}

#[test]
fn both_crates_hold_an_integer_map_alike_in_both_of_its_forms() {
    let lines = compare(&map_ops(), 3000, up::map_run, wz::map_run);
    assert!(lines > 10_000, "{lines} lines");
    // The comparison saw both forms and the move from one to the other.
    let sample: Vec<String> = (3000..3000 + SEQUENCES)
        .flat_map(|seed| wz::map_run(&sequence(seed, &map_ops())))
        .collect();
    assert!(sample.iter().any(|l| l.contains("vec[")), "no dense form");
    assert!(
        sample.iter().any(|l| l.contains("map len")),
        "no hash map form"
    );
}

/// The load at which the dense form gives way is what random keys rarely land on, so it is run
/// as a grid: fill the keys below `n`, remove `holes` of them (every `n / holes`th), then insert
/// one key `k` at or past the fallback bound, and compare the form and the entries that result.
#[test]
fn both_crates_give_up_the_dense_form_at_the_same_load() {
    let (mut compared, mut fell_back, mut stayed) = (0, 0, 0);
    for n in 8u8..=48 {
        for holes in 0..=n / 2 {
            let mut ops: Vec<Op> = (0..n).map(Op::Push).collect();
            if holes > 0 {
                ops.extend((0..holes).map(|h| Op::Remove(h * (n / holes))));
            }
            for k in 16..=n.saturating_add(24).min(255) {
                let mut ops = ops.clone();
                ops.push(Op::Push(k));
                let (a, b) = (up::map_run(&ops), wz::map_run(&ops));
                assert_eq!(a.last(), b.last(), "n {n}, holes {holes}, key {k}");
                compared += 1;
                if b.last().is_some_and(|l| l.contains("map len")) {
                    fell_back += 1;
                } else {
                    stayed += 1;
                }
            }
        }
    }
    assert!(compared > 10_000, "{compared} maps");
    assert!(
        fell_back > 1000 && stayed > 1000,
        "fell back {fell_back}, stayed {stayed}"
    );
}

#[test]
fn both_crates_bound_a_queue_and_a_stack_alike() {
    for capacity in 1..=6 {
        let ring = compare(
            &buffer_ops(),
            4000 + capacity as u64 * 1000,
            |o| up::ring_run(capacity, o),
            |o| wz::ring_run(capacity, o),
        );
        let stack = compare(
            &buffer_ops(),
            11_000 + capacity as u64 * 1000,
            |o| up::stack_run(capacity, o),
            |o| wz::stack_run(capacity, o),
        );
        assert!(ring > 10_000 && stack > 10_000);
    }
}

#[test]
fn both_crates_make_a_set_of_integers_alike() {
    let mut rng = StdRng::seed_from_u64(77);
    for _ in 0..SEQUENCES {
        let keys: Vec<u8> = (0..40).map(|_| rng.gen_range(0..30)).collect();
        assert_eq!(up::int_set_run(&keys), wz::int_set_run(&keys));
    }
}

/// The four classes in which upstream is wrong. Each is shown on upstream's crate and held to the
/// documented definition on wz's, and the sequences are chosen so that the class occurs.
#[test]
fn the_four_places_upstream_is_wrong_are_pinned_on_both_sides() {
    let mut rng = StdRng::seed_from_u64(99);

    // A drained set is empty. Upstream's is empty only if it held fewer than two elements.
    let (mut up_wrong, mut sets) = (0, 0);
    for _ in 0..SEQUENCES {
        let values: Vec<u8> = (0..rng.gen_range(0..8))
            .map(|_| rng.gen_range(0..12))
            .collect();
        let (taken_up, len_up, empty_up) = up::drained(&values);
        let (taken_wz, len_wz, empty_wz) = wz::drained(&values);
        assert_eq!((&taken_up, len_up), (&taken_wz, len_wz), "{values:?}");
        assert!(empty_wz && len_wz == 0, "{values:?}");
        up_wrong += usize::from(len_up == 0 && !empty_up);
        sets += 1;
    }
    assert!(
        up_wrong > 0 && up_wrong < sets,
        "upstream's empty set was seen {up_wrong} of {sets}"
    );

    // An equal value does not replace the one held. Upstream replaces it when the set holds one.
    let (mut replaced, mut kept) = (0, 0);
    for _ in 0..SEQUENCES {
        let keys: Vec<u8> = (0..rng.gen_range(2..6))
            .map(|_| rng.gen_range(0..3))
            .collect();
        let first_tag_of =
            |read: &[(u8, usize)], key: u8| read.iter().find(|(k, _)| *k == key).map(|(_, t)| *t);
        let (read_up, read_wz) = (up::duplicates(&keys), wz::duplicates(&keys));
        for key in 0..3u8 {
            let first = keys.iter().position(|k| *k == key);
            assert_eq!(first_tag_of(&read_wz, key), first, "{keys:?}");
            if first_tag_of(&read_up, key) == first {
                kept += 1;
            } else {
                replaced += 1;
            }
        }
        assert_eq!(
            read_up.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            read_wz.iter().map(|(k, _)| *k).collect::<Vec<_>>()
        );
    }
    assert!(replaced > 0 && kept > 0, "replaced {replaced}, kept {kept}");

    // A cleared map has no entries and says so. Upstream's dense form reports the old count.
    let (mut stale, mut dense) = (0, 0);
    for _ in 0..SEQUENCES {
        let keys: Vec<u8> = (0..rng.gen_range(4..12))
            .map(|_| rng.gen_range(0..16))
            .collect();
        let (entries_up, len_up, _) = up::cleared(&keys);
        let (entries_wz, len_wz, form_wz) = wz::cleared(&keys);
        assert_eq!(entries_up, entries_wz, "{keys:?}");
        assert_eq!(len_wz, entries_wz.len(), "{keys:?}");
        if form_wz {
            dense += 1;
            stale += usize::from(len_up != entries_up.len());
        }
    }
    assert!(stale > 0 && stale <= dense, "stale {stale} of {dense}");

    // A queue of no room takes nothing. Upstream stores the element and loses count.
    let (back_up, len_up, empty_up) = up::forced_into_nothing();
    let (back_wz, len_wz, empty_wz) = wz::forced_into_nothing();
    assert_eq!((back_up, len_up, empty_up), (None, 0, false));
    assert_eq!((back_wz, len_wz, empty_wz), (Some(7), 0, true));
}

/// The control: the comparison is made on lines, so a container that lost an operation differs.
#[test]
fn the_comparison_sees_a_sequence_that_lost_an_operation() {
    let ops = sequence(1000, &vec_ops());
    let full = wz::vec_run(&ops);
    let mut short = ops.clone();
    short.remove(10);
    assert_ne!(full, wz::vec_run(&short));
    let ring = wz::ring_run(3, &sequence(5, &buffer_ops()));
    assert_ne!(ring, wz::ring_run(2, &sequence(5, &buffer_ops())));
}
