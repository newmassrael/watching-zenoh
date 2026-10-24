// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Bytes a structure holds on the heap, counted from what it owns.
//!
//! Open-debt item 924 (`docs/dissect-row-index.md`, D7). A handle that says what
//! it holds, by structure, can be budgeted by the program that opens it and
//! graded by a gate that names the structure which grew; a total taken from the
//! allocator can do neither. A holder reports the structures that grow with its
//! rows, and this module is the arithmetic those reports share.
//!
//! # What is exact and what is a model
//!
//! A buffer is exact: [`vec_bytes`] is its capacity times its element, which is
//! what the allocator was asked for. A B-tree map keeps its capacity to itself,
//! so [`btree_bytes`] is a MODEL of the nodes a map of that many entries holds,
//! written from the node layout and checked against the allocator rather than
//! trusted: the gate that reads these figures compares the sum with what the
//! allocator counted, which is what makes a model that drifts a failure and not
//! a belief.
//!
//! # What a report leaves out
//!
//! Only the structures whose size follows the row count are reported. What is
//! fixed, or follows the count of distinct things (keyexprs, nodes, sessions), is
//! not, and the comparison with the allocator is what shows the difference stayed
//! small. A report is a lower bound on the heap, never an upper one.

use alloc::vec::Vec;
use core::mem::size_of;

/// Bytes a vector has allocated: its capacity, not its length.
pub fn vec_bytes<T>(v: &Vec<T>) -> usize {
    v.capacity() * size_of::<T>()
}

/// Entries a B-tree leaf holds at most (`alloc::collections::btree`'s `CAPACITY`).
const LEAF_CAPACITY: usize = 11;

/// Entries per leaf, and children per internal node, of a map filled in
/// ascending key order, as the allocator measured them (`tests/btree_model.rs`):
/// a node that fills splits and the left half is never written again, so a node
/// stays a little more than half full. A map filled in another order holds more
/// per node, so for it the model counts more nodes than there are: it errs toward
/// charging. `BTreeMap::append` of a sorted run onto a map behaves as inserting
/// the run does, and is measured to hold the same.
const NODE_FILL: usize = 7;

/// Bytes a node of the B-tree holds `K` keys and `V` values in, which is a
/// header (its parent, its place in the parent and its length: twelve bytes)
/// and [`LEAF_CAPACITY`] of each, padded to the alignment.
const fn leaf_bytes<K, V>() -> usize {
    let align = if core::mem::align_of::<K>() > core::mem::align_of::<V>() {
        core::mem::align_of::<K>()
    } else {
        core::mem::align_of::<V>()
    };
    let align = if align > 8 { align } else { 8 };
    let raw = 12 + LEAF_CAPACITY * (size_of::<K>() + size_of::<V>());
    raw.div_ceil(align) * align
}

/// A B-tree map of `len` entries held in ascending key order, in bytes: its
/// leaves, and the internal nodes above them (a node above holds twelve edges,
/// one pointer each, beyond what a leaf does).
///
/// Checked against the allocator by `tests/btree_model.rs`, which fills real maps
/// and requires the two to agree within 3%.
pub fn btree_bytes<K, V>(len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let leaf = leaf_bytes::<K, V>();
    let leaves = len.div_ceil(NODE_FILL);
    let mut bytes = leaves * leaf;
    let mut level = leaves;
    while level > 1 {
        level = level.div_ceil(NODE_FILL);
        bytes += level * (leaf + 12 * size_of::<usize>());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vector_is_charged_its_capacity() {
        let mut v: Vec<u32> = Vec::with_capacity(10);
        v.push(1);
        assert_eq!(vec_bytes(&v), 40);
    }

    /// The leaf the allocator measured: a `u64` key and an 88-byte value make a
    /// 1 072-byte node.
    #[test]
    fn a_leaf_of_u64_and_eighty_eight_bytes_is_the_measured_size() {
        assert_eq!(leaf_bytes::<u64, [u8; 88]>(), 1072);
    }

    #[test]
    fn an_empty_map_holds_nothing_and_one_entry_holds_one_leaf() {
        assert_eq!(btree_bytes::<u64, u64>(0), 0);
        assert_eq!(btree_bytes::<u64, u64>(1), leaf_bytes::<u64, u64>());
    }

    /// The model is linear in the entries, so a map twice as long is charged
    /// twice as much, within the internal nodes' share. Its agreement with the
    /// allocator is not tested here: that is the memory gate's comparison.
    #[test]
    fn the_model_grows_in_step_with_the_entries() {
        let small = btree_bytes::<u64, u64>(6_000);
        let large = btree_bytes::<u64, u64>(12_000);
        let ratio = large as f64 / small as f64;
        assert!(
            (1.95..2.05).contains(&ratio),
            "a map twice as long is charged {ratio:.3} times as much"
        );
    }
}
