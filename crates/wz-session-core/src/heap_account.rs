// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Bytes a structure holds on the heap, counted from what it owns.
//!
//! Open-debt item 924 (`docs/dissect-row-index.md`, D7). A handle that says what
//! it holds, by structure, can be budgeted by the program that opens it and graded
//! by a gate that names the structure which grew; a total taken from the allocator
//! can do neither. A holder reports the structures that grow with its rows, and
//! this is the arithmetic those reports share.
//!
//! # Exact, and only exact
//!
//! A buffer's bytes are its capacity times its element, which is what the
//! allocator was asked for, so [`vec_bytes`] is the allocator's figure and not an
//! estimate of it. Every structure a report counts is built of buffers, so the
//! report is exact. There is no model here, and that is a decision: a B-tree keeps
//! its node count to itself, the first report that modelled one was 3% off for the
//! order a map was filled in, and a report that is a few percent off cannot tell a
//! structure that grew from the model being wrong. The ordered maps a report counts
//! are `crate::sorted_chunks::SortedChunks`, which are chunks of `Vec`s.
//!
//! # What a report leaves out
//!
//! Only the structures whose size follows the row count are reported. What is
//! fixed, or follows the count of distinct things (keyexprs, nodes, sessions), is
//! not, and the gate that compares a report with the allocator is what shows the
//! difference stayed nil. A report is a lower bound on the heap, never an upper
//! one.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::mem::size_of;

/// Bytes a vector has allocated: its capacity, not its length.
pub fn vec_bytes<T>(v: &Vec<T>) -> usize {
    v.capacity() * size_of::<T>()
}

/// Bytes a deque has allocated: its capacity, not its length.
pub fn vec_deque_bytes<T>(v: &VecDeque<T>) -> usize {
    v.capacity() * size_of::<T>()
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
}
