// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2908 — a value whose every MUTABLE access is counted.
//!
//! A route cache is only as correct as its invalidation, and upstream keeps
//! its own correct by calling `disable_data_routes` / `disable_all_routes` at
//! each site that changes what a route reads
//! (`zenoh/src/net/routing/hat/mod.rs` @ `fn disable_all_routes(&mut self, tables: &mut TablesData) {`).
//! That is a list of call sites, and a list is exactly what a later mutation
//! site forgets to join. wz derives the invalidation from the table instead:
//! a table that keeps its route inputs in [`Versioned`] fields cannot be
//! changed without its version moving, because the only way to reach a
//! `&mut T` is [`DerefMut`], and that is where the count is taken.
//!
//! The count over-approximates on purpose: a mutable borrow that turns out to
//! change nothing still bumps it. That costs a recompute and never a stale
//! route, which is the only direction a cache may err in.

use core::ops::{Deref, DerefMut};

/// A `T` plus the number of times a `&mut T` has been handed out.
///
/// Reads go through [`Deref`] and leave the version alone; any mutable access
/// goes through [`DerefMut`] and advances it. The counter WRAPS rather than
/// saturating: a saturated counter would stop moving and freeze every cache
/// keyed on it, while a wrapped one only repeats a value after 2^64 mutations
/// between two reads.
#[derive(Debug, Clone, Default)]
pub struct Versioned<T> {
    value: T,
    version: u64,
}

impl<T> Versioned<T> {
    /// Wrap `value` at version 0.
    pub const fn new(value: T) -> Self {
        Self { value, version: 0 }
    }

    /// How many mutable accesses this value has seen.
    pub fn version(&self) -> u64 {
        self.version
    }
}

impl<T> Deref for Versioned<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T> DerefMut for Versioned<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.version = self.version.wrapping_add(1);
        &mut self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_leaves_the_version_and_a_mutable_access_advances_it() {
        let mut v = Versioned::new(vec![1u8]);
        assert_eq!(v.version(), 0);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], 1);
        assert_eq!(v.version(), 0, "a read must not count");
        v.push(2);
        assert_eq!(v.version(), 1);
        // A mutable access that changes nothing still counts: the cache this
        // feeds may recompute, never serve a stale answer.
        let _ = v.get_mut(0);
        assert_eq!(v.version(), 2);
        assert_eq!(*v, vec![1, 2]);
    }
}
