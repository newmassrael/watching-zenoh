//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-keyexpr 1.10.2, file
// src/key_expr/intersect/mod.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

//! Intersection between key expressions: do two sets of keys have a key in common?
//!
//! The answer is watching-zenoh's one key expression matcher (`wz_session_core::keyexpr_match`):
//! [`keyexpr::intersects`] asks it about the two key texts, and
//! [`ClassicIntersector`](crate::key_expr::intersect::ClassicIntersector) about the bytes it is
//! given.

// The links above name crate paths. rustdoc joins this text with the outer doc `mod.rs` keeps on
// `pub mod intersect` (upstream's form) and resolves the joined text from `key_expr`, where a
// bare `ClassicIntersector` is not in scope; a crate path resolves from either module.

use super::keyexpr;

mod classical;
pub use classical::ClassicIntersector;

/// The default intersection algorithm, the one [`keyexpr::intersects`] answers by.
pub const DEFAULT_INTERSECTOR: ClassicIntersector = ClassicIntersector;

/// An algorithm that tells whether `left` and `right` intersect.
pub trait Intersector<Left, Right> {
    /// Whether the sets `left` and `right` denote have at least one key in common.
    fn intersect(&self, left: Left, right: Right) -> bool;
}

pub(crate) mod restriction {
    /// A value known to hold no `$*`, which an algorithm may then answer without a `$*` step.
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct NoSubWilds<T>(pub T);
}

/// How much matching a key expression asks of the algorithm.
#[repr(u8)]
enum MatchComplexity {
    NoWilds = 0,
    ChunkWildsOnly = 1,
    Dsl = 2,
}

trait KeyExprHelpers {
    fn match_complexity(&self) -> MatchComplexity;
}

impl KeyExprHelpers for keyexpr {
    fn match_complexity(&self) -> MatchComplexity {
        let mut has_wilds = false;
        for &c in self.as_bytes() {
            match c {
                b'*' => has_wilds = true,
                b'$' => return MatchComplexity::Dsl,
                _ => {}
            }
        }
        if has_wilds {
            MatchComplexity::ChunkWildsOnly
        } else {
            MatchComplexity::NoWilds
        }
    }
}

use restriction::NoSubWilds;

impl<
        T: for<'a> Intersector<&'a [u8], &'a [u8]>
            + for<'a> Intersector<NoSubWilds<&'a [u8]>, NoSubWilds<&'a [u8]>>,
    > Intersector<&keyexpr, &keyexpr> for T
{
    fn intersect(&self, left: &keyexpr, right: &keyexpr) -> bool {
        let left_bytes = left.as_bytes();
        let right_bytes = right.as_bytes();
        if left_bytes == right_bytes {
            return true;
        }
        // Two different key expressions without a wildcard denote two different keys, and a pair
        // with no `$*` is handed over as such. Every `T` gets this impl, a caller's own intersector
        // included, so these answers stay though the default one would give the same.
        match left.match_complexity() as u8 | right.match_complexity() as u8 {
            0 => false,
            1 => self.intersect(NoSubWilds(left_bytes), NoSubWilds(right_bytes)),
            _ => self.intersect(left_bytes, right_bytes),
        }
    }
}
