// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Intersection between key expressions: do two sets of keys have a key in common?

use super::keyexpr;

mod classical;
pub use classical::ClassicIntersector;

/// The intersection algorithm [`keyexpr::intersects`] uses.
pub const DEFAULT_INTERSECTOR: ClassicIntersector = ClassicIntersector;

/// An algorithm that tells whether `left` and `right` intersect.
pub trait Intersector<Left, Right> {
    /// Whether the sets `left` and `right` denote have at least one key in common.
    fn intersect(&self, left: Left, right: Right) -> bool;
}

pub(crate) mod restriction {
    /// A value known to hold no `$*`, whose chunks are then compared without the glob step.
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
        // Two different key expressions without a wildcard denote two different keys, and when no
        // `$*` is involved the chunks are compared without the glob step.
        match left.match_complexity() as u8 | right.match_complexity() as u8 {
            0 => false,
            1 => self.intersect(NoSubWilds(left_bytes), NoSubWilds(right_bytes)),
            _ => self.intersect(left_bytes, right_bytes),
        }
    }
}

/// What the algorithms ask of a slice of bytes about verbatim chunks (those starting with `@`).
pub(crate) trait MayHaveVerbatim {
    /// Whether the first chunk starts with `@`.
    fn has_direct_verbatim(&self) -> bool;
    /// Whether the first chunk is non-empty and starts with `@`.
    fn has_direct_verbatim_non_empty(&self) -> bool {
        self.has_direct_verbatim()
    }
}

impl MayHaveVerbatim for [u8] {
    fn has_direct_verbatim(&self) -> bool {
        matches!(self, [b'@', ..])
    }
    fn has_direct_verbatim_non_empty(&self) -> bool {
        self.first() == Some(&b'@')
    }
}
