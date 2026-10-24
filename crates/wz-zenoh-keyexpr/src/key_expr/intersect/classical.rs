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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-keyexpr 1.10.1, file
// src/key_expr/intersect/classical.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

//! The default intersection algorithm: a dynamic program over the chunks of the two key expressions,
//! with the chunk step a non-emptiness test of the intersection of two glob patterns.

use alloc::{vec, vec::Vec};

use super::{restriction::NoSubWilds, Intersector, MayHaveVerbatim};
use crate::key_expr::{
    include::{tokens, Token},
    DELIMITER,
};

/// Whether some string is matched by both patterns. A star of one side takes nothing, or takes the
/// next token of the other (a star included, which that way is absorbed whole), and a byte is
/// matched by the same byte.
fn glob_intersect(a: &[Token], b: &[Token]) -> bool {
    let (n, m) = (a.len(), b.len());
    let mut meet = vec![vec![false; m + 1]; n + 1];
    meet[n][m] = true;
    for i in (0..=n).rev() {
        for j in (0..=m).rev() {
            if i == n && j == m {
                continue;
            }
            meet[i][j] = if i < n && a[i] == Token::Star {
                meet[i + 1][j] || (j < m && meet[i][j + 1])
            } else if j < m && b[j] == Token::Star {
                meet[i][j + 1] || (i < n && meet[i + 1][j])
            } else {
                i < n && j < m && a[i] == b[j] && meet[i + 1][j + 1]
            };
        }
    }
    meet[0][0]
}

/// Whether two chunks, neither of which is `**`, have a key chunk in common. With `star_dsl` off the
/// only wildcard of a chunk is the chunk `*`.
fn chunk_intersect(star_dsl: bool, c1: &[u8], c2: &[u8]) -> bool {
    if c1 == c2 {
        return true;
    }
    if c1.has_direct_verbatim() || c2.has_direct_verbatim() {
        return false;
    }
    c1 == b"*" || c2 == b"*" || (star_dsl && glob_intersect(&tokens(c1), &tokens(c2)))
}

/// Whether the key expressions `s1` and `s2` intersect. A dynamic program over the chunk lists:
/// `**` against a chunk either takes it (if it is not verbatim) or is done, and a last `**` takes
/// the whole rest of the other side, which then must hold no verbatim chunk.
pub fn intersect(star_dsl: bool, s1: &[u8], s2: &[u8]) -> bool {
    let a: Vec<&[u8]> = s1.split(|c| *c == DELIMITER).collect();
    let b: Vec<&[u8]> = s2.split(|c| *c == DELIMITER).collect();
    let (n, m) = (a.len(), b.len());
    // The empty key expression has no chunk, where splitting it gives one empty chunk.
    let (n, m) = (
        if s1.is_empty() { 0 } else { n },
        if s2.is_empty() { 0 } else { m },
    );
    // `meet[i][j]`: the chunks `a[i..]` and `b[j..]` intersect.
    let mut meet = vec![vec![false; m + 1]; n + 1];
    let lone_double = |c: &[&[u8]], from: usize| from + 1 == c.len() && c[from] == b"**";
    for i in (0..=n).rev() {
        for j in (0..=m).rev() {
            meet[i][j] = if i == n || j == m {
                // One side is spent: the other may only have a last `**` left, or nothing.
                (i == n || lone_double(&a, i)) && (j == m || lone_double(&b, j))
            } else if a[i] == b"**" {
                if i + 1 == n {
                    !b[j..].iter().any(|c| c.has_direct_verbatim())
                } else {
                    (!b[j].has_direct_verbatim_non_empty() && meet[i][j + 1]) || meet[i + 1][j]
                }
            } else if b[j] == b"**" {
                if j + 1 == m {
                    !a[i..].iter().any(|c| c.has_direct_verbatim())
                } else {
                    (!a[i].has_direct_verbatim_non_empty() && meet[i + 1][j]) || meet[i][j + 1]
                }
            } else {
                chunk_intersect(star_dsl, a[i], b[j]) && meet[i + 1][j + 1]
            };
        }
    }
    meet[0][0]
}

/// The default intersection algorithm.
#[derive(Debug)]
pub struct ClassicIntersector;

impl Intersector<NoSubWilds<&[u8]>, NoSubWilds<&[u8]>> for ClassicIntersector {
    fn intersect(&self, left: NoSubWilds<&[u8]>, right: NoSubWilds<&[u8]>) -> bool {
        intersect(false, left.0, right.0)
    }
}

impl Intersector<&[u8], &[u8]> for ClassicIntersector {
    fn intersect(&self, left: &[u8], right: &[u8]) -> bool {
        intersect(true, left, right)
    }
}
