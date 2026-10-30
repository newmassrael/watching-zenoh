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
// src/key_expr/include.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

//! Inclusion between key expressions: does every key of one set belong to the other?
//!
//! A key expression is a list of chunks. `**` stands for any number of chunks (none included) that
//! are not verbatim, a verbatim chunk (one that starts with `@`) is matched only by itself, `*` is any
//! one chunk that is not verbatim, and inside a chunk `$*` is any run of characters. Inclusion of
//! the chunk lists is a dynamic program over the two lists, and inclusion of two chunks is inclusion
//! of two glob patterns, in which a `$*` of the including side takes any stretch of the other side
//! and a `$*` of the included side can be matched only by a `$*`, since it stands for every string.

use alloc::vec::Vec;

use super::{intersect::MayHaveVerbatim, keyexpr, DELIMITER};

/// The inclusion algorithm [`keyexpr::includes`] uses.
pub const DEFAULT_INCLUDER: LTRIncluder = LTRIncluder;

/// An algorithm that tells whether `left` includes `right`.
pub trait Includer<Left, Right> {
    /// Whether the set `left` denotes contains every key of the set `right` denotes.
    fn includes(&self, left: Left, right: Right) -> bool;
}

impl<T: for<'a> Includer<&'a [u8], &'a [u8]>> Includer<&keyexpr, &keyexpr> for T {
    fn includes(&self, left: &keyexpr, right: &keyexpr) -> bool {
        let left = left.as_bytes();
        let right = right.as_bytes();
        if left == right {
            return true;
        }
        self.includes(left, right)
    }
}

/// The default inclusion algorithm.
#[derive(Debug)]
pub struct LTRIncluder;

impl Includer<&[u8], &[u8]> for LTRIncluder {
    fn includes(&self, left: &[u8], right: &[u8]) -> bool {
        let l: Vec<&[u8]> = left.split(|c| *c == DELIMITER).collect();
        let r: Vec<&[u8]> = right.split(|c| *c == DELIMITER).collect();
        let (n, m) = (l.len(), r.len());
        // `inc[i][j]`: the chunks `l[i..]` include the chunks `r[j..]`, where `j == m` is the empty
        // remainder. Filled from the ends, since a cell depends on those after it.
        let mut inc = alloc::vec![alloc::vec![false; m + 1]; n + 1];
        for i in (0..n).rev() {
            let last = i + 1 == n;
            for j in (0..=m).rev() {
                inc[i][j] = if l[i] == b"**" {
                    // `**` takes no chunk, which is all it can do after the last chunk if the rest
                    // holds no verbatim one, or takes one more non-verbatim chunk and goes on.
                    let takes_none = if last {
                        !r[j.min(m)..].iter().any(|c| c.has_direct_verbatim())
                    } else {
                        inc[i + 1][j]
                    };
                    takes_none
                        || (j < m && !r[j].has_direct_verbatim() && j + 1 < m && inc[i][j + 1])
                } else {
                    j < m
                        && r[j] != b"**"
                        && chunk_includes(l[i], r[j])
                        && if last { j + 1 == m } else { inc[i + 1][j + 1] }
                };
            }
        }
        inc[0][0]
    }
}

/// A pattern of one chunk: a literal byte, or a stretch of any characters.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Token {
    Byte(u8),
    Star,
}

/// The tokens of a chunk: `$*` is a [`Token::Star`], the chunk `*` is one too, and every other byte
/// is itself.
pub(crate) fn tokens(chunk: &[u8]) -> Vec<Token> {
    if chunk == b"*" {
        return alloc::vec![Token::Star];
    }
    let mut out = Vec::with_capacity(chunk.len());
    let mut i = 0;
    while i < chunk.len() {
        if chunk[i..].starts_with(b"$*") {
            out.push(Token::Star);
            i += 2;
        } else {
            out.push(Token::Byte(chunk[i]));
            i += 1;
        }
    }
    out
}

/// Whether the chunk `left`, which is not `**`, includes the chunk `right`, which is not `**` either.
fn chunk_includes(left: &[u8], right: &[u8]) -> bool {
    if left == right {
        true
    } else if left.has_direct_verbatim_non_empty() || right.has_direct_verbatim_non_empty() {
        false
    } else if left == b"*" {
        true
    } else if left.contains(&b'$') {
        glob_includes(&tokens(left), &tokens(right))
    } else {
        false
    }
}

/// Whether the pattern `left` matches every string the pattern `right` matches. A star of `left`
/// takes any stretch of `right`,
/// a byte of `left` is matched by the same byte of `right` and by nothing else, in particular not
/// by a star of `right`, which stands for strings with other bytes.
fn glob_includes(left: &[Token], right: &[Token]) -> bool {
    let (n, m) = (left.len(), right.len());
    let mut inc = alloc::vec![alloc::vec![false; m + 1]; n + 1];
    inc[n][m] = true;
    for i in (0..n).rev() {
        for j in (0..=m).rev() {
            inc[i][j] = match left[i] {
                Token::Star => (j..=m).any(|k| inc[i + 1][k]),
                Token::Byte(b) => j < m && right[j] == Token::Byte(b) && inc[i + 1][j + 1],
            };
        }
    }
    inc[0][0]
}
