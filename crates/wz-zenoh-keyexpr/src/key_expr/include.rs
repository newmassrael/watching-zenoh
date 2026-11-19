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
//! The answer is watching-zenoh's one key expression matcher (`wz_session_core::keyexpr_match`),
//! the code the sessions route by: [`keyexpr::includes`] asks it about the two key texts, and
//! [`LTRIncluder`] about the bytes it is given.

use wz_session_core::keyexpr_match::keyexpr_includes;

use super::{key_texts, keyexpr};

/// The default inclusion algorithm, the one [`keyexpr::includes`] answers by.
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
        // The bytes come from a caller, not from a `keyexpr`, so they may be neither UTF-8 nor
        // canonical. Bytes that are not UTF-8 spell no key expression and are in no relation; a
        // text that is not canonical is answered by the matcher's own rule for it (a text with an
        // empty chunk includes nothing and is included by nothing).
        key_texts(left, right).is_some_and(|(left, right)| keyexpr_includes(left, right))
    }
}
