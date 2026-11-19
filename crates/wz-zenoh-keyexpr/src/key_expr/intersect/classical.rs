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
// src/key_expr/intersect/classical.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

//! The default intersection algorithm: watching-zenoh's one key expression matcher
//! (`wz_session_core::keyexpr_match`), so this crate and the sessions that route by key
//! expression answer from the same code.

use wz_session_core::keyexpr_match::keyexpr_intersects;

use super::{restriction::NoSubWilds, Intersector};
use crate::key_expr::key_texts;

/// Whether the key expressions spelled by `left` and `right` intersect.
///
/// The bytes come from a caller, not from a [`keyexpr`](crate::keyexpr), so they may be neither
/// UTF-8 nor canonical. Bytes that are not UTF-8 spell no key expression and intersect nothing; a
/// text that is not canonical is answered by the matcher's own rule for it (a text with an empty
/// chunk intersects nothing).
fn intersect_bytes(left: &[u8], right: &[u8]) -> bool {
    key_texts(left, right).is_some_and(|(left, right)| keyexpr_intersects(left, right))
}

/// The default intersection algorithm.
#[derive(Debug)]
pub struct ClassicIntersector;

impl Intersector<NoSubWilds<&[u8]>, NoSubWilds<&[u8]>> for ClassicIntersector {
    fn intersect(&self, left: NoSubWilds<&[u8]>, right: NoSubWilds<&[u8]>) -> bool {
        // Only the `&keyexpr` impl builds this pair, for two texts without a `$`, where the
        // matcher's `$*` step has nothing to act on: the answer is the general one.
        intersect_bytes(left.0, right.0)
    }
}

impl Intersector<&[u8], &[u8]> for ClassicIntersector {
    fn intersect(&self, left: &[u8], right: &[u8]) -> bool {
        intersect_bytes(left, right)
    }
}
