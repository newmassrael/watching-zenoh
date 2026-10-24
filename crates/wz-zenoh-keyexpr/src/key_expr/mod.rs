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
// src/key_expr/mod.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

//! The Key Expression Language, as explained in [`keyexpr`]'s documentation.

pub(crate) const DELIMITER: u8 = b'/';
pub(crate) const SINGLE_WILD: u8 = b'*';

pub(crate) mod owned;
pub use owned::{OwnedKeyExpr, OwnedNonWildKeyExpr};

pub(crate) mod borrowed;
pub use borrowed::*;

/// The tools to implement canonization of key expressions for string-like types.
/// The average user doesn't need to bother with it.
pub mod canon;
/// The tools to implement algorithms to detect key expression inclusivity.
/// The average user doesn't need to bother with it.
pub mod include;
/// The tools to implement algorithms to detect key expression intersection.
/// The average user doesn't need to bother with it.
pub mod intersect;

pub mod format;

/// A random key expression generator, to help with testing.
#[cfg(feature = "std")]
pub mod fuzzer;

#[cfg(test)]
mod tests;
