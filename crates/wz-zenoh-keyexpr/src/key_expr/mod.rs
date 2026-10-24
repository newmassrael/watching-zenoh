// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

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

/// A random key expression generator, to help with testing.
#[cfg(feature = "std")]
pub mod fuzzer;

#[cfg(test)]
mod tests;
