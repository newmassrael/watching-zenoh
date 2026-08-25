// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Shared registration-failure taxonomy for the application-layer
//! registries.
//!
//! R311gb (Track 2) — every bounded registry's `register*` /
//! `on_*_declared_sink` entry point can fail in exactly the same two ways
//! on the no-alloc (MCU) backing: the backing table is at its declared
//! [`crate::caps`] capacity, or a stored keyexpr exceeds
//! [`crate::caps::MAX_KEYEXPR_BYTES`]. Rather than each registry minting a
//! byte-identical private error enum (the R311hd..hg state had five),
//! they share this single type — the SSOT for "a bounded registry
//! rejected a registration."
//!
//! Not every registry produces every variant: the reply registry and the
//! declaration-observer registries store no keyexpr, so they only ever
//! return [`RegisterError::TableFull`]. This is the idiomatic shared-error
//! shape (cf. `std::io::Error`'s kinds) — a single operation produces a
//! subset of the type's variants. On the `alloc` (AP) backing no variant
//! is ever returned: the table and keyexpr buffer grow past the advisory
//! capacity, so the convenience wrappers `.expect()` the result.

/// Failure modes of a bounded registry registration on the no-alloc
/// backing. Shared across [`crate::pubsub`], [`crate::query`],
/// [`crate::reply`], and the [`crate::declare`] registries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    /// The registry's backing table is at its declared
    /// [`crate::caps`] capacity.
    TableFull,
    /// A stored keyexpr exceeds [`crate::caps::MAX_KEYEXPR_BYTES`].
    /// Produced by registries that store a keyexpr pattern
    /// (subscriber / queryable / liveliness-subscriber) and, since
    /// R311y833, by the REPLY registry too: a pending z_get stores the
    /// keyexpr it was asked under so it can keep zenoh's matching-reply
    /// guarantee ([`crate::reply_acceptance`]). This doc previously said
    /// "never by the reply ... registries"; that ceased to be true when the
    /// guarantee landed. The declaration-observer registry still never
    /// produces it.
    KeyexprTooLong,
}

impl core::fmt::Display for RegisterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TableFull => f.write_str("registry backing table at declared capacity"),
            Self::KeyexprTooLong => f.write_str("registry keyexpr exceeds declared capacity"),
        }
    }
}

impl core::error::Error for RegisterError {}
