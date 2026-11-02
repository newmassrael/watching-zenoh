// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Owned byte and text fields built by hand.
//!
//! A generated owned message holds each `bytes` or `string` field as the
//! profile's container inside a `Bounded` of the field's bound (SCE ADR 0077):
//! `Bounded<B, MAX>`, where `MAX` is the document's `sce:max-size`, the
//! protocol's bound, and `B` is what the storage profile holds the field in.
//! These two constructors copy a slice into such a field, with the container
//! and the bounds inferred from the field the result is assigned to, so each
//! construction site stays a one-liner (`owned_bytes(x)?` / `owned_string(x)?`).
//!
//! A slice past the field's bound is refused as `LengthOutOfRange`, the error a
//! decode of such a frame gives. A profile that stores the field inline at a
//! capacity below the bound (a node's deployment) refuses a slice past that
//! capacity as `CapacityExceeded`; a growable profile (the heap) never does.

use sce_forge_runtime::codec::{Bounded, CodecError, SceByteBuf, SceStr};

/// Copy a byte slice into an owned `bytes` field: `LengthOutOfRange` past the
/// field's bound, `CapacityExceeded` past what the profile's container holds.
#[allow(dead_code)] // used by codec-gated builders; unused in no-codec subsets
pub fn owned_bytes<B: SceByteBuf, const MAX: usize, const MIN: usize>(
    b: &[u8],
) -> Result<Bounded<B, MAX, MIN>, CodecError> {
    Bounded::from_slice(b)
}

/// `suffix` as the borrowed suffix field of a key expression a node SENDS, for the
/// composers that build a message over the sender's own text (`lent_push`,
/// `lent_control`, `lent_response`): `LengthOutOfRange` past the `u16` length
/// the protocol bounds a suffix at, the refusal a decode of such a frame gives,
/// so a key past it is not sent rather than sent as another.
#[allow(dead_code)] // used by codec-gated composers; unused in no-codec subsets
pub fn sent_suffix<const MAX: usize>(suffix: &str) -> Result<Bounded<&str, MAX>, CodecError> {
    Bounded::new(suffix).ok_or(CodecError::LengthOutOfRange)
}

/// [`sent_suffix`] for any borrowed field a composer fills from the sender's own
/// bytes or text (a payload, an attachment, a schema, a selector's parameters):
/// `LengthOutOfRange` past the field's bound.
#[allow(dead_code)] // used by codec-gated composers; unused in no-codec subsets
pub fn sent<L, const MAX: usize, const MIN: usize>(
    value: L,
) -> Result<Bounded<L, MAX, MIN>, CodecError>
where
    L: sce_forge_runtime::codec::Entries,
{
    Bounded::new(value).ok_or(CodecError::LengthOutOfRange)
}

/// Copy a string slice into an owned `string` field, refused as
/// [`owned_bytes`] refuses bytes.
#[allow(dead_code)] // used by codec-gated builders; unused in no-codec subsets
pub fn owned_string<T: SceStr, const MAX: usize, const MIN: usize>(
    s: &str,
) -> Result<Bounded<T, MAX, MIN>, CodecError> {
    Bounded::from_text(s)
}
