// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! W3 (SCE pin 7a94d084a) bounded owned-mirror adapters.
//!
//! SCE's codec owned projection now stores declared-`max-size` `String` /
//! `Bytes` fields as no-alloc bounded inline (`heapless::String<N>` /
//! `heapless::Vec<u8, N>`) rather than alloc `String` / `Vec<u8>`. The wz
//! builders that hand-assemble a `*Owned` value from caller-supplied data
//! must therefore copy that data into the bounded carrier, which is fallible
//! when the input exceeds the field's declared capacity `N` — the same bound
//! and error (`CodecError::TooManyElements`) the decode path enforces, so a
//! builder propagating this is symmetric with decode rejecting an over-bound
//! wire value.
//!
//! These two helpers centralise that copy so each construction site stays a
//! one-liner (`bounded_bytes(x)?` / `bounded_string(x)?`); `N` is inferred
//! from the target field type at the call site.

use sce_forge_runtime::codec::CodecError;
use sce_forge_runtime::heapless;

/// Copy a byte slice into a bounded `heapless::Vec<u8, N>`. Returns
/// [`CodecError::TooManyElements`] if the slice is longer than the field's
/// declared capacity `N` (the same bound decode enforces).
#[allow(dead_code)] // used by codec-gated builders; unused in no-codec subsets
pub fn bounded_bytes<const N: usize>(b: &[u8]) -> Result<heapless::Vec<u8, N>, CodecError> {
    heapless::Vec::from_slice(b).map_err(|_| CodecError::TooManyElements)
}

/// Copy a string slice into a bounded `heapless::String<N>`. Returns
/// [`CodecError::TooManyElements`] if the string is longer than the field's
/// declared capacity `N` (the same bound decode enforces).
#[allow(dead_code)] // used by codec-gated builders; unused in no-codec subsets
pub fn bounded_string<const N: usize>(s: &str) -> Result<heapless::String<N>, CodecError> {
    heapless::String::try_from(s).map_err(|_| CodecError::TooManyElements)
}
