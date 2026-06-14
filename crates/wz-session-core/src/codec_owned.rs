// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311nq (SCE pin 5769510d8) owned-projection byte/string adapters.
//!
//! SCE's codec owned projection stores declared-`max-size` `String` / `Bytes`
//! fields via the profile-aware, N-preserving newtypes `SceString<N>` /
//! `SceBytes<N>` (`vendor/sce/sce-forge-runtime/rust/src/codec.rs`): under
//! `alloc` they wrap an UNBOUNDED `String` / `Vec<u8>` (the `N` is advisory —
//! the heap backs the carrier), under no-alloc they wrap `heapless::String<N>`
//! / `heapless::Vec<u8, N>`, where an over-`N` input is UNREPRESENTABLE and
//! the constructor returns `CodecError::TooManyElements`. This split is
//! uniform across EVERY `sce:max-size` scalar field in the workspace (msg_put
//! / query / err / init_body / encoding / ...), not special to one codec.
//!
//! These wrappers re-export SCE's associated constructors
//! `SceBytes::<N>::from_slice` / `SceString::<N>::from_view` so each
//! construction site stays a one-liner (`owned_bytes(x)?` / `owned_string(x)?`);
//! `N` is inferred from the target field type (the newtype preserves it).
//!
//! Tier symmetry: alloc is lossless — the unbounded-PUT parity with zenoh-pico,
//! exercised end-to-end by the 257B
//! `wz_acceptor_accepts_pico_put_over_legacy_256_bound`. no-alloc over-`N` is a
//! structural `TooManyElements` guaranteed by the `heapless<N>` TYPE, not a
//! runtime assert — unrepresentable, so no separate wz test re-checks what the
//! type already forbids. The module/fn names are `owned_*` (not `bounded_*`,
//! R311nq rename) precisely because the alloc carrier is unbounded.

use sce_forge_runtime::codec::{CodecError, SceBytes, SceString};

/// Copy a byte slice into the profile-aware `SceBytes<N>` owned carrier
/// (alloc: unbounded `Vec<u8>`; no-alloc: `heapless::Vec<u8, N>` with
/// [`CodecError::TooManyElements`] if longer than `N`).
#[allow(dead_code)] // used by codec-gated builders; unused in no-codec subsets
pub fn owned_bytes<const N: usize>(b: &[u8]) -> Result<SceBytes<N>, CodecError> {
    // SCE 1d439ea07 moved SceBytes to the shared `sce-portable-bytes` crate,
    // whose `from_slice` returns `Err(CapacityExceeded)`; the `?` maps it to
    // `CodecError` via the SCE-provided `From` impl (codec.rs:144) — the same
    // pattern the generated codecs use. `SceString` still lives in
    // `sce_forge_runtime::codec` and returns `CodecError` directly.
    Ok(SceBytes::<N>::from_slice(b)?)
}

/// Copy a string slice into the profile-aware `SceString<N>` owned carrier
/// (alloc: unbounded `String`; no-alloc: `heapless::String<N>` with
/// [`CodecError::TooManyElements`] if longer than `N`).
#[allow(dead_code)] // used by codec-gated builders; unused in no-codec subsets
pub fn owned_string<const N: usize>(s: &str) -> Result<SceString<N>, CodecError> {
    SceString::<N>::from_view(s)
}
