// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Round 311wa — the shared no_std **bincode 1.3** wire primitives: the single
//! little-endian fixint cursor + length helpers both the replication Digest
//! codec ([`crate::storage_replication::wire`]) and the aligner codec
//! ([`crate::storage_aligner::wire`]) build on, so the one bincode-1.3 framing
//! contract (LE fixint integers, `u64` length prefixes, no-prefix fixed arrays)
//! lives in ONE place.
//!
//! Before this module each codec hand-rolled its own identical
//! `Reader` / `push_u64` / `check_len`; a fix to one could silently drift from
//! the other. The two codecs keep their own *typed* error enums
//! ([`DigestDecodeError`](crate::storage_replication::wire::DigestDecodeError) /
//! [`AlignmentDecodeError`](crate::storage_aligner::wire::AlignmentDecodeError))
//! — each `impl From<WireError>` for its enum, so `?` lifts the two structural
//! failures here into the domain error while the codec adds its own variants
//! (bad option tag, unknown variant, …).
//!
//! Gated on `storage-replication` (the Digest codec's feature); the aligner
//! feature implies it, so the aligner codec sees this module too.

use alloc::vec::Vec;

/// The two structural failures any bincode-1.3 decode can hit. Each codec maps
/// these into its own typed error (via `From`) and layers its domain-specific
/// variants on top.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireError {
    /// The buffer ended before a fixed-width field could be read.
    UnexpectedEof,
    /// A length prefix exceeds the bytes that remain — a corrupt or hostile
    /// buffer, rejected before allocating or looping.
    LengthOverflow,
}

/// Append a `u64` as 8 little-endian bytes (bincode fixint; also a length
/// prefix). The one integer width both codecs encode; wider/narrower widths
/// (e.g. the aligner's `u32` enum tags) stay with their sole consumer.
pub(crate) fn push_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// A cursor over the input bytes that reads fixed-width little-endian fields
/// and refuses to read past the end. The two byte-level reads
/// ([`read_bytes`](Reader::read_bytes) and [`read_u64`](Reader::read_u64)) are
/// all both codecs share; each codec adds its own wider reads (the aligner's
/// `read_u8`/`read_u32`/`read_string`) as inherent methods on this same type.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub(crate) fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::UnexpectedEof)?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(WireError::UnexpectedEof)?;
        self.pos = end;
        Ok(slice)
    }

    pub(crate) fn read_u64(&mut self) -> Result<u64, WireError> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.read_bytes(8)?);
        Ok(u64::from_le_bytes(bytes))
    }
}

/// Rejects a collection length that could not possibly fit in the bytes that
/// remain (`len * min_entry_bytes > remaining`, or an overflow), so a hostile
/// `u64::MAX` length fails fast instead of allocating / looping.
pub(crate) fn check_len(len: u64, min_entry_bytes: usize, r: &Reader) -> Result<(), WireError> {
    match (len as usize).checked_mul(min_entry_bytes) {
        Some(n) if n <= r.remaining() => Ok(()),
        _ => Err(WireError::LengthOverflow),
    }
}
