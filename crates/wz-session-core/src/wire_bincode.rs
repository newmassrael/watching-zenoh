// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Round 311wa — the shared no_std **bincode 1.3** wire primitives: the single
//! little-endian fixint cursor + length helpers the three wire codecs build on
//! — the replication Digest codec and the aligner codec of the storage plane
//! (the wz-storage crate's `storage_replication::wire` and `storage_aligner::wire`),
//! and the group-membership codec (`group_membership`, under its own feature) — so the one
//! bincode-1.3 framing contract (LE fixint integers, `u64` length prefixes,
//! no-prefix fixed arrays) lives in ONE place.
//!
//! Before this module each codec hand-rolled its own identical
//! `Reader` / `push_u64` / `check_len`; a fix to one could silently drift from
//! the others (and the aligner / group `read_string` guards had). Each codec
//! keeps its own *typed* error enum (the storage plane's `DigestDecodeError` and
//! `AlignmentDecodeError`, the group codec's `GroupDecodeError`) — each an
//! `impl From<WireError>`, so `?` lifts the two structural failures here into the
//! domain error while the codec adds its own variants (bad option tag, unknown
//! variant, …).
//!
//! Public under `wire-bincode` (lib.rs) since the server-layer split moved two of
//! its three consumers above the core: the storage plane's replication and
//! aligner turn it on, and `ext-pubsub-group-membership` implies it. Every item
//! is public, so a build with one consumer carries the widths the others use as
//! public items rather than dead code; until the split they were narrowed per
//! consumer pair, which a crate boundary cannot see.

use alloc::vec::Vec;

/// The two structural failures any bincode-1.3 decode can hit. Each codec maps
/// these into its own typed error (via `From`) and layers its domain-specific
/// variants on top.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The buffer ended before a fixed-width field could be read.
    UnexpectedEof,
    /// A length prefix exceeds the bytes that remain — a corrupt or hostile
    /// buffer, rejected before allocating or looping.
    LengthOverflow,
}

/// Append a `u64` as 8 little-endian bytes (bincode fixint; also a length
/// prefix). The one width the digest codec needs; the other multi-consumer
/// widths (`u32` enum tags, length-prefixed `String`s / `Option<String>`s) are
/// below, shared by the aligner and group codecs. Single-consumer composite
/// shapes (an `f32`, a std `Duration`, the zenoh uhlc `Timestamp`) stay with
/// their sole consumer.
pub fn push_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// A cursor over the input bytes that reads fixed-width little-endian fields
/// and refuses to read past the end. [`read_bytes`](Reader::read_bytes) and
/// [`read_u64`](Reader::read_u64) are the byte-level reads every consumer
/// shares; the wider multi-consumer widths (`read_u8` / `read_u32` /
/// `read_len_prefixed_bytes`) are the free fns below, and each codec layers its
/// own typed reads (e.g. the aligner's `read_string` / `read_timestamp`) on
/// this same type.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A cursor at the start of `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// The bytes not read yet.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// The next `n` bytes, or [`WireError::UnexpectedEof`] when fewer remain.
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::UnexpectedEof)?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(WireError::UnexpectedEof)?;
        self.pos = end;
        Ok(slice)
    }

    /// A `u64` from 8 little-endian bytes.
    pub fn read_u64(&mut self) -> Result<u64, WireError> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.read_bytes(8)?);
        Ok(u64::from_le_bytes(bytes))
    }
}

/// Rejects a collection / string length that could not possibly fit in the
/// bytes that remain (`len * min_entry_bytes > remaining`, or an overflow), so
/// a hostile `u64::MAX` length fails fast instead of allocating / looping.
///
/// The wire `len` is a `u64`; this first rejects a `len` that does not fit the
/// platform `usize` — the overflow guard the aligner's `read_string` used to
/// inline as a `try_into`. On a 64-bit target a `u64` always fits `usize`, so
/// it is a no-op there; on a 32-bit target it rejects a `len >= 2^32` that a
/// bare `as usize` cast would otherwise truncate (and then mis-read). Folding
/// the reject into the one guard hardens every length-prefixed read — digest,
/// aligner, group — uniformly, keeping the SSOT the stricter of the two prior
/// copies.
pub fn check_len(len: u64, min_entry_bytes: usize, r: &Reader) -> Result<(), WireError> {
    let len = usize::try_from(len).map_err(|_| WireError::LengthOverflow)?;
    match len.checked_mul(min_entry_bytes) {
        Some(n) if n <= r.remaining() => Ok(()),
        _ => Err(WireError::LengthOverflow),
    }
}

// ---- multi-consumer bincode-1.3 widths (the aligner + group codecs) ----
//
// These widths are encoded/decoded byte-identically by BOTH the storage plane's
// aligner codec and the group-membership codec ([`crate::group_membership`]);
// before R311y103 each hand-rolled its own copy (the aligner as inherent
// `Reader` methods, the group as free fns), and the two `read_string` length
// guards had already drifted apart — the aligner inlined a `try_into` +
// `len > remaining` check while the group routed through the shared
// [`check_len`]. Hoisting the structural widths here makes the one bincode-1.3
// framing the SSOT (and [`check_len`] now folds in the aligner's over-`usize`
// `try_into` reject, so neither codec loses behavior); each codec keeps its own
// *domain* validity (a bad-UTF-8 string, an out-of-range `Option` tag, a
// `Duration` with illegal nanos) mapped to its own typed error at a thin
// wrapper, so the shared [`WireError`] stays the two structural failures and no
// codec gains a variant it cannot produce (the digest codec reads none of these
// widths).

/// Append a `u32` as 4 little-endian bytes (a bincode enum-variant index /
/// `Action` tag).
pub fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// Append a bincode `String`: a `u64` length prefix then the UTF-8 bytes.
pub fn push_string(out: &mut Vec<u8>, s: &str) {
    push_u64(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

/// Append a bincode `Option<String>`: a single `0` / `1` tag byte, then the
/// `String` only for `Some` (serde's `serialize_none` / `serialize_some`, a
/// `u8` tag — distinct from an enum's `u32` variant index).
pub fn push_option_string(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(v) => {
            out.push(1);
            push_string(out, v);
        }
        None => out.push(0),
    }
}

/// Read a single byte (a bincode `u8` / an `Option`-or-`bool` discriminant the
/// caller interprets against its own typed error).
pub fn read_u8(r: &mut Reader) -> Result<u8, WireError> {
    Ok(r.read_bytes(1)?[0])
}

/// Read a `u32` as 4 little-endian bytes (a bincode enum-variant index).
pub fn read_u32(r: &mut Reader) -> Result<u32, WireError> {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(r.read_bytes(4)?);
    Ok(u32::from_le_bytes(bytes))
}

/// Read a length-prefixed byte run: a `u64` length, guarded against the bytes
/// that remain ([`check_len`] with a 1-byte element), then that many bytes.
/// The single length-guard SSOT under both codecs' `String` decode — the guard
/// that had drifted between them. The caller layers its own UTF-8 validation
/// (and typed bad-UTF-8 error) on the returned slice; a passing [`check_len`]
/// means `len` fits both `usize` and the remaining buffer, so the `as usize` is
/// exact and cannot truncate-then-over-read.
pub fn read_len_prefixed_bytes<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], WireError> {
    let len = r.read_u64()?;
    check_len(len, 1, r)?;
    r.read_bytes(len as usize)
}
