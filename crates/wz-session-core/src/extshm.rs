// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the wz shared-memory (SHM) DESCRIPTOR + the Put-body `ext_shm`
//! marker (`transport-shm`) — the no_std half of the scoped same-host SHM
//! transport.
//!
//! zenoh sends an SHM payload zero-copy by putting a DESCRIPTOR on the wire
//! (`commons/zenoh-codec/src/core/shm.rs:65-82` `ShmBufInfo`: data_len + a
//! `MetadataDescriptor{id,index}` + generation) in place of the payload bytes,
//! and tags the Put body with a UNIT `ext_shm` extension
//! (`commons/zenoh-protocol/src/zenoh/put.rs:73` `Shm = zextunit!(0x2, true)` —
//! body ext id 0x2, the MANDATORY bit set so a non-SHM peer rejects rather than
//! mis-reads the descriptor as data). The receiver mmaps the segment and reads
//! the payload directly from /dev/shm (`io/zenoh-transport/src/shm.rs:149-163`).
//!
//! This module is the no_std SHM machinery: the descriptor type + its VLE codec,
//! the 0x2 Put-body marker codec, and the [`ShmResolver`] trait seam. The actual
//! POSIX segment (create / mmap / open) is `std` (mmap = libc), so it lives in
//! `wz-runtime-tokio::shm_provider` behind this trait — the same no_std-core /
//! AP-runtime split as the tls / quic config. SCOPED: wz collapses zenoh's
//! `MetadataDescriptor{id:u16, index:u16}` (a slot within a watchdog metadata
//! segment) to a single `segment_id` (one segment per payload, no pool), and the
//! receiver copies the bytes out of the mmap into the owned Sample payload (wz's
//! Sample is an owned `Vec`, so the wire is zero-copy but the local Sample is a
//! single copy off the shared page — the bounded scoped characteristic).
//!
//! R3a lands the codec + trait (inert: `is_shm` is always false, so nothing is
//! emitted / resolved on the wire); the live TX swap, the RX resolver wiring, and
//! the Z_EXT_SHM 0x2 ESTABLISHMENT challenge handshake (a DIFFERENT 0x2 — the
//! init/open ext space, not this body ext space) are R3b.

use alloc::vec::Vec;
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::ext_unit::ExtUnit;

use crate::ext_header::EXT_FLAG_M;
use crate::vle::{encode_vle_u64_into, read_vle_u64};

/// The Put-body `ext_shm` marker id — zenoh `put.rs:73` `zextunit!(0x2, true)`.
/// Body ext id 0x2 (the Put / Del network-message body ext space, where wz also
/// carries 0x1 source_info + 0x3 attachment — 0x2 was unoccupied). DISTINCT from
/// the establishment 0x2 Shm ext (the Init / Open id space); a body ext and an
/// establishment ext share the numeric value but never the carrier.
pub const SHM_BODY_EXT_ID: u8 = 0x02;

/// The scoped wz SHM descriptor: the wire stand-in for an SHM-backed payload. A
/// `segment_id` (the POSIX shm object name the receiver re-opens), the payload
/// `length`, and a `generation` (zenoh's buffer version; always 0 in the scoped
/// one-segment-per-payload model — reserved for an R3b+ pool).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShmDescriptor {
    pub segment_id: u32,
    pub length: u32,
    pub generation: u32,
}

/// Encode the descriptor as the Put payload stand-in: `VLE(length) ++
/// VLE(segment_id) ++ VLE(generation)`, the field order mirroring zenoh's
/// `ShmBufInfo` write (data_len first). Uses the [`crate::vle`] SSOT.
pub fn encode_shm_descriptor(d: &ShmDescriptor) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    encode_vle_u64_into(&mut out, d.length as u64);
    encode_vle_u64_into(&mut out, d.segment_id as u64);
    encode_vle_u64_into(&mut out, d.generation as u64);
    out
}

/// Decode a descriptor from a Put payload field that carried the `ext_shm`
/// marker. `None` on truncation or a value past `u32` (a malformed peer — the
/// caller rejects).
pub fn decode_shm_descriptor(bytes: &[u8]) -> Option<ShmDescriptor> {
    let (length, n0) = read_vle_u64(bytes)?;
    let (segment_id, n1) = read_vle_u64(bytes.get(n0..)?)?;
    let (generation, _n2) = read_vle_u64(bytes.get(n0 + n1..)?)?;
    Some(ShmDescriptor {
        segment_id: u32::try_from(segment_id).ok()?,
        length: u32::try_from(length).ok()?,
        generation: u32::try_from(generation).ok()?,
    })
}

/// Build the Put-body `ext_shm` UNIT marker (header `0x02 | M` — zenoh sets the
/// MANDATORY bit, `put.rs:73 zextunit!(0x2, true)`, so a peer that does not
/// understand SHM rejects the Put rather than reading the descriptor as payload).
/// The surrounding body-ext codec applies the chain-continuation `Z` bit.
pub fn encode_shm_marker_ext() -> ExtEntryOwned {
    ExtEntryOwned {
        header: SHM_BODY_EXT_ID | EXT_FLAG_M,
        body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
    }
}

/// `true` iff a Put body ext chain carries the `ext_shm` marker — the RX signal
/// that the payload field is a descriptor to resolve (not raw bytes).
pub fn body_has_shm_marker(extensions: &[ExtEntryOwned]) -> bool {
    extensions.iter().any(|e| e.ext_id() == SHM_BODY_EXT_ID)
}

/// The no_std/std seam: an SHM-backed Put's descriptor is resolved to its bytes
/// by an AP-injected resolver (the `std` mmap-open lives in
/// `wz-runtime-tokio::shm_provider`, behind this trait). `None` when the segment
/// cannot be opened / mapped (a stale or foreign descriptor — the caller drops
/// the Sample). Used on the RX path (R3b wires it onto the subscriber registry).
pub trait ShmResolver {
    /// Open the descriptor's segment and copy its `length` bytes out (the bounded
    /// scoped copy off the shared page into wz's owned Sample payload).
    fn resolve(&self, descriptor: &ShmDescriptor) -> Option<Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The descriptor round-trips across VLE 1-byte / multi-byte field widths.
    #[test]
    fn descriptor_round_trips() {
        for d in [
            ShmDescriptor {
                segment_id: 0,
                length: 0,
                generation: 0,
            },
            ShmDescriptor {
                segment_id: 7,
                length: 63,
                generation: 1,
            },
            ShmDescriptor {
                segment_id: 0xDEAD_BEEF,
                length: 1 << 20,
                generation: 0,
            },
        ] {
            let wire = encode_shm_descriptor(&d);
            assert_eq!(decode_shm_descriptor(&wire), Some(d));
        }
    }

    /// A truncated descriptor decodes to `None` (no panic) — the malformed-peer
    /// guard.
    #[test]
    fn truncated_descriptor_is_rejected() {
        let wire = encode_shm_descriptor(&ShmDescriptor {
            segment_id: 0xABCD,
            length: 4096,
            generation: 0,
        });
        assert_eq!(decode_shm_descriptor(&wire[..1]), None);
    }

    /// The marker header byte is `0x02 | 0x10` (UNIT enc | id 0x02 | MANDATORY) —
    /// the shape zenoh emits for `put::ext::Shm`.
    #[test]
    fn marker_header_is_unit_id_two_mandatory() {
        let ext = encode_shm_marker_ext();
        assert_eq!(
            ext.header, 0x12,
            "UNIT (0x00) | SHM_BODY_EXT_ID (0x02) | M (0x10)"
        );
        assert_eq!(ext.ext_id(), SHM_BODY_EXT_ID);
        assert_eq!(
            ext.as_borrowed().encode_to_vec().len(),
            1,
            "a unit ext is one byte"
        );
    }

    /// `body_has_shm_marker` finds 0x2 and is not confused by the sibling body
    /// exts (0x1 source_info, 0x3 attachment).
    #[test]
    fn marker_detected_and_not_confused_with_siblings() {
        assert!(body_has_shm_marker(&[encode_shm_marker_ext()]));
        assert!(!body_has_shm_marker(&[]));
        let source_info = ExtEntryOwned {
            header: 0x01,
            body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
        };
        let attachment = ExtEntryOwned {
            header: 0x03,
            body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
        };
        assert!(!body_has_shm_marker(&[source_info, attachment]));
    }
}
