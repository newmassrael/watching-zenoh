// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The ring a session's advanced publishers' caches keep their samples in (`ADVANCED_CACHE_BYTES`),
//! as the session's form holds it ([`CacheRing`]): a span of the arena the open claimed, zero as
//! its table was lent, or, where the session's tables take their memory on use, bytes of its own
//! taken zeroed of the allocator at the caches' first use and kept for the session's life. Either
//! is lent to one caller at a time under the engine's lock of the ring
//! (`wz_capi_port::CacheBytes`).

#[cfg(not(wz_on_use))]
use crate::arena::CacheSpan;

/// The ring the session's caches keep their samples in.
pub(super) struct CacheRing {
    /// The span the open claimed in the session's arena, none for a plan of no ring.
    #[cfg(not(wz_on_use))]
    span: Option<CacheSpan>,
    /// The ring's bytes once they were taken, empty before.
    #[cfg(wz_on_use)]
    bytes: alloc::vec::Vec<u8>,
    /// The bytes the ring takes at its first use, none for a session of no ring.
    #[cfg(wz_on_use)]
    len: usize,
}

impl CacheRing {
    /// The ring over `span`, the open's claim, or none.
    #[cfg(not(wz_on_use))]
    pub(super) const fn claimed(span: Option<CacheSpan>) -> Self {
        Self { span }
    }

    /// A ring of `len` bytes, none taken yet.
    #[cfg(wz_on_use)]
    pub(super) const fn counted(len: usize) -> Self {
        Self {
            bytes: alloc::vec::Vec::new(),
            len,
        }
    }

    /// Call `with` with the ring's bytes. A ring of no bytes, and where the tables take their
    /// memory on use one whose bytes the allocator refused at this first use, is handed as an
    /// empty span, which a cache made over it refuses as a ring that holds no record; a later use
    /// asks again.
    ///
    /// # Safety
    /// The caller holds the ring alone for the call (the engine's lock of it), and, in a form whose
    /// ring is a span of the arena, the arena stands for the call.
    pub(super) unsafe fn with_bytes(&mut self, with: &mut dyn FnMut(&mut [u8])) {
        #[cfg(not(wz_on_use))]
        match self.span {
            // SAFETY: the caller's: the span is the arena's, held alone for the call, and the
            // arena stands.
            Some(span) => with(unsafe { span.bytes() }),
            None => with(&mut []),
        }
        #[cfg(wz_on_use)]
        {
            if self.bytes.is_empty() && self.len != 0 {
                self.bytes =
                    wz_runtime_coop::link_storage::zeroed_bytes(self.len).unwrap_or_default();
            }
            with(&mut self.bytes)
        }
    }
}

#[cfg(all(test, wz_on_use))]
mod tests {
    use super::*;

    /// A ring of its own takes nothing until its first use, which takes its bytes zeroed; what
    /// one use writes the next reads, in the same bytes; a ring of no bytes hands an empty span
    /// and takes nothing. Turned red by a ring taken at the open (`counted` taking its bytes),
    /// one taken again at each use (a write lost), or one not zeroed.
    #[test]
    fn an_on_use_ring_takes_its_bytes_zeroed_at_its_first_use_and_keeps_them() {
        let mut ring = CacheRing::counted(16);
        assert!(
            ring.bytes.is_empty(),
            "nothing is taken before the first use"
        );
        let mut seen = (0, false);
        // SAFETY: the ring is this test's alone.
        unsafe {
            ring.with_bytes(&mut |bytes| {
                seen = (bytes.len(), bytes.iter().all(|byte| *byte == 0));
                if let Some(first) = bytes.first_mut() {
                    *first = 7;
                }
            });
        }
        assert_eq!(seen, (16, true), "the ring's bytes, zeroed");
        let base = ring.bytes.as_ptr();
        let mut first = None;
        // SAFETY: as above.
        unsafe { ring.with_bytes(&mut |bytes| first = bytes.first().copied()) };
        assert_eq!(first, Some(7), "what one use wrote the next reads");
        assert_eq!(ring.bytes.as_ptr(), base, "in the same bytes");

        let mut none = CacheRing::counted(0);
        let mut len = None;
        // SAFETY: as above.
        unsafe { none.with_bytes(&mut |bytes| len = Some(bytes.len())) };
        assert_eq!(len, Some(0), "a ring of no bytes is an empty span");
        assert_eq!(none.bytes.capacity(), 0, "and takes nothing");
    }
}
