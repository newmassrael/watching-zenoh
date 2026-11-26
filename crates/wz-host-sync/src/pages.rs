// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The system's fresh pages: a block mapped for its caller alone, every byte of it zero as the
//! system hands it, and resident a page at a time as each is first written. An anonymous private
//! `mmap` on a POSIX host, `VirtualAlloc` reserved and committed on Windows; given back with
//! `munmap` and `VirtualFree`, which return its pages to the system at once.
//!
//! What a block whose untouched bytes must read zero is reserved from: the allocator's zeroed
//! block is written whole when the allocator hands it from memory given back to it before (glibc's
//! `calloc` of a heap chunk, which its rising mapping threshold makes of a block it mapped fresh
//! the first time), so a block only partly used would be written, and resident, whole.

use core::ptr::NonNull;

use crate::sys;

/// The alignment a block starts on at least: 4 KiB, the smallest page of every host this crate is
/// built for. A POSIX mapping starts on a page and a Windows one on the allocation granularity
/// (64 KiB).
pub const ALIGN: usize = 4096;

/// A block of `bytes` bytes of fresh pages, aligned to [`ALIGN`], every byte zero and no page
/// resident until it is written; `None` for no bytes, or when the system has none to map.
pub fn reserve(bytes: usize) -> Option<NonNull<u8>> {
    if bytes == 0 {
        return None;
    }
    sys::map_pages(bytes)
}

/// Give back the block at `base`: its pages return to the system, and its bytes are no longer
/// this process's.
///
/// # Safety
/// `base` is what [`reserve`] gave for `bytes`, it is given back once, and nothing uses it
/// after.
pub unsafe fn release(base: NonNull<u8>, bytes: usize) {
    // SAFETY: the caller's contract.
    unsafe { sys::unmap_pages(base, bytes) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A block of a few pages and a byte starts on [`ALIGN`], reads zero in every byte, holds
    /// what is written in it, and is given back. Turned red by a block the system hands not zero
    /// or off a page, or by a release of fewer bytes than were mapped (a later block would then
    /// meet pages written here).
    #[test]
    fn a_block_is_on_a_page_zero_and_written_as_any_memory() {
        let bytes = 3 * ALIGN + 1;
        let base = reserve(bytes).expect("the system has the pages");
        assert_eq!(
            base.as_ptr() as usize % ALIGN,
            0,
            "the block starts on a page"
        );
        // SAFETY: the block is `bytes` bytes at `base`, this test's alone until it is given back.
        let block = unsafe { core::slice::from_raw_parts_mut(base.as_ptr(), bytes) };
        assert!(block.iter().all(|byte| *byte == 0), "the block is zero");
        block.fill(0xa5);
        assert!(
            block.iter().all(|byte| *byte == 0xa5),
            "the block holds what is written"
        );
        // SAFETY: given back once, and `block` is not used after.
        unsafe { release(base, bytes) };
    }

    /// No block is mapped for no bytes. Turned red by a reservation of nothing that answers.
    #[test]
    fn no_block_is_reserved_for_no_bytes() {
        assert_eq!(reserve(0), None);
    }

    /// The host's page size.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn page_bytes() -> usize {
        // SAFETY: `sysconf` reads a value of the system and writes nothing.
        let bytes = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(bytes).expect("the system names its page size")
    }

    /// Whether each page of the `bytes` at `base` is resident, read with `mincore`, which a
    /// process may ask of its own mappings with no privilege.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn resident(base: NonNull<u8>, bytes: usize) -> std::vec::Vec<bool> {
        let mut pages = std::vec![0_u8; bytes.div_ceil(page_bytes())];
        // SAFETY: `base` starts a page of a mapping of this process at least `bytes` long, and
        // `pages` holds a byte for each page of it, which is what the call writes.
        let read = unsafe { libc::mincore(base.as_ptr().cast(), bytes, pages.as_mut_ptr()) };
        assert_eq!(read, 0, "mincore reads the mapping");
        pages.iter().map(|page| page & 1 == 1).collect()
    }

    /// No page of a block is resident before it is written, and a page written is. The block is
    /// smaller than a huge page, so no page is made resident beside the one written. The CONTROL
    /// is the page written, which is then resident. Turned red by a reservation that writes its
    /// block (the allocator's zeroed block of a reused chunk) or maps it populated.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_page_of_a_block_is_resident_only_once_written() {
        const PAGES: usize = 64;
        let bytes = PAGES * page_bytes();
        let base = reserve(bytes).expect("the system has the pages");
        let before = resident(base, bytes);
        assert_eq!(before.len(), PAGES, "a byte for each page");
        assert_eq!(
            before.iter().filter(|page| **page).count(),
            0,
            "a page no one wrote is resident"
        );
        let written = PAGES / 2;
        // SAFETY: a byte inside the block, which is this test's alone.
        unsafe { base.as_ptr().add(written * page_bytes()).write_volatile(1) };
        assert!(
            resident(base, bytes)[written],
            "CONTROL: a written page is resident"
        );
        // SAFETY: given back once, and nothing reads it after.
        unsafe { release(base, bytes) };
    }
}
