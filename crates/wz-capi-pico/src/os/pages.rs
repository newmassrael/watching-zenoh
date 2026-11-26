// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The memory a session's arena is reserved from on a host: the system's fresh pages
//! (`wz_host_sync::pages`), one block for each arena, zero as the system hands it. The open lays
//! its rows over the block as it lies, so it writes no row it does not use and a page no row
//! uses is never resident, and the close gives the pages back to the system at once. zenoh-pico
//! takes each part of a session from `malloc` as it comes.

use core::alloc::Layout;
use core::ptr::NonNull;

use wz_capi_coop::arena::ArenaMemory;

/// The system's fresh pages, said zero (`ArenaMemory::reserves_zeroed`).
pub(crate) struct HostPages;

impl ArenaMemory for HostPages {
    /// A block of fresh pages; refused for an alignment past a page's, which no arena asks (its
    /// spans are aligned far below a page).
    fn reserve(&self, layout: Layout) -> Option<NonNull<u8>> {
        if layout.align() > wz_host_sync::pages::ALIGN {
            return None;
        }
        wz_host_sync::pages::reserve(layout.size())
    }

    fn reserves_zeroed(&self) -> bool {
        true
    }

    unsafe fn release(&self, base: NonNull<u8>, layout: Layout) {
        // SAFETY: the caller's contract: `reserve` mapped `base` for `layout.size()` bytes, and
        // it is given back once.
        unsafe { wz_host_sync::pages::release(base, layout.size()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pages are said zero and are: a block reserved for a layout of an odd size reads zero
    /// in every byte, starts on its alignment and is given back. Turned red by pages not said
    /// zero, whose open writes the arena's rows, or by a block of fewer bytes than the layout.
    #[test]
    fn host_pages_are_said_zero_and_read_zero() {
        assert!(HostPages.reserves_zeroed());
        let layout = Layout::from_size_align(5 * 4096 + 7, 64).expect("a layout");
        let base = HostPages.reserve(layout).expect("the system has the pages");
        assert_eq!(
            base.as_ptr() as usize % layout.align(),
            0,
            "on its alignment"
        );
        // SAFETY: the block is `layout.size()` bytes at `base`, this test's alone.
        let block = unsafe { core::slice::from_raw_parts(base.as_ptr(), layout.size()) };
        assert!(block.iter().all(|byte| *byte == 0), "the block is zero");
        // SAFETY: `reserve` gave `base` for `layout`, given back once and not read after.
        unsafe { HostPages.release(base, layout) };
    }

    /// A layout aligned past a page is refused, taking nothing. The CONTROL is the same size on a
    /// page's alignment, which is given. Turned red by a block handed off the alignment asked.
    #[test]
    fn a_layout_aligned_past_a_page_is_refused() {
        let past = Layout::from_size_align(4096, 2 * wz_host_sync::pages::ALIGN).expect("a layout");
        assert_eq!(HostPages.reserve(past), None);
        let page = Layout::from_size_align(4096, wz_host_sync::pages::ALIGN).expect("a layout");
        let base = HostPages
            .reserve(page)
            .expect("CONTROL: a page's alignment is given");
        // SAFETY: `reserve` gave `base` for `page`, given back once.
        unsafe { HostPages.release(base, page) };
    }
}
