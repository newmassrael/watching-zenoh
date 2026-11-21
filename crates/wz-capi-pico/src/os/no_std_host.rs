// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the library links in `std`'s place on a host when it is built without it (`os-posix`): the
//! global allocator, which is the C library's heap, and the panic handler, which aborts the
//! process.
//!
//! The heap is the process's own `malloc`, the one zenoh-pico allocates from and the one
//! `z_malloc` hands a program (`os::malloc`), so the library adds no allocator of its own to the
//! process. A block whose alignment `malloc` does not promise is taken with the C library's aligned
//! allocation: `posix_memalign` on a POSIX host, whose blocks `free` releases, and `_aligned_malloc`
//! on Windows, whose blocks only `_aligned_free` releases; which one a block came from is read
//! again from its layout when it is released, the rule the standard library's own allocator over
//! the C library keeps.
//!
//! A panic ends the process, as a failed assertion in zenoh-pico does: a library without `std`
//! does not unwind (docs/c-abi-engine-and-memory.md, section 3), and what is left to panic is a
//! defect, since memory and the wire are refused by code. So the personality routine the
//! toolchain's prebuilt `core` names is answered here too, and it aborts.

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;

/// The alignment every block `malloc` returns has: two words on a 64-bit host, one on a 32-bit
/// one (glibc's `MALLOC_ALIGNMENT`, and the C runtime's on Windows, are at least this).
const MALLOC_ALIGN: usize = if cfg!(target_pointer_width = "64") {
    16
} else {
    8
};

/// Whether `malloc` alone gives a block of `layout`: an alignment it promises, which a block
/// smaller than its alignment may not get from an allocator that packs small sizes.
fn malloc_fits(layout: &Layout) -> bool {
    layout.align() <= MALLOC_ALIGN && layout.align() <= layout.size()
}

/// The C library's heap.
pub(crate) struct CHeap;

// SAFETY: every block is the C library's, of at least the layout's size and alignment, and is
// released by the call that matches the one that took it (`malloc_fits` reads the same answer from
// the same layout at both ends).
unsafe impl GlobalAlloc for CHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if malloc_fits(&layout) {
            libc::malloc(layout.size()).cast()
        } else {
            aligned_alloc(&layout)
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if malloc_fits(&layout) {
            libc::calloc(1, layout.size()).cast()
        } else {
            let block = aligned_alloc(&layout);
            if !block.is_null() {
                core::ptr::write_bytes(block, 0, layout.size());
            }
            block
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if malloc_fits(&layout) {
            libc::free(ptr.cast());
        } else {
            aligned_free(ptr.cast());
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
        if malloc_fits(&layout) && malloc_fits(&new_layout) {
            return libc::realloc(ptr.cast(), new_size).cast();
        }
        let block = self.alloc(new_layout);
        if !block.is_null() {
            core::ptr::copy_nonoverlapping(ptr, block, layout.size().min(new_size));
            self.dealloc(ptr, layout);
        }
        block
    }
}

/// A block of `layout` from `posix_memalign`, whose alignment must be a power of two and a
/// multiple of a word. Null when the C library has none.
#[cfg(unix)]
unsafe fn aligned_alloc(layout: &Layout) -> *mut u8 {
    let align = layout.align().max(core::mem::size_of::<usize>());
    let mut block: *mut c_void = core::ptr::null_mut();
    if libc::posix_memalign(&mut block, align, layout.size()) != 0 {
        return core::ptr::null_mut();
    }
    block.cast()
}

/// `posix_memalign`'s blocks are `free`'s.
#[cfg(unix)]
unsafe fn aligned_free(block: *mut c_void) {
    libc::free(block);
}

/// A block of `layout` from the C runtime's `_aligned_malloc`. Null when it has none.
#[cfg(windows)]
unsafe fn aligned_alloc(layout: &Layout) -> *mut u8 {
    libc::aligned_malloc(layout.size(), layout.align()).cast()
}

/// `_aligned_malloc`'s blocks are `_aligned_free`'s and no other call's.
#[cfg(windows)]
unsafe fn aligned_free(block: *mut c_void) {
    libc::aligned_free(block);
}

// The C library the library calls (its heap, threads, clocks and sockets), named for the linker.
// A program with `std` has it named through `std`; the `libc` crate names none on a host outside
// `std`'s own build (on GNU/Linux only as `std`'s dependency, on any host not with its `std`
// feature, which this graph turns on). Unnamed, the library carries no DT_NEEDED for it and each
// of its calls is an unversioned reference, which the loader binds to the OLDEST version of the
// symbol: glibc's 2.2.5 compatibility `pthread_cond_*`, whose condition variable is another
// object, so `z_condvar_init` failed and a timed wait returned at once (measured on the first
// build). Named here, the link records the C library and the default version of every symbol.
// `pthread` is its own library before glibc 2.34; the linker drops a library nothing needs.
#[cfg(all(
    feature = "os-posix",
    not(feature = "std"),
    target_os = "linux",
    target_env = "gnu"
))]
#[link(name = "pthread")]
#[link(name = "c")]
extern "C" {}
// Every other POSIX host keeps its threads in its C library.
#[cfg(all(
    feature = "os-posix",
    not(feature = "std"),
    unix,
    not(all(target_os = "linux", target_env = "gnu"))
))]
#[link(name = "c")]
extern "C" {}
// Windows: the C runtime, the DLL's (`msvcrt`, its import library) or the static one (`libcmt`)
// as the target's `crt-static` says, as `std` names it.
#[cfg(all(
    feature = "os-posix",
    not(feature = "std"),
    target_env = "msvc",
    not(target_feature = "crt-static")
))]
#[link(name = "msvcrt")]
extern "C" {}
#[cfg(all(
    feature = "os-posix",
    not(feature = "std"),
    target_env = "msvc",
    target_feature = "crt-static"
))]
#[link(name = "libcmt")]
extern "C" {}

// The library's own memory, in a build that has no `std` to give it. A test build links `std`,
// whose allocator and panic handler are the test's.
#[cfg(all(feature = "os-posix", not(feature = "std"), not(test)))]
#[global_allocator]
static HEAP: CHeap = CHeap;

#[cfg(all(feature = "os-posix", not(feature = "std"), not(test)))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: ends the process; nothing returns.
    unsafe { libc::abort() }
}

// The toolchain's `core` and `alloc` are prebuilt to unwind, and their unwind tables name the
// personality routine `std`'s unwinder defines (`DW.ref.rust_eh_personality`); linking the library
// as one program does not take that reference out (measured: an undefined `rust_eh_personality`
// in the fat-LTO build, which no C program linking the library resolves). Nothing unwinds here:
// the library is built `panic = "abort"` and its panic handler aborts, so no unwind ever starts
// and the routine is never called. It is the name answered, and if it were ever reached, the
// answer is the panic handler's. Rebuilding `core` without unwinding (`-Z build-std` with
// `panic_abort`) would take the reference out at its source, but needs a nightly toolchain, and the
// pin is the stable one (`rust-toolchain.toml`). An MSVC build's tables name the C runtime's
// `__CxxFrameHandler3` and not this routine, so it defines none. The same answer as the host
// program glue's (`wz_runtime_posix::posix_image_no_heap!`).
#[cfg(all(
    feature = "os-posix",
    not(feature = "std"),
    not(test),
    not(target_env = "msvc")
))]
#[no_mangle]
extern "C" fn rust_eh_personality() -> ! {
    // SAFETY: ends the process; nothing returns.
    unsafe { libc::abort() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layouts a library asks for: below, at and above `malloc`'s alignment, and blocks smaller
    /// than their alignment.
    fn layouts() -> impl Iterator<Item = Layout> {
        [1usize, 2, 8, 16, 32, 64, 4096]
            .into_iter()
            .flat_map(|align| {
                [1usize, 7, 16, 100, 5000]
                    .into_iter()
                    .map(move |size| Layout::from_size_align(size, align).expect("a layout"))
            })
    }

    /// Every block is at least its alignment and holds its size, and is released by the call that
    /// matches the one that took it (a mismatch is a crash or a corrupted heap under the C
    /// library's own checks).
    #[test]
    fn every_block_has_its_alignment_and_holds_its_size() {
        let mut taken = 0;
        for layout in layouts() {
            // SAFETY: a layout of a non-zero size; the block is written within it and released
            // with the same layout.
            unsafe {
                let block = CHeap.alloc(layout);
                assert!(!block.is_null(), "{layout:?}");
                assert_eq!(block as usize % layout.align(), 0, "{layout:?}");
                core::ptr::write_bytes(block, 0xa5, layout.size());
                assert_eq!(*block.add(layout.size() - 1), 0xa5);
                CHeap.dealloc(block, layout);
            }
            taken += 1;
        }
        assert_eq!(taken, 35, "ANTI-VACUITY: every layout was taken");
    }

    #[test]
    fn a_zeroed_block_is_zero_at_every_alignment() {
        for layout in layouts() {
            // SAFETY: as above.
            unsafe {
                let block = CHeap.alloc_zeroed(layout);
                assert!(!block.is_null(), "{layout:?}");
                assert_eq!(block as usize % layout.align(), 0, "{layout:?}");
                let bytes = core::slice::from_raw_parts(block, layout.size());
                assert!(bytes.iter().all(|&b| b == 0), "{layout:?}");
                CHeap.dealloc(block, layout);
            }
        }
    }

    /// A block grown or shrunk keeps what it held up to the smaller size and its alignment, on the
    /// C library's `realloc` and on the aligned path that copies.
    #[test]
    fn a_resized_block_keeps_its_bytes_and_its_alignment() {
        for layout in layouts() {
            for new_size in [1usize, layout.size() * 3 + 1] {
                // SAFETY: as above; the resized block is released with its new layout.
                unsafe {
                    let block = CHeap.alloc(layout);
                    assert!(!block.is_null());
                    for i in 0..layout.size() {
                        *block.add(i) = i as u8;
                    }
                    let grown = CHeap.realloc(block, layout, new_size);
                    assert!(!grown.is_null(), "{layout:?} to {new_size}");
                    assert_eq!(
                        grown as usize % layout.align(),
                        0,
                        "{layout:?} to {new_size}"
                    );
                    for i in 0..layout.size().min(new_size) {
                        assert_eq!(*grown.add(i), i as u8, "{layout:?} to {new_size} at {i}");
                    }
                    CHeap.dealloc(
                        grown,
                        Layout::from_size_align(new_size, layout.align()).expect("a layout"),
                    );
                }
            }
        }
    }
}
