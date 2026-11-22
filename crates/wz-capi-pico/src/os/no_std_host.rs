// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the library links in `std`'s place on a host when it is built without it (`os-posix` on a
//! POSIX host, `os-windows` on Windows): the global allocator, the C library the platform exports
//! forward to, and the panic handler, which aborts the process.
//!
//! On a POSIX host the heap is the process's own `malloc`, the one zenoh-pico allocates from and
//! the one `z_malloc` hands a program (`os::malloc`), so the library adds no allocator of its own
//! to the process. A block whose alignment `malloc` does not promise is taken with
//! `posix_memalign`, whose blocks `free` releases; which call a block came from is read again
//! from its layout when it is released, the rule the standard library's own allocator over the C
//! library keeps.
//!
//! On Windows the heap is the process heap (`GetProcessHeap`), taken with `HeapAlloc` as the
//! standard library's own allocator takes it there, so the library's memory is the system's and
//! no call of the C runtime. The C runtime's `malloc`, which `z_malloc` hands a program as
//! zenoh-pico's Windows backend does, allocates from the same heap. A block whose alignment
//! `HeapAlloc` does not promise is taken larger and aligned inside it, with the address
//! `HeapAlloc` gave kept in the word before the block, from which it is released.
//!
//! A panic ends the process, as a failed assertion in zenoh-pico does: a library without `std`
//! does not unwind (docs/c-abi-engine-and-memory.md, section 3), and what is left to panic is a
//! defect, since memory and the wire are refused by code. So the personality routine the
//! toolchain's prebuilt `core` names on a POSIX host is answered here too, and it aborts.

/// The C library's heap, the global allocator of a POSIX host's library.
#[cfg(unix)]
mod c_heap {
    use core::alloc::{GlobalAlloc, Layout};
    use core::ffi::c_void;

    /// The alignment every block `malloc` returns has: two words on a 64-bit host, one on a 32-bit
    /// one (glibc's `MALLOC_ALIGNMENT` is at least this).
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
    // released by the call that matches the one that took it (`malloc_fits` reads the same answer
    // from the same layout at both ends).
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

        unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
            // `posix_memalign`'s blocks are `free`'s too, so either kind is released alike.
            libc::free(ptr.cast());
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
    unsafe fn aligned_alloc(layout: &Layout) -> *mut u8 {
        let align = layout.align().max(core::mem::size_of::<usize>());
        let mut block: *mut c_void = core::ptr::null_mut();
        if libc::posix_memalign(&mut block, align, layout.size()) != 0 {
            return core::ptr::null_mut();
        }
        block.cast()
    }
}

/// The process heap, the global allocator of the library on Windows.
#[cfg(windows)]
mod process_heap {
    use core::alloc::{GlobalAlloc, Layout};
    use core::ffi::c_void;

    use windows_sys::Win32::System::Memory::{
        GetProcessHeap, HeapAlloc, HeapFree, HeapReAlloc, HEAP_FLAGS, HEAP_NONE, HEAP_ZERO_MEMORY,
    };

    /// The alignment every block `HeapAlloc` returns has (`MEMORY_ALLOCATION_ALIGNMENT`): sixteen
    /// bytes on a 64-bit Windows, eight on a 32-bit one.
    const HEAP_ALIGN: usize = if cfg!(target_pointer_width = "64") {
        16
    } else {
        8
    };

    /// Whether `HeapAlloc` alone gives a block of `layout`. Its alignment holds for a block of any
    /// size, so the size does not enter, as it does for `malloc`.
    fn heap_fits(layout: &Layout) -> bool {
        layout.align() <= HEAP_ALIGN
    }

    /// The process heap.
    pub(crate) struct ProcessHeap;

    impl ProcessHeap {
        /// A block of `layout` with `flags` (`HEAP_ZERO_MEMORY` for a zeroed one). Null when the
        /// heap has none.
        ///
        /// # Safety
        /// `layout` has a size other than zero.
        unsafe fn take(layout: &Layout, flags: HEAP_FLAGS) -> *mut u8 {
            let heap = GetProcessHeap();
            if heap.is_null() {
                return core::ptr::null_mut();
            }
            if heap_fits(layout) {
                return HeapAlloc(heap, flags, layout.size()).cast();
            }
            // Room for the block at any of the offsets its alignment allows, one word at least.
            let Some(total) = layout.size().checked_add(layout.align()) else {
                return core::ptr::null_mut();
            };
            let base = HeapAlloc(heap, flags, total).cast::<u8>();
            if base.is_null() {
                return base;
            }
            // `base` is aligned to `HEAP_ALIGN`, below the layout's alignment and at least a word,
            // so the offset is between a word and the alignment: the block ends within `total`
            // and the word before it is `base`'s own.
            let offset = layout.align() - (base as usize & (layout.align() - 1));
            let block = base.add(offset);
            block.cast::<*mut u8>().sub(1).write(base);
            block
        }

        /// The address `HeapAlloc` gave for the block of `layout` at `block`.
        ///
        /// # Safety
        /// `block` is a block `take` gave for `layout`.
        unsafe fn base_of(block: *mut u8, layout: &Layout) -> *mut c_void {
            if heap_fits(layout) {
                block.cast()
            } else {
                block.cast::<*mut u8>().sub(1).read().cast()
            }
        }
    }

    // SAFETY: every block is the process heap's, of at least the layout's size and alignment, and
    // is released from the address `HeapAlloc` gave (`heap_fits` reads the same answer from the
    // same layout at both ends).
    unsafe impl GlobalAlloc for ProcessHeap {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            Self::take(&layout, HEAP_NONE)
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            Self::take(&layout, HEAP_ZERO_MEMORY)
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            HeapFree(GetProcessHeap(), HEAP_NONE, Self::base_of(ptr, &layout));
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            if heap_fits(&layout) {
                return HeapReAlloc(GetProcessHeap(), HEAP_NONE, ptr.cast::<c_void>(), new_size)
                    .cast();
            }
            let block = self.alloc(Layout::from_size_align_unchecked(new_size, layout.align()));
            if !block.is_null() {
                core::ptr::copy_nonoverlapping(ptr, block, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
            block
        }
    }
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
// Windows: the C runtime, which the platform exports forward to as zenoh-pico's Windows backend
// does (`z_malloc` is its `malloc`), and which the compiler's own code calls on an MSVC target
// (`memcpy` and its kin, the stack probe, a 32-bit build's 64-bit division) and the DLL is entered
// through (`_DllMainCRTStartup`): the runtime DLL's (`msvcrt`) or the static runtime (`libcmt`) as
// the target's `crt-static` says, as `std` names it. The runtime defines `_fltused` and the frame
// handler the prebuilt `core`'s tables name (`__CxxFrameHandler3`), so nothing stands in for
// them here and the link keeps its default libraries (no `/NODEFAULTLIB`). `kernel32` is named
// for the runtime's own startup code; the system calls of this crate and its dependencies name
// their DLLs themselves (`windows-sys`'s `raw-dylib` imports).
#[cfg(all(
    feature = "os-windows",
    not(feature = "std"),
    target_env = "msvc",
    not(target_feature = "crt-static")
))]
#[link(name = "msvcrt")]
#[link(name = "kernel32")]
extern "C" {}
#[cfg(all(
    feature = "os-windows",
    not(feature = "std"),
    target_env = "msvc",
    target_feature = "crt-static"
))]
#[link(name = "libcmt")]
#[link(name = "kernel32")]
extern "C" {}

// The library's own memory, in a build that has no `std` to give it. A test build links `std`,
// whose allocator and panic handler are the test's.
#[cfg(all(feature = "os-posix", not(feature = "std"), not(test), unix))]
#[global_allocator]
static HEAP: c_heap::CHeap = c_heap::CHeap;
#[cfg(all(feature = "os-windows", not(feature = "std"), not(test), windows))]
#[global_allocator]
static HEAP: process_heap::ProcessHeap = process_heap::ProcessHeap;

#[cfg(all(
    any(feature = "os-posix", feature = "os-windows"),
    not(feature = "std"),
    not(test)
))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: ends the process; nothing returns.
    unsafe { libc::abort() }
}

// The toolchain's `core` and `alloc` are prebuilt to unwind, and on a POSIX host their unwind
// tables name the personality routine `std`'s unwinder defines (`DW.ref.rust_eh_personality`);
// linking the library as one program does not take that reference out (measured: an undefined
// `rust_eh_personality` in the fat-LTO build, which no C program linking the library resolves).
// Nothing unwinds here: the library is built `panic = "abort"` and its panic handler aborts, so no
// unwind ever starts and the routine is never called. It is the name answered, and if it were ever
// reached, the answer is the panic handler's. Rebuilding `core` without unwinding (`-Z build-std`
// with `panic_abort`) would take the reference out at its source, but needs a nightly toolchain,
// and the pin is the stable one (`rust-toolchain.toml`). An MSVC build's tables name the C
// runtime's `__CxxFrameHandler3` and not this routine, so `os-windows` defines none. The same
// answer as the host program glue's (`wz_runtime_posix::posix_image_no_heap!`).
#[cfg(all(feature = "os-posix", not(feature = "std"), not(test), unix))]
#[no_mangle]
extern "C" fn rust_eh_personality() -> ! {
    // SAFETY: ends the process; nothing returns.
    unsafe { libc::abort() }
}

// The host's allocator, held to the layouts a library asks for: on a POSIX host the C library's
// heap, on Windows the process heap.
#[cfg(test)]
mod tests {
    use core::alloc::{GlobalAlloc, Layout};

    #[cfg(unix)]
    use super::c_heap::CHeap as Heap;
    #[cfg(windows)]
    use super::process_heap::ProcessHeap as Heap;

    /// The layouts a library asks for: below, at and above the heap's own alignment (eight or
    /// sixteen), far above it (a page), and blocks smaller than their alignment.
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
    /// matches the one that took it (a mismatch is a crash or a corrupted heap under the heap's own
    /// checks).
    #[test]
    fn every_block_has_its_alignment_and_holds_its_size() {
        let mut taken = 0;
        for layout in layouts() {
            // SAFETY: a layout of a non-zero size; the block is written within it and released
            // with the same layout.
            unsafe {
                let block = Heap.alloc(layout);
                assert!(!block.is_null(), "{layout:?}");
                assert_eq!(block as usize % layout.align(), 0, "{layout:?}");
                core::ptr::write_bytes(block, 0xa5, layout.size());
                assert_eq!(*block.add(layout.size() - 1), 0xa5);
                Heap.dealloc(block, layout);
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
                let block = Heap.alloc_zeroed(layout);
                assert!(!block.is_null(), "{layout:?}");
                assert_eq!(block as usize % layout.align(), 0, "{layout:?}");
                let bytes = core::slice::from_raw_parts(block, layout.size());
                assert!(bytes.iter().all(|&b| b == 0), "{layout:?}");
                Heap.dealloc(block, layout);
            }
        }
    }

    /// A block grown or shrunk keeps what it held up to the smaller size and its alignment, on the
    /// heap's own resize and on the aligned path that copies.
    #[test]
    fn a_resized_block_keeps_its_bytes_and_its_alignment() {
        for layout in layouts() {
            for new_size in [1usize, layout.size() * 3 + 1] {
                // SAFETY: as above; the resized block is released with its new layout.
                unsafe {
                    let block = Heap.alloc(layout);
                    assert!(!block.is_null());
                    for i in 0..layout.size() {
                        *block.add(i) = i as u8;
                    }
                    let grown = Heap.realloc(block, layout, new_size);
                    assert!(!grown.is_null(), "{layout:?} to {new_size}");
                    assert_eq!(
                        grown as usize % layout.align(),
                        0,
                        "{layout:?} to {new_size}"
                    );
                    for i in 0..layout.size().min(new_size) {
                        assert_eq!(*grown.add(i), i as u8, "{layout:?} to {new_size} at {i}");
                    }
                    Heap.dealloc(
                        grown,
                        Layout::from_size_align(new_size, layout.align()).expect("a layout"),
                    );
                }
            }
        }
    }

    /// Many blocks held at once, of an alignment past the heap's own, each released from where it
    /// was taken: a block released from its aligned address rather than the heap's own would
    /// corrupt the heap, which the process's next calls into it report.
    #[test]
    fn over_aligned_blocks_held_together_are_each_released_whole() {
        let layout = Layout::from_size_align(24, 64).expect("a layout");
        let mut blocks = [core::ptr::null_mut::<u8>(); 64];
        // SAFETY: each block is written within its layout and released once with it.
        unsafe {
            for (i, slot) in blocks.iter_mut().enumerate() {
                let block = Heap.alloc(layout);
                assert!(!block.is_null());
                assert_eq!(block as usize % 64, 0);
                core::ptr::write_bytes(block, i as u8, layout.size());
                *slot = block;
            }
            for (i, &block) in blocks.iter().enumerate() {
                let bytes = core::slice::from_raw_parts(block, layout.size());
                assert!(
                    bytes.iter().all(|&b| b == i as u8),
                    "block {i} was written over"
                );
            }
            for &block in &blocks {
                Heap.dealloc(block, layout);
            }
        }
    }
}
