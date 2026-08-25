// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `zephyr-sys` — hand-written FFI to the Zephyr kernel symbols the wz Zephyr
//! cooperative single-task profile calls.
//!
//! UNLIKE `freertos-sys`, which vendors + cross-compiles the FreeRTOS kernel
//! in a `build.rs` (the FreeRTOS deploy is cargo-driven, so cargo must produce
//! the kernel), the **Zephyr build system compiles the kernel** and links the
//! wz Rust static lib into the final image (the Z2 `deploy/` west/cmake build).
//! So this crate is PURE `extern "C"` declarations: no `build.rs`, no vendored
//! source, and crucially NO bindgen — the `__UINTxx_C` bindgen friction that
//! the zephyr-lang-rust path hits simply does not exist here. The symbols are
//! undefined in the rlib and resolve at the Zephyr image link.
//!
//! The declarations target REAL exported Zephyr symbols, never the inline /
//! syscall wrappers (verified by `arm-zephyr-eabi-nm libkernel.a | grep ' T '`):
//! - `sys_clock_tick_get` is the raw tick source. (`k_uptime_get` is a
//!   `static inline`; `k_uptime_ticks` is a `__syscall` whose real symbol is
//!   `z_impl_k_uptime_ticks` — neither is a stable hand-FFI target.)
//! - `k_malloc` / `k_free` are real extern fns. `k_malloc` is only compiled in
//!   when the deploy sets `CONFIG_HEAP_MEM_POOL_SIZE > 0` (the kernel heap).
#![no_std]

use core::ffi::c_void;

extern "C" {
    /// Absolute kernel tick count since boot (monotonic, non-decreasing).
    /// Convert to time with the deploy's `CONFIG_SYS_CLOCK_TICKS_PER_SEC`
    /// (qemu_cortex_m3 default = 100).
    pub fn sys_clock_tick_get() -> i64;

    /// Allocate `size` bytes from the Zephyr kernel heap. Returns null on OOM.
    /// Requires `CONFIG_HEAP_MEM_POOL_SIZE > 0` in the deploy's prj.conf.
    pub fn k_malloc(size: usize) -> *mut c_void;

    /// Free a block previously returned by [`k_malloc`].
    pub fn k_free(ptr: *mut c_void);
}
