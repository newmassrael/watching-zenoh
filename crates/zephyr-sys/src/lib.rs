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
//! - [`socket`] holds the network ones (R2916).
#![no_std]

/// Zephyr's BSD sockets, through its POSIX layer — the route zenoh-pico's
/// Zephyr port takes (`vendor/zenoh-pico/src/system/zephyr/network.c`).
///
/// The same rule as the kernel symbols above: these are REAL functions, not
/// the `zsock_*` names, which are `__syscall` wrappers whose link symbol
/// depends on `CONFIG_USERSPACE`. `socket` / `bind` / `sendto` / `recvfrom`
/// are defined in `subsys/portability/posix/options/net.c`
/// (`CONFIG_POSIX_NETWORKING`); `poll` / `close` in `device_io.c`
/// (`CONFIG_POSIX_DEVICE_IO`).
///
/// ⚠ The CONSTANTS are Zephyr's, not Linux's: `AF_INET` is 1 there
/// (`NET_PF_INET`), and a value copied from a host `libc` would open the
/// wrong family.
pub mod socket {
    use core::ffi::{c_int, c_short, c_void};

    /// `NET_AF_INET` (`include/zephyr/net/net_ip.h`).
    pub const AF_INET: c_int = 1;
    /// `NET_SOCK_DGRAM` — the second value of `enum net_sock_type`, which
    /// starts at `NET_SOCK_STREAM = 1`.
    pub const SOCK_DGRAM: c_int = 2;
    /// `NET_IPPROTO_UDP`.
    pub const IPPROTO_UDP: c_int = 17;
    /// `ZSOCK_POLLIN` (`include/zephyr/net/socket.h`).
    pub const POLLIN: c_short = 1;

    /// `struct net_sockaddr_in`: family, port (network order), IPv4 address
    /// (network order). 8 bytes, 2-aligned.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct SockaddrIn {
        pub sin_family: u16,
        pub sin_port: u16,
        pub sin_addr: u32,
    }

    /// `struct zsock_pollfd`.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    pub struct PollFd {
        pub fd: c_int,
        pub events: c_short,
        pub revents: c_short,
    }

    /// `socklen_t` (`uint32_t`, `include/zephyr/posix/sys/socket.h`).
    pub type SockLen = u32;

    extern "C" {
        pub fn socket(family: c_int, kind: c_int, proto: c_int) -> c_int;
        pub fn bind(sock: c_int, addr: *const SockaddrIn, addrlen: SockLen) -> c_int;
        pub fn sendto(
            sock: c_int,
            buf: *const c_void,
            len: usize,
            flags: c_int,
            dest: *const SockaddrIn,
            addrlen: SockLen,
        ) -> isize;
        pub fn recvfrom(
            sock: c_int,
            buf: *mut c_void,
            max_len: usize,
            flags: c_int,
            src: *mut SockaddrIn,
            addrlen: *mut SockLen,
        ) -> isize;
        pub fn poll(fds: *mut PollFd, nfds: c_int, timeout_ms: c_int) -> c_int;
        pub fn close(fd: c_int) -> c_int;
    }
}

use core::ffi::c_void;

extern "C" {
    /// Absolute kernel tick count since boot (monotonic, non-decreasing).
    /// Convert to time with the deploy's `CONFIG_SYS_CLOCK_TICKS_PER_SEC`
    /// (the reference deploy pins 100).
    pub fn sys_clock_tick_get() -> i64;

    /// Allocate `size` bytes from the Zephyr kernel heap. Returns null on OOM.
    /// Requires `CONFIG_HEAP_MEM_POOL_SIZE > 0` in the deploy's prj.conf.
    pub fn k_malloc(size: usize) -> *mut c_void;

    /// Free a block previously returned by [`k_malloc`].
    pub fn k_free(ptr: *mut c_void);
}
