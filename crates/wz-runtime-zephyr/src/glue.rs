// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The image glue every wz Zephyr firmware needs and none should retype.
//!
//! A Zephyr image is the kernel plus one Rust staticlib, and the staticlib has
//! to bring four things the kernel cannot supply for it: a global allocator over
//! the kernel heap, a `critical_section` implementation over the kernel's IRQ
//! lock, a panic handler, and a way to print. They are identical in every
//! firmware (the acceptor e2e, the admin node), so they live here once and a
//! firmware writes [`zephyr_image!`](crate::zephyr_image) in its crate root.
//!
//! The functions are the Rust side of the C seams in
//! `deploy/zephyr-common/wz_board_hooks.c`; `printk` is variadic and `k_msleep` /
//! `irq_lock` are `static inline`, so neither can be called from Rust directly.

use alloc::string::String;
use core::ffi::{c_char, CStr};

extern "C" {
    /// `printk("%s\n", msg)`, wrapped C-side so the FFI target is non-variadic.
    fn wz_log(msg: *const c_char);
    /// `k_msleep(ms)`, wrapped C-side because it is `static inline`.
    fn wz_yield_ms(ms: i32);
    /// Wait about `us` microseconds: `k_busy_wait` for a short wait, `k_msleep`
    /// once the wait is long enough for the thread to give the CPU away.
    fn wz_delay_us(us: u32);
    /// `irq_lock()`: the prior IRQ key, wrapped C-side (the macro expands to the
    /// inline `arch_irq_lock()`).
    fn wz_irq_lock() -> u32;
    /// `irq_unlock(key)`: restores the IRQ state `wz_irq_lock` saved.
    fn wz_irq_unlock(key: u32);
    /// The calling thread's stack: write its size and its never-touched bytes
    /// through the two pointers and return 0, or return nonzero when the kernel's
    /// configuration does not measure stacks (`k_thread_stack_space_get` needs
    /// `CONFIG_INIT_STACKS` and `CONFIG_THREAD_STACK_INFO`).
    fn wz_stack_usage(size: *mut u32, unused: *mut u32) -> i32;
}

/// Print a static C string on the board's console.
#[inline]
pub fn log(msg: &CStr) {
    // SAFETY: `msg` is a valid nul-terminated C string that outlives the call;
    // `wz_log` only reads it (printk %s).
    unsafe { wz_log(msg.as_ptr()) };
}

/// Print a formatted line on the board's console.
pub fn log_line(line: String) {
    let mut bytes = line.into_bytes();
    bytes.push(0);
    // SAFETY: `bytes` is nul-terminated and outlives the call; `wz_log` only
    // reads it (printk %s).
    unsafe { wz_log(bytes.as_ptr() as *const c_char) };
}

/// Sleep this thread for `ms` milliseconds, which is how the net stack's own
/// threads get the CPU between the cooperative loop's iterations.
#[inline]
pub fn yield_ms(ms: i32) {
    // SAFETY: the board's `k_msleep` seam; blocks this thread, no preconditions.
    unsafe { wz_yield_ms(ms) };
}

/// Wait about `us` microseconds. A driver polling a peripheral that answers in
/// microseconds (a PHY's management port) needs the short waits exact and the long
/// ones to cost no CPU, which is what the board's hook does with the two.
#[inline]
pub fn delay_us(us: u32) {
    // SAFETY: the board's wait seam; blocks this thread, no preconditions.
    unsafe { wz_delay_us(us) };
}

/// Take the kernel's IRQ lock and return the key that restores the state it
/// found, which makes nesting correct.
#[inline]
pub fn irq_lock() -> u32 {
    // SAFETY: `irq_lock` has no preconditions; the key is returned for the
    // matching [`irq_unlock`].
    unsafe { wz_irq_lock() }
}

/// Restore the IRQ state a matching [`irq_lock`] saved.
///
/// # Safety
/// `key` must be the value the matching [`irq_lock`] returned, and each key must
/// be released once, innermost first.
#[inline]
pub unsafe fn irq_unlock(key: u32) {
    // SAFETY: the caller holds the contract above.
    unsafe { wz_irq_unlock(key) };
}

/// The calling thread's stack as the kernel measures it, or `None` when the
/// kernel's configuration does not (see `wz_stack_usage`). The node runs on one thread,
/// so the thread that calls this is the one whose stack is the node's budget.
///
/// Walks the stack looking for the paint the kernel laid down at creation, so it
/// costs time in proportion to the stack's size; ask for it every few hundred
/// milliseconds and not every pass of a loop.
pub fn stack_usage() -> Option<crate::stack::StackUsage> {
    let (mut size, mut unused) = (0u32, 0u32);
    // SAFETY: both pointers are to live locals, and the hook writes one `u32`
    // through each and only reads the calling thread's own descriptor.
    let rc = unsafe { wz_stack_usage(&mut size, &mut unused) };
    (rc == 0).then_some(crate::stack::StackUsage { size, unused })
}

/// What a panic does on this profile: log it, then halt with the CPU yielded
/// rather than pinned. A CI lane's verdict is a console sentinel under a
/// timeout, so a halted image that never prints its sentinel reads as a failure,
/// and a deployed board is left idle for a watchdog instead of spinning.
pub fn halt_after_panic() -> ! {
    log(c"wz: PANIC");
    loop {
        yield_ms(100);
    }
}
