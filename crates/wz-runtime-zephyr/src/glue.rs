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
    /// The core's clock in hertz as the chip's registers say it is, or 0 when the
    /// board cannot know (an emulator, a board with no hook for it).
    fn wz_core_clock_hz() -> u32;
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

/// The longest console line [`log_args`] prints, nul included. A longer one is cut,
/// which a console line can afford and a node with no allocator cannot do without.
pub const LOG_LINE_BYTES: usize = 192;

/// A line of formatted text in a fixed buffer, cut at the end of it.
struct LineBuf {
    bytes: [u8; LOG_LINE_BYTES],
    len: usize,
}

impl core::fmt::Write for LineBuf {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        // One byte stays for the terminating nul. Text that does not fit is cut at a
        // character boundary and the rest is dropped; the formatting goes on.
        let room = LOG_LINE_BYTES - 1 - self.len;
        let mut take = text.len().min(room);
        while !text.is_char_boundary(take) {
            take -= 1;
        }
        self.bytes[self.len..self.len + take].copy_from_slice(&text.as_bytes()[..take]);
        self.len += take;
        Ok(())
    }
}

/// Format `args` into a nul-terminated line of at most [`LOG_LINE_BYTES`] bytes.
fn render_line(args: core::fmt::Arguments<'_>) -> LineBuf {
    let mut line = LineBuf {
        bytes: [0; LOG_LINE_BYTES],
        len: 0,
    };
    // `LineBuf::write_str` never fails, so neither does the formatting.
    let _ = core::fmt::write(&mut line, args);
    line
}

/// Print a formatted line on the board's console without allocating: `log_line` for a
/// firmware that has no heap to build the `String` in, as
/// `log_args(format_args!("a {}", 1))`. A line longer than [`LOG_LINE_BYTES`] is cut.
pub fn log_args(args: core::fmt::Arguments<'_>) {
    let line = render_line(args);
    // SAFETY: the buffer is zero-filled past `len` and `len` leaves one byte, so it is
    // nul-terminated; it outlives the call and `wz_log` only reads it (printk %s).
    unsafe { wz_log(line.bytes.as_ptr() as *const c_char) };
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

/// The clock the core runs at, in hertz, read from the chip's registers by the
/// board's hook, or 0 when the board cannot know. It is the board's REAL clock and
/// not the one the image was built for (that is `CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC`,
/// which the kernel assumes without checking): [`crate::core_clock`] compares the
/// two.
pub fn core_clock_hz() -> u32 {
    // SAFETY: the board's hook takes no argument and only reads clock registers.
    unsafe { wz_core_clock_hz() }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn text(line: &LineBuf) -> &str {
        core::str::from_utf8(&line.bytes[..line.len]).expect("the line is text")
    }

    #[test]
    fn a_formatted_line_is_what_format_gives_and_is_nul_terminated() {
        let line = render_line(format_args!(
            "zephyr-admin-node: {} session(s) {:#06x}",
            2, 255
        ));
        assert_eq!(text(&line), "zephyr-admin-node: 2 session(s) 0x00ff");
        assert_eq!(
            line.bytes[line.len], 0,
            "the byte after the text is the nul"
        );
    }

    #[test]
    fn a_line_longer_than_the_buffer_is_cut_at_a_character_and_keeps_its_nul() {
        // 191 bytes of room: ninety-six two-byte characters are 192, so the last cannot
        // fit and the line ends one character earlier, on a boundary.
        let long = "\u{e9}".repeat(96);
        let line = render_line(format_args!("{long}"));
        assert_eq!(line.len, 190, "ninety-five whole characters");
        assert!(text(&line).chars().all(|c| c == '\u{e9}'));
        assert_eq!(line.bytes[line.len], 0, "and the nul is still there");
        assert_eq!(
            line.bytes[LOG_LINE_BYTES - 1],
            0,
            "the last byte is never text"
        );
    }
}
