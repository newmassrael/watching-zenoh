// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The bare-metal deploy binaries' STACK BUDGET check — paint the stack
//! region, read back how deep the program went, judge it against the budget
//! the linker script declares.
//!
//! ## Why this crate exists (R2776, open-debt item 805)
//!
//! The microbit (nrf51, 16 KB of SRAM) holds `.data`, `.bss` and the stack in
//! one region, and until R2776 nothing declared how much of it the stack
//! could have: cortex-m-rt put the stack at the top of RAM and it grew down
//! toward `.bss` with nothing in between. Measured, the session acceptor's
//! deepest call went 208 bytes past what its layout left above `.bss`, and
//! Layer Q reported PASS anyway, because the bytes it overwrote belonged to
//! lwIP variables nothing on that path read. The push that deepened it by 144
//! more reached `loop_netif` and faulted. The PASS before it was luck, and no
//! instrument could have said so.
//!
//! Two structures replace that, and this crate is the second:
//!
//! 1. Each microbit linker script DECLARES the stack as its own region at the
//!    BOTTOM of SRAM, below `.data`/`.bss`. Past its budget the stack leaves
//!    SRAM altogether and faults at the offending push, instead of writing
//!    over variables. A `.bss` that outgrows its share fails at link time.
//! 2. The binary MEASURES its peak against that budget and refuses to report
//!    success without headroom, so the margin is a number every Layer Q run
//!    prints rather than something found out at the next overflow.
//!
//! ## How the peak is measured
//!
//! Before the workload runs, every word from the bottom of the region up to a
//! little below the current stack pointer is PAINTED with [`PAINT`]. After it,
//! the lowest word that no longer holds the paint is the deepest the stack
//! reached, and the peak is the distance from there to the top. A word the
//! program happened to write with the paint value itself would under-read by
//! at most the words below it that it also left painted, which is why the
//! value is an odd pattern rather than zero.
//!
//! The painting stops [`PAINT_GUARD_BYTES`] below the caller's stack pointer
//! so it can never paint over the frame that is painting.
//!
//! ## Why the stack pointer comes from the caller
//!
//! Reading it here would need `cortex-m`, and that would make this crate a
//! no_std island the host workspace lanes cannot build. Taking it as an
//! argument keeps the crate dependency-free and its painting and reading
//! unit-tested on the host over an ordinary buffer; only `linker_region` is
//! bare-metal, because only there do cortex-m-rt's symbols exist (and so it
//! is named here as code rather than linked: a host doc build has no such
//! item to link to).

#![no_std]

/// The word unused stack is painted with. Odd and not a small integer, so a
/// real stack slot is unlikely to hold it by accident.
pub const PAINT: u32 = 0xCCCC_CCCC;

/// How far below the caller's stack pointer painting stops — room for the
/// painting call's own frame, which sits below the caller's.
pub const PAINT_GUARD_BYTES: usize = 256;

/// The headroom a binary must keep between its measured peak and its
/// budget. 256 bytes is the tolerance Layer Q's footprint gate already uses
/// for text and data (`scripts/check-footprint.sh`), so the stack is held to
/// the same resolution as the rest of the image rather than to a new number.
pub const MARGIN_BYTES: usize = 256;

/// One stack region, `[bottom, top)`: the stack starts at `top` and grows
/// down toward `bottom`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackRegion {
    bottom: usize,
    top: usize,
}

/// What a run measured against its budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackVerdict {
    /// The deepest the stack went, in bytes below the top.
    pub peak: usize,
    /// The region's size in bytes — what the linker script declared.
    pub budget: usize,
}

impl StackVerdict {
    /// Whether the peak leaves at least [`MARGIN_BYTES`] of the budget unused.
    pub fn fits(&self) -> bool {
        self.peak + MARGIN_BYTES <= self.budget
    }
}

impl StackRegion {
    /// The region `[bottom, top)`.
    ///
    /// # Safety
    ///
    /// `bottom` and `top` must be word-aligned, `bottom <= top`, and every
    /// word between them must be memory this program may read and write for
    /// as long as the region is used.
    pub const unsafe fn new(bottom: usize, top: usize) -> Self {
        Self { bottom, top }
    }

    /// The region's size in bytes.
    pub fn budget(&self) -> usize {
        self.top - self.bottom
    }

    /// Paint every word from the bottom of the region up to
    /// [`PAINT_GUARD_BYTES`] below `sp`, the caller's current stack pointer.
    /// Nothing is painted when `sp` is not inside the region or sits closer
    /// to the bottom than the guard.
    ///
    /// # Safety
    ///
    /// The words below `sp - PAINT_GUARD_BYTES` must not be in use: call this
    /// before the workload, from the frame that will run it.
    pub unsafe fn paint(&self, sp: usize) {
        if sp <= self.bottom || sp > self.top {
            return;
        }
        let end = sp.saturating_sub(PAINT_GUARD_BYTES) & !3;
        let mut at = self.bottom;
        while at < end {
            // SAFETY: `at` is word-aligned and inside the region, which the
            // caller of `new` vouched for, and below the live stack, which the
            // caller of this function vouched for.
            unsafe { core::ptr::write_volatile(at as *mut u32, PAINT) };
            at += 4;
        }
    }

    /// The deepest the stack has gone since [`Self::paint`]: the distance from
    /// the top to the lowest word that no longer holds [`PAINT`]. The whole
    /// region when even the bottom word was overwritten.
    pub fn peak(&self) -> usize {
        let mut at = self.bottom;
        while at < self.top {
            // SAFETY: word-aligned and inside the region (see `new`).
            if unsafe { core::ptr::read_volatile(at as *const u32) } != PAINT {
                return self.top - at;
            }
            at += 4;
        }
        0
    }

    /// The peak and the budget together.
    pub fn verdict(&self) -> StackVerdict {
        StackVerdict {
            peak: self.peak(),
            budget: self.budget(),
        }
    }
}

/// This program's stack region as cortex-m-rt's linker script lays it out:
/// `_stack_end` to `_stack_start`. A deploy that declares its stack as its
/// own region sets both; one that does not gets cortex-m-rt's defaults, the
/// end of `.uninit` to the end of RAM, which is still exactly the room the
/// stack has.
#[cfg(target_os = "none")]
pub fn linker_region() -> StackRegion {
    unsafe extern "C" {
        static _stack_start: u32;
        static _stack_end: u32;
    }
    // SAFETY: the linker places both symbols, word-aligned (cortex-m-rt
    // asserts `_stack_start % 8 == 0` and `_stack_end % 4 == 0`) with
    // `_stack_end <= _stack_start`, and the words between them are this
    // program's stack.
    unsafe {
        StackRegion::new(
            core::ptr::addr_of!(_stack_end) as usize,
            core::ptr::addr_of!(_stack_start) as usize,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Words in the fake stack: four times the guard, so a paint from the
    /// top leaves three quarters of it painted. A stack no larger than the
    /// guard would paint nothing and every assertion below would be vacuous.
    const WORDS: usize = 4 * PAINT_GUARD_BYTES / 4;

    /// A fake stack of [`WORDS`] zeroed words, and the region over it. Every
    /// later access goes through the region's address, as the real stack's
    /// does, never through the buffer's own binding: the program under
    /// measurement writes its stack by address too, and mixing the two
    /// would let the compiler treat a word as unread.
    fn region(buf: &mut [u32; WORDS]) -> StackRegion {
        let bottom = buf.as_mut_ptr() as usize;
        // SAFETY: the buffer is word-aligned and outlives the region's use.
        unsafe { StackRegion::new(bottom, bottom + WORDS * 4) }
    }

    /// Word `i` of the region, read by address.
    fn peek(r: &StackRegion, i: usize) -> u32 {
        // SAFETY: inside the region (see `region`).
        unsafe { core::ptr::read_volatile((r.bottom + i * 4) as *const u32) }
    }

    /// Word `i` of the region, written by address — the workload's stack use.
    fn poke(r: &StackRegion, i: usize, value: u32) {
        // SAFETY: inside the region (see `region`).
        unsafe { core::ptr::write_volatile((r.bottom + i * 4) as *mut u32, value) }
    }

    /// The whole claim in one run: paint, "use" the top of the region, read
    /// back exactly that depth.
    #[test]
    fn the_peak_is_the_deepest_word_written() {
        let mut buf = [0u32; WORDS];
        let r = region(&mut buf);
        // The caller's stack pointer is at the top: everything below the
        // guard is painted.
        unsafe { r.paint(r.top) };
        let painted = (r.top - PAINT_GUARD_BYTES - r.bottom) / 4;
        assert!(
            (0..painted).all(|i| peek(&r, i) == PAINT),
            "ANTI-VACUITY: the words under the guard must be painted"
        );
        assert_eq!(
            r.peak(),
            PAINT_GUARD_BYTES,
            "nothing ran yet: the peak is the guard"
        );
        // The workload goes 20 words deeper than the guard.
        let deepest = painted - 20;
        poke(&r, deepest, 0x1234_5678);
        assert_eq!(r.peak(), r.top - (r.bottom + deepest * 4));
    }

    /// A slot the workload wrote and then left holding something else still
    /// counts — the peak is the lowest SCRUBBED word, not the lowest live one.
    #[test]
    fn a_scrubbed_word_counts_whatever_it_holds_now() {
        let mut buf = [0u32; WORDS];
        let r = region(&mut buf);
        unsafe { r.paint(r.top) };
        poke(&r, 3, 0);
        assert_eq!(r.peak(), r.top - (r.bottom + 12));
    }

    /// Overwriting the bottom word means the whole budget was used.
    #[test]
    fn an_overwritten_bottom_is_the_whole_budget() {
        let mut buf = [0u32; WORDS];
        let r = region(&mut buf);
        unsafe { r.paint(r.top) };
        poke(&r, 0, 1);
        assert_eq!(r.peak(), r.budget());
        assert!(!r.verdict().fits());
    }

    /// Painting never reaches the guard below the caller's stack pointer, and
    /// a stack pointer outside the region paints nothing at all.
    #[test]
    fn painting_stays_below_the_guard_and_inside_the_region() {
        let mut buf = [0u32; WORDS];
        let r = region(&mut buf);
        let sp = r.bottom + 3 * WORDS;
        unsafe { r.paint(sp) };
        let end_word = (sp - PAINT_GUARD_BYTES - r.bottom) / 4;
        assert!(
            end_word > 0 && (0..end_word).all(|i| peek(&r, i) == PAINT),
            "ANTI-VACUITY: something below the guard must be painted"
        );
        assert!(
            (end_word..WORDS).all(|i| peek(&r, i) == 0),
            "the guard and the live frame above it must be untouched"
        );

        let mut other = [0u32; WORDS];
        let r2 = region(&mut other);
        unsafe { r2.paint(r2.top + 4) };
        assert!(
            (0..WORDS).all(|i| peek(&r2, i) == 0),
            "a foreign sp paints nothing"
        );
    }

    /// The margin is a strict floor: exactly `MARGIN_BYTES` of headroom fits,
    /// one word less does not.
    #[test]
    fn the_margin_is_a_floor() {
        let budget = 4096;
        let at_margin = StackVerdict {
            peak: budget - MARGIN_BYTES,
            budget,
        };
        assert!(at_margin.fits());
        let past_margin = StackVerdict {
            peak: budget - MARGIN_BYTES + 4,
            budget,
        };
        assert!(!past_margin.fits());
    }
}
