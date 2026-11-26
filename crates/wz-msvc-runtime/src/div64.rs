// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The 64-bit division helpers of the 32-bit MSVC target: `_aulldiv`, `_aullrem`, `_alldiv` and
//! `_allrem`, which the compiler calls for every `u64` and `i64` division and remainder.
//!
//! Their convention is `stdcall`'s: the dividend and the divisor on the stack, the helper pops
//! both (`ret 16`), the result in `edx:eax`. So each is a `stdcall` function here, and its C name
//! is a label that jumps to it with the caller's stack untouched (`crate::symbols`).
//!
//! Nothing below divides a 64-bit value with the operator, which would call the helper being
//! defined: a divisor below 2^32 takes two hardware divisions, a larger one, whose quotient fits in
//! 32 bits, the shift-and-subtract over the quotient's bits. A divisor of zero faults in the
//! hardware division, as the C runtime's helper does; the compiler checks for one before it calls.

use core::arch::asm;

/// `(hi:lo) / d` and its remainder, by the hardware division. `d` is not zero and `hi < d`, so
/// the quotient fits in 32 bits.
#[inline(always)]
fn div_64_32(hi: u32, lo: u32, d: u32) -> (u32, u32) {
    let q: u32;
    let r: u32;
    // SAFETY: `hi < d` and `d != 0` (the callers' arguments), so `div` neither faults nor
    // overflows; it reads and writes registers only.
    unsafe {
        asm!("div {d}", d = in(reg) d, inout("eax") lo => q, inout("edx") hi => r,
             options(pure, nomem, nostack));
    }
    (q, r)
}

/// The quotient and the remainder of `n / d`.
#[inline(never)]
pub fn udivmod(n: u64, d: u64) -> (u64, u64) {
    if d >> 32 == 0 {
        let d32 = d as u32;
        let (qh, rh) = div_64_32(0, (n >> 32) as u32, d32);
        let (ql, r) = div_64_32(rh, n as u32, d32);
        ((u64::from(qh) << 32) | u64::from(ql), u64::from(r))
    } else {
        let mut q: u64 = 0;
        let mut r: u64 = n;
        // The divisor shifted up to the dividend's top bit: it cannot shift out of the word.
        let shift = d.leading_zeros() - n.leading_zeros().min(d.leading_zeros());
        let mut i = shift as i32;
        while i >= 0 {
            let ds = d << i;
            if r >= ds {
                r -= ds;
                q |= 1u64 << i;
            }
            i -= 1;
        }
        (q, r)
    }
}

/// `_aulldiv`: the unsigned quotient.
pub extern "stdcall" fn aulldiv(n: u64, d: u64) -> u64 {
    udivmod(n, d).0
}

/// `_aullrem`: the unsigned remainder.
pub extern "stdcall" fn aullrem(n: u64, d: u64) -> u64 {
    udivmod(n, d).1
}

/// `_alldiv`: the signed quotient, rounded toward zero; `i64::MIN / -1` wraps, as the C runtime's.
pub extern "stdcall" fn alldiv(n: i64, d: i64) -> i64 {
    let q = udivmod(n.unsigned_abs(), d.unsigned_abs()).0 as i64;
    if (n < 0) != (d < 0) {
        q.wrapping_neg()
    } else {
        q
    }
}

/// `_allrem`: the signed remainder, of the dividend's sign.
pub extern "stdcall" fn allrem(n: i64, d: i64) -> i64 {
    let r = udivmod(n.unsigned_abs(), d.unsigned_abs()).1 as i64;
    if n < 0 {
        r.wrapping_neg()
    } else {
        r
    }
}
