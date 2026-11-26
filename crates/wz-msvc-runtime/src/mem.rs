// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The memory functions: `memcpy`, `memmove`, `memset`, `memcmp` and `strlen`, in SSE2 and, where
//! the processor and the system state have it, AVX2, chosen once at run time (`cpuid`, `xgetbv`).
//!
//! Up to 128 bytes every load comes before every store, so a short copy is right for any overlap
//! and takes no branch on it. Past that a copy stores to an aligned destination; past a size the
//! string instructions are used, and past 2 MiB an AVX2 copy writes around the caches. Each
//! operation is also given with the level as an argument (`*_at`), which the tests use to hold
//! both paths on one processor.

use core::arch::asm;
#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use core::sync::atomic::{AtomicU8, Ordering};

/// The level of the SSE2 paths, which every processor of these targets has.
pub const SSE2: u8 = 1;
/// The level of the AVX2 paths.
pub const AVX2: u8 = 2;

/// The level detected, 0 before the first call asks.
static LEVEL: AtomicU8 = AtomicU8::new(0);

/// The level this processor and its system give: AVX2 when `cpuid` reports AVX2, AVX and
/// `xsave` enabled by the system (`osxsave`), and the system saves the vector state (`xgetbv`).
#[cold]
fn detect() -> u8 {
    let mut level = SSE2;
    // SAFETY: `cpuid` is on every processor of these targets, and `xgetbv` is executed only when
    // `cpuid` reports `osxsave`, which says the system enabled it.
    unsafe {
        if __cpuid(0).eax >= 7 {
            let leaf1 = __cpuid(1);
            if leaf1.ecx & (1 << 27) != 0 && leaf1.ecx & (1 << 28) != 0 {
                let state: u32;
                asm!("xgetbv", in("ecx") 0u32, out("eax") state, out("edx") _,
                     options(nomem, nostack, preserves_flags));
                if state & 6 == 6 && __cpuid_count(7, 0).ebx & (1 << 5) != 0 {
                    level = AVX2;
                }
            }
        }
    }
    LEVEL.store(level, Ordering::Relaxed);
    level
}

/// The level the exported functions take.
#[inline(always)]
pub fn level() -> u8 {
    match LEVEL.load(Ordering::Relaxed) {
        0 => detect(),
        known => known,
    }
}

// Below this an SSE2 copy or fill is a vector loop, at or above it the string instruction.
const SSE_REP_MIN: usize = 2048;
// Below this an AVX2 copy is a vector loop, then the string instruction up to `NT_MIN`.
const AVX_COPY_LOOP_MAX: usize = 8192;
// At or above this an AVX2 copy writes around the caches.
const NT_MIN: usize = 2 << 20;
// Below this an AVX2 fill is a vector loop, at or above it the string instruction.
const AVX_SET_LOOP_MAX: usize = 65536;

#[inline(always)]
unsafe fn ld(p: *const u8) -> __m128i {
    _mm_loadu_si128(p.cast())
}
#[inline(always)]
unsafe fn st(p: *mut u8, v: __m128i) {
    _mm_storeu_si128(p.cast(), v)
}
#[inline(always)]
unsafe fn sta(p: *mut u8, v: __m128i) {
    _mm_store_si128(p.cast(), v)
}
#[inline(always)]
unsafe fn r64(p: *const u8) -> u64 {
    p.cast::<u64>().read_unaligned()
}
#[inline(always)]
unsafe fn w64(p: *mut u8, v: u64) {
    p.cast::<u64>().write_unaligned(v)
}
#[inline(always)]
unsafe fn r32(p: *const u8) -> u32 {
    p.cast::<u32>().read_unaligned()
}
#[inline(always)]
unsafe fn w32(p: *mut u8, v: u32) {
    p.cast::<u32>().write_unaligned(v)
}
#[inline(always)]
unsafe fn r16(p: *const u8) -> u16 {
    p.cast::<u16>().read_unaligned()
}
#[inline(always)]
unsafe fn w16(p: *mut u8, v: u16) {
    p.cast::<u16>().write_unaligned(v)
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn ly(p: *const u8) -> __m256i {
    _mm256_loadu_si256(p.cast())
}
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn sy(p: *mut u8, v: __m256i) {
    _mm256_storeu_si256(p.cast(), v)
}
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn sya(p: *mut u8, v: __m256i) {
    _mm256_store_si256(p.cast(), v)
}

/// `n <= 128`. Every load precedes every store, so any overlap of `d` and `s` is copied right.
#[inline(always)]
unsafe fn copy_le128(d: *mut u8, s: *const u8, n: usize) {
    if n <= 16 {
        if n >= 8 {
            let (a, b) = (r64(s), r64(s.add(n - 8)));
            w64(d, a);
            w64(d.add(n - 8), b);
        } else if n >= 4 {
            let (a, b) = (r32(s), r32(s.add(n - 4)));
            w32(d, a);
            w32(d.add(n - 4), b);
        } else if n >= 2 {
            let (a, b) = (r16(s), r16(s.add(n - 2)));
            w16(d, a);
            w16(d.add(n - 2), b);
        } else if n == 1 {
            *d = *s;
        }
        return;
    }
    if n <= 32 {
        let (a, b) = (ld(s), ld(s.add(n - 16)));
        st(d, a);
        st(d.add(n - 16), b);
        return;
    }
    if n <= 64 {
        let (a, b) = (ld(s), ld(s.add(16)));
        let (c, e) = (ld(s.add(n - 32)), ld(s.add(n - 16)));
        st(d, a);
        st(d.add(16), b);
        st(d.add(n - 32), c);
        st(d.add(n - 16), e);
        return;
    }
    let (a0, a1, a2, a3) = (ld(s), ld(s.add(16)), ld(s.add(32)), ld(s.add(48)));
    let (b0, b1) = (ld(s.add(n - 64)), ld(s.add(n - 48)));
    let (b2, b3) = (ld(s.add(n - 32)), ld(s.add(n - 16)));
    st(d, a0);
    st(d.add(16), a1);
    st(d.add(32), a2);
    st(d.add(48), a3);
    st(d.add(n - 64), b0);
    st(d.add(n - 48), b1);
    st(d.add(n - 32), b2);
    st(d.add(n - 16), b3);
}

/// `128 < n`, no overlap: 64-byte blocks to an aligned destination, the last 64 bytes overlapped.
#[inline(always)]
unsafe fn copy_mid_sse(d: *mut u8, s: *const u8, n: usize) {
    st(d, ld(s));
    let mut i = (16 - (d as usize & 15)) & 15;
    while n - i > 64 {
        let (a0, a1) = (ld(s.add(i)), ld(s.add(i + 16)));
        let (a2, a3) = (ld(s.add(i + 32)), ld(s.add(i + 48)));
        sta(d.add(i), a0);
        sta(d.add(i + 16), a1);
        sta(d.add(i + 32), a2);
        sta(d.add(i + 48), a3);
        i += 64;
    }
    let (t0, t1) = (ld(s.add(n - 64)), ld(s.add(n - 48)));
    let (t2, t3) = (ld(s.add(n - 32)), ld(s.add(n - 16)));
    st(d.add(n - 64), t0);
    st(d.add(n - 48), t1);
    st(d.add(n - 32), t2);
    st(d.add(n - 16), t3);
}

/// `128 < n`, no overlap: 128-byte blocks of 32-byte vectors to an aligned destination, the last
/// 128 bytes overlapped.
#[target_feature(enable = "avx2")]
unsafe fn copy_mid_avx2(d: *mut u8, s: *const u8, n: usize) {
    sy(d, ly(s));
    let mut i = (32 - (d as usize & 31)) & 31;
    while n - i > 128 {
        let (a0, a1) = (ly(s.add(i)), ly(s.add(i + 32)));
        let (a2, a3) = (ly(s.add(i + 64)), ly(s.add(i + 96)));
        sya(d.add(i), a0);
        sya(d.add(i + 32), a1);
        sya(d.add(i + 64), a2);
        sya(d.add(i + 96), a3);
        i += 128;
    }
    let (t0, t1) = (ly(s.add(n - 128)), ly(s.add(n - 96)));
    let (t2, t3) = (ly(s.add(n - 64)), ly(s.add(n - 32)));
    sy(d.add(n - 128), t0);
    sy(d.add(n - 96), t1);
    sy(d.add(n - 64), t2);
    sy(d.add(n - 32), t3);
}

/// `NT_MIN <= n`, no overlap: stores that go around the caches, fenced before the ordinary tail.
#[target_feature(enable = "avx2")]
unsafe fn copy_nt_avx2(d: *mut u8, s: *const u8, n: usize) {
    sy(d, ly(s));
    let mut i = (32 - (d as usize & 31)) & 31;
    while n - i > 128 {
        let (a0, a1) = (ly(s.add(i)), ly(s.add(i + 32)));
        let (a2, a3) = (ly(s.add(i + 64)), ly(s.add(i + 96)));
        _mm256_stream_si256(d.add(i).cast(), a0);
        _mm256_stream_si256(d.add(i + 32).cast(), a1);
        _mm256_stream_si256(d.add(i + 64).cast(), a2);
        _mm256_stream_si256(d.add(i + 96).cast(), a3);
        i += 128;
    }
    _mm_sfence();
    let (t0, t1) = (ly(s.add(n - 128)), ly(s.add(n - 96)));
    let (t2, t3) = (ly(s.add(n - 64)), ly(s.add(n - 32)));
    sy(d.add(n - 128), t0);
    sy(d.add(n - 96), t1);
    sy(d.add(n - 64), t2);
    sy(d.add(n - 32), t3);
}

/// `rep movsb`: `n` bytes forward.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn rep_movsb(d: *mut u8, s: *const u8, n: usize) {
    asm!("rep movsb", inout("rcx") n => _, inout("rdi") d => _, inout("rsi") s => _,
         options(nostack, preserves_flags));
}

/// `rep movsb`: `n` bytes forward. The compiler keeps `esi` for itself on x86 and takes no operand
/// in it, so the instruction's source register is saved and loaded inside the block.
#[cfg(target_arch = "x86")]
#[inline(always)]
unsafe fn rep_movsb(d: *mut u8, s: *const u8, n: usize) {
    asm!("push esi", "mov esi, {s}", "rep movsb", "pop esi", s = in(reg) s,
         inout("ecx") n => _, inout("edi") d => _, options(preserves_flags));
}

/// `rep stosb`: `n` bytes of `c`.
#[inline(always)]
unsafe fn rep_stosb(d: *mut u8, c: u8, n: usize) {
    #[cfg(target_arch = "x86_64")]
    asm!("rep stosb", inout("rcx") n => _, inout("rdi") d => _, in("al") c,
         options(nostack, preserves_flags));
    #[cfg(target_arch = "x86")]
    asm!("rep stosb", inout("ecx") n => _, inout("edi") d => _, in("al") c,
         options(nostack, preserves_flags));
}

#[inline(always)]
unsafe fn copy_nonoverlapping_at(level: u8, d: *mut u8, s: *const u8, n: usize) {
    if n <= 128 {
        copy_le128(d, s, n);
    } else if level == AVX2 {
        if n < AVX_COPY_LOOP_MAX {
            copy_mid_avx2(d, s, n)
        } else if n < NT_MIN {
            rep_movsb(d, s, n)
        } else {
            copy_nt_avx2(d, s, n)
        }
    } else if n < SSE_REP_MIN {
        copy_mid_sse(d, s, n)
    } else {
        rep_movsb(d, s, n)
    }
}

/// `memcpy` at `level` (`SSE2`, or `AVX2` on a processor `level()` reports it for).
///
/// # Safety
/// `s` is readable and `d` writable for `n` bytes, and the two do not overlap.
pub unsafe fn memcpy_at(level: u8, d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    copy_nonoverlapping_at(level, d, s, n);
    d
}

/// The C runtime's `memcpy`.
///
/// # Safety
/// As `memcpy_at`.
pub unsafe extern "C" fn memcpy(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    memcpy_at(level(), d, s, n)
}

#[target_feature(enable = "avx2")]
unsafe fn move_fwd_avx2(d: *mut u8, s: *const u8, n: usize) {
    let mut i = 0;
    while n - i > 128 {
        let (a0, a1) = (ly(s.add(i)), ly(s.add(i + 32)));
        let (a2, a3) = (ly(s.add(i + 64)), ly(s.add(i + 96)));
        sy(d.add(i), a0);
        sy(d.add(i + 32), a1);
        sy(d.add(i + 64), a2);
        sy(d.add(i + 96), a3);
        i += 128;
    }
    copy_le128(d.add(i), s.add(i), n - i);
}

#[target_feature(enable = "avx2")]
unsafe fn move_bwd_avx2(d: *mut u8, s: *const u8, n: usize) {
    let mut j = n;
    while j > 128 {
        j -= 128;
        let (a0, a1) = (ly(s.add(j)), ly(s.add(j + 32)));
        let (a2, a3) = (ly(s.add(j + 64)), ly(s.add(j + 96)));
        sy(d.add(j), a0);
        sy(d.add(j + 32), a1);
        sy(d.add(j + 64), a2);
        sy(d.add(j + 96), a3);
    }
    copy_le128(d, s, j);
}

#[inline(always)]
unsafe fn move_fwd_sse(d: *mut u8, s: *const u8, n: usize) {
    let mut i = 0;
    while n - i > 128 {
        let (a0, a1) = (ld(s.add(i)), ld(s.add(i + 16)));
        let (a2, a3) = (ld(s.add(i + 32)), ld(s.add(i + 48)));
        st(d.add(i), a0);
        st(d.add(i + 16), a1);
        st(d.add(i + 32), a2);
        st(d.add(i + 48), a3);
        i += 64;
    }
    copy_le128(d.add(i), s.add(i), n - i);
}

#[inline(always)]
unsafe fn move_bwd_sse(d: *mut u8, s: *const u8, n: usize) {
    let mut j = n;
    while j > 128 {
        j -= 64;
        let (a0, a1) = (ld(s.add(j)), ld(s.add(j + 16)));
        let (a2, a3) = (ld(s.add(j + 32)), ld(s.add(j + 48)));
        st(d.add(j), a0);
        st(d.add(j + 16), a1);
        st(d.add(j + 32), a2);
        st(d.add(j + 48), a3);
    }
    copy_le128(d, s, j);
}

/// `memmove` at `level`. A block that the source has not yet been read from is never written
/// first: forward when the destination is below the source, backward when above.
///
/// # Safety
/// `s` is readable and `d` writable for `n` bytes; they may overlap.
pub unsafe fn memmove_at(level: u8, d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    if n <= 128 {
        copy_le128(d, s, n);
        return d;
    }
    let (du, su) = (d as usize, s as usize);
    if du.wrapping_sub(su) >= n && su.wrapping_sub(du) >= n {
        copy_nonoverlapping_at(level, d, s, n);
    } else if du < su {
        if level == AVX2 {
            move_fwd_avx2(d, s, n)
        } else {
            move_fwd_sse(d, s, n)
        }
    } else if du > su {
        if level == AVX2 {
            move_bwd_avx2(d, s, n)
        } else {
            move_bwd_sse(d, s, n)
        }
    }
    d
}

/// The C runtime's `memmove`.
///
/// # Safety
/// As `memmove_at`.
pub unsafe extern "C" fn memmove(d: *mut u8, s: *const u8, n: usize) -> *mut u8 {
    memmove_at(level(), d, s, n)
}

#[target_feature(enable = "avx2")]
unsafe fn set_mid_avx2(d: *mut u8, c: u8, n: usize) {
    let v = _mm256_set1_epi8(c as i8);
    sy(d, v);
    let mut i = (32 - (d as usize & 31)) & 31;
    while n - i > 128 {
        sya(d.add(i), v);
        sya(d.add(i + 32), v);
        sya(d.add(i + 64), v);
        sya(d.add(i + 96), v);
        i += 128;
    }
    sy(d.add(n - 128), v);
    sy(d.add(n - 96), v);
    sy(d.add(n - 64), v);
    sy(d.add(n - 32), v);
}

/// `memset` at `level`: `n` bytes of the low byte of `c`.
///
/// # Safety
/// `d` is writable for `n` bytes.
pub unsafe fn memset_at(level: u8, d: *mut u8, c: i32, n: usize) -> *mut u8 {
    let c = c as u8;
    if n <= 16 {
        let v = u64::from(c).wrapping_mul(0x0101_0101_0101_0101);
        if n >= 8 {
            w64(d, v);
            w64(d.add(n - 8), v);
        } else if n >= 4 {
            w32(d, v as u32);
            w32(d.add(n - 4), v as u32);
        } else if n >= 2 {
            w16(d, v as u16);
            w16(d.add(n - 2), v as u16);
        } else if n == 1 {
            *d = c;
        }
        return d;
    }
    let v = _mm_set1_epi8(c as i8);
    if n <= 32 {
        st(d, v);
        st(d.add(n - 16), v);
        return d;
    }
    if n <= 64 {
        st(d, v);
        st(d.add(16), v);
        st(d.add(n - 32), v);
        st(d.add(n - 16), v);
        return d;
    }
    if n <= 128 {
        st(d, v);
        st(d.add(16), v);
        st(d.add(32), v);
        st(d.add(48), v);
        st(d.add(n - 64), v);
        st(d.add(n - 48), v);
        st(d.add(n - 32), v);
        st(d.add(n - 16), v);
        return d;
    }
    if level == AVX2 {
        if n < AVX_SET_LOOP_MAX {
            set_mid_avx2(d, c, n)
        } else {
            rep_stosb(d, c, n)
        }
        return d;
    }
    if n < SSE_REP_MIN {
        st(d, v);
        let mut i = (16 - (d as usize & 15)) & 15;
        while n - i > 64 {
            sta(d.add(i), v);
            sta(d.add(i + 16), v);
            sta(d.add(i + 32), v);
            sta(d.add(i + 48), v);
            i += 64;
        }
        st(d.add(n - 64), v);
        st(d.add(n - 48), v);
        st(d.add(n - 32), v);
        st(d.add(n - 16), v);
        return d;
    }
    rep_stosb(d, c, n);
    d
}

/// The C runtime's `memset`.
///
/// # Safety
/// As `memset_at`.
pub unsafe extern "C" fn memset(d: *mut u8, c: i32, n: usize) -> *mut u8 {
    memset_at(level(), d, c, n)
}

/// The difference of the first differing bytes of two 16-byte blocks, 0 when equal.
#[inline(always)]
unsafe fn cmp16(a: *const u8, b: *const u8) -> i32 {
    let m = _mm_movemask_epi8(_mm_cmpeq_epi8(ld(a), ld(b))) as u32;
    if m == 0xFFFF {
        return 0;
    }
    let k = (!m).trailing_zeros() as usize;
    i32::from(*a.add(k)) - i32::from(*b.add(k))
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn cmp32(a: *const u8, b: *const u8) -> i32 {
    let m = _mm256_movemask_epi8(_mm256_cmpeq_epi8(ly(a), ly(b))) as u32;
    if m == u32::MAX {
        return 0;
    }
    let k = (!m).trailing_zeros() as usize;
    i32::from(*a.add(k)) - i32::from(*b.add(k))
}

/// The difference of the first differing bytes of two little-endian words, 0 when equal.
#[inline(always)]
fn cmp_word(x: u64, y: u64) -> i32 {
    if x == y {
        return 0;
    }
    let k = (x ^ y).trailing_zeros() / 8;
    i32::from((x >> (k * 8)) as u8) - i32::from((y >> (k * 8)) as u8)
}

/// `n >= 64`: four 16-byte blocks compared per branch.
#[inline(always)]
unsafe fn memcmp_sse2_large(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while n - i >= 64 {
        let e0 = _mm_cmpeq_epi8(ld(a.add(i)), ld(b.add(i)));
        let e1 = _mm_cmpeq_epi8(ld(a.add(i + 16)), ld(b.add(i + 16)));
        let e2 = _mm_cmpeq_epi8(ld(a.add(i + 32)), ld(b.add(i + 32)));
        let e3 = _mm_cmpeq_epi8(ld(a.add(i + 48)), ld(b.add(i + 48)));
        let all = _mm_and_si128(_mm_and_si128(e0, e1), _mm_and_si128(e2, e3));
        if _mm_movemask_epi8(all) as u32 != 0xFFFF {
            let mut k = 0;
            while k < 64 {
                let r = cmp16(a.add(i + k), b.add(i + k));
                if r != 0 {
                    return r;
                }
                k += 16;
            }
        }
        i += 64;
    }
    while n - i > 16 {
        let r = cmp16(a.add(i), b.add(i));
        if r != 0 {
            return r;
        }
        i += 16;
    }
    if i < n {
        return cmp16(a.add(n - 16), b.add(n - 16));
    }
    0
}

/// `n >= 64`: four 32-byte blocks compared per branch.
#[target_feature(enable = "avx2")]
unsafe fn memcmp_avx2_large(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while n - i >= 128 {
        let e0 = _mm256_cmpeq_epi8(ly(a.add(i)), ly(b.add(i)));
        let e1 = _mm256_cmpeq_epi8(ly(a.add(i + 32)), ly(b.add(i + 32)));
        let e2 = _mm256_cmpeq_epi8(ly(a.add(i + 64)), ly(b.add(i + 64)));
        let e3 = _mm256_cmpeq_epi8(ly(a.add(i + 96)), ly(b.add(i + 96)));
        let all = _mm256_and_si256(_mm256_and_si256(e0, e1), _mm256_and_si256(e2, e3));
        if _mm256_movemask_epi8(all) as u32 != u32::MAX {
            let mut k = 0;
            while k < 128 {
                let r = cmp32(a.add(i + k), b.add(i + k));
                if r != 0 {
                    return r;
                }
                k += 32;
            }
        }
        i += 128;
    }
    while n - i > 32 {
        let r = cmp32(a.add(i), b.add(i));
        if r != 0 {
            return r;
        }
        i += 32;
    }
    if i < n {
        return cmp32(a.add(n - 32), b.add(n - 32));
    }
    0
}

/// `memcmp` at `level`: the difference of the first differing bytes, read unsigned.
///
/// # Safety
/// `a` and `b` are readable for `n` bytes.
pub unsafe fn memcmp_at(level: u8, a: *const u8, b: *const u8, n: usize) -> i32 {
    if n >= 64 {
        return if level == AVX2 {
            memcmp_avx2_large(a, b, n)
        } else {
            memcmp_sse2_large(a, b, n)
        };
    }
    if n >= 16 {
        let mut i = 0;
        while n - i > 16 {
            let r = cmp16(a.add(i), b.add(i));
            if r != 0 {
                return r;
            }
            i += 16;
        }
        return cmp16(a.add(n - 16), b.add(n - 16));
    }
    if n >= 8 {
        let r = cmp_word(r64(a), r64(b));
        if r != 0 {
            return r;
        }
        return cmp_word(r64(a.add(n - 8)), r64(b.add(n - 8)));
    }
    if n >= 4 {
        let r = cmp_word(u64::from(r32(a)), u64::from(r32(b)));
        if r != 0 {
            return r;
        }
        return cmp_word(u64::from(r32(a.add(n - 4))), u64::from(r32(b.add(n - 4))));
    }
    let mut i = 0;
    while i < n {
        let (x, y) = (*a.add(i), *b.add(i));
        if x != y {
            return i32::from(x) - i32::from(y);
        }
        i += 1;
    }
    0
}

/// The C runtime's `memcmp`.
///
/// # Safety
/// As `memcmp_at`.
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    memcmp_at(level(), a, b, n)
}

/// The C runtime's `strlen`. Each read is an aligned 16-byte block, which never crosses a page, so
/// it reads only bytes of pages the string itself lies in.
///
/// # Safety
/// `s` points at a string ended by a zero byte.
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    let off = s as usize & 15;
    let mut p = s.sub(off);
    let z = _mm_setzero_si128();
    let m = (_mm_movemask_epi8(_mm_cmpeq_epi8(_mm_load_si128(p.cast()), z)) as u32) >> off;
    if m != 0 {
        return m.trailing_zeros() as usize;
    }
    loop {
        p = p.add(16);
        let m = _mm_movemask_epi8(_mm_cmpeq_epi8(_mm_load_si128(p.cast()), z)) as u32;
        if m != 0 {
            return (p as usize - s as usize) + m.trailing_zeros() as usize;
        }
    }
}
