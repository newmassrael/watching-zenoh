// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The runtime held to the standard library's own operations: the memory functions and the 64-bit
//! division on any x86 host (the x86 Linux and Windows builds run them alike), and the labels a
//! program's calls reach, under their test names, on the MSVC targets.

use std::vec;
use std::vec::Vec;

use crate::mem::{self, AVX2, SSE2};

/// Every level this processor runs: SSE2 always, AVX2 where it is detected.
fn levels() -> Vec<u8> {
    let mut out = vec![SSE2];
    if mem::level() == AVX2 {
        out.push(AVX2);
    }
    out
}

/// `len` bytes of a fixed sequence, different for each `seed`.
fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(0x9E37_79B9);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// The sizes at and around every boundary of the paths: each size to 300, the string instruction's
/// thresholds, and the copy that writes around the caches.
fn sizes() -> Vec<usize> {
    let mut out: Vec<usize> = (0..=300).collect();
    for edge in [512usize, 1024, 2048, 4096, 8192, 65536, 2 << 20] {
        out.extend([edge - 1, edge, edge + 1, edge + 33]);
    }
    out
}

/// The offsets a size is tried at: every alignment within 16 bytes for the short sizes, a few for
/// the long ones.
fn offsets(size: usize) -> &'static [usize] {
    if size <= 300 {
        &[0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33]
    } else {
        &[0, 1, 15, 32]
    }
}

const GUARD: usize = 64;

#[test]
fn memcpy_copies_every_size_and_alignment_and_nothing_else() {
    let mut checked = 0;
    for level in levels() {
        for size in sizes() {
            let src = pattern(size + GUARD, size as u32);
            for &soff in offsets(size) {
                for &doff in offsets(size) {
                    let mut dst = vec![0xEEu8; size + 2 * GUARD];
                    // SAFETY: both ranges lie in their own buffers, which do not overlap.
                    let ret = unsafe {
                        mem::memcpy_at(
                            level,
                            dst.as_mut_ptr().add(doff),
                            src.as_ptr().add(soff),
                            size,
                        )
                    };
                    assert_eq!(
                        ret,
                        dst.as_mut_ptr().wrapping_add(doff),
                        "level {level} size {size}"
                    );
                    assert_eq!(
                        &dst[doff..doff + size],
                        &src[soff..soff + size],
                        "level {level} size {size} src+{soff} dst+{doff}"
                    );
                    assert!(
                        dst[..doff].iter().all(|&b| b == 0xEE),
                        "wrote below, size {size}"
                    );
                    assert!(
                        dst[doff + size..].iter().all(|&b| b == 0xEE),
                        "wrote past, size {size}"
                    );
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 5000, "ANTI-VACUITY: {checked} copies");
}

/// Overlap in both directions at every distance a path splits on, held to `copy_within`.
#[test]
fn memmove_copies_overlapping_ranges_either_way() {
    let deltas: [isize; 18] = [
        -129, -128, -65, -64, -33, -32, -17, -16, -1, 1, 16, 17, 32, 33, 64, 65, 128, 129,
    ];
    let mut checked = 0;
    for level in levels() {
        for size in sizes() {
            for delta in deltas {
                let span = 200usize;
                let base = pattern(size + 2 * span, size as u32 ^ 0x55);
                let s = span;
                let d = (span as isize + delta) as usize;
                let mut want = base.clone();
                want.copy_within(s..s + size, d);
                let mut have = base;
                let p = have.as_mut_ptr();
                // SAFETY: both ranges lie in `have`; `memmove` allows them to overlap.
                let ret = unsafe { mem::memmove_at(level, p.add(d), p.add(s), size) };
                assert_eq!(ret, p.wrapping_add(d));
                assert!(have == want, "level {level} size {size} delta {delta}");
                checked += 1;
            }
            // Apart: the copy without overlap the function hands on.
            let src = pattern(size, 7);
            let mut dst = vec![0u8; size];
            // SAFETY: two buffers of `size` bytes.
            unsafe { mem::memmove_at(level, dst.as_mut_ptr(), src.as_ptr(), size) };
            assert!(dst == src, "level {level} size {size} apart");
        }
    }
    assert!(checked > 5000, "ANTI-VACUITY: {checked} moves");
}

#[test]
fn memset_fills_with_the_low_byte_only_within_the_range() {
    let mut checked = 0;
    for level in levels() {
        for size in sizes() {
            for &off in offsets(size) {
                for (value, byte) in [(0, 0u8), (0xA5, 0xA5), (0x1FF, 0xFF), (-1, 0xFF)] {
                    let mut buf = vec![0x11u8; size + 2 * GUARD];
                    // SAFETY: the range lies in `buf`.
                    let ret =
                        unsafe { mem::memset_at(level, buf.as_mut_ptr().add(off), value, size) };
                    assert_eq!(ret, buf.as_mut_ptr().wrapping_add(off));
                    assert!(
                        buf[off..off + size].iter().all(|&b| b == byte),
                        "level {level} size {size}"
                    );
                    assert!(
                        buf[..off].iter().all(|&b| b == 0x11),
                        "wrote below, size {size}"
                    );
                    assert!(
                        buf[off + size..].iter().all(|&b| b == 0x11),
                        "wrote past, size {size}"
                    );
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 5000, "ANTI-VACUITY: {checked} fills");
}

/// Equal ranges compare 0; a range that differs answers the difference of the first differing
/// bytes read unsigned (0x00 against 0xFF is below), wherever the difference lies.
#[test]
fn memcmp_answers_the_first_difference_read_unsigned() {
    let mut checked = 0;
    for level in levels() {
        for size in sizes() {
            let a = pattern(size + GUARD, size as u32 ^ 0xA);
            let off = if size > 300 { 1 } else { 3 };
            let a = &a[off..off + size];
            let b = a.to_vec();
            // SAFETY: both ranges are `size` bytes.
            assert_eq!(
                unsafe { mem::memcmp_at(level, a.as_ptr(), b.as_ptr(), size) },
                0,
                "size {size}"
            );
            let positions: Vec<usize> = if size <= 70 {
                (0..size).collect()
            } else {
                [
                    0,
                    1,
                    15,
                    16,
                    31,
                    63,
                    64,
                    127,
                    128,
                    size / 2,
                    size - 17,
                    size - 16,
                    size - 1,
                ]
                .into_iter()
                .filter(|&k| k < size)
                .collect()
            };
            for k in positions {
                for (x, y) in [(0x00u8, 0xFFu8), (0xFF, 0x00), (0x7F, 0x80), (0x41, 0x42)] {
                    let (mut p, mut q) = (a.to_vec(), b.clone());
                    p[k] = x;
                    q[k] = y;
                    // A difference after the first one does not change the answer.
                    if k + 1 < size {
                        p[size - 1] ^= 0x5A;
                    }
                    let want = i32::from(x) - i32::from(y);
                    // SAFETY: both ranges are `size` bytes.
                    let have = unsafe { mem::memcmp_at(level, p.as_ptr(), q.as_ptr(), size) };
                    assert_eq!(have, want, "level {level} size {size} at {k}");
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 5000, "ANTI-VACUITY: {checked} comparisons");
}

#[test]
fn strlen_counts_to_the_first_zero_at_every_alignment() {
    for len in (0..=100).chain([255, 256, 4095, 5000]) {
        for off in 0..32 {
            let mut buf = vec![b'x'; off + len + 1 + 32];
            buf[off + len] = 0;
            // SAFETY: a zero byte ends the string within `buf`.
            let have = unsafe { mem::strlen(buf.as_ptr().add(off)) };
            assert_eq!(have, len, "length {len} at +{off}");
        }
    }
}

/// The values a division helper splits on: the halves of the word, the signs, and their neighbours.
#[cfg(target_arch = "x86")]
const EDGES: [u64; 20] = [
    0,
    1,
    2,
    3,
    7,
    0x7FFF_FFFF,
    0x8000_0000,
    0xFFFF_FFFF,
    0x1_0000_0000,
    0x1_0000_0001,
    0x1_FFFF_FFFF,
    0xFFFF_FFFF_0000_0000,
    0x7FFF_FFFF_FFFF_FFFE,
    0x7FFF_FFFF_FFFF_FFFF,
    0x8000_0000_0000_0000,
    0x8000_0000_0000_0001,
    0xFFFF_FFFF_FFFF_FFFE,
    u64::MAX,
    0x0123_4567_89AB_CDEF,
    0xFEDC_BA98_7654_3210,
];

/// Pairs over the edges and a fixed sequence of every width of dividend and divisor.
#[cfg(target_arch = "x86")]
fn division_pairs() -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = EDGES
        .iter()
        .flat_map(|&n| EDGES.iter().map(move |&d| (n, d)))
        .collect();
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    for _ in 0..20_000 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let n = x >> (x as u32 % 64);
        let d = x.rotate_left(29) >> ((x >> 8) as u32 % 64);
        out.push((n, d));
    }
    out.retain(|&(_, d)| d != 0);
    out
}

/// The helpers agree with the compiler's own division (the C runtime's helper on Windows, the
/// compiler's built-ins on Linux), the signed ones with its wrapping division.
#[cfg(target_arch = "x86")]
#[test]
fn the_division_helpers_agree_with_the_compilers_division() {
    use crate::div64::{alldiv, allrem, aulldiv, aullrem};
    let pairs = division_pairs();
    for &(n, d) in &pairs {
        assert_eq!(aulldiv(n, d), n / d, "{n:#x} / {d:#x}");
        assert_eq!(aullrem(n, d), n % d, "{n:#x} % {d:#x}");
        let (sn, sd) = (n as i64, d as i64);
        assert_eq!(alldiv(sn, sd), sn.wrapping_div(sd), "{sn} / {sd}");
        assert_eq!(allrem(sn, sd), sn.wrapping_rem(sd), "{sn} % {sd}");
    }
    assert_eq!(
        alldiv(i64::MIN, -1),
        i64::MIN,
        "the quotient past the range wraps"
    );
    assert_eq!(allrem(i64::MIN, -1), 0);
    assert!(pairs.len() > 19_000, "ANTI-VACUITY: {} pairs", pairs.len());
}

#[cfg(all(windows, target_env = "msvc"))]
mod labels {
    use core::ffi::c_void;
    use std::vec;

    extern "C" {
        #[link_name = "wzrt_memcpy"]
        fn label_memcpy(d: *mut u8, s: *const u8, n: usize) -> *mut u8;
        #[link_name = "wzrt_memmove"]
        fn label_memmove(d: *mut u8, s: *const u8, n: usize) -> *mut u8;
        #[link_name = "wzrt_memset"]
        fn label_memset(d: *mut u8, c: i32, n: usize) -> *mut u8;
        #[link_name = "wzrt_memcmp"]
        fn label_memcmp(a: *const u8, b: *const u8, n: usize) -> i32;
        #[link_name = "wzrt_strlen"]
        fn label_strlen(s: *const u8) -> usize;
        #[link_name = "wzrt___CxxFrameHandler3"]
        fn label_frame_handler(
            r: *mut c_void,
            f: *mut c_void,
            c: *mut c_void,
            d: *mut c_void,
        ) -> i32;
        #[link_name = "wzrt__fltused"]
        static LABEL_FLTUSED: i32;
    }

    extern "system" {
        #[link_name = "wzrt__DllMainCRTStartup"]
        fn label_entry(module: *mut c_void, reason: u32, reserved: *mut c_void) -> i32;
    }

    /// A call of each memory function's C name reaches its function with its arguments as they
    /// were passed, and returns its answer.
    #[test]
    fn the_memory_labels_reach_their_functions() {
        let src: vec::Vec<u8> = (0..=255u8).collect();
        let mut dst = vec![0u8; 256];
        // SAFETY: each range lies in its buffer, and `text` ends in a zero byte.
        unsafe {
            assert_eq!(
                label_memcpy(dst.as_mut_ptr(), src.as_ptr(), 256),
                dst.as_mut_ptr()
            );
            assert!(dst == src);
            assert_eq!(label_memcmp(dst.as_ptr(), src.as_ptr(), 256), 0);
            dst[200] = 0;
            assert_eq!(label_memcmp(dst.as_ptr(), src.as_ptr(), 256), -200);
            label_memmove(dst.as_mut_ptr().add(1), dst.as_ptr(), 255);
            assert_eq!(&dst[1..201], &src[0..200]);
            label_memset(dst.as_mut_ptr(), 0x17C, 256);
            assert!(dst.iter().all(|&b| b == 0x7C));
            let text = b"seventeen bytes!!\0";
            assert_eq!(label_strlen(text.as_ptr()), 17);
        }
    }

    /// The entry accepts every notice and the handler searches on; the marker is a zero.
    #[test]
    fn the_entry_succeeds_and_the_handler_searches_on() {
        // SAFETY: neither reads its arguments.
        unsafe {
            for reason in 0..4 {
                assert_eq!(
                    label_entry(core::ptr::null_mut(), reason, core::ptr::null_mut()),
                    1
                );
            }
            let null = core::ptr::null_mut();
            assert_eq!(
                label_frame_handler(null, null, null, null),
                1,
                "ExceptionContinueSearch"
            );
            assert_eq!(core::ptr::read_volatile(&raw const LABEL_FLTUSED), 0);
        }
    }

    /// The stack probe touches the pages of the size asked and keeps every register but the stack
    /// pointer, which x64's leaves alone.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_stack_probe_keeps_the_registers_and_the_stack_pointer() {
        for size in [0x10usize, 0xFFF, 0x1000, 0x1001, 0x10000 + 0x123] {
            let (rax, rcx, moved): (usize, usize, usize);
            // SAFETY: the probe reads the pages below the stack pointer of this thread's stack,
            // which is larger than the largest size; the stack pointer is put back whatever it does.
            unsafe {
                core::arch::asm!(
                    "mov {base}, rsp",
                    "call wzrt___chkstk",
                    "mov {moved}, {base}",
                    "sub {moved}, rsp",
                    "mov rsp, {base}",
                    base = out(reg) _,
                    moved = out(reg) moved,
                    inout("rax") size => rax,
                    inout("rcx") 0x5A5A_5A5A_5A5A_5A5Ausize => rcx,
                );
            }
            assert_eq!(
                moved, 0,
                "the x64 probe does not move the stack pointer, size {size:#x}"
            );
            assert_eq!(rax, size);
            assert_eq!(rcx, 0x5A5A_5A5A_5A5A_5A5A);
        }
    }

    /// x86's probe lowers the stack pointer by the size, as the compiler's call expects, and keeps
    /// every other register.
    #[cfg(target_arch = "x86")]
    #[test]
    fn the_stack_probe_lowers_the_stack_pointer_by_the_size() {
        for size in [0x10u32, 0xFFF, 0x1000, 0x1001, 0x10000 + 0x123] {
            let (eax, ecx, lowered): (u32, u32, u32);
            // SAFETY: as on x64; the stack pointer is put back after it is read.
            unsafe {
                core::arch::asm!(
                    "mov {base}, esp",
                    "call _wzrt__chkstk",
                    "mov {lowered}, {base}",
                    "sub {lowered}, esp",
                    "mov esp, {base}",
                    base = out(reg) _,
                    lowered = out(reg) lowered,
                    inout("eax") size => eax,
                    inout("ecx") 0x5A5A_5A5Au32 => ecx,
                );
            }
            assert_eq!(
                lowered, size,
                "the x86 probe lowers the stack pointer by the size"
            );
            assert_eq!(eax, size);
            assert_eq!(ecx, 0x5A5A_5A5A);
        }
    }

    /// Calls the division helper at `$label` as the compiler calls one: the dividend and the
    /// divisor pushed, the helper to pop them. Gives the result and the bytes left on the stack.
    #[cfg(target_arch = "x86")]
    macro_rules! call_helper {
        ($label:literal, $n:expr, $d:expr) => {{
            let (n, d): (u64, u64) = ($n, $d);
            let args: [u32; 4] = [n as u32, (n >> 32) as u32, d as u32, (d >> 32) as u32];
            let (lo, hi, left): (u32, u32, u32);
            // SAFETY: the helper reads the four words pushed; the stack pointer is put back
            // whatever it popped, so a helper that pops otherwise fails the test, not the program.
            unsafe {
                core::arch::asm!(
                    "mov {base}, esp",
                    "push dword ptr [{args} + 12]",
                    "push dword ptr [{args} + 8]",
                    "push dword ptr [{args} + 4]",
                    "push dword ptr [{args}]",
                    concat!("call ", $label),
                    "mov {left}, {base}",
                    "sub {left}, esp",
                    "mov esp, {base}",
                    args = in(reg) args.as_ptr(),
                    base = out(reg) _,
                    left = out(reg) left,
                    lateout("eax") lo,
                    lateout("edx") hi,
                    clobber_abi("C"),
                );
            }
            ((u64::from(hi) << 32) | u64::from(lo), left)
        }};
    }

    /// Each helper's C name answers the compiler's own division and pops its two operands.
    #[cfg(target_arch = "x86")]
    #[test]
    fn the_division_labels_answer_and_pop_their_operands() {
        for (n, d) in super::division_pairs().into_iter().take(2_000) {
            let (q, left) = call_helper!("_wzrt__aulldiv", n, d);
            assert_eq!((q, left), (n / d, 0), "{n:#x} / {d:#x}");
            let (r, left) = call_helper!("_wzrt__aullrem", n, d);
            assert_eq!((r, left), (n % d, 0), "{n:#x} % {d:#x}");
            let (sn, sd) = (n as i64, d as i64);
            let (q, left) = call_helper!("_wzrt__alldiv", n, d);
            assert_eq!((q as i64, left), (sn.wrapping_div(sd), 0), "{sn} / {sd}");
            let (r, left) = call_helper!("_wzrt__allrem", n, d);
            assert_eq!((r as i64, left), (sn.wrapping_rem(sd), 0), "{sn} % {sd}");
        }
    }
}
