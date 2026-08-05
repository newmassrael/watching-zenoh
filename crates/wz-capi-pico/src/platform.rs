// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `z_malloc` / `z_free`, `z_sleep_*`, `z_clock_*` — pico's PLATFORM surface.
//!
//! These carry no zenoh semantics at all; they are the libc shims a pico
//! program reaches for while doing something else (timing a round trip,
//! pacing a publisher loop, sizing a payload buffer). They are here because
//! upstream's examples call them, and a missing one is an undefined symbol
//! that keeps an otherwise-working program from linking: measured across the
//! 32 upstream examples, `z_malloc` / `z_free` alone block nine of them and
//! `z_sleep_s` seven, which is more than any protocol-level export.
//!
//! ## Why libc and not Rust's own primitives
//!
//! `z_malloc` and `z_free` MUST be the C allocator, not `std::alloc`. pico
//! defines them as exactly `malloc` and `free`
//! (`vendor/zenoh-pico/src/system/unix/system.c:101,105`), and a C program is
//! entitled to mix them with plain `free()` / `malloc()` on the same pointer —
//! upstream's `z_ping.c` does not, but nothing in the contract stops it, and
//! `std::alloc::dealloc` also needs a `Layout` that a bare `void*` cannot
//! supply. Forwarding keeps the two allocators the same allocator.
//!
//! `z_clock_now` is `clock_gettime(CLOCK_MONOTONIC)` for the same reason it is
//! in pico: the value is handed back to `z_clock_elapsed_*`, so it has to be
//! monotonic, and `std::time::Instant` cannot be used because the C side
//! stack-allocates the result as a `struct timespec` it may read. Taking
//! `libc` as a direct dependency (it is already in this workspace's graph via
//! `wz-runtime-tokio`) is what keeps `CLOCK_MONOTONIC` correct per platform —
//! it is 1 on Linux and 6 on macOS, and hand-writing the constant is a
//! portability bug waiting for the first non-Linux build.

use std::ffi::{c_ulong, c_void};
use std::time::Duration;

use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_OK};

/// pico `z_clock_t` — `struct timespec` on every Unix
/// (`vendor/zenoh-pico/include/zenoh-pico/system/platform/unix.h:41`), 16 B
/// measured. Returned BY VALUE from [`z_clock_now`], which the SysV AMD64 ABI
/// passes back in two integer registers; `libc::timespec` is `#[repr(C)]` with
/// the same two fields, so the register assignment matches without a shim.
pub type z_clock_t = libc::timespec;

/// Allocate (pico `z_malloc`). Plain `malloc`, so the result is freeable by
/// [`z_free`] or by the caller's own `free`.
#[no_mangle]
pub unsafe extern "C" fn z_malloc(size: usize) -> *mut c_void {
    libc::malloc(size)
}

/// Release (pico `z_free`). Plain `free`; null-tolerant, as `free` is.
#[no_mangle]
pub unsafe extern "C" fn z_free(ptr: *mut c_void) {
    libc::free(ptr);
}

/// Sleep for `time` microseconds (pico `z_sleep_us`).
///
/// pico's is `usleep`, which is at-least-this-long; `thread::sleep` carries the
/// identical guarantee, so the observable contract is the same. Always `Z_OK`:
/// the error channel exists because `usleep` can report `EINTR`, and
/// `thread::sleep` handles interruption internally rather than surfacing it.
#[no_mangle]
pub unsafe extern "C" fn z_sleep_us(time: usize) -> ZResult {
    guard_val(Z_OK, || {
        std::thread::sleep(Duration::from_micros(time as u64));
        Z_OK
    })
}

/// Sleep for `time` milliseconds (pico `z_sleep_ms`).
#[no_mangle]
pub unsafe extern "C" fn z_sleep_ms(time: usize) -> ZResult {
    guard_val(Z_OK, || {
        std::thread::sleep(Duration::from_millis(time as u64));
        Z_OK
    })
}

/// Sleep for `time` seconds (pico `z_sleep_s`).
#[no_mangle]
pub unsafe extern "C" fn z_sleep_s(time: usize) -> ZResult {
    guard_val(Z_OK, || {
        std::thread::sleep(Duration::from_secs(time as u64));
        Z_OK
    })
}

/// Read the monotonic clock (pico `z_clock_now`).
#[no_mangle]
pub unsafe extern "C" fn z_clock_now() -> z_clock_t {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now);
    now
}

/// Microseconds elapsed since `instant` (pico `z_clock_elapsed_us`).
///
/// The arithmetic is pico's, saturation included: it computes the difference
/// as a SIGNED `long` and clamps a negative result to 0
/// (`system.c:235-238`). Reproducing the clamp rather than the obvious
/// `Duration` subtraction matters because the C side may hand back a `z_clock_t`
/// it advanced past now (`z_clock_advance_us` exists for exactly that), and a
/// `Duration` subtraction would panic where pico returns zero.
#[no_mangle]
pub unsafe extern "C" fn z_clock_elapsed_us(instant: *mut z_clock_t) -> c_ulong {
    elapsed_since(instant, 1_000_000, 1_000)
}

/// Milliseconds elapsed since `instant` (pico `z_clock_elapsed_ms`).
#[no_mangle]
pub unsafe extern "C" fn z_clock_elapsed_ms(instant: *mut z_clock_t) -> c_ulong {
    elapsed_since(instant, 1_000, 1_000_000)
}

/// Seconds elapsed since `instant` (pico `z_clock_elapsed_s`).
#[no_mangle]
pub unsafe extern "C" fn z_clock_elapsed_s(instant: *mut z_clock_t) -> c_ulong {
    elapsed_since(instant, 1, 0)
}

/// The shared body of the three `z_clock_elapsed_*` exports.
///
/// `sec_scale` converts whole seconds into the target unit and `nsec_div`
/// converts nanoseconds into it (0 meaning "drop the sub-second part", which is
/// what pico's `_s` variant does — it uses only `tv_sec`). One body rather than
/// three keeps the clamp and the null guard from drifting between siblings, the
/// asymmetry this crate has already been bitten by once.
unsafe fn elapsed_since(instant: *mut z_clock_t, sec_scale: i64, nsec_div: i64) -> c_ulong {
    // Upstream's own definition: `z_clock_elapsed_X(i)` IS
    // `zp_clock_elapsed_X_since(&now, i)` (`system.c:249-268`). Delegating
    // rather than repeating the arithmetic is what keeps the clamp from
    // drifting between the two families — the asymmetry this crate has already
    // been bitten by once.
    let mut now = z_clock_now();
    elapsed_between(&mut now, instant, sec_scale, nsec_div)
}

/// Elapsed microseconds between two READINGS (pico `zp_clock_elapsed_us_since`).
///
/// The `z_clock_elapsed_*` trio above is this function with `instant = now`,
/// which is exactly how upstream defines them (`system.c:249-268`) — so the
/// three-line body lives once here and the trio delegates, rather than each
/// re-deriving the clamp.
///
/// # Safety
/// `instant` and `epoch` must be null or valid `z_clock_t`.
#[no_mangle]
pub unsafe extern "C" fn zp_clock_elapsed_us_since(
    instant: *mut z_clock_t,
    epoch: *mut z_clock_t,
) -> c_ulong {
    elapsed_between(instant, epoch, 1_000_000, 1_000)
}

/// Elapsed milliseconds between two readings (pico `zp_clock_elapsed_ms_since`).
///
/// # Safety
/// As [`zp_clock_elapsed_us_since`].
#[no_mangle]
pub unsafe extern "C" fn zp_clock_elapsed_ms_since(
    instant: *mut z_clock_t,
    epoch: *mut z_clock_t,
) -> c_ulong {
    elapsed_between(instant, epoch, 1_000, 1_000_000)
}

/// Elapsed whole seconds between two readings (pico `zp_clock_elapsed_s_since`).
///
/// Sub-second parts are DROPPED rather than rounded — upstream's body reads
/// only `tv_sec` (`system.c:245-248`), so a 0.9 s gap is 0.
///
/// # Safety
/// As [`zp_clock_elapsed_us_since`].
#[no_mangle]
pub unsafe extern "C" fn zp_clock_elapsed_s_since(
    instant: *mut z_clock_t,
    epoch: *mut z_clock_t,
) -> c_ulong {
    elapsed_between(instant, epoch, 1, 0)
}

/// The shared body of the `zp_clock_elapsed_*_since` trio, and — through
/// [`elapsed_since`] — of the `z_clock_elapsed_*` trio too.
unsafe fn elapsed_between(
    instant: *mut z_clock_t,
    epoch: *mut z_clock_t,
    sec_scale: i64,
    nsec_div: i64,
) -> c_ulong {
    guard_val(0, || {
        if instant.is_null() || epoch.is_null() {
            return 0;
        }
        let secs: i64 = (*instant).tv_sec - (*epoch).tv_sec;
        let mut elapsed = secs.saturating_mul(sec_scale);
        if nsec_div != 0 {
            let nsecs: i64 = (*instant).tv_nsec - (*epoch).tv_nsec;
            elapsed = elapsed.saturating_add(nsecs / nsec_div);
        }
        if elapsed > 0 {
            elapsed as c_ulong
        } else {
            0
        }
    })
}

/// Move a clock reading FORWARD by `duration` microseconds (pico
/// `z_clock_advance_us`).
///
/// The normalisation is upstream's and it is deliberately ONE carry, not a
/// loop: `tv_nsec` starts below 1e9 and gains at most 999_999_000 ns, so a
/// single borrow suffices. Reproduced rather than replaced by a `Duration`
/// addition because a caller may then hand the advanced clock to
/// `z_clock_elapsed_*`, whose clamp is what makes a FUTURE instant read as 0.
///
/// # Safety
/// `clock` must be null or a valid, writable `z_clock_t`.
#[no_mangle]
pub unsafe extern "C" fn z_clock_advance_us(clock: *mut z_clock_t, duration: c_ulong) {
    advance(
        clock,
        (duration / 1_000_000) as i64,
        ((duration % 1_000_000) * 1_000) as i64,
    );
}

/// Move a clock reading forward by `duration` milliseconds (pico
/// `z_clock_advance_ms`).
///
/// # Safety
/// As [`z_clock_advance_us`].
#[no_mangle]
pub unsafe extern "C" fn z_clock_advance_ms(clock: *mut z_clock_t, duration: c_ulong) {
    advance(
        clock,
        (duration / 1_000) as i64,
        ((duration % 1_000) * 1_000_000) as i64,
    );
}

/// Move a clock reading forward by whole seconds (pico `z_clock_advance_s`).
///
/// # Safety
/// As [`z_clock_advance_us`].
#[no_mangle]
pub unsafe extern "C" fn z_clock_advance_s(clock: *mut z_clock_t, duration: c_ulong) {
    advance(clock, duration as i64, 0);
}

/// The shared body of the three `z_clock_advance_*` exports.
unsafe fn advance(clock: *mut z_clock_t, secs: i64, nsecs: i64) {
    let _ = guarded(|| {
        if clock.is_null() {
            return Z_OK;
        }
        (*clock).tv_sec += secs;
        (*clock).tv_nsec += nsecs;
        if (*clock).tv_nsec >= 1_000_000_000 {
            (*clock).tv_sec += 1;
            (*clock).tv_nsec -= 1_000_000_000;
        }
        Z_OK
    });
}

/// pico `z_time_t` — `struct timeval`
/// (`system/platform/unix.h`), the WALL clock, distinct from
/// [`z_clock_t`]'s monotonic one. 16 B measured; `libc::timeval` is the same
/// two-field `#[repr(C)]`, so the by-value return matches without a shim.
pub type z_time_t = libc::timeval;

/// Read the wall clock (pico `z_time_now`) — `gettimeofday`, not the monotonic
/// clock [`z_clock_now`] reads. The two are separate exports in pico because
/// they answer different questions, and a program that timestamps a log line
/// wants this one.
#[no_mangle]
pub unsafe extern "C" fn z_time_now() -> z_time_t {
    let mut now = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    libc::gettimeofday(&mut now, std::ptr::null_mut());
    now
}

/// Render the current LOCAL time into `buf` as `%Y-%m-%dT%H:%M:%SZ` (pico
/// `z_time_now_as_str`), returning `buf`.
///
/// `localtime` + `strftime` are called through libc rather than reimplemented.
/// The format string is upstream's, but the VALUE depends on the process's
/// timezone database and `TZ`, so a Rust-side formatter would agree with
/// upstream only until the first non-UTC machine — and this is a log-line
/// helper, where the mismatch would be silent. (Upstream's trailing `Z` on a
/// LOCAL time is upstream's; reproducing it is fidelity, not endorsement.)
///
/// # Safety
/// `buf` must be null or point at `buflen` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_time_now_as_str(
    buf: *mut std::ffi::c_char,
    buflen: c_ulong,
) -> *const std::ffi::c_char {
    guard_val(std::ptr::null(), || {
        if buf.is_null() || buflen == 0 {
            return buf;
        }
        let now = z_time_now();
        let secs = now.tv_sec;
        let tm = libc::localtime(&secs);
        if tm.is_null() {
            *buf = 0;
            return buf;
        }
        let fmt = c"%Y-%m-%dT%H:%M:%SZ";
        let written = libc::strftime(buf, buflen as usize, fmt.as_ptr(), tm);
        // `strftime` returns 0 when the result did not fit and leaves the
        // buffer's contents unspecified; NUL-terminating keeps the returned
        // pointer safe to pass to `printf`, which is what the caller does.
        if written == 0 {
            *buf = 0;
        }
        buf
    })
}

/// Microseconds elapsed on the WALL clock since `time` (pico
/// `z_time_elapsed_us`).
///
/// No clamp, unlike the monotonic siblings: upstream casts a signed difference
/// straight to `unsigned long` (`system.c:307-313`), so a `time` in the future
/// WRAPS rather than reading 0. Reproduced, because a program that compares
/// against a huge value is reading upstream's behaviour, not a bug wz should
/// silently repair.
///
/// # Safety
/// `time` must be null or a valid `z_time_t`.
#[no_mangle]
pub unsafe extern "C" fn z_time_elapsed_us(time: *mut z_time_t) -> c_ulong {
    wall_elapsed(time, 1_000_000, 1)
}

/// Milliseconds elapsed on the wall clock since `time` (pico
/// `z_time_elapsed_ms`).
///
/// # Safety
/// As [`z_time_elapsed_us`].
#[no_mangle]
pub unsafe extern "C" fn z_time_elapsed_ms(time: *mut z_time_t) -> c_ulong {
    wall_elapsed(time, 1_000, 1_000)
}

/// Whole seconds elapsed on the wall clock since `time` (pico
/// `z_time_elapsed_s`).
///
/// # Safety
/// As [`z_time_elapsed_us`].
#[no_mangle]
pub unsafe extern "C" fn z_time_elapsed_s(time: *mut z_time_t) -> c_ulong {
    wall_elapsed(time, 1, 0)
}

/// The shared body of the three `z_time_elapsed_*` exports. `usec_div` of 0
/// drops the sub-second part, which is upstream's `_s` arm.
unsafe fn wall_elapsed(time: *mut z_time_t, sec_scale: i64, usec_div: i64) -> c_ulong {
    guard_val(0, || {
        if time.is_null() {
            return 0;
        }
        let now = z_time_now();
        let secs: i64 = now.tv_sec - (*time).tv_sec;
        let mut elapsed = secs.saturating_mul(sec_scale);
        if usec_div != 0 {
            let usecs: i64 = now.tv_usec - (*time).tv_usec;
            elapsed = elapsed.saturating_add(usecs / usec_div);
        }
        // The wrapping cast IS the contract here — see the `_us` doc.
        elapsed as c_ulong
    })
}

/// Resize an allocation (pico `z_realloc`). Plain `realloc`, for the same
/// reason [`z_malloc`] is plain `malloc`.
///
/// # Safety
/// `ptr` must be null or a pointer this allocator returned.
#[no_mangle]
pub unsafe extern "C" fn z_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    libc::realloc(ptr, size)
}

/// Fill `len` bytes of `buf` with cryptographic-quality randomness (pico
/// `z_random_fill`).
///
/// `getrandom` in a retry loop, which is upstream's own body. The loop is not
/// decoration: `getrandom` short-reads for a request above 256 bytes and
/// returns `EINTR` on a signal, and pico's `while (getrandom(..) <= 0)` spins
/// on both. wz advances the cursor on a short read instead of restarting, which
/// is the same contract with the O(n^2) worst case removed.
///
/// # Safety
/// `buf` must be null or point at `len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_random_fill(buf: *mut c_void, len: usize) {
    let _ = guarded(|| {
        if buf.is_null() || len == 0 {
            return Z_OK;
        }
        let mut filled = 0usize;
        while filled < len {
            let got = libc::getrandom(
                buf.cast::<u8>().add(filled).cast::<c_void>(),
                len - filled,
                0,
            );
            if got > 0 {
                filled += got as usize;
            }
            // A negative return is EINTR / EAGAIN; upstream spins, and so does
            // this, because there is no error channel on the export.
        }
        Z_OK
    });
}

/// A random byte (pico `z_random_u8`).
#[no_mangle]
pub unsafe extern "C" fn z_random_u8() -> u8 {
    random_value::<1>()[0]
}

/// A random 16-bit word (pico `z_random_u16`).
#[no_mangle]
pub unsafe extern "C" fn z_random_u16() -> u16 {
    u16::from_ne_bytes(random_value::<2>())
}

/// A random 32-bit word (pico `z_random_u32`).
#[no_mangle]
pub unsafe extern "C" fn z_random_u32() -> u32 {
    u32::from_ne_bytes(random_value::<4>())
}

/// A random 64-bit word (pico `z_random_u64`).
#[no_mangle]
pub unsafe extern "C" fn z_random_u64() -> u64 {
    u64::from_ne_bytes(random_value::<8>())
}

/// `N` random bytes, through the same source [`z_random_fill`] uses.
///
/// NATIVE byte order, matching upstream: pico fills the integer's own storage
/// with `getrandom`, so the word it returns is the little-endian reading of
/// those bytes on a little-endian host. Any order is equally random; agreeing
/// with upstream matters only because a program may derive a session id from
/// one and compare it with bytes from the other.
unsafe fn random_value<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    z_random_fill(out.as_mut_ptr().cast::<c_void>(), N);
    out
}

/// Build a payload from a caller-owned buffer, taking ownership (pico
/// `z_bytes_from_buf`).
///
/// pico ADOPTS `data` and calls `deleter(data, context)` when the payload is
/// released. wz copies into its owning [`crate::bytes::ByteBuf`], so the
/// deleter is invoked HERE, as soon as the copy is taken — dropping it would
/// leak the caller's buffer, which is the one thing a program handing over
/// ownership cannot check for itself. A NULL deleter means the buffer is
/// static and must not be released, which pico documents at the parameter.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_buf(
    bytes: *mut crate::abi::z_owned_bytes_t,
    data: *mut u8,
    len: usize,
    deleter: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        let rc = crate::bytes::z_bytes_copy_from_buf(bytes, data, len);
        // Release the caller's buffer on EVERY path, success or not: pico's
        // ownership transfer is unconditional once the call is made.
        if let Some(free) = deleter {
            free(data as *mut c_void, context);
        }
        rc
    })
}

/// Build a payload from a statically allocated buffer (pico
/// `z_bytes_from_static_buf`). Copies, for the same reason
/// [`crate::bytes::z_bytes_from_static_str`] does; no deleter, because static
/// storage is never released.
#[no_mangle]
pub unsafe extern "C" fn z_bytes_from_static_buf(
    bytes: *mut crate::abi::z_owned_bytes_t,
    data: *const u8,
    len: usize,
) -> ZResult {
    crate::bytes::z_bytes_copy_from_buf(bytes, data, len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The carry in `z_clock_advance_*` is ONE borrow, and it has to fire when
    /// the nanosecond field crosses 1e9 — the single arithmetic step in this
    /// family that a plausible implementation gets wrong by omitting.
    #[test]
    fn advancing_a_clock_normalises_exactly_one_carry() {
        let mut c = libc::timespec {
            tv_sec: 100,
            tv_nsec: 900_000_000,
        };
        // SAFETY: a live local.
        unsafe { z_clock_advance_ms(&mut c, 200) };
        assert_eq!(c.tv_sec, 101, "the carry fired");
        assert_eq!(c.tv_nsec, 100_000_000);

        // No carry when the sum stays below 1e9.
        let mut d = libc::timespec {
            tv_sec: 5,
            tv_nsec: 1_000,
        };
        // SAFETY: a live local.
        unsafe { z_clock_advance_us(&mut d, 999) };
        assert_eq!((d.tv_sec, d.tv_nsec), (5, 1_000_000));

        // The seconds arm touches only `tv_sec`.
        let mut e = libc::timespec {
            tv_sec: 7,
            tv_nsec: 123,
        };
        // SAFETY: a live local.
        unsafe { z_clock_advance_s(&mut e, 3) };
        assert_eq!((e.tv_sec, e.tv_nsec), (10, 123));
    }

    /// `zp_clock_elapsed_*_since` CLAMPS a negative interval to zero and DROPS
    /// the sub-second part in the `_s` arm. Both are upstream behaviours a
    /// `Duration` subtraction would get wrong in opposite directions (panic,
    /// and rounding up).
    #[test]
    fn elapsed_since_clamps_backwards_and_truncates_seconds() {
        let mut early = libc::timespec {
            tv_sec: 10,
            tv_nsec: 0,
        };
        let mut late = libc::timespec {
            tv_sec: 11,
            tv_nsec: 500_000_000,
        };
        // SAFETY: live locals.
        unsafe {
            assert_eq!(zp_clock_elapsed_ms_since(&mut late, &mut early), 1_500);
            assert_eq!(zp_clock_elapsed_us_since(&mut late, &mut early), 1_500_000);
            assert_eq!(
                zp_clock_elapsed_s_since(&mut late, &mut early),
                1,
                "1.5 s truncates to 1, it does not round to 2"
            );
            // Backwards: clamped, not wrapped.
            assert_eq!(zp_clock_elapsed_ms_since(&mut early, &mut late), 0);
            assert_eq!(zp_clock_elapsed_s_since(&mut early, &mut late), 0);
        }
    }

    /// `z_clock_elapsed_*` IS `zp_clock_elapsed_*_since(&now, instant)` — a
    /// clock advanced into the FUTURE therefore reads 0, not a wrapped huge
    /// value. This is the pairing that makes `z_clock_advance_*` useful, and it
    /// is the one place the monotonic family differs from the wall-clock one.
    #[test]
    fn a_future_monotonic_instant_reads_zero_elapsed() {
        // SAFETY: live locals throughout.
        unsafe {
            let mut future = z_clock_now();
            z_clock_advance_s(&mut future, 60);
            assert_eq!(z_clock_elapsed_ms(&mut future), 0);
            assert_eq!(z_clock_elapsed_s(&mut future), 0);

            let mut past = z_clock_now();
            z_clock_advance_s(&mut past, 0);
            past.tv_sec -= 2;
            assert!(z_clock_elapsed_ms(&mut past) >= 2_000);
        }
    }

    /// The WALL clock family does NOT clamp — upstream casts a signed
    /// difference to `unsigned long`, so a future timestamp wraps. Pinned
    /// because it is the opposite of the monotonic family two tests up, and
    /// "obviously both should clamp" is the plausible wrong repair.
    #[test]
    fn a_future_wall_time_wraps_rather_than_clamping() {
        // SAFETY: a live local.
        unsafe {
            let now = z_time_now();
            let mut future = libc::timeval {
                tv_sec: now.tv_sec + 3_600,
                tv_usec: now.tv_usec,
            };
            let elapsed = z_time_elapsed_s(&mut future);
            assert!(
                elapsed > u64::from(u32::MAX) as c_ulong,
                "a future wall time must WRAP (got {elapsed}), which is what \
                 upstream's unsigned cast does"
            );
        }
    }

    /// `z_time_now_as_str` writes an ISO-8601-shaped, NUL-terminated string and
    /// hands back the caller's own buffer.
    #[test]
    fn time_now_as_str_fills_the_callers_buffer() {
        let mut buf = [0i8; 64];
        // SAFETY: a live, adequately sized local.
        let out = unsafe { z_time_now_as_str(buf.as_mut_ptr(), buf.len() as c_ulong) };
        assert_eq!(out, buf.as_ptr(), "the caller's buffer is returned");
        // SAFETY: NUL-terminated by the export.
        let rendered = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
            .to_str()
            .expect("ASCII");
        assert_eq!(rendered.len(), 20, "%Y-%m-%dT%H:%M:%SZ is 20 characters");
        assert_eq!(&rendered[4..5], "-");
        assert_eq!(&rendered[10..11], "T");
        assert_eq!(&rendered[19..], "Z");

        // A buffer too small must still leave something safe to `printf`.
        let mut tiny = [0x7fi8; 4];
        // SAFETY: a live local.
        unsafe { z_time_now_as_str(tiny.as_mut_ptr(), tiny.len() as c_ulong) };
        assert_eq!(
            tiny[0], 0,
            "NUL-terminated even when strftime could not fit"
        );
    }

    /// The randomness sources actually produce entropy rather than a fixed
    /// value — the failure mode of a stubbed `getrandom` loop, which would make
    /// every session id in a pico program identical.
    #[test]
    fn the_random_family_varies() {
        // SAFETY: the exports take no pointers here.
        unsafe {
            let a = z_random_u64();
            let b = z_random_u64();
            assert_ne!(a, b, "two draws from a 64-bit source must differ");
            // The narrower widths cannot be pinned by a single draw (u8 hits 0
            // once in 256), so they are pinned as a SET: eight u8 draws being
            // all-zero is a 2^-64 event on a live source and a certainty on a
            // stub.
            assert!(
                (0..8).any(|_| z_random_u8() != 0),
                "eight u8 draws were all zero"
            );
            assert!(
                (0..8).any(|_| z_random_u16() != 0),
                "eight u16 draws were all zero"
            );
            assert!(
                (0..8).any(|_| z_random_u32() != 0),
                "eight u32 draws were all zero"
            );

            let mut buf = [0u8; 64];
            z_random_fill(buf.as_mut_ptr().cast(), buf.len());
            assert!(
                buf.iter().any(|&b| b != 0),
                "z_random_fill left the buffer untouched"
            );
            // A short request must not overrun: the tail stays as written.
            let mut guarded_buf = [0xAAu8; 8];
            z_random_fill(guarded_buf.as_mut_ptr().cast(), 4);
            assert_eq!(
                &guarded_buf[4..],
                &[0xAA; 4],
                "wrote past the requested length"
            );
        }
    }

    /// `z_realloc` grows an allocation in place-or-elsewhere while preserving
    /// the prefix, and is `free`-compatible with the rest of the family.
    #[test]
    fn realloc_preserves_the_prefix() {
        // SAFETY: a matched malloc/realloc/free triple.
        unsafe {
            let p = z_malloc(4) as *mut u8;
            assert!(!p.is_null());
            std::ptr::copy_nonoverlapping(b"abcd".as_ptr(), p, 4);
            let q = z_realloc(p.cast(), 64) as *mut u8;
            assert!(!q.is_null());
            assert_eq!(std::slice::from_raw_parts(q, 4), b"abcd");
            z_free(q.cast());
        }
    }
}
