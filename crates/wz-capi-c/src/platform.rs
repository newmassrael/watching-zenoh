// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The platform helpers upstream's examples call to stay alive and to time
//! themselves.
//!
//! None of this is zenoh — it is the portability shim zenoh-c exports so an
//! example does not have to `#include <unistd.h>` or pick a clock per platform.
//! It is here because a drop-in that does not export it does not link `z_sub.c`
//! or `z_sub_thr.c`.
//!
//! ## `z_clock_t`'s CONTENTS are wz's to choose; its FOOTPRINT is not
//!
//! `z_clock_t` is `{ uint64_t t; const void *t_base; }`
//! (`zenoh_commons.h:466-469`) — 16 bytes, and the C side stack-allocates one and
//! passes it back. It never READS either field: the only producer is
//! [`z_clock_now`] and the only consumers are the three `z_clock_elapsed_*`, all
//! in this library. So the encoding below (nanoseconds since a process-global
//! monotonic base, with `t_base` unused) is an internal choice, while the size
//! and the by-value return are the ABI.
//!
//! The base is a `OnceLock<Instant>` rather than `SystemTime`: upstream calls
//! this the "monotonic clock", and a wall clock stepping backwards would make a
//! throughput benchmark print a negative interval as a huge unsigned one.

use std::ffi::c_char;
use std::sync::OnceLock;
use std::time::Instant;

use crate::ffi::{guard_val, guarded};
use crate::result::{ZResult, Z_OK};

/// zenoh-c `z_clock_t` (`zenoh_commons.h:466-469`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct z_clock_t {
    /// Nanoseconds since this process's monotonic base. See the module note for
    /// why the encoding is wz's to pick.
    pub t: u64,
    /// Upstream's platform slot. Unused here, and always null.
    pub t_base: *const std::ffi::c_void,
}

const _: () = {
    assert!(std::mem::size_of::<z_clock_t>() == 16);
    assert!(std::mem::align_of::<z_clock_t>() == 8);
};

/// The process-global monotonic base every `z_clock_t` is measured from.
static CLOCK_BASE: OnceLock<Instant> = OnceLock::new();

/// Nanoseconds since the base, installing it on first use.
fn monotonic_nanos() -> u64 {
    let base = CLOCK_BASE.get_or_init(Instant::now);
    // `as u64` truncates after ~584 years of uptime, which is not a case this
    // needs to handle; `Instant` is monotonic so the value never goes backwards.
    base.elapsed().as_nanos() as u64
}

/// The current monotonic time point (zenoh-c `z_clock_now`).
///
/// Returned BY VALUE: 16 bytes of integer/pointer fields, which SysV x86-64
/// classifies into RAX:RDX rather than a hidden out-pointer. The const assertion
/// above is what keeps that true — a 17th byte would silently change the calling
/// convention on the wz side only.
#[no_mangle]
pub extern "C" fn z_clock_now() -> z_clock_t {
    guard_val(
        z_clock_t {
            t: 0,
            t_base: std::ptr::null(),
        },
        || z_clock_t {
            t: monotonic_nanos(),
            t_base: std::ptr::null(),
        },
    )
}

/// Nanoseconds elapsed since `time`, or 0 for a null pointer.
///
/// Saturating rather than wrapping: a caller who passes a clock from the FUTURE
/// (one this library never produces, but a zeroed struct is not) gets 0 instead
/// of an interval near `u64::MAX`.
///
/// # Safety
/// `time` must be null or a valid `z_clock_t`.
unsafe fn elapsed_nanos(time: *const z_clock_t) -> u64 {
    if time.is_null() {
        return 0;
    }
    // SAFETY: the caller's contract.
    monotonic_nanos().saturating_sub(unsafe { (*time).t })
}

/// Microseconds since `time` was taken (zenoh-c `z_clock_elapsed_us`).
///
/// # Safety
/// `time` must be null or a valid `z_clock_t`.
#[no_mangle]
pub unsafe extern "C" fn z_clock_elapsed_us(time: *const z_clock_t) -> u64 {
    guard_val(0, || unsafe { elapsed_nanos(time) } / 1_000)
}

/// Milliseconds since `time` was taken (zenoh-c `z_clock_elapsed_ms`).
///
/// # Safety
/// `time` must be null or a valid `z_clock_t`.
#[no_mangle]
pub unsafe extern "C" fn z_clock_elapsed_ms(time: *const z_clock_t) -> u64 {
    guard_val(0, || unsafe { elapsed_nanos(time) } / 1_000_000)
}

/// Seconds since `time` was taken (zenoh-c `z_clock_elapsed_s`).
///
/// # Safety
/// `time` must be null or a valid `z_clock_t`.
#[no_mangle]
pub unsafe extern "C" fn z_clock_elapsed_s(time: *const z_clock_t) -> u64 {
    guard_val(0, || unsafe { elapsed_nanos(time) } / 1_000_000_000)
}

/// Sleep for `time` seconds (zenoh-c `z_sleep_s`).
///
/// Upstream returns a `z_result_t`; on a std host the sleep does not fail, so
/// this is always `Z_OK`.
///
/// # Safety
/// No pointers are dereferenced. `unsafe` for signature parity with the rest of
/// the exported surface would be noise, so this one is safe — the ABI is
/// unaffected either way.
#[no_mangle]
pub extern "C" fn z_sleep_s(time: usize) -> ZResult {
    guarded(|| {
        std::thread::sleep(std::time::Duration::from_secs(time as u64));
        Z_OK
    })
}

// --- R311y564: the WALL-CLOCK, RANDOM and TASK surfaces ---------------------
//
// `z_clock_t` above is the MONOTONIC clock (`CLOCK_MONOTONIC`, for measuring
// intervals). `z_time_t` below is the WALL clock, and upstream keeps them
// separate because they answer different questions — a wall clock can jump
// backwards, a monotonic one cannot. Both are exported and they are not
// interchangeable.

/// zenoh-c's `z_time_t` (`zenoh_commons.h:1245-1247`) — a wall-clock instant as
/// one `uint64_t`.
///
/// The field is opaque to a C caller (upstream never documents its unit), so
/// this build stores MICROSECONDS since the Unix epoch: it is the finest unit
/// any `z_time_elapsed_*` reader needs, so every reader divides rather than
/// losing precision.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct z_time_t {
    /// Microseconds since the Unix epoch.
    pub t: u64,
}

const _: () = {
    assert!(std::mem::size_of::<z_time_t>() == 8);
    assert!(std::mem::align_of::<z_time_t>() == 8);
};

/// Microseconds since the Unix epoch, or 0 if the clock is before it.
fn epoch_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

/// The current wall-clock instant (zenoh-c `z_time_now`).
#[no_mangle]
pub extern "C" fn z_time_now() -> z_time_t {
    z_time_t { t: epoch_micros() }
}

/// The elapsed microseconds since `time` (zenoh-c `z_time_elapsed_us`).
///
/// SATURATES at 0 rather than wrapping, for the same reason
/// [`z_clock_elapsed_us`] does: a wall clock can legitimately move backwards
/// (NTP), and a wrapped `u64` would read as ~584 000 years of uptime.
///
/// # Safety
/// `time` must be null or a valid `z_time_t`.
#[no_mangle]
pub unsafe extern "C" fn z_time_elapsed_us(time: *const z_time_t) -> u64 {
    guard_val(0, || {
        if time.is_null() {
            return 0;
        }
        // SAFETY: the caller's contract.
        epoch_micros().saturating_sub(unsafe { (*time).t })
    })
}

/// The elapsed milliseconds since `time` (zenoh-c `z_time_elapsed_ms`).
///
/// # Safety
/// `time` must be null or a valid `z_time_t`.
#[no_mangle]
pub unsafe extern "C" fn z_time_elapsed_ms(time: *const z_time_t) -> u64 {
    // SAFETY: the caller's contract, delegated — one clock read, so the three
    // readings cannot disagree about which instant "now" was.
    (unsafe { z_time_elapsed_us(time) }) / 1_000
}

/// The elapsed seconds since `time` (zenoh-c `z_time_elapsed_s`).
///
/// # Safety
/// `time` must be null or a valid `z_time_t`.
#[no_mangle]
pub unsafe extern "C" fn z_time_elapsed_s(time: *const z_time_t) -> u64 {
    // SAFETY: the caller's contract, delegated.
    (unsafe { z_time_elapsed_us(time) }) / 1_000_000
}

/// Render the current time into the caller's buffer (zenoh-c
/// `z_time_now_as_str`).
///
/// Returns `buf`, which is what upstream's signature promises and what a caller
/// passes straight to `printf`. The buffer is always NUL-terminated, including
/// when it is too short for the rendering — a truncated timestamp is a bad log
/// line, an unterminated one is a read past the end.
///
/// # Safety
/// `buf` must be null or point at `len` WRITABLE bytes.
#[no_mangle]
pub unsafe extern "C" fn z_time_now_as_str(buf: *const c_char, len: usize) -> *const c_char {
    guard_val(buf, || {
        if buf.is_null() || len == 0 {
            return buf;
        }
        let micros = epoch_micros();
        let rendered = format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000);
        let bytes = rendered.as_bytes();
        // One byte of the caller's buffer is reserved for the terminator.
        let n = bytes.len().min(len - 1);
        // SAFETY: the caller's contract — `len` writable bytes, and `n < len`.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, n);
            *(buf as *mut u8).add(n) = 0;
        }
        buf
    })
}

/// Sleep for `time` microseconds (zenoh-c `z_sleep_us`).
#[no_mangle]
pub extern "C" fn z_sleep_us(time: usize) -> ZResult {
    guarded(|| {
        std::thread::sleep(std::time::Duration::from_micros(time as u64));
        Z_OK
    })
}

/// Fill `buf` with `len` random bytes (zenoh-c `z_random_fill`).
///
/// # Safety
/// `buf` must be null or point at `len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn z_random_fill(buf: *mut std::ffi::c_void, len: usize) {
    guard_val((), || {
        if buf.is_null() || len == 0 {
            return;
        }
        // SAFETY: the caller's contract.
        let out = unsafe { std::slice::from_raw_parts_mut(buf.cast::<u8>(), len) };
        fill_random(out);
    });
}

/// The random source behind the whole family.
///
/// `getrandom(2)` through `/dev/urandom`, with a per-thread counter-based
/// fallback if that is unavailable. The fallback is NOT cryptographic and does
/// not claim to be: upstream's own `z_random_*` is documented as a convenience
/// for example programs (nonces, jittered sleeps), and this crate's security
/// surface (`extauth`, TLS) does not route through it.
fn fill_random(out: &mut [u8]) {
    use std::io::Read;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(out).is_ok() {
            return;
        }
    }
    // Fallback: splitmix64 seeded from the wall clock and this thread's id.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    epoch_micros().hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    let mut state = hasher.finish();
    for chunk in out.chunks_mut(8) {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        for (byte, source) in chunk.iter_mut().zip(z.to_le_bytes()) {
            *byte = source;
        }
    }
}

/// One random byte (zenoh-c `z_random_u8`).
#[no_mangle]
pub extern "C" fn z_random_u8() -> u8 {
    let mut buf = [0u8; 1];
    fill_random(&mut buf);
    buf[0]
}

/// A random `u16` (zenoh-c `z_random_u16`).
#[no_mangle]
pub extern "C" fn z_random_u16() -> u16 {
    let mut buf = [0u8; 2];
    fill_random(&mut buf);
    u16::from_le_bytes(buf)
}

/// A random `u32` (zenoh-c `z_random_u32`).
#[no_mangle]
pub extern "C" fn z_random_u32() -> u32 {
    let mut buf = [0u8; 4];
    fill_random(&mut buf);
    u32::from_le_bytes(buf)
}

/// A random `u64` (zenoh-c `z_random_u64`).
#[no_mangle]
pub extern "C" fn z_random_u64() -> u64 {
    let mut buf = [0u8; 8];
    fill_random(&mut buf);
    u64::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The elapsed readings must be MONOTONIC and consistent with each other:
    /// microseconds >= milliseconds >= seconds after truncating division. A clock
    /// that ran backwards, or one whose divisors were transposed, fails here.
    #[test]
    fn the_three_elapsed_readings_agree_on_one_interval() {
        let start = z_clock_now();
        std::thread::sleep(std::time::Duration::from_millis(20));
        // SAFETY: `start` is a live local.
        let (us, ms, s) = unsafe {
            (
                z_clock_elapsed_us(&start),
                z_clock_elapsed_ms(&start),
                z_clock_elapsed_s(&start),
            )
        };
        assert!(ms >= 20, "20 ms of sleep must be visible, saw {ms} ms");
        assert!(us >= ms * 1_000, "us ({us}) must dominate ms ({ms})");
        assert_eq!(s, 0, "20 ms is under a second");
    }

    /// A null clock is 0, not a crash and not an enormous interval — the guard is
    /// what keeps a C caller's uninitialised pointer from reading as uptime.
    #[test]
    fn a_null_clock_elapses_zero() {
        // SAFETY: null is explicitly in the contract.
        unsafe {
            assert_eq!(z_clock_elapsed_us(std::ptr::null()), 0);
            assert_eq!(z_clock_elapsed_ms(std::ptr::null()), 0);
            assert_eq!(z_clock_elapsed_s(std::ptr::null()), 0);
        }
    }

    /// A clock from the FUTURE saturates to 0 rather than wrapping to ~u64::MAX.
    /// `z_clock_now` never produces one, but a zeroed-then-poked struct can.
    #[test]
    fn a_future_clock_saturates_rather_than_wrapping() {
        let future = z_clock_t {
            t: u64::MAX,
            t_base: std::ptr::null(),
        };
        // SAFETY: `future` is a live local.
        assert_eq!(unsafe { z_clock_elapsed_ms(&future) }, 0);
    }
}
