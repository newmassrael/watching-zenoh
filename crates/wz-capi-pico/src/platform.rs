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
    guard_val(0, || {
        if instant.is_null() {
            return 0;
        }
        let now = z_clock_now();
        // Annotated `i64` with NO cast, deliberately. `time_t` is i64 on every
        // LP64 target, which is the only shape this crate's ABI is grounded for
        // (see `crate::abi`'s size table); a cast would be a same-type cast here
        // and a silent narrowing somewhere else, while the annotation simply
        // fails to compile on a target whose header layout this crate does not
        // reproduce anyway.
        let secs: i64 = now.tv_sec - (*instant).tv_sec;
        let mut elapsed = secs.saturating_mul(sec_scale);
        if nsec_div != 0 {
            let nsecs: i64 = now.tv_nsec - (*instant).tv_nsec;
            elapsed = elapsed.saturating_add(nsecs / nsec_div);
        }
        if elapsed > 0 {
            elapsed as c_ulong
        } else {
            0
        }
    })
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
