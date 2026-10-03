// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Unix host layer: libc's pthread objects and POSIX clocks, as zenoh-pico's own
//! `system/unix/system.c` uses them.
//!
//! Every value here is the bytes the C program's header says it is.
//! `vendor/zenoh-pico/include/zenoh-pico/system/platform/unix.h` types the mutex as
//! `pthread_mutex_t`, the condvar as `pthread_cond_t`, the clock as `struct timespec`
//! and the wall time as `struct timeval`, and the C program stack-allocates them
//! before wz sees them. The only correct implementation is therefore libc's own
//! primitives acting on those bytes, which is what pico's backend does. A design that
//! kept a handle in the value's first word would compile and then corrupt, since the C
//! side may copy the struct by value (`z_mutex_take` is `*obj = src->_this`).
//!
//! macOS differs from Linux in four places, and pico's own macOS arm differs in the
//! same four: no `getrandom` (it is `arc4random_buf`), no `pthread_condattr_setclock`
//! (the condvar waits on an interval instead), a 32-bit `suseconds_t`, and Darwin's
//! larger pthread layouts.

use std::ffi::{c_char, c_int, c_ulong, c_void};

use super::Unit;
use crate::result::{ZResult, Z_OK};
use crate::sync::{Z_ERR_SYSTEM_GENERIC, Z_ETIMEDOUT};

/// pico `z_clock_t`: `struct timespec`, 16 B. Returned BY VALUE from `clock_now`,
/// which the SysV AMD64 ABI passes back in two integer registers; `libc::timespec`
/// is `#[repr(C)]` with the same two fields, so the register assignment matches
/// without a shim.
pub type Clock = libc::timespec;
/// pico `z_time_t`: `struct timeval`, the WALL clock, 16 B.
pub type WallTime = libc::timeval;
/// pico `_z_mutex_t`: `pthread_mutex_t`. 40 B on Linux, measured; 64 B on macOS.
pub type RawMutex = libc::pthread_mutex_t;
/// pico `_z_condvar_t`: `pthread_cond_t`, 48 B.
pub type RawCondvar = libc::pthread_cond_t;
/// pico `_z_task_t`: `pthread_t`, 8 B.
pub type RawTask = libc::pthread_t;
/// pico `z_task_attr_t`: `pthread_attr_t`, 56 B on Linux, measured; 64 B on macOS,
/// where Darwin's pthread types are a signature word plus an opaque block
/// (`__sig` and `__opaque[56]`).
pub type TaskAttr = libc::pthread_attr_t;

/// The value of a task that was never started or has been joined or detached.
pub const TASK_NULL: RawTask = 0;

/// What `sizeof(pthread_attr_t)` is on this host. The pin exists so that a target
/// whose layout is not the one a size was measured on fails the build instead of
/// writing past the caller's storage, which is exactly what it did on macOS the first
/// time this crate was built there.
#[cfg(target_os = "macos")]
const TASK_ATTR_BYTES: usize = 64;
#[cfg(not(target_os = "macos"))]
const TASK_ATTR_BYTES: usize = 56;

const _: () = {
    assert!(std::mem::size_of::<RawTask>() == 8);
    assert!(std::mem::size_of::<TaskAttr>() == TASK_ATTR_BYTES);
};

/// pico's `_Z_CHECK_SYS_ERR`: 0 is `Z_OK`, anything else is the system-error code.
/// pico additionally logs the raw `errno`; the code handed to C is the same either
/// way.
#[inline]
fn sys(rc: c_int) -> ZResult {
    if rc == 0 {
        Z_OK
    } else {
        Z_ERR_SYSTEM_GENERIC
    }
}

// ---------------------------------------------------------------------------
// Monotonic clock
// ---------------------------------------------------------------------------

/// Read the monotonic clock: `clock_gettime(CLOCK_MONOTONIC)`, as pico does. The
/// value is handed back to the elapsed functions, so it has to be monotonic, and
/// `std::time::Instant` cannot be used because the C side stack-allocates the result
/// as a `struct timespec` it may read. `libc` keeps `CLOCK_MONOTONIC` correct per
/// platform: it is 1 on Linux and 6 on macOS.
pub fn clock_now() -> Clock {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a live local the call writes.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
    now
}

/// Elapsed time in `unit` between two readings.
///
/// The arithmetic is pico's, saturation included: the difference is a SIGNED `long`
/// and a negative result is clamped to 0 (`system.c:235-238`). Reproducing the clamp
/// rather than the obvious `Duration` subtraction matters because the C side may hand
/// back a clock it advanced past now, and a `Duration` subtraction would panic where
/// pico returns zero. The seconds unit uses only `tv_sec`, so a 0.9 s gap is 0.
pub fn clock_elapsed_between(instant: &Clock, epoch: &Clock, unit: Unit) -> c_ulong {
    let (sec_scale, nsec_div): (i64, i64) = match unit {
        Unit::Micro => (1_000_000, 1_000),
        Unit::Milli => (1_000, 1_000_000),
        Unit::Second => (1, 0),
    };
    let secs: i64 = instant.tv_sec - epoch.tv_sec;
    let mut elapsed = secs.saturating_mul(sec_scale);
    if nsec_div != 0 {
        let nsecs: i64 = instant.tv_nsec - epoch.tv_nsec;
        elapsed = elapsed.saturating_add(nsecs / nsec_div);
    }
    if elapsed > 0 {
        elapsed as c_ulong
    } else {
        0
    }
}

/// Move a reading FORWARD by `duration` units.
///
/// The normalisation is upstream's and it is deliberately ONE carry, not a loop:
/// `tv_nsec` starts below 1e9 and gains at most 999_999_000 ns, so a single borrow
/// suffices. Reproduced rather than replaced by a `Duration` addition because a caller
/// may then hand the advanced clock to the elapsed functions, whose clamp is what
/// makes a FUTURE instant read as 0.
pub fn clock_advance(clock: &mut Clock, unit: Unit, duration: c_ulong) {
    let (secs, nsecs) = match unit {
        Unit::Micro => (
            (duration / 1_000_000) as i64,
            ((duration % 1_000_000) * 1_000) as i64,
        ),
        Unit::Milli => (
            (duration / 1_000) as i64,
            ((duration % 1_000) * 1_000_000) as i64,
        ),
        Unit::Second => (duration as i64, 0),
    };
    clock.tv_sec += secs;
    clock.tv_nsec += nsecs;
    if clock.tv_nsec >= 1_000_000_000 {
        clock.tv_sec += 1;
        clock.tv_nsec -= 1_000_000_000;
    }
}

// ---------------------------------------------------------------------------
// Wall clock
// ---------------------------------------------------------------------------

/// Read the wall clock: `gettimeofday`, not the monotonic clock `clock_now` reads.
/// The two are separate in pico because they answer different questions, and a
/// program that timestamps a log line wants this one.
pub fn wall_now() -> WallTime {
    let mut now = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    // SAFETY: `now` is a live local the call writes; a null timezone is allowed.
    unsafe { libc::gettimeofday(&mut now, std::ptr::null_mut()) };
    now
}

/// A `timeval`'s microseconds as `i64`. `suseconds_t` is `i64` on Linux and `i32` on
/// macOS, so this is an identity on one host and a widening on the other, and the two
/// lints name exactly those two cases.
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn usec_i64(usec: libc::suseconds_t) -> i64 {
    usec as i64
}

/// Elapsed time in `unit` on the WALL clock since `time`.
///
/// No clamp, unlike the monotonic family: upstream casts a signed difference straight
/// to `unsigned long` (`system.c:307-313`), so a `time` in the future WRAPS rather than
/// reading 0. Reproduced, because a program that compares against a huge value is
/// reading upstream's behaviour, not a bug wz should silently repair. The seconds unit
/// drops the sub-second part.
pub fn wall_elapsed(time: &WallTime, unit: Unit) -> c_ulong {
    let (sec_scale, usec_div): (i64, i64) = match unit {
        Unit::Micro => (1_000_000, 1),
        Unit::Milli => (1_000, 1_000),
        Unit::Second => (1, 0),
    };
    let now = wall_now();
    let secs: i64 = now.tv_sec - time.tv_sec;
    let mut elapsed = secs.saturating_mul(sec_scale);
    if usec_div != 0 {
        let usecs: i64 = usec_i64(now.tv_usec) - usec_i64(time.tv_usec);
        elapsed = elapsed.saturating_add(usecs / usec_div);
    }
    // The wrapping cast IS the contract here.
    elapsed as c_ulong
}

/// Render `time` as LOCAL time in `buf` as `%Y-%m-%dT%H:%M:%SZ`, and say whether it
/// fit.
///
/// `localtime` + `strftime` are called through libc rather than reimplemented. The
/// format string is upstream's, but the VALUE depends on the process's timezone
/// database and `TZ`, so a Rust-side formatter would agree with upstream only until
/// the first non-UTC machine, and this is a log-line helper, where the mismatch would
/// be silent. (Upstream's trailing `Z` on a LOCAL time is upstream's; reproducing it
/// is fidelity, not endorsement.) `false` means the caller must NUL-terminate.
///
/// # Safety
/// `buf` must point at `buflen` writable bytes.
pub unsafe fn wall_render_local(time: &WallTime, buf: *mut c_char, buflen: usize) -> bool {
    let secs = time.tv_sec;
    let tm = libc::localtime(&secs);
    if tm.is_null() {
        return false;
    }
    let fmt = c"%Y-%m-%dT%H:%M:%SZ";
    // `strftime` returns 0 when the result did not fit and leaves the buffer's
    // contents unspecified.
    libc::strftime(buf, buflen, fmt.as_ptr(), tm) != 0
}

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

/// Fill `len` bytes of `buf` with cryptographic-quality randomness.
///
/// `getrandom` in a retry loop, which is upstream's own body. The loop is not
/// decoration: `getrandom` short-reads for a request above 256 bytes and returns
/// `EINTR` on a signal, and pico's `while (getrandom(..) <= 0)` spins on both. wz
/// advances the cursor on a short read instead of restarting, which is the same
/// contract with the O(n^2) worst case removed.
///
/// # Safety
/// `buf` must point at `len` writable bytes.
#[cfg(not(target_os = "macos"))]
pub unsafe fn random_fill(buf: *mut c_void, len: usize) {
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
        // A negative return is EINTR / EAGAIN; upstream spins, and so does this,
        // because there is no error channel on the export.
    }
}

/// macOS: `arc4random_buf`, as pico's own macOS arm is (`system.c:95-96`).
/// `getrandom` does not exist there, and `arc4random_buf` cannot fail or short-read,
/// so there is no loop to keep.
///
/// # Safety
/// `buf` must point at `len` writable bytes.
#[cfg(target_os = "macos")]
pub unsafe fn random_fill(buf: *mut c_void, len: usize) {
    libc::arc4random_buf(buf, len);
}

// ---------------------------------------------------------------------------
// Mutex
// ---------------------------------------------------------------------------

/// Initialise a mutex in place.
///
/// # Safety
/// `m` must point at storage for a `RawMutex`.
pub unsafe fn mutex_init(m: *mut RawMutex) -> ZResult {
    sys(libc::pthread_mutex_init(m, std::ptr::null()))
}

/// Destroy a mutex.
///
/// # Safety
/// `m` must point at an initialised, unlocked `RawMutex`.
pub unsafe fn mutex_destroy(m: *mut RawMutex) -> ZResult {
    sys(libc::pthread_mutex_destroy(m))
}

/// Lock, blocking.
///
/// # Safety
/// `m` must point at an initialised `RawMutex`.
pub unsafe fn mutex_lock(m: *mut RawMutex) -> ZResult {
    sys(libc::pthread_mutex_lock(m))
}

/// Try to lock without blocking.
///
/// # Safety
/// As `mutex_lock`.
pub unsafe fn mutex_try_lock(m: *mut RawMutex) -> ZResult {
    sys(libc::pthread_mutex_trylock(m))
}

/// Unlock.
///
/// # Safety
/// As `mutex_lock`, and the caller holds the lock.
pub unsafe fn mutex_unlock(m: *mut RawMutex) -> ZResult {
    sys(libc::pthread_mutex_unlock(m))
}

// ---------------------------------------------------------------------------
// Condition variable
// ---------------------------------------------------------------------------

/// Initialise a condvar on `CLOCK_MONOTONIC`.
///
/// The clock is set through a `pthread_condattr_t` exactly as pico does
/// (`system.c:160-166`), and it is load-bearing rather than incidental. Skipping it
/// leaves glibc's default `CLOCK_REALTIME`, and since `clock_now` is
/// `CLOCK_MONOTONIC`, a deadline computed from it would be read against a different
/// epoch: `condvar_wait_until` would return immediately or hang for the
/// wall-clock/uptime skew. The two only agree because both name the same clock. The
/// attr is destroyed on every path, including the failure one, because
/// `pthread_condattr_init` may allocate.
///
/// # Safety
/// `cv` must point at storage for a `RawCondvar`.
pub unsafe fn condvar_init(cv: *mut RawCondvar) -> ZResult {
    let mut attr: libc::pthread_condattr_t = std::mem::zeroed();
    let rc = libc::pthread_condattr_init(&mut attr);
    if rc != 0 {
        return sys(rc);
    }
    let rc = condattr_use_monotonic(&mut attr);
    let out = if rc != 0 {
        sys(rc)
    } else {
        sys(libc::pthread_cond_init(cv, &attr))
    };
    libc::pthread_condattr_destroy(&mut attr);
    out
}

/// Put `CLOCK_MONOTONIC` on the condattr, which is what makes an absolute deadline
/// taken from `clock_now` mean the same instant to the wait. macOS has no
/// `pthread_condattr_setclock`, and pico skips the call there (`system.c:162-165`);
/// `cond_wait_until` is where that gap is closed.
#[cfg(not(target_os = "macos"))]
unsafe fn condattr_use_monotonic(attr: *mut libc::pthread_condattr_t) -> c_int {
    libc::pthread_condattr_setclock(attr, libc::CLOCK_MONOTONIC)
}

#[cfg(target_os = "macos")]
unsafe fn condattr_use_monotonic(_attr: *mut libc::pthread_condattr_t) -> c_int {
    0
}

/// Destroy a condvar.
///
/// # Safety
/// `cv` must point at an initialised `RawCondvar` nobody waits on.
pub unsafe fn condvar_destroy(cv: *mut RawCondvar) -> ZResult {
    sys(libc::pthread_cond_destroy(cv))
}

/// Wake one waiter.
///
/// # Safety
/// `cv` must point at an initialised `RawCondvar`.
pub unsafe fn condvar_signal(cv: *mut RawCondvar) -> ZResult {
    sys(libc::pthread_cond_signal(cv))
}

/// Wait, releasing `m`.
///
/// # Safety
/// `cv` and `m` must be initialised, and the caller holds `m`.
pub unsafe fn condvar_wait(cv: *mut RawCondvar, m: *mut RawMutex) -> ZResult {
    sys(libc::pthread_cond_wait(cv, m))
}

/// Wait until an ABSOLUTE monotonic deadline.
///
/// A timeout is `Z_ETIMEDOUT` and NOT the generic system error, because that
/// distinction is the whole point of the call: pico special-cases `ETIMEDOUT` ahead of
/// `_Z_CHECK_SYS_ERR` (`system.c:199-203`), and a caller that cannot tell "deadline
/// reached" from "the system refused" has no way to decide whether to retry.
///
/// # Safety
/// As `condvar_wait`.
pub unsafe fn condvar_wait_until(
    cv: *mut RawCondvar,
    m: *mut RawMutex,
    abstime: &Clock,
) -> ZResult {
    let rc = cond_wait_until(cv, m, abstime);
    if rc == libc::ETIMEDOUT {
        return Z_ETIMEDOUT;
    }
    sys(rc)
}

#[cfg(not(target_os = "macos"))]
unsafe fn cond_wait_until(cv: *mut RawCondvar, m: *mut RawMutex, abstime: &Clock) -> c_int {
    libc::pthread_cond_timedwait(cv, m, abstime)
}

/// macOS: `pthread_cond_timedwait` reads its deadline against the REALTIME clock,
/// while a `Clock` is a MONOTONIC instant, so pico (`system.c:178-203`) turns the
/// deadline into an interval from `clock_now` and waits on that with the Darwin-only
/// `pthread_cond_timedwait_relative_np`. This is the same.
#[cfg(target_os = "macos")]
unsafe fn cond_wait_until(cv: *mut RawCondvar, m: *mut RawMutex, abstime: &Clock) -> c_int {
    let deadline = relative_deadline(clock_now(), *abstime);
    libc::pthread_cond_timedwait_relative_np(cv, m, &deadline)
}

/// The interval from `now` to the absolute instant `abs`, or zero when `abs` is not
/// in the future. Pure arithmetic and compiled on every Unix, so the one place the
/// macOS wait differs from the others is tested where the tests run.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn relative_deadline(now: Clock, abs: Clock) -> Clock {
    let mut sec = abs.tv_sec - now.tv_sec;
    let mut nsec = abs.tv_nsec - now.tv_nsec;
    if nsec < 0 {
        sec -= 1;
        nsec += 1_000_000_000;
    }
    if sec < 0 {
        return libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
    }
    libc::timespec {
        tv_sec: sec,
        tv_nsec: nsec,
    }
}

// ---------------------------------------------------------------------------
// Task
// ---------------------------------------------------------------------------

/// Start a thread running `fun(arg)`.
///
/// `pthread_create` directly, because upstream's is: the handle a caller gets back is
/// a real `pthread_t` it may hand to `task_join`, and a Rust `JoinHandle` cannot be
/// one. `attr` is passed through rather than ignored, because a program setting a
/// stack size on a constrained target is the reason the parameter exists.
///
/// # Safety
/// `task` must be valid and writable; `attr` must be null or a valid `pthread_attr_t`.
pub unsafe fn task_spawn(
    task: *mut RawTask,
    attr: *mut TaskAttr,
    fun: extern "C" fn(*mut c_void) -> *mut c_void,
    arg: *mut c_void,
) -> ZResult {
    sys(libc::pthread_create(task, attr, fun, arg))
}

/// Wait for a started task to finish. The handle is not null.
///
/// # Safety
/// `handle` must be a task `task_spawn` started and nothing has joined or detached.
pub unsafe fn task_join(handle: RawTask) -> ZResult {
    sys(libc::pthread_join(handle, std::ptr::null_mut()))
}

/// Release a started task WITHOUT waiting. The handle is not null.
///
/// # Safety
/// As `task_join`.
pub unsafe fn task_detach(handle: RawTask) -> ZResult {
    sys(libc::pthread_detach(handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(tv_sec: i64, tv_nsec: i64) -> Clock {
        libc::timespec { tv_sec, tv_nsec }
    }

    /// The carry in `clock_advance` is ONE borrow, and it has to fire when the
    /// nanosecond field crosses 1e9, the single arithmetic step in this family that a
    /// plausible implementation gets wrong by omitting.
    #[test]
    fn advancing_a_clock_normalises_exactly_one_carry() {
        let mut c = at(100, 900_000_000);
        clock_advance(&mut c, Unit::Milli, 200);
        assert_eq!(c.tv_sec, 101, "the carry fired");
        assert_eq!(c.tv_nsec, 100_000_000);

        // No carry when the sum stays below 1e9.
        let mut d = at(5, 1_000);
        clock_advance(&mut d, Unit::Micro, 999);
        assert_eq!((d.tv_sec, d.tv_nsec), (5, 1_000_000));

        // The seconds arm touches only `tv_sec`.
        let mut e = at(7, 123);
        clock_advance(&mut e, Unit::Second, 3);
        assert_eq!((e.tv_sec, e.tv_nsec), (10, 123));
    }

    /// `clock_elapsed_between` CLAMPS a negative interval to zero and DROPS the
    /// sub-second part in the seconds arm. Both are upstream behaviours a `Duration`
    /// subtraction would get wrong in opposite directions (panic, and rounding up).
    #[test]
    fn elapsed_between_clamps_backwards_and_truncates_seconds() {
        let early = at(10, 0);
        let late = at(11, 500_000_000);
        assert_eq!(clock_elapsed_between(&late, &early, Unit::Milli), 1_500);
        assert_eq!(clock_elapsed_between(&late, &early, Unit::Micro), 1_500_000);
        assert_eq!(
            clock_elapsed_between(&late, &early, Unit::Second),
            1,
            "1.5 s truncates to 1, it does not round to 2"
        );
        // Backwards: clamped, not wrapped.
        assert_eq!(clock_elapsed_between(&early, &late, Unit::Milli), 0);
        assert_eq!(clock_elapsed_between(&early, &late, Unit::Second), 0);
    }

    /// The WALL clock family does NOT clamp: upstream casts a signed difference to
    /// `unsigned long`, so a future timestamp wraps. Pinned because it is the
    /// opposite of the monotonic family above, and "obviously both should clamp" is
    /// the plausible wrong repair.
    #[test]
    fn a_future_wall_time_wraps_rather_than_clamping() {
        let now = wall_now();
        let future = libc::timeval {
            tv_sec: now.tv_sec + 3_600,
            tv_usec: now.tv_usec,
        };
        let elapsed = wall_elapsed(&future, Unit::Second);
        assert!(
            elapsed > u64::from(u32::MAX) as c_ulong,
            "a future wall time must WRAP (got {elapsed}), which is what upstream's \
             unsigned cast does"
        );
    }

    /// The ABI claim this layer rests on, asserted rather than assumed: the owned
    /// structs a C program stack-allocates through pico's header are 40 (64 on macOS)
    /// and 48 bytes, and those are the sizes the pthread objects wz initialises in
    /// place occupy.
    #[test]
    fn owned_sync_types_match_picos_measured_sizes() {
        // Linux: measured. macOS: `__sig` plus `__opaque[56]` for the mutex and
        // `__opaque[40]` for the condvar, read off Darwin's layout.
        let mutex_bytes = if cfg!(target_os = "macos") { 64 } else { 40 };
        assert_eq!(std::mem::size_of::<RawMutex>(), mutex_bytes);
        assert_eq!(std::mem::size_of::<RawCondvar>(), 48);
    }

    // The constants above are a claim read off a header; this is the measurement.
    // pico's unix layer types its mutex, condvar and task attribute as the host's
    // `pthread_*_t` (system/platform/unix.h), so the host C compiler's own `sizeof` is
    // the layout pico programs see, and the Rust types must be exactly that large on
    // every host that builds them. A missing compiler fails the test; it is never a
    // skip.
    #[test]
    fn owned_sync_types_match_the_host_c_compilers_pthread_sizes() {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let source = "#include <pthread.h>\n#include <stdio.h>\n\
                      int main(void) { printf(\"%zu %zu %zu\\n\", sizeof(pthread_attr_t), \
                      sizeof(pthread_mutex_t), sizeof(pthread_cond_t)); return 0; }\n";
        let exe =
            std::env::temp_dir().join(format!("wz_capi_pico_pthread_sizes_{}", std::process::id()));
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
        let mut compile = Command::new(&cc)
            .args(["-x", "c", "-", "-o"])
            .arg(&exe)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("the host C compiler `{cc}` could not be started: {e}"));
        compile
            .stdin
            .take()
            .expect("the compiler's stdin is piped")
            .write_all(source.as_bytes())
            .expect("the probe source reaches the compiler");
        assert!(compile.wait().expect("the compiler finishes").success());
        let out = Command::new(&exe)
            .output()
            .expect("the compiled probe runs");
        std::fs::remove_file(&exe).expect("the probe binary is removed");
        assert!(out.status.success());
        let measured: Vec<usize> = String::from_utf8(out.stdout)
            .expect("the probe prints ASCII")
            .split_whitespace()
            .map(|n| n.parse().expect("the probe prints three integers"))
            .collect();
        assert_eq!(
            measured,
            [
                std::mem::size_of::<TaskAttr>(),
                std::mem::size_of::<RawMutex>(),
                std::mem::size_of::<RawCondvar>(),
            ],
            "pthread_attr_t, pthread_mutex_t, pthread_cond_t as the host C compiler sizes them"
        );
    }

    /// The one place the macOS condvar wait differs, tested where the tests run.
    #[test]
    fn a_relative_deadline_is_the_interval_to_the_instant_or_zero() {
        let same = |a: Clock, b: Clock| a.tv_sec == b.tv_sec && a.tv_nsec == b.tv_nsec;
        // Later in the same second, and across a second boundary with a borrow.
        assert!(same(
            relative_deadline(at(10, 100), at(10, 600)),
            at(0, 500)
        ));
        assert!(same(
            relative_deadline(at(10, 900_000_000), at(12, 100_000_000)),
            at(1, 200_000_000)
        ));
        assert!(same(relative_deadline(at(10, 0), at(12, 0)), at(2, 0)));
        // Now, and any instant already past, are zero, never a negative interval.
        assert!(same(relative_deadline(at(10, 500), at(10, 500)), at(0, 0)));
        assert!(same(relative_deadline(at(10, 600), at(10, 500)), at(0, 0)));
        assert!(same(
            relative_deadline(at(11, 0), at(10, 999_999_999)),
            at(0, 0)
        ));
    }
}
