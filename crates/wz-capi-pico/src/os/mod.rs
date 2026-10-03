// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host layer under the platform and sync exports.
//!
//! zenoh-pico ships one system backend per host (`system/unix/system.c`,
//! `system/windows/system.c`, ...). The exports a C program links are the same on
//! all of them, but the bytes behind them are not: the header the program compiled
//! against types a mutex as `pthread_mutex_t` on a Unix and as `SRWLOCK` on Windows,
//! its clock as a `timespec` and as a performance-counter reading, its task as a
//! `pthread_t` and as a thread `HANDLE`. The program stack-allocates those values
//! before wz sees them, so the layout is decided by the host and the only correct
//! implementation is the one pico's own backend for that host has.
//!
//! This module is that split. `platform` and `sync` keep the exports, with their
//! null checks and panic guards, and hand every operation whose bytes or semantics
//! differ by host to the one backend this build selects. A new host is one new file
//! here that provides the same names, and a host with none is a compile error that
//! says so, never a link error in a C program.
//!
//! Every backend provides: the types `Clock`, `WallTime`, `RawMutex`, `RawCondvar`,
//! `RawTask` and `TaskAttr`; the constant `TASK_NULL`; and the functions `clock_now`, `clock_elapsed_between`, `clock_advance`, `wall_now`,
//! `wall_elapsed`, `wall_render_local`, `random_fill`, `mutex_init`, `mutex_destroy`,
//! `mutex_lock`, `mutex_try_lock`, `mutex_unlock`, `condvar_init`, `condvar_destroy`,
//! `condvar_signal`, `condvar_wait`, `condvar_wait_until`, `task_spawn`, `task_join`
//! and `task_detach`. The ones that can fail return the code pico's own backend for
//! that host returns, because a C caller reads that code.

/// The unit of a duration or an interval, shared by the clock and wall-time
/// operations so that one backend function serves the micro, milli and whole-second
/// exports without three copies of its arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unit {
    Micro,
    Milli,
    Second,
}

// The pure arithmetic of the Windows backend. It is plain integer and floating-point
// work on numbers the Win32 calls return, so it compiles on every host and is tested
// where the tests run, which is how a Windows rule gets a unit test from a Linux
// build; a Windows build uses it, and a Unix build compiles it for those tests only.
#[cfg(any(windows, test))]
mod arith;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(crate) use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::*;

#[cfg(not(any(unix, windows)))]
compile_error!(
    "wz-capi-pico has no host layer for this target: add src/os/<host>.rs providing the \
     names listed in src/os/mod.rs, modelled on zenoh-pico's system/<host>/system.c"
);
