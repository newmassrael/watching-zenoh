// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Windows host's calls: the wait on an address that the locks, the condition variables and
//! the parker sleep on, the clocks, the threads, and the sleep.

use core::ffi::c_void;
use core::sync::atomic::AtomicU32;

use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows_sys::Win32::System::Environment::{FreeEnvironmentStringsA, GetEnvironmentStrings};
use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
use windows_sys::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime;
use windows_sys::Win32::System::Threading::{
    CreateThread, GetCurrentThreadId, Sleep, WaitForSingleObject, WaitOnAddress, WakeByAddressAll,
    WakeByAddressSingle, INFINITE,
};

/// Sleep while `word` reads `expected`, until a wake on it or, with a deadline, until the
/// performance counter reads `deadline_ns`. It may end sooner: the caller reads the word again.
/// The wait takes the milliseconds left, rounded up so that it does not end before the deadline.
#[inline(never)]
pub(crate) fn wait(word: &AtomicU32, expected: u32, deadline_ns: Option<u64>) {
    let ms = deadline_ns.map_or(INFINITE, |deadline| {
        deadline
            .saturating_sub(monotonic_ns())
            .div_ceil(1_000_000)
            .min(u64::from(INFINITE - 1)) as u32
    });
    // SAFETY: the word and `expected` are live 32-bit integers, which the wait compares.
    unsafe {
        WaitOnAddress(
            core::ptr::from_ref(word).cast(),
            core::ptr::from_ref(&expected).cast(),
            core::mem::size_of::<u32>(),
            ms,
        );
    }
}

/// Wake one thread asleep on `word`.
#[inline(never)]
pub(crate) fn wake_one(word: &AtomicU32) {
    // SAFETY: a wake reads no memory; the address only names the threads asleep on it.
    unsafe { WakeByAddressSingle(core::ptr::from_ref(word).cast()) };
}

/// Wake every thread asleep on `word`.
#[inline(never)]
pub(crate) fn wake_all(word: &AtomicU32) {
    // SAFETY: as in `wake_one`.
    unsafe { WakeByAddressAll(core::ptr::from_ref(word).cast()) };
}

/// The hundreds of nanoseconds from 1601-01-01, where a `FILETIME` counts from, to the Unix epoch.
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// The precise system time: the seconds and nanoseconds since the Unix epoch, `None` before it.
pub(crate) fn wall_clock() -> Option<(u64, u32)> {
    let mut now = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: a live local the call writes.
    unsafe { GetSystemTimePreciseAsFileTime(&mut now) };
    let ticks = (u64::from(now.dwHighDateTime) << 32) | u64::from(now.dwLowDateTime);
    let since = ticks.checked_sub(FILETIME_UNIX_EPOCH)?;
    Some((since / 10_000_000, ((since % 10_000_000) * 100) as u32))
}

/// The performance counter in nanoseconds.
pub(crate) fn monotonic_ns() -> u64 {
    let mut ticks = 0_i64;
    let mut per_second = 0_i64;
    // SAFETY: live locals the calls write.
    unsafe {
        QueryPerformanceCounter(&mut ticks);
        QueryPerformanceFrequency(&mut per_second);
    }
    crate::counter::ticks_to_ns(ticks, per_second)
}

/// A thread of the system, by its handle.
pub(crate) type Thread = HANDLE;

unsafe extern "system" fn entry(arg: *mut c_void) -> u32 {
    crate::enter(arg);
    0
}

/// Start a thread that calls `crate::enter` with `arg`.
///
/// # Safety
/// `arg` is what `crate::enter` is to be called with, valid until it has run.
pub(crate) unsafe fn spawn(arg: *mut c_void) -> Option<(Thread, usize)> {
    let mut id = 0u32;
    let handle = CreateThread(
        core::ptr::null(),
        0,
        Some(entry),
        arg.cast_const(),
        0,
        &mut id,
    );
    if handle.is_null() {
        return None;
    }
    // The number `GetCurrentThreadId` answers on the new thread.
    Some((handle, id as usize))
}

pub(crate) fn current_thread() -> usize {
    // SAFETY: no argument; any thread.
    unsafe { GetCurrentThreadId() as usize }
}

pub(crate) fn env_var<R>(name: &core::ffi::CStr, read: impl FnOnce(Option<&[u8]>) -> R) -> R {
    // SAFETY: no argument; the block is the system's copy of the environment, given back below.
    let block = unsafe { GetEnvironmentStrings() };
    if block.is_null() {
        return read(None);
    }
    // SAFETY: the block is as `value_in` asks, and stands until it is given back below, after
    // `read` has returned.
    let answer = read(unsafe { value_in(block.cast_const(), name.to_bytes()) });
    // SAFETY: the block the call above gave, given back once.
    unsafe { FreeEnvironmentStringsA(block.cast_const()) };
    answer
}

/// The value of the entry of `block` that `name` names.
///
/// # Safety
/// `block` is a run of `NAME=VALUE` strings, each ended by its NUL and the run by an empty one, as
/// `GetEnvironmentStrings` gives it, and stands for `'a`.
unsafe fn value_in<'a>(block: *const u8, name: &[u8]) -> Option<&'a [u8]> {
    let mut at = block;
    loop {
        // SAFETY: `at` is the start of an entry of the block (the caller's contract).
        let entry = unsafe { core::ffi::CStr::from_ptr(at.cast()) }.to_bytes();
        if entry.is_empty() {
            return None;
        }
        if let Some(value) = value_of(entry, name) {
            return Some(value);
        }
        // SAFETY: the entry's NUL lies in the block, and the next entry starts past it.
        at = unsafe { at.add(entry.len().saturating_add(1)) };
    }
}

/// The value of `entry` when `name` names it: the names compared as Windows compares them, without
/// regard to ASCII case.
fn value_of<'a>(entry: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let (named, rest) = entry.split_at_checked(name.len())?;
    if named.eq_ignore_ascii_case(name) {
        rest.strip_prefix(b"=")
    } else {
        None
    }
}

/// # Safety
/// `thread` is a started thread's handle that nothing has joined or detached.
pub(crate) unsafe fn join(thread: Thread) {
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
}

/// Closing the handle is what lets a Windows thread go; it runs on.
///
/// # Safety
/// As [`join`].
pub(crate) unsafe fn detach(thread: Thread) {
    CloseHandle(thread);
}

/// `Sleep` takes a 32-bit count whose largest value is `INFINITE`, so a longer sleep is taken in
/// parts.
pub(crate) fn sleep_ms(ms: u64) {
    let mut left = ms;
    loop {
        let part = left.min(u64::from(INFINITE - 1));
        // SAFETY: any thread, any count below `INFINITE`.
        unsafe { Sleep(part as u32) };
        left -= part;
        if left == 0 {
            break;
        }
    }
}

/// `Sleep` counts whole milliseconds; a part of one is rounded up, so the sleep is at least what
/// was asked.
pub(crate) fn sleep_us(us: u64) {
    sleep_ms(us.div_ceil(1_000));
}

#[cfg(test)]
mod tests {
    use super::value_of;

    /// An entry is the name's when its name matches without regard to ASCII case and an `=`
    /// follows it; a longer name that starts with it, or a drive's `=C:` entry, is not. Turned red
    /// by a match that is case-sensitive or that takes a prefix of a name.
    #[test]
    fn an_entry_is_named_by_its_whole_name_in_any_case() {
        assert_eq!(value_of(b"Uhlc_Max=700", b"UHLC_MAX"), Some(&b"700"[..]));
        assert_eq!(value_of(b"UHLC_MAX=", b"UHLC_MAX"), Some(&b""[..]));
        assert_eq!(value_of(b"UHLC_MAXIMUM=1", b"UHLC_MAX"), None);
        assert_eq!(value_of(b"=C:=C:\\", b"UHLC_MAX"), None);
        assert_eq!(value_of(b"UHLC", b"UHLC_MAX"), None);
    }
}
