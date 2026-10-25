// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz-runtime-posix` -- the host **cooperative single-thread profile with no allocator**.
//!
//! The same shape as `wz-runtime-zephyr`: it does not reimplement the executor or the link. The
//! audited [`wz_runtime_coop::CoopRuntime`] runs inside ONE thread, the session code is the
//! shared MCU code, and the datagram link is `wz_runtime_coop::udp_link`. This crate supplies the
//! host's SEAMS, over the C library:
//!
//! 1. [`PosixClock`] -- a [`ClockSource`] over `clock_gettime(CLOCK_MONOTONIC)`.
//! 2. [`PosixEntropy`] -- the session core's `EntropySource`, over `getrandom(2)`.
//! 3. [`PosixEpoch`] -- the session core's `EpochSource`, over `clock_gettime(CLOCK_REALTIME)`.
//! 4. [`net`] -- UDP over the kernel's sockets ([`net::PosixUdpSocket`]), the socket the shared
//!    link is written against; and, under `session-slot`, [`slot`], the stack the slot profile's
//!    session host is given over it. [`stream`] -- TCP over the same, ([`stream::PosixTcpSocket`]),
//!    the socket the shared stream link (`wz_runtime_coop::stream_link`) is written against.
//! 5. [`glue`] -- the console line and the sleep, and [`posix_image_no_heap!`], the image glue
//!    (a `critical_section` implementation and the panic handler) of a `#![no_std]`
//!    `#![no_main]` program.
//!
//! A program built from this crate declares no `#[global_allocator]`: it is a `#![no_std]` binary,
//! so a reference to the `alloc` crate anywhere in its graph does not link ("no global memory
//! allocator found"). That is the whole-program proof the kit's image relies on, here at a Linux
//! process. The kernel allocates for the process (socket buffers, page tables); the program's own
//! code does not.
//!
//! The profile is single-threaded by construction, and the `critical_section` implementation says
//! so: it takes no lock, because nothing else runs.
//!
//! Linux, Android and QNX Neutrino only. Two OS calls differ between them and are named once each:
//! `errno` (glibc's `__errno_location`, bionic's `__errno`, Neutrino's `__get_errno_ptr`) and the
//! entropy (`getrandom(2)` on Linux and Android; Neutrino 7.1's C library has none, so
//! `/dev/urandom` is read). A socket the three make alike is made by one code path, and the one
//! thing Linux has that Neutrino does not (`SOCK_NONBLOCK`, `accept4`) is two calls where Linux has
//! one. On another OS this crate is empty, so a workspace-wide build there does not stop on it; a
//! port names its own calls here.
#![no_std]
#![cfg(any(target_os = "linux", target_os = "android", target_os = "nto"))]

#[cfg(test)]
extern crate std;

// The heap profile's links hand their owner a boxed wait on their socket (`net::FdReadiness`).
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
extern crate alloc;

pub mod glue;
pub mod group;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub mod links;
pub mod net;
#[cfg(feature = "session-slot")]
pub mod slot;
pub mod stream;

use wz_runtime_coop::ClockSource;

/// Monotonic [`ClockSource`] over `clock_gettime(CLOCK_MONOTONIC)`.
///
/// Zero-sized and `Copy`: the clock is the kernel's. The monotonic contract holds by the
/// kernel's: `CLOCK_MONOTONIC` never steps back. It is not the wall clock (see [`PosixEpoch`]),
/// so a date set by an administrator moves no timer of a session.
#[derive(Clone, Copy, Default)]
pub struct PosixClock;

impl ClockSource for PosixClock {
    fn now_us(&self) -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a live `timespec` the call writes; the clock id is a constant the
        // kernel defines.
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        // `CLOCK_MONOTONIC` cannot fail with a valid pointer; a refusal reads as time stood still
        // rather than as a jump, which the monotonic contract allows.
        if rc != 0 {
            return 0;
        }
        (ts.tv_sec as u64) * 1_000_000 + (ts.tv_nsec as u64) / 1_000
    }
}

/// The session core's [`EntropySource`](wz_session_core::entropy::EntropySource) over
/// `getrandom(2)` (on Neutrino, which has none, a read of `/dev/urandom`): the kernel's CSPRNG. A
/// call that returns fewer bytes than asked is asked again for the rest; one that fails, fails the
/// fill -- the cookie nonce and the signing key must never be made of whatever the buffer held.
#[derive(Clone, Copy, Default)]
pub struct PosixEntropy;

impl wz_session_core::entropy::EntropySource for PosixEntropy {
    fn try_fill_bytes(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(), wz_session_core::entropy::EntropyUnavailable> {
        let mut filled = 0;
        while filled < buf.len() {
            let rest = &mut buf[filled..];
            let got = random_bytes(rest);
            if got == 0 {
                return Err(wz_session_core::entropy::EntropyUnavailable);
            }
            filled += got;
        }
        Ok(())
    }
}

/// Fill the front of `rest` from the kernel's CSPRNG: how many bytes it gave, none when it could
/// not.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn random_bytes(rest: &mut [u8]) -> usize {
    // SAFETY: `rest` is live and writable for its whole length.
    let got = unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
    usize::try_from(got).unwrap_or(0)
}

/// Neutrino 7.1's C library has no `getrandom` and no `getentropy`; its random service answers
/// reads of `/dev/urandom`. The descriptor is opened for the read and closed after it, so the node
/// holds none between fills, and a service that is not running makes the fill fail, which is
/// refused and not guessed.
#[cfg(target_os = "nto")]
fn random_bytes(rest: &mut [u8]) -> usize {
    // SAFETY: the path is a NUL-terminated literal; the descriptor is this call's own.
    let fd = unsafe { libc::open(c"/dev/urandom".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return 0;
    }
    // SAFETY: `rest` is live and writable for its whole length; `fd` is open.
    let got = unsafe { libc::read(fd, rest.as_mut_ptr().cast(), rest.len()) };
    // SAFETY: `fd` is this call's own descriptor, closed exactly once.
    unsafe { libc::close(fd) };
    usize::try_from(got).unwrap_or(0)
}

/// The session core's [`EpochSource`](wz_session_core::epoch::EpochSource) over
/// `clock_gettime(CLOCK_REALTIME)`: the date. A read the kernel refuses, or a nanosecond count at
/// or above a second, is refused rather than normalised.
#[derive(Clone, Copy, Default)]
pub struct PosixEpoch;

impl wz_session_core::epoch::EpochSource for PosixEpoch {
    fn try_since_epoch(
        &self,
    ) -> Result<wz_session_core::epoch::SinceEpoch, wz_session_core::epoch::EpochUnavailable> {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a live `timespec` the call writes.
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
        if rc != 0 || ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
            return Err(wz_session_core::epoch::EpochUnavailable);
        }
        Ok(wz_session_core::epoch::SinceEpoch {
            secs: ts.tv_sec as u64,
            nanos: ts.tv_nsec as u32,
        })
    }
}

/// A host program's image glue with NO allocator, written once in its crate root: a
/// `critical_section` implementation and the panic handler ([`glue::abort_after_panic`]). It
/// declares no `#[global_allocator]`, so a build that allocates anywhere in its graph does not
/// link, which is the proof the no-allocator link gate reads.
///
/// The `critical_section` implementation takes no lock and masks nothing: the profile runs the
/// whole program on ONE thread and installs no signal handler that touches the runtime, so there
/// is nothing a critical section would exclude. A program that starts a second thread leaves the
/// profile, and this implementation with it.
///
/// The program depends on `critical-section` itself, because the macro's expansion names it: an
/// implementation has to be in the final crate, which a dependency's is not guaranteed to be.
///
/// ```ignore
/// wz_runtime_posix::posix_image_no_heap!();
/// ```
#[macro_export]
macro_rules! posix_image_no_heap {
    () => {
        struct WzPosixCriticalSection;
        critical_section::set_impl!(WzPosixCriticalSection);

        // SAFETY: one thread runs the whole program (the profile's rule), so a critical section
        // has nothing to exclude and the restore state is the unit.
        unsafe impl critical_section::Impl for WzPosixCriticalSection {
            unsafe fn acquire() -> critical_section::RawRestoreState {}

            unsafe fn release(_state: critical_section::RawRestoreState) {}
        }

        #[panic_handler]
        fn wz_posix_panic(_info: &core::panic::PanicInfo) -> ! {
            $crate::glue::abort_after_panic()
        }

        // The toolchain's prebuilt `core` names a personality routine in its unwind tables. A
        // release link with LTO drops the tables with the code that uses them; a debug link keeps
        // them and so keeps the name, which `std` would have supplied and an image that links no
        // `std` must. The image is built `panic = "abort"`, so nothing unwinds and nothing calls
        // this: it is the name satisfied, and if it were ever reached the answer is the panic
        // handler's.
        #[unsafe(no_mangle)]
        extern "C" fn rust_eh_personality() -> ! {
            $crate::glue::abort_after_panic()
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::entropy::EntropySource;
    use wz_session_core::epoch::EpochSource;

    #[test]
    fn the_clock_does_not_step_back_and_moves() {
        let clock = PosixClock;
        let first = clock.now_us();
        let mut last = first;
        for _ in 0..1000 {
            let now = clock.now_us();
            assert!(now >= last, "a monotonic clock does not step back");
            last = now;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(clock.now_us() >= first + 1_500, "two milliseconds pass");
    }

    #[test]
    fn entropy_fills_the_whole_buffer_and_differs_between_draws() {
        let mut entropy = PosixEntropy;
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        entropy.try_fill_bytes(&mut a).expect("getrandom works");
        entropy.try_fill_bytes(&mut b).expect("getrandom works");
        assert_ne!(a, [0u8; 64], "64 zero bytes from a CSPRNG is not a draw");
        assert_ne!(a, b, "two draws of 64 bytes are not the same");
        // More than `getrandom` returns at once on a small-limit kernel still fills whole.
        let mut big = [0u8; 4096];
        entropy.try_fill_bytes(&mut big).expect("a large fill");
        assert_ne!(&big[..64], &[0u8; 64][..]);
    }

    #[test]
    fn the_wall_clock_is_after_2020() {
        let now = PosixEpoch.try_since_epoch().expect("a date");
        assert!(now.secs > 1_577_836_800, "the host's date is after 2020");
        assert!(now.nanos < 1_000_000_000);
    }
}
