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
//! 2. [`PosixEntropy`] -- the session core's `EntropySource`, over `getrandom(2)` (macOS:
//!    `getentropy(2)`).
//! 3. [`PosixEpoch`] -- the session core's `EpochSource`, over `clock_gettime(CLOCK_REALTIME)`.
//! 4. [`net`] -- UDP over the kernel's sockets ([`net::PosixUdpSocket`]), the socket the shared
//!    link is written against; and, under `session-slot`, [`slot`], the stack the slot profile's
//!    session host is given over it. [`stream`] -- TCP over the same, ([`stream::PosixTcpSocket`]),
//!    the socket the shared stream link (`wz_runtime_coop::stream_link`) is written against.
//!    [`group`](mod@group) -- a multicast group's two sockets as the group transport the shared
//!    group drive loop runs on, written once over either host's sockets. Under `host-multicast`,
//!    what a node on a host opens beside them, over either host's sockets too: `interfaces`, the
//!    host's interface table; `multicast`, a group's sockets made by the policy its locator states,
//!    as the transport of a session's group face; and `scouting`, a scouting window's sockets.
//! 5. [`file`](mod@file) -- a file read whole into the caller's buffer, and a secret read only when its
//!    owner alone may read it: a document provisioned to the device apart from the program.
//! 6. [`glue`] -- the console line and the sleep, and [`posix_image_no_heap!`], the image glue
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
//! The POSIX hosts are Linux, Android, QNX Neutrino and macOS. Two OS calls differ between them
//! and are named once each: `errno` (glibc's `__errno_location`, bionic's `__errno`, Neutrino's
//! `__get_errno_ptr`, Darwin's `__error`) and the entropy (`getrandom(2)` on Linux and Android,
//! `getentropy(2)` on macOS; Neutrino 7.1's C library has neither, so `/dev/urandom` is read). A
//! socket the four make alike is made by one code path, and the one thing Linux has that Neutrino
//! does not (`SOCK_NONBLOCK`, `accept4`) is two calls where Linux has one. macOS has no
//! `SOCK_CLOEXEC` either, so its socket is made close-on-exec by a call of its own, and a write to
//! a stream whose peer is gone is kept from raising SIGPIPE by the socket's `SO_NOSIGPIPE`, the way
//! Darwin states it, where the others pass `MSG_NOSIGNAL` to each send.
//!
//! Windows is the one host that is not POSIX: its calls are the system's own (the performance
//! counter, the system's random number generator, Winsock), and they are
#![cfg_attr(windows, doc = "[`windows`](mod@windows),")]
#![cfg_attr(not(windows), doc = "`windows` (a module of the Windows build),")]
//! the clock, entropy, wall clock and sockets the pico C ABI's cooperative engine is opened over,
//! and the slot profile's stack over the same sockets. Every item above but `group` is the POSIX
//! half's, compiled on a POSIX host only; `group` is written once over either host's sockets. On another OS this crate
//! is empty, so a workspace-wide build there does not stop on it; a port names its own calls here.
#![no_std]
#![cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "nto",
    target_os = "macos",
    windows
))]

#[cfg(test)]
extern crate std;

// The heap profile's waits share a session's wake among its wakers (`net::PosixWaits::wake`), and a
// group keeps what it receives (`multicast`).
#[cfg(any(
    all(feature = "alloc", not(feature = "session-slot")),
    feature = "host-multicast"
))]
extern crate alloc;

#[cfg(unix)]
pub mod control;
#[cfg(unix)]
pub mod file;
#[cfg(unix)]
pub mod glue;
// A multicast group's two sockets as the group transport, over either host's sockets.
pub mod group;
#[cfg(feature = "host-multicast")]
pub mod interfaces;
#[cfg(feature = "host-multicast")]
pub mod multicast;
#[cfg(feature = "host-multicast")]
pub mod scouting;

// The waits over several links of the heap profile (`net::PosixWaits`, `windows::WindowsWaits`).
wz_runtime_coop::with_heap_link_seams! {
    /// How many sockets one wait over several links names to the system. The set lies on the
    /// waiting thread's stack, so a wait allocates nothing, as zenoh-pico's wait over its sockets is
    /// an `fd_set` there, of `FD_SETSIZE` sockets on Windows, 64
    /// (`vendor/zenoh-pico/src/system/windows/network.c` @ `fd_set read_fds;`). A wait over more
    /// is the bounded look the runtime gives a wait it cannot name to the system
    /// (`LinkWaits::wait`): it ends within a millisecond, and the step after it
    /// reads every link.
    pub(crate) const WAIT_SET_SOCKETS: usize = 64;

    /// Move the entries of `on` that `ready` answers for to its front, and answer how many they
    /// are: what a host's wait does with what its poll found
    /// (`LinkWaits::wait_ready`). `ready` is asked of each entry once, front to back, so a poll's
    /// entries, filled in that order, are read in it.
    pub(crate) fn front_the_ready(
        on: &mut [wz_runtime_coop::session_drive::LinkWait],
        mut ready: impl FnMut(&wz_runtime_coop::session_drive::LinkWait) -> bool,
    ) -> usize {
        let mut front = 0;
        for at in 0..on.len() {
            let Some(wait) = on.get(at) else {
                break;
            };
            if ready(wait) {
                // `front` never passes `at`, so the window holds both, and a window of one entry
                // is that entry left where it stands.
                if let Some([first, .., last]) = on.get_mut(front..=at) {
                    core::mem::swap(first, last);
                }
                front += 1;
            }
        }
        front
    }

    #[cfg(test)]
    mod front_the_ready_tests {
        use wz_runtime_coop::session_drive::{LinkWait, WaitOn};

        fn wait(handle: u64) -> LinkWait {
            LinkWait::input(WaitOn::AppLink(handle))
        }

        /// The entries found ready come to the front in the order they stood, each swapped with
        /// the first entry not yet found ready; the rest keep what is left of the set. Every entry
        /// is asked once, front to back. Turned red by a swap that leaves an entry where it stood,
        /// or by a count that is not the number found.
        #[test]
        fn the_ready_entries_come_to_the_front_in_their_order() {
            let mut set = [wait(0), wait(1), wait(2), wait(3)];
            let mut asked = [0u64; 4];
            let mut times = 0;
            let found = super::front_the_ready(&mut set, |entry| {
                let WaitOn::AppLink(handle) = entry.on else {
                    return false;
                };
                if let Some(slot) = asked.get_mut(times) {
                    *slot = handle;
                }
                times += 1;
                handle % 2 == 1
            });
            assert_eq!(found, 2);
            assert_eq!(set, [wait(1), wait(3), wait(2), wait(0)]);
            assert_eq!((times, asked), (4, [0, 1, 2, 3]));
        }

        /// A set found all ready stays as it stood, and one found none ready answers none and
        /// stays too; an empty set answers none. CONTROL for the swap above: an entry swapped
        /// with itself is left in place.
        #[test]
        fn all_ready_or_none_ready_leaves_the_set_as_it_stood() {
            let mut all = [wait(5), wait(6), wait(7)];
            assert_eq!(super::front_the_ready(&mut all, |_| true), 3);
            assert_eq!(all, [wait(5), wait(6), wait(7)]);
            let mut none = [wait(5), wait(6)];
            assert_eq!(super::front_the_ready(&mut none, |_| false), 0);
            assert_eq!(none, [wait(5), wait(6)]);
            let mut empty: [LinkWait; 0] = [];
            assert_eq!(super::front_the_ready(&mut empty, |_| true), 0);
        }
    }
}

// Written over the runtime's heap link layer, so compiled where the runtime declares it.
wz_runtime_coop::with_heap_link_seams! {
    #[cfg(all(unix, feature = "alloc"))]
    pub mod links;
}
#[cfg(unix)]
pub mod net;
/// The host's raw packet sockets as the devices of the cooperative engine's `reth/` groups, on
/// Linux.
#[cfg(all(feature = "raweth", not(feature = "session-slot")))]
pub mod raweth;
// The host's ttys as the lines of the cooperative engine's serial links, on Linux and Android
// (documented from inside, so its links resolve in the module).
// A host name handed to the host's resolver and its answer kept, for `net` and `windows`.
mod resolve;
#[cfg(feature = "serial")]
pub mod serial;
#[cfg(feature = "session-slot")]
pub mod slot;
#[cfg(unix)]
pub mod stream;
// The host's named FIFOs as the ends of the cooperative engine's unixpipe links, on Linux and
// Android. The heap profile's, as the engine's unixpipe links are: a slot build has none.
#[cfg(all(feature = "unixpipe", not(feature = "session-slot")))]
pub mod unixpipe;
#[cfg(windows)]
pub mod windows;
/// The host's TCP connections, clock and entropy as what the cooperative engine's WebSocket links
/// open with.
#[cfg(all(unix, feature = "ws"))]
pub mod ws;
// The Windows host's arithmetic, compiled where the tests run so that a Linux build checks it.
#[cfg(any(windows, test))]
mod windows_arith;

#[cfg(unix)]
use wz_runtime_coop::ClockSource;

/// Monotonic [`ClockSource`] over `clock_gettime(CLOCK_MONOTONIC)`.
///
/// Zero-sized and `Copy`: the clock is the kernel's. The monotonic contract holds by the
/// kernel's: `CLOCK_MONOTONIC` never steps back. It is not the wall clock (see [`PosixEpoch`]),
/// so a date set by an administrator moves no timer of a session.
#[cfg(unix)]
#[derive(Clone, Copy, Default)]
pub struct PosixClock;

#[cfg(unix)]
impl ClockSource for PosixClock {
    // Out of line: the session's readers call this one body, and a stream's wait for room, which
    // reads the clock on both sides of its poll, would otherwise carry two copies of it.
    #[inline(never)]
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
/// `getrandom(2)` (`getentropy(2)` on macOS; on Neutrino, which has neither, a read of
/// `/dev/urandom`): the kernel's CSPRNG. A call that returns fewer bytes than asked is asked again
/// for the rest; one that fails, fails the fill -- the cookie nonce and the signing key must never
/// be made of whatever the buffer held.
#[cfg(unix)]
#[derive(Clone, Copy, Default)]
pub struct PosixEntropy;

#[cfg(unix)]
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

/// macOS has no `getrandom`; `getentropy(2)` is its call to the kernel's generator, and it fills
/// at most `GETENTROPY_MAX` bytes a call (`EIO` past that), so a longer fill is asked in pieces
/// by the caller's loop, as a short `getrandom` is.
#[cfg(target_os = "macos")]
fn random_bytes(rest: &mut [u8]) -> usize {
    let take = rest.len().min(GETENTROPY_MAX);
    // SAFETY: the first `take` bytes of `rest` are live and writable.
    if unsafe { libc::getentropy(rest.as_mut_ptr().cast(), take) } == 0 {
        take
    } else {
        0
    }
}

/// The most bytes one `getentropy(2)` call fills (`<sys/random.h>`, `GETENTROPY_MAX`).
#[cfg(target_os = "macos")]
const GETENTROPY_MAX: usize = 256;

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
#[cfg(unix)]
#[derive(Clone, Copy, Default)]
pub struct PosixEpoch;

#[cfg(unix)]
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
#[cfg(unix)]
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

#[cfg(all(test, unix))]
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
        // More than one call gives (`getrandom` on a small-limit kernel, `getentropy`'s 256 bytes
        // on macOS) still fills whole.
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
