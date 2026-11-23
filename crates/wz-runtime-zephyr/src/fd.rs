// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The close of a Zephyr socket descriptor, and the waits another thread makes on several.
//!
//! A socket of this crate closes its descriptor when it is dropped. On the heap profile a thread
//! that does not drive the link may also wait for the socket's input: the pico C ABI's read task
//! waits outside the session's lock, while the session may let the link go under it. The wait
//! names the descriptor by its number ([`WaitOn`](wz_runtime_coop::session_drive::WaitOn)) and
//! holds nothing of it, so a wait made after the socket was closed polls a number the stack may
//! have given another socket: a hint, as every answer is, and the step that follows looks again
//! under the session's lock.

use core::ffi::c_int;

use zephyr_sys::socket::close;

/// What closes a socket's descriptor once, when the socket is dropped.
pub(crate) struct FdClose(c_int);

impl FdClose {
    /// The close of `fd`, which the caller hands over: nothing else closes it.
    pub(crate) fn new(fd: c_int) -> Self {
        Self(fd)
    }
}

impl Drop for FdClose {
    fn drop(&mut self) {
        // SAFETY: the descriptor this owns, closed exactly once.
        unsafe { close(self.0) };
    }
}

// What a wait names a descriptor by, and the waits over several, where the runtime declares the
// seam they implement (`with_heap_link_seams!`).
wz_runtime_coop::with_heap_link_seams! {
impl FdClose {
    /// What a wait on the descriptor names it by: its number, a value. Nothing holds the
    /// descriptor open for the wait: one a close freed and a new socket took is polled as that
    /// socket, a hint as every answer is.
    pub(crate) fn wait_on(&self) -> Option<wz_runtime_coop::session_drive::WaitOn> {
        usize::try_from(self.0)
            .ok()
            .map(wz_runtime_coop::session_drive::WaitOn::Socket)
    }
}

/// How many descriptors one wait over several links names to the stack: a set on the waiting
/// thread's stack, so a wait allocates nothing. A wait over more is a bounded look.
const WAIT_SET_SOCKETS: usize = 16;

/// The waits of Zephyr's sockets ([`LinkWaits`](wz_runtime_coop::session_drive::LinkWaits)): one
/// `poll` over the descriptors the links name, for their input. Zephyr's sockets name no wait for
/// room, so a wait for room is never asked of these, and one asked answers that there is.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZephyrWaits;

impl wz_runtime_coop::session_drive::LinkWaits for ZephyrWaits {
    fn wait(&self, on: &[wz_runtime_coop::session_drive::LinkWait], timeout_ms: u32) {
        use wz_runtime_coop::session_drive::WaitOn;
        use zephyr_sys::socket::{poll, PollFd, POLLIN};
        if on.is_empty() {
            return;
        }
        let mut fds = [PollFd::default(); WAIT_SET_SOCKETS];
        let mut count = 0;
        let mut look = false;
        for wait in on {
            let fd = match wait.on {
                WaitOn::Socket(handle) => c_int::try_from(handle).ok(),
                WaitOn::AppLink(_) => None,
            };
            match (fd, fds.get_mut(count)) {
                (Some(fd), Some(entry)) => {
                    *entry = PollFd {
                        fd,
                        events: POLLIN,
                        revents: 0,
                    };
                    count += 1;
                }
                // A handle this cannot name to the stack, or one past the set: the bounded look,
                // so it is not starved behind a wait on the others.
                _ => look = true,
            }
        }
        let timeout_ms = if look { timeout_ms.min(1) } else { timeout_ms };
        let nfds = c_int::try_from(count).unwrap_or(c_int::MAX);
        let timeout = c_int::try_from(timeout_ms).unwrap_or(c_int::MAX);
        // SAFETY: the first `count` entries of `fds` are written and live for the call, and the
        // timeout bounds the wait. A failed wait is a quiet link: the step that follows reports it.
        unsafe { poll(fds.as_mut_ptr(), nfds, timeout) };
    }

    fn wait_room(&self, _on: wz_runtime_coop::session_drive::WaitOn, _timeout_us: u64) -> bool {
        true
    }
}
}

// On a host the socket calls bind to the C library's of the same names, so the waits are tested
// over host sockets' descriptors.
wz_runtime_coop::with_heap_link_seams! {
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};
    use wz_runtime_coop::session_drive::{LinkWait, LinkWaits, WaitOn};

    /// A wait over descriptors names each to the stack: one over quiet sockets sleeps its time, a
    /// datagram on the last ends it at once, and a handle of another stack's is the bounded look.
    /// Turned red by a wait that names only the first descriptor, or sleeps its whole time on what
    /// it cannot name.
    #[test]
    fn the_waits_name_each_descriptor_and_look_at_what_they_cannot() {
        let quiet = std::net::UdpSocket::bind("127.0.0.1:0").expect("a socket");
        let ready = std::net::UdpSocket::bind("127.0.0.1:0").expect("a socket");
        let on = |socket: &std::net::UdpSocket| {
            LinkWait::input(WaitOn::Socket(
                usize::try_from(socket.as_raw_fd()).expect("a descriptor"),
            ))
        };
        let set = [on(&quiet), on(&ready)];
        let started = Instant::now();
        ZephyrWaits.wait(&set, 100);
        assert!(
            started.elapsed() >= Duration::from_millis(80),
            "CONTROL: quiet sockets sleep the wait's time"
        );
        let started = Instant::now();
        ZephyrWaits.wait(&[on(&quiet), LinkWait::input(WaitOn::AppLink(7))], 5_000);
        assert!(
            started.elapsed() < Duration::from_millis(1_000),
            "a handle of another stack's is the bounded look"
        );
        quiet
            .send_to(b"wake", ready.local_addr().expect("bound"))
            .expect("a send");
        let started = Instant::now();
        ZephyrWaits.wait(&set, 5_000);
        assert!(
            started.elapsed() < Duration::from_millis(2_500),
            "the datagram on the last descriptor ended the wait"
        );
    }
}
}
