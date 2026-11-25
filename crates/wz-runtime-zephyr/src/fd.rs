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

/// The descriptor a wait names to the stack: `None` for a wake, which Zephyr's sockets make
/// none of, and for a link of the program's, which is not one of its.
fn descriptor(on: wz_runtime_coop::session_drive::WaitOn) -> Option<c_int> {
    match on {
        wz_runtime_coop::session_drive::WaitOn::Socket(handle) => c_int::try_from(handle).ok(),
        wz_runtime_coop::session_drive::WaitOn::AppLink(_)
        | wz_runtime_coop::session_drive::WaitOn::Wake(_) => None,
    }
}

/// One `poll` over what `on` names, in `fds`, for at most `timeout_ms`: how many entries of
/// `fds` it filled, in the order of `on`, and whether the poll answered.
fn poll_on(
    on: &[wz_runtime_coop::session_drive::LinkWait],
    timeout_ms: u32,
    fds: &mut [zephyr_sys::socket::PollFd; WAIT_SET_SOCKETS],
) -> (usize, bool) {
    use zephyr_sys::socket::{poll, PollFd, POLLIN};
    let mut count = 0;
    let mut look = false;
    for wait in on {
        match (descriptor(wait.on), fds.get_mut(count)) {
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
    let answered = unsafe { poll(fds.as_mut_ptr(), nfds, timeout) } >= 0;
    (count, answered)
}

impl wz_runtime_coop::session_drive::LinkWaits for ZephyrWaits {
    fn wait(&self, on: &[wz_runtime_coop::session_drive::LinkWait], timeout_ms: u32) {
        if on.is_empty() {
            return;
        }
        let mut fds = [zephyr_sys::socket::PollFd::default(); WAIT_SET_SOCKETS];
        let _ = poll_on(on, timeout_ms, &mut fds);
    }

    /// The entries `poll` found with an event, any event (an error or a hang-up is one the step
    /// reads), and every entry it could not name to the stack, whose wait was the bounded look.
    /// A poll that failed tells nothing, so every entry is answered.
    fn wait_ready(
        &self,
        on: &mut [wz_runtime_coop::session_drive::LinkWait],
        timeout_ms: u32,
    ) -> usize {
        if on.is_empty() {
            return 0;
        }
        let mut fds = [zephyr_sys::socket::PollFd::default(); WAIT_SET_SOCKETS];
        let (count, answered) = poll_on(on, timeout_ms, &mut fds);
        if !answered {
            return on.len();
        }
        // The entries are walked in the order `poll_on` filled `fds` in, so the next entry it
        // named is the next of `fds`; each ready one is swapped to the front, past every entry
        // walked already.
        let mut named = 0;
        let mut front = 0;
        for at in 0..on.len() {
            let Some(wait) = on.get(at) else {
                break;
            };
            let ready = match descriptor(wait.on) {
                Some(_) if named < count => {
                    let polled = fds.get(named).is_some_and(|entry| entry.revents != 0);
                    named += 1;
                    polled
                }
                _ => true,
            };
            if ready {
                on.swap(front, at);
                front += 1;
            }
        }
        front
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

    /// A wait that tells what it found ready moves the socket with a datagram, and the handles it
    /// cannot name (a link of the program's, and a wake, which Zephyr's sockets make none of), to
    /// the front, and answers three: the quiet sockets stay behind. A set of quiet sockets alone
    /// answers none. Turned red by a wait that answers every entry, which would ask a quiet port
    /// for a connection after every wait.
    #[test]
    fn the_stacks_wait_moves_what_it_found_ready_to_the_front() {
        let quiet = std::net::UdpSocket::bind("127.0.0.1:0").expect("a socket");
        let ready = std::net::UdpSocket::bind("127.0.0.1:0").expect("a socket");
        let on = |socket: &std::net::UdpSocket| {
            LinkWait::input(WaitOn::Socket(
                usize::try_from(socket.as_raw_fd()).expect("a descriptor"),
            ))
        };
        let mut set = [on(&quiet), on(&quiet)];
        assert_eq!(
            ZephyrWaits.wait_ready(&mut set, 10),
            0,
            "CONTROL: quiet sockets alone are none ready"
        );

        let elsewhere = LinkWait::input(WaitOn::AppLink(7));
        let wake = LinkWait::input(WaitOn::Wake(5));
        quiet
            .send_to(b"wake", ready.local_addr().expect("bound"))
            .expect("a send");
        // The datagram has arrived once a wait on its socket alone ends; nothing reads it.
        ZephyrWaits.wait(&[on(&ready)], 5_000);
        let mut set = [on(&quiet), on(&ready), on(&quiet), elsewhere, wake];
        let found = ZephyrWaits.wait_ready(&mut set, 5_000);
        assert_eq!(found, 3, "the socket with a datagram and the handles it cannot name");
        assert_eq!(set.get(..found), Some(&[on(&ready), elsewhere, wake][..]));
    }
}
}
