// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The close of a Zephyr socket descriptor, and the wait another thread makes on it.
//!
//! A socket of this crate closes its descriptor when it is dropped. On the heap profile a thread
//! that does not drive the link may also wait for the socket's input (`LinkReadiness`): the
//! pico C ABI's read task waits outside the session's lock, while the session may let the link go
//! under it. The host's sockets keep that wait off a descriptor number the stack has given to
//! another socket by polling a duplicate of the descriptor (`wz-runtime-posix`'s `FdReadiness`).
//! Zephyr's sockets cannot be duplicated (`fcntl(F_DUPFD)` is handed to the socket's ioctl, which
//! does not answer it), so here the descriptor is held by the socket and by every wait made on it,
//! and closed when the last of them lets it go. The fixed-memory profile has no such wait, and its
//! socket alone closes the descriptor.

use core::ffi::c_int;

use zephyr_sys::socket::close;

/// What closes a descriptor once.
struct Closer(c_int);

impl Drop for Closer {
    fn drop(&mut self) {
        // SAFETY: the descriptor this owns, closed exactly once, when the last holder lets it go.
        unsafe { close(self.0) };
    }
}

/// The share of a descriptor's close that a socket holds.
#[cfg(all(
    feature = "alloc",
    not(feature = "session-slot"),
    target_has_atomic = "ptr"
))]
pub(crate) struct FdClose {
    held: alloc::sync::Arc<Closer>,
}

/// The share of a descriptor's close that a socket holds: all of it, on a profile with no wait
/// from another thread. Held for its drop alone.
#[cfg(not(all(
    feature = "alloc",
    not(feature = "session-slot"),
    target_has_atomic = "ptr"
)))]
pub(crate) struct FdClose {
    _held: Closer,
}

impl FdClose {
    /// The close of `fd`, which the caller hands over: nothing else closes it.
    pub(crate) fn new(fd: c_int) -> Self {
        #[cfg(all(
            feature = "alloc",
            not(feature = "session-slot"),
            target_has_atomic = "ptr"
        ))]
        {
            Self {
                held: alloc::sync::Arc::new(Closer(fd)),
            }
        }
        #[cfg(not(all(
            feature = "alloc",
            not(feature = "session-slot"),
            target_has_atomic = "ptr"
        )))]
        {
            Self { _held: Closer(fd) }
        }
    }

    /// A wait for the descriptor's input that another thread may make, holding the descriptor
    /// open for as long as it is held.
    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    pub(crate) fn readiness(
        &self,
    ) -> alloc::boxed::Box<dyn wz_runtime_coop::session_drive::LinkReadiness> {
        alloc::boxed::Box::new(readiness::FdReadiness(self.held.clone()))
    }
}

#[cfg(all(
    feature = "alloc",
    not(feature = "session-slot"),
    target_has_atomic = "ptr"
))]
mod readiness {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::ffi::c_int;

    use wz_runtime_coop::session_drive::LinkReadiness;
    use zephyr_sys::socket::{poll, PollFd, POLLIN};

    use super::Closer;

    /// `poll` on a descriptor this holds open.
    pub(super) struct FdReadiness(pub(super) Arc<Closer>);

    /// The `pollfd` of a descriptor asked for input.
    fn asked(fd: c_int) -> PollFd {
        PollFd {
            fd,
            events: POLLIN,
            revents: 0,
        }
    }

    /// A wait in milliseconds as `poll` takes it.
    fn timeout(ms: u32) -> c_int {
        c_int::try_from(ms).unwrap_or(c_int::MAX)
    }

    impl LinkReadiness for FdReadiness {
        fn wait_readable(&self, timeout_ms: u32) {
            let mut pfd = asked(self.0 .0);
            // SAFETY: one live `pollfd` over a descriptor this holds open; the timeout bounds the
            // wait. A failed wait is a quiet socket: the step that follows reports the error.
            unsafe { poll(&mut pfd, 1, timeout(timeout_ms)) };
        }

        fn handle(&self) -> Option<usize> {
            usize::try_from(self.0 .0).ok()
        }

        fn wait_readable_among(&self, others: &[Arc<dyn LinkReadiness>], timeout_ms: u32) {
            let mut fds = Vec::with_capacity(others.len() + 1);
            fds.push(asked(self.0 .0));
            for other in others {
                match other
                    .handle()
                    .and_then(|handle| c_int::try_from(handle).ok())
                {
                    Some(fd) => fds.push(asked(fd)),
                    // A wait this cannot name to the stack: the bounded look, so it is not starved
                    // behind a wait on the others.
                    None => return self.wait_readable(timeout_ms.min(1)),
                }
            }
            let count = c_int::try_from(fds.len()).unwrap_or(c_int::MAX);
            // SAFETY: `fds` is live for the call and holds `count` entries; every descriptor is
            // held open by the wait that named it for as long as the caller holds that wait; the
            // timeout bounds the wait. A failed wait is a quiet socket.
            unsafe { poll(fds.as_mut_ptr(), count, timeout(timeout_ms)) };
        }
    }
}

// On a host the socket calls bind to the C library's of the same names, so the holding is tested
// over a host socket's descriptor.
#[cfg(all(
    test,
    unix,
    feature = "alloc",
    not(feature = "session-slot"),
    target_has_atomic = "ptr"
))]
mod tests {
    use super::*;

    use core::mem::ManuallyDrop;
    use std::os::fd::{FromRawFd, IntoRawFd};

    /// Whether `fd` names an open file, asked without taking it over.
    fn is_open(fd: c_int) -> bool {
        // SAFETY: a look at `fd` through a `File` that is never dropped, so it closes nothing.
        let file = ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
        file.metadata().is_ok()
    }

    #[test]
    fn a_descriptor_stays_open_while_a_wait_on_it_is_held() {
        let fd = std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("a socket")
            .into_raw_fd();
        let close = FdClose::new(fd);
        let wait = close.readiness();
        assert_eq!(wait.handle(), usize::try_from(fd).ok());
        drop(close);
        assert!(
            is_open(fd),
            "the socket let its share go and the wait still holds the descriptor"
        );
        drop(wait);
    }
}
