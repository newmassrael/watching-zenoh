// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host profile's named FIFOs: what the cooperative engine's `unixpipe/` links run over.
//!
//! [`PosixFifo`] is the FIFO end `wz_runtime_coop::unixpipe_link` is written against ([`Fifo`]),
//! and [`PosixFifoOpen`] what a stack opens them with ([`FifoOpen`]). Every end is opened as
//! upstream's unixpipe link opens it, without blocking
//! (`io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs` @ `.custom_flags(libc::O_NONBLOCK)`),
//! and every end a link reads holds an exclusive `flock` on its node, which is how a dial tells a
//! listener's request FIFO from a stale node and how two dials tell their pairs apart.
//!
//! Three ends are opened otherwise than upstream's, as wz's tokio engine opens them: a dedicated
//! read end read-only, so it reads the end of the stream once its peer's writer closes; the
//! request FIFO read-write, so it never reads an end as dials come and go; and every write end
//! read-write, so a write never meets a FIFO without a reader and raises `SIGPIPE` in a host
//! program that did not ignore it. A dial still learns that no listener reads the request FIFO
//! from a write-only open of it (`ENXIO`), which it closes at once.
//!
//! Nothing here allocates: a path is copied into a buffer of the longest a row names.

#![cfg(any(target_os = "linux", target_os = "android"))]

use core::ffi::{c_char, c_int};

wz_runtime_coop::with_heap_link_seams! {
    use wz_runtime_coop::session_drive::WaitOn;
}
use wz_runtime_coop::session_drive::LinkOpenError;
use wz_runtime_coop::unixpipe_link::{Fifo, FifoOpen};
use wz_runtime_coop::ClockSource;
use wz_session_core::caps::MAX_LOCATOR_LEN;

use crate::net::{errno, poll_writable};

/// The longest path a FIFO of a link is named by, with its NUL: no longer than a row's locator.
const PATH_BUF: usize = MAX_LOCATOR_LEN + 1;

/// A path as the C calls take it: its bytes and a NUL, in a buffer of the longest a row names.
struct CPath {
    bytes: [u8; PATH_BUF],
}

impl CPath {
    /// `path`, or `None` when it holds a NUL or is longer than a row names.
    fn new(path: &str) -> Option<Self> {
        if path.as_bytes().contains(&0) {
            return None;
        }
        let mut bytes = [0u8; PATH_BUF];
        // One byte is left for the NUL the buffer was made with.
        bytes
            .get_mut(..path.len())
            .filter(|_| path.len() < PATH_BUF)?
            .copy_from_slice(path.as_bytes());
        Some(Self { bytes })
    }

    fn as_ptr(&self) -> *const c_char {
        self.bytes.as_ptr().cast()
    }
}

/// Why a FIFO end failed once open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosixFifoError {
    /// `write` failed with this `errno`.
    Write(c_int),
    /// `read` failed with this `errno`.
    Read(c_int),
}

/// One open FIFO end. A read end the link holds the lock of names its node, and removes it when
/// it is let go, as upstream's read end does
/// (`io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs` @ `let _ = unlink(self.path.as_str());`).
pub struct PosixFifo {
    fd: c_int,
    node: Option<CPath>,
}

impl Fifo for PosixFifo {
    type Error = PosixFifoError;

    // One `write` on the non-blocking descriptor, taken again when a signal interrupts it: a full
    // FIFO is `EAGAIN`, nothing taken.
    fn write(&self, bytes: &[u8]) -> Result<usize, PosixFifoError> {
        loop {
            // SAFETY: `bytes` is live and readable for its length.
            let written = unsafe { libc::write(self.fd, bytes.as_ptr().cast(), bytes.len()) };
            if written >= 0 {
                return Ok(written.unsigned_abs());
            }
            match errno() {
                libc::EINTR => continue,
                libc::EAGAIN => return Ok(0),
                other => return Err(PosixFifoError::Write(other)),
            }
        }
    }

    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, PosixFifoError> {
        // SAFETY: `buf` is live and writable for its length.
        let got = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
        if got < 0 {
            return match errno() {
                libc::EAGAIN | libc::EINTR => Ok(None),
                other => Err(PosixFifoError::Read(other)),
            };
        }
        Ok(Some(got.unsigned_abs()))
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live `pollfd`; the timeout bounds the wait. A failed or interrupted wait is
        // a quiet FIFO here: the read that follows reads and reports the error.
        unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    }

    // Timed on the host's monotonic clock, as a stream's wait for room is.
    fn wait_writable(&self, timeout_us: u64) -> (bool, u64) {
        let started = crate::PosixClock.now_us();
        let room = poll_writable(self.fd, timeout_us);
        (room, crate::PosixClock.now_us().saturating_sub(started))
    }

    wz_runtime_coop::with_heap_link_seams! {
        fn input_wait(&self) -> Option<WaitOn> {
            crate::net::wait_on(self.fd)
        }

        fn room_wait(&self) -> Option<WaitOn> {
            crate::net::wait_on(self.fd)
        }
    }
}

impl Drop for PosixFifo {
    fn drop(&mut self) {
        if let Some(node) = &self.node {
            // The node leaves the filesystem while the descriptor still holds the FIFO, so what
            // is queued in it is not lost by the order.
            // SAFETY: a NUL-terminated path live for the call.
            unsafe { libc::unlink(node.as_ptr()) };
        }
        // SAFETY: `fd` is this end's own descriptor, closed exactly once; its `flock` ends with it.
        unsafe { libc::close(self.fd) };
    }
}

/// The host's named FIFOs as a stack's unixpipe links.
#[derive(Debug, Clone, Copy, Default)]
pub struct PosixFifoOpen;

/// `open` of `path` with `flags`, non-blocking and closed on `exec`: the descriptor, or the
/// `errno` it failed with.
fn open(path: &CPath, flags: c_int) -> Result<c_int, c_int> {
    // SAFETY: a NUL-terminated path live for the call.
    let fd = unsafe { libc::open(path.as_ptr(), flags | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if fd < 0 {
        Err(errno())
    } else {
        Ok(fd)
    }
}

/// Take the exclusive `flock` of `fd` without waiting: whether it was free.
fn lock(fd: c_int) -> bool {
    // SAFETY: plain system call on a descriptor the caller holds.
    unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

/// A failed open as the stack's refusal of the link: no descriptor left is worth a later try.
fn refused(errno: c_int) -> LinkOpenError {
    match errno {
        libc::EMFILE | libc::ENFILE => LinkOpenError::Exhausted,
        _ => LinkOpenError::Refused,
    }
}

impl PosixFifoOpen {
    /// The FIFO at `path`, made with `mode` when there is none, opened with `flags` and locked
    /// as one end's alone. A node another end holds the lock of is
    /// [`LinkOpenError::AddressInUse`], and is left as it is; one this call made and could not open
    /// is removed again.
    fn locked(path: &str, mode: u32, flags: c_int) -> Result<PosixFifo, LinkOpenError> {
        let path = CPath::new(path).ok_or(LinkOpenError::Unsupported)?;
        // SAFETY: a NUL-terminated path live for the call.
        let made = unsafe { libc::mkfifo(path.as_ptr(), mode as libc::mode_t) } == 0;
        if !made && errno() != libc::EEXIST {
            return Err(refused(errno()));
        }
        let fd = match open(&path, flags) {
            Ok(fd) => fd,
            Err(error) => {
                if made {
                    // SAFETY: as above.
                    unsafe { libc::unlink(path.as_ptr()) };
                }
                return Err(refused(error));
            }
        };
        if !lock(fd) {
            // SAFETY: the descriptor just opened, closed once.
            unsafe { libc::close(fd) };
            return Err(LinkOpenError::AddressInUse);
        }
        Ok(PosixFifo {
            fd,
            node: Some(path),
        })
    }
}

impl FifoOpen for PosixFifoOpen {
    type Fifo = PosixFifo;

    fn reader(&self, path: &str, mode: u32) -> Result<PosixFifo, LinkOpenError> {
        Self::locked(path, mode, libc::O_RDONLY)
    }

    fn listen(&self, path: &str, mode: u32) -> Result<PosixFifo, LinkOpenError> {
        Self::locked(path, mode, libc::O_RDWR)
    }

    // A write-only open finds no reader (`ENXIO`) or no node (`ENOENT`) when no listener is
    // there; a lock this end can take is one no listener holds
    // (`io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs` @ `bail!("no listener...")`).
    fn request(&self, path: &str) -> Result<PosixFifo, LinkOpenError> {
        let at = CPath::new(path).ok_or(LinkOpenError::Unsupported)?;
        let probe = open(&at, libc::O_WRONLY).map_err(refused)?;
        let listening = !lock(probe);
        // SAFETY: the probe just opened, closed once; a lock it took ends with it.
        unsafe { libc::close(probe) };
        if !listening {
            return Err(LinkOpenError::Refused);
        }
        self.writer(path)
    }

    fn writer(&self, path: &str) -> Result<PosixFifo, LinkOpenError> {
        let at = CPath::new(path).ok_or(LinkOpenError::Unsupported)?;
        let fd = open(&at, libc::O_RDWR).map_err(refused)?;
        Ok(PosixFifo { fd, node: None })
    }

    // The kernel's random bytes; should it fail, the clock's low bits, since two dials that draw
    // the same suffix are told apart by the lock and draw again.
    fn suffix(&self) -> u32 {
        let mut bytes = [0u8; 4];
        // SAFETY: `bytes` is live and writable for its length.
        let got = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
        if usize::try_from(got).ok() == Some(bytes.len()) {
            u32::from_ne_bytes(bytes)
        } else {
            // Truncated on purpose: the low bits move fastest.
            crate::PosixClock.now_us() as u32
        }
    }

    fn now_us(&self) -> u64 {
        crate::PosixClock.now_us()
    }
}

wz_runtime_coop::with_heap_link_seams! {
    /// The links of a stack `S` with links over the host's named FIFOs beside them: what a
    /// cooperative engine on this host dials and listens on `unixpipe/` locators with
    /// (`PosixUnixpipeLinks::<S>::new(links, PosixFifoOpen)`).
    pub type PosixUnixpipeLinks<S, N = wz_runtime_coop::link_cells::OneTask> =
        wz_runtime_coop::unixpipe_link::UnixpipeLinks<S, PosixFifoOpen, N>;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::format;
    use std::string::String;

    /// A FIFO path no other test of this process uses.
    fn unique(tag: &str) -> String {
        use core::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        format!("/tmp/wz-fifo-{}-{n}-{tag}", std::process::id())
    }

    fn exists(path: &str) -> bool {
        std::fs::metadata(path).is_ok()
    }

    /// One listener holds a request FIFO: a second is refused, a dial finds it, and once it is let
    /// go its node is gone and a dial is refused. Turned red by a listener that takes no lock, or
    /// a probe that reads a free lock as a listener.
    #[test]
    fn one_listener_holds_a_request_fifo_and_a_dial_finds_it() {
        let open = PosixFifoOpen;
        let path = unique("uplink");
        assert!(matches!(open.request(&path), Err(LinkOpenError::Refused)));
        let listener = open.listen(&path, 0o600).expect("a request FIFO");
        assert!(matches!(
            open.listen(&path, 0o600),
            Err(LinkOpenError::AddressInUse)
        ));
        let dial = open.request(&path).expect("a listener holds it");
        assert_eq!(dial.write(b"12345678"), Ok(8));
        let mut got = [0u8; 8];
        assert_eq!(listener.try_read(&mut got), Ok(Some(8)));
        assert_eq!(&got, b"12345678");
        drop(listener);
        assert!(!exists(&path), "the listener's node goes with it");
        assert!(matches!(open.request(&path), Err(LinkOpenError::Refused)));
    }

    /// A dedicated read end reads nothing before its peer writes, the peer's bytes once it has, and
    /// the end of the stream once the peer's writer is closed; a second reader of a held node is
    /// refused and leaves it. Turned red by a read end opened so that it never reads the end, or
    /// a refused reader that removes the holder's node.
    #[test]
    fn a_read_end_reads_its_peer_and_the_end_of_the_stream() {
        let open = PosixFifoOpen;
        let path = unique("downlink7");
        let read = open.reader(&path, 0o600).expect("a read end");
        assert!(matches!(
            open.reader(&path, 0o600),
            Err(LinkOpenError::AddressInUse)
        ));
        assert!(exists(&path), "the holder's node stays");
        let mut got = [0u8; 4];
        assert!(matches!(read.try_read(&mut got), Ok(Some(0) | None)));
        let write = open.writer(&path).expect("a write end");
        assert_eq!(write.write(b"abc"), Ok(3));
        assert_eq!(read.try_read(&mut got), Ok(Some(3)));
        assert_eq!(&got[..3], b"abc");
        drop(write);
        assert_eq!(
            read.try_read(&mut got),
            Ok(Some(0)),
            "the peer's writer is gone"
        );
        drop(read);
        assert!(!exists(&path));
    }

    /// Two suffixes in a row are not the same one. Turned red by a suffix drawn from nothing that
    /// moves.
    #[test]
    fn a_suffix_is_drawn_at_random() {
        let open = PosixFifoOpen;
        let draws = [open.suffix(), open.suffix(), open.suffix()];
        assert!(draws.iter().any(|draw| *draw != draws[0]));
    }
}
