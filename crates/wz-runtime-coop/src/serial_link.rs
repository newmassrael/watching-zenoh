// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session's link over a serial line: what a platform supplies to open one.
//!
//! A platform supplies a [`SerialOpen`], which opens the line a [`SerialLocator`] names at its
//! baud rate, and the [`SerialDevice`] it yields: write without waiting, wait, read what is
//! queued, and throw away what is queued. The framing of zenoh's serial link (COBS, the CRC32 and
//! the header of each frame) is the session core's (`wz_session_core::serial_link`), written once
//! for every engine; the line under it is the platform's. The link over the line, its handshake
//! and the stack that opens it beside another's are the heap profile's (`SerialLinks`).

use core::ffi::c_int;
use core::fmt::Debug;

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::session_drive::WaitOn;
use crate::session_drive::{LinkOpenError, SerialLocator};

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
mod links;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub use links::{SerialDial, SerialDriver, SerialLinks, SerialLinksDial};

/// One open serial line: a platform's tty, or a UART. Only the one thread that drives the link
/// touches it. A line keeps no message boundaries and has no peer address: what is written is read
/// at the other end as bytes, and the framing finds the frames in them.
pub trait SerialDevice: Sized {
    /// Why a call failed, as the platform reports it. `Copy`, because a link keeps the last
    /// failure for the deploy to report.
    type Error: Copy + Debug;

    /// Write `bytes`, in order, as far as the line takes them now, without waiting: how many it
    /// took, `0` when its output has no room.
    fn write(&self, bytes: &[u8]) -> Result<usize, Self::Error>;

    /// Block until bytes are queued or `timeout_ms` has passed, and return at once when some
    /// already are. A failed wait is the same as a quiet line here: the read that follows reports
    /// the error.
    fn wait_readable(&self, timeout_ms: c_int);

    /// Wait up to `timeout_us` microseconds for the line to take more bytes: whether it will (or
    /// has failed, which the write that follows reports) and how long the wait took in
    /// microseconds, as [`crate::stream_link::StreamSocket::wait_writable`] answers for a stream.
    /// A line that cannot tell answers room at once.
    fn wait_writable(&self, timeout_us: u64) -> (bool, u64) {
        let _ = timeout_us;
        (true, 0)
    }

    /// Read what is queued into `buf` without blocking: `Ok(Some(n))` for `n` bytes,
    /// `Ok(Some(0))` when the line has hung up, `Ok(None)` when nothing is queued.
    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, Self::Error>;

    /// Throw away every byte queued on the line in both directions, read and not yet written: what
    /// a dial does before it writes its first frame, so the peer's answer is not read behind
    /// bytes left from an earlier link, as zenoh-pico's open flushes the tty
    /// (`vendor/zenoh-pico/src/link/transport/serial/tty_posix.c` @ `tcflush(fd, TCIOFLUSH)`).
    fn discard_queued(&self) -> Result<(), Self::Error>;

    /// What a thread other than the link's waits on for this line's input
    /// ([`crate::session_drive::SessionDatagramLink::input_wait`]); `None` when the platform gives
    /// none, and then a link over the line waits in its own loop whatever it was asked.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn input_wait(&self) -> Option<WaitOn> {
        None
    }

    /// What a thread other than the link's waits on for room on this line; `None` when the
    /// platform gives none.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn room_wait(&self) -> Option<WaitOn> {
        None
    }
}

/// How a stack opens the serial lines its `serial/` links run over: a value the stack holds.
pub trait SerialOpen {
    /// The line this platform opens.
    type Device: SerialDevice;

    /// The line `at` names, open at its baud rate and set as zenoh-pico sets a tty: raw bytes,
    /// eight data bits, no parity, one stop bit, no flow control. A line this platform cannot open
    /// at all for the locator (a pin pair on a host, a baud rate it has no speed for, a path that
    /// is no terminal) is [`LinkOpenError::Unsupported`]; a device that is absent or held by
    /// another (one plugged in later may answer) is [`LinkOpenError::Refused`]; no descriptor
    /// left is [`LinkOpenError::Exhausted`].
    fn open(&self, at: &SerialLocator) -> Result<Self::Device, LinkOpenError>;

    /// The platform's monotonic clock, in microseconds: what a dial times the locator's `tout`
    /// on, the wait after the peer's `RESET` before its `INIT` is written again.
    fn now_us(&self) -> u64;
}
