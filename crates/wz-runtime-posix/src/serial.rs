// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host profile's serial line: a tty set as zenoh-pico sets one.
//!
//! [`PosixSerialLine`] is the line `wz_runtime_coop::serial_link` is written against
//! ([`SerialDevice`]), and [`PosixSerialOpen`] what a stack opens it with ([`SerialOpen`]). The
//! tty is set as zenoh-pico's POSIX tty sets it
//! (`vendor/zenoh-pico/src/link/transport/serial/tty_posix.c` @ `_z_posix_tty_open_impl`): raw,
//! `CLOCAL | CREAD`, eight data bits, no parity, one stop bit, no hardware flow control,
//! `VMIN = 1` and `VTIME = 0`, the speed out of the same table, and both queues flushed. It is
//! opened non-blocking, where pico's blocks in its read: a cooperative loop reads what is queued
//! and waits in `poll`. A pin pair names no tty, and is refused as pico's POSIX tty refuses it.
//! Nothing here allocates: the line is a file descriptor.

#![cfg(any(target_os = "linux", target_os = "android"))]

use core::ffi::c_int;

wz_runtime_coop::with_heap_link_seams! {
    use wz_runtime_coop::session_drive::WaitOn;
}
use wz_runtime_coop::serial_link::{SerialDevice, SerialOpen};
use wz_runtime_coop::session_drive::{LinkOpenError, SerialLine, SerialLocator, SERIAL_PATH_LEN};
use wz_runtime_coop::ClockSource;

use crate::net::{errno, poll_writable};

/// Why a serial line could not be opened or used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosixSerialError {
    /// The locator names a pin pair, which no tty is.
    Pins,
    /// The path holds a NUL byte, so no C string names it.
    Path,
    /// The baud rate has no speed in the table zenoh-pico's POSIX tty takes.
    Rate(u32),
    /// `open` failed with this `errno`.
    Open(c_int),
    /// The path is open and is no terminal (`tcgetattr` answered `ENOTTY`).
    NotATerminal,
    /// Reading or setting the terminal's attributes or speed failed with this `errno`.
    Attributes(c_int),
    /// `tcflush` failed with this `errno`.
    Flush(c_int),
    /// `write` failed with this `errno`.
    Write(c_int),
    /// `read` failed with this `errno`.
    Read(c_int),
}

/// The speed of `baudrate` in the table zenoh-pico's POSIX tty reads it with
/// (`vendor/zenoh-pico/src/link/transport/serial/tty_posix.c` @ `_z_posix_tty_baudrate_to_speed`),
/// `None` for a rate it has none for.
fn speed_of(baudrate: u32) -> Option<libc::speed_t> {
    Some(match baudrate {
        1200 => libc::B1200,
        2400 => libc::B2400,
        4800 => libc::B4800,
        9600 => libc::B9600,
        19200 => libc::B19200,
        38400 => libc::B38400,
        57600 => libc::B57600,
        115200 => libc::B115200,
        230400 => libc::B230400,
        _ => return None,
    })
}

/// The bytes of a path and the NUL after it: the longest path a serial locator holds.
const PATH_BYTES: usize = SERIAL_PATH_LEN + 1;

/// One open tty on the host.
pub struct PosixSerialLine {
    fd: c_int,
}

impl PosixSerialLine {
    /// Open the tty at `path` at `baudrate` and set it as zenoh-pico sets one (see the module).
    pub fn open(path: &str, baudrate: u32) -> Result<Self, PosixSerialError> {
        let speed = speed_of(baudrate).ok_or(PosixSerialError::Rate(baudrate))?;
        // A path longer than a locator holds is one no locator named; the NUL stays after it.
        if path.len() >= PATH_BYTES || path.bytes().any(|byte| byte == 0) {
            return Err(PosixSerialError::Path);
        }
        let mut name = [0u8; PATH_BYTES];
        name.get_mut(..path.len())
            .ok_or(PosixSerialError::Path)?
            .copy_from_slice(path.as_bytes());
        // SAFETY: `name` is a live NUL-terminated string: the path, and zeros after it.
        let fd = unsafe {
            libc::open(
                name.as_ptr().cast(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(PosixSerialError::Open(errno()));
        }
        // Owned from here, so an early return closes it.
        let line = Self { fd };
        line.set_raw(speed)?;
        line.discard_queued()?;
        Ok(line)
    }

    /// Set the tty raw at `speed`, eight data bits, no parity, one stop bit, no flow control.
    fn set_raw(&self, speed: libc::speed_t) -> Result<(), PosixSerialError> {
        // SAFETY: `termios` is plain data; `tcgetattr` fills it before anything reads it.
        let mut tty: libc::termios = unsafe { core::mem::zeroed() };
        // SAFETY: this line's own descriptor and a live `termios`.
        if unsafe { libc::tcgetattr(self.fd, &mut tty) } != 0 {
            return Err(match errno() {
                libc::ENOTTY => PosixSerialError::NotATerminal,
                other => PosixSerialError::Attributes(other),
            });
        }
        // SAFETY: a live `termios`.
        unsafe { libc::cfmakeraw(&mut tty) };
        tty.c_cflag |= libc::CLOCAL | libc::CREAD;
        tty.c_cflag &= !(libc::CRTSCTS | libc::CSTOPB | libc::PARENB | libc::CSIZE);
        tty.c_cflag |= libc::CS8;
        if let Some(min) = tty.c_cc.get_mut(libc::VMIN) {
            *min = 1;
        }
        if let Some(time) = tty.c_cc.get_mut(libc::VTIME) {
            *time = 0;
        }
        // SAFETY: a live `termios` and a speed out of the table.
        let set_speed = unsafe {
            libc::cfsetispeed(&mut tty, speed) == 0 && libc::cfsetospeed(&mut tty, speed) == 0
        };
        // SAFETY: this line's own descriptor and a live `termios`.
        if !set_speed || unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &tty) } != 0 {
            return Err(PosixSerialError::Attributes(errno()));
        }
        Ok(())
    }
}

impl SerialDevice for PosixSerialLine {
    type Error = PosixSerialError;

    // One `write` on the non-blocking descriptor, taken again when a signal interrupts it: the
    // tty takes what its output queue has room for, and a full queue is `EAGAIN`, nothing taken.
    fn write(&self, bytes: &[u8]) -> Result<usize, PosixSerialError> {
        loop {
            // SAFETY: `bytes` is live and readable for its length.
            let written = unsafe { libc::write(self.fd, bytes.as_ptr().cast(), bytes.len()) };
            if written >= 0 {
                return Ok(written.unsigned_abs());
            }
            match errno() {
                libc::EINTR => continue,
                libc::EAGAIN => return Ok(0),
                other => return Err(PosixSerialError::Write(other)),
            }
        }
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live `pollfd`; the timeout bounds the wait. A failed or interrupted wait is
        // a quiet line here: the read that follows reads and reports the error.
        unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    }

    // Timed on the host's monotonic clock, as a stream's wait for room is.
    fn wait_writable(&self, timeout_us: u64) -> (bool, u64) {
        let started = crate::PosixClock.now_us();
        let room = poll_writable(self.fd, timeout_us);
        (room, crate::PosixClock.now_us().saturating_sub(started))
    }

    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, PosixSerialError> {
        // SAFETY: `buf` is live and writable for its length.
        let got = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
        if got < 0 {
            return match errno() {
                libc::EAGAIN | libc::EINTR => Ok(None),
                other => Err(PosixSerialError::Read(other)),
            };
        }
        Ok(Some(got.unsigned_abs()))
    }

    fn discard_queued(&self) -> Result<(), PosixSerialError> {
        // SAFETY: plain system call on this line's own descriptor.
        if unsafe { libc::tcflush(self.fd, libc::TCIOFLUSH) } != 0 {
            return Err(PosixSerialError::Flush(errno()));
        }
        Ok(())
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

impl Drop for PosixSerialLine {
    fn drop(&mut self) {
        // SAFETY: `fd` is this line's own descriptor, closed exactly once.
        unsafe { libc::close(self.fd) };
    }
}

/// The host's ttys as a stack's serial lines.
#[derive(Debug, Clone, Copy, Default)]
pub struct PosixSerialOpen;

/// A failed open of a tty as the stack's refusal of the link: what the locator names wrongly for
/// a host is permanent, a device absent or held by another may answer later, and no descriptor
/// left is worth a later try.
fn open_refused(error: PosixSerialError) -> LinkOpenError {
    match error {
        PosixSerialError::Pins
        | PosixSerialError::Path
        | PosixSerialError::Rate(_)
        | PosixSerialError::NotATerminal => LinkOpenError::Unsupported,
        PosixSerialError::Open(libc::EMFILE | libc::ENFILE) => LinkOpenError::Exhausted,
        _ => LinkOpenError::Refused,
    }
}

impl SerialOpen for PosixSerialOpen {
    type Device = PosixSerialLine;

    fn open(&self, at: &SerialLocator) -> Result<PosixSerialLine, LinkOpenError> {
        let path = match &at.line {
            SerialLine::Device(path) => path.as_str(),
            SerialLine::Pins { .. } => return Err(open_refused(PosixSerialError::Pins)),
        };
        PosixSerialLine::open(path, at.baudrate).map_err(open_refused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_runtime_coop::locator_text::parse_locator;

    /// A pseudo-terminal: its master end, and the path of the tty the line opens.
    struct Pty {
        master: c_int,
        path: std::string::String,
    }

    impl Pty {
        fn open() -> Self {
            // SAFETY: value arguments; the call makes a descriptor or fails.
            let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
            assert!(master >= 0, "a pseudo-terminal");
            // SAFETY: the master's own descriptor.
            assert_eq!(unsafe { libc::grantpt(master) }, 0);
            // SAFETY: as above.
            assert_eq!(unsafe { libc::unlockpt(master) }, 0);
            let mut name = [0 as libc::c_char; 128];
            // SAFETY: a live buffer of its length, which the call writes a C string into.
            assert_eq!(
                unsafe { libc::ptsname_r(master, name.as_mut_ptr(), name.len()) },
                0
            );
            // SAFETY: `ptsname_r` wrote a NUL-terminated string into `name`.
            let path = unsafe { core::ffi::CStr::from_ptr(name.as_ptr()) }
                .to_str()
                .expect("a UTF-8 path")
                .into();
            Self { master, path }
        }

        fn write(&self, bytes: &[u8]) {
            // SAFETY: `bytes` is live and readable for its length.
            let written = unsafe { libc::write(self.master, bytes.as_ptr().cast(), bytes.len()) };
            assert_eq!(written, bytes.len() as isize);
        }

        fn read(&self, buf: &mut [u8]) -> usize {
            let mut pfd = libc::pollfd {
                fd: self.master,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one live `pollfd`.
            assert_eq!(
                unsafe { libc::poll(&mut pfd, 1, 2_000) },
                1,
                "bytes for the master"
            );
            // SAFETY: `buf` is live and writable for its length.
            let got = unsafe { libc::read(self.master, buf.as_mut_ptr().cast(), buf.len()) };
            usize::try_from(got).expect("a read")
        }
    }

    impl Drop for Pty {
        fn drop(&mut self) {
            // SAFETY: the master's own descriptor, closed once.
            unsafe { libc::close(self.master) };
        }
    }

    /// The attributes of the line's tty.
    fn attributes(line: &PosixSerialLine) -> libc::termios {
        // SAFETY: plain data, filled by the call.
        let mut tty: libc::termios = unsafe { core::mem::zeroed() };
        // SAFETY: the line's own descriptor and a live `termios`.
        assert_eq!(unsafe { libc::tcgetattr(line.fd, &mut tty) }, 0);
        tty
    }

    /// The tty is set as zenoh-pico's POSIX tty sets it. Turned red by a flag of `set_raw` that
    /// is dropped or turned the other way, or a speed out of another row of the table.
    #[test]
    fn a_line_is_set_raw_eight_n_one_at_its_rate() {
        let pty = Pty::open();
        let line = PosixSerialLine::open(&pty.path, 115_200).expect("the tty");
        let tty = attributes(&line);
        assert_eq!(tty.c_cflag & libc::CSIZE, libc::CS8);
        assert_eq!(
            tty.c_cflag & (libc::PARENB | libc::CSTOPB | libc::CRTSCTS),
            0
        );
        assert_eq!(
            tty.c_cflag & (libc::CLOCAL | libc::CREAD),
            libc::CLOCAL | libc::CREAD
        );
        assert_eq!(
            tty.c_lflag & (libc::ICANON | libc::ECHO | libc::ISIG),
            0,
            "raw"
        );
        assert_eq!(tty.c_cc[libc::VMIN], 1);
        assert_eq!(tty.c_cc[libc::VTIME], 0);
        // SAFETY: a live `termios`.
        assert_eq!(unsafe { libc::cfgetospeed(&tty) }, libc::B115200);
        // SAFETY: as above.
        assert_eq!(unsafe { libc::cfgetispeed(&tty) }, libc::B115200);
    }

    /// Bytes go both ways, a read with nothing queued answers at once, and a discard drops what
    /// was queued. Turned red by a blocking read, a write that loses bytes, or a discard that
    /// flushes nothing.
    #[test]
    fn a_line_carries_bytes_both_ways_and_never_blocks_a_read() {
        let pty = Pty::open();
        let line = PosixSerialLine::open(&pty.path, 9_600).expect("the tty");
        let mut buf = [0u8; 16];
        assert_eq!(line.try_read(&mut buf), Ok(None), "nothing queued");
        assert_eq!(line.write(b"\x00zenoh\x00"), Ok(7));
        let mut far = [0u8; 16];
        let got = pty.read(&mut far);
        assert_eq!(far.get(..got), Some(&b"\x00zenoh\x00"[..]));
        pty.write(b"back");
        line.wait_readable(2_000);
        assert_eq!(line.try_read(&mut buf), Ok(Some(4)));
        assert_eq!(buf.get(..4), Some(&b"back"[..]));
        pty.write(b"stale");
        line.wait_readable(2_000);
        line.discard_queued().expect("a flush");
        assert_eq!(
            line.try_read(&mut buf),
            Ok(None),
            "the stale bytes are gone"
        );
    }

    /// What the line cannot be opened from is refused with its reason, and the stack's open reads
    /// each as permanent or worth a later try. Turned red by a refusal mapped to the other kind,
    /// or a pin pair or an unknown rate taken.
    #[test]
    fn a_line_that_cannot_be_opened_is_refused_with_its_reason() {
        let pty = Pty::open();
        assert_eq!(
            PosixSerialLine::open(&pty.path, 12_345).err(),
            Some(PosixSerialError::Rate(12_345))
        );
        assert_eq!(
            PosixSerialLine::open("/dev/null", 9_600).err(),
            Some(PosixSerialError::NotATerminal)
        );
        assert_eq!(
            PosixSerialLine::open("/nonexistent/tty", 9_600).err(),
            Some(PosixSerialError::Open(libc::ENOENT))
        );
        let open = |text: &str| {
            let at = parse_locator(text)
                .ok()
                .and_then(|locator| locator.as_serial())
                .expect("a serial locator");
            PosixSerialOpen.open(&at).map(|_| ())
        };
        assert_eq!(
            open("serial/3.4#baudrate=9600"),
            Err(LinkOpenError::Unsupported)
        );
        assert_eq!(
            open("serial//dev/null#baudrate=9600"),
            Err(LinkOpenError::Unsupported)
        );
        assert_eq!(
            open("serial//nonexistent/tty#baudrate=9600"),
            Err(LinkOpenError::Refused)
        );
        let named = std::format!("serial/{}#baudrate=115200", pty.path);
        assert_eq!(
            open(named.as_str()),
            Ok(()),
            "CONTROL: the tty itself opens"
        );
    }
}
