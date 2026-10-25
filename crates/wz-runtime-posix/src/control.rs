// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The channel an agent drives a host node over: lines read from standard input, one answer per
//! line written to standard output (`glue::log` is standard error, a diagnostic; the output is
//! the agent's). It carries the out-of-band transport of `wz_session_mcu::control_port`, and
//! knows nothing of what a line says.
//!
//! The node's loop is one thread and never blocks on this: a round asks [`Lines::take_line`], which
//! asks the descriptor whether a byte is waiting before it reads, so an idle channel costs the
//! round one `poll(2)` and a descriptor that is not a pipe or a terminal behaves the same.

/// The bytes of one command line. A longer line is dropped whole (it is no command the port
/// reads, since the longest is `open` and a 32-digit zid), and the channel says so by returning
/// it cut at this length with [`Line::overlong`] set.
pub const LINE_BYTES: usize = 128;

/// One line taken from the channel.
pub struct Line<'a> {
    /// The text of the line, its end cut. Not valid UTF-8 is an empty line, which no command is.
    pub text: &'a str,
    /// The line was longer than [`LINE_BYTES`] and `text` is what was kept of it.
    pub overlong: bool,
}

/// A line reader over a descriptor, in a fixed buffer.
pub struct Lines {
    fd: libc::c_int,
    buf: [u8; LINE_BYTES],
    len: usize,
    /// Bytes of the current line that did not fit and were dropped, until its end.
    dropping: bool,
    /// The line just returned, kept until the next call moves past it.
    taken: usize,
    closed: bool,
}

impl Lines {
    /// The reader of standard input.
    pub const fn stdin() -> Self {
        Self::on(0)
    }

    /// The reader of descriptor `fd`.
    pub const fn on(fd: libc::c_int) -> Self {
        Self {
            fd,
            buf: [0; LINE_BYTES],
            len: 0,
            dropping: false,
            taken: 0,
            closed: false,
        }
    }

    /// Whether the other end is gone: no line will come again.
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// The next complete line, if one is waiting; `None` when none is (or the channel closed).
    /// Never blocks. The line is valid until the next call.
    pub fn take_line(&mut self) -> Option<Line<'_>> {
        // Move past the line handed out last time.
        if self.taken > 0 {
            self.buf.copy_within(self.taken..self.len, 0);
            self.len -= self.taken;
            self.taken = 0;
        }
        loop {
            if let Some(end) = self.buf[..self.len].iter().position(|b| *b == b'\n') {
                self.taken = end + 1;
                let overlong = core::mem::take(&mut self.dropping);
                return Some(Line {
                    text: core::str::from_utf8(&self.buf[..end]).unwrap_or(""),
                    overlong,
                });
            }
            if self.len == LINE_BYTES {
                // No end in a full buffer: keep what fits, drop the rest up to the line's end.
                self.dropping = true;
                self.len = 0;
                self.buf.fill(0);
            }
            if self.closed || !self.waiting() {
                return None;
            }
            // SAFETY: the destination is the unused tail of `buf`, live for its length.
            let n = unsafe {
                libc::read(
                    self.fd,
                    self.buf[self.len..].as_mut_ptr().cast(),
                    LINE_BYTES - self.len,
                )
            };
            if n == 0 {
                self.closed = true;
                return None;
            }
            if n < 0 {
                // Interrupted or nothing after all: the next round asks again.
                return None;
            }
            self.len += n as usize;
        }
    }

    /// Whether a byte (or the end of the stream) is waiting, without waiting for one.
    fn waiting(&self) -> bool {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live `pollfd`; a zero timeout returns at once.
        let ready = unsafe { libc::poll(&mut pfd, 1, 0) };
        ready > 0 && pfd.revents & (libc::POLLIN | libc::POLLHUP) != 0
    }
}

/// Write `text` and a line end to standard output.
pub fn reply(text: &str) {
    write_all(1, text.as_bytes());
    write_all(1, b"\n");
}

fn write_all(fd: libc::c_int, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        // SAFETY: `bytes` is live for its length.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n <= 0 {
            return;
        }
        bytes = &bytes[n as usize..];
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::io::Write as _;
    use std::os::fd::AsRawFd;
    use std::vec::Vec;

    /// A pipe: the reader's descriptor, and the writer to feed it from the test.
    fn pipe() -> (std::fs::File, Lines) {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` holds the two descriptors `pipe(2)` fills.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        use std::os::fd::FromRawFd;
        // SAFETY: the write end is a descriptor this test owns.
        let writer = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        (writer, Lines::on(fds[0]))
    }

    fn drain(lines: &mut Lines) -> Vec<(std::string::String, bool)> {
        let mut got = Vec::new();
        while let Some(line) = lines.take_line() {
            got.push((line.text.into(), line.overlong));
        }
        got
    }

    #[test]
    fn an_idle_channel_gives_no_line_and_does_not_block() {
        let (_writer, mut lines) = pipe();
        assert!(lines.take_line().is_none());
        assert!(!lines.is_closed());
    }

    #[test]
    fn lines_come_whole_in_order_and_a_partial_one_waits_for_its_end() {
        let (mut writer, mut lines) = pipe();
        writer.write_all(b"open abc\nopen d").unwrap();
        assert_eq!(drain(&mut lines), [("open abc".into(), false)]);
        writer.write_all(b"ef\n\nclose\n").unwrap();
        assert_eq!(
            drain(&mut lines),
            [
                ("open def".into(), false),
                ("".into(), false),
                ("close".into(), false)
            ]
        );
    }

    #[test]
    fn a_line_longer_than_the_buffer_is_cut_and_says_so() {
        let (mut writer, mut lines) = pipe();
        let long = std::vec![b'a'; LINE_BYTES + 40];
        writer.write_all(&long).unwrap();
        writer.write_all(b"\nopen a\n").unwrap();
        let got = drain(&mut lines);
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(got[0].1, "the long line is marked");
        assert_eq!(got[1], ("open a".into(), false));
    }

    #[test]
    fn the_end_of_the_stream_closes_the_channel() {
        let (mut writer, mut lines) = pipe();
        writer.write_all(b"open a\n").unwrap();
        drop(writer);
        assert_eq!(drain(&mut lines), [("open a".into(), false)]);
        assert!(lines.is_closed());
        let _ = std::io::stdout().as_raw_fd();
    }
}
