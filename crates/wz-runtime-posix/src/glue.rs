// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host program's console and its sleep: the few C library calls a `#![no_std]`
//! `#![no_main]` program makes beside the network. The counterpart of `wz-runtime-zephyr`'s
//! `glue`, over `write(2)` and `nanosleep(2)`.

use core::fmt::Write;

/// The bytes of one console line. A longer line is cut, never allocated for.
const LINE: usize = 256;

/// Write `msg` and a newline to standard error. Standard error, not standard output: a program's
/// output is the caller's, and a console line is a diagnostic.
pub fn log(msg: &str) {
    write_all(msg.as_bytes());
    write_all(b"\n");
}

/// [`log`] of a formatted line, built in a buffer on the stack and cut at 256 bytes.
pub fn log_args(args: core::fmt::Arguments<'_>) {
    let mut line = LineBuf {
        bytes: [0; LINE],
        len: 0,
    };
    let _ = line.write_fmt(args);
    write_all(&line.bytes[..line.len]);
    write_all(b"\n");
}

struct LineBuf {
    bytes: [u8; LINE],
    len: usize,
}

impl Write for LineBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let room = LINE - self.len;
        let take = s.len().min(room);
        self.bytes[self.len..self.len + take].copy_from_slice(&s.as_bytes()[..take]);
        self.len += take;
        Ok(())
    }
}

fn write_all(mut bytes: &[u8]) {
    while !bytes.is_empty() {
        // SAFETY: `bytes` is live for its length; descriptor 2 is the process's.
        let n = unsafe { libc::write(2, bytes.as_ptr().cast(), bytes.len()) };
        if n <= 0 {
            return;
        }
        bytes = &bytes[n as usize..];
    }
}

/// Sleep `us` microseconds. The cooperative loop's idle: a node that holds no socket sleeps its
/// tick here, and a node that holds one waits on the socket instead.
pub fn yield_us(us: u32) {
    let ts = libc::timespec {
        tv_sec: (us / 1_000_000) as libc::time_t,
        tv_nsec: ((us % 1_000_000) * 1_000) as libc::c_long,
    };
    // SAFETY: `ts` is a live `timespec`; the remainder pointer may be null. An interrupted sleep
    // is a short one, which the loop that calls this does not mind.
    unsafe { libc::nanosleep(&ts, core::ptr::null_mut()) };
}

/// What the panic handler does: say so on the console and abort the process. A node that
/// panicked holds state it cannot trust, and a host process has a supervisor that restarts it.
pub fn abort_after_panic() -> ! {
    log("wz: PANIC");
    // SAFETY: ends the process; nothing returns.
    unsafe { libc::abort() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_is_cut_at_its_buffer_and_never_overruns() {
        let mut line = LineBuf {
            bytes: [0; LINE],
            len: 0,
        };
        for _ in 0..100 {
            line.write_str("0123456789").unwrap();
        }
        assert_eq!(line.len, LINE);
    }
}
