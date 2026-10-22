// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "transport-link-serial", target_os = "linux"))]

//! The `serial/` link through the pico C ABI: a session listening on one tty receives a sample
//! put by a session that dialled another, the two ttys being the two ends of one wire.
//!
//! zenoh-pico builds this link under `Z_FEATURE_LINK_SERIAL` (default 0), and this crate's twin
//! is `transport-link-serial`, off by default. As for the ws link, the refusal in a build
//! without it is the runtime's typed `Unsupported`, held by the runtime's own tests.
//!
//! Both ends open their device BY PATH, which is what the locator names, and one pty pair has
//! only one path (the slave; the master is a descriptor). So the wire is two pty pairs whose
//! masters this process pumps into each other, the shape `wz-integration-tests`' pico serial
//! witness uses. Each slave is held open and never read: a master read fails with `EIO` once
//! the last slave descriptor closes, and a reader on the slave would take the session's bytes.
//! The slaves are made raw before either session opens them, so a byte pumped early is not
//! echoed or rewritten by the line discipline.
//!
//! Linux only: the pty calls are `posix_openpt` and `ptsname_r`, and on macOS a pty opened by
//! path refuses the speed ioctl the serial backend issues (the runtime's serial tests record
//! the same limit).
//!
//! RED reproduction: drop `wz-runtime-tokio/transport-link-serial` from this crate's
//! `transport-link-serial` feature and from `wz-capi-core`'s, and the listener's `z_open`
//! fails at bind.

mod link_roundtrip;

use std::ffi::CStr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use link_roundtrip::{payloads_across, PAYLOAD};

/// The panic message of a failed libc call: what was called and the OS's reason.
fn os_error(call: &str) -> String {
    format!("{call}: {}", std::io::Error::last_os_error())
}

/// One pseudo-terminal: the master the pump reads and writes, and the slave's device path,
/// which is what a `serial/` endpoint names.
struct Pty {
    master: OwnedFd,
    path: String,
    _slave: OwnedFd,
}

impl Pty {
    fn open() -> Self {
        // SAFETY: every call's result is checked before it is used, each descriptor is owned
        // by an `OwnedFd` from the moment it exists, and `name` outlives the calls that read it.
        unsafe {
            let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(master >= 0, "{}", os_error("posix_openpt"));
            let master = OwnedFd::from_raw_fd(master);
            let fd = master.as_raw_fd();
            assert_eq!(libc::grantpt(fd), 0, "{}", os_error("grantpt"));
            assert_eq!(libc::unlockpt(fd), 0, "{}", os_error("unlockpt"));
            let flags = libc::fcntl(fd, libc::F_GETFL);
            assert!(flags >= 0, "{}", os_error("fcntl(F_GETFL)"));
            assert_ne!(
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK),
                -1,
                "{}",
                os_error("fcntl(F_SETFL)")
            );

            let mut name: [libc::c_char; 128] = [0; 128];
            let rc = libc::ptsname_r(fd, name.as_mut_ptr(), name.len());
            assert_eq!(rc, 0, "ptsname_r: errno {rc}");
            let slave = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
            assert!(slave >= 0, "{}", os_error("open(pts)"));
            let slave = OwnedFd::from_raw_fd(slave);

            let mut termios: libc::termios = std::mem::zeroed();
            assert_eq!(
                libc::tcgetattr(slave.as_raw_fd(), &mut termios),
                0,
                "{}",
                os_error("tcgetattr")
            );
            libc::cfmakeraw(&mut termios);
            assert_eq!(
                libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &termios),
                0,
                "{}",
                os_error("tcsetattr")
            );

            let path = CStr::from_ptr(name.as_ptr())
                .to_str()
                .expect("a pts path is UTF-8")
                .to_owned();
            Pty {
                master,
                path,
                _slave: slave,
            }
        }
    }
}

/// Two ptys joined master to master: what one end's slave is written, the other end's slave
/// reads. Pumped by a thread of its own until dropped.
struct Wire {
    stop: Arc<AtomicBool>,
    pump: Option<JoinHandle<()>>,
}

impl Wire {
    /// Join `a` and `b`; answers the wire and the two device paths.
    fn join(a: Pty, b: Pty) -> (Self, String, String) {
        let (path_a, path_b) = (a.path.clone(), b.path.clone());
        let stop = Arc::new(AtomicBool::new(false));
        let pump = {
            let stop = stop.clone();
            std::thread::spawn(move || pump_bytes(&a, &b, &stop))
        };
        let wire = Wire {
            stop,
            pump: Some(pump),
        };
        (wire, path_a, path_b)
    }
}

impl Drop for Wire {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(pump) = self.pump.take() {
            let _ = pump.join();
        }
    }
}

/// Move bytes both ways between the two masters until `stop`. The masters are non-blocking,
/// so a stop is seen within one poll interval even while a write waits for room.
fn pump_bytes(a: &Pty, b: &Pty, stop: &AtomicBool) {
    let ends = [a.master.as_raw_fd(), b.master.as_raw_fd()];
    let mut buf = [0u8; 4096];
    while !stop.load(Ordering::SeqCst) {
        let mut fds = ends.map(|fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        });
        // SAFETY: `fds` is a live array of two `pollfd`s for the duration of the call.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 20) };
        let mut moved = false;
        if ready > 0 {
            for (from, to) in [(0, 1), (1, 0)] {
                if fds[from].revents & libc::POLLIN == 0 {
                    continue;
                }
                // SAFETY: `buf` is valid for writes of its whole length.
                let n = unsafe { libc::read(ends[from], buf.as_mut_ptr().cast(), buf.len()) };
                if n > 0 {
                    write_all(ends[to], &buf[..n as usize], stop);
                    moved = true;
                }
            }
        }
        // A descriptor that reports a condition but yields no bytes would otherwise turn this
        // loop into a spin.
        if ready > 0 && !moved {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

fn write_all(fd: RawFd, mut bytes: &[u8], stop: &AtomicBool) {
    while !bytes.is_empty() && !stop.load(Ordering::SeqCst) {
        // SAFETY: `bytes` is valid for reads of its whole length.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n > 0 {
            bytes = &bytes[n as usize..];
        } else {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

#[test]
fn a_sample_crosses_a_serial_link_between_two_pico_sessions() {
    let (_wire, listened, dialled) = Wire::join(Pty::open(), Pty::open());
    let received = payloads_across(
        &format!("serial/{listened}#baudrate=115200"),
        &format!("serial/{dialled}#baudrate=115200"),
    );
    assert_eq!(
        received.first().map(Vec::as_slice),
        Some(PAYLOAD.to_bytes()),
        "nothing, or something else, reached the serial listener's subscriber: {received:?}"
    );
}
