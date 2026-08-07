// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y594 (B1) — the LIVE capture source, feeding the same dissection a pcap
//! file does.
//!
//! [`wz_capture`] reads a file. Everything above it — decapsulation, TCP flow
//! reassembly, the passive zenoh observer — takes a packet and a capture
//! instant and does not care where either came from, which is what its own
//! docs claimed ("an AF_PACKET or ring-buffer source replaces `pcap` without
//! touching anything below it") and what this module makes true.
//!
//! ## Why here and not in `wz-capture`
//!
//! `wz-capture` is `no_std` with ZERO third-party dependencies, deliberately: a
//! capture parser is a pure function of bytes and stays testable on any target.
//! A live tap is the opposite — a socket, a privilege, a kernel timestamp — so
//! putting it there would cost that crate its whole shape for one module. This
//! crate already has `std`, `libc`, and the [`AfPacketSocket`] that
//! R311y579 (G9) built for the raweth LINK, and a capture tap is the same
//! socket read for a different purpose.
//!
//! ## The clock is the KERNEL's, not the reader's
//!
//! `SO_TIMESTAMP` is enabled at open and every packet's instant is taken from
//! the `SCM_TIMESTAMP` control message. Reading the host clock after `recvmsg`
//! would time the READER — a scheduling delay would show up as network delay,
//! and a reader that fell behind would expire reassembly chains that were never
//! late. If the option cannot be set, [`LiveTap::open`] FAILS rather than
//! quietly falling back: a capture whose timestamps mean something different
//! from packet to packet is worse than one that does not start.
//!
//! ## What this is NOT
//!
//! No ring buffer (`PACKET_MMAP`), no BPF pre-filter, no snaplen. Those are
//! throughput features, and the honest order is to make the path exist before
//! tuning it. A tap that drops packets under load reports what it saw and the
//! kernel's own drop counter is not read here — so this is a development and
//! diagnosis tool, not a line-rate capture appliance, and the module says so
//! rather than leaving it to be discovered.

use std::io;
use std::os::fd::AsRawFd;
use std::time::Duration;

use wz_capture::link::LINKTYPE_ETHERNET;
use wz_capture::Dissection;

use crate::raweth_socket::AfPacketSocket;

/// One packet a [`PacketSource`] produced.
pub struct CapturedPacket<'a> {
    /// Capture-wide index, the anchor a decoded message is reported against.
    pub index: usize,
    /// When the KERNEL saw it, in milliseconds — the unit
    /// `PassiveSession::observe_at` speaks.
    pub ts_millis: u64,
    /// The frame, starting at the Ethernet header.
    pub bytes: &'a [u8],
}

/// Where packets come from.
///
/// A trait rather than a concrete socket for one reason that matters: the FEED
/// LOOP ([`pump`]) is the part with logic in it, and a loop that can only be
/// driven by a privileged socket is a loop that is never tested. A fake source
/// exercises it on any host.
pub trait PacketSource {
    /// The next packet, or `None` when the source is idle or exhausted.
    ///
    /// `None` is not an error and not an end: a live tap returns it on a read
    /// timeout, which is how a caller gets control back to decide whether to
    /// keep going.
    fn next_packet(&mut self) -> io::Result<Option<CapturedPacket<'_>>>;
}

/// A live `AF_PACKET` tap on one interface.
pub struct LiveTap {
    sock: AfPacketSocket,
    buf: Vec<u8>,
    control: Vec<u8>,
    next_index: usize,
    /// Length and instant of the packet currently in `buf`. Split from the
    /// borrow so `next_packet` can hand out a slice of `buf` without also
    /// lending the bookkeeping.
    last: (u64, usize),
}

impl LiveTap {
    /// Default read timeout: how long [`PacketSource::next_packet`] blocks
    /// before reporting idleness. Short enough that a caller polling a stop
    /// flag feels responsive; long enough not to spin.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(100);

    /// The largest frame stored. 64 KiB covers any Ethernet frame including
    /// jumbo; a packet longer than this is TRUNCATED by the kernel and the
    /// dissection sees a short frame, exactly as a pcap snaplen would produce.
    pub const CAPTURE_LEN: usize = 65_536;

    /// Open a tap on `interface`.
    ///
    /// Needs `CAP_NET_RAW`; without it this fails with
    /// [`io::ErrorKind::PermissionDenied`], which is the ordinary outcome for
    /// an unprivileged process rather than a misconfiguration.
    pub fn open(interface: &str) -> io::Result<Self> {
        Self::open_with_timeout(interface, Self::DEFAULT_TIMEOUT)
    }

    /// [`Self::open`] with an explicit read timeout.
    pub fn open_with_timeout(interface: &str, timeout: Duration) -> io::Result<Self> {
        let sock = AfPacketSocket::open(interface)?;
        set_timestamping(sock.as_raw_fd())?;
        set_read_timeout(sock.as_raw_fd(), timeout)?;
        Ok(Self {
            sock,
            buf: vec![0u8; Self::CAPTURE_LEN],
            // Room for one `SCM_TIMESTAMP` plus slack. `CMSG_SPACE` is not a
            // const fn, so this is sized generously rather than exactly; an
            // undersized control buffer sets `MSG_CTRUNC` and loses the
            // timestamp, which is the failure this must not risk.
            control: vec![0u8; 256],
            next_index: 0,
            last: (0, 0),
        })
    }
}

impl PacketSource for LiveTap {
    fn next_packet(&mut self) -> io::Result<Option<CapturedPacket<'_>>> {
        loop {
            let mut iov = libc::iovec {
                iov_base: self.buf.as_mut_ptr().cast(),
                iov_len: self.buf.len(),
            };
            // SAFETY: `msghdr` is a plain C struct; zeroing it is the
            // documented way to build one before filling the fields used.
            let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = self.control.as_mut_ptr().cast();
            msg.msg_controllen = self.control.len() as _;

            // SAFETY: the fd is open for the socket's lifetime, and `msg`
            // points at an iovec and control buffer that both outlive the call.
            let n = unsafe { libc::recvmsg(self.sock.as_raw_fd(), &mut msg, 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                return match err.raw_os_error() {
                    // A signal interrupted the wait; the caller asked for a
                    // packet, not for a syscall, so retry rather than surface
                    // an error it can only retry on itself.
                    Some(libc::EINTR) => continue,
                    // The read timeout elapsed: idle, not broken. `EAGAIN`
                    // and `EWOULDBLOCK` are the SAME value on Linux, so
                    // matching both is a pattern the compiler calls
                    // unreachable rather than a portability courtesy.
                    Some(libc::EAGAIN) => Ok(None),
                    _ => Err(err),
                };
            }

            let ts = timestamp_millis(&msg).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the kernel returned no SCM_TIMESTAMP despite SO_TIMESTAMP \
                     being set; a capture whose instants come from two different \
                     clocks is not evidence",
                )
            })?;

            let index = self.next_index;
            self.next_index += 1;
            self.last = (ts, n as usize);
            return Ok(Some(CapturedPacket {
                index,
                ts_millis: self.last.0,
                bytes: &self.buf[..self.last.1],
            }));
        }
    }
}

/// Drive `source` into `into` for at most `max_packets`, returning how many
/// were fed.
///
/// Bounded rather than looping forever, so the caller keeps control: a live tap
/// has no end, and a `pump` that owned the thread would make stopping someone
/// else's problem. Returning early on idleness is the same decision.
pub fn pump<S: PacketSource>(
    source: &mut S,
    into: &mut Dissection,
    max_packets: usize,
) -> io::Result<usize> {
    let mut fed = 0;
    while fed < max_packets {
        match source.next_packet()? {
            Some(p) => {
                into.push_packet_at(LINKTYPE_ETHERNET, p.index, Some(p.ts_millis), p.bytes);
                fed += 1;
            }
            None => break,
        }
    }
    Ok(fed)
}

fn set_timestamping(fd: std::os::fd::RawFd) -> io::Result<()> {
    let on: libc::c_int = 1;
    // SAFETY: `SO_TIMESTAMP` takes an `int`, whose address and size are passed.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMP,
            (&on as *const libc::c_int).cast(),
            core::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_read_timeout(fd: std::os::fd::RawFd, timeout: Duration) -> io::Result<()> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    // SAFETY: `SO_RCVTIMEO` takes a `struct timeval`, passed by address+size.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tv as *const libc::timeval).cast(),
            core::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The `SCM_TIMESTAMP` control message, in milliseconds.
fn timestamp_millis(msg: &libc::msghdr) -> Option<u64> {
    // SAFETY: `msg` is a fully-initialised `msghdr` whose control buffer was
    // filled by `recvmsg`; the CMSG walk is the documented traversal.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_TIMESTAMP {
                let mut tv: libc::timeval = core::mem::zeroed();
                core::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(cmsg),
                    (&mut tv as *mut libc::timeval).cast(),
                    core::mem::size_of::<libc::timeval>(),
                );
                return Some(tv.tv_sec as u64 * 1_000 + tv.tv_usec as u64 / 1_000);
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A source with no kernel behind it, so the FEED LOOP is provable on a
    /// host without `CAP_NET_RAW` — which is every developer machine and every
    /// unprivileged CI runner.
    struct Canned {
        packets: Vec<(u64, Vec<u8>)>,
        at: usize,
    }

    impl PacketSource for Canned {
        fn next_packet(&mut self) -> io::Result<Option<CapturedPacket<'_>>> {
            if self.at >= self.packets.len() {
                return Ok(None);
            }
            let index = self.at;
            self.at += 1;
            let (ts, bytes) = &self.packets[index];
            Ok(Some(CapturedPacket {
                index,
                ts_millis: *ts,
                bytes,
            }))
        }
    }

    /// Ethernet + IPv4 + UDP carrying `payload`, padded to the 60-byte minimum.
    fn udp_packet(payload: &[u8]) -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend_from_slice(&7447u16.to_be_bytes());
        udp.extend_from_slice(&7446u16.to_be_bytes());
        udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(payload);

        let mut ip = vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[224, 0, 0, 224]);
        ip.extend_from_slice(&udp);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    /// THE B1 CLAIM: a live source reaches the same dissection a file does, and
    /// the KERNEL's instant reaches the observer's clock.
    ///
    /// Asserted on the decoded flow AND on `now_ms`, because a pump that fed
    /// bytes but dropped the timestamp would satisfy the first alone — and the
    /// timestamp is the half B1 was blocked on.
    #[test]
    fn a_live_source_feeds_the_dissection_and_carries_the_kernels_clock() {
        let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let mut src = Canned {
            packets: vec![
                (1_000, udp_packet(&keepalive)),
                (9_500, udp_packet(&keepalive)),
            ],
            at: 0,
        };
        let mut d = Dissection::with_reassembly_window(5_000);

        let fed = pump(&mut src, &mut d, 16).expect("pump");
        assert_eq!(fed, 2, "both packets must be fed");
        assert_eq!(d.datagram_flows().len(), 1);
        assert_eq!(
            d.datagram_flows()[0].session.now_ms(),
            9_500,
            "the LAST packet's kernel instant is where the clock ends up"
        );
    }

    /// The bound is honoured, and an exhausted source stops the pump rather
    /// than spinning. Without this `pump` could ignore `max_packets` and the
    /// test above would still pass.
    #[test]
    fn the_pump_stops_at_its_budget_and_at_idleness() {
        let keepalive = [wz_session_core::wire_const::T_MID_KEEP_ALIVE];
        let mut src = Canned {
            packets: (0..5).map(|i| (i * 100, udp_packet(&keepalive))).collect(),
            at: 0,
        };
        let mut d = Dissection::new();

        assert_eq!(pump(&mut src, &mut d, 2).expect("pump"), 2, "budget of 2");
        assert_eq!(pump(&mut src, &mut d, 99).expect("pump"), 3, "the rest");
        assert_eq!(
            pump(&mut src, &mut d, 99).expect("pump"),
            0,
            "an exhausted source feeds nothing and returns"
        );
    }

    /// THE REAL SOCKET PATH, which no test above reaches: `recvmsg`, the CMSG
    /// walk, and a timestamp that came from the KERNEL.
    ///
    /// `#[ignore]`d because it needs `CAP_NET_RAW`. Everything else in this
    /// module is driven by a canned source, so without this the `recvmsg` and
    /// `SCM_TIMESTAMP` code would be a path that exists and never runs — the
    /// shape this repo has been burned by before. Run it with:
    ///
    /// ```text
    /// cargo test -p wz-runtime-tokio --features live-capture --lib --no-run
    /// sudo <the built binary> live_capture::tests::a_real_tap --ignored --exact
    /// ```
    ///
    /// The assertion is on the timestamp's ORIGIN, not merely its presence: a
    /// zero or a small number would pass an `is_some` check and prove nothing,
    /// so it is compared against the wall clock the kernel shares.
    #[test]
    #[ignore = "needs CAP_NET_RAW"]
    fn a_real_tap_reads_a_packet_with_a_kernel_timestamp() {
        use std::net::UdpSocket;
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut tap = LiveTap::open_with_timeout("lo", Duration::from_millis(500))
            .expect("CAP_NET_RAW and a loopback interface");

        // Traffic of our own making, so the test does not wait on whatever the
        // host happens to be doing.
        let tx = UdpSocket::bind("127.0.0.1:0").expect("bind");
        tx.send_to(b"wz-live-capture-probe", "127.0.0.1:9")
            .expect("send");

        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis() as u64;

        let mut seen = None;
        for _ in 0..20 {
            match tap.next_packet().expect("recvmsg") {
                Some(p) => {
                    if p.bytes.windows(21).any(|w| w == b"wz-live-capture-probe") {
                        seen = Some(p.ts_millis);
                        break;
                    }
                }
                None => break,
            }
        }
        let ts = seen.expect("the probe packet must come back on the loopback tap");

        // Within a minute of the wall clock in BOTH directions: a fabricated
        // zero fails the lower bound and a mis-scaled value (seconds read as
        // milliseconds, or the reverse) fails one of the two.
        assert!(
            ts + 60_000 > before && ts < before + 60_000,
            "kernel timestamp {ts} is not near the wall clock {before}"
        );
    }

    /// Opening a tap without `CAP_NET_RAW` must fail as a PERMISSION problem.
    ///
    /// Runs everywhere: unprivileged it asserts the errno, privileged it
    /// asserts the open succeeds on loopback. Either way the call is exercised,
    /// which is what keeps this from being a module nothing ever constructs.
    #[test]
    fn opening_a_tap_either_works_or_says_it_needs_privilege() {
        match LiveTap::open("lo") {
            Ok(_) => {}
            Err(e) => assert!(
                matches!(
                    e.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
                ),
                "expected a privilege or interface error, got {e:?}"
            ),
        }
    }
}
