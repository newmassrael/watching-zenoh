// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `scouting/multicast/ttl` through `z_open`: the hop limit a session's Scout leaves with is the
//! one the config names, and one when it names none (upstream's default, the OS's for a
//! multicast socket).
//!
//! The runtime's own tests read the option back from a socket they built by hand
//! (`McastSocketConfig { ttl: Some(8), .. }`), which shows the socket layer honours a value it is
//! given and not that the key reaches it. This file starts at the key: a client opens with it
//! stated on a group of its own, nobody answers, and the Scouts it sends are read off a receiver
//! joined to that group with `IP_RECVTTL`, so what is measured is the IP header field and not
//! anything wz reports about itself.
//!
//! ## Which of these run where
//!
//! The row needs a multicast datagram to be DELIVERED to a receiver on the same host, so it is
//! `#[ignore]`d and owned by Layer M for the reason `scouting_open.rs` states, and the file is
//! Linux only because the reader is raw `libc` (`recvmsg` and its control messages).
#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::net::Ipv4Addr;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use wz_capi_c::abi::{z_moved_config_t, z_moved_session_t, z_owned_config_t, z_owned_session_t};
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::result::{Z_ENETWORK, Z_OK};
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan_mut};

/// A group of this file's own, apart from the ones `scouting_open.rs` and `session_roles.rs`
/// use: the receiver must meet only the Scouts of the session the test opens.
fn group(n: u16) -> (Ipv4Addr, u16, String) {
    (
        Ipv4Addr::new(224, 0, 0, 231),
        7640 + n,
        format!("\"224.0.0.231:{}\"", 7640 + n),
    )
}

/// Open with `entries` inserted as json5 values, returning the result code and the session.
unsafe fn open_with(entries: &[(&str, String)]) -> (i8, z_owned_session_t) {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (key, value) in entries {
        let key = CString::new(*key).unwrap();
        let value = CString::new(value.as_str()).unwrap();
        assert_eq!(
            zc_config_insert_json5(z_config_loan_mut(&mut cfg), key.as_ptr(), value.as_ptr()),
            Z_OK
        );
    }
    let mut session: z_owned_session_t = std::mem::zeroed();
    let rc = z_open(
        &mut session,
        (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
        std::ptr::null(),
    );
    (rc, session)
}

unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}

/// An owned socket descriptor, closed on every return.
struct Fd(i32);

impl Drop for Fd {
    fn drop(&mut self) {
        // SAFETY: the descriptor is this value's own and is closed once.
        unsafe { libc::close(self.0) };
    }
}

fn set_option(fd: &Fd, level: i32, name: i32, value: &[u8]) {
    // SAFETY: `fd` is an open socket and `value` is a live slice of the length passed.
    let rc = unsafe {
        libc::setsockopt(
            fd.0,
            level,
            name,
            value.as_ptr().cast(),
            value.len() as libc::socklen_t,
        )
    };
    assert_eq!(
        rc,
        0,
        "setsockopt({level},{name}): {}",
        std::io::Error::last_os_error()
    );
}

/// A UDP socket bound to the wildcard at `port`, joined to `group` on the interface the kernel
/// picks (as the runtime's own scouting responder is, which these rows share a host with), asking
/// for the TTL of every datagram it receives. `SO_REUSEADDR` and `SO_REUSEPORT` come before the
/// bind because the session under test binds the same port.
fn joined_socket(group: Ipv4Addr, port: u16) -> Fd {
    // SAFETY: plain POSIX socket calls on a descriptor this function owns; every pointer passed
    // refers to a live local of the stated size.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(fd >= 0, "socket(): {}", std::io::Error::last_os_error());
    let fd = Fd(fd);
    let one = 1i32.to_ne_bytes();
    set_option(&fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &one);
    set_option(&fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, &one);

    let bind_addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    // SAFETY: `bind_addr` is a live `sockaddr_in` and the length passed is its size.
    let rc = unsafe {
        libc::bind(
            fd.0,
            (&bind_addr as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    assert_eq!(
        rc,
        0,
        "bind(0.0.0.0:{port}): {}",
        std::io::Error::last_os_error()
    );

    let mreq = libc::ip_mreq {
        imr_multiaddr: libc::in_addr {
            s_addr: u32::from(group).to_be(),
        },
        imr_interface: libc::in_addr { s_addr: 0 },
    };
    // SAFETY: a live `ip_mreq` viewed as its own bytes.
    let mreq_bytes = unsafe {
        std::slice::from_raw_parts(
            (&mreq as *const libc::ip_mreq).cast::<u8>(),
            std::mem::size_of::<libc::ip_mreq>(),
        )
    };
    set_option(&fd, libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP, mreq_bytes);
    set_option(&fd, libc::IPPROTO_IP, libc::IP_RECVTTL, &one);

    // A short receive timeout so the read loop can look at its deadline between datagrams.
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 200_000,
    };
    // SAFETY: a live `timeval` viewed as its own bytes.
    let tv_bytes = unsafe {
        std::slice::from_raw_parts(
            (&tv as *const libc::timeval).cast::<u8>(),
            std::mem::size_of::<libc::timeval>(),
        )
    };
    set_option(&fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, tv_bytes);
    fd
}

/// The IP TTL the kernel attached to the datagram `msg` describes.
fn ttl_in_control(msg: &libc::msghdr) -> Option<u8> {
    // SAFETY: `msg` was filled by `recvmsg` and its control buffer is live for this call; the
    // CMSG walk stays inside `msg_controllen`, which the kernel wrote.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let hdr = &*cmsg;
            if hdr.cmsg_level == libc::IPPROTO_IP && hdr.cmsg_type == libc::IP_TTL {
                let ttl = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<i32>());
                return u8::try_from(ttl).ok();
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    None
}

/// The TTL of every datagram that reaches `fd` within `span`.
fn collect_ttls(fd: &Fd, span: Duration) -> Vec<u8> {
    let deadline = Instant::now() + span;
    let mut ttls = Vec::new();
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline {
        let mut control = [0u8; 256];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: an all-zero `msghdr` is a valid empty one; the two buffers it points at outlive
        // the call below.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len() as _;
        // SAFETY: `fd` is an open socket and `msg` describes buffers that are live and writable.
        let n = unsafe { libc::recvmsg(fd.0, &mut msg, 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            match err.kind() {
                std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::Interrupted => continue,
                _ => panic!("recvmsg: {err}"),
            }
        }
        let ttl = ttl_in_control(&msg)
            .expect("a datagram arrived but the kernel attached no IP_TTL control message");
        ttls.push(ttl);
    }
    ttls
}

/// A receiver on `group` that reads on a thread of its own, started only once it has joined, so
/// the Scout of an open that follows is heard.
struct TtlReader {
    thread: JoinHandle<Vec<u8>>,
}

impl TtlReader {
    fn start(group: Ipv4Addr, port: u16, span: Duration) -> Self {
        let (ready_tx, ready) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let fd = joined_socket(group, port);
            let _ = ready_tx.send(());
            collect_ttls(&fd, span)
        });
        ready.recv().expect("the receiver joined its group");
        Self { thread }
    }

    /// The TTLs read, once the span has run out.
    fn finish(self) -> Vec<u8> {
        self.thread.join().expect("the receiver thread ended")
    }
}

/// A client with nobody to answer sends its Scouts with the hop limit `scouting/multicast/ttl`
/// names, and with one when the key is left alone.
///
/// The first arm is the control: with the key absent the Scout reads one, so the arms that follow
/// can only read their value if the key reached the socket, and a receiver that reported a fixed
/// number would fail the second of them. Each arm has a group of its own so a datagram of one
/// cannot be read in the next.
#[test]
#[ignore = "multicast loopback e2e; Layer M runs via --layer M / WZ_RUN_LAYER_M=1 --ignored"]
fn a_scout_leaves_with_the_ttl_the_config_names_and_with_one_when_it_names_none() {
    let arms: [(u16, Option<u32>, u8); 3] = [(1, None, 1), (2, Some(7), 7), (3, Some(31), 31)];
    for (n, ttl, expected) in arms {
        let (group_ip, group_port, group_text) = group(n);
        let reader = TtlReader::start(group_ip, group_port, Duration::from_millis(2500));
        let mut entries = vec![
            ("mode", String::from("\"client\"")),
            ("scouting/multicast/address", group_text),
            ("scouting/timeout", String::from("600")),
        ];
        if let Some(ttl) = ttl {
            entries.push(("scouting/multicast/ttl", ttl.to_string()));
        }
        // SAFETY: a fresh config and session.
        let (rc, session) = unsafe { open_with(&entries) };
        assert_eq!(
            rc, Z_ENETWORK,
            "nobody answers on a group of its own, so the client's search ends in a failed open \
             ({ttl:?})"
        );
        // SAFETY: a gravestone drops as a no-op.
        unsafe { close_session(session) };
        let ttls = reader.finish();
        assert!(
            !ttls.is_empty(),
            "no Scout reached a receiver joined to the group ({ttl:?}): the host delivered no \
             multicast, so the hop limit read nothing"
        );
        assert!(
            ttls.iter().all(|read| *read == expected),
            "`scouting/multicast/ttl` = {ttl:?} sent Scouts with IP TTLs {ttls:?}, not {expected}"
        );
    }
}
