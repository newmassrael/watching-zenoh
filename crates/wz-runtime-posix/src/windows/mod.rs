// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Windows host of the cooperative engine: the seams the POSIX half of this crate gives a
//! Linux process, over the system's own calls instead of a C library's.
//!
//! 1. [`WindowsClock`] -- a [`ClockSource`] over the performance counter
//!    (`QueryPerformanceCounter`), which never steps back.
//! 2. [`WindowsEntropy`] -- the session core's `EntropySource`, over the system's preferred
//!    generator (`BCryptGenRandom`).
//! 3. [`WindowsEpoch`] -- the session core's `EpochSource`, over the precise system time
//!    (`GetSystemTimePreciseAsFileTime`).
//! 4. [`net`] -- UDP over Winsock ([`net::WindowsUdpSocket`]), with the group membership a member
//!    of a multicast group asks for; [`stream`] -- TCP over Winsock
//!    ([`stream::WindowsTcpSocket`], its dial and its listener); [`links`](mod@links), the
//!    two as the session shell's links on the heap profile, which is what the pico C ABI's
//!    cooperative engine is opened over; under `session-slot`, the crate's `slot`
//!    holds the two as the stack the slot profile's session host is given
//!    (`slot::WindowsStack`), whose links take their buffers from the program's tables; and
//!    [`group`](mod@group), a multicast group's two sockets as the group transport the shared
//!    group drive loop runs on.
//!
//! A socket is made non-inheritable (a child the program starts holds none of them, as a
//! close-on-exec descriptor is not held by a program the process executes), and is waited on
//! with `WSAPoll`: a read never blocks, a wait is bounded, and a write blocks until the stack has
//! taken every byte, as the POSIX sockets of this crate do. Winsock is started on the first
//! socket the process asks for and stays started for the life of the process.
//!
//! What the POSIX half has and this one does not: the console and panic glue of a `#![no_std]`
//! `#![no_main]` program, the control line, the file reads, and the interface lookup a group
//! join falls back to. The first three serve a program built from this crate alone, a node of
//! the kit's kind, which a Windows process is not: what runs the slot profile here is a library a
//! program with its own entry point links. In place of the last, Winsock picks the interface when a
//! join names the unspecified one.

use core::mem::size_of;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use core::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::Networking::WinSock as ws;
use wz_runtime_coop::ClockSource;

use crate::windows_arith;

// Compiled where the runtime declares the heap profile's seams (`with_heap_link_seams!`), as
// every implementation of them in this module is.
wz_runtime_coop::with_heap_link_seams! {
    #[cfg(feature = "alloc")]
    use wz_runtime_coop::session_drive::{LinkReadiness, LinkWritability};
}

wz_runtime_coop::with_heap_link_seams! {
    #[cfg(feature = "alloc")]
    pub mod links;
}
pub mod group;
pub mod net;
pub mod stream;

/// Monotonic [`ClockSource`] over the performance counter.
///
/// Zero-sized and `Copy`: the clock is the system's. The counter never steps back and is not
/// the wall clock (see [`WindowsEpoch`]), so a date set by an administrator moves no timer of a
/// session. Its frequency is fixed at boot and read with each reading, which costs a read of
/// memory the system shares with the process.
#[derive(Clone, Copy, Default)]
pub struct WindowsClock;

impl ClockSource for WindowsClock {
    fn now_us(&self) -> u64 {
        let mut ticks = 0_i64;
        let mut frequency = 0_i64;
        // SAFETY: two live locals the calls write. Neither call fails on a system that runs
        // Windows XP or later; a counter left at zero reads as time stood still.
        unsafe {
            windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut ticks);
            windows_sys::Win32::System::Performance::QueryPerformanceFrequency(&mut frequency);
        }
        windows_arith::ticks_to_us(ticks, frequency)
    }
}

/// The session core's [`EntropySource`](wz_session_core::entropy::EntropySource) over the
/// system's preferred random number generator. A refusal fails the fill: the cookie nonce and
/// the signing key must never be made of whatever the buffer held.
#[derive(Clone, Copy, Default)]
pub struct WindowsEntropy;

impl wz_session_core::entropy::EntropySource for WindowsEntropy {
    fn try_fill_bytes(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(), wz_session_core::entropy::EntropyUnavailable> {
        use windows_sys::Win32::Security::Cryptography::{
            BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        };
        // The call takes a 32-bit length, so a larger buffer is filled a piece at a time.
        for piece in buf.chunks_mut(u32::MAX as usize) {
            // SAFETY: `piece` is live and writable for its length, which fits the `u32` passed;
            // a null algorithm handle with the system-preferred flag names the system's
            // generator.
            let status = unsafe {
                BCryptGenRandom(
                    core::ptr::null_mut(),
                    piece.as_mut_ptr(),
                    piece.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            // An `NTSTATUS` below zero is a failure.
            if status < 0 {
                return Err(wz_session_core::entropy::EntropyUnavailable);
            }
        }
        Ok(())
    }
}

/// The session core's [`EpochSource`](wz_session_core::epoch::EpochSource) over the precise
/// system time. A date before 1970 is refused rather than read as the epoch.
#[derive(Clone, Copy, Default)]
pub struct WindowsEpoch;

impl wz_session_core::epoch::EpochSource for WindowsEpoch {
    fn try_since_epoch(
        &self,
    ) -> Result<wz_session_core::epoch::SinceEpoch, wz_session_core::epoch::EpochUnavailable> {
        let mut now = windows_sys::Win32::Foundation::FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        // SAFETY: `now` is a live `FILETIME` the call writes; the call cannot fail.
        unsafe {
            windows_sys::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime(&mut now)
        };
        let intervals = windows_arith::filetime_intervals(now.dwLowDateTime, now.dwHighDateTime);
        let (secs, nanos) = windows_arith::filetime_since_unix_epoch(intervals)
            .ok_or(wz_session_core::epoch::EpochUnavailable)?;
        Ok(wz_session_core::epoch::SinceEpoch { secs, nanos })
    }
}

/// Why a socket call failed: the call, and the Winsock error code it left (`WSAGetLastError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsNetError {
    /// `WSAStartup` failed with this code: the process has no Winsock to give a socket.
    Startup(i32),
    /// `WSASocketW` failed with this code (`WSAEAFNOSUPPORT`: the system has no socket of the
    /// family).
    Socket(i32),
    /// The report of an unreachable port could not be turned off on a datagram socket
    /// (`WSAIoctl(SIO_UDP_CONNRESET)`), with this code.
    ResetReport(i32),
    /// `bind` failed with this code.
    Bind(i32),
    /// `ioctlsocket(FIONBIO)` on a listening or an accepted socket failed with this code.
    NonBlocking(i32),
    /// `setsockopt(SO_REUSEADDR)` failed with this code.
    ReuseAddr(i32),
    /// `setsockopt(IP_ADD_MEMBERSHIP)` or `setsockopt(IPV6_ADD_MEMBERSHIP)` failed with this code:
    /// the group could not be joined on the interface asked for.
    Membership(i32),
    /// A multicast interface was named in the other family than the group's or the socket's (an
    /// IPv4 address for an IPv6 group, an index for an IPv4 one), so no system call was made.
    InterfaceFamily,
    /// `setsockopt` of a multicast egress option (`IP_MULTICAST_IF`, `IP_MULTICAST_TTL`) failed
    /// with this code.
    MulticastOption(i32),
    /// `listen` failed with this code.
    Listen(i32),
    /// `getsockname` failed with this code reading back the port a bind on port 0 was given.
    SockName(i32),
    /// A bind on port 0 succeeded and the system reported port 0 all the same, so there is no
    /// port for the link's locator to name.
    NoPortChosen,
    /// `sendto` took this many bytes (`SOCKET_ERROR`: refused, with the code in the second
    /// field) of a datagram.
    Send(i32, i32),
    /// `recvfrom` (or a stream's `recv`) failed with this code.
    Recv(i32),
    /// `connect` failed with this code.
    Connect(i32),
    /// `setsockopt(TCP_NODELAY)` failed with this code.
    NoDelay(i32),
    /// `getpeername` failed with this code.
    PeerName(i32),
    /// A stream's `WSASend` failed with this code.
    Write(i32),
}

/// Whether this process has started Winsock. Set once the start succeeded; two threads that
/// both find it unset both start it, which Winsock counts and which is harmless.
static STARTED: AtomicBool = AtomicBool::new(false);

/// Start Winsock (version 2.2, which every Windows since 98 has) if this process has not. It is
/// never cleaned up: the process keeps its sockets until it ends, and the system releases them
/// then.
pub(crate) fn startup() -> Result<(), WindowsNetError> {
    if STARTED.load(Ordering::Acquire) {
        return Ok(());
    }
    let mut data = ws::WSADATA::default();
    // SAFETY: `data` is a live `WSADATA` the call writes.
    let rc = unsafe { ws::WSAStartup(0x0202, &mut data) };
    if rc != 0 {
        return Err(WindowsNetError::Startup(rc));
    }
    STARTED.store(true, Ordering::Release);
    Ok(())
}

/// The calling thread's last Winsock error.
pub(crate) fn last_error() -> i32 {
    // SAFETY: reads the calling thread's own error slot.
    unsafe { ws::WSAGetLastError() }
}

/// The system's family number of `at`: `AF_INET` or `AF_INET6`.
pub(crate) fn family_of(at: &SocketAddr) -> i32 {
    match at {
        SocketAddr::V4(_) => i32::from(ws::AF_INET),
        SocketAddr::V6(_) => i32::from(ws::AF_INET6),
    }
}

/// A socket of `at`'s family, of `kind` and `protocol`, that no child process inherits, once
/// Winsock is started. Overlapped, as `socket` makes one, so that a blocking call on it behaves
/// as on any other socket of the process.
pub(crate) fn open_socket(
    at: &SocketAddr,
    kind: i32,
    protocol: i32,
) -> Result<ws::SOCKET, WindowsNetError> {
    startup()?;
    // SAFETY: value arguments and no protocol description.
    let socket = unsafe {
        ws::WSASocketW(
            family_of(at),
            kind,
            protocol,
            core::ptr::null(),
            0,
            ws::WSA_FLAG_OVERLAPPED | ws::WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    if socket == ws::INVALID_SOCKET {
        return Err(WindowsNetError::Socket(last_error()));
    }
    Ok(socket)
}

/// Close `socket`. A failure leaves nothing for the caller to do: the socket is gone either way.
pub(crate) fn close(socket: ws::SOCKET) {
    // SAFETY: the caller's own socket, closed exactly once.
    unsafe { ws::closesocket(socket) };
}

/// Set the socket option `name` of `level` on `socket` to `value`: the code when the system
/// refuses.
pub(crate) fn set_option<T>(
    socket: ws::SOCKET,
    level: i32,
    name: i32,
    value: &T,
) -> Result<(), i32> {
    // SAFETY: `value` is a live `T` and the length passed is its size.
    let rc = unsafe {
        ws::setsockopt(
            socket,
            level,
            name,
            (value as *const T).cast::<u8>(),
            size_of::<T>() as i32,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(last_error())
    }
}

/// Switch the boolean socket option `name` of `level` on for `socket` (a `BOOL` of 1).
pub(crate) fn set_flag(socket: ws::SOCKET, level: i32, name: i32) -> Result<(), i32> {
    set_option(socket, level, name, &1_i32)
}

/// Make `socket` non-blocking or blocking (`ioctlsocket(FIONBIO)`): the code when the system
/// refuses. A connection a non-blocking listener hands over is non-blocking on Windows, and is
/// made blocking here, as a dialled one is.
pub(crate) fn set_nonblocking(socket: ws::SOCKET, on: bool) -> Result<(), i32> {
    let mut mode = u32::from(on);
    // SAFETY: `mode` is a live `u32` the call reads.
    if unsafe { ws::ioctlsocket(socket, ws::FIONBIO, &mut mode) } != 0 {
        return Err(last_error());
    }
    Ok(())
}

/// Keep `socket` from a child process the program starts: `false` when the system refuses. A
/// socket this module opens is made so; one `accept` hands over is asked again here, as the
/// POSIX half sets close-on-exec on an accepted descriptor.
pub(crate) fn keep_from_children(socket: ws::SOCKET) -> bool {
    use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT};
    // SAFETY: a socket is a kernel handle the call takes by value.
    unsafe { SetHandleInformation(socket as HANDLE, HANDLE_FLAG_INHERIT, 0) != 0 }
}

/// Whether `socket` has input (a datagram, bytes, the end of a stream, a connection on a
/// listener, or an error the next read reports) within `timeout_ms` milliseconds; at once when
/// it already has, and without waiting at 0. A failed wait is a quiet socket: the read that
/// follows reads and reports the error.
pub(crate) fn poll_readable(socket: ws::SOCKET, timeout_ms: i32) -> bool {
    let mut fd = ws::WSAPOLLFD {
        fd: socket,
        events: ws::POLLRDNORM,
        revents: 0,
    };
    // SAFETY: one live `WSAPOLLFD`; the timeout bounds the wait.
    let ready = unsafe { ws::WSAPoll(&mut fd, 1, timeout_ms) };
    ready > 0 && fd.revents != 0
}

/// Whether `socket` takes more bytes (or has failed, which the write that follows reports) within
/// `timeout_ms` milliseconds; at once when it already does. A failed wait is a socket that did not
/// become writable.
pub(crate) fn poll_writable(socket: ws::SOCKET, timeout_ms: i32) -> bool {
    let mut fd = ws::WSAPOLLFD {
        fd: socket,
        events: ws::POLLWRNORM,
        revents: 0,
    };
    // SAFETY: one live `WSAPOLLFD`; the timeout bounds the wait.
    let ready = unsafe { ws::WSAPoll(&mut fd, 1, timeout_ms) };
    ready > 0 && fd.revents != 0
}

/// The address an IPv4 address is in Winsock's form.
pub(crate) fn in_addr(address: Ipv4Addr) -> ws::IN_ADDR {
    ws::IN_ADDR {
        S_un: ws::IN_ADDR_0 {
            S_addr: u32::from_ne_bytes(address.octets()),
        },
    }
}

/// An IPv6 address in Winsock's form.
pub(crate) fn in6_addr(address: Ipv6Addr) -> ws::IN6_ADDR {
    ws::IN6_ADDR {
        u: ws::IN6_ADDR_0 {
            Byte: address.octets(),
        },
    }
}

/// A socket address as Winsock reads and writes it, of either family: a `SOCKADDR_STORAGE`
/// holding a `SOCKADDR_IN` or a `SOCKADDR_IN6`, and the length of the one it holds. The one
/// conversion between it and [`SocketAddr`], both ways.
pub(crate) struct RawAddr {
    storage: ws::SOCKADDR_STORAGE,
    len: i32,
}

impl RawAddr {
    /// `at` in Winsock's form, for a call that reads an address (`bind`, `connect`, `sendto`).
    pub(crate) fn of(at: SocketAddr) -> Self {
        let mut storage = ws::SOCKADDR_STORAGE::default();
        let len = match at {
            SocketAddr::V4(v4) => {
                let sin = ws::SOCKADDR_IN {
                    sin_family: ws::AF_INET,
                    sin_port: v4.port().to_be(),
                    sin_addr: in_addr(*v4.ip()),
                    sin_zero: [0; 8],
                };
                // SAFETY: `SOCKADDR_STORAGE` is large and aligned enough for every socket address
                // Winsock has, so a `SOCKADDR_IN` written at its start is in bounds.
                unsafe {
                    core::ptr::write((&mut storage as *mut ws::SOCKADDR_STORAGE).cast(), sin)
                };
                size_of::<ws::SOCKADDR_IN>()
            }
            SocketAddr::V6(v6) => {
                let sin6 = ws::SOCKADDR_IN6 {
                    sin6_family: ws::AF_INET6,
                    sin6_port: v6.port().to_be(),
                    sin6_flowinfo: v6.flowinfo(),
                    sin6_addr: in6_addr(*v6.ip()),
                    Anonymous: ws::SOCKADDR_IN6_0 {
                        sin6_scope_id: v6.scope_id(),
                    },
                };
                // SAFETY: as for the IPv4 form: the storage holds any socket address.
                unsafe {
                    core::ptr::write((&mut storage as *mut ws::SOCKADDR_STORAGE).cast(), sin6)
                };
                size_of::<ws::SOCKADDR_IN6>()
            }
        };
        Self {
            storage,
            len: len as i32,
        }
    }

    /// Room for any address, for a call that writes one (`recvfrom`, `getsockname`, `accept`).
    pub(crate) fn empty() -> Self {
        Self {
            storage: ws::SOCKADDR_STORAGE::default(),
            len: size_of::<ws::SOCKADDR_STORAGE>() as i32,
        }
    }

    /// The address, for a call that reads it.
    pub(crate) fn as_ptr(&self) -> *const ws::SOCKADDR {
        (&self.storage as *const ws::SOCKADDR_STORAGE).cast()
    }

    /// The address, for a call that writes it.
    pub(crate) fn as_mut_ptr(&mut self) -> *mut ws::SOCKADDR {
        (&mut self.storage as *mut ws::SOCKADDR_STORAGE).cast()
    }

    /// The length a call reads.
    pub(crate) fn size(&self) -> i32 {
        self.len
    }

    /// The length a call that writes the address reads as the room it has and sets to the length
    /// it wrote.
    pub(crate) fn size_mut(&mut self) -> &mut i32 {
        &mut self.len
    }

    /// The address Winsock wrote, or `None` for a family other than the two. The flow label is
    /// left out, as the POSIX half leaves it: a link compares its peer by address, port and
    /// scope.
    pub(crate) fn to_socket_addr(&self) -> Option<SocketAddr> {
        let len = usize::try_from(self.len).unwrap_or(0);
        match self.storage.ss_family {
            ws::AF_INET if len >= size_of::<ws::SOCKADDR_IN>() => {
                // SAFETY: Winsock wrote an `AF_INET` address, which is a `SOCKADDR_IN`, and the
                // storage is aligned for it.
                let sin = unsafe { &*(self.as_ptr() as *const ws::SOCKADDR_IN) };
                // SAFETY: every member of the address union is the same four bytes.
                let address = unsafe { sin.sin_addr.S_un.S_addr };
                Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(address.to_ne_bytes()),
                    u16::from_be(sin.sin_port),
                )))
            }
            ws::AF_INET6 if len >= size_of::<ws::SOCKADDR_IN6>() => {
                // SAFETY: Winsock wrote an `AF_INET6` address, which is a `SOCKADDR_IN6`, and the
                // storage is aligned for it.
                let sin6 = unsafe { &*(self.as_ptr() as *const ws::SOCKADDR_IN6) };
                // SAFETY: every member of the address union is the same sixteen bytes, and every
                // member of the scope union the same four.
                let (octets, scope) =
                    unsafe { (sin6.sin6_addr.u.Byte, sin6.Anonymous.sin6_scope_id) };
                Some(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(octets),
                    u16::from_be(sin6.sin6_port),
                    0,
                    scope,
                )))
            }
            _ => None,
        }
    }
}

/// The address a `getsockname` or `getpeername` of `socket` reports: the code when the call
/// fails, `WSAEAFNOSUPPORT` when it names a family other than the two.
pub(crate) fn name_of(
    socket: ws::SOCKET,
    call: unsafe extern "system" fn(ws::SOCKET, *mut ws::SOCKADDR, *mut i32) -> i32,
) -> Result<SocketAddr, i32> {
    let mut name = RawAddr::empty();
    // SAFETY: `name`'s storage and length are live and writable, and the length is its size.
    let rc = unsafe { call(socket, name.as_mut_ptr(), name.size_mut()) };
    if rc != 0 {
        return Err(last_error());
    }
    name.to_socket_addr().ok_or(ws::WSAEAFNOSUPPORT)
}

wz_runtime_coop::with_heap_link_seams! {
/// A wait of `timeout_ms` milliseconds as `WSAPoll` takes it; a longer one than it can say is the
/// longest it can.
#[cfg(feature = "alloc")]
fn wait_ms(timeout_ms: u32) -> i32 {
    i32::try_from(timeout_ms).unwrap_or(i32::MAX)
}

/// A wait on a socket that a thread other than its link's makes, for input ([`LinkReadiness`])
/// or for room ([`LinkWritability`]): `WSAPoll` on a duplicate of the socket, which this owns and
/// closes. A duplicate and not the handle itself, so a wait that outlives the socket never
/// reaches a handle value its close has freed for another object.
#[cfg(feature = "alloc")]
pub(crate) struct SocketReadiness(ws::SOCKET);

#[cfg(feature = "alloc")]
impl SocketReadiness {
    /// A wait for input on `socket`, or `None` when the socket cannot be duplicated.
    pub(crate) fn of(socket: ws::SOCKET) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
        Some(alloc::boxed::Box::new(Self::duplicate(socket)?))
    }

    /// A wait for room on the stream `socket`, or `None` when the socket cannot be duplicated.
    pub(crate) fn writable_of(
        socket: ws::SOCKET,
    ) -> Option<alloc::boxed::Box<dyn LinkWritability>> {
        Some(alloc::boxed::Box::new(Self::duplicate(socket)?))
    }

    /// A wait on `socket`, or `None` when the socket cannot be duplicated.
    fn duplicate(socket: ws::SOCKET) -> Option<Self> {
        let mut info = ws::WSAPROTOCOL_INFOW::default();
        // SAFETY: `info` is a live description the call writes; `socket` is the caller's open
        // socket, and the process the duplicate is for is this one.
        let rc = unsafe {
            ws::WSADuplicateSocketW(
                socket,
                windows_sys::Win32::System::Threading::GetCurrentProcessId(),
                &mut info,
            )
        };
        if rc != 0 {
            return None;
        }
        // SAFETY: `info` is the description the call above wrote, which names the family, the
        // type and the protocol of the duplicate.
        let duplicate = unsafe {
            ws::WSASocketW(
                ws::FROM_PROTOCOL_INFO,
                ws::FROM_PROTOCOL_INFO,
                ws::FROM_PROTOCOL_INFO,
                &info,
                0,
                ws::WSA_FLAG_OVERLAPPED | ws::WSA_FLAG_NO_HANDLE_INHERIT,
            )
        };
        if duplicate == ws::INVALID_SOCKET {
            return None;
        }
        Some(SocketReadiness(duplicate))
    }
}

#[cfg(feature = "alloc")]
impl LinkWritability for SocketReadiness {
    fn wait_writable(&self, timeout_us: u64) -> bool {
        poll_writable(
            self.0,
            i32::try_from(timeout_us.div_ceil(1_000)).unwrap_or(i32::MAX),
        )
    }
}

#[cfg(feature = "alloc")]
impl LinkReadiness for SocketReadiness {
    fn wait_readable(&self, timeout_ms: u32) {
        poll_readable(self.0, wait_ms(timeout_ms));
    }

    fn handle(&self) -> Option<usize> {
        Some(self.0)
    }

    fn wait_readable_among(&self, others: &[alloc::sync::Arc<dyn LinkReadiness>], timeout_ms: u32) {
        let mut fds = alloc::vec![ws::WSAPOLLFD {
            fd: self.0,
            events: ws::POLLRDNORM,
            revents: 0,
        }];
        for other in others {
            match other.handle() {
                Some(socket) => fds.push(ws::WSAPOLLFD {
                    fd: socket,
                    events: ws::POLLRDNORM,
                    revents: 0,
                }),
                // A wait this cannot name to the system: the bounded look, so it is not starved
                // behind a wait on the others.
                None => return self.wait_readable(timeout_ms.min(1)),
            }
        }
        // SAFETY: `fds` is live for the call and its length is the count passed; every socket is
        // a duplicate its owner holds open for as long as the wait is held, and the timeout
        // bounds the wait. A failed wait is a quiet socket: the step that follows reads and
        // reports the error.
        unsafe { ws::WSAPoll(fds.as_mut_ptr(), fds.len() as u32, wait_ms(timeout_ms)) };
    }
}

#[cfg(feature = "alloc")]
impl Drop for SocketReadiness {
    fn drop(&mut self) {
        close(self.0);
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::entropy::EntropySource;
    use wz_session_core::epoch::EpochSource;

    #[test]
    fn the_clock_does_not_step_back_and_moves() {
        let clock = WindowsClock;
        let first = clock.now_us();
        let mut last = first;
        for _ in 0..1000 {
            let now = clock.now_us();
            assert!(now >= last, "a monotonic clock does not step back");
            last = now;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(clock.now_us() >= first + 15_000, "twenty milliseconds pass");
    }

    #[test]
    fn entropy_fills_the_whole_buffer_and_differs_between_draws() {
        let mut entropy = WindowsEntropy;
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        entropy
            .try_fill_bytes(&mut a)
            .expect("the system generator");
        entropy
            .try_fill_bytes(&mut b)
            .expect("the system generator");
        assert_ne!(a, [0u8; 64], "64 zero bytes from a CSPRNG is not a draw");
        assert_ne!(a, b, "two draws of 64 bytes are not the same");
        let mut big = [0u8; 4096];
        entropy.try_fill_bytes(&mut big).expect("a large fill");
        assert_ne!(
            &big[4032..],
            &[0u8; 64][..],
            "the end of a large fill is drawn too"
        );
    }

    #[test]
    fn the_wall_clock_is_after_2020() {
        let now = WindowsEpoch.try_since_epoch().expect("a date");
        assert!(now.secs > 1_577_836_800, "the host's date is after 2020");
        assert!(now.nanos < 1_000_000_000);
    }

    /// An address goes into Winsock's form and comes back as it was, on either family, with the
    /// scope of a link-local end and the length of the form it is; the flow label alone is left
    /// behind.
    #[test]
    fn an_address_round_trips_through_winsocks_form_on_either_family() {
        let scoped = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            7447,
            0,
            3,
        ));
        for at in [
            SocketAddr::from(([192, 168, 1, 50], 7447)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 7447)),
            scoped,
        ] {
            let raw = RawAddr::of(at);
            assert_eq!(raw.to_socket_addr(), Some(at));
            let (family, size) = match at {
                SocketAddr::V4(_) => (i32::from(ws::AF_INET), size_of::<ws::SOCKADDR_IN>()),
                SocketAddr::V6(_) => (i32::from(ws::AF_INET6), size_of::<ws::SOCKADDR_IN6>()),
            };
            assert_eq!(family_of(&at), family);
            assert_eq!(raw.size() as usize, size);
        }
        let labelled = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 7447, 0x1234, 0));
        assert_eq!(
            RawAddr::of(labelled).to_socket_addr(),
            Some(SocketAddr::from((Ipv6Addr::LOCALHOST, 7447)))
        );
        assert_eq!(
            RawAddr::empty().to_socket_addr(),
            None,
            "an unspecified family names no end"
        );
    }

    #[test]
    fn winsock_starts_once_and_a_second_start_is_no_change() {
        startup().expect("Winsock starts");
        startup().expect("a second start is the first one's");
        assert!(STARTED.load(Ordering::Acquire));
    }
}
