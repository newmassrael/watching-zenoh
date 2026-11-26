// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host profile's network seam: UDP over the kernel's own sockets, IPv4 and IPv6.
//!
//! [`PosixUdpSocket`] is the socket `wz_runtime_coop::udp_link` is written against
//! ([`DatagramSocket`]); the session's link over it is that module's `UdpDriver`, and
//! `slot::PosixStack` opens it, beside the stream socket of `stream`, as the stack the slot
//! profile's session host is given. Nothing here allocates: the socket is a file descriptor and
//! the address it is bound to.
//!
//! A socket's family is its address's: `socket(AF_INET6, ..)` for an IPv6 one, as zenoh-pico's
//! POSIX link opens the family its locator resolved to. `RawAddr` is the one conversion between
//! `core::net`'s address and the kernel's `sockaddr_in` / `sockaddr_in6`, both ways, which every
//! call that passes or reads an address here and in `stream` goes through. An IPv6 socket keeps
//! the kernel's own `IPV6_V6ONLY` default, as upstream zenoh's listeners do.
//!
//! Where Zephyr's socket cannot read `errno` (the FFI has no portable reach for it), this one can,
//! so a non-blocking receive is one `recvfrom` with `MSG_DONTWAIT` and "nothing yet" is the
//! `EAGAIN` it answers, not a `poll` that came first. The blocking receive the loop makes is
//! bounded by `SO_RCVTIMEO` ([`SERVICE_WAIT_MS`]), so a datagram that arrives wakes the loop in
//! the same system call that waited for it.

use core::ffi::{c_int, c_uint};
use core::mem::size_of;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use wz_runtime_coop::group_transport::GroupInterface;

/// The option that joins an IPv6 group: RFC 3493's `IPV6_JOIN_GROUP`, which Linux and Android
/// spell `IPV6_ADD_MEMBERSHIP` (the same number), and which zenoh-pico's POSIX link sets
/// (`vendor/zenoh-pico/src/link/transport/udp/udp_multicast_posix.c` @
/// `IPPROTO_IPV6, IPV6_JOIN_GROUP`).
#[cfg(any(target_os = "linux", target_os = "android"))]
const IPV6_JOIN: c_int = libc::IPV6_ADD_MEMBERSHIP;
/// See the Linux form of this constant.
#[cfg(any(target_os = "nto", target_os = "macos"))]
const IPV6_JOIN: c_int = libc::IPV6_JOIN_GROUP;

// The heap profile's readiness seam is compiled where the runtime declares it, whatever this crate's
// own features are (`wz_runtime_coop::with_heap_link_seams!`), as is every implementation of it here.
wz_runtime_coop::with_heap_link_seams! {
    use wz_runtime_coop::session_drive::{LinkWait, LinkWaits, WaitOn};
    #[cfg(feature = "alloc")]
    use wz_runtime_coop::session_drive::StackWake;
}
use wz_runtime_coop::locator_text::NamedHost;
use wz_runtime_coop::udp_link::{DatagramSocket, Received, SERVICE_WAIT_MS};

/// Why a socket call failed: the call, and the `errno` it left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosixNetError {
    /// `socket(AF_INET, ...)` or `socket(AF_INET6, ...)` failed with this `errno`
    /// (`EAFNOSUPPORT`: the kernel has no socket of the family).
    Socket(c_int),
    /// `setsockopt(SO_RCVTIMEO)` failed with this `errno`.
    ReceiveTimeout(c_int),
    /// `bind` failed with this `errno`.
    Bind(c_int),
    /// `fcntl(F_SETFL, O_NONBLOCK)` on a listening or a multicast socket failed with this `errno`.
    NonBlocking(c_int),
    /// `setsockopt(SO_REUSEADDR)` failed with this `errno`.
    ReuseAddr(c_int),
    /// `setsockopt(SO_REUSEPORT)` failed with this `errno`.
    ReusePort(c_int),
    /// `setsockopt(IP_ADD_MEMBERSHIP)` or `setsockopt(IPV6_JOIN_GROUP)` failed with this `errno`:
    /// the group could not be joined on the interface asked for.
    Membership(c_int),
    /// A multicast interface was named in the other family than the group's or the socket's (an
    /// IPv4 address for an IPv6 group, an index for an IPv4 one), so no kernel call was made.
    InterfaceFamily,
    /// `setsockopt` of a multicast egress option (`IP_MULTICAST_IF`, `IP_MULTICAST_TTL`,
    /// `IP_MULTICAST_LOOP`) or of the traffic class (`IP_TOS`, `IPV6_TCLASS`) failed with this
    /// `errno`.
    MulticastOption(c_int),
    /// `listen` failed with this `errno`.
    Listen(c_int),
    /// `getsockname` failed with this `errno` reading back the port a bind on port 0 was given.
    SockName(c_int),
    /// A bind on port 0 succeeded and the kernel reported port 0 all the same, so there is no
    /// port for the link's locator to name.
    NoPortChosen,
    /// `sendto` took this many bytes (negative: refused, with the `errno` in the second field) of
    /// a datagram.
    Send(isize, c_int),
    /// `poll` failed with this `errno`.
    Poll(c_int),
    /// `recvfrom` (or a stream's `recv`) failed with this `errno`.
    Recv(c_int),
    /// `connect` failed with this `errno`.
    Connect(c_int),
    /// `setsockopt(TCP_NODELAY)` failed with this `errno`.
    NoDelay(c_int),
    /// `getpeername` failed with this `errno`.
    PeerName(c_int),
    /// A stream's `sendmsg` failed with this `errno`.
    Write(c_int),
}

wz_runtime_coop::with_heap_link_seams! {
/// What a wait on a socket asks `poll` for: input, and room as well when `room`.
fn wait_events(room: bool) -> libc::c_short {
    if room {
        libc::POLLIN | libc::POLLOUT
    } else {
        libc::POLLIN
    }
}

/// The waits of this platform's sockets ([`LinkWaits`]): one `poll` over the descriptors the
/// links name, made by a thread other than the links' own with nothing of a session held. A
/// descriptor is named by its number and nothing holds it open: one a close freed and a new socket
/// took is polled as that socket, a hint as every answer is, and the step that follows looks again
/// under the session's lock.
#[derive(Debug, Clone, Copy, Default)]
pub struct PosixWaits;

/// The descriptor a wait names to the kernel: `None` for a handle of another stack's.
fn descriptor(on: WaitOn) -> Option<c_int> {
    match on {
        WaitOn::Socket(handle) | WaitOn::Wake(handle) => c_int::try_from(handle).ok(),
        WaitOn::AppLink(_) => None,
    }
}

// The entries of a wait set are marked one bit each of a word (`poll_on`'s wakes).
const _: () = assert!(crate::WAIT_SET_SOCKETS <= u64::BITS as usize);

/// The `poll` entries of one wait, on the waiting thread's stack. None is written before the wait
/// names it: a wait names one or two links far more often than the set's length, and writing the
/// set whole would copy every entry of it on every wait.
type WaitSet = [core::mem::MaybeUninit<libc::pollfd>; crate::WAIT_SET_SOCKETS];

/// A set of `poll` entries none of which is written yet.
const NO_FDS: WaitSet = [core::mem::MaybeUninit::uninit(); crate::WAIT_SET_SOCKETS];

/// One `poll` over what `on` names, in `fds`, for at most `timeout_ms`: the entries of `fds` it
/// wrote, in the order of `on`, and whether the poll answered. A wake the poll found ready is made
/// quiet; one it did not look at, or found quiet, is not read.
fn poll_on<'s>(
    on: &[LinkWait],
    timeout_ms: u32,
    fds: &'s mut WaitSet,
) -> (&'s [libc::pollfd], bool) {
    let mut count = 0;
    let mut look = false;
    // The entries of `fds` that are wakes, a bit each by their place, so a poll that found one
    // ready reads it without walking `on` again.
    let mut wakes = 0u64;
    for wait in on {
        match (descriptor(wait.on), fds.get_mut(count)) {
            (Some(fd), Some(entry)) => {
                entry.write(libc::pollfd {
                    fd,
                    events: wait_events(wait.room),
                    revents: 0,
                });
                // Below the set's length, at most the bits of the word (asserted above).
                if matches!(wait.on, WaitOn::Wake(_)) {
                    wakes |= 1u64 << count;
                }
                count += 1;
            }
            // A handle this cannot name to the kernel, or one past the set: the bounded look,
            // so it is not starved behind a wait on the others.
            _ => look = true,
        }
    }
    let timeout_ms = if look { timeout_ms.min(1) } else { timeout_ms };
    let timeout = c_int::try_from(timeout_ms).unwrap_or(c_int::MAX);
    // SAFETY: the loop above wrote the first `count` entries of `fds`, one place each in order,
    // and `count` never passes the set's length; `MaybeUninit<T>` is laid out as `T`.
    let polled: &'s mut [libc::pollfd] = unsafe {
        core::slice::from_raw_parts_mut(fds.as_mut_ptr().cast::<libc::pollfd>(), count)
    };
    // SAFETY: the entries are written and live for the call, and the timeout bounds the wait. A
    // failed or interrupted wait is a quiet link: the step that follows reads and reports the
    // error.
    let answered =
        unsafe { libc::poll(polled.as_mut_ptr(), count as libc::nfds_t, timeout) } >= 0;
    // A wake found ready is made quiet, so the next wait waits for the next word.
    if answered {
        let mut left = wakes;
        while left != 0 {
            let at = left.trailing_zeros() as usize;
            // The lowest bit, which the line above read, is cleared.
            left &= left - 1;
            if let Some(entry) = polled.get(at).filter(|entry| entry.revents != 0) {
                drain(entry.fd);
            }
        }
    }
    (polled, answered)
}

impl LinkWaits for PosixWaits {
    fn wait(&self, on: &[LinkWait], timeout_ms: u32) {
        if on.is_empty() {
            return;
        }
        let mut fds = NO_FDS;
        let _ = poll_on(on, timeout_ms, &mut fds);
    }

    /// The entries `poll` found with an event, any event (an error or a hang-up is one the step
    /// reads), and every entry it could not name to the kernel, whose wait was the bounded look.
    /// A poll that failed tells nothing, so every entry is answered.
    fn wait_ready(&self, on: &mut [LinkWait], timeout_ms: u32) -> usize {
        if on.is_empty() {
            return 0;
        }
        let mut fds = NO_FDS;
        let (polled, answered) = poll_on(on, timeout_ms, &mut fds);
        if !answered {
            return on.len();
        }
        // The entries are walked in the order `poll_on` wrote `polled` in, so the next entry it
        // named is the next of `polled`.
        let mut named = 0;
        crate::front_the_ready(on, |wait| match descriptor(wait.on) {
            Some(_) if named < polled.len() => {
                let ready = polled.get(named).is_some_and(|entry| entry.revents != 0);
                named += 1;
                ready
            }
            _ => true,
        })
    }

    fn wait_room(&self, on: WaitOn, timeout_us: u64) -> bool {
        match on {
            WaitOn::Socket(handle) => {
                c_int::try_from(handle).map_or(true, |fd| poll_writable(fd, timeout_us))
            }
            // Not a socket that takes bytes: the send that follows answers.
            WaitOn::AppLink(_) | WaitOn::Wake(_) => true,
        }
    }

    // An eventfd where the host has one, else a pipe: made once for a session, and closed when
    // the last waker of it goes.
    #[cfg(feature = "alloc")]
    fn wake(&self) -> Option<StackWake> {
        let wake = FdWake::open()?;
        let on = WaitOn::Wake(usize::try_from(wake.read).ok()?);
        Some(StackWake {
            on,
            waker: core::task::Waker::from(alloc::sync::Arc::new(wake)),
        })
    }
}

/// Read what `fd`, a wake's read end, holds until it holds nothing: the wake is quiet again.
fn drain(fd: c_int) {
    let mut buf = [0u8; 64];
    loop {
        // SAFETY: a live buffer of its length, on the caller's non-blocking descriptor.
        let read = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if read <= 0 {
            return;
        }
    }
}

/// A wake of [`PosixWaits`]: a descriptor a wait polls, ready once a waker writes to it.
#[cfg(feature = "alloc")]
struct FdWake {
    read: c_int,
    write: c_int,
}

#[cfg(feature = "alloc")]
impl FdWake {
    /// An eventfd (Linux, Android): one descriptor both read and written, which never blocks.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn open() -> Option<Self> {
        // SAFETY: value arguments; the call makes a descriptor or fails.
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        (fd >= 0).then_some(Self { read: fd, write: fd })
    }

    /// A pipe, both ends non-blocking and closed on exec, where the host has no eventfd.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn open() -> Option<Self> {
        let mut ends = [0 as c_int; 2];
        // SAFETY: a live array of two descriptors, which the call writes.
        if unsafe { libc::pipe(ends.as_mut_ptr()) } != 0 {
            return None;
        }
        let [read, write] = ends;
        let wake = Self { read, write };
        for fd in ends {
            if set_nonblocking(fd, true).is_err() || set_close_on_exec(fd).is_err() {
                return None;
            }
        }
        Some(wake)
    }
}

#[cfg(feature = "alloc")]
impl alloc::task::Wake for FdWake {
    fn wake(self: alloc::sync::Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &alloc::sync::Arc<Self>) {
        let one = 1u64.to_ne_bytes();
        // SAFETY: a live buffer of its length, on this wake's non-blocking descriptor. A wake
        // that finds the descriptor full is ready already, which is all a waker is for.
        unsafe { libc::write(self.write, one.as_ptr().cast(), one.len()) };
    }
}

#[cfg(feature = "alloc")]
impl Drop for FdWake {
    fn drop(&mut self) {
        // SAFETY: this wake's own descriptors, each closed exactly once.
        unsafe { libc::close(self.read) };
        if self.write != self.read {
            // SAFETY: as above, the write end of a pipe.
            unsafe { libc::close(self.write) };
        }
    }
}

/// What a wait on the socket `fd` names it by.
pub(crate) fn wait_on(fd: c_int) -> Option<WaitOn> {
    usize::try_from(fd).ok().map(WaitOn::Socket)
}
}

/// The calling thread's `errno`.
#[cfg(target_os = "linux")]
pub(crate) fn errno() -> c_int {
    // SAFETY: `__errno_location` returns the address of the calling thread's `errno`, valid for
    // the thread's life.
    unsafe { *libc::__errno_location() }
}

/// Wait up to `timeout_us` microseconds for the stream socket `fd` to take more bytes: `true` on
/// `POLLOUT`, or on an error or hang-up the write that follows reports; `false` when the time is
/// up first, or when the wait itself failed otherwise.
// Out of line: a stream's wait for room, its connect's look and the waits' room each ask, and a
// copy inlined in each was larger than the call.
#[inline(never)]
pub(crate) fn poll_writable(fd: c_int, timeout_us: u64) -> bool {
    let timeout_ms = c_int::try_from(timeout_us.div_ceil(1_000)).unwrap_or(c_int::MAX);
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    loop {
        // SAFETY: one live `pollfd`; the timeout bounds the wait.
        let ready = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ready < 0 && errno() == libc::EINTR {
            continue;
        }
        return ready > 0 && pfd.revents != 0;
    }
}

/// The calling thread's `errno`: bionic's `__errno()`, the same address by another name.
#[cfg(target_os = "android")]
pub(crate) fn errno() -> c_int {
    // SAFETY: `__errno` returns the address of the calling thread's `errno`, valid for the
    // thread's life.
    unsafe { *libc::__errno() }
}

/// The calling thread's `errno`.
#[cfg(target_os = "nto")]
pub(crate) fn errno() -> c_int {
    // SAFETY: `__get_errno_ptr` is what Neutrino's `errno` macro reads: the address of the calling
    // thread's `errno`, valid for the thread's life.
    unsafe { *libc::__get_errno_ptr() }
}

/// The calling thread's `errno`.
#[cfg(target_os = "macos")]
pub(crate) fn errno() -> c_int {
    // SAFETY: `__error` is what Darwin's `errno` macro reads: the address of the calling thread's
    // `errno`, valid for the thread's life.
    unsafe { *libc::__error() }
}

/// A socket of `family` and `kind` (`SOCK_DGRAM`, `SOCK_STREAM`) as every socket of this crate is
/// made: closed when the process starts another program, and on macOS one whose write to a stream
/// the peer has closed is the write's error and not a SIGPIPE. The descriptor, or the `errno` of
/// the refusal. Where the kernel takes `SOCK_CLOEXEC` with the kind it is one call; macOS has no
/// such flag, so its socket is made and then set, and closed again when a setting is refused.
pub(crate) fn open_socket(family: c_int, kind: c_int) -> Result<c_int, c_int> {
    #[cfg(not(target_os = "macos"))]
    {
        // SAFETY: plain system call with value arguments.
        let fd = unsafe { libc::socket(family, kind | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(errno());
        }
        Ok(fd)
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: plain system call with value arguments.
        let fd = unsafe { libc::socket(family, kind, 0) };
        if fd < 0 {
            return Err(errno());
        }
        match set_close_on_exec(fd).and_then(|()| set_no_sigpipe(fd)) {
            Ok(()) => Ok(fd),
            Err(refused) => {
                // SAFETY: `fd` is this call's own descriptor, closed exactly once.
                unsafe { libc::close(fd) };
                Err(refused)
            }
        }
    }
}

/// Make a write to `fd` after its peer closed the stream fail with `EPIPE` rather than raise
/// SIGPIPE (`SO_NOSIGPIPE`): Darwin's form of the `MSG_NOSIGNAL` the other hosts pass to each send,
/// which a library loaded into a C program, whose SIGPIPE ends the process, must not leave to it.
#[cfg(target_os = "macos")]
pub(crate) fn set_no_sigpipe(fd: c_int) -> Result<(), c_int> {
    set_flag(fd, libc::SOL_SOCKET, libc::SO_NOSIGPIPE)
}

/// Bound every blocking read of `fd` by `ms` milliseconds (`SO_RCVTIMEO`): the `errno` when the
/// kernel refuses.
fn set_receive_timeout_ms(fd: c_int, ms: c_int) -> Result<(), c_int> {
    let timeout = libc::timeval {
        tv_sec: (ms / 1000) as libc::time_t,
        tv_usec: ((ms % 1000) * 1000) as libc::suseconds_t,
    };
    // SAFETY: `timeout` is a live `timeval` and the length passed is its size.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

/// The most instructions an `OwnSourceFilter` holds: an IPv6 source's, read as four words.
#[cfg(all(feature = "host-multicast", target_os = "linux"))]
const OWN_FILTER_MOST: usize = 12;

/// A classic socket filter that drops a UDP datagram whose source address and port are `own`'s
/// and keeps every other (`PosixUdpSocket::drop_sent_by`): the source compared where the kernel
/// holds it, the packet's own bytes, as upstream's link compares it with its send socket's address
/// (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @ `if self.unicast_addr == addr {`). At a
/// UDP socket's filter the packet begins at its UDP header, whose first two bytes are the source
/// port, and the network header is read past `SKF_NET_OFF`: an IPv4 source at its byte 12, an
/// IPv6 source at its bytes 8 to 24.
#[cfg(all(feature = "host-multicast", target_os = "linux"))]
struct OwnSourceFilter {
    code: [libc::sock_filter; OWN_FILTER_MOST],
    len: u16,
}

#[cfg(all(feature = "host-multicast", target_os = "linux"))]
impl OwnSourceFilter {
    /// What a kept datagram keeps of itself: the whole of it.
    const KEEP: u32 = u32::MAX;

    /// The filter of `own`, or `None` where the source alone does not tell `own`'s datagrams
    /// (an IPv6 address with a scope, which a receive compares by the interface too, as
    /// `sent_by_own` does) or no datagram has it (the unspecified address, port zero).
    fn of(own: SocketAddr) -> Option<Self> {
        if own.ip().is_unspecified() || own.port() == 0 {
            return None;
        }
        // The source as the words a filter loads, each read in the network's order, how many of
        // them there are, and where in the network header they start.
        let (words, count, at): ([u32; 4], usize, u32) = match own {
            SocketAddr::V4(v4) => ([u32::from(*v4.ip()), 0, 0, 0], 1, 12),
            SocketAddr::V6(v6) if v6.scope_id() == 0 => {
                let bits = u128::from(*v6.ip());
                let words = [
                    (bits >> 96) as u32,
                    (bits >> 64) as u32,
                    (bits >> 32) as u32,
                    bits as u32,
                ];
                (words, 4, 8)
            }
            SocketAddr::V6(_) => return None,
        };
        let net = libc::SKF_NET_OFF as u32;
        let load_half = (libc::BPF_LD | libc::BPF_H | libc::BPF_ABS) as u16;
        let load_word = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
        let equal = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
        let ret = (libc::BPF_RET | libc::BPF_K) as u16;
        let op = |code: u16, jf: usize, k: u32| libc::sock_filter {
            code,
            jt: 0,
            jf: u8::try_from(jf).unwrap_or(u8::MAX),
            k,
        };
        // Each comparison that fails jumps to the last instruction, which keeps the datagram; the
        // one before it drops a datagram every comparison matched.
        let keep_at = 2 * count + 3;
        let mut code = [op(ret, 0, Self::KEEP); OWN_FILTER_MOST];
        let mut len = 0usize;
        let mut put = |instruction: libc::sock_filter| {
            if let Some(slot) = code.get_mut(len) {
                *slot = instruction;
            }
            len += 1;
        };
        put(op(load_half, 0, 0));
        put(op(equal, keep_at - 2, u32::from(own.port())));
        for (n, word) in words.iter().take(count).enumerate() {
            let offset = net.wrapping_add(at).wrapping_add(4 * n as u32);
            put(op(load_word, 0, offset));
            put(op(equal, keep_at - 4 - 2 * n, *word));
        }
        put(op(ret, 0, 0));
        put(op(ret, 0, Self::KEEP));
        Some(Self {
            code,
            len: u16::try_from(len).ok()?,
        })
    }

    /// The instructions written.
    #[cfg(test)]
    fn program(&self) -> &[libc::sock_filter] {
        self.code.get(..usize::from(self.len)).unwrap_or_default()
    }
}

/// Set the socket option `name` of `level` on `fd` to `value`: the `errno` when the kernel refuses.
pub(crate) fn set_option<T>(fd: c_int, level: c_int, name: c_int, value: &T) -> Result<(), c_int> {
    // SAFETY: `value` is a live `T` and the length passed is its size.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (value as *const T).cast(),
            size_of::<T>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

/// Switch the boolean socket option `name` of `level` on for `fd`. Out of line: every socket a
/// stack opens sets its flags here, one body for the call and the read of `errno`.
#[inline(never)]
pub(crate) fn set_flag(fd: c_int, level: c_int, name: c_int) -> Result<(), c_int> {
    set_option(fd, level, name, &(1 as c_int))
}

/// Make `fd` non-blocking or blocking (`fcntl(F_SETFL, O_NONBLOCK)`): the `errno` when the kernel
/// refuses. A socket is made this way and not by a flag of `socket` or `accept4`, which Neutrino
/// does not have: the one call is the same on both kernels, and a connection a non-blocking
/// listener hands over is made blocking here whether the kernel's accept passed the flag on (the
/// BSD one does) or not (Linux's). Out of line: a dial, its connection made and each port's socket
/// set it, and the two calls with their reads of `errno` are one copy.
#[inline(never)]
pub(crate) fn set_nonblocking(fd: c_int, on: bool) -> Result<(), c_int> {
    // SAFETY: plain system call with value arguments.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(errno());
    }
    let wanted = if on {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    // SAFETY: plain system call with value arguments.
    if wanted != flags && unsafe { libc::fcntl(fd, libc::F_SETFL, wanted) } < 0 {
        return Err(errno());
    }
    Ok(())
}

/// Close `fd` when the process starts another program (`FD_CLOEXEC`): the `errno` when the kernel
/// refuses.
pub(crate) fn set_close_on_exec(fd: c_int) -> Result<(), c_int> {
    // SAFETY: plain system call with value arguments.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(errno());
    }
    Ok(())
}

/// The first interface that is up, can multicast, is not a loopback and holds an address of
/// `group`'s family, named as a group of that family names one: by its IPv4 address, or by its
/// index for an IPv6 group. None when there is no such interface. It is the interface to give a
/// multicast join when routing has no answer for the group (a board with one subnet route and no
/// default route, where joining on "the interface routing picks" fails with `ENODEV`), as upstream
/// zenoh takes the first non-loopback multicast interface of the group's family
/// (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @
/// `get_unicast_addresses_of_multicast_interfaces()`). The C library's `getifaddrs` is what lists
/// them, on every OS this crate is built for; it takes a list from the C library's own heap and
/// gives it back before returning, and the program's own allocator, which it has none of, is not
/// asked.
pub fn multicast_interface(group: &SocketAddr) -> Option<GroupInterface> {
    let mut list: *mut libc::ifaddrs = core::ptr::null_mut();
    // SAFETY: `list` is a live pointer the call fills; it is freed below whenever the call succeeds.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return None;
    }
    let wanted = (libc::IFF_UP | libc::IFF_MULTICAST) as u32;
    let mut found = None;
    let mut at = list;
    while !at.is_null() {
        // SAFETY: `at` is an entry of the list `getifaddrs` returned, live until `freeifaddrs`.
        let entry = unsafe { &*at };
        let flags = entry.ifa_flags as u32;
        if flags & wanted == wanted
            && flags & (libc::IFF_LOOPBACK as u32) == 0
            && !entry.ifa_addr.is_null()
        {
            // SAFETY: a non-null `ifa_addr` points at a socket address whose family field is valid.
            let family = unsafe { (*entry.ifa_addr).sa_family } as c_int;
            if family == libc::AF_INET && group.is_ipv4() {
                // SAFETY: an `AF_INET` address is a `sockaddr_in`.
                let sin = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
                let address = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
                if !address.is_unspecified() {
                    found = Some(GroupInterface::V4(address));
                    break;
                }
            } else if family == libc::AF_INET6 && group.is_ipv6() && !entry.ifa_name.is_null() {
                // SAFETY: a non-null `ifa_name` is the interface's NUL-terminated name, live until
                // `freeifaddrs`.
                let index = unsafe { libc::if_nametoindex(entry.ifa_name) };
                if index != 0 {
                    found = Some(GroupInterface::Index(index));
                    break;
                }
            }
        }
        at = entry.ifa_next;
    }
    // SAFETY: `list` is the list `getifaddrs` returned, freed once.
    unsafe { libc::freeifaddrs(list) };
    found
}

/// Whether `address` is an IPv6 unicast link-local address (`fe80::/10`), which names an
/// interface only with its zone.
fn unicast_link_local(address: &Ipv6Addr) -> bool {
    let [first, second, ..] = address.octets();
    first == 0xfe && second & 0xc0 == 0x80
}

/// The index of the interface that holds `address`, an IPv6 address read back without its zone:
/// `None` when no interface holds it. Listed by `getifaddrs`, as [`multicast_interface`] lists
/// them.
fn zone_of(address: Ipv6Addr) -> Option<u32> {
    let mut list: *mut libc::ifaddrs = core::ptr::null_mut();
    // SAFETY: `list` is a live pointer the call fills; it is freed below whenever the call succeeds.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return None;
    }
    let mut found = None;
    let mut at = list;
    while !at.is_null() {
        // SAFETY: `at` is an entry of the list `getifaddrs` returned, live until `freeifaddrs`.
        let entry = unsafe { &*at };
        if !entry.ifa_addr.is_null() && !entry.ifa_name.is_null() {
            // SAFETY: a non-null `ifa_addr` points at a socket address whose family field is valid.
            let family = unsafe { (*entry.ifa_addr).sa_family } as c_int;
            if family == libc::AF_INET6 {
                // SAFETY: an `AF_INET6` address is a `sockaddr_in6`.
                let sin6 = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in6) };
                if Ipv6Addr::from(sin6.sin6_addr.s6_addr) == address {
                    // SAFETY: a non-null `ifa_name` is the interface's NUL-terminated name, live
                    // until `freeifaddrs`.
                    let index = unsafe { libc::if_nametoindex(entry.ifa_name) };
                    if index != 0 {
                        found = Some(index);
                        break;
                    }
                }
            }
        }
        at = entry.ifa_next;
    }
    // SAFETY: `list` is the list `getifaddrs` returned, freed once.
    unsafe { libc::freeifaddrs(list) };
    found
}

/// The kernel's family number of `at`: `AF_INET` or `AF_INET6`.
pub(crate) fn family_of(at: &SocketAddr) -> c_int {
    match at {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    }
}

/// A socket address as the kernel reads and writes it, of either family: a `sockaddr_storage`
/// holding a `sockaddr_in` or a `sockaddr_in6`, and the length of the one it holds. The one
/// conversion between it and [`SocketAddr`], both ways.
pub(crate) struct RawAddr {
    storage: libc::sockaddr_storage,
    len: libc::socklen_t,
}

impl RawAddr {
    /// `at` in the kernel's form, for a call that reads an address (`bind`, `connect`, `sendto`).
    ///
    /// Out of line, as [`socket_addr_at`] and [`name_of`] are: each opener and each send
    /// would otherwise carry its own copy of both families' conversion, where the one system call
    /// beside it costs far more than the call.
    #[inline(never)]
    pub(crate) fn of(at: SocketAddr) -> Self {
        // SAFETY: an all-zero `sockaddr_storage` is a valid value of it, an unspecified family.
        let mut storage: libc::sockaddr_storage = unsafe { core::mem::zeroed() };
        let len = match at {
            SocketAddr::V4(v4) => {
                let sin = libc::sockaddr_in {
                    // Neutrino's and macOS's socket address, as the BSDs', carries its own length.
                    #[cfg(any(target_os = "nto", target_os = "macos"))]
                    sin_len: size_of::<libc::sockaddr_in>() as u8,
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: v4.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.ip().octets()),
                    },
                    sin_zero: [0; 8],
                };
                // SAFETY: `sockaddr_storage` is large and aligned enough for every socket address
                // the kernel has, so a `sockaddr_in` written at its start is in bounds.
                unsafe {
                    core::ptr::write((&mut storage as *mut libc::sockaddr_storage).cast(), sin)
                };
                size_of::<libc::sockaddr_in>()
            }
            SocketAddr::V6(v6) => {
                // SAFETY: an all-zero `sockaddr_in6` is a valid value of it; the fields are set
                // below, and what is not set (the BSD length aside) is zero as the kernel wants.
                let mut sin6: libc::sockaddr_in6 = unsafe { core::mem::zeroed() };
                #[cfg(any(target_os = "nto", target_os = "macos"))]
                {
                    sin6.sin6_len = size_of::<libc::sockaddr_in6>() as u8;
                }
                sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sin6.sin6_port = v6.port().to_be();
                sin6.sin6_flowinfo = v6.flowinfo();
                sin6.sin6_addr.s6_addr = v6.ip().octets();
                sin6.sin6_scope_id = v6.scope_id();
                // SAFETY: as for the IPv4 form: the storage holds any socket address.
                unsafe {
                    core::ptr::write((&mut storage as *mut libc::sockaddr_storage).cast(), sin6)
                };
                size_of::<libc::sockaddr_in6>()
            }
        };
        Self {
            storage,
            len: len as libc::socklen_t,
        }
    }

    /// Room for any address, for a call that writes one (`recvfrom`, `getsockname`, `accept`).
    pub(crate) fn empty() -> Self {
        Self {
            // SAFETY: an all-zero `sockaddr_storage` is a valid value of it.
            storage: unsafe { core::mem::zeroed() },
            len: size_of::<libc::sockaddr_storage>() as libc::socklen_t,
        }
    }

    /// The address, for a call that reads it.
    pub(crate) fn as_ptr(&self) -> *const libc::sockaddr {
        (&self.storage as *const libc::sockaddr_storage).cast()
    }

    /// The address, for a call that writes it.
    pub(crate) fn as_mut_ptr(&mut self) -> *mut libc::sockaddr {
        (&mut self.storage as *mut libc::sockaddr_storage).cast()
    }

    /// The length a call reads.
    pub(crate) fn size(&self) -> libc::socklen_t {
        self.len
    }

    /// The length a call that writes the address reads as the room it has and sets to the length
    /// it wrote.
    pub(crate) fn size_mut(&mut self) -> &mut libc::socklen_t {
        &mut self.len
    }

    /// The address the kernel wrote, or `None` for a family other than the two (no socket here
    /// has one) ([`socket_addr_at`]).
    pub(crate) fn to_socket_addr(&self) -> Option<SocketAddr> {
        // SAFETY: the storage holds `len` bytes the kernel wrote, is larger than a `sockaddr`
        // and is aligned for every family's form.
        unsafe { socket_addr_at(self.as_ptr(), self.len) }
    }
}

/// The address `len` bytes at `addr` hold in the kernel's form, or `None` for a family other
/// than the two (no socket here has one) or a length short of its family's form. The flow label
/// is left out: it is a field of a packet and not of an end, and a link compares its peer by
/// address, port and scope. The one conversion from the kernel's form, for an address the kernel
/// wrote into a [`RawAddr`] and for one the resolver answered in its own list alike. Out of line,
/// as [`RawAddr::of`] is.
///
/// # Safety
///
/// `addr` points to at least a `sockaddr`'s bytes and to `len` readable bytes, aligned as the
/// form of the family it names, as the kernel and `getaddrinfo` write an address.
#[inline(never)]
pub(crate) unsafe fn socket_addr_at(
    addr: *const libc::sockaddr,
    len: libc::socklen_t,
) -> Option<SocketAddr> {
    // SAFETY: `addr` points to a `sockaddr`'s bytes, as the caller states.
    match c_int::from(unsafe { (*addr).sa_family }) {
        libc::AF_INET if len as usize >= size_of::<libc::sockaddr_in>() => {
            // SAFETY: an `AF_INET` address is a `sockaddr_in`, whose bytes the length holds and
            // for which the caller states the address is aligned.
            let sin = unsafe { &*addr.cast::<libc::sockaddr_in>() };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(sin.sin_port),
            )))
        }
        libc::AF_INET6 if len as usize >= size_of::<libc::sockaddr_in6>() => {
            // SAFETY: as for the IPv4 form, an `AF_INET6` address being a `sockaddr_in6`.
            let sin6 = unsafe { &*addr.cast::<libc::sockaddr_in6>() };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                u16::from_be(sin6.sin6_port),
                0,
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// The addresses the host's resolver (`getaddrinfo`) answers for the host `name`, each at its
/// port, written to the front of `found` in its order: how many, `0` when it answers none or
/// fails. Asked as zenoh-pico asks it for a locator's host, of every family the host has and of
/// the stream kind alone (`vendor/zenoh-pico/src/link/transport/tcp/tcp_posix.c` @
/// `hints.ai_family = PF_UNSPEC`), so that each address of a record is answered once and not
/// once for each kind; the answer is walked as that open walks it, in its order, each address
/// read in place.
pub(crate) fn resolve(name: &NamedHost<'_>, found: &mut [SocketAddr]) -> usize {
    let text = crate::resolve::terminated(name);
    // SAFETY: an all-zero `addrinfo` is a valid value of it: no flags, no family, null pointers.
    let mut hints: libc::addrinfo = unsafe { core::mem::zeroed() };
    hints.ai_family = libc::AF_UNSPEC;
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut answers: *mut libc::addrinfo = core::ptr::null_mut();
    // SAFETY: `text` ends in a 0 byte, `hints` is live for the call, and the call writes
    // `answers`, which is freed below once read.
    let failed = unsafe {
        libc::getaddrinfo(
            text.as_ptr().cast(),
            core::ptr::null(),
            &hints,
            &mut answers,
        )
    } != 0;
    if failed {
        return 0;
    }
    // SAFETY: the list the call made, live until it is freed below.
    let count = unsafe { read_answers(answers, name.port(), found) };
    // SAFETY: `answers` is the list the call made, freed once, and nothing read of it is held.
    unsafe { libc::freeaddrinfo(answers) };
    count
}

/// The addresses of the resolver's answers from `first` on, each at `port`, written to the front
/// of `found` in their order, past each answer with no address or of a family other than the two:
/// how many. The resolver was asked for no service, so an answer names no port, and the one the
/// name is dialled at is written in.
///
/// # Safety
///
/// `first` is null or the first of a list of answers linked by `ai_next`, each with a null
/// `ai_addr` or one of `ai_addrlen` bytes in its family's form and aligned for it, all live for
/// the call, as `getaddrinfo` makes them.
unsafe fn read_answers(first: *const libc::addrinfo, port: u16, found: &mut [SocketAddr]) -> usize {
    let mut count: usize = 0;
    let mut next = first;
    // SAFETY: `next` is null or an answer of the list, live for the call.
    while let (Some(answer), Some(place)) = (unsafe { next.as_ref() }, found.get_mut(count)) {
        next = answer.ai_next.cast_const();
        if answer.ai_addr.is_null() {
            continue;
        }
        // SAFETY: a non-null `ai_addr` is the resolver's address of `ai_addrlen` bytes, in the
        // form of its family and aligned for it.
        if let Some(mut at) = unsafe { socket_addr_at(answer.ai_addr, answer.ai_addrlen) } {
            at.set_port(port);
            *place = at;
            // `count` names a place of `found`, so the sum does not wrap.
            count = count.wrapping_add(1);
        }
    }
    count
}

/// Bind or connect `fd` to `at`: `call` is `libc::bind` or `libc::connect`, handed `at` in the
/// kernel's form. The `errno` when the call fails. The one way a socket here is given an address,
/// so each opener calls it and carries no conversion of its own.
#[inline(never)]
pub(crate) fn call_at(
    fd: c_int,
    at: SocketAddr,
    call: unsafe extern "C" fn(c_int, *const libc::sockaddr, libc::socklen_t) -> c_int,
) -> Result<(), c_int> {
    let raw = RawAddr::of(at);
    // SAFETY: `raw` is a live socket address of the length passed, which `call` only reads.
    if unsafe { call(fd, raw.as_ptr(), raw.size()) } == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

/// The address a `getsockname` or `getpeername` of `fd` reports: the `errno` when the call fails,
/// `EAFNOSUPPORT` when it names a family other than the two.
#[inline(never)]
pub(crate) fn name_of(
    fd: c_int,
    call: unsafe extern "C" fn(c_int, *mut libc::sockaddr, *mut libc::socklen_t) -> c_int,
) -> Result<SocketAddr, c_int> {
    let mut name = RawAddr::empty();
    // SAFETY: `name`'s storage and length are live and writable, and the length is its size.
    let rc = unsafe { call(fd, name.as_mut_ptr(), name.size_mut()) };
    if rc != 0 {
        return Err(errno());
    }
    name.to_socket_addr().ok_or(libc::EAFNOSUPPORT)
}

/// One UDP socket on the host, of the family of the address it is bound to, with every blocking
/// read of it bounded by [`SERVICE_WAIT_MS`].
pub struct PosixUdpSocket {
    fd: c_int,
    local: SocketAddr,
}

impl PosixUdpSocket {
    /// A socket bound to `at`; `shared` sets `SO_REUSEADDR` and `SO_REUSEPORT` first, which is
    /// what lets a group's receiver bind the port another member on this host already holds.
    fn open(at: SocketAddr, shared: bool) -> Result<Self, PosixNetError> {
        let fd = open_socket(family_of(&at), libc::SOCK_DGRAM).map_err(PosixNetError::Socket)?;
        // Owned from here, so an early return closes it.
        let mut this = Self { fd, local: at };
        if let Err(e) = set_receive_timeout_ms(fd, SERVICE_WAIT_MS) {
            return Err(PosixNetError::ReceiveTimeout(e));
        }
        if shared {
            set_flag(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR).map_err(PosixNetError::ReuseAddr)?;
            set_flag(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT).map_err(PosixNetError::ReusePort)?;
        }
        call_at(fd, at, libc::bind).map_err(PosixNetError::Bind)?;
        if at.port() == 0 {
            // The locators the link reports and the source every reply comes from name this
            // port; keeping the 0 that was asked for would render `udp/<ip>:0` for a link that
            // has a real one.
            this.local.set_port(this.chosen_port()?);
        }
        Ok(this)
    }

    /// The descriptor, for a test that reads an option back.
    #[cfg(test)]
    pub(crate) fn fd(&self) -> c_int {
        self.fd
    }

    /// A socket bound to `at` that other sockets of this host may bind too, as every member of a
    /// multicast group does (zenoh-pico sets both options on its group listener
    /// unconditionally).
    pub fn bind_shared(at: SocketAddr) -> Result<Self, PosixNetError> {
        Self::open(at, true)
    }

    /// The address a datagram this socket sends to `to` leaves from, learned by connecting the
    /// socket to `to`: the kernel picks the source then, as it would for each send, under the
    /// socket's multicast interface.
    pub fn source_toward(&self, to: SocketAddr) -> Result<SocketAddr, PosixNetError> {
        call_at(self.fd, to, libc::connect).map_err(PosixNetError::Connect)?;
        let mut source = name_of(self.fd, libc::getsockname).map_err(PosixNetError::SockName)?;
        // A socket bound to no interface reads its link-local source back with no zone (scope 0),
        // which a bind of that source refuses (EINVAL): the zone is the interface that holds it.
        if let SocketAddr::V6(v6) = &mut source {
            if v6.scope_id() == 0 && unicast_link_local(v6.ip()) {
                let zone = zone_of(*v6.ip()).ok_or(PosixNetError::SockName(libc::EADDRNOTAVAIL))?;
                v6.set_scope_id(zone);
            }
        }
        Ok(source)
    }

    /// Join `group` on `interface`: an IPv4 group through `IP_ADD_MEMBERSHIP` on the interface
    /// that holds an address, an IPv6 one through `IPV6_JOIN_GROUP` (MLD) on the interface of an
    /// index, either on the one the kernel's routing picks for [`GroupInterface::Routing`]. An
    /// interface named in the other family than the group's is
    /// [`PosixNetError::InterfaceFamily`], before the kernel is asked.
    pub fn join_group(
        &self,
        group: IpAddr,
        interface: GroupInterface,
    ) -> Result<(), PosixNetError> {
        match (group, interface) {
            (IpAddr::V4(group), GroupInterface::Routing | GroupInterface::V4(_)) => {
                let interface = match interface {
                    GroupInterface::V4(address) => address,
                    _ => Ipv4Addr::UNSPECIFIED,
                };
                // `ip_mreq`, which every kernel here takes and Neutrino has no wider form of: the
                // group and the address of the interface (the kernel's choice when it is the
                // unspecified one). Linux's `ip_mreqn` is this plus an interface index this code
                // never sets.
                let request = libc::ip_mreq {
                    imr_multiaddr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(group.octets()),
                    },
                    imr_interface: libc::in_addr {
                        s_addr: u32::from_ne_bytes(interface.octets()),
                    },
                };
                set_option(self.fd, libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP, &request)
                    .map_err(PosixNetError::Membership)
            }
            (IpAddr::V6(group), GroupInterface::Routing | GroupInterface::Index(_)) => {
                let index = match interface {
                    GroupInterface::Index(index) => index,
                    _ => 0,
                };
                // SAFETY: an all-zero `ipv6_mreq` is a valid value of it; both fields are set below.
                let mut request: libc::ipv6_mreq = unsafe { core::mem::zeroed() };
                request.ipv6mr_multiaddr.s6_addr = group.octets();
                // `c_uint` on Linux, Neutrino and macOS, `c_int` on Android: an index fits either.
                request.ipv6mr_interface = index as _;
                set_option(self.fd, libc::IPPROTO_IPV6, IPV6_JOIN, &request)
                    .map_err(PosixNetError::Membership)
            }
            _ => Err(PosixNetError::InterfaceFamily),
        }
    }

    /// Send multicast datagrams out of `interface`: the interface that holds an IPv4 address
    /// (`IP_MULTICAST_IF`), the interface of an index (`IPV6_MULTICAST_IF`), or, for the routing's
    /// choice, the one the kernel picks, which needs no option.
    pub fn set_multicast_interface(&self, interface: GroupInterface) -> Result<(), PosixNetError> {
        match (self.local, interface) {
            (_, GroupInterface::Routing) => Ok(()),
            (SocketAddr::V4(_), GroupInterface::V4(address)) => {
                let address = libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.octets()),
                };
                set_option(self.fd, libc::IPPROTO_IP, libc::IP_MULTICAST_IF, &address)
                    .map_err(PosixNetError::MulticastOption)
            }
            (SocketAddr::V6(_), GroupInterface::Index(index)) => set_option(
                self.fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_MULTICAST_IF,
                &(index as c_uint),
            )
            .map_err(PosixNetError::MulticastOption),
            _ => Err(PosixNetError::InterfaceFamily),
        }
    }

    /// The hop limit of the multicast datagrams this socket sends, in the option of its family:
    /// `IP_MULTICAST_TTL` or `IPV6_MULTICAST_HOPS` (the kernel's default is 1: one subnet).
    pub fn set_multicast_hops(&self, hops: u8) -> Result<(), PosixNetError> {
        let (level, name) = match self.local {
            SocketAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_MULTICAST_TTL),
            SocketAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS),
        };
        set_option(self.fd, level, name, &c_int::from(hops)).map_err(PosixNetError::MulticastOption)
    }

    /// Make every call of this socket return at once: a send that finds no room fails with
    /// `EAGAIN` rather than wait for it.
    #[cfg(feature = "host-multicast")]
    pub(crate) fn make_nonblocking(&self) -> Result<(), PosixNetError> {
        set_nonblocking(self.fd, true).map_err(PosixNetError::NonBlocking)
    }

    /// Make a receive that passes no flag wait again, up to the socket's receive timeout: `true`
    /// when the kernel took it.
    #[cfg(all(feature = "host-multicast", unix))]
    pub(crate) fn make_receive_wait(&self) -> bool {
        set_nonblocking(self.fd, false).is_ok()
    }

    /// Whether this host's other members of a group observe what this socket sends:
    /// `IP_MULTICAST_LOOP` or `IPV6_MULTICAST_LOOP`, as the socket's family names it.
    #[cfg(feature = "host-multicast")]
    pub(crate) fn set_multicast_loopback(&self, on: bool) -> Result<(), PosixNetError> {
        let (level, name) = match self.local {
            SocketAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP),
            SocketAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_LOOP),
        };
        set_option(self.fd, level, name, &c_int::from(on)).map_err(PosixNetError::MulticastOption)
    }

    /// Have the kernel drop every datagram `own` sent before it is queued on this socket, with a
    /// socket filter (`SO_ATTACH_FILTER`, `OwnSourceFilter`) that reads the source's address and
    /// port in the packet: `true` when the kernel took it. A group's own datagrams, which come back
    /// on its joined socket while the loopback is on, then never wake its receive, where a receive
    /// that drops them pays a system call, the source's conversion and a reading of the clock for
    /// each. An `own` the filter cannot tell (one with an IPv6 scope, or the unspecified address)
    /// is left to the receive, and nothing is set.
    #[cfg(all(feature = "host-multicast", target_os = "linux"))]
    pub(crate) fn drop_sent_by(&self, own: SocketAddr) -> bool {
        let Some(mut filter) = OwnSourceFilter::of(own) else {
            return false;
        };
        let program = libc::sock_fprog {
            len: filter.len,
            filter: filter.code.as_mut_ptr(),
        };
        // The kernel copies the program in the call, so it need not outlive it.
        set_option(self.fd, libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &program).is_ok()
    }

    /// Mark what this socket sends with the traffic class `class`, as written: `IP_TOS` on an
    /// IPv4 socket, `IPV6_TCLASS` on an IPv6 one. `Ok(false)` where the kernel's IPv6 socket is
    /// not marked here (Neutrino), and nothing is set.
    #[cfg(feature = "host-multicast")]
    pub(crate) fn set_traffic_class(&self, class: u32) -> Result<bool, PosixNetError> {
        let (level, name) = match self.local {
            SocketAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_TOS),
            #[cfg(not(target_os = "nto"))]
            SocketAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_TCLASS),
            #[cfg(target_os = "nto")]
            SocketAddr::V6(_) => return Ok(false),
        };
        set_option(self.fd, level, name, &(class as c_int))
            .map(|()| true)
            .map_err(PosixNetError::MulticastOption)
    }

    /// Wait up to `timeout_us` microseconds for this socket to take another datagram.
    #[cfg(feature = "host-multicast")]
    pub(crate) fn wait_writable(&self, timeout_us: u64) -> bool {
        poll_writable(self.fd, timeout_us)
    }

    /// Wait up to `timeout_ms` milliseconds for any of `sockets` to have a datagram: one `poll`
    /// over their descriptors, which with none passes the time.
    #[cfg(feature = "host-multicast")]
    pub(crate) fn wait_readable_any(sockets: &[&Self], timeout_ms: c_int) {
        let mut fds: alloc::vec::Vec<libc::pollfd> = sockets
            .iter()
            .map(|socket| libc::pollfd {
                fd: socket.fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        // SAFETY: `fds` is live for the call and its length is the count passed; every descriptor
        // is one of a socket the caller holds for the call, and the timeout bounds the wait. A
        // failed or interrupted wait returns early, and the read that follows reports the error.
        unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
    }

    /// The port the kernel bound this socket to.
    fn chosen_port(&self) -> Result<u16, PosixNetError> {
        match name_of(self.fd, libc::getsockname)
            .map_err(PosixNetError::SockName)?
            .port()
        {
            0 => Err(PosixNetError::NoPortChosen),
            port => Ok(port),
        }
    }

    /// One `recvfrom` with `flags`, into `buf`: the length and source, `Ok(None)` when the call
    /// answered "nothing yet" (`EAGAIN`, which is what a receive timeout and `MSG_DONTWAIT` both
    /// leave) or was interrupted by a signal, any other failure as an error. A datagram whose
    /// source the kernel names in a family other than the socket's two is an error too: there
    /// is no end to judge it by.
    // Out of line: both receives call it, and a copy inlined in each is larger than the call.
    #[inline(never)]
    fn receive(&self, buf: &mut [u8], flags: c_int) -> Result<Option<Received>, PosixNetError> {
        let mut src = RawAddr::empty();
        // SAFETY: `buf` and `src` are live and writable for the lengths given.
        let got = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                flags,
                src.as_mut_ptr(),
                src.size_mut(),
            )
        };
        if got < 0 {
            return match errno() {
                libc::EAGAIN | libc::EINTR => Ok(None),
                other => Err(PosixNetError::Recv(other)),
            };
        }
        let from = src
            .to_socket_addr()
            .ok_or(PosixNetError::Recv(libc::EAFNOSUPPORT))?;
        Ok(Some((got as usize, from)))
    }
}

impl DatagramSocket for PosixUdpSocket {
    type Error = PosixNetError;

    const RESOLVES: bool = true;

    fn resolve(name: &NamedHost<'_>, found: &mut [SocketAddr]) -> usize {
        resolve(name, found)
    }

    fn bind(at: SocketAddr) -> Result<Self, PosixNetError> {
        Self::open(at, false)
    }

    fn local(&self) -> SocketAddr {
        self.local
    }

    fn send_to(&self, to: SocketAddr, bytes: &[u8]) -> Result<(), PosixNetError> {
        let dest = RawAddr::of(to);
        // SAFETY: `bytes` and `dest` are live for the call, lengths match.
        let sent = unsafe {
            libc::sendto(
                self.fd,
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
                dest.as_ptr(),
                dest.size(),
            )
        };
        if sent == bytes.len() as isize {
            Ok(())
        } else {
            Err(PosixNetError::Send(sent, errno()))
        }
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live `pollfd`; the timeout bounds the wait. A failed or interrupted wait is
        // a quiet socket here: the receive that follows reads and reports the error.
        unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    }

    fn times_out(&self) -> bool {
        // `bind` does not return a socket without its receive timeout.
        true
    }

    const CAN_SET_RECEIVE_TIMEOUT: bool = true;

    fn set_receive_timeout(&self, ms: c_int) -> bool {
        set_receive_timeout_ms(self.fd, ms).is_ok()
    }

    fn recv_waiting(&self, buf: &mut [u8]) -> Result<Option<Received>, PosixNetError> {
        self.receive(buf, 0)
    }

    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<Received>, PosixNetError> {
        self.receive(buf, libc::MSG_DONTWAIT)
    }

    fn refuses_address(error: &PosixNetError) -> bool {
        *error == PosixNetError::Socket(libc::EAFNOSUPPORT)
    }

    fn address_in_use(error: &PosixNetError) -> bool {
        *error == PosixNetError::Bind(libc::EADDRINUSE)
    }

    wz_runtime_coop::with_heap_link_seams! {
        type Waits = PosixWaits;

        fn input_wait(&self) -> Option<WaitOn> {
            wait_on(self.fd)
        }

    }
}

wz_runtime_coop::with_heap_link_seams! {
    #[cfg(feature = "host-multicast")]
    impl PosixUdpSocket {
        /// What a wait for room on this socket names it by.
        pub(crate) fn room_wait(&self) -> Option<WaitOn> {
            wait_on(self.fd)
        }
    }
}

impl Drop for PosixUdpSocket {
    fn drop(&mut self) {
        // SAFETY: `fd` is this socket's own descriptor, closed exactly once.
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The host's resolver answers `localhost` with its loopback addresses, each at the port the
    /// name is dialled at, and the answer is cut at the room it is given; an answer given no room
    /// is none. Turned red by an address answered at the wrong port or past the room, or by a
    /// resolver not asked.
    #[test]
    fn the_host_resolver_answers_a_name_with_its_addresses() {
        let name = crate::resolve::named("tcp/localhost:7447");
        let unset = SocketAddr::from(([0, 0, 0, 0], 0));
        let mut found = [unset; 4];
        let count = resolve(&name, &mut found);
        assert!(count >= 1, "localhost resolves");
        let answered = found.get(..count).expect("the count is within the room");
        for at in answered {
            assert!(at.ip().is_loopback(), "{at}");
            assert_eq!(at.port(), 7447, "{at}");
        }
        let mut one = [unset; 1];
        assert_eq!(resolve(&name, &mut one), 1);
        assert_eq!(one.first().map(SocketAddr::port), Some(7447));
        assert_eq!(resolve(&name, &mut []), 0);
    }

    /// A walk of the resolver's answers passes over an answer without an address and one of a
    /// family other than the two, and writes the address after them at the port it is asked for;
    /// it stops at the room it is given. Turned red by a walk that stops at the first answer it
    /// cannot read, keeps the answer's own port, or writes past its room.
    #[test]
    fn a_walk_passes_over_an_answer_it_cannot_read() {
        let v4 = RawAddr::of(SocketAddr::from(([192, 168, 1, 50], 9)));
        // SAFETY: an all-zero `sockaddr_storage` is a valid value of it, an unspecified family.
        let unspecified: libc::sockaddr_storage = unsafe { core::mem::zeroed() };
        // SAFETY: an all-zero `addrinfo` is a valid value of it: null pointers.
        let mut answers: [libc::addrinfo; 3] = unsafe { core::mem::zeroed() };
        let [no_address, other_family, address] = &mut answers;
        other_family.ai_addr = (&unspecified as *const libc::sockaddr_storage)
            .cast::<libc::sockaddr>()
            .cast_mut();
        other_family.ai_addrlen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        address.ai_addr = v4.as_ptr().cast_mut();
        address.ai_addrlen = v4.size();
        other_family.ai_next = address;
        no_address.ai_next = other_family;
        let first: *const libc::addrinfo = &*no_address;
        let unset = SocketAddr::from(([0, 0, 0, 0], 0));
        let mut found = [unset; 2];
        // SAFETY: the answers and the addresses they name outlive the walk.
        let count = unsafe { read_answers(first, 7447, &mut found) };
        assert_eq!(count, 1);
        assert_eq!(found, [SocketAddr::from(([192, 168, 1, 50], 7447)), unset]);
        // SAFETY: as above.
        assert_eq!(unsafe { read_answers(first, 7447, &mut []) }, 0, "no room");
    }

    /// Only `fe80::/10` is a unicast link-local address, the one a source needs its zone for;
    /// a site-local multicast group, the loopback and a global address are not. Turned red by a
    /// test of the first byte alone, which takes `fec0::` too.
    #[test]
    fn a_link_local_source_is_told_by_its_first_ten_bits() {
        assert!(unicast_link_local(&Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(unicast_link_local(&Ipv6Addr::new(
            0xfebf, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(!unicast_link_local(&Ipv6Addr::new(
            0xfec0, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(!unicast_link_local(&Ipv6Addr::new(
            0xff05, 0, 0, 0, 0, 0, 0x7a, 0x7703
        )));
        assert!(!unicast_link_local(&Ipv6Addr::LOCALHOST));
        assert!(!unicast_link_local(&Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        )));
    }

    /// The IPv4 loopback, on a port the kernel picks.
    const LOOPBACK: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

    /// The IPv6 loopback, on a port the kernel picks.
    const LOOPBACK_V6: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);

    fn pair() -> (PosixUdpSocket, PosixUdpSocket) {
        (
            PosixUdpSocket::bind(LOOPBACK).expect("a first socket"),
            PosixUdpSocket::bind(LOOPBACK).expect("a second socket"),
        )
    }

    /// An address goes into the kernel's form and comes back as it was, on either family, with
    /// the scope of a link-local end and the length of the form it is; the flow label alone is
    /// left behind.
    #[test]
    fn an_address_round_trips_through_the_kernels_form_on_either_family() {
        let scoped = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            7446,
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
                SocketAddr::V4(_) => (libc::AF_INET, size_of::<libc::sockaddr_in>()),
                SocketAddr::V6(_) => (libc::AF_INET6, size_of::<libc::sockaddr_in6>()),
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
        let raw = RawAddr::of(SocketAddr::from(([192, 168, 1, 50], 7447)));
        // SAFETY: the storage holds an address and is larger than any length asked of it here.
        let short = unsafe { socket_addr_at(raw.as_ptr(), raw.size() - 1) };
        assert_eq!(
            short, None,
            "a length short of its family's form names no end"
        );
    }

    /// A datagram between two IPv6 sockets is taken with its source, and the source is the
    /// sender's own end, as a link compares it. Needs the host's IPv6 loopback.
    #[test]
    fn an_ipv6_datagram_is_taken_with_its_source() {
        let a = PosixUdpSocket::bind(LOOPBACK_V6).expect("an IPv6 socket");
        let b = PosixUdpSocket::bind(LOOPBACK_V6).expect("a second IPv6 socket");
        assert_eq!(b.local().ip(), LOOPBACK_V6.ip());
        assert_ne!(b.local().port(), 0, "the locator must name a real port");
        a.send_to(b.local(), b"ping6").expect("a send");
        let mut buf = [0u8; 16];
        let (len, src) = b
            .recv_waiting(&mut buf)
            .expect("no error")
            .expect("a datagram within the receive timeout");
        assert_eq!(&buf[..len], b"ping6");
        assert_eq!(src, a.local(), "the source is the sender's end");
    }

    /// Only a socket the kernel has no family for is the family's refusal: a dial that meets it
    /// is not retried, any other failure is.
    #[test]
    fn only_a_missing_family_is_refused_for_its_family() {
        assert!(PosixUdpSocket::refuses_address(&PosixNetError::Socket(
            libc::EAFNOSUPPORT
        )));
        assert!(!PosixUdpSocket::refuses_address(&PosixNetError::Socket(
            libc::EMFILE
        )));
        assert!(!PosixUdpSocket::refuses_address(&PosixNetError::Bind(
            libc::EAFNOSUPPORT
        )));
    }

    /// A bind of a port another socket holds is refused as that, kept apart from a stack with no
    /// socket to give and from a family the kernel lacks. CONTROL: a descriptor the process has no
    /// more of is `Exhausted`. Turned red by a refusal that names every failed bind one way.
    #[test]
    fn a_port_another_socket_holds_is_refused_as_in_use() {
        use wz_runtime_coop::session_drive::LinkOpenError;
        use wz_runtime_coop::udp_link::bind_refused;

        let first = PosixUdpSocket::bind(LOOPBACK).expect("a socket");
        let taken = PosixUdpSocket::bind(first.local())
            .err()
            .expect("the port is held");
        assert_eq!(
            bind_refused::<PosixUdpSocket>(taken),
            LinkOpenError::AddressInUse
        );
        assert_eq!(
            bind_refused::<PosixUdpSocket>(PosixNetError::Socket(libc::EMFILE)),
            LinkOpenError::Exhausted,
            "CONTROL: no descriptor left"
        );
        assert_eq!(
            bind_refused::<PosixUdpSocket>(PosixNetError::Socket(libc::EAFNOSUPPORT)),
            LinkOpenError::Unsupported
        );
    }

    #[test]
    fn a_descriptor_is_made_non_blocking_and_blocking_again_and_each_is_read_back() {
        let socket = PosixUdpSocket::bind(LOOPBACK).expect("a socket");
        let flags = |fd| unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert_eq!(
            flags(socket.fd()) & libc::O_NONBLOCK,
            0,
            "a fresh socket blocks"
        );
        set_nonblocking(socket.fd(), true).expect("non-blocking");
        assert_ne!(flags(socket.fd()) & libc::O_NONBLOCK, 0);
        set_nonblocking(socket.fd(), true).expect("a second time is no change");
        set_nonblocking(socket.fd(), false).expect("blocking");
        assert_eq!(flags(socket.fd()) & libc::O_NONBLOCK, 0);
        assert_eq!(
            set_nonblocking(-1, true),
            Err(libc::EBADF),
            "a descriptor that is not one is the kernel's refusal, with its errno"
        );
    }

    #[test]
    fn the_interface_for_a_group_is_never_a_loopback_or_the_unspecified_address() {
        // A host in a sandbox may have none; a host that has one names a real, routable address
        // for an IPv4 group, and an index (never 0, which names no interface) for an IPv6 one.
        let v4 = SocketAddr::from(([224, 0, 0, 224], 7446));
        match multicast_interface(&v4) {
            Some(GroupInterface::V4(address)) => {
                assert!(
                    !address.is_unspecified(),
                    "the unspecified address is no interface"
                );
                assert!(
                    !address.is_loopback(),
                    "a loopback is not where a group is joined"
                );
            }
            None => {}
            Some(other) => panic!("an IPv4 group is given {other:?}"),
        }
        let v6 = SocketAddr::from((Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 7446));
        match multicast_interface(&v6) {
            Some(GroupInterface::Index(index)) => assert_ne!(index, 0),
            None => {}
            Some(other) => panic!("an IPv6 group is given {other:?}"),
        }
    }

    /// An interface named in the other family than the group's is refused before the kernel is
    /// asked, on the join and on the sender's interface alike; the routing's choice of the sender's
    /// interface asks the kernel nothing.
    #[test]
    fn an_interface_of_the_other_family_is_refused_before_the_kernel_is_asked() {
        let socket = PosixUdpSocket::bind(LOOPBACK).expect("an IPv4 socket");
        let v6_group = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(
            socket.join_group(v6_group, GroupInterface::V4(Ipv4Addr::LOCALHOST)),
            Err(PosixNetError::InterfaceFamily)
        );
        assert_eq!(
            socket.join_group(IpAddr::from([224, 0, 0, 224]), GroupInterface::Index(1)),
            Err(PosixNetError::InterfaceFamily)
        );
        assert_eq!(
            socket.set_multicast_interface(GroupInterface::Index(1)),
            Err(PosixNetError::InterfaceFamily)
        );
        assert_eq!(
            socket.set_multicast_interface(GroupInterface::Routing),
            Ok(())
        );
    }

    /// The hop limit is set in the option of the socket's family, and read back from it.
    #[test]
    fn the_hop_limit_is_the_option_of_the_sockets_family() {
        let get = |fd: c_int, level: c_int, name: c_int| -> c_int {
            let mut value: c_int = -1;
            let mut len = size_of::<c_int>() as libc::socklen_t;
            // SAFETY: `value` and `len` are live and writable, and `len` is `value`'s size.
            let rc = unsafe {
                libc::getsockopt(fd, level, name, (&mut value as *mut c_int).cast(), &mut len)
            };
            assert_eq!(rc, 0);
            value
        };
        let v4 = PosixUdpSocket::bind(LOOPBACK).expect("an IPv4 socket");
        v4.set_multicast_hops(4).expect("a hop limit");
        assert_eq!(get(v4.fd(), libc::IPPROTO_IP, libc::IP_MULTICAST_TTL), 4);
        let v6 = PosixUdpSocket::bind(LOOPBACK_V6).expect("an IPv6 socket");
        v6.set_multicast_hops(6).expect("a hop limit");
        assert_eq!(
            get(v6.fd(), libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_HOPS),
            6
        );
    }

    /// A flag is switched on and read back as on; a descriptor that is not one is the kernel's
    /// refusal, with its errno.
    #[test]
    fn a_sockets_flag_is_switched_on_and_a_bad_descriptor_is_refused() {
        let socket = PosixUdpSocket::bind(LOOPBACK).expect("a socket");
        let read = |name: c_int| -> c_int {
            let mut value: c_int = -1;
            let mut len = size_of::<c_int>() as libc::socklen_t;
            // SAFETY: `value` and `len` are live and writable, and `len` is `value`'s size.
            let rc = unsafe {
                libc::getsockopt(
                    socket.fd(),
                    libc::SOL_SOCKET,
                    name,
                    (&mut value as *mut c_int).cast(),
                    &mut len,
                )
            };
            assert_eq!(rc, 0);
            value
        };
        assert_eq!(read(libc::SO_BROADCAST), 0, "a fresh socket has it off");
        set_flag(socket.fd(), libc::SOL_SOCKET, libc::SO_BROADCAST).expect("switched on");
        assert_ne!(read(libc::SO_BROADCAST), 0);
        assert_eq!(
            set_flag(-1, libc::SOL_SOCKET, libc::SO_BROADCAST),
            Err(libc::EBADF)
        );
    }

    /// Every socket this crate opens is closed when the process starts another program, made so by
    /// the open itself (with the kind where the kernel takes `SOCK_CLOEXEC`, by a call of its own
    /// on macOS), so no descriptor of a node leaks into a program it starts; a family the kernel
    /// has no socket of is the refusal, with its errno. Turned red by an open that drops
    /// `SOCK_CLOEXEC`, or on macOS the `fcntl` after the `socket`.
    #[test]
    fn a_socket_this_crate_opens_is_closed_on_exec() {
        for kind in [libc::SOCK_DGRAM, libc::SOCK_STREAM] {
            let fd = open_socket(libc::AF_INET, kind).expect("a socket");
            // SAFETY: plain system call on the descriptor just opened.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            // SAFETY: the descriptor this test opened, closed exactly once.
            unsafe { libc::close(fd) };
            assert_ne!(flags & libc::FD_CLOEXEC, 0, "a socket of kind {kind}");
        }
        assert_eq!(
            open_socket(-1, libc::SOCK_DGRAM),
            Err(libc::EAFNOSUPPORT),
            "no family numbered -1"
        );
    }

    #[test]
    fn a_descriptor_is_closed_on_exec_and_a_bad_one_is_refused() {
        let socket = PosixUdpSocket::bind(LOOPBACK).expect("a socket");
        set_close_on_exec(socket.fd()).expect("close-on-exec");
        let flags = unsafe { libc::fcntl(socket.fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        assert_eq!(set_close_on_exec(-1), Err(libc::EBADF));
    }

    #[test]
    fn a_bind_on_port_zero_names_the_port_the_kernel_chose() {
        let socket = PosixUdpSocket::bind(LOOPBACK).expect("a socket");
        assert_eq!(socket.local().ip(), LOOPBACK.ip());
        assert_ne!(
            socket.local().port(),
            0,
            "the locator must name a real port"
        );
    }

    #[test]
    fn a_datagram_sent_to_a_socket_is_taken_with_its_source() {
        let (a, b) = pair();
        a.send_to(b.local(), b"ping").expect("a send");
        let mut buf = [0u8; 16];
        let (len, src) = b
            .recv_waiting(&mut buf)
            .expect("no error")
            .expect("a datagram within the receive timeout");
        assert_eq!(&buf[..len], b"ping");
        assert_eq!(
            src,
            a.local(),
            "the source is the sender's address and port"
        );
    }

    #[test]
    fn a_quiet_socket_answers_nothing_yet_both_ways_and_does_not_block() {
        let socket = PosixUdpSocket::bind(LOOPBACK).expect("a socket");
        let mut buf = [0u8; 16];
        assert_eq!(socket.try_recv(&mut buf), Ok(None));
        let started = std::time::Instant::now();
        assert_eq!(socket.recv_waiting(&mut buf), Ok(None));
        let waited = started.elapsed();
        assert!(
            waited < std::time::Duration::from_millis(200),
            "a wait is bounded by the receive timeout, took {waited:?}"
        );
    }

    #[test]
    fn a_queued_datagram_is_taken_without_waiting() {
        let (a, b) = pair();
        a.send_to(b.local(), b"now").expect("a send");
        // Let the loopback deliver it, then ask without waiting.
        b.wait_readable(100);
        let mut buf = [0u8; 16];
        let (len, ..) = b
            .try_recv(&mut buf)
            .expect("no error")
            .expect("a queued datagram");
        assert_eq!(&buf[..len], b"now");
        assert_eq!(b.try_recv(&mut buf), Ok(None), "and then nothing");
    }

    #[test]
    fn a_longer_receive_timeout_is_taken_and_a_datagram_still_wakes_the_wait_at_once() {
        let (a, b) = pair();
        assert!(b.set_receive_timeout(2000), "the kernel takes two seconds");
        // A thread would make this test timing-dependent; send first, then ask: the wait returns
        // with the datagram without using its two seconds.
        a.send_to(b.local(), b"early").expect("a send");
        let started = std::time::Instant::now();
        let mut buf = [0u8; 16];
        let (len, ..) = b
            .recv_waiting(&mut buf)
            .expect("no error")
            .expect("the datagram");
        assert_eq!(&buf[..len], b"early");
        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "a queued datagram does not wait out the timeout"
        );

        // And a quiet socket now waits as long as it was told.
        assert!(b.set_receive_timeout(150));
        let started = std::time::Instant::now();
        assert_eq!(b.recv_waiting(&mut buf), Ok(None));
        let waited = started.elapsed();
        assert!(
            waited >= std::time::Duration::from_millis(120),
            "the wait is the armed 150 ms, took {waited:?}"
        );
    }

    /// A classic socket filter run as the kernel runs one at a UDP socket, on a datagram from
    /// `port` whose network header is `net`: how much of the datagram it keeps.
    #[cfg(all(feature = "host-multicast", target_os = "linux"))]
    fn run_filter(program: &[libc::sock_filter], port: u16, net: &[u8]) -> u32 {
        let base = libc::SKF_NET_OFF as u32;
        let mut a = 0u32;
        let mut pc = 0usize;
        while let Some(op) = program.get(pc) {
            pc += 1;
            match u32::from(op.code) {
                c if c == libc::BPF_LD | libc::BPF_H | libc::BPF_ABS => {
                    assert_eq!(op.k, 0, "the source port opens the UDP header");
                    a = u32::from(port);
                }
                c if c == libc::BPF_LD | libc::BPF_W | libc::BPF_ABS => {
                    let at = op.k.wrapping_sub(base) as usize;
                    let word: [u8; 4] = net
                        .get(at..at + 4)
                        .expect("a word of the network header")
                        .try_into()
                        .expect("four bytes");
                    a = u32::from_be_bytes(word);
                }
                c if c == libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K => {
                    pc += usize::from(if a == op.k { op.jt } else { op.jf });
                }
                c if c == libc::BPF_RET | libc::BPF_K => return op.k,
                other => panic!("an instruction the filter does not write: {other:#x}"),
            }
        }
        panic!("the program ran past its end")
    }

    /// The filter of a group's own send socket drops a datagram from its address and port and keeps
    /// one from another port or another address, in either family, run as the kernel runs it; an
    /// own address the source alone does not tell (an IPv6 scope, the unspecified address, port
    /// zero) has no filter. Turned red by a comparison that jumps to the wrong place, a source
    /// read at the wrong offset of its header, or a filter made for a scoped or unspecified address
    /// (`OwnSourceFilter::of`).
    #[cfg(all(feature = "host-multicast", target_os = "linux"))]
    #[test]
    fn the_own_source_filter_drops_only_the_own_address_and_port() {
        let keep = OwnSourceFilter::KEEP;
        let v4 = |ip: [u8; 4]| {
            let mut net = [0u8; 20];
            net[0] = 0x45;
            net[12..16].copy_from_slice(&ip);
            net
        };
        let own = SocketAddr::from(([10, 0, 0, 5], 40_000));
        let filter = OwnSourceFilter::of(own).expect("an IPv4 source");
        let program = filter.program();
        assert_eq!(program.len(), 6);
        assert_eq!(
            run_filter(program, 40_000, &v4([10, 0, 0, 5])),
            0,
            "its own"
        );
        assert_eq!(
            run_filter(program, 40_001, &v4([10, 0, 0, 5])),
            keep,
            "another port"
        );
        assert_eq!(
            run_filter(program, 40_000, &v4([10, 0, 0, 6])),
            keep,
            "another address"
        );

        let v6 = |ip: Ipv6Addr| {
            let mut net = [0u8; 40];
            net[0] = 0x60;
            net[8..24].copy_from_slice(&ip.octets());
            net
        };
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5);
        let own = SocketAddr::V6(SocketAddrV6::new(addr, 40_000, 0, 0));
        let filter = OwnSourceFilter::of(own).expect("an IPv6 source with no scope");
        let program = filter.program();
        assert_eq!(program.len(), 12);
        assert_eq!(run_filter(program, 40_000, &v6(addr)), 0, "its own");
        assert_eq!(run_filter(program, 40_001, &v6(addr)), keep, "another port");
        // One address for each of the four words the source is compared in.
        for other in [
            Ipv6Addr::new(0x2002, 0xdb8, 0, 0, 0, 0, 0, 5),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 5),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 1, 0, 5),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 6),
        ] {
            assert_eq!(run_filter(program, 40_000, &v6(other)), keep, "{other}");
        }

        let scoped = SocketAddrV6::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 5), 40_000, 0, 3);
        assert!(
            OwnSourceFilter::of(SocketAddr::V6(scoped)).is_none(),
            "a scoped address is left to the receive"
        );
        assert!(OwnSourceFilter::of(SocketAddr::from(([0, 0, 0, 0], 40_000))).is_none());
        assert!(OwnSourceFilter::of(SocketAddr::from(([10, 0, 0, 5], 0))).is_none());
    }

    /// A socket that has the kernel drop what one socket sent never receives it, and still receives
    /// what another socket sent: the member's datagram is the first its receive finds, with nothing
    /// queued behind it. The CONTROL is the same two sends to a socket with no filter, whose first
    /// datagram is the own one. Turned red by a filter the kernel refuses
    /// (`PosixUdpSocket::drop_sent_by`), or one that drops the member's datagram too.
    #[cfg(all(feature = "host-multicast", target_os = "linux"))]
    #[test]
    fn the_kernel_drops_what_the_own_socket_sent_and_keeps_a_members() {
        let own = PosixUdpSocket::bind(LOOPBACK).expect("the own socket");
        let member = PosixUdpSocket::bind(LOOPBACK).expect("a member's socket");
        let plain = PosixUdpSocket::bind(LOOPBACK).expect("a socket with no filter");
        let filtered = PosixUdpSocket::bind(LOOPBACK).expect("a filtered socket");
        assert!(
            filtered.drop_sent_by(own.local()),
            "the kernel takes the filter"
        );
        for to in [plain.local(), filtered.local()] {
            own.send_to(to, b"own").expect("a send");
            member.send_to(to, b"member").expect("a send");
        }
        let mut buf = [0u8; 16];
        let (len, from) = plain
            .recv_waiting(&mut buf)
            .expect("no error")
            .expect("a datagram");
        assert_eq!(
            (&buf[..len], from),
            (&b"own"[..], own.local()),
            "CONTROL: the own datagram comes first"
        );
        let (len, from) = filtered
            .recv_waiting(&mut buf)
            .expect("no error")
            .expect("a datagram");
        assert_eq!(
            (&buf[..len], from),
            (&b"member"[..], member.local()),
            "the own datagram was dropped"
        );
        assert_eq!(
            filtered.recv_waiting(&mut buf),
            Ok(None),
            "and nothing is queued behind it"
        );
    }

    #[test]
    fn a_datagram_longer_than_the_buffer_is_truncated_to_it() {
        let (a, b) = pair();
        a.send_to(b.local(), b"0123456789").expect("a send");
        let mut buf = [0u8; 4];
        let (len, ..) = b
            .recv_waiting(&mut buf)
            .expect("no error")
            .expect("a datagram");
        assert_eq!(
            len, 4,
            "the stack truncates, which the session reads as a bad frame"
        );
    }

    #[test]
    fn binding_a_port_that_is_taken_is_a_bind_error() {
        let first = PosixUdpSocket::bind(LOOPBACK).expect("a socket");
        match PosixUdpSocket::bind(first.local()) {
            Err(PosixNetError::Bind(e)) => assert_eq!(e, libc::EADDRINUSE),
            Err(other) => panic!("a different error: {other:?}"),
            Ok(_) => panic!("a second bind on a taken port must fail"),
        }
    }

    wz_runtime_coop::with_heap_link_seams! {
        /// The stack's waits name each socket by its descriptor: a wait over a set whose last
        /// socket has a datagram ends at once, one over quiet sockets sleeps its time, and one
        /// that names a handle of another stack's, or more sockets than the set holds, is the
        /// bounded look. A socket with room answers a wait for room. Turned red by a wait that
        /// names only the first socket, or sleeps its whole time on what it cannot name.
        #[test]
        fn the_stacks_waits_name_each_socket_and_look_at_what_they_cannot() {
            use std::time::{Duration, Instant};
            use std::vec::Vec;

            let (quiet, sender) = pair();
            let ready = PosixUdpSocket::bind(LOOPBACK).expect("a socket");
            let on = |socket: &PosixUdpSocket| {
                LinkWait::input(socket.input_wait().expect("a socket names its descriptor"))
            };
            let mut set: Vec<LinkWait> = (0..crate::WAIT_SET_SOCKETS).map(|_| on(&quiet)).collect();

            let started = Instant::now();
            PosixWaits.wait(&set, 100);
            assert!(
                started.elapsed() >= Duration::from_millis(80),
                "CONTROL: quiet sockets that fill the set sleep the wait's time"
            );

            let started = Instant::now();
            PosixWaits.wait(&[on(&quiet), LinkWait::input(WaitOn::AppLink(7))], 5_000);
            assert!(
                started.elapsed() < Duration::from_millis(1_000),
                "a handle of another stack's is the bounded look, took {:?}",
                started.elapsed()
            );

            set.push(on(&quiet));
            let started = Instant::now();
            PosixWaits.wait(&set, 5_000);
            assert!(
                started.elapsed() < Duration::from_millis(1_000),
                "a wait past the set is the bounded look, took {:?}",
                started.elapsed()
            );

            set.pop();
            set.pop();
            set.push(on(&ready));
            sender.send_to(ready.local(), b"wake").expect("a send");
            let started = Instant::now();
            PosixWaits.wait(&set, 5_000);
            assert!(
                started.elapsed() < Duration::from_millis(2_500),
                "the datagram on the set's last socket ended the wait, took {:?}",
                started.elapsed()
            );

            assert!(
                PosixWaits.wait_room(on(&quiet).on, 1_000),
                "an idle datagram socket has room"
            );
        }

        /// A wait that tells what it found ready moves the socket with a datagram and the handle it
        /// cannot name to the front, and answers two: the quiet sockets stay behind. A set of quiet
        /// sockets alone answers none. Turned red by a wait that answers every entry, which would
        /// ask a quiet port for a connection after every wait.
        #[test]
        fn the_stacks_wait_moves_what_it_found_ready_to_the_front() {
            let (quiet, sender) = pair();
            let ready = PosixUdpSocket::bind(LOOPBACK).expect("a socket");
            let on = |socket: &PosixUdpSocket| {
                LinkWait::input(socket.input_wait().expect("a socket names its descriptor"))
            };
            let mut set = [on(&quiet), on(&quiet)];
            assert_eq!(
                PosixWaits.wait_ready(&mut set, 10),
                0,
                "CONTROL: quiet sockets alone are none ready"
            );

            let elsewhere = LinkWait::input(WaitOn::AppLink(7));
            sender.send_to(ready.local(), b"wake").expect("a send");
            // The datagram has arrived once a wait on its socket alone ends; nothing reads it.
            PosixWaits.wait(&[on(&ready)], 5_000);
            let mut set = [on(&quiet), on(&ready), on(&quiet), elsewhere];
            let found = PosixWaits.wait_ready(&mut set, 5_000);
            assert_eq!(found, 2, "the socket with a datagram and the handle it cannot name");
            assert_eq!(set.get(..found), Some(&[on(&ready), elsewhere][..]));
        }

        /// A stack's wake ends a wait over the links beside it once its waker is woken from
        /// another thread, and the wait that found it leaves it quiet: the next wait sleeps its
        /// time. CONTROL: before the waker is woken the wait sleeps too. Turned red by a wake
        /// that is never named to the kernel, or one left ready after the wait that found it.
        #[cfg(feature = "alloc")]
        #[test]
        fn a_stacks_wake_ends_the_wait_beside_it_and_is_quiet_after() {
            use std::time::{Duration, Instant};

            let (quiet, _sender) = pair();
            let wake = PosixWaits.wake().expect("the host makes a wake");
            let set = [
                LinkWait::input(quiet.input_wait().expect("a descriptor")),
                LinkWait::input(wake.on),
            ];
            let started = Instant::now();
            PosixWaits.wait(&set, 50);
            assert!(
                started.elapsed() >= Duration::from_millis(40),
                "CONTROL: nothing woke it"
            );
            let waker = wake.waker.clone();
            let waking = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                waker.wake();
            });
            let started = Instant::now();
            PosixWaits.wait(&set, 10_000);
            let waited = started.elapsed();
            waking.join().expect("the waking thread");
            assert!(
                waited < Duration::from_secs(5),
                "the wake ended the wait: {waited:?}"
            );
            let started = Instant::now();
            PosixWaits.wait(&set, 50);
            assert!(
                started.elapsed() >= Duration::from_millis(40),
                "the wait that found the wake left it quiet"
            );
        }

        /// A wake is read only by a wait that found it ready: one past the set, which the wait
        /// did not name to the kernel, keeps its word for the next wait, which ends at once.
        /// CONTROL: the first wait is the bounded look. Turned red by a wait that reads every wake
        /// it was given, ready or not.
        #[cfg(feature = "alloc")]
        #[test]
        fn a_wake_the_wait_did_not_find_ready_keeps_its_word() {
            use std::time::{Duration, Instant};
            use std::vec::Vec;

            let (quiet, _sender) = pair();
            let wake = PosixWaits.wake().expect("the host makes a wake");
            let mut set: Vec<LinkWait> = (0..crate::WAIT_SET_SOCKETS)
                .map(|_| LinkWait::input(quiet.input_wait().expect("a descriptor")))
                .collect();
            set.push(LinkWait::input(wake.on));
            wake.waker.wake_by_ref();
            let started = Instant::now();
            PosixWaits.wait(&set, 5_000);
            assert!(
                started.elapsed() < Duration::from_millis(1_000),
                "CONTROL: a wait past the set is the bounded look"
            );
            let started = Instant::now();
            PosixWaits.wait(&[LinkWait::input(wake.on)], 5_000);
            assert!(
                started.elapsed() < Duration::from_millis(1_000),
                "the wake the first wait did not look at was left ready, took {:?}",
                started.elapsed()
            );
        }

        /// A wait reads the wake it found ready and no socket beside it, past an entry before the
        /// wake that it could not name to the kernel: a socket with a datagram keeps it for its
        /// link. Turned red by a wake looked for at the place of its entry in the wait rather than
        /// in the set the kernel was handed (the wake left ready), or by a ready socket read as a
        /// wake (its datagram gone).
        #[cfg(feature = "alloc")]
        #[test]
        fn a_wait_reads_the_ready_wake_and_no_socket_beside_it() {
            let (_quiet, sender) = pair();
            let ready = PosixUdpSocket::bind(LOOPBACK).expect("a socket");
            let on = |socket: &PosixUdpSocket| {
                LinkWait::input(socket.input_wait().expect("a socket names its descriptor"))
            };
            let wake = PosixWaits.wake().expect("the host makes a wake");
            sender.send_to(ready.local(), b"data").expect("a send");
            // The datagram has arrived once a wait on its socket alone ends; nothing reads it.
            PosixWaits.wait(&[on(&ready)], 5_000);
            assert_eq!(
                PosixWaits.wait_ready(&mut [on(&ready)], 0),
                1,
                "CONTROL: the datagram waits on its socket"
            );
            wake.waker.wake_by_ref();
            let elsewhere = LinkWait::input(WaitOn::AppLink(7));
            PosixWaits.wait(&[elsewhere, on(&ready), LinkWait::input(wake.on)], 5_000);
            assert_eq!(
                PosixWaits.wait_ready(&mut [on(&ready)], 0),
                1,
                "the socket keeps its datagram"
            );
            assert_eq!(
                PosixWaits.wait_ready(&mut [LinkWait::input(wake.on)], 0),
                0,
                "the wake the wait found ready was read"
            );
        }
    }
}
