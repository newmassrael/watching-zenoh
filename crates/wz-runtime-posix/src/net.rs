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
#[cfg(target_os = "nto")]
const IPV6_JOIN: c_int = libc::IPV6_JOIN_GROUP;

// The heap profile's readiness seam is compiled where the runtime declares it, whatever this crate's
// own features are (`wz_runtime_coop::with_heap_link_seams!`), as is every implementation of it here.
wz_runtime_coop::with_heap_link_seams! {
    #[cfg(feature = "alloc")]
    use wz_runtime_coop::session_drive::{LinkReadiness, LinkWritability};
}
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
    /// `fcntl(F_SETFL, O_NONBLOCK)` on a listening socket failed with this `errno`.
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
    /// `setsockopt` of a multicast egress option (`IP_MULTICAST_IF`, `IP_MULTICAST_TTL`) failed
    /// with this `errno`.
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
/// A wait on a socket that a thread other than its link's makes, for input ([`LinkReadiness`]) or
/// for room ([`LinkWritability`]): `poll` on a duplicate of the socket's descriptor, which this
/// owns and closes. A duplicate and not the number itself, so a wait that outlives the socket
/// never reaches a descriptor number its close has freed for another file.
#[cfg(feature = "alloc")]
pub(crate) struct FdReadiness(c_int);

#[cfg(feature = "alloc")]
impl FdReadiness {
    /// A wait on `fd`, or `None` when the descriptor cannot be duplicated.
    fn duplicate(fd: c_int) -> Option<Self> {
        // SAFETY: `fd` is the caller's live descriptor; `fcntl` duplicates it or fails.
        let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            return None;
        }
        Some(FdReadiness(dup))
    }

    /// A wait for input on `fd`, or `None` when the descriptor cannot be duplicated.
    pub(crate) fn of(fd: c_int) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
        Some(alloc::boxed::Box::new(Self::duplicate(fd)?))
    }

    /// A wait for room on the stream socket `fd`, or `None` when the descriptor cannot be
    /// duplicated.
    pub(crate) fn writable_of(fd: c_int) -> Option<alloc::boxed::Box<dyn LinkWritability>> {
        Some(alloc::boxed::Box::new(Self::duplicate(fd)?))
    }
}

#[cfg(feature = "alloc")]
impl LinkWritability for FdReadiness {
    fn wait_writable(&self, timeout_us: u64) -> bool {
        poll_writable(self.0, timeout_us)
    }
}

#[cfg(feature = "alloc")]
impl LinkReadiness for FdReadiness {
    fn wait_readable(&self, timeout_ms: u32) {
        let mut pfd = libc::pollfd {
            fd: self.0,
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout = c_int::try_from(timeout_ms).unwrap_or(c_int::MAX);
        // SAFETY: one live `pollfd` over the descriptor this owns; the timeout bounds the wait. A
        // failed or interrupted wait is a quiet socket: the step that follows reports the error.
        unsafe { libc::poll(&mut pfd, 1, timeout) };
    }

    fn handle(&self) -> Option<usize> {
        usize::try_from(self.0).ok()
    }

    fn wait_readable_among(&self, others: &[alloc::sync::Arc<dyn LinkReadiness>], timeout_ms: u32) {
        let mut fds = alloc::vec![libc::pollfd {
            fd: self.0,
            events: libc::POLLIN,
            revents: 0,
        }];
        for other in others {
            match other
                .handle()
                .and_then(|handle| c_int::try_from(handle).ok())
            {
                Some(fd) => fds.push(libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                }),
                // A wait this cannot name to the kernel: the bounded look, so it is not starved
                // behind a wait on the others.
                None => return self.wait_readable(timeout_ms.min(1)),
            }
        }
        let timeout = c_int::try_from(timeout_ms).unwrap_or(c_int::MAX);
        // SAFETY: `fds` is live for the call and its length is the count passed; every descriptor
        // is a duplicate its owner holds open for as long as the wait is held, and the timeout
        // bounds the wait. A failed or interrupted wait is a quiet socket: the step that follows
        // reads and reports the error.
        unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
    }
}

#[cfg(feature = "alloc")]
impl Drop for FdReadiness {
    fn drop(&mut self) {
        // SAFETY: the duplicate is this value's own descriptor, closed exactly once.
        unsafe { libc::close(self.0) };
    }
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

/// Switch the boolean socket option `name` of `level` on for `fd`.
pub(crate) fn set_flag(fd: c_int, level: c_int, name: c_int) -> Result<(), c_int> {
    set_option(fd, level, name, &(1 as c_int))
}

/// Make `fd` non-blocking or blocking (`fcntl(F_SETFL, O_NONBLOCK)`): the `errno` when the kernel
/// refuses. A socket is made this way and not by a flag of `socket` or `accept4`, which Neutrino
/// does not have: the one call is the same on both kernels, and a connection a non-blocking
/// listener hands over is made blocking here whether the kernel's accept passed the flag on (the
/// BSD one does) or not (Linux's).
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
    pub(crate) fn of(at: SocketAddr) -> Self {
        // SAFETY: an all-zero `sockaddr_storage` is a valid value of it, an unspecified family.
        let mut storage: libc::sockaddr_storage = unsafe { core::mem::zeroed() };
        let len = match at {
            SocketAddr::V4(v4) => {
                let sin = libc::sockaddr_in {
                    // Neutrino's socket address, as the BSDs', carries its own length.
                    #[cfg(target_os = "nto")]
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
                // below, and what is not set (Neutrino's length aside) is zero as the kernel wants.
                let mut sin6: libc::sockaddr_in6 = unsafe { core::mem::zeroed() };
                #[cfg(target_os = "nto")]
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
    /// has one). The flow label is left out: it is a field of a packet and not of an end, and a
    /// link compares its peer by address, port and scope.
    pub(crate) fn to_socket_addr(&self) -> Option<SocketAddr> {
        match c_int::from(self.storage.ss_family) {
            libc::AF_INET if self.len as usize >= size_of::<libc::sockaddr_in>() => {
                // SAFETY: the kernel wrote an `AF_INET` address, which is a `sockaddr_in`, and the
                // storage is aligned for it.
                let sin = unsafe { &*(self.as_ptr() as *const libc::sockaddr_in) };
                Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()),
                    u16::from_be(sin.sin_port),
                )))
            }
            libc::AF_INET6 if self.len as usize >= size_of::<libc::sockaddr_in6>() => {
                // SAFETY: the kernel wrote an `AF_INET6` address, which is a `sockaddr_in6`, and
                // the storage is aligned for it.
                let sin6 = unsafe { &*(self.as_ptr() as *const libc::sockaddr_in6) };
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
}

/// The address a `getsockname` or `getpeername` of `fd` reports: the `errno` when the call fails,
/// `EAFNOSUPPORT` when it names a family other than the two.
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
        // SAFETY: plain system call with value arguments.
        let fd = unsafe { libc::socket(family_of(&at), libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(PosixNetError::Socket(errno()));
        }
        // Owned from here, so an early return closes it.
        let mut this = Self { fd, local: at };
        if let Err(e) = set_receive_timeout_ms(fd, SERVICE_WAIT_MS) {
            return Err(PosixNetError::ReceiveTimeout(e));
        }
        if shared {
            set_flag(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR).map_err(PosixNetError::ReuseAddr)?;
            set_flag(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT).map_err(PosixNetError::ReusePort)?;
        }
        let local = RawAddr::of(at);
        // SAFETY: `local` is a live socket address of the length passed.
        let rc = unsafe { libc::bind(fd, local.as_ptr(), local.size()) };
        if rc != 0 {
            return Err(PosixNetError::Bind(errno()));
        }
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
                // `c_uint` on Linux and Neutrino, `c_int` on Android: an index fits either.
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

    wz_runtime_coop::with_heap_link_seams! {
        #[cfg(feature = "alloc")]
        fn readiness(&self) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
            FdReadiness::of(self.fd)
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
}
