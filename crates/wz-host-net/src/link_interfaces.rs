// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y453 — LIVE resolution of the NIC names an address is configured on: the
//! data source for the §5.16 `interfaces` SUBJECT axis, the wz counterpart of
//! zenoh's `zenoh_util::net::get_interface_names_by_addr`
//! (`commons/zenoh-util/src/net/mod.rs:318-334`).
//!
//! # Three deliberate improvements on upstream
//!
//! Each is a defect in zenoh 1.5.0 (`49c8a53`) that this module does not
//! reproduce. They are divergences, so they are named rather than left implicit.
//!
//! 1. **No process-lifetime cache.** zenoh resolves the interface table ONCE,
//!    into a `lazy_static ref IFACES: Vec<NetworkInterface> =
//!    pnet_datalink::interfaces()` (`net/mod.rs:31-33`), and every later lookup
//!    filters that frozen snapshot. A NIC — or an address — that appears after
//!    the first lookup is therefore invisible to zenoh's subject axis for the
//!    rest of the process's life, which on a router that outlives an interface
//!    reconfiguration is silently wrong. wz calls `getifaddrs` at each
//!    resolution, and resolves once per LINK OPEN, which is the moment a link's
//!    local address is actually established and cannot subsequently change.
//! 2. **"Could not determine" is distinguishable from "no NICs".** zenoh maps a
//!    resolution ERROR to `vec![]` (`zenoh-link-commons/src/unicast.rs:112-118`),
//!    the identical value it uses for a link that genuinely sits on no NIC — so
//!    a failed syscall reads downstream as a definite negative. This function
//!    returns [`Option`]: `Some(names)` resolved (possibly empty, meaning
//!    definitively no matching NIC), `None` could not determine. The interceptor
//!    subject filter then treats the two differently, which zenoh cannot.
//! 3. **POSIX, not Linux-only.** The syscall is `getifaddrs(3)`, available across
//!    unix; a non-unix target returns `None` (could not determine) rather than a
//!    wrong answer.
//!
//! # No new workspace dependency
//!
//! zenoh reaches this through `pnet_datalink`. wz calls `getifaddrs` through the
//! `libc` crate it ALREADY carries (previously pulled by
//! `transport-link-unixpipe` for `mkfifo`), so the §5.16 subject axis costs the
//! from-scratch reimplementation no new third-party surface.
//!
//! # Where it lives
//!
//! These are facts about the host, not about a runtime, so they are this crate's and not the
//! tokio runtime's: the cooperative host reads the same interface table the same way. The tokio
//! runtime re-exports the module at its old path and keeps the builders of a link's subject and
//! endpoints, which are spelled in session-core's types.

use std::net::{IpAddr, SocketAddr};

/// The names of the network interfaces configured with `addr`, or `None` when
/// that could not be determined.
///
/// - `Some(names)` — resolved. An EMPTY vec is a definite answer: no interface
///   carries this address (a unix-socket / pipe / serial / vsock link, or an
///   address that is not local).
/// - `None` — the resolution itself failed, or the platform has no
///   implementation. NOT the same as "no NICs": a rule narrowed by `interfaces`
///   treats an indeterminate subject as MATCHING (fail-closed), because all
///   three §5.16 interceptors are restrictive when they apply.
///
/// An UNSPECIFIED address (`0.0.0.0` / `::`) yields every interface name, as
/// zenoh's `get_interface_names_by_addr` does for the same input
/// (`net/mod.rs:320-326`) — a socket bound to the wildcard is on all of them.
#[cfg(unix)]
pub fn interface_names_for(addr: IpAddr) -> Option<Vec<String>> {
    use std::ffi::CStr;

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` writes a freshly allocated linked-list head through
    // the out-pointer and returns 0 on success. On failure it leaves `head`
    // untouched, and the early return below never reads it.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }

    let mut names: Vec<String> = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is non-null and points at a node the successful
        // `getifaddrs` above allocated; the list is not mutated while walked.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;

        if ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: `ifa_name` is a NUL-terminated C string owned by the list.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();

        // A wildcard-bound socket is on every interface (zenoh's same arm).
        if addr.is_unspecified() {
            if !names.contains(&name) {
                names.push(name);
            }
            continue;
        }
        if sockaddr_ip(ifa.ifa_addr) == Some(addr) && !names.contains(&name) {
            names.push(name);
        }
    }

    // SAFETY: `head` came from the successful `getifaddrs` above and is freed
    // exactly once here; no node pointer outlives this call (names are owned
    // `String`s copied out of the list).
    unsafe { libc::freeifaddrs(head) };
    Some(names)
}

/// The IP address a `struct sockaddr` carries, or `None` for a null pointer or a
/// family that is not `AF_INET` / `AF_INET6` (the link-layer `AF_PACKET` /
/// `AF_LINK` entries `getifaddrs` also returns).
#[cfg(unix)]
fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    if sa.is_null() {
        return None;
    }
    // SAFETY: `sa` is non-null and points at a `sockaddr` owned by the ifaddrs
    // list. `sa_family` is the first field of every sockaddr variant, so reading
    // it through the base type is the documented way to discriminate. The read
    // is UNALIGNED because the list packs the larger variants behind a pointer
    // typed as the smaller base struct.
    let family = unsafe { std::ptr::read_unaligned(sa) }.sa_family as i32;
    match family {
        libc::AF_INET => {
            // SAFETY: family says this is a `sockaddr_in`, which is at least as
            // large as the `sockaddr` the pointer is typed as.
            let v4 = unsafe { std::ptr::read_unaligned(sa.cast::<libc::sockaddr_in>()) };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr))))
        }
        libc::AF_INET6 => {
            // SAFETY: family says this is a `sockaddr_in6`.
            let v6 = unsafe { std::ptr::read_unaligned(sa.cast::<libc::sockaddr_in6>()) };
            Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

/// Windows (R3140): the adapters that carry `addr`, by `AdapterName`, read from the adapter table
/// the way upstream's `get_interface_names_by_addr` reads it there. `None` when the table could
/// not be read, which is "indeterminate", not "on no NIC".
#[cfg(windows)]
pub fn interface_names_for(addr: IpAddr) -> Option<Vec<String>> {
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;
    Some(adapter_names_for(
        &read_adapter_rows(u32::from(AF_UNSPEC))?,
        addr,
    ))
}

/// Neither `getifaddrs` nor the Windows adapter table: the subject is INDETERMINATE rather than
/// empty. Returning `Some(vec![])` here would claim "this link is on no NIC", which is a
/// different — and wrong — statement; `None` lets the interceptor apply its fail-closed policy
/// instead.
#[cfg(not(any(unix, windows)))]
pub fn interface_names_for(_addr: IpAddr) -> Option<Vec<String>> {
    None
}

/// R311y454 — why a named interface could not be resolved to a usable local
/// address. The §5.2 `#iface=` MULTICAST honor needs an ADDRESS (`IP_MULTICAST_IF`
/// and `IP_ADD_MEMBERSHIP` both take one), where the unicast honor needs only a
/// device NAME (`SO_BINDTODEVICE`) — so this is a distinct resolution with a
/// distinct failure surface.
///
/// This is deliberately NOT the `Option` [`interface_names_for`] returns. That
/// function feeds the §5.16 subject filter, which needs exactly two answers
/// (resolved / indeterminate). The honor path needs THREE, because upstream
/// treats them differently: a name that does not resolve is a hard error, while a
/// name that resolves to an interface carrying no address of the group's family
/// is what zenoh silently falls back on. Collapsing those two into `None` would
/// erase the one boundary the policy turns on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IfaceResolveError {
    /// No interface by that name — zenoh `bail!("Interface {name} not found")`
    /// (`commons/zenoh-util/src/net/mod.rs:247`).
    NotFound,
    /// Present but `!IFF_UP` — zenoh `bail!("Interface {name} is not up")`
    /// (`net/mod.rs:233-235`). Pinning multicast egress at a down NIC would
    /// silently black-hole the group.
    NotUp,
    /// Present and up but `!IFF_RUNNING` (no carrier) — zenoh
    /// `bail!("Interface {name} is not running")` (`net/mod.rs:236-238`).
    NotRunning,
    /// The resolution itself could not run: `getifaddrs` failed, or the platform
    /// has none. Distinct from the three upstream arms because it says nothing
    /// about the interface — the CALLER decides, and it warns rather than failing,
    /// matching the off-platform arm of `bind_socket_to_device`
    /// (`crate::iface_bind`) so one locator does not fail multicast while merely
    /// warning on tcp.
    Undetermined,
}

impl core::fmt::Display for IfaceResolveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::NotFound => "not found",
            Self::NotUp => "not up",
            Self::NotRunning => "not running (no carrier)",
            Self::Undetermined => "could not be resolved on this platform",
        };
        f.write_str(s)
    }
}

/// The local unicast addresses configured on the interface named `name`, or why
/// that could not be determined — the wz counterpart of zenoh's
/// `get_unicast_addresses_of_interface` (`net/mod.rs:228-250`).
///
/// Multicast addresses are excluded, as upstream does (`net/mod.rs:239-243`): a
/// group address is never a legal `IP_MULTICAST_IF` or `imr_interface` value. The
/// FAMILY filter is deliberately left to the caller, exactly as upstream leaves
/// it to `zenoh-link-udp` (`multicast.rs:231-238` filters by the group's family
/// and takes the first) — the caller is the only one that knows which group is
/// being joined, and returning a mixed `Vec` that the caller must narrow is
/// what keeps a v4 site from `unwrap`ping a v6 address.
///
/// Divergence from upstream, and the reason this is not a port: zenoh answers
/// from a `lazy_static` snapshot of the interface table taken at first use
/// (`net/mod.rs:31-33`), so an interface reconfigured after process start is
/// answered from stale data forever. This resolves live, per call.
#[cfg(unix)]
pub fn unicast_addresses_of_interface(name: &str) -> Result<Vec<IpAddr>, IfaceResolveError> {
    use std::ffi::CStr;

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: as in `interface_names_for` — `getifaddrs` allocates the list and
    // writes its head through the out-pointer, returning 0 on success; on failure
    // `head` is untouched and the early return never reads it.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(IfaceResolveError::Undetermined);
    }

    let mut found = false;
    let mut up = false;
    let mut running = false;
    let mut addrs: Vec<IpAddr> = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is non-null and points at a node the successful
        // `getifaddrs` above allocated; the list is not mutated while walked.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;

        if ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: `ifa_name` is a NUL-terminated C string owned by the list.
        if unsafe { CStr::from_ptr(ifa.ifa_name) }.to_bytes() != name.as_bytes() {
            continue;
        }
        // The interface exists. `getifaddrs` emits one node PER ADDRESS, and each
        // node repeats the same flags, so OR-ing across nodes is the same answer
        // as reading any one of them — and it is also correct for an interface
        // that has flags but no address node at all (`ifa_addr` null).
        found = true;
        up |= ifa.ifa_flags as i32 & libc::IFF_UP != 0;
        running |= ifa.ifa_flags as i32 & libc::IFF_RUNNING != 0;
        if let Some(ip) = sockaddr_ip(ifa.ifa_addr) {
            // Upstream's filter: a multicast address is not a valid interface
            // selector.
            if !ip.is_multicast() && !addrs.contains(&ip) {
                addrs.push(ip);
            }
        }
    }

    // SAFETY: `head` came from the successful `getifaddrs` above and is freed
    // exactly once here; no node pointer outlives this call (the addresses are
    // copied out by value).
    unsafe { libc::freeifaddrs(head) };

    // The three upstream arms, in upstream's order.
    if !found {
        return Err(IfaceResolveError::NotFound);
    }
    if !up {
        return Err(IfaceResolveError::NotUp);
    }
    if !running {
        return Err(IfaceResolveError::NotRunning);
    }
    Ok(addrs)
}

/// Non-unix: no `getifaddrs`. [`IfaceResolveError::Undetermined`] rather than
/// `NotFound`, so the caller warns instead of rejecting a locator that a unix
/// host would have accepted.
#[cfg(not(unix))]
pub fn unicast_addresses_of_interface(_name: &str) -> Result<Vec<IpAddr>, IfaceResolveError> {
    Err(IfaceResolveError::Undetermined)
}

/// R3138 -- the FIRST IPv4 address of the interface named `name`, the way
/// `zenoh_util::net::get_interface` answers a name
/// (`commons/zenoh-util/src/net/mod.rs` @ `pub fn get_interface`).
///
/// Unlike [`unicast_addresses_of_interface`], which resolves a LOCATOR's `#iface=` and so
/// refuses an interface that is down, not running, or unknown, this reads the interface table and
/// nothing else: an interface with no link still answers with its address, and one with no IPv4
/// address, or none of that name, answers `None`. That is the difference the scouting key needs.
/// Upstream scouts by whatever address the table holds, up or not, and a name that finds nothing
/// is only logged and left out.
///
/// Same divergence as the neighbours: resolved live per call, where upstream answers from a
/// snapshot taken at first use.
#[cfg(unix)]
pub fn first_ipv4_of_interface_named(name: &str) -> Option<IpAddr> {
    use std::ffi::CStr;

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: as in `unicast_addresses_of_interface` -- `getifaddrs` allocates the list and
    // writes its head through the out-pointer, returning 0 on success; on failure `head` is
    // untouched and the early return never reads it.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    // Every address of the interface, in the table's order: `getifaddrs` emits one node per
    // address, and which of them is FIRST is the table's, not a choice made here.
    let mut addresses: Vec<IpAddr> = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is non-null and points at a node the successful `getifaddrs` above
        // allocated; the list is not mutated while walked.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: `ifa_name` is a NUL-terminated C string owned by the list.
        if unsafe { CStr::from_ptr(ifa.ifa_name) }.to_bytes() != name.as_bytes() {
            continue;
        }
        if let Some(ip) = sockaddr_ip(ifa.ifa_addr) {
            addresses.push(ip);
        }
    }
    // SAFETY: `head` came from the successful `getifaddrs` above and is freed exactly once.
    unsafe { libc::freeifaddrs(head) };
    first_ipv4_among(&addresses)
}

/// The first IPv4 address of `addresses`, in the order given: upstream's per-interface loop
/// returns the first address that `is_ipv4` and never looks at the rest, so an interface that
/// holds a second IPv4 address, or an IPv6 one ahead of its IPv4, is answered by that first IPv4
/// all the same. Split out of the table walk so that it can be told on a table made for it.
pub fn first_ipv4_among(addresses: &[IpAddr]) -> Option<IpAddr> {
    addresses.iter().find(|address| address.is_ipv4()).copied()
}

/// Windows: the IPv4 adapter table, as upstream's `get_interface` reads it there. A name matches
/// an adapter's `AdapterName`, `FriendlyName` or `Description`; see [`adapter_first_ipv4_named`].
#[cfg(windows)]
pub fn first_ipv4_of_interface_named(name: &str) -> Option<IpAddr> {
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    adapter_first_ipv4_named(&read_adapter_rows(u32::from(AF_INET))?, name)
}

/// Neither `getifaddrs` nor the Windows adapter table: a name finds nothing and is left out, as an
/// unknown one is.
#[cfg(not(any(unix, windows)))]
pub fn first_ipv4_of_interface_named(_name: &str) -> Option<IpAddr> {
    None
}

/// R3140 -- one adapter of the Windows adapter table, as `GetAdaptersAddresses` reports it.
///
/// Upstream answers every interface question on Windows from this one table, and its answers
/// differ from the unix ones in what they look at, so the reading is kept as plain data and the
/// questions as pure functions over it: they are told on tables made for them on any host, and
/// the one place that touches the system is [`read_adapter_rows`].
#[cfg(any(windows, test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AdapterRow {
    /// `AdapterName`, the adapter's identifier (a GUID in braces), which is what upstream's
    /// `get_local_addresses` and `get_interface_names_by_addr` call an interface's name.
    pub(crate) adapter_name: String,
    /// `FriendlyName`, the name a user sees ("Ethernet").
    pub(crate) friendly_name: String,
    /// `Description`, the driver's text.
    pub(crate) description: String,
    /// `Ipv6IfIndex`, which is the index upstream's `get_index_of_interface` returns for an
    /// IPv4 address too.
    pub(crate) ipv6_if_index: u32,
    /// Every unicast address, in the table's order.
    pub(crate) unicast: Vec<IpAddr>,
}

/// Every unicast address of the adapters, restricted to the one whose `AdapterName` is
/// `interface` when one is named: upstream's `get_local_addresses` on Windows
/// (`commons/zenoh-util/src/net/mod.rs` @ `pub fn get_local_addresses(interface: Option<&str>) -> ZResult<Vec<IpAddr>> {`).
///
/// It does not ask whether an adapter is up or running, which the unix reading does: the Windows
/// reading never has.
#[cfg(any(windows, test))]
pub(crate) fn adapter_local_addresses(rows: &[AdapterRow], interface: Option<&str>) -> Vec<IpAddr> {
    rows.iter()
        .filter(|row| interface.map_or(true, |name| row.adapter_name == name))
        .flat_map(|row| row.unicast.iter().copied())
        .collect()
}

/// What a name finds on the adapter table: upstream's `get_interface` on Windows
/// (`commons/zenoh-util/src/net/mod.rs` @ `pub fn get_interface(name: &str) -> ZResult<Option<IpAddr>> {`).
///
/// An adapter whose `AdapterName`, `FriendlyName` or `Description` is `name` answers with its
/// first IPv4 address. And, adapter by adapter and after that, an address whose text is `name` is
/// itself the answer; the table is walked once, so an earlier adapter's address text wins over a
/// later adapter's name.
#[cfg(any(windows, test))]
pub(crate) fn adapter_first_ipv4_named(rows: &[AdapterRow], name: &str) -> Option<IpAddr> {
    for row in rows {
        if row.adapter_name == name || row.friendly_name == name || row.description == name {
            if let Some(address) = first_ipv4_among(&row.unicast) {
                return Some(address);
            }
        }
        if let Some(address) = row.unicast.iter().find(|a| a.to_string() == name) {
            return Some(*address);
        }
    }
    None
}

/// The adapters that carry `addr`, by `AdapterName`: upstream's `get_interface_names_by_addr` on
/// Windows (`commons/zenoh-util/src/net/mod.rs` @ `pub fn get_interface_names_by_addr(addr: IpAddr) -> ZResult<Vec<String>> {`).
/// An unspecified address names every adapter.
#[cfg(any(windows, test))]
pub(crate) fn adapter_names_for(rows: &[AdapterRow], addr: IpAddr) -> Vec<String> {
    if addr.is_unspecified() {
        return rows.iter().map(|row| row.adapter_name.clone()).collect();
    }
    let addr = addr.to_canonical();
    rows.iter()
        .flat_map(|row| {
            row.unicast
                .iter()
                .filter(move |a| **a == addr)
                .map(move |_| row.adapter_name.clone())
        })
        .collect()
}

/// The index of every adapter that carries `addr`, as `Ipv6IfIndex`: upstream's
/// `get_index_of_interface` on Windows answers the first carrier's `Ipv6IfIndex` for an IPv4
/// address too (`commons/zenoh-util/src/net/mod.rs` @ `pub fn get_index_of_interface(addr: IpAddr) -> ZResult<u32> {`).
/// Every carrier is returned, as the unix reading of this crate does, and the caller takes the
/// one it needs.
#[cfg(any(windows, test))]
pub(crate) fn adapter_indices_of(rows: &[AdapterRow], addr: IpAddr) -> Vec<u32> {
    rows.iter()
        .filter(|row| row.unicast.contains(&addr))
        .map(|row| row.ipv6_if_index)
        .collect()
}

/// R3140 -- the adapter table of this Windows host, read with `GetAdaptersAddresses` for one
/// address family (`AF_UNSPEC` for both, `AF_INET` for IPv4 alone, as upstream asks for each
/// question). The buffer starts at 8192 bytes and is grown up to three times on
/// `ERROR_BUFFER_OVERFLOW`, as upstream's `get_adapters_addresses` does; any other failure
/// answers `None`, "could not be determined", and not an empty table.
#[cfg(windows)]
fn read_adapter_rows(family: u32) -> Option<Vec<AdapterRow>> {
    use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };

    const START_BYTES: u32 = 8192;
    const MAX_RETRIES: u32 = 3;

    let mut size = START_BYTES;
    let mut retries = 0;
    // Eight-byte units, so the buffer is aligned for the structs the call writes into it.
    let mut buffer: Vec<u64>;
    loop {
        buffer = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: `buffer` is at least `size` bytes and 8-aligned, `size` is the in/out length
        // the call expects, and the flags and reserved pointer are the documented defaults.
        let ret = unsafe {
            GetAdaptersAddresses(
                family,
                0,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &mut size,
            )
        };
        if ret == 0 {
            break;
        }
        if ret != ERROR_BUFFER_OVERFLOW || retries >= MAX_RETRIES {
            return None;
        }
        retries += 1;
    }

    let mut rows = Vec::new();
    let mut cursor = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !cursor.is_null() {
        // SAFETY: `cursor` is the head of the list the successful call wrote into `buffer`, or
        // a `Next` it linked; every pointer in that list points into `buffer`, which outlives
        // this loop.
        let adapter = unsafe { &*cursor };
        let mut unicast = Vec::new();
        let mut address = adapter.FirstUnicastAddress;
        while !address.is_null() {
            // SAFETY: a `Next` of the list described above.
            let entry = unsafe { &*address };
            if let Some(ip) = sockaddr_ip_windows(entry.Address.lpSockaddr) {
                unicast.push(ip);
            }
            address = entry.Next;
        }
        rows.push(AdapterRow {
            adapter_name: c_string(adapter.AdapterName),
            friendly_name: wide_string(adapter.FriendlyName),
            description: wide_string(adapter.Description),
            ipv6_if_index: adapter.Ipv6IfIndex,
            unicast,
        });
        cursor = adapter.Next;
    }
    Some(rows)
}

/// The IP address a Windows `SOCKADDR` holds, or `None` for a family that is neither.
#[cfg(windows)]
fn sockaddr_ip_windows(
    sa: *const windows_sys::Win32::Networking::WinSock::SOCKADDR,
) -> Option<IpAddr> {
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};

    if sa.is_null() {
        return None;
    }
    // SAFETY: a non-null `lpSockaddr` of a unicast entry points at a `SOCKADDR` of the size its
    // family says; the family is read first and the wider struct only when it is the one
    // named.
    unsafe {
        match (*sa).sa_family {
            AF_INET => {
                let v4 = &*(sa.cast::<SOCKADDR_IN>());
                Some(IpAddr::from(v4.sin_addr.S_un.S_addr.to_ne_bytes()))
            }
            AF_INET6 => {
                let v6 = &*(sa.cast::<SOCKADDR_IN6>());
                Some(IpAddr::from(v6.sin6_addr.u.Byte))
            }
            _ => None,
        }
    }
}

/// A NUL-terminated ANSI string of the adapter list, or empty for a null pointer.
#[cfg(windows)]
fn c_string(p: *const u8) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: a non-null `AdapterName` is NUL-terminated and lives in the caller's buffer.
    unsafe { std::ffi::CStr::from_ptr(p.cast()) }
        .to_string_lossy()
        .into_owned()
}

/// A NUL-terminated UTF-16 string of the adapter list, or empty for a null pointer.
#[cfg(windows)]
fn wide_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    // SAFETY: a non-null `FriendlyName` or `Description` is NUL-terminated and lives in the
    // caller's buffer; the walk stops at the terminator.
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

/// R3138 -- what `scouting/multicast/interface` names, as upstream reads it
/// (`zenoh/src/net/runtime/orchestrator.rs` @ `pub fn get_interfaces`): the text is split on
/// commas, each part is trimmed, a part that parses as an address IS that address (of either
/// family, held by this host or not), and any other part is a NAME that `lookup` turns into an
/// address or, finding nothing, leaves out. The result can be empty, and then the node has no
/// interface to scout by: it opens, sends nothing, and ends alone.
///
/// The lookup is a parameter so that what this decides can be told without a host that holds the
/// interfaces: an interface with several IPv4 addresses, or one that is down, is a table here.
pub fn scouting_interface_addresses(
    text: &str,
    lookup: impl Fn(&str) -> Option<IpAddr>,
) -> Vec<IpAddr> {
    text.split(',')
        .filter_map(|part| {
            let part = part.trim();
            part.parse::<IpAddr>().ok().or_else(|| lookup(part))
        })
        .collect()
}

/// R2219 — one IPv4 address per interface that can carry multicast: the wz
/// counterpart of zenoh's `get_multicast_interfaces`
/// (`commons/zenoh-util/src/net/mod.rs:131-153`).
///
/// Upstream's rule, kept: an interface qualifies when it is UP and RUNNING and
/// `IFF_MULTICAST`, and it contributes its FIRST IPv4 address (`net/mod.rs:137
/// -142`). One address per interface, not all of them — these are the addresses
/// a node holds a scouting socket on, and a second socket on the same NIC would
/// answer no asker the first could not.
///
/// Loopback is not named in the filter and does not need to be: on Linux `lo`
/// carries `LOOPBACK,UP,LOWER_UP` and no `MULTICAST`, so the flag test already
/// excludes it. Naming it separately would be a second rule with no subject.
///
/// The divergences are [`unicast_addresses_of_interface`]'s, for the same two
/// reasons: this resolves LIVE per call rather than out of upstream's
/// process-lifetime `lazy_static` snapshot, and it distinguishes "resolved, and
/// no interface qualifies" (`Some(vec![])`) from "the resolution could not run"
/// (`None`), where upstream returns an empty vec for both.
#[cfg(unix)]
pub fn multicast_interface_addresses() -> Option<Vec<IpAddr>> {
    use std::ffi::CStr;

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: as in `interface_names_for` — `getifaddrs` allocates the list and
    // writes its head through the out-pointer, returning 0 on success; on failure
    // `head` is untouched and the early return never reads it.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }

    // Interface names already answered, so the FIRST v4 address of each wins and
    // a NIC with several contributes one — upstream's `return` out of its own
    // per-interface loop.
    let mut taken: Vec<String> = Vec::new();
    let mut addrs: Vec<IpAddr> = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is non-null and points at a node the successful
        // `getifaddrs` above allocated; the list is not mutated while walked.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;

        if ifa.ifa_name.is_null() {
            continue;
        }
        let flags = ifa.ifa_flags as i32;
        if flags & libc::IFF_UP == 0
            || flags & libc::IFF_RUNNING == 0
            || flags & libc::IFF_MULTICAST == 0
        {
            continue;
        }
        // SAFETY: `ifa_name` is a NUL-terminated C string owned by the list.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        if taken.contains(&name) {
            continue;
        }
        match sockaddr_ip(ifa.ifa_addr) {
            Some(ip @ IpAddr::V4(_)) if !ip.is_multicast() => {
                taken.push(name);
                addrs.push(ip);
            }
            _ => continue,
        }
    }

    // SAFETY: `head` came from the successful `getifaddrs` above and is freed
    // exactly once here; no node pointer outlives this call (the names and
    // addresses are copied out by value).
    unsafe { libc::freeifaddrs(head) };
    Some(addrs)
}

/// Non-unix: no `getifaddrs`, so this cannot answer. `None` (could not
/// determine) rather than `Some(vec![])`, which would claim this host has no
/// multicast interface at all.
///
/// Upstream answers `vec![Ipv4Addr::UNSPECIFIED]` on windows and lets the system
/// choose (`net/mod.rs:148-152`). That is deliberately NOT mirrored: the wildcard
/// is not an address a reply can be ELECTED by, so handing it to the scouting
/// responder's reply-source election (`best_reply_source` in session-core) as a
/// candidate would score every asker at zero and make the choice the caller
/// thought it was making.
#[cfg(not(unix))]
pub fn multicast_interface_addresses() -> Option<Vec<IpAddr>> {
    None
}

/// R2859 — EVERY unicast address, of either family, of every interface that can
/// carry multicast: the wz counterpart of zenoh's
/// `get_unicast_addresses_of_multicast_interfaces`
/// (`commons/zenoh-util/src/net/mod.rs` @ `pub fn get_unicast_addresses_of_multicast_interfaces() -> Vec<IpAddr> {`).
///
/// NOT [`multicast_interface_addresses`], though the names are close and so are
/// upstream's: that one keeps the first IPv4 address per interface, for the
/// scouting sockets, while this one is what upstream's UDP multicast link reads
/// to fill an unspecified local address, filtering by the group's family and
/// loopback itself and taking the first
/// (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @ `zenoh_util::net::get_unicast_addresses_of_multicast_interfaces()`).
/// Order is `getifaddrs`' order, which is the order upstream's interface table
/// is built in.
///
/// The qualifying rule is upstream's: UP, RUNNING and `IFF_MULTICAST`, and a
/// multicast address is not a unicast one. The divergences are
/// [`unicast_addresses_of_interface`]'s: resolved live per call, and `None` when
/// the resolution could not run where upstream answers an empty vec.
#[cfg(unix)]
pub fn unicast_addresses_of_multicast_interfaces() -> Option<Vec<IpAddr>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: as in `interface_names_for` — `getifaddrs` allocates the list and
    // writes its head through the out-pointer, returning 0 on success; on failure
    // `head` is untouched and the early return never reads it.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }

    let mut addrs: Vec<IpAddr> = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is non-null and points at a node the successful
        // `getifaddrs` above allocated; the list is not mutated while walked.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;

        let flags = ifa.ifa_flags as i32;
        if flags & libc::IFF_UP == 0
            || flags & libc::IFF_RUNNING == 0
            || flags & libc::IFF_MULTICAST == 0
        {
            continue;
        }
        if let Some(ip) = sockaddr_ip(ifa.ifa_addr) {
            if !ip.is_multicast() && !addrs.contains(&ip) {
                addrs.push(ip);
            }
        }
    }

    // SAFETY: `head` came from the successful `getifaddrs` above and is freed
    // exactly once here; no node pointer outlives this call (the addresses are
    // copied out by value).
    unsafe { libc::freeifaddrs(head) };
    Some(addrs)
}

/// Non-unix: no `getifaddrs`, so this cannot answer. `None`, which leaves the
/// caller on the wildcard, and that is the answer upstream reaches on windows
/// by returning an empty vec.
#[cfg(not(unix))]
pub fn unicast_addresses_of_multicast_interfaces() -> Option<Vec<IpAddr>> {
    None
}

/// R3071 -- EVERY address of every interface that is UP and RUNNING, loopback included, in
/// `getifaddrs`' order: zenoh's `get_local_addresses(None)`
/// (`commons/zenoh-util/src/net/mod.rs` @ `pub fn get_local_addresses(interface: Option<&str>) -> ZResult<Vec<IpAddr>> {`).
///
/// What an UNSPECIFIED listener stands for: a node bound to `0.0.0.0` or `[::]` tells a scouter
/// the addresses of the host it is bound on, not the wildcard
/// ([`expand_unspecified`] orders them). NOT [`unicast_addresses_of_multicast_interfaces`], which
/// keeps only the interfaces that can carry multicast and so never names loopback; the two agree
/// on a host whose only other interface is a NIC, and differ on one with a point-to-point or
/// tunnel interface that carries no multicast.
///
/// The divergences are [`unicast_addresses_of_interface`]'s: resolved live per call, and `None`
/// when the resolution could not run where upstream answers an empty vec.
#[cfg(unix)]
pub fn local_addresses() -> Option<Vec<IpAddr>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: as in `interface_names_for` -- `getifaddrs` allocates the list and writes its head
    // through the out-pointer, returning 0 on success; on failure `head` is untouched and the
    // early return never reads it.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }

    let mut addrs: Vec<IpAddr> = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is non-null and points at a node the successful `getifaddrs` above
        // allocated; the list is not mutated while walked.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;

        let flags = ifa.ifa_flags as i32;
        if flags & libc::IFF_UP == 0 || flags & libc::IFF_RUNNING == 0 {
            continue;
        }
        if let Some(ip) = sockaddr_ip(ifa.ifa_addr) {
            addrs.push(ip);
        }
    }

    // SAFETY: `head` came from the successful `getifaddrs` above and is freed exactly once here;
    // no node pointer outlives this call (the addresses are copied out by value).
    unsafe { libc::freeifaddrs(head) };
    Some(addrs)
}

/// Windows (R3140): every unicast address of every adapter, of either family, in the adapter
/// table's order -- upstream's `get_local_addresses(None)` there. Unlike the unix reading it does not
/// ask whether an adapter is up or running, because the Windows reading never has. `None` when the
/// table could not be read, which a caller reads as "could not determine" and not as a host with
/// no address.
#[cfg(windows)]
pub fn local_addresses() -> Option<Vec<IpAddr>> {
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;
    Some(adapter_local_addresses(
        &read_adapter_rows(u32::from(AF_UNSPEC))?,
        None,
    ))
}

/// Neither `getifaddrs` nor the Windows adapter table, so this cannot answer. `None`, which a
/// caller reads as "could not determine" and not as a host with no address.
#[cfg(not(any(unix, windows)))]
pub fn local_addresses() -> Option<Vec<IpAddr>> {
    None
}

/// R3071 -- the socket addresses an UNSPECIFIED listener stands for on a host whose addresses are
/// `local`, in the order zenoh lists them, with or without the loopback ones.
///
/// Pure, so the order is testable on a host that has one interface. The rule is zenoh's
/// (`commons/zenoh-util/src/net/mod.rs` @ `pub fn get_ipv4_ipaddrs(interface: Option<&str>, noloopback: bool) -> Vec<IpAddr> {`
/// for a `0.0.0.0` bind and
/// `commons/zenoh-util/src/net/mod.rs` @ `pub fn get_ipv6_ipaddrs(interface: Option<&str>, noloopback: bool) -> Vec<IpAddr> {`
/// for a `[::]` bind), MEASURED against the real library before it was written down: a peer
/// bound to `[::]` told a scouter its global IPv6 address, then its public IPv4 one, then its
/// link-local IPv6 ones, then its private IPv4 one, and nothing else.
///
/// - `0.0.0.0` stands for the host's IPv4 addresses, in the order given, none of them multicast.
/// - `[::]` stands for BOTH families, ordered global IPv6, public IPv4, link-local IPv6, private
///   IPv4; an IPv4 address that is link-local, multicast or broadcast is not offered.
///
/// A bound address that is not unspecified is not expanded and stands for itself.
pub fn expand_unspecified(
    bound: SocketAddr,
    local: &[IpAddr],
    exclude_loopback: bool,
) -> Vec<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    if !bound.ip().is_unspecified() {
        return vec![bound];
    }
    let port = bound.port();
    let v4 = |keep: &dyn Fn(&Ipv4Addr) -> bool| -> Vec<Ipv4Addr> {
        local
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(a) if !(exclude_loopback && a.is_loopback()) && keep(a) => Some(*a),
                _ => None,
            })
            .collect()
    };
    let v6 = |keep: &dyn Fn(&Ipv6Addr) -> bool| -> Vec<Ipv6Addr> {
        local
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V6(a) if !(exclude_loopback && a.is_loopback()) && keep(a) => Some(*a),
                _ => None,
            })
            .collect()
    };
    let link_local = |a: &Ipv6Addr| (a.segments()[0] & 0xffc0) == 0xfe80;

    let ips: Vec<IpAddr> = if bound.is_ipv4() {
        v4(&|a| !a.is_multicast())
            .into_iter()
            .map(IpAddr::V4)
            .collect()
    } else {
        let usable_v4 = |a: &Ipv4Addr| !a.is_link_local() && !a.is_multicast() && !a.is_broadcast();
        v6(&|a| !a.is_multicast() && !link_local(a))
            .into_iter()
            .map(IpAddr::V6)
            .chain(
                v4(&|a| usable_v4(a) && !a.is_private())
                    .into_iter()
                    .map(IpAddr::V4),
            )
            .chain(
                v6(&|a| !a.is_multicast() && link_local(a))
                    .into_iter()
                    .map(IpAddr::V6),
            )
            .chain(
                v4(&|a| usable_v4(a) && a.is_private())
                    .into_iter()
                    .map(IpAddr::V4),
            )
            .collect()
    };
    ips.into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect()
}

/// R2584 — the kernel index of the interface named `name`.
///
/// IPv6 multicast selects an interface by INDEX where IPv4 selects it by address:
/// `IPV6_MULTICAST_IF` and the `ipv6mr_interface` field of `IPV6_ADD_MEMBERSHIP`
/// both take a `u32`. So a v6 `#iface=` needs a resolution the v4 honor never did.
///
/// A name that `if_nametoindex` does not know is [`IfaceResolveError::NotFound`],
/// which also covers an interface removed between an earlier table walk and this
/// call.
#[cfg(unix)]
pub fn interface_index_of_name(name: &str) -> Result<u32, IfaceResolveError> {
    // An interior NUL cannot name a device, so it is absent rather than undetermined.
    let c = std::ffi::CString::new(name).map_err(|_| IfaceResolveError::NotFound)?;
    // SAFETY: `c` is a NUL-terminated C string that outlives the call, and
    // `if_nametoindex` only reads it. It returns 0 when no interface has that name.
    match unsafe { libc::if_nametoindex(c.as_ptr()) } {
        0 => Err(IfaceResolveError::NotFound),
        index => Ok(index),
    }
}

/// Non-unix: no `if_nametoindex` here, so the index is undetermined.
#[cfg(not(unix))]
pub fn interface_index_of_name(_name: &str) -> Result<u32, IfaceResolveError> {
    Err(IfaceResolveError::Undetermined)
}

/// R2584 — the indices of every interface that CARRIES `addr` as one of its own
/// addresses: the wz counterpart of zenoh's `get_index_of_interface`
/// (`commons/zenoh-util/src/net/mod.rs` @ `pub fn get_index_of_interface(addr: IpAddr) -> ZResult<u32> {`).
///
/// Built on [`interface_names_for`], which already answers "which interfaces
/// carry this address", so the table walk stays in one place.
///
/// It returns EVERY carrier where upstream returns the first. Address uniqueness
/// is not a kernel guarantee: a link-local `fe80::` address may sit on more than
/// one interface. Which of them was first in upstream's interface snapshot is not
/// something a config author can see, so the caller decides what several carriers
/// mean (see [`multicast_iface_selector_v6`]).
///
/// The unspecified address is carried by NO interface here. [`interface_names_for`]
/// maps it to every interface because a socket bound to the wildcard is on all of
/// them, but no interface holds `::` as an address, so upstream's lookup finds none
/// either.
#[cfg(unix)]
pub fn interface_indices_of_address(addr: IpAddr) -> Result<Vec<u32>, IfaceResolveError> {
    if addr.is_unspecified() {
        return Ok(Vec::new());
    }
    let names = interface_names_for(addr).ok_or(IfaceResolveError::Undetermined)?;
    let mut indices = Vec::with_capacity(names.len());
    for name in names {
        match interface_index_of_name(&name) {
            Ok(index) if !indices.contains(&index) => indices.push(index),
            Ok(_) => {}
            // The interface disappeared between the walk and the index lookup, so
            // it no longer carries the address.
            Err(IfaceResolveError::NotFound) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(indices)
}

/// Windows (R3140): the `Ipv6IfIndex` of every adapter that carries `addr`, read from the IPv4
/// adapter table as upstream's `get_index_of_interface` reads it there. A table that cannot be read
/// is undetermined, not "no carrier".
#[cfg(windows)]
pub fn interface_indices_of_address(addr: IpAddr) -> Result<Vec<u32>, IfaceResolveError> {
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    let rows = read_adapter_rows(u32::from(AF_INET)).ok_or(IfaceResolveError::Undetermined)?;
    Ok(adapter_indices_of(&rows, addr))
}

/// Neither `getifaddrs` nor the Windows adapter table, so no carrier can be named.
#[cfg(not(any(unix, windows)))]
pub fn interface_indices_of_address(_addr: IpAddr) -> Result<Vec<u32>, IfaceResolveError> {
    Err(IfaceResolveError::Undetermined)
}

/// R2584 — the one interface index an IPv6 address literal selects, or why it
/// selects none.
///
/// Kept apart from the table walk so that each case can be tested without a
/// host that has that shape. A host with one address on two interfaces is rare,
/// but that case is exactly where upstream and wz differ.
#[cfg(feature = "locator-iface")]
fn the_one_carrier(iface: &str, carriers: &[u32]) -> std::io::Result<u32> {
    match carriers {
        [index] => Ok(*index),
        // Upstream's own refusal: `bail!("No interface found with address {addr}")`.
        [] => Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!(
                "wz: locator #iface={iface} is an address no local interface carries, \
                 so it cannot select a v6 multicast interface"
            ),
        )),
        // Divergence from upstream, which takes the first carrier in its interface
        // snapshot. That order is invisible to whoever wrote the config, so taking
        // it would pin a NIC the config never chose. The v4 selector refuses a
        // substituted interface for the same reason.
        several => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "wz: locator #iface={iface} is carried by {} interfaces (indices \
                 {several:?}), so it does not name one; give the interface name instead",
                several.len()
            ),
        )),
    }
}

/// R2584 — the `#iface=` value of a v6 MULTICAST locator, resolved to the
/// interface INDEX that `IPV6_MULTICAST_IF` (egress) and `ipv6mr_interface`
/// (join) both take.
///
/// Same contract as [`multicast_iface_selector_v4`]: `Ok(Some(index))` pin to
/// that interface, `Ok(None)` do not pin (warning already logged), `Err` refuse to
/// bind.
///
/// # Upstream's chain, and where wz stops following it
///
/// zenoh resolves a v6 `iface` in two steps
/// (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @ `IpAddr::V6(_) => match zenoh_util::net::get_index_of_interface(local_addr.ip()) {`):
/// first to an ADDRESS, either the literal or the named interface's first v6
/// address, and then to the index of the interface carrying that address.
///
/// - An address literal follows that chain exactly: its carrier's index, and a
///   refusal when nothing carries it. The one difference is an address carried
///   by several interfaces; see `the_one_carrier`.
/// - A NAME takes that interface's own index, once the interface is shown to be
///   up, running and carrying a v6 address. Going through its first address
///   instead, as upstream does, can land on a DIFFERENT interface when that
///   address is also on another one.
/// - A name whose interface carries no v6 address is refused. Upstream quietly
///   uses the first non-loopback multicast interface instead, and wz's v4
///   selector already refuses that substitution for the same reason.
/// - An IPv4 literal is refused because the families differ. Upstream fails too:
///   it calls `set_multicast_if_v4` on an IPv6 socket.
#[cfg(feature = "locator-iface")]
pub fn multicast_iface_selector_v6(iface: &str) -> std::io::Result<Option<u32>> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    if iface.parse::<Ipv4Addr>().is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "wz: locator #iface={iface} is an IPv4 address and cannot select the \
                 interface of an IPv6 multicast group (the protocols must match)"
            ),
        ));
    }
    let undetermined = || {
        log::warn!(
            "wz: locator #iface={iface} ignored for multicast \
             (interface resolution unavailable on this platform)"
        );
        Ok(None)
    };
    if let Ok(addr) = iface.parse::<Ipv6Addr>() {
        return match interface_indices_of_address(IpAddr::V6(addr)) {
            Ok(carriers) => the_one_carrier(iface, &carriers).map(Some),
            Err(IfaceResolveError::Undetermined) => undetermined(),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("wz: locator #iface={iface} is {e}; refusing to bind the multicast socket"),
            )),
        };
    }
    match unicast_addresses_of_interface(iface) {
        Ok(addrs) if addrs.iter().any(IpAddr::is_ipv6) => match interface_index_of_name(iface) {
            Ok(index) => Ok(Some(index)),
            Err(IfaceResolveError::Undetermined) => undetermined(),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("wz: locator #iface={iface} is {e}; refusing to bind the multicast socket"),
            )),
        },
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!(
                "wz: locator #iface={iface} is up but carries no IPv6 address, so it \
                 cannot select a v6 multicast interface (zenoh would silently \
                 substitute another non-loopback interface; wz refuses rather than \
                 pin a NIC the config did not name)"
            ),
        )),
        Err(IfaceResolveError::Undetermined) => undetermined(),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("wz: locator #iface={iface} is {e}; refusing to bind the multicast socket"),
        )),
    }
}

/// The build without `locator-iface` compiles the v6 honor out as it does the v4
/// one: warn, and leave the socket on the kernel's default interface, as
/// [`multicast_iface_selector_v4`]'s twin does.
#[cfg(not(feature = "locator-iface"))]
pub fn multicast_iface_selector_v6(iface: &str) -> std::io::Result<Option<u32>> {
    log::warn!(
        "wz: locator #iface={iface} ignored for multicast \
         (build without the locator-iface feature)"
    );
    Ok(None)
}

/// R311y454 — the `#iface=` value of a v4 MULTICAST locator, resolved to the
/// interface-selector address that `IP_MULTICAST_IF` (egress) and the
/// `imr_interface` field of `IP_ADD_MEMBERSHIP` (join) both take.
///
/// `Ok(Some(addr))` pin to `addr`; `Ok(None)` do not pin, a warning already
/// logged; `Err` refuse to bind.
///
/// # The same key, two mechanisms
///
/// zenoh spells BOTH honors `iface` — `BIND_INTERFACE` for unicast
/// (`io/zenoh-link-commons/src/lib.rs:52`) and `UDP_MULTICAST_IFACE` for udp
/// multicast (`io/zenoh-links/zenoh-link-udp/src/lib.rs:109`) are the SAME string.
/// They are not the same mechanism: unicast binds the socket to a DEVICE
/// (`SO_BINDTODEVICE`, see `crate::iface_bind`), multicast selects an interface by
/// one of its ADDRESSES. wz keeps them separate for that reason, and deliberately
/// does NOT call `SO_BINDTODEVICE` on a multicast socket — upstream never does
/// (no `bind_device` anywhere in `zenoh-link-udp/src/multicast.rs`), and mixing
/// the two would be invented behaviour rather than a reimplementation.
///
/// # Accepting an address as well as a name
///
/// An `#iface=` value that parses as an IPv4 address is used directly, before any
/// interface lookup — zenoh's first arm (`multicast.rs:228-230`). So
/// `#iface=127.0.0.1` and `#iface=lo` reach the same selector by different routes.
///
/// # The one divergence from upstream, and its exact boundary
///
/// For a name that does not resolve — absent, down, or no carrier — this is a
/// HARD ERROR, and so is upstream: `get_unicast_addresses_of_interface` `bail!`s
/// on all three (`commons/zenoh-util/src/net/mod.rs:233-247`) and
/// `zenoh-link-udp` propagates with `?` (`multicast.rs:229`). No divergence there.
///
/// The divergence is one case only: the interface resolves, is up and running,
/// but carries no IPv4 address. zenoh then silently pins egress to the FIRST
/// non-loopback multicast interface it finds instead (`multicast.rs:243-259`),
/// which is a different NIC from the one the deploy named. wz refuses. A config
/// that asked to pin one interface and silently got another is worse than a
/// listener that does not start.
#[cfg(feature = "locator-iface")]
pub fn multicast_iface_selector_v4(iface: &str) -> std::io::Result<Option<std::net::Ipv4Addr>> {
    use std::net::Ipv4Addr;

    // Upstream's first arm: an address literal needs no interface table.
    if let Ok(addr) = iface.parse::<Ipv4Addr>() {
        return Ok(Some(addr));
    }
    // R2584 — an IPv6 literal was looked up as an interface NAME and refused as
    // "not found", which named the wrong fault. The fault is the family: upstream
    // parses it as an address and then fails on the v4 socket. Say so.
    if iface.parse::<std::net::Ipv6Addr>().is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "wz: locator #iface={iface} is an IPv6 address and cannot select the \
                 interface of an IPv4 multicast group (the protocols must match)"
            ),
        ));
    }
    match unicast_addresses_of_interface(iface) {
        Ok(addrs) => match addrs.iter().find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        }) {
            Some(v4) => Ok(Some(v4)),
            // The named divergence. Upstream substitutes another interface here.
            None => Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!(
                    "wz: locator #iface={iface} is up but carries no IPv4 address, so it \
                     cannot select a v4 multicast interface (zenoh would silently \
                     substitute another non-loopback interface; wz refuses rather than \
                     pin a NIC the config did not name)"
                ),
            )),
        },
        // `getifaddrs` could not run at all: warn and leave the socket unpinned,
        // the same posture the off-platform arm of `bind_socket_to_device` takes.
        // Failing here would make one locator reject a multicast bind on a
        // platform where it merely warns on tcp.
        Err(IfaceResolveError::Undetermined) => {
            log::warn!(
                "wz: locator #iface={iface} ignored for multicast \
                 (interface resolution unavailable on this platform)"
            );
            Ok(None)
        }
        // The three upstream hard-error arms.
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("wz: locator #iface={iface} is {e}; refusing to bind the multicast socket"),
        )),
    }
}

/// Without the `locator-iface` feature the multicast honor is compiled out, matching
/// the third arm of `bind_socket_to_device` (`crate::iface_bind`): warn, so a
/// configured-but-unhonoured `#iface=` is never silent, and leave the socket on
/// the kernel's default interface.
#[cfg(not(feature = "locator-iface"))]
pub fn multicast_iface_selector_v4(iface: &str) -> std::io::Result<Option<std::net::Ipv4Addr>> {
    log::warn!(
        "wz: locator #iface={iface} ignored for multicast \
         (build without the locator-iface feature)"
    );
    Ok(None)
}

// Gated on `unix`, not just `test`: EVERY test of this module is `#[cfg(unix)]` (they all need
// a POSIX interface table), so on Windows the module would compile to a `use super::*` with no
// consumer and the lib-test build would fail `-D warnings` with `unused import`.
#[cfg(all(test, unix))]
mod tests;

// R3071 -- the order an unspecified listener's locators are listed in.
#[cfg(test)]
mod expansion;

// R3140 -- the Windows adapter table's questions, told on tables made for them.
#[cfg(test)]
mod adapter_table_reading;

// R3138 -- how `scouting/multicast/interface` is read, told on tables made for it.
#[cfg(test)]
mod scouting_interface_reading;
