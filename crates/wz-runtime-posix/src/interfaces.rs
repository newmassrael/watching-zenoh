// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host's interface table, read without `std`: the interfaces a node can join a group on, send
//! a Scout from or name in a locator's `#iface=`.
//!
//! On a POSIX host the table is `getifaddrs`' list, read once per question into an
//! [`InterfaceTable`] (one row per address an interface holds, with its name, index and flags), and
//! each question is a function of that table, so that what it decides is told on tables made for
//! it as well as on the host's. The table is read live each time: an interface that comes up after
//! the process started is in the next answer, where upstream answers from a snapshot taken at its
//! first lookup. The C library takes the list from its own heap and is given it back before the
//! reading returns.
//!
//! The rules are those of the tokio runtime's host crate (`wz-host-net`'s `link_interfaces`),
//! which reads the same table for the same questions: an interface that can carry multicast is up,
//! running and `IFF_MULTICAST`; a multicast address is never an interface's own; "could not be
//! read" is an answer of its own ([`IfaceResolveError::Undetermined`], `None`) and never an empty
//! table.
//!
//! On Windows the one question a multicast socket asks of the system is which adapter carries an
//! address, read from the adapter table (`GetAdaptersAddresses`) as upstream reads it there; the
//! others answer that they could not be read, which leaves a socket on the system's own choice of
//! interface, as the host crate answers them there.

use alloc::vec::Vec;
use core::fmt;
use core::net::IpAddr;

#[cfg(unix)]
use alloc::string::String;

/// Why an interface named in a locator could not be resolved to a usable address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfaceResolveError {
    /// No interface by that name.
    NotFound,
    /// The interface is not up: pinning a group to it would leave the group silent.
    NotUp,
    /// The interface is up but has no carrier.
    NotRunning,
    /// The table could not be read, or the platform has none to read: nothing is known of the
    /// interface, and the caller decides.
    Undetermined,
}

impl fmt::Display for IfaceResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotFound => "not found",
            Self::NotUp => "not up",
            Self::NotRunning => "not running (no carrier)",
            Self::Undetermined => "could not be resolved on this platform",
        })
    }
}

/// One row of the table: one address an interface holds, or none for an entry of the interface
/// that carries no IP address (the link-layer entry a POSIX table lists for every interface).
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceRow {
    /// The interface's name.
    pub name: String,
    /// The interface's index, 0 when the system named none.
    pub index: u32,
    /// `IFF_UP`.
    pub up: bool,
    /// `IFF_RUNNING`: the interface has a carrier.
    pub running: bool,
    /// `IFF_MULTICAST`.
    pub multicast: bool,
    /// The IP address of this row, `None` for a row of another family.
    pub address: Option<IpAddr>,
}

/// The host's interfaces as the table lists them, in the table's order.
#[cfg(unix)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InterfaceTable {
    rows: Vec<InterfaceRow>,
}

#[cfg(unix)]
impl InterfaceTable {
    /// A table of `rows`, in the order given.
    pub fn from_rows(rows: Vec<InterfaceRow>) -> Self {
        Self { rows }
    }

    /// The host's table now, or `None` when `getifaddrs` could not read it.
    pub fn read() -> Option<Self> {
        let mut head: *mut libc::ifaddrs = core::ptr::null_mut();
        // SAFETY: `getifaddrs` writes the head of a list it allocates through the out-pointer and
        // returns 0 on success; on failure `head` is not read.
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return None;
        }
        let mut rows: Vec<InterfaceRow> = Vec::new();
        let mut cur = head;
        while !cur.is_null() {
            // SAFETY: `cur` is a node of the list the successful call above returned, live until
            // `freeifaddrs`, and the list is not changed while it is walked.
            let ifa = unsafe { &*cur };
            cur = ifa.ifa_next;
            if ifa.ifa_name.is_null() {
                continue;
            }
            // SAFETY: a non-null `ifa_name` is the interface's NUL-terminated name, owned by the
            // list.
            let name_bytes = unsafe { core::ffi::CStr::from_ptr(ifa.ifa_name) }.to_bytes();
            let name = String::from_utf8_lossy(name_bytes).into_owned();
            // The table lists an interface once for each address it holds: its index is asked of
            // the system once.
            let index = match rows.iter().find(|row| row.name == name) {
                Some(row) => row.index,
                // SAFETY: `ifa_name` is NUL-terminated and live for the call, which only reads it.
                None => unsafe { libc::if_nametoindex(ifa.ifa_name) },
            };
            let flags = ifa.ifa_flags as libc::c_int;
            rows.push(InterfaceRow {
                name,
                index,
                up: flags & libc::IFF_UP != 0,
                running: flags & libc::IFF_RUNNING != 0,
                multicast: flags & libc::IFF_MULTICAST != 0,
                address: sockaddr_ip(ifa.ifa_addr),
            });
        }
        // SAFETY: `head` is the list the successful call above returned, freed once; every row
        // holds copies of what it read.
        unsafe { libc::freeifaddrs(head) };
        Some(Self { rows })
    }

    /// Whether `row` is of an interface that can carry multicast: up, running and multicast.
    fn carries_multicast(row: &InterfaceRow) -> bool {
        row.up && row.running && row.multicast
    }

    /// The first IPv4 address of every interface that can carry multicast, one for each interface,
    /// in the table's order: the addresses a scouting window asks by. A second socket on the same
    /// interface would reach no node the first does not, and a loopback has no `IFF_MULTICAST` on
    /// the hosts this crate is built for, so the flag test leaves it out.
    pub fn multicast_interface_addresses(&self) -> Vec<IpAddr> {
        let mut taken: Vec<&str> = Vec::new();
        let mut addresses = Vec::new();
        for row in &self.rows {
            if !Self::carries_multicast(row) || taken.contains(&row.name.as_str()) {
                continue;
            }
            if let Some(address @ IpAddr::V4(_)) = row.address {
                if !address.is_multicast() {
                    taken.push(&row.name);
                    addresses.push(address);
                }
            }
        }
        addresses
    }

    /// Every unicast address, of either family, of every interface that can carry multicast, once
    /// each and in the table's order: what an unpinned multicast link takes its interface and its
    /// source address from, as upstream's link reads
    /// `get_unicast_addresses_of_multicast_interfaces`.
    pub fn unicast_addresses_of_multicast_interfaces(&self) -> Vec<IpAddr> {
        let mut addresses = Vec::new();
        for row in self.rows.iter().filter(|row| Self::carries_multicast(row)) {
            if let Some(address) = row.address {
                if !address.is_multicast() && !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
        }
        addresses
    }

    /// The unicast addresses of the interface named `name`, once each and in the table's order, or
    /// why there are none to give: an interface that is absent, down or without a carrier is
    /// refused in that order, as upstream refuses it; one that is up and running and holds no
    /// address is an empty list, which the caller judges for the family it needs.
    pub fn unicast_addresses_of_interface(
        &self,
        name: &str,
    ) -> Result<Vec<IpAddr>, IfaceResolveError> {
        let mut found = false;
        let mut up = false;
        let mut running = false;
        let mut addresses = Vec::new();
        for row in self.rows.iter().filter(|row| row.name == name) {
            found = true;
            up |= row.up;
            running |= row.running;
            if let Some(address) = row.address {
                if !address.is_multicast() && !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
        }
        if !found {
            return Err(IfaceResolveError::NotFound);
        }
        if !up {
            return Err(IfaceResolveError::NotUp);
        }
        if !running {
            return Err(IfaceResolveError::NotRunning);
        }
        Ok(addresses)
    }

    /// The index of every interface that holds `address`, once each and in the table's order. An
    /// address may sit on several interfaces (a link-local one does), so every carrier is given and
    /// the caller says what several mean. An IPv4 address an IPv6 socket reports in its mapped form
    /// is the IPv4 address; the unspecified address is held by no interface.
    pub fn indices_of_address(&self, address: IpAddr) -> Vec<u32> {
        if address.is_unspecified() {
            return Vec::new();
        }
        let address = address.to_canonical();
        let mut indices = Vec::new();
        for row in &self.rows {
            if row.address == Some(address) && row.index != 0 && !indices.contains(&row.index) {
                indices.push(row.index);
            }
        }
        indices
    }
}

/// The IP address a `sockaddr` of the table carries, or `None` for a null pointer or a family
/// other than the two (the link-layer entries the table also lists).
#[cfg(unix)]
fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: `sa` is non-null and points at a socket address the list owns; the family is the
    // first field of every form, and the read is unaligned because the list may pack a wider form
    // behind a pointer typed as the narrow one.
    let family = c_int_of(unsafe { core::ptr::read_unaligned(sa) }.sa_family);
    match family {
        libc::AF_INET => {
            // SAFETY: the family says the address is a `sockaddr_in`.
            let v4 = unsafe { core::ptr::read_unaligned(sa.cast::<libc::sockaddr_in>()) };
            Some(IpAddr::from(v4.sin_addr.s_addr.to_ne_bytes()))
        }
        libc::AF_INET6 => {
            // SAFETY: the family says the address is a `sockaddr_in6`.
            let v6 = unsafe { core::ptr::read_unaligned(sa.cast::<libc::sockaddr_in6>()) };
            Some(IpAddr::from(v6.sin6_addr.s6_addr))
        }
        _ => None,
    }
}

/// The family field of a socket address as the kernel's family numbers are typed.
#[cfg(unix)]
fn c_int_of(family: libc::sa_family_t) -> libc::c_int {
    libc::c_int::from(family)
}

/// The first IPv4 address of every interface that can carry multicast, read from the host's table
/// now; `None` when it could not be read. See [`InterfaceTable::multicast_interface_addresses`].
#[cfg(unix)]
pub fn multicast_interface_addresses() -> Option<Vec<IpAddr>> {
    Some(InterfaceTable::read()?.multicast_interface_addresses())
}

/// Every unicast address of every interface that can carry multicast, read now; `None` when the
/// table could not be read. See [`InterfaceTable::unicast_addresses_of_multicast_interfaces`].
#[cfg(unix)]
pub fn unicast_addresses_of_multicast_interfaces() -> Option<Vec<IpAddr>> {
    Some(InterfaceTable::read()?.unicast_addresses_of_multicast_interfaces())
}

/// The unicast addresses of the interface named `name`, read now. See
/// [`InterfaceTable::unicast_addresses_of_interface`].
#[cfg(unix)]
pub fn unicast_addresses_of_interface(name: &str) -> Result<Vec<IpAddr>, IfaceResolveError> {
    InterfaceTable::read()
        .ok_or(IfaceResolveError::Undetermined)?
        .unicast_addresses_of_interface(name)
}

/// The system's index of the interface named `name`: what an IPv6 group is joined on and sent out
/// of, where an IPv4 one names an address. A name the system does not know, or one with a NUL in
/// it, which can name no interface, is [`IfaceResolveError::NotFound`].
#[cfg(unix)]
pub fn interface_index_of_name(name: &str) -> Result<u32, IfaceResolveError> {
    let name = alloc::ffi::CString::new(name).map_err(|_| IfaceResolveError::NotFound)?;
    // SAFETY: `name` is NUL-terminated and outlives the call, which only reads it; 0 is the
    // answer for a name no interface has.
    match unsafe { libc::if_nametoindex(name.as_ptr()) } {
        0 => Err(IfaceResolveError::NotFound),
        index => Ok(index),
    }
}

/// The index of every interface that holds `address`, read now. See
/// [`InterfaceTable::indices_of_address`].
#[cfg(unix)]
pub fn interface_indices_of_address(address: IpAddr) -> Result<Vec<u32>, IfaceResolveError> {
    if address.is_unspecified() {
        return Ok(Vec::new());
    }
    Ok(InterfaceTable::read()
        .ok_or(IfaceResolveError::Undetermined)?
        .indices_of_address(address))
}

/// Windows lists no interface by flags here: a scouting window asks on its group socket alone, as
/// the host crate's reading answers there.
#[cfg(windows)]
pub fn multicast_interface_addresses() -> Option<Vec<IpAddr>> {
    None
}

/// See the Windows form of [`multicast_interface_addresses`]: an unpinned link stays on the
/// system's choice of interface.
#[cfg(windows)]
pub fn unicast_addresses_of_multicast_interfaces() -> Option<Vec<IpAddr>> {
    None
}

/// See the Windows form of [`multicast_interface_addresses`]: a name is not resolved, and a
/// locator that names one is left on the system's choice with a warning.
#[cfg(windows)]
pub fn unicast_addresses_of_interface(name: &str) -> Result<Vec<IpAddr>, IfaceResolveError> {
    let _ = name;
    Err(IfaceResolveError::Undetermined)
}

/// See [`unicast_addresses_of_interface`]'s Windows form.
#[cfg(windows)]
pub fn interface_index_of_name(name: &str) -> Result<u32, IfaceResolveError> {
    let _ = name;
    Err(IfaceResolveError::Undetermined)
}

/// The `Ipv6IfIndex` of every adapter that holds `address`, read from the IPv4 adapter table as
/// upstream's `get_index_of_interface` reads it there; a table that cannot be read is
/// undetermined, not "no carrier".
#[cfg(windows)]
pub fn interface_indices_of_address(address: IpAddr) -> Result<Vec<u32>, IfaceResolveError> {
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    let rows = read_adapter_rows(u32::from(AF_INET)).ok_or(IfaceResolveError::Undetermined)?;
    Ok(adapter_indices_of(&rows, address))
}

/// One adapter of the Windows adapter table, as far as a multicast socket asks of it.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct AdapterRow {
    /// `Ipv6IfIndex`, which is the index upstream gives for an IPv4 address too.
    ipv6_if_index: u32,
    /// Every unicast address of the adapter, in the table's order.
    unicast: Vec<IpAddr>,
}

/// The index of every adapter that holds `address`, in the table's order.
#[cfg(any(windows, test))]
fn adapter_indices_of(rows: &[AdapterRow], address: IpAddr) -> Vec<u32> {
    rows.iter()
        .filter(|row| row.unicast.contains(&address))
        .map(|row| row.ipv6_if_index)
        .collect()
}

/// The adapter table of this host for one address family, read with `GetAdaptersAddresses`. The
/// buffer starts at 8192 bytes and is grown up to three times when the call says it is short, as
/// upstream's reading does; any other failure is `None`.
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
    // Eight-byte units, so the buffer is aligned for the structures the call writes into it.
    let mut buffer: Vec<u64>;
    loop {
        buffer = alloc::vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: `buffer` is at least `size` bytes and 8-aligned, `size` is the in/out length the
        // call expects, and the flags and the reserved pointer are the documented defaults.
        let ret = unsafe {
            GetAdaptersAddresses(
                family,
                0,
                core::ptr::null(),
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
        // SAFETY: `cursor` is the head of the list the successful call wrote into `buffer`, or a
        // `Next` it linked; every pointer of the list points into `buffer`, which outlives the
        // loop.
        let adapter = unsafe { &*cursor };
        let mut unicast = Vec::new();
        let mut entry = adapter.FirstUnicastAddress;
        while !entry.is_null() {
            // SAFETY: a `Next` of the list described above.
            let address = unsafe { &*entry };
            if let Some(ip) = windows_sockaddr_ip(address.Address.lpSockaddr) {
                unicast.push(ip);
            }
            entry = address.Next;
        }
        rows.push(AdapterRow {
            ipv6_if_index: adapter.Ipv6IfIndex,
            unicast,
        });
        cursor = adapter.Next;
    }
    Some(rows)
}

/// The IP address a Windows `SOCKADDR` of the adapter table holds, or `None` for another family.
#[cfg(windows)]
fn windows_sockaddr_ip(
    sa: *const windows_sys::Win32::Networking::WinSock::SOCKADDR,
) -> Option<IpAddr> {
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};

    if sa.is_null() {
        return None;
    }
    // SAFETY: a non-null `lpSockaddr` of a unicast entry points at an address of the size its
    // family says; the family is read first and the wider form only when it is the one named.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    /// The Windows adapter table's answer: an address selects the `Ipv6IfIndex` of every adapter
    /// that holds it, for an IPv4 address as for an IPv6 one, and one no adapter holds selects none.
    #[test]
    fn an_address_selects_the_index_of_every_adapter_that_holds_it() {
        let rows = alloc::vec![
            AdapterRow {
                ipv6_if_index: 1,
                unicast: alloc::vec![ip("::1"), ip("127.0.0.1")],
            },
            AdapterRow {
                ipv6_if_index: 12,
                unicast: alloc::vec![ip("fe80::5"), ip("10.0.0.5")],
            },
            AdapterRow {
                ipv6_if_index: 14,
                unicast: alloc::vec![ip("fe80::5")],
            },
        ];
        assert_eq!(adapter_indices_of(&rows, ip("10.0.0.5")), [12]);
        assert_eq!(adapter_indices_of(&rows, ip("::1")), [1]);
        assert_eq!(adapter_indices_of(&rows, ip("fe80::5")), [12, 14]);
        assert!(adapter_indices_of(&rows, ip("192.0.2.1")).is_empty());
    }

    #[cfg(unix)]
    mod posix {
        use super::*;
        use alloc::borrow::ToOwned;
        use core::net::{Ipv4Addr, Ipv6Addr};

        /// One row of a table made for a test.
        fn row(
            name: &str,
            index: u32,
            flags: (bool, bool, bool),
            address: Option<&str>,
        ) -> InterfaceRow {
            InterfaceRow {
                name: name.to_owned(),
                index,
                up: flags.0,
                running: flags.1,
                multicast: flags.2,
                address: address.map(ip),
            }
        }

        const MULTICAST: (bool, bool, bool) = (true, true, true);

        /// A loopback (no multicast flag), an Ethernet interface with an IPv6 address ahead of two
        /// IPv4 ones and a multicast address it has joined, a wireless one, one that is down, one
        /// that is up with no carrier, and one that holds IPv6 alone.
        fn table() -> InterfaceTable {
            InterfaceTable::from_rows(alloc::vec![
                row("lo", 1, (true, true, false), None),
                row("lo", 1, (true, true, false), Some("127.0.0.1")),
                row("lo", 1, (true, true, false), Some("::1")),
                row("eth0", 2, MULTICAST, None),
                row("eth0", 2, MULTICAST, Some("fe80::5")),
                row("eth0", 2, MULTICAST, Some("224.0.0.251")),
                row("eth0", 2, MULTICAST, Some("10.0.0.5")),
                row("eth0", 2, MULTICAST, Some("10.0.0.6")),
                row("wlan0", 3, MULTICAST, Some("192.168.1.9")),
                row("down0", 4, (false, false, true), Some("10.9.0.1")),
                row("nocarrier0", 5, (true, false, true), Some("10.8.0.1")),
                row("v6only", 6, MULTICAST, Some("fd00::6")),
                row("v6only", 6, MULTICAST, Some("fe80::5")),
            ])
        }

        /// A scouting window asks by the first IPv4 address of each interface that is up, running
        /// and can carry multicast: past an IPv6 address and a joined group ahead of it, short of
        /// the second IPv4 one, and nothing from a loopback, a down interface, one with no carrier,
        /// or one that holds no IPv4 address.
        #[test]
        fn a_window_asks_by_the_first_ipv4_of_each_multicast_interface() {
            assert_eq!(
                table().multicast_interface_addresses(),
                [ip("10.0.0.5"), ip("192.168.1.9")]
            );
            assert!(InterfaceTable::default()
                .multicast_interface_addresses()
                .is_empty());
        }

        /// An unpinned link reads every unicast address of either family of the multicast
        /// interfaces, once each, in the table's order; never a group address, never a loopback's.
        #[test]
        fn a_link_reads_every_unicast_address_of_the_multicast_interfaces() {
            assert_eq!(
                table().unicast_addresses_of_multicast_interfaces(),
                [
                    ip("fe80::5"),
                    ip("10.0.0.5"),
                    ip("10.0.0.6"),
                    ip("192.168.1.9"),
                    ip("fd00::6"),
                ]
            );
        }

        /// A named interface answers with its unicast addresses, its joined group left out; one
        /// that is absent, down or without carrier is refused for that, and one that is up and
        /// running and holds no address answers with none.
        #[test]
        fn a_named_interface_answers_with_its_addresses_or_why_not() {
            let table = table();
            assert_eq!(
                table.unicast_addresses_of_interface("eth0"),
                Ok(alloc::vec![ip("fe80::5"), ip("10.0.0.5"), ip("10.0.0.6")])
            );
            assert_eq!(
                table.unicast_addresses_of_interface("nope"),
                Err(IfaceResolveError::NotFound)
            );
            assert_eq!(
                table.unicast_addresses_of_interface("down0"),
                Err(IfaceResolveError::NotUp)
            );
            assert_eq!(
                table.unicast_addresses_of_interface("nocarrier0"),
                Err(IfaceResolveError::NotRunning)
            );
            let bare = InterfaceTable::from_rows(alloc::vec![row("tun0", 9, MULTICAST, None)]);
            assert_eq!(bare.unicast_addresses_of_interface("tun0"), Ok(Vec::new()));
        }

        /// An address selects the index of every interface that holds it, once each; an IPv4
        /// address in its mapped IPv6 form is the IPv4 address; the unspecified address and an
        /// address nobody holds select none.
        #[test]
        fn an_address_selects_the_index_of_every_interface_that_holds_it() {
            let table = table();
            assert_eq!(table.indices_of_address(ip("10.0.0.6")), [2]);
            assert_eq!(table.indices_of_address(ip("fe80::5")), [2, 6]);
            assert_eq!(
                table.indices_of_address(IpAddr::V6(Ipv4Addr::new(10, 0, 0, 5).to_ipv6_mapped())),
                [2]
            );
            assert!(table
                .indices_of_address(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
                .is_empty());
            assert!(table.indices_of_address(ip("192.0.2.1")).is_empty());
        }

        /// The host's own table: whatever it holds, a scouting address is an IPv4 address that is
        /// neither a loopback nor a group. A host in a sandbox may list nothing but its loopback.
        #[test]
        fn the_hosts_table_is_read_and_answers_by_the_same_rules() {
            let table = InterfaceTable::read().expect("getifaddrs reads the host's table");
            for address in table.multicast_interface_addresses() {
                assert!(address.is_ipv4(), "{address}");
                assert!(
                    !address.is_loopback() && !address.is_multicast(),
                    "{address}"
                );
            }
            assert_eq!(
                multicast_interface_addresses(),
                Some(table.multicast_interface_addresses()),
                "the free function reads the same table"
            );
        }

        /// A name no interface has, and one that cannot be a name, find no index.
        #[test]
        fn a_name_no_interface_has_finds_no_index() {
            assert_eq!(
                interface_index_of_name("wz-no-such-interface"),
                Err(IfaceResolveError::NotFound)
            );
            assert_eq!(
                interface_index_of_name("bad\0name"),
                Err(IfaceResolveError::NotFound)
            );
            assert_eq!(
                interface_indices_of_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                Ok(Vec::new())
            );
        }
    }
}
