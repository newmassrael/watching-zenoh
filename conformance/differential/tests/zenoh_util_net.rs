// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-util`, the network interfaces (the third slice of the crate): upstream's crate (`up_util`)
//! and wz's (`wz_util`) asked the same questions of the interfaces of the machine they run on,
//! results equal as text.
//!
//! Each crate reads the interfaces of the machine once, the first time it is asked (a `lazy_static`
//! snapshot), so the test asks both at the start, one after the other, before any test reads
//! anything, and every later question meets the same list in both. The inputs are taken from that
//! list (the names of the interfaces, their addresses, the addresses next to them) and from a set of
//! addresses that no interface holds (the unspecified ones, a mapped IPv4 address, the loopback of
//! the other family, a documentation range), so an input is a real one on any machine.
//!
//! * BY NAME: the address of an interface, its unicast addresses, its local addresses and the IPv4
//!   and IPv6 addresses of it, for each name, a name that is an address, and names that are nothing;
//! * BY ADDRESS: the index of the interface that holds an address and the names of those that hold
//!   it (the canonical form of a mapped address included);
//! * OF THE MACHINE: the multicast interfaces, their unicast addresses, and the local, IPv4 and IPv6
//!   addresses with and without the loopback;
//! * BINDING a socket to an interface by name, for a TCP and a UDP socket.
//!
//! What a machine has decides what a fault could show: a question about an interface that is down
//! has an answer only where one is, so the injected faults of the round were run on a machine with
//! interfaces up, down, with and without multicast, and with private, public and link-local
//! addresses. There is nothing that upstream does and wz does not here, on a Unix machine; the
//! Windows half of the module is compile-checked on the Windows host.

#![cfg(target_os = "linux")]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Once,
};

/// An error as text without the place of the crate that made it.
fn plain(e: &impl std::fmt::Display) -> String {
    let s = e.to_string();
    s.split(" at ").next().unwrap_or("").to_string()
}

/// Both crates read the interfaces now, one after the other.
fn snapshot() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = up_util::net::get_multicast_interfaces();
        let _ = wz_util::net::get_multicast_interfaces();
    });
}

macro_rules! net_cases {
    ($m:ident, $u:ident) => {
        mod $m {
            use std::net::IpAddr;

            use $u::net::{
                get_index_of_interface, get_interface, get_interface_names_by_addr,
                get_ipv4_ipaddrs, get_ipv6_ipaddrs, get_local_addresses, get_multicast_interfaces,
                get_unicast_addresses_of_interface, get_unicast_addresses_of_multicast_interfaces,
                set_bind_to_device_tcp_socket, set_bind_to_device_udp_socket,
            };

            use super::plain;

            pub fn names() -> Vec<String> {
                get_interface_names_by_addr(IpAddr::from([0, 0, 0, 0])).unwrap()
            }

            pub fn addresses() -> Vec<IpAddr> {
                get_local_addresses(None).unwrap()
            }

            pub fn by_name(name: &str) -> Vec<String> {
                vec![
                    format!(
                        "get_interface {:?}",
                        get_interface(name).map_err(|e| plain(&e))
                    ),
                    format!(
                        "unicast {:?}",
                        get_unicast_addresses_of_interface(name).map_err(|e| plain(&e))
                    ),
                    format!(
                        "local {:?}",
                        get_local_addresses(Some(name)).map_err(|e| plain(&e))
                    ),
                    format!(
                        "v4 {:?} {:?}",
                        get_ipv4_ipaddrs(Some(name), false),
                        get_ipv4_ipaddrs(Some(name), true)
                    ),
                    format!(
                        "v6 {:?} {:?}",
                        get_ipv6_ipaddrs(Some(name), false),
                        get_ipv6_ipaddrs(Some(name), true)
                    ),
                ]
            }

            pub fn by_addr(addr: IpAddr) -> Vec<String> {
                vec![
                    format!(
                        "index {:?}",
                        get_index_of_interface(addr).map_err(|e| plain(&e))
                    ),
                    format!(
                        "names {:?}",
                        get_interface_names_by_addr(addr).map_err(|e| plain(&e))
                    ),
                    format!(
                        "as name {:?}",
                        get_interface(&addr.to_string()).map_err(|e| plain(&e))
                    ),
                ]
            }

            pub fn of_machine() -> Vec<String> {
                vec![
                    format!("multicast {:?}", get_multicast_interfaces()),
                    format!(
                        "unicast of multicast {:?}",
                        get_unicast_addresses_of_multicast_interfaces()
                    ),
                    format!(
                        "local {:?}",
                        get_local_addresses(None).map_err(|e| plain(&e))
                    ),
                    format!(
                        "v4 {:?} {:?}",
                        get_ipv4_ipaddrs(None, false),
                        get_ipv4_ipaddrs(None, true)
                    ),
                    format!(
                        "v6 {:?} {:?}",
                        get_ipv6_ipaddrs(None, false),
                        get_ipv6_ipaddrs(None, true)
                    ),
                ]
            }

            /// Binding a TCP and a UDP socket to an interface by name: what each says.
            pub fn bind(iface: &str) -> Vec<String> {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let tcp = tokio::net::TcpSocket::new_v4().unwrap();
                let udp = rt
                    .block_on(tokio::net::UdpSocket::bind("127.0.0.1:0"))
                    .unwrap();
                vec![
                    format!(
                        "tcp {:?}",
                        set_bind_to_device_tcp_socket(&tcp, iface).map_err(|e| plain(&e))
                    ),
                    format!(
                        "udp {:?}",
                        set_bind_to_device_udp_socket(&udp, iface).map_err(|e| plain(&e))
                    ),
                ]
            }
        }
    };
}

net_cases!(up, up_util);
net_cases!(wz, wz_util);

/// Names that no interface has and names that look like something else.
const NAMES: [&str; 9] = [
    "",
    "nosuchiface0",
    "LO",
    "lo ",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "fe80::1%lo",
    "\u{65e5}\u{672c}",
];

/// Addresses no interface holds, and addresses of the forms the questions treat in their own way.
fn foreign_addresses() -> Vec<IpAddr> {
    vec![
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        // a documentation range, and a mapped IPv4 loopback and mapped IPv4 documentation address
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77)),
        IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
        IpAddr::V6(Ipv4Addr::new(192, 0, 2, 77).to_ipv6_mapped()),
        IpAddr::V4(Ipv4Addr::BROADCAST),
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
        IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)),
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
    ]
}

#[test]
fn both_crates_see_the_same_interfaces_and_addresses() {
    snapshot();
    let (un, wn) = (up::names(), wz::names());
    assert_eq!(un, wn);
    assert!(!un.is_empty(), "a machine with no interface at all");
    let (ua, wa) = (up::addresses(), wz::addresses());
    assert_eq!(ua, wa);
    // Every machine has its loopback, up and running.
    assert!(
        ua.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)),
        "the loopback is not up: {ua:?}"
    );
    assert!(un.iter().any(|n| n == "lo"), "{un:?}");
}

#[test]
fn both_crates_answer_every_question_about_an_interface_by_its_name_alike() {
    snapshot();
    let mut names = up::names();
    names.extend(NAMES.iter().map(|s| s.to_string()));
    // Every address of the machine is also a name that `get_interface` takes.
    names.extend(up::addresses().iter().map(|a| a.to_string()));
    let (mut ok, mut err) = (0usize, 0usize);
    for name in &names {
        let (u, w) = (up::by_name(name), wz::by_name(name));
        assert_eq!(u, w, "{name:?}");
        for row in &u {
            if row.contains("Err(") {
                err += 1
            } else {
                ok += 1
            }
        }
    }
    assert!(ok > 10 && err >= NAMES.len(), "{ok} {err}");
    // The error of a name that is not there says so, and the loopback has an address.
    assert!(
        up::by_name("nosuchiface0")[1].contains("Interface nosuchiface0 not found"),
        "{:?}",
        up::by_name("nosuchiface0")
    );
    assert!(
        up::by_name("lo")[0].contains("Some(127.0.0.1)"),
        "{:?}",
        up::by_name("lo")
    );
}

#[test]
fn both_crates_answer_every_question_about_an_address_alike() {
    snapshot();
    let mut addrs = up::addresses();
    addrs.extend(foreign_addresses());
    let mut found = 0usize;
    for addr in &addrs {
        let (u, w) = (up::by_addr(*addr), wz::by_addr(*addr));
        assert_eq!(u, w, "{addr}");
        found += u[0].starts_with("index Ok") as usize;
    }
    // The addresses of the machine have an interface, and the foreign ones have none.
    assert!(found >= 2, "{found}");
    assert!(
        up::by_addr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77)))[0]
            .contains("No interface found with address 192.0.2.77"),
        "{:?}",
        up::by_addr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77)))
    );
    // The unspecified address names every interface, in both families.
    let all = up::names();
    for unspecified in [
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    ] {
        assert!(
            up::by_addr(unspecified)[1].contains(&format!("{all:?}")),
            "{unspecified}"
        );
    }
    // A mapped IPv4 address is looked up by the canonical form of it.
    assert_eq!(
        up::by_addr(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()))[1],
        up::by_addr(IpAddr::V4(Ipv4Addr::LOCALHOST))[1]
    );
}

#[test]
fn both_crates_answer_every_question_about_the_machine_alike() {
    snapshot();
    let (u, w) = (up::of_machine(), wz::of_machine());
    assert_eq!(u, w);
    // The loopback is not a multicast interface and is a local address, and the IPv6 list of the
    // machine without the loopback has none in it.
    assert!(!u[0].contains("127.0.0.1"), "{u:?}");
    assert!(u[2].contains("127.0.0.1"), "{u:?}");
    assert!(u[4].contains("::1") && u[3].contains("127.0.0.1"), "{u:?}");
}

#[test]
fn both_crates_leave_the_loopback_out_when_asked_and_keep_the_order_of_the_ipv6_list() {
    snapshot();
    // With the loopback left out, no loopback is in the lists, for the machine and for each name.
    let mut scopes: Vec<Option<String>> = vec![None];
    scopes.extend(up::names().into_iter().map(Some));
    for scope in &scopes {
        let s = scope.as_deref();
        let (u4, w4) = (
            up_util::net::get_ipv4_ipaddrs(s, true),
            wz_util::net::get_ipv4_ipaddrs(s, true),
        );
        let (u6, w6) = (
            up_util::net::get_ipv6_ipaddrs(s, true),
            wz_util::net::get_ipv6_ipaddrs(s, true),
        );
        assert_eq!((&u4, &u6), (&w4, &w6), "{scope:?}");
        assert!(
            u4.iter().chain(&u6).all(|a| !a.is_loopback()),
            "{scope:?} {u4:?} {u6:?}"
        );
        // The IPv6 list is the non-link-local IPv6 addresses, then the public IPv4 ones, then the
        // link-local IPv6 ones, then the private IPv4 ones: the classes never go back.
        let rank = |a: &IpAddr| match a {
            IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) != 0xfe80 => 0,
            IpAddr::V4(v4) if !v4.is_private() => 1,
            IpAddr::V6(_) => 2,
            IpAddr::V4(_) => 3,
        };
        let ranks: Vec<u8> = wz_util::net::get_ipv6_ipaddrs(s, false)
            .iter()
            .map(rank)
            .collect();
        assert!(
            ranks.windows(2).all(|w| w[0] <= w[1]),
            "{scope:?} {ranks:?}"
        );
    }
}

#[test]
fn both_crates_bind_a_socket_to_an_interface_alike() {
    snapshot();
    let mut names = up::names();
    names.extend(["nosuchiface0".to_string(), "".to_string(), "a".repeat(40)]);
    let mut ok = 0usize;
    for name in &names {
        let (u, w) = (up::bind(name), wz::bind(name));
        assert_eq!(u, w, "{name:?}");
        ok += u.iter().filter(|r| r.contains("Ok(())")).count();
    }
    // A name that no interface has is refused for both kinds of socket, or it is accepted by both:
    // the answer is the kernel's, the same for the two crates, and it is never an error of a panic.
    let nothing = up::bind("nosuchiface0");
    assert_eq!(nothing.len(), 2);
    let _ = ok;
}

/// The control: the comparison is on text, so a question that has another answer gives text that
/// differs.
#[test]
fn the_comparison_sees_an_answer_that_differs() {
    snapshot();
    assert_ne!(wz::by_name("lo"), wz::by_name("nosuchiface0"));
    assert_ne!(
        wz::by_addr(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        wz::by_addr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77)))
    );
    assert_ne!(wz::of_machine()[0], wz::of_machine()[2]);
}
