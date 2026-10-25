//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-util 1.10.1, file
// src/ffi/win.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).
use std::{
    io, mem,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use winapi::shared::{ws2def, ws2ipdef};

#[allow(clippy::many_single_char_names)]
pub fn sockaddr_to_addr(socket_addr: ws2def::SOCKET_ADDRESS) -> io::Result<SocketAddr> {
    // Three places differ from upstream, which panics on a null or short address (an unwrap and
    // two asserts) and passes the flow information as the scope identifier of an IPv6 address.
    unsafe {
        let Some(sockaddr) = socket_addr.lpSockaddr.as_ref() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "null socket address",
            ));
        };
        let length = usize::try_from(socket_addr.iSockaddrLength).unwrap_or(0);
        if length < mem::size_of::<ws2def::ADDRESS_FAMILY>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "socket address too short to hold its family",
            ));
        }
        match sockaddr.sa_family as i32 {
            ws2def::AF_INET => {
                if length < mem::size_of::<ws2def::SOCKADDR_IN>() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "IPv4 socket address too short",
                    ));
                }
                let socket_addr: &ws2def::SOCKADDR_IN =
                    &*(sockaddr as *const ws2def::SOCKADDR as *const ws2def::SOCKADDR_IN);
                let ip: u32 = mem::transmute(socket_addr.sin_addr.S_un);
                let ip = ip.to_be();
                let a = (ip >> 24) as u8;
                let b = (ip >> 16) as u8;
                let c = (ip >> 8) as u8;
                let d = ip as u8;
                let sockaddrv4 = SocketAddrV4::new(
                    Ipv4Addr::new(a, b, c, d),
                    u16::from_be(socket_addr.sin_port),
                );
                Ok(SocketAddr::V4(sockaddrv4))
            }
            ws2def::AF_INET6 => {
                if length < mem::size_of::<ws2ipdef::SOCKADDR_IN6>() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "IPv6 socket address too short",
                    ));
                }
                let socket_addr: &ws2ipdef::SOCKADDR_IN6 =
                    &*(sockaddr as *const ws2def::SOCKADDR as *const ws2ipdef::SOCKADDR_IN6_LH);
                let arr: [u16; 8] = mem::transmute(socket_addr.sin6_addr.u);
                let a = u16::from_be(arr[0]);
                let b = u16::from_be(arr[1]);
                let c = u16::from_be(arr[2]);
                let d = u16::from_be(arr[3]);
                let e = u16::from_be(arr[4]);
                let f = u16::from_be(arr[5]);
                let g = u16::from_be(arr[6]);
                let h = u16::from_be(arr[7]);
                let ip = Ipv6Addr::new(a, b, c, d, e, f, g, h);
                Ok(SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    u16::from_be(socket_addr.sin6_port),
                    u32::from_be(socket_addr.sin6_flowinfo),
                    *socket_addr.u.sin6_scope_id(),
                )))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected IPv4 or IPv6 socket",
            )),
        }
    }
}

// Run on a Windows host only: this module is the Windows half of the tests of the crate. The
// address conversion is read from socket addresses built by hand, and the adapter functions are
// read against the adapters of the machine as `GetAdaptersAddresses` lists them.
#[cfg(test)]
mod tests {
    use std::{net::IpAddr, panic};

    use winapi::um::{iphlpapi::GetAdaptersAddresses, iptypes::IP_ADAPTER_ADDRESSES_LH};

    use super::*;

    fn v6_sockaddr(flow_net: u32, scope: u32) -> ws2ipdef::SOCKADDR_IN6 {
        unsafe {
            let mut sa: ws2ipdef::SOCKADDR_IN6 = mem::zeroed();
            sa.sin6_family = ws2def::AF_INET6 as u16;
            sa.sin6_port = 0x1234u16.to_be();
            sa.sin6_flowinfo = flow_net;
            *sa.u.sin6_scope_id_mut() = scope;
            *sa.sin6_addr.u.Byte_mut() = "fe80::1".parse::<Ipv6Addr>().unwrap().octets();
            sa
        }
    }

    #[test]
    fn the_scope_identifier_is_the_scope_and_not_the_flow_information() {
        let mut sa = v6_sockaddr(0x0102_0304u32.to_be(), 7);
        let address = ws2def::SOCKET_ADDRESS {
            lpSockaddr: &mut sa as *mut _ as *mut ws2def::SOCKADDR,
            iSockaddrLength: mem::size_of::<ws2ipdef::SOCKADDR_IN6>() as i32,
        };
        let got = sockaddr_to_addr(address).unwrap();
        let SocketAddr::V6(v6) = got else {
            panic!("{got:?}")
        };
        assert_eq!(*v6.ip(), "fe80::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(v6.port(), 0x1234);
        assert_eq!(v6.flowinfo(), 0x0102_0304);
        assert_eq!(v6.scope_id(), 7);
    }

    #[test]
    fn an_ipv4_address_is_read_in_network_order() {
        let mut sa: ws2def::SOCKADDR_IN = unsafe { mem::zeroed() };
        sa.sin_family = ws2def::AF_INET as u16;
        sa.sin_port = 4321u16.to_be();
        unsafe {
            *sa.sin_addr.S_un.S_addr_mut() = u32::from_ne_bytes([192, 168, 7, 9]);
        }
        let address = ws2def::SOCKET_ADDRESS {
            lpSockaddr: &mut sa as *mut _ as *mut ws2def::SOCKADDR,
            iSockaddrLength: mem::size_of::<ws2def::SOCKADDR_IN>() as i32,
        };
        assert_eq!(
            sockaddr_to_addr(address).unwrap(),
            "192.168.7.9:4321".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn a_short_or_null_address_is_an_error_and_not_a_panic() {
        let null = ws2def::SOCKET_ADDRESS {
            lpSockaddr: std::ptr::null_mut(),
            iSockaddrLength: 0,
        };
        let mut sa: ws2def::SOCKADDR_IN = unsafe { mem::zeroed() };
        sa.sin_family = ws2def::AF_INET as u16;
        let mut sa6 = v6_sockaddr(0, 0);
        let cases = [
            ("null", null),
            (
                "no room for the family",
                ws2def::SOCKET_ADDRESS {
                    lpSockaddr: &mut sa as *mut _ as *mut ws2def::SOCKADDR,
                    iSockaddrLength: 1,
                },
            ),
            (
                "short v4",
                ws2def::SOCKET_ADDRESS {
                    lpSockaddr: &mut sa as *mut _ as *mut ws2def::SOCKADDR,
                    iSockaddrLength: 2,
                },
            ),
            (
                "short v6",
                ws2def::SOCKET_ADDRESS {
                    lpSockaddr: &mut sa6 as *mut _ as *mut ws2def::SOCKADDR,
                    iSockaddrLength: 4,
                },
            ),
        ];
        for (what, address) in cases {
            let r = panic::catch_unwind(|| sockaddr_to_addr(address).is_err());
            assert_eq!(r.ok(), Some(true), "{what}");
        }
    }

    // The addresses of the machine read directly: (address, IfIndex, Ipv6IfIndex).
    fn adapters() -> Vec<(IpAddr, u32, u32)> {
        unsafe {
            let mut size: u32 = 32 * 1024;
            let mut buffer: Vec<u8>;
            loop {
                buffer = vec![0u8; size as usize];
                let ret = GetAdaptersAddresses(
                    ws2def::AF_UNSPEC as u32,
                    0,
                    std::ptr::null_mut(),
                    buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                    &mut size,
                );
                if ret == 0 {
                    break;
                }
                assert_eq!(ret, winapi::shared::winerror::ERROR_BUFFER_OVERFLOW);
            }
            let mut out = vec![];
            let mut next = (buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH).as_ref();
            while let Some(iface) = next {
                let mut unicast = iface.FirstUnicastAddress.as_ref();
                while let Some(a) = unicast {
                    if let Ok(sa) = sockaddr_to_addr(a.Address) {
                        out.push((sa.ip(), iface.u.s().IfIndex, iface.Ipv6IfIndex));
                    }
                    unicast = a.Next.as_ref();
                }
                next = iface.Next.as_ref();
            }
            out
        }
    }

    #[test]
    fn the_index_of_an_interface_is_the_one_of_its_family() {
        let all = adapters();
        assert!(!all.is_empty());
        let mut differ = vec![];
        for (ip, if_index, v6_index) in &all {
            let want = if ip.is_ipv4() { *if_index } else { *v6_index };
            match crate::net::get_index_of_interface(*ip) {
                Ok(got) if got == want => {}
                other => differ.push((*ip, want, other.map_err(|e| e.to_string()))),
            }
        }
        assert!(differ.is_empty(), "{differ:?}");
    }

    #[test]
    fn a_filter_the_first_adapter_does_not_match_returns() {
        let none = crate::net::get_local_addresses(Some("no-such-adapter")).unwrap();
        assert!(none.is_empty(), "{none:?}");
        let all = crate::net::get_local_addresses(None).unwrap();
        assert!(!all.is_empty());
        let names = crate::net::get_interface_names_by_addr("0.0.0.0".parse().unwrap()).unwrap();
        assert!(!names.is_empty());
        // A filter that does match the last adapter, which upstream never gets to.
        let last = names.last().unwrap().clone();
        let one = crate::net::get_local_addresses(Some(&last)).unwrap();
        assert!(!one.is_empty(), "adapter {last}");
        let _ = crate::net::get_multicast_interfaces();
    }
}
