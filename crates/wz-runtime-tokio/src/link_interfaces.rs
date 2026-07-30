// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

use std::net::{IpAddr, SocketAddr};

use wz_session_core::link::{InterceptorLink, LinkSubject};

/// The §5.16 subject of an IP-addressed link: its protocol, plus the NICs its
/// LOCAL address sits on, resolved live at link open.
///
/// `local` is the socket's own address; `None` means the pipeline could not read
/// it, which propagates as an INDETERMINATE interface set (`None`) rather than an
/// empty one — the caller could not determine the NICs, which is not the same
/// statement as "there are none".
pub fn ip_link_subject(protocol: InterceptorLink, local: Option<SocketAddr>) -> LinkSubject {
    LinkSubject {
        protocol: Some(protocol),
        interfaces: local.and_then(|addr| interface_names_for(addr.ip())),
    }
}

/// The §5.16 subject of a link that has no IP address at all — a unix stream
/// socket, a named pipe, a serial tty, an AF_VSOCK channel.
///
/// Its interface set is `Some(empty)`: a DEFINITE "this link is on no NIC", not
/// an indeterminate one. A rule narrowed by `interfaces` therefore does not
/// govern it, while a rule narrowed only by `link_protocols` still can. zenoh
/// cannot draw that line — it reports `vec![]` for a failed lookup too
/// (`io/zenoh-link-commons/src/unicast.rs:112-118`).
pub fn addressless_link_subject(protocol: InterceptorLink) -> LinkSubject {
    LinkSubject {
        protocol: Some(protocol),
        interfaces: Some(Vec::new()),
    }
}

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

/// Non-unix: no `getifaddrs`, so the subject is INDETERMINATE rather than empty.
/// Returning `Some(vec![])` here would claim "this link is on no NIC", which is
/// a different — and wrong — statement; `None` lets the interceptor apply its
/// fail-closed policy instead.
#[cfg(not(unix))]
pub fn interface_names_for(_addr: IpAddr) -> Option<Vec<String>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The loopback address must resolve to at least one interface on any host
    /// this test can run on, and the resolution must be a definite `Some`.
    #[test]
    #[cfg(unix)]
    fn loopback_resolves_to_a_named_interface() {
        let names = interface_names_for(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
            .expect("getifaddrs resolves on a unix host");
        assert!(
            !names.is_empty(),
            "127.0.0.1 must sit on some interface; got {names:?}"
        );
    }

    /// An address no local interface carries resolves to an EMPTY set — a
    /// definite negative, NOT an error. This is the distinction zenoh collapses:
    /// upstream returns `vec![]` for this case AND for a failed lookup.
    #[test]
    #[cfg(unix)]
    fn a_foreign_address_resolves_to_a_definite_empty_set() {
        // TEST-NET-1 (RFC5737) — reserved for documentation, never assigned to a
        // host interface.
        let names = interface_names_for(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)))
            .expect("the lookup itself succeeds");
        assert!(
            names.is_empty(),
            "192.0.2.1 is reserved and must be on no interface; got {names:?}"
        );
    }

    /// The wildcard address is on EVERY interface (zenoh's same arm), so it must
    /// be a strict superset of what a specific local address resolves to.
    #[test]
    #[cfg(unix)]
    fn the_unspecified_address_covers_every_interface() {
        let all = interface_names_for(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
            .expect("getifaddrs resolves");
        let loopback = interface_names_for(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
            .expect("getifaddrs resolves");
        assert!(!all.is_empty(), "the host has at least one interface");
        for name in &loopback {
            assert!(
                all.contains(name),
                "the wildcard set {all:?} must contain the loopback's {name}"
            );
        }
    }
}
