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

use wz_session_core::link::{InterceptorLink, LinkEndpoints, LinkSubject};

/// R311y473 — the `{src,dst}` LOCATOR PAIR of an IP-addressed link, for the
/// adminspace's per-link view (zenoh `link_to_json`,
/// `net/runtime/adminspace.rs:608-613`).
///
/// Both ends are required: `None` when either address could not be read, which
/// is the same "could not determine" honesty [`ip_link_subject`] applies to its
/// interface set. A half-known pair rendered as a locator would be a string an
/// admin client cannot dial and cannot tell apart from one it can.
///
/// The scheme comes from [`InterceptorLink::locator_for`] — the single table
/// `BoundListener::advertised_locator` also delegates to — so this emitter cannot
/// repeat the R311y470 defect of shipping a log word where a scheme belongs.
pub fn ip_link_endpoints(
    protocol: InterceptorLink,
    local: Option<SocketAddr>,
    peer: Option<SocketAddr>,
) -> Option<LinkEndpoints> {
    Some(LinkEndpoints::new(
        protocol.locator_for(&local?.to_string()),
        protocol.locator_for(&peer?.to_string()),
    ))
}

/// R311y473 — the `{src,dst}` pair of a link addressed by something other than an
/// IP socket: a unix-socket path, a vsock `cid:port`, a named pipe, a serial
/// device. The caller renders each end's ADDRESS; the scheme is applied here from
/// the same single table [`ip_link_endpoints`] uses.
pub fn addressless_link_endpoints(
    protocol: InterceptorLink,
    local: &str,
    peer: &str,
) -> LinkEndpoints {
    LinkEndpoints::new(protocol.locator_for(local), protocol.locator_for(peer))
}

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

/// Without the `locator-iface` feature the multicast honor is not built, matching
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

    /// The loopback interface must resolve to a set containing `127.0.0.1`. This
    /// checks the resolver against the KERNEL's interface table, not against its
    /// own syscall: the expected address is a constant of the loopback contract,
    /// not something the function under test chose.
    #[test]
    #[cfg(unix)]
    fn the_loopback_interface_resolves_to_its_loopback_address() {
        let addrs = unicast_addresses_of_interface("lo").expect("lo is present, up and running");
        assert!(
            addrs.contains(&IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            "lo must carry 127.0.0.1; got {addrs:?}"
        );
        assert!(
            addrs.iter().all(|ip| !ip.is_multicast()),
            "a multicast address is not a valid interface selector; got {addrs:?}"
        );
    }

    /// An interface name that cannot exist is `NotFound` — DISTINCT from
    /// `Undetermined`. This is the boundary the honor policy turns on: `NotFound`
    /// is upstream's hard error, `Undetermined` is the platform warn.
    #[test]
    #[cfg(unix)]
    fn an_absent_interface_name_is_not_found_rather_than_undetermined() {
        // IFNAMSIZ caps a real device name at 15 bytes, and `/` is not legal in
        // one, so this name cannot collide with a host interface.
        let err = unicast_addresses_of_interface("wz/no/such/dev")
            .expect_err("an unnameable device cannot resolve");
        assert_eq!(
            err,
            IfaceResolveError::NotFound,
            "an absent name must be NotFound, not {err:?} — the policy treats \
             Undetermined as a warn and NotFound as a hard error"
        );
    }

    /// An `#iface=` value that is an IPv4 LITERAL is used directly, without any
    /// interface lookup — upstream's first arm (`zenoh-link-udp/src/multicast.rs`
    /// :228-230). Checked with an address NO interface carries, so it can only pass
    /// if the literal short-circuits the table walk.
    #[test]
    #[cfg(all(unix, feature = "locator-iface"))]
    fn a_multicast_iface_given_as_an_address_literal_skips_the_interface_lookup() {
        // TEST-NET-1 (RFC5737): reserved for documentation, never on a host NIC. A
        // name-based resolution of it would be NotFound.
        let selector = multicast_iface_selector_v4("192.0.2.1")
            .expect("an address literal needs no interface table");
        assert_eq!(
            selector,
            Some(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            "an IPv4 literal must be taken verbatim as the interface selector"
        );
    }

    /// A NAME resolves through the interface table to that interface's v4 address.
    #[test]
    #[cfg(all(unix, feature = "locator-iface"))]
    fn a_multicast_iface_given_as_a_name_resolves_to_its_v4_address() {
        let selector = multicast_iface_selector_v4("lo").expect("lo is present, up and running");
        assert_eq!(
            selector,
            Some(std::net::Ipv4Addr::LOCALHOST),
            "lo's v4 address is the selector a v4 group pins to"
        );
    }

    /// An absent name is a HARD ERROR, not a warn-and-continue — the same posture as
    /// upstream, which `bail!`s and propagates with `?` (`multicast.rs:229`). This is
    /// the boundary the policy turns on: silently falling back would pin the group to
    /// an interface the config never named.
    #[test]
    #[cfg(all(unix, feature = "locator-iface"))]
    fn an_absent_multicast_iface_refuses_the_bind_rather_than_warning() {
        let err = multicast_iface_selector_v4("wz/no/such/dev")
            .expect_err("an unnameable device must not yield a selector");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidInput,
            "an unresolvable #iface= must refuse the bind; got {err:?}"
        );
    }

    /// The IFF_UP / IFF_RUNNING verdicts must agree with what sysfs independently
    /// reports, for EVERY interface the host has.
    ///
    /// This exists because the carrier check is otherwise unasserted: nothing else
    /// here can construct a down interface (that needs `CAP_NET_ADMIN`), so without
    /// a cross-check the whole `NotUp` / `NotRunning` surface would rest on reading
    /// the code. `/sys/class/net/<dev>/carrier` is a genuinely independent source —
    /// sysfs, not `getifaddrs` — and it is the right one: sysfs's `flags` file
    /// deliberately omits IFF_RUNNING (`lo` reads `0x9`, no `0x40`, while
    /// `getifaddrs` does report it), so comparing against `flags` would manufacture
    /// a disagreement on loopback.
    ///
    /// A host whose every interface has carrier means the `carrier == 0` direction
    /// checks nothing — but the `carrier == 1` direction still asserts on every one
    /// of them, so the test is never vacuous.
    #[test]
    #[cfg(unix)]
    fn the_carrier_verdict_agrees_with_sysfs_for_every_interface() {
        let entries = match std::fs::read_dir("/sys/class/net") {
            Ok(e) => e,
            // Not Linux, or sysfs unmounted: the resolver still works, there is just
            // no second source to compare against.
            Err(_) => return,
        };
        let mut checked = 0usize;
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().into_owned();
            let carrier = match std::fs::read_to_string(format!("/sys/class/net/{name}/carrier")) {
                Ok(s) => s.trim().to_string(),
                // A device can refuse the read (EINVAL while down); skip only that one.
                Err(_) => continue,
            };
            let verdict = unicast_addresses_of_interface(&name);
            checked += 1;
            match carrier.as_str() {
                "0" => assert!(
                    matches!(
                        verdict,
                        Err(IfaceResolveError::NotRunning) | Err(IfaceResolveError::NotUp)
                    ),
                    "sysfs says {name} has no carrier, so the resolver must reject it as \
                     NotRunning/NotUp (upstream bails on exactly this); got {verdict:?}"
                ),
                "1" => assert!(
                    !matches!(verdict, Err(IfaceResolveError::NotRunning)),
                    "sysfs says {name} HAS carrier, so the resolver must not call it \
                     NotRunning; got {verdict:?}"
                ),
                other => panic!("unexpected carrier value {other:?} for {name}"),
            }
        }
        assert!(
            checked > 0,
            "no interface carrier was readable under /sys/class/net, so this \
             cross-check asserted nothing"
        );
    }

    /// The two directions must agree: every address `lo` resolves to must resolve
    /// BACK to a name set containing `lo`. Neither function can satisfy this
    /// alone, so it witnesses the pair rather than either one's own output.
    #[test]
    #[cfg(unix)]
    fn the_two_resolution_directions_agree_on_loopback() {
        let addrs = unicast_addresses_of_interface("lo").expect("lo resolves");
        assert!(!addrs.is_empty(), "lo carries at least one address");
        for addr in addrs {
            let names = interface_names_for(addr).expect("the reverse lookup runs");
            assert!(
                names.iter().any(|n| n == "lo"),
                "{addr} came from lo, so its name set {names:?} must contain lo"
            );
        }
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
