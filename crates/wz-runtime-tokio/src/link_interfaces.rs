// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

use wz_session_core::link::{LinkEndpoints, LinkKind, LinkSubject};

/// R311y473 — the `{src,dst}` LOCATOR PAIR of an IP-addressed link, for the
/// adminspace's per-link view (zenoh `link_to_json`,
/// `net/runtime/adminspace.rs:608-613`).
///
/// Both ends are required: `None` when either address could not be read, which
/// is the same "could not determine" honesty [`ip_link_subject`] applies to its
/// interface set. A half-known pair rendered as a locator would be a string an
/// admin client cannot dial and cannot tell apart from one it can.
///
/// The scheme comes from [`LinkKind::locator_for`] — the single table
/// `BoundListener::advertised_locator` also delegates to — so this emitter cannot
/// repeat the R311y470 defect of shipping a log word where a scheme belongs.
///
/// R2794 (open-debt item 814) — takes the link's KIND, the same value
/// [`ip_link_subject`] takes. Every pipeline used to hand one `InterceptorLink`
/// to both, which is where the two axes were fused: this function wants the
/// kind's advertised form, the subject wants what a rule sees.
pub fn ip_link_endpoints(
    kind: LinkKind,
    local: Option<SocketAddr>,
    peer: Option<SocketAddr>,
) -> Option<LinkEndpoints> {
    Some(LinkEndpoints::new(
        kind.locator_for(&local?.to_string()),
        kind.locator_for(&peer?.to_string()),
    ))
}

/// R311y473 — the `{src,dst}` pair of a link addressed by something other than an
/// IP socket: a unix-socket path, a vsock `cid:port`, a named pipe, a serial
/// device. The caller renders each end's ADDRESS; the scheme is applied here from
/// the same single table [`ip_link_endpoints`] uses.
pub fn addressless_link_endpoints(kind: LinkKind, local: &str, peer: &str) -> LinkEndpoints {
    LinkEndpoints::new(kind.locator_for(local), kind.locator_for(peer))
}

/// The §5.16 subject of an IP-addressed link: its protocol, plus the NICs its
/// LOCAL address sits on, resolved live at link open.
///
/// `local` is the socket's own address; `None` means the pipeline could not read
/// it, which propagates as an INDETERMINATE interface set (`None`) rather than an
/// empty one — the caller could not determine the NICs, which is not the same
/// statement as "there are none".
pub fn ip_link_subject(kind: LinkKind, local: Option<SocketAddr>) -> LinkSubject {
    LinkSubject {
        kind: Some(kind),
        interfaces: local.and_then(|addr| interface_names_for(addr.ip())),
        // R2698 — no certificate is reachable from an address alone. A link
        // that HAS one fills this in afterwards with
        // [`LinkSubject::with_cert_common_name`], which is the only way it can
        // be right: the chain exists for one window inside the link's own
        // `wire_*`, and this helper is called from every IP transport including
        // the ones that never see a certificate.
        cert_common_name: None,
    }
}

/// The §5.16 subject of a link that has no IP address at all — a unix stream
/// socket, a named pipe, a serial tty, an AF_VSOCK channel.
///
/// Its interface set is DEFINITE (`Some`), never indeterminate: a rule narrowed
/// by `interfaces` is answered rather than skipped. zenoh cannot draw that line
/// — it reports `vec![]` for a failed lookup too
/// (`io/zenoh-link-commons/src/unicast.rs:112-118`).
///
/// R2548 — THE NAMES ARE A PARAMETER, and that is the whole point of this
/// signature. It used to take only the protocol and hard-code `Some(vec![])`,
/// on the reasoning that a link with no IP address is on no NIC. That is true
/// of the WIRE and false of UPSTREAM, which gives the four addressless links
/// FOUR different answers at the pin:
///
/// * `io/zenoh-links/zenoh-link-vsock/src/unicast.rs` @ `vec!["vsock".to_string()]`
///   — a deliberate pseudo-interface, so an ACL narrowed by `interfaces` can
///   target a vsock link at all;
/// * `io/zenoh-links/zenoh-link-serial/src/unicast.rs` @ `match z_serial::get_available_port_names()`
///   — the tty device names, without the path;
/// * `io/zenoh-links/zenoh-link-unixsock_stream/src/unicast.rs` @ `vec![]`, and
///   `io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs` @ `vec![]` too,
///   both declaring themselves "not supported".
///
/// A helper that assumed one of those four made the other three UNEXPRESSIBLE,
/// which is why the vsock divergence could not be fixed at its own call site
/// without fixing this. Each caller now STATES its answer and can be read
/// against the upstream link it mirrors.
pub fn addressless_link_subject(kind: LinkKind, interfaces: Vec<String>) -> LinkSubject {
    LinkSubject {
        kind: Some(kind),
        interfaces: Some(interfaces),
        // R2698 — none of the four addressless links presents a peer
        // certificate, so this is a definite absence rather than an unfilled
        // field.
        cert_common_name: None,
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

/// Non-unix: no `getifaddrs`, so a name finds nothing and is left out, as an unknown one is.
#[cfg(not(unix))]
pub fn first_ipv4_of_interface_named(_name: &str) -> Option<IpAddr> {
    None
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
/// is not an address a reply can be ELECTED by, so handing it to
/// [`wz_session_core::scout_responder::best_reply_source`] as a candidate would
/// score every asker at zero and make the choice the caller thought it was
/// making.
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

/// Non-unix: no `getifaddrs`, so this cannot answer. `None`, which a caller reads as "could not
/// determine" and not as a host with no address.
#[cfg(not(unix))]
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

/// Non-unix: no `getifaddrs`, so no carrier can be named.
#[cfg(not(unix))]
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

// R311y581 — gated on `unix`, not just `test`. EVERY test below is
// `#[cfg(unix)]` (they all need a POSIX interface table), so on Windows this
// module compiled to a `use super::*` with no consumer and the whole lib-test
// build failed `-D warnings` with `unused import`. Nothing had ever compiled it
// there: the portability lane ran `clippy` on the LIB, which does not build the
// test target, and the first `cargo test --lib` on Windows is what surfaced it.
// Gating the module is exactly equivalent to the ten per-test gates it replaces
// and leaves no dead import to allow away.
#[cfg(all(test, unix))]
mod tests {
    /// The loopback interface's NAME, discovered rather than assumed.
    ///
    /// R311y581 — three tests below hardcoded `"lo"`, and all three FAILED the
    /// first time any CI lane actually RAN this crate on macOS, where the
    /// loopback interface is `lo0`. They had compiled cleanly on that host since
    /// R311y13; a name that only exists on Linux is invisible to `clippy`.
    ///
    /// The defect was in the FIXTURES, not the resolver: every function here
    /// takes the name as an argument and asks the kernel, so none of them
    /// assumes a platform. What the tests assert is the loopback ADDRESS
    /// contract, and the name is an INPUT to that — so it belongs here, once,
    /// instead of at three call sites.
    ///
    /// Deliberately a candidate list rather than a lookup through
    /// `interface_names_for(127.0.0.1)`: that would make
    /// `the_two_resolution_directions_agree_on_loopback` circular, since
    /// witnessing exactly that pair is the test's whole purpose.
    fn loopback_iface_name() -> &'static str {
        // `lo` on Linux, `lo0` on macOS and the BSDs.
        for candidate in ["lo", "lo0"] {
            if super::unicast_addresses_of_interface(candidate).is_ok() {
                return candidate;
            }
        }
        panic!("no loopback interface resolved as `lo` or `lo0` on this host");
    }

    use super::*;

    /// The loopback address must resolve to at least one interface on any host
    /// this test can run on, and the resolution must be a definite `Some`.
    #[test]
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
    fn the_loopback_interface_resolves_to_its_loopback_address() {
        let lo = loopback_iface_name();
        let addrs =
            unicast_addresses_of_interface(lo).expect("the loopback is present, up and running");
        assert!(
            addrs.contains(&IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            "{lo} must carry 127.0.0.1; got {addrs:?}"
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
    #[cfg(feature = "locator-iface")]
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
    #[cfg(feature = "locator-iface")]
    fn a_multicast_iface_given_as_a_name_resolves_to_its_v4_address() {
        let lo = loopback_iface_name();
        let selector =
            multicast_iface_selector_v4(lo).expect("the loopback is present, up and running");
        assert_eq!(
            selector,
            Some(std::net::Ipv4Addr::LOCALHOST),
            "{lo}'s v4 address is the selector a v4 group pins to"
        );
    }

    /// An absent name is a HARD ERROR, not a warn-and-continue — the same posture as
    /// upstream, which `bail!`s and propagates with `?` (`multicast.rs:229`). This is
    /// the boundary the policy turns on: silently falling back would pin the group to
    /// an interface the config never named.
    #[test]
    #[cfg(feature = "locator-iface")]
    fn an_absent_multicast_iface_refuses_the_bind_rather_than_warning() {
        let err = multicast_iface_selector_v4("wz/no/such/dev")
            .expect_err("an unnameable device must not yield a selector");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidInput,
            "an unresolvable #iface= must refuse the bind; got {err:?}"
        );
    }

    /// R2584 — the loopback's kernel index, read from sysfs so that it does not
    /// come from the `if_nametoindex` call the resolver itself makes.
    ///
    /// Without sysfs (not Linux) the resolver's own answer is used instead. The
    /// name test below then checks `if_nametoindex` against itself, but the
    /// address test still checks two lookups against each other.
    fn loopback_index(lo: &str) -> u32 {
        match std::fs::read_to_string(format!("/sys/class/net/{lo}/ifindex")) {
            Ok(s) => s
                .trim()
                .parse()
                .expect("sysfs ifindex is a decimal integer"),
            Err(_) => interface_index_of_name(lo).expect("the loopback has an index"),
        }
    }

    /// The loopback must carry `::1`, or every v6 test below is about an address
    /// the host does not have. A host with IPv6 disabled FAILS here rather than
    /// skipping, because a skipped selector test reports green while checking
    /// nothing.
    fn loopback_carrying_v6() -> &'static str {
        let lo = loopback_iface_name();
        let addrs = unicast_addresses_of_interface(lo).expect("the loopback resolves");
        assert!(
            addrs.contains(&IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            "{lo} carries no ::1, so IPv6 is disabled on this host and the v6 \
             resolution cannot be checked; got {addrs:?}"
        );
        lo
    }

    /// An address resolves to the index of the interface holding it, checked
    /// against sysfs. Both families go through the same lookup, and IPv4 is
    /// included because a family filter hidden in it would pass a v6-only test.
    #[test]
    fn an_address_resolves_to_the_index_of_the_interface_that_carries_it() {
        let lo = loopback_carrying_v6();
        let want = loopback_index(lo);
        for addr in [
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        ] {
            let got = interface_indices_of_address(addr).expect("the lookup runs");
            assert!(
                got.contains(&want),
                "{addr} sits on {lo} (index {want}), so its carriers {got:?} must include it"
            );
        }
    }

    /// No interface holds the wildcard as an address. `interface_names_for`
    /// returns every interface for it, for a different reason (a socket bound to
    /// the wildcard is on all of them), and an index lookup that reused that
    /// answer would let `#iface=::` pin some arbitrary interface.
    #[test]
    fn the_unspecified_address_is_carried_by_no_interface() {
        let got = interface_indices_of_address(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED))
            .expect("the lookup runs");
        assert!(got.is_empty(), ":: is no interface's address; got {got:?}");
    }

    /// A v6 `#iface=` NAME selects that interface's own index.
    #[test]
    #[cfg(feature = "locator-iface")]
    fn a_v6_multicast_iface_given_a_name_selects_that_interfaces_index() {
        let lo = loopback_carrying_v6();
        let selector = multicast_iface_selector_v6(lo).expect("the loopback carries ::1");
        assert_eq!(
            selector,
            Some(loopback_index(lo)),
            "a v6 group pinned to {lo} must select {lo}'s index"
        );
    }

    /// A v6 address LITERAL selects the interface that holds it: upstream's
    /// address-then-index chain.
    #[test]
    #[cfg(feature = "locator-iface")]
    fn a_v6_multicast_iface_given_an_address_selects_the_interface_carrying_it() {
        let lo = loopback_carrying_v6();
        let selector = multicast_iface_selector_v6("::1").expect("::1 is carried by the loopback");
        assert_eq!(selector, Some(loopback_index(lo)));
    }

    /// An address no interface holds is refused. That matches upstream, which
    /// `bail!`s when it finds no interface with that address. Unlike the v4 literal,
    /// the address cannot be handed to the kernel as-is, because a v6 selector
    /// is an index.
    #[test]
    #[cfg(feature = "locator-iface")]
    fn a_v6_multicast_iface_no_interface_carries_refuses_the_bind() {
        // 2001:db8::/32 (RFC3849) is reserved for documentation and never assigned.
        let err = multicast_iface_selector_v6("2001:db8::7a")
            .expect_err("an address nothing carries selects no interface");
        assert_eq!(err.kind(), std::io::ErrorKind::AddrNotAvailable, "{err}");
    }

    /// The selection itself, for every carrier count, including the one this
    /// host cannot produce: one address on SEVERAL interfaces. Upstream takes
    /// whichever came first in its snapshot. wz refuses, because that order is
    /// not something the config author chose.
    #[test]
    #[cfg(feature = "locator-iface")]
    fn an_address_on_several_interfaces_names_none_of_them() {
        assert_eq!(the_one_carrier("fe80::1", &[5]).expect("one carrier"), 5);
        let none = the_one_carrier("fe80::1", &[]).expect_err("no carrier");
        assert_eq!(none.kind(), std::io::ErrorKind::AddrNotAvailable);
        let several = the_one_carrier("fe80::1", &[2, 5]).expect_err("two carriers");
        assert_eq!(several.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            several.to_string().contains("2 interfaces"),
            "the refusal says how many interfaces claimed the address: {several}"
        );
    }

    /// An address of the OTHER family is refused by both selectors and the
    /// message names the family. Before R2584 the v4 selector looked a v6 literal
    /// up as a NAME and reported "not found".
    #[test]
    #[cfg(feature = "locator-iface")]
    fn a_multicast_iface_of_the_other_family_is_refused_by_both_selectors() {
        let v6_given_v4 = multicast_iface_selector_v6("127.0.0.1").expect_err("family mismatch");
        let v4_given_v6 = multicast_iface_selector_v4("::1").expect_err("family mismatch");
        for err in [v6_given_v4, v4_given_v6] {
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
            assert!(
                err.to_string().contains("protocols must match"),
                "the refusal names the family mismatch: {err}"
            );
        }
    }

    /// An absent name is a hard error for v6 as well.
    #[test]
    #[cfg(feature = "locator-iface")]
    fn an_absent_v6_multicast_iface_refuses_the_bind_rather_than_warning() {
        let err = multicast_iface_selector_v6("wz/no/such/dev")
            .expect_err("an unnameable device must not yield a selector");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
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
    fn the_two_resolution_directions_agree_on_loopback() {
        let lo = loopback_iface_name();
        let addrs = unicast_addresses_of_interface(lo).expect("the loopback resolves");
        assert!(!addrs.is_empty(), "{lo} carries at least one address");
        for addr in addrs {
            let names = interface_names_for(addr).expect("the reverse lookup runs");
            assert!(
                names.iter().any(|n| n == lo),
                "{addr} came from {lo}, so its name set {names:?} must contain {lo}"
            );
        }
    }

    /// The wildcard address is on EVERY interface (zenoh's same arm), so it must
    /// be a strict superset of what a specific local address resolves to.
    #[test]
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

    /// R3071 -- the host's own address list, read from the kernel, names loopback and a
    /// non-loopback address, which is the population an unspecified listener expands over.
    #[test]
    fn the_local_address_list_holds_loopback_and_something_else() {
        let local = local_addresses().expect("getifaddrs resolves");
        assert!(
            local.iter().any(IpAddr::is_loopback),
            "an UP interface named loopback is in {local:?}"
        );
    }
}

/// R3071 -- the order an unspecified listener's locators are listed in, on a host whose addresses
/// are written out here. The addresses and the order are the ones MEASURED from a real peer bound
/// to `[::]` on a multi-homed host: global IPv6, public IPv4, link-local IPv6 (in the order the
/// host lists them), private IPv4, and no loopback to a neighbour.
#[cfg(test)]
mod expansion {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    fn host() -> Vec<IpAddr> {
        // The order `getifaddrs` gave on the measured host: the IPv4 ones first, then IPv6.
        [
            "127.0.0.1",
            "172.30.1.74",
            "100.75.93.118",
            "::1",
            "fe80::44be:2469:54d9:9a33",
            "fe80::a583:492f:8016:3c7e",
            "fd7a:115c:a1e0::db37:5d7a",
        ]
        .iter()
        .map(|text| ip(text))
        .collect()
    }

    fn texts(list: Vec<SocketAddr>) -> Vec<String> {
        list.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn a_v6_wildcard_lists_global_then_public_then_link_local_then_private() {
        let bound: SocketAddr = "[::]:36561".parse().unwrap();
        assert_eq!(
            texts(expand_unspecified(bound, &host(), true)),
            [
                "[fd7a:115c:a1e0::db37:5d7a]:36561",
                "100.75.93.118:36561",
                "[fe80::44be:2469:54d9:9a33]:36561",
                "[fe80::a583:492f:8016:3c7e]:36561",
                "172.30.1.74:36561",
            ]
        );
    }

    /// An asker on this host is owed the loopback addresses too: `::1` is a global-scope IPv6
    /// address and so comes first of the IPv6 ones, and `127.0.0.1` is not private so it follows
    /// the other public IPv4 address.
    #[test]
    fn a_loopback_asker_is_also_offered_loopback() {
        let bound: SocketAddr = "[::]:1".parse().unwrap();
        let with = texts(expand_unspecified(bound, &host(), false));
        assert_eq!(with.len(), 7, "every address of the host: {with:?}");
        assert_eq!(with[0], "[::1]:1");
        assert!(with.contains(&"127.0.0.1:1".to_string()));
    }

    #[test]
    fn a_v4_wildcard_lists_only_ipv4_in_the_hosts_order() {
        let bound: SocketAddr = "0.0.0.0:17922".parse().unwrap();
        assert_eq!(
            texts(expand_unspecified(bound, &host(), true)),
            ["172.30.1.74:17922", "100.75.93.118:17922"]
        );
        assert_eq!(
            texts(expand_unspecified(bound, &host(), false)),
            [
                "127.0.0.1:17922",
                "172.30.1.74:17922",
                "100.75.93.118:17922"
            ]
        );
    }

    /// An address that is not unspecified stands for itself, and loopback in it is the node's
    /// own choice and is not filtered.
    #[test]
    fn a_specific_bind_stands_for_itself() {
        let bound: SocketAddr = "127.0.0.1:17921".parse().unwrap();
        assert_eq!(expand_unspecified(bound, &host(), true), vec![bound]);
    }

    /// An IPv4 link-local, multicast or broadcast address is not offered through a `[::]` bind.
    #[test]
    fn a_v6_wildcard_does_not_offer_an_unusable_ipv4_address() {
        let local: Vec<IpAddr> = ["169.254.3.4", "224.0.0.1", "255.255.255.255", "10.1.2.3"]
            .iter()
            .map(|text| ip(text))
            .collect();
        let bound: SocketAddr = "[::]:5".parse().unwrap();
        assert_eq!(
            texts(expand_unspecified(bound, &local, true)),
            ["10.1.2.3:5"]
        );
    }
}

/// R3138 -- how `scouting/multicast/interface` is read, told on tables made for it. What a host
/// holds is not needed: an interface with several IPv4 addresses, or none, or one that is down,
/// cannot be made on an ordinary user's host, and the reading does not depend on any of them.
#[cfg(test)]
mod scouting_interface_reading {
    use super::{first_ipv4_among, scouting_interface_addresses};
    use std::net::IpAddr;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    /// The lookup a host would give: names to the first IPv4 of the interface of that name.
    fn host(name: &str) -> Option<IpAddr> {
        match name {
            "eth0" => Some(ip("10.0.0.5")),
            "wlan0" => Some(ip("192.168.1.9")),
            _ => None,
        }
    }

    /// An interface that holds several addresses is answered by its first IPv4, whatever comes
    /// before it and whatever follows.
    #[test]
    fn the_first_ipv4_of_an_interface_answers_for_all_of_it() {
        let table = [ip("fe80::1"), ip("10.0.0.5"), ip("10.0.0.6"), ip("fd00::2")];
        assert_eq!(first_ipv4_among(&table), Some(ip("10.0.0.5")));
        assert_eq!(first_ipv4_among(&[ip("fe80::1"), ip("fd00::2")]), None);
        assert_eq!(first_ipv4_among(&[]), None);
    }

    /// Commas split the text, each part is trimmed, and a literal is itself in either family.
    #[test]
    fn a_list_is_split_on_commas_and_trimmed() {
        assert_eq!(
            scouting_interface_addresses(" eth0 , 192.0.2.7 ,fd7a::1", host),
            vec![ip("10.0.0.5"), ip("192.0.2.7"), ip("fd7a::1")]
        );
        assert_eq!(
            scouting_interface_addresses("wlan0,eth0", host),
            vec![ip("192.168.1.9"), ip("10.0.0.5")],
            "the order of the text is the order of the addresses"
        );
    }

    /// A part that finds nothing is left out and the others stand: a name that matches no
    /// interface, an interface that holds no IPv4 address, an empty part.
    #[test]
    fn a_part_that_finds_nothing_is_left_out() {
        assert_eq!(
            scouting_interface_addresses("nope,eth0,,v6only", host),
            vec![ip("10.0.0.5")]
        );
        assert!(scouting_interface_addresses("nope", host).is_empty());
        assert!(scouting_interface_addresses("", host).is_empty());
    }

    /// A literal is taken before any name is looked up: a lookup that would answer for it is
    /// never asked, so an address a host does not hold is still what the text says.
    #[test]
    fn a_literal_is_taken_before_a_name_is_looked_up() {
        let asked = std::cell::RefCell::new(Vec::new());
        let lookup = |name: &str| {
            asked.borrow_mut().push(name.to_owned());
            None
        };
        assert_eq!(
            scouting_interface_addresses("192.0.2.7,wlan0", lookup),
            vec![ip("192.0.2.7")]
        );
        assert_eq!(*asked.borrow(), vec!["wlan0".to_owned()]);
    }
}
