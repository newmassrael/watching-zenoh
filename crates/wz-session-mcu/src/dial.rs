// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2831 (§5.23 `adminspace-write`) — the MCU node's dialer: what makes a
//! `udp/<ip>:<port>` endpoint in the connection control a live session.
//!
//! [`crate::connect_manager::ConnectManager`] decides WHEN to dial; this
//! module is the [`crate::connect_manager::Dialer`] that does it. A dial asks
//! the network stack, through `wz_runtime_coop::session_drive::SessionLinks`, for a link towards the endpoint
//! and spawns an INITIATOR session onto the firmware's local task set with
//! `wz_runtime_coop::session_drive::spawn_session` — the same call a deploy
//! `main()` writes for its one configured peer, so a written endpoint and a
//! compiled-in one are the same kind of session.
//!
//! R2835-era this was written on lwIP and named for it. Nothing in it is lwIP's
//! but the four lines that open a socket, so the socket is now the stack's
//! (`wz_runtime_coop::session_drive::SessionLinks::open_initiator`) and the rest is written once: a board whose
//! network is Zephyr's sockets dials a written endpoint with the same code a
//! board on lwIP does.
//!
//! ## What this build can dial
//!
//! UDP and TCP over IPv4 or IPv6, by address, as far as the node's stack has the link:
//! an endpoint is read into a [`Locator`] here, and a stack with no link of its
//! protocol (an lwIP image asked for `tcp/`) refuses it as `Unsupported`. A stack
//! built without IPv6 says so (`Bind::IPV6`, `SessionLinks::IPV6`): its endpoints are
//! read by [`parse_locator_for`], which refuses a bracketed address as `Unsupported`,
//! as the stack's socket would refuse the family, and its image holds the IPv4 reader
//! alone.
//!
//! An endpoint with another scheme, or one that carries upstream's `?metadata` /
//! `#config` parts, is refused as `Unsupported` too: this link honours
//! neither, and dialling it anyway would quietly drop what the writer asked
//! for. A host name is refused as `BadAddress`, since the node has no resolver.
//! All three are permanent for the text, which is why the manager does not
//! retry them; a TCP connection the other end refused is retried.
//!
//! ## How an ended session is read
//!
//! A session has ended when its task has finished. Whether it had been
//! established is remembered from the session's own
//! `SessionLinkActions::is_established`, sampled each time the manager asks,
//! and that is the one approximation here: a session that establishes and
//! drops between two ticks of the manager reads as never established, so its
//! re-dial continues the old outage's period instead of starting a fresh one.
//! It errs towards waiting longer, never towards dialling harder.

use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use wz_runtime_coop::session_drive::{LinkOpenError, LinkProto, Locator};
use wz_runtime_coop::{CoopRuntime, CoopTime};
use wz_session_core::session_actions::SessionLinkActions;

use crate::connect_manager::{DialFailed, DialRefused};

// What reads an endpoint, and the type of a session's action bundle, is written once
// for every profile. The dialler that OPENS a link and spawns a session is the
// growable profile's (`Rc` handles, a boxed sink per dial, links opened through
// `SessionLinks`); the slot profile's is `wz_session_lwip::slot_node::SlotDialer`,
// over the session host, whose tables the image declared (fixed-memory step S9c).
#[cfg(not(feature = "session-slot"))]
pub use heap::*;

/// The action bundle of one MCU session.
pub type McuActions<C> = SessionLinkActions<CoopRuntime<C>, CoopTime<C>>;

/// Read `udp/<a.b.c.d>:<port>`, `tcp/[<ipv6>]:<port>`, `tls/...` into the locator it
/// names: an IPv4 address or a bracketed IPv6 one, as zenoh writes them. A port of 0 names
/// nothing to dial.
pub fn parse_locator(endpoint: &str) -> Result<Locator, DialRefused> {
    parse_endpoint::<true>(endpoint, false)
}

/// [`parse_locator`] for a stack that opens IPv6 links only when `ipv6` says so, its
/// `Bind::IPV6` or `SessionLinks::IPV6`. With `false` a bracketed address is refused as
/// [`DialRefused::Unsupported`], which is what the stack's socket would answer for the family,
/// whether or not the text is a well-formed IPv6 address; every other text reads as
/// [`parse_locator`] reads it. Always inlined, so that the stack's constant picks one reader where
/// it is called and an image of a stack without IPv6 links no reader of IPv6 text.
#[inline(always)]
pub fn parse_locator_for(endpoint: &str, ipv6: bool) -> Result<Locator, DialRefused> {
    if ipv6 {
        parse_endpoint::<true>(endpoint, false)
    } else {
        parse_endpoint::<false>(endpoint, false)
    }
}

/// Read the locator of a port to listen on: [`parse_locator`]'s text, where a port of 0 is
/// the stack's to choose and the locator it is bound to then names the port it chose.
pub fn parse_listen_locator(endpoint: &str) -> Result<Locator, DialRefused> {
    parse_endpoint::<true>(endpoint, true)
}

/// An endpoint's text, read for a stack that opens IPv6 links when `IPV6` is true.
fn parse_endpoint<const IPV6: bool>(
    endpoint: &str,
    any_port: bool,
) -> Result<Locator, DialRefused> {
    let Some((proto, rest)) = [LinkProto::Udp, LinkProto::Tcp, LinkProto::Tls]
        .into_iter()
        .find_map(|proto| {
            let rest = endpoint.strip_prefix(proto.scheme())?.strip_prefix('/')?;
            Some((proto, rest))
        })
    else {
        return Err(DialRefused::Unsupported);
    };
    if rest.bytes().any(|b| b == b'?' || b == b'#') {
        return Err(DialRefused::Unsupported);
    }
    // The address is a socket address's text, as zenoh resolves a locator's address
    // (`io/zenoh-link-commons/src/lib.rs` @ `pub async fn get_ip_addrs(`): `a.b.c.d:port`, or an
    // IPv6 address in brackets, `[x:y::z]:port` with a numeric `%scope` inside them, which is
    // the text zenoh-pico takes the host out of too (`vendor/zenoh-pico/src/link/endpoint.c` @
    // `char *_z_endpoint_parse_host(`). A name the node has no resolver for is refused.
    //
    // A socket address's text is IPv6's when it opens with a bracket and IPv4's otherwise, as
    // `SocketAddr`'s own reader tells them apart, so each family is read by its own reader, which
    // a stack without IPv6 never reaches for the bracketed form.
    let at = if rest.starts_with('[') {
        if !IPV6 {
            return Err(DialRefused::Unsupported);
        }
        SocketAddr::V6(socket_addr_v6(rest.as_bytes()).ok_or(DialRefused::BadAddress)?)
    } else {
        SocketAddr::V4(socket_addr_v4(rest.as_bytes()).ok_or(DialRefused::BadAddress)?)
    };
    if at.port() == 0 && !any_port {
        return Err(DialRefused::BadAddress);
    }
    Ok(Locator { proto, at })
}

/// `a.b.c.d:port` read as `SocketAddrV4`'s `FromStr` reads it, in one pass over the bytes: four
/// decimal octets of one to three digits, none above 255 and none written with a leading zero (an
/// octet `010` is octal to C's `inet_aton`, so it is one text two readers would take for different
/// addresses), then `:` and a port of decimal digits, leading zeros taken, none above 65535.
/// `None` for anything else.
///
/// Written here rather than taken from `core::net`, whose reader is one parser for both families
/// and every radix, some 1.5 KB of an image's text; a stack without IPv6 needs this grammar alone.
/// `the_ipv4_reader_reads_what_core_reads` holds the two to the same answer for every text.
fn socket_addr_v4(text: &[u8]) -> Option<SocketAddrV4> {
    let (octets, used) = ipv4_address(text)?;
    let port = decimal(text[used..].strip_prefix(b":")?, u32::from(u16::MAX))?;
    Some(SocketAddrV4::new(
        Ipv4Addr::from(octets),
        u16::try_from(port).ok()?,
    ))
}

/// `[address%scope]:port` read as `SocketAddrV6`'s `FromStr` reads it: an IPv6 address in
/// brackets ([`ipv6_address`]), a scope of decimal digits after `%` inside them (leading zeros
/// taken, none above `u32::MAX`), then `:` and a port as the IPv4 reader reads one. `None` for
/// anything else.
///
/// Written here for the reason [`socket_addr_v4`] is: `core::net`'s reader of this text brings
/// its reader of every family and radix (some 3 KB of an image's text).
/// `the_ipv6_reader_reads_what_core_reads` holds the two to the same answer for every text.
fn socket_addr_v6(text: &[u8]) -> Option<SocketAddrV6> {
    let text = text.strip_prefix(b"[")?;
    let (groups, used) = ipv6_address(text)?;
    let mut rest = &text[used..];
    let mut scope = 0;
    if let Some(after) = rest.strip_prefix(b"%") {
        let digits = after
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        scope = decimal(&after[..digits], u32::MAX)?;
        rest = &after[digits..];
    }
    let port = decimal(rest.strip_prefix(b"]:")?, u32::from(u16::MAX))?;
    Some(SocketAddrV6::new(
        Ipv6Addr::from(groups),
        u16::try_from(port).ok()?,
        0,
        scope,
    ))
}

/// The IPv6 address at the front of `text` as `core::net` reads one, and the bytes it took:
/// up to eight groups, and when fewer, `::` and the rest, the groups `::` stands for being
/// zeros. An embedded IPv4 address closes the groups after `::`, or all eight without it.
fn ipv6_address(text: &[u8]) -> Option<([u16; 8], usize)> {
    let mut head = [0u16; 8];
    let (head_size, head_ipv4, mut used) = ipv6_groups(text, &mut head);
    if head_size == head.len() {
        return Some((head, used));
    }
    if head_ipv4 || text.get(used..used + 2) != Some(b"::".as_slice()) {
        return None;
    }
    used += 2;
    // `::` stands for one group at least, so the groups after it are seven at most.
    let mut tail = [0u16; 7];
    let limit = head.len() - (head_size + 1);
    let (tail_size, _, tail_used) = ipv6_groups(&text[used..], &mut tail[..limit]);
    head[head.len() - tail_size..].copy_from_slice(&tail[..tail_size]);
    Some((head, used + tail_used))
}

/// One run of an IPv6 address's groups at the front of `text`, as `core::net` reads one: up to
/// `groups.len()` groups of one to four hexadecimal digits, `:` between two, the last two of
/// which may be written as an IPv4 address. Answers how many groups it read, whether an IPv4
/// address closed them, and the bytes it took; a separator that no group follows is not taken.
fn ipv6_groups(text: &[u8], groups: &mut [u16]) -> (usize, bool, usize) {
    let limit = groups.len();
    let mut used = 0;
    for index in 0..limit {
        let start = if index == 0 {
            used
        } else if text.get(used) == Some(&b':') {
            used + 1
        } else {
            return (index, false, used);
        };
        if index + 1 < limit {
            if let Some((octets, taken)) = ipv4_address(&text[start..]) {
                groups[index] = u16::from_be_bytes([octets[0], octets[1]]);
                groups[index + 1] = u16::from_be_bytes([octets[2], octets[3]]);
                return (index + 2, true, start + taken);
            }
        }
        let digits = text[start..]
            .iter()
            .take_while(|byte| byte.is_ascii_hexdigit())
            .count();
        if digits == 0 || digits > 4 {
            return (index, false, used);
        }
        groups[index] = text[start..start + digits]
            .iter()
            .fold(0u16, |group, &byte| (group << 4) | hex_digit(byte));
        used = start + digits;
    }
    (limit, false, used)
}

/// The IPv4 address at the front of `text` as `core::net` reads one, and the bytes it took: four
/// octets of one to three decimal digits, `.` between two, none above 255 and none written with
/// a leading zero. A fourth digit in an octet refuses the address. [`socket_addr_v4`] reads one
/// before its port and [`ipv6_groups`] one as an IPv6 address's last two groups.
fn ipv4_address(text: &[u8]) -> Option<([u8; 4], usize)> {
    let mut octets = [0u8; 4];
    let mut used = 0;
    for (index, octet) in octets.iter_mut().enumerate() {
        if index > 0 {
            if text.get(used) != Some(&b'.') {
                return None;
            }
            used += 1;
        }
        let digits = text[used..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        let field = &text[used..used + digits];
        if digits > 3 || (digits > 1 && field[0] == b'0') {
            return None;
        }
        *octet = u8::try_from(decimal(field, u32::from(u8::MAX))?).ok()?;
        used += digits;
    }
    Some((octets, used))
}

/// The value of one ASCII hexadecimal digit, either case.
fn hex_digit(byte: u8) -> u16 {
    u16::from(match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => byte - b'A' + 10,
    })
}

/// `text` as decimal digits only (`str::parse` would also take a leading `+`), at most `max`:
/// `None` for an empty text, another byte, or a number above `max`. One reader for the octets,
/// the port and the scope, where a generic `str::parse` is a copy of the integer reader for each
/// width. The sum is kept in 64 bits, so a `max` of `u32::MAX` cannot overflow it.
fn decimal(text: &[u8], max: u32) -> Option<u32> {
    if text.is_empty() {
        return None;
    }
    let mut value = 0u64;
    for &byte in text {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value * 10 + u64::from(byte - b'0');
        if value > u64::from(max) {
            return None;
        }
    }
    u32::try_from(value).ok()
}

/// What a stack's refusal to open a link means for the dial: a protocol it has
/// no link for is permanent for the endpoint, and an end that did not take the
/// link or a stack with nothing left to give is a failed attempt of the outage.
pub fn dial_failed(refused: LinkOpenError) -> DialFailed {
    match refused {
        LinkOpenError::Unsupported => DialFailed::Refused(DialRefused::Unsupported),
        LinkOpenError::Refused => DialFailed::Unreachable,
        LinkOpenError::Exhausted => DialFailed::Exhausted,
    }
}

#[cfg(not(feature = "session-slot"))]
mod heap {
    use alloc::boxed::Box;
    use alloc::rc::Rc;

    use wz_runtime_coop::session_drive::{
        spawn_session, OpenedLink, SessionDriveConfig, SessionLinks, SessionRole,
    };
    use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopTime};
    use wz_session_core::close_reason::CloseReason;
    use wz_session_core::driver_loop::{DriverOutcome, IterationEvent};
    use wz_session_core::session_init_params::SessionInitParams;
    use wz_session_core::session_timeouts::SessionTimeouts;

    use super::{dial_failed, parse_locator_for, DialRefused, McuActions};
    use crate::connect_manager::{DialFailed, Dialer, Ended};
    use wz_session_core::locator_directory::DirectoryZid;

    /// What a dialled session reports its iterations to — typically
    /// `crate::app_layer::dispatch_to` over the node's observer.
    pub type EventSink = Box<dyn FnMut(IterationEvent<'_, '_>)>;

    /// A session this dialer started.
    pub struct UdpSession<C: ClockSource + 'static> {
        handle: CoopLocalJoinHandle<DriverOutcome>,
        actions: Rc<McuActions<C>>,
        established: bool,
    }

    impl<C: ClockSource + 'static> UdpSession<C> {
        /// The session's action bundle, to publish or declare through.
        pub fn actions(&self) -> &Rc<McuActions<C>> {
            &self.actions
        }

        /// End the session's task now, without a Close on the wire. A test that
        /// must see a session end uses it; the manager hangs up through the
        /// [`Dialer`], which tells an established peer first.
        pub fn abort(&self) {
            self.handle.abort();
        }

        /// R2834 (§5.23 `adminspace-core`) — this session as a `sessions[]` entry
        /// of the node's admin GET, or `None` while it is not established.
        ///
        /// Upstream lists transports, and a transport exists only once its
        /// handshake has finished, so a session still dialling is not reported.
        /// The role is read off the wire through `WhatAmI::from_wire`; a role that
        /// never arrived stays `None`, which the answerer renders as upstream's
        /// `"unknown"`. SHM and the router link weight are `false` / `None`: this
        /// build has neither, which is what those values say.
        ///
        /// A firmware reports its dialled sessions each time round its loop with
        /// `NodeStatus::set_sessions`, collecting this over
        /// `ConnectManager::sessions`.
        #[cfg(feature = "adminspace-core")]
        pub fn admin_session(&self) -> Option<wz_admin::adminspace::AdminSession> {
            admin_session_of(&self.actions)
        }
    }

    /// R2837 — any MCU session as a `sessions[]` entry, dialled or accepted:
    /// `None` until it is established. What `UdpSession::admin_session` reports,
    /// for a session this dialer did not start (the node's acceptor).
    #[cfg(feature = "adminspace-core")]
    pub fn admin_session_of<C: ClockSource + 'static>(
        actions: &McuActions<C>,
    ) -> Option<wz_admin::adminspace::AdminSession> {
        use wz_admin::adminspace::SessionAdminRow;

        if !actions.is_established() {
            return None;
        }
        // R2860 — the row constructor the host runtimes share, so `links`, `shm`
        // and `region` are computed here exactly as they are there. An MCU session
        // holds no router graph, so it reports no weight.
        Some(
            actions.admin_session(
                actions
                    .peer_zid()
                    .map(|zid| wz_session_core::zid_hex::zid_to_zenoh_hex(&zid))
                    .unwrap_or_default(),
                actions
                    .peer_whatami_wire()
                    .and_then(wz_session_core::WhatAmI::from_wire)
                    .map(|role| alloc::string::String::from(role.to_str())),
                None,
            ),
        )
    }

    /// Dials UDP endpoints as initiator sessions on the firmware's task set, over
    /// whichever network stack `L` is.
    ///
    /// `params` is asked for a fresh [`SessionInitParams`] per dial, so each
    /// session can carry its own initial sequence number and cookie; `on_event`
    /// is asked for the sink each new session reports to.
    pub struct UdpDialer<'a, L, C, P, E>
    where
        L: SessionLinks,
        C: ClockSource + 'static,
        P: FnMut() -> SessionInitParams,
        E: FnMut(&Rc<McuActions<C>>) -> EventSink,
    {
        local: &'a CoopLocalSet<C>,
        links: Rc<L>,
        timeouts: SessionTimeouts,
        max_iters: Option<usize>,
        params: P,
        on_event: E,
    }

    impl<'a, L, C, P, E> UdpDialer<'a, L, C, P, E>
    where
        L: SessionLinks,
        C: ClockSource + 'static,
        P: FnMut() -> SessionInitParams,
        E: FnMut(&Rc<McuActions<C>>) -> EventSink,
    {
        /// A dialer spawning onto `local`, over `links`, with the handshake
        /// deadlines `timeouts`.
        pub fn new(
            local: &'a CoopLocalSet<C>,
            links: Rc<L>,
            timeouts: SessionTimeouts,
            params: P,
            on_event: E,
        ) -> Self {
            Self {
                local,
                links,
                timeouts,
                max_iters: None,
                params,
                on_event,
            }
        }

        /// Cap every session's iterations, for a test that must terminate.
        pub fn with_max_iters(mut self, max_iters: usize) -> Self {
            self.max_iters = Some(max_iters);
            self
        }

        /// One dial, made for the node `expected_zid` or for no node. The expectation is set
        /// before the session is spawned, so the handshake reads it at the InitAck.
        fn dial_expecting(
            &mut self,
            endpoint: &str,
            expected_zid: Option<DirectoryZid>,
        ) -> Result<UdpSession<C>, DialFailed> {
            let to = parse_locator_for(endpoint, L::IPV6).map_err(DialFailed::Refused)?;
            // The stack picks the local port, one per session, and may have none
            // left to give: that is a failed attempt of this outage, not a refusal.
            let OpenedLink { sink, pump } = self.links.open_initiator(to).map_err(dial_failed)?;
            let runtime = self.local.runtime();
            let actions =
                McuActions::<C>::new_generic(sink, (self.params)(), CoopTime::new(runtime));
            if let Some(zid) = expected_zid {
                actions.expect_peer_zid(zid);
            }
            let on_event = (self.on_event)(&actions);
            let handle = spawn_session(
                self.local,
                pump,
                actions.clone(),
                CoopTime::new(runtime),
                SessionDriveConfig {
                    timeouts: self.timeouts,
                    role: SessionRole::Initiator,
                    max_iters: self.max_iters,
                },
                on_event,
            );
            Ok(UdpSession {
                handle,
                actions,
                established: false,
            })
        }
    }

    impl<'a, L, C, P, E> Dialer for UdpDialer<'a, L, C, P, E>
    where
        L: SessionLinks,
        C: ClockSource + 'static,
        P: FnMut() -> SessionInitParams,
        E: FnMut(&Rc<McuActions<C>>) -> EventSink,
    {
        type Session = UdpSession<C>;

        fn classify(endpoint: &str) -> Result<(), DialRefused> {
            parse_locator_for(endpoint, L::IPV6).map(|_| ())
        }

        /// The session's handshake holds a dial made for a node to that node: the InitAck must
        /// carry its zid, or the session closes before the OpenSyn (decision D4), so a node may
        /// be opened by its zid over this dialer.
        const VERIFIES_NODES: bool = true;

        fn dial(&mut self, endpoint: &str) -> Result<Self::Session, DialFailed> {
            // A configured endpoint names no node, as upstream's `connect/endpoints` does not.
            self.dial_expecting(endpoint, None)
        }

        fn dial_for(
            &mut self,
            endpoint: &str,
            node: &DirectoryZid,
        ) -> Result<Self::Session, DialFailed> {
            self.dial_expecting(endpoint, Some(*node))
        }

        fn established(&mut self, session: &mut Self::Session) -> bool {
            session.established |= session.actions.is_established();
            session.established
        }

        fn remote(
            &self,
            session: &Self::Session,
        ) -> Option<[u8; wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES]> {
            session.actions.peer_zid_array()
        }

        fn ended(&mut self, session: &mut Self::Session) -> Option<Ended> {
            session.established |= session.actions.is_established();
            if !session.handle.is_finished() {
                return None;
            }
            Some(if session.established {
                Ended::AfterEstablished
            } else {
                Ended::BeforeEstablished
            })
        }

        fn hang_up(&mut self, session: Self::Session) {
            // An established peer is told; a half-open one has nothing to close.
            if session.actions.is_established() {
                session.actions.send_close_with_reason(CloseReason::Generic);
            }
            session.handle.abort();
        }
    }
}

// The endpoint parser is shared by both profiles' diallers, so its cases run on both.
#[cfg(test)]
mod parse_tests {
    use super::*;
    use core::str::FromStr;

    /// An IPv6 address is read in the brackets zenoh writes it in, with a numeric scope inside
    /// them, on every scheme; the same address without brackets, an empty pair, a named scope and
    /// a bracketed IPv4 address are not a socket address's text and are refused.
    #[test]
    fn udp_tcp_or_tls_to_a_bracketed_ipv6_address_is_dialable() {
        use core::net::{Ipv6Addr, SocketAddrV6};
        let loopback = SocketAddr::from((Ipv6Addr::LOCALHOST, 7447));
        std::assert_eq!(parse_locator("tcp/[::1]:7447"), Ok(Locator::tcp(loopback)));
        std::assert_eq!(parse_locator("tls/[::1]:7447"), Ok(Locator::tls(loopback)));
        std::assert_eq!(
            parse_locator("udp/[ff02::1]:7446"),
            Ok(Locator::udp(SocketAddr::from((
                Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
                7446
            ))))
        );
        std::assert_eq!(
            parse_locator("udp/[fe80::1%3]:7447"),
            Ok(Locator::udp(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                7447,
                0,
                3
            ))))
        );
        std::assert_eq!(
            parse_listen_locator("tcp/[::]:0"),
            Ok(Locator::tcp(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))))
        );
        for (text, why) in [
            ("tcp/::1:7447", DialRefused::BadAddress),
            ("tcp/[]:7447", DialRefused::BadAddress),
            ("tcp/[::1]", DialRefused::BadAddress),
            ("tcp/[::1]:0", DialRefused::BadAddress),
            ("tcp/[fe80::1%eth0]:7447", DialRefused::BadAddress),
            ("tcp/[127.0.0.1]:7447", DialRefused::BadAddress),
            ("tcp/[::1]:7447?prio=1", DialRefused::Unsupported),
            ("udp/[::1]:7447#iface=eth0", DialRefused::Unsupported),
        ] {
            std::assert_eq!(parse_locator(text), Err(why), "{text}");
        }
    }

    #[test]
    fn udp_tcp_or_tls_to_an_ipv4_address_is_dialable() {
        let at = SocketAddr::from(([127, 0, 0, 1], 7447));
        std::assert_eq!(parse_locator("udp/127.0.0.1:7447"), Ok(Locator::udp(at)));
        std::assert_eq!(parse_locator("tcp/127.0.0.1:7447"), Ok(Locator::tcp(at)));
        // Whether a stack carries the secure channel is the stack's to say, not the parser's.
        std::assert_eq!(parse_locator("tls/127.0.0.1:7447"), Ok(Locator::tls(at)));
        for (text, why) in [
            ("quic/127.0.0.1:7447", DialRefused::Unsupported),
            ("tlsx/127.0.0.1:7447", DialRefused::Unsupported),
            ("tls/127.0.0.1:7447?prio=1", DialRefused::Unsupported),
            ("tcp/127.0.0.1:7447?prio=1", DialRefused::Unsupported),
            ("tcp/router.local:7447", DialRefused::BadAddress),
            ("udp/127.0.0.1:7447#iface=eth0", DialRefused::Unsupported),
            ("udp/127.0.0.1:7447?prio=1", DialRefused::Unsupported),
            ("udp/router.local:7447", DialRefused::BadAddress),
            ("udp/127.0.0.1", DialRefused::BadAddress),
            ("udp/127.0.0.1:0", DialRefused::BadAddress),
            ("udp/127.0.0.1:+80", DialRefused::BadAddress),
            ("udp/127.0.0.256:7447", DialRefused::BadAddress),
            ("udp/127.0.0.1.5:7447", DialRefused::BadAddress),
            ("udp/127.0.0:7447", DialRefused::BadAddress),
            ("udp/127.0.0.:7447", DialRefused::BadAddress),
            ("udp/.127.0.0.1:7447", DialRefused::BadAddress),
            ("udp/127..0.1:7447", DialRefused::BadAddress),
            ("udp/127.0.0.1:", DialRefused::BadAddress),
            ("udp/:7447", DialRefused::BadAddress),
            ("udp/127.0.0.1:65536", DialRefused::BadAddress),
            (
                "udp/127.0.0.1:99999999999999999999",
                DialRefused::BadAddress,
            ),
            ("udp/127.0.0.1:-1", DialRefused::BadAddress),
            ("udp/+1.0.0.1:7447", DialRefused::BadAddress),
            ("udp/1.0.0.9999999999:7447", DialRefused::BadAddress),
            ("udp//127.0.0.1:7447", DialRefused::BadAddress),
            ("udp", DialRefused::Unsupported),
            ("", DialRefused::Unsupported),
        ] {
            std::assert_eq!(parse_locator(text), Err(why), "{text}");
        }
    }

    /// The numbers the reader takes: the widest of each, and leading zeros in the port but not in
    /// an octet, as a socket address's text is read (and as the host's parser reads a locator,
    /// `wz_session_core::locator::parse_locator`): `010` is octal to C's `inet_aton`, so an
    /// octet written that way is one text two readers would take for different addresses.
    #[test]
    fn the_widest_numbers_and_a_ports_leading_zeros_are_read() {
        let at = |addr: [u8; 4], port| SocketAddr::from((addr, port));
        std::assert_eq!(
            parse_locator("udp/255.255.255.255:65535"),
            Ok(Locator::udp(at([255; 4], 65535)))
        );
        std::assert_eq!(
            parse_locator("udp/1.2.3.4:00080"),
            Ok(Locator::udp(at([1, 2, 3, 4], 80)))
        );
        std::assert_eq!(
            parse_locator("udp/001.002.003.004:80"),
            Err(DialRefused::BadAddress)
        );
        std::assert_eq!(
            parse_locator("tcp/0.0.0.0:1"),
            Ok(Locator::tcp(at([0; 4], 1)))
        );
        std::assert_eq!(
            parse_listen_locator("udp/10.0.0.1:0"),
            Ok(Locator::udp(at([10, 0, 0, 1], 0)))
        );
    }

    #[test]
    fn a_stacks_refusal_is_permanent_only_for_a_protocol_it_lacks() {
        std::assert_eq!(
            dial_failed(LinkOpenError::Unsupported),
            DialFailed::Refused(DialRefused::Unsupported)
        );
        std::assert_eq!(dial_failed(LinkOpenError::Refused), DialFailed::Unreachable);
        std::assert_eq!(dial_failed(LinkOpenError::Exhausted), DialFailed::Exhausted);
    }

    /// The IPv4 reader takes exactly the texts `SocketAddrV4`'s `FromStr` takes, as the same
    /// address and port. Each field is drawn from texts on either side of every rule of the grammar
    /// (a leading zero, the widest value and one past it, a fourth digit, a sign, a letter, nothing),
    /// every combination is read both ways, and so is each malformed shape of the whole text.
    #[test]
    fn the_ipv4_reader_reads_what_core_reads() {
        const OCTETS: [&str; 14] = [
            "0", "00", "01", "7", "10", "99", "100", "255", "256", "999", "1000", "", "+1", "a",
        ];
        const PORTS: [&str; 11] = [
            "0",
            "00080",
            "7447",
            "65535",
            "065535",
            "65536",
            "99999999999999999999",
            "",
            "+80",
            "-1",
            "80 ",
        ];
        let same = |text: &str| {
            let ours = socket_addr_v4(text.as_bytes());
            std::assert_eq!(ours, SocketAddrV4::from_str(text).ok(), "{text:?}");
            ours.is_some()
        };
        let (mut taken, mut refused) = (0usize, 0usize);
        let mut count = |was_taken: bool| {
            if was_taken {
                taken += 1;
            } else {
                refused += 1;
            }
        };
        for a in OCTETS {
            for b in ["0", "255", "01", ""] {
                for c in OCTETS {
                    for d in OCTETS {
                        for port in PORTS {
                            count(same(std::format!("{a}.{b}.{c}.{d}:{port}").as_str()));
                        }
                    }
                }
            }
        }
        for text in [
            "1.2.3.4",
            "1.2.3:80",
            "1.2.3.4.5:80",
            "1..3.4:80",
            ".1.2.3:80",
            "1.2.3.4.:80",
            "1.2.3.4:",
            ":80",
            "1.2.3.4:80:80",
            "[1.2.3.4]:80",
            " 1.2.3.4:80",
            "1.2.3.4 :80",
            "1.2.3.4:8a0",
            "",
            "\u{0661}.2.3.4:80",
            "1.2.3.\u{0664}:80",
        ] {
            count(same(text));
        }
        std::assert!(
            taken > 0 && refused > 0,
            "the corpus reaches both answers: {taken} taken, {refused} refused"
        );
    }

    /// The IPv6 reader takes exactly the texts `SocketAddrV6`'s `FromStr` takes, as the same
    /// address, port and scope. The addresses are built on either side of every rule of the
    /// grammar (each count of groups before and after `::`, `::` twice, a fifth digit, either
    /// case, an embedded IPv4 address in each place and malformed), each is read with scopes and
    /// ports on either side of theirs, and so is each malformed shape of the brackets.
    #[test]
    fn the_ipv6_reader_reads_what_core_reads() {
        use std::string::String;
        use std::vec::Vec;
        const GROUPS: [&str; 9] = ["0", "1", "ffff", "FFFF", "0000", "00000", "1a2B", "g", ""];
        const IPV4: [&str; 8] = [
            "1.2.3.4",
            "255.255.255.255",
            "01.2.3.4",
            "1.2.3",
            "1.2.3.4.5",
            "256.1.1.1",
            "1234.1.1.1",
            "1.2.3.04",
        ];
        const SCOPES: [&str; 8] = [
            "",
            "%0",
            "%3",
            "%0003",
            "%4294967295",
            "%4294967296",
            "%",
            "%x",
        ];
        const PORTS: [&str; 7] = [":7447", ":0", ":065535", ":65536", ":", "", ":+1"];
        let same = |text: &str| {
            let ours = socket_addr_v6(text.as_bytes());
            std::assert_eq!(ours, SocketAddrV6::from_str(text).ok(), "{text:?}");
            ours.is_some()
        };
        let run = |n: usize, from: usize| -> String {
            (from..from + n)
                .map(|g| std::format!("{g:x}"))
                .collect::<Vec<_>>()
                .join(":")
        };
        let mut addresses: Vec<String> = Vec::new();
        for head in 0..=8 {
            addresses.push(run(head, 1));
            for tail in 0..=8 {
                addresses.push(std::format!("{}::{}", run(head, 1), run(tail, 10)));
            }
        }
        addresses.push(String::from("1::2::3"));
        addresses.push(String::from("1:::2"));
        addresses.push(String::from(":1:2:3:4:5:6:7:8"));
        addresses.push(String::from("1:2:3:4:5:6:7:8:"));
        for group in GROUPS {
            addresses.push(std::format!("{group}::1"));
            addresses.push(std::format!("1::{group}"));
            addresses.push(std::format!("{group}:1:2:3:4:5:6:7"));
            addresses.push(std::format!("1:2:3:4:5:6:7:{group}"));
        }
        for v4 in IPV4 {
            for shape in [
                "::{}",
                "::ffff:{}",
                "1:2:3:4:5:6:{}",
                "1:2:3:4:5:6:7:{}",
                "1:2:3:4:5::{}",
                "1:2:3:4:5:6::{}",
                "{}::1",
                "1::2:3:4:5:6:{}",
                "1::2:3:4:5:{}",
                "{}",
            ] {
                addresses.push(shape.replace("{}", v4));
            }
        }
        let (mut taken, mut refused) = (0usize, 0usize);
        let mut count = |was_taken: bool| {
            if was_taken {
                taken += 1;
            } else {
                refused += 1;
            }
        };
        for address in &addresses {
            for scope in SCOPES {
                for port in PORTS {
                    count(same(std::format!("[{address}{scope}]{port}").as_str()));
                }
            }
        }
        for text in [
            "::1]:80",
            "[::1:80",
            "[::1]]:80",
            "[[::1]:80",
            "[::1] :80",
            " [::1]:80",
            "[::1]:80 ",
            "[ ::1]:80",
            "[::1%3%4]:80",
            "[::1]:80:80",
            "[]:80",
            "[",
            "",
            "[\u{0661}::1]:80",
            "[::\u{00e9}]:80",
            "[::1]:\u{0668}0",
        ] {
            count(same(text));
        }
        std::assert!(
            taken > 0 && refused > 0,
            "the corpus reaches both answers: {taken} taken, {refused} refused"
        );
    }

    /// A stack without IPv6 reads an IPv4 endpoint as every stack does and refuses a bracketed
    /// address as one it never dials (`Unsupported`, the answer its socket gives the family),
    /// whether or not the text is a well-formed IPv6 address. A stack with IPv6 reads both as
    /// `parse_locator` reads them.
    #[test]
    fn a_stack_without_ipv6_refuses_a_bracketed_address_as_unsupported() {
        for text in [
            "udp/127.0.0.1:7447",
            "tcp/10.0.0.1:80",
            "tls/10.0.0.1:7447",
            "udp/127.0.0.1:0",
            "udp/router.local:7447",
            "udp/001.0.0.1:7447",
            "quic/1.2.3.4:5",
            "udp/1.2.3.4:5?prio=1",
        ] {
            std::assert_eq!(
                parse_locator_for(text, false),
                parse_locator(text),
                "{text}"
            );
            std::assert_eq!(parse_locator_for(text, true), parse_locator(text), "{text}");
        }
        for text in [
            "tcp/[::1]:7447",
            "udp/[fe80::1%3]:7447",
            "tcp/[]:7447",
            "tcp/[127.0.0.1]:7447",
            "tcp/[::1]:0",
        ] {
            std::assert_eq!(
                parse_locator_for(text, false),
                Err(DialRefused::Unsupported),
                "{text}"
            );
            std::assert_eq!(parse_locator_for(text, true), parse_locator(text), "{text}");
        }
        std::assert_eq!(
            parse_locator_for("tcp/[::1]:7447", true),
            Ok(Locator::tcp(SocketAddr::from((
                core::net::Ipv6Addr::LOCALHOST,
                7447
            ))))
        );
    }
}

// What these tests build is the heap dialler over the in-memory network, which the
// slot profile does not have.
#[cfg(all(test, not(feature = "session-slot")))]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::rc::Rc;
    use alloc::vec;

    use wz_runtime_coop::session_drive::{
        spawn_session, LinkOpenError, OpenedLink, SessionDriveConfig, SessionLinks, SessionRole,
    };
    use wz_runtime_coop::{ClockSource, CoopLocalSet};
    use wz_session_core::session_init_params::SessionInitParams;
    use wz_session_core::session_timeouts::SessionTimeouts;

    use crate::connect_manager::{DialFailed, Dialer, Ended};
    use crate::memory::{MemoryLinks, MemoryNetwork};

    const NODE: [u8; 4] = [10, 0, 0, 2];
    const FAR: [u8; 4] = [10, 0, 0, 1];

    #[derive(Clone, Default)]
    struct FrozenClock;
    impl ClockSource for FrozenClock {
        fn now_us(&self) -> u64 {
            0
        }
    }

    /// A deterministic stand-in for a board's TRNG.
    struct Counting(u8);
    impl wz_session_core::entropy::EntropySource for Counting {
        fn try_fill_bytes(
            &mut self,
            buf: &mut [u8],
        ) -> Result<(), wz_session_core::entropy::EntropyUnavailable> {
            for b in buf {
                self.0 = self.0.wrapping_add(1);
                *b = self.0;
            }
            Ok(())
        }
    }

    fn params(zid: u8) -> SessionInitParams {
        SessionInitParams {
            whatami: wz_session_core::WhatAmI::Peer,
            zid: [zid; 4].into(),
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 1024,
            lease_ms: 10_000,
            keep_alive: wz_session_core::session_init_params::KeepAliveConf::PICO,
            initial_sn: 0,
            cookie: vec![],
            tx_queue: wz_session_core::session_init_params::TxQueueConf::of_snapshot(
                &wz_session_core::policy::SessionPolicy::defaults(),
                &wz_session_core::limits::SessionLimits::BUILD,
            ),
            link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
            policy: wz_session_core::policy::SessionPolicy::defaults(),
            limits: wz_session_core::limits::SessionLimits::BUILD,
            cookie_signing_key: wz_session_core::signing_key::SigningKey::new(vec![7u8; 32])
                .expect("key"),
        }
    }

    fn quiet(_: &Rc<McuActions<FrozenClock>>) -> EventSink {
        Box::new(|_| {})
    }

    /// A dial opens a real session towards the endpoint: an acceptor on the
    /// same network completes the handshake with it, and once the session's
    /// task ends it reads as ended AFTER establishing. The control is a dial
    /// nobody answers, which ends BEFORE establishing.
    #[test]
    fn a_dialled_endpoint_becomes_an_established_session() {
        let net = MemoryNetwork::new();
        // The acceptor's host and the dialling node's are two hosts on one net.
        let far = Rc::new(MemoryLinks::new(net.clone(), FAR));
        let near = Rc::new(MemoryLinks::new(net.clone(), NODE));
        let runtime = CoopRuntime::new(FrozenClock);
        let local = CoopLocalSet::new(&runtime);

        // The acceptor the dial will reach.
        let OpenedLink {
            sink: acceptor_sink,
            pump: acceptor_pump,
        } = far.open_acceptor(7494).expect("bind acceptor");
        // An acceptor mints its cookie from a per-handshake nonce and refuses
        // to mint without an entropy source, so it is built through the seam
        // a board uses.
        let acceptor_actions = wz_runtime_coop::session_runtime::new_session_actions(
            acceptor_sink,
            params(0xa1),
            CoopTime::new(&runtime),
            Counting(1),
        );
        let _acceptor = spawn_session(
            &local,
            acceptor_pump,
            acceptor_actions.clone(),
            CoopTime::new(&runtime),
            SessionDriveConfig {
                timeouts: SessionTimeouts::from_build(),
                role: SessionRole::Acceptor,
                max_iters: None,
            },
            |_| {},
        );

        let mut dialer = UdpDialer::new(
            &local,
            near.clone(),
            SessionTimeouts::from_build(),
            || params(0xb1),
            quiet,
        );
        let mut session = dialer.dial("udp/10.0.0.1:7494").expect("dialable");
        for _ in 0..64 {
            local.run_until_idle();
            if session.actions().is_established() {
                break;
            }
        }
        std::assert!(
            session.actions().is_established(),
            "the handshake completed\ninitiator: {:?}\nacceptor: {:?}",
            session.actions().trace_snapshot(),
            acceptor_actions.trace_snapshot()
        );
        std::assert!(acceptor_actions.is_established(), "on both ends");
        std::assert_eq!(dialer.ended(&mut session), None, "still live");

        // R2834 — the established session reports the acceptor it reached,
        // as the admin GET's `sessions[]` entry.
        #[cfg(feature = "adminspace-core")]
        {
            let entry = session.admin_session().expect("established, so reported");
            std::assert_eq!(
                entry.peer_zid_hex,
                wz_session_core::zid_hex::zid_to_zenoh_hex(&[0xa1; 4])
            );
            std::assert_eq!(entry.whatami.as_deref(), Some("peer"));
            std::assert_eq!(entry.links.len(), 1, "one UDP link");
            // R2841 — the link's ends, as upstream renders them: the dialled
            // side's dst is the endpoint it was given; its src is the address
            // the node is on and the port the stack chose.
            std::assert_eq!(entry.links[0].dst, "udp/10.0.0.1:7494");
            std::assert!(
                entry.links[0].src.starts_with("udp/10.0.0.2:")
                    && !entry.links[0].src.ends_with(":0"),
                "src {:?}",
                entry.links[0].src
            );
            // ... and the accepting side names the same link from its end.
            let accepted = admin_session_of(&acceptor_actions).expect("established");
            std::assert_eq!(accepted.links[0].src, "udp/10.0.0.1:7494");
            std::assert_eq!(accepted.links[0].dst, entry.links[0].src);
        }

        session.abort();
        std::assert_eq!(dialer.ended(&mut session), Some(Ended::AfterEstablished));

        // CONTROL: nobody listens on 7495, and the capped session ends first.
        let mut unanswered = UdpDialer::new(
            &local,
            near.clone(),
            SessionTimeouts::from_build(),
            || params(0xc1),
            quiet,
        )
        .with_max_iters(8);
        let mut lost = unanswered.dial("udp/10.0.0.1:7495").expect("dialable");
        // R2834 — CONTROL: a session nobody answered is not reported.
        #[cfg(feature = "adminspace-core")]
        std::assert!(lost.admin_session().is_none());
        for _ in 0..16 {
            local.run_until_idle();
        }
        std::assert_eq!(unanswered.ended(&mut lost), Some(Ended::BeforeEstablished));

        std::assert!(matches!(
            unanswered.dial("tcp/127.0.0.1:7447"),
            Err(DialFailed::Refused(DialRefused::Unsupported))
        ));
    }

    /// Decision D4 on the heap dialer: a dial made FOR a node holds the session to that node.
    /// The acceptor on the net is node `0xa1`; a dial for it establishes, a dial for another
    /// zid closes at the InitAck and ends before establishing, and a dial that names no node
    /// (a configured endpoint) admits whichever node answers, as it did before.
    #[test]
    fn a_dial_for_a_node_holds_the_session_to_that_node() {
        use wz_session_core::close_reason::CloseReason;
        use wz_session_core::credential_identity::zid_from_wire;

        fn verifies_nodes<D: Dialer>(_: &D) -> bool {
            D::VERIFIES_NODES
        }

        let net = MemoryNetwork::new();
        let far = Rc::new(MemoryLinks::new(net.clone(), FAR));
        let near = Rc::new(MemoryLinks::new(net.clone(), NODE));
        let runtime = CoopRuntime::new(FrozenClock);
        let local = CoopLocalSet::new(&runtime);

        // Three acceptors, all node 0xa1, one per dial below.
        let mut acceptors = vec![];
        for port in [7494u16, 7495, 7496] {
            let OpenedLink { sink, pump } = far.open_acceptor(port).expect("bind acceptor");
            let actions = wz_runtime_coop::session_runtime::new_session_actions(
                sink,
                params(0xa1),
                CoopTime::new(&runtime),
                Counting(1),
            );
            let task = spawn_session(
                &local,
                pump,
                actions.clone(),
                CoopTime::new(&runtime),
                SessionDriveConfig {
                    timeouts: SessionTimeouts::from_build(),
                    role: SessionRole::Acceptor,
                    max_iters: None,
                },
                |_| {},
            );
            acceptors.push((actions, task));
        }

        let mut dialer = UdpDialer::new(
            &local,
            near.clone(),
            SessionTimeouts::from_build(),
            || params(0xb1),
            quiet,
        );
        std::assert!(
            verifies_nodes(&dialer),
            "the heap dialer holds a dial to its node, so a node may be opened over it"
        );
        let node_a1 = zid_from_wire(&[0xa1; 4]).expect("a zid");
        let node_other = zid_from_wire(&[0xa2; 4]).expect("a zid");

        let mut right = dialer
            .dial_for("udp/10.0.0.1:7494", &node_a1)
            .expect("dialable");
        let wrong = dialer
            .dial_for("udp/10.0.0.1:7495", &node_other)
            .expect("dialable");
        let unnamed = dialer.dial("udp/10.0.0.1:7496").expect("dialable");
        for _ in 0..64 {
            local.run_until_idle();
        }

        std::assert!(right.actions().is_established(), "the node it was made for");
        std::assert_eq!(dialer.ended(&mut right), None, "and stays up");
        std::assert!(
            !wrong.actions().is_established(),
            "a session to another node than the one asked for is not a session to the zid"
        );
        // Closed at the InitAck, before any OpenSyn, with upstream's reason for it. The task is
        // not asked whether it has ended: it sleeps to its next deadline, which a clock that
        // never moves does not bring, so it ends on a clock that does.
        std::assert_eq!(
            wrong.actions().close_reason(),
            Some(CloseReason::Invalid),
            "{:?}",
            wrong.actions().trace_snapshot()
        );
        std::assert_eq!(
            wrong.actions().trace_snapshot().send_open_syn,
            0,
            "no OpenSyn goes to a node that was not asked for"
        );
        std::assert!(
            right.actions().close_reason().is_none() && unnamed.actions().close_reason().is_none(),
            "the others were not closed"
        );
        std::assert!(
            unnamed.actions().is_established(),
            "a configured endpoint names no node and admits the one that answers"
        );
        right.abort();
        unnamed.abort();
    }

    /// A stack with no link left to give is a failed attempt of the outage, not
    /// a refusal: the manager waits and tries again.
    #[test]
    fn a_stack_with_no_link_left_makes_the_dial_exhausted_and_not_refused() {
        struct NoLinks;
        impl SessionLinks for NoLinks {
            type Pump = Rc<crate::memory::MemoryEnd>;
            fn open_acceptor(&self, _: u16) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
                Err(LinkOpenError::Exhausted)
            }
            fn open_initiator(&self, _: Locator) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
                Err(LinkOpenError::Exhausted)
            }
        }
        let runtime = CoopRuntime::new(FrozenClock);
        let local = CoopLocalSet::new(&runtime);
        let mut dialer = UdpDialer::new(
            &local,
            Rc::new(NoLinks),
            SessionTimeouts::from_build(),
            || params(0xd1),
            quiet,
        );
        std::assert!(matches!(
            dialer.dial("udp/10.0.0.1:7494"),
            Err(DialFailed::Exhausted)
        ));
        // And what is refused is refused before the stack is asked.
        std::assert!(matches!(
            dialer.dial("quic/10.0.0.1:7494"),
            Err(DialFailed::Refused(DialRefused::Unsupported))
        ));
    }
}
