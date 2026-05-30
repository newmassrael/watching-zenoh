// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311er — mode-agnostic locator parsing: `proto/addr:port` -> typed
//! `(Proto, SocketAddr)`.
//!
//! The single seam through which every scouting outcome reaches a
//! connectable target, independent of how it was discovered:
//! - active mode's `ScoutOutcome::Discovered(String)`
//!   (`wz-runtime-tokio::scouting_glue`), and
//! - static mode's `synth_static_locators(..) -> Vec<String>`
//!   ([`crate::scout_static`])
//!
//! both produce zenoh locator strings; `parse_locator` turns either into
//! the typed [`ParsedLocator`] a link-dial step consumes. Keeping the
//! parse here — pure, [`core::net`]-based, alloc-only — means the
//! mode-agnostic contract ("a discovered locator is a discovered
//! locator, regardless of mode") is enforced in one runtime-agnostic
//! place that compiles on the MCU static-deploy profile as well as AP.
//!
//! Distinct from `wz-codecs::locator`, which is the *wire* Locator codec
//! (a length-prefixed string field inside a Hello body). This module
//! operates one level up: it interprets that already-decoded string as a
//! transport endpoint.
//!
//! ## MVP scope
//!
//! Handles `tcp` / `udp` over a numeric [`SocketAddr`] (IPv4 `1.2.3.4:7447`
//! or IPv6 `[::1]:7447`). Deferred, surfaced as parse errors rather than
//! silently mis-parsed:
//! - DNS hostnames (`tcp/example.org:7447`) — resolution is an AP-side
//!   (`std`) concern, out of this no_std-compatible parse;
//! - locator metadata suffixes (`udp/1.2.3.4:7447#iface=eth0`) — the
//!   `#`-delimited config tail is not split here;
//! - non-IP transports (`unixsock-stream/...`, `serial/...`).

use alloc::string::{String, ToString};
use core::net::SocketAddr;
use core::str::FromStr;

/// Transport protocol of a locator. MVP set; extended as new link
/// drivers land (the catalog's transport domain).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    /// `tcp/...` — stream transport (`TcpDriver`).
    Tcp,
    /// `udp/...` — datagram transport (`UdpDriver`).
    Udp,
}

/// A locator parsed into its transport protocol and numeric endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedLocator {
    pub proto: Proto,
    pub addr: SocketAddr,
}

/// Why a locator string did not parse into a [`ParsedLocator`]. Each
/// variant carries enough context for the static-mode diagnostic
/// ("the configured locators are wrong", docs/scouting-fsm.md §2.4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocatorParseError {
    /// No `/` separating the protocol from the address.
    MissingProtoSeparator,
    /// The protocol token is not one of the supported transports.
    UnknownProto(String),
    /// The `addr:port` part is not a numeric [`SocketAddr`] (DNS names,
    /// metadata suffixes, and malformed addresses all land here).
    BadAddress(String),
}

/// Parse a zenoh locator `proto/addr:port` into a [`ParsedLocator`].
///
/// The protocol is the substring before the first `/`; everything after
/// it is parsed as a [`SocketAddr`]. See the module doc for the MVP
/// scope (numeric tcp/udp endpoints; DNS / metadata / other transports
/// are reported as errors, not silently accepted).
pub fn parse_locator(locator: &str) -> Result<ParsedLocator, LocatorParseError> {
    let (proto_str, addr_str) = locator
        .split_once('/')
        .ok_or(LocatorParseError::MissingProtoSeparator)?;
    let proto = match proto_str {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        other => return Err(LocatorParseError::UnknownProto(other.to_string())),
    };
    let addr = SocketAddr::from_str(addr_str)
        .map_err(|_| LocatorParseError::BadAddress(addr_str.to_string()))?;
    Ok(ParsedLocator { proto, addr })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_ipv4() {
        let p = parse_locator("tcp/192.168.1.10:7447").expect("valid tcp locator");
        assert_eq!(p.proto, Proto::Tcp);
        assert_eq!(p.addr, "192.168.1.10:7447".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parses_udp_ipv4() {
        let p = parse_locator("udp/127.0.0.1:7447").expect("valid udp locator");
        assert_eq!(p.proto, Proto::Udp);
        assert_eq!(p.addr.port(), 7447);
    }

    #[test]
    fn parses_ipv6_bracketed() {
        let p = parse_locator("tcp/[::1]:7447").expect("valid ipv6 locator");
        assert_eq!(p.proto, Proto::Tcp);
        assert_eq!(p.addr, "[::1]:7447".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn rejects_missing_separator() {
        assert_eq!(
            parse_locator("127.0.0.1:7447"),
            Err(LocatorParseError::MissingProtoSeparator)
        );
    }

    #[test]
    fn rejects_unknown_proto() {
        assert_eq!(
            parse_locator("ws/127.0.0.1:7447"),
            Err(LocatorParseError::UnknownProto("ws".to_string()))
        );
    }

    #[test]
    fn rejects_dns_hostname_as_bad_address() {
        // DNS resolution is deferred (AP/std concern) — a hostname is
        // not a numeric SocketAddr, so it surfaces as BadAddress.
        assert_eq!(
            parse_locator("tcp/example.org:7447"),
            Err(LocatorParseError::BadAddress(
                "example.org:7447".to_string()
            ))
        );
    }

    #[test]
    fn rejects_metadata_suffix_as_bad_address() {
        assert_eq!(
            parse_locator("udp/1.2.3.4:7447#iface=eth0"),
            Err(LocatorParseError::BadAddress(
                "1.2.3.4:7447#iface=eth0".to_string()
            ))
        );
    }

    #[test]
    fn rejects_out_of_range_port() {
        assert_eq!(
            parse_locator("tcp/1.2.3.4:99999"),
            Err(LocatorParseError::BadAddress("1.2.3.4:99999".to_string()))
        );
    }
}
