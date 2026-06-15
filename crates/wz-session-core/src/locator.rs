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

// ─── unified locator (IP | Serial) ───
//
// R311nv — the SERIAL link backend (`wz-runtime-tokio::serial_pipeline`)
// needs a `serial/...` locator to reach a dial seam alongside the IP
// `tcp`/`udp` endpoints. A `serial/...` target is NOT a numeric
// [`SocketAddr`] (it is a device path or a GPIO pin pair, with a baud
// rate), so it cannot be a [`Proto`] variant on [`ParsedLocator`]; it is a
// genuinely different endpoint shape. The textbook composition (the
// serial_link B7 seam note) is a sum type over the per-scheme leaves, NOT
// a third combined parser: [`AnyLocator`] holds the leaf output, and
// [`parse_any_locator`] is a thin scheme-dispatcher delegating to
// [`parse_locator`] (IP) or [`crate::serial_link::parse_serial_locator`]
// (serial). Each leaf keeps its own scheme re-check, so a mis-routed
// string still errors in-leaf.

/// A locator parsed into its transport endpoint, across every link
/// transport. The scheme-dispatch sum type whose arms are the outputs of
/// the per-scheme parse leaves; [`parse_any_locator`] builds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyLocator {
    /// An IP endpoint (`tcp/...` / `udp/...`) — see [`ParsedLocator`].
    Ip(ParsedLocator),
    /// A serial endpoint (`serial/...`) — see
    /// [`crate::serial_link::SerialEndpoint`]. Present only when the host
    /// can carry serial (the `transport-link-serial` feature gates the
    /// whole `serial_link` leaf); without it a `serial/...` string surfaces
    /// as [`LocatorParseError::UnknownProto`] through the IP leaf.
    #[cfg(feature = "transport-link-serial")]
    Serial(crate::serial_link::SerialEndpoint),
}

/// Why a locator string did not parse into an [`AnyLocator`] — the
/// composed error over the per-scheme leaf errors (serial_link B7 seam
/// note: `enum { Ip(LocatorParseError), Serial(SerialLocatorError) }`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyLocatorError {
    /// The IP leaf ([`parse_locator`]) rejected the string. Also the home
    /// of an unknown scheme (e.g. `serial/...` with the serial leaf not
    /// compiled in) via [`LocatorParseError::UnknownProto`].
    Ip(LocatorParseError),
    /// The serial leaf ([`crate::serial_link::parse_serial_locator`])
    /// rejected a `serial/...` string.
    #[cfg(feature = "transport-link-serial")]
    Serial(crate::serial_link::SerialLocatorError),
}

/// Parse any zenoh locator string into an [`AnyLocator`], dispatching on
/// the scheme (the substring before the first `/`) to the matching leaf.
///
/// `serial/...` routes to [`crate::serial_link::parse_serial_locator`] when
/// the `transport-link-serial` feature is on; everything else (and, with
/// the feature off, `serial/...` too) routes to the IP leaf
/// [`parse_locator`], which reports an unknown scheme as
/// [`LocatorParseError::UnknownProto`]. This is the single seam through
/// which the session-open path turns a discovered / configured locator into
/// a dialable endpoint, regardless of transport.
pub fn parse_any_locator(locator: &str) -> Result<AnyLocator, AnyLocatorError> {
    #[cfg(feature = "transport-link-serial")]
    if matches!(locator.split_once('/'), Some(("serial", _))) {
        return crate::serial_link::parse_serial_locator(locator)
            .map(AnyLocator::Serial)
            .map_err(AnyLocatorError::Serial);
    }
    parse_locator(locator)
        .map(AnyLocator::Ip)
        .map_err(AnyLocatorError::Ip)
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

    // ─── unified scheme-dispatcher ───

    #[test]
    fn parse_any_routes_ip_to_the_ip_leaf() {
        let any = parse_any_locator("tcp/192.168.1.10:7447").expect("ip locator");
        assert_eq!(
            any,
            AnyLocator::Ip(parse_locator("tcp/192.168.1.10:7447").unwrap())
        );
    }

    #[test]
    fn parse_any_propagates_ip_leaf_error() {
        // A malformed IP address surfaces the IP leaf error verbatim,
        // wrapped in the AnyLocator composition.
        assert_eq!(
            parse_any_locator("tcp/example.org:7447"),
            Err(AnyLocatorError::Ip(LocatorParseError::BadAddress(
                "example.org:7447".to_string()
            )))
        );
    }

    #[cfg(feature = "transport-link-serial")]
    #[test]
    fn parse_any_routes_serial_to_the_serial_leaf() {
        use crate::serial_link::{parse_serial_locator, SerialLocatorError};
        let any = parse_any_locator("serial//dev/ttyUSB0#baudrate=115200").expect("serial locator");
        assert_eq!(
            any,
            AnyLocator::Serial(
                parse_serial_locator("serial//dev/ttyUSB0#baudrate=115200").unwrap()
            )
        );
        // And the serial leaf error composes through too.
        assert_eq!(
            parse_any_locator("serial//dev/ttyUSB0"),
            Err(AnyLocatorError::Serial(SerialLocatorError::MissingBaudrate))
        );
    }

    #[cfg(not(feature = "transport-link-serial"))]
    #[test]
    fn parse_any_serial_without_feature_is_unknown_proto() {
        // With the serial leaf not compiled in, a serial/... string falls to
        // the IP leaf, which reports it as an unknown scheme.
        assert_eq!(
            parse_any_locator("serial//dev/ttyUSB0#baudrate=115200"),
            Err(AnyLocatorError::Ip(LocatorParseError::UnknownProto(
                "serial".to_string()
            )))
        );
    }
}
