// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311er — mode-agnostic locator parsing: a zenoh locator string -> a
//! typed transport endpoint ([`AnyLocator`], IP `(Proto, SocketAddr)` |
//! serial [`SerialEndpoint`]).
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
//! ## Scope
//!
//! Two leaves, dispatched by scheme through [`parse_any_locator`] into the
//! [`AnyLocator`] sum type:
//! - the IP leaf [`parse_locator`] — `tcp` / `udp` over a numeric
//!   [`SocketAddr`] (IPv4 `1.2.3.4:7447` or IPv6 `[::1]:7447`);
//! - the serial leaf [`parse_serial_locator`] — `serial/...` device or
//!   pin endpoints (relocated here from `serial_link` in R311ny so the
//!   [`AnyLocator::Serial`] variant is unconditional; see that leaf's
//!   note).
//!
//! Deferred, surfaced as parse errors rather than silently mis-parsed:
//! - DNS hostnames (`tcp/example.org:7447`) — resolution is an AP-side
//!   (`std`) concern, out of this no_std-compatible parse;
//! - IP locator metadata suffixes (`udp/1.2.3.4:7447#iface=eth0`) — the
//!   `#`-delimited config tail is not split by the IP leaf (the serial
//!   leaf DOES read its `#baudrate=` tail);
//! - other non-IP transports (`unixsock-stream/...`, `ws/...`, `tls/...`).

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

// ─── serial locator leaf ───
//
// R311ny — the `serial/...` locator GRAMMAR is universal: parsing a serial
// endpoint string is always possible and costs only alloc string work, so
// it lives HERE (the locator home, `#[cfg(feature = "alloc")]`) alongside
// the IP leaf, NOT behind `transport-link-serial`. Only the serial BACKEND
// (framing/handshake in [`crate::serial_link`], tty I/O in
// `wz-runtime-tokio::serial_pipeline`) is feature-gated. This mirrors the IP
// leaf — `udp` always PARSES (`Proto::Udp`) and only `dial_udp` is gated —
// and it lets [`AnyLocator::Serial`] be an ALWAYS-present variant, so a
// consumer's `match` can never skew non-exhaustive when the serial codec is
// enabled by one crate (this leaf's `transport-link-serial`) but the
// backend by another (the runtime's). That skew was the R311nx finding;
// relocating the leaf out of the gated module liquidates it.

/// The connection target of a serial endpoint: a host device path
/// (`/dev/ttyUSB0`) or a GPIO TX/RX pin pair (MCU). Mirrors pico's
/// `_z_serial_endpoint_cfg_t` dev-vs-pins split (serial_protocol.c:79-131).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerialTarget {
    /// A device path opened by the host tty backend.
    Device(String),
    /// A TX/RX GPIO pin pair (MCU UART HAL).
    Pins { tx: u32, rx: u32 },
}

/// A parsed `serial/...` locator: its connection target and baud rate.
/// The baud-rate *value* is carried verbatim (any `u32`); validating it
/// against a supported speed table is the tty backend's concern, not the
/// parser's (pico parses the `u32` here and validates at tty-open,
/// tty_posix.c:27-56).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialEndpoint {
    pub target: SerialTarget,
    pub baudrate: u32,
}

/// Why a `serial/...` locator string did not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerialLocatorError {
    /// The locator does not begin with the `serial/` scheme.
    NotSerialScheme,
    /// The address (between the scheme and the `#config`) is empty.
    EmptyAddress,
    /// The required `baudrate=<u32>` config key is absent.
    MissingBaudrate,
    /// A config value (the baud rate, or a pin) is not a valid `u32`.
    BadNumber(String),
}

const SERIAL_SCHEME: &str = "serial";
const SERIAL_BAUDRATE_KEY: &str = "baudrate";

/// Parse a zenoh serial locator into a [`SerialEndpoint`].
///
/// Accepted forms (mirror of `_z_serial_endpoint_parse`,
/// serial_protocol.c:79-131):
/// - device: `serial//dev/ttyUSB0#baudrate=115200`
/// - pins:   `serial/12.13#baudrate=115200`
///
/// The scheme is the substring before the first `/`; the remainder is
/// `<address>#<config>` (config optional in shape, but `baudrate` is
/// required). An address containing `.` is read as a `TX.RX` pin pair,
/// otherwise as a device path — the same `.`-heuristic pico uses
/// (serial_protocol.c:109).
///
/// The serial counterpart of [`parse_locator`] (the IP `tcp`/`udp` leaf);
/// [`parse_any_locator`] is the scheme-dispatcher delegating to the two.
pub fn parse_serial_locator(locator: &str) -> Result<SerialEndpoint, SerialLocatorError> {
    let (scheme, rest) = locator
        .split_once('/')
        .ok_or(SerialLocatorError::NotSerialScheme)?;
    if scheme != SERIAL_SCHEME {
        return Err(SerialLocatorError::NotSerialScheme);
    }

    let (address, config) = match rest.split_once('#') {
        Some((addr, cfg)) => (addr, cfg),
        None => (rest, ""),
    };
    if address.is_empty() {
        return Err(SerialLocatorError::EmptyAddress);
    }

    let baudrate = parse_baudrate(config)?;

    let target = match address.split_once('.') {
        Some((tx_str, rx_str)) => {
            let tx = parse_u32(tx_str)?;
            let rx = parse_u32(rx_str)?;
            SerialTarget::Pins { tx, rx }
        }
        None => SerialTarget::Device(address.to_string()),
    };

    Ok(SerialEndpoint { target, baudrate })
}

/// Extract the required `baudrate=<u32>` from the `#`-delimited config
/// tail (`key=value` pairs separated by `;`). Only `baudrate` is
/// recognised — pico's serial config map has exactly one key
/// (config/serial.h:29-52).
fn parse_baudrate(config: &str) -> Result<u32, SerialLocatorError> {
    for pair in config.split(';') {
        if let Some((key, value)) = pair.split_once('=') {
            if key == SERIAL_BAUDRATE_KEY {
                return parse_u32(value);
            }
        }
    }
    Err(SerialLocatorError::MissingBaudrate)
}

/// Parse a positive `u32` config value (baud rate or pin). Pico's
/// `_z_serial_parse_u32` (serial_protocol.c:62) rejects zero — a `0` baud
/// rate or pin number is invalid — so `0` is a `BadNumber` here too, for
/// parity.
fn parse_u32(s: &str) -> Result<u32, SerialLocatorError> {
    match s.parse::<u32>() {
        Ok(v) if v != 0 => Ok(v),
        _ => Err(SerialLocatorError::BadNumber(s.to_string())),
    }
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
// [`parse_locator`] (IP) or [`parse_serial_locator`] (serial — the leaf
// relocated here from `serial_link` in R311ny so the variant is ungated).
// Each leaf keeps its own scheme re-check, so a mis-routed string still
// errors in-leaf.

/// A locator parsed into its transport endpoint, across every link
/// transport. The scheme-dispatch sum type whose arms are the outputs of
/// the per-scheme parse leaves; [`parse_any_locator`] builds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyLocator {
    /// An IP endpoint (`tcp/...` / `udp/...`) — see [`ParsedLocator`].
    Ip(ParsedLocator),
    /// A serial endpoint (`serial/...`) — see [`SerialEndpoint`]. ALWAYS
    /// present (R311ny: the serial locator leaf is ungated), so a
    /// `serial/...` string parses to this on any alloc build. Whether it
    /// can be DIALED is the runtime backend's concern
    /// (`transport-link-serial`), surfaced at dial time — exactly as `udp`
    /// always parses (`Proto::Udp`) but dials only with `transport-link-udp`.
    /// Keeping the variant unconditional means a consumer's `match` is
    /// exhaustive in every feature combination (no cross-crate skew).
    Serial(SerialEndpoint),
}

/// Why a locator string did not parse into an [`AnyLocator`] — the
/// composed error over the per-scheme leaf errors (serial_link B7 seam
/// note: `enum { Ip(LocatorParseError), Serial(SerialLocatorError) }`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyLocatorError {
    /// The IP leaf ([`parse_locator`]) rejected the string (unknown
    /// scheme, missing separator, or a non-numeric address).
    Ip(LocatorParseError),
    /// The serial leaf ([`parse_serial_locator`]) rejected a `serial/...`
    /// string.
    Serial(SerialLocatorError),
}

/// Parse any zenoh locator string into an [`AnyLocator`], dispatching on
/// the scheme (the substring before the first `/`) to the matching leaf.
///
/// `serial/...` routes to [`parse_serial_locator`]; everything else to the
/// IP leaf [`parse_locator`] (which reports an unknown scheme as
/// [`LocatorParseError::UnknownProto`]). Both leaves are unconditional
/// (R311ny) — serial parsing is NOT feature-gated, so a `serial/...` string
/// always parses to [`AnyLocator::Serial`] whether or not a serial BACKEND
/// is compiled; dialing it without one fails at dial time (the IP `udp`
/// model). This is the single seam through which the session-open path
/// turns a discovered / configured locator into a dialable endpoint,
/// regardless of transport.
pub fn parse_any_locator(locator: &str) -> Result<AnyLocator, AnyLocatorError> {
    if matches!(locator.split_once('/'), Some(("serial", _))) {
        return parse_serial_locator(locator)
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

    #[test]
    fn parse_any_routes_serial_to_the_serial_leaf() {
        // R311ny — unconditional (no `transport-link-serial` cfg): the
        // serial leaf is always compiled, so a `serial/...` string always
        // routes here regardless of whether a serial backend exists.
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

    // ─── serial locator leaf (relocated from serial_link in R311ny) ───

    #[test]
    fn parses_serial_device() {
        let ep = parse_serial_locator("serial//dev/ttyUSB0#baudrate=115200").expect("device");
        assert_eq!(ep.target, SerialTarget::Device("/dev/ttyUSB0".to_string()));
        assert_eq!(ep.baudrate, 115200);
    }

    #[test]
    fn parses_serial_pins() {
        let ep = parse_serial_locator("serial/12.13#baudrate=9600").expect("pins");
        assert_eq!(ep.target, SerialTarget::Pins { tx: 12, rx: 13 });
        assert_eq!(ep.baudrate, 9600);
    }

    #[test]
    fn rejects_non_serial_scheme() {
        assert_eq!(
            parse_serial_locator("tcp/127.0.0.1:7447"),
            Err(SerialLocatorError::NotSerialScheme)
        );
        assert_eq!(
            parse_serial_locator("serial"),
            Err(SerialLocatorError::NotSerialScheme)
        );
    }

    #[test]
    fn rejects_empty_serial_address() {
        assert_eq!(
            parse_serial_locator("serial/#baudrate=115200"),
            Err(SerialLocatorError::EmptyAddress)
        );
    }

    #[test]
    fn rejects_missing_baudrate() {
        assert_eq!(
            parse_serial_locator("serial//dev/ttyUSB0"),
            Err(SerialLocatorError::MissingBaudrate)
        );
    }

    #[test]
    fn rejects_bad_baudrate() {
        assert_eq!(
            parse_serial_locator("serial//dev/ttyUSB0#baudrate=fast"),
            Err(SerialLocatorError::BadNumber("fast".to_string()))
        );
    }

    #[test]
    fn rejects_zero_baudrate_like_pico() {
        // pico's `_z_serial_parse_u32` rejects 0 (serial_protocol.c:62).
        assert_eq!(
            parse_serial_locator("serial//dev/ttyUSB0#baudrate=0"),
            Err(SerialLocatorError::BadNumber("0".to_string()))
        );
    }

    #[test]
    fn rejects_zero_pin_like_pico() {
        assert_eq!(
            parse_serial_locator("serial/0.13#baudrate=9600"),
            Err(SerialLocatorError::BadNumber("0".to_string()))
        );
    }
}
