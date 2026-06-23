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
//! Three leaves, dispatched by scheme through [`parse_any_locator`] into the
//! [`AnyLocator`] sum type:
//! - the IP leaf [`parse_locator`] — `tcp` / `udp` / `tls` / `ws` over a
//!   numeric [`SocketAddr`] (IPv4 `1.2.3.4:7447` or IPv6 `[::1]:7447`); `tls`
//!   and `ws` share the `tcp` grammar (both ride a TCP connection), parsing
//!   unconditionally while only their dial backends are
//!   `transport-link-{tls,ws}`-gated;
//! - the serial leaf [`parse_serial_locator`] — `serial/...` device or
//!   pin endpoints (relocated here from `serial_link` in R311ny so the
//!   [`AnyLocator::Serial`] variant is unconditional; see that leaf's
//!   note);
//! - the unixsock leaf [`parse_unixsock_locator`] — `unixsock-stream/...`
//!   filesystem-path endpoints (R311xi). Like serial, it is a non-IP
//!   endpoint shape (a socket path, not a [`SocketAddr`]) parsed
//!   unconditionally so the [`AnyLocator::Unixsock`] variant is always
//!   present; only the dial BACKEND (`transport-link-unixsock` in
//!   `wz-runtime-tokio`) is gated.
//!
//! DNS hostnames (`tcp/example.org:7447`) are CLASSIFIED, not rejected
//! (R311ps): the IP leaf [`parse_locator`] is numeric-only and returns
//! [`LocatorParseError::BadAddress`], but [`parse_any_locator`] then classifies
//! a hostname-shaped address into [`AnyLocator::Named`]. Only the SHAPE is
//! decided here — resolution stays an AP-side (`std`) concern, out of this
//! no_std-compatible parse (the dial seam resolves a `Named` tcp endpoint).
//!
//! Still surfaced as parse errors rather than silently mis-parsed:
//! - IP locator metadata suffixes (`udp/1.2.3.4:7447#iface=eth0`) — the
//!   `#`-delimited config tail is not split by the IP leaf (the serial
//!   leaf DOES read its `#baudrate=` tail);
//! - other transports not yet wired (`bt/...`).

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
    /// `tls/...` — TLS-over-TCP stream transport: the same numeric
    /// `host:port` grammar as `tcp`, the byte stream wrapped in a rustls
    /// session (pico's `tls/` scheme, `_z_get_link_mtu_tls` = 65535, the TCP
    /// stream ceiling). Parses unconditionally like every other proto; the
    /// BACKEND dial is gated (`transport-link-tls`) and needs cert config the
    /// locator alone does not carry, so it dials only through
    /// `wz-runtime-tokio::tls_pipeline`'s explicit `dial_tls`/`accept_tls`,
    /// not the generic `dial_locator`.
    Tls,
    /// `ws/...` — WebSocket-over-TCP DATAGRAM transport: the same numeric
    /// `host:port` grammar as `tcp`, but each zenoh batch rides one WebSocket
    /// BINARY message — pico's `ws/` scheme sets `Z_LINK_CAP_FLOW_DATAGRAM`
    /// (`_z_get_link_mtu_ws` = 65535), so the message boundary delimits a
    /// frame with no length prefix, exactly like UDP (NOT the TCP/TLS
    /// StreamEnvelope). Parses unconditionally; the BACKEND dial is gated
    /// (`transport-link-ws`) and — UNLIKE `tls` — needs no cert config, so a
    /// `ws/...` locator dials directly through `dial_locator` (like `udp`),
    /// via `wz-runtime-tokio::ws_pipeline`.
    Ws,
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
/// scope (numeric tcp/udp/tls/ws endpoints; DNS / metadata / other transports
/// are reported as errors, not silently accepted).
pub fn parse_locator(locator: &str) -> Result<ParsedLocator, LocatorParseError> {
    let (proto_str, addr_str) = locator
        .split_once('/')
        .ok_or(LocatorParseError::MissingProtoSeparator)?;
    let proto = match proto_str {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        "tls" => Proto::Tls,
        "ws" => Proto::Ws,
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

// ─── unixsock-stream locator leaf ───
//
// R311xi — the `unixsock-stream/...` locator GRAMMAR is universal, exactly
// like the serial leaf above: parsing a unix-domain socket path is always
// possible and costs only alloc string work, so it lives HERE alongside the
// IP and serial leaves, NOT behind `transport-link-unixsock`. Only the
// unixsock BACKEND (the tokio `UnixStream` dial/accept in
// `wz-runtime-tokio::unixsock_pipeline`) is feature-gated. This mirrors the
// serial leaf — `serial/...` always PARSES and only the tty backend is gated
// — and lets [`AnyLocator::Unixsock`] be an ALWAYS-present variant, so a
// consumer's `match` can never skew non-exhaustive across feature combos
// (the R311ny / R311nx skew-liquidation lesson, applied to the new leaf).

/// A parsed `unixsock-stream/...` locator: the filesystem path of the unix
/// domain socket. zenoh's `unixsock-stream` link
/// (`io/zenoh-links/zenoh-link-unixsock_stream`, `UNIXSOCKSTREAM_LOCATOR_PREFIX`)
/// carries the socket path as the locator address with no further structure —
/// the path is taken verbatim (`get_unix_path_as_string` = `address.to_string()`),
/// so this leaf carries just the path. Validating the path (existence,
/// permissions) is the dial/bind backend's concern, exactly as the serial
/// leaf defers baud-rate validation to the tty open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixsockEndpoint {
    /// The unix-domain socket path, taken verbatim from the locator address
    /// (everything after the `unixsock-stream/` scheme). An absolute path
    /// (`/tmp/zenoh.sock`) yields the double-slash locator
    /// `unixsock-stream//tmp/zenoh.sock`, the same scheme+abs-path shape the
    /// serial leaf parses (`serial//dev/ttyUSB0`).
    pub path: String,
}

/// Why a `unixsock-stream/...` locator string did not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnixsockLocatorError {
    /// The locator does not begin with the `unixsock-stream/` scheme.
    NotUnixsockScheme,
    /// The path (after the scheme) is empty (`unixsock-stream/`).
    EmptyPath,
}

const UNIXSOCK_SCHEME: &str = "unixsock-stream";

/// Parse a zenoh `unixsock-stream/...` locator into a [`UnixsockEndpoint`].
///
/// The scheme is the substring before the first `/`; everything after it is
/// the socket path, taken verbatim (zenoh's `get_unix_path_as_string` is a
/// bare `address.to_string()`, so an absolute path keeps its leading `/`:
/// `unixsock-stream//tmp/zenoh.sock` -> path `/tmp/zenoh.sock`). An empty path
/// is rejected ([`UnixsockLocatorError::EmptyPath`]) — the unixsock counterpart
/// of the serial leaf's [`SerialLocatorError::EmptyAddress`].
///
/// The unixsock counterpart of [`parse_locator`] (IP) and
/// [`parse_serial_locator`] (serial); [`parse_any_locator`] is the
/// scheme-dispatcher delegating to the three leaves.
pub fn parse_unixsock_locator(locator: &str) -> Result<UnixsockEndpoint, UnixsockLocatorError> {
    let (scheme, path) = locator
        .split_once('/')
        .ok_or(UnixsockLocatorError::NotUnixsockScheme)?;
    if scheme != UNIXSOCK_SCHEME {
        return Err(UnixsockLocatorError::NotUnixsockScheme);
    }
    if path.is_empty() {
        return Err(UnixsockLocatorError::EmptyPath);
    }
    Ok(UnixsockEndpoint {
        path: path.to_string(),
    })
}

// ─── unified locator (IP | Serial | Unixsock) ───
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
    /// An IP endpoint with a NUMERIC address (`tcp/1.2.3.4:7447`,
    /// `tcp/[::1]:7447`) — see [`ParsedLocator`]. The address parsed straight
    /// to a [`SocketAddr`]; no resolution needed.
    Ip(ParsedLocator),
    /// An IP-family endpoint whose address is a DNS NAME, not a numeric
    /// [`SocketAddr`] (`tcp/example.org:7447`). R311ps — a name is a distinct
    /// PARSED outcome from both a numeric address ([`Self::Ip`]) and a
    /// malformed one ([`LocatorParseError::BadAddress`]): DNS-vs-numeric is a
    /// property of the ADDRESS TOKEN, orthogonal to the scheme, so the parser
    /// classifies it here for every IP-family proto rather than letting each
    /// caller re-inspect the raw string. Resolution stays a std-layer concern
    /// (this no_std parser only classifies the token shape — it never resolves);
    /// the dial seam turns a `tcp` name into a host-string TCP dial and reports
    /// the other protos' name dial as unsupported-for-now (a clean extension
    /// point, not a string-prefix special-case). `host` is the non-empty,
    /// non-numeric host token; `port` the validated `u16`.
    Named {
        proto: Proto,
        host: String,
        port: u16,
    },
    /// A serial endpoint (`serial/...`) — see [`SerialEndpoint`]. ALWAYS
    /// present (R311ny: the serial locator leaf is ungated), so a
    /// `serial/...` string parses to this on any alloc build. Whether it
    /// can be DIALED is the runtime backend's concern
    /// (`transport-link-serial`), surfaced at dial time — exactly as `udp`
    /// always parses (`Proto::Udp`) but dials only with `transport-link-udp`.
    /// Keeping the variant unconditional means a consumer's `match` is
    /// exhaustive in every feature combination (no cross-crate skew).
    Serial(SerialEndpoint),
    /// A unix-domain-socket endpoint (`unixsock-stream/...`) — see
    /// [`UnixsockEndpoint`]. ALWAYS present (R311xi: the unixsock locator
    /// leaf is ungated, like serial), so a `unixsock-stream/...` string
    /// parses to this on any alloc build. Whether it can be DIALED is the
    /// runtime backend's concern (`transport-link-unixsock`), surfaced at
    /// dial time — exactly as `serial` always parses but dials only with
    /// `transport-link-serial`. A non-IP endpoint (a socket path, not a
    /// [`SocketAddr`]), so — like serial — it cannot be a [`Proto`] variant.
    Unixsock(UnixsockEndpoint),
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
    /// The unixsock leaf ([`parse_unixsock_locator`]) rejected a
    /// `unixsock-stream/...` string (R311xi).
    Unixsock(UnixsockLocatorError),
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
    // R311xi — `unixsock-stream/...` routes to the unixsock leaf, like the
    // serial scheme above. Checked before the IP leaf (which would reject
    // `unixsock-stream` as an UnknownProto); the leaf is unconditional, so
    // the string always parses to [`AnyLocator::Unixsock`] whether or not a
    // unixsock BACKEND is compiled (dialing without one fails at dial time —
    // the serial/udp model).
    if matches!(locator.split_once('/'), Some(("unixsock-stream", _))) {
        return parse_unixsock_locator(locator)
            .map(AnyLocator::Unixsock)
            .map_err(AnyLocatorError::Unixsock);
    }
    match parse_locator(locator) {
        Ok(ip) => Ok(AnyLocator::Ip(ip)),
        // R311ps — a non-numeric IP-family address is either a DNS NAME
        // (classified to [`AnyLocator::Named`]; resolution stays the std dial
        // layer's job) or genuinely malformed (the error propagates). Splitting
        // them here makes DNS-vs-numeric an address-token property the dial seam
        // routes on, instead of a raw-string re-inspection at each caller.
        Err(LocatorParseError::BadAddress(addr)) => match classify_named_ip(locator) {
            Some((proto, host, port)) => Ok(AnyLocator::Named { proto, host, port }),
            None => Err(AnyLocatorError::Ip(LocatorParseError::BadAddress(addr))),
        },
        Err(e) => Err(AnyLocatorError::Ip(e)),
    }
}

/// Classify an IP-family locator whose address failed numeric [`SocketAddr`]
/// parse: a `proto/HOST:PORT` with a known proto, a non-empty host bearing no
/// `/` or extra `:`, and a valid `u16` port is a DNS NAME
/// (`Some((proto, host, port))`); anything else — no port, bad port, empty
/// host, a path-bearing host, or a bracketed (IPv6-literal) address that did
/// not already parse numerically — is genuinely malformed (`None`). This only
/// classifies the token SHAPE; it performs NO DNS resolution (that is the std
/// dial layer's concern, per this module's deferral contract).
fn classify_named_ip(locator: &str) -> Option<(Proto, String, u16)> {
    let (proto_str, addr) = locator.split_once('/')?;
    let proto = match proto_str {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        "tls" => Proto::Tls,
        "ws" => Proto::Ws,
        _ => return None,
    };
    // A bracketed address is an IPv6 literal; if it did not parse as a
    // SocketAddr above, it is malformed, not a name.
    if addr.starts_with('[') {
        return None;
    }
    let (host, port_str) = addr.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;
    if host.is_empty() || host.contains('/') || host.contains(':') {
        return None;
    }
    Some((proto, host.to_string(), port))
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
    fn parses_tls_ipv4() {
        // `tls` shares the `tcp` numeric grammar (TLS wraps the same stream);
        // parsing is unconditional, only the dial backend is feature-gated.
        let p = parse_locator("tls/192.168.1.10:7447").expect("valid tls locator");
        assert_eq!(p.proto, Proto::Tls);
        assert_eq!(p.addr, "192.168.1.10:7447".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parses_ws_ipv4() {
        // `ws` shares the `tcp` numeric grammar (WebSocket rides TCP);
        // parsing is unconditional, only the dial backend is feature-gated.
        let p = parse_locator("ws/192.168.1.10:7447").expect("valid ws locator");
        assert_eq!(p.proto, Proto::Ws);
        assert_eq!(p.addr, "192.168.1.10:7447".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_any_routes_ws_to_the_ip_leaf() {
        // A `ws/...` locator parses through the IP leaf (numeric host:port),
        // landing as `AnyLocator::Ip(Proto::Ws)` whether or not the WS backend
        // is compiled — the dial step decides reachability.
        let any = parse_any_locator("ws/127.0.0.1:7447").expect("ws locator");
        assert_eq!(
            any,
            AnyLocator::Ip(parse_locator("ws/127.0.0.1:7447").unwrap())
        );
    }

    #[test]
    fn parse_any_routes_tls_to_the_ip_leaf() {
        // A `tls/...` locator parses through the IP leaf (numeric host:port),
        // landing as `AnyLocator::Ip(Proto::Tls)` whether or not the TLS
        // backend is compiled — the dial step decides reachability.
        let any = parse_any_locator("tls/127.0.0.1:7447").expect("tls locator");
        assert_eq!(
            any,
            AnyLocator::Ip(parse_locator("tls/127.0.0.1:7447").unwrap())
        );
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
        // `quic` is a not-yet-wired transport — `ws` is now a known proto
        // (R311ob), so the unknown-proto example moved to one still absent.
        assert_eq!(
            parse_locator("quic/127.0.0.1:7447"),
            Err(LocatorParseError::UnknownProto("quic".to_string()))
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
    fn parse_any_propagates_genuinely_malformed_ip_error() {
        // R311ps — a GENUINELY malformed IP address (no port) still surfaces
        // the IP leaf error verbatim, wrapped in the AnyLocator composition.
        // (A DNS name like `tcp/example.org:7447` is now classified as
        // `AnyLocator::Named`, not an error — see the Named tests below.)
        assert_eq!(
            parse_any_locator("tcp/no-port-here"),
            Err(AnyLocatorError::Ip(LocatorParseError::BadAddress(
                "no-port-here".to_string()
            )))
        );
    }

    #[test]
    fn parse_any_classifies_dns_name_as_named() {
        // R311ps — a `tcp/HOST:PORT` whose host is a DNS name is a distinct
        // PARSED outcome (Named), not a BadAddress error. The numeric leaf
        // `parse_locator` still rejects it (it only knows SocketAddr); the
        // classification lives in `parse_any_locator`.
        assert_eq!(
            parse_any_locator("tcp/example.org:7447"),
            Ok(AnyLocator::Named {
                proto: Proto::Tcp,
                host: "example.org".to_string(),
                port: 7447,
            })
        );
    }

    #[test]
    fn parse_any_classifies_named_for_every_ip_proto() {
        // DNS-vs-numeric is an address-token property orthogonal to scheme:
        // every IP-family proto classifies a name to Named (whether that proto
        // can DIAL a name is the dial seam's concern, surfaced there).
        for (s, proto) in [
            ("udp/example.org:7447", Proto::Udp),
            ("ws/example.org:7447", Proto::Ws),
            ("tls/example.org:7447", Proto::Tls),
        ] {
            assert_eq!(
                parse_any_locator(s),
                Ok(AnyLocator::Named {
                    proto,
                    host: "example.org".to_string(),
                    port: 7447,
                }),
                "{s} should classify as Named"
            );
        }
    }

    #[test]
    fn parse_any_rejects_malformed_not_as_named() {
        // Shapes that are NOT a valid host:port stay BadAddress (malformed),
        // not Named: no port, bad port, empty host, path-bearing host, and an
        // unparsed bracketed (IPv6-literal) address.
        for s in [
            "tcp/example.org",       // no port
            "tcp/example.org:99999", // port out of u16 range
            "tcp/:7447",             // empty host
            "tcp/a/b:7447",          // path-bearing host
            "tcp/[::1",              // malformed bracketed literal
        ] {
            assert!(
                matches!(
                    parse_any_locator(s),
                    Err(AnyLocatorError::Ip(LocatorParseError::BadAddress(_)))
                ),
                "{s} should be BadAddress, not Named"
            );
        }
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

    #[test]
    fn parse_any_routes_unixsock_to_the_unixsock_leaf() {
        // R311xi — unconditional (no `transport-link-unixsock` cfg): the
        // unixsock leaf is always compiled, so a `unixsock-stream/...` string
        // always routes here whether or not a unixsock backend exists, exactly
        // like the serial scheme.
        let any = parse_any_locator("unixsock-stream//tmp/zenoh.sock").expect("unixsock locator");
        assert_eq!(
            any,
            AnyLocator::Unixsock(
                parse_unixsock_locator("unixsock-stream//tmp/zenoh.sock").unwrap()
            )
        );
        // And the unixsock leaf error composes through too.
        assert_eq!(
            parse_any_locator("unixsock-stream/"),
            Err(AnyLocatorError::Unixsock(UnixsockLocatorError::EmptyPath))
        );
    }

    // ─── unixsock-stream locator leaf (R311xi) ───

    #[test]
    fn parses_unixsock_absolute_path() {
        // The double-slash shape: scheme `/` + absolute path. zenoh takes the
        // path verbatim (`get_unix_path_as_string`), so the leading `/` of an
        // absolute path is preserved.
        let ep = parse_unixsock_locator("unixsock-stream//tmp/zenoh.sock").expect("abs path");
        assert_eq!(ep.path, "/tmp/zenoh.sock");
    }

    #[test]
    fn parses_unixsock_relative_path() {
        // A relative path (no leading `/`) is also a valid socket path —
        // taken verbatim like zenoh.
        let ep = parse_unixsock_locator("unixsock-stream/zenoh.sock").expect("rel path");
        assert_eq!(ep.path, "zenoh.sock");
    }

    #[test]
    fn rejects_empty_unixsock_path() {
        // `unixsock-stream/` has an empty path — the unixsock counterpart of
        // the serial leaf's EmptyAddress.
        assert_eq!(
            parse_unixsock_locator("unixsock-stream/"),
            Err(UnixsockLocatorError::EmptyPath)
        );
    }

    #[test]
    fn rejects_non_unixsock_scheme() {
        assert_eq!(
            parse_unixsock_locator("tcp/127.0.0.1:7447"),
            Err(UnixsockLocatorError::NotUnixsockScheme)
        );
        assert_eq!(
            parse_unixsock_locator("unixsock-stream"),
            Err(UnixsockLocatorError::NotUnixsockScheme)
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
