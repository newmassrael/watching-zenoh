// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! An endpoint's text read into the [`Locator`] a link is opened towards, and why a text names
//! none.
//!
//! UDP, TCP and TLS over IPv4 or IPv6, by address (and `ws/`, at the same address, in a build with
//! WebSocket links, `ws`). A dial reads a host name too ([`read_dial_target`]), which the
//! network resolves as the dial begins; the readers of an address, [`parse_locator`] and
//! [`parse_listen_locator`], refuse a name as [`DialRefused::BadAddress`]. Another scheme,
//! or upstream's `?metadata` / `#config` parts, as [`DialRefused::Unsupported`]: no link here
//! honours them, and opening one anyway would quietly drop what the writer asked for. Both are
//! permanent for the text. A build with serial links (`serial`) reads `serial/` too, with the
//! `#config` that is that link's own (`wz_session_core::locator_grammar`); without it the scheme
//! is one more this build does not carry; a build with unixpipe links (`unixpipe`) reads
//! `unixpipe/` with its `#file_mask` the same way. Whether a stack carries the protocol or the family is
//! the stack's to answer when it opens the link; a stack built without IPv6 reads its endpoints with
//! [`parse_locator_for`], so its image holds the IPv4 reader alone.
//!
//! Written once for every engine over this runtime: the session shell's dialler and connection
//! manager, and a transport that dials and listens for a C ABI's session.

use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::session_drive::{LinkProto, Locator};
#[cfg(feature = "serial")]
use crate::session_drive::{SerialLine, SerialLocator, SerialPath};
#[cfg(feature = "unixpipe")]
use crate::session_drive::{UnixpipeLocator, UnixpipePath};
#[cfg(feature = "serial")]
use wz_session_core::locator_grammar::{read_serial_locator, SerialAddress, SerialTextError};
#[cfg(feature = "unixpipe")]
use wz_session_core::locator_grammar::{read_unixpipe_locator, UnixpipeTextError};

/// Why a dial could not even be attempted. Permanent for this endpoint text in this build, so it
/// is not retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialRefused {
    /// The endpoint's scheme names a link this build does not carry.
    Unsupported,
    /// The address could not be read as one this link can reach.
    BadAddress,
    /// One locator of a `{ strategy, locators }` group of several: one session over several
    /// links, which a session of this runtime cannot hold. Decided by a connection manager from
    /// the list, before any dial.
    MultiLinkGroup,
    /// The node's sessions offer a width of sequence numbers the build's `sn-resolution` domain
    /// leaves out, so no endpoint can be dialled until the node's parameters change. Decided by
    /// the dialer before it opens a link.
    SnResolution,
    /// The endpoint names a host and the network the build dials on has no resolver to turn it
    /// into an address (`SessionLinks::RESOLVES`). Decided by the transport before any dial.
    NoResolver,
}

impl DialRefused {
    /// The reason in the word a node reports it with, at `status/connect`.
    pub const fn as_str(self) -> &'static str {
        match self {
            DialRefused::Unsupported => "unsupported",
            DialRefused::BadAddress => "bad_address",
            DialRefused::MultiLinkGroup => "multi_link_group",
            DialRefused::SnResolution => "sn_resolution",
            DialRefused::NoResolver => "no_resolver",
        }
    }
}

/// The longest host name a dial reads (RFC 1035 section 2.3.4, written without its final dot): a
/// resolver of the network is handed it in a buffer of this many bytes and its terminator.
pub const HOST_NAME_MAX: usize = 253;

/// What a dial's endpoint text reaches ([`read_dial_target`]): the locator of an address, or a
/// host name the network resolves as the dial begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialTarget<'a> {
    /// The address the text names.
    At(Locator),
    /// A host the text names, dialled at the addresses the network resolves it to.
    Named(NamedHost<'a>),
}

/// A host name, the port a dial of it reaches and the link it opens there: a `udp/`, `tcp/` or
/// `tls/` endpoint, or `ws/` in a build with WebSocket links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamedHost<'a> {
    host: &'a str,
    port: u16,
    link: NamedLink,
}

/// The link a dial of a [`NamedHost`] opens at each address the host resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NamedLink {
    Ip(LinkProto),
    #[cfg(feature = "ws")]
    Ws,
}

impl<'a> NamedHost<'a> {
    /// The host name: letters, digits, `-` and `.`, at most [`HOST_NAME_MAX`] bytes.
    pub fn host(&self) -> &'a str {
        self.host
    }

    /// The port the dial reaches at every address of the host; never 0.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The locator a dial of the host opens at `at`, one of the addresses it resolved to.
    pub fn locator(&self, at: SocketAddr) -> Locator {
        match self.link {
            NamedLink::Ip(proto) => Locator::ip(proto, at),
            #[cfg(feature = "ws")]
            NamedLink::Ws => Locator::ws(at),
        }
    }
}

/// Read a dial's endpoint text: the address [`parse_locator`] reads, or, where that reader finds
/// no address, a host name and a port, `<scheme>/<host>:<port>` (zenoh-pico hands the same host
/// to its resolver, `vendor/zenoh-pico/src/link/transport/tcp/tcp_posix.c` @ `getaddrinfo(`).
/// Every other refusal is that reader's.
///
/// A name is labels of letters, digits and `-` joined by `.`, none empty, none longer than 63
/// bytes and none that opens or closes with `-`, at most [`HOST_NAME_MAX`] bytes in all; its
/// last label opens with a letter (RFC 3696 section 2), so a text a C resolver would read as a
/// number (`0x7f.1`, `127.1`) is never handed to it as a name: a text the address reader
/// refused stays refused when it reads as a number to another reader.
pub fn read_dial_target(endpoint: &str) -> Result<DialTarget<'_>, DialRefused> {
    match parse_locator(endpoint) {
        Ok(at) => Ok(DialTarget::At(at)),
        Err(DialRefused::BadAddress) => named_host(endpoint)
            .map(DialTarget::Named)
            .ok_or(DialRefused::BadAddress),
        Err(refused) => Err(refused),
    }
}

/// The host and port of an IP scheme's text, or `None` for a text that names none.
fn named_host(endpoint: &str) -> Option<NamedHost<'_>> {
    let schemes = [LinkProto::Udp, LinkProto::Tcp, LinkProto::Tls]
        .into_iter()
        .map(|proto| (proto.scheme(), NamedLink::Ip(proto)));
    #[cfg(feature = "ws")]
    let schemes = schemes.chain(core::iter::once((
        wz_session_core::link::LinkKind::Ws.scheme(),
        NamedLink::Ws,
    )));
    let (link, rest) = schemes.into_iter().find_map(|(scheme, link)| {
        let rest = endpoint.strip_prefix(scheme)?.strip_prefix('/')?;
        Some((link, rest))
    })?;
    let (host, port) = rest.rsplit_once(':')?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) || !is_host_name(host) {
        return None;
    }
    let port = port.parse::<u16>().ok().filter(|port| *port != 0)?;
    Some(NamedHost { host, port, link })
}

/// Whether `host` is a name as [`read_dial_target`] reads one.
fn is_host_name(host: &str) -> bool {
    if host.len() > HOST_NAME_MAX {
        return false;
    }
    let mut last_opens_with_letter = false;
    for label in host.split('.') {
        let bytes = label.as_bytes();
        let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
            return false;
        };
        if bytes.len() > 63
            || *first == b'-'
            || *last == b'-'
            || !bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return false;
        }
        last_opens_with_letter = first.is_ascii_alphabetic();
    }
    last_opens_with_letter
}

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
    #[cfg(feature = "serial")]
    if let Some(serial) = serial_endpoint(endpoint) {
        return serial;
    }
    #[cfg(feature = "unixpipe")]
    if let Some(unixpipe) = unixpipe_endpoint(endpoint) {
        return unixpipe;
    }
    // A WebSocket link is reached at a socket address as a TCP one is
    // (`io/zenoh-links/zenoh-link-ws/src/lib.rs` @ `pub async fn get_ws_addr(`), so its text is
    // read by the same reader. Upstream's link reads no config key and no metadata, so a `#` or
    // `?` part (zenoh-pico's `tout` among them) is refused below as on every IP scheme.
    #[cfg(feature = "ws")]
    if let Some(rest) = endpoint
        .strip_prefix(wz_session_core::link::LinkKind::Ws.scheme())
        .and_then(|rest| rest.strip_prefix('/'))
    {
        return socket_addr::<IPV6>(rest, any_port).map(Locator::ws);
    }
    let Some((proto, rest)) = [LinkProto::Udp, LinkProto::Tcp, LinkProto::Tls]
        .into_iter()
        .find_map(|proto| {
            let rest = endpoint.strip_prefix(proto.scheme())?.strip_prefix('/')?;
            Some((proto, rest))
        })
    else {
        return Err(DialRefused::Unsupported);
    };
    socket_addr::<IPV6>(rest, any_port).map(|at| Locator::ip(proto, at))
}

/// The socket address an IP scheme's text names after its `<scheme>/`, read for a stack that
/// opens IPv6 links when `IPV6` is true. A port of 0 is taken only where `any_port` says the
/// stack chooses one.
#[inline(always)]
fn socket_addr<const IPV6: bool>(rest: &str, any_port: bool) -> Result<SocketAddr, DialRefused> {
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
    Ok(at)
}

/// A `serial/` endpoint's text read into its locator, or `None` for a text of another scheme. A
/// line that cannot be read, or a device path longer than a row of the build names
/// ([`SerialPath`]), is [`DialRefused::BadAddress`]; a `?metadata` span is
/// [`DialRefused::Unsupported`], as on every other scheme here. A listener reads the same text:
/// a line has no port for the stack to choose.
#[cfg(feature = "serial")]
fn serial_endpoint(endpoint: &str) -> Option<Result<Locator, DialRefused>> {
    let read = match read_serial_locator(endpoint) {
        Ok(read) => read,
        Err(SerialTextError::NotSerialScheme) => return None,
        Err(SerialTextError::EmptyAddress | SerialTextError::BadNumber(_)) => {
            return Some(Err(DialRefused::BadAddress))
        }
    };
    if !read.metadata.is_empty() {
        return Some(Err(DialRefused::Unsupported));
    }
    let line = match read.address {
        SerialAddress::Device(path) => match SerialPath::new(path) {
            Some(path) => SerialLine::Device(path),
            None => return Some(Err(DialRefused::BadAddress)),
        },
        SerialAddress::Pins { tx, rx } => SerialLine::Pins { tx, rx },
    };
    Some(Ok(Locator::Serial(SerialLocator {
        line,
        baudrate: read.baudrate,
        options: read.options,
    })))
}

/// A `unixpipe/` endpoint's text read into its locator, or `None` for a text of another scheme.
/// An empty path, a path longer than a row of the build names with the suffix of a link's end
/// ([`UnixpipePath`]), or a `file_mask` that is no decimal `u32` is [`DialRefused::BadAddress`];
/// a `?metadata` span is [`DialRefused::Unsupported`], as on every other scheme here. A listener
/// reads the same text: a path has no port for the stack to choose.
#[cfg(feature = "unixpipe")]
fn unixpipe_endpoint(endpoint: &str) -> Option<Result<Locator, DialRefused>> {
    let read = match read_unixpipe_locator(endpoint) {
        Ok(read) => read,
        Err(UnixpipeTextError::NotUnixpipeScheme) => return None,
        Err(UnixpipeTextError::EmptyPath | UnixpipeTextError::BadFileMask(_)) => {
            return Some(Err(DialRefused::BadAddress))
        }
    };
    if !read.metadata.is_empty() {
        return Some(Err(DialRefused::Unsupported));
    }
    let Some(path) = UnixpipePath::new(read.path) else {
        return Some(Err(DialRefused::BadAddress));
    };
    Some(Ok(Locator::Unixpipe(UnixpipeLocator {
        path,
        file_mask: read.file_mask,
    })))
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
    let mut text = Text(text);
    let octets = ipv4_address(&mut text)?;
    if !text.eat(b':') {
        return None;
    }
    Some(SocketAddrV4::new(Ipv4Addr::from(octets), text.port()?))
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
    let mut text = Text(text);
    if !text.eat(b'[') {
        return None;
    }
    let groups = ipv6_address(&mut text)?;
    let mut scope = 0;
    if text.eat(b'%') {
        let (digits, value) = text.number(10);
        if digits == 0 {
            return None;
        }
        scope = u32::try_from(value).ok()?;
    }
    if !(text.eat(b']') && text.eat(b':')) {
        return None;
    }
    Some(SocketAddrV6::new(
        Ipv6Addr::from(groups),
        text.port()?,
        0,
        scope,
    ))
}

/// The IPv6 address at the front of `text` as `core::net` reads one, taken from it: up to eight
/// groups, and when fewer, `::` and the rest, the groups `::` stands for being zeros. An
/// embedded IPv4 address closes the groups after `::`, or all eight without it.
fn ipv6_address(text: &mut Text<'_>) -> Option<[u16; 8]> {
    let mut head = [0u16; 8];
    let (head_size, head_ipv4) = ipv6_groups(text, &mut head);
    if head_size == head.len() {
        return Some(head);
    }
    if head_ipv4 || !(text.eat(b':') && text.eat(b':')) {
        return None;
    }
    // `::` stands for one group at least, so the groups after it are seven at most.
    let mut tail = [0u16; 7];
    let room = tail.len().saturating_sub(head_size);
    let (tail_size, _) = ipv6_groups(text, tail.get_mut(..room)?);
    let at = head.len().saturating_sub(tail_size);
    // One copy of the groups read, and not a step for each place they might take: `at` leaves as
    // many places at the end as there are groups.
    if let (Some(places), Some(groups)) = (head.get_mut(at..), tail.get(..tail_size)) {
        if places.len() == groups.len() {
            places.copy_from_slice(groups);
        }
    }
    Some(head)
}

/// One run of an IPv6 address's groups at the front of `text`, as `core::net` reads one, taken
/// from it: up to `groups.len()` groups of one to four hexadecimal digits, `:` between two, the
/// last two of which may be written as an IPv4 address. Answers how many groups it read and
/// whether an IPv4 address closed them; a separator that no group follows is not taken.
fn ipv6_groups(text: &mut Text<'_>, groups: &mut [u16]) -> (usize, bool) {
    let limit = groups.len();
    for index in 0..limit {
        let mut group = *text;
        if index > 0 && !group.eat(b':') {
            return (index, false);
        }
        // `index` is below the groups' length, so neither sum wraps.
        let (next, after_pair) = (index.wrapping_add(1), index.wrapping_add(2));
        if next < limit {
            let mut embedded = group;
            if let (Some([a, b, c, d]), Some([high, low])) = (
                ipv4_address(&mut embedded),
                groups.get_mut(index..after_pair),
            ) {
                *high = u16::from_be_bytes([a, b]);
                *low = u16::from_be_bytes([c, d]);
                *text = embedded;
                return (after_pair, true);
            }
        }
        let (digits, value) = group.number(16);
        match (digits, u16::try_from(value), groups.get_mut(index)) {
            (1..=4, Ok(value), Some(slot)) => *slot = value,
            _ => return (index, false),
        }
        *text = group;
    }
    (limit, false)
}

/// The IPv4 address at the front of `text` as `core::net` reads one, taken from it: four octets
/// of one to three decimal digits, `.` between two, none above 255 and none written with a
/// leading zero. A fourth digit in an octet refuses the address, and so does a `.` after the
/// fourth octet, which no address's text has in either family. [`socket_addr_v4`] reads one
/// before its port and [`ipv6_groups`] one as an IPv6 address's last two groups.
fn ipv4_address(text: &mut Text<'_>) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut read = 0usize;
    // Octets are read while a `.` follows one, and the address is four of them: the text ends the
    // loop, not a count of four, so the reader is one body and not one copy for each octet.
    loop {
        let leading_zero = text.0.first() == Some(&b'0');
        let (digits, value) = text.number(10);
        if digits == 0 || digits > 3 || (digits > 1 && leading_zero) {
            return None;
        }
        *octets.get_mut(read)? = u8::try_from(value).ok()?;
        read = read.wrapping_add(1);
        if !text.eat(b'.') {
            break;
        }
    }
    (read == octets.len()).then_some(octets)
}

/// The text of an address still to be read, which each reader above takes its part from. A
/// reader that may not take what it tried reads a copy and keeps it only when it reads.
///
/// One cursor over the bytes, so that no reader indexes the text: each step is a look at the
/// front, and none has a bound to check or a panic to carry.
#[derive(Clone, Copy)]
struct Text<'a>(&'a [u8]);

impl Text<'_> {
    /// Take `byte` when the text begins with it.
    fn eat(&mut self, byte: u8) -> bool {
        match self.0 {
            [first, rest @ ..] if *first == byte => {
                self.0 = rest;
                true
            }
            _ => false,
        }
    }

    /// Take the run of digits of `radix` (10 or 16) at the front: how many there were, and their
    /// value, held at `u64::MAX` once it passes it, which every reader refuses. `str::parse`
    /// would also take a leading `+`, and is a copy of the integer reader for each width.
    ///
    /// Out of line: every octet, group, scope and port is read by it, and the loop inlined at each
    /// was a copy of it in every reader above, the four octets of an IPv4 address unrolled.
    #[inline(never)]
    fn number(&mut self, radix: u8) -> (usize, u64) {
        let (mut digits, mut value) = (0usize, 0u64);
        while let [first, rest @ ..] = self.0 {
            let Some(digit) = digit_of(*first, radix) else {
                break;
            };
            value = value
                .saturating_mul(u64::from(radix))
                .saturating_add(u64::from(digit));
            digits = digits.saturating_add(1);
            self.0 = rest;
        }
        (digits, value)
    }

    /// The whole of the rest as a port: decimal digits only, leading zeros taken, none above
    /// 65535.
    fn port(mut self) -> Option<u16> {
        let (digits, value) = self.number(10);
        if digits == 0 || !self.0.is_empty() {
            return None;
        }
        u16::try_from(value).ok()
    }
}

/// The value of one ASCII digit of `radix` (10 or 16, either case), `None` for any other byte.
fn digit_of(byte: u8, radix: u8) -> Option<u8> {
    let value = match byte {
        // Each arm's byte is at or past the arm's first, and below it plus 16.
        b'0'..=b'9' => byte.wrapping_sub(b'0'),
        b'a'..=b'f' => byte.wrapping_sub(b'a').wrapping_add(10),
        b'A'..=b'F' => byte.wrapping_sub(b'A').wrapping_add(10),
        _ => return None,
    };
    (value < radix).then_some(value)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::str::FromStr;

    /// A dial's text is an address where the address reader reads one, and a host name and port
    /// where it reads none and the text is a name; the link and the port carry to every address the
    /// host resolves to. Turned red by a name read as an address or refused, or by a numeric text a
    /// C resolver would read handed to it as a name.
    #[test]
    fn a_dial_reads_a_host_name_where_no_address_is_written() {
        let at = SocketAddr::from(([127, 0, 0, 1], 7447));
        std::assert_eq!(
            read_dial_target("tcp/127.0.0.1:7447"),
            Ok(DialTarget::At(Locator::tcp(at)))
        );
        for (text, host, port) in [
            ("tcp/localhost:7447", "localhost", 7447),
            ("udp/router.example:7447", "router.example", 7447),
            ("tls/a-1.b2.example:1", "a-1.b2.example", 1),
            ("tcp/ap-demo:00080", "ap-demo", 80),
        ] {
            let Ok(DialTarget::Named(name)) = read_dial_target(text) else {
                panic!("{text} names a host");
            };
            std::assert_eq!((name.host(), name.port()), (host, port), "{text}");
            let proto = match text.split('/').next() {
                Some("udp") => LinkProto::Udp,
                Some("tcp") => LinkProto::Tcp,
                _ => LinkProto::Tls,
            };
            std::assert_eq!(name.locator(at), Locator::ip(proto, at), "{text}");
        }
        for (text, why) in [
            ("tcp/localhost:0", DialRefused::BadAddress),
            ("tcp/localhost", DialRefused::BadAddress),
            ("tcp/localhost:+80", DialRefused::BadAddress),
            ("tcp/localhost:65536", DialRefused::BadAddress),
            ("tcp/:7447", DialRefused::BadAddress),
            ("tcp/-router:7447", DialRefused::BadAddress),
            ("tcp/router-:7447", DialRefused::BadAddress),
            ("tcp/router..example:7447", DialRefused::BadAddress),
            ("tcp/router.example.:7447", DialRefused::BadAddress),
            ("tcp/router_1:7447", DialRefused::BadAddress),
            ("tcp/127.1:7447", DialRefused::BadAddress),
            ("tcp/0x7f.1:7447", DialRefused::BadAddress),
            ("tcp/0x7f000001:7447", DialRefused::BadAddress),
            ("tcp/127.0.0.256:7447", DialRefused::BadAddress),
            ("tcp/localhost:7447?prio=1", DialRefused::Unsupported),
            ("tcp/localhost:7447#iface=eth0", DialRefused::Unsupported),
            ("quic/localhost:7447", DialRefused::Unsupported),
        ] {
            std::assert_eq!(read_dial_target(text), Err(why), "{text}");
        }
        let labels = std::vec!["a".repeat(63); 5].join(".");
        let longest = std::format!("tcp/{}:7447", &labels[..HOST_NAME_MAX]);
        std::assert!(read_dial_target(&longest).is_ok(), "{longest}");
        let past = std::format!("tcp/{labels}:7447");
        std::assert_eq!(read_dial_target(&past), Err(DialRefused::BadAddress));
        let wide_label = std::format!("tcp/{}.example:7447", "a".repeat(64));
        std::assert_eq!(read_dial_target(&wide_label), Err(DialRefused::BadAddress));
    }

    /// A WebSocket dial reads a host name as the IP schemes do, and opens a WebSocket link at each
    /// address. Turned red by a `ws/` name refused or opened as another link.
    #[cfg(feature = "ws")]
    #[test]
    fn a_ws_dial_reads_a_host_name() {
        let at = SocketAddr::from(([127, 0, 0, 1], 7447));
        let Ok(DialTarget::Named(name)) = read_dial_target("ws/localhost:7447") else {
            panic!("a ws text names a host");
        };
        std::assert_eq!((name.host(), name.port()), ("localhost", 7447));
        std::assert_eq!(name.locator(at), Locator::ws(at));
    }

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

    /// A locator read from its text writes that text back, through the one reader and the one
    /// writer, by either writer (`Locator::text` and `Display`), and its IP form builds the same
    /// locator again. Turned red by a writer or a reader that drifts from the other.
    #[test]
    fn an_ip_locator_is_written_as_it_was_read() {
        for text in ["udp/127.0.0.1:7447", "tcp/10.0.0.1:80", "tls/[::1]:7447"] {
            let read = parse_locator(text).expect("a dialable locator");
            std::assert_eq!(read.text().finish(), Ok(text), "{text}");
            std::assert_eq!(std::format!("{read}"), text);
            let ip = read.as_ip().expect("an IP locator");
            std::assert_eq!(Locator::ip(ip.proto, ip.at), read);
        }
    }

    /// A WebSocket locator is read at the address a TCP one is, written back under its own scheme
    /// by either writer, and is no IP locator; a port of 0 is a listener's alone, and a stack
    /// without IPv6 refuses a bracketed address. Turned red by a `ws/` text read as another kind,
    /// or by a writer that drifts from the reader.
    #[cfg(feature = "ws")]
    #[test]
    fn a_ws_locator_is_read_at_a_socket_address_and_written_back() {
        for text in ["ws/127.0.0.1:7447", "ws/[::1]:8080"] {
            let read = parse_locator(text).expect("a dialable ws locator");
            std::assert_eq!(read.text().finish(), Ok(text), "{text}");
            std::assert_eq!(std::format!("{read}"), text);
            std::assert_eq!(read.as_ip(), None, "{text}");
            std::assert_eq!(parse_listen_locator(text), Ok(read), "{text}");
        }
        std::assert_eq!(
            parse_locator("ws/10.0.0.1:7447").map(Locator::as_ws),
            Ok(Some(crate::session_drive::WsLocator {
                at: SocketAddr::from(([10, 0, 0, 1], 7447))
            }))
        );
        std::assert_eq!(
            parse_listen_locator("ws/0.0.0.0:0"),
            Ok(Locator::ws(SocketAddr::from(([0, 0, 0, 0], 0))))
        );
        std::assert_eq!(
            parse_locator_for("ws/[::1]:7447", false),
            Err(DialRefused::Unsupported)
        );
    }

    /// What upstream's WebSocket link does not read is refused, never dropped: a config part
    /// (zenoh-pico's `tout`), a metadata part, a host name, a port of 0 to dial, another scheme
    /// that starts with the same letters. Turned red by a reader that opens the link and loses
    /// what the text asked for.
    #[cfg(feature = "ws")]
    #[test]
    fn a_ws_text_upstream_would_not_read_is_refused() {
        for (text, why) in [
            ("ws/127.0.0.1:7447#tout=1000", DialRefused::Unsupported),
            ("ws/127.0.0.1:7447?rel=1", DialRefused::Unsupported),
            ("ws/router.local:7447", DialRefused::BadAddress),
            ("ws/127.0.0.1:0", DialRefused::BadAddress),
            ("ws/", DialRefused::BadAddress),
            ("wss/127.0.0.1:7447", DialRefused::Unsupported),
            ("ws127.0.0.1:7447", DialRefused::Unsupported),
        ] {
            std::assert_eq!(parse_locator(text), Err(why), "{text}");
        }
    }

    /// A build without WebSocket links carries no `ws/` scheme: the text is refused as one it
    /// does not carry, not read as another. Turned red by a `ws` reader that escapes its feature.
    #[cfg(not(feature = "ws"))]
    #[test]
    fn a_build_without_ws_links_refuses_the_scheme() {
        std::assert_eq!(
            parse_locator("ws/127.0.0.1:7447"),
            Err(DialRefused::Unsupported)
        );
    }

    /// A serial locator read from its text writes that text back by either writer, to dial and to
    /// listen on, and is no IP locator. Turned red by a reader or a writer of the serial grammar
    /// that drifts from the other, or by a serial text read as another kind.
    #[cfg(feature = "serial")]
    #[test]
    fn a_serial_locator_is_written_as_it_was_read() {
        for text in [
            "serial//dev/ttyUSB0#baudrate=115200",
            "serial/12.13#baudrate=9600",
            "serial//dev/ttyS1#baudrate=9600;exclusive=false;tout=1000;release_on_close=false",
        ] {
            let read = parse_locator(text).expect("a dialable serial locator");
            std::assert_eq!(read.text().finish(), Ok(text), "{text}");
            std::assert_eq!(std::format!("{read}"), text);
            std::assert_eq!(read.as_ip(), None, "{text}");
            std::assert_eq!(parse_listen_locator(text), Ok(read), "{text}");
        }
    }

    /// What a serial locator names is read into its parts: the device, the baud rate (upstream's
    /// 9600 when none is written, and written back then) and the options. Turned red by a reader
    /// that loses the default or a key.
    #[cfg(feature = "serial")]
    #[test]
    fn a_serial_locator_is_read_into_its_line_and_rate() {
        use wz_session_core::locator_grammar::SerialOptions;
        let read = parse_locator("serial//dev/ttyACM0").expect("no config");
        let serial = read.as_serial().expect("a serial locator");
        std::assert_eq!(
            serial.line,
            SerialLine::Device(SerialPath::new("/dev/ttyACM0").expect("short"))
        );
        std::assert_eq!(serial.baudrate, 9600);
        std::assert_eq!(serial.options, SerialOptions::UPSTREAM);
        std::assert_eq!(
            read.text().finish(),
            Ok("serial//dev/ttyACM0#baudrate=9600")
        );
        let pins = parse_locator("serial/3.4#baudrate=57600;tout=10")
            .ok()
            .and_then(Locator::as_serial);
        std::assert_eq!(
            pins.map(|serial| (serial.line, serial.baudrate, serial.options.timeout_us)),
            Some((SerialLine::Pins { tx: 3, rx: 4 }, 57600, 10))
        );
    }

    /// A serial text this engine cannot open a line from is refused for good, with the reason:
    /// no line, a number that is no positive `u32`, a path longer than a row names, and a
    /// `?metadata` span no link here honours. Turned red by a reader that takes any of them.
    #[cfg(feature = "serial")]
    #[test]
    fn a_serial_text_that_names_no_line_is_refused() {
        use crate::session_drive::SERIAL_PATH_LEN;
        for (text, why) in [
            ("serial/#baudrate=9600", DialRefused::BadAddress),
            ("serial//dev/ttyUSB0#baudrate=0", DialRefused::BadAddress),
            ("serial//dev/ttyUSB0#baudrate=fast", DialRefused::BadAddress),
            ("serial/0.1#baudrate=9600", DialRefused::BadAddress),
            (
                "serial//dev/ttyUSB0?prio=1#baudrate=9600",
                DialRefused::Unsupported,
            ),
        ] {
            std::assert_eq!(parse_locator(text), Err(why), "{text}");
        }
        let longest = std::format!("serial//{}", "a".repeat(SERIAL_PATH_LEN - 1));
        std::assert!(parse_locator(&longest).is_ok(), "{longest}");
        let past = std::format!("serial//{}", "a".repeat(SERIAL_PATH_LEN));
        std::assert_eq!(parse_locator(&past), Err(DialRefused::BadAddress));
    }

    /// A build without serial links refuses a serial text as a scheme it does not carry. Turned
    /// red by a reader that takes it into another kind of locator.
    #[cfg(not(feature = "serial"))]
    #[test]
    fn a_build_without_serial_links_refuses_a_serial_text() {
        std::assert_eq!(
            parse_locator("serial//dev/ttyUSB0#baudrate=115200"),
            Err(DialRefused::Unsupported)
        );
    }

    /// A unixpipe locator read from its text writes that text back, to dial and to listen on, and
    /// is no IP locator. Turned red by a reader or a writer of the unixpipe grammar that drifts
    /// from the other, or by a unixpipe text read as another kind.
    #[cfg(feature = "unixpipe")]
    #[test]
    fn a_unixpipe_locator_is_written_as_it_was_read() {
        for text in [
            "unixpipe//tmp/wz.pipe",
            "unixpipe//tmp/wz.pipe#file_mask=438",
        ] {
            let read = parse_locator(text).expect("a dialable unixpipe locator");
            std::assert_eq!(read.text().finish(), Ok(text), "{text}");
            std::assert_eq!(std::format!("{read}"), text);
            std::assert_eq!(read.as_ip(), None, "{text}");
            std::assert_eq!(parse_listen_locator(text), Ok(read), "{text}");
        }
        let read = parse_locator("unixpipe//tmp/wz.pipe#file_mask=438").ok();
        std::assert_eq!(
            read.and_then(Locator::as_unixpipe),
            Some(UnixpipeLocator {
                path: UnixpipePath::new("/tmp/wz.pipe").expect("short"),
                file_mask: Some(438),
            })
        );
    }

    /// A unixpipe text this engine cannot open a link from is refused for good, with the reason:
    /// no path, a mask that is no decimal `u32`, a path a row cannot name with the suffix of an
    /// end, and a `?metadata` span no link here honours. Turned red by a reader that takes any of
    /// them, or by a path bound that leaves no room for the suffix.
    #[cfg(feature = "unixpipe")]
    #[test]
    fn a_unixpipe_text_that_names_no_path_is_refused() {
        use crate::session_drive::UNIXPIPE_PATH_LEN;
        for (text, why) in [
            ("unixpipe/", DialRefused::BadAddress),
            ("unixpipe//tmp/p#file_mask=0o600", DialRefused::BadAddress),
            ("unixpipe//tmp/p?prio=1", DialRefused::Unsupported),
        ] {
            std::assert_eq!(parse_locator(text), Err(why), "{text}");
        }
        let longest = std::format!("unixpipe/{}", "a".repeat(UNIXPIPE_PATH_LEN));
        std::assert!(parse_locator(&longest).is_ok(), "{longest}");
        let past = std::format!("unixpipe/{}", "a".repeat(UNIXPIPE_PATH_LEN + 1));
        std::assert_eq!(parse_locator(&past), Err(DialRefused::BadAddress));
        let end = std::format!("{longest}_downlink4294967295");
        std::assert!(
            end.len() <= wz_session_core::caps::MAX_LOCATOR_LEN,
            "the end of a link over the longest path fits a row"
        );
    }

    /// A build without unixpipe links refuses a unixpipe text as a scheme it does not carry.
    /// Turned red by a reader that takes it into another kind of locator.
    #[cfg(not(feature = "unixpipe"))]
    #[test]
    fn a_build_without_unixpipe_links_refuses_a_unixpipe_text() {
        std::assert_eq!(
            parse_locator("unixpipe//tmp/wz.pipe"),
            Err(DialRefused::Unsupported)
        );
    }

    /// The octet reader takes four octets and leaves what follows them, and refuses a `.` after
    /// the fourth, which no address's text has. Turned red by a reader that stops at the fourth
    /// octet whatever follows it, or one that takes fewer than four.
    #[test]
    fn the_octet_reader_takes_four_octets_and_refuses_a_fifth() {
        let mut text = Text(b"10.0.0.1:7447");
        std::assert_eq!(ipv4_address(&mut text), Some([10, 0, 0, 1]));
        std::assert_eq!(text.0, b":7447", "what follows the address is left");
        let mut text = Text(b"1.2.3.4]");
        std::assert_eq!(ipv4_address(&mut text), Some([1, 2, 3, 4]));
        std::assert_eq!(text.0, b"]");
        let refused: [&[u8]; 6] = [b"1.2.3.4.5", b"1.2.3.4.", b"1.2.3", b"1.2.3.", b"1", b""];
        for refused in refused {
            std::assert_eq!(
                ipv4_address(&mut Text(refused)),
                None,
                "{:?}",
                core::str::from_utf8(refused)
            );
        }
    }
}
