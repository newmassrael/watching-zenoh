// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The grammar of a locator's text that needs no heap: the split of a locator's body into its
//! address, metadata and config spans, and the `serial/` and `unixpipe/` leaves, read into
//! borrowed parts and written into any [`TextOut`] sink.
//!
//! One grammar for every reader of a serial locator: the heap profile's `crate::locator`
//! builds its owned endpoint out of what [`read_serial_locator`] reads and writes it back with
//! [`write_serial_address_with_config`], and an engine with no heap reads and writes the same
//! text with the same two functions, so the two cannot come to disagree on a locator.

use crate::text_out::TextOut;

/// zenoh's locator separators (`zenoh-protocol/src/core/endpoint.rs:22-24`),
/// mirrored by pico (`include/zenoh-pico/link/endpoint.h:49,71`).
/// Each is one ASCII byte, as every separator of this grammar is: the text is cut where a byte
/// search finds it, so a cut is a char boundary and no character searcher is linked to find one.
pub(crate) const LOCATOR_METADATA_SEPARATOR: u8 = b'?';
pub(crate) const LOCATOR_CONFIG_SEPARATOR: u8 = b'#';
/// The separator of the pairs of a `key=value;...` span, and of a pair's key from its value.
const PAIR_SEPARATOR: u8 = b';';
const KEY_SEPARATOR: u8 = b'=';

/// Where the first `byte`, an ASCII byte, lies in `text`.
fn find_byte(text: &str, byte: u8) -> Option<usize> {
    text.bytes().position(|at| at == byte)
}

/// `text` before and after its first `byte`, an ASCII byte, which neither half keeps; `None`
/// when it holds none. The one cut of every reader of a locator's text: the halves are taken
/// without asking again whether the cut lies between two characters, since an ASCII byte is a
/// whole character, and that question would be a copy of its own at each inlined cut.
pub fn split_once_byte(text: &str, byte: u8) -> Option<(&str, &str)> {
    debug_assert!(byte.is_ascii());
    let at = find_byte(text, byte)?;
    // SAFETY: the byte at `at` is the ASCII `byte`, a whole character, so `at` lies on a character
    // boundary of `text`, and so does the end of that byte, the start of what follows it in
    // `rest`, at most at its end.
    unsafe {
        let rest = text.get_unchecked(at..);
        Some((text.get_unchecked(..at), rest.get_unchecked(1..)))
    }
}

/// The pieces of `text` between each `byte`, an ASCII byte, as `str::split` gives them: one empty
/// piece for an empty text.
pub fn split_byte(text: &str, byte: u8) -> BytePieces<'_> {
    BytePieces {
        rest: Some(text),
        byte,
    }
}

/// The iterator [`split_byte`] answers.
pub struct BytePieces<'a> {
    /// What is left to split; `None` once the last piece is given.
    rest: Option<&'a str>,
    byte: u8,
}

impl<'a> Iterator for BytePieces<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        let rest = self.rest?;
        match split_once_byte(rest, self.byte) {
            Some((piece, after)) => {
                self.rest = Some(after);
                Some(piece)
            }
            None => {
                self.rest = None;
                Some(rest)
            }
        }
    }
}

/// The config span of an endpoint: everything after its first `#`, empty when it has none, as
/// zenoh's `config()` reads it (endpoint.rs:49-54). The span `split_locator_parts` answers as
/// `config` for the endpoint's body, read without splitting the rest.
pub fn endpoint_config(endpoint: &str) -> &str {
    split_once_byte(endpoint, LOCATOR_CONFIG_SEPARATOR).map_or("", |(_, config)| config)
}

/// R311y469 — the three spans of a locator BODY (everything after the
/// `<proto>/` separator) under zenoh's canon form
/// `<proto>/<address>[?<metadata>][#<config>]`
/// (`zenoh-protocol/src/core/endpoint.rs:460`).
///
/// Borrowed slices, so the split allocates nothing and every leaf can share it.
pub(crate) struct LocatorParts<'a> {
    /// Up to whichever of `?` / `#` comes first — zenoh `address()`
    /// (endpoint.rs:32-37), pico `_z_locator_address_from_string`
    /// (src/link/endpoint.c:110-137).
    pub(crate) address: &'a str,
    /// Between `?` and the following `#` — zenoh `metadata()` (endpoint.rs:39-47).
    /// Empty when there is no `?`.
    pub(crate) metadata: &'a str,
    /// Everything after the first `#` — zenoh `config()` (endpoint.rs:49-54).
    /// Empty when there is no `#`.
    pub(crate) config: &'a str,
}

/// R311y469 — split a locator body into address / metadata / config, mirroring
/// zenoh's three accessors. The single seam EVERY leaf goes through, so no leaf
/// can drift on where the address ends.
///
/// Before R311y469 the leaves split only `#` (and unixsock / unixpipe split
/// nothing at all), so a canon locator carrying `?<metadata>` pushed it into the
/// ADDRESS: R311y467 measured pico opening `<dev>` from
/// `serial/<dev>?meta=x#baudrate=115200` while wz built the device path
/// `<dev>?meta=x` and failed the open.
///
/// zenoh's own `metadata()` would panic on the non-canon order `#` before `?`
/// (a reversed slice); its `EndPoint::try_from` rejects that string outright
/// (endpoint.rs:626-630). Here the metadata span is simply empty in that case,
/// which agrees with zenoh byte-for-byte on every string zenoh accepts and
/// keeps `address` / `config` equal to its accessors on the rest.
pub(crate) fn split_locator_parts(body: &str) -> LocatorParts<'_> {
    let midx = find_byte(body, LOCATOR_METADATA_SEPARATOR);
    let cidx = find_byte(body, LOCATOR_CONFIG_SEPARATOR);
    let address_end = match (midx, cidx) {
        (Some(m), Some(c)) => m.min(c),
        (Some(m), None) => m,
        (None, Some(c)) => c,
        (None, None) => body.len(),
    };
    // Each separator is one ASCII byte, so a cut past it or before it is a
    // char boundary; a cut `get` refuses is no part.
    let after = |at: usize| at.saturating_add(1);
    let metadata = match (midx, cidx) {
        (Some(m), Some(c)) if m < c => body.get(after(m)..c).unwrap_or(""),
        (Some(m), None) => body.get(after(m)..).unwrap_or(""),
        _ => "",
    };
    let config = match cidx {
        Some(c) => body.get(after(c)..).unwrap_or(""),
        None => "",
    };
    LocatorParts {
        address: body.get(..address_end).unwrap_or(body),
        metadata,
        config,
    }
}

/// The scheme of a serial locator, `serial/<address>`.
pub const SERIAL_SCHEME: &str = "serial";
const SERIAL_BAUDRATE_KEY: &str = "baudrate";
// R2704 — the other three keys upstream's `pub mod config` declares, spelled
// exactly as upstream spells them so a zenoh-authored locator parses here.
const SERIAL_EXCLUSIVE_KEY: &str = "exclusive";
const SERIAL_TIMEOUT_KEY: &str = "tout";
const SERIAL_RELEASE_ON_CLOSE_KEY: &str = "release_on_close";

/// R2704 — upstream's default for `baudrate` when the locator omits it
/// (`io/zenoh-links/zenoh-link-serial/src/lib.rs` @ `const DEFAULT_BAUDRATE: u32 = 9_600;`).
///
/// wz used to REFUSE a serial locator with no `#baudrate=` tail, which matched
/// zenoh-pico (`vendor/zenoh-pico/src/link/transport/upper/serial_protocol.c`
/// @ `baudrate_str = _z_str_intmap_get(&endpoint->_config, SERIAL_CONFIG_BAUDRATE_KEY);`
/// feeds a parse that fails on the absent key) but not zenoh, which dials
/// `serial//dev/ttyUSB0` happily at 9600. A locator zenoh accepts and wz
/// refuses is a hole in the drop-in claim, and pico never EMITS such a locator,
/// so accepting it costs pico parity nothing.
pub const SERIAL_DEFAULT_BAUDRATE: u32 = 9_600;

/// R2704 — the three serial locator config keys beyond `baudrate`, with
/// upstream's own defaults.
///
/// zenoh's serial link declares FOUR keys in its `pub mod config`
/// (`io/zenoh-links/zenoh-link-serial/src/lib.rs` @ `pub const PORT_EXCLUSIVE_RAW: &str = "exclusive";`)
/// and reads every one off the endpoint config; wz bound only `baudrate`, so a
/// locator asking for any of the other three was silently ignored. They are one
/// struct rather than three loose fields because they share a fate: all three
/// are READ at the same place (the locator) and CONSUMED at the same place (the
/// tty open), and a default that lives in one named place cannot drift between
/// the parser and the renderer the way two hand-kept copies would.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialOptions {
    /// Claim the tty exclusively. Upstream default `true`
    /// (`@ const DEFAULT_EXCLUSIVE: bool = true;`).
    pub exclusive: bool,
    /// Port-level read timeout in MICROSECONDS — upstream's unit, not
    /// milliseconds (`@ const DEFAULT_TIMEOUT: u64 = 50_000;`, i.e. 50 ms).
    pub timeout_us: u64,
    /// Release the device when the link closes. Upstream default `true`
    /// (`@ const DEFAULT_RELEASE_ON_CLOSE: bool = true;`).
    pub release_on_close: bool,
}

impl SerialOptions {
    /// Upstream's default row: what a locator that names none of the three keys asks for.
    pub const UPSTREAM: Self = Self {
        exclusive: true,
        timeout_us: 50_000,
        release_on_close: true,
    };
}

impl Default for SerialOptions {
    fn default() -> Self {
        Self::UPSTREAM
    }
}

/// The address of a serial locator, borrowed from its text: a host device path
/// (`/dev/ttyUSB0`) or a TX/RX pin pair. Mirrors pico's
/// `_z_serial_endpoint_cfg_t` dev-vs-pins split
/// (`vendor/zenoh-pico/src/link/transport/upper/serial_protocol.c`
/// @ `static z_result_t _z_serial_endpoint_parse(`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialAddress<'a> {
    /// A device path opened by a host tty backend.
    Device(&'a str),
    /// A TX/RX GPIO pin pair (MCU UART HAL).
    Pins {
        /// The transmit pin.
        tx: u32,
        /// The receive pin.
        rx: u32,
    },
}

/// A `serial/...` locator read into its parts, borrowed from its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialLocatorText<'a> {
    /// The device or the pin pair.
    pub address: SerialAddress<'a>,
    /// The baud rate, [`SERIAL_DEFAULT_BAUDRATE`] when the locator names none. Carried as written:
    /// whether a backend can run a line at it is that backend's question when it opens the line
    /// (pico validates it at tty open, `vendor/zenoh-pico/src/link/transport/serial/tty_posix.c`
    /// @ `static speed_t _z_posix_tty_baudrate_to_speed(uint32_t baudrate) {`).
    pub baudrate: u32,
    /// The other three keys upstream reads.
    pub options: SerialOptions,
    /// The `?metadata` span, empty when there is none, for a reader that honours a key of it.
    pub metadata: &'a str,
}

/// Why a text is not a serial locator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialTextError<'a> {
    /// The text does not begin with the `serial/` scheme.
    NotSerialScheme,
    /// The address (between the scheme and the `?metadata` or `#config`) is empty.
    EmptyAddress,
    /// A value (the baud rate, or a pin) is not a positive `u32`: the text of it.
    BadNumber(&'a str),
}

/// Read a zenoh serial locator into its parts, allocating nothing.
///
/// Accepted forms (mirror of `_z_serial_endpoint_parse`,
/// `vendor/zenoh-pico/src/link/transport/upper/serial_protocol.c`
/// @ `static z_result_t _z_serial_endpoint_parse(`):
/// - device: `serial//dev/ttyUSB0#baudrate=115200`
/// - pins:   `serial/12.13#baudrate=115200`
///
/// The scheme is the substring before the first `/`; the remainder is
/// `<address>[?<metadata>][#<config>]`. An address containing `.` is read as a
/// `TX.RX` pin pair, otherwise as a device path — the same `.`-heuristic pico
/// uses (`vendor/zenoh-pico/src/link/transport/upper/serial_protocol.c`
/// @ `dot = strchr(address, '.');`).
pub fn read_serial_locator(locator: &str) -> Result<SerialLocatorText<'_>, SerialTextError<'_>> {
    let (scheme, rest) = split_once_byte(locator, b'/').ok_or(SerialTextError::NotSerialScheme)?;
    if scheme != SERIAL_SCHEME {
        return Err(SerialTextError::NotSerialScheme);
    }
    let parts = split_locator_parts(rest);
    if parts.address.is_empty() {
        return Err(SerialTextError::EmptyAddress);
    }
    let baudrate = baudrate(parts.config)?;
    let options = options(parts.config);
    let address = match split_once_byte(parts.address, b'.') {
        Some((tx, rx)) => SerialAddress::Pins {
            tx: positive_u32(tx)?,
            rx: positive_u32(rx)?,
        },
        None => SerialAddress::Device(parts.address),
    };
    Ok(SerialLocatorText {
        address,
        baudrate,
        options,
        metadata: parts.metadata,
    })
}

/// Write the address of a serial locator and the `#config` it needs to be read back as it was
/// (everything after `serial/`), into `out`: what [`read_serial_locator`] reads.
///
/// The `#baudrate=` key is always written, even though the reader defaults it (R2704): zenoh-pico's
/// parser still requires the key, so a locator written without it is one a pico peer cannot read.
/// The other three are written only when they differ from upstream's default: written always,
/// they would change every serial locator this tree produces (and hand a pico peer three keys its
/// config map has no slot for); written never, a caller's choice would be lost at the first
/// reconnect, which reads this text again.
pub fn write_serial_address_with_config<W: TextOut + ?Sized>(
    out: &mut W,
    address: SerialAddress<'_>,
    baudrate: u32,
    options: SerialOptions,
) {
    match address {
        SerialAddress::Device(path) => out.push_str(path),
        SerialAddress::Pins { tx, rx } => {
            out.push_u64(u64::from(tx));
            out.push_str(".");
            out.push_u64(u64::from(rx));
        }
    }
    out.push_str("#");
    out.push_str(SERIAL_BAUDRATE_KEY);
    out.push_str("=");
    out.push_u64(u64::from(baudrate));
    let defaults = SerialOptions::UPSTREAM;
    if options.exclusive != defaults.exclusive {
        push_key(out, SERIAL_EXCLUSIVE_KEY);
        out.push_str(bool_text(options.exclusive));
    }
    if options.timeout_us != defaults.timeout_us {
        push_key(out, SERIAL_TIMEOUT_KEY);
        out.push_u64(options.timeout_us);
    }
    if options.release_on_close != defaults.release_on_close {
        push_key(out, SERIAL_RELEASE_ON_CLOSE_KEY);
        out.push_str(bool_text(options.release_on_close));
    }
}

/// `;key=`, the start of one more pair of the config list.
fn push_key<W: TextOut + ?Sized>(out: &mut W, key: &str) {
    out.push_str(";");
    out.push_str(key);
    out.push_str("=");
}

/// A flag as `{flag}` prints it, which is what upstream's `bool::from_str` reads back.
const fn bool_text(flag: bool) -> &'static str {
    if flag {
        "true"
    } else {
        "false"
    }
}

/// R2704 — read `exclusive`, `tout` and `release_on_close` out of the
/// `#`-delimited config tail, each falling back to upstream's default.
///
/// The fallback is upstream's and is deliberately looser than [`baudrate`]'s.
/// These three keys exist in zenoh only, and zenoh reads each as
/// `T::from_str(v).unwrap_or(DEFAULT)`
/// (`io/zenoh-links/zenoh-link-serial/src/lib.rs` @ `pub fn get_exclusive(endpoint: &EndPoint) -> bool {`),
/// so an unparseable value takes the default and the locator still dials.
/// `baudrate` is the one key BOTH references know, and zenoh-pico REFUSES a
/// malformed one, so the refusing arm stays there: where the two references
/// disagree about an error arm, wz takes the one that fails fast, and where only
/// zenoh has an opinion, wz takes zenoh's.
fn options(config: &str) -> SerialOptions {
    let mut options = SerialOptions::UPSTREAM;
    for pair in split_byte(config, PAIR_SEPARATOR) {
        let Some((key, value)) = split_once_byte(pair, KEY_SEPARATOR) else {
            continue;
        };
        match key {
            SERIAL_EXCLUSIVE_KEY => {
                options.exclusive = value.parse().unwrap_or(options.exclusive);
            }
            SERIAL_TIMEOUT_KEY => {
                options.timeout_us = value.parse().unwrap_or(options.timeout_us);
            }
            SERIAL_RELEASE_ON_CLOSE_KEY => {
                options.release_on_close = value.parse().unwrap_or(options.release_on_close);
            }
            _ => {}
        }
    }
    options
}

/// `baudrate=<u32>` out of the `#`-delimited config tail (`key=value` pairs separated by `;`).
///
/// R2704 — ABSENT yields [`SERIAL_DEFAULT_BAUDRATE`], which is what zenoh does.
/// MALFORMED is [`SerialTextError::BadNumber`], because that is the arm both
/// references can be read for and zenoh-pico takes it: silently running a tty at
/// 9600 because someone typed `baudrate=115.200` is a misconfiguration this tree
/// refuses to paper over.
fn baudrate(config: &str) -> Result<u32, SerialTextError<'_>> {
    match config_value(config, SERIAL_BAUDRATE_KEY) {
        Some(value) => positive_u32(value),
        None => Ok(SERIAL_DEFAULT_BAUDRATE),
    }
}

/// A positive `u32` config value (baud rate or pin). Pico's `_z_serial_parse_u32`
/// (`vendor/zenoh-pico/src/link/transport/upper/serial_protocol.c`
/// @ `parsed == 0 || parsed > UINT32_MAX`) rejects zero — a `0` baud rate or pin
/// number is invalid — so `0` is a `BadNumber` here too, for parity.
fn positive_u32(text: &str) -> Result<u32, SerialTextError<'_>> {
    match text.parse::<u32>() {
        Ok(value) if value != 0 => Ok(value),
        _ => Err(SerialTextError::BadNumber(text)),
    }
}

/// The scheme of a unixpipe locator, `unixpipe/<path>`.
pub const UNIXPIPE_SCHEME: &str = "unixpipe";

/// zenoh's one unixpipe config key, the creation mode of the link's FIFOs
/// (`io/zenoh-links/zenoh-link-unixpipe/src/unix/mod.rs` @ `pub const FILE_ACCESS_MASK: &str = "file_mask";`).
pub const UNIXPIPE_FILE_MASK_KEY: &str = "file_mask";

/// A `unixpipe/...` locator read into its parts, borrowed from its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnixpipeLocatorText<'a> {
    /// The base path of the link's FIFOs, to which a link appends `_uplink` and `_downlink`.
    pub path: &'a str,
    /// The `#file_mask=<n>` creation mode, `None` when the locator names none and the
    /// opener's default applies. Decimal, as upstream reads it
    /// (`io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs` @ `val.parse().unwrap_or(*FILE_ACCESS_MASK)`),
    /// so `file_mask=511` is `0o777`.
    pub file_mask: Option<u32>,
    /// The `?metadata` span, empty when there is none.
    pub metadata: &'a str,
}

/// Why a text is not a unixpipe locator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnixpipeTextError<'a> {
    /// The text does not begin with the `unixpipe/` scheme.
    NotUnixpipeScheme,
    /// The path (between the scheme and the `?metadata` or `#config`) is empty.
    EmptyPath,
    /// The `file_mask` value is not a decimal `u32`: the text of it. Upstream falls back to its
    /// default there; a typo in the one key that decides who else on the host may open the link is
    /// refused here instead.
    BadFileMask(&'a str),
}

/// Read a zenoh unixpipe locator into its parts, allocating nothing: `unixpipe/<path>`, the
/// path taken verbatim (an absolute one keeps its `/`: `unixpipe//tmp/wz.pipe` is the path
/// `/tmp/wz.pipe`), and the `file_mask` of the config span, never of the metadata one, the first
/// one written when there are several, as upstream's `Parameters::get` takes it. An empty value
/// is no mask.
pub fn read_unixpipe_locator(
    locator: &str,
) -> Result<UnixpipeLocatorText<'_>, UnixpipeTextError<'_>> {
    let (scheme, rest) =
        split_once_byte(locator, b'/').ok_or(UnixpipeTextError::NotUnixpipeScheme)?;
    if scheme != UNIXPIPE_SCHEME {
        return Err(UnixpipeTextError::NotUnixpipeScheme);
    }
    let parts = split_locator_parts(rest);
    if parts.address.is_empty() {
        return Err(UnixpipeTextError::EmptyPath);
    }
    Ok(UnixpipeLocatorText {
        path: parts.address,
        file_mask: unixpipe_file_mask(parts.config)?,
        metadata: parts.metadata,
    })
}

/// The `file_mask` a bare `key=value;...` config span names: the first one written, `None` when
/// it is absent or empty, [`UnixpipeTextError::BadFileMask`] when it is no decimal `u32`. The one
/// reader of the key, for a locator's config span and for the span upstream renders out of
/// `transport/link/unixpipe/file_access_mask` alike.
pub fn unixpipe_file_mask(config: &str) -> Result<Option<u32>, UnixpipeTextError<'_>> {
    match config_value(config, UNIXPIPE_FILE_MASK_KEY) {
        None | Some("") => Ok(None),
        Some(value) => value
            .parse::<u32>()
            .map(Some)
            .map_err(|_| UnixpipeTextError::BadFileMask(value)),
    }
}

/// Write the path of a unixpipe locator and the `#file_mask=` it needs to be read back as it was
/// (everything after `unixpipe/`), into `out`: what [`read_unixpipe_locator`] reads. A locator
/// that names no mask is written without a config span.
pub fn write_unixpipe_path_with_config<W: TextOut + ?Sized>(
    out: &mut W,
    path: &str,
    file_mask: Option<u32>,
) {
    out.push_str(path);
    if let Some(mask) = file_mask {
        out.push_str("#");
        out.push_str(UNIXPIPE_FILE_MASK_KEY);
        out.push_str("=");
        out.push_u64(u64::from(mask));
    }
}

/// The first value a `key=value;...` span gives `key`, as upstream's `Parameters::get` reads it;
/// `None` when no pair names it. The one reader of a key of a span, for this grammar's leaves and
/// for a reader of an endpoint's config elsewhere ([`endpoint_config`]).
pub fn config_value<'a>(config: &'a str, key: &'a str) -> Option<&'a str> {
    config_values(config, key).next()
}

/// Every key a `key=value;...` span names, in the order written: a pair with no `=` names none.
/// Read by the heap profile's locator (`crate::locator`), which checks a span's keys against a set.
#[cfg(feature = "alloc")]
pub(crate) fn config_keys(config: &str) -> impl Iterator<Item = &str> {
    split_byte(config, PAIR_SEPARATOR)
        .filter_map(|pair| split_once_byte(pair, KEY_SEPARATOR))
        .map(|(key, _)| key)
}

/// Every value a `key=value;...` span gives `key`, in the order written, as upstream's
/// `Parameters::values` reads them: a key a link reads more than once (`join`) takes them all.
pub(crate) fn config_values<'a>(
    config: &'a str,
    key: &'a str,
) -> impl Iterator<Item = &'a str> + 'a {
    split_byte(config, PAIR_SEPARATOR)
        .filter_map(|pair| split_once_byte(pair, KEY_SEPARATOR))
        .filter(move |(k, _)| *k == key)
        .map(|(_, value)| value)
}

/// A `dscp` value in upstream's exact accepted set, or `None`.
///
/// Mirrors `parse_dscp`
/// (`io/zenoh-link-commons/src/dscp.rs` @ `dscp.split('|')`): `|`-separated
/// integers OR-ed together, each decimal, `0x`/`0X` hexadecimal, or `0B`
/// binary. Upstream also lists a `0xb` binary prefix, but its `0x` arm is tried
/// first and takes every string that prefix could match, so `0xb101` is
/// hexadecimal there and here. Mirrored rather than corrected: an operator's
/// string must mean the same thing to both implementations. Any part that does
/// not parse refuses the whole value, as upstream's `reduce` over `Option`s does.
pub fn parse_dscp_value(value: &str) -> Option<u32> {
    fn part(s: &str) -> Option<u32> {
        if let Some(hex) = ["0x", "0X"].iter().find_map(|p| s.strip_prefix(p)) {
            u32::from_str_radix(hex, 16).ok()
        } else if let Some(bin) = ["0xb", "0B"].iter().find_map(|p| s.strip_prefix(p)) {
            u32::from_str_radix(bin, 2).ok()
        } else {
            s.parse::<u32>().ok()
        }
    }
    split_byte(value, b'|')
        .map(part)
        .reduce(|a, b| Some(a? | b?))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::{
        read_serial_locator, read_unixpipe_locator, write_serial_address_with_config,
        write_unixpipe_path_with_config, SerialAddress, SerialLocatorText, SerialOptions,
        SerialTextError, UnixpipeLocatorText, UnixpipeTextError, SERIAL_DEFAULT_BAUDRATE,
    };
    use crate::text_out::FixedText;

    /// A byte split gives the pieces `str::split` gives at the same ASCII byte, an empty piece for
    /// each empty run and one for an empty text. Turned red by a split that drops an empty piece
    /// or the last one.
    #[test]
    fn a_byte_split_gives_the_pieces_a_split_at_the_character_gives() {
        for text in ["", ";", "a", "a;b", ";a;;b;", "é;ü=1;;", "iface=lo;ttl=1"] {
            let by_byte: alloc::vec::Vec<&str> = super::split_byte(text, b';').collect();
            let by_char: alloc::vec::Vec<&str> = text.split(';').collect();
            assert_eq!(by_byte, by_char, "{text:?}");
            assert_eq!(
                super::split_once_byte(text, b';'),
                text.split_once(';'),
                "{text:?}"
            );
        }
    }

    /// An endpoint's config span is all after its first `#`, and a key of it is the first pair
    /// whose text before its first `=` is the key: a key only contained in a pair, a later `#`
    /// or the metadata span names nothing. Turned red by a span cut at a later `#`, or a key
    /// found inside another pair.
    #[test]
    fn a_config_key_is_read_from_the_span_after_the_first_hash() {
        use super::{config_value, endpoint_config};
        assert_eq!(endpoint_config("udp/224.0.0.224:7447"), "");
        assert_eq!(endpoint_config("udp/224.0.0.224:7447#"), "");
        assert_eq!(endpoint_config("udp/a?rel=0#iface=lo#x"), "iface=lo#x");
        fn value(endpoint: &str) -> Option<&str> {
            config_value(endpoint_config(endpoint), "iface")
        }
        assert_eq!(value("udp/224.0.0.224:7447#iface=lo"), Some("lo"));
        assert_eq!(
            value("udp/224.0.0.224:7447#ttl=1;iface=lo;iface=eth0"),
            Some("lo")
        );
        assert_eq!(value("udp/224.0.0.224:7447#iface="), Some(""));
        assert_eq!(value("udp/224.0.0.224:7447#iface"), None);
        assert_eq!(value("udp/224.0.0.224:7447#xiface=lo"), None);
        assert_eq!(value("udp/224.0.0.224:7447#ttl=iface=lo"), None);
        assert_eq!(value("udp/224.0.0.224:7447#ttl#iface=lo"), None);
        assert_eq!(value("udp/224.0.0.224:7447?iface=lo"), None);
    }

    /// The address and config a locator's parts are written as, after `serial/`.
    fn written(read: &SerialLocatorText<'_>) -> FixedText<128> {
        let mut out = FixedText::new();
        write_serial_address_with_config(&mut out, read.address, read.baudrate, read.options);
        out
    }

    #[test]
    fn a_serial_locator_is_read_without_a_heap_and_written_back_as_it_was() {
        for text in [
            "serial//dev/ttyUSB0#baudrate=115200",
            "serial/12.13#baudrate=9600",
            "serial//dev/ttyS1#baudrate=9600;exclusive=false",
            "serial//dev/ttyS1#baudrate=9600;tout=1000",
            "serial//dev/ttyS1#baudrate=9600;exclusive=false;tout=1;release_on_close=false",
        ] {
            let read = read_serial_locator(text).expect(text);
            let body = text.strip_prefix("serial/").expect(text);
            assert_eq!(written(&read).finish(), Ok(body), "{text}");
        }
    }

    #[test]
    fn the_reader_takes_the_address_baudrate_and_options_apart() {
        assert_eq!(
            read_serial_locator("serial//dev/ttyUSB0?prio=1#baudrate=115200;tout=7"),
            Ok(SerialLocatorText {
                address: SerialAddress::Device("/dev/ttyUSB0"),
                baudrate: 115_200,
                options: SerialOptions {
                    timeout_us: 7,
                    ..SerialOptions::UPSTREAM
                },
                metadata: "prio=1",
            })
        );
        assert_eq!(
            read_serial_locator("serial/3.4").map(|read| (read.address, read.baudrate)),
            Ok((
                SerialAddress::Pins { tx: 3, rx: 4 },
                SERIAL_DEFAULT_BAUDRATE
            ))
        );
    }

    #[test]
    fn a_locator_without_a_baudrate_is_written_with_the_default_one() {
        let read = read_serial_locator("serial//dev/ttyUSB0").expect("no config");
        assert_eq!(written(&read).finish(), Ok("/dev/ttyUSB0#baudrate=9600"));
    }

    #[test]
    fn what_is_not_a_serial_locator_is_refused_with_its_reason() {
        assert_eq!(
            read_serial_locator("tcp/127.0.0.1:7447"),
            Err(SerialTextError::NotSerialScheme)
        );
        assert_eq!(
            read_serial_locator("serial"),
            Err(SerialTextError::NotSerialScheme)
        );
        assert_eq!(
            read_serial_locator("serial/#baudrate=9600"),
            Err(SerialTextError::EmptyAddress)
        );
        assert_eq!(
            read_serial_locator("serial//dev/ttyUSB0#baudrate=0"),
            Err(SerialTextError::BadNumber("0"))
        );
        assert_eq!(
            read_serial_locator("serial/1.x#baudrate=9600"),
            Err(SerialTextError::BadNumber("x"))
        );
        // A malformed key upstream alone reads takes its default; the baud rate does not.
        assert_eq!(
            read_serial_locator("serial//dev/ttyUSB0#tout=soon").map(|read| read.options),
            Ok(SerialOptions::UPSTREAM)
        );
    }

    /// A unixpipe locator is read without a heap and written back as it was: the path, and the
    /// mask when one is named. Turned red by a reader or a writer that drifts from the other.
    #[test]
    fn a_unixpipe_locator_is_read_without_a_heap_and_written_back_as_it_was() {
        for text in [
            "unixpipe//tmp/wz.pipe",
            "unixpipe/rel.pipe",
            "unixpipe//tmp/wz.pipe#file_mask=416",
        ] {
            let read = read_unixpipe_locator(text).expect(text);
            let mut out = FixedText::<64>::new();
            write_unixpipe_path_with_config(&mut out, read.path, read.file_mask);
            assert_eq!(
                out.finish(),
                Ok(text.strip_prefix("unixpipe/").expect(text)),
                "{text}"
            );
        }
    }

    /// The reader takes the path, the first `file_mask` of the config span (never of the
    /// metadata) and the metadata apart. Turned red by a reader that reads the mask out of the
    /// metadata, takes the last of two, or keeps a separator in the path.
    #[test]
    fn the_unixpipe_reader_takes_the_path_mask_and_metadata_apart() {
        assert_eq!(
            read_unixpipe_locator(
                "unixpipe//tmp/wz.pipe?file_mask=1#iface=x;file_mask=416;file_mask=7"
            ),
            Ok(UnixpipeLocatorText {
                path: "/tmp/wz.pipe",
                file_mask: Some(416),
                metadata: "file_mask=1",
            })
        );
        assert_eq!(
            read_unixpipe_locator("unixpipe//tmp/wz.pipe#file_mask=").map(|read| read.file_mask),
            Ok(None)
        );
    }

    /// What is not a unixpipe locator is refused with its reason. Turned red by a reader that
    /// takes another scheme, an empty path, or a mask that is no decimal `u32`.
    #[test]
    fn what_is_not_a_unixpipe_locator_is_refused_with_its_reason() {
        assert_eq!(
            read_unixpipe_locator("unixsock//tmp/wz.sock"),
            Err(UnixpipeTextError::NotUnixpipeScheme)
        );
        assert_eq!(
            read_unixpipe_locator("unixpipe"),
            Err(UnixpipeTextError::NotUnixpipeScheme)
        );
        assert_eq!(
            read_unixpipe_locator("unixpipe/#file_mask=416"),
            Err(UnixpipeTextError::EmptyPath)
        );
        assert_eq!(
            read_unixpipe_locator("unixpipe//tmp/p#file_mask=0o600"),
            Err(UnixpipeTextError::BadFileMask("0o600"))
        );
    }
}
