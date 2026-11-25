// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y579 (G9) — the raweth (L2) link's FRAMING: the Ethernet header zenoh
//! puts a zenoh batch inside, and the `reth/` locator that configures it.
//!
//! Reference: `vendor/zenoh-pico/include/zenoh-pico/link/transport/raweth.h`
//! (the two header structs), `vendor/zenoh-pico/src/transport/raweth/tx.c:102-152`
//! (how they are written), `.../rx.c:39-73` (how they are read back) and
//! `.../link.c:62-65` (the defaults). All four are IN-TREE, so unlike the
//! zenoh-side references this one is readable from every clone.
//!
//! ## The header is NOT a standard Ethernet header
//!
//! A standard Ethernet II frame is `dmac[6] smac[6] ethertype[2]` = 14 bytes,
//! and the payload length is inferred from the frame. zenoh-pico's raweth
//! transport writes **16** bytes: it appends its own explicit `data_length`
//! after the ethertype (`_zp_eth_header_t`), and 20 bytes in the VLAN form
//! (`_zp_eth_vlan_header_t`, which inserts `vlan_type` + `tag` before the
//! ethertype). A reader that assumed the standard 14-byte header would take
//! the first two payload bytes as the last two header bytes and be wrong about
//! everything after.
//!
//! ## Byte order is NOT uniform across the header, and that is pico's shape
//!
//! pico builds the header as a C struct and `memcpy`s it onto the wire
//! (tx.c:135/145), so `ethtype`, `vlan_type` and `tag` land in the HOST's byte
//! order, while `data_length` is passed through `htons` and lands BIG-endian.
//! The default ethertype constant is written to match: `0x72e0` in the config
//! reaches the wire as `e0 72` on a little-endian host, and `_ZP_ETH_TYPE_VLAN`
//! is spelled `0x0081` precisely so that it lands as the real `81 00`.
//!
//! wz reproduces that exactly rather than "fixing" it, because the point of a
//! link is to interoperate. [`RawEthHeader::encode_into`] therefore writes
//! those three fields NATIVE-endian and `data_length` big-endian. On a
//! big-endian host wz and pico would agree with each other and both differ
//! from a little-endian pico — which is pico's own property, is asserted
//! rather than hidden by `tests::the_wire_order_is_picos_not_a_tidied_one`,
//! and is why this module documents it instead of normalising it away.

/// Bytes in a MAC address (`_ZP_MAC_ADDR_LENGTH`).
pub const MAC_LEN: usize = 6;

/// Largest frame the link carries, header included (`_ZP_MAX_ETH_FRAME_SIZE`).
pub const MAX_ETH_FRAME_SIZE: usize = 1514;

/// `sizeof(_zp_eth_header_t)` — six, six, two, two, no padding.
pub const ETH_HEADER_LEN: usize = 16;

/// `sizeof(_zp_eth_vlan_header_t)` — the above plus `vlan_type` and `tag`.
pub const ETH_VLAN_HEADER_LEN: usize = 20;

/// The VLAN ethertype AS PICO SPELLS IT (`_ZP_ETH_TYPE_VLAN`): byte-swapped in
/// the source so a little-endian `memcpy` lands the real `0x8100` on the wire.
/// Compared against the decoded native-endian field, never against `0x8100`.
pub const ETH_TYPE_VLAN: u16 = 0x0081;

/// `_ZP_RAWETH_DEFAULT_ETHTYPE` (link.c:62).
pub const DEFAULT_ETHTYPE: u16 = 0x72e0;

/// `_ZP_RAWETH_DEFAULT_INTERFACE` (link.c:63).
pub const DEFAULT_INTERFACE: &str = "lo";

/// `_ZP_RAWETH_DEFAULT_SMAC` (link.c:64).
pub const DEFAULT_SMAC: [u8; MAC_LEN] = [0x30, 0x03, 0xc8, 0x37, 0x25, 0xa1];

/// The default mapping entry's destination MAC (`_ZP_RAWETH_DEFAULT_MAPPING`,
/// link.c:65).
pub const DEFAULT_DMAC: [u8; MAC_LEN] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

/// The locator scheme (`RAWETH_SCHEMA`).
pub const RAWETH_SCHEMA: &str = "reth";

/// The longest `reth/` endpoint a session joins by, which [`parse_reth_locator`] refuses past.
/// Every row of a [`RethLocator`] is sized from it, so a value that fits the endpoint fits its
/// row: nothing is allocated and nothing is cut.
pub const RETH_ENDPOINT_LEN: usize = crate::caps::MAX_RAWETH_ENDPOINT_LEN;

/// The shortest text a config key can follow: the scheme and the config separator, no address.
const SHORTEST_HEAD: usize = "reth/#".len();

/// Characters of a MAC as a locator writes it.
const MAC_TEXT_LEN: usize = "00:00:00:00:00:00".len();

/// The shortest mapping entry: no key, a MAC, no tag.
const SHORTEST_MAPPING_ENTRY: usize = MAC_TEXT_LEN + "##".len();

/// The most mapping entries an endpoint of [`RETH_ENDPOINT_LEN`] bytes can name, and never less
/// than the one default entry a link that names none sends by. The first entry needs no `,`
/// before it, hence the one byte added.
pub const RETH_MAPPING_CAPACITY: usize = at_least(
    1,
    (RETH_ENDPOINT_LEN.saturating_sub(SHORTEST_HEAD + "mapping=".len()) + 1)
        / (SHORTEST_MAPPING_ENTRY + 1),
);

/// The most source MACs the whitelist of an endpoint of [`RETH_ENDPOINT_LEN`] bytes can name.
pub const RETH_WHITELIST_CAPACITY: usize =
    (RETH_ENDPOINT_LEN.saturating_sub(SHORTEST_HEAD + "whitelist=".len()) + 1) / (MAC_TEXT_LEN + 1);

/// `value`, raised to `floor` when it is less.
const fn at_least(floor: usize, value: usize) -> usize {
    if value < floor {
        floor
    } else {
        value
    }
}

/// What can go wrong framing, deframing, or configuring a raweth link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawEthError {
    /// Fewer bytes than the header the frame's own ethertype selects.
    Truncated {
        /// Bytes available.
        got: usize,
        /// Bytes the header needs.
        need: usize,
    },
    /// The header's `data_length` claims more payload than the frame carries.
    /// pico rejects the same case at rx.c:54/65 rather than reading past it.
    LengthOverrun {
        /// What the header claimed.
        claimed: usize,
        /// What was actually there.
        available: usize,
    },
    /// The frame would exceed [`MAX_ETH_FRAME_SIZE`].
    FrameTooLarge {
        /// The size that was asked for.
        size: usize,
    },
    /// The destination buffer is too small for the frame.
    BufferTooSmall {
        /// Bytes needed.
        need: usize,
        /// Bytes available.
        got: usize,
    },
    /// A locator that is not `reth/...`.
    NotRawEth,
    /// An endpoint longer than [`RETH_ENDPOINT_LEN`]: no row of the build holds it.
    TooLong,
    /// A MAC that is not six colon-separated hex octets.
    MalformedMac,
}

impl core::fmt::Display for RawEthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RawEthError::Truncated { got, need } => {
                write!(f, "raweth frame is {got} bytes, header needs {need}")
            }
            RawEthError::LengthOverrun { claimed, available } => write!(
                f,
                "raweth header claims {claimed} payload bytes but {available} are present"
            ),
            RawEthError::FrameTooLarge { size } => {
                write!(f, "raweth frame of {size} exceeds {MAX_ETH_FRAME_SIZE}")
            }
            RawEthError::BufferTooSmall { need, got } => {
                write!(f, "raweth frame needs {need} bytes, buffer holds {got}")
            }
            RawEthError::NotRawEth => write!(f, "locator scheme is not {RAWETH_SCHEMA}"),
            RawEthError::TooLong => {
                write!(
                    f,
                    "raweth endpoint is longer than {RETH_ENDPOINT_LEN} bytes"
                )
            }
            RawEthError::MalformedMac => write!(f, "MAC is not six colon-separated hex octets"),
        }
    }
}

/// The header zenoh-pico's raweth transport writes, in either of its two
/// widths.
///
/// `vlan` carries the tag AND selects the width: `Some` is the 20-byte
/// `_zp_eth_vlan_header_t`, `None` the 16-byte `_zp_eth_header_t`. Modelling
/// it as one type with an `Option` rather than two structs is what makes the
/// width impossible to get wrong at a call site — the pico code has to
/// remember to branch at four separate places (tx.c:105/107, 124/138).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawEthHeader {
    /// Destination MAC.
    pub dmac: [u8; MAC_LEN],
    /// Source MAC.
    pub smac: [u8; MAC_LEN],
    /// VLAN tag, native-endian as pico stores it. `None` = no VLAN.
    pub vlan: Option<u16>,
    /// Ethertype, native-endian as pico stores it (see the module doc).
    pub ethtype: u16,
    /// Payload bytes following the header. BIG-endian on the wire.
    pub data_length: u16,
}

impl RawEthHeader {
    /// A header for `payload_len` bytes between two MACs, no VLAN.
    pub fn new(dmac: [u8; MAC_LEN], smac: [u8; MAC_LEN], ethtype: u16, payload_len: u16) -> Self {
        Self {
            dmac,
            smac,
            vlan: None,
            ethtype,
            data_length: payload_len,
        }
    }

    /// Tag this header, widening it to the VLAN form.
    pub fn with_vlan(mut self, tag: u16) -> Self {
        self.vlan = Some(tag);
        self
    }

    /// Width on the wire.
    pub fn len(&self) -> usize {
        if self.vlan.is_some() {
            ETH_VLAN_HEADER_LEN
        } else {
            ETH_HEADER_LEN
        }
    }

    /// Never true — a raweth header always occupies bytes. Present because
    /// clippy asks for it beside `len`.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Write the header at the front of `out`, returning its width.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, RawEthError> {
        let need = self.len();
        let got = out.len();
        let too_small = || RawEthError::BufferTooSmall { need, got };
        // Nothing is written into a buffer too small for the whole header.
        let head = out.get_mut(..need).ok_or_else(too_small)?;
        let rest = put(head, self.dmac).and_then(|rest| put(rest, self.smac));
        let rest = match self.vlan {
            // pico memcpy's the struct, so these two ride the host's order.
            Some(tag) => rest
                .and_then(|rest| put(rest, ETH_TYPE_VLAN.to_ne_bytes()))
                .and_then(|rest| put(rest, tag.to_ne_bytes())),
            None => rest,
        };
        rest.and_then(|rest| put(rest, self.ethtype.to_ne_bytes()))
            // ...and this one alone goes through htons (tx.c:134/145).
            .and_then(|rest| put(rest, self.data_length.to_be_bytes()))
            .ok_or_else(too_small)?;
        Ok(need)
    }

    /// Read a header from the front of `bytes`, returning it and its width.
    ///
    /// The VLAN form is detected exactly as pico detects it (rx.c:42): the
    /// two bytes at the ethertype offset equal `_ZP_ETH_TYPE_VLAN`. That is a
    /// read of the NON-vlan layout used to decide whether the layout is the
    /// VLAN one, which works because the field sits at the same offset in
    /// both.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), RawEthError> {
        let truncated = |need: usize| RawEthError::Truncated {
            got: bytes.len(),
            need,
        };
        // The 16 bytes both widths begin with: two MACs and two 16-bit fields.
        let Some((dmac, smac, first, second, rest)) =
            take::<MAC_LEN>(bytes).and_then(|(dmac, rest)| {
                let (smac, rest) = take::<MAC_LEN>(rest)?;
                let (first, rest) = take::<2>(rest)?;
                let (second, rest) = take::<2>(rest)?;
                Some((dmac, smac, first, second, rest))
            })
        else {
            return Err(truncated(ETH_HEADER_LEN));
        };
        let first = u16::from_ne_bytes(first);
        if first == ETH_TYPE_VLAN {
            let Some((ethtype, length)) =
                take::<2>(rest).and_then(|(ethtype, rest)| Some((ethtype, take::<2>(rest)?.0)))
            else {
                return Err(truncated(ETH_VLAN_HEADER_LEN));
            };
            let tag = u16::from_ne_bytes(second);
            let ethtype = u16::from_ne_bytes(ethtype);
            let data_length = u16::from_be_bytes(length);
            Ok((
                Self {
                    dmac,
                    smac,
                    vlan: Some(tag),
                    ethtype,
                    data_length,
                },
                ETH_VLAN_HEADER_LEN,
            ))
        } else {
            let data_length = u16::from_be_bytes(second);
            Ok((
                Self {
                    dmac,
                    smac,
                    vlan: None,
                    ethtype: first,
                    data_length,
                },
                ETH_HEADER_LEN,
            ))
        }
    }
}

/// `bytes` written at the front of `out`, and the rest of `out`; `None` when it is shorter.
fn put<const N: usize>(out: &mut [u8], bytes: [u8; N]) -> Option<&mut [u8]> {
    let (head, rest) = out.split_first_chunk_mut::<N>()?;
    *head = bytes;
    Some(rest)
}

/// The first `N` bytes of `bytes` and the rest; `None` when it is shorter.
fn take<const N: usize>(bytes: &[u8]) -> Option<([u8; N], &[u8])> {
    let (head, rest) = bytes.split_first_chunk::<N>()?;
    Some((*head, rest))
}

/// Build one raweth frame: the header (with `data_length` set from `payload`)
/// followed by the payload.
///
/// `header.data_length` is OVERWRITTEN from `payload.len()` rather than
/// trusted. A length field that can disagree with the bytes it describes is
/// the one field a caller must not be able to get wrong, and pico computes it
/// the same way (tx.c:134/145) rather than accepting it.
#[cfg(feature = "alloc")]
pub fn frame(header: &RawEthHeader, payload: &[u8]) -> Result<alloc::vec::Vec<u8>, RawEthError> {
    let total = header.len().saturating_add(payload.len());
    if total > MAX_ETH_FRAME_SIZE {
        return Err(RawEthError::FrameTooLarge { size: total });
    }
    let mut sized = *header;
    sized.data_length = payload.len() as u16;
    let mut out = alloc::vec::Vec::with_capacity(total);
    out.resize(sized.len(), 0);
    let n = sized.encode_into(&mut out)?;
    out.truncate(n);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Split a received frame into its header and the payload its `data_length`
/// delimits.
///
/// The payload is cut to `data_length`, NOT to the end of the frame: an
/// Ethernet frame shorter than 60 bytes is padded by the NIC, and a reader
/// that took the whole tail would hand those pad bytes to the batch decoder.
/// pico applies the same cut (rx.c:59/70) and rejects a `data_length` that
/// overruns the frame, which is [`RawEthError::LengthOverrun`] here.
pub fn deframe(bytes: &[u8]) -> Result<(RawEthHeader, &[u8]), RawEthError> {
    let (header, n) = RawEthHeader::decode(bytes)?;
    let claimed = header.data_length as usize;
    let after = bytes.get(n..).unwrap_or_default();
    let available = after.len();
    let payload = after
        .get(..claimed)
        .ok_or(RawEthError::LengthOverrun { claimed, available })?;
    Ok((header, payload))
}

/// The source-MAC allow-list a raweth link filters received frames through.
///
/// EMPTY MEANS ADMIT EVERYTHING, matching pico (raweth_unix.c:97 — the filter
/// only runs when the array is non-empty). That is the opposite of the usual
/// allow-list default and is therefore stated here rather than left to be
/// discovered: an unconfigured link is promiscuous, not deaf.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MacWhitelist {
    entries: heapless::Vec<[u8; MAC_LEN], RETH_WHITELIST_CAPACITY>,
}

impl MacWhitelist {
    /// An empty list, which admits every source.
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit this source MAC; the MAC back, admitted by nothing, when the list already holds
    /// [`RETH_WHITELIST_CAPACITY`].
    pub fn allow(mut self, mac: [u8; MAC_LEN]) -> Result<Self, [u8; MAC_LEN]> {
        self.entries.push(mac)?;
        Ok(self)
    }

    /// `true` when the list is empty (admit all) or names `smac`.
    pub fn accepts(&self, smac: &[u8; MAC_LEN]) -> bool {
        self.entries.is_empty() || self.entries.iter().any(|e| e == smac)
    }

    /// How many sources are named. `0` is the admit-all state.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when nothing is named — the admit-all state.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// One entry of a raweth endpoint's `mapping`, as a link reads it: the frames of a message whose
/// key meets `keyexpr` go to `dmac`, tagged with `vlan` when there is one
/// (`_zp_raweth_mapping_entry_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawEthMapping<'a> {
    /// The key the entry serves; the default entry's is empty and serves none by name.
    pub keyexpr: &'a str,
    /// The destination MAC.
    pub dmac: [u8; MAC_LEN],
    /// The VLAN tag, which selects the 20-byte header; `None` for the 16-byte one.
    pub vlan: Option<u16>,
}

/// `_ZP_RAWETH_DEFAULT_MAPPING`, which a locator with no mapping of its own sends by.
const DEFAULT_MAPPING: RawEthMapping<'static> = RawEthMapping {
    keyexpr: "",
    dmac: DEFAULT_DMAC,
    vlan: None,
};

impl RawEthMapping<'_> {
    /// `_ZP_RAWETH_DEFAULT_MAPPING`: [`DEFAULT_DMAC`], no VLAN, no key.
    pub const fn default_entry() -> Self {
        DEFAULT_MAPPING
    }
}

/// A mapping entry as a [`RethLocator`] holds it: where its key sits in the locator's text, and
/// where its frames go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Route {
    key: (u16, u16),
    dmac: [u8; MAC_LEN],
    vlan: Option<u16>,
}

/// A parsed `reth/` endpoint, as zenoh-pico opens a raweth link from one
/// (`vendor/zenoh-pico/src/transport/raweth/link.c` @
/// `static z_result_t _z_f_link_open_raweth(_z_link_t *self) {`).
///
/// The interface name and the key of every mapping entry are substrings of the endpoint, so
/// together they fit one text of [`RETH_ENDPOINT_LEN`] bytes; holding them end to end there,
/// rather than each in a row as long as the longest it could be, keeps the value near the size of
/// a UDP group's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RethLocator {
    /// The SOURCE MAC this link sends from: the endpoint's address. pico takes the address
    /// as the link's own MAC, and the destinations from [`Self::mapping`].
    pub smac: [u8; MAC_LEN],
    /// `ethtype=` (hex), [`DEFAULT_ETHTYPE`] when absent or not an ethertype.
    pub ethtype: u16,
    /// `whitelist=` — the source MACs a frame is admitted from; empty (admit all) when absent
    /// or invalid.
    pub whitelist: MacWhitelist,
    /// The interface name, then each mapping entry's key.
    text: heapless::String<RETH_ENDPOINT_LEN>,
    /// Where the interface name ends in `text`.
    iface_end: u16,
    /// `mapping=`, never empty: an absent or invalid mapping is the one default entry.
    routes: heapless::Vec<Route, RETH_MAPPING_CAPACITY>,
}

impl RethLocator {
    /// `iface=` — the interface to bind, [`DEFAULT_INTERFACE`] when absent.
    pub fn interface(&self) -> &str {
        self.text
            .get(..usize::from(self.iface_end))
            .unwrap_or_default()
    }

    /// `mapping=` — where each message's frames go by its key, the first entry also being where
    /// a message with no key, or a key no entry meets, goes. Never empty: an absent or invalid
    /// mapping is the one [`RawEthMapping::default_entry`].
    pub fn mapping(&self) -> impl Iterator<Item = RawEthMapping<'_>> + '_ {
        self.routes.iter().map(|route| self.entry(route))
    }

    /// How many entries [`Self::mapping`] gives.
    pub fn mapping_len(&self) -> usize {
        self.routes.len()
    }

    /// The entry at `index` of [`Self::mapping`], the first when there is none there.
    pub fn mapping_at(&self, index: usize) -> RawEthMapping<'_> {
        self.routes
            .get(index)
            .or_else(|| self.routes.first())
            .map_or(DEFAULT_MAPPING, |route| self.entry(route))
    }

    /// The mapping entry a message on `keyexpr` is sent by: the first whose key meets it, or the
    /// first entry when none does or the message names no key
    /// (`vendor/zenoh-pico/src/transport/raweth/tx.c` @
    /// `static z_result_t _zp_raweth_set_socket(const _z_keyexpr_t *keyexpr, _z_raweth_socket_t *sock) {`).
    pub fn mapping_for(&self, keyexpr: Option<&str>) -> RawEthMapping<'_> {
        self.mapping_at(self.mapping_index_for(keyexpr))
    }

    /// The index in [`Self::mapping`] of the entry [`Self::mapping_for`] gives.
    pub fn mapping_index_for(&self, keyexpr: Option<&str>) -> usize {
        keyexpr
            .and_then(|key| {
                self.mapping().position(|entry| {
                    crate::keyexpr_match::keyexpr_intersects_text(key, entry.keyexpr)
                })
            })
            .unwrap_or(0)
    }

    /// `route` with its key read out of the text.
    fn entry(&self, route: &Route) -> RawEthMapping<'_> {
        let (start, end) = route.key;
        RawEthMapping {
            keyexpr: self
                .text
                .get(usize::from(start)..usize::from(end))
                .unwrap_or_default(),
            dmac: route.dmac,
            vlan: route.vlan,
        }
    }
}

/// The literal key of the network message `payload` begins with, as pico picks a raweth
/// destination by: the key of a put, a query or a reply, and none for any other message
/// (`vendor/zenoh-pico/src/transport/raweth/tx.c` @ `case _Z_N_PUSH:`).
///
/// Only the message's header, its request id and its key are read, so a payload cut short
/// after the key names it as the whole message does: the first fragment of a message that
/// does not fit one frame begins as the message does, and pico sends every fragment of a
/// message to the destination its key picked (`_zp_raweth_set_socket` runs once per message,
/// before the fragmenting loop, `vendor/zenoh-pico/src/transport/raweth/tx.c` @
/// `// The message does not fit in the current batch, let's fragment it`). `None` as well for
/// a key named by a declared id, which names no key text on the wire. The key is read in place.
pub fn leading_message_key(payload: &[u8]) -> Option<&str> {
    use sce_forge_runtime::codec::SceCursor;
    // The network message ids and the flag that says a key carries its suffix
    // (`vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/network.h` @ `#define _Z_MID_N_PUSH 0x1d`).
    const MID_PUSH: u8 = 0x1d;
    const MID_REQUEST: u8 = 0x1c;
    const MID_RESPONSE: u8 = 0x1b;
    const FLAG_N: u8 = 0x20;
    let (&header, rest) = payload.split_first()?;
    let mut cursor = SceCursor::new(rest);
    match header & 0x1f {
        MID_PUSH => {}
        MID_REQUEST | MID_RESPONSE => {
            cursor.read_vle_u64().ok()?;
        }
        _ => return None,
    }
    let scope = cursor.read_vle_u64().ok()?;
    if scope != 0 || header & FLAG_N == 0 {
        return None;
    }
    let len = usize::try_from(cursor.read_vle_u64().ok()?).ok()?;
    let suffix = cursor.peek_slice(len).ok()?;
    core::str::from_utf8(suffix).ok()
}

/// Parse a `reth/<smac>[#key=value;...]` endpoint as zenoh-pico does.
///
/// The address is the link's own MAC. The config, after the endpoint's `#`
/// (`ENDPOINT_CONFIG_SEPARATOR`), holds `iface`, `ethtype` (hex), `mapping` (a `,` list of
/// `keyexpr#mac#[vlan]`) and `whitelist` (a `,` list of MACs). pico is lenient past the scheme
/// and so is this: an address that is not a MAC is [`DEFAULT_SMAC`], an ethertype at or below
/// `0x600` on the wire is [`DEFAULT_ETHTYPE`], a mapping with one malformed entry is the default
/// one, a whitelist with one malformed MAC is none, and a key it does not know is ignored. Only
/// a locator that is not `reth/`, and one longer than [`RETH_ENDPOINT_LEN`], are refused.
pub fn parse_reth_locator(locator: &str) -> Result<RethLocator, RawEthError> {
    let rest = locator
        .strip_prefix(RAWETH_SCHEMA)
        .and_then(|r| r.strip_prefix('/'))
        .ok_or(RawEthError::NotRawEth)?;
    if locator.len() > RETH_ENDPOINT_LEN {
        return Err(RawEthError::TooLong);
    }
    let (locator_part, config) = match rest.split_once('#') {
        Some((l, c)) => (l, c),
        None => (rest, ""),
    };
    let address = locator_part
        .split_once('?')
        .map_or(locator_part, |(a, _)| a);
    let value_of = |wanted: &str| {
        config
            .split(';')
            .filter_map(|pair| pair.split_once('='))
            .find(|(key, _)| *key == wanted)
            .map(|(_, value)| value)
    };
    let smac = if valid_mac(address) {
        parse_mac(address).unwrap_or(DEFAULT_SMAC)
    } else {
        DEFAULT_SMAC
    };
    // The text holds the interface and the mapping keys, substrings of the endpoint, and each row
    // below what its length lets in, so a push that does not fit is the length check above
    // missing a case, refused by the same name.
    let mut text = heapless::String::new();
    text.push_str(value_of("iface").unwrap_or(DEFAULT_INTERFACE))
        .map_err(|()| RawEthError::TooLong)?;
    let iface_end = text_offset(&text)?;
    let ethtype = value_of("ethtype")
        .map(strtol_hex)
        .filter(|ethtype| (*ethtype as u16).to_be() > 0x600)
        .map_or(DEFAULT_ETHTYPE, |ethtype| ethtype as u16);
    let mut routes = heapless::Vec::new();
    if let Some(list) = value_of("mapping") {
        if !read_routes(list, &mut text, &mut routes)? {
            text.truncate(usize::from(iface_end));
            routes.clear();
        }
    }
    if routes.is_empty() {
        routes
            .push(Route {
                key: (iface_end, iface_end),
                dmac: DEFAULT_DMAC,
                vlan: None,
            })
            .map_err(|_| RawEthError::TooLong)?;
    }
    let whitelist = value_of("whitelist")
        .map(whitelist_entries)
        .transpose()?
        .flatten()
        .unwrap_or_default();
    Ok(RethLocator {
        smac,
        ethtype,
        whitelist,
        text,
        iface_end,
        routes,
    })
}

/// Where `text` ends, as a [`Route`] holds it.
fn text_offset(text: &str) -> Result<u16, RawEthError> {
    u16::try_from(text.len()).map_err(|_| RawEthError::TooLong)
}

/// Read a `mapping` list into `routes`, each key appended to `text`; `Ok(false)` for a list
/// with an entry pico refuses, which sends by the default entry.
fn read_routes(
    list: &str,
    text: &mut heapless::String<RETH_ENDPOINT_LEN>,
    routes: &mut heapless::Vec<Route, RETH_MAPPING_CAPACITY>,
) -> Result<bool, RawEthError> {
    for entry in list.split(',').filter(|entry| !entry.is_empty()) {
        let Some((keyexpr, dmac, vlan)) = mapping_entry(entry) else {
            return Ok(false);
        };
        let start = text_offset(text)?;
        text.push_str(keyexpr).map_err(|()| RawEthError::TooLong)?;
        let key = (start, text_offset(text)?);
        routes
            .push(Route { key, dmac, vlan })
            .map_err(|_| RawEthError::TooLong)?;
    }
    Ok(true)
}

/// The MACs of a `whitelist` list, or `Ok(None)` for a list with one malformed MAC, which names
/// none.
fn whitelist_entries(list: &str) -> Result<Option<MacWhitelist>, RawEthError> {
    let mut entries = heapless::Vec::new();
    for mac in list.split(',').filter(|entry| !entry.is_empty()) {
        let Some(mac) = Some(mac)
            .filter(|m| valid_mac(m))
            .and_then(|m| parse_mac(m).ok())
        else {
            return Ok(None);
        };
        entries.push(mac).map_err(|_| RawEthError::TooLong)?;
    }
    Ok(Some(MacWhitelist { entries }))
}

/// `strtol(value, NULL, 16)`: the leading hex digits after an optional `0x`, `0` when there
/// are none, as pico reads an ethertype and a VLAN tag.
fn strtol_hex(value: &str) -> i64 {
    let digits = value.trim_start_matches("0x").trim_start_matches("0X");
    let leading = digits
        .split(|c: char| !c.is_ascii_hexdigit())
        .next()
        .unwrap_or_default();
    i64::from_str_radix(leading, 16).unwrap_or(0)
}

/// `_z_valid_address_raweth`: six two-digit hex octets and five colons, seventeen characters.
fn valid_mac(s: &str) -> bool {
    s.len() == 17 && parse_mac(s).is_ok()
}

/// One `keyexpr#mac#[vlan]` mapping entry, or `None` for one pico refuses
/// (`vendor/zenoh-pico/src/transport/raweth/link.c` @ `static bool _z_valid_mapping_entry(char *entry) {`):
/// it needs both `#`s and a valid MAC between them. The tag is read when at least two
/// characters follow the second `#`, as pico's `p_start >= entry_end` test reads it.
fn mapping_entry(entry: &str) -> Option<(&str, [u8; MAC_LEN], Option<u16>)> {
    let (keyexpr, rest) = entry.split_once('#')?;
    let (mac, vlan) = rest.split_once('#')?;
    if !valid_mac(mac) {
        return None;
    }
    let tag = (vlan.len() >= 2).then(|| strtol_hex(vlan) as u16);
    Some((keyexpr, parse_mac(mac).ok()?, tag))
}

/// Parse `aa:bb:cc:dd:ee:ff`.
pub fn parse_mac(s: &str) -> Result<[u8; MAC_LEN], RawEthError> {
    let mut out = [0u8; MAC_LEN];
    let mut octets = s.split(':');
    for slot in &mut out {
        let octet = octets.next().ok_or(RawEthError::MalformedMac)?;
        if octet.len() != 2 {
            return Err(RawEthError::MalformedMac);
        }
        *slot = u8::from_str_radix(octet, 16).map_err(|_| RawEthError::MalformedMac)?;
    }
    if octets.next().is_some() {
        return Err(RawEthError::MalformedMac);
    }
    Ok(out)
}

/// The address a member whose frames come from `mac` is keyed by: the IPv6 link-local address
/// of the MAC's modified EUI-64 (RFC 4291 appendix A), which is unique per MAC, so a group keys a
/// raweth member by address as it keys a UDP one, on either engine.
pub fn member_address(mac: [u8; MAC_LEN]) -> core::net::SocketAddr {
    let ip = core::net::Ipv6Addr::new(
        0xfe80,
        0,
        0,
        0,
        u16::from_be_bytes([mac[0] ^ 0x02, mac[1]]),
        u16::from_be_bytes([mac[2], 0xff]),
        u16::from_be_bytes([0xfe, mac[3]]),
        u16::from_be_bytes([mac[4], mac[5]]),
    );
    core::net::SocketAddr::V6(core::net::SocketAddrV6::new(ip, 0, 0, 0))
}

/// The `reth/` locator of the member [`member_address`] keyed `addr` by: its MAC, read back out
/// of the modified EUI-64. `None` for an address no raweth member is keyed by.
#[cfg(feature = "alloc")]
pub fn member_locator(addr: &core::net::SocketAddr) -> Option<alloc::string::String> {
    let core::net::SocketAddr::V6(v6) = addr else {
        return None;
    };
    let o = v6.ip().octets();
    if o[..8] != [0xfe, 0x80, 0, 0, 0, 0, 0, 0] || o[11] != 0xff || o[12] != 0xfe {
        return None;
    }
    let mac = [o[8] ^ 0x02, o[9], o[10], o[13], o[14], o[15]];
    Some(alloc::format!("reth/{}", mac_text(&mac)))
}

/// `mac` as a locator writes it, `aa:bb:cc:dd:ee:ff`, the form [`parse_mac`] reads.
#[cfg(feature = "alloc")]
pub fn mac_text(mac: &[u8; MAC_LEN]) -> alloc::string::String {
    use core::fmt::Write as _;
    let mut text = alloc::string::String::with_capacity(MAC_TEXT_LEN);
    for (at, octet) in mac.iter().enumerate() {
        if at > 0 {
            text.push(':');
        }
        // A write into a `String` does not fail.
        let _ = write!(text, "{octet:02x}");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;

    const A: [u8; MAC_LEN] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    const B: [u8; MAC_LEN] = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16];

    /// A member's address reads back as its MAC's `reth/` locator, the MAC as `parse_mac` reads
    /// it, and an address no raweth member is keyed by reads as none. Turned red by an EUI-64
    /// that does not flip the universal bit, or a reading back that takes an address of another
    /// kind for a member.
    #[cfg(feature = "alloc")]
    #[test]
    fn a_member_address_reads_back_as_its_mac() {
        use alloc::string::ToString;
        let mac = [0x30, 0x03, 0x8c, 0xc8, 0x00, 0xa1];
        assert_eq!(
            member_address(mac).to_string(),
            "[fe80::3203:8cff:fec8:a1]:0"
        );
        assert_eq!(
            member_locator(&member_address(mac)).as_deref(),
            Some("reth/30:03:8c:c8:00:a1")
        );
        assert_eq!(parse_mac(&mac_text(&mac)), Ok(mac));
        let v4: core::net::SocketAddr = "127.0.0.1:7447".parse().unwrap();
        let other_v6: core::net::SocketAddr = "[fe80::1]:0".parse().unwrap();
        assert_eq!(member_locator(&v4), None);
        assert_eq!(member_locator(&other_v6), None);
    }

    #[test]
    fn the_wire_order_is_picos_not_a_tidied_one() {
        // pico memcpy's its struct, so ethtype rides the HOST order while
        // data_length goes through htons. On this (little-endian) host the
        // default 0x72e0 must therefore appear as `e0 72`, and a 3-byte
        // payload length as `00 03`. A "tidied" encoder that made both
        // big-endian would put `72 e0` here and no pico would decode it.
        let header = RawEthHeader::new(A, B, DEFAULT_ETHTYPE, 3);
        let mut out = [0u8; ETH_HEADER_LEN];
        assert_eq!(header.encode_into(&mut out).unwrap(), ETH_HEADER_LEN);
        assert_eq!(&out[0..6], &A);
        assert_eq!(&out[6..12], &B);
        assert_eq!(&out[12..14], &DEFAULT_ETHTYPE.to_ne_bytes());
        assert_eq!(&out[14..16], &[0x00, 0x03]);
        #[cfg(target_endian = "little")]
        {
            assert_eq!(&out[12..14], &[0xe0, 0x72]);
            // And the VLAN constant is spelled so it lands as the real 0x8100.
            assert_eq!(ETH_TYPE_VLAN.to_ne_bytes(), [0x81, 0x00]);
        }
    }

    #[test]
    fn a_vlan_header_is_four_bytes_wider_and_round_trips() {
        let header = RawEthHeader::new(A, B, DEFAULT_ETHTYPE, 0).with_vlan(0x0102);
        let mut out = [0u8; ETH_VLAN_HEADER_LEN];
        assert_eq!(header.encode_into(&mut out).unwrap(), ETH_VLAN_HEADER_LEN);
        assert_eq!(&out[12..14], &ETH_TYPE_VLAN.to_ne_bytes());
        assert_eq!(&out[14..16], &0x0102u16.to_ne_bytes());
        assert_eq!(&out[16..18], &DEFAULT_ETHTYPE.to_ne_bytes());
        let (back, n) = RawEthHeader::decode(&out).unwrap();
        assert_eq!(n, ETH_VLAN_HEADER_LEN);
        assert_eq!(back, header);
        // The width is DETECTED, not configured: the same bytes without the
        // VLAN marker decode four bytes narrower.
        let plain = RawEthHeader::new(A, B, DEFAULT_ETHTYPE, 0);
        let mut plain_out = [0u8; ETH_VLAN_HEADER_LEN];
        plain.encode_into(&mut plain_out).unwrap();
        assert_eq!(RawEthHeader::decode(&plain_out).unwrap().1, ETH_HEADER_LEN);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn deframe_cuts_to_data_length_not_to_the_end_of_the_frame() {
        // A 60-byte minimum-size Ethernet frame carrying 3 payload bytes: the
        // remaining 41 are NIC padding and must not reach the batch decoder.
        let frame_bytes = {
            let mut f = frame(&RawEthHeader::new(A, B, DEFAULT_ETHTYPE, 0), b"abc").unwrap();
            f.resize(60, 0);
            f
        };
        let (header, payload) = deframe(&frame_bytes).unwrap();
        assert_eq!(payload, b"abc");
        assert_eq!(header.data_length, 3);
        assert_eq!(header.smac, B);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn a_length_that_overruns_the_frame_is_rejected() {
        let mut f = frame(&RawEthHeader::new(A, B, DEFAULT_ETHTYPE, 0), b"abc").unwrap();
        // Claim 300 payload bytes in a 19-byte frame.
        f[14..16].copy_from_slice(&300u16.to_be_bytes());
        assert_eq!(
            deframe(&f),
            Err(RawEthError::LengthOverrun {
                claimed: 300,
                available: 3
            })
        );
    }

    #[test]
    fn a_truncated_frame_names_what_it_needed() {
        assert_eq!(
            RawEthHeader::decode(&[0u8; 8]),
            Err(RawEthError::Truncated { got: 8, need: 16 })
        );
        // A frame that carries the VLAN marker but stops inside the wider
        // header is truncated against the WIDER requirement, not the narrower.
        let mut short = [0u8; 18];
        short[12..14].copy_from_slice(&ETH_TYPE_VLAN.to_ne_bytes());
        assert_eq!(
            RawEthHeader::decode(&short),
            Err(RawEthError::Truncated { got: 18, need: 20 })
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn an_oversized_frame_is_refused_rather_than_truncated() {
        let payload = alloc::vec![0u8; MAX_ETH_FRAME_SIZE];
        assert_eq!(
            frame(&RawEthHeader::new(A, B, DEFAULT_ETHTYPE, 0), &payload),
            Err(RawEthError::FrameTooLarge {
                size: MAX_ETH_FRAME_SIZE + ETH_HEADER_LEN
            })
        );
        // One byte under the cap is fine, so the bound is the cap and not an
        // off-by-one somewhere below it.
        let ok = alloc::vec![0u8; MAX_ETH_FRAME_SIZE - ETH_HEADER_LEN];
        assert!(frame(&RawEthHeader::new(A, B, DEFAULT_ETHTYPE, 0), &ok).is_ok());
    }

    #[test]
    fn an_empty_whitelist_admits_everything_and_a_populated_one_does_not() {
        assert!(MacWhitelist::new().accepts(&A));
        let list = MacWhitelist::new()
            .allow(B)
            .expect("a whitelist has room for one MAC");
        assert!(list.accepts(&B));
        assert!(!list.accepts(&A));
        assert_eq!(list.len(), 1);
    }

    /// An endpoint names the link's OWN MAC, and everything it does not name, or names in a form
    /// pico refuses, is pico's default (`_z_f_link_open_raweth`).
    #[test]
    fn a_reth_endpoint_carries_the_defaults_it_does_not_name() {
        let l = parse_reth_locator("reth/01:02:03:04:05:06").unwrap();
        assert_eq!(l.smac, A, "the address is the source MAC");
        assert_eq!(l.interface(), DEFAULT_INTERFACE);
        assert_eq!(l.ethtype, DEFAULT_ETHTYPE);
        assert_eq!(
            l.mapping().collect::<Vec<_>>(),
            [RawEthMapping::default_entry()]
        );
        assert!(l.whitelist.is_empty());

        let l = parse_reth_locator(
            "reth/01:02:03:04:05:06#iface=eth0;ethtype=1234;\
             mapping=demo/a#11:12:13:14:15:16#,demo/b/**#01:02:03:04:05:06#0102;\
             whitelist=11:12:13:14:15:16",
        )
        .unwrap();
        assert_eq!(l.interface(), "eth0");
        assert_eq!(l.ethtype, 0x1234);
        assert_eq!(
            l.mapping().collect::<Vec<_>>(),
            [
                RawEthMapping {
                    keyexpr: "demo/a",
                    dmac: B,
                    vlan: None
                },
                RawEthMapping {
                    keyexpr: "demo/b/**",
                    dmac: A,
                    vlan: Some(0x0102)
                },
            ]
        );
        assert!(l.whitelist.accepts(&B) && !l.whitelist.accepts(&A));
        assert_eq!(l.mapping_for(Some("demo/b/x")).dmac, A);
        assert_eq!(
            l.mapping_for(Some("other")).dmac,
            B,
            "a key no entry meets goes by the first entry"
        );
        assert_eq!(l.mapping_for(None).dmac, B);

        assert_eq!(
            parse_reth_locator("tcp/1.2.3.4:7447"),
            Err(RawEthError::NotRawEth)
        );
        let lenient = parse_reth_locator(
            "reth/aa:bb#ethtype=0500;mapping=demo#11:12:13:14:15:16;whitelist=zz",
        )
        .unwrap();
        assert_eq!(lenient.smac, DEFAULT_SMAC, "an address that is not a MAC");
        assert_eq!(
            lenient.ethtype, DEFAULT_ETHTYPE,
            "an ethertype pico refuses"
        );
        assert_eq!(
            lenient.mapping().collect::<Vec<_>>(),
            [RawEthMapping::default_entry()],
            "an entry without its second `#`"
        );
        let rolled_back = parse_reth_locator(
            "reth/01:02:03:04:05:06#iface=eth0;mapping=demo/a#11:12:13:14:15:16#,bad",
        )
        .unwrap();
        assert_eq!(
            rolled_back.mapping().collect::<Vec<_>>(),
            [RawEthMapping::default_entry()],
            "a list with one entry pico refuses keeps none of the others"
        );
        assert_eq!(rolled_back.interface(), "eth0");
        assert!(
            lenient.whitelist.is_empty(),
            "a whitelist with a malformed MAC"
        );
    }

    /// An endpoint of `RETH_ENDPOINT_LEN` bytes is read, one byte longer is refused by that name,
    /// and a whitelist one past its rows is refused, never cut.
    #[test]
    fn an_endpoint_past_the_bound_is_refused_by_it() {
        let fill = |len: usize| {
            let mut text = String::from("reth/01:02:03:04:05:06#x=");
            while text.len() < len {
                text.push('e');
            }
            text
        };
        assert!(parse_reth_locator(&fill(RETH_ENDPOINT_LEN)).is_ok());
        assert_eq!(
            parse_reth_locator(&fill(RETH_ENDPOINT_LEN + 1)),
            Err(RawEthError::TooLong)
        );

        let mut full = MacWhitelist::new();
        for at in 0..RETH_WHITELIST_CAPACITY {
            full = full.allow([0, 0, 0, 0, 0, at as u8]).expect("a row");
        }
        assert_eq!(full.allow(A).err(), Some(A));
    }

    /// The rows are sized for the longest endpoint the bound lets in: an interface name, a
    /// mapping key, a list of the shortest mapping entries and a whitelist that each fill it are
    /// read whole.
    #[test]
    fn the_longest_rows_the_bound_lets_in_fit() {
        let filled = |head: &str, item: &str, sep: &str| {
            let mut text = String::from(head);
            text.push_str(item);
            while text.len() + sep.len() + item.len() <= RETH_ENDPOINT_LEN {
                text.push_str(sep);
                text.push_str(item);
            }
            text
        };
        let mut iface = String::from("reth/#iface=");
        while iface.len() < RETH_ENDPOINT_LEN {
            iface.push('e');
        }
        assert_eq!(
            parse_reth_locator(&iface).unwrap().interface().len(),
            RETH_ENDPOINT_LEN - "reth/#iface=".len()
        );

        let mut key = String::from("reth/#mapping=");
        while key.len() + SHORTEST_MAPPING_ENTRY < RETH_ENDPOINT_LEN {
            key.push('k');
        }
        key.push_str("#11:12:13:14:15:16#");
        let read = parse_reth_locator(&key).unwrap();
        assert_eq!(
            read.mapping_at(0).keyexpr.len(),
            RETH_ENDPOINT_LEN - "reth/#mapping=".len() - SHORTEST_MAPPING_ENTRY
        );
        assert_eq!(read.mapping_at(0).dmac, B);

        let entries = filled("reth/#mapping=", "#11:12:13:14:15:16#", ",");
        assert_eq!(
            parse_reth_locator(&entries).unwrap().mapping_len(),
            RETH_MAPPING_CAPACITY
        );

        let macs = filled("reth/#whitelist=", "11:12:13:14:15:16", ",");
        assert_eq!(
            parse_reth_locator(&macs).unwrap().whitelist.len(),
            RETH_WHITELIST_CAPACITY
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn frame_recomputes_the_length_a_caller_got_wrong() {
        // The header says 999; the payload is 3 bytes. The frame must carry 3.
        let lying = RawEthHeader::new(A, B, DEFAULT_ETHTYPE, 999);
        let f = frame(&lying, b"abc").unwrap();
        assert_eq!(&f[14..16], &[0x00, 0x03]);
        assert_eq!(deframe(&f).unwrap().1, b"abc");
    }

    /// The key a message names is read from its first bytes alone, as the first fragment of
    /// a message that does not fit one frame carries them: a put's key follows its header, a
    /// query's and a reply's follow the request id. A key named by a declared id, and a message
    /// that names no key, read as none.
    ///
    /// # Control
    ///
    /// The whole put, past its key, reads the same as the put cut right after its key.
    #[test]
    fn the_key_a_message_begins_with_is_read_from_its_head() {
        // Push, N set: scope 0, an 8-byte suffix, then whatever the body holds.
        let put = [
            0x3d, 0x00, 0x08, b'd', b'e', b'm', b'o', b'/', b'b', b'/', b'x', 0x01, 0x02, 0x03,
        ];
        assert_eq!(leading_message_key(&put), Some("demo/b/x"));
        assert_eq!(leading_message_key(&put[..11]), Some("demo/b/x"));
        // Cut inside the key: there is no key to read.
        assert_eq!(leading_message_key(&put[..6]), None);
        // Request and Response: the request id, then the key.
        let query = [0x3c, 0x05, 0x00, 0x03, b'a', b'/', b'b'];
        assert_eq!(leading_message_key(&query), Some("a/b"));
        let reply = [0x3b, 0x81, 0x01, 0x00, 0x01, b'z'];
        assert_eq!(leading_message_key(&reply), Some("z"));
        // A put by a declared id, with and without a suffix of its own.
        assert_eq!(leading_message_key(&[0x1d, 0x03, 0x09]), None);
        assert_eq!(leading_message_key(&[0x3d, 0x03, 0x01, b'x']), None);
        // A declaration names no key a destination is picked by.
        assert_eq!(leading_message_key(&[0x1e, 0x00]), None);
        assert_eq!(leading_message_key(&[]), None);
    }
}
