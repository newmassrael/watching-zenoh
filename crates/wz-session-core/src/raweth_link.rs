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
//! rather than hidden by [`tests::the_wire_order_is_picos_not_a_tidied_one`],
//! and is why this module documents it instead of normalising it away.

use alloc::string::String;
use alloc::vec::Vec;

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
    /// A MAC that is not six colon-separated hex octets.
    MalformedMac,
    /// A config value that is not the hex the key expects.
    MalformedConfig {
        /// The offending `key=value` pair.
        pair: String,
    },
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
            RawEthError::MalformedMac => write!(f, "MAC is not six colon-separated hex octets"),
            RawEthError::MalformedConfig { pair } => write!(f, "malformed raweth config {pair:?}"),
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
        if out.len() < need {
            return Err(RawEthError::BufferTooSmall {
                need,
                got: out.len(),
            });
        }
        out[0..MAC_LEN].copy_from_slice(&self.dmac);
        out[MAC_LEN..2 * MAC_LEN].copy_from_slice(&self.smac);
        let mut at = 2 * MAC_LEN;
        if let Some(tag) = self.vlan {
            // pico memcpy's the struct, so these two ride the host's order.
            out[at..at + 2].copy_from_slice(&ETH_TYPE_VLAN.to_ne_bytes());
            out[at + 2..at + 4].copy_from_slice(&tag.to_ne_bytes());
            at += 4;
        }
        out[at..at + 2].copy_from_slice(&self.ethtype.to_ne_bytes());
        // ...and this one alone goes through htons (tx.c:134/145).
        out[at + 2..at + 4].copy_from_slice(&self.data_length.to_be_bytes());
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
        if bytes.len() < ETH_HEADER_LEN {
            return Err(RawEthError::Truncated {
                got: bytes.len(),
                need: ETH_HEADER_LEN,
            });
        }
        let mut dmac = [0u8; MAC_LEN];
        let mut smac = [0u8; MAC_LEN];
        dmac.copy_from_slice(&bytes[0..MAC_LEN]);
        smac.copy_from_slice(&bytes[MAC_LEN..2 * MAC_LEN]);
        let at = 2 * MAC_LEN;
        let first = u16::from_ne_bytes([bytes[at], bytes[at + 1]]);
        if first == ETH_TYPE_VLAN {
            if bytes.len() < ETH_VLAN_HEADER_LEN {
                return Err(RawEthError::Truncated {
                    got: bytes.len(),
                    need: ETH_VLAN_HEADER_LEN,
                });
            }
            let tag = u16::from_ne_bytes([bytes[at + 2], bytes[at + 3]]);
            let ethtype = u16::from_ne_bytes([bytes[at + 4], bytes[at + 5]]);
            let data_length = u16::from_be_bytes([bytes[at + 6], bytes[at + 7]]);
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
            let data_length = u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]);
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

/// Build one raweth frame: the header (with `data_length` set from `payload`)
/// followed by the payload.
///
/// `header.data_length` is OVERWRITTEN from `payload.len()` rather than
/// trusted. A length field that can disagree with the bytes it describes is
/// the one field a caller must not be able to get wrong, and pico computes it
/// the same way (tx.c:134/145) rather than accepting it.
pub fn frame(header: &RawEthHeader, payload: &[u8]) -> Result<Vec<u8>, RawEthError> {
    let total = header.len() + payload.len();
    if total > MAX_ETH_FRAME_SIZE {
        return Err(RawEthError::FrameTooLarge { size: total });
    }
    let mut out = alloc::vec![0u8; total];
    let mut sized = *header;
    sized.data_length = payload.len() as u16;
    let n = sized.encode_into(&mut out)?;
    out[n..].copy_from_slice(payload);
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
    let available = bytes.len() - n;
    if claimed > available {
        return Err(RawEthError::LengthOverrun { claimed, available });
    }
    Ok((header, &bytes[n..n + claimed]))
}

/// The source-MAC allow-list a raweth link filters received frames through.
///
/// EMPTY MEANS ADMIT EVERYTHING, matching pico (raweth_unix.c:97 — the filter
/// only runs when the array is non-empty). That is the opposite of the usual
/// allow-list default and is therefore stated here rather than left to be
/// discovered: an unconfigured link is promiscuous, not deaf.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MacWhitelist {
    entries: Vec<[u8; MAC_LEN]>,
}

impl MacWhitelist {
    /// An empty list, which admits every source.
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit this source MAC.
    pub fn allow(mut self, mac: [u8; MAC_LEN]) -> Self {
        self.entries.push(mac);
        self
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

/// One entry of a raweth endpoint's `mapping`: the frames of a message whose key meets
/// `keyexpr` go to `dmac`, tagged with `vlan` when there is one (`_zp_raweth_mapping_entry_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEthMapping {
    /// The key the entry serves; the default entry's is empty and serves none by name.
    pub keyexpr: String,
    /// The destination MAC.
    pub dmac: [u8; MAC_LEN],
    /// The VLAN tag, which selects the 20-byte header; `None` for the 16-byte one.
    pub vlan: Option<u16>,
}

impl RawEthMapping {
    /// `_ZP_RAWETH_DEFAULT_MAPPING`: [`DEFAULT_DMAC`], no VLAN, no key.
    pub fn default_entry() -> Self {
        Self {
            keyexpr: String::new(),
            dmac: DEFAULT_DMAC,
            vlan: None,
        }
    }
}

/// A parsed `reth/` endpoint, as zenoh-pico opens a raweth link from one
/// (`vendor/zenoh-pico/src/transport/raweth/link.c` @
/// `static z_result_t _z_f_link_open_raweth(_z_link_t *self) {`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RethLocator {
    /// The SOURCE MAC this link sends from: the endpoint's address. pico takes the address
    /// as the link's own MAC, and the destinations from [`Self::mapping`].
    pub smac: [u8; MAC_LEN],
    /// `iface=` — the interface to bind, [`DEFAULT_INTERFACE`] when absent.
    pub interface: String,
    /// `ethtype=` (hex), [`DEFAULT_ETHTYPE`] when absent or not an ethertype.
    pub ethtype: u16,
    /// `mapping=` — where each message's frames go by its key, the first entry also being
    /// where a message with no key, or a key no entry meets, goes. Never empty: an absent or
    /// invalid mapping is the one [`RawEthMapping::default_entry`].
    pub mapping: Vec<RawEthMapping>,
    /// `whitelist=` — the source MACs a frame is admitted from; empty (admit all) when absent
    /// or invalid.
    pub whitelist: MacWhitelist,
}

impl RethLocator {
    /// The mapping entry a message on `keyexpr` is sent by: the first whose key meets it, or the
    /// first entry when none does or the message names no key
    /// (`vendor/zenoh-pico/src/transport/raweth/tx.c` @
    /// `static z_result_t _zp_raweth_set_socket(const _z_keyexpr_t *keyexpr, _z_raweth_socket_t *sock) {`).
    pub fn mapping_for(&self, keyexpr: Option<&str>) -> &RawEthMapping {
        keyexpr
            .and_then(|key| {
                self.mapping.iter().find(|entry| {
                    crate::keyexpr_match::keyexpr_intersects_text(key, &entry.keyexpr)
                })
            })
            .unwrap_or(&self.mapping[0])
    }
}

/// Parse a `reth/<smac>[#key=value;...]` endpoint as zenoh-pico does.
///
/// The address is the link's own MAC. The config, after the endpoint's `#`
/// (`ENDPOINT_CONFIG_SEPARATOR`), holds `iface`, `ethtype` (hex), `mapping` (a `,` list of
/// `keyexpr#mac#[vlan]`) and `whitelist` (a `,` list of MACs). pico is lenient past the scheme
/// and so is this: an address that is not a MAC is [`DEFAULT_SMAC`], an ethertype at or below
/// `0x600` on the wire is [`DEFAULT_ETHTYPE`], a mapping with one malformed entry is the default
/// one, a whitelist with one malformed MAC is none, and a key it does not know is ignored. Only
/// a locator that is not `reth/` is refused.
pub fn parse_reth_locator(locator: &str) -> Result<RethLocator, RawEthError> {
    let rest = locator
        .strip_prefix(RAWETH_SCHEMA)
        .and_then(|r| r.strip_prefix('/'))
        .ok_or(RawEthError::NotRawEth)?;
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
    let interface = value_of("iface").map_or_else(|| String::from(DEFAULT_INTERFACE), String::from);
    let ethtype = value_of("ethtype")
        .map(strtol_hex)
        .filter(|ethtype| (*ethtype as u16).to_be() > 0x600)
        .map_or(DEFAULT_ETHTYPE, |ethtype| ethtype as u16);
    let mapping = value_of("mapping")
        .and_then(|list| {
            list.split(',')
                .filter(|entry| !entry.is_empty())
                .map(mapping_entry)
                .collect::<Option<Vec<_>>>()
        })
        .filter(|entries| !entries.is_empty())
        .unwrap_or_else(|| alloc::vec![RawEthMapping::default_entry()]);
    let whitelist = value_of("whitelist")
        .and_then(|list| {
            list.split(',')
                .filter(|entry| !entry.is_empty())
                .map(|mac| {
                    Some(mac)
                        .filter(|m| valid_mac(m))
                        .and_then(|m| parse_mac(m).ok())
                })
                .collect::<Option<Vec<_>>>()
        })
        .map(|macs| {
            macs.into_iter()
                .fold(MacWhitelist::new(), MacWhitelist::allow)
        })
        .unwrap_or_default();
    Ok(RethLocator {
        smac,
        interface,
        ethtype,
        mapping,
        whitelist,
    })
}

/// `strtol(value, NULL, 16)`: the leading hex digits after an optional `0x`, `0` when there
/// are none, as pico reads an ethertype and a VLAN tag.
fn strtol_hex(value: &str) -> i64 {
    let digits = value.trim_start_matches("0x").trim_start_matches("0X");
    let end = digits
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(digits.len());
    i64::from_str_radix(&digits[..end], 16).unwrap_or(0)
}

/// `_z_valid_address_raweth`: six two-digit hex octets and five colons, seventeen characters.
fn valid_mac(s: &str) -> bool {
    s.len() == 17 && parse_mac(s).is_ok()
}

/// One `keyexpr#mac#[vlan]` mapping entry, or `None` for one pico refuses
/// (`vendor/zenoh-pico/src/transport/raweth/link.c` @ `static bool _z_valid_mapping_entry(char *entry) {`):
/// it needs both `#`s and a valid MAC between them. The tag is read when at least two
/// characters follow the second `#`, as pico's `p_start >= entry_end` test reads it.
fn mapping_entry(entry: &str) -> Option<RawEthMapping> {
    let (keyexpr, rest) = entry.split_once('#')?;
    let (mac, vlan) = rest.split_once('#')?;
    if !valid_mac(mac) {
        return None;
    }
    Some(RawEthMapping {
        keyexpr: String::from(keyexpr),
        dmac: parse_mac(mac).ok()?,
        vlan: (vlan.len() >= 2).then(|| strtol_hex(vlan) as u16),
    })
}

/// Parse `aa:bb:cc:dd:ee:ff`.
pub fn parse_mac(s: &str) -> Result<[u8; MAC_LEN], RawEthError> {
    let mut out = [0u8; MAC_LEN];
    let mut seen = 0usize;
    for (i, octet) in s.split(':').enumerate() {
        if i >= MAC_LEN || octet.len() != 2 {
            return Err(RawEthError::MalformedMac);
        }
        out[i] = u8::from_str_radix(octet, 16).map_err(|_| RawEthError::MalformedMac)?;
        seen += 1;
    }
    if seen != MAC_LEN {
        return Err(RawEthError::MalformedMac);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; MAC_LEN] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    const B: [u8; MAC_LEN] = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16];

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
        let list = MacWhitelist::new().allow(B);
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
        assert_eq!(l.interface, DEFAULT_INTERFACE);
        assert_eq!(l.ethtype, DEFAULT_ETHTYPE);
        assert_eq!(l.mapping, [RawEthMapping::default_entry()]);
        assert!(l.whitelist.is_empty());

        let l = parse_reth_locator(
            "reth/01:02:03:04:05:06#iface=eth0;ethtype=1234;\
             mapping=demo/a#11:12:13:14:15:16#,demo/b/**#01:02:03:04:05:06#0102;\
             whitelist=11:12:13:14:15:16",
        )
        .unwrap();
        assert_eq!(l.interface, "eth0");
        assert_eq!(l.ethtype, 0x1234);
        assert_eq!(
            l.mapping,
            [
                RawEthMapping {
                    keyexpr: String::from("demo/a"),
                    dmac: B,
                    vlan: None
                },
                RawEthMapping {
                    keyexpr: String::from("demo/b/**"),
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
            lenient.mapping,
            [RawEthMapping::default_entry()],
            "an entry without its second `#`"
        );
        assert!(
            lenient.whitelist.is_empty(),
            "a whitelist with a malformed MAC"
        );
    }

    #[test]
    fn frame_recomputes_the_length_a_caller_got_wrong() {
        // The header says 999; the payload is 3 bytes. The frame must carry 3.
        let lying = RawEthHeader::new(A, B, DEFAULT_ETHTYPE, 999);
        let f = frame(&lying, b"abc").unwrap();
        assert_eq!(&f[14..16], &[0x00, 0x03]);
        assert_eq!(deframe(&f).unwrap().1, b"abc");
    }
}
