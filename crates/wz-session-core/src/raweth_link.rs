// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

/// A parsed `reth/` locator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RethLocator {
    /// The destination MAC the address names.
    pub dmac: [u8; MAC_LEN],
    /// `iface=` — the interface to bind, [`DEFAULT_INTERFACE`] when absent.
    pub interface: String,
    /// `ethtype=` (hex), [`DEFAULT_ETHTYPE`] when absent.
    pub ethtype: u16,
    /// `vlan=` (hex) — the tag, absent for the 16-byte header form.
    pub vlan: Option<u16>,
}

/// Parse `reth/<dmac>[?k=v;k=v]`.
///
/// Recognised keys are `iface`, `ethtype` and `vlan`. pico's endpoint config
/// also carries `mapping` and `whitelist` list values (link.c:36-46); those are
/// NOT parsed here and their absence is deliberate — a keyexpr-to-MAC mapping
/// table is a routing policy, and inventing a half of one that silently
/// ignored the entries it could not represent would be worse than not having
/// it. [`MacWhitelist`] is configured through its own API instead.
pub fn parse_reth_locator(locator: &str) -> Result<RethLocator, RawEthError> {
    let rest = locator
        .strip_prefix(RAWETH_SCHEMA)
        .and_then(|r| r.strip_prefix('/'))
        .ok_or(RawEthError::NotRawEth)?;
    let (address, config) = match rest.split_once('?') {
        Some((a, c)) => (a, Some(c)),
        None => (rest, None),
    };
    let mut out = RethLocator {
        dmac: parse_mac(address)?,
        interface: String::from(DEFAULT_INTERFACE),
        ethtype: DEFAULT_ETHTYPE,
        vlan: None,
    };
    for pair in config.into_iter().flat_map(|c| c.split(';')) {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| RawEthError::MalformedConfig {
                pair: String::from(pair),
            })?;
        let hex = |v: &str| {
            u16::from_str_radix(v.trim_start_matches("0x"), 16).map_err(|_| {
                RawEthError::MalformedConfig {
                    pair: String::from(pair),
                }
            })
        };
        match key {
            "iface" => out.interface = String::from(value),
            // pico reads this key with `strtol(.., 16)` (link.c:107), so the
            // value is hex WITHOUT a `0x` — accepted either way here, since a
            // prefix that pico's strtol also tolerates cannot be a divergence.
            "ethtype" => out.ethtype = hex(value)?,
            "vlan" => out.vlan = Some(hex(value)?),
            _ => {
                return Err(RawEthError::MalformedConfig {
                    pair: String::from(pair),
                })
            }
        }
    }
    Ok(out)
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

    #[test]
    fn a_reth_locator_carries_the_defaults_it_does_not_name() {
        let l = parse_reth_locator("reth/aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(l.dmac, DEFAULT_DMAC);
        assert_eq!(l.interface, DEFAULT_INTERFACE);
        assert_eq!(l.ethtype, DEFAULT_ETHTYPE);
        assert_eq!(l.vlan, None);

        let l = parse_reth_locator("reth/01:02:03:04:05:06?iface=eth0;ethtype=1234;vlan=0x0102")
            .unwrap();
        assert_eq!(l.dmac, A);
        assert_eq!(l.interface, "eth0");
        assert_eq!(l.ethtype, 0x1234);
        assert_eq!(l.vlan, Some(0x0102));

        assert_eq!(
            parse_reth_locator("tcp/1.2.3.4:7447"),
            Err(RawEthError::NotRawEth)
        );
        assert_eq!(
            parse_reth_locator("reth/aa:bb"),
            Err(RawEthError::MalformedMac)
        );
        assert_eq!(
            parse_reth_locator("reth/01:02:03:04:05:06?mapping=x"),
            Err(RawEthError::MalformedConfig {
                pair: String::from("mapping=x")
            })
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
