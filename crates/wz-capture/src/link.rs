// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Link-layer and network-layer decapsulation: from a captured frame down to
//! a TCP segment plus the 4-tuple that identifies its flow.
//!
//! Only the link types a zenoh capture actually arrives on are handled, and
//! an unhandled one says so rather than guessing — a dissector that assumed
//! Ethernet on a `LINKTYPE_LINUX_SLL` capture would read the IP header 2
//! bytes off and report plausible garbage.

use alloc::vec::Vec;

/// `LINKTYPE_ETHERNET` — the ordinary case.
pub const LINKTYPE_ETHERNET: u32 = 1;
/// `LINKTYPE_RAW` — bare IP, no link header. What a tun interface yields.
pub const LINKTYPE_RAW: u32 = 101;
/// `LINKTYPE_LINUX_SLL` — the cooked header `tcpdump -i any` produces.
pub const LINKTYPE_LINUX_SLL: u32 = 113;
/// `LINKTYPE_IPV4` — bare IPv4.
pub const LINKTYPE_IPV4: u32 = 228;
/// `LINKTYPE_IPV6` — bare IPv6.
pub const LINKTYPE_IPV6: u32 = 229;
/// `LINKTYPE_LINUX_SLL2` — the 20-byte cooked v2 header.
pub const LINKTYPE_LINUX_SLL2: u32 = 276;
/// `LINKTYPE_NULL` — BSD loopback encapsulation (`/usr/include/pcap/dlt.h:62`).
/// What `tcpdump -i lo0` yields on macOS and on every BSD.
pub const LINKTYPE_NULL: u32 = 0;
/// `LINKTYPE_LOOP` — OpenBSD's loopback encapsulation
/// (`/usr/include/pcap/dlt.h:279-289`). Identical to [`LINKTYPE_NULL`] except
/// that its address-family word is specified in network byte order.
pub const LINKTYPE_LOOP: u32 = 108;
/// `LINKTYPE_VSOCK` — AF_VSOCK, captured through the kernel's `vsockmon`
/// device (`DLT_VSOCK`, `/usr/include/pcap/dlt.h:1448`).
///
/// R311y603. Absent from this table, a `vsock/...` zenoh link — the VM-to-VM
/// shape an AP deployment actually takes — came back as
/// [`SkipReason::UnsupportedLinkType`]`(271)`. That was a NAMED skip and so
/// never silent, but it was an under-promise: both the DLT and `vsockmon.ko`
/// exist, so nothing was blocking it.
pub const LINKTYPE_VSOCK: u32 = 271;

/// Every pcap link type this build reads, with its name — the answer to
/// "will this tool open my capture" BEFORE it is run.
///
/// # Why this exists
///
/// R311y895, open-debt item 385. The set was discoverable only by reading
/// `strip_link`'s match arms, and nothing counted them: a test in
/// `wz-analyze` still said "decap dispatches SIX link types" two rounds after
/// it became eight. Both surfaces that could have answered a reader —
/// `wz-analyze --help` and the report's own skip census — answered only AFTER
/// a run, and the run's answer for an unread capture is `messages decoded: 0`,
/// which R311y893 measured as reading like "no traffic". A tool that cannot
/// say what it reads makes its own silence ambiguous.
///
/// # Why a list beside the dispatch rather than a dispatch through the list
///
/// Each arm strips a DIFFERENT header — a fixed offset, a walked VLAN chain,
/// a version nibble, an address-family word — so there is no one function the
/// table could hold. What binds the two is a TEST rather than a type: it
/// sweeps every link type up to 1000 through [`decapsulate`] and requires the
/// set that is not [`SkipReason::UnsupportedLinkType`] to equal this list
/// exactly, in BOTH directions. A new arm with no row here reds, and a row
/// with no arm reds.
///
/// NOT included, because neither is a link type this reader decapsulates:
/// `--serial <linktype>` DECLARES an arbitrary one as raw serial bytes, and
/// raw-Ethernet zenoh rides [`LINKTYPE_ETHERNET`] rather than a code of its
/// own.
pub const READABLE_LINK_TYPES: &[(u32, &str)] = &[
    (LINKTYPE_NULL, "NULL"),
    (LINKTYPE_ETHERNET, "ETHERNET"),
    (LINKTYPE_RAW, "RAW"),
    (LINKTYPE_LOOP, "LOOP"),
    (LINKTYPE_LINUX_SLL, "LINUX_SLL"),
    (LINKTYPE_IPV4, "IPV4"),
    (LINKTYPE_IPV6, "IPV6"),
    (LINKTYPE_VSOCK, "VSOCK"),
    (LINKTYPE_LINUX_SLL2, "LINUX_SLL2"),
];

/// [`READABLE_LINK_TYPES`] as one line of `<code> <NAME>`, ascending by code.
///
/// One renderer so the help text and the test that pins it cannot disagree
/// about spacing — the failure `analysis_surface_parity` exists to prevent one
/// level up.
pub fn readable_link_types_line() -> alloc::string::String {
    use core::fmt::Write as _;
    let mut codes: Vec<(u32, &str)> = READABLE_LINK_TYPES.to_vec();
    codes.sort_unstable_by_key(|(c, _)| *c);
    let mut out = alloc::string::String::new();
    for (i, (code, name)) in codes.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{code} {name}");
    }
    out
}

/// Bytes of `struct af_vsockmon_hdr` (`/usr/include/linux/vsockmon.h`), read
/// off that header rather than remembered: `__le64 src_cid` + `__le64 dst_cid`
/// + `__le32 src_port` + `__le32 dst_port` + `__le16 op` + `__le16 transport`
/// + `__le16 len` + 2 reserved.
const VSOCKMON_HDR_LEN: usize = 32;

/// `AF_VSOCK_OP_PAYLOAD` — the only op that carries data. The header's own
/// comment is explicit: "If af_vsockmon_hdr->op is AF_VSOCK_OP_PAYLOAD then
/// the payload follows the transport header. Other ops do not have a payload."
const AF_VSOCK_OP_PAYLOAD: u16 = 4;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;

/// Transparent Ethernet Bridging — GRE's payload when the tunnel carries a
/// whole Ethernet FRAME rather than an IP packet (`GRETAP`, and what every
/// cloud overlay builds an L2 segment out of).
///
/// It is the one ethertype whose body does not continue the IP walk, which is
/// why it needed the link layer to become reachable from inside the walk
/// rather than only from the front door.
const ETHERTYPE_TEB: u16 = 0x6558;

const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;

/// R311y862 — the two encapsulations this reader WALKS: an IP packet whose
/// payload is another IP packet.
///
/// Both numbers mean "the body is a datagram", and which one says only which
/// family the inner header belongs to. They are walked rather than reported
/// because the walk is the existing one — no new parser, only a second turn
/// around the loop.
const IP_PROTO_IPV4_IN_IP: u8 = 4;
const IP_PROTO_IPV6_IN_IP: u8 = 41;

/// R311y864 — GRE (RFC 2784, with RFC 2890's Key and Sequence Number).
///
/// The third carrier this reader walks, and the first whose header is not
/// simply another IP header. R311y862 named it and R311y863's carry called it
/// the largest unread class left, on a measured ground rather than a guess: a
/// capture taken off a VPN concentrator carries GRE, and until this it produced
/// `tunnel IP protocol(s) not opened: 47` — honest, and useless to anyone
/// holding such a capture.
const IP_PROTO_GRE: u8 = 47;

/// R311y862 — how many nested CARRIERS this reader will walk.
///
/// A BOUND and not a recursion, for the reason every other limit in this crate
/// exists: the depth is read out of the packet, so a crafted chain of headers
/// would otherwise decide how much work this function does. Four is far past
/// any real deployment — one tunnel is ordinary, two is a tunnel inside a VPN,
/// and nothing this workspace has seen goes further.
///
/// Round 2013 (item 256) — a chain beyond it is
/// [`SkipReason::EncapsulationTooDeep`] and NOT `Encapsulation`. This doc used
/// to end "which is the same answer as for GRE and is honest for the same
/// reason", and it was neither: GRE is a tunnel this build opens, so answering
/// a too-deep chain with its number told a reader to write a parser that
/// already exists.
///
/// # The unit is a CARRIER, and that is a choice — Round 2015 (item 262)
///
/// It was made when every carrier was an IP header and left unrecorded when
/// GRE arrived, which is what item 262 named. Recorded now, with what it costs.
///
/// A carrier is the right unit for what this bound protects: the walk's own
/// RECURSION, which advances once per carrier whatever that carrier's header
/// weighs. Bounding header BYTES instead would bound a different thing, and it
/// would make the limit depend on GRE's optional fields — Key, Sequence,
/// Checksum — which the sender chooses. A bound a sender can move is not one.
///
/// The price is that four carriers is not one amount of parsing.
/// `the_depth_bound_counts_carriers_whatever_a_carrier_costs` measures it:
/// four IPIP carriers are 80 header bytes, four GRE 96, four GRETAP 152,
/// because a GRETAP carrier carries a whole Ethernet header the count never
/// sees. The spread is under a factor of two and every arm is bounded, which is
/// why the unit stands — but it stands as a decision with a number on it rather
/// than as the way it happened to be written.
///
/// ⚠ It is also NOT the only carrier bound. `Dissection::push_fragment` holds a
/// separate one, on a different subject — how many times a completed datagram
/// turns out to be another fragment — and open-debt item 257 is where the two
/// are told apart.
pub(crate) const MAX_ENCAPSULATION_DEPTH: usize = 4;

/// R311y862 — IP protocol numbers whose body is ANOTHER packet.
///
/// This list is what makes the furniture class defensible instead of merely
/// asserted. [`SkipCensus::not_this_protocol`](crate::SkipCensus::not_this_protocol)
/// calls a non-TCP, non-UDP protocol incapable of carrying zenoh; that argument
/// holds for ICMP and IGMP, which terminate at the host and carry no session,
/// and it does NOT hold for an encapsulation, which is transparent to whatever
/// is inside it. Measured before it was believed: a capture of one IPIP packet
/// carrying a complete zenoh session reported `capture: complete` with zero
/// flows read.
///
/// The WALKED numbers are here as well, so that a REASSEMBLED datagram — which
/// reaches [`transport_from_ip`] without passing the walk in [`decapsulate`] —
/// is judged rather than filed as furniture.
///
/// R311y863 amended what that judgement is. This paragraph used to end "the
/// bytes are named as absent, and reading them would need the walk to run over
/// reassembled payloads too", which described a state of affairs that stopped
/// being true the moment the walk moved: `transport_from_ip` runs it, so a
/// reassembled carrier is READ. The sentence is corrected rather than deleted
/// because a comment stating a settled half-answer is what stops the next
/// reader looking (R311y838).
fn is_encapsulation(proto: u8) -> bool {
    matches!(
        proto,
        IP_PROTO_IPV4_IN_IP
            | IP_PROTO_IPV6_IN_IP
            | IP_PROTO_GRE
            | 50   // ESP -- the remainder is encrypted, as at the v6 chain
            | 51   // AH
            | 94   // IPIP, the obsolete duplicate of 4
            | 97   // ETHERIP
            | 115  // L2TP
            | 137  // MPLS-in-IP
            | 143  // Ethernet (RFC 8986)
            // Round 2010 (open-debt item 250) — THREE THIS LIST HAD MISSED,
            // found by asking its own question of IANA's assignments rather
            // than by meeting one in a capture. Each carries a body that could
            // be a session, so filing it as furniture is the exact defect
            // R311y862 measured on protocol 4.
            | 55   // MOBILE -- RFC 2004 minimal encapsulation: the body is an
                   // IP datagram behind a short forwarding header
            | 98   // ENCAP -- RFC 1241, an encapsulation by its own name
            | 108 // IPComp -- RFC 3173: the body is a COMPRESSED IP datagram.
                  // This build cannot decompress it, which is what makes it a
                  // tunnel not opened rather than a protocol that terminates
    )
}

/// Round 2010 (item 250) — the encapsulation set, as a SET a test can read.
///
/// [`is_encapsulation`] is a `matches!`, which a caller can ask about one
/// number and cannot enumerate. The gate that keeps this list from shrinking
/// silently needs the whole set, and deriving it by sweeping 0..=255 through
/// the predicate is what makes the two agree by construction rather than by a
/// second list somebody keeps in step.
///
/// ⚠ WHAT THIS DOES NOT CLOSE, and item 250 says it plainly: nothing here is
/// checked against IANA's assignments. A number IANA calls an encapsulation
/// and this list omits is still furniture by omission, and the only honest
/// gate for that is a table this tree does not have.
#[cfg(test)]
fn encapsulation_set() -> Vec<u8> {
    (0u8..=u8::MAX).filter(|p| is_encapsulation(*p)).collect()
}

/// One end of a flow: address bytes plus a port.
///
/// The address is a fixed 16-byte buffer with a length, not an enum: the
/// flow key only ever compares and orders it, and a `[u8; 16]` keeps the key
/// `Copy` and hashable without an address-family split rippling into every
/// consumer. The LENGTH is also what distinguishes the families — 4 for IPv4,
/// 16 for IPv6, and (R311y603) 8 for an AF_VSOCK context id, so a vsock flow
/// can never collide with an IP one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint {
    addr: [u8; 16],
    addr_len: u8,
    /// TCP / UDP port, host order — or an AF_VSOCK port, which is 32 bits
    /// wide (`struct af_vsockmon_hdr.src_port`, `linux/vsockmon.h`). The field
    /// is `u32` for that reason: truncating a vsock port to 16 bits would
    /// silently alias two distinct flows onto one key.
    pub port: u32,
}

impl Endpoint {
    /// The address bytes, network order, 4 or 16 long.
    pub fn addr(&self) -> &[u8] {
        &self.addr[..self.addr_len as usize]
    }

    /// `true` for an IPv4 endpoint.
    pub fn is_ipv4(&self) -> bool {
        self.addr_len == 4
    }

    /// R311y607 — is this an IP MULTICAST address?
    ///
    /// The one question that tells a passive observer which zenoh message
    /// NAMESPACE a datagram belongs to. `S_MID_SCOUT` and `T_MID_INIT` are both
    /// `0x01`, so the byte cannot settle it and the link must: a multicast
    /// transport has no handshake at all — pico's own multicast receive path
    /// drops INIT and OPEN with "multicast transports are not expected to
    /// handle INIT messages" (`vendor/zenoh-pico/src/transport/multicast/rx.c`
    /// :493-504) — so `0x01` toward a multicast group is a SCOUT, and toward a
    /// unicast peer it is an Init.
    ///
    /// IPv4 `224.0.0.0/4` (RFC 1112 class D) and IPv6 `ff00::/8` (RFC 4291
    /// §2.7). A vsock endpoint is neither: its 8-byte address is a context id,
    /// and AF_VSOCK has no multicast, so it answers `false` by LENGTH rather
    /// than by reading a cid as if it were an address.
    pub fn is_ip_multicast(&self) -> bool {
        match self.addr_len {
            4 => self.addr[0] & 0xF0 == 0xE0,
            16 => self.addr[0] == 0xFF,
            _ => false,
        }
    }

    /// The context id of an AF_VSOCK endpoint, or `None` for an IP one.
    ///
    /// Distinguished by the address LENGTH rather than by a flag: a vsock
    /// endpoint is the only 8-byte one, so a consumer that asks this question
    /// gets an answer the key itself already encodes.
    pub fn vsock_cid(&self) -> Option<u64> {
        if self.addr_len != 8 {
            return None;
        }
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&self.addr[..8]);
        Some(u64::from_le_bytes(raw))
    }

    /// `pub(crate)` and not `pub`: R311y606 needs it in [`crate::frag`]'s
    /// tests to build a fragment key, and a crate-private constructor is the
    /// smallest thing that allows. Still not public — an endpoint outside this
    /// crate should come from a decapsulated packet, not be asserted into
    /// existence.
    pub(crate) fn new(addr_bytes: &[u8], port: u32) -> Self {
        let mut addr = [0u8; 16];
        addr[..addr_bytes.len()].copy_from_slice(addr_bytes);
        Self {
            addr,
            addr_len: addr_bytes.len() as u8,
            port,
        }
    }
}

/// A TCP connection, identified without regard to direction.
///
/// The two endpoints are stored SORTED, so both directions of one connection
/// produce the same key and a consumer never has to canonicalise. Which
/// direction a given segment travelled is [`Segment::from_low`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    /// The lesser of the two endpoints, by `(addr, port)` order.
    pub low: Endpoint,
    /// The greater.
    pub high: Endpoint,
}

impl FlowKey {
    /// R311y720 (§D M3) — the key a SERIAL line stands under.
    ///
    /// A serial link has NO addressing: two wires, no ports, no MACs. So the
    /// key is empty in every field, and that is the whole design -- there is
    /// exactly ONE serial line per capture (it is point to point), so the key
    /// has nothing to distinguish and nothing to carry.
    ///
    /// R311y722 — it USED to carry the interface count in the `port`, on the
    /// argument that this was "a real fact in the only field that can hold
    /// one". That was the wrong argument: the field is a PORT, a reader
    /// matching a row against their deployment reads it as one, and a count
    /// sitting there is a fabricated fact in the column that must not hold any.
    /// The interface count belongs to the census, where it already is
    /// ([`crate::serial::SerialCensus::interfaces`]), and putting it here as
    /// well was a second home for one number.
    pub fn serial_line() -> Self {
        let end = Endpoint {
            addr: [0; 16],
            addr_len: 0,
            port: 0,
        };
        Self {
            low: end,
            high: end,
        }
    }

    fn new(a: Endpoint, b: Endpoint) -> (Self, bool) {
        if a <= b {
            (Self { low: a, high: b }, true)
        } else {
            (Self { low: b, high: a }, false)
        }
    }
}

/// What a packet's checksums said, REPORTED rather than acted on.
///
/// R311y597 — this build verified nothing at all before, so a corrupted packet
/// was read as good and its garbage entered the byte stream as though the peer
/// had sent it.
///
/// ## Why it reports instead of dropping, which is not timidity
///
/// A NIC computes TX checksums in hardware, so a capture taken on the SENDING
/// host routinely sees zeroed or stale fields — the packet is fine and the
/// checksum has not been filled in yet. Dropping on a bad checksum would make
/// a loopback or same-host capture disappear almost entirely, which is exactly
/// the case a developer captures most. Wireshark defaults its own validation
/// off for this reason. The verdict is therefore evidence a reader can weigh,
/// not a gate this crate applies on their behalf.
///
/// This crate's own fixtures write zero checksums, and they keep working
/// precisely because nothing acts on the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checksums {
    /// The IPv4 header checksum. `None` for IPv6, which has none at all —
    /// the field was removed on the grounds that the layers below and above
    /// already cover it.
    pub ip: Option<bool>,
    /// The TCP or UDP checksum. `None` when a UDP datagram over IPv4 carried
    /// zero, which is the sender explicitly DECLINING to compute one
    /// (RFC 768) rather than getting it wrong. Over IPv6 zero is illegal and
    /// reports `Some(false)`.
    pub transport: Option<bool>,
    /// Round 2014 (item 261) — the CARRIER's own checksum, folded across every
    /// GRE header in the chain that carried one.
    ///
    /// `None` is the ordinary answer and means no carrier in this packet's
    /// chain declared a checksum: GRE's is optional (RFC 2784 §2.5, the `C`
    /// bit), and an untunnelled packet has no carrier at all. `Some` means at
    /// least one was present, and `false` that one of them did not verify.
    ///
    /// # Why this field exists
    ///
    /// `strip_gre` read the `C` bit only to SIZE the header and stepped over
    /// the two bytes it announced. Every other integrity verdict this crate
    /// reaches is reported — that is what this struct is for — so the carrier's
    /// was the one judgement that was neither made nor reported as absent. A
    /// GRE header with a corrupt checksum and one with a correct checksum
    /// produced byte-identical pages, which is the state item 261 named and
    /// this round measured before changing anything.
    ///
    /// Folded across the chain rather than read off the outermost carrier, for
    /// the reason the walk folds `ip` the same way: reporting only the outer
    /// would let a tunnel whose inner header is corrupt read as verified.
    pub tunnel: Option<bool>,
}

impl Checksums {
    /// `true` when a checksum was present and did not verify — the only state
    /// that is evidence of corruption rather than of absence.
    pub fn any_invalid(&self) -> bool {
        self.ip == Some(false) || self.transport == Some(false) || self.tunnel == Some(false)
    }
}

/// One TCP segment lifted out of a captured packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Which connection it belongs to.
    pub flow: FlowKey,
    /// `true` when it travelled from [`FlowKey::low`] toward `high`.
    pub from_low: bool,
    /// Sequence number of its first payload byte.
    pub seq: u32,
    /// SYN flag — carries the initial sequence number, which is what lets a
    /// reassembler know where a stream BEGAN rather than merely where the
    /// capture did.
    pub syn: bool,
    /// FIN flag.
    pub fin: bool,
    /// RST flag.
    pub rst: bool,
    /// Payload bytes, empty for a pure ACK.
    pub payload: Vec<u8>,
    /// Index of the packet this came out of, carried through so a decoded
    /// message can be reported against the packet that carried it.
    pub packet_index: usize,
    /// What this packet's checksums said. Reported, never acted on.
    pub checksums: Checksums,
    /// Item 252 — the carriers this segment arrived inside, outermost first.
    /// Empty when it arrived on the wire it was addressed on. Reported, never
    /// acted on: the flow is keyed by the INNER header and stays so.
    pub tunnel: Tunnel,
}

/// Why a captured packet yielded no TCP segment.
///
/// Every variant is a REASON, not a bare `None`. A dissector that silently
/// drops packets cannot tell its user whether a missing message was never
/// captured, was IP-fragmented, or was simply not TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The capture's link type is not decapsulated by this build.
    UnsupportedLinkType(u32),
    /// The packet was shorter than the headers it declared.
    Truncated,
    /// Not IP (ARP, LLDP, ...), or not a protocol carried onward.
    NotIp,
    /// IP, but neither TCP nor UDP — the two transports zenoh links use.
    ///
    /// R311y584 (A3) — was `NotTcp`, and UDP fell into it. That named skip
    /// was honest about the byte stream having a hole and silent about WHICH
    /// hole: scouting, multicast Join, and the whole UDP unicast link are all
    /// carried there, so a capture of a multicast deployment produced a
    /// dissection with no messages and no error.
    NotTransport(u8),
    /// An IPv4 fragment other than the first.
    ///
    /// R311y606 — RETAINED but no longer produced by [`decapsulate`], which now
    /// reports every piece as [`Transport::IpFragment`] and leaves the
    /// reassembly decision to the consumer. A consumer that does not reassemble
    /// records this, so the vocabulary a reader chases a hole with is unchanged.
    Ipv4Fragment,
    /// R311y606 — a piece of a fragmented datagram that is now IN the
    /// reassembly table, waiting for the rest of it.
    ///
    /// Distinct from [`Self::Ipv4Fragment`] on purpose: those bytes were LOST,
    /// these are held. A packet recorded here yielded no frames of its own and
    /// belongs in the skipped list for that reason, but the datagram it belongs
    /// to may still arrive — and when it does, the packet that COMPLETES it is
    /// the one that produces the frames.
    IpFragmentPending,
    /// An IPv6 packet whose extension-header chain could not be walked to a
    /// transport, carrying the header that stopped it.
    ///
    /// R311y597 — the payload is the extension header's own number, and it is
    /// now only ever one of `is_ipv6_extension_header`'s set. It previously
    /// carried any next-header that was not TCP, so a reader saw UDP (17) and
    /// ICMPv6 (58) reported as unwalked chains.
    ///
    /// R311y603 — the chain IS walked now, so this narrowed from "any chain" to
    /// the three cases that genuinely cannot be walked: ESP (50), whose
    /// remainder is encrypted, the two experimental numbers (253 / 254) that
    /// carry no length this reader may assume, and a chain longer than
    /// `IPV6_MAX_EXT_HEADERS`.
    Ipv6ExtensionChain(u8),
    /// An IPv6 fragment other than the first, which has no transport header to
    /// find. The v6 twin of [`Self::Ipv4Fragment`], and named separately
    /// because a reader chasing a hole should not have to guess which address
    /// family produced it.
    Ipv6Fragment,
    /// R311y603 — a `vsockmon` record whose op is not `AF_VSOCK_OP_PAYLOAD`,
    /// carrying the op itself.
    ///
    /// CONNECT / DISCONNECT / CONTROL records are the credit-and-lifecycle
    /// traffic of the transport, and by the kernel header's own statement they
    /// have no payload at all. Skipping them is correct; skipping them ANONYMOUS
    /// would leave a reader unable to tell a quiet link from a link whose
    /// records this build could not read.
    VsockNonPayload(u16),
    /// R311y862 — an IP packet whose body is another packet this reader did not
    /// open, carrying the protocol number that stopped it.
    ///
    /// Split out of [`Self::NotTransport`], which counts protocols that
    /// TERMINATE at the host — ICMP, IGMP — and is furniture for that reason.
    /// An encapsulation terminates nothing: whatever is inside it could be a
    /// zenoh session, and filing it as furniture is how a capture of one IPIP
    /// packet carrying a complete session reported itself complete with zero
    /// flows read. The v4 sibling of [`Self::Ipv6ExtensionChain`].
    ///
    /// Round 2013 (item 256) — this now means ONE thing: a protocol this build
    /// has no parser for (ESP, AH, L2TP, MPLS-in-IP). The doc used to end "and
    /// a chain longer than `MAX_ENCAPSULATION_DEPTH`", and that second cause
    /// has moved to [`Self::EncapsulationTooDeep`]. See there for why.
    Encapsulation(u8),
    /// Round 2013 (item 256) — a chain of carriers LONGER THAN THIS READER
    /// WALKS, carrying the protocol of the carrier it stopped at.
    ///
    /// # Why this is not `Encapsulation`
    ///
    /// It was, and the page said `tunnel IP protocol(s) not opened: 4` for a
    /// five-deep IPIP chain. Protocol 4 IS opened by this build — R311y862
    /// opened it — so that line told a reader to write a parser that already
    /// exists. It is the exact false sentence R311y863 measured and item 251
    /// removed, arriving by a second route: two different facts sharing one
    /// variant and one number, which is the shape [`Self::GrePayload`] was
    /// split out to avoid one carrier earlier.
    ///
    /// The two send a reader to DIFFERENT WORK, which is the test this crate
    /// applies to every skip reason. `Encapsulation` says "build a parser".
    /// This says "the parser exists and the chain was deeper than the bound" —
    /// and the remedy is to raise the bound, or to accept it, both of which are
    /// decisions rather than code. A reader cannot make either while the page
    /// is naming a protocol as unsupported.
    ///
    /// Bytes absent, not furniture, exactly as for the variant it left.
    EncapsulationTooDeep(u8),
    /// R311y864 — a GRE header this reader PARSED whose payload ethertype it
    /// does not walk, carrying that ethertype.
    ///
    /// Distinct from [`Self::Encapsulation`]`(47)` and the distinction is the
    /// point. That variant means the tunnel itself could not be opened, and
    /// tells a reader to add GRE. This one means GRE was opened and what came
    /// out is something else. Reporting 47 for it would send a reader to write
    /// a parser that already exists, which is the misdirection R311y863
    /// measured on protocol 4 and this variant exists to avoid repeating one
    /// carrier later.
    ///
    /// Item 260 CORRECTS this paragraph rather than deleting the correction.
    /// It used to name Transparent Ethernet Bridging (0x6558) "above all" as
    /// the member of this class, and that is no longer true: TEB is WALKED —
    /// `step_gre` hands its frame to `enter_link`, the same door the
    /// capture's own frames come through. What reaches here now is the rest —
    /// MPLS, PPP, an ethertype nobody in this workspace has yet met. The
    /// sentence is corrected in place because a comment stating a settled
    /// half-answer is what stops the next reader looking (R311y838), and the
    /// number on the page is still what names the next thing to build.
    ///
    /// Bytes absent, not furniture: whatever GRE was carrying could have been a
    /// zenoh session, exactly as for the tunnel around it.
    GrePayload(u16),
}

/// One UDP datagram lifted out of a captured packet.
///
/// R311y584 (A3) — deliberately NOT a [`Segment`] with the TCP fields left
/// blank. A datagram has no sequence number and needs no reassembly: zenoh
/// puts exactly ONE wire message in each one and relies on the datagram
/// boundary instead of a length prefix
/// (`wz-runtime-tokio/src/udp_pipeline.rs:34-36`). Giving it a `seq` field to
/// ignore would invite a reader to treat the two the same, and they are not
/// the same — the framing differs, which is the whole reason UDP could not
/// simply be routed into the existing TCP path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    /// The two endpoints, sorted, exactly as for TCP so a consumer keys both
    /// transports the same way.
    pub flow: FlowKey,
    /// `true` when it travelled from [`FlowKey::low`] toward `high`.
    pub from_low: bool,
    /// The datagram body: one complete zenoh wire message.
    pub payload: Vec<u8>,
    /// Index of the packet this came out of.
    pub packet_index: usize,
    /// What this packet's checksums said. Reported, never acted on.
    pub checksums: Checksums,
    /// Item 252 — the carriers this datagram arrived inside, outermost first.
    /// Empty when it arrived on the wire it was addressed on.
    pub tunnel: Tunnel,
}

impl Datagram {
    /// R311y607 — where this datagram was ADDRESSED.
    ///
    /// [`FlowKey`] stores its two endpoints sorted so both directions produce
    /// one key, which means neither field is "the destination" on its own —
    /// [`Self::from_low`] is what un-sorts them. A consumer asking whether a
    /// datagram was multicast must combine the two, and combining them at each
    /// call site is how one of them eventually gets it backwards.
    pub fn destination(&self) -> Endpoint {
        if self.from_low {
            self.flow.high
        } else {
            self.flow.low
        }
    }

    /// R311y608 — where this datagram came FROM, the other half of
    /// [`Self::destination`].
    ///
    /// Needed because zenoh's scouting is a REQUEST/RESPONSE exchange whose
    /// two halves travel to different addresses: the SCOUT goes to the group,
    /// and the HELLO answering it goes back to the address the scout was sent
    /// from (`socket.send_to(wbuf.as_slice(), peer)`,
    /// `zenoh/src/net/runtime/orchestrator.rs:1179`). Correlating them needs
    /// the source of one against the destination of the other, and un-sorting
    /// [`FlowKey`] at each call site is how one of them gets it backwards.
    pub fn source(&self) -> Endpoint {
        if self.from_low {
            self.flow.low
        } else {
            self.flow.high
        }
    }
}

/// R311y603 — one AF_VSOCK record's payload, lifted out of a `vsockmon`
/// capture.
///
/// The byte-stream twin of [`Datagram`]: same flow keying, same direction bit,
/// but the payload is a piece OF a stream rather than a whole message, because
/// zenoh's vsock link is `SOCK_STREAM` and carries the same length-prefixed
/// StreamEnvelope framing tcp does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VsockRecord {
    /// The two endpoints, sorted, keyed by `(cid, port)`.
    pub flow: FlowKey,
    /// `true` when it travelled from [`FlowKey::low`] toward `high`.
    pub from_low: bool,
    /// The record's payload bytes.
    pub payload: Vec<u8>,
    /// Index of the packet this came out of.
    pub packet_index: usize,
}

/// What a captured packet turned out to carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// A TCP segment, to be fed to a stream reassembler.
    Tcp(Segment),
    /// A UDP datagram, already a whole message.
    Udp(Datagram),
    /// R311y603 — the payload of one AF_VSOCK record.
    ///
    /// A distinct variant from [`Self::Tcp`] even though both feed a byte
    /// stream, because a vsockmon record has NO sequence number: the transport
    /// is reliable and in-order and the monitor device records what the kernel
    /// delivered, so the stream position is the running byte count and nothing
    /// else. Handing this back as a `Segment` with a fabricated `seq` would put
    /// that fabrication in the parser, where the running count cannot be known;
    /// [`crate::Dissection`] holds the counter and synthesises the sequence
    /// there, one layer up, where it is per-flow state rather than a guess.
    Vsock(VsockRecord),
    /// A raweth (L2) frame's payload — one whole message, like a datagram.
    ///
    /// R311y597. A separate variant from [`Self::Udp`] even though both carry
    /// a [`Datagram`], because the two are only alike in SHAPE: a raweth flow
    /// is keyed by MAC with no ports, so a consumer that reports "UDP flow"
    /// over it would be naming a transport that is not there.
    RawEth(Datagram),
    /// R311y606 — one piece of a fragmented IP datagram, v4 or v6.
    ///
    /// Reported rather than skipped. Reassembling needs a table and a deadline,
    /// which is per-capture state this function does not hold — the same
    /// division [`Self::Vsock`] is under, where the parser reports the record
    /// and [`crate::Dissection`] holds the running count. A consumer that does
    /// not want to reassemble treats this exactly as the old skip.
    IpFragment(IpFragment),
}

/// The fragment fields of one piece of a fragmented IP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentInfo {
    /// The datagram's identification: 16 bits on IPv4, 32 on IPv6. Widened to
    /// `u32` so one type carries both — the value is only ever compared, and
    /// the two families never share a key because their addresses differ in
    /// length.
    pub ident: u32,
    /// This piece's first byte, as an offset into the reassembled payload.
    /// Both families encode it in 8-byte units; this is already multiplied out.
    pub offset: usize,
    /// Whether more pieces follow. The LAST piece is the one that declares the
    /// total length, and it is the only piece that can.
    pub more: bool,
}

/// One piece of a fragmented IP datagram, with what it takes to place it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpFragment {
    /// Source address, port zero — a fragment other than the first carries no
    /// transport header, so no port is knowable here for any of them.
    pub src: Endpoint,
    /// Destination address, port zero.
    pub dst: Endpoint,
    /// The upper-layer protocol the reassembled datagram will carry.
    pub proto: u8,
    /// Where this piece goes and whether it is the last.
    pub info: FragmentInfo,
    /// This piece's bytes.
    pub payload: Vec<u8>,
    /// Index of the captured packet this came from.
    pub packet_index: usize,
    /// IP-header verdict only. The transport checksum is deliberately absent:
    /// it covers the whole datagram, so no single fragment can verify it, and
    /// reporting `Some(false)` for a piece would call every fragmented capture
    /// corrupt.
    pub checksums: Checksums,
    /// Item 252 — the carriers this PIECE arrived inside, outermost first.
    ///
    /// Held on the piece rather than only on the reassembled datagram because
    /// reassembly happens one layer up and the carrier is knowable only here.
    /// A tunnel ingress that fragments is the ordinary shape, so a fragmented
    /// capture is exactly where dropping this would be least noticed.
    pub tunnel: Tunnel,
}

/// ONE carrier header the walk stepped through on its way to a session.
///
/// Item 252 — before this, every header the walk consumed was discarded the
/// instant its payload was in hand (`cursor = d.payload; continue;`), so a
/// session inside a tunnel and a session on the wire produced byte-identical
/// output. Two deployments tunnelled from different SITES were one page.
///
/// The addresses carry `port` zero for the same reason [`IpFragment::src`]
/// does: a carrier header has no transport under it that this walk has read,
/// so there is no port to know. Renderers print the address alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelHop {
    /// Carrier source address, port zero.
    pub src: Endpoint,
    /// Carrier destination address, port zero.
    pub dst: Endpoint,
    /// The IP protocol number that made this header a carrier rather than a
    /// terminator: 4 (IPv4-in-IP), 41 (IPv6-in-IP) or 47 (GRE).
    ///
    /// Spelled rather than linked because the constants behind these are
    /// private to the walk, and a consumer reading this field has the number
    /// and not the name.
    pub proto: u8,
}

/// The carriers a packet arrived inside, OUTERMOST FIRST.
///
/// Empty for a packet that arrived on the wire it was addressed on, which is
/// the overwhelming majority, so the empty case costs no allocation.
///
/// Bounded by the walk's own encapsulation-depth limit, which refuses a longer
/// chain before it can be recorded, so this can never grow past it.
///
/// A CHAIN and not a single hop because the outermost pair alone would answer
/// "which site" for a one-hop tunnel and lie about a two-hop one — an overlay
/// inside a VPN has two sites, and reporting only the outer names the VPN
/// concentrator every tenant shares.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tunnel {
    hops: Vec<TunnelHop>,
}

impl Tunnel {
    /// A packet that arrived on the wire it was addressed on.
    pub fn none() -> Self {
        Self { hops: Vec::new() }
    }

    /// The carriers, outermost first.
    pub fn hops(&self) -> &[TunnelHop] {
        &self.hops
    }

    /// `true` when this packet was NOT tunnelled.
    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    /// How many carriers the walk stepped through.
    pub fn depth(&self) -> usize {
        self.hops.len()
    }

    /// Record one carrier. Called by the walk as it descends, so the order is
    /// outermost first by construction rather than by a later sort.
    fn push(&mut self, src: Endpoint, dst: Endpoint, proto: u8) {
        self.hops.push(TunnelHop { src, dst, proto });
    }
}

/// How many DISTINCT carrier chains one flow will remember.
///
/// A cap and not a `Vec` left to grow, for the reason every other population
/// in this reader is capped: the input is a file somebody else wrote. Eight is
/// chosen to be past any real deployment — a flow reaching a peer through more
/// than a couple of tunnels at once is already the anomaly the count reports —
/// while keeping the per-flow cost bounded by a constant.
pub const MAX_CARRIERS_PER_FLOW: usize = 8;

/// The distinct ways one flow was observed ARRIVING.
///
/// Item 252. Kept per flow rather than per packet because that is the question
/// a reader has: two sessions on the page differ by where they came from, and
/// a per-packet field answers it only for whoever walks every packet.
///
/// Both halves are recorded, and the second is why this is not a bare list: a
/// capture taken at a tunnel EGRESS sees the same flow arrive tunnelled and
/// then direct, and a reader told only "tunnelled" would conclude the capture
/// point was outside the tunnel for all of it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Carriers {
    seen: Vec<Tunnel>,
    untunnelled: bool,
    overflowed: bool,
}

impl Carriers {
    /// Record how ONE packet arrived.
    pub fn observe(&mut self, tunnel: &Tunnel) {
        if tunnel.is_empty() {
            self.untunnelled = true;
            return;
        }
        if self.seen.iter().any(|t| t == tunnel) {
            return;
        }
        if self.seen.len() >= MAX_CARRIERS_PER_FLOW {
            self.overflowed = true;
            return;
        }
        self.seen.push(tunnel.clone());
    }

    /// The distinct carrier chains, in the order first seen.
    pub fn tunnels(&self) -> &[Tunnel] {
        &self.seen
    }

    /// `true` when at least one packet on this flow arrived NOT tunnelled.
    pub fn saw_untunnelled(&self) -> bool {
        self.untunnelled
    }

    /// `true` when this flow arrived through more distinct chains than
    /// [`MAX_CARRIERS_PER_FLOW`], so the list above is a floor.
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// `true` when no packet on this flow arrived through any carrier.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// What an IP header resolved to, before the transport layer is read.
struct IpDatagram<'a> {
    src: Endpoint,
    dst: Endpoint,
    proto: u8,
    payload: &'a [u8],
    /// `Some` when this packet is one piece of a larger datagram.
    fragment: Option<FragmentInfo>,
}

/// What a LINK-layer frame turned out to carry.
///
/// The link layer has two arms, not one, and this type is what makes that
/// countable. [`strip_raweth`] answers first and [`strip_link`] second, and a
/// caller that reached for only the second would classify a zenoh-pico raweth
/// frame as [`SkipReason::NotIp`] — furniture — while the identical frame
/// arriving at the front door reached its own arm.
enum LinkBody<'a> {
    /// The frame carried an IP packet: its bytes, and whether they are v6.
    Ip { bytes: &'a [u8], is_v6: bool },
    /// The frame WAS a zenoh-pico raweth frame; there is no IP layer under it.
    RawEth(Datagram),
}

/// The ONE door onto a link-layer frame.
///
/// Item 260 — extracted from [`decapsulate`] because GRETAP made the link
/// layer reachable from a SECOND place: a GRE tunnel carrying Transparent
/// Ethernet Bridging hands back a whole Ethernet frame, which has to be
/// entered exactly as the capture's own frames are. Writing that second entry
/// as `strip_link` alone is the trap R311y864 declined to walk into, and it is
/// R311y863's "two doors" defect one carrier further down: the same frame
/// would read one way inside a tunnel and another way outside it.
///
/// Keeping both arms behind one function is what makes the two doors the same
/// door rather than two that agree today.
fn enter_link(
    link_type: u32,
    bytes: &[u8],
    packet_index: usize,
) -> Result<LinkBody<'_>, SkipReason> {
    if link_type == LINKTYPE_ETHERNET {
        if let Some(d) = strip_raweth(bytes, packet_index) {
            return Ok(LinkBody::RawEth(d));
        }
    }
    let (ip_bytes, is_v6) = strip_link(link_type, bytes)?;
    Ok(LinkBody::Ip {
        bytes: ip_bytes,
        is_v6,
    })
}

/// Decapsulate one captured packet down to the transport payload zenoh uses.
///
/// R311y584 (A3) — returns both transports rather than TCP alone. The
/// previous shape made "not TCP" a skip reason, which is where every
/// multicast and scouting packet went.
pub fn decapsulate(
    link_type: u32,
    packet_index: usize,
    bytes: &[u8],
) -> Result<Transport, SkipReason> {
    if link_type == LINKTYPE_VSOCK {
        return strip_vsockmon(bytes, packet_index).map(Transport::Vsock);
    }
    let (ip_bytes, is_v6) = match enter_link(link_type, bytes, packet_index)? {
        LinkBody::RawEth(d) => return Ok(Transport::RawEth(d)),
        LinkBody::Ip { bytes, is_v6 } => (bytes, is_v6),
    };
    let walked = walk_ip_chain(ip_bytes, is_v6, 0, None, None, Tunnel::none(), packet_index)?;
    let ip_checksum = walked.ip_checksum;
    let tunnel_checksum = walked.tunnel_checksum;
    let tunnel = walked.tunnel;
    let ip = match walked.end {
        // A GRETAP tunnel whose inner frame was a pico raweth one. The walk
        // reached the link layer and the link layer answered, so there is no
        // IP header here to strip a transport off — the datagram IS the answer.
        // Item 252 — and it is stamped like every other arm: a raweth frame
        // inside GRETAP is the MOST tunnelled thing this reader produces, so
        // an unstamped arm here would be the one that mattered most.
        ChainEnd::RawEth(mut d) => {
            d.tunnel = tunnel;
            // Round 2014 (item 261) — and its carriers' verdict with it. A
            // GRETAP frame is the arm where the ONLY checksum that exists is
            // the carrier's, so an arm that stamped the chain and not the
            // verdict would report where a corrupt tunnel came from while
            // staying silent that it was corrupt.
            d.checksums.tunnel = tunnel_checksum;
            return Ok(Transport::RawEth(d));
        }
        ChainEnd::Ip(ip) => ip,
    };
    // R311y606 — a fragment leaves here before the transport strip, because
    // there is no transport to strip. Even the FIRST fragment must: its header
    // is present but the body behind it is a prefix, and reading it as whole is
    // how a fragmented TCP segment used to advance the stream by less than the
    // sender sent — which desynchronises the flow, and desynchronisation is
    // terminal (`passive.rs:394`).
    if let Some(info) = ip.fragment {
        return Ok(Transport::IpFragment(IpFragment {
            src: ip.src,
            dst: ip.dst,
            proto: ip.proto,
            info,
            payload: ip.payload.to_vec(),
            packet_index,
            checksums: Checksums {
                ip: ip_checksum,
                transport: None,
                tunnel: tunnel_checksum,
            },
            tunnel,
        }));
    }
    // R311y597 — computed here, where both the addresses (for the pseudo
    // header) and the transport body are in hand, and REPORTED rather than
    // acted on. See [`Checksums`] for why a bad one is not a skip.
    let checksums = Checksums {
        ip: ip_checksum,
        transport: transport_checksum(&ip.src, &ip.dst, ip.proto, ip.payload),
        tunnel: tunnel_checksum,
    };
    transport_from_ip(
        ip.src,
        ip.dst,
        ip.proto,
        ip.payload,
        packet_index,
        checksums,
        tunnel,
    )
}

/// One GRE header: its payload and the ethertype that names what the payload
/// is.
///
/// R311y864. RFC 2784 §2.1 gives four fixed bytes — a flags-and-version word
/// and a Protocol Type — and makes every other field OPTIONAL and keyed by a
/// flag bit, which is why this cannot be a constant offset. RFC 2890 defines
/// the two that are actually deployed (Key and Sequence Number); the Checksum
/// is RFC 2784's own.
///
/// WHAT IS REFUSED IS REFUSED BY NAME, and the three cases are not the same
/// question:
///
/// - **Routing Present (`R`)** — RFC 2784 §2.1 requires it be zero, and its
///   field is a variable-length list this reader would have to walk to find the
///   payload at all. A header carrying it cannot be SIZED, so nothing after it
///   can be read.
/// - **Version other than 0** — version 1 is PPTP's Enhanced GRE (RFC 2637),
///   whose word at the same offset is a payload length rather than a flag set.
///   Parsing it as version 0 would find a plausible ethertype at the wrong
///   offset, which is the failure this crate refuses everywhere else.
/// - **Reserved0 non-zero** — RFC 2784 §2.1: "MUST be discarded". A reader that
///   guessed here would be inventing a variant.
///
/// All three answer `Encapsulation(47)` rather than the payload-typed reason
/// below, and the distinction is real: in these cases the payload type cannot
/// be READ, so "protocol 47, not opened" is the whole of what is known. Where
/// the header parses and only its payload is unwalkable, the ethertype IS
/// known, and reporting 47 there would tell a reader to add GRE support that
/// is already present.
fn strip_gre(bytes: &[u8]) -> Result<(&[u8], u16, Option<bool>), SkipReason> {
    if bytes.len() < 4 {
        return Err(SkipReason::Truncated);
    }
    let flags = u16::from_be_bytes([bytes[0], bytes[1]]);
    let checksum_present = flags & 0x8000 != 0;
    let routing_present = flags & 0x4000 != 0;
    let key_present = flags & 0x2000 != 0;
    let sequence_present = flags & 0x1000 != 0;
    let reserved0 = flags & 0x0FF8;
    let version = flags & 0x0007;
    if routing_present || version != 0 || reserved0 != 0 {
        return Err(SkipReason::Encapsulation(IP_PROTO_GRE));
    }
    let protocol_type = u16::from_be_bytes([bytes[2], bytes[3]]);
    // The Checksum and Reserved1 share one optional four-byte word: RFC 2784
    // §2.1 says Reserved1 is present if and only if the Checksum is.
    let mut len = 4;
    if checksum_present {
        len += 4;
    }
    if key_present {
        len += 4;
    }
    if sequence_present {
        len += 4;
    }
    if bytes.len() < len {
        return Err(SkipReason::Truncated);
    }
    // Round 2014 (item 261) — VERIFIED, not merely stepped over.
    //
    // RFC 2784 §2.5: the field holds the one's-complement checksum of the GRE
    // header AND the payload packet, so the sum over the whole thing WITH the
    // field in place must be zero — the same property `ipv4_header_ok` uses,
    // over a different span. `bytes` is exactly that span: `strip_gre` is
    // handed the carrier's whole body.
    //
    // Reported, never acted on. A corrupt carrier still gets walked, for the
    // reason [`Checksums`] gives about every other verdict here: a dissector
    // that refuses what it can read leaves the reader with less than one that
    // reads it and says so.
    let checksum = checksum_present.then(|| ones_complement(bytes, 0) == 0);
    Ok((&bytes[len..], protocol_type, checksum))
}

/// Consume ONE GRE carrier: the header, and whatever its ethertype names.
///
/// Item 260 — its own function because the step is reached from BOTH doors
/// onto the walk, and R311y863's finding was that a step written at one of
/// them makes the same carrier readable at one packet and unreadable at two.
/// Every ethertype this reader opens is opened here, once.
///
/// Round 2014 (item 261) — returns the carrier's own checksum verdict beside
/// the body. It rides out of the SAME function the header is parsed in, for
/// item 260's reason: a verdict computed at one of the walk's two doors would
/// be a carrier that verifies on a whole packet and not on a fragmented one.
fn step_gre(
    payload: &[u8],
    packet_index: usize,
) -> Result<(LinkBody<'_>, Option<bool>), SkipReason> {
    let (body, protocol_type, checksum) = strip_gre(payload)?;
    let body = match protocol_type {
        ETHERTYPE_IPV4 => Ok(LinkBody::Ip {
            bytes: body,
            is_v6: false,
        }),
        ETHERTYPE_IPV6 => Ok(LinkBody::Ip {
            bytes: body,
            is_v6: true,
        }),
        // Transparent Ethernet Bridging: the body is a whole FRAME, so it
        // re-enters at the link layer through the same door the capture's own
        // frames use. [`enter_link`] rather than [`strip_link`] — see its doc
        // for the defect the shorter spelling would have reproduced.
        ETHERTYPE_TEB => enter_link(LINKTYPE_ETHERNET, body, packet_index),
        // A payload this reader cannot walk, named BY ITS ETHERTYPE rather
        // than as protocol 47, which would send a reader to build GRE support
        // that is already here.
        other => Err(SkipReason::GrePayload(other)),
    }?;
    Ok((body, checksum))
}

/// Fold one carrier's checksum verdict into the chain's.
///
/// Round 2014 (item 261) — the same three-state fold [`walk_ip_chain`] applies
/// to `ip`, written once because it is applied at both of the walk's doors and
/// two copies is how they come to disagree: `Some(false)` if any carrier that
/// HAD a checksum failed, `Some(true)` if at least one had one and all passed,
/// `None` if none did.
fn fold_checksum(sofar: Option<bool>, this: Option<bool>) -> Option<bool> {
    match (sofar, this) {
        (a, None) => a,
        (None, b) => b,
        (Some(a), Some(b)) => Some(a && b),
    }
}

/// Where a chain walk ended.
///
/// Item 260 — a walk that can step through GRETAP can end at the LINK layer
/// instead of at an IP header, so the return type has to be able to say so.
/// Before that, "the chain ended" and "the chain ended at an IP header" were
/// the same sentence.
enum ChainEnd<'a> {
    Ip(IpDatagram<'a>),
    RawEth(Datagram),
}

/// Everything one chain walk OBSERVED, not merely where it ended.
///
/// Item 252 — the walk had been returning a pair, and adding the carrier chain
/// to it would have made a triple whose members are told apart by position.
/// The three are not the same kind of fact: one is where the walk stopped, and
/// two are things it saw on the way and would otherwise discard. A struct is
/// what lets the next such observation be added without every caller's
/// destructuring changing shape.
struct Walked<'a> {
    end: ChainEnd<'a>,
    /// Folded across every v4 header in the chain — see [`walk_ip_chain`].
    ip_checksum: Option<bool>,
    /// Round 2014 (item 261) — folded across every GRE carrier that declared
    /// one. The third such fold, and the reason `Walked` is a struct.
    tunnel_checksum: Option<bool>,
    /// The carriers stepped through, outermost first.
    tunnel: Tunnel,
}

/// Walk an IP-in-IP chain down to the header whose body is NOT another packet.
///
/// R311y862 wrote this loop inside [`decapsulate`]; R311y863 lifted it out
/// because the walk has TWO doors and only one of them reached it. A packet
/// that arrives whole comes through `decapsulate`; a packet the sender
/// fragmented is rebuilt by [`crate::frag`] and comes through
/// [`transport_from_ip`], and a tunnel is exactly as much a tunnel on that
/// second path. Leaving the loop in one function made the same carrier
/// readable at one packet and unreadable at two.
///
/// The checksum verdict is folded across every v4 header the chain carries
/// rather than read off the outermost one. Three states and each is a real
/// answer: `Some(false)` if any header that HAS a checksum failed, `Some(true)`
/// if at least one had one and all passed, `None` if none did (an all-v6
/// chain). Reporting only the outer header would let a tunnel whose inner
/// header is corrupt read as verified, and reporting only the inner would drop
/// the outer's verdict on the floor. `start_checksum` is what the caller
/// already folded — for the reassembly door, the outer header's verdict, which
/// was reached before this chain was in hand.
///
/// `start_depth` is likewise the caller's count of carriers already consumed,
/// so [`MAX_ENCAPSULATION_DEPTH`] bounds the CHAIN and not the call.
///
/// `packet_index` is carried only so a GRETAP frame can be handed to the link
/// layer, which stamps it onto the datagram it produces. Item 260.
///
/// `start_tunnel` is the third such caller-carried fold, and the reassembly
/// door is why it exists: the piece's OUTER header was consumed before the
/// reassembler had a whole datagram, so the carrier it named is knowable only
/// to that caller. Item 252.
fn walk_ip_chain<'a>(
    bytes: &'a [u8],
    is_v6: bool,
    start_depth: usize,
    start_checksum: Option<bool>,
    start_tunnel_checksum: Option<bool>,
    start_tunnel: Tunnel,
    packet_index: usize,
) -> Result<Walked<'a>, SkipReason> {
    let mut cursor: &'a [u8] = bytes;
    let mut v6 = is_v6;
    let mut ip_checksum = start_checksum;
    let mut tunnel_checksum = start_tunnel_checksum;
    let mut depth = start_depth;
    let mut tunnel = start_tunnel;
    loop {
        let d = if v6 {
            strip_ipv6(cursor)?
        } else {
            strip_ipv4(cursor)?
        };
        if !v6 {
            let ok = ipv4_header_ok(&cursor[..ipv4_header_len(cursor)]);
            ip_checksum = Some(ip_checksum.unwrap_or(true) && ok);
        }
        // A FRAGMENT ENDS THE WALK, and it must: the body behind this header is
        // a prefix of the inner packet, so stepping into it would read a
        // truncated header as a whole one — the same mistake R311y606 fixed one
        // layer down. The piece is reported, and the datagram the reassembler
        // rebuilds out of it re-enters this walk through `transport_from_ip`.
        if d.fragment.is_some() {
            return Ok(Walked {
                end: ChainEnd::Ip(d),
                ip_checksum,
                tunnel_checksum,
                tunnel,
            });
        }
        if d.proto == IP_PROTO_IPV4_IN_IP || d.proto == IP_PROTO_IPV6_IN_IP {
            depth += 1;
            if depth > MAX_ENCAPSULATION_DEPTH {
                // Round 2013 (item 256) — NOT `Encapsulation`. This build
                // opens protocol 4 and 41; what stopped here is the bound.
                return Err(SkipReason::EncapsulationTooDeep(d.proto));
            }
            // Item 252 — recorded BEFORE the cursor moves, which is the only
            // instant this header's addresses exist. The line under it used to
            // be the whole step.
            tunnel.push(d.src, d.dst, d.proto);
            v6 = d.proto == IP_PROTO_IPV6_IN_IP;
            cursor = d.payload;
            continue;
        }
        // R311y864 — GRE is a carrier like the two above and is counted as one,
        // but its body is named by an ETHERTYPE rather than by an IP version,
        // so the step is a header parse and then the same loop.
        if d.proto == IP_PROTO_GRE {
            depth += 1;
            if depth > MAX_ENCAPSULATION_DEPTH {
                // Round 2013 (item 256) — and GRE is the sharper case of the
                // two: R311y864 built the parser this line used to send a
                // reader away to write.
                return Err(SkipReason::EncapsulationTooDeep(IP_PROTO_GRE));
            }
            // Item 260 — the ethertype step, INCLUDING the TEB arm that
            // re-enters at the link layer. `depth` is not incremented a second
            // time for the Ethernet header GRETAP adds: the bound counts
            // CARRIERS, and one GRETAP carrier is one carrier that happens to
            // cost a link header as well as a GRE one. That the bound's unit
            // is a carrier and not a header is open-debt item 262, which this
            // step joins rather than settles.
            tunnel.push(d.src, d.dst, d.proto);
            let (body, carrier_checksum) = step_gre(d.payload, packet_index)?;
            tunnel_checksum = fold_checksum(tunnel_checksum, carrier_checksum);
            match body {
                LinkBody::Ip { bytes, is_v6 } => {
                    v6 = is_v6;
                    cursor = bytes;
                }
                LinkBody::RawEth(dg) => {
                    return Ok(Walked {
                        end: ChainEnd::RawEth(dg),
                        ip_checksum,
                        tunnel_checksum,
                        tunnel,
                    })
                }
            }
            continue;
        }
        return Ok(Walked {
            end: ChainEnd::Ip(d),
            ip_checksum,
            tunnel_checksum,
            tunnel,
        });
    }
}

/// Read the transport layer of a whole IP datagram.
///
/// Split out of [`decapsulate`] so a REASSEMBLED datagram takes the same path
/// as one that arrived whole. The alternative was re-synthesising an IP header
/// around the reassembled bytes just to feed it back through the front door,
/// and a synthesised header is a second place for the fields to be wrong.
///
/// `tunnel` is what the CALLER already walked through, and it is a parameter
/// rather than a fresh [`Tunnel::none`] for the reason item 252 exists: the
/// reassembly door reaches this function having consumed the outer header
/// itself, so a chain rebuilt here would start one carrier short and a
/// fragmented tunnel would report as an untunnelled one.
pub fn transport_from_ip(
    src: Endpoint,
    dst: Endpoint,
    proto: u8,
    payload: &[u8],
    packet_index: usize,
    checksums: Checksums,
    tunnel: Tunnel,
) -> Result<Transport, SkipReason> {
    match proto {
        IP_PROTO_TCP => {
            strip_tcp(src, dst, payload, packet_index, checksums, tunnel).map(Transport::Tcp)
        }
        IP_PROTO_UDP => {
            strip_udp(src, dst, payload, packet_index, checksums, tunnel).map(Transport::Udp)
        }
        // R311y863 — a REASSEMBLED datagram whose body is another packet is
        // WALKED here, not refused.
        //
        // R311y862's comment below said what lands on the encapsulation arm is
        // "a tunnel this build does not open ... or a reassembled datagram that
        // was one", and treated the two as the same answer. They are not. A
        // capture in which the carrier was fragmented — which is the ORDINARY
        // shape, since a tunnel adds header bytes to a packet that was already
        // at the path MTU — held a session this build can read, reassembled it
        // correctly, and then reported protocol 4 as a tunnel it could not
        // open, one packet after opening one.
        //
        // `start_depth` is 1 because the header that declared this body is the
        // one the reassembler already consumed.
        //
        // R311y864 — GRE joined, because a fragmented GRE carrier is as ordinary
        // as a fragmented IPIP one and R311y863 would otherwise have left the
        // new walk reachable through only one of the two doors again.
        IP_PROTO_IPV4_IN_IP | IP_PROTO_IPV6_IN_IP | IP_PROTO_GRE => {
            // Item 252 — THIS header is a carrier, and its addresses are the
            // arguments. `start_depth` is 1 for exactly the same reason, so the
            // hop and the count are recorded at the same place; recording the
            // count here and the addresses inside the walk is how the two would
            // come to disagree.
            let mut tunnel = tunnel;
            tunnel.push(src, dst, proto);
            let walked = if proto == IP_PROTO_GRE {
                // The reassembled body IS the GRE header, so the step the walk
                // takes for protocol 47 has to happen before re-entering it.
                // Item 260 — through `step_gre`, so this door opens exactly the
                // ethertypes the other one does, GRETAP included.
                // Round 2014 (item 261) — the reassembled carrier's OWN
                // checksum is folded in here, at the door that consumed it.
                // A GRE carrier that arrived in pieces is exactly as checksummed
                // as one that arrived whole, and this is the only place that
                // knows it.
                let (body, carrier_checksum) = step_gre(payload, packet_index)?;
                let seeded = fold_checksum(checksums.tunnel, carrier_checksum);
                match body {
                    LinkBody::Ip { bytes, is_v6 } => {
                        walk_ip_chain(bytes, is_v6, 1, checksums.ip, seeded, tunnel, packet_index)?
                    }
                    // A reassembled GRETAP carrier whose inner frame was a pico
                    // raweth one: the walk is over before it starts.
                    LinkBody::RawEth(mut dg) => {
                        dg.tunnel = tunnel;
                        dg.checksums.tunnel = seeded;
                        return Ok(Transport::RawEth(dg));
                    }
                }
            } else {
                walk_ip_chain(
                    payload,
                    proto == IP_PROTO_IPV6_IN_IP,
                    1,
                    checksums.ip,
                    checksums.tunnel,
                    tunnel,
                    packet_index,
                )?
            };
            let ip_checksum = walked.ip_checksum;
            let tunnel_checksum = walked.tunnel_checksum;
            let tunnel = walked.tunnel;
            let ip = match walked.end {
                ChainEnd::Ip(ip) => ip,
                ChainEnd::RawEth(mut dg) => {
                    dg.tunnel = tunnel;
                    dg.checksums.tunnel = tunnel_checksum;
                    return Ok(Transport::RawEth(dg));
                }
            };
            if let Some(info) = ip.fragment {
                // A FRAGMENT INSIDE A REASSEMBLED CARRIER, which is a real
                // shape: a tunnel ingress fragments a packet that was itself a
                // fragment. Handed back so the caller re-enters the reassembler
                // with it. Refusing it here is how this fix would have
                // regenerated the very defect it closes, one layer down.
                return Ok(Transport::IpFragment(IpFragment {
                    src: ip.src,
                    dst: ip.dst,
                    proto: ip.proto,
                    info,
                    payload: ip.payload.to_vec(),
                    packet_index,
                    checksums: Checksums {
                        ip: ip_checksum,
                        transport: None,
                        tunnel: tunnel_checksum,
                    },
                    tunnel,
                }));
            }
            // The transport checksum is recomputed from the INNERMOST header,
            // because the pseudo-header is the inner one's addresses. The value
            // handed in covers a carrier whose protocol has no transport
            // checksum at all, so carrying it forward would report a verdict
            // about the wrong packet.
            let inner = Checksums {
                ip: ip_checksum,
                transport: transport_checksum(&ip.src, &ip.dst, ip.proto, ip.payload),
                // Round 2014 (item 261) — CARRIED FORWARD, unlike `transport`
                // above. The transport verdict is recomputed because it is
                // about the inner header; the carrier verdict is about the
                // headers already consumed, which no deeper call can revisit.
                tunnel: tunnel_checksum,
            };
            // Recursion of depth exactly ONE: `walk_ip_chain` returns either a
            // fragment (handled above), a raweth datagram (returned above), or
            // a header whose proto is none of 4, 41 and 47, so this call cannot
            // reach this arm again.
            transport_from_ip(
                ip.src,
                ip.dst,
                ip.proto,
                ip.payload,
                packet_index,
                inner,
                tunnel,
            )
        }
        // R311y862 — an encapsulation is NOT furniture, and this arm is what
        // stops it being filed as such. What lands here is a tunnel this build
        // has no parser for: ESP, whose remainder is encrypted, AH, L2TP,
        // MPLS-in-IP and the Ethernet-in-IP pair. Bytes the capture holds and
        // no row does. (R311y864 removed GRE from that list, in the text as
        // well as in the behaviour — the arms above walk it now, and a comment
        // naming it here would send the next reader to build it twice.)
        p if is_encapsulation(p) => Err(SkipReason::Encapsulation(p)),
        other => Err(SkipReason::NotTransport(other)),
    }
}

/// The transport checksum of a reassembled datagram.
///
/// Public for the same reason [`transport_from_ip`] is: the verdict can only be
/// reached once every piece is in hand, so the reassembler is the only caller
/// that can produce it, and it must produce the same value the whole-datagram
/// path does.
pub fn reassembled_transport_checksum(
    src: &Endpoint,
    dst: &Endpoint,
    proto: u8,
    payload: &[u8],
) -> Option<bool> {
    transport_checksum(src, dst, proto, payload)
}

/// The IPv4 header's own declared length, clamped to what was captured.
fn ipv4_header_len(bytes: &[u8]) -> usize {
    let ihl = bytes.first().map_or(0, |b| ((b & 0x0F) as usize) * 4);
    ihl.clamp(0, bytes.len())
}

/// The UDP header is eight fixed bytes: src port, dst port, length, checksum.
///
/// The header's own `length` field is READ and used, not ignored in favour of
/// the slice length: a captured frame can carry trailing padding (Ethernet's
/// 60-byte minimum pads a short datagram), and handing those pad bytes to the
/// decoder as part of the message turns a valid Scout into a trailing-garbage
/// parse error.
fn strip_udp(
    src: Endpoint,
    dst: Endpoint,
    bytes: &[u8],
    packet_index: usize,
    checksums: Checksums,
    tunnel: Tunnel,
) -> Result<Datagram, SkipReason> {
    if bytes.len() < 8 {
        return Err(SkipReason::Truncated);
    }
    let src_port = u16::from_be_bytes([bytes[0], bytes[1]]);
    let dst_port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let declared = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    // `length` counts the header itself. A value below 8 is malformed; one
    // past the captured bytes means the capture was snapped short.
    if declared < 8 {
        return Err(SkipReason::Truncated);
    }
    let body_len = declared - 8;
    if bytes.len() < 8 + body_len {
        return Err(SkipReason::Truncated);
    }
    let src = Endpoint::new(src.addr(), src_port as u32);
    let dst = Endpoint::new(dst.addr(), dst_port as u32);
    let (flow, from_low) = FlowKey::new(src, dst);
    Ok(Datagram {
        flow,
        from_low,
        payload: bytes[8..8 + body_len].to_vec(),
        packet_index,
        checksums,
        tunnel,
    })
}

/// The 16-bit one's-complement sum RFC 1071 defines, folded to a checksum.
///
/// Returns the value the field must hold. Verification runs the same sum over
/// the bytes WITH the field in place and expects `0`, which is the standard
/// property and avoids having to zero and restore the field.
fn ones_complement(bytes: &[u8], seed: u32) -> u16 {
    let mut sum = seed;
    let mut chunks = bytes.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    // An odd trailing byte is padded on the RIGHT with zero.
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// The IPv4 header checksum, verified over the header as captured.
fn ipv4_header_ok(header: &[u8]) -> bool {
    ones_complement(header, 0) == 0
}

/// The TCP / UDP checksum, verified over the pseudo-header plus the segment.
///
/// `None` means the sender declined: a UDP datagram over IPv4 whose field is
/// zero carried no checksum at all (RFC 768), which is legal and is NOT a
/// failure. Over IPv6 the checksum is mandatory, so zero there is a real
/// `Some(false)`.
fn transport_checksum(src: &Endpoint, dst: &Endpoint, proto: u8, body: &[u8]) -> Option<bool> {
    // The field sits at offset 16 in TCP and 6 in UDP.
    let field_at = if proto == IP_PROTO_TCP { 16 } else { 6 };
    if body.len() < field_at + 2 {
        return None;
    }
    let field = u16::from_be_bytes([body[field_at], body[field_at + 1]]);
    let is_v4 = src.is_ipv4();
    if field == 0 && proto == IP_PROTO_UDP && is_v4 {
        return None;
    }
    // Pseudo-header: the addresses, the protocol, and the transport length.
    let mut seed: u32 = 0;
    for addr in [src.addr(), dst.addr()] {
        for c in addr.chunks_exact(2) {
            seed += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
    }
    let len = body.len() as u32;
    seed += u32::from(proto as u16);
    seed += (len >> 16) & 0xFFFF;
    seed += len & 0xFFFF;
    Some(ones_complement(body, seed) == 0)
}

/// A raweth (L2) frame, or `None` if this is not one.
///
/// R311y597 — before this, every non-IP ethertype died on
/// [`SkipReason::NotIp`] at the Ethernet arm, so zenoh-pico's raweth link was
/// invisible to a capture even though the framing had been sitting in
/// `wz_session_core::raweth_link` since R311y579.
///
/// ## Why this runs BEFORE `strip_link` rather than as a case inside it
///
/// The generic VLAN walk would half-succeed on the VLAN form and be wrong in a
/// way that looks right. pico spells its VLAN type `0x0081` so a little-endian
/// `memcpy` lands the real `81 00`, which the generic walk consumes; it then
/// reads pico's ethertype from the correct offset and treats the NEXT two
/// bytes as payload. Those two bytes are raweth's `data_length`. Delegating to
/// [`RawEthHeader::decode`] instead keeps one implementation of pico's layout,
/// including its VLAN detection, rather than a second one that agrees until it
/// does not.
///
/// ## Both byte orders are accepted, and that is not laxity
///
/// pico `memcpy`s the header struct, so `ethtype` lands in the SENDER's byte
/// order (`raweth_link`'s module doc). A little-endian pico puts `0x72e0` on
/// the wire as `e0 72` and a big-endian one as `72 e0`. The sender's
/// endianness is not observable from the capture, so a reader that accepted
/// only one spelling would be blind to half the deployments — for a property
/// that is pico's, not this parser's, to normalise.
fn strip_raweth(bytes: &[u8], packet_index: usize) -> Option<Datagram> {
    use wz_session_core::raweth_link::{self, RawEthHeader, DEFAULT_ETHTYPE};

    let (header, _) = RawEthHeader::decode(bytes).ok()?;
    if header.ethtype != DEFAULT_ETHTYPE && header.ethtype != DEFAULT_ETHTYPE.swap_bytes() {
        return None;
    }
    let (_, payload) = raweth_link::deframe(bytes).ok()?;
    // MACs, not addresses, and no ports — `Endpoint` carries the six bytes and
    // `is_ipv4()` answers false, so nothing downstream can mistake one for an
    // address it could route.
    let src = Endpoint::new(&header.smac, 0);
    let dst = Endpoint::new(&header.dmac, 0);
    let (flow, from_low) = FlowKey::new(src, dst);
    Some(Datagram {
        flow,
        from_low,
        payload: payload.to_vec(),
        packet_index,
        // A raweth frame has NEITHER: no IP header to checksum and no
        // transport pseudo-header to build one over. `None`/`None` is the
        // honest report, not an unchecked default -- the Ethernet FCS the NIC
        // verifies is stripped before a capture ever sees the frame.
        checksums: Checksums {
            ip: None,
            transport: None,
            // Round 2014 (item 261) — `None` here even for a raweth frame
            // inside GRETAP, and for the same reason `tunnel` below is empty:
            // the carriers are consumed by the walk ABOVE this strip, which
            // stamps both onto the datagram when it returns.
            tunnel: None,
        },
        // Item 252 — [`Tunnel::none`] because this strip runs at the LINK
        // layer, which is above every carrier: a raweth frame inside GRETAP
        // reaches here through `step_gre`, and the walk that consumed those
        // carriers stamps them onto this datagram when it returns. Building
        // the chain here would need the frame to know what carried it, which
        // is exactly what a link header cannot say.
        tunnel: Tunnel::none(),
    })
}

/// Returns the IP-layer bytes and whether they are IPv6.
fn strip_link(link_type: u32, bytes: &[u8]) -> Result<(&[u8], bool), SkipReason> {
    match link_type {
        LINKTYPE_ETHERNET => {
            if bytes.len() < 14 {
                return Err(SkipReason::Truncated);
            }
            let mut off = 12;
            let mut ethertype = u16::from_be_bytes([bytes[off], bytes[off + 1]]);
            // Walk any number of VLAN / QinQ tags: each is 4 bytes, the last
            // two of which are the next ethertype.
            while ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ {
                off += 4;
                if bytes.len() < off + 2 {
                    return Err(SkipReason::Truncated);
                }
                ethertype = u16::from_be_bytes([bytes[off], bytes[off + 1]]);
            }
            off += 2;
            match ethertype {
                ETHERTYPE_IPV4 => Ok((&bytes[off..], false)),
                ETHERTYPE_IPV6 => Ok((&bytes[off..], true)),
                _ => Err(SkipReason::NotIp),
            }
        }
        LINKTYPE_LINUX_SLL => {
            if bytes.len() < 16 {
                return Err(SkipReason::Truncated);
            }
            match u16::from_be_bytes([bytes[14], bytes[15]]) {
                ETHERTYPE_IPV4 => Ok((&bytes[16..], false)),
                ETHERTYPE_IPV6 => Ok((&bytes[16..], true)),
                _ => Err(SkipReason::NotIp),
            }
        }
        LINKTYPE_LINUX_SLL2 => {
            if bytes.len() < 20 {
                return Err(SkipReason::Truncated);
            }
            // SLL2 puts the protocol FIRST, unlike SLL.
            match u16::from_be_bytes([bytes[0], bytes[1]]) {
                ETHERTYPE_IPV4 => Ok((&bytes[20..], false)),
                ETHERTYPE_IPV6 => Ok((&bytes[20..], true)),
                _ => Err(SkipReason::NotIp),
            }
        }
        LINKTYPE_RAW => {
            // Bare IP: the version nibble is the only discriminator.
            match bytes.first().map(|b| b >> 4) {
                Some(4) => Ok((bytes, false)),
                Some(6) => Ok((bytes, true)),
                Some(_) => Err(SkipReason::NotIp),
                None => Err(SkipReason::Truncated),
            }
        }
        LINKTYPE_IPV4 => Ok((bytes, false)),
        LINKTYPE_IPV6 => Ok((bytes, true)),
        LINKTYPE_NULL | LINKTYPE_LOOP => strip_loopback(bytes),
        other => Err(SkipReason::UnsupportedLinkType(other)),
    }
}

/// `AF_INET`, which is 2 on every system that has ever written this
/// encapsulation.
const BSD_AF_INET: u32 = 2;

/// `AF_INET6`, which is the one number here that is NOT portable: 24 on
/// NetBSD / OpenBSD, 28 on FreeBSD / DragonFly, 30 on Darwin. A capture does
/// not record which system wrote it, so all three are read.
///
/// Linux's `AF_INET6` (10) is deliberately ABSENT. This is a BSD loopback
/// encapsulation and Linux does not write it — `tcpdump` refuses 10 here, and a
/// table that accepted it would be reading a number no producer of this format
/// emits.
const BSD_AF_INET6: [u32; 3] = [24, 28, 30];

/// The BSD loopback header: four bytes naming the address family, then the IP
/// packet.
///
/// R311y893. This is the `lo0` capture — the shape a developer's own
/// `tcpdump -i lo0` produces on macOS, and the one an OpenBSD host writes as
/// [`LINKTYPE_LOOP`]. Without it every packet of such a file came back
/// [`SkipReason::UnsupportedLinkType`] and the dissection was empty, which
/// reads as "this deployment carried no zenoh traffic" — a wrong conclusion
/// about a working system, reached from a correct number, and the same
/// under-promise R311y603 removed for `vsock`.
///
/// # Both byte orders, and why that is not a guess
///
/// [`LINKTYPE_NULL`]'s word is in the byte order of the machine that SAVED the
/// capture, so a reader may not assume its own. [`LINKTYPE_LOOP`] is specified
/// as network order (`/usr/include/pcap/dlt.h:280`) and is read the same way
/// regardless, because `tcpdump` accepts either on both — measured against
/// `tcpdump 4.99.4` rather than remembered.
///
/// Reading both is unambiguous rather than lenient: no member of this table is
/// the byte-swap of another member, so at most one of the two readings can
/// name a family. A word neither reading answers to is [`SkipReason::NotIp`],
/// the same answer the Ethernet arm gives an ethertype it does not carry — the
/// version nibble behind it is NOT consulted, because a reader that overruled
/// the header it was handed would be inventing the family rather than reading
/// it.
fn strip_loopback(bytes: &[u8]) -> Result<(&[u8], bool), SkipReason> {
    let Some(word) = bytes.first_chunk::<4>() else {
        return Err(SkipReason::Truncated);
    };
    for af in [u32::from_le_bytes(*word), u32::from_be_bytes(*word)] {
        if af == BSD_AF_INET {
            return Ok((&bytes[4..], false));
        }
        if BSD_AF_INET6.contains(&af) {
            return Ok((&bytes[4..], true));
        }
    }
    Err(SkipReason::NotIp)
}

fn strip_ipv4(bytes: &[u8]) -> Result<IpDatagram<'_>, SkipReason> {
    if bytes.len() < 20 {
        return Err(SkipReason::Truncated);
    }
    let ihl = ((bytes[0] & 0x0F) as usize) * 4;
    if ihl < 20 || bytes.len() < ihl {
        return Err(SkipReason::Truncated);
    }
    // The flags/offset word: bit 13 is More Fragments, the low 13 bits are the
    // offset in 8-byte units.
    //
    // R311y606 — BOTH halves decide. Reading the offset alone called a first
    // fragment (offset 0, MF set) a whole datagram and handed its prefix to the
    // transport, which is a silent truncation rather than a named skip.
    let flags_off = u16::from_be_bytes([bytes[6], bytes[7]]);
    let frag_off = (flags_off & 0x1FFF) as usize * 8;
    let more = flags_off & 0x2000 != 0;
    let fragment = (more || frag_off != 0).then(|| FragmentInfo {
        ident: u16::from_be_bytes([bytes[4], bytes[5]]) as u32,
        offset: frag_off,
        more,
    });
    let total_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    // Trust the header's total length when it fits, so trailing link padding
    // (an Ethernet frame padded to 60 bytes) is not read as payload. Fall
    // back to the captured length when the capture was snaplen-truncated.
    let end = if total_len >= ihl && total_len <= bytes.len() {
        total_len
    } else {
        bytes.len()
    };
    Ok(IpDatagram {
        src: Endpoint::new(&bytes[12..16], 0),
        dst: Endpoint::new(&bytes[16..20], 0),
        proto: bytes[9],
        payload: &bytes[ihl..end],
        fragment,
    })
}

/// Whether an IPv6 next-header value names an EXTENSION HEADER rather than an
/// upper-layer protocol (RFC 8200 §4.1 plus the IANA additions). Walking a
/// chain of these needs per-header length rules this build does not implement,
/// so they are refused by name.
///
/// R311y597 — this predicate is the fix, and the shape it replaced is worth
/// recording. The test was `next_header != IP_PROTO_TCP`, which refused UDP
/// and every other protocol as though it were an unwalked chain. Two failures
/// came out of that one line, and the second is the reason a bare "allow UDP
/// too" patch would not have been enough:
///
/// 1. An IPv6 UDP datagram never reached the UDP arm [`decapsulate`] already
///    had, so IPv6 multicast scouting and IPv6 UDP unicast links produced a
///    dissection with no messages.
/// 2. The skip NAMED THE WRONG CAUSE. `Ipv6ExtensionChain(17)` says "this
///    build cannot walk the chain" about a packet with no chain at all, which
///    points a reader at writing a chain walker rather than at the missing
///    branch. A skip reason that misattributes is worse than a generic one.
///
/// The IPv4 path never had either failure because [`strip_ipv4`] returns its
/// protocol byte through and lets [`decapsulate`] classify it. This restores
/// the same division of labour: refuse only what genuinely cannot be parsed
/// here, and let the caller name everything else.
const fn is_ipv6_extension_header(next_header: u8) -> bool {
    matches!(
        next_header,
        0        // Hop-by-Hop Options
        | 43     // Routing
        | 44     // Fragment
        | 50     // Encapsulating Security Payload
        | 51     // Authentication Header
        | 60     // Destination Options
        | 135    // Mobility
        | 139    // Host Identity Protocol
        | 140    // Shim6
        | 253    // reserved for experimentation
        | 254 // reserved for experimentation
    )
}

/// R311y603 — one `vsockmon` record: a 32-byte transport-independent header, a
/// transport header whose length the first one declares, then the payload.
///
/// The layout is read straight off `/usr/include/linux/vsockmon.h` on this
/// machine, and the `len` field is what makes the transport header skippable
/// without knowing which transport it is — the header's own stated purpose:
/// "so that no transport-specific knowledge is necessary to process packets".
/// That is why this reader needs nothing about virtio.
fn strip_vsockmon(bytes: &[u8], packet_index: usize) -> Result<VsockRecord, SkipReason> {
    if bytes.len() < VSOCKMON_HDR_LEN {
        return Err(SkipReason::Truncated);
    }
    let le64 = |at: usize| {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&bytes[at..at + 8]);
        u64::from_le_bytes(raw)
    };
    let le32 =
        |at: usize| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    let le16 = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);

    let src_cid = le64(0);
    let dst_cid = le64(8);
    let src_port = le32(16);
    let dst_port = le32(20);
    let op = le16(24);
    let transport_hdr_len = le16(28) as usize;

    if op != AF_VSOCK_OP_PAYLOAD {
        return Err(SkipReason::VsockNonPayload(op));
    }
    let payload_at = VSOCKMON_HDR_LEN
        .checked_add(transport_hdr_len)
        .ok_or(SkipReason::Truncated)?;
    if bytes.len() < payload_at {
        return Err(SkipReason::Truncated);
    }
    // The CID goes in as its little-endian bytes, giving an 8-byte address —
    // a length no IP endpoint can have, so a vsock flow cannot collide with an
    // IP one in the shared key space.
    let src = Endpoint::new(&src_cid.to_le_bytes(), src_port);
    let dst = Endpoint::new(&dst_cid.to_le_bytes(), dst_port);
    let (flow, from_low) = FlowKey::new(src, dst);
    Ok(VsockRecord {
        flow,
        from_low,
        payload: bytes[payload_at..].to_vec(),
        packet_index,
    })
}

/// How many extension headers this build will walk before giving up.
///
/// RFC 8200 sets no limit, so a corrupt or hostile capture can present a chain
/// that never terminates; a bound turns that into a named skip instead of a
/// loop. Eight is far past anything real — a packet with more than two or three
/// is already unusual.
const IPV6_MAX_EXT_HEADERS: usize = 8;

fn strip_ipv6(bytes: &[u8]) -> Result<IpDatagram<'_>, SkipReason> {
    if bytes.len() < 40 {
        return Err(SkipReason::Truncated);
    }
    let payload_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let end = if 40 + payload_len <= bytes.len() {
        40 + payload_len
    } else {
        bytes.len()
    };
    let src = Endpoint::new(&bytes[8..24], 0);
    let dst = Endpoint::new(&bytes[24..40], 0);

    // R311y603 — WALK the chain rather than refusing at its first link.
    //
    // A zenoh session over IPv6 with any extension header present produced a
    // dissection with no messages: the transport header is a few bytes past the
    // one this used to stop at, and every one of those bytes is a fixed-layout
    // field this crate already reads five other kinds of. The named skip was
    // the right SHAPE — it said which header stopped it — but it named work
    // rather than a limit, and the work is this loop.
    let mut next_header = bytes[6];
    let mut at = 40usize;
    // R311y606 — set by the Fragment header if the chain carries one. The walk
    // CONTINUES past it either way now: a first fragment's remaining chain is
    // what names the upper-layer protocol, and a later fragment's `next_header`
    // field carries the same value, so both arrive with `proto` correct.
    let mut fragment: Option<FragmentInfo> = None;
    for _ in 0..IPV6_MAX_EXT_HEADERS {
        // Not an extension header: hand the protocol byte back and let
        // `decapsulate` classify it, exactly as `strip_ipv4` does. TCP and UDP
        // reach their arms; anything else lands on `NotTransport`, which names
        // the real cause.
        if !is_ipv6_extension_header(next_header) {
            return Ok(IpDatagram {
                src,
                dst,
                proto: next_header,
                payload: &bytes[at.min(end)..end],
                fragment,
            });
        }
        let step = match next_header {
            // ESP encrypts everything after it, so there is nothing to walk to
            // — the same honest refusal as TLS without keys, one layer down.
            // 253 / 254 are reserved for experimentation and carry no length
            // this reader may assume.
            50 | 253 | 254 => return Err(SkipReason::Ipv6ExtensionChain(next_header)),
            // Fragment: fixed 8 bytes, and the only extension header that
            // makes this packet a PIECE rather than a datagram.
            //
            // R311y606 — the walk now continues for every offset, not only
            // zero. A later fragment has no transport header behind this one,
            // but it does not need one: `next_header` names the protocol the
            // reassembled datagram will carry, and the bytes after this header
            // are the piece's payload. Stopping at offset != 0 is what made
            // every fragmented IPv6 datagram unreadable.
            44 => {
                if end < at + 8 {
                    return Err(SkipReason::Truncated);
                }
                let off_word = u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]);
                fragment = Some(FragmentInfo {
                    ident: u32::from_be_bytes([
                        bytes[at + 4],
                        bytes[at + 5],
                        bytes[at + 6],
                        bytes[at + 7],
                    ]),
                    offset: (off_word >> 3) as usize * 8,
                    more: off_word & 0x1 != 0,
                });
                next_header = bytes[at];
                8
            }
            // Authentication Header measures in 4-byte units and counts from 2,
            // which is NOT the (len+1)*8 rule every other header here uses —
            // reading it with the common formula would land the walk in the
            // middle of the payload and decode noise.
            51 => {
                if end < at + 2 {
                    return Err(SkipReason::Truncated);
                }
                let len = (bytes[at + 1] as usize + 2) * 4;
                if end < at + len {
                    return Err(SkipReason::Truncated);
                }
                next_header = bytes[at];
                len
            }
            // Hop-by-Hop, Routing, Destination Options, Mobility, HIP, Shim6:
            // the common form, 8-byte units counted from 1.
            _ => {
                if end < at + 2 {
                    return Err(SkipReason::Truncated);
                }
                let len = (bytes[at + 1] as usize + 1) * 8;
                if end < at + len {
                    return Err(SkipReason::Truncated);
                }
                next_header = bytes[at];
                len
            }
        };
        at += step;
    }
    // Past the bound: still a chain this build did not walk to the end, and the
    // header it stopped on is the actionable part.
    Err(SkipReason::Ipv6ExtensionChain(next_header))
}

fn strip_tcp(
    src: Endpoint,
    dst: Endpoint,
    bytes: &[u8],
    packet_index: usize,
    checksums: Checksums,
    tunnel: Tunnel,
) -> Result<Segment, SkipReason> {
    if bytes.len() < 20 {
        return Err(SkipReason::Truncated);
    }
    let src_port = u16::from_be_bytes([bytes[0], bytes[1]]);
    let dst_port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let seq = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let data_off = ((bytes[12] >> 4) as usize) * 4;
    if data_off < 20 || bytes.len() < data_off {
        return Err(SkipReason::Truncated);
    }
    let flags = bytes[13];
    let src = Endpoint::new(src.addr(), src_port as u32);
    let dst = Endpoint::new(dst.addr(), dst_port as u32);
    let (flow, from_low) = FlowKey::new(src, dst);
    Ok(Segment {
        flow,
        from_low,
        seq,
        syn: flags & 0x02 != 0,
        fin: flags & 0x01 != 0,
        rst: flags & 0x04 != 0,
        payload: bytes[data_off..].to_vec(),
        packet_index,
        checksums,
        tunnel,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// The declared readable set IS the set the dispatch reads — both ways.
    ///
    /// R311y895, open-debt item 385. The sweep is what makes
    /// [`READABLE_LINK_TYPES`] a fact rather than a comment: every link type
    /// from 0 to 1000 is put through [`decapsulate`], and the ones that do NOT
    /// come back [`SkipReason::UnsupportedLinkType`] must be exactly the
    /// declared list. A new arm nobody documented reds here; a documented row
    /// with no arm reds here too.
    ///
    /// 1000 covers the whole assigned DLT space with room over — libpcap's
    /// highest at this pin is in the 200s — and the sweep is a thousand calls
    /// on a 64-byte buffer, so the bound buys certainty rather than costing
    /// time.
    ///
    /// The probe bytes are 64 zeros: long enough that no arm can call it
    /// truncated for its own header, and not IP under any of them, so every
    /// readable arm declines with `NotIp` or its own reason. What separates
    /// readable from unreadable here is which ERROR comes back, never whether
    /// one does.
    #[test]
    fn the_declared_readable_link_types_are_the_ones_the_dispatch_reads() {
        let probe = [0u8; 64];
        let declared: alloc::collections::BTreeSet<u32> =
            READABLE_LINK_TYPES.iter().map(|(c, _)| *c).collect();
        let mut read: alloc::collections::BTreeSet<u32> = alloc::collections::BTreeSet::new();
        for code in 0u32..=1000 {
            match decapsulate(code, 0, &probe) {
                Err(SkipReason::UnsupportedLinkType(n)) => {
                    assert_eq!(n, code, "the skip must name the link type it refused");
                }
                _ => {
                    read.insert(code);
                }
            }
        }
        assert_eq!(
            read, declared,
            "READABLE_LINK_TYPES and the dispatch disagree; the extra codes are \
             on whichever side is larger",
        );
    }

    /// The rendered line is ascending by code and names every declared row.
    ///
    /// Pinned here rather than only where it is printed, because the help text
    /// this feeds is in another crate and a renderer nobody tests is how the
    /// two drift apart.
    #[test]
    fn the_readable_link_type_line_renders_every_row_in_code_order() {
        let line = readable_link_types_line();
        for (code, name) in READABLE_LINK_TYPES {
            assert!(
                line.contains(&alloc::format!("{code} {name}")),
                "{code} {name} is declared but not rendered",
            );
        }
        let codes: Vec<u32> = line
            .split(", ")
            .map(|e| e.split(' ').next().expect("a code").parse().expect("a u32"))
            .collect();
        assert_eq!(codes.len(), READABLE_LINK_TYPES.len());
        assert!(
            codes.windows(2).all(|w| w[0] < w[1]),
            "ascending: {codes:?}"
        );
    }

    /// Decapsulate and require a TCP segment. R311y584 made `decapsulate`
    /// return both transports; these legs are all about the TCP path, so the
    /// unwrap is here rather than repeated at every call site.
    #[track_caller]
    fn tcp(link_type: u32, idx: usize, bytes: &[u8]) -> Result<Segment, SkipReason> {
        match decapsulate(link_type, idx, bytes) {
            Ok(Transport::Tcp(s)) => Ok(s),
            Ok(Transport::Udp(d) | Transport::RawEth(d)) => {
                panic!("expected TCP, got a datagram: {d:?}")
            }
            Ok(Transport::Vsock(r)) => panic!("expected TCP, got a vsock record: {r:?}"),
            Ok(Transport::IpFragment(f)) => panic!("expected TCP, got an IP fragment: {f:?}"),
            Err(e) => Err(e),
        }
    }

    /// Decapsulate and require an IP fragment. The sibling of [`tcp`] for the
    /// R311y606 legs, and it PANICS on a whole datagram rather than returning
    /// an option: a test that meant to build a fragment and built a whole
    /// packet would otherwise assert about the wrong thing.
    #[track_caller]
    fn fragment(link_type: u32, idx: usize, bytes: &[u8]) -> IpFragment {
        match decapsulate(link_type, idx, bytes) {
            Ok(Transport::IpFragment(f)) => f,
            other => panic!("expected an IP fragment, got {other:?}"),
        }
    }

    /// Build an Ethernet + IPv4 + TCP packet. The fixture builder is here in
    /// the tests rather than in the library because nothing in production
    /// EMITS packets — a builder in `src` would be a second, unverified
    /// opinion about the layouts the parser reads.
    /// R311y584 (A3) — Ethernet + IPv4 + UDP. Pads the Ethernet frame out to
    /// the 60-byte minimum on purpose: a real NIC does, and the pad bytes are
    /// exactly what makes the UDP header's own `length` field load-bearing
    /// rather than decorative.
    fn eth_ipv4_udp(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend_from_slice(&sport.to_be_bytes());
        udp.extend_from_slice(&dport.to_be_bytes());
        udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes()); // checksum (unverified)
        udp.extend_from_slice(payload);

        let mut ip = Vec::new();
        ip.push(0x45);
        ip.push(0);
        ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.push(64);
        ip.push(IP_PROTO_UDP);
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&udp);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    fn eth_ipv4_tcp(
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        seq: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&sport.to_be_bytes());
        tcp.extend_from_slice(&dport.to_be_bytes());
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&0u32.to_be_bytes()); // ack
        tcp.push(5 << 4); // data offset 5 words, no options
        tcp.push(flags);
        tcp.extend_from_slice(&0xFFFFu16.to_be_bytes()); // window
        tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum (unverified)
        tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent
        tcp.extend_from_slice(payload);

        let mut ip = Vec::new();
        ip.push(0x45); // v4, IHL 5
        ip.push(0);
        ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes()); // id
        ip.extend_from_slice(&0u16.to_be_bytes()); // flags/frag
        ip.push(64); // ttl
        ip.push(IP_PROTO_TCP);
        ip.extend_from_slice(&0u16.to_be_bytes()); // checksum (unverified)
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&tcp);

        let mut eth = vec![0x02; 12];
        eth.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        eth.extend_from_slice(&ip);
        eth
    }

    /// The ordinary path, end to end, with the flow key and the direction.
    #[test]
    fn an_ethernet_ipv4_tcp_packet_yields_its_segment() {
        let pkt = eth_ipv4_tcp(
            [10, 0, 0, 1],
            7447,
            [10, 0, 0, 2],
            40000,
            42,
            0x18,
            b"hello",
        );
        let seg = tcp(LINKTYPE_ETHERNET, 3, &pkt).expect("decapsulate");
        assert_eq!(seg.payload, b"hello");
        assert_eq!(seg.seq, 42);
        assert_eq!(seg.packet_index, 3);
        assert!(!seg.syn && !seg.fin && !seg.rst);
        assert_eq!(seg.flow.low.addr(), &[10, 0, 0, 1]);
        assert_eq!(seg.flow.low.port, 7447);
        assert!(seg.from_low, "10.0.0.1:7447 sorts below 10.0.0.2:40000");
    }

    /// BOTH directions of one connection produce the SAME flow key, with
    /// `from_low` as the only difference. Without this a reassembler would
    /// see two unrelated half-flows and never pair them.
    #[test]
    fn both_directions_share_one_flow_key() {
        let a = eth_ipv4_tcp([10, 0, 0, 1], 7447, [10, 0, 0, 2], 40000, 1, 0x18, b"a");
        let b = eth_ipv4_tcp([10, 0, 0, 2], 40000, [10, 0, 0, 1], 7447, 1, 0x18, b"b");
        let sa = tcp(LINKTYPE_ETHERNET, 0, &a).expect("a");
        let sb = tcp(LINKTYPE_ETHERNET, 1, &b).expect("b");
        assert_eq!(sa.flow, sb.flow, "one connection, one key");
        assert_ne!(sa.from_low, sb.from_low, "opposite directions");
    }

    /// VLAN tags are walked, however many there are. A capture off a trunk
    /// port carries them and an unwalked tag shifts the IP header by 4.
    #[test]
    fn vlan_and_qinq_tags_are_walked() {
        let plain = eth_ipv4_tcp([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 5, 0x18, b"tagged");
        for tags in [vec![ETHERTYPE_VLAN], vec![ETHERTYPE_QINQ, ETHERTYPE_VLAN]] {
            let mut tagged: Vec<u8> = plain[..12].to_vec();
            for t in &tags {
                tagged.extend_from_slice(&t.to_be_bytes());
                tagged.extend_from_slice(&[0x00, 0x64]); // VID 100
            }
            tagged.extend_from_slice(&plain[12..]);
            let seg = tcp(LINKTYPE_ETHERNET, 0, &tagged)
                .unwrap_or_else(|e| panic!("{tags:?} tags: {e:?}"));
            assert_eq!(seg.payload, b"tagged");
        }
    }

    /// Ethernet PADDING is not payload. A short frame is padded to 60 bytes
    /// on the wire, and a reassembler that appended the padding would inject
    /// zero bytes into the middle of a byte stream — a corruption that looks
    /// exactly like a protocol bug.
    #[test]
    fn ethernet_padding_is_not_read_as_payload() {
        let mut pkt = eth_ipv4_tcp([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 9, 0x18, b"hi");
        assert!(pkt.len() < 60);
        pkt.resize(60, 0x00);
        let seg = tcp(LINKTYPE_ETHERNET, 0, &pkt).expect("padded frame");
        assert_eq!(
            seg.payload, b"hi",
            "the IP header's total length bounds the payload, not the frame length"
        );
    }

    /// Every non-TCP outcome is a NAMED reason. Silent drops are what make a
    /// dissector's byte stream unaccountable.
    #[test]
    fn every_skip_names_itself() {
        // Not IP: an ARP ethertype.
        let mut arp = vec![0x02; 12];
        arp.extend_from_slice(&0x0806u16.to_be_bytes());
        arp.extend_from_slice(&[0; 28]);
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &arp),
            Err(SkipReason::NotIp)
        );

        // IP but UDP.
        // IP, but a transport zenoh does not use (SCTP).
        let mut sctp = eth_ipv4_tcp([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 0, 0x18, b"x");
        sctp[14 + 9] = 132;
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &sctp),
            Err(SkipReason::NotTransport(132))
        );

        // A non-first IPv4 fragment. R311y606 — this is no longer a skip: the
        // piece is REPORTED, with the offset it claims, and the reassembly
        // decision belongs to the consumer. The leg is kept here because the
        // packet it builds is the same one that used to be lost.
        let mut frag = eth_ipv4_tcp([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 0, 0x18, b"x");
        frag[14 + 6..14 + 8].copy_from_slice(&0x0001u16.to_be_bytes());
        let piece = fragment(LINKTYPE_ETHERNET, 0, &frag);
        assert_eq!(piece.info.offset, 8);
        assert!(!piece.info.more);
        assert_eq!(piece.proto, IP_PROTO_TCP);

        // An IPv6 extension-header chain. R311y597 — this leg was MISSING,
        // which is why the test's name was a claim it did not keep: the one
        // variant it never built was the one whose branch was wrong.
        //
        // R311y603 — the chain is WALKED now, so the leg moved to a header that
        // genuinely cannot be walked. ESP encrypts its remainder, which is a
        // limit rather than unfinished work.
        let ipv6_esp = {
            let mut ip = Vec::new();
            ip.extend_from_slice(&0x6000_0000u32.to_be_bytes());
            ip.extend_from_slice(&8u16.to_be_bytes());
            ip.push(50); // ESP
            ip.push(64);
            ip.extend_from_slice(&[0u8; 32]);
            ip.extend_from_slice(&[0u8; 8]);
            let mut eth = vec![0x02; 12];
            eth.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
            eth.extend_from_slice(&ip);
            eth
        };
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &ipv6_esp),
            Err(SkipReason::Ipv6ExtensionChain(50))
        );

        // R311y603 — a NON-FIRST IPv6 fragment, the v6 twin of the IPv4 leg
        // above. Named separately so a reader chasing a hole is not left to
        // guess the address family.
        let ipv6_frag = {
            let mut frag = alloc::vec![0u8; 8];
            frag[0] = IP_PROTO_TCP;
            // Offset 185 (bytes 1480), M clear. Non-zero offset is the point.
            frag[2..4].copy_from_slice(&(185u16 << 3).to_be_bytes());
            eth_ipv6([0x20; 16], [0x21; 16], 44, &frag)
        };
        // R311y606 — reported, not skipped, and the v6 identification is the
        // full 32 bits.
        let piece = fragment(LINKTYPE_ETHERNET, 0, &ipv6_frag);
        assert_eq!(piece.info.offset, 1480);
        assert!(!piece.info.more);
        assert_eq!(piece.proto, IP_PROTO_TCP);

        // A link type this build does not decapsulate.
        assert_eq!(
            decapsulate(999, 0, &[0u8; 64]),
            Err(SkipReason::UnsupportedLinkType(999))
        );

        // Truncated.
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &[0u8; 8]),
            Err(SkipReason::Truncated)
        );
    }

    /// The bare-IP and cooked link types reach the same segment as Ethernet
    /// does — the assertion is that the header WIDTHS are right, since an
    /// off-by-N would not fail, it would decode a different flow.
    #[test]
    fn raw_and_cooked_link_types_reach_the_same_segment() {
        let eth = eth_ipv4_tcp([10, 0, 0, 1], 7447, [10, 0, 0, 2], 40000, 3, 0x18, b"body");
        let ip = &eth[14..];
        let reference = tcp(LINKTYPE_ETHERNET, 0, &eth).expect("ethernet");

        for (lt, framed) in [
            (LINKTYPE_RAW, ip.to_vec()),
            (LINKTYPE_IPV4, ip.to_vec()),
            (LINKTYPE_LINUX_SLL, {
                let mut v = vec![0u8; 14];
                v.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
                v.extend_from_slice(ip);
                v
            }),
            (LINKTYPE_LINUX_SLL2, {
                let mut v = ETHERTYPE_IPV4.to_be_bytes().to_vec();
                v.extend_from_slice(&[0u8; 18]);
                v.extend_from_slice(ip);
                v
            }),
        ] {
            let seg = tcp(lt, 0, &framed).unwrap_or_else(|e| panic!("link {lt}: {e:?}"));
            assert_eq!(seg, reference, "link type {lt} decapsulates identically");
        }
    }

    /// TCP options are skipped by the data offset, not assumed away. A SYN
    /// carries them (MSS, window scale, SACK-permitted), and reading past a
    /// fixed 20 bytes would treat the options as stream payload.
    #[test]
    fn tcp_options_are_skipped_by_the_data_offset() {
        let mut pkt = eth_ipv4_tcp([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, 0, 0x02, b"");
        // Splice 8 bytes of options in and widen the data offset to 7 words.
        let tcp_at = 14 + 20;
        pkt[tcp_at + 12] = 7 << 4;
        let opts = [0x02, 0x04, 0x05, 0xB4, 0x01, 0x01, 0x01, 0x00];
        let insert_at = tcp_at + 20;
        for (i, b) in opts.iter().enumerate() {
            pkt.insert(insert_at + i, *b);
        }
        let total = (pkt.len() - 14) as u16;
        pkt[14 + 2..14 + 4].copy_from_slice(&total.to_be_bytes());
        let seg = tcp(LINKTYPE_ETHERNET, 0, &pkt).expect("syn with options");
        assert!(seg.syn);
        assert!(
            seg.payload.is_empty(),
            "the options are header, not payload: {:?}",
            seg.payload
        );
    }

    /// R311y584 (A3) — the leg the old `NotTcp(17)` skip stood in for.
    ///
    /// Before this, every UDP packet in a capture became a named skip, which
    /// meant scouting, multicast Join and the whole UDP unicast link produced
    /// a dissection with no messages and no error.
    #[test]
    fn a_udp_datagram_is_decapsulated_rather_than_skipped() {
        let pkt = eth_ipv4_udp([10, 0, 0, 1], 7447, [224, 0, 0, 224], 7446, b"hello");
        match decapsulate(LINKTYPE_ETHERNET, 5, &pkt) {
            Ok(Transport::Udp(d)) => {
                assert_eq!(d.payload, b"hello");
                assert_eq!(d.packet_index, 5);
                assert_eq!(d.flow.low.port.min(d.flow.high.port), 7446);
            }
            other => panic!("expected a datagram, got {other:?}"),
        }
    }

    /// The UDP header's `length` field is READ, not inferred from the slice.
    ///
    /// The fixture's Ethernet frame is padded to the 60-byte minimum, so the
    /// captured bytes run PAST the datagram. A reader that took "everything
    /// after the header" would hand five bytes of payload plus a tail of
    /// zeroes to the decoder, and a zenoh message followed by zero bytes
    /// parses as trailing garbage rather than as the message it is.
    #[test]
    fn ethernet_padding_is_not_read_as_datagram_payload() {
        let pkt = eth_ipv4_udp([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, b"abc");
        assert_eq!(pkt.len(), 60, "the fixture must actually be padded");
        match decapsulate(LINKTYPE_ETHERNET, 0, &pkt) {
            Ok(Transport::Udp(d)) => assert_eq!(d.payload, b"abc"),
            other => panic!("expected a datagram, got {other:?}"),
        }
    }

    /// Both directions of one UDP conversation key to the SAME flow, exactly
    /// as they do for TCP — otherwise an observer would treat a request and
    /// its reply as two unrelated sessions.
    #[test]
    fn both_directions_of_a_udp_flow_share_one_key() {
        let a = eth_ipv4_udp([10, 0, 0, 1], 1000, [10, 0, 0, 2], 2000, b"x");
        let b = eth_ipv4_udp([10, 0, 0, 2], 2000, [10, 0, 0, 1], 1000, b"y");
        let (da, db) = match (
            decapsulate(LINKTYPE_ETHERNET, 0, &a),
            decapsulate(LINKTYPE_ETHERNET, 1, &b),
        ) {
            (Ok(Transport::Udp(x)), Ok(Transport::Udp(y))) => (x, y),
            other => panic!("expected two datagrams, got {other:?}"),
        };
        assert_eq!(da.flow, db.flow);
        assert_ne!(da.from_low, db.from_low);
    }

    // ---- R311y597: checksums ------------------------------------------------

    /// A REAL IPv4 + UDP packet whose two checksums were computed by an
    /// INDEPENDENT implementation (a short Python one's-complement), not by
    /// the code under test.
    ///
    /// That distinction is the whole value of the fixture. Generating the
    /// expected value with `ones_complement` itself would assert only that the
    /// function agrees with itself, which is true of a wrong one.
    /// `ip ck = 0x66ca`, `udp ck = 0xe1a4`, payload `"zenoh"`.
    #[rustfmt::skip]
    const GOOD_CHECKSUM_PKT: [u8; 47] = [
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x08, 0x00, 0x45, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11,
        0x66, 0xca, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x1d, 0x17,
        0x9c, 0x40, 0x00, 0x0d, 0xe1, 0xa4, 0x7a, 0x65, 0x6e, 0x6f, 0x68,
    ];

    fn checksums_of(pkt: &[u8]) -> Checksums {
        match decapsulate(LINKTYPE_ETHERNET, 0, pkt) {
            Ok(Transport::Udp(d)) => d.checksums,
            other => panic!("expected a datagram, got {other:?}"),
        }
    }

    /// Correct checksums verify — against a vector this crate did not compute.
    #[test]
    fn a_correctly_checksummed_packet_verifies() {
        let c = checksums_of(&GOOD_CHECKSUM_PKT);
        assert_eq!(c.ip, Some(true), "the IPv4 header checksum must verify");
        assert_eq!(c.transport, Some(true), "the UDP checksum must verify");
        assert!(!c.any_invalid());
    }

    /// Corruption is CAUGHT — and separately for each layer, so a verifier
    /// that only ever answered "true" or that conflated the two fails here.
    #[test]
    fn corruption_is_caught_in_the_layer_it_happened_in() {
        // A payload byte is covered by the UDP checksum and not by the IP one.
        let mut body = GOOD_CHECKSUM_PKT;
        body[44] ^= 0xFF;
        let c = checksums_of(&body);
        assert_eq!(c.ip, Some(true), "the IP header was not touched");
        assert_eq!(c.transport, Some(false), "a flipped payload byte must show");
        assert!(c.any_invalid());

        // The IP TTL is covered by the IP checksum and is NOT in the UDP
        // pseudo-header, so exactly the opposite verdict must come back.
        let mut ttl = GOOD_CHECKSUM_PKT;
        ttl[22] ^= 0xFF;
        let c = checksums_of(&ttl);
        assert_eq!(c.ip, Some(false), "a flipped TTL must show");
        assert_eq!(c.transport, Some(true), "the UDP body was not touched");
    }

    /// A UDP datagram over IPv4 with a ZERO checksum declined to compute one
    /// (RFC 768). That is absence, not corruption, and the two must not be
    /// reported the same way — every fixture in this file is that shape.
    #[test]
    fn a_zero_udp_checksum_over_ipv4_is_absence_not_failure() {
        let pkt = eth_ipv4_udp([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, b"abc");
        let c = checksums_of(&pkt);
        assert_eq!(c.transport, None, "zero over IPv4 means none was computed");
        // ...and the SAME fixture's IP header checksum really is wrong, because
        // the builder writes zero there too and zero is not special for IPv4.
        // The two layers reporting differently on one packet is the point: an
        // implementation that folded them into a single verdict could not say
        // this, and this is the shape every fixture in this file has.
        assert_eq!(
            c.ip,
            Some(false),
            "a zero IPv4 header checksum is wrong, not absent",
        );
    }

    /// IPv6 has no header checksum at all, so claiming one either way would be
    /// an invention.
    #[test]
    fn ipv6_reports_no_header_checksum() {
        let pkt = eth_ipv6(V6_A, V6_B, IP_PROTO_UDP, &udp_body(1, 2, b"x"));
        let c = checksums_of(&pkt);
        assert_eq!(c.ip, None);
    }

    /// A raweth frame has neither checksum available: no IP header, and no
    /// pseudo-header to build a transport one over.
    #[test]
    fn a_raweth_frame_reports_neither_checksum() {
        use wz_session_core::raweth_link::DEFAULT_ETHTYPE;
        let pkt = raweth_frame([1; 6], [2; 6], DEFAULT_ETHTYPE, b"x");
        match decapsulate(LINKTYPE_ETHERNET, 0, &pkt) {
            Ok(Transport::RawEth(d)) => {
                assert_eq!(d.checksums.ip, None);
                assert_eq!(d.checksums.transport, None);
                assert!(!d.checksums.any_invalid());
            }
            other => panic!("expected a raweth datagram, got {other:?}"),
        }
    }

    // ---- R311y597: raweth (L2) ---------------------------------------------

    /// The fixture is built with `raweth_link`'s OWN framer, so a walker that
    /// disagrees with wz's framing fails here instead of agreeing with my
    /// reading of pico's header.
    fn raweth_frame(smac: [u8; 6], dmac: [u8; 6], ethtype: u16, payload: &[u8]) -> Vec<u8> {
        use wz_session_core::raweth_link::{frame, RawEthHeader};
        let h = RawEthHeader::new(dmac, smac, ethtype, payload.len() as u16);
        frame(&h, payload).expect("raweth frame")
    }

    /// THE GAP. A raweth frame used to die on `NotIp` at the Ethernet arm.
    #[test]
    fn a_raweth_frame_yields_its_payload_as_a_datagram() {
        use wz_session_core::raweth_link::DEFAULT_ETHTYPE;
        let smac = [0x30, 0x03, 0xc8, 0x37, 0x25, 0xa1];
        let dmac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let pkt = raweth_frame(smac, dmac, DEFAULT_ETHTYPE, b"zenoh-batch");

        match decapsulate(LINKTYPE_ETHERNET, 11, &pkt) {
            Ok(Transport::RawEth(d)) => {
                assert_eq!(d.payload, b"zenoh-batch");
                assert_eq!(d.packet_index, 11);
                // Keyed by MAC, and neither endpoint claims to be an address.
                assert!(!d.flow.low.is_ipv4() && !d.flow.high.is_ipv4());
                assert_eq!(d.flow.low.port, 0);
                let mut macs = alloc::vec![d.flow.low.addr(), d.flow.high.addr()];
                macs.sort();
                assert_eq!(macs, alloc::vec![&smac[..], &dmac[..]]);
            }
            other => panic!("expected a raweth datagram, got {other:?}"),
        }
    }

    /// BOTH byte orders of pico's ethertype are admitted, because the sender's
    /// endianness is not observable and pico `memcpy`s the field.
    #[test]
    fn a_raweth_frame_is_recognised_in_either_byte_order() {
        use wz_session_core::raweth_link::DEFAULT_ETHTYPE;
        for (ethtype, label) in [
            (DEFAULT_ETHTYPE, "as a little-endian pico writes it"),
            (
                DEFAULT_ETHTYPE.swap_bytes(),
                "as a big-endian pico writes it",
            ),
        ] {
            let pkt = raweth_frame([1; 6], [2; 6], ethtype, b"x");
            assert!(
                matches!(
                    decapsulate(LINKTYPE_ETHERNET, 0, &pkt),
                    Ok(Transport::RawEth(_))
                ),
                "{label}",
            );
        }
    }

    /// The CONTROL, and it is the leg that keeps the change honest: another
    /// non-IP ethertype must STILL be `NotIp`. Admitting every non-IP frame as
    /// raweth would pass the two legs above.
    #[test]
    fn a_non_raweth_ethertype_is_still_not_ip() {
        let pkt = raweth_frame([1; 6], [2; 6], 0x1234, b"x");
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &pkt),
            Err(SkipReason::NotIp),
        );
        // ...and an ordinary IPv4 frame must not be diverted into raweth.
        let ip = eth_ipv4_udp([10, 0, 0, 1], 1, [10, 0, 0, 2], 2, b"abc");
        assert!(matches!(
            decapsulate(LINKTYPE_ETHERNET, 0, &ip),
            Ok(Transport::Udp(_))
        ));
    }

    /// A frame whose `data_length` overruns what was captured is declined, not
    /// read past — the payload is cut to the header's claim, so a NIC-padded
    /// short frame does not hand pad bytes to the decoder.
    #[test]
    fn a_raweth_payload_is_cut_to_its_declared_length() {
        use wz_session_core::raweth_link::DEFAULT_ETHTYPE;
        let mut pkt = raweth_frame([1; 6], [2; 6], DEFAULT_ETHTYPE, b"abc");
        while pkt.len() < 60 {
            pkt.push(0); // the NIC's minimum-frame padding
        }
        match decapsulate(LINKTYPE_ETHERNET, 0, &pkt) {
            Ok(Transport::RawEth(d)) => assert_eq!(d.payload, b"abc"),
            other => panic!("expected a raweth datagram, got {other:?}"),
        }
    }

    /// Round 2009 (open-debt item 248) — WHAT ELSE REACHES THE FURNITURE ARM.
    ///
    /// `not_ip` is one of three classes this crate calls furniture, and the
    /// furniture claim is a POSITIVE argument: nothing counted there could have
    /// carried a zenoh session, so a capture is not short for holding it. Two
    /// of the three had that argument checked; this one rested on a paragraph
    /// about "ARP and its neighbours" and nobody had ever asked what the
    /// neighbours ARE.
    ///
    /// So the whole 16-bit space is swept and the answer is exact rather than
    /// representative. The escaping set is DERIVED — every ethertype is driven
    /// through `decapsulate` and the ones that do not land on `NotIp` are
    /// collected — so an ethertype this build learns to walk shows up here
    /// without anyone remembering to add it.
    ///
    /// ⚠ THE BODY IS ZEROS AND THAT IS PART OF THE CLAIM. A VLAN or QinQ tag
    /// escapes only if what follows it is walkable, and here it is `0x0000`,
    /// which is furniture — so the tags are correctly absent from the set below
    /// and their walk is witnessed by `vlan_and_qinq_tags_are_walked` instead.
    /// What this leg settles is the OTHER 65 000-odd values, which no test had
    /// ever touched.
    #[test]
    fn every_ethertype_this_build_does_not_walk_is_furniture() {
        use wz_session_core::raweth_link::DEFAULT_ETHTYPE;

        let mut escaped: Vec<u16> = Vec::new();
        for ethertype in 0u16..=u16::MAX {
            let mut frame = vec![0u8; 12];
            frame.extend_from_slice(&ethertype.to_be_bytes());
            frame.extend_from_slice(&[0u8; 46]);
            if decapsulate(LINKTYPE_ETHERNET, 0, &frame) != Err(SkipReason::NotIp) {
                escaped.push(ethertype);
            }
        }

        // The answer, and it is a SET rather than a count: a build that walked
        // a different ethertype would have the same number here.
        //
        // ⚠ THE SWEEP FOUND ONE THIS TEST'S AUTHOR DID NOT. The expected list
        // was written as three and came back four: raweth's ethertype escapes
        // in BOTH byte orders, because pico `memcpy`s its header and the value
        // lands in the SENDER's order — `strip_raweth` accepts either, and its
        // module doc says why. Enumerating by hand would have missed it, which
        // is the whole reason item 248 asked for the space to be counted
        // instead of argued about.
        assert_eq!(
            escaped,
            vec![
                ETHERTYPE_IPV4,
                DEFAULT_ETHTYPE,
                ETHERTYPE_IPV6,
                DEFAULT_ETHTYPE.swap_bytes(),
            ],
            "exactly four ethertypes leave the furniture arm on a zero body: \
             IPv4, IPv6, and zenoh-pico's raweth in either byte order. \
             Anything else here is a link this build started walking and \
             nobody classified; anything MISSING is a link it stopped walking"
        );

        // THE ARGUMENT, made checkable. The furniture claim is that nothing in
        // the complement could carry zenoh, and the complement is enormous --
        // so the check is that the ethertypes a real segment actually carries
        // are IN it, by name, rather than that the complement is empty.
        for (name, ethertype) in [
            ("ARP", 0x0806u16),
            ("RARP", 0x8035),
            ("LLDP", 0x88CC),
            ("EAPOL", 0x888E),
            ("PPPoE discovery", 0x8863),
            ("PPPoE session", 0x8864),
            ("MPLS unicast", 0x8847),
            ("PTP", 0x88F7),
            ("Wake-on-LAN", 0x0842),
            ("an 802.3 LENGTH field, not a type at all", 0x0040),
        ] {
            assert!(
                !escaped.contains(&ethertype),
                "{name} ({ethertype:#06x}) must be furniture: no zenoh link \
                 speaks it, and every link this workspace does speak arrives \
                 as TCP, UDP, or raweth"
            );
        }
    }

    /// Round 2010 (open-debt item 250) — THE ENCAPSULATION SET, PINNED, AND
    /// every protocol number classified rather than defaulted.
    ///
    /// Item 250 is that this list is ten numbers somebody typed, so an
    /// encapsulation it omits is FURNITURE BY OMISSION -- filed as "could not
    /// have carried a session" for no reason but absence. That is the defect
    /// R311y862 measured on protocol 4, one item away.
    ///
    /// ⚠ THIS DOES NOT CLOSE 250 AND DOES NOT CLAIM TO. The honest gate is a
    /// comparison against IANA's assignments, and this tree has no such table;
    /// asking the question by hand is what THIS round did, and hand
    /// enumeration is the thing Round 2009 caught itself getting wrong. What
    /// the leg below buys is narrower and real: the set cannot SHRINK
    /// silently, and every number is now sorted into a named class by a sweep
    /// rather than falling into a default.
    #[test]
    fn every_ip_protocol_number_lands_in_a_named_class() {
        // The set, DERIVED from the predicate rather than transcribed beside
        // it -- so a number removed from `is_encapsulation` reds here even
        // though nobody edited this list.
        assert_eq!(
            encapsulation_set(),
            vec![4, 41, 47, 50, 51, 55, 94, 97, 98, 108, 115, 137, 143],
            "the encapsulation set. A number MISSING here is one this build \
             stopped treating as a tunnel, which sends it straight to the \
             furniture class; a number ADDED is one somebody classified and \
             this list has not been told about"
        );

        // THE THREE THIS ROUND ADDED REACH THE ARM, driven rather than
        // asserted from the predicate: a number in the list and not in the
        // dispatch would be a classification nothing acts on.
        for (name, proto) in [("MOBILE", 55u8), ("ENCAP", 98), ("IPComp", 108)] {
            assert_eq!(
                decapsulate(LINKTYPE_ETHERNET, 0, &eth_ipv4_carrier(proto, &[0u8; 8])),
                Err(SkipReason::Encapsulation(proto)),
                "{name} ({proto}) must be a tunnel not opened, NOT furniture -- \
                 its body could be a session"
            );
        }
        // CONTROL: a protocol that genuinely terminates at the host still
        // reaches the furniture arm, so the widening did not swallow the class.
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &eth_ipv4_carrier(1, &[0u8; 8])),
            Err(SkipReason::NotTransport(1)),
            "ICMP terminates at the host and carries no session"
        );

        // And the partition is TOTAL: every one of the 256 numbers is a
        // transport this build reads, an encapsulation it names, or furniture
        // -- with no fourth outcome and no number in two classes at once.
        let mut transports = 0usize;
        let mut encapsulations = 0usize;
        let mut furniture = 0usize;
        for proto in 0u8..=u8::MAX {
            let is_transport = proto == IP_PROTO_TCP || proto == IP_PROTO_UDP;
            let is_encap = is_encapsulation(proto);
            assert!(
                !(is_transport && is_encap),
                "protocol {proto} is in two classes at once"
            );
            if is_transport {
                transports += 1;
            } else if is_encap {
                encapsulations += 1;
            } else {
                furniture += 1;
            }
        }
        assert_eq!(transports, 2, "TCP and UDP, and nothing else is read");
        assert_eq!(encapsulations, 13);
        assert_eq!(
            transports + encapsulations + furniture,
            256,
            "every number must be classified"
        );
        // ⚠ THE NUMBER THIS ITEM IS ABOUT. 241 protocols are furniture, and
        // the claim attached to each is "could not have carried a session".
        // For ICMP and IGMP that is argued; for the rest it is inherited from
        // absence, and no gate in this tree distinguishes the two.
        assert_eq!(
            furniture, 241,
            "the furniture class is this large, and 250 is that its size is \
             what nobody has justified"
        );
    }

    /// Round 2009 (item 248) — the OTHER furniture class that rested on a
    /// sentence: every vsock op except one is counted as carrying nothing.
    ///
    /// The argument is upstream's, quoted in this file beside
    /// `AF_VSOCK_OP_PAYLOAD`: "If af_vsockmon_hdr->op is AF_VSOCK_OP_PAYLOAD
    /// then the payload follows the transport header. Other ops do not have a
    /// payload." THIS TREE CANNOT CHECK THAT CLAIM — it is about a kernel, and
    /// no kernel is present here. Saying so is part of the closure rather than
    /// a hole in it.
    ///
    /// What IS checkable is the half this crate owns: that the class is reached
    /// by every op except the one named, and by exactly that set. Swept over
    /// the whole 16-bit op space for the same reason the ethertype leg above is
    /// — an enumeration by hand is what item 248 says was never done, and doing
    /// it by hand missed a member one screen up.
    #[test]
    fn every_vsock_op_but_one_is_furniture() {
        let mut carried: Vec<u16> = Vec::new();
        for op in 0u16..=u16::MAX {
            let mut rec = vec![0u8; 32];
            rec[24..26].copy_from_slice(&op.to_le_bytes());
            rec.extend_from_slice(&[0u8; 16]);
            if decapsulate(LINKTYPE_VSOCK, 0, &rec) != Err(SkipReason::VsockNonPayload(op)) {
                carried.push(op);
            }
        }
        assert_eq!(
            carried,
            vec![AF_VSOCK_OP_PAYLOAD],
            "exactly one vsock op leaves the furniture arm, and it is the one \
             the kernel header says carries data. A second here is an op this \
             build started reading; none at all means the arm swallowed \
             everything"
        );
    }

    // ---- item 260: GRETAP -- a GRE tunnel whose payload is a whole frame ---
    //
    // R311y864 opened GRE and stopped at the ethertype, naming `0x6558`
    // (Transparent Ethernet Bridging) rather than half-opening it. The reason
    // it named it instead is the trap the second leg below pins: TEB's body
    // re-enters at the LINK layer, and the link layer already has two arms.

    /// Ethernet + IPv4 carrying an arbitrary protocol number.
    ///
    /// The carrier is addressed `10.0.0.x`, distinct from every inner address
    /// these legs use, so a flow keyed by the WRONG header is visible as a
    /// wrong address rather than only as a wrong count.
    fn eth_ipv4_carrier(proto: u8, body: &[u8]) -> Vec<u8> {
        let mut ip = Vec::new();
        ip.push(0x45);
        ip.push(0);
        ip.extend_from_slice(&((20 + body.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.push(64);
        ip.push(proto);
        ip.extend_from_slice(&0u16.to_be_bytes());
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(body);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        eth.extend_from_slice(&ip);
        eth
    }

    /// A GRE header with no optional fields, wrapping `body`.
    fn gre_no_options(protocol_type: u16, body: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8, 0];
        out.extend_from_slice(&protocol_type.to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// THE GAP. GRETAP is what a cloud overlay puts a session inside, and its
    /// payload is a whole Ethernet frame rather than one more turn of the IP
    /// walk. Before this the capture reported `GRE payload ethertype(s) not
    /// walked: 0x6558` and zero flows.
    ///
    /// The inner addresses are asserted, not merely the arm: a link strip that
    /// lands a few bytes off does not error, it decodes a plausible flow out of
    /// the middle of the frame.
    #[test]
    fn zenoh_inside_a_gretap_tunnel_is_read() {
        let inner = eth_ipv4_udp([192, 168, 0, 1], 7447, [192, 168, 0, 2], 40000, b"zenoh");
        let pkt = eth_ipv4_carrier(IP_PROTO_GRE, &gre_no_options(ETHERTYPE_TEB, &inner));
        match decapsulate(LINKTYPE_ETHERNET, 3, &pkt) {
            Ok(Transport::Udp(d)) => {
                assert_eq!(d.payload, b"zenoh");
                assert_eq!(d.packet_index, 3);
                let mut ends = vec![d.flow.low.addr().to_vec(), d.flow.high.addr().to_vec()];
                ends.sort();
                assert_eq!(
                    ends,
                    vec![vec![192, 168, 0, 1], vec![192, 168, 0, 2]],
                    "keyed by the INNER header, never by the carrier's 10.0.0.x"
                );
            }
            other => panic!("GRETAP must be read to its transport, got {other:?}"),
        }
    }

    /// Item 474 — the tunnelled frame carries VLAN tags, which for GRETAP is
    /// the ORDINARY shape and not the exotic one: an overlay segment is what a
    /// tag is FOR, so a tunnel whose inner frame is untagged is the special
    /// case this file was otherwise the only witness of.
    ///
    /// It already works, because the inner frame goes through the same
    /// `strip_link` the capture's own frames do — and that is precisely why it
    /// needs a leg rather than why it does not. What item 260 bought is that
    /// there is ONE link-layer door; a door nobody drives a tagged frame
    /// through is a door whose tag walk can be deleted without a red, and the
    /// tunnel is where nobody would look.
    ///
    /// Both tag shapes, for the reason `vlan_and_qinq_tags_are_walked` drives
    /// both: a walk that consumed exactly one tag would pass the single-tag leg
    /// and land inside the QinQ frame's header.
    #[test]
    fn a_gretap_frames_vlan_tags_are_walked_inside_the_tunnel() {
        let plain = eth_ipv4_udp([192, 168, 0, 1], 7447, [192, 168, 0, 2], 40000, b"tagged");
        for tags in [vec![ETHERTYPE_VLAN], vec![ETHERTYPE_QINQ, ETHERTYPE_VLAN]] {
            let mut inner: Vec<u8> = plain[..12].to_vec();
            for t in &tags {
                inner.extend_from_slice(&t.to_be_bytes());
                inner.extend_from_slice(&[0x00, 0x64]); // VID 100
            }
            inner.extend_from_slice(&plain[12..]);

            let pkt = eth_ipv4_carrier(IP_PROTO_GRE, &gre_no_options(ETHERTYPE_TEB, &inner));
            match decapsulate(LINKTYPE_ETHERNET, 0, &pkt) {
                Ok(Transport::Udp(d)) => {
                    assert_eq!(d.payload, b"tagged", "{tags:?} inside the tunnel");
                    let mut ends = vec![d.flow.low.addr().to_vec(), d.flow.high.addr().to_vec()];
                    ends.sort();
                    assert_eq!(
                        ends,
                        vec![vec![192, 168, 0, 1], vec![192, 168, 0, 2]],
                        "{tags:?}: keyed by the inner header, not the carrier's"
                    );
                }
                other => panic!("{tags:?}: GRETAP must be read, got {other:?}"),
            }
        }
    }

    /// THE TRAP, and the reason R311y864 named the ethertype rather than
    /// half-opening it.
    ///
    /// [`decapsulate`] tries [`strip_raweth`] BEFORE [`strip_link`], so an
    /// inner frame handed only to `strip_link` would send a zenoh-pico raweth
    /// frame inside the tunnel to `NotIp` — furniture — while the identical
    /// frame outside it reaches its own arm. That is R311y863's "two doors"
    /// defect regenerated one carrier down, so the two are asserted EQUAL
    /// rather than each asserted separately: a leg that only checked the
    /// tunnelled frame would pass against a second, diverging door.
    ///
    /// ⚠ ITEM 252 SPLIT THAT EQUALITY, AND THE SPLIT IS THE POINT. This leg
    /// asserted the two whole `Transport` values were the same, which was the
    /// right claim about the PARSE and the wrong one about the packet: the
    /// tunnelled frame really did arrive somewhere else, and a reading in which
    /// that is invisible is exactly the defect item 252 names. So the equality
    /// is now taken over everything the link layer produced — flow, direction,
    /// payload, packet index, checksums — and the carrier is asserted to be the
    /// ONE thing that differs. A test that had kept the whole-value equality
    /// would have been a green assertion that the defect must stay.
    #[test]
    fn a_pico_raweth_frame_reads_the_same_inside_a_gretap_tunnel_as_outside() {
        use wz_session_core::raweth_link::DEFAULT_ETHTYPE;
        let smac = [0x30, 0x03, 0xc8, 0x37, 0x25, 0xa1];
        let dmac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let bare = raweth_frame(smac, dmac, DEFAULT_ETHTYPE, b"zenoh-batch");
        let tunnelled = eth_ipv4_carrier(IP_PROTO_GRE, &gre_no_options(ETHERTYPE_TEB, &bare));

        let outside = decapsulate(LINKTYPE_ETHERNET, 7, &bare);
        let inside = decapsulate(LINKTYPE_ETHERNET, 7, &tunnelled);
        let (Ok(Transport::RawEth(out)), Ok(Transport::RawEth(inn))) = (&outside, &inside) else {
            panic!("both must be raweth datagrams: {outside:?} / {inside:?}");
        };
        // Everything the LINK layer decided, which is what "one door" means.
        assert_eq!(
            (
                out.flow,
                out.from_low,
                &out.payload,
                out.packet_index,
                out.checksums
            ),
            (
                inn.flow,
                inn.from_low,
                &inn.payload,
                inn.packet_index,
                inn.checksums
            ),
            "the tunnel must not become a second door onto the link layer"
        );
        assert_eq!(inn.payload, b"zenoh-batch");
        // And the ONE difference, asserted from both sides so neither "the
        // tunnel vanished" nor "the bare frame grew one" can pass.
        assert!(
            out.tunnel.is_empty(),
            "a frame on the wire arrived through no carrier"
        );
        assert_eq!(
            inn.tunnel.hops().len(),
            1,
            "and the tunnelled one through exactly the GRE carrier"
        );
        assert_eq!(inn.tunnel.hops()[0].proto, IP_PROTO_GRE);
        assert_eq!(inn.tunnel.hops()[0].src.addr(), &[10, 0, 0, 1]);
        assert_eq!(inn.tunnel.hops()[0].dst.addr(), &[10, 0, 0, 2]);
    }

    /// CONTROL. An ethertype this reader genuinely does not walk is still
    /// named by its number, so opening TEB did not open everything.
    #[test]
    fn a_gre_payload_ethertype_that_is_not_teb_is_still_named() {
        const ETHERTYPE_MPLS: u16 = 0x8847;
        let pkt = eth_ipv4_carrier(IP_PROTO_GRE, &gre_no_options(ETHERTYPE_MPLS, &[0u8; 32]));
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &pkt),
            Err(SkipReason::GrePayload(ETHERTYPE_MPLS)),
        );
    }

    /// CONTROL. A TEB frame whose own ethertype is neither IP nor raweth is
    /// `NotIp` — the same answer the identical frame gets outside a tunnel,
    /// which is the invariant the trap above is about.
    #[test]
    fn a_gretap_frame_carrying_neither_ip_nor_raweth_is_not_ip() {
        let mut inner = vec![0u8; 12];
        inner.extend_from_slice(&0x0806u16.to_be_bytes()); // ARP
        inner.extend_from_slice(&[0u8; 28]);
        let pkt = eth_ipv4_carrier(IP_PROTO_GRE, &gre_no_options(ETHERTYPE_TEB, &inner));
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &pkt),
            decapsulate(LINKTYPE_ETHERNET, 0, &inner),
            "inside the tunnel and outside it must classify identically"
        );
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &pkt),
            Err(SkipReason::NotIp)
        );
    }

    // ---- R311y597: the IPv6 leg, which had NO tests at all ----------------
    //
    // That absence is the finding, not a footnote. `strip_ipv6` is reachable
    // from all four link types `strip_link` handles, and every one of its legs
    // was unwitnessed — which is how a branch that refused UDP survived the
    // round that added UDP support to the IPv4 side.

    /// Ethernet + IPv6 + an ARBITRARY next-header, so a leg can aim at the
    /// classification directly. `body` is placed after the 40-byte fixed
    /// header with `payload_len` set to its length, which is what a packet
    /// with no extension chain looks like.
    fn eth_ipv6(src: [u8; 16], dst: [u8; 16], next_header: u8, body: &[u8]) -> Vec<u8> {
        let mut ip = Vec::new();
        ip.extend_from_slice(&0x6000_0000u32.to_be_bytes()); // version 6
        ip.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ip.push(next_header);
        ip.push(64); // hop limit
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(body);

        let mut eth = vec![0x02; 12];
        eth.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        eth.extend_from_slice(&ip);
        eth
    }

    fn udp_body(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend_from_slice(&sport.to_be_bytes());
        udp.extend_from_slice(&dport.to_be_bytes());
        udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes()); // checksum (unverified)
        udp.extend_from_slice(payload);
        udp
    }

    const V6_A: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
    const V6_B: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];

    /// THE DEFECT. An IPv6 UDP datagram must reach the UDP arm. Before
    /// R311y597 this returned `Ipv6ExtensionChain(17)`, so IPv6 multicast
    /// scouting and IPv6 UDP unicast links were invisible to a capture.
    #[test]
    fn an_ipv6_udp_datagram_reaches_the_udp_arm() {
        let pkt = eth_ipv6(V6_A, V6_B, IP_PROTO_UDP, &udp_body(7447, 7447, b"scout"));
        match decapsulate(LINKTYPE_ETHERNET, 5, &pkt) {
            Ok(Transport::Udp(d)) => {
                assert_eq!(d.payload, b"scout");
                assert_eq!(d.packet_index, 5);
                assert_eq!(d.flow.low.addr(), &V6_A);
                assert_eq!(d.flow.low.port, 7447);
            }
            other => panic!("expected an IPv6 datagram, got {other:?}"),
        }
    }

    /// The TCP leg the old branch did allow — kept so the fix is shown not to
    /// have traded one protocol for the other.
    #[test]
    fn an_ipv6_tcp_segment_still_reaches_the_tcp_arm() {
        let pkt = eth_ipv6(
            V6_A,
            V6_B,
            IP_PROTO_TCP,
            &tcp_body(7447, 40000, 99, 0x18, b"hi"),
        );
        let seg = tcp(LINKTYPE_ETHERNET, 0, &pkt).expect("decapsulate");
        assert_eq!(seg.payload, b"hi");
        assert_eq!(seg.seq, 99);
    }

    /// A bare TCP header + body, for the tests that build what sits BEHIND an
    /// IPv6 extension chain. Extracted from the test above rather than written
    /// twice: a chain-walk test whose TCP fixture differs from the no-chain
    /// one's proves less than it looks like, because a difference in the
    /// fixture and a difference in the walk are then indistinguishable.
    fn tcp_body(sport: u16, dport: u16, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&sport.to_be_bytes());
        out.extend_from_slice(&dport.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // ack
        out.push(5 << 4); // data offset, no options
        out.push(flags);
        out.extend_from_slice(&0xFFFFu16.to_be_bytes()); // window
        out.extend_from_slice(&0u16.to_be_bytes()); // checksum, unverified
        out.extend_from_slice(&0u16.to_be_bytes()); // urgent
        out.extend_from_slice(payload);
        out
    }

    /// R311y603 — the extension headers that genuinely CANNOT be walked still
    /// refuse, and the reason still carries the header's own number.
    ///
    /// This list shrank from eleven to three in the round that added the walk,
    /// and the shrink is the deliverable rather than a test being relaxed: ESP
    /// (50) encrypts everything after it, and 253 / 254 are reserved for
    /// experimentation with no length a reader may assume. Those three are
    /// LIMITS. The other eight were WORK, and the tests below do it.
    #[test]
    fn an_unwalkable_ipv6_extension_header_is_still_refused_by_name() {
        for ext in [50u8, 253, 254] {
            let pkt = eth_ipv6(V6_A, V6_B, ext, b"whatever");
            assert_eq!(
                decapsulate(LINKTYPE_ETHERNET, 0, &pkt),
                Err(SkipReason::Ipv6ExtensionChain(ext)),
                "next-header {ext} cannot be walked and must be named as such",
            );
        }
    }

    /// THE ONE THAT MATTERS. Every walkable extension header must land the
    /// walk on the TCP segment behind it — a zenoh session over IPv6 with a
    /// Hop-by-Hop option present produced a dissection with no messages, and
    /// nothing said why beyond naming the header.
    ///
    /// Each header is built with a REAL length field rather than padding,
    /// because the failure mode of a chain walker is landing a few bytes off:
    /// an off-by-N would not error, it would decode a different flow out of
    /// the middle of the payload. Asserting the recovered ports and body is
    /// what catches that; asserting only "not an error" would not.
    #[test]
    fn every_walkable_ipv6_extension_header_is_stepped_over_to_the_transport() {
        // The (len+1)*8 family: Hop-by-Hop, Routing, Destination Options,
        // Mobility, HIP, Shim6.
        for ext in [0u8, 43, 60, 135, 139, 140] {
            let mut chain = alloc::vec![0u8; 8];
            chain[0] = IP_PROTO_TCP;
            chain[1] = 0; // (0 + 1) * 8 = this 8-byte header
            chain.extend_from_slice(&tcp_body(7447, 40000, 99, 0x18, b"hi"));
            let pkt = eth_ipv6(V6_A, V6_B, ext, &chain);
            let seg = tcp(LINKTYPE_ETHERNET, 0, &pkt)
                .unwrap_or_else(|e| panic!("next-header {ext} must be walked, got {e:?}"));
            assert_eq!(seg.payload, b"hi", "walked to the wrong offset for {ext}");
            assert_eq!(seg.seq, 99);
        }
    }

    /// The Authentication Header measures in 4-byte units counted from 2, not
    /// in 8-byte units counted from 1. Reading it with the common formula lands
    /// the walk inside the payload, so it gets its own leg with a length the
    /// two rules disagree about: `len = 1` means 12 bytes by AH's rule and 16
    /// by the common one.
    #[test]
    fn the_authentication_header_uses_its_own_length_rule() {
        let mut chain = alloc::vec![0u8; 12];
        chain[0] = IP_PROTO_TCP;
        chain[1] = 1; // (1 + 2) * 4 = 12
        chain.extend_from_slice(&tcp_body(7447, 40000, 7, 0x18, b"ah"));
        let pkt = eth_ipv6(V6_A, V6_B, 51, &chain);
        let seg = tcp(LINKTYPE_ETHERNET, 0, &pkt).expect("AH must be walked");
        assert_eq!(seg.payload, b"ah");
        assert_eq!(seg.seq, 7);
    }

    /// Every piece of a fragmented IPv6 datagram is reported as a piece —
    /// INCLUDING the first, which is the leg this test used to get wrong.
    ///
    /// R311y606. The old shape walked the first fragment through to TCP and
    /// asserted its payload, which is the silent-truncation defect stated as an
    /// expectation: `f1` was a PREFIX of that segment, and delivering it
    /// advanced the stream by less than the sender sent. The fix is that offset
    /// zero with M set is a fragment like any other.
    #[test]
    fn every_ipv6_fragment_is_reported_as_a_piece() {
        let mut first = alloc::vec![0u8; 8];
        first[0] = IP_PROTO_TCP;
        first[2..4].copy_from_slice(&0x0001u16.to_be_bytes()); // offset 0, M set
        first[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        first.extend_from_slice(&tcp_body(7447, 40000, 5, 0x18, b"f1"));
        let piece = fragment(LINKTYPE_ETHERNET, 0, &eth_ipv6(V6_A, V6_B, 44, &first));
        assert_eq!(piece.info.offset, 0);
        assert!(piece.info.more, "M is set, so this is not the last piece");
        assert_eq!(piece.info.ident, 0xDEAD_BEEF);
        assert_eq!(piece.proto, IP_PROTO_TCP);
        // The piece's bytes are the TCP header and its prefix — carried, not
        // parsed. Parsing them here is exactly what used to happen.
        assert_eq!(&piece.payload[20..], b"f1");

        let mut later = alloc::vec![0u8; 8];
        later[0] = IP_PROTO_TCP;
        later[2..4].copy_from_slice(&(64u16 << 3).to_be_bytes());
        later[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        let piece = fragment(LINKTYPE_ETHERNET, 0, &eth_ipv6(V6_A, V6_B, 44, &later));
        assert_eq!(piece.info.offset, 512);
        assert!(!piece.info.more);
        assert_eq!(
            piece.info.ident, 0xDEAD_BEEF,
            "both pieces must key to one datagram"
        );
    }

    /// Two headers in a row, because a walker that handles one can still be a
    /// walker that does not loop.
    #[test]
    fn a_chain_of_two_headers_reaches_the_transport() {
        let mut second = alloc::vec![0u8; 8];
        second[0] = IP_PROTO_TCP;
        second.extend_from_slice(&tcp_body(7447, 40000, 11, 0x18, b"two"));
        let mut first = alloc::vec![0u8; 8];
        first[0] = 60; // -> Destination Options
        first.extend_from_slice(&second);
        let seg = tcp(LINKTYPE_ETHERNET, 0, &eth_ipv6(V6_A, V6_B, 0, &first))
            .expect("hop-by-hop then destination-options then TCP");
        assert_eq!(seg.payload, b"two");
        assert_eq!(seg.seq, 11);
    }

    /// A chain that never terminates must stop at the bound and NAME the
    /// header it stopped on, not loop. Each header points at another of its own
    /// kind, so the only thing that ends this walk is the cap.
    #[test]
    fn an_endless_chain_stops_at_the_bound_instead_of_looping() {
        let mut chain = Vec::new();
        for _ in 0..IPV6_MAX_EXT_HEADERS + 2 {
            chain.extend_from_slice(&[60u8, 0, 0, 0, 0, 0, 0, 0]);
        }
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &eth_ipv6(V6_A, V6_B, 60, &chain)),
            Err(SkipReason::Ipv6ExtensionChain(60)),
        );
    }

    /// THE SECOND FAILURE OF THE SAME LINE, and the reason "also allow UDP"
    /// would have been the wrong fix. A non-transport upper-layer protocol
    /// (ICMPv6 here) is not an extension header, and reporting it as an
    /// unwalked chain points a reader at building a chain walker that would
    /// not have helped. It must classify exactly as the IPv4 path does.
    #[test]
    fn a_non_transport_ipv6_protocol_is_not_reported_as_an_extension_chain() {
        const IP_PROTO_ICMPV6: u8 = 58;
        let pkt = eth_ipv6(V6_A, V6_B, IP_PROTO_ICMPV6, b"\x80\x00\x00\x00");
        assert_eq!(
            decapsulate(LINKTYPE_ETHERNET, 0, &pkt),
            Err(SkipReason::NotTransport(IP_PROTO_ICMPV6)),
        );
    }

    /// IPv6 has no header checksum and no `total_length` — only `payload_len`,
    /// counted from the END of the fixed header rather than from its start.
    /// Getting that origin wrong reads link padding as payload, so it is
    /// pinned the same way the IPv4 leg pins its own.
    #[test]
    fn ipv6_payload_len_is_measured_from_the_end_of_the_fixed_header() {
        let mut pkt = eth_ipv6(V6_A, V6_B, IP_PROTO_UDP, &udp_body(1, 2, b"abc"));
        while pkt.len() < 60 {
            pkt.push(0); // the pad a real NIC adds
        }
        match decapsulate(LINKTYPE_ETHERNET, 0, &pkt) {
            Ok(Transport::Udp(d)) => assert_eq!(d.payload, b"abc"),
            other => panic!("expected a datagram, got {other:?}"),
        }
    }

    /// A loopback frame: the four-byte address-family word this DLT puts in
    /// front of the packet, in the byte order asked for.
    ///
    /// `af` is passed as a NUMBER rather than a named constant so a leg can
    /// build a word this build must refuse; the production table is this
    /// module's own and a fixture that shared it would agree with the parser
    /// by construction.
    fn loopback_frame(af: u32, big_endian: bool, ip: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&if big_endian {
            af.to_be_bytes()
        } else {
            af.to_le_bytes()
        });
        out.extend_from_slice(ip);
        out
    }

    /// R311y893 — a capture taken on a BSD / macOS **loopback** interface.
    ///
    /// # The defect this ends
    ///
    /// `tcpdump -i lo0` on macOS, and the same on any BSD, writes
    /// `LINKTYPE_NULL` (`/usr/include/pcap/dlt.h:62`, "BSD loopback
    /// encapsulation"); OpenBSD writes `LINKTYPE_LOOP`
    /// (`/usr/include/pcap/dlt.h:279-289`). Neither was in this table, so every
    /// packet of such a capture came back `UnsupportedLinkType` and the
    /// dissection was EMPTY — the reading R311y603 called an under-promise for
    /// `vsock`, landing here on the most ordinary way there is to capture a
    /// local zenoh session.
    ///
    /// # Why both byte orders, and where the table came from
    ///
    /// `LINKTYPE_NULL`'s word is in the byte order of the machine that SAVED
    /// the capture, so a reader may not assume its own. `LINKTYPE_LOOP` is
    /// specified as network order (`dlt.h:280`) and is read the same way
    /// anyway, because `tcpdump` accepts either on both — MEASURED, not
    /// remembered: `tcpdump 4.99.4` was handed files carrying AF 2, 10, 17, 24,
    /// 26, 28 and 30 in both orders, and read 2 as IPv4 and 24 / 28 / 30 as
    /// IPv6 in either order while refusing 10, 17 and 26 outright.
    #[test]
    fn a_bsd_loopback_capture_is_read_in_either_byte_order() {
        const AF_INET_WORD: u32 = 2;
        let v4 = eth_ipv4_udp([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, b"scout")[14..].to_vec();
        for link_type in [LINKTYPE_NULL, LINKTYPE_LOOP] {
            for big_endian in [false, true] {
                let pkt = loopback_frame(AF_INET_WORD, big_endian, &v4);
                match decapsulate(link_type, 3, &pkt) {
                    Ok(Transport::Udp(d)) => {
                        assert_eq!(d.payload, b"scout", "dlt {link_type} be={big_endian}");
                        assert_eq!(d.packet_index, 3);
                        assert_eq!(d.flow.high.port, 7447);
                    }
                    other => panic!("dlt {link_type} be={big_endian}: {other:?}"),
                }
            }
        }
    }

    /// The v6 half, and the three address families that mean it.
    ///
    /// `AF_INET6` is the one number that is NOT portable — 24 on
    /// NetBSD / OpenBSD, 28 on FreeBSD, 30 on Darwin — which is why it is a
    /// table rather than a constant, and why this leg drives every member.
    #[test]
    fn every_bsd_af_inet6_spelling_reaches_the_v6_walk() {
        let v6 =
            eth_ipv6(V6_A, V6_B, IP_PROTO_UDP, &udp_body(43210, 7447, b"scout"))[14..].to_vec();
        for af in [24u32, 28, 30] {
            for big_endian in [false, true] {
                let pkt = loopback_frame(af, big_endian, &v6);
                match decapsulate(LINKTYPE_NULL, 0, &pkt) {
                    Ok(Transport::Udp(d)) => {
                        assert_eq!(d.payload, b"scout", "af {af} be={big_endian}");
                        assert_eq!(d.flow.low.addr(), &V6_A, "af {af}: the v6 walk ran");
                    }
                    other => panic!("af {af} be={big_endian}: {other:?}"),
                }
            }
        }
    }

    /// THE CONTROL, and what stops this from being "skip four bytes".
    ///
    /// An implementation that discarded the word and read what follows as IPv4
    /// would pass both legs above. These three say the word is READ: a family
    /// this encapsulation does not carry is refused BY NAME, and a v4 body
    /// under a v6 word is refused rather than walked as the family it happens
    /// to look like — a reader may not overrule the header it was handed, the
    /// same rule the Ethernet arm follows for an ethertype.
    #[test]
    fn a_loopback_word_this_build_does_not_know_is_refused_by_name() {
        let v4 = eth_ipv4_udp([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, b"scout")[14..].to_vec();
        // 10 is Linux's `AF_INET6` and 17 is BSD's `AF_ROUTE`; `tcpdump` reads
        // neither, and Linux never writes this encapsulation at all.
        for af in [10u32, 17, 26] {
            assert_eq!(
                decapsulate(LINKTYPE_NULL, 0, &loopback_frame(af, false, &v4)),
                Err(SkipReason::NotIp),
                "af {af} must be refused, not guessed"
            );
        }
        // The word says IPv6; the body is IPv4. Nothing may come back whole.
        assert!(
            !matches!(
                decapsulate(LINKTYPE_NULL, 0, &loopback_frame(30, false, &v4)),
                Ok(Transport::Udp(_) | Transport::Tcp(_))
            ),
            "a v4 body under a v6 word must not decode"
        );
        // And a frame with no room for the word at all.
        assert_eq!(
            decapsulate(LINKTYPE_NULL, 0, &[0u8, 0, 0]),
            Err(SkipReason::Truncated)
        );
    }
}
