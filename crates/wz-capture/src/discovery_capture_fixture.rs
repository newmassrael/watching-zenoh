// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt item 808 — the tracked discovery capture: a Scout and the
//! Hello that answers it, over IPv4 and over IPv6, and the oracle that keeps it
//! a function of the encoders.
//!
//! # What a consumer could not do before this file
//!
//! The dissection has named `Scout` and `Hello` rows since document revision 10,
//! and a consumer that picks its badges by the transport message WORD can only
//! be graded against a decoder's real output if it has a capture to read. The
//! datagram fixtures in this crate are built inside `#[cfg(test)]` code, which a
//! C consumer cannot point at by path, and copying their bytes into the
//! consumer's tree goes stale the moment the pin moves.
//!
//! # What the file holds, and why it is two exchanges
//!
//! Each exchange is a Scout sent to the scouting group and the Hello that came
//! back to the Scout's sender, which is the only shape a Hello has: a node
//! answers the asker, from a socket of its own, never to the group. The second
//! exchange is IPv6, whose group is a different rule (`ff00::/8`) and whose flow
//! orders its ends by sixteen bytes rather than four.
//!
//! The two numbers a scouting message shares with the transport namespace are
//! the point of putting both on one file. `S_MID_SCOUT` is `0x01`, which is an
//! `Init` on a session, and `S_MID_HELLO` is `0x02`, an `Open`; with the locator
//! flag the Hello's header is `0x22`, an `Open` with its ack bit. A reader that
//! picked the namespace by the byte would read every packet here as a handshake
//! message. What decides it is the destination (a multicast destination carries
//! no handshake, so `0x01` there is a Scout) and, for the unicast Hello, the
//! memory that its destination sent a Scout first. Both halves of that decision
//! are walked by this file, and the consumer-surface test below also reads the
//! two Hellos WITHOUT their Scouts to show the file is what steers the answer.
//!
//! # How the bytes are made, and how that is CHECKED
//!
//! * the Scout is the SCOUT codec's `encode_to_vec` behind the header byte, in
//!   the order `scouting_glue`'s `scout_emit` does it (version, the `what`
//!   mask, then the `I` flag, the length nibble and the zid when the scouter has
//!   one). That action lives in `wz-runtime-tokio`, which depends on this crate,
//!   so it cannot be called from here; the recipe is repeated, and the
//!   byte-layout test in that module (`scout_emit_stages_framed_datagram`) is
//!   the layout the comparison below pins the result against;
//! * the Hello is not laid out here at all: it is the output of
//!   `scout_responder::answer_scout_from` over the Scout, with the asker's
//!   address, exactly as the responder loop answers. So the Hello is a function
//!   of the Scout in the file, and the checks below recompute it from the bytes
//!   the file holds;
//! * the frames are an Ethernet header (the group's multicast MAC derived by
//!   RFC 1112 section 6.4 and RFC 2464 section 7), the IP header, and a UDP
//!   header whose checksum is computed. IPv6 forbids a zero UDP checksum
//!   (RFC 8200 section 8.1), so the sample must not carry one;
//! * the container is `crate::pcap::write`.
//!
//! `the_tracked_discovery_capture_is_byte_identical_to_what_wz_emits` rebuilds
//! all of it and compares the whole file. Code spans and not intra-doc links, as
//! in the sibling fixtures: the module is `#[cfg(test)]`.

use alloc::string::ToString;
use alloc::vec::Vec;

use wz_codecs::whatami::WhatAmI;
use wz_session_core::scout_responder::{answer_scout_from, ResponderIdentity, ScoutDecision};
use wz_session_core::wire_const::S_MID_SCOUT;

use crate::link::LINKTYPE_ETHERNET;

/// The tracked capture, read at COMPILE time, as the sibling oracles read theirs.
const TRACKED: &[u8] = include_bytes!("../../../captures/scout-and-hello-ipv4-ipv6.pcap");

/// Where it lives, for the refusals below to name.
const TRACKED_PATH: &str = "captures/scout-and-hello-ipv4-ipv6.pcap";

/// Microseconds between packets: a deterministic timeline, no wall clock.
const PACKET_SPACING_MICROS: u32 = 1_000;

/// The protocol version byte every scouting fixture in this tree carries.
const VERSION: u8 = 0x09;

/// The scouting group's port, for both families.
const SCOUT_PORT: u16 = 7446;

/// The asker's ephemeral source port, in both exchanges.
const ASKER_PORT: u16 = 43210;

/// The port a responder's reply leaves from. Not the group's and not the
/// asker's: a reply comes from a socket of the responder's own, and its source
/// port is what lets a reader tell its two ends apart on a host-to-host flow.
const REPLY_PORT: u16 = 38117;

/// The IPv4 scouting group (`udp/224.0.0.224:7446`, zenoh's default scout
/// socket, the `zenoh-config` doc of `scouting/multicast/address`).
const GROUP_V4: [u8; 4] = [224, 0, 0, 224];

/// The IPv6 group of the second exchange. zenoh ships NO IPv6 default (searched
/// in `zenoh-config` and `zenoh` 1.10.1: the only default scout socket there is
/// the IPv4 one), so this is the link-local group the `wz-capture` IPv6 fixtures
/// already use, not a claim about an upstream address.
const GROUP_V6: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x24];

const ASKER_V4: [u8; 4] = [192, 168, 1, 5];
const RESPONDER_V4: [u8; 4] = [192, 168, 1, 9];
const ASKER_V6: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05];
const RESPONDER_V6: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09];

/// Locally administered unicast MACs, one per host.
const MAC_ASKER_V4: [u8; 6] = [0x02, 0, 0, 0, 0, 0x05];
const MAC_RESPONDER_V4: [u8; 6] = [0x02, 0, 0, 0, 0, 0x09];
const MAC_ASKER_V6: [u8; 6] = [0x02, 0, 0, 0, 0, 0x06];
const MAC_RESPONDER_V6: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];

/// The four nodes' ids: a scouter and a responder in each family, all distinct
/// so the node plane holds four nodes and a census that merged two would show.
const ZID_ASKER_V4: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
const ZID_RESPONDER_V4: [u8; 8] = [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8];
const ZID_ASKER_V6: [u8; 8] = [0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98];
const ZID_RESPONDER_V6: [u8; 8] = [0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8];

/// The locators each responder advertises. Two for the IPv4 one so a Hello with a
/// list is read as a list; the IPv6 one uses the documentation prefix
/// (RFC 3849) because a link-local address is not a locator a peer could dial.
const LOCATORS_V4: [&str; 2] = ["tcp/192.168.1.9:7447", "udp/192.168.1.9:7447"];
const LOCATORS_V6: [&str; 1] = ["tcp/[2001:db8::9]:7447"];

/// The roles a Scout asks for: routers and peers, the mask a peer that wants to
/// join a network sends.
fn what() -> u8 {
    WhatAmI::Router.to_api() | WhatAmI::Peer.to_api()
}

/// A Scout datagram naming `zid`, framed as the scouting window emits it.
fn scout_datagram(zid: &[u8]) -> Vec<u8> {
    let mut scout = wz_codecs::scout::Scout::new();
    scout.version = VERSION;
    scout.set_what(what());
    if !zid.is_empty() {
        scout.set_i(true);
        scout.set_zid_len_m1((zid.len() - 1) as u8);
        scout.zid = Some(zid);
    }
    let body = scout.encode_to_vec();
    let mut datagram = Vec::with_capacity(1 + body.len());
    datagram.push(S_MID_SCOUT);
    datagram.extend_from_slice(&body);
    datagram
}

/// A responder's identity: a peer with `zid` advertising `locators`.
fn identity(zid: &[u8], locators: &[&str]) -> ResponderIdentity {
    ResponderIdentity::try_new(
        VERSION,
        WhatAmI::Peer,
        zid.to_vec(),
        locators.iter().map(|l| l.to_string()).collect(),
    )
    .expect("a fixture identity is well-formed")
}

/// The Hello `identity` sends back for `scout`, as the responder loop decides it.
fn hello_for(identity: &ResponderIdentity, scout: &[u8], asker: core::net::IpAddr) -> Vec<u8> {
    match answer_scout_from(identity, scout, Some(asker)) {
        ScoutDecision::Answer(hello) => hello,
        ScoutDecision::Ignored(why) => {
            panic!("the responder must answer the fixture's Scout, and ignored it: {why:?}")
        }
    }
}

/// The multicast MAC of an IPv4 group: `01:00:5e` and the low 23 bits of the
/// address (RFC 1112 section 6.4).
fn multicast_mac_v4(group: [u8; 4]) -> [u8; 6] {
    [0x01, 0x00, 0x5e, group[1] & 0x7f, group[2], group[3]]
}

/// The multicast MAC of an IPv6 group: `33:33` and the low 32 bits of the
/// address (RFC 2464 section 7).
fn multicast_mac_v6(group: [u8; 16]) -> [u8; 6] {
    [0x33, 0x33, group[12], group[13], group[14], group[15]]
}

/// An Ethernet II header.
fn ethernet(dst: [u8; 6], src: [u8; 6], ethertype: u16) -> Vec<u8> {
    let mut eth = Vec::new();
    eth.extend_from_slice(&dst);
    eth.extend_from_slice(&src);
    eth.extend_from_slice(&ethertype.to_be_bytes());
    eth
}

/// The UDP header and `payload`, checksum left zero for the caller to fill.
fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut udp = Vec::new();
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    udp
}

/// Pad a frame to the 60-byte minimum a NIC puts on the wire, as the sibling
/// captures do: a datagram shorter than that arrives with trailing zeros that
/// the IP length says are not part of it.
fn pad_to_minimum_frame(mut frame: Vec<u8>) -> Vec<u8> {
    while frame.len() < 60 {
        frame.push(0);
    }
    frame
}

/// Ethernet, IPv4 and UDP, with both checksums computed.
fn frame_v4(
    macs: ([u8; 6], [u8; 6]),
    src: ([u8; 4], u16),
    dst: ([u8; 4], u16),
    payload: &[u8],
) -> Vec<u8> {
    let mut udp = udp(src.1, dst.1, payload);
    wz_packet_fixtures::fill_udp_checksum(src.0, dst.0, &mut udp);

    let mut ip = alloc::vec![0x45u8, 0];
    ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
    ip.extend_from_slice(&src.0);
    ip.extend_from_slice(&dst.0);
    wz_packet_fixtures::fill_ipv4_checksum(&mut ip);
    ip.extend_from_slice(&udp);

    let mut frame = ethernet(macs.0, macs.1, 0x0800);
    frame.extend_from_slice(&ip);
    pad_to_minimum_frame(frame)
}

/// Ethernet, IPv6 and UDP, with the UDP checksum computed over the RFC 8200
/// section 8.1 pseudo-header.
fn frame_v6(
    macs: ([u8; 6], [u8; 6]),
    src: ([u8; 16], u16),
    dst: ([u8; 16], u16),
    payload: &[u8],
) -> Vec<u8> {
    let mut udp = udp(src.1, dst.1, payload);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.0);
    pseudo.extend_from_slice(&dst.0);
    pseudo.extend_from_slice(&(udp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    let mut checksum = wz_packet_fixtures::ones_complement(&[&pseudo, &udp]);
    // A computed zero goes out as all ones: zero is the value for "no checksum".
    if checksum == 0 {
        checksum = 0xffff;
    }
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    let mut ip = alloc::vec![0x60u8, 0, 0, 0];
    ip.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    ip.extend_from_slice(&[17, 64]);
    ip.extend_from_slice(&src.0);
    ip.extend_from_slice(&dst.0);
    ip.extend_from_slice(&udp);

    let mut frame = ethernet(macs.0, macs.1, 0x86dd);
    frame.extend_from_slice(&ip);
    pad_to_minimum_frame(frame)
}

/// The four packets, in the order of the file: Scout and Hello over IPv4, then
/// Scout and Hello over IPv6.
fn packets() -> Vec<Vec<u8>> {
    let scout_v4 = scout_datagram(&ZID_ASKER_V4);
    let hello_v4 = hello_for(
        &identity(&ZID_RESPONDER_V4, &LOCATORS_V4),
        &scout_v4,
        core::net::IpAddr::from(ASKER_V4),
    );
    let scout_v6 = scout_datagram(&ZID_ASKER_V6);
    let hello_v6 = hello_for(
        &identity(&ZID_RESPONDER_V6, &LOCATORS_V6),
        &scout_v6,
        core::net::IpAddr::from(ASKER_V6),
    );
    alloc::vec![
        frame_v4(
            (multicast_mac_v4(GROUP_V4), MAC_ASKER_V4),
            (ASKER_V4, ASKER_PORT),
            (GROUP_V4, SCOUT_PORT),
            &scout_v4,
        ),
        frame_v4(
            (MAC_ASKER_V4, MAC_RESPONDER_V4),
            (RESPONDER_V4, REPLY_PORT),
            (ASKER_V4, ASKER_PORT),
            &hello_v4,
        ),
        frame_v6(
            (multicast_mac_v6(GROUP_V6), MAC_ASKER_V6),
            (ASKER_V6, ASKER_PORT),
            (GROUP_V6, SCOUT_PORT),
            &scout_v6,
        ),
        frame_v6(
            (MAC_ASKER_V6, MAC_RESPONDER_V6),
            (RESPONDER_V6, REPLY_PORT),
            (ASKER_V6, ASKER_PORT),
            &hello_v6,
        ),
    ]
}

/// Rebuild the whole file from the encoders.
fn rebuild() -> Vec<u8> {
    let packets = packets();
    let refs: Vec<(u32, u32, &[u8])> = packets
        .iter()
        .enumerate()
        .map(|(i, p)| (0u32, i as u32 * PACKET_SPACING_MICROS, p.as_slice()))
        .collect();
    crate::pcap::write(LINKTYPE_ETHERNET, &refs)
}

/// Rewrite the tracked file from `rebuild`. `#[ignore]`d: the REFRESHER, not a
/// check.
///
/// ```text
/// cargo test -p wz-capture --features dissect --lib \
///   refresh_the_tracked_discovery_capture -- --ignored
/// ```
#[test]
#[ignore = "REFRESHER, not a check: rewrites the tracked capture"]
fn refresh_the_tracked_discovery_capture() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(TRACKED_PATH);
    let bytes = rebuild();
    std::fs::write(&path, &bytes).unwrap_or_else(|e| panic!("writing {path:?}: {e}"));
    std::println!(
        "wrote {} byte(s) to {} — now re-run the suite to grade it",
        bytes.len(),
        TRACKED_PATH
    );
}

/// The tracked file IS what the encoders emit, byte for byte.
#[test]
fn the_tracked_discovery_capture_is_byte_identical_to_what_wz_emits() {
    let rebuilt = rebuild();
    assert_eq!(
        TRACKED.len(),
        rebuilt.len(),
        "{TRACKED_PATH} is {} byte(s) and the encoders emit {} — refresh it with \
         `cargo test -p wz-capture --features dissect --lib \
         refresh_the_tracked_discovery_capture -- --ignored` if an encoder \
         changed on purpose",
        TRACKED.len(),
        rebuilt.len()
    );
    if let Some(at) = TRACKED.iter().zip(rebuilt.iter()).position(|(a, b)| a != b) {
        panic!(
            "{TRACKED_PATH} first differs from what the encoders emit at byte {at}: \
             tracked {:#04x}, emitted {:#04x}. The file has been hand-edited, or an \
             encoder changed and the fixture was not refreshed.",
            TRACKED[at], rebuilt[at]
        );
    }
}

/// One packet of the tracked file, taken apart far enough to say who sent what
/// to whom. Read off the bytes with no help from the dissection, so what the
/// consumer-surface test later asks of the dissection is not asked of itself.
struct Seen {
    source: core::net::SocketAddr,
    destination: core::net::SocketAddr,
    datagram: Vec<u8>,
}

/// Take apart an Ethernet frame carrying UDP over IPv4 or IPv6.
fn take_apart(frame: &[u8]) -> Seen {
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    let (src, dst, udp): (IpAddr, IpAddr, &[u8]) = match (frame[12], frame[13]) {
        (0x08, 0x00) => {
            let total = usize::from(u16::from_be_bytes([frame[16], frame[17]]));
            let ip = &frame[14..14 + total];
            (
                IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15])),
                IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19])),
                &ip[20..],
            )
        }
        (0x86, 0xdd) => {
            let payload = usize::from(u16::from_be_bytes([frame[18], frame[19]]));
            let ip = &frame[14..14 + 40 + payload];
            let v6 = |at: usize| {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&ip[at..at + 16]);
                IpAddr::V6(Ipv6Addr::from(octets))
            };
            (v6(8), v6(24), &ip[40..])
        }
        other => panic!("a frame of ethertype {other:?} is not in this capture"),
    };
    let port = |at: usize| u16::from_be_bytes([udp[at], udp[at + 1]]);
    let length = usize::from(port(4));
    Seen {
        source: SocketAddr::new(src, port(0)),
        destination: SocketAddr::new(dst, port(2)),
        datagram: udp[8..length].to_vec(),
    }
}

/// The file holds the two exchanges it claims, each a Scout to the group and the
/// Hello that goes back to the Scout's sender.
///
/// Everything is read off the tracked bytes. The Hello of each exchange is then
/// COMPUTED from the Scout that file holds, by the responder's own decision, and
/// compared to the Hello that file holds: a Hello that did not answer this Scout
/// (a different version, a stale locator list, another node's id) would differ.
#[test]
fn the_tracked_discovery_capture_holds_the_exchanges_it_claims() {
    let file = crate::pcap::parse(TRACKED).expect("the tracked capture parses");
    assert_eq!(file.link_type, LINKTYPE_ETHERNET);
    assert_eq!(
        file.packets.len(),
        4,
        "a Scout and a Hello over IPv4, then the same over IPv6"
    );
    let seen: Vec<Seen> = file.packets.iter().map(|p| take_apart(&p.data)).collect();

    for (scout, hello, group, zid_asker, zid_responder, locators) in [
        (
            &seen[0],
            &seen[1],
            core::net::IpAddr::from(GROUP_V4),
            &ZID_ASKER_V4,
            &ZID_RESPONDER_V4,
            &LOCATORS_V4[..],
        ),
        (
            &seen[2],
            &seen[3],
            core::net::IpAddr::from(GROUP_V6),
            &ZID_ASKER_V6,
            &ZID_RESPONDER_V6,
            &LOCATORS_V6[..],
        ),
    ] {
        // The Scout goes to the group, and the group is multicast: the only
        // thing that makes its `0x01` a Scout and not an Init.
        assert_eq!(scout.destination.ip(), group, "the Scout goes to the group");
        assert_eq!(scout.destination.port(), SCOUT_PORT);
        assert!(scout.destination.ip().is_multicast());
        // The Hello goes back to the Scout's SENDER, unicast, and its source is
        // not the group.
        assert_eq!(
            hello.destination, scout.source,
            "the Hello answers the asker"
        );
        assert!(!hello.destination.ip().is_multicast());
        assert_ne!(
            hello.source, scout.destination,
            "the reply is not from the group"
        );

        // The Scout is the Scout codec's output: the header byte, the version,
        // the flags byte (`what`, the I bit, the zid length less one in the high
        // nibble) and the zid. The layout is the one `scouting_glue`'s own
        // `scout_emit_stages_framed_datagram` pins for the runtime.
        let cbyte = what() | 0x08 | (((zid_asker.len() - 1) as u8) << 4);
        let mut layout = alloc::vec![S_MID_SCOUT, VERSION, cbyte];
        layout.extend_from_slice(zid_asker);
        assert_eq!(
            scout.datagram, layout,
            "the Scout is [mid, version, flags, zid]"
        );

        // And the Hello is what the responder decides for THIS Scout.
        let expected = hello_for(
            &identity(zid_responder, locators),
            &scout.datagram,
            scout.source.ip(),
        );
        assert_eq!(
            hello.datagram, expected,
            "the Hello is the responder's answer to the Scout the file holds"
        );
        // Its header byte is the Hello MID with the locator flag, which is
        // numerically an Open with its ack bit: the overlap this file is for.
        assert_eq!(
            hello.datagram[0],
            wz_session_core::wire_const::S_MID_HELLO | wz_session_core::wire_const::FLAG_S_HELLO_L
        );
    }
}

/// The revision a census document declares for itself, read off its envelope.
#[cfg(feature = "dissect")]
fn census_revision(doc: &str) -> u32 {
    let key = "\"name\":\"census\",\"revision\":";
    let at = doc.find(key).expect("the census declares its revision") + key.len();
    let digits: alloc::string::String =
        doc[at..].chars().take_while(char::is_ascii_digit).collect();
    digits.parse().expect("the revision is a number")
}

/// The tracked file reaches the surfaces a consumer reads, and says what each of
/// the four datagrams is in the words a consumer selects on.
///
/// # What is asked of the dissection, and what that rules out
///
/// * every datagram lands in the SCOUTING list of its own flow and none in the
///   transport list: a multicast `0x01` read as a transport message is an
///   `Init`, and a unicast `0x22` is an `Open`, the two misreads the namespace
///   decision exists to refuse;
/// * the field document names the four rows `Scout`, `Hello`, `Scout`, `Hello`
///   in the scouting MID space, with none named `Init` or `Open`;
/// * the census document seats the zids: the four nodes, the Hellos' locators,
///   and, new at census revision 20, an `ends` row for each sender, which is
///   the only place the document says which END of a discovery flow a node sat
///   at. A Scout that carried no zid would seat nobody, so the two Scouts here
///   carry one and the rows prove it reached.
///
/// # The control
///
/// The two Hellos are then dissected WITHOUT the Scouts that asked for them. A
/// unicast `0x22` is an answer only to a node that was seen asking, so the file's
/// Scouts are what steer the Hellos into the scouting list; without them the same
/// bytes are not a Hello. A file whose Hellos read as Hellos on their own would
/// not be exercising that memory at all.
#[cfg(feature = "dissect")]
#[test]
fn the_tracked_discovery_capture_reaches_the_consumer_surface() {
    use crate::link::FlowEnd;
    use crate::node::ObservedEnd;

    let d = crate::Dissection::from_capture(TRACKED).expect("the tracked capture dissects");
    let flows = d.datagram_flows();
    assert_eq!(
        flows.len(),
        4,
        "each datagram has its own flow: no two share both endpoints"
    );
    let lists: Vec<(usize, usize)> = flows
        .iter()
        .map(|f| (f.frames.len(), f.scouting.len()))
        .collect();
    assert_eq!(
        lists,
        [(0, 1); 4],
        "every datagram is a SCOUTING message and none was read as a transport one"
    );
    let words: Vec<&'static str> = flows
        .iter()
        .map(|f| {
            f.scouting[0]
                .frame
                .as_ref()
                .expect("a scouting datagram decodes")
                .kind_name()
        })
        .collect();
    assert_eq!(words, ["Scout", "Hello", "Scout", "Hello"]);

    // The field document: the same words, as rows.
    let fields = crate::fields_json::fields_json(&d, TRACKED, None, None);
    for word in ["Scout", "Hello"] {
        let row = alloc::format!("\"name\":\"{word}\",\"fields\":");
        let entry =
            alloc::format!("\"carried\":[{{\"message\":\"{word}\",\"body\":null,\"start\":0,");
        assert_eq!(
            (fields.matches(&row).count(), fields.matches(&entry).count()),
            (2, 2),
            "two {word} rows, each read in the scouting MID space: {fields}"
        );
    }
    for misread in ["\"message\":\"Init\"", "\"message\":\"Open\""] {
        assert!(
            !fields.contains(misread),
            "{misread} is the transport reading of the same byte: {fields}"
        );
    }
    // Each row walks its zid as a `zid` field, spelled the way zenoh prints one
    // (the recipe every surface that names a zid shares), once per datagram.
    for zid in [
        ZID_ASKER_V4,
        ZID_RESPONDER_V4,
        ZID_ASKER_V6,
        ZID_RESPONDER_V6,
    ] {
        let field = alloc::format!(
            "\"kind\":\"zid\",\"value\":\"{}\"",
            wz_session_core::zid_hex::zid_to_zenoh_hex(&zid)
        );
        assert_eq!(fields.matches(&field).count(), 1, "{field} once: {fields}");
    }
    for locator in LOCATORS_V4.iter().chain(LOCATORS_V6.iter()) {
        let field = alloc::format!("\"kind\":\"text\",\"value\":\"{locator}\"");
        assert_eq!(fields.matches(&field).count(), 1, "{field} once: {fields}");
    }

    // The census: who is in the capture, and which end of its flow each sender
    // sat at.
    let census = crate::node::nodes(&d);
    let index_of = |zid: &[u8]| {
        census
            .nodes()
            .iter()
            .position(|n| n.zid == zid)
            .unwrap_or_else(|| panic!("the capture must name {zid:02x?}: {:?}", census.nodes()))
    };
    assert_eq!(
        census.nodes().len(),
        4,
        "a scouter and a responder per family"
    );
    // The ends are asserted against the flows' own endpoints, so which word each
    // sender gets is derived from where it sat and not written beside it.
    let endpoint = |flow: &crate::link::FlowKey, end: FlowEnd| match end {
        FlowEnd::Low => (flow.low.addr().to_vec(), flow.low.port),
        FlowEnd::High => (flow.high.addr().to_vec(), flow.high.port),
    };
    let expected = [
        (
            &ZID_ASKER_V4[..],
            FlowEnd::Low,
            ASKER_V4.to_vec(),
            ASKER_PORT,
        ),
        (
            &ZID_RESPONDER_V4[..],
            FlowEnd::High,
            RESPONDER_V4.to_vec(),
            REPLY_PORT,
        ),
        (
            &ZID_ASKER_V6[..],
            FlowEnd::Low,
            ASKER_V6.to_vec(),
            ASKER_PORT,
        ),
        (
            &ZID_RESPONDER_V6[..],
            FlowEnd::High,
            RESPONDER_V6.to_vec(),
            REPLY_PORT,
        ),
    ];
    let want: Vec<ObservedEnd> = expected
        .iter()
        .zip(flows)
        .map(|((zid, end, addr, port), flow)| {
            assert_eq!(
                endpoint(&flow.flow, *end),
                (addr.clone(), u32::from(*port)),
                "the sender sat at the {end:?} end of its flow"
            );
            ObservedEnd {
                node: index_of(zid),
                end: *end,
                flow: flow.flow,
            }
        })
        .collect();
    assert_eq!(census.ends(), want.as_slice(), "{:?}", census.ends());

    let doc = crate::census_json::census_json(&d);
    assert!(
        census_revision(&doc) >= 20,
        "`ends` is new at census revision 20: {doc}"
    );
    for zid in [
        ZID_ASKER_V4,
        ZID_RESPONDER_V4,
        ZID_ASKER_V6,
        ZID_RESPONDER_V6,
    ] {
        let text = alloc::format!(
            "\"zid\":\"{}\"",
            wz_session_core::zid_hex::zid_to_zenoh_hex(&zid)
        );
        assert_eq!(doc.matches(&text).count(), 1, "{text} once: {doc}");
    }
    assert_eq!(
        (
            doc.matches("\"sender_end\":\"low\"").count(),
            doc.matches("\"sender_end\":\"high\"").count()
        ),
        (2, 2),
        "{doc}"
    );
    assert!(
        doc.contains("\"locators\":[\"tcp/192.168.1.9:7447\",\"udp/192.168.1.9:7447\"]")
            && doc.contains("\"locators\":[\"tcp/[2001:db8::9]:7447\"]"),
        "each Hello's locator list reaches its node: {doc}"
    );

    // The file is well-formed at every layer a reader checks: the checksums that
    // exist verify, and IPv6 contributes no header checksum to judge.
    let health = d.health();
    assert_eq!(
        (
            health.ip_checksum_valid,
            health.ip_checksum_invalid,
            health.ip_checksum_absent,
            health.transport_checksum_valid,
            health.transport_checksum_invalid,
            health.transport_checksum_absent,
        ),
        (2, 0, 2, 4, 0, 0),
        "two IPv4 headers verify, two IPv6 headers have no checksum, and all four \
         UDP checksums verify"
    );

    // The control: the Hellos alone are not Hellos.
    let packets = packets();
    let alone = crate::pcap::write(
        LINKTYPE_ETHERNET,
        &[
            (0, 0, packets[1].as_slice()),
            (0, 1_000, packets[3].as_slice()),
        ],
    );
    let d = crate::Dissection::from_capture(&alone).expect("the Hellos alone dissect");
    let lists: Vec<(usize, usize)> = d
        .datagram_flows()
        .iter()
        .map(|f| (f.frames.len(), f.scouting.len()))
        .collect();
    assert_eq!(
        lists,
        [(1, 0); 2],
        "with no Scout before it a unicast `0x22` is a transport message, not a Hello"
    );
}
