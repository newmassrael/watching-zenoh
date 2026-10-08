// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y886 (open-debt item 357) — the checksum arithmetic every hand-laid
//! packet fixture in this workspace needs, in one place.
//!
//! # The defect this ends
//!
//! Six crates lay Ethernet/IPv4/TCP or /UDP packets by hand for their tests.
//! Three of them wrote ZERO into the checksum fields. Over IPv4 that is not
//! absence — IPv4 and TCP have no declining form, so a zero is a checksum that
//! is PRESENT AND WRONG — and `wz-capture` verifies both, so every capture
//! those fixtures built read as corrupt on both axes. Nothing went red, because
//! nothing asserted on the counters; R311y884 found it only when a verdict
//! finally read one, and could not close that item until the corpus could
//! express a HEALTHY capture at all.
//!
//! The other three each carried their own copy of the sum, two of them byte
//! for byte.
//!
//! # What this crate owns, and what it deliberately does not
//!
//! The ARITHMETIC only. A packet LAYOUT is a claim a crate makes about the
//! wire, and those stay hand-laid on the argument `wz-capi-dissect`'s fixture
//! doc states: a fixture the reader and the writer share proves only that they
//! hold one belief between them. A one's complement sum is not a belief — RFC
//! 1071 gives it one right answer, and six copies of it are six chances to be
//! wrong in a way no failing test would attribute correctly.
//!
//! # Why not `wz_capture::link`'s own sum
//!
//! That one VERIFIES. A fixture computing its checksum with the function that
//! checks it would make "this capture's checksums are valid" tautological: two
//! implementations agreeing is evidence, one implementation agreeing with
//! itself is not. This is a second implementation on purpose, and
//! `tests::the_sum_matches_an_answer_computed_off_this_tree` pins it against a
//! number that came from neither. A code span and NOT an intra-doc link: the
//! test module is `#[cfg(test)]`, so rustdoc does not compile it and the link
//! is unresolved in every build a reader would run — which Layer C1bz counts,
//! and which is the only reason this note exists rather than the link.

#![no_std]

/// The one's complement sum RFC 1071 defines, over `parts` end to end.
///
/// `parts` are summed as if concatenated: a part of odd length carries its last
/// byte into the next part's first, which is what lets a caller pass a
/// pseudo-header and a segment without building the concatenation. A trailing
/// odd byte is padded with zero, per the RFC.
pub fn ones_complement(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut odd: Option<u8> = None;
    for part in parts {
        let mut at = 0usize;
        if let Some(hi) = odd.take() {
            if let Some(lo) = part.first() {
                sum += u32::from(u16::from_be_bytes([hi, *lo]));
                at = 1;
            } else {
                odd = Some(hi);
            }
        }
        while at + 1 < part.len() {
            sum += u32::from(u16::from_be_bytes([part[at], part[at + 1]]));
            at += 2;
        }
        if at < part.len() {
            odd = Some(part[at]);
        }
    }
    if let Some(hi) = odd {
        sum += u32::from(u16::from_be_bytes([hi, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Fill an IPv4 header's checksum in place. `ip` starts at the version byte and
/// must hold at least the 20-byte fixed header.
///
/// The field is zeroed before summing, so this is idempotent and a caller may
/// leave whatever it likes in those two bytes while building.
pub fn fill_ipv4_checksum(ip: &mut [u8]) {
    ip[10] = 0;
    ip[11] = 0;
    let ck = ones_complement(&[&ip[..20]]);
    ip[10..12].copy_from_slice(&ck.to_be_bytes());
}

/// Fill a TCP segment's checksum in place, over the IPv4 pseudo-header.
///
/// `tcp` is the whole segment, header and payload; `src` and `dst` are the IPv4
/// addresses the packet will carry, which is why they are arguments rather than
/// read out of a header this function is not given.
pub fn fill_tcp_checksum(src: [u8; 4], dst: [u8; 4], tcp: &mut [u8]) {
    fill_transport_checksum(src, dst, 6, tcp);
}

/// Fill a UDP datagram's checksum in place, over the IPv4 pseudo-header.
///
/// UDP is the one axis where zero is a legitimate wire value — RFC 768 lets an
/// IPv4 sender decline the checksum by leaving it zero, and `wz-capture` reads
/// that as ABSENT rather than invalid. Call this when the fixture means "a
/// sender that computed it"; leave the field zero when it means "a sender that
/// declined", and the two are then different captures rather than one mistake.
pub fn fill_udp_checksum(src: [u8; 4], dst: [u8; 4], udp: &mut [u8]) {
    fill_transport_checksum(src, dst, 17, udp);
    // RFC 768: a computed sum of zero is transmitted as all ones, because zero
    // is the value that means "not computed". Without this a fixture could
    // land on the one value that says the opposite of what it did.
    if udp[6] == 0 && udp[7] == 0 {
        udp[6] = 0xFF;
        udp[7] = 0xFF;
    }
}

/// Leave in a TCP or UDP segment's checksum field what a SENDING host leaves
/// there when its network card is to finish the checksum: the pseudo-header sum
/// folded to 16 bits and NOT complemented.
///
/// A capture taken on the sending host sees the packet before the card has run,
/// so the field is that partial value and the segment does not verify. Linux
/// writes it as `~tcp_v6_check(skb->len, saddr, daddr, 0)`
/// (`include/net/ip6_checksum.h`, `__tcp_v6_send_check`), and `tcp_v6_check` is
/// the complemented fold, so the field is the sum itself. This function lays the
/// same value from RFC 793 / RFC 8200 §8.1's own pseudo-header, byte by byte,
/// and shares nothing with the reader's sum.
///
/// `src` and `dst` are both 4 bytes (IPv4) or both 16 (IPv6); `proto` is 6 (TCP)
/// or 17 (UDP), which also decides where the field sits. `seg` is the whole
/// segment, as in [`fill_tcp_checksum`]; whatever the field held is ignored,
/// because the pseudo-header sum does not cover it.
///
/// # Panics
/// On an address pair of any other shape or a protocol other than 6 and 17: a
/// fixture asking for those has a bug this should not paper over.
pub fn fill_offload_checksum(src: &[u8], dst: &[u8], proto: u8, seg: &mut [u8]) {
    assert!(
        (src.len() == 4 || src.len() == 16) && src.len() == dst.len(),
        "addresses must be both IPv4 or both IPv6: {} and {} byte(s)",
        src.len(),
        dst.len()
    );
    assert!(proto == 6 || proto == 17, "TCP or UDP only: {proto}");
    let at = if proto == 6 { 16 } else { 6 };
    let mut pseudo = [0u8; 40];
    let n = if src.len() == 4 {
        // RFC 793 "Specification": source, destination, zero, protocol, length.
        pseudo[..4].copy_from_slice(src);
        pseudo[4..8].copy_from_slice(dst);
        pseudo[9] = proto;
        pseudo[10..12].copy_from_slice(&(seg.len() as u16).to_be_bytes());
        12
    } else {
        // RFC 8200 §8.1: source, destination, the upper-layer length as 32
        // bits, then three zero bytes and the next header.
        pseudo[..16].copy_from_slice(src);
        pseudo[16..32].copy_from_slice(dst);
        pseudo[32..36].copy_from_slice(&(seg.len() as u32).to_be_bytes());
        pseudo[39] = proto;
        40
    };
    // `ones_complement` returns the COMPLEMENT of the folded sum, and the field
    // holds the sum itself, so it is inverted back.
    let folded = !ones_complement(&[&pseudo[..n]]);
    seg[at..at + 2].copy_from_slice(&folded.to_be_bytes());
}

/// R311y888 (open-debt item 364) — rewrite an Ethernet/IPv4/TCP frame's SOURCE
/// PORT and refill the sum that rewrite invalidates.
///
/// # The defect this makes hard rather than merely fixed
///
/// A fixture that varies one field to get many flows writes the port straight
/// into the built frame, and the port is INSIDE what the TCP checksum covers.
/// R311y886 fixed the builders and every packet still read as corrupt for
/// exactly this reason; measured this round, three more sites in `wz-capture`
/// were doing the same thing. It announces itself only as one checksum axis
/// disagreeing with the other — IPv4 does not cover the port, so that half
/// stays clean — which is not a signal anybody reads by accident.
///
/// So the edit and the repair are ONE call. The addresses and the segment
/// length come out of the frame itself, because a caller that had to supply
/// them could supply the wrong ones and get a self-consistent wrong answer.
///
/// # Panics
/// If `frame` is not at least a 14-byte Ethernet header, a 20-byte IPv4 header
/// and a 20-byte TCP header, or if its IPv4 total-length field runs past the
/// buffer. A fixture builder that produced such a frame has a bug this should
/// not paper over.
pub fn set_tcp_source_port(frame: &mut [u8], port: u16) {
    assert!(
        frame.len() >= 14 + 20 + 20,
        "not an Ethernet/IPv4/TCP frame: {} byte(s)",
        frame.len()
    );
    frame[34..36].copy_from_slice(&port.to_be_bytes());
    let src = [frame[26], frame[27], frame[28], frame[29]];
    let dst = [frame[30], frame[31], frame[32], frame[33]];
    // The segment ends where the IPv4 header says the datagram does, NOT where
    // the frame does: a real NIC pads to 60 bytes and those pad bytes are not
    // part of the checksum's cover.
    let total = usize::from(u16::from_be_bytes([frame[16], frame[17]]));
    let end = 14 + total;
    assert!(
        end <= frame.len() && end >= 34 + 20,
        "IPv4 total length {total} does not fit the frame"
    );
    fill_tcp_checksum(src, dst, &mut frame[34..end]);
}

/// The shared body of the two transport fills: same pseudo-header, same field
/// offset relative to nothing — TCP's checksum sits at 16 and UDP's at 6, which
/// is the only thing that differs and is why `at` is computed from `proto`.
fn fill_transport_checksum(src: [u8; 4], dst: [u8; 4], proto: u8, seg: &mut [u8]) {
    let at = if proto == 6 { 16 } else { 6 };
    seg[at] = 0;
    seg[at + 1] = 0;
    let len = (seg.len() as u16).to_be_bytes();
    let pseudo = [
        src[0], src[1], src[2], src[3], dst[0], dst[1], dst[2], dst[3], 0, proto, len[0], len[1],
    ];
    let ck = ones_complement(&[&pseudo[..], seg]);
    seg[at..at + 2].copy_from_slice(&ck.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sum agrees with an answer this tree did not produce.
    ///
    /// The header is the IPv4 worked example that circulates with the header
    /// checksum's definition — `45 00 00 73 00 00 40 00 40 11 b8 61 c0 a8 00 01
    /// c0 a8 00 c7`, published checksum `0xb861` — deliberately NOT RFC 1071,
    /// which states the algorithm and works no IPv4 header through it. What
    /// matters is only that the pair came from outside: this arm is then
    /// neither "the implementation agrees with itself" nor "the implementation
    /// agrees with the reader that will verify it", and a sum wrong in the same
    /// way twice passes both of those.
    #[test]
    fn the_sum_matches_an_answer_computed_off_this_tree() {
        let mut ip = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        fill_ipv4_checksum(&mut ip);
        assert_eq!(
            [ip[10], ip[11]],
            [0xb8, 0x61],
            "RFC 1071's own worked example is the answer this must produce"
        );
    }

    /// A filled header re-sums to zero, which is the property a VERIFIER reads.
    ///
    /// Separate from the arm above because the two fail differently: a sum with
    /// a byte-order slip passes this one (it is self-consistent) and fails
    /// that one.
    #[test]
    fn a_filled_header_verifies() {
        let mut ip = [
            0x45u8, 0x00, 0x00, 0x28, 0, 0, 0, 0, 64, 6, 0xAB, 0xCD, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        fill_ipv4_checksum(&mut ip);
        assert_eq!(
            ones_complement(&[&ip[..20]]),
            0,
            "a header whose checksum is in place sums to zero"
        );
    }

    /// The transport fill is idempotent and does not depend on what was in the
    /// field.
    ///
    /// A fixture builder leaves those two bytes as whatever placeholder it
    /// pushed, so a fill that summed the old value would be right exactly once
    /// per builder — the failure that looks like a flake.
    #[test]
    fn a_transport_fill_ignores_what_was_already_there() {
        let payload = [1u8, 2, 3];
        let mut a = tcp_segment(&payload, [0x00, 0x00]);
        let mut b = tcp_segment(&payload, [0xDE, 0xAD]);
        fill_tcp_checksum([10, 0, 0, 1], [10, 0, 0, 2], &mut a);
        fill_tcp_checksum([10, 0, 0, 1], [10, 0, 0, 2], &mut b);
        assert_eq!(a, b, "the placeholder must not reach the sum");
        fill_tcp_checksum([10, 0, 0, 1], [10, 0, 0, 2], &mut a);
        assert_eq!(a, b, "and filling twice must not move it");
    }

    /// UDP's declining form is never produced by a fill.
    ///
    /// Driven off a payload whose sum lands on zero, so this is the arm and not
    /// a restatement of the one above: without the RFC 768 fold-up the fixture
    /// would say "this sender declined" about a sender that computed.
    #[test]
    fn a_computed_udp_sum_is_never_the_value_that_means_declined() {
        // Search a small space for the payload whose sum is zero; a hand-picked
        // constant here would rot the moment the pseudo-header changed.
        let mut found = false;
        for i in 0..=u16::MAX {
            let mut udp = udp_datagram(&i.to_be_bytes());
            fill_udp_checksum([10, 0, 0, 1], [10, 0, 0, 2], &mut udp);
            let raw = {
                let mut probe = udp_datagram(&i.to_be_bytes());
                probe[6] = 0;
                probe[7] = 0;
                let len = (probe.len() as u16).to_be_bytes();
                let pseudo = [10u8, 0, 0, 1, 10, 0, 0, 2, 0, 17, len[0], len[1]];
                ones_complement(&[&pseudo[..], &probe])
            };
            if raw == 0 {
                assert_eq!(
                    [udp[6], udp[7]],
                    [0xFF, 0xFF],
                    "a computed zero must ship as all ones (RFC 768)"
                );
                found = true;
                break;
            }
        }
        assert!(found, "no payload in the search space summed to zero");
    }

    /// The offload field is the folded pseudo-header sum itself, against sums
    /// worked by hand from the RFC layouts and written here as literals.
    ///
    /// IPv4: `127.0.0.1` to itself, protocol 6, length 63 is
    /// `0x7f00 + 0x0001 + 0x7f00 + 0x0001 + 0x0006 + 0x003f = 0xfe47`, which fits
    /// in 16 bits. IPv6: `fe80::1` to `fe80::2`, protocol 6, length 20 is
    /// `0xfe80 + 0x0001 + 0xfe80 + 0x0002 + 0x0014 + 0x0006 = 0x1fd1d`, which
    /// folds to `0xfd1e`. Neither is the complement, so a fill that inverted its
    /// answer, as a full checksum does, fails both.
    #[test]
    fn an_offload_field_is_the_folded_pseudo_header_sum_and_not_its_complement() {
        let mut v4 = [0u8; 63];
        fill_offload_checksum(&[127, 0, 0, 1], &[127, 0, 0, 1], 6, &mut v4);
        assert_eq!([v4[16], v4[17]], [0xfe, 0x47]);

        let mut v6 = [0u8; 20];
        let a = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let b = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];
        fill_offload_checksum(&a, &b, 6, &mut v6);
        assert_eq!([v6[16], v6[17]], [0xfd, 0x1e]);
    }

    /// The carry out of bit 15 is FOLDED back in, not dropped.
    ///
    /// `192.168.1.2` to `192.168.1.3`, protocol 6, length 20 is
    /// `0xc0a8 + 0x0102 + 0xc0a8 + 0x0103 + 0x0006 + 0x0014 = 0x1836f`, so the
    /// field is `0x836f + 1 = 0x8370`. A fill that kept the low 16 bits writes
    /// `0x836f`, one short, which no address pair that stays under 0x10000 can
    /// tell from the right answer.
    #[test]
    fn an_offload_field_folds_the_carry_back_in() {
        let mut seg = [0u8; 20];
        fill_offload_checksum(&[192, 168, 1, 2], &[192, 168, 1, 3], 6, &mut seg);
        assert_eq!([seg[16], seg[17]], [0x83, 0x70]);
    }

    /// A UDP field sits at offset 6, and the segment under it does not verify
    /// once the field is the partial sum: that is the property a reader tells it
    /// by, so the fixture must have it.
    #[test]
    fn an_offload_udp_field_sits_at_offset_6_and_the_segment_does_not_verify() {
        let mut seg = udp_datagram(&[1, 2]);
        fill_offload_checksum(&[10, 0, 0, 1], &[10, 0, 0, 2], 17, &mut seg);
        // Length 10: 0x0a00 + 0x0001 + 0x0a00 + 0x0002 + 0x0011 + 0x000a = 0x141e.
        assert_eq!([seg[6], seg[7]], [0x14, 0x1e]);
        let len = (seg.len() as u16).to_be_bytes();
        let pseudo = [10u8, 0, 0, 1, 10, 0, 0, 2, 0, 17, len[0], len[1]];
        assert_ne!(
            ones_complement(&[&pseudo[..], &seg]),
            0,
            "an offload segment is not a verifying one"
        );
    }

    /// R311y888 — the port rewrite leaves the frame VERIFYING, and it is the
    /// pad bytes that make this worth a test.
    ///
    /// A real NIC pads a short frame to 60 bytes and those bytes are outside
    /// the checksum's cover, so a refill that summed to the end of the BUFFER
    /// instead of to the end of the IPv4 datagram would be self-consistent and
    /// wrong — the shape a caller could never see, because the sum it wrote is
    /// the sum it would read back.
    #[test]
    fn rewriting_the_source_port_leaves_the_frame_verifying() {
        let mut frame = padded_frame(&[9, 9, 9]);
        // The control: it verifies before the edit, so a failure after it is
        // the edit and not the fixture.
        assert_eq!(tcp_sum_of(&frame), 0, "the built frame must verify");

        set_tcp_source_port(&mut frame, 20_001);
        assert_eq!(
            [frame[34], frame[35]],
            20_001u16.to_be_bytes(),
            "the port must actually have moved"
        );
        assert_eq!(
            tcp_sum_of(&frame),
            0,
            "and the sum the port invalidated must have been refilled"
        );
        assert_eq!(frame.len(), 60, "the pad is still there to be excluded");
    }

    /// R311y888 — and the SAME edit without the refill does NOT verify, or the
    /// arm above would pass for a frame nobody could break.
    #[test]
    fn the_port_is_inside_what_the_sum_covers() {
        let mut frame = padded_frame(&[9, 9, 9]);
        frame[34..36].copy_from_slice(&20_001u16.to_be_bytes());
        assert_ne!(
            tcp_sum_of(&frame),
            0,
            "a raw port write must break the sum, or this class is imaginary"
        );
    }

    /// An Ethernet/IPv4/TCP frame carrying a 3-byte payload, checksums filled,
    /// padded to the 60-byte minimum a NIC emits.
    ///
    /// A fixed array and no `alloc`: this crate is `#![no_std]` with no
    /// dependencies at all, which is what lets `wz-capture` dev-depend on it
    /// without touching its own zero-third-party rule.
    fn padded_frame(payload: &[u8; 3]) -> [u8; 60] {
        let mut tcp = tcp_segment(payload, [0, 0]);
        fill_tcp_checksum([10, 0, 0, 1], [10, 0, 0, 2], &mut tcp);

        let mut ip = [0u8; 43];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
        fill_ipv4_checksum(&mut ip);
        ip[20..].copy_from_slice(&tcp);

        let mut eth = [0u8; 60];
        eth[12..14].copy_from_slice(&[0x08, 0x00]);
        eth[14..14 + ip.len()].copy_from_slice(&ip);
        eth
    }

    /// The one's complement over a frame's TCP segment and its pseudo-header;
    /// zero means the checksum in place verifies.
    fn tcp_sum_of(frame: &[u8]) -> u16 {
        let total = usize::from(u16::from_be_bytes([frame[16], frame[17]]));
        let seg = &frame[34..14 + total];
        let len = (seg.len() as u16).to_be_bytes();
        let pseudo = [
            frame[26], frame[27], frame[28], frame[29], frame[30], frame[31], frame[32], frame[33],
            0, 6, len[0], len[1],
        ];
        ones_complement(&[&pseudo[..], seg])
    }

    /// A 20-byte TCP header with `checksum` in place and `payload` after it.
    fn tcp_segment(payload: &[u8; 3], checksum: [u8; 2]) -> [u8; 23] {
        let mut seg = [0u8; 23];
        seg[..2].copy_from_slice(&1111u16.to_be_bytes());
        seg[2..4].copy_from_slice(&7447u16.to_be_bytes());
        seg[12] = 5 << 4;
        seg[13] = 0x10;
        seg[16..18].copy_from_slice(&checksum);
        seg[20..].copy_from_slice(payload);
        seg
    }

    /// An 8-byte UDP header with `payload` after it.
    fn udp_datagram(payload: &[u8]) -> [u8; 10] {
        let mut d = [0u8; 10];
        d[..2].copy_from_slice(&1111u16.to_be_bytes());
        d[2..4].copy_from_slice(&7447u16.to_be_bytes());
        d[4..6].copy_from_slice(&(8u16 + payload.len() as u16).to_be_bytes());
        d[8..].copy_from_slice(payload);
        d
    }
}
