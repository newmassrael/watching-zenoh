// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y702 — the replay fixtures, shared by BOTH integration targets.
//!
//! They were `binary.rs`'s own module until the live leg needed the same
//! capture. A second copy would be a second opinion about what the wire form
//! is, which is exactly the argument the original module's doc makes for
//! copying them from `wz-analyze` rather than rewriting them -- and it applies
//! one target over just as well.
//!
//! The fixtures: real zenoh messages over a real pcapng.
//!
//! Copied verbatim from `wz-analyze`'s own binary tests rather than rewritten,
//! because a second hand-written encoding of the same wire form is a second
//! opinion about it -- and the point of this test is that the EXTRACTION reads
//! what a conforming sender wrote.

#![allow(dead_code)]

fn keyexpr(suffix: &'static str) -> wz_codecs::wireexpr::Wireexpr<'static> {
    wz_codecs::wireexpr::Wireexpr {
        body: wz_codecs::wireexpr::WireexprVariant::WireexprLocal(
            wz_codecs::wireexpr_local::WireexprLocal {
                id: 0,
                suffix_len: Some(suffix.len() as u64),
                suffix: Some(suffix),
            },
        ),
    }
}

fn framed_frame(record: &[u8]) -> Vec<u8> {
    let mut frame = vec![wz_session_core::wire_const::T_MID_FRAME, 0x00];
    frame.extend_from_slice(record);
    let mut out = (frame.len() as u16).to_le_bytes().to_vec();
    out.extend_from_slice(&frame);
    out
}

fn reply(request_id: u64, suffix: &'static str, payload: &'static [u8]) -> Vec<u8> {
    wz_codecs::response::Response {
        header: wz_codecs::response::Response::default().header | wz_codecs::wire_const::FLAG_N_N,
        request_id,
        keyexpr: keyexpr(suffix),
        body: wz_codecs::response::ResponseVariant::CodecZenohReply(wz_codecs::reply::Reply {
            body: wz_codecs::reply::ReplyVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
                payload_len: payload.len() as u64,
                payload,
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
    .encode_to_vec()
}

/// R311y716 ([REDACTED-REQ]) — a PUSH, which is the one record shape in this module
/// that leaves nothing outstanding.
///
/// Every other fixture here carries a `Response`, and a reply whose request the
/// capture never held is an ORPHAN: the exchange plane reports a gap and the
/// verdict is short. That is right, and it means none of them could witness the
/// alert's silent arm -- a capture that raises nothing has to be a capture with
/// nothing wrong with it, and until this existed there was no such capture to
/// point the tool at.
fn push(suffix: &'static str, payload: &'static [u8]) -> Vec<u8> {
    wz_codecs::push::Push {
        // The N flag says the keyexpr carries a SUFFIX, and `keyexpr` above
        // always writes one. Without it the decode reads a different shape and
        // the walk halts on the record -- which reports as three plane-level
        // gaps rather than as a bad fixture.
        header: wz_codecs::push::Push::default().header | wz_codecs::wire_const::FLAG_N_N,
        keyexpr: keyexpr(suffix),
        body: wz_codecs::push::PushVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
            payload_len: payload.len() as u64,
            payload,
            ..Default::default()
        }),
        ..Default::default()
    }
    .encode_to_vec()
}

/// R311y716 ([REDACTED-REQ]) — a capture with NOTHING wrong with it.
pub fn clean_capture() -> Vec<u8> {
    let mut body = framed_frame(&push("demo/a", b"first"));
    body.extend_from_slice(&framed_frame(&push("demo/b", b"second")));
    wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &tcp_packet_reverse(1000, &body))],
    )
}

fn tcp_segment_from(seq: u32, payload: &[u8], reverse: bool, client_port: u16) -> Vec<u8> {
    const CLIENT: [u8; 4] = [10, 0, 0, 1];
    const SERVER: [u8; 4] = [10, 0, 0, 2];
    const SERVER_PORT: u16 = 7447;
    let client_side = client_port;
    let (src, dst) = if reverse {
        (SERVER, CLIENT)
    } else {
        (CLIENT, SERVER)
    };
    let (src_port, dst_port) = if reverse {
        (SERVER_PORT, client_side)
    } else {
        (client_side, SERVER_PORT)
    };

    let mut tcp = Vec::new();
    tcp.extend_from_slice(&src_port.to_be_bytes());
    tcp.extend_from_slice(&dst_port.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes());
    tcp.push(5 << 4);
    tcp.push(0x10);
    tcp.extend_from_slice(&64u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(payload);
    // The TCP checksum covers a pseudo-header of the addresses, the protocol
    // and the segment length.
    let mut pseudo = src.to_vec();
    pseudo.extend_from_slice(&dst);
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    let tcp_sum = checksum(&[&pseudo, &tcp]);
    tcp[16..18].copy_from_slice(&tcp_sum.to_be_bytes());

    let mut ip = vec![0x45u8, 0];
    ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let ip_sum = checksum(&[&ip[..20]]);
    ip[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    ip.extend_from_slice(&tcp);

    let mut eth = vec![0u8; 12];
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&ip);
    while eth.len() < 60 {
        eth.push(0);
    }
    eth
}

fn tcp_segment(seq: u32, payload: &[u8], reverse: bool) -> Vec<u8> {
    tcp_segment_from(seq, payload, reverse, 1111)
}

fn tcp_packet_reverse(seq: u32, payload: &[u8]) -> Vec<u8> {
    tcp_segment(seq, payload, true)
}

fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let mut carry: Option<u8> = None;
    for part in parts {
        let mut at = 0usize;
        if let Some(hi) = carry.take() {
            if let Some(lo) = part.first() {
                sum += u32::from(u16::from_be_bytes([hi, *lo]));
                at = 1;
            } else {
                carry = Some(hi);
            }
        }
        while at + 1 < part.len() {
            sum += u32::from(u16::from_be_bytes([part[at], part[at + 1]]));
            at += 2;
        }
        if at < part.len() {
            carry = Some(part[at]);
        }
    }
    if let Some(hi) = carry {
        sum += u32::from(u16::from_be_bytes([hi, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// One reply under `demo/a` carrying five bytes.
pub fn reply_capture() -> Vec<u8> {
    let body = framed_frame(&reply(7, "demo/a", b"first"));
    wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &tcp_packet_reverse(1000, &body))],
    )
}

/// Two, so a schedule has a gap to scale.
pub fn two_sample_capture() -> Vec<u8> {
    let mut body = framed_frame(&reply(7, "demo/a", b"first"));
    body.extend_from_slice(&framed_frame(&reply(8, "demo/b", b"second")));
    wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &tcp_packet_reverse(1000, &body))],
    )
}

/// R311y704 — one reply under a keyexpr named by NUMERIC ID, optionally
/// preceded by the `DeclKexpr` that binds it.
///
/// The two captures differ by ONE message, which is what makes the difference
/// in the plan attributable to the declaration rather than to anything else.
pub fn aliased_capture(with_declaration: bool) -> Vec<u8> {
    let mut body = Vec::new();
    if with_declaration {
        body.extend_from_slice(&framed_frame(&declare_kexpr(5, "demo/sensor")));
    }
    body.extend_from_slice(&framed_frame(&aliased_reply(7, 5, b"first")));
    wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &tcp_packet_reverse(1000, &body))],
    )
}

/// `DeclKexpr`: bind `id` to the literal `base` in the sender's space.
fn declare_kexpr(id: u64, base: &'static str) -> Vec<u8> {
    wz_codecs::declare::Declare {
        body: wz_codecs::declare::DeclareVariant::CodecZenohDeclKexpr(
            wz_codecs::decl_kexpr::DeclKexpr {
                header: wz_session_core::wire_const::D_MID_KEXPR
                    | wz_session_core::wire_const::FLAG_D_N,
                id,
                keyexpr: keyexpr(base),
            },
        ),
        ..Default::default()
    }
    .encode_to_vec()
}

/// A reply whose keyexpr is the bare numeric `id`, with no suffix at all.
fn aliased_reply(request_id: u64, id: u64, payload: &'static [u8]) -> Vec<u8> {
    wz_codecs::response::Response {
        header: wz_codecs::response::Response::default().header,
        request_id,
        keyexpr: wz_codecs::wireexpr::Wireexpr {
            body: wz_codecs::wireexpr::WireexprVariant::WireexprLocal(
                wz_codecs::wireexpr_local::WireexprLocal {
                    id,
                    suffix_len: None,
                    suffix: None,
                },
            ),
        },
        body: wz_codecs::response::ResponseVariant::CodecZenohReply(wz_codecs::reply::Reply {
            body: wz_codecs::reply::ReplyVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
                payload_len: payload.len() as u64,
                payload,
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
    .encode_to_vec()
}

/// R311y703 (RP4) — two replies in SEPARATE PACKETS, 350 ms apart.
///
/// `two_sample_capture` batches both into one TCP segment, so both samples
/// resolve to the same packet and the capture's own interval between them is
/// genuinely zero. That is a correct measurement and a useless discriminator:
/// a build that resolved no timestamps at all would produce the same number.
/// These two arrive at 1_000_000 and 1_350_000 microseconds (the writer's
/// interface declares `if_tsresol` 6), so the measured gap is 350 ms and
/// nothing else in this crate produces that number.
pub fn two_packet_capture() -> Vec<u8> {
    let first = framed_frame(&reply(7, "demo/a", b"first"));
    let second = framed_frame(&reply(8, "demo/b", b"second"));
    wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[
            (0, 1_000_000, &tcp_packet_reverse(1000, &first)),
            // The second segment continues the stream, so its sequence number
            // is the first's plus its length -- a gap here would make the
            // assembler hold the bytes and the second sample would not exist.
            (
                0,
                1_350_000,
                &tcp_packet_reverse(1000 + first.len() as u32, &second),
            ),
        ],
    )
}

/// R311y701 (RP2) — the same reply over a DATAGRAM link. No length prefix:
/// a datagram is its own framing unit.
pub fn datagram_capture() -> Vec<u8> {
    let mut frame = vec![wz_session_core::wire_const::T_MID_FRAME, 0x00];
    frame.extend_from_slice(&reply(7, "demo/dgram", b"first"));
    wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &udp_to_zenoh(&frame))],
    )
}

fn udp_to_zenoh(payload: &[u8]) -> Vec<u8> {
    let mut udp = Vec::new();
    udp.extend_from_slice(&50000u16.to_be_bytes());
    udp.extend_from_slice(&7447u16.to_be_bytes());
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes());
    udp.extend_from_slice(payload);
    let mut ip = vec![0x45u8, 0];
    ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
    ip.extend_from_slice(&[10, 0, 0, 1]);
    ip.extend_from_slice(&[10, 0, 0, 2]);
    let ip_sum = checksum(&[&ip[..20]]);
    ip[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    ip.extend_from_slice(&udp);
    let mut eth = vec![0u8; 12];
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&ip);
    while eth.len() < 60 {
        eth.push(0);
    }
    eth
}
