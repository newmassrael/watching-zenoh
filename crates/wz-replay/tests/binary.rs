// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y700 — the replay binary, driven with a real capture.
//!
//! The engine's own tests build `Samples` by hand, which proves the schedule
//! and the mutations and proves nothing about whether a CAPTURE yields any. A
//! library nobody runs hides its own lies (R311y664), and the lie available
//! here is the extraction: a plan of zero emissions is what both a broken
//! walker and an empty capture produce.

use std::path::PathBuf;
use std::process::Command;

/// A scratch directory that removes itself.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("wz-replay-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&path).expect("a scratch directory");
        Self(path)
    }
    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).expect("a fixture");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// R311y700 ([REDACTED-REQ]) — A REAL CAPTURE YIELDS A REAL PLAN, at the command line.
///
/// ## What this proves that the engine's tests cannot
///
/// The engine is driven by `Samples` a test built. This drives the EXTRACTION:
/// a pcapng holding a zenoh reply is read, its keyexpr and payload are
/// recovered by the same walk the field layer uses, and the plan names both.
/// A walker that recovered nothing produces a plan of zero emissions, which is
/// also what an empty capture produces — so the assertion is on the CONTENT.
#[test]
fn a_capture_yields_a_plan_naming_its_keyexpr_and_its_payload_length() {
    let scratch = Scratch::new("plan");
    let capture = scratch.write("reply.pcapng", &fixture::reply_capture());

    let out = Command::new(env!("CARGO_BIN_EXE_wz-replay"))
        .arg(&capture)
        .output()
        .expect("runs");
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout).into_owned();

    assert!(
        text.contains("`demo/a` 5 byte(s)"),
        "the sample's keyexpr and its payload length come out of the capture: {text}"
    );
    assert!(text.contains("1 emission(s)"), "{text}");
    assert!(
        text.contains("0 mutated"),
        "and nothing was mutated without --fuzz: {text}"
    );
}

/// R311y700 ([REDACTED-REQ]) — the SPEED reaches the plan from the command line.
///
/// The engine proves the arithmetic; this proves the flag is wired to it. A
/// flag the parser reads and nothing acts on is the defect R311y669 shipped and
/// R311y670 had to close.
#[test]
fn the_speed_and_gap_options_reach_the_plan() {
    let scratch = Scratch::new("speed");
    let capture = scratch.write("reply.pcapng", &fixture::two_sample_capture());

    let run = |args: &[&str]| {
        String::from_utf8_lossy(
            &Command::new(env!("CARGO_BIN_EXE_wz-replay"))
                .arg(&capture)
                .args(args)
                .output()
                .expect("runs")
                .stdout,
        )
        .into_owned()
    };

    let normal = run(&["--gap", "200"]);
    assert!(normal.contains("1: +200 ms"), "{normal}");
    let fast = run(&["--gap", "200", "--speed", "4"]);
    assert!(
        fast.contains("1: +50 ms"),
        "four times as fast is a quarter of the gap: {fast}"
    );
    // AND THE TOTAL follows, which is the number an operator checks before
    // starting a replay.
    assert!(normal.contains("200 ms total"), "{normal}");
    assert!(fast.contains("50 ms total"), "{fast}");
}

/// R311y700 ([REDACTED-REQ]) — `--fuzz` reaches the payload, and the plan says which
/// emissions it changed.
#[test]
fn the_fuzz_option_mutates_the_payload_and_the_plan_says_so() {
    let scratch = Scratch::new("fuzz");
    let capture = scratch.write("reply.pcapng", &fixture::reply_capture());

    let out = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-replay"))
            .arg(&capture)
            .arg("--fuzz")
            .arg("truncate:2")
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    assert!(
        out.contains("`demo/a` 2 byte(s) MUTATED (was 5)"),
        "the row carries the mutated length and the captured one: {out}"
    );
    assert!(out.contains("1 mutated"), "{out}");

    // A --fuzz spec this build cannot read is a usage error rather than a run
    // that quietly sends the captured bytes.
    let bad = Command::new(env!("CARGO_BIN_EXE_wz-replay"))
        .arg(&capture)
        .arg("--fuzz")
        .arg("rotate:3")
        .output()
        .expect("runs");
    assert_eq!(bad.status.code(), Some(2));
}

/// R311y700 ([REDACTED-REQ]) — a speed that cannot be played is refused at the command
/// line, before anything is read.
#[test]
fn a_speed_of_zero_is_refused_at_the_command_line() {
    let scratch = Scratch::new("speed-zero");
    let capture = scratch.write("reply.pcapng", &fixture::reply_capture());
    let out = Command::new(env!("CARGO_BIN_EXE_wz-replay"))
        .arg(&capture)
        .arg("--speed")
        .arg("0")
        .output()
        .expect("runs");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("greater than zero"));
}

/// The fixtures: real zenoh messages over a real pcapng.
///
/// Copied verbatim from `wz-analyze`'s own binary tests rather than rewritten,
/// because a second hand-written encoding of the same wire form is a second
/// opinion about it -- and the point of this test is that the EXTRACTION reads
/// what a conforming sender wrote.
mod fixture {
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
            header: wz_codecs::response::Response::default().header
                | wz_codecs::wire_const::FLAG_N_N,
            request_id,
            keyexpr: keyexpr(suffix),
            body: wz_codecs::response::ResponseVariant::CodecZenohReply(wz_codecs::reply::Reply {
                body: wz_codecs::reply::ReplyVariant::CodecZenohMsgPut(
                    wz_codecs::msg_put::MsgPut {
                        payload_len: payload.len() as u64,
                        payload,
                        ..Default::default()
                    },
                ),
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
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
}
