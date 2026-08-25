// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2054 (open-debt item 384) — the BSD address-family table, re-measured
//! against `tcpdump` instead of remembered.
//!
//! ## The gap
//!
//! `wz_capture::link`'s `BSD_AF_INET6` is `[24, 28, 30]`, and item 384 records
//! how that set was arrived at: someone fed `tcpdump` a handful of families in
//! both byte orders, read the answers, and wrote the set down. The judgement
//! was correct and it lived in a session. Nothing in the repository reproduces
//! it, so if libpcap grows a family — or if an OS disagrees — the table goes
//! quietly wrong and every gate stays green.
//!
//! That is the same shape R2053 found in the damage sweep and R2052 in the
//! opaque-body reasons: a pinned set with no instrument behind it.
//!
//! ## Why `tcpdump` is the right judge, and not a header constant
//!
//! The property that matters operationally is not "24 is `AF_INET6` on
//! NetBSD". It is "a capture `tcpdump` reads as IPv6, wz reads as IPv6" — the
//! two tools are pointed at the same files by the same people, and a
//! disagreement is what makes a reader doubt the analyzer. So the adjudicator
//! is the tool, run for real, on captures this test writes.
//!
//! ## The sweep, and the two bodies
//!
//! Every family in [`SWEPT`] is written into a `LINKTYPE_NULL` capture twice —
//! once carrying a UDP-over-IPv6 datagram, once UDP-over-IPv4 — and both wz and
//! `tcpdump` are asked. Two bodies rather than one because the family word and
//! the packet behind it are separate claims: `tcpdump` given family 2 and an
//! IPv6 body prints `IP6, wrong link-layer encapsulation`, which names the
//! MISMATCH rather than the family. Judging each body separately keeps the two
//! apart.
//!
//! MEASURED before this file existed, with a throwaway probe: `tcpdump` prints
//! `IP6 ` for 24 / 28 / 30, `IP ` for 2, `IPX` for 23 — a family it knows and wz
//! must still refuse — and `Unknown AF n` for everything else. The `IPX` row is
//! why the reject half of this assertion is not vacuous: it is a family the
//! judge accepts and the subject must decline.
//!
//! ## Byte order
//!
//! Both orders are swept because `strip_loopback` tries both, and the probe
//! showed `tcpdump` does too — every family read identically LE and BE. An
//! agreement that held in only one order would be a difference worth knowing.

use std::process::Command;

use wz_capture::link::{decapsulate, LINKTYPE_NULL};

/// The families this test asks about. Wide enough to bracket every BSD
/// `AF_INET6` (24 NetBSD/OpenBSD, 28 FreeBSD/DragonFly, 30 Darwin), Linux's 10
/// (which this encapsulation never carries), and 23, the `IPX` family that
/// makes the reject half of the assertion real.
const SWEPT: std::ops::RangeInclusive<u32> = 0..=40;

/// What `tcpdump` made of one capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Judged {
    /// The line began `IP6 ` — the family names IPv6 and the body agreed.
    Ipv6,
    /// The line began `IP ` — the family names IPv4 and the body agreed.
    Ipv4,
    /// Anything else: `Unknown AF n`, a non-IP family such as `IPX`, or an
    /// `IP6, wrong link-layer encapsulation` complaint about a mismatch.
    Neither,
}

/// A `LINKTYPE_NULL` capture of one packet: the four-byte family word in the
/// requested order, then `body`.
fn loopback_pcap(af: u32, big_endian: bool, body: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(4 + body.len());
    packet.extend_from_slice(&if big_endian {
        af.to_be_bytes()
    } else {
        af.to_le_bytes()
    });
    packet.extend_from_slice(body);
    wz_capture::pcap::write(LINKTYPE_NULL, &[(0, 0, packet.as_slice())])
}

/// One UDP datagram over IPv6, `::1` to `::1`, with a real checksum.
fn udp_over_ipv6() -> Vec<u8> {
    const PAYLOAD: &[u8] = b"af-adjudicator";
    let udp_len = (8 + PAYLOAD.len()) as u16;
    let mut src = [0u8; 16];
    src[15] = 1;
    let dst = src;

    let mut ip = Vec::with_capacity(40 + udp_len as usize);
    ip.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    ip.extend_from_slice(&udp_len.to_be_bytes());
    ip.push(17); // next header: UDP
    ip.push(64); // hop limit
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);

    let mut udp = Vec::with_capacity(udp_len as usize);
    udp.extend_from_slice(&7447u16.to_be_bytes());
    udp.extend_from_slice(&7447u16.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0x00, 0x00]);
    udp.extend_from_slice(PAYLOAD);
    // The IPv6 pseudo-header is {src, dst, u32 length, three zeros, next
    // header}. UDP over IPv6 has no zero-checksum escape, so this has to be
    // real or `tcpdump` reports `bad udp cksum` and wz's own verifier disagrees
    // with it for a reason that is not the family.
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.extend_from_slice(&u32::from(udp_len).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    let sum = wz_packet_fixtures::ones_complement(&[&pseudo, &udp]);
    udp[6..8].copy_from_slice(&sum.to_be_bytes());

    ip.extend_from_slice(&udp);
    ip
}

/// One UDP datagram over IPv4, `127.0.0.1` to `127.0.0.1`.
fn udp_over_ipv4() -> Vec<u8> {
    const PAYLOAD: &[u8] = b"af-adjudicator";
    const HOST: [u8; 4] = [127, 0, 0, 1];
    let udp_len = (8 + PAYLOAD.len()) as u16;
    let total = 20 + udp_len;

    let mut ip = Vec::with_capacity(total as usize);
    ip.extend_from_slice(&[0x45, 0x00]);
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 64, 17, 0x00, 0x00]);
    ip.extend_from_slice(&HOST);
    ip.extend_from_slice(&HOST);

    let mut udp = Vec::with_capacity(udp_len as usize);
    udp.extend_from_slice(&7447u16.to_be_bytes());
    udp.extend_from_slice(&7447u16.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0x00, 0x00]);
    udp.extend_from_slice(PAYLOAD);

    ip.extend_from_slice(&udp);
    wz_packet_fixtures::fill_ipv4_checksum(&mut ip[..20]);
    wz_packet_fixtures::fill_udp_checksum(HOST, HOST, &mut ip[20..]);
    ip
}

/// Ask `tcpdump` what a capture is, or `None` when the tool is absent.
fn ask_tcpdump(pcap: &[u8], dir: &std::path::Path, name: &str) -> Option<Judged> {
    let path = dir.join(name);
    std::fs::write(&path, pcap).expect("write the probe capture");
    // `-t` drops the timestamp so the protocol word is the start of the line,
    // `-n` stops name resolution, `-q` keeps the line short.
    let out = Command::new("tcpdump")
        .args(["-t", "-n", "-q", "-r"])
        .arg(&path)
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().find(|l| !l.trim().is_empty())?.trim();
    Some(if line.starts_with("IP6 ") {
        Judged::Ipv6
    } else if line.starts_with("IP ") {
        Judged::Ipv4
    } else {
        Judged::Neither
    })
}

/// THE ADJUDICATOR: wz's BSD address-family table, judged by `tcpdump`.
///
/// The `tcpdump` in the name is LOAD-BEARING: Layer C0's skip-token rule reads
/// the FUNCTION name, because that is what libtest's `--skip` matches.
// NO CROSS-IMPL PROOF DECLARATION HERE, and its absence is the correct answer
// rather than an omission.
//
// This file was first written with a `none --` declaration, and Layer A4 refused
// it: a file that spawns no foreign IMPLEMENTATION may say nothing about proof
// at all, not even nothing. The gate is right and the reason is worth keeping.
// `tcpdump` is a foreign TOOL but it is not a zenoh implementation -- it
// adjudicates a LINK-LAYER table, not a zenoh peer -- so this test contributes
// no cross-impl coverage and must not appear in that accounting. Teaching A4 a
// `tcpdump` class would have made the number say something it does not mean.
#[test]
fn the_bsd_address_family_table_agrees_with_tcpdump() {
    let dir = tempfile::tempdir().expect("tempdir for probe captures");
    let v6_body = udp_over_ipv6();
    let v4_body = udp_over_ipv4();

    // ── IS THE JUDGE PRESENT? ─────────────────────────────────────────────
    // A missing `tcpdump` is a SKIP, not a pass -- but an armed lane turns it
    // into a failure, which is how this tree keeps "the oracle was absent" from
    // reading as "the subject was right" (the `WZ_*_REQUIRE` pattern Layers D
    // and F already use).
    let probe = loopback_pcap(28, false, &v6_body);
    let Some(_) = ask_tcpdump(&probe, dir.path(), "probe.pcap") else {
        if std::env::var("WZ_TCPDUMP_REQUIRE").is_ok() {
            panic!(
                "WZ_TCPDUMP_REQUIRE is set and `tcpdump` did not run. The BSD \
                 address-family table has no other adjudicator, so a lane that \
                 armed this flag was asking for the measurement, not for a skip"
            );
        }
        eprintln!(
            "skip: `tcpdump` is not runnable here; set WZ_TCPDUMP_REQUIRE=1 to make that a failure"
        );
        return;
    };

    let mut wz_v6 = Vec::new();
    let mut judge_v6 = Vec::new();
    let mut wz_v4 = Vec::new();
    let mut judge_v4 = Vec::new();
    let mut disagreements = Vec::new();

    for af in SWEPT {
        for big_endian in [false, true] {
            for (body, is_v6_body) in [(&v6_body, true), (&v4_body, false)] {
                let pcap = loopback_pcap(af, big_endian, body);
                let name = format!(
                    "af{af}-{}-{}.pcap",
                    u8::from(big_endian),
                    u8::from(is_v6_body)
                );
                let judged = ask_tcpdump(&pcap, dir.path(), &name)
                    .expect("`tcpdump` ran once and must keep running");

                // wz's verdict on the SAME bytes, through the same entry point a
                // reader opens a capture with.
                let mut packet = Vec::new();
                packet.extend_from_slice(&if big_endian {
                    af.to_be_bytes()
                } else {
                    af.to_le_bytes()
                });
                packet.extend_from_slice(body);
                let accepted = decapsulate(LINKTYPE_NULL, 0, &packet).is_ok();

                let judge_accepted = judged
                    == if is_v6_body {
                        Judged::Ipv6
                    } else {
                        Judged::Ipv4
                    };
                if accepted != judge_accepted {
                    disagreements.push(format!(
                        "AF {af} ({}, {} body): tcpdump {judged:?}, wz {}",
                        if big_endian { "BE" } else { "LE" },
                        if is_v6_body { "IPv6" } else { "IPv4" },
                        if accepted { "accepted" } else { "refused" },
                    ));
                }
                if is_v6_body {
                    if accepted {
                        wz_v6.push(af);
                    }
                    if judge_accepted {
                        judge_v6.push(af);
                    }
                } else {
                    if accepted {
                        wz_v4.push(af);
                    }
                    if judge_accepted {
                        judge_v4.push(af);
                    }
                }
            }
        }
    }
    for set in [&mut wz_v6, &mut judge_v6, &mut wz_v4, &mut judge_v4] {
        set.sort_unstable();
        set.dedup();
    }

    // ── ANTI-VACUITY: THE JUDGE MUST HAVE ACCEPTED SOMETHING ──────────────
    // Without this, a `tcpdump` that printed nothing readable would make every
    // family "Neither", wz would refuse most of them, and the agreement below
    // would be an agreement about refusals.
    assert!(
        !judge_v6.is_empty() && !judge_v4.is_empty(),
        "tcpdump accepted no family as IPv6 ({judge_v6:?}) or none as IPv4 \
         ({judge_v4:?}), so the agreement below would be about nothing"
    );

    // ── THE AGREEMENT, AS TWO SETS, BOTH WAYS ─────────────────────────────
    assert!(
        disagreements.is_empty(),
        "wz and tcpdump disagree about {} address famil(ies) in a BSD loopback \
         capture. This is the table item 384 says was decided once by hand: \
         `BSD_AF_INET6` is a set someone read off this tool in a session, and \
         these rows are where the two now differ.\n  {}",
        disagreements.len(),
        disagreements.join("\n  "),
    );
    assert_eq!(
        wz_v6, judge_v6,
        "the IPv6 family SET differs even though no individual row \
         disagreed -- which cannot happen and means this test is \
         miscounting"
    );
    assert_eq!(wz_v4, judge_v4, "the IPv4 family SET differs, as above");

    // ── AND WHAT THAT SET ACTUALLY IS ─────────────────────────────────────
    // Pinned so a CHANGE is visible even when both sides move together: if a
    // future libpcap teaches tcpdump a fourth IPv6 family and wz is updated to
    // match, the rows above stay silent and this line is what says the table
    // grew. The three are NetBSD/OpenBSD, FreeBSD/DragonFly and Darwin.
    assert_eq!(
        wz_v6,
        vec![24, 28, 30],
        "the set of families read as IPv6 changed"
    );
    assert_eq!(wz_v4, vec![2], "the set of families read as IPv4 changed");
    eprintln!("BSD AF adjudication: IPv6 {wz_v6:?}, IPv4 {wz_v4:?} (tcpdump agrees on both)");
}
