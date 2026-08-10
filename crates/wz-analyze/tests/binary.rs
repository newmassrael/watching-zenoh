// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y664 (§1.2a) — THE BINARY, run as a person runs it.
//!
//! The library tests beside this one drive `analyze` with byte slices, which
//! proves the analysis and says nothing about the program. This drives the
//! executable: two files on disk, a command line, stdout, an exit code. That is
//! the whole of what a person actually has, and every part of it -- reading the
//! paths, merging the key log, choosing the exit code -- is code the byte-slice
//! tests never execute.
//!
//! The files are written under this test's own directory and REMOVED at the
//! end. They are unavoidable here: the claim is about a program that takes
//! paths.

use std::io::Write;
use std::process::Command;

use rustls::crypto::cipher::{AeadKey, Iv, OutboundPlainMessage};
use wz_tls_record::{expand_label, Suite};

const SUITE: Suite = Suite::Aes256GcmSha384;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sealer(secret: &[u8]) -> Box<dyn rustls::crypto::cipher::MessageEncrypter> {
    let mut key = [0u8; 32];
    expand_label(SUITE, secret, b"key", &[], &mut key);
    let mut iv = [0u8; 12];
    expand_label(SUITE, secret, b"iv", &[], &mut iv);
    rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384
        .tls13()
        .expect("a TLS 1.3 suite")
        .aead_alg
        .encrypter(AeadKey::from(key), Iv::from(iv))
}

/// The ones' complement sum RFC 1071 defines, over `parts` concatenated.
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

/// One Ethernet/IPv4/TCP packet WITH VALID CHECKSUMS.
///
/// The checksums are computed rather than zeroed, and the reason is a
/// measurement: a zeroed one is not absent, it is PRESENT AND WRONG, and this
/// reader counts it as such. A fixture with zeroes there makes every capture it
/// builds read as corrupt, which is a fine thing to ignore in a test asserting
/// a frame count and a wrong thing to build an exit-code claim on.
fn tcp_packet(seq: u32, payload: &[u8]) -> Vec<u8> {
    const SRC: [u8; 4] = [10, 0, 0, 1];
    const DST: [u8; 4] = [10, 0, 0, 2];

    let mut tcp = Vec::new();
    tcp.extend_from_slice(&1111u16.to_be_bytes());
    tcp.extend_from_slice(&7447u16.to_be_bytes());
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
    let mut pseudo = SRC.to_vec();
    pseudo.extend_from_slice(&DST);
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    let tcp_sum = checksum(&[&pseudo, &tcp]);
    tcp[16..18].copy_from_slice(&tcp_sum.to_be_bytes());

    let mut ip = vec![0x45u8, 0];
    ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
    ip.extend_from_slice(&SRC);
    ip.extend_from_slice(&DST);
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

fn client_hello(random: &[u8; 32]) -> Vec<u8> {
    let mut body = vec![0x03u8, 0x03];
    body.extend_from_slice(random);
    body.resize(0x30, 0);
    let mut handshake = vec![0x01u8, 0x00, 0x00, body.len() as u8];
    handshake.extend_from_slice(&body);
    let mut record = vec![0x16u8, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// A capture of a TLS flow carrying three zenoh KeepAlives, and the key log
/// that opens it.
fn capture_and_key_log() -> (Vec<u8>, String, [u8; 32]) {
    let secret: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(11).wrapping_add(3))
        .collect();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(2));

    let mut stream = client_hello(&random);
    let mut enc = sealer(&secret);
    for i in 0..3u8 {
        // A framed KeepAlive and NOTHING ELSE in the unit. A trailing byte
        // beside it would be a second message the reader walks to and cannot
        // decode -- counted, correctly, as a byte the capture could not explain,
        // which then makes the whole capture read as incomplete. Measured: the
        // two-byte unit this fixture used first produced
        // `unaccounted_batch_bytes: 3` on a capture that had decrypted perfectly.
        let unit = vec![0x04u8];
        let mut framed = (unit.len() as u16).to_le_bytes().to_vec();
        framed.extend_from_slice(&unit);
        stream.extend_from_slice(
            &enc.encrypt(
                OutboundPlainMessage {
                    typ: rustls::ContentType::ApplicationData,
                    version: rustls::ProtocolVersion::TLSv1_2,
                    payload: rustls::crypto::cipher::OutboundChunks::Single(&framed),
                },
                i as u64,
            )
            .expect("seal")
            .encode(),
        );
    }

    let file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &tcp_packet(1000, &stream))],
    );
    let log = format!(
        "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
        hex(&random),
        hex(&secret)
    );
    (file, log, random)
}

/// A directory of this test's own, removed when the guard drops -- so a
/// failing assertion does not leave files behind either.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("wz-analyze-test-{name}"));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a directory for this test's files");
        Self(path)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = self.0.join(name);
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(bytes).expect("write");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// R311y664 — a person with a capture and a key log runs one command and reads
/// the zenoh session out of a TLS flow.
///
/// Every round from R311y648 to R311y663 added something to this answer and
/// none of them could be reached this way: the workspace had no analyzer front
/// end at all.
#[test]
fn the_binary_decrypts_a_capture_given_a_key_log_on_the_command_line() {
    let scratch = Scratch::new("decrypts");
    let (file, log, _) = capture_and_key_log();
    let capture = scratch.write("session.pcapng", &file);
    let keylog = scratch.write("keys.txt", log.as_bytes());

    let out = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .arg("--keylog")
        .arg(&keylog)
        .arg("--json")
        .output()
        .expect("the binary runs");
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        stdout.contains("\"decrypted\":true"),
        "the tool must report the decryption it performed: {stdout}"
    );
    assert!(
        stdout.contains("\"records_decrypted\":3"),
        "with the record count: {stdout}"
    );
    assert!(
        stdout.contains("\"complete\":true"),
        "AND THE CAPTURE IS COMPLETE: a flow whose every record opened is not a \
         shortfall in the rows, it IS the rows: {stdout}"
    );

    // The TEXT rendering must agree with the JSON about the same run. It did
    // not until R311y664: `decrypted` was a fact in one and a constant in the
    // other, and the constant was in the rendering a person reads.
    let text = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .arg("--keylog")
        .arg(&keylog)
        .output()
        .expect("the binary runs");
    let text = String::from_utf8_lossy(&text.stdout).into_owned();
    assert!(
        text.contains("DECRYPTED: 1 flow(s), 3 record(s) opened"),
        "the text rendering must say what happened: {text}"
    );
    assert!(
        !text.contains("NOT DECRYPTED"),
        "and must not say the opposite in the same breath: {text}"
    );

    // WITHOUT the key log, the same capture and the same command produce the
    // finding and not the session -- so the assertions above are about the keys
    // and not about the fixture.
    let out = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .arg("--json")
        .output()
        .expect("the binary runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"decrypted\":false") && stdout.contains("\"frames\":0"),
        "keyless, the same capture must yield no session: {stdout}"
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "and the exit code must say the capture was not fully seen"
    );
}

/// R311y664 — the exit codes are three states and not two.
///
/// 0 is a capture this reader saw whole, 1 is one it did not, and 2 is the TOOL
/// failing. Collapsing the last two would make a script treat an unreadable
/// path and an encrypted flow as the same event.
#[test]
fn the_exit_code_separates_an_incomplete_capture_from_a_failed_run() {
    let scratch = Scratch::new("exit-codes");
    let (file, log, _) = capture_and_key_log();
    let capture = scratch.write("session.pcapng", &file);
    let keylog = scratch.write("keys.txt", log.as_bytes());

    let ok = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .arg("--keylog")
        .arg(&keylog)
        .output()
        .expect("runs");
    assert_eq!(
        ok.status.code(),
        Some(0),
        "a fully decrypted capture is complete: {}",
        String::from_utf8_lossy(&ok.stdout)
    );

    let missing = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(scratch.0.join("no-such-file.pcapng"))
        .output()
        .expect("runs");
    assert_eq!(
        missing.status.code(),
        Some(2),
        "a file that is not there is the TOOL failing, not an incomplete capture"
    );

    let junk = scratch.write("junk.bin", b"not a capture at all, by any magic");
    let bad = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&junk)
        .output()
        .expect("runs");
    assert_eq!(
        bad.status.code(),
        Some(2),
        "and neither is a file that does not parse -- an empty report about it \
         would read as a capture with nothing in it"
    );
}

/// R311y664 — a key log the caller named and that cannot be read is a hard
/// failure, not a quiet fallback.
///
/// Falling back to analysing without it produces a report saying the capture
/// could not be decrypted -- which is the wrong answer to the question that was
/// asked, delivered with an exit code that claims the tool worked.
#[test]
fn an_unreadable_key_log_fails_instead_of_reporting_the_capture_as_encrypted() {
    let scratch = Scratch::new("bad-keylog");
    let (file, _, _) = capture_and_key_log();
    let capture = scratch.write("session.pcapng", &file);

    let out = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .arg("--keylog")
        .arg(scratch.0.join("no-such-keylog.txt"))
        .output()
        .expect("runs");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        out.stdout.is_empty(),
        "and no report may be printed: a report here would be believed"
    );
}
