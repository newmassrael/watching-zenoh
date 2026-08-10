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
    tcp_segment(seq, payload, false)
}

/// R311y672 — the SAME connection, travelling the other way.
///
/// A `KeyUpdate` obligation crosses the two directions (RFC 8446 §4.6.3), so a
/// fixture for it needs both halves of one flow rather than two flows. The
/// addresses and ports are simply swapped, which is what makes the dissector fold
/// these packets into direction B of the connection the forward packets opened.
fn tcp_packet_reverse(seq: u32, payload: &[u8]) -> Vec<u8> {
    tcp_segment(seq, payload, true)
}

fn tcp_segment(seq: u32, payload: &[u8], reverse: bool) -> Vec<u8> {
    const CLIENT: [u8; 4] = [10, 0, 0, 1];
    const SERVER: [u8; 4] = [10, 0, 0, 2];
    const CLIENT_PORT: u16 = 1111;
    const SERVER_PORT: u16 = 7447;
    let (src, dst) = if reverse {
        (SERVER, CLIENT)
    } else {
        (CLIENT, SERVER)
    };
    let (src_port, dst_port) = if reverse {
        (SERVER_PORT, CLIENT_PORT)
    } else {
        (CLIENT_PORT, SERVER_PORT)
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

/// R311y672 — seal one record at one sequence number.
///
/// The epoch fixtures below each build several records under several generations,
/// and written out longhand the `OutboundPlainMessage` literal is nine lines that
/// say nothing. What varies between records is the content type, the plaintext
/// and the sequence — so those are the arguments, and everything else is stated
/// once here.
fn seal_at(
    enc: &mut Box<dyn rustls::crypto::cipher::MessageEncrypter>,
    typ: rustls::ContentType,
    payload: &[u8],
    seq: u64,
) -> Vec<u8> {
    enc.encrypt(
        OutboundPlainMessage {
            typ,
            version: rustls::ProtocolVersion::TLSv1_2,
            payload: rustls::crypto::cipher::OutboundChunks::Single(payload),
        },
        seq,
    )
    .expect("seal")
    .encode()
}

/// One length-framed zenoh KeepAlive, which is the smallest thing that makes a
/// decrypted record count as a message rather than as opened bytes.
fn unit(id: u8) -> Vec<u8> {
    let body = vec![0x04u8, id];
    let mut framed = (body.len() as u16).to_le_bytes().to_vec();
    framed.extend_from_slice(&body);
    framed
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
    // R311y665 — AND THE MESSAGE COUNT, which is the number the analyzer exists
    // to produce and which no line of the report carried until this round. The
    // three messages here are KeepAlives, so `sequence.frames` -- the only
    // frame-ish number the report had -- reads zero for them.
    assert!(
        stdout.contains("\"messages_decoded\":3"),
        "the report must say how many messages it read: {stdout}"
    );
    assert!(
        stdout.contains("\"frames\":0"),
        "and the pre-existing `sequence.frames` must still read zero, which is \
         what makes the new field a different question rather than a rename: \
         {stdout}"
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
        stdout.contains("\"decrypted\":false") && stdout.contains("\"messages_decoded\":0"),
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

/// R311y666 (§1.2a) — `--flows` names WHICH connection, which a summary cannot.
///
/// The capture-wide report answers "how much of this capture was unreadable".
/// With more than one peer in a file it cannot answer "which one" -- and that is
/// the question a person looking at a capture actually has. Every fact printed
/// here was already in the dissection and had no rendering at all.
#[test]
fn the_flows_option_names_which_connection_the_summary_cannot() {
    let scratch = Scratch::new("per-flow");
    let (file, log, _) = capture_and_key_log();
    let capture = scratch.write("session.pcapng", &file);
    let keylog = scratch.write("keys.txt", log.as_bytes());

    let out = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .arg("--keylog")
        .arg(&keylog)
        .arg("--flows")
        .output()
        .expect("runs");
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        stdout.contains("10.0.0.1:1111 <-> 10.0.0.2:7447"),
        "the endpoints must be named: {stdout}"
    );
    assert!(
        stdout.contains("tls") && stdout.contains("decrypted"),
        "with what the stream turned out to be and whether it was read: {stdout}"
    );
    assert!(
        stdout.contains("3 message(s)"),
        "and how many messages came out of THIS flow: {stdout}"
    );

    // WITHOUT the flag the same run prints no flow rows, so the assertions
    // above are about `--flows` and not about the summary having named them all
    // along.
    let plain = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .arg("--keylog")
        .arg(&keylog)
        .output()
        .expect("runs");
    let plain = String::from_utf8_lossy(&plain.stdout);
    assert!(
        !plain.contains("10.0.0.1:1111"),
        "the summary must not have named endpoints all along: {plain}"
    );
}

/// R311y667 (§1.2a) — `--json --flows` is ONE document.
///
/// R311y666 appended the flow list as a second JSON object on the same stream.
/// A consumer parsing that as a single value gets the first object and silently
/// ignores the second: the flows are there, the reader does not see them, and
/// nothing says so -- the exact failure this whole track exists to end, arriving
/// through the output format.
///
/// Checked structurally rather than by eye: the nesting depth returns to zero
/// exactly once, at the very end. Two documents return to zero twice.
#[test]
fn the_json_rendering_is_a_single_document_even_with_flows() {
    let scratch = Scratch::new("one-doc");
    let (file, log, _) = capture_and_key_log();
    let capture = scratch.write("session.pcapng", &file);
    let keylog = scratch.write("keys.txt", log.as_bytes());

    let out = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .arg("--keylog")
        .arg(&keylog)
        .arg("--json")
        .arg("--flows")
        .output()
        .expect("runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json = stdout.trim();

    assert!(
        json.contains("\"flows\":["),
        "the flow list must be in the output at all: {json}"
    );
    assert!(
        json.contains("10.0.0.1:1111"),
        "with the endpoints in it: {json}"
    );

    assert_one_document(json);
}

/// R311y667 (§1.2a) — the structural document-count check, ignoring braces
/// inside strings: the nesting depth must return to zero EXACTLY ONCE and at the
/// last character. Two documents on one stream return to zero twice, and a
/// consumer parsing the stream as one value sees only the first.
///
/// R311y668 — extracted, because a second flag combination now needs it and a
/// second hand-copied depth walker would be a second thing to get wrong.
fn assert_one_document(json: &str) {
    // R311y675 — VALIDITY first, and by a real parser rather than by this
    // function's own arithmetic.
    //
    // The bracket walk below answers "is this ONE value" -- which `serde_json`
    // cannot, since it stops at the end of the first one and never sees a second
    // document appended after it. It does NOT answer "is this valid", and the
    // difference is not hypothetical: R311y675 emitted a field array whose rows
    // were concatenated with no comma (`...}}{"from":...`), which is invalid
    // JSON and PERFECTLY BALANCED, so every assertion below passed on it. The
    // defect was caught by reading the output, which is not a gate.
    //
    // Both checks stay. Neither implies the other.
    if let Err(err) = serde_json::from_str::<serde_json::Value>(json) {
        panic!("the rendering must be valid JSON -- {err}: {json}");
    }
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    let mut closed_at: Vec<usize> = Vec::new();
    for (i, c) in json.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '{' | '[' => depth += 1,
            '}' | ']' => {
                depth -= 1;
                if depth == 0 {
                    closed_at.push(i);
                }
            }
            _ => {}
        }
    }
    assert_eq!(depth, 0, "the document must be balanced: {json}");
    assert_eq!(
        closed_at.len(),
        1,
        "the nesting must return to zero EXACTLY ONCE -- more than once is more \
         than one document, and a consumer sees only the first: {json}"
    );
    assert_eq!(
        closed_at[0],
        json.len() - 1,
        "and that once is the last character"
    );
}

/// R311y668 (§1.2a) — `--json --messages` carries the MESSAGES, in one document.
///
/// R311y667 added `--messages` inside the text branch only, so the JSON form
/// listed the flows and dropped their messages -- the same silent narrowing that
/// round closed in the document count, one field lower down. A consumer asking
/// for the messages got a well-formed document that did not contain them and
/// nothing said so.
///
/// The document count is re-asserted here rather than assumed from the `--flows`
/// case: the message list adds a nested ARRAY inside a nested array, which is
/// the shape a depth walker is most likely to be wrong about.
#[test]
fn the_json_listing_carries_the_messages_and_stays_one_document() {
    let scratch = Scratch::new("json-messages");
    let (file, log, _) = capture_and_key_log();
    let capture = scratch.write("session.pcapng", &file);
    let keylog = scratch.write("keys.txt", log.as_bytes());

    let run = |flag: &str| -> String {
        let out = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--keylog")
            .arg(&keylog)
            .arg("--json")
            .arg(flag)
            .output()
            .expect("runs");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    let with = run("--messages");
    assert_eq!(
        with.matches("\"name\":\"KeepAlive\"").count(),
        3,
        "each of the fixture's three decrypted messages must be in the JSON by \
         name: {with}"
    );
    assert!(
        with.contains("\"offset\":57")
            && with.contains("\"offset\":82")
            && with.contains("\"offset\":107"),
        "with the TCP-space offset that ties each one back to a packet: {with}"
    );
    assert!(
        with.contains("\"space\":\"transport\""),
        "and the namespace it was read in: {with}"
    );
    assert_one_document(&with);

    // The DISCRIMINATOR: without the flag the key is absent rather than empty,
    // so "not asked for" and "there were none" remain different answers.
    let without = run("--flows");
    assert!(
        !without.contains("message_list") && without.contains("\"messages\":3"),
        "--json --flows counts them and does not list them: {without}"
    );
    assert_one_document(&without);
}

/// R311y667 (§1.2a) — `--messages` lists the messages themselves.
///
/// Three rounds carried "the decoded messages have no rendering". A count says
/// how much was read; a list says WHAT was read, which is the question a person
/// opening a capture actually has -- and for a decrypted TLS flow those messages
/// are the entire point of the track that produced them.
#[test]
fn the_messages_option_lists_what_was_read_and_not_only_how_much() {
    let scratch = Scratch::new("messages");
    let (file, log, _) = capture_and_key_log();
    let capture = scratch.write("session.pcapng", &file);
    let keylog = scratch.write("keys.txt", log.as_bytes());

    let out = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .arg("--keylog")
        .arg(&keylog)
        .arg("--messages")
        .output()
        .expect("runs");
    let stdout = String::from_utf8_lossy(&out.stdout);

    // The fixture's three messages are KeepAlives, decrypted out of TLS.
    assert_eq!(
        stdout.matches("KeepAlive").count(),
        3,
        "each decoded message must appear BY NAME: {stdout}"
    );
    // The hello is 57 bytes and each sealed record is 25 (5 header + 3
    // plaintext + 1 inner content type + 16 tag), so the three records begin at
    // 57, 82 and 107 of the TCP stream. TCP-space, not plaintext-space -- which
    // is what ties a message back to a packet.
    assert!(
        stdout.contains("A @57") && stdout.contains("A @82") && stdout.contains("A @107"),
        "with the direction and the TCP-space offset of the record it came out \
         of: {stdout}"
    );

    // `--flows` alone gives the count and NOT the list, so the assertions above
    // are about `--messages`.
    let flows_only = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .arg("--keylog")
        .arg(&keylog)
        .arg("--flows")
        .output()
        .expect("runs");
    let flows_only = String::from_utf8_lossy(&flows_only.stdout);
    assert!(
        flows_only.contains("3 message(s)") && !flows_only.contains("KeepAlive"),
        "--flows counts them and does not name them: {flows_only}"
    );
}

/// R311y670 (§1.2a) — the two flags added this round REACH THE ANALYSIS.
///
/// The failure this gates is specific and this project has had it before: a flag
/// the parser reads, stores in `Options`, and that nothing downstream acts on.
/// The library test beside this one proves `parse` reads them; only the BINARY
/// can prove `main` passes them on. R311y669 shipped the message ceiling with no
/// caller at all -- `wz-analyze` passed `None` unconditionally -- which is that
/// shape one argument deep.
#[test]
fn the_quic_and_max_message_options_reach_the_analysis() {
    let scratch = Scratch::new("quic-flag");

    // A QUIC 1-RTT packet on 7447, whose first byte is a flagged zenoh MID.
    let mut one_rtt = vec![0x46u8];
    one_rtt.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);
    one_rtt.push(0x06);
    one_rtt.extend_from_slice(&[0xCC; 25]);
    let mut udp = Vec::new();
    udp.extend_from_slice(&50000u16.to_be_bytes());
    udp.extend_from_slice(&7447u16.to_be_bytes());
    udp.extend_from_slice(&((8 + one_rtt.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes());
    udp.extend_from_slice(&one_rtt);
    let mut ip = vec![0x45u8, 0];
    ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
    ip.extend_from_slice(&[10, 0, 0, 1]);
    ip.extend_from_slice(&[10, 0, 0, 2]);
    ip.extend_from_slice(&udp);
    let mut eth = vec![0u8; 12];
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&ip);
    while eth.len() < 60 {
        eth.push(0);
    }

    let file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &eth)],
    );
    let capture = scratch.write("mid.pcapng", &file);

    let run = |extra: &[&str]| -> String {
        let out = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--messages")
            .args(extra)
            .output()
            .expect("runs");
        String::from_utf8_lossy(&out.stdout).to_string()
    };

    // `--quic` reaches it: the zenoh reading disappears and the flow is named.
    let told = run(&["--quic", "7447"]);
    assert!(
        told.contains("messages decoded: 0") && told.contains("1 declared, not recognised"),
        "--quic must reach the analysis, not just the parser: {told}"
    );
    // And without it, the misread the flag exists for is present -- which is
    // what makes the assertion above about the flag rather than about the bytes.
    let blind = run(&[]);
    assert!(
        blind.contains("Fragment"),
        "the discriminating half: unflagged, this capture still reads as zenoh, \
         so the difference above is the flag's: {blind}"
    );

    // `--max-messages` reaches it too, on a capture with more than one message.
    let scouts = scratch.write("scouts.pcapng", &scouting_capture());
    let out = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&scouts)
        .arg("--messages")
        .arg("--max-messages")
        .arg("1")
        .output()
        .expect("runs");
    let capped = String::from_utf8_lossy(&out.stdout);
    assert!(
        capped.contains("... 2 more not listed"),
        "--max-messages must reach the analysis and say what it cut: {capped}"
    );
}

/// Three multicast SCOUTs, so a listing has something to cap.
fn scouting_capture() -> Vec<u8> {
    let scout = [0x01u8, 0x09, (3 << 4) | 0x08 | 0x03, 0x11, 0x22, 0x33, 0x44];
    let mut udp = Vec::new();
    udp.extend_from_slice(&43210u16.to_be_bytes());
    udp.extend_from_slice(&7446u16.to_be_bytes());
    udp.extend_from_slice(&((8 + scout.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes());
    udp.extend_from_slice(&scout);
    let mut ip = vec![0x45u8, 0];
    ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
    ip.extend_from_slice(&[192, 168, 1, 5]);
    ip.extend_from_slice(&[224, 0, 0, 224]);
    ip.extend_from_slice(&udp);
    let mut eth = vec![0u8; 12];
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&ip);
    while eth.len() < 60 {
        eth.push(0);
    }
    let refs: Vec<(u32, u64, &[u8])> = (0..3).map(|i| (0u32, 1_000_000 + i, &eth[..])).collect();
    wz_capture::pcapng::write(&[(wz_capture::link::LINKTYPE_ETHERNET, 6)], &refs)
}

/// R311y671 (§1.2a) — the EPOCH line reaches the rendering a person reads.
///
/// The witness values are asserted in `wz-tls-record`'s oracle suite; this is the
/// other half, and this project has been bitten by exactly the gap between them:
/// a fact computed correctly and rendered nowhere. The `epochs` line prints only
/// when there was a key change to report, so it needs a capture that REKEYS --
/// which no other fixture here has.
#[test]
fn the_epoch_line_reaches_the_rendering() {
    let scratch = Scratch::new("epochs");

    let gen0: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(11).wrapping_add(3))
        .collect();
    let gen1: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(29).wrapping_add(5))
        .collect();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(4));

    let unit = {
        let u = vec![0x04u8];
        let mut framed = (u.len() as u16).to_le_bytes().to_vec();
        framed.extend_from_slice(&u);
        framed
    };
    let mut stream = client_hello(&random);
    // Generation 0: one session record, then the KeyUpdate announcing the change.
    let mut a = sealer(&gen0);
    for (seq, (typ, body)) in [
        (rustls::ContentType::ApplicationData, unit.clone()),
        (
            rustls::ContentType::Handshake,
            b"\x18\x00\x00\x01\x00".to_vec(),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        stream.extend_from_slice(
            &a.encrypt(
                OutboundPlainMessage {
                    typ,
                    version: rustls::ProtocolVersion::TLSv1_2,
                    payload: rustls::crypto::cipher::OutboundChunks::Single(&body),
                },
                seq as u64,
            )
            .expect("seal")
            .encode(),
        );
    }
    // Generation 1, sequence from zero.
    let mut b = sealer(&gen1);
    stream.extend_from_slice(
        &b.encrypt(
            OutboundPlainMessage {
                typ: rustls::ContentType::ApplicationData,
                version: rustls::ProtocolVersion::TLSv1_2,
                payload: rustls::crypto::cipher::OutboundChunks::Single(&unit),
            },
            0,
        )
        .expect("seal")
        .encode(),
    );

    let file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &tcp_packet(1000, &stream))],
    );
    let capture = scratch.write("rekey.pcapng", &file);
    let log = format!(
        "CLIENT_TRAFFIC_SECRET_0 {} {}\nCLIENT_TRAFFIC_SECRET_1 {} {}\n",
        hex(&random),
        hex(&gen0),
        hex(&random),
        hex(&gen1)
    );
    let keylog = scratch.write("keys.txt", log.as_bytes());

    let out = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .arg("--keylog")
        .arg(&keylog)
        .output()
        .expect("runs");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("epochs: 1 key change(s), 1 confirmed by a KeyUpdate"),
        "the epoch witness must reach the text a person reads: {text}"
    );
    assert!(
        text.contains("1 KeyUpdate message(s) read"),
        "including that the announcement itself was opened: {text}"
    );
    // A confirmed change prints no caveat; the caveat belongs to the other case.
    assert!(
        !text.contains("rests on the trial alone"),
        "a confirmed change needs no hedge: {text}"
    );

    // And the JSON carries the same numbers, structurally.
    let out = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .arg("--keylog")
        .arg(&keylog)
        .arg("--json")
        .output()
        .expect("runs");
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(
        json.contains(
            "\"epochs\":{\"advances\":1,\"advances_confirmed\":1,\
             \"advances_unannounced\":0,\"advances_unwitnessed\":0,\
             \"key_updates\":1,\"updates_requested\":0,\
             \"updates_answering\":0,\"requests_unanswered\":0}"
        ),
        "and the JSON must agree with the text, in one document: {json}"
    );
    assert_one_document(json.trim());
}

/// R311y672 (§1.2a) — an unconfirmed key change says WHICH KIND it is, and the
/// two kinds are told apart by the SAME run.
///
/// ## The defect this pins, measured before the fix
///
/// R311y671 reported `advances` and `advances_confirmed` and let the reader
/// subtract. The difference has two causes that call for opposite responses:
///
/// - the handshake-to-application boundary, which TLS ends with an encrypted
///   `Finished` and never announces, so nothing was missed; and
/// - a rekey, which RFC 8446 §4.6.3 says IS announced, so an unconfirmed one
///   means the announcement was missed or the trial crossed on a coincidence.
///
/// Both printed the same figure and the same parenthetical. Measured on this
/// fixture under the old rendering: `epochs: 2 key change(s), 0 confirmed`, with
/// one hedge covering both — a reader could not tell that exactly one of the two
/// was worth investigating.
///
/// ## Why the fixture carries BOTH in one capture
///
/// Separately, each leg passes against a renderer that simply relabelled the
/// single count: call every unconfirmed advance "unannounced" and the
/// handshake-boundary capture is right; call them all "unwitnessed" and the
/// mid-session one is. Only a capture holding one of each fails both of those.
#[test]
fn an_unconfirmed_key_change_distinguishes_the_announced_boundary_from_the_silent_one() {
    let scratch = Scratch::new("epoch-kinds");
    let handshake: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(11).wrapping_add(5))
        .collect();
    let gen0: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(29).wrapping_add(6))
        .collect();
    let gen1: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(31).wrapping_add(7))
        .collect();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(19).wrapping_add(2));

    let mut stream = client_hello(&random);
    // Epoch 0: the handshake flight. No KeyUpdate ends it -- TLS sends none.
    let mut hs = sealer(&handshake);
    stream.extend_from_slice(&seal_at(
        &mut hs,
        rustls::ContentType::Handshake,
        b"\x14\x00\x00\x02\x00\x00",
        0,
    ));
    // Epoch 1: the first application generation. Reached WITHOUT an announcement,
    // which is the expected kind.
    let mut app0 = sealer(&gen0);
    stream.extend_from_slice(&seal_at(
        &mut app0,
        rustls::ContentType::ApplicationData,
        &unit(0),
        0,
    ));
    // Epoch 2: a REKEY, and deliberately with no KeyUpdate in front of it -- the
    // announcing record is the one a mid-session tap or a hole would have missed.
    let mut app1 = sealer(&gen1);
    stream.extend_from_slice(&seal_at(
        &mut app1,
        rustls::ContentType::ApplicationData,
        &unit(1),
        0,
    ));

    let file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &tcp_packet(1000, &stream))],
    );
    let capture = scratch.write("epoch-kinds.pcapng", &file);
    let keylog = scratch.write(
        "keys.txt",
        format!(
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}\n\
             CLIENT_TRAFFIC_SECRET_0 {} {}\n\
             CLIENT_TRAFFIC_SECRET_1 {} {}\n",
            hex(&random),
            hex(&handshake),
            hex(&random),
            hex(&gen0),
            hex(&random),
            hex(&gen1)
        )
        .as_bytes(),
    );

    let out = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .arg("--keylog")
        .arg(&keylog)
        .output()
        .expect("runs");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("epochs: 2 key change(s), 0 confirmed by a KeyUpdate"),
        "two boundaries were crossed and neither was announced: {text}"
    );
    assert!(
        text.contains("1 crossed a boundary TLS never announces"),
        "the handshake-to-application boundary is the harmless one: {text}"
    );
    assert!(
        text.contains("1 was a rekey with NO KeyUpdate behind it"),
        "and the rekey is the one worth looking at -- naming them the same way \
         is what this round replaces: {text}"
    );

    let out = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .arg("--keylog")
        .arg(&keylog)
        .arg("--json")
        .output()
        .expect("runs");
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(
        json.contains("\"advances\":2,\"advances_confirmed\":0,\"advances_unannounced\":1,\"advances_unwitnessed\":1"),
        "the split reaches JSON too, and the three parts must sum to the whole: {json}"
    );
    assert_one_document(json.trim());
}

/// R311y672 (§1.2a) — the `update_requested` byte is READ, and it attributes a
/// key change on the OTHER direction.
///
/// ## What was missing
///
/// `KeyUpdate` carries a one-byte body (RFC 8446 §4.6.3). `update_requested` (1)
/// obliges the PEER to send its own `KeyUpdate` in reply; `update_not_requested`
/// (0) does not. R311y671 opened the message, checked its type byte, and never
/// looked at the body — so the one fact in this protocol that crosses the two
/// directions was on the floor, and each direction could only ever confirm its
/// own advances.
///
/// ## The discriminating shape
///
/// The client sends `update_requested`; the server answers with its own
/// `KeyUpdate` and rekeys. If the body byte were still ignored, `updates_answering`
/// would be 0 here — the server's message would be an unrelated announcement
/// rather than the discharge of an obligation — while every other figure in the
/// report stayed exactly as it is.
#[test]
fn a_key_update_requesting_one_back_attributes_the_peers_change() {
    let scratch = Scratch::new("epoch-request");
    let c0: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(37).wrapping_add(1))
        .collect();
    let c1: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(41).wrapping_add(2))
        .collect();
    let s0: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(43).wrapping_add(3))
        .collect();
    let s1: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(47).wrapping_add(4))
        .collect();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(23).wrapping_add(5));

    // Client: one record, then a KeyUpdate whose body is `update_requested` (1),
    // then its own new generation.
    let mut client = client_hello(&random);
    let mut cg0 = sealer(&c0);
    client.extend_from_slice(&seal_at(
        &mut cg0,
        rustls::ContentType::ApplicationData,
        &unit(0),
        0,
    ));
    client.extend_from_slice(&seal_at(
        &mut cg0,
        rustls::ContentType::Handshake,
        b"\x18\x00\x00\x01\x01",
        1,
    ));
    let mut cg1 = sealer(&c1);
    client.extend_from_slice(&seal_at(
        &mut cg1,
        rustls::ContentType::ApplicationData,
        &unit(1),
        0,
    ));

    // Server: the obliged reply -- `update_not_requested`, because answering a
    // request must not start an infinite exchange -- and then its own new key.
    let mut server = Vec::new();
    let mut sg0 = sealer(&s0);
    server.extend_from_slice(&seal_at(
        &mut sg0,
        rustls::ContentType::ApplicationData,
        &unit(2),
        0,
    ));
    server.extend_from_slice(&seal_at(
        &mut sg0,
        rustls::ContentType::Handshake,
        b"\x18\x00\x00\x01\x00",
        1,
    ));
    let mut sg1 = sealer(&s1);
    server.extend_from_slice(&seal_at(
        &mut sg1,
        rustls::ContentType::ApplicationData,
        &unit(3),
        0,
    ));

    let file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[
            (0, 1_000_000, &tcp_packet(1000, &client)),
            (0, 1_000_100, &tcp_packet_reverse(1000, &server)),
        ],
    );
    let capture = scratch.write("epoch-request.pcapng", &file);
    let keylog = scratch.write(
        "keys.txt",
        format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\nCLIENT_TRAFFIC_SECRET_1 {} {}\n\
             SERVER_TRAFFIC_SECRET_0 {} {}\nSERVER_TRAFFIC_SECRET_1 {} {}\n",
            hex(&random),
            hex(&c0),
            hex(&random),
            hex(&c1),
            hex(&random),
            hex(&s0),
            hex(&random),
            hex(&s1)
        )
        .as_bytes(),
    );

    let out = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .arg("--keylog")
        .arg(&keylog)
        .arg("--json")
        .output()
        .expect("runs");
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(
        json.contains("\"key_updates\":2,\"updates_requested\":1,\"updates_answering\":1"),
        "two announcements, ONE of which demanded a reply, and the peer's message \
         is recognised AS that reply: {json}"
    );
    assert!(
        json.contains("\"requests_unanswered\":0"),
        "the obligation was discharged, so nothing is outstanding: {json}"
    );
    assert_one_document(json.trim());

    let text = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--keylog")
            .arg(&keylog)
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    assert!(
        text.contains("1 KeyUpdate(s) asked the peer to rekey; 1 answered"),
        "and a person reading the report is told so: {text}"
    );
}

/// R311y672 (§1.2a) — THE DISCRIMINATING NEGATIVE for the byte: a `KeyUpdate`
/// carrying `update_not_requested` demands nothing.
///
/// Without this leg, `updates_requested` could be a copy of `key_updates` and the
/// test above would pass unchanged. This is the same fixture as the confirming
/// one with the single body byte flipped from `\x01` to `\x00`, so the byte is
/// the only difference between the two measurements.
#[test]
fn a_key_update_not_requesting_one_back_demands_nothing() {
    let scratch = Scratch::new("epoch-norequest");
    let c0: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(37).wrapping_add(1))
        .collect();
    let c1: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(41).wrapping_add(2))
        .collect();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(23).wrapping_add(5));

    let mut client = client_hello(&random);
    let mut cg0 = sealer(&c0);
    client.extend_from_slice(&seal_at(
        &mut cg0,
        rustls::ContentType::ApplicationData,
        &unit(0),
        0,
    ));
    // The ONLY difference from the test above: `\x00` where that one has `\x01`.
    client.extend_from_slice(&seal_at(
        &mut cg0,
        rustls::ContentType::Handshake,
        b"\x18\x00\x00\x01\x00",
        1,
    ));
    let mut cg1 = sealer(&c1);
    client.extend_from_slice(&seal_at(
        &mut cg1,
        rustls::ContentType::ApplicationData,
        &unit(1),
        0,
    ));

    let file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &tcp_packet(1000, &client))],
    );
    let capture = scratch.write("epoch-norequest.pcapng", &file);
    let keylog = scratch.write(
        "keys.txt",
        format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\nCLIENT_TRAFFIC_SECRET_1 {} {}\n",
            hex(&random),
            hex(&c0),
            hex(&random),
            hex(&c1)
        )
        .as_bytes(),
    );

    let out = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .arg("--keylog")
        .arg(&keylog)
        .arg("--json")
        .output()
        .expect("runs");
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(
        json.contains("\"key_updates\":1,\"updates_requested\":0,\"updates_answering\":0"),
        "the message was read and it asked for NOTHING -- a count that cannot \
         say this is a count that is not reading the byte: {json}"
    );
    assert!(
        json.contains("\"requests_unanswered\":0"),
        "and no obligation was created, so none can be outstanding: {json}"
    );
    assert_one_document(json.trim());
}

/// R311y672 (§1.2a) — a request the capture never sees answered is REPORTED.
///
/// The obligation is the reason an expected key change on the other direction is
/// absent. A capture that ends between the demand and the reply — the ordinary
/// shape of a tap stopped by hand — otherwise shows a peer that simply never
/// rekeyed, with nothing anywhere saying it had been asked to.
#[test]
fn a_request_the_peer_never_answered_is_reported_as_outstanding() {
    let scratch = Scratch::new("epoch-outstanding");
    let c0: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(53).wrapping_add(1))
        .collect();
    let c1: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(59).wrapping_add(2))
        .collect();
    let s0: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(61).wrapping_add(3))
        .collect();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(29).wrapping_add(11));

    let mut client = client_hello(&random);
    let mut cg0 = sealer(&c0);
    client.extend_from_slice(&seal_at(
        &mut cg0,
        rustls::ContentType::Handshake,
        b"\x18\x00\x00\x01\x01",
        0,
    ));
    let mut cg1 = sealer(&c1);
    client.extend_from_slice(&seal_at(
        &mut cg1,
        rustls::ContentType::ApplicationData,
        &unit(1),
        0,
    ));

    // The server sends ordinary traffic and never the KeyUpdate it owes: the
    // capture stopped first.
    let mut server = Vec::new();
    let mut sg0 = sealer(&s0);
    server.extend_from_slice(&seal_at(
        &mut sg0,
        rustls::ContentType::ApplicationData,
        &unit(2),
        0,
    ));

    let file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[
            (0, 1_000_000, &tcp_packet(1000, &client)),
            (0, 1_000_100, &tcp_packet_reverse(1000, &server)),
        ],
    );
    let capture = scratch.write("epoch-outstanding.pcapng", &file);
    let keylog = scratch.write(
        "keys.txt",
        format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\nCLIENT_TRAFFIC_SECRET_1 {} {}\n\
             SERVER_TRAFFIC_SECRET_0 {} {}\n",
            hex(&random),
            hex(&c0),
            hex(&random),
            hex(&c1),
            hex(&random),
            hex(&s0)
        )
        .as_bytes(),
    );

    let text = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--keylog")
            .arg(&keylog)
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    assert!(
        text.contains("1 request(s) still unanswered when the capture ended"),
        "the demand was read and the reply never came, and BOTH halves of that \
         have to be in the report for either to mean anything: {text}"
    );

    let json = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--keylog")
            .arg(&keylog)
            .arg("--json")
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    assert!(
        json.contains("\"updates_requested\":1,\"updates_answering\":0,\"requests_unanswered\":1"),
        "and the same three numbers in JSON: {json}"
    );
    assert_one_document(json.trim());
}

/// R311y672 (§1.2a) — the `KeyUpdate` scan reads the RFC's framing, not the
/// first byte.
///
/// ## Two defects in one look
///
/// R311y671 asked `plaintext.first() == Some(&HS_KEY_UPDATE)`, which fails in
/// both directions at once:
///
/// - a handshake record may carry SEVERAL messages back to back, and
///   post-handshake the common shape is a `NewSessionTicket` followed by
///   something else — so a `KeyUpdate` that is not first was invisible, and the
///   epoch it announced went unconfirmed; and
/// - the declared body length was never checked, so any record whose first
///   plaintext byte happened to be 24 confirmed a boundary it never announced.
///
/// ## Why the fixture needs TWO hidden messages and one malformed one
///
/// Measured, not reasoned: the obvious fixture -- one `KeyUpdate` behind a ticket
/// plus one ill-framed type-24 message -- was written first and PASSED against
/// the old look. The two defects cancel exactly. The old look misses the hidden
/// message (one false negative) and accepts the malformed one (one false
/// positive), so its total is 1 and the walk's total is 1, and every assertion
/// about that total holds under both. The pending announcement survives the same
/// way, so `advances_confirmed` matched too.
///
/// So the counts are made to DIFFER rather than merely be right: two well-framed
/// `KeyUpdate`s hidden behind tickets, one ill-framed message, three generations.
/// The walk reads 2; the old look reads 1 and leaves the second boundary
/// unconfirmed.
#[test]
fn a_key_update_is_found_by_framing_rather_than_by_the_first_byte() {
    let scratch = Scratch::new("epoch-framing");
    let c0: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(67).wrapping_add(1))
        .collect();
    let c1: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(71).wrapping_add(2))
        .collect();
    let c2: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(73).wrapping_add(3))
        .collect();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(13));

    let mut client = client_hello(&random);
    let mut cg0 = sealer(&c0);
    // A NewSessionTicket (type 4, body 3 bytes) and THEN the real KeyUpdate, in
    // one record. The old look saw only the ticket and stopped.
    client.extend_from_slice(&seal_at(
        &mut cg0,
        rustls::ContentType::Handshake,
        b"\x04\x00\x00\x03\xaa\xbb\xcc\x18\x00\x00\x01\x01",
        0,
    ));
    // A malformed message of type 24: the `uint24` length says 4, and a KeyUpdate
    // body is one byte. Counted by the old look, refused by the framing walk.
    client.extend_from_slice(&seal_at(
        &mut cg0,
        rustls::ContentType::Handshake,
        b"\x18\x00\x00\x04\x00\x00\x00\x00",
        1,
    ));
    // Generation 1, and a second hidden KeyUpdate announcing generation 2.
    let mut cg1 = sealer(&c1);
    client.extend_from_slice(&seal_at(
        &mut cg1,
        rustls::ContentType::ApplicationData,
        &unit(1),
        0,
    ));
    client.extend_from_slice(&seal_at(
        &mut cg1,
        rustls::ContentType::Handshake,
        b"\x04\x00\x00\x03\xdd\xee\xff\x18\x00\x00\x01\x00",
        1,
    ));
    let mut cg2 = sealer(&c2);
    client.extend_from_slice(&seal_at(
        &mut cg2,
        rustls::ContentType::ApplicationData,
        &unit(2),
        0,
    ));

    let file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &tcp_packet(1000, &client))],
    );
    let capture = scratch.write("epoch-framing.pcapng", &file);
    let keylog = scratch.write(
        "keys.txt",
        format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\nCLIENT_TRAFFIC_SECRET_1 {} {}\n\
             CLIENT_TRAFFIC_SECRET_2 {} {}\n",
            hex(&random),
            hex(&c0),
            hex(&random),
            hex(&c1),
            hex(&random),
            hex(&c2)
        )
        .as_bytes(),
    );

    let json = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--keylog")
            .arg(&keylog)
            .arg("--json")
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    assert!(
        json.contains("\"key_updates\":2,\"updates_requested\":1"),
        "EXACTLY the two well-framed messages, both of them behind a ticket, and \
         NOT the ill-framed one -- a look at the first byte reads 1 here: {json}"
    );
    assert!(
        json.contains("\"advances\":2,\"advances_confirmed\":2,\"advances_unannounced\":0,\"advances_unwitnessed\":0"),
        "and both boundaries are confirmed by the message that announced them; \
         missing the second hidden one leaves it an unwitnessed rekey: {json}"
    );
    assert_one_document(json.trim());
}

/// R311y673 (§1.2a) — a sender-space keyexpr with a literal suffix.
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

/// One network message wrapped in a transport `Frame` and length-framed for a
/// stream link, which is what a TLS record carries.
fn framed_frame(record: &[u8]) -> Vec<u8> {
    let mut frame = vec![wz_session_core::wire_const::T_MID_FRAME, 0x00];
    frame.extend_from_slice(record);
    let mut out = (frame.len() as u16).to_le_bytes().to_vec();
    out.extend_from_slice(&frame);
    out
}

/// A `Request` carrying a `Query` for `suffix`, under `rid`.
fn query(rid: u64, suffix: &'static str) -> Vec<u8> {
    wz_codecs::request::Request {
        header: wz_codecs::request::Request::default().header | wz_codecs::wire_const::FLAG_N_N,
        rid,
        keyexpr: keyexpr(suffix),
        body: wz_codecs::request::RequestVariant::CodecZenohQuery(
            wz_codecs::query::Query::default(),
        ),
        ..Default::default()
    }
    .encode_to_vec()
}

/// The `Response` that answers it, carrying `payload`.
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

/// The closing `ResponseFinal`.
fn response_final(request_id: u64) -> Vec<u8> {
    wz_codecs::response_final::ResponseFinal {
        request_id,
        ..Default::default()
    }
    .encode_to_vec()
}

/// A cleartext TCP capture of ONE query exchange: the client asks, the server
/// replies and closes.
fn exchange_capture() -> Vec<u8> {
    let mut client = Vec::new();
    client.extend_from_slice(&framed_frame(&query(7, "demo/**")));
    let mut server = Vec::new();
    server.extend_from_slice(&framed_frame(&reply(7, "demo/a", b"first")));
    server.extend_from_slice(&framed_frame(&response_final(7)));
    wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[
            (0, 1_000_000, &tcp_packet(1000, &client)),
            (0, 1_030_000, &tcp_packet_reverse(1000, &server)),
        ],
    )
}

/// R311y673 (§1.2a) — THE THREE OBSERVER PLANES REACH THE PROGRAM A PERSON RUNS.
///
/// ## What was measured, and it is the reason this crate exists said twice
///
/// `CaptureReport` has taken a throughput table, an exchange table and a payload
/// census for many rounds, and `to_text` / `to_json` render all three when they
/// are attached. Swept for consumers, `with_throughput` / `with_exchanges` /
/// `with_payloads` had exactly ONE call site each -- `report.rs`'s own
/// `#[cfg(test)]` module -- and `wz-analyze` had NONE. Measured with the
/// R311y654 question ("which public accessor has no consumer") applied to the
/// rest of the crate, which R311y660 recorded as still unasked.
///
/// So the shipped analyzer could not say which keyexpr carried the traffic, how
/// long a query took to answer, or what the samples held. Those planes are the
/// bulk of what `wz-capture` knows, and the tool a person runs attached none of
/// them.
///
/// ## Why the fixture carries a real query exchange
///
/// A capture of KeepAlives makes all three planes answer zero, HONESTLY -- and a
/// test pinning those zeroes would pass equally against planes that were never
/// handed a frame. Measured that way first: the KeepAlive fixture prints
/// `throughput: 0 of 0`, which is the same string a plane built from an empty
/// dissection prints. The numbers here are non-zero, so a wiring that reached the
/// renderer without reaching the data cannot produce them.
#[test]
fn the_census_planes_reach_the_command_line() {
    let scratch = Scratch::new("census");
    let capture = scratch.write("census.pcapng", &exchange_capture());

    let text = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--census")
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    assert!(
        text.contains("exchanges: 1 request(s), 1 completed, 0 unclosed"),
        "the exchange plane must have CORRELATED the reply to the query -- a \
         plane handed no frames reports 0 requests and reads identical to a \
         capture with no queries in it: {text}"
    );
    // 2 of 3, not 3 of 3, and the difference is the point: the closing
    // `ResponseFinal` carries no keyexpr, so it is walked and NOT attributed.
    // Measured rather than predicted -- this assertion was first written as
    // `2 of 2` and the run corrected it.
    assert!(
        text.contains("throughput: 2 of 3 record(s) attributed, 5 bytes"),
        "and the throughput plane must have attributed the two keyed records: \
         {text}"
    );
    assert!(
        text.contains("demo/**") && text.contains("demo/a"),
        "with the keyexpr ROWS, which are the plane's actual answer to `which \
         keyexpr carries the traffic` and were unreachable from a command line \
         until this round: {text}"
    );
    assert!(
        text.contains("first reply 30ms"),
        "and the exchange plane's latency, measured against the capture's own \
         clock (the reply packet is stamped 30ms after the query): {text}"
    );
    assert!(
        text.contains("payloads: 1 judged"),
        "and the payload plane must have judged the reply's bytes: {text}"
    );

    // WITHOUT the flag, none of the three is built and none of the three lines
    // appears. This is the other half of the claim: the planes are a REQUEST,
    // because each is a separate walk of every frame and the cost of walking
    // them three times has never been measured here.
    let bare = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    for plane in ["throughput:", "exchanges:", "payloads:"] {
        assert!(
            !bare.contains(plane),
            "`{plane}` must be absent without --census: {bare}"
        );
    }
    assert!(
        bare.contains("messages decoded: 3"),
        "while the capture itself reads exactly the same either way: {bare}"
    );
}

/// R311y673 (§1.2a) — each plane flag turns on ITS OWN plane and no other.
///
/// Without this, `--census` could be the only path that works and the three
/// single flags could all set the same bit -- or `Census::all()` could be
/// returned from every arm. Each is asserted to bring exactly one line.
#[test]
fn each_census_flag_builds_only_its_own_plane() {
    let scratch = Scratch::new("census-each");
    let capture = scratch.write("census.pcapng", &exchange_capture());

    for (flag, mine, others) in [
        ("--throughput", "throughput:", ["exchanges:", "payloads:"]),
        ("--exchanges", "exchanges:", ["throughput:", "payloads:"]),
        ("--payloads", "payloads:", ["throughput:", "exchanges:"]),
    ] {
        let text = String::from_utf8_lossy(
            &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
                .arg(&capture)
                .arg(flag)
                .output()
                .expect("runs")
                .stdout,
        )
        .into_owned();
        assert!(text.contains(mine), "{flag} must build {mine}: {text}");
        for other in others {
            assert!(
                !text.contains(other),
                "{flag} must NOT build {other}: {text}"
            );
        }
    }
}

/// R311y673 (§1.2a) — the JSON carries the planes too, in ONE document.
///
/// The text and JSON renderings are two paths over one fact, and this workspace
/// has measured them disagreeing (R311y664: a flow reported decrypted in JSON and
/// NOT DECRYPTED in text, in the same run). Asserted in the same test for that
/// reason.
#[test]
fn the_census_planes_reach_the_json_as_one_document() {
    let scratch = Scratch::new("census-json");
    let capture = scratch.write("census.pcapng", &exchange_capture());

    let json = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--census")
            .arg("--json")
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    assert!(json.contains("\"throughput\""), "throughput key: {json}");
    assert!(json.contains("\"exchanges\""), "exchanges key: {json}");
    assert!(json.contains("\"payloads\""), "payloads key: {json}");
    assert_one_document(json.trim());
}

/// R311y674 (§1.2a) — THE SELECTOR reaches the command line.
///
/// ## What was measured
///
/// `wz-capture::filter` is a language: a lexer, a three-valued evaluator, six
/// fields, wildcards behind their own feature, and `aggregate_where` /
/// `exchanges_where` / `payloads_where` to fold under it. Swept for consumers,
/// every call site of all four was inside `wz-capture`'s own tests. R311y673
/// made the planes reachable and that made this visible in the same breath: the
/// tool emitted the WHOLE keyexpr tree with no way to ask about one subtree,
/// which is the R311y642 item arriving where a reader can see it.
///
/// ## What the narrowed report must still say
///
/// The three planes report a [`Selection`] -- matched, rejected, and UNDECIDED --
/// and the last is the one that matters. A keyexpr whose declaration went past
/// before the tap started cannot be judged, and a filter that counted it as a
/// non-match would hand back a total that is quietly short. That line was
/// rendered by `report.rs` already and nothing could produce it.
#[test]
fn a_selector_narrows_the_census_planes_and_says_what_it_left_out() {
    let scratch = Scratch::new("select");
    let capture = scratch.write("select.pcapng", &exchange_capture());
    let run = |args: &[&str]| {
        String::from_utf8_lossy(
            &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
                .arg(&capture)
                .args(args)
                .output()
                .expect("runs")
                .stdout,
        )
        .into_owned()
    };

    // Unfiltered: BOTH keyexprs are in the rows. This is the control -- without
    // it, a selector that rejected everything would satisfy every assertion
    // below about what is absent.
    let all = run(&["--census"]);
    assert!(
        all.contains("demo/a") && all.contains("demo/**"),
        "the control must carry both rows: {all}"
    );

    let one = run(&["--census", "--select", "key == demo/a"]);
    assert!(
        one.contains("selection: 1 matched, 1 rejected, 0 UNDECIDED"),
        "the plane must say what the selector left out, not merely show fewer \
         rows: {one}"
    );
    assert!(
        one.contains("throughput: 1 of 2 record(s) attributed, 5 bytes"),
        "and the narrowed totals are the selected records' own: {one}"
    );
    assert!(
        one.contains("demo/a") && !one.contains("demo/**"),
        "the rejected keyexpr must be gone from the rows: {one}"
    );

    // A DIFFERENT field, so the wiring is not one term deep: `kind` selects the
    // query and its exchange, where `key == demo/a` selected the reply.
    let queries = run(&["--census", "--select", "kind == query"]);
    assert!(
        queries.contains("exchanges: 1 request(s), 1 completed"),
        "the exchange plane folds under the selector too: {queries}"
    );
    assert!(
        queries.contains("demo/**") && !queries.contains("demo/a"),
        "and it selected the OTHER record than the key term did, which is what \
         makes this a second term rather than the same one twice: {queries}"
    );
}

/// R311y674 (§1.2a) — a selector that does not parse is refused, with the
/// PARSER's own reason.
///
/// `--select` could have joined `--quic` under `BadValue` and printed
/// "--select does not take `key = demo/**`". The filter language writes a
/// column-accurate message and throwing it away would make a typo in a
/// six-field language a guessing game.
#[test]
fn a_selector_that_does_not_parse_is_refused_with_the_parsers_own_reason() {
    let scratch = Scratch::new("select-bad");
    let capture = scratch.write("select.pcapng", &exchange_capture());
    let out = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .args(["--census", "--select", "key = demo/**"])
        .output()
        .expect("runs");
    assert_eq!(
        out.status.code(),
        Some(2),
        "a bad command line is this tool failing (2), not the capture being \
         incomplete (1)"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--select: at byte 4: unexpected character '='"),
        "the parser's own column-accurate reason must survive to the terminal: \
         {err}"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).is_empty(),
        "and nothing is reported about a capture that was never analysed"
    );
}

/// R311y674 (§1.2a) — a selector with no plane to narrow is REFUSED.
///
/// The three census planes are the only thing a selector narrows, so `--select`
/// without one changes nothing about the output. A flag that silently does
/// nothing is exactly the shape this workspace turns into a refusal wherever a
/// person typed the input, and the message names the flags that would make it
/// mean something.
#[test]
fn a_selector_with_no_plane_to_narrow_is_refused_rather_than_ignored() {
    let scratch = Scratch::new("select-noplane");
    let capture = scratch.write("select.pcapng", &exchange_capture());
    let out = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .args(["--select", "key == demo/a"])
        .output()
        .expect("runs");
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--select narrows the census planes and none was asked for"),
        "refused by name: {err}"
    );
    assert!(
        err.contains("--census"),
        "and the message says what would make it mean something: {err}"
    );
}

/// R311y675 (§1.1n) — THE FIELD LAYER: the reader can name which BYTES are the
/// keyexpr.
///
/// ## The requirement, in the store's own words
///
/// R311y645's carry: "The analyzer's finest coordinate is a RECORD -- it can now
/// point at the bytes a record begins at and cannot say which of them are the
/// keyexpr's length prefix." R311y641's: "A reader can now locate a record and
/// still not locate the keyexpr inside it." `wz-session-core::dissect` walks
/// every message into per-field spans and nothing in the reader called a single
/// `walk_*`.
///
/// ## Why the spans are the assertion and the names are not
///
/// A rendering that printed the field NAMES and got the byte ranges wrong would
/// look right and be useless, which is the whole failure this layer exists to
/// prevent. So the assertions are on the RANGES, and specifically on ranges that
/// pin the coordinate base: the frame begins at 2, not 0, because
/// `stream_offset` names the length PREFIX and the message starts
/// `prefix_width` bytes later. A walk handed the wrong base produces a tree that
/// is internally consistent and points at the wrong bytes.
#[test]
fn the_field_layer_names_which_bytes_are_the_keyexpr() {
    let scratch = Scratch::new("fields");
    let capture = scratch.write("fields.pcapng", &exchange_capture());

    let text = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--fields")
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();

    // THE CLAIM: the keyexpr's length prefix and its text are separately
    // located, to the byte. This is the sentence R311y645 said could not be
    // produced.
    assert!(
        text.contains("[5..6] suffix_len = Uint(7)"),
        "the keyexpr's LENGTH PREFIX is one byte at offset 5 OF THE MESSAGE: \
         {text}"
    );
    assert!(
        text.contains("[6..13] suffix = Text(\"demo/**\")"),
        "and the seven bytes after it are the keyexpr itself: {text}"
    );
    // R311y677 — spans are MESSAGE-RELATIVE, one space for every row. R311y675
    // passed the stream offset here, which made a cleartext row absolute and a
    // decrypted row -- whose plaintext has no position in the stream -- relative,
    // in one listing, marked by nothing.
    //
    // The discriminator is now the message's own LENGTH: the framed unit is 14
    // bytes, so a walk handed the wrong bytes cannot produce `[0..14]` with the
    // right fields inside it.
    assert!(
        text.contains("[0..14] Frame"),
        "the frame spans the whole message and nothing else: {text}"
    );
    assert!(
        text.contains("[1..2] sn = Uint(0)"),
        "and the transport sequence number is the byte after the header: {text}"
    );
    // The DIRECTION is the other half of a coordinate: B travels the other way,
    // and printing the endpoints in table order for both would say every
    // message went the same direction.
    assert!(
        text.contains("10.0.0.1:1111 -> 10.0.0.2:7447 A"),
        "the query travels client to server: {text}"
    );
    assert!(
        text.contains("10.0.0.2:7447 -> 10.0.0.1:1111 B"),
        "and the reply travels back: {text}"
    );

    // Without the flag, none of it. The walk is a REQUEST -- it re-reads the
    // retained bytes rather than keeping a copy, and a reader who did not ask
    // for it should not pay for it.
    let bare = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    assert!(
        !bare.contains("suffix_len") && !bare.contains("fields:"),
        "no field layer without --fields: {bare}"
    );
}

/// R311y675 (§1.1n) — the field layer reaches JSON as ONE document.
#[test]
fn the_field_layer_reaches_the_json_as_one_document() {
    let scratch = Scratch::new("fields-json");
    let capture = scratch.write("fields.pcapng", &exchange_capture());
    let json = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--fields")
            .arg("--json")
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    assert!(json.contains("\"fields\":["), "structural key: {json}");
    assert!(
        json.contains("\"direction\":\"B\"") && json.contains("\"from\":\"10.0.0.2:7447\""),
        "the reply's row names where it came FROM, not the flow table's order: \
         {json}"
    );
    assert!(
        json.contains("\"suffix\""),
        "and the field tree itself is in it: {json}"
    );
    assert_one_document(json.trim());
}

/// R311y675 (§1.1n) — the listing is BOUNDED, and says how many it left out.
///
/// The walk is one pass per message a reader asked to see. Unbounded, the
/// output's size depends on how much traffic there was -- the leak every `drops`
/// counter in `wz-capture` exists to prevent, arriving in the renderer.
#[test]
fn the_field_listing_is_bounded_and_says_how_many_it_left_out() {
    let scratch = Scratch::new("fields-cap");
    let capture = scratch.write("fields.pcapng", &exchange_capture());
    let text = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .args(["--fields", "--max-messages", "1"])
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    // The cap is per FLOW, not per direction -- the same unit `--messages`
    // bounds. Measured: this expectation was written per-direction and the run
    // corrected it.
    assert!(
        text.contains("... 2 more not listed"),
        "the flow has three messages and two were cut: {text}"
    );
    assert_eq!(
        text.matches("] Frame").count(),
        1,
        "exactly one message survived the cap: {text}"
    );
}

/// R311y677 (§1.1n) — a DECRYPTED flow is WALKED, and the R311y676 defect
/// cannot come back under any wording.
///
/// ## What this test was, and why it changed
///
/// R311y676 asserted this fixture DECLINED, which was the honest state then: the
/// walk had been slicing the retained ciphertext at coordinates that name
/// positions in it but bytes that are not there, reading a length prefix of
/// `791` out of encrypted bytes and declining by accident. The refusal replaced
/// an accident with a named fact.
///
/// R311y677 replaces the refusal with the feature. The premise moved, so the
/// test moves with it -- what must NOT move is the defect: no field row here may
/// come from reading the ciphertext.
///
/// ## The discriminator, kept
///
/// A refusal computed from the bytes reports what it measured and differs per
/// message; a walk of the real plaintext produces the message's own fields. Both
/// are asserted, so a regression that resumed the ciphertext read would either
/// produce a measured refusal again or produce fields that are not these.
#[test]
fn a_decrypted_flow_is_walked_and_never_from_the_ciphertext() {
    let scratch = Scratch::new("fields-tls");
    let (file, log, _) = capture_and_key_log();
    let capture = scratch.write("fields.pcapng", &file);
    let keylog = scratch.write("keys.txt", log.as_bytes());

    let text = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--keylog")
            .arg(&keylog)
            .arg("--fields")
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();

    assert!(
        text.contains("DECRYPTED: 1 flow(s), 3 record(s) opened"),
        "the fixture must actually decrypt: {text}"
    );
    // The plaintext of this capture is three KeepAlives, one byte each.
    assert_eq!(
        text.matches("[0..1] KeepAlive").count(),
        3,
        "every opened message is walked, from its own plaintext: {text}"
    );
    assert_eq!(
        text.matches("(decrypted)").count(),
        3,
        "and every row says the bytes came from a decryption: {text}"
    );
    // THE R311y676 DEFECT: a length prefix read out of ciphertext. Its message
    // is gone, and so is the shape that produced it -- nothing here declines.
    assert!(
        !text.contains("the framing unit declares"),
        "no length prefix may be read out of encrypted bytes: {text}"
    );
    assert!(
        !text.contains("NO FIELDS"),
        "and nothing is declined, because the plaintext was there: {text}"
    );
}

/// A TLS capture whose PLAINTEXT is the same query exchange, and its key log.
fn tls_exchange_capture() -> (Vec<u8>, String) {
    let secret: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(19).wrapping_add(7))
        .collect();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(13));
    let mut stream = client_hello(&random);
    let mut enc = sealer(&secret);
    for (seq, record) in [query(7, "demo/**"), reply(7, "demo/a", b"first")]
        .iter()
        .enumerate()
    {
        stream.extend_from_slice(&seal_at(
            &mut enc,
            rustls::ContentType::ApplicationData,
            &framed_frame(record),
            seq as u64,
        ));
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
    (file, log)
}

/// R311y677 (§1.1n) — THE FIELD LAYER READS INSIDE TLS.
///
/// ## What R311y676 left, and why it was not the feature
///
/// That round made `--fields` decline a decrypted flow by name, because its
/// frames' coordinates are remapped to the CIPHERTEXT record they came out of
/// and the plaintext is a local that `decrypt_with` drops. Honest, and TLS is
/// the interesting case for an analyzer: a zenoh session on the wire is a
/// `tls/...` endpoint, and a reader that can name the keyexpr's bytes only for
/// cleartext can name them almost never.
///
/// ## Why a sink rather than a stored buffer
///
/// Keeping the plaintext would add an eighth thing to `wz-capture` that grows
/// with the input, to a crate whose bound discipline exists because seven was
/// already too many, and it is the third copy of a flow's bytes. So
/// `decrypt_with_sink` OFFERS it at the one moment it exists and keeps nothing;
/// what this reader keeps is bounded by the same `--max-messages` as every other
/// listing.
#[test]
fn the_field_layer_reads_the_keyexpr_inside_tls() {
    let scratch = Scratch::new("fields-tls-ok");
    let (file, log) = tls_exchange_capture();
    let capture = scratch.write("fields.pcapng", &file);
    let keylog = scratch.write("keys.txt", log.as_bytes());

    let text = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--keylog")
            .arg(&keylog)
            .arg("--fields")
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();

    // ANTI-VACUITY: the flow must actually have decrypted, or there is nothing
    // to have walked and every assertion below is about an empty listing.
    assert!(
        text.contains("DECRYPTED: 1 flow(s), 2 record(s) opened"),
        "the fixture must decrypt: {text}"
    );
    // THE CLAIM: the keyexpr's length prefix and its text, named to the byte,
    // out of a flow that was encrypted on the wire.
    assert!(
        text.contains("suffix = Text(\"demo/**\")"),
        "the query's keyexpr, read from inside TLS: {text}"
    );
    assert!(
        text.contains("suffix = Text(\"demo/a\")"),
        "and the reply's: {text}"
    );
    assert!(
        text.contains("[5..6] suffix_len"),
        "with the length prefix separately located, in the SAME message-relative \
         space a cleartext row uses: {text}"
    );
    // The ROW coordinate is the ciphertext record's, because that is the space
    // the rest of the report speaks; the SPANS are message-relative, because a
    // field's byte range is a range of the message. Two spaces on one line, on
    // purpose, and the row says which it is.
    assert!(
        text.contains("(decrypted)"),
        "and the row says the bytes came from a decryption: {text}"
    );
    // THE R311y676 DEFECT MUST NOT COME BACK: no length prefix read out of
    // ciphertext, under any wording.
    assert!(
        !text.contains("NO FIELDS"),
        "nothing is declined here -- the plaintext was available: {text}"
    );
}

/// R311y677 (§1.1n) — THE DISCRIMINATING NEGATIVE: without the keys, the same
/// capture declines rather than inventing fields.
///
/// Without this leg, a sink that walked something other than the plaintext could
/// satisfy the test above on a fixture that happens to decrypt. Here the bytes
/// are identical and only the key log is withheld.
#[test]
fn the_same_capture_without_keys_has_no_fields_to_show() {
    let scratch = Scratch::new("fields-tls-nokey");
    let (file, _) = tls_exchange_capture();
    let capture = scratch.write("fields.pcapng", &file);

    let text = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--fields")
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    assert!(
        !text.contains("suffix = Text"),
        "no keys, no plaintext, no fields -- and certainly not these ones: \
         {text}"
    );
    assert!(
        text.contains("NO FIELDS -- this flow's messages were decrypted")
            || !text.contains("] KeepAlive"),
        "an encrypted flow with nothing opened contributes no field rows: {text}"
    );
}

/// R311y677 (§1.1n) — the SINK's bound bites, and says how many it left out.
///
/// `wz-capture` offers the plaintext and keeps nothing; what this reader keeps is
/// its own accumulation and therefore its own bound. Measured by a probe first:
/// the bound was written with no gate, and disabling it left every test green.
#[test]
fn the_decrypted_field_listing_is_bounded_and_says_so() {
    let scratch = Scratch::new("fields-tls-cap");
    let (file, log, _) = capture_and_key_log();
    let capture = scratch.write("fields.pcapng", &file);
    let keylog = scratch.write("keys.txt", log.as_bytes());

    let text = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--keylog")
            .arg(&keylog)
            .args(["--fields", "--max-messages", "1"])
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    assert_eq!(
        text.matches("[0..1] KeepAlive").count(),
        1,
        "one message survived the cap: {text}"
    );
    assert!(
        text.contains("... 2 more not listed"),
        "and the two it dropped are counted, not silent: {text}"
    );
}

/// R311y678 (§1.1n) — THE FIELD ROWS ARE THE MESSAGES THE READER DECODED.
///
/// ## The gate R311y677 did not have
///
/// That round handed the sink the plaintext before the frames existed, so it
/// walked the `u16`-length-prefixed units itself. Two walkers, two opinions
/// about where the messages are, and nothing comparing them: a capture they read
/// differently would print `messages decoded: N` over a listing of something
/// else, and every assertion in place would have passed.
///
/// The number is now taken from the report's own summary line and compared with
/// the rows underneath it, on BOTH transports of this listing -- cleartext,
/// where the rows come from `flow.frames`, and decrypted, where they come from
/// the sink. One count, two paths, asserted equal in the same run.
#[test]
fn the_field_rows_are_the_messages_the_reader_decoded() {
    let scratch = Scratch::new("fields-agree");

    let cleartext = scratch.write("plain.pcapng", &exchange_capture());
    let (tls_file, log) = tls_exchange_capture();
    let tls = scratch.write("tls.pcapng", &tls_file);
    let keylog = scratch.write("keys.txt", log.as_bytes());

    for (name, args) in [
        ("cleartext", vec![cleartext.clone()]),
        (
            "decrypted",
            vec![tls.clone(), "--keylog".into(), keylog.clone()],
        ),
    ] {
        let text = String::from_utf8_lossy(
            &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
                .args(&args)
                .arg("--fields")
                .output()
                .expect("runs")
                .stdout,
        )
        .into_owned();
        let decoded: usize = text
            .lines()
            .find_map(|l| l.trim().strip_prefix("messages decoded: "))
            .expect("the summary line")
            .parse()
            .expect("a number");
        // ANTI-VACUITY: zero rows would satisfy an equality with zero.
        assert!(
            decoded > 0,
            "{name}: the fixture must decode something: {text}"
        );
        let rows = text.matches("] Frame").count() + text.matches("] KeepAlive").count();
        assert_eq!(
            rows, decoded,
            "{name}: the field listing must be the messages the summary counted, \
             not a second walk's opinion of them: {text}"
        );
    }
}

/// R311y679 (§1.1n) — DATAGRAM flows are WALKED, and R311y678 said they could
/// not be.
///
/// ## The claim that round made, and what measuring said
///
/// R311y678 declared this blocked: "a datagram's bytes are not reachable ... the
/// symmetric answer is the sink shape, offered at `push_packet_at`, and it needs
/// a construction seam". Every piece of that was already public.
/// `pcapng::parse` is; a `Packet` carries `link_type` and `data`;
/// `link::decapsulate` is; and a datagram frame's `stream_offset` IS its packet
/// index. Nothing was added to `wz-capture` and nothing is retained -- the
/// capture bytes were in this crate's hand the whole time.
///
/// ## Why the SCOUTING list and not `frames`
///
/// Measured, not assumed. A discovery capture reports `messages decoded: 0`
/// beside `scouting: 3 message(s)`: the scouting datagrams are a different MID
/// space in a different list, walked by a different entry point. A walk of
/// `frames` alone produced an EMPTY listing over a capture that is nothing but
/// discovery traffic -- which is the silence R311y678 replaced with a notice,
/// arriving one list further in.
#[test]
fn a_datagram_capture_has_its_fields_walked() {
    let scratch = Scratch::new("fields-datagram");
    let capture = scratch.write("scout.pcapng", &scouting_capture());
    let text = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--fields")
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();

    // ANTI-VACUITY, both halves: datagram-only, and carrying messages.
    assert!(
        text.contains("flows: 0 stream, 1 datagram"),
        "the fixture must be datagram-only: {text}"
    );
    assert!(
        text.contains("scouting: 3 message(s)"),
        "and must carry three of them: {text}"
    );
    assert_eq!(
        text.matches("] Scout").count(),
        3,
        "every scouting message is walked into its fields: {text}"
    );
    // The FIELDS, to the byte: a Scout's version, its flag byte, and the zid
    // whose length that byte encodes.
    assert!(
        text.contains("[1..2] version = Uint(9)"),
        "the version byte is named and located: {text}"
    );
    assert!(
        text.contains("[3..7] zid = Bytes([17, 34, 51, 68])"),
        "and the zid is the four bytes after the flag byte: {text}"
    );
    // THE LABEL MUST BE HONEST. `render_sink_row` hardcoded `(decrypted)` when
    // its only caller was the TLS sink; these rows are cleartext.
    assert!(
        !text.contains("(decrypted)"),
        "a cleartext datagram row must not claim to have been decrypted: {text}"
    );
    // And the R311y678 notice is gone, because it is no longer true.
    assert!(
        !text.contains("NO FIELDS"),
        "nothing is declined here: {text}"
    );
}

/// R311y679 (§1.1n) — a flow this reader walks NOTHING of still says so.
///
/// The R311y678 notice is kept for the case that is still real: a datagram flow
/// whose messages this build cannot walk contributes no rows, and silence there
/// reads as "this flow carried nothing".
#[test]
fn a_datagram_row_the_reader_cannot_walk_is_still_named() {
    let scratch = Scratch::new("fields-datagram-none");
    // A UDP flow carrying one datagram that is not a zenoh message at all.
    // An EMPTY datagram: a flow with no message in it at all.
    let junk: [u8; 0] = [];
    let mut udp = Vec::new();
    udp.extend_from_slice(&43210u16.to_be_bytes());
    udp.extend_from_slice(&7446u16.to_be_bytes());
    udp.extend_from_slice(&((8 + junk.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes());
    udp.extend_from_slice(&junk);
    let mut ip = vec![0x45u8, 0];
    ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
    ip.extend_from_slice(&[192, 168, 1, 5]);
    ip.extend_from_slice(&[224, 0, 0, 224]);
    ip.extend_from_slice(&udp);
    let mut packet = vec![0u8; 12];
    packet.extend_from_slice(&[0x08, 0x00]);
    packet.extend_from_slice(&ip);
    while packet.len() < 60 {
        packet.push(0);
    }
    let file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &packet)],
    );
    let capture = scratch.write("junk.pcapng", &file);
    let text = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--fields")
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    // ANTI-VACUITY: the flow must EXIST, or the notice is absent for the
    // trivial reason. Measured -- the first fixture for this test used a
    // malformed zenoh MID and the walker read it as `Unknown` and produced a
    // row, so the branch was not reached at all; an EMPTY datagram is what
    // makes a flow with nothing in it.
    assert!(
        text.contains("flows: 0 stream, 1 datagram"),
        "the flow must exist: {text}"
    );
    assert!(
        text.contains("NO FIELDS -- this reader walked none of this datagram flow's messages"),
        "a datagram flow with nothing walkable must say so: {text}"
    );
}

/// R311y680 (§1.1n) — the packet cross-check does not reject a scout/hello
/// exchange, which spans two flows by design.
#[test]
fn a_scout_and_its_hello_are_both_walked_across_two_flows() {
    let scratch = Scratch::new("observe-sh");
    // A SCOUT to the multicast group, then a HELLO back from a responder.
    let mk = |src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, body: &[u8]| {
        let mut udp = Vec::new();
        udp.extend_from_slice(&sport.to_be_bytes());
        udp.extend_from_slice(&dport.to_be_bytes());
        udp.extend_from_slice(&((8 + body.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(body);
        let mut ip = vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&udp);
        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    };
    let scout = [0x01u8, 0x09, (3 << 4) | 0x08 | 0x03, 0x11, 0x22, 0x33, 0x44];
    let hello = [0x02u8, 0x09, (3 << 4) | 0x03, 0x55, 0x66, 0x77, 0x88, 0x00];
    let a = mk([192, 168, 1, 5], [224, 0, 0, 224], 43210, 7446, &scout);
    let b = mk([192, 168, 1, 9], [192, 168, 1, 5], 7447, 43210, &hello);
    let file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &a), (0, 1_000_100, &b)],
    );
    let capture = scratch.write("sh.pcapng", &file);
    let text = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--fields")
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();

    // ANTI-VACUITY: TWO flows, which is the whole point -- a single-flow capture
    // could not tell a cross-check that compares flow keys from one that does
    // not.
    assert!(
        text.contains("flows: 0 stream, 2 datagram"),
        "the exchange must span two flows: {text}"
    );
    assert!(
        text.contains("] Scout") && text.contains("] Hello"),
        "both halves are walked: {text}"
    );
    // AND NEITHER IS REJECTED. `Dissection::push_packet_at` notes that a SCOUT's
    // key is (asker, group) while its HELLO's is (asker, responder), so the two
    // messages of one exchange live in DIFFERENT flows -- exactly the shape that
    // would make a flow-key cross-check throw away legitimate rows.
    assert!(
        !text.contains("message(s) skipped"),
        "a scout/hello exchange spans two flows BY DESIGN and neither row may be \
         rejected for it: {text}"
    );
}
