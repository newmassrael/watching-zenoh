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

    // And the JSON carries the same three numbers, structurally.
    let out = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .arg("--keylog")
        .arg(&keylog)
        .arg("--json")
        .output()
        .expect("runs");
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(
        json.contains("\"epochs\":{\"advances\":1,\"advances_confirmed\":1,\"key_updates\":1}"),
        "and the JSON must agree with the text, in one document: {json}"
    );
    assert_one_document(json.trim());
}
