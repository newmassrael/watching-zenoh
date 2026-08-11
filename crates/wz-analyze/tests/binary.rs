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
    tcp_segment_from(seq, payload, false, 1111)
}

/// R311y692 — the same segment from a DIFFERENT client port, which is a
/// different flow key and therefore a different TLS connection to the opener.
fn tcp_packet_from(port: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    tcp_segment_from(seq, payload, false, port)
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
    tcp_segment_from(seq, payload, reverse, 1111)
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

/// R311y708 (G2) — A KEY LOG FOR ANOTHER CONNECTION NAMES BOTH SIDES.
///
/// `no_key_for_session` tells a reader their keys are for a different session
/// and gives them nothing to check that against. Both facts that decide what to
/// do next were already computed — the capture's own client random, and the
/// randoms the log holds, the latter through a `KeyLog::client_randoms` with
/// zero callers anywhere in the workspace.
///
/// BOTH AXES, because a rendering that printed this unconditionally would pass
/// the mismatch arm on its own: the second half runs the same capture with keys
/// that DO fit and requires the sentence to be absent and the set to be empty.
#[test]
fn a_key_log_for_another_connection_names_what_each_side_holds() {
    let scratch = Scratch::new("key-mismatch");
    let (file, log, random) = capture_and_key_log();
    let capture = scratch.write("session.pcapng", &file);

    let other_random: [u8; 32] =
        core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(9));
    let other_secret: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(5).wrapping_add(1))
        .collect();
    let wrong = scratch.write(
        "wrong.txt",
        format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
            hex(&other_random),
            hex(&other_secret)
        )
        .as_bytes(),
    );
    let right = scratch.write("right.txt", log.as_bytes());

    let run = |keys: &std::path::Path, json: bool| -> String {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_wz-analyze"));
        cmd.arg(&capture).arg("--keylog").arg(keys);
        if json {
            cmd.arg("--json");
        }
        String::from_utf8_lossy(&cmd.output().expect("the binary runs").stdout).into_owned()
    };

    // THE MISMATCH ARM.
    let text = run(&wrong, false);
    assert!(
        text.contains("1 flow(s) name a session the supplied keys do not cover"),
        "the reader must be told the keys are for another session: {text}"
    );
    assert!(
        text.contains(&hex(&random)),
        "and WHICH session this capture is, or they cannot find the right log: {text}"
    );
    assert!(
        text.contains(&hex(&other_random)),
        "and which one their log holds, which is the half that says whether they \
         grabbed the wrong file or the wrong capture: {text}"
    );

    let json = run(&wrong, true);
    assert!(
        json.contains(&format!(
            "\"key_mismatch\":{{\"unopened_sessions\":[\"{}\"],\"log_holds\":[\"{}\"]}}",
            hex(&random),
            hex(&other_random)
        )),
        "and the machine-facing rendering carries the same two SETS: {json}"
    );

    // THE OTHER AXIS: keys that fit.
    let ok_text = run(&right, false);
    assert!(
        !ok_text.contains("do not cover"),
        "a capture whose keys fit must not carry the mismatch sentence: {ok_text}"
    );
    let ok_json = run(&right, true);
    assert!(
        ok_json.contains("\"key_mismatch\":{\"unopened_sessions\":[],\"log_holds\":["),
        "the JSON key stays present with an empty set -- absent cannot say \
         'no mismatch': {ok_json}"
    );
}

/// R311y708 (Y4) — TWO `--keylog` FILES, AND THE FIRST ONE STILL COUNTS.
///
/// ## What was measured before this test existed
///
/// The parser ASSIGNED `--keylog`, so the last occurrence won and every earlier
/// one was discarded without a word. An operator holding a client-side and a
/// server-side `SSLKEYLOGFILE` -- the ordinary shape of a two-sided capture --
/// passed both and got a report about one, with nothing in the output to say
/// which.
///
/// ## Why the order below is the discriminating one
///
/// The real key is given FIRST and an inert one SECOND. Under the old parser
/// that is precisely the losing arrangement: the inert file survives, the real
/// one is dropped, and the tool reports a capture it could not decrypt. The
/// opposite order passed even while broken, which is why it is not the arm this
/// test leads with.
///
/// The inert file is asserted inert ON ITS OWN first. Without that arm a decoy
/// that happened to decrypt would make every assertion below pass while proving
/// nothing -- the population-of-zero shape this workspace keeps measuring.
///
/// The first file is also written WITHOUT a trailing newline, because the merge
/// is a textual append: two line-oriented logs joined without a separator would
/// glue the last line of one onto the first line of the next, and both keys
/// would be lost rather than one.
#[test]
fn two_key_logs_are_both_read_and_the_earlier_one_is_not_dropped() {
    let scratch = Scratch::new("two-keylogs");
    let (file, log, random) = capture_and_key_log();
    let capture = scratch.write("session.pcapng", &file);

    // A well-formed key log line for a DIFFERENT connection: same shape, a
    // random this capture never carried, so it can decrypt nothing here.
    let other_random: [u8; 32] =
        core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(9));
    let other_secret: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(5).wrapping_add(1))
        .collect();
    assert_ne!(
        other_random, random,
        "the inert log must be for another connection or it is not inert"
    );
    let inert = format!(
        "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
        hex(&other_random),
        hex(&other_secret)
    );

    // Both written WITHOUT their trailing newline, which is what makes the
    // separator load-bearing rather than decorative.
    let real_path = scratch.write("real.txt", log.trim_end().as_bytes());
    let inert_path = scratch.write("inert.txt", inert.trim_end().as_bytes());

    let run = |args: &[&std::path::Path]| -> String {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_wz-analyze"));
        cmd.arg(&capture);
        for a in args {
            cmd.arg("--keylog").arg(a);
        }
        let out = cmd.arg("--json").output().expect("the binary runs");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    // THE POPULATION ARM: the inert file alone decrypts nothing.
    let alone = run(&[&inert_path]);
    assert!(
        alone.contains("\"decrypted\":false"),
        "the inert key log must decrypt nothing on its own, or this test proves \
         nothing: {alone}"
    );

    // THE DISCRIMINATING ARM: real first, inert second.
    let both = run(&[&real_path, &inert_path]);
    assert!(
        both.contains("\"decrypted\":true"),
        "a real key log followed by another file must still decrypt -- this is \
         the exact order the old parser dropped: {both}"
    );
    assert!(
        both.contains("\"records_decrypted\":3"),
        "and all three records, so the newline join did not corrupt the line it \
         appended to: {both}"
    );
    // THE SEPARATOR ARM: the inert file first, and it does NOT end in a newline.
    // Join the two texts without a `\n` between them and the inert file's line
    // swallows the real one -- so this arm fails on a merge that concatenates
    // naively, while the arm above still passes. It is the one that pins the
    // byte, not merely the loop.
    let reversed = run(&[&inert_path, &real_path]);
    assert!(
        reversed.contains("\"decrypted\":true"),
        "a key log appended after a file with no trailing newline must still be \
         read as its own line: {reversed}"
    );
    assert!(
        reversed.contains("\"records_decrypted\":3"),
        "and completely: {reversed}"
    );
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
             \"advances_before_first_record\":0,\"advances_after_hole\":0,\
             \"advances_unexplained\":0,\
             \"advances_after_abandoned_handshake\":0,\
             \"key_updates\":1,\"updates_requested\":0,\
             \"updates_answering\":0,\"requests_unanswered\":0,\
             \"key_updates_reassembled\":0,\"handshake_bytes_abandoned\":0}"
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

/// R311y681 (§1.1n) — EVERY field-layer notice reaches the JSON, and the two
/// renderings are asserted in the SAME run.
///
/// ## What was measured
///
/// Five notices — a flow whose plaintext was never opened, a datagram flow
/// nothing walkable came out of, a capture that could not be re-read, a bound
/// that bit, and a disagreement between this reader's two reads — were each
/// written straight into the text branch behind `format == Format::Text`. A
/// consuming tool saw an array that was SHORT and no key saying why: exactly the
/// silence this track spent six rounds removing for a person, left standing for
/// a program. The store's own carry has said so since R311y678 and three rounds
/// added new notices without closing it.
///
/// ## Why both formats in one run, per notice
///
/// The failure this crate exists to end is a fact rendered twice and drifting:
/// R311y664 found `NOT DECRYPTED` in text beside `"decrypted":true` in JSON, in
/// one run of one binary. So each notice below is driven through both renderings
/// of the SAME capture and the SAME sentence is required in both — a `note` key
/// whose prose disagrees with the line above it would red here.
#[test]
fn every_field_notice_reaches_the_json_carrying_the_same_sentence() {
    let scratch = Scratch::new("field-notes");

    // (1) A TLS flow with NO keys: nothing was opened, so there is nothing to
    // walk and the reason is the interesting part.
    let (tls_file, _) = tls_exchange_capture();
    let no_keys = scratch.write("nokeys.pcapng", &tls_file);
    // (2) A datagram flow with an EMPTY datagram in it: a flow that exists and
    // has no message this reader can walk.
    let empty = scratch.write("empty.pcapng", &empty_datagram_capture());
    // (3) A cleartext flow under a bound that takes two of its three messages.
    let bounded = scratch.write("bounded.pcapng", &exchange_capture());

    for (name, args, kind, sentence) in [
        (
            "not_decrypted",
            vec![no_keys.to_string_lossy().into_owned(), "--fields".into()],
            "not_decrypted",
            "NO FIELDS -- this flow's messages were decrypted",
        ),
        (
            "nothing_walkable",
            vec![empty.to_string_lossy().into_owned(), "--fields".into()],
            "nothing_walkable",
            "NO FIELDS -- this reader walked none of this datagram flow's messages",
        ),
        (
            "omitted",
            vec![
                bounded.to_string_lossy().into_owned(),
                "--fields".into(),
                "--max-messages".into(),
                "1".into(),
            ],
            "omitted",
            "2 more not listed",
        ),
    ] {
        let run = |extra: Option<&str>| {
            let mut command = Command::new(env!("CARGO_BIN_EXE_wz-analyze"));
            command.args(&args);
            if let Some(flag) = extra {
                command.arg(flag);
            }
            String::from_utf8_lossy(&command.output().expect("runs").stdout).into_owned()
        };

        let text = run(None);
        assert!(
            text.contains(sentence),
            "{name}: the text listing must carry the notice at all: {text}"
        );

        let json = run(Some("--json"));
        let json = json.trim();
        assert_one_document(json);
        // THE STRUCTURAL KEY. A consumer must not have to test for the key that
        // explains a short array, which is the rule the epoch object already
        // follows one listing over.
        assert!(
            json.contains("\"field_notes\":["),
            "{name}: the notes key is structural and present on every run: {json}"
        );
        assert!(
            json.contains(&format!("\"kind\":\"{kind}\"")),
            "{name}: the notice must be machine-readable, not only printable: \
             {json}"
        );
        assert!(
            json.contains(&format!("\"note\":\"{sentence}")),
            "{name}: and it must carry the SAME sentence the text printed, \
             because one fact rendered twice is two facts to keep true: {json}"
        );
        // ANTI-VACUITY: the notice must be about a flow this run actually saw,
        // so a build that emitted a constant note array would not pass.
        let notes = json
            .split("\"field_notes\":[")
            .nth(1)
            .expect("the notes array");
        assert!(
            kind == "capture_not_reread" || notes.contains("\"low\":\""),
            "{name}: a flow-scoped note names its flow: {json}"
        );
    }
}

/// R311y681 (§1.1n) — a bound that takes EVERY row still reports itself.
///
/// ## The silence this closes, measured
///
/// The notice sat below a `continue` taken when a flow produced no rows, so a
/// flow whose every row the bound removed printed nothing AND said nothing.
/// Driven before the fix: `--fields --max-messages 0` over a three-message
/// cleartext capture produced a `fields:` heading with nothing under it — the
/// exact reading this crate is built against, an empty listing that looks like
/// an empty capture.
#[test]
fn a_bound_that_takes_every_row_still_reports_itself() {
    let scratch = Scratch::new("fields-cap-zero");
    let capture = scratch.write("fields.pcapng", &exchange_capture());
    let run = |extra: &[&str]| {
        String::from_utf8_lossy(
            &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
                .arg(&capture)
                .args(["--fields", "--max-messages", "0"])
                .args(extra)
                .output()
                .expect("runs")
                .stdout,
        )
        .into_owned()
    };

    let text = run(&[]);
    // ANTI-VACUITY: the capture must have had messages for the bound to take.
    assert!(
        text.contains("messages decoded: 3"),
        "the fixture must carry three messages: {text}"
    );
    assert_eq!(
        text.matches("] Frame").count(),
        0,
        "the bound takes every row: {text}"
    );
    assert!(
        text.contains("... 3 more not listed"),
        "and says so rather than printing an empty listing: {text}"
    );

    let json = run(&["--json"]);
    let json = json.trim();
    assert_one_document(json);
    assert!(
        json.contains("\"fields\":[]"),
        "the rows really are gone: {json}"
    );
    assert!(
        json.contains("\"kind\":\"omitted\"") && json.contains("\"count\":3"),
        "and the consumer is told how many, as a number: {json}"
    );
}

/// A pcapng carrying ONE empty UDP datagram: a datagram flow that exists and has
/// no message in it to walk.
///
/// R311y679 measured why an empty one and not a malformed one: a datagram
/// carrying a bad MID is read as `Unknown` and produces a ROW, so the notice
/// under test is never reached.
fn empty_datagram_capture() -> Vec<u8> {
    let mut udp = Vec::new();
    udp.extend_from_slice(&43210u16.to_be_bytes());
    udp.extend_from_slice(&7446u16.to_be_bytes());
    udp.extend_from_slice(&8u16.to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes());
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
    wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &packet)],
    )
}

/// R311y682 (§1.1n) — the agreement gate reaches the DATAGRAM transport, and
/// says out loud which number it is agreeing with.
///
/// ## The hole R311y678 left and R311y679 widened
///
/// `the_field_rows_are_the_messages_the_reader_decoded` compares the rows with
/// the `messages decoded:` summary. That number counts TRANSPORT messages, and a
/// discovery capture has none of them: it reports `messages decoded: 0` beside
/// `scouting: 3 message(s)` and produces three rows. So the equality is false on
/// a datagram capture by construction, the gate simply never ran there, and
/// nothing in the tree stated the rule -- which is how a listing that silently
/// stopped walking scouting messages would have gone unnoticed.
///
/// The rule, written down: a datagram flow's rows are its SCOUTING messages plus
/// its transport frames, and `messages decoded` counts only the second.
#[test]
fn a_datagram_capture_lists_exactly_the_messages_its_own_summary_counted() {
    let scratch = Scratch::new("fields-agree-datagram");
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

    let number = |prefix: &str| -> usize {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(prefix))
            .unwrap_or_else(|| panic!("the {prefix:?} summary line: {text}"))
            .split_whitespace()
            .next()
            .expect("a number")
            .parse()
            .expect("a number")
    };
    let scouting = number("scouting: ");
    let decoded = number("messages decoded: ");
    // THE RULE, STATED: this transport's messages are not in the number the
    // stream gate compares against, and that is why it needs its own.
    assert_eq!(
        decoded, 0,
        "a discovery capture carries no transport messages, so the stream \
         gate's number is 0 here and cannot be the one to compare: {text}"
    );
    // ANTI-VACUITY: zero rows would satisfy an equality with zero.
    assert!(
        scouting > 0,
        "the fixture must carry scouting messages: {text}"
    );
    let rows = text.matches("] Scout").count() + text.matches("] Hello").count();
    assert_eq!(
        rows, scouting,
        "every scouting message the summary counted must appear as a row: {text}"
    );
    // And nothing was quietly dropped on the way.
    assert!(
        !text.contains("message(s) skipped") && !text.contains("more not listed"),
        "an unbounded run over a whole capture drops nothing: {text}"
    );
}

/// R311y682 (§1.1n) — under a cap the rows and the omission ADD UP, which is
/// what the agreement gate must become where equality stops holding.
///
/// R311y678's carry said it exactly: "the rows and the summary agree only
/// without `--max-messages`; with a cap they must not, and nothing states that
/// -- the gate simply does not exercise it." A gate that only runs where the
/// numbers are equal cannot tell a bound that bit from a walker that quietly
/// lost rows, because both look like "fewer than the summary".
#[test]
fn under_a_cap_the_rows_and_the_omission_still_add_up_to_the_whole() {
    let scratch = Scratch::new("fields-agree-cap");
    let capture = scratch.write("fields.pcapng", &exchange_capture());
    for cap in ["1", "2"] {
        let text = String::from_utf8_lossy(
            &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
                .arg(&capture)
                .args(["--fields", "--max-messages", cap])
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
        let rows = text.matches("] Frame").count() + text.matches("] KeepAlive").count();
        let omitted: usize = text
            .lines()
            .find_map(|l| l.trim().strip_prefix("... "))
            .and_then(|l| l.split_whitespace().next())
            .expect("the omission line")
            .parse()
            .expect("a number");

        let cap: usize = cap.parse().expect("a number");
        // ANTI-VACUITY, both halves: the bound must actually bite, and it must
        // not have taken everything -- either extreme would satisfy the sum
        // below without testing what it is for.
        assert!(
            omitted > 0 && rows > 0,
            "cap {cap}: the bound must bite and leave something: {text}"
        );
        assert_eq!(rows, cap, "cap {cap}: the bound is the row count: {text}");
        assert_eq!(
            rows + omitted,
            decoded,
            "cap {cap}: what was shown plus what was left out is what the \
             summary counted -- a row lost anywhere else would break this sum \
             while leaving each half plausible: {text}"
        );
    }
}

/// One Ethernet/IPv4/UDP packet from `src:sport` to `dst:dport` carrying `body`.
fn udp_packet(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, body: &[u8]) -> Vec<u8> {
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
}

/// R311y683 (§1.1n) — a CLASSIC `.pcap` datagram capture gets its fields, and
/// R311y679 told it its packets could not be re-read.
///
/// ## The notice that was true about the code and false about the file
///
/// `Dissection::from_capture` dispatches on `looks_like_pcapng` and reads both
/// formats. The field walk called `pcapng::parse` unconditionally, so a classic
/// pcap was dissected and counted and then handed a notice saying its packets
/// were unreadable — narrower than the tool's own input surface, recorded in
/// R311y679's carry and left standing by R311y680.
///
/// ## The discriminator
///
/// The SAME packet bytes are written in both container formats and the two runs
/// must produce the same rows. A build that re-read only one of them would show
/// the difference here as a notice on one side and fields on the other.
#[test]
fn a_classic_pcap_datagram_capture_is_walked_like_a_pcapng_one() {
    let scratch = Scratch::new("fields-classic-pcap");
    let scout = [0x01u8, 0x09, (3 << 4) | 0x08 | 0x03, 0x11, 0x22, 0x33, 0x44];
    let packet = udp_packet([192, 168, 1, 5], [224, 0, 0, 224], 43210, 7446, &scout);

    let ng = scratch.write(
        "scout.pcapng",
        &wz_capture::pcapng::write(
            &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
            &[(0, 1_000_000, &packet)],
        ),
    );
    let classic = scratch.write(
        "scout.pcap",
        &wz_capture::pcap::write(wz_capture::link::LINKTYPE_ETHERNET, &[(0, 1_000, &packet)]),
    );

    let run = |path: &std::path::Path| {
        String::from_utf8_lossy(
            &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
                .arg(path)
                .arg("--fields")
                .output()
                .expect("runs")
                .stdout,
        )
        .into_owned()
    };
    let from_ng = run(&ng);
    let from_classic = run(&classic);

    // ANTI-VACUITY: the pcapng side must actually produce a row, or "the same
    // as the pcapng" is a comparison of two empty listings.
    assert!(
        from_ng.contains("] Scout"),
        "the pcapng side must walk the message: {from_ng}"
    );
    assert!(
        from_classic.contains("] Scout"),
        "and so must the classic pcap, which carries the same packet: \
         {from_classic}"
    );
    assert!(
        !from_classic.contains("could not be re-read"),
        "a file this tool just dissected must not be reported as unreadable: \
         {from_classic}"
    );
    // The FIELDS, to the byte, on the classic side too -- same packet, same
    // answer, and not merely "some row appeared".
    assert!(
        from_classic.contains("[3..7] zid = Bytes([17, 34, 51, 68])"),
        "the walked fields must be the same ones: {from_classic}"
    );
}

/// R311y683 (§1.1n) — a datagram carrying SEVERAL messages produces one row per
/// message.
///
/// R311y679 used `frame.unit_offset` as the message's start within the datagram
/// and its own carry recorded that the batch case was untested: every fixture in
/// the tree carries one message per packet. `Dissection::push_datagram` folds
/// "one datagram, every message it batched" (R311y631) into the frame list, so
/// the coordinate has to be right for the second and later messages, where a
/// reader that ignored `unit_offset` would print the FIRST message N times.
#[test]
fn a_datagram_carrying_several_messages_walks_each_of_them() {
    let scratch = Scratch::new("fields-datagram-batch");
    // Two transport messages in one datagram: a KeepAlive (MID 0x04, empty
    // body) and a Close (MID 0x03, one reason byte). Different kinds on
    // purpose -- two of the same would not tell a walk of the second from a
    // second walk of the first.
    let batch = [0x04u8, 0x03, 0x00];
    let packet = udp_packet([192, 168, 1, 5], [192, 168, 1, 9], 41000, 41001, &batch);
    let capture = scratch.write(
        "batch.pcapng",
        &wz_capture::pcapng::write(
            &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
            &[(0, 1_000_000, &packet)],
        ),
    );
    let text = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--fields")
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();

    // ANTI-VACUITY: one datagram flow, and the session must have found BOTH
    // messages in it -- otherwise this tests the walk against a batch that was
    // never batched.
    assert!(
        text.contains("flows: 0 stream, 1 datagram"),
        "the fixture must be one datagram flow: {text}"
    );
    assert!(
        text.contains("messages decoded: 2"),
        "and the session must have decoded both messages of the batch: {text}"
    );
    assert_eq!(
        text.matches("] KeepAlive").count(),
        1,
        "the first message is walked exactly once: {text}"
    );
    assert_eq!(
        text.matches("] Close").count(),
        1,
        "and the SECOND one is walked too, from its own offset -- a reader \
         ignoring unit_offset would print the first message twice: {text}"
    );
    // R311y689 — and NEITHER row is declined, which is the positive form of the
    // check this path took that round: a datagram row is now compared against
    // the frame the session decoded, like the other two producers. A reader
    // ignoring `unit_offset` no longer prints the first message twice -- it
    // prints one row and one decline naming both verdicts.
    assert!(
        !text.contains("NO FIELDS"),
        "the two readers agree about both messages: {text}"
    );
}

/// A TLS capture whose plaintext carries one good KeepAlive and one framing
/// unit the FIELD WALKER cannot read: an Init MID with its body missing.
fn capture_with_an_unwalkable_unit() -> (Vec<u8>, String) {
    let secret: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(13).wrapping_add(5))
        .collect();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(29));

    let mut stream = client_hello(&random);
    let mut enc = sealer(&secret);
    for (i, body) in [vec![0x04u8], vec![0x01u8]].into_iter().enumerate() {
        let mut framed = (body.len() as u16).to_le_bytes().to_vec();
        framed.extend_from_slice(&body);
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
    (file, log)
}

/// R311y683 (§1.1n) — a DECRYPTED record the field walker cannot read is a row
/// saying so, and it used to be no row at all.
///
/// ## Why this fixture had to exist
///
/// Measured by probe: putting the drop back -- `if let Ok(field)`, which is what
/// the sink did until this round -- left all 62 tests in the crate green. A
/// guard with no gate is a comment, and this is the transport where the silence
/// costs most: a reader looking at a decrypted listing cannot check the bytes by
/// eye, so a record that quietly left the listing is a record they will never
/// know about.
///
/// The unwalkable unit is an Init MID with its body missing. The session cannot
/// decode it either, which is the point: `walk_agrees` treats an undecodable
/// frame as silence rather than contradiction, so what is under test here is the
/// walker's own refusal and not the cross-check.
#[test]
fn a_decrypted_record_the_walker_cannot_read_is_still_a_row() {
    let scratch = Scratch::new("fields-tls-unwalkable");
    let (file, log) = capture_with_an_unwalkable_unit();
    let capture = scratch.write("bad.pcapng", &file);
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

    // ANTI-VACUITY, both halves: the flow must have been opened, and the good
    // message must be there -- a listing that failed entirely would satisfy a
    // "the bad one is named" assertion for the wrong reason.
    assert!(
        text.contains("DECRYPTED: 1 flow(s)"),
        "the fixture must actually decrypt: {text}"
    );
    assert!(
        text.contains("[0..1] KeepAlive"),
        "the walkable message must still be walked: {text}"
    );
    assert!(
        text.contains("(decrypted): NO FIELDS -- the field walker refused these bytes"),
        "and the one the walker refused must be a row that says so, not a row \
         that is missing: {text}"
    );
}

/// R311y684 (§1.1n) — THE DOCUMENT CHECKER IS ITSELF CHECKED.
///
/// ## Why a helper needs a test
///
/// `assert_one_document` is the gate twelve tests lean on, and it has two legs
/// that answer different questions: a real parser for VALIDITY, and a bracket
/// walk for "is this ONE value". Measured: deleting the parser leg left all
/// twelve green, because none of their fixtures is invalid-and-balanced -- which
/// is precisely the shape the parser leg was added for (R311y675 emitted rows
/// concatenated with no comma: invalid JSON, perfectly balanced, and every
/// assertion passed on it).
///
/// A gate whose own failure modes nothing exercises is a gate that can be
/// quietly deleted. So each leg is driven with the input only it catches, and
/// the honest document is driven first so a checker that rejected everything
/// could not pass.
#[test]
fn the_one_document_check_catches_each_shape_it_exists_for() {
    let rejects = |json: &str| std::panic::catch_unwind(|| assert_one_document(json)).is_err();

    // ANTI-VACUITY: a real single document must pass, or every rejection below
    // is satisfied by a checker that rejects everything.
    assert!(
        !rejects("{\"a\":1,\"b\":[{\"c\":\"}\"}]}"),
        "one valid document -- braces inside strings and all -- must pass"
    );

    // THE BRACKET LEG's own shape: two documents on one stream. Valid JSON by
    // the parser's reckoning, because it stops at the end of the first.
    assert!(
        rejects("{\"a\":1}{\"b\":2}"),
        "two documents must be caught: a consumer sees only the first"
    );
    // THE PARSER LEG's own shape: invalid and PERFECTLY BALANCED, which is what
    // the bracket walk cannot see. This is the R311y675 defect exactly.
    assert!(
        rejects("[{\"a\":1}{\"b\":2}]"),
        "rows concatenated with no comma are balanced and invalid, and only a \
         real parser catches it"
    );
    // And the plain unbalanced case.
    assert!(
        rejects("{\"a\":1"),
        "an unterminated document must be caught"
    );
}

/// R311y685 (§1.2a) — an unwitnessed advance says WHICH of its three causes,
/// and the three are driven side by side.
///
/// ## Why one number could not answer
///
/// R311y672 split the harmless boundary (one TLS never announces) off from the
/// rekey with no `KeyUpdate` behind it, and its own doc listed the three causes
/// the second still sums: a capture that began mid-session, a hole over the
/// announcing record, and a 128-bit coincidence. Two of those are facts about
/// the CAPTURE — go and take a longer one, go and fix the tap — and the third is
/// a fact about this READER. A figure summing them answers neither, which is the
/// same objection that produced the earlier split.
///
/// ## The discriminator
///
/// Three captures differing in exactly the thing under test, run through one
/// assertion each, plus the invariant that the three always add up to the figure
/// they subdivide. A build that attributed everything to one cause would pass
/// any single leg and fails here.
#[test]
fn an_unwitnessed_key_change_says_which_of_its_three_causes_it_was() {
    let scratch = Scratch::new("epoch-causes");
    let c0: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(37).wrapping_add(1))
        .collect();
    let c1: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(41).wrapping_add(2))
        .collect();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(23).wrapping_add(5));
    let log = format!(
        "CLIENT_TRAFFIC_SECRET_0 {} {}\nCLIENT_TRAFFIC_SECRET_1 {} {}\n",
        hex(&random),
        hex(&c0),
        hex(&random),
        hex(&c1)
    );
    let keylog = scratch.write("keys.txt", log.as_bytes());

    // (1) UNEXPLAINED: two records, contiguous, the second under the next key
    // and no KeyUpdate anywhere. This reader was watching the whole time.
    let mut watching = client_hello(&random);
    watching.extend_from_slice(&seal_at(
        &mut sealer(&c0),
        rustls::ContentType::ApplicationData,
        &unit(1),
        0,
    ));
    watching.extend_from_slice(&seal_at(
        &mut sealer(&c1),
        rustls::ContentType::ApplicationData,
        &unit(2),
        0,
    ));

    // (2) AFTER A HOLE: the same two records, with a TCP gap between them --
    // the announcing record is one the capture lost.
    let mut first = client_hello(&random);
    first.extend_from_slice(&seal_at(
        &mut sealer(&c0),
        rustls::ContentType::ApplicationData,
        &unit(1),
        0,
    ));
    let second = seal_at(
        &mut sealer(&c1),
        rustls::ContentType::ApplicationData,
        &unit(2),
        0,
    );

    // (3) BEFORE THE FIRST RECORD: the capture holds only the LATER key's
    // record, so the trial climbs to it before this direction opens anything.
    let mut late = client_hello(&random);
    late.extend_from_slice(&seal_at(
        &mut sealer(&c1),
        rustls::ContentType::ApplicationData,
        &unit(2),
        0,
    ));

    let files = [
        (
            "unexplained",
            wz_capture::pcapng::write(
                &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
                &[(0, 1_000_000, &tcp_packet(1000, &watching))],
            ),
        ),
        (
            "after_hole",
            wz_capture::pcapng::write(
                &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
                &[
                    (0, 1_000_000, &tcp_packet(1000, &first)),
                    // 4096 bytes of sequence space nobody captured.
                    (
                        0,
                        1_000_100,
                        &tcp_packet(1000 + first.len() as u32 + 4096, &second),
                    ),
                ],
            ),
        ),
        (
            "before_first_record",
            wz_capture::pcapng::write(
                &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
                &[(0, 1_000_000, &tcp_packet(1000, &late))],
            ),
        ),
    ];

    for (cause, file) in files {
        let capture = scratch.write(&format!("{cause}.pcapng"), &file);
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
        let json = json.trim();
        assert_one_document(json);

        let number = |key: &str| -> usize {
            json.split(&format!("\"{key}\":"))
                .nth(1)
                .unwrap_or_else(|| panic!("{cause}: the {key} key: {json}"))
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .expect("digits")
                .parse()
                .expect("a number")
        };
        // ANTI-VACUITY: there must BE an unwitnessed advance to attribute, or
        // every equality below is between two zeroes.
        let unwitnessed = number("advances_unwitnessed");
        assert_eq!(
            unwitnessed, 1,
            "{cause}: the fixture must produce exactly one unwitnessed advance \
             for the attribution to be about anything: {json}"
        );
        // R311y692 added a FOURTH cause, and the invariant below is why it had
        // to be added here rather than beside: a partition that grows a member
        // and leaves this sum at three members would start passing while
        // silently losing advances.
        let causes = [
            number("advances_before_first_record"),
            number("advances_after_hole"),
            number("advances_after_abandoned_handshake"),
            number("advances_unexplained"),
        ];
        // THE INVARIANT: the causes subdivide the figure and never exceed it.
        assert_eq!(
            causes.iter().sum::<usize>(),
            unwitnessed,
            "{cause}: the causes must add up to the figure they subdivide: \
             {json}"
        );
        let expected = match cause {
            "before_first_record" => [1, 0, 0, 0],
            "after_hole" => [0, 1, 0, 0],
            _ => [0, 0, 0, 1],
        };
        assert_eq!(
            causes, expected,
            "{cause}: this capture's advance belongs to exactly one cause, and \
             a build that attributed everything to one would pass a single leg \
             and fail this table: {json}"
        );
    }
}

/// R311y685 (§1.2a) — a peer that asks TWICE before answering owes two, and the
/// obligation used to be a bool.
///
/// `owed` could not exceed one, so the second `update_requested` was silently
/// absorbed and `requests_unanswered` could not exceed one per direction per
/// connection. "An expected key change did not arrive" is the fact this number
/// exists to report, and it was reporting a ceiling.
#[test]
fn two_requests_before_a_reply_are_two_obligations_and_not_one() {
    let scratch = Scratch::new("epoch-two-requests");
    let c0: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(67).wrapping_add(1))
        .collect();
    let c1: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(71).wrapping_add(2))
        .collect();
    let c2: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(73).wrapping_add(3))
        .collect();
    let s0: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(79).wrapping_add(4))
        .collect();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(17));

    // The client rekeys twice, ASKING each time. `\x18\x00\x00\x01\x01` is a
    // KeyUpdate whose one body byte is update_requested.
    let mut client = client_hello(&random);
    client.extend_from_slice(&seal_at(
        &mut sealer(&c0),
        rustls::ContentType::Handshake,
        b"\x18\x00\x00\x01\x01",
        0,
    ));
    client.extend_from_slice(&seal_at(
        &mut sealer(&c1),
        rustls::ContentType::Handshake,
        b"\x18\x00\x00\x01\x01",
        0,
    ));
    client.extend_from_slice(&seal_at(
        &mut sealer(&c2),
        rustls::ContentType::ApplicationData,
        &unit(1),
        0,
    ));
    // The server answers neither.
    let mut server = Vec::new();
    server.extend_from_slice(&seal_at(
        &mut sealer(&s0),
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
    let capture = scratch.write("two-requests.pcapng", &file);
    let keylog = scratch.write(
        "keys.txt",
        format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\nCLIENT_TRAFFIC_SECRET_1 {} {}\n\
             CLIENT_TRAFFIC_SECRET_2 {} {}\nSERVER_TRAFFIC_SECRET_0 {} {}\n",
            hex(&random),
            hex(&c0),
            hex(&random),
            hex(&c1),
            hex(&random),
            hex(&c2),
            hex(&random),
            hex(&s0)
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
    // ANTI-VACUITY: both asks must have been READ, or an unanswered count of
    // two would be measuring something else.
    assert!(
        json.contains("\"updates_requested\":2"),
        "both requests must be read off the wire: {json}"
    );
    assert!(
        json.contains("\"updates_answering\":0"),
        "and neither answered: {json}"
    );
    assert!(
        json.contains("\"requests_unanswered\":2"),
        "so TWO obligations stand -- a bool could only ever report one: {json}"
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
        text.contains("2 request(s) still unanswered"),
        "and the person reading the text sees the same two: {text}"
    );
}

/// R311y686 (§1.2a) — a `KeyUpdate` SPLIT ACROSS TWO RECORDS is found, and the
/// round before this one would have blamed a coincidence for it.
///
/// ## What the scan gave up on
///
/// R311y672 made the scan read the RFC's framing rather than the first byte,
/// which found a `KeyUpdate` hiding behind a `NewSessionTicket` in the SAME
/// record. Its own note recorded the rest: "fragmented or truncated -- the rest
/// of this message is in another record this walk does not have", and `break`
/// there discards that message and every message after it. TLS may split a
/// handshake message across records, so a ticket large enough to fill one hid
/// the announcement completely.
///
/// ## The discriminator, which R311y685 sharpened
///
/// The same capture read by the old scan does not merely lose a count: the
/// boundary the hidden message announced becomes an UNWITNESSED advance, and
/// R311y685 attributes an unwitnessed advance with no hole and records already
/// open to `advances_unexplained` -- this reader saying it was watching and saw
/// nothing. So the test asserts BOTH ways round: the update is found AND
/// reassembled, and the advance is confirmed rather than unexplained.
#[test]
fn a_key_update_split_across_two_records_is_still_read() {
    let scratch = Scratch::new("epoch-split");
    let c0: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(83).wrapping_add(1))
        .collect();
    let c1: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(89).wrapping_add(2))
        .collect();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(19).wrapping_add(7));

    // A NewSessionTicket (type 4, three body bytes) and then a KeyUpdate
    // (type 24, one body byte) whose five bytes are CUT after the second.
    let ticket = [0x04u8, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00];
    let key_update = [0x18u8, 0x00, 0x00, 0x01, 0x01];
    let mut head = ticket.to_vec();
    head.extend_from_slice(&key_update[..2]);
    let tail = &key_update[2..];

    let mut client = client_hello(&random);
    let mut g0 = sealer(&c0);
    client.extend_from_slice(&seal_at(&mut g0, rustls::ContentType::Handshake, &head, 0));
    client.extend_from_slice(&seal_at(&mut g0, rustls::ContentType::Handshake, tail, 1));
    // And the record under the NEXT key, which is the boundary the message
    // announced.
    client.extend_from_slice(&seal_at(
        &mut sealer(&c1),
        rustls::ContentType::ApplicationData,
        &unit(1),
        0,
    ));

    let file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &tcp_packet(1000, &client))],
    );
    let capture = scratch.write("split.pcapng", &file);
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
    assert_one_document(json.trim());

    // ANTI-VACUITY: there must BE an advance to attribute, or "confirmed" and
    // "unexplained" are both zero and the assertion below is about nothing.
    assert!(
        json.contains("\"advances\":1"),
        "the fixture must cross exactly one boundary: {json}"
    );
    assert!(
        json.contains("\"key_updates\":1"),
        "the split message must be READ, which is the whole round: {json}"
    );
    assert!(
        json.contains("\"key_updates_reassembled\":1"),
        "and it must be marked as one that began in an earlier record -- a \
         message found without the carry would not be: {json}"
    );
    // BOTH WAYS ROUND: found, and the advance it announces attributed to it.
    assert!(
        json.contains("\"advances_confirmed\":1"),
        "the boundary it announces is confirmed by it: {json}"
    );
    assert!(
        json.contains("\"advances_unexplained\":0"),
        "and is NOT the residue this reader blames itself for -- which is \
         exactly what the old scan produced for this capture: {json}"
    );
    // Nothing was let go of: the tail arrived.
    assert!(
        json.contains("\"handshake_bytes_abandoned\":0"),
        "the carry was consumed, not dropped: {json}"
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
        text.contains("began in an earlier record"),
        "and the person reading the text is told the same thing: {text}"
    );
}

/// R311y686 (§1.2a) — a handshake message left open when a record of ANOTHER
/// content type arrives is let go of, and SAID.
///
/// RFC 8446 §5.1 forbids interleaving a handshake message's fragments with
/// another content type, so this shape means a record went missing. Holding the
/// tail against a continuation that is never coming would be a carry that grows
/// for the life of the flow; dropping it silently would be an announcement this
/// reader quietly stopped looking for.
#[test]
fn a_handshake_tail_interrupted_by_another_record_is_let_go_of_and_counted() {
    let scratch = Scratch::new("epoch-interrupted");
    let c0: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(97).wrapping_add(1))
        .collect();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(3));

    let key_update = [0x18u8, 0x00, 0x00, 0x01, 0x01];
    let mut client = client_hello(&random);
    let mut g0 = sealer(&c0);
    // Half a KeyUpdate...
    client.extend_from_slice(&seal_at(
        &mut g0,
        rustls::ContentType::Handshake,
        &key_update[..2],
        0,
    ));
    // ...and then application data, which the RFC says cannot happen.
    client.extend_from_slice(&seal_at(
        &mut g0,
        rustls::ContentType::ApplicationData,
        &unit(1),
        1,
    ));

    let file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &tcp_packet(1000, &client))],
    );
    let capture = scratch.write("interrupted.pcapng", &file);
    let keylog = scratch.write(
        "keys.txt",
        format!("CLIENT_TRAFFIC_SECRET_0 {} {}\n", hex(&random), hex(&c0)).as_bytes(),
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
    assert_one_document(json.trim());
    // ANTI-VACUITY: the flow must have opened both records, or nothing was
    // carried and nothing could be abandoned.
    assert!(
        json.contains("\"records_decrypted\":2"),
        "both records must open: {json}"
    );
    assert!(
        json.contains("\"key_updates\":0"),
        "the half message is not a message: {json}"
    );
    assert!(
        json.contains("\"handshake_bytes_abandoned\":2"),
        "and the two bytes held for it are counted when they are let go: {json}"
    );
}

/// R311y687 (§1.1n) — a STREAM framing unit carrying several messages walks
/// each of them, and the datagram path has done so since R311y679.
#[test]
fn a_stream_unit_carrying_several_messages_walks_each_of_them() {
    let scratch = Scratch::new("fields-stream-batch");
    // One framing unit, two messages: a KeepAlive and a Close.
    let body = [0x04u8, 0x03, 0x00];
    let mut framed = (body.len() as u16).to_le_bytes().to_vec();
    framed.extend_from_slice(&body);
    let file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &tcp_packet(1000, &framed))],
    );
    let capture = scratch.write("batch.pcapng", &file);
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
        text.contains("messages decoded: 2"),
        "the session must have decoded both messages of the unit: {text}"
    );
    assert_eq!(
        text.matches("] KeepAlive").count(),
        1,
        "the first message is walked exactly once: {text}"
    );
    assert_eq!(
        text.matches("] Close").count(),
        1,
        "and the SECOND one is walked too, from its own offset within the \
         unit: {text}"
    );
}

/// R311y687 (§1.1n) — and the DECRYPTED path walks each message of a unit too.
///
/// The sink read the same two prefix bytes and took the unit from its first
/// byte for every message in it, so the defect the cleartext path carried was
/// carried here as well -- in the transport where a reader cannot check the
/// bytes by eye. Same fixture shape, sealed.
#[test]
fn a_decrypted_unit_carrying_several_messages_walks_each_of_them() {
    let scratch = Scratch::new("fields-tls-batch");
    let secret: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(17).wrapping_add(9))
        .collect();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(41));
    let body = [0x04u8, 0x03, 0x00];
    let mut framed = (body.len() as u16).to_le_bytes().to_vec();
    framed.extend_from_slice(&body);

    let mut stream = client_hello(&random);
    stream.extend_from_slice(&seal_at(
        &mut sealer(&secret),
        rustls::ContentType::ApplicationData,
        &framed,
        0,
    ));
    let file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &tcp_packet(1000, &stream))],
    );
    let capture = scratch.write("tls-batch.pcapng", &file);
    let keylog = scratch.write(
        "keys.txt",
        format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
            hex(&random),
            hex(&secret)
        )
        .as_bytes(),
    );

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

    // ANTI-VACUITY: the flow must have been opened and both messages decoded.
    assert!(
        text.contains("DECRYPTED: 1 flow(s)"),
        "the fixture must decrypt: {text}"
    );
    assert!(
        text.contains("messages decoded: 2"),
        "and both messages of the unit must be decoded: {text}"
    );
    assert_eq!(
        text.matches("] KeepAlive").count(),
        1,
        "the first is walked once: {text}"
    );
    assert_eq!(
        text.matches("] Close").count(),
        1,
        "and the second from its own offset within the unit: {text}"
    );
    assert!(
        !text.contains("NO FIELDS"),
        "neither row is declined, which is what the cross-check said about the \
         old slice: {text}"
    );
}

/// R311y688 (§1.1n) — every field row NAMES the coordinate space its `@N` is
/// in, and the three spaces are driven side by side.
///
/// ## What a reader could not tell
///
/// Three producers put a number after `@` and they count three different
/// things: a cleartext stream row's is a byte offset into the retained stream,
/// a datagram row's is a PACKET INDEX, and a decrypted row's is the offset of
/// the ciphertext record the plaintext came out of. All three are small numbers
/// and nothing distinguished them.
///
/// The spans inside every tree are message-relative, so "row offset + span" is a
/// capture coordinate in exactly ONE of the three cases -- and R311y687 showed
/// that even there the sum needs the framing prefix and the message's place in
/// its batch. That arithmetic is now printed rather than left to be inferred.
#[test]
fn every_field_row_says_which_coordinate_space_its_offset_is_in() {
    let scratch = Scratch::new("fields-spaces");
    let cleartext = scratch.write("plain.pcapng", &exchange_capture());
    let datagram = scratch.write("scout.pcapng", &scouting_capture());
    let (tls_file, log) = tls_exchange_capture();
    let tls = scratch.write("tls.pcapng", &tls_file);
    let keylog = scratch.write("keys.txt", log.as_bytes());

    for (space, args) in [
        ("stream_byte", vec![cleartext.clone()]),
        ("packet", vec![datagram.clone()]),
        (
            "ciphertext_record",
            vec![tls.clone(), "--keylog".into(), keylog.clone()],
        ),
    ] {
        let run = |extra: &[&str]| {
            String::from_utf8_lossy(
                &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
                    .args(&args)
                    .arg("--fields")
                    .args(extra)
                    .output()
                    .expect("runs")
                    .stdout,
            )
            .into_owned()
        };

        let json = run(&["--json"]);
        let json = json.trim();
        assert_one_document(json);
        assert!(
            json.contains(&format!("\"offset_space\":\"{space}\"")),
            "{space}: every row must name its space: {json}"
        );
        // AND NO OTHER SPACE APPEARS, which is what says the label follows the
        // producer rather than being a constant somebody typed once.
        for other in ["stream_byte", "packet", "ciphertext_record"] {
            if other != space {
                assert!(
                    !json.contains(&format!("\"offset_space\":\"{other}\"")),
                    "{space}: a row of this capture must not be labelled \
                     {other}: {json}"
                );
            }
        }

        let text = run(&[]);
        let note = match space {
            "stream_byte" => "[stream byte; this message begins at",
            "packet" => "[packet index]",
            _ => "[ciphertext record]",
        };
        assert!(
            text.contains(note),
            "{space}: and the person reading the text is told the same: {text}"
        );
    }
}

/// R311y688 (§1.1n) — the offset a stream row reports for its MESSAGE is the
/// one a reader can add a span to, and it is not the row's own number.
///
/// R311y687's fix is what makes the two differ by more than the prefix: a
/// message standing second in a batched unit begins `prefix_width +
/// unit_offset` past the unit, and a reader doing that sum by hand would have to
/// know both.
#[test]
fn the_message_offset_a_stream_row_reports_lands_on_the_message() {
    let scratch = Scratch::new("fields-message-at");
    // One unit, two messages: KeepAlive at unit offset 0, Close at 1.
    let body = [0x04u8, 0x03, 0x00];
    let mut framed = (body.len() as u16).to_le_bytes().to_vec();
    framed.extend_from_slice(&body);
    let file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &tcp_packet(1000, &framed))],
    );
    let capture = scratch.write("batch.pcapng", &file);
    let json = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .args(["--fields", "--json"])
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    assert_one_document(json.trim());

    let ats: Vec<&str> = json.split("\"message_at\":").skip(1).collect();
    // ANTI-VACUITY: two rows, or the pair below is not a pair.
    assert_eq!(ats.len(), 2, "the unit's two messages are two rows: {json}");
    let value = |s: &str| -> usize {
        s.split(|c: char| !c.is_ascii_digit())
            .next()
            .expect("digits")
            .parse()
            .expect("a number")
    };
    let (first, second) = (value(ats[0]), value(ats[1]));
    // The stream begins at offset 0 with a two-byte prefix, so the first
    // message is at 2 and the second one byte further on.
    assert_eq!(
        (first, second),
        (2, 3),
        "the two messages of one unit must have DIFFERENT message offsets, one \
         byte apart -- the same number twice is the R311y687 defect wearing a \
         new label: {json}"
    );

    // R311y690 — AND THE OFFSET LANDS ON THE MESSAGE, which the numbers alone
    // do not say. The stream's bytes here are `03 00 04 03 00`: a two-byte
    // prefix, then a KeepAlive (MID 4) at 2 and a Close (MID 3) at 3. Each
    // row's own header value is read back and paired with the offset it
    // reported, so an offset that is arithmetically tidy and points at the
    // wrong byte cannot pass.
    //
    // This is the check R311y689's carry asked for: `message_at` and the slice
    // now come from ONE function, and this is what says that function is right
    // rather than merely singular.
    let headers: Vec<usize> = json
        .split("\"name\":\"header\"")
        .skip(1)
        .map(|s| {
            s.split("\"value\":")
                .nth(1)
                .expect("a header value")
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .expect("digits")
                .parse()
                .expect("a number")
        })
        .collect();
    assert_eq!(
        headers,
        vec![4, 3],
        "the row reporting message_at 2 must be the KeepAlive at byte 2 and the \
         one reporting 3 the Close at byte 3: {json}"
    );
}

/// R311y690 (§1.1n) — the rule that decides ROW or NOTE, as behaviour rather
/// than as prose.
///
/// Two shapes carry one genre of fact and R311y681's own carry recorded that
/// nothing stated which applies: a failure with a MESSAGE to attach to is a row
/// with a `declined` key, and one about a FLOW or about the capture is an entry
/// in `field_notes`. The distinction is not stylistic -- a consumer walking rows
/// would never see a flow-level refusal, and one walking notes would never see
/// a message the walker refused.
///
/// Driven on the two captures that produce one each, and each is asserted to
/// produce ITS shape and NOT the other.
#[test]
fn a_message_level_failure_is_a_row_and_a_flow_level_one_is_a_note() {
    let scratch = Scratch::new("row-or-note");

    // MESSAGE level: a decrypted record the field walker cannot read.
    let (file, log) = capture_with_an_unwalkable_unit();
    let capture = scratch.write("bad.pcapng", &file);
    let keylog = scratch.write("keys.txt", log.as_bytes());
    let json = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--keylog")
            .arg(&keylog)
            .args(["--fields", "--json"])
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    let json = json.trim();
    assert_one_document(json);
    // `split_once` and not `split(..).nth(1)`: a walked row's own tree carries a
    // NESTED `"fields"` key, so counting occurrences cuts the rows array off at
    // the first row. Measured -- the first version of this test did exactly
    // that and failed looking for a separator it had already walked past.
    let (_, rows) = json.split_once("\"fields\":[").expect("the rows array");
    let (rows, notes) = rows
        .split_once("],\"field_notes\":[")
        .unwrap_or_else(|| panic!("both arrays: {json}"));
    assert!(
        rows.contains("\"declined\":\"the field walker refused these bytes"),
        "a failure with a message to attach to is a ROW: {json}"
    );
    assert!(
        notes.trim_end_matches([']', '}']).is_empty(),
        "and it is NOT also a note: {json}"
    );

    // FLOW level: a datagram flow with nothing walkable in it.
    let empty = scratch.write("empty.pcapng", &empty_datagram_capture());
    let json = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&empty)
            .args(["--fields", "--json"])
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();
    let json = json.trim();
    assert_one_document(json);
    let (_, rows) = json.split_once("\"fields\":[").expect("the rows array");
    let (rows, notes) = rows.split_once("],\"field_notes\":[").expect("both arrays");
    assert!(
        rows.is_empty(),
        "a flow-level failure produces no row at all: {json}"
    );
    assert!(
        notes.contains("\"kind\":\"nothing_walkable\""),
        "and IS a note: {json}"
    );
}

/// R311y689 (§1.1n) — the FLOW listing's per-message offsets name their space
/// too, and a decrypted flow's are a third space again.
///
/// R311y688 closed this for the field listing and left it standing one listing
/// over -- in the one a reader reaches for first. `MessageRow`'s own doc has
/// said "byte offset for a stream flow, packet index for a datagram one" since
/// R311y668 and the output said neither, so `@12` and `@12` counted different
/// things and looked identical.
///
/// A decrypted flow is the third case and is driven here because it is the one
/// that cannot be reasoned out from the transport: `remap_decrypted_offsets`
/// puts a decrypted frame's offset back to the CIPHERTEXT RECORD it came out
/// of, so it is not a byte offset a reader may add a span to.
#[test]
fn the_flow_listing_says_which_space_each_message_offset_is_in() {
    let scratch = Scratch::new("flows-spaces");
    let cleartext = scratch.write("plain.pcapng", &exchange_capture());
    let datagram = scratch.write("scout.pcapng", &scouting_capture());
    let (tls_file, log) = capture_and_key_log_pair();
    let tls = scratch.write("tls.pcapng", &tls_file);
    let keylog = scratch.write("keys.txt", log.as_bytes());

    for (space, args) in [
        ("stream_byte", vec![cleartext.clone()]),
        ("packet", vec![datagram.clone()]),
        (
            "ciphertext_record",
            vec![tls.clone(), "--keylog".into(), keylog.clone()],
        ),
    ] {
        let run = |extra: &[&str]| {
            String::from_utf8_lossy(
                &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
                    .args(&args)
                    .args(["--flows", "--messages"])
                    .args(extra)
                    .output()
                    .expect("runs")
                    .stdout,
            )
            .into_owned()
        };
        let json = run(&["--json"]);
        let json = json.trim();
        assert_one_document(json);
        // ANTI-VACUITY: there must be message rows at all.
        assert!(
            json.contains("\"name\":\""),
            "{space}: the listing must carry messages: {json}"
        );
        assert!(
            json.contains(&format!("\"offset_space\":\"{space}\"")),
            "{space}: every message row must name its space: {json}"
        );
        for other in ["stream_byte", "packet", "ciphertext_record"] {
            if other != space {
                assert!(
                    !json.contains(&format!("\"offset_space\":\"{other}\"")),
                    "{space}: no row of this capture may be labelled {other}: \
                     {json}"
                );
            }
        }
    }
}

/// The TLS fixture of `capture_and_key_log`, as a pair -- the third value is
/// the client random, which this test does not need.
fn capture_and_key_log_pair() -> (Vec<u8>, String) {
    let (file, log, _) = capture_and_key_log();
    (file, log)
}

/// R311y691 (§1.2a) — the DECRYPTION PASS's own summary reaches the reader, and
/// every call here used to drop it on the floor.
///
/// ## What was unreachable
///
/// `Dissection::decrypt_with` has returned a `DecryptionSummary` since long
/// before this crate existed, and both call sites discarded it. Most of what it
/// holds the report re-derives from the dissection -- but not all: `flows` is
/// what THIS PASS considered and `refused` is what the opener declined before
/// trying a record, and neither is a fact about the capture that survives the
/// call. A key log for a different connection produced a report saying "not
/// decrypted, reason no_key_for_session" and nothing saying that a pass had run
/// and been turned away at the door.
///
/// ## The discriminator
///
/// Two runs of the SAME capture, one with its own key log and one with a key log
/// for a different connection. The report's own numbers and the pass's move in
/// different directions, which is what says the pass block is not a second
/// rendering of the report.
#[test]
fn the_decryption_passs_own_numbers_reach_the_reader() {
    let scratch = Scratch::new("pass-summary");
    let (file, log, _) = capture_and_key_log();
    let capture = scratch.write("session.pcapng", &file);
    let mine = scratch.write("mine.txt", log.as_bytes());
    // The same shape of log for a connection this capture does not contain.
    let stranger: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(200));
    let secret: Vec<u8> = (0..48u8).map(|i| i.wrapping_mul(23)).collect();
    let theirs = scratch.write(
        "theirs.txt",
        format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
            hex(&stranger),
            hex(&secret)
        )
        .as_bytes(),
    );

    let run = |keylog: &std::path::Path| {
        String::from_utf8_lossy(
            &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
                .arg(&capture)
                .arg("--keylog")
                .arg(keylog)
                .arg("--json")
                .output()
                .expect("runs")
                .stdout,
        )
        .into_owned()
    };

    let ours = run(&mine);
    let ours = ours.trim();
    assert_one_document(ours);
    // ANTI-VACUITY: the pass must have had a flow to consider at all.
    assert!(
        ours.contains("\"pass\":{\"flows_considered\":1,\"flows_refused\":0,\"already_opened\":0}"),
        "a pass that opened the flow considered one and refused none: {ours}"
    );
    assert!(
        ours.contains("\"flows_decrypted\":1"),
        "and the capture-level number agrees with it here: {ours}"
    );

    let strangers = run(&theirs);
    let strangers = strangers.trim();
    assert_one_document(strangers);
    // THE DISCRIMINATOR: the capture's own numbers say nothing happened; the
    // pass's say it ran and was turned away.
    assert!(
        strangers.contains("\"flows_decrypted\":0"),
        "the capture opened nothing: {strangers}"
    );
    assert!(
        strangers
            .contains("\"pass\":{\"flows_considered\":1,\"flows_refused\":1,\"already_opened\":0}"),
        "but a pass DID run and was refused, which the report alone cannot say: \
         {strangers}"
    );
}

/// R311y692 (§1.2a) — an unwitnessed rekey on a direction that LET GO OF
/// handshake bytes says so, instead of being filed as unexplained.
///
/// R311y686's carry named the residue exactly: `advances_unexplained` is a
/// 128-bit coincidence OR an announcement this reader could not read, and that
/// round removed the only known member of the second class without proving the
/// class empty. The carry it introduced is the signal -- a tail dropped past its
/// bound, or abandoned when another content type interrupted it, is precisely
/// an announcement whose bytes this reader stopped being able to assemble.
///
/// It is not proof that THIS advance's announcement was in those bytes, and the
/// wording says so. It is the difference between "no explanation" and "an
/// explanation this reader already reported, on this direction, since the last
/// time the keys moved".
#[test]
fn a_rekey_after_abandoned_handshake_bytes_is_not_filed_as_unexplained() {
    let scratch = Scratch::new("epoch-after-abandon");
    let c0: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(29).wrapping_add(6))
        .collect();
    let c1: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(31).wrapping_add(8))
        .collect();
    let c2: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(41).wrapping_add(10))
        .collect();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(2));

    let mut client = client_hello(&random);
    let mut g0 = sealer(&c0);
    // Half a KeyUpdate...
    client.extend_from_slice(&seal_at(
        &mut g0,
        rustls::ContentType::Handshake,
        &[0x18u8, 0x00],
        0,
    ));
    // ...interrupted by application data, which abandons the tail...
    client.extend_from_slice(&seal_at(
        &mut g0,
        rustls::ContentType::ApplicationData,
        &unit(1),
        1,
    ));
    // ...and then the keys move, with nothing this reader could read announcing
    // it.
    client.extend_from_slice(&seal_at(
        &mut sealer(&c1),
        rustls::ContentType::ApplicationData,
        &unit(2),
        0,
    ));
    // AND THEY MOVE AGAIN. The dropped bytes explain at most the NEXT boundary;
    // this one has nothing behind it and must be filed as the residue.
    // Measured: without this record, reading the flag instead of TAKING it
    // passed every assertion -- the leak had no witness.
    client.extend_from_slice(&seal_at(
        &mut sealer(&c2),
        rustls::ContentType::ApplicationData,
        &unit(3),
        0,
    ));

    let file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &tcp_packet(1000, &client))],
    );
    let capture = scratch.write("after-abandon.pcapng", &file);
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
    let json = json.trim();
    assert_one_document(json);

    // ANTI-VACUITY, both halves: bytes must actually have been abandoned, and
    // there must be unwitnessed advances to attribute.
    assert!(
        json.contains("\"handshake_bytes_abandoned\":2"),
        "the tail must have been let go of: {json}"
    );
    assert!(
        json.contains("\"advances_unwitnessed\":2"),
        "and the keys must have moved TWICE with no announcement read: {json}"
    );
    // ONE EACH, which is the whole point: the dropped bytes explain the next
    // boundary and not the one after it.
    assert!(
        json.contains("\"advances_after_abandoned_handshake\":1"),
        "the FIRST advance is attributed to the bytes this reader dropped: \
         {json}"
    );
    assert!(
        json.contains("\"advances_unexplained\":1"),
        "and the SECOND is the residue -- an explanation that carried forward \
         would attribute both, which is what reading the flag instead of taking \
         it does: {json}"
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
        text.contains("let go of handshake bytes"),
        "and the person reading the text is told the same: {text}"
    );
}

/// R311y692 (§1.2a) — a handshake tail outstanding when the opener moves to
/// ANOTHER connection is counted as abandoned, not dropped in silence.
///
/// R311y686 bounded the carry and counted what the bound let go of, and left
/// this door open: `begin_flow` replaces both `DirectionState`s, and a flow
/// still holding half a message dropped it with no number moving. That is the
/// same silence the whole round was about, one lifetime event further out.
///
/// The two connections differ by client port, which is a different flow key and
/// therefore a different `client_random` to the opener.
#[test]
fn a_tail_outstanding_when_the_opener_moves_on_is_counted() {
    let scratch = Scratch::new("epoch-flow-change");
    let a0: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(43).wrapping_add(1))
        .collect();
    let b0: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(47).wrapping_add(2))
        .collect();
    let ra: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(1));
    let rb: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(2));

    // Connection A: a ClientHello, then HALF a KeyUpdate and nothing more.
    let mut first = client_hello(&ra);
    first.extend_from_slice(&seal_at(
        &mut sealer(&a0),
        rustls::ContentType::Handshake,
        &[0x18u8, 0x00],
        0,
    ));
    // Connection B: ordinary traffic on a different client port.
    let mut second = client_hello(&rb);
    second.extend_from_slice(&seal_at(
        &mut sealer(&b0),
        rustls::ContentType::ApplicationData,
        &unit(1),
        0,
    ));

    let file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[
            (0, 1_000_000, &tcp_packet(1000, &first)),
            (0, 1_000_100, &tcp_packet_from(2222, 1000, &second)),
        ],
    );
    let capture = scratch.write("two.pcapng", &file);
    let keylog = scratch.write(
        "keys.txt",
        format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\nCLIENT_TRAFFIC_SECRET_0 {} {}\n",
            hex(&ra),
            hex(&a0),
            hex(&rb),
            hex(&b0)
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
    let json = json.trim();
    assert_one_document(json);

    // ANTI-VACUITY: BOTH connections must have been considered, or the opener
    // never moved on and nothing could be dropped by moving.
    assert!(
        json.contains("\"pass\":{\"flows_considered\":2"),
        "the pass must have seen two connections: {json}"
    );
    assert!(
        json.contains("\"handshake_bytes_abandoned\":2"),
        "the tail the first connection was still holding is counted when the \
         opener moves to the second: {json}"
    );
}

/// One protobuf message, by hand: field 1 varint 150, field 2 the string
/// `zenoh`. Both encodings are the wire format's own worked example shapes.
const PROTOBUF: &[u8] = &[0x08, 0x96, 0x01, 0x12, 0x05, b'z', b'e', b'n', b'o', b'h'];

/// A capture whose reply payload is that protobuf message, under `demo/a`.
fn protobuf_capture() -> Vec<u8> {
    let mut client = Vec::new();
    client.extend_from_slice(&framed_frame(&query(7, "demo/**")));
    let mut server = Vec::new();
    server.extend_from_slice(&framed_frame(&reply(7, "demo/a", PROTOBUF)));
    server.extend_from_slice(&framed_frame(&response_final(7)));
    wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[
            (0, 1_000_000, &tcp_packet(1000, &client)),
            (0, 1_030_000, &tcp_packet_reverse(1000, &server)),
        ],
    )
}

/// R311y699 ([REDACTED-REQ]) — A USER-DEFINED PAYLOAD FORMAT, SELECTED BY KEY
/// EXPRESSION, at the command line.
///
/// ## What the requirement asks and what this proves
///
/// "decode a user-defined format (nanopb / e2e) payload by key expression
/// mapping". The format list is parenthetical; the load-bearing half is the
/// MAPPING, because a schema-less decoder run over the wrong topic does not
/// fail — protobuf's wire format reads almost any bytes as fields. So the test
/// drives all three halves in one run: the rule matches by zenoh's own keyexpr
/// dialect (`demo/**` covers `demo/a`), the decoder recovers the fields, and
/// the spans it reports are in the MESSAGE's coordinate space rather than the
/// payload's.
///
/// ## Anti-vacuity
///
/// The same capture is run WITHOUT the rule and with a rule for a different
/// subtree. If the fields appeared in either, "the mapping selected it" would
/// be a statement about nothing.
#[test]
fn a_payload_format_rule_decodes_by_keyexpr_and_reports_message_coordinates() {
    let scratch = Scratch::new("payload-format");
    let capture = scratch.write("pb.pcapng", &protobuf_capture());

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

    let with = run(&["--fields", "--payload-format", "demo/**=protobuf"]);
    assert!(
        with.contains("payload `demo/a` as protobuf:"),
        "the rule fired on a keyexpr the pattern covers by zenoh's dialect: {with}"
    );
    assert!(
        with.contains("1 = varint 150"),
        "field 1 is a varint and its value is decoded, not shown as bytes: {with}"
    );
    assert!(
        with.contains("2 = len \"zenoh\""),
        "and a length-delimited field that IS text is rendered as text: {with}"
    );

    // THE COORDINATES. Every other span in this listing is message-relative
    // (R311y677), and a decoder is handed a payload slice that knows nothing
    // about where it sat. So the rebase is the caller's, and a build that
    // skipped it would print `[0..3]` for field 1.
    let payload_at = with
        .lines()
        .find_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix('[')?;
            let (span, name) = rest.split_once(']')?;
            (name.trim().starts_with("payload ")).then(|| {
                span.split_once("..")
                    .and_then(|(start, _)| start.parse::<usize>().ok())
            })?
        })
        .expect("the payload field is in the tree");
    assert!(
        payload_at > 0,
        "the payload does not begin at byte zero of the message, or the rebase \
         below would be untestable"
    );
    assert!(
        with.contains(&format!(
            "[{}..{}] 1 = varint 150",
            payload_at,
            payload_at + 3
        )),
        "field 1 sits at the payload's offset plus its own, in MESSAGE \
         coordinates (payload begins at {payload_at}): {with}"
    );
    assert!(
        with.contains(&format!(
            "[{}..{}] 2 = len \"zenoh\"",
            payload_at + 3,
            payload_at + 10
        )),
        "and field 2 follows it: {with}"
    );

    // ANTI-VACUITY 1: no rule, no payload block at all.
    let without = run(&["--fields"]);
    assert!(
        !without.contains("as protobuf"),
        "a reader who asked for no rule is told nothing about payload formats: {without}"
    );
    assert!(
        !without.contains("varint 150"),
        "and the fields are not decoded: {without}"
    );

    // ANTI-VACUITY 2: a rule for a DIFFERENT subtree does not fire, and says so
    // by naming the keyexpr it tested -- which is what stops a reader blaming
    // the decoder for their pattern.
    let elsewhere = run(&["--fields", "--payload-format", "other/**=protobuf"]);
    assert!(
        elsewhere.contains("no --payload-format rule covers `demo/a`"),
        "the keyexpr that was TESTED is named: {elsewhere}"
    );
    assert!(
        !elsewhere.contains("varint 150"),
        "and nothing was decoded: {elsewhere}"
    );
}

/// A zenoh transport `Frame` carrying `record`, WITHOUT the stream link's
/// length prefix — a datagram is its own framing unit.
fn datagram_frame(record: &[u8]) -> Vec<u8> {
    let mut frame = vec![wz_session_core::wire_const::T_MID_FRAME, 0x00];
    frame.extend_from_slice(record);
    frame
}

/// Ethernet + IPv4 + UDP from 50000 to the zenoh port, carrying `payload`.
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
    // Checked, so the report this fixture produces carries no finding of its
    // own: an `ip_checksum_invalid` beside the rows would be a second thing for
    // a reader of a failure here to rule out.
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

/// A DATAGRAM capture whose one message is a reply carrying `PROTOBUF` under
/// `demo/a`.
fn protobuf_datagram_capture() -> Vec<u8> {
    let packet = udp_to_zenoh(&datagram_frame(&reply(7, "demo/a", PROTOBUF)));
    wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &packet)],
    )
}

/// A TLS capture whose one decrypted record carries that same reply, and the
/// key log that opens it.
fn protobuf_tls_capture() -> (Vec<u8>, String) {
    let secret: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(11).wrapping_add(3))
        .collect();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(2));
    let mut stream = client_hello(&random);
    let mut enc = sealer(&secret);
    stream.extend_from_slice(&seal_at(
        &mut enc,
        rustls::ContentType::ApplicationData,
        &framed_frame(&reply(7, "demo/a", PROTOBUF)),
        0,
    ));
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

/// R311y701 ([REDACTED-REQ], PF1) — A PAYLOAD-FORMAT RULE REACHES EVERY ROW PRODUCER,
/// NOT ONLY THE CLEARTEXT STREAM.
///
/// ## The defect, measured before the fix
///
/// R311y699 attached `--payload-format` inside `render_field_row`, which draws
/// exactly one of this crate's three row producers. `render_sink_row` draws the
/// other two — the rows a TLS decryption produced, and every datagram row — and
/// carried no payload block at all. A reader who typed a rule and pointed it at
/// a multicast capture or a decrypted session got a listing with NO payload
/// section, which is the rendering for "no rule matched": the tool reported the
/// absence of a finding rather than the absence of a lookup.
///
/// ## Why this shape gets its own test rather than a line in the R311y699 one
///
/// It is the FOURTH time a plane in this crate reached one producer — R311y668
/// (`--flows`), R311y678 (the field layer), R311y699 (payloads), this. So the
/// witness is built the way the repetition says to build it: the SAME rule and
/// the SAME payload bytes driven through each producer, so a future plane can be
/// checked by copying the shape rather than by remembering the lesson.
///
/// ## Anti-vacuity
///
/// Each capture is run WITHOUT the rule as well. The decoded fields must be
/// absent there, or "the rule fired" would be a claim about a listing that
/// prints those fields regardless.
#[test]
fn a_payload_format_rule_reaches_every_row_producer() {
    let scratch = Scratch::new("payload-format-producers");
    let run = |path: &std::path::Path, args: &[&str]| {
        String::from_utf8_lossy(
            &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
                .arg(path)
                .args(args)
                .output()
                .expect("runs")
                .stdout,
        )
        .into_owned()
    };

    // PRODUCER 2 — the DATAGRAM rows.
    let datagram = scratch.write("dgram.pcapng", &protobuf_datagram_capture());
    let bare = run(&datagram, &["--fields"]);
    assert!(
        bare.contains("payload"),
        "the fixture must reach the field listing at all, or every claim below \
         is about an empty page: {bare}"
    );
    assert!(
        !bare.contains("as protobuf"),
        "ANTI-VACUITY: no rule, no payload block: {bare}"
    );
    let told = run(
        &datagram,
        &["--fields", "--payload-format", "demo/**=protobuf"],
    );
    assert!(
        told.contains("payload `demo/a` as protobuf:"),
        "a datagram row must carry the payload decoding -- it did not before \
         R311y701, and the absence read as `no rule matched`: {told}"
    );
    assert!(
        told.contains("1 = varint 150") && told.contains("2 = len \"zenoh\""),
        "with the fields actually decoded: {told}"
    );
    // And in the OTHER rendering, which is a separate branch of the same
    // function -- the shape R311y664 found rendering two different verdicts.
    let json = run(
        &datagram,
        &["--fields", "--json", "--payload-format", "demo/**=protobuf"],
    );
    assert!(
        json.contains("\"payload_decode\":{\"state\":\"decoded\",\"keyexpr\":\"demo/a\"")
            && json.contains("\"value\":\"varint 150\""),
        "the JSON row carries it too: {json}"
    );

    // PRODUCER 3 — the DECRYPTED rows.
    let (file, log) = protobuf_tls_capture();
    let tls = scratch.write("tls.pcapng", &file);
    let keylog = scratch.write("keys.txt", log.as_bytes());
    let keylog = keylog.to_string_lossy().into_owned();
    let bare = run(&tls, &["--fields", "--keylog", &keylog]);
    assert!(
        bare.contains("(decrypted)"),
        "the fixture must actually decrypt, or this half tests nothing: {bare}"
    );
    assert!(
        !bare.contains("as protobuf"),
        "ANTI-VACUITY: no rule, no payload block: {bare}"
    );
    let told = run(
        &tls,
        &[
            "--fields",
            "--keylog",
            &keylog,
            "--payload-format",
            "demo/**=protobuf",
        ],
    );
    assert!(
        told.contains("payload `demo/a` as protobuf:"),
        "a decrypted row must carry it as well: {told}"
    );
    assert!(
        told.contains("1 = varint 150"),
        "with the fields decoded out of the PLAINTEXT: {told}"
    );
}

/// A `Wireexpr` naming an id in the SENDER's space, with an optional suffix
/// appended to whatever that id was bound to.
fn aliased_keyexpr(
    id: u64,
    suffix: Option<&'static str>,
) -> wz_codecs::wireexpr::Wireexpr<'static> {
    wz_codecs::wireexpr::Wireexpr {
        body: wz_codecs::wireexpr::WireexprVariant::WireexprLocal(
            wz_codecs::wireexpr_local::WireexprLocal {
                id,
                suffix_len: suffix.map(|s| s.len() as u64),
                suffix,
            },
        ),
    }
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

/// A reply under an ALIASED keyexpr, carrying `payload`.
fn aliased_reply(
    request_id: u64,
    id: u64,
    suffix: Option<&'static str>,
    payload: &'static [u8],
) -> Vec<u8> {
    let n_flag = if suffix.is_some() {
        wz_codecs::wire_const::FLAG_N_N
    } else {
        0
    };
    wz_codecs::response::Response {
        header: wz_codecs::response::Response::default().header | n_flag,
        request_id,
        keyexpr: aliased_keyexpr(id, suffix),
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

/// R311y701 ([REDACTED-REQ], PF2) — A KEYEXPR NAMED BY NUMERIC ID IS RESOLVED, and a
/// suffix hanging off an id gets its BASE.
///
/// ## Two defects, and the second is the worse one
///
/// R311y699 read the wire `suffix` and stopped, on the note that the id table
/// lived in another plane. The visible cost was silence: a capture taken from a
/// running system names every keyexpr by id, so every `--payload-format` rule
/// matched nothing and the listing said `keyexpr_unresolved` per message.
///
/// The cost that was not noticed is that a message carrying an id AND a suffix
/// has the id's base PREPENDED. Reading the suffix alone reported `/temp` for a
/// record published under `demo/sensor/temp` — a WRONG keyexpr rather than a
/// missing one, so a rule keyed on `demo/**` silently did not fire on traffic
/// it covers, and a reader had no way to tell that from an empty topic.
///
/// ## Anti-vacuity
///
/// A rule for `other/**` is run over the same capture. If it fired, "resolved
/// to demo/..." would be a claim about a listing that decodes regardless.
#[test]
fn a_keyexpr_named_by_id_is_resolved_through_the_declaration_the_capture_carried() {
    let scratch = Scratch::new("payload-format-alias");
    let mut client = Vec::new();
    client.extend_from_slice(&framed_frame(&query(7, "demo/**")));
    let mut server = Vec::new();
    // The declaration first, exactly as a real session sends it...
    server.extend_from_slice(&framed_frame(&declare_kexpr(5, "demo/sensor")));
    // ...then a reply under the bare id, and one under the id plus a suffix.
    server.extend_from_slice(&framed_frame(&aliased_reply(7, 5, None, PROTOBUF)));
    server.extend_from_slice(&framed_frame(&aliased_reply(8, 5, Some("/temp"), PROTOBUF)));
    let file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[
            (0, 1_000_000, &tcp_packet(1000, &client)),
            (0, 1_030_000, &tcp_packet_reverse(1000, &server)),
        ],
    );
    let capture = scratch.write("alias.pcapng", &file);

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

    let told = run(&["--fields", "--payload-format", "demo/**=protobuf"]);
    assert!(
        told.contains("payload `demo/sensor` as protobuf:"),
        "the bare id resolves to what the capture's own DeclKexpr bound it to: \
         {told}"
    );
    assert!(
        told.contains("payload `demo/sensor/temp` as protobuf:"),
        "and a suffix hanging off that id gets the base PREPENDED -- reading \
         the suffix alone reported `/temp`, which is a wrong keyexpr and not a \
         missing one: {told}"
    );
    assert!(
        !told.contains("keyexpr_unresolved") && !told.contains("no --payload-format rule"),
        "neither message is refused any more: {told}"
    );
    assert!(
        told.matches("1 = varint 150").count() == 2,
        "both payloads are decoded: {told}"
    );

    // ANTI-VACUITY: a rule for another subtree still does not fire, and names
    // the RESOLVED keyexpr it tested -- which is the half a reader acts on.
    let elsewhere = run(&["--fields", "--payload-format", "other/**=protobuf"]);
    assert!(
        elsewhere.contains("no --payload-format rule covers `demo/sensor`"),
        "the keyexpr that was tested is the resolved one: {elsewhere}"
    );
    assert!(
        !elsewhere.contains("varint 150"),
        "and nothing was decoded: {elsewhere}"
    );
}

/// `{ 1: 150, 2: { 1: 7, 2: "in" } }` — the nested shape, by hand.
const NESTED_PROTOBUF: &[u8] = &[
    0x08, 0x96, 0x01, // 1: varint 150
    0x12, 0x06, // 2: len 6
    0x08, 0x07, // 2.1: varint 7
    0x12, 0x02, b'i', b'n', // 2.2: len "in"
];

/// R311y701 ([REDACTED-REQ], PF3) — A NESTED PAYLOAD IS WALKED ALL THE WAY DOWN, run
/// through the binary rather than only through the decoder.
///
/// The decoder's own tests pin the walk. This pins that a person pointing the
/// tool at a capture SEES it: R311y664's rule is that a library nobody runs
/// hides its own lies, and the lie available here is the rebase — the nested
/// spans are computed against the sub-buffer and then moved twice, once into
/// the payload and once into the message.
#[test]
fn a_nested_payload_is_decoded_to_its_leaves_at_the_command_line() {
    let scratch = Scratch::new("payload-format-nested");
    let mut client = Vec::new();
    client.extend_from_slice(&framed_frame(&query(7, "demo/**")));
    let mut server = Vec::new();
    server.extend_from_slice(&framed_frame(&reply(7, "demo/a", NESTED_PROTOBUF)));
    let file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[
            (0, 1_000_000, &tcp_packet(1000, &client)),
            (0, 1_030_000, &tcp_packet_reverse(1000, &server)),
        ],
    );
    let capture = scratch.write("nested.pcapng", &file);

    let out = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--fields")
            .arg("--payload-format")
            .arg("demo/**=protobuf")
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();

    assert!(
        out.contains("1 = varint 150"),
        "the outer fields are still walked: {out}"
    );
    assert!(
        out.contains("2 = len 2 field(s)"),
        "and a length field holding a message says how many are under it \
         rather than printing a byte count: {out}"
    );
    assert!(
        out.contains("2.1 = varint 7") && out.contains("2.2 = len \"in\""),
        "the LEAVES reach the listing, named by the route to them -- before \
         R311y701 the walk stopped at `2`: {out}"
    );

    // THE COORDINATES, one layer in. Every span in this listing is
    // message-relative; a nested span is computed against the sub-buffer and
    // has to be moved twice to get there, so it is the one most likely to be
    // in the wrong space. `2.1` begins two bytes past where `2`'s body does.
    let outer_at = out
        .lines()
        .find_map(|line| {
            let line = line.trim();
            let (span, name) = line.strip_prefix('[')?.split_once(']')?;
            (name.trim().starts_with("2 = len")).then(|| {
                span.split_once("..")
                    .and_then(|(start, _)| start.parse::<usize>().ok())
            })?
        })
        .expect("the nested field is in the listing");
    assert!(
        out.contains(&format!(
            "[{}..{}] 2.1 = varint 7",
            outer_at + 2,
            outer_at + 4
        )),
        "the first nested field sits at the parent's tag and length plus its \
         own offset (parent begins at {outer_at}): {out}"
    );
}

/// R311y699 ([REDACTED-REQ]) — a format name this build has no decoder for is REFUSED
/// at the command line, and the refusal says what it does have.
///
/// A reader who typed `protobufff` and got their payload rendered as raw bytes
/// would believe their rule was live. That is the same failure the wildcard
/// refusal in `payload::formats` exists for, one layer out.
#[test]
fn a_format_name_this_build_cannot_decode_is_refused_at_the_command_line() {
    let scratch = Scratch::new("payload-format-unknown");
    let capture = scratch.write("pb.pcapng", &protobuf_capture());

    let output = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .arg("--fields")
        .arg("--payload-format")
        .arg("demo/**=protobufff")
        .output()
        .expect("runs");
    assert_eq!(
        output.status.code(),
        Some(2),
        "a rule this build cannot honour is a usage error, not a run that \
         quietly does less"
    );
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(
        err.contains("--payload-format"),
        "and the message names the option: {err}"
    );

    // A rule with no `=` at all is the other half of the same refusal.
    let output = Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
        .arg(&capture)
        .arg("--fields")
        .arg("--payload-format")
        .arg("demo/**")
        .output()
        .expect("runs");
    assert_eq!(output.status.code(), Some(2));
}

/// R311y699 ([REDACTED-REQ]) — the JSON carries the decoding, in one document.
#[test]
fn the_payload_decoding_reaches_the_json_as_one_document() {
    let scratch = Scratch::new("payload-format-json");
    let capture = scratch.write("pb.pcapng", &protobuf_capture());

    let text = String::from_utf8_lossy(
        &Command::new(env!("CARGO_BIN_EXE_wz-analyze"))
            .arg(&capture)
            .arg("--fields")
            .arg("--json")
            .arg("--payload-format")
            .arg("demo/**=protobuf")
            .output()
            .expect("runs")
            .stdout,
    )
    .into_owned();

    let parsed: serde_json::Value = serde_json::from_str(&text).expect("one valid document");
    let rows = parsed["fields"].as_array().expect("a field listing");
    let decoded = rows
        .iter()
        .find(|row| row["payload_decode"]["state"] == serde_json::json!("decoded"))
        .expect("one row decoded its payload");
    assert_eq!(
        decoded["payload_decode"]["keyexpr"],
        serde_json::json!("demo/a")
    );
    assert_eq!(
        decoded["payload_decode"]["format"],
        serde_json::json!("protobuf")
    );
    let fields = decoded["payload_decode"]["fields"]
        .as_array()
        .expect("the decoded fields");
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0]["path"], serde_json::json!("1"));
    assert_eq!(fields[0]["value"], serde_json::json!("varint 150"));
    // The spans are the SAME numbers the text rendering printed, which is what
    // stops the two renderings from drifting into two coordinate spaces.
    assert!(
        fields[1]["start"].as_u64().expect("a start") == fields[0]["end"].as_u64().expect("an end"),
        "the second field begins where the first ends: {decoded}"
    );
    // A row whose keyexpr no rule covers says so rather than being absent --
    // the state a reader needs to tell "rule did not fire" from "rule fired and
    // found nothing".
    assert!(
        rows.iter().any(
            |row| row["payload_decode"]["state"] == serde_json::json!("no_rule")
                || row["payload_decode"]["state"] == serde_json::json!("no_payload")
        ),
        "the other messages carry a state too: {text}"
    );
}
