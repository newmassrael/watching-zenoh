// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y660 (§1.2a) — THE WHOLE CHAIN, in one test.
//!
//! Every round of this track proved one link. R311y648 recognised an encrypted
//! flow; R311y657 opened a record given a secret; R311y658 read a key log out of
//! a capture file; R311y659 read the ClientHello random the log is indexed by;
//! R311y660 numbered and kept the records. Each was gated on its own, and a
//! chain of separately-proven links is not a proven chain — the joins are
//! exactly where a coordinate, a length or an index goes wrong with neither
//! side noticing.
//!
//! This drives all of it: rustls seals real records, `wz-capture` dissects the
//! TCP stream carrying them, a key log in that capture's own format yields the
//! secret, and this crate opens what the capture kept.

use rustls::crypto::cipher::{AeadKey, Iv, OutboundPlainMessage};
use wz_tls_record::capture::CaptureOpener;
use wz_tls_record::keylog::{KeyLog, SecretLabel, SECRETS_TYPE_TLS_KEY_LOG};
use wz_tls_record::{expand_label, Suite, TrafficKeys};

/// The suite: a 32-byte one, because rustls can only be handed a 32-byte key
/// through its public API (`AeadKey: From<[u8; 32]>`), which R311y657 measured
/// and recorded.
const SUITE: Suite = Suite::Aes256GcmSha384;

/// The traffic secret, as a key log would carry it. Fixed rather than random:
/// a fixture that varies per run cannot be quoted in a failure report.
fn traffic_secret() -> Vec<u8> {
    (0..48u8)
        .map(|i| i.wrapping_mul(11).wrapping_add(3))
        .collect()
}

/// Ethernet + IPv4 + TCP from low to high, carrying `payload` at `seq`.
fn tcp_packet(seq: u32, payload: &[u8]) -> Vec<u8> {
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

    let mut ip = vec![0x45u8, 0];
    ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
    ip.extend_from_slice(&[10, 0, 0, 1]);
    ip.extend_from_slice(&[10, 0, 0, 2]);
    ip.extend_from_slice(&tcp);

    let mut eth = vec![0u8; 12];
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&ip);
    while eth.len() < 60 {
        eth.push(0);
    }
    eth
}

/// A ClientHello record carrying `random`, well-formed enough that
/// `wz-capture`'s recogniser answers `Yes` — which R311y649 made deliberately
/// hard to satisfy by accident.
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// R311y660 — a capture goes in and PLAINTEXT comes out.
#[test]
fn a_captured_tls_flow_is_decrypted_with_the_captures_own_key_log() {
    let secret = traffic_secret();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(2));

    // The payloads are ZENOH-SHAPED, which is the point of the whole track: a
    // framed KeepAlive is what the reader would have decoded had the link been
    // in cleartext, and what it reported as nothing before R311y648.
    let payloads: Vec<Vec<u8>> = (0..3u8)
        .map(|i| {
            let unit = vec![0x04u8, i];
            let mut framed = (unit.len() as u16).to_le_bytes().to_vec();
            framed.extend_from_slice(&unit);
            framed
        })
        .collect();

    // THE SEALING SIDE derives key and iv through this crate's own
    // `expand_label` -- the same function the opening side uses, which is
    // legitimate here because what this test gates is the JOINS, and the
    // derivation itself is gated differentially against rustls in the unit
    // tests. What it must not share is the sealing implementation, and that is
    // rustls's.
    let mut key = [0u8; 32];
    expand_label(SUITE, &secret, b"key", &[], &mut key);
    let mut iv = [0u8; 12];
    expand_label(SUITE, &secret, b"iv", &[], &mut iv);
    let t13 = rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384
        .tls13()
        .expect("a TLS 1.3 suite");
    let mut enc = t13.aead_alg.encrypter(AeadKey::from(key), Iv::from(iv));

    let mut stream = client_hello(&random);
    for (seq, payload) in payloads.iter().enumerate() {
        let sealed = enc
            .encrypt(
                OutboundPlainMessage {
                    typ: rustls::ContentType::ApplicationData,
                    version: rustls::ProtocolVersion::TLSv1_2,
                    payload: rustls::crypto::cipher::OutboundChunks::Single(payload),
                },
                seq as u64,
            )
            .expect("seal");
        stream.extend_from_slice(&sealed.encode());
    }

    // THE CAPTURE. One TCP flow carrying the hello and the three records.
    let mut d = wz_capture::Dissection::new();
    d.push_packet(
        wz_capture::link::LINKTYPE_ETHERNET,
        0,
        &tcp_packet(1000, &stream),
    );
    d.finish();

    let flows = d.encrypted_flows();
    assert_eq!(flows.len(), 1, "the capture must recognise one TLS flow");
    assert_eq!(
        flows[0].client_random,
        Some(random),
        "and read the random the key log is indexed by"
    );
    assert_eq!(
        flows[0].kept_records[0].len(),
        3,
        "the three protected records are kept; the ClientHello is not, because \
         it is not protected"
    );
    assert_eq!(flows[0].records_dropped, [0, 0]);
    assert_eq!(
        flows[0].kept_records[0]
            .iter()
            .map(|r| r.index)
            .collect::<Vec<_>>(),
        vec![0, 1, 2],
        "numbered from zero WITHIN the direction"
    );

    // THE CAPTURE'S OWN KEY LOG, in the form a Decryption Secrets Block carries.
    let log_text = format!(
        "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
        hex(&random),
        hex(&secret)
    );
    let log = KeyLog::from_secrets_block(SECRETS_TYPE_TLS_KEY_LOG, log_text.as_bytes())
        .expect("a TLS key log");
    let secrets = log
        .get(&flows[0].client_random.expect("the capture read one"))
        .expect("the log is indexed by exactly what the capture reported");
    let from_log = secrets
        .get(SecretLabel::ClientApplication)
        .expect("the client's application secret");

    // AND THE PLAINTEXT COMES OUT.
    let keys = TrafficKeys::derive(SUITE, from_log);
    for (record, expected) in flows[0].kept_records[0].iter().zip(payloads.iter()) {
        let mut bytes = record.bytes.clone();
        let opened = keys
            .open(record.index, &mut bytes)
            .unwrap_or_else(|e| panic!("record {} did not open: {e:?}", record.index));
        assert_eq!(
            opened.plaintext,
            &expected[..],
            "record {} decrypted to the wrong bytes",
            record.index
        );
        assert_eq!(opened.content_type, 23, "application data");
    }

    // THE DISCRIMINATOR, and without it "it decrypted" says only that something
    // was decryptable: the SECOND record must NOT open at the first one's
    // index, so the numbering the capture assigned is load bearing rather than
    // decorative.
    let mut second = flows[0].kept_records[0][1].bytes.clone();
    assert!(
        keys.open(0, &mut second).is_err(),
        "record 1 opened at index 0 -- the index is not being used"
    );
}

/// R311y660 — and the flow the chain CANNOT serve, pinned so the limit is a
/// statement rather than a surprise.
///
/// A capture that began mid-session has no ClientHello, so it has no random,
/// so no key log entry can be selected for it — however many secrets the file
/// carries. The records are still kept and still numbered; what is missing is
/// the connection's identity.
#[test]
fn a_mid_session_flow_keeps_its_records_and_cannot_be_matched_to_a_log() {
    let secret = traffic_secret();
    let mut key = [0u8; 32];
    expand_label(SUITE, &secret, b"key", &[], &mut key);
    let mut iv = [0u8; 12];
    expand_label(SUITE, &secret, b"iv", &[], &mut iv);
    let t13 = rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384
        .tls13()
        .expect("a TLS 1.3 suite");
    let mut enc = t13.aead_alg.encrypter(AeadKey::from(key), Iv::from(iv));

    // No hello: the capture starts on application data, which is the ordinary
    // shape of a SPAN port attached to a link that was already up.
    let mut stream = Vec::new();
    for seq in 0..2u64 {
        let sealed = enc
            .encrypt(
                OutboundPlainMessage {
                    typ: rustls::ContentType::ApplicationData,
                    version: rustls::ProtocolVersion::TLSv1_2,
                    payload: rustls::crypto::cipher::OutboundChunks::Single(b"zenoh"),
                },
                seq,
            )
            .expect("seal");
        stream.extend_from_slice(&sealed.encode());
    }

    let mut d = wz_capture::Dissection::new();
    d.push_packet(
        wz_capture::link::LINKTYPE_ETHERNET,
        0,
        &tcp_packet(1000, &stream),
    );
    d.finish();

    let flows = d.encrypted_flows();
    assert_eq!(
        flows.len(),
        1,
        "the chain question recognises it (R311y649)"
    );
    assert_eq!(
        flows[0].client_random, None,
        "and there is no ClientHello in it to read a random from"
    );
    assert_eq!(
        flows[0].kept_records[0].len(),
        2,
        "the records are kept regardless -- what is missing is the identity, \
         not the ciphertext"
    );

    // Given the secret BY OTHER MEANS the records open, which is what makes
    // the missing piece an identity problem and not a decryption one.
    let keys = TrafficKeys::derive(SUITE, &secret);
    let mut bytes = flows[0].kept_records[0][1].bytes.clone();
    let opened = keys.open(1, &mut bytes).expect("record 1");
    assert_eq!(opened.plaintext, b"zenoh");
}

/// R311y661 (§1.2a) — THE PRODUCTION PATH. A capture FILE goes in, and the
/// zenoh session inside its TLS comes out.
///
/// R311y660's test above proves the chain by holding every piece itself: it
/// builds the dissection in memory, reaches into `kept_records`, parses the key
/// log by hand and calls `open` per record. That is a proof about the PARTS.
/// What it does not touch is the path a caller actually has — a `.pcapng` on
/// disk — and along that path the keys were being thrown away: `from_pcapng`
/// parsed the Decryption Secrets Block and dropped it, so the reader reported
/// `no_keys_supplied` about a file whose keys it had read.
///
/// Here nothing is reached into. The file is parsed by `from_pcapng`, the
/// opener is built from what that parse carried, and the frames are read off
/// the flow like any other flow's.
#[test]
fn a_pcapng_carrying_its_own_key_log_decrypts_through_the_public_path() {
    let secret = traffic_secret();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(9));

    let payloads: Vec<Vec<u8>> = (0..3u8)
        .map(|i| {
            // A framed zenoh KeepAlive, which is what the reader must decode.
            let unit = vec![0x04u8, i];
            let mut framed = (unit.len() as u16).to_le_bytes().to_vec();
            framed.extend_from_slice(&unit);
            framed
        })
        .collect();

    let mut key = [0u8; 32];
    expand_label(SUITE, &secret, b"key", &[], &mut key);
    let mut iv = [0u8; 12];
    expand_label(SUITE, &secret, b"iv", &[], &mut iv);
    let t13 = rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384
        .tls13()
        .expect("a TLS 1.3 suite");
    let mut enc = t13.aead_alg.encrypter(AeadKey::from(key), Iv::from(iv));

    let mut stream = client_hello(&random);
    for (seq, payload) in payloads.iter().enumerate() {
        let sealed = enc
            .encrypt(
                OutboundPlainMessage {
                    typ: rustls::ContentType::ApplicationData,
                    version: rustls::ProtocolVersion::TLSv1_2,
                    payload: rustls::crypto::cipher::OutboundChunks::Single(payload),
                },
                seq as u64,
            )
            .expect("seal");
        stream.extend_from_slice(&sealed.encode());
    }

    // THE FILE: one Ethernet interface, one packet, and the key log in the
    // block the format defines for it.
    let packet = tcp_packet(1000, &stream);
    let mut file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &packet)],
    );
    let log_text = format!(
        "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
        hex(&random),
        hex(&secret)
    );
    file.extend_from_slice(&decryption_secrets_block(
        SECRETS_TYPE_TLS_KEY_LOG,
        log_text.as_bytes(),
    ));

    // THE PUBLIC PATH, and every step of it is a call a caller can make.
    let mut d = wz_capture::Dissection::from_pcapng(&file).expect("the file parses");
    assert_eq!(
        d.encrypted_flows().len(),
        1,
        "the flow must be recognised as encrypted"
    );
    assert_eq!(
        d.flows()[0].frames.len(),
        0,
        "and decode nothing until the keys are applied"
    );

    let (mut opener, skipped) = CaptureOpener::from_secrets_blocks(d.decryption_secrets());
    assert_eq!(skipped, 0, "the file's only secrets block IS a TLS key log");
    assert_eq!(
        opener.log().len(),
        1,
        "the capture's own key log reached the opener"
    );

    let summary = d.decrypt_with(&mut opener);

    assert_eq!(summary.flows, 1);
    assert_eq!(summary.decrypted, 1, "summary={summary:?}");
    assert_eq!(summary.records, 3);
    assert_eq!(
        summary.frames, 3,
        "THE POINT: three zenoh messages out of a file that reported none"
    );

    // AND THE FRAMES ARE ZENOH, read off the flow exactly as a cleartext
    // capture's would be.
    let frames = &d.flows()[0].frames;
    assert_eq!(frames.len(), 3);
    for frame in frames {
        assert!(
            frame.frame.is_ok(),
            "a decrypted frame must PARSE, not merely appear: {:?}",
            frame.frame
        );
    }
    // Each frame attributes to the packet that carried its record -- there is
    // one packet here, so the claim under test is that the offset resolves at
    // all rather than falling outside the stream.
    for frame in frames {
        assert_eq!(
            d.flows()[0].packet_for(frame.direction, frame.stream_offset),
            Some(0),
            "offset {} resolved to no packet",
            frame.stream_offset
        );
    }

    // AND THE REPORT SAYS SO. This is the statement that was false: a capture
    // carrying its own keys reported `"decrypted":false` and
    // `"reason":"no_keys_supplied"`.
    let json = wz_capture::report::CaptureReport::of(&d).to_json();
    assert!(
        json.contains("\"decrypted\":true"),
        "the report must claim the decryption it performed: {json}"
    );
    assert!(
        json.contains("\"records_decrypted\":3"),
        "with the record count: {json}"
    );
}

/// R311y661 — and a file whose key log is for ANOTHER connection is refused by
/// name rather than reported as keyless.
///
/// The discriminator for the reason strings: this capture and one with no
/// secrets block at all are the same to a reader who is told only
/// `no_keys_supplied`, and they need different things done about them.
#[test]
fn a_pcapng_whose_key_log_is_for_another_connection_says_which_refusal_it_is() {
    let secret = traffic_secret();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(9));

    let mut key = [0u8; 32];
    expand_label(SUITE, &secret, b"key", &[], &mut key);
    let mut iv = [0u8; 12];
    expand_label(SUITE, &secret, b"iv", &[], &mut iv);
    let t13 = rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384
        .tls13()
        .expect("a TLS 1.3 suite");
    let mut enc = t13.aead_alg.encrypter(AeadKey::from(key), Iv::from(iv));

    let mut stream = client_hello(&random);
    for seq in 0..2u64 {
        let sealed = enc
            .encrypt(
                OutboundPlainMessage {
                    typ: rustls::ContentType::ApplicationData,
                    version: rustls::ProtocolVersion::TLSv1_2,
                    payload: rustls::crypto::cipher::OutboundChunks::Single(b"\x02\x00\x04\x01"),
                },
                seq,
            )
            .expect("seal");
        stream.extend_from_slice(&sealed.encode());
    }

    let packet = tcp_packet(1000, &stream);
    let mut file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &packet)],
    );
    // A REAL key log, for a connection that is not this one.
    let other: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(200));
    let log_text = format!("CLIENT_TRAFFIC_SECRET_0 {} {}\n", hex(&other), hex(&secret));
    file.extend_from_slice(&decryption_secrets_block(
        SECRETS_TYPE_TLS_KEY_LOG,
        log_text.as_bytes(),
    ));

    let mut d = wz_capture::Dissection::from_pcapng(&file).expect("the file parses");
    let (mut opener, _) = CaptureOpener::from_secrets_blocks(d.decryption_secrets());
    assert_eq!(opener.log().len(), 1, "the log itself is fine");

    let summary = d.decrypt_with(&mut opener);
    assert_eq!(summary.refused, 1);
    assert_eq!(summary.frames, 0);
    assert_eq!(
        d.encrypted_flows()[0].not_decrypted,
        Some(wz_capture::tls::NotDecrypted::NoKeyForSession),
        "keys were supplied and are for another session -- that is not the \
         same finding as no keys at all"
    );

    let json = wz_capture::report::CaptureReport::of(&d).to_json();
    assert!(
        json.contains("\"reason\":\"no_key_for_session\""),
        "and the report must carry the distinction: {json}"
    );
}

/// A pcapng Decryption Secrets Block wrapping `secrets`.
fn decryption_secrets_block(secrets_type: u32, secrets: &[u8]) -> Vec<u8> {
    let mut body = secrets_type.to_le_bytes().to_vec();
    body.extend_from_slice(&(secrets.len() as u32).to_le_bytes());
    body.extend_from_slice(secrets);
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    let total = (12 + body.len()) as u32;
    let mut out = 0x0000_000Au32.to_le_bytes().to_vec();
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&total.to_le_bytes());
    out
}

/// A record sealer for one secret, so a test can drive two EPOCHS.
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

/// R311y662 (§1.2a) — THE ORDINARY SHAPE: a capture taken from the start of the
/// connection, whose first protected records are the handshake flight.
///
/// This is what R311y661 could not read, and it is not a corner case — it is
/// every capture of a session whose start was recorded. TLS 1.3 hides the real
/// content type inside the protected payload and writes `application_data` in
/// the outer header of the handshake flight too, so `wz-capture` keeps and
/// numbers those records along with the session's. The application secret opens
/// none of them, and R311y661 stopped at index 0 and reported
/// `RecordRefusedKeys` — a true statement that amounted to decrypting nothing.
///
/// The boundary cannot be read off the wire: the `Finished` that ends the
/// handshake epoch is itself encrypted. It is found by TRIAL, and this test is
/// what says the trial finds it.
#[test]
fn a_capture_of_a_full_handshake_finds_the_epoch_boundary_by_trial() {
    let handshake_secret: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(1))
        .collect();
    let application_secret = traffic_secret();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(4));

    let mut stream = client_hello(&random);

    // THE HANDSHAKE FLIGHT: two records under the handshake secret, sequences 0
    // and 1, carrying `handshake` as their INNER content type.
    let mut hs = sealer(&handshake_secret);
    for seq in 0..2u64 {
        let sealed = hs
            .encrypt(
                OutboundPlainMessage {
                    typ: rustls::ContentType::Handshake,
                    version: rustls::ProtocolVersion::TLSv1_2,
                    payload: rustls::crypto::cipher::OutboundChunks::Single(
                        b"\x08\x00\x00\x02\x00\x00",
                    ),
                },
                seq,
            )
            .expect("seal");
        stream.extend_from_slice(&sealed.encode());
    }

    // THE SESSION: three records under the application secret, and its sequence
    // RESTARTS AT ZERO -- which is the whole difficulty.
    let payloads: Vec<Vec<u8>> = (0..3u8)
        .map(|i| {
            let unit = vec![0x04u8, i];
            let mut framed = (unit.len() as u16).to_le_bytes().to_vec();
            framed.extend_from_slice(&unit);
            framed
        })
        .collect();
    let mut app = sealer(&application_secret);
    for (seq, payload) in payloads.iter().enumerate() {
        let sealed = app
            .encrypt(
                OutboundPlainMessage {
                    typ: rustls::ContentType::ApplicationData,
                    version: rustls::ProtocolVersion::TLSv1_2,
                    payload: rustls::crypto::cipher::OutboundChunks::Single(payload),
                },
                seq as u64,
            )
            .expect("seal");
        stream.extend_from_slice(&sealed.encode());
    }

    let packet = tcp_packet(1000, &stream);
    let mut file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &packet)],
    );
    let log_text = format!(
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET {} {}\nCLIENT_TRAFFIC_SECRET_0 {} {}\n",
        hex(&random),
        hex(&handshake_secret),
        hex(&random),
        hex(&application_secret)
    );
    file.extend_from_slice(&decryption_secrets_block(
        SECRETS_TYPE_TLS_KEY_LOG,
        log_text.as_bytes(),
    ));

    let mut d = wz_capture::Dissection::from_pcapng(&file).expect("the file parses");
    assert_eq!(
        d.encrypted_flows()[0].kept_records[0].len(),
        5,
        "the flight is KEPT along with the session -- that is why the epoch is a \
         problem in the first place"
    );

    let (mut opener, _) = CaptureOpener::from_secrets_blocks(d.decryption_secrets());
    let summary = d.decrypt_with(&mut opener);

    assert_eq!(
        summary.records, 5,
        "all five open: two under the handshake keys, three under the \
         application keys at a sequence that restarted"
    );
    assert_eq!(
        summary.decrypted, 1,
        "and the flow is fully decrypted, not stopped at index 0: {summary:?}"
    );
    assert_eq!(
        summary.frames, 3,
        "only the three application records are zenoh; the flight is opened and \
         withheld from the reader"
    );
    assert_eq!(d.encrypted_flows()[0].not_decrypted, None);
    assert_eq!(d.encrypted_flows()[0].decrypted_records, [5, 0]);

    // THE DISCRIMINATOR, and without it this test passes on a reader that simply
    // tried every secret against every record: the boundary must be found at
    // index 2 and the sequence must RESTART there. A reader that kept counting
    // would open record 2 at sequence 2 under the application keys, which is a
    // different nonce and fails to authenticate -- so `records == 5` above
    // already depends on the restart. This states it as the claim it is.
    let json = wz_capture::report::CaptureReport::of(&d).to_json();
    assert!(
        json.contains("\"records_decrypted\":5") && json.contains("\"decrypted\":true"),
        "the report must carry the whole flow: {json}"
    );
}

/// R311y662 — the SERVER direction, end to end.
///
/// R311y661 wired both directions and drove only direction A. "The same code"
/// is what R311y655 and R311y656 each found to be untrue at a second site, and
/// this path has a genuine asymmetry in it: the server's records open under
/// `SERVER_TRAFFIC_SECRET_0` and the assignment depends on
/// `client_direction`, which is read from whichever side sent the ClientHello.
#[test]
fn the_server_direction_decrypts_with_its_own_secret() {
    let client_secret = traffic_secret();
    let server_secret: Vec<u8> = (0..48u8)
        .map(|i| i.wrapping_mul(13).wrapping_add(5))
        .collect();
    let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(6));

    let mut from_client = client_hello(&random);
    let mut c = sealer(&client_secret);
    let sealed = c
        .encrypt(
            OutboundPlainMessage {
                typ: rustls::ContentType::ApplicationData,
                version: rustls::ProtocolVersion::TLSv1_2,
                payload: rustls::crypto::cipher::OutboundChunks::Single(b"\x02\x00\x04\x01"),
            },
            0,
        )
        .expect("seal");
    from_client.extend_from_slice(&sealed.encode());

    // The server's half, sealed with the SERVER secret. Two records, so the
    // sequence is exercised on this side too.
    let mut from_server = Vec::new();
    let mut s = sealer(&server_secret);
    for seq in 0..2u64 {
        let sealed = s
            .encrypt(
                OutboundPlainMessage {
                    typ: rustls::ContentType::ApplicationData,
                    version: rustls::ProtocolVersion::TLSv1_2,
                    payload: rustls::crypto::cipher::OutboundChunks::Single(b"\x02\x00\x04\x01"),
                },
                seq,
            )
            .expect("seal");
        from_server.extend_from_slice(&sealed.encode());
    }

    let mut file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[
            (0, 1_000_000, &tcp_packet(1000, &from_client)),
            (0, 1_000_001, &tcp_packet_from_server(5000, &from_server)),
        ],
    );
    let log_text = format!(
        "CLIENT_TRAFFIC_SECRET_0 {} {}\nSERVER_TRAFFIC_SECRET_0 {} {}\n",
        hex(&random),
        hex(&client_secret),
        hex(&random),
        hex(&server_secret)
    );
    file.extend_from_slice(&decryption_secrets_block(
        SECRETS_TYPE_TLS_KEY_LOG,
        log_text.as_bytes(),
    ));

    let mut d = wz_capture::Dissection::from_pcapng(&file).expect("the file parses");
    let flow = &d.encrypted_flows()[0];
    assert_eq!(
        (flow.kept_records[0].len(), flow.kept_records[1].len()),
        (1, 2),
        "the fixture must put records on BOTH sides or it tests one again"
    );
    assert_eq!(flow.client_direction, Some(wz_capture::tls::Direction::A));

    let (mut opener, _) = CaptureOpener::from_secrets_blocks(d.decryption_secrets());
    let summary = d.decrypt_with(&mut opener);

    assert_eq!(summary.records, 3, "one client record and two server ones");
    assert_eq!(summary.decrypted, 1);
    assert_eq!(
        d.encrypted_flows()[0].decrypted_records,
        [1, 2],
        "the SERVER's records must open under the server's secret -- swapping \
         the two would refuse both sides"
    );
    assert_eq!(summary.frames, 3, "and all three decode as zenoh");
}

/// The server's half of the same 5-tuple: ports and addresses reversed.
fn tcp_packet_from_server(seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&7447u16.to_be_bytes());
    tcp.extend_from_slice(&1111u16.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes());
    tcp.push(5 << 4);
    tcp.push(0x10);
    tcp.extend_from_slice(&64u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(payload);

    let mut ip = vec![0x45u8, 0];
    ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
    ip.extend_from_slice(&[10, 0, 0, 2]);
    ip.extend_from_slice(&[10, 0, 0, 1]);
    ip.extend_from_slice(&tcp);

    let mut eth = vec![0u8; 12];
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&ip);
    while eth.len() < 60 {
        eth.push(0);
    }
    eth
}
