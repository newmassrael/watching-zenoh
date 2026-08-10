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
