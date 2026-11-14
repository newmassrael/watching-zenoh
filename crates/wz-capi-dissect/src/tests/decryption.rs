// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The decryption pass across the boundary.
//!
//! The pass is held where it lives (`wz-tls-record`'s `pass` and
//! `end_to_end` tests, `wz-capture`'s continuing-pass tests). What this crate
//! adds is the boundary: a key log crossing as bytes into the keyed doors and
//! into an open handle, a capture's own Decryption Secrets Blocks reaching the
//! doors that take no key log, and no byte of a key in anything a door writes.
//! The records are sealed by rustls, so what opens them is not checked against
//! itself.

use super::*;

use rustls::crypto::cipher::{AeadKey, Iv, OutboundPlainMessage};
use wz_tls_record::{expand_label, Suite};

/// The client random the capture's ClientHello carries.
const RANDOM: [u8; 32] = [0x5a; 32];

/// The traffic secret. Every byte differs, so its hex is a run no document
/// carries by chance.
fn secret() -> Vec<u8> {
    (0..48u8).map(|i| 0xd0 ^ i.wrapping_mul(7)).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The key log that opens the capture: the client's application secret.
fn key_log() -> String {
    format!(
        "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
        hex(&RANDOM),
        hex(&secret())
    )
}

/// A well-formed key log for another connection: it opens nothing here.
fn other_key_log() -> String {
    format!(
        "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
        hex(&[0x33u8; 32]),
        hex(&secret())
    )
}

fn sealer() -> Box<dyn rustls::crypto::cipher::MessageEncrypter> {
    const SUITE: Suite = Suite::Aes256GcmSha384;
    let secret = secret();
    let mut key = [0u8; 32];
    expand_label(SUITE, &secret, b"key", &[], &mut key);
    let mut iv = [0u8; 12];
    expand_label(SUITE, &secret, b"iv", &[], &mut iv);
    rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384
        .tls13()
        .expect("a TLS 1.3 suite")
        .aead_alg
        .encrypter(AeadKey::from(key), Iv::from(iv))
}

/// One framed zenoh KeepAlive and nothing else in its unit, sealed as
/// application data at sequence `n`.
fn sealed_keep_alive(
    enc: &mut Box<dyn rustls::crypto::cipher::MessageEncrypter>,
    n: u64,
) -> Vec<u8> {
    let unit = [0x04u8];
    let mut framed = (unit.len() as u16).to_le_bytes().to_vec();
    framed.extend_from_slice(&unit);
    enc.encrypt(
        OutboundPlainMessage {
            typ: rustls::ContentType::ApplicationData,
            version: rustls::ProtocolVersion::TLSv1_2,
            payload: rustls::crypto::cipher::OutboundChunks::Single(&framed),
        },
        n,
    )
    .expect("seal")
    .encode()
}

fn client_hello() -> Vec<u8> {
    let mut body = vec![0x03u8, 0x03];
    body.extend_from_slice(&RANDOM);
    body.resize(0x30, 0);
    let mut handshake = vec![0x01u8, 0x00, 0x00, body.len() as u8];
    handshake.extend_from_slice(&body);
    let mut record = vec![0x16u8, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// A pcapng Decryption Secrets Block wrapping an NSS key log.
fn secrets_block(text: &str) -> Vec<u8> {
    let secrets = text.as_bytes();
    let mut body = wz_tls_record::keylog::SECRETS_TYPE_TLS_KEY_LOG
        .to_le_bytes()
        .to_vec();
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

/// A pcapng of one TLS flow: a ClientHello and three sealed KeepAlives in one
/// TCP segment, and, when `carried` names one, the key log in the file's own
/// Decryption Secrets Block.
fn tls_capture(carried: Option<&str>) -> Vec<u8> {
    let mut enc = sealer();
    let mut stream = client_hello();
    for n in 0..3u64 {
        stream.extend_from_slice(&sealed_keep_alive(&mut enc, n));
    }
    let packet = tcp_packet(1000, &stream);
    let mut file = wz_capture::pcapng::write(
        &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
        &[(0, 1_000_000, &packet)],
    );
    if let Some(text) = carried {
        file.extend_from_slice(&secrets_block(text));
    }
    file
}

/// The flow fed to an open handle one packet at a time: the ClientHello, then
/// one segment per sealed record.
struct LiveFeed {
    handle: *mut live::LiveDissection,
    enc: Box<dyn rustls::crypto::cipher::MessageEncrypter>,
    seq: u32,
    sealed: u64,
}

impl LiveFeed {
    fn new() -> Self {
        let mut feed = Self {
            handle: open_live(WZ_DISSECT_LIMITS_NONE).expect("opens"),
            enc: sealer(),
            seq: 1000,
            sealed: 0,
        };
        feed.push(&client_hello());
        feed
    }

    fn push(&mut self, payload: &[u8]) {
        let packet = tcp_packet(self.seq, payload);
        let rc = unsafe {
            wz_dissect_live_push(
                self.handle,
                LINKTYPE_ETHERNET,
                1_000_000 + u64::from(self.seq),
                packet.as_ptr(),
                packet.len(),
            )
        };
        assert_eq!(rc, WZ_DISSECT_OK);
        self.seq += payload.len() as u32;
    }

    fn push_records(&mut self, n: u64) {
        for _ in 0..n {
            let record = sealed_keep_alive(&mut self.enc, self.sealed);
            self.sealed += 1;
            self.push(&record);
        }
    }

    fn add_keylog(&mut self, text: &[u8]) -> usize {
        let mut named = usize::MAX;
        let rc = unsafe {
            wz_dissect_live_add_keylog(self.handle, text.as_ptr(), text.len(), &mut named)
        };
        assert_eq!(rc, WZ_DISSECT_OK);
        named
    }

    fn document(
        &self,
        door: unsafe extern "C" fn(*const live::LiveDissection, *mut *mut c_char) -> c_int,
    ) -> String {
        let mut out: *mut c_char = core::ptr::null_mut();
        let rc = unsafe { door(self.handle, &mut out) };
        taken(rc, out).expect("the handle answers")
    }
}

impl Drop for LiveFeed {
    fn drop(&mut self) {
        unsafe { wz_dissect_live_close(self.handle) };
    }
}

/// THE KEYED DOOR: the same capture reads `decrypted_tls` with its key, and
/// `encrypted_unreadable` with none and with a key for another connection.
#[test]
fn a_tls_capture_reads_decrypted_tls_with_its_key_and_encrypted_unreadable_without() {
    let file = tls_capture(None);
    let none = WZ_DISSECT_LIMITS_NONE;

    let without = call_session_table_keyed(&file, none, None).expect("reads");
    assert!(
        without.contains("\"encrypted\":\"encrypted_unreadable\""),
        "{without}"
    );
    assert!(
        !without.contains("\"encrypted\":\"decrypted_tls\""),
        "{without}"
    );

    let keys = key_log();
    let with = call_session_table_keyed(&file, none, Some(keys.as_bytes())).expect("reads");
    assert!(with.contains("\"encrypted\":\"decrypted_tls\""), "{with}");
    assert!(
        !with.contains("\"encrypted\":\"encrypted_unreadable\""),
        "{with}"
    );

    let other = other_key_log();
    let unmatched = call_session_table_keyed(&file, none, Some(other.as_bytes())).expect("reads");
    assert!(
        unmatched.contains("\"encrypted\":\"encrypted_unreadable\""),
        "keys given and none matched read as no key applied: {unmatched}"
    );
    assert!(
        !unmatched.contains("\"encrypted\":\"decrypted_tls\""),
        "{unmatched}"
    );

    // The summary counts the messages the key opened, and none without it.
    let counted = call_summary_keyed(&file, none, Some(keys.as_bytes())).expect("reads");
    assert!(
        counted.contains("\"tcp_flows\":[{\"frames\":3}]"),
        "{counted}"
    );
    let uncounted = call_summary_keyed(&file, none, None).expect("reads");
    assert!(
        uncounted.contains("\"tcp_flows\":[{\"frames\":0}]"),
        "{uncounted}"
    );
}

/// A caller's bug at the keyed doors is a code and no string: a length with
/// no bytes, and a preset this build does not have.
#[test]
fn the_keyed_doors_refuse_a_length_with_no_key_bytes() {
    let file = tls_capture(None);
    let mut out: *mut c_char = core::ptr::null_mut();
    let rc = unsafe {
        wz_dissect_pcap_session_table_keyed(
            file.as_ptr(),
            file.len(),
            WZ_DISSECT_LIMITS_NONE,
            core::ptr::null(),
            5,
            &mut out,
        )
    };
    assert_eq!(taken(rc, out), Err(WZ_DISSECT_ERR_INVALID_ARG));
    let rc = unsafe {
        wz_dissect_pcap_summary_keyed(
            file.as_ptr(),
            file.len(),
            WZ_DISSECT_LIMITS_NONE,
            core::ptr::null(),
            5,
            &mut out,
        )
    };
    assert_eq!(taken(rc, out), Err(WZ_DISSECT_ERR_INVALID_ARG));
    assert_eq!(
        call_summary_keyed(&file, 9, None),
        Err(WZ_DISSECT_ERR_INVALID_ARG)
    );
}

/// THE CAPTURE'S OWN KEYS reach the doors that take no key log: the session
/// table, the summary and a replay handle all read the flow opened.
#[test]
fn a_capture_carrying_its_keys_decrypts_through_the_doors_that_take_none() {
    let keys = key_log();
    let file = tls_capture(Some(&keys));

    let table = session_table::call_pcap(&file, WZ_DISSECT_LIMITS_NONE).expect("reads");
    assert!(table.contains("\"encrypted\":\"decrypted_tls\""), "{table}");
    let summary = call_summary(&file).expect("reads");
    assert!(
        summary.contains("\"tcp_flows\":[{\"frames\":3}]"),
        "{summary}"
    );

    let handle = replay(&file, WZ_DISSECT_LIMITS_NONE).expect("replays");
    let records = drain_all(handle);
    assert_eq!(
        records.len(),
        3,
        "three KeepAlives out of the replayed file"
    );
    assert!(records.iter().all(|r| r.kind == KIND_KEEPALIVE));
    let mut out: *mut c_char = core::ptr::null_mut();
    let rc = unsafe { wz_dissect_live_session_table(handle, &mut out) };
    let live_table = taken(rc, out).expect("the handle answers");
    unsafe { wz_dissect_live_close(handle) };
    assert!(
        live_table.contains("\"encrypted\":\"decrypted_tls\""),
        "{live_table}"
    );

    // The control: the same flow with no key anywhere stays unread.
    let bare = session_table::call_pcap(&tls_capture(None), WZ_DISSECT_LIMITS_NONE).expect("reads");
    assert!(
        bare.contains("\"encrypted\":\"encrypted_unreadable\""),
        "{bare}"
    );
}

/// AN OPEN HANDLE HANDED KEYS reads the records it already kept, and opens the
/// ones pushed after as they arrive. Keys for another connection first open
/// nothing and settle nothing.
#[test]
fn a_handle_handed_keys_reads_the_records_it_kept_and_the_ones_after() {
    let mut feed = LiveFeed::new();
    feed.push_records(2);
    assert!(
        drain_all(feed.handle).is_empty(),
        "nothing is read out of ciphertext"
    );

    let other = other_key_log();
    assert_eq!(feed.add_keylog(other.as_bytes()), 1);
    assert!(
        drain_all(feed.handle).is_empty(),
        "a key for another connection opens nothing"
    );

    let keys = key_log();
    assert_eq!(feed.add_keylog(keys.as_bytes()), 1);
    let opened = drain_all(feed.handle);
    assert_eq!(
        opened.len(),
        2,
        "the two records the handle kept are read when the key arrives"
    );
    assert!(opened.iter().all(|r| r.kind == KIND_KEEPALIVE));

    feed.push_records(1);
    let later = drain_all(feed.handle);
    assert_eq!(
        later.len(),
        1,
        "a record pushed after the key opens as it arrives"
    );

    let table = feed.document(wz_dissect_live_session_table);
    assert!(table.contains("\"encrypted\":\"decrypted_tls\""), "{table}");
    assert_eq!(
        feed.add_keylog(b"not a key log"),
        0,
        "bytes naming no connection are an answer of zero"
    );
}

/// The live door refuses a caller's bug and changes nothing.
#[test]
fn the_live_door_refuses_a_null_handle_count_or_key_bytes() {
    let feed = LiveFeed::new();
    let text = key_log();
    let mut named = 7usize;
    let rc = unsafe {
        wz_dissect_live_add_keylog(core::ptr::null_mut(), text.as_ptr(), text.len(), &mut named)
    };
    assert_eq!(rc, WZ_DISSECT_ERR_INVALID_ARG);
    let rc = unsafe {
        wz_dissect_live_add_keylog(
            feed.handle,
            text.as_ptr(),
            text.len(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(rc, WZ_DISSECT_ERR_INVALID_ARG);
    let rc = unsafe { wz_dissect_live_add_keylog(feed.handle, core::ptr::null(), 3, &mut named) };
    assert_eq!(rc, WZ_DISSECT_ERR_INVALID_ARG);
    assert_eq!(named, 7, "a refused call writes no count");
    let rc = unsafe { wz_dissect_live_add_keylog(feed.handle, core::ptr::null(), 0, &mut named) };
    assert_eq!(
        (rc, named),
        (WZ_DISSECT_OK, 0),
        "no bytes name no connection"
    );
}

/// NO DOOR WRITES A BYTE OF A KEY. A key log whose secret is recognisable is
/// handed to every door that takes one, well formed and malformed, and carried
/// in a capture's own Decryption Secrets Block; every string any door hands
/// back afterwards, and the `Debug` of every value holding the keys, is
/// searched for the secret in hex, either case.
#[test]
fn no_door_writes_a_byte_of_a_key() {
    let secret_hex = hex(&secret());
    let keys = key_log();
    // The secret where a label, a random or a malformed line would be: what a
    // refusal or a count of unparsed lines could be tempted to quote.
    let malformed = format!(
        "{secret_hex} CLIENT_TRAFFIC_SECRET_0 {r}\n\
         CLIENT_RANDOM {r} {secret_hex}\n\
         CLIENT_TRAFFIC_SECRET_0 {r} {secret_hex}zz\n\
         CLIENT_TRAFFIC_SECRET_x {r} {secret_hex}\n",
        r = hex(&RANDOM)
    );
    let bare = tls_capture(None);
    let carrying = tls_capture(Some(&keys));
    let none = WZ_DISSECT_LIMITS_NONE;

    let mut written: Vec<(String, String)> = Vec::new();
    for (name, text) in [("keys", &keys), ("malformed", &malformed)] {
        for (file_name, file) in [("bare", &bare), ("carrying", &carrying)] {
            written.push((
                format!("session_table_keyed {name} {file_name}"),
                call_session_table_keyed(file, none, Some(text.as_bytes())).expect("reads"),
            ));
            written.push((
                format!("summary_keyed {name} {file_name}"),
                call_summary_keyed(file, none, Some(text.as_bytes())).expect("reads"),
            ));
        }
        written.push((
            format!("session_table_keyed {name} refusal"),
            call_session_table_keyed(b"not a capture", none, Some(text.as_bytes()))
                .expect("a refusal is a document"),
        ));
    }
    written.push((
        "census carrying".into(),
        call_census(&carrying).expect("reads"),
    ));
    written.push((
        "fields carrying".into(),
        call_fields(&carrying, 0).expect("reads"),
    ));
    written.push((
        "session_table carrying".into(),
        session_table::call_pcap(&carrying, none).expect("reads"),
    ));

    let mut feed = LiveFeed::new();
    feed.push_records(2);
    feed.add_keylog(malformed.as_bytes());
    feed.add_keylog(keys.as_bytes());
    feed.push_records(1);
    written.push((
        "live session_table".into(),
        feed.document(wz_dissect_live_session_table),
    ));
    written.push(("live health".into(), feed.document(wz_dissect_live_health)));
    written.push(("live memory".into(), feed.document(wz_dissect_live_memory)));
    written.push((
        "live retention".into(),
        feed.document(wz_dissect_live_retention),
    ));
    written.push(("readable surfaces".into(), call_readable_surfaces()));

    let mut held = wz_tls_record::pass::LiveDecryptor::new();
    held.absorb(keys.as_bytes());
    held.absorb(malformed.as_bytes());
    written.push(("decryptor debug".into(), format!("{held:?}")));
    written.push((
        "key log debug".into(),
        format!(
            "{:?}",
            wz_tls_record::keylog::KeyLog::parse(malformed.as_bytes())
        ),
    ));

    // The population: the key did open the flow, so the documents above were
    // written by doors that held it.
    assert!(
        written
            .iter()
            .any(|(_, s)| s.contains("\"encrypted\":\"decrypted_tls\"")),
        "no door decrypted, so this search proves nothing"
    );
    let upper = secret_hex.to_uppercase();
    for (what, text) in &written {
        assert!(
            !text.contains(&secret_hex) && !text.contains(&upper),
            "{what} carries the secret: {text}"
        );
    }
}
