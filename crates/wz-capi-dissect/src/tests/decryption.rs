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
//! itself. A QUIC connection, built by `wz-tls-record`'s packet fixtures, is
//! read through a handle's push, replay and lent replay doors against the keyed
//! file door.

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
        "keys given and none matched read nothing: {unmatched}"
    );
    assert!(
        !unmatched.contains("\"encrypted\":\"decrypted_tls\""),
        "{unmatched}"
    );
    // ...and say why, where the run with no key at all says `encrypted`.
    assert!(
        unmatched.contains("{\"cell\":\"phase\",\"reason\":\"no_matching_key\"}"),
        "a key log for another connection reads no_matching_key: {unmatched}"
    );
    assert!(
        without.contains("{\"cell\":\"phase\",\"reason\":\"encrypted\"}"),
        "no key material at all reads encrypted: {without}"
    );
    assert!(!without.contains("no_matching_key"), "{without}");
    // The capture's own secrets block naming another connection is key
    // material too.
    let carrying_other = tls_capture(Some(&other));
    let from_block = session_table::call_pcap(&carrying_other, none).expect("reads");
    assert!(
        from_block.contains("{\"cell\":\"phase\",\"reason\":\"no_matching_key\"}"),
        "{from_block}"
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

// ── QUIC on a handle ────────────────────────────────────────────────────────

/// The ClientHello random of the QUIC connection below, which its key log
/// names.
const QUIC_RANDOM: [u8; 32] = [0x4d; 32];

/// The key log that opens the QUIC connection below.
fn quic_key_log() -> String {
    wz_tls_record::quic::fixture::log_text(&QUIC_RANDOM, 1)
}

/// One datagram between the client, 10.0.0.1:51000, and the server,
/// 10.0.0.2:4433. The client sorts low, so it is direction A.
fn quic_datagram(from_client: bool, payload: &[u8]) -> Vec<u8> {
    let (client, server) = ([10, 0, 0, 1], [10, 0, 0, 2]);
    if from_client {
        udp_packet(client, 51000, server, 4433, payload)
    } else {
        udp_packet(server, 4433, client, 51000, payload)
    }
}

/// One QUIC connection, the packets in capture order: the client's Initial
/// carrying its ClientHello, the server's Initial, two client 1-RTT packets
/// carrying two KeepAlives on stream 0, cut inside the second one so the packet
/// that completes it carries a message the one before began, and a server
/// 1-RTT packet carrying a KeepAlive on stream 0 and one in an RFC 9221
/// datagram.
fn quic_packets() -> Vec<Vec<u8>> {
    use wz_tls_record::quic::fixture::{
        application_secret, client_hello, crypto_frame, datagram_frame, long_header, protect,
        short_header, stream_frame, ICID, SCID,
    };
    use wz_tls_record::quic::{QuicKeys, QuicVersion};

    /// A framed unit on a QUIC stream: `u16` little-endian length, then the
    /// message.
    fn unit(message: &[u8]) -> Vec<u8> {
        let mut out = (message.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(message);
        out
    }
    /// One 1-RTT packet addressed to `dcid`.
    fn one_rtt(keys: &QuicKeys, dcid: &[u8], number: u32, payload: &[u8]) -> Vec<u8> {
        let (h, o) = short_header(dcid, number);
        protect(keys, u64::from(number), &h, o, payload)
    }

    const CUT: usize = 4;
    let (client_initial, server_initial) = QuicKeys::initial(QuicVersion::V1, &ICID);
    let first = crypto_frame(0, &client_hello(&QUIC_RANDOM));
    let (h, o) = long_header(0, &ICID, &[], first.len(), 0);
    let client_first = protect(&client_initial, 0, &h, o, &first);
    let reply = crypto_frame(0, b"\x02\x00\x00\x04....");
    let (h, o) = long_header(0, &[], &SCID, reply.len(), 0);
    let server_first = protect(&server_initial, 0, &h, o, &reply);

    let client = QuicKeys::derive(Suite::Aes128GcmSha256, &application_secret(false, 0));
    let server = QuicKeys::derive(Suite::Aes128GcmSha256, &application_secret(true, 0));
    let mut stream = unit(&KEEPALIVE);
    stream.extend_from_slice(&unit(&KEEPALIVE));
    let mut answer = stream_frame(0, 0, &unit(&KEEPALIVE));
    answer.extend_from_slice(&datagram_frame(&KEEPALIVE));
    let head = one_rtt(&client, &SCID, 1, &stream_frame(0, 0, &stream[..CUT]));
    let tail = one_rtt(
        &client,
        &SCID,
        2,
        &stream_frame(0, CUT as u8, &stream[CUT..]),
    );
    vec![
        quic_datagram(true, &client_first),
        quic_datagram(false, &server_first),
        quic_datagram(true, &head),
        quic_datagram(true, &tail),
        quic_datagram(false, &one_rtt(&server, &[], 1, &answer)),
    ]
}

/// The capture instant of packet `i`, in the microseconds a pcapng of
/// resolution 6 counts.
fn quic_instant_us(i: usize) -> u64 {
    1_000_000 + i as u64 * 100
}

/// The connection as a pcapng file, and when `carried` names a key log, the
/// file's own Decryption Secrets Block after the packets.
fn quic_capture(carried: Option<&str>) -> Vec<u8> {
    let packets = quic_packets();
    let refs: Vec<(u32, u64, &[u8])> = packets
        .iter()
        .enumerate()
        .map(|(i, p)| (0u32, quic_instant_us(i), p.as_slice()))
        .collect();
    let mut file = wz_capture::pcapng::write(&[(LINKTYPE_ETHERNET, 6)], &refs);
    if let Some(text) = carried {
        file.extend_from_slice(&secrets_block(text));
    }
    file
}

/// The connection pushed into an open handle a packet at a time, at the
/// instants the file gives the same packets.
fn push_quic(handle: *mut live::LiveDissection) {
    for (i, packet) in quic_packets().iter().enumerate() {
        let rc = unsafe {
            wz_dissect_live_push(
                handle,
                LINKTYPE_ETHERNET,
                quic_instant_us(i) * 1_000,
                packet.as_ptr(),
                packet.len(),
            )
        };
        assert_eq!(rc, WZ_DISSECT_OK);
    }
}

/// Hand an open handle a key log, and return how many connections it named.
fn hand_keys(handle: *mut live::LiveDissection, text: &str) -> usize {
    let mut named = usize::MAX;
    let rc = unsafe { wz_dissect_live_add_keylog(handle, text.as_ptr(), text.len(), &mut named) };
    assert_eq!(rc, WZ_DISSECT_OK);
    named
}

/// One document of an open handle.
fn document_of(
    handle: *mut live::LiveDissection,
    door: unsafe extern "C" fn(*const live::LiveDissection, *mut *mut c_char) -> c_int,
) -> String {
    let mut out: *mut c_char = core::ptr::null_mut();
    let rc = unsafe { door(handle, &mut out) };
    taken(rc, out).expect("the handle answers")
}

/// The number a document gives `key` the first time it gives it.
fn number_at(doc: &str, key: &str) -> u64 {
    let at = doc.find(key).unwrap_or_else(|| panic!("no {key} in {doc}")) + key.len();
    doc[at..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("{key} is not a number in {doc}"))
}

/// What two reads of one capture are compared by, a record at a time: kind,
/// list kind, half, anchor space, anchor and place in the unit, sorted, so the
/// order lists are drained in is not the claim.
fn quic_rows(records: &[WzDissectRecord]) -> Vec<(u8, u8, u8, u8, u64, u32)> {
    let mut rows: Vec<_> = records
        .iter()
        .map(|r| {
            (
                r.kind,
                r.origin,
                r.direction,
                r.anchor_space,
                r.anchor,
                r.batch_index,
            )
        })
        .collect();
    rows.sort_unstable();
    rows
}

/// The records the connection reads to: three KeepAlives on stream 0, the
/// client's at stream bytes 0 and 3 and the server's at 0, and the one in the
/// server's datagram, anchored at the packet that carried it (the fifth).
fn quic_rows_read() -> Vec<(u8, u8, u8, u8, u64, u32)> {
    const STREAM: u8 = 3;
    const DATAGRAM: u8 = 4;
    const PACKET: u8 = 0;
    const BYTES: u8 = 1;
    vec![
        (KIND_KEEPALIVE, STREAM, 0, BYTES, 0, 0),
        (KIND_KEEPALIVE, STREAM, 0, BYTES, 3, 0),
        (KIND_KEEPALIVE, STREAM, 1, BYTES, 0, 0),
        (KIND_KEEPALIVE, DATAGRAM, 1, PACKET, 4, 0),
    ]
}

/// KEYS FIRST, then the packets pushed one at a time: the handle reads the
/// QUIC flow to the messages the keyed file door reads, the session table says
/// `decrypted_quic` with the same frame count, and the opened flow keeps no
/// packet.
#[test]
fn a_quic_flow_pushed_with_its_keys_first_reads_as_the_keyed_file_door_does() {
    let keys = quic_key_log();
    let file_table = call_session_table_keyed(
        &quic_capture(None),
        WZ_DISSECT_LIMITS_NONE,
        Some(keys.as_bytes()),
    )
    .expect("reads");
    assert!(
        file_table.contains("\"encrypted\":\"decrypted_quic\""),
        "{file_table}"
    );
    assert_eq!(number_at(&file_table, "\"frames\":"), 4, "{file_table}");

    let handle = open_live(WZ_DISSECT_LIMITS_NONE).expect("the preset opens");
    assert_eq!(hand_keys(handle, &keys), 1);
    push_quic(handle);
    let rows = quic_rows(&drain_all(handle));
    let table = document_of(handle, wz_dissect_live_session_table);
    let memory = document_of(handle, wz_dissect_live_memory);
    unsafe { wz_dissect_live_close(handle) };

    assert_eq!(rows, quic_rows_read());
    assert!(
        table.contains("\"encrypted\":\"decrypted_quic\""),
        "{table}"
    );
    assert_eq!(number_at(&table, "\"frames\":"), 4, "{table}");
    assert_eq!(
        number_at(&memory, "\"quic_packets\":"),
        0,
        "a flow whose application data opened keeps no packet: {memory}"
    );
}

/// KEYS AFTER THE PACKETS: with no key the flow is `encrypted_unreadable` and
/// its packets are kept, counted in the memory document; the key log reads it
/// from what was kept, to the same messages, and the packets are let go of.
#[test]
fn a_quic_flow_whose_keys_arrive_after_its_packets_is_read_from_what_the_handle_kept() {
    let handle = open_live(WZ_DISSECT_LIMITS_NONE).expect("the preset opens");
    push_quic(handle);
    let unread = drain_all(handle);
    let before = document_of(handle, wz_dissect_live_session_table);
    let kept = document_of(handle, wz_dissect_live_memory);
    assert_eq!(hand_keys(handle, &quic_key_log()), 1);
    let rows = quic_rows(&drain_all(handle));
    let after = document_of(handle, wz_dissect_live_session_table);
    let let_go = document_of(handle, wz_dissect_live_memory);
    unsafe { wz_dissect_live_close(handle) };

    assert!(
        unread.is_empty(),
        "nothing past the Initial space opens without a key"
    );
    assert!(
        before.contains("\"encrypted\":\"encrypted_unreadable\""),
        "{before}"
    );
    assert!(
        number_at(&kept, "\"quic_packets\":") > 0,
        "the packets a later key may open are kept: {kept}"
    );
    assert!(
        number_at(&kept, "\"total\":") >= number_at(&kept, "\"quic_packets\":"),
        "and counted in the total: {kept}"
    );
    assert_eq!(rows, quic_rows_read());
    assert!(
        after.contains("\"encrypted\":\"decrypted_quic\""),
        "{after}"
    );
    assert_eq!(
        number_at(&let_go, "\"quic_packets\":"),
        0,
        "and let go of once the flow opened: {let_go}"
    );
}

/// A REPLAYED FILE that carries its own keys reads the QUIC flow through the
/// replay door and the lent one alike; with no key anywhere it stays
/// `encrypted_unreadable` and reads nothing.
#[test]
fn a_replayed_quic_capture_reads_with_the_keys_it_carries_through_both_replay_doors() {
    /// A lent replay handle over `file`, which outlives it in the test.
    fn lent(file: &[u8]) -> *mut live::LiveDissection {
        let mut handle: *mut live::LiveDissection = core::ptr::null_mut();
        let rc = unsafe {
            wz_dissect_pcap_replay_lent(
                file.as_ptr(),
                file.len(),
                WZ_DISSECT_LIMITS_NONE,
                &mut handle,
            )
        };
        assert_eq!(rc, WZ_DISSECT_OK);
        handle
    }
    let carrying = quic_capture(Some(&quic_key_log()));
    let bare = quic_capture(None);
    for (door, handle) in [
        (
            "replay",
            replay(&carrying, WZ_DISSECT_LIMITS_NONE).expect("replays"),
        ),
        ("replay_lent", lent(&carrying)),
    ] {
        let rows = quic_rows(&drain_all(handle));
        let table = document_of(handle, wz_dissect_live_session_table);
        unsafe { wz_dissect_live_close(handle) };
        assert_eq!(rows, quic_rows_read(), "{door}");
        assert!(
            table.contains("\"encrypted\":\"decrypted_quic\""),
            "{door}: {table}"
        );
    }

    let handle = lent(&bare);
    let rows = drain_all(handle);
    let table = document_of(handle, wz_dissect_live_session_table);
    unsafe { wz_dissect_live_close(handle) };
    assert!(rows.is_empty(), "no key, no application data");
    assert!(
        table.contains("\"encrypted\":\"encrypted_unreadable\""),
        "{table}"
    );
}
