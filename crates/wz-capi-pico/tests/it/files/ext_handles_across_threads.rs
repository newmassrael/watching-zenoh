// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The handles of the additional doors used from several threads at once, as their documentation
//! allows: an end-to-end sender and receiver whose streams each belong to one thread, an instance
//! keyer whose instances each belong to one thread, a message catalog any number of threads read,
//! and a payload schema shared by the payloads each thread makes from it.
//!
//! Each thread's results are its own and so are asserted exactly; what the interleaving adds is
//! what the race detector of Layer Vtsan reads (`docs/verification.md`): every one of these
//! handles holds its state behind its own lock, and a handle whose lock let two threads at its
//! state would be a report there, and a wrong count here. The profile, the schemas, the
//! description and the catalog are the synthetic ones of the doors' own tests.

#![cfg(all(
    feature = "e2e-sender",
    feature = "e2e-receiver",
    feature = "instance-key",
    feature = "message-catalog",
    feature = "message-payload"
))]

use std::ffi::{CStr, CString};
use std::sync::Barrier;

use wz_capi_pico::e2e_receiver::*;
use wz_capi_pico::e2e_sender::*;
use wz_capi_pico::instance_key::*;
use wz_capi_pico::message_catalog::*;
use wz_capi_pico::message_payload::*;
use wz_capi_pico::proto_file::wz_ext_proto_file_t;
use wz_capi_pico::result::{Z_ERR_OVERFLOW, Z_OK};

/// How many threads share each handle, and how many calls each makes.
const THREADS: usize = 4;
const ROUNDS: usize = 64;

/// The profile of the end-to-end doors' own tests: a 16-bit counter, a 16-bit CRC, an identifier
/// split in two and judged, and a message cell whose sender is derived from the address. Synthetic.
const PROFILE: &str = r#"{
  "name": "door-demo",
  "fields": [
    {"name": "length", "bytes": 2},
    {"name": "ident", "bytes": 3, "xor": "0x3C3C3C",
     "split": [{"name": "app", "lsb": 12, "width": 12}, {"name": "msg", "lsb": 0, "width": 12}]},
    {"name": "crc", "bytes": 2},
    {"name": "cell", "bytes": 4,
     "split": [{"name": "kind", "lsb": 28, "width": 4},
               {"name": "sender", "lsb": 0, "width": 28,
                "derive": {"from": "address", "mask": "0x0F00FF00", "xor": "0x77"}}]},
    {"name": "counter", "bytes": 2}
  ],
  "crc": {"field": "crc", "width": 16, "poly": "0x1021", "init": "0xFFFF",
          "refin": false, "refout": false, "xorout": "0x0000",
          "cover": ["length", "ident", "cell", "@payload", "counter"]},
  "length": {"field": "length", "counts": "frame"},
  "counter": {"field": "counter", "max_gap": 2, "timeout_ms": 50},
  "judge": {"ident": "ident", "length": true},
  "cell": {"field": "cell", "kind": "kind", "sender": "sender"}
}"#;
const VALUES: &str =
    r#"{"ident": {"app": 801, "msg": 99}, "cell": {"kind": 5}, "@address": 201986612}"#;

const KEYED_SCHEMA: &str = r#"
syntax = "proto3";
package syn.thread;
message Reading {
  optional uint32 bay = 1;
  sint32 tilt = 2;
  bytes body = 3;
}
"#;
/// Two bays and two tilts: four instances, one a thread.
const KEYED_DESCRIPTION: &str = r#"{
  "message": "syn.thread.Reading",
  "fields": [
    {"path": "bay", "values": [12, 30]},
    {"path": "tilt", "values": [-3, 5]}
  ],
  "report_interval_ms": 1000
}"#;

const PAYLOAD_SCHEMA: &str = r#"
syntax = "proto3";
package syn.thread;
message Pose {
  uint32 serial = 1;
  string label = 5;
}
"#;

const CATALOG: &str = include_str!("../../../../wz-app-frame/catalog/synthetic.json5");

/// A handle's address, handed to the threads that share it: the handle types hold raw pointers
/// and so are neither `Send` nor `Sync`, as a C program's handles are plain words.
#[derive(Clone, Copy)]
struct Shared(usize);

impl Shared {
    fn of<T>(handle: &T) -> Self {
        Self(handle as *const T as usize)
    }

    fn get<T>(self) -> *const T {
        self.0 as *const T
    }
}

fn varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// A reading of `bay` and `tilt` (zigzag-encoded, as `sint32` is), with a body of `body`.
fn reading(bay: u64, tilt: i32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    varint(1 << 3, &mut out);
    varint(bay, &mut out);
    varint(2 << 3, &mut out);
    varint(u64::from(((tilt << 1) ^ (tilt >> 31)) as u32), &mut out);
    varint((3 << 3) | 2, &mut out);
    varint(body.len() as u64, &mut out);
    out.extend_from_slice(body);
    out
}

#[test]
fn a_sender_and_a_receiver_shared_by_threads_keep_each_streams_counter() {
    let profile = CString::new(PROFILE).unwrap();
    let values = CString::new(VALUES).unwrap();
    unsafe {
        let mut options: wz_ext_e2e_sender_options_t = std::mem::zeroed();
        wz_ext_e2e_sender_options_default(&mut options);
        options.streams = THREADS;
        let mut tx: wz_ext_owned_e2e_sender_t = std::mem::zeroed();
        let rc = wz_ext_e2e_sender_new(
            &mut tx,
            profile.as_ptr(),
            values.as_ptr(),
            &options,
            std::ptr::null_mut(),
        );
        assert_eq!(rc, Z_OK, "the sender is made");
        let mut judge_options: wz_ext_e2e_receiver_options_t = std::mem::zeroed();
        wz_ext_e2e_receiver_options_default(&mut judge_options);
        judge_options.streams = THREADS;
        let mut rx: wz_ext_owned_e2e_receiver_t = std::mem::zeroed();
        let rc = wz_ext_e2e_receiver_new(
            &mut rx,
            profile.as_ptr(),
            values.as_ptr(),
            &judge_options,
            std::ptr::null_mut(),
        );
        assert_eq!(rc, Z_OK, "the receiver is made");

        let (tx_at, rx_at) = (Shared::of(&tx), Shared::of(&rx));
        let start = Barrier::new(THREADS);
        std::thread::scope(|scope| {
            for stream in 0..THREADS {
                let start = &start;
                scope.spawn(move || {
                    let tx = wz_ext_e2e_sender_loan(tx_at.get());
                    let rx = wz_ext_e2e_receiver_loan(rx_at.get());
                    let payload = [stream as u8; 5];
                    start.wait();
                    for round in 0..ROUNDS {
                        let mut frame = [0u8; 64];
                        let (mut written, mut counter) = (0usize, 0u64);
                        let rc = wz_ext_e2e_sender_protect(
                            tx,
                            stream,
                            payload.as_ptr(),
                            payload.len(),
                            frame.as_mut_ptr(),
                            frame.len(),
                            &mut written,
                            &mut counter,
                            std::ptr::null_mut(),
                        );
                        assert_eq!(rc, Z_OK, "stream {stream} round {round}");
                        assert_eq!(
                            counter, round as u64,
                            "stream {stream} keeps its own counter"
                        );
                        let mut verdict: wz_ext_e2e_verdict_t = std::mem::zeroed();
                        let rc = wz_ext_e2e_receiver_judge(
                            rx,
                            stream,
                            frame.as_ptr(),
                            written,
                            round as u64,
                            &mut verdict,
                        );
                        assert_eq!(rc, Z_OK);
                        let want = if round == 0 {
                            WZ_EXT_E2E_FIRST
                        } else {
                            WZ_EXT_E2E_OK
                        };
                        assert_eq!(
                            (verdict.status, verdict.failed, verdict.counter),
                            (want, 0, round as u64),
                            "stream {stream} round {round}"
                        );
                    }
                });
            }
        });

        for stream in 0..THREADS {
            let mut next = 0u64;
            assert!(wz_ext_e2e_sender_next(
                wz_ext_e2e_sender_loan(&tx),
                stream,
                &mut next
            ));
            assert_eq!(next, ROUNDS as u64, "stream {stream} moved once a frame");
        }
        wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(&mut tx));
        wz_ext_e2e_receiver_drop(wz_ext_e2e_receiver_move(&mut rx));
    }
}

#[test]
fn a_keyer_shared_by_threads_keeps_each_instances_last_value() {
    let name = CString::new("thread.proto").unwrap();
    let text = CString::new(KEYED_SCHEMA).unwrap();
    let files = [wz_ext_proto_file_t {
        name: name.as_ptr(),
        text: text.as_ptr(),
    }];
    let description = CString::new(KEYED_DESCRIPTION).unwrap();
    const ROOM: usize = 32;
    let mut storage = vec![0u8; THREADS * ROOM];
    unsafe {
        let mut options: wz_ext_instance_keyer_options_t = std::mem::zeroed();
        wz_ext_instance_keyer_options_default(&mut options);
        options.storage = storage.as_mut_ptr();
        options.storage_len = storage.len();
        options.value_capacity = ROOM;
        let mut keyer: wz_ext_owned_instance_keyer_t = std::mem::zeroed();
        let rc = wz_ext_instance_keyer_new(
            &mut keyer,
            files.as_ptr(),
            files.len(),
            description.as_ptr(),
            &options,
            std::ptr::null_mut(),
        );
        assert_eq!(rc, Z_OK, "the keyer is made");

        let at = Shared::of(&keyer);
        let start = Barrier::new(THREADS);
        std::thread::scope(|scope| {
            for instance in 0..THREADS {
                let start = &start;
                scope.spawn(move || {
                    let keyer = wz_ext_instance_keyer_loan(at.get());
                    let bay = [12u64, 30][instance / 2];
                    let tilt = [-3i32, 5][instance % 2];
                    start.wait();
                    for round in 0..ROUNDS {
                        // An undecodable payload between each two, which every thread counts.
                        let mut key: wz_ext_instance_key_t = std::mem::zeroed();
                        let garbage = [0xFFu8, 0xFF];
                        let rc = wz_ext_instance_keyer_index(
                            keyer,
                            garbage.as_ptr(),
                            garbage.len(),
                            0,
                            &mut key,
                        );
                        assert_eq!((rc, key.status), (Z_OK, WZ_EXT_INSTANCE_KEY_UNDECODABLE));
                        let payload = reading(bay, tilt, &[instance as u8, round as u8]);
                        let rc = wz_ext_instance_keyer_index(
                            keyer,
                            payload.as_ptr(),
                            payload.len(),
                            0,
                            &mut key,
                        );
                        assert_eq!(rc, Z_OK);
                        assert_eq!(
                            (key.status, key.instance, key.last),
                            (
                                WZ_EXT_INSTANCE_KEY_INDEXED,
                                instance,
                                WZ_EXT_INSTANCE_KEY_LAST_RECORDED
                            ),
                            "thread {instance} round {round}"
                        );
                        let mut out = [0u8; ROOM];
                        let mut len = 0usize;
                        let rc = wz_ext_instance_keyer_last(
                            keyer,
                            instance,
                            out.as_mut_ptr(),
                            out.len(),
                            &mut len,
                        );
                        assert_eq!(rc, Z_OK);
                        assert_eq!(
                            &out[..len],
                            payload.as_slice(),
                            "the last value is this thread's"
                        );
                    }
                });
            }
        });

        let mut undecodable = 0u64;
        let rc = wz_ext_instance_keyer_counts(
            wz_ext_instance_keyer_loan(&keyer),
            &mut undecodable,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(rc, Z_OK);
        assert_eq!(
            undecodable,
            (THREADS * ROUNDS) as u64,
            "every drop of every thread is counted"
        );
        wz_ext_instance_keyer_drop(wz_ext_instance_keyer_move(&mut keyer));
    }
    drop(storage);
}

#[test]
fn a_catalog_and_a_schema_are_read_by_threads_at_once() {
    let text = CString::new(CATALOG).unwrap();
    let name = CString::new("syn/thread.proto").unwrap();
    let schema_text = CString::new(PAYLOAD_SCHEMA).unwrap();
    let files = [wz_ext_proto_file_t {
        name: name.as_ptr(),
        text: schema_text.as_ptr(),
    }];
    unsafe {
        let mut catalog: wz_ext_owned_message_catalog_t = std::mem::zeroed();
        let rc = wz_ext_message_catalog_new(&mut catalog, text.as_ptr(), std::ptr::null_mut());
        assert_eq!(rc, Z_OK, "the synthetic catalog is read");
        let mut schema: wz_ext_owned_payload_schema_t = std::mem::zeroed();
        let rc = wz_ext_payload_schema_new(
            &mut schema,
            files.as_ptr(),
            files.len(),
            std::ptr::null_mut(),
        );
        assert_eq!(rc, Z_OK, "the schema is read");

        let (catalog_at, schema_at) = (Shared::of(&catalog), Shared::of(&schema));
        let start = Barrier::new(THREADS);
        std::thread::scope(|scope| {
            for thread in 0..THREADS {
                let start = &start;
                scope.spawn(move || {
                    let catalog = wz_ext_message_catalog_loan(catalog_at.get());
                    let schema = wz_ext_payload_schema_loan(schema_at.get());
                    let message = CString::new("syn.thread.Pose").unwrap();
                    let path = CString::new("serial").unwrap();
                    let mut payload: wz_ext_owned_message_payload_t = std::mem::zeroed();
                    let rc = wz_ext_message_payload_new(
                        &mut payload,
                        catalog,
                        thread % 2,
                        schema,
                        message.as_ptr(),
                        std::ptr::null_mut(),
                    );
                    assert_eq!(rc, Z_OK, "thread {thread}'s payload");
                    let mine = wz_ext_message_payload_loan(&payload);
                    start.wait();
                    for round in 0..ROUNDS {
                        let mut entry: wz_ext_message_entry_t = std::mem::zeroed();
                        let index = round % 2;
                        let rc = wz_ext_message_catalog_entry(catalog, index, &mut entry);
                        assert_eq!(rc, Z_OK);
                        let key = CStr::from_ptr(entry.key_expr);
                        let mut found = usize::MAX;
                        let rc = wz_ext_message_catalog_find(catalog, key.as_ptr(), &mut found);
                        assert_eq!((rc, found), (Z_OK, index), "a key finds its own entry");

                        let serial = (thread * ROUNDS + round) as u64;
                        let rc = wz_ext_message_payload_set_uint(mine, path.as_ptr(), serial);
                        assert_eq!(rc, Z_OK);
                        let mut size = 0usize;
                        let rc =
                            wz_ext_message_payload_encode(mine, std::ptr::null_mut(), 0, &mut size);
                        assert!(rc == Z_OK || rc == Z_ERR_OVERFLOW, "{rc}");
                        let mut bytes = vec![0u8; size];
                        let rc = wz_ext_message_payload_encode(
                            mine,
                            bytes.as_mut_ptr(),
                            bytes.len(),
                            &mut size,
                        );
                        assert_eq!(rc, Z_OK);
                        let rc = wz_ext_message_payload_reset(mine);
                        assert_eq!(rc, Z_OK);
                        let rc = wz_ext_message_payload_decode(mine, bytes.as_ptr(), bytes.len());
                        assert_eq!(rc, Z_OK);
                        let mut back = u64::MAX;
                        let rc = wz_ext_message_payload_get_uint(mine, path.as_ptr(), &mut back);
                        assert_eq!(
                            (rc, back),
                            (Z_OK, serial),
                            "thread {thread} reads its own value"
                        );
                    }
                    wz_ext_message_payload_drop(wz_ext_message_payload_move(&mut payload));
                });
            }
        });

        wz_ext_payload_schema_drop(wz_ext_payload_schema_move(&mut schema));
        wz_ext_message_catalog_drop(wz_ext_message_catalog_move(&mut catalog));
    }
}
