// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The timestamp of an interception of a timestamp stack, as a wz node writes it when it routes a
//! message (`wz_session_core::ts_stack::timestamp_bytes`), against upstream's codec for a
//! `uhlc::Timestamp` (`zenoh-codec`, `core/timestamp.rs`), which is what an upstream node reads an
//! interception with and writes its own with.
//!
//! * the bytes the two write for the same time and identity are equal;
//! * the bytes of wz are read by upstream's codec as the time and the identity they were made from.
//!
//! Over a spread of times (the edges of each width of a zint and the ends of the word) and of
//! identities (every length a node identity has, and one with a zero byte inside it).

use up_codec::{RCodec, WCodec, Zenoh080};
use up_zenoh::time::{Timestamp, TimestampId, NTP64};
use wz_session_core::ts_stack::timestamp_bytes;

const TIMES: [u64; 12] = [
    0,
    1,
    127,
    128,
    16_383,
    16_384,
    (1 << 21) - 1,
    1 << 21,
    u32::MAX as u64,
    1 << 56,
    0x1234_5678_9abc_def0,
    u64::MAX,
];

/// The identities of nodes: every length from one to sixteen bytes, each ending in a byte that is
/// not zero (a trailing zero is not part of an identity), and one with a zero byte inside.
fn identities() -> Vec<Vec<u8>> {
    let mut ids: Vec<Vec<u8>> = (1..=16u8).map(|n| (1..=n).collect()).collect();
    ids.push(vec![0x05, 0x00, 0x07]);
    ids
}

fn upstream(time: u64, id: &[u8]) -> Timestamp {
    Timestamp::new(NTP64(time), TimestampId::try_from(id).expect("an identity"))
}

#[test]
fn the_bytes_of_an_interception_are_those_upstream_writes() {
    let mut compared = 0;
    for time in TIMES {
        for id in identities() {
            let mut written = Vec::new();
            Zenoh080
                .write(&mut written, &upstream(time, &id))
                .expect("upstream writes a timestamp");
            assert_eq!(
                timestamp_bytes(time, &id),
                written,
                "time {time:#x}, identity {id:02x?}"
            );
            compared += 1;
        }
    }
    assert_eq!(compared, TIMES.len() * 17);
}

#[test]
fn upstream_reads_the_bytes_of_an_interception_as_what_they_were_made_from() {
    for time in TIMES {
        for id in identities() {
            let bytes = timestamp_bytes(time, &id);
            let mut reader = bytes.as_slice();
            let read: Timestamp = Zenoh080
                .read(&mut reader)
                .expect("upstream reads the timestamp of wz");
            assert!(reader.is_empty(), "all of it was read");
            assert_eq!(read.get_time().as_u64(), time);
            assert_eq!(
                &read.get_id().to_le_bytes()[..read.get_id().size()],
                id.as_slice(),
                "time {time:#x}"
            );
        }
    }
}
