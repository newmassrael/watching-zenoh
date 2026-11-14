// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What holding TLS keys costs a live handle on every push, against the number
//! of flows it holds.
//!
//! # The question this answers
//!
//! A live handle that holds a key log runs the decryption pass after every
//! push (`wz_dissect_live_add_keylog`, ABI 57), and the pass visits every flow
//! the handle holds to find the encrypted ones with records it has not opened.
//! That is a cost per push that follows the flow count, paid even by a capture
//! with no TLS at all. This measures it: the same capture of `F` interleaved
//! cleartext sessions pushed packet by packet into a handle that holds no key
//! and into one that holds a key log naming another connection, for several
//! `F`, and prints nanoseconds per push for each and their difference.
//!
//! # What this does NOT do
//!
//! It fails on no threshold, for `wz-capture`'s `decode_cost` reason. It
//! asserts that it measured what it names: every push is accepted, and the
//! keyed handle really holds a key.
//!
//! # Usage
//!
//! ```text
//! cargo bench -p wz-capi-dissect --bench live_keys_cost
//! ```

use std::time::Instant;

use wz_capi_dissect::live::LiveDissection;
use wz_capi_dissect::*;
use wz_capture::fixtures::interleaved_flows_capture;

/// The flow counts measured.
const FLOWS: [usize; 4] = [1, 64, 512, 2048];

/// About this many packets are pushed at every flow count.
const PACKETS: usize = 40_000;

/// Each measurement is the fastest of this many runs.
const RUNS: usize = 3;

/// A key log naming a connection that is not in the capture: the handle holds a
/// key, and no flow of the capture is opened by it. A TLS 1.3 traffic secret,
/// because the parser refuses TLS 1.2's `CLIENT_RANDOM` on purpose.
const FOREIGN_KEYLOG: &[u8] = b"CLIENT_TRAFFIC_SECRET_0 \
00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n";

/// The packets of a classic pcap file, with their instants in nanoseconds.
fn packets_of(pcap: &[u8]) -> (u32, Vec<(u64, &[u8])>) {
    let link = u32::from_le_bytes(pcap[20..24].try_into().unwrap());
    let mut at = 24;
    let mut out = Vec::new();
    while at + 16 <= pcap.len() {
        let sec = u32::from_le_bytes(pcap[at..at + 4].try_into().unwrap());
        let usec = u32::from_le_bytes(pcap[at + 4..at + 8].try_into().unwrap());
        let len = u32::from_le_bytes(pcap[at + 8..at + 12].try_into().unwrap()) as usize;
        let data = &pcap[at + 16..at + 16 + len];
        out.push((
            u64::from(sec) * 1_000_000_000 + u64::from(usec) * 1_000,
            data,
        ));
        at += 16 + len;
    }
    (link, out)
}

/// Nanoseconds per push of `packets` into a fresh handle, keyed or not.
fn ns_per_push(link: u32, packets: &[(u64, &[u8])], keyed: bool) -> f64 {
    let mut handle: *mut LiveDissection = core::ptr::null_mut();
    // SAFETY: every pointer handed in is valid for the call; the handle is used
    // only while open and closed once.
    unsafe {
        assert_eq!(
            wz_dissect_live_open(WZ_DISSECT_LIMITS_NONE, &mut handle),
            WZ_DISSECT_OK
        );
        if keyed {
            let mut named = 0usize;
            assert_eq!(
                wz_dissect_live_add_keylog(
                    handle,
                    FOREIGN_KEYLOG.as_ptr(),
                    FOREIGN_KEYLOG.len(),
                    &mut named
                ),
                WZ_DISSECT_OK
            );
            assert_eq!(named, 1, "the keyed handle holds the key");
        }
        let started = Instant::now();
        for (ts_ns, data) in packets {
            assert_eq!(
                wz_dissect_live_push(handle, link, *ts_ns, data.as_ptr(), data.len()),
                WZ_DISSECT_OK
            );
        }
        let elapsed = started.elapsed();
        wz_dissect_live_close(handle);
        elapsed.as_nanos() as f64 / packets.len() as f64
    }
}

fn main() {
    println!("flows  packets  no_keys_ns  keys_ns  delta_ns");
    for flows in FLOWS {
        let pushes = (PACKETS / flows).saturating_sub(4).max(1);
        let pcap = interleaved_flows_capture(flows, pushes);
        let (link, packets) = packets_of(&pcap);
        let best = |keyed| {
            (0..RUNS)
                .map(|_| ns_per_push(link, &packets, keyed))
                .fold(f64::INFINITY, f64::min)
        };
        let plain = best(false);
        let keyed = best(true);
        println!(
            "{flows:5}  {:7}  {plain:10.0}  {keyed:7.0}  {:8.0}",
            packets.len(),
            keyed - plain
        );
    }
}
