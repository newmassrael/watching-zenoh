// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The generated codecs of the network messages, each read where its bytes lie and held to its
//! round trip (`wz_fuzz::records`): a value decoded from a peer's bytes encodes to bytes that
//! decode, wholly, to the same value, and encode again to the same bytes.
//!
//! Input: one byte of arguments, then the bytes.
//!
//! | byte | argument |
//! |------|----------|
//! | 0    | bit 0 clear: the bytes are units (`wz_fuzz_ingress_common::units`), and the records of each Frame they hold are read; set: the bytes are the records of one Frame |
//!
//! The first form starts from what a session receives, so the seeds the captures give reach the
//! codecs; the second hands the fuzzer the codecs with no transport header in front.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wz_fuzz::records::lent_records;
use wz_fuzz::Reader;
use wz_fuzz_ingress_common::units;
use wz_session_core::inbound::{parse_inbound_observed, InboundFrame};

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let records_only = r.u8() & 1 != 0;
    let bytes = r.rest();
    if records_only {
        lent_records(bytes, |_, _| {});
        return;
    }
    for unit in units(bytes) {
        let mut at = 0;
        while let Some(rest) = unit.get(at..).filter(|rest| !rest.is_empty()) {
            let Ok((message, used)) = parse_inbound_observed(rest) else {
                break;
            };
            if let InboundFrame::Frame { payload, .. } = &message {
                lent_records(payload, |_, _| {});
            }
            // A Frame and a Fragment take the rest of their unit; a message whose length this
            // build cannot know takes nothing, and ends the unit.
            if used == 0 {
                break;
            }
            at += used;
        }
    }
});
