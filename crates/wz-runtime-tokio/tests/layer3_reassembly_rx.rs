// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(feature = "reassembly")]

//! R311im — reassembly RX seam integration: a `T_MID_FRAGMENT` (0x06)
//! wire frame is decoded by `parse_inbound` into `InboundFrame::Fragment`,
//! and a multi-fragment chain reassembles through the
//! `ReassemblyDispatcher` exactly as the drive loop wires it
//! (`wz_runtime_tokio::session_glue::report_outcome_reassembling`).
//!
//! Proves the full RX path `wire bytes -> parse_inbound -> Fragment ->
//! ReassemblyDispatcher::ingest -> reassembled message` against the real
//! transport-header decode (R/M flags, VLE sn, tail payload), not a
//! hand-rolled fragment struct.

use wz_runtime_tokio::session_glue::{parse_inbound, InboundFrame};
use wz_session_core::reassembly_dispatch::{Fragment, ReassemblyConfig, ReassemblyDispatcher};
// The `T_MID_FRAGMENT` wire crafter is the shared no_std SSOT (R311it
// sibling), byte-identical with the MCU reassembly e2e so both profiles
// inspect the same fragment bytes.
use wz_session_wire_fixtures::craft_fragment_wire as fragment_frame;

/// `parse_inbound` decodes the transport-header R/M bits, the VLE sn, and
/// the tail payload into `InboundFrame::Fragment`.
#[test]
fn fragment_frame_decodes_r_m_sn_payload() {
    let wire = fragment_frame(true, true, 7, b"chunk0");
    let frame = parse_inbound(&wire).expect("parse fragment frame");
    let InboundFrame::Fragment {
        reliable,
        more,
        sn,
        payload,
        ..
    } = frame
    else {
        panic!("expected InboundFrame::Fragment");
    };
    assert!(reliable);
    assert!(more);
    assert_eq!(sn, 7);
    assert_eq!(payload, b"chunk0");
}

/// A best-effort fragment clears the R bit; a final fragment clears the M
/// bit — the two header discriminators are independent.
#[test]
fn best_effort_final_fragment_clears_r_and_m() {
    let wire = fragment_frame(false, false, 3, b"end");
    let frame = parse_inbound(&wire).expect("parse fragment frame");
    let InboundFrame::Fragment {
        reliable,
        more,
        sn,
        payload,
        ..
    } = frame
    else {
        panic!("expected InboundFrame::Fragment");
    };
    assert!(!reliable);
    assert!(!more);
    assert_eq!(sn, 3);
    assert_eq!(payload, b"end");
}

/// A two-fragment chain reassembles end-to-end through the real
/// `parse_inbound` decode + the dispatcher, concatenating the bodies in
/// SN order. This is the data path `report_outcome_reassembling` drives in
/// the steady-state session loop.
#[test]
fn two_fragment_chain_reassembles_through_parse_inbound() {
    let mut d: ReassemblyDispatcher<4, 256> =
        ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000));
    let zid: &[u8] = &[0x01; 16];

    let f0 = fragment_frame(true, true, 10, b"hello ");
    let f1 = fragment_frame(true, false, 11, b"world");

    let mut reassembled: Option<Vec<u8>> = None;
    for wire in [&f0, &f1] {
        let frame = parse_inbound(wire).expect("parse fragment frame");
        let InboundFrame::Fragment {
            reliable,
            sn,
            more,
            payload,
            ..
        } = frame
        else {
            panic!("expected InboundFrame::Fragment");
        };
        d.ingest(
            Fragment {
                peer_key: zid,
                reliable,
                sn,
                more: u8::from(more),
                payload: &payload,
                priority: wz_session_core::qos::Priority::DEFAULT,
            },
            wz_session_core::sn::mask_from_res(0x02),
            0,
            |msg| reassembled = Some(msg.to_vec()),
        );
    }

    assert_eq!(reassembled.as_deref(), Some(&b"hello world"[..]));
}
