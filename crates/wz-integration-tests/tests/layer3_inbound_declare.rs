// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop — reverse direction (DECLARE inbound batch dispatch).
//!
//! `layer3_declare.rs` closed the forward direction in R110e (wz
//! `Declare::default().encode_to_vec()` byte-equals zenoh-pico
//! `_z_declare_encode`). R115 closes the loop: the same bytes routed
//! through `parse_frame_payload` produce a `NetworkMessage::Declare`
//! variant whose inner body field-matches the canonical
//! `Declare::default()` shape.
//!
//! Wire path:
//! ```text
//!   wz Declare::default().encode  ─→  bytes  ─→  parse_frame_payload
//!     ↓                                            ↓
//!   wire-equiv vs pico (R110e)                  NetworkMessage::Declare
//! ```
//!
//! The forward direction already guarantees these bytes are what a
//! zenoh-pico peer would emit; reusing them as the inbound fixture
//! removes the FFI dependency from the inbound test while preserving
//! the byte-level peer-emission semantics.

use sce_forge_runtime::codec::SceCursor;
use wz_codecs::declare::Declare;
use wz_codecs::push::Push;
use wz_codecs::response_final::ResponseFinal;
use wz_runtime_tokio::session_glue::{parse_frame_payload, NetworkMessage};

#[test]
fn declare_default_round_trips_through_parse_frame_payload() {
    let wire = Declare::default().encode_to_vec();
    assert_eq!(
        wire,
        &[0x1E, 0x1A],
        "fixture sanity: default DECLARE wire is envelope hdr 0x1E + decl_final inner hdr 0x1A"
    );

    let messages = parse_frame_payload(&wire).expect("parse default DECLARE");
    assert_eq!(messages.len(), 1, "single-record batch");

    match &messages[0] {
        NetworkMessage::Declare(decl) => {
            let mut cursor = SceCursor::new(&wire);
            let canonical = Declare::decode(&mut cursor).expect("canonical decode");
            let re_encoded = decl
                .try_as_borrowed()
                .expect("test: <=N exts by construction")
                .encode_to_vec();
            assert_eq!(
                re_encoded,
                canonical.encode_to_vec(),
                "parse_frame_payload-produced Declare must field-match the canonical decode"
            );
            assert_eq!(re_encoded, wire, "round-trip byte-equivalence preserved");
        }
        other => panic!("expected NetworkMessage::Declare, got {other:?}"),
    }
}

#[test]
fn declare_dispatch_does_not_swallow_subsequent_records() {
    // Build a 3-record batch — Push :: Declare :: ResponseFinal — to
    // verify Declare's decode advances the cursor cleanly so the next
    // peek-byte dispatch lands on the ResponseFinal header rather than
    // mis-reading a tail byte of the Declare body. Equivalent guard
    // against the "unknown body length" failure mode that
    // `NetworkMessage::Unknown` is documented to avoid.
    let mut wire = Vec::new();
    wire.extend_from_slice(&Push::default().encode_to_vec());
    wire.extend_from_slice(&Declare::default().encode_to_vec());
    wire.extend_from_slice(&ResponseFinal::default().encode_to_vec());

    let messages = parse_frame_payload(&wire).expect("parse 3-record batch");
    assert_eq!(messages.len(), 3, "all three records must be dispatched");
    assert!(matches!(messages[0], NetworkMessage::Push(_)));
    assert!(matches!(messages[1], NetworkMessage::Declare(_)));
    assert!(matches!(messages[2], NetworkMessage::ResponseFinal(_)));
}

#[test]
fn declare_dispatch_surfaces_codec_error_on_truncated_envelope() {
    // Two-byte default DECLARE truncated to the envelope header byte
    // only. `Declare::decode` should fail with `NeedMoreBytes` because
    // the peek-byte inner dispatch can't read the inner declaration
    // header. `parse_frame_payload` surfaces the codec error verbatim
    // (caller in `poll_and_dispatch_one` maps it to a FramingError).
    let truncated = [0x1Eu8];
    parse_frame_payload(&truncated).expect_err("truncated DECLARE must reject");
}
