// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R3062 -- a queryable that answers with a chunk of shared memory sends the DESCRIPTOR to a
//! face that negotiated shared memory and the bytes to one that did not, and hands a requester
//! of its own session the chunk.
//!
//! The upstream-facing proof of the same property is leg 12 of
//! `zenoh_c_shm_and_advanced_on_wz_capi_c` (a C queryable answered by upstream's own Rust
//! `z_get_shm`), which needs upstream's programs and so skips on a runner that does not have
//! them. These read the frame the session hands its link, which every runner has, and the
//! count of references on the chunk's slot, which is what a descriptor that left must have
//! raised and a frame that did not leave must not leave raised.

use super::tests::{make_request_query, query_frame_outcome};
use super::*;
use crate::observer::ApplicationLayerObserver;
use crate::runtime_impl::TokioTime;
use crate::shm_provider::{reference_state, ReferenceState, ShmBackedPayload};
use crate::test_fixtures::{recording_actions, RecordingLinkDriver};
use wz_session_core::extshm::encode_shm_descriptor;
use wz_session_core::query_sink::ReplyMeta;

const KEY: &str = "home/temp";
const VALUE: &[u8] = b"a reply that lives in shared memory";

/// A session whose link records the frames it is handed, with shared memory offered on this
/// side and, when `peer_offered`, on the other too. The same arrangement as the query-value
/// tests', which sit behind other features and so cannot lend it.
fn session(peer_offered: bool) -> (TokioSession, Arc<RecordingLinkDriver>) {
    let (actions, driver) = recording_actions();
    actions.set_shm_offer(true);
    actions.negotiate_shm_against_peer(peer_offered);
    assert_eq!(actions.is_shm(), peer_offered);
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(actions, observer, Arc::new(TokioTime::new()));
    (session, driver)
}

fn chunk() -> Arc<ShmBackedPayload> {
    let mut held = ShmBackedPayload::alloc(VALUE.len()).expect("alloc a reply buffer");
    held.write(VALUE);
    Arc::new(held)
}

/// Declare a queryable on `home/**` that answers every query with `chunk` as its payload.
fn answer_with(session: &TokioSession, chunk: &Arc<ShmBackedPayload>) -> Queryable {
    let shared = chunk.send_handle();
    session
        .declare_queryable(
            "home/**",
            QueryableOptions::default(),
            move |_query: &dyn QueryView, out: &mut dyn ReplyOut| {
                out.reply_keyed_meta(
                    KEY,
                    shared.bytes(),
                    ReplyMeta::new().with_shared(Some(&shared)),
                )
                .expect("the reply is admitted");
            },
        )
        .expect("query-queryable is on in this lane")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Ask `session` the wire query `home/temp` and return the Response frame it answered with.
fn ask_over_the_wire(session: &TokioSession, driver: &RecordingLinkDriver) -> Vec<u8> {
    let base = driver.frame_count();
    let outcome = query_frame_outcome(make_request_query(11, KEY));
    session.dispatch_iteration_event(crate::session_glue::IterationEvent::Poll(&outcome));
    assert_eq!(
        driver.frame_count() - base,
        2,
        "one Response and its ResponseFinal left the session"
    );
    let frame = driver.frame_bytes(base);
    eprintln!("Response frame: {frame:02x?}");
    frame
}

#[test]
fn a_reply_that_is_a_chunk_goes_on_the_wire_as_its_descriptor_to_a_face_that_negotiated() {
    let (session, driver) = session(true);
    let chunk = chunk();
    let _queryable = answer_with(&session, &chunk);

    let frame = ask_over_the_wire(&session, &driver);

    assert!(
        contains(&frame, &encode_shm_descriptor(&chunk.descriptor())),
        "the chunk's descriptor is not on the wire, and the receiver maps the segment from it"
    );
    assert!(
        !contains(&frame, VALUE),
        "the reply's bytes are on the wire, so it was sent as a copy and not as a reference to \
         the segment"
    );
    assert_eq!(
        reference_state(&chunk.descriptor()),
        Some(ReferenceState::Held(2)),
        "the owner's reference and the one the receiver will release: the frame that carries \
         the descriptor left, so its reservation was committed and not returned"
    );
}

#[test]
fn a_reply_that_is_a_chunk_goes_as_bytes_to_a_face_that_never_negotiated() {
    let (session, driver) = session(false);
    let chunk = chunk();
    let _queryable = answer_with(&session, &chunk);

    let frame = ask_over_the_wire(&session, &driver);

    assert!(
        contains(&frame, VALUE),
        "a peer that never agreed to shared memory cannot read a descriptor, so the reply goes \
         as bytes"
    );
    assert!(
        !contains(&frame, &encode_shm_descriptor(&chunk.descriptor())),
        "a descriptor reached a peer that never agreed to shared memory"
    );
    assert_eq!(
        reference_state(&chunk.descriptor()),
        Some(ReferenceState::Held(1)),
        "no descriptor left, so no reference was raised for a receiver"
    );
}

/// The requester of the SAME session is handed the chunk, and the reference taken for it goes
/// back when the reply drops. The plain reply beside it is the control.
#[test]
fn a_reply_that_is_a_chunk_reaches_a_requester_of_the_same_session_as_the_chunk() {
    let (session, _driver) = session(false);
    let chunk = chunk();
    let _queryable = answer_with(&session, &chunk);
    let shared_memory = Arc::new(Mutex::new(Vec::<bool>::new()));
    let seen = shared_memory.clone();

    session
        .query(
            KEY,
            QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
            move |reply: &dyn ReplyView| {
                seen.lock().unwrap().push(
                    reply
                        .payload_shared()
                        .is_some_and(|bytes| bytes.is_shared_memory()),
                );
            },
            |_| {},
        )
        .expect("query-get is on in this lane");

    assert_eq!(
        *shared_memory.lock().unwrap(),
        [true],
        "the requester was handed the chunk and not a copy of its bytes"
    );
    assert!(
        chunk.is_unique(),
        "and gave its reference back when the reply was dropped"
    );
}
