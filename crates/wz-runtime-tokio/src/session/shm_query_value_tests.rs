// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R3049 -- every way a getter sends the VALUE of a query through shared memory puts
//! a descriptor on the wire, and none of them puts the bytes there.
//!
//! The upstream-facing proof of the same property is the live legs of
//! `wz_shm_query_reply_zenohd_interop`, which need upstream's own programs and so skip
//! on a runner that does not have them. These read the frame the session hands its
//! link, which every runner has, and they are what keeps the three calls that reach
//! the wire (`Session::query_shm`, `Querier::get_shm`, `QuerierAliased::get_shm`) on
//! the one body they share: a call that dropped back to sending bytes, or that named
//! its key the wrong way, reads here.

use super::*;
use crate::observer::ApplicationLayerObserver;
use crate::runtime_impl::TokioTime;
use crate::shm_provider::ShmBackedPayload;
use crate::test_fixtures::{recording_actions, RecordingLinkDriver};
use wz_session_core::extshm::encode_shm_descriptor;

const KEY: &str = "demo/shm/query";
const VALUE: &[u8] = b"a query value that lives in shared memory";
const MAPPING_ID: u64 = 7;

/// The calls that put a query's value in shared memory on the wire.
#[derive(Clone, Copy, Debug)]
enum Call {
    /// `Session::query_shm`: the key is written out.
    Session,
    /// `Querier::get_shm`: the key is written out.
    Querier,
    /// `QuerierAliased::get_shm`: the key is the declared mapping's id.
    AliasedQuerier,
}

const CALLS: [Call; 3] = [Call::Session, Call::Querier, Call::AliasedQuerier];

/// A session whose link records the frames it is handed, with shared memory offered on
/// this side and, when `peer_offered`, on the other too.
fn session(peer_offered: bool) -> (TokioSession, Arc<RecordingLinkDriver>) {
    let (actions, driver) = recording_actions();
    actions.set_shm_offer(true);
    actions.negotiate_shm_against_peer(peer_offered);
    assert_eq!(
        actions.is_shm(),
        peer_offered,
        "the session negotiated shared memory exactly when the peer offered it"
    );
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(actions, observer, Arc::new(TokioTime::new()));
    (session, driver)
}

fn held_value() -> ShmBackedPayload {
    let mut held = ShmBackedPayload::alloc(VALUE.len()).expect("alloc a value buffer");
    held.write(VALUE);
    held
}

/// The last frame the link was handed, after printing every one: the output of a test
/// that passes is not shown, and a failing assertion is read against the frames.
fn last_frame(call: Call, driver: &RecordingLinkDriver) -> Vec<u8> {
    let frames = driver.frame_count();
    for idx in 0..frames {
        eprintln!(
            "{call:?}: frame {idx} of {frames}: {:02x?}",
            driver.frame_bytes(idx)
        );
    }
    driver.frame_bytes(frames - 1)
}

/// Send one query whose value is `held` through `call` and return the frame the link
/// was handed for it. A querier is read WHILE IT IS ALIVE: declaring one sends an
/// interest and dropping it sends the interest's end, so the query is the last frame
/// only between the two, and the frame read after the drop is not the query's.
fn send(
    call: Call,
    session: &TokioSession,
    driver: &RecordingLinkDriver,
    held: &ShmBackedPayload,
) -> Vec<u8> {
    let options = QueryOptions::get();
    match call {
        Call::Session => {
            session
                .query_shm(KEY, options, held, |_| {}, |_| {})
                .expect("query_shm sends");
            last_frame(call, driver)
        }
        Call::Querier => {
            let querier = session.declare_querier(KEY, options);
            querier
                .get_shm(held, |_| {}, |_| {})
                .expect("Querier::get_shm sends");
            last_frame(call, driver)
        }
        Call::AliasedQuerier => {
            session
                .actions()
                .send_declare_keyexpr(MAPPING_ID, KEY)
                .expect("declare the mapping");
            let querier = session.declare_querier_aliased(MAPPING_ID, None, options);
            querier
                .get_shm(held, |_| {}, |_| {})
                .expect("QuerierAliased::get_shm sends");
            last_frame(call, driver)
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn a_value_in_shared_memory_goes_on_the_wire_as_its_descriptor_by_every_call() {
    for call in CALLS {
        let (session, driver) = session(true);
        let held = held_value();
        let frame = send(call, &session, &driver, &held);
        assert!(
            contains(&frame, &encode_shm_descriptor(&held.descriptor())),
            "{call:?}: the buffer's descriptor is not on the wire, and the receiver maps the \
             segment from it"
        );
        assert!(
            !contains(&frame, VALUE),
            "{call:?}: the value's bytes are on the wire, so it was sent as a copy and not \
             as a reference to the segment"
        );
    }
}

#[test]
fn a_literal_call_names_its_key_and_an_aliased_one_names_its_mapping() {
    for call in CALLS {
        let (session, driver) = session(true);
        let held = held_value();
        let frame = send(call, &session, &driver, &held);
        let names_the_key = contains(&frame, KEY.as_bytes());
        match call {
            Call::Session | Call::Querier => assert!(
                names_the_key,
                "{call:?}: a literal query writes its key on the wire"
            ),
            Call::AliasedQuerier => assert!(
                !names_the_key,
                "{call:?}: an aliased query names its key by the mapping's id, and the \
                 literal is on the wire again"
            ),
        }
    }
}

#[test]
fn a_session_that_did_not_negotiate_shared_memory_carries_the_bytes() {
    for call in CALLS {
        let (session, driver) = session(false);
        let held = held_value();
        let frame = send(call, &session, &driver, &held);
        assert!(
            contains(&frame, VALUE),
            "{call:?}: a peer that never agreed to shared memory cannot read a descriptor, so \
             the value goes as bytes"
        );
        assert!(
            !contains(&frame, &encode_shm_descriptor(&held.descriptor())),
            "{call:?}: a descriptor reached a peer that never agreed to shared memory"
        );
    }
}
