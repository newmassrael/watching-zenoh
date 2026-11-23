// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session that reads each inbound datagram where its link holds it (`rx-in-place`): a Push
//! reaches the subscriber, and a Response the get that asked for it, from the frame's own bytes,
//! each record lent for its dispatch, as the copying receive delivers them.

use std::sync::{Arc, Mutex};

use wz_capi_port::{SessionEngine, WireKey};
use wz_session_core::locality::Locality;
use wz_session_core::sink::SampleView;

use super::{open, until, CatchAll, Command, Router};

/// A Push the router sends is read in place and reaches the subscriber with its key and payload.
#[test]
fn a_push_read_in_place_reaches_the_subscriber() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let got = Arc::new(Mutex::new(Vec::new()));
    let into = got.clone();
    engine.declare_subscriber_on_wire(
        "demo/**",
        WireKey::literal(),
        Locality::Any,
        None,
        Arc::new(move || {
            let into = into.clone();
            Box::new(move |sample: &dyn SampleView| {
                into.lock()
                    .unwrap()
                    .push((sample.keyexpr().to_owned(), sample.payload().to_vec()));
            })
        }),
    );
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares >= 1)
    });
    router.send(Command::Push("demo/in-place", b"lent"));
    until(&engine, "the sample", || !got.lock().unwrap().is_empty());
    assert_eq!(
        *got.lock().unwrap(),
        [("demo/in-place".to_owned(), b"lent".to_vec())]
    );
}

/// A get the router's queryable answers ends with its reply, read in place, and its Final.
#[cfg(feature = "query")]
#[test]
fn a_reply_read_in_place_answers_its_get() {
    use super::get::{ask, remote_get, settle};
    use wz_session_core::reply_sink::ReplyKind;

    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    settle(&router, &engine, Command::Answer("demo/g/**", b"r"));
    let (issued, leg) = ask(&engine, "demo/g/a", &remote_get(), None, None, None);
    assert_eq!(issued, Ok(1), "one leg: the link's peer");
    until(&engine, "the leg to end", || leg.lock().unwrap().ended);
    assert_eq!(
        leg.lock().unwrap().replies,
        vec![(ReplyKind::Put, "demo/g/a".to_owned(), b"r".to_vec())]
    );
}

/// The engine's tables are handed an owned record only where its receive projects one: the build
/// that lends only (`rx-lent-only`), with no counter that reads owned messages, hands them none,
/// so their readers of owned messages are left out of its text; any other build hands them the
/// batch it was given.
#[test]
fn the_tables_take_owned_records_only_where_the_engine_projects_them() {
    use wz_session_core::driver_loop::{owned_records, OWNED_RECORDS};
    let lends_only = cfg!(feature = "rx-lent-only") && !cfg!(feature = "transport-stats");
    assert_eq!(OWNED_RECORDS, !lends_only);
    assert_eq!(
        owned_records(&[]).is_some(),
        !lends_only,
        "an empty batch is read only where owned records are"
    );
}

/// The walk of a frame this engine reads in place lends every record (`rx-lent-control`): in the
/// build whose tables take no owned record (the C library's, `rx-lent-only` with no counters), the
/// walk's one-record buffer is a marker of no size too, so the build links no drop of an owned
/// message for a list that is always empty. Run with `--features rx-lent-only` to build that form.
#[test]
fn the_walk_holds_a_record_buffer_of_no_size_where_the_tables_take_no_owned_record() {
    use wz_session_core::driver_loop::OWNED_RECORDS;
    use wz_session_core::network_message::{new_record_buf, RecordBuf};
    let mut record = new_record_buf();
    record.clear();
    const {
        assert!(
            OWNED_RECORDS || core::mem::size_of::<RecordBuf>() == 0,
            "a build that lends every record holds a buffer of no size"
        );
    }
}

/// The records an outcome carries are a list of no size in the build whose tables take no owned
/// record, so an outcome dropped there links no drop of an owned message; in either form a frame
/// with no record reads as an empty batch, and the tables are handed it only where they read owned
/// records. Run with `--features rx-lent-only` to build the form of no size.
#[test]
fn an_outcome_holds_a_batch_of_no_size_where_the_tables_take_no_owned_record() {
    use wz_session_core::driver_loop::{
        frame_records, owned_records, DriverLoopOutcome, FrameRecords, OWNED_RECORDS,
    };
    const {
        assert!(
            OWNED_RECORDS == (core::mem::size_of::<FrameRecords>() != 0),
            "the batch is owned exactly where the tables read owned records"
        );
    }
    let outcome = DriverLoopOutcome::FramePayload {
        reliable: true,
        sn: 0,
        messages: frame_records(Vec::new()),
        has_ext: false,
        extensions: Vec::new(),
        priority: wz_session_core::qos::Priority::DEFAULT,
    };
    let DriverLoopOutcome::FramePayload { messages, .. } = &outcome else {
        panic!("built as a frame's payload, got {outcome:?}");
    };
    assert!(messages.is_empty());
    assert_eq!(owned_records(messages).is_some(), OWNED_RECORDS);
    assert!(FrameRecords::new().is_empty());
}
