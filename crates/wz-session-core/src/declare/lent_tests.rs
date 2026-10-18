// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A `Declare`, an `Interest` or a `ResponseFinal` that the per-session slot
//! profile's receive path LENDS does what its owned form does, registry by
//! registry (fixed-memory step S9d).
//!
//! Each test feeds one stream of records twice, to two registries built alike: as
//! the owned messages of a `FramePayload` (what every other profile reads) and as
//! the records decoded where their frame lies ([`IterationEvent::InPlace`], what the
//! slot profile reads). What each registry then did must be the same, and not
//! empty: a lent record that a registry ignored would pass an equality test of two
//! empty logs, so every test also pins what the log holds.
//!
//! The end-to-end claim (the lent records cost the heap nothing on a real session)
//! is `wz-session-lwip`'s `slot_control_records`; what this file adds is the
//! per-registry equivalence that file cannot see for the planes it does not
//! register (the queryables, the liveliness planes, the local tokens, the pending
//! replies).

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use std::sync::{Arc, Mutex};

use hashbrown::HashMap;
use wz_codecs::declare::DeclareOwned;

use crate::decl_sink::DeclView;
use crate::declare_build::{
    build_declare_final, build_declare_final_reply, build_declare_queryable_with_id_info,
    build_declare_subscriber, build_declare_token, build_declare_token_reply,
    build_undeclare_queryable, build_undeclare_subscriber, build_undeclare_token,
};
use crate::driver_loop::{DriverLoopOutcome, InPlaceRecord, IterationEvent};
use crate::locality::Locality;
use crate::network_message::NetworkMessage;
use crate::qos::Priority;
use crate::queryable_info::QueryableInfo;

type Log = Arc<Mutex<Vec<String>>>;

fn log() -> Log {
    Arc::new(Mutex::new(Vec::new()))
}

fn lines(log: &Log) -> Vec<String> {
    log.lock().expect("not poisoned").clone()
}

/// A received frame carrying `messages`, as the owned form reports it.
fn frame(messages: Vec<NetworkMessage>) -> DriverLoopOutcome {
    DriverLoopOutcome::FramePayload {
        reliable: true,
        sn: 0,
        messages,
        has_ext: false,
        extensions: Vec::new(),
        priority: Priority::DEFAULT,
    }
}

/// Hand `declare` to `owned` as the owned message of a frame and to `lent` as the
/// record read where its frame lies.
fn both_declare(
    declare: &DeclareOwned,
    mut owned: impl FnMut(IterationEvent<'_>),
    mut lent: impl FnMut(IterationEvent<'_>),
) {
    owned(IterationEvent::Poll(&frame(vec![NetworkMessage::Declare(
        Box::new(declare.clone()),
    )])));
    let view = declare.try_as_borrowed().expect("a borrowed view");
    lent(IterationEvent::InPlace(InPlaceRecord::declare_of_frame(
        &view,
        true,
        0,
        Priority::DEFAULT,
    )));
}

#[test]
fn a_lent_subscriber_declaration_reaches_the_remote_subscribers_as_the_owned_one_does() {
    use super::subscriber::RemoteSubscriberRegistry;
    let (owned_log, lent_log) = (log(), log());
    let mut owned = RemoteSubscriberRegistry::new();
    let mut lent = RemoteSubscriberRegistry::new();
    for (registry, log) in [(&mut owned, &owned_log), (&mut lent, &lent_log)] {
        let seen = log.clone();
        registry.on_subscriber_declared(move |d: &dyn DeclView| {
            seen.lock()
                .expect("not poisoned")
                .push(format!("+{} {}", d.id(), d.keyexpr()));
        });
        let seen = log.clone();
        registry.on_subscriber_undeclared(move |id| {
            seen.lock().expect("not poisoned").push(format!("-{id}"));
        });
    }
    let table: HashMap<u64, String> = HashMap::new();
    for declare in [
        build_declare_subscriber(1, 0, Some("a/b")).expect("build"),
        build_declare_subscriber(2, 0, Some("c/d")).expect("build"),
        build_undeclare_subscriber(1),
        build_declare_final(),
    ] {
        both_declare(
            &declare,
            |event| owned.dispatch_iteration_event(event, &table),
            |event| lent.dispatch_iteration_event(event, &table),
        );
    }
    assert_eq!(
        lines(&lent_log),
        vec!["+1 a/b", "+2 c/d", "-1"],
        "the lent declarations were announced, and the DeclFinal was not"
    );
    assert_eq!(
        lines(&owned_log),
        lines(&lent_log),
        "as the owned form does"
    );
    assert_eq!(
        (owned.has_matching("c/d"), owned.has_matching("a/b")),
        (lent.has_matching("c/d"), lent.has_matching("a/b")),
        "and the peer's table holds the same declarations"
    );
    assert!(lent.has_matching("c/d") && !lent.has_matching("a/b"));
}

#[test]
fn a_lent_queryable_declaration_carries_its_completeness_as_the_owned_one_does() {
    use super::queryable::{QuerierCriterion, RemoteQueryableRegistry};
    let (owned_log, lent_log) = (log(), log());
    let mut owned = RemoteQueryableRegistry::new();
    let mut lent = RemoteQueryableRegistry::new();
    for (registry, log) in [(&mut owned, &owned_log), (&mut lent, &lent_log)] {
        let seen = log.clone();
        registry.on_queryable_declared(move |d: &dyn DeclView| {
            seen.lock()
                .expect("not poisoned")
                .push(format!("+{} {}", d.id(), d.keyexpr()));
        });
        let seen = log.clone();
        registry.on_queryable_undeclared(move |id| {
            seen.lock().expect("not poisoned").push(format!("-{id}"));
        });
    }
    let table: HashMap<u64, String> = HashMap::new();
    let info = |complete| QueryableInfo {
        complete,
        distance: 0,
    };
    for declare in [
        build_declare_queryable_with_id_info(1, "q/complete", info(true)).expect("build"),
        build_declare_queryable_with_id_info(2, "q/partial", info(false)).expect("build"),
        build_undeclare_queryable(2),
    ] {
        both_declare(
            &declare,
            |event| owned.dispatch_iteration_event(event, &table),
            |event| lent.dispatch_iteration_event(event, &table),
        );
    }
    assert_eq!(
        lines(&lent_log),
        vec!["+1 q/complete", "+2 q/partial", "-2"]
    );
    assert_eq!(
        lines(&owned_log),
        lines(&lent_log),
        "as the owned form does"
    );
    // Completeness is what a querier that demands it asks of the table: only the
    // declaration whose extension says complete answers it.
    let complete = QuerierCriterion::new("q/complete", Locality::Any, true);
    let partial = QuerierCriterion::new("q/partial", Locality::Any, true);
    assert_eq!(
        (
            owned.has_matching_for(&complete),
            owned.has_matching_for(&partial)
        ),
        (
            lent.has_matching_for(&complete),
            lent.has_matching_for(&partial)
        ),
    );
    assert!(
        lent.has_matching_for(&complete),
        "the completeness the lent declaration carried was read"
    );
}

#[test]
fn a_lent_token_declaration_is_announced_as_the_owned_one_is() {
    use super::liveliness::LivelinessRegistry;
    let (owned_log, lent_log) = (log(), log());
    let mut owned = LivelinessRegistry::new();
    let mut lent = LivelinessRegistry::new();
    for (registry, log) in [(&mut owned, &owned_log), (&mut lent, &lent_log)] {
        let seen = log.clone();
        registry.on_token_declared(move |d: &dyn DeclView| {
            seen.lock()
                .expect("not poisoned")
                .push(format!("+{} {}", d.id(), d.keyexpr()));
        });
        let seen = log.clone();
        registry.on_token_undeclared(move |id| {
            seen.lock().expect("not poisoned").push(format!("-{id}"));
        });
    }
    let table: HashMap<u64, String> = HashMap::new();
    for declare in [
        build_declare_token(3, 0, Some("live/a")).expect("build"),
        build_undeclare_token(3),
    ] {
        both_declare(
            &declare,
            |event| owned.dispatch_iteration_event(event, &table),
            |event| lent.dispatch_iteration_event(event, &table),
        );
    }
    assert_eq!(lines(&lent_log), vec!["+3 live/a", "-3"]);
    assert_eq!(
        lines(&owned_log),
        lines(&lent_log),
        "as the owned form does"
    );
    assert_eq!(lent.oversize(), 0, "nothing was past the bounded buffer");
}

#[test]
fn a_lent_token_reaches_a_liveliness_subscriber_and_a_current_replays_final_completes_its_history()
{
    use super::liveliness_sample::{BoxedLivelinessSampleSink, LivelinessSample};
    use super::liveliness_subscriber::LivelinessSubscriberRegistry;
    let (owned_log, lent_log) = (log(), log());
    let mut owned = LivelinessSubscriberRegistry::new();
    let mut lent = LivelinessSubscriberRegistry::new();
    for (registry, log) in [(&mut owned, &owned_log), (&mut lent, &lent_log)] {
        let seen = log.clone();
        registry
            .register(
                4,
                "live/**",
                true,
                BoxedLivelinessSampleSink::new(move |sample: LivelinessSample<'_>| {
                    seen.lock().expect("not poisoned").push(format!(
                        "{:?} {} {}",
                        sample.kind, sample.keyexpr, sample.token_id
                    ));
                }),
            )
            .expect("register the subscriber");
    }
    let table: HashMap<u64, String> = HashMap::new();
    for declare in [
        build_declare_token(3, 0, Some("live/a")).expect("build"),
        // A token this subscriber's pattern does not cover.
        build_declare_token(4, 0, Some("other/b")).expect("build"),
        build_undeclare_token(3),
        // The terminator of the subscriber's own CURRENT replay (interest 4).
        build_declare_final_reply(4),
    ] {
        both_declare(
            &declare,
            |event| owned.dispatch_iteration_event(event, &table),
            |event| lent.dispatch_iteration_event(event, &table),
        );
    }
    assert_eq!(lines(&lent_log), vec!["Put live/a 3", "Delete live/a 3"]);
    assert_eq!(
        lines(&owned_log),
        lines(&lent_log),
        "as the owned form does"
    );
    assert_eq!(
        (owned.history_complete(4), lent.history_complete(4)),
        (true, true),
        "the DeclFinal that answers a CURRENT interest completes the history"
    );
}

#[test]
fn a_lent_reply_to_a_liveliness_get_is_delivered_and_its_final_ends_the_get_as_the_owned_ones_do() {
    use super::liveliness_get::LivelinessGetRegistry;
    let (owned_log, lent_log) = (log(), log());
    let mut owned = LivelinessGetRegistry::new();
    let mut lent = LivelinessGetRegistry::new();
    for (registry, log) in [(&mut owned, &owned_log), (&mut lent, &lent_log)] {
        let replies = log.clone();
        let finals = log.clone();
        registry
            .register_get(
                9,
                None,
                move |reply| {
                    replies
                        .lock()
                        .expect("not poisoned")
                        .push(format!("reply {}", reply.keyexpr()));
                },
                move |id| {
                    finals
                        .lock()
                        .expect("not poisoned")
                        .push(format!("final {id}"));
                },
            )
            .expect("register the get");
    }
    let table: HashMap<u64, String> = HashMap::new();
    for declare in [
        // An unsolicited token is not a get reply, on either form.
        build_declare_token(1, 0, Some("not/a/reply")).expect("build"),
        build_declare_token_reply(9, "live/x").expect("build"),
        build_declare_final_reply(9),
    ] {
        both_declare(
            &declare,
            |event| owned.dispatch_iteration_event(event, &table),
            |event| lent.dispatch_iteration_event(event, &table),
        );
    }
    assert_eq!(lines(&lent_log), vec!["reply live/x", "final 9"]);
    assert_eq!(
        lines(&owned_log),
        lines(&lent_log),
        "as the owned form does"
    );
    assert!(!lent.has_pending(9), "the final removed the get");
}

#[test]
fn a_lent_interest_is_answered_by_the_local_tokens_as_the_owned_one_is() {
    use super::local_token::{DeclResponseItem, LocalTokenRegistry};
    use crate::bounded::BoundedVec;
    use crate::caps;
    use crate::interest_build::{build_interest_final, build_interest_liveliness_get};

    let mut registry = LocalTokenRegistry::new();
    registry.register(1, "live/a").expect("register");
    registry.register(2, "other/b").expect("register");
    let table: HashMap<u64, String> = HashMap::new();
    let tokens_and_finals =
        |pending: &BoundedVec<DeclResponseItem, { caps::MAX_PENDING_DECLARES }>| {
            pending
                .iter()
                .map(|item| match item {
                    DeclResponseItem::Token {
                        token_id,
                        interest_id,
                    } => format!("token {token_id} for {interest_id}"),
                    DeclResponseItem::Final { interest_id } => format!("final for {interest_id}"),
                })
                .collect::<Vec<_>>()
        };
    for interest in [
        build_interest_liveliness_get(5, 0, Some("live/**")).expect("build"),
        build_interest_liveliness_get(6, 0, None).expect("build"),
        // A FINAL solicits nothing.
        build_interest_final(5),
    ] {
        let mut owned_pending: BoundedVec<DeclResponseItem, { caps::MAX_PENDING_DECLARES }> =
            BoundedVec::new();
        let mut lent_pending: BoundedVec<DeclResponseItem, { caps::MAX_PENDING_DECLARES }> =
            BoundedVec::new();
        let owned_refused = registry.dispatch_iteration_event(
            IterationEvent::Poll(&frame(vec![NetworkMessage::Interest(interest.clone())])),
            &table,
            &mut owned_pending,
        );
        let view = interest.try_as_borrowed().expect("a borrowed view");
        let lent_refused = registry.dispatch_iteration_event(
            IterationEvent::InPlace(InPlaceRecord::interest_of_frame(
                &view,
                true,
                0,
                Priority::DEFAULT,
            )),
            &table,
            &mut lent_pending,
        );
        assert_eq!(owned_refused, lent_refused, "refused chains");
        assert_eq!(
            tokens_and_finals(&lent_pending),
            tokens_and_finals(&owned_pending),
            "interest {}: the same chain is staged",
            interest.interest_id
        );
    }
    // And the lent one staged something: the first interest matched one token.
    let mut pending: BoundedVec<DeclResponseItem, { caps::MAX_PENDING_DECLARES }> =
        BoundedVec::new();
    let first = build_interest_liveliness_get(5, 0, Some("live/**")).expect("build");
    let view = first.try_as_borrowed().expect("a borrowed view");
    registry.dispatch_iteration_event(
        IterationEvent::InPlace(InPlaceRecord::interest_of_frame(
            &view,
            true,
            0,
            Priority::DEFAULT,
        )),
        &table,
        &mut pending,
    );
    assert_eq!(
        tokens_and_finals(&pending),
        vec!["token 1 for 5", "final for 5"]
    );
}

#[test]
fn a_lent_response_final_ends_the_pending_get_as_the_owned_one_does() {
    use crate::reply::ReplyRegistry;
    use crate::reply_acceptance::ReplyAcceptance;
    use crate::response_final_build::build_response_final;
    use crate::sample::QosLevel;

    let (owned_log, lent_log) = (log(), log());
    let mut owned = ReplyRegistry::new();
    let mut lent = ReplyRegistry::new();
    for (registry, log) in [(&mut owned, &owned_log), (&mut lent, &lent_log)] {
        let finals = log.clone();
        registry.register(
            7,
            1,
            None,
            ReplyAcceptance::Any,
            |_reply| {},
            move |rid| {
                finals
                    .lock()
                    .expect("not poisoned")
                    .push(format!("final {rid}"));
            },
        );
    }
    let table: HashMap<u64, String> = HashMap::new();
    // A final for a request nobody here asked is dropped, on both forms.
    for done in [
        build_response_final(99, QosLevel::default()),
        build_response_final(7, QosLevel::default()),
    ] {
        owned.dispatch_iteration_event(
            IterationEvent::Poll(&frame(vec![NetworkMessage::ResponseFinal(done.clone())])),
            &table,
        );
        let view = done.try_as_borrowed().expect("a borrowed view");
        lent.dispatch_iteration_event(
            IterationEvent::InPlace(InPlaceRecord::response_final_of_frame(
                &view,
                true,
                0,
                Priority::DEFAULT,
            )),
            &table,
        );
    }
    assert_eq!(lines(&lent_log), vec!["final 7"]);
    assert_eq!(
        lines(&owned_log),
        lines(&lent_log),
        "as the owned form does"
    );
    assert_eq!(lent.len(), 0, "the final removed the pending get");
}

#[test]
fn a_lent_alias_and_a_lent_subscriber_interest_are_kept_as_the_owned_ones_are() {
    use crate::declare_build::build_declare_kexpr;
    use crate::interest_build::{build_interest_final, build_interest_subscribers};
    use crate::pubsub::SubscriberRegistry;
    use crate::sink::BoxedSink;

    let mut owned: SubscriberRegistry<BoxedSink> = SubscriberRegistry::new();
    let mut lent: SubscriberRegistry<BoxedSink> = SubscriberRegistry::new();
    for registry in [&mut owned, &mut lent] {
        registry
            .register_sink(
                "i/**",
                Locality::Any,
                BoxedSink::new(|_sample: &dyn crate::sink::SampleView| {}),
            )
            .expect("register a subscriber the interest can name");
    }
    // The alias a peer minted: the same id must name the same keyexpr afterwards.
    both_declare(
        &build_declare_kexpr(5, "i/area").expect("build"),
        |event| owned.dispatch_iteration_event(event),
        |event| lent.dispatch_iteration_event(event),
    );
    assert_eq!(
        (owned.peer().alias_count(), lent.peer().alias_count()),
        (1, 1),
        "the alias is bound"
    );
    assert_eq!(
        lent.resolve_inbound_mapping(5).as_deref(),
        Some("i/area"),
        "and names the keyexpr it was declared on"
    );
    assert_eq!(
        owned.resolve_inbound_mapping(5),
        lent.resolve_inbound_mapping(5)
    );

    // A CURRENT and FUTURE subscriber interest: the row is kept and the answer is
    // staged; its FINAL retires the row.
    let interest = build_interest_subscribers(11, true, true, 0, Some("i/**")).expect("build");
    owned.dispatch_iteration_event(IterationEvent::Poll(&frame(vec![
        NetworkMessage::Interest(interest.clone()),
    ])));
    let view = interest.try_as_borrowed().expect("a borrowed view");
    lent.dispatch_iteration_event(IterationEvent::InPlace(InPlaceRecord::interest_of_frame(
        &view,
        true,
        0,
        Priority::DEFAULT,
    )));
    assert_eq!(
        (owned.peer().interest_count(), lent.peer().interest_count()),
        (1, 1),
        "the interest is kept"
    );
    assert_eq!(
        owned.take_staged_sub_interest_replies().len(),
        lent.take_staged_sub_interest_replies().len(),
        "and answered alike"
    );
    let done = build_interest_final(11);
    owned.dispatch_iteration_event(IterationEvent::Poll(&frame(vec![
        NetworkMessage::Interest(done.clone()),
    ])));
    let view = done.try_as_borrowed().expect("a borrowed view");
    lent.dispatch_iteration_event(IterationEvent::InPlace(InPlaceRecord::interest_of_frame(
        &view,
        true,
        0,
        Priority::DEFAULT,
    )));
    assert_eq!(
        (owned.peer().interest_count(), lent.peer().interest_count()),
        (0, 0),
        "the FINAL retired it"
    );
}
