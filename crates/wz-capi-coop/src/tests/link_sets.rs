// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a call states that this engine does not carry out: a set of links (policy
//! `entity-link-restriction`), a retry of a publish (`publisher-admission-retry`), the
//! all-or-none form (`multi-route-atomic-tx`) and a query's one node (`targeted-query`). The
//! engine numbers none of its links, offers no frame without waiting, reserves none and addresses
//! no query, so every operation that states one of these is refused by name and makes nothing,
//! and the same operation stating none is made as before.

use std::sync::Arc;

use wz_capi_port::{
    FanoutError, LinksNotHonoured, Refusal, SessionEngine, StatementNotHonoured, SubscriberSink,
    WireKey,
};
use wz_session_core::admission_retry::AdmissionRetry;
use wz_session_core::link_restriction::LinkRestriction;
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::sink::SampleView;

use super::{open, until, CatchAll, Router};

fn one_link() -> LinkRestriction {
    LinkRestriction::only([1]).expect("one slot")
}

/// A publish that states a set of links, a retry or the all-or-none form is refused by name and
/// sends nothing; the same publish stating none of them reaches the router, and is the only one
/// that does.
#[test]
fn a_stated_publish_is_refused_by_name_and_sends_nothing() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);

    let remote = || PublishOptions::put().with_locality(Locality::Remote);
    let retry = AdmissionRetry {
        attempts: 2,
        delay_ms: 5,
    };
    for (stated, named) in [
        (remote().with_links(one_link()), StatementNotHonoured::Links),
        (
            remote().with_admission_retry(retry),
            StatementNotHonoured::AdmissionRetry,
        ),
        (remote().with_atomic_tx(), StatementNotHonoured::AtomicTx),
    ] {
        assert_eq!(
            engine.publish_on_wire_all("demo/links/a", &WireKey::literal(), b"stated", &stated),
            Err(FanoutError::NotHonoured(named))
        );
    }
    engine
        .publish_on_wire_all(
            "demo/links/a",
            &WireKey::literal(),
            b"plain",
            &PublishOptions::put().with_locality(Locality::Remote),
        )
        .expect("a publish that states no set is sent");
    until(&engine, "the router to receive the plain put", || {
        router.seen(|s| s.samples.iter().any(|(_, v)| v == b"plain"))
    });
    assert_eq!(
        router.seen(|s| s.samples.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>()),
        vec![b"plain".to_vec()],
        "the limited publish went out on no link"
    );
}

/// A subscriber limited to a link is refused by name and nothing is declared; the same one
/// stating no set is declared to the router.
#[test]
fn a_limited_subscriber_is_refused_by_name_and_declares_nothing() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);
    let sink: SubscriberSink =
        Arc::new(|| Box::new(|_: &dyn SampleView| {}) as Box<dyn FnMut(&dyn SampleView) + Send>);

    let declares_before = router.seen(|s| s.declares);
    assert_eq!(
        engine.declare_subscriber_on_link_set(
            "demo/links/**",
            WireKey::literal(),
            Locality::Any,
            one_link(),
            None,
            sink.clone(),
        ),
        Err(LinksNotHonoured)
    );
    let taken = engine.declare_subscriber_on_link_set(
        "demo/links/**",
        WireKey::literal(),
        Locality::Any,
        LinkRestriction::Any,
        None,
        sink,
    );
    assert!(
        matches!(taken, Ok(Some(_))),
        "no set is never refused: {taken:?}"
    );
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
}

/// A get limited to a link or addressed to one node is refused by that statement, and no leg is
/// minted for it.
#[cfg(feature = "query")]
#[test]
fn a_stated_get_is_refused_by_name_and_asks_no_link() {
    use wz_capi_port::ReplyCallback;
    use wz_session_core::query_options::QueryOptions;
    use wz_session_core::reply_sink::ReplyView;

    let router = Router::start(CatchAll::Held);
    let engine = open(&router);

    let mut legs = 0usize;
    for (stated, named) in [
        (
            QueryOptions::default().with_links(one_link()),
            StatementNotHonoured::Links,
        ),
        (
            QueryOptions::default().with_target_peer([0xc3]),
            StatementNotHonoured::TargetPeer,
        ),
    ] {
        assert_eq!(
            engine.get_on_wire(
                "demo/links/q",
                &WireKey::literal(),
                &stated,
                None,
                &mut || -> ReplyCallback {
                    legs += 1;
                    Box::new(|_: &dyn ReplyView| {})
                }
            ),
            Err(Refusal::NotHonoured(named))
        );
    }
    assert_eq!(legs, 0, "no leg was minted for a get that states something");
}

/// A liveliness token and a liveliness get limited to a link are refused by name; the token
/// stating no set is declared.
#[cfg(feature = "liveliness")]
#[test]
fn a_limited_liveliness_token_is_refused_by_name() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);

    assert_eq!(
        engine.declare_liveliness_token_on_link_set(
            "demo/links/token",
            WireKey::literal(),
            one_link(),
            None,
        ),
        Err(LinksNotHonoured)
    );
    let taken = engine.declare_liveliness_token_on_link_set(
        "demo/links/token",
        WireKey::literal(),
        LinkRestriction::Any,
        None,
    );
    assert!(
        matches!(taken, Ok(Some(_))),
        "no set is never refused: {taken:?}"
    );
}

/// A liveliness get limited to a link is refused by name, and no leg is minted for it.
#[cfg(feature = "liveliness-get")]
#[test]
fn a_limited_liveliness_get_is_refused_by_name() {
    use wz_capi_port::ReplyCallback;
    use wz_session_core::reply_sink::ReplyView;

    let router = Router::start(CatchAll::Held);
    let engine = open(&router);

    let mut legs = 0usize;
    assert_eq!(
        engine.liveliness_get_on_link_set(
            "demo/links/**",
            &WireKey::literal(),
            0,
            one_link(),
            None,
            &mut || -> ReplyCallback {
                legs += 1;
                Box::new(|_: &dyn ReplyView| {})
            }
        ),
        Err(Refusal::NotHonoured(StatementNotHonoured::Links))
    );
    assert_eq!(legs, 0, "no leg was minted for a limited liveliness get");
}
