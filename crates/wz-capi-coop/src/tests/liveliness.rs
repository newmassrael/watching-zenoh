// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The liveliness plane: the session's tokens reach the router and go when retracted or with
//! their link, and come back over a new one; its liveliness subscribers hear the router's tokens
//! appear and go, are told the ones alive when they ask for history, and hear the tokens of a lost
//! link go.

use std::sync::{Arc, Mutex};

use wz_capi_port::{LivelinessSink, SessionDrive, SessionEngine, SubId, WireKey};
use wz_session_core::declare::liveliness_sample::{LivelinessSample, LivelinessSampleKind};
use wz_session_core::declare_form::RetractionKey;

use super::{config, open, open_with, until, CatchAll, Command, Engine, Router};
use crate::CoopConfig;

/// What a liveliness subscriber heard: each sample as its kind and key.
type Heard = Arc<Mutex<Vec<(LivelinessSampleKind, String)>>>;

/// Subscribe to the tokens on `keyexpr`, with `history` as given: the subscriber's id and what it
/// hears.
fn subscribe(engine: &Engine, keyexpr: &str, history: bool) -> (SubId, Heard) {
    let heard: Heard = Arc::default();
    let into = heard.clone();
    let sink: LivelinessSink = Arc::new(move || {
        let into = into.clone();
        Box::new(move |sample: LivelinessSample<'_>| {
            into.lock()
                .unwrap()
                .push((sample.kind, sample.keyexpr.to_owned()));
        })
    });
    let id = engine
        .declare_liveliness_subscriber_on_wire(
            keyexpr.to_owned(),
            WireKey::literal(),
            history,
            sink,
        )
        .expect("the engine has liveliness");
    (id, heard)
}

fn put(key: &str) -> (LivelinessSampleKind, String) {
    (LivelinessSampleKind::Put, key.to_owned())
}

fn delete(key: &str) -> (LivelinessSampleKind, String) {
    (LivelinessSampleKind::Delete, key.to_owned())
}

/// A token reaches the router under the id the engine gave it, and goes when it is retracted,
/// with its retraction naming its key as zenoh-pico's does; a second token, retracted by id
/// alone, goes too.
#[test]
fn a_token_reaches_the_router_and_goes_when_retracted() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let named = engine
        .declare_liveliness_token_on_wire(
            "demo/alive/a".to_owned(),
            WireKey::literal(),
            Some(RetractionKey {
                mapping_id: 0,
                suffix: "demo/alive/a".to_owned(),
            }),
        )
        .expect("the engine has liveliness");
    let bare = engine
        .declare_liveliness_token_on_wire("demo/alive/b".to_owned(), WireKey::literal(), None)
        .expect("the engine has liveliness");
    until(&engine, "the router to hold both tokens", || {
        router.seen(|s| {
            s.tokens.contains(&(named, "demo/alive/a".to_owned()))
                && s.tokens.contains(&(bare, "demo/alive/b".to_owned()))
        })
    });

    engine.undeclare_liveliness_token(named);
    until(&engine, "the named retraction to reach the router", || {
        router.seen(|s| s.tokens == [(bare, "demo/alive/b".to_owned())])
    });
    engine.undeclare_liveliness_token(bare);
    until(&engine, "the bare retraction to reach the router", || {
        router.seen(|s| s.tokens.is_empty())
    });
    // Retracting one already retracted does nothing.
    engine.undeclare_liveliness_token(bare);
}

/// A liveliness subscriber hears the router's token appear and go, and only on its key; once it
/// is retracted it hears nothing more, while the CONTROL subscriber on another key hears nothing
/// at all.
#[test]
fn a_liveliness_subscriber_hears_the_routers_tokens_on_its_key() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let (id, heard) = subscribe(&engine, "demo/**", false);
    let (_, elsewhere) = subscribe(&engine, "other/**", false);
    until(&engine, "the router to see both Interests", || {
        router.seen(|s| s.interests >= 2)
    });

    router.send(Command::DeclareToken(1, "demo/t"));
    until(&engine, "the token to be heard", || {
        *heard.lock().unwrap() == [put("demo/t")]
    });
    router.send(Command::UndeclareToken(1));
    until(&engine, "its retraction to be heard", || {
        *heard.lock().unwrap() == [put("demo/t"), delete("demo/t")]
    });

    engine.undeclare_subscriber(id);
    router.send(Command::DeclareToken(2, "demo/u"));
    // The CONTROL's key never matches, so once this token has been dispatched, the retracted
    // subscriber's silence is not that nothing arrived: the session holds it as a peer token.
    router.send(Command::DeclareToken(3, "other/v"));
    until(&engine, "the CONTROL's token to be heard", || {
        *elsewhere.lock().unwrap() == [put("other/v")]
    });
    assert_eq!(
        heard.lock().unwrap().len(),
        2,
        "a retracted subscriber hears nothing"
    );
}

/// A subscriber that asks for history is told the tokens alive when it asked, which the router
/// only answers and never announced; one that does not ask is told none of them, by session-core's
/// rule, which is zenoh's (`dispatch_declare_historical`: pico keeps no history bit and would tell
/// it too).
#[test]
fn a_history_subscriber_is_told_the_tokens_alive_when_it_asked() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    router.send(Command::HoldToken(4, "demo/held"));
    until(&engine, "the router to hold its token", || {
        router.seen(|s| s.held == 1)
    });
    // The future-only subscriber is declared first, so the history one's answer comes after its
    // Interest reached the router.
    let (_, future) = subscribe(&engine, "demo/**", false);
    let (_, history) = subscribe(&engine, "demo/**", true);
    until(&engine, "the history subscriber to be told", || {
        *history.lock().unwrap() == [put("demo/held")]
    });
    assert!(
        future.lock().unwrap().is_empty(),
        "CONTROL: a subscriber that asked no history is told none"
    );
    // The same token, announced now, reaches both.
    router.send(Command::DeclareToken(5, "demo/new"));
    until(&engine, "the announced token to reach both", || {
        future.lock().unwrap().contains(&put("demo/new"))
            && history.lock().unwrap().contains(&put("demo/new"))
    });
}

/// A router that goes takes its tokens with it, and the subscriber hears each go; a router on the
/// same endpoint after it is told the session's token again and hears its subscriber's Interest,
/// so its token is heard too.
#[test]
fn a_lost_link_takes_the_routers_tokens_and_a_new_one_is_told_the_sessions() {
    let router = Router::start(CatchAll::None);
    let port = router.port;
    let engine = open_with(CoopConfig {
        redial_ms: Some(50),
        open_timeout_ms: 300,
        ..config(&router)
    });
    let (_, heard) = subscribe(&engine, "demo/**", false);
    let token = engine
        .declare_liveliness_token_on_wire("demo/mine".to_owned(), WireKey::literal(), None)
        .expect("the engine has liveliness");
    router.send(Command::DeclareToken(6, "demo/theirs"));
    until(&engine, "the router's token to be heard", || {
        *heard.lock().unwrap() == [put("demo/theirs")]
    });
    until(&engine, "the router to hold the session's token", || {
        router.seen(|s| s.tokens == [(token, "demo/mine".to_owned())])
    });

    router.send(Command::Close);
    drop(router);
    until(&engine, "the router's token to go with its link", || {
        *heard.lock().unwrap() == [put("demo/theirs"), delete("demo/theirs")]
    });

    let router = Router::start_on(port, CatchAll::None);
    until(
        &engine,
        "the new router to be told the session's token",
        || router.seen(|s| s.tokens == [(token, "demo/mine".to_owned())]),
    );
    until(
        &engine,
        "the subscriber's Interest to reach the new router",
        || router.seen(|s| s.interests >= 1),
    );
    router.send(Command::DeclareToken(7, "demo/again"));
    until(&engine, "the new router's token to be heard", || {
        heard.lock().unwrap().last() == Some(&put("demo/again"))
    });
    SessionDrive::close(&*engine);
}
