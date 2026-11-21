// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The declaration watch against the router stand-in: what the router declares and retracts is
//! told to the watches of its kind, what it held before a watch came is told to that watch first,
//! and a watch undeclared or a session closed lets go of its sink. A build with neither
//! `remote-declaration-watch` nor `declarations-synced-event` refuses a watch by name rather than
//! taking it and never telling it anything.

use std::sync::Arc;

use wz_capi_port::{DeclPlane, DeclWatchEvent, DeclWatchRefused, DeclWatchSink, SessionEngine};

use super::{open, CatchAll, Router};

#[cfg(not(any(
    feature = "remote-declaration-watch",
    feature = "declarations-synced-event"
)))]
#[test]
fn a_declaration_watch_is_refused_by_name_and_holds_nothing() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);
    let sink: DeclWatchSink = Arc::new(|_: DeclWatchEvent<'_>| {});

    for plane in [
        DeclPlane::Subscribers,
        DeclPlane::Queryables,
        DeclPlane::Tokens,
    ] {
        assert_eq!(
            engine.declare_decl_watch(plane, Arc::clone(&sink)),
            Err(DeclWatchRefused::NotProvided),
            "{plane:?}"
        );
    }
    assert_eq!(
        Arc::strong_count(&sink),
        1,
        "the engine kept no sink of a watch it refused"
    );
    assert!(
        !engine.undeclare_decl_watch(1),
        "no watch is held to undeclare"
    );
}

#[cfg(any(
    feature = "remote-declaration-watch",
    feature = "declarations-synced-event"
))]
mod watched {
    use std::sync::Mutex;

    use wz_capi_port::SessionDrive;

    use super::super::{until, Command, Engine, ROUTER_ZID};
    use super::*;

    /// One event as a watch was told it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Seen {
        Declared(u64, String),
        Undeclared(u64),
        Synced,
    }

    /// Each event a watch was told, with the peer it named.
    type Heard = Arc<Mutex<Vec<(Seen, Option<Vec<u8>>)>>>;

    /// A watch's sink and what it was told, with the peer each event named.
    struct Log {
        sink: DeclWatchSink,
        seen: Heard,
    }

    impl Log {
        fn new() -> Self {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let into = Arc::clone(&seen);
            let sink: DeclWatchSink = Arc::new(move |event: DeclWatchEvent<'_>| {
                let what = match event {
                    DeclWatchEvent::Declared { id, keyexpr, .. } => {
                        Seen::Declared(id, keyexpr.to_owned())
                    }
                    DeclWatchEvent::Undeclared { id, .. } => Seen::Undeclared(id),
                    DeclWatchEvent::Synced { .. } => Seen::Synced,
                };
                into.lock()
                    .unwrap()
                    .push((what, event.peer().map(<[u8]>::to_vec)));
            });
            Self { sink, seen }
        }

        fn events(&self) -> Vec<Seen> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .map(|(what, _)| what.clone())
                .collect()
        }

        fn peers(&self) -> Vec<Option<Vec<u8>>> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .map(|(_, peer)| peer.clone())
                .collect()
        }

        fn has(&self, what: &Seen) -> bool {
            self.events().contains(what)
        }
    }

    /// The peer every event names: the router's zid with `remote-declaration-watch`, no one
    /// without it.
    fn router_peer() -> Option<Vec<u8>> {
        cfg!(feature = "remote-declaration-watch").then(|| vec![ROUTER_ZID; 4])
    }

    fn watch(engine: &Engine, plane: DeclPlane, log: &Log) -> u64 {
        engine
            .declare_decl_watch(plane, Arc::clone(&log.sink))
            .expect("a watch of a kind this build hears")
    }

    /// Step the session a while, for a CONTROL that waits for something that must not come.
    fn settle(engine: &Engine) {
        let quiet = std::time::Instant::now() + std::time::Duration::from_millis(300);
        while std::time::Instant::now() < quiet {
            let _ = SessionDrive::read(engine, false);
        }
    }

    /// A watch of queryables is told the router's queryable live, with the router as its peer; a
    /// second watch declared after is told it first, from what the router holds; both are told the
    /// next one and its retraction; a watch of subscribers is told none of it.
    #[test]
    fn a_watch_is_told_what_the_peer_held_then_declares_and_retracts_of_its_kind() {
        let router = Router::start(CatchAll::None);
        let engine = open(&router);
        let early = Log::new();
        let subscribers = Log::new();
        watch(&engine, DeclPlane::Queryables, &early);
        watch(&engine, DeclPlane::Subscribers, &subscribers);

        router.send(Command::DeclareQueryable(5, "demo/w/held", false));
        let held = Seen::Declared(5, "demo/w/held".to_owned());
        until(&engine, "the live declaration", || early.has(&held));

        let late = Log::new();
        watch(&engine, DeclPlane::Queryables, &late);
        until(&engine, "the held declaration", || late.has(&held));

        router.send(Command::DeclareQueryable(6, "demo/w/live", false));
        let live = Seen::Declared(6, "demo/w/live".to_owned());
        until(&engine, "the second declaration", || {
            early.has(&live) && late.has(&live)
        });
        router.send(Command::UndeclareQueryable(5));
        until(&engine, "the retraction", || {
            early.has(&Seen::Undeclared(5)) && late.has(&Seen::Undeclared(5))
        });

        assert_eq!(
            early.events(),
            [held.clone(), live.clone(), Seen::Undeclared(5)],
            "each declaration is told once, in the order the router made them"
        );
        assert_eq!(late.events(), [held, live, Seen::Undeclared(5)]);
        assert!(
            early.peers().iter().all(|peer| *peer == router_peer()),
            "{:?}",
            early.peers()
        );
        assert!(late.peers().iter().all(|peer| *peer == router_peer()));
        assert!(
            subscribers.events().is_empty(),
            "a watch of subscribers hears no queryable"
        );
    }

    /// An undeclared watch is told nothing more and the engine lets go of its sink; a second
    /// undeclare finds none. The CONTROL is a watch kept beside it, which is told the declaration
    /// the undeclared one is not.
    #[test]
    fn an_undeclared_watch_is_told_nothing_more_and_its_sink_is_let_go_of() {
        let router = Router::start(CatchAll::None);
        let engine = open(&router);
        let gone = Log::new();
        let kept = Log::new();
        let id = watch(&engine, DeclPlane::Subscribers, &gone);
        watch(&engine, DeclPlane::Subscribers, &kept);
        assert!(engine.undeclare_decl_watch(id));
        assert_eq!(Arc::strong_count(&gone.sink), 1, "the engine let go of it");
        assert!(!engine.undeclare_decl_watch(id), "undeclared once only");

        router.send(Command::DeclareSubscriber(3, "demo/w/sub"));
        let declared = Seen::Declared(3, "demo/w/sub".to_owned());
        until(&engine, "CONTROL: the kept watch's event", || {
            kept.has(&declared)
        });
        settle(&engine);
        assert!(gone.events().is_empty());
    }

    /// A close lets go of every watch's sink, and a closed session refuses a watch by name.
    #[test]
    fn a_close_lets_go_of_every_watch_and_refuses_the_next() {
        let router = Router::start(CatchAll::None);
        let engine = open(&router);
        let log = Log::new();
        watch(&engine, DeclPlane::Queryables, &log);
        SessionDrive::close(&*engine);
        assert_eq!(Arc::strong_count(&log.sink), 1);
        assert_eq!(
            engine.declare_decl_watch(DeclPlane::Queryables, Arc::clone(&log.sink)),
            Err(DeclWatchRefused::SessionClosed)
        );
        assert_eq!(
            Arc::strong_count(&log.sink),
            1,
            "a refused sink is not kept"
        );
    }

    /// A watch of tokens is told the router's token and its retraction, and a watch of queryables
    /// is told neither. A build without the liveliness plane refuses a watch of tokens by name.
    #[cfg(feature = "liveliness")]
    #[test]
    fn a_watch_of_tokens_is_told_the_peers_tokens_alone() {
        let router = Router::start(CatchAll::None);
        let engine = open(&router);
        let tokens = Log::new();
        let queryables = Log::new();
        watch(&engine, DeclPlane::Tokens, &tokens);
        watch(&engine, DeclPlane::Queryables, &queryables);
        router.send(Command::DeclareToken(11, "demo/w/alive"));
        until(&engine, "the token", || {
            tokens.has(&Seen::Declared(11, "demo/w/alive".to_owned()))
        });
        router.send(Command::UndeclareToken(11));
        until(&engine, "the token's retraction", || {
            tokens.has(&Seen::Undeclared(11))
        });
        assert!(queryables.events().is_empty());
    }

    #[cfg(not(feature = "liveliness"))]
    #[test]
    fn a_build_without_liveliness_refuses_a_watch_of_tokens() {
        let router = Router::start(CatchAll::None);
        let engine = open(&router);
        let log = Log::new();
        assert_eq!(
            engine.declare_decl_watch(DeclPlane::Tokens, Arc::clone(&log.sink)),
            Err(DeclWatchRefused::PlaneNotBuilt)
        );
        assert_eq!(Arc::strong_count(&log.sink), 1);
    }

    /// The router's final of the initial declarations is told once to every watch, whatever its
    /// kind; a second final is not told again, and without `declarations-synced-event` none is.
    #[test]
    fn the_end_of_the_initial_declarations_is_told_once_to_every_watch() {
        let router = Router::start(CatchAll::None);
        let engine = open(&router);
        let subscribers = Log::new();
        let queryables = Log::new();
        watch(&engine, DeclPlane::Subscribers, &subscribers);
        watch(&engine, DeclPlane::Queryables, &queryables);
        router.send(Command::FinishInitial);
        router.send(Command::FinishInitial);
        // A declaration after both finals marks where the router's sends have arrived.
        router.send(Command::DeclareSubscriber(4, "demo/w/after"));
        let after = Seen::Declared(4, "demo/w/after".to_owned());
        until(&engine, "the declaration after the finals", || {
            subscribers.has(&after)
        });
        settle(&engine);
        let synced = usize::from(cfg!(feature = "declarations-synced-event"));
        for log in [&subscribers, &queryables] {
            assert_eq!(
                log.events()
                    .iter()
                    .filter(|seen| **seen == Seen::Synced)
                    .count(),
                synced,
                "{:?}",
                log.events()
            );
        }
    }
}
