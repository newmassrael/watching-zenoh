// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The declaration watch against the router stand-in: what the router declares and retracts is
//! told to the watches of its kind, what it held before a watch came is told to that watch first,
//! and a watch undeclared or a session closed lets go of its sink. A build with neither
//! `remote-declaration-watch` nor `declarations-synced-event` refuses a watch by name rather than
//! taking it and never telling it anything.

use std::sync::Arc;

use wz_capi_port::{DeclPlane, DeclWatchEvent, DeclWatchSink, Refusal, SessionEngine};

use super::{open, CatchAll, Router};

/// A Rust closure a watch's sink shares, so a test reads from its count whether the engine still
/// holds the sink.
type SharedCall = Arc<dyn Fn(DeclWatchEvent<'_>) + Send + Sync>;

#[cfg(not(any(
    feature = "remote-declaration-watch",
    feature = "declarations-synced-event"
)))]
#[test]
fn a_declaration_watch_is_refused_by_name_and_holds_nothing() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);
    let sink: SharedCall = Arc::new(|_: DeclWatchEvent<'_>| {});

    for plane in [
        DeclPlane::Subscribers,
        DeclPlane::Queryables,
        DeclPlane::Tokens,
    ] {
        assert_eq!(
            engine.declare_decl_watch(plane, DeclWatchSink::Shared(Arc::clone(&sink))),
            Err(Refusal::NotBuilt),
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
        Lost(u64),
    }

    /// Each event a watch was told, with the peer it named.
    type Heard = Arc<Mutex<Vec<(Seen, Option<Vec<u8>>)>>>;

    /// A watch's sink and what it was told, with the peer each event named.
    struct Log {
        sink: SharedCall,
        seen: Heard,
    }

    impl Log {
        fn new() -> Self {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let into = Arc::clone(&seen);
            let sink: SharedCall = Arc::new(move |event: DeclWatchEvent<'_>| {
                let what = match event {
                    DeclWatchEvent::Declared { id, keyexpr, .. } => {
                        Seen::Declared(id, keyexpr.to_owned())
                    }
                    DeclWatchEvent::Undeclared { id, .. } => Seen::Undeclared(id),
                    DeclWatchEvent::Synced { .. } => Seen::Synced,
                    DeclWatchEvent::Lost { count } => Seen::Lost(count),
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
            .declare_decl_watch(plane, DeclWatchSink::Shared(Arc::clone(&log.sink)))
            .expect("a watch of a kind this build hears")
    }

    /// Step the session a while, for a CONTROL that waits for something that must not come.
    fn settle(engine: &Engine) {
        let quiet = std::time::Instant::now() + std::time::Duration::from_millis(300);
        while std::time::Instant::now() < quiet {
            let _ = SessionDrive::read(engine, false);
        }
    }

    /// A catch-up longer than a round of one thread holds is told whole, in the order the peer's
    /// table hands it, with nothing lost, and a sample its link brought before the watch came is
    /// handed after it: the link is read no further while the catch-up is owed. A round of threads
    /// takes it at once. Turned red by a catch-up a round too small for it tells as a loss, or one a
    /// sample overtakes.
    #[test]
    fn a_catch_up_longer_than_a_round_is_told_whole_and_in_order_before_what_follows() {
        use wz_capi_port::{SubscriberSink, WireKey};
        use wz_session_core::locality::Locality;
        use wz_session_core::round::ONE_THREAD_RECORDS;
        use wz_session_core::sink::SampleView;

        const KEYS: [&str; 4] = ["demo/w/a", "demo/w/b", "demo/w/c", "demo/w/d"];
        const _: () = assert!(KEYS.len() > ONE_THREAD_RECORDS);
        let router = Router::start(CatchAll::None);
        let engine = open(&router);
        let order: Arc<Mutex<Vec<String>>> = Arc::default();
        let into = Arc::clone(&order);
        engine
            .declare_subscriber_on_wire(
                "demo/w/push",
                WireKey::literal(),
                Locality::Any,
                None,
                SubscriberSink::shared(move |_: &dyn SampleView| {
                    into.lock().unwrap().push("sample".to_owned());
                }),
            )
            .expect("the session declares the subscriber");
        let early = Log::new();
        watch(&engine, DeclPlane::Subscribers, &early);
        for (id, key) in (1..).zip(KEYS) {
            router.send(Command::DeclareSubscriber(id, key));
        }
        let last = Seen::Declared(4, "demo/w/d".to_owned());
        until(&engine, "the router's declarations", || early.has(&last));

        // Read by nothing until the late watch is declared, the sample waits in the link.
        router.send(Command::Push("demo/w/push", b"p"));
        std::thread::sleep(std::time::Duration::from_millis(200));
        let into = Arc::clone(&order);
        let late: SharedCall = Arc::new(move |event: DeclWatchEvent<'_>| {
            let what = match event {
                DeclWatchEvent::Declared { id, keyexpr, .. } => format!("declared {id} {keyexpr}"),
                DeclWatchEvent::Lost { count } => format!("lost {count}"),
                _ => "other".to_owned(),
            };
            into.lock().unwrap().push(what);
        });
        engine
            .declare_decl_watch(DeclPlane::Subscribers, DeclWatchSink::Shared(late))
            .expect("a watch of a kind this build hears");
        until(&engine, "the sample", || {
            order.lock().unwrap().iter().any(|seen| seen == "sample")
        });
        let mut told: Vec<String> = (1..)
            .zip(KEYS)
            .map(|(id, key): (u64, &str)| format!("declared {id} {key}"))
            .collect();
        told.push("sample".to_owned());
        assert_eq!(
            *order.lock().unwrap(),
            told,
            "every declaration once, in order, none lost, and the sample after them"
        );
    }

    /// A watch of queryables is told the router's queryable live, with the router as its peer; a
    /// second watch declared after is told it first, from what the router holds; both are told the
    /// next one and its retraction; a watch of subscribers is told none of it.
    #[cfg(any(feature = "query", feature = "queryable"))]
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
        assert!(
            kept.peers().iter().all(|peer| *peer == router_peer()),
            "{:?}",
            kept.peers()
        );
    }

    /// A close lets go of every watch's sink, and a closed session refuses a watch by name.
    #[test]
    fn a_close_lets_go_of_every_watch_and_refuses_the_next() {
        let router = Router::start(CatchAll::None);
        let engine = open(&router);
        let log = Log::new();
        watch(&engine, DeclPlane::Subscribers, &log);
        SessionDrive::close(&*engine);
        assert_eq!(Arc::strong_count(&log.sink), 1);
        assert_eq!(
            engine.declare_decl_watch(
                DeclPlane::Subscribers,
                DeclWatchSink::Shared(Arc::clone(&log.sink))
            ),
            Err(Refusal::Closed)
        );
        assert_eq!(
            Arc::strong_count(&log.sink),
            1,
            "a refused sink is not kept"
        );
    }

    /// A watch of tokens is told the router's token and its retraction, and a watch of subscribers
    /// is told neither. A build without the liveliness plane refuses a watch of tokens by name.
    #[cfg(feature = "liveliness")]
    #[test]
    fn a_watch_of_tokens_is_told_the_peers_tokens_alone() {
        let router = Router::start(CatchAll::None);
        let engine = open(&router);
        let tokens = Log::new();
        let subscribers = Log::new();
        watch(&engine, DeclPlane::Tokens, &tokens);
        watch(&engine, DeclPlane::Subscribers, &subscribers);
        router.send(Command::DeclareToken(11, "demo/w/alive"));
        until(&engine, "the token", || {
            tokens.has(&Seen::Declared(11, "demo/w/alive".to_owned()))
        });
        router.send(Command::UndeclareToken(11));
        until(&engine, "the token's retraction", || {
            tokens.has(&Seen::Undeclared(11))
        });
        assert!(subscribers.events().is_empty());
    }

    /// A build without a querier or a queryable holds no table of the queryables a peer declares,
    /// so it refuses a watch of them by name and keeps no sink of it.
    #[cfg(not(any(feature = "query", feature = "queryable")))]
    #[test]
    fn a_build_without_the_queryables_plane_refuses_a_watch_of_queryables() {
        let router = Router::start(CatchAll::None);
        let engine = open(&router);
        let log = Log::new();
        assert_eq!(
            engine.declare_decl_watch(
                DeclPlane::Queryables,
                DeclWatchSink::Shared(Arc::clone(&log.sink))
            ),
            Err(Refusal::NotBuilt)
        );
        assert_eq!(Arc::strong_count(&log.sink), 1);
    }

    #[cfg(not(feature = "liveliness"))]
    #[test]
    fn a_build_without_liveliness_refuses_a_watch_of_tokens() {
        let router = Router::start(CatchAll::None);
        let engine = open(&router);
        let log = Log::new();
        assert_eq!(
            engine.declare_decl_watch(
                DeclPlane::Tokens,
                DeclWatchSink::Shared(Arc::clone(&log.sink))
            ),
            Err(Refusal::NotBuilt)
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
        let other = Log::new();
        watch(&engine, DeclPlane::Subscribers, &subscribers);
        // A watch of another kind where the build hears one, of the same kind where it does not.
        let other_plane = if cfg!(any(feature = "query", feature = "queryable")) {
            DeclPlane::Queryables
        } else {
            DeclPlane::Subscribers
        };
        watch(&engine, other_plane, &other);
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
        for log in [&subscribers, &other] {
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

    /// A watch declared from inside another watch's call, while the round is handed out, is
    /// declared, not refused, and told what the peer held by the next round.
    #[cfg(any(feature = "query", feature = "queryable"))]
    #[test]
    fn a_watch_declared_inside_a_call_is_told_what_the_peer_held_by_the_next_round() {
        use crate::EngineHold;

        let router = Router::start(CatchAll::None);
        let engine = open(&router);
        let first = Log::new();
        watch(&engine, DeclPlane::Queryables, &first);
        router.send(Command::DeclareQueryable(5, "demo/w/held", false));
        let held = Seen::Declared(5, "demo/w/held".to_owned());
        until(&engine, "CONTROL: the live declaration", || {
            first.has(&held)
        });

        let late = Arc::new(Log::new());
        let declared_inside: Arc<Mutex<Option<Result<u64, Refusal>>>> = Arc::default();
        let trigger: SharedCall = {
            let session = EngineHold::downgrade(&engine);
            let late = Arc::clone(&late);
            let into = Arc::clone(&declared_inside);
            Arc::new(move |event: DeclWatchEvent<'_>| {
                if !matches!(event, DeclWatchEvent::Declared { .. }) {
                    return;
                }
                let Some(engine) = session.upgrade() else {
                    return;
                };
                let mut slot = into.lock().unwrap();
                if slot.is_none() {
                    *slot = Some(engine.declare_decl_watch(
                        DeclPlane::Queryables,
                        DeclWatchSink::Shared(Arc::clone(&late.sink)),
                    ));
                }
            })
        };
        engine
            .declare_decl_watch(DeclPlane::Subscribers, DeclWatchSink::Shared(trigger))
            .expect("a watch of subscribers");
        router.send(Command::DeclareSubscriber(3, "demo/w/trigger"));
        until(
            &engine,
            "the held declaration, told to the inner watch",
            || late.has(&held),
        );
        assert!(
            matches!(*declared_inside.lock().unwrap(), Some(Ok(_))),
            "declared from inside the call, not refused"
        );
        assert_eq!(late.events(), [held]);
    }

    /// What a peer declares is told in the order it arrived among the session's other deliveries:
    /// a declaration ahead of the sample the peer sent after it, as records of one round.
    #[test]
    fn a_declaration_is_told_ahead_of_the_sample_sent_after_it() {
        use wz_capi_port::{SubscriberSink, WireKey};
        use wz_session_core::locality::Locality;
        use wz_session_core::sink::SampleView;

        let router = Router::start(CatchAll::None);
        let engine = open(&router);
        let order: Arc<Mutex<Vec<&'static str>>> = Arc::default();
        let watched: SharedCall = {
            let order = Arc::clone(&order);
            Arc::new(move |event: DeclWatchEvent<'_>| {
                if matches!(event, DeclWatchEvent::Declared { .. }) {
                    order.lock().unwrap().push("declared");
                }
            })
        };
        engine
            .declare_decl_watch(DeclPlane::Subscribers, DeclWatchSink::Shared(watched))
            .expect("a watch of subscribers");
        engine
            .declare_subscriber_on_wire("demo/**", WireKey::literal(), Locality::Any, None, {
                let order = Arc::clone(&order);
                SubscriberSink::shared(move |_sample: &dyn SampleView| {
                    order.lock().unwrap().push("sample");
                })
            })
            .expect("declared");
        router.send(Command::DeclareSubscriber(3, "demo/w/order"));
        router.send(Command::Push("demo/w/order", b"x"));
        until(&engine, "the declaration and the sample", || {
            order.lock().unwrap().len() >= 2
        });
        assert_eq!(*order.lock().unwrap(), ["declared", "sample"]);
    }

    /// A watch's sink is called with the session let go of: it undeclares its own watch from inside
    /// its call, is told nothing more, and its sink is let go of as the call returns. The CONTROL
    /// is a watch kept beside it, which is told the declaration the undeclared one is not. Turned
    /// red by a call made with the session held, which the undeclare inside it waits on.
    #[test]
    fn a_watch_undeclared_from_inside_its_call_is_told_nothing_more() {
        use crate::EngineHold;

        let router = Router::start(CatchAll::None);
        let engine = open(&router);
        let kept = Log::new();
        watch(&engine, DeclPlane::Subscribers, &kept);
        let own: Arc<Mutex<Option<u64>>> = Arc::default();
        let undeclared: Arc<Mutex<Vec<bool>>> = Arc::default();
        let told: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let sink: SharedCall = {
            let session = EngineHold::downgrade(&engine);
            let own = Arc::clone(&own);
            let undeclared = Arc::clone(&undeclared);
            let told = Arc::clone(&told);
            Arc::new(move |event: DeclWatchEvent<'_>| {
                let DeclWatchEvent::Declared { id, keyexpr, .. } = event else {
                    return;
                };
                told.lock()
                    .unwrap()
                    .push(Seen::Declared(id, keyexpr.to_owned()));
                let Some(engine) = session.upgrade() else {
                    return;
                };
                if let Some(own) = own.lock().unwrap().take() {
                    undeclared
                        .lock()
                        .unwrap()
                        .push(engine.undeclare_decl_watch(own));
                }
            })
        };
        let id = engine
            .declare_decl_watch(
                DeclPlane::Subscribers,
                DeclWatchSink::Shared(Arc::clone(&sink)),
            )
            .expect("a watch of subscribers");
        *own.lock().unwrap() = Some(id);

        router.send(Command::DeclareSubscriber(3, "demo/w/first"));
        until(&engine, "the undeclare from inside the call", || {
            !undeclared.lock().unwrap().is_empty()
        });
        router.send(Command::DeclareSubscriber(4, "demo/w/second"));
        let second = Seen::Declared(4, "demo/w/second".to_owned());
        until(&engine, "CONTROL: the kept watch's second event", || {
            kept.has(&second)
        });
        settle(&engine);
        assert_eq!(*undeclared.lock().unwrap(), [true]);
        assert_eq!(
            *told.lock().unwrap(),
            [Seen::Declared(3, "demo/w/first".to_owned())],
            "told nothing after its undeclare"
        );
        assert_eq!(Arc::strong_count(&sink), 1, "the engine let go of the sink");
    }
}
