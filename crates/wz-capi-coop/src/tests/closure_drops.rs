// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Each callback the program hands a declaration is let go of exactly once: when the declaration is
//! undeclared, when the session closes, or, for a declaration refused, with the refusal itself. An
//! undeclaration after the close lets go of nothing more.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use wz_capi_port::{
    FilterPlane, MatchingSink, Refusal, SessionDrive, SessionEngine, SubscriberSink, WireKey,
};
use wz_session_core::limit_binding::Quota;
use wz_session_core::locality::Locality;
use wz_session_core::sink::SampleView;

use super::entity_tables::{lowered, open_under};
use super::{open, CatchAll, Router};

/// Counts its own drop.
struct Dropped(Arc<AtomicUsize>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// What became of the callbacks one test handed out: how many were let go of.
#[derive(Default)]
struct Counts {
    callbacks_dropped: Arc<AtomicUsize>,
}

impl Counts {
    fn callbacks_dropped(&self) -> usize {
        self.callbacks_dropped.load(Ordering::SeqCst)
    }

    /// A subscriber's callback, which counts its drop.
    fn subscriber_sink(&self) -> SubscriberSink {
        let guard = Dropped(self.callbacks_dropped.clone());
        SubscriberSink::shared(move |_sample: &dyn SampleView| {
            let _held = &guard;
        })
    }
}

fn declare(
    engine: &super::Engine,
    key: &str,
    sink: SubscriberSink,
) -> Result<wz_capi_port::SubId, Refusal> {
    engine.declare_subscriber_on_wire(key, WireKey::literal(), Locality::Any, None, sink)
}

/// Undeclared, a subscriber's callback is let go of once; a second undeclaration lets go of
/// nothing.
#[test]
fn a_subscribers_callback_is_dropped_once_on_undeclare() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let counts = Counts::default();
    let id = declare(&engine, "demo/drop/a", counts.subscriber_sink()).expect("declared");
    assert_eq!(counts.callbacks_dropped(), 0, "a declared callback is held");
    assert_eq!(engine.subscriber_rows(), 1, "the subscriber is one row");
    engine.undeclare_subscriber(id);
    assert_eq!(engine.subscriber_rows(), 0, "its row is taken out");
    assert_eq!(counts.callbacks_dropped(), 1);
    engine.undeclare_subscriber(id);
    assert_eq!(
        counts.callbacks_dropped(),
        1,
        "a second undeclaration drops nothing"
    );
}

/// The close lets go of every callback the session held, once; an undeclaration after it lets go
/// of nothing more.
#[test]
fn a_subscribers_callback_is_dropped_once_on_close() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let counts = Counts::default();
    let first = declare(&engine, "demo/drop/a", counts.subscriber_sink()).expect("declared");
    let second = declare(&engine, "demo/drop/b", counts.subscriber_sink()).expect("declared");
    assert_eq!(counts.callbacks_dropped(), 0, "both callbacks are held");
    SessionDrive::close(&*engine);
    assert_eq!(counts.callbacks_dropped(), 2);
    engine.undeclare_subscriber(first);
    engine.undeclare_subscriber(second);
    assert_eq!(
        counts.callbacks_dropped(),
        2,
        "nothing more after the close"
    );
}

/// The close lets go of every callback, whatever kind of declaration each was minted for: each is
/// held by its own row, and the close empties the rows.
#[test]
fn the_close_lets_go_of_every_rows_callback() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let counts = Counts::default();
    declare(&engine, "demo/drop/a", counts.subscriber_sink()).expect("declared");
    let sink: MatchingSink = Arc::new(|_matching: bool| {});
    let alive = Arc::downgrade(&sink);
    assert!(engine
        .declare_matching_listener(FilterPlane::Subscribers, "demo/drop/m", sink, false)
        .is_ok());
    assert_eq!(engine.subscriber_rows(), 1);
    assert!(
        alive.upgrade().is_some(),
        "the listener's row holds its sink"
    );
    SessionDrive::close(&*engine);
    assert_eq!(
        engine.subscriber_rows(),
        0,
        "the close emptied the subscribers' rows"
    );
    assert_eq!(counts.callbacks_dropped(), 1);
    assert!(
        alive.upgrade().is_none(),
        "the listener's sink is let go of"
    );
}

/// A declaration refused for want of a row lets go of its callback with the refusal, once.
#[test]
fn a_refused_subscribers_callback_is_dropped_once_with_the_refusal() {
    let limits = lowered(|l| l.select_max_subscriptions(Quota::at_most(1)));
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let held = Counts::default();
    declare(&engine, "demo/drop/a", held.subscriber_sink()).expect("a row is free");
    let refused = Counts::default();
    assert_eq!(
        declare(&engine, "demo/drop/b", refused.subscriber_sink()),
        Err(Refusal::TableFull)
    );
    assert_eq!(refused.callbacks_dropped(), 1, "let go of with the refusal");
    assert_eq!(
        held.callbacks_dropped(),
        0,
        "the declaration held is untouched"
    );
}

/// A matching listener's sink is let go of on its undeclaration, at the close, and with a
/// refusal, whether its table is full or its session closed: none of them outlives its end.
#[test]
fn a_matching_listeners_sink_is_let_go_of_on_each_end() {
    let limits = lowered(|l| l.select_max_matching_listeners(Quota::at_most(1)));
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let listen = |sink: MatchingSink| {
        engine.declare_matching_listener(FilterPlane::Subscribers, "demo/drop/m", sink, false)
    };

    let undeclared: MatchingSink = Arc::new(|_matching: bool| {});
    let undeclared_alive = Arc::downgrade(&undeclared);
    let id = listen(undeclared).expect("a row is free");
    assert!(
        undeclared_alive.upgrade().is_some(),
        "a declared sink is held"
    );
    engine.undeclare_matching_listener(id);
    assert!(
        undeclared_alive.upgrade().is_none(),
        "undeclared, it is let go of"
    );

    let held: MatchingSink = Arc::new(|_matching: bool| {});
    let held_alive = Arc::downgrade(&held);
    assert!(listen(held).is_ok());
    let refused: MatchingSink = Arc::new(|_matching: bool| {});
    let refused_alive = Arc::downgrade(&refused);
    assert_eq!(listen(refused), Err(Refusal::TableFull));
    assert!(
        refused_alive.upgrade().is_none(),
        "refused, it is let go of"
    );

    SessionDrive::close(&*engine);
    assert!(held_alive.upgrade().is_none(), "closed, it is let go of");

    let late: MatchingSink = Arc::new(|_matching: bool| {});
    let late_alive = Arc::downgrade(&late);
    assert_eq!(listen(late), Err(Refusal::Closed));
    assert!(
        late_alive.upgrade().is_none(),
        "refused by the closed session, it is let go of"
    );
}

/// A liveliness subscriber's callback is let go of once on its undeclaration and once at the
/// close, and a refused one with the refusal.
#[cfg(feature = "liveliness")]
#[test]
fn a_liveliness_subscribers_callback_is_dropped_once_on_each_end() {
    use wz_capi_port::LivelinessSink;
    use wz_session_core::declare::liveliness_sample::LivelinessSample;

    let limits = lowered(|l| l.select_max_liveliness_subscriptions(Quota::at_most(1)));
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let sink = |counts: &Counts| {
        let guard = Dropped(counts.callbacks_dropped.clone());
        LivelinessSink::shared(move |_sample: LivelinessSample<'_>| {
            let _held = &guard;
        })
    };
    let declare = |key: &str, counts: &Counts| {
        engine.declare_liveliness_subscriber_on_wire(key, WireKey::literal(), false, sink(counts))
    };

    let undeclared = Counts::default();
    let id = declare("demo/drop/l1", &undeclared).expect("a row is free");
    assert_eq!(undeclared.callbacks_dropped(), 0);
    engine.undeclare_subscriber(id);
    assert_eq!(undeclared.callbacks_dropped(), 1);

    let held = Counts::default();
    declare("demo/drop/l2", &held).expect("the row given back");
    let refused = Counts::default();
    assert_eq!(declare("demo/drop/l3", &refused), Err(Refusal::TableFull));
    assert_eq!(refused.callbacks_dropped(), 1, "let go of with the refusal");

    SessionDrive::close(&*engine);
    assert_eq!(held.callbacks_dropped(), 1);
    assert_eq!(
        undeclared.callbacks_dropped(),
        1,
        "nothing more after the close"
    );
}

/// A queryable's callback is let go of once on its undeclaration, once at the close, and a
/// refused one's at once.
#[cfg(feature = "queryable")]
#[test]
fn a_queryables_callback_is_dropped_once_on_each_end() {
    use wz_capi_port::{QueryHolder, QueryableSink};
    use wz_session_core::query_sink::{QueryView, ReplyOut};

    let limits = lowered(|l| l.select_max_queryables(Quota::at_most(1)));
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let sink = |counts: &Counts| -> QueryableSink {
        let guard = Dropped(counts.callbacks_dropped.clone());
        QueryableSink::shared(
            move |_query: &dyn QueryView, _out: &mut dyn ReplyOut, _holder: &dyn QueryHolder| {
                let _held = &guard;
            },
        )
    };
    let declare = |key: &str, counts: &Counts| {
        engine.declare_queryable_on_wire(
            key,
            WireKey::literal(),
            false,
            Locality::Remote,
            None,
            sink(counts),
        )
    };

    let undeclared = Counts::default();
    let id = declare("demo/drop/q1", &undeclared).expect("a row is free");
    engine.undeclare_queryable(id);
    assert_eq!(undeclared.callbacks_dropped(), 1);

    let held = Counts::default();
    declare("demo/drop/q2", &held).expect("the row given back");
    let refused = Counts::default();
    assert_eq!(declare("demo/drop/q3", &refused), Err(Refusal::TableFull));
    assert_eq!(
        refused.callbacks_dropped(),
        1,
        "a refusal lets its callback go at once"
    );

    SessionDrive::close(&*engine);
    assert_eq!(held.callbacks_dropped(), 1);
    assert_eq!(
        undeclared.callbacks_dropped(),
        1,
        "nothing more after the close"
    );
}

/// A queryable undeclared while a query owes it a call is handed nothing more, and its callback is
/// let go of once, after that call ended: two queryables on one key are reached by one query, and
/// whichever's callback runs first undeclares the other, whose call the query still owes. The
/// query's Final follows once both were done with it. The CONTROL is the first callback's reply,
/// which reaches the router before the Final.
#[cfg(feature = "queryable")]
#[test]
fn a_queryable_undeclared_while_a_query_owes_it_a_call_is_let_go_of_after_it() {
    use std::sync::Mutex;
    use wz_capi_port::{QblId, QueryHolder, QueryableSink};
    use wz_session_core::query_sink::{QueryView, ReplyOut};

    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let ids: Arc<Mutex<Option<[QblId; 2]>>> = Arc::default();
    let called = Arc::new(AtomicUsize::new(0));
    let counts = Counts::default();
    let sink = |me: usize| -> QueryableSink {
        let (ids, called, dropped) = (
            ids.clone(),
            called.clone(),
            counts.callbacks_dropped.clone(),
        );
        let undeclaring = engine.clone();
        let guard = Dropped(dropped);
        QueryableSink::shared(
            move |query: &dyn QueryView, out: &mut dyn ReplyOut, _holder: &dyn QueryHolder| {
                let _held = &guard;
                called.fetch_add(1, Ordering::SeqCst);
                let both = ids.lock().unwrap().take();
                if let Some(both) = both {
                    undeclaring.undeclare_queryable(both[1 - me]);
                }
                out.reply_keyed(query.keyexpr(), b"one")
                    .expect("a reply on the query's own key");
            },
        )
    };
    let declare = |me: usize| {
        engine
            .declare_queryable_on_wire(
                "demo/drop/owed",
                WireKey::literal(),
                false,
                Locality::Remote,
                None,
                sink(me),
            )
            .expect("a row is free")
    };
    let both = [declare(0), declare(1)];
    *ids.lock().unwrap() = Some(both);
    super::until(&engine, "the router to see both queryables", || {
        router.seen(|s| s.declares) >= 2
    });

    router.send(super::Command::Query(5, "demo/drop/owed"));
    super::until(&engine, "the reply and the final", || {
        router.seen(|s| s.answers.len()) >= 2
    });
    assert_eq!(
        router.seen(|s| s.answers.clone()),
        vec!["reply", "final"],
        "CONTROL: the first callback's reply, then the Final"
    );
    super::until(&engine, "the undeclared queryable's callback to go", || {
        counts.callbacks_dropped() >= 1
    });
    assert_eq!(
        called.load(Ordering::SeqCst),
        1,
        "the undeclared queryable is handed nothing of the query it was owed"
    );
    assert_eq!(
        counts.callbacks_dropped(),
        1,
        "the undeclared queryable's callback is let go of once, the other's is held"
    );
    SessionDrive::close(&*engine);
    assert_eq!(
        counts.callbacks_dropped(),
        2,
        "the queryable still declared is let go of with the close"
    );
}

/// A liveliness subscriber undeclared while a token's delivery owes it a call is handed nothing
/// more, and its callback is let go of once, after that call ended: two subscribers on one key are
/// owed one token's appearance, and whichever's callback runs first undeclares the other. The
/// CONTROL is the first callback, which is handed the token.
#[cfg(feature = "liveliness")]
#[test]
fn a_liveliness_subscriber_undeclared_while_a_token_owes_it_a_call_is_let_go_of_after_it() {
    use std::sync::Mutex;
    use wz_capi_port::{LivelinessSink, SubId};
    use wz_session_core::declare::liveliness_sample::LivelinessSample;

    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let ids: Arc<Mutex<Option<[SubId; 2]>>> = Arc::default();
    let called = Arc::new(AtomicUsize::new(0));
    let counts = Counts::default();
    let sink = |me: usize| -> LivelinessSink {
        let (ids, called) = (ids.clone(), called.clone());
        let guard = Dropped(counts.callbacks_dropped.clone());
        let undeclaring = engine.clone();
        LivelinessSink::shared(move |_sample: LivelinessSample<'_>| {
            let _held = &guard;
            called.fetch_add(1, Ordering::SeqCst);
            let both = ids.lock().unwrap().take();
            if let Some(both) = both {
                undeclaring.undeclare_subscriber(both[1 - me]);
            }
        })
    };
    let declare = |me: usize| {
        engine
            .declare_liveliness_subscriber_on_wire(
                "demo/drop/**",
                WireKey::literal(),
                false,
                sink(me),
            )
            .expect("a row is free")
    };
    let both = [declare(0), declare(1)];
    *ids.lock().unwrap() = Some(both);
    super::until(&engine, "the router to see both Interests", || {
        router.seen(|s| s.interests) >= 2
    });

    router.send(super::Command::DeclareToken(1, "demo/drop/t"));
    super::until(
        &engine,
        "the undeclared subscriber's callback to go",
        || counts.callbacks_dropped() >= 1,
    );
    assert_eq!(
        called.load(Ordering::SeqCst),
        1,
        "CONTROL: the first callback is handed the token, the undeclared one nothing"
    );
    assert_eq!(
        counts.callbacks_dropped(),
        1,
        "the undeclared subscriber's callback is let go of once, the other's is held"
    );
    SessionDrive::close(&*engine);
    assert_eq!(
        counts.callbacks_dropped(),
        2,
        "the subscriber still declared is let go of with the close"
    );
}
