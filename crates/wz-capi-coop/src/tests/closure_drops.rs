// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Each callback the program hands a declaration is let go of exactly once: when the declaration is
//! undeclared, when the session closes, or, for a declaration refused, with the refusal itself and
//! never minted. An undeclaration after the close lets go of nothing more.

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

/// What became of the callbacks one test handed out: how many were minted, how many of them were
/// let go of, and how many of the factories that mint them were.
#[derive(Default)]
struct Counts {
    minted: Arc<AtomicUsize>,
    callbacks_dropped: Arc<AtomicUsize>,
    factories_dropped: Arc<AtomicUsize>,
}

impl Counts {
    fn minted(&self) -> usize {
        self.minted.load(Ordering::SeqCst)
    }

    fn callbacks_dropped(&self) -> usize {
        self.callbacks_dropped.load(Ordering::SeqCst)
    }

    fn factories_dropped(&self) -> usize {
        self.factories_dropped.load(Ordering::SeqCst)
    }

    /// A subscriber's sink whose factory and every callback it mints count their drop.
    fn subscriber_sink(&self) -> SubscriberSink {
        let minted = self.minted.clone();
        let dropped = self.callbacks_dropped.clone();
        let factory = Dropped(self.factories_dropped.clone());
        Arc::new(move || {
            let _held = &factory;
            minted.fetch_add(1, Ordering::SeqCst);
            let guard = Dropped(dropped.clone());
            Box::new(move |_sample: &dyn SampleView| {
                let _held = &guard;
            }) as Box<dyn FnMut(&dyn SampleView) + Send>
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

/// Undeclared, a subscriber's callback is let go of once, and its factory once; a second
/// undeclaration lets go of nothing.
#[test]
fn a_subscribers_callback_is_dropped_once_on_undeclare() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let counts = Counts::default();
    let id = declare(&engine, "demo/drop/a", counts.subscriber_sink()).expect("declared");
    assert_eq!(counts.minted(), 1);
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
    assert_eq!(counts.factories_dropped(), 1);
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
    assert_eq!(counts.minted(), 2);
    SessionDrive::close(&*engine);
    assert_eq!(counts.callbacks_dropped(), 2);
    engine.undeclare_subscriber(first);
    engine.undeclare_subscriber(second);
    assert_eq!(
        counts.callbacks_dropped(),
        2,
        "nothing more after the close"
    );
    assert_eq!(counts.factories_dropped(), 2);
}

/// The close takes the whole table of callbacks at once: after it the table holds none, whatever
/// kind of declaration each was minted for, and each is let go of.
#[test]
fn the_close_leaves_no_callback_in_the_table() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let counts = Counts::default();
    declare(&engine, "demo/drop/a", counts.subscriber_sink()).expect("declared");
    let sink: MatchingSink = Arc::new(|_matching: bool| {});
    let alive = Arc::downgrade(&sink);
    assert!(engine
        .declare_matching_listener(FilterPlane::Subscribers, "demo/drop/m", sink, false)
        .is_ok());
    assert_eq!(engine.callbacks_held(), 2, "one for each declaration");
    assert_eq!(engine.subscriber_rows(), 1);
    SessionDrive::close(&*engine);
    assert_eq!(engine.callbacks_held(), 0, "the close took the table whole");
    assert_eq!(engine.subscriber_rows(), 0, "and the subscribers' rows");
    assert_eq!(counts.callbacks_dropped(), 1);
    assert!(
        alive.upgrade().is_none(),
        "the listener's sink is let go of"
    );
}

/// A declaration refused for want of a row mints no callback, and its factory is let go of with
/// the refusal, once.
#[test]
fn a_refused_subscribers_factory_is_dropped_once_and_mints_nothing() {
    let limits = lowered(|l| l.select_max_subscriptions(Quota::at_most(1)));
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let held = Counts::default();
    declare(&engine, "demo/drop/a", held.subscriber_sink()).expect("a row is free");
    let refused = Counts::default();
    assert_eq!(
        declare(&engine, "demo/drop/b", refused.subscriber_sink()),
        None
    );
    assert_eq!(refused.minted(), 0, "no callback for a refusal");
    assert_eq!(refused.callbacks_dropped(), 0);
    assert_eq!(refused.factories_dropped(), 1);
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
/// close, and a refused one mints none.
#[cfg(feature = "liveliness")]
#[test]
fn a_liveliness_subscribers_callback_is_dropped_once_on_each_end() {
    use wz_capi_port::LivelinessSink;
    use wz_session_core::declare::liveliness_sample::LivelinessSample;

    let limits = lowered(|l| l.select_max_liveliness_subscriptions(Quota::at_most(1)));
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let sink = |counts: &Counts| -> LivelinessSink {
        let minted = counts.minted.clone();
        let dropped = counts.callbacks_dropped.clone();
        Arc::new(move || {
            minted.fetch_add(1, Ordering::SeqCst);
            let guard = Dropped(dropped.clone());
            Box::new(move |_sample: LivelinessSample<'_>| {
                let _held = &guard;
            }) as Box<dyn for<'a> FnMut(LivelinessSample<'a>) + Send>
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
    assert_eq!(refused.minted(), 0, "no callback for a refusal");

    SessionDrive::close(&*engine);
    assert_eq!(held.callbacks_dropped(), 1);
    assert_eq!(
        undeclared.callbacks_dropped(),
        1,
        "nothing more after the close"
    );
}

/// A queryable's callback is let go of once on its undeclaration, once at the close, and a
/// refused one mints none.
#[cfg(feature = "queryable")]
#[test]
fn a_queryables_callback_is_dropped_once_on_each_end() {
    use wz_capi_port::{QueryCallback, QueryHolder, QueryableSink};
    use wz_session_core::query_sink::{QueryView, ReplyOut};

    let limits = lowered(|l| l.select_max_queryables(Quota::at_most(1)));
    let router = Router::start(CatchAll::None);
    let engine = open_under(&router, limits);
    let sink = |counts: &Counts| -> QueryableSink {
        let minted = counts.minted.clone();
        let dropped = counts.callbacks_dropped.clone();
        Arc::new(move |_holder: Arc<dyn QueryHolder>| {
            minted.fetch_add(1, Ordering::SeqCst);
            let guard = Dropped(dropped.clone());
            Box::new(move |_query: &dyn QueryView, _out: &mut dyn ReplyOut| {
                let _held = &guard;
            }) as QueryCallback
        })
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
    assert_eq!(refused.minted(), 0, "no callback for a refusal");

    SessionDrive::close(&*engine);
    assert_eq!(held.callbacks_dropped(), 1);
    assert_eq!(
        undeclared.callbacks_dropped(),
        1,
        "nothing more after the close"
    );
}
