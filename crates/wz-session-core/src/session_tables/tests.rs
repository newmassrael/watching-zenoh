// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

use super::*;
use crate::bounded::{Static, ARENA_ALIGN};
use crate::limits::SessionLimits;
use crate::reply_acceptance::ReplyAcceptance;
use crate::row_callback::{CClosure, CallLatch};
use crate::sink::RowAccess;
use core::cell::Cell;
use core::ptr::NonNull;
use std::vec::Vec;

/// A test's callback the tables call only while they are held.
macro_rules! called_while_held {
    ($($ty:ty),*) => {$(
        impl RowCallback for $ty {
            type Call = core::convert::Infallible;
            const READS_ROW_IN_PLACE: bool = false;
            fn begin(&self) -> Option<core::convert::Infallible> {
                None
            }
            unsafe fn end(call: core::convert::Infallible) -> bool {
                match call {}
            }
            fn retire(&self) -> bool {
                true
            }
            fn drained(&self) -> bool {
                true
            }
        }
    )*};
}

called_while_held!(u32);
#[cfg(feature = "alloc")]
called_while_held!(FrameEnds);

/// A C closure whose call is the number `n`, with no context and no drop.
fn latched(n: u32) -> CClosure<u32> {
    // SAFETY: neither the call, a number, nor the absent drop reads the context.
    unsafe { CClosure::new(n, core::ptr::null_mut(), None) }
}

/// Callbacks a call of runs after the tables are let go: a C closure each.
enum Latched {}

impl RowCallbacks for Latched {
    type Subscriber = CClosure<u32>;
    type Queryable = CClosure<u32>;
    type LivelinessSubscriber = CClosure<u32>;
    type Matching = CClosure<u32>;
    type Reply = CClosure<u32>;
    type QueryablePresence = Present;
    type LivelinessPresence = Present;
    type FilterPresence = Present;
    type GetPresence = Present;
}

/// The tables of the lent policy, whose rows lie in the arena, with latched callbacks.
type LatchedTables = SessionTables<Latched, Lent>;

/// Latched tables lent every table at the build's bound.
fn latched_tables() -> LatchedTables {
    let rows = rows();
    let mut arena = arena(LatchedTables::arena_bytes(&rows).unwrap());
    LatchedTables::lent(&mut arena, keys(4096), &rows).unwrap()
}

/// End `call`, begun on a row of `R`'s that has not moved since.
fn ended<R: RowCallback>(call: R::Call) -> bool {
    // SAFETY: the tables these tests begin calls on are not moved while a call runs.
    unsafe { R::end(call) }
}

/// Callbacks the tests can tell apart: a number each.
enum Calls {}

impl RowCallbacks for Calls {
    type Subscriber = u32;
    type Queryable = u32;
    type LivelinessSubscriber = u32;
    type Matching = u32;
    type Reply = u32;
    type QueryablePresence = Present;
    type LivelinessPresence = Present;
    type FilterPresence = Present;
    type GetPresence = Present;
}

type Tables = SessionTables<Calls>;

/// Every table at the build's bound, for a test to lower one of.
fn rows() -> TableRows {
    TableRows {
        keyexprs: caps::MAX_DECLARED_KEYEXPRS,
        subscribers: caps::MAX_SUBSCRIPTIONS,
        queryables: caps::MAX_QUERYABLES,
        tokens: caps::MAX_LOCAL_TOKENS,
        liveliness_subscribers: caps::MAX_LIVELINESS_SUBSCRIPTIONS,
        publishers: caps::MAX_PUBLISHERS,
        queriers: caps::MAX_QUERIERS,
        matching_listeners: caps::MAX_MATCHING_LISTENERS,
        key_listeners: caps::MAX_MATCHING_LISTENERS,
        pending_gets: caps::MAX_PENDING_QUERIES,
        held_replies: caps::MAX_PENDING_REPLIES,
    }
}

fn subscribe(
    tables: &mut Tables,
    key: &str,
    origin: Locality,
    callback: u32,
) -> Declared<kind::Subscriber> {
    tables
        .declare_subscriber(key, origin, KeyForm::default(), callback)
        .unwrap()
}

/// The callbacks of the subscribers a sample on `key` reaches.
fn reached(tables: &Tables, key: &str, local: bool) -> Vec<u32> {
    tables
        .subscribers_for(key, local)
        .map(|(_, row)| *row.callback())
        .collect()
}

/// Peers whose answer the test sets, counting how often they are asked.
#[derive(Default)]
struct Peers {
    declares: Cell<bool>,
    written: Cell<u64>,
    asked: Cell<u32>,
}

impl PeerDeclarations for Peers {
    fn declares(&self, _plane: Plane, _key: &str) -> bool {
        self.asked.set(self.asked.get() + 1);
        self.declares.get()
    }

    fn written(&self) -> u64 {
        self.written.get()
    }
}

/// Every kind of entity is admitted by the one body (`Declaring::keyed`) and holds the declaration
/// its key is named under as every other kind does: once while it stands, and not after it goes.
///
/// # Control
///
/// A kind whose declaration skips `Declaring::hold` for its prefix, or whose undeclaration keeps
/// the hold, reds that kind's line.
#[test]
fn every_kind_of_entity_holds_its_prefix_declaration_alike() {
    let mut tables = Tables::new();
    let prefix = tables.declare_keyexpr("demo").unwrap();
    let holds = |tables: &Tables| tables.keyexprs().get(prefix.handle).unwrap().holds();
    let alone = holds(&tables);
    let form = KeyForm {
        prefix: Some(prefix.handle),
        own: None,
        retraction: Retraction::ById,
    };
    let sub = tables
        .declare_subscriber("demo/s", Locality::Any, form, 1)
        .unwrap();
    assert_eq!(holds(&tables), alone + 1, "a subscriber holds its prefix");
    let qbl = tables
        .declare_queryable("demo/q", Locality::Any, true, form, 2)
        .unwrap();
    assert_eq!(holds(&tables), alone + 2, "a queryable holds its prefix");
    let token = tables.declare_token("demo/t", form).unwrap();
    assert_eq!(holds(&tables), alone + 3, "a token holds its prefix");
    let live = tables
        .declare_liveliness_subscriber("demo/l", true, form, 3)
        .unwrap();
    assert_eq!(
        holds(&tables),
        alone + 4,
        "a liveliness subscriber holds its prefix"
    );
    assert_eq!([sub.id, qbl.id, token.id, live.id], [1, 2, 3, 4]);
    assert!(tables.undeclare_subscriber(sub.handle).is_some());
    assert!(tables.undeclare_queryable(qbl.handle).is_some());
    assert!(tables.undeclare_token(token.handle).is_some());
    assert!(tables
        .undeclare_liveliness_subscriber(live.handle)
        .is_some());
    assert_eq!(holds(&tables), alone, "each kind let its hold go");
}

#[test]
fn every_kind_of_entity_takes_its_id_from_one_space() {
    let mut tables = Tables::new();
    let sub = subscribe(&mut tables, "a", Locality::Any, 1);
    let qbl = tables
        .declare_queryable("b", Locality::Any, true, KeyForm::default(), 2)
        .unwrap();
    let token = tables.declare_token("c", KeyForm::default()).unwrap();
    let live = tables
        .declare_liveliness_subscriber("d", true, KeyForm::default(), 3)
        .unwrap();
    assert_eq!([sub.id, qbl.id, token.id, live.id], [1, 2, 3, 4]);
    assert_eq!(tables.subscribers().get(sub.handle).unwrap().callback(), &1);
    assert_eq!(
        tables.subscribers().get(sub.handle).unwrap().key().as_str(),
        "a"
    );
    assert!(tables.queryables().get(qbl.handle).unwrap().complete());
    assert_eq!(tables.tokens().get(token.handle).unwrap().id(), 3);
    assert!(tables
        .liveliness_subscribers()
        .get(live.handle)
        .unwrap()
        .history());
}

#[test]
fn a_full_table_refuses_before_an_id_is_spent_and_hands_the_callback_back() {
    let mut tables = Tables::new();
    tables.limit_to(&TableRows {
        subscribers: 1,
        ..rows()
    });
    subscribe(&mut tables, "a", Locality::Any, 1);
    let refused = tables
        .declare_subscriber("b", Locality::Any, KeyForm::default(), 2)
        .unwrap_err();
    assert_eq!(refused.why, RegisterError::TableFull);
    assert_eq!(refused.callback, 2);
    // The refusal spent no id: the next entity takes the one after the first.
    let token = tables.declare_token("c", KeyForm::default()).unwrap();
    assert_eq!(token.id, 2);
}

#[test]
fn spent_entity_ids_refuse_a_declaration_rather_than_wrap() {
    let mut tables = Tables::new();
    tables.entity_ids_from(Some(u32::MAX));
    assert_eq!(subscribe(&mut tables, "a", Locality::Any, 1).id, u32::MAX);
    let refused = tables
        .declare_subscriber("b", Locality::Any, KeyForm::default(), 2)
        .unwrap_err();
    assert_eq!(refused.why, RegisterError::IdsExhausted);
    assert_eq!(refused.callback, 2);
    assert_eq!(tables.subscribers().len(), 1);
}

#[test]
fn a_key_longer_than_a_fixed_row_holds_is_refused_before_an_id_is_spent() {
    let mut tables = SessionTables::<Calls, Static>::new();
    let long = "k".repeat(caps::MAX_KEYEXPR_BYTES + 1);
    let refused = tables
        .declare_subscriber(&long, Locality::Any, KeyForm::default(), 5)
        .unwrap_err();
    assert_eq!(refused.why, RegisterError::KeyexprTooLong);
    assert_eq!(refused.callback, 5);
    assert_eq!(
        tables
            .declare_subscriber("k", Locality::Any, KeyForm::default(), 6)
            .unwrap()
            .id,
        1
    );
}

#[test]
fn an_undeclared_entity_hands_its_callback_back_and_its_handle_goes_stale() {
    let mut tables = Tables::new();
    let sub = subscribe(&mut tables, "a", Locality::Any, 7);
    let undeclared = tables.undeclare_subscriber(sub.handle).unwrap();
    assert_eq!(undeclared.id, sub.id);
    assert_eq!(undeclared.taken.unwrap(), 7);
    assert_eq!(undeclared.keyexpr, None);
    assert!(tables.undeclare_subscriber(sub.handle).is_none());
    assert!(reached(&tables, "a", false).is_empty());
}

#[test]
fn a_subscriber_undeclared_while_its_callback_runs_is_let_go_by_the_last_call() {
    let mut tables = latched_tables();
    let sub = tables
        .declare_subscriber("a", Locality::Any, KeyForm::default(), latched(7))
        .unwrap();
    let call = tables.begin_subscriber(sub.handle).unwrap();
    assert_eq!(call.call, 7);
    let undeclared = tables.undeclare_subscriber(sub.handle).unwrap();
    assert_eq!(undeclared.id, sub.id);
    assert!(undeclared.taken.is_none(), "a call of it runs");
    // No later sample reaches it and no call of it begins, while the running call still holds it.
    assert!(tables.subscribers_for("a", false).next().is_none());
    assert!(tables.begin_subscriber(sub.handle).is_none());
    assert!(tables.subscribers().holds_slot(sub.handle));
    assert!(ended::<CClosure<u32>>(call), "the last call lets it go");
    assert!(tables.release_subscriber(sub.handle).is_some());
    assert!(!tables.subscribers().holds_slot(sub.handle));
    assert!(tables.subscribers().is_empty());
}

/// A walk of the tables takes out each row undeclared while a call of it ran once its last call
/// ended, each once, of every kind a call of which may outlive the tables' hold; a live row is
/// never taken. The CONTROL is the walk while the calls still run, which takes nothing.
#[test]
fn a_walk_lets_go_of_the_rows_whose_last_call_ended() {
    let mut tables = latched_tables();
    let kept = tables
        .declare_subscriber("k", Locality::Any, KeyForm::default(), latched(1))
        .unwrap();
    let gone = tables
        .declare_subscriber("g", Locality::Any, KeyForm::default(), latched(2))
        .unwrap();
    let qbl = tables
        .declare_queryable("q", Locality::Any, false, KeyForm::default(), latched(3))
        .unwrap();
    let live = tables
        .declare_liveliness_subscriber("l", false, KeyForm::default(), latched(4))
        .unwrap();
    let calls = (
        tables.begin_subscriber(kept.handle).unwrap(),
        tables.begin_subscriber(gone.handle).unwrap(),
        tables.begin_queryable(qbl.handle).unwrap(),
        tables.begin_liveliness_subscriber(live.handle).unwrap(),
    );
    assert!(tables
        .undeclare_subscriber(gone.handle)
        .unwrap()
        .taken
        .is_none());
    assert!(tables
        .undeclare_queryable(qbl.handle)
        .unwrap()
        .taken
        .is_none());
    assert!(tables
        .undeclare_liveliness_subscriber(live.handle)
        .unwrap()
        .taken
        .is_none());
    assert!(
        tables.release_drained_subscriber(&mut 0).is_none(),
        "CONTROL: its call still runs"
    );
    assert!(tables.release_drained_queryable(&mut 0).is_none());
    assert!(tables
        .release_drained_liveliness_subscriber(&mut 0)
        .is_none());
    assert!(
        !ended::<CClosure<u32>>(calls.0),
        "a live row's call marks nothing"
    );
    assert!(ended::<CClosure<u32>>(calls.1));
    assert!(ended::<CClosure<u32>>(calls.2));
    assert!(ended::<CClosure<u32>>(calls.3));
    let mut cursor = 0;
    assert!(tables.release_drained_subscriber(&mut cursor).is_some());
    assert!(
        tables.release_drained_subscriber(&mut cursor).is_none(),
        "each once"
    );
    assert!(!tables.subscribers().holds_slot(gone.handle));
    assert!(
        tables.subscribers().contains(kept.handle),
        "the live row is not taken"
    );
    assert!(tables.release_drained_subscriber(&mut 0).is_none());
    assert!(tables.release_drained_queryable(&mut 0).is_some());
    assert!(!tables.queryables().holds_slot(qbl.handle));
    assert!(tables.release_drained_queryable(&mut 0).is_none());
    assert!(tables
        .release_drained_liveliness_subscriber(&mut 0)
        .is_some());
    assert!(!tables.liveliness_subscribers().holds_slot(live.handle));
    assert!(tables
        .release_drained_liveliness_subscriber(&mut 0)
        .is_none());
}

#[test]
fn a_row_no_call_of_which_runs_is_let_go_when_it_is_undeclared() {
    let mut tables = latched_tables();
    let sub = tables
        .declare_subscriber("a", Locality::Any, KeyForm::default(), latched(7))
        .unwrap();
    let call = tables.begin_subscriber(sub.handle).unwrap();
    assert!(
        !ended::<CClosure<u32>>(call),
        "a live row is let go of by no call"
    );
    let undeclared = tables.undeclare_subscriber(sub.handle).unwrap();
    assert!(
        undeclared.taken.is_some(),
        "no call runs: the undeclarer lets it go"
    );
    assert!(tables.release_subscriber(sub.handle).is_none());
}

#[test]
fn every_kind_with_a_callback_is_let_go_by_its_last_call() {
    let mut tables = latched_tables();
    let qbl = tables
        .declare_queryable("q", Locality::Any, false, KeyForm::default(), latched(1))
        .unwrap();
    let live = tables
        .declare_liveliness_subscriber("l", false, KeyForm::default(), latched(2))
        .unwrap();
    let filter = tables
        .declare_write_filter(Plane::Subscribers, "m", false)
        .unwrap()
        .handle;
    let listener = tables
        .declare_matching_listener(filter, latched(3))
        .unwrap();
    let get = tables
        .begin_get(ReplyAcceptance::Matching("g"), 1, 10, latched(4))
        .unwrap();
    let calls = (
        tables.begin_queryable(qbl.handle).unwrap(),
        tables.begin_liveliness_subscriber(live.handle).unwrap(),
        tables.begin_matching_listener(listener).unwrap(),
        tables.begin_reply(get.handle).unwrap(),
    );
    assert_eq!(
        (calls.0.call, calls.1.call, calls.2.call, calls.3.call),
        (1, 2, 3, 4)
    );
    assert!(tables
        .undeclare_queryable(qbl.handle)
        .unwrap()
        .taken
        .is_none());
    assert!(tables
        .undeclare_liveliness_subscriber(live.handle)
        .unwrap()
        .taken
        .is_none());
    assert!(tables
        .undeclare_matching_listener(listener)
        .unwrap()
        .row
        .is_none());
    assert!(matches!(
        tables.end_get(get.handle),
        Some(Removal::AfterCalls)
    ));
    assert!(ended::<CClosure<u32>>(calls.0));
    assert!(tables.release_queryable(qbl.handle).is_some());
    assert!(ended::<CClosure<u32>>(calls.1));
    assert!(tables.release_liveliness_subscriber(live.handle).is_some());
    assert!(ended::<CClosure<u32>>(calls.2));
    assert!(tables.release_matching_listener(listener).is_some());
    assert!(
        tables.begin_reply(get.handle).is_none(),
        "an ended get begins no call"
    );
    assert!(ended::<CClosure<u32>>(calls.3));
    assert!(tables.release_get(get.handle).is_some());
}

#[test]
fn a_key_expression_declared_twice_is_held_twice_and_retracted_by_its_last_holder() {
    let mut tables = Tables::new();
    let first = tables.declare_keyexpr("demo/").unwrap();
    assert!(first.new);
    assert_eq!(first.id, 1);
    let again = tables.declare_keyexpr("demo/").unwrap();
    assert!(!again.new);
    assert_eq!((again.handle, again.id), (first.handle, first.id));
    assert_eq!(tables.undeclare_keyexpr(first.handle), None);
    assert_eq!(tables.undeclare_keyexpr(first.handle), Some(1));
    assert!(tables.keyexprs().is_empty());
    assert_eq!(tables.undeclare_keyexpr(first.handle), None);
}

/// A hold taken for a copied holder keeps the declaration until that holder lets go too; a handle
/// that names no row takes none.
#[test]
fn a_retained_key_expression_is_retracted_by_its_last_holder() {
    let mut tables = Tables::new();
    let declared = tables.declare_keyexpr("demo/").unwrap();
    assert!(tables.retain_keyexpr(declared.handle));
    assert_eq!(tables.undeclare_keyexpr(declared.handle), None);
    assert_eq!(tables.undeclare_keyexpr(declared.handle), Some(declared.id));
    assert!(
        !tables.retain_keyexpr(declared.handle),
        "a retracted one takes none"
    );
    assert!(tables.keyexprs().is_empty());
}

/// Ids minted from the last wrap past it to 1, and skip one a row still holds. Turned red by a
/// mint that refuses past the last id, or one that hands out an id a row holds.
#[test]
fn key_expression_ids_minted_from_the_last_wrap_and_skip_one_still_declared() {
    let mut tables = Tables::new();
    let one = tables.declare_keyexpr("a").unwrap();
    assert_eq!(one.id, 1);
    tables.expr_ids_from(ExprId::MAX);
    assert_eq!(tables.declare_keyexpr("b").unwrap().id, ExprId::MAX);
    assert_eq!(
        tables.declare_keyexpr("c").unwrap().id,
        2,
        "1 is still declared"
    );
}

#[test]
fn a_key_expression_id_skips_one_still_declared() {
    let mut tables = Tables::new();
    let one = tables.declare_keyexpr("a").unwrap();
    tables.next_expr = one.id;
    let two = tables.declare_keyexpr("b").unwrap();
    assert_ne!(two.id, one.id);
    assert_ne!(two.id, 0);
}

#[test]
fn an_entity_names_its_key_by_the_declaration_it_starts_with_and_holds_it() {
    let mut tables = Tables::new();
    let prefix = tables.declare_keyexpr("demo/").unwrap();
    let form = KeyForm {
        prefix: Some(prefix.handle),
        own: None,
        retraction: Retraction::AsAnnounced,
    };
    let sub = tables
        .declare_subscriber("demo/x", Locality::Any, form, 1)
        .unwrap();
    let key = tables.subscribers().get(sub.handle).unwrap().key();
    assert_eq!(key.retraction(), Retraction::AsAnnounced);
    assert_eq!(key.prefix(), Some(prefix.handle));
    assert_eq!(
        tables.wire_of(key),
        WireForm {
            mapping: prefix.id,
            suffix: "x"
        }
    );
    assert_eq!(tables.keyexprs().get(prefix.handle).unwrap().holds(), 2);
    // The program lets go of its declaration; the subscriber still holds it.
    assert_eq!(tables.undeclare_keyexpr(prefix.handle), None);
    // The subscriber's retraction retracts the declaration with it.
    let undeclared = tables.undeclare_subscriber(sub.handle).unwrap();
    assert_eq!(undeclared.keyexpr, Some(prefix.id));
    assert!(tables.keyexprs().is_empty());
}

#[test]
fn a_prefix_the_key_does_not_start_with_or_that_is_gone_is_not_used() {
    let mut tables = Tables::new();
    let other = tables.declare_keyexpr("other/").unwrap();
    let gone = tables.declare_keyexpr("demo/").unwrap();
    assert_eq!(tables.undeclare_keyexpr(gone.handle), Some(gone.id));
    for prefix in [other.handle, gone.handle] {
        let form = KeyForm {
            prefix: Some(prefix),
            own: None,
            retraction: Retraction::ById,
        };
        let token = tables.declare_token("demo/x", form).unwrap();
        let key = tables.tokens().get(token.handle).unwrap().key();
        assert_eq!(key.prefix(), None);
        assert_eq!(
            tables.wire_of(key),
            WireForm {
                mapping: 0,
                suffix: "demo/x"
            }
        );
    }
    assert_eq!(tables.keyexprs().get(other.handle).unwrap().holds(), 1);
}

#[test]
fn a_sample_reaches_the_subscribers_its_key_and_origin_admit() {
    let mut tables = Tables::new();
    subscribe(&mut tables, "a/b", Locality::Any, 1);
    subscribe(&mut tables, "a/b", Locality::Remote, 2);
    subscribe(&mut tables, "a/b", Locality::SessionLocal, 3);
    subscribe(&mut tables, "c", Locality::Any, 4);
    assert_eq!(reached(&tables, "a/b", false), std::vec![1, 2]);
    assert_eq!(reached(&tables, "a/b", true), std::vec![1, 3]);
    assert_eq!(reached(&tables, "c", false), std::vec![4]);
    assert!(reached(&tables, "d", false).is_empty());
}

#[cfg(feature = "keyexpr-wildcard-single")]
#[test]
fn a_sample_reaches_a_subscriber_whose_pattern_intersects_its_key() {
    let mut tables = Tables::new();
    subscribe(&mut tables, "a/*", Locality::Any, 1);
    assert_eq!(reached(&tables, "a/b", false), std::vec![1]);
    assert!(reached(&tables, "b/a", false).is_empty());
}

#[test]
fn queries_tokens_and_liveliness_reach_by_their_keys() {
    let mut tables = Tables::new();
    tables
        .declare_queryable("q", Locality::Remote, true, KeyForm::default(), 1)
        .unwrap();
    tables
        .declare_liveliness_subscriber("t", false, KeyForm::default(), 2)
        .unwrap();
    let token = tables.declare_token("t", KeyForm::default()).unwrap();
    let qbls: Vec<u32> = tables
        .queryables_for("q", false)
        .map(|(_, row)| *row.callback())
        .collect();
    assert_eq!(qbls, std::vec![1]);
    assert_eq!(tables.queryables_for("q", true).count(), 0);
    let live: Vec<u32> = tables
        .liveliness_subscribers_for("t")
        .map(|(_, row)| *row.callback())
        .collect();
    assert_eq!(live, std::vec![2]);
    let tokens: Vec<_> = tables.tokens_for("t").map(|(handle, _)| handle).collect();
    assert_eq!(tokens, std::vec![token.handle]);
    assert_eq!(tables.tokens_for("u").count(), 0);
}

/// Each write filter that asks opens an Interest of its own, a second one on the same kind and
/// key too, as zenoh-pico's `_z_write_filter_create` adds one for each filter; a listener on a
/// filter reads its filter's and opens none. Turned red by a search that hands the second filter
/// the first's Interest, or a Final held back while another filter on the key stands.
#[test]
fn each_filter_opens_an_interest_of_its_own_its_listeners_read() {
    let mut tables = Tables::new();
    let first = tables
        .declare_write_filter(Plane::Subscribers, "k", false)
        .unwrap();
    let opened = first.interest.unwrap();
    let asked = opened.id;
    let second = tables
        .declare_write_filter(Plane::Subscribers, "k", true)
        .unwrap();
    let again = second
        .interest
        .expect("a second filter on the same kind and key asks apart");
    assert_ne!(again.id, asked);
    assert_ne!(again.handle, opened.handle);
    let listener = tables.declare_matching_listener(first.handle, 9).unwrap();
    // Another kind on the same key asks apart too.
    let querier = tables
        .declare_write_filter(
            Plane::Queryables {
                complete_required: false,
            },
            "k",
            false,
        )
        .unwrap();
    assert!(querier
        .interest
        .is_some_and(|new| new.id != asked && new.id != again.id));
    assert_eq!(tables.interests().len(), 3, "the listener opened none");
    let interest = tables
        .write_filters()
        .get(first.handle)
        .unwrap()
        .interest()
        .unwrap();
    assert_eq!(
        interest, opened.handle,
        "the filter holds the Interest it opened"
    );
    assert_eq!(tables.interests().get(interest).unwrap().id(), asked);
    assert_eq!(tables.interest_key(interest), Some("k"));
    assert_eq!(
        tables.matching_listeners().get(listener).unwrap().filter(),
        first.handle,
        "a listener is its filter's callback"
    );
    // Each filter's Final goes with it; the listener goes with its filter.
    let mut gone = Vec::new();
    assert_eq!(
        tables
            .undeclare_write_filter(first.handle, |handle, removal| gone.push((handle, removal)))
            .unwrap()
            .interest_final,
        Some(asked)
    );
    assert_eq!(gone.len(), 1);
    assert_eq!(gone[0].0, listener);
    assert!(matches!(&gone[0].1, Removal::Taken(row) if *row.callback() == 9));
    assert!(tables.matching_listeners().get(listener).is_none());
    assert_eq!(
        tables
            .undeclare_write_filter(second.handle, |_, _| unreachable!("no listener on it"))
            .unwrap()
            .interest_final,
        Some(again.id)
    );
    assert_eq!(tables.interests().len(), 1);
}

#[test]
fn a_listener_on_no_filter_is_refused_with_its_callback() {
    let mut tables = Tables::new();
    let filter = tables
        .declare_write_filter(Plane::Subscribers, "k", false)
        .unwrap()
        .handle;
    let _ = tables.undeclare_write_filter(filter, |_, _| {});
    let refused = tables.declare_matching_listener(filter, 5).unwrap_err();
    assert_eq!(refused.why, RegisterError::OwnerGone);
    assert_eq!(refused.callback, 5);
}

#[test]
fn a_filter_undeclared_while_its_listener_is_called_leaves_it_to_the_last_call() {
    let mut tables = latched_tables();
    let filter = tables
        .declare_write_filter(Plane::Subscribers, "k", false)
        .unwrap()
        .handle;
    let listener = tables
        .declare_matching_listener(filter, latched(4))
        .unwrap();
    let call = tables.begin_matching_listener(listener).unwrap();
    let mut gone = Vec::new();
    let _ = tables.undeclare_write_filter(filter, |handle, removal| gone.push((handle, removal)));
    assert!(matches!(gone.as_slice(), [(handle, Removal::AfterCalls)] if *handle == listener));
    assert!(tables.begin_matching_listener(listener).is_none());
    assert!(ended::<CClosure<u32>>(call));
    assert!(tables.release_matching_listener(listener).is_some());
}

#[test]
fn a_full_listener_table_refuses_and_hands_the_callback_back() {
    let mut tables = Tables::new();
    tables.limit_to(&TableRows {
        matching_listeners: 0,
        ..rows()
    });
    let filter = tables
        .declare_write_filter(Plane::Subscribers, "k", false)
        .unwrap()
        .handle;
    let refused = tables.declare_matching_listener(filter, 4).unwrap_err();
    assert_eq!(refused.why, RegisterError::TableFull);
    assert_eq!(refused.callback, 4);
    assert_eq!(tables.interests().len(), 1, "the filter's alone");
}

#[test]
fn a_write_filter_keeps_the_peers_answer_until_their_tables_change() {
    let mut tables = Tables::new();
    let filter = tables
        .declare_write_filter(Plane::Subscribers, "k", false)
        .unwrap()
        .handle;
    let peers = Peers::default();
    assert_eq!(tables.write_filter_open(filter, &peers), Some(false));
    assert_eq!(peers.asked.get(), 1);
    // A peer declares, but the count has not moved: the kept answer stands, and nobody is asked.
    peers.declares.set(true);
    assert_eq!(tables.write_filter_open(filter, &peers), Some(false));
    assert_eq!(peers.asked.get(), 1);
    peers.written.set(1);
    assert_eq!(tables.write_filter_open(filter, &peers), Some(true));
    assert_eq!(peers.asked.get(), 2);
    let _ = tables.undeclare_write_filter(filter, |_, _| {});
    assert_eq!(tables.write_filter_open(filter, &peers), None);
}

#[test]
fn the_sessions_own_subscribers_count_only_where_the_filter_asks_and_their_origin_admits() {
    let mut tables = Tables::new();
    let counting = tables
        .declare_write_filter(Plane::Subscribers, "k", true)
        .unwrap()
        .handle;
    let blind = tables
        .declare_write_filter(Plane::Subscribers, "k", false)
        .unwrap()
        .handle;
    let remote_only = subscribe(&mut tables, "k", Locality::Remote, 1);
    assert_eq!(tables.write_filter_open(counting, &NoPeers), Some(false));
    let _ = tables.undeclare_subscriber(remote_only.handle);
    subscribe(&mut tables, "k", Locality::Any, 2);
    assert_eq!(tables.write_filter_open(counting, &NoPeers), Some(true));
    assert_eq!(tables.write_filter_open(blind, &NoPeers), Some(false));
}

#[test]
fn only_a_complete_queryable_counts_where_completeness_is_required() {
    let mut tables = Tables::new();
    let complete = Plane::Queryables {
        complete_required: true,
    };
    let any = Plane::Queryables {
        complete_required: false,
    };
    let partial = tables
        .declare_queryable("k", Locality::Any, false, KeyForm::default(), 1)
        .unwrap();
    assert!(tables.matches(any, "k", true, &NoPeers));
    assert!(!tables.matches(complete, "k", true, &NoPeers));
    let _ = tables.undeclare_queryable(partial.handle);
    tables
        .declare_queryable("k", Locality::Any, true, KeyForm::default(), 2)
        .unwrap();
    assert!(tables.matches(complete, "k", true, &NoPeers));
    assert!(!tables.matches(complete, "k", false, &NoPeers));
}

#[test]
fn a_matching_listener_is_told_each_change_once() {
    let mut tables = Tables::new();
    let filter = tables
        .declare_write_filter(Plane::Subscribers, "k", true)
        .unwrap()
        .handle;
    let mut cursor = 0;
    assert_eq!(
        tables.next_matching_change(&mut cursor, &NoPeers),
        None,
        "a filter no listener is declared on is not read"
    );
    tables.declare_matching_listener(filter, 3).unwrap();
    let mut cursor = 0;
    assert_eq!(tables.next_matching_change(&mut cursor, &NoPeers), None);
    let sub = subscribe(&mut tables, "k", Locality::Any, 1);
    let mut cursor = 0;
    assert_eq!(
        tables.next_matching_change(&mut cursor, &NoPeers),
        Some((filter, true))
    );
    assert_eq!(tables.next_matching_change(&mut cursor, &NoPeers), None);
    let mut cursor = 0;
    assert_eq!(tables.next_matching_change(&mut cursor, &NoPeers), None);
    assert!(tables.write_filters().get(filter).unwrap().matching());
    let _ = tables.undeclare_subscriber(sub.handle);
    let mut cursor = 0;
    assert_eq!(
        tables.next_matching_change(&mut cursor, &NoPeers),
        Some((filter, false))
    );
    // A peer's declaration counts too.
    let peers = Peers::default();
    peers.declares.set(true);
    let mut cursor = 0;
    assert_eq!(
        tables.next_matching_change(&mut cursor, &peers),
        Some((filter, true))
    );
}

/// A listener's verdict is read and recorded through a shared borrow of the tables, so an engine
/// reads it beside what its peers declared, both borrowed from one owner. Turned red by a read that
/// needs the tables to write, or that records no verdict.
#[test]
fn a_matching_verdict_is_recorded_through_shared_tables() {
    let mut tables = Tables::new();
    let filter = tables
        .declare_write_filter(Plane::Subscribers, "k", false)
        .unwrap()
        .handle;
    tables.declare_matching_listener(filter, 3).unwrap();
    let peers = Peers::default();
    peers.declares.set(true);
    let shared: &Tables = &tables;
    let mut cursor = 0;
    assert_eq!(
        shared.next_matching_change(&mut cursor, &peers),
        Some((filter, true))
    );
    assert!(shared.write_filters().get(filter).unwrap().matching());
    let mut cursor = 0;
    assert_eq!(
        shared.next_matching_change(&mut cursor, &peers),
        None,
        "told once"
    );
}

/// A listener's callback is handed each verdict it is owed once, is owed nothing for a change
/// undone before it was handed, and stays owed while its callback is out for a call. Turned red by
/// a walk that hands a verdict twice, that hands a change undone before it was handed, or that
/// records as handed a verdict whose callback was out.
#[test]
fn a_listeners_callback_is_owed_its_verdict_until_it_takes_it() {
    let mut tables = Tables::new();
    let filter = tables
        .declare_write_filter(Plane::Subscribers, "k", false)
        .unwrap()
        .handle;
    let listener = tables.declare_matching_listener(filter, 3).unwrap();
    let take = |callback: &mut u32| Some(*callback);
    let out = |_: &mut u32| None::<u32>;
    assert_eq!(
        tables.take_owed_matching(&mut 0, take),
        None,
        "nothing moved"
    );
    let peers = Peers::default();
    peers.declares.set(true);
    assert_eq!(
        tables.next_matching_change(&mut 0, &peers),
        Some((filter, true))
    );
    assert_eq!(
        tables.take_owed_matching(&mut 0, out),
        None,
        "its callback out"
    );
    assert_eq!(
        tables.take_owed_matching(&mut 0, take),
        Some((listener, true, 3)),
        "still owed once its callback is back"
    );
    assert_eq!(tables.take_owed_matching(&mut 0, take), None, "handed once");
    peers.declares.set(false);
    assert_eq!(
        tables.next_matching_change(&mut 0, &peers),
        Some((filter, false))
    );
    peers.declares.set(true);
    assert_eq!(
        tables.next_matching_change(&mut 0, &peers),
        Some((filter, true))
    );
    assert_eq!(
        tables.take_owed_matching(&mut 0, take),
        None,
        "a change undone before it was handed owes nothing"
    );
}

#[test]
fn a_get_is_found_by_its_request_and_ended_by_its_last_leg_or_its_deadline() {
    let mut tables = Tables::new();
    let first = tables
        .begin_get(ReplyAcceptance::Matching("k"), 2, 100, 7)
        .unwrap();
    let second = tables.begin_get(ReplyAcceptance::Any, 1, 50, 8).unwrap();
    assert_ne!(first.request, second.request);
    let (found, row) = tables.pending_get(first.request).unwrap();
    assert_eq!(found, first.handle);
    assert_eq!(
        (row.gate(), row.legs(), row.deadline()),
        (Some("k"), 2, 100)
    );
    assert_eq!(
        tables
            .pending_get(second.request)
            .map(|(_, row)| row.gate()),
        Some(None),
        "a get that takes any key keeps none"
    );
    assert_eq!(tables.next_get_deadline(), Some(50));
    let mut cursor = 0;
    assert_eq!(
        tables.next_expired_get(60, &mut cursor),
        Some(second.handle)
    );
    assert_eq!(tables.next_expired_get(60, &mut cursor), None);
    assert!(matches!(
        tables.end_leg(first.handle),
        Some(LegEnded::Owed(1))
    ));
    assert!(
        tables.pending_get(first.request).is_some(),
        "a leg still owes"
    );
    match tables.end_leg(first.handle) {
        Some(LegEnded::Over(Removal::Taken(row))) => assert_eq!(row.into_callback(), 7),
        _ => panic!("the last leg ends a get no call runs on, and hands it back at once"),
    }
    assert!(tables.pending_get(first.request).is_none());
    assert_eq!(tables.next_get_deadline(), Some(50));
    assert!(
        tables.end_leg(first.handle).is_none(),
        "an ended get has no leg"
    );
}

/// A get's gate admits a Put or a Del on a key it intersects and every Err; a get that takes any
/// key admits every reply.
#[test]
fn a_gets_gate_admits_its_key_and_every_err() {
    use crate::reply_sink::{BorrowedReply, ReplyKind};
    let reply = |keyexpr, kind| BorrowedReply {
        rid: 0,
        keyexpr,
        kind,
        payload: &[],
        err_encoding: None,
        attachment: None,
        put_encoding: None,
    };
    let mut tables = Tables::new();
    let gated = tables
        .begin_get(ReplyAcceptance::Matching("a/b"), 1, 0, 1)
        .unwrap();
    let any = tables.begin_get(ReplyAcceptance::Any, 1, 0, 2).unwrap();
    let gated = tables.pending_get(gated.request).unwrap().1;
    assert!(gated.admits(&reply("a/b", ReplyKind::Put)));
    assert!(gated.admits(&reply("a/b", ReplyKind::Del)));
    assert!(!gated.admits(&reply("c/d", ReplyKind::Put)));
    assert!(gated.admits(&reply("c/d", ReplyKind::Err)));
    let any = tables.pending_get(any.request).unwrap().1;
    assert!(any.admits(&reply("c/d", ReplyKind::Put)));
}

#[test]
fn a_request_id_skips_the_ones_still_pending() {
    let mut tables = Tables::new();
    tables.next_request = u32::MAX;
    let last = tables.begin_get(ReplyAcceptance::Any, 1, 0, 1).unwrap();
    let wrapped = tables.begin_get(ReplyAcceptance::Any, 1, 0, 2).unwrap();
    assert_eq!((last.request, wrapped.request), (u32::MAX, 0));
    tables.next_request = u32::MAX;
    let next = tables.begin_get(ReplyAcceptance::Any, 1, 0, 3).unwrap();
    assert_eq!(next.request, 1);
}

#[test]
fn a_full_get_table_refuses_and_hands_the_callback_back() {
    let mut tables = Tables::new();
    tables.limit_to(&TableRows {
        pending_gets: 0,
        ..rows()
    });
    let refused = tables
        .begin_get(ReplyAcceptance::Matching("k"), 1, 0, 5)
        .unwrap_err();
    assert_eq!(refused.why, RegisterError::TableFull);
    assert_eq!(refused.callback, 5);
}

/// A `Latest` get holds its replies in the tables until its caller takes them out, and a get
/// ended with replies still held lets them go with it.
#[cfg(feature = "storage-profile")]
#[test]
fn a_latest_get_holds_its_replies_until_they_are_taken_and_ends_with_the_rest() {
    use crate::query_mode::ConsolidationMode;
    use crate::reply_hold::Consolidated;
    use crate::reply_sink::{BorrowedReply, ReplyKind, ReplyView};
    let reply = |keyexpr, payload| BorrowedReply {
        rid: 0,
        keyexpr,
        kind: ReplyKind::Put,
        payload,
        err_encoding: None,
        attachment: None,
        put_encoding: None,
    };
    let mut tables = Tables::new();
    let first = tables.begin_get(ReplyAcceptance::Any, 1, 0, 1).unwrap();
    let second = tables.begin_get(ReplyAcceptance::Any, 1, 0, 2).unwrap();
    let latest = ConsolidationMode::Latest;
    assert_eq!(
        tables.consolidate_reply(first.handle, latest, &reply("a", b"one")),
        Consolidated::Held
    );
    assert_eq!(
        tables.consolidate_reply(first.handle, latest, &reply("a", b"two")),
        Consolidated::Held,
        "two unstamped replies tie, and the later is held"
    );
    assert_eq!(
        tables.consolidate_reply(second.handle, latest, &reply("b", b"other")),
        Consolidated::Held
    );
    let taken = tables
        .take_held(first.handle)
        .expect("the first get holds a reply");
    assert_eq!((taken.keyexpr(), taken.payload()), ("a", b"two".as_slice()));
    assert!(tables.take_held(first.handle).is_none());
    assert!(tables.end_get(second.handle).is_some());
    assert!(
        tables.take_held(second.handle).is_none(),
        "what an ended get held went with it"
    );
}

/// A get whose gate is longer than a fixed row keeps is refused before it spends a request id, and
/// its callback is handed back.
#[test]
fn a_get_whose_gate_is_too_long_is_refused_and_spends_no_request_id() {
    let mut tables = SessionTables::<Calls, Static>::new();
    let before = tables.next_request;
    let long = "k".repeat(caps::MAX_KEYEXPR_BYTES + 1);
    let refused = tables
        .begin_get(ReplyAcceptance::Matching(&long), 1, 0, 6)
        .unwrap_err();
    assert_eq!(refused.why, RegisterError::KeyexprTooLong);
    assert_eq!(refused.callback, 6);
    assert_eq!(tables.next_request, before, "no request id was spent");
}

/// One block of an arena's memory, aligned as an arena's spans start.
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct Block([u8; ARENA_ALIGN]);

/// An arena over `bytes` bytes the test process leaks, so it outlives every table lent from it.
fn arena(bytes: usize) -> Arena {
    let blocks = bytes.div_ceil(ARENA_ALIGN).max(1);
    let region: &'static mut [Block] = std::vec![Block([0; ARENA_ALIGN]); blocks].leak();
    // SAFETY: the region is aligned to `ARENA_ALIGN`, as its blocks are, holds at least `bytes`
    // bytes, and is leaked, so nothing else uses it and it outlives every lent table.
    unsafe { Arena::over(NonNull::from(region).cast::<u8>(), bytes) }
}

/// A key arena of `bytes` bytes of blocks, lent from an arena of its own.
fn keys(bytes: usize) -> KeySpace {
    arena(KeySpace::span_bytes(bytes).unwrap())
        .lend_keys(bytes, SessionLimits::defaults().max_keyexpr_bytes_held())
        .unwrap()
}

fn small_rows() -> TableRows {
    TableRows {
        keyexprs: 2,
        subscribers: 2,
        queryables: 1,
        tokens: 1,
        liveliness_subscribers: 1,
        publishers: 1,
        queriers: 0,
        matching_listeners: 1,
        key_listeners: 1,
        pending_gets: 1,
        held_replies: 1,
    }
}

#[test]
fn lent_tables_take_the_arena_their_plan_counts_and_hold_the_rows_they_were_lent() {
    let rows = small_rows();
    let bytes = SessionTables::<Calls, Lent>::arena_bytes(&rows).unwrap();
    let mut arena = arena(bytes);
    let mut tables = SessionTables::<Calls, Lent>::lent(&mut arena, keys(256), &rows).unwrap();
    assert_eq!(arena.high_water(), bytes);
    let sub = tables
        .declare_subscriber("a/b", Locality::Any, KeyForm::default(), 1)
        .unwrap();
    tables
        .declare_subscriber("a/c", Locality::Any, KeyForm::default(), 2)
        .unwrap();
    let refused = tables
        .declare_subscriber("a/d", Locality::Any, KeyForm::default(), 3)
        .unwrap_err();
    assert_eq!(refused.why, RegisterError::TableFull);
    assert_eq!(
        tables.subscribers().get(sub.handle).unwrap().key().as_str(),
        "a/b"
    );
    let undeclared = tables.undeclare_subscriber(sub.handle).unwrap();
    assert_eq!(undeclared.taken.unwrap(), 1);
}

#[test]
fn a_key_the_key_arena_has_no_room_for_is_refused_as_a_full_table() {
    let rows = small_rows();
    let mut arena = arena(SessionTables::<Calls, Lent>::arena_bytes(&rows).unwrap());
    let mut tables = SessionTables::<Calls, Lent>::lent(&mut arena, keys(16), &rows).unwrap();
    let long = "k".repeat(64);
    let refused = tables
        .declare_subscriber(&long, Locality::Any, KeyForm::default(), 1)
        .unwrap_err();
    assert_eq!(refused.why, RegisterError::TableFull);
    assert_eq!(refused.callback, 1);
    // Nothing was taken: a key that fits is declared under the first id.
    assert_eq!(
        tables
            .declare_subscriber("k", Locality::Any, KeyForm::default(), 2)
            .unwrap()
            .id,
        1
    );
}

/// Rows of one text take one block of the key arena between them, whoever made the first: a
/// subscriber on a key the session declared shares the declaration's block. The CONTROL is a
/// subscriber on another text, which takes a block of its own.
#[test]
fn rows_of_one_text_share_its_block() {
    let rows = small_rows();
    let mut arena = arena(SessionTables::<Calls, Lent>::arena_bytes(&rows).unwrap());
    let space = keys(256);
    let mut tables = SessionTables::<Calls, Lent>::lent(&mut arena, space, &rows).unwrap();
    tables.declare_keyexpr("a/shared").unwrap();
    let one = space.counts().used;
    tables
        .declare_subscriber("a/shared", Locality::Any, KeyForm::default(), 1)
        .unwrap();
    assert_eq!(
        space.counts().used,
        one,
        "the subscriber shares the declaration's block"
    );
    tables
        .declare_subscriber("a/other", Locality::Any, KeyForm::default(), 2)
        .unwrap();
    assert!(
        space.counts().used > one,
        "CONTROL: another text takes a block of its own"
    );
}

#[test]
fn lent_tables_past_a_build_bound_are_refused() {
    let rows = TableRows {
        subscribers: caps::MAX_SUBSCRIPTIONS + 1,
        ..small_rows()
    };
    let mut arena = arena(1 << 16);
    assert!(matches!(
        SessionTables::<Calls, Lent>::lent(&mut arena, keys(64), &rows),
        Err(LendRefused::OverCeiling { .. })
    ));
}

/// A table refused past its build bound leaves the tables after it rowless: the arena keeps the
/// key expressions' table lent before the refusal, and lends nothing after it. The CONTROL is the
/// same rows within the bound, which take every table's span.
#[test]
fn a_refused_table_leaves_the_tables_after_it_unlent() {
    let within = small_rows();
    let past = TableRows {
        subscribers: caps::MAX_SUBSCRIPTIONS + 1,
        ..small_rows()
    };
    let before = <Keyexprs<Lent>>::arena_bytes(past.keyexprs).unwrap();
    let mut refused = arena(1 << 16);
    assert!(SessionTables::<Calls, Lent>::lent(&mut refused, keys(64), &past).is_err());
    assert_eq!(refused.high_water(), before);
    let bytes = SessionTables::<Calls, Lent>::arena_bytes(&within).unwrap();
    let mut whole = arena(bytes);
    SessionTables::<Calls, Lent>::lent(&mut whole, keys(64), &within).unwrap();
    assert_eq!(whole.high_water(), bytes, "CONTROL: every table is lent");
}

/// The rows of a session that keeps no queryable.
struct NoQueryables;

impl RowCallbacks for NoQueryables {
    type Subscriber = u32;
    type Queryable = u32;
    type LivelinessSubscriber = u32;
    type Matching = u32;
    type Reply = u32;
    type QueryablePresence = Absent;
    type LivelinessPresence = Present;
    type FilterPresence = Present;
    type GetPresence = Present;
}

/// Tables that keep no queryable lend no table of them, find none and refuse one, handing its
/// callback back. The CONTROL is the same rows on tables that keep queryables, which lend the
/// queryables' table and take the declaration.
#[test]
fn tables_that_keep_no_queryable_lend_none_and_refuse_one() {
    let rows = small_rows();
    let kept = SessionTables::<Calls, Lent>::arena_bytes(&rows).unwrap();
    let absent = SessionTables::<NoQueryables, Lent>::arena_bytes(&rows).unwrap();
    assert_eq!(
        kept - absent,
        <Queryables<Calls, Lent>>::arena_bytes(rows.queryables).unwrap(),
        "the queryables' table is all the difference"
    );
    let mut lent = arena(absent);
    let mut tables =
        SessionTables::<NoQueryables, Lent>::lent(&mut lent, keys(256), &rows).unwrap();
    assert_eq!(lent.high_water(), absent);
    assert!(tables.kept_queryables().is_none());
    let refused = tables
        .declare_queryable("q", Locality::Any, false, KeyForm::default(), 7)
        .unwrap_err();
    assert_eq!(
        (refused.why, refused.callback),
        (RegisterError::TableFull, 7)
    );
    assert!(!tables.local_declares(
        Plane::Queryables {
            complete_required: false
        },
        "q"
    ));
    let mut whole = arena(kept);
    let mut control = SessionTables::<Calls, Lent>::lent(&mut whole, keys(256), &rows).unwrap();
    assert!(
        control
            .declare_queryable("q", Locality::Any, false, KeyForm::default(), 7)
            .is_ok(),
        "CONTROL: tables that keep queryables take one"
    );
}

/// The rows of a session that keeps none of the kinds a build may leave out.
struct NoneKept;

impl RowCallbacks for NoneKept {
    type Subscriber = u32;
    type Queryable = u32;
    type LivelinessSubscriber = u32;
    type Matching = u32;
    type Reply = u32;
    type QueryablePresence = Absent;
    type LivelinessPresence = Absent;
    type FilterPresence = Absent;
    type GetPresence = Absent;
}

/// Tables that keep none of the kinds a build may leave out lend the key expressions, the
/// subscribers and the reply hold alone, and refuse a token, a liveliness subscriber, a write
/// filter and a get, finding none of them. The CONTROL is the same rows on tables that keep every
/// kind, which take each declaration.
#[test]
fn tables_that_keep_no_optional_kind_lend_none_and_refuse_each() {
    let rows = small_rows();
    let none = SessionTables::<NoneKept, Lent>::arena_bytes(&rows).unwrap();
    let kept_alone = <Keyexprs<Lent>>::arena_bytes(rows.keyexprs).unwrap()
        + <Subscribers<Calls, Lent>>::arena_bytes(rows.subscribers).unwrap()
        + held_arena_bytes(rows.held_replies).unwrap();
    assert_eq!(none, kept_alone, "the optional kinds take no byte");
    let mut lent = arena(none);
    let mut tables = SessionTables::<NoneKept, Lent>::lent(&mut lent, keys(256), &rows).unwrap();
    assert_eq!(lent.high_water(), none);
    assert_eq!(
        tables.declare_token("t", KeyForm::default()),
        Err(RegisterError::TableFull)
    );
    let refused = tables
        .declare_liveliness_subscriber("l", false, KeyForm::default(), 3)
        .unwrap_err();
    assert_eq!(
        (refused.why, refused.callback),
        (RegisterError::TableFull, 3)
    );
    assert_eq!(
        tables
            .declare_write_filter(Plane::Subscribers, "w", false)
            .unwrap_err(),
        RegisterError::TableFull
    );
    let refused = tables
        .begin_get(ReplyAcceptance::Any, 1, 10, 5)
        .unwrap_err();
    assert_eq!(
        (refused.why, refused.callback),
        (RegisterError::TableFull, 5)
    );
    assert_eq!(tables.tokens_for("t").count(), 0);
    assert_eq!(tables.next_get_deadline(), None);
    let mut whole = arena(SessionTables::<Calls, Lent>::arena_bytes(&rows).unwrap());
    let mut control = SessionTables::<Calls, Lent>::lent(&mut whole, keys(256), &rows).unwrap();
    assert!(
        control.declare_token("t", KeyForm::default()).is_ok(),
        "CONTROL: tables that keep tokens take one"
    );
    assert!(control
        .declare_write_filter(Plane::Subscribers, "w", false)
        .is_ok());
    assert!(control.begin_get(ReplyAcceptance::Any, 1, 10, 5).is_ok());
}

#[test]
fn a_declaration_apart_takes_an_id_of_its_own_and_skips_the_unusable_ones() {
    let mut tables = Tables::new();
    let shared = tables.declare_keyexpr("k").unwrap();
    let apart = tables.declare_keyexpr_where("k", true, |_| true).unwrap();
    assert!(apart.new);
    assert_ne!(apart.id, shared.id);
    let skipped = tables
        .declare_keyexpr_where("j", true, |id| id != 3)
        .unwrap();
    assert_eq!(skipped.id, 4);
    assert_eq!(tables.keyexpr_by_id(4), Some(skipped.handle));
    assert_eq!(
        tables.declare_keyexpr_where("i", true, |_| false),
        Err(RegisterError::IdsExhausted)
    );
}

/// An entity's key form names the declaration its wire names while that declaration stands, and
/// none for a wire that names none or one that went.
#[test]
fn a_key_form_names_the_declaration_the_wire_names_while_it_stands() {
    let mut tables = Tables::new();
    let declared = tables.declare_keyexpr("demo/").unwrap();
    assert_eq!(
        tables.key_form(declared.id, Retraction::AsAnnounced),
        KeyForm {
            prefix: Some(declared.handle),
            own: None,
            retraction: Retraction::AsAnnounced
        }
    );
    assert_eq!(
        tables.key_form(0, Retraction::ById),
        KeyForm {
            prefix: None,
            own: None,
            retraction: Retraction::ById
        },
        "a wire that names no declaration"
    );
    assert_eq!(tables.undeclare_keyexpr(declared.handle), Some(declared.id));
    assert_eq!(
        tables.key_form(declared.id, Retraction::AsAnnounced),
        KeyForm {
            prefix: None,
            own: None,
            retraction: Retraction::AsAnnounced
        },
        "a declaration that went is not named"
    );
}

/// A retraction names what its declaration stated: the id alone, the key as it is announced (by
/// the declaration the row holds while that stands, whole once it went), or the declaration of
/// the entity's own key the ABI named, which need not be the one its announcement names.
///
/// # Control
///
/// Keeping the form's retraction out of the row (every key retracted by id) reds the first
/// assertion; reading a named retraction as the announcement reds the second.
#[test]
fn a_retraction_names_what_its_declaration_stated() {
    let mut tables = Tables::new();
    let announced = tables.declare_keyexpr("demo/").unwrap();
    let own = tables.declare_keyexpr("demo/x").unwrap();
    let key = "demo/x/**";
    let as_announced = KeyForm {
        prefix: Some(announced.handle),
        own: None,
        retraction: Retraction::AsAnnounced,
    };
    let token = tables.declare_token(key, as_announced).unwrap();
    let row = tables.tokens().get(token.handle).unwrap().key();
    assert_eq!(
        tables.retraction_of(row).map(|names| names.names(key)),
        Some((announced.id, "x/**"))
    );
    let named = KeyForm {
        prefix: Some(announced.handle),
        own: None,
        retraction: Retraction::Named(RetractionKey::declared(own.id, "/**")),
    };
    let sub = tables
        .declare_subscriber(key, Locality::Any, named, 1)
        .unwrap();
    let row = tables.subscribers().get(sub.handle).unwrap().key();
    assert_eq!(
        tables.retraction_of(row).map(|names| names.names(key)),
        Some((own.id, "/**")),
        "the retraction names its own declaration, the announcement another"
    );
    assert_eq!(tables.wire_of(row).mapping, announced.id);
    let by_id = KeyForm {
        prefix: Some(announced.handle),
        own: None,
        retraction: Retraction::ById,
    };
    let quiet = tables
        .declare_subscriber(key, Locality::Any, by_id, 2)
        .unwrap();
    let row = tables.subscribers().get(quiet.handle).unwrap().key();
    assert_eq!(tables.retraction_of(row), None);
    // The announcement's declaration goes: the token is retracted naming its key whole.
    assert_eq!(tables.retract_keyexpr(announced.handle), Some(announced.id));
    let row = tables.tokens().get(token.handle).unwrap().key();
    assert_eq!(
        tables.retraction_of(row).map(|names| names.names(key)),
        Some((0, key))
    );
}

/// An entity whose retraction names a declaration holds it as it holds the one its key is named
/// by: the program's letting go of it leaves it declared, and the entity's going retracts it after
/// the entity, by the id the retraction named.
///
/// # Control
///
/// Holding no declaration for a named retraction (`Declaring::declare` without `hold(named)`)
/// reds the first `undeclare_keyexpr` (the program's release retracts it); releasing none in
/// `undeclare_entity` reds `named`.
#[test]
fn a_named_retraction_holds_its_declaration_until_the_entity_goes() {
    let mut tables = Tables::new();
    let own = tables.declare_keyexpr("demo/n").unwrap();
    let key = "demo/n/**";
    let form = KeyForm {
        prefix: None,
        own: None,
        retraction: Retraction::Named(RetractionKey::declared(own.id, "/**")),
    };
    let sub = tables
        .declare_subscriber(key, Locality::Any, form, 1)
        .unwrap();
    assert_eq!(tables.keyexprs().get(own.handle).unwrap().holds(), 2);
    assert_eq!(
        tables.undeclare_keyexpr(own.handle),
        None,
        "the subscriber still holds it"
    );
    let row = tables.subscribers().get(sub.handle).unwrap().key();
    assert_eq!(
        tables.retraction_of(row).map(|names| names.names(key)),
        Some((own.id, "/**"))
    );
    let undeclared = tables.undeclare_subscriber(sub.handle).unwrap();
    assert_eq!(undeclared.keyexpr, None, "its key was named whole");
    assert_eq!(undeclared.named, Some(own.id));
    assert_eq!(tables.keyexpr_by_id(own.id), None);
}

/// A declaration an entity's key is named by and its retraction names alike is held once, and
/// retracted once with it.
///
/// # Control
///
/// Holding the named declaration even when it is the key's (`EntityKey::holds` without its
/// filter) reds the count, and the entity's going then leaves it declared.
#[test]
fn one_declaration_named_twice_by_an_entity_is_held_once() {
    let mut tables = Tables::new();
    let declared = tables.declare_keyexpr("demo/t").unwrap();
    let form = KeyForm {
        prefix: Some(declared.handle),
        own: None,
        retraction: Retraction::Named(RetractionKey::declared(declared.id, "")),
    };
    let token = tables.declare_token("demo/t", form).unwrap();
    assert_eq!(tables.keyexprs().get(declared.handle).unwrap().holds(), 2);
    assert_eq!(tables.undeclare_keyexpr(declared.handle), None);
    let undeclared = tables.undeclare_token(token.handle).unwrap();
    assert_eq!(undeclared.keyexpr, Some(declared.id));
    assert_eq!(undeclared.named, None);
    assert_eq!(tables.keyexpr_by_id(declared.id), None);
}

/// A named retraction whose declaration no longer stands holds nothing and retracts the key
/// whole; one whose declaration is retracted whatever held it does too.
///
/// # Control
///
/// Reading the stated id back unchecked (`retraction_of` returning the named key as stated)
/// reds both literal assertions.
#[test]
fn a_named_retraction_without_its_declaration_names_the_key_whole() {
    let mut tables = Tables::new();
    let key = "demo/w/x";
    let gone = KeyForm {
        prefix: None,
        own: None,
        retraction: Retraction::Named(RetractionKey::declared(77, "/x")),
    };
    let token = tables.declare_token(key, gone).unwrap();
    let row = tables.tokens().get(token.handle).unwrap().key();
    assert_eq!(row.holds(), (None, None));
    assert_eq!(
        tables.retraction_of(row).map(|names| names.names(key)),
        Some((0, key))
    );
    let own = tables.declare_keyexpr("demo/w").unwrap();
    let named = KeyForm {
        prefix: None,
        own: None,
        retraction: Retraction::Named(RetractionKey::declared(own.id, "/x")),
    };
    let held = tables.declare_token(key, named).unwrap();
    assert_eq!(tables.retract_keyexpr(own.handle), Some(own.id));
    let row = tables.tokens().get(held.handle).unwrap().key();
    assert_eq!(
        tables.retraction_of(row).map(|names| names.names(key)),
        Some((0, key))
    );
    assert_eq!(tables.undeclare_token(held.handle).unwrap().named, None);
}

/// The declaration of an entity's own key the form states is held by its row whatever its
/// retraction names, and goes with the entity after the program let it go: a subscriber announced
/// on another key keeps its own declared key as zenoh-pico's subscription does.
///
/// # Control
///
/// Ignoring `KeyForm::own` in `Declaring::entity_key` reds the first `undeclare_keyexpr`.
#[test]
fn an_entity_holds_the_declaration_of_its_own_key_its_form_states() {
    let mut tables = Tables::new();
    let own = tables.declare_keyexpr("demo/o").unwrap();
    let form = KeyForm {
        prefix: None,
        own: Some(own.handle),
        retraction: Retraction::ById,
    };
    let sub = tables
        .declare_subscriber("demo/o/x", Locality::Any, form, 1)
        .unwrap();
    assert_eq!(
        tables.undeclare_keyexpr(own.handle),
        None,
        "the subscriber holds it"
    );
    let undeclared = tables.undeclare_subscriber(sub.handle).unwrap();
    assert_eq!(undeclared.named, Some(own.id));
    assert_eq!(tables.keyexpr_by_id(own.id), None);
    assert_eq!(
        KeyForm::default().owning(Some(own.handle)).own,
        Some(own.handle)
    );
}

/// An entity whose row would hold a declaration whose count of holders is full is refused, and
/// takes nothing: no row, no entity id, no hold. Whether the declaration is the one its key is
/// named by, the one of its own key its form states, or the one its named retraction names. A
/// declaration that went is held by nothing and refuses nothing.
///
/// # Control
///
/// `Declaring::holdable` answering `Ok` for a full count reds the three refusals (a row that names
/// the declaration and holds nothing); the declaration once one holder let it go is declared.
#[test]
fn an_entity_whose_declaration_has_no_room_for_a_holder_is_refused() {
    let mut tables = Tables::new();
    let full = tables.declare_keyexpr("demo/f").unwrap();
    while tables.retain_keyexpr(full.handle) {}
    assert_eq!(
        tables.keyexprs().get(full.handle).unwrap().holds(),
        KeyexprHolds::MAX
    );
    let next = tables.next_entity_id();
    let by_prefix = KeyForm {
        prefix: Some(full.handle),
        own: None,
        retraction: Retraction::ById,
    };
    assert_eq!(
        tables.declare_token("demo/f/x", by_prefix).map(|_| ()),
        Err(RegisterError::KeyexprHoldsFull)
    );
    let by_own = KeyForm::default().owning(Some(full.handle));
    let Err(refused) = tables.declare_subscriber("demo/f/x", Locality::Any, by_own, 7) else {
        panic!("a subscriber holding the full declaration was declared");
    };
    assert_eq!(refused.why, RegisterError::KeyexprHoldsFull);
    assert_eq!(refused.callback, 7, "the callback is handed back");
    let by_retraction = KeyForm {
        prefix: None,
        own: None,
        retraction: Retraction::Named(RetractionKey::declared(full.id, "/x")),
    };
    assert_eq!(
        tables.declare_token("demo/f/x", by_retraction).map(|_| ()),
        Err(RegisterError::KeyexprHoldsFull)
    );
    assert_eq!(tables.next_entity_id(), next, "no entity id was taken");
    assert_eq!(
        tables.keyexprs().get(full.handle).unwrap().holds(),
        KeyexprHolds::MAX,
        "no hold was taken"
    );
    assert_eq!(tables.subscribers().iter().count(), 0);
    // CONTROL: a holder lets go, and the entity takes the room it left.
    assert_eq!(tables.undeclare_keyexpr(full.handle), None);
    let token = tables.declare_token("demo/f/x", by_prefix).unwrap();
    assert_eq!(
        tables.keyexprs().get(full.handle).unwrap().holds(),
        KeyexprHolds::MAX
    );
    let row = tables.tokens().get(token.handle).unwrap().key();
    assert_eq!(tables.wire_of(row).mapping, full.id);
    // A declaration that went is held by nothing, and the key goes whole.
    let gone = tables.declare_keyexpr("demo/g").unwrap();
    assert_eq!(tables.retract_keyexpr(gone.handle), Some(gone.id));
    let whole = KeyForm {
        prefix: Some(gone.handle),
        own: Some(gone.handle),
        retraction: Retraction::ById,
    };
    let token = tables.declare_token("demo/g/x", whole).unwrap();
    let row = tables.tokens().get(token.handle).unwrap().key();
    assert_eq!(row.holds(), (None, None));
    assert_eq!(tables.wire_of(row).mapping, 0);
}

#[test]
fn a_retracted_declaration_goes_whatever_holds_it() {
    let mut tables = Tables::new();
    let declared = tables.declare_keyexpr("demo/").unwrap();
    tables.declare_keyexpr("demo/").unwrap();
    let form = KeyForm {
        prefix: Some(declared.handle),
        own: None,
        retraction: Retraction::ById,
    };
    let token = tables.declare_token("demo/x", form).unwrap();
    assert_eq!(tables.retract_keyexpr(declared.handle), Some(declared.id));
    assert_eq!(tables.keyexpr_by_id(declared.id), None);
    let key = tables.tokens().get(token.handle).unwrap().key();
    assert_eq!(tables.wire_of(key).mapping, 0);
    assert_eq!(tables.retract_keyexpr(declared.handle), None);
    // The token's retraction finds no declaration left to let go of.
    assert_eq!(tables.undeclare_token(token.handle).unwrap().keyexpr, None);
}

#[test]
fn a_key_is_named_as_the_session_sends_it_by_the_declaration_that_stands() {
    use crate::named_key::NamedKey;
    use crate::wire_key::{KeyText, MappedId, WireKey};
    let mut tables = Tables::new();
    let declared = tables.declare_keyexpr("demo/").unwrap();
    let id = MappedId::new(declared.id).unwrap();
    let form = KeyForm {
        prefix: Some(declared.handle),
        own: None,
        retraction: Retraction::ById,
    };
    let token = tables.declare_token("demo/x", form).unwrap();
    let key = tables.tokens().get(token.handle).unwrap().key();
    let named = tables.named(key).unwrap();
    assert_eq!(named.text(), "demo/x");
    assert_eq!(named.wire(), WireKey::mapped(id, KeyText::new("x")));
    // A key the program names by a declaration's id is named by it while the key starts with
    // the declared literal, and whole otherwise.
    assert_eq!(
        tables.named_by("demo/y", declared.id).unwrap().wire(),
        WireKey::mapped(id, KeyText::new("y"))
    );
    assert_eq!(
        tables.named_by("away/y", declared.id),
        NamedKey::literal("away/y")
    );
    assert_eq!(tables.named_by("demo/y", 0), NamedKey::literal("demo/y"));
    assert_eq!(tables.named_by("demo/y", 99), NamedKey::literal("demo/y"));
    assert_eq!(tables.named_by("", declared.id), None);
    // A retracted declaration names no key any more, the token's included.
    assert_eq!(tables.retract_keyexpr(declared.handle), Some(declared.id));
    let key = tables.tokens().get(token.handle).unwrap().key();
    assert_eq!(tables.named(key), NamedKey::literal("demo/x"));
    assert_eq!(
        tables.named_by("demo/y", declared.id),
        NamedKey::literal("demo/y")
    );
}

#[test]
fn ids_handed_out_apart_from_any_row_come_from_the_same_space() {
    let mut tables = Tables::new();
    assert_eq!(tables.take_entity_id(), Some(1));
    assert_eq!(tables.declare_token("t", KeyForm::default()).unwrap().id, 2);
    assert_eq!(tables.next_entity_id(), Some(3));
    tables.entity_ids_from(Some(u32::MAX));
    assert_eq!(tables.take_entity_id(), Some(u32::MAX));
    assert_eq!(tables.take_entity_id(), None);
    assert_eq!(tables.next_entity_id(), None);
}

/// A sink that counts what it is handed, and whose calls may also run after the tables are let go.
#[derive(Default)]
struct Counted(Cell<usize>, CallLatch);

impl Counted {
    /// Count one more delivery, through the shared row a delivery reads in place.
    fn hear(&self) {
        self.0.set(self.0.get() + 1);
    }
}

impl RowCallback for Counted {
    type Call = NonNull<CallLatch>;
    const READS_ROW_IN_PLACE: bool = true;
    fn begin(&self) -> Option<NonNull<CallLatch>> {
        self.1.begin().then(|| NonNull::from(&self.1))
    }
    unsafe fn end(call: NonNull<CallLatch>) -> bool {
        // SAFETY: the caller's: the row the latch lies in has not moved and is not let go of.
        unsafe { call.as_ref() }.end()
    }
    fn retire(&self) -> bool {
        self.1.retire()
    }
    fn drained(&self) -> bool {
        self.1.drained()
    }
}

impl crate::sink::SampleSink for Counted {
    fn deliver(&mut self, _sample: &dyn crate::sink::SampleView) {
        self.hear();
    }
}

/// Callbacks a delivery can be handed: a counting sink for the subscribers.
enum Sinks {}

impl RowCallbacks for Sinks {
    type Subscriber = Counted;
    type Queryable = u32;
    type LivelinessSubscriber = u32;
    type Matching = u32;
    type Reply = u32;
    type QueryablePresence = Present;
    type LivelinessPresence = Present;
    type FilterPresence = Present;
    type GetPresence = Present;
}

#[test]
fn the_tables_read_as_the_sessions_local_subscribers() {
    use crate::pubsub::LocalSubscribers;
    let mut tables = SessionTables::<Sinks>::new();
    assert_eq!(tables.epoch(), 0);
    assert_eq!(tables.next_subscription_id(), 1);
    let any = tables
        .declare_subscriber("a/b", Locality::Any, KeyForm::default(), Counted::default())
        .unwrap();
    let remote = tables
        .declare_subscriber(
            "a/b",
            Locality::Remote,
            KeyForm::default(),
            Counted::default(),
        )
        .unwrap();
    assert_eq!(tables.epoch(), 2);
    assert_eq!(tables.next_subscription_id(), 3);
    assert_eq!(tables.pattern_of(u64::from(remote.id)), Some("a/b"));
    assert_eq!(tables.pattern_of(99), None);
    let mut seen = std::vec::Vec::new();
    tables.for_each_subscription(&mut |id, pattern, origin| {
        seen.push((id, std::string::String::from(pattern), origin))
    });
    assert_eq!(
        seen,
        std::vec![
            (u64::from(any.id), "a/b".into(), Locality::Any),
            (u64::from(remote.id), "a/b".into(), Locality::Remote),
        ]
    );
    assert!(tables.has_local_matching("a/b"));
    assert!(!tables.has_local_matching("b"));
    let count = |_, row: RowAccess<'_, Counted>| row.row().hear();
    assert_eq!(tables.fire_matching("a/b", false, false, count), 2);
    assert_eq!(heard(&tables, any.handle), 1);
    assert_eq!(heard(&tables, remote.handle), 1);
    assert_eq!(tables.fire_matching("a/b", true, false, count), 1);
    assert_eq!(heard(&tables, any.handle), 2);
    assert_eq!(
        heard(&tables, remote.handle),
        1,
        "a subscriber of peers only does not hear the session"
    );
    let _ = tables.undeclare_subscriber(any.handle);
    assert_eq!(tables.epoch(), 3);
    assert!(
        !tables.has_local_matching("a/b"),
        "the subscriber of peers only is no local match"
    );
}

/// The table set is the session's own id space: a peer's `M=0` key that names a key expression
/// the session declared is read from the set's own table and reaches the subscriber on that key,
/// with no space installed on the peer's side, and one that names an id the session never declared
/// reaches nothing; a space a host installs there is read before the tables. The CONTROL is the
/// peer's side alone, which holds no own space.
#[cfg(all(
    feature = "alloc",
    feature = "storage-profile",
    feature = "codec-push",
    target_has_atomic = "ptr",
    any(feature = "pubsub-put", feature = "pubsub-delete")
))]
#[test]
fn the_tables_are_the_own_space_a_peers_alias_is_read_from() {
    use crate::network_message::NetworkMessage;
    use crate::pubsub::SubscriberPeer;
    use crate::reliability::Reliability;
    use wz_codecs::lent::{Push, Wireexpr, WireexprNonlocal, WireexprVariant};

    let push_naming_ours = |id: ExprId| {
        Push {
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                    id,
                    suffix_len: None,
                    suffix: None,
                }),
            },
            ..Push::default()
        }
        .try_into_owned_in::<crate::wire::WireStorage>()
        .unwrap()
    };
    let mut tables = SessionTables::<Sinks>::new();
    let declared = tables.declare_keyexpr("ours/temp").unwrap();
    let subscriber = tables
        .declare_subscriber(
            "ours/temp",
            Locality::Any,
            KeyForm::default(),
            Counted::default(),
        )
        .unwrap();
    let mut peer = SubscriberPeer::<crate::bounded::Heap>::default();
    assert!(
        !peer.mapping_spaces().has_own(),
        "CONTROL: the peer's side holds no own space"
    );
    peer.dispatch(
        &mut tables,
        &mut Handed::default(),
        &NetworkMessage::Push(alloc::boxed::Box::new(push_naming_ours(declared.id))),
        Reliability::Reliable,
    );
    assert_eq!(
        heard(&tables, subscriber.handle),
        1,
        "read from the set's own table"
    );
    peer.dispatch(
        &mut tables,
        &mut Handed::default(),
        &NetworkMessage::Push(alloc::boxed::Box::new(push_naming_ours(declared.id + 1))),
        Reliability::Reliable,
    );
    assert_eq!(
        heard(&tables, subscriber.handle),
        1,
        "an id never declared reaches nothing"
    );
    // A space a host installs on the peer's side is read before the tables: the same id names
    // the key the host holds for it.
    let elsewhere = tables
        .declare_subscriber(
            "installed/key",
            Locality::Any,
            KeyForm::default(),
            Counted::default(),
        )
        .unwrap();
    let mut installed = hashbrown::HashMap::new();
    installed.insert(declared.id, std::string::String::from("installed/key"));
    let installed: crate::wireexpr_resolve::SharedOwnMappingSpace =
        alloc::sync::Arc::new(installed);
    peer.set_own_mapping_space(installed);
    peer.dispatch(
        &mut tables,
        &mut Handed::default(),
        &NetworkMessage::Push(alloc::boxed::Box::new(push_naming_ours(declared.id))),
        Reliability::Reliable,
    );
    assert_eq!(
        (
            heard(&tables, elsewhere.handle),
            heard(&tables, subscriber.handle)
        ),
        (1, 1),
        "the installed space is read first"
    );
}

/// A Push naming id `id` in the receiver's own space (`M=0`), or in the sender's (`M=1`) when
/// `theirs`.
#[cfg(all(
    feature = "alloc",
    feature = "storage-profile",
    feature = "codec-push",
    feature = "codec-declare",
    target_has_atomic = "ptr",
    any(feature = "pubsub-put", feature = "pubsub-delete")
))]
fn push_naming(id: ExprId, theirs: bool) -> crate::wire::PushOwned {
    use wz_codecs::lent::{Push, Wireexpr, WireexprLocal, WireexprNonlocal, WireexprVariant};
    let body = if theirs {
        WireexprVariant::WireexprLocal(WireexprLocal {
            id,
            suffix_len: None,
            suffix: None,
        })
    } else {
        WireexprVariant::WireexprNonlocal(WireexprNonlocal {
            id,
            suffix_len: None,
            suffix: None,
        })
    };
    Push {
        keyexpr: Wireexpr { body },
        ..Push::default()
    }
    .try_into_owned_in::<crate::wire::WireStorage>()
    .unwrap()
}

/// The peer's declaration of `key` under id `id` in its own space.
#[cfg(all(
    feature = "alloc",
    feature = "storage-profile",
    feature = "codec-push",
    feature = "codec-declare",
    target_has_atomic = "ptr",
    any(feature = "pubsub-put", feature = "pubsub-delete")
))]
fn peer_declares(id: ExprId, key: &str) -> crate::network_message::NetworkMessage {
    use wz_session_core_test_support as fx;
    crate::network_message::NetworkMessage::Declare(alloc::boxed::Box::new(
        fx::declare_envelope_decl_kexpr(fx::decl_kexpr(u64::from(id), key)),
    ))
}

/// The own-space witness of the table set: the peer and the session each declared the same id, the
/// peer as `theirs/x` and the session as `ours/x`, and a peer's `M=0` alias of that id is read
/// from the session's table and reaches the subscriber on `ours/x` alone. The CONTROL is the
/// same id under `M=1`, read from the peer's space, which reaches `theirs/x`; its twin without
/// an own space is what shows the fixture tells the two spaces apart.
#[cfg(all(
    feature = "alloc",
    feature = "storage-profile",
    feature = "codec-push",
    feature = "codec-declare",
    target_has_atomic = "ptr",
    any(feature = "pubsub-put", feature = "pubsub-delete")
))]
#[test]
fn an_own_space_resolves_a_peers_alias_to_our_literal_on_a_colliding_id() {
    use crate::pubsub::SubscriberPeer;
    use crate::reliability::Reliability;

    let mut tables = SessionTables::<Sinks>::new();
    let ours = tables.declare_keyexpr("ours/x").unwrap();
    let on_ours = tables
        .declare_subscriber(
            "ours/x",
            Locality::Any,
            KeyForm::default(),
            Counted::default(),
        )
        .unwrap();
    let on_theirs = tables
        .declare_subscriber(
            "theirs/x",
            Locality::Any,
            KeyForm::default(),
            Counted::default(),
        )
        .unwrap();
    let mut peer = SubscriberPeer::<crate::bounded::Heap>::default();
    let mut cx = Handed::default();
    peer.dispatch(
        &mut tables,
        &mut cx,
        &peer_declares(ours.id, "theirs/x"),
        Reliability::Reliable,
    );
    peer.dispatch(
        &mut tables,
        &mut cx,
        &crate::network_message::NetworkMessage::Push(alloc::boxed::Box::new(push_naming(
            ours.id, true,
        ))),
        Reliability::Reliable,
    );
    assert_eq!(
        (
            heard(&tables, on_ours.handle),
            heard(&tables, on_theirs.handle)
        ),
        (0, 1),
        "CONTROL: the id in the peer's space is the peer's key"
    );
    peer.dispatch(
        &mut tables,
        &mut cx,
        &crate::network_message::NetworkMessage::Push(alloc::boxed::Box::new(push_naming(
            ours.id, false,
        ))),
        Reliability::Reliable,
    );
    assert_eq!(
        (
            heard(&tables, on_ours.handle),
            heard(&tables, on_theirs.handle)
        ),
        (1, 1),
        "the same id in our space is our literal, not the peer's"
    );
}

/// The anti-vacuity twin: the same colliding id and the same alias, read by subscriptions that
/// hold no own space (a subscriber table, whose `own_space` is none), so the peer's space is all
/// there is. The `M=0` alias then resolves to nothing at all, neither key: it is not read from the
/// peer's space in place of ours. The CONTROL is the `M=1` alias, which still reaches `theirs/x`,
/// so the fixture can deliver.
#[cfg(all(
    feature = "alloc",
    feature = "storage-profile",
    feature = "codec-push",
    feature = "codec-declare",
    target_has_atomic = "ptr",
    any(feature = "pubsub-put", feature = "pubsub-delete")
))]
#[test]
fn without_an_own_space_a_peers_alias_resolves_to_nothing() {
    use crate::pubsub::{SubscriberPeer, SubscriberTable};
    use crate::reliability::Reliability;
    use crate::sink::{BoxedSink, SampleView};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let id: ExprId = 1;
    let mut subscribers = SubscriberTable::<BoxedSink>::default();
    let count = |seen: &Arc<AtomicUsize>| {
        let seen = Arc::clone(seen);
        BoxedSink::new(move |_: &dyn SampleView| {
            seen.fetch_add(1, Ordering::Relaxed);
        })
    };
    let (ours, theirs) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    subscribers
        .register_sink("ours/x", Locality::Any, count(&ours))
        .unwrap();
    subscribers
        .register_sink("theirs/x", Locality::Any, count(&theirs))
        .unwrap();
    let mut peer = SubscriberPeer::<crate::bounded::Heap>::default();
    peer.dispatch(
        &mut subscribers,
        &mut (),
        &peer_declares(id, "theirs/x"),
        Reliability::Reliable,
    );
    peer.dispatch(
        &mut subscribers,
        &mut (),
        &crate::network_message::NetworkMessage::Push(alloc::boxed::Box::new(push_naming(
            id, true,
        ))),
        Reliability::Reliable,
    );
    let seen = || (ours.load(Ordering::Relaxed), theirs.load(Ordering::Relaxed));
    assert_eq!(
        seen(),
        (0, 1),
        "CONTROL: the peer's own id is the peer's key"
    );
    peer.dispatch(
        &mut subscribers,
        &mut (),
        &crate::network_message::NetworkMessage::Push(alloc::boxed::Box::new(push_naming(
            id, false,
        ))),
        Reliability::Reliable,
    );
    assert_eq!(
        seen(),
        (0, 1),
        "with no own space an M=0 alias reaches no key, the peer's least of all"
    );
}

/// How many samples the subscriber `handle` names was handed.
fn heard(tables: &SessionTables<Sinks>, handle: SubscriberHandle) -> usize {
    tables.subscribers().get(handle).unwrap().callback().0.get()
}

/// A pair reads each half under the storage policy that keeps it: the peer's aliases of the
/// static policy, and our own space the table set's declarations of the build's policy, handed
/// beside the pair. Under one id, `M=1` reads the peer's literal and `M=0` ours; with no own space
/// handed the `M=0` key resolves to nothing, and a space installed on the pair is read before the
/// tables.
#[cfg(all(feature = "alloc", feature = "storage-profile"))]
#[test]
fn a_pair_reads_each_half_under_the_policy_that_keeps_it() {
    use crate::id_map::{key_text_as, FixedIdMap, IdMap, PeerAliases};
    use crate::wireexpr_resolve::{
        resolve_wireexpr_into_over, KeyexprBuf, MappingSpaces, OwnMappingSpace, OwnSpace,
    };
    use wz_codecs::wireexpr::WireexprOwnedVariant;
    use wz_codecs::wireexpr_local::WireexprLocalOwned;
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocalOwned;

    let mut tables = SessionTables::<Sinks>::new();
    let declared = tables.declare_keyexpr("ours/temp").unwrap();
    let mut peer: PeerAliases<Static> = FixedIdMap::new();
    let key = key_text_as::<Static>(&crate::bounded::InlineKeys, "peers/temp")
        .expect("the key fits a row");
    peer.bind(crate::wire_id::peer_key(declared.id), key)
        .expect("the table has room");
    let sender: WireexprOwnedVariant = WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
        id: declared.id,
        suffix_len: None,
        suffix: None,
    });
    let receiver: WireexprOwnedVariant =
        WireexprOwnedVariant::WireexprNonlocal(WireexprNonlocalOwned {
            id: declared.id,
            suffix_len: None,
            suffix: None,
        });
    let spaces = MappingSpaces::<Static, Static>::for_aliases(&peer, None);
    let own = Some(OwnSpace::of_keyexprs(&tables.keyexprs));
    let mut out = KeyexprBuf::new();
    assert_eq!(
        resolve_wireexpr_into_over(&sender, spaces, own, &mut out),
        Ok(Some("peers/temp")),
        "M=1 reads the peer's aliases"
    );
    assert_eq!(
        resolve_wireexpr_into_over(&receiver, spaces, own, &mut out),
        Ok(Some("ours/temp")),
        "M=0 reads the table set's declarations under the same id"
    );
    assert_eq!(
        resolve_wireexpr_into_over(&receiver, spaces, None::<OwnSpace<'_, Static>>, &mut out),
        Ok(None),
        "CONTROL: with no own space handed the M=0 key resolves to nothing"
    );
    let mut installed: hashbrown::HashMap<crate::wire_id::ExprId, std::string::String> =
        hashbrown::HashMap::new();
    installed.insert(declared.id, std::string::String::from("installed/temp"));
    let with_handle = MappingSpaces::<Static, Static>::for_aliases(
        &peer,
        Some(&installed as &dyn OwnMappingSpace),
    );
    assert_eq!(
        resolve_wireexpr_into_over(&receiver, with_handle, own, &mut out),
        Ok(Some("installed/temp")),
        "a space installed on the pair is read before the tables"
    );
}

/// A key delivered again at the same epoch is answered from the match cache, the same function
/// the subscriber table delivers through; a subscriber declared in the place an undeclared one
/// left is reached, and the cache answers nothing it remembered from before.
#[cfg(feature = "alloc")]
#[test]
fn a_key_delivered_again_is_answered_from_the_match_cache_until_the_subscribers_change() {
    use crate::bounded::Heap;
    use crate::pubsub::{LocalSubscribers, MATCH_SCANS};
    let scans = || MATCH_SCANS.with(|count| count.get());
    let count = |_, row: RowAccess<'_, Counted>| row.row().hear();
    let mut tables = SessionTables::<Sinks, Heap>::new();
    tables.limit_memo_to(4);
    assert_eq!(tables.memo_slot_count(), 4);
    let first = tables
        .declare_subscriber("a/x", Locality::Any, KeyForm::default(), Counted::default())
        .unwrap();
    let start = scans();
    for _ in 0..3 {
        assert_eq!(tables.fire_matching("a/x", false, false, count), 1);
    }
    assert_eq!(
        scans() - start,
        1,
        "matched once, then answered from the cache"
    );
    let gone = tables.undeclare_subscriber(first.handle).unwrap();
    assert_eq!(gone.taken.unwrap().0.get(), 3);
    let second = tables
        .declare_subscriber("a/x", Locality::Any, KeyForm::default(), Counted::default())
        .unwrap();
    assert_eq!(
        second.handle.to_bits().get() & 0xFFFF,
        first.handle.to_bits().get() & 0xFFFF,
        "the second subscriber takes the place the first left"
    );
    let start = scans();
    assert_eq!(tables.fire_matching("a/x", false, false, count), 1);
    assert_eq!(
        scans() - start,
        1,
        "the subscribers changed: matched afresh"
    );
    assert_eq!(
        tables
            .subscribers()
            .get(second.handle)
            .unwrap()
            .callback()
            .0
            .get(),
        1
    );
    tables.limit_memo_to(0);
    assert_eq!(tables.memo_slot_count(), 0);
    let start = scans();
    assert_eq!(tables.fire_matching("a/x", false, false, count), 1);
    assert_eq!(tables.fire_matching("a/x", false, false, count), 1);
    assert_eq!(scans() - start, 2, "no cache: every key is matched");
}

/// A subscriber undeclared while a call of its callback runs leaves every delivery at once, the
/// cache's answers among them, and the session-local half of a matching verdict, while its row
/// waits in its place for its last call to end.
#[test]
fn a_retired_subscriber_is_neither_delivered_to_nor_counted_as_matching() {
    use crate::pubsub::LocalSubscribers;
    let count = |_, row: RowAccess<'_, Counted>| row.row().hear();
    // A row read in place lies in the arena.
    let rows = small_rows();
    let mut arena = arena(SessionTables::<Sinks, Lent>::arena_bytes(&rows).unwrap());
    let mut tables = SessionTables::<Sinks, Lent>::lent(&mut arena, keys(256), &rows).unwrap();
    let sub = tables
        .declare_subscriber("a/x", Locality::Any, KeyForm::default(), Counted::default())
        .unwrap();
    assert_eq!(tables.fire_matching("a/x", true, false, count), 1);
    assert!(tables.has_local_matching("a/x"));
    let call = tables.begin_subscriber(sub.handle).unwrap();
    let undeclared = tables.undeclare_subscriber(sub.handle).unwrap();
    assert!(undeclared.taken.is_none(), "let go of by the last call");
    assert_eq!(tables.fire_matching("a/x", true, false, count), 0);
    assert_eq!(tables.fire_matching("a/x", false, true, count), 0);
    assert!(!tables.has_local_matching("a/x"));
    assert!(ended::<Counted>(call));
    let row = tables.release_subscriber(sub.handle).unwrap();
    assert_eq!(
        row.callback().0.get(),
        1,
        "delivered to once, before it was undeclared"
    );
}

/// A peer's message is matched afresh where the delivery may not allocate (the in-place receive
/// path), through the cache otherwise, and reaches only the subscribers that hear peers.
#[cfg(feature = "alloc")]
#[test]
fn a_peers_message_is_matched_afresh_where_it_may_not_allocate() {
    use crate::bounded::Heap;
    use crate::pubsub::{LocalSubscribers, PeerDelivery, MATCH_SCANS};
    let scans = || MATCH_SCANS.with(|count| count.get());
    let count = |_, row: RowAccess<'_, Counted>| row.row().hear();
    let mut tables = SessionTables::<Sinks, Heap>::new();
    tables.limit_memo_to(4);
    let peers = tables
        .declare_subscriber(
            "a/x",
            Locality::Remote,
            KeyForm::default(),
            Counted::default(),
        )
        .unwrap();
    let own = tables
        .declare_subscriber(
            "a/x",
            Locality::SessionLocal,
            KeyForm::default(),
            Counted::default(),
        )
        .unwrap();
    let lent = PeerDelivery {
        no_allocation: true,
        ..PeerDelivery::default()
    };
    let start = scans();
    for _ in 0..2 {
        assert_eq!(tables.deliver_from_peer("a/x", None, lent, count), 1);
    }
    assert_eq!(scans() - start, 2, "no cache slot is taken");
    let start = scans();
    for _ in 0..2 {
        assert_eq!(
            tables.deliver_from_peer("a/x", None, PeerDelivery::default(), count),
            1
        );
    }
    assert_eq!(scans() - start, 1, "the cache answers the second");
    assert_eq!(
        tables
            .subscribers()
            .get(peers.handle)
            .unwrap()
            .callback()
            .0
            .get(),
        4
    );
    assert_eq!(
        tables
            .subscribers()
            .get(own.handle)
            .unwrap()
            .callback()
            .0
            .get(),
        0,
        "a subscriber of the session's own messages hears no peer"
    );
}

/// A sink that counts the plain frames it was told ended.
#[cfg(feature = "alloc")]
#[derive(Default)]
struct FrameEnds(usize);

#[cfg(feature = "alloc")]
impl crate::sink::SampleSink for FrameEnds {
    fn deliver(&mut self, _sample: &dyn crate::sink::SampleView) {}

    fn end_plain_frame(&mut self) {
        self.0 += 1;
    }
}

/// Callbacks whose subscribers count the ends of plain frames.
#[cfg(feature = "alloc")]
enum FrameSinks {}

#[cfg(feature = "alloc")]
impl RowCallbacks for FrameSinks {
    type Subscriber = FrameEnds;
    type Queryable = u32;
    type LivelinessSubscriber = u32;
    type Matching = u32;
    type Reply = u32;
    type QueryablePresence = Present;
    type LivelinessPresence = Present;
    type FilterPresence = Present;
    type GetPresence = Present;
}

/// The end of a plain frame is told to every subscriber, whatever it hears.
#[cfg(feature = "alloc")]
#[test]
fn every_subscriber_is_told_a_plain_frame_ended() {
    use crate::pubsub::LocalSubscribers;
    let mut tables = SessionTables::<FrameSinks>::new();
    let any = tables
        .declare_subscriber("a", Locality::Any, KeyForm::default(), FrameEnds::default())
        .unwrap();
    let own = tables
        .declare_subscriber(
            "b",
            Locality::SessionLocal,
            KeyForm::default(),
            FrameEnds::default(),
        )
        .unwrap();
    tables.end_plain_frame(&mut ());
    assert_eq!(
        tables.subscribers().get(any.handle).unwrap().callback().0,
        1
    );
    assert_eq!(
        tables.subscribers().get(own.handle).unwrap().callback().0,
        1
    );
}

/// A delivery context that keeps nothing in the rows: it counts each delivery into the row and
/// records the handle the row was named by.
#[derive(Default)]
struct Handed(Vec<SubscriberHandle>);

impl crate::sink::SampleDelivery<Counted, SubscriberHandle> for Handed {
    fn deliver(
        &mut self,
        id: SubscriberHandle,
        row: RowAccess<'_, Counted>,
        _sample: &dyn crate::sink::SampleView,
        _turn: crate::sink::FanOut,
    ) {
        row.row().hear();
        self.0.push(id);
    }
}

/// A sample published by the session reaches, through the context it is handed, every row that
/// hears the session, each named by the handle the tables gave it; a row that hears only peers
/// is not handed it.
#[test]
fn a_delivery_names_each_row_it_reaches_by_its_handle() {
    use crate::pubsub::LocalSubscribers;
    let mut tables = SessionTables::<Sinks>::new();
    let any = tables
        .declare_subscriber("a/b", Locality::Any, KeyForm::default(), Counted::default())
        .unwrap();
    let remote = tables
        .declare_subscriber(
            "a/b",
            Locality::Remote,
            KeyForm::default(),
            Counted::default(),
        )
        .unwrap();
    // Literal keys: a build without the wildcard features reads `*` as a literal chunk.
    let own = tables
        .declare_subscriber(
            "a/b",
            Locality::SessionLocal,
            KeyForm::default(),
            Counted::default(),
        )
        .unwrap();
    let sample = crate::sink::BorrowedSample {
        keyexpr: "a/b",
        payload: b"x",
        kind: crate::sample_kind::SampleKind::Put,
        reliability: crate::reliability::Reliability::Reliable,
    };
    let mut handed = Handed::default();
    assert_eq!(tables.local_publish(&mut handed, &sample), 2);
    assert_eq!(handed.0, std::vec![any.handle, own.handle]);
    assert_eq!(heard(&tables, any.handle), 1);
    assert_eq!(heard(&tables, own.handle), 1);
    assert_eq!(heard(&tables, remote.handle), 0);
    // The same key again is answered from the match cache, which keeps places: the rows are
    // still named by their handles.
    assert_eq!(tables.local_publish(&mut handed, &sample), 2);
    assert_eq!(
        handed.0,
        std::vec![any.handle, own.handle, any.handle, own.handle]
    );
}

#[test]
fn a_refused_subscriber_leaves_the_epoch_where_it_was() {
    use crate::pubsub::LocalSubscribers;
    let mut tables = SessionTables::<Sinks>::new();
    tables.limit_to(&TableRows {
        subscribers: 0,
        ..rows()
    });
    assert!(tables
        .declare_subscriber("a", Locality::Any, KeyForm::default(), Counted::default())
        .is_err());
    assert_eq!(tables.epoch(), 0);
}

#[cfg(all(feature = "declare-subscriber", feature = "interest-answer"))]
#[test]
fn a_peers_subscriber_interest_is_answered_out_of_the_tables() {
    use crate::pubsub::{SubInterestReply, SubscriberPeer};
    let mut tables = SessionTables::<Sinks>::new();
    let sub = tables
        .declare_subscriber("a/b", Locality::Any, KeyForm::default(), Counted::default())
        .unwrap();
    tables
        .declare_subscriber("c", Locality::Any, KeyForm::default(), Counted::default())
        .unwrap();
    let mut peer: SubscriberPeer = SubscriberPeer::default();
    // A CURRENT interest on a/b: one subscription answers it, then the Final.
    assert_eq!(
        peer.answer_subscriber_interest(&mut tables, 7, Some("a/b"), false, true, false),
        1
    );
    let staged = peer.take_staged_sub_interest_replies();
    assert_eq!(staged.len(), 2);
    let concrete = staged.first().unwrap();
    assert!(matches!(
        concrete,
        SubInterestReply::Concrete { interest_id: 7, .. }
    ));
    assert_eq!(
        peer.sub_interest_reply(&tables, concrete),
        Some((u64::from(sub.id), "a/b"))
    );
    assert!(matches!(
        staged.last(),
        Some(SubInterestReply::Final { interest_id: 7 })
    ));
    // The remembered row took the next entity id from the tables' one space.
    let after = tables.next_entity_id();
    assert_eq!(after, Some(sub.id + 3));
    // A FUTURE interest is told of a subscription registered after it.
    assert_eq!(
        peer.answer_subscriber_interest(&mut tables, 8, Some("d/e"), false, false, true),
        0
    );
    let _ = peer.take_staged_sub_interest_replies();
    let later = tables
        .declare_subscriber("d/e", Locality::Any, KeyForm::default(), Counted::default())
        .unwrap();
    peer.stage_registered(&tables, u64::from(later.id));
    let pushed = peer.take_staged_sub_interest_replies();
    assert!(pushed.iter().any(|item| matches!(
        item,
        SubInterestReply::Concrete { interest_id: 8, subscription_id } if *subscription_id == u64::from(later.id)
    )));
    assert_eq!(
        peer.sub_interest_reply(&tables, &SubInterestReply::Final { interest_id: 8 }),
        None
    );
}

/// The table set's queryables are matched by the functions the queryable registry's are: a remote
/// query reaches the queryables that answer peers, in declaration order; an `AllComplete` query
/// only the complete one; a session-local one only those that answer the session; and the
/// session-local half of a querier's verdict reads the same rows.
#[test]
fn a_query_reaches_the_table_sets_queryables_by_the_registrys_rule() {
    use crate::query::LocalQueryables;
    use crate::query_mode::QueryTarget;
    let mut tables = Tables::new();
    for (key, origin, complete, callback) in [
        ("q/a", Locality::Any, false, 1),
        ("q/a", Locality::Remote, true, 2),
        ("q/a", Locality::SessionLocal, true, 3),
        ("other", Locality::Any, true, 4),
    ] {
        tables
            .declare_queryable(key, origin, complete, KeyForm::default(), callback)
            .unwrap();
    }
    let fire = |tables: &mut Tables, remote: bool, target: Option<QueryTarget>| {
        let mut asked = Vec::new();
        let fired = tables.queryables.fire_matching_queryables(
            "q/a",
            KeyFacts::of("q/a"),
            remote,
            target,
            |_, callback: RowAccess<'_, u32>| asked.push(*callback.row()),
        );
        assert_eq!(fired, asked.len());
        asked
    };
    assert_eq!(fire(&mut tables, true, None), [1, 2]);
    assert_eq!(fire(&mut tables, true, Some(QueryTarget::AllComplete)), [2]);
    assert_eq!(fire(&mut tables, false, None), [1, 3]);
    #[cfg(feature = "storage-profile")]
    {
        assert!(tables.queryables.has_local_queryable("q/a", false));
        assert!(!tables.queryables.has_local_queryable("elsewhere", false));
    }
}

/// The table set's liveliness subscribers are told a peer's tokens by the registry's rule: a live
/// token reaches every subscriber on a key it intersects, a historical one only those that asked
/// for history; a subscriber is found by its Interest's id, and the responder's end of its history
/// marks it.
#[test]
fn a_token_reaches_the_table_sets_liveliness_subscribers_by_the_registrys_rule() {
    use crate::declare::liveliness_subscriber::LocalLivelinessSubscribers;
    let mut tables = Tables::new();
    tables
        .declare_liveliness_subscriber("l/a", false, KeyForm::default(), 1)
        .unwrap();
    let history = tables
        .declare_liveliness_subscriber("l/a", true, KeyForm::default(), 2)
        .unwrap();
    tables
        .declare_liveliness_subscriber("other", true, KeyForm::default(), 3)
        .unwrap();
    let tell = |tables: &mut Tables, historical: bool| {
        let mut told = Vec::new();
        let fired = tables.liveliness_subscribers.fire_matching(
            "l/a",
            historical,
            |_, row: RowAccess<'_, u32>| told.push(*row.row()),
        );
        assert_eq!(fired, told.len());
        told
    };
    assert_eq!(tell(&mut tables, false), [1, 2]);
    assert_eq!(tell(&mut tables, true), [2]);
    let id = u64::from(
        tables
            .liveliness_subscribers()
            .get(history.handle)
            .unwrap()
            .id(),
    );
    assert_eq!(tables.liveliness_subscribers.pattern_of(id), Some("l/a"));
    assert_eq!(
        tables
            .liveliness_subscribers
            .row_of(id)
            .map(|(handle, _)| handle),
        Some(history.handle)
    );
    let complete = |tables: &Tables| {
        tables
            .liveliness_subscribers()
            .get(history.handle)
            .unwrap()
            .history_complete()
    };
    assert!(!complete(&tables));
    tables.liveliness_subscribers.mark_history_complete(id);
    assert!(complete(&tables));
}

/// A filter that asks the peers nothing holds no Interest and spends no id, and is judged on its
/// own key; a listener on it reads that key, and goes with it. Turned red by a filter that still
/// holds an Interest, or a listener that finds no key without one.
#[test]
fn a_filter_that_asks_nothing_is_judged_on_its_own_key() {
    let mut tables = Tables::new();
    let before = tables.next_entity_id();
    let quiet = tables
        .declare_write_filter_as(Plane::Subscribers, "q", false, None, None)
        .unwrap();
    assert_eq!(quiet.interest, None);
    assert_eq!(tables.interests().len(), 0, "no Interest held");
    assert_eq!(tables.next_entity_id(), before, "no id spent");
    let row = tables.write_filters().get(quiet.handle).unwrap();
    assert_eq!((row.interest(), row.key()), (None, "q"));
    let peers = Peers::default();
    peers.declares.set(true);
    assert_eq!(tables.write_filter_open(quiet.handle, &peers), Some(true));
    let listener = tables.declare_matching_listener(quiet.handle, 4).unwrap();
    let mut cursor = 0;
    assert_eq!(
        tables.next_matching_change(&mut cursor, &peers),
        Some((quiet.handle, true)),
        "the filter is read on its own key for its listener"
    );
    let mut gone = Vec::new();
    let unwatched = tables
        .undeclare_write_filter(quiet.handle, |handle, _| gone.push(handle))
        .unwrap();
    assert_eq!(unwatched.interest_final, None);
    assert_eq!(gone, [listener]);
}

/// A write filter's row holds the declaration its entity's key is named by from its declaration to
/// its undeclaration, which hands the row's hold to the caller, whose giving it back retracts the
/// declaration when the row held it last; a count with no room refuses the filter, keeping nothing
/// and opening no Interest. Turned red by a row that takes no hold, an undeclaration that hands
/// none over or lets it go itself, or a filter kept past a full count.
#[test]
fn a_write_filter_holds_its_keys_declaration_until_it_goes() {
    let mut tables = Tables::new();
    let declared = tables.declare_keyexpr("demo/pub").unwrap();
    let holds = |tables: &Tables| {
        tables
            .keyexprs()
            .get(declared.handle)
            .map(|row| row.holds())
    };
    let filter = tables
        .declare_write_filter_as(
            Plane::Subscribers,
            "demo/pub",
            false,
            None,
            Some(declared.handle),
        )
        .unwrap();
    assert_eq!(holds(&tables), Some(2), "the declarer's and the row's");
    assert_eq!(
        tables.write_filters().get(filter.handle).unwrap().own(),
        Some(declared.handle)
    );
    assert_eq!(
        tables.undeclare_keyexpr(declared.handle),
        None,
        "the row still holds it"
    );
    let unwatched = tables
        .undeclare_write_filter(filter.handle, |_, _| {})
        .unwrap();
    assert_eq!(
        unwatched.held,
        Some(declared.handle),
        "the row's hold goes to the caller"
    );
    assert_eq!(
        holds(&tables),
        Some(1),
        "kept until the caller gives it back"
    );
    assert_eq!(
        tables.undeclare_keyexpr(declared.handle),
        Some(declared.id),
        "the row's was the last hold"
    );
    assert_eq!(holds(&tables), None, "gone with its last holder");

    let full = tables.declare_keyexpr("demo/full").unwrap();
    while tables.retain_keyexpr(full.handle) {}
    let interests = tables.interests().len();
    assert!(matches!(
        tables.declare_write_filter_as(
            Plane::Subscribers,
            "demo/full",
            false,
            Some(InterestName::whole("demo/full")),
            Some(full.handle),
        ),
        Err(RegisterError::KeyexprHoldsFull)
    ));
    assert_eq!(
        tables.interests().len(),
        interests,
        "no Interest was opened"
    );
    assert_eq!(
        tables.keyexprs().get(full.handle).map(|row| row.holds()),
        Some(KeyexprHolds::MAX),
        "CONTROL: the count is full"
    );
}

/// A listener declared on a key opens an Interest of its own on the key whole, apart from a filter
/// on the same key and kind, and its undeclaration hands back that Interest's Final; it is told
/// its changes as one on a filter is. Turned red by a listener that takes the filter's Interest,
/// or keeps its own open once it is gone.
#[test]
fn a_listener_on_a_key_opens_an_interest_of_its_own() {
    let mut tables = Tables::new();
    let alone = tables
        .declare_matching_listener_on(Plane::Subscribers, "m", true, 6)
        .unwrap();
    let opened = alone.interest.expect("a new Interest");
    let asked = opened.id;
    let listener = tables.matching_listeners().get(alone.handle).unwrap();
    assert!(listener.owns_filter());
    let own = listener.filter();
    let interest = tables.write_filters().get(own).unwrap().interest().unwrap();
    assert_eq!(
        interest, opened.handle,
        "the listener's own filter holds the Interest it opened"
    );
    let row = tables.interests().get(interest).unwrap();
    assert_eq!(
        (row.mapping_id(), row.suffix(), row.aggregate()),
        (0, Some("m"), false)
    );
    let filter = tables
        .declare_write_filter(Plane::Subscribers, "m", false)
        .unwrap();
    let filters = filter
        .interest
        .expect("the filter asks apart from the listener");
    assert_ne!(filters.id, asked);
    assert_eq!(tables.interests().len(), 2);
    let sub = subscribe(&mut tables, "m", Locality::Any, 1);
    let mut cursor = 0;
    assert_eq!(
        tables.next_matching_change(&mut cursor, &NoPeers),
        Some((own, true)),
        "the listener's own filter is read; the entity's, with no listener, is not"
    );
    let _ = tables.undeclare_subscriber(sub.handle);
    let first = tables.undeclare_matching_listener(alone.handle).unwrap();
    assert_eq!(
        first.interest_final,
        Some(asked),
        "its own filter and Interest end with it"
    );
    assert!(first.row.is_some());
    assert!(tables.write_filters().get(own).is_none());
    assert_eq!(tables.interests().len(), 1, "the entity's filter's stands");
    assert_eq!(
        tables
            .undeclare_write_filter(filter.handle, |_, _| {})
            .unwrap()
            .interest_final,
        Some(filters.id)
    );
    assert_eq!(tables.interests().len(), 0);
}

/// A matching listener declared on a key judges through a filter of its own, held to the key
/// listeners' rows and not to the publishers' bound, and gone with the listener; one past those
/// rows is refused with its callback, nothing opened. Turned red by a listener's filter counted as
/// a publisher's, one taken past the key listeners' rows, or one left behind by its listener.
#[test]
fn a_key_listeners_filter_is_held_to_the_key_listeners_rows() {
    let mut tables = Tables::new();
    tables.limit_to(&TableRows {
        publishers: 1,
        key_listeners: 1,
        ..rows()
    });
    assert!(tables
        .declare_write_filter(Plane::Subscribers, "p", false)
        .is_ok());
    let listener = tables
        .declare_matching_listener_on(Plane::Subscribers, "m", false, 1)
        .expect("the publishers' bound does not hold a listener's filter");
    let refused = tables
        .declare_matching_listener_on(Plane::Subscribers, "n", false, 2)
        .unwrap_err();
    assert_eq!(
        (refused.why, refused.callback),
        (RegisterError::TableFull, 2)
    );
    assert_eq!(
        tables.interests().len(),
        2,
        "the refused listener opened nothing"
    );
    let _ = tables.undeclare_matching_listener(listener.handle);
    assert_eq!(tables.write_filters().len(), 1, "its filter went with it");
    assert!(
        tables
            .declare_matching_listener_on(Plane::Subscribers, "n", false, 3)
            .is_ok(),
        "the row it gave back takes the next"
    );
}

/// An Interest keeps the rest of the key it names as a range of its own key: the tail where the
/// rest ends the key, the place inside the key where it lies elsewhere, and the key whole by no
/// declaration where it lies nowhere in the key, which names the same key. Turned red by a rest
/// read from the wrong range, or one refused.
#[test]
fn an_interest_names_its_rest_by_a_range_of_its_key() {
    let rest = |text: &str| Some(std::string::String::from(text));
    let mut tables = Tables::new();
    let named = |tables: &mut Tables, key: &str, suffix: &str| {
        let filter = tables
            .declare_write_filter_as(
                Plane::Subscribers,
                key,
                false,
                Some(InterestName {
                    mapping_id: 5,
                    suffix: Some(suffix),
                    aggregate: true,
                }),
                None,
            )
            .unwrap();
        let interest = tables
            .write_filters()
            .get(filter.handle)
            .unwrap()
            .interest()
            .unwrap();
        let row = tables.interests().get(interest).unwrap();
        (
            row.mapping_id(),
            row.suffix().map(std::string::String::from),
            row.aggregate(),
        )
    };
    assert_eq!(
        named(&mut tables, "a/b/c", "/c"),
        (5, rest("/c"), true),
        "the tail"
    );
    assert_eq!(
        named(&mut tables, "x/y/x/y", "x/y"),
        (5, rest("x/y"), true),
        "the tail, where the rest lies twice"
    );
    assert_eq!(
        named(&mut tables, "p/q/r", "q"),
        (5, rest("q"), true),
        "inside the key"
    );
    assert_eq!(
        named(&mut tables, "s/t", "u"),
        (0, rest("s/t"), true),
        "nowhere in the key: the key whole"
    );
    assert_eq!(
        named(&mut Tables::new(), "ä/ö/ü", "ö"),
        (5, rest("ö"), true),
        "inside the key, after characters of two bytes"
    );
    assert_eq!(
        named(&mut Tables::new(), "s", "s/t"),
        (0, rest("s"), true),
        "a rest longer than the key: the key whole"
    );
    let plain = tables
        .declare_write_filter_as(
            Plane::Subscribers,
            "n",
            false,
            Some(InterestName {
                mapping_id: 9,
                suffix: None,
                aggregate: false,
            }),
            None,
        )
        .unwrap();
    let interest = tables
        .write_filters()
        .get(plain.handle)
        .unwrap()
        .interest()
        .unwrap();
    let row = tables.interests().get(interest).unwrap();
    assert_eq!((row.mapping_id(), row.suffix()), (9, None), "no rest");
}

/// A matching listener's callback is reached to change through its handle while the listener
/// stands, and not through that handle once the listener is undeclared, even after another took its
/// slot. Turned red by an accessor that reads a retired row or ignores the handle's generation.
#[test]
fn a_listeners_callback_is_reached_by_its_handle_until_it_goes() {
    let mut tables = Tables::new();
    let first = tables
        .declare_matching_listener_on(Plane::Subscribers, "m", false, 1)
        .unwrap();
    if let Some(callback) = tables.matching_listener_callback_mut(first.handle) {
        *callback = 2;
    }
    assert_eq!(
        tables
            .matching_listeners()
            .get(first.handle)
            .map(|row| *row.callback()),
        Some(2),
        "changed in its row"
    );
    let _ = tables.undeclare_matching_listener(first.handle);
    assert_eq!(tables.matching_listener_callback_mut(first.handle), None);
    let second = tables
        .declare_matching_listener_on(Plane::Subscribers, "n", false, 3)
        .unwrap();
    assert_eq!(
        tables.matching_listener_callback_mut(first.handle),
        None,
        "the undeclared listener's handle reaches no row that came since"
    );
    assert_eq!(
        tables
            .matching_listener_callback_mut(second.handle)
            .copied(),
        Some(3)
    );
}

/// A value of a kept kind is held as itself; one of a kind not kept is refused.
#[test]
fn a_record_of_a_kept_kind_holds_its_value_and_one_not_kept_is_refused() {
    let kept = <Present as Presence>::record(7_u64).expect("kept");
    assert_eq!(*<Present as Presence>::read(&kept), 7);
    assert_eq!(<Present as Presence>::take(kept), 7);
    assert!(<Absent as Presence>::record(7_u64).is_none());
}

// Whether a kind is kept is known to the build, of each presence.
const _: () = assert!(<Present as Presence>::KEPT && !<Absent as Presence>::KEPT);

/// A variant that holds a record of a kind not kept takes no room: the enum is as small as its
/// other variant alone, which a kept kind's record outgrows.
#[test]
fn a_variant_of_a_kind_not_kept_takes_no_room() {
    enum Owes<K: Presence> {
        Call(&'static u8),
        Other(K::Record<[u64; 2]>),
    }
    impl<K: Presence> Owes<K> {
        fn first(&self) -> u64 {
            match self {
                Self::Call(byte) => u64::from(**byte),
                Self::Other(other) => K::read(other)[0],
            }
        }
    }
    let both = [Owes::<Present>::Call(&3), Owes::<Present>::Other([5, 6])];
    assert_eq!(both.iter().map(Owes::first).collect::<Vec<_>>(), [3, 5]);
    assert_eq!(
        core::mem::size_of::<Owes<Absent>>(),
        core::mem::size_of::<&u8>()
    );
    assert!(core::mem::size_of::<Owes<Present>>() > core::mem::size_of::<&u8>());
}

/// Each table of declarations is read through its own slots, and a row of any of them named as
/// data has the rank its table's walk gives it. Turned red by a table read through another
/// kind's slots, each table holding a count of rows no other holds.
#[test]
fn each_table_of_declarations_is_read_through_its_own_slots() {
    let mut tables = Tables::new();
    let keyexpr = tables.declare_keyexpr("k").unwrap();
    let subscribers = [
        subscribe(&mut tables, "s0", Locality::Any, 0),
        subscribe(&mut tables, "s1", Locality::Any, 1),
    ];
    let mut interests = Vec::new();
    for key in ["i0", "i1", "i2"] {
        let filter = tables
            .declare_write_filter(Plane::Subscribers, key, false)
            .unwrap();
        interests.push(filter.interest.unwrap().handle);
    }
    let mut queryables = Vec::new();
    for (n, key) in (0u32..).zip(["q0", "q1", "q2", "q3"]) {
        let declared = tables
            .declare_queryable(key, Locality::Any, false, KeyForm::default(), n)
            .unwrap();
        queryables.push(declared.handle);
    }
    let mut tokens = Vec::new();
    for key in ["t0", "t1", "t2", "t3", "t4"] {
        tokens.push(
            tables
                .declare_token(key, KeyForm::default())
                .unwrap()
                .handle,
        );
    }
    let mut lives = Vec::new();
    for (n, key) in (0u32..).zip(["l0", "l1", "l2", "l3", "l4", "l5"]) {
        let declared = tables
            .declare_liveliness_subscriber(key, false, KeyForm::default(), n)
            .unwrap();
        lives.push(declared.handle);
    }
    let lens = [
        DeclaredTable::Keyexprs,
        DeclaredTable::Subscribers,
        DeclaredTable::Interests,
        DeclaredTable::Queryables,
        DeclaredTable::Tokens,
        DeclaredTable::LivelinessSubscribers,
    ]
    .map(|table| tables.slots_of(table).len());
    assert_eq!(lens, [1, 2, 3, 4, 5, 6]);
    let last = [
        DeclaredRow::of(keyexpr.handle),
        DeclaredRow::of(subscribers[1].handle),
        DeclaredRow::of(interests[2]),
        DeclaredRow::of(queryables[3]),
        DeclaredRow::of(tokens[4]),
        DeclaredRow::of(lives[5]),
    ];
    for (declared, len) in last.into_iter().zip(lens) {
        let slots = tables.slots_of(declared.table);
        assert_eq!(slots.rank_of(declared.row), Some(len - 1));
        assert_eq!(slots.nth_live(len - 1), Some(declared.row));
    }
    assert_eq!(
        DeclaredRow::of(subscribers[0].handle).table,
        DeclaredTable::Subscribers
    );
}

/// A plane's write filters are held to its own bound in the table the two planes share: a
/// publisher's filter past the publishers' bound is refused while the table has room, asking
/// nothing and spending no id, and a querier's is still taken up to the queriers' bound. The
/// CONTROL is tables given no bound, which take a second publisher's filter. Turned red by a plane
/// bound that is not read, or one read for the other plane.
#[test]
fn a_planes_write_filters_are_held_to_its_own_bound() {
    let querier = Plane::Queryables {
        complete_required: false,
    };
    let mut tables = Tables::new();
    tables.limit_to(&TableRows {
        publishers: 1,
        queriers: 2,
        ..rows()
    });
    assert!(tables
        .declare_write_filter(Plane::Subscribers, "p0", false)
        .is_ok());
    let before = tables.next_entity_id();
    assert!(matches!(
        tables.declare_write_filter(Plane::Subscribers, "p1", false),
        Err(RegisterError::TableFull)
    ));
    assert_eq!(tables.next_entity_id(), before, "no id spent");
    assert_eq!(tables.interests().len(), 1, "no Interest held for it");
    assert!(tables.declare_write_filter(querier, "q0", false).is_ok());
    assert!(tables.declare_write_filter(querier, "q1", false).is_ok());
    assert!(matches!(
        tables.declare_write_filter(querier, "q2", false),
        Err(RegisterError::TableFull)
    ));

    let mut unbound = Tables::new();
    assert!(unbound
        .declare_write_filter(Plane::Subscribers, "p0", false)
        .is_ok());
    assert!(
        unbound
            .declare_write_filter(Plane::Subscribers, "p1", false)
            .is_ok(),
        "CONTROL: tables given no bound hold a plane to the table's alone"
    );
}

/// The bytes the tables take are what a build whose limits are fixed lays out when it compiles:
/// the same evaluated in a const as at run time, less where a kind is left out, and none past the
/// address space. Turned red by `arena_bytes` no longer a const fn, by a kind left out still
/// counted, or by a table past the address space answered as a size.
#[test]
fn the_tables_bytes_are_the_same_in_a_const_as_at_run_time() {
    const ROWS: TableRows = TableRows {
        keyexprs: 2,
        subscribers: 3,
        queryables: 1,
        tokens: 1,
        liveliness_subscribers: 1,
        publishers: 2,
        queriers: 1,
        matching_listeners: 1,
        key_listeners: 1,
        pending_gets: 2,
        held_replies: 2,
    };
    const AT_BUILD: Option<usize> = SessionTables::<Calls, Lent>::arena_bytes(&ROWS);
    const NONE_KEPT: Option<usize> = SessionTables::<NoneKept, Lent>::arena_bytes(&ROWS);
    let rows = ROWS;
    assert_eq!(
        AT_BUILD,
        SessionTables::<Calls, Lent>::arena_bytes(core::hint::black_box(&rows))
    );
    assert!(AT_BUILD.is_some_and(|bytes| bytes > 0));
    assert!(NONE_KEPT.is_some() && NONE_KEPT < AT_BUILD);
    let past = TableRows {
        subscribers: usize::MAX,
        ..ROWS
    };
    assert_eq!(SessionTables::<Calls, Lent>::arena_bytes(&past), None);
}

/// A plain way kept on a write filter carries the Put's head for the declaration that names its
/// key, written for the QoS the way is sent with, and none for the whole key. Turned red by a way
/// that keeps no head, or one written for another id or another QoS byte than the way's.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
#[test]
fn a_plain_way_carries_the_head_of_its_declaration() {
    use crate::lent_push::PutHead;
    use crate::publish_options::PlainPutParams;
    use crate::sample::QosLevel;
    let mut tables = Tables::new();
    let declared = tables.declare_keyexpr("demo/x").unwrap();
    let filter = tables
        .declare_write_filter(Plane::Subscribers, "demo/x", false)
        .unwrap()
        .handle;
    let head = |tables: &Tables| {
        tables
            .write_filters()
            .get(filter)
            .and_then(|row| row.plain())
            .expect("a way kept")
            .head
    };
    let riding = QosLevel::from_raw(0x1a);
    for qos in [None, Some(riding)] {
        let params = PlainPutParams {
            destination: Locality::Any,
            qos,
            reliable: true,
            express: false,
            priority: crate::qos::Priority::DEFAULT,
        };
        tables.keep_write_filter_plain(filter, Some((params, KeyexprRef::by_id(declared.id))));
        assert_eq!(
            head(&tables),
            PutHead::new(declared.id, qos.unwrap_or(QosLevel::DEFAULT)),
            "the head of the declaration, qos {qos:?}"
        );
        assert!(head(&tables).is_some(), "a declared id has a head");
        tables.keep_write_filter_plain(filter, Some((params, KeyexprRef::by_id(0))));
        assert_eq!(head(&tables), None, "the whole key has none");
    }
}

/// A plain way is planned at an epoch only for its key named by its head's declaration alone, and
/// its put is read back at that epoch alone, named by that declaration and written from the way's
/// head. A way stated again is planned again. Turned red by a plan kept for a key the head does not
/// name (the literal, or a key past the declaration), by a plan read at another epoch, or by a way
/// stated again that keeps its plan.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
#[test]
fn a_plain_way_is_planned_at_one_epoch_for_its_heads_key_alone() {
    use crate::named_key::NamedKey;
    use crate::publish_options::PlainPutParams;
    use crate::wire_key::{MappedId, WireKey};
    let mut tables = Tables::new();
    let declared = tables.declare_keyexpr("demo/x").unwrap();
    let filter = tables
        .declare_write_filter(Plane::Subscribers, "demo/x", false)
        .unwrap()
        .handle;
    let params = PlainPutParams {
        destination: Locality::Any,
        qos: None,
        reliable: true,
        express: false,
        priority: crate::qos::Priority::DEFAULT,
    };
    let at = KeyexprRef::by_id(declared.id);
    tables.keep_write_filter_plain(filter, Some((params, at)));
    let row = tables.write_filters().get(filter).unwrap();
    assert!(row.planned_put(7).is_none(), "no plan yet");
    assert!(
        !row.keep_plan(7, NamedKey::literal("demo/x").unwrap()),
        "the literal is not the key the head names"
    );
    assert!(row.planned_put(7).is_none());
    let past = tables.named_at("demo/x/y", at).expect("a key");
    assert!(
        !row.keep_plan(7, past),
        "a key past the declaration is not the filter's key"
    );
    let named = tables.named_at("demo/x", at).expect("a key");
    assert!(row.keep_plan(7, named));
    let planned = row.planned_put(7).expect("planned at 7");
    assert_eq!(planned.key().text(), "demo/x");
    assert_eq!(
        planned.key().wire(),
        WireKey::Id(MappedId::new(declared.id).unwrap())
    );
    assert_eq!(Some(planned.head()), row.plain().and_then(|way| way.head));
    assert!(row.planned_put(8).is_none(), "another epoch");
    tables.keep_write_filter_plain(filter, Some((params, at)));
    let row = tables.write_filters().get(filter).unwrap();
    assert!(
        row.planned_put(7).is_none(),
        "a way stated again is planned again"
    );
}

/// A plain way kept on a write filter keeps the row of the declaration that names its key, found
/// by its id when the holder gave none, and none for a key that names no declaration; a key named
/// at that row is named as by the declaration's id; a row that no longer holds the id is passed
/// over for the search by id, and a retracted declaration names nothing. Turned red by a kept way
/// that keeps no row, and by a read at a row that holds another declaration.
#[cfg(feature = "alloc")]
#[test]
fn a_plain_way_keeps_its_declarations_row_and_a_key_is_named_there() {
    use crate::named_key::NamedKey;
    use crate::publish_options::PlainPutParams;
    use crate::wire_key::{KeyText, MappedId, WireKey};
    let mut tables = Tables::new();
    let declared = tables.declare_keyexpr("demo/").unwrap();
    let other = tables.declare_keyexpr("other/").unwrap();
    let filter = tables
        .declare_write_filter(Plane::Subscribers, "demo/x", false)
        .unwrap()
        .handle;
    let params = PlainPutParams {
        destination: Locality::Any,
        qos: None,
        reliable: true,
        express: false,
        priority: crate::qos::Priority::DEFAULT,
    };
    let way = |tables: &Tables| {
        tables
            .write_filters()
            .get(filter)
            .and_then(|row| row.plain())
    };
    assert!(way(&tables).is_none(), "no way kept yet");
    let at = KeyexprRef {
        id: declared.id,
        row: Some(declared.handle),
    };
    tables.keep_write_filter_plain(filter, Some((params, KeyexprRef::by_id(declared.id))));
    assert_eq!(way(&tables).expect("a way kept").key, at, "found by its id");
    tables.keep_write_filter_plain(filter, Some((params, at)));
    assert_eq!(way(&tables).unwrap().key, at, "the row the holder gave");
    let stale = KeyexprRef {
        id: declared.id,
        row: Some(other.handle),
    };
    tables.keep_write_filter_plain(filter, Some((params, stale)));
    assert_eq!(
        way(&tables).unwrap().key,
        at,
        "a row of another declaration"
    );
    tables.keep_write_filter_plain(filter, Some((params, KeyexprRef::by_id(0))));
    assert_eq!(way(&tables).unwrap().key.row, None, "a whole key");
    tables.keep_write_filter_plain(filter, Some((params, KeyexprRef::by_id(99))));
    assert_eq!(
        way(&tables).unwrap().key.row,
        None,
        "an id nothing declares"
    );
    tables.keep_write_filter_plain(filter, None);
    assert!(way(&tables).is_none(), "the general way");

    let id = MappedId::new(declared.id).unwrap();
    let under = Some(WireKey::mapped(id, KeyText::new("y")));
    assert_eq!(
        tables.named_at("demo/y", at).map(|named| named.wire()),
        under
    );
    assert_eq!(
        tables.named_at("demo/y", stale).map(|named| named.wire()),
        under,
        "a row of another declaration is passed over"
    );
    assert_eq!(
        tables
            .named_at("demo/y", KeyexprRef::by_id(declared.id))
            .map(|named| named.wire()),
        under
    );
    assert_eq!(tables.keyexpr_at(KeyexprRef::by_id(0)), None);
    assert_eq!(
        tables.key_form_at(stale, Retraction::ById).prefix,
        Some(declared.handle)
    );
    assert_eq!(tables.retract_keyexpr(declared.handle), Some(declared.id));
    assert_eq!(tables.named_at("demo/y", at), NamedKey::literal("demo/y"));
    assert_eq!(tables.keyexpr_at(at), None);

    // A filter the tables no longer hold keeps nothing, and its row reads as none.
    let _ = tables.undeclare_write_filter(filter, |_, _| {});
    tables.keep_write_filter_plain(filter, Some((params, KeyexprRef::by_id(other.id))));
    assert!(way(&tables).is_none());
}

/// A write filter's answer read at the row it holds is its answer read by its handle. Turned red
/// by a row read that keeps the peers' answer apart from the handle's.
#[test]
fn a_write_filter_row_answers_as_its_handle_does() {
    let mut tables = Tables::new();
    let filter = tables
        .declare_write_filter(Plane::Subscribers, "k", false)
        .unwrap()
        .handle;
    let peers = Peers::default();
    let row_open = |tables: &Tables| {
        let row = tables.write_filters().get(filter).unwrap();
        tables.write_filter_row_open(row, &peers)
    };
    assert!(!row_open(&tables));
    assert_eq!(tables.write_filter_open(filter, &peers), Some(false));
    assert_eq!(
        peers.asked.get(),
        1,
        "the row read kept the answer the handle read"
    );
    peers.declares.set(true);
    peers.written.set(1);
    assert!(row_open(&tables));
    assert_eq!(tables.write_filter_open(filter, &peers), Some(true));
    assert_eq!(peers.asked.get(), 2);
}

/// A row read by its handle names the first bytes of a key it declares, and nothing once it went
/// or for a key it does not start; an entity's row lends the declaration of its own key.
///
/// # Control
///
/// Reading the row without checking the key starts with it reds the second assertion; a row that
/// answers after it went reds the third; an entity row lending the declaration its key is named
/// by in place of its own reds the last.
#[test]
fn a_rows_declaration_names_the_keys_it_starts_and_an_entity_lends_its_own() {
    let mut tables = Tables::new();
    let announced = tables.declare_keyexpr("demo/").unwrap();
    let own = tables.declare_keyexpr("demo/x").unwrap();
    assert_eq!(
        tables.declared_prefix(announced.handle, "demo/x/**"),
        Some((announced.id, "demo/".len()))
    );
    assert_eq!(tables.declared_prefix(announced.handle, "other/x"), None);
    let form = KeyForm {
        prefix: Some(announced.handle),
        own: Some(own.handle),
        retraction: Retraction::ById,
    };
    let sub = tables
        .declare_subscriber("demo/x/**", Locality::Any, form, 1)
        .unwrap();
    let row = tables.subscribers().get(sub.handle).unwrap().key();
    assert_eq!(row.as_str(), "demo/x/**");
    assert_eq!(row.named(), Some(own.handle));
    let gone = tables.declare_keyexpr("gone/").unwrap();
    assert_eq!(tables.undeclare_keyexpr(gone.handle), Some(gone.id));
    assert_eq!(tables.declared_prefix(gone.handle, "gone/x"), None);
}

/// Entity ids counted from zero: none given hands out 1 first, the last id is `u32::MAX`, and ids
/// from 0 are ids from 1. Turned red by `EntityIds::next` answering 0 for none given.
#[test]
fn entity_ids_of_zero_hand_out_one_first_and_end_at_the_last() {
    let mut ids = EntityIds::default();
    assert_eq!(ids.next(), Some(1));
    assert_eq!(ids.take(), Some(1));
    assert_eq!(ids.take(), Some(2));
    let mut last = EntityIds::from_next(Some(u32::MAX));
    assert_eq!(last.take(), Some(u32::MAX));
    assert_eq!(last.take(), None);
    assert_eq!(EntityIds::from_next(None).next(), None);
    assert_eq!(EntityIds::from_next(Some(0)).next(), Some(1));
    assert_eq!(EntityIds::from_next(Some(7)).next(), Some(7));
}

/// Plane bounds of zero bytes bind no plane; bounds from rows bind each plane to its own count.
/// Turned red by `of_filter` reading a bound uninverted.
#[test]
fn plane_bounds_of_zero_bind_nothing_and_bounds_of_rows_bind_each_plane() {
    let unbound = PlaneBounds::UNBOUND;
    assert_eq!(unbound.of_filter(Plane::Subscribers, false), usize::MAX);
    assert_eq!(unbound.of_filter(Plane::Subscribers, true), usize::MAX);
    let rows = TableRows {
        publishers: 3,
        queriers: 2,
        key_listeners: 1,
        ..small_rows()
    };
    let bound = PlaneBounds::of(&rows);
    assert_eq!(bound.of_filter(Plane::Subscribers, false), 3);
    assert_eq!(
        bound.of_filter(
            Plane::Queryables {
                complete_required: false
            },
            false
        ),
        2
    );
    assert_eq!(bound.of_filter(Plane::Subscribers, true), 1);
}

/// A session's tables of the region policy, their rows and their key arena, as a region of the
/// build's shape lays them out.
struct OneSession {
    tables: SessionTables<Calls, Region>,
    rows: SessionRows<Calls>,
    keys: crate::key_arena::KeyArena<4096>,
}

// SAFETY: every field is `ZeroEmpty`.
unsafe impl ZeroEmpty for OneSession {}

/// The description of a `OneSession`.
const ONE_SESSION: RegionLines<SESSION_TABLE_LINES> = SessionTables::<Calls, Region>::places(
    core::mem::offset_of!(OneSession, tables),
    core::mem::offset_of!(OneSession, rows),
);

/// Tables of the region policy of all zero bytes are empty and refuse nothing they are asked to
/// read; placed by their description, each holds its build's bound of rows and keeps its keys in
/// the region's key arena. Turned red by a table left out of `SessionTables::places`, by the key
/// handle's line left out, or by a zero field that is not an empty one.
#[test]
fn region_tables_of_zero_bytes_placed_by_their_description_declare_and_undeclare() {
    let layout = std::alloc::Layout::new::<OneSession>();
    // SAFETY: the layout is of a type of some bytes.
    let block = unsafe { std::alloc::alloc_zeroed(layout) };
    let region = NonNull::new(block).expect("the test allocator answers");
    let session = block.cast::<OneSession>();
    // SAFETY: the zeroed block is a `OneSession`, every field of which is `ZeroEmpty`; the key arena
    // is reached by this one reference, made before any key exists and not used after `space`.
    let space = unsafe {
        (*core::ptr::addr_of_mut!((*session).keys))
            .space(SessionLimits::defaults().max_keyexpr_bytes_held())
    };
    // SAFETY: the description is the region's own, its lines naming the tables' columns and handle
    // in it and the rows beside them, which nothing else reaches; the key arena stays in the block
    // until it is given back below.
    unsafe { crate::key_arena::place_region(region, space, &ONE_SESSION) };
    // SAFETY: the tables field alone, projected from the block; the rows and the key arena are
    // reached only through the tables from here on.
    let tables = unsafe { &mut *core::ptr::addr_of_mut!((*session).tables) };
    assert!(tables.subscribers().is_empty());
    assert_eq!(tables.next_entity_id(), Some(1));
    assert_eq!(tables.subscribers().capacity(), caps::MAX_SUBSCRIPTIONS);
    let first = tables
        .declare_subscriber("a/b", Locality::Any, KeyForm::default(), 1)
        .unwrap();
    assert_eq!(tables.subscribers().get(first.handle).unwrap().id(), 1);
    assert_eq!(
        tables
            .subscribers()
            .get(first.handle)
            .unwrap()
            .key()
            .as_str(),
        "a/b"
    );
    for n in 1..caps::MAX_SUBSCRIPTIONS {
        let key = std::format!("a/{n}");
        tables
            .declare_subscriber(&key, Locality::Any, KeyForm::default(), 2)
            .unwrap();
    }
    let refused = tables
        .declare_subscriber("a/full", Locality::Any, KeyForm::default(), 3)
        .unwrap_err();
    assert_eq!(refused.why, RegisterError::TableFull);
    let undeclared = tables.undeclare_subscriber(first.handle).unwrap();
    assert_eq!(undeclared.taken.unwrap(), 1);
    let declared = tables.declare_keyexpr("k/one").unwrap();
    assert_eq!(declared.id, 1, "a zero expression id mints 1 first");
    // SAFETY: the tables are dropped once, in place, while the key arena their keys lie in is still
    // in the block; then the block goes back with its layout.
    unsafe {
        core::ptr::drop_in_place(core::ptr::addr_of_mut!((*session).tables));
        std::alloc::dealloc(block, layout);
    }
}

/// Every row `fan` pins, each call ended at once: the number each row's closure was given.
fn pinned_in_turn(tables: &mut LatchedTables, fan: &mut PinnedFanOut<'_>) -> Vec<u32> {
    let mut seen = Vec::new();
    while let Some(call) = tables.pin_next_subscriber(fan) {
        seen.push(call.call);
        assert!(
            !ended::<CClosure<u32>>(call),
            "a live row's call marks nothing"
        );
    }
    seen
}

/// The walk that pins one row at a time reaches the rows a peer's fan-out reaches, in its order: a
/// row whose locality hears no peer, or whose pattern does not meet the key, is passed. Turned red
/// by a walk that skips a row, repeats one, or matches by another rule than the fan-out's.
#[test]
fn the_pinned_walk_reaches_the_rows_a_peers_fan_out_reaches_in_its_order() {
    use crate::pubsub::{LocalSubscribers, PeerDelivery};
    let mut tables = latched_tables();
    let mut declared = Vec::new();
    for (n, key, origin) in [
        (1, "a/b", Locality::Any),
        (2, "a/*", Locality::Remote),
        (3, "c", Locality::Any),
        (4, "a/**", Locality::SessionLocal),
        (5, "a/b", Locality::Any),
    ] {
        let row = tables
            .declare_subscriber(key, origin, KeyForm::default(), latched(n))
            .unwrap();
        declared.push((row.handle, n));
    }
    let mut fanned = Vec::new();
    tables.deliver_from_peer("a/b", None, PeerDelivery::default(), |id, _| {
        fanned.extend(
            declared
                .iter()
                .filter(|(handle, _)| *handle == id)
                .map(|(_, n)| *n),
        );
    });
    assert_eq!(fanned, std::vec![1, 2, 5], "CONTROL: the fan-out's rows");
    let mut fan = PinnedFanOut::new("a/b", None);
    assert_eq!(pinned_in_turn(&mut tables, &mut fan), fanned);
    assert!(
        tables.pin_next_subscriber(&mut fan).is_none(),
        "a walk that ended stays ended"
    );
}

/// The walk of a message the session itself published reaches the rows its own loopback reaches,
/// in its order: a row whose locality hears only peers is passed, and one that hears only the
/// session is reached. Turned red by a walk of the session's own message that matches the rows by
/// a peer's origin.
#[test]
fn the_pinned_walk_of_the_sessions_own_message_reaches_the_rows_its_loopback_reaches() {
    use crate::pubsub::LocalSubscribers;
    let mut tables = latched_tables();
    let mut declared = Vec::new();
    for (n, key, origin) in [
        (1, "a/b", Locality::Any),
        (2, "a/*", Locality::Remote),
        (3, "c", Locality::Any),
        (4, "a/**", Locality::SessionLocal),
        (5, "a/b", Locality::Any),
    ] {
        let row = tables
            .declare_subscriber(key, origin, KeyForm::default(), latched(n))
            .unwrap();
        declared.push((row.handle, n));
    }
    let mut fanned = Vec::new();
    tables.fire_matching("a/b", true, false, |id, _| {
        fanned.extend(
            declared
                .iter()
                .filter(|(handle, _)| *handle == id)
                .map(|(_, n)| *n),
        );
    });
    assert_eq!(fanned, std::vec![1, 4, 5], "CONTROL: the loopback's rows");
    let mut fan = PinnedFanOut::local("a/b");
    assert_eq!(pinned_in_turn(&mut tables, &mut fan), fanned);
    assert_eq!(
        pinned_in_turn(&mut tables, &mut PinnedFanOut::new("a/b", None)),
        std::vec![1, 2, 5],
        "CONTROL: a peer's message on the same key reaches the rows that hear peers"
    );
}

/// A row undeclared while a call pinned before it runs begins no call, so the walk passes it; a
/// row undeclared while its own call runs keeps its slot until that call ends, which says so and
/// lets the drained walk take it. Turned red by a walk that pins a retired row, or by a pin that
/// does not hold the row's latch up across its call.
#[test]
fn a_row_undeclared_while_a_pinned_call_runs_is_passed_and_let_go_after() {
    let mut tables = latched_tables();
    let one = tables
        .declare_subscriber("k", Locality::Any, KeyForm::default(), latched(1))
        .unwrap();
    let two = tables
        .declare_subscriber("k", Locality::Any, KeyForm::default(), latched(2))
        .unwrap();
    let three = tables
        .declare_subscriber("k", Locality::Any, KeyForm::default(), latched(3))
        .unwrap();
    let mut fan = PinnedFanOut::new("k", None);
    let first = tables.pin_next_subscriber(&mut fan).expect("the first row");
    assert_eq!(first.call, 1);
    // Its own row undeclared under its call: kept, its callback not handed back.
    assert!(tables
        .undeclare_subscriber(one.handle)
        .unwrap()
        .taken
        .is_none());
    // The next row undeclared before the walk reaches it: no call runs, so it goes at once.
    assert!(tables
        .undeclare_subscriber(two.handle)
        .unwrap()
        .taken
        .is_some());
    let next = tables.pin_next_subscriber(&mut fan).expect("the row after");
    assert_eq!(next.call, 3, "the undeclared row is passed");
    assert!(!ended::<CClosure<u32>>(next));
    assert!(tables.pin_next_subscriber(&mut fan).is_none());
    assert!(
        tables.release_drained_subscriber(&mut 0).is_none(),
        "CONTROL: the first call still runs"
    );
    assert!(
        ended::<CClosure<u32>>(first),
        "the last call of a retired row"
    );
    assert!(tables.release_drained_subscriber(&mut 0).is_some());
    assert!(!tables.subscribers().holds_slot(one.handle));
    assert!(tables.subscribers().contains(three.handle));
}

/// Three subscribers that hear peers, on `a/b`, `a/*` and `a/c` (numbered 1, 2, 3), in tables
/// whose key gate is `gate`. Of the keys of the test catalogue, `a/b` is one and `a/c` is not.
#[cfg(feature = "key-set-closed")]
fn gated_tables(gate: KeyGate<'static>) -> LatchedTables {
    let mut tables = latched_tables();
    for (n, key) in [(1, "a/b"), (2, "a/*"), (3, "a/c")] {
        tables
            .declare_subscriber(key, Locality::Any, KeyForm::default(), latched(n))
            .unwrap();
    }
    tables.set_key_gate(gate);
    tables
}

/// The subscribers a peer of `class` reaches with a message on `key` through the fan-out.
#[cfg(feature = "key-set-closed")]
fn fanned_out(tables: &mut LatchedTables, key: &str, class: Option<ClassId>) -> usize {
    crate::pubsub::LocalSubscribers::deliver_from_peer(
        tables,
        key,
        class,
        crate::pubsub::PeerDelivery::default(),
        |_, _| {},
    )
}

/// A closed key set drops a peer's message on a key outside it before the fan-out reaches any
/// subscriber, and counts it; a key of the set reaches the rows its pattern meets. Turned red by a
/// fan-out of the session's tables that does not put the message to the key gate.
#[cfg(feature = "key-set-closed")]
#[test]
fn a_closed_key_set_drops_a_peers_message_outside_it_from_the_fan_out() {
    use crate::key_catalogue::tests::TABLE;
    let mut open = gated_tables(KeyGate::open());
    assert_eq!(
        fanned_out(&mut open, "a/c", None),
        2,
        "CONTROL: an open gate admits every key"
    );
    let mut tables = gated_tables(KeyGate::closed(&TABLE));
    assert_eq!(fanned_out(&mut tables, "a/b", None), 2, "a key of the set");
    assert_eq!(fanned_out(&mut tables, "a/c", None), 0, "a key outside it");
    assert_eq!(
        tables.key_gate_refused(),
        crate::key_gate::Refused {
            total: 1,
            outside_set: 1,
            ..crate::key_gate::Refused::default()
        }
    );
}

/// A closed key set that declares its peers drops what a peer's row does not allow, and what a
/// peer it does not declare sends, by the class the fan-out is given. Turned red by a fan-out that
/// drops the class it is given.
#[cfg(feature = "key-set-closed")]
#[test]
fn a_closed_key_set_drops_from_the_fan_out_what_the_peers_row_does_not_allow() {
    use crate::key_catalogue::tests::TABLE;
    use crate::key_gate::tests::{ALLOWANCE, PEER_A, PEER_B};
    let mut tables = gated_tables(KeyGate::closed(&TABLE).with_allowance(&ALLOWANCE));
    let a = ALLOWANCE.class_of(&PEER_A);
    let b = ALLOWANCE.class_of(&PEER_B);
    assert_eq!(
        fanned_out(&mut tables, "a/b", a),
        2,
        "CONTROL: A's row allows a/b"
    );
    assert_eq!(fanned_out(&mut tables, "a/b", b), 0, "B's row does not");
    assert_eq!(
        fanned_out(&mut tables, "a/b", None),
        0,
        "a peer not declared"
    );
    assert_eq!(tables.key_gate_refused().peer_not_allowed, 1);
    assert_eq!(tables.key_gate_refused().peer_unknown, 1);
}

/// The walk that pins one row at a time keeps the fan-out's key gate: a peer's message on a key
/// outside a closed set reaches no row, counted once for the message however often the walk is
/// asked, and the session's own message is not gated. Turned red by a pinned walk that does not
/// put the message to the gate, or that asks it at each pin.
#[cfg(feature = "key-set-closed")]
#[test]
fn a_closed_key_set_drops_a_peers_message_outside_it_from_the_pinned_walk() {
    use crate::key_catalogue::tests::TABLE;
    let mut open = gated_tables(KeyGate::open());
    assert_eq!(
        pinned_in_turn(&mut open, &mut PinnedFanOut::new("a/c", None)),
        std::vec![2, 3],
        "CONTROL: an open gate admits every key"
    );
    let mut tables = gated_tables(KeyGate::closed(&TABLE));
    assert_eq!(
        pinned_in_turn(&mut tables, &mut PinnedFanOut::new("a/b", None)),
        std::vec![1, 2],
        "a key of the set"
    );
    let mut fan = PinnedFanOut::new("a/c", None);
    assert!(
        tables.pin_next_subscriber(&mut fan).is_none(),
        "a key outside it"
    );
    assert!(
        tables.pin_next_subscriber(&mut fan).is_none(),
        "a refused walk stays ended"
    );
    assert_eq!(
        tables.key_gate_refused().outside_set,
        1,
        "counted once for the message"
    );
    assert_eq!(
        pinned_in_turn(&mut tables, &mut PinnedFanOut::local("a/c")),
        std::vec![2, 3],
        "the session's own message is not gated"
    );
    assert_eq!(tables.key_gate_refused().total, 1);
}

/// The pinned walk asks the key gate with the class it carries: what a peer's row does not allow
/// reaches no row. Turned red by a walk that asks the gate without the peer's class.
#[cfg(feature = "key-set-closed")]
#[test]
fn a_closed_key_set_drops_from_the_pinned_walk_what_the_peers_row_does_not_allow() {
    use crate::key_catalogue::tests::TABLE;
    use crate::key_gate::tests::{ALLOWANCE, PEER_A, PEER_B};
    let mut tables = gated_tables(KeyGate::closed(&TABLE).with_allowance(&ALLOWANCE));
    let a = ALLOWANCE.class_of(&PEER_A);
    let b = ALLOWANCE.class_of(&PEER_B);
    assert_eq!(
        pinned_in_turn(&mut tables, &mut PinnedFanOut::new("a/b", a)),
        std::vec![1, 2],
        "CONTROL: A's row allows a/b"
    );
    assert!(pinned_in_turn(&mut tables, &mut PinnedFanOut::new("a/b", b)).is_empty());
    assert_eq!(tables.key_gate_refused().peer_not_allowed, 1);
}

/// Every liveliness subscriber `fan` pins, each call ended at once: the number each row's
/// closure was given.
fn tokens_pinned_in_turn(tables: &LatchedTables, fan: &mut PinnedTokenFan<'_>) -> Vec<u32> {
    let mut seen = Vec::new();
    while let Some(call) = tables.pin_next_liveliness_subscriber(fan) {
        seen.push(call.call);
        assert!(
            !ended::<CClosure<u32>>(call),
            "a live row's call marks nothing"
        );
    }
    seen
}

/// A peer token's walk pins, one at a time in the table's order, each liveliness subscriber whose
/// pattern meets its key, and of a historical token only the rows that asked for history; a row
/// undeclared before the walk reaches it begins no call. The CONTROL is the live token, which
/// reaches the row that asked no history too. Turned red by a walk that matches by another rule
/// than the token fan's (`token_reaches`), repeats a row, or pins a row undeclared.
#[test]
fn a_tokens_walk_pins_each_liveliness_subscriber_it_reaches_in_turn() {
    let mut tables = latched_tables();
    tables
        .declare_liveliness_subscriber("demo/**", false, KeyForm::default(), latched(1))
        .unwrap();
    tables
        .declare_liveliness_subscriber("other/**", true, KeyForm::default(), latched(2))
        .unwrap();
    let asked = tables
        .declare_liveliness_subscriber("demo/*", true, KeyForm::default(), latched(3))
        .unwrap();
    assert_eq!(
        tokens_pinned_in_turn(&tables, &mut PinnedTokenFan::new("demo/t", false)),
        [1, 3],
        "CONTROL: a live token reaches every row its key meets"
    );
    assert_eq!(
        tokens_pinned_in_turn(&tables, &mut PinnedTokenFan::new("demo/t", true)),
        [3],
        "a historical token reaches only the rows that asked for history"
    );
    let mut fan = PinnedTokenFan::new("demo/t", false);
    let first = tables
        .pin_next_liveliness_subscriber(&mut fan)
        .expect("the first row");
    assert_eq!(first.call, 1);
    assert!(!ended::<CClosure<u32>>(first));
    assert!(tables
        .undeclare_liveliness_subscriber(asked.handle)
        .unwrap()
        .taken
        .is_some());
    assert!(
        tables.pin_next_liveliness_subscriber(&mut fan).is_none(),
        "a row undeclared between two pins begins no call"
    );
}

/// A declaration's row is counted at its own address by the generation its holder's row was taken
/// at: one more hold there up to the count's bound, the holds given back there down to the last,
/// which only the table lets go of; a hold at another generation is neither taken nor given back
/// there, and the row names its own tables and no other.
///
/// # Control
///
/// A `retain` that does not stop at the bound reds the `Full` assertion; a `release_shared` that
/// lets go of the last reds the assertion that the row stands until `undeclare_keyexpr`; a count
/// that does not carry the generation reds the assertions on the other generation.
#[test]
fn a_rows_count_is_taken_at_its_address_by_its_generation_and_its_last_hold_by_the_table() {
    let mut tables = Tables::new();
    let other = Tables::new();
    let declared = tables.declare_keyexpr("demo/row").unwrap();
    let at: *const _ = tables.keyexprs().get(declared.handle).unwrap().head();
    // SAFETY: the row stands where it was put until its last hold goes, at the end; the table's
    // calls in between take no `&mut` of it.
    let head = unsafe { &*at };
    assert!(tables.is_own_row(head));
    assert!(
        !other.is_own_row(head),
        "another table's row is not its own"
    );
    assert_eq!(
        (head.id(), head.key_len(), head.holds()),
        (declared.id, "demo/row".len(), 1)
    );
    // The same row at another generation: a declaration that left it, or one that took it since.
    let stranger = core::num::NonZeroU32::new(declared.handle.to_bits().get() ^ 0x0001_0000)
        .and_then(KeyexprHandle::from_bits)
        .unwrap();
    assert_eq!(head.count().retain(stranger), Err(RowHoldRefused::Released));
    assert_eq!(head.count().retain(declared.handle), Ok(()));
    assert!(!head.count().release_shared(stranger));
    assert_eq!(head.holds(), 2);
    while head.holds() < KeyexprHolds::MAX {
        head.count().retain(declared.handle).unwrap();
    }
    assert_eq!(
        head.count().retain(declared.handle),
        Err(RowHoldRefused::Full)
    );
    assert!(
        !tables.retain_keyexpr(declared.handle),
        "the table's own hold meets the same bound"
    );
    while head.count().release_shared(declared.handle) {}
    assert_eq!(
        head.holds(),
        1,
        "the last hold is not let go of at the address"
    );
    assert_eq!(tables.keyexprs().len(), 1);
    assert_eq!(tables.undeclare_keyexpr(declared.handle), Some(declared.id));
    assert!(tables.keyexprs().is_empty());
}

/// A row a declaration was retracted from whatever held it, taken again by the next declaration,
/// counts the new declaration's holders only: a hold of the first given back at the address lets
/// go of nothing, and none is taken there for it, as long as the slot was taken again fewer than
/// 65536 times since. At 65536 the generation in the count's word has come round, and the stale
/// hold reads as the new declaration's: the bound [`KeyexprHead`] states, pinned here.
///
/// # Control
///
/// A word that does not carry the slot's generation reds the assertions on the first
/// declaration's hold after the second declaration took its row; a generation wider or narrower
/// than the handle's reds the last assertion.
#[test]
fn a_retracted_declarations_hold_spares_its_rows_next_declaration_below_65536_reuses() {
    let mut tables = Tables::new();
    let first = tables.declare_keyexpr("demo/row/first").unwrap();
    let at: *const _ = tables.keyexprs().get(first.handle).unwrap().head().count();
    // SAFETY: the table keeps its rows where they were put; the count is read while the first
    // declaration stands and while a later one stands in the same row, never in between.
    let head = unsafe { &*at };
    assert_eq!(head.retain(first.handle), Ok(()));
    assert_eq!(tables.retract_keyexpr(first.handle), Some(first.id));
    let second = tables.declare_keyexpr("demo/row/second").unwrap();
    let again: *const _ = tables.keyexprs().get(second.handle).unwrap().head().count();
    assert!(
        core::ptr::eq(at, again),
        "the second declaration takes the first's row"
    );
    assert_ne!(second.handle, first.handle, "at the row's next generation");
    assert_eq!(head.retain(second.handle), Ok(()));
    assert!(
        !head.release_shared(first.handle),
        "the first declaration's hold lets go of nothing"
    );
    assert_eq!(
        head.retain(first.handle),
        Err(RowHoldRefused::Released),
        "and takes none"
    );
    assert_eq!(head.holds(), 2);
    assert_eq!(tables.retract_keyexpr(second.handle), Some(second.id));
    // The slot taken again until its generation is the first declaration's once more.
    let mut last = second.handle;
    for _ in 2..=u32::from(u16::MAX) {
        let taken = tables.declare_keyexpr("demo/row/again").unwrap();
        last = taken.handle;
        assert!(tables.retract_keyexpr(taken.handle).is_some());
    }
    assert_ne!(
        last, first.handle,
        "65535 reuses: the generation has not come round"
    );
    let round = tables.declare_keyexpr("demo/row/round").unwrap();
    assert_eq!(
        round.handle, first.handle,
        "the 65536th takes the first's generation"
    );
    assert_eq!(head.retain(round.handle), Ok(()));
    assert!(
        head.release_shared(first.handle),
        "past the bound the stale hold reads as the new declaration's"
    );
}

/// A declaration's row keeps its key's length in the integer of its table's policy: on a bounded
/// policy the narrowest the build's bound on a key's length fits, so the row's head is as small as
/// its fields allow, and on the growable one `u32`, which takes every key the wire can name.
///
/// # Control
///
/// A `KeyLen` chosen apart from the bound reds the width assertion; a bounded policy that keeps
/// the growable one's integer reds the size of its head.
#[test]
fn a_bounded_rows_key_length_is_as_wide_as_the_builds_bound() {
    let width = if caps::MAX_KEYEXPR_BYTES <= usize::from(u16::MAX) {
        2
    } else {
        4
    };
    assert_eq!(core::mem::size_of::<caps::KeyLen>(), width);
    assert_eq!(
        core::mem::size_of::<KeyexprHead<<Static as Storage>::KeyLen>>(),
        (4 + 2 + width).next_multiple_of(core::mem::size_of::<usize>())
            + core::mem::size_of::<usize>(),
        "the count, the id and the length share the word before the tables' address"
    );
}

/// A growable table keeps a key of any length the wire can name, past a bounded policy's
/// narrowest integer: its rows keep the length in `u32`.
///
/// # Control
///
/// A growable policy that keeps the bounded policies' integer reds the width assertion, and one
/// that refuses or cuts a key past `u16` reds the declaration's.
#[cfg(feature = "alloc")]
#[test]
fn a_growable_rows_key_length_takes_a_key_past_u16() {
    assert_eq!(
        core::mem::size_of::<<crate::bounded::Heap as Storage>::KeyLen>(),
        4
    );
    type Growable = SessionTables<Calls, crate::bounded::Heap>;
    let mut tables = Growable::new();
    let long = "k".repeat(usize::from(u16::MAX) + 1);
    let declared = tables
        .declare_keyexpr(&long)
        .expect("no bound on a growable table's key");
    let row = tables.keyexprs().get(declared.handle).unwrap();
    assert_eq!(row.head().key_len(), long.len());
    assert_eq!(row.key(), long);
}

/// Rows of a growable table stay where they were put however many declarations come after them,
/// past the build's bound: the table grows by chunks that are only ever added, with no bound but
/// the allocator's. Turned red by a column that moves its rows to grow (the first row's address
/// changes) or one held to the build's bound (a declaration past it refused).
#[cfg(feature = "alloc")]
#[test]
fn growable_rows_stay_where_they_were_put_past_the_builds_bound() {
    type Growable = SessionTables<Calls, crate::bounded::Heap>;
    let mut tables = Growable::new();
    let first = tables.declare_keyexpr("k/0").unwrap();
    let at = |tables: &Growable| -> *const KeyexprHead<u32> {
        tables.keyexprs().get(first.handle).unwrap().head()
    };
    let before = at(&tables);
    let past = caps::MAX_DECLARED_KEYEXPRS + 2 * crate::slot_map::CHUNK_ROWS;
    for n in 1..=past {
        tables.declare_keyexpr(&std::format!("k/{n}")).unwrap();
    }
    assert_eq!(tables.keyexprs().len(), past + 1, "no declaration refused");
    assert_eq!(at(&tables), before, "the first row is where it was put");
}
