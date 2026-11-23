// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

use super::*;
use crate::bounded::{Static, ARENA_ALIGN};
use crate::limits::SessionLimits;
use crate::row_callback::{CClosure, CallLatch};
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
    type Reply = u32;
}

/// The tables of the static policy, whose rows never move, with latched callbacks.
type LatchedTables = SessionTables<Latched, Static>;

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
        write_filters: FILTER_ROWS,
        matching_listeners: caps::MAX_MATCHING_LISTENERS,
        pending_gets: caps::MAX_PENDING_QUERIES,
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
fn an_undeclared_entity_hands_its_row_back_and_its_handle_goes_stale() {
    let mut tables = Tables::new();
    let sub = subscribe(&mut tables, "a", Locality::Any, 7);
    let undeclared = tables.undeclare_subscriber(sub.handle).unwrap();
    assert_eq!(undeclared.id, sub.id);
    assert_eq!(undeclared.row.unwrap().into_callback(), 7);
    assert_eq!(undeclared.keyexpr, None);
    assert!(tables.undeclare_subscriber(sub.handle).is_none());
    assert!(reached(&tables, "a", false).is_empty());
}

#[test]
fn a_subscriber_undeclared_while_its_callback_runs_is_let_go_by_the_last_call() {
    let mut tables = LatchedTables::new();
    let sub = tables
        .declare_subscriber("a", Locality::Any, KeyForm::default(), latched(7))
        .unwrap();
    let call = tables.begin_subscriber(sub.handle).unwrap();
    assert_eq!(call.call, 7);
    let undeclared = tables.undeclare_subscriber(sub.handle).unwrap();
    assert_eq!(undeclared.id, sub.id);
    assert!(undeclared.row.is_none(), "a call of it runs");
    // No later sample reaches it and no call of it begins, while the running call still holds it.
    assert!(tables.subscribers_for("a", false).next().is_none());
    assert!(tables.begin_subscriber(sub.handle).is_none());
    assert!(tables.subscribers().holds_slot(sub.handle));
    assert!(ended::<CClosure<u32>>(call), "the last call lets it go");
    assert!(tables.release_subscriber(sub.handle).is_some());
    assert!(!tables.subscribers().holds_slot(sub.handle));
    assert!(tables.subscribers().is_empty());
}

#[test]
fn a_row_no_call_of_which_runs_is_let_go_when_it_is_undeclared() {
    let mut tables = LatchedTables::new();
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
        undeclared.row.is_some(),
        "no call runs: the undeclarer lets it go"
    );
    assert!(tables.release_subscriber(sub.handle).is_none());
}

#[test]
fn every_kind_with_a_callback_is_let_go_by_its_last_call() {
    let mut tables = LatchedTables::new();
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
    let get = tables.begin_get(1, "g", 10, 4).unwrap();
    let calls = (
        tables.begin_queryable(qbl.handle).unwrap(),
        tables.begin_liveliness_subscriber(live.handle).unwrap(),
        tables.begin_matching_listener(listener).unwrap(),
        tables.pin_get(get.handle).unwrap(),
    );
    assert_eq!((calls.0.call, calls.1.call, calls.2.call), (1, 2, 3));
    assert!(tables
        .undeclare_queryable(qbl.handle)
        .unwrap()
        .row
        .is_none());
    assert!(tables
        .undeclare_liveliness_subscriber(live.handle)
        .unwrap()
        .row
        .is_none());
    assert!(matches!(
        tables.undeclare_matching_listener(listener),
        Some(Removal::AfterCalls)
    ));
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
    assert_eq!(tables.unpin_get(calls.3).unwrap().into_callback(), 4);
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
        names_key: true,
    };
    let sub = tables
        .declare_subscriber("demo/x", Locality::Any, form, 1)
        .unwrap();
    let key = tables.subscribers().get(sub.handle).unwrap().key();
    assert!(key.names_key());
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
            names_key: false,
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

#[test]
fn filters_of_one_kind_and_key_share_one_interest_their_listeners_read() {
    let mut tables = Tables::new();
    let first = tables
        .declare_write_filter(Plane::Subscribers, "k", false)
        .unwrap();
    let asked = first.interest.unwrap();
    let second = tables
        .declare_write_filter(Plane::Subscribers, "k", true)
        .unwrap();
    assert_eq!(second.interest, None);
    let listener = tables.declare_matching_listener(first.handle, 9).unwrap();
    // Another kind on the same key asks apart.
    let querier = tables
        .declare_write_filter(
            Plane::Queryables {
                complete_required: false,
            },
            "k",
            false,
        )
        .unwrap();
    assert!(querier.interest.is_some_and(|id| id != asked));
    assert_eq!(tables.interests().len(), 2);
    let interest = tables.write_filters().get(first.handle).unwrap().interest();
    assert_eq!(tables.interest_key(interest), Some("k"));
    assert_eq!(tables.interests().get(interest).unwrap().holds(), 2);
    assert_eq!(
        tables
            .matching_listeners()
            .get(listener)
            .unwrap()
            .interest(),
        interest,
        "a listener reads its filter's Interest"
    );
    // The Interest's Final goes with its last holder; the listener goes with its filter.
    let mut gone = Vec::new();
    assert_eq!(
        tables
            .undeclare_write_filter(first.handle, |handle, removal| gone.push((handle, removal)))
            .unwrap()
            .interest_final,
        None
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
        Some(asked)
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
    let mut tables = LatchedTables::new();
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
    let listener = tables.declare_matching_listener(filter, 3).unwrap();
    let mut cursor = 0;
    assert_eq!(tables.next_matching_change(&mut cursor, &NoPeers), None);
    let sub = subscribe(&mut tables, "k", Locality::Any, 1);
    let mut cursor = 0;
    assert_eq!(
        tables.next_matching_change(&mut cursor, &NoPeers),
        Some((listener, true))
    );
    assert_eq!(tables.next_matching_change(&mut cursor, &NoPeers), None);
    let mut cursor = 0;
    assert_eq!(tables.next_matching_change(&mut cursor, &NoPeers), None);
    assert!(tables.matching_listeners().get(listener).unwrap().last());
    let _ = tables.undeclare_subscriber(sub.handle);
    let mut cursor = 0;
    assert_eq!(
        tables.next_matching_change(&mut cursor, &NoPeers),
        Some((listener, false))
    );
    // A peer's declaration counts too.
    let peers = Peers::default();
    peers.declares.set(true);
    let mut cursor = 0;
    assert_eq!(
        tables.next_matching_change(&mut cursor, &peers),
        Some((listener, true))
    );
}

#[test]
fn a_get_is_found_by_its_face_and_request_and_ended_by_deadline_or_face() {
    let mut tables = Tables::new();
    let first = tables.begin_get(1, "k", 100, 7).unwrap();
    let second = tables.begin_get(2, "k", 50, 8).unwrap();
    assert_ne!(first.request, second.request);
    let (found, row) = tables.pending_get(1, first.request).unwrap();
    assert_eq!(found, first.handle);
    assert_eq!((row.face(), row.key(), row.deadline()), (1, "k", 100));
    assert!(tables.pending_get(2, first.request).is_none());
    assert_eq!(tables.next_get_deadline(), Some(50));
    let mut cursor = 0;
    assert_eq!(
        tables.next_expired_get(60, &mut cursor),
        Some(second.handle)
    );
    assert_eq!(tables.next_expired_get(60, &mut cursor), None);
    let mut cursor = 0;
    assert_eq!(tables.next_get_on_face(1, &mut cursor), Some(first.handle));
    assert_eq!(tables.next_get_on_face(1, &mut cursor), None);
    match tables.end_get(first.handle) {
        Some(Removal::Taken(row)) => assert_eq!(row.into_callback(), 7),
        _ => panic!("the get was not pinned, so it is handed back at once"),
    }
    assert!(tables.pending_get(1, first.request).is_none());
    assert_eq!(tables.next_get_deadline(), Some(50));
}

#[test]
fn a_request_id_skips_the_ones_still_pending() {
    let mut tables = Tables::new();
    tables.next_request = u32::MAX;
    let last = tables.begin_get(1, "k", 0, 1).unwrap();
    let wrapped = tables.begin_get(1, "k", 0, 2).unwrap();
    assert_eq!((last.request, wrapped.request), (u32::MAX, 0));
    tables.next_request = u32::MAX;
    let next = tables.begin_get(1, "k", 0, 3).unwrap();
    assert_eq!(next.request, 1);
}

#[test]
fn a_full_get_table_refuses_and_hands_the_callback_back() {
    let mut tables = Tables::new();
    tables.limit_to(&TableRows {
        pending_gets: 0,
        ..rows()
    });
    let refused = tables.begin_get(1, "k", 0, 5).unwrap_err();
    assert_eq!(refused.why, RegisterError::TableFull);
    assert_eq!(refused.callback, 5);
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
        write_filters: 1,
        matching_listeners: 1,
        pending_gets: 1,
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
    assert_eq!(undeclared.row.unwrap().into_callback(), 1);
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

#[test]
fn a_retracted_declaration_goes_whatever_holds_it() {
    let mut tables = Tables::new();
    let declared = tables.declare_keyexpr("demo/").unwrap();
    tables.declare_keyexpr("demo/").unwrap();
    let form = KeyForm {
        prefix: Some(declared.handle),
        names_key: false,
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
struct Counted(usize, CallLatch);

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
}

impl crate::sink::SampleSink for Counted {
    fn deliver(&mut self, _sample: &dyn crate::sink::SampleView) {
        self.0 += 1;
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
    let count = |sink: &mut Counted| sink.0 += 1;
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

/// How many samples the subscriber `handle` names was handed.
fn heard(tables: &SessionTables<Sinks>, handle: SubscriberHandle) -> usize {
    tables.subscribers().get(handle).unwrap().callback().0
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
    let count = |sink: &mut Counted| sink.0 += 1;
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
    assert_eq!(gone.row.unwrap().callback().0, 3);
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
            .0,
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
    let count = |sink: &mut Counted| sink.0 += 1;
    let mut tables = SessionTables::<Sinks, Static>::new();
    let sub = tables
        .declare_subscriber("a/x", Locality::Any, KeyForm::default(), Counted::default())
        .unwrap();
    assert_eq!(tables.fire_matching("a/x", true, false, count), 1);
    assert!(tables.has_local_matching("a/x"));
    let call = tables.begin_subscriber(sub.handle).unwrap();
    let undeclared = tables.undeclare_subscriber(sub.handle).unwrap();
    assert!(undeclared.row.is_none(), "let go of by the last call");
    assert_eq!(tables.fire_matching("a/x", true, false, count), 0);
    assert_eq!(tables.fire_matching("a/x", false, true, count), 0);
    assert!(!tables.has_local_matching("a/x"));
    assert!(ended::<Counted>(call));
    let row = tables.release_subscriber(sub.handle).unwrap();
    assert_eq!(
        row.callback().0,
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
    let count = |sink: &mut Counted| sink.0 += 1;
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
        tables.subscribers().get(peers.handle).unwrap().callback().0,
        4
    );
    assert_eq!(
        tables.subscribers().get(own.handle).unwrap().callback().0,
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
    tables.end_plain_frame();
    assert_eq!(
        tables.subscribers().get(any.handle).unwrap().callback().0,
        1
    );
    assert_eq!(
        tables.subscribers().get(own.handle).unwrap().callback().0,
        1
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

#[cfg(feature = "declare-subscriber")]
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
    // A CURRENT interest on a/**: one subscription answers it, then the Final.
    assert_eq!(
        peer.answer_subscriber_interest(&mut tables, 7, Some("a/**"), false, true, false),
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
        peer.answer_subscriber_interest(&mut tables, 8, Some("d/*"), false, false, true),
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
        let fired = tables.fire_matching_queryables(
            "q/a",
            KeyFacts::of("q/a"),
            remote,
            target,
            |callback: &mut u32| asked.push(*callback),
        );
        assert_eq!(fired, asked.len());
        asked
    };
    assert_eq!(fire(&mut tables, true, None), [1, 2]);
    assert_eq!(fire(&mut tables, true, Some(QueryTarget::AllComplete)), [2]);
    assert_eq!(fire(&mut tables, false, None), [1, 3]);
    #[cfg(feature = "storage-profile")]
    {
        assert!(tables.has_local_queryable("q/a", false));
        assert!(!tables.has_local_queryable("elsewhere", false));
    }
}
