// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The fixed-capacity backing of `bounded::BoundedVec` / `BoundedString`,
//! measured on the profile that selects it WHILE an allocator is linked.
//!
//! `bounded-heapless` exists so an MCU build keeps `alloc` for everything else
//! and still gets every `caps` limit as a hard bound. Two properties say that
//! the selection actually happened, and both are observable from outside the
//! crate:
//!
//! - the entry past a table's declared capacity is REFUSED with
//!   `RegisterError::TableFull`, where the growable backing accepts it; and
//! - filling a table to its capacity performs ZERO heap allocations, which is
//!   what "fixed backing" means. A counting `#[global_allocator]` measures it;
//!   the growable backing allocates on the first push and fails that count.
//!
//! The file compiles only where the capped backing is selected (`alloc` off,
//! or `bounded-heapless` on). It is host-test level: no board runs it.
#![cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use wz_session_core::caps;
use wz_session_core::locality::Locality;
use wz_session_core::registry_error::RegisterError;

/// Counts the allocations made BY THE CURRENT THREAD, so the parallel test
/// threads of this binary cannot move each other's numbers.
struct CountingAllocator;

thread_local! {
    // `const` initialisation with a destructor-free type: reading it from
    // inside `alloc` cannot itself allocate.
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call forwards to `System` unchanged; the only addition is a
// thread-local counter bump, which neither allocates nor unwinds.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// Run `f` and return its result with the number of allocations it made on
/// this thread.
fn allocations_during<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let before = ALLOCATIONS.with(Cell::get);
    let out = f();
    let after = ALLOCATIONS.with(Cell::get);
    (out, after - before)
}

/// Distinct canonical keyexprs `t/<i>`, built in a stack buffer so the
/// fixture itself allocates nothing inside the measured window.
fn key(buf: &mut [u8; 16], i: usize) -> &str {
    use std::io::Write;
    let mut cursor = std::io::Cursor::new(&mut buf[..]);
    write!(cursor, "t/{i}").expect("16 bytes hold `t/` and a usize");
    let len = cursor.position() as usize;
    std::str::from_utf8(&buf[..len]).expect("ASCII")
}

struct NoopSampleSink;
impl wz_session_core::sink::SampleSink for NoopSampleSink {
    fn deliver(&mut self, _sample: &dyn wz_session_core::sink::SampleView) {}
}

struct NoopQuerySink;
impl wz_session_core::query_sink::QuerySink for NoopQuerySink {
    fn handle(
        &mut self,
        _query: &dyn wz_session_core::query_sink::QueryView,
        _out: &mut dyn wz_session_core::query_sink::ReplyOut,
    ) {
    }
}

struct NoopReplySink;
impl wz_session_core::reply_sink::ReplySink for NoopReplySink {
    fn on_reply(&mut self, _reply: &dyn wz_session_core::reply_sink::ReplyView) {}
    fn on_final(&mut self, _rid: u64) {}
}

struct NoopDeclSink;
impl wz_session_core::decl_sink::DeclSink for NoopDeclSink {
    fn on_declared(&mut self, _decl: &dyn wz_session_core::decl_sink::DeclView) {}
}

struct NoopUndeclSink;
impl wz_session_core::decl_sink::UndeclSink for NoopUndeclSink {
    fn on_undeclared(&mut self, _id: u64) {}
}

#[test]
fn subscriber_table_refuses_the_entry_past_max_subscriptions_without_allocating() {
    use wz_session_core::pubsub::SubscriberRegistry;
    let mut reg: SubscriberRegistry<NoopSampleSink> = SubscriberRegistry::with_sink_backing();
    let mut buf = [0u8; 16];
    let (filled, allocations) = allocations_during(|| {
        (0..caps::MAX_SUBSCRIPTIONS).all(|i| {
            reg.register_sink(key(&mut buf, i), Locality::Any, NoopSampleSink)
                .is_ok()
        })
    });
    let past = reg.register_sink(
        key(&mut buf, caps::MAX_SUBSCRIPTIONS),
        Locality::Any,
        NoopSampleSink,
    );
    // One verdict, so a red run reports every half of it at once.
    assert_eq!(
        (filled, allocations, past.err(), reg.len()),
        (
            true,
            0,
            Some(RegisterError::TableFull),
            caps::MAX_SUBSCRIPTIONS
        ),
        "(filled to N, allocations while filling, entry N+1, table length)"
    );
}

#[test]
fn subscriber_pattern_past_max_keyexpr_bytes_is_refused_not_truncated() {
    use wz_session_core::pubsub::SubscriberRegistry;
    let mut reg: SubscriberRegistry<NoopSampleSink> = SubscriberRegistry::with_sink_backing();
    let long = "k".repeat(caps::MAX_KEYEXPR_BYTES + 1);
    let refused = reg.register_sink(&long, Locality::Any, NoopSampleSink);
    assert_eq!(
        (refused.err(), reg.len()),
        (Some(RegisterError::KeyexprTooLong), 0),
        "(over-long pattern, table length)"
    );
}

#[test]
fn queryable_table_refuses_the_entry_past_max_queryables_without_allocating() {
    use wz_session_core::query::QueryableRegistry;
    let mut reg: QueryableRegistry<NoopQuerySink> = QueryableRegistry::with_sink_backing();
    let mut buf = [0u8; 16];
    let (filled, allocations) = allocations_during(|| {
        (0..caps::MAX_QUERYABLES).all(|i| {
            reg.register_sink(key(&mut buf, i), Locality::Any, false, NoopQuerySink)
                .is_ok()
        })
    });
    let past = reg.register_sink(
        key(&mut buf, caps::MAX_QUERYABLES),
        Locality::Any,
        false,
        NoopQuerySink,
    );
    assert_eq!(
        (filled, allocations, past.err(), reg.len()),
        (
            true,
            0,
            Some(RegisterError::TableFull),
            caps::MAX_QUERYABLES
        ),
        "(filled to N, allocations while filling, entry N+1, table length)"
    );
}

#[test]
fn pending_query_table_refuses_the_entry_past_max_pending_queries_without_allocating() {
    use wz_session_core::reply::ReplyRegistry;
    use wz_session_core::reply_acceptance::ReplyAcceptance;
    let mut reg: ReplyRegistry<NoopReplySink> = ReplyRegistry::with_sink_backing();
    let (filled, allocations) = allocations_during(|| {
        (0..caps::MAX_PENDING_QUERIES as u64).all(|rid| {
            reg.register_sink(
                rid,
                1,
                None,
                ReplyAcceptance::Matching("svc/a"),
                NoopReplySink,
            )
            .is_ok()
        })
    });
    let past = reg.register_sink(
        caps::MAX_PENDING_QUERIES as u64,
        1,
        None,
        ReplyAcceptance::Any,
        NoopReplySink,
    );
    assert_eq!(
        (filled, allocations, past.err(), reg.len()),
        (
            true,
            0,
            Some(RegisterError::TableFull),
            caps::MAX_PENDING_QUERIES
        ),
        "(filled to N, allocations while filling, entry N+1, table length)"
    );
}

#[test]
fn declaration_observer_list_refuses_the_observer_past_max_decl_observers() {
    use wz_session_core::declare::subscriber::RemoteSubscriberRegistry;
    let mut reg: RemoteSubscriberRegistry<NoopDeclSink, NoopUndeclSink> =
        RemoteSubscriberRegistry::with_sink_backing();
    let (filled, allocations) = allocations_during(|| {
        (0..caps::MAX_DECL_OBSERVERS).all(|_| reg.on_subscriber_declared_sink(NoopDeclSink).is_ok())
    });
    let past = reg.on_subscriber_declared_sink(NoopDeclSink);
    assert_eq!(
        (filled, allocations, past.err()),
        (true, 0, Some(RegisterError::TableFull)),
        "(filled to N, allocations while filling, observer N+1)"
    );
}

#[cfg(feature = "liveliness-token")]
#[test]
fn local_token_table_refuses_the_token_past_max_local_tokens_without_allocating() {
    use wz_session_core::declare::local_token::LocalTokenRegistry;
    let mut reg = LocalTokenRegistry::new();
    let mut buf = [0u8; 16];
    let (filled, allocations) = allocations_during(|| {
        (0..caps::MAX_LOCAL_TOKENS).all(|i| reg.register(i as u64, key(&mut buf, i)) == Ok(true))
    });
    let past = reg.register(
        caps::MAX_LOCAL_TOKENS as u64,
        key(&mut buf, caps::MAX_LOCAL_TOKENS),
    );
    assert_eq!(
        (filled, allocations, past, reg.len()),
        (
            true,
            0,
            Err(RegisterError::TableFull),
            caps::MAX_LOCAL_TOKENS
        ),
        "(filled to N, allocations while filling, token N+1, table length)"
    );
}

// ---------------------------------------------------------------------------
// S9a: the tables a PEER writes. Each is filled to its capacity under the
// counting allocator, the entry past it is refused and COUNTED, and a second
// session's table next to it is untouched by the first one filling its own.
// ---------------------------------------------------------------------------

#[cfg(feature = "codec-declare")]
mod peer_tables {
    use super::*;
    use wz_codecs::declare::DeclareOwned;
    use wz_session_core::id_map::PeerAliases;
    use wz_session_core::wireexpr_resolve::MappingSpaces;
    use wz_session_core_test_support as fx;

    /// The owned `Declare` messages a peer would send, built before any window:
    /// the message is the peer's, only what the session does with it is measured.
    fn declares(n: usize, make: impl Fn(u64, &str) -> DeclareOwned) -> Vec<DeclareOwned> {
        (1..=n as u64)
            .map(|id| make(id, &format!("peer/{id}")))
            .collect()
    }

    #[cfg(feature = "declare-subscriber")]
    mod subscribers {
        use super::*;
        use wz_session_core::declare::subscriber::{RemoteSubscriberPeer, RemoteSubscriberTable};

        fn sub(id: u64, ke: &str) -> DeclareOwned {
            fx::declare_envelope_decl_subscriber(fx::decl_subscriber(id, 0, Some(ke)))
        }

        #[test]
        fn the_remote_subscriber_table_refuses_the_id_past_remote_decls_and_counts_it() {
            let mut table: RemoteSubscriberTable<NoopDeclSink, NoopUndeclSink> =
                RemoteSubscriberTable::with_sink_backing();
            let mut peer = RemoteSubscriberPeer::new();
            let msgs = declares(caps::MAX_REMOTE_DECLS + 1, sub);
            let aliases = PeerAliases::new();
            let (_, allocations) = allocations_during(|| {
                for m in &msgs {
                    table.dispatch_declare(
                        &mut peer,
                        &m.body,
                        MappingSpaces::for_aliases(&aliases, None),
                    );
                }
            });
            assert_eq!(
                (peer.declared_count(), peer.refusals(), allocations),
                (caps::MAX_REMOTE_DECLS, 1, 0),
                "(rows held, refusals counted, allocations)"
            );
            // A refused id is not a held one, and the ids that fit are all there.
            assert!(peer.has_matching("peer/1"));
            assert!(!peer.has_matching(&format!("peer/{}", caps::MAX_REMOTE_DECLS + 1)));
        }

        #[test]
        fn one_session_filling_its_subscriber_table_leaves_the_other_session_untouched() {
            let mut table: RemoteSubscriberTable<NoopDeclSink, NoopUndeclSink> =
                RemoteSubscriberTable::with_sink_backing();
            let (mut flooded, mut quiet) =
                (RemoteSubscriberPeer::new(), RemoteSubscriberPeer::new());
            let aliases = PeerAliases::new();
            for m in &declares(caps::MAX_REMOTE_DECLS + 4, sub) {
                table.dispatch_declare(
                    &mut flooded,
                    &m.body,
                    MappingSpaces::for_aliases(&aliases, None),
                );
            }
            // The same id from the other session means something else there, and fits.
            let one = sub(3, "quiet/three");
            table.dispatch_declare(
                &mut quiet,
                &one.body,
                MappingSpaces::for_aliases(&aliases, None),
            );
            assert_eq!(
                (
                    flooded.declared_count(),
                    flooded.refusals(),
                    quiet.declared_count(),
                    quiet.refusals()
                ),
                (caps::MAX_REMOTE_DECLS, 4, 1, 0),
                "(flooded rows, flooded refusals, quiet rows, quiet refusals)"
            );
            assert!(quiet.has_matching("quiet/three") && !flooded.has_matching("quiet/three"));
        }
    }

    #[cfg(feature = "declare-queryable")]
    mod queryables {
        use super::*;
        use wz_session_core::declare::queryable::{RemoteQueryablePeer, RemoteQueryableTable};

        fn qbl(id: u64, ke: &str) -> DeclareOwned {
            fx::declare_envelope_decl_queryable(fx::decl_queryable(id, 0, Some(ke)))
        }

        #[test]
        fn the_remote_queryable_table_refuses_the_id_past_remote_decls_and_counts_it() {
            let mut table: RemoteQueryableTable<NoopDeclSink, NoopUndeclSink> =
                RemoteQueryableTable::with_sink_backing();
            let mut peer = RemoteQueryablePeer::new();
            let msgs = declares(caps::MAX_REMOTE_DECLS + 1, qbl);
            let aliases = PeerAliases::new();
            let (_, allocations) = allocations_during(|| {
                for m in &msgs {
                    table.dispatch_declare(
                        &mut peer,
                        &m.body,
                        MappingSpaces::for_aliases(&aliases, None),
                    );
                }
            });
            assert_eq!(
                (peer.declared_count(), peer.refusals(), allocations),
                (caps::MAX_REMOTE_DECLS, 1, 0),
                "(rows held, refusals counted, allocations)"
            );
        }

        #[test]
        fn one_session_filling_its_queryable_table_leaves_the_other_session_untouched() {
            let mut table: RemoteQueryableTable<NoopDeclSink, NoopUndeclSink> =
                RemoteQueryableTable::with_sink_backing();
            let (mut flooded, mut quiet) = (RemoteQueryablePeer::new(), RemoteQueryablePeer::new());
            let aliases = PeerAliases::new();
            for m in &declares(caps::MAX_REMOTE_DECLS + 4, qbl) {
                table.dispatch_declare(
                    &mut flooded,
                    &m.body,
                    MappingSpaces::for_aliases(&aliases, None),
                );
            }
            let one = qbl(3, "quiet/three");
            table.dispatch_declare(
                &mut quiet,
                &one.body,
                MappingSpaces::for_aliases(&aliases, None),
            );
            assert_eq!(
                (
                    flooded.declared_count(),
                    flooded.refusals(),
                    quiet.declared_count(),
                    quiet.refusals()
                ),
                (caps::MAX_REMOTE_DECLS, 4, 1, 0)
            );
        }
    }

    #[cfg(feature = "liveliness-subscriber")]
    mod tokens {
        use super::*;
        use wz_session_core::declare::liveliness_sample::{LivelinessSample, LivelinessSampleSink};
        use wz_session_core::declare::liveliness_subscriber::LivelinessSubscriberRegistry;

        struct NoopTokenSink;
        impl LivelinessSampleSink for NoopTokenSink {
            fn on_sample(&mut self, _sample: LivelinessSample<'_>) {}
        }

        fn tok(id: u64, ke: &str) -> DeclareOwned {
            fx::declare_envelope_decl_token(fx::decl_token(id, 0, Some(ke)))
        }

        #[test]
        fn the_peer_token_table_refuses_the_id_past_remote_decls_and_counts_it() {
            let mut reg: LivelinessSubscriberRegistry<NoopTokenSink> =
                LivelinessSubscriberRegistry::with_sink_backing();
            let msgs = declares(caps::MAX_REMOTE_DECLS + 1, tok);
            let aliases = PeerAliases::new();
            let (_, allocations) = allocations_during(|| {
                for m in &msgs {
                    reg.dispatch_declare(&m.body, MappingSpaces::for_aliases(&aliases, None));
                }
            });
            assert_eq!(
                (
                    reg.peer_token_count(),
                    reg.peer_token_refusals(),
                    allocations
                ),
                (caps::MAX_REMOTE_DECLS, 1, 0),
                "(rows held, refusals counted, allocations)"
            );
        }

        #[test]
        fn one_session_filling_its_token_table_leaves_the_other_session_untouched() {
            let aliases = PeerAliases::new();
            let mut flooded: LivelinessSubscriberRegistry<NoopTokenSink> =
                LivelinessSubscriberRegistry::with_sink_backing();
            let mut quiet: LivelinessSubscriberRegistry<NoopTokenSink> =
                LivelinessSubscriberRegistry::with_sink_backing();
            for m in &declares(caps::MAX_REMOTE_DECLS + 4, tok) {
                flooded.dispatch_declare(&m.body, MappingSpaces::for_aliases(&aliases, None));
            }
            let one = tok(3, "quiet/three");
            quiet.dispatch_declare(&one.body, MappingSpaces::for_aliases(&aliases, None));
            assert_eq!(
                (
                    flooded.peer_token_count(),
                    flooded.peer_token_refusals(),
                    quiet.peer_token_count(),
                    quiet.peer_token_refusals()
                ),
                (caps::MAX_REMOTE_DECLS, 4, 1, 0)
            );
        }
    }

    #[cfg(feature = "pubsub-put")]
    mod aliases {
        use super::*;
        use wz_session_core::network_message::NetworkMessage;
        use wz_session_core::pubsub::{SubscriberPeer, SubscriberTable};
        use wz_session_core::reliability::Reliability;

        fn kexpr(id: u64, ke: &str) -> DeclareOwned {
            fx::declare_envelope_decl_kexpr(fx::decl_kexpr(id, ke))
        }

        fn messages(n: usize) -> Vec<NetworkMessage> {
            declares(n, kexpr)
                .into_iter()
                .map(|d| NetworkMessage::Declare(Box::new(d)))
                .collect()
        }

        #[test]
        fn the_alias_table_refuses_the_id_past_peer_keyexpr_aliases_and_counts_it() {
            let mut table: SubscriberTable<NoopSampleSink> = SubscriberTable::with_sink_backing();
            let mut peer = SubscriberPeer::new();
            let msgs = messages(caps::MAX_PEER_KEYEXPR_ALIASES + 1);
            let (_, allocations) = allocations_during(|| {
                for m in &msgs {
                    table.dispatch(&mut peer, m, Reliability::Reliable);
                }
            });
            assert_eq!(
                (peer.alias_count(), peer.alias_refusals(), allocations),
                (caps::MAX_PEER_KEYEXPR_ALIASES, 1, 0),
                "(aliases held, refusals counted, allocations)"
            );
            assert_eq!(peer.resolve_inbound_mapping(1).as_deref(), Some("peer/1"));
            assert_eq!(
                peer.resolve_inbound_mapping(caps::MAX_PEER_KEYEXPR_ALIASES as u64 + 1),
                None,
                "the refused alias is not recorded"
            );
        }

        #[test]
        fn one_session_filling_its_alias_table_leaves_the_other_session_untouched() {
            let mut table: SubscriberTable<NoopSampleSink> = SubscriberTable::with_sink_backing();
            let (mut flooded, mut quiet) = (SubscriberPeer::new(), SubscriberPeer::new());
            for m in &messages(caps::MAX_PEER_KEYEXPR_ALIASES + 4) {
                table.dispatch(&mut flooded, m, Reliability::Reliable);
            }
            // The same wire id, in the other session, is another keyexpr.
            let one = NetworkMessage::Declare(Box::new(kexpr(3, "quiet/three")));
            table.dispatch(&mut quiet, &one, Reliability::Reliable);
            assert_eq!(
                (
                    flooded.alias_count(),
                    flooded.alias_refusals(),
                    quiet.alias_count(),
                    quiet.alias_refusals()
                ),
                (caps::MAX_PEER_KEYEXPR_ALIASES, 4, 1, 0)
            );
            assert_eq!(
                quiet.resolve_inbound_mapping(3).as_deref(),
                Some("quiet/three")
            );
            assert_eq!(
                flooded.resolve_inbound_mapping(3).as_deref(),
                Some("peer/3")
            );
        }
    }

    #[cfg(feature = "declare-subscriber")]
    mod interests {
        use super::*;
        use wz_session_core::pubsub::{SubscriberPeer, SubscriberTable};

        /// One FUTURE-only interest per id on a distinct keyexpr.
        fn register(
            table: &mut SubscriberTable<NoopSampleSink>,
            peer: &mut SubscriberPeer,
            id: u64,
        ) {
            let mut buf = [0u8; 16];
            let ke = key(&mut buf, id as usize);
            table.respond_to_subscriber_interest_borrowed(peer, id, Some(ke), false, false, true);
        }

        #[test]
        fn the_interest_table_refuses_the_id_past_inbound_sub_interests_and_counts_it() {
            let mut table: SubscriberTable<NoopSampleSink> = SubscriberTable::with_sink_backing();
            let mut peer = SubscriberPeer::new();
            let (_, allocations) = allocations_during(|| {
                for id in 1..=(caps::MAX_INBOUND_SUB_INTERESTS as u64 + 1) {
                    register(&mut table, &mut peer, id);
                }
            });
            assert_eq!(
                (
                    peer.interest_count(),
                    peer.interest_staging_refusals().future_interests,
                    allocations
                ),
                (caps::MAX_INBOUND_SUB_INTERESTS, 1, 0),
                "(rows held, refused FUTURE interests, allocations)"
            );
        }

        #[test]
        fn one_session_filling_its_interest_table_leaves_the_other_session_untouched() {
            let mut table: SubscriberTable<NoopSampleSink> = SubscriberTable::with_sink_backing();
            let (mut flooded, mut quiet) = (SubscriberPeer::new(), SubscriberPeer::new());
            for id in 1..=(caps::MAX_INBOUND_SUB_INTERESTS as u64 + 4) {
                register(&mut table, &mut flooded, id);
            }
            register(&mut table, &mut quiet, 3);
            assert_eq!(
                (
                    flooded.interest_count(),
                    flooded.interest_staging_refusals().future_interests,
                    quiet.interest_count(),
                    quiet.interest_staging_refusals().future_interests
                ),
                (caps::MAX_INBOUND_SUB_INTERESTS, 4, 1, 0)
            );
        }
    }
}
