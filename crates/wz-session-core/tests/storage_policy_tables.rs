// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The subscriber and declaration tables, written once and run on every storage
//! policy: each body is generic over `P: Storage` and runs on `Static` and on `Heap`
//! in one build, so the two policies are compared by the same code and not by two
//! copies of it. What a policy promises is read from `P::ENFORCES_CAPACITY`, never
//! from a feature gate: the hard bound refuses the entry past `N` and counts it, the
//! growable one takes it.
//!
//! `bounded_heapless_backing.rs` measures the build's own profile (including the
//! zero-allocation property, which needs the whole build to be fixed); this file is
//! the cross-policy half, which is why it needs the allocator for `Heap`.
#![cfg(all(feature = "storage-profile", feature = "alloc"))]

use wz_session_core::bounded::{Heap, Static, Storage};
use wz_session_core::caps;
use wz_session_core::locality::Locality;
use wz_session_core::registry_error::RegisterError;

struct NoopSampleSink;
impl wz_session_core::sink::SampleSink for NoopSampleSink {
    fn deliver(&mut self, _sample: &dyn wz_session_core::sink::SampleView) {}
}

#[cfg(any(feature = "declare-subscriber", feature = "declare-queryable"))]
struct NoopDeclSink;
#[cfg(any(feature = "declare-subscriber", feature = "declare-queryable"))]
impl wz_session_core::decl_sink::DeclSink for NoopDeclSink {
    fn on_declared(&mut self, _decl: &dyn wz_session_core::decl_sink::DeclView) {}
}

#[cfg(any(feature = "declare-subscriber", feature = "declare-queryable"))]
struct NoopUndeclSink;
#[cfg(any(feature = "declare-subscriber", feature = "declare-queryable"))]
impl wz_session_core::decl_sink::UndeclSink for NoopUndeclSink {
    fn on_undeclared(&mut self, _id: u64) {}
}

/// The local subscriber table: the entry past `MAX_SUBSCRIPTIONS` is refused with the
/// table as it was where the capacity is hard, and taken where it is not.
fn subscriber_table_fills_to_n_and_refuses_at_n_plus_one<P: Storage>() {
    use wz_session_core::pubsub::SubscriberRegistry;
    let mut reg: SubscriberRegistry<NoopSampleSink, P> = SubscriberRegistry::default();
    for i in 0..caps::MAX_SUBSCRIPTIONS {
        let key = format!("s/{i}");
        assert!(
            reg.register_sink(&key, Locality::Any, NoopSampleSink)
                .is_ok(),
            "entry {i} is within the capacity"
        );
    }
    assert_eq!(reg.len(), caps::MAX_SUBSCRIPTIONS);

    let past = reg.register_sink("s/past", Locality::Any, NoopSampleSink);
    if P::ENFORCES_CAPACITY {
        assert_eq!(past.err(), Some(RegisterError::TableFull));
        assert_eq!(reg.len(), caps::MAX_SUBSCRIPTIONS);
    } else {
        assert!(past.is_ok());
        assert_eq!(reg.len(), caps::MAX_SUBSCRIPTIONS + 1);
    }
}

/// A pattern past `MAX_KEYEXPR_BYTES` is refused, never truncated, where the capacity
/// is hard; the growable policy never had that bound.
fn subscriber_pattern_past_the_bound<P: Storage>() {
    use wz_session_core::pubsub::SubscriberRegistry;
    let mut reg: SubscriberRegistry<NoopSampleSink, P> = SubscriberRegistry::default();
    let long = "k".repeat(caps::MAX_KEYEXPR_BYTES + 1);
    let outcome = reg.register_sink(&long, Locality::Any, NoopSampleSink);
    if P::ENFORCES_CAPACITY {
        assert_eq!(outcome.err(), Some(RegisterError::KeyexprTooLong));
        assert_eq!(reg.len(), 0, "a refused pattern leaves the table empty");
    } else {
        assert!(outcome.is_ok());
        assert_eq!(reg.len(), 1);
    }
}

/// An unregistered slot is taken again, and a refused registration leaves no gap in
/// the ids.
fn subscriber_unregister_frees_a_slot<P: Storage>() {
    use wz_session_core::pubsub::SubscriberRegistry;
    let mut reg: SubscriberRegistry<NoopSampleSink, P> = SubscriberRegistry::default();
    let mut first = None;
    for i in 0..caps::MAX_SUBSCRIPTIONS {
        let id = reg
            .register_sink(&format!("s/{i}"), Locality::Any, NoopSampleSink)
            .expect("within the capacity");
        first.get_or_insert(id);
    }
    let first = first.expect("the table holds at least one");
    assert!(reg.unregister(first));
    assert!(!reg.unregister(first), "a second unregister finds nothing");
    assert_eq!(reg.len(), caps::MAX_SUBSCRIPTIONS - 1);
    assert!(reg
        .register_sink("s/again", Locality::Any, NoopSampleSink)
        .is_ok());
    assert_eq!(reg.len(), caps::MAX_SUBSCRIPTIONS);
}

#[cfg(feature = "codec-declare")]
mod declarations {
    use super::*;
    use wz_session_core::id_map::PeerAliases;
    use wz_session_core::wireexpr_resolve::MappingSpaces;

    // The fixtures serve the three declaration tables; a build that decodes declares
    // but carries none of them has no use for them.
    #[cfg(any(
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "liveliness-subscriber"
    ))]
    use wz_codecs::declare::DeclareOwned;
    #[cfg(any(
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "liveliness-subscriber"
    ))]
    use wz_session_core_test_support as fx;

    /// The owned `Declare` messages a peer would send: ids `1..=n`, each naming
    /// `peer/<id>`.
    #[cfg(any(
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "liveliness-subscriber"
    ))]
    fn declares(n: usize, make: impl Fn(u64, &str) -> DeclareOwned) -> Vec<DeclareOwned> {
        (1..=n as u64)
            .map(|id| make(id, &format!("peer/{id}")))
            .collect()
    }

    #[cfg(feature = "declare-subscriber")]
    pub mod subscribers {
        use super::*;
        use wz_session_core::declare::subscriber::{RemoteSubscriberPeer, RemoteSubscriberTable};

        fn sub(id: u64, ke: &str) -> DeclareOwned {
            fx::declare_envelope_decl_subscriber(fx::decl_subscriber(id, 0, Some(ke)))
        }

        /// The id past `MAX_REMOTE_DECLS` is refused and counted where the capacity is
        /// hard, taken where it is not; the ids that fit are all there either way.
        pub fn fills_to_n_and_refuses_at_n_plus_one<P: Storage>() {
            let mut table: RemoteSubscriberTable<NoopDeclSink, NoopUndeclSink, P> =
                RemoteSubscriberTable::default();
            let mut peer: RemoteSubscriberPeer<P> = RemoteSubscriberPeer::default();
            let aliases = PeerAliases::<P>::default();
            for m in &declares(caps::MAX_REMOTE_DECLS + 1, sub) {
                table.dispatch_declare(
                    &mut peer,
                    &m.body,
                    MappingSpaces::for_aliases::<P>(&aliases, None),
                );
            }
            if P::ENFORCES_CAPACITY {
                assert_eq!(
                    (peer.declared_count(), peer.refusals()),
                    (caps::MAX_REMOTE_DECLS, 1)
                );
                assert!(!peer.has_matching(&format!("peer/{}", caps::MAX_REMOTE_DECLS + 1)));
            } else {
                assert_eq!(
                    (peer.declared_count(), peer.refusals()),
                    (caps::MAX_REMOTE_DECLS + 1, 0)
                );
                assert!(peer.has_matching(&format!("peer/{}", caps::MAX_REMOTE_DECLS + 1)));
            }
            assert!(peer.has_matching("peer/1"));
        }

        /// A flood of one session's peer table is that session's own: the other
        /// peer's table, built from the same type, holds its single declaration.
        pub fn one_peer_flooding_leaves_the_other_untouched<P: Storage>() {
            let mut table: RemoteSubscriberTable<NoopDeclSink, NoopUndeclSink, P> =
                RemoteSubscriberTable::default();
            let mut flooded: RemoteSubscriberPeer<P> = RemoteSubscriberPeer::default();
            let mut quiet: RemoteSubscriberPeer<P> = RemoteSubscriberPeer::default();
            let aliases = PeerAliases::<P>::default();
            for m in &declares(caps::MAX_REMOTE_DECLS + 4, sub) {
                table.dispatch_declare(
                    &mut flooded,
                    &m.body,
                    MappingSpaces::for_aliases::<P>(&aliases, None),
                );
            }
            let one = sub(3, "quiet/three");
            table.dispatch_declare(
                &mut quiet,
                &one.body,
                MappingSpaces::for_aliases::<P>(&aliases, None),
            );
            assert_eq!((quiet.declared_count(), quiet.refusals()), (1, 0));
            assert!(quiet.has_matching("quiet/three"));
            assert!(!quiet.has_matching("peer/1"));
        }
    }

    #[cfg(feature = "declare-queryable")]
    pub mod queryables {
        use super::*;
        use wz_session_core::declare::queryable::{RemoteQueryablePeer, RemoteQueryableTable};

        fn qbl(id: u64, ke: &str) -> DeclareOwned {
            fx::declare_envelope_decl_queryable(fx::decl_queryable(id, 0, Some(ke)))
        }

        pub fn fills_to_n_and_refuses_at_n_plus_one<P: Storage>() {
            let mut table: RemoteQueryableTable<NoopDeclSink, NoopUndeclSink, P> =
                RemoteQueryableTable::default();
            let mut peer: RemoteQueryablePeer<P> = RemoteQueryablePeer::default();
            let aliases = PeerAliases::<P>::default();
            for m in &declares(caps::MAX_REMOTE_DECLS + 1, qbl) {
                table.dispatch_declare(
                    &mut peer,
                    &m.body,
                    MappingSpaces::for_aliases::<P>(&aliases, None),
                );
            }
            if P::ENFORCES_CAPACITY {
                assert_eq!(
                    (peer.declared_count(), peer.refusals()),
                    (caps::MAX_REMOTE_DECLS, 1)
                );
            } else {
                assert_eq!(
                    (peer.declared_count(), peer.refusals()),
                    (caps::MAX_REMOTE_DECLS + 1, 0)
                );
            }
            assert!(peer.has_matching("peer/1"));
        }

        pub fn one_peer_flooding_leaves_the_other_untouched<P: Storage>() {
            let mut table: RemoteQueryableTable<NoopDeclSink, NoopUndeclSink, P> =
                RemoteQueryableTable::default();
            let mut flooded: RemoteQueryablePeer<P> = RemoteQueryablePeer::default();
            let mut quiet: RemoteQueryablePeer<P> = RemoteQueryablePeer::default();
            let aliases = PeerAliases::<P>::default();
            for m in &declares(caps::MAX_REMOTE_DECLS + 4, qbl) {
                table.dispatch_declare(
                    &mut flooded,
                    &m.body,
                    MappingSpaces::for_aliases::<P>(&aliases, None),
                );
            }
            let one = qbl(3, "quiet/three");
            table.dispatch_declare(
                &mut quiet,
                &one.body,
                MappingSpaces::for_aliases::<P>(&aliases, None),
            );
            assert_eq!((quiet.declared_count(), quiet.refusals()), (1, 0));
        }
    }

    #[cfg(feature = "liveliness-subscriber")]
    pub mod tokens {
        use super::*;
        use wz_session_core::declare::liveliness_sample::{LivelinessSample, LivelinessSampleSink};
        use wz_session_core::declare::liveliness_subscriber::{
            LivelinessSubscriberTable, PeerTokens,
        };

        struct NoopTokenSink;
        impl LivelinessSampleSink for NoopTokenSink {
            fn on_sample(&mut self, _sample: LivelinessSample<'_>) {}
        }

        fn tok(id: u64, ke: &str) -> DeclareOwned {
            fx::declare_envelope_decl_token(fx::decl_token(id, 0, Some(ke)))
        }

        pub fn fills_to_n_and_refuses_at_n_plus_one<P: Storage>() {
            let mut table: LivelinessSubscriberTable<NoopTokenSink, P> =
                LivelinessSubscriberTable::default();
            let mut peer: PeerTokens<P> = PeerTokens::default();
            let aliases = PeerAliases::<P>::default();
            for m in &declares(caps::MAX_REMOTE_DECLS + 1, tok) {
                table.dispatch_declare(
                    &mut peer,
                    &m.body,
                    MappingSpaces::for_aliases::<P>(&aliases, None),
                );
            }
            if P::ENFORCES_CAPACITY {
                assert_eq!((peer.count(), peer.refusals()), (caps::MAX_REMOTE_DECLS, 1));
            } else {
                assert_eq!(
                    (peer.count(), peer.refusals()),
                    (caps::MAX_REMOTE_DECLS + 1, 0)
                );
            }
        }

        pub fn one_peer_flooding_leaves_the_other_untouched<P: Storage>() {
            let mut table: LivelinessSubscriberTable<NoopTokenSink, P> =
                LivelinessSubscriberTable::default();
            let mut flooded: PeerTokens<P> = PeerTokens::default();
            let mut quiet: PeerTokens<P> = PeerTokens::default();
            let aliases = PeerAliases::<P>::default();
            for m in &declares(caps::MAX_REMOTE_DECLS + 4, tok) {
                table.dispatch_declare(
                    &mut flooded,
                    &m.body,
                    MappingSpaces::for_aliases::<P>(&aliases, None),
                );
            }
            let one = tok(3, "quiet/three");
            table.dispatch_declare(
                &mut quiet,
                &one.body,
                MappingSpaces::for_aliases::<P>(&aliases, None),
            );
            assert_eq!((quiet.count(), quiet.refusals()), (1, 0));
        }
    }

    /// The peer's alias table read through `MappingSpaces`: a keyexpr declared with an
    /// id resolves to its literal on both policies, and an id the table does not hold
    /// does not resolve, so the policy is not visible to the reader.
    pub fn peer_aliases_resolve_the_same_on_both<P: Storage>() {
        let aliases = PeerAliases::<P>::default();
        let spaces = MappingSpaces::for_aliases::<P>(&aliases, None);
        assert!(spaces.peer().is_empty());
        assert_eq!(spaces.peer().get(&7), None);
    }
}

/// One generic body as two tests, one per policy; the policy is the only thing that
/// differs between them.
macro_rules! case {
    ($name:ident, $($body:tt)+) => {
        mod $name {
            use super::*;
            #[test]
            fn on_static() {
                $($body)+::<Static>();
            }
            #[test]
            fn on_heap() {
                $($body)+::<Heap>();
            }
        }
    };
}

case!(
    subscriber_table_fills_to_n_and_refuses_at_n_plus_one_case,
    subscriber_table_fills_to_n_and_refuses_at_n_plus_one
);
case!(
    subscriber_pattern_past_the_bound_case,
    subscriber_pattern_past_the_bound
);
case!(
    subscriber_unregister_frees_a_slot_case,
    subscriber_unregister_frees_a_slot
);
#[cfg(feature = "codec-declare")]
case!(
    peer_aliases_resolve_the_same_on_both_case,
    declarations::peer_aliases_resolve_the_same_on_both
);
#[cfg(all(feature = "codec-declare", feature = "declare-subscriber"))]
case!(
    remote_subscribers_fill_case,
    declarations::subscribers::fills_to_n_and_refuses_at_n_plus_one
);
#[cfg(all(feature = "codec-declare", feature = "declare-subscriber"))]
case!(
    remote_subscribers_isolation_case,
    declarations::subscribers::one_peer_flooding_leaves_the_other_untouched
);
#[cfg(all(feature = "codec-declare", feature = "declare-queryable"))]
case!(
    remote_queryables_fill_case,
    declarations::queryables::fills_to_n_and_refuses_at_n_plus_one
);
#[cfg(all(feature = "codec-declare", feature = "declare-queryable"))]
case!(
    remote_queryables_isolation_case,
    declarations::queryables::one_peer_flooding_leaves_the_other_untouched
);
#[cfg(all(feature = "codec-declare", feature = "liveliness-subscriber"))]
case!(
    peer_tokens_fill_case,
    declarations::tokens::fills_to_n_and_refuses_at_n_plus_one
);
#[cfg(all(feature = "codec-declare", feature = "liveliness-subscriber"))]
case!(
    peer_tokens_isolation_case,
    declarations::tokens::one_peer_flooding_leaves_the_other_untouched
);
