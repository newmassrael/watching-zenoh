// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The limits of a build that a stage after the build may decide, as snapshots.
//!
//! # What a limit is here
//!
//! Every limit is declared in `deploy/wz-config.toml` (`[[limit]]`) and its build value is a
//! constant of [`crate::caps`]. A limit that is a capacity alone sizes storage only the build can
//! size and stays that constant. Every other limit has a type of its own in the generated module
//! here, implementing [`crate::limit_binding::LimitSpec`] (its kind, who makes it grow, its
//! capacity in this build, its domain and the build's value), and is a field of one of two
//! snapshots: [`SessionLimits`], held by a session and read by its links and entities, and
//! [`RuntimeLimits`], held by the node or runtime that creates the sessions.
//!
//! # Who reads a value
//!
//! A snapshot is resolved once by a creator, starting from the build defaults, and handed to the
//! machines it creates, as a [`crate::policy::SessionPolicy`] is. Until each limit's reader moves
//! to its snapshot, the readers still read [`crate::caps`]; the build defaults are what the build
//! runs with today, so a snapshot that holds them changes nothing.

#[path = "limits_generated.rs"]
mod generated;

pub use generated::*;

/// Each bound a table enforces, read through the door its creator uses: with nothing stated the
/// table admits what it admitted while it read the build's constant, and a stated quota refuses
/// the next entry with the path's own refusal and changes nothing. Two tests per bound.
#[cfg(all(test, feature = "alloc"))]
mod enforcement {
    use super::*;
    use crate::caps;
    use crate::limit_binding::{LimitSpec, Quota};
    use crate::observer::ApplicationLayerObserver;
    use crate::registry_error::RegisterError;

    /// `MAX_SUBSCRIPTIONS` with nothing stated: the heap grows the table past the declared count,
    /// as it did, and a fixed table holds its capacity.
    #[test]
    fn max_subscriptions_with_nothing_stated_admits_what_the_build_admitted() {
        let mut observer = ApplicationLayerObserver::with_limits(&SessionLimits::defaults());
        let admitted = if crate::bounded::ENFORCES_CAPACITY {
            caps::MAX_SUBSCRIPTIONS
        } else {
            caps::MAX_SUBSCRIPTIONS + 1
        };
        for index in 0..admitted {
            observer
                .subscribers
                .register(&std::format!("bound/sub/{index}"), |_| {})
                .expect("no quota is stated");
        }
        assert_eq!(observer.subscribers.len(), admitted);
    }

    /// `MAX_SUBSCRIPTIONS` stated as two: the third registration is refused as a full table, and
    /// the refusal takes no declaration id.
    #[test]
    fn max_subscriptions_stated_refuses_the_next_and_takes_no_id() {
        let mut limits = SessionLimits::defaults();
        let stated = limits.select_max_subscriptions(Quota::at_most(2));
        if MaxSubscriptions::DOMAIN.is_singleton() {
            // A build that keeps the build's value alone refuses the statement itself.
            assert!(stated.is_err());
            return;
        }
        stated.expect("two is inside the domain");
        let mut observer = ApplicationLayerObserver::with_limits(&limits);
        let first = observer
            .subscribers
            .register("bound/a", |_| {})
            .expect("under the quota");
        let second = observer
            .subscribers
            .register("bound/b", |_| {})
            .expect("under the quota");
        assert_eq!(
            observer.subscribers.register("bound/c", |_| {}),
            Err(RegisterError::TableFull)
        );
        assert_eq!(observer.subscribers.len(), 2);
        assert!(observer.subscribers.unregister(first));
        let third = observer
            .subscribers
            .register("bound/c", |_| {})
            .expect("a place is free under the quota");
        assert_eq!(third.entity_id(), second.entity_id() + 1);
    }

    /// One entry of a bound's table, the `index`th, taken through the door its creator uses.
    type Admit = fn(&mut ApplicationLayerObserver, usize) -> Result<(), RegisterError>;
    /// The `index`th entry let go; whether it was held.
    type Release = fn(&mut ApplicationLayerObserver, usize) -> bool;
    /// How many entries the table holds.
    type Held = fn(&ApplicationLayerObserver) -> usize;
    /// A bound's statement in a snapshot.
    type Select =
        fn(&mut SessionLimits, Quota) -> Result<(), crate::limit_binding::OutsideLimitDomain>;

    /// With nothing stated the table takes one past the build's count on the heap and the
    /// capacity on a fixed backing, as it did when it read the build's constant.
    fn admits_what_the_build_admitted(build: usize, admit: Admit, held: Held) {
        let mut observer = ApplicationLayerObserver::with_limits(&SessionLimits::defaults());
        let admitted = if crate::bounded::ENFORCES_CAPACITY {
            build
        } else {
            build + 1
        };
        for index in 0..admitted {
            admit(&mut observer, index).expect("no quota is stated");
        }
        assert_eq!(held(&observer), admitted);
    }

    /// Two, as `select` states it; `None` where the build keeps its value alone, which refuses
    /// the statement itself.
    fn stated_two(select: Select, singleton: bool) -> Option<SessionLimits> {
        let mut limits = SessionLimits::defaults();
        let stated = select(&mut limits, Quota::at_most(2));
        if singleton {
            assert!(stated.is_err());
            return None;
        }
        stated.expect("two is inside the domain");
        Some(limits)
    }

    /// Held to two: the third entry is refused as a full table and changes nothing, and a place
    /// let go is taken again.
    fn refuses_the_third(limits: &SessionLimits, admit: Admit, release: Release, held: Held) {
        let mut observer = ApplicationLayerObserver::with_limits(limits);
        admit(&mut observer, 0).expect("under the quota");
        admit(&mut observer, 1).expect("under the quota");
        assert_eq!(admit(&mut observer, 2), Err(RegisterError::TableFull));
        assert_eq!(held(&observer), 2);
        assert!(release(&mut observer, 0));
        admit(&mut observer, 2).expect("a place is free under the quota");
        assert_eq!(held(&observer), 2);
    }

    #[cfg(feature = "query-queryable")]
    fn queryable(
        observer: &mut ApplicationLayerObserver,
        index: usize,
    ) -> Result<(), RegisterError> {
        let key = std::format!("bound/queryable/{index}");
        observer.queryables.register(&key, |_, _| {}).map(|_| ())
    }

    /// `MAX_QUERYABLES` with nothing stated.
    #[cfg(feature = "query-queryable")]
    #[test]
    fn max_queryables_with_nothing_stated_admits_what_the_build_admitted() {
        admits_what_the_build_admitted(caps::MAX_QUERYABLES, queryable, |o| o.queryables.len());
    }

    /// `MAX_QUERYABLES` stated as two: the third is refused, and the refusal takes no
    /// declaration id.
    #[cfg(feature = "query-queryable")]
    #[test]
    fn max_queryables_stated_refuses_the_next_and_takes_no_id() {
        let Some(limits) = stated_two(
            SessionLimits::select_max_queryables,
            MaxQueryables::DOMAIN.is_singleton(),
        ) else {
            return;
        };
        let mut observer = ApplicationLayerObserver::with_limits(&limits);
        let first = observer
            .queryables
            .register("bound/a", |_, _| {})
            .expect("under the quota");
        let second = observer
            .queryables
            .register("bound/b", |_, _| {})
            .expect("under the quota");
        assert_eq!(
            observer.queryables.register("bound/c", |_, _| {}),
            Err(RegisterError::TableFull)
        );
        assert_eq!(observer.queryables.len(), 2);
        assert!(observer.queryables.unregister(first));
        let third = observer
            .queryables
            .register("bound/c", |_, _| {})
            .expect("a place is free under the quota");
        assert_eq!(third.as_u64(), second.as_u64() + 1);
    }

    fn pending_query(
        observer: &mut ApplicationLayerObserver,
        index: usize,
    ) -> Result<(), RegisterError> {
        let rid = u32::try_from(index).expect("a test index");
        observer
            .replies
            .register(
                rid,
                1,
                None,
                crate::reply_acceptance::ReplyAcceptance::Any,
                |_| {},
                |_| {},
            )
            .map(|_| ())
    }

    /// `MAX_PENDING_QUERIES` with nothing stated.
    #[test]
    fn max_pending_queries_with_nothing_stated_admits_what_the_build_admitted() {
        admits_what_the_build_admitted(caps::MAX_PENDING_QUERIES, pending_query, |o| {
            o.replies.len()
        });
    }

    /// `MAX_PENDING_QUERIES` stated as two.
    #[test]
    fn max_pending_queries_stated_refuses_the_next() {
        if let Some(limits) = stated_two(
            SessionLimits::select_max_pending_queries,
            MaxPendingQueries::DOMAIN.is_singleton(),
        ) {
            refuses_the_third(
                &limits,
                pending_query,
                |o, index| {
                    o.replies
                        .unregister(u32::try_from(index).expect("a test index"))
                },
                |o| o.replies.len(),
            );
        }
    }

    #[cfg(feature = "declare-subscriber")]
    fn decl_observer(
        observer: &mut ApplicationLayerObserver,
        _: usize,
    ) -> Result<(), RegisterError> {
        observer
            .remote_subscribers
            .on_subscriber_declared(|_| {})
            .map(|_| ())
    }

    /// `MAX_DECL_OBSERVERS` with nothing stated.
    #[cfg(feature = "declare-subscriber")]
    #[test]
    fn max_decl_observers_with_nothing_stated_admits_what_the_build_admitted() {
        admits_what_the_build_admitted(caps::MAX_DECL_OBSERVERS, decl_observer, |o| {
            o.remote_subscribers.on_decl_len()
        });
    }

    /// `MAX_DECL_OBSERVERS` stated as two. The observer ids count from zero, one per install.
    #[cfg(feature = "declare-subscriber")]
    #[test]
    fn max_decl_observers_stated_refuses_the_next() {
        if let Some(limits) = stated_two(
            SessionLimits::select_max_decl_observers,
            MaxDeclObservers::DOMAIN.is_singleton(),
        ) {
            refuses_the_third(
                &limits,
                decl_observer,
                |o, index| {
                    o.remote_subscribers
                        .remove_subscriber_declared_sink(index as u64)
                },
                |o| o.remote_subscribers.on_decl_len(),
            );
        }
    }

    #[cfg(feature = "liveliness-subscriber")]
    fn liveliness_subscriber(
        observer: &mut ApplicationLayerObserver,
        index: usize,
    ) -> Result<(), RegisterError> {
        let key = std::format!("bound/liveliness/{index}");
        let sink = crate::declare::liveliness_sample::BoxedLivelinessSampleSink::new(|_| {});
        observer
            .liveliness_subscribers
            .register(index as u64, &key, false, sink)
            .map(|_| ())
    }

    /// `MAX_LIVELINESS_SUBSCRIPTIONS` with nothing stated.
    #[cfg(feature = "liveliness-subscriber")]
    #[test]
    fn max_liveliness_subscriptions_with_nothing_stated_admits_what_the_build_admitted() {
        admits_what_the_build_admitted(
            caps::MAX_LIVELINESS_SUBSCRIPTIONS,
            liveliness_subscriber,
            |o| o.liveliness_subscribers.slot_count(),
        );
    }

    /// `MAX_LIVELINESS_SUBSCRIPTIONS` stated as two.
    #[cfg(feature = "liveliness-subscriber")]
    #[test]
    fn max_liveliness_subscriptions_stated_refuses_the_next() {
        if let Some(limits) = stated_two(
            SessionLimits::select_max_liveliness_subscriptions,
            MaxLivelinessSubscriptions::DOMAIN.is_singleton(),
        ) {
            refuses_the_third(
                &limits,
                liveliness_subscriber,
                |o, index| o.liveliness_subscribers.unregister(index as u64),
                |o| o.liveliness_subscribers.slot_count(),
            );
        }
    }

    #[cfg(feature = "liveliness-token")]
    fn local_token(
        observer: &mut ApplicationLayerObserver,
        index: usize,
    ) -> Result<(), RegisterError> {
        let key = std::format!("bound/token/{index}");
        observer
            .local_tokens
            .register(index as u64, &key)
            .map(|_| ())
    }

    /// `MAX_LOCAL_TOKENS` with nothing stated.
    #[cfg(feature = "liveliness-token")]
    #[test]
    fn max_local_tokens_with_nothing_stated_admits_what_the_build_admitted() {
        admits_what_the_build_admitted(caps::MAX_LOCAL_TOKENS, local_token, |o| {
            o.local_tokens.len()
        });
    }

    /// `MAX_LOCAL_TOKENS` stated as two.
    #[cfg(feature = "liveliness-token")]
    #[test]
    fn max_local_tokens_stated_refuses_the_next() {
        if let Some(limits) = stated_two(
            SessionLimits::select_max_local_tokens,
            MaxLocalTokens::DOMAIN.is_singleton(),
        ) {
            refuses_the_third(
                &limits,
                local_token,
                |o, index| o.local_tokens.unregister(index as u64),
                |o| o.local_tokens.len(),
            );
        }
    }

    #[cfg(feature = "liveliness-get")]
    fn liveliness_get(
        observer: &mut ApplicationLayerObserver,
        index: usize,
    ) -> Result<(), RegisterError> {
        observer
            .liveliness_gets
            .register_get(index as u64, None, |_| {}, |_| {})
            .map(|_| ())
    }

    /// `MAX_PENDING_LIVELINESS_GETS` with nothing stated.
    #[cfg(feature = "liveliness-get")]
    #[test]
    fn max_pending_liveliness_gets_with_nothing_stated_admits_what_the_build_admitted() {
        admits_what_the_build_admitted(caps::MAX_PENDING_LIVELINESS_GETS, liveliness_get, |o| {
            o.liveliness_gets.len()
        });
    }

    /// `MAX_PENDING_LIVELINESS_GETS` stated as two.
    #[cfg(feature = "liveliness-get")]
    #[test]
    fn max_pending_liveliness_gets_stated_refuses_the_next() {
        if let Some(limits) = stated_two(
            SessionLimits::select_max_pending_liveliness_gets,
            MaxPendingLivelinessGets::DOMAIN.is_singleton(),
        ) {
            refuses_the_third(
                &limits,
                liveliness_get,
                |o, index| o.liveliness_gets.unregister(index as u64),
                |o| o.liveliness_gets.len(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps;
    use crate::limit_binding::{LimitEntry, LimitSpec, LimitValue, Outside, Quota};
    use crate::policy_binding::{Driven, LimitKind, Storage};

    /// Every limit of `crate::caps` with its binding, by id.
    fn binding(id: &str) -> crate::policy_binding::LimitBinding {
        use crate::caps::binding as b;
        let all = [
            ("MAX_SUBSCRIPTIONS", b::MAX_SUBSCRIPTIONS),
            ("HANDSHAKE_COOKIE_BYTES", b::HANDSHAKE_COOKIE_BYTES),
            ("MAX_TASKS", b::MAX_TASKS),
            ("PICO_TX_QUEUE_SIZE", b::PICO_TX_QUEUE_SIZE),
        ];
        all.iter()
            .find(|(name, _)| *name == id)
            .map(|(_, binding)| *binding)
            .expect("a limit this test names")
    }

    fn ids<S>(table: &[LimitEntry<S>]) -> std::vec::Vec<&'static str> {
        table.iter().map(LimitEntry::id).collect()
    }

    /// The two tables hold each limit a stage after the build may decide once, and no capacity:
    /// a capacity sizes storage only the build can size.
    #[test]
    fn the_tables_hold_every_open_limit_once_and_no_capacity() {
        let mut all = ids(&SESSION_LIMITS);
        all.extend(ids(&RUNTIME_LIMITS));
        let count = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), count, "a limit is in a table twice");
        assert_eq!(count, SESSION_LIMIT_COUNT + RUNTIME_LIMIT_COUNT);
        for capacity in ["HANDSHAKE_COOKIE_BYTES", "MAX_TASKS"] {
            assert_eq!(binding(capacity).storage, Storage::Capacity);
            assert!(!all.contains(&capacity), "{capacity} is a capacity alone");
        }
        assert_eq!(binding("MAX_SUBSCRIPTIONS").storage, Storage::Both);
        assert!(all.contains(&"MAX_SUBSCRIPTIONS"));
    }

    /// A runtime-wide limit is the node's, every other the session's.
    #[test]
    fn a_limit_is_in_the_snapshot_of_its_widest_scope() {
        assert!(ids(&RUNTIME_LIMITS).contains(&"EVENT_RING_SLOTS"));
        assert!(ids(&RUNTIME_LIMITS).contains(&"MAX_LOCATOR_LEN"));
        assert!(ids(&SESSION_LIMITS).contains(&"MAX_REMOTE_DECLS"));
        assert!(ids(&SESSION_LIMITS).contains(&"DELIVERY_LANE_EVENTS"));
    }

    /// Each entry's kind and driver are the declaration's, and the build's value is inside the
    /// domain the build allows.
    #[test]
    fn each_entry_holds_its_build_value_inside_its_domain() {
        let session = SessionLimits::defaults();
        for entry in SESSION_LIMITS.iter() {
            let value = entry.value_in(&session);
            assert!(entry.domain().contains(value), "{}: {value}", entry.id());
            assert_eq!(entry.kind() == LimitKind::Bound, entry.driven().is_some());
        }
        let runtime = RuntimeLimits::defaults();
        for entry in RUNTIME_LIMITS.iter() {
            assert!(
                entry.domain().contains(entry.value_in(&runtime)),
                "{}",
                entry.id()
            );
        }
    }

    /// The build defaults are what the build runs with today: a table the heap grows is
    /// unbounded there and its capacity on the fixed profile; a limit the code refuses past is
    /// its build value, `0` read as no bound where the limit says so; a parameter is its value.
    #[test]
    fn the_build_defaults_are_what_the_build_runs_with_today() {
        let limits = SessionLimits::defaults();
        let subscriptions = if crate::bounded::ENFORCES_CAPACITY {
            Quota::at_most(caps::MAX_SUBSCRIPTIONS)
        } else {
            Quota::UNBOUNDED
        };
        assert_eq!(limits.max_subscriptions(), subscriptions);
        // Sized on every profile, so its capacity in both.
        assert_eq!(
            limits.max_keyexpr_bytes(),
            Quota::at_most(caps::MAX_KEYEXPR_BYTES)
        );
        // `0` is no bound for these, the build's value otherwise.
        assert_eq!(
            limits.query_parameters_max_bytes(),
            Quota::from_build(caps::QUERY_PARAMETERS_MAX_BYTES, true)
        );
        assert_eq!(
            limits.querier_max_pending_queries(),
            Quota::from_build(caps::QUERIER_MAX_PENDING_QUERIES, true)
        );
        assert_eq!(
            limits.max_shared_key_ids(),
            Quota::at_most(caps::MAX_SHARED_KEY_IDS)
        );
        assert_eq!(limits.pico_tx_queue_size(), caps::PICO_TX_QUEUE_SIZE);
        assert_eq!(
            RuntimeLimits::defaults().event_ring_slots(),
            caps::EVENT_RING_SLOTS
        );
    }

    /// A selection inside the domain is held and read back; one outside is refused and leaves the
    /// snapshot as it was.
    #[test]
    fn a_selection_follows_the_domain_and_a_refusal_changes_nothing() {
        let mut limits = SessionLimits::defaults();
        // A parameter outside its declared range, `1..=16`.
        let refused = limits.select_pico_tx_queue_size(17).unwrap_err();
        assert_eq!(refused.limit, "PICO_TX_QUEUE_SIZE");
        assert_eq!(limits, SessionLimits::defaults());
        let range = binding("PICO_TX_QUEUE_SIZE").range;
        assert_eq!(range, Some((1, 16)));
        if MaxSubscriptions::HELD == 1 {
            // A count under the build's capacity, or any count where the heap sizes nothing.
            limits
                .select_max_subscriptions(Quota::at_most(1))
                .expect("inside the domain");
            assert_eq!(limits.max_subscriptions(), Quota::at_most(1));
            let unbounded = limits.select_max_subscriptions(Quota::UNBOUNDED);
            assert_eq!(unbounded.is_ok(), !crate::bounded::ENFORCES_CAPACITY);
        }
        // A bound sized on every profile is never unbounded.
        let entry = SESSION_LIMITS
            .iter()
            .find(|entry| entry.id() == "MAX_KEYEXPR_BYTES")
            .expect("an open limit");
        assert_eq!(entry.driven(), Some(Driven::Remote));
        if !entry.domain().is_singleton() {
            let refused = entry
                .select(&mut limits, LimitValue::Unbounded)
                .unwrap_err();
            assert_eq!(
                refused.why,
                Outside::UnboundedOverCapacity {
                    capacity: caps::MAX_KEYEXPR_BYTES
                }
            );
        }
    }
}
