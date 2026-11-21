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
//! runs with today, so a snapshot that holds them changes nothing. Which limits' readers have moved
//! is declared once, by each limit's `read` in the declaration
//! ([`crate::limit_binding::LimitSpec::READ_FROM_SNAPSHOT`]), and a document that states a limit
//! whose readers still read the build is refused by name.

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

    /// A directory of a node's locators, held to the `MAX_LOCATOR_LEN` of `limits` as the
    /// loop that dials from it holds it.
    fn locator_directory(limits: &RuntimeLimits) -> crate::locator_directory::LocatorDirectory<4> {
        let mut directory = crate::locator_directory::LocatorDirectory::new();
        directory.limit_to(limits.max_locator_len_held());
        directory
    }

    /// A Hello's confirmation that one node may be reached at `locator`.
    fn confirm_hint(
        directory: &mut crate::locator_directory::LocatorDirectory<4>,
        locator: &str,
    ) -> Result<(), crate::locator_directory::DirectoryRefusal> {
        use crate::locator_directory::{Lifetime, LocatorSource};
        directory.confirm(
            [0xa1; 16],
            locator,
            LocatorSource::Hello,
            0,
            Lifetime::Millis(1_000),
        )
    }

    /// `MAX_LOCATOR_LEN` with nothing stated: the directory keeps a locator of the build's length
    /// and refuses one a byte longer, as its rows sized by the build did.
    #[test]
    fn max_locator_len_with_nothing_stated_admits_what_the_build_admitted() {
        use crate::locator_directory::DirectoryRefusal;
        let mut directory = locator_directory(&RuntimeLimits::defaults());
        assert_eq!(
            directory.locator_len(),
            Quota::at_most(caps::MAX_LOCATOR_LEN)
        );
        let longest = "l".repeat(caps::MAX_LOCATOR_LEN);
        confirm_hint(&mut directory, &longest).expect("the build's length is kept");
        let longer = "l".repeat(caps::MAX_LOCATOR_LEN + 1);
        assert_eq!(
            confirm_hint(&mut directory, &longer),
            Err(DirectoryRefusal::LocatorTooLong)
        );
        assert_eq!(directory.len(), 1);
        assert_eq!(directory.refused(), 1);
    }

    /// `MAX_LOCATOR_LEN` stated as two: a locator of three bytes is refused as too long and
    /// counted, the rows held stay as they were, and a hint already held is refreshed.
    #[test]
    fn max_locator_len_stated_refuses_the_next_byte_and_keeps_the_rows() {
        use crate::locator_directory::DirectoryRefusal;
        let mut limits = RuntimeLimits::defaults();
        let stated = limits.select_max_locator_len(Quota::at_most(2));
        if MaxLocatorLen::DOMAIN.is_singleton() {
            // A build that keeps the build's value alone refuses the statement itself.
            assert!(stated.is_err(), "a build of one value refuses two");
            return;
        }
        stated.expect("two is inside the domain");
        let mut directory = locator_directory(&limits);
        assert_eq!(directory.locator_len(), Quota::at_most(2));
        confirm_hint(&mut directory, "ab").expect("under the quota");
        assert_eq!(
            confirm_hint(&mut directory, "abc"),
            Err(DirectoryRefusal::LocatorTooLong)
        );
        assert_eq!(directory.len(), 1, "a refusal leaves the rows as they were");
        assert_eq!(directory.refused(), 1);
        confirm_hint(&mut directory, "ab").expect("a held hint is refreshed");
        assert_eq!(directory.len(), 1);
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

    /// Two, as `select` states it, and `check` run on the snapshot that states it. A build that
    /// keeps the build's value alone (`singleton`) refuses the statement itself, and that
    /// refusal is what the build is checked for: it has no snapshot of two to run `check` on.
    fn held_to_two(select: Select, singleton: bool, check: impl FnOnce(&SessionLimits)) {
        let mut limits = SessionLimits::defaults();
        let stated = select(&mut limits, Quota::at_most(2));
        if singleton {
            assert!(stated.is_err(), "a build of one value refuses two");
        } else {
            stated.expect("two is inside the domain");
            check(&limits);
        }
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

    /// The key ids `1..=count`, each naming a key of its own, as an open is handed them.
    #[cfg(feature = "shared-key-ids")]
    fn key_ids(count: usize) -> crate::shared_key_ids::KeyIdsAtOpen {
        let keys: std::vec::Vec<std::string::String> =
            (1..=count).map(|id| std::format!("bound/k{id}")).collect();
        let entries = keys.iter().enumerate().map(|(at, key)| {
            let id = u16::try_from(at + 1).expect("a test count of ids");
            (id, key.as_str())
        });
        crate::shared_key_ids::KeyIdsAtOpen {
            ids: Some(std::sync::Arc::new(
                crate::shared_key_ids::KeyIds::new(entries).expect("a valid dictionary"),
            )),
            links: std::vec::Vec::new(),
        }
    }

    /// `MAX_SHARED_KEY_IDS` with nothing stated: an open is handed as many entries as the build
    /// states and refused one more.
    #[cfg(feature = "shared-key-ids")]
    #[test]
    fn max_shared_key_ids_with_nothing_stated_admits_what_the_build_admitted() {
        let build = caps::MAX_SHARED_KEY_IDS;
        if build >= usize::from(u16::MAX) {
            // Every id a wireexpr has fits: no dictionary of distinct ids is past the build's.
            return;
        }
        let limits = SessionLimits::defaults();
        assert_eq!(key_ids(build).check_limits(&limits), Ok(()));
        assert_eq!(
            key_ids(build + 1).check_limits(&limits),
            Err(crate::shared_key_ids::KeyIdsRefused::TooMany {
                stated: build + 1,
                limit: build
            })
        );
    }

    /// `MAX_SHARED_KEY_IDS` stated as two: a dictionary of three is refused when it is handed
    /// over, and the dictionary it was is left as it was; one of two is held.
    #[cfg(feature = "shared-key-ids")]
    #[test]
    fn max_shared_key_ids_stated_refuses_the_next() {
        held_to_two(
            SessionLimits::select_max_shared_key_ids,
            MaxSharedKeyIds::DOMAIN.is_singleton(),
            |limits| {
                let three = key_ids(3);
                assert_eq!(
                    three.check_limits(limits),
                    Err(crate::shared_key_ids::KeyIdsRefused::TooMany {
                        stated: 3,
                        limit: 2
                    })
                );
                assert_eq!(three, key_ids(3), "a refusal changes no dictionary");
                assert_eq!(key_ids(2).check_limits(limits), Ok(()));
            },
        );
    }

    /// The queries of ids `0..count` a link made from `limits` still remembers the key form of
    /// after it noted each, in order, as a session's creator makes the link.
    #[cfg(feature = "shared-key-ids")]
    fn noted_after(limits: &SessionLimits, count: u32) -> std::vec::Vec<u32> {
        use crate::shared_key_ids::{KeyIds, LinkKeys, ReplyKey};
        let ids = std::sync::Arc::new(KeyIds::new([(41, "bound/rig")]).expect("valid"));
        let mut keys = LinkKeys::new(
            Some(ids),
            crate::policy::KeyWireForm::Shared,
            limits.link_noted_requests(),
        );
        for rid in 0..count {
            keys.note_request(rid, 41, None, true, false);
        }
        (0..count)
            .filter(|rid| keys.reply_key(*rid, "bound/rig") != ReplyKey::Literal)
            .collect()
    }

    /// `LINK_NOTED_REQUESTS` with nothing stated: a link remembers the build's number of queries,
    /// the oldest giving way to the next.
    #[cfg(feature = "shared-key-ids")]
    #[test]
    fn link_noted_requests_with_nothing_stated_holds_the_builds_value() {
        let build = caps::LINK_NOTED_REQUESTS;
        let Ok(count) = u32::try_from(build + 1) else {
            return;
        };
        let kept = noted_after(&SessionLimits::defaults(), count);
        assert_eq!(kept.len(), build);
        assert_eq!(kept.first(), Some(&1), "the oldest gave way");
    }

    /// A transport whose program takes every link up and every byte sent, under a host lock, as a
    /// session that opens links over it sees it under `limits`.
    #[cfg(all(feature = "app-link", target_has_atomic = "ptr"))]
    fn app_transport(limits: &SessionLimits) -> crate::app_transport::SessionTransport {
        use crate::app_link_table::{
            AppLinkKind, AppLinkTable, LinkHandle, ProgramOpen, ProgramSend,
        };
        use crate::app_transport::{AppPort, AppTransport, SessionTransport, TableLock};
        struct Lock(std::sync::Mutex<AppLinkTable>);
        impl TableLock for Lock {
            fn lock_with(&self, f: &mut dyn FnMut(&mut AppLinkTable)) {
                f(&mut self.0.lock().unwrap());
            }
        }
        struct Up;
        impl AppPort for Up {
            fn open(&self, _: LinkHandle, _: AppLinkKind, _: &str) -> ProgramOpen {
                ProgramOpen::Up
            }
            fn send(&self, _: LinkHandle, bytes: &[u8]) -> ProgramSend {
                ProgramSend::Wrote(bytes.len())
            }
            fn close(&self, _: LinkHandle) {}
        }
        let transport = AppTransport::new(
            std::boxed::Box::new(Lock(std::sync::Mutex::new(AppLinkTable::new()))),
            std::boxed::Box::new(Up),
        );
        SessionTransport::new(std::sync::Arc::new(transport), limits)
    }

    /// `APP_LINK_QUEUE_BYTES` with nothing stated: a link queues the build's number of bytes the
    /// session has not read and refuses the next byte.
    #[cfg(all(feature = "app-link", target_has_atomic = "ptr"))]
    #[test]
    fn app_link_queue_bytes_with_nothing_stated_admits_what_the_build_admitted() {
        use crate::app_link_table::{AppLinkKind, InboundRefusal};
        let build = caps::APP_LINK_QUEUE_BYTES;
        if build < 2 {
            // An empty queue takes anything, so a bound under two bytes refuses nothing here.
            return;
        }
        let session = app_transport(&SessionLimits::defaults());
        let link = session.begin_open(AppLinkKind::StreamDial, "tcp/192.0.2.1:7447");
        let transport = &session.transport;
        transport
            .received(link, &std::vec![0u8; build - 1], None)
            .expect("an empty queue takes the bytes");
        transport
            .received(link, b"a", None)
            .expect("the build's bound is reached, not passed");
        assert_eq!(
            transport.received(link, b"b", None),
            Err(InboundRefusal::Full)
        );
        assert_eq!(transport.with(|table| table.queued_bytes(link)), build);
    }

    /// `APP_LINK_QUEUE_BYTES` stated as two: the third byte is refused and nothing of it is
    /// taken, while a link another session opened over the same transport keeps its own bound.
    #[cfg(all(feature = "app-link", target_has_atomic = "ptr"))]
    #[test]
    fn app_link_queue_bytes_stated_refuses_the_next() {
        use crate::app_link_table::{AppLinkKind, InboundRefusal};
        held_to_two(
            SessionLimits::select_app_link_queue_bytes,
            AppLinkQueueBytes::DOMAIN.is_singleton(),
            |limits| {
                let session = app_transport(limits);
                let link = session.begin_open(AppLinkKind::StreamDial, "tcp/192.0.2.1:7447");
                let transport = &session.transport;
                transport
                    .received(link, b"a", None)
                    .expect("under the quota");
                transport
                    .received(link, b"b", None)
                    .expect("under the quota");
                assert_eq!(
                    transport.received(link, b"c", None),
                    Err(InboundRefusal::Full)
                );
                assert_eq!(transport.with(|table| table.queued_bytes(link)), 2);
                let other = crate::app_transport::SessionTransport::new(
                    std::sync::Arc::clone(transport),
                    &SessionLimits::defaults(),
                );
                let wide = other.begin_open(AppLinkKind::StreamDial, "tcp/192.0.2.2:7447");
                transport
                    .received(wide, b"a", None)
                    .expect("under the quota");
                transport
                    .received(wide, b"b", None)
                    .expect("under the quota");
                if caps::APP_LINK_QUEUE_BYTES >= 3 {
                    assert_eq!(
                        transport.received(wide, b"c", None),
                        Ok(()),
                        "the build's bound is the other session's"
                    );
                }
            },
        );
    }

    /// `LINK_NOTED_REQUESTS` stated as two: a link remembers the last two queries it noted.
    #[cfg(feature = "shared-key-ids")]
    #[test]
    fn link_noted_requests_stated_is_the_value_the_link_uses() {
        let mut limits = SessionLimits::defaults();
        let stated = limits.select_link_noted_requests(2);
        if LinkNotedRequests::DOMAIN.is_singleton() {
            // A build that keeps the build's value alone refuses the statement itself.
            assert!(stated.is_err());
            return;
        }
        stated.expect("two is inside the domain");
        assert_eq!(noted_after(&limits, 5), [3, 4]);
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
        held_to_two(
            SessionLimits::select_max_queryables,
            MaxQueryables::DOMAIN.is_singleton(),
            |limits| {
                let mut observer = ApplicationLayerObserver::with_limits(limits);
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
            },
        );
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
        held_to_two(
            SessionLimits::select_max_pending_queries,
            MaxPendingQueries::DOMAIN.is_singleton(),
            |limits| {
                refuses_the_third(
                    limits,
                    pending_query,
                    |o, index| {
                        o.replies
                            .unregister(u32::try_from(index).expect("a test index"))
                    },
                    |o| o.replies.len(),
                )
            },
        );
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
        held_to_two(
            SessionLimits::select_max_decl_observers,
            MaxDeclObservers::DOMAIN.is_singleton(),
            |limits| {
                refuses_the_third(
                    limits,
                    decl_observer,
                    |o, index| {
                        o.remote_subscribers
                            .remove_subscriber_declared_sink(index as u64)
                    },
                    |o| o.remote_subscribers.on_decl_len(),
                )
            },
        );
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
        held_to_two(
            SessionLimits::select_max_liveliness_subscriptions,
            MaxLivelinessSubscriptions::DOMAIN.is_singleton(),
            |limits| {
                refuses_the_third(
                    limits,
                    liveliness_subscriber,
                    |o, index| o.liveliness_subscribers.unregister(index as u64),
                    |o| o.liveliness_subscribers.slot_count(),
                )
            },
        );
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
        held_to_two(
            SessionLimits::select_max_local_tokens,
            MaxLocalTokens::DOMAIN.is_singleton(),
            |limits| {
                refuses_the_third(
                    limits,
                    local_token,
                    |o, index| o.local_tokens.unregister(index as u64),
                    |o| o.local_tokens.len(),
                )
            },
        );
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
        held_to_two(
            SessionLimits::select_max_pending_liveliness_gets,
            MaxPendingLivelinessGets::DOMAIN.is_singleton(),
            |limits| {
                refuses_the_third(
                    limits,
                    liveliness_get,
                    |o, index| o.liveliness_gets.unregister(index as u64),
                    |o| o.liveliness_gets.len(),
                )
            },
        );
    }

    /// The requesters a session on the slot profile holds beside its slot, held to `limits` as the
    /// session's dispatch holds them to the limits the session was opened with.
    #[cfg(feature = "storage-profile")]
    fn slot_requesters(
        limits: &SessionLimits,
    ) -> crate::slot_observer::Requesters<
        crate::reply_sink::BoxedReplySink,
        crate::reply_sink::BoxedReplySink,
    > {
        let mut requesters = crate::slot_observer::Requesters::new();
        requesters.limit_to(limits);
        requesters
    }

    /// `MAX_PENDING_QUERIES` stated as two, on the requesters of a session on the slot profile:
    /// the third pending query is refused as a full table and leaves the two pending.
    #[cfg(feature = "storage-profile")]
    #[test]
    fn max_pending_queries_stated_refuses_the_next_on_a_slot_sessions_requesters() {
        held_to_two(
            SessionLimits::select_max_pending_queries,
            MaxPendingQueries::DOMAIN.is_singleton(),
            |limits| {
                let mut requesters = slot_requesters(limits);
                let mut pend = |rid: u32| {
                    requesters
                        .replies
                        .register_sink(
                            rid,
                            1,
                            None,
                            crate::reply_acceptance::ReplyAcceptance::Any,
                            crate::reply_sink::BoxedReplySink::new(|_| {}, |_| {}),
                        )
                        .map(|_| ())
                };
                pend(0).expect("under the quota");
                pend(1).expect("under the quota");
                assert_eq!(pend(2), Err(RegisterError::TableFull));
                assert_eq!(requesters.replies.len(), 2);
            },
        );
    }

    /// `MAX_PENDING_LIVELINESS_GETS` stated as two, on the requesters of a session on the slot
    /// profile: the third pending get is refused as a full table and leaves the two pending.
    #[cfg(all(feature = "storage-profile", feature = "liveliness-get"))]
    #[test]
    fn max_pending_liveliness_gets_stated_refuses_the_next_on_a_slot_sessions_requesters() {
        held_to_two(
            SessionLimits::select_max_pending_liveliness_gets,
            MaxPendingLivelinessGets::DOMAIN.is_singleton(),
            |limits| {
                let mut requesters = slot_requesters(limits);
                let mut ask = |interest_id: u64| {
                    requesters.liveliness_gets.register(
                        interest_id,
                        None,
                        crate::reply_sink::BoxedReplySink::new(|_| {}, |_| {}),
                    )
                };
                assert_eq!(ask(1), Ok(true), "under the quota");
                assert_eq!(ask(2), Ok(true), "under the quota");
                assert_eq!(ask(3), Err(RegisterError::TableFull));
                assert_eq!(requesters.liveliness_gets.len(), 2);
            },
        );
    }

    /// One FUTURE interest of the peer, the `index`th, answered through the subscriber registry
    /// the creator held to its limits. An interest the side cannot remember is counted, not
    /// returned as an error; the count moving is what reads here as a refusal.
    #[cfg(feature = "declare-subscriber")]
    fn future_interest(
        observer: &mut ApplicationLayerObserver,
        index: usize,
    ) -> Result<(), RegisterError> {
        let refused = observer
            .subscribers
            .interest_staging_refusals()
            .future_interests;
        observer
            .subscribers
            .respond_to_subscriber_interest_borrowed(index as u64, None, false, false, true);
        let now = observer
            .subscribers
            .interest_staging_refusals()
            .future_interests;
        if now == refused {
            Ok(())
        } else {
            Err(RegisterError::TableFull)
        }
    }

    /// `MAX_INBOUND_SUB_INTERESTS` with nothing stated.
    #[cfg(feature = "declare-subscriber")]
    #[test]
    fn max_inbound_sub_interests_with_nothing_stated_admits_what_the_build_admitted() {
        admits_what_the_build_admitted(caps::MAX_INBOUND_SUB_INTERESTS, future_interest, |o| {
            o.subscribers.peer().interest_count()
        });
    }

    /// `MAX_INBOUND_SUB_INTERESTS` stated as two: the third FUTURE interest is not remembered,
    /// is counted, and takes no declaration id; the two rows are kept, and a row the peer
    /// cancels frees its place.
    #[cfg(feature = "declare-subscriber")]
    #[test]
    fn max_inbound_sub_interests_stated_refuses_the_next_and_takes_no_id() {
        held_to_two(
            SessionLimits::select_max_inbound_sub_interests,
            MaxInboundSubInterests::DOMAIN.is_singleton(),
            |limits| {
                let mut observer = ApplicationLayerObserver::with_limits(limits);
                let subscribers = &mut observer.subscribers;
                for interest in 0..3 {
                    subscribers.respond_to_subscriber_interest_borrowed(
                        interest, None, false, false, true,
                    );
                }
                assert_eq!(subscribers.peer().interest_count(), 2);
                assert_eq!(
                    subscribers.interest_staging_refusals(),
                    crate::pubsub::SubInterestRefusals {
                        future_interests: 1,
                        ..Default::default()
                    }
                );
                // The two rows took the ids 1 and 2; the refused interest took none.
                let id = subscribers
                    .register("bound/a", |_| {})
                    .expect("no quota on subscriptions is stated");
                assert_eq!(id.as_u64(), 3);
                // The peer cancels its first interest: the place it held is taken again.
                subscribers.respond_to_subscriber_interest_borrowed(0, None, false, false, false);
                subscribers.respond_to_subscriber_interest_borrowed(3, None, false, false, true);
                assert_eq!(subscribers.peer().interest_count(), 2);
                assert_eq!(subscribers.interest_staging_refusals().future_interests, 1);
            },
        );
    }

    /// One frame of queries on `bound/reply`, one for each request id of `rids`, as a peer
    /// sends them.
    #[cfg(feature = "query-queryable")]
    fn queries(rids: core::ops::Range<u32>) -> crate::driver_loop::DriverLoopOutcome {
        let messages = rids
            .map(|rid| {
                let request =
                    crate::request_build::build_request_query(rid, 0, Some("bound/reply"))
                        .expect("a literal key builds");
                crate::network_message::NetworkMessage::Request(std::boxed::Box::new(request))
            })
            .collect();
        crate::driver_loop::DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages,
            has_ext: false,
            extensions: std::vec::Vec::new(),
            priority: crate::qos::Priority::DEFAULT,
        }
    }

    /// A one-byte reply on `bound/reply`, as a queryable of a peer's session describes it.
    #[cfg(feature = "query-queryable")]
    fn reply_parts() -> crate::reply_stage::ReplyParts<'static> {
        use crate::reply_stage::{PartsBody, PartsKind, ReplyParts};
        ReplyParts {
            rid: 0,
            keyexpr: "bound/reply",
            responder: None,
            qos: crate::sample::QosLevel::DEFAULT,
            #[cfg(feature = "pubsub-ts-stack")]
            ts_stack: None,
            kind: PartsKind::Reply {
                body: PartsBody::Put(b"r"),
                encoding: None,
                timestamp: None,
                attachment: None,
                source_info: None,
            },
        }
    }

    /// `MAX_PENDING_REPLIES` with nothing stated: a queryable answers one query once past the
    /// build's count, and the heap stages every answer, as it did, while a fixed stage holds its
    /// capacity and refuses the last.
    #[cfg(feature = "query-queryable")]
    #[test]
    fn max_pending_replies_with_nothing_stated_admits_what_the_build_admitted() {
        let mut observer = ApplicationLayerObserver::with_limits(&SessionLimits::defaults());
        observer
            .queryables
            .register("bound/reply", |_, responder| {
                for _ in 0..=caps::MAX_PENDING_REPLIES {
                    responder.reply(b"r");
                }
            })
            .expect("no quota is stated on the queryables");
        observer.dispatch_event(crate::driver_loop::IterationEvent::Poll(&queries(0..1)));
        let refused = usize::from(crate::bounded::ENFORCES_CAPACITY);
        assert_eq!(
            observer.pending_reply_count(),
            caps::MAX_PENDING_REPLIES + 1 - refused
        );
        assert_eq!(
            observer.reply_refusals().staging_full,
            u32::from(crate::bounded::ENFORCES_CAPACITY)
        );
    }

    /// `MAX_PENDING_REPLIES` stated as two: the third reply is refused to the handler as a full
    /// stage and counted, the two staged and the query's `Final` are kept, and the stage keeps
    /// its quota when its replies are taken to be sent. A peer's tables, where a slot observer
    /// stages, are held the same, and keep the quota when the peer is forgotten.
    #[cfg(feature = "query-queryable")]
    #[test]
    fn max_pending_replies_stated_refuses_the_next() {
        use crate::query_sink::ReplyError;
        use crate::reply_stage::ReplyStaging;
        use std::sync::{Arc, Mutex};
        held_to_two(
            SessionLimits::select_max_pending_replies,
            MaxPendingReplies::DOMAIN.is_singleton(),
            |limits| {
                let mut observer = ApplicationLayerObserver::with_limits(limits);
                let answers = Arc::new(Mutex::new(std::vec::Vec::new()));
                let told = Arc::clone(&answers);
                observer
                    .queryables
                    .register("bound/reply", move |_, responder| {
                        let mut seen = told.lock().expect("not poisoned");
                        for _ in 0..3 {
                            seen.push(responder.try_reply(b"r"));
                        }
                    })
                    .expect("no quota is stated on the queryables");
                observer.dispatch_event(crate::driver_loop::IterationEvent::Poll(&queries(0..1)));
                assert_eq!(
                    *answers.lock().expect("not poisoned"),
                    [Ok(()), Ok(()), Err(ReplyError::StagingFull)]
                );
                assert_eq!(observer.pending_reply_count(), 2);
                assert_eq!(observer.reply_refusals().staging_full, 1);
                assert_eq!(
                    observer.pending_final_count(),
                    1,
                    "the query still owes its Final"
                );

                let mut owed = crate::owed_replies::OwedReplies::new();
                observer.take_owed_reply_bodies(&mut owed);
                assert_eq!(observer.pending_reply_count(), 0);
                observer.dispatch_event(crate::driver_loop::IterationEvent::Poll(&queries(1..2)));
                assert_eq!(
                    observer.pending_reply_count(),
                    2,
                    "the quota stayed with the stage"
                );
                assert_eq!(observer.reply_refusals().staging_full, 2);

                let mut peers = crate::peer_tables::PeerTables::new();
                peers.limit_to(limits);
                assert_eq!(peers.replies.stage_parts(reply_parts()), Ok(()));
                assert_eq!(peers.replies.stage_parts(reply_parts()), Ok(()));
                assert_eq!(
                    peers.replies.stage_parts(reply_parts()),
                    Err(ReplyError::StagingFull)
                );
                assert_eq!(peers.replies.staged(), 2);
                peers.forget_peer();
                assert_eq!(peers.replies.stage_parts(reply_parts()), Ok(()));
                assert_eq!(peers.replies.stage_parts(reply_parts()), Ok(()));
                assert_eq!(
                    peers.replies.stage_parts(reply_parts()),
                    Err(ReplyError::StagingFull)
                );
                assert_eq!(peers.replies.refusals().staging_full, 2);
            },
        );
    }

    /// `MAX_PENDING_DECLARES` with nothing stated, on both tables it bounds: the answers to
    /// the peer's subscriber interests and to its token interests. Each CURRENT interest that
    /// nothing matches is answered by its `Final` alone, one item.
    #[cfg(any(feature = "declare-subscriber", feature = "liveliness-token"))]
    #[test]
    fn max_pending_declares_with_nothing_stated_admits_what_the_build_admitted() {
        let admitted = if crate::bounded::ENFORCES_CAPACITY {
            caps::MAX_PENDING_DECLARES
        } else {
            caps::MAX_PENDING_DECLARES + 1
        };
        #[cfg(feature = "declare-subscriber")]
        {
            let mut observer = ApplicationLayerObserver::with_limits(&SessionLimits::defaults());
            for interest in 0..admitted as u64 {
                observer
                    .subscribers
                    .respond_to_subscriber_interest_borrowed(interest, None, false, true, false);
            }
            assert_eq!(observer.subscribers.interest_staging_refusals().chains, 0);
            assert_eq!(
                observer
                    .subscribers
                    .take_staged_sub_interest_replies()
                    .len(),
                admitted
            );
        }
        #[cfg(feature = "liveliness-token")]
        {
            let observer = ApplicationLayerObserver::with_limits(&SessionLimits::defaults());
            let mut pending: crate::bounded::BoundedVec<
                crate::declare::local_token::DeclResponseItem,
                { caps::MAX_PENDING_DECLARES },
            > = crate::bounded::BoundedVec::new();
            for interest in 0..admitted as u64 {
                observer
                    .local_tokens
                    .respond_to_interest_borrowed(None, interest, &mut pending)
                    .expect("no quota is stated");
            }
            assert_eq!(pending.len(), admitted);
        }
    }

    /// `MAX_PENDING_DECLARES` stated as two, on both tables it bounds: a chain of one match and
    /// its `Final` takes both places, the next chain is refused whole and stages nothing, and
    /// the drain frees the places for the chain after it.
    #[cfg(any(feature = "declare-subscriber", feature = "liveliness-token"))]
    #[test]
    fn max_pending_declares_stated_refuses_the_next_chain_whole() {
        held_to_two(
            SessionLimits::select_max_pending_declares,
            MaxPendingDeclares::DOMAIN.is_singleton(),
            |limits| {
                #[cfg(feature = "declare-subscriber")]
                {
                    let mut observer = ApplicationLayerObserver::with_limits(limits);
                    let subscribers = &mut observer.subscribers;
                    subscribers
                        .register("bound/a", |_| {})
                        .expect("no quota on subscriptions is stated");
                    assert_eq!(
                        subscribers
                            .respond_to_subscriber_interest_borrowed(1, None, false, true, false),
                        1
                    );
                    assert_eq!(
                        subscribers
                            .respond_to_subscriber_interest_borrowed(2, None, false, true, false),
                        0
                    );
                    assert_eq!(subscribers.interest_staging_refusals().chains, 1);
                    let staged = subscribers.take_staged_sub_interest_replies();
                    assert_eq!(staged.len(), 2);
                    assert!(matches!(
                        staged.last(),
                        Some(crate::pubsub::SubInterestReply::Final { interest_id: 1 })
                    ));
                    assert_eq!(
                        subscribers
                            .respond_to_subscriber_interest_borrowed(3, None, false, true, false),
                        1
                    );
                    assert_eq!(subscribers.take_staged_sub_interest_replies().len(), 2);
                }
                #[cfg(feature = "liveliness-token")]
                {
                    let mut observer = ApplicationLayerObserver::with_limits(limits);
                    observer
                        .local_tokens
                        .register(1, "bound/token")
                        .expect("no quota on tokens is stated");
                    let mut pending: crate::bounded::BoundedVec<
                        crate::declare::local_token::DeclResponseItem,
                        { caps::MAX_PENDING_DECLARES },
                    > = crate::bounded::BoundedVec::new();
                    let tokens = &observer.local_tokens;
                    assert_eq!(
                        tokens
                            .respond_to_interest_borrowed(None, 1, &mut pending)
                            .expect("two places take the chain"),
                        1
                    );
                    assert!(tokens
                        .respond_to_interest_borrowed(None, 2, &mut pending)
                        .is_err());
                    assert_eq!(pending.len(), 2);
                    pending.clear();
                    assert_eq!(
                        tokens
                            .respond_to_interest_borrowed(None, 3, &mut pending)
                            .expect("the drained places take the chain"),
                        1
                    );
                    assert_eq!(pending.len(), 2);
                }
            },
        );
    }

    /// A peer's declaration of the entity `id` in one of the tables it fills, handed to the
    /// door the session's receive path hands it to. A table answers a peer with nothing: a
    /// declaration it cannot take is dropped and counted.
    #[cfg(feature = "codec-declare")]
    type Declare = fn(&mut ApplicationLayerObserver, u64);
    /// The peer's withdrawal of the entity `id`.
    #[cfg(feature = "codec-declare")]
    type Withdraw = fn(&mut ApplicationLayerObserver, u64);
    /// How many entities the table holds, and how many declarations it refused.
    #[cfg(feature = "codec-declare")]
    type Tally = fn(&ApplicationLayerObserver) -> (usize, u32);

    /// With nothing stated a peer's table takes one past the build's count on the heap and the
    /// capacity on a fixed backing, refusing none of them, as it did when it read the build's
    /// constant; the fixed table refuses the next by its room.
    #[cfg(feature = "codec-declare")]
    fn declarations_admit_what_the_build_admitted(build: usize, declare: Declare, tally: Tally) {
        let mut observer = ApplicationLayerObserver::with_limits(&SessionLimits::defaults());
        let admitted = if crate::bounded::ENFORCES_CAPACITY {
            build
        } else {
            build + 1
        };
        for id in 1..=admitted as u64 {
            declare(&mut observer, id);
        }
        assert_eq!(tally(&observer), (admitted, 0));
        if crate::bounded::ENFORCES_CAPACITY {
            declare(&mut observer, admitted as u64 + 1);
            assert_eq!(
                tally(&observer),
                (admitted, 1),
                "refused by the table's room"
            );
        }
    }

    /// Held to two: the third declaration is refused and counted as a full table refuses it,
    /// and changes nothing held; an id held is declared again without a place, and a place the
    /// peer withdraws is taken again.
    #[cfg(feature = "codec-declare")]
    fn refuses_the_third_declaration(
        limits: &SessionLimits,
        declare: Declare,
        withdraw: Withdraw,
        tally: Tally,
    ) {
        let mut observer = ApplicationLayerObserver::with_limits(limits);
        declare(&mut observer, 1);
        declare(&mut observer, 2);
        assert_eq!(tally(&observer), (2, 0));
        declare(&mut observer, 3);
        assert_eq!(tally(&observer), (2, 1), "the third is refused and counted");
        declare(&mut observer, 2);
        assert_eq!(tally(&observer), (2, 1), "an id held needs no place");
        withdraw(&mut observer, 1);
        assert_eq!(tally(&observer), (1, 1));
        declare(&mut observer, 3);
        assert_eq!(tally(&observer), (2, 1), "a place withdrawn is taken again");
    }

    /// The keyexpr the peer declares the entity `id` of `plane` on: one per id, so no
    /// declaration repeats another's.
    #[cfg(feature = "codec-declare")]
    fn declared_key(plane: &str, id: u64) -> std::string::String {
        std::format!("bound/{plane}/{id}")
    }

    /// The peer's aliases the declarations resolve against: none, as every key is literal.
    #[cfg(any(
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "liveliness-subscriber"
    ))]
    fn no_aliases() -> hashbrown::HashMap<u64, std::string::String> {
        hashbrown::HashMap::new()
    }

    #[cfg(feature = "codec-declare")]
    fn alias(observer: &mut ApplicationLayerObserver, id: u64) {
        let declare = wz_session_core_test_support::declare_envelope_decl_kexpr(
            wz_session_core_test_support::decl_kexpr(id, &declared_key("alias", id)),
        );
        observer.subscribers.dispatch(
            &crate::network_message::NetworkMessage::Declare(std::boxed::Box::new(declare)),
            crate::sample::Reliability::Reliable,
        );
    }

    #[cfg(feature = "codec-declare")]
    fn alias_withdrawn(observer: &mut ApplicationLayerObserver, id: u64) {
        let undeclare = wz_session_core_test_support::declare_envelope_undecl_kexpr(
            wz_session_core_test_support::undecl_kexpr(id),
        );
        observer.subscribers.dispatch(
            &crate::network_message::NetworkMessage::Declare(std::boxed::Box::new(undeclare)),
            crate::sample::Reliability::Reliable,
        );
    }

    #[cfg(feature = "codec-declare")]
    fn alias_tally(observer: &ApplicationLayerObserver) -> (usize, u32) {
        let peer = observer.subscribers.peer();
        (peer.alias_count(), peer.alias_refusals())
    }

    /// `MAX_PEER_KEYEXPR_ALIASES` with nothing stated.
    #[cfg(feature = "codec-declare")]
    #[test]
    fn max_peer_keyexpr_aliases_with_nothing_stated_admits_what_the_build_admitted() {
        declarations_admit_what_the_build_admitted(
            caps::MAX_PEER_KEYEXPR_ALIASES,
            alias,
            alias_tally,
        );
    }

    /// `MAX_PEER_KEYEXPR_ALIASES` stated as two: the third alias is refused and counted, and
    /// a message that names it resolves to nothing, as one naming an id never declared does.
    #[cfg(feature = "codec-declare")]
    #[test]
    fn max_peer_keyexpr_aliases_stated_refuses_the_next() {
        held_to_two(
            SessionLimits::select_max_peer_keyexpr_aliases,
            MaxPeerKeyexprAliases::DOMAIN.is_singleton(),
            |limits| {
                refuses_the_third_declaration(limits, alias, alias_withdrawn, alias_tally);
                let mut observer = ApplicationLayerObserver::with_limits(limits);
                for id in 1..=3 {
                    alias(&mut observer, id);
                }
                assert_eq!(
                    observer.subscribers.resolve_inbound_mapping(3),
                    None,
                    "the refused alias names nothing"
                );
                assert_eq!(
                    observer.subscribers.resolve_inbound_mapping(2),
                    Some(declared_key("alias", 2))
                );
            },
        );
    }

    #[cfg(feature = "declare-subscriber")]
    fn remote_subscriber(observer: &mut ApplicationLayerObserver, id: u64) {
        let body = crate::transport_profile::owned::DeclareOwnedVariant::CodecZenohDeclSubscriber(
            wz_session_core_test_support::decl_subscriber(
                id,
                0,
                Some(&declared_key("subscriber", id)),
            ),
        );
        observer
            .remote_subscribers
            .dispatch_declare(&body, &no_aliases());
    }

    #[cfg(feature = "declare-subscriber")]
    fn remote_subscriber_withdrawn(observer: &mut ApplicationLayerObserver, id: u64) {
        let body = crate::transport_profile::owned::DeclareOwnedVariant::CodecZenohUndeclSubscriber(
            wz_session_core_test_support::undecl_subscriber(id),
        );
        observer
            .remote_subscribers
            .dispatch_declare(&body, &no_aliases());
    }

    #[cfg(feature = "declare-subscriber")]
    fn remote_subscriber_tally(observer: &ApplicationLayerObserver) -> (usize, u32) {
        let peer = observer.remote_subscribers.peer();
        (peer.declared_count(), peer.refusals())
    }

    #[cfg(feature = "declare-queryable")]
    fn remote_queryable(observer: &mut ApplicationLayerObserver, id: u64) {
        let body = crate::transport_profile::owned::DeclareOwnedVariant::CodecZenohDeclQueryable(
            wz_session_core_test_support::decl_queryable(
                id,
                0,
                Some(&declared_key("queryable", id)),
            ),
        );
        observer
            .remote_queryables
            .dispatch_declare(&body, &no_aliases());
    }

    #[cfg(feature = "declare-queryable")]
    fn remote_queryable_withdrawn(observer: &mut ApplicationLayerObserver, id: u64) {
        let body = crate::transport_profile::owned::DeclareOwnedVariant::CodecZenohUndeclQueryable(
            wz_session_core_test_support::undecl_queryable(id),
        );
        observer
            .remote_queryables
            .dispatch_declare(&body, &no_aliases());
    }

    #[cfg(feature = "declare-queryable")]
    fn remote_queryable_tally(observer: &ApplicationLayerObserver) -> (usize, u32) {
        let peer = observer.remote_queryables.peer();
        (peer.declared_count(), peer.refusals())
    }

    #[cfg(feature = "liveliness-subscriber")]
    fn peer_token(observer: &mut ApplicationLayerObserver, id: u64) {
        let body = crate::transport_profile::owned::DeclareOwnedVariant::CodecZenohDeclToken(
            wz_session_core_test_support::decl_token(id, 0, Some(&declared_key("token", id))),
        );
        observer
            .liveliness_subscribers
            .dispatch_declare(&body, &no_aliases());
    }

    #[cfg(feature = "liveliness-subscriber")]
    fn peer_token_withdrawn(observer: &mut ApplicationLayerObserver, id: u64) {
        let body = crate::transport_profile::owned::DeclareOwnedVariant::CodecZenohUndeclToken(
            wz_session_core_test_support::undecl_token(id),
        );
        observer
            .liveliness_subscribers
            .dispatch_declare(&body, &no_aliases());
    }

    #[cfg(feature = "liveliness-subscriber")]
    fn peer_token_tally(observer: &ApplicationLayerObserver) -> (usize, u32) {
        (
            observer.liveliness_subscribers.peer_token_count(),
            observer.liveliness_subscribers.peer_token_refusals(),
        )
    }

    /// `MAX_REMOTE_DECLS` with nothing stated, in each declaration table the build carries.
    #[cfg(any(
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "liveliness-subscriber"
    ))]
    #[test]
    fn max_remote_decls_with_nothing_stated_admits_what_the_build_admitted() {
        #[cfg(feature = "declare-subscriber")]
        declarations_admit_what_the_build_admitted(
            caps::MAX_REMOTE_DECLS,
            remote_subscriber,
            remote_subscriber_tally,
        );
        #[cfg(feature = "declare-queryable")]
        declarations_admit_what_the_build_admitted(
            caps::MAX_REMOTE_DECLS,
            remote_queryable,
            remote_queryable_tally,
        );
        #[cfg(feature = "liveliness-subscriber")]
        declarations_admit_what_the_build_admitted(
            caps::MAX_REMOTE_DECLS,
            peer_token,
            peer_token_tally,
        );
    }

    /// `MAX_REMOTE_DECLS` stated as two, in each declaration table the build carries: one
    /// quota per table, so a peer's two subscribers leave room for its two queryables.
    #[cfg(any(
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "liveliness-subscriber"
    ))]
    #[test]
    fn max_remote_decls_stated_refuses_the_next() {
        held_to_two(
            SessionLimits::select_max_remote_decls,
            MaxRemoteDecls::DOMAIN.is_singleton(),
            |limits| {
                #[cfg(feature = "declare-subscriber")]
                refuses_the_third_declaration(
                    limits,
                    remote_subscriber,
                    remote_subscriber_withdrawn,
                    remote_subscriber_tally,
                );
                #[cfg(feature = "declare-queryable")]
                refuses_the_third_declaration(
                    limits,
                    remote_queryable,
                    remote_queryable_withdrawn,
                    remote_queryable_tally,
                );
                #[cfg(feature = "liveliness-subscriber")]
                refuses_the_third_declaration(
                    limits,
                    peer_token,
                    peer_token_withdrawn,
                    peer_token_tally,
                );
                #[cfg(all(feature = "declare-subscriber", feature = "declare-queryable"))]
                {
                    let mut observer = ApplicationLayerObserver::with_limits(limits);
                    for id in 1..=2 {
                        remote_subscriber(&mut observer, id);
                        remote_queryable(&mut observer, id);
                    }
                    assert_eq!(remote_subscriber_tally(&observer), (2, 0));
                    assert_eq!(remote_queryable_tally(&observer), (2, 0));
                }
            },
        );
    }

    /// `MAX_PENDING_FINALS` with nothing stated: one query past the build's count in one frame
    /// owes every `Final` on the heap, as it did, while a fixed table holds its capacity and
    /// refuses the last request.
    #[cfg(feature = "query-queryable")]
    #[test]
    fn max_pending_finals_with_nothing_stated_admits_what_the_build_admitted() {
        let mut observer = ApplicationLayerObserver::with_limits(&SessionLimits::defaults());
        observer
            .queryables
            .register("bound/reply", |_, _| {})
            .expect("no quota is stated on the queryables");
        let past = u32::try_from(caps::MAX_PENDING_FINALS + 1).expect("a test count");
        observer.dispatch_event(crate::driver_loop::IterationEvent::Poll(&queries(0..past)));
        let refused = usize::from(crate::bounded::ENFORCES_CAPACITY);
        assert_eq!(
            observer.pending_final_count(),
            caps::MAX_PENDING_FINALS + 1 - refused
        );
        assert_eq!(
            observer.request_refusals(),
            u32::from(crate::bounded::ENFORCES_CAPACITY)
        );
    }

    /// `MAX_PENDING_FINALS` stated as two: the third request is refused before its queryable
    /// runs, so it stages no reply and owes no `Final`, and is counted; the table keeps its
    /// quota and its count when the owed `Final`s are taken to be sent. A peer's tables are
    /// held the same.
    #[cfg(feature = "query-queryable")]
    #[test]
    fn max_pending_finals_stated_refuses_the_next() {
        use crate::reply_stage::FinalStaging;
        use core::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        held_to_two(
            SessionLimits::select_max_pending_finals,
            MaxPendingFinals::DOMAIN.is_singleton(),
            |limits| {
                let mut observer = ApplicationLayerObserver::with_limits(limits);
                let ran = Arc::new(AtomicUsize::new(0));
                let runs = Arc::clone(&ran);
                observer
                    .queryables
                    .register("bound/reply", move |_, responder| {
                        runs.fetch_add(1, Ordering::Relaxed);
                        responder.reply(b"r");
                    })
                    .expect("no quota is stated on the queryables");
                observer.dispatch_event(crate::driver_loop::IterationEvent::Poll(&queries(0..3)));
                assert_eq!(
                    ran.load(Ordering::Relaxed),
                    2,
                    "the third request reached no queryable"
                );
                assert_eq!(observer.pending_reply_count(), 2);
                assert_eq!(observer.pending_final_count(), 2);
                assert_eq!(observer.request_refusals(), 1);

                assert_eq!(observer.take_pending_final_rids().len(), 2);
                assert_eq!(observer.pending_final_count(), 0);
                observer.dispatch_event(crate::driver_loop::IterationEvent::Poll(&queries(3..6)));
                assert_eq!(ran.load(Ordering::Relaxed), 4);
                assert_eq!(
                    observer.pending_final_count(),
                    2,
                    "the quota stayed with the table"
                );
                assert_eq!(observer.request_refusals(), 2, "and so did the count");

                let mut peers = crate::peer_tables::PeerTables::new();
                peers.limit_to(limits);
                peers.finals.owe(1, crate::sample::QosLevel::DEFAULT);
                peers.finals.owe(2, crate::sample::QosLevel::DEFAULT);
                assert!(!peers.finals.has_room());
                assert_eq!(peers.finals.take_owed().len(), 2);
                assert!(peers.finals.has_room(), "a place is free under the quota");
            },
        );
    }

    /// A reply on `bound/reply` whose payload and attachment are the ones given, as a queryable
    /// of a peer's session describes it.
    #[cfg(feature = "query-queryable")]
    fn reply_carrying<'a>(
        payload: &'a [u8],
        attachment: Option<&'a [u8]>,
    ) -> crate::reply_stage::ReplyParts<'a> {
        use crate::reply_stage::{PartsBody, PartsKind, ReplyParts};
        ReplyParts {
            rid: 0,
            keyexpr: "bound/reply",
            responder: None,
            qos: crate::sample::QosLevel::DEFAULT,
            #[cfg(feature = "pubsub-ts-stack")]
            ts_stack: None,
            kind: PartsKind::Reply {
                body: PartsBody::Put(payload),
                encoding: None,
                timestamp: None,
                attachment,
                source_info: None,
            },
        }
    }

    /// `MAX_REPLY_PAYLOAD_BYTES` with nothing stated: a reply one byte past the build's value is
    /// staged on the heap, which never bounded it, as it was, and refused as too large by a
    /// fixed stage, which holds the build's value.
    #[cfg(feature = "query-queryable")]
    #[test]
    fn max_reply_payload_bytes_with_nothing_stated_admits_what_the_build_admitted() {
        use crate::query_sink::ReplyError;
        use std::sync::{Arc, Mutex};
        let mut observer = ApplicationLayerObserver::with_limits(&SessionLimits::defaults());
        let answers = Arc::new(Mutex::new(std::vec::Vec::new()));
        let told = Arc::clone(&answers);
        observer
            .queryables
            .register("bound/reply", move |_, responder| {
                let past = std::vec![b'r'; caps::MAX_REPLY_PAYLOAD_BYTES + 1];
                let answer = responder.try_reply(&past[..]);
                told.lock().expect("not poisoned").push(answer);
            })
            .expect("no quota is stated on the queryables");
        observer.dispatch_event(crate::driver_loop::IterationEvent::Poll(&queries(0..1)));
        let fixed = crate::bounded::ENFORCES_CAPACITY;
        let answer = if fixed {
            Err(ReplyError::PayloadTooLarge)
        } else {
            Ok(())
        };
        assert_eq!(*answers.lock().expect("not poisoned"), [answer]);
        assert_eq!(observer.pending_reply_count(), usize::from(!fixed));
        assert_eq!(
            observer.reply_refusals().payload_too_large,
            u32::from(fixed)
        );
    }

    /// `MAX_REPLY_PAYLOAD_BYTES` stated as two: a reply of three bytes is refused to the handler
    /// as too large and counted, and stages nothing, while a reply of two is staged; an
    /// attachment of three is refused the same. The stage a runtime makes to answer one query
    /// apart from the observer, held to the observer's bounds, and a peer's tables are held the
    /// same.
    #[cfg(feature = "query-queryable")]
    #[test]
    fn max_reply_payload_bytes_stated_refuses_the_next() {
        use crate::query_sink::ReplyError;
        use crate::reply_stage::{ReplyBounds, ReplyStage, ReplyStaging};
        use std::sync::{Arc, Mutex};
        held_to_two(
            SessionLimits::select_max_reply_payload_bytes,
            MaxReplyPayloadBytes::DOMAIN.is_singleton(),
            |limits| {
                let mut observer = ApplicationLayerObserver::with_limits(limits);
                let answers = Arc::new(Mutex::new(std::vec::Vec::new()));
                let told = Arc::clone(&answers);
                observer
                    .queryables
                    .register("bound/reply", move |_, responder| {
                        let mut seen = told.lock().expect("not poisoned");
                        seen.push(responder.try_reply(b"abc"));
                        seen.push(responder.try_reply(b"ab"));
                    })
                    .expect("no quota is stated on the queryables");
                observer.dispatch_event(crate::driver_loop::IterationEvent::Poll(&queries(0..1)));
                assert_eq!(
                    *answers.lock().expect("not poisoned"),
                    [Err(ReplyError::PayloadTooLarge), Ok(())]
                );
                assert_eq!(
                    observer.pending_reply_count(),
                    1,
                    "the refusal staged nothing"
                );
                assert_eq!(observer.reply_refusals().payload_too_large, 1);
                assert_eq!(observer.reply_refusals().staging_full, 0);
                assert_eq!(observer.reply_bounds(), ReplyBounds::of(limits));

                let mut stage = ReplyStage::held_to(observer.reply_bounds());
                assert_eq!(
                    stage.stage_parts(reply_carrying(b"abc", None)),
                    Err(ReplyError::PayloadTooLarge)
                );
                assert_eq!(
                    stage.stage_parts(reply_carrying(b"a", Some(&b"abc"[..]))),
                    Err(ReplyError::PayloadTooLarge)
                );
                assert_eq!(
                    stage.stage_parts(reply_carrying(b"ab", Some(&b"ab"[..]))),
                    Ok(())
                );
                assert_eq!(stage.staged(), 1);
                assert_eq!(stage.refusals().payload_too_large, 2);

                let mut peers = crate::peer_tables::PeerTables::new();
                peers.limit_to(limits);
                assert_eq!(
                    peers.replies.stage_parts(reply_carrying(b"abc", None)),
                    Err(ReplyError::PayloadTooLarge)
                );
                assert_eq!(
                    peers.replies.stage_parts(reply_carrying(b"ab", None)),
                    Ok(())
                );
                assert_eq!(peers.replies.staged(), 1);
            },
        );
    }

    /// A query from a peer as [`sized_queries`] writes it: its request id, its selector parameters
    /// and its attachment, a field left out where it is `None`.
    #[cfg(all(
        feature = "query-queryable",
        any(feature = "query-selector-parameters", feature = "query-attachment")
    ))]
    type SizedQuery<'a> = (u32, Option<&'a [u8]>, Option<&'a [u8]>);

    /// One frame from a peer of one query on `bound/reply` for each `(rid, parameters,
    /// attachment)`, a field left out where it is `None`.
    #[cfg(all(
        feature = "query-queryable",
        any(feature = "query-selector-parameters", feature = "query-attachment")
    ))]
    fn sized_queries(asked: &[SizedQuery<'_>]) -> crate::driver_loop::DriverLoopOutcome {
        let messages = asked
            .iter()
            .map(|&(rid, parameters, attachment)| {
                let mut builder =
                    crate::request_build::RequestQueryBuilder::new(rid, 0, Some("bound/reply"));
                if let Some(parameters) = parameters {
                    builder = builder.parameters(parameters);
                }
                #[cfg(feature = "query-attachment")]
                if let Some(attachment) = attachment {
                    builder = builder.query_attachment(attachment);
                }
                #[cfg(not(feature = "query-attachment"))]
                let _ = attachment;
                let request = builder.build().expect("a literal key builds");
                crate::network_message::NetworkMessage::Request(std::boxed::Box::new(request))
            })
            .collect();
        crate::driver_loop::DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages,
            has_ext: false,
            extensions: std::vec::Vec::new(),
            priority: crate::qos::Priority::DEFAULT,
        }
    }

    /// An observer held to `limits` with one queryable on `bound/reply` that counts its runs.
    #[cfg(all(
        feature = "query-queryable",
        any(feature = "query-selector-parameters", feature = "query-attachment")
    ))]
    fn counting_queryable(
        limits: &SessionLimits,
    ) -> (
        ApplicationLayerObserver,
        std::sync::Arc<core::sync::atomic::AtomicUsize>,
    ) {
        use core::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let mut observer = ApplicationLayerObserver::with_limits(limits);
        let ran = Arc::new(AtomicUsize::new(0));
        let runs = Arc::clone(&ran);
        observer
            .queryables
            .register("bound/reply", move |_, _| {
                runs.fetch_add(1, Ordering::Relaxed);
            })
            .expect("no quota is stated on the queryables");
        (observer, ran)
    }

    /// The length one byte past a build's size bound of a query field, or the longest the
    /// request builder writes where that is shorter or the build states no bound (`0`), and
    /// whether a node of the build refuses it.
    #[cfg(all(
        feature = "query-queryable",
        any(feature = "query-selector-parameters", feature = "query-attachment")
    ))]
    fn past_the_build(bound: usize) -> (usize, bool) {
        let most = crate::request_build::REQUEST_QUERY_PARAMETERS_MAX_LEN;
        let length = if bound == 0 {
            most
        } else {
            (bound + 1).min(most)
        };
        (length, bound != 0 && length > bound)
    }

    /// `QUERY_PARAMETERS_MAX_BYTES` with nothing stated: a query from a peer whose parameters are
    /// past the build's value runs nowhere and is counted, and one where the build states no
    /// bound runs, as it did; its final is owed either way.
    #[cfg(all(feature = "query-queryable", feature = "query-selector-parameters"))]
    #[test]
    fn query_parameters_max_bytes_with_nothing_stated_admits_what_the_build_admitted() {
        use core::sync::atomic::Ordering;
        let (mut observer, ran) = counting_queryable(&SessionLimits::defaults());
        let (length, refused) = past_the_build(caps::QUERY_PARAMETERS_MAX_BYTES);
        let long = std::vec![b'x'; length];
        observer.dispatch_event(crate::driver_loop::IterationEvent::Poll(&sized_queries(&[
            (0, Some(&long[..]), None),
        ])));
        assert_eq!(ran.load(Ordering::Relaxed), usize::from(!refused));
        assert_eq!(observer.queryables.oversize_refusals(), u32::from(refused));
        assert_eq!(
            observer.pending_final_count(),
            1,
            "the query is owed its final"
        );
    }

    /// `QUERY_PARAMETERS_MAX_BYTES` stated as two: a query from a peer with three bytes of
    /// parameters reaches no queryable and is counted, one with two runs, and both are owed
    /// their final; a refusal stages no reply.
    #[cfg(all(feature = "query-queryable", feature = "query-selector-parameters"))]
    #[test]
    fn query_parameters_max_bytes_stated_refuses_the_next() {
        use core::sync::atomic::Ordering;
        held_to_two(
            SessionLimits::select_query_parameters_max_bytes,
            QueryParametersMaxBytes::DOMAIN.is_singleton(),
            |limits| {
                let (mut observer, ran) = counting_queryable(limits);
                observer.dispatch_event(crate::driver_loop::IterationEvent::Poll(&sized_queries(
                    &[(0, Some(&b"abc"[..]), None), (1, Some(&b"ab"[..]), None)],
                )));
                assert_eq!(
                    ran.load(Ordering::Relaxed),
                    1,
                    "the longer query ran nowhere"
                );
                assert_eq!(observer.queryables.oversize_refusals(), 1);
                assert_eq!(
                    observer.pending_final_count(),
                    2,
                    "both are owed their final"
                );
                assert_eq!(observer.pending_reply_count(), 0);
            },
        );
    }

    /// `QUERY_ATTACHMENT_MAX_BYTES` with nothing stated: a query from a peer whose attachment is
    /// past the build's value runs nowhere and is counted, and one where the build states no
    /// bound runs, as it did; its final is owed either way.
    #[cfg(all(feature = "query-queryable", feature = "query-attachment"))]
    #[test]
    fn query_attachment_max_bytes_with_nothing_stated_admits_what_the_build_admitted() {
        use core::sync::atomic::Ordering;
        let (mut observer, ran) = counting_queryable(&SessionLimits::defaults());
        let (length, refused) = past_the_build(caps::QUERY_ATTACHMENT_MAX_BYTES);
        let long = std::vec![b'x'; length];
        observer.dispatch_event(crate::driver_loop::IterationEvent::Poll(&sized_queries(&[
            (0, None, Some(&long[..])),
        ])));
        assert_eq!(ran.load(Ordering::Relaxed), usize::from(!refused));
        assert_eq!(observer.queryables.oversize_refusals(), u32::from(refused));
        assert_eq!(
            observer.pending_final_count(),
            1,
            "the query is owed its final"
        );
    }

    /// `QUERY_ATTACHMENT_MAX_BYTES` stated as two: a query from a peer with three bytes of
    /// attachment reaches no queryable and is counted, one with two runs, and both are owed their
    /// final; the parameters' bound, stated by nobody, refuses neither.
    #[cfg(all(feature = "query-queryable", feature = "query-attachment"))]
    #[test]
    fn query_attachment_max_bytes_stated_refuses_the_next() {
        use core::sync::atomic::Ordering;
        held_to_two(
            SessionLimits::select_query_attachment_max_bytes,
            QueryAttachmentMaxBytes::DOMAIN.is_singleton(),
            |limits| {
                let (mut observer, ran) = counting_queryable(limits);
                observer.dispatch_event(crate::driver_loop::IterationEvent::Poll(&sized_queries(
                    &[(0, None, Some(&b"abc"[..])), (1, None, Some(&b"ab"[..]))],
                )));
                assert_eq!(
                    ran.load(Ordering::Relaxed),
                    1,
                    "the longer query ran nowhere"
                );
                assert_eq!(observer.queryables.oversize_refusals(), 1);
                assert_eq!(
                    observer.pending_final_count(),
                    2,
                    "both are owed their final"
                );
            },
        );
    }

    /// `check` run on the pace a session's replay reads from a snapshot with
    /// `declaration-sync-pacing` on and `limits`, as every host of a paced replay makes it. A
    /// build that keeps the policy off refuses it, and is checked for what that means: no snapshot
    /// paces a replay.
    fn paced(limits: &SessionLimits, check: impl FnOnce(crate::replay_pacing::ReplayPacing)) {
        use crate::policy::{DeclarationSyncPacing, SessionPolicy};
        use crate::replay_pacing::ReplayPacing;
        let mut policy = SessionPolicy::defaults();
        if policy
            .select_declaration_sync_pacing(DeclarationSyncPacing::On)
            .is_err()
        {
            assert!(
                ReplayPacing::of_snapshot(&policy, limits).is_none(),
                "a build that keeps the policy off paces no replay"
            );
            return;
        }
        let pace = ReplayPacing::of_snapshot(&policy, limits)
            .expect("a snapshot's burst and interval make a pace");
        check(pace);
    }

    /// A parameter's statement in a snapshot.
    type SelectValue =
        fn(&mut SessionLimits, usize) -> Result<(), crate::limit_binding::OutsideLimitDomain>;

    /// `value`, as `select` states it, and `check` run on the snapshot that states it. A build
    /// that keeps the build's value alone (`singleton`) refuses the statement itself, and that
    /// refusal is what the build is checked for.
    fn stated_as(
        select: SelectValue,
        value: usize,
        singleton: bool,
        check: impl FnOnce(&SessionLimits),
    ) {
        let mut limits = SessionLimits::defaults();
        let stated = select(&mut limits, value);
        if singleton {
            assert!(stated.is_err(), "a build of one value refuses another");
        } else {
            stated.expect("the value is inside the domain");
            check(&limits);
        }
    }

    /// `DECLARATION_SYNC_BURST_MESSAGES` with nothing stated: a paced replay sends the build's
    /// burst a turn.
    #[test]
    fn declaration_sync_burst_messages_with_nothing_stated_is_the_builds_burst() {
        paced(&SessionLimits::defaults(), |pace| {
            assert_eq!(pace.burst(), caps::DECLARATION_SYNC_BURST_MESSAGES);
        });
    }

    /// `DECLARATION_SYNC_BURST_MESSAGES` stated as three: a paced replay sends three a turn.
    #[test]
    fn declaration_sync_burst_messages_stated_is_the_burst_a_replay_sends() {
        stated_as(
            SessionLimits::select_declaration_sync_burst_messages,
            3,
            DeclarationSyncBurstMessages::DOMAIN.is_singleton(),
            |limits| {
                paced(limits, |pace| {
                    assert_eq!(pace.burst(), 3);
                });
            },
        );
    }

    /// `DECLARATION_SYNC_INTERVAL_MS` with nothing stated: a paced replay waits the build's
    /// interval between turns.
    #[test]
    fn declaration_sync_interval_ms_with_nothing_stated_is_the_builds_interval() {
        paced(&SessionLimits::defaults(), |pace| {
            assert_eq!(
                pace.interval_ms(),
                caps::DECLARATION_SYNC_INTERVAL_MS as u64
            );
        });
    }

    /// `DECLARATION_SYNC_INTERVAL_MS` stated as 25: a paced replay waits 25 ms between turns.
    #[test]
    fn declaration_sync_interval_ms_stated_is_the_interval_a_replay_waits() {
        stated_as(
            SessionLimits::select_declaration_sync_interval_ms,
            25,
            DeclarationSyncIntervalMs::DOMAIN.is_singleton(),
            |limits| {
                paced(limits, |pace| {
                    assert_eq!(pace.interval_ms(), 25);
                });
            },
        );
    }

    /// `DECLARATION_SYNC_RETRY_INTERVAL_MS` with nothing stated: a refused turn is answered as
    /// the build's retry interval says.
    #[test]
    fn declaration_sync_retry_interval_ms_with_nothing_stated_is_the_builds_retry_interval() {
        paced(&SessionLimits::defaults(), |pace| {
            assert_eq!(
                pace.retry_interval_ms(),
                caps::DECLARATION_SYNC_RETRY_INTERVAL_MS as u64
            );
        });
    }

    /// `DECLARATION_SYNC_RETRY_INTERVAL_MS` stated as 7: a refused turn is tried again 7 ms on,
    /// and the turn interval is left as it was.
    #[test]
    fn declaration_sync_retry_interval_ms_stated_is_the_wait_before_a_retry() {
        stated_as(
            SessionLimits::select_declaration_sync_retry_interval_ms,
            7,
            DeclarationSyncRetryIntervalMs::DOMAIN.is_singleton(),
            |limits| {
                paced(limits, |pace| {
                    assert_eq!(pace.retry_interval_ms(), 7);
                    assert_eq!(
                        pace.interval_ms(),
                        caps::DECLARATION_SYNC_INTERVAL_MS as u64
                    );
                    assert_eq!(
                        pace.after_refusal(0, 0),
                        crate::replay_pacing::RefusalStep::RetryIn(7)
                    );
                });
            },
        );
    }

    /// `DECLARATION_SYNC_TX_NO_PROGRESS_MS` with nothing stated: a retrying replay gives up as
    /// the build's bound says.
    #[test]
    fn declaration_sync_tx_no_progress_ms_with_nothing_stated_is_the_builds_bound() {
        paced(&SessionLimits::defaults(), |pace| {
            assert_eq!(
                pace.no_progress_ms(),
                caps::DECLARATION_SYNC_TX_NO_PROGRESS_MS as u64
            );
        });
    }

    /// `DECLARATION_SYNC_TX_NO_PROGRESS_MS` stated as 40: a retrying replay gives up once 40 ms
    /// pass with no declaration sent.
    #[test]
    fn declaration_sync_tx_no_progress_ms_stated_is_the_bound_a_replay_gives_up_at() {
        stated_as(
            SessionLimits::select_declaration_sync_tx_no_progress_ms,
            40,
            DeclarationSyncTxNoProgressMs::DOMAIN.is_singleton(),
            |limits| {
                paced(limits, |pace| {
                    assert_eq!(pace.no_progress_ms(), 40);
                });
            },
        );
    }

    /// `check` run on a snapshot with `tx-no-progress-deadline` on. A build that keeps the policy
    /// off refuses it, and is checked for what that means: no queue its creator builds holds a
    /// window.
    #[cfg(feature = "storage-profile")]
    fn no_progress_deadline_on(check: impl FnOnce(crate::policy::SessionPolicy)) {
        use crate::policy::{SessionPolicy, TxNoProgressDeadline};
        use crate::session_init_params::TxQueueConf;
        let mut policy = SessionPolicy::defaults();
        if policy
            .select_tx_no_progress_deadline(TxNoProgressDeadline::On)
            .is_err()
        {
            assert_eq!(
                TxQueueConf::of_snapshot(&policy, &SessionLimits::defaults()).no_progress_us,
                None,
                "a build that keeps the policy off holds no window"
            );
            return;
        }
        check(policy);
    }

    /// `TX_NO_PROGRESS_WINDOW_US` with nothing stated: the queue a creator builds from the
    /// snapshots holds the build's window, and a blocking message asks for room no longer than it.
    #[cfg(feature = "storage-profile")]
    #[test]
    fn tx_no_progress_window_us_with_nothing_stated_is_the_builds_window() {
        use crate::link::RoomWait;
        use crate::session_init_params::TxQueueConf;
        use crate::tx_deadline::PushDeadline;
        no_progress_deadline_on(|on| {
            let queue = TxQueueConf::of_snapshot(&on, &SessionLimits::defaults());
            let window = caps::TX_NO_PROGRESS_WINDOW_US as u64;
            assert_eq!(queue.no_progress_us, Some(window));
            assert_eq!(
                PushDeadline::new(false, &queue).ask(),
                RoomWait::Block {
                    wait_us: window.min(queue.wait_before_close_us)
                }
            );
        });
    }

    /// `TX_NO_PROGRESS_WINDOW_US` stated as 250: the queue of either transmit model holds a
    /// window of 250 microseconds, and a blocking message asks for room no longer than that,
    /// while its total wait is left as it was.
    #[cfg(feature = "storage-profile")]
    #[test]
    fn tx_no_progress_window_us_stated_is_the_window_a_blocking_message_waits() {
        use crate::link::RoomWait;
        use crate::session_init_params::{TxQueueConf, WAIT_BEFORE_CLOSE_US};
        use crate::tx_deadline::PushDeadline;
        stated_as(
            SessionLimits::select_tx_no_progress_window_us,
            250,
            TxNoProgressWindowUs::DOMAIN.is_singleton(),
            |limits| {
                no_progress_deadline_on(|on| {
                    for queue in [
                        TxQueueConf::of_snapshot(&on, limits),
                        TxQueueConf::pico_of_snapshot(&on, limits),
                    ] {
                        assert_eq!(queue.no_progress_us, Some(250));
                        assert_eq!(queue.wait_before_close_us, WAIT_BEFORE_CLOSE_US);
                        assert_eq!(
                            PushDeadline::new(false, &queue).ask(),
                            RoomWait::Block { wait_us: 250 }
                        );
                    }
                });
            },
        );
    }

    /// The places of one querier, made as the runtime that declares the querier makes them: held
    /// to the bound the session's observer was handed.
    fn querier_places(limits: &SessionLimits) -> crate::quota::Quota {
        let observer = ApplicationLayerObserver::with_limits(limits);
        crate::quota::Quota::new(observer.querier_max_pending_queries())
    }

    /// `QUERIER_MAX_PENDING_QUERIES` with nothing stated: the build's value, whose `0` is no bound,
    /// so a querier takes every place it asks for, or the build's number of places and no more.
    #[test]
    fn querier_max_pending_queries_with_nothing_stated_admits_what_the_build_admitted() {
        let mut places = querier_places(&SessionLimits::defaults());
        assert_eq!(
            places.limit(),
            Quota::from_build(caps::QUERIER_MAX_PENDING_QUERIES, true)
        );
        match caps::QUERIER_MAX_PENDING_QUERIES {
            0 => {
                for _ in 0..1_000 {
                    places.try_acquire().expect("the build states no bound");
                }
                assert_eq!(places.live(), 1_000);
            }
            build => {
                for _ in 0..build {
                    places.try_acquire().expect("under the build's bound");
                }
                assert_eq!(
                    places.try_acquire(),
                    Err(crate::quota::QuotaExceeded { limit: build })
                );
                assert_eq!(places.live(), build);
            }
        }
    }

    /// `QUERIER_MAX_PENDING_QUERIES` stated as two: the third query is refused with the bound it
    /// reached and takes no place, and a place given back is taken again.
    #[test]
    fn querier_max_pending_queries_stated_refuses_the_next() {
        held_to_two(
            SessionLimits::select_querier_max_pending_queries,
            QuerierMaxPendingQueries::DOMAIN.is_singleton(),
            |limits| {
                let mut places = querier_places(limits);
                places.try_acquire().expect("under the quota");
                places.try_acquire().expect("under the quota");
                assert_eq!(
                    places.try_acquire(),
                    Err(crate::quota::QuotaExceeded { limit: 2 })
                );
                assert_eq!(places.live(), 2, "a refusal takes no place");
                places.release();
                places
                    .try_acquire()
                    .expect("a place is free under the quota");
                assert_eq!(places.live(), 2);
            },
        );
    }
    /// The lane of an entity on a session whose limits are `limits`, as the host builds it.
    type Lane = crate::delivery_lane::DeliveryLane<{ caps::DELIVERY_LANE_EVENTS }>;

    /// A lane of four slots, so a test of the bytes or the callbacks does not depend on the
    /// build's event count.
    type SmallLane = crate::delivery_lane::DeliveryLane<4>;

    /// `DELIVERY_LANE_EVENTS` with nothing stated: the lane admits a sample into each slot the
    /// build sized, and refuses the next as a full lane.
    #[test]
    fn delivery_lane_events_with_nothing_stated_admits_what_the_build_admitted() {
        let mut lane = Lane::with_limits(&SessionLimits::defaults());
        for _ in 0..caps::DELIVERY_LANE_EVENTS {
            assert!(lane.reserve(0).is_ok(), "no quota is stated");
        }
        assert_eq!(
            lane.reserve(0),
            Err(crate::delivery_lane::Refusal::EventsFull)
        );
        let stats = lane.stats();
        assert_eq!(stats.queued_events, caps::DELIVERY_LANE_EVENTS);
        assert_eq!(stats.event_capacity, caps::DELIVERY_LANE_EVENTS);
    }

    /// `DELIVERY_LANE_EVENTS` stated as two: the third sample is refused as a full lane and
    /// takes no slot, and a slot let go is taken again.
    #[test]
    fn delivery_lane_events_stated_as_two_refuses_the_next() {
        held_to_two(
            SessionLimits::select_delivery_lane_events,
            DeliveryLaneEvents::DOMAIN.is_singleton(),
            |limits| {
                let mut lane = Lane::with_limits(limits);
                assert_eq!(lane.stats().event_capacity, 2);
                let first = lane.reserve(0).expect("under the quota");
                let _second = lane.reserve(0).expect("under the quota");
                assert_eq!(
                    lane.reserve(0),
                    Err(crate::delivery_lane::Refusal::EventsFull)
                );
                let stats = lane.stats();
                assert_eq!(stats.queued_events, 2, "a refusal takes no slot");
                assert_eq!(stats.refused.events_full, 1);
                lane.cancel(first);
                assert_eq!(lane.front(), crate::delivery_lane::Next::Waiting);
                assert!(lane.reserve(0).is_ok(), "a slot is free under the quota");
                assert_eq!(lane.stats().queued_events, 2);
            },
        );
    }

    /// `DELIVERY_LANE_BYTES` with nothing stated: the lane's byte area is the build's size.
    #[test]
    fn delivery_lane_bytes_with_nothing_stated_holds_the_builds_value() {
        let lane = SmallLane::with_limits(&SessionLimits::defaults());
        assert_eq!(lane.stats().byte_capacity, caps::DELIVERY_LANE_BYTES);
        assert!(lane.can_ever_fit(caps::DELIVERY_LANE_BYTES));
        assert!(!lane.can_ever_fit(caps::DELIVERY_LANE_BYTES + 1));
    }

    /// `DELIVERY_LANE_BYTES` stated as sixteen: the lane's byte area is sixteen bytes, a sample
    /// of sixteen is admitted and one of seventeen is refused without taking a slot.
    #[test]
    fn delivery_lane_bytes_stated_is_the_value_the_lane_uses() {
        let mut limits = SessionLimits::defaults();
        let stated = limits.select_delivery_lane_bytes(16);
        if DeliveryLaneBytes::DOMAIN.is_singleton() {
            // A build that keeps the build's value alone refuses the statement itself.
            assert!(stated.is_err(), "a build of one value refuses sixteen");
            return;
        }
        stated.expect("sixteen is inside the domain");
        let mut lane = SmallLane::with_limits(&limits);
        assert_eq!(lane.stats().byte_capacity, 16);
        assert!(!lane.can_ever_fit(17));
        assert_eq!(
            lane.reserve(17),
            Err(crate::delivery_lane::Refusal::BytesFull)
        );
        assert_eq!(lane.stats().queued_events, 0, "a refusal takes no slot");
        assert!(lane.reserve(16).is_ok(), "the whole area is free");
        assert_eq!(lane.stats().pending_bytes, 16);
    }

    /// `DELIVERY_LANE_CALLBACKS` with nothing stated: two samples owe the build's budget between
    /// them, and a third that owes one more is refused.
    #[test]
    fn delivery_lane_callbacks_with_nothing_stated_admits_what_the_build_admitted() {
        let mut lane = SmallLane::with_limits(&SessionLimits::defaults());
        let budget = caps::DELIVERY_LANE_CALLBACKS;
        assert_eq!(lane.stats().callback_budget, budget);
        let first = lane.reserve(0).expect("a slot is free");
        lane.publish(first, budget - 1)
            .expect("under the build's budget");
        let second = lane.reserve(0).expect("a slot is free");
        lane.publish(second, 1).expect("at the build's budget");
        assert_eq!(lane.stats().pending_callbacks, budget);
        let third = lane.reserve(0).expect("a slot is free");
        assert_eq!(
            lane.publish(third, 1),
            Err(crate::delivery_lane::Refusal::CallbacksFull)
        );
    }

    /// `DELIVERY_LANE_CALLBACKS` stated as two: a third callback owed is refused and charges
    /// nothing, and a callback given back is taken again.
    #[test]
    fn delivery_lane_callbacks_stated_as_two_refuses_the_next() {
        held_to_two(
            SessionLimits::select_delivery_lane_callbacks,
            DeliveryLaneCallbacks::DOMAIN.is_singleton(),
            |limits| {
                let mut lane = SmallLane::with_limits(limits);
                assert_eq!(lane.stats().callback_budget, 2);
                for _ in 0..2 {
                    let reserved = lane.reserve(0).expect("a slot is free");
                    lane.publish(reserved, 1).expect("under the quota");
                }
                let third = lane.reserve(0).expect("a slot is free");
                assert_eq!(
                    lane.publish(third, 1),
                    Err(crate::delivery_lane::Refusal::CallbacksFull)
                );
                let stats = lane.stats();
                assert_eq!(stats.pending_callbacks, 2, "a refusal charges nothing");
                assert_eq!(stats.refused.callbacks_full, 1);
                assert!(matches!(lane.front(), crate::delivery_lane::Next::Ready(_)));
                assert!(lane.complete());
                let fourth = lane.reserve(0).expect("a slot is free");
                lane.publish(fourth, 1)
                    .expect("a callback is free under the quota");
                assert_eq!(lane.stats().pending_callbacks, 2);
            },
        );
    }

    /// `MAX_KEYEXPR_BYTES` with nothing stated: the build's bound is the rows' capacity on every
    /// profile, so a subscription takes a pattern of that length and refuses one byte more, and
    /// a retraction that names its key does the same beside the widest id.
    #[test]
    fn max_keyexpr_bytes_with_nothing_stated_admits_what_the_build_admitted() {
        let mut observer = ApplicationLayerObserver::with_limits(&SessionLimits::defaults());
        let at_build = "k".repeat(caps::MAX_KEYEXPR_BYTES);
        let past_build = "k".repeat(caps::MAX_KEYEXPR_BYTES + 1);
        assert_eq!(
            observer.subscribers.register(&past_build, |_| {}).err(),
            Some(RegisterError::KeyexprTooLong)
        );
        observer
            .subscribers
            .register(&at_build, |_| {})
            .expect("a pattern of the build's length");
        assert_eq!(observer.subscribers.len(), 1);
        #[cfg(all(feature = "storage-profile", feature = "codec-declare"))]
        {
            use crate::lent_control::NamedKeyexpr;
            let held = SessionLimits::defaults().max_keyexpr_bytes_held();
            let widest = crate::wire_id::ExprId::MAX;
            assert!(NamedKeyexpr::new(widest, &at_build, held).is_ok());
            assert!(NamedKeyexpr::new(widest, &past_build, held).is_err());
            assert!(NamedKeyexpr::literal(&past_build, held).is_err());
        }
    }

    /// `MAX_KEYEXPR_BYTES` stated as two: every table the session registers in refuses a key of
    /// three bytes as one its row cannot hold and keeps what it holds, and takes a key of two.
    #[test]
    fn max_keyexpr_bytes_stated_refuses_the_next() {
        held_to_two(
            SessionLimits::select_max_keyexpr_bytes,
            MaxKeyexprBytes::DOMAIN.is_singleton(),
            |limits| {
                let mut observer = ApplicationLayerObserver::with_limits(limits);
                let too_long = Some(RegisterError::KeyexprTooLong);
                observer
                    .subscribers
                    .register("ab", |_| {})
                    .expect("at the quota");
                assert_eq!(observer.subscribers.register("abc", |_| {}).err(), too_long);
                assert_eq!(
                    observer.subscribers.len(),
                    1,
                    "a refusal keeps what is held"
                );
                #[cfg(feature = "query-queryable")]
                {
                    assert_eq!(
                        observer.queryables.register("abc", |_, _| {}).err(),
                        too_long
                    );
                    assert!(observer.queryables.register("ab", |_, _| {}).is_ok());
                    assert_eq!(observer.queryables.len(), 1);
                }
                #[cfg(feature = "liveliness-token")]
                {
                    assert_eq!(
                        observer.local_tokens.register(1, "abc"),
                        Err(RegisterError::KeyexprTooLong)
                    );
                    assert_eq!(observer.local_tokens.register(2, "ab"), Ok(true));
                    assert_eq!(observer.local_tokens.len(), 1);
                }
                #[cfg(feature = "liveliness-subscriber")]
                {
                    let sink = || {
                        crate::declare::liveliness_sample::BoxedLivelinessSampleSink::new(|_| {})
                    };
                    assert_eq!(
                        observer
                            .liveliness_subscribers
                            .register(1, "abc", false, sink())
                            .err(),
                        too_long
                    );
                    assert_eq!(
                        observer
                            .liveliness_subscribers
                            .register(2, "ab", false, sink()),
                        Ok(true)
                    );
                    assert_eq!(observer.liveliness_subscribers.slot_count(), 1);
                }
                let asked = |observer: &mut ApplicationLayerObserver, rid: u32, keyexpr: &str| {
                    observer
                        .replies
                        .register(
                            rid,
                            1,
                            None,
                            crate::reply_acceptance::ReplyAcceptance::Matching(keyexpr),
                            |_| {},
                            |_| {},
                        )
                        .err()
                };
                assert_eq!(asked(&mut observer, 1, "abc"), too_long);
                assert_eq!(asked(&mut observer, 2, "ab"), None);
                assert_eq!(observer.replies.len(), 1);
                #[cfg(all(feature = "storage-profile", feature = "codec-declare"))]
                {
                    use crate::lent_control::NamedKeyexpr;
                    let held = limits.max_keyexpr_bytes_held();
                    assert!(NamedKeyexpr::literal("abc", held).is_err());
                    assert!(NamedKeyexpr::new(1, "abc", held).is_err());
                    assert!(NamedKeyexpr::literal("ab", held).is_ok());
                    assert!(NamedKeyexpr::new(crate::wire_id::ExprId::MAX, "ab", held).is_ok());
                }
            },
        );
    }

    /// The build's sampler under `limits`, with one snapshot taken at time 0, so the next is due
    /// a period on.
    fn sampled_at_zero(limits: &RuntimeLimits) -> crate::resource_snapshot::BuildSampler {
        use crate::resource_snapshot::{BuildSampler, MessageReading, ResourceReading};
        let mut sampler = BuildSampler::of_limits(limits, 0);
        sampler.take(0, ResourceReading::default(), MessageReading::default());
        sampler
    }

    /// `SNAPSHOT_PERIOD_MS` with nothing stated: the sampler holds the build's period, the next
    /// snapshot due that many milliseconds after the last and not a microsecond before.
    #[test]
    fn snapshot_period_ms_with_nothing_stated_holds_the_builds_period() {
        let sampler = sampled_at_zero(&RuntimeLimits::defaults());
        let period_us = caps::SNAPSHOT_PERIOD_MS as u32 * 1000;
        assert_eq!(sampler.until_due_us(0), period_us);
        assert!(!sampler.is_due(period_us - 1));
        assert!(sampler.is_due(period_us));
    }

    /// `SNAPSHOT_PERIOD_MS` stated: the sampler takes the stated period, not the build's. A build
    /// that keeps the build's value alone refuses the statement itself.
    #[test]
    fn snapshot_period_ms_stated_is_the_period_the_sampler_uses() {
        let value = if caps::SNAPSHOT_PERIOD_MS == 250 {
            125
        } else {
            250
        };
        let mut limits = RuntimeLimits::defaults();
        let stated = limits.select_snapshot_period_ms(value);
        if SnapshotPeriodMs::DOMAIN.is_singleton() {
            assert!(stated.is_err(), "a build of one value refuses another");
            return;
        }
        stated.expect("the period is inside the domain");
        let sampler = sampled_at_zero(&limits);
        let period_us = value as u32 * 1000;
        assert_eq!(sampler.until_due_us(0), period_us);
        assert!(!sampler.is_due(period_us - 1));
        assert!(sampler.is_due(period_us));
    }

    /// The shape of a replay cache of `depth` frames for one instance.
    #[cfg(feature = "replay-cache")]
    fn replay_shape(depth: usize) -> crate::replay_publisher::Shape {
        crate::replay_publisher::Shape {
            depth,
            instances: 1,
            frame_max: 4,
        }
    }

    /// The storage of a replay cache of `depth` frames for one instance, every byte `0xA5`.
    #[cfg(feature = "replay-cache")]
    fn replay_storage(depth: usize) -> std::vec::Vec<u8> {
        let bytes = replay_shape(depth).storage_bytes();
        std::vec![0xA5; bytes.expect("a small shape")]
    }

    /// A replay cache of `depth` frames for one instance over `storage`, made as the replay door
    /// makes it: held to the `REPLAY_DEPTH_MAX` of the session it is made on.
    #[cfg(feature = "replay-cache")]
    fn replay_cache(
        limits: &SessionLimits,
        depth: usize,
        storage: &mut [u8],
    ) -> Result<(), crate::replay_publisher::CreateRefused> {
        crate::replay_publisher::ReplayPublisher::new(
            storage,
            replay_shape(depth),
            limits.replay_depth_max(),
            false,
        )
        .map(|_| ())
    }

    /// `REPLAY_DEPTH_MAX` with nothing stated: a cache as deep as the build's value is made, and
    /// one frame deeper is refused, on every profile.
    #[cfg(feature = "replay-cache")]
    #[test]
    fn replay_depth_max_with_nothing_stated_admits_what_the_build_admitted() {
        let limits = SessionLimits::defaults();
        let mut storage = replay_storage(caps::REPLAY_DEPTH_MAX);
        replay_cache(&limits, caps::REPLAY_DEPTH_MAX, &mut storage).expect("no quota is stated");
        let mut storage = replay_storage(caps::REPLAY_DEPTH_MAX + 1);
        assert_eq!(
            replay_cache(&limits, caps::REPLAY_DEPTH_MAX + 1, &mut storage),
            Err(crate::replay_publisher::CreateRefused::DepthOutOfRange)
        );
    }

    /// `REPLAY_DEPTH_MAX` stated as two: a cache of three frames is refused as out of range and
    /// writes none of its storage, and a cache of two is made.
    #[cfg(feature = "replay-cache")]
    #[test]
    fn replay_depth_max_stated_as_two_refuses_a_deeper_cache() {
        held_to_two(
            SessionLimits::select_replay_depth_max,
            ReplayDepthMax::DOMAIN.is_singleton(),
            |limits| {
                let mut storage = replay_storage(3);
                assert_eq!(
                    replay_cache(limits, 3, &mut storage),
                    Err(crate::replay_publisher::CreateRefused::DepthOutOfRange)
                );
                assert!(
                    storage.iter().all(|&byte| byte == 0xA5),
                    "a refusal writes none of the storage"
                );
                let mut storage = replay_storage(2);
                replay_cache(limits, 2, &mut storage).expect("under the quota");
            },
        );
    }

    /// `MATCH_MEMO_SLOTS` with nothing stated: the receive match cache of the session's
    /// subscriptions holds the build's count of slots, `MATCH_MEMO_FIXED_SLOTS` on a table of
    /// fixed size.
    #[test]
    fn match_memo_slots_with_nothing_stated_holds_the_build_value() {
        let observer = ApplicationLayerObserver::with_limits(&SessionLimits::defaults());
        let build = if crate::bounded::ENFORCES_CAPACITY {
            caps::MATCH_MEMO_FIXED_SLOTS
        } else {
            caps::MATCH_MEMO_SLOTS
        };
        assert_eq!(observer.subscribers.memo_slot_count(), build);
    }

    /// `MATCH_MEMO_SLOTS` stated: the cache of a table that grows holds the stated count of
    /// slots, and a table of fixed size keeps the slots its build holds in RAM.
    #[test]
    fn match_memo_slots_stated_is_the_count_the_cache_holds() {
        let other = if caps::MATCH_MEMO_SLOTS == 3 { 2 } else { 3 };
        let mut limits = SessionLimits::defaults();
        let stated = limits.select_match_memo_slots(other);
        if MatchMemoSlots::DOMAIN.is_singleton() {
            assert!(stated.is_err(), "a build of one value refuses another");
        } else {
            stated.expect("inside the declared range");
            let observer = ApplicationLayerObserver::with_limits(&limits);
            let held = if crate::bounded::ENFORCES_CAPACITY {
                caps::MATCH_MEMO_FIXED_SLOTS
            } else {
                other
            };
            assert_eq!(observer.subscribers.memo_slot_count(), held);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps;
    use crate::limit_binding::{LimitEntry, LimitSpec, Outside, Quota};
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
            let refused = limits
                .select_max_keyexpr_bytes(Quota::UNBOUNDED)
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
