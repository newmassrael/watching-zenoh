// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The registry of a session whose tables take their memory at their first row
//! (`tables-on-use`): made by value at the open, each table counted from the limits the open
//! resolved and holding no row, every key counted against the session's key budget. Its table of
//! sets is counted to the sets the plan counts, one for each face the session may hold at once,
//! and takes the rows of all of them at its first push, the dial face's set (or, for a session
//! that dials nothing, a set of no rows for the dial face): the one memory the open takes for the
//! sets. A face that comes later builds its set in a row taken then, its tables counted as the
//! dial face's are (`adding::SpareSets`), so its attach takes nothing but its tables' first rows.
//! No frame holds a set as a value of its own.

use core::mem::ManuallyDrop;

use wz_session_core::bounded::BoundedVec;
use wz_session_core::limits::SessionLimits;
use wz_session_core::on_use::BudgetKeys;
use wz_session_core::peer_tables::PeerRows;
#[cfg(feature = "local-queryable")]
use wz_session_core::pending_get::DueRow;
use wz_session_core::session_tables::TableRows;
use wz_session_core::slot_observer::{ObserverRows, RequesterRows};

use super::held::Holders;
#[cfg(any(
    feature = "remote-declaration-watch",
    feature = "declarations-synced-event"
))]
use super::DeclWatches;
use super::{App, FaceTables, Gets, RegistryOf};
use crate::arena::{ArenaRefused, FacePeers, GetTables, MAX_FACE_SETS};
use crate::engine::RoundDelivery;
use crate::RowPolicy;

impl FaceTables {
    /// Count a set of no rows where it lies: its gets of `gets` rows and its peer's tables of
    /// `peer`, each taking its memory at its first row, every key counted against `keys`, the
    /// session's key budget, and held to `limits`.
    fn count_rows(
        &mut self,
        keys: BudgetKeys,
        gets: RequesterRows,
        peer: PeerRows,
        limits: &SessionLimits,
    ) {
        self.gets = Gets::counted(keys, gets, limits);
        self.peer.count_rows(keys, peer, limits);
    }
}

/// Write a set of no rows in the next row of `sets`, held to `limits`, and hand it back: the
/// dial face's of a session that dials nothing, which never has a peer and is counted no row, and
/// the first step of every other. `None` when `sets` holds every row it was counted, or when
/// the allocator refuses the rows of `sets`, which the first push takes.
fn push_rowless<'s>(
    sets: &'s mut BoundedVec<FaceTables, MAX_FACE_SETS, RowPolicy>,
    limits: &SessionLimits,
) -> Option<&'s mut FaceTables> {
    // SAFETY: `rowless_in` writes a whole set into the row it is handed and cannot unwind.
    unsafe {
        sets.push_in_place(|place| {
            FaceTables::rowless_in(place, limits);
        })
    }
}

/// Write a set at the end of `sets` and count its rows there: its gets of `gets` rows and its
/// peer's tables of `peer`, every key counted against `keys`, held to `limits`. `None`, as
/// [`push_rowless`] refuses.
///
/// Never inlined: the open calls it in a loop and a face that comes calls it again, and a loop
/// whose first turn the compiler peels would carry the set's writing and counting twice.
#[inline(never)]
pub(super) fn count_set(
    sets: &mut BoundedVec<FaceTables, MAX_FACE_SETS, RowPolicy>,
    keys: BudgetKeys,
    gets: RequesterRows,
    peer: PeerRows,
    limits: &SessionLimits,
) -> Option<()> {
    push_rowless(sets, limits)?.count_rows(keys, gets, peer, limits);
    Some(())
}

impl<H: Holders> RegistryOf<H> {
    /// A session that holds nothing and has been told nothing, with its dial face, made by value:
    /// the application's tables of the rows `tables` counts, a set for each face `peers` counts
    /// with `gets` rows of gets each and `peers`' rows of its peer's tables, and the session's own
    /// gets where it answers its own, every table holding no row until its first and held to
    /// `limits`, every key counted against `keys`, the session's key budget. The dial face's set
    /// is built now (one of no rows for a session that dials nothing, `FacePeers::dial`), and
    /// where faces are added beside the dial role's, the set of each other place when a face first
    /// takes it. What the application's subscribers match goes to `delivery`. Refused when
    /// `limits` admit more declaration watchers or watches than the build, or when the allocator
    /// has no room for the rows of the table of sets or of the index of held sets, which the open
    /// takes here.
    pub(in crate::engine) fn counted(
        limits: &SessionLimits,
        keys: BudgetKeys,
        tables: TableRows,
        gets: GetTables,
        peers: FacePeers,
        delivery: RoundDelivery,
    ) -> Result<Self, ArenaRefused> {
        // The session's tokens are rows of its one table set, which answers a peer's Interest too,
        // so the observer's own registry of them is counted none.
        let app = App::counted(
            keys,
            ObserverRows {
                tables,
                local_tokens: 0,
            },
            limits,
        )
        .map_err(ArenaRefused::Lend)?;
        let sets_refused = ArenaRefused::NoMemory {
            bytes: core::mem::size_of::<FaceTables>().saturating_mul(peers.sets()),
        };
        let mut sets = BoundedVec::<FaceTables, MAX_FACE_SETS, RowPolicy>::counted(peers.sets());
        let holders = H::counted(peers.sets())?;
        // A session that dials nothing holds a set of no rows for its dial face, first, and every
        // other set is for the faces to come; otherwise the first set is the dial face's.
        if !peers.dial {
            push_rowless(&mut sets, limits).ok_or(sets_refused)?;
        }
        // Where faces are added beside the dial role's, the dial face's set is built now and the
        // set of each other place when a face first takes it.
        #[cfg(any(feature = "listen", feature = "group"))]
        let built = usize::from(peers.dial).min(peers.tables);
        #[cfg(not(any(feature = "listen", feature = "group")))]
        let built = peers.tables;
        for _ in 0..built {
            count_set(&mut sets, keys, gets.rows, peers.rows, limits).ok_or(sets_refused)?;
        }
        #[cfg(any(feature = "listen", feature = "group"))]
        let spares = super::adding::SpareSets::counted(keys, gets.rows, peers.rows, *limits);
        #[cfg(feature = "local-queryable")]
        let local = Gets::counted(keys, gets.rows, limits);
        // The watches' events wait in the session's round where the build keeps one; a read that
        // hands each record out as it reads it hands them out itself.
        #[cfg(all(
            any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ),
            wz_round
        ))]
        let decl_watches =
            DeclWatches::under(limits, &delivery.round).map_err(ArenaRefused::Lend)?;
        #[cfg(all(
            any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ),
            not(wz_round)
        ))]
        let decl_watches = DeclWatches::under(limits).map_err(ArenaRefused::Lend)?;
        let mut registry = Self {
            app: ManuallyDrop::new(app),
            delivery,
            sets: ManuallyDrop::new(sets),
            holders,
            #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
            owed: super::owed::Owed::counted(&peers, limits),
            #[cfg(feature = "multicast-declarations")]
            peer_aliases: limits.max_peer_keyexpr_aliases_held(),
            #[cfg(any(feature = "listen", feature = "group"))]
            spares,
            #[cfg(feature = "local-queryable")]
            local,
            #[cfg(feature = "local-queryable")]
            local_due: DueRow::NEVER,
            #[cfg(any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ))]
            decl_watches,
            faces_written: 0,
            #[cfg(all(test, feature = "std"))]
            face_lookups: 0,
            #[cfg(test)]
            peer_looks: core::cell::Cell::new(0),
            #[cfg(test)]
            set_reads: core::cell::Cell::new(0),
            #[cfg(all(test, feature = "std"))]
            pushes: (0, 0, 0),
            #[cfg(all(test, feature = "std", feature = "query"))]
            replies_alone: 0,
            #[cfg(all(test, feature = "std", feature = "queryable"))]
            drains_within_frames: 0,
        };
        registry.index_dues();
        Ok(registry)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::arena::{ArenaPlan, PlanShape};
    use wz_session_core::on_use::KeyBudget;
    use wz_session_core::policy::SessionPolicy;
    use wz_session_core::reply_stage::FinalStaging;

    /// Where a registry no session holds hands what its tables match.
    fn delivery() -> RoundDelivery {
        RoundDelivery {
            #[cfg(wz_round)]
            round: crate::round::leaked(4),
            #[cfg(feature = "queryable")]
            plane: wz_session_core::placed::PlacedRef::of_static(alloc::boxed::Box::leak(
                crate::engine::query::leaked_plane(1),
            )),
        }
    }

    /// A registry of the on-use form, counted at the open, holds the application's tables at the
    /// rows the plan of the build's client counts and its dial face's one set, counted from the
    /// plan's rows of a face; no table of the application's has taken a row, and no key is counted
    /// against the budget.
    /// Turned red by an application's table made of the build's bound rather than counted
    /// (`SlotMap::new` in place of `SlotMap::counted`), by a table that takes its rows when it is
    /// made, by a registry with no set, or, in a build without `queryable`, by a set whose peer's
    /// tables are not counted (`count_rows` not called: its Finals keep the build's bound and have
    /// room).
    #[test]
    fn an_on_use_registry_holds_the_plans_rows_and_has_taken_none() {
        let limits = SessionLimits::BUILD;
        let shape = PlanShape::dial_only(0, 1024, &SessionPolicy::defaults());
        let plan = ArenaPlan::planned(shape, &limits).expect("the build's client");
        let budget = KeyBudget::new(limits.key_arena_bytes(), limits.max_keyexpr_bytes_held());
        // SAFETY: the budget outlives the registry, which is dropped first, and every key of it.
        let keys = unsafe { budget.keys() };
        let rows = plan.tables();
        let registry = super::super::Registry::counted(
            &limits,
            keys,
            rows,
            plan.gets(),
            plan.peers(),
            delivery(),
        )
        .expect("the build's limits admit the build's watches");
        let tables = &registry.app.tables;
        assert_eq!(tables.keyexprs().capacity(), rows.keyexprs);
        assert_eq!(tables.subscribers().capacity(), rows.subscribers);
        assert!(
            !tables.keyexprs().holds_rows() && !tables.subscribers().holds_rows(),
            "no table of the application's took a row"
        );
        assert_eq!(registry.sets.len(), 1, "the dial face's set");
        let set = registry.sets.first().expect("the dial face's set");
        assert_eq!(set.peer.finals.owed(), 0);
        assert_eq!(
            set.peer.finals.has_room(),
            cfg!(feature = "queryable"),
            "the Finals are counted rows only where the build answers queries"
        );
        assert_eq!(budget.counts().used, 0, "no key is counted yet");
        drop(registry);
    }

    /// A registry of a session that adds faces beside its dial role's, its faces' sets and its
    /// index of held sets counted for `faces` faces, the first the dial face's when `dial`, every
    /// table of one row, and a row for a liveliness subscriber, which the tests of retractions
    /// declare.
    #[cfg(any(feature = "listen", feature = "group"))]
    fn many(
        limits: &SessionLimits,
        keys: BudgetKeys,
        faces: usize,
        dial: bool,
    ) -> RegistryOf<super::super::held::ManyHolders> {
        let gets = GetTables {
            rows: RequesterRows {
                queries: 1,
                liveliness_gets: 0,
            },
            tables: faces + usize::from(cfg!(feature = "local-queryable")),
        };
        let peers = FacePeers {
            rows: PeerRows {
                pending_declares: 1,
                replies: 1,
                reply_bytes: 64,
                finals: 1,
            },
            tables: faces,
            pools: wz_session_core::peer_tables::PeerPoolRows::default(),
            dial,
        };
        RegistryOf::counted(
            limits,
            keys,
            TableRows {
                liveliness_subscribers: 1,
                ..Default::default()
            },
            gets,
            peers,
            delivery(),
        )
        .expect("the limits admit the build's watches")
    }

    /// Whether a subscriber the peer of face `id` declares on `key` is held in the face's set.
    #[cfg(any(feature = "listen", feature = "group"))]
    fn declares_on(
        registry: &mut RegistryOf<super::super::held::ManyHolders>,
        id: super::super::FaceId,
        key: &str,
    ) -> bool {
        use wz_session_core::declare_build::build_declare_subscriber;
        let at = registry.held_at(id).expect("the registry holds the face");
        let RegistryOf { app, sets, .. } = registry;
        let peer = &mut sets[at].peer;
        let declare = build_declare_subscriber(1, 0, Some(key)).expect("a declaration");
        app.remote_subscribers.dispatch_declare(
            &mut peer.remote_subscribers,
            &declare.body,
            peer.subscribers.mapping_spaces(),
        );
        peer.remote_subscribers.has_matching(key)
    }

    /// A face added to an on-use registry takes the first free place, its set built there as the
    /// place's first face comes and counted as the dial face's is, its peer's keys counted against
    /// the session's budget; a face that goes leaves the set where it lies for the next face, and a
    /// face past every place is refused. Only the dial face's set is built at the open (the
    /// CONTROL). Turned red by a spare set built of rows that are not counted
    /// (`SpareSets::build` with no `count_rows`, whose peer then holds no key), by sets built for
    /// every place at the open, or by a set given back that is built again elsewhere.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[test]
    fn an_on_use_face_builds_its_set_at_its_places_first_face_and_gives_it_back() {
        use super::super::adding::FacesFull;
        use super::super::{DIAL_FACE, NO_FACE};
        use wz_session_core::key_arena::block_bytes;

        let limits = SessionLimits::defaults();
        let budget = KeyBudget::new(4096, limits.max_keyexpr_bytes_held());
        // SAFETY: the budget outlives the registry, which is dropped first, and every key of it.
        let keys = unsafe { budget.keys() };
        let mut registry = many(&limits, keys, 3, true);
        assert_eq!(registry.places(), 3);
        assert_eq!(
            registry.sets.len(),
            1,
            "CONTROL: the dial face's set alone is built at the open"
        );
        assert_eq!(registry.holders.rows(), &[DIAL_FACE, NO_FACE, NO_FACE]);
        let face = registry.add_face(5).expect("a place is free");
        assert_eq!(face.at(), 1);
        assert_eq!(
            registry.sets.len(),
            2,
            "its set built at its place's first face"
        );
        let key = "demo/declared/k";
        assert!(
            declares_on(&mut registry, 5, key),
            "the set built for it holds what its peer declares"
        );
        assert_eq!(
            budget.counts().used,
            block_bytes(key.len()).expect("a short key"),
            "its peer's key counted against the session's budget"
        );
        let lies_at: *const FaceTables = &registry.sets[1];
        registry.remove_face(face);
        assert_eq!(registry.holders.rows(), &[DIAL_FACE, NO_FACE, NO_FACE]);
        assert_eq!(registry.sets.len(), 2, "the set stays where it lies");
        let next = registry.add_face(6).expect("the place is free again");
        assert_eq!(next.at(), 1);
        assert!(
            core::ptr::eq(&registry.sets[1], lies_at),
            "the next face takes the same set"
        );
        registry.add_face(7).expect("the last place");
        assert_eq!(registry.sets.len(), 3);
        assert_eq!(registry.add_face(8), Err(FacesFull), "past every place");
        assert_eq!(registry.faces().count(), 3, "the dial face and two others");
        drop(registry);
    }

    /// An on-use session that dials nothing holds a set of no rows for its dial face, first, and
    /// builds the first face that comes its set in the next place, counted. Turned red by a dial
    /// face's set counted rows in a session that dials nothing, or by a registry that builds that
    /// face no set at all, which leaves the first face that comes at the first place.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[test]
    fn an_on_use_session_that_dials_nothing_keeps_a_rowless_set_for_its_dial_face() {
        use super::super::{DIAL_FACE, NO_FACE};

        let limits = SessionLimits::defaults();
        let budget = KeyBudget::new(4096, limits.max_keyexpr_bytes_held());
        // SAFETY: the budget outlives the registry, which is dropped first, and every key of it.
        let keys = unsafe { budget.keys() };
        let mut registry = many(&limits, keys, 1, false);
        assert_eq!(
            registry.places(),
            2,
            "the dial face's place and the face to come"
        );
        assert_eq!(registry.sets.len(), 1);
        assert_eq!(registry.holders.rows(), &[DIAL_FACE, NO_FACE]);
        assert!(
            !registry.sets[0].peer.finals.has_room(),
            "the dial face's set has no rows"
        );
        let face = registry
            .add_face(5)
            .expect("the place kept for the face that comes");
        assert_eq!(face.at(), 1);
        assert!(
            declares_on(&mut registry, 5, "demo/declared/one"),
            "the face that comes takes a counted set"
        );
        let dial = registry.held(DIAL_FACE);
        registry.remove_face(dial);
        assert_eq!(registry.faces().count(), 2, "the dial face stays");
        drop(registry);
    }

    /// The tokens of the faces that went are owed as rows of one relation, their keys still
    /// counted, and retracted in the order the faces went, each face's in ascending id; while they
    /// hold the rows a new face would need, the face is refused as one past the session's faces is,
    /// and admitted again once they are retracted. With nothing owed two faces are admitted (the
    /// CONTROL). Turned red by an admission that `add_face` does not ask (`Owed::admits_face`), by
    /// tokens dropped as their face goes rather than owed, or by a retraction in another order.
    #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
    #[test]
    fn an_on_use_registry_owes_the_tokens_of_faces_that_went_and_admits_faces_while_they_fit() {
        use super::super::adding::FacesFull;
        use super::super::{DIAL_FACE, NO_FACE};
        use std::sync::{Arc, Mutex};
        use wz_capi_port::{LivelinessSink, WireKey};
        use wz_session_core::declare::liveliness_sample::{LivelinessSample, LivelinessSampleKind};
        use wz_session_core::declare_build::build_declare_token;
        use wz_session_core::limit_binding::Quota;
        use wz_session_core::session_tables::KeyForm;

        let mut limits = SessionLimits::defaults();
        if limits.select_max_remote_decls(Quota::at_most(2)).is_err() {
            // A build whose limits keep the build's value alone states no quota of a face.
            return;
        }
        let budget = KeyBudget::new(4096, limits.max_keyexpr_bytes_held());
        // SAFETY: the budget outlives the registry, which is dropped first, and every key of it.
        let keys = unsafe { budget.keys() };
        let mut registry = many(&limits, keys, 3, true);
        let heard: Arc<Mutex<Vec<(String, u64)>>> = Arc::default();
        let into = Arc::clone(&heard);
        registry
            .app
            .tables
            .declare_liveliness_subscriber(
                "demo/**",
                false,
                KeyForm::default(),
                crate::engine::LivelinessRow::new(
                    WireKey::literal().into_anchor(),
                    LivelinessSink::shared(move |sample: LivelinessSample<'_>| {
                        if sample.kind == LivelinessSampleKind::Delete {
                            into.lock()
                                .unwrap()
                                .push((sample.keyexpr.to_owned(), sample.token_id));
                        }
                    }),
                ),
            )
            .map_err(|refused| refused.why)
            .expect("the subscriber is declared");
        let subscribed = budget.counts().used;
        registry
            .add_face(5)
            .expect("CONTROL: nothing is owed, so the face is admitted");
        registry
            .add_face(6)
            .expect("CONTROL: nothing is owed, so the face is admitted");
        for (id, tokens) in [(5, [3_u64, 1]), (6, [4, 2])] {
            let at = registry.held_at(id).expect("the registry holds the face");
            let RegistryOf {
                app,
                delivery,
                sets,
                ..
            } = &mut registry;
            let peer = &mut sets[at].peer;
            for token in tokens {
                let key = std::format!("demo/{id}/{token}");
                let declare = build_declare_token(token, 0, Some(&key)).expect("a declaration");
                let (_, subscribers) = app.tables.liveliness_mut();
                peer.tokens.dispatch_declare_historical(
                    subscribers,
                    delivery,
                    &declare.body,
                    peer.subscribers.mapping_spaces(),
                    false,
                );
            }
            assert_eq!(peer.tokens.count(), 2, "face {id} holds its peer's tokens");
        }
        // The appearances are handed out, so the round has room for the retractions.
        #[cfg(wz_round)]
        {
            // SAFETY: this thread is the round's one writer.
            unsafe { registry.delivery.round.seal() };
            assert!(registry.delivery.round.deliver(), "the appearances");
        }
        let held_keys = budget.counts().used;
        for id in [5, 6] {
            registry.lose_tokens(id);
            let face = registry.held(id);
            registry.remove_face(face);
        }
        assert_eq!(
            registry.owed.len(),
            4,
            "each token owed as a row of its own"
        );
        assert_eq!(
            budget.counts().used,
            held_keys,
            "the keys of the tokens owed stay counted"
        );
        assert_eq!(
            registry.add_face(7),
            Err(FacesFull),
            "the tokens owed hold the rows a new face would need"
        );
        assert_eq!(registry.holders.rows(), &[DIAL_FACE, NO_FACE, NO_FACE]);
        #[cfg(wz_round)]
        {
            assert!(registry.retract_owed(&mut || true), "every token retracted");
            // SAFETY: this thread is the round's one writer.
            unsafe { registry.delivery.round.seal() };
            assert!(registry.delivery.round.deliver(), "the retractions");
        }
        // The read hands each token it takes to the subscribers itself; here the test is that
        // read, and the subscriber's sink is told nothing.
        #[cfg(not(wz_round))]
        {
            let mut news = wz_session_core::declare::liveliness_subscriber::TokenNews::default();
            while registry.take_lost_token(&mut news) {
                let sample = news.sample();
                assert!(
                    sample.kind == LivelinessSampleKind::Delete,
                    "a lost token is retracted"
                );
                heard
                    .lock()
                    .unwrap()
                    .push((sample.keyexpr.to_owned(), sample.token_id));
            }
            assert!(!registry.retracting(), "every token retracted");
        }
        assert_eq!(
            *heard.lock().unwrap(),
            [
                ("demo/5/1".to_owned(), 1),
                ("demo/5/3".to_owned(), 3),
                ("demo/6/2".to_owned(), 2),
                ("demo/6/4".to_owned(), 4),
            ],
            "in the order the faces went, each face's in ascending id"
        );
        assert!(registry.owed.is_empty(), "nothing is owed any more");
        assert_eq!(
            budget.counts().used,
            subscribed,
            "every owed key's bytes back with its row"
        );
        registry
            .add_face(7)
            .expect("with nothing owed, a face is admitted again");
        drop(registry);
    }
}
