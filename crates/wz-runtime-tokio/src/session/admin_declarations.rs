// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2690 (§5.23 `adminspace-introspection-handlers`) — the pure-Session admin
//! host's per-entity declaration materialization.
//!
//! ## Which upstream shape this is
//!
//! A [`Session`](crate::session::Session) is upstream's CLIENT HAT: the one hat
//! whose entire routing state is a face's `remote_subs` / `remote_qabls` rather
//! than a link-state graph. Upstream's loop is
//! `zenoh/src/net/routing/hat/client/pubsub.rs` @ `fn sourced_subscribers` — over
//! `owned_faces`, over that face's `remote_subs`, bucketing by `face.whatami` —
//! and its queryable twin in the sibling `queries.rs`. A Session owns exactly ONE
//! face, so the outer loop has exactly one iteration here; nothing else about the
//! shape changes.
//!
//! ⚠ The bucketing rule is the CLIENT hat's three-way `match face.whatami`, NOT
//! the peer hat's unconditional `srcs.peers.push` (`hat/peer/pubsub.rs`). Both
//! were read at the pin before choosing. The peer hat can push unconditionally
//! because the faces its region owns are peers by construction; a Session's one
//! face is whatever connected to it, so collapsing the three buckets here would
//! mis-file a client's declaration exactly as the degenerate `peers`-only body
//! R2687 replaced used to. The wz peer host reached the same rule from its own
//! tables in R2689, and two hosts of one node must not disagree about one fact.
//!
//! ## Why a rebuilt cache rather than a live view
//!
//! The admin GET handler is STORED INSIDE the observer's queryable registry and
//! is dispatched with `&mut ApplicationLayerObserver` held
//! (`observer.rs` @ `self.queryables.dispatch_iteration_event`), so it can
//! neither borrow the observer back nor re-lock it. The router host solves the
//! same problem with a live handle
//! ([`RouterDeclarationsView`](crate::router_forward::RouterDeclarationsView))
//! because ITS tables are already `Rc<RefCell<..>>`; the observer's registries
//! own their tables outright, and giving them a shared cell would put a
//! synchronization primitive into `no_std` `wz-session-core`, which the MCU
//! profile has no answer for.
//!
//! So the Session's answer is a CACHE — and a cache is only honest while it
//! cannot drift. [`materialize`] therefore rebuilds WHOLESALE from the live
//! tables every time it is called and never patches an existing vector; the
//! refresh is driven from the sites that MUTATE those tables, so the cached value
//! is always a whole state the tables actually held. An incremental side-table
//! fed by declaration sinks would be the other thing — a second source of truth
//! that can disagree with the first — which is the shape `run_peer` also refused.

use wz_codecs::whatami::WhatAmI;
use wz_session_core::adminspace::{AdminDeclaration, AdminEntityKind, AdminSources};
use wz_session_core::observer::ApplicationLayerObserver;

/// The identity of the ONE face a Session holds, as the admin plane needs it:
/// the zid that lands IN a bucket and the role that CHOOSES the bucket.
///
/// Both are `Option` because both are populated by the INIT exchange and a
/// Session can be dispatched before it. They are kept as separate options rather
/// than one because they go missing independently: a face can be identified with
/// its role still unreported, and that case has a defined answer (below) where
/// "no face at all" does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdminFace<'a> {
    /// The face's zid in zenoh's admin hex rendering.
    pub zid_hex: &'a str,
    /// The face's role as the INIT wire form reported it, or `None` when the
    /// exchange has not populated the slot.
    pub whatami: Option<WhatAmI>,
}

/// File one source zid into the bucket its role names.
///
/// A face whose role the INIT exchange never reported is recorded as a PEER —
/// the same default the routing boundary applies to the same missing slot
/// (`linkstate_forward` @ `fn peer_whatami_routing`), so the two places that must
/// name a role for an unroled face name the same one.
fn file_source(sources: &mut AdminSources, face: AdminFace<'_>) {
    match face.whatami {
        Some(WhatAmI::Router) => sources.routers.push(face.zid_hex.to_string()),
        Some(WhatAmI::Client) => sources.clients.push(face.zid_hex.to_string()),
        Some(WhatAmI::Peer) | None => sources.peers.push(face.zid_hex.to_string()),
    }
}

/// Fold one registry's `(id, keyexpr)` declarations into per-keyexpr entries.
///
/// Grouping is BY KEYEXPR because that is what the reply key is: two peer
/// declarations of `home/temp` under different declaration ids are ONE admin
/// entity, not two. Upstream groups the same way — its
/// `subs.entry(sub.clone()).or_insert_with(Sources::empty)` is keyed by the
/// resource, not by the declaration.
///
/// ⚠ Grouping the ENTITY is not deduplicating the SOURCE, and upstream settles
/// those separately: its push runs once per entry of `remote_subs`, which is
/// keyed by declaration id, so a face holding two subscribers on one keyexpr is
/// named twice in that bucket. This fold reproduces that rather than tidying it —
/// see the unit test that pins it, which was written asserting the opposite until
/// the pin said otherwise.
fn fold_declarations<'a>(
    kind: AdminEntityKind,
    declared: impl Iterator<Item = &'a str>,
    face: Option<AdminFace<'_>>,
    out: &mut alloc_map::Map,
) {
    for keyexpr in declared {
        let sources = out.entry(kind, keyexpr);
        // A face whose zid the handshake has not produced yet leaves the entity
        // LISTED with no source rather than unlisted: the declaration is a fact
        // this node holds, and dropping it would under-report the table to hide
        // an attribution it cannot make. Upstream never reaches this state (a
        // face exists before it can declare), so there is no shape to copy.
        if let Some(face) = face {
            file_source(sources, face);
        }
    }
}

/// A deterministically-ordered `(kind, keyexpr) -> AdminSources` accumulator.
///
/// `BTreeMap` rather than `HashMap` — where upstream uses a `HashMap` and leaves
/// reply order unspecified — because the admin reply is an ANSWER a consumer
/// diffs across scrapes, and an order that changes between two identical states
/// reads as a change that did not happen.
mod alloc_map {
    use super::{AdminEntityKind, AdminSources};
    use std::collections::BTreeMap;

    /// Ordered by kind then keyexpr; the key is owned because the accumulator
    /// outlives the registry borrows the keyexprs come from.
    pub(super) struct Map(BTreeMap<(u8, String), AdminSources>);

    impl Map {
        pub(super) fn new() -> Self {
            Self(BTreeMap::new())
        }

        /// The entry for one admin entity, created empty on first sight.
        pub(super) fn entry(&mut self, kind: AdminEntityKind, keyexpr: &str) -> &mut AdminSources {
            self.0
                .entry((kind_ord(kind), keyexpr.to_string()))
                .or_default()
        }

        /// Drain into the answerer's slice form, ordering preserved.
        pub(super) fn into_declarations(self) -> Vec<super::AdminDeclaration> {
            self.0
                .into_iter()
                .map(|((ord, keyexpr), sources)| super::AdminDeclaration {
                    kind: kind_of(ord),
                    keyexpr,
                    sources,
                })
                .collect()
        }
    }

    /// `AdminEntityKind` is not `Ord`, and making it so would widen a
    /// `wz-session-core` public type for one consumer's map key. The ordinal is
    /// local, total, and round-trips through [`kind_of`].
    fn kind_ord(kind: AdminEntityKind) -> u8 {
        match kind {
            AdminEntityKind::Subscriber => 0,
            AdminEntityKind::Queryable => 1,
        }
    }

    fn kind_of(ord: u8) -> AdminEntityKind {
        match ord {
            0 => AdminEntityKind::Subscriber,
            _ => AdminEntityKind::Queryable,
        }
    }
}

/// Rebuild the pure-Session admin host's declaration answer WHOLESALE from the
/// observer's live tables.
///
/// Returns every entity the node's one face has declared to it, each with the
/// sources bucket its face's role names. Never patches and never reads its own
/// previous result: the returned vector is a whole state the tables actually
/// held, which is the property that lets a cache of it stay honest.
pub(crate) fn materialize(
    observer: &ApplicationLayerObserver,
    face: Option<AdminFace<'_>>,
) -> Vec<AdminDeclaration> {
    let mut map = alloc_map::Map::new();
    #[cfg(feature = "declare-subscriber")]
    fold_declarations(
        AdminEntityKind::Subscriber,
        observer
            .remote_subscribers
            .iter_declared()
            .map(|(_, ke)| ke),
        face,
        &mut map,
    );
    #[cfg(feature = "declare-queryable")]
    fold_declarations(
        AdminEntityKind::Queryable,
        observer.remote_queryables.iter_declared().map(|(_, ke)| ke),
        face,
        &mut map,
    );
    // A build with neither declaration plane has no table to read, so the answer
    // is empty — which is the honest one, not a stub. The discard is spelled with
    // the same `#[cfg]` the readers carry, so it says WHICH build leaves these
    // untouched instead of silencing the compiler on every build.
    #[cfg(not(any(feature = "declare-subscriber", feature = "declare-queryable")))]
    let _ = (observer, face);
    map.into_declarations()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FACE: AdminFace<'static> = AdminFace {
        zid_hex: "3007370",
        whatami: Some(WhatAmI::Client),
    };

    /// The bucket is chosen by the face's ROLE, across every role a face can
    /// report plus the unreported case — the whole `match` upstream's client hat
    /// writes, arm for arm.
    ///
    /// Written as a table over ALL FOUR inputs rather than one call per test:
    /// the defect this guards against is a MIS-FILING, and a mis-filing is only
    /// visible when the arm that should be empty is asserted empty too.
    #[test]
    fn a_faces_role_chooses_its_bucket_and_leaves_the_other_two_empty() {
        let cases = [
            (
                Some(WhatAmI::Router),
                ["z"].as_slice(),
                [].as_slice(),
                [].as_slice(),
            ),
            (
                Some(WhatAmI::Peer),
                [].as_slice(),
                ["z"].as_slice(),
                [].as_slice(),
            ),
            (
                Some(WhatAmI::Client),
                [].as_slice(),
                [].as_slice(),
                ["z"].as_slice(),
            ),
            // Role unreported — the routing boundary's own default for the same
            // missing slot.
            (None, [].as_slice(), ["z"].as_slice(), [].as_slice()),
        ];
        for (whatami, routers, peers, clients) in cases {
            let mut sources = AdminSources::default();
            file_source(
                &mut sources,
                AdminFace {
                    zid_hex: "z",
                    whatami,
                },
            );
            assert_eq!(sources.routers, routers, "routers for {whatami:?}");
            assert_eq!(sources.peers, peers, "peers for {whatami:?}");
            assert_eq!(sources.clients, clients, "clients for {whatami:?}");
        }
    }

    /// Two declarations of ONE keyexpr are ONE admin entity whose source is named
    /// ONCE PER DECLARATION.
    ///
    /// ⚠ THE SECOND HALF OF THAT SENTENCE WAS WRITTEN THE OTHER WAY FIRST, and
    /// the pin refuted it. The grouping and the counting are separate facts and
    /// upstream settles them separately: its accumulator is keyed by the RESOURCE
    /// (`subs.entry(sub.clone()).or_insert_with(Sources::empty)`, so two declares
    /// of one keyexpr are one entry) while its push runs once per ENTRY of
    /// `remote_subs`, which is `HashMap<SubscriberId, Arc<Resource>>` — keyed by
    /// the declaration id, so a face holding two subscribers on one keyexpr lands
    /// in that bucket twice
    /// (`zenoh/src/net/routing/hat/client/pubsub.rs` @ `fn sourced_subscribers`).
    /// It is reachable rather than theoretical: each `Subscriber` upstream hands
    /// out carries its own id and sends its own declare, so an application with
    /// two subscribers on one keyexpr produces exactly this.
    ///
    /// wz's `declared` is the same `id -> keyexpr` map, so the repeat is not a
    /// wart being copied — it is the same fact reported the same way, which is
    /// what "replaces zenoh" has to mean at an answer a consumer diffs.
    #[test]
    fn two_declarations_of_one_keyexpr_are_one_entity_sourced_once_each() {
        let mut map = alloc_map::Map::new();
        fold_declarations(
            AdminEntityKind::Subscriber,
            ["home/temp", "home/temp"].into_iter(),
            Some(FACE),
            &mut map,
        );
        let got = map.into_declarations();
        assert_eq!(got.len(), 1, "one keyexpr is one entity: {got:?}");
        assert_eq!(got[0].keyexpr, "home/temp");
        assert_eq!(
            got[0].sources.clients,
            ["3007370", "3007370"],
            "one push per declaration, as upstream's `.values()` loop gives"
        );
    }

    /// An entity whose face has no zid yet is LISTED with no source. The
    /// anti-vacuity arm of the clause above it: without this the "empty sources"
    /// branch would be reachable only through a state no test builds.
    #[test]
    fn a_declaration_with_no_identified_face_is_listed_unattributed() {
        let mut map = alloc_map::Map::new();
        fold_declarations(
            AdminEntityKind::Subscriber,
            ["home/temp"].into_iter(),
            None,
            &mut map,
        );
        let got = map.into_declarations();
        assert_eq!(got.len(), 1, "the declaration is a fact the node holds");
        assert_eq!(
            got[0].sources,
            AdminSources::default(),
            "and is unattributed"
        );
    }

    /// Subscribers sort before queryables and keyexprs sort within a kind, so two
    /// scrapes of one unchanged state answer in one order.
    #[test]
    fn the_answer_is_ordered_by_kind_then_keyexpr() {
        let mut map = alloc_map::Map::new();
        fold_declarations(
            AdminEntityKind::Queryable,
            ["b/q", "a/q"].into_iter(),
            Some(FACE),
            &mut map,
        );
        fold_declarations(
            AdminEntityKind::Subscriber,
            ["b/s", "a/s"].into_iter(),
            Some(FACE),
            &mut map,
        );
        let got: Vec<(AdminEntityKind, String)> = map
            .into_declarations()
            .into_iter()
            .map(|d| (d.kind, d.keyexpr))
            .collect();
        assert_eq!(
            got,
            vec![
                (AdminEntityKind::Subscriber, "a/s".to_string()),
                (AdminEntityKind::Subscriber, "b/s".to_string()),
                (AdminEntityKind::Queryable, "a/q".to_string()),
                (AdminEntityKind::Queryable, "b/q".to_string()),
            ]
        );
    }
}
