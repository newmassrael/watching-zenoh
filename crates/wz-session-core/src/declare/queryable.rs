// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `RemoteQueryableRegistry` — application-layer registry tracking
//! the peer's outbound `DeclQueryable` / `UndeclQueryable` records.
//! Q-side mirror of [`crate::declare::subscriber::RemoteSubscriberRegistry`];
//! see [`crate::declare`] module docs for the rationale.
//!
//! R311dp / di-16 — migrated to wz-session-core (was
//! `wz-runtime-tokio::declare::queryable`). `has_matching` is an
//! inherent method on the registry calling
//! [`crate::keyexpr_match::keyexpr_intersect_patterns`] directly —
//! no extension-trait split (R311dn-pre lift made this possible).

// R311gb (Track 2) — String / Vec / HashMap back the `alloc` wire side
// (the peer `declared` membership table + `has_matching` chunking + the
// dispatch params); the no-alloc control plane stores observers in a
// `BoundedVec` and fires through the borrowed `DeclView` seam.
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use hashbrown::HashMap;

#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use wz_codecs::declare::DeclareOwnedVariant;

#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use crate::decl_sink::BorrowedDecl;
#[cfg(feature = "alloc")]
use crate::decl_sink::{BoxedDeclSink, BoxedUndeclSink};
use crate::decl_sink::{DeclObserverPair, DeclSink, DeclView, UndeclSink};
#[cfg(all(feature = "session-matching", feature = "alloc"))]
use crate::declare::matching::{BoxedMatchingSink, MatchingWatchList};
#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
#[cfg(feature = "alloc")]
use crate::locality::Locality;
#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use crate::network_message::NetworkMessage;
use crate::registry_error::RegisterError;
#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use crate::wireexpr_resolve::{resolve_wireexpr_in, MappingSpaces};

/// R311y797 — one peer-declared queryable, as the membership table holds
/// it: the resolved keyexpr AND the completeness the peer advertised on
/// the declaration's `QueryableInfo` ext.
///
/// `complete` is not decoration. A querier targeting
/// [`QueryTarget::AllComplete`](crate::query_mode::QueryTarget) is asking
/// for responders that can answer its WHOLE keyexpr by themselves, so an
/// incomplete peer queryable is not a match for it however well the
/// keyexprs overlap — pico drops such a declaration from the write
/// filter's target list outright
/// (`vendor/zenoh-pico/src/net/filtering.c:206-207`). Until this round wz
/// stored the keyexpr alone, so every peer queryable read as complete and
/// an `AllComplete` querier was told `true` by responders that would
/// answer it partially or not at all.
#[cfg(feature = "alloc")]
struct RemoteQueryable {
    /// Resolved (alias-expanded) keyexpr the peer declared.
    keyexpr: String,
    /// The peer's advertised `QueryableInfo::complete` — zenoh's
    /// `ext_info.complete` bit on `DeclareQueryable`
    /// (`zenoh-protocol/src/network/declare.rs:440-460`). A declaration
    /// carrying no such ext reads as `false`, which is upstream's own
    /// default (`QueryableInfoType::DEFAULT`).
    complete: bool,
}

/// R311y797 — everything a querier's matching verdict depends on, as one
/// value: the keyexpr it queries, the locality it is willing to be
/// answered from, and whether its target demands COMPLETE responders. The
/// watch key of the queryable-side `MatchingWatchList` (a code span, not a
/// link: that type lives behind `session-matching` and this one does not),
/// and the argument of [`RemoteQueryableRegistry::has_matching_for`].
///
/// It is a struct rather than three arguments because the watch has to
/// STORE it: a matching listener must keep re-evaluating under the
/// criterion of the querier that created it, long after that call
/// returned, and a re-evaluation driven from an inbound declaration has
/// nothing else to read the querier's target and locality from. pico
/// stores exactly this set for exactly this reason — `ctx->key`,
/// `ctx->allow_local` / `ctx->allow_remote`, `ctx->is_complete`
/// (`vendor/zenoh-pico/include/zenoh-pico/net/filtering.h:56-66`) — and
/// reads `allow_local` on every local-entity notification
/// (`src/net/filtering.c:386`) as well as at registration.
///
/// The [`Locality`] is carried as wz's own
/// type rather than pico's two bools; it answers the same two questions
/// through `allows_local` / `allows_remote` and cannot represent the
/// neither-half state those bools can.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuerierCriterion {
    /// The querier's keyexpr (a pattern; both sides may be wildcards).
    pub keyexpr: String,
    /// The querier's `allowed_destination`: which halves of the verdict
    /// it admits at all. pico's `ctx->allow_local` / `ctx->allow_remote`
    /// (`vendor/zenoh-pico/src/net/filtering.c:261-262`), zenoh's
    /// `destination` on the matching-listener state
    /// (`zenoh/src/api/matching.rs:83`).
    pub locality: Locality,
    /// `true` iff the querier's target is
    /// [`QueryTarget::AllComplete`](crate::query_mode::QueryTarget) —
    /// zenoh's `MatchingStatusType::Queryables(complete)` discriminant
    /// (`zenoh/src/api/querier.rs:225`), pico's `ctx->is_complete`
    /// (`vendor/zenoh-pico/src/api/api.c:1843-1844`).
    pub complete_required: bool,
}

#[cfg(feature = "alloc")]
impl QuerierCriterion {
    /// Build from the querier's own three knobs.
    pub fn new(keyexpr: &str, locality: Locality, complete_required: bool) -> Self {
        Self {
            keyexpr: String::from(keyexpr),
            locality,
            complete_required,
        }
    }

    /// The plain criterion a locality-blind caller means: any origin, any
    /// intersecting queryable answers. The shape
    /// [`RemoteQueryableRegistry::has_matching`] keeps for its existing
    /// callers.
    pub fn intersecting(keyexpr: &str) -> Self {
        Self::new(keyexpr, Locality::Any, false)
    }
}

/// R311y797 — the queryable-plane membership consult, the completeness-
/// aware counterpart of [`crate::declare::declared_intersects`]. A free fn
/// for the same reason that one is: the watch-list sweep consults the
/// membership table while the watch list itself is mutably borrowed, which
/// only disjoint FIELD borrows allow.
///
/// The two arms are upstream's, and they are NOT the same predicate:
///
/// * ordinary target — the declared keyexpr must INTERSECT the querier's
///   (some literal key both would carry). zenoh
///   `matching_status_local`'s `Queryables(false)` arm
///   (`zenoh/src/api/session.rs:1887-1890`), pico's `!ctx->is_complete`
///   short-circuit (`filtering.c:206`).
/// * `AllComplete` — the declared queryable must itself be `complete` AND
///   its keyexpr must INCLUDE the querier's (`declared ⊇ querier`), i.e.
///   it can answer the whole question alone. zenoh's `Queryables(true)`
///   arm (`session.rs:1891-1894`: `q.complete && q.key_expr.includes(..)`)
///   and pico's (`filtering.c:207`,
///   `msg->is_complete && _z_keyexpr_includes(msg->key, &ctx->key)`).
///
/// Inclusion is STRICTLY STRONGER than intersection, so a `true` under the
/// `AllComplete` arm still predicts a real delivery — the dispatch filter
/// [`Queryable::matches`](crate::query::QueryableRegistry) admits on
/// intersection plus the same completeness conjunct, and every keyexpr
/// pair this arm admits the dispatch admits too.
///
/// pico's `ctx->is_aggregate` escape (`filtering.c:207`, which waives the
/// inclusion test for an AGGREGATE interest) has no counterpart here on
/// purpose: wz never sets the AG bit — `InterestKinds` deliberately has no
/// aggregate member (see the `declare-interest` atom) — so the waiver
/// could only ever fire on a flag wz cannot emit.
#[cfg(feature = "alloc")]
fn declared_answers(
    declared: &HashMap<u64, RemoteQueryable>,
    criterion: &QuerierCriterion,
) -> bool {
    use alloc::vec::Vec;
    // R311y797 — the querier's own locality gates this half BEFORE the
    // membership is consulted at all: a `Locality::SessionLocal` querier
    // is not answered by any peer, so no peer declaration can make it
    // match. pico refuses the same way, per remote target
    // (`_z_write_filter_peer_allowed`, `net/filtering.c:66`).
    if !criterion.locality.allows_remote() {
        return false;
    }
    let target_chunks: Vec<&str> = criterion.keyexpr.split('/').collect();
    if criterion.complete_required {
        #[cfg(feature = "keyexpr-includes")]
        {
            declared.values().any(|candidate| {
                candidate.complete
                    && crate::keyexpr_match::keyexpr_includes_target(
                        &candidate.keyexpr,
                        &target_chunks,
                    )
            })
        }
        // `session-matching` forwards `keyexpr-includes` (Cargo.toml), and
        // the poll's own `AllComplete` arm is reachable only through this
        // fn, so this branch is unreachable in every build that can ask the
        // question. It exists so the module still compiles for a consumer
        // depending on the registry without the matching atom.
        #[cfg(not(feature = "keyexpr-includes"))]
        {
            false
        }
    } else {
        declared.values().any(|candidate| {
            crate::keyexpr_match::keyexpr_intersects_target(&candidate.keyexpr, &target_chunks)
        })
    }
}

/// Application-layer registry tracking the peer's outbound
/// `DeclQueryable` / `UndeclQueryable` records. Q-side mirror of
/// [`crate::declare::subscriber::RemoteSubscriberRegistry`]; the
/// dispatch + callback contracts are identical, only the codec record
/// types differ.
///
/// Why a separate registry rather than a single
/// "RemoteDeclarationRegistry" that handles both: keeping the two
/// surfaces separate lets consumers wire metrics / debug callbacks
/// independently for "peer subscribers" vs "peer queryables"
/// (z_get-side topology in particular is interested only in the
/// queryable subset). Cost is a small amount of duplicated dispatch
/// code; benefit is type-safe consumer wiring and an honest scope
/// boundary that matches zenoh-pico's
/// `Z_FEATURE_SUBSCRIPTION` vs `Z_FEATURE_QUERYABLE` compile-time
/// feature split.
pub struct RemoteQueryableRegistry<D: DeclSink, U: UndeclSink> {
    /// R311gb (Track 2) — shared 2-list observer machinery composed from
    /// [`crate::decl_sink::DeclObserverPair`] (SSOT across the three
    /// `DeclSink` registries). `D = BoxedDeclSink` / `U = BoxedUndeclSink`
    /// on AP, consumer-supplied closed `enum`s on MCU.
    observers: DeclObserverPair<D, U>,
    /// R288 — peer-declared queryables tracked by `{id -> resolved
    /// keyexpr}`. Populated on every inbound `DeclQueryable` whose
    /// keyexpr resolves through `peer_keyexpr_table`, and entries
    /// removed on the matching `UndeclQueryable`. Backbone for
    /// `Querier::get_matching_status` which iterates this map at
    /// consult time to decide whether any currently-declared peer
    /// queryable's keyexpr intersects the querier's keyexpr.
    ///
    /// Why a HashMap (rather than a Vec or BTreeMap): the membership
    /// invariant is by id, undeclare removal is keyed by id, and the
    /// only iteration consumer ([`Self::has_matching`]) does not
    /// depend on ordering. HashMap gives O(1) insert + remove + the
    /// rare full-iteration on get_matching_status calls.
    ///
    /// R311gb (Track 2) — wire-side membership state (populated by
    /// `dispatch_declare` consuming owned `Declare` records, read by
    /// `has_matching`); `alloc`-gated per the borrow boundary.
    /// R311y797 — the value is a [`RemoteQueryable`], not a bare keyexpr:
    /// the peer's advertised completeness is part of the membership fact.
    #[cfg(feature = "alloc")]
    declared: HashMap<u64, RemoteQueryable>,
    /// R311kh — matching-listener watches (pico `Z_FEATURE_MATCHING`),
    /// the Q-side mirror of the subscriber registry's list: re-evaluated
    /// against the `declared` table on every membership mutation, firing
    /// each watch's sink on a verdict flip (the listener form of the
    /// polling `Querier::get_matching_status`).
    /// R311y797 — keyed by [`QuerierCriterion`] rather than a bare
    /// keyexpr, so an `AllComplete` querier's watch keeps re-evaluating
    /// under ITS target.
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    matching_watches: MatchingWatchList<BoxedMatchingSink, QuerierCriterion>,
}

impl<D: DeclSink, U: UndeclSink> Default for RemoteQueryableRegistry<D, U> {
    fn default() -> Self {
        Self::with_sink_backing()
    }
}

impl<D: DeclSink, U: UndeclSink> RemoteQueryableRegistry<D, U> {
    /// New empty registry over explicit sink backings `D` / `U`. Both
    /// observer lists start empty; an empty registry processes inbound
    /// `Declare(Decl*Queryable)` records as no-ops.
    ///
    /// R311gb-3d — the generic constructor (no-`alloc` / MCU entry point,
    /// paired with the `*_sink` installers). AP callers use the inferring
    /// [`new`](RemoteQueryableRegistry::new) shorthand, which fixes
    /// `D = BoxedDeclSink` / `U = BoxedUndeclSink`.
    pub fn with_sink_backing() -> Self {
        Self {
            observers: DeclObserverPair::new(),
            #[cfg(feature = "alloc")]
            declared: HashMap::new(),
            #[cfg(all(feature = "session-matching", feature = "alloc"))]
            matching_watches: MatchingWatchList::new(),
        }
    }

    /// R311gb-3d — install an explicit [`DeclSink`] observer (the
    /// seam-native entry point; works on every profile). The `alloc`-only
    /// [`on_queryable_declared`](RemoteQueryableRegistry::on_queryable_declared)
    /// convenience wrapper funnels through here. Duplicate sinks allowed;
    /// dispatch fires them in registration order. R311lb — returns the
    /// registry-local observer id for
    /// [`remove_queryable_declared_sink`](Self::remove_queryable_declared_sink).
    pub fn on_queryable_declared_sink(&mut self, sink: D) -> Result<u64, RegisterError> {
        self.observers.install_decl(sink)
    }

    /// R311gb-3d — install an explicit [`UndeclSink`] observer. The
    /// `alloc`-only
    /// [`on_queryable_undeclared`](RemoteQueryableRegistry::on_queryable_undeclared)
    /// convenience wrapper funnels through here. R311lb — returns the
    /// registry-local observer id for
    /// [`remove_queryable_undeclared_sink`](Self::remove_queryable_undeclared_sink).
    pub fn on_queryable_undeclared_sink(&mut self, sink: U) -> Result<u64, RegisterError> {
        self.observers.install_undecl(sink)
    }

    /// R311lb — remove the declaration observer keyed by `id` (the
    /// return of
    /// [`on_queryable_declared_sink`](Self::on_queryable_declared_sink)).
    /// Returns whether one was removed; double removal is a `false`
    /// no-op. The removal half of the Session-tier decl-listener
    /// surface (R311lc).
    pub fn remove_queryable_declared_sink(&mut self, id: u64) -> bool {
        self.observers.uninstall_decl(id)
    }

    /// R311lb — remove the undeclaration observer keyed by `id`. Same
    /// contract as
    /// [`remove_queryable_declared_sink`](Self::remove_queryable_declared_sink).
    pub fn remove_queryable_undeclared_sink(&mut self, id: u64) -> bool {
        self.observers.uninstall_undecl(id)
    }

    /// Number of installed `on_queryable_declared` callbacks.
    pub fn on_decl_len(&self) -> usize {
        self.observers.decl_len()
    }

    /// Number of installed `on_queryable_undeclared` callbacks.
    pub fn on_undecl_len(&self) -> usize {
        self.observers.undecl_len()
    }

    /// R288 — count of currently-declared peer queryables (those whose
    /// inbound `DeclQueryable` has been dispatched and whose
    /// `UndeclQueryable` has not). Exposed for diagnostic surfaces
    /// (test fixtures, metrics) and for the `get_matching_status`
    /// implementation that wants to short-circuit when no peer is
    /// declared at all.
    #[cfg(feature = "alloc")]
    pub fn declared_count(&self) -> usize {
        self.declared.len()
    }

    /// R288 — iterate over currently-declared peer queryables as
    /// `(id, resolved_keyexpr)` pairs. Ordering is unspecified (the
    /// backing storage is a `HashMap`). Useful for debug surfaces
    /// that want to enumerate every peer-side declaration; the
    /// `has_matching` accessor below is the production consult
    /// path.
    #[cfg(feature = "alloc")]
    pub fn iter_declared(&self) -> impl Iterator<Item = (u64, &str)> + '_ {
        self.declared
            .iter()
            .map(|(id, q)| (*id, q.keyexpr.as_str()))
    }

    /// R311y797 — [`Self::iter_declared`] carrying the third fact the
    /// membership table now holds: the peer's advertised
    /// `QueryableInfo::complete`. Separate from `iter_declared` rather
    /// than replacing it because every existing consumer wants the pair
    /// and would otherwise have to destructure a flag it ignores.
    #[cfg(feature = "alloc")]
    pub fn iter_declared_info(&self) -> impl Iterator<Item = (u64, &str, bool)> + '_ {
        self.declared
            .iter()
            .map(|(id, q)| (*id, q.keyexpr.as_str(), q.complete))
    }

    /// Backbone for `Querier::get_matching_status` (R288 surfaced
    /// the API; R293 lifted the underlying matcher to honest
    /// wildcard-vs-wildcard intersection). Returns `true` iff at
    /// least one currently-declared peer queryable's keyexpr
    /// intersects `query_keyexpr` under
    /// [`crate::keyexpr_match::keyexpr_intersect_patterns`] — i.e.
    /// there exists at least one literal `/`-separated keyexpr that
    /// both sides match.
    ///
    /// The semantic covers every textbook case:
    ///
    /// * both literals — intersect iff byte-equal,
    /// * one-side pattern covering the other-side literal (any
    ///   `**` / `*` / `$*` shape) — intersect via the asymmetric
    ///   pattern-vs-literal walk inside `keyexpr_intersect_patterns`,
    /// * two-pattern overlap where neither contains the other
    ///   (e.g. `home/*/temp` vs `*/sensor/temp` share
    ///   `home/sensor/temp`) — intersect via the two-side
    ///   `**`-backtracking recursion. This case was the R288
    ///   bidirectional-asymmetric approximation's gap; R293 closed
    ///   it.
    ///
    /// `peer-declared` keyexprs arrive over the wire as runtime
    /// strings (resolved by `resolve_wireexpr` against the peer
    /// keyexpr alias table); the wz spec's "compile-time fixed
    /// KeyExpr set + O(1) table lookup" promise (Appendix C of the
    /// SCE-forge RFC) governs wz's *own* declared keyexprs, not the
    /// peer-side. The matcher here is therefore the production
    /// answer for the peer-declared domain.
    /// R311y797 — `has_matching` is the ordinary-target consult; a
    /// querier whose target demands COMPLETE responders must ask through
    /// [`Self::has_matching_for`], which reads the completeness this
    /// registry now stores.
    #[cfg(feature = "alloc")]
    pub fn has_matching(&self, query_keyexpr: &str) -> bool {
        declared_answers(
            &self.declared,
            &QuerierCriterion::intersecting(query_keyexpr),
        )
    }

    /// R311y797 — the criterion-aware consult behind
    /// `Querier::get_matching_status`: does any currently-declared peer
    /// queryable ANSWER a querier described by `criterion`? See the
    /// module-private `declared_answers` for the two arms and their
    /// upstream sites.
    #[cfg(feature = "alloc")]
    pub fn has_matching_for(&self, criterion: &QuerierCriterion) -> bool {
        declared_answers(&self.declared, criterion)
    }

    /// R311kh — register a matching-listener watch over `keyexpr`, the
    /// Q-side mirror of the subscriber registry's
    /// `declare_matching_listener`: fires on every verdict flip of
    /// [`Self::has_matching`]`(keyexpr)` caused by an inbound
    /// `DeclQueryable` / `UndeclQueryable`, seeded with the current
    /// verdict (registration fires only when already matching).
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn declare_matching_listener(&mut self, keyexpr: &str, sink: BoxedMatchingSink) -> u64 {
        self.declare_matching_listener_seeded(QuerierCriterion::intersecting(keyexpr), false, sink)
    }

    /// R311y797 — [`Self::declare_matching_listener`] carrying the
    /// querier's full criterion and the SESSION-LOCAL half of the current
    /// verdict, the queryable-plane twin of the subscriber registry's
    /// `declare_matching_listener_seeded` (R311y788).
    ///
    /// The seed decides whether registration fires (pico fires `true` at
    /// registration when already matching,
    /// `vendor/zenoh-pico/src/net/filtering.c:341-357`), so it must be the
    /// SAME verdict the poll reports — including the local half, or a
    /// querier whose only match is a queryable on its own session polls
    /// `true` and is then told `true` again by a spurious registration
    /// fire.
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn declare_matching_listener_seeded(
        &mut self,
        criterion: QuerierCriterion,
        local_matching: bool,
        sink: BoxedMatchingSink,
    ) -> u64 {
        let initial = self.has_matching_for(&criterion) || local_matching;
        self.matching_watches.register(criterion, initial, sink)
    }

    /// R311y797 — re-evaluate every matching watch after a change this
    /// registry cannot see: a queryable declared or undeclared on THIS
    /// session. The remote half is read from this registry's own
    /// membership; `local_matching` supplies the local half, and receives
    /// the watch's whole criterion because the local answer depends on the
    /// querier's target too. Returns the number of watches that flipped.
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn reevaluate_matching(
        &mut self,
        local_matching: &dyn Fn(&QuerierCriterion) -> bool,
    ) -> usize {
        self.matching_watches
            .reevaluate(|c| declared_answers(&self.declared, c) || local_matching(c))
    }

    /// R311kh — remove a matching-listener watch. Returns whether one
    /// was removed.
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn undeclare_matching_listener(&mut self, id: u64) -> bool {
        self.matching_watches.unregister(id)
    }

    /// Number of registered matching-listener watches.
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn matching_listener_len(&self) -> usize {
        self.matching_watches.len()
    }

    /// Route an inbound `Declare` envelope's inner body through the
    /// remote-queryable callbacks. Same scope rules as
    /// [`crate::declare::subscriber::RemoteSubscriberRegistry::dispatch_declare`]:
    /// only `DeclQueryable` / `UndeclQueryable` arms route here,
    /// others (Subscriber, Token, Kexpr, Final) are no-ops at this
    /// layer.
    /// R311gb (Track 2) — no-heap declaration fire: hand each installed
    /// `on_decl` observer the borrowed [`DeclView`]. The MCU no-heap
    /// fan-out SSOT; the wire path
    /// ([`dispatch_declare`](Self::dispatch_declare)) funnels through here
    /// after updating the `declared` table. Returns the count fired.
    pub fn dispatch_declared_borrowed(&mut self, view: &dyn DeclView) -> usize {
        self.observers.fire_declared(view)
    }

    /// R311gb (Track 2) — no-heap undeclaration fire: hand each installed
    /// `on_undecl` observer the bare `id`. Returns the count fired.
    pub fn dispatch_undeclared(&mut self, id: u64) -> usize {
        self.observers.fire_undeclared(id)
    }

    /// R311gb (Track 2) — `all(codec-declare, alloc)`-gated wire dispatch;
    /// updates the `alloc` `declared` table then funnels through the
    /// no-heap fire SSOT.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_declare<'a>(
        &mut self,
        body: &DeclareOwnedVariant,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        self.dispatch_declare_with_local(body, peer_keyexpr_table, &|_| false)
    }

    /// R311y797 — [`Self::dispatch_declare`] with the SESSION-LOCAL half
    /// of the matching verdict supplied by the caller; the queryable-plane
    /// twin of the subscriber registry's `dispatch_declare_with_local`
    /// (R311y788).
    ///
    /// It is needed for the same reason that one is, and the failure it
    /// prevents is the same: a watch is a predicate over "does ANYTHING
    /// answer", so an inbound REMOTE undeclare that leaves a session-local
    /// queryable still answering must not flip the watch to `false`. The
    /// local half lives in a sibling observer field and is passed in
    /// rather than mirrored here, so the fact stays in one place.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_declare_with_local<'a>(
        &mut self,
        body: &DeclareOwnedVariant,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
        local_matching: &dyn Fn(&QuerierCriterion) -> bool,
    ) {
        // Consumed only by the `session-matching` re-evaluations below.
        let _ = &local_matching;
        let peer_keyexpr_table = peer_keyexpr_table.into();
        match body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl) => {
                let resolved = match resolve_wireexpr_in(&decl.keyexpr.body, peer_keyexpr_table) {
                    Some(s) => s,
                    None => return,
                };
                // R288 — track peer-declared queryable so
                // get_matching_status can consult the membership at
                // a later point. Late-arrival semantics — a
                // subsequent declare with the same id overwrites
                // the prior entry (peer renamed the keyexpr), which
                // matches zenoh-pico's same-id-replaces behaviour.
                //
                // R311y797 — the completeness rides the SAME insert, read
                // off this declaration's own `QueryableInfo` ext through
                // the production `read_queryable_info` SSOT. A re-declare
                // that only flips completeness (`false -> true`) therefore
                // updates the stored flag in place, which is exactly the
                // case upstream reuses the id for
                // (`build_declare_queryable_reply_with_id`, pico
                // `net/filtering.c:202`).
                let complete =
                    crate::queryable_info::read_queryable_info(decl.extensions.as_ref()).complete;
                self.declared.insert(
                    decl.id,
                    RemoteQueryable {
                        keyexpr: resolved.clone(),
                        complete,
                    },
                );
                let view = BorrowedDecl {
                    id: decl.id,
                    keyexpr: &resolved,
                };
                self.dispatch_declared_borrowed(&view);
                // R311kh — membership changed: flip-fire the matching
                // watches (disjoint field borrows via the free-fn consult).
                #[cfg(feature = "session-matching")]
                self.matching_watches
                    .reevaluate(|c| declared_answers(&self.declared, c) || local_matching(c));
            }
            DeclareOwnedVariant::CodecZenohUndeclQueryable(undecl) => {
                // R288 — drop the membership entry first so a
                // get_matching_status fired from inside the
                // on_undecl callback chain observes the post-
                // undeclare state. Missing-id remove is silent.
                self.declared.remove(&undecl.id);
                self.dispatch_undeclared(undecl.id);
                // R311kh — see the DeclQueryable arm.
                #[cfg(feature = "session-matching")]
                self.matching_watches
                    .reevaluate(|c| declared_answers(&self.declared, c) || local_matching(c));
            }
            // Other sub-variants do not reach this registry.
            _ => {}
        }
    }

    /// Drain a `Vec<NetworkMessage>` through [`Self::dispatch_declare`].
    /// Mirror of the sibling registries.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_messages<'a>(
        &mut self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        self.dispatch_messages_with_local(messages, peer_keyexpr_table, &|_| false)
    }

    /// R311y797 — [`Self::dispatch_messages`] threading the session-local
    /// half through to [`Self::dispatch_declare_with_local`].
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_messages_with_local<'a>(
        &mut self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
        local_matching: &dyn Fn(&QuerierCriterion) -> bool,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        for message in messages {
            if let NetworkMessage::Declare(decl) = message {
                self.dispatch_declare_with_local(&decl.body, peer_keyexpr_table, local_matching);
            }
        }
    }

    /// `IterationEvent` adapter; mirror of the sibling registries.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_iteration_event<'a>(
        &mut self,
        event: IterationEvent<'_>,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        self.dispatch_iteration_event_with_local(event, peer_keyexpr_table, &|_| false)
    }

    /// R311y797 — [`Self::dispatch_iteration_event`] threading the
    /// session-local half; the entry point the observer fan uses, so an
    /// inbound frame's declarations re-evaluate against BOTH halves.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_iteration_event_with_local<'a>(
        &mut self,
        event: IterationEvent<'_>,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
        local_matching: &dyn Fn(&QuerierCriterion) -> bool,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event {
            self.dispatch_messages_with_local(messages, peer_keyexpr_table, local_matching);
        }
    }
}

/// R311gb-3d — AP / `alloc`-profile convenience constructors (the
/// `BoxedDeclSink` / `BoxedUndeclSink` instantiation only). Mirror of the
/// subscriber-side block; the no-`alloc` profile installs consumer-
/// supplied sinks through the generic `*_sink` installers.
#[cfg(feature = "alloc")]
impl RemoteQueryableRegistry<BoxedDeclSink, BoxedUndeclSink> {
    /// New empty AP registry backed by heap-boxed closures. Inferring
    /// shorthand for
    /// [`with_sink_backing`](RemoteQueryableRegistry::with_sink_backing).
    pub fn new() -> Self {
        Self::with_sink_backing()
    }

    /// Install a closure fired on every inbound `Declare(DeclQueryable)`
    /// whose keyexpr resolves. The closure receives `&dyn DeclView` (the
    /// peer-declared `id` + resolved keyexpr) — the R311gb-3d seam
    /// contract replaces the prior `(&DeclQueryableOwned, &str)`
    /// ([`feedback_signature_stability`] wire-data exemption). Heap-boxed
    /// via [`BoxedDeclSink`]. R311lb — returns the registry-local
    /// observer id (see [`Self::remove_queryable_declared_sink`]).
    pub fn on_queryable_declared(
        &mut self,
        callback: impl FnMut(&dyn crate::decl_sink::DeclView) + Send + 'static,
    ) -> u64 {
        // AP backing: the observer `BoundedVec` grows past the advisory
        // `N`, so installing never fails here.
        self.on_queryable_declared_sink(BoxedDeclSink::new(callback))
            .expect("observer install on the alloc backing never exceeds declared capacity")
    }

    /// Install a closure fired on every inbound `Declare(UndeclQueryable)`.
    /// The closure receives the bare `id` (`u64`). Heap-boxed via
    /// [`BoxedUndeclSink`]. R311lb — returns the registry-local observer
    /// id (see [`Self::remove_queryable_undeclared_sink`]).
    pub fn on_queryable_undeclared(&mut self, callback: impl FnMut(u64) + Send + 'static) -> u64 {
        self.on_queryable_undeclared_sink(BoxedUndeclSink::new(callback))
            .expect("observer install on the alloc backing never exceeds declared capacity")
    }
}

// R311gb (Track 2) — test gate now explicit (was inherited from the
// module's `codec-declare` gate); exercises `dispatch_declare` +
// `has_matching`, now `all(codec-declare, alloc)`-gated.
#[cfg(all(test, feature = "codec-declare"))]
mod tests {
    //! R311ds — wider behavioural tests migrated here from the
    //! wz-runtime-tokio `declare/queryable.rs` shell (R311dr-wider-tests
    //! carry closure). `Mutex` is `std` under `#[cfg(test)]` per the
    //! wz-codecs sibling-crate convention; production stays no_std.

    use super::*;
    use alloc::boxed::Box;
    use alloc::string::{String, ToString};
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use hashbrown::HashMap;
    use wz_codecs::declare::DeclareOwnedVariant;
    use wz_session_core_test_support::*;

    use crate::network_message::NetworkMessage;

    /// R311y740 (N37) — the own-space WITNESS for the peer-DECLARE(Queryable)
    /// plane. Sibling of the declare-subscriber pair; see that one for why a
    /// per-plane measurement is not redundant with the shared-resolver tests.
    ///
    /// THE DISCRIMINATOR is the collision: id 7 is in BOTH spaces under
    /// different literals, so a wrong-space read is a confident wrong keyexpr,
    /// not silence.
    #[test]
    fn an_own_space_alias_resolves_in_our_space_on_the_declare_queryable_plane() {
        let mut reg = RemoteQueryableRegistry::new();
        let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_queryable_declared(move |decl| {
            captured_for_cb
                .lock()
                .unwrap()
                .push(decl.keyexpr().to_string());
        });

        let mut peer = HashMap::new();
        peer.insert(7u64, "theirs/q".to_string());
        let mut own = HashMap::new();
        own.insert(7u64, "ours/q".to_string());

        let body =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable_nonlocal(1, 7, None));
        reg.dispatch_declare(&body, MappingSpaces::with_own(&peer, &own));

        assert_eq!(
            *captured.lock().unwrap(),
            vec!["ours/q".to_string()],
            "an M=0 alias names OUR space; reading the peer's would have \
             resolved `theirs/q`",
        );
    }

    /// ANTI-VACUITY twin: with only the peer's space the same record refuses.
    #[test]
    fn without_an_own_space_the_declare_queryable_plane_refuses_the_same_alias() {
        let mut reg = RemoteQueryableRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_for_cb = fired.clone();
        reg.on_queryable_declared(move |_decl| {
            fired_for_cb.fetch_add(1, Ordering::SeqCst);
        });

        let mut peer = HashMap::new();
        peer.insert(7u64, "theirs/q".to_string());

        let body =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable_nonlocal(1, 7, None));
        reg.dispatch_declare(&body, &peer);

        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "with no own space an M=0 alias must refuse -- never fall back to \
             the peer's table",
        );
    }

    #[test]
    fn queryable_empty_registry_dispatch_is_noop() {
        let mut reg = RemoteQueryableRegistry::new();
        let body =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(7, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(reg.on_decl_len(), 0);
        assert_eq!(reg.on_undecl_len(), 0);
    }

    #[test]
    fn queryable_declare_callback_fires_on_literal_keyexpr() {
        let mut reg = RemoteQueryableRegistry::new();
        let captured: Arc<Mutex<Vec<(u64, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_queryable_declared(move |decl| {
            captured_for_cb
                .lock()
                .unwrap()
                .push((decl.id(), decl.keyexpr().to_string()));
        });
        let body =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(8, 0, Some("home/door")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(
            *captured.lock().unwrap(),
            vec![(8, "home/door".to_string())]
        );
    }

    #[test]
    fn queryable_callback_skipped_on_unresolvable_mapping_id() {
        let mut reg = RemoteQueryableRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_for_cb = fired.clone();
        reg.on_queryable_declared(move |_d| {
            fired_for_cb.fetch_add(1, Ordering::SeqCst);
        });
        let body = DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(1, 77, None));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(fired.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn queryable_undeclare_callback_fires() {
        let mut reg = RemoteQueryableRegistry::new();
        let captured: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_queryable_undeclared(move |id| {
            captured_for_cb.lock().unwrap().push(id);
        });
        let body = DeclareOwnedVariant::CodecZenohUndeclQueryable(undecl_queryable(99));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(*captured.lock().unwrap(), vec![99]);
    }

    #[test]
    fn queryable_declared_count_starts_at_zero_and_tracks_decl_undecl_lifecycle() {
        let mut reg = RemoteQueryableRegistry::new();
        assert_eq!(reg.declared_count(), 0);

        // DeclQueryable id=10 keyexpr=home/temp → count 1
        let decl1 =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(10, 0, Some("home/temp")));
        reg.dispatch_declare(&decl1, &HashMap::new());
        assert_eq!(reg.declared_count(), 1);

        // DeclQueryable id=11 keyexpr=home/door → count 2
        let decl2 =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(11, 0, Some("home/door")));
        reg.dispatch_declare(&decl2, &HashMap::new());
        assert_eq!(reg.declared_count(), 2);

        // UndeclQueryable id=10 → count 1 (only id=11 remains)
        let undecl1 = DeclareOwnedVariant::CodecZenohUndeclQueryable(undecl_queryable(10));
        reg.dispatch_declare(&undecl1, &HashMap::new());
        assert_eq!(reg.declared_count(), 1);
        let remaining: Vec<(u64, &str)> = reg.iter_declared().collect();
        assert_eq!(remaining, vec![(11, "home/door")]);

        // UndeclQueryable id=11 → count 0
        let undecl2 = DeclareOwnedVariant::CodecZenohUndeclQueryable(undecl_queryable(11));
        reg.dispatch_declare(&undecl2, &HashMap::new());
        assert_eq!(reg.declared_count(), 0);
    }

    #[test]
    fn queryable_has_matching_false_on_empty_registry() {
        let reg = RemoteQueryableRegistry::new();
        assert!(!reg.has_matching("home/temp"));
        assert!(!reg.has_matching("anything"));
    }

    #[test]
    fn queryable_has_matching_true_on_literal_keyexpr_equality() {
        let mut reg = RemoteQueryableRegistry::new();
        let body =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(7, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/temp"));
        assert!(!reg.has_matching("home/door"));
    }

    #[test]
    fn queryable_has_matching_true_when_peer_pattern_covers_query_literal() {
        let mut reg = RemoteQueryableRegistry::new();
        let body =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(8, 0, Some("home/**")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/temp"));
        assert!(reg.has_matching("home/door/inner"));
        assert!(!reg.has_matching("other/x"));
    }

    #[test]
    fn queryable_has_matching_true_when_query_pattern_covers_peer_literal() {
        let mut reg = RemoteQueryableRegistry::new();
        let body =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(9, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/**"));
        assert!(reg.has_matching("**"));
        assert!(!reg.has_matching("other/**"));
    }

    #[test]
    fn queryable_has_matching_false_after_undeclare() {
        let mut reg = RemoteQueryableRegistry::new();
        let decl =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(12, 0, Some("home/temp")));
        reg.dispatch_declare(&decl, &HashMap::new());
        assert!(reg.has_matching("home/temp"));
        let undecl = DeclareOwnedVariant::CodecZenohUndeclQueryable(undecl_queryable(12));
        reg.dispatch_declare(&undecl, &HashMap::new());
        assert!(!reg.has_matching("home/temp"));
    }

    #[test]
    fn queryable_has_matching_with_mixed_peers_finds_any_match() {
        let mut reg = RemoteQueryableRegistry::new();
        let d1 =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(20, 0, Some("other/foo")));
        let d2 =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(21, 0, Some("home/temp")));
        let d3 = DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(22, 0, Some("a/b/c")));
        reg.dispatch_declare(&d1, &HashMap::new());
        reg.dispatch_declare(&d2, &HashMap::new());
        reg.dispatch_declare(&d3, &HashMap::new());
        assert_eq!(reg.declared_count(), 3);
        // Match on the middle entry; other entries do not interfere.
        assert!(reg.has_matching("home/temp"));
        // Match on the last entry via query-pattern asymmetric arm.
        assert!(reg.has_matching("a/**"));
        // No match on either side.
        assert!(!reg.has_matching("nothing/here"));
    }

    // ── R293 — honest two-pattern overlap (was a false-negative under
    // the pre-R293 bidirectional asymmetric pattern-match approx) ──

    #[test]
    fn queryable_has_matching_true_when_two_patterns_share_literal_via_mid_star() {
        // The textbook two-pattern overlap case: `home/*/temp` (peer)
        // and `*/sensor/temp` (querier) share `home/sensor/temp` (and
        // any `home/<x>/temp` where `<x> == sensor` literally). Pre-
        // R293 the matcher only walked pattern-vs-literal on each
        // direction; neither arm fired for two patterns-without-
        // containment, so this case returned false. R293 honest
        // intersection returns true.
        let mut reg = RemoteQueryableRegistry::new();
        let d = DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(
            30,
            0,
            Some("home/*/temp"),
        ));
        reg.dispatch_declare(&d, &HashMap::new());
        assert!(reg.has_matching("*/sensor/temp"));
        assert!(reg.has_matching("*/*/temp"));
    }

    #[test]
    fn queryable_has_matching_false_when_two_patterns_have_disjoint_anchors() {
        // `home/**/temp ∩ kitchen/**/temp` — literal anchor at chunk
        // 0 disagrees on both sides and no `**` shape can bridge the
        // anchor disagreement. Negative-side coverage for the same
        // two-pattern domain as the test above.
        let mut reg = RemoteQueryableRegistry::new();
        let d = DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(
            31,
            0,
            Some("home/**/temp"),
        ));
        reg.dispatch_declare(&d, &HashMap::new());
        assert!(!reg.has_matching("kitchen/**/temp"));
    }

    #[test]
    fn queryable_has_matching_true_when_double_star_intersects_either_direction() {
        // `home/** ∩ **/temp` shares `home/temp` and any
        // `home/<x>/.../temp`. Both sides are unrestricted-tail / -head
        // patterns; the matcher must walk both **-backtracks.
        let mut reg = RemoteQueryableRegistry::new();
        let d =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(32, 0, Some("home/**")));
        reg.dispatch_declare(&d, &HashMap::new());
        assert!(reg.has_matching("**/temp"));
        assert!(reg.has_matching("**"));
    }

    #[test]
    fn queryable_dispatch_messages_routes_only_queryable_arms() {
        let mut reg = RemoteQueryableRegistry::new();
        let decl_count = Arc::new(AtomicUsize::new(0));
        let undecl_count = Arc::new(AtomicUsize::new(0));
        let d = decl_count.clone();
        let u = undecl_count.clone();
        reg.on_queryable_declared(move |_d| {
            d.fetch_add(1, Ordering::SeqCst);
        });
        reg.on_queryable_undeclared(move |_u| {
            u.fetch_add(1, Ordering::SeqCst);
        });

        // Mix of Subscriber + Queryable envelopes — only Queryable
        // arms route into this registry.
        let messages =
            vec![
                NetworkMessage::Declare(Box::new(declare_envelope_decl_subscriber(
                    decl_subscriber(1, 0, Some("not-this")),
                ))),
                NetworkMessage::Declare(Box::new(declare_envelope_decl_queryable(decl_queryable(
                    2,
                    0,
                    Some("yes-this"),
                )))),
                NetworkMessage::Declare(Box::new(declare_envelope_undecl_queryable(
                    undecl_queryable(2),
                ))),
            ];
        reg.dispatch_messages(&messages, &HashMap::new());
        assert_eq!(
            decl_count.load(Ordering::SeqCst),
            1,
            "only the queryable decl routes here"
        );
        assert_eq!(undecl_count.load(Ordering::SeqCst), 1);
    }

    // ── R311y797 — the peer's advertised completeness, and the criterion
    //    consult that reads it ──────────────────────────────────────────

    /// Build a `Declare(DeclQueryable)` body carrying an explicit
    /// `QueryableInfo` ext, which is how a peer advertises a COMPLETE
    /// queryable on the wire (`zenoh-protocol/src/network/declare.rs:440`,
    /// ext id `0x01` bit 0). The `complete = false` form deliberately goes
    /// through the SAME builder rather than omitting the ext, so the two
    /// arms of every test below differ in one bit and nothing else.
    fn decl_queryable_complete(id: u64, keyexpr: &str, complete: bool) -> DeclareOwnedVariant {
        let mut dq = decl_queryable(id, 0, Some(keyexpr));
        crate::queryable_info::set_queryable_info(
            &mut dq.extensions,
            crate::queryable_info::QueryableInfo {
                complete,
                distance: 0,
            },
        );
        DeclareOwnedVariant::CodecZenohDeclQueryable(dq)
    }

    /// The membership table stores the peer's `QueryableInfo::complete`,
    /// not just its keyexpr. Both arms declare the SAME keyexpr and differ
    /// only in the ext, so a registry that dropped the flag would report
    /// the two identically.
    ///
    /// The absent-ext arm pins upstream's default rather than wz's guess:
    /// zenoh OMITS the ext when it is `{ complete: false, distance: 0 }`
    /// (`QueryableInfoType::DEFAULT`), so "no ext" MUST read as incomplete
    /// and not as unknown.
    #[test]
    fn a_peer_queryables_advertised_completeness_is_stored() {
        let mut reg = RemoteQueryableRegistry::new();
        reg.dispatch_declare(
            &decl_queryable_complete(1, "home/temp", true),
            &HashMap::new(),
        );
        reg.dispatch_declare(
            &decl_queryable_complete(2, "home/temp", false),
            &HashMap::new(),
        );
        // No ext at all — the wire form of the DEFAULT.
        reg.dispatch_declare(
            &DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(3, 0, Some("home/temp"))),
            &HashMap::new(),
        );

        let mut got: Vec<(u64, bool)> = reg
            .iter_declared_info()
            .map(|(id, _ke, complete)| (id, complete))
            .collect();
        got.sort_unstable();
        assert_eq!(
            got,
            vec![(1, true), (2, false), (3, false)],
            "the complete bit rides the declaration; an absent ext is \
             upstream's DEFAULT (incomplete), never unknown",
        );
    }

    /// An `AllComplete` querier is not answered by an INCOMPLETE peer
    /// queryable, however well the keyexprs line up. The discriminator is
    /// that the ordinary criterion over the very same registry says `true`
    /// — so this cannot pass by the keyexprs failing to match.
    ///
    /// pico drops such a declaration from the write filter's target list
    /// (`msg->is_complete &&`, `vendor/zenoh-pico/src/net/filtering.c:207`);
    /// zenoh's local twin is `q.complete &&`
    /// (`zenoh/src/api/session.rs:1894`).
    #[test]
    fn an_all_complete_criterion_refuses_an_incomplete_peer_queryable() {
        let mut reg = RemoteQueryableRegistry::new();
        reg.dispatch_declare(
            &decl_queryable_complete(1, "home/temp", false),
            &HashMap::new(),
        );
        assert!(
            reg.has_matching("home/temp"),
            "the ordinary criterion matches — the keyexprs are identical",
        );
        assert!(
            !reg.has_matching_for(&QuerierCriterion::new(
                "home/temp",
                Locality::Any,
                /*complete_required=*/ true,
            )),
            "an AllComplete querier needs a COMPLETE responder",
        );
    }

    /// Under `AllComplete` the keyexpr test is INCLUSION, not
    /// intersection: the responder must cover the querier's whole
    /// keyexpr on its own.
    ///
    /// The two arms are chosen so intersection cannot stand in for
    /// inclusion. `home/*/temp` and `home/**` INTERSECT (they share
    /// `home/a/temp`) but neither includes the other, so the first arm
    /// separates the predicates; `home/**` DOES include
    /// `home/kitchen/temp`, so the second proves the arm is not simply
    /// refusing everything. Both peers are COMPLETE, so the completeness
    /// conjunct is held fixed.
    ///
    /// Gated on `keyexpr-includes`, which owns the directional matcher the
    /// positive arm needs; `session-matching` forwards it, so every build
    /// that can ask this question runs this test.
    #[cfg(feature = "keyexpr-includes")]
    #[test]
    fn an_all_complete_criterion_demands_inclusion_not_intersection() {
        let mut reg = RemoteQueryableRegistry::new();
        reg.dispatch_declare(
            &decl_queryable_complete(1, "home/*/temp", true),
            &HashMap::new(),
        );
        assert!(
            reg.has_matching("home/**"),
            "`home/*/temp` and `home/**` intersect at `home/a/temp`",
        );
        assert!(
            !reg.has_matching_for(&QuerierCriterion::new("home/**", Locality::Any, true)),
            "`home/*/temp` does NOT include `home/**` — a querier asking \
             for the whole subtree cannot be served alone by a responder \
             holding one depth of it",
        );

        let mut wide = RemoteQueryableRegistry::new();
        wide.dispatch_declare(
            &decl_queryable_complete(2, "home/**", true),
            &HashMap::new(),
        );
        assert!(
            wide.has_matching_for(&QuerierCriterion::new(
                "home/kitchen/temp",
                Locality::Any,
                true,
            )),
            "`home/**` includes `home/kitchen/temp`, so it answers alone",
        );
    }

    /// A `Locality::SessionLocal` querier is not answered by ANY peer
    /// declaration — the remote half is refused before the membership is
    /// even consulted. pico gates every remote target the same way
    /// (`_z_write_filter_peer_allowed`,
    /// `vendor/zenoh-pico/src/net/filtering.c:66`).
    ///
    /// The `Locality::Any` arm over the same registry is the
    /// discriminator: without it a registry that simply never matched
    /// would pass.
    #[test]
    fn a_session_local_querier_is_answered_by_no_peer_declaration() {
        let mut reg = RemoteQueryableRegistry::new();
        reg.dispatch_declare(
            &decl_queryable_complete(1, "home/temp", true),
            &HashMap::new(),
        );
        assert!(
            reg.has_matching_for(&QuerierCriterion::new("home/temp", Locality::Any, false)),
            "a locality-Any querier is answered by the peer",
        );
        assert!(
            !reg.has_matching_for(&QuerierCriterion::new(
                "home/temp",
                Locality::SessionLocal,
                false,
            )),
            "a SessionLocal querier never reaches a peer, so no peer \
             declaration can make it match",
        );
    }

    /// A watch keeps re-evaluating under the criterion it was registered
    /// with — the whole reason the watch key is a criterion rather than a
    /// keyexpr. Registered by an `AllComplete` querier, it must stay
    /// silent while only an INCOMPLETE peer queryable exists and fire
    /// exactly once when a complete one arrives.
    ///
    /// A watch that stored the keyexpr alone fires on the first
    /// declaration, which is the failure this shape is here to catch.
    ///
    /// Gated on `session-matching` (the atom that owns the watch list) as
    /// well as the module's `codec-declare`: Layer C1g's union has the
    /// latter and not the former, so an ungated test here would not fail
    /// there — it would fail to COMPILE.
    #[cfg(feature = "session-matching")]
    #[test]
    fn a_watch_re_evaluates_under_the_criterion_it_was_registered_with() {
        let log: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
        let log_for_sink = log.clone();
        let mut reg = RemoteQueryableRegistry::new();
        let id = reg.declare_matching_listener_seeded(
            QuerierCriterion::new("home/temp", Locality::Any, /*complete_required=*/ true),
            /*local_matching=*/ false,
            crate::declare::matching::BoxedMatchingSink::new(move |m| {
                log_for_sink.lock().unwrap().push(m)
            }),
        );

        reg.dispatch_declare(
            &decl_queryable_complete(1, "home/temp", false),
            &HashMap::new(),
        );
        assert!(
            log.lock().unwrap().is_empty(),
            "an incomplete peer queryable does not satisfy an AllComplete \
             watch, so there is no verdict flip to fire",
        );

        reg.dispatch_declare(
            &decl_queryable_complete(2, "home/temp", true),
            &HashMap::new(),
        );
        assert_eq!(
            *log.lock().unwrap(),
            vec![true],
            "the complete peer queryable flips the verdict exactly once",
        );

        assert!(reg.undeclare_matching_listener(id));
    }

    /// The SESSION-LOCAL half reaches the watch on the INBOUND path, not
    /// only at registration: a remote undeclare that leaves a local
    /// queryable still answering must not flip the watch to `false`.
    ///
    /// The two halves are separated by the local predicate's return value,
    /// so the fixture cannot pass by the remote half alone.
    #[cfg(feature = "session-matching")]
    #[test]
    fn an_unrelated_remote_undeclare_does_not_flip_a_watch_a_local_queryable_holds() {
        let log: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
        let log_for_sink = log.clone();
        let mut reg = RemoteQueryableRegistry::new();
        reg.declare_matching_listener_seeded(
            QuerierCriterion::new("home/temp", Locality::Any, false),
            /*local_matching=*/ true,
            crate::declare::matching::BoxedMatchingSink::new(move |m| {
                log_for_sink.lock().unwrap().push(m)
            }),
        );
        assert_eq!(
            *log.lock().unwrap(),
            vec![true],
            "registration fires `true` when already matching (pico \
             fire-before-insert)",
        );

        // A peer declares and then retracts, while the local half stays true.
        reg.dispatch_declare_with_local(
            &decl_queryable_complete(1, "home/temp", false),
            &HashMap::new(),
            &|_| true,
        );
        reg.dispatch_declare_with_local(
            &DeclareOwnedVariant::CodecZenohUndeclQueryable(undecl_queryable(1)),
            &HashMap::new(),
            &|_| true,
        );
        assert_eq!(
            *log.lock().unwrap(),
            vec![true],
            "the local queryable still answers, so the remote undeclare \
             flips nothing",
        );

        // Now the local half goes away too.
        reg.dispatch_declare_with_local(
            &DeclareOwnedVariant::CodecZenohUndeclQueryable(undecl_queryable(1)),
            &HashMap::new(),
            &|_| false,
        );
        assert_eq!(
            *log.lock().unwrap(),
            vec![true, false],
            "with neither half answering the watch flips to false",
        );
    }
}
