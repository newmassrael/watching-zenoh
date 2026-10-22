// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `RemoteSubscriberRegistry` — application-layer registry tracking
//! the peer's outbound `DeclSubscriber` / `UndeclSubscriber` records.
//! See [`crate::declare`] module docs for the cross-registry rationale
//! and callback contract.
//!
//! R311do / di-15 — migrated to wz-session-core (was
//! `wz-runtime-tokio::declare::subscriber`). AP-side test fixtures
//! stay in the wz-runtime-tokio shell because they exercise
//! Tokio-bound sync primitives. `has_matching` is an inherent method
//! on the registry calling [`crate::keyexpr_match::keyexpr_intersect_patterns`]
//! directly — no extension-trait split (R311dn-pre lift made this
//! possible).

// R311gb (Track 2) — String / Vec back the `alloc` wire side
// (the dispatch params); the peer `declared` membership table is a
// `DeclaredKeys` (S9a): the map it always was on the growable backing and a
// bounded table on the fixed one. The no-alloc control plane stores observers in a
// `BoundedVec` and fires through the borrowed `DeclView` seam.
#[cfg(feature = "storage-profile")]
use crate::bounded::EpochCounter;
use crate::bounded::{Profile, Static, Storage};
#[cfg(all(feature = "codec-declare", feature = "storage-profile"))]
use crate::id_map::key_text_as;
#[cfg(feature = "storage-profile")]
use crate::id_map::{DeclaredKeys, FixedIdMap, IdMap};
#[cfg(feature = "alloc")]
use alloc::string::String;

#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use wz_codecs::declare::DeclareOwnedVariant;
#[cfg(all(
    feature = "codec-declare",
    feature = "storage-profile",
    feature = "session-slot"
))]
use wz_codecs::declare::DeclareVariant;

// The shared [`DeclObserverPair`] holds the bounded observer lists +
// install/fire SSOT; `DeclSink` / `UndeclSink` (bounds) + `DeclView`
// (no-heap fire currency) are unconditional; the `BorrowedDecl` builder +
// `Boxed*` adapters + the wire-codec / envelope imports carry the
// narrower gates.
#[cfg(all(feature = "codec-declare", feature = "storage-profile"))]
use crate::decl_sink::BorrowedDecl;
#[cfg(feature = "alloc")]
use crate::decl_sink::{BoxedDeclSink, BoxedUndeclSink};
use crate::decl_sink::{DeclObserverPair, DeclSink, DeclView, UndeclSink};
#[cfg(feature = "storage-profile")]
use crate::declare::declared_intersects;
#[cfg(all(feature = "session-matching", feature = "alloc"))]
use crate::declare::matching::{BoxedMatchingSink, MatchingWatchList};
#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use crate::driver_loop::DriverLoopOutcome;
#[cfg(all(feature = "codec-declare", feature = "storage-profile"))]
use crate::driver_loop::IterationEvent;
#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use crate::network_message::NetworkMessage;
use crate::registry_error::RegisterError;
#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use crate::wireexpr_resolve::resolve_wireexpr_into;
#[cfg(all(
    feature = "codec-declare",
    feature = "storage-profile",
    feature = "session-slot"
))]
use crate::wireexpr_resolve::resolve_wireexpr_view;
#[cfg(all(feature = "codec-declare", feature = "storage-profile"))]
use crate::wireexpr_resolve::{KeyexprBuf, MappingSpaces};

/// R311y797 — everything a publisher's matching verdict depends on, as
/// one value: the keyexpr it publishes on and the locality it is willing
/// to reach. The watch key of the subscriber-side
/// `MatchingWatchList` (a code span, not a link: that type lives behind
/// `session-matching` and this one does not) and the argument of
/// [`RemoteSubscriberRegistry::has_matching_for`]; the pub-side sibling of
/// [`QuerierCriterion`](crate::declare::queryable::QuerierCriterion),
/// which additionally carries the query target.
///
/// WHAT THIS CLOSED, found by direct read while building the querier
/// twin: R311y788 gave the POLL both halves and gated each on the
/// publisher's `allowed_destination`, but the WATCH kept only a keyexpr,
/// so every re-evaluation answered as if the locality were `Any`. A
/// `Locality::SessionLocal` publisher polled `false` on a purely remote
/// subscriber and was told `true` by its own listener a moment later, and
/// a `Locality::Remote` publisher had the mirror-image disagreement. pico
/// has no such gap because the locality lives in the same write-filter
/// ctx as the keyexpr and is re-read on every notification —
/// `registration_ctx->allow_local` at
/// `vendor/zenoh-pico/src/net/filtering.c:386`, and
/// `_z_write_filter_peer_allowed` (`:66`) on the remote side.
#[cfg(feature = "storage-profile")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherCriterion {
    /// The publisher's keyexpr (a pattern; both sides may be wildcards). Read it
    /// through `as_str`: it is a `String` on the heap profile and a bounded buffer
    /// with no allocator (`crate::declare::CriterionKey`).
    pub keyexpr: super::CriterionKey,
    /// The publisher's `allowed_destination`: which halves of the verdict
    /// it admits at all.
    pub locality: crate::locality::Locality,
}

#[cfg(feature = "alloc")]
impl PublisherCriterion {
    /// Build from the publisher's own two knobs.
    pub fn new(keyexpr: &str, locality: crate::locality::Locality) -> Self {
        Self {
            keyexpr: String::from(keyexpr),
            locality,
        }
    }

    /// The plain criterion a locality-blind caller means: any origin
    /// counts. The shape [`RemoteSubscriberRegistry::has_matching`] keeps
    /// for its existing callers.
    pub fn any_locality(keyexpr: &str) -> Self {
        Self::new(keyexpr, crate::locality::Locality::Any)
    }
}

/// R311y797 — the REMOTE half of a publisher's verdict: does any
/// currently-declared peer subscriber intersect `criterion.keyexpr`, AND
/// does the publisher admit a remote destination at all? A free fn for
/// the same reason [`declared_intersects`] is one — the watch-list sweep
/// consults the membership table while the watch list itself is mutably
/// borrowed.
#[cfg(feature = "alloc")]
fn declared_reaches<M, K>(declared: &M, criterion: &PublisherCriterion) -> bool
where
    M: IdMap<K>,
    K: AsRef<str>,
{
    criterion.locality.allows_remote() && declared_intersects(declared, &criterion.keyexpr)
}

/// Application-layer registry tracking the peer's outbound
/// `DeclSubscriber` / `UndeclSubscriber` records. `!Sync` by
/// construction; cross-task sharing goes through `Arc<Mutex<…>>`.
///
/// `register` and `unregister` are not provided here because the
/// registry is callback-only — there is no per-subscription state to
/// track on the consumer side. The application installs an
/// `on_subscriber_declared` and / or `on_subscriber_undeclared`
/// callback once at startup; every matching inbound declare fires
/// every installed callback in registration order.
///
/// S9a — the registry is the application's [`RemoteSubscriberTable`] (the observer
/// lists, the matching watches) and one peer's [`RemoteSubscriberPeer`] (what that
/// peer has declared) together, the shape every AP session has always had. A
/// process that serves several sessions holds the table once and one peer side
/// per session, since the ids a peer declares are scoped to its own session.
pub struct RemoteSubscriberRegistry<D: DeclSink, U: UndeclSink, P: Storage = Profile> {
    table: RemoteSubscriberTable<D, U, P>,
    peer: RemoteSubscriberPeer<P>,
}

/// The application's half of [`RemoteSubscriberRegistry`]: the observer lists and
/// the matching watches. Nothing a peer writes is here.
pub struct RemoteSubscriberTable<D: DeclSink, U: UndeclSink, P: Storage = Profile> {
    /// R311gb (Track 2) — the shared 2-list observer machinery
    /// (`on_decl` + `on_undecl`, install + fire), composed from
    /// [`crate::decl_sink::DeclObserverPair`] so the fan-out logic lives
    /// once across the three `DeclSink` registries. `D = BoxedDeclSink` /
    /// `U = BoxedUndeclSink` on AP (heap closures), consumer-supplied
    /// closed `enum`s on MCU.
    observers: DeclObserverPair<D, U, P>,
    /// R311kh — matching-listener watches (pico `Z_FEATURE_MATCHING`):
    /// re-evaluated against the peer's `declared` table on every membership
    /// mutation, firing each watch's sink on a verdict flip. The
    /// listener form of the polling `has_matching` consult.
    ///
    /// A watch has no session key, so a table that serves several peers
    /// re-evaluates it against whichever peer's declaration just arrived: the
    /// listener is a single-session facility, and no image that holds more than
    /// one session selects `session-matching` (its sinks are heap closures).
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    matching_watches: MatchingWatchList<BoxedMatchingSink, PublisherCriterion>,
}

/// What ONE peer has declared as subscribers to this session: the table a peer
/// writes. See [`RemoteSubscriberRegistry`].
pub struct RemoteSubscriberPeer<P: Storage = Profile> {
    /// R290 — peer-declared subscribers tracked by `{id -> resolved
    /// keyexpr}`. Pub-side analogue of the `declared` map landed on
    /// [`crate::declare::queryable::RemoteQueryableRegistry`] in R288.
    /// Populated on every inbound `DeclSubscriber` whose keyexpr
    /// resolves through the peer's alias table, and entries removed on
    /// the matching `UndeclSubscriber`. Backbone for the publisher-
    /// side `get_matching_status` consult which iterates this map at
    /// query time to decide whether any currently-declared peer
    /// subscriber's keyexpr intersects the publisher's keyexpr.
    ///
    /// Same by-id rationale as the Q-side: by-id membership
    /// invariant, by-id Undecl removal, no ordering dependency on
    /// the rare full-iteration consult path.
    ///
    /// R311gb (Track 2) — wire-side membership state (populated by
    /// `dispatch_declare` consuming owned `Declare` records, read by
    /// `has_matching`); `alloc`-gated per the borrow boundary. The
    /// no-alloc control plane (observer lists + fan-out) does not depend
    /// on it.
    ///
    /// S9a — a [`DeclaredKeys`]: a `HashMap` on the growable backing and, on the
    /// fixed one, a table of [`crate::caps::MAX_REMOTE_DECLS`] rows whose full
    /// state refuses a NEW id, counts it, and announces nothing for it.
    #[cfg(feature = "storage-profile")]
    declared: DeclaredKeys<P>,
    /// `DeclSubscriber`s refused because their keyexpr is longer than the table's
    /// text (a [`DeclaredKeys`] row holds [`crate::caps::MAX_KEYEXPR_BYTES`] bytes
    /// on the fixed backing). Counted with the table's own refusals.
    #[cfg(feature = "storage-profile")]
    oversize: u32,
    /// Whether the peer has ended its initial declarations: it sent the `DeclareFinal` of
    /// the initial interest ([`crate::extbound::INITIAL_INTEREST_ID`]). Until then `declared`
    /// is what has ARRIVED, not what the peer holds, and a sender must not read an absent
    /// subscriber as no subscriber. Cleared with the table when the link is lost.
    #[cfg(feature = "storage-profile")]
    initial_final: bool,
    /// Moves after every change to `declared`: a shared counter on a policy that can
    /// share one ([`crate::declare::DeclEpoch`]), nothing on one that cannot.
    #[cfg(feature = "storage-profile")]
    epoch: P::Epoch,
    /// Names the policy where no field above does (a build without the session
    /// machinery). Zero-sized.
    _policy: core::marker::PhantomData<P>,
}

impl<P: Storage> Default for RemoteSubscriberPeer<P> {
    fn default() -> Self {
        Self {
            #[cfg(feature = "storage-profile")]
            declared: DeclaredKeys::<P>::default(),
            #[cfg(feature = "storage-profile")]
            oversize: 0,
            #[cfg(feature = "storage-profile")]
            initial_final: false,
            #[cfg(feature = "storage-profile")]
            epoch: <P::Epoch as Default>::default(),
            _policy: core::marker::PhantomData,
        }
    }
}

impl RemoteSubscriberPeer<Static> {
    /// A peer of the static policy that has declared nothing. `const`, so a session
    /// slot that holds one can be a `static`.
    pub const fn new_static() -> Self {
        Self {
            #[cfg(feature = "storage-profile")]
            declared: FixedIdMap::new(),
            #[cfg(feature = "storage-profile")]
            oversize: 0,
            #[cfg(feature = "storage-profile")]
            initial_final: false,
            #[cfg(feature = "storage-profile")]
            epoch: (),
            _policy: core::marker::PhantomData,
        }
    }
}

impl RemoteSubscriberPeer<Profile> {
    /// A peer of this build's storage profile that has declared nothing. `const` where
    /// the profile is the static policy, so a session slot that holds one can be a
    /// `static`.
    #[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
    pub const fn new() -> Self {
        Self::new_static()
    }

    /// A peer of this build's storage profile that has declared nothing.
    #[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(all(
    feature = "storage-profile",
    feature = "alloc",
    target_has_atomic = "64"
))]
impl RemoteSubscriberPeer<crate::bounded::Heap> {
    /// The counter that moves after every change to what this peer has declared, to be
    /// read without this table's lock; see [`crate::declare::DeclEpoch`].
    pub fn epoch(&self) -> crate::declare::DeclEpoch {
        self.epoch.clone()
    }
}

impl<P: Storage> RemoteSubscriberPeer<P> {
    /// Whether the peer has ended its initial declarations, which is what makes an absent
    /// subscriber mean no subscriber: before it, a declaration may simply not have arrived.
    #[cfg(feature = "storage-profile")]
    pub fn initial_declarations_final(&self) -> bool {
        self.initial_final
    }

    /// The peer's `DeclareFinal` of the initial interest arrived. The counter moves, because
    /// an answer kept against it (a write filter's) changes with this.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    fn mark_initial_final(&mut self) {
        if !self.initial_final {
            self.initial_final = true;
            self.changed();
        }
    }

    /// Move the counter: what a change to `declared` ends with.
    #[cfg(feature = "storage-profile")]
    #[inline]
    fn changed(&self) {
        self.epoch.moved();
    }

    /// R290 — count of currently-declared peer subscribers (those
    /// whose inbound `DeclSubscriber` has been dispatched and whose
    /// `UndeclSubscriber` has not). Pub-side mirror of the Q-side
    /// `declared_count`.
    #[cfg(feature = "storage-profile")]
    pub fn declared_count(&self) -> usize {
        self.declared.count()
    }

    /// R290 — iterate over currently-declared peer subscribers as
    /// `(id, resolved_keyexpr)` pairs. Pub-side mirror of the Q-side
    /// `iter_declared`. Ordering is unspecified.
    #[cfg(feature = "storage-profile")]
    pub fn iter_declared(&self) -> impl Iterator<Item = (u64, &str)> + '_ {
        self.declared.entries().map(|(id, ke)| (id, ke.as_ref()))
    }

    /// How many `DeclSubscriber` this peer's table refused: for a NEW id because
    /// it was full ([`crate::caps::MAX_REMOTE_DECLS`]), or for a keyexpr longer
    /// than a row's text. Always zero on the growable backing, where nothing is
    /// refused.
    #[cfg(feature = "storage-profile")]
    pub fn refusals(&self) -> u32 {
        self.declared.refusals().saturating_add(self.oversize)
    }

    /// Backbone for `Publisher::get_matching_status` (R290 surfaced
    /// the API; R293 lifted the underlying matcher to honest
    /// wildcard-vs-wildcard intersection). Pub-side mirror of the
    /// Q-side `has_matching`; returns `true` iff at least one
    /// currently-declared peer subscriber's keyexpr intersects
    /// `publish_keyexpr` under
    /// [`crate::keyexpr_match::keyexpr_intersect_patterns`] — i.e.
    /// there exists at least one literal `/`-separated keyexpr that
    /// both sides match. The Q-side has_matching doc-comment carries
    /// the per-case textbook expansion (literal-literal byte-equal,
    /// one-side wildcard, two-side wildcard overlap); the semantic
    /// is symmetric across Pub-side and Q-side because the matcher
    /// itself is symmetric.
    #[cfg(feature = "storage-profile")]
    pub fn has_matching(&self, publish_keyexpr: &str) -> bool {
        declared_intersects(&self.declared, publish_keyexpr)
    }

    /// R311y797 — the criterion-aware consult: the REMOTE half of a
    /// publisher's matching verdict, gated by that publisher's own
    /// locality. [`Self::has_matching`] is the locality-blind membership
    /// question and stays exactly that for its other callers.
    #[cfg(feature = "alloc")]
    pub fn has_matching_for(&self, criterion: &PublisherCriterion) -> bool {
        declared_reaches(&self.declared, criterion)
    }

    /// Drop everything the peer declared, in place; the refusal count is kept.
    /// Returns how many declarations were dropped.
    #[cfg(feature = "storage-profile")]
    pub fn forget(&mut self) -> usize {
        let dropped = self.declared.count();
        self.declared.reset();
        // A reconnected peer declares again from the start and ends it again.
        self.initial_final = false;
        self.changed();
        dropped
    }
}

impl<D: DeclSink, U: UndeclSink, P: Storage> Default for RemoteSubscriberRegistry<D, U, P> {
    fn default() -> Self {
        Self {
            table: RemoteSubscriberTable::default(),
            peer: RemoteSubscriberPeer::default(),
        }
    }
}

impl<D: DeclSink, U: UndeclSink, P: Storage> Default for RemoteSubscriberTable<D, U, P> {
    fn default() -> Self {
        Self {
            observers: DeclObserverPair::default(),
            #[cfg(all(feature = "session-matching", feature = "alloc"))]
            matching_watches: MatchingWatchList::new(),
        }
    }
}

impl<D: DeclSink, U: UndeclSink, P: Storage> core::ops::Deref
    for RemoteSubscriberRegistry<D, U, P>
{
    type Target = RemoteSubscriberTable<D, U, P>;

    fn deref(&self) -> &RemoteSubscriberTable<D, U, P> {
        &self.table
    }
}

impl<D: DeclSink, U: UndeclSink, P: Storage> core::ops::DerefMut
    for RemoteSubscriberRegistry<D, U, P>
{
    fn deref_mut(&mut self) -> &mut RemoteSubscriberTable<D, U, P> {
        &mut self.table
    }
}

impl<D: DeclSink, U: UndeclSink> RemoteSubscriberRegistry<D, U, Profile> {
    /// New empty registry over explicit sink backings `D` / `U`, of this build's
    /// storage profile. Both observer lists start empty; an empty registry processes
    /// inbound `Declare(Decl*)` records as no-ops.
    ///
    /// R311gb-3d — the generic constructor (the no-`alloc` / MCU entry
    /// point, paired with [`on_subscriber_declared_sink`](RemoteSubscriberTable::on_subscriber_declared_sink)
    /// / [`on_subscriber_undeclared_sink`](RemoteSubscriberTable::on_subscriber_undeclared_sink)).
    /// AP callers use the inferring [`new`](RemoteSubscriberRegistry::new)
    /// shorthand, which fixes `D = BoxedDeclSink` / `U = BoxedUndeclSink`. Defined for
    /// the profile alone, so it names its storage policy by itself; code generic over a
    /// policy builds a registry with `Default`.
    pub fn with_sink_backing() -> Self {
        Self::default()
    }
}

impl<D: DeclSink, U: UndeclSink, P: Storage> RemoteSubscriberRegistry<D, U, P> {
    /// The peer's side of this registry, for a caller that wants its table or its
    /// counters by name.
    pub fn peer(&self) -> &RemoteSubscriberPeer<P> {
        &self.peer
    }

    /// R290 — count of currently-declared peer subscribers; see
    /// [`RemoteSubscriberPeer::declared_count`].
    #[cfg(feature = "storage-profile")]
    pub fn declared_count(&self) -> usize {
        self.peer.declared_count()
    }

    /// R290 — iterate over currently-declared peer subscribers; see
    /// [`RemoteSubscriberPeer::iter_declared`].
    #[cfg(feature = "storage-profile")]
    pub fn iter_declared(&self) -> impl Iterator<Item = (u64, &str)> + '_ {
        self.peer.iter_declared()
    }

    /// Backbone for `Publisher::get_matching_status`; see
    /// [`RemoteSubscriberPeer::has_matching`].
    #[cfg(feature = "storage-profile")]
    pub fn has_matching(&self, publish_keyexpr: &str) -> bool {
        self.peer.has_matching(publish_keyexpr)
    }

    /// R311y797 — the criterion-aware consult; see
    /// [`RemoteSubscriberPeer::has_matching_for`].
    #[cfg(feature = "alloc")]
    pub fn has_matching_for(&self, criterion: &PublisherCriterion) -> bool {
        self.peer.has_matching_for(criterion)
    }

    /// R311kh — register a matching-listener watch over `keyexpr`; see
    /// [`RemoteSubscriberTable::declare_matching_listener`].
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn declare_matching_listener(&mut self, keyexpr: &str, sink: BoxedMatchingSink) -> u64 {
        self.table
            .declare_matching_listener(&self.peer, keyexpr, sink)
    }

    /// R311y788 — [`Self::declare_matching_listener`] with the
    /// session-local half of the current verdict supplied by the caller.
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn declare_matching_listener_seeded(
        &mut self,
        criterion: PublisherCriterion,
        local_matching: bool,
        sink: BoxedMatchingSink,
    ) -> u64 {
        self.table
            .declare_matching_listener_seeded(&self.peer, criterion, local_matching, sink)
    }

    /// R311y788 — re-evaluate every matching watch after a change this
    /// registry cannot see; see [`RemoteSubscriberTable::reevaluate_matching`].
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn reevaluate_matching(
        &mut self,
        local_matching: &dyn Fn(&PublisherCriterion) -> bool,
    ) -> usize {
        self.table.reevaluate_matching(&self.peer, local_matching)
    }

    /// R311y799 — the peer's link died: drop every declaration it had made; see
    /// [`RemoteSubscriberTable::flush_declarations_on_link_loss`].
    #[cfg(all(feature = "codec-declare", feature = "storage-profile"))]
    pub fn flush_declarations_on_link_loss(
        &mut self,
        local_matching: &dyn Fn(&PublisherCriterion) -> bool,
    ) -> usize {
        self.table
            .flush_declarations_on_link_loss(&mut self.peer, local_matching)
    }

    /// Route an inbound `Declare` envelope's inner body through the
    /// remote-subscriber callbacks; see
    /// [`RemoteSubscriberTable::dispatch_declare`].
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_declare<'a>(
        &mut self,
        body: &DeclareOwnedVariant,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        self.table
            .dispatch_declare(&mut self.peer, body, peer_keyexpr_table);
    }

    /// R311y788 — [`Self::dispatch_declare`] with the SESSION-LOCAL half
    /// of the matching verdict supplied by the caller.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_declare_with_local<'a>(
        &mut self,
        body: &DeclareOwnedVariant,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
        local_matching: &dyn Fn(&PublisherCriterion) -> bool,
    ) {
        self.table.dispatch_declare_with_local(
            &mut self.peer,
            body,
            peer_keyexpr_table,
            local_matching,
        );
    }

    /// Drain a `Vec<NetworkMessage>` through [`Self::dispatch_declare`].
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_messages<'a>(
        &mut self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        self.table
            .dispatch_messages(&mut self.peer, messages, peer_keyexpr_table);
    }

    /// R311y788 — [`Self::dispatch_messages`] carrying the session-local
    /// half of the matching verdict.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_messages_with_local<'a>(
        &mut self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
        local_matching: &dyn Fn(&PublisherCriterion) -> bool,
    ) {
        self.table.dispatch_messages_with_local(
            &mut self.peer,
            messages,
            peer_keyexpr_table,
            local_matching,
        );
    }

    /// Convenience adapter over an `IterationEvent`; see
    /// [`RemoteSubscriberTable::dispatch_iteration_event`].
    #[cfg(all(feature = "codec-declare", feature = "storage-profile"))]
    pub fn dispatch_iteration_event<'a>(
        &mut self,
        event: IterationEvent<'_>,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        self.table
            .dispatch_iteration_event(&mut self.peer, event, peer_keyexpr_table);
    }

    /// R311y788 — [`Self::dispatch_iteration_event`] carrying the
    /// session-local half of the matching verdict.
    #[cfg(all(feature = "codec-declare", feature = "storage-profile"))]
    pub fn dispatch_iteration_event_with_local<'a>(
        &mut self,
        event: IterationEvent<'_>,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
        local_matching: &dyn Fn(&PublisherCriterion) -> bool,
    ) {
        self.table.dispatch_iteration_event_with_local(
            &mut self.peer,
            event,
            peer_keyexpr_table,
            local_matching,
        );
    }
}

impl<D: DeclSink, U: UndeclSink> RemoteSubscriberTable<D, U, Profile> {
    /// New empty table over explicit sink backings `D` / `U`, of this build's
    /// storage profile. Both observer lists start empty.
    pub fn with_sink_backing() -> Self {
        Self::default()
    }
}

impl<D: DeclSink, U: UndeclSink, P: Storage> RemoteSubscriberTable<D, U, P> {
    /// R311gb-3d — install an explicit [`DeclSink`] observer (the
    /// seam-native entry point; works on every profile). The `alloc`-only
    /// [`on_subscriber_declared`](RemoteSubscriberRegistry::on_subscriber_declared)
    /// convenience wrapper funnels through here after wrapping a closure
    /// in a [`BoxedDeclSink`]. Duplicate sinks are explicitly allowed;
    /// dispatch fires them in registration order. R311lb — returns the
    /// registry-local observer id for
    /// [`remove_subscriber_declared_sink`](Self::remove_subscriber_declared_sink).
    pub fn on_subscriber_declared_sink(&mut self, sink: D) -> Result<u64, RegisterError> {
        self.observers.install_decl(sink)
    }

    /// R311gb-3d — install an explicit [`UndeclSink`] observer. The
    /// `alloc`-only
    /// [`on_subscriber_undeclared`](RemoteSubscriberRegistry::on_subscriber_undeclared)
    /// convenience wrapper funnels through here. R311lb — returns the
    /// registry-local observer id for
    /// [`remove_subscriber_undeclared_sink`](Self::remove_subscriber_undeclared_sink).
    pub fn on_subscriber_undeclared_sink(&mut self, sink: U) -> Result<u64, RegisterError> {
        self.observers.install_undecl(sink)
    }

    /// R311lb — remove the declaration observer keyed by `id` (the
    /// return of
    /// [`on_subscriber_declared_sink`](Self::on_subscriber_declared_sink)).
    /// Returns whether one was removed; double removal is a `false`
    /// no-op. The removal half of the Session-tier decl-listener
    /// surface (R311lc).
    pub fn remove_subscriber_declared_sink(&mut self, id: u64) -> bool {
        self.observers.uninstall_decl(id)
    }

    /// R311lb — remove the undeclaration observer keyed by `id`. Same
    /// contract as
    /// [`remove_subscriber_declared_sink`](Self::remove_subscriber_declared_sink).
    pub fn remove_subscriber_undeclared_sink(&mut self, id: u64) -> bool {
        self.observers.uninstall_undecl(id)
    }

    /// Number of installed `on_subscriber_declared` callbacks.
    pub fn on_decl_len(&self) -> usize {
        self.observers.decl_len()
    }

    /// Number of installed `on_subscriber_undeclared` callbacks.
    pub fn on_undecl_len(&self) -> usize {
        self.observers.undecl_len()
    }

    /// R311kh — register a matching-listener watch over `keyexpr` (pico
    /// `Z_FEATURE_MATCHING`): the sink fires on every VERDICT FLIP of
    /// [`RemoteSubscriberPeer::has_matching`]`(keyexpr)` caused by an inbound
    /// `DeclSubscriber` / `UndeclSubscriber`, seeded with the CURRENT
    /// verdict so registration itself never fires (pico transition-only
    /// semantics; `get_matching_status` remains the poll for the current
    /// value). Returns the watch id for
    /// [`Self::undeclare_matching_listener`].
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn declare_matching_listener(
        &mut self,
        peer: &RemoteSubscriberPeer<P>,
        keyexpr: &str,
        sink: BoxedMatchingSink,
    ) -> u64 {
        self.declare_matching_listener_seeded(
            peer,
            PublisherCriterion::any_locality(keyexpr),
            false,
            sink,
        )
    }

    /// R311y788 — [`Self::declare_matching_listener`] with the
    /// session-local half of the current verdict supplied by the caller.
    ///
    /// The seed decides whether registration fires (pico fires `true` at
    /// registration when already matching,
    /// `vendor/zenoh-pico/src/net/filtering.c:341-357`), so it has to be
    /// the SAME verdict the poll reports or the two disagree about the
    /// instant the listener was created — a publisher whose only match is
    /// a subscriber on its own session would poll `true` and then be told
    /// `true` again by a spurious registration fire.
    ///
    /// R311y797 — the seed takes the publisher's whole
    /// [`PublisherCriterion`], not a bare keyexpr, because the LOCALITY is
    /// part of the verdict too and the watch has to keep applying it. See
    /// that type for the divergence this closed.
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn declare_matching_listener_seeded(
        &mut self,
        peer: &RemoteSubscriberPeer<P>,
        criterion: PublisherCriterion,
        local_matching: bool,
        sink: BoxedMatchingSink,
    ) -> u64 {
        let initial = peer.has_matching_for(&criterion) || local_matching;
        self.matching_watches.register(criterion, initial, sink)
    }

    /// R311y788 — re-evaluate every matching watch after a change this
    /// registry cannot see: a subscriber declared or undeclared on THIS
    /// session. The remote half is read from this registry's own
    /// membership; `local_matching` supplies the local half. Returns the
    /// number of watches whose verdict flipped (and therefore fired).
    ///
    /// The remote counterpart needs no such entry point — an inbound
    /// declaration already arrives through
    /// [`Self::dispatch_declare_with_local`], which re-evaluates.
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn reevaluate_matching(
        &mut self,
        peer: &RemoteSubscriberPeer<P>,
        local_matching: &dyn Fn(&PublisherCriterion) -> bool,
    ) -> usize {
        self.matching_watches
            .reevaluate(|c| declared_reaches(&peer.declared, c) || local_matching(c))
    }

    /// R311y799 — the peer's link died: drop every declaration it had made
    /// and re-evaluate the matching watches. Returns the number of
    /// declarations dropped.
    ///
    /// pico's own arm, and the reason this is a purge rather than a
    /// per-declaration undeclare: `_Z_INTEREST_MSG_TYPE_CONNECTION_DROPPED`
    /// drops ALL of that peer's write-filter targets in one sweep and then
    /// runs `_z_write_filter_ctx_update_state`
    /// (`vendor/zenoh-pico/src/net/filtering.c:217-220`), which is what
    /// flips a matching listener back to `false`.
    ///
    /// WHY "ALL" IS THE SAME AS "THIS PEER'S" HERE, and why wz needs no
    /// `peer` key to do it: the `peer` side passed in is ONE session's, and what
    /// it holds is `{declaration id -> keyexpr}` for the one peer on that link.
    /// (Until S9a this registry sat on an
    /// [`ApplicationLayerObserver`](crate::observer) whose single alias table
    /// two peers' id spaces would have collided in, so the observer was
    /// single-peer by construction; each session now has a side of its own, and
    /// the flush is of the side whose link just died.) pico keys its targets by
    /// peer because its write-filter ctx spans a session that really can hold
    /// several transport peers.
    ///
    /// The decl-listener surface (`on_subscriber_undeclared`) is
    /// deliberately NOT fired: pico's connection-dropped arm touches the
    /// filter targets and nothing else, so firing it would be a wz
    /// superset rather than parity. The liveliness plane's link-loss flush
    /// (R311y521) DOES deliver to the application, and that asymmetry is
    /// upstream's too — `_z_liveliness_subscription_undeclare_all` calls
    /// the subscriber callbacks where the write filter does not.
    #[cfg(all(feature = "codec-declare", feature = "storage-profile"))]
    pub fn flush_declarations_on_link_loss(
        &mut self,
        peer: &mut RemoteSubscriberPeer<P>,
        local_matching: &dyn Fn(&PublisherCriterion) -> bool,
    ) -> usize {
        let _ = &local_matching;
        let dropped = peer.forget();
        #[cfg(feature = "session-matching")]
        self.matching_watches
            .reevaluate(|c| declared_reaches(&peer.declared, c) || local_matching(c));
        dropped
    }

    /// R311kh — remove a matching-listener watch. Returns whether one
    /// was removed (pico `_z_matching_listener_undeclare`).
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn undeclare_matching_listener(&mut self, id: u64) -> bool {
        self.matching_watches.unregister(id)
    }

    /// Number of registered matching-listener watches (observability /
    /// test helper).
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn matching_listener_len(&self) -> usize {
        self.matching_watches.len()
    }

    /// R311gb (Track 2) — no-heap declaration fire: hand each installed
    /// `on_decl` observer the borrowed [`DeclView`]. Borrow-driven (the
    /// caller owns the view), so it is the MCU no-heap fan-out; the wire
    /// path ([`dispatch_declare`](Self::dispatch_declare)) builds a
    /// [`BorrowedDecl`] from the resolved keyexpr and funnels through here
    /// after updating the `declared` membership table. Returns the count
    /// of observers fired.
    pub fn dispatch_declared_borrowed(&mut self, view: &dyn DeclView) -> usize {
        self.observers.fire_declared(view)
    }

    /// R311gb (Track 2) — no-heap undeclaration fire: hand each installed
    /// `on_undecl` observer the bare `id` (the undeclaration carries no
    /// keyexpr). Returns the count of observers fired.
    pub fn dispatch_undeclared(&mut self, id: u64) -> usize {
        self.observers.fire_undeclared(id)
    }

    /// Route an inbound `Declare` envelope's inner body through the
    /// remote-subscriber callbacks. `DeclareOwnedVariant` arms other than
    /// `DeclSubscriber` / `UndeclSubscriber` are no-ops here — the
    /// queryable / token / kexpr / final arms route through their own
    /// dedicated registries.
    ///
    /// `peer_keyexpr_table` is the same table maintained by the
    /// session-level `SubscriberRegistry` from inbound
    /// `Declare(DeclKexpr)` records. Unresolvable keyexprs (mapping
    /// id not yet declared) drop the dispatch silently rather than
    /// firing on a partial keyexpr.
    ///
    /// R311gb (Track 2) — `all(codec-declare, alloc)`-gated: it consumes
    /// the owned `DeclareOwnedVariant` (codec) and updates the `alloc`
    /// `declared` table, then funnels the fan-out through the no-heap
    /// [`dispatch_declared_borrowed`](Self::dispatch_declared_borrowed) /
    /// [`dispatch_undeclared`](Self::dispatch_undeclared) SSOT.
    ///
    /// S9a — `peer` is the declaring peer's side (its `declared` table), passed
    /// in so one table serves many sessions.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_declare<'a>(
        &mut self,
        peer: &mut RemoteSubscriberPeer<P>,
        body: &DeclareOwnedVariant,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        self.dispatch_declare_with_local(peer, body, peer_keyexpr_table, &|_| false)
    }

    /// R311y788 — [`Self::dispatch_declare`] with the SESSION-LOCAL half
    /// of the matching verdict supplied by the caller.
    ///
    /// A matching watch is a predicate over "does anything match", and
    /// this registry only knows the REMOTE half; the local subscriptions
    /// live on the sibling
    /// [`SubscriberRegistry`](crate::pubsub::SubscriberRegistry). Passing
    /// the local half in rather than mirroring it here keeps one copy of
    /// that fact — and it has to be passed on THIS path, not only at
    /// registration, because a watch held `true` by a local subscriber
    /// must not be flipped to `false` by an unrelated remote undeclare.
    ///
    /// [`Self::dispatch_declare`] delegates here with a `false` local
    /// half, which is the honest answer for a caller that has no local
    /// subscriber table in reach. The production fan
    /// ([`crate::observer::SessionObserver`]) passes the real one.
    ///
    /// S9a — a `DeclSubscriber` whose id the peer's table has no room for, or whose
    /// keyexpr is longer than the table's text, is REFUSED: counted
    /// ([`RemoteSubscriberPeer::refusals`]), not recorded, and not announced to
    /// the observers, so what the application is told is what the table holds.
    /// The keyexpr is resolved into a bounded buffer, so on the fixed backing the
    /// whole absorb allocates nothing.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_declare_with_local<'a>(
        &mut self,
        peer: &mut RemoteSubscriberPeer<P>,
        body: &DeclareOwnedVariant,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
        local_matching: &dyn Fn(&PublisherCriterion) -> bool,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        match body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl) => {
                let mut composed = KeyexprBuf::new();
                let resolved = match resolve_wireexpr_into(
                    &decl.keyexpr.body,
                    peer_keyexpr_table,
                    &mut composed,
                ) {
                    Ok(Some(s)) => s,
                    Ok(None) => return,
                    Err(_) => {
                        peer.oversize = peer.oversize.saturating_add(1);
                        return;
                    }
                };
                self.apply_declared(peer, decl.id, resolved, local_matching);
            }
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(undecl) => {
                self.apply_undeclared(peer, undecl.id, local_matching);
            }
            // Other sub-variants do not reach this registry.
            _ => {}
        }
    }

    /// [`Self::dispatch_declare_with_local`] for a `Declare` the in-place receive
    /// path lends ([`IterationEvent::InPlace`]): the same two arms, the same
    /// refusals and the same fan-out, over the declaration as it is decoded where
    /// its frame lies. Only the reading differs (the keyexpr is resolved by
    /// [`resolve_wireexpr_view`], the rule the owned form's resolver shares); what is
    /// done with the resolved keyexpr is `apply_declared` for both, so a
    /// rule lives in one place.
    #[cfg(all(
        feature = "codec-declare",
        feature = "storage-profile",
        feature = "session-slot"
    ))]
    pub fn dispatch_declare_view_with_local<'a>(
        &mut self,
        peer: &mut RemoteSubscriberPeer<P>,
        body: &DeclareVariant<'a>,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
        local_matching: &dyn Fn(&PublisherCriterion) -> bool,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        match body {
            DeclareVariant::CodecZenohDeclSubscriber(decl) => {
                let mut composed = KeyexprBuf::new();
                let resolved = match resolve_wireexpr_view(
                    &decl.keyexpr.body,
                    peer_keyexpr_table,
                    &mut composed,
                ) {
                    Ok(Some(s)) => s,
                    Ok(None) => return,
                    Err(_) => {
                        peer.oversize = peer.oversize.saturating_add(1);
                        return;
                    }
                };
                self.apply_declared(peer, decl.id, resolved, local_matching);
            }
            DeclareVariant::CodecZenohUndeclSubscriber(undecl) => {
                self.apply_undeclared(peer, undecl.id, local_matching);
            }
            // Other sub-variants do not reach this registry.
            _ => {}
        }
    }

    /// What a declared peer subscriber does once its keyexpr is resolved, whichever
    /// form carried the declaration: bind it in the peer's table (refusing and
    /// counting past the table's room or a row's text), fan it to the observers
    /// through the no-heap SSOT, and re-evaluate the matching watches.
    #[cfg(all(feature = "codec-declare", feature = "storage-profile"))]
    fn apply_declared(
        &mut self,
        peer: &mut RemoteSubscriberPeer<P>,
        id: u64,
        resolved: &str,
        local_matching: &dyn Fn(&PublisherCriterion) -> bool,
    ) {
        // Consumed only by the `session-matching` re-evaluation below.
        let _ = &local_matching;
        // R290 — same membership-tracking pattern as the
        // Q-side registry: same-id-replaces semantic, no
        // explicit conflict surfacing.
        let Ok(text) = key_text_as::<P>(resolved) else {
            peer.oversize = peer.oversize.saturating_add(1);
            return;
        };
        if peer.declared.bind(id, text).is_err() {
            return;
        }
        peer.changed();
        // R311gb-3d / Track 2 — fan through the DeclSink seam via
        // the no-heap SSOT: build the `(id, resolved-keyexpr)`
        // view once and hand each observer `&dyn DeclView`.
        let view = BorrowedDecl {
            id,
            keyexpr: resolved,
        };
        self.dispatch_declared_borrowed(&view);
        // R311kh — membership changed: re-evaluate the matching
        // watches (flip-fire only). Disjoint field borrows: the
        // watch list is &mut, the membership table is read
        // through the free-fn consult.
        #[cfg(feature = "session-matching")]
        self.matching_watches
            .reevaluate(|c| declared_reaches(&peer.declared, c) || local_matching(c));
    }

    /// What an undeclared peer subscriber does, whichever form carried the
    /// undeclaration: drop the membership entry first (so a `get_matching_status`
    /// fired from inside the `on_undecl` chain observes the post-undeclare state),
    /// fan it to the observers, and re-evaluate the matching watches.
    #[cfg(all(feature = "codec-declare", feature = "storage-profile"))]
    fn apply_undeclared(
        &mut self,
        peer: &mut RemoteSubscriberPeer<P>,
        id: u64,
        local_matching: &dyn Fn(&PublisherCriterion) -> bool,
    ) {
        let _ = &local_matching;
        // R290 — drop the membership entry first so a
        // get_matching_status fired from inside the
        // on_undecl callback chain observes the post-
        // undeclare state.
        peer.declared.unbind(id);
        peer.changed();
        self.dispatch_undeclared(id);
        // R311kh — see `apply_declared`.
        #[cfg(feature = "session-matching")]
        self.matching_watches
            .reevaluate(|c| declared_reaches(&peer.declared, c) || local_matching(c));
    }

    /// Drain a `Vec<NetworkMessage>` (typically the
    /// `FramePayload.messages` field surfaced by the production
    /// driver loop) through [`Self::dispatch_declare`]. Mirrors the
    /// sibling registries so the observer in production code can fan
    /// one event into every registry uniformly.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_messages<'a>(
        &mut self,
        peer: &mut RemoteSubscriberPeer<P>,
        messages: &[NetworkMessage],
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        self.dispatch_messages_with_local(peer, messages, peer_keyexpr_table, &|_| false)
    }

    /// R311y788 — [`Self::dispatch_messages`] carrying the session-local
    /// half of the matching verdict; see
    /// [`Self::dispatch_declare_with_local`].
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_messages_with_local<'a>(
        &mut self,
        peer: &mut RemoteSubscriberPeer<P>,
        messages: &[NetworkMessage],
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
        local_matching: &dyn Fn(&PublisherCriterion) -> bool,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        for message in messages {
            if let NetworkMessage::Declare(decl) = message {
                // The `DeclareFinal` of the initial interest ends the peer's first burst of
                // declarations; any other interest's final is some other plane's answer.
                if matches!(decl.body, DeclareOwnedVariant::CodecZenohDeclFinal(_))
                    && decl.interest_id == Some(crate::extbound::INITIAL_INTEREST_ID)
                {
                    peer.mark_initial_final();
                }
                self.dispatch_declare_with_local(
                    peer,
                    &decl.body,
                    peer_keyexpr_table,
                    local_matching,
                );
            }
        }
    }

    /// Convenience adapter that pulls the `FramePayload.messages` out
    /// of an `IterationEvent::Poll(DriverLoopOutcome::FramePayload)`
    /// and forwards to [`Self::dispatch_messages`]. Mirror of the
    /// sibling registries. Other `IterationEvent` variants (`Lease`,
    /// non-FramePayload `Poll` outcomes) are no-ops.
    #[cfg(all(feature = "codec-declare", feature = "storage-profile"))]
    pub fn dispatch_iteration_event<'a>(
        &mut self,
        peer: &mut RemoteSubscriberPeer<P>,
        event: IterationEvent<'_>,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        self.dispatch_iteration_event_with_local(peer, event, peer_keyexpr_table, &|_| false)
    }

    /// R311y788 — [`Self::dispatch_iteration_event`] carrying the
    /// session-local half of the matching verdict; see
    /// [`Self::dispatch_declare_with_local`]. This is the entry point the
    /// production observer fan uses, so both runtime profiles get the
    /// local half without either of them mirroring the local table.
    #[cfg(all(feature = "codec-declare", feature = "storage-profile"))]
    pub fn dispatch_iteration_event_with_local<'a>(
        &mut self,
        peer: &mut RemoteSubscriberPeer<P>,
        event: IterationEvent<'_>,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
        local_matching: &dyn Fn(&PublisherCriterion) -> bool,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        match event {
            #[cfg(feature = "alloc")]
            IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) => {
                self.dispatch_messages_with_local(
                    peer,
                    messages,
                    peer_keyexpr_table,
                    local_matching,
                );
            }
            // A Declare the slot profile's receive path lends where its frame lies.
            #[cfg(feature = "session-slot")]
            IterationEvent::InPlace(record) => {
                if let Some(declare) = record.declare() {
                    self.dispatch_declare_view_with_local(
                        peer,
                        &declare.body,
                        peer_keyexpr_table,
                        local_matching,
                    );
                }
            }
            _ => {}
        }
    }
}

/// R311gb-3d — AP / `alloc`-profile convenience constructors. The
/// closure-taking `on_subscriber_declared` / `on_subscriber_undeclared`
/// wrappers live here (on the `BoxedDeclSink` / `BoxedUndeclSink`
/// instantiation only) because they heap-box the closures; the no-`alloc`
/// profile installs consumer-supplied sinks through the generic
/// [`on_subscriber_declared_sink`](RemoteSubscriberTable::on_subscriber_declared_sink)
/// / [`on_subscriber_undeclared_sink`](RemoteSubscriberTable::on_subscriber_undeclared_sink)
/// instead.
///
/// R311gb (Track 2) — gated on `alloc` only (not `codec-declare`): the
/// closure installers funnel through the un-gated `on_*_declared_sink`, so
/// the AP observer-install surface composes in any `alloc` subset
/// (`BoxedDeclSink` / `BoxedUndeclSink` are themselves `alloc`-gated).
#[cfg(feature = "alloc")]
impl RemoteSubscriberRegistry<BoxedDeclSink, BoxedUndeclSink> {
    /// New empty AP registry backed by heap-boxed closures. The inferring
    /// shorthand for
    /// [`with_sink_backing`](RemoteSubscriberRegistry::with_sink_backing):
    /// `RemoteSubscriberRegistry::new()` fixes `D = BoxedDeclSink` /
    /// `U = BoxedUndeclSink` so the closure-taking wrappers are in reach
    /// without a turbofish.
    pub fn new() -> Self {
        Self::with_sink_backing()
    }

    /// Install a closure fired on every inbound `Declare(DeclSubscriber)`
    /// whose keyexpr resolves through the peer keyexpr table. The closure
    /// receives `&dyn DeclView` (the peer-declared `id` + resolved
    /// keyexpr) — the R311gb-3d seam contract replaces the prior
    /// `(&DeclSubscriberOwned, &str)`; this is the
    /// [`feedback_signature_stability`] wire-data principled exemption.
    /// Duplicate callbacks are allowed; dispatch fires them in
    /// registration order. The closure is heap-boxed via [`BoxedDeclSink`].
    /// R311lb — returns the registry-local observer id (see
    /// [`RemoteSubscriberTable::remove_subscriber_declared_sink`]); existing callers that
    /// never remove may ignore it.
    ///
    /// GROWABLE BACKING ONLY: under `bounded-heapless` the observer list is
    /// fixed and the `.expect` inside would be a panic at the first full
    /// list, so this wrapper is not compiled there (except for this crate's
    /// own tests and docs). A fixed-backing build installs through
    /// [`RemoteSubscriberTable::on_subscriber_declared_sink`] and handles the `Err`.
    #[cfg(any(test, doc, not(feature = "bounded-heapless")))]
    pub fn on_subscriber_declared(
        &mut self,
        callback: impl FnMut(&dyn crate::decl_sink::DeclView) + Send + 'static,
    ) -> u64 {
        // AP backing: the observer `BoundedVec` grows past the advisory
        // `N`, so installing never fails here.
        self.on_subscriber_declared_sink(BoxedDeclSink::new(callback))
            .expect("observer install on the alloc backing never exceeds declared capacity")
    }

    /// Install a closure fired on every inbound
    /// `Declare(UndeclSubscriber)`. The closure receives the bare `id`
    /// (`u64`) — the undeclaration carries no keyexpr. Same registration-
    /// order + duplicates-allowed contract as
    /// [`Self::on_subscriber_declared`]. The closure is heap-boxed via
    /// [`BoxedUndeclSink`]. R311lb — returns the registry-local observer
    /// id (see [`RemoteSubscriberTable::remove_subscriber_undeclared_sink`]).
    ///
    /// GROWABLE BACKING ONLY, for the reason
    /// [`Self::on_subscriber_declared`] gives.
    #[cfg(any(test, doc, not(feature = "bounded-heapless")))]
    pub fn on_subscriber_undeclared(&mut self, callback: impl FnMut(u64) + Send + 'static) -> u64 {
        self.on_subscriber_undeclared_sink(BoxedUndeclSink::new(callback))
            .expect("observer install on the alloc backing never exceeds declared capacity")
    }
}

// R311gb (Track 2) — the behavioural tests exercise `dispatch_declare`
// (owned `DeclareOwnedVariant`) + `has_matching`, now
// `all(codec-declare, alloc)`-gated; the module un-gated from
// `codec-declare`, so the test gate is now explicit (was inherited).
#[cfg(all(test, feature = "codec-declare"))]
mod tests {
    //! R311ds — wider behavioural tests migrated here from the
    //! wz-runtime-tokio `declare/subscriber.rs` shell (R311dr-wider-tests
    //! carry closure). They exercise the callback fan-out value capture
    //! through `Arc<Mutex<Vec<…>>>`; the `Mutex` comes from `std` under
    //! `#[cfg(test)]` per the wz-codecs sibling-crate convention (see
    //! `crate` root `extern crate std`). Production stays no_std.

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

    #[test]
    fn empty_registry_dispatch_is_noop() {
        let mut reg = RemoteSubscriberRegistry::new();
        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(7, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(reg.on_decl_len(), 0);
        assert_eq!(reg.on_undecl_len(), 0);
    }

    #[test]
    fn declare_callback_fires_on_literal_keyexpr() {
        let mut reg = RemoteSubscriberRegistry::new();
        let captured: Arc<Mutex<Vec<(u64, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_subscriber_declared(move |decl| {
            captured_for_cb
                .lock()
                .unwrap()
                .push((decl.id(), decl.keyexpr().to_string()));
        });

        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(7, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0], (7, "home/temp".to_string()));
    }

    #[test]
    fn declare_callback_resolves_mapping_id_against_peer_table() {
        let mut reg = RemoteSubscriberRegistry::new();
        let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_subscriber_declared(move |decl| {
            captured_for_cb
                .lock()
                .unwrap()
                .push(decl.keyexpr().to_string());
        });

        let mut peer_table = HashMap::new();
        peer_table.insert(11u64, "sensors/temp".to_string());

        // mapping_id=11, no suffix -> table lookup -> "sensors/temp"
        let body = DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(1, 11, None));
        reg.dispatch_declare(&body, &peer_table);
        // mapping_id=11, suffix="/extra" -> concat
        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(2, 11, Some("/extra")));
        reg.dispatch_declare(&body, &peer_table);

        let captured = captured.lock().unwrap();
        assert_eq!(
            *captured,
            vec!["sensors/temp".to_string(), "sensors/temp/extra".to_string()]
        );
    }

    #[test]
    fn declare_callback_skipped_on_unresolvable_mapping_id() {
        let mut reg = RemoteSubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_for_cb = fired.clone();
        reg.on_subscriber_declared(move |_decl| {
            fired_for_cb.fetch_add(1, Ordering::SeqCst);
        });

        // mapping_id=99 not in (empty) peer table -> skip.
        let body = DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(1, 99, None));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "unresolvable mapping id must skip the callback (no partial keyexpr fire)"
        );
    }

    /// R311y740 (N37) — the own-space WITNESS for this plane.
    ///
    /// R311y739 wired both id spaces into the observer fan and proved the
    /// resolution end-to-end on the Push plane only; every other plane was
    /// *argued* correct from sharing `resolve_wireexpr_in` rather than
    /// measured. This is that measurement for the peer-DECLARE(Subscriber)
    /// plane, and it is not redundant with the shared-resolver tests: what it
    /// rules out is this registry reaching for the peer table by some other
    /// route, which no test of the resolver in isolation can see.
    ///
    /// R311y750 (carry N38) — the route this named, `SubscriberRegistry`'s bare
    /// `peer_keyexpr_table()`, is gone; the raw peer half is now reachable only
    /// through the pair. That narrows what this test has to watch for without
    /// retiring it: a registry can still read the peer half through
    /// `MappingSpaces::peer` after being handed both.
    ///
    /// THE DISCRIMINATOR is the collision: id 7 exists in BOTH spaces under
    /// different literals, so reading the wrong one is a confident WRONG
    /// keyexpr rather than a silent `None`. Both upstreams number their
    /// mappings from 1, so that is the realistic failure.
    #[test]
    fn an_own_space_alias_resolves_in_our_space_on_the_declare_subscriber_plane() {
        let mut reg = RemoteSubscriberRegistry::new();
        let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_subscriber_declared(move |decl| {
            captured_for_cb
                .lock()
                .unwrap()
                .push(decl.keyexpr().to_string());
        });

        let mut peer = HashMap::new();
        peer.insert(7u64, "theirs/sub".to_string());
        let mut own = HashMap::new();
        own.insert(7u64, "ours/sub".to_string());

        // M=0 (`WireexprNonlocal`) names OUR space.
        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber_nonlocal(1, 7, None));
        reg.dispatch_declare(&body, MappingSpaces::with_own(&peer, &own));

        assert_eq!(
            *captured.lock().unwrap(),
            vec!["ours/sub".to_string()],
            "an M=0 alias names OUR space; reading the peer's would have \
             resolved `theirs/sub`",
        );
    }

    /// ANTI-VACUITY twin of
    /// [`an_own_space_alias_resolves_in_our_space_on_the_declare_subscriber_plane`].
    /// With only the peer's space the SAME record resolves nothing, so the
    /// witness above is measuring the installed own space rather than any
    /// table happening to hold id 7.
    #[test]
    fn without_an_own_space_the_declare_subscriber_plane_refuses_the_same_alias() {
        let mut reg = RemoteSubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_for_cb = fired.clone();
        reg.on_subscriber_declared(move |_decl| {
            fired_for_cb.fetch_add(1, Ordering::SeqCst);
        });

        let mut peer = HashMap::new();
        peer.insert(7u64, "theirs/sub".to_string());

        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber_nonlocal(1, 7, None));
        reg.dispatch_declare(&body, &peer);

        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "with no own space an M=0 alias must refuse -- never fall back to \
             the peer's table",
        );
    }

    #[test]
    fn undeclare_callback_fires_on_undecl_subscriber() {
        let mut reg = RemoteSubscriberRegistry::new();
        let captured: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_subscriber_undeclared(move |id| {
            captured_for_cb.lock().unwrap().push(id);
        });

        let body = DeclareOwnedVariant::CodecZenohUndeclSubscriber(undecl_subscriber(42));
        reg.dispatch_declare(&body, &HashMap::new());

        let captured = captured.lock().unwrap();
        assert_eq!(*captured, vec![42]);
    }

    /// R311kh — matching listener flip-fires through the production
    /// dispatch: a matching DeclSubscriber flips false->true, the
    /// matching UndeclSubscriber flips back true->false, a NON-matching
    /// declare never fires, and registration itself is silent (pico
    /// transition-only semantics).
    #[cfg(feature = "session-matching")]
    #[test]
    fn matching_listener_flips_on_membership_mutation() {
        use crate::declare::matching::BoxedMatchingSink;

        let mut reg = RemoteSubscriberRegistry::new();
        let log: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
        let log_cb = log.clone();
        let id = reg.declare_matching_listener(
            "home/temp",
            BoxedMatchingSink::new(move |m| log_cb.lock().unwrap().push(m)),
        );
        assert_eq!(reg.matching_listener_len(), 1);
        assert!(log.lock().unwrap().is_empty(), "registration never fires");

        // Non-matching peer subscriber: membership changes, verdict does not.
        let body = DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(
            1,
            0,
            Some("garage/door"),
        ));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(
            log.lock().unwrap().is_empty(),
            "non-matching declare is silent"
        );

        // Matching peer subscriber (literal-literal byte-equal — no
        // wildcard feature dependency): false -> true fires once.
        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(2, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(*log.lock().unwrap(), vec![true]);

        // Its undeclare: true -> false fires once more.
        let body = DeclareOwnedVariant::CodecZenohUndeclSubscriber(undecl_subscriber(2));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(*log.lock().unwrap(), vec![true, false]);

        // After undeclare-listener, further mutations are silent.
        assert!(reg.undeclare_matching_listener(id));
        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(3, 0, Some("home/x")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(*log.lock().unwrap(), vec![true, false]);
    }

    /// R311y800 — the SUBSCRIBER-plane twin of
    /// `RemoteQueryableRegistry`'s `a_link_loss_drops_the_peers_declarations_
    /// and_flips_the_watch`, and it is new because that twin did not exist.
    ///
    /// R311y799 built `flush_declarations_on_link_loss` on BOTH planes and
    /// wrote "its two tests are registry-tier" — but both of those tests are
    /// on the QUERYABLE registry. This plane had none, and the gap was
    /// MEASURED rather than noticed: deleting the `reevaluate` call from this
    /// file's flush leaves all 527 tests of `cargo test -p wz-session-core
    /// --features session-matching,declare-subscriber,declare-queryable,
    /// query-queryable,codec-declare` GREEN. Only the e2e gate reds.
    ///
    /// The `matching=false` fire is the discriminator, not the emptied table:
    /// a flush that cleared the map without re-evaluating would leave every
    /// listener believing it still matched, which is the exact failure the
    /// surviving table produced.
    #[cfg(feature = "session-matching")]
    #[test]
    fn a_link_loss_drops_the_peers_subscribers_and_flips_the_watch() {
        use crate::declare::matching::BoxedMatchingSink;

        let log: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
        let log_cb = log.clone();
        let mut reg = RemoteSubscriberRegistry::new();
        reg.declare_matching_listener(
            "home/temp",
            BoxedMatchingSink::new(move |m| log_cb.lock().unwrap().push(m)),
        );

        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(1, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(*log.lock().unwrap(), vec![true], "the peer raised it");
        assert_eq!(reg.declared_count(), 1);

        assert_eq!(
            reg.flush_declarations_on_link_loss(&|_| false),
            1,
            "the one declaration the dead link had made is dropped"
        );
        assert_eq!(reg.declared_count(), 0);
        assert_eq!(
            *log.lock().unwrap(),
            vec![true, false],
            "and the watch follows it down — the emptied table alone would \
             leave every listener believing it still matched"
        );
    }

    /// The local half survives the link, so a watch a session-local
    /// subscriber is holding must NOT be flipped by a remote link dying.
    /// Same fixture as above, one predicate apart — the pair is what proves
    /// the flush consults the local half rather than flipping everything.
    #[cfg(feature = "session-matching")]
    #[test]
    fn a_link_loss_does_not_flip_a_watch_a_local_subscriber_holds() {
        use crate::declare::matching::BoxedMatchingSink;

        let log: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
        let log_cb = log.clone();
        let mut reg = RemoteSubscriberRegistry::new();
        reg.declare_matching_listener_seeded(
            PublisherCriterion::any_locality("home/temp"),
            /*local_matching=*/ true,
            BoxedMatchingSink::new(move |m| log_cb.lock().unwrap().push(m)),
        );
        assert_eq!(*log.lock().unwrap(), vec![true]);

        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(1, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(reg.flush_declarations_on_link_loss(&|_| true), 1);
        assert_eq!(
            *log.lock().unwrap(),
            vec![true],
            "the local subscriber still receives, so the link loss flips nothing"
        );
    }

    #[test]
    fn multiple_decl_callbacks_fire_in_registration_order() {
        let mut reg = RemoteSubscriberRegistry::new();
        let order: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let order_a = order.clone();
        let order_b = order.clone();
        reg.on_subscriber_declared(move |_d| order_a.lock().unwrap().push(1));
        reg.on_subscriber_declared(move |_d| order_b.lock().unwrap().push(2));
        assert_eq!(reg.on_decl_len(), 2);

        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(3, 0, Some("a/b")));
        reg.dispatch_declare(&body, &HashMap::new());

        assert_eq!(*order.lock().unwrap(), vec![1, 2]);
    }

    #[test]
    fn nonlocal_keyexpr_arm_resolves_identically_to_local_arm() {
        let mut reg = RemoteSubscriberRegistry::new();
        let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_subscriber_declared(move |d| {
            captured_for_cb
                .lock()
                .unwrap()
                .push(d.keyexpr().to_string())
        });

        let body = DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber_nonlocal(
            9,
            0,
            Some("zone/1"),
        ));
        reg.dispatch_declare(&body, &HashMap::new());

        let captured = captured.lock().unwrap();
        assert_eq!(*captured, vec!["zone/1".to_string()]);
    }

    #[test]
    fn other_declare_arms_are_silently_dropped_here() {
        let mut reg = RemoteSubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_for_cb = fired.clone();
        reg.on_subscriber_declared(move |_d| {
            fired_for_cb.fetch_add(1, Ordering::SeqCst);
        });

        // A DeclFinal envelope must not fire the subscriber callback
        // — it lives in the SubscriberRegistry's path (DeclKexpr /
        // UndeclKexpr) or the future RemoteQueryableRegistry path
        // (DeclQueryable).
        let body = DeclareOwnedVariant::CodecZenohDeclFinal(
            wz_codecs::decl_final::DeclFinal::default()
                .try_into_owned()
                .expect("DeclFinal::default owns no borrowed data"),
        );
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "Subscriber callback must not fire on DeclFinal body"
        );
    }

    #[test]
    fn dispatch_messages_routes_only_declare_variants() {
        let mut reg = RemoteSubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_cb = counter.clone();
        reg.on_subscriber_declared(move |_d| {
            counter_for_cb.fetch_add(1, Ordering::SeqCst);
        });

        let messages =
            vec![
                NetworkMessage::Declare(Box::new(declare_envelope_decl_subscriber(
                    decl_subscriber(1, 0, Some("home/a")),
                ))),
                NetworkMessage::Declare(Box::new(declare_envelope_decl_subscriber(
                    decl_subscriber(2, 0, Some("home/b")),
                ))),
            ];
        reg.dispatch_messages(&messages, &HashMap::new());
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn dispatch_messages_undecl_and_decl_route_independently() {
        let mut reg = RemoteSubscriberRegistry::new();
        let decl_count = Arc::new(AtomicUsize::new(0));
        let undecl_count = Arc::new(AtomicUsize::new(0));
        let d = decl_count.clone();
        let u = undecl_count.clone();
        reg.on_subscriber_declared(move |_d| {
            d.fetch_add(1, Ordering::SeqCst);
        });
        reg.on_subscriber_undeclared(move |_u| {
            u.fetch_add(1, Ordering::SeqCst);
        });

        let messages =
            vec![
                NetworkMessage::Declare(Box::new(declare_envelope_decl_subscriber(
                    decl_subscriber(1, 0, Some("a")),
                ))),
                NetworkMessage::Declare(Box::new(declare_envelope_undecl_subscriber(
                    undecl_subscriber(1),
                ))),
                NetworkMessage::Declare(Box::new(declare_envelope_decl_subscriber(
                    decl_subscriber(2, 0, Some("b")),
                ))),
            ];
        reg.dispatch_messages(&messages, &HashMap::new());
        assert_eq!(decl_count.load(Ordering::SeqCst), 2);
        assert_eq!(undecl_count.load(Ordering::SeqCst), 1);
    }

    /// A sender may read an absent subscriber as no subscriber only after the peer has ended
    /// its first declarations, and only the `DeclareFinal` of the INITIAL interest does that:
    /// another interest's final answers some other question, and an unsolicited one ends
    /// nothing.
    #[cfg(feature = "declare-final")]
    #[test]
    fn only_the_initial_interests_final_ends_the_peers_first_declarations() {
        use crate::declare_build::{build_declare_final, build_declare_final_reply};
        let mut reg = RemoteSubscriberRegistry::new();
        assert!(!reg.peer().initial_declarations_final());

        let others =
            vec![
                NetworkMessage::Declare(Box::new(build_declare_final_reply(7))),
                NetworkMessage::Declare(Box::new(build_declare_final())),
                NetworkMessage::Declare(Box::new(declare_envelope_decl_subscriber(
                    decl_subscriber(1, 0, Some("a")),
                ))),
            ];
        reg.dispatch_messages(&others, &HashMap::new());
        assert!(
            !reg.peer().initial_declarations_final(),
            "a final of another interest, an unsolicited one and a declaration end nothing"
        );

        let initial = vec![NetworkMessage::Declare(Box::new(
            build_declare_final_reply(crate::extbound::INITIAL_INTEREST_ID),
        ))];
        reg.dispatch_messages(&initial, &HashMap::new());
        assert!(reg.peer().initial_declarations_final());

        // The peer's link was lost: it declares again from the start, and ends it again.
        reg.flush_declarations_on_link_loss(&|_| false);
        assert!(!reg.peer().initial_declarations_final());
    }

    // ── R290 declared / has_matching membership surface ──

    #[test]
    fn subscriber_declared_count_starts_at_zero_and_tracks_decl_undecl_lifecycle() {
        let mut reg = RemoteSubscriberRegistry::new();
        assert_eq!(reg.declared_count(), 0);

        let decl1 = DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(
            10,
            0,
            Some("home/temp"),
        ));
        reg.dispatch_declare(&decl1, &HashMap::new());
        assert_eq!(reg.declared_count(), 1);

        let decl2 = DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(
            11,
            0,
            Some("home/door"),
        ));
        reg.dispatch_declare(&decl2, &HashMap::new());
        assert_eq!(reg.declared_count(), 2);

        let undecl1 = DeclareOwnedVariant::CodecZenohUndeclSubscriber(undecl_subscriber(10));
        reg.dispatch_declare(&undecl1, &HashMap::new());
        assert_eq!(reg.declared_count(), 1);
        let remaining: Vec<(u64, &str)> = reg.iter_declared().collect();
        assert_eq!(remaining, vec![(11, "home/door")]);

        let undecl2 = DeclareOwnedVariant::CodecZenohUndeclSubscriber(undecl_subscriber(11));
        reg.dispatch_declare(&undecl2, &HashMap::new());
        assert_eq!(reg.declared_count(), 0);
    }

    /// The counter a reader without the lock keeps its answers by moves after EVERY change
    /// to what the peer has declared (a declaration, a replacement under the same id, an
    /// undeclaration, the whole table forgotten) and stands still when nothing changed: an
    /// undeclaration of an id nobody declared still moves it (a missed move would keep a
    /// stale answer, an extra one only costs a recomputation), and reading does not.
    #[cfg(all(
        feature = "storage-profile",
        feature = "alloc",
        not(feature = "bounded-heapless"),
        target_has_atomic = "64"
    ))]
    #[test]
    fn the_peers_declaration_counter_moves_after_every_change_and_only_then() {
        use core::sync::atomic::Ordering::Acquire;
        let mut reg = RemoteSubscriberRegistry::new();
        let counter = reg.peer().epoch();
        let at = |c: &crate::declare::DeclEpoch| c.load(Acquire);
        let start = at(&counter);

        let _ = reg.has_matching("home/temp");
        let _ = reg.declared_count();
        assert_eq!(at(&counter), start, "reading moves nothing");

        let declare = |id, key: &str| {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(id, 0, Some(key)))
        };
        reg.dispatch_declare(&declare(1, "home/temp"), &HashMap::new());
        let after_declare = at(&counter);
        assert!(after_declare > start, "a declaration moves it");

        reg.dispatch_declare(&declare(1, "home/door"), &HashMap::new());
        let after_replace = at(&counter);
        assert!(
            after_replace > after_declare,
            "a replacement under the same id moves it"
        );

        reg.dispatch_declare(
            &DeclareOwnedVariant::CodecZenohUndeclSubscriber(undecl_subscriber(1)),
            &HashMap::new(),
        );
        let after_undeclare = at(&counter);
        assert!(after_undeclare > after_replace, "an undeclaration moves it");

        reg.dispatch_declare(&declare(2, "home/a"), &HashMap::new());
        let before_forget = at(&counter);
        // `forget` is the peer's own (a link loss).
        let mut peer = RemoteSubscriberPeer::new();
        let other = peer.epoch();
        assert_eq!(other.load(Acquire), 0, "a new peer starts at zero");
        assert_eq!(peer.forget(), 0);
        assert!(other.load(Acquire) > 0, "forgetting the table moves it");
        assert_eq!(
            at(&counter),
            before_forget,
            "and a peer's counter is its own"
        );
    }

    #[test]
    fn subscriber_has_matching_false_on_empty_registry() {
        let reg = RemoteSubscriberRegistry::new();
        assert!(!reg.has_matching("home/temp"));
        assert!(!reg.has_matching("anything"));
    }

    #[test]
    fn subscriber_has_matching_true_on_literal_keyexpr_equality() {
        let mut reg = RemoteSubscriberRegistry::new();
        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(7, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/temp"));
        assert!(!reg.has_matching("home/door"));
    }

    #[test]
    fn subscriber_has_matching_true_when_peer_pattern_covers_publish_literal() {
        let mut reg = RemoteSubscriberRegistry::new();
        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(8, 0, Some("home/**")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/temp"));
        assert!(reg.has_matching("home/door/inner"));
        assert!(!reg.has_matching("other/x"));
    }

    #[test]
    fn subscriber_has_matching_false_on_a_malformed_published_key() {
        // The LOCAL delivery membership check (zenoh compute_data_route parity):
        // a `home/**` subscriber must NOT match a malformed published key (an
        // empty `/`-delimited chunk). This is the local-delivery twin of the
        // mesh-forward drop — both route through the matcher's
        // `target_chunks_well_formed` invariant, so a stray `home/temp/` /
        // `home//temp` / `/home/temp` / `""` reaches no subscriber on any path.
        let mut reg = RemoteSubscriberRegistry::new();
        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(13, 0, Some("home/**")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/temp"), "well-formed key matches");
        for malformed in ["home/temp/", "home//temp", "/home/temp", ""] {
            assert!(
                !reg.has_matching(malformed),
                "`home/**` must not match malformed `{malformed}`"
            );
        }
    }

    #[test]
    fn subscriber_has_matching_true_when_publish_pattern_covers_peer_literal() {
        let mut reg = RemoteSubscriberRegistry::new();
        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(9, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/**"));
        assert!(reg.has_matching("**"));
        assert!(!reg.has_matching("other/**"));
    }

    #[test]
    fn subscriber_has_matching_false_after_undeclare() {
        let mut reg = RemoteSubscriberRegistry::new();
        let decl = DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(
            12,
            0,
            Some("home/temp"),
        ));
        reg.dispatch_declare(&decl, &HashMap::new());
        assert!(reg.has_matching("home/temp"));
        let undecl = DeclareOwnedVariant::CodecZenohUndeclSubscriber(undecl_subscriber(12));
        reg.dispatch_declare(&undecl, &HashMap::new());
        assert!(!reg.has_matching("home/temp"));
    }

    // ── R293 — honest two-pattern overlap (Pub-side mirror) ──

    #[test]
    fn subscriber_has_matching_true_when_two_patterns_share_literal_via_mid_star() {
        // Pub-side mirror of the Q-side test
        // `queryable_has_matching_true_when_two_patterns_share_literal_via_mid_star`.
        // `home/*/temp` peer subscriber + `*/sensor/temp` publish
        // keyexpr share `home/sensor/temp` — pre-R293 the matcher
        // missed this; R293 honest intersection fires.
        let mut reg = RemoteSubscriberRegistry::new();
        let d = DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(
            30,
            0,
            Some("home/*/temp"),
        ));
        reg.dispatch_declare(&d, &HashMap::new());
        assert!(reg.has_matching("*/sensor/temp"));
        assert!(reg.has_matching("*/*/temp"));
    }

    #[test]
    fn subscriber_has_matching_false_when_two_patterns_have_disjoint_anchors() {
        // Pub-side mirror of the Q-side disjoint-anchor negative test.
        let mut reg = RemoteSubscriberRegistry::new();
        let d = DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(
            31,
            0,
            Some("home/**/temp"),
        ));
        reg.dispatch_declare(&d, &HashMap::new());
        assert!(!reg.has_matching("kitchen/**/temp"));
    }

    #[test]
    fn subscriber_has_matching_true_when_double_star_intersects_either_direction() {
        // Pub-side mirror — `home/** ∩ **/temp` shares `home/temp`
        // and any `home/<x>.../temp`. Backtracking on both sides.
        let mut reg = RemoteSubscriberRegistry::new();
        let d =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(32, 0, Some("home/**")));
        reg.dispatch_declare(&d, &HashMap::new());
        assert!(reg.has_matching("**/temp"));
        assert!(reg.has_matching("**"));
    }
}
