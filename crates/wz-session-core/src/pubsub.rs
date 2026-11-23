// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Application-layer subscriber registry — routes decoded
//! `NetworkMessage::Push` records to user-registered callbacks
//! filtered by keyexpr literal.
//!
//! ## Scope (R98 + R99 + R100 — AP MVP critical path)
//!
//! - Push messages only. R90 landed Push decoding; R98 wires the
//!   FramePayload → subscriber → callback path so an application can
//!   actually observe pub/sub data over a session; R99 added the
//!   `dispatch_iteration_event` adapter so the registry plugs into
//!   `drive_session_until_terminal` as an observer.
//! - Keyexpr matching follows zenoh-spec chunk wildcards (R100,
//!   R220): chunks are split on `/`, `*` matches exactly one chunk,
//!   `**` matches zero or more chunks (including the empty
//!   sequence), and `$*` is the intra-chunk substring wildcard
//!   (R220) — a pattern chunk like `prefix$*suffix` matches any
//!   target chunk that starts with `prefix` and ends with `suffix`
//!   (with arbitrary intra-chunk content between). Multiple `$*` in
//!   a chunk anchor non-overlapping sub-parts in order, mirroring
//!   zenoh-pico's `_z_chunk_right_contains_all_stardsl_subchunks_of_left`.
//!   `$*` never crosses chunk boundaries — target chunks are split on
//!   `/` first, so intra-chunk DSL is bounded by the same `/`
//!   separators as the pattern. Literal chunks (no DSL token)
//!   continue to compare byte-for-byte.
//!   Pushes whose `keyexpr.id == 0` and `keyexpr.suffix == Some(s)`
//!   match against the pattern's wildcard expansion. R121d
//!   landed the DECLARE-table resolver, so pushes whose
//!   `keyexpr.id != 0` are resolved against the peer's locally-
//!   declared mapping table (populated by inbound
//!   `Declare(DeclKexpr)` records, removed by `Declare(UndeclKexpr)`).
//!   The resolved keyexpr is `table[id] + push.suffix.unwrap_or("")`
//!   per Zenoh's mapping-id + optional inline suffix composition.
//! - Reply / Err / Interest / OAM dispatch are NOT routed through
//!   the registry. They land in a future round once a use case
//!   surfaces — pub/sub demo is sufficient for the AP MVP.
//! - R227 — self-publish loopback. An in-process publisher can hand
//!   a [`Sample`] to `SubscriberRegistry::local_publish`; the
//!   registry walks the same locality + pattern-match dispatch that
//!   wire-arrived Pushes go through, just with `is_remote = false`
//!   so the locality predicate selects `allows_local()`. Subscribers
//!   pinned to [`crate::locality::Locality::SessionLocal`] now fire
//!   (they were dormant before R227), while subscribers pinned to
//!   [`crate::locality::Locality::Remote`] are suppressed; the
//!   [`crate::locality::Locality::Any`] default fires on both
//!   origins. Mirrors zenoh-pico's `_z_session_deliver_push_locally`
//!   (`vendor/zenoh-pico/src/session/loopback.c` 70-100) routed
//!   from `_z_write` (`vendor/zenoh-pico/src/net/primitives.c`
//!   198-202) when the publisher's
//!   `allowed_destination.allows_local()` holds.
//!
//! ## Threading
//!
//! Registry is `!Sync` by design. Callers that need shared mutation
//! across tasks wrap the registry in `Arc<Mutex<SubscriberRegistry>>`
//! (or `tokio::sync::Mutex` for await-safe locking). Keeping the
//! registry single-owner avoids paying mutex overhead on the hot
//! dispatch path when no sharing is needed.
//!
//! ## Sample-delivery seam (R311gb-2b — model B)
//!
//! The registry is generic over `C: SampleSink` (the [`crate::sink`]
//! Dependency-Inversion seam) rather than storing a hard-coded
//! `Box<dyn FnMut>`, so one registry implementation backs both
//! profiles (ARCHITECTURE.md §2.4 static-first, dynamic-opt-in):
//!
//! - **AP / `alloc` on** — `C = BoxedSink` (the default type param):
//!   [`register`](SubscriberRegistry::register) wraps an arbitrary
//!   capturing closure in a heap `Box`, type-erasing differently-
//!   captured closures behind a homogeneous sink list (the dynamic-
//!   opt-in side). The closure receives `&dyn SampleView` — the
//!   accessor contract, a borrowed fat pointer with no heap and no
//!   copy — so it inspects the resolved keyexpr / kind / payload /
//!   reliability without taking ownership.
//! - **MCU / `alloc` off** — the consumer supplies a closed `enum`
//!   that impls [`SampleSink`] with no heap, registered through the
//!   generic [`register_sink`](SubscriberRegistry::register_sink).
//!
//! Dispatch passes the projected owned [`Sample`] directly as
//! `&dyn SampleView` (`Sample: SampleView`), so there is no
//! intermediate projection step. `BoxedSink` is `Send`; callers that
//! need cross-task sharing wrap the registry in `Arc<Mutex<…>>` as
//! before.

#[cfg(feature = "alloc")]
use alloc::string::String;
// R311y308 — `Vec` is NOT imported at module scope. Its production uses in
// `dispatch_push` are fully qualified (`alloc::vec::Vec`, the form already
// used by `own_zid` / `set_own_zid` below), because a module-scope import
// would have to be gated on *which cfg arm happens to NAME the type* — the
// `not(pubsub-attachment)` annotations name it, while the ON arm's
// `.map(<[u8]>::to_vec)` does not, and only the `pubsub-delete` arm names
// `Vec::new()`. The pre-y308 gate `any(pubsub-put, pubsub-delete)` encoded
// that coupling WRONG (its comment claimed the opposite of the truth) and
// broke `alloc + pubsub-put + pubsub-attachment` with an unused import —
// a subset no lane built until Layer C1bj. Fully qualifying removes the
// coupling rather than restating it in a longer cfg.

use crate::bounded::{
    Arena, BoundedString, BoundedVec, KeyMaker, KeyUnkept, LendRefused, Lent, Profile, Storage,
};
use crate::key_arena::{KeySpace, LentKeys};
// The fixed own-zid row of a peer's naming is its one reader.
#[cfg(feature = "storage-profile")]
use crate::bounded::Static;
// Not every build reads a held chain here: the arms that do are gated on the body codecs.
use crate::caps;
#[cfg(feature = "storage-profile")]
#[allow(unused_imports)]
use crate::held_list::HeldList;
#[cfg(all(feature = "storage-profile", feature = "codec-declare"))]
use crate::id_map::key_text_within;
#[cfg(feature = "storage-profile")]
use crate::id_map::{IdMap, PeerAliases};
use crate::key_gate::{Admitted, ClassId, EntityId, EntityKind, KeyGate, KeyId, PeerOp, Refused};
#[cfg(feature = "key-set-closed")]
use crate::keyexpr_match::keyexpr_intersects_text;
use crate::keyexpr_match::{keyexpr_intersects_text_with, KeyFacts, MAX_KEYEXPR_CHUNKS};
use crate::registry_error::RegisterError;
#[cfg(feature = "declare-subscriber")]
use crate::row_pool::RowList;

// R311gb (Track 2) — `resolve_wireexpr` lives in the `alloc`-gated
// `wireexpr_resolve` module and is reached only from the `alloc`
// wire-dispatch paths, so the import carries `alloc` in addition to the codec
// markers (else `codec-declare` without `alloc` pulls an absent module).
//
// S9a — the owned Push dispatch is the one consumer left that wants a `String`
// (it builds an owned `Sample` around it). The interest path and the alias
// absorb resolve into a bounded buffer instead (`resolve_wireexpr_into`,
// `resolve_declared_keyexpr_into`), which is what lets them run on the fixed
// backing without the heap.
#[cfg(all(
    feature = "alloc",
    any(feature = "pubsub-put", feature = "pubsub-delete")
))]
use crate::wireexpr_resolve::resolve_wireexpr_in;
#[cfg(all(feature = "alloc", feature = "declare-subscriber"))]
use crate::wireexpr_resolve::resolve_wireexpr_into;
// R2385 — the DECLARED keyexpr's own scope has a rule of its own (the D_KEXPR
// header has no mapping bit), and `absorb_declare` is its only caller here, so
// this import carries that arm's gate rather than the wider `any(..)` above.
#[cfg(all(feature = "alloc", feature = "codec-declare"))]
use crate::wireexpr_resolve::resolve_declared_keyexpr_into;
#[cfg(all(feature = "storage-profile", feature = "codec-declare"))]
use crate::wireexpr_resolve::KeyexprBuf;
// R311y739 — the two-space PAIR is `alloc`-gated only: the `own_mapping_space`
// field and the `mapping_spaces()` accessor exist in every `alloc` profile,
// including one with no wire-dispatch consumer compiled in, whereas the
// resolver call above is reached only from those consumers.
#[cfg(feature = "storage-profile")]
// R311y740 — `OwnMappingSpace` itself is no longer NAMED by this module: the
// field and its setter go through the per-profile `SharedOwnMappingSpace`
// alias, which spells the `dyn` type per target. It survives only in doc links
// here, and those are fully qualified (an import kept alive by doc links alone
// is an `unused_imports` error under this workspace's `-D warnings`, and the
// subset lanes are where that surfaces).
use crate::wireexpr_resolve::MappingSpaces;
// The handle on the session's own id space is a reference-counted pointer, the heap
// profile's. A session in a slot installs none (its own space is read through the
// slot's handle, which the registry does not take yet), and reads `M=0` aliases as
// the relay face does.
#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use crate::transport_profile::owned::DeclareOwnedVariant;
#[cfg(feature = "alloc")]
use crate::wireexpr_resolve::SharedOwnMappingSpace;
// R311gb (Track 2) — these wire-dispatch-supporting imports feed the
// `alloc`-gated `dispatch_push` (owned `PushOwned` / `Sample` building),
// and `crate::sample` / the owned codec types are `alloc`-gated, so each
// carries `alloc` in addition to its pub/sub feature gate. Without it a
// `codec-push`-without-`alloc` profile pulls an absent module / leaves an
// unused import (mirror of the sibling codecs, which compose no-alloc).
#[cfg(all(
    feature = "alloc",
    any(feature = "pubsub-put", feature = "pubsub-delete")
))]
use crate::wire::{PushOwned, PushOwnedVariant};

#[cfg(all(
    feature = "alloc",
    any(feature = "pubsub-put", feature = "pubsub-delete"),
    feature = "pubsub-attachment"
))]
use crate::attachment::{decode_attachment_ext_shared, ATTACHMENT_EXT_ID_PUSH};
#[cfg(feature = "alloc")]
use crate::driver_loop::DriverLoopOutcome;
#[cfg(feature = "storage-profile")]
use crate::driver_loop::IterationEvent;
#[cfg(feature = "alloc")]
use crate::network_message::NetworkMessage;
// R311y530 — the inbound SUBSCRIBER-Interest parse (`declare-subscriber`), the
// session-local half of zenoh's `remote-interests` table.
#[cfg(all(
    feature = "alloc",
    any(feature = "pubsub-put", feature = "pubsub-delete"),
    feature = "pubsub-qos"
))]
use crate::sample::extract_qos;
#[cfg(all(
    feature = "alloc",
    any(feature = "pubsub-put", feature = "pubsub-delete"),
    feature = "pubsub-source-info"
))]
use crate::sample::extract_source_info;
#[cfg(all(feature = "pubsub-put", feature = "alloc"))]
use crate::sample::EncodingHint;
#[cfg(feature = "alloc")]
use crate::sample::Reliability;
#[cfg(feature = "alloc")]
use crate::sample::Sample;
#[cfg(all(
    feature = "alloc",
    any(feature = "pubsub-put", feature = "pubsub-delete")
))]
use crate::sample::{SampleKind, TimestampHint};
use crate::sink::{SampleSink, SampleView};
#[cfg(all(feature = "alloc", feature = "declare-subscriber"))]
use crate::transport_profile::owned::InterestOwned;
// R311gb-2b — `BoxedSink` is the default sink type (the AP closure
// adapter); only needed by the `alloc`-gated `register` /
// `register_with_locality` convenience wrappers. The whole `pubsub`
// module is `alloc`-gated, but the import is scoped to the `alloc`
// feature for symmetry with `sink::BoxedSink`'s own gate.
#[cfg(feature = "alloc")]
use crate::sink::BoxedSink;

/// Stable handle returned by `register` so the caller can later
/// unregister the subscriber without holding a string-typed key
/// (subscriber tables with duplicate keyexpr filters are explicitly
/// allowed — e.g. a metrics callback AND a domain callback on the
/// same topic).
///
/// The id is also the `DeclSubscriber.id` the session announces the
/// subscription under, so it is a `u32`, the width of upstream's
/// `EntityId` (`commons/zenoh-protocol/src/network/declare.rs` @
/// `pub type SubscriberId = EntityId;`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriptionId(u32);

impl SubscriptionId {
    /// The declaration id the subscription is announced under on the wire.
    /// The registry assigns ids in order from one session-local counter, so
    /// the value is not stable across runs.
    pub fn entity_id(self) -> u32 {
        self.0
    }

    /// [`entity_id`](Self::entity_id), widened for the callers that carry a
    /// declaration id as the wire's z64.
    pub fn as_u64(self) -> u64 {
        u64::from(self.0)
    }
}

struct Subscriber<C: SampleSink, P: Storage = Profile> {
    id: SubscriptionId,
    /// R311gb (Track 2) — the canonical keyexpr pattern, kept as the policy keeps a row's key
    /// ([`Storage::Key`]): a buffer inline in the row on the static policy, a block of the
    /// session's key arena on the lent one. Matching reads it as text at dispatch time rather
    /// than keeping a pre-split owned `Vec<String>`. A pattern with an empty chunk (like
    /// `a//b`) is stored as written and matches nothing; `*` / `**` are single-char chunks;
    /// matching is performed by [`keyexpr_intersects`].
    pattern: P::Key,
    /// What [`KeyFacts`] reads of `pattern`, read once at registration so that a message
    /// matched against it does not scan the pattern again.
    pattern_facts: KeyFacts,
    /// R223 — locality filter applied before the sink fires.
    /// See [`crate::locality`] for the semantics and the wz
    /// dispatch invariant (every inbound Push is treated as remote
    /// until self-publish loopback lands in a future round).
    allowed_origin: crate::locality::Locality,
    /// The subscriber entity the image declares on this pattern, when the table has a closed key
    /// set: a message is then delivered by the selection of its key and this number, with no
    /// text compared. `None` for an open table, and for a row made before the table was given
    /// its key set that the set does not declare; such a row is matched by its pattern as
    /// before (`fire_by_selection`).
    entity: Option<EntityId>,
    /// R311gb-2b — the delivery sink (DIP seam). `C = BoxedSink` on AP
    /// (heap closure), a consumer-supplied closed `enum` on MCU.
    sink: C,
}

/// The keyexpr glob and intersection matchers live in
/// [`crate::keyexpr_match`]; re-exported here because callers in other
/// crates reach them as `wz_session_core::pubsub::keyexpr_matches` /
/// `wz_session_core::pubsub::keyexpr_intersects`.
pub use crate::keyexpr_match::{keyexpr_intersects, keyexpr_matches};

/// The application-written half of the subscriber registry: the local
/// subscriptions, the counter that numbers them, and what only the application
/// configures. What a PEER writes (its keyexpr aliases, its interests, what is
/// staged back to it) is [`SubscriberPeer`], which this never holds.
///
/// Fixed-memory step S9a split the registry along that line. A registry that the
/// application fills once and every session reads is ONE per process, while the
/// peer's side is per SESSION: a keyexpr alias id, an interest id are scoped by
/// the transport session they came in on, so two peers' ids collide in a shared
/// table, and one peer filling it starves the other. The AP keeps exactly the
/// registry it had, [`SubscriberRegistry`], which is this plus ONE peer side;
/// `session-slot` has the process hold this alone and each session slot hold its
/// own [`SubscriberPeer`] (the `peer_tables` module).
///
/// See module-level docs for scope (Push + DECLARE resolver, R121d).
/// `!Sync` by construction (no shared mutable state); callers that
/// need cross-task sharing wrap in `Arc<Mutex<…>>`.
pub struct SubscriberTable<C: SampleSink, P: Storage = Profile> {
    subscribers: BoundedVec<Subscriber<C, P>, { caps::MAX_SUBSCRIPTIONS }, P>,
    /// The most subscriptions the table admits (`MAX_SUBSCRIPTIONS`): what the creator of the
    /// table resolved ([`Self::limit_to`]), the build's value until it does. A growable table
    /// refuses nothing by its storage, so this is what bounds it; where the build fixes the
    /// bound to the storage's capacity it is held in no byte and the storage refuses alone.
    quota: crate::limits::MaxSubscriptionsHeld,
    /// The longest key the table stores (`MAX_KEYEXPR_BYTES`), a subscription's pattern or the
    /// keyexpr of a peer's interest: what the creator of the table resolved
    /// ([`Self::limit_keys_to`]), the build's value until it does. Where the build fixes the
    /// bound to the rows' capacity it is held in no byte and the rows refuse alone.
    key_quota: crate::limits::MaxKeyexprBytesHeld,
    /// The most interests one peer's side remembers (`MAX_INBOUND_SUB_INTERESTS`), applied to
    /// every [`SubscriberPeer`] this table answers: what the creator of the table resolved
    /// ([`Self::limit_interests_to`]), the build's value until it does. Held here and not on the
    /// peer's side because the table is what every session's interests are answered through,
    /// and the creator that resolves the limits creates the table.
    #[cfg(feature = "declare-subscriber")]
    interest_quota: crate::limits::MaxInboundSubInterestsHeld,
    /// The most items one peer's side stages between two drains (`MAX_PENDING_DECLARES`),
    /// applied as the interest quota above is ([`Self::limit_interest_replies_to`]).
    #[cfg(feature = "declare-subscriber")]
    reply_quota: crate::limits::MaxPendingDeclaresHeld,
    /// The declaration id the next subscription or aggregate reply takes. It
    /// starts at 1, as upstream's counter does (0 is the routing core's), and
    /// it is a `u64` only so that it can stand one past `u32::MAX`, which is
    /// how the table knows every id has been handed out (`next_entity_id`).
    next_id: u64,
    /// How many times a subscription was registered or retired since this was
    /// built. A session that stages announcements from the subscription table
    /// ([`SubscriberPeer::reconcile`]) compares it with the epoch it last saw, so
    /// it learns that the table moved without the table having to know the
    /// session: that is what lets one table serve many peers.
    epoch: u64,
    /// How many subscribers a publish from this process can reach (those whose locality
    /// allows a local origin), readable without the lock that guards this table. A publisher
    /// asks whether anything in its own process wants a message once per message, and the
    /// answer is almost always "no subscriber at all"; this lets it be given by a load
    /// ([`Self::local_live`]) instead of a lock. Moved only where the list moves
    /// (`register_sink`, `unregister`), under the table's own lock. Absent on a target without
    /// pointer-width atomics, which has no second thread to read it.
    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    local_live: alloc::sync::Arc<core::sync::atomic::AtomicUsize>,
    /// Which subscribers the keys that arrived lately matched, so that a key that comes
    /// again is delivered without matching it against every subscription's pattern.
    /// Valid for one `epoch`: a subscription registered or retired moves it,
    /// and an entry from an earlier one is not read. See `MatchMemo`.
    memo: MatchMemo<P>,
    /// Which keys a message from a peer may be on: open takes every key, closed takes the keys of
    /// the image's key set and drops the rest, counted by reason. Starts as the build's
    /// `key-set` policy ([`KeyGate::of_build`]); see [`Self::set_key_gate`].
    key_gate: KeyGate<'static>,
    /// Where the subscriptions keep their patterns ([`Storage::Keys`]): the session's key arena
    /// on the lent policy ([`Self::lent`]). A pattern with no room there is refused as a full
    /// table refuses the subscription ([`RegisterError::TableFull`]).
    keys: P::Keys,
    /// transport-shm — the receive side of shared memory for a push: the negotiated
    /// capability, the AP-injected resolver, the means of acknowledging the peer's
    /// slices, the drop counters, and the un-swap itself. R3042 moved all of it into
    /// one [`ShmReceiveState`](crate::extshm::ShmReceiveState) that the reply
    /// registry holds a twin of, because upstream un-swaps every message that
    /// carries a payload and wz did it for a push alone. The setters below keep
    /// their signatures and forward to it, so the ~110 registry construction sites
    /// are unchanged and `ApplicationLayerObserver` stays `Send`.
    #[cfg(feature = "transport-shm")]
    shm: crate::extshm::ShmReceiveState,
    /// The Puts the in-place receive path could not deliver lent and delivered
    /// through the owned projection instead, by why; see [`InPlaceFallbacks`].
    #[cfg(all(
        feature = "storage-profile",
        any(feature = "pubsub-put", feature = "pubsub-delete")
    ))]
    in_place_fallbacks: InPlaceFallbacks,
}

/// What a PEER writes into the subscriber registry, and what is staged back to it:
/// one session's side of it.
///
/// Every field is scoped by the transport session it belongs to, which is why it
/// is not part of [`SubscriberTable`]: the alias ids and interest ids a peer names
/// mean nothing in another session, and what is staged is owed to THIS peer only.
/// The fixed backing bounds each table ([`caps::MAX_PEER_KEYEXPR_ALIASES`],
/// [`caps::MAX_INBOUND_SUB_INTERESTS`], [`caps::MAX_PENDING_DECLARES`]). The
/// [`SubscriberTable`] that answers the side holds its interests and its staging
/// to the quotas its creator stated, on every backing, and the alias table is held
/// on both backings to the `MAX_PEER_KEYEXPR_ALIASES` the creator of the session's
/// tables states (`limit_aliases_to`); a peer that fills one is refused and
/// counted, and no other session's side changes.
///
/// Two halves that are borrowed apart: `PeerNaming`, what the peer's ids name
/// (read by every plane that resolves a keyexpr), and `InterestSide`, what it
/// asked to be told and what is staged back (written by the interest plane while
/// it holds a keyexpr resolved out of the first).
pub struct SubscriberPeer<P: Storage = Profile> {
    #[cfg(feature = "storage-profile")]
    naming: PeerNaming<P>,
    #[cfg(feature = "declare-subscriber")]
    interests: InterestSide<P>,
    /// Which peer the image declares this session's peer to be, once the session knows its zid
    /// (`PeerAllowance::class_of`): the row of the
    /// allowance a message from it is asked against. `None` is a peer not declared, which a closed
    /// image that declares its peers allows nothing.
    class: Option<ClassId>,
    /// Names the policy where no field above does (a build without the session
    /// machinery). Zero-sized.
    _policy: core::marker::PhantomData<P>,
}

/// What a session's peer has named, and what names OUR side: its keyexpr aliases,
/// the id space of our own bundle, and our zid. See [`SubscriberPeer`].
#[cfg(feature = "storage-profile")]
struct PeerNaming<P: Storage = Profile> {
    /// R121d — peer-side keyexpr alias table. Populated from
    /// inbound `Declare(DeclKexpr)` records; cleared per-id by
    /// `Declare(UndeclKexpr)`. Each entry maps a peer-declared
    /// mapping id (the `DeclKexpr.id` u64) to the literal keyexpr
    /// string the peer aliased it to.
    ///
    /// For now only the simple "DeclKexpr.keyexpr is a literal
    /// (id=0, suffix=Some)" case is recorded. Composite
    /// declarations (`DeclKexpr.keyexpr.id != 0`) — where one
    /// alias references another — are recorded as their resolved
    /// form when the table already contains the inner reference;
    /// unresolved composites stay out of the table so a
    /// downstream Push referencing them is filtered as "no
    /// resolution" rather than firing on a partial keyexpr.
    ///
    /// R311gb (Track 2) — wire-side state (populated by `absorb_declare`
    /// consuming owned `Declare` records, consumed by `dispatch_push`);
    /// `alloc`-gated per the borrow boundary. The no-alloc control plane
    /// (subscription table + matching) does not depend on it.
    ///
    /// S9a — a [`PeerAliases`]: the `HashMap` it always was on the growable
    /// backing, and on the fixed one a table of
    /// [`caps::MAX_PEER_KEYEXPR_ALIASES`] rows whose full state refuses a NEW id
    /// and counts it.
    #[cfg(feature = "storage-profile")]
    aliases: PeerAliases<P>,
    /// The most aliases `aliases` holds (`MAX_PEER_KEYEXPR_ALIASES`): what the creator of
    /// the session's tables resolved ([`SubscriberPeer::limit_aliases_to`]), the build's value
    /// until it does. A growable table refuses nothing by its room, so this is what bounds it;
    /// where the build fixes the bound to the table's capacity it is held in no byte and the
    /// table refuses alone.
    alias_quota: crate::limits::MaxPeerKeyexprAliasesHeld,
    /// The longest keyexpr an alias row holds (`MAX_KEYEXPR_BYTES`): what the creator of the
    /// session's tables resolved ([`SubscriberPeer::limit_keys_to`]), the build's value until it
    /// does. A `DeclKexpr` whose keyexpr is longer is dropped, as one a fixed row cannot hold is.
    key_quota: crate::limits::MaxKeyexprBytesHeld,
    /// Where the alias rows keep their keys ([`Storage::Keys`]): the session's key arena on the
    /// lent policy ([`SubscriberPeer::keep_keys_in`]). A `DeclKexpr` whose key finds no room
    /// there is dropped and counted with the alias table's refusals.
    keys: P::Keys,
    /// R311y739 — OUR id space, the other half of the pair the `M` bit picks
    /// between. Installed (not owned) so there is exactly ONE copy of the fact:
    /// the table itself is the session's own declarations (`crate::declared_keyexprs`),
    /// kept by the link that sends them or by the session for all its links, and this
    /// handle reads it through
    /// [`OwnMappingSpace::resolve_own_mapping`](crate::wireexpr_resolve::OwnMappingSpace::resolve_own_mapping). A
    /// mirrored `HashMap` here would go stale on the first undeclare.
    ///
    /// `None` is the honest state for a face that declares no aliases of its own
    /// — a relay, or a session before bring-up — and it keeps the pre-R311y739
    /// answer: an `M=0` ALIAS refuses rather than being read out of the peer's
    /// table. `M=0` LITERALS (`id == 0`) never consulted a space and are
    /// unaffected either way.
    ///
    /// Why it matters that this is usually `Some`: zenoh PREFERS the id the peer
    /// declared when rendering a keyexpr back at it (`get_best_key`,
    /// `dispatcher/resource.rs:625`), so a zenoh peer starts naming OUR ids with
    /// `M=0` the moment we declare one. Absent the install, every such Push was
    /// dropped.
    ///
    /// R311y740 — held through the per-profile
    /// [`SharedOwnMappingSpace`]
    /// alias (AP `Arc`, ARMv6-M `Rc`) rather than a hard-coded
    /// `alloc::sync::Arc`, which is absent from `alloc` on Cortex-M0+ and
    /// walled the whole crate off that target.
    ///
    /// Per SESSION for the reason the table above is: our id space is the one of
    /// the session's own bundle, and two sessions have two.
    #[cfg(feature = "alloc")]
    own_mapping_space: Option<SharedOwnMappingSpace>,
    /// The key ids every node of the deployment shares, when the session holds them
    /// (`shared-key-ids`): an id neither declared space holds is read in it. Installed, as the
    /// own space is, by the engine that opened the session; `None` keeps the two spaces alone.
    #[cfg(feature = "shared-key-ids")]
    shared_key_ids: Option<crate::shared_key_ids::SharedKeyIds>,
    /// R231 — this session's own zid prefix (1..=16 bytes),
    /// negotiated during the session-FSM open handshake. When set,
    /// [`dispatch_push`](SubscriberTable::dispatch_push) suppresses wire-arrived
    /// Push records whose `source_info.zid` prefix-matches this
    /// value (with equal effective length), preventing
    /// `Locality::Any` self-publishes from double-firing local
    /// subscribers in mesh / router-echo topologies. `None` disables
    /// the dedup (safe default — never silently swallows samples,
    /// only suppresses confirmed self-echoes).
    ///
    /// Mirrors the zenoh-cpp / zenoh-rust self-origin guard rather
    /// than the zenoh-pico client-mode dispatch path (pico's
    /// `peer == NULL` distinguishes local-vs-wire by call site, not
    /// by source identity, because the pico client has no router
    /// that could echo a publish back). When wz operates in
    /// single-peer unicast mode the dedup is a no-op; the
    /// production correctness payoff is the mesh / router topology.
    ///
    /// R311gb (Track 2) — wire-side self-echo dedup state, consumed by
    /// `dispatch_push`; `alloc`-gated per the borrow boundary.
    ///
    /// Per SESSION: two sessions of one process may carry two zids, and an echo
    /// is a sample that names the zid of the session it came back on.
    // Inline whatever the policy: sixteen bytes no table lends.
    own_zid: Option<BoundedVec<u8, 16, Static>>,
}

/// What a session's peer asked to be told about our subscriptions, and what is
/// staged back to it. See [`SubscriberPeer`].
#[cfg(feature = "declare-subscriber")]
struct InterestSide<P: Storage = Profile> {
    /// R311y530 — inbound SUBSCRIBER `Interest`s this session has been told
    /// about, zenoh's per-face `remote-interests` table restricted to the
    /// session-local half. Retired on that interest's `Interest(Final)`.
    ///
    /// Its only consumer is [`SubscriberTable::respond_to_subscriber_interest_borrowed`],
    /// which needs the interest's OWN keyexpr at DRAIN time to build an
    /// aggregate reply — and a staged reply item cannot carry it (the staging
    /// buffer is an inline array sized to its largest variant, and a
    /// `BoundedString` slot per item is what overflowed a Cortex-M0 stack when
    /// the liveliness twin tried it). So the keyexpr lives here, once, and the
    /// staged item is two `u64`s that resolve through it.
    ///
    /// At most `MAX_INBOUND_SUB_INTERESTS` rows, in the policy's sequence of a peer's rows
    /// (`Storage::Pooled`): on the lent policy each row lies in a pool every face of the session
    /// shares (`InterestRows`), so a face holds the interests its peer asked and not the most it
    /// could.
    #[cfg(feature = "declare-subscriber")]
    rows: <P as Storage>::Pooled<InboundSubInterest<P>, { caps::MAX_INBOUND_SUB_INTERESTS }>,
    /// R311y530 — the staged interest-response chain, drained by
    /// [`Self::take_staged_sub_interest_replies`] through a
    /// [`crate::response_sink::DeclareReplySink`].
    #[cfg(feature = "declare-subscriber")]
    staged: BoundedVec<SubInterestReply, { caps::MAX_PENDING_DECLARES }, P>,
    /// What the two tables above could not take, counted rather than dropped
    /// in silence. Every field stays zero on the growable backing with no
    /// quota stated, where nothing is refused; see [`SubInterestRefusals`].
    #[cfg(feature = "declare-subscriber")]
    refusals: SubInterestRefusals,
    /// The [`SubscriberTable`] epoch this side last staged announcements for.
    /// Only a side that does NOT see registrations as they happen (a session slot,
    /// under `session-slot`) reads it; see [`Self::reconcile`].
    #[cfg(feature = "declare-subscriber")]
    reconciled_epoch: u64,
    /// Where the rows keep their keys ([`Storage::Keys`]): the session's key arena on the lent
    /// policy ([`SubscriberPeer::keep_keys_in`]). An interest whose key finds no room there is
    /// answered by its `Final` alone, as one whose key is past the bound is.
    #[cfg(feature = "declare-subscriber")]
    keys: P::Keys,
}

/// The Push records the in-place receive path (`drive::dispatch_datagram`, the
/// MCU profile's `rx-in-place`) handed this registry lent, and that it then
/// delivered through the owned projection ([`SubscriberRegistry::dispatch`]'s
/// path) because a lent delivery could not represent them. Each is still
/// delivered, exactly as the copying path delivers it; what it costs is the heap
/// the owned projection takes. Counted so a profile can see how much of its
/// traffic pays that.
#[cfg(all(
    feature = "storage-profile",
    any(feature = "pubsub-put", feature = "pubsub-delete")
))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct InPlaceFallbacks {
    /// A Put whose payload is a list of slices (the shared-memory layout): the
    /// slices are joined or resolved into a buffer of their own, which is the
    /// owned path's (`put_payload::collect_wire_payload`).
    pub sliced: u32,
    /// A Put whose resolved keyexpr is longer than
    /// [`crate::wireexpr_resolve::KeyexprBuf`] holds. Only the
    /// fixed bounded backing refuses one; the owned path resolves it into a
    /// `String`.
    pub keyexpr_past_bound: u32,
    /// A message that carries a timestamp stack (extension `0x7`): the nodes that deliver it add
    /// to the stack, which is an owned value the lent form has none of, so the owned path takes it.
    #[cfg(feature = "pubsub-ts-stack")]
    pub instrumented: u32,
}

/// The counted refusals of the session-local subscriber-interest staging, by
/// what was refused.
///
/// Reachable where the tables are held to a count: on the fixed backing
/// ([`crate::bounded::ENFORCES_CAPACITY`]) by their storage, and on every backing
/// by the quotas the creator of the subscriber table states
/// ([`SubscriberTable::limit_interests_to`],
/// [`SubscriberTable::limit_interest_replies_to`]). The interest table then holds
/// at most [`caps::MAX_INBOUND_SUB_INTERESTS`] rows and the staging buffer at most
/// [`caps::MAX_PENDING_DECLARES`] items between two drains, and one frame of
/// Interests is staged before the drain runs. A refusal is the peer's to see as
/// an unanswered or un-pushed interest; this is where the session says how many
/// there were.
#[cfg(feature = "declare-subscriber")]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SubInterestRefusals {
    /// CURRENT reply chains staged NOT AT ALL, because the staging buffer could
    /// not take the whole chain with its terminating `Final`. A chain is staged
    /// whole or not at all: a truncated chain under a `Final` would tell the
    /// peer that the subscriptions it lacks do not exist.
    pub chains: u32,
    /// FUTURE interests not remembered, because the interest table was full. A
    /// subscription declared later is not pushed to that publisher.
    pub future_interests: u32,
    /// Unsolicited announcements (a FUTURE push for a new subscription, or the
    /// retraction of an aggregate declaration) not staged, because the staging
    /// buffer was full.
    pub announcements: u32,
}

/// ARCHITECTURE section 9.2 -- the delivery of a Push the in-place receive path
/// lends ([`IterationEvent::InPlace`]).
#[cfg(all(
    feature = "storage-profile",
    any(feature = "pubsub-put", feature = "pubsub-delete")
))]
mod in_place;

/// R3040 (transport-shm) -- the priority band a received Push was sent at: the
/// shared [`priority_band`](crate::put_payload::priority_band) over the push's own
/// extension chain.
///
/// Gated with the Put arm that calls it, which is also what brings `PushOwned`
/// into scope.
#[cfg(all(feature = "transport-shm", feature = "pubsub-put"))]
fn push_priority_band(push: &PushOwned) -> usize {
    crate::put_payload::priority_band(push.extensions.entries().unwrap_or(&[]))
}

/// R311y530 — whether a session-local subscription `pattern` intersects an
/// inbound subscriber-interest `interest` (`None` = the keyexpr-less match-all
/// form). BOTH sides can carry wildcards — the subscription is `demo/**` and
/// the interest is a publisher's concrete `demo/a` in the case that motivated
/// this — so the test is INTERSECTION, not one-sided glob matching.
///
/// Matched as text (no heap). On the fixed backing a keyexpr deeper than
/// [`MAX_KEYEXPR_CHUNKS`] is treated as non-matching rather than matched
/// truncated, mirroring the sibling registries' conservative rule; the
/// matcher applies that bound itself.
#[cfg(feature = "declare-subscriber")]
fn subscription_matches_interest(pattern: &str, interest: Option<&str>) -> bool {
    match interest {
        Some(interest) => keyexpr_intersects(pattern, interest),
        None => true,
    }
}

/// R311y530 — one remembered inbound SUBSCRIBER `Interest`.
#[cfg(feature = "declare-subscriber")]
struct InboundSubInterest<P: Storage = Profile> {
    /// The peer's interest id, echoed on every reply and on the terminating
    /// `DeclFinal` so the peer routes them to this interest.
    interest_id: u64,
    /// The interest's RESOLVED keyexpr — the reply keyexpr when
    /// [`aggregate`](Self::aggregate) is set — kept as the policy keeps a row's key.
    keyexpr: P::Key,
    /// The `AGGREGATE` flag off the interest body. Load-bearing, not
    /// informational: an aggregate interest's replies are associated by
    /// `_z_keyexpr_equals` against THIS keyexpr (`session/interest.c:274-276`),
    /// so a reply carrying a concrete subscription keyexpr matches nothing.
    aggregate: bool,
    /// The `DeclSubscriber.id` this session answers this interest with when the
    /// reply is aggregate. Non-zero and STABLE per registered interest: pico
    /// dedups a filter target by `(peer, decl_id)` (`net/filtering.c`
    /// `_z_filter_target_eq`), so a re-answered interest must reuse its id
    /// rather than stack a second target. R2292 draws it from the registry's
    /// ONE id counter — see the allocation site for why a second counter was
    /// a defect rather than a detail.
    aggregate_decl_id: u32,
    /// The subscription id from which a registration is a FUTURE one for this
    /// interest: the id counter AFTER the row took its own declaration id. A
    /// subscription at or after it came after the interest, and is the one a peer
    /// that only reads the subscription table's epoch still owes an announcement
    /// ([`SubscriberPeer::reconcile`]); one before it was already part of the
    /// CURRENT dump.
    watermark: u64,
    /// R2292 (open-debt item 627) — whether a `DeclSubscriber` carrying
    /// [`aggregate_decl_id`](Self::aggregate_decl_id) has actually reached the
    /// wire and has not been retracted since.
    ///
    /// It is what makes the retraction retract only what was ANNOUNCED. The
    /// declare-rollback path unregisters a subscription whose reply was staged
    /// and then dropped (R2291), so a purely structural "the last match went
    /// away" rule would emit an `UndeclSubscriber` for an id no peer was ever
    /// told about. Upstream needs no such flag because its declare and its
    /// table insert are one transaction; wz stages and drains on two threads,
    /// so the fact has to be recorded.
    ///
    /// Only meaningful when [`aggregate`](Self::aggregate) is set: a
    /// non-aggregate interest is answered per subscription, and each of those
    /// replies is retracted by its own subscription's teardown.
    ///
    /// GATED AS THE UNION OF ITS CONSUMERS — every one of them is behind
    /// `declare-undeclare`, because without that feature this session emits no
    /// `UndeclSubscriber` at all and there is nothing for the flag to arm. A
    /// `declare-subscriber`-without-`declare-undeclare` build was measured
    /// dying at `-D dead-code` on Layer C1c, which is the same shape R2290's
    /// probe fixture died in one round earlier.
    #[cfg(feature = "declare-undeclare")]
    announced: bool,
}

/// R311y530 — one staged item of a session-local subscriber interest-response
/// chain. Deliberately two `u64`s wide at most: see `inbound_sub_interests`.
#[cfg(feature = "declare-subscriber")]
pub enum SubInterestReply {
    /// Reply ONCE with the interest's own keyexpr (the AGGREGATE form).
    Aggregate {
        /// Resolves to the interest row holding the keyexpr and the decl id.
        interest_id: u64,
    },
    /// Reply with local subscription `subscription_id`'s own pattern (the
    /// non-aggregate form: one item per matching subscription).
    Concrete {
        /// Echoed on the reply.
        interest_id: u64,
        /// The local subscription whose pattern is the reply keyexpr, and whose
        /// id is the wire `DeclSubscriber.id`.
        subscription_id: u64,
    },
    /// The terminating `Declare(DeclFinal)`. Staged even when nothing matched,
    /// so the peer's CURRENT interest always resolves.
    Final {
        /// Echoed on the terminator.
        interest_id: u64,
    },
    /// R2292 (open-debt item 627) — retract the AGGREGATE declaration this
    /// session answered `interest_id` with, because the last local
    /// subscription it stood for has gone away.
    ///
    /// The counterpart of [`Aggregate`](Self::Aggregate), and the only item in
    /// this enum that is staged by a RETIREMENT rather than by a declaration.
    /// zenoh emits exactly this transition: its aggregated resource's info is
    /// `Some` iff at least one simple resource is aggregated into it, and
    /// `remove_simple_resource` reports the aggregate's own id when that flips
    /// to `None`, which `maybe_unpropagate_subscriber` turns into an
    /// `UndeclareSubscriber { id }`
    /// (`zenoh/src/net/routing/dispatcher/local_resources.rs`
    /// @ `pub(crate) fn remove_simple_resource` and
    /// `zenoh/src/net/routing/hat/broker/pubsub.rs`
    /// @ `fn maybe_unpropagate_subscriber`, 1.10.0).
    #[cfg(feature = "declare-undeclare")]
    AggregateRetract {
        /// Resolves to the interest row holding the decl id, RE-CHECKED at
        /// drain: what a retraction says has to be true when it is SENT.
        interest_id: u64,
    },
}

/// The subscriber registry a single peer's session holds: the application's
/// [`SubscriberTable`] and that one peer's [`SubscriberPeer`] side together. The
/// registry every AP session has always had, and the API it has always had: the
/// application-facing methods are the table's (this derefs to it), and the ones
/// that need the peer's side are this type's own and pass its own.
///
/// What the fixed-memory profile does with the two halves apart is
/// `session-slot`'s ([`SubscriberTable`] once per process, a [`SubscriberPeer`] in
/// each session slot); it uses this type for nothing but the single-session case
/// and for tests.
pub struct SubscriberRegistry<C: SampleSink, P: Storage = Profile> {
    table: SubscriberTable<C, P>,
    peer: SubscriberPeer<P>,
}

impl<C: SampleSink, P: Storage> core::ops::Deref for SubscriberRegistry<C, P> {
    type Target = SubscriberTable<C, P>;

    fn deref(&self) -> &SubscriberTable<C, P> {
        &self.table
    }
}

impl<C: SampleSink, P: Storage> core::ops::DerefMut for SubscriberRegistry<C, P> {
    fn deref_mut(&mut self) -> &mut SubscriberTable<C, P> {
        &mut self.table
    }
}

impl<C: SampleSink, P: Storage> Default for SubscriberRegistry<C, P> {
    fn default() -> Self {
        Self {
            table: SubscriberTable::default(),
            peer: SubscriberPeer::default(),
        }
    }
}

impl<C: SampleSink> SubscriberTable<C, Profile> {
    /// New empty table over an explicit sink backing `C`, of this build's storage
    /// profile. Subscriber ids start at 1 so 0 stays available as a sentinel "no
    /// subscription" value for any caller-side wrapper that needs one. Defined for
    /// the profile alone, so it names its storage policy by itself; code generic
    /// over a policy builds a table with `Default`.
    pub fn with_sink_backing() -> Self {
        Self::default()
    }
}

impl<C: SampleSink> SubscriberTable<C, Lent> {
    /// An empty table whose subscriptions are `rows` rows lent from `arena`, at most
    /// `MAX_SUBSCRIPTIONS`, their patterns kept in `keys`, the session's key arena: a session's,
    /// at its open. Refused, taking nothing, past that ceiling or past what the arena has left.
    pub fn lent(arena: &mut Arena, keys: KeySpace, rows: usize) -> Result<Self, LendRefused> {
        Ok(Self {
            subscribers: arena.lend(rows)?,
            keys: LentKeys::from(keys),
            ..Self::default()
        })
    }
}

impl<C: SampleSink, P: Storage> Default for SubscriberTable<C, P> {
    fn default() -> Self {
        Self {
            subscribers: BoundedVec::default(),
            quota: Default::default(),
            key_quota: Default::default(),
            #[cfg(feature = "declare-subscriber")]
            interest_quota: Default::default(),
            #[cfg(feature = "declare-subscriber")]
            reply_quota: Default::default(),
            next_id: 1,
            epoch: 0,
            #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
            local_live: alloc::sync::Arc::new(core::sync::atomic::AtomicUsize::new(0)),
            memo: MatchMemo::new(
                <crate::limits::MatchMemoSlots as crate::limit_binding::LimitSpec>::DEFAULT,
            ),
            key_gate: KeyGate::of_build(),
            keys: Default::default(),
            #[cfg(feature = "transport-shm")]
            shm: crate::extshm::ShmReceiveState::default(),
            #[cfg(all(
                feature = "storage-profile",
                any(feature = "pubsub-put", feature = "pubsub-delete")
            ))]
            in_place_fallbacks: InPlaceFallbacks::default(),
        }
    }
}

impl<C: SampleSink, P: Storage> SubscriberTable<C, P> {
    /// The bytes one subscription takes in the table's storage: its pattern's text with it where
    /// the storage policy keeps the text in the row, and its sink as the table holds it.
    pub const ROW_BYTES: usize = core::mem::size_of::<Subscriber<C, P>>();

    /// Hold the table to the `MAX_SUBSCRIPTIONS` its creator resolved: a registration that would
    /// leave more subscriptions than `quota` admits is refused ([`RegisterError::TableFull`]),
    /// and the subscriptions already in are kept, as a lowered soft limit keeps what it holds.
    pub fn limit_to(&mut self, quota: crate::limits::MaxSubscriptionsHeld) {
        self.quota = quota;
    }

    /// Hold the table to the `MAX_KEYEXPR_BYTES` its creator resolved: a subscription whose
    /// pattern is longer than `quota` admits is refused ([`RegisterError::KeyexprTooLong`]), and
    /// a peer's interest whose keyexpr is longer is answered by its `Final` alone, as a fixed row
    /// that cannot hold the key refuses them. What the table holds is kept.
    pub fn limit_keys_to(&mut self, quota: crate::limits::MaxKeyexprBytesHeld) {
        self.key_quota = quota;
    }

    /// Size the receive match cache to the `MATCH_MEMO_SLOTS` its creator resolved: how many
    /// distinct keys it remembers at once, `0` leaving it out. The keys it remembered are
    /// forgotten, which changes no delivery: a key not remembered is matched afresh. A table of
    /// the fixed storage policy keeps the `MATCH_MEMO_FIXED_SLOTS` its build holds in RAM.
    pub fn limit_memo_to(&mut self, slots: usize) {
        if !P::ENFORCES_CAPACITY {
            self.memo = MatchMemo::new(slots);
        }
    }

    /// How many distinct keys the receive match cache remembers at once
    /// ([`Self::limit_memo_to`]).
    pub fn memo_slot_count(&self) -> usize {
        self.memo.slot_count()
    }

    /// Hold every peer's side this table answers to the `MAX_INBOUND_SUB_INTERESTS` its creator
    /// resolved: an interest that would leave a side with more rows than `quota` admits is not
    /// remembered, as a full fixed table does not remember it (a FUTURE one is counted in
    /// [`SubInterestRefusals::future_interests`], an AGGREGATE CURRENT one has its chain refused),
    /// and the rows already held are kept.
    #[cfg(feature = "declare-subscriber")]
    pub fn limit_interests_to(&mut self, quota: crate::limits::MaxInboundSubInterestsHeld) {
        self.interest_quota = quota;
    }

    /// Hold every peer's side this table answers to the `MAX_PENDING_DECLARES` its creator
    /// resolved: what would leave more items staged between two drains than `quota` admits is
    /// refused and counted, as a full fixed staging buffer refuses it (a CURRENT chain whole, in
    /// [`SubInterestRefusals::chains`]; an announcement in
    /// [`SubInterestRefusals::announcements`]), and what is staged is kept.
    ///
    /// A quota under the subscriptions a match-all interest is answered with, plus its `Final`,
    /// refuses that interest's chain every time it is asked. The build holds its own capacities
    /// clear of that (`caps.rs`); a stage that states a lower quota states that refusal.
    #[cfg(feature = "declare-subscriber")]
    pub fn limit_interest_replies_to(&mut self, quota: crate::limits::MaxPendingDeclaresHeld) {
        self.reply_quota = quota;
    }

    /// Replace the gate that decides which keys a message from a peer may be on, which starts as
    /// what the build's `key-set` policy states. A closed image hands it the gate over its
    /// generated table. The counts of the gate it replaces are not carried over.
    ///
    /// A subscription made before the gate was set is numbered by it now when the image declares
    /// its pattern as a subscriber, and is otherwise kept and matched by its pattern, so that a
    /// subscription the application declared is never silently left without its messages. An
    /// image that gives its table first has none of the second kind.
    pub fn set_key_gate(&mut self, gate: KeyGate<'static>) {
        self.key_gate = gate;
        for subscriber in self.subscribers.iter_mut() {
            subscriber.entity = gate.entity_of(&subscriber.pattern, EntityKind::Subscriber);
        }
    }

    /// How many messages from a peer the key gate dropped, by reason: all zero for an open gate.
    pub const fn key_gate_refused(&self) -> Refused {
        self.key_gate.refused()
    }

    /// What the key gate says of a message, by the key it arrived on and the peer it came from
    /// (`class`, the row the session found for the peer's zid). A message that is not from a peer
    /// (a local publish) is the application's own and is not gated.
    #[inline]
    fn admission(&mut self, keyexpr: &str, is_remote: bool, class: Option<ClassId>) -> Admission {
        if !is_remote {
            return Admission::Matched;
        }
        match self
            .key_gate
            .admit_key_from(class, PeerOp::Publish, keyexpr)
        {
            Ok(Admitted::Key(key)) => Admission::Numbered(key),
            Ok(Admitted::Unchecked) => Admission::Matched,
            Err(_) => Admission::Refused,
        }
    }

    /// Deliver a message that was read in place, whose key may lie in the peer's own table so that
    /// this table is borrowed apart from it ([`SubscriberPeer`]): the gate, then the selection of a
    /// key of a closed set or the match of every subscription (through the match cache where the
    /// table is fixed in size and `MATCH_MEMO_FIXED_SLOTS` asks for it; a heap table matches
    /// afresh, so that this path allocates nothing for a key it has not seen). The delivery of
    /// the in-place receive path, which a closed image of the fixed profile takes.
    #[cfg(all(
        feature = "storage-profile",
        any(feature = "pubsub-put", feature = "pubsub-delete")
    ))]
    pub(super) fn fire_lent(&mut self, view: &dyn SampleView, class: Option<ClassId>) -> usize {
        match self.admission(view.keyexpr(), true, class) {
            Admission::Refused => return 0,
            Admission::Numbered(key) => {
                if let Some(fired) =
                    self.deliver_by_selection(key, view.keyexpr(), |sink| sink.deliver(view))
                {
                    return fired;
                }
            }
            Admission::Matched => {}
        }
        // A heap table's cache slot allocates the first time it sees a key (the key's text and
        // the list of what it matched), which the in-place path's contract does not allow: it
        // costs the heap nothing (the matcher reads the key as text). A fixed table's slots are
        // already in place, so there the cache costs no allocation and is used.
        if !P::ENFORCES_CAPACITY {
            return scan_subscribers(
                &mut self.subscribers,
                view.keyexpr(),
                true,
                |sink| sink.deliver(view),
                |_| {},
            )
            .unwrap_or(0);
        }
        fire_into_memoized(
            &mut self.subscribers,
            &mut self.memo,
            self.epoch,
            view.keyexpr(),
            true,
            false,
            |sink| sink.deliver(view),
        )
    }

    /// What the in-place receive path's Puts cost in owned fallbacks since this
    /// registry was built; see [`InPlaceFallbacks`].
    #[cfg(all(
        feature = "storage-profile",
        any(feature = "pubsub-put", feature = "pubsub-delete")
    ))]
    pub fn in_place_fallbacks(&self) -> InPlaceFallbacks {
        self.in_place_fallbacks
    }

    /// transport-shm — install the AP SHM resolver (the `std` mmap-open impl). The
    /// single mutation entry point for the gated `shm_resolver` field, called once
    /// at AP bring-up (the wz-runtime-tokio `Session::set_shm_resolver` forwarder),
    /// so the ~110 registry construction sites keep their unchanged signatures.
    #[cfg(feature = "transport-shm")]
    pub fn set_shm_resolver(
        &mut self,
        resolver: alloc::boxed::Box<dyn crate::extshm::ShmResolver + Send + Sync>,
    ) {
        self.shm.set_resolver(alloc::sync::Arc::from(resolver));
    }

    /// R3042 (transport-shm) -- [`set_shm_resolver`](Self::set_shm_resolver) for a
    /// resolver that more than one registry of a session shares: the session turns
    /// the one it was given into a shared handle and installs it here and on the
    /// reply registry, so a reply is read by the same resolver a push is.
    #[cfg(feature = "transport-shm")]
    pub fn set_shm_resolver_shared(
        &mut self,
        resolver: alloc::sync::Arc<dyn crate::extshm::ShmResolver + Send + Sync>,
    ) {
        self.shm.set_resolver(resolver);
    }

    /// transport-shm — the number of SHM Puts dropped because their descriptor
    /// could not be resolved (no resolver installed, or a stale / foreign
    /// segment). A non-zero value at steady state usually means the AP forgot to
    /// [`set_shm_resolver`](Self::set_shm_resolver).
    #[cfg(feature = "transport-shm")]
    pub fn shm_unresolved_drops(&self) -> u64 {
        self.shm.unresolved_drops()
    }

    /// R311y516 (transport-shm) — restamp the LIVE negotiated SHM capability of
    /// the session feeding this registry. Called once per dispatch iteration
    /// from the unicast dispatch SSOT
    /// (`wz-runtime-tokio::Session::dispatch_iteration_event_with`), which is
    /// wz's counterpart of the zenoh boundary that carries the same guard
    /// (`TransportUnicastUniversal::trigger_callback`).
    ///
    /// Restamped, not snapshotted — see the [`shm_negotiated`](Self#structfield.shm_negotiated)
    /// field doc for why a snapshot fails OPEN across a reconnect.
    #[cfg(feature = "transport-shm")]
    pub fn set_shm_negotiated(&mut self, negotiated: bool) {
        self.shm.set_negotiated(negotiated);
    }

    /// R3040 (transport-shm) -- install or withdraw the means of acknowledging the
    /// peer's shared-memory slices. `None` withdraws, which a new establishment
    /// does first, so a registry never writes the counters of a peer the session
    /// has moved on from.
    #[cfg(feature = "transport-shm")]
    pub fn set_shm_handoff(
        &mut self,
        handoff: Option<alloc::boxed::Box<dyn crate::extshm::ShmHandoff>>,
    ) {
        self.shm.set_handoff(handoff.map(alloc::sync::Arc::from));
    }

    /// R3042 (transport-shm) -- [`set_shm_handoff`](Self::set_shm_handoff) for a
    /// handoff that more than one registry of a session shares: the counters the
    /// peer named are the peer's, and a reply's slice is acknowledged through the
    /// same ones a push's is.
    #[cfg(feature = "transport-shm")]
    pub fn set_shm_handoff_shared(
        &mut self,
        handoff: Option<alloc::sync::Arc<dyn crate::extshm::ShmHandoff>>,
    ) {
        self.shm.set_handoff(handoff);
    }

    /// R3040 (transport-shm) -- whether a handoff is installed. For tests and
    /// diagnostics: the data path reads the state directly.
    #[cfg(feature = "transport-shm")]
    pub fn has_shm_handoff(&self) -> bool {
        self.shm.has_handoff()
    }

    /// R311y516 (transport-shm) — whether the RX un-swap will currently honour
    /// an inbound 0x2 SHM marker on this registry.
    #[cfg(feature = "transport-shm")]
    pub fn shm_negotiated(&self) -> bool {
        self.shm.negotiated()
    }

    /// R311y516 (transport-shm) — the number of SHM Puts dropped because the
    /// 0x2 marker arrived on a session that never NEGOTIATED SHM. A non-zero
    /// value means a peer named a segment it had no right to name (or, on a
    /// custom drive loop, that the registry is never stamped).
    #[cfg(feature = "transport-shm")]
    pub fn shm_unnegotiated_drops(&self) -> u64 {
        self.shm.unnegotiated_drops()
    }

    /// The declaration id the next subscription or aggregate reply takes, or
    /// `None` once every `u32` id has been handed out. Upstream's counter wraps
    /// (`zenoh/src/net/runtime/mod.rs` @ `self.next_id.fetch_add(1, Ordering::SeqCst)`)
    /// and would hand out an id a live declaration may still hold; this one
    /// stops instead, and the id is taken only by [`Self::consume_entity_id`].
    fn next_entity_id(&self) -> Option<u32> {
        u32::try_from(self.next_id).ok()
    }

    /// Take the id [`Self::next_entity_id`] returned. Called only after it
    /// returned one, so the counter stops one past `u32::MAX`.
    fn consume_entity_id(&mut self) {
        self.next_id += 1;
    }

    /// R311gb-2b — register an explicit [`SampleSink`] for a keyexpr
    /// pattern. The seam-native registration entry point: works on
    /// every profile (`C = BoxedSink` heap closure on AP, a consumer-
    /// supplied closed `enum` on MCU). The `alloc`-only
    /// [`register`](Self::register) /
    /// [`register_with_locality`](Self::register_with_locality)
    /// convenience wrappers funnel through here after wrapping a
    /// closure in a [`BoxedSink`].
    ///
    /// Pattern syntax matches zenoh chunk wildcards: `/`-separated
    /// chunks where each chunk is a literal, `*` (single chunk), `**`
    /// (zero or more chunks), or contains the `$*` intra-chunk
    /// substring wildcard (R220). The returned `SubscriptionId` is
    /// stable until [`unregister`](Self::unregister) is called.
    /// Duplicate patterns are allowed and produce distinct
    /// subscriptions — `dispatch` fires every matching sink in
    /// registration order.
    ///
    /// R221 — the pattern is canonicalized via
    /// [`canonize_keyexpr`](crate::keyexpr_canon::canonize_keyexpr)
    /// before being split into chunks, so the stored form agrees
    /// byte-for-byte with what a peer's `Declare(DeclKexpr)` would
    /// carry on the wire (lone `$*` chunk → `*`, `**/*` → `**`,
    /// etc.). If the pattern is structurally invalid the raw form
    /// is stored unchanged and a warning is emitted (`diag_warn!`) — this is
    /// non-breaking with prior callers; promotion to a Result-
    /// returning signature is deferred to the cluster API rewrite.
    ///
    /// Once the table has handed out every `u32` declaration id it refuses
    /// with [`RegisterError::IdsExhausted`], on every backing.
    pub fn register_sink(
        &mut self,
        keyexpr_pattern: &str,
        allowed_origin: crate::locality::Locality,
        sink: C,
    ) -> Result<SubscriptionId, RegisterError> {
        // R221/R311gb — canonicalize into the bounded pattern buffer. A
        // grammar-invalid pattern falls back to the raw form (non-
        // breaking; the matcher still operates). An over-capacity
        // canonical form is a hard no-alloc failure (fail-fast, no
        // silent truncation). On the `alloc` backing neither capacity
        // branch is ever taken.
        let pattern: BoundedString<{ caps::MAX_KEYEXPR_BYTES }, P> =
            match crate::keyexpr_canon::canonize_keyexpr_as::<P>(
                keyexpr_pattern,
                crate::keyexpr_canon::KeyexprDialect::Pico,
            ) {
                Ok(canon) => canon,
                Err(crate::keyexpr_canon::KeyexprCanonError::ExceedsCapacity) => {
                    return Err(RegisterError::KeyexprTooLong);
                }
                Err(err) => {
                    crate::diag_warn!(
                        "SubscriberRegistry::register: keyexpr `{keyexpr_pattern}` is not \
                         canonical ({err}); storing raw form. The matcher still operates but \
                         the stored chunks may drift from the canonical form a peer emits."
                    );
                    let mut raw = BoundedString::default();
                    raw.push_str(keyexpr_pattern)
                        .map_err(|_| RegisterError::KeyexprTooLong)?;
                    raw
                }
            };
        // A pattern past the session's key bound is refused as one the row cannot hold.
        if !self.key_quota.admits(pattern.len()) {
            return Err(RegisterError::KeyexprTooLong);
        }
        // The quota first, before the key gate numbers an entity or an id is taken: a refused
        // registration changes nothing.
        if !self.quota.admits(self.subscribers.len() + 1) {
            return Err(RegisterError::TableFull);
        }
        // The row's key, also before an entity or an id is taken: a pattern with no room where
        // the table keeps its keys is refused as a full table refuses it, and a refusal after this
        // gives the key back as it drops.
        let key = self.keys.key(&pattern).map_err(|unkept| match unkept {
            KeyUnkept::TooLong => RegisterError::KeyexprTooLong,
            KeyUnkept::NoRoom => RegisterError::TableFull,
        })?;
        // A closed key set admits a subscription only on a pattern the image declares as one, and
        // numbers it: the entity it is delivered by. An open table has none.
        let entity = self
            .key_gate
            .admit_entity(&pattern, EntityKind::Subscriber)
            .map_err(|_| RegisterError::KeyNotInSet)?;
        let id = SubscriptionId(self.next_entity_id().ok_or(RegisterError::IdsExhausted)?);
        let pattern_facts = KeyFacts::of(&pattern);
        // Push first; only consume the id counter on success so a
        // rejected (table-full) registration leaves no id gap.
        self.subscribers
            .push(Subscriber {
                id,
                pattern: key,
                pattern_facts,
                allowed_origin,
                entity,
                sink,
            })
            .map_err(|_| RegisterError::TableFull)?;
        self.consume_entity_id();
        self.epoch = self.epoch.saturating_add(1);
        #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
        if allowed_origin.allows_local() {
            self.local_live
                .fetch_add(1, core::sync::atomic::Ordering::Release);
        }
        Ok(id)
    }

    /// The count of subscribers a local publish can reach, as a handle a reader keeps and
    /// loads without taking the lock that guards this table: `0` means no subscriber of this
    /// process wants a message from it ([`Self::has_local_matching`] would answer `false`),
    /// any other value means the question is open and is answered by it.
    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    pub fn local_live(&self) -> alloc::sync::Arc<core::sync::atomic::AtomicUsize> {
        self.local_live.clone()
    }

    /// Remove a previously-registered subscriber. Returns `true` if
    /// the id was found and removed. Idempotent — calling on an id
    /// that was never registered or already removed returns `false`
    /// without panicking.
    ///
    /// R311y530 / R2292 — what the registry's two reasons to tell a PEER about a
    /// change in the subscription table (a subscription declared after the peer's
    /// interest, an aggregate declaration the last match of which went away) are
    /// staged from is the change, and the change is recorded here once, in the
    /// table's epoch. A [`SubscriberRegistry`], which has one peer, stages them as
    /// it is told ([`SubscriberRegistry::register_sink`]); a table with many peers
    /// leaves each of them to see the epoch move ([`SubscriberPeer::reconcile`]).
    pub fn unregister(&mut self, id: SubscriptionId) -> bool {
        let Some(at) = self.subscribers.iter().position(|s| s.id == id) else {
            return false;
        };
        self.take_at(at).is_some()
    }

    /// Remove the subscription at `at`, in the table's order, and hand its sink back for the
    /// caller to let go of where it chooses: `None` past the table's end. The subscriptions after
    /// it move down, so a walk by position (a replay of the session's declarations) keeps its
    /// order; the epoch moves as [`Self::unregister`]'s does.
    pub fn take_at(&mut self, at: usize) -> Option<C> {
        if at >= self.subscribers.len() {
            return None;
        }
        let removed = self.subscribers.remove(at);
        self.epoch = self.epoch.saturating_add(1);
        #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
        if removed.allowed_origin.allows_local() {
            self.local_live
                .fetch_sub(1, core::sync::atomic::Ordering::Release);
        }
        Some(removed.sink)
    }

    /// The pattern and the sink of the subscription at `at`, in the table's order: the order the
    /// subscriptions were registered in, a removal closing its gap.
    pub fn row_at(&self, at: usize) -> Option<(&str, &C)> {
        self.subscribers
            .get(at)
            .map(|subscriber| (&*subscriber.pattern, &subscriber.sink))
    }

    /// [`Self::row_at`], the sink to write: what its registration could not say yet.
    pub fn row_at_mut(&mut self, at: usize) -> Option<(&str, &mut C)> {
        self.subscribers
            .get_mut(at)
            .map(|subscriber| (&*subscriber.pattern, &mut subscriber.sink))
    }

    /// The place, in the table's order, of the first subscription whose sink `found` picks.
    pub fn position_of(&self, found: impl Fn(&C) -> bool) -> Option<usize> {
        self.subscribers
            .iter()
            .position(|subscriber| found(&subscriber.sink))
    }

    /// Whether one more subscription would be refused for want of a row: the table holds as
    /// many as its limit admits, or its storage has no row left. Asked before anything is taken
    /// for a declaration, so a full table refuses it with nothing spent.
    pub fn is_full(&self) -> bool {
        !self.quota.admits(self.subscribers.len().saturating_add(1))
            || self.subscribers.free_slots() == 0
    }

    /// Number of currently-registered subscribers across all keyexpr
    /// literals.
    pub fn len(&self) -> usize {
        self.subscribers.len()
    }

    /// Whether the registry holds any subscriber.
    pub fn is_empty(&self) -> bool {
        self.subscribers.is_empty()
    }

    /// Route an `IterationEvent` produced by the wz-runtime-tokio
    /// `drive_session_until_terminal` loop
    /// to matching subscriber callbacks. The adapter pulls
    /// `FramePayload.messages` out of `IterationEvent::Poll` and
    /// dispatches each record via [`dispatch`](Self::dispatch),
    /// threading the frame's `reliable` discriminator through so the
    /// downstream `Sample.reliability` carries the link-layer
    /// classification (R226 — zenoh-pico `_z_trigger_push` argument
    /// mirror). `Lease` events and non-FramePayload poll outcomes are
    /// no-ops. Callers use this as the registry's observer callback so
    /// they need not hand-write the `if let Poll(FramePayload { ... })`
    /// matcher at the integration site.
    ///
    /// A Push the in-place receive path lends ([`IterationEvent::InPlace`]) is
    /// delivered here too, as a borrowed sample over the frame's own bytes: the
    /// same subscribers, the same projection, the same self-echo rule, and no
    /// heap for a Put whose keyexpr fits (see `pubsub::in_place`).
    ///
    /// S9a — `peer` is the side of the registry the sending peer owns (its
    /// aliases, its interests), passed in so one table serves many sessions; a
    /// [`SubscriberRegistry`] passes its own.
    // Out of line, for the stack: the observer's fan (`SlotObserverOf::dispatch_event_among`)
    // calls each plane in turn, and each plane's temporaries stay in a frame of its own.
    #[inline(never)]
    #[cfg(feature = "storage-profile")]
    pub fn dispatch_iteration_event<Q: Storage>(
        &mut self,
        peer: &mut SubscriberPeer<Q>,
        event: IterationEvent<'_, '_>,
    ) {
        match event {
            #[cfg(feature = "alloc")]
            IterationEvent::Poll(DriverLoopOutcome::FramePayload {
                messages, reliable, ..
            }) => {
                if let Some(messages) = crate::driver_loop::owned_records(messages) {
                    let reliability = Reliability::from_reliable_bool(*reliable);
                    for message in messages {
                        self.dispatch(peer, message, reliability);
                    }
                }
            }
            // A frame of plain Puts, reported as where they lie in it: the stream
            // lane, delivered without an owned message per record. The lane is the copying
            // receive's, which a build whose tables take no owned record does not read by.
            #[cfg(all(feature = "alloc", feature = "pubsub-put"))]
            IterationEvent::Poll(DriverLoopOutcome::FramePlainPuts {
                reliable,
                payload,
                puts,
                ..
            }) => {
                if crate::driver_loop::OWNED_RECORDS {
                    self.dispatch_plain_puts(peer, *reliable, payload, puts);
                }
            }
            // A Push lent where its frame lies, and the control records lent beside
            // it where a build lends them: a Declare's alias is absorbed and a
            // subscriber Interest is answered from the same views.
            #[cfg(any(
                feature = "pubsub-put",
                feature = "pubsub-delete",
                feature = "rx-lent-control"
            ))]
            IterationEvent::InPlace(record) => {
                #[cfg(any(feature = "pubsub-put", feature = "pubsub-delete"))]
                self.dispatch_in_place(peer, &record);
                #[cfg(feature = "rx-lent-control")]
                self.dispatch_in_place_control(peer, &record);
            }
            _ => {}
        }
    }

    /// The control records this registry owns, lent where
    /// their frame lies: a `Declare`'s `DeclKexpr` / `UndeclKexpr` bind and unbind
    /// the peer's keyexpr aliases, and a subscriber `Interest` is answered from this
    /// session's own subscriptions. Both are the owned forms' rules over the
    /// borrowed views ([`SubscriberPeer::absorb_declare_view`],
    /// `respond_to_subscriber_interest_view`); a record of any other kind is another
    /// registry's.
    #[cfg(feature = "rx-lent-control")]
    fn dispatch_in_place_control<Q: Storage>(
        &mut self,
        peer: &mut SubscriberPeer<Q>,
        record: &crate::driver_loop::InPlaceRecord<'_, '_>,
    ) {
        #[cfg(feature = "codec-declare")]
        if let Some(declare) = record.declare() {
            peer.absorb_declare_view(&declare.body);
        }
        #[cfg(feature = "declare-subscriber")]
        if let Some(interest) = record.interest() {
            self.respond_to_subscriber_interest_view(peer, interest);
        }
        // Nothing of either kind is compiled in: the arguments are unread.
        let _ = (&self, &peer, &record);
    }

    /// Route a decoded `NetworkMessage` to matching subscriber
    /// callbacks. R98 routes Push; R121d also processes
    /// `Declare(DeclKexpr / UndeclKexpr)` to maintain the peer
    /// mapping table so a downstream mapping-id Push can be
    /// resolved against it. Other `Declare` sub-variants
    /// (DeclSubscriber, DeclQueryable, DeclToken, etc.) and other
    /// `NetworkMessage` variants are no-ops in this registry's
    /// scope — the AP MVP path only needs Push round-trip.
    ///
    /// `reliability` is the link-layer classification of the frame
    /// that carried this message; it is threaded into Push dispatch so
    /// the resulting `Sample.reliability` reflects the actual delivery
    /// guarantee (R226 — see `dispatch_iteration_event` for the
    /// canonical caller that derives this from
    /// `FramePayload.reliable`). Declare-arm dispatch ignores
    /// `reliability` because the peer-mapping absorb is reliability-
    /// agnostic (declarations always travel on the reliable channel).
    ///
    /// S9a — `peer` is the sending peer's side of the registry; see
    /// [`dispatch_iteration_event`](Self::dispatch_iteration_event).
    #[cfg(feature = "alloc")]
    pub fn dispatch<Q: Storage>(
        &mut self,
        peer: &mut SubscriberPeer<Q>,
        message: &NetworkMessage,
        _reliability: Reliability,
    ) {
        #[cfg(any(feature = "pubsub-put", feature = "pubsub-delete"))]
        let reliability = _reliability;
        match message {
            // R227 — wire-arrived Push carries `is_remote = true` so
            // the locality filter selects `allows_remote()`. The
            // self-publish loopback path (see
            // [`local_publish`](Self::local_publish)) enters
            // [`fire_to_subscribers`](Self::fire_to_subscribers)
            // directly with `is_remote = false`.
            //
            // R311h — the `NetworkMessage::Push` variant is elided when
            // `codec-push` is off. R311dx-pre — the dispatch arm here is
            // gated one level finer, on `any(pubsub-put, pubsub-delete)`:
            // projecting a Push into a Sample needs at least one body op
            // (Put/Del), so a `codec-push`-only build can parse a Push
            // frame but has no body op to interpret it. The arm is then
            // absent and the Push falls through to `_ => {}` (drop),
            // mirroring the `PushOwnedVariant::Default` silent-drop. The
            // loopback path ([`local_publish`](Self::local_publish)) stays
            // unguarded — it does not depend on the wire codec gate.
            #[cfg(any(feature = "pubsub-put", feature = "pubsub-delete"))]
            NetworkMessage::Push(push) => self.dispatch_push(peer, push, reliability, true),
            #[cfg(feature = "codec-declare")]
            NetworkMessage::Declare(decl) => peer.absorb_declare(&decl.body),
            // R311y530 — a remote publisher's SUBSCRIBER Interest. Answered
            // from this session's OWN subscriptions; see
            // [`Self::respond_to_subscriber_interest`].
            #[cfg(feature = "declare-subscriber")]
            NetworkMessage::Interest(interest) => {
                self.respond_to_subscriber_interest(peer, interest)
            }
            _ => {}
        }
        // `peer` is read by every arm that exists; with none compiled in it is
        // not, and the signature is the same in every subset.
        let _ = &peer;
    }

    /// R311y530 — `alloc` inbound-parse entry: consume an inbound
    /// `Interest`, resolve its keyexpr through the peer mapping table, and
    /// funnel into the no-heap
    /// [`Self::respond_to_subscriber_interest_borrowed`].
    ///
    /// No-op unless the interest targets SUBSCRIBERS. A subscriber interest
    /// with no keyexpr is match-all; one naming an undeclared peer mapping id
    /// drops silently (the same policy every sibling registry applies to an
    /// unresolvable wireexpr — firing on a partial keyexpr is worse than not
    /// firing).
    ///
    /// S9a — the keyexpr is resolved into a bounded buffer
    /// ([`resolve_wireexpr_into`]), not a `String`, so on the fixed backing the
    /// whole absorb of an interest allocates nothing; one longer than
    /// [`KeyexprBuf`] holds cannot be remembered and is answered with its
    /// terminating `Final` alone, as an over-long one always was.
    #[cfg(all(feature = "alloc", feature = "declare-subscriber"))]
    fn respond_to_subscriber_interest<Q: Storage>(
        &mut self,
        peer: &mut SubscriberPeer<Q>,
        interest: &InterestOwned,
    ) {
        let SubscriberPeer {
            naming, interests, ..
        } = peer;
        let interest_id = interest.interest_id;
        let (current, future) = (interest.c(), interest.f());
        let Some(body) = crate::interest_build::interest_body(&interest.header_c_or_f) else {
            // No body and neither bit set is zenoh's interest FINAL: the peer
            // is CANCELLING `interest_id` (pico emits exactly this when a
            // declared publisher drops, `net/primitives.c`). Retire the row so
            // a recycled id cannot inherit a dead publisher's keyexpr.
            if !current && !future {
                interests.retire(interest_id);
            }
            return;
        };
        if !body.su() {
            // A queryable / token interest — the query and liveliness planes
            // answer those; this registry holds neither.
            return;
        }
        let mut composed = KeyexprBuf::new();
        let pattern: Option<&str> = match &body.keyexpr {
            Some(w) => match resolve_wireexpr_into(&w.body, naming.spaces(), &mut composed) {
                Ok(Some(p)) => Some(p),
                Ok(None) => return,
                Err(crate::wireexpr_resolve::KeyexprPastBound) => {
                    interests.stage_final_only(self.reply_quota, interest_id);
                    return;
                }
            },
            None => None,
        };
        self.respond_to_interest(interests, interest_id, pattern, body.ag(), current, future);
    }

    /// [`Self::respond_to_subscriber_interest`] for an `Interest` the in-place
    /// receive path lends: the same reading of the interest (a FINAL retires its
    /// row, only a subscriber interest is answered, a keyexpr past the buffer is
    /// answered with the terminating `Final` alone) over the interest as it is
    /// decoded where its frame lies, then the one staging SSOT both forms funnel
    /// into. The keyexpr is resolved by the rule both forms share
    /// ([`crate::wireexpr_resolve::resolve_wireexpr_view`]).
    #[cfg(all(
        feature = "storage-profile",
        feature = "declare-subscriber",
        feature = "rx-lent-control"
    ))]
    fn respond_to_subscriber_interest_view<Q: Storage>(
        &mut self,
        peer: &mut SubscriberPeer<Q>,
        interest: &wz_codecs::lent::Interest<'_>,
    ) {
        let SubscriberPeer {
            naming, interests, ..
        } = peer;
        let interest_id = interest.interest_id;
        let (current, future) = (interest.c(), interest.f());
        let Some(body) = crate::interest_build::interest_body(&interest.header_c_or_f) else {
            if !current && !future {
                interests.retire(interest_id);
            }
            return;
        };
        if !body.su() {
            return;
        }
        let mut composed = KeyexprBuf::new();
        let pattern: Option<&str> = match &body.keyexpr {
            Some(w) => match crate::wireexpr_resolve::resolve_wireexpr_view(
                &w.body,
                naming.spaces(),
                &mut composed,
            ) {
                Ok(Some(p)) => Some(p),
                Ok(None) => return,
                Err(crate::wireexpr_resolve::KeyexprPastBound) => {
                    interests.stage_final_only(self.reply_quota, interest_id);
                    return;
                }
            },
            None => None,
        };
        self.respond_to_interest(interests, interest_id, pattern, body.ag(), current, future);
    }

    /// R311y530 — the no-heap staging SSOT for an inbound SUBSCRIBER
    /// `Interest`, and the reason a zenoh-pico DECLARED publisher can reach
    /// this session at all.
    ///
    /// pico arms a write filter per `z_declare_publisher` and drops every put
    /// LOCALLY until it observes a matching `DeclSubscriber`
    /// (`net/filtering.c`). Two consequences shape this method:
    ///
    /// - **CURRENT** dumps the subscriptions this session already holds. An
    ///   AGGREGATE interest gets ONE reply carrying the INTEREST's keyexpr iff
    ///   any local subscription matches, because the peer associates an
    ///   aggregate interest's replies by `_z_keyexpr_equals`
    ///   (`session/interest.c:274-276`) — answering `demo/**` to an interest on
    ///   `demo/a` decodes fine and matches NOTHING. Non-aggregate gets one
    ///   reply per matching subscription, with the subscription's own keyexpr.
    /// - **FUTURE** registers the interest so a subscription declared LATER is
    ///   pushed to that publisher (`Self::stage_future_subscriber_pushes`).
    ///
    /// The terminating `Final` is staged even with zero replies: a peer whose
    /// CURRENT interest is never terminated keeps the solicitation open, and
    /// "no matching subscriber" is a legitimate answer (its filter correctly
    /// stays ACTIVE and it does not put).
    ///
    /// Returns the number of reply items staged (the `Final` is not counted).
    ///
    /// S9a — `peer` is the asking peer's side, whose interest rows are read and
    /// written and whose staging buffer is filled; the subscription table this
    /// answers from is `self`'s, and one table serves every peer.
    #[cfg(feature = "declare-subscriber")]
    pub fn respond_to_subscriber_interest_borrowed<Q: Storage>(
        &mut self,
        peer: &mut SubscriberPeer<Q>,
        interest_id: u64,
        pattern: Option<&str>,
        aggregate: bool,
        current: bool,
        future: bool,
    ) -> usize {
        self.respond_to_interest(
            &mut peer.interests,
            interest_id,
            pattern,
            aggregate,
            current,
            future,
        )
    }

    /// [`Self::respond_to_subscriber_interest_borrowed`] over the interest side
    /// alone, so the owned entry can hold the keyexpr it resolved out of the
    /// peer's other half while it runs.
    #[cfg(feature = "declare-subscriber")]
    fn respond_to_interest<Q: Storage>(
        &mut self,
        interests: &mut InterestSide<Q>,
        interest_id: u64,
        pattern: Option<&str>,
        aggregate: bool,
        current: bool,
        future: bool,
    ) -> usize {
        if !current && !future {
            // Interest FINAL — a cancellation, not a solicitation.
            interests.retire(interest_id);
            return 0;
        }
        // Register (or refresh) the row FIRST: the CURRENT dump's aggregate
        // reply resolves its keyexpr and its decl id THROUGH this row at drain,
        // so a CURRENT-only interest needs it too. Refreshing rather than
        // stacking keeps pico's `(peer, decl_id)` target dedup meaningful.
        let row_held = if interests
            .rows
            .iter()
            .any(|row| row.interest_id == interest_id)
        {
            true
        } else {
            // Of the interest side's own policy: the row it is kept in is that side's, and so is
            // where the row keeps its key.
            let text = pattern.unwrap_or("**");
            let keyexpr = if self.key_quota.admits(text.len()) {
                interests.keys.key(text).ok()
            } else {
                None
            };
            let Some(keyexpr) = keyexpr else {
                // A keyexpr past the bounded field, or with no room where the side keeps its
                // keys, cannot be replied with anyway; terminate the chain honestly instead of
                // half-answering it. The terminator is a chain of one, staged whole or counted.
                interests.stage_final_only(self.reply_quota, interest_id);
                return 0;
            };
            // R2292 (open-debt item 627) — ONE id space per session, drawn
            // from the SAME counter `register_sink` uses for a
            // `SubscriptionId`. It used to be a second counter that also
            // started at 1, so a session announced an aggregate reply and
            // a routed subscriber under the SAME `DeclSubscriber.id`; the
            // peer's registry is keyed by that id with same-id-replaces,
            // so it saw one declaration where two were sent. Harmless
            // while nothing retracted an aggregate id and NOT harmless
            // once something does — an `UndeclSubscriber(1)` would be
            // ambiguous. Upstream has no such second counter: zenoh draws
            // the simple AND the aggregated resource id from one
            // per-face `next_id`
            // (`zenoh/src/net/routing/hat/broker/interests.rs`
            // @ `local_subs.insert_aggregated_resource`, 1.10.0).
            //
            // The id is consumed only when the row is stored, the same rule
            // `register_sink` keeps, so a refused row leaves no gap. A table
            // that has handed out every id stores no row, as a full one does,
            // and so does a side at the quota the creator stated.
            //
            // A subscription registered from here on is the FUTURE half of this
            // interest: its id is at least the counter AFTER the id the row
            // took. `watermark` is that boundary, for a table that learns of
            // registrations by reading its epoch ([`SubscriberPeer::reconcile`]).
            let stored = self.interest_quota.admits(interests.rows.len() + 1)
                && self.next_entity_id().is_some_and(|decl_id| {
                    interests
                        .rows
                        .push(InboundSubInterest {
                            interest_id,
                            keyexpr,
                            aggregate,
                            aggregate_decl_id: decl_id,
                            watermark: u64::from(decl_id) + 1,
                            #[cfg(feature = "declare-undeclare")]
                            announced: false,
                        })
                        .is_ok()
                });
            if stored {
                self.consume_entity_id();
            } else if future {
                // A full table loses the FUTURE half for this publisher: a
                // subscription declared later is not pushed to it.
                interests.refusals.future_interests =
                    interests.refusals.future_interests.saturating_add(1);
            }
            stored
        };
        if !current {
            return 0;
        }
        // The CURRENT dump is one chain -- its replies, then its `Final` -- and
        // it is staged WHOLE or not at all. Truncating it under a `Final` would
        // tell the peer that the subscriptions it lacks do not exist, which for
        // a pico publisher keeps its write filter shut on a subscriber that is
        // there. So the chain is sized first and refused, counted, if the
        // staging buffer cannot take all of it, by its storage or by the
        // quota the creator stated. On the growable backing with no quota
        // stated the room is unbounded and nothing below refuses.
        let replies = if aggregate {
            if !self.any_subscription_matches(pattern) {
                0
            } else if !row_held {
                // The aggregate reply resolves its keyexpr and decl id THROUGH
                // the row at drain. With no row it would resolve to nothing and
                // the chain would leave as a bare `Final`, the false "nothing
                // matches" the paragraph above refuses to send.
                interests.count_refused_chain();
                return 0;
            } else {
                1
            }
        } else {
            self.subscribers
                .iter()
                .filter(|sub| subscription_matches_interest(&sub.pattern, pattern))
                .count()
        };
        if !interests.has_room(self.reply_quota, replies.saturating_add(1)) {
            interests.count_refused_chain();
            return 0;
        }
        const RESERVED: &str = "room for the whole chain was checked above";
        if aggregate {
            if replies == 1 {
                interests
                    .staged
                    .push(SubInterestReply::Aggregate { interest_id })
                    .expect(RESERVED);
            }
        } else {
            for sub in self.subscribers.iter() {
                if subscription_matches_interest(&sub.pattern, pattern) {
                    interests
                        .staged
                        .push(SubInterestReply::Concrete {
                            interest_id,
                            subscription_id: sub.id.as_u64(),
                        })
                        .expect(RESERVED);
                }
            }
        }
        interests
            .staged
            .push(SubInterestReply::Final { interest_id })
            .expect(RESERVED);
        replies
    }

    /// R311y530 — whether ANY session-local subscription intersects the
    /// interest `pattern` (`None` = match-all).
    #[cfg(feature = "declare-subscriber")]
    fn any_subscription_matches(&self, pattern: Option<&str>) -> bool {
        self.subscribers
            .iter()
            .any(|sub| subscription_matches_interest(&sub.pattern, pattern))
    }

    /// R311y530 — stage an unsolicited `DeclSubscriber` for a subscription
    /// declared AFTER a remote publisher registered its FUTURE interest: the
    /// pub-before-sub half of the write-filter release.
    ///
    /// Without it the ordering decides whether a publisher ever sees the
    /// subscriber, which is exactly the kind of race that reads as a flaky
    /// interop test. Called from [`SubscriberRegistry::register_sink`] so no
    /// declare path can forget it, and for a table with many peers from
    /// [`SubscriberPeer::reconcile`], which finds the same subscriptions by their
    /// ids instead of by being told.
    #[cfg(feature = "declare-subscriber")]
    fn stage_future_subscriber_pushes<Q: Storage>(
        &self,
        interests: &mut InterestSide<Q>,
        new_id: SubscriptionId,
    ) {
        // As many rows as the interest table can hold, in a buffer of its own: a policy whose rows
        // are only lent makes none for itself (`Storage::Scratch`).
        let mut hits: BoundedVec<(u64, bool), { caps::MAX_INBOUND_SUB_INTERESTS }, Q::Scratch> =
            BoundedVec::default();
        {
            // The new subscription's pattern is read back out of the table
            // rather than passed in: `register_sink` has already MOVED it into
            // the row, and `BoundedString` is deliberately not `Clone` (the
            // no-alloc backing is an inline buffer). Both borrows are immutable
            // and end with this block, before the staging push below.
            let Some(sub) = self.subscribers.iter().find(|s| s.id == new_id) else {
                return;
            };
            let new_pattern: &str = &sub.pattern;
            for row in interests.rows.iter() {
                if subscription_matches_interest(new_pattern, Some(&*row.keyexpr))
                    && hits.push((row.interest_id, row.aggregate)).is_err()
                {
                    break;
                }
            }
        }
        for (interest_id, aggregate) in hits.iter().copied() {
            let item = if aggregate {
                SubInterestReply::Aggregate { interest_id }
            } else {
                SubInterestReply::Concrete {
                    interest_id,
                    subscription_id: new_id.as_u64(),
                }
            };
            // NO terminating `Final` here: this is an unsolicited FUTURE push,
            // not a CURRENT dump, and the peer's CURRENT solicitation was
            // already resolved when the interest arrived. A second `Final`
            // would close an interest that is still live.
            interests.stage_announcement(self.reply_quota, item);
        }
    }

    /// R2292 (open-debt item 627) — stage a retraction for every ANNOUNCED
    /// aggregate declaration that no local subscription stands for any more.
    ///
    /// Called after a subscription was retired, so `any_subscription_matches`
    /// already reads the post-removal table: the `1 -> 0` transition is the whole
    /// trigger, exactly as upstream's `Some -> None` on the aggregated resource's
    /// info is.
    ///
    /// A row that was never announced stages nothing, which is what keeps the
    /// declare-rollback path silent — it unregisters a subscription whose
    /// reply was staged and then dropped, so no peer was ever told an id.
    ///
    /// ⚠ MEASURED, R2292: the `any_subscription_matches` test here is a
    /// PRESSURE FILTER, not the correctness guard. Deleting it leaves every
    /// wire assertion green, because `take_aggregate_retract` re-checks the
    /// same predicate at DRAIN time and that is the one a retraction's
    /// truthfulness rests on. What deleting it does cost is the staging
    /// buffer: an unregister that matches no interest would then push one item
    /// per announced aggregate into a `BoundedVec` only for the drain to throw
    /// them away. `an_unrelated_unregister_stages_no_aggregate_retraction` is
    /// the red that keeps this line honest; the wire tests are not.
    #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
    fn stage_emptied_aggregate_retracts<Q: Storage>(&self, interests: &mut InterestSide<Q>) {
        // A buffer of its own, as in `stage_future_subscriber_pushes`.
        let mut hits: BoundedVec<u64, { caps::MAX_INBOUND_SUB_INTERESTS }, Q::Scratch> =
            BoundedVec::default();
        for row in interests.rows.iter() {
            if row.aggregate
                && row.announced
                && !self.any_subscription_matches(Some(&*row.keyexpr))
                && hits.push(row.interest_id).is_err()
            {
                break;
            }
        }
        for interest_id in hits.iter().copied() {
            // A refused retraction leaves the row `announced`, so it is still
            // owed; what is lost is THIS staging of it, and that is counted.
            interests.stage_announcement(
                self.reply_quota,
                SubInterestReply::AggregateRetract { interest_id },
            );
        }
    }

    /// R2292 (open-debt item 627) — resolve a staged
    /// [`SubInterestReply::AggregateRetract`] to the `UndeclSubscriber.id` the
    /// sink should emit, or `None` when it must not be emitted after all.
    ///
    /// The re-check mirrors the AGGREGATE declare arm's
    /// (R2290): a subscription declared between the stage and the drain makes
    /// the aggregate TRUE again, and a retraction announcing otherwise would
    /// be a lie at the moment it is sent. Clearing `announced` here rather
    /// than at stage time is what makes the pair idempotent — two staged
    /// retractions for one interest emit once.
    #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
    pub fn take_aggregate_retract<Q: Storage>(
        &self,
        peer: &mut SubscriberPeer<Q>,
        interest_id: u64,
    ) -> Option<u64> {
        let row = peer
            .interests
            .rows
            .iter_mut()
            .find(|row| row.interest_id == interest_id && row.aggregate && row.announced)?;
        if self.any_subscription_matches(Some(&*row.keyexpr)) {
            return None;
        }
        row.announced = false;
        Some(u64::from(row.aggregate_decl_id))
    }

    /// R311y530 — resolve one staged reply item to the `(subscriber_id,
    /// keyexpr)` pair the sink encodes. `None` when the backing row vanished
    /// between stage and drain (an interest cancelled, or a subscription
    /// dropped): that reply is skipped and its chain's `Final` still
    /// terminates the peer's solicitation.
    ///
    /// R2290 (open-debt item 626) — "or a subscription dropped" is a promise
    /// EVERY announcing arm has to keep, and the AGGREGATE arm did not keep
    /// it. It resolves through the peer's INTEREST row, which an undeclare
    /// never touches, so a reply staged while a subscription matched was
    /// still emitted after that subscription had been undeclared — a
    /// `DeclSubscriber` announcing a subscription this session no longer has.
    /// On the wire that lands AFTER the undeclare's `UndeclSubscriber` (the
    /// staging is on the drive thread, the undeclare on the application's),
    /// so the peer re-inserts the entry it has just been told to drop and its
    /// matching verdict flips back to `true` and stays there until the link
    /// dies. Measured as a 1-2% `wz-capi-pico` `matching_multiface` failure
    /// delivering `[true, false, true, false]` where `[true, false]` is the
    /// contract.
    ///
    /// The re-check is the SAME predicate the staging used
    /// (`any_subscription_matches` over the interest's keyexpr — a code span,
    /// not a link: it is private, and a doc link to it is a BROKEN one this
    /// crate's Layer C1bz budget counts), for the
    /// same reason the `Concrete` arm re-resolves through `subscribers`:
    /// what a reply announces has to be true when it is SENT, not when it was
    /// queued.
    ///
    /// TWO live routes retire a subscription inside that window, and only one
    /// of them was the flake. `Subscriber::teardown` is now atomic with its
    /// wire retract (wz-runtime-tokio), which closes that one at the source.
    /// The other is the DECLARE ROLLBACK: `declare_subscriber` registers
    /// locally FIRST — which stages a future-push reply against any standing
    /// interest — and unregisters again when the wire announce is rejected, so
    /// a reply can outlive a subscription that was never announced at all.
    /// Nothing makes that path atomic, which is why this arm is a live guard
    /// rather than a belt on a closed hazard.
    ///
    /// S9a — the interest row an `Aggregate` resolves through is the asking
    /// peer's (`peer`); the subscription a `Concrete` resolves through is the
    /// table's.
    #[cfg(feature = "declare-subscriber")]
    pub fn sub_interest_reply<'a, Q: Storage>(
        &'a self,
        peer: &'a SubscriberPeer<Q>,
        item: &SubInterestReply,
    ) -> Option<(u64, &'a str)> {
        match item {
            SubInterestReply::Aggregate { interest_id } => peer
                .interests
                .rows
                .iter()
                .find(|row| row.interest_id == *interest_id)
                .filter(|row| self.any_subscription_matches(Some(&*row.keyexpr)))
                .map(|row| (u64::from(row.aggregate_decl_id), &*row.keyexpr)),
            SubInterestReply::Concrete {
                subscription_id, ..
            } => self
                .subscribers
                .iter()
                .find(|sub| sub.id.as_u64() == *subscription_id)
                .map(|sub| (sub.id.as_u64(), &*sub.pattern)),
            SubInterestReply::Final { .. } => None,
            // R2292 — a retraction is not a reply: it resolves through
            // `take_aggregate_retract`, which needs `&mut self` to clear the
            // announced flag. Answering `None` here is the honest projection,
            // not a skip.
            #[cfg(feature = "declare-undeclare")]
            SubInterestReply::AggregateRetract { .. } => None,
        }
    }

    /// Project a wire-decoded `Push` into a [`Sample`] and route it
    /// through [`fire_to_subscribers`](Self::fire_to_subscribers).
    /// `is_remote` discriminates wire-arrived dispatch
    /// ([`Locality::allows_remote`](crate::locality::Locality)) from
    /// self-publish loopback
    /// ([`Locality::allows_local`](crate::locality::Locality)) — the
    /// projection + locality + pattern-match path is otherwise
    /// byte-identical, so the wz subscriber surface sees the same
    /// `Sample` shape regardless of origin (R227).
    ///
    /// Mirrors zenoh-pico's `_z_handle_network_message` dispatch
    /// lattice: a wire-arrived Push and a loopback Push converge on
    /// the same subscriber-side handler
    /// (`vendor/zenoh-pico/src/session/loopback.c` 70-100 calls
    /// `_z_handle_network_message` with a wz-equivalent
    /// `is_remote = false` semantic).
    #[cfg(any(feature = "pubsub-put", feature = "pubsub-delete"))]
    #[cfg(feature = "alloc")]
    fn dispatch_push<Q: Storage>(
        &mut self,
        peer: &SubscriberPeer<Q>,
        push: &PushOwned,
        reliability: Reliability,
        is_remote: bool,
    ) {
        // R121d / R311gl CLEANUP-2 — resolve the Push's keyexpr against
        // the peer mapping table via the shared `resolve_wireexpr` SSOT
        // (the same resolver the four remote-declare registries + the
        // switchboard consume). Composition rule: id==0 → suffix
        // verbatim; id!=0 → table[id] + optional suffix. `None` means
        // either the empty (id=0, suffix=None) form or an id the peer
        // never declared — drop silently rather than fire on a partial
        // keyexpr (R125c2: the tagged-union arms are folded inside the
        // resolver; both carry the same id + Option<suffix> fields).
        // R311y739 — resolved against BOTH id spaces: an `M=0` alias names an id
        // WE declared and is answered out of the installed own space, never out
        // of the peer's (both sides number from 1, so the wrong space would very
        // likely FIND an entry and fire the wrong subscriber).
        let resolved: String = match resolve_wireexpr_in(&push.keyexpr.body, peer.mapping_spaces())
        {
            Some(r) => r,
            None => {
                // R3041 -- a Put that cannot be routed has still ARRIVED, and
                // the shared-memory slices it carries are owed their release
                // and their acknowledgement: upstream un-swaps a message in
                // `trigger_callback` BEFORE it hands the message to the
                // routing callback (`io/zenoh-transport/src/unicast/universal/rx.rs`
                // @ `map_zmsg_to_shmbuf`), so a message routing then refuses has
                // already been read and is dropped with its buffers released.
                // Returning here without that would leave the sender holding
                // every such buffer, confirmed, until the transport ends.
                #[cfg(all(feature = "transport-shm", feature = "pubsub-put"))]
                self.settle_unrouted_shm(push);
                return;
            }
        };

        // R222 / R225 — project the decoded Push into a Sample once
        // per dispatch_push. R222 handled the three load-bearing
        // fields (keyexpr / kind / payload); R225 extends the
        // projection to surface body-level timestamp + encoding
        // (already decoded inline by MsgPut / MsgDel), outer-level
        // QoS (Push.extensions, ext_id=0x01 ZInt), and body-level
        // attachment + source_info (MsgPut/MsgDel.extensions,
        // ext_id=0x03 ZBuf and ext_id=0x01 ZBuf respectively). The
        // canonical zenoh-pico subscriber path
        // (`_z_trigger_subscriptions_impl`) consumes a complete
        // `_z_sample_t`; this projection brings parity so wz
        // subscribers no longer need to dig into Push.extensions or
        // MsgPut.extensions to inspect Sample metadata.
        //
        // Encoding is Put-only on the wire: zenoh-pico's _Z_FLAG_Z_P_E
        // lives in `_z_msg_put_t` but not `_z_msg_del_t`, so the Del
        // arm fills None for encoding. Reliability is filled with the
        // zenoh-pico default Reliable — transport-context wire-up so
        // wz can surface the actual link-layer reliability is an R226+
        // carry (Sample::with_reliability is the surface the future
        // wire-up will use).
        //
        // PushVariant::Default { .. } is the catalog's fallback arm
        // for unknown body tags (RFC variant-default-uniformity).
        // We drop the dispatch silently — surfacing such a body
        // through a Sample callback with arbitrary `tag` would
        // semantically lie about the kind (it is neither a
        // confirmed Put nor a confirmed Del).
        // R311cc — pubsub-put / pubsub-delete arm cfg gates the wire
        // Put / Del body branches. cfg-off routes the corresponding
        // variant to the silent-drop `_ =>` fall-through, matching the
        // PushVariant::Default behavior (subscriber callback not fired).
        // pubsub-attachment / pubsub-timestamp / pubsub-source-info gate
        // the per-arm projection helpers — fields stay declared on Sample
        // for signature stability (R311g1); cfg-off populator returns None.
        // With pubsub-source-info off the subscriber never decodes the
        // source_info ext, so self-echo dedup (R231) cannot engage and the
        // dispatch falls back to the cautious-fire default — the same
        // behaviour as a wire sample that simply carries no source_info.
        let (kind, payload, body_timestamp, body_encoding, body_attachment, body_source_info) =
            match &push.body {
                #[cfg(feature = "pubsub-put")]
                PushOwnedVariant::CodecZenohMsgPut(put) => {
                    let body_exts: &[crate::wire::parts::ExtEntryOwned] =
                        crate::put_payload::chain(put);
                    #[cfg(feature = "pubsub-timestamp")]
                    let body_timestamp = put.timestamp.as_ref().map(TimestampHint::from_codec);
                    #[cfg(not(feature = "pubsub-timestamp"))]
                    let body_timestamp: Option<TimestampHint> = None;
                    #[cfg(feature = "pubsub-attachment")]
                    let body_attachment =
                        decode_attachment_ext_shared(body_exts, ATTACHMENT_EXT_ID_PUSH);
                    #[cfg(not(feature = "pubsub-attachment"))]
                    let body_attachment: Option<crate::link::RxBytes> = {
                        let _ = body_exts;
                        None
                    };
                    #[cfg(feature = "pubsub-source-info")]
                    let body_source_info = extract_source_info(body_exts);
                    #[cfg(not(feature = "pubsub-source-info"))]
                    let body_source_info: Option<crate::sample::SourceInfo> = {
                        let _ = body_exts;
                        None
                    };
                    // pubsub-encoding gate: with the feature off the subscriber
                    // never projects the inline encoding field, so Sample.encoding
                    // stays None — mirroring a wire Put that simply carries no
                    // encoding. Symmetric to the send-side `gated_encoding_field`.
                    #[cfg(feature = "pubsub-encoding")]
                    let body_encoding = put.encoding.as_ref().map(EncodingHint::from_codec);
                    #[cfg(not(feature = "pubsub-encoding"))]
                    let body_encoding: Option<EncodingHint> = None;
                    // transport-shm — the RX un-swap: if the body carries the 0x2
                    // ext_shm marker, the payload field is a DESCRIPTOR (not data);
                    // decode it + resolve the segment off /dev/shm via the
                    // AP-injected resolver. A stale / foreign descriptor, or no
                    // resolver installed, drops the Sample (the scoped lifecycle:
                    // the owner backs the segment until the round-trip completes).
                    // Absent the marker, the inline-bytes path is byte-identical.
                    //
                    // The marker in the chain is what makes the payload sliced
                    // (`put_payload`): the codec reads the slice list instead
                    // of a length and bytes, so "carries the marker" and "has
                    // slices" are one fact, and a slice of kind SHM_PTR is the
                    // descriptor this branch resolves.
                    #[cfg(feature = "transport-shm")]
                    let put_payload = if crate::put_payload::is_sliced(put) {
                        match self.unswap_shm_payload(push, put) {
                            Some(bytes) => bytes,
                            None => return,
                        }
                    } else {
                        // The inline layout never fails: no slice, no descriptor.
                        crate::put_payload::collect_wire_payload(put, |_| None)
                            .unwrap_or_else(|_| crate::link::RxBytes::from(alloc::vec::Vec::new()))
                    };
                    // Without the shared-memory transport there is no resolver to
                    // ask, so a sliced Put can only be delivered when every slice
                    // is plain bytes; one that names a segment is dropped rather
                    // than delivered as the descriptor it carries.
                    #[cfg(not(feature = "transport-shm"))]
                    let put_payload = match crate::put_payload::collect_wire_payload(put, |_| None)
                    {
                        Ok(bytes) => bytes,
                        Err(_) => return,
                    };
                    (
                        SampleKind::Put,
                        put_payload,
                        body_timestamp,
                        body_encoding,
                        body_attachment,
                        body_source_info,
                    )
                }
                #[cfg(feature = "pubsub-delete")]
                PushOwnedVariant::CodecZenohMsgDel(del) => {
                    let body_exts: &[crate::wire::parts::ExtEntryOwned] =
                        del.extensions.entries().unwrap_or(&[]);
                    #[cfg(feature = "pubsub-timestamp")]
                    let body_timestamp = del.timestamp.as_ref().map(TimestampHint::from_codec);
                    #[cfg(not(feature = "pubsub-timestamp"))]
                    let body_timestamp: Option<TimestampHint> = None;
                    // R2370 — the DEL id (0x02) on a Del body, not the Put's
                    // 0x03. Emit and decode were BOTH the Put id, which is
                    // exactly why the round-trip test passed over a wrong wire
                    // byte: the two ids encode identically, so only a test that
                    // NAMES the id can tell them apart, and none did.
                    #[cfg(feature = "pubsub-attachment")]
                    let body_attachment = decode_attachment_ext_shared(
                        body_exts,
                        crate::attachment::ATTACHMENT_EXT_ID_DEL,
                    );
                    #[cfg(not(feature = "pubsub-attachment"))]
                    let body_attachment: Option<crate::link::RxBytes> = {
                        let _ = body_exts;
                        None
                    };
                    #[cfg(feature = "pubsub-source-info")]
                    let body_source_info = extract_source_info(body_exts);
                    #[cfg(not(feature = "pubsub-source-info"))]
                    let body_source_info: Option<crate::sample::SourceInfo> = {
                        let _ = body_exts;
                        None
                    };
                    (
                        SampleKind::Del,
                        crate::link::RxBytes::from(alloc::vec::Vec::new()),
                        body_timestamp,
                        None,
                        body_attachment,
                        body_source_info,
                    )
                }
                _ => return,
            };
        let outer_exts: &[crate::wire::parts::ExtEntryOwned] =
            push.extensions.entries().unwrap_or(&[]);
        // R311em / R311y307 — the outer QoS extension is a single packed
        // byte (priority / congestion-control / express are bit views of
        // the same _z_qos_t._val), so the subscriber-side projection gates
        // on the one `pubsub-qos` compile unit that owns the ext. Off, the
        // build never decodes the QoS ext and Sample.qos stays None (field
        // declared for signature stability, R311g1).
        //
        // The projection is all-or-nothing BY DESIGN: a decoded byte is
        // recorded exactly as the peer sent it, never per-field masked. The
        // bits already arrived; rewriting one to a local default would make
        // wz report a QoS the peer never sent — a divergence from zenoh and
        // zenoh-pico that the all-features-on cross-impl proofs could never
        // observe. Absence (`None`) is honest; a fabricated value is not.
        // This is why the three sub-fields cannot be separately gated here.
        #[cfg(feature = "pubsub-qos")]
        let qos = extract_qos(outer_exts);
        #[cfg(not(feature = "pubsub-qos"))]
        let qos: Option<crate::sample::QosLevel> = {
            let _ = outer_exts;
            None
        };
        // R311di-4 — Sample lives in wz-session-core (non_exhaustive)
        // so wz-runtime-tokio composes via the constructor + with_*
        // chain. The build order mirrors the prior struct-literal
        // shape (kind-dispatched constructor + every applicable
        // optional setter); semantics are byte-identical.
        let mut sample = match kind {
            SampleKind::Put => Sample::new_put_shared(resolved, payload),
            SampleKind::Del => Sample::new_del(resolved),
        };
        if let Some(ts) = body_timestamp {
            sample = sample.with_timestamp(ts);
        }
        if let Some(enc) = body_encoding {
            sample = sample.with_encoding(enc);
        }
        if let Some(q) = qos {
            sample = sample.with_qos(q);
        }
        // The timestamp stack of an instrumented message: the nodes it crossed recorded on it.
        #[cfg(feature = "pubsub-ts-stack")]
        if let Some(stack) = crate::ts_stack::read_ts_stack(outer_exts.iter()) {
            sample = sample.with_ts_stack(stack);
        }
        if let Some(att) = body_attachment {
            sample = sample.with_attachment_shared(att);
        }
        if let Some(si) = body_source_info {
            sample = sample.with_source_info(si);
        }
        sample = sample.with_reliability(reliability);
        #[cfg(feature = "pubsub-ts-stack")]
        {
            sample = sample.with_routed(is_remote);
        }

        // R231 — self-echo dedup. When this dispatch is on the
        // wire-arrival path (is_remote=true) AND the decoded sample
        // carries a source_info matching this session's own zid
        // prefix (equal length AND equal bytes), the sample is a
        // mesh / router echo of a publish we just issued; firing it
        // here would double-invoke any Locality::Any subscriber that
        // already fired on the loopback path. Suppress all callbacks
        // for this dispatch.
        //
        // Cautious defaults: dedup is skipped when own_zid is unset,
        // when source_info is absent, when source_info's prefix is
        // empty (sentinel / malformed record), or when is_remote is
        // false (loopback is the authoritative source — no dedup
        // needed and applying it here would silently suppress
        // legitimate fires). Length equality is required so a
        // 4-byte own_zid does not falsely match an 8-byte peer zid
        // that happens to share the first 4 bytes.
        if is_remote {
            if let (Some(own), Some(info)) = (peer.own_zid(), sample.source_info.as_ref()) {
                let prefix = info.zid_prefix();
                if !prefix.is_empty() && prefix == own {
                    return;
                }
            }
        }

        self.fire_to_subscribers(&sample, is_remote, peer.class);
    }

    /// The receive-side un-swap of a sliced Put, at the priority the push was sent
    /// at: [`ShmReceiveState::unswap_put`](crate::extshm::ShmReceiveState::unswap_put),
    /// which holds the negotiation check, the read and the acknowledgement. `None`
    /// is a counted drop; `Some` is the assembled payload.
    ///
    /// R3041 -- one entry for the two places that owe the same thing and must not
    /// drift apart: the delivery path in [`dispatch_push`](Self::dispatch_push), and
    /// [`settle_unrouted_shm`](Self::settle_unrouted_shm) for a Put whose keyexpr
    /// routing then refuses.
    #[cfg(all(feature = "alloc", feature = "transport-shm", feature = "pubsub-put"))]
    fn unswap_shm_payload(
        &mut self,
        push: &PushOwned,
        put: &wz_codecs::msg_put::MsgPutOwned<crate::wire::WireStorage>,
    ) -> Option<crate::link::RxBytes> {
        let band = push_priority_band(push);
        self.shm.unswap_put(put, band)
    }

    /// Settle the shared-memory slices of a Put that routing cannot deliver
    /// (its keyexpr names an id the peer never declared, or is empty): read
    /// each, which releases the reference its sender took for this receiver, and
    /// acknowledge each, then let the bytes go. A Put with no slice has nothing
    /// to settle and costs nothing: the inline layout is not touched.
    #[cfg(all(feature = "alloc", feature = "transport-shm", feature = "pubsub-put"))]
    fn settle_unrouted_shm(&mut self, push: &PushOwned) {
        if let PushOwnedVariant::CodecZenohMsgPut(put) = &push.body {
            if crate::put_payload::is_sliced(put) {
                let _ = self.unswap_shm_payload(push, put);
            }
        }
    }

    /// Apply the locality filter + keyexpr pattern match against every
    /// registered subscriber and fire the callbacks that pass. Returns
    /// the count of callbacks that fired so loopback callers can
    /// verify delivery (the wire-path caller discards the count).
    ///
    /// R227 — the single source of truth for subscriber filtering.
    /// Both `dispatch_push` (wire path) and
    /// [`local_publish`](Self::local_publish) (self-publish loopback)
    /// converge here so the locality + pattern-match invariants are
    /// enforced exactly once. Mirrors zenoh-pico's
    /// `_z_trigger_subscriptions_impl`
    /// (`vendor/zenoh-pico/src/session/subscription.c`), which is the
    /// single trigger both wire-arrived
    /// (`_z_handle_network_message → _z_trigger_local_subscriptions`)
    /// and loopback
    /// (`_z_session_deliver_push_locally → _z_handle_network_message`)
    /// paths converge on.
    ///
    /// `is_remote` selects the locality predicate:
    /// `true`  → [`Locality::allows_remote`](crate::locality::Locality)
    /// `false` → [`Locality::allows_local`](crate::locality::Locality).
    /// Subscribers pinned to
    /// [`Locality::Any`](crate::locality::Locality) (the
    /// [`register`](Self::register) default) pass either predicate
    /// and so fire on both origins.
    /// R311gb (Track 2) — no-heap fire entry: match `view`'s keyexpr
    /// against every subscription and deliver the borrowed
    /// [`SampleView`] to each matching sink, applying the locality
    /// filter. Borrow-driven (no owned `Sample` materialization), so it
    /// is the MCU no-heap delivery path; the AP wire path
    /// (`dispatch_push`) funnels its owned
    /// `Sample` through the same matcher via the `Sample: SampleView`
    /// coercion (one matching SSOT). Returns the count of sinks fired.
    pub fn dispatch_borrowed(&mut self, view: &dyn SampleView, is_remote: bool) -> usize {
        self.fire_to_subscribers(view, is_remote, None)
    }

    /// [`Self::dispatch_borrowed`] for a message from a peer whose declared class is `class`: what a
    /// closed image that declares its peers must call, since without a class a message from a peer is
    /// allowed nothing.
    pub fn dispatch_borrowed_from(
        &mut self,
        view: &dyn SampleView,
        class: Option<ClassId>,
    ) -> usize {
        self.fire_to_subscribers(view, true, class)
    }

    fn fire_to_subscribers(
        &mut self,
        view: &dyn SampleView,
        is_remote: bool,
        class: Option<ClassId>,
    ) -> usize {
        match self.admission(view.keyexpr(), is_remote, class) {
            Admission::Refused => return 0,
            Admission::Numbered(key) => {
                if let Some(fired) =
                    self.deliver_by_selection(key, view.keyexpr(), |sink| sink.deliver(view))
                {
                    return fired;
                }
            }
            Admission::Matched => {}
        }
        fire_into_memoized(
            &mut self.subscribers,
            &mut self.memo,
            self.epoch,
            view.keyexpr(),
            is_remote,
            false,
            |sink| sink.deliver(view),
        )
    }

    /// Deliver a message on a numbered key of the closed key set to the subscribers its
    /// selection names, or `None` when this gate holds no table to select from (a gate set open
    /// after it numbered the key). A build without the `key-set-closed` feature has no number to
    /// read and always answers `None`, and the call is not compiled.
    #[inline]
    fn deliver_by_selection(
        &mut self,
        key: KeyId,
        text: &str,
        deliver: impl FnMut(&mut C),
    ) -> Option<usize> {
        #[cfg(feature = "key-set-closed")]
        {
            let catalogue = self.key_gate.catalogue()?;
            Some(fire_by_selection(
                &mut self.subscribers,
                catalogue,
                key,
                text,
                deliver,
            ))
        }
        #[cfg(not(feature = "key-set-closed"))]
        {
            let _ = (key, text, deliver);
            None
        }
    }

    /// [`Self::fire_to_subscribers`] for a plain `Put` of a frame
    /// ([`crate::sink::PlainSample`]): the same matcher and memory, and each matching sink
    /// is handed the sample through [`SampleSink::deliver_plain`], which a sink that can
    /// keep a range of the frame instead of a copy of the sample answers more cheaply than
    /// [`SampleSink::deliver`].
    #[cfg(all(feature = "alloc", feature = "pubsub-put"))]
    fn fire_plain_to_subscribers(
        &mut self,
        sample: &crate::sink::PlainSample<'_>,
        is_remote: bool,
        class: Option<ClassId>,
    ) -> usize {
        match self.admission(sample.keyexpr(), is_remote, class) {
            Admission::Refused => return 0,
            Admission::Numbered(key) => {
                if let Some(fired) = self
                    .deliver_by_selection(key, sample.keyexpr(), |sink| sink.deliver_plain(sample))
                {
                    return fired;
                }
            }
            Admission::Matched => {}
        }
        fire_into_memoized(
            &mut self.subscribers,
            &mut self.memo,
            self.epoch,
            sample.keyexpr(),
            is_remote,
            sample.repeats_previous_key(),
            |sink| sink.deliver_plain(sample),
        )
    }
}

/// What the key gate said of a message.
enum Admission {
    /// Dropped: the key is outside the closed key set.
    Refused,
    /// Not looked up: an open table, or a message of the application's own. Delivered by matching.
    Matched,
    /// A key of the closed key set, by number. Delivered by the selection of that key.
    Numbered(KeyId),
}

/// Deliver a peer's message on a key of the closed key set to the subscribers its selection
/// names: for each row in registration order, whether the row's entity is in the selection, an
/// integer search, and no pattern is matched. Registration order is what every delivery
/// promises, which is why the rows are walked and the selection is asked, and not the other way.
///
/// A row that has no entity (made before the table was given, and not declared by it) is matched
/// by its pattern, as `scan_subscribers` matches it, so no subscription is left without messages.
#[cfg(feature = "key-set-closed")]
fn fire_by_selection<C: SampleSink, P: Storage>(
    subscribers: &mut BoundedVec<Subscriber<C, P>, { caps::MAX_SUBSCRIPTIONS }, P>,
    catalogue: &crate::key_catalogue::KeyCatalogue<'_>,
    key: KeyId,
    text: &str,
    mut deliver: impl FnMut(&mut C),
) -> usize {
    let selection = catalogue.selection(key, EntityKind::Subscriber);
    let mut fired = 0usize;
    for subscriber in subscribers.iter_mut() {
        if !subscriber.allowed_origin.allows_remote() {
            continue;
        }
        let reached = match subscriber.entity {
            Some(entity) => selection.contains(entity),
            None => keyexpr_intersects_text(&subscriber.pattern, text),
        };
        if reached {
            deliver(&mut subscriber.sink);
            fired = fired.saturating_add(1);
        }
    }
    fired
}

/// How many distinct keys a `MatchMemo` of policy `P` remembers at once, where its creator
/// states `stated` (`MATCH_MEMO_SLOTS`). A table that grows with the allocator holds the stated
/// count, its slots filling as keys arrive; a table of fixed size holds every slot in RAM from the
/// start and so holds its own count, `MATCH_MEMO_FIXED_SLOTS`, which the build sizes and which is
/// `0` unless the image asks for the memory. Zero leaves the memory out, and every message is
/// matched afresh.
const fn memo_slots<P: Storage>(stated: usize) -> usize {
    // A table whose rows are lent at open holds none: each slot is rows of its own (its key and
    // its hits), which only the arena that lends the table could give it.
    if P::LENT_AT_OPEN {
        0
    } else if P::ENFORCES_CAPACITY {
        caps::MATCH_MEMO_FIXED_SLOTS
    } else {
        stated
    }
}

/// One remembered key: which subscribers it matched, under which table state.
struct MemoSlot<P: Storage> {
    /// The table epoch the answer was worked out at.
    epoch: u64,
    /// The locality the answer was worked out for: wire-arrived and local-origin
    /// deliveries filter on different sides of a subscriber's `allowed_origin`.
    remote: bool,
    /// The key. Where the policy fixes capacity it holds `MATCH_MEMO_KEY_BYTES`, and a longer key
    /// is not remembered (it is matched each time it arrives).
    key: BoundedString<{ caps::MATCH_MEMO_KEY_BYTES }, P>,
    /// The positions in the subscriber table, ascending, of the subscribers that matched.
    hits: BoundedVec<u16, { caps::MAX_SUBSCRIPTIONS }, P>,
}

// A slot keeps a position in 16 bits. A table of a build that enforces capacity holds at most
// `MAX_SUBSCRIPTIONS` rows, so where it has slots every position it can hold fits one, and no key
// it matches is left out of the cache for the position of a match (`fire_into_memoized`).
const _: () = assert!(
    !crate::bounded::ENFORCES_CAPACITY
        || caps::MATCH_MEMO_FIXED_SLOTS == 0
        || caps::MAX_SUBSCRIPTIONS <= u16::MAX as usize + 1,
    "MAX_SUBSCRIPTIONS is at most 65536 on a fixed-capacity build with MATCH_MEMO_FIXED_SLOTS: \
     the receive match cache keeps a subscriber's position in a u16"
);

/// A small direct-mapped memory of which subscribers a key matched, so that the key arriving
/// again (a stream's every message carries the same one) is delivered without splitting it and
/// every subscription's pattern on `/` and intersecting them, which was the larger part of what
/// delivering a sample cost once it was decoded.
///
/// Zenoh keeps the same answer in the resource a key resolves to (its `Resource::matches`),
/// invalidated by the routing tables' version; here the table's `epoch` is
/// that version, and it moves on every registration and every retirement, the only two
/// writers of the subscriber list. An entry carries the epoch it was made at and is read only
/// at that one, so a subscription added or retired between two messages is seen by the second.
///
/// Written once for both storage policies: the slots are a [`BoundedVec`], so a heap table fills
/// `MATCH_MEMO_SLOTS` of them and a fixed table holds `MATCH_MEMO_FIXED_SLOTS` inline, and a
/// fixed table with none holds nothing at all.
struct MatchMemo<P: Storage> {
    slots: BoundedVec<Option<MemoSlot<P>>, { caps::MATCH_MEMO_FIXED_SLOTS }, P>,
    /// How many times a slot was written. A repeated key may be answered from the slot the key
    /// before it was, but only while no slot has been written since.
    writes: u64,
    /// The slot the last delivery was answered from, and `writes` as it was then; `None` when
    /// that delivery was not answered from a slot at all (a key too deep to match).
    last: Option<(usize, u64)>,
}

impl<P: Storage> MatchMemo<P> {
    /// A memory of `memo_slots::<P>(stated)` empty slots.
    fn new(stated: usize) -> Self {
        let mut slots = BoundedVec::default();
        for _ in 0..memo_slots::<P>(stated) {
            // A fixed table's capacity is its slot count, so this never refuses.
            let _ = slots.push(None);
        }
        Self {
            slots,
            writes: 0,
            last: None,
        }
    }

    /// How many slots the memory holds: the count it was made with. A fixed table's is the
    /// build's, decided when the build is compiled.
    fn slot_count(&self) -> usize {
        memo_slots::<P>(self.slots.len())
    }

    /// The slot `key` maps to: a hash of its bytes (FNV-1a, which is a handful of
    /// instructions per byte and has no setup), folded to the table's size.
    fn slot_of(&self, key: &str) -> usize {
        let mut hash: u32 = 0x811c_9dc5;
        for byte in key.as_bytes() {
            hash ^= u32::from(*byte);
            hash = hash.wrapping_mul(0x0100_0193);
        }
        // `max(1)` only keeps the remainder defined where there are no slots: nothing reaches
        // this function then (see `fire_into_memoized`).
        (hash ^ (hash >> 15)) as usize % self.slot_count().max(1)
    }
}

/// Deliver a key to the subscribers it matches, over the subscriber table alone so that a caller
/// holding other fields of the registry borrowed (the in-place delivery, whose keyexpr may be the
/// peer table's own literal) can fire with them still borrowed. A key remembered at this epoch
/// is delivered to the subscribers it matched without being matched again; any other key is
/// matched by `scan_subscribers`, and what it matched is remembered where a slot can hold it.
///
/// The subscribers fired and the order they fire in are the scan's: the matched positions
/// are kept ascending, which is the table's order.
///
/// `repeats_previous` is the caller's word that `key` is the key of the delivery just before this
/// one (the next record of a frame naming the same key). Then, when that delivery was answered
/// from a slot and no slot has been written nor the table changed since, this one is answered
/// from the same slot without hashing the key or comparing it again; anything else is looked up
/// as usual.
fn fire_into_memoized<C: SampleSink, P: Storage>(
    subscribers: &mut BoundedVec<Subscriber<C, P>, { caps::MAX_SUBSCRIPTIONS }, P>,
    memo: &mut MatchMemo<P>,
    epoch: u64,
    key: &str,
    is_remote: bool,
    repeats_previous: bool,
    mut deliver: impl FnMut(&mut C),
) -> usize {
    // No slots: the memory is out, and the message is matched by the scan alone.
    if memo.slot_count() == 0 {
        return scan_subscribers(subscribers, key, is_remote, deliver, |_| {}).unwrap_or(0);
    }
    if repeats_previous {
        if let Some((at, writes)) = memo.last {
            if writes == memo.writes {
                if let Some(slot) = &memo.slots[at] {
                    if slot.epoch == epoch && slot.remote == is_remote {
                        for position in slot.hits.iter() {
                            if let Some(subscriber) = subscribers.get_mut(usize::from(*position)) {
                                deliver(&mut subscriber.sink);
                            }
                        }
                        return slot.hits.len();
                    }
                }
            }
        }
    }
    memo.last = None;
    let at = memo.slot_of(key);
    if let Some(slot) = &memo.slots[at] {
        if slot.epoch == epoch && slot.remote == is_remote && slot.key == key {
            memo.last = Some((at, memo.writes));
            for position in slot.hits.iter() {
                if let Some(subscriber) = subscribers.get_mut(usize::from(*position)) {
                    deliver(&mut subscriber.sink);
                }
            }
            return slot.hits.len();
        }
    }
    // Not remembered at this epoch: match it with the scan, noting each hit. A key
    // that cannot be matched at all (deeper than the bound) delivers to nobody and is not
    // remembered.
    let mut hits: BoundedVec<u16, { caps::MAX_SUBSCRIPTIONS }, P> = BoundedVec::default();
    let mut every_hit_noted = true;
    let Some(fired) = scan_subscribers(subscribers, key, is_remote, deliver, |position| {
        // A slot keeps a position in 16 bits. A heap table can grow past that, and a position
        // cut to fit would name another subscriber, so a key that matched one there is
        // delivered by this scan and not remembered (a table of a fixed-capacity build never
        // holds one; see the assertion beside `MatchMemo`).
        match u16::try_from(position) {
            Ok(position) => {
                // At most one position per subscriber, and the table holds `MAX_SUBSCRIPTIONS`.
                let _ = hits.push(position);
            }
            Err(_) => every_hit_noted = false,
        }
    }) else {
        return 0;
    };
    if !every_hit_noted {
        return fired;
    }
    // A key longer than a fixed slot holds is delivered as matched and not remembered; the slot
    // it would have taken keeps what it had.
    let mut text: BoundedString<{ caps::MATCH_MEMO_KEY_BYTES }, P> = BoundedString::default();
    if text.push_str(key).is_err() {
        return fired;
    }
    memo.slots[at] = Some(MemoSlot {
        epoch,
        remote: is_remote,
        key: text,
        hits,
    });
    memo.writes += 1;
    memo.last = Some((at, memo.writes));
    fired
}

/// The one matcher: every subscriber whose locality admits the origin and whose pattern
/// intersects `keyexpr` is handed to `deliver`, in the table's order, and its position in the
/// table to `hit`. Returns how many matched, or `None` for a key deeper than the matcher's bound,
/// which is delivered to nobody (a caller that remembers answers does not remember this one).
///
/// Every route to a subscriber reaches it: the borrowed delivery, the plain one and the
/// receive match cache's refill, so what a message reaches does not depend on which.
fn scan_subscribers<C: SampleSink, P: Storage>(
    subscribers: &mut BoundedVec<Subscriber<C, P>, { caps::MAX_SUBSCRIPTIONS }, P>,
    keyexpr: &str,
    is_remote: bool,
    mut deliver: impl FnMut(&mut C),
    mut hit: impl FnMut(usize),
) -> Option<usize> {
    #[cfg(test)]
    MATCH_SCANS.with(|scans| scans.set(scans.get() + 1));
    let mut fired: usize = 0;
    // R2662 (open-debt item 763) — THE ARRIVING KEYEXPR MAY ITSELF BE A
    // PATTERN, so each subscriber is INTERSECTED against it. A one-sided
    // match that compares a subscriber pattern against the arriving key as a
    // LITERAL lets a `demo/*` Put match the subscriber `demo/*` character-for-
    // character and miss `demo/a` — upstream's subscriber rule is
    // intersection, and a real zenoh-pico client does send such keys
    // (`wz_storage_wildcard_update_pico_interop` fires `demo/**` and the
    // storage plane applies it, so they ARRIVE and must be delivered).
    //
    // ⛔ FOR A CONCRETE ARRIVING KEY INTERSECTION IS THE ONE-SIDED MATCH —
    // the argument `query.rs` @ `fn matches` records for the QUERY plane.
    // So this widens delivery to the wildcard case and changes nothing about
    // the concrete one.
    //
    // The arriving key is read once for the whole table, and each pattern was read when it
    // registered: a pattern and a key that hold no wildcard are compared as text, and only a
    // wildcard on either side walks them, which zenoh-pico's matcher does too
    // (`vendor/zenoh-pico/src/session/keyexpr.c` @ `fast path for identical key expressions`).
    let facts = KeyFacts::of(keyexpr);
    // Over-depth arriving key on the fixed backing: delivered to nobody and
    // answered `None`, so a caller that remembers answers does not remember
    // it. The matcher would refuse it for every subscriber anyway; the depth
    // is counted here only for that answer, and only for a key the facts do not
    // already place within the bound.
    if crate::bounded::ENFORCES_CAPACITY
        && !facts.is_key()
        && keyexpr.split('/').count() > MAX_KEYEXPR_CHUNKS
    {
        return None;
    }
    for (position, subscriber) in subscribers.iter_mut().enumerate() {
        let pass = if is_remote {
            subscriber.allowed_origin.allows_remote()
        } else {
            subscriber.allowed_origin.allows_local()
        };
        if !pass {
            continue;
        }
        // R2662 — the subscriber's pattern is the CANDIDATE; the matcher
        // applies the fixed backing's depth bound to it, the same defensive
        // over-depth skip every scan inherits from the one seam.
        if keyexpr_intersects_text_with(
            &subscriber.pattern,
            subscriber.pattern_facts,
            keyexpr,
            facts,
        ) {
            // R311gb-2b — deliver via the DIP seam (borrowed view,
            // no projection step). On MCU `C` is a closed `enum`
            // whose `deliver` injects; on AP a `BoxedSink` closure.
            deliver(&mut subscriber.sink);
            hit(position);
            fired = fired.saturating_add(1);
        }
    }
    Some(fired)
}

/// The sample a Put or a Del the wire carried inline is, with everything the message says
/// of it beside its payload: the timestamp and the encoding of the body, its attachment and
/// source, the QoS of the push, and the timestamp stack the nodes it crossed recorded on it.
///
/// What `SubscriberTable::dispatch_push` projects, for a reader that holds no table of
/// subscribers and resolves no key: the key is the one the reader names, and the payload is
/// copied out of the message. A Put whose payload names a segment of shared memory is `None`,
/// since there is no reader to resolve it. `routed` says whether the message came from a face.
#[cfg(all(
    feature = "alloc",
    any(feature = "pubsub-put", feature = "pubsub-delete")
))]
pub fn sample_of_inline_push(
    push: &PushOwned,
    keyexpr: &str,
    reliability: Reliability,
    routed: bool,
) -> Option<Sample> {
    sample_of_push(push, keyexpr, reliability, routed, &mut |put| {
        Some(crate::link::RxBytes::from(
            crate::put_payload::inline_bytes(put)?.to_vec(),
        ))
    })
}

/// [`sample_of_inline_push`] for a reader that knows how to read the payload of a Put: a Put
/// whose payload names a segment of shared memory is the sample `payload_of` makes of it, and
/// `None` when it makes none.
#[cfg(all(
    feature = "alloc",
    any(feature = "pubsub-put", feature = "pubsub-delete")
))]
pub fn sample_of_push(
    push: &PushOwned,
    keyexpr: &str,
    reliability: Reliability,
    routed: bool,
    payload_of: &mut dyn FnMut(
        &wz_codecs::msg_put::MsgPutOwned<crate::wire::WireStorage>,
    ) -> Option<crate::link::RxBytes>,
) -> Option<Sample> {
    // Only a Put has a payload to read; a build with the delete alone never calls it.
    #[cfg(not(feature = "pubsub-put"))]
    let _ = payload_of;
    let (mut sample, timestamp, encoding, attachment, source_info) = match &push.body {
        #[cfg(feature = "pubsub-put")]
        PushOwnedVariant::CodecZenohMsgPut(put) => {
            let exts: &[crate::wire::parts::ExtEntryOwned] = crate::put_payload::chain(put);
            let payload = payload_of(put)?;
            #[cfg(feature = "pubsub-timestamp")]
            let timestamp = put.timestamp.as_ref().map(TimestampHint::from_codec);
            #[cfg(not(feature = "pubsub-timestamp"))]
            let timestamp: Option<TimestampHint> = None;
            #[cfg(feature = "pubsub-encoding")]
            let encoding = put.encoding.as_ref().map(EncodingHint::from_codec);
            #[cfg(not(feature = "pubsub-encoding"))]
            let encoding: Option<EncodingHint> = None;
            #[cfg(feature = "pubsub-attachment")]
            let attachment = decode_attachment_ext_shared(exts, ATTACHMENT_EXT_ID_PUSH);
            #[cfg(not(feature = "pubsub-attachment"))]
            let attachment: Option<crate::link::RxBytes> = None;
            #[cfg(feature = "pubsub-source-info")]
            let source_info = extract_source_info(exts);
            #[cfg(not(feature = "pubsub-source-info"))]
            let source_info: Option<crate::sample::SourceInfo> = None;
            #[cfg(not(any(feature = "pubsub-attachment", feature = "pubsub-source-info")))]
            let _ = exts;
            (
                Sample::new_put_shared(keyexpr, payload),
                timestamp,
                encoding,
                attachment,
                source_info,
            )
        }
        #[cfg(feature = "pubsub-delete")]
        PushOwnedVariant::CodecZenohMsgDel(del) => {
            let exts: &[crate::wire::parts::ExtEntryOwned] =
                del.extensions.entries().unwrap_or(&[]);
            #[cfg(feature = "pubsub-timestamp")]
            let timestamp = del.timestamp.as_ref().map(TimestampHint::from_codec);
            #[cfg(not(feature = "pubsub-timestamp"))]
            let timestamp: Option<TimestampHint> = None;
            #[cfg(feature = "pubsub-attachment")]
            let attachment =
                decode_attachment_ext_shared(exts, crate::attachment::ATTACHMENT_EXT_ID_DEL);
            #[cfg(not(feature = "pubsub-attachment"))]
            let attachment: Option<crate::link::RxBytes> = None;
            #[cfg(feature = "pubsub-source-info")]
            let source_info = extract_source_info(exts);
            #[cfg(not(feature = "pubsub-source-info"))]
            let source_info: Option<crate::sample::SourceInfo> = None;
            #[cfg(not(any(feature = "pubsub-attachment", feature = "pubsub-source-info")))]
            let _ = exts;
            (
                Sample::new_del(keyexpr),
                timestamp,
                None,
                attachment,
                source_info,
            )
        }
        _ => return None,
    };
    let outer: &[crate::wire::parts::ExtEntryOwned] = push.extensions.entries().unwrap_or(&[]);
    if let Some(timestamp) = timestamp {
        sample = sample.with_timestamp(timestamp);
    }
    if let Some(encoding) = encoding {
        sample = sample.with_encoding(encoding);
    }
    #[cfg(feature = "pubsub-qos")]
    if let Some(qos) = extract_qos(outer) {
        sample = sample.with_qos(qos);
    }
    #[cfg(feature = "pubsub-ts-stack")]
    if let Some(stack) = crate::ts_stack::read_ts_stack(outer.iter()) {
        sample = sample.with_ts_stack(stack);
    }
    #[cfg(not(any(feature = "pubsub-qos", feature = "pubsub-ts-stack")))]
    let _ = outer;
    if let Some(attachment) = attachment {
        sample = sample.with_attachment_shared(attachment);
    }
    if let Some(source_info) = source_info {
        sample = sample.with_source_info(source_info);
    }
    sample = sample.with_reliability(reliability);
    #[cfg(feature = "pubsub-ts-stack")]
    {
        sample = sample.with_routed(routed);
    }
    #[cfg(not(feature = "pubsub-ts-stack"))]
    let _ = routed;
    Some(sample)
}

// How many times `scan_subscribers` ran on this thread: a message answered from the receive
// match cache is not scanned, one that is not answered from it is. A test reads the difference.
#[cfg(test)]
std::thread_local! {
    static MATCH_SCANS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

impl<C: SampleSink, P: Storage> SubscriberTable<C, P> {
    /// R311y788 — the SESSION-LOCAL half of a publisher's matching
    /// status: `true` iff at least one subscriber registered on THIS
    /// session would receive a local publish on `publish_keyexpr`.
    ///
    /// Two filters, both of them the ones
    /// [`local_publish`](Self::local_publish) already applies, so a
    /// `true` here means a real delivery rather than a mere table entry:
    /// the subscriber's own `allowed_origin` must permit a local origin
    /// (a `Locality::Remote` subscriber is not a matching target for its
    /// own session's publisher), and the two keyexprs must INTERSECT as
    /// patterns — both sides may be wildcards, which is why this is
    /// [`keyexpr_intersects`] and not the one-sided
    /// [`keyexpr_matches`], which reads its target as a literal key.
    ///
    /// This is zenoh-pico's local-target count rather than zenoh's:
    /// pico gates on the subscriber's `_allowed_origin` before counting
    /// (`vendor/zenoh-pico/src/net/filtering.c:386-397`), while zenoh
    /// reads only the keyexpr (`zenoh/src/api/session.rs:1876-1897`) and
    /// so can report a match no local publish would reach. `P=` for the
    /// matching atom is pico, and the stricter answer is also the one
    /// that agrees with this registry's own delivery rule.
    ///
    /// The PUBLISHER-side locality gate is the caller's, exactly as it
    /// is for [`local_publish`](Self::local_publish) — pico's
    /// `ctx->allow_local` (`filtering.c:66`, `:127`).
    #[cfg(feature = "storage-profile")]
    pub fn has_local_matching(&self, publish_keyexpr: &str) -> bool {
        // Nothing here a local publish could reach: answer before the key is taken apart. A
        // publisher with no subscriber in its own process asks this once per message.
        if !self
            .subscribers
            .iter()
            .any(|subscriber| subscriber.allowed_origin.allows_local())
        {
            return false;
        }
        // On the fixed backing a keyexpr or a pattern deeper than the
        // chunk bound matches nothing; the matcher applies that bound.
        self.subscribers.iter().any(|subscriber| {
            subscriber.allowed_origin.allows_local()
                && keyexpr_intersects(&subscriber.pattern, publish_keyexpr)
        })
    }

    /// R227 — self-publish loopback entry point. Routes `sample`
    /// through the same locality + pattern-match dispatch as a
    /// wire-arrived Push, but with `is_remote = false` so subscribers
    /// pinned to [`Locality::SessionLocal`](crate::locality::Locality)
    /// fire and subscribers pinned to
    /// [`Locality::Remote`](crate::locality::Locality) are suppressed.
    /// [`Locality::Any`](crate::locality::Locality) subscribers (the
    /// default for [`register`](Self::register)) fire on both wire and
    /// loopback origins. Returns the number of subscriber callbacks
    /// that fired so the caller can assert loopback delivery in a
    /// test or wire it into an observability counter in production.
    ///
    /// The caller constructs the [`Sample`] through
    /// [`Sample::new_put`](crate::sample::Sample::new_put) /
    /// [`Sample::new_del`](crate::sample::Sample::new_del) plus
    /// optional `with_*` setters; the registry does not synthesize
    /// wire-shape metadata for the loopback path because an
    /// application performing loopback already owns every field it
    /// just published. This keeps the loopback API a thin Rust idiom
    /// over zenoh-pico's
    /// `_z_session_deliver_push_locally`
    /// (`vendor/zenoh-pico/src/session/loopback.c` 70-100) without
    /// imposing the codec wire-shape on in-process callers.
    ///
    /// The publisher-side locality check (zenoh-pico's
    /// `allowed_destination.allows_local()` in
    /// `vendor/zenoh-pico/src/net/primitives.c` 198-202) is the
    /// caller's responsibility: only invoke `local_publish` when the
    /// publisher's locality permits a local delivery. The registry's
    /// `is_remote = false` branch then filters on the subscriber-side
    /// locality so the Any/Remote/SessionLocal contract holds for
    /// every receiver.
    #[cfg(feature = "alloc")]
    pub fn local_publish(&mut self, sample: &Sample) -> usize {
        self.fire_to_subscribers(sample, false, None)
    }
}

/// The peer's side of the registry: the operations that read and write only what
/// ONE peer owns, which is all of them that do not also need the subscription
/// table.
impl<P: Storage> Default for SubscriberPeer<P> {
    fn default() -> Self {
        Self {
            #[cfg(feature = "storage-profile")]
            naming: PeerNaming {
                aliases: PeerAliases::<P>::default(),
                alias_quota: crate::limits::MaxPeerKeyexprAliasesHeld::build_default(),
                key_quota: crate::limits::MaxKeyexprBytesHeld::build_default(),
                keys: Default::default(),
                #[cfg(feature = "alloc")]
                own_mapping_space: None,
                #[cfg(feature = "shared-key-ids")]
                shared_key_ids: None,
                own_zid: None,
            },
            #[cfg(feature = "declare-subscriber")]
            interests: InterestSide::default(),
            class: None,
            _policy: core::marker::PhantomData,
        }
    }
}

impl SubscriberPeer<crate::bounded::Static> {
    /// An empty side of the static policy, for a session that has heard nothing yet.
    /// `const`, so a session slot that holds one can be a `static`.
    pub const fn new_static() -> Self {
        Self {
            #[cfg(feature = "storage-profile")]
            naming: PeerNaming {
                aliases: crate::id_map::FixedIdMap::new(),
                alias_quota: crate::limits::MaxPeerKeyexprAliasesHeld::build_default(),
                key_quota: crate::limits::MaxKeyexprBytesHeld::build_default(),
                keys: crate::bounded::InlineKeys,
                #[cfg(feature = "alloc")]
                own_mapping_space: None,
                #[cfg(feature = "shared-key-ids")]
                shared_key_ids: None,
                own_zid: None,
            },
            #[cfg(feature = "declare-subscriber")]
            interests: InterestSide::new_static(),
            class: None,
            _policy: core::marker::PhantomData,
        }
    }
}

impl SubscriberPeer<Lent> {
    /// An empty side whose staging (`staged` rows) is lent from `arena`. Refused when it is over
    /// the build's capacity or the arena has not the room. The alias table and the interest table
    /// keep their rows in the session's pools they are handed (`keep_alias_rows_in`,
    /// `keep_interest_rows_in`) and their keys in the key arena it is handed (`keep_keys_in`), and
    /// refuse what the peer asks before.
    pub fn lent(arena: &mut Arena, staged: usize) -> Result<Self, LendRefused> {
        let mut side = Self::default();
        side.lend_rows(arena, staged)?;
        Ok(side)
    }

    /// Lend an empty side its staging (`staged` rows) from `arena`, where it lies: what
    /// [`Self::lent`] makes, without the side being a value of its own. Refused as `lent` is.
    ///
    /// The key arena and the rows of interests the side was handed stay its own: lending its
    /// staging before or after it was handed them keeps the interests' keys and rows in them.
    #[cfg(feature = "declare-subscriber")]
    pub fn lend_rows(&mut self, arena: &mut Arena, staged: usize) -> Result<(), LendRefused> {
        self.interests.staged = arena.lend(staged)?;
        Ok(())
    }

    /// Nothing to lend: a build without `declare-subscriber` keeps no interest of the peer.
    #[cfg(not(feature = "declare-subscriber"))]
    pub fn lend_rows(&mut self, _arena: &mut Arena, _staged: usize) -> Result<(), LendRefused> {
        Ok(())
    }

    /// The bytes of an arena [`Self::lent`] takes. `None` past the address space.
    #[cfg(feature = "declare-subscriber")]
    pub const fn arena_bytes(staged: usize) -> Option<usize> {
        InterestSide::<Lent>::arena_bytes(staged)
    }

    /// The bytes of an arena [`Self::lent`] takes: none without `declare-subscriber`.
    #[cfg(not(feature = "declare-subscriber"))]
    pub const fn arena_bytes(_staged: usize) -> Option<usize> {
        Some(0)
    }

    /// Keep the aliases the peer declares from here on in rows of `space`, the session's: a pool the
    /// faces share, or a span of this table's own; the aliases held elsewhere are forgotten first.
    #[cfg(all(feature = "storage-profile", feature = "peer-row-pools"))]
    pub fn keep_alias_rows_in(
        &mut self,
        space: crate::row_pool::RowSpace<crate::row_pool::Keyed<crate::key_arena::KeyRef>>,
    ) {
        self.naming.aliases.keep_rows_in(space);
    }

    /// Keep the interests the peer asks from here on in rows `rows` hands out, the session's: a
    /// pool the faces share, or a span of this side's own if no table took it before; the
    /// interests held elsewhere are forgotten first. Rows with nothing left to hand change nothing.
    #[cfg(all(feature = "declare-subscriber", feature = "peer-row-pools"))]
    pub fn keep_interest_rows_in(&mut self, rows: &mut InterestRows) {
        if let Some(space) = rows.0.hand_out() {
            self.interests.rows.keep_rows_in(space);
        }
    }
}

impl SubscriberPeer<Profile> {
    /// An empty side of this build's storage profile, for a session that has heard
    /// nothing yet. `const` where the profile is the static policy, so a session slot
    /// that holds one can be a `static`.
    #[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
    pub const fn new() -> Self {
        Self::new_static()
    }

    /// An empty side of this build's storage profile, for a session that has heard
    /// nothing yet.
    #[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<P: Storage> SubscriberPeer<P> {
    /// Forget everything the peer said: the aliases it declared, the interests it
    /// registered and what was staged to it. What the session itself installed
    /// (its own id space and zid) stays, because it is the session's and not the
    /// peer's. Done in place, because a session slot's side is large and a fresh
    /// value built on the stack to be moved in would cost the stack its size.
    ///
    /// The counted refusals are kept: they say what the peer asked for and was
    /// told no to over the life of the table, not what it holds now.
    pub fn forget_peer(&mut self) {
        #[cfg(feature = "storage-profile")]
        self.naming.aliases.reset();
        #[cfg(feature = "declare-subscriber")]
        self.interests.forget();
        // The next peer on this slot is not known to be the last one.
        self.class = None;
    }

    /// Say which declared peer this session's peer is, once its zid is known:
    /// `PeerAllowance::class_of` of the zid, or `None`
    /// for a peer the image does not declare. A closed image that declares its peers allows a message
    /// from a peer with no class nothing; an image that declares none ignores the class. Forgotten with
    /// the peer ([`Self::forget_peer`]).
    pub fn set_class(&mut self, class: Option<ClassId>) {
        self.class = class;
    }

    /// The declared peer this session's peer was said to be, `None` when none was.
    pub const fn class(&self) -> Option<ClassId> {
        self.class
    }

    /// R311y739 — install OUR id space, the `M=0` half of the pair.
    ///
    /// Call once at bring-up with the session's own outbound-mapping surface
    /// (`Session::new` does it automatically from its `SessionLinkActions`); the
    /// registry then answers an `M=0` alias out of the right table instead of
    /// dropping the message. Idempotent — a second install replaces the first,
    /// which is what a session re-init wants.
    ///
    /// The sibling of `set_shm_resolver`: an AP-injected capability the no_std
    /// core cannot construct for itself. (Named rather than linked — that method
    /// is `transport-shm`-gated, so a link would dangle in every subset without
    /// the feature, and this one is only `alloc`-gated.)
    ///
    /// R311y740 — the handle type is the per-profile
    /// [`SharedOwnMappingSpace`] (AP `Arc<dyn .. + Send + Sync>`, ARMv6-M
    /// `Rc<dyn ..>`), so an MCU profile can install the very `Rc` bundle
    /// handle it already holds. (Bare label: the alias is imported into this
    /// module, so an explicit target is a `redundant_explicit_link_target`
    /// error under this workspace's deny-warnings docs policy.)
    #[cfg(feature = "alloc")]
    pub fn set_own_mapping_space(&mut self, space: SharedOwnMappingSpace) {
        self.naming.own_mapping_space = Some(space);
    }

    /// R311y739 — release the installed own space; `M=0` aliases refuse again.
    /// Paired with [`set_own_mapping_space`](Self::set_own_mapping_space) for
    /// session teardown / re-init, exactly as `clear_own_zid` pairs its install.
    #[cfg(feature = "alloc")]
    pub fn clear_own_mapping_space(&mut self) {
        self.naming.own_mapping_space = None;
    }

    /// Install the key ids every node of the deployment shares: from now on an id that neither
    /// the peer's space nor ours holds is read in the dictionary, on every plane that resolves
    /// through [`Self::mapping_spaces`]. Installed by the engine that opened the session, before
    /// its link carries anything; a second install replaces the first.
    #[cfg(feature = "shared-key-ids")]
    pub fn set_shared_key_ids(&mut self, ids: crate::shared_key_ids::SharedKeyIds) {
        self.naming.shared_key_ids = Some(ids);
    }

    /// Release the installed dictionary: an id neither declared space holds resolves to
    /// nothing again.
    #[cfg(feature = "shared-key-ids")]
    pub fn clear_shared_key_ids(&mut self) {
        self.naming.shared_key_ids = None;
    }

    /// R311y739 — BOTH id spaces, for this registry and for every consumer the
    /// observer fans the table into.
    ///
    /// R311y750 (carry N38) — this is the ONLY way out of this registry to
    /// either id space. There used to be a second, weaker one beside it
    /// (`peer_keyexpr_table`, which lent the bare peer map), and handing a
    /// consumer that map hands it a resolver silently refusing every `M=0`
    /// alias — the defect R311y739 exists to remove. It survived that round on
    /// a justification that was not merely unused but IMPOSSIBLE: it was kept
    /// "for the caller that binds INTO the peer's space", and it lends a `&`,
    /// so no caller could ever have bound through it. `absorb_declare` reaches
    /// the field, as it always did. A consumer that must READ the raw peer half
    /// now goes through [`MappingSpaces::peer`], which cannot be reached
    /// without first holding the pair.
    #[cfg(feature = "storage-profile")]
    pub fn mapping_spaces(&self) -> MappingSpaces<'_> {
        self.naming.spaces()
    }

    /// R237 — single-id resolver mirroring R234
    /// `SessionLinkActions::resolve_outbound_mapping` (wz-runtime-tokio).
    /// Returns the literal keyexpr the peer declared for `id`, or
    /// `None` if no `DeclKexpr` for `id` has arrived (or an
    /// `UndeclKexpr` retracted it).
    ///
    /// The cross-registry zero-clone path is [`Self::mapping_spaces`] (R311y739
    /// widened it to the PAIR, and R311y750 made it the only door); this
    /// single-id form is the ergonomic application-facing surface for
    /// callers that only need one resolution per call site and
    /// prefer an owned `String` over keeping the registry borrow
    /// live. It reads the PEER half by name and by contract — an inbound
    /// `M=0` alias is not its question and is not silently answered here.
    /// Mirrors zenoh-pico's `_z_get_resource_by_id` lookup on
    /// the inbound side
    /// (`vendor/zenoh-pico/src/session/resource.c`).
    ///
    /// The returned `String` is a clone of the table entry so the
    /// caller can drop the registry borrow before further use — the
    /// alternative (returning `&str`) would tie the registry lock
    /// (or the registry borrow lifetime) to every downstream
    /// operation, which is the same trade-off the outbound mirror
    /// makes intentionally.
    #[cfg(feature = "alloc")]
    pub fn resolve_inbound_mapping(&self, id: crate::wire_id::ExprId) -> Option<String> {
        self.naming
            .aliases
            .find(crate::wire_id::peer_key(id))
            .map(|text| String::from(&text[..]))
    }

    /// How many keyexpr aliases the peer has declared and not retracted.
    #[cfg(feature = "storage-profile")]
    pub fn alias_count(&self) -> usize {
        self.naming.aliases.count()
    }

    /// Hold the peer's alias table to the `MAX_PEER_KEYEXPR_ALIASES` the creator of the
    /// session's tables resolved: a `DeclKexpr` for a NEW id that would leave more aliases than
    /// `quota` admits is refused and counted as a full table refuses it
    /// ([`Self::alias_refusals`]), and the aliases already held are kept, as a lowered soft
    /// limit keeps what it holds.
    #[cfg(feature = "storage-profile")]
    pub fn limit_aliases_to(&mut self, quota: crate::limits::MaxPeerKeyexprAliasesHeld) {
        self.naming.alias_quota = quota;
    }

    /// Hold the peer's alias table to the `MAX_KEYEXPR_BYTES` the creator of the session's
    /// tables resolved: a `DeclKexpr` whose keyexpr is longer than `quota` admits is dropped, as
    /// one longer than a fixed row holds is, and the aliases already held are kept.
    #[cfg(feature = "storage-profile")]
    pub fn limit_keys_to(&mut self, quota: crate::limits::MaxKeyexprBytesHeld) {
        self.naming.key_quota = quota;
    }

    /// The quota the peer's alias keyexprs are held to (`MAX_KEYEXPR_BYTES`): what the creator
    /// of the session's tables stated ([`Self::limit_keys_to`]), the build's value until it did.
    #[cfg(feature = "storage-profile")]
    pub fn key_quota(&self) -> crate::limits::MaxKeyexprBytesHeld {
        self.naming.key_quota
    }

    /// Keep the keys of the aliases the peer declares from here on in `keys`: the session's key
    /// arena, on the lent policy. The aliases already held keep theirs.
    #[cfg(feature = "storage-profile")]
    pub fn keep_keys_in(&mut self, keys: P::Keys) {
        #[cfg(feature = "declare-subscriber")]
        {
            self.interests.keys = keys.clone();
        }
        self.naming.keys = keys;
    }

    /// The quota the peer's alias table is held to (`MAX_PEER_KEYEXPR_ALIASES`): what the
    /// creator of the session's tables stated ([`Self::limit_aliases_to`]), the build's value
    /// until it did.
    #[cfg(feature = "storage-profile")]
    pub fn alias_quota(&self) -> crate::limits::MaxPeerKeyexprAliasesHeld {
        self.naming.alias_quota
    }

    /// How many `DeclKexpr` for a NEW id this side refused because its alias
    /// table was full ([`caps::MAX_PEER_KEYEXPR_ALIASES`]) or held the quota its
    /// creator stated ([`Self::limit_aliases_to`]). Zero on the growable backing
    /// while no quota is stated, as its room refuses nothing.
    #[cfg(feature = "storage-profile")]
    pub fn alias_refusals(&self) -> u32 {
        self.naming.aliases.refusals()
    }

    /// R231 — install this session's own zid (1..=16 bytes) so
    /// [`SubscriberTable::dispatch`] can recognise and
    /// suppress wire-arrived self-echoes. The wire-form `_z_id_t`
    /// range is `1..=16` bytes; this setter rejects out-of-range
    /// inputs (returns `false`) without mutating state so a buggy
    /// caller cannot silently disable dedup with an invalid value.
    /// Returns `true` on a successful install, `false` on an
    /// invalid length.
    ///
    /// Production deployment path: the session-FSM open handshake
    /// completes with both sides' zids known (zenoh-pico's
    /// `_z_session_t._local_zid` slot); the wz session-FSM should
    /// forward its own zid here once the handshake settles. The
    /// integration is currently caller-driven (see the wz-runtime-tokio
    /// `Session::set_own_zid`); an auto-wire from
    /// the session-FSM completion event is an R232+ carry.
    #[cfg(feature = "storage-profile")]
    pub fn set_own_zid_bytes(&mut self, zid: &[u8]) -> bool {
        if !(1..=16).contains(&zid.len()) {
            return false;
        }
        let mut own: BoundedVec<u8, 16, Static> = BoundedVec::default();
        for byte in zid {
            // At most 16 were admitted above, so the fixed backing has room.
            if own.push(*byte).is_err() {
                return false;
            }
        }
        self.naming.own_zid = Some(own);
        true
    }

    /// R231 — release the previously-installed own zid (e.g. on
    /// session close or re-init). Subsequent dispatches behave as
    /// if `set_own_zid` had never been called: no self-echo dedup,
    /// every wire-arrived Push fires its matching subscribers.
    #[cfg(feature = "storage-profile")]
    pub fn clear_own_zid(&mut self) {
        self.naming.own_zid = None;
    }

    /// R231 — expose the currently-installed own zid for diagnostic
    /// and test purposes. Returns the same slice that
    /// [`SubscriberTable::dispatch`] compares against
    /// `source_info.zid_prefix()`.
    #[cfg(feature = "storage-profile")]
    pub fn own_zid(&self) -> Option<&[u8]> {
        self.naming.own_zid.as_deref()
    }

    /// R121d — absorb a `Declare` envelope's inner body so the
    /// peer mapping table tracks the peer's locally-declared
    /// keyexpr aliases. Only `DeclKexpr` and `UndeclKexpr` are
    /// processed; the other Declare sub-variants are routed to
    /// their dedicated registries elsewhere in the runtime and
    /// must not mutate the keyexpr table.
    ///
    /// R218 — every `DeclareVariant` arm is matched explicitly so
    /// that adding a new arm in the upstream codec catalog
    /// surfaces as a compile error here rather than a silent
    /// miss. The intentional no-op arms cite the dedicated
    /// registry that owns each Declare sub-type.
    ///
    /// R311gb (Track 2) — `all(codec-declare, alloc)`-gated: it mutates
    /// the `alloc`-gated alias table via the `alloc`
    /// `resolve_wireexpr`, so a `codec-declare`-without-`alloc` profile
    /// elides it (its sole caller `dispatch` is already `alloc`-gated).
    ///
    /// S9a — a `DeclKexpr` for a NEW id with the alias table full, or at the quota
    /// its creator stated ([`Self::limit_aliases_to`]), is REFUSED and
    /// counted ([`Self::alias_refusals`]), never grown for: the alias is not
    /// recorded, and a later message that names it resolves to nothing and is
    /// dropped, which is what any message naming an id the peer never declared
    /// has always been. A peer that re-declares an id it holds is replacing, and
    /// needs no room.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub(crate) fn absorb_declare(&mut self, body: &DeclareOwnedVariant) {
        match body {
            DeclareOwnedVariant::CodecZenohDeclKexpr(d) => {
                // Resolve the declared keyexpr to a literal string,
                // following the same composition rule as Push
                // resolution (id==0 → suffix verbatim; id!=0 →
                // table[id] + suffix). If the inner reference is
                // unresolvable we skip — recording a partial entry
                // would later mis-fire subscriber matches.
                // R311y739 — the INNER reference resolves against both spaces
                // (the peer may alias an id it learned from us), while the
                // BINDING `d.id -> literal` goes into the peer's space and only
                // there: `d.id` is a number the PEER minted. Bound to a `let`
                // before the insert so the immutable spaces borrow ends first.
                //
                // R2385 — through `resolve_declared_keyexpr`, not
                // `resolve_wireexpr_in`. Both spaces were already reachable
                // here, but the ARM decided which one was read, and on
                // `D_KEXPR` the arm is a decoder constant rather than a wire
                // bit: bit 6 of that header is Reserved, so wz pinned the
                // `WireexprLocal` (peer's-space) arm and a zenoh peer's scope —
                // which names an id WE declared — resolved to nothing.
                //
                // S9a — resolved into a bounded buffer and bound from it, so
                // the fixed backing does the whole absorb without the heap.
                let mut composed = KeyexprBuf::new();
                let literal = match resolve_declared_keyexpr_into(
                    &d.keyexpr.body,
                    self.naming.spaces(),
                    &mut composed,
                ) {
                    Ok(Some(literal)) => literal,
                    // Unresolvable, or too long for the table's text.
                    Ok(None) | Err(_) => return,
                };
                // Past the quota or a row's text the alias is dropped; with no room where the rows
                // keep their keys it is dropped and counted with the alias table's refusals, as
                // zenoh-pico drops one its heap cannot hold.
                let text =
                    match key_text_within::<P>(&self.naming.keys, literal, self.naming.key_quota) {
                        Ok(text) => text,
                        Err(crate::bounded::KeyUnkept::TooLong) => return,
                        Err(crate::bounded::KeyUnkept::NoRoom) => {
                            self.naming.aliases.count_refused();
                            return;
                        }
                    };
                // A refusal, for want of room or past the quota, is counted by the
                // table itself; the declaration that did not fit is dropped here, with
                // the peer none the wiser.
                let quota = self.naming.alias_quota;
                let _ = self.naming.aliases.bind_within(
                    crate::wire_id::declared_peer_key(d.id),
                    text,
                    |count| quota.admits(count),
                );
            }
            DeclareOwnedVariant::CodecZenohUndeclKexpr(u) => {
                self.naming
                    .aliases
                    .unbind(crate::wire_id::declared_peer_key(u.id));
            }
            // DeclSubscriber / UndeclSubscriber are observed by
            // `crate::declare::subscriber::DeclSubscriberRegistry`
            // so the runtime can fire user callbacks on peer
            // subscriber lifecycle — not a keyexpr-table concern.
            DeclareOwnedVariant::CodecZenohDeclSubscriber(_)
            | DeclareOwnedVariant::CodecZenohUndeclSubscriber(_) => {}
            // DeclQueryable / UndeclQueryable are observed by
            // `crate::declare::queryable::QueryableRegistry` so
            // the runtime can fire user callbacks on peer
            // queryable lifecycle — not a keyexpr-table concern.
            DeclareOwnedVariant::CodecZenohDeclQueryable(_)
            | DeclareOwnedVariant::CodecZenohUndeclQueryable(_) => {}
            // DeclToken / UndeclToken are observed by
            // `crate::declare::liveliness::TokenRegistry` for the
            // peer liveliness layer — not a keyexpr-table concern.
            DeclareOwnedVariant::CodecZenohDeclToken(_)
            | DeclareOwnedVariant::CodecZenohUndeclToken(_) => {}
            // DeclFinal is the terminator marker zenoh emits after
            // an initial declaration burst. No side effects in
            // this registry — the runtime's session glue tracks
            // the marker separately if it cares about burst
            // completion.
            DeclareOwnedVariant::CodecZenohDeclFinal(_) => {}
            // Default arm preserves an unknown wire tag for
            // forward compatibility (codegen generates this for
            // every variant-dispatch enum). The peer keyexpr
            // table is by definition not affected by an unknown
            // Declare sub-type.
            DeclareOwnedVariant::Default { .. } => {}
        }
    }

    /// [`Self::absorb_declare`] for a `Declare` the in-place receive path lends
    /// ([`IterationEvent::InPlace`]): the same two arms by the same rules, over the
    /// declaration as it is decoded where its frame lies. The keyexpr a `DeclKexpr`
    /// declares is resolved by the one rule both forms share
    /// ([`crate::wireexpr_resolve::resolve_declared_keyexpr_view`]), into a
    /// bounded buffer, so the slot profile absorbs an alias without the heap and
    /// without the owned `DeclareOwned` it could not build. Every other arm is
    /// another registry's, as in the owned form.
    #[cfg(all(
        feature = "codec-declare",
        feature = "storage-profile",
        feature = "rx-lent-control"
    ))]
    pub(crate) fn absorb_declare_view(&mut self, body: &wz_codecs::lent::DeclareVariant<'_>) {
        use wz_codecs::lent::DeclareVariant;
        match body {
            DeclareVariant::CodecZenohDeclKexpr(d) => {
                let mut composed = KeyexprBuf::new();
                let literal = match crate::wireexpr_resolve::resolve_declared_keyexpr_view(
                    &d.keyexpr.body,
                    self.naming.spaces(),
                    &mut composed,
                ) {
                    Ok(Some(literal)) => literal,
                    // Unresolvable, or too long for the table's text.
                    Ok(None) | Err(_) => return,
                };
                // Past the quota or a row's text the alias is dropped; with no room where the rows
                // keep their keys it is dropped and counted with the alias table's refusals, as
                // zenoh-pico drops one its heap cannot hold.
                let text =
                    match key_text_within::<P>(&self.naming.keys, literal, self.naming.key_quota) {
                        Ok(text) => text,
                        Err(crate::bounded::KeyUnkept::TooLong) => return,
                        Err(crate::bounded::KeyUnkept::NoRoom) => {
                            self.naming.aliases.count_refused();
                            return;
                        }
                    };
                // A refusal is counted by the table itself, as for the owned form.
                let quota = self.naming.alias_quota;
                let _ = self.naming.aliases.bind_within(
                    crate::wire_id::declared_peer_key(d.id),
                    text,
                    |count| quota.admits(count),
                );
            }
            DeclareVariant::CodecZenohUndeclKexpr(u) => {
                self.naming
                    .aliases
                    .unbind(crate::wire_id::declared_peer_key(u.id));
            }
            // The other arms are the dedicated registries', as in the owned form.
            DeclareVariant::CodecZenohDeclSubscriber(_)
            | DeclareVariant::CodecZenohUndeclSubscriber(_)
            | DeclareVariant::CodecZenohDeclQueryable(_)
            | DeclareVariant::CodecZenohUndeclQueryable(_)
            | DeclareVariant::CodecZenohDeclToken(_)
            | DeclareVariant::CodecZenohUndeclToken(_)
            | DeclareVariant::CodecZenohDeclFinal(_)
            | DeclareVariant::Default { .. } => {}
        }
    }
}

#[cfg(feature = "storage-profile")]
impl<P: Storage> PeerNaming<P> {
    /// The two id spaces this session resolves a keyexpr against: the peer's
    /// aliases and, when installed, our own.
    fn spaces(&self) -> MappingSpaces<'_> {
        #[cfg(feature = "alloc")]
        let own = self
            .own_mapping_space
            .as_ref()
            .map(|own| &**own as &dyn crate::wireexpr_resolve::OwnMappingSpace);
        // A session in a slot installs no own space: it reads an `M=0` alias as the
        // relay face does, which refuses it.
        #[cfg(not(feature = "alloc"))]
        let own = None;
        #[cfg(feature = "shared-key-ids")]
        if let Some(ids) = &self.shared_key_ids {
            return MappingSpaces::for_aliases::<P>(&self.aliases, own).with_shared(ids);
        }
        MappingSpaces::for_aliases::<P>(&self.aliases, own)
    }
}

#[cfg(feature = "declare-subscriber")]
impl<P: Storage> Default for InterestSide<P> {
    /// No interest registered, nothing staged.
    fn default() -> Self {
        Self {
            rows: Default::default(),
            staged: BoundedVec::default(),
            refusals: SubInterestRefusals::default(),
            reconciled_epoch: 0,
            keys: Default::default(),
        }
    }
}

#[cfg(feature = "declare-subscriber")]
impl InterestSide<Lent> {
    /// The bytes of an arena [`SubscriberPeer::lend_rows`] takes: the staging's. `None` past the
    /// address space.
    const fn arena_bytes(staged: usize) -> Option<usize> {
        Arena::table_bytes::<SubInterestReply>(staged)
    }
}

/// The kind of row a peer's interests are kept in on the lent policy.
#[cfg(all(feature = "declare-subscriber", feature = "peer-row-pools"))]
type InterestKind = crate::row_pool::Seq<InboundSubInterest<Lent>>;

/// Where every face of a session keeps the interests its peer asks
/// ([`SubscriberPeer::keep_interest_rows_in`]): a pool the faces of a session of many share, lent
/// from its arena once, so a face holds the interests its peer asked and the session holds what its
/// faces together asked, up to the pool's rows; or, for a session of one face, a span of that
/// face's own, handed to the first side that asks and to no other.
#[cfg(all(feature = "declare-subscriber", feature = "peer-row-pools"))]
#[derive(Debug)]
pub struct InterestRows(crate::row_pool::RowSource<InterestKind>);

#[cfg(all(feature = "declare-subscriber", feature = "peer-row-pools"))]
impl InterestRows {
    /// `rows` interests lent by `lend`: a pool the faces share, or a span of one face's own, a group
    /// of its own ([`Self::own_bytes`]). A refusal is `lend`'s to hand back.
    pub fn lent(lend: &mut crate::row_pool::RowLender<'_>, rows: usize) -> Self {
        lend.group(Self::own_bytes(rows));
        Self(lend.next(rows))
    }

    /// The bytes of an arena a pool of `rows` interests takes. `None` past the most rows a pool
    /// names or the address space.
    pub const fn pool_bytes(rows: usize) -> Option<usize> {
        crate::row_pool::RowSpace::<InterestKind>::pool_bytes(rows)
    }

    /// The bytes a span of one face's own of `rows` interests takes, not rounded to an arena's
    /// spans. `None` past the most rows a span names or the address space.
    pub const fn own_bytes(rows: usize) -> Option<usize> {
        crate::row_pool::RowSpace::<InterestKind>::own_bytes(rows)
    }

    /// What a shared pool holds now; `None` for a span of one face's own.
    pub fn counts(&self) -> Option<crate::row_pool::RowCounts> {
        self.0.counts()
    }
}

#[cfg(feature = "declare-subscriber")]
impl InterestSide<crate::bounded::Static> {
    /// No interest registered, nothing staged, of the static policy. `const`.
    const fn new_static() -> Self {
        Self {
            rows: BoundedVec::new_static(),
            staged: BoundedVec::new_static(),
            refusals: SubInterestRefusals {
                chains: 0,
                future_interests: 0,
                announcements: 0,
            },
            reconciled_epoch: 0,
            keys: crate::bounded::InlineKeys,
        }
    }
}

#[cfg(feature = "declare-subscriber")]
impl<P: Storage> InterestSide<P> {
    /// Retire the row of `interest_id`: the peer cancelled it, or a recycled id
    /// must not inherit a dead publisher's keyexpr.
    fn retire(&mut self, interest_id: u64) {
        self.rows.retain(|row| row.interest_id != interest_id);
    }

    /// Whether the staging takes `count` more items: its storage has the slots,
    /// and `quota` admits the items they would leave staged. Inlined so that a
    /// build whose quota is its storage's capacity, where `admits` compares
    /// nothing, compiles each caller to the storage's check alone.
    #[inline(always)]
    fn has_room(&self, quota: crate::limits::MaxPendingDeclaresHeld, count: usize) -> bool {
        self.staged.free_slots() >= count && quota.admits(self.staged.len().saturating_add(count))
    }

    /// Stage one unsolicited announcement, which has no chain to keep whole, or
    /// count it when the staging has no room for it under `quota`. Inlined as
    /// [`Self::has_room`] is.
    #[inline(always)]
    fn stage_announcement(
        &mut self,
        quota: crate::limits::MaxPendingDeclaresHeld,
        item: SubInterestReply,
    ) {
        Self::stage_announcement_in(&mut self.staged, &mut self.refusals, quota, item);
    }

    /// [`Self::stage_announcement`] into the side's staging and refusals alone, for a caller that
    /// holds the side's rows meanwhile.
    #[inline(always)]
    fn stage_announcement_in(
        staged: &mut BoundedVec<SubInterestReply, { caps::MAX_PENDING_DECLARES }, P>,
        refusals: &mut SubInterestRefusals,
        quota: crate::limits::MaxPendingDeclaresHeld,
        item: SubInterestReply,
    ) {
        if !quota.admits(staged.len() + 1) || staged.push(item).is_err() {
            refusals.announcements = refusals.announcements.saturating_add(1);
        }
    }

    /// Stage the terminating `Final` of an interest that could not be
    /// remembered, as a chain of one, whole or counted.
    fn stage_final_only(&mut self, quota: crate::limits::MaxPendingDeclaresHeld, interest_id: u64) {
        if !self.has_room(quota, 1) {
            self.count_refused_chain();
        } else {
            self.staged
                .push(SubInterestReply::Final { interest_id })
                .expect("one free slot was checked above");
        }
    }

    /// Count one CURRENT reply chain the staging buffer could not take whole.
    fn count_refused_chain(&mut self) {
        self.refusals.chains = self.refusals.chains.saturating_add(1);
    }

    /// Drop the rows and the staging, in place.
    fn forget(&mut self) {
        self.rows.clear();
        self.staged.clear();
    }
}

/// The interest plane of one peer's side: what it registered, what is staged back
/// to it, and what could not be.
#[cfg(feature = "declare-subscriber")]
impl<P: Storage> SubscriberPeer<P> {
    /// The counted refusals of this peer's interest staging. All zero on the
    /// growable backing with no quota stated; see [`SubInterestRefusals`].
    pub fn interest_staging_refusals(&self) -> SubInterestRefusals {
        self.interests.refusals
    }

    /// How many interests this peer has registered and not cancelled.
    pub fn interest_count(&self) -> usize {
        self.interests.rows.len()
    }

    /// R311y530 — take the staged interest-response chain for the drain.
    /// Paired with [`SubscriberTable::sub_interest_reply`], which resolves each
    /// item to its `(DeclSubscriber.id, reply keyexpr)` against the tables that
    /// own them.
    ///
    /// The items move to a buffer of their own (`Storage::Scratch`) and the staging keeps its
    /// rows: on a policy whose rows are only lent, a staging moved out would take them with it and
    /// leave the side none to stage the next chain in.
    pub fn take_staged_sub_interest_replies(
        &mut self,
    ) -> BoundedVec<SubInterestReply, { caps::MAX_PENDING_DECLARES }, P::Scratch> {
        let mut taken: BoundedVec<SubInterestReply, { caps::MAX_PENDING_DECLARES }, P::Scratch> =
            BoundedVec::default();
        // Taken from the back and turned round, so each item moves once.
        while let Some(item) = self.interests.staged.pop() {
            let kept = taken.push(item);
            debug_assert!(kept.is_ok(), "a buffer of the staging's capacity");
        }
        taken.reverse();
        taken
    }

    /// Whether an interest-response chain is staged for the drain
    /// ([`Self::take_staged_sub_interest_replies`]), asked without taking it.
    pub fn has_staged_sub_interest_replies(&self) -> bool {
        !self.interests.staged.is_empty()
    }

    /// R2292 (open-debt item 627) — record that the drain actually put a
    /// `DeclSubscriber` for this interest's AGGREGATE declaration on the wire.
    ///
    /// Separate from [`SubscriberTable::sub_interest_reply`] because that one
    /// resolves under a shared borrow whose `&str` is still alive while the sink
    /// encodes; this runs after that borrow has ended.
    #[cfg(feature = "declare-undeclare")]
    pub fn mark_aggregate_announced(&mut self, interest_id: u64) {
        if let Some(row) = self
            .interests
            .rows
            .iter_mut()
            .find(|row| row.interest_id == interest_id && row.aggregate)
        {
            row.announced = true;
        }
    }

    /// Stage, for THIS peer, what the subscription table has done since it last
    /// looked: a FUTURE push for every subscription registered after one of its
    /// interests, and the retraction of every announced aggregate declaration
    /// that no subscription stands for any more.
    ///
    /// This is what [`SubscriberRegistry`] does as it is told, by being the one
    /// who registers and unregisters. A table that serves many peers cannot be: it
    /// does not know them, and the application that registers a subscription does
    /// not know which session's peer asked for it. So each side compares the
    /// table's epoch with the one it last saw, and when they differ finds the same
    /// subscriptions by their ids (an interest row remembers the id counter it was
    /// taken at, and a subscription at or after it is the FUTURE half of that
    /// interest). The wire result is the same: the same announcements, to the same
    /// peers, staged here before the drain that sends them. What it does not do is
    /// announce a subscription that was registered and withdrawn between two
    /// looks, which the push form announces and then skips at the drain, when the
    /// row it resolves through is gone.
    ///
    /// A no-op when the table did not move. Staging that does not fit is counted
    /// and refused, as everywhere else.
    pub fn reconcile<C: SampleSink, R: Storage>(&mut self, table: &SubscriberTable<C, R>) {
        if self.interests.reconciled_epoch == table.epoch {
            return;
        }
        self.interests.reconciled_epoch = table.epoch;
        // FUTURE pushes. An aggregate interest is told ONCE that something
        // matches, however many matching subscriptions arrived; any other is
        // told of each, under that subscription's own keyexpr. Staged straight
        // from the two tables: collecting the hits first would need a bound of
        // rows times subscriptions on the stack.
        let InterestSide {
            rows,
            staged,
            refusals,
            ..
        } = &mut self.interests;
        for row in rows.iter_mut() {
            let (interest_id, aggregate, watermark) =
                (row.interest_id, row.aggregate, row.watermark);
            let mut told = false;
            for sub in table
                .subscribers
                .iter()
                .filter(|s| s.id.as_u64() >= watermark)
            {
                if !subscription_matches_interest(&sub.pattern, Some(&*row.keyexpr)) {
                    continue;
                }
                let item = if aggregate {
                    if told {
                        continue;
                    }
                    told = true;
                    SubInterestReply::Aggregate { interest_id }
                } else {
                    SubInterestReply::Concrete {
                        interest_id,
                        subscription_id: sub.id.as_u64(),
                    }
                };
                // No terminating `Final`: an unsolicited FUTURE push, not a
                // CURRENT dump (see `stage_future_subscriber_pushes`).
                InterestSide::<P>::stage_announcement_in(staged, refusals, table.reply_quota, item);
            }
            row.watermark = table.next_id;
        }
        #[cfg(feature = "declare-undeclare")]
        table.stage_emptied_aggregate_retracts(&mut self.interests);
    }

    /// Forget this peer's interests and what was staged to it, because its
    /// session ended; see [`Self::forget_peer`]. Named for the interest plane's
    /// own callers.
    pub fn forget_interests(&mut self) {
        self.interests.forget();
    }
}

/// The application-facing registry of ONE session: the table and that session's
/// peer side. Everything that does not need the peer is the table's, reached
/// through `Deref`; what does is here, with the signature it has always had.
impl<C: SampleSink, P: Storage> SubscriberTable<C, P> {
    /// [`Self::register_sink`], and then what the registration owes `peer`.
    ///
    /// R311y530 — pub-before-sub: a remote publisher that already registered
    /// a FUTURE subscriber interest is told about THIS subscription now.
    /// Placed here, on the single table-insert path, rather than in the
    /// callers: every declare route funnels through this method, so none
    /// can skip the push. A table shared by several peers stages it for the
    /// peer of the caller; every other peer finds it by its id when it next
    /// reconciles ([`SubscriberPeer::reconcile`]).
    pub fn register_sink_for(
        &mut self,
        peer: &mut SubscriberPeer<P>,
        keyexpr_pattern: &str,
        allowed_origin: crate::locality::Locality,
        sink: C,
    ) -> Result<SubscriptionId, RegisterError> {
        let id = self.register_sink(keyexpr_pattern, allowed_origin, sink)?;
        #[cfg(feature = "declare-subscriber")]
        {
            self.stage_future_subscriber_pushes(&mut peer.interests, id);
            peer.interests.reconciled_epoch = self.epoch;
        }
        #[cfg(not(feature = "declare-subscriber"))]
        let _ = peer;
        Ok(id)
    }

    /// [`Self::unregister`], and then what the retirement owes `peer`.
    ///
    /// R2292 (open-debt item 627) — an aggregate declaration this session
    /// announced stands for "some local subscription matches your
    /// interest", so the retirement that makes that false has to retract
    /// it. Placed HERE, on the single removal path, for the same reason
    /// [`Self::register_sink_for`] sits on the single insert path: no
    /// retirement route can skip the retraction.
    pub fn unregister_for(&mut self, peer: &mut SubscriberPeer<P>, id: SubscriptionId) -> bool {
        let removed = self.unregister(id);
        #[cfg(feature = "declare-subscriber")]
        if removed {
            #[cfg(feature = "declare-undeclare")]
            self.stage_emptied_aggregate_retracts(&mut peer.interests);
            peer.interests.reconciled_epoch = self.epoch;
        }
        #[cfg(not(feature = "declare-subscriber"))]
        let _ = peer;
        removed
    }
}

impl<C: SampleSink> SubscriberRegistry<C, Profile> {
    /// New empty registry over an explicit sink backing `C`, of this build's storage
    /// profile. Subscriber ids start at 1 so 0 stays available as a sentinel "no
    /// subscription" value for any caller-side wrapper that needs one.
    ///
    /// R311gb-2b — the generic constructor (the no-`alloc` / MCU entry
    /// point, paired with [`register_sink`](Self::register_sink)). AP
    /// callers use the inferring [`new`](SubscriberRegistry::new)
    /// shorthand, which fixes `C = BoxedSink`; this mirrors the std
    /// `HashMap::new` (default hasher) vs `with_hasher` split, so a bare
    /// `SubscriberRegistry::new()` resolves its type parameter without a
    /// turbofish. Defined for the profile alone, so it names its storage policy by
    /// itself; code generic over a policy builds a registry with `Default`.
    pub fn with_sink_backing() -> Self {
        Self::default()
    }
}

impl<C: SampleSink, P: Storage> SubscriberRegistry<C, P> {
    /// The peer's side of this registry, for a caller that wants its counters or
    /// its tables by name.
    pub fn peer(&self) -> &SubscriberPeer<P> {
        &self.peer
    }

    /// The two halves apart: the application's SubscriberTable<C, P> and the peer's SubscriberPeer<P>, for a caller
    /// that hands the second to a method of the first, as a session whose application half is
    /// shared with other faces must.
    pub fn split_mut(&mut self) -> (&mut SubscriberTable<C, P>, &mut SubscriberPeer<P>) {
        (&mut self.table, &mut self.peer)
    }

    /// The two halves apart, to read ([`Self::split_mut`]).
    pub fn split(&self) -> (&SubscriberTable<C, P>, &SubscriberPeer<P>) {
        (&self.table, &self.peer)
    }

    /// [`SubscriberPeer::limit_aliases_to`] for this registry's peer.
    #[cfg(feature = "storage-profile")]
    pub fn limit_peer_aliases_to(&mut self, quota: crate::limits::MaxPeerKeyexprAliasesHeld) {
        self.peer.limit_aliases_to(quota);
    }

    /// [`SubscriberPeer::limit_keys_to`] for this registry's peer.
    #[cfg(feature = "storage-profile")]
    pub fn limit_peer_keys_to(&mut self, quota: crate::limits::MaxKeyexprBytesHeld) {
        self.peer.limit_keys_to(quota);
    }

    /// [`SubscriberTable::register_sink_for`] for this registry's peer: the
    /// registration, and what it owes the peer.
    pub fn register_sink(
        &mut self,
        keyexpr_pattern: &str,
        allowed_origin: crate::locality::Locality,
        sink: C,
    ) -> Result<SubscriptionId, RegisterError> {
        self.table
            .register_sink_for(&mut self.peer, keyexpr_pattern, allowed_origin, sink)
    }

    /// [`SubscriberTable::unregister`], and then what the retirement owes this
    /// registry's peer ([`SubscriberTable::unregister_for`]).
    pub fn unregister(&mut self, id: SubscriptionId) -> bool {
        self.table.unregister_for(&mut self.peer, id)
    }

    /// [`SubscriberPeer::set_own_mapping_space`] for this registry's peer.
    #[cfg(feature = "alloc")]
    pub fn set_own_mapping_space(&mut self, space: SharedOwnMappingSpace) {
        self.peer.set_own_mapping_space(space);
    }

    /// [`SubscriberPeer::clear_own_mapping_space`] for this registry's peer.
    #[cfg(feature = "alloc")]
    pub fn clear_own_mapping_space(&mut self) {
        self.peer.clear_own_mapping_space();
    }

    /// [`SubscriberPeer::set_shared_key_ids`] for this registry's peer.
    #[cfg(feature = "shared-key-ids")]
    pub fn set_shared_key_ids(&mut self, ids: crate::shared_key_ids::SharedKeyIds) {
        self.peer.set_shared_key_ids(ids);
    }

    /// [`SubscriberPeer::clear_shared_key_ids`] for this registry's peer.
    #[cfg(feature = "shared-key-ids")]
    pub fn clear_shared_key_ids(&mut self) {
        self.peer.clear_shared_key_ids();
    }

    /// [`SubscriberPeer::mapping_spaces`] for this registry's peer.
    #[cfg(feature = "storage-profile")]
    pub fn mapping_spaces(&self) -> MappingSpaces<'_> {
        self.peer.mapping_spaces()
    }

    /// [`SubscriberPeer::resolve_inbound_mapping`] for this registry's peer.
    #[cfg(feature = "alloc")]
    pub fn resolve_inbound_mapping(&self, id: crate::wire_id::ExprId) -> Option<String> {
        self.peer.resolve_inbound_mapping(id)
    }

    /// R231 — install this session's own zid (1..=16 bytes); see
    /// [`SubscriberPeer::set_own_zid_bytes`]. `false` for a length outside that
    /// range, with nothing changed.
    #[cfg(feature = "alloc")]
    pub fn set_own_zid(&mut self, zid: alloc::vec::Vec<u8>) -> bool {
        self.peer.set_own_zid_bytes(&zid)
    }

    /// [`SubscriberPeer::clear_own_zid`] for this registry's peer.
    #[cfg(feature = "storage-profile")]
    pub fn clear_own_zid(&mut self) {
        self.peer.clear_own_zid();
    }

    /// [`SubscriberPeer::own_zid`] for this registry's peer.
    #[cfg(feature = "storage-profile")]
    pub fn own_zid(&self) -> Option<&[u8]> {
        self.peer.own_zid()
    }

    /// [`SubscriberTable::dispatch_iteration_event`] for this registry's peer.
    #[cfg(feature = "storage-profile")]
    pub fn dispatch_iteration_event(&mut self, event: IterationEvent<'_, '_>) {
        self.table.dispatch_iteration_event(&mut self.peer, event);
    }

    /// [`SubscriberTable::dispatch`] for this registry's peer.
    #[cfg(feature = "alloc")]
    pub fn dispatch(&mut self, message: &NetworkMessage, reliability: Reliability) {
        self.table.dispatch(&mut self.peer, message, reliability);
    }

    /// [`SubscriberTable::respond_to_subscriber_interest_borrowed`] for this
    /// registry's peer.
    #[cfg(feature = "declare-subscriber")]
    pub fn respond_to_subscriber_interest_borrowed(
        &mut self,
        interest_id: u64,
        pattern: Option<&str>,
        aggregate: bool,
        current: bool,
        future: bool,
    ) -> usize {
        self.table.respond_to_subscriber_interest_borrowed(
            &mut self.peer,
            interest_id,
            pattern,
            aggregate,
            current,
            future,
        )
    }

    /// [`SubscriberPeer::take_staged_sub_interest_replies`] for this registry's
    /// peer.
    #[cfg(feature = "declare-subscriber")]
    pub fn take_staged_sub_interest_replies(
        &mut self,
    ) -> BoundedVec<SubInterestReply, { caps::MAX_PENDING_DECLARES }, P::Scratch> {
        self.peer.take_staged_sub_interest_replies()
    }

    /// [`SubscriberTable::sub_interest_reply`] for this registry's peer.
    #[cfg(feature = "declare-subscriber")]
    pub fn sub_interest_reply(&self, item: &SubInterestReply) -> Option<(u64, &str)> {
        self.table.sub_interest_reply(&self.peer, item)
    }

    /// [`SubscriberPeer::mark_aggregate_announced`] for this registry's peer.
    #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
    pub fn mark_aggregate_announced(&mut self, interest_id: u64) {
        self.peer.mark_aggregate_announced(interest_id);
    }

    /// [`SubscriberTable::take_aggregate_retract`] for this registry's peer.
    #[cfg(all(feature = "declare-subscriber", feature = "declare-undeclare"))]
    pub fn take_aggregate_retract(&mut self, interest_id: u64) -> Option<u64> {
        self.table
            .take_aggregate_retract(&mut self.peer, interest_id)
    }

    /// [`SubscriberPeer::interest_staging_refusals`] for this registry's peer.
    #[cfg(feature = "declare-subscriber")]
    pub fn interest_staging_refusals(&self) -> SubInterestRefusals {
        self.peer.interest_staging_refusals()
    }
}

/// R311gb-2b — AP / `alloc`-profile convenience constructors on the TABLE. The
/// closure-taking `register` / `register_with_locality` wrappers live here (on
/// the `BoxedSink` instantiation only) because they heap-box the closure via
/// [`BoxedSink`]; a table with many peers registers through them as the
/// application, and stages nothing for any peer
/// ([`SubscriberPeer::reconcile`] does, from the epoch they bump).
#[cfg(feature = "alloc")]
impl SubscriberTable<BoxedSink> {
    /// New empty table backed by heap-boxed closures ([`BoxedSink`]).
    pub fn new() -> Self {
        Self::with_sink_backing()
    }

    /// [`SubscriberRegistry::register`] for a table: the closure is boxed and
    /// registered under [`Locality::Any`](crate::locality::Locality). It refuses
    /// as [`register_sink`](Self::register_sink) does, for the reason
    /// [`SubscriberRegistry::register`] gives.
    pub fn register(
        &mut self,
        keyexpr_pattern: &str,
        callback: impl FnMut(&dyn SampleView) + Send + 'static,
    ) -> Result<SubscriptionId, RegisterError> {
        self.register_with_locality(keyexpr_pattern, crate::locality::Locality::Any, callback)
    }

    /// [`SubscriberRegistry::register_with_locality`] for a table.
    pub fn register_with_locality(
        &mut self,
        keyexpr_pattern: &str,
        allowed_origin: crate::locality::Locality,
        callback: impl FnMut(&dyn SampleView) + Send + 'static,
    ) -> Result<SubscriptionId, RegisterError> {
        self.register_sink(keyexpr_pattern, allowed_origin, BoxedSink::new(callback))
    }
}

/// R311gb-2b — AP / `alloc`-profile convenience constructors. The
/// closure-taking `register` / `register_with_locality` wrappers live
/// here (on the `BoxedSink` instantiation only) because they heap-box
/// the closure via [`BoxedSink`]; the no-`alloc` profile registers a
/// consumer-supplied sink through the generic
/// [`register_sink`](SubscriberRegistry::register_sink) instead.
#[cfg(feature = "alloc")]
impl SubscriberRegistry<BoxedSink> {
    /// New empty AP registry backed by heap-boxed closures
    /// ([`BoxedSink`]). The inferring shorthand for
    /// [`with_sink_backing`](SubscriberRegistry::with_sink_backing):
    /// `SubscriberRegistry::new()` fixes `C = BoxedSink` so the
    /// closure-taking [`register`](Self::register) /
    /// [`register_with_locality`](Self::register_with_locality) wrappers
    /// are in reach without a turbofish.
    pub fn new() -> Self {
        Self::with_sink_backing()
    }

    /// Register a subscriber closure for a keyexpr pattern. The
    /// closure receives `&dyn SampleView` — the resolved keyexpr,
    /// SampleKind, payload bytes, and reliability (R311gb-2b: the seam
    /// accessor contract replaces the prior owned `&Sample`; this is
    /// the `feedback_signature_stability` wire-data principled
    /// exemption, taken so one registry backs both heap and no-heap
    /// profiles). The closure is heap-boxed via [`BoxedSink`].
    ///
    /// R223 — defaults [`Locality::Any`](crate::locality::Locality)
    /// so both session-local and remote-origin samples fire the
    /// closure. Use [`register_with_locality`](Self::register_with_locality)
    /// to restrict to one origin class.
    ///
    /// Admission to a bounded resource is a partial operation, so this
    /// returns what [`register_sink`](SubscriberRegistry::register_sink)
    /// returns on every backing. No backing makes it total: a fixed backing
    /// fills, and a growable one is held to the quota its creator stated
    /// ([`SubscriberTable::limit_to`]), which is a value the open path reads at
    /// run time and no type can see. A caller that knows its table admits the
    /// registration says so where it calls, with the reason it knows.
    pub fn register(
        &mut self,
        keyexpr_pattern: &str,
        callback: impl FnMut(&dyn SampleView) + Send + 'static,
    ) -> Result<SubscriptionId, RegisterError> {
        self.register_with_locality(keyexpr_pattern, crate::locality::Locality::Any, callback)
    }

    /// R223 — variant of [`register`](Self::register) that pins the
    /// locality filter explicitly. Stores `allowed_origin` on the
    /// subscriber record; `dispatch_push`
    /// consults the filter before firing the closure.
    ///
    /// wz today treats every Push reaching `dispatch_push` as
    /// remote (no self-publish loopback). So a
    /// [`Locality::SessionLocal`](crate::locality::Locality)
    /// subscription registered now will not fire until a future
    /// round wires up loopback; this is the correct
    /// surface-mirrors-zenoh-pico shape, not a bug.
    ///
    /// It refuses as [`register`](Self::register) does.
    pub fn register_with_locality(
        &mut self,
        keyexpr_pattern: &str,
        allowed_origin: crate::locality::Locality,
        callback: impl FnMut(&dyn SampleView) + Send + 'static,
    ) -> Result<SubscriptionId, RegisterError> {
        self.register_sink(keyexpr_pattern, allowed_origin, BoxedSink::new(callback))
    }
}

// R311du — the test module gates on the full pub/sub data-plane feature
// union it exercises: codec-push (Push records), codec-declare
// (DeclareVariant + absorb_declare peer-keyexpr-table population),
// codec-response-final (NetworkMessage::ResponseFinal), and the
// pubsub-{put,delete,attachment,timestamp} dispatch arms. The workspace
// lane (cargo test --workspace) runs these because wz-runtime-tokio's
// default features enable all of them; the explicit `-p wz-session-core`
// C1d lane enumerates the same union so the coverage is non-implicit
// (R311ds-c1c precedent).
// Shared Push builders for BOTH test modules below. The `mod tests`
// suite requires put+delete (+ more), while `mod decode_isolation_tests`
// requires put XOR delete — disjoint gates, so neither can host helpers
// the other reaches. This module's gate is the EXACT union of the two
// consumer gates (codec-push factored out) so it compiles iff at least
// one consumer does — no dead-code arm, no `#[allow]`.
#[cfg(all(
    test,
    feature = "codec-push",
    any(
        all(
            feature = "codec-declare",
            feature = "codec-response-final",
            feature = "pubsub-put",
            feature = "pubsub-delete",
            feature = "pubsub-attachment",
            feature = "pubsub-timestamp"
        ),
        all(feature = "pubsub-put", not(feature = "pubsub-delete")),
        all(not(feature = "pubsub-put"), feature = "pubsub-delete"),
    )
))]
mod push_fixtures {
    use super::*;
    use wz_codecs::lent::{Push, Wireexpr, WireexprLocal, WireexprVariant};

    /// A Put-bodied Push for `suffix` (literal local wireexpr, id=0).
    /// `Push::default()` already carries a `CodecZenohMsgPut` body, so the
    /// keyexpr is the only field overridden. Constructible regardless of
    /// `pubsub-put` — that feature gates the dispatch consumer, not the
    /// `codec-push` wire variant.
    pub(super) fn push_with_keyexpr(suffix: &str) -> PushOwned {
        Push {
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprLocal(WireexprLocal {
                    id: 0,
                    suffix_len: Some(suffix.len() as u64),
                    suffix: Some(sce_forge_runtime::codec::Bounded::new(suffix).unwrap()),
                }),
            },
            ..Push::default()
        }
        .try_into_owned_in::<crate::wire::WireStorage>()
        .unwrap()
    }

    /// A Del-bodied Push for `suffix`. Constructible regardless of
    /// `pubsub-delete` (same reason as [`push_with_keyexpr`]).
    pub(super) fn push_with_del_body(suffix: &str) -> PushOwned {
        let mut push = push_with_keyexpr(suffix);
        push.body = PushOwnedVariant::CodecZenohMsgDel(
            wz_codecs::lent::MsgDel::default()
                .try_into_owned_in::<crate::wire::WireStorage>()
                .unwrap(),
        );
        push
    }
}

#[cfg(all(
    test,
    feature = "codec-push",
    feature = "codec-declare",
    feature = "codec-response-final",
    feature = "pubsub-put",
    feature = "pubsub-delete",
    feature = "pubsub-attachment",
    feature = "pubsub-timestamp"
))]
mod tests {
    use super::push_fixtures::{push_with_del_body, push_with_keyexpr};
    use super::*;
    use hashbrown::HashMap;
    // no_std test prelude: the std prelude (String / Vec / Box / vec!)
    // is absent here, so the alloc-provided forms are imported
    // explicitly. `.to_vec()` needs no import (inherent slice method
    // once alloc is linked).
    use alloc::boxed::Box;
    use alloc::string::{String, ToString};
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    // Fixtures build the borrowed codec views then `.into_owned()` at the
    // dispatch boundary (`NetworkMessage::*` carriers store `*Owned`).
    use wz_codecs::lent::{Push, Wireexpr, WireexprNonlocal, WireexprVariant};

    #[test]
    fn dispatch_fires_callback_on_matching_keyexpr() {
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let _id = registry
            .register("topic/a", move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let push = push_with_keyexpr("topic/a");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "matching keyexpr fires the callback exactly once"
        );
    }

    /// R2662 (open-debt item 763) — A WILDCARD-ADDRESSED PUT REACHES A CONCRETE
    /// SUBSCRIBER. This is the witness for the delivery half of the migration
    /// the QUERY plane completed first.
    ///
    /// Before this round `fire_to_subscribers` compared the subscriber pattern
    /// against the arriving keyexpr as a LITERAL, so `topic/*` matched the
    /// subscriber `topic/*` character-for-character and reached `topic/a`
    /// NEVER. Upstream's subscriber rule is intersection, and such keys really
    /// do arrive: `wz_storage_wildcard_update_pico_interop` fires `demo/**`
    /// from a real zenoh-pico `z_put` and the storage plane applies it — so the
    /// sample crosses the node correctly and only LOCAL delivery dropped it.
    ///
    /// ⛔ THE SECOND ASSERTION IS WHY THIS IS NOT A WIDENING-BY-ACCIDENT: a
    /// wildcard that does NOT cover the subscriber must still not fire. A
    /// change that merely made intersection permissive would pass the first
    /// assertion and fail this one.
    #[test]
    fn dispatch_fires_a_concrete_subscriber_on_a_wildcard_addressed_put() {
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let _id = registry
            .register("topic/a", move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let push = push_with_keyexpr("topic/*");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "a `topic/*` PUT intersects the subscriber `topic/a`, so it must be \
             delivered; 0 here is the one-sided match this round replaced"
        );

        // NEGATIVE CONTROL — a wildcard under a DIFFERENT prefix stays out.
        let push = push_with_keyexpr("other/*");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "`other/*` does not intersect `topic/a`; intersection must not mean \
             'fires for any wildcard'"
        );
    }

    #[test]
    fn dispatch_skips_callback_on_non_matching_keyexpr() {
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let _id = registry
            .register("topic/a", move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let push = push_with_keyexpr("topic/b");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);

        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "non-matching keyexpr does not fire the callback"
        );
    }

    #[test]
    fn dispatch_fires_all_matching_subscribers_in_registration_order() {
        let mut registry = SubscriberRegistry::new();
        let log = Arc::new(std::sync::Mutex::new(Vec::<&'static str>::new()));

        let log1 = log.clone();
        registry
            .register("topic/a", move |_push| {
                log1.lock().unwrap().push("first");
            })
            .expect("no quota is stated on this table");
        let log2 = log.clone();
        registry
            .register("topic/a", move |_push| {
                log2.lock().unwrap().push("second");
            })
            .expect("no quota is stated on this table");
        let log3 = log.clone();
        registry
            .register("topic/b", move |_push| {
                log3.lock().unwrap().push("other");
            })
            .expect("no quota is stated on this table");

        let push = push_with_keyexpr("topic/a");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);

        let log = log.lock().unwrap();
        assert_eq!(
            log.as_slice(),
            &["first", "second"],
            "both topic/a callbacks fire in registration order, topic/b skipped"
        );
    }

    #[test]
    fn dispatch_skips_pushes_with_nonzero_mapping_id() {
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("topic/a", move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        // Push referencing a DECLARE-established mapping id (no
        // inline suffix). The registry has no resolver for the id so
        // the dispatch path is a no-op — documented R98 scope limit.
        // R125c2: keyexpr is now a tagged-union; Nonlocal arm chosen
        // because a peer-declared mapping id is by definition not the
        // sender's local key (M=0 on wire ⇔ Nonlocal arm).
        let push = Push {
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                    id: 7,
                    suffix_len: None,
                    suffix: None,
                }),
            },
            ..Push::default()
        }
        .try_into_owned_in::<crate::wire::WireStorage>()
        .unwrap();
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);

        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "non-zero mapping id pushes are filtered out (DECLARE table not modeled)"
        );
    }

    // ── R226 — reliability projection ──

    #[test]
    fn dispatch_reliable_records_reliable_on_sample() {
        let mut registry = SubscriberRegistry::new();
        let captured = Arc::new(std::sync::Mutex::new(None::<Reliability>));
        let captured_clone = captured.clone();
        registry
            .register("topic/a", move |sample| {
                *captured_clone.lock().unwrap() = Some(sample.reliability());
            })
            .expect("no quota is stated on this table");
        let push = push_with_keyexpr("topic/a");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
        assert_eq!(*captured.lock().unwrap(), Some(Reliability::Reliable));
    }

    #[test]
    fn dispatch_best_effort_records_best_effort_on_sample() {
        let mut registry = SubscriberRegistry::new();
        let captured = Arc::new(std::sync::Mutex::new(None::<Reliability>));
        let captured_clone = captured.clone();
        registry
            .register("topic/a", move |sample| {
                *captured_clone.lock().unwrap() = Some(sample.reliability());
            })
            .expect("no quota is stated on this table");
        let push = push_with_keyexpr("topic/a");
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push)),
            Reliability::BestEffort,
        );
        assert_eq!(*captured.lock().unwrap(), Some(Reliability::BestEffort));
    }

    #[test]
    fn dispatch_iteration_event_projects_frame_reliable_bool_to_sample() {
        let mut registry = SubscriberRegistry::new();
        let captured = Arc::new(std::sync::Mutex::new(None::<Reliability>));
        let captured_clone = captured.clone();
        registry
            .register("topic/a", move |sample| {
                *captured_clone.lock().unwrap() = Some(sample.reliability());
            })
            .expect("no quota is stated on this table");
        let push = push_with_keyexpr("topic/a");
        let outcome = DriverLoopOutcome::FramePayload {
            priority: crate::qos::Priority::DEFAULT,
            reliable: false,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(push))],
            has_ext: false,
            extensions: Vec::new(),
        };
        crate::driver_loop::deliver_frame(&outcome, |event| {
            registry.dispatch_iteration_event(event)
        });
        assert_eq!(
            *captured.lock().unwrap(),
            Some(Reliability::BestEffort),
            "FramePayload.reliable=false must project to Sample.reliability=BestEffort"
        );
    }

    #[test]
    fn reliability_from_reliable_bool_matches_canonical_pairing() {
        assert_eq!(Reliability::from_reliable_bool(true), Reliability::Reliable);
        assert_eq!(
            Reliability::from_reliable_bool(false),
            Reliability::BestEffort
        );
    }

    #[test]
    fn dispatch_ignores_non_push_messages() {
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("topic/a", move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        // R98 scope routes Push only. ResponseFinal (or any other
        // variant) flowing through dispatch must not invoke any
        // subscriber callback.
        use wz_codecs::lent::ResponseFinal;
        registry.dispatch(
            &NetworkMessage::ResponseFinal(
                ResponseFinal::default()
                    .try_into_owned_in::<crate::transport_profile::TransportStorage>()
                    .unwrap(),
            ),
            Reliability::Reliable,
        );

        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "non-Push variants do not fire subscriber callbacks in R98 scope"
        );
    }

    // ── R100 wildcard matcher behaviour ──

    #[test]
    fn keyexpr_matches_literal_equality() {
        assert!(keyexpr_matches("home/temp", "home/temp"));
        assert!(!keyexpr_matches("home/temp", "home/humid"));
        assert!(!keyexpr_matches("home", "home/temp"));
        assert!(!keyexpr_matches("home/temp", "home"));
    }

    #[test]
    fn keyexpr_matches_single_chunk_wildcard() {
        // `*` matches exactly one chunk.
        assert!(keyexpr_matches("home/*/temp", "home/kitchen/temp"));
        assert!(keyexpr_matches("home/*/temp", "home/bedroom/temp"));
        // The wildcard does NOT match zero chunks.
        assert!(!keyexpr_matches("home/*/temp", "home/temp"));
        // The wildcard does NOT span chunk boundaries.
        assert!(!keyexpr_matches("home/*/temp", "home/kitchen/sub/temp"));
    }

    #[test]
    fn keyexpr_matches_double_star_zero_or_more() {
        // `**` matches zero chunks.
        assert!(keyexpr_matches("home/**", "home"));
        // `**` matches one chunk.
        assert!(keyexpr_matches("home/**", "home/temp"));
        // `**` matches many chunks.
        assert!(keyexpr_matches("home/**", "home/kitchen/temp/c"));
        // `**` at the prefix.
        assert!(keyexpr_matches("**/temp", "home/kitchen/temp"));
        assert!(keyexpr_matches("**/temp", "temp"));
        // `**` in the middle.
        assert!(keyexpr_matches("home/**/temp", "home/temp"));
        assert!(keyexpr_matches("home/**/temp", "home/kitchen/temp"));
        assert!(keyexpr_matches("home/**/temp", "home/a/b/c/temp"));
        // Negative: literal suffix must still align.
        assert!(!keyexpr_matches("home/**/temp", "home/kitchen/humid"));
    }

    // ── R220 `$*` intra-chunk DSL matcher behaviour ──

    #[test]
    fn keyexpr_matches_dsl_prefix_suffix_anchors() {
        // `prefix$*suffix` anchors both ends: target must start with
        // "sensor_" and end with "_temp", with any (possibly empty)
        // bytes in between within the same chunk.
        assert!(keyexpr_matches("sensor_$*_temp", "sensor_room1_temp"));
        assert!(keyexpr_matches("sensor_$*_temp", "sensor__temp"));
        // Missing the required suffix → no match.
        assert!(!keyexpr_matches("sensor_$*_temp", "sensor_room1_humid"));
        // Missing the required prefix → no match.
        assert!(!keyexpr_matches("sensor_$*_temp", "device_room1_temp"));
    }

    #[test]
    fn keyexpr_matches_dsl_leading_only_floats_prefix() {
        // `$*foo` lets the leading sub-part float; target need only
        // end with "foo".
        assert!(keyexpr_matches("$*foo", "barfoo"));
        assert!(keyexpr_matches("$*foo", "foo"));
        // Target lacks the required suffix.
        assert!(!keyexpr_matches("$*foo", "barfo"));
    }

    #[test]
    fn keyexpr_matches_dsl_trailing_only_floats_suffix() {
        // `foo$*` lets the trailing sub-part float; target need only
        // start with "foo".
        assert!(keyexpr_matches("foo$*", "foobar"));
        assert!(keyexpr_matches("foo$*", "foo"));
        // Target lacks the required prefix.
        assert!(!keyexpr_matches("foo$*", "fobar"));
    }

    #[test]
    fn keyexpr_matches_dsl_multiple_dsl_in_order() {
        // Multiple `$*` in one chunk anchor sub-parts in order
        // without overlap, mirroring zenoh-pico's
        // _z_chunk_right_contains_all_stardsl_subchunks_of_left.
        assert!(keyexpr_matches("$*aa$*bb$*", "xxaaYYbbZZ"));
        // The order is enforced: "bb" before "aa" must not match.
        assert!(!keyexpr_matches("$*aa$*bb$*", "xxbbYYaaZZ"));
        // Overlap is rejected: two non-overlapping "foo" needed.
        assert!(keyexpr_matches("$*foo$*foo$*", "foofoo"));
        assert!(!keyexpr_matches("$*foo$*foo$*", "foofo"));
    }

    #[test]
    fn keyexpr_matches_dsl_does_not_cross_chunk_boundary() {
        // `foo$*bar` is bounded by the same `/` separator the pattern
        // chunk is, so the matching content for `$*` cannot span
        // across chunks. The target chunk that aligns with the
        // pattern chunk is `foobaz`; the next pattern chunk is `bar`
        // which must align with the next target chunk independently.
        assert!(!keyexpr_matches("home/foo$*bar", "home/foobaz/bar"));
        // Same chunk → match.
        assert!(keyexpr_matches("home/foo$*bar", "home/foobazbar"));
    }

    #[test]
    fn keyexpr_matches_dsl_chunk_alone_acts_like_single_star() {
        // A non-canonical `$*`-only chunk behaves like `*`: any
        // single-chunk target content matches at the matcher level.
        // After R221 the registry call sites canonicalize on register
        // so a registered `home/$*/temp` is stored as
        // `home/*/temp`; this test exercises the matcher
        // directly with the pre-canonical shape to document the
        // matcher's own fallback semantics for non-canonical input.
        assert!(keyexpr_matches("home/$*/temp", "home/kitchen/temp"));
        assert!(keyexpr_matches("home/$*/temp", "home/x/temp"));
        // Still does not span chunk boundaries.
        assert!(!keyexpr_matches("home/$*/temp", "home/a/b/temp"));
        // Still does not collapse to zero chunks.
        assert!(!keyexpr_matches("home/$*/temp", "home/temp"));
    }

    #[test]
    fn keyexpr_matches_dsl_combines_with_double_star() {
        // `**` traversal and intra-chunk `$*` interact orthogonally:
        // `**` consumes whole chunks, `$*` consumes intra-chunk
        // substrings within a single chunk.
        assert!(keyexpr_matches(
            "sensors/**/id_$*",
            "sensors/room1/sub1/id_42"
        ));
        assert!(keyexpr_matches("sensors/**/id_$*", "sensors/id_42"));
        // The literal in the DSL chunk must still align.
        assert!(!keyexpr_matches(
            "sensors/**/id_$*",
            "sensors/room1/value_42"
        ));
    }

    // ── R293 keyexpr_intersects — honest 2-pattern matcher ──
    //
    // `keyexpr_intersects(a, b)` returns true
    // iff at least one literal keyexpr exists that both `a` and `b`
    // would match. The function backs `has_matching` on the
    // RemoteQueryableRegistry and RemoteSubscriberRegistry; the
    // pre-R293 implementation used a bidirectional asymmetric
    // pattern-match approximation (peer-pattern over literal-query
    // OR query-pattern over literal-peer) that missed two-pattern
    // overlap cases such as `home/*/temp ∩ */sensor/temp`.

    #[test]
    fn intersect_literals_equal() {
        let a = "home/temp";
        let b = "home/temp";
        assert!(keyexpr_intersects(a, b));
    }

    #[test]
    fn intersect_literals_differ() {
        let a = "home/temp";
        let b = "home/door";
        assert!(!keyexpr_intersects(a, b));
        let c = "kitchen/temp";
        assert!(!keyexpr_intersects(a, c));
    }

    #[test]
    fn intersect_pattern_covers_literal_either_side() {
        // The pre-R293 asymmetric form caught these; the new matcher
        // must keep them green.
        let pat = "home/**";
        let lit = "home/temp";
        assert!(keyexpr_intersects(pat, lit));
        assert!(keyexpr_intersects(lit, pat));

        let mid_star = "sensors/*/temp";
        let exact = "sensors/room1/temp";
        assert!(keyexpr_intersects(mid_star, exact));
        assert!(keyexpr_intersects(exact, mid_star));
    }

    #[test]
    fn intersect_two_patterns_share_literal_via_mid_star() {
        // `home/*/temp ∩ */sensor/temp` shares `home/sensor/temp`
        // (and any `<x>/sensor/temp` for `<x> == home`). This is
        // the textbook two-pattern overlap case the pre-R293
        // approximation missed.
        let a = "home/*/temp";
        let b = "*/sensor/temp";
        assert!(keyexpr_intersects(a, b));
        assert!(keyexpr_intersects(b, a));
    }

    #[test]
    fn intersect_two_patterns_no_shared_literal() {
        // `home/* ∩ kitchen/*` share no literal: first chunk
        // disagrees on the literal anchor.
        let a = "home/*";
        let b = "kitchen/*";
        assert!(!keyexpr_intersects(a, b));
    }

    #[test]
    fn intersect_double_star_consumes_zero() {
        // `home/** ∩ home/temp` — `**` consumes zero on the empty
        // tail; `home/temp` exhausts after two chunks, `home/**`
        // consumes one chunk then `**` swallows the trailing
        // `temp` (or zero, depending on the recursion arm).
        let a = "home/**";
        let b = "home/temp";
        assert!(keyexpr_intersects(a, b));
        let c = "home";
        assert!(keyexpr_intersects(a, c));
        let d = "home/**";
        assert!(keyexpr_intersects(a, d));
    }

    #[test]
    fn intersect_double_star_both_sides_overlap_mid() {
        // `**/temp ∩ home/**` shares `home/temp` (and any
        // `home/<x>.../temp`).
        let a = "**/temp";
        let b = "home/**";
        assert!(keyexpr_intersects(a, b));
        assert!(keyexpr_intersects(b, a));
    }

    #[test]
    fn intersect_double_star_disjoint_anchors() {
        // `home/**/temp ∩ kitchen/**/temp` — literal anchors on
        // both sides disagree at position 0, no `**` shape can
        // bridge them.
        let a = "home/**/temp";
        let b = "kitchen/**/temp";
        assert!(!keyexpr_intersects(a, b));
    }

    #[test]
    fn intersect_double_star_match_anywhere() {
        // `**` alone is the zenoh match-everything pattern; it
        // intersects with every chunk shape.
        let star_star = "**";
        for ke in [
            "home/temp",
            "**",
            "*",
            "a/b/c/d/e",
            "sensors/$*",
            "home/*/door",
        ] {
            assert!(
                keyexpr_intersects(star_star, ke),
                "** should intersect with {ke}"
            );
            assert!(
                keyexpr_intersects(ke, star_star),
                "{ke} should intersect with ** (symmetric)"
            );
        }
    }

    #[test]
    fn intersect_dsl_one_side_matches_other_literal_chunk() {
        // `pre$*post ∩ prefix_post` — single-side $*; the DSL chunk
        // covers the literal chunk on the other side.
        let a = "a/pre$*post/b";
        let b = "a/prefix_post/b";
        assert!(keyexpr_intersects(a, b));
        assert!(keyexpr_intersects(b, a));
        // And a negative case: literal does not satisfy DSL anchors.
        let c = "a/wrongprefix_post/b";
        // `pre$*post` requires `pre` prefix and `post` suffix.
        assert!(!keyexpr_intersects(a, c));
    }

    #[test]
    fn intersect_dsl_both_sides_lead_trail_anchor() {
        // R296 closure: two-side `$*` is exact (not an
        // over-approximation) — equivalent to zenoh-pico's
        // intersects-mode chunk matcher. The lead/trail anchor
        // pair is both necessary and sufficient because middle
        // `$*`-separated sub-parts always interleave in a single
        // shared chunk literal.

        // `pre$*` ∩ `$*post` — shared literal `prepost` exists.
        let a = "pre$*";
        let b = "$*post";
        assert!(keyexpr_intersects(a, b));

        // Identical DSL chunks: trivially intersect.
        let c = "a$*b";
        let d = "a$*b";
        assert!(keyexpr_intersects(c, d));
    }

    #[test]
    fn intersect_dsl_both_sides_lead_anchor_mismatch_rejects() {
        // Lead anchors `A` vs `B` are byte-distinct (neither is a
        // prefix of the other) — no shared chunk literal possible.
        let a = "A$*Z";
        let b = "B$*Z";
        assert!(!keyexpr_intersects(a, b));
        assert!(!keyexpr_intersects(b, a));
    }

    #[test]
    fn intersect_dsl_both_sides_trail_anchor_mismatch_rejects() {
        // Trail anchors `A` vs `B` are byte-distinct — no shared
        // chunk literal.
        let a = "X$*A";
        let b = "X$*B";
        assert!(!keyexpr_intersects(a, b));
        assert!(!keyexpr_intersects(b, a));
    }

    #[test]
    fn intersect_dsl_both_sides_lead_prefix_compatible_accepts() {
        // Lead anchor `AB` extends `A` — the shorter is a prefix
        // of the longer. Shared literal exists (`AB...` family
        // covers both patterns when trails align).
        let a = "A$*Z";
        let b = "AB$*Z";
        assert!(keyexpr_intersects(a, b));
        assert!(keyexpr_intersects(b, a));
    }

    #[test]
    fn intersect_dsl_both_sides_trail_suffix_compatible_accepts() {
        // Trail anchor `BC` extends `C` — the shorter is a suffix
        // of the longer. Shared literal exists in the `...BC`
        // family (lead empties trivially align).
        let a = "$*C";
        let b = "$*BC";
        assert!(keyexpr_intersects(a, b));
        assert!(keyexpr_intersects(b, a));
    }

    #[test]
    fn intersect_dsl_both_sides_middle_sub_parts_always_fit() {
        // Middle sub-parts in arbitrary order on either side fit
        // in a shared chunk literal via alternating interleaving.
        // a = "$*A$*B$*"   — middles [A, B] in order
        // b = "$*B$*A$*"   — middles [B, A] in opposite order
        // Lead/trail both empty → compatible. Shared literal e.g.
        // "BABA" satisfies both pattern orderings.
        let a = "$*A$*B$*";
        let b = "$*B$*A$*";
        assert!(keyexpr_intersects(a, b));
        assert!(keyexpr_intersects(b, a));
    }

    #[test]
    fn intersect_dsl_both_sides_distinct_middles_accept() {
        // Distinct middle sub-parts on both sides ("ABC" vs
        // "XYZ") — shared chunk literal `ABCXYZ` (or any
        // concatenation) satisfies both. zenoh-pico matches the
        // outcome via the `right has $*` over-approximation
        // branch (line 156 of keyexpr_match_template.h).
        let a = "$*ABC$*";
        let b = "$*XYZ$*";
        assert!(keyexpr_intersects(a, b));
        assert!(keyexpr_intersects(b, a));
    }

    #[test]
    fn intersect_dsl_both_sides_lead_prefix_with_trail_suffix_overlap() {
        // Lead "AB" extends "A", trail "BA" extends "A" — both
        // anchor checks pass. Shared literal example: "ABA"
        // (a pattern: "AB" + "" + "A"; b pattern: "A" + "B" + "A").
        let a = "AB$*A";
        let b = "A$*BA";
        assert!(keyexpr_intersects(a, b));
        assert!(keyexpr_intersects(b, a));
    }

    #[test]
    fn intersect_dsl_both_sides_byte_overlap_lead_rejects() {
        // Lead "AB" and "AX" share the first byte 'A' but diverge
        // at the second byte. Neither is a prefix of the other —
        // no shared literal with both `AB` and `AX` prefixes.
        let a = "AB$*Z";
        let b = "AX$*Z";
        assert!(!keyexpr_intersects(a, b));
        assert!(!keyexpr_intersects(b, a));
    }

    #[test]
    fn intersect_symmetry_under_swap() {
        // Spot-check symmetry: every honest input pair should give
        // the same answer regardless of arg order.
        let cases: &[(&str, &str)] = &[
            ("home/temp", "home/temp"),
            ("home/*", "home/temp"),
            ("home/*/temp", "*/sensor/temp"),
            ("home/**", "home/temp"),
            ("**/temp", "home/**"),
            ("home/**/temp", "kitchen/**/temp"),
            ("**", "anything/at/all"),
            ("a/$*/b", "a/literal/b"),
        ];
        for &(lhs, rhs) in cases {
            assert_eq!(
                keyexpr_intersects(lhs, rhs),
                keyexpr_intersects(rhs, lhs),
                "symmetry must hold for {lhs} vs {rhs}",
            );
        }
    }

    // ── R221 canonicalization-on-register behaviour ──

    #[test]
    fn register_canonicalizes_lone_dollar_star_chunk_to_single_star() {
        // `home/$*/temp` is non-canonical; the registry should
        // canonicalize to `home/*/temp` on register so the stored
        // chunks behave identically to a peer's canonical wire form.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("home/$*/temp", move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let push = push_with_keyexpr("home/kitchen/temp");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "canonicalized `home/$*/temp` (== `home/*/temp`) matches single-chunk middle"
        );

        // Boundary check: still does not collapse to zero chunks.
        let push = push_with_keyexpr("home/temp");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "canonicalized `*` does not match the zero-chunk case"
        );
    }

    /// R311y564 — this test used to assert the OPPOSITE, and asserting it is
    /// what kept the defect alive for the whole life of the canonizer.
    ///
    /// `home/**/*/temp` canonicalizes to `home/*/**/temp`: the `*` is
    /// REORDERED ahead of the `**`, not absorbed by it. The two say different
    /// things and this registry is where the difference is observable —
    /// `home/**/temp` matches `home/temp`, while `home/**/*/temp` requires at
    /// least one chunk in between. wz was absorbing, so every subscriber of
    /// this shape was silently WIDENED and received samples upstream would not
    /// have delivered.
    ///
    /// Both real references were probed and both reorder; see
    /// [`keyexpr_canon`](crate::keyexpr_canon::KeyexprDialect).
    #[test]
    fn register_canonicalizes_single_star_after_double_star() {
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("home/**/*/temp", move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        // The zero-extra-chunk case must NOT match: one wild chunk is required.
        let push = push_with_keyexpr("home/temp");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "`home/**/*/temp` requires at least one chunk between `home` and \
             `temp`; matching `home/temp` is the widening this canon rule fixed"
        );

        // One chunk, and more than one, both match.
        for target in ["home/a/temp", "home/a/b/temp"] {
            let push = push_with_keyexpr(target);
            registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "`home/*/**/temp` matches one or more intervening chunks"
        );
    }

    #[test]
    fn register_canonicalizes_dsl_run_collapse() {
        // `home/$*$*$*foo` canonicalizes to `home/$*foo` via the
        // singleify pass; the DSL matcher then anchors the trailing
        // "foo" against the target chunk.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("home/$*$*$*foo", move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let push = push_with_keyexpr("home/barfoo");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "canonicalized `$*foo` (post-singleify) matches the target's trailing 'foo'"
        );
    }

    #[test]
    fn register_falls_back_to_raw_on_invalid_pattern() {
        // Structurally invalid pattern (`?` is reserved) — the
        // registry should not panic; it should store the raw form
        // and emit a warning (not asserted here). The matcher will
        // simply never fire since no canonical wire keyexpr
        // contains `?`.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("home/foo?bar", move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");
        // Registry accepted the registration without panicking.
        assert_eq!(registry.len(), 1);
        // Dispatch with a structurally valid keyexpr that does NOT
        // contain `?` — no callback fires.
        let push = push_with_keyexpr("home/foobar");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "invalid pattern stored raw does not spuriously match canonical traffic"
        );
    }

    // ── R223 Locality filter behaviour ──

    #[test]
    fn register_defaults_to_locality_any_and_fires_on_inbound() {
        // Default register() uses Locality::Any; inbound Pushes
        // (which wz treats as remote) fire the callback as they did
        // before R223. Regression guard for the default path.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("home/temp", move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let push = push_with_keyexpr("home/temp");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "Locality::Any default fires on inbound (remote) Push"
        );
    }

    #[test]
    fn register_with_locality_remote_fires_on_inbound() {
        // Locality::Remote is the canonical setting for the
        // wire-only subscription; inbound Pushes still fire because
        // they originate from the wire (== remote).
        use crate::locality::Locality;
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register_with_locality("home/temp", Locality::Remote, move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let push = push_with_keyexpr("home/temp");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "Locality::Remote fires for wire-arrived Push"
        );
    }

    #[test]
    fn register_with_locality_session_local_does_not_fire_on_inbound() {
        // Wire-arrived Push reaches dispatch_push with `is_remote =
        // true`; the locality predicate is therefore
        // `allows_remote()`, which is false for SessionLocal.
        // SessionLocal subscribers fire only through the
        // `local_publish` loopback path (R227) — never on inbound.
        use crate::locality::Locality;
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register_with_locality("home/temp", Locality::SessionLocal, move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let push = push_with_keyexpr("home/temp");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "Locality::SessionLocal suppresses wire-arrived (is_remote=true) Push"
        );
    }

    #[test]
    fn locality_filter_applies_per_subscriber_not_globally() {
        // Two subscribers on the same keyexpr — one Any, one
        // SessionLocal — share a registry. An inbound Push fires
        // exactly the Any one; the SessionLocal one is silent.
        use crate::locality::Locality;
        let mut registry = SubscriberRegistry::new();
        let any_counter = Arc::new(AtomicUsize::new(0));
        let local_counter = Arc::new(AtomicUsize::new(0));
        let any_clone = any_counter.clone();
        let local_clone = local_counter.clone();
        registry
            .register("home/temp", move |_push| {
                any_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");
        registry
            .register_with_locality("home/temp", Locality::SessionLocal, move |_push| {
                local_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let push = push_with_keyexpr("home/temp");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
        assert_eq!(
            any_counter.load(Ordering::SeqCst),
            1,
            "Locality::Any subscriber fires on inbound"
        );
        assert_eq!(
            local_counter.load(Ordering::SeqCst),
            0,
            "Locality::SessionLocal subscriber does not fire on inbound"
        );
    }

    #[test]
    fn locality_filter_runs_before_keyexpr_match() {
        // Even when the keyexpr would match, locality must filter
        // first — a SessionLocal subscriber on a wildcard pattern
        // still does not fire on an inbound Push. Guards against
        // a future refactor that accidentally inverts the check
        // order.
        use crate::locality::Locality;
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register_with_locality("**", Locality::SessionLocal, move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let push = push_with_keyexpr("home/kitchen/temp");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "locality short-circuits before keyexpr match (`**` matches everything but is suppressed)"
        );
    }

    // ── R222 Push -> Sample projection behaviour ──

    fn push_with_payload(keyexpr: &str, payload: &[u8]) -> PushOwned {
        let mut push = push_with_keyexpr(keyexpr);
        if let PushOwnedVariant::CodecZenohMsgPut(ref mut put) = push.body {
            *put = crate::put_payload::inline(payload).unwrap();
        }
        push
    }

    #[test]
    fn dispatch_projects_put_push_into_sample_put_with_payload() {
        use crate::sample::SampleKind;
        use std::sync::Mutex;
        let mut registry = SubscriberRegistry::new();
        let captured = Arc::new(Mutex::new(None::<crate::sample::Sample>));
        let captured_clone = captured.clone();
        registry
            .register("home/temp", move |sample| {
                *captured_clone.lock().unwrap() = Some(Sample::from_view(sample));
            })
            .expect("no quota is stated on this table");

        let push = push_with_payload("home/temp", b"23.5");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);

        let observed = captured.lock().unwrap().clone().expect("callback fired");
        assert_eq!(observed.keyexpr, "home/temp");
        assert_eq!(observed.kind, SampleKind::Put);
        assert_eq!(observed.payload, b"23.5");
    }

    #[test]
    fn dispatch_projects_del_push_into_sample_del_with_empty_payload() {
        use crate::sample::SampleKind;
        use std::sync::Mutex;
        let mut registry = SubscriberRegistry::new();
        let captured = Arc::new(Mutex::new(None::<crate::sample::Sample>));
        let captured_clone = captured.clone();
        registry
            .register("clear/me", move |sample| {
                *captured_clone.lock().unwrap() = Some(Sample::from_view(sample));
            })
            .expect("no quota is stated on this table");

        let push = push_with_del_body("clear/me");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);

        let observed = captured.lock().unwrap().clone().expect("callback fired");
        assert_eq!(observed.keyexpr, "clear/me");
        assert_eq!(observed.kind, SampleKind::Del);
        assert!(
            observed.payload.is_empty(),
            "Del has no payload on the wire"
        );
    }

    #[test]
    fn dispatch_sample_keyexpr_carries_resolved_form_not_wire_id() {
        // Models the DECLARE-then-Push flow: peer declares mapping
        // id=7 → "sensors/room1/temp"; subsequent Push with id=7 +
        // suffix=None must surface Sample.keyexpr == the resolved
        // literal, NOT the raw id form.
        use std::sync::Mutex;
        let mut registry = SubscriberRegistry::new();
        let captured = Arc::new(Mutex::new(None::<String>));
        let captured_clone = captured.clone();
        registry
            .register("sensors/**", move |sample| {
                *captured_clone.lock().unwrap() = Some(sample.keyexpr().to_string());
            })
            .expect("no quota is stated on this table");

        registry.dispatch(
            &NetworkMessage::Declare(Box::new(declare_kexpr_literal(7, "sensors/room1/temp"))),
            Reliability::Reliable,
        );
        let push = push_with_mapping_id(7, None);
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);

        let observed = captured.lock().unwrap().clone().expect("callback fired");
        assert_eq!(
            observed, "sensors/room1/temp",
            "Sample.keyexpr surfaces the resolved literal, not the mapping id"
        );
    }

    #[test]
    fn dispatch_fires_callback_on_wildcard_match() {
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("sensors/*/temp", move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let push = push_with_keyexpr("sensors/room1/temp");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "single-chunk `*` matches the target's middle chunk"
        );
    }

    #[test]
    fn dispatch_fires_callback_on_double_star_prefix() {
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("home/**", move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let push = push_with_keyexpr("home/kitchen/sensor/c");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "`home/**` matches any descendant of `home`"
        );
    }

    #[test]
    fn dispatch_skips_callback_on_wildcard_mismatch() {
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("sensors/*/temp", move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        // `sensors/temp` lacks the middle chunk that `*` requires.
        let push = push_with_keyexpr("sensors/temp");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);

        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "`*` does not collapse to zero chunks"
        );
    }

    #[test]
    fn unregister_removes_subscriber_idempotently() {
        let mut registry = SubscriberRegistry::new();
        let id = registry
            .register("topic/a", |_push| {})
            .expect("no quota is stated on this table");
        assert_eq!(registry.len(), 1);
        assert!(registry.unregister(id));
        assert_eq!(registry.len(), 0);
        // Second call to unregister returns false (idempotent) and
        // does not panic.
        assert!(!registry.unregister(id));
    }

    // ── R121d DECLARE-resolver behaviour ──

    /// Build a Declare envelope carrying a DeclKexpr that maps
    /// `id` to the literal keyexpr suffix `s`. Models the wire
    /// shape zenoh-pico emits on `z_declare_keyexpr` when the
    /// argument is a string (no prefix mapping).
    fn declare_kexpr_literal(
        mapping_id: u64,
        s: &str,
    ) -> crate::transport_profile::owned::DeclareOwned {
        wz_codecs::lent::Declare {
            body: wz_codecs::lent::DeclareVariant::CodecZenohDeclKexpr(
                wz_codecs::lent::DeclKexpr {
                    id: mapping_id,
                    keyexpr: wz_codecs::lent::Wireexpr {
                        body: WireexprVariant::WireexprLocal(wz_codecs::lent::WireexprLocal {
                            id: 0,
                            suffix_len: Some(s.len() as u64),
                            suffix: Some(sce_forge_runtime::codec::Bounded::new(s).unwrap()),
                        }),
                    },
                    ..Default::default()
                },
            ),
            ..Default::default()
        }
        .try_into_owned_in::<crate::transport_profile::TransportStorage>()
        .unwrap()
    }

    /// R2385 — a DeclKexpr whose declared keyexpr is itself SCOPED: `mapping_id`
    /// is bound to `scope`'s literal plus `suffix`.
    ///
    /// The arm is `WireexprLocal` because that is what wz's decoder produces for
    /// every inbound DeclKexpr — `out/wz-codecs/decl_kexpr.rs` passes the arm
    /// selector as the literal `0x1u8`, since the D_KEXPR header has no bit 6 to
    /// derive it from. So this is the wire shape, not a choice the fixture makes.
    fn declare_kexpr_scoped(
        mapping_id: u64,
        scope: crate::wire_id::ExprId,
        suffix: &str,
    ) -> crate::transport_profile::owned::DeclareOwned {
        wz_codecs::lent::Declare {
            body: wz_codecs::lent::DeclareVariant::CodecZenohDeclKexpr(
                wz_codecs::lent::DeclKexpr {
                    id: mapping_id,
                    keyexpr: wz_codecs::lent::Wireexpr {
                        body: WireexprVariant::WireexprLocal(wz_codecs::lent::WireexprLocal {
                            id: scope,
                            suffix_len: Some(suffix.len() as u64),
                            suffix: Some(sce_forge_runtime::codec::Bounded::new(suffix).unwrap()),
                        }),
                    },
                    ..Default::default()
                },
            ),
            ..Default::default()
        }
        .try_into_owned_in::<crate::transport_profile::TransportStorage>()
        .unwrap()
    }

    fn undeclare_kexpr(mapping_id: u64) -> crate::transport_profile::owned::DeclareOwned {
        wz_codecs::lent::Declare {
            body: wz_codecs::lent::DeclareVariant::CodecZenohUndeclKexpr(
                wz_codecs::lent::UndeclKexpr {
                    id: mapping_id,
                    ..Default::default()
                },
            ),
            ..Default::default()
        }
        .try_into_owned_in::<crate::transport_profile::TransportStorage>()
        .unwrap()
    }

    fn push_with_mapping_id(
        mapping_id: crate::wire_id::ExprId,
        inline_suffix: Option<&str>,
    ) -> PushOwned {
        Push {
            keyexpr: wz_codecs::lent::Wireexpr {
                body: WireexprVariant::WireexprLocal(wz_codecs::lent::WireexprLocal {
                    id: mapping_id,
                    suffix_len: inline_suffix.map(|s| s.len() as u64),
                    suffix: inline_suffix.map(|s| wz_codecs::Bounded::new(s).unwrap()),
                }),
            },
            ..Push::default()
        }
        .try_into_owned_in::<crate::wire::WireStorage>()
        .unwrap()
    }

    /// An `M=0` (`Mapping::Receiver`) aliased Push — the id names OUR space.
    /// This is what a zenoh peer emits for an id we declared, because
    /// `get_best_key` prefers `ctx.remote_expr_id` and stamps it
    /// `Mapping::Receiver` (`dispatcher/resource.rs:625`).
    fn push_with_own_mapping_id(
        mapping_id: crate::wire_id::ExprId,
        inline_suffix: Option<&str>,
    ) -> PushOwned {
        Push {
            keyexpr: wz_codecs::lent::Wireexpr {
                body: WireexprVariant::WireexprNonlocal(wz_codecs::lent::WireexprNonlocal {
                    id: mapping_id,
                    suffix_len: inline_suffix.map(|s| s.len() as u64),
                    suffix: inline_suffix.map(|s| wz_codecs::Bounded::new(s).unwrap()),
                }),
            },
            ..Push::default()
        }
        .try_into_owned_in::<crate::wire::WireStorage>()
        .unwrap()
    }

    /// R311y739 — OUR id space as a bare table, installed on the registry.
    fn own_space(
        id: crate::wire_id::ExprId,
        literal: &str,
    ) -> alloc::sync::Arc<HashMap<crate::wire_id::ExprId, String>> {
        let mut t = HashMap::new();
        t.insert(id, literal.to_string());
        alloc::sync::Arc::new(t)
    }

    /// R311y739 — an `M=0` alias fires the subscriber registered against the
    /// literal WE declared for that id.
    ///
    /// THE DISCRIMINATOR is the peer declaration of the SAME id 4 under a
    /// different literal: if the resolver read the wrong space it would resolve
    /// `peer/only/temp` and fire the OTHER subscriber, so a swapped lookup is
    /// caught as a wrong fire rather than as silence.
    #[test]
    fn an_own_space_alias_fires_the_subscriber_that_matches_our_literal() {
        let mut registry = SubscriberRegistry::new();
        registry.set_own_mapping_space(own_space(4, "ours/temp"));

        let ours = Arc::new(AtomicUsize::new(0));
        let theirs = Arc::new(AtomicUsize::new(0));
        let (o, t) = (ours.clone(), theirs.clone());
        registry
            .register("ours/temp", move |_| {
                o.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");
        registry
            .register("peer/only/temp", move |_| {
                t.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        // The PEER declares id 4 too, under its own literal. Both spaces now
        // hold 4, which is the collision the mapping bit exists to resolve.
        registry.dispatch(
            &NetworkMessage::Declare(Box::new(declare_kexpr_literal(4, "peer/only/temp"))),
            Reliability::Reliable,
        );
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_with_own_mapping_id(4, None))),
            Reliability::Reliable,
        );

        assert_eq!(
            ours.load(Ordering::SeqCst),
            1,
            "an M=0 alias names OUR space; id 4 is `ours/temp` there",
        );
        assert_eq!(
            theirs.load(Ordering::SeqCst),
            0,
            "reading the peer's space for an M=0 alias is the wrong-space read \
             -- it would have fired this subscriber instead",
        );
    }

    /// ANTI-VACUITY twin. With NO own space installed the same Push resolves
    /// nothing and fires nobody — so the test above is measuring the install,
    /// not merely that some table was consulted. This is also the pre-R311y739
    /// behaviour, i.e. the defect this round removed: the peer's traffic was
    /// silently dropped.
    #[test]
    fn without_an_installed_own_space_the_same_alias_fires_nobody() {
        let mut registry = SubscriberRegistry::new();
        let ours = Arc::new(AtomicUsize::new(0));
        let theirs = Arc::new(AtomicUsize::new(0));
        let (o, t) = (ours.clone(), theirs.clone());
        registry
            .register("ours/temp", move |_| {
                o.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");
        registry
            .register("peer/only/temp", move |_| {
                t.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");
        registry.dispatch(
            &NetworkMessage::Declare(Box::new(declare_kexpr_literal(4, "peer/only/temp"))),
            Reliability::Reliable,
        );
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_with_own_mapping_id(4, None))),
            Reliability::Reliable,
        );
        assert_eq!(ours.load(Ordering::SeqCst), 0);
        assert_eq!(
            theirs.load(Ordering::SeqCst),
            0,
            "no own space must mean NO resolution -- never a fallback read of \
             the peer's table, which holds id 4",
        );
    }

    /// The install is releasable, and releasing it restores the refusal. Pins
    /// that the two states are reachable in both directions from one registry,
    /// so a session re-init cannot leave a stale space answering for ids the
    /// new session never declared.
    #[test]
    fn clearing_the_own_space_restores_the_refusal() {
        let mut registry = SubscriberRegistry::new();
        registry.set_own_mapping_space(own_space(4, "ours/temp"));
        let ours = Arc::new(AtomicUsize::new(0));
        let o = ours.clone();
        registry
            .register("ours/temp", move |_| {
                o.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_with_own_mapping_id(4, None))),
            Reliability::Reliable,
        );
        assert_eq!(ours.load(Ordering::SeqCst), 1);

        registry.clear_own_mapping_space();
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_with_own_mapping_id(4, None))),
            Reliability::Reliable,
        );
        assert_eq!(
            ours.load(Ordering::SeqCst),
            1,
            "after clear, the same alias must resolve nothing again",
        );
    }

    /// The suffix composes on the `M=0` arm too: `ours/` + `temp`.
    #[test]
    fn an_own_space_alias_composes_its_inline_suffix() {
        let mut registry = SubscriberRegistry::new();
        registry.set_own_mapping_space(own_space(6, "ours/"));
        let fired = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        registry
            .register("ours/temp", move |_| {
                f.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_with_own_mapping_id(6, Some("temp")))),
            Reliability::Reliable,
        );
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    }

    /// An `M=0` LITERAL (`id == 0`) consults no space at all, so it kept
    /// working before this round and must keep working now. The regression
    /// guard: the overwhelming majority of wire keyexprs take this path, and
    /// keying the refusal on the ARM rather than on `id != 0` would silence
    /// them all.
    #[test]
    fn an_own_space_literal_needs_no_install() {
        let mut registry = SubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        registry
            .register("home/temp", move |_| {
                f.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_with_own_mapping_id(0, Some("home/temp")))),
            Reliability::Reliable,
        );
        assert_eq!(fired.load(Ordering::SeqCst), 1);
    }

    /// R311y750 (carry N38) — the peer half has ONE door out of this registry,
    /// and that door does not answer the pair's question.
    ///
    /// N38 carried a zero-caller accessor, `SubscriberRegistry`'s bare
    /// `peer_keyexpr_table()`, kept for "the caller that binds INTO the peer's
    /// space". No such caller could ever have existed: it lent a `&`, and the
    /// binding site reaches the field. What a zero-caller accessor costs is not
    /// the dead code — it is that the WEAKER of two doors stays in reach of a
    /// consumer who only wants to read something, and reading the peer half
    /// where the pair was needed is a confident wrong answer, not a miss.
    ///
    /// THE DISCRIMINATOR is that wrong answer made real: id 7 is declared by
    /// the peer as `theirs/seven` and by US as `ours/seven`. The narrow half
    /// yields the peer's literal; the pair, asked about an `M=0` alias for the
    /// same id, yields ours. A test that only checked "the table is readable"
    /// would pass with the two spaces swapped.
    #[test]
    fn the_peer_half_is_reachable_only_through_the_pair_and_cannot_answer_for_it() {
        let mut registry = SubscriberRegistry::new();
        registry.set_own_mapping_space(own_space(7, "ours/seven"));
        registry.dispatch(
            &NetworkMessage::Declare(Box::new(declare_kexpr_literal(7, "theirs/seven"))),
            Reliability::Reliable,
        );

        // ONE door: what `absorb_declare` bound is what the pair yields.
        assert_eq!(
            registry
                .mapping_spaces()
                .peer()
                .get(&7)
                .map(AsRef::<str>::as_ref),
            Some("theirs/seven"),
            "the pair's peer half IS the table the DeclKexpr absorb binds into",
        );
        // The single-id resolver reads that same table, so the two readers
        // cannot drift apart into two tables holding two answers.
        assert_eq!(
            registry.resolve_inbound_mapping(7).as_deref(),
            Some("theirs/seven"),
            "the single-id form names the PEER half by contract",
        );

        // The half is NOT the pair, and this is the half's whole hazard: an
        // `M=0` alias for the SAME id resolves in our space, which the peer
        // table neither holds nor can be asked about.
        let spaces = registry.mapping_spaces();
        assert!(spaces.has_own(), "the own space was installed above");
        let own_alias = push_with_own_mapping_id(7, None);
        assert_eq!(
            resolve_wireexpr_in(&own_alias.keyexpr.body, spaces).as_deref(),
            Some("ours/seven"),
            "an M=0 alias names OUR space; substituting the peer half here \
             would have answered `theirs/seven` with full confidence",
        );
    }

    /// A peer's `DeclareKeyExpr` id wider than an `ExprId` binds the id upstream
    /// narrows it to, so the scope a later message names finds it, and its
    /// `UndeclareKeyExpr` of the same wide id unbinds it.
    #[test]
    fn a_declared_id_wider_than_an_expr_id_binds_and_unbinds_the_narrowed_id() {
        let mut registry = SubscriberRegistry::new();
        let wide = (1u64 << 16) | 7;
        registry.dispatch(
            &NetworkMessage::Declare(Box::new(declare_kexpr_literal(wide, "theirs/seven"))),
            Reliability::Reliable,
        );
        assert_eq!(
            registry.resolve_inbound_mapping(7).as_deref(),
            Some("theirs/seven")
        );
        registry.dispatch(
            &NetworkMessage::Declare(Box::new(undeclare_kexpr(wide))),
            Reliability::Reliable,
        );
        assert_eq!(registry.resolve_inbound_mapping(7), None);
    }

    /// R2385 — a peer declaring a mapping ROOTED IN A PREFIX WE DECLARED now
    /// binds, and the Push that follows fires the subscriber.
    ///
    /// This is zenoh's inbound reading of a D_KEXPR scope: `register_expr`
    /// resolves it through `Mapping::DEFAULT`, which is `Receiver`, so the scope
    /// names `FaceState::local_mappings` — the ids the RECEIVER declared. wz's
    /// decoder pins the `WireexprLocal` arm on this message (bit 6 of the
    /// D_KEXPR header is Reserved, so there is nothing to derive it from), which
    /// sent the lookup to the peer's table; id 4 is not there, so the whole
    /// declaration used to bind NOTHING and every later reference to id 9 went
    /// unresolved.
    ///
    /// THE DISCRIMINATOR is the second subscriber. If the scope had been read
    /// out of the peer's space the declaration would bind nothing and NEITHER
    /// callback fires, so a silent regression here reads as zero rather than as
    /// the wrong one — and the `theirs/temp` registration is what proves the
    /// resolution went to our space rather than to whichever table was
    /// non-empty.
    #[test]
    fn a_peer_mapping_scoped_on_a_prefix_we_declared_binds_and_fires() {
        let mut registry = SubscriberRegistry::new();
        registry.set_own_mapping_space(own_space(4, "ours/temp"));

        let ours = Arc::new(AtomicUsize::new(0));
        let theirs = Arc::new(AtomicUsize::new(0));
        let (o, t) = (ours.clone(), theirs.clone());
        registry
            .register("ours/temp/inner", move |_| {
                o.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");
        registry
            .register("theirs/temp/inner", move |_| {
                t.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        // The peer mints id 9 for "<the prefix you called 4>/inner".
        registry.dispatch(
            &NetworkMessage::Declare(Box::new(declare_kexpr_scoped(9, 4, "/inner"))),
            Reliability::Reliable,
        );
        assert_eq!(
            registry.resolve_inbound_mapping(9).as_deref(),
            Some("ours/temp/inner"),
            "the scope names an id WE declared; before R2385 this bound nothing",
        );

        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_with_mapping_id(9, None))),
            Reliability::Reliable,
        );
        assert_eq!(ours.load(Ordering::SeqCst), 1);
        assert_eq!(theirs.load(Ordering::SeqCst), 0);
    }

    /// ANTI-VACUITY for the test above, and the pico reading kept intact: a
    /// scope naming an id THE PEER declared still resolves in the peer's space.
    ///
    /// pico decodes a D_KEXPR wireexpr with `remote_mapping = true` and stamps
    /// the peer token, so `_z_register_resource_inner` takes
    /// `peer->_remote_resources`. That is the arm wz always had; if R2385 had
    /// merely swapped which table it reads, this test breaks.
    #[test]
    fn a_peer_mapping_scoped_on_a_prefix_the_peer_declared_still_binds() {
        let mut registry = SubscriberRegistry::new();
        registry.set_own_mapping_space(own_space(4, "ours/temp"));
        registry.dispatch(
            &NetworkMessage::Declare(Box::new(declare_kexpr_literal(5, "theirs/temp"))),
            Reliability::Reliable,
        );
        registry.dispatch(
            &NetworkMessage::Declare(Box::new(declare_kexpr_scoped(9, 5, "/inner"))),
            Reliability::Reliable,
        );
        assert_eq!(
            registry.resolve_inbound_mapping(9).as_deref(),
            Some("theirs/temp/inner"),
        );
    }

    /// A scope BOTH spaces claim, under different literals, binds nothing.
    ///
    /// The wire has no bit to say which was meant — zenoh would take ours, pico
    /// the peer's — and a wrong base makes every later reference to id 9
    /// confidently wrong. Before R2385 this bound `theirs/temp/inner` without
    /// hesitating.
    #[test]
    fn a_scope_both_spaces_claim_differently_binds_nothing() {
        let mut registry = SubscriberRegistry::new();
        registry.set_own_mapping_space(own_space(4, "ours/temp"));
        registry.dispatch(
            &NetworkMessage::Declare(Box::new(declare_kexpr_literal(4, "theirs/temp"))),
            Reliability::Reliable,
        );
        registry.dispatch(
            &NetworkMessage::Declare(Box::new(declare_kexpr_scoped(9, 4, "/inner"))),
            Reliability::Reliable,
        );
        assert_eq!(
            registry.resolve_inbound_mapping(9),
            None,
            "two candidate bases and no bit to choose: bind nothing",
        );
        assert_eq!(
            registry.resolve_inbound_mapping(4).as_deref(),
            Some("theirs/temp"),
            "the ambiguous scope must not disturb the binding it read",
        );
    }

    #[test]
    fn declare_then_push_with_mapping_id_resolves_via_table() {
        // Models the zenoh-pico z_put flow: peer first declares
        // a literal keyexpr under mapping id 1, then publishes
        // referencing that id. The registry's resolver must
        // resolve id=1 to "demo/test" and fire the matching
        // subscriber.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("demo/test", move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        registry.dispatch(
            &NetworkMessage::Declare(Box::new(declare_kexpr_literal(1, "demo/test"))),
            Reliability::Reliable,
        );
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_with_mapping_id(1, None))),
            Reliability::Reliable,
        );

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "Push referencing a declared mapping id must resolve via the table \
             and fire the matching subscriber"
        );
    }

    #[test]
    fn undeclare_removes_mapping_so_later_push_no_longer_resolves() {
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("demo/test", move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        registry.dispatch(
            &NetworkMessage::Declare(Box::new(declare_kexpr_literal(1, "demo/test"))),
            Reliability::Reliable,
        );
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_with_mapping_id(1, None))),
            Reliability::Reliable,
        );
        registry.dispatch(
            &NetworkMessage::Declare(Box::new(undeclare_kexpr(1))),
            Reliability::Reliable,
        );
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_with_mapping_id(1, None))),
            Reliability::Reliable,
        );

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "post-undeclare Push referencing the same id must not resolve / fire"
        );
    }

    #[test]
    fn push_with_mapping_id_and_inline_suffix_appends_to_base() {
        // The Zenoh mapping-id + optional inline suffix composition:
        // resolved keyexpr = table[id] + suffix.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("home/sensor/temp", move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        registry.dispatch(
            &NetworkMessage::Declare(Box::new(declare_kexpr_literal(5, "home/sensor/"))),
            Reliability::Reliable,
        );
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_with_mapping_id(5, Some("temp")))),
            Reliability::Reliable,
        );

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "Push id=5 + suffix=temp must resolve to 'home/sensor/temp' \
             via the base+suffix composition rule"
        );
    }

    // ── R237 resolve_inbound_mapping single-id accessor ──

    #[test]
    fn resolve_inbound_mapping_returns_none_for_unknown_id() {
        // A fresh registry has no peer-declared mappings; every id
        // queried must resolve to None. This pins the "absent =
        // None" contract so a future refactor that defaults a
        // missing slot to the empty string (silent mis-mapping)
        // surfaces here.
        let registry = SubscriberRegistry::new();
        assert_eq!(registry.resolve_inbound_mapping(0), None);
        assert_eq!(registry.resolve_inbound_mapping(1), None);
        assert_eq!(
            registry.resolve_inbound_mapping(crate::wire_id::ExprId::MAX),
            None
        );
    }

    #[test]
    fn resolve_inbound_mapping_returns_literal_after_decl_kexpr() {
        // After absorbing a `Declare(DeclKexpr(id=7, "home/temp"))`,
        // the resolver must return Some("home/temp") for id=7 and
        // None for every other id. The returned String is owned —
        // the caller may drop the registry borrow before further
        // use, matching the R234 outbound mirror contract.
        let mut registry = SubscriberRegistry::new();
        registry.dispatch(
            &NetworkMessage::Declare(Box::new(declare_kexpr_literal(7, "home/temp"))),
            Reliability::Reliable,
        );
        assert_eq!(
            registry.resolve_inbound_mapping(7),
            Some("home/temp".to_string()),
        );
        assert_eq!(registry.resolve_inbound_mapping(8), None);
    }

    /// What one registry records of each sample it delivers, in the form two registries
    /// can be compared by.
    fn record_samples(
        registry: &mut SubscriberRegistry<BoxedSink>,
        pattern: &str,
    ) -> Arc<std::sync::Mutex<Vec<String>>> {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_in = seen.clone();
        registry
            .register(pattern, move |sample| {
                seen_in.lock().unwrap().push(std::format!(
                    "{} {:?} {:?} {:?} {:?}",
                    sample.keyexpr(),
                    sample.payload(),
                    sample.kind(),
                    sample.reliability(),
                    sample.qos()
                ));
            })
            .expect("no quota is stated on this table");
        seen
    }

    /// A frame of plain Puts reaches a subscriber as the owned path delivers the same
    /// frame: the same keys (an alias, an alias with a suffix, a literal), payloads, QoS and
    /// reliability, in the same order, with a key nobody declared dropped by both and a key
    /// no subscriber matches delivered to nobody by both.
    ///
    /// The build that lends every record has no plain-put lane: its receive lends the same frame's
    /// records where they lie, and that delivery is the one compared there
    /// (`crate::driver_loop::deliver_frame`).
    #[test]
    fn a_frame_of_plain_puts_is_delivered_as_the_owned_path_delivers_it() {
        let long = vec![5u8; 300];
        let puts: [(crate::wire_id::ExprId, Option<&str>, &[u8], u8); 7] = [
            (7, None, b"alias", 0x05),
            (7, Some("/sub"), b"", 0x05),
            (0, Some("demo/literal"), &long, 0x1a),
            (9, None, b"nobody declared 9", 0x05),
            (0, Some("other/key"), b"matches no subscriber", 0x05),
            (7, None, b"alias again", 0x1a),
            (0, Some("demo/literal"), b"x", 0x05),
        ];
        let mut batch = Vec::new();
        for (id, suffix, payload, qos) in puts {
            let push = crate::lent_push::put_with_qos(
                id,
                suffix,
                payload,
                crate::sample::QosLevel::from_raw(qos),
            )
            .unwrap();
            let mut one = Vec::new();
            push.encode(&mut sce_forge_runtime::codec::VecSink::new(&mut one))
                .unwrap();
            batch.extend_from_slice(&one);
        }

        for reliable in [true, false] {
            let reliability = Reliability::from_reliable_bool(reliable);
            let mut owned = SubscriberRegistry::new();
            let mut lane = SubscriberRegistry::new();
            let seen_owned = record_samples(&mut owned, "demo/**");
            let seen_lane = record_samples(&mut lane, "demo/**");
            for registry in [&mut owned, &mut lane] {
                registry.dispatch(
                    &NetworkMessage::Declare(Box::new(declare_kexpr_literal(7, "demo/alias"))),
                    Reliability::Reliable,
                );
            }

            for message in crate::network_message::parse_frame_payload(&batch).unwrap() {
                owned.dispatch(&message, reliability);
            }
            let frame = crate::link::RxBytes::from(batch.clone());
            let read = crate::plain_push::read_plain_puts(&frame).expect("every record is plain");
            assert_eq!(read.len(), puts.len());
            let outcome = DriverLoopOutcome::FramePlainPuts {
                reliable,
                sn: 0,
                priority: crate::qos::Priority::DEFAULT,
                payload: frame,
                puts: read,
            };
            crate::driver_loop::deliver_frame(&outcome, |event| {
                lane.dispatch_iteration_event(event)
            });

            let (want, got) = (
                seen_owned.lock().unwrap().clone(),
                seen_lane.lock().unwrap().clone(),
            );
            assert_eq!(
                want.len(),
                5,
                "the owned path delivers the five that route: {want:?}"
            );
            assert_eq!(got, want, "reliable={reliable}");
        }
    }

    /// Records that repeat the key before them are delivered as the owned path delivers
    /// them: the same sequence of keys and payloads to every subscriber, whatever mix of
    /// literal keys, aliases, aliases with a suffix and undeclared ids the frame holds, with
    /// the subscribers' matches differing (one takes everything, one a single key, one an
    /// alias). A repeated key rests on the record before it having been delivered, so a
    /// dropped record between two equal ones, an alias that changes meaning and a key that
    /// returns after another are all in the frame, and the reader's own flag is checked to
    /// have been set where it should and only there. The build that lends every record compares
    /// the frame lent where it lies, as the test above does.
    #[test]
    fn a_frame_of_repeated_keys_is_delivered_as_the_owned_path_delivers_it() {
        let puts: [(crate::wire_id::ExprId, Option<&str>, &[u8]); 16] = [
            (0, Some("demo/x"), b"1"),
            (0, Some("demo/x"), b"2"),
            (0, Some("demo/x"), b"3"),
            (9, None, b"undeclared"),
            (9, None, b"undeclared again"),
            (0, Some("demo/x"), b"4"),
            (7, None, b"alias"),
            (7, None, b"alias 2"),
            (7, Some("/s"), b"alias with a suffix"),
            (7, Some("/s"), b"alias with a suffix 2"),
            (0, Some("demo/y"), b"y"),
            (0, Some("demo/x"), b"x back"),
            (0, Some("demo/x"), b"x back 2"),
            (0, Some("other/key"), b"matches nobody"),
            (0, Some("other/key"), b"matches nobody 2"),
            (7, None, b"alias last"),
        ];
        let mut batch = Vec::new();
        for (id, suffix, payload) in puts {
            let push = crate::lent_push::put_with_qos(
                id,
                suffix,
                payload,
                crate::sample::QosLevel::DEFAULT,
            )
            .unwrap();
            let mut one = Vec::new();
            push.encode(&mut sce_forge_runtime::codec::VecSink::new(&mut one))
                .unwrap();
            batch.extend_from_slice(&one);
        }
        let patterns = ["demo/**", "demo/x", "demo/alias"];

        let mut owned = SubscriberRegistry::new();
        let mut lane = SubscriberRegistry::new();
        let seen_owned: Vec<_> = patterns
            .iter()
            .map(|pattern| record_samples(&mut owned, pattern))
            .collect();
        let seen_lane: Vec<_> = patterns
            .iter()
            .map(|pattern| record_samples(&mut lane, pattern))
            .collect();
        for registry in [&mut owned, &mut lane] {
            registry.dispatch(
                &NetworkMessage::Declare(Box::new(declare_kexpr_literal(7, "demo/alias"))),
                Reliability::Reliable,
            );
        }
        for message in crate::network_message::parse_frame_payload(&batch).unwrap() {
            owned.dispatch(&message, Reliability::Reliable);
        }
        let frame = crate::link::RxBytes::from(batch.clone());
        let read = crate::plain_push::read_plain_puts(&frame).expect("every record is plain");
        assert_eq!(read.len(), puts.len());
        // Set where the key is the one before it, and only there.
        let repeats: Vec<bool> = read.iter().map(|put| put.repeats_key).collect();
        assert_eq!(
            repeats,
            [
                false, true, true, false, true, false, false, true, false, true, false, false,
                true, false, true, false
            ]
        );
        let outcome = DriverLoopOutcome::FramePlainPuts {
            reliable: true,
            sn: 0,
            priority: crate::qos::Priority::DEFAULT,
            payload: frame,
            puts: read,
        };
        crate::driver_loop::deliver_frame(&outcome, |event| lane.dispatch_iteration_event(event));
        for (index, pattern) in patterns.iter().enumerate() {
            let (want, got) = (
                seen_owned[index].lock().unwrap().clone(),
                seen_lane[index].lock().unwrap().clone(),
            );
            assert!(!want.is_empty(), "{pattern}: the owned path delivers some");
            assert_eq!(got, want, "{pattern}");
        }
        assert_eq!(
            seen_lane[0].lock().unwrap().len(),
            12,
            "demo/** takes the twelve that are under demo/ or the alias, in order"
        );
    }

    #[test]
    fn resolve_inbound_mapping_returns_none_after_undecl_kexpr() {
        // `Declare(UndeclKexpr(id))` removes the entry; the
        // resolver must immediately reflect the retraction
        // (mirrors zenoh-pico's `_z_unregister_resource` flushing
        // `_z_session_t._remote_resources` so subsequent
        // resolutions miss).
        let mut registry = SubscriberRegistry::new();
        registry.dispatch(
            &NetworkMessage::Declare(Box::new(declare_kexpr_literal(7, "home/temp"))),
            Reliability::Reliable,
        );
        assert_eq!(
            registry.resolve_inbound_mapping(7),
            Some("home/temp".to_string()),
        );
        registry.dispatch(
            &NetworkMessage::Declare(Box::new(undeclare_kexpr(7))),
            Reliability::Reliable,
        );
        assert_eq!(
            registry.resolve_inbound_mapping(7),
            None,
            "post-undeclare resolution must return None — the peer \
             retracted the mapping and any further reference is \
             unresolvable until a fresh DeclKexpr arrives"
        );
    }

    #[test]
    fn resolve_inbound_mapping_returns_latest_literal_on_redeclare() {
        // Two `DeclKexpr` records for the same id must overwrite
        // (latest-wins semantics) — mirrors zenoh-pico's
        // `_z_register_resource` accepting an overwrite without
        // raising an error. The resolver must reflect the latest
        // declared literal so an application-visible publish
        // routed under the same id lands on the new literal's
        // subscriber set rather than the stale one.
        let mut registry = SubscriberRegistry::new();
        registry.dispatch(
            &NetworkMessage::Declare(Box::new(declare_kexpr_literal(7, "home/temp"))),
            Reliability::Reliable,
        );
        registry.dispatch(
            &NetworkMessage::Declare(Box::new(declare_kexpr_literal(7, "home/humid"))),
            Reliability::Reliable,
        );
        assert_eq!(
            registry.resolve_inbound_mapping(7),
            Some("home/humid".to_string()),
            "second DeclKexpr(7) must overwrite the first literal"
        );
    }

    // ── R218 absorb_declare explicit-arm coverage ──

    /// R218 — every non-keyexpr `DeclareVariant` arm must be a
    /// no-op against the peer keyexpr alias table. Each arm is
    /// dispatched in isolation against a fresh registry; the
    /// table must remain empty. Failure here means a future
    /// codegen change accidentally routed a non-keyexpr arm
    /// through the keyexpr path, OR the explicit match acquired
    /// an erroneous side-effect on one of the no-op arms.
    #[test]
    fn absorb_declare_non_keyexpr_arms_leave_table_empty() {
        use wz_codecs::lent::{
            DeclFinal, DeclQueryable, DeclSubscriber, DeclToken, DeclareVariant, UndeclQueryable,
            UndeclSubscriber, UndeclToken,
        };

        let arms: Vec<(&str, DeclareVariant)> = vec![
            (
                "DeclSubscriber",
                DeclareVariant::CodecZenohDeclSubscriber(DeclSubscriber::default()),
            ),
            (
                "UndeclSubscriber",
                DeclareVariant::CodecZenohUndeclSubscriber(UndeclSubscriber::default()),
            ),
            (
                "DeclQueryable",
                DeclareVariant::CodecZenohDeclQueryable(DeclQueryable::default()),
            ),
            (
                "UndeclQueryable",
                DeclareVariant::CodecZenohUndeclQueryable(UndeclQueryable::default()),
            ),
            (
                "DeclToken",
                DeclareVariant::CodecZenohDeclToken(DeclToken::default()),
            ),
            (
                "UndeclToken",
                DeclareVariant::CodecZenohUndeclToken(UndeclToken::default()),
            ),
            (
                "DeclFinal",
                DeclareVariant::CodecZenohDeclFinal(DeclFinal::default()),
            ),
            (
                "Default",
                DeclareVariant::Default {
                    // A tag within Declare's five bits that no arm names.
                    tag: wz_codecs::declare::DeclareUnknownTag::new(0x1F)
                        .expect("0x1F is no arm's tag of Declare"),
                    body: DeclFinal::default(),
                },
            ),
        ];

        for (name, body) in arms {
            let mut registry = SubscriberRegistry::new();
            // `absorb_declare` takes the owned variant; deep-copy the
            // borrowed test arm at the boundary.
            let body = body
                .try_into_owned_in::<crate::transport_profile::TransportStorage>()
                .unwrap();
            registry.peer.absorb_declare(&body);
            assert!(
                registry.mapping_spaces().peer().is_empty(),
                "{name} arm must not mutate the peer keyexpr table"
            );
        }
    }

    // ── R227 Self-publish loopback (local_publish) ──

    #[test]
    fn local_publish_fires_any_locality_subscriber() {
        // Locality::Any subscribers fire on both wire-arrived and
        // loopback paths. The loopback path runs through
        // `fire_to_subscribers` with `is_remote = false`, which
        // selects `allows_local()` — true for `Any`.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("home/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let sample = Sample::new_put("home/temp", b"22.5".to_vec());
        let fired = registry.local_publish(&sample);
        assert_eq!(fired, 1, "Any subscriber fires on loopback");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn local_publish_fires_session_local_subscriber() {
        // Locality::SessionLocal is the canonical loopback-only
        // setting: `allows_local()` true, `allows_remote()` false. A
        // SessionLocal subscription was dormant pre-R227; R227
        // activates it through `local_publish`.
        use crate::locality::Locality;
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register_with_locality("home/temp", Locality::SessionLocal, move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let sample = Sample::new_put("home/temp", b"22.5".to_vec());
        let fired = registry.local_publish(&sample);
        assert_eq!(
            fired, 1,
            "Locality::SessionLocal fires on R227 loopback (is_remote=false)"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn local_publish_suppresses_remote_only_subscriber() {
        // Locality::Remote is the wire-only setting: `allows_remote()`
        // true, `allows_local()` false. A Remote subscriber must
        // never see a self-publish loopback Sample — mirrors
        // zenoh-pico's `_z_locality_allows_local(Z_LOCALITY_REMOTE)`
        // returning false.
        use crate::locality::Locality;
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register_with_locality("home/temp", Locality::Remote, move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let sample = Sample::new_put("home/temp", b"22.5".to_vec());
        let fired = registry.local_publish(&sample);
        assert_eq!(
            fired, 0,
            "Locality::Remote suppresses loopback (allows_local() == false)"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    // ── R311y788 — has_local_matching, the SESSION-LOCAL half of a
    // publisher's matching status. Each case pairs the predicate with the
    // delivery it is supposed to predict, so a divergence between "would
    // match" and "would fire" fails the test rather than passing quietly.

    #[test]
    fn has_local_matching_sees_a_session_local_subscriber() {
        use crate::locality::Locality;
        let mut registry = SubscriberRegistry::new();
        registry
            .register_with_locality("home/temp", Locality::SessionLocal, |_s| {})
            .expect("no quota is stated on this table");
        assert!(
            registry.has_local_matching("home/temp"),
            "a SessionLocal subscriber is a local matching target"
        );
        // The prediction agrees with the delivery.
        let sample = Sample::new_put("home/temp", b"1".to_vec());
        assert_eq!(registry.local_publish(&sample), 1);
    }

    #[test]
    fn has_local_matching_ignores_a_remote_only_subscriber() {
        // The DISCRIMINATOR against reading the table alone: the entry is
        // there and intersects, and it still is not a local target, because
        // `local_publish` would not fire it (pico gates the local count on
        // `_z_locality_allows_local(sub->_allowed_origin)`).
        use crate::locality::Locality;
        let mut registry = SubscriberRegistry::new();
        registry
            .register_with_locality("home/temp", Locality::Remote, |_s| {})
            .expect("no quota is stated on this table");
        assert!(
            !registry.has_local_matching("home/temp"),
            "a Remote-only subscriber is not a target for its own session's publisher"
        );
        let sample = Sample::new_put("home/temp", b"1".to_vec());
        assert_eq!(
            registry.local_publish(&sample),
            0,
            "and the delivery agrees"
        );
    }

    #[test]
    fn has_local_matching_is_a_two_pattern_intersection() {
        // Both sides may be wildcards — this is `intersect`, not the
        // one-sided `matches` the dispatch path runs against a literal
        // sample keyexpr. `home/*/temp` and `home/kitchen/**` share
        // `home/kitchen/temp`, so a publisher on the latter matches.
        use crate::locality::Locality;
        let mut registry = SubscriberRegistry::new();
        registry
            .register_with_locality("home/*/temp", Locality::Any, |_s| {})
            .expect("no quota is stated on this table");
        assert!(registry.has_local_matching("home/kitchen/**"));
        assert!(
            !registry.has_local_matching("garden/kitchen/temp"),
            "a disjoint keyexpr does not match"
        );
    }

    #[test]
    fn has_local_matching_is_false_on_an_empty_registry() {
        // Anti-vacuity: the true cases above must be caused by the
        // subscriber, not by a predicate that answers true for anything.
        let registry: SubscriberRegistry<crate::pubsub::BoxedSink> = SubscriberRegistry::new();
        assert!(!registry.has_local_matching("home/temp"));
    }

    #[test]
    fn has_local_matching_follows_the_undeclare() {
        use crate::locality::Locality;
        let mut registry = SubscriberRegistry::new();
        let id = registry
            .register_with_locality("home/temp", Locality::Any, |_s| {})
            .expect("no quota is stated on this table");
        assert!(registry.has_local_matching("home/temp"));
        assert!(registry.unregister(id));
        assert!(
            !registry.has_local_matching("home/temp"),
            "the last local subscriber leaving flips the verdict back"
        );
    }

    #[test]
    fn local_publish_mixed_locality_isolation() {
        // Three subscribers on the same keyexpr, each pinned to a
        // different Locality. Loopback fires Any + SessionLocal,
        // suppresses Remote. Wire-path (dispatch on equivalent Push)
        // fires Any + Remote, suppresses SessionLocal. Same registry,
        // single source of truth for the Locality contract.
        use crate::locality::Locality;
        let mut registry = SubscriberRegistry::new();
        let any_hits = Arc::new(AtomicUsize::new(0));
        let local_hits = Arc::new(AtomicUsize::new(0));
        let remote_hits = Arc::new(AtomicUsize::new(0));
        {
            let any_clone = any_hits.clone();
            registry
                .register_with_locality("home/temp", Locality::Any, move |_sample| {
                    any_clone.fetch_add(1, Ordering::SeqCst);
                })
                .expect("no quota is stated on this table");
        }
        {
            let local_clone = local_hits.clone();
            registry
                .register_with_locality("home/temp", Locality::SessionLocal, move |_sample| {
                    local_clone.fetch_add(1, Ordering::SeqCst);
                })
                .expect("no quota is stated on this table");
        }
        {
            let remote_clone = remote_hits.clone();
            registry
                .register_with_locality("home/temp", Locality::Remote, move |_sample| {
                    remote_clone.fetch_add(1, Ordering::SeqCst);
                })
                .expect("no quota is stated on this table");
        }

        let sample = Sample::new_put("home/temp", b"22.5".to_vec());
        let fired = registry.local_publish(&sample);
        assert_eq!(
            fired, 2,
            "loopback fires Any + SessionLocal, suppresses Remote"
        );
        assert_eq!(any_hits.load(Ordering::SeqCst), 1);
        assert_eq!(local_hits.load(Ordering::SeqCst), 1);
        assert_eq!(remote_hits.load(Ordering::SeqCst), 0);

        // Same registry, wire-arrived Push: fires Any + Remote,
        // suppresses SessionLocal. Both paths converge on
        // `fire_to_subscribers`; the discriminator is `is_remote`.
        let push = push_with_keyexpr("home/temp");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
        assert_eq!(
            any_hits.load(Ordering::SeqCst),
            2,
            "Any subscriber fires on both wire and loopback origins"
        );
        assert_eq!(
            local_hits.load(Ordering::SeqCst),
            1,
            "SessionLocal subscriber stays at 1 after wire-arrived dispatch"
        );
        assert_eq!(
            remote_hits.load(Ordering::SeqCst),
            1,
            "Remote subscriber fires on wire-arrived dispatch only"
        );
    }

    #[test]
    fn local_publish_returns_zero_with_empty_registry() {
        // No subscribers registered → no callbacks fire → count is 0.
        // The empty-registry case must not panic on any internal
        // iteration assumption.
        let mut registry = SubscriberRegistry::new();
        let sample = Sample::new_put("home/temp", b"22.5".to_vec());
        let fired = registry.local_publish(&sample);
        assert_eq!(fired, 0);
    }

    #[test]
    fn local_publish_returns_zero_when_pattern_mismatches() {
        // Subscriber registered on a literal that does not match the
        // Sample's keyexpr — locality predicate passes (Any), but the
        // pattern matcher rejects, so no callback fires.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("kitchen/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let sample = Sample::new_put("home/temp", b"22.5".to_vec());
        let fired = registry.local_publish(&sample);
        assert_eq!(fired, 0);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn local_publish_returns_count_for_multiple_matching_subscribers() {
        // Two subscribers on overlapping literals that both match the
        // Sample's keyexpr. `local_publish` returns the total count of
        // subscriber callbacks that fired (2) so loopback callers can
        // verify multi-listener delivery.
        let mut registry = SubscriberRegistry::new();
        let hits_a = Arc::new(AtomicUsize::new(0));
        let hits_b = Arc::new(AtomicUsize::new(0));
        {
            let clone = hits_a.clone();
            registry
                .register("home/temp", move |_sample| {
                    clone.fetch_add(1, Ordering::SeqCst);
                })
                .expect("no quota is stated on this table");
        }
        {
            let clone = hits_b.clone();
            registry
                .register("home/*", move |_sample| {
                    clone.fetch_add(1, Ordering::SeqCst);
                })
                .expect("no quota is stated on this table");
        }

        let sample = Sample::new_put("home/temp", b"22.5".to_vec());
        let fired = registry.local_publish(&sample);
        assert_eq!(fired, 2, "both matching subscribers fire");
        assert_eq!(hits_a.load(Ordering::SeqCst), 1);
        assert_eq!(hits_b.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn local_publish_matches_double_star_wildcard() {
        // Pattern `home/**` matches `home/kitchen/temp` through the
        // `**` zero-or-more-chunks rule. The matcher is the same
        // `keyexpr_intersects` the wire path uses, so wildcard
        // semantics carry across origins.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("home/**", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let sample = Sample::new_put("home/kitchen/temp", b"22.5".to_vec());
        let fired = registry.local_publish(&sample);
        assert_eq!(fired, 1, "`home/**` matches `home/kitchen/temp`");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn local_publish_matches_intra_chunk_dsl() {
        // R220 intra-chunk `$*` DSL works on loopback too — same
        // matcher engine, just routed with `is_remote = false`.
        // Pattern `home/temp_$*` matches `home/temp_42` because
        // `$*` floats the trailing chunk content.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("home/temp_$*", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let sample = Sample::new_put("home/temp_42", b"22.5".to_vec());
        let fired = registry.local_publish(&sample);
        assert_eq!(fired, 1);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn local_publish_propagates_sample_fields_to_callback() {
        // The Sample handed to `local_publish` reaches the callback
        // unmodified — keyexpr / kind / payload / reliability /
        // qos / attachment / timestamp / encoding / source_info
        // are all caller-owned. R227 does not synthesize any field.
        use crate::sample::{QosLevel, Reliability as Rel};
        let mut registry = SubscriberRegistry::new();
        let observed = Arc::new(std::sync::Mutex::new(None::<Sample>));
        let observed_clone = observed.clone();
        registry
            .register("home/temp", move |sample| {
                *observed_clone.lock().unwrap() = Some(Sample::from_view(sample));
            })
            .expect("no quota is stated on this table");

        let sample = Sample::new_put("home/temp", b"payload".to_vec())
            .with_reliability(Rel::BestEffort)
            .with_qos(QosLevel::from_raw(0x12))
            .with_attachment(b"attach".to_vec());
        let fired = registry.local_publish(&sample);
        assert_eq!(fired, 1);

        let got = observed
            .lock()
            .unwrap()
            .clone()
            .expect("callback fired and stored the Sample");
        assert_eq!(got.keyexpr, "home/temp");
        assert_eq!(got.kind, SampleKind::Put);
        assert_eq!(got.payload, b"payload");
        assert_eq!(got.reliability, Rel::BestEffort);
        assert_eq!(got.qos, Some(QosLevel::from_raw(0x12)));
        assert_eq!(got.attachment.as_deref(), Some(b"attach".as_slice()));
    }

    #[test]
    fn local_publish_del_kind_routes_to_subscriber() {
        // Sample::new_del routes through the same `fire_to_subscribers`
        // branch as Put; the kind discriminator is opaque to the
        // dispatcher. The subscriber observes SampleKind::Del with an
        // empty payload.
        let mut registry = SubscriberRegistry::new();
        let observed = Arc::new(std::sync::Mutex::new(None::<SampleKind>));
        let observed_clone = observed.clone();
        registry
            .register("home/temp", move |sample| {
                *observed_clone.lock().unwrap() = Some(sample.kind());
                assert!(sample.payload().is_empty(), "Del Sample carries no payload");
            })
            .expect("no quota is stated on this table");

        let sample = Sample::new_del("home/temp");
        let fired = registry.local_publish(&sample);
        assert_eq!(fired, 1);
        assert_eq!(*observed.lock().unwrap(), Some(SampleKind::Del));
    }

    #[test]
    fn local_publish_passes_only_locality_predicate_not_keyexpr() {
        // Regression guard for the ordering bug class: even when the
        // pattern matches, a subscriber whose locality predicate
        // rejects the loopback origin must not fire. The locality
        // check runs before the pattern match in
        // `fire_to_subscribers`; this test pins that ordering.
        use crate::locality::Locality;
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register_with_locality("home/**", Locality::Remote, move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        let sample = Sample::new_put("home/kitchen/temp", b"22.5".to_vec());
        let fired = registry.local_publish(&sample);
        assert_eq!(
            fired, 0,
            "Locality::Remote suppresses loopback even when the wildcard pattern matches"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    // ─── R231: self-echo dedup ─────────────────────────────────────

    /// Build a literal-keyexpr Push (id=0, suffix=keyexpr) carrying a
    /// MsgPut body whose extension chain contains a source_info entry
    /// with the supplied zid prefix (1..=16 bytes), eid=0, sn=0. The
    /// wire-form source_info payload mirrors
    /// `session_glue::encode_source_info_ext_body`: header byte
    /// `(zidlen-1) << 4`, raw zid bytes, then VLE eid + sn.
    fn push_put_literal_with_source_info(keyexpr: &str, source_zid: &[u8]) -> PushOwned {
        assert!(
            (1..=16).contains(&source_zid.len()),
            "test helper: source_zid len must be 1..=16"
        );
        let mut ext = wz_codecs::lent::ExtEntry::new();
        ext.set_ext_id(0x01); // source_info ext_id
        ext.set_enc(0x02); // ENC_ZBUF
        let mut payload = vec![((source_zid.len() as u8) - 1) << 4];
        payload.extend_from_slice(source_zid);
        payload.push(0); // VLE eid = 0
        payload.push(0); // VLE sn = 0
        ext.body = wz_codecs::lent::ExtEntryVariant::CodecZenohExtZbuf(wz_codecs::lent::ExtZbuf {
            value_len: payload.len() as u64,
            value: sce_forge_runtime::codec::Bounded::new(&payload[..]).unwrap(),
        });
        // The owned `MsgPut` holds its chain in the profile's list; deep-copy the
        // borrowed ext in.
        let mut put: crate::wire::parts::MsgPutOwned = crate::put_payload::inline(b"").unwrap();
        crate::put_payload::set_chain(
            &mut put,
            [ext.try_into_owned_in::<crate::wire::WireStorage>().unwrap()],
        )
        .unwrap();
        let mut push = Push {
            keyexpr: wz_codecs::lent::Wireexpr {
                body: WireexprVariant::WireexprLocal(wz_codecs::lent::WireexprLocal {
                    id: 0,
                    suffix_len: Some(keyexpr.len() as u64),
                    suffix: Some(sce_forge_runtime::codec::Bounded::new(keyexpr).unwrap()),
                }),
            },
            ..Push::default()
        }
        .try_into_owned_in::<crate::wire::WireStorage>()
        .unwrap();
        push.body = PushOwnedVariant::CodecZenohMsgPut(put);
        push
    }

    // Requires pubsub-source-info: the suppression assertion only holds
    // when the subscriber decodes the wire source_info to recognise the
    // self-echo. With the feature off the dispatch cautious-fires (see
    // dispatch_push_fires_when_source_zid_differs_from_own, which holds
    // in both configurations).
    #[cfg(feature = "pubsub-source-info")]
    #[test]
    fn dispatch_push_suppresses_self_echo_when_zid_matches() {
        // Self-publish via Locality::Any fires the loopback path; the
        // mesh / router then echoes the wire form back to us with the
        // same source_info.zid we just sent. Without dedup the
        // Any-locality subscriber would fire twice. With own_zid
        // installed the wire-arrival path matches and suppresses.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("demo/temp", move |_s| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");
        let own = vec![0x01, 0x02, 0x03, 0x04];
        assert!(registry.set_own_zid(own.clone()));

        let push = push_put_literal_with_source_info("demo/temp", &own);
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);

        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "wire-arrived self-echo (source_info.zid == own_zid) must not fire local subscribers"
        );
    }

    /// transport-shm — an SHM Put whose descriptor cannot be resolved (here: no
    /// resolver installed) delivers nothing AND increments the observable drop
    /// counter, so a missing-`set_shm_resolver` misconfiguration is a readable
    /// number rather than silently vanishing samples (R311xr review remediation).
    #[cfg(all(feature = "transport-shm", feature = "codec-push"))]
    #[test]
    fn shm_put_with_no_resolver_drops_observably() {
        let mut registry = SubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        registry
            .register("demo/shm", move |_s| {
                f.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");
        // R311y516 — negotiate FIRST so this test still measures what it is
        // named for. The negotiation gate added in R311y516 runs BEFORE the
        // resolve and would otherwise absorb this Put into
        // `shm_unnegotiated_drops`, leaving the missing-resolver precondition
        // untested behind a green assertion.
        registry.set_shm_negotiated(true);
        // No resolver installed -> the descriptor is unresolvable.
        let descriptor = crate::extshm::ShmDescriptor {
            data_len: 4,
            metadata_id: 0x12,
            metadata_index: 0x34,
            generation: 0,
        };
        let push = crate::push_build::build_push_shm_literal(
            "demo/shm",
            &descriptor,
            &crate::metadata::PushMetadata::default(),
        )
        .expect("build the SHM Put");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);

        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "an unresolvable SHM Put delivers nothing"
        );
        assert_eq!(
            registry.shm_unresolved_drops(),
            1,
            "but the drop is COUNTED, so the missing-resolver misconfiguration is observable"
        );
    }

    // R3042 -- the doubles the acknowledgement tests read through live in
    // `extshm::test_support`, shared with the reply registry's tests.
    #[cfg(all(feature = "transport-shm", feature = "pubsub-put"))]
    use crate::extshm::test_support::{AlwaysResolves, CountingResolver, RecordingHandoff};

    /// A negotiated registry with a recording handoff, a subscriber, and the
    /// recorded bands to read.
    #[cfg(all(feature = "transport-shm", feature = "pubsub-put"))]
    fn handoff_registry() -> (
        SubscriberRegistry<BoxedSink>,
        Arc<std::sync::Mutex<Vec<usize>>>,
        Arc<AtomicUsize>,
    ) {
        let mut registry = SubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        registry
            .register("demo/shm", move |_s| {
                f.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");
        registry.set_shm_negotiated(true);
        let bands = Arc::new(std::sync::Mutex::new(Vec::new()));
        registry.set_shm_handoff(Some(Box::new(RecordingHandoff(bands.clone()))));
        (registry, bands, fired)
    }

    /// A shared-memory Put for `demo/shm`, at the QoS byte `qos` (`None` for a
    /// message that carries none).
    #[cfg(all(feature = "transport-shm", feature = "pubsub-put"))]
    fn shm_push(qos: Option<u8>) -> PushOwned {
        let descriptor = crate::extshm::ShmDescriptor {
            data_len: 7,
            metadata_id: 0x12,
            metadata_index: 0x34,
            generation: 0,
        };
        let mut push = crate::push_build::build_push_shm_literal(
            "demo/shm",
            &descriptor,
            &crate::metadata::PushMetadata::default(),
        )
        .expect("build the SHM Put");
        // The QoS extension is put on by hand, as `push_put_with_qos` does, and not
        // through the builder: the builder writes it only under `pubsub-qos`, while
        // the band an acknowledgement is owed at is read from the wire whether or
        // not that feature is compiled in. This fixture is the receive side alone.
        if let Some(raw) = qos {
            let mut ext = wz_codecs::lent::ExtEntry::new();
            ext.set_ext_id(0x01); // QOS_EXT_ID
            ext.set_enc(0x01); // ENC_ZINT
            ext.body =
                wz_codecs::lent::ExtEntryVariant::CodecZenohExtZint(wz_codecs::ext_zint::ExtZint {
                    value: u64::from(raw),
                });
            push.extensions = Some(crate::held_list::one_entry(
                ext.try_into_owned_in::<crate::wire::WireStorage>().unwrap(),
            ));
            push.header |= 0x80;
        }
        push
    }

    /// R3040 -- THE ACKNOWLEDGEMENT: each shared-memory slice received is told to
    /// the handoff once, at the priority the message was sent at. A message at
    /// priority 2 acknowledges band 2, and one with no QoS extension acknowledges
    /// the default band 5, which is the counter index a zenoh sender at its default
    /// priority names (MEASURED: its counter at index 5 climbed with every put).
    #[cfg(all(feature = "transport-shm", feature = "pubsub-put"))]
    #[test]
    fn a_shm_slice_is_acknowledged_once_at_its_messages_priority() {
        let (mut registry, bands, fired) = handoff_registry();
        registry.set_shm_resolver(Box::new(AlwaysResolves));

        registry.dispatch(
            &NetworkMessage::Push(Box::new(shm_push(Some(0x02)))),
            Reliability::Reliable,
        );
        assert_eq!(*bands.lock().expect("bands"), [2], "priority 2");
        registry.dispatch(
            &NetworkMessage::Push(Box::new(shm_push(None))),
            Reliability::Reliable,
        );
        assert_eq!(
            *bands.lock().expect("bands"),
            [2, 5],
            "no QoS extension reads as the default priority"
        );
        assert_eq!(fired.load(Ordering::SeqCst), 2, "and both were delivered");
    }

    /// R3040 -- a slice that does NOT resolve is acknowledged all the same, as
    /// upstream calls `handoff.on_rx` before it looks at the result: the sender
    /// counted that slice sent, and an acknowledgement withheld because the read
    /// failed would pin a buffer nobody can read for the life of the transport.
    #[cfg(all(feature = "transport-shm", feature = "pubsub-put"))]
    #[test]
    fn an_unresolvable_shm_slice_is_acknowledged_all_the_same() {
        let (mut registry, bands, fired) = handoff_registry();
        // No resolver installed: the descriptor cannot be resolved.
        registry.dispatch(
            &NetworkMessage::Push(Box::new(shm_push(None))),
            Reliability::Reliable,
        );
        assert_eq!(fired.load(Ordering::SeqCst), 0, "nothing was delivered");
        assert_eq!(registry.shm_unresolved_drops(), 1);
        assert_eq!(
            *bands.lock().expect("bands"),
            [5],
            "but the sender is still told the slice arrived"
        );
    }

    /// R3040 -- a Put with no shared-memory slice acknowledges nothing: the
    /// sender counts only the slices it sent as shared memory, so an inline
    /// message acknowledged would lower a counter that was never raised.
    #[cfg(all(feature = "transport-shm", feature = "pubsub-put"))]
    #[test]
    fn an_inline_put_acknowledges_nothing() {
        let (mut registry, bands, fired) = handoff_registry();
        let push = push_put_with_qos("demo/shm", 0x00);
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
        assert_eq!(fired.load(Ordering::SeqCst), 1, "the inline Put delivers");
        assert!(bands.lock().expect("bands").is_empty());
    }

    /// R3049 -- A PUT WHOSE PAYLOAD IS ONE SHARED-MEMORY BUFFER IS DELIVERED AS THE
    /// BUFFER THE RESOLVER RETURNED. The address is the witness: the subscriber is
    /// handed bytes that start where the resolver's storage starts, which a copy
    /// cannot be made to do, where comparing the bytes with the ones sent passes a
    /// copy too.
    #[cfg(all(
        feature = "transport-shm",
        feature = "pubsub-put",
        feature = "rx-shared-bytes"
    ))]
    #[test]
    fn a_put_of_one_shm_buffer_is_delivered_as_the_storage_the_resolver_lent() {
        let storage = Arc::new(b"seven b".to_vec());
        let delivered = Arc::new(AtomicUsize::new(0));
        let mut registry = SubscriberRegistry::<BoxedSink>::new();
        let seen = delivered.clone();
        registry
            .register("demo/shm", move |sample| {
                seen.store(sample.payload().as_ptr() as usize, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");
        registry.set_shm_negotiated(true);
        registry.set_shm_resolver(Box::new(crate::extshm::test_support::LendsStorage(
            storage.clone(),
        )));

        registry.dispatch(
            &NetworkMessage::Push(Box::new(shm_push(None))),
            Reliability::Reliable,
        );

        assert_eq!(
            delivered.load(Ordering::SeqCst),
            storage.as_ptr() as usize,
            "the sample's bytes are the storage the resolver lent and not a copy of it"
        );
    }

    /// A shared-memory Put for `demo/shm` whose payload is TWO shared-memory buffers.
    ///
    /// Gated on its one caller's features and not wider: a build with shared memory and no
    /// shared bytes would carry it as dead code, which `-D warnings` rejects.
    #[cfg(all(
        feature = "transport-shm",
        feature = "pubsub-put",
        feature = "rx-shared-bytes"
    ))]
    fn shm_push_of_two_buffers() -> PushOwned {
        use sce_forge_runtime::codec::SceList;

        let mut push = shm_push(None);
        let second = crate::extshm::ShmDescriptor {
            data_len: 5,
            metadata_id: 0x13,
            metadata_index: 0x35,
            generation: 0,
        };
        let second = crate::put_payload::shm_slices::<crate::wire::WireStorage, _, _>(
            &crate::extshm::encode_shm_descriptor(&second),
        )
        .expect("one slice for the second buffer");
        let crate::wire::PushOwnedVariant::CodecZenohMsgPut(put) = &mut push.body else {
            panic!("a Put");
        };
        let wz_codecs::msg_put::MsgPutExtensionsHas0x12::Has0x12 { slices, .. } =
            &mut put.extensions_has_0x12
        else {
            panic!("the sliced layout");
        };
        // The first buffer's slices, then the second's, in the list the field holds.
        let first = core::mem::replace(slices, second);
        let mut list = first.into_inner();
        for slice in SceList::as_slice(slices.inner()) {
            list.try_push(slice.clone()).expect("a second slice fits");
        }
        *slices = sce_forge_runtime::codec::Bounded::new(list).expect("two slices are in bound");
        put.slice_count = Some(2);
        push
    }

    /// R3124 -- A PUT OF TWO SHARED-MEMORY BUFFERS IS DELIVERED AS THE TWO BUFFERS. The addresses
    /// are the witness, as for one buffer: the subscriber is handed a payload whose slices start
    /// where the two storages the resolver lent start, in the order the Put named them, which a
    /// join of the two cannot be made to do. Read as one run the payload is the two joined.
    #[cfg(all(
        feature = "transport-shm",
        feature = "pubsub-put",
        feature = "rx-shared-bytes"
    ))]
    #[test]
    fn a_put_of_two_shm_buffers_is_delivered_as_the_two_storages_the_resolver_lent() {
        let first = Arc::new(b"seven b".to_vec());
        let second = Arc::new(b"five!".to_vec());
        let seen: Arc<std::sync::Mutex<Vec<(usize, usize)>>> = Arc::default();
        let joined: Arc<std::sync::Mutex<Vec<u8>>> = Arc::default();
        let mut registry = SubscriberRegistry::<BoxedSink>::new();
        let (slices_seen, joined_seen) = (seen.clone(), joined.clone());
        registry
            .register("demo/shm", move |sample| {
                let payload = sample.payload_shared().expect("a shared payload");
                *slices_seen.lock().expect("seen") = payload
                    .slices()
                    .map(|slice| (slice.as_ptr() as usize, slice.len()))
                    .collect();
                *joined_seen.lock().expect("joined") = sample.payload().to_vec();
            })
            .expect("no quota is stated on this table");
        registry.set_shm_negotiated(true);
        registry.set_shm_resolver(Box::new(crate::extshm::test_support::LendsEach(
            std::sync::Mutex::new([first.clone(), second.clone()].into()),
        )));

        registry.dispatch(
            &NetworkMessage::Push(Box::new(shm_push_of_two_buffers())),
            Reliability::Reliable,
        );

        assert_eq!(
            *seen.lock().expect("seen"),
            [
                (first.as_ptr() as usize, first.len()),
                (second.as_ptr() as usize, second.len())
            ],
            "two slices, each the storage the resolver lent for its descriptor, in order"
        );
        assert_eq!(
            *joined.lock().expect("joined"),
            b"seven bfive!",
            "and read as one run, the two joined"
        );
    }

    /// R3040 -- a session that never negotiated shared memory acknowledges
    /// nothing: the Put is refused before any slice is read, so no counter of a
    /// peer this node has no agreement with is written.
    #[cfg(all(feature = "transport-shm", feature = "pubsub-put"))]
    #[test]
    fn an_unnegotiated_session_acknowledges_nothing() {
        let (mut registry, bands, _fired) = handoff_registry();
        registry.set_shm_negotiated(false);
        registry.dispatch(
            &NetworkMessage::Push(Box::new(shm_push(None))),
            Reliability::Reliable,
        );
        assert_eq!(registry.shm_unnegotiated_drops(), 1);
        assert!(bands.lock().expect("bands").is_empty());
    }

    /// The same shared-memory Put, addressed to an id the peer never declared, so
    /// routing refuses it.
    #[cfg(all(feature = "transport-shm", feature = "pubsub-put"))]
    fn unroutable(mut push: PushOwned) -> PushOwned {
        push.keyexpr = push_with_mapping_id(9, None).keyexpr;
        push
    }

    /// R3041 -- A PUT THAT ROUTING REFUSES HAS STILL ARRIVED. Its slice is read,
    /// which gives back the reference its sender took for this receiver, and
    /// acknowledged, though nothing is delivered: upstream un-swaps a message
    /// before it routes it, so a refused message is dropped with its buffers
    /// already released. Before this, the keyexpr was resolved first and the
    /// return skipped both, and the sender pinned the buffer, confirmed, until the
    /// transport ended. The twin is the same message to a declared key, which pays
    /// the same and also delivers, so the counter is read to count and not to be
    /// always zero.
    #[cfg(all(feature = "transport-shm", feature = "pubsub-put"))]
    #[test]
    fn an_unroutable_shm_put_is_still_released_and_acknowledged() {
        let (mut registry, bands, fired) = handoff_registry();
        let resolved = Arc::new(AtomicUsize::new(0));
        registry.set_shm_resolver(Box::new(CountingResolver(resolved.clone())));

        registry.dispatch(
            &NetworkMessage::Push(Box::new(unroutable(shm_push(Some(0x02))))),
            Reliability::Reliable,
        );
        assert_eq!(fired.load(Ordering::SeqCst), 0, "routing refused it");
        assert_eq!(
            resolved.load(Ordering::SeqCst),
            1,
            "yet its slice was read, which releases the sender's reference"
        );
        assert_eq!(
            *bands.lock().expect("bands"),
            [2],
            "and acknowledged at the message's own priority"
        );

        registry.dispatch(
            &NetworkMessage::Push(Box::new(shm_push(Some(0x02)))),
            Reliability::Reliable,
        );
        assert_eq!(fired.load(Ordering::SeqCst), 1, "the twin is delivered");
        assert_eq!(resolved.load(Ordering::SeqCst), 2, "and read once");
        assert_eq!(
            *bands.lock().expect("bands"),
            [2, 2],
            "and acknowledged once"
        );
    }

    /// R3041 -- the settlement is for SLICES: an inline Put routing refuses
    /// touches no resolver and no counter, so a flood to an undeclared id costs
    /// what it cost before and lowers nothing it never raised.
    #[cfg(all(feature = "transport-shm", feature = "pubsub-put"))]
    #[test]
    fn an_unroutable_inline_put_settles_nothing() {
        let (mut registry, bands, fired) = handoff_registry();
        let resolved = Arc::new(AtomicUsize::new(0));
        registry.set_shm_resolver(Box::new(CountingResolver(resolved.clone())));

        registry.dispatch(
            &NetworkMessage::Push(Box::new(unroutable(push_put_with_qos("demo/shm", 0x00)))),
            Reliability::Reliable,
        );
        assert_eq!(fired.load(Ordering::SeqCst), 0);
        assert_eq!(resolved.load(Ordering::SeqCst), 0, "no slice, nothing read");
        assert!(
            bands.lock().expect("bands").is_empty(),
            "nothing acknowledged"
        );
        assert_eq!(registry.shm_unresolved_drops(), 0);
        assert_eq!(registry.shm_unnegotiated_drops(), 0);
    }

    /// R3041 -- a session that never negotiated shared memory refuses a sliced Put
    /// the same way whether or not its key routes: counted, nothing read, nothing
    /// acknowledged. The count was silent when the key was refused first.
    #[cfg(all(feature = "transport-shm", feature = "pubsub-put"))]
    #[test]
    fn an_unroutable_put_of_an_unnegotiated_session_is_counted_and_not_read() {
        let (mut registry, bands, _fired) = handoff_registry();
        let resolved = Arc::new(AtomicUsize::new(0));
        registry.set_shm_resolver(Box::new(CountingResolver(resolved.clone())));
        registry.set_shm_negotiated(false);

        registry.dispatch(
            &NetworkMessage::Push(Box::new(unroutable(shm_push(None)))),
            Reliability::Reliable,
        );
        assert_eq!(registry.shm_unnegotiated_drops(), 1);
        assert_eq!(resolved.load(Ordering::SeqCst), 0, "no segment was opened");
        assert!(bands.lock().expect("bands").is_empty());
    }

    /// R3040 -- a registry with no handoff (the peer named no counters, as a
    /// zenoh sender does on a best-effort link) delivers exactly as before and
    /// acknowledges nothing, and the handoff can be withdrawn.
    #[cfg(all(feature = "transport-shm", feature = "pubsub-put"))]
    #[test]
    fn a_registry_without_a_handoff_still_delivers_and_a_handoff_can_be_withdrawn() {
        let (mut registry, bands, fired) = handoff_registry();
        registry.set_shm_resolver(Box::new(AlwaysResolves));
        assert!(registry.has_shm_handoff());
        registry.set_shm_handoff(None);
        assert!(!registry.has_shm_handoff());

        registry.dispatch(
            &NetworkMessage::Push(Box::new(shm_push(None))),
            Reliability::Reliable,
        );
        assert_eq!(fired.load(Ordering::SeqCst), 1);
        assert!(
            bands.lock().expect("bands").is_empty(),
            "a withdrawn handoff is not written to"
        );
    }

    #[test]
    fn dispatch_push_fires_when_source_zid_differs_from_own() {
        // Genuine remote-origin sample (peer's zid differs from
        // ours). Dedup must not engage; the subscriber must fire.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("demo/temp", move |_s| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");
        assert!(registry.set_own_zid(vec![0x01, 0x02, 0x03, 0x04]));

        let push = push_put_literal_with_source_info("demo/temp", &[0xAA, 0xBB, 0xCC, 0xDD]);
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "remote-origin sample (source zid differs from own) must fire the subscriber"
        );
    }

    #[test]
    fn dispatch_push_fires_when_source_info_absent() {
        // No source_info on the wire → dedup cannot decide → cautious
        // default is to fire. Suppressing a metadata-stripped sample
        // would silently swallow legitimate publishes from older /
        // simpler peers that never attach source_info.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("demo/temp", move |_s| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");
        assert!(registry.set_own_zid(vec![0x01, 0x02, 0x03, 0x04]));

        // push_with_mapping_id builds a Push::default() body which
        // has no MsgPut extensions and therefore no source_info.
        // To reach dispatch_push's PushVariant arm with no source_info
        // we hand in a MsgPut with `extensions = None`.
        let push =
            Push {
                keyexpr: wz_codecs::lent::Wireexpr {
                    body: WireexprVariant::WireexprLocal(wz_codecs::lent::WireexprLocal {
                        id: 0,
                        suffix_len: Some("demo/temp".len() as u64),
                        suffix: Some(sce_forge_runtime::codec::Bounded::new("demo/temp").unwrap()),
                    }),
                },
                body: wz_codecs::lent::PushVariant::CodecZenohMsgPut(
                    wz_codecs::lent::MsgPut::default(),
                ),
                ..Push::default()
            }
            .try_into_owned_in::<crate::wire::WireStorage>()
            .unwrap();
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "absent source_info means cautious default fires the subscriber"
        );
    }

    // ─── receive-side metadata field-projection isolation ────────────
    //
    // dispatch_push's Put arm projects the wire-carried `encoding` /
    // `source_info` into the `Sample` only when the consumer feature is
    // ON; with it OFF the per-arm populator yields `None` (the
    // `#[cfg(not(feature = "pubsub-encoding"))]` / `..-source-info`
    // branches above). The wire bytes still carry the field — the codec
    // `MsgPut.encoding` field and the source_info ext are ungated
    // (struct stability) — so an un-gating regression (projecting
    // unconditionally) would leak the field into the Sample on a build
    // that never opted in, and no behavioural test would catch it (Layer
    // F only proves the OFF feature shrinks the binary). These symmetric
    // POS/NEG pairs pin both directions: with the feature ON the wire
    // field projects (Some); with it OFF the SAME wire projects None
    // while the subscriber still fires — only the metadata field is
    // dropped, not the whole dispatch (distinguishing a gated field from
    // a dropped message). The C1d pubsub lane runs both arms: its first
    // invocation omits pubsub-encoding / pubsub-source-info (NEG arm),
    // its second enables them (POS arm).

    /// A literal-keyexpr Put (id=0, suffix=keyexpr) carrying a wire
    /// `encoding` (packed_id, no schema). The codec `MsgPut.encoding`
    /// field is ungated, so this is constructible regardless of
    /// `pubsub-encoding` — that feature gates only the subscriber-side
    /// projection.
    fn push_put_with_encoding(keyexpr: &str, packed_id: u32) -> PushOwned {
        let put = wz_codecs::lent::MsgPut {
            encoding: Some(wz_codecs::lent::Encoding {
                packed_id,
                schema_len: None,
                schema: None,
            }),
            ..wz_codecs::lent::MsgPut::default()
        }
        .try_into_owned_in::<crate::wire::WireStorage>()
        .unwrap();
        let mut push = Push {
            keyexpr: wz_codecs::lent::Wireexpr {
                body: WireexprVariant::WireexprLocal(wz_codecs::lent::WireexprLocal {
                    id: 0,
                    suffix_len: Some(keyexpr.len() as u64),
                    suffix: Some(sce_forge_runtime::codec::Bounded::new(keyexpr).unwrap()),
                }),
            },
            ..Push::default()
        }
        .try_into_owned_in::<crate::wire::WireStorage>()
        .unwrap();
        push.body = PushOwnedVariant::CodecZenohMsgPut(put);
        push
    }

    #[cfg(feature = "pubsub-encoding")]
    #[test]
    fn inbound_put_encoding_is_projected_when_pubsub_encoding_on() {
        let mut registry = SubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let present = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        let p = present.clone();
        registry
            .register("home/temp", move |sample| {
                f.fetch_add(1, Ordering::SeqCst);
                if sample.encoding().is_some() {
                    p.fetch_add(1, Ordering::SeqCst);
                }
            })
            .expect("no quota is stated on this table");
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_put_with_encoding("home/temp", 4))),
            Reliability::Reliable,
        );
        assert_eq!(fired.load(Ordering::SeqCst), 1, "subscriber fires");
        assert_eq!(
            present.load(Ordering::SeqCst),
            1,
            "wire encoding projects to Sample.encoding when pubsub-encoding is on"
        );
    }

    #[cfg(not(feature = "pubsub-encoding"))]
    #[test]
    fn inbound_put_encoding_is_dropped_when_pubsub_encoding_off() {
        let mut registry = SubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let present = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        let p = present.clone();
        registry
            .register("home/temp", move |sample| {
                f.fetch_add(1, Ordering::SeqCst);
                if sample.encoding().is_some() {
                    p.fetch_add(1, Ordering::SeqCst);
                }
            })
            .expect("no quota is stated on this table");
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_put_with_encoding("home/temp", 4))),
            Reliability::Reliable,
        );
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "subscriber still fires — only the metadata field is dropped"
        );
        assert_eq!(
            present.load(Ordering::SeqCst),
            0,
            "wire encoding must NOT project to Sample.encoding when pubsub-encoding is off"
        );
    }

    #[cfg(feature = "pubsub-source-info")]
    #[test]
    fn inbound_put_source_info_is_projected_when_pubsub_source_info_on() {
        // No own_zid installed → dedup cannot engage → the sample fires
        // and carries the projected source_info.
        let mut registry = SubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let present = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        let p = present.clone();
        registry
            .register("demo/temp", move |sample| {
                f.fetch_add(1, Ordering::SeqCst);
                if sample.source_info().is_some() {
                    p.fetch_add(1, Ordering::SeqCst);
                }
            })
            .expect("no quota is stated on this table");
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_put_literal_with_source_info(
                "demo/temp",
                &[0xAA, 0xBB, 0xCC, 0xDD],
            ))),
            Reliability::Reliable,
        );
        assert_eq!(fired.load(Ordering::SeqCst), 1, "subscriber fires");
        assert_eq!(
            present.load(Ordering::SeqCst),
            1,
            "wire source_info projects to Sample.source_info when pubsub-source-info is on"
        );
    }

    #[cfg(not(feature = "pubsub-source-info"))]
    #[test]
    fn inbound_put_source_info_is_dropped_when_pubsub_source_info_off() {
        let mut registry = SubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let present = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        let p = present.clone();
        registry
            .register("demo/temp", move |sample| {
                f.fetch_add(1, Ordering::SeqCst);
                if sample.source_info().is_some() {
                    p.fetch_add(1, Ordering::SeqCst);
                }
            })
            .expect("no quota is stated on this table");
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_put_literal_with_source_info(
                "demo/temp",
                &[0xAA, 0xBB, 0xCC, 0xDD],
            ))),
            Reliability::Reliable,
        );
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "subscriber still fires — only the metadata field is dropped"
        );
        assert_eq!(
            present.load(Ordering::SeqCst),
            0,
            "wire source_info must NOT project to Sample.source_info when pubsub-source-info is off"
        );
    }

    /// A literal-keyexpr Put carrying an OUTER QoS ext (ext_id 0x01,
    /// ENC_ZINT, packed byte = `raw`). The outer ext lives on
    /// `Push.extensions`; the codec carries it ungated, so this is
    /// constructible regardless of the QoS-byte consumer features — they
    /// gate only the subscriber-side projection (`extract_qos`).
    fn push_put_with_qos(keyexpr: &str, raw: u8) -> PushOwned {
        let mut ext = wz_codecs::lent::ExtEntry::new();
        ext.set_ext_id(0x01); // QOS_EXT_ID
        ext.set_enc(0x01); // ENC_ZINT
        ext.body =
            wz_codecs::lent::ExtEntryVariant::CodecZenohExtZint(wz_codecs::ext_zint::ExtZint {
                value: u64::from(raw),
            });
        let mut push =
            Push {
                keyexpr: wz_codecs::lent::Wireexpr {
                    body: WireexprVariant::WireexprLocal(wz_codecs::lent::WireexprLocal {
                        id: 0,
                        suffix_len: Some(keyexpr.len() as u64),
                        suffix: Some(sce_forge_runtime::codec::Bounded::new(keyexpr).unwrap()),
                    }),
                },
                body: wz_codecs::lent::PushVariant::CodecZenohMsgPut(
                    wz_codecs::lent::MsgPut::default(),
                ),
                ..Push::default()
            }
            .try_into_owned_in::<crate::wire::WireStorage>()
            .unwrap();
        push.extensions = Some(crate::held_list::one_entry(
            ext.try_into_owned_in::<crate::wire::WireStorage>().unwrap(),
        ));
        push
    }

    #[cfg(feature = "pubsub-qos")]
    #[test]
    fn inbound_put_qos_is_projected_when_a_qos_consumer_on() {
        let mut registry = SubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let present = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        let p = present.clone();
        registry
            .register("home/temp", move |sample| {
                f.fetch_add(1, Ordering::SeqCst);
                if sample.qos().is_some() {
                    p.fetch_add(1, Ordering::SeqCst);
                }
            })
            .expect("no quota is stated on this table");
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_put_with_qos("home/temp", 0xBE))),
            Reliability::Reliable,
        );
        assert_eq!(fired.load(Ordering::SeqCst), 1, "subscriber fires");
        assert_eq!(
            present.load(Ordering::SeqCst),
            1,
            "wire QoS projects to Sample.qos when a QoS-byte consumer is on"
        );
    }

    #[cfg(not(feature = "pubsub-qos"))]
    #[test]
    fn inbound_put_qos_is_dropped_when_all_qos_consumers_off() {
        let mut registry = SubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let present = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        let p = present.clone();
        registry
            .register("home/temp", move |sample| {
                f.fetch_add(1, Ordering::SeqCst);
                if sample.qos().is_some() {
                    p.fetch_add(1, Ordering::SeqCst);
                }
            })
            .expect("no quota is stated on this table");
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_put_with_qos("home/temp", 0xBE))),
            Reliability::Reliable,
        );
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "subscriber still fires — only the metadata field is dropped"
        );
        assert_eq!(
            present.load(Ordering::SeqCst),
            0,
            "wire QoS must NOT project to Sample.qos when all QoS-byte consumers are off"
        );
    }

    // timestamp / attachment POS arm — the wire-decode projection ON
    // contrast for the NEG arm in `metadata_decode_isolation_tests` (which
    // can only build with pubsub-timestamp / pubsub-attachment OFF). The
    // module gate forces both features ON here, so these run in C1d /
    // default; together with the NEG module they complete the wire-decode
    // POS/NEG matrix for every pubsub metadata field.

    /// A Put carrying a wire `timestamp` (time + 4-byte zid).
    fn push_put_with_timestamp(keyexpr: &str) -> PushOwned {
        let zid = [0x09u8, 0x0A, 0x0B, 0x0C];
        let put = wz_codecs::lent::MsgPut {
            timestamp: Some(wz_codecs::lent::Timestamp {
                time: 0x1122_3344_5566_7788,
                zid_len: zid.len() as u64,
                zid: sce_forge_runtime::codec::Bounded::new(&zid[..]).unwrap(),
            }),
            ..wz_codecs::lent::MsgPut::default()
        }
        .try_into_owned_in::<crate::wire::WireStorage>()
        .unwrap();
        let mut push = Push {
            keyexpr: wz_codecs::lent::Wireexpr {
                body: WireexprVariant::WireexprLocal(wz_codecs::lent::WireexprLocal {
                    id: 0,
                    suffix_len: Some(keyexpr.len() as u64),
                    suffix: Some(sce_forge_runtime::codec::Bounded::new(keyexpr).unwrap()),
                }),
            },
            ..Push::default()
        }
        .try_into_owned_in::<crate::wire::WireStorage>()
        .unwrap();
        push.body = PushOwnedVariant::CodecZenohMsgPut(put);
        push
    }

    /// A Put carrying a wire attachment ext (ext_id 0x03 ZBuf).
    fn push_put_with_attachment(keyexpr: &str, bytes: &[u8]) -> PushOwned {
        let mut ext = wz_codecs::lent::ExtEntry::new();
        ext.set_ext_id(0x03); // ATTACHMENT_EXT_ID_PUSH
        ext.set_enc(0x02); // ENC_ZBUF
        ext.body = wz_codecs::lent::ExtEntryVariant::CodecZenohExtZbuf(wz_codecs::lent::ExtZbuf {
            value_len: bytes.len() as u64,
            value: sce_forge_runtime::codec::Bounded::new(bytes).unwrap(),
        });
        let mut put: crate::wire::parts::MsgPutOwned = crate::put_payload::inline(b"").unwrap();
        crate::put_payload::set_chain(
            &mut put,
            [ext.try_into_owned_in::<crate::wire::WireStorage>().unwrap()],
        )
        .unwrap();
        let mut push = Push {
            keyexpr: wz_codecs::lent::Wireexpr {
                body: WireexprVariant::WireexprLocal(wz_codecs::lent::WireexprLocal {
                    id: 0,
                    suffix_len: Some(keyexpr.len() as u64),
                    suffix: Some(sce_forge_runtime::codec::Bounded::new(keyexpr).unwrap()),
                }),
            },
            ..Push::default()
        }
        .try_into_owned_in::<crate::wire::WireStorage>()
        .unwrap();
        push.body = PushOwnedVariant::CodecZenohMsgPut(put);
        push
    }

    #[test]
    fn inbound_put_timestamp_is_projected_when_pubsub_timestamp_on() {
        let mut registry = SubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let present = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        let p = present.clone();
        registry
            .register("home/temp", move |sample| {
                f.fetch_add(1, Ordering::SeqCst);
                if sample.timestamp().is_some() {
                    p.fetch_add(1, Ordering::SeqCst);
                }
            })
            .expect("no quota is stated on this table");
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_put_with_timestamp("home/temp"))),
            Reliability::Reliable,
        );
        assert_eq!(fired.load(Ordering::SeqCst), 1, "subscriber fires");
        assert_eq!(
            present.load(Ordering::SeqCst),
            1,
            "wire timestamp projects to Sample.timestamp when pubsub-timestamp is on"
        );
    }

    #[test]
    fn inbound_put_attachment_is_projected_when_pubsub_attachment_on() {
        let mut registry = SubscriberRegistry::new();
        let captured: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let cap = captured.clone();
        registry
            .register("home/temp", move |sample| {
                *cap.lock().unwrap() = sample.attachment().map(<[u8]>::to_vec);
            })
            .expect("no quota is stated on this table");
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_put_with_attachment(
                "home/temp",
                &[0xDE, 0xAD, 0xBE, 0xEF],
            ))),
            Reliability::Reliable,
        );
        assert_eq!(
            captured.lock().unwrap().as_deref(),
            Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]),
            "wire attachment projects to Sample.attachment verbatim when pubsub-attachment is on"
        );
    }

    #[test]
    fn dispatch_push_fires_when_own_zid_not_set() {
        // Without an installed own_zid the registry cannot recognise
        // self-echo. Fire normally — this is the default state from
        // SubscriberRegistry::new() and the production behaviour
        // before the session-FSM handshake settles.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("demo/temp", move |_s| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");
        assert!(
            registry.own_zid().is_none(),
            "fresh registry must have no own_zid installed"
        );

        let push = push_put_literal_with_source_info("demo/temp", &[0x01, 0x02, 0x03, 0x04]);
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "no own_zid installed → no dedup, subscriber fires"
        );
    }

    #[test]
    fn dispatch_push_does_not_dedup_on_length_mismatch_prefix_collision() {
        // own_zid = 4 bytes, peer zid = 8 bytes whose first 4 bytes
        // coincide with own. The padded [u8;16] representations both
        // begin with the same 4 bytes, so a naive memcmp on the
        // padded buffer would false-positive. The zid_len-based
        // comparison must reject this.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("demo/temp", move |_s| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");
        assert!(registry.set_own_zid(vec![0x01, 0x02, 0x03, 0x04]));

        let push = push_put_literal_with_source_info(
            "demo/temp",
            &[0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB, 0xCC, 0xDD],
        );
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "length-mismatched zid (4 vs 8) must not match even when prefix coincides"
        );
    }

    #[test]
    fn local_publish_ignores_own_zid_dedup() {
        // Loopback path (is_remote=false) bypasses the dedup branch.
        // Otherwise a `Session::publish(Locality::SessionLocal, ...)`
        // by a session that has installed its own_zid would never fire
        // any subscriber — applying the dedup to loopback would
        // silently swallow legitimate in-process publishes.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("demo/temp", move |_s| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");
        let own = vec![0x01, 0x02, 0x03, 0x04];
        assert!(registry.set_own_zid(own.clone()));

        // Loopback sample carrying source_info.zid == own_zid. dedup
        // must NOT engage because is_remote=false.
        let sample = Sample::new_put("demo/temp", b"local".to_vec())
            .with_source_info(crate::sample::SourceInfo::new(&own, 0, 0));
        let fired = registry.local_publish(&sample);

        assert_eq!(
            fired, 1,
            "loopback path must fire even when source matches own_zid"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn set_own_zid_rejects_invalid_lengths() {
        // 0 bytes or 17 bytes are outside the zenoh-pico _Z_ID_LENGTH
        // wire-form range. The setter must reject without mutating
        // state — a silent accept of length 0 would store an empty
        // own_zid that matches every empty source_info.zid_prefix()
        // (i.e. every absent or sentinel source_info) and break the
        // cautious-default contract.
        let mut registry = SubscriberRegistry::new();
        assert!(!registry.set_own_zid(vec![]));
        assert!(registry.own_zid().is_none());
        assert!(!registry.set_own_zid(vec![0u8; 17]));
        assert!(registry.own_zid().is_none());
        assert!(registry.set_own_zid(vec![0x42]));
        assert_eq!(registry.own_zid(), Some(&[0x42u8][..]));
        assert!(registry.set_own_zid(vec![0u8; 16]));
        assert_eq!(registry.own_zid(), Some(&[0u8; 16][..]));
    }

    // Requires pubsub-source-info: the first dispatch asserts a
    // suppressed self-echo, which only engages when source_info is
    // decoded from the wire (see the sibling suppress test).
    #[cfg(feature = "pubsub-source-info")]
    #[test]
    fn clear_own_zid_reenables_callback_fire() {
        // After clear_own_zid a wire-arrived push that would
        // previously have been suppressed as self-echo fires the
        // subscriber. Models the session-close / re-init path.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry
            .register("demo/temp", move |_s| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");
        let own = vec![0x09, 0x08, 0x07, 0x06];
        assert!(registry.set_own_zid(own.clone()));

        // First dispatch: self-echo, suppressed.
        let push = push_put_literal_with_source_info("demo/temp", &own);
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        // clear_own_zid re-disables dedup.
        registry.clear_own_zid();
        assert!(registry.own_zid().is_none());

        // Same wire content now fires — no dedup state to suppress it.
        let push2 = push_put_literal_with_source_info("demo/temp", &own);
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push2)),
            Reliability::Reliable,
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "clear_own_zid must re-enable normal fire on wire-arrived samples"
        );
    }

    /// R311gb (Track 2) — direct exercise of the no-heap fire entry
    /// `dispatch_borrowed`: the wire path reaches `fire_to_subscribers`
    /// via `dispatch_push`, but this proves the public no-heap entry
    /// itself delivers a borrowed `SampleView` to a matching sink (and
    /// filters non-matches) without an owned `Sample`.
    #[test]
    fn dispatch_borrowed_delivers_borrowed_sample_to_matching_sink() {
        use crate::sink::BorrowedSample;
        let mut reg = SubscriberRegistry::new();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        reg.register("home/temp", move |v: &dyn SampleView| {
            assert_eq!(v.keyexpr(), "home/temp");
            h.fetch_add(1, Ordering::SeqCst);
        })
        .expect("no quota is stated on this table");
        let fired = reg.dispatch_borrowed(
            &BorrowedSample {
                keyexpr: "home/temp",
                payload: b"21.5",
                kind: SampleKind::Put,
                reliability: Reliability::BestEffort,
            },
            /* is_remote = */ true,
        );
        assert_eq!(fired, 1);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let none = reg.dispatch_borrowed(
            &BorrowedSample {
                keyexpr: "other/x",
                payload: b"",
                kind: SampleKind::Put,
                reliability: Reliability::BestEffort,
            },
            true,
        );
        assert_eq!(none, 0, "non-matching keyexpr does not fire");
    }

    /// The match memory delivers a repeated key to exactly the subscribers a fresh match
    /// finds, and never a stale set: a subscription registered or retired between two
    /// messages is seen by the second, a key that matches several subscribers reaches them
    /// all in the table's order, and the locality an answer was worked out for is part of
    /// it (a Remote-only subscriber answers a wire-arrived key and not a local-origin one).
    #[test]
    fn the_match_memory_follows_the_subscriptions_and_the_locality() {
        use crate::locality::Locality;
        use crate::sink::BorrowedSample;
        use std::sync::Mutex;
        use std::vec::Vec;

        let order: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
        let log = |name: &'static str| {
            let order = order.clone();
            move |_: &dyn SampleView| order.lock().unwrap().push(name)
        };
        let key = |keyexpr: &'static str| BorrowedSample {
            keyexpr,
            payload: b"x",
            kind: SampleKind::Put,
            reliability: Reliability::Reliable,
        };
        let mut reg = SubscriberRegistry::new();
        let wildcard = reg
            .register("a/*", log("wildcard"))
            .expect("no quota is stated on this table");

        // Three messages on one key: the first is matched, the next two are remembered.
        for _ in 0..3 {
            assert_eq!(reg.dispatch_borrowed(&key("a/x"), true), 1);
        }
        assert_eq!(order.lock().unwrap().len(), 3);

        // A subscription registered now moves the epoch: the next message reaches both,
        // in the table's order, and the one after that (remembered) still does.
        reg.register("a/x", log("exact"))
            .expect("no quota is stated on this table");
        order.lock().unwrap().clear();
        for _ in 0..2 {
            assert_eq!(reg.dispatch_borrowed(&key("a/x"), true), 2);
        }
        assert_eq!(
            *order.lock().unwrap(),
            ["wildcard", "exact", "wildcard", "exact"]
        );

        // A subscription retired moves it again: only the exact one is left.
        assert!(reg.unregister(wildcard));
        order.lock().unwrap().clear();
        for _ in 0..2 {
            assert_eq!(reg.dispatch_borrowed(&key("a/x"), true), 1);
        }
        assert_eq!(*order.lock().unwrap(), ["exact", "exact"]);

        // A key nobody matches is a remembered nobody, and stays so.
        for _ in 0..2 {
            assert_eq!(reg.dispatch_borrowed(&key("other/y"), true), 0);
        }

        // The locality is part of the answer: a Remote-only subscriber is fired for a
        // wire-arrived key and not for a local-origin one, whichever was asked first.
        reg.register_with_locality("loc/k", Locality::Remote, log("remote-only"))
            .expect("no quota is stated on this table");
        order.lock().unwrap().clear();
        assert_eq!(reg.dispatch_borrowed(&key("loc/k"), false), 0);
        assert_eq!(reg.dispatch_borrowed(&key("loc/k"), true), 1);
        assert_eq!(reg.dispatch_borrowed(&key("loc/k"), false), 0);
        assert_eq!(reg.dispatch_borrowed(&key("loc/k"), true), 1);
        assert_eq!(*order.lock().unwrap(), ["remote-only", "remote-only"]);
    }

    /// With slots the memory answers a key that comes again without matching it, and with none
    /// (the build's slot count for its profile's storage policy, `MATCH_MEMO_SLOTS` on the heap
    /// and `MATCH_MEMO_FIXED_SLOTS` on fixed tables, of 0) every message is matched: the one
    /// difference between the two builds, which the test above shows is not a difference in what
    /// is delivered. A key a subscription's registration made stale is matched again either way.
    #[test]
    fn a_repeated_key_is_matched_once_with_slots_and_every_time_without() {
        use crate::sink::BorrowedSample;
        let scans = || MATCH_SCANS.with(|count| count.get());
        let key = |keyexpr: &'static str| BorrowedSample {
            keyexpr,
            payload: b"x",
            kind: SampleKind::Put,
            reliability: Reliability::Reliable,
        };
        // `SubscriberRegistry::new()` is of this build's profile, so the count that applies is the
        // one its storage policy reads.
        let remembered = if memo_slots::<Profile>(caps::MATCH_MEMO_SLOTS) == 0 {
            5
        } else {
            1
        };
        let mut reg = SubscriberRegistry::new();
        reg.register("a/*", |_: &dyn SampleView| {})
            .expect("no quota is stated on this table");

        let start = scans();
        for _ in 0..5 {
            assert_eq!(reg.dispatch_borrowed(&key("a/x"), true), 1);
        }
        let first_key = scans() - start;
        assert_eq!(first_key, remembered, "five messages on one key");

        reg.register("a/x", |_: &dyn SampleView| {})
            .expect("no quota is stated on this table");
        let start = scans();
        for _ in 0..5 {
            assert_eq!(reg.dispatch_borrowed(&key("a/x"), true), 2);
        }
        assert_eq!(
            scans() - start,
            remembered,
            "a registration is seen by the next message, then the key is remembered again"
        );
    }

    /// A table of the fixed storage policy holds its cache in RAM and so reads its own count,
    /// `MATCH_MEMO_FIXED_SLOTS` (0 unless the image asks): with slots a repeated key is matched
    /// once and a registration is seen by the next message, with none every message is matched,
    /// and either way a key longer than a slot holds is matched every time it arrives.
    #[test]
    fn a_fixed_table_remembers_a_key_where_its_own_slots_ask_and_never_one_too_long() {
        use crate::bounded::Static;
        use crate::sink::BorrowedSample;

        struct Noop;
        impl SampleSink for Noop {
            fn deliver(&mut self, _sample: &dyn SampleView) {}
        }

        let scans = || MATCH_SCANS.with(|count| count.get());
        let key = |keyexpr: &'static str| BorrowedSample {
            keyexpr,
            payload: b"x",
            kind: SampleKind::Put,
            reliability: Reliability::Reliable,
        };
        let remembered = if caps::MATCH_MEMO_FIXED_SLOTS == 0 {
            5
        } else {
            1
        };
        let mut reg: SubscriberRegistry<Noop, Static> = SubscriberRegistry::default();
        reg.register_sink("a/*", crate::locality::Locality::Any, Noop)
            .expect("one subscription fits");

        let start = scans();
        for _ in 0..5 {
            assert_eq!(reg.dispatch_borrowed(&key("a/x"), true), 1);
        }
        assert_eq!(scans() - start, remembered, "five messages on one key");

        reg.register_sink("a/x", crate::locality::Locality::Any, Noop)
            .expect("two subscriptions fit");
        let start = scans();
        for _ in 0..5 {
            assert_eq!(reg.dispatch_borrowed(&key("a/x"), true), 2);
        }
        assert_eq!(
            scans() - start,
            remembered,
            "a registration is seen by the next message"
        );

        // A key longer than `MATCH_MEMO_KEY_BYTES` is delivered, and matched each time.
        let long: &'static str = std::boxed::Box::leak(
            std::format!("a/{}", "k".repeat(caps::MATCH_MEMO_KEY_BYTES)).into_boxed_str(),
        );
        let start = scans();
        for _ in 0..5 {
            assert_eq!(reg.dispatch_borrowed(&key(long), true), 1);
        }
        assert_eq!(scans() - start, 5, "a key too long for a slot");
    }

    /// A pattern and a key with no wildcard are compared as text, from the facts each was read
    /// for once, and only a wildcard on either side walks the two: a concrete key delivered past
    /// two concrete subscriptions and a wildcard one walks the wildcard one alone, and a wildcard
    /// key walks every subscription.
    #[test]
    fn a_concrete_key_walks_only_the_wildcard_subscriptions() {
        use crate::bounded::Static;
        use crate::keyexpr_match::INTERSECT_WALKS;
        use crate::sink::BorrowedSample;

        struct Noop;
        impl SampleSink for Noop {
            fn deliver(&mut self, _sample: &dyn SampleView) {}
        }

        if caps::MAX_SUBSCRIPTIONS < 3 {
            return;
        }
        let walks = || INTERSECT_WALKS.with(|count| count.get());
        let key = |keyexpr: &'static str| BorrowedSample {
            keyexpr,
            payload: b"x",
            kind: SampleKind::Put,
            reliability: Reliability::Reliable,
        };
        let mut reg: SubscriberRegistry<Noop, Static> = SubscriberRegistry::default();
        for pattern in ["s/one", "s/two", "s/*"] {
            reg.register_sink(pattern, crate::locality::Locality::Any, Noop)
                .expect("three subscriptions fit");
        }

        let start = walks();
        assert_eq!(reg.dispatch_borrowed(&key("s/one"), true), 2);
        assert_eq!(walks() - start, 1, "the wildcard subscription alone");

        let start = walks();
        assert_eq!(reg.dispatch_borrowed(&key("s/other"), true), 1);
        assert_eq!(walks() - start, 1, "a key no concrete subscription equals");

        let start = walks();
        assert_eq!(reg.dispatch_borrowed(&key("s/*"), true), 3);
        assert_eq!(
            walks() - start,
            3,
            "a wildcard key walks every subscription"
        );
    }
}

// ── decode-side feature-isolation NEG (asymmetric pubsub-put /
// pubsub-delete) ──
//
// The main `mod tests` above is gated on BOTH pubsub-put AND
// pubsub-delete (its Del-body POS tests construct the Del variant and
// assert `SampleKind::Del`), so it is entirely cfg'd out under an
// asymmetric build and cannot host these guards. `dispatch_push` routes
// the variant whose consumer feature is OFF to the `_ => return`
// silent-drop (the put arm is `cfg(feature = "pubsub-put")`, the del arm
// `cfg(feature = "pubsub-delete")`). Layer F proves the off feature
// SHRINKS the binary; only these pin the receive BEHAVIOUR — an inbound
// Push of the off variant fires NO subscriber callback, while the ON
// variant still dispatches (so the drop is variant-selective, not a dead
// registry). Each test runs only in the single-variant build its `cfg`
// selects; the run-ci C1d asymmetric lanes
// (`--features codec-push,pubsub-put` and `…,pubsub-delete`) compile
// exactly those two builds, which the symmetric (both-on) lanes never do.
#[cfg(test)]
#[cfg(all(
    feature = "storage-profile",
    feature = "codec-push",
    any(
        all(feature = "pubsub-put", not(feature = "pubsub-delete")),
        all(not(feature = "pubsub-put"), feature = "pubsub-delete"),
    )
))]
mod decode_isolation_tests {
    use super::push_fixtures::{push_with_del_body, push_with_keyexpr};
    use super::*;
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[cfg(all(feature = "pubsub-put", not(feature = "pubsub-delete")))]
    #[test]
    fn inbound_del_push_is_silently_dropped_when_pubsub_delete_off() {
        let mut registry = SubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        registry
            .register("home/temp", move |_| {
                f.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        // Del variant → `pubsub-delete` arm cfg'd out → `_ => return`.
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_with_del_body("home/temp"))),
            Reliability::Reliable,
        );
        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "inbound Del must not fire the subscriber when pubsub-delete is off"
        );

        // Put still dispatches — proves the drop is variant-selective,
        // not a dead/unwired registry.
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_with_keyexpr("home/temp"))),
            Reliability::Reliable,
        );
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "inbound Put still fires when pubsub-put is on"
        );
    }

    #[cfg(all(not(feature = "pubsub-put"), feature = "pubsub-delete"))]
    #[test]
    fn inbound_put_push_is_silently_dropped_when_pubsub_put_off() {
        let mut registry = SubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        registry
            .register("home/temp", move |_| {
                f.fetch_add(1, Ordering::SeqCst);
            })
            .expect("no quota is stated on this table");

        // Put variant → `pubsub-put` arm cfg'd out → `_ => return`.
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_with_keyexpr("home/temp"))),
            Reliability::Reliable,
        );
        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "inbound Put must not fire the subscriber when pubsub-put is off"
        );

        // Del still dispatches — proves the drop is variant-selective.
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_with_del_body("home/temp"))),
            Reliability::Reliable,
        );
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "inbound Del still fires when pubsub-delete is on"
        );
    }
}

// ── receive-side timestamp / attachment field-drop NEG ──
//
// The main `mod tests` gates on pubsub-timestamp + pubsub-attachment ON
// (the data-plane union), so it cannot host the OFF arm of those two
// projection gates. This module pins it: in a build with `pubsub-put`
// ON but `pubsub-timestamp` / `pubsub-attachment` OFF, dispatch_push's
// Put arm yields `None` for those fields (the
// `#[cfg(not(feature = "pubsub-timestamp"))]` / `..-attachment`
// branches) even though the wire body carries them — the codec
// `MsgPut.timestamp` field and the attachment ext (ext_id 0x03 ZBuf)
// are ungated (struct stability). An un-gating regression would leak
// the field into the Sample on a build that never opted in, and only
// this lane would catch it; Layer F proves the OFF feature shrinks the
// binary, not that the field is dropped. Companion of the encoding /
// source_info pairs in `mod tests` (whose OFF arm the C1d-first lane
// covers); these two metadata fields have no put-on / feature-off build
// there, so they get a dedicated module. The run-ci C1d
// `--features codec-push,pubsub-put` lane (added with the put/delete
// `decode_isolation_tests`) builds exactly this profile — pubsub-put ON,
// every metadata feature OFF — so these RUN there.
#[cfg(test)]
#[cfg(all(
    feature = "storage-profile",
    feature = "codec-push",
    feature = "pubsub-put",
    not(feature = "pubsub-timestamp"),
    not(feature = "pubsub-attachment"),
))]
mod metadata_decode_isolation_tests {
    use super::*;
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use wz_codecs::lent::{Push, Wireexpr, WireexprLocal, WireexprVariant};

    /// A literal-keyexpr Put with a `Push::default()` body (no metadata).
    fn put_push_literal(keyexpr: &str) -> PushOwned {
        Push {
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprLocal(WireexprLocal {
                    id: 0,
                    suffix_len: Some(keyexpr.len() as u64),
                    suffix: Some(sce_forge_runtime::codec::Bounded::new(keyexpr).unwrap()),
                }),
            },
            ..Push::default()
        }
        .try_into_owned_in::<crate::wire::WireStorage>()
        .unwrap()
    }

    /// A Put carrying a wire `timestamp` (time + 4-byte zid). The codec
    /// `MsgPut.timestamp` field is ungated, so this is constructible with
    /// `pubsub-timestamp` off — that feature gates only the projection.
    fn put_push_with_timestamp(keyexpr: &str) -> PushOwned {
        let zid = [0x01u8, 0x02, 0x03, 0x04];
        let put = wz_codecs::lent::MsgPut {
            timestamp: Some(wz_codecs::lent::Timestamp {
                time: 0x0102_0304_0506_0708,
                zid_len: zid.len() as u64,
                zid: sce_forge_runtime::codec::Bounded::new(&zid[..]).unwrap(),
            }),
            ..wz_codecs::lent::MsgPut::default()
        }
        .try_into_owned_in::<crate::wire::WireStorage>()
        .unwrap();
        let mut push = put_push_literal(keyexpr);
        push.body = PushOwnedVariant::CodecZenohMsgPut(put);
        push
    }

    /// A Put carrying a wire attachment ext (ext_id 0x03 ZBuf). Built by
    /// hand (the `crate::attachment` helper is `attachment-bytes`-gated
    /// and absent in this profile); the wire form is the raw ZBuf value.
    fn put_push_with_attachment(keyexpr: &str, bytes: &[u8]) -> PushOwned {
        let mut ext = wz_codecs::lent::ExtEntry::new();
        ext.set_ext_id(0x03); // ATTACHMENT_EXT_ID_PUSH
        ext.set_enc(0x02); // ENC_ZBUF
        ext.body = wz_codecs::lent::ExtEntryVariant::CodecZenohExtZbuf(wz_codecs::lent::ExtZbuf {
            value_len: bytes.len() as u64,
            value: sce_forge_runtime::codec::Bounded::new(bytes).unwrap(),
        });
        let mut put: crate::wire::parts::MsgPutOwned = crate::put_payload::inline(b"").unwrap();
        crate::put_payload::set_chain(
            &mut put,
            [ext.try_into_owned_in::<crate::wire::WireStorage>().unwrap()],
        )
        .unwrap();
        let mut push = put_push_literal(keyexpr);
        push.body = PushOwnedVariant::CodecZenohMsgPut(put);
        push
    }

    #[test]
    fn inbound_put_timestamp_is_dropped_when_pubsub_timestamp_off() {
        let mut registry = SubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let present = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        let p = present.clone();
        registry
            .register("home/temp", move |sample| {
                f.fetch_add(1, Ordering::SeqCst);
                if sample.timestamp().is_some() {
                    p.fetch_add(1, Ordering::SeqCst);
                }
            })
            .expect("no quota is stated on this table");
        registry.dispatch(
            &NetworkMessage::Push(Box::new(put_push_with_timestamp("home/temp"))),
            Reliability::Reliable,
        );
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "subscriber still fires — only the metadata field is dropped"
        );
        assert_eq!(
            present.load(Ordering::SeqCst),
            0,
            "wire timestamp must NOT project to Sample.timestamp when pubsub-timestamp is off"
        );
    }

    #[test]
    fn inbound_put_attachment_is_dropped_when_pubsub_attachment_off() {
        let mut registry = SubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let present = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        let p = present.clone();
        registry
            .register("home/temp", move |sample| {
                f.fetch_add(1, Ordering::SeqCst);
                if sample.attachment().is_some() {
                    p.fetch_add(1, Ordering::SeqCst);
                }
            })
            .expect("no quota is stated on this table");
        registry.dispatch(
            &NetworkMessage::Push(Box::new(put_push_with_attachment(
                "home/temp",
                &[0xDE, 0xAD, 0xBE, 0xEF],
            ))),
            Reliability::Reliable,
        );
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "subscriber still fires — only the metadata field is dropped"
        );
        assert_eq!(
            present.load(Ordering::SeqCst),
            0,
            "wire attachment must NOT project to Sample.attachment when pubsub-attachment is off"
        );
    }
}

/// The subscriber-interest staging on the FIXED backing, where its buffer and
/// its interest table refuse by their storage. On the growable backing none of
/// these refusals is reachable with no quota stated, so the module is gated to
/// the fixed one; a stated quota is the enforcement tests' (`limits.rs`). Interests use the
/// keyexpr-less match-all form so no wildcard feature decides the outcome.
#[cfg(all(
    test,
    feature = "declare-subscriber",
    any(not(feature = "alloc"), feature = "bounded-heapless")
))]
mod fixed_backing_interest_staging_tests {
    use super::*;

    struct Noop;
    impl SampleSink for Noop {
        fn deliver(&mut self, _sample: &dyn SampleView) {}
    }

    const PATTERNS: [&str; 16] = [
        "t/0", "t/1", "t/2", "t/3", "t/4", "t/5", "t/6", "t/7", "t/8", "t/9", "t/10", "t/11",
        "t/12", "t/13", "t/14", "t/15",
    ];

    fn registry_with(subscriptions: usize) -> SubscriberRegistry<Noop> {
        let mut reg = SubscriberRegistry::with_sink_backing();
        for pattern in PATTERNS.iter().take(subscriptions) {
            reg.register_sink(pattern, crate::locality::Locality::Any, Noop)
                .expect("below MAX_SUBSCRIPTIONS");
        }
        reg
    }

    /// Two CURRENT dumps of 16 replies each need 2 x 17 slots against 32. The
    /// code this replaced pushed the second best-effort: 15 of its replies and
    /// no `Final`, so that peer was answered half and never terminated. Now the
    /// second is refused whole and counted, and the first is intact.
    #[test]
    fn a_current_chain_that_does_not_fit_whole_is_refused_and_counted() {
        assert_eq!(PATTERNS.len(), caps::MAX_SUBSCRIPTIONS);
        let mut reg = registry_with(caps::MAX_SUBSCRIPTIONS);
        assert_eq!(
            reg.respond_to_subscriber_interest_borrowed(1, None, false, true, false),
            caps::MAX_SUBSCRIPTIONS
        );
        assert_eq!(
            reg.respond_to_subscriber_interest_borrowed(2, None, false, true, false),
            0
        );
        assert_eq!(
            reg.interest_staging_refusals(),
            SubInterestRefusals {
                chains: 1,
                ..SubInterestRefusals::default()
            }
        );
        let staged = reg.take_staged_sub_interest_replies();
        assert_eq!(staged.len(), caps::MAX_SUBSCRIPTIONS + 1);
        assert!(staged.iter().all(|item| matches!(
            item,
            SubInterestReply::Concrete { interest_id: 1, .. }
                | SubInterestReply::Final { interest_id: 1 }
        )));
        assert!(matches!(
            staged.last(),
            Some(SubInterestReply::Final { interest_id: 1 })
        ));
    }

    /// A FUTURE interest the full table cannot remember loses the push of a
    /// later subscription to that publisher. That loss is counted.
    #[test]
    fn a_future_interest_the_full_table_cannot_hold_is_counted() {
        let mut reg = registry_with(0);
        for id in 0..caps::MAX_INBOUND_SUB_INTERESTS as u64 {
            reg.respond_to_subscriber_interest_borrowed(id, None, false, false, true);
        }
        assert_eq!(reg.interest_staging_refusals().future_interests, 0);
        reg.respond_to_subscriber_interest_borrowed(99, None, false, false, true);
        assert_eq!(reg.interest_staging_refusals().future_interests, 1);
    }

    /// An AGGREGATE CURRENT interest answers through its own row at drain. With
    /// the table full there is no row, and the code this replaced staged the
    /// `Final` alone: "no subscription matches" to a peer whose interest one
    /// subscription does match. Now the chain is refused and nothing is staged.
    #[test]
    fn an_aggregate_current_interest_without_its_row_is_refused_not_answered_empty() {
        let mut reg = registry_with(1);
        for id in 0..caps::MAX_INBOUND_SUB_INTERESTS as u64 {
            reg.respond_to_subscriber_interest_borrowed(id, None, false, false, true);
        }
        assert!(reg.take_staged_sub_interest_replies().is_empty());
        assert_eq!(
            reg.respond_to_subscriber_interest_borrowed(99, None, true, true, false),
            0
        );
        assert_eq!(reg.interest_staging_refusals().chains, 1);
        assert!(
            reg.take_staged_sub_interest_replies().is_empty(),
            "no bare Final for a chain that could not be answered"
        );
    }
}

/// A subscription's id is the `DeclSubscriber.id` it is announced under, a
/// `u32` upstream's decoder refuses to read wider, so the table hands out ids
/// up to `u32::MAX` and refuses past it.
#[cfg(all(test, feature = "alloc"))]
mod entity_id_space_tests {
    use super::*;
    use crate::locality::Locality;

    #[test]
    fn the_last_u32_id_is_handed_out_and_the_next_registration_is_refused() {
        let mut table = SubscriberTable::new();
        table.next_id = u64::from(u32::MAX);

        let last = table
            .register_sink("topic/a", Locality::Any, BoxedSink::new(|_| {}))
            .expect("the last id is free");
        assert_eq!(last.entity_id(), u32::MAX);
        assert_eq!(last.as_u64(), u64::from(u32::MAX));

        let epoch = table.epoch;
        assert_eq!(
            table.register_sink("topic/b", Locality::Any, BoxedSink::new(|_| {})),
            Err(RegisterError::IdsExhausted)
        );
        assert_eq!(table.len(), 1, "the refused subscription is not stored");
        assert_eq!(table.epoch, epoch, "a refusal does not move the table");

        // Retiring a subscription frees its row, not its id: an id a peer may
        // still hold for the retired declaration is not handed out again.
        assert!(table.unregister(last));
        assert_eq!(
            table.register_sink("topic/c", Locality::Any, BoxedSink::new(|_| {})),
            Err(RegisterError::IdsExhausted)
        );
    }

    #[test]
    fn ids_start_at_one_and_count_up() {
        let mut table = SubscriberTable::new();
        let first = table
            .register_sink("topic/a", Locality::Any, BoxedSink::new(|_| {}))
            .expect("registers");
        let second = table
            .register_sink("topic/b", Locality::Any, BoxedSink::new(|_| {}))
            .expect("registers");
        assert_eq!((first.entity_id(), second.entity_id()), (1, 2));
    }

    /// A sink a test can tell apart from another.
    struct Tagged(u8);

    impl SampleSink for Tagged {
        fn deliver(&mut self, _sample: &dyn SampleView) {}
    }

    /// A subscription is read and taken by its place in the table's order, the ones after it
    /// closing the gap, and its sink is handed back to the taker; a place past the end takes
    /// nothing and moves nothing.
    #[test]
    fn a_row_is_read_and_taken_by_its_place() {
        let mut table = SubscriberTable::<Tagged>::with_sink_backing();
        for (key, tag) in [("topic/a", 1), ("topic/b", 2), ("topic/c", 3)] {
            table
                .register_sink(key, Locality::Any, Tagged(tag))
                .expect("registers");
        }
        assert_eq!(
            table.row_at(1).map(|(key, sink)| (key, sink.0)),
            Some(("topic/b", 2))
        );
        assert!(table.row_at(3).is_none());
        let epoch = table.epoch;
        assert_eq!(table.take_at(1).map(|sink| sink.0), Some(2));
        assert_eq!(table.epoch, epoch + 1, "a removal moves the table");
        assert_eq!(table.len(), 2);
        assert_eq!(table.row_at(1).map(|(key, _)| key), Some("topic/c"));
        assert!(table.take_at(2).is_none(), "nothing past the end");
        assert_eq!(table.epoch, epoch + 1, "a take of nothing moves nothing");
    }

    /// A subscription is found by what its sink holds, at its place in the table's order.
    #[test]
    fn a_row_is_found_by_its_sink() {
        let mut table = SubscriberTable::<Tagged>::with_sink_backing();
        for (key, tag) in [("topic/a", 1), ("topic/b", 2)] {
            table
                .register_sink(key, Locality::Any, Tagged(tag))
                .expect("registers");
        }
        assert_eq!(table.position_of(|sink| sink.0 == 2), Some(1));
        assert_eq!(table.position_of(|sink| sink.0 == 3), None);
        assert!(table.take_at(0).is_some());
        assert_eq!(table.position_of(|sink| sink.0 == 2), Some(0));
    }

    /// A table holding as many subscriptions as its limit admits is full, and refuses the next;
    /// one taken out makes it not full again. The limit is the one its creator resolved: a table
    /// that was given none holds the build's growable bound, which no count reaches.
    #[test]
    fn a_table_at_its_limit_is_full() {
        const MOST: usize = 2;
        let mut limits = crate::limits::SessionLimits::defaults();
        limits
            .select_max_subscriptions(crate::limit_binding::Quota::at_most(MOST))
            .expect("inside the build's domain");
        let mut table = SubscriberTable::<Tagged>::with_sink_backing();
        table.limit_to(limits.max_subscriptions_held());
        let mut held = 0;
        while !table.is_full() {
            table
                .register_sink(&alloc::format!("topic/{held}"), Locality::Any, Tagged(0))
                .expect("a table that is not full takes one more");
            held += 1;
            assert!(held <= caps::MAX_SUBSCRIPTIONS, "the bound is reached");
        }
        assert!(
            held >= MOST.min(caps::MAX_SUBSCRIPTIONS),
            "full only at its bound"
        );
        assert_eq!(
            table
                .register_sink("topic/past", Locality::Any, Tagged(0))
                .map(|_| ()),
            Err(RegisterError::TableFull),
            "a full table refuses as it said"
        );
        assert!(table.take_at(0).is_some());
        assert!(!table.is_full());
    }

    /// An aggregate interest's reply takes its declaration id from the same
    /// counter, so a table with no id left stores no row for it and refuses
    /// the chain rather than answer under an id it does not have.
    #[cfg(feature = "declare-subscriber")]
    #[test]
    fn an_aggregate_interest_is_refused_once_the_ids_are_spent() {
        let mut control = SubscriberRegistry::new();
        control
            .register_sink("topic/a", Locality::Any, BoxedSink::new(|_| {}))
            .expect("registers");
        assert_eq!(
            control.respond_to_subscriber_interest_borrowed(7, Some("topic/**"), true, true, false),
            1,
            "a table with ids left answers the aggregate interest"
        );

        let mut spent = SubscriberRegistry::new();
        spent.table.next_id = u64::from(u32::MAX);
        spent
            .register_sink("topic/a", Locality::Any, BoxedSink::new(|_| {}))
            .expect("the last id is free");
        assert_eq!(
            spent.respond_to_subscriber_interest_borrowed(7, Some("topic/**"), true, true, false),
            0,
            "no id is left for the aggregate reply"
        );
        assert!(
            spent.take_staged_sub_interest_replies().is_empty(),
            "no bare Final for a chain that could not be answered"
        );
    }
}

/// The receive match cache of a heap table that has grown past the 65536 positions a slot keeps
/// in 16 bits: a key that matched a subscriber beyond them is delivered by the scan each time and
/// never answered from a slot, where a position cut to 16 bits would name another subscriber.
///
/// The table is filled with real rows rather than a cache slot written by hand: 65537 rows of a
/// short pattern cost a few megabytes and three scans of them a few milliseconds, and the test
/// then goes through the same registration and delivery a session does.
///
/// Only a build whose subscriber tables may grow past the positions has the case: a fixed build
/// states its capacity as every table's quota (`MAX_SUBSCRIPTIONS`), a table on the heap policy
/// included, and that capacity fits the 16 bits by the build-time assertion beside the cache.
#[cfg(all(test, feature = "alloc", not(feature = "bounded-heapless")))]
mod match_memo_position_tests {
    use super::*;
    use crate::bounded::Heap;
    use crate::locality::Locality;
    use crate::sample::{Reliability, SampleKind};
    use crate::sink::BorrowedSample;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Counts each delivery into the counter it shares.
    struct Count(Arc<AtomicUsize>);
    impl SampleSink for Count {
        fn deliver(&mut self, _sample: &dyn SampleView) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn a_key_matched_past_the_16_bit_positions_is_scanned_each_time_and_not_remembered() {
        let scans = || MATCH_SCANS.with(|count| count.get());
        let elsewhere = Arc::new(AtomicUsize::new(0));
        let target = Arc::new(AtomicUsize::new(0));
        let mut table: SubscriberTable<Count, Heap> = SubscriberTable::default();
        // Every position 16 bits can name holds a subscriber the key does not reach.
        for _ in 0..=usize::from(u16::MAX) {
            table
                .register_sink("other/x", Locality::Any, Count(elsewhere.clone()))
                .expect("a heap table grows");
        }
        // The one it reaches is at 65536, which is position 0 once cut to 16 bits.
        table
            .register_sink("k", Locality::Any, Count(target.clone()))
            .expect("a heap table grows");
        assert_eq!(table.len(), usize::from(u16::MAX) + 2);

        let sample = BorrowedSample {
            keyexpr: "k",
            payload: b"x",
            kind: SampleKind::Put,
            reliability: Reliability::Reliable,
        };
        let start = scans();
        for _ in 0..3 {
            assert_eq!(table.dispatch_borrowed(&sample, false), 1);
        }
        assert_eq!(
            target.load(Ordering::Relaxed),
            3,
            "each message reaches the subscriber the key matches"
        );
        assert_eq!(elsewhere.load(Ordering::Relaxed), 0, "and no other");
        assert_eq!(
            scans() - start,
            3,
            "the key is matched by the scan each time, never answered from a slot"
        );
    }

    /// The count a heap table's creator states is the count its cache holds: none matches a
    /// repeated key every time, one remembers it after the first, and each delivers the same.
    #[test]
    fn a_heap_table_remembers_as_many_keys_as_its_creator_states() {
        let scans = || MATCH_SCANS.with(|count| count.get());
        let delivered = Arc::new(AtomicUsize::new(0));
        let mut table: SubscriberTable<Count, Heap> = SubscriberTable::default();
        table
            // A literal key: a build without the wildcard features matches `a/*` only as text.
            .register_sink("a/x", Locality::Any, Count(delivered.clone()))
            .expect("a heap table grows");
        let sample = BorrowedSample {
            keyexpr: "a/x",
            payload: b"x",
            kind: SampleKind::Put,
            reliability: Reliability::Reliable,
        };
        for (stated, matched) in [(0, 5), (1, 1)] {
            table.limit_memo_to(stated);
            assert_eq!(table.memo_slot_count(), stated);
            let start = scans();
            for _ in 0..5 {
                assert_eq!(table.dispatch_borrowed(&sample, true), 1);
            }
            assert_eq!(
                scans() - start,
                matched,
                "{stated} slots, five messages on one key"
            );
        }
        assert_eq!(
            delivered.load(Ordering::Relaxed),
            10,
            "every message is delivered"
        );
    }
}

/// The announcements a heap table stages: the lists the two stagers gather matching interest rows
/// into are of the table's own storage policy, so a heap table holding more rows than
/// `MAX_INBOUND_SUB_INTERESTS` announces to every one of them, where a list of the build's fixed
/// policy would stop at that many without counting the rest.
///
/// Only a build whose interest tables may grow past that count has the case: a fixed build states
/// its capacity as every table's quota, a table on the heap policy included
/// ([`SubscriberTable::limit_interests_to`]), so no table of it holds more rows than its lists do.
#[cfg(all(
    test,
    feature = "alloc",
    not(feature = "bounded-heapless"),
    feature = "declare-subscriber",
    any(feature = "keyexpr-wildcard-double", feature = "declare-undeclare")
))]
mod heap_table_interest_staging_tests {
    use super::*;
    use crate::bounded::Heap;
    use crate::locality::Locality;

    struct Noop;
    impl SampleSink for Noop {
        fn deliver(&mut self, _sample: &dyn SampleView) {}
    }

    /// One interest more than a table of the fixed policy holds.
    const INTERESTS: u64 = caps::MAX_INBOUND_SUB_INTERESTS as u64 + 1;

    /// A match-all FUTURE interest is stored under `**`, so a subscription matches it only
    /// where the matcher reads `**` as a wildcard.
    #[cfg(feature = "keyexpr-wildcard-double")]
    #[test]
    fn a_new_subscription_is_announced_to_every_future_interest_of_a_heap_table() {
        let mut reg: SubscriberRegistry<Noop, Heap> = SubscriberRegistry::default();
        for interest in 0..INTERESTS {
            reg.respond_to_subscriber_interest_borrowed(interest, None, false, false, true);
        }
        assert_eq!(reg.peer().interest_count() as u64, INTERESTS);
        reg.register_sink("t/0", Locality::Any, Noop)
            .expect("a heap table grows");
        let staged = reg.take_staged_sub_interest_replies();
        assert_eq!(staged.len() as u64, INTERESTS, "one announcement each");
        assert!(staged
            .iter()
            .all(|item| matches!(item, SubInterestReply::Concrete { .. })));
        assert_eq!(
            reg.peer().interest_staging_refusals(),
            SubInterestRefusals::default()
        );
    }

    #[cfg(feature = "declare-undeclare")]
    #[test]
    fn a_retirement_retracts_every_announced_aggregate_of_a_heap_table() {
        let mut reg: SubscriberRegistry<Noop, Heap> = SubscriberRegistry::default();
        let id = reg
            .register_sink("t/0", Locality::Any, Noop)
            .expect("a heap table grows");
        for interest in 0..INTERESTS {
            reg.respond_to_subscriber_interest_borrowed(interest, None, true, false, true);
            reg.mark_aggregate_announced(interest);
        }
        assert!(
            reg.take_staged_sub_interest_replies().is_empty(),
            "a FUTURE-only interest stages nothing when it arrives"
        );
        assert!(reg.unregister(id));
        let staged = reg.take_staged_sub_interest_replies();
        assert_eq!(staged.len() as u64, INTERESTS, "one retraction each");
        assert!(staged
            .iter()
            .all(|item| matches!(item, SubInterestReply::AggregateRetract { .. })));
    }
}
