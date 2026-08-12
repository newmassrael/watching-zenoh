// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//!   a [`Sample`] to [`SubscriberRegistry::local_publish`]; the
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

#[cfg(feature = "alloc")]
use hashbrown::HashMap;

use crate::bounded::{BoundedString, BoundedVec};
use crate::caps;
use crate::keyexpr_match::MAX_KEYEXPR_CHUNKS;
use crate::registry_error::RegisterError;

// R311gb (Track 2) — `resolve_wireexpr` lives in the `alloc`-gated
// `wireexpr_resolve` module and is reached only from the `alloc`
// wire-dispatch paths (`dispatch_push` / `absorb_declare`), so the import
// carries `alloc` in addition to the codec markers (else `codec-declare`
// without `alloc` pulls an absent module).
#[cfg(all(
    feature = "alloc",
    any(
        feature = "pubsub-put",
        feature = "pubsub-delete",
        feature = "codec-declare"
    )
))]
use crate::wireexpr_resolve::resolve_wireexpr_in;
// R311y739 — the two-space PAIR is `alloc`-gated only: the `own_mapping_space`
// field and the `mapping_spaces()` accessor exist in every `alloc` profile,
// including one with no wire-dispatch consumer compiled in, whereas the
// resolver call above is reached only from those consumers.
#[cfg(feature = "alloc")]
use crate::wireexpr_resolve::{MappingSpaces, OwnMappingSpace};
#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use wz_codecs::declare::DeclareOwnedVariant;
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
use wz_codecs::push::{PushOwned, PushOwnedVariant};

#[cfg(all(
    feature = "alloc",
    any(feature = "pubsub-put", feature = "pubsub-delete"),
    feature = "pubsub-attachment"
))]
use crate::attachment::{decode_attachment_ext, ATTACHMENT_EXT_ID_PUSH};
#[cfg(feature = "alloc")]
use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
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
use crate::sample::{Reliability, Sample};
#[cfg(all(
    feature = "alloc",
    any(feature = "pubsub-put", feature = "pubsub-delete")
))]
use crate::sample::{SampleKind, TimestampHint};
use crate::sink::{SampleSink, SampleView};
#[cfg(all(feature = "alloc", feature = "declare-subscriber"))]
use wz_codecs::interest::InterestOwned;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriptionId(u64);

impl SubscriptionId {
    /// The numeric id behind the handle. Exposed for diagnostic
    /// surfaces; callers should not depend on the exact value across
    /// runs since the registry assigns ids monotonically from the
    /// session-local counter, not from a deterministic hash.
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

struct Subscriber<C: SampleSink> {
    id: SubscriptionId,
    /// R311gb (Track 2) — the canonical keyexpr pattern, stored as one
    /// [`BoundedString`] (no-alloc backing on MCU). Matching splits it
    /// on `/` at dispatch time into a stack chunk view rather than
    /// keeping a pre-split owned `Vec<String>`, so the subscriber row
    /// carries a single bounded buffer. Empty literal chunks are
    /// preserved (a pattern like `a//b` keeps its empty chunk); `*` /
    /// `**` are single-char chunks; matching is performed by
    /// [`keyexpr_pattern_matches`].
    pattern: BoundedString<{ caps::MAX_KEYEXPR_BYTES }>,
    /// R223 — locality filter applied before the sink fires.
    /// See [`crate::locality`] for the semantics and the wz
    /// dispatch invariant (every inbound Push is treated as remote
    /// until self-publish loopback lands in a future round).
    allowed_origin: crate::locality::Locality,
    /// R311gb-2b — the delivery sink (DIP seam). `C = BoxedSink` on AP
    /// (heap closure), a consumer-supplied closed `enum` on MCU.
    sink: C,
}

/// R311dn / di-15-pre — keyexpr glob + intersection matchers moved
/// to [`crate::keyexpr_match`]; re-exported here so prior
/// `crate::pubsub::keyexpr_pattern_matches` /
/// `crate::pubsub::keyexpr_intersect_patterns` callsites (declare/
/// subscriber, declare/queryable, declare/liveliness_subscriber,
/// query.rs, this file's tests) keep their existing import paths.
pub use crate::keyexpr_match::{keyexpr_intersect_patterns, keyexpr_pattern_matches};

/// Subscriber table backing the FramePayload → callback dispatch.
///
/// See module-level docs for scope (Push + DECLARE resolver, R121d).
/// `!Sync` by construction (no shared mutable state); callers that
/// need cross-task sharing wrap in `Arc<Mutex<…>>`.
pub struct SubscriberRegistry<C: SampleSink> {
    subscribers: BoundedVec<Subscriber<C>, { caps::MAX_SUBSCRIPTIONS }>,
    next_id: u64,
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
    #[cfg(feature = "alloc")]
    peer_keyexpr_table: HashMap<u64, String>,
    /// R311y739 — OUR id space, the other half of the pair the `M` bit picks
    /// between. Installed (not owned) so there is exactly ONE copy of the fact:
    /// the table itself lives on `SessionActions::outbound_mappings`, written by
    /// `send_declare_keyexpr` and pruned by `send_undeclare_kexpr`, and this
    /// handle reads it through [`OwnMappingSpace::resolve_own_mapping`]. A
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
    #[cfg(feature = "alloc")]
    own_mapping_space: Option<alloc::sync::Arc<dyn OwnMappingSpace + Send + Sync>>,
    /// R231 — this session's own zid prefix (1..=16 bytes),
    /// negotiated during the session-FSM open handshake. When set,
    /// [`dispatch_push`](Self::dispatch_push) suppresses wire-arrived
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
    #[cfg(feature = "alloc")]
    own_zid: Option<alloc::vec::Vec<u8>>,
    /// transport-shm — the AP-injected resolver that maps an inbound SHM
    /// descriptor's segment off /dev/shm (the no_std/std seam; the impl is
    /// `wz-runtime-tokio::shm_provider::PosixShmResolver`). `None` until the AP
    /// bring-up installs it via [`set_shm_resolver`](Self::set_shm_resolver) — an
    /// SHM Put arriving with no resolver installed drops (the marker is honoured,
    /// the descriptor unresolvable). Boxed (not a generic param) so the ~110
    /// registry construction sites keep their inferred `C = BoxedSink`; `Send +
    /// Sync` keeps `ApplicationLayerObserver: Send` (the drive-task boundary).
    #[cfg(feature = "transport-shm")]
    shm_resolver: Option<alloc::boxed::Box<dyn crate::extshm::ShmResolver + Send + Sync>>,
    /// transport-shm — count of SHM Puts dropped because their descriptor could
    /// NOT be resolved (no resolver installed, or a stale / foreign segment). The
    /// drop is silent on the data path (the Sample is discarded), but it is
    /// OBSERVABLE here so a misconfiguration (resolver never installed) is a
    /// readable counter rather than a mystery of vanishing samples
    /// ([`shm_unresolved_drops`](Self::shm_unresolved_drops)).
    #[cfg(feature = "transport-shm")]
    shm_unresolved_drops: u64,
    /// R311y516 (transport-shm) — the LIVE negotiated SHM capability for the
    /// session that feeds this registry, restamped on every dispatch iteration
    /// by [`set_shm_negotiated`](Self::set_shm_negotiated).
    ///
    /// This is the RX-side enforcement gate, and it is the wz counterpart of
    /// zenoh's `if self.config.shm.is_some()` guard around
    /// `map_zmsg_to_shmbuf` (`io/zenoh-transport/src/unicast/universal/rx.rs`
    /// :50-51, the same expression as its `is_shm()` at
    /// `unicast/universal/transport.rs:349-350`). Before R311y516 the wz
    /// un-swap consulted only the body's 0x2 marker, so a peer that had NOT
    /// negotiated SHM could still name a `/dev/shm` segment and have this node
    /// map it — the negotiation was decorative on the receive side.
    ///
    /// Defaults to `false` and is restamped rather than snapshotted on
    /// purpose: `negotiate_shm_against_peer` is a monotonic `&=`, so a
    /// reconnect can only drive the capability DOWN, and a construction-time
    /// snapshot would therefore go stale in the fail-OPEN direction. A
    /// multicast registry is never stamped and so stays fail-closed.
    #[cfg(feature = "transport-shm")]
    shm_negotiated: bool,
    /// transport-shm — count of SHM Puts dropped because the 0x2 marker
    /// arrived on a session that never NEGOTIATED SHM. Distinct from
    /// [`shm_unresolved_drops`](Self::shm_unresolved_drops), which counts a
    /// negotiated-but-unmappable descriptor: this one means the peer sent a
    /// descriptor it had no right to send (or the registry was never stamped),
    /// and the segment was deliberately not opened.
    #[cfg(feature = "transport-shm")]
    shm_unnegotiated_drops: u64,
    /// R311y530 — inbound SUBSCRIBER `Interest`s this session has been told
    /// about, zenoh's per-face `remote-interests` table restricted to the
    /// session-local half. Retired on that interest's `Interest(Final)`.
    ///
    /// Its only consumer is [`Self::respond_to_subscriber_interest_borrowed`],
    /// which needs the interest's OWN keyexpr at DRAIN time to build an
    /// aggregate reply — and a staged reply item cannot carry it (the staging
    /// buffer is an inline array sized to its largest variant, and a
    /// `BoundedString` slot per item is what overflowed a Cortex-M0 stack when
    /// the liveliness twin tried it). So the keyexpr lives here, once, and the
    /// staged item is two `u64`s that resolve through it.
    #[cfg(feature = "declare-subscriber")]
    inbound_sub_interests: BoundedVec<InboundSubInterest, { caps::MAX_INBOUND_SUB_INTERESTS }>,
    /// R311y530 — the staged interest-response chain, drained by
    /// [`Self::take_staged_sub_interest_replies`] through a
    /// [`crate::response_sink::DeclareReplySink`].
    #[cfg(feature = "declare-subscriber")]
    pending_sub_interest_replies: BoundedVec<SubInterestReply, { caps::MAX_PENDING_DECLARES }>,
    /// R311y530 — monotonic source for the wire `DeclSubscriber.id` this
    /// session answers an AGGREGATE interest with. Non-zero and STABLE per
    /// registered interest: pico dedups a filter target by `(peer, decl_id)`
    /// (`net/filtering.c` `_z_filter_target_eq`), so a re-answered interest
    /// must reuse its id rather than stack a second target.
    #[cfg(feature = "declare-subscriber")]
    next_sub_interest_decl_id: u64,
}

/// R311y530 — whether a session-local subscription `pattern` intersects an
/// inbound subscriber-interest `interest` (`None` = the keyexpr-less match-all
/// form). BOTH sides can carry wildcards — the subscription is `demo/**` and
/// the interest is a publisher's concrete `demo/a` in the case that motivated
/// this — so the test is INTERSECTION, not one-sided glob matching.
///
/// Splits into stack chunk views (no heap). A keyexpr deeper than
/// [`MAX_KEYEXPR_CHUNKS`] is treated as non-matching rather than matched
/// truncated, mirroring the sibling registries' conservative rule.
#[cfg(feature = "declare-subscriber")]
fn subscription_matches_interest(pattern: &str, interest: Option<&str>) -> bool {
    let Some(interest) = interest else {
        return true;
    };
    let mut sub_chunks: BoundedVec<&str, MAX_KEYEXPR_CHUNKS> = BoundedVec::new();
    for c in pattern.split('/') {
        if sub_chunks.push(c).is_err() {
            return false;
        }
    }
    let mut interest_chunks: BoundedVec<&str, MAX_KEYEXPR_CHUNKS> = BoundedVec::new();
    for c in interest.split('/') {
        if interest_chunks.push(c).is_err() {
            return false;
        }
    }
    keyexpr_intersect_patterns(&sub_chunks, &interest_chunks)
}

/// R311y530 — one remembered inbound SUBSCRIBER `Interest`.
#[cfg(feature = "declare-subscriber")]
struct InboundSubInterest {
    /// The peer's interest id, echoed on every reply and on the terminating
    /// `DeclFinal` so the peer routes them to this interest.
    interest_id: u64,
    /// The interest's RESOLVED keyexpr — the reply keyexpr when
    /// [`aggregate`](Self::aggregate) is set.
    keyexpr: BoundedString<{ caps::MAX_KEYEXPR_BYTES }>,
    /// The `AGGREGATE` flag off the interest body. Load-bearing, not
    /// informational: an aggregate interest's replies are associated by
    /// `_z_keyexpr_equals` against THIS keyexpr (`session/interest.c:274-276`),
    /// so a reply carrying a concrete subscription keyexpr matches nothing.
    aggregate: bool,
    /// The `DeclSubscriber.id` this session answers this interest with when the
    /// reply is aggregate (see `next_sub_interest_decl_id`).
    aggregate_decl_id: u64,
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
}

impl<C: SampleSink> Default for SubscriberRegistry<C> {
    fn default() -> Self {
        Self::with_sink_backing()
    }
}

impl<C: SampleSink> SubscriberRegistry<C> {
    /// New empty registry over an explicit sink backing `C`. Subscriber
    /// ids start at 1 so 0 stays available as a sentinel "no
    /// subscription" value for any caller-side wrapper that needs one.
    ///
    /// R311gb-2b — the generic constructor (the no-`alloc` / MCU entry
    /// point, paired with [`register_sink`](Self::register_sink)). AP
    /// callers use the inferring [`new`](SubscriberRegistry::new)
    /// shorthand, which fixes `C = BoxedSink`; this mirrors the std
    /// `HashMap::new` (default hasher) vs `with_hasher` split, so a bare
    /// `SubscriberRegistry::new()` resolves its type parameter without a
    /// turbofish.
    pub fn with_sink_backing() -> Self {
        Self {
            subscribers: BoundedVec::new(),
            next_id: 1,
            #[cfg(feature = "alloc")]
            peer_keyexpr_table: HashMap::new(),
            #[cfg(feature = "alloc")]
            own_mapping_space: None,
            #[cfg(feature = "alloc")]
            own_zid: None,
            #[cfg(feature = "transport-shm")]
            shm_resolver: None,
            #[cfg(feature = "transport-shm")]
            shm_unresolved_drops: 0,
            #[cfg(feature = "transport-shm")]
            shm_negotiated: false,
            #[cfg(feature = "transport-shm")]
            shm_unnegotiated_drops: 0,
            #[cfg(feature = "declare-subscriber")]
            inbound_sub_interests: BoundedVec::new(),
            #[cfg(feature = "declare-subscriber")]
            pending_sub_interest_replies: BoundedVec::new(),
            // Starts at 1: id 0 is zenoh's "current dump, no future id"
            // (`make_sub_id`), and reusing it here would collide with that.
            #[cfg(feature = "declare-subscriber")]
            next_sub_interest_decl_id: 1,
        }
    }

    /// R231 — install this session's own zid (1..=16 bytes) so
    /// [`dispatch_push`](Self::dispatch_push) can recognise and
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
    #[cfg(feature = "alloc")]
    pub fn set_own_zid(&mut self, zid: alloc::vec::Vec<u8>) -> bool {
        if !(1..=16).contains(&zid.len()) {
            return false;
        }
        self.own_zid = Some(zid);
        true
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
        self.shm_resolver = Some(resolver);
    }

    /// transport-shm — the number of SHM Puts dropped because their descriptor
    /// could not be resolved (no resolver installed, or a stale / foreign
    /// segment). A non-zero value at steady state usually means the AP forgot to
    /// [`set_shm_resolver`](Self::set_shm_resolver).
    #[cfg(feature = "transport-shm")]
    pub fn shm_unresolved_drops(&self) -> u64 {
        self.shm_unresolved_drops
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
        self.shm_negotiated = negotiated;
    }

    /// R311y516 (transport-shm) — whether the RX un-swap will currently honour
    /// an inbound 0x2 SHM marker on this registry.
    #[cfg(feature = "transport-shm")]
    pub fn shm_negotiated(&self) -> bool {
        self.shm_negotiated
    }

    /// R311y516 (transport-shm) — the number of SHM Puts dropped because the
    /// 0x2 marker arrived on a session that never NEGOTIATED SHM. A non-zero
    /// value means a peer named a segment it had no right to name (or, on a
    /// custom drive loop, that the registry is never stamped).
    #[cfg(feature = "transport-shm")]
    pub fn shm_unnegotiated_drops(&self) -> u64 {
        self.shm_unnegotiated_drops
    }

    /// R231 — release the previously-installed own zid (e.g. on
    /// session close or re-init). Subsequent dispatches behave as
    /// if `set_own_zid` had never been called: no self-echo dedup,
    /// every wire-arrived Push fires its matching subscribers.
    #[cfg(feature = "alloc")]
    pub fn clear_own_zid(&mut self) {
        self.own_zid = None;
    }

    /// R231 — expose the currently-installed own zid for diagnostic
    /// and test purposes. Returns the same slice that
    /// [`dispatch_push`](Self::dispatch_push) compares against
    /// `source_info.zid_prefix()`.
    #[cfg(feature = "alloc")]
    pub fn own_zid(&self) -> Option<&[u8]> {
        self.own_zid.as_deref()
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
    /// is stored unchanged and a `log::warn!` is emitted — this is
    /// non-breaking with prior callers; promotion to a Result-
    /// returning signature is deferred to the cluster API rewrite.
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
        let pattern: BoundedString<{ caps::MAX_KEYEXPR_BYTES }> =
            match crate::keyexpr_canon::canonize_keyexpr(keyexpr_pattern) {
                Ok(canon) => canon,
                Err(crate::keyexpr_canon::KeyexprCanonError::ExceedsCapacity) => {
                    return Err(RegisterError::KeyexprTooLong);
                }
                Err(err) => {
                    log::warn!(
                        "SubscriberRegistry::register: keyexpr `{keyexpr_pattern}` is not \
                         canonical ({err}); storing raw form. The matcher still operates but \
                         the stored chunks may drift from the canonical form a peer emits."
                    );
                    let mut raw = BoundedString::new();
                    raw.push_str(keyexpr_pattern)
                        .map_err(|_| RegisterError::KeyexprTooLong)?;
                    raw
                }
            };
        let id = SubscriptionId(self.next_id);
        // Push first; only consume the id counter on success so a
        // rejected (table-full) registration leaves no id gap.
        self.subscribers
            .push(Subscriber {
                id,
                pattern,
                allowed_origin,
                sink,
            })
            .map_err(|_| RegisterError::TableFull)?;
        self.next_id = self.next_id.saturating_add(1);
        // R311y530 — pub-before-sub: a remote publisher that already registered
        // a FUTURE subscriber interest is told about THIS subscription now.
        // Placed here, on the single table-insert path, rather than in the
        // callers: `register` / `register_with_locality` both funnel through
        // this method, so no declare route can skip the push.
        #[cfg(feature = "declare-subscriber")]
        self.stage_future_subscriber_pushes(id.0);
        Ok(id)
    }

    /// Remove a previously-registered subscriber. Returns `true` if
    /// the id was found and removed. Idempotent — calling on an id
    /// that was never registered or already removed returns `false`
    /// without panicking.
    pub fn unregister(&mut self, id: SubscriptionId) -> bool {
        let before = self.subscribers.len();
        self.subscribers.retain(|s| s.id != id);
        before != self.subscribers.len()
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

    /// R121j-5c — borrow the peer keyexpr alias table for cross-
    /// registry use. The `QueryableRegistry` (wz-runtime-tokio)
    /// resolves inbound `Request(Query)` keyexpr through the same
    /// peer mapping that the subscriber side populated via
    /// [`absorb_declare`](Self::absorb_declare) on inbound
    /// `Declare(DeclKexpr|UndeclKexpr)`. Lending the table by
    /// reference avoids dual-write bookkeeping (one DECLARE absorbed
    /// once, observed by both registries) without requiring
    /// `Arc<Mutex<…>>` shared state.
    #[cfg(feature = "alloc")]
    pub fn peer_keyexpr_table(&self) -> &HashMap<u64, String> {
        &self.peer_keyexpr_table
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
    #[cfg(feature = "alloc")]
    pub fn set_own_mapping_space(
        &mut self,
        space: alloc::sync::Arc<dyn OwnMappingSpace + Send + Sync>,
    ) {
        self.own_mapping_space = Some(space);
    }

    /// R311y739 — release the installed own space; `M=0` aliases refuse again.
    /// Paired with [`set_own_mapping_space`](Self::set_own_mapping_space) for
    /// session teardown / re-init, exactly as `clear_own_zid` pairs its install.
    #[cfg(feature = "alloc")]
    pub fn clear_own_mapping_space(&mut self) {
        self.own_mapping_space = None;
    }

    /// R311y739 — BOTH id spaces, for this registry and for every consumer the
    /// observer fans the table into.
    ///
    /// This is the accessor the fan should use rather than
    /// [`peer_keyexpr_table`](Self::peer_keyexpr_table): handing a consumer the
    /// bare peer table hands it a resolver that silently refuses every `M=0`
    /// alias, which is the defect R311y739 exists to remove. The peer table
    /// accessor survives for the one caller that genuinely needs the raw map —
    /// a `DeclKexpr` absorb binds INTO the peer's space and into no other.
    #[cfg(feature = "alloc")]
    pub fn mapping_spaces(&self) -> MappingSpaces<'_> {
        match &self.own_mapping_space {
            Some(own) => MappingSpaces::with_own(&self.peer_keyexpr_table, &**own),
            None => MappingSpaces::peer_only(&self.peer_keyexpr_table),
        }
    }

    /// R237 — single-id resolver mirroring R234
    /// `SessionLinkActions::resolve_outbound_mapping` (wz-runtime-tokio).
    /// Returns the literal keyexpr the peer declared for `id`, or
    /// `None` if no `DeclKexpr` for `id` has arrived (or an
    /// `UndeclKexpr` retracted it).
    ///
    /// The full [`Self::peer_keyexpr_table`] accessor remains for
    /// cross-registry borrow (the canonical zero-clone path used by
    /// `QueryableRegistry` and other in-process observers); this
    /// single-id form is the ergonomic application-facing surface for
    /// callers that only need one resolution per call site and
    /// prefer an owned `String` over keeping the registry borrow
    /// live. Mirrors zenoh-pico's `_z_get_resource_by_id` lookup on
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
    pub fn resolve_inbound_mapping(&self, id: u64) -> Option<String> {
        self.peer_keyexpr_table.get(&id).cloned()
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
    #[cfg(feature = "alloc")]
    pub fn dispatch_iteration_event(&mut self, event: IterationEvent<'_>) {
        if let IterationEvent::Poll(DriverLoopOutcome::FramePayload {
            messages, reliable, ..
        }) = event
        {
            let reliability = Reliability::from_reliable_bool(*reliable);
            for message in messages {
                self.dispatch(message, reliability);
            }
        }
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
    #[cfg(feature = "alloc")]
    pub fn dispatch(&mut self, message: &NetworkMessage, _reliability: Reliability) {
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
            NetworkMessage::Push(push) => self.dispatch_push(push, reliability, true),
            #[cfg(feature = "codec-declare")]
            NetworkMessage::Declare(decl) => self.absorb_declare(&decl.body),
            // R311y530 — a remote publisher's SUBSCRIBER Interest. Answered
            // from this session's OWN subscriptions; see
            // [`Self::respond_to_subscriber_interest`].
            #[cfg(feature = "declare-subscriber")]
            NetworkMessage::Interest(interest) => self.respond_to_subscriber_interest(interest),
            _ => {}
        }
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
    #[cfg(all(feature = "alloc", feature = "declare-subscriber"))]
    fn respond_to_subscriber_interest(&mut self, interest: &InterestOwned) {
        let interest_id = interest.interest_id;
        let (current, future) = (interest.c(), interest.f());
        let Some(body) = interest.body.as_ref() else {
            // No body and neither bit set is zenoh's interest FINAL: the peer
            // is CANCELLING `interest_id` (pico emits exactly this when a
            // declared publisher drops, `net/primitives.c`). Retire the row so
            // a recycled id cannot inherit a dead publisher's keyexpr.
            if !current && !future {
                self.inbound_sub_interests
                    .retain(|row| row.interest_id != interest_id);
            }
            return;
        };
        if !body.su() {
            // A queryable / token interest — the query and liveliness planes
            // answer those; this registry holds neither.
            return;
        }
        let pattern: Option<String> = match &body.keyexpr {
            Some(w) => match resolve_wireexpr_in(&w.body, self.mapping_spaces()) {
                Some(p) => Some(p),
                None => return,
            },
            None => None,
        };
        self.respond_to_subscriber_interest_borrowed(
            interest_id,
            pattern.as_deref(),
            body.ag(),
            current,
            future,
        );
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
    ///   pushed to that publisher ([`Self::stage_future_subscriber_pushes`]).
    ///
    /// The terminating `Final` is staged even with zero replies: a peer whose
    /// CURRENT interest is never terminated keeps the solicitation open, and
    /// "no matching subscriber" is a legitimate answer (its filter correctly
    /// stays ACTIVE and it does not put).
    ///
    /// Returns the number of reply items staged (the `Final` is not counted).
    #[cfg(feature = "declare-subscriber")]
    pub fn respond_to_subscriber_interest_borrowed(
        &mut self,
        interest_id: u64,
        pattern: Option<&str>,
        aggregate: bool,
        current: bool,
        future: bool,
    ) -> usize {
        if !current && !future {
            // Interest FINAL — a cancellation, not a solicitation.
            self.inbound_sub_interests
                .retain(|row| row.interest_id != interest_id);
            return 0;
        }
        // Register (or refresh) the row FIRST: the CURRENT dump's aggregate
        // reply resolves its keyexpr and its decl id THROUGH this row at drain,
        // so a CURRENT-only interest needs it too. Refreshing rather than
        // stacking keeps pico's `(peer, decl_id)` target dedup meaningful.
        let decl_id = match self
            .inbound_sub_interests
            .iter()
            .position(|row| row.interest_id == interest_id)
        {
            Some(idx) => self.inbound_sub_interests[idx].aggregate_decl_id,
            None => {
                let mut keyexpr = BoundedString::new();
                if keyexpr.push_str(pattern.unwrap_or("**")).is_err() {
                    // A keyexpr past the bounded field cannot be replied with
                    // anyway; terminate the chain honestly instead of half-
                    // answering it.
                    let _ = self
                        .pending_sub_interest_replies
                        .push(SubInterestReply::Final { interest_id });
                    return 0;
                }
                let decl_id = self.next_sub_interest_decl_id;
                self.next_sub_interest_decl_id = decl_id.saturating_add(1);
                // A full table loses only the FUTURE half for this publisher —
                // the CURRENT dump below still answers, because it reads the
                // row we would have pushed only for the aggregate keyexpr, and
                // the push failure hands that keyexpr straight back.
                let _ = self.inbound_sub_interests.push(InboundSubInterest {
                    interest_id,
                    keyexpr,
                    aggregate,
                    aggregate_decl_id: decl_id,
                });
                decl_id
            }
        };
        let _ = decl_id;
        let mut staged = 0usize;
        if current {
            if aggregate {
                if self.any_subscription_matches(pattern)
                    && self
                        .pending_sub_interest_replies
                        .push(SubInterestReply::Aggregate { interest_id })
                        .is_ok()
                {
                    staged += 1;
                }
            } else {
                for sub in self.subscribers.iter() {
                    if !subscription_matches_interest(sub.pattern.as_str(), pattern) {
                        continue;
                    }
                    if self
                        .pending_sub_interest_replies
                        .push(SubInterestReply::Concrete {
                            interest_id,
                            subscription_id: sub.id.0,
                        })
                        .is_err()
                    {
                        break;
                    }
                    staged += 1;
                }
            }
            let _ = self
                .pending_sub_interest_replies
                .push(SubInterestReply::Final { interest_id });
        }
        staged
    }

    /// R311y530 — whether ANY session-local subscription intersects the
    /// interest `pattern` (`None` = match-all).
    #[cfg(feature = "declare-subscriber")]
    fn any_subscription_matches(&self, pattern: Option<&str>) -> bool {
        self.subscribers
            .iter()
            .any(|sub| subscription_matches_interest(sub.pattern.as_str(), pattern))
    }

    /// R311y530 — stage an unsolicited `DeclSubscriber` for a subscription
    /// declared AFTER a remote publisher registered its FUTURE interest: the
    /// pub-before-sub half of the write-filter release.
    ///
    /// Without it the ordering decides whether a publisher ever sees the
    /// subscriber, which is exactly the kind of race that reads as a flaky
    /// interop test. Called from [`Self::register_sink`] so no declare path can
    /// forget it.
    #[cfg(feature = "declare-subscriber")]
    fn stage_future_subscriber_pushes(&mut self, new_id: u64) {
        let mut hits: BoundedVec<(u64, bool), { caps::MAX_INBOUND_SUB_INTERESTS }> =
            BoundedVec::new();
        {
            // The new subscription's pattern is read back out of the table
            // rather than passed in: `register_sink` has already MOVED it into
            // the row, and `BoundedString` is deliberately not `Clone` (the
            // no-alloc backing is an inline buffer). Both borrows are immutable
            // and end with this block, before the staging push below.
            let Some(sub) = self.subscribers.iter().find(|s| s.id.0 == new_id) else {
                return;
            };
            let new_pattern = sub.pattern.as_str();
            for row in self.inbound_sub_interests.iter() {
                if subscription_matches_interest(new_pattern, Some(row.keyexpr.as_str()))
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
                    subscription_id: new_id,
                }
            };
            // NO terminating `Final` here: this is an unsolicited FUTURE push,
            // not a CURRENT dump, and the peer's CURRENT solicitation was
            // already resolved when the interest arrived. A second `Final`
            // would close an interest that is still live.
            let _ = self.pending_sub_interest_replies.push(item);
        }
    }

    /// R311y530 — take the staged interest-response chain for the drain.
    /// Paired with [`Self::sub_interest_reply`], which resolves each item to
    /// its `(DeclSubscriber.id, reply keyexpr)` against the tables that own
    /// them.
    #[cfg(feature = "declare-subscriber")]
    pub fn take_staged_sub_interest_replies(
        &mut self,
    ) -> BoundedVec<SubInterestReply, { caps::MAX_PENDING_DECLARES }> {
        core::mem::take(&mut self.pending_sub_interest_replies)
    }

    /// R311y530 — resolve one staged reply item to the `(subscriber_id,
    /// keyexpr)` pair the sink encodes. `None` when the backing row vanished
    /// between stage and drain (an interest cancelled, or a subscription
    /// dropped): that reply is skipped and its chain's `Final` still
    /// terminates the peer's solicitation.
    #[cfg(feature = "declare-subscriber")]
    pub fn sub_interest_reply(&self, item: &SubInterestReply) -> Option<(u64, &str)> {
        match item {
            SubInterestReply::Aggregate { interest_id } => self
                .inbound_sub_interests
                .iter()
                .find(|row| row.interest_id == *interest_id)
                .map(|row| (row.aggregate_decl_id, row.keyexpr.as_str())),
            SubInterestReply::Concrete {
                subscription_id, ..
            } => self
                .subscribers
                .iter()
                .find(|sub| sub.id.0 == *subscription_id)
                .map(|sub| (sub.id.0, sub.pattern.as_str())),
            SubInterestReply::Final { .. } => None,
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
    fn dispatch_push(&mut self, push: &PushOwned, reliability: Reliability, is_remote: bool) {
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
        let resolved: String = match resolve_wireexpr_in(&push.keyexpr.body, self.mapping_spaces())
        {
            Some(r) => r,
            None => return,
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
                    let body_exts: &[wz_codecs::ext_entry::ExtEntryOwned] =
                        put.extensions.as_deref().unwrap_or(&[]);
                    #[cfg(feature = "pubsub-timestamp")]
                    let body_timestamp = put.timestamp.as_ref().map(TimestampHint::from_codec);
                    #[cfg(not(feature = "pubsub-timestamp"))]
                    let body_timestamp: Option<TimestampHint> = None;
                    #[cfg(feature = "pubsub-attachment")]
                    let body_attachment = decode_attachment_ext(body_exts, ATTACHMENT_EXT_ID_PUSH)
                        .map(<[u8]>::to_vec);
                    #[cfg(not(feature = "pubsub-attachment"))]
                    let body_attachment: Option<alloc::vec::Vec<u8>> = {
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
                    #[cfg(feature = "transport-shm")]
                    let put_payload = if crate::extshm::body_has_shm_marker(body_exts) {
                        // R311y516 — ENFORCE the negotiation before opening
                        // anything. zenoh gates its whole RX un-swap on the
                        // negotiated per-transport capability
                        // (`if self.config.shm.is_some() {
                        // map_zmsg_to_shmbuf(..) }`,
                        // io/zenoh-transport/src/unicast/universal/rx.rs:50-51 —
                        // literally the expression behind its `is_shm()`,
                        // unicast/universal/transport.rs:349-350). wz honoured
                        // only the body's 0x2 marker, so a peer that never
                        // negotiated SHM could name a /dev/shm segment and have
                        // this node map it. Drop + COUNT instead: delivering the
                        // raw descriptor bytes as if they were the payload would
                        // hand the application 8 bytes of struct in place of its
                        // data, which is worse than a counted drop.
                        if !self.shm_negotiated {
                            self.shm_unnegotiated_drops += 1;
                            return;
                        }
                        match crate::extshm::decode_shm_descriptor(put.payload.as_slice())
                            .and_then(|d| self.shm_resolver.as_ref().and_then(|r| r.resolve(&d)))
                        {
                            Some(bytes) => bytes,
                            None => {
                                // Unresolvable descriptor (no resolver, or a stale
                                // / foreign segment): drop the Sample, but COUNT it
                                // so the misconfiguration is observable.
                                self.shm_unresolved_drops += 1;
                                return;
                            }
                        }
                    } else {
                        put.payload.as_slice().to_vec()
                    };
                    #[cfg(not(feature = "transport-shm"))]
                    let put_payload = put.payload.as_slice().to_vec();
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
                    let body_exts: &[wz_codecs::ext_entry::ExtEntryOwned] =
                        del.extensions.as_deref().unwrap_or(&[]);
                    #[cfg(feature = "pubsub-timestamp")]
                    let body_timestamp = del.timestamp.as_ref().map(TimestampHint::from_codec);
                    #[cfg(not(feature = "pubsub-timestamp"))]
                    let body_timestamp: Option<TimestampHint> = None;
                    #[cfg(feature = "pubsub-attachment")]
                    let body_attachment = decode_attachment_ext(body_exts, ATTACHMENT_EXT_ID_PUSH)
                        .map(<[u8]>::to_vec);
                    #[cfg(not(feature = "pubsub-attachment"))]
                    let body_attachment: Option<alloc::vec::Vec<u8>> = {
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
                        alloc::vec::Vec::new(),
                        body_timestamp,
                        None,
                        body_attachment,
                        body_source_info,
                    )
                }
                _ => return,
            };
        let outer_exts: &[wz_codecs::ext_entry::ExtEntryOwned] =
            push.extensions.as_deref().unwrap_or(&[]);
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
            SampleKind::Put => Sample::new_put(resolved, payload),
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
        if let Some(att) = body_attachment {
            sample = sample.with_attachment(att);
        }
        if let Some(si) = body_source_info {
            sample = sample.with_source_info(si);
        }
        sample = sample.with_reliability(reliability);

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
            if let (Some(own), Some(info)) = (self.own_zid.as_deref(), sample.source_info.as_ref())
            {
                let prefix = info.zid_prefix();
                if !prefix.is_empty() && prefix == own {
                    return;
                }
            }
        }

        self.fire_to_subscribers(&sample, is_remote);
    }

    /// Apply the locality filter + keyexpr pattern match against every
    /// registered subscriber and fire the callbacks that pass. Returns
    /// the count of callbacks that fired so loopback callers can
    /// verify delivery (the wire-path caller discards the count).
    ///
    /// R227 — the single source of truth for subscriber filtering.
    /// Both [`dispatch_push`](Self::dispatch_push) (wire path) and
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
    /// ([`dispatch_push`](Self::dispatch_push)) funnels its owned
    /// `Sample` through the same matcher via the `Sample: SampleView`
    /// coercion (one matching SSOT). Returns the count of sinks fired.
    pub fn dispatch_borrowed(&mut self, view: &dyn SampleView, is_remote: bool) -> usize {
        self.fire_to_subscribers(view, is_remote)
    }

    fn fire_to_subscribers(&mut self, view: &dyn SampleView, is_remote: bool) -> usize {
        let mut fired: usize = 0;
        let keyexpr = view.keyexpr();
        for subscriber in self.subscribers.iter_mut() {
            let pass = if is_remote {
                subscriber.allowed_origin.allows_remote()
            } else {
                subscriber.allowed_origin.allows_local()
            };
            if !pass {
                continue;
            }
            // Split the bounded pattern into a stack chunk view. On the
            // no-alloc backing `BoundedVec` is heapless-backed (no heap);
            // the canon stored at register time already bounds the chunk
            // count to `MAX_KEYEXPR_CHUNKS`, so the push is infallible in
            // practice — skip defensively on overflow rather than match a
            // truncated pattern.
            let mut chunks: BoundedVec<&str, MAX_KEYEXPR_CHUNKS> = BoundedVec::new();
            let mut overflow = false;
            for c in subscriber.pattern.split('/') {
                if chunks.push(c).is_err() {
                    overflow = true;
                    break;
                }
            }
            if overflow {
                continue;
            }
            if keyexpr_pattern_matches(&chunks, keyexpr) {
                // R311gb-2b — deliver via the DIP seam (borrowed view,
                // no projection step). On MCU `C` is a closed `enum`
                // whose `deliver` injects; on AP a `BoxedSink` closure.
                subscriber.sink.deliver(view);
                fired = fired.saturating_add(1);
            }
        }
        fired
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
        self.fire_to_subscribers(sample, false)
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
    /// the `alloc`-gated `peer_keyexpr_table` via the `alloc`
    /// `resolve_wireexpr`, so a `codec-declare`-without-`alloc` profile
    /// elides it (its sole caller `dispatch` is already `alloc`-gated).
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    fn absorb_declare(&mut self, body: &DeclareOwnedVariant) {
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
                let literal = resolve_wireexpr_in(&d.keyexpr.body, self.mapping_spaces());
                if let Some(literal) = literal {
                    self.peer_keyexpr_table.insert(d.id, literal);
                }
            }
            DeclareOwnedVariant::CodecZenohUndeclKexpr(u) => {
                self.peer_keyexpr_table.remove(&u.id);
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
    /// the [`feedback_signature_stability`] wire-data principled
    /// exemption, taken so one registry backs both heap and no-heap
    /// profiles). The closure is heap-boxed via [`BoxedSink`].
    ///
    /// R223 — defaults [`Locality::Any`](crate::locality::Locality)
    /// so both session-local and remote-origin samples fire the
    /// closure. Use [`register_with_locality`](Self::register_with_locality)
    /// to restrict to one origin class.
    pub fn register(
        &mut self,
        keyexpr_pattern: impl Into<String>,
        callback: impl FnMut(&dyn SampleView) + Send + 'static,
    ) -> SubscriptionId {
        self.register_with_locality(keyexpr_pattern, crate::locality::Locality::Any, callback)
    }

    /// R223 — variant of [`register`](Self::register) that pins the
    /// locality filter explicitly. Stores `allowed_origin` on the
    /// subscriber record; [`dispatch_push`](Self::dispatch_push)
    /// consults the filter before firing the closure.
    ///
    /// wz today treats every Push reaching `dispatch_push` as
    /// remote (no self-publish loopback). So a
    /// [`Locality::SessionLocal`](crate::locality::Locality)
    /// subscription registered now will not fire until a future
    /// round wires up loopback; this is the correct
    /// surface-mirrors-zenoh-pico shape, not a bug.
    pub fn register_with_locality(
        &mut self,
        keyexpr_pattern: impl Into<String>,
        allowed_origin: crate::locality::Locality,
        callback: impl FnMut(&dyn SampleView) + Send + 'static,
    ) -> SubscriptionId {
        let pattern = keyexpr_pattern.into();
        // AP backing: `register_sink` is infallible here (the BoundedVec
        // table + BoundedString pattern grow past the advisory `N`), so
        // the convenience wrapper keeps its `SubscriptionId` signature.
        self.register_sink(&pattern, allowed_origin, BoxedSink::new(callback))
            .expect("register on the alloc backing never exceeds declared capacity")
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
    use wz_codecs::push::Push;
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_local::WireexprLocal;

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
                    suffix: Some(suffix),
                }),
            },
            ..Push::default()
        }
        .try_into_owned()
        .unwrap()
    }

    /// A Del-bodied Push for `suffix`. Constructible regardless of
    /// `pubsub-delete` (same reason as [`push_with_keyexpr`]).
    pub(super) fn push_with_del_body(suffix: &str) -> PushOwned {
        let mut push = push_with_keyexpr(suffix);
        push.body = PushOwnedVariant::CodecZenohMsgDel(
            wz_codecs::msg_del::MsgDel::default()
                .try_into_owned()
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
    use wz_codecs::push::Push;
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;

    #[test]
    fn dispatch_fires_callback_on_matching_keyexpr() {
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let _id = registry.register("topic/a", move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        let push = push_with_keyexpr("topic/a");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "matching keyexpr fires the callback exactly once"
        );
    }

    #[test]
    fn dispatch_skips_callback_on_non_matching_keyexpr() {
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let _id = registry.register("topic/a", move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        registry.register("topic/a", move |_push| {
            log1.lock().unwrap().push("first");
        });
        let log2 = log.clone();
        registry.register("topic/a", move |_push| {
            log2.lock().unwrap().push("second");
        });
        let log3 = log.clone();
        registry.register("topic/b", move |_push| {
            log3.lock().unwrap().push("other");
        });

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
        registry.register("topic/a", move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        .try_into_owned()
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
        registry.register("topic/a", move |sample| {
            *captured_clone.lock().unwrap() = Some(sample.reliability());
        });
        let push = push_with_keyexpr("topic/a");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
        assert_eq!(*captured.lock().unwrap(), Some(Reliability::Reliable));
    }

    #[test]
    fn dispatch_best_effort_records_best_effort_on_sample() {
        let mut registry = SubscriberRegistry::new();
        let captured = Arc::new(std::sync::Mutex::new(None::<Reliability>));
        let captured_clone = captured.clone();
        registry.register("topic/a", move |sample| {
            *captured_clone.lock().unwrap() = Some(sample.reliability());
        });
        let push = push_with_keyexpr("topic/a");
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push)),
            Reliability::BestEffort,
        );
        assert_eq!(*captured.lock().unwrap(), Some(Reliability::BestEffort));
    }

    #[test]
    fn dispatch_iteration_event_projects_frame_reliable_bool_to_sample() {
        use crate::driver_loop::IterationEvent;
        let mut registry = SubscriberRegistry::new();
        let captured = Arc::new(std::sync::Mutex::new(None::<Reliability>));
        let captured_clone = captured.clone();
        registry.register("topic/a", move |sample| {
            *captured_clone.lock().unwrap() = Some(sample.reliability());
        });
        let push = push_with_keyexpr("topic/a");
        let outcome = DriverLoopOutcome::FramePayload {
            priority: crate::qos::Priority::DEFAULT,
            reliable: false,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(push))],
            has_ext: false,
            extensions: Vec::new(),
        };
        registry.dispatch_iteration_event(IterationEvent::Poll(&outcome));
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
        registry.register("topic/a", move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        // R98 scope routes Push only. ResponseFinal (or any other
        // variant) flowing through dispatch must not invoke any
        // subscriber callback.
        use wz_codecs::response_final::ResponseFinal;
        registry.dispatch(
            &NetworkMessage::ResponseFinal(ResponseFinal::default().try_into_owned().unwrap()),
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
    fn keyexpr_pattern_matches_literal_equality() {
        assert!(keyexpr_pattern_matches(&["home", "temp"], "home/temp"));
        assert!(!keyexpr_pattern_matches(&["home", "temp"], "home/humid"));
        assert!(!keyexpr_pattern_matches(&["home"], "home/temp"));
        assert!(!keyexpr_pattern_matches(&["home", "temp"], "home"));
    }

    #[test]
    fn keyexpr_pattern_matches_single_chunk_wildcard() {
        // `*` matches exactly one chunk.
        assert!(keyexpr_pattern_matches(
            &["home", "*", "temp"],
            "home/kitchen/temp"
        ));
        assert!(keyexpr_pattern_matches(
            &["home", "*", "temp"],
            "home/bedroom/temp"
        ));
        // The wildcard does NOT match zero chunks.
        assert!(!keyexpr_pattern_matches(
            &["home", "*", "temp"],
            "home/temp"
        ));
        // The wildcard does NOT span chunk boundaries.
        assert!(!keyexpr_pattern_matches(
            &["home", "*", "temp"],
            "home/kitchen/sub/temp"
        ));
    }

    #[test]
    fn keyexpr_pattern_matches_double_star_zero_or_more() {
        // `**` matches zero chunks.
        assert!(keyexpr_pattern_matches(&["home", "**"], "home"));
        // `**` matches one chunk.
        assert!(keyexpr_pattern_matches(&["home", "**"], "home/temp"));
        // `**` matches many chunks.
        assert!(keyexpr_pattern_matches(
            &["home", "**"],
            "home/kitchen/temp/c"
        ));
        // `**` at the prefix.
        assert!(keyexpr_pattern_matches(
            &["**", "temp"],
            "home/kitchen/temp"
        ));
        assert!(keyexpr_pattern_matches(&["**", "temp"], "temp"));
        // `**` in the middle.
        assert!(keyexpr_pattern_matches(
            &["home", "**", "temp"],
            "home/temp"
        ));
        assert!(keyexpr_pattern_matches(
            &["home", "**", "temp"],
            "home/kitchen/temp"
        ));
        assert!(keyexpr_pattern_matches(
            &["home", "**", "temp"],
            "home/a/b/c/temp"
        ));
        // Negative: literal suffix must still align.
        assert!(!keyexpr_pattern_matches(
            &["home", "**", "temp"],
            "home/kitchen/humid"
        ));
    }

    // ── R220 `$*` intra-chunk DSL matcher behaviour ──

    #[test]
    fn keyexpr_pattern_matches_dsl_prefix_suffix_anchors() {
        // `prefix$*suffix` anchors both ends: target must start with
        // "sensor_" and end with "_temp", with any (possibly empty)
        // bytes in between within the same chunk.
        assert!(keyexpr_pattern_matches(
            &["sensor_$*_temp"],
            "sensor_room1_temp"
        ));
        assert!(keyexpr_pattern_matches(&["sensor_$*_temp"], "sensor__temp"));
        // Missing the required suffix → no match.
        assert!(!keyexpr_pattern_matches(
            &["sensor_$*_temp"],
            "sensor_room1_humid"
        ));
        // Missing the required prefix → no match.
        assert!(!keyexpr_pattern_matches(
            &["sensor_$*_temp"],
            "device_room1_temp"
        ));
    }

    #[test]
    fn keyexpr_pattern_matches_dsl_leading_only_floats_prefix() {
        // `$*foo` lets the leading sub-part float; target need only
        // end with "foo".
        assert!(keyexpr_pattern_matches(&["$*foo"], "barfoo"));
        assert!(keyexpr_pattern_matches(&["$*foo"], "foo"));
        // Target lacks the required suffix.
        assert!(!keyexpr_pattern_matches(&["$*foo"], "barfo"));
    }

    #[test]
    fn keyexpr_pattern_matches_dsl_trailing_only_floats_suffix() {
        // `foo$*` lets the trailing sub-part float; target need only
        // start with "foo".
        assert!(keyexpr_pattern_matches(&["foo$*"], "foobar"));
        assert!(keyexpr_pattern_matches(&["foo$*"], "foo"));
        // Target lacks the required prefix.
        assert!(!keyexpr_pattern_matches(&["foo$*"], "fobar"));
    }

    #[test]
    fn keyexpr_pattern_matches_dsl_multiple_dsl_in_order() {
        // Multiple `$*` in one chunk anchor sub-parts in order
        // without overlap, mirroring zenoh-pico's
        // _z_chunk_right_contains_all_stardsl_subchunks_of_left.
        assert!(keyexpr_pattern_matches(&["$*aa$*bb$*"], "xxaaYYbbZZ"));
        // The order is enforced: "bb" before "aa" must not match.
        assert!(!keyexpr_pattern_matches(&["$*aa$*bb$*"], "xxbbYYaaZZ"));
        // Overlap is rejected: two non-overlapping "foo" needed.
        assert!(keyexpr_pattern_matches(&["$*foo$*foo$*"], "foofoo"));
        assert!(!keyexpr_pattern_matches(&["$*foo$*foo$*"], "foofo"));
    }

    #[test]
    fn keyexpr_pattern_matches_dsl_does_not_cross_chunk_boundary() {
        // `foo$*bar` is bounded by the same `/` separator the pattern
        // chunk is, so the matching content for `$*` cannot span
        // across chunks. The target chunk that aligns with the
        // pattern chunk is `foobaz`; the next pattern chunk is `bar`
        // which must align with the next target chunk independently.
        assert!(!keyexpr_pattern_matches(
            &["home", "foo$*bar"],
            "home/foobaz/bar"
        ));
        // Same chunk → match.
        assert!(keyexpr_pattern_matches(
            &["home", "foo$*bar"],
            "home/foobazbar"
        ));
    }

    #[test]
    fn keyexpr_pattern_matches_dsl_chunk_alone_acts_like_single_star() {
        // A non-canonical `$*`-only chunk behaves like `*`: any
        // single-chunk target content matches at the matcher level.
        // After R221 the registry call sites canonicalize on register
        // so a registered `home/$*/temp` is stored as
        // `["home", "*", "temp"]`; this test exercises the matcher
        // directly with the pre-canonical shape to document the
        // matcher's own fallback semantics for non-canonical input.
        assert!(keyexpr_pattern_matches(
            &["home", "$*", "temp"],
            "home/kitchen/temp"
        ));
        assert!(keyexpr_pattern_matches(
            &["home", "$*", "temp"],
            "home/x/temp"
        ));
        // Still does not span chunk boundaries.
        assert!(!keyexpr_pattern_matches(
            &["home", "$*", "temp"],
            "home/a/b/temp"
        ));
        // Still does not collapse to zero chunks.
        assert!(!keyexpr_pattern_matches(
            &["home", "$*", "temp"],
            "home/temp"
        ));
    }

    #[test]
    fn keyexpr_pattern_matches_dsl_combines_with_double_star() {
        // `**` traversal and intra-chunk `$*` interact orthogonally:
        // `**` consumes whole chunks, `$*` consumes intra-chunk
        // substrings within a single chunk.
        assert!(keyexpr_pattern_matches(
            &["sensors", "**", "id_$*"],
            "sensors/room1/sub1/id_42"
        ));
        assert!(keyexpr_pattern_matches(
            &["sensors", "**", "id_$*"],
            "sensors/id_42"
        ));
        // The literal in the DSL chunk must still align.
        assert!(!keyexpr_pattern_matches(
            &["sensors", "**", "id_$*"],
            "sensors/room1/value_42"
        ));
    }

    // ── R293 keyexpr_intersect_patterns — honest 2-pattern matcher ──
    //
    // `keyexpr_intersect_patterns(a_chunks, b_chunks)` returns true
    // iff at least one literal keyexpr exists that both `a` and `b`
    // would match. The function backs `has_matching` on the
    // RemoteQueryableRegistry and RemoteSubscriberRegistry; the
    // pre-R293 implementation used a bidirectional asymmetric
    // pattern-match approximation (peer-pattern over literal-query
    // OR query-pattern over literal-peer) that missed two-pattern
    // overlap cases such as `home/*/temp ∩ */sensor/temp`.

    fn split(s: &str) -> Vec<&str> {
        s.split('/').collect()
    }

    #[test]
    fn intersect_literals_equal() {
        let a = split("home/temp");
        let b = split("home/temp");
        assert!(keyexpr_intersect_patterns(&a, &b));
    }

    #[test]
    fn intersect_literals_differ() {
        let a = split("home/temp");
        let b = split("home/door");
        assert!(!keyexpr_intersect_patterns(&a, &b));
        let c = split("kitchen/temp");
        assert!(!keyexpr_intersect_patterns(&a, &c));
    }

    #[test]
    fn intersect_pattern_covers_literal_either_side() {
        // The pre-R293 asymmetric form caught these; the new matcher
        // must keep them green.
        let pat = split("home/**");
        let lit = split("home/temp");
        assert!(keyexpr_intersect_patterns(&pat, &lit));
        assert!(keyexpr_intersect_patterns(&lit, &pat));

        let mid_star = split("sensors/*/temp");
        let exact = split("sensors/room1/temp");
        assert!(keyexpr_intersect_patterns(&mid_star, &exact));
        assert!(keyexpr_intersect_patterns(&exact, &mid_star));
    }

    #[test]
    fn intersect_two_patterns_share_literal_via_mid_star() {
        // `home/*/temp ∩ */sensor/temp` shares `home/sensor/temp`
        // (and any `<x>/sensor/temp` for `<x> == home`). This is
        // the textbook two-pattern overlap case the pre-R293
        // approximation missed.
        let a = split("home/*/temp");
        let b = split("*/sensor/temp");
        assert!(keyexpr_intersect_patterns(&a, &b));
        assert!(keyexpr_intersect_patterns(&b, &a));
    }

    #[test]
    fn intersect_two_patterns_no_shared_literal() {
        // `home/* ∩ kitchen/*` share no literal: first chunk
        // disagrees on the literal anchor.
        let a = split("home/*");
        let b = split("kitchen/*");
        assert!(!keyexpr_intersect_patterns(&a, &b));
    }

    #[test]
    fn intersect_double_star_consumes_zero() {
        // `home/** ∩ home/temp` — `**` consumes zero on the empty
        // tail; `home/temp` exhausts after two chunks, `home/**`
        // consumes one chunk then `**` swallows the trailing
        // `temp` (or zero, depending on the recursion arm).
        let a = split("home/**");
        let b = split("home/temp");
        assert!(keyexpr_intersect_patterns(&a, &b));
        let c = split("home");
        assert!(keyexpr_intersect_patterns(&a, &c));
        let d = split("home/**");
        assert!(keyexpr_intersect_patterns(&a, &d));
    }

    #[test]
    fn intersect_double_star_both_sides_overlap_mid() {
        // `**/temp ∩ home/**` shares `home/temp` (and any
        // `home/<x>.../temp`).
        let a = split("**/temp");
        let b = split("home/**");
        assert!(keyexpr_intersect_patterns(&a, &b));
        assert!(keyexpr_intersect_patterns(&b, &a));
    }

    #[test]
    fn intersect_double_star_disjoint_anchors() {
        // `home/**/temp ∩ kitchen/**/temp` — literal anchors on
        // both sides disagree at position 0, no `**` shape can
        // bridge them.
        let a = split("home/**/temp");
        let b = split("kitchen/**/temp");
        assert!(!keyexpr_intersect_patterns(&a, &b));
    }

    #[test]
    fn intersect_double_star_match_anywhere() {
        // `**` alone is the zenoh match-everything pattern; it
        // intersects with every chunk shape.
        let star_star = split("**");
        for ke in [
            "home/temp",
            "**",
            "*",
            "a/b/c/d/e",
            "sensors/$*",
            "home/*/door",
        ] {
            let other = split(ke);
            assert!(
                keyexpr_intersect_patterns(&star_star, &other),
                "** should intersect with {ke}"
            );
            assert!(
                keyexpr_intersect_patterns(&other, &star_star),
                "{ke} should intersect with ** (symmetric)"
            );
        }
    }

    #[test]
    fn intersect_dsl_one_side_matches_other_literal_chunk() {
        // `pre$*post ∩ prefix_post` — single-side $*; the DSL chunk
        // covers the literal chunk on the other side.
        let a = split("a/pre$*post/b");
        let b = split("a/prefix_post/b");
        assert!(keyexpr_intersect_patterns(&a, &b));
        assert!(keyexpr_intersect_patterns(&b, &a));
        // And a negative case: literal does not satisfy DSL anchors.
        let c = split("a/wrongprefix_post/b");
        // `pre$*post` requires `pre` prefix and `post` suffix.
        assert!(!keyexpr_intersect_patterns(&a, &c));
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
        let a = split("pre$*");
        let b = split("$*post");
        assert!(keyexpr_intersect_patterns(&a, &b));

        // Identical DSL chunks: trivially intersect.
        let c = split("a$*b");
        let d = split("a$*b");
        assert!(keyexpr_intersect_patterns(&c, &d));
    }

    #[test]
    fn intersect_dsl_both_sides_lead_anchor_mismatch_rejects() {
        // Lead anchors `A` vs `B` are byte-distinct (neither is a
        // prefix of the other) — no shared chunk literal possible.
        let a = split("A$*Z");
        let b = split("B$*Z");
        assert!(!keyexpr_intersect_patterns(&a, &b));
        assert!(!keyexpr_intersect_patterns(&b, &a));
    }

    #[test]
    fn intersect_dsl_both_sides_trail_anchor_mismatch_rejects() {
        // Trail anchors `A` vs `B` are byte-distinct — no shared
        // chunk literal.
        let a = split("X$*A");
        let b = split("X$*B");
        assert!(!keyexpr_intersect_patterns(&a, &b));
        assert!(!keyexpr_intersect_patterns(&b, &a));
    }

    #[test]
    fn intersect_dsl_both_sides_lead_prefix_compatible_accepts() {
        // Lead anchor `AB` extends `A` — the shorter is a prefix
        // of the longer. Shared literal exists (`AB...` family
        // covers both patterns when trails align).
        let a = split("A$*Z");
        let b = split("AB$*Z");
        assert!(keyexpr_intersect_patterns(&a, &b));
        assert!(keyexpr_intersect_patterns(&b, &a));
    }

    #[test]
    fn intersect_dsl_both_sides_trail_suffix_compatible_accepts() {
        // Trail anchor `BC` extends `C` — the shorter is a suffix
        // of the longer. Shared literal exists in the `...BC`
        // family (lead empties trivially align).
        let a = split("$*C");
        let b = split("$*BC");
        assert!(keyexpr_intersect_patterns(&a, &b));
        assert!(keyexpr_intersect_patterns(&b, &a));
    }

    #[test]
    fn intersect_dsl_both_sides_middle_sub_parts_always_fit() {
        // Middle sub-parts in arbitrary order on either side fit
        // in a shared chunk literal via alternating interleaving.
        // a = "$*A$*B$*"   — middles [A, B] in order
        // b = "$*B$*A$*"   — middles [B, A] in opposite order
        // Lead/trail both empty → compatible. Shared literal e.g.
        // "BABA" satisfies both pattern orderings.
        let a = split("$*A$*B$*");
        let b = split("$*B$*A$*");
        assert!(keyexpr_intersect_patterns(&a, &b));
        assert!(keyexpr_intersect_patterns(&b, &a));
    }

    #[test]
    fn intersect_dsl_both_sides_distinct_middles_accept() {
        // Distinct middle sub-parts on both sides ("ABC" vs
        // "XYZ") — shared chunk literal `ABCXYZ` (or any
        // concatenation) satisfies both. zenoh-pico matches the
        // outcome via the `right has $*` over-approximation
        // branch (line 156 of keyexpr_match_template.h).
        let a = split("$*ABC$*");
        let b = split("$*XYZ$*");
        assert!(keyexpr_intersect_patterns(&a, &b));
        assert!(keyexpr_intersect_patterns(&b, &a));
    }

    #[test]
    fn intersect_dsl_both_sides_lead_prefix_with_trail_suffix_overlap() {
        // Lead "AB" extends "A", trail "BA" extends "A" — both
        // anchor checks pass. Shared literal example: "ABA"
        // (a pattern: "AB" + "" + "A"; b pattern: "A" + "B" + "A").
        let a = split("AB$*A");
        let b = split("A$*BA");
        assert!(keyexpr_intersect_patterns(&a, &b));
        assert!(keyexpr_intersect_patterns(&b, &a));
    }

    #[test]
    fn intersect_dsl_both_sides_byte_overlap_lead_rejects() {
        // Lead "AB" and "AX" share the first byte 'A' but diverge
        // at the second byte. Neither is a prefix of the other —
        // no shared literal with both `AB` and `AX` prefixes.
        let a = split("AB$*Z");
        let b = split("AX$*Z");
        assert!(!keyexpr_intersect_patterns(&a, &b));
        assert!(!keyexpr_intersect_patterns(&b, &a));
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
        for (lhs, rhs) in cases {
            let a = split(lhs);
            let b = split(rhs);
            assert_eq!(
                keyexpr_intersect_patterns(&a, &b),
                keyexpr_intersect_patterns(&b, &a),
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
        registry.register("home/$*/temp", move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        registry.register("home/**/*/temp", move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        registry.register("home/$*$*$*foo", move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        // and emit a log::warn (not asserted here). The matcher will
        // simply never fire since no canonical wire keyexpr
        // contains `?`.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry.register("home/foo?bar", move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });
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
        registry.register("home/temp", move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        registry.register_with_locality("home/temp", Locality::Remote, move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        registry.register_with_locality("home/temp", Locality::SessionLocal, move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        registry.register("home/temp", move |_push| {
            any_clone.fetch_add(1, Ordering::SeqCst);
        });
        registry.register_with_locality("home/temp", Locality::SessionLocal, move |_push| {
            local_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        registry.register_with_locality("**", Locality::SessionLocal, move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
            put.payload_len = payload.len() as u64;
            put.payload = crate::codec_owned::owned_bytes(payload).unwrap();
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
        registry.register("home/temp", move |sample| {
            *captured_clone.lock().unwrap() = Some(Sample::from_view(sample));
        });

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
        registry.register("clear/me", move |sample| {
            *captured_clone.lock().unwrap() = Some(Sample::from_view(sample));
        });

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
        registry.register("sensors/**", move |sample| {
            *captured_clone.lock().unwrap() = Some(sample.keyexpr().to_string());
        });

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
        registry.register("sensors/*/temp", move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        registry.register("home/**", move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        registry.register("sensors/*/temp", move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        let id = registry.register("topic/a", |_push| {});
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
    fn declare_kexpr_literal(mapping_id: u64, s: &str) -> wz_codecs::declare::DeclareOwned {
        wz_codecs::declare::Declare {
            body: wz_codecs::declare::DeclareVariant::CodecZenohDeclKexpr(
                wz_codecs::decl_kexpr::DeclKexpr {
                    id: mapping_id,
                    keyexpr: wz_codecs::wireexpr::Wireexpr {
                        body: WireexprVariant::WireexprLocal(
                            wz_codecs::wireexpr_local::WireexprLocal {
                                id: 0,
                                suffix_len: Some(s.len() as u64),
                                suffix: Some(s),
                            },
                        ),
                    },
                    ..Default::default()
                },
            ),
            ..Default::default()
        }
        .try_into_owned()
        .unwrap()
    }

    fn undeclare_kexpr(mapping_id: u64) -> wz_codecs::declare::DeclareOwned {
        wz_codecs::declare::Declare {
            body: wz_codecs::declare::DeclareVariant::CodecZenohUndeclKexpr(
                wz_codecs::undecl_kexpr::UndeclKexpr {
                    id: mapping_id,
                    ..Default::default()
                },
            ),
            ..Default::default()
        }
        .try_into_owned()
        .unwrap()
    }

    fn push_with_mapping_id(mapping_id: u64, inline_suffix: Option<&str>) -> PushOwned {
        Push {
            keyexpr: wz_codecs::wireexpr::Wireexpr {
                body: WireexprVariant::WireexprLocal(wz_codecs::wireexpr_local::WireexprLocal {
                    id: mapping_id,
                    suffix_len: inline_suffix.map(|s| s.len() as u64),
                    suffix: inline_suffix,
                }),
            },
            ..Push::default()
        }
        .try_into_owned()
        .unwrap()
    }

    /// An `M=0` (`Mapping::Receiver`) aliased Push — the id names OUR space.
    /// This is what a zenoh peer emits for an id we declared, because
    /// `get_best_key` prefers `ctx.remote_expr_id` and stamps it
    /// `Mapping::Receiver` (`dispatcher/resource.rs:625`).
    fn push_with_own_mapping_id(mapping_id: u64, inline_suffix: Option<&str>) -> PushOwned {
        Push {
            keyexpr: wz_codecs::wireexpr::Wireexpr {
                body: WireexprVariant::WireexprNonlocal(
                    wz_codecs::wireexpr_nonlocal::WireexprNonlocal {
                        id: mapping_id,
                        suffix_len: inline_suffix.map(|s| s.len() as u64),
                        suffix: inline_suffix,
                    },
                ),
            },
            ..Push::default()
        }
        .try_into_owned()
        .unwrap()
    }

    /// R311y739 — OUR id space as a bare table, installed on the registry.
    fn own_space(id: u64, literal: &str) -> alloc::sync::Arc<HashMap<u64, String>> {
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
        registry.register("ours/temp", move |_| {
            o.fetch_add(1, Ordering::SeqCst);
        });
        registry.register("peer/only/temp", move |_| {
            t.fetch_add(1, Ordering::SeqCst);
        });

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
        registry.register("ours/temp", move |_| {
            o.fetch_add(1, Ordering::SeqCst);
        });
        registry.register("peer/only/temp", move |_| {
            t.fetch_add(1, Ordering::SeqCst);
        });
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
        registry.register("ours/temp", move |_| {
            o.fetch_add(1, Ordering::SeqCst);
        });
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
        registry.register("ours/temp", move |_| {
            f.fetch_add(1, Ordering::SeqCst);
        });
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
        registry.register("home/temp", move |_| {
            f.fetch_add(1, Ordering::SeqCst);
        });
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push_with_own_mapping_id(0, Some("home/temp")))),
            Reliability::Reliable,
        );
        assert_eq!(fired.load(Ordering::SeqCst), 1);
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
        registry.register("demo/test", move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        registry.register("demo/test", move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        registry.register("home/sensor/temp", move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        assert_eq!(registry.resolve_inbound_mapping(u64::MAX), None);
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
        use wz_codecs::decl_final::DeclFinal;
        use wz_codecs::decl_queryable::DeclQueryable;
        use wz_codecs::decl_subscriber::DeclSubscriber;
        use wz_codecs::decl_token::DeclToken;
        use wz_codecs::declare::DeclareVariant;
        use wz_codecs::undecl_queryable::UndeclQueryable;
        use wz_codecs::undecl_subscriber::UndeclSubscriber;
        use wz_codecs::undecl_token::UndeclToken;

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
                    tag: 0xFF,
                    body: DeclFinal::default(),
                },
            ),
        ];

        for (name, body) in arms {
            let mut registry = SubscriberRegistry::new();
            // `absorb_declare` takes the owned variant; deep-copy the
            // borrowed test arm at the boundary.
            let body = body.try_into_owned().unwrap();
            registry.absorb_declare(&body);
            assert!(
                registry.peer_keyexpr_table().is_empty(),
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
        registry.register("home/temp", move |_sample| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        registry.register_with_locality("home/temp", Locality::SessionLocal, move |_sample| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        registry.register_with_locality("home/temp", Locality::Remote, move |_sample| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        let sample = Sample::new_put("home/temp", b"22.5".to_vec());
        let fired = registry.local_publish(&sample);
        assert_eq!(
            fired, 0,
            "Locality::Remote suppresses loopback (allows_local() == false)"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 0);
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
            registry.register_with_locality("home/temp", Locality::Any, move |_sample| {
                any_clone.fetch_add(1, Ordering::SeqCst);
            });
        }
        {
            let local_clone = local_hits.clone();
            registry.register_with_locality("home/temp", Locality::SessionLocal, move |_sample| {
                local_clone.fetch_add(1, Ordering::SeqCst);
            });
        }
        {
            let remote_clone = remote_hits.clone();
            registry.register_with_locality("home/temp", Locality::Remote, move |_sample| {
                remote_clone.fetch_add(1, Ordering::SeqCst);
            });
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
        registry.register("kitchen/temp", move |_sample| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
            registry.register("home/temp", move |_sample| {
                clone.fetch_add(1, Ordering::SeqCst);
            });
        }
        {
            let clone = hits_b.clone();
            registry.register("home/*", move |_sample| {
                clone.fetch_add(1, Ordering::SeqCst);
            });
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
        // `keyexpr_pattern_matches` the wire path uses, so wildcard
        // semantics carry across origins.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry.register("home/**", move |_sample| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        registry.register("home/temp_$*", move |_sample| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        registry.register("home/temp", move |sample| {
            *observed_clone.lock().unwrap() = Some(Sample::from_view(sample));
        });

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
        registry.register("home/temp", move |sample| {
            *observed_clone.lock().unwrap() = Some(sample.kind());
            assert!(sample.payload().is_empty(), "Del Sample carries no payload");
        });

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
        registry.register_with_locality("home/**", Locality::Remote, move |_sample| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

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
        let mut ext = wz_codecs::ext_entry::ExtEntry::new();
        ext.set_ext_id(0x01); // source_info ext_id
        ext.set_enc(0x02); // ENC_ZBUF
        let mut payload = vec![((source_zid.len() as u8) - 1) << 4];
        payload.extend_from_slice(source_zid);
        payload.push(0); // VLE eid = 0
        payload.push(0); // VLE sn = 0
        ext.body = wz_codecs::ext_entry::ExtEntryVariant::CodecZenohExtZbuf(
            wz_codecs::ext_zbuf::ExtZbuf {
                value_len: payload.len() as u64,
                value: &payload,
            },
        );
        // The owned `MsgPut` carries an alloc `Vec<ExtEntryOwned>` (vs the
        // borrowed heapless `Vec<_, 4>`); deep-copy the borrowed ext in.
        let mut put = wz_codecs::msg_put::MsgPut::default()
            .try_into_owned()
            .unwrap();
        put.extensions = Some(vec![ext.try_into_owned().unwrap()]);
        let mut push = Push {
            keyexpr: wz_codecs::wireexpr::Wireexpr {
                body: WireexprVariant::WireexprLocal(wz_codecs::wireexpr_local::WireexprLocal {
                    id: 0,
                    suffix_len: Some(keyexpr.len() as u64),
                    suffix: Some(keyexpr),
                }),
            },
            ..Push::default()
        }
        .try_into_owned()
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
        registry.register("demo/temp", move |_s| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });
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
        registry.register("demo/shm", move |_s| {
            f.fetch_add(1, Ordering::SeqCst);
        });
        // R311y516 — negotiate FIRST so this test still measures what it is
        // named for. The negotiation gate added in R311y516 runs BEFORE the
        // resolve and would otherwise absorb this Put into
        // `shm_unnegotiated_drops`, leaving the missing-resolver precondition
        // untested behind a green assertion.
        registry.set_shm_negotiated(true);
        // No resolver installed -> the descriptor is unresolvable.
        let descriptor = crate::extshm::ShmDescriptor {
            segment_id: 0x1234,
            length: 4,
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

    #[test]
    fn dispatch_push_fires_when_source_zid_differs_from_own() {
        // Genuine remote-origin sample (peer's zid differs from
        // ours). Dedup must not engage; the subscriber must fire.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry.register("demo/temp", move |_s| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });
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
        registry.register("demo/temp", move |_s| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });
        assert!(registry.set_own_zid(vec![0x01, 0x02, 0x03, 0x04]));

        // push_with_mapping_id builds a Push::default() body which
        // has no MsgPut extensions and therefore no source_info.
        // To reach dispatch_push's PushVariant arm with no source_info
        // we hand in a MsgPut with `extensions = None`.
        let push = Push {
            keyexpr: wz_codecs::wireexpr::Wireexpr {
                body: WireexprVariant::WireexprLocal(wz_codecs::wireexpr_local::WireexprLocal {
                    id: 0,
                    suffix_len: Some("demo/temp".len() as u64),
                    suffix: Some("demo/temp"),
                }),
            },
            body: wz_codecs::push::PushVariant::CodecZenohMsgPut(
                wz_codecs::msg_put::MsgPut::default(),
            ),
            ..Push::default()
        }
        .try_into_owned()
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
        let put = wz_codecs::msg_put::MsgPut {
            encoding: Some(wz_codecs::encoding::Encoding {
                packed_id,
                schema_len: None,
                schema: None,
            }),
            ..wz_codecs::msg_put::MsgPut::default()
        }
        .try_into_owned()
        .unwrap();
        let mut push = Push {
            keyexpr: wz_codecs::wireexpr::Wireexpr {
                body: WireexprVariant::WireexprLocal(wz_codecs::wireexpr_local::WireexprLocal {
                    id: 0,
                    suffix_len: Some(keyexpr.len() as u64),
                    suffix: Some(keyexpr),
                }),
            },
            ..Push::default()
        }
        .try_into_owned()
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
        registry.register("home/temp", move |sample| {
            f.fetch_add(1, Ordering::SeqCst);
            if sample.encoding().is_some() {
                p.fetch_add(1, Ordering::SeqCst);
            }
        });
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
        registry.register("home/temp", move |sample| {
            f.fetch_add(1, Ordering::SeqCst);
            if sample.encoding().is_some() {
                p.fetch_add(1, Ordering::SeqCst);
            }
        });
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
        registry.register("demo/temp", move |sample| {
            f.fetch_add(1, Ordering::SeqCst);
            if sample.source_info().is_some() {
                p.fetch_add(1, Ordering::SeqCst);
            }
        });
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
        registry.register("demo/temp", move |sample| {
            f.fetch_add(1, Ordering::SeqCst);
            if sample.source_info().is_some() {
                p.fetch_add(1, Ordering::SeqCst);
            }
        });
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
        let mut ext = wz_codecs::ext_entry::ExtEntry::new();
        ext.set_ext_id(0x01); // QOS_EXT_ID
        ext.set_enc(0x01); // ENC_ZINT
        ext.body = wz_codecs::ext_entry::ExtEntryVariant::CodecZenohExtZint(
            wz_codecs::ext_zint::ExtZint {
                value: u64::from(raw),
            },
        );
        let mut push = Push {
            keyexpr: wz_codecs::wireexpr::Wireexpr {
                body: WireexprVariant::WireexprLocal(wz_codecs::wireexpr_local::WireexprLocal {
                    id: 0,
                    suffix_len: Some(keyexpr.len() as u64),
                    suffix: Some(keyexpr),
                }),
            },
            body: wz_codecs::push::PushVariant::CodecZenohMsgPut(
                wz_codecs::msg_put::MsgPut::default(),
            ),
            ..Push::default()
        }
        .try_into_owned()
        .unwrap();
        push.extensions = Some(vec![ext.try_into_owned().unwrap()]);
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
        registry.register("home/temp", move |sample| {
            f.fetch_add(1, Ordering::SeqCst);
            if sample.qos().is_some() {
                p.fetch_add(1, Ordering::SeqCst);
            }
        });
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
        registry.register("home/temp", move |sample| {
            f.fetch_add(1, Ordering::SeqCst);
            if sample.qos().is_some() {
                p.fetch_add(1, Ordering::SeqCst);
            }
        });
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
        let put = wz_codecs::msg_put::MsgPut {
            timestamp: Some(wz_codecs::timestamp::Timestamp {
                time: 0x1122_3344_5566_7788,
                zid_len: zid.len() as u64,
                zid: &zid,
            }),
            ..wz_codecs::msg_put::MsgPut::default()
        }
        .try_into_owned()
        .unwrap();
        let mut push = Push {
            keyexpr: wz_codecs::wireexpr::Wireexpr {
                body: WireexprVariant::WireexprLocal(wz_codecs::wireexpr_local::WireexprLocal {
                    id: 0,
                    suffix_len: Some(keyexpr.len() as u64),
                    suffix: Some(keyexpr),
                }),
            },
            ..Push::default()
        }
        .try_into_owned()
        .unwrap();
        push.body = PushOwnedVariant::CodecZenohMsgPut(put);
        push
    }

    /// A Put carrying a wire attachment ext (ext_id 0x03 ZBuf).
    fn push_put_with_attachment(keyexpr: &str, bytes: &[u8]) -> PushOwned {
        let mut ext = wz_codecs::ext_entry::ExtEntry::new();
        ext.set_ext_id(0x03); // ATTACHMENT_EXT_ID_PUSH
        ext.set_enc(0x02); // ENC_ZBUF
        ext.body = wz_codecs::ext_entry::ExtEntryVariant::CodecZenohExtZbuf(
            wz_codecs::ext_zbuf::ExtZbuf {
                value_len: bytes.len() as u64,
                value: bytes,
            },
        );
        let mut put = wz_codecs::msg_put::MsgPut::default()
            .try_into_owned()
            .unwrap();
        put.extensions = Some(vec![ext.try_into_owned().unwrap()]);
        let mut push = Push {
            keyexpr: wz_codecs::wireexpr::Wireexpr {
                body: WireexprVariant::WireexprLocal(wz_codecs::wireexpr_local::WireexprLocal {
                    id: 0,
                    suffix_len: Some(keyexpr.len() as u64),
                    suffix: Some(keyexpr),
                }),
            },
            ..Push::default()
        }
        .try_into_owned()
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
        registry.register("home/temp", move |sample| {
            f.fetch_add(1, Ordering::SeqCst);
            if sample.timestamp().is_some() {
                p.fetch_add(1, Ordering::SeqCst);
            }
        });
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
        registry.register("home/temp", move |sample| {
            *cap.lock().unwrap() = sample.attachment().map(<[u8]>::to_vec);
        });
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
        registry.register("demo/temp", move |_s| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });
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
        registry.register("demo/temp", move |_s| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });
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
        registry.register("demo/temp", move |_s| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });
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
        registry.register("demo/temp", move |_s| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });
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
        });
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
    feature = "alloc",
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
        registry.register("home/temp", move |_| {
            f.fetch_add(1, Ordering::SeqCst);
        });

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
        registry.register("home/temp", move |_| {
            f.fetch_add(1, Ordering::SeqCst);
        });

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
    feature = "alloc",
    feature = "codec-push",
    feature = "pubsub-put",
    not(feature = "pubsub-timestamp"),
    not(feature = "pubsub-attachment"),
))]
mod metadata_decode_isolation_tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use wz_codecs::push::Push;
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_local::WireexprLocal;

    /// A literal-keyexpr Put with a `Push::default()` body (no metadata).
    fn put_push_literal(keyexpr: &str) -> PushOwned {
        Push {
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprLocal(WireexprLocal {
                    id: 0,
                    suffix_len: Some(keyexpr.len() as u64),
                    suffix: Some(keyexpr),
                }),
            },
            ..Push::default()
        }
        .try_into_owned()
        .unwrap()
    }

    /// A Put carrying a wire `timestamp` (time + 4-byte zid). The codec
    /// `MsgPut.timestamp` field is ungated, so this is constructible with
    /// `pubsub-timestamp` off — that feature gates only the projection.
    fn put_push_with_timestamp(keyexpr: &str) -> PushOwned {
        let zid = [0x01u8, 0x02, 0x03, 0x04];
        let put = wz_codecs::msg_put::MsgPut {
            timestamp: Some(wz_codecs::timestamp::Timestamp {
                time: 0x0102_0304_0506_0708,
                zid_len: zid.len() as u64,
                zid: &zid,
            }),
            ..wz_codecs::msg_put::MsgPut::default()
        }
        .try_into_owned()
        .unwrap();
        let mut push = put_push_literal(keyexpr);
        push.body = PushOwnedVariant::CodecZenohMsgPut(put);
        push
    }

    /// A Put carrying a wire attachment ext (ext_id 0x03 ZBuf). Built by
    /// hand (the `crate::attachment` helper is `attachment-bytes`-gated
    /// and absent in this profile); the wire form is the raw ZBuf value.
    fn put_push_with_attachment(keyexpr: &str, bytes: &[u8]) -> PushOwned {
        let mut ext = wz_codecs::ext_entry::ExtEntry::new();
        ext.set_ext_id(0x03); // ATTACHMENT_EXT_ID_PUSH
        ext.set_enc(0x02); // ENC_ZBUF
        ext.body = wz_codecs::ext_entry::ExtEntryVariant::CodecZenohExtZbuf(
            wz_codecs::ext_zbuf::ExtZbuf {
                value_len: bytes.len() as u64,
                value: bytes,
            },
        );
        let mut put = wz_codecs::msg_put::MsgPut::default()
            .try_into_owned()
            .unwrap();
        put.extensions = Some(vec![ext.try_into_owned().unwrap()]);
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
        registry.register("home/temp", move |sample| {
            f.fetch_add(1, Ordering::SeqCst);
            if sample.timestamp().is_some() {
                p.fetch_add(1, Ordering::SeqCst);
            }
        });
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
        registry.register("home/temp", move |sample| {
            f.fetch_add(1, Ordering::SeqCst);
            if sample.attachment().is_some() {
                p.fetch_add(1, Ordering::SeqCst);
            }
        });
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
