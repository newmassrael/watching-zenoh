// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The §5.16 access-control interceptor SEAM — the composable message-admission
//! pipeline. The wz mirror of zenoh `net/routing/interceptor/mod.rs`
//! (`InterceptorTrait` + `InterceptorsChain`).
//!
//! # Why the seam, not an inline check
//!
//! zenoh enforces access control as a COMPOSABLE chain of interceptors run
//! uniformly at the per-face message boundary (`Mux`/`DeMux`), decoupled from
//! routing logic; the ACL is one interceptor on that chain, alongside
//! downsampling / qos / low-pass. Each is a `intercept(msg) -> bool` that
//! either admits or drops, dispatching internally on the message KIND. wz
//! ports that shape: an [`Interceptor`] is `intercept(ctx, msg) -> bool`, an
//! [`InterceptorChain`] admits a message only when EVERY interceptor admits it,
//! and the chain is consulted ONCE per inbound message ahead of the
//! kind-dispatch — never an `if deny` welded into one message arm. Adding the
//! next §5.16 feature (downsampling, quota) is a new [`Interceptor`] on the
//! chain, and the next ACL action (Delete, DeclareSubscriber, Query) is a new
//! arm in the enforcer's [`match`](access_control), not a new check site.
//!
//! # Where it lives
//!
//! Unlike the pure policy ENGINE ([`wz_access_control`], zenoh's
//! `authorization.rs`), this seam and the [`access_control`] enforcer adapter
//! reference the codec [`NetworkMessage`] types, so they stay in the runtime
//! crate — exactly as zenoh keeps `access_control.rs` (which matches on
//! `NetworkBodyMut`) separate from the message-type-free `authorization.rs`.
//!
//! # Scope of the first atom
//!
//! The chain is consulted at the linkstate forwarder's INBOUND boundary — the
//! mesh-RELAY admission point. A denied inbound message is not relayed onward.
//! Local delivery to THIS node's own subscriber is driven by the session layer
//! (a separate consumer of the inbound frame), so gating it is the full
//! Primitives/`DeMux` seam a later atom builds; this atom enforces ingress on
//! the relay path. Egress (the `Mux` twin) and the per-transport factory that
//! resolves cert/username subjects are likewise later atoms. The enforcer
//! checks the `Put` action by the auth-free zid subject — the smallest real
//! rule, on the structure that the rest of §5.16 extends rather than replaces.

// Each concrete interceptor is an independent §5.16 composition knob: the
// module, its config field, and its build_chain push gate on the matching
// `access-*` feature. The SEAM below (the trait + chain + flow descriptor)
// stays under `routing-peer` so the chain builds for any subset — including
// none, which is access control disabled.
#[cfg(feature = "access-acl")]
pub mod access_control;
// A node's document compiled into this module's config. Not gated on `routing-peer`: the C ABI
// compiles its own session's interceptors from the same keys a router reads, and the compile
// must not drag the routing plane in with it.
#[cfg(feature = "zenoh-config")]
pub mod document;
#[cfg(feature = "access-downsampling")]
pub mod downsampling;
// Gated on its CONSUMERS, which are the `InterceptorContext` implementations
// rather than the enforcers: the region-hat forwarder's face contexts
// (`routing-router-hat`, which a peer node is as well since the single-net forwarder retired)
// and the session's egress context (`access-acl`). A downsampling- or quota-only build
// compiles an enforcer but no context to run it against, so it resolves no governed keyexpr and
// this module would be dead code there; so would it with `routing-peer` alone, which has the
// config types of the chain and no forwarder to run it.
#[cfg(any(feature = "routing-router-hat", feature = "access-acl"))]
pub(crate) mod keyexpr;
#[cfg(feature = "access-quota")]
pub mod low_pass;
#[cfg(feature = "access-qos-overwrite")]
pub mod qos_overwrite;

use std::any::Any;
// The policy engine's types, nameable from the seam that takes them: `InterceptorConfig::with_acl`
// is public, and a caller that cannot name its argument cannot call it. They were reachable only
// through `linkstate_forward`, which is a routing build, so a host that governs a SESSION (the
// multicast one, say) had to depend on the routing plane or on the engine crate directly.
#[cfg(feature = "access-acl")]
pub use wz_access_control::{
    AclConfig, AclFlow, AclMessage, AclPolicy, AclRule, AclUsername, Permission, SubjectSelector,
};

use wz_routing_graph::Zid;
use wz_session_core::link::LinkSubject;
use wz_session_core::network_message::NetworkMessage;

#[cfg(feature = "access-acl")]
use self::access_control::AclInterceptor;
#[cfg(feature = "access-downsampling")]
use self::downsampling::{DownsamplingInterceptor, DownsamplingRule};
#[cfg(feature = "access-quota")]
use self::low_pass::{LowPassInterceptor, LowPassRule};
#[cfg(feature = "access-qos-overwrite")]
use self::qos_overwrite::{QosOverwriteInterceptor, QosOverwriteRule};

/// The per-message context an [`Interceptor`] reads — the wz mirror of zenoh
/// `InterceptorContext`. The resolved subject (who is on the other end of the
/// face) and a face-local keyexpr resolver. Implemented by the forwarder, which
/// owns the per-face alias table and transport identity; the interceptor stays
/// free of face internals.
pub trait InterceptorContext {
    /// The request's subject — the routing identity of the peer on the other
    /// end of the face (the auth-free ACL subject). `None` when the face has no
    /// resolved identity: either it has not completed its handshake yet, or the
    /// zid the peer presented was non-conformant and `peer_zid_routing` rejected
    /// it.
    ///
    /// `None` is NOT an exemption. An enforcer passes it to its policy and the
    /// policy answers, so a rule that does not name a peer still governs the
    /// face and one that names a peer does not. Open-debt item 655 (R2347) is
    /// why that is spelled out on the SEAM and not only at the one enforcer that
    /// reads it: a peer chooses its own zid bytes, so an interceptor that
    /// skipped an unattributable face would let the peer choose to be
    /// unfiltered. `wz_access_control::AclPolicy::decision` takes the `Option`
    /// for the same reason — no link here, because that crate is optional
    /// (`access-acl`) and this trait is not.
    fn subject(&self) -> Option<Zid>;

    /// Resolve a message's key expression against THIS face's alias table to
    /// its literal form — the wz mirror of zenoh `InterceptorContext`'s
    /// keyexpr resolution. `None` when the message carries no keyexpr, or an
    /// aliased id the peer never declared on this face (the message would drop
    /// in routing anyway), in which case an enforcer admits.
    fn full_keyexpr(&self, msg: &NetworkMessage) -> Option<String>;

    /// R311y453 — the LINK-derived subject of the face this message arrived on:
    /// its protocol and the NICs it sits on, for the `link_protocols` /
    /// `interfaces` rule-scoping axes.
    ///
    /// zenoh resolves these once per transport, inside each interceptor FACTORY,
    /// and decides there whether to install the interceptor at all
    /// (`net/routing/interceptor/downsampling.rs:90-116`). wz has no per-transport
    /// factory — one chain serves every face — so the subject is read per message
    /// off the face's already-held driver, which is a field read rather than a
    /// re-resolution (see [`LinkSubject`]).
    ///
    /// Returns a REFERENCE, not an owned value: this is read once per message per
    /// subject-narrowed rule, and an owned return would clone the interface-name
    /// vector every time.
    ///
    /// `None` means the same thing as [`LinkSubject::UNKNOWN`] — every axis
    /// indeterminate — which the fail-closed matchers
    /// ([`LinkSubject::opt_matches_protocols`]) treat as MATCHING every narrowed
    /// rule. The default exists for the test contexts; both production impls
    /// override it.
    fn link_subject(&self) -> Option<&LinkSubject> {
        None
    }

    /// R2631 — the name the peer on this face AUTHENTICATED as, for the ACL's
    /// `usernames` subject axis: the wz counterpart of the username zenoh reads
    /// off the transport's auth ids when it resolves a subject
    /// (`zenoh/src/net/routing/interceptor/access_control.rs` @ `let username = auth_ids.username().cloned().map(Username);`).
    ///
    /// A SESSION fact, not a link one, which is why it is a method beside
    /// [`subject`](Self::subject) and not a field of [`LinkSubject`]: a link
    /// driver cannot know who authenticated over it, and the name comes from the
    /// accept handshake the session ran, exactly as the zid does.
    ///
    /// ⛔ DELIBERATELY NO DEFAULT, unlike [`link_subject`](Self::link_subject)
    /// above, and the asymmetry is the point. That method's `None` is
    /// fail-CLOSED: a narrowed rule still applies to a link that cannot describe
    /// itself. This one's `None` is a definite "no name", under which a rule
    /// naming a user does NOT apply — so a context that inherited a silent `None`
    /// would exempt an authenticated user from every username-scoped DENY. Making
    /// each implementation write the answer is what keeps that from being a
    /// thing a new forwarder can forget.
    ///
    /// `None` for an unauthenticated session, a pubkey-only one, a name that is
    /// not UTF-8 (upstream keeps no username then either), and every face this
    /// node DIALED, since only the accepting side learns who connected.
    fn username(&self) -> Option<String>;
}

/// What an operator is told about a policy that is installed beside a multicast GROUP, or `None`
/// when there is nothing to tell: a transport with a peer is governed as it always was, no policy
/// governs nothing anywhere, and a group the host chose to govern is covered.
///
/// A group left outside its policy is the case with something to say. Upstream's own interceptors
/// leave a multicast transport alone without a word, which is how an operator comes to believe a
/// group is covered by an ACL it is outside. A pure function of three facts, so the decision is a
/// thing a test can hold where a log line is not, and so the session (which knows its config) and
/// the router (which knows its chains) ask the same question.
///
/// Compiled where one of those two asks, so a build that has neither (a downsampling-only one,
/// say) carries no function nobody calls.
#[cfg(any(feature = "access-acl", feature = "router-multicast-faces"))]
pub(crate) fn group_policy_notice(
    is_group: bool,
    policy_installed: bool,
    governed: bool,
) -> Option<&'static str> {
    if !is_group || !policy_installed || governed {
        return None;
    }
    Some(if cfg!(feature = "access-acl-multicast") {
        "a policy is installed beside a multicast group that it does not govern: access control, \
         downsampling and low-pass apply to unicast sessions only, as upstream's do; set \
         `InterceptorConfig::govern_multicast` to hold the group to it"
    } else {
        "a policy is installed beside a multicast group, and this build cannot hold the group to \
         it: access control, downsampling and low-pass apply to unicast sessions only, as \
         upstream's do; build with `access-acl-multicast` to govern the group"
    })
}

/// The per-message [`InterceptorContext`] of a GROUP (a multicast transport): the group's link and
/// the message's key, nothing more.
///
/// A group has no peer to ask. It answers no zid and no user, which under the chain's own rules
/// means a rule scoped by either never applies to it, and it answers its LINK, which is what a
/// rule scoped by `link_protocols` or `interfaces` reads. One type for the three places a group's
/// traffic is judged (a multicast session's egress, the dispatcher's ingress gate, and the
/// router's group face), so the three cannot disagree about who a group is.
#[cfg(feature = "access-acl-multicast")]
pub(crate) struct GroupContext<'a> {
    link: &'a LinkSubject,
    keyexpr: Option<String>,
}

#[cfg(feature = "access-acl-multicast")]
impl<'a> GroupContext<'a> {
    /// A context whose key the caller has already resolved to a literal (the router holds it).
    /// Only the router's group face has the literal in hand, so only a build with that face
    /// compiles this.
    #[cfg(feature = "router-multicast-faces")]
    pub(crate) fn resolved(link: &'a LinkSubject, keyexpr: &str) -> Self {
        Self {
            link,
            keyexpr: Some(keyexpr.to_owned()),
        }
    }

    /// A context for `msg`, whose key is read as the literal it carries. A group has no alias
    /// table at the point it is judged (the dispatcher has already turned a member's declared
    /// aliases into literals, and a session sends literals), so a key that does not resolve is
    /// `None`, which the chain denies for a governed message, as everywhere in it.
    pub(crate) fn of_message(link: &'a LinkSubject, msg: &NetworkMessage) -> Self {
        let no_aliases = hashbrown::HashMap::new();
        let keyexpr = keyexpr::resolve_governed_keyexpr_in(
            msg,
            wz_session_core::wireexpr_resolve::MappingSpaces::peer_only(&no_aliases),
        );
        Self { link, keyexpr }
    }
}

#[cfg(feature = "access-acl-multicast")]
impl InterceptorContext for GroupContext<'_> {
    // A group member is not authenticated and its zid is not a routing identity here: no subject.
    fn subject(&self) -> Option<Zid> {
        None
    }

    fn link_subject(&self) -> Option<&LinkSubject> {
        Some(self.link)
    }

    // No handshake ran, so nobody authenticated as anyone: a rule naming a user does not apply.
    fn username(&self) -> Option<String> {
        None
    }

    // Resolved at construction; one message per context, so the argument is ignored.
    fn full_keyexpr(&self, _msg: &NetworkMessage) -> Option<String> {
        self.keyexpr.clone()
    }
}

/// WHICH interceptor a chain verdict came from — R2371.
///
/// zenoh keeps a per-interceptor drop stat; wz used to collapse every drop into
/// one count because [`InterceptorChain::admit`] returned a bare `bool` and
/// could not say who dropped. This enum is what un-collapses it, and it is
/// declared BY THE INTERCEPTOR ([`Interceptor::kind`]) rather than inferred from
/// its position, so a new interceptor cannot join the chain without naming
/// itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptorKind {
    /// The §5.16 access-control enforcer denied the message.
    ///
    /// ⚠ This kind reaches NO stats counter, and that is upstream's shape rather
    /// than an omission: the 1.10.0 counter set has drop counters for
    /// downsampling and low-pass only
    /// (`commons/zenoh-stats/src/stats.rs` @ `ReasonLabel::Downsampling`),
    /// because an ACL denial is a policy outcome
    /// its operator already knows about from the policy. It still moves the
    /// forwarder's own `interceptor_dropped` witness.
    AccessControl,
    /// The downsampling rate limiter dropped the message.
    Downsampling,
    /// The low-pass size cap refused the message.
    LowPass,
    /// The QoS overwrite. It never refuses a message, so no verdict carries this kind; it is named
    /// because every interceptor on a chain names itself, and so that a build can tell the chain
    /// holds one. It reaches no stats counter, as upstream has none for it.
    QosOverwrite,
}

/// Whether a chain admitted a message, and if not, WHO dropped it.
///
/// Replaces the bare `bool` the chain used to return (R2371). The `bool` was
/// what made `transport-stats` unable to charge `downsampler_dropped_msgs`
/// separately from `low_pass_dropped_msgs`: the numbers existed but the
/// attribution did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a chain verdict decides whether the message is relayed"]
pub enum InterceptorVerdict {
    /// Every interceptor admitted the message.
    Admit,
    /// The named interceptor dropped it; the chain short-circuited there, so no
    /// later interceptor was consulted (zenoh's chain does the same).
    Drop(InterceptorKind),
}

impl InterceptorVerdict {
    /// Whether the message is admitted — the predicate the relay paths branch
    /// on, so a caller that does not care WHO dropped reads the same as before.
    pub fn is_admitted(self) -> bool {
        matches!(self, InterceptorVerdict::Admit)
    }

    /// The interceptor that dropped, or `None` when admitted.
    pub fn dropped_by(self) -> Option<InterceptorKind> {
        match self {
            InterceptorVerdict::Admit => None,
            InterceptorVerdict::Drop(kind) => Some(kind),
        }
    }
}

/// One message interceptor — zenoh `InterceptorTrait::intercept(msg) -> bool`.
/// Returns `true` to ADMIT the message, `false` to drop it. The implementation
/// dispatches internally on the message kind (it checks only the kinds it
/// governs and admits the rest).
///
/// R2701 — `Send + Sync`, which is the bound upstream's trait OBJECT carries
/// (`zenoh/src/net/routing/interceptor/mod.rs` @ `pub(crate) type Interceptor = Box<dyn InterceptorTrait + Send + Sync>;`)
/// and which wz had silently dropped. It reads like a formality and is not: an
/// `InterceptorChain` is `Vec<Box<dyn Interceptor>>`, so without it the WHOLE
/// chain is neither `Send` nor `Sync`, and the only thing that can hold one is a
/// task-local cell. That was invisible for as long as the single holder WAS
/// task-local (the forwarders' `RefCell`), and it is what refused every attempt
/// to install a chain anywhere else — a `SessionInner` behind the runtime's
/// `Mutex` GAT (which requires `T: Send`) does not compile against the unbounded
/// trait, which is the measured reason the §5.16 client-transport residual had
/// no seam to attach to.
///
/// `Sync` as well as `Send`, again as upstream: the egress door is called from
/// every application thread that publishes, so a policy that could only be read
/// under a lock would serialize publishing on the access check. The cost lands
/// on implementations — see the downsampler's per-rule timer — and that is the
/// correct place for it.
pub trait Interceptor: Send + Sync {
    /// Which interceptor this is — the attribution a chain verdict carries.
    ///
    /// Declared rather than derived: the chain holds `Box<dyn Interceptor>` and
    /// has no other way to name what it just ran, and a positional guess would
    /// go wrong the first time a build elides one interceptor's feature. R2371.
    fn kind(&self) -> InterceptorKind;

    /// Whether to admit `msg`, given the per-message `ctx`.
    fn intercept(&self, ctx: &dyn InterceptorContext, msg: &NetworkMessage) -> bool;

    /// R311y508 (`routing-interceptor-hotreload`) — precompute whatever this
    /// interceptor can derive from a keyexpr ALONE for the given `subject`, so
    /// the per-message path does not redo it. The wz mirror of zenoh
    /// `InterceptorTrait::compute_keyexpr_cache`
    /// (`net/routing/interceptor/mod.rs:102`).
    ///
    /// `ctx` is a parameter here where zenoh has none, and the difference is
    /// structural rather than a divergence: zenoh builds ONE enforcer PER FACE,
    /// so each instance already closes over that face's subject and link
    /// properties, while wz runs ONE chain for every face (see
    /// [`InterceptorContext::link_subject`]'s note on the same asymmetry). Only
    /// the FACE-derived parts of `ctx` may be read here — [`Self::subject`] and
    /// [`Self::link_subject`] — never anything message-derived, because the
    /// result is reused for every later message on the same (face, keyexpr).
    ///
    /// `None` (the default) means "nothing to precompute": an interceptor whose
    /// verdict does not factor through the keyexpr — a rate limiter, a size cap —
    /// correctly caches nothing, and [`Self::intercept_cached`] falls back to
    /// [`Self::intercept`] for it.
    ///
    /// [`Self::subject`]: InterceptorContext::subject
    /// [`Self::link_subject`]: InterceptorContext::link_subject
    fn compute_keyexpr_cache(
        &self,
        _ctx: &dyn InterceptorContext,
        _keyexpr: &str,
    ) -> Option<InterceptorCacheValue> {
        None
    }

    /// Whether to admit `msg`, given a cache value this interceptor produced
    /// earlier from [`Self::compute_keyexpr_cache`] for THIS message's
    /// (face, keyexpr). The default ignores the cache and asks
    /// [`Self::intercept`], which is what an interceptor that caches nothing
    /// wants.
    ///
    /// The cache is an OPTIMISATION and must never be a semantic difference: an
    /// implementation's cached answer has to equal what `intercept` would have
    /// returned. That equivalence is what makes the invalidation load-bearing
    /// rather than decorative — a chain swap that failed to invalidate would
    /// keep answering with the OLD policy, which is exactly the failure the
    /// version in [`InterceptorChain`] exists to prevent.
    /// R2701 — the borrowed form carries the same `Send + Sync` the owned
    /// [`InterceptorCacheValue`] does, as upstream's accessor does
    /// (`zenoh/src/net/routing/interceptor/mod.rs` @ `fn get_cache(&self, msg: &NetworkMessageMut) -> Option<&Box<dyn Any + Send + Sync>>;`).
    /// Not cosmetic: `Option<&(dyn Any + Send + Sync)>` does not coerce to
    /// `Option<&dyn Any>` — auto-trait removal is a coercion on the reference,
    /// not through the `Option` — so an unbounded parameter here would force
    /// every caller holding a real cache slot to launder it.
    fn intercept_cached(
        &self,
        ctx: &dyn InterceptorContext,
        msg: &NetworkMessage,
        _cache: Option<&(dyn Any + Send + Sync)>,
    ) -> bool {
        self.intercept(ctx, msg)
    }

    /// Whether this interceptor rewrites the QoS of the messages it is shown. The chain reads it
    /// once, when the interceptor is pushed, so that a chain with no rewriter takes no step on
    /// behalf of one: a forwarder asks [`InterceptorChain::overwrites_qos`] before it builds the
    /// context [`Self::overwrite_qos`] needs.
    #[cfg(feature = "access-qos-overwrite")]
    fn rewrites_qos(&self) -> bool {
        false
    }

    /// The QoS `msg` should leave this interceptor with, given the QoS it has reached it with.
    ///
    /// The one place an interceptor changes a message instead of judging it (zenoh's
    /// `InterceptorTrait::intercept` takes the message mutably; wz's takes it by reference, so
    /// the change is returned and the forwarder that owns the message writes it, which keeps a
    /// borrowed ingress message from being copied until a rule has changed it). `qos` is passed in
    /// rather than read off `msg` so that interceptors on one chain compose: each is handed what
    /// the earlier ones produced. The default changes nothing.
    ///
    /// `reliable` is the reliability of the frame the message rides, which a message does not
    /// carry itself (upstream reads it off the message it was decoded into).
    #[cfg(feature = "access-qos-overwrite")]
    fn overwrite_qos(
        &self,
        _ctx: &dyn InterceptorContext,
        _msg: &NetworkMessage,
        qos: wz_session_core::sample::QosLevel,
        _reliable: bool,
    ) -> wz_session_core::sample::QosLevel {
        qos
    }
}

/// What one interceptor precomputes for one (face, keyexpr) — the type
/// `Interceptor::compute_keyexpr_cache` returns and `InterceptorChain` stores
/// a slot of per interceptor.
///
/// R2701 — `Send + Sync` on the erased value, matching upstream's own cache
/// payload (`zenoh/src/net/routing/interceptor/mod.rs` @ `fn compute_keyexpr_cache(&self, key_expr: &keyexpr) -> Option<Box<dyn Any + Send + Sync>>;`).
/// A cache slot is reachable from whatever holds the chain, so a payload without
/// the bound would re-impose on every holder exactly the restriction the trait's
/// own bound just lifted. Named as an alias rather than spelled at each of the
/// four sites so the two cannot drift apart.
pub type InterceptorCacheValue = Box<dyn Any + Send + Sync>;

/// R311y508 — the per-(face, keyexpr) precomputed state for ONE chain, tagged
/// with the version of the chain that produced it. The wz mirror of zenoh's
/// `InterceptorCache` (`net/routing/dispatcher/resource.rs:91-117`), which
/// likewise stores the value beside `interceptor.version` and recomputes when
/// the two disagree.
///
/// The version is the whole point. Without it a live
/// [`InterceptorSink::set_interceptors`] would install a new chain while every
/// face kept answering out of state compiled against the OLD one — a reconfigure
/// that silently does nothing for exactly the keyexprs that were already busy.
pub struct InterceptorKeyexprCache {
    version: u64,
    per_interceptor: Vec<Option<InterceptorCacheValue>>,
}

impl InterceptorKeyexprCache {
    /// The version of the chain this cache was computed against.
    pub fn version(&self) -> u64 {
        self.version
    }
}

/// The composable interceptor chain — zenoh `InterceptorsChain`. A message is
/// admitted only when EVERY interceptor admits it; an EMPTY chain admits
/// everything, which is access control DISABLED (zenoh `AclConfig.enabled =
/// false`). A deploy installs the chain via the forwarder's `set_interceptors`.
#[derive(Default)]
pub struct InterceptorChain {
    interceptors: Vec<Box<dyn Interceptor>>,
    /// R311y508 — the chain's identity for cache invalidation, zenoh's
    /// `InterceptorsChain.version` fed by `Tables.next_interceptor_version`
    /// (`net/routing/dispatcher/tables.rs:84`). Monotonic per forwarder: every
    /// `set_interceptors` builds chains at a FRESH version, so every cache
    /// computed against a previous chain compares unequal and is recomputed.
    version: u64,
    /// Whether any interceptor on the chain rewrites QoS, read when each was pushed.
    #[cfg(feature = "access-qos-overwrite")]
    rewrites_qos: bool,
}

impl InterceptorChain {
    /// An empty chain — access control disabled (admits every message).
    pub fn new() -> Self {
        Self::default()
    }

    /// The chain's cache-invalidation version. See
    /// [`InterceptorKeyexprCache`].
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Stamp this chain with `version` — called by
    /// [`InterceptorConfig::build_chain_versioned`] so both flow chains of one
    /// install share it.
    pub fn set_version(&mut self, version: u64) {
        self.version = version;
    }

    /// Precompute every interceptor's keyexpr-derived state for
    /// (`subject`, `keyexpr`), tagged with this chain's version — zenoh's
    /// `InterceptorsChain::compute_keyexpr_cache`
    /// (`net/routing/interceptor/mod.rs:167-173`), which likewise collects one
    /// slot per interceptor so the per-message path can index positionally.
    pub fn compute_keyexpr_cache(
        &self,
        ctx: &dyn InterceptorContext,
        keyexpr: &str,
    ) -> InterceptorKeyexprCache {
        InterceptorKeyexprCache {
            version: self.version,
            per_interceptor: self
                .interceptors
                .iter()
                .map(|i| i.compute_keyexpr_cache(ctx, keyexpr))
                .collect(),
        }
    }

    /// Whether to ADMIT `msg` using `cache`, which MUST have been computed by
    /// this chain (same version) for this message's (face, keyexpr). A cache
    /// whose version disagrees, or whose slot count does not match, is IGNORED
    /// and every interceptor is asked directly — so a stale cache can only cost
    /// time, never change a verdict.
    pub fn admit_cached(
        &self,
        ctx: &dyn InterceptorContext,
        msg: &NetworkMessage,
        cache: Option<&InterceptorKeyexprCache>,
    ) -> InterceptorVerdict {
        let slots = cache.filter(|c| {
            c.version == self.version && c.per_interceptor.len() == self.interceptors.len()
        });
        match slots {
            Some(c) => {
                for (i, slot) in self.interceptors.iter().zip(c.per_interceptor.iter()) {
                    if !i.intercept_cached(ctx, msg, slot.as_deref()) {
                        return InterceptorVerdict::Drop(i.kind());
                    }
                }
                InterceptorVerdict::Admit
            }
            None => self.admit(ctx, msg),
        }
    }

    /// Whether the chain holds no interceptors (the fast path: a forwarder with
    /// no ACL configured skips context construction entirely).
    pub fn is_empty(&self) -> bool {
        self.interceptors.is_empty()
    }

    /// Append an interceptor to the chain.
    pub fn push(&mut self, interceptor: Box<dyn Interceptor>) {
        #[cfg(feature = "access-qos-overwrite")]
        {
            self.rewrites_qos |= interceptor.rewrites_qos();
        }
        self.interceptors.push(interceptor);
    }

    /// Whether any interceptor on the chain rewrites QoS. A forwarder asks before it builds the
    /// context [`Self::overwritten_qos`] needs, so a chain of an ACL and a size cap pays nothing.
    #[cfg(feature = "access-qos-overwrite")]
    pub fn overwrites_qos(&self) -> bool {
        self.rewrites_qos
    }

    /// The QoS `msg` leaves the chain with, or `None` when it leaves with the QoS it had (or
    /// carries none a rule may set). Each interceptor is handed what the earlier ones produced, in
    /// the chain's order. The caller writes the answer into the message it owns
    /// ([`qos_overwrite::apply_qos`]); the chain only decides.
    #[cfg(feature = "access-qos-overwrite")]
    pub fn overwritten_qos(
        &self,
        ctx: &dyn InterceptorContext,
        msg: &NetworkMessage,
        reliable: bool,
    ) -> Option<wz_session_core::sample::QosLevel> {
        if !self.rewrites_qos {
            return None;
        }
        let before = self::qos_overwrite::message_qos(msg)?;
        let after = self
            .interceptors
            .iter()
            .filter(|i| i.rewrites_qos())
            .fold(before, |qos, i| i.overwrite_qos(ctx, msg, qos, reliable));
        (after != before).then_some(after)
    }

    /// Whether to ADMIT `msg`: every interceptor must admit it (zenoh's chain
    /// runs each in order, dropping on the first that returns `false`). An
    /// empty chain admits.
    ///
    /// R2371 — the verdict NAMES the interceptor that dropped. The short-circuit
    /// is unchanged (`all` stopped at the first `false` too); what is new is
    /// that the answer says which one, which is what lets `transport-stats`
    /// charge upstream's separate downsampler / low-pass drop counters instead
    /// of one collapsed total.
    pub fn admit(&self, ctx: &dyn InterceptorContext, msg: &NetworkMessage) -> InterceptorVerdict {
        for i in &self.interceptors {
            if !i.intercept(ctx, msg) {
                return InterceptorVerdict::Drop(i.kind());
            }
        }
        InterceptorVerdict::Admit
    }
}

/// Which message flow a chain enforces — ingress (the inbound relay-admission
/// point) or egress (the outbound fan-out point). The SEAM-LOCAL flow
/// descriptor, kept free of the access-acl engine's [`AclFlow`] so a chain
/// builds for the downsampling / low-pass interceptors alone (access-acl
/// elided); it maps to `AclFlow` only where the ACL enforcer is constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptorFlow {
    /// Inbound messages arriving on a face (the relay-admission point).
    Ingress,
    /// Outbound messages leaving toward a face (the fan-out point).
    Egress,
}

impl InterceptorFlow {
    /// Both flows — the default a per-rule `flows` selector inherits when a
    /// deploy does not narrow it, mirroring zenoh's
    /// `flows.get_or_insert(nev![Ingress, Egress])`
    /// (`net/routing/interceptor/low_pass.rs:83-85`). R311y451.
    pub const ALL: [InterceptorFlow; 2] = [InterceptorFlow::Ingress, InterceptorFlow::Egress];

    /// R2650 — upstream's wire spelling, from its
    /// `commons/zenoh-config/src/lib.rs`
    /// @ `pub enum InterceptorFlow`, which a config document names on the
    /// `flows` axis of both interceptor keys.
    ///
    /// Exhaustive on purpose: a third direction would stop this COMPILING
    /// rather than quietly acquiring no spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            InterceptorFlow::Ingress => "ingress",
            InterceptorFlow::Egress => "egress",
        }
    }

    /// The flow upstream spells `text`, or `None` — derived from [`Self::ALL`]
    /// through [`Self::as_str`], so the inverse cannot drift from the table.
    pub fn from_upstream_str(text: &str) -> Option<InterceptorFlow> {
        InterceptorFlow::ALL
            .iter()
            .copied()
            .find(|f| f.as_str() == text)
    }
}

#[cfg(feature = "access-acl")]
impl From<InterceptorFlow> for AclFlow {
    fn from(flow: InterceptorFlow) -> Self {
        match flow {
            InterceptorFlow::Ingress => AclFlow::Ingress,
            InterceptorFlow::Egress => AclFlow::Egress,
        }
    }
}

/// The full §5.16 interceptor configuration — the SINGLE funnel a deploy fills,
/// the wz mirror of the config slices zenoh's `interceptor_factories` reads
/// (`config.downsampling()` / `config.access_control()` /
/// `config.low_pass_filter()`, `net/routing/interceptor/mod.rs:133-136`). The
/// forwarder builds BOTH flow chains from one value of this via
/// [`build_chain`](Self::build_chain), so a deploy configures the whole pipeline
/// once rather than through three independent, order-dependent, append-only
/// setters (the footgun the R311tx review flagged: re-calling a setter
/// duplicated an interceptor, and the cross-setter order was unspecified). Each
/// field is present only when its `access-*` feature is enabled; an all-elided
/// config is the empty struct (access control disabled).
///
/// R311y39 — `Debug + Clone` so the typed [`crate::config::WzConfig`] SSOT
/// can hold + re-apply it (the config keeps its copy as the introspection
/// source while driving the forwarder from a clone).
#[derive(Debug, Clone, Default)]
pub struct InterceptorConfig {
    /// The access-control policy, or `None` for no ACL enforcer (zenoh
    /// `AclConfig.enabled = false`). Present only under `access-acl`.
    #[cfg(feature = "access-acl")]
    pub acl: Option<AclPolicy>,
    /// The downsampling (rate-limit) rules; empty installs no downsampling
    /// interceptor. Present only under `access-downsampling`.
    #[cfg(feature = "access-downsampling")]
    pub downsampling: Vec<DownsamplingRule>,
    /// The low-pass (per-key payload-size cap) rules; empty installs no low-pass
    /// interceptor. Present only under `access-quota`.
    #[cfg(feature = "access-quota")]
    pub low_pass: Vec<LowPassRule>,
    /// The QoS overwrite rules (`qos/network`); empty installs no overwriting interceptor.
    /// Present only under `access-qos-overwrite`.
    #[cfg(feature = "access-qos-overwrite")]
    pub qos_overwrite: Vec<QosOverwriteRule>,
    /// Whether this config governs a MULTICAST session too. `false` (the default) is upstream's
    /// shape: it installs no interceptor on a multicast transport, so a policy written for the
    /// node's unicast sessions leaves its groups alone. `true` applies the whole pipeline above
    /// to the group's traffic, in both directions, with the group's link as the only subject (a
    /// group has no peer identity, so a rule scoped by a user, a certificate or a zid never
    /// matches there). Present only under `access-acl-multicast`; a unicast session ignores it.
    #[cfg(feature = "access-acl-multicast")]
    pub govern_multicast: bool,
}

impl InterceptorConfig {
    /// Whether this config asks for no interception at all, so a caller can keep every fast path
    /// it has for a node that wants none.
    ///
    /// Moved here from `document`, which is gated on `zenoh-config`: the answer reads only this
    /// struct's own fields, each under its own feature, and a session that wants to say a policy
    /// it was handed governs nothing has no document to read.
    pub fn is_inert(&self) -> bool {
        #[allow(unused_mut)]
        let mut inert = true;
        #[cfg(feature = "access-acl")]
        {
            inert &= self.acl.is_none();
        }
        #[cfg(feature = "access-downsampling")]
        {
            inert &= self.downsampling.is_empty();
        }
        #[cfg(feature = "access-quota")]
        {
            inert &= self.low_pass.is_empty();
        }
        #[cfg(feature = "access-qos-overwrite")]
        {
            inert &= self.qos_overwrite.is_empty();
        }
        inert
    }

    /// Set whether the pipeline also governs multicast sessions, returning `self` for chaining.
    /// See [`with_acl`](Self::with_acl) for why this is a builder.
    #[cfg(feature = "access-acl-multicast")]
    #[must_use]
    pub fn with_govern_multicast(mut self, govern: bool) -> Self {
        self.govern_multicast = govern;
        self
    }

    /// R311y453 — set the ACL policy, returning `self` for chaining.
    ///
    /// These three builders exist because a STRUCT LITERAL of this type cannot be
    /// written feature-agnostically: which fields exist depends on the enabled
    /// `access-*` set, so `InterceptorConfig { low_pass, ..Default::default() }`
    /// is correct under the full set and a `clippy::needless_update` error under
    /// `access-quota` alone — the shape that made `--all-targets -D warnings` fail
    /// on four of the eight access subsets (recorded as a pre-existing defect in
    /// the R311y452 carry). Assigning onto a `default()` instead just trades that
    /// for `clippy::field_reassign_with_default`. A builder has neither problem,
    /// and a caller no longer has to know which fields its feature set compiled.
    #[cfg(feature = "access-acl")]
    #[must_use]
    pub fn with_acl(mut self, policy: AclPolicy) -> Self {
        self.acl = Some(policy);
        self
    }

    /// Set the downsampling (rate-limit) rules, returning `self` for chaining.
    /// See [`with_acl`](Self::with_acl) for why these are builders.
    #[cfg(feature = "access-downsampling")]
    #[must_use]
    pub fn with_downsampling(mut self, rules: Vec<DownsamplingRule>) -> Self {
        self.downsampling = rules;
        self
    }

    /// Set the low-pass (per-key size cap) rules, returning `self` for chaining.
    /// See [`with_acl`](Self::with_acl) for why these are builders.
    #[cfg(feature = "access-quota")]
    #[must_use]
    pub fn with_low_pass(mut self, rules: Vec<LowPassRule>) -> Self {
        self.low_pass = rules;
        self
    }

    /// Set the QoS overwrite rules, returning `self` for chaining.
    /// See [`with_acl`](Self::with_acl) for why these are builders.
    #[cfg(feature = "access-qos-overwrite")]
    #[must_use]
    pub fn with_qos_overwrite(mut self, rules: Vec<QosOverwriteRule>) -> Self {
        self.qos_overwrite = rules;
        self
    }

    /// Build the interceptor chain for `flow`, in zenoh's FIXED factory order:
    /// downsampling, then access-control, then the QoS overwrite, then low-pass
    /// (`zenoh/src/net/routing/interceptor/mod.rs` @ `res.extend(qos_overwrite_interceptor_factories(`).
    /// The order is deterministic regardless of which features a
    /// deploy enables — unlike per-setter append order, which depended on call
    /// order. Each flow gets its OWN interceptor instances (a per-flow
    /// downsampling timer, a per-flow ACL enforcer bound to `flow`), as zenoh
    /// keeps separate per-flow enforcers. An empty config — or one whose
    /// interceptors are all feature-elided — yields an empty chain (access
    /// control disabled, every message admitted).
    pub fn build_chain(&self, flow: InterceptorFlow) -> InterceptorChain {
        // `flow` is consumed by the access-acl ACL push (mapped to `AclFlow`),
        // by the low-pass per-rule `flows` selector (R311y451) and by the
        // downsampler's (R311y452). With ALL THREE elided the chain is
        // flow-agnostic.
        #[cfg(not(any(
            feature = "access-acl",
            feature = "access-downsampling",
            feature = "access-quota",
            feature = "access-qos-overwrite"
        )))]
        let _ = flow;
        // `mut` is exercised by whichever interceptor pushes compile in; a
        // routing-peer build with no access knob leaves the chain empty.
        #[allow(unused_mut)]
        let mut chain = InterceptorChain::new();
        // R311y452 — the downsampling rules are FLOW-SCOPED, and each flow gets
        // its OWN rule timers: only the subset whose `flows` names this flow is
        // installed, and a flow no rule governs gets no interceptor at all
        // (zenoh's `self.flows.<flow>.then(...)`, `downsampling.rs:133-152`).
        #[cfg(feature = "access-downsampling")]
        if let Some(downsampling) = DownsamplingInterceptor::for_flow(&self.downsampling, flow) {
            chain.push(Box::new(downsampling));
        }
        #[cfg(feature = "access-acl")]
        if let Some(policy) = &self.acl {
            chain.push(Box::new(AclInterceptor::new(policy.clone(), flow.into())));
        }
        // The QoS overwrite rules are FLOW-SCOPED as the low-pass ones are, and sit between the
        // ACL and the low-pass cap as upstream installs them: a message is judged by the ACL on
        // the QoS it arrived with, and the cap reads the size, which no rewrite changes.
        #[cfg(feature = "access-qos-overwrite")]
        if let Some(overwrite) = QosOverwriteInterceptor::for_flow(&self.qos_overwrite, flow) {
            chain.push(Box::new(overwrite));
        }
        // R311y451 — the low-pass rules are FLOW-SCOPED: only the subset whose
        // `flows` names this flow is installed, and a flow no rule governs gets
        // no interceptor at all (zenoh's `interface_enabled.<flow>.then(...)`,
        // `low_pass.rs:188-205`).
        #[cfg(feature = "access-quota")]
        if let Some(low_pass) = LowPassInterceptor::for_flow(&self.low_pass, flow) {
            chain.push(Box::new(low_pass));
        }
        chain
    }

    /// R311y508 — [`Self::build_chain`], stamped with the install's cache
    /// version. zenoh does the same in one step
    /// (`FaceState::set_interceptors_from_factories(&factories, version)`,
    /// reached from `TablesLock::regen_interceptors`, which bumps
    /// `next_interceptor_version` first and hands the SAME value to every face);
    /// wz splits the build from the stamp only because both flow chains come
    /// from one config and must share the version.
    pub fn build_chain_versioned(&self, flow: InterceptorFlow, version: u64) -> InterceptorChain {
        let mut chain = self.build_chain(flow);
        chain.set_version(version);
        chain
    }
}

/// R311y43 — the sink an [`InterceptorConfig`] is installed onto: the seam the
/// typed [`crate::config::WzConfig`] SSOT drives, decoupled from the concrete
/// forwarder type. `WzConfig::install_interceptors` / `reconfigure_interceptors`
/// take `&dyn InterceptorSink`, so the §5.23 combined node composes the
/// config-drive surface against this abstraction rather than the concrete
/// `RouterForwarder` of `crate::router_forward` (which is the production
/// impl; the module exists with `routing-router-hat`, so a link to it would not resolve in a
/// build without). One method — re-install both flow chains from the given config — so a
/// reconfigure re-drives the live verdict through the same path setup uses.
pub trait InterceptorSink {
    /// Re-install the ingress + egress interceptor chains built from `config`
    /// (replaces, not appends — idempotent), exactly as a one-shot deploy setup
    /// does. See [`InterceptorConfig::build_chain`] for the fixed factory order.
    fn set_interceptors(&self, config: InterceptorConfig);
}
