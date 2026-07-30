// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
#[cfg(feature = "access-downsampling")]
pub mod downsampling;
#[cfg(feature = "access-quota")]
pub mod low_pass;

#[cfg(feature = "access-acl")]
use wz_access_control::{AclFlow, AclPolicy};
use wz_routing_graph::Zid;
use wz_session_core::link::LinkSubject;
use wz_session_core::network_message::NetworkMessage;

#[cfg(feature = "access-acl")]
use self::access_control::AclInterceptor;
#[cfg(feature = "access-downsampling")]
use self::downsampling::{DownsamplingInterceptor, DownsamplingRule};
#[cfg(feature = "access-quota")]
use self::low_pass::{LowPassInterceptor, LowPassRule};

/// The per-message context an [`Interceptor`] reads — the wz mirror of zenoh
/// `InterceptorContext`. The resolved subject (who is on the other end of the
/// face) and a face-local keyexpr resolver. Implemented by the forwarder, which
/// owns the per-face alias table and transport identity; the interceptor stays
/// free of face internals.
pub trait InterceptorContext {
    /// The request's subject — the routing identity of the peer on the other
    /// end of the face (the auth-free ACL subject). `None` when the face has no
    /// resolved identity yet, in which case an enforcer admits (it cannot
    /// attribute the message to a subject).
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
    /// re-resolution (see [`LinkSubject`](wz_session_core::link::LinkSubject)).
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
}

/// One message interceptor — zenoh `InterceptorTrait::intercept(msg) -> bool`.
/// Returns `true` to ADMIT the message, `false` to drop it. The implementation
/// dispatches internally on the message kind (it checks only the kinds it
/// governs and admits the rest).
pub trait Interceptor {
    /// Whether to admit `msg`, given the per-message `ctx`.
    fn intercept(&self, ctx: &dyn InterceptorContext, msg: &NetworkMessage) -> bool;
}

/// The composable interceptor chain — zenoh `InterceptorsChain`. A message is
/// admitted only when EVERY interceptor admits it; an EMPTY chain admits
/// everything, which is access control DISABLED (zenoh `AclConfig.enabled =
/// false`). A deploy installs the chain via the forwarder's `set_interceptors`.
#[derive(Default)]
pub struct InterceptorChain {
    interceptors: Vec<Box<dyn Interceptor>>,
}

impl InterceptorChain {
    /// An empty chain — access control disabled (admits every message).
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the chain holds no interceptors (the fast path: a forwarder with
    /// no ACL configured skips context construction entirely).
    pub fn is_empty(&self) -> bool {
        self.interceptors.is_empty()
    }

    /// Append an interceptor to the chain.
    pub fn push(&mut self, interceptor: Box<dyn Interceptor>) {
        self.interceptors.push(interceptor);
    }

    /// Whether to ADMIT `msg`: every interceptor must admit it (zenoh's chain
    /// runs each in order, dropping on the first that returns `false`). An
    /// empty chain admits.
    pub fn admit(&self, ctx: &dyn InterceptorContext, msg: &NetworkMessage) -> bool {
        self.interceptors.iter().all(|i| i.intercept(ctx, msg))
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
}

impl InterceptorConfig {
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

    /// Build the interceptor chain for `flow`, in zenoh's FIXED factory order:
    /// downsampling, then access-control, then low-pass (zenoh
    /// `interceptor_factories` `mod.rs:133-136`, minus the qos-overwrite wz does
    /// not implement). The order is deterministic regardless of which features a
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
            feature = "access-quota"
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
}

/// R311y43 — the sink an [`InterceptorConfig`] is installed onto: the seam the
/// typed [`crate::config::WzConfig`] SSOT drives, decoupled from the concrete
/// forwarder type. `WzConfig::install_interceptors` / `reconfigure_interceptors`
/// take `&dyn InterceptorSink`, so the §5.23 combined node composes the
/// config-drive surface against this abstraction rather than the concrete
/// [`crate::linkstate_forward::LinkstateForwarder`] (which is the production
/// impl). One method — re-install both flow chains from the given config — so a
/// reconfigure re-drives the live verdict through the same path setup uses.
pub trait InterceptorSink {
    /// Re-install the ingress + egress interceptor chains built from `config`
    /// (replaces, not appends — idempotent), exactly as a one-shot deploy setup
    /// does. See [`InterceptorConfig::build_chain`] for the fixed factory order.
    fn set_interceptors(&self, config: InterceptorConfig);
}
