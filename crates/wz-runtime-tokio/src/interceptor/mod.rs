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

pub mod access_control;
pub mod downsampling;
pub mod low_pass;

use wz_routing_graph::Zid;
use wz_session_core::network_message::NetworkMessage;

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
/// false`). A deploy installs an enforcer via the forwarder's `set_acl_policy`.
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
