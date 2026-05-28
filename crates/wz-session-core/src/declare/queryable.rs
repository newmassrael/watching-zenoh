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

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use hashbrown::HashMap;

use wz_codecs::decl_queryable::DeclQueryable;
use wz_codecs::declare::DeclareVariant;
use wz_codecs::undecl_queryable::UndeclQueryable;

use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
use crate::keyexpr_match::keyexpr_intersect_patterns;
use crate::network_message::NetworkMessage;
use crate::wireexpr_resolve::resolve_wireexpr;

/// Boxed callback invoked when an inbound
/// `Declare(DeclQueryable)` is decoded and its keyexpr resolves to a
/// literal. Same shape as the subscriber-side callback — the codec
/// records carry identical field layout (header / id / keyexpr) and
/// the application-level "peer declared a queryable on this keyexpr"
/// signal mirrors the subscriber surface; consumers may install a
/// queryable-side counterpart of every subscriber-side hook (metrics,
/// route table, debug log).
pub type DeclQueryableCallback = Box<dyn FnMut(&DeclQueryable, &str) + Send + 'static>;

/// Boxed callback invoked when an inbound
/// `Declare(UndeclQueryable)` is decoded. The undeclare body has no
/// keyexpr field; the peer identifies the prior queryable by `id`.
pub type UndeclQueryableCallback = Box<dyn FnMut(&UndeclQueryable) + Send + 'static>;

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
pub struct RemoteQueryableRegistry {
    on_decl: Vec<DeclQueryableCallback>,
    on_undecl: Vec<UndeclQueryableCallback>,
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
    declared: HashMap<u64, String>,
}

impl Default for RemoteQueryableRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RemoteQueryableRegistry {
    /// New empty registry. Both callback lists start empty; an empty
    /// registry processes inbound `Declare(Decl*Queryable)` records
    /// as no-ops.
    pub fn new() -> Self {
        Self {
            on_decl: Vec::new(),
            on_undecl: Vec::new(),
            declared: HashMap::new(),
        }
    }

    /// Install a callback fired on every inbound
    /// `Declare(DeclQueryable)` whose keyexpr resolves through the
    /// peer keyexpr table. Duplicate callbacks allowed; dispatch
    /// fires them in registration order.
    pub fn on_queryable_declared(
        &mut self,
        callback: impl FnMut(&DeclQueryable, &str) + Send + 'static,
    ) {
        self.on_decl.push(Box::new(callback));
    }

    /// Install a callback fired on every inbound
    /// `Declare(UndeclQueryable)`.
    pub fn on_queryable_undeclared(
        &mut self,
        callback: impl FnMut(&UndeclQueryable) + Send + 'static,
    ) {
        self.on_undecl.push(Box::new(callback));
    }

    /// Number of installed `on_queryable_declared` callbacks.
    pub fn on_decl_len(&self) -> usize {
        self.on_decl.len()
    }

    /// Number of installed `on_queryable_undeclared` callbacks.
    pub fn on_undecl_len(&self) -> usize {
        self.on_undecl.len()
    }

    /// R288 — count of currently-declared peer queryables (those whose
    /// inbound `DeclQueryable` has been dispatched and whose
    /// `UndeclQueryable` has not). Exposed for diagnostic surfaces
    /// (test fixtures, metrics) and for the `get_matching_status`
    /// implementation that wants to short-circuit when no peer is
    /// declared at all.
    pub fn declared_count(&self) -> usize {
        self.declared.len()
    }

    /// R288 — iterate over currently-declared peer queryables as
    /// `(id, resolved_keyexpr)` pairs. Ordering is unspecified (the
    /// backing storage is a `HashMap`). Useful for debug surfaces
    /// that want to enumerate every peer-side declaration; the
    /// `has_matching` accessor below is the production consult
    /// path.
    pub fn iter_declared(&self) -> impl Iterator<Item = (u64, &str)> + '_ {
        self.declared.iter().map(|(id, ke)| (*id, ke.as_str()))
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
    pub fn has_matching(&self, query_keyexpr: &str) -> bool {
        let query_chunks: Vec<&str> = query_keyexpr.split('/').collect();
        self.declared.values().any(|peer_keyexpr| {
            let peer_chunks: Vec<&str> = peer_keyexpr.split('/').collect();
            keyexpr_intersect_patterns(&peer_chunks, &query_chunks)
        })
    }

    /// Route an inbound `Declare` envelope's inner body through the
    /// remote-queryable callbacks. Same scope rules as
    /// [`crate::declare::subscriber::RemoteSubscriberRegistry::dispatch_declare`]:
    /// only `DeclQueryable` / `UndeclQueryable` arms route here,
    /// others (Subscriber, Token, Kexpr, Final) are no-ops at this
    /// layer.
    pub fn dispatch_declare(
        &mut self,
        body: &DeclareVariant,
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        match body {
            DeclareVariant::CodecZenohDeclQueryable(decl) => {
                let resolved = match resolve_wireexpr(&decl.keyexpr.body, peer_keyexpr_table) {
                    Some(s) => s,
                    None => return,
                };
                // R288 — track peer-declared queryable so
                // get_matching_status can consult the membership at
                // a later point. Late-arrival semantics — a
                // subsequent declare with the same id overwrites
                // the prior entry (peer renamed the keyexpr), which
                // matches zenoh-pico's same-id-replaces behaviour.
                self.declared.insert(decl.id, resolved.clone());
                for cb in &mut self.on_decl {
                    cb(decl, &resolved);
                }
            }
            DeclareVariant::CodecZenohUndeclQueryable(undecl) => {
                // R288 — drop the membership entry first so a
                // get_matching_status fired from inside the
                // on_undecl callback chain observes the post-
                // undeclare state. Missing-id remove is silent
                // (peer sent UndeclQueryable for an id we never
                // saw a DeclQueryable for; this is a peer-side
                // contract violation we do not surface here).
                self.declared.remove(&undecl.id);
                for cb in &mut self.on_undecl {
                    cb(undecl);
                }
            }
            // Other sub-variants do not reach this registry.
            _ => {}
        }
    }

    /// Drain a `Vec<NetworkMessage>` through [`Self::dispatch_declare`].
    /// Mirror of the sibling registries.
    pub fn dispatch_messages(
        &mut self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        for message in messages {
            if let NetworkMessage::Declare(decl) = message {
                self.dispatch_declare(&decl.body, peer_keyexpr_table);
            }
        }
    }

    /// `IterationEvent` adapter; mirror of the sibling registries.
    pub fn dispatch_iteration_event(
        &mut self,
        event: IterationEvent<'_>,
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event {
            self.dispatch_messages(messages, peer_keyexpr_table);
        }
    }
}
