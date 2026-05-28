// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use hashbrown::HashMap;

use wz_codecs::decl_subscriber::DeclSubscriber;
use wz_codecs::declare::DeclareVariant;
use wz_codecs::undecl_subscriber::UndeclSubscriber;

use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
use crate::keyexpr_match::keyexpr_intersect_patterns;
use crate::network_message::NetworkMessage;
use crate::wireexpr_resolve::resolve_wireexpr;

/// Boxed callback invoked when an inbound
/// `Declare(DeclSubscriber)` is decoded and its keyexpr resolves to a
/// literal. The callback receives the codec record + the resolved
/// keyexpr literal so consumers don't have to re-resolve.
pub type DeclSubscriberCallback = Box<dyn FnMut(&DeclSubscriber, &str) + Send + 'static>;

/// Boxed callback invoked when an inbound
/// `Declare(UndeclSubscriber)` is decoded. The undeclare body has no
/// keyexpr field; the peer identifies the prior subscription by `id`.
pub type UndeclSubscriberCallback = Box<dyn FnMut(&UndeclSubscriber) + Send + 'static>;

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
pub struct RemoteSubscriberRegistry {
    on_decl: Vec<DeclSubscriberCallback>,
    on_undecl: Vec<UndeclSubscriberCallback>,
    /// R290 — peer-declared subscribers tracked by `{id -> resolved
    /// keyexpr}`. Pub-side analogue of the `declared` map landed on
    /// [`crate::declare::queryable::RemoteQueryableRegistry`] in R288.
    /// Populated on every inbound `DeclSubscriber` whose keyexpr
    /// resolves through `peer_keyexpr_table`, and entries removed on
    /// the matching `UndeclSubscriber`. Backbone for the publisher-
    /// side `get_matching_status` consult which iterates this map at
    /// query time to decide whether any currently-declared peer
    /// subscriber's keyexpr intersects the publisher's keyexpr.
    ///
    /// Same HashMap rationale as the Q-side: by-id membership
    /// invariant, by-id Undecl removal, no ordering dependency on
    /// the rare full-iteration consult path.
    declared: HashMap<u64, String>,
}

impl Default for RemoteSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RemoteSubscriberRegistry {
    /// New empty registry. Both callback lists start empty; an empty
    /// registry processes inbound `Declare(Decl*)` records as no-ops.
    pub fn new() -> Self {
        Self {
            on_decl: Vec::new(),
            on_undecl: Vec::new(),
            declared: HashMap::new(),
        }
    }

    /// Install a callback fired on every inbound
    /// `Declare(DeclSubscriber)` whose keyexpr resolves through the
    /// peer keyexpr table. Duplicate callbacks are explicitly allowed
    /// (e.g. one for metrics, one for route-table maintenance);
    /// dispatch fires them in registration order.
    pub fn on_subscriber_declared(
        &mut self,
        callback: impl FnMut(&DeclSubscriber, &str) + Send + 'static,
    ) {
        self.on_decl.push(Box::new(callback));
    }

    /// Install a callback fired on every inbound
    /// `Declare(UndeclSubscriber)`. Same registration-order +
    /// duplicates-allowed contract as
    /// [`Self::on_subscriber_declared`].
    pub fn on_subscriber_undeclared(
        &mut self,
        callback: impl FnMut(&UndeclSubscriber) + Send + 'static,
    ) {
        self.on_undecl.push(Box::new(callback));
    }

    /// Number of installed `on_subscriber_declared` callbacks.
    pub fn on_decl_len(&self) -> usize {
        self.on_decl.len()
    }

    /// Number of installed `on_subscriber_undeclared` callbacks.
    pub fn on_undecl_len(&self) -> usize {
        self.on_undecl.len()
    }

    /// R290 — count of currently-declared peer subscribers (those
    /// whose inbound `DeclSubscriber` has been dispatched and whose
    /// `UndeclSubscriber` has not). Pub-side mirror of the Q-side
    /// `declared_count`.
    pub fn declared_count(&self) -> usize {
        self.declared.len()
    }

    /// R290 — iterate over currently-declared peer subscribers as
    /// `(id, resolved_keyexpr)` pairs. Pub-side mirror of the Q-side
    /// `iter_declared`. Ordering is unspecified (HashMap iteration).
    pub fn iter_declared(&self) -> impl Iterator<Item = (u64, &str)> + '_ {
        self.declared.iter().map(|(id, ke)| (*id, ke.as_str()))
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
    pub fn has_matching(&self, publish_keyexpr: &str) -> bool {
        let publish_chunks: Vec<&str> = publish_keyexpr.split('/').collect();
        self.declared.values().any(|peer_keyexpr| {
            let peer_chunks: Vec<&str> = peer_keyexpr.split('/').collect();
            keyexpr_intersect_patterns(&peer_chunks, &publish_chunks)
        })
    }

    /// Route an inbound `Declare` envelope's inner body through the
    /// remote-subscriber callbacks. `DeclareVariant` arms other than
    /// `DeclSubscriber` / `UndeclSubscriber` are no-ops here — the
    /// queryable / token / kexpr / final arms route through their own
    /// dedicated registries.
    ///
    /// `peer_keyexpr_table` is the same table maintained by the
    /// session-level `SubscriberRegistry` from inbound
    /// `Declare(DeclKexpr)` records. Unresolvable keyexprs (mapping
    /// id not yet declared) drop the dispatch silently rather than
    /// firing on a partial keyexpr.
    pub fn dispatch_declare(
        &mut self,
        body: &DeclareVariant,
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        match body {
            DeclareVariant::CodecZenohDeclSubscriber(decl) => {
                let resolved = match resolve_wireexpr(&decl.keyexpr.body, peer_keyexpr_table) {
                    Some(s) => s,
                    None => return,
                };
                // R290 — same membership-tracking pattern as the
                // Q-side registry: same-id-replaces semantic, no
                // explicit conflict surfacing.
                self.declared.insert(decl.id, resolved.clone());
                for cb in &mut self.on_decl {
                    cb(decl, &resolved);
                }
            }
            DeclareVariant::CodecZenohUndeclSubscriber(undecl) => {
                // R290 — drop the membership entry first so a
                // get_matching_status fired from inside the
                // on_undecl callback chain observes the post-
                // undeclare state.
                self.declared.remove(&undecl.id);
                for cb in &mut self.on_undecl {
                    cb(undecl);
                }
            }
            // Other sub-variants do not reach this registry.
            _ => {}
        }
    }

    /// Drain a `Vec<NetworkMessage>` (typically the
    /// `FramePayload.messages` field surfaced by the production
    /// driver loop) through [`Self::dispatch_declare`]. Mirrors the
    /// sibling registries so the observer in production code can fan
    /// one event into every registry uniformly.
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

    /// Convenience adapter that pulls the `FramePayload.messages` out
    /// of an `IterationEvent::Poll(DriverLoopOutcome::FramePayload)`
    /// and forwards to [`Self::dispatch_messages`]. Mirror of the
    /// sibling registries. Other `IterationEvent` variants (`Lease`,
    /// non-FramePayload `Poll` outcomes) are no-ops.
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
