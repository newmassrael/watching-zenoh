// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `LivelinessRegistry` — application-layer registry tracking the
//! peer's outbound `DeclToken` / `UndeclToken` records, i.e. the
//! liveliness layer in zenoh's protocol stack
//! (`_z_liveliness_process_token_declare` /
//! `_z_liveliness_process_token_undeclare` upstream).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use hashbrown::HashMap;

use wz_codecs::decl_token::DeclToken;
use wz_codecs::declare::DeclareVariant;
use wz_codecs::undecl_token::UndeclToken;

use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
use crate::network_message::NetworkMessage;
use crate::wireexpr_resolve::resolve_wireexpr;

/// Boxed callback invoked when an inbound `Declare(DeclToken)` is
/// decoded and its keyexpr resolves to a literal. Liveliness signal —
/// "an entity (process / device / sub-system) just declared itself
/// alive on keyexpr X". Consumers wire this into watchdog or
/// presence-detection logic, e.g. a UI that surfaces "online" badges.
pub type DeclTokenCallback = Box<dyn FnMut(&DeclToken, &str) + Send + 'static>;

/// Boxed callback invoked when an inbound `Declare(UndeclToken)` is
/// decoded. The undeclare body carries only `id: u64`; the peer
/// identifies the prior liveliness token by the same id used in its
/// earlier `DeclToken`. Liveliness signal — "the entity that was
/// alive on keyexpr X is now gone (graceful undeclare; lease-based
/// expiry surfaces separately through the session FSM)".
pub type UndeclTokenCallback = Box<dyn FnMut(&UndeclToken) + Send + 'static>;

/// Application-layer registry tracking the peer's outbound
/// `DeclToken` / `UndeclToken` records — the liveliness layer in
/// zenoh's protocol stack (`_z_liveliness_process_token_declare` /
/// `_z_liveliness_process_token_undeclare` upstream).
///
/// Why a separate registry rather than reusing the subscriber or
/// queryable Remote* registries: liveliness signals are a distinct
/// application surface from pub/sub topology — a consumer that wires
/// "process X is alive" logic does not (and should not) also fire on
/// "process X just subscribed to Y". Keeping the registries split
/// matches zenoh-pico's structural separation and lets consumers
/// reason about each surface independently.
pub struct LivelinessRegistry {
    on_decl: Vec<DeclTokenCallback>,
    on_undecl: Vec<UndeclTokenCallback>,
}

impl Default for LivelinessRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LivelinessRegistry {
    /// New empty registry. Both callback lists start empty; an empty
    /// registry processes inbound `Declare(Decl*Token)` records as
    /// no-ops.
    pub fn new() -> Self {
        Self {
            on_decl: Vec::new(),
            on_undecl: Vec::new(),
        }
    }

    /// Install a callback fired on every inbound
    /// `Declare(DeclToken)` whose keyexpr resolves through the peer
    /// keyexpr table. Duplicate callbacks allowed; dispatch fires
    /// them in registration order.
    pub fn on_token_declared(&mut self, callback: impl FnMut(&DeclToken, &str) + Send + 'static) {
        self.on_decl.push(Box::new(callback));
    }

    /// Install a callback fired on every inbound
    /// `Declare(UndeclToken)`.
    pub fn on_token_undeclared(&mut self, callback: impl FnMut(&UndeclToken) + Send + 'static) {
        self.on_undecl.push(Box::new(callback));
    }

    /// Number of installed `on_token_declared` callbacks.
    pub fn on_decl_len(&self) -> usize {
        self.on_decl.len()
    }

    /// Number of installed `on_token_undeclared` callbacks.
    pub fn on_undecl_len(&self) -> usize {
        self.on_undecl.len()
    }

    /// Route an inbound `Declare` envelope's inner body through the
    /// liveliness callbacks. Only `DeclToken` / `UndeclToken` arms
    /// route here; Subscriber, Queryable, Kexpr, and Final arms are
    /// handled by their own dedicated registries.
    pub fn dispatch_declare(
        &mut self,
        body: &DeclareVariant,
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        match body {
            DeclareVariant::CodecZenohDeclToken(decl) => {
                let resolved = match resolve_wireexpr(&decl.keyexpr.body, peer_keyexpr_table) {
                    Some(s) => s,
                    None => return,
                };
                for cb in &mut self.on_decl {
                    cb(decl, &resolved);
                }
            }
            DeclareVariant::CodecZenohUndeclToken(undecl) => {
                for cb in &mut self.on_undecl {
                    cb(undecl);
                }
            }
            // Other sub-variants do not reach this registry.
            _ => {}
        }
    }

    /// Drain a `Vec<NetworkMessage>` through [`Self::dispatch_declare`].
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

    /// `IterationEvent` adapter; mirror of the other Remote* registries.
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
