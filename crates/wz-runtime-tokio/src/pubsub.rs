// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Application-layer subscriber registry — routes decoded
//! `NetworkMessage::Push` records to user-registered callbacks
//! filtered by keyexpr literal.
//!
//! ## Scope (R98 — AP MVP critical path)
//!
//! - Push messages only. R90 landed Push decoding; R98 wires the
//!   FramePayload → subscriber → callback path so an application can
//!   actually observe pub/sub data over a session.
//! - Literal keyexpr matching only. A registered subscriber's filter
//!   is matched against `Push.keyexpr.suffix` (the inline
//!   UTF-8 string) when `Push.keyexpr.id == 0` (sentinel mapping).
//!   Non-zero mapping ids reference a DECLARE-established table that
//!   this crate does NOT model yet; such Pushes are filtered out at
//!   dispatch time and never invoke a callback. Closing that gap
//!   requires the DECLARE codec chain (deferred).
//! - Reply / Err / Interest / OAM dispatch are NOT routed through
//!   the registry in R98. They land in a future round once a use
//!   case surfaces — pub/sub demo is sufficient for the AP MVP.
//!
//! ## Threading
//!
//! Registry is `!Sync` by design. Callers that need shared mutation
//! across tasks wrap the registry in `Arc<Mutex<SubscriberRegistry>>`
//! (or `tokio::sync::Mutex` for await-safe locking). Keeping the
//! registry single-owner avoids paying mutex overhead on the hot
//! dispatch path when no sharing is needed.
//!
//! ## Callback lifetime
//!
//! Callbacks are `Box<dyn FnMut(&Push) + Send + 'static>` so the
//! registry can outlive any reference the callback captures
//! (callbacks must own or `Arc`-share their captured state). `FnMut`
//! permits closures that mutate captured state (typical counter /
//! buffer accumulation patterns); `Send` permits the registry to
//! cross task boundaries when wrapped in `Arc<Mutex<…>>`. The
//! callback receives the decoded `Push` by reference so the
//! application can inspect `Push.body` (msg_put / msg_del peek-byte
//! variant) without taking ownership.

use wz_codecs::push::Push;

use crate::session_glue::NetworkMessage;

/// Boxed callback invoked when a Push message's keyexpr matches a
/// registered subscriber. See module-level docs for the lifetime and
/// thread-safety contract.
pub type SubscriberCallback = Box<dyn FnMut(&Push) + Send + 'static>;

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

struct Subscriber {
    id: SubscriptionId,
    keyexpr_literal: String,
    callback: SubscriberCallback,
}

/// Subscriber table backing the FramePayload → callback dispatch.
///
/// See module-level docs for scope (Push-only, literal-matching,
/// `!Sync`).
pub struct SubscriberRegistry {
    subscribers: Vec<Subscriber>,
    next_id: u64,
}

impl Default for SubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SubscriberRegistry {
    /// New empty registry. Subscriber ids start at 1 so 0 stays
    /// available as a sentinel "no subscription" value for any
    /// caller-side wrapper that needs one.
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
            next_id: 1,
        }
    }

    /// Register a subscriber for a literal keyexpr. The returned
    /// `SubscriptionId` is stable until [`unregister`] is called.
    /// Duplicate keyexpr literals are allowed and produce distinct
    /// subscriptions — `dispatch` fires every matching callback in
    /// registration order.
    pub fn register(
        &mut self,
        keyexpr: impl Into<String>,
        callback: impl FnMut(&Push) + Send + 'static,
    ) -> SubscriptionId {
        let id = SubscriptionId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        self.subscribers.push(Subscriber {
            id,
            keyexpr_literal: keyexpr.into(),
            callback: Box::new(callback),
        });
        id
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

    /// Route a decoded `NetworkMessage` to matching subscriber
    /// callbacks. Non-Push variants and mapping-id Pushes (where
    /// `keyexpr.id != 0`) are no-ops in R98 scope; see module-level
    /// docs for the rationale.
    pub fn dispatch(&mut self, message: &NetworkMessage) {
        let push = match message {
            NetworkMessage::Push(push) => push,
            _ => return,
        };
        // Mapping-id pushes need the DECLARE-established table to
        // resolve `id` to a base keyexpr. Without that table the
        // registry cannot tell whether a non-zero id matches any
        // registered literal, so we silently filter — a future
        // round attaches the mapping resolver to the registry and
        // promotes the filter to an equality check.
        if push.keyexpr.id != 0 {
            return;
        }
        let suffix = match push.keyexpr.suffix.as_deref() {
            Some(s) => s,
            None => return,
        };
        for subscriber in &mut self.subscribers {
            if subscriber.keyexpr_literal == suffix {
                (subscriber.callback)(push);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use wz_codecs::wireexpr::Wireexpr;

    fn push_with_keyexpr(suffix: &str) -> Push {
        Push {
            keyexpr: Wireexpr {
                id: 0,
                suffix_len: Some(suffix.len() as u64),
                suffix: Some(suffix.into()),
            },
            ..Push::default()
        }
    }

    #[test]
    fn dispatch_fires_callback_on_matching_keyexpr() {
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let _id = registry.register("topic/a", move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        let push = push_with_keyexpr("topic/a");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)));

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
        registry.dispatch(&NetworkMessage::Push(Box::new(push)));

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
        registry.dispatch(&NetworkMessage::Push(Box::new(push)));

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
        let push = Push {
            keyexpr: Wireexpr {
                id: 7,
                suffix_len: None,
                suffix: None,
            },
            ..Push::default()
        };
        registry.dispatch(&NetworkMessage::Push(Box::new(push)));

        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "non-zero mapping id pushes are filtered out (DECLARE table not modeled)"
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
        registry.dispatch(&NetworkMessage::ResponseFinal(ResponseFinal::default()));

        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "non-Push variants do not fire subscriber callbacks in R98 scope"
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
}
