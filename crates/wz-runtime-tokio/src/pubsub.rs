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
//! - Keyexpr matching follows zenoh-spec chunk wildcards (R100):
//!   chunks are split on `/`, `*` matches exactly one chunk, `**`
//!   matches zero or more chunks (including the empty sequence),
//!   literal chunks compare byte-for-byte. The `$*` intra-chunk
//!   substring wildcard from full zenoh is NOT modeled — production
//!   AP MVP use cases (e.g. `home/**`, `sensors/*/temp`) work
//!   without it, and adding `$*` requires per-chunk pattern
//!   compilation that doesn't pay off until a consumer surfaces.
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

use std::collections::HashMap;

use wz_codecs::declare::DeclareVariant;
use wz_codecs::push::Push;
use wz_codecs::wireexpr::WireexprVariant;

use crate::session_glue::{DriverLoopOutcome, IterationEvent, NetworkMessage};

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
    /// Pre-split pattern chunks. Empty literal chunks are preserved
    /// so a pattern like `a//b` (which canonical zenoh treats as a
    /// chunk-with-empty-string) distinguishes from `a/b`. Wildcards
    /// `*` and `**` appear as single-char chunk entries; matching is
    /// performed by [`keyexpr_pattern_matches`].
    pattern_chunks: Vec<String>,
    callback: SubscriberCallback,
}

/// Match a `/`-separated zenoh keyexpr `target` (Push's suffix) against
/// a pattern split into chunks. Pattern chunks are:
///
/// * `**` — matches zero or more target chunks.
/// * `*`  — matches exactly one target chunk (any content).
/// * any other chunk — must compare byte-for-byte against the
///   corresponding target chunk.
///
/// Returns `true` when the target is covered by the pattern.
///
/// The matcher is implemented as a non-recursive two-cursor walk
/// over pattern + target with a single `**` backtrack frame, mirror-
/// ing standard glob-match algorithms. Worst-case complexity is
/// `O(|pattern| * |target|)` when the pattern contains a single
/// `**`; with multiple `**` the algorithm degrades only on
/// pathological inputs (the productive zenoh-style patterns
/// `home/**` / `sensors/*/temp` stay linear).
pub fn keyexpr_pattern_matches(pattern_chunks: &[&str], target: &str) -> bool {
    let target_chunks: Vec<&str> = target.split('/').collect();
    matches_chunks(pattern_chunks, &target_chunks)
}

fn matches_chunks(pattern: &[&str], target: &[&str]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    // Backtrack frame for the last `**` encountered. When a
    // subsequent literal mismatch occurs we rewind pattern to one-
    // past-`**` and advance target by one, letting `**` consume one
    // more chunk before re-attempting the suffix.
    let mut star_star_pi: Option<usize> = None;
    let mut star_star_ti: usize = 0;

    while ti < target.len() {
        if pi < pattern.len() {
            let pat = pattern[pi];
            if pat == "**" {
                star_star_pi = Some(pi);
                star_star_ti = ti;
                pi += 1;
                continue;
            }
            if pat == "*" || pat == target[ti] {
                pi += 1;
                ti += 1;
                continue;
            }
        }
        // Mismatch (literal differs, or pattern is exhausted while
        // target still has chunks). If we are inside a `**` frame,
        // backtrack by absorbing one more target chunk into `**`.
        if let Some(saved_pi) = star_star_pi {
            star_star_ti += 1;
            ti = star_star_ti;
            pi = saved_pi + 1;
        } else {
            return false;
        }
    }
    // Target exhausted. Pattern must be exhausted too, except for a
    // trailing `**` which matches zero chunks.
    while pi < pattern.len() && pattern[pi] == "**" {
        pi += 1;
    }
    pi == pattern.len()
}

/// Subscriber table backing the FramePayload → callback dispatch.
///
/// See module-level docs for scope (Push + DECLARE resolver, R121d).
/// `!Sync` by construction (no shared mutable state); callers that
/// need cross-task sharing wrap in `Arc<Mutex<…>>`.
pub struct SubscriberRegistry {
    subscribers: Vec<Subscriber>,
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
    peer_keyexpr_table: HashMap<u64, String>,
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
            peer_keyexpr_table: HashMap::new(),
        }
    }

    /// Register a subscriber for a keyexpr pattern. Pattern syntax
    /// matches zenoh chunk wildcards: `/`-separated chunks where
    /// each chunk is a literal, `*` (single chunk), or `**` (zero
    /// or more chunks). The returned `SubscriptionId` is stable
    /// until [`unregister`](Self::unregister) is called. Duplicate
    /// patterns are allowed and produce distinct subscriptions —
    /// `dispatch` fires every matching callback in registration
    /// order.
    pub fn register(
        &mut self,
        keyexpr_pattern: impl Into<String>,
        callback: impl FnMut(&Push) + Send + 'static,
    ) -> SubscriptionId {
        let id = SubscriptionId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        let pattern_chunks: Vec<String> =
            keyexpr_pattern.into().split('/').map(String::from).collect();
        self.subscribers.push(Subscriber {
            id,
            pattern_chunks,
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

    /// R121j-5c — borrow the peer keyexpr alias table for cross-
    /// registry use. The [`QueryableRegistry`](crate::query::QueryableRegistry)
    /// resolves inbound `Request(Query)` keyexpr through the same
    /// peer mapping that the subscriber side populated via
    /// [`absorb_declare`](Self::absorb_declare) on inbound
    /// `Declare(DeclKexpr|UndeclKexpr)`. Lending the table by
    /// reference avoids dual-write bookkeeping (one DECLARE absorbed
    /// once, observed by both registries) without requiring
    /// `Arc<Mutex<…>>` shared state.
    pub fn peer_keyexpr_table(&self) -> &HashMap<u64, String> {
        &self.peer_keyexpr_table
    }

    /// Route an `IterationEvent` produced by
    /// [`drive_session_until_terminal`](crate::session_glue::drive_session_until_terminal)
    /// to matching subscriber callbacks. The adapter pulls
    /// `FramePayload.messages` out of `IterationEvent::Poll` and
    /// dispatches each record via [`dispatch`](Self::dispatch);
    /// `Lease` events and non-FramePayload poll outcomes are
    /// no-ops. Callers use this as the registry's observer
    /// callback so they need not hand-write the
    /// `if let Poll(FramePayload { messages, .. })` matcher at the
    /// integration site.
    pub fn dispatch_iteration_event(&mut self, event: IterationEvent<'_>) {
        if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event {
            for message in messages {
                self.dispatch(message);
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
    pub fn dispatch(&mut self, message: &NetworkMessage) {
        match message {
            NetworkMessage::Push(push) => self.dispatch_push(push),
            NetworkMessage::Declare(decl) => self.absorb_declare(&decl.body),
            _ => {}
        }
    }

    fn dispatch_push(&mut self, push: &Push) {
        // R125c2: keyexpr is now a tagged-union (B5-ν parent-tag
        // variant dispatch on parent.M); extract id + suffix from
        // whichever arm the dispatcher selected. Both arms carry the
        // same id + Option<suffix> fields — the variant is a type-
        // level mapping-context refinement, not a wire-shape split.
        let (id, suffix_opt) = match &push.keyexpr.body {
            WireexprVariant::WireexprLocal(arm) => (arm.id, arm.suffix.as_deref()),
            WireexprVariant::WireexprNonlocal(arm) => (arm.id, arm.suffix.as_deref()),
        };
        // R121d — resolve the Push's keyexpr against the peer
        // mapping table. The composition rule is:
        //
        //   id == 0                       → keyexpr = suffix.unwrap_or("")
        //   id != 0, suffix is None       → keyexpr = table[id]
        //   id != 0, suffix is Some(s)    → keyexpr = table[id] + s
        //
        // If `id != 0` and the table has no entry, the push is
        // un-resolvable (the peer never declared this id, OR the
        // declaration arrived through a path the registry has not
        // yet absorbed). Drop silently rather than firing on a
        // partial keyexpr.
        let resolved: String = if id == 0 {
            match suffix_opt {
                Some(s) => s.to_string(),
                None => return,
            }
        } else {
            let base = match self.peer_keyexpr_table.get(&id) {
                Some(s) => s.clone(),
                None => return,
            };
            match suffix_opt {
                Some(s) => {
                    let mut out = base;
                    out.push_str(s);
                    out
                }
                None => base,
            }
        };

        for subscriber in &mut self.subscribers {
            let chunks: Vec<&str> =
                subscriber.pattern_chunks.iter().map(String::as_str).collect();
            if keyexpr_pattern_matches(&chunks, &resolved) {
                (subscriber.callback)(push);
            }
        }
    }

    /// R121d — absorb a `Declare` envelope's inner body so the
    /// peer mapping table tracks the peer's locally-declared
    /// keyexpr aliases. Only `DeclKexpr` and `UndeclKexpr` are
    /// processed; the other 7 Declare sub-variants do not affect
    /// the keyexpr table.
    fn absorb_declare(&mut self, body: &DeclareVariant) {
        match body {
            DeclareVariant::CodecZenohDeclKexpr(d) => {
                // Resolve the declared keyexpr to a literal string,
                // following the same composition rule as Push
                // resolution (id==0 → suffix verbatim; id!=0 →
                // table[id] + suffix). If the inner reference is
                // unresolvable we skip — recording a partial entry
                // would later mis-fire subscriber matches.
                if let Some(literal) = self.resolve_wireexpr(&d.keyexpr.body) {
                    self.peer_keyexpr_table.insert(d.id, literal);
                }
            }
            DeclareVariant::CodecZenohUndeclKexpr(u) => {
                self.peer_keyexpr_table.remove(&u.id);
            }
            // Other sub-variants do not affect the keyexpr table.
            _ => {}
        }
    }

    /// Resolve a `Wireexpr` to its literal keyexpr string using the
    /// current peer mapping table. Returns `None` when the
    /// expression references a mapping id that has not been
    /// declared yet (or when it is the empty `(id=0, suffix=None)`
    /// form, which carries no resolution).
    fn resolve_wireexpr(&self, body: &WireexprVariant) -> Option<String> {
        let (id, suffix_opt) = match body {
            WireexprVariant::WireexprLocal(arm) => (arm.id, arm.suffix.as_deref()),
            WireexprVariant::WireexprNonlocal(arm) => (arm.id, arm.suffix.as_deref()),
        };
        if id == 0 {
            suffix_opt.map(str::to_string)
        } else {
            let base = self.peer_keyexpr_table.get(&id)?.clone();
            Some(match suffix_opt {
                Some(s) => {
                    let mut out = base;
                    out.push_str(s);
                    out
                }
                None => base,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use wz_codecs::wireexpr::Wireexpr;
    use wz_codecs::wireexpr_local::WireexprLocal;
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;

    fn push_with_keyexpr(suffix: &str) -> Push {
        // R125c2: wireexpr is now a tagged-union (Local default arm at
        // M=1; mirrors zenoh-pico's `_z_wireexpr_t` zero-init mapping=
        // LOCAL → is_local=true → encoder OR's M=1). Construct the
        // Local arm so the test wire shape matches zenoh-pico's
        // default-state push (header M=1 ORed in by the encoder via
        // the b5_nu_derivation_block).
        Push {
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprLocal(WireexprLocal {
                    id: 0,
                    suffix_len: Some(suffix.len() as u64),
                    suffix: Some(suffix.into()),
                }),
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
        assert!(keyexpr_pattern_matches(&["home", "*", "temp"], "home/kitchen/temp"));
        assert!(keyexpr_pattern_matches(&["home", "*", "temp"], "home/bedroom/temp"));
        // The wildcard does NOT match zero chunks.
        assert!(!keyexpr_pattern_matches(&["home", "*", "temp"], "home/temp"));
        // The wildcard does NOT span chunk boundaries.
        assert!(!keyexpr_pattern_matches(&["home", "*", "temp"], "home/kitchen/sub/temp"));
    }

    #[test]
    fn keyexpr_pattern_matches_double_star_zero_or_more() {
        // `**` matches zero chunks.
        assert!(keyexpr_pattern_matches(&["home", "**"], "home"));
        // `**` matches one chunk.
        assert!(keyexpr_pattern_matches(&["home", "**"], "home/temp"));
        // `**` matches many chunks.
        assert!(keyexpr_pattern_matches(&["home", "**"], "home/kitchen/temp/c"));
        // `**` at the prefix.
        assert!(keyexpr_pattern_matches(&["**", "temp"], "home/kitchen/temp"));
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

    #[test]
    fn dispatch_fires_callback_on_wildcard_match() {
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry.register("sensors/*/temp", move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        let push = push_with_keyexpr("sensors/room1/temp");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)));

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
        registry.dispatch(&NetworkMessage::Push(Box::new(push)));

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
        registry.dispatch(&NetworkMessage::Push(Box::new(push)));

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
    fn declare_kexpr_literal(mapping_id: u64, s: &str) -> wz_codecs::declare::Declare {
        wz_codecs::declare::Declare {
            body: wz_codecs::declare::DeclareVariant::CodecZenohDeclKexpr(
                wz_codecs::decl_kexpr::DeclKexpr {
                    id: mapping_id,
                    keyexpr: wz_codecs::wireexpr::Wireexpr {
                        body: WireexprVariant::WireexprLocal(
                            wz_codecs::wireexpr_local::WireexprLocal {
                                id: 0,
                                suffix_len: Some(s.len() as u64),
                                suffix: Some(s.into()),
                            },
                        ),
                    },
                    ..Default::default()
                },
            ),
            ..Default::default()
        }
    }

    fn undeclare_kexpr(mapping_id: u64) -> wz_codecs::declare::Declare {
        wz_codecs::declare::Declare {
            body: wz_codecs::declare::DeclareVariant::CodecZenohUndeclKexpr(
                wz_codecs::undecl_kexpr::UndeclKexpr {
                    id: mapping_id,
                    ..Default::default()
                },
            ),
            ..Default::default()
        }
    }

    fn push_with_mapping_id(mapping_id: u64, inline_suffix: Option<&str>) -> Push {
        Push {
            keyexpr: wz_codecs::wireexpr::Wireexpr {
                body: WireexprVariant::WireexprLocal(
                    wz_codecs::wireexpr_local::WireexprLocal {
                        id: mapping_id,
                        suffix_len: inline_suffix.map(|s| s.len() as u64),
                        suffix: inline_suffix.map(str::to_string),
                    },
                ),
            },
            ..Push::default()
        }
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

        registry.dispatch(&NetworkMessage::Declare(Box::new(
            declare_kexpr_literal(1, "demo/test"),
        )));
        registry.dispatch(&NetworkMessage::Push(Box::new(
            push_with_mapping_id(1, None),
        )));

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

        registry.dispatch(&NetworkMessage::Declare(Box::new(
            declare_kexpr_literal(1, "demo/test"),
        )));
        registry.dispatch(&NetworkMessage::Push(Box::new(
            push_with_mapping_id(1, None),
        )));
        registry.dispatch(&NetworkMessage::Declare(Box::new(undeclare_kexpr(1))));
        registry.dispatch(&NetworkMessage::Push(Box::new(
            push_with_mapping_id(1, None),
        )));

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

        registry.dispatch(&NetworkMessage::Declare(Box::new(
            declare_kexpr_literal(5, "home/sensor/"),
        )));
        registry.dispatch(&NetworkMessage::Push(Box::new(
            push_with_mapping_id(5, Some("temp")),
        )));

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "Push id=5 + suffix=temp must resolve to 'home/sensor/temp' \
             via the base+suffix composition rule"
        );
    }
}
