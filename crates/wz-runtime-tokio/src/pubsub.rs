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
    /// R223 — locality filter applied before the callback fires.
    /// See [`crate::locality`] for the semantics and the wz
    /// dispatch invariant (every inbound Push is treated as remote
    /// until self-publish loopback lands in a future round).
    allowed_origin: crate::locality::Locality,
    callback: SubscriberCallback,
}

/// Match a `/`-separated zenoh keyexpr `target` (Push's suffix) against
/// a pattern split into chunks. Pattern chunks are:
///
/// * `**` — matches zero or more target chunks.
/// * `*`  — matches exactly one target chunk (any content).
/// * a chunk containing `$*` — intra-chunk substring wildcard
///   (R220). The chunk is split on `$*` into sub-parts; the leading
///   sub-part (if non-empty) must be a prefix of the target chunk,
///   the trailing sub-part (if non-empty) must be a suffix, and
///   each middle sub-part must appear in order in the remaining
///   slice without overlap. See [`chunk_matches_with_dsl`] for the
///   full algorithm.
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
            if pat == "*" || chunk_matches(pat, target[ti]) {
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

/// Match one pattern chunk against one target chunk. Routes between
/// the DSL path ([`chunk_matches_with_dsl`]) and a byte-equal
/// fast-path based on whether the pattern chunk contains the `$*`
/// token. The `*` and `**` whole-chunk wildcards are handled by the
/// caller before reaching this function.
fn chunk_matches(pattern: &str, target: &str) -> bool {
    if pattern.contains("$*") {
        chunk_matches_with_dsl(pattern, target)
    } else {
        pattern == target
    }
}

/// Intra-chunk substring DSL matcher. The pattern chunk is split on
/// `$*` into sub-parts; each non-empty sub-part must appear in
/// `target` in order without overlap, anchored as follows:
///
/// * If the chunk starts with `$*` (leading sub-part is empty), the
///   first non-empty sub-part can appear at any byte offset.
///   Otherwise the first sub-part must align with target byte 0.
/// * Symmetric for the chunk end: a trailing `$*` lets the last
///   non-empty sub-part float; otherwise it must align with the
///   target's last byte.
/// * Middle sub-parts are located via leftmost-first substring
///   search, mirroring zenoh-pico's
///   `_z_chunk_right_contains_all_stardsl_subchunks_of_left`.
///
/// Empty middle sub-parts (which only arise from non-canonical
/// `$*$*` runs, since canonical zenoh collapses them) are treated
/// as no-ops so the matcher remains equivalent to the canonical
/// form `$*`.
fn chunk_matches_with_dsl(pattern: &str, target: &str) -> bool {
    let parts: Vec<&str> = pattern.split("$*").collect();
    debug_assert!(
        parts.len() >= 2,
        "chunk_matches_with_dsl invoked on a pattern without `$*` — caller routing bug",
    );

    let n = parts.len();
    let mut remaining = target;

    let leading = parts[0];
    if !leading.is_empty() {
        match remaining.strip_prefix(leading) {
            Some(rest) => remaining = rest,
            None => return false,
        }
    }

    for &part in &parts[1..n - 1] {
        if part.is_empty() {
            continue;
        }
        match remaining.find(part) {
            Some(pos) => remaining = &remaining[pos + part.len()..],
            None => return false,
        }
    }

    let trailing = parts[n - 1];
    if trailing.is_empty() {
        true
    } else {
        remaining.ends_with(trailing) && remaining.len() >= trailing.len()
    }
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
    /// each chunk is a literal, `*` (single chunk), `**` (zero or
    /// more chunks), or contains the `$*` intra-chunk substring
    /// wildcard (R220). The returned `SubscriptionId` is stable
    /// until [`unregister`](Self::unregister) is called. Duplicate
    /// patterns are allowed and produce distinct subscriptions —
    /// `dispatch` fires every matching callback in registration
    /// order.
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
    ///
    /// R223 — defaults [`Locality::Any`](crate::locality::Locality)
    /// so both session-local and remote-origin samples fire the
    /// callback. Use [`register_with_locality`](Self::register_with_locality)
    /// to restrict to one origin class.
    pub fn register(
        &mut self,
        keyexpr_pattern: impl Into<String>,
        callback: impl FnMut(&Push) + Send + 'static,
    ) -> SubscriptionId {
        self.register_with_locality(
            keyexpr_pattern,
            crate::locality::Locality::Any,
            callback,
        )
    }

    /// R223 — variant of [`register`](Self::register) that pins the
    /// locality filter explicitly. Stores `allowed_origin` on the
    /// subscriber record; [`dispatch_push`](Self::dispatch_push)
    /// consults the filter before firing the callback.
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
        callback: impl FnMut(&Push) + Send + 'static,
    ) -> SubscriptionId {
        let id = SubscriptionId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        let raw = keyexpr_pattern.into();
        let canonical = match crate::keyexpr_canon::canonize_keyexpr(&raw) {
            Ok(canon) => canon,
            Err(err) => {
                log::warn!(
                    "SubscriberRegistry::register: keyexpr `{raw}` is not canonical \
                     ({err}); storing raw form. The matcher still operates but the \
                     stored chunks may drift from the canonical form a peer emits."
                );
                raw
            }
        };
        let pattern_chunks: Vec<String> =
            canonical.split('/').map(String::from).collect();
        self.subscribers.push(Subscriber {
            id,
            pattern_chunks,
            allowed_origin,
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
            // R223 — every Push reaching dispatch_push has been
            // parsed off the wire, so it is treated as remote in
            // zenoh-pico's is_remote=true sense. The locality filter
            // therefore reduces to allows_remote(). When self-publish
            // loopback lands, the local-origin call path will
            // similarly route through dispatch_push with an
            // is_remote=false flag and consult allows_local().
            if !subscriber.allowed_origin.allows_remote() {
                continue;
            }
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
    /// processed; the other Declare sub-variants are routed to
    /// their dedicated registries elsewhere in the runtime and
    /// must not mutate the keyexpr table.
    ///
    /// R218 — every `DeclareVariant` arm is matched explicitly so
    /// that adding a new arm in the upstream codec catalog
    /// surfaces as a compile error here rather than a silent
    /// miss. The intentional no-op arms cite the dedicated
    /// registry that owns each Declare sub-type.
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
            // DeclSubscriber / UndeclSubscriber are observed by
            // `crate::declare::subscriber::DeclSubscriberRegistry`
            // so the runtime can fire user callbacks on peer
            // subscriber lifecycle — not a keyexpr-table concern.
            DeclareVariant::CodecZenohDeclSubscriber(_)
            | DeclareVariant::CodecZenohUndeclSubscriber(_) => {}
            // DeclQueryable / UndeclQueryable are observed by
            // `crate::declare::queryable::QueryableRegistry` so
            // the runtime can fire user callbacks on peer
            // queryable lifecycle — not a keyexpr-table concern.
            DeclareVariant::CodecZenohDeclQueryable(_)
            | DeclareVariant::CodecZenohUndeclQueryable(_) => {}
            // DeclToken / UndeclToken are observed by
            // `crate::declare::liveliness::TokenRegistry` for the
            // peer liveliness layer — not a keyexpr-table concern.
            DeclareVariant::CodecZenohDeclToken(_)
            | DeclareVariant::CodecZenohUndeclToken(_) => {}
            // DeclFinal is the terminator marker zenoh emits after
            // an initial declaration burst. No side effects in
            // this registry — the runtime's session glue tracks
            // the marker separately if it cares about burst
            // completion.
            DeclareVariant::CodecZenohDeclFinal(_) => {}
            // Default arm preserves an unknown wire tag for
            // forward compatibility (codegen generates this for
            // every variant-dispatch enum). The peer keyexpr
            // table is by definition not affected by an unknown
            // Declare sub-type.
            DeclareVariant::Default { .. } => {}
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
        assert!(keyexpr_pattern_matches(
            &["$*aa$*bb$*"],
            "xxaaYYbbZZ"
        ));
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
        assert!(keyexpr_pattern_matches(&["home", "$*", "temp"], "home/kitchen/temp"));
        assert!(keyexpr_pattern_matches(&["home", "$*", "temp"], "home/x/temp"));
        // Still does not span chunk boundaries.
        assert!(!keyexpr_pattern_matches(
            &["home", "$*", "temp"],
            "home/a/b/temp"
        ));
        // Still does not collapse to zero chunks.
        assert!(!keyexpr_pattern_matches(&["home", "$*", "temp"], "home/temp"));
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
        registry.dispatch(&NetworkMessage::Push(Box::new(push)));
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "canonicalized `home/$*/temp` (== `home/*/temp`) matches single-chunk middle"
        );

        // Boundary check: still does not collapse to zero chunks.
        let push = push_with_keyexpr("home/temp");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)));
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "canonicalized `*` does not match the zero-chunk case"
        );
    }

    #[test]
    fn register_canonicalizes_single_star_after_double_star() {
        // `home/**/*/temp` canonicalizes to `home/**/temp` (the `*`
        // after `**` is absorbed). After canon the stored chunks
        // match the zero-extra-chunk case `home/temp` because `**`
        // already covers zero or more.
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry.register("home/**/*/temp", move |_push| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        let push = push_with_keyexpr("home/temp");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)));
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "canonicalized `**/*` → `**` matches the zero-extra-chunk case"
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
        registry.dispatch(&NetworkMessage::Push(Box::new(push)));
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
        registry.dispatch(&NetworkMessage::Push(Box::new(push)));
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
        registry.dispatch(&NetworkMessage::Push(Box::new(push)));
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
        registry.dispatch(&NetworkMessage::Push(Box::new(push)));
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "Locality::Remote fires for wire-arrived Push"
        );
    }

    #[test]
    fn register_with_locality_session_local_does_not_fire_on_inbound() {
        // wz currently has no self-publish loopback — every
        // inbound Push reaching dispatch_push is remote. A
        // Locality::SessionLocal subscriber therefore correctly
        // suppresses every inbound match. This documents the
        // surface-only-correct shape: SessionLocal will activate
        // when a future round wires loopback, but today fires zero.
        use crate::locality::Locality;
        let mut registry = SubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        registry.register_with_locality(
            "home/temp",
            Locality::SessionLocal,
            move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            },
        );

        let push = push_with_keyexpr("home/temp");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)));
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "Locality::SessionLocal suppresses inbound (remote) Push pre-loopback"
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
        registry.register_with_locality(
            "home/temp",
            Locality::SessionLocal,
            move |_push| {
                local_clone.fetch_add(1, Ordering::SeqCst);
            },
        );

        let push = push_with_keyexpr("home/temp");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)));
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
        registry.register_with_locality(
            "**",
            Locality::SessionLocal,
            move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            },
        );

        let push = push_with_keyexpr("home/kitchen/temp");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)));
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "locality short-circuits before keyexpr match (`**` matches everything but is suppressed)"
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
            registry.absorb_declare(&body);
            assert!(
                registry.peer_keyexpr_table().is_empty(),
                "{name} arm must not mutate the peer keyexpr table"
            );
        }
    }
}
