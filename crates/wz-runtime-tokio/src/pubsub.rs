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
use wz_codecs::push::{Push, PushVariant};
use wz_codecs::wireexpr::WireexprVariant;

use crate::sample::{
    extract_attachment, extract_qos, extract_source_info, EncodingHint, Reliability, Sample,
    SampleKind, TimestampHint,
};
use crate::session_glue::{DriverLoopOutcome, IterationEvent, NetworkMessage};

/// Boxed callback invoked when a Push message's keyexpr matches a
/// registered subscriber. R222 — receives `&Sample` (resolved
/// keyexpr + SampleKind + payload bytes), no longer the raw `&Push`.
/// See module-level docs for the lifetime and thread-safety contract.
pub type SubscriberCallback = Box<dyn FnMut(&Sample) + Send + 'static>;

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
    own_zid: Option<Vec<u8>>,
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
            own_zid: None,
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
    /// integration is currently caller-driven (see
    /// [`crate::session::Session::set_own_zid`]); an auto-wire from
    /// the session-FSM completion event is an R232+ carry.
    pub fn set_own_zid(&mut self, zid: Vec<u8>) -> bool {
        if !(1..=16).contains(&zid.len()) {
            return false;
        }
        self.own_zid = Some(zid);
        true
    }

    /// R231 — release the previously-installed own zid (e.g. on
    /// session close or re-init). Subsequent dispatches behave as
    /// if `set_own_zid` had never been called: no self-echo dedup,
    /// every wire-arrived Push fires its matching subscribers.
    pub fn clear_own_zid(&mut self) {
        self.own_zid = None;
    }

    /// R231 — expose the currently-installed own zid for diagnostic
    /// and test purposes. Returns the same slice that
    /// [`dispatch_push`](Self::dispatch_push) compares against
    /// `source_info.zid_prefix()`.
    pub fn own_zid(&self) -> Option<&[u8]> {
        self.own_zid.as_deref()
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
        callback: impl FnMut(&Sample) + Send + 'static,
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
        callback: impl FnMut(&Sample) + Send + 'static,
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
    /// dispatches each record via [`dispatch`](Self::dispatch),
    /// threading the frame's `reliable` discriminator through so the
    /// downstream `Sample.reliability` carries the link-layer
    /// classification (R226 — zenoh-pico `_z_trigger_push` argument
    /// mirror). `Lease` events and non-FramePayload poll outcomes are
    /// no-ops. Callers use this as the registry's observer callback so
    /// they need not hand-write the `if let Poll(FramePayload { ... })`
    /// matcher at the integration site.
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
    pub fn dispatch(&mut self, message: &NetworkMessage, reliability: Reliability) {
        match message {
            // R227 — wire-arrived Push carries `is_remote = true` so
            // the locality filter selects `allows_remote()`. The
            // self-publish loopback path (see
            // [`local_publish`](Self::local_publish)) enters
            // [`fire_to_subscribers`](Self::fire_to_subscribers)
            // directly with `is_remote = false`.
            NetworkMessage::Push(push) => self.dispatch_push(push, reliability, true),
            NetworkMessage::Declare(decl) => self.absorb_declare(&decl.body),
            _ => {}
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
    fn dispatch_push(&mut self, push: &Push, reliability: Reliability, is_remote: bool) {
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
        let (kind, payload, body_timestamp, body_encoding, body_attachment, body_source_info) =
            match &push.body {
                PushVariant::CodecZenohMsgPut(put) => {
                    let body_exts: &[wz_codecs::ext_entry::ExtEntry] =
                        put.extensions.as_deref().unwrap_or(&[]);
                    (
                        SampleKind::Put,
                        put.payload.clone(),
                        put.timestamp.as_ref().map(TimestampHint::from_codec),
                        put.encoding.as_ref().map(EncodingHint::from_codec),
                        extract_attachment(body_exts),
                        extract_source_info(body_exts),
                    )
                }
                PushVariant::CodecZenohMsgDel(del) => {
                    let body_exts: &[wz_codecs::ext_entry::ExtEntry] =
                        del.extensions.as_deref().unwrap_or(&[]);
                    (
                        SampleKind::Del,
                        Vec::new(),
                        del.timestamp.as_ref().map(TimestampHint::from_codec),
                        None,
                        extract_attachment(body_exts),
                        extract_source_info(body_exts),
                    )
                }
                PushVariant::Default { .. } => return,
            };
        let outer_exts: &[wz_codecs::ext_entry::ExtEntry] =
            push.extensions.as_deref().unwrap_or(&[]);
        let qos = extract_qos(outer_exts);
        let sample = Sample {
            keyexpr: resolved,
            kind,
            payload,
            timestamp: body_timestamp,
            encoding: body_encoding,
            qos,
            attachment: body_attachment,
            source_info: body_source_info,
            reliability,
        };

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
    fn fire_to_subscribers(&mut self, sample: &Sample, is_remote: bool) -> usize {
        let mut fired: usize = 0;
        for subscriber in &mut self.subscribers {
            let pass = if is_remote {
                subscriber.allowed_origin.allows_remote()
            } else {
                subscriber.allowed_origin.allows_local()
            };
            if !pass {
                continue;
            }
            let chunks: Vec<&str> = subscriber
                .pattern_chunks
                .iter()
                .map(String::as_str)
                .collect();
            if keyexpr_pattern_matches(&chunks, &sample.keyexpr) {
                (subscriber.callback)(sample);
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
        };
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
            *captured_clone.lock().unwrap() = Some(sample.reliability);
        });
        let push = push_with_keyexpr("topic/a");
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push)),
            Reliability::Reliable,
        );
        assert_eq!(*captured.lock().unwrap(), Some(Reliability::Reliable));
    }

    #[test]
    fn dispatch_best_effort_records_best_effort_on_sample() {
        let mut registry = SubscriberRegistry::new();
        let captured = Arc::new(std::sync::Mutex::new(None::<Reliability>));
        let captured_clone = captured.clone();
        registry.register("topic/a", move |sample| {
            *captured_clone.lock().unwrap() = Some(sample.reliability);
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
        use crate::session_glue::IterationEvent;
        let mut registry = SubscriberRegistry::new();
        let captured = Arc::new(std::sync::Mutex::new(None::<Reliability>));
        let captured_clone = captured.clone();
        registry.register("topic/a", move |sample| {
            *captured_clone.lock().unwrap() = Some(sample.reliability);
        });
        let push = push_with_keyexpr("topic/a");
        let outcome = DriverLoopOutcome::FramePayload {
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
        assert_eq!(
            Reliability::from_reliable_bool(true),
            Reliability::Reliable
        );
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
            &NetworkMessage::ResponseFinal(ResponseFinal::default()),
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
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
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
        registry.register_with_locality(
            "home/temp",
            Locality::SessionLocal,
            move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            },
        );

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
        registry.register_with_locality(
            "home/temp",
            Locality::SessionLocal,
            move |_push| {
                local_clone.fetch_add(1, Ordering::SeqCst);
            },
        );

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
        registry.register_with_locality(
            "**",
            Locality::SessionLocal,
            move |_push| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            },
        );

        let push = push_with_keyexpr("home/kitchen/temp");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "locality short-circuits before keyexpr match (`**` matches everything but is suppressed)"
        );
    }

    // ── R222 Push -> Sample projection behaviour ──

    fn push_with_payload(keyexpr: &str, payload: &[u8]) -> Push {
        let mut push = push_with_keyexpr(keyexpr);
        if let wz_codecs::push::PushVariant::CodecZenohMsgPut(ref mut put) = push.body {
            put.payload_len = payload.len() as u64;
            put.payload = payload.to_vec();
        }
        push
    }

    fn push_with_del_body(keyexpr: &str) -> Push {
        let mut push = push_with_keyexpr(keyexpr);
        push.body = wz_codecs::push::PushVariant::CodecZenohMsgDel(
            wz_codecs::msg_del::MsgDel::default(),
        );
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
            *captured_clone.lock().unwrap() = Some(sample.clone());
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
            *captured_clone.lock().unwrap() = Some(sample.clone());
        });

        let push = push_with_del_body("clear/me");
        registry.dispatch(&NetworkMessage::Push(Box::new(push)), Reliability::Reliable);

        let observed = captured.lock().unwrap().clone().expect("callback fired");
        assert_eq!(observed.keyexpr, "clear/me");
        assert_eq!(observed.kind, SampleKind::Del);
        assert!(observed.payload.is_empty(), "Del has no payload on the wire");
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
            *captured_clone.lock().unwrap() = Some(sample.keyexpr.clone());
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
        registry.register_with_locality(
            "home/temp",
            Locality::SessionLocal,
            move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            },
        );

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
        registry.register_with_locality(
            "home/temp",
            Locality::Remote,
            move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            },
        );

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
            registry.register_with_locality(
                "home/temp",
                Locality::Any,
                move |_sample| {
                    any_clone.fetch_add(1, Ordering::SeqCst);
                },
            );
        }
        {
            let local_clone = local_hits.clone();
            registry.register_with_locality(
                "home/temp",
                Locality::SessionLocal,
                move |_sample| {
                    local_clone.fetch_add(1, Ordering::SeqCst);
                },
            );
        }
        {
            let remote_clone = remote_hits.clone();
            registry.register_with_locality(
                "home/temp",
                Locality::Remote,
                move |_sample| {
                    remote_clone.fetch_add(1, Ordering::SeqCst);
                },
            );
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
            *observed_clone.lock().unwrap() = Some(sample.clone());
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
            *observed_clone.lock().unwrap() = Some(sample.kind);
            assert!(sample.payload.is_empty(), "Del Sample carries no payload");
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
        registry.register_with_locality(
            "home/**",
            Locality::Remote,
            move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            },
        );

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
    fn push_put_literal_with_source_info(keyexpr: &str, source_zid: &[u8]) -> Push {
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
        ext.body =
            wz_codecs::ext_entry::ExtEntryVariant::CodecZenohExtZbuf(wz_codecs::ext_zbuf::ExtZbuf {
                value_len: payload.len() as u64,
                value: payload,
            });
        let put = wz_codecs::msg_put::MsgPut {
            extensions: Some(vec![ext]),
            ..wz_codecs::msg_put::MsgPut::default()
        };
        Push {
            keyexpr: wz_codecs::wireexpr::Wireexpr {
                body: WireexprVariant::WireexprLocal(wz_codecs::wireexpr_local::WireexprLocal {
                    id: 0,
                    suffix_len: Some(keyexpr.len() as u64),
                    suffix: Some(keyexpr.to_string()),
                }),
            },
            body: wz_codecs::push::PushVariant::CodecZenohMsgPut(put),
            ..Push::default()
        }
    }

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
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push)),
            Reliability::Reliable,
        );

        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "wire-arrived self-echo (source_info.zid == own_zid) must not fire local subscribers"
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
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push)),
            Reliability::Reliable,
        );

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
                    suffix: Some("demo/temp".to_string()),
                }),
            },
            body: wz_codecs::push::PushVariant::CodecZenohMsgPut(
                wz_codecs::msg_put::MsgPut::default(),
            ),
            ..Push::default()
        };
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push)),
            Reliability::Reliable,
        );

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "absent source_info means cautious default fires the subscriber"
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
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push)),
            Reliability::Reliable,
        );

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
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push)),
            Reliability::Reliable,
        );

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

        assert_eq!(fired, 1, "loopback path must fire even when source matches own_zid");
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
        registry.dispatch(
            &NetworkMessage::Push(Box::new(push)),
            Reliability::Reliable,
        );
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
}
