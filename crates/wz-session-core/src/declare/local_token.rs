// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `LocalTokenRegistry` — DECLARER-side registry of wz's own held
//! `LivelinessToken`s, and the R283 inbound-Interest responder.
//!
//! The sibling liveliness registries
//! ([`crate::declare::liveliness::LivelinessRegistry`] /
//! [`crate::declare::liveliness_subscriber::LivelinessSubscriberRegistry`])
//! track the PEER's declared tokens. This registry is their mirror on
//! the declarer side: it tracks the tokens wz itself has declared
//! (`token_id -> resolved literal keyexpr`), so that when a peer sends a
//! non-final liveliness Interest ("tell me your current tokens") wz can
//! reply with each matching token.
//!
//! R283 — before this registry the declarer emitted `Declare(DeclToken)`
//! proactively at declare time only, and silently dropped inbound
//! non-final Interests (see the pre-R283 arm in
//! [`crate::declare::liveliness_subscriber`]). That made wz a fragile
//! declarer: a foreign subscriber that connects + sends its CURRENT
//! Interest AFTER the proactive declare never learns the token. zenoh
//! resolves a CURRENT liveliness Interest by replying with an
//! `interest_id`-tagged `Declare(DeclToken)` per matching token,
//! terminated by an `interest_id`-tagged `Declare(DeclFinal)`
//! (zenoh-pico `_z_liveliness_process_token_declare` /
//! `_z_liveliness_process_declare_final`,
//! `vendor/zenoh-pico/src/session/liveliness.c:218-256`).
//!
//! ## R311hn (Track 2, Decision 2 no-heap emit) — no-heap rewrite
//!
//! This registry was the last one still gated `all(liveliness-token,
//! alloc)`: its storage was an unbounded `HashMap<u64, String>` and its
//! responder staged owned `DeclareOwned` records (heap `String`
//! keyexpr). That correctly placed it on the alloc half — outbound wire
//! *construction* is alloc-gated everywhere (Decision 2). R311hn opens a
//! no-heap *emit* route so the registry composes on the MCU no-alloc
//! profile, following the 3-layer split of every other registry:
//!
//! 1. **Storage (no-heap)** — the token table is a
//!    [`crate::bounded::BoundedVec`] of `(token_id, keyexpr)` rows, each
//!    keyexpr a [`crate::bounded::BoundedString`]; scanned linearly
//!    (`caps::MAX_LOCAL_TOKENS` is small). Mirror of
//!    [`crate::declare::liveliness_subscriber`]'s slot table.
//! 2. **Borrowed no-heap response** —
//!    [`LocalTokenRegistry::respond_to_interest_borrowed`] stages
//!    [`DeclResponseItem`] records (a `Token` per match, id-only — the
//!    keyexpr stays in the table and is resolved at drain via
//!    [`LocalTokenRegistry::keyexpr_for`] — then one `Final`) into a
//!    bounded buffer. No codec, no heap; the caller supplies the
//!    already-resolved Interest pattern.
//! 3. **Owned inbound parse (alloc)** —
//!    [`LocalTokenRegistry::respond_to_interest`] /
//!    [`LocalTokenRegistry::dispatch_messages`] consume an owned
//!    `InterestOwned` + resolve its keyexpr through the peer table
//!    (`alloc`), then funnel through the no-heap borrowed SSOT.
//!
//! The owned-`DeclareOwned` builders moved to the AP sink
//! (`wz-runtime-tokio::session_glue`), which implements the borrowed
//! [`crate::response_sink::ResponseSink`] emit seam
//! (`send_declare_token_reply` / `send_declare_final_reply`): the registry says
//! WHICH tokens to declare; the sink owns HOW to encode them (a `VecSink`
//! on AP, a `SliceSink` over a stack buffer on MCU — both via SCE's
//! `encode<S: SceSink>`).
//!
//! ## Two-phase contract (mirror of the queryable registry)
//!
//! The inbound Interest is processed during the fan phase (no actions
//! handle available), staging [`DeclResponseItem`] records; the
//! observer's drain phase ([`crate::observer::ApplicationLayerObserver::flush_pending`])
//! emits them through the sink. Wire ordering is preserved — every
//! `DeclToken` precedes the terminating `DeclFinal`.

use crate::bounded::{BoundedString, BoundedVec};
use crate::caps;
use crate::keyexpr_match::{keyexpr_intersect_patterns, MAX_KEYEXPR_CHUNKS};
use crate::registry_error::RegisterError;

// R311ho — borrowed codec types for the single-source reply builders
// ([`build_token_reply`] / [`build_final_reply`]). These are the no-heap
// (`encode<S: SceSink>`) borrowed projections; `liveliness-token` (this
// module's gate) implies `codec-declare`, so they are always available
// here without `alloc`.
use wz_codecs::decl_final::DeclFinal;
use wz_codecs::decl_token::DeclToken;
use wz_codecs::declare::{Declare, DeclareVariant};
use wz_codecs::wire_const;
use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
use wz_codecs::wireexpr_local::WireexprLocal;

#[cfg(feature = "alloc")]
use alloc::string::String;
// R311y739 -- the wire-dispatch params take `impl Into<MappingSpaces>` now,
// so this file's own code no longer names `HashMap`; the suites below import
// it themselves to stand in for the peer's id space.

#[cfg(feature = "alloc")]
use wz_codecs::interest::InterestOwned;

#[cfg(feature = "alloc")]
use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
#[cfg(feature = "alloc")]
use crate::network_message::NetworkMessage;
#[cfg(feature = "alloc")]
use crate::wireexpr_resolve::{resolve_wireexpr_in, MappingSpaces};

/// One staged declarer-side interest-response record. The no-heap
/// replacement for the prior owned `DeclareOwned` staging: it carries
/// exactly the *identity* the [`crate::response_sink::ResponseSink`]
/// borrowed emit seam needs, so no codec type is constructed during the
/// fan phase. The observer drains a `BoundedVec<DeclResponseItem>` through
/// `send_declare_token_reply` / `send_declare_final_reply`.
///
/// SSOT note: the matched token's keyexpr is **not** copied into the
/// staged item — it lives once in the registry's token table and is
/// resolved by `token_id` at drain via [`LocalTokenRegistry::keyexpr_for`].
/// Keeping the item id-only (two `u64`s) avoids duplicating the keyexpr
/// and keeps the staging buffer small: a `BoundedVec<DeclResponseItem, N>`
/// is an inline array sized to the largest variant, so a `BoundedString`
/// per slot would have ballooned the buffer past a small MCU's stack
/// (the microbit/M0 overflow that surfaced this).
pub enum DeclResponseItem {
    /// One matching held token: emit an `interest_id`-tagged
    /// `Declare(DeclToken)` for the held token `token_id` (the keyexpr is
    /// resolved from the registry at drain).
    Token {
        /// The held token's unique id (the `DeclToken.id` wire field, and
        /// the registry lookup key for the keyexpr).
        token_id: u64,
        /// The peer's `interest_id`, echoed so zenoh-pico routes the
        /// reply to the matching pending query.
        interest_id: u64,
    },
    /// The terminating `Declare(DeclFinal)` for one interest-response
    /// chain. Emitted once after the chain's `Token` items (even when no
    /// token matched, so the peer's pending CURRENT query resolves).
    Final {
        /// The peer's `interest_id`, echoed on the terminator.
        interest_id: u64,
    },
}

/// One held-token row. Private to this module; the `BoundedVec` of these
/// is the no-alloc backing for the token table (was a `HashMap` key/value
/// pair before R311hn).
struct LocalToken {
    /// The token's unique id (was the `HashMap` key; carried in-row now
    /// the table is a linear `BoundedVec`).
    token_id: u64,
    /// The token's resolved literal keyexpr, stored as one
    /// [`BoundedString`] (no-alloc backing on MCU).
    keyexpr: BoundedString<{ caps::MAX_KEYEXPR_BYTES }>,
}

/// DECLARER-side registry of wz's own held `LivelinessToken`s.
///
/// Populated by `Session::declare_token` (one entry per held
/// `LivelinessToken`, keyed by the token's unique id) and emptied by the
/// token handle's `Drop`. The membership is consulted only when an
/// inbound non-final liveliness Interest arrives, to decide which held
/// tokens to reply with.
pub struct LocalTokenRegistry {
    /// R311hn (Track 2) — bounded token table (was an unbounded
    /// `HashMap<u64, String>`; now a linear `BoundedVec` with the id
    /// carried in-row, scanned on register / unregister / response —
    /// `caps::MAX_LOCAL_TOKENS` is small so the linear scan is cheaper
    /// than a no-alloc map).
    tokens: BoundedVec<LocalToken, { caps::MAX_LOCAL_TOKENS }>,
}

impl Default for LocalTokenRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalTokenRegistry {
    /// New empty registry. An empty registry still replies to an inbound
    /// Interest — with zero `DeclToken`s and a single terminating
    /// `DeclFinal` — so the peer's CURRENT query resolves cleanly even
    /// when wz holds no matching token.
    pub fn new() -> Self {
        Self {
            tokens: BoundedVec::new(),
        }
    }

    /// Record a locally-declared token. Called by
    /// `Session::declare_token` after the proactive `Declare(DeclToken)`
    /// emit.
    ///
    /// R311hn (Track 2) — fallible on the no-alloc backing:
    /// `Ok(true)` = newly registered, `Ok(false)` = duplicate `token_id`
    /// (no-op; matches the same-id-replaces intent — in practice each
    /// `LivelinessToken` gets a fresh monotonic id),
    /// `Err(TableFull)` = token table at [`caps::MAX_LOCAL_TOKENS`],
    /// `Err(KeyexprTooLong)` = keyexpr exceeds [`caps::MAX_KEYEXPR_BYTES`].
    /// On the `alloc` backing the two `Err` arms are never returned.
    pub fn register(&mut self, token_id: u64, keyexpr: &str) -> Result<bool, RegisterError> {
        if self.tokens.iter().any(|t| t.token_id == token_id) {
            return Ok(false);
        }
        let mut ke: BoundedString<{ caps::MAX_KEYEXPR_BYTES }> = BoundedString::new();
        ke.push_str(keyexpr)
            .map_err(|_| RegisterError::KeyexprTooLong)?;
        self.tokens
            .push(LocalToken {
                token_id,
                keyexpr: ke,
            })
            .map_err(|_| RegisterError::TableFull)?;
        Ok(true)
    }

    /// Drop a locally-declared token. Called by `LivelinessToken::Drop`
    /// alongside the proactive `Declare(UndeclToken)` emit. Returns
    /// `true` when a token was removed, `false` when no token matched
    /// (idempotent on a double-unregister).
    pub fn unregister(&mut self, token_id: u64) -> bool {
        let before = self.tokens.len();
        self.tokens.retain(|t| t.token_id != token_id);
        before != self.tokens.len()
    }

    /// Number of tokens currently held. Diagnostic / test surface.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Whether the registry holds no tokens. Diagnostic / test surface.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// R311hn (Track 2) — no-heap response entry (the staging SSOT). For
    /// the already-resolved Interest `pattern` (`None` = match-all, the
    /// `ke`-bit-clear tokens Interest), stage one [`DeclResponseItem::Token`]
    /// per held token whose keyexpr intersects the pattern, then one
    /// [`DeclResponseItem::Final`] terminator. The `Final` is staged even
    /// when no token matched. Borrow-driven (the caller supplies the
    /// resolved pattern), so it is the MCU no-heap path; the `alloc`
    /// inbound-parse path ([`Self::respond_to_interest`]) resolves the
    /// pattern through the peer table and funnels through here. Returns
    /// the number of `Token` items staged (the `Final` is not counted).
    ///
    /// Staging is best-effort under the buffer bound
    /// ([`caps::MAX_PENDING_DECLARES`]): if `pending` fills mid-chain the
    /// remaining items are dropped — INCLUDING the terminating `Final`,
    /// whose `let _ = pending.push(..)` below swallows the same
    /// `CapacityFull` the token loop just broke on. A caller that loses a
    /// chain's `Final` leaves that peer's CURRENT Interest unterminated.
    ///
    /// R311y341 — that is unreachable as shipped, and the reason is a cfg
    /// accident worth stating rather than trusting. `push` can only fail on
    /// the no-alloc backing (on `alloc` it is a `Vec` and `N` is advisory),
    /// and the only thing that threads ONE buffer across several Interests
    /// — [`Self::dispatch_messages`] — is itself `alloc`-gated. So the
    /// profile that can overflow does not batch, and the profile that
    /// batches cannot overflow. **The contract this method actually needs
    /// from a no-alloc caller: ONE Interest per buffer, drained between.**
    /// One chain is `MAX_LOCAL_TOKENS + 1` = 9 against 32. A future no-heap
    /// consumer that fans a frame's Interests through one buffer breaks the
    /// invariant silently — reserve the `Final` slot before adding tokens if
    /// that day comes.
    pub fn respond_to_interest_borrowed(
        &self,
        pattern: Option<&str>,
        interest_id: u64,
        pending: &mut BoundedVec<DeclResponseItem, { caps::MAX_PENDING_DECLARES }>,
    ) -> usize {
        let mut staged: usize = 0;
        for token in self.tokens.iter() {
            if !token_matches(token.keyexpr.as_str(), pattern) {
                continue;
            }
            // Stage the token by id only — the keyexpr stays in the table
            // (SSOT) and is resolved at drain via `keyexpr_for`.
            if pending
                .push(DeclResponseItem::Token {
                    token_id: token.token_id,
                    interest_id,
                })
                .is_err()
            {
                // Staging buffer full — stop adding tokens (best-effort).
                break;
            }
            staged = staged.saturating_add(1);
        }
        // Terminate the chain (best-effort under the buffer bound).
        let _ = pending.push(DeclResponseItem::Final { interest_id });
        staged
    }

    /// Resolve a staged [`DeclResponseItem::Token`]'s `token_id` back to
    /// the held token's literal keyexpr, for the drain phase's borrowed
    /// emit (`ResponseSink::send_declare_token_reply`). Returns `None` if
    /// the token was unregistered between staging and drain (a `DeclToken`
    /// for a vanished token is silently skipped — the chain's `DeclFinal`
    /// still resolves the peer's query).
    pub fn keyexpr_for(&self, token_id: u64) -> Option<&str> {
        self.tokens
            .iter()
            .find(|t| t.token_id == token_id)
            .map(|t| t.keyexpr.as_str())
    }

    /// R311hn (Track 2) — `alloc`-gated inbound-parse path: consume an
    /// owned `InterestOwned`, resolve its keyexpr against the peer table,
    /// then funnel through the no-heap [`Self::respond_to_interest_borrowed`].
    ///
    /// No-op unless the Interest is (a) non-final (CURRENT and/or FUTURE)
    /// and (b) a TOKENS-target Interest with a body. A tokens Interest
    /// that carries no keyexpr (ke bit clear) is treated as match-all; an
    /// Interest whose keyexpr references an undeclared peer mapping drops
    /// silently (same policy as the peer-side registries).
    #[cfg(feature = "alloc")]
    pub fn respond_to_interest<'a>(
        &self,
        interest: &InterestOwned,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
        pending: &mut BoundedVec<DeclResponseItem, { caps::MAX_PENDING_DECLARES }>,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        if !interest.c() {
            // No CURRENT bit (read via the generated `<sce:flags>` `c()`
            // accessor -- the SSOT for that bit, not a hand-rolled mask):
            // a FUTURE-only interest (live updates come from the declarer's
            // proactive Declare(DeclToken)) or a FINAL terminator. Neither
            // solicits a current-token replay -- zenoh gates the enumeration
            // on `mode.current()` (hat/client/token.rs).
            return;
        }
        let body = match &interest.body {
            Some(b) => b,
            // A non-final Interest with no body targets nothing
            // resolvable; the declarer has nothing to reply with.
            None => return,
        };
        if !body.to() {
            // Not a tokens Interest (subscriber / queryable interest) —
            // out of scope for the liveliness-token declarer.
            return;
        }
        let pattern: Option<String> = match &body.keyexpr {
            Some(w) => match resolve_wireexpr_in(&w.body, peer_keyexpr_table) {
                Some(p) => Some(p),
                // Unresolvable mapping id — drop silently.
                None => return,
            },
            None => None,
        };
        self.respond_to_interest_borrowed(pattern.as_deref(), interest.interest_id, pending);
    }

    /// Drain a `&[NetworkMessage]`, staging an interest-response for each
    /// inbound `Interest`. Mirror of the sibling registries'
    /// `dispatch_messages`. `alloc`-gated (consumes owned messages +
    /// resolves keyexprs).
    #[cfg(feature = "alloc")]
    pub fn dispatch_messages<'a>(
        &self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
        pending: &mut BoundedVec<DeclResponseItem, { caps::MAX_PENDING_DECLARES }>,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        for message in messages {
            if let NetworkMessage::Interest(interest) = message {
                self.respond_to_interest(interest, peer_keyexpr_table, pending);
            }
        }
    }

    /// `IterationEvent` adapter; mirror of the sibling registries.
    /// Non-`FramePayload` events (Lease branch, non-poll outcomes) are
    /// no-ops. `alloc`-gated (consumes owned messages).
    #[cfg(feature = "alloc")]
    pub fn dispatch_iteration_event<'a>(
        &self,
        event: IterationEvent<'_>,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
        pending: &mut BoundedVec<DeclResponseItem, { caps::MAX_PENDING_DECLARES }>,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event {
            self.dispatch_messages(messages, peer_keyexpr_table, pending);
        }
    }
}

/// Whether a held token's concrete `keyexpr` intersects the inbound
/// Interest `pattern` (`None` = match-all). Splits both into stack chunk
/// views (no heap); a keyexpr deeper than [`MAX_KEYEXPR_CHUNKS`] chunks
/// (cannot happen for a registered keyexpr) is treated as non-matching
/// rather than matched truncated.
fn token_matches(token_keyexpr: &str, pattern: Option<&str>) -> bool {
    let p = match pattern {
        Some(p) => p,
        None => return true,
    };
    let mut token_chunks: BoundedVec<&str, MAX_KEYEXPR_CHUNKS> = BoundedVec::new();
    for c in token_keyexpr.split('/') {
        if token_chunks.push(c).is_err() {
            return false;
        }
    }
    let mut pattern_chunks: BoundedVec<&str, MAX_KEYEXPR_CHUNKS> = BoundedVec::new();
    for c in p.split('/') {
        if pattern_chunks.push(c).is_err() {
            return false;
        }
    }
    keyexpr_intersect_patterns(&token_chunks, &pattern_chunks)
}

/// R311ho — build the borrowed `Declare(DeclToken)` interest-response for
/// one matching held token: the `I`-flagged outer `Declare` carrying the
/// peer's `interest_id`, wrapping a `DeclToken` whose keyexpr is inline
/// (mapping_id 0 / `WireexprLocal`).
///
/// This is the **single source** of the interest-response wire shape (the
/// MID/flag bits + the inline-keyexpr `WireexprLocal` form). Both emit
/// profiles funnel through it: the AP sink derives its owned form via
/// [`Declare::into_owned`]; an MCU sink encodes this borrowed value
/// directly through a `SliceSink` (`encode<S: SceSink>`, no heap). The
/// returned `Declare` borrows `keyexpr` for its lifetime.
pub fn build_token_reply(token_id: u64, keyexpr: &str, interest_id: u64) -> Declare<'_> {
    Declare {
        header: wire_const::N_MID_DECLARE | wire_const::FLAG_N_DECLARE_I,
        interest_id: Some(interest_id),
        extensions: None,
        body: DeclareVariant::CodecZenohDeclToken(DeclToken {
            header: wire_const::D_MID_TOKEN | wire_const::FLAG_D_N,
            id: token_id,
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprLocal(WireexprLocal {
                    id: 0,
                    suffix_len: Some(keyexpr.len() as u64),
                    suffix: Some(keyexpr),
                }),
            },
            // R311y804: Z=0 — the reply's bytes are unchanged; the body's ext
            // chain exists so an INBOUND Z-flagged DeclToken is consumed.
            extensions: None,
        }),
    }
}

/// R311ho — build the borrowed `Declare(DeclFinal)` that terminates the
/// interest-response chain for `interest_id`. Single source shared by the
/// AP (`into_owned`) and MCU (`SliceSink` encode) emit paths. The value
/// borrows nothing — R311y804 gave `DeclFinal` a lifetime parameter for its
/// inbound ext chain, but this builder leaves the chain absent, so the
/// parameter is free and the result is still `'static`.
pub fn build_final_reply(interest_id: u64) -> Declare<'static> {
    Declare {
        header: wire_const::N_MID_DECLARE | wire_const::FLAG_N_DECLARE_I,
        interest_id: Some(interest_id),
        extensions: None,
        body: DeclareVariant::CodecZenohDeclFinal(DeclFinal {
            header: wire_const::D_MID_FINAL,
            // R311y804: Z=0 — the bare one-byte Final both upstreams write.
            extensions: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    //! `std` is available under `#[cfg(test)]` per the wz-codecs sibling
    //! convention; production stays no_std + (optionally) alloc. The
    //! no-heap `respond_to_interest_borrowed` is exercised directly; the
    //! `alloc` inbound-parse path is exercised through `InterestOwned`.

    use super::*;
    use hashbrown::HashMap;

    /// Count `(tokens, finals)` staged in `pending`.
    fn count(
        pending: &BoundedVec<DeclResponseItem, { caps::MAX_PENDING_DECLARES }>,
    ) -> (usize, usize) {
        let t = pending
            .iter()
            .filter(|i| matches!(i, DeclResponseItem::Token { .. }))
            .count();
        let f = pending
            .iter()
            .filter(|i| matches!(i, DeclResponseItem::Final { .. }))
            .count();
        (t, f)
    }

    fn new_pending() -> BoundedVec<DeclResponseItem, { caps::MAX_PENDING_DECLARES }> {
        BoundedVec::new()
    }

    #[test]
    fn empty_registry_stages_only_a_final() {
        let reg = LocalTokenRegistry::new();
        let mut pending = new_pending();
        let staged = reg.respond_to_interest_borrowed(Some("group1/**"), 7, &mut pending);
        assert_eq!(staged, 0);
        assert_eq!(count(&pending), (0, 1));
        assert!(matches!(
            pending.iter().next(),
            Some(DeclResponseItem::Final { interest_id: 7 })
        ));
    }

    #[test]
    fn matching_token_stages_token_then_final() {
        let mut reg = LocalTokenRegistry::new();
        assert!(reg.register(1, "group1/zenoh-pico").unwrap());
        let mut pending = new_pending();
        let staged = reg.respond_to_interest_borrowed(Some("group1/**"), 42, &mut pending);
        assert_eq!(staged, 1);
        assert_eq!(count(&pending), (1, 1));
        // Wire ordering: the Token precedes the terminating Final.
        match pending.iter().next() {
            Some(DeclResponseItem::Token {
                token_id,
                interest_id,
            }) => {
                assert_eq!(*token_id, 1);
                assert_eq!(*interest_id, 42);
                // keyexpr is resolved from the registry (SSOT), not staged.
                assert_eq!(reg.keyexpr_for(*token_id), Some("group1/zenoh-pico"));
            }
            other => panic!("expected Token first, got {:?}", other.is_some()),
        }
        assert!(matches!(
            pending.iter().last(),
            Some(DeclResponseItem::Final { interest_id: 42 })
        ));
    }

    /// R2290 (open-debt item 626) — the NEGATIVE twin of the assertion just
    /// above, and the reason it is worth writing separately: the population
    /// this round derived is "every staged interest-reply arm that ANNOUNCES a
    /// declaration", and each such arm has to resolve to `None` once what it
    /// announces is gone. The subscriber plane's AGGREGATE arm did not, and
    /// re-announced a subscription after its `UndeclSubscriber` had already
    /// gone out. This arm resolves through the token table, so it does — but
    /// only the positive half was ever asserted, and "resolves correctly while
    /// the token lives" is exactly the half a broken arm also passes.
    #[test]
    fn a_token_unregistered_between_stage_and_drain_resolves_to_none() {
        let mut reg = LocalTokenRegistry::new();
        assert!(reg.register(1, "group1/zenoh-pico").unwrap());
        let mut pending = new_pending();
        assert_eq!(
            reg.respond_to_interest_borrowed(Some("group1/**"), 42, &mut pending),
            1,
            "a matching token must stage exactly one reply — a fixture that \
             stages none would make the assertion below vacuous"
        );

        // The application drops the token inside the stage/drain window.
        assert!(reg.unregister(1));

        match pending.iter().next() {
            Some(DeclResponseItem::Token { token_id, .. }) => {
                assert_eq!(
                    reg.keyexpr_for(*token_id),
                    None,
                    "a staged DeclToken must not announce a token this session \
                     no longer holds"
                );
            }
            other => panic!("expected Token first, got {:?}", other.is_some()),
        }
        assert!(
            matches!(
                pending.iter().last(),
                Some(DeclResponseItem::Final { interest_id: 42 })
            ),
            "the chain's Final still terminates the peer's solicitation"
        );
    }

    #[test]
    fn match_all_pattern_stages_every_token() {
        let mut reg = LocalTokenRegistry::new();
        reg.register(1, "a/b").unwrap();
        reg.register(2, "c/d").unwrap();
        let mut pending = new_pending();
        // `None` pattern = the ke-bit-clear tokens Interest (match-all).
        let staged = reg.respond_to_interest_borrowed(None, 5, &mut pending);
        assert_eq!(staged, 2);
        assert_eq!(count(&pending), (2, 1));
    }

    #[test]
    fn non_matching_token_stages_only_final() {
        let mut reg = LocalTokenRegistry::new();
        reg.register(1, "home/temp").unwrap();
        let mut pending = new_pending();
        let staged = reg.respond_to_interest_borrowed(Some("group1/**"), 9, &mut pending);
        assert_eq!(staged, 0);
        assert_eq!(count(&pending), (0, 1));
    }

    #[test]
    fn unregister_removes_token_from_responses() {
        let mut reg = LocalTokenRegistry::new();
        reg.register(1, "group1/zenoh-pico").unwrap();
        assert_eq!(reg.len(), 1);
        assert!(reg.unregister(1));
        assert!(reg.is_empty());
        assert!(!reg.unregister(1), "double-unregister is idempotent");
        let mut pending = new_pending();
        reg.respond_to_interest_borrowed(Some("group1/**"), 5, &mut pending);
        assert_eq!(count(&pending), (0, 1));
    }

    #[test]
    fn multiple_matching_tokens_each_stage_a_token() {
        let mut reg = LocalTokenRegistry::new();
        reg.register(1, "group1/a").unwrap();
        reg.register(2, "group1/b").unwrap();
        reg.register(3, "other/c").unwrap();
        let mut pending = new_pending();
        let staged = reg.respond_to_interest_borrowed(Some("group1/**"), 11, &mut pending);
        assert_eq!(staged, 2);
        assert_eq!(count(&pending), (2, 1));
        // The Final is last (terminates the batch).
        assert!(matches!(
            pending.iter().last(),
            Some(DeclResponseItem::Final { .. })
        ));
    }

    #[test]
    fn duplicate_register_is_noop() {
        let mut reg = LocalTokenRegistry::new();
        assert!(reg.register(1, "a").unwrap());
        assert!(
            !reg.register(1, "b").unwrap(),
            "second register on same token_id must report no-op"
        );
        assert_eq!(reg.len(), 1);
    }

    /// `alloc` inbound-parse path: an InterestFinal (C/F both clear) is
    /// the subscriber's own terminator, not a request — the declarer
    /// stages nothing.
    #[cfg(feature = "alloc")]
    #[test]
    fn final_interest_is_noop() {
        use wz_codecs::interest_body::InterestBodyOwned;
        use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};
        use wz_codecs::wireexpr_local::WireexprLocalOwned;

        let mut reg = LocalTokenRegistry::new();
        reg.register(1, "group1/zenoh-pico").unwrap();
        let interest = InterestOwned {
            header: 0x19, // C/F cleared → final
            interest_id: 3,
            body: Some(InterestBodyOwned {
                header: 0x08, // tokens bit
                keyexpr: Some(WireexprOwned {
                    body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                        id: 0,
                        suffix_len: Some(9),
                        suffix: Some(crate::codec_owned::owned_string("group1/**").unwrap()),
                    }),
                }),
            }),
            extensions: None,
        };
        let mut pending = new_pending();
        reg.respond_to_interest(&interest, &HashMap::new(), &mut pending);
        assert!(pending.is_empty());
    }

    /// `alloc` inbound-parse path: a non-final Interest whose body does
    /// NOT target tokens is out of scope for the liveliness-token
    /// declarer.
    #[cfg(feature = "alloc")]
    #[test]
    fn non_tokens_interest_is_noop() {
        use wz_codecs::interest_body::InterestBodyOwned;

        let mut reg = LocalTokenRegistry::new();
        reg.register(1, "group1/zenoh-pico").unwrap();
        let interest = InterestOwned {
            header: 0x19 | 0x20, // CURRENT
            interest_id: 4,
            body: Some(InterestBodyOwned {
                header: 0x00, // tokens bit clear
                keyexpr: None,
            }),
            extensions: None,
        };
        let mut pending = new_pending();
        reg.respond_to_interest(&interest, &HashMap::new(), &mut pending);
        assert!(pending.is_empty());
    }

    /// R311xx (diagnose-first) — a FUTURE-only tokens Interest (the
    /// history=false subscriber's declare) must NOT trigger a
    /// current-token replay. zenoh gates the replay on `mode.current()`
    /// (`zenoh/src/net/routing/hat/client/token.rs` @ `fn propagate_token`);
    /// the FUTURE path is covered by the
    /// declarer's proactive `Declare(DeclToken)` at token-declare time,
    /// not by replaying current state to a future-only subscriber. The
    /// pre-fix gate was "non-final" (C|F), which wrongly replied to a
    /// FUTURE-only (C-clear) interest; this pins the corrected
    /// CURRENT-only gate.
    #[cfg(feature = "alloc")]
    #[test]
    fn future_only_interest_stages_nothing() {
        use wz_codecs::interest_body::InterestBodyOwned;
        use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};
        use wz_codecs::wireexpr_local::WireexprLocalOwned;

        let mut reg = LocalTokenRegistry::new();
        reg.register(1, "group1/zenoh-pico").unwrap();
        let interest = InterestOwned {
            header: 0x19 | 0x40, // FUTURE only — no CURRENT bit
            interest_id: 7,
            body: Some(InterestBodyOwned {
                header: 0x08, // tokens bit
                keyexpr: Some(WireexprOwned {
                    body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                        id: 0,
                        suffix_len: Some(9),
                        suffix: Some(crate::codec_owned::owned_string("group1/**").unwrap()),
                    }),
                }),
            }),
            extensions: None,
        };
        let mut pending = new_pending();
        reg.respond_to_interest(&interest, &HashMap::new(), &mut pending);
        assert!(
            pending.is_empty(),
            "FUTURE-only interest must not stage a current-token replay",
        );
    }

    /// `alloc` inbound-parse path: a non-final TOKENS Interest funnels
    /// through to the no-heap staging SSOT.
    #[cfg(feature = "alloc")]
    #[test]
    fn tokens_interest_stages_matching_response() {
        use wz_codecs::interest_body::InterestBodyOwned;
        use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};
        use wz_codecs::wireexpr_local::WireexprLocalOwned;

        let mut reg = LocalTokenRegistry::new();
        reg.register(1, "group1/zenoh-pico").unwrap();
        let interest = InterestOwned {
            header: 0x19 | 0x20, // CURRENT
            interest_id: 42,
            body: Some(InterestBodyOwned {
                header: 0x08, // tokens bit
                keyexpr: Some(WireexprOwned {
                    body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                        id: 0,
                        suffix_len: Some(9),
                        suffix: Some(crate::codec_owned::owned_string("group1/**").unwrap()),
                    }),
                }),
            }),
            extensions: None,
        };
        let mut pending = new_pending();
        reg.respond_to_interest(&interest, &HashMap::new(), &mut pending);
        assert_eq!(count(&pending), (1, 1));
    }

    /// R311y740 (N37) — the own-space WITNESS for the local-token INTEREST
    /// plane. This is the declarer-side responder: it resolves the inbound
    /// Interest's keyexpr and replays the LOCAL tokens that match it, so a
    /// wrong-space read changes which of our own tokens we hand back.
    ///
    /// THE DISCRIMINATOR is the collision plus two disjoint held tokens: id 7
    /// resolves `ours/**` in our space and `theirs/**` in the peer's, and one
    /// token is registered under each prefix. Reading the wrong space replays
    /// the OTHER token — a confident wrong answer, not silence.
    #[cfg(feature = "alloc")]
    #[test]
    fn an_own_space_alias_resolves_in_our_space_on_the_local_token_interest_plane() {
        use alloc::string::ToString;
        use wz_codecs::interest_body::InterestBodyOwned;
        use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};
        use wz_codecs::wireexpr_nonlocal::WireexprNonlocalOwned;

        let mut reg = LocalTokenRegistry::new();
        reg.register(1, "ours/tok").unwrap();
        reg.register(2, "theirs/tok").unwrap();

        let mut peer = HashMap::new();
        peer.insert(7u64, "theirs/**".to_string());
        let mut own = HashMap::new();
        own.insert(7u64, "ours/**".to_string());

        // M=0 (`WireexprNonlocal`) with no inline suffix: the id alone.
        let interest = InterestOwned {
            header: 0x19 | 0x20, // CURRENT
            interest_id: 42,
            body: Some(InterestBodyOwned {
                header: 0x08, // tokens bit
                keyexpr: Some(WireexprOwned {
                    body: WireexprOwnedVariant::WireexprNonlocal(WireexprNonlocalOwned {
                        id: 7,
                        suffix_len: None,
                        suffix: None,
                    }),
                }),
            }),
            extensions: None,
        };

        let mut pending = new_pending();
        reg.respond_to_interest(
            &interest,
            crate::wireexpr_resolve::MappingSpaces::with_own(&peer, &own),
            &mut pending,
        );

        assert_eq!(
            count(&pending),
            (1, 1),
            "exactly one token matches `ours/**` -- the interest resolved in \
             OUR space",
        );
        assert!(
            pending
                .iter()
                .any(|i| matches!(i, DeclResponseItem::Token { token_id: 1, .. })),
            "token 1 is the `ours/tok` one; staging token 2 would mean the \
             interest was resolved out of the peer's space",
        );
    }

    /// ANTI-VACUITY twin: with only the peer's space the same Interest
    /// resolves nothing, so NO token is replayed (the bare `Final` still
    /// terminates the chain — an unresolvable interest is not a hang).
    #[cfg(feature = "alloc")]
    #[test]
    fn without_an_own_space_the_local_token_interest_plane_refuses_the_same_alias() {
        use alloc::string::ToString;
        use wz_codecs::interest_body::InterestBodyOwned;
        use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};
        use wz_codecs::wireexpr_nonlocal::WireexprNonlocalOwned;

        let mut reg = LocalTokenRegistry::new();
        reg.register(1, "ours/tok").unwrap();
        reg.register(2, "theirs/tok").unwrap();

        let mut peer = HashMap::new();
        peer.insert(7u64, "theirs/**".to_string());

        let interest = InterestOwned {
            header: 0x19 | 0x20,
            interest_id: 42,
            body: Some(InterestBodyOwned {
                header: 0x08,
                keyexpr: Some(WireexprOwned {
                    body: WireexprOwnedVariant::WireexprNonlocal(WireexprNonlocalOwned {
                        id: 7,
                        suffix_len: None,
                        suffix: None,
                    }),
                }),
            }),
            extensions: None,
        };

        let mut pending = new_pending();
        reg.respond_to_interest(&interest, &peer, &mut pending);

        assert_eq!(
            count(&pending),
            (0, 0),
            "with no own space an M=0 alias must refuse -- never fall back to \
             the peer's table (which would have replayed `theirs/tok`)",
        );
    }
}
