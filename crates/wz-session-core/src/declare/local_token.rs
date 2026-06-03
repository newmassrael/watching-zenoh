// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//!    [`DeclResponseItem`] records (a `Token` per match carrying the
//!    held keyexpr in a `BoundedString`, then one `Final`) into a
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

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use hashbrown::HashMap;

#[cfg(feature = "alloc")]
use wz_codecs::interest::InterestOwned;

#[cfg(feature = "alloc")]
use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
#[cfg(feature = "alloc")]
use crate::network_message::NetworkMessage;
#[cfg(feature = "alloc")]
use crate::wireexpr_resolve::resolve_wireexpr;

/// Outer Interest header `C | F` mask: a non-zero result means the
/// Interest is non-final (CURRENT and/or FUTURE), i.e. a real request
/// rather than an `InterestFinal` terminator. Mirrors the
/// `(header & 0x60) == 0` final test in
/// [`crate::declare::liveliness_subscriber`]. (An Interest-flag mask, not
/// a declaration MID, so it stays local rather than in `wire_const`'s
/// declaration-MID block.) Consumed only by the `alloc` inbound-parse
/// path ([`LocalTokenRegistry::respond_to_interest`]).
#[cfg(feature = "alloc")]
const INTEREST_NOT_FINAL_MASK: u8 = 0x60;

/// One staged declarer-side interest-response record. The no-heap
/// replacement for the prior owned `DeclareOwned` staging: it carries
/// exactly the data the [`crate::response_sink::ResponseSink`] borrowed
/// emit seam needs, so no codec type is constructed during the fan
/// phase. The observer drains a `BoundedVec<DeclResponseItem>` through
/// `send_declare_token_reply` / `send_declare_final_reply`.
///
/// `clippy::large_enum_variant` is allowed deliberately: the `Token`
/// variant carries a [`BoundedString`] and dwarfs `Final`, but the
/// staging buffer is a `BoundedVec<DeclResponseItem, _>` — an inline
/// array already sized to the largest variant per slot — so the size
/// disparity is already paid by the backing. The lint's suggested fix
/// (box the large variant) would put the keyexpr on the heap, defeating
/// the whole no-heap purpose of this type.
#[allow(clippy::large_enum_variant)]
pub enum DeclResponseItem {
    /// One matching held token: emit an `interest_id`-tagged
    /// `Declare(DeclToken)` carrying `token_id` + `keyexpr`.
    Token {
        /// The held token's unique id (the `DeclToken.id` wire field).
        token_id: u64,
        /// The held token's resolved literal keyexpr (copied into a
        /// `BoundedString` — no heap).
        keyexpr: BoundedString<{ caps::MAX_KEYEXPR_BYTES }>,
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
    /// remaining items are dropped — the bound is sized so a single
    /// Interest's chain always fits.
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
            let mut keyexpr: BoundedString<{ caps::MAX_KEYEXPR_BYTES }> = BoundedString::new();
            // The source is already a `BoundedString<MAX_KEYEXPR_BYTES>`,
            // so this copy cannot overflow; a defensive `continue` keeps
            // the loop total rather than panicking on the impossible arm.
            if keyexpr.push_str(token.keyexpr.as_str()).is_err() {
                continue;
            }
            if pending
                .push(DeclResponseItem::Token {
                    token_id: token.token_id,
                    keyexpr,
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
    pub fn respond_to_interest(
        &self,
        interest: &InterestOwned,
        peer_keyexpr_table: &HashMap<u64, String>,
        pending: &mut BoundedVec<DeclResponseItem, { caps::MAX_PENDING_DECLARES }>,
    ) {
        if (interest.header & INTEREST_NOT_FINAL_MASK) == 0 {
            // InterestFinal terminator — the subscriber-side registry
            // handles it (history-complete marking); nothing to reply.
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
            Some(w) => match resolve_wireexpr(&w.body, peer_keyexpr_table) {
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
    pub fn dispatch_messages(
        &self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: &HashMap<u64, String>,
        pending: &mut BoundedVec<DeclResponseItem, { caps::MAX_PENDING_DECLARES }>,
    ) {
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
    pub fn dispatch_iteration_event(
        &self,
        event: IterationEvent<'_>,
        peer_keyexpr_table: &HashMap<u64, String>,
        pending: &mut BoundedVec<DeclResponseItem, { caps::MAX_PENDING_DECLARES }>,
    ) {
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

#[cfg(test)]
mod tests {
    //! `std` is available under `#[cfg(test)]` per the wz-codecs sibling
    //! convention; production stays no_std + (optionally) alloc. The
    //! no-heap `respond_to_interest_borrowed` is exercised directly; the
    //! `alloc` inbound-parse path is exercised through `InterestOwned`.

    use super::*;

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
                keyexpr,
                interest_id,
            }) => {
                assert_eq!(*token_id, 1);
                assert_eq!(keyexpr.as_str(), "group1/zenoh-pico");
                assert_eq!(*interest_id, 42);
            }
            other => panic!("expected Token first, got {:?}", other.is_some()),
        }
        assert!(matches!(
            pending.iter().last(),
            Some(DeclResponseItem::Final { interest_id: 42 })
        ));
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
                        suffix: Some(alloc::string::String::from("group1/**")),
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
                        suffix: Some(alloc::string::String::from("group1/**")),
                    }),
                }),
            }),
            extensions: None,
        };
        let mut pending = new_pending();
        reg.respond_to_interest(&interest, &HashMap::new(), &mut pending);
        assert_eq!(count(&pending), (1, 1));
    }
}
