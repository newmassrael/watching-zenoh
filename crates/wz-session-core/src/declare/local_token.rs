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
//! `vendor/zenoh-pico/src/session/liveliness.c:218-256`). This registry
//! stages exactly that response into the observer's pending-declare
//! buffer; the drain phase flushes it through
//! [`crate::response_sink::ResponseSink::send_declare`].
//!
//! Two-phase contract (mirror of the queryable registry): the inbound
//! Interest is processed during the fan phase (no actions handle
//! available), staging `DeclareOwned` records; the observer's drain
//! phase emits them through the sink. Wire ordering is preserved —
//! every `DeclToken` precedes the terminating `DeclFinal`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use hashbrown::HashMap;

use wz_codecs::decl_final::DeclFinal;
use wz_codecs::decl_token::DeclTokenOwned;
use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant};
use wz_codecs::interest::InterestOwned;
use wz_codecs::wire_const;
use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};
use wz_codecs::wireexpr_local::WireexprLocalOwned;

use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
use crate::keyexpr_match::keyexpr_intersect_patterns;
use crate::network_message::NetworkMessage;
use crate::wireexpr_resolve::resolve_wireexpr;

/// Outer Interest header `C | F` mask: a non-zero result means the
/// Interest is non-final (CURRENT and/or FUTURE), i.e. a real request
/// rather than an `InterestFinal` terminator. Mirrors the
/// `(header & 0x60) == 0` final test in
/// [`crate::declare::liveliness_subscriber`]. (An Interest-flag mask, not
/// a declaration MID, so it stays local rather than in `wire_const`'s
/// declaration-MID block.)
const INTEREST_NOT_FINAL_MASK: u8 = 0x60;

/// DECLARER-side registry of wz's own held `LivelinessToken`s.
///
/// Populated by `Session::declare_token` (one entry per held
/// `LivelinessToken`, keyed by the token's unique id) and emptied by the
/// token handle's `Drop`. The membership is consulted only when an
/// inbound non-final liveliness Interest arrives, to decide which held
/// tokens to reply with.
pub struct LocalTokenRegistry {
    /// `token_id -> resolved literal keyexpr` for every token wz
    /// currently holds. HashMap because the membership invariant is by
    /// id (Drop removes by id) and the only read consumer
    /// ([`Self::respond_to_interest`]) iterates without ordering
    /// requirements — O(1) register / unregister + a full scan per
    /// inbound Interest (rare).
    tokens: HashMap<u64, String>,
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
            tokens: HashMap::new(),
        }
    }

    /// Record a locally-declared token. Called by
    /// `Session::declare_token` after the proactive `Declare(DeclToken)`
    /// emit. A subsequent register with the same id overwrites the prior
    /// keyexpr (matches the same-id-replaces convention of the
    /// peer-side registries), though in practice each `LivelinessToken`
    /// gets a fresh monotonic id.
    pub fn register(&mut self, token_id: u64, keyexpr: String) {
        self.tokens.insert(token_id, keyexpr);
    }

    /// Drop a locally-declared token. Called by `LivelinessToken::Drop`
    /// alongside the proactive `Declare(UndeclToken)` emit. Removing an
    /// id that was never registered is silent.
    pub fn unregister(&mut self, token_id: u64) {
        self.tokens.remove(&token_id);
    }

    /// Number of tokens currently held. Diagnostic / test surface.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Whether the registry holds no tokens. Diagnostic / test surface.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Stage the R283 interest-response for one inbound Interest.
    ///
    /// No-op unless the Interest is (a) non-final (CURRENT and/or
    /// FUTURE) and (b) a TOKENS-target Interest with a body. For a
    /// matching Interest, stages one `interest_id`-tagged
    /// `Declare(DeclToken)` per held token whose keyexpr intersects the
    /// Interest pattern, then one `interest_id`-tagged
    /// `Declare(DeclFinal)` terminator. The `DeclFinal` is staged even
    /// when no token matched so the peer's pending query is always
    /// resolved.
    fn respond_to_interest(
        &self,
        interest: &InterestOwned,
        peer_keyexpr_table: &HashMap<u64, String>,
        pending: &mut Vec<DeclareOwned>,
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
        // Resolve the Interest's keyexpr pattern. A tokens Interest that
        // carries no keyexpr (ke bit clear) is treated as match-all.
        let pattern = match &body.keyexpr {
            Some(w) => match resolve_wireexpr(&w.body, peer_keyexpr_table) {
                Some(p) => Some(p),
                // Unresolvable mapping id — drop silently (same policy as
                // the peer-side registries on an unknown mapping).
                None => return,
            },
            None => None,
        };
        for (id, keyexpr) in &self.tokens {
            let matches = match &pattern {
                Some(p) => {
                    let pattern_chunks: Vec<&str> = p.split('/').collect();
                    let token_chunks: Vec<&str> = keyexpr.split('/').collect();
                    keyexpr_intersect_patterns(&token_chunks, &pattern_chunks)
                }
                None => true,
            };
            if matches {
                pending.push(build_decl_token_reply(*id, keyexpr, interest.interest_id));
            }
        }
        pending.push(build_decl_final_reply(interest.interest_id));
    }

    /// Drain a `Vec<NetworkMessage>`, staging an interest-response for
    /// each inbound `Interest`. Mirror of the sibling registries'
    /// `dispatch_messages`.
    pub fn dispatch_messages(
        &self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: &HashMap<u64, String>,
        pending: &mut Vec<DeclareOwned>,
    ) {
        for message in messages {
            if let NetworkMessage::Interest(interest) = message {
                self.respond_to_interest(interest, peer_keyexpr_table, pending);
            }
        }
    }

    /// `IterationEvent` adapter; mirror of the sibling registries.
    /// Non-`FramePayload` events (Lease branch, non-poll outcomes) are
    /// no-ops.
    pub fn dispatch_iteration_event(
        &self,
        event: IterationEvent<'_>,
        peer_keyexpr_table: &HashMap<u64, String>,
        pending: &mut Vec<DeclareOwned>,
    ) {
        if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event {
            self.dispatch_messages(messages, peer_keyexpr_table, pending);
        }
    }
}

/// Build an `interest_id`-tagged `Declare(DeclToken)` carrying wz's own
/// token keyexpr inline (mapping_id 0 / `WireexprLocal`). The `I` flag
/// on the outer header + the `Some(interest_id)` field route it to the
/// peer's pending liveliness query. Mirror of the proactive
/// `build_declare_token` in wz-runtime-tokio, with the interest_id set.
fn build_decl_token_reply(token_id: u64, keyexpr: &str, interest_id: u64) -> DeclareOwned {
    DeclareOwned {
        header: wire_const::N_MID_DECLARE | wire_const::FLAG_N_DECLARE_I,
        interest_id: Some(interest_id),
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohDeclToken(DeclTokenOwned {
            header: wire_const::D_MID_TOKEN | wire_const::FLAG_D_N,
            id: token_id,
            keyexpr: WireexprOwned {
                body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                    id: 0,
                    suffix_len: Some(keyexpr.len() as u64),
                    suffix: Some(keyexpr.to_string()),
                }),
            },
        }),
    }
}

/// Build an `interest_id`-tagged `Declare(DeclFinal)` terminating the
/// peer's pending liveliness query. Mirror of the proactive
/// `build_declare_final` in wz-runtime-tokio, with the interest_id set.
fn build_decl_final_reply(interest_id: u64) -> DeclareOwned {
    DeclareOwned {
        header: wire_const::N_MID_DECLARE | wire_const::FLAG_N_DECLARE_I,
        interest_id: Some(interest_id),
        extensions: None,
        body: DeclareOwnedVariant::CodecZenohDeclFinal(DeclFinal {
            header: wire_const::D_MID_FINAL,
        }),
    }
}

#[cfg(test)]
mod tests {
    //! `Mutex` is unused here (no shared-state tests); the registry
    //! response is a pure function of (held tokens, inbound Interest).
    //! `std` is available under `#[cfg(test)]` per the wz-codecs sibling
    //! convention; production stays no_std + alloc.

    use super::*;
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use wz_codecs::interest_body::InterestBodyOwned;

    /// `N_MID_INTEREST` outer MID + the `C` (CURRENT) flag = a non-final
    /// Interest. (0x19 | 0x20.)
    const INTEREST_HEADER_CURRENT: u8 = 0x19 | 0x20;
    /// `InterestBody` header with the `to` (TOKENS) bit set (0x08).
    const INTEREST_BODY_TOKENS: u8 = 0x08;

    fn empty_table() -> HashMap<u64, String> {
        HashMap::new()
    }

    /// A non-final, TOKENS-target Interest carrying `pattern` as an
    /// inline literal keyexpr (mapping_id 0).
    fn tokens_interest(interest_id: u64, pattern: &str) -> InterestOwned {
        InterestOwned {
            header: INTEREST_HEADER_CURRENT,
            interest_id,
            body: Some(InterestBodyOwned {
                header: INTEREST_BODY_TOKENS,
                keyexpr: Some(WireexprOwned {
                    body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                        id: 0,
                        suffix_len: Some(pattern.len() as u64),
                        suffix: Some(pattern.to_string()),
                    }),
                }),
            }),
            extensions: None,
        }
    }

    fn stage(reg: &LocalTokenRegistry, interest: &InterestOwned) -> Vec<DeclareOwned> {
        let mut pending = Vec::new();
        reg.respond_to_interest(interest, &empty_table(), &mut pending);
        pending
    }

    fn is_decl_token(d: &DeclareOwned) -> bool {
        matches!(d.body, DeclareOwnedVariant::CodecZenohDeclToken(_))
    }
    fn is_decl_final(d: &DeclareOwned) -> bool {
        matches!(d.body, DeclareOwnedVariant::CodecZenohDeclFinal(_))
    }

    #[test]
    fn empty_registry_responds_with_only_a_final() {
        let reg = LocalTokenRegistry::new();
        let pending = stage(&reg, &tokens_interest(7, "group1/**"));
        // Even with no held token the pending query must be resolved:
        // exactly one DeclFinal, no DeclToken.
        assert_eq!(pending.len(), 1);
        assert!(is_decl_final(&pending[0]));
        assert_eq!(pending[0].interest_id, Some(7));
    }

    #[test]
    fn matching_token_yields_decl_token_then_final() {
        let mut reg = LocalTokenRegistry::new();
        reg.register(1, "group1/zenoh-pico".to_string());
        let pending = stage(&reg, &tokens_interest(42, "group1/**"));
        assert_eq!(pending.len(), 2);
        // Wire ordering: the DeclToken precedes the terminating DeclFinal.
        assert!(is_decl_token(&pending[0]));
        assert!(is_decl_final(&pending[1]));
        // Both carry the echoed interest_id so zenoh-pico routes them to
        // the matching pending query.
        assert_eq!(pending[0].interest_id, Some(42));
        assert_eq!(pending[1].interest_id, Some(42));
        // The DeclToken carries the held token's id + literal keyexpr.
        if let DeclareOwnedVariant::CodecZenohDeclToken(t) = &pending[0].body {
            assert_eq!(t.id, 1);
            if let WireexprOwnedVariant::WireexprLocal(w) = &t.keyexpr.body {
                assert_eq!(w.suffix.as_deref(), Some("group1/zenoh-pico"));
            } else {
                panic!("expected WireexprLocal");
            }
        } else {
            panic!("expected DeclToken");
        }
    }

    #[test]
    fn non_matching_token_yields_only_final() {
        let mut reg = LocalTokenRegistry::new();
        reg.register(1, "home/temp".to_string());
        let pending = stage(&reg, &tokens_interest(9, "group1/**"));
        // home/temp does not intersect group1/** — no DeclToken, just the
        // terminating DeclFinal.
        assert_eq!(pending.len(), 1);
        assert!(is_decl_final(&pending[0]));
    }

    #[test]
    fn final_interest_is_noop() {
        let mut reg = LocalTokenRegistry::new();
        reg.register(1, "group1/zenoh-pico".to_string());
        // An InterestFinal (C/F both clear) is the subscriber's own
        // terminator, not a request — the declarer stages nothing.
        let mut interest = tokens_interest(3, "group1/**");
        interest.header = 0x19; // C/F cleared → final
        let pending = stage(&reg, &interest);
        assert!(pending.is_empty());
    }

    #[test]
    fn non_tokens_interest_is_noop() {
        let mut reg = LocalTokenRegistry::new();
        reg.register(1, "group1/zenoh-pico".to_string());
        // A non-final Interest whose body does NOT target tokens (e.g. a
        // subscribers/queryables interest) is out of scope for the
        // liveliness-token declarer.
        let mut interest = tokens_interest(4, "group1/**");
        if let Some(body) = interest.body.as_mut() {
            body.header = 0x00; // clear the `to` bit
        }
        let pending = stage(&reg, &interest);
        assert!(pending.is_empty());
    }

    #[test]
    fn unregister_removes_token_from_responses() {
        let mut reg = LocalTokenRegistry::new();
        reg.register(1, "group1/zenoh-pico".to_string());
        assert_eq!(reg.len(), 1);
        reg.unregister(1);
        assert!(reg.is_empty());
        // After unregister the token no longer appears in a response.
        let pending = stage(&reg, &tokens_interest(5, "group1/**"));
        assert_eq!(pending.len(), 1);
        assert!(is_decl_final(&pending[0]));
    }

    #[test]
    fn multiple_matching_tokens_each_get_a_decl_token() {
        let mut reg = LocalTokenRegistry::new();
        reg.register(1, "group1/a".to_string());
        reg.register(2, "group1/b".to_string());
        reg.register(3, "other/c".to_string());
        let pending = stage(&reg, &tokens_interest(11, "group1/**"));
        // Two matching tokens (group1/a, group1/b) + one terminating
        // DeclFinal; other/c does not intersect group1/**.
        let decl_tokens = pending.iter().filter(|d| is_decl_token(d)).count();
        let decl_finals = pending.iter().filter(|d| is_decl_final(d)).count();
        assert_eq!(decl_tokens, 2);
        assert_eq!(decl_finals, 1);
        // The DeclFinal is last (terminates the batch).
        assert!(is_decl_final(pending.last().unwrap()));
    }
}
