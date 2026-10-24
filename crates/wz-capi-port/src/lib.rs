// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The port between a wz C ABI and the engine that runs its sessions.
//!
//! A C ABI describes what a C program asks of a session; an engine runs the session. Today the
//! one engine is `wz-capi-core` (one OS thread and one tokio runtime per session); the next is
//! the cooperative engine, which the application steps as zenoh-pico's single-threaded arm does
//! (`docs/capi-pico-on-coop-engine.md`). This crate is what both sides name: the vocabulary a
//! request and its answer are spelled in, independent of any engine, async runtime or thread.
//!
//! ## What lives here
//!
//! A type belongs here when an ABI and an engine both have to name it and nothing in it is a
//! particular engine's. The ids an ABI's handles carry ([`SubId`], [`MatchId`], [`FilterId`]),
//! the callback factories an ABI hands an engine ([`SubscriberSink`], [`MatchingSink`]), the
//! form a key takes on the wire ([`WireKey`]), what a write filter counts ([`FilterPlane`]) and
//! what a filtered put did ([`FilteredPut`], [`FanoutError`]). They lived in `wz-capi-core`'s
//! face registry, which re-exports them, so the zenoh-c ABI keeps its paths.
//!
//! The operations an engine implements are [`SessionEngine`]: what a zenoh-pico client asks of a
//! session, which an ABI reaches through `Arc<dyn SessionEngine>` and nothing else; and
//! [`SessionDrive`], the session as a C handle holds it (its close, and how it is driven).
//!
//! A queryable's callbacks are minted with what the face's queries are held through
//! ([`QueryHolder`]), so a query a C program keeps past its handler ([`HeldQuery`]) answers on its
//! own route whatever engine carried it.
//!
//! What stays with an engine is everything that names its sessions: the liveliness sample of the
//! tokio runtime, and the registry itself.
//!
//! ## Why a factory, not a callback
//!
//! An engine may hold several faces for one C session and replays every declaration onto each
//! face as it comes up, so a callback is needed once PER FACE: the ABI hands in something that
//! MINTS one, and the engine never learns what it closes over. The factory owns whatever the ABI
//! captured (its C closure), so the last factory released still runs the C `drop(context)`, which
//! is allowed to re-enter the session: an engine releases these outside its own locks.

use std::sync::Arc;

use wz_session_core::sink::SampleView;

mod drive;
mod engine;
mod query;
pub use drive::{CalledFromReadTask, SessionClosed, SessionDrive};
pub use engine::SessionEngine;
pub use query::{HeldQuery, QblId, QueryCallback, QueryHolder, QueryableSink};

/// A C-level subscription id — what a `z_owned_subscriber_t` handle carries. It keys whatever an
/// engine holds for the one C subscription (the per-face subscribers it spawned, on an engine
/// with faces).
pub type SubId = u64;

/// A C-level matching-listener id, keying what an engine holds for one C declaration.
pub type MatchId = u64;

/// A C-level WRITE FILTER id — zenoh-pico's `_z_write_filter_t`, which a publisher or querier
/// holds for its whole life.
pub type FilterId = u64;

/// Mints one subscriber callback per face.
pub type SubscriberSink =
    Arc<dyn Fn() -> Box<dyn FnMut(&dyn SampleView) + Send + 'static> + Send + Sync>;

/// Delivers ONE aggregated matching verdict to C.
///
/// Unlike [`SubscriberSink`] this is NOT a per-face factory, and the difference is the whole
/// design of the matching plane: a C program holds one matching listener and must be told about
/// the SESSION's verdict, not about each face's. A per-face pass-through would report the
/// opposite of the truth whenever one face matches and another does not.
pub type MatchingSink = Arc<dyn Fn(bool) + Send + Sync>;

/// Which declarations a write filter counts: pico's `_Z_WRITE_FILTER_SUBSCRIBER` for a
/// publisher, `_Z_WRITE_FILTER_QUERYABLE` for a querier (`vendor/zenoh-pico/src/net/filtering.c`
/// @ `ctx->target_type = expects_queryable ? _Z_WRITE_FILTER_QUERYABLE : _Z_WRITE_FILTER_SUBSCRIBER;`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterPlane {
    /// A publisher: does any peer subscribe to the key.
    Subscribers,
    /// A querier: does any peer answer on the key. `complete_required` is a target of
    /// `ALL_COMPLETE`, which counts only queryables declared complete.
    Queryables {
        /// See the variant.
        complete_required: bool,
    },
}

/// Why a fan-out publish could not be delivered to ANY face.
///
/// Named `FanoutError`, not `PublishError`: `wz_session_core::publish_options::PublishError` is
/// the per-session refusal, and two types with one name in one file is the shape a later reader
/// resolves wrongly.
///
/// R311y498 — a real type rather than `Result<_, ()>`, and not merely to satisfy
/// `clippy::result_unit_err`: a public function whose error carries no information leaves every
/// ABI mapping "something went wrong" onto its own generic code with no way to do better. The
/// variant is face-INDEPENDENT by construction — a per-face failure is skipped rather than
/// surfaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanoutError {
    /// The payload or keyexpr exceeded the bounded codec's capacity, so no face could have
    /// carried it.
    ExceedsCapacity,
}

/// What a put through a write filter did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilteredPut {
    /// The write filter said nothing matches: nothing was sent, and the put is answered as a
    /// success, as pico's is.
    Suppressed,
    /// The put was sent, with the answer a plain declared put gives.
    Sent(Result<usize, FanoutError>),
    /// The put is not plain on this node (a local subscriber wants it, or a face stamps what it
    /// sends): nothing was sent, and the caller takes the general publish.
    NotPlain,
}

/// How a C declaration's key goes on the WIRE, as distinct from the literal it matches on
/// locally.
///
/// The two differ whenever a declaring ABI names a key through one of its own keyexpr
/// declarations: the entity still matches the resolved literal, but the peer is told
/// `(mapping_id, suffix)`. `mapping_id == 0` is the literal itself, which is what zenoh-c's
/// session sends and the default here; the pico ABI announces through the declarations
/// zenoh-pico makes for its entities (`_z_declared_keyexpr_declare` and its non-wild-prefix
/// twin, `vendor/zenoh-pico/src/session/keyexpr.c`).
///
/// An engine records it with each declaration, because a face that joins later replays the
/// declaration and must announce it the same way. The id stays valid there: keyexpr
/// declarations are session-global and an engine replays them onto a new face FIRST.
///
/// ## What keeps the id declared
///
/// An entry that names `mapping_id` on the wire needs that declaration to outlive it, and the ABI
/// that made the declaration is the one that knows what retracts it. So the key carries what it
/// [`keeps`](Self::keeping) alive, and the entry holding the key holds that. For an entity with a
/// handle the ABI usually holds its own reference too; for a BACKGROUND entity, which has no
/// handle and lives as long as the session, the entry is the only holder — which is exactly the
/// lifetime zenoh-pico gives the declaration, stored with the subscription in the session's
/// table.
///
/// Entries are always released OUTSIDE an engine's locks, so what they keep may re-enter the
/// session as it drops (a keyexpr retraction does).
#[derive(Clone, Default)]
pub struct WireKey {
    /// The keyexpr declaration the wire names, `0` for none.
    pub mapping_id: u64,
    /// What follows the declared prefix, `None` when it covers the whole key.
    pub suffix: Option<String>,
    keeps: Option<Arc<dyn Send + Sync>>,
}

impl std::fmt::Debug for WireKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireKey")
            .field("mapping_id", &self.mapping_id)
            .field("suffix", &self.suffix)
            .field("keeps", &self.keeps.is_some())
            .finish()
    }
}

impl WireKey {
    /// The literal itself — no declaration.
    pub fn literal() -> Self {
        Self::default()
    }

    /// Declaration `mapping_id` followed by `suffix`.
    pub fn aliased(mapping_id: u64, suffix: Option<String>) -> Self {
        Self {
            mapping_id,
            suffix,
            keeps: None,
        }
    }

    /// This key, holding `anchor` alive for as long as a declaration made on it stays recorded.
    pub fn keeping(mut self, anchor: Arc<dyn Send + Sync>) -> Self {
        self.keeps = Some(anchor);
        self
    }

    /// Whether the key goes on the wire as its literal, naming no declaration.
    pub fn is_literal(&self) -> bool {
        self.mapping_id == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_literal_key_names_no_declaration() {
        assert!(WireKey::literal().is_literal());
        assert!(!WireKey::aliased(3, None).is_literal());
    }

    #[test]
    fn a_kept_anchor_lives_as_long_as_the_key() {
        let anchor: Arc<dyn Send + Sync> = Arc::new(());
        let key = WireKey::aliased(7, Some(String::from("rest"))).keeping(anchor.clone());
        assert_eq!(Arc::strong_count(&anchor), 2);
        let copy = key.clone();
        assert_eq!(Arc::strong_count(&anchor), 3);
        drop(key);
        drop(copy);
        assert_eq!(Arc::strong_count(&anchor), 1);
    }
}
