// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y69 — `ext-pubsub-advanced-cache` (§5.25): the publisher-side
//! sample ring + the queryable that answers `_sn` / `_max` recovery and
//! history selectors from it.
//!
//! The ring, its samples and the answer it gives (the `_sn` / `_max` / `_time` filters and
//! the reply arms) are `wz-ext-pubsub`'s, which no runtime owns, and are re-exported here at the
//! paths they have always had. What this module keeps is the one part that is a runtime's: the
//! cache bound to a [`Session`], which declares the answering queryable and reads the wall clock
//! the `_time` filter resolves against ([`crate::timestamp_source::wall_clock_ntp64`]).

use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;

pub use wz_ext_pubsub::advanced_cache::{
    CacheConfig, CacheStore, CachedSample, RepliesConfig, Retained,
};

use crate::session::{Queryable, QueryableError, QueryableOptions, Session, Unicast};
use crate::session_glue::SessionLinkActions;

/// A live advanced cache bound to a [`Session`]: owns the sample ring +
/// the answering [`Queryable`]. Dropping it undeclares the queryable
/// (RAII).
pub struct AdvancedCache<R: SessionRuntime, T: TimeSource> {
    store: CacheStore,
    _queryable: Queryable<R, T>,
}

impl<R, T> AdvancedCache<R, T>
where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    /// Declare the cache queryable on `queryable_keyexpr` (the publisher's
    /// `<key_expr>/@adv/pub/...` suffix), answering out of a fresh
    /// [`CacheStore`].
    pub fn declare(
        session: &Session<R, T, Unicast>,
        queryable_keyexpr: impl Into<String>,
        config: CacheConfig,
    ) -> Result<Self, QueryableError> {
        let store = CacheStore::new(config);
        // R2556 — INCOMPLETE, which is upstream's default and, more to the
        // point, the only honest answer this queryable can give.
        //
        // wz used to declare `with_complete(true)` on the rationale that "the
        // cache is the authoritative answerer for its `@adv` suffix". That
        // rationale was wrong twice over. Upstream makes no `.complete()` call
        // at all: it declares an ordinary queryable and so takes the builder
        // default, `zenoh/src/api/session.rs` @ `complete: false,`
        // — and the old comment's own parenthetical said as much while setting
        // the flag anyway.
        //
        // AND THE FLAG IS A PROMISE THIS CACHE CANNOT KEEP. zenoh's own doc
        // for it, `zenoh/src/api/builders/queryable.rs` @ `/// When queryable is declared as "complete", it promises to have all the data`,
        // is the contract: a querier may ask for complete queryables ONLY
        // (`QueryTarget::AllComplete`) and expect a whole answer. This
        // queryable answers out of a ring bounded by `max_samples`, so it
        // structurally does not have all the data — declaring otherwise is a
        // false promise on the wire, not a local optimisation.
        let queryable = session.declare_queryable(
            queryable_keyexpr,
            QueryableOptions::default(),
            store.query_handler(crate::timestamp_source::wall_clock_ntp64),
        )?;
        Ok(Self {
            store,
            _queryable: queryable,
        })
    }

    /// The ring this cache answers from and is fed into.
    pub fn store(&self) -> &CacheStore {
        &self.store
    }

    /// Push a freshly published sample into the ring — [`CacheStore::cache_sample`].
    pub fn cache_sample(&self, sample: CachedSample) {
        self.store.cache_sample(sample);
    }

    /// Number of samples currently retained (test / introspection seam).
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// True when the ring holds no samples.
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// R2556 — the cache queryable is INCOMPLETE, witnessed through the
    /// contract the flag actually governs rather than by reading the flag.
    ///
    /// A `QueryTarget::AllComplete` querier is answered ONLY by queryables
    /// that promise to hold all the data
    /// (`zenoh/src/api/builders/queryable.rs` @ `/// When queryable is declared as "complete", it promises to have all the data`),
    /// so `get_matching_status()` against a live cache is a direct read of the
    /// promise this declaration makes to the network. A ring bounded by
    /// `max_samples` cannot keep that promise, and upstream accordingly
    /// declares an ordinary queryable — `zenoh/src/api/session.rs` @ `complete: false,`
    /// is the default it thereby takes.
    ///
    /// ⚠ WHY THIS TEST HAD TO BE WRITTEN AT ALL, which is the finding rather
    /// than the fix: flipping the flag changed NOTHING in this module's other
    /// eleven cases. The completeness of the cache's own queryable was
    /// unwitnessed, so a false promise could sit on the wire indefinitely
    /// without a single test noticing — the flag was graded by nobody.
    #[cfg(all(feature = "query-target", feature = "query-get"))]
    #[test]
    fn the_cache_queryable_does_not_promise_completeness() {
        use crate::observer::ApplicationLayerObserver;
        use crate::runtime_impl::TokioTime;
        use crate::session::TokioSession;
        use wz_session_core::query_mode::QueryTarget;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let querier = session.declare_querier(
            "demo/data/@adv/pub/ff/7/_",
            crate::session::QueryOptions::get().with_target(QueryTarget::AllComplete),
        );
        assert!(
            !querier.get_matching_status().matching,
            "no queryable yet, so the AllComplete querier matches nothing"
        );

        let _cache = AdvancedCache::declare(
            &session,
            "demo/data/@adv/pub/ff/7/_".to_string(),
            CacheConfig {
                max_samples: 8,
                ..CacheConfig::default()
            },
        )
        .expect("advanced cache declares");

        assert!(
            !querier.get_matching_status().matching,
            "a live cache still does not answer an AllComplete querier: a \
             bounded ring makes no completeness promise"
        );
    }
}
