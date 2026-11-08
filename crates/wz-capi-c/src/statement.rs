// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a call states beyond the zenoh-c option structs, as the values the session model reads.
//!
//! The option structs of the `z_*` functions are upstream's layout and carry no field of wz's
//! own. The wz-only statements (the links an entity may use, a retry when no link had room, an
//! all-or-none publish, a node a query is addressed to) reach the model through these carriers.
//! The `z_*` functions pass the carrier that states nothing, and applying it changes no option,
//! so a call that states nothing is the call upstream's function makes. The doors that take a
//! statement from a C program are `crate::switch_doors`, behind the `switch-doors` feature: they
//! build a carrier, refuse it by the build's policy, and hand it to the same body.
//!
//! The carrier is kept apart from the doors so that the bodies shared with the `z_*` functions
//! compile in every build.

use wz_runtime_tokio::session::PublishOptions;
use wz_session_core::admission_retry::AdmissionRetry;
use wz_session_core::link_restriction::LinkRestriction;

/// What a publish states: the links it may be sent on, a retry for the case where no link had
/// room, and whether it reaches every link it may use or none. The default states nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct PublishStatement {
    pub(crate) links: LinkRestriction,
    pub(crate) retry: Option<AdmissionRetry>,
    pub(crate) atomic: bool,
}

impl PublishStatement {
    /// `options` with what this statement states put on them; the options of a statement that
    /// states nothing come back as they were.
    pub(crate) fn apply(self, options: PublishOptions) -> PublishOptions {
        let options = options.with_links(self.links);
        let options = match self.retry {
            Some(retry) => options.with_admission_retry(retry),
            None => options,
        };
        if self.atomic {
            options.with_atomic_tx()
        } else {
            options
        }
    }
}

/// What a query states: the links it may be asked on and the one node it is addressed to, by the
/// identity bytes the engine names the node by. The default states nothing.
#[cfg(feature = "query")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct QueryStatement {
    pub(crate) links: LinkRestriction,
    pub(crate) target_peer: Option<Vec<u8>>,
}

#[cfg(feature = "query")]
impl QueryStatement {
    /// `options` with what this statement states put on them; the options of a statement that
    /// states nothing come back as they were.
    pub(crate) fn apply(
        self,
        options: wz_runtime_tokio::session::QueryOptions,
    ) -> wz_runtime_tokio::session::QueryOptions {
        let options = options.with_links(self.links);
        match self.target_peer {
            Some(zid) => options.with_target_peer(zid),
            None => options,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn some_retry() -> AdmissionRetry {
        AdmissionRetry::new(3, 20).expect("a retry with both numbers set")
    }

    #[test]
    fn a_statement_that_states_nothing_leaves_the_publish_options_as_they_were() {
        let base = PublishOptions::put();
        let applied = PublishStatement::default().apply(base.clone());
        assert_eq!(applied.links, base.links);
        assert_eq!(applied.admission_retry, None);
        assert!(!applied.atomic_tx);
        assert_eq!(applied.allowed_destination, base.allowed_destination);
    }

    #[test]
    fn each_part_of_a_publish_statement_reaches_the_options_on_its_own() {
        let only_second = LinkRestriction::only([1]).expect("one slot");
        let links = PublishStatement {
            links: only_second,
            ..PublishStatement::default()
        }
        .apply(PublishOptions::put());
        assert_eq!(links.links, only_second);
        assert_eq!(links.admission_retry, None);
        assert!(!links.atomic_tx);

        let retry = PublishStatement {
            retry: Some(some_retry()),
            ..PublishStatement::default()
        }
        .apply(PublishOptions::put());
        assert_eq!(retry.admission_retry, Some(some_retry()));
        assert_eq!(retry.links, LinkRestriction::Any);
        assert!(!retry.atomic_tx);

        let atomic = PublishStatement {
            atomic: true,
            ..PublishStatement::default()
        }
        .apply(PublishOptions::put());
        assert!(atomic.atomic_tx);
        assert_eq!(atomic.admission_retry, None);
        assert_eq!(atomic.links, LinkRestriction::Any);
    }

    #[test]
    fn a_publish_statement_that_states_all_three_reaches_the_options_together() {
        let only_second = LinkRestriction::only([1]).expect("one slot");
        let applied = PublishStatement {
            links: only_second,
            retry: Some(some_retry()),
            atomic: true,
        }
        .apply(PublishOptions::put());
        assert_eq!(applied.links, only_second);
        assert_eq!(applied.admission_retry, Some(some_retry()));
        assert!(applied.atomic_tx);
    }

    #[cfg(feature = "query")]
    #[test]
    fn a_query_statement_that_states_nothing_leaves_the_query_options_as_they_were() {
        use wz_runtime_tokio::session::QueryOptions;
        let applied = QueryStatement::default().apply(QueryOptions::default());
        assert_eq!(applied.links, LinkRestriction::Any);
        assert_eq!(applied.target_peer, None);
    }

    #[cfg(feature = "query")]
    #[test]
    fn each_part_of_a_query_statement_reaches_the_options() {
        use wz_runtime_tokio::session::QueryOptions;
        let only_second = LinkRestriction::only([1]).expect("one slot");
        let applied = QueryStatement {
            links: only_second,
            target_peer: Some(vec![0xc7, 0xd1]),
        }
        .apply(QueryOptions::default());
        assert_eq!(applied.links, only_second);
        assert_eq!(applied.target_peer, Some(vec![0xc7, 0xd1]));

        let target_only = QueryStatement {
            target_peer: Some(vec![0x01]),
            ..QueryStatement::default()
        }
        .apply(QueryOptions::default());
        assert_eq!(target_only.links, LinkRestriction::Any);
        assert_eq!(target_only.target_peer, Some(vec![0x01]));
    }
}
