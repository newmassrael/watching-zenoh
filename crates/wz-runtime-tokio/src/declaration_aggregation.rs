// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `aggregation/subscribers` and `aggregation/publishers`: the key expressions a
//! session declares its subscribers and its publishers UNDER.
//!
//! Upstream's rule, read at the pin
//! (`zenoh/src/api/session.rs` @ `.aggregated_subscribers` for a subscriber,
//! `zenoh/src/api/session.rs` @ `.aggregated_publishers` for a publisher):
//!
//! * an entity whose key the FIRST listed aggregate includes is declared as that
//!   aggregate, not as its own key: a subscriber's `DeclareSubscriber` and a
//!   publisher's subscribers interest name the aggregate;
//! * the declaration is made once, by the first entity under the aggregate, and
//!   every later one under it shares it and sends nothing;
//! * it is retracted with the LAST entity that shares it
//!   (`zenoh/src/api/session.rs` @ `s.origin != Locality::SessionLocal && s.remote_id == sub_state.remote_id`);
//! * an entity local to the session (`Locality::SessionLocal`) declares nothing
//!   and is not aggregated.
//!
//! So a node with N subscribers on keys under one aggregate puts ONE declaration
//! on the wire where it would otherwise put N, and the remote routes everything
//! the aggregate matches to it.
//!
//! One departure. Upstream finds the entity to share with by asking whether the
//! aggregate includes that entity's KEY, so with aggregates `a/b/**` then `a/**`
//! a subscriber on `a/x` (under `a/**`) shares the declaration a subscriber on
//! `a/b/c` made for `a/b/**`, and nothing announces `a/**`: the remote never
//! routes `a/x` to the node. wz keys the shared declaration by the AGGREGATE it
//! stands for, so `a/x` declares `a/**`. Lists whose aggregates do not include
//! one another behave identically under both rules.

use wz_session_core::keyexpr_canon::validate_keyexpr;

/// The capability this crate compiles the inclusion test under; a build without it
/// holds no aggregate.
pub const AGGREGATION_CAPABILITY: &str = "keyexpr-includes";

/// Why a list of aggregates was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggregationError {
    /// A member is not a key expression, as upstream's `OwnedKeyExpr` refuses it.
    InvalidKeyexpr {
        /// The member as given.
        key: String,
    },
    /// The build was made without [`AGGREGATION_CAPABILITY`], so it cannot tell which key an
    /// aggregate includes, and a list it cannot apply is refused rather than ignored.
    NotInBuild,
}

impl core::fmt::Display for AggregationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AggregationError::InvalidKeyexpr { key } => {
                write!(f, "{key:?} is not a key expression")
            }
            AggregationError::NotInBuild => write!(
                f,
                "aggregating declarations needs the `{AGGREGATION_CAPABILITY}` capability, \
                 which this build was made without"
            ),
        }
    }
}

impl std::error::Error for AggregationError {}

/// The two aggregate lists of one session, each in the order its document gave.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeclarationAggregation {
    subscribers: Vec<String>,
    publishers: Vec<String>,
}

impl DeclarationAggregation {
    /// No aggregate: every entity is declared as its own key.
    pub fn none() -> Self {
        Self::default()
    }

    /// The aggregates `subscribers` and `publishers`, each member checked as a key
    /// expression. A non-empty list in a build without [`AGGREGATION_CAPABILITY`] is
    /// refused.
    pub fn new(
        subscribers: Vec<String>,
        publishers: Vec<String>,
    ) -> Result<Self, AggregationError> {
        for key in subscribers.iter().chain(&publishers) {
            if validate_keyexpr(key).is_err() {
                return Err(AggregationError::InvalidKeyexpr { key: key.clone() });
            }
        }
        if !cfg!(feature = "keyexpr-includes")
            && (!subscribers.is_empty() || !publishers.is_empty())
        {
            return Err(AggregationError::NotInBuild);
        }
        Ok(Self {
            subscribers,
            publishers,
        })
    }

    /// The subscriber aggregates, in order.
    pub fn subscribers(&self) -> &[String] {
        &self.subscribers
    }

    /// The publisher aggregates, in order.
    pub fn publishers(&self) -> &[String] {
        &self.publishers
    }

    /// Whether neither list holds an aggregate.
    pub fn is_empty(&self) -> bool {
        self.subscribers.is_empty() && self.publishers.is_empty()
    }

    /// The aggregate a subscriber on `key` is declared as: the first subscriber aggregate that
    /// includes `key`, or `None` when none does and it is declared as `key` itself.
    pub fn subscriber_aggregate(&self, key: &str) -> Option<&str> {
        first_including(&self.subscribers, key)
    }

    /// The aggregate a publisher on `key` asks for subscribers on, by the publisher list.
    pub fn publisher_aggregate(&self, key: &str) -> Option<&str> {
        first_including(&self.publishers, key)
    }
}

/// The first member of `aggregates` that includes every key `key` matches.
fn first_including<'a>(aggregates: &'a [String], key: &str) -> Option<&'a str> {
    #[cfg(feature = "keyexpr-includes")]
    {
        // Every declare asks, and most sessions hold no aggregate: they pay no split.
        if aggregates.is_empty() {
            return None;
        }
        let chunks: Vec<&str> = key.split('/').collect();
        aggregates
            .iter()
            .find(|aggregate| {
                wz_session_core::keyexpr_match::keyexpr_includes_target(aggregate, &chunks)
            })
            .map(String::as_str)
    }
    // `new` refuses every aggregate in this build, so there is none to find.
    #[cfg(not(feature = "keyexpr-includes"))]
    {
        let _ = (aggregates, key);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| String::from(*s)).collect()
    }

    #[test]
    fn a_member_that_is_not_a_key_expression_is_refused() {
        for bad in ["a//b", "", "a/**/*"] {
            assert_eq!(
                DeclarationAggregation::new(keys(&[bad]), Vec::new()),
                Err(AggregationError::InvalidKeyexpr {
                    key: String::from(bad)
                }),
                "{bad:?}"
            );
            assert_eq!(
                DeclarationAggregation::new(Vec::new(), keys(&[bad])),
                Err(AggregationError::InvalidKeyexpr {
                    key: String::from(bad)
                }),
                "{bad:?}"
            );
        }
        assert_eq!(
            DeclarationAggregation::new(Vec::new(), Vec::new()),
            Ok(DeclarationAggregation::none()),
            "two empty lists aggregate nothing, in every build"
        );
    }

    #[cfg(feature = "keyexpr-includes")]
    #[test]
    fn the_first_aggregate_that_includes_the_key_is_the_one_declared() {
        let aggregation =
            DeclarationAggregation::new(keys(&["demo/a/**", "demo/**"]), keys(&["sensor/*/temp"]))
                .unwrap();
        assert_eq!(
            aggregation.subscriber_aggregate("demo/a/x"),
            Some("demo/a/**")
        );
        assert_eq!(aggregation.subscriber_aggregate("demo/b"), Some("demo/**"));
        assert_eq!(
            aggregation.subscriber_aggregate("demo/a/**"),
            Some("demo/a/**"),
            "an aggregate includes itself"
        );
        assert_eq!(
            aggregation.subscriber_aggregate("other/x"),
            None,
            "a key no aggregate includes is declared as itself"
        );
        assert_eq!(
            aggregation.subscriber_aggregate("demo"),
            Some("demo/**"),
            "`**` includes the empty remainder"
        );
        assert_eq!(
            aggregation.publisher_aggregate("sensor/1/temp"),
            Some("sensor/*/temp")
        );
        assert_eq!(
            aggregation.publisher_aggregate("demo/a/x"),
            None,
            "the subscriber list does not aggregate a publisher"
        );
        assert_eq!(
            aggregation.publisher_aggregate("sensor/**"),
            None,
            "`sensor/*/temp` does not include every key `sensor/**` matches"
        );
    }

    #[cfg(not(feature = "keyexpr-includes"))]
    #[test]
    fn a_build_without_the_inclusion_test_refuses_an_aggregate() {
        assert_eq!(
            DeclarationAggregation::new(keys(&["demo/**"]), Vec::new()),
            Err(AggregationError::NotInBuild)
        );
        assert_eq!(
            DeclarationAggregation::new(Vec::new(), keys(&["demo/**"])),
            Err(AggregationError::NotInBuild)
        );
    }
}
