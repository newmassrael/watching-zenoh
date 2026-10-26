// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `advanced_publish`: declare an advanced publisher on `key` and put a stream
//! through it (`super::super::stream`: the same keys and the same schedule as
//! `publish`), keeping the last `cache` samples for a subscriber that joins late.
//!
//! The publisher is held after the last put, finite run or not: the cache is the
//! thing a late subscriber asks, so dropping it when the puts end would retract
//! exactly what the role exists to offer.
//!
//! Behind the demo feature `advanced`, as `--advanced-publish` is.

#[cfg(feature = "advanced")]
use std::time::Duration;

#[cfg(feature = "advanced")]
use wz::runtime_tokio::advanced_cache::CacheConfig;
#[cfg(feature = "advanced")]
use wz::runtime_tokio::advanced_publisher::{
    AdvancedPublisher, AdvancedPublisherOptions, MissDetectionConfig,
};

use crate::sessions_driver::stream::{self, stream_keys};
use crate::sessions_driver::{Ctx, KeyDef, KeyKind, Play, RoleDef};

/// How many samples the publisher keeps when the document names none: the
/// runtime's own default depth, which is also upstream's.
pub(crate) const DEFAULT_CACHE: u64 = 1;

pub(crate) static ROLE: RoleDef = RoleDef::gated(
    "advanced_publish",
    stream_keys!(
        KeyDef::defaulted("cache", KeyKind::Count, DEFAULT_CACHE),
        KeyDef::optional("heartbeat_ms", KeyKind::Millis),
    ),
    "advanced",
    cfg!(feature = "advanced"),
    play,
)
.checked(stream::check);

#[cfg(feature = "advanced")]
fn play(ctx: Ctx) -> Play {
    Box::pin(run(ctx))
}

#[cfg(not(feature = "advanced"))]
fn play(_ctx: Ctx) -> Play {
    Box::pin(async {})
}

/// The publisher's options: a cache `cache` samples deep, and the last-sequence
/// beacon every `heartbeat_ms` when one is asked for. The beacon needs the
/// default sequence-number tagging, which this leaves alone.
#[cfg(feature = "advanced")]
fn options_of(cache: u64, heartbeat_ms: Option<u64>) -> AdvancedPublisherOptions {
    let mut options = AdvancedPublisherOptions::default();
    if let Some(ms) = heartbeat_ms {
        options.sample_miss_detection =
            MissDetectionConfig::default().heartbeat(Duration::from_millis(ms));
    }
    options.cache = Some(CacheConfig {
        max_samples: usize::try_from(cache).unwrap_or(usize::MAX),
        ..CacheConfig::default()
    });
    options
}

#[cfg(feature = "advanced")]
async fn run(ctx: Ctx) {
    let key = ctx.text("key");
    let cache = ctx.int("cache").unwrap_or(DEFAULT_CACHE);
    let heartbeat_ms = ctx.int("heartbeat_ms");
    let publisher = match AdvancedPublisher::declare(
        &ctx.session,
        key.clone(),
        options_of(cache, heartbeat_ms),
        ctx.session.zid().to_vec(),
    ) {
        Ok(publisher) => publisher,
        Err(e) => {
            ctx.say.line(&format!("refused key={key}: {e:?}"));
            return;
        }
    };
    ctx.say.line(&format!(
        "declared key={key} cache={cache} heartbeat_ms={}",
        heartbeat_ms.map_or_else(|| "none".to_string(), |ms| ms.to_string())
    ));
    stream::run(&ctx, &key, |bytes| match publisher.put(bytes) {
        Ok(_) => ctx
            .say
            .line(&format!("sent key={key} bytes={}", bytes.len())),
        Err(e) => ctx.say.line(&format!("refused key={key}: {e}")),
    })
    .await;
    ctx.hold().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::{read_sessions_document, BuildCapabilities, SessionsPlan};
    use crate::sessions_driver::{all_words, Args, DriverEntry, Value};

    const HEAD: &str = r#"{ sessions: [ { name: "a", mode: "client", transport: "unicast",
        connect: { endpoints: ["tcp/127.0.0.1:7447"] }, driver: [ ROLE ] } ] }"#;

    fn read(role: &str) -> Result<SessionsPlan, Vec<String>> {
        read_sessions_document(&HEAD.replace("ROLE", role))
            .map_err(|refusals| refusals.into_iter().map(|r| r.to_string()).collect())
    }

    fn entry(role: &str) -> DriverEntry {
        read(role)
            .expect("the document is accepted")
            .sessions
            .remove(0)
            .driver
            .remove(0)
    }

    #[test]
    fn the_role_is_available_exactly_when_the_feature_is_built() {
        assert_eq!(ROLE.word, "advanced_publish");
        assert_eq!(ROLE.feature, Some("advanced"));
        assert_eq!(ROLE.available, cfg!(feature = "advanced"));
    }

    /// The keys are read as written, the cache depth defaults to one and the
    /// optional ones are absent when the document leaves them out.
    #[test]
    fn the_keys_are_read_and_the_cache_defaults_to_one() {
        assert_eq!(
            entry(r#"{ role: "advanced_publish", key: "d/a", payload: "x", period_ms: 20 }"#),
            DriverEntry {
                word: "advanced_publish",
                after_ms: 0,
                args: Args::of(&[
                    ("key", Value::Text("d/a".into())),
                    ("payload", Value::Text("x".into())),
                    ("period_ms", Value::Int(20)),
                    ("cache", Value::Int(DEFAULT_CACHE)),
                ]),
            }
        );
        assert_eq!(
            entry(
                r#"{ role: "advanced_publish", key: "d/a", payload: "x", period_ms: 20,
                    count: 4, cache: 3, heartbeat_ms: 250, after_ms: 9 }"#
            ),
            DriverEntry {
                word: "advanced_publish",
                after_ms: 9,
                args: Args::of(&[
                    ("key", Value::Text("d/a".into())),
                    ("payload", Value::Text("x".into())),
                    ("period_ms", Value::Int(20)),
                    ("count", Value::Int(4)),
                    ("cache", Value::Int(3)),
                    ("heartbeat_ms", Value::Int(250)),
                ]),
            }
        );
    }

    /// A missing key, a key of another role and a wrong kind are each refused at
    /// their own key path.
    #[test]
    fn a_missing_foreign_or_ill_typed_key_is_refused_by_path() {
        let at = "sessions[0].driver[0]";
        assert_eq!(
            read(r#"{ role: "advanced_publish", key: "d/a", period_ms: 20 }"#).map(|_| ()),
            Err(vec![format!(
                "{at}.payload: give exactly one of payload, payload_hex and payload_bytes"
            )])
        );
        assert_eq!(
            read(r#"{ role: "advanced_publish", payload: "x", period_ms: 20 }"#).map(|_| ()),
            Err(vec![format!(
                "{at}.key: required, a keyexpr with no whitespace"
            )])
        );
        assert_eq!(
            read(r#"{ role: "advanced_publish", key: "d/a", payload: "x" }"#).map(|_| ()),
            Err(vec![format!(
                "{at}.period_ms: give exactly one of period_ms and rate_per_s"
            )])
        );
        assert_eq!(
            read(
                r#"{ role: "advanced_publish", key: "d/a", payload: "x", period_ms: 20,
                    history: 3 }"#
            )
            .map(|_| ()),
            Err(vec![format!(
                "{at}.history: not a key of the `advanced_publish` role"
            )])
        );
        assert_eq!(
            read(
                r#"{ role: "advanced_publish", key: "d/a", payload: "x", period_ms: 20,
                    cache: 0, heartbeat_ms: "soon" }"#
            )
            .map(|_| ()),
            Err(vec![
                format!("{at}.cache: must be a positive integer"),
                format!("{at}.heartbeat_ms: must be a positive integer"),
            ])
        );
    }

    /// A build without the feature refuses the role by key path, naming the
    /// feature, rather than skipping it.
    #[test]
    fn a_build_without_the_feature_refuses_the_role_by_path() {
        let plan = read(r#"{ role: "advanced_publish", key: "d/a", payload: "x", period_ms: 20 }"#)
            .expect("the rules accept it");
        let caps = BuildCapabilities {
            multicast: true,
            iface: true,
            scouting_responder: true,
            access_multicast: true,
            driver_roles: all_words()
                .into_iter()
                .filter(|w| *w != "advanced_publish")
                .collect(),
            schemes: vec!["tcp"],
        };
        let refused: Vec<String> = plan
            .build_refusals(&caps)
            .into_iter()
            .map(|r| r.to_string())
            .collect();
        assert_eq!(
            refused,
            vec![
                "sessions[0].driver[0].role: the `advanced_publish` role needs the `advanced` \
                 build feature (build: cargo build -p wz-ap-demo --features advanced)"
            ]
        );
    }

    #[cfg(feature = "advanced")]
    #[test]
    fn the_options_carry_the_cache_depth_and_the_beacon() {
        let plain = options_of(3, None);
        assert_eq!(plain.cache.map(|c| c.max_samples), Some(3));
        assert!(
            format!("{:?}", plain.sample_miss_detection).contains("None"),
            "no beacon unless asked: {:?}",
            plain.sample_miss_detection
        );
        let beaconed = options_of(1, Some(250));
        assert_eq!(beaconed.cache.map(|c| c.max_samples), Some(1));
        assert!(
            format!("{:?}", beaconed.sample_miss_detection).contains("250ms"),
            "the beacon period: {:?}",
            beaconed.sample_miss_detection
        );
    }
}
