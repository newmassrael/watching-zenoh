// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `advanced_subscribe`: hold an advanced subscriber on `key`, printing each
//! sample and each miss it reports.
//!
//! `history` and `history_age_ms` make the join ask the publishers' caches for
//! what they kept (the newest `history` samples, none older than the age);
//! `recovery` arms retransmission, and `periodic_ms` is the period of the
//! `periodic` kind. A subscriber that names no history asks for none: the
//! one-shot `--advanced-subscribe` asks for the whole cache even then, which a
//! document that wants no history must be able to decline.
//!
//! Behind the demo feature `advanced`, as `--advanced-subscribe` is.

#[cfg(feature = "advanced")]
use std::time::Duration;

#[cfg(feature = "advanced")]
use wz::runtime_tokio::advanced_subscriber::{
    AdvancedSubscriber, AdvancedSubscriberOptions, HistoryConfig, RecoveryConfig,
};

use crate::sessions_driver::{Args, Ctx, KeyDef, KeyKind, Play, RoleDef};

/// The ceiling on `periodic_ms`, one hour, as on the one-shot
/// `--advanced-recovery-periodic`: a period no run will reach reports the
/// trigger as armed while it never fires.
pub(crate) const PERIODIC_MAX_MS: u64 = 3_600_000;

pub(crate) static ROLE: RoleDef = RoleDef::gated(
    "advanced_subscribe",
    &[
        KeyDef::required("key", KeyKind::Keyexpr),
        KeyDef::optional("history", KeyKind::Count),
        KeyDef::optional("history_age_ms", KeyKind::Millis),
        KeyDef::optional(
            "recovery",
            KeyKind::Word(&["samples", "periodic", "heartbeat"]),
        ),
        KeyDef::optional("periodic_ms", KeyKind::Millis),
    ],
    "advanced",
    cfg!(feature = "advanced"),
    play,
)
.checked(check);

/// `periodic_ms` is the period of the periodic re-ask and means nothing for any
/// other recovery, so it is required with `recovery: "periodic"` and refused
/// without it, rather than ignored.
fn check(args: &Args) -> Vec<(&'static str, String)> {
    let mut refused = Vec::new();
    match (args.text("recovery"), args.int("periodic_ms")) {
        (Some("periodic"), None) => refused.push((
            "periodic_ms",
            "required when recovery is periodic: the period of the re-ask, in milliseconds"
                .to_string(),
        )),
        (Some("periodic"), Some(ms)) if ms > PERIODIC_MAX_MS => refused.push((
            "periodic_ms",
            format!(
                "{ms} ms exceeds the {PERIODIC_MAX_MS} ms ceiling; a period no run will reach \
                 reports the trigger as armed while it never fires"
            ),
        )),
        (Some("periodic"), Some(_)) | (_, None) => {}
        (_, Some(_)) => refused.push((
            "periodic_ms",
            "only meaningful when recovery is periodic".to_string(),
        )),
    }
    refused
}

#[cfg(feature = "advanced")]
fn play(ctx: Ctx) -> Play {
    Box::pin(run(ctx))
}

#[cfg(not(feature = "advanced"))]
fn play(_ctx: Ctx) -> Play {
    Box::pin(async {})
}

/// The subscriber's options. History is asked only when the document names a
/// bound; the trigger of the recovery is the one `recovery` words, and `check`
/// has already seen to it that `periodic` comes with its period.
#[cfg(feature = "advanced")]
fn options_of(
    history: Option<u64>,
    history_age_ms: Option<u64>,
    recovery: Option<&str>,
    periodic_ms: Option<u64>,
) -> AdvancedSubscriberOptions {
    let mut options = AdvancedSubscriberOptions::new();
    if history.is_some() || history_age_ms.is_some() {
        let mut config = HistoryConfig::new();
        if let Some(n) = history {
            config = config.max_samples(usize::try_from(n).unwrap_or(usize::MAX));
        }
        if let Some(ms) = history_age_ms {
            config = config.max_age(Duration::from_millis(ms).as_secs_f64());
        }
        options = options.with_history(config);
    }
    if let Some(word) = recovery {
        let config = match (word, periodic_ms) {
            ("periodic", Some(ms)) => {
                RecoveryConfig::new().with_periodic_queries(Duration::from_millis(ms))
            }
            ("heartbeat", _) => RecoveryConfig::new().with_heartbeat(),
            _ => RecoveryConfig::new(),
        };
        options = options.with_recovery(config);
    }
    options
}

/// A number, or `none` for a key the document left out.
#[cfg(feature = "advanced")]
fn shown<T: ToString>(value: Option<T>) -> String {
    value.map_or_else(|| "none".to_string(), |v| v.to_string())
}

/// The line that says what was declared. `heartbeat_channel_live` is what the
/// subscriber built, not what was asked: it drops the heartbeat channel without
/// a word when it cannot derive the key, and the request alone reads as armed.
#[cfg(feature = "advanced")]
fn declared_line(
    key: &str,
    history: Option<u64>,
    history_age_ms: Option<u64>,
    recovery: Option<&str>,
    periodic_ms: Option<u64>,
    heartbeat_channel_live: bool,
) -> String {
    format!(
        "declared key={key} history={} recovery={} history_age_ms={} periodic_ms={} \
         heartbeat_channel_live={heartbeat_channel_live}",
        shown(history),
        shown(recovery),
        shown(history_age_ms),
        shown(periodic_ms),
    )
}

#[cfg(feature = "advanced")]
async fn run(ctx: Ctx) {
    let key = ctx.text("key");
    let history = ctx.int("history");
    let history_age_ms = ctx.int("history_age_ms");
    let recovery = ctx.args().text("recovery");
    let periodic_ms = ctx.int("periodic_ms");
    let on_sample = ctx.say.clone();
    let on_miss = ctx.say.clone();
    let miss_key = key.clone();
    let declared = AdvancedSubscriber::declare_with_options_and_miss_listener(
        &ctx.session,
        key.clone(),
        options_of(history, history_age_ms, recovery, periodic_ms),
        move |sample| {
            on_sample.line(&format!(
                "sample key={} kind={:?} bytes={}",
                sample.keyexpr,
                sample.kind,
                sample.payload.len()
            ));
        },
        move |miss| {
            on_miss.line(&format!("miss key={miss_key} missed={}", miss.nb()));
        },
    );
    match declared {
        Ok(subscriber) => {
            ctx.say.line(&declared_line(
                &key,
                history,
                history_age_ms,
                recovery,
                periodic_ms,
                subscriber.heartbeat_channel_is_live(),
            ));
            ctx.hold().await;
        }
        Err(e) => ctx.say.line(&format!("refused key={key}: {e:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::{read_sessions_document, BuildCapabilities, SessionsPlan};
    use crate::sessions_driver::{all_words, DriverEntry, Value};

    const HEAD: &str = r#"{ sessions: [ { name: "a", mode: "client", transport: "unicast",
        connect: { endpoints: ["tcp/127.0.0.1:7447"] }, driver: [ ROLE ] } ] }"#;

    fn read(role: &str) -> Result<SessionsPlan, Vec<String>> {
        read_sessions_document(&HEAD.replace("ROLE", role))
            .map_err(|refusals| refusals.into_iter().map(|r| r.to_string()).collect())
    }

    fn refused(role: &str) -> Vec<String> {
        read(role).expect_err("the document is refused")
    }

    fn entry(role: &str) -> DriverEntry {
        read(role)
            .expect("the document is accepted")
            .sessions
            .remove(0)
            .driver
            .remove(0)
    }

    const AT: &str = "sessions[0].driver[0]";

    #[test]
    fn the_role_is_available_exactly_when_the_feature_is_built() {
        assert_eq!(ROLE.word, "advanced_subscribe");
        assert_eq!(ROLE.feature, Some("advanced"));
        assert_eq!(ROLE.available, cfg!(feature = "advanced"));
    }

    /// Only the key is required; the rest is read as written and absent when the
    /// document leaves it out.
    #[test]
    fn the_keys_are_read_as_written() {
        assert_eq!(
            entry(r#"{ role: "advanced_subscribe", key: "d/**" }"#),
            DriverEntry {
                word: "advanced_subscribe",
                after_ms: 0,
                args: Args::of(&[("key", Value::Text("d/**".into()))]),
            }
        );
        assert_eq!(
            entry(
                r#"{ role: "advanced_subscribe", key: "d/a", history: 3, history_age_ms: 1500,
                    recovery: "periodic", periodic_ms: 200, after_ms: 40 }"#
            ),
            DriverEntry {
                word: "advanced_subscribe",
                after_ms: 40,
                args: Args::of(&[
                    ("key", Value::Text("d/a".into())),
                    ("history", Value::Int(3)),
                    ("history_age_ms", Value::Int(1500)),
                    ("recovery", Value::Text("periodic".into())),
                    ("periodic_ms", Value::Int(200)),
                ]),
            }
        );
        for word in ["samples", "heartbeat"] {
            let doc =
                format!(r#"{{ role: "advanced_subscribe", key: "d/a", recovery: "{word}" }}"#);
            assert_eq!(entry(&doc).args.text("recovery"), Some(word));
        }
    }

    /// A missing key, a key of another role and a wrong kind are each refused at
    /// their own key path.
    #[test]
    fn a_missing_foreign_or_ill_typed_key_is_refused_by_path() {
        assert_eq!(
            refused(r#"{ role: "advanced_subscribe", history: 3 }"#),
            vec![format!("{AT}.key: required, a keyexpr with no whitespace")]
        );
        assert_eq!(
            refused(r#"{ role: "advanced_subscribe", key: "d/a", cache: 3 }"#),
            vec![format!(
                "{AT}.cache: not a key of the `advanced_subscribe` role"
            )]
        );
        assert_eq!(
            refused(
                r#"{ role: "advanced_subscribe", key: "d/a", history: 0, history_age_ms: "old",
                    recovery: "always", periodic_ms: -5 }"#
            ),
            vec![
                format!("{AT}.history: must be a positive integer"),
                format!("{AT}.history_age_ms: must be a positive integer"),
                format!("{AT}.recovery: must be one of: samples, periodic, heartbeat"),
                format!("{AT}.periodic_ms: must be a positive integer"),
            ]
        );
    }

    /// `periodic_ms` is required with a periodic recovery and refused with any
    /// other, each at the key, and the one-shot ceiling holds.
    #[test]
    fn the_period_belongs_to_the_periodic_recovery_alone() {
        assert_eq!(
            refused(r#"{ role: "advanced_subscribe", key: "d/a", recovery: "periodic" }"#),
            vec![format!(
                "{AT}.periodic_ms: required when recovery is periodic: the period of the \
                 re-ask, in milliseconds"
            )]
        );
        let only_when_periodic =
            format!("{AT}.periodic_ms: only meaningful when recovery is periodic");
        for recovery in [r#"recovery: "samples","#, r#"recovery: "heartbeat","#, ""] {
            let doc = format!(
                r#"{{ role: "advanced_subscribe", key: "d/a", {recovery} periodic_ms: 100 }}"#
            );
            assert_eq!(refused(&doc), vec![only_when_periodic.clone()], "{doc}");
        }
        assert_eq!(
            refused(
                r#"{ role: "advanced_subscribe", key: "d/a", recovery: "periodic",
                    periodic_ms: 3600001 }"#
            ),
            vec![format!(
                "{AT}.periodic_ms: 3600001 ms exceeds the 3600000 ms ceiling; a period no run \
                 will reach reports the trigger as armed while it never fires"
            )]
        );
        let at_the_ceiling = entry(
            r#"{ role: "advanced_subscribe", key: "d/a", recovery: "periodic",
                periodic_ms: 3600000 }"#,
        );
        assert_eq!(
            at_the_ceiling.args.int("periodic_ms"),
            Some(PERIODIC_MAX_MS)
        );
    }

    /// The rule is a function of the keys alone, so it is held without a document.
    #[test]
    fn the_cross_key_rule_reads_the_recovery_and_the_period() {
        let args = |pairs: &[(&'static str, Value)]| Args::of(pairs);
        let word = |w: &str| Value::Text(w.to_string());
        assert!(check(&args(&[])).is_empty());
        assert!(check(&args(&[("recovery", word("samples"))])).is_empty());
        assert!(check(&args(&[
            ("recovery", word("periodic")),
            ("periodic_ms", Value::Int(1)),
        ]))
        .is_empty());
        let refusals = check(&args(&[("recovery", word("periodic"))]));
        assert_eq!(refusals.len(), 1);
        assert_eq!(refusals[0].0, "periodic_ms");
        let refusals = check(&args(&[("periodic_ms", Value::Int(1))]));
        assert_eq!(refusals.len(), 1);
        assert_eq!(refusals[0].0, "periodic_ms");
    }

    /// A build without the feature refuses the role by key path, naming the
    /// feature, rather than skipping it.
    #[test]
    fn a_build_without_the_feature_refuses_the_role_by_path() {
        let plan =
            read(r#"{ role: "advanced_subscribe", key: "d/a" }"#).expect("the rules accept it");
        let caps = BuildCapabilities {
            multicast: true,
            iface: true,
            scouting_responder: true,
            driver_roles: all_words()
                .into_iter()
                .filter(|w| *w != "advanced_subscribe")
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
                "sessions[0].driver[0].role: the `advanced_subscribe` role needs the `advanced` \
                 build feature (build: cargo build -p wz-ap-demo --features advanced)"
            ]
        );
    }

    #[cfg(feature = "advanced")]
    #[test]
    fn history_is_asked_only_when_a_bound_is_named() {
        assert!(options_of(None, None, None, None).history.is_none());
        let counted = options_of(Some(3), None, None, None)
            .history
            .expect("a count asks for history");
        assert_eq!(counted.sample_depth, Some(3));
        assert_eq!(counted.max_age, None);
        let aged = options_of(None, Some(1500), None, None)
            .history
            .expect("an age asks for history");
        assert_eq!(aged.sample_depth, None);
        assert_eq!(aged.max_age, Some(1.5));
    }

    #[cfg(feature = "advanced")]
    #[test]
    fn the_recovery_word_picks_the_trigger() {
        assert!(options_of(None, None, None, None).recovery.is_none());
        let samples = options_of(None, None, Some("samples"), None)
            .recovery
            .expect("armed");
        assert!(!samples.heartbeat());
        assert_eq!(samples.periodic_queries(), None);
        let heartbeat = options_of(None, None, Some("heartbeat"), None)
            .recovery
            .expect("armed");
        assert!(heartbeat.heartbeat());
        assert_eq!(heartbeat.periodic_queries(), None);
        let periodic = options_of(None, None, Some("periodic"), Some(250))
            .recovery
            .expect("armed");
        assert!(!periodic.heartbeat());
        assert_eq!(
            periodic.periodic_queries(),
            Some(Duration::from_millis(250))
        );
    }

    #[cfg(feature = "advanced")]
    #[test]
    fn the_declared_line_names_what_was_asked_and_what_was_built() {
        assert_eq!(
            declared_line("d/a", None, None, None, None, false),
            "declared key=d/a history=none recovery=none history_age_ms=none periodic_ms=none \
             heartbeat_channel_live=false"
        );
        assert_eq!(
            declared_line("d/a", Some(3), Some(1500), Some("heartbeat"), None, true),
            "declared key=d/a history=3 recovery=heartbeat history_age_ms=1500 \
             periodic_ms=none heartbeat_channel_live=true"
        );
    }
}
