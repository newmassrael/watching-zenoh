// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `query`: declare a querier on `key` and ask through it, `count` times (until
//! the process stops when `count` is absent): every `period_ms` (open loop, the
//! next question whatever the last one's answer), or, with `think_ms`, the next
//! question `think_ms` after the last one's final (closed loop, the asker that
//! waits for its answer: what one client does, and what a fixed period cannot
//! model when the answers are slower than the period).
//!
//! `get` asks once through `Session::query`; this role is the declared handle,
//! which is what a long-lived asker holds: the options (the timeout here) are
//! fixed at the declaration and every question after it goes through them.
//!
//! A question the session refuses ends the role: the refusal is a property of the
//! key or of the build, so the next question would be refused the same way.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use wz::runtime_tokio::session::QueryOptions;

use super::get::DEFAULT_TIMEOUT_MS;
use crate::sessions_driver::{Args, Ctx, KeyDef, KeyKind, Play, RoleDef};

/// How much longer than its timeout a closed loop waits for a question's final
/// before it says the final was lost and asks again: the session ends a question
/// at its timeout with a final of its own, so reaching this is a defect to see.
const FINAL_MARGIN_MS: u64 = 1_000;

pub(crate) static ROLE: RoleDef = RoleDef::played(
    "query",
    &[
        KeyDef::required("key", KeyKind::Keyexpr),
        KeyDef::optional("period_ms", KeyKind::Millis),
        KeyDef::optional("think_ms", KeyKind::Integer),
        KeyDef::optional("count", KeyKind::Count),
        KeyDef::defaulted("timeout_ms", KeyKind::Millis, DEFAULT_TIMEOUT_MS),
    ],
    play,
)
.checked(check);

/// One loop: a period (open) or a think time after each final (closed).
fn check(args: &Args) -> Vec<(&'static str, String)> {
    if args.has("period_ms") == args.has("think_ms") {
        return vec![(
            "period_ms",
            "give exactly one of period_ms (open loop) and think_ms (closed loop)".to_string(),
        )];
    }
    Vec::new()
}

fn play(ctx: Ctx) -> Play {
    Box::pin(run(ctx))
}

async fn run(ctx: Ctx) {
    let key = ctx.text("key");
    let period = ctx.int("period_ms").map(Duration::from_millis);
    let think = Duration::from_millis(ctx.int("think_ms").unwrap_or(0));
    let count = ctx.int("count");
    let timeout_ms = ctx.int("timeout_ms").unwrap_or(DEFAULT_TIMEOUT_MS);
    let timeout = u32::try_from(timeout_ms).unwrap_or(u32::MAX);
    let querier = ctx.session.declare_querier(
        key.clone(),
        QueryOptions::default().with_timeout_ms(timeout),
    );
    ctx.say.line(&format!("declared key={key}"));
    let mut asked = 0u64;
    while count.map_or(true, |n| asked < n) {
        let n = asked + 1;
        let (replies, finals) = (ctx.say.clone(), ctx.say.clone());
        let answered = Arc::new(Notify::new());
        let notify = Arc::clone(&answered);
        let sent = querier.get(
            move |reply| {
                replies.line(&format!(
                    "reply key={} kind={:?} bytes={}",
                    reply.keyexpr(),
                    reply.kind(),
                    reply.payload().len()
                ));
            },
            move |_rid| {
                finals.line(&format!("final n={n}"));
                notify.notify_one();
            },
        );
        match sent {
            Ok(_) => ctx.say.line(&format!("asked key={key} n={n}")),
            Err(e) => {
                ctx.say.line(&format!("refused key={key}: {e}"));
                return;
            }
        }
        asked = n;
        match period {
            Some(period) => tokio::time::sleep(period).await,
            None => {
                let wait = Duration::from_millis(timeout_ms.saturating_add(FINAL_MARGIN_MS));
                if tokio::time::timeout(wait, answered.notified())
                    .await
                    .is_err()
                {
                    ctx.say.line(&format!("lost final n={n}"));
                }
                tokio::time::sleep(think).await;
            }
        }
    }
    ctx.say.line(&format!("done key={key} count={asked}"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::{read_sessions_document, Refusal, SessionsPlan};
    use crate::sessions_driver::{Args, DriverEntry, Value};

    fn plan(role: &str) -> Result<SessionsPlan, Vec<Refusal>> {
        read_sessions_document(&format!(
            r#"{{ sessions: [ {{ name: "a", mode: "client", transport: "unicast",
                connect: {{ endpoints: ["tcp/127.0.0.1:7447"] }}, driver: [ {role} ] }} ] }}"#
        ))
    }

    fn refused(role: &str) -> Vec<String> {
        plan(role)
            .expect_err("refused")
            .into_iter()
            .map(|r| r.to_string())
            .collect()
    }

    /// Every key is read, `count` stays absent when the document leaves it out and
    /// the timeout takes the `get` role's default.
    #[test]
    fn the_keys_are_read_and_the_timeout_defaults() {
        let full = plan(
            r#"{ role: "query", key: "d/q", period_ms: 40, count: 2, timeout_ms: 900, after_ms: 5 }"#,
        )
        .expect("accepted");
        assert_eq!(
            full.sessions[0].driver[0],
            DriverEntry {
                word: "query",
                after_ms: 5,
                args: Args::of(&[
                    ("key", Value::Text("d/q".into())),
                    ("period_ms", Value::Int(40)),
                    ("count", Value::Int(2)),
                    ("timeout_ms", Value::Int(900)),
                ]),
            }
        );
        let bare = plan(r#"{ role: "query", key: "d/q", period_ms: 40 }"#).expect("accepted");
        let args = &bare.sessions[0].driver[0].args;
        assert_eq!(
            args.int("count"),
            None,
            "an absent count runs until stopped"
        );
        assert_eq!(args.int("timeout_ms"), Some(DEFAULT_TIMEOUT_MS));
    }

    /// A key missing, a key of another role and a value of the wrong kind each
    /// name their key.
    #[test]
    fn a_missing_foreign_or_malformed_key_is_refused_by_its_name() {
        assert_eq!(
            refused(r#"{ role: "query", period_ms: 40 }"#),
            vec!["sessions[0].driver[0].key: required, a keyexpr with no whitespace"]
        );
        assert_eq!(
            refused(r#"{ role: "query", key: "d/q" }"#),
            vec![
                "sessions[0].driver[0].period_ms: give exactly one of period_ms (open loop) and \
                 think_ms (closed loop)"
            ]
        );
        assert_eq!(
            refused(r#"{ role: "query", key: "d/q", period_ms: 40, think_ms: 0 }"#),
            vec![
                "sessions[0].driver[0].period_ms: give exactly one of period_ms (open loop) and \
                 think_ms (closed loop)"
            ]
        );
        assert!(plan(r#"{ role: "query", key: "d/q", think_ms: 0 }"#).is_ok());
        assert_eq!(
            refused(r#"{ role: "query", key: "d/q", period_ms: 40, reply: "x" }"#),
            vec!["sessions[0].driver[0].reply: not a key of the `query` role"]
        );
        assert_eq!(
            refused(r#"{ role: "query", key: "d/q", period_ms: 40, count: 0 }"#),
            vec!["sessions[0].driver[0].count: must be a positive integer"]
        );
        assert_eq!(
            refused(r#"{ role: "query", key: "d/q", period_ms: 40, timeout_ms: "soon" }"#),
            vec!["sessions[0].driver[0].timeout_ms: must be a positive integer"]
        );
    }

    /// The role needs no build feature of the demo: it is played by every build and
    /// the registry names no feature for it.
    #[test]
    fn the_role_is_played_by_every_build() {
        assert!(ROLE.available);
        assert_eq!(ROLE.feature, None);
    }
}
