// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `query`: declare a querier on `key` and ask through it every `period_ms`,
//! `count` times (until the process stops when `count` is absent).
//!
//! `get` asks once through `Session::query`; this role is the declared handle,
//! which is what a long-lived asker holds: the options (the timeout here) are
//! fixed at the declaration and every question after it goes through them.
//!
//! A question the session refuses ends the role: the refusal is a property of the
//! key or of the build, so the next question would be refused the same way.

use std::time::Duration;

use wz::runtime_tokio::session::QueryOptions;

use super::get::DEFAULT_TIMEOUT_MS;
use crate::sessions_driver::{Ctx, KeyDef, KeyKind, Play, RoleDef};

pub(crate) static ROLE: RoleDef = RoleDef::played(
    "query",
    &[
        KeyDef::required("key", KeyKind::Keyexpr),
        KeyDef::required("period_ms", KeyKind::Millis),
        KeyDef::optional("count", KeyKind::Count),
        KeyDef::defaulted("timeout_ms", KeyKind::Millis, DEFAULT_TIMEOUT_MS),
    ],
    play,
);

fn play(ctx: Ctx) -> Play {
    Box::pin(run(ctx))
}

async fn run(ctx: Ctx) {
    let key = ctx.text("key");
    let period = Duration::from_millis(ctx.int("period_ms").unwrap_or(1));
    let count = ctx.int("count");
    let timeout =
        u32::try_from(ctx.int("timeout_ms").unwrap_or(DEFAULT_TIMEOUT_MS)).unwrap_or(u32::MAX);
    let querier = ctx.session.declare_querier(
        key.clone(),
        QueryOptions::default().with_timeout_ms(timeout),
    );
    ctx.say.line(&format!("declared key={key}"));
    let mut asked = 0u64;
    while count.map_or(true, |n| asked < n) {
        let n = asked + 1;
        let (replies, finals) = (ctx.say.clone(), ctx.say.clone());
        let sent = querier.get(
            move |reply| {
                replies.line(&format!(
                    "reply key={} kind={:?} bytes={}",
                    reply.keyexpr(),
                    reply.kind(),
                    reply.payload().len()
                ));
            },
            move |_rid| finals.line(&format!("final n={n}")),
        );
        match sent {
            Ok(_) => ctx.say.line(&format!("asked key={key} n={n}")),
            Err(e) => {
                ctx.say.line(&format!("refused key={key}: {e}"));
                return;
            }
        }
        asked = n;
        tokio::time::sleep(period).await;
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
            vec!["sessions[0].driver[0].period_ms: required, a positive integer of milliseconds"]
        );
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
