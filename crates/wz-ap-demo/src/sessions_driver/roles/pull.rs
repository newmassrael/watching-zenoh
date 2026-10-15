// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `pull`: hold a buffered subscriber on `key` and drain its queue every
//! `period_ms`.
//!
//! The queue holds `capacity` samples. When it is full the session does not drop
//! the next sample: its drive loop waits at the drain until the role takes some
//! out, so a `period_ms` much longer than the session's lease with a small
//! `capacity` stalls the session for as long as the queue stays full. That
//! backpressure is what the role exists to show, and the period is the document's
//! to choose.

use std::time::Duration;

use wz::runtime_tokio::session::SubscribeOptions;
use wz::runtime_tokio::sink::SampleView;

use crate::sessions_driver::{Args, Ctx, KeyDef, KeyKind, Play, RoleDef};

/// How many samples the queue holds when the document names no capacity.
const DEFAULT_CAPACITY: u64 = 16;
/// The largest queue the role accepts. The channel behind it panics above a bound
/// of its own, so a document that asks for more is refused rather than aborting
/// the process.
const MAX_CAPACITY: u64 = 1_048_576;

pub(crate) static ROLE: RoleDef = RoleDef::played(
    "pull",
    &[
        KeyDef::required("key", KeyKind::Keyexpr),
        KeyDef::required("period_ms", KeyKind::Millis),
        KeyDef::defaulted("capacity", KeyKind::Count, DEFAULT_CAPACITY),
    ],
    play,
)
.checked(check);

fn check(args: &Args) -> Vec<(&'static str, String)> {
    match args.int("capacity") {
        Some(n) if n > MAX_CAPACITY => {
            vec![("capacity", format!("must be at most {MAX_CAPACITY}"))]
        }
        _ => Vec::new(),
    }
}

fn play(ctx: Ctx) -> Play {
    Box::pin(run(ctx))
}

async fn run(ctx: Ctx) {
    let key = ctx.text("key");
    let period = Duration::from_millis(ctx.int("period_ms").unwrap_or(1));
    // Bounded by `check`, so it always fits; the fallback is never taken.
    let capacity = usize::try_from(
        ctx.int("capacity")
            .unwrap_or(DEFAULT_CAPACITY)
            .min(MAX_CAPACITY),
    )
    .unwrap_or(1);
    let declared = ctx.session.declare_subscriber_buffered(
        key.clone(),
        SubscribeOptions::default(),
        capacity,
        // Runs on the drive loop, so it keeps only what a line prints.
        |sample: &dyn SampleView| {
            (
                sample.keyexpr().to_string(),
                sample.kind(),
                sample.payload().len(),
            )
        },
    );
    match declared {
        Ok((_held, mut queue, _stage)) => {
            ctx.say
                .line(&format!("declared key={key} capacity={capacity}"));
            loop {
                tokio::time::sleep(period).await;
                let mut drained = Vec::new();
                while let Ok(item) = queue.try_recv() {
                    drained.push(item);
                }
                ctx.say.line(&format!("pulled n={}", drained.len()));
                for (sample_key, kind, bytes) in drained {
                    ctx.say.line(&format!(
                        "sample key={sample_key} kind={kind:?} bytes={bytes}"
                    ));
                }
            }
        }
        Err(e) => ctx.say.line(&format!("refused key={key}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::{read_sessions_document, Refusal, SessionsPlan};
    use crate::sessions_driver::{DriverEntry, Value};

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

    /// The keys are read, and a document that names no capacity gets the default.
    #[test]
    fn the_keys_are_read_and_the_capacity_defaults() {
        let named =
            plan(r#"{ role: "pull", key: "d/**", period_ms: 50, capacity: 4 }"#).expect("accepted");
        assert_eq!(
            named.sessions[0].driver[0],
            DriverEntry {
                word: "pull",
                after_ms: 0,
                args: Args::of(&[
                    ("key", Value::Text("d/**".into())),
                    ("period_ms", Value::Int(50)),
                    ("capacity", Value::Int(4)),
                ]),
            }
        );
        let bare = plan(r#"{ role: "pull", key: "d/**", period_ms: 50 }"#).expect("accepted");
        assert_eq!(
            bare.sessions[0].driver[0].args.int("capacity"),
            Some(DEFAULT_CAPACITY)
        );
    }

    /// A key missing, a key of another role and a wrong kind each name their key,
    /// and so does a capacity the channel cannot hold.
    #[test]
    fn a_missing_foreign_or_malformed_key_is_refused_by_its_name() {
        assert_eq!(
            refused(r#"{ role: "pull", period_ms: 50 }"#),
            vec!["sessions[0].driver[0].key: required, a keyexpr with no whitespace"]
        );
        assert_eq!(
            refused(r#"{ role: "pull", key: "d/**" }"#),
            vec!["sessions[0].driver[0].period_ms: required, a positive integer of milliseconds"]
        );
        assert_eq!(
            refused(r#"{ role: "pull", key: "d/**", period_ms: 50, count: 3 }"#),
            vec!["sessions[0].driver[0].count: not a key of the `pull` role"]
        );
        assert_eq!(
            refused(r#"{ role: "subscribe", key: "d/**", capacity: 4 }"#),
            vec!["sessions[0].driver[0].capacity: not a key of the `subscribe` role"]
        );
        assert_eq!(
            refused(r#"{ role: "pull", key: "d/**", period_ms: 50, capacity: 0 }"#),
            vec!["sessions[0].driver[0].capacity: must be a positive integer"]
        );
        assert_eq!(
            refused(r#"{ role: "pull", key: "d/**", period_ms: 50, capacity: 1048577 }"#),
            vec!["sessions[0].driver[0].capacity: must be at most 1048576"]
        );
        assert!(
            plan(r#"{ role: "pull", key: "d/**", period_ms: 50, capacity: 1048576 }"#).is_ok(),
            "the largest queue is accepted"
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
