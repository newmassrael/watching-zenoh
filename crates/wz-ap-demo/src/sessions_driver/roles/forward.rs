// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `forward`: subscribe on `key` and republish every sample on `to`, in the same
//! session. A delete is republished as a delete.
//!
//! The subscriber callback runs on the session's drive loop and only copies the
//! sample into a channel; the republish happens on the role's own task, so the
//! loop never publishes from inside a delivery.
//!
//! `to` must not be a key `key` can match: the republished sample would reach
//! this same subscriber and circulate for ever, so the document is refused.

use wz::runtime_tokio::keyexpr_match::keyexpr_intersect_patterns;
use wz::runtime_tokio::sample::SampleKind;
use wz::runtime_tokio::session::{PublishOptions, SubscribeOptions};
use wz::runtime_tokio::Reliability;

use crate::sessions_driver::{Args, Ctx, KeyDef, KeyKind, Play, RoleDef};

pub(crate) static ROLE: RoleDef = RoleDef::played(
    "forward",
    &[
        KeyDef::required("key", KeyKind::Keyexpr),
        KeyDef::required("to", KeyKind::Keyexpr),
    ],
    play,
)
.checked(check);

/// `key` and `to` are keyexprs that intersect exactly when some sample `key`
/// receives could be one the role publishes on `to`.
fn check(args: &Args) -> Vec<(&'static str, String)> {
    let (Some(key), Some(to)) = (args.text("key"), args.text("to")) else {
        return Vec::new();
    };
    let key_chunks: Vec<&str> = key.split('/').collect();
    let to_chunks: Vec<&str> = to.split('/').collect();
    if keyexpr_intersect_patterns(&key_chunks, &to_chunks) {
        vec![(
            "to",
            format!("must not be matched by `key` ({key}): the role would forward its own samples"),
        )]
    } else {
        Vec::new()
    }
}

fn play(ctx: Ctx) -> Play {
    Box::pin(run(ctx))
}

async fn run(ctx: Ctx) {
    let key = ctx.text("key");
    let to = ctx.text("to");
    let (staged, mut samples) =
        tokio::sync::mpsc::unbounded_channel::<(String, SampleKind, Vec<u8>)>();
    let declared =
        ctx.session
            .declare_subscriber(key.clone(), SubscribeOptions::default(), move |sample| {
                // A send fails only once the role has ended, and then nobody reads it.
                let _ = staged.send((
                    sample.keyexpr().to_string(),
                    sample.kind(),
                    sample.payload().to_vec(),
                ));
            });
    let _held = match declared {
        Ok(held) => held,
        Err(e) => {
            ctx.say.line(&format!("refused key={key}: {e}"));
            return;
        }
    };
    ctx.say.line(&format!("declared key={key} to={to}"));
    while let Some((from, kind, payload)) = samples.recv().await {
        let mut options = PublishOptions::default().with_reliability(Reliability::Reliable);
        options.kind = kind;
        match ctx.session.publish(&to, &payload, options) {
            Ok(_) => ctx.say.line(&format!(
                "forwarded from={from} to={to} kind={kind:?} bytes={}",
                payload.len()
            )),
            Err(e) => ctx.say.line(&format!("refused key={to}: {e}")),
        }
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

    /// Both keys are read.
    #[test]
    fn the_keys_are_read() {
        let accepted =
            plan(r#"{ role: "forward", key: "a/**", to: "b/x", after_ms: 3 }"#).expect("accepted");
        assert_eq!(
            accepted.sessions[0].driver[0],
            DriverEntry {
                word: "forward",
                after_ms: 3,
                args: Args::of(&[
                    ("key", Value::Text("a/**".into())),
                    ("to", Value::Text("b/x".into())),
                ]),
            }
        );
    }

    /// A key missing and a key of another role each name their key.
    #[test]
    fn a_missing_or_foreign_key_is_refused_by_its_name() {
        assert_eq!(
            refused(r#"{ role: "forward", to: "b/x" }"#),
            vec!["sessions[0].driver[0].key: required, a keyexpr with no whitespace"]
        );
        assert_eq!(
            refused(r#"{ role: "forward", key: "a/**" }"#),
            vec!["sessions[0].driver[0].to: required, a keyexpr with no whitespace"]
        );
        assert_eq!(
            refused(r#"{ role: "subscribe", key: "a/**", to: "b/x" }"#),
            vec!["sessions[0].driver[0].to: not a key of the `subscribe` role"]
        );
        assert_eq!(
            refused(r#"{ role: "forward", key: "a/**", to: "b/x", payload: "p" }"#),
            vec!["sessions[0].driver[0].payload: not a key of the `forward` role"]
        );
    }

    /// A `to` that `key` can match is a forwarding loop and is refused at `to`;
    /// a disjoint one is accepted.
    #[test]
    fn a_forwarding_loop_is_refused_at_to() {
        let loop_refusal = |key: &str, to: &str| {
            refused(&format!(
                r#"{{ role: "forward", key: "{key}", to: "{to}" }}"#
            ))
        };
        assert_eq!(
            loop_refusal("a/**", "a/x"),
            vec![
                "sessions[0].driver[0].to: must not be matched by `key` (a/**): the role would \
                 forward its own samples"
            ]
        );
        assert_eq!(loop_refusal("a/x", "a/x").len(), 1, "the same key");
        assert_eq!(
            loop_refusal("a/*", "a/b").len(),
            1,
            "a single-chunk wildcard"
        );
        assert_eq!(loop_refusal("a/b", "a/*").len(), 1, "a wildcard `to`");
        assert!(plan(r#"{ role: "forward", key: "a/**", to: "b/x" }"#).is_ok());
        assert!(plan(r#"{ role: "forward", key: "a/b", to: "a/c" }"#).is_ok());
    }

    /// The role needs no build feature of the demo: it is played by every build and
    /// the registry names no feature for it.
    #[test]
    fn the_role_is_played_by_every_build() {
        assert!(ROLE.available);
        assert_eq!(ROLE.feature, None);
    }
}
