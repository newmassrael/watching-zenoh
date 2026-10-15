// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `liveliness_subscribe`: hold a liveliness subscriber on `key`, printing one
//! line when a matching token appears (`Put`) and one when it goes away
//! (`Delete`).
//!
//! `history` asks the peer for the tokens that were alive before the subscriber
//! existed, which is what makes the subscriber independent of the order in which
//! the two sides declared.

use wz::runtime_tokio::declare::LivelinessSampleKind;
use wz::runtime_tokio::session::LivelinessSubscriberOptions;

use crate::sessions_driver::{Ctx, KeyDef, KeyKind, Play, RoleDef};

pub(crate) static ROLE: RoleDef = RoleDef::played(
    "liveliness_subscribe",
    &[
        KeyDef::required("key", KeyKind::Keyexpr),
        KeyDef::optional("history", KeyKind::Flag),
    ],
    play,
);

fn play(ctx: Ctx) -> Play {
    Box::pin(run(ctx))
}

/// The words `subscribe` prints for a put and a delete, so a harness waits on one
/// vocabulary for both: a token that appears is a `Put`, one that goes is a `Del`.
fn kind_word(kind: LivelinessSampleKind) -> &'static str {
    match kind {
        LivelinessSampleKind::Put => "Put",
        LivelinessSampleKind::Delete => "Del",
    }
}

async fn run(ctx: Ctx) {
    let key = ctx.text("key");
    let history = ctx.flag("history").unwrap_or(false);
    let say = ctx.say.clone();
    let declared = ctx.session.declare_liveliness_subscriber(
        key.clone(),
        LivelinessSubscriberOptions::default().with_history(history),
        move |sample| {
            say.line(&format!(
                "sample key={} kind={}",
                sample.keyexpr,
                kind_word(sample.kind)
            ));
        },
    );
    match declared {
        Ok(_held) => {
            ctx.say
                .line(&format!("declared key={key} history={history}"));
            ctx.hold().await;
        }
        Err(e) => ctx.say.line(&format!("refused key={key}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::{read_sessions_document, BuildCapabilities};
    use crate::sessions_driver::{Args, Value};

    fn document(role: &str) -> String {
        format!(
            r#"{{ sessions: [ {{ name: "a", mode: "client", transport: "unicast",
                connect: {{ endpoints: ["tcp/127.0.0.1:7447"] }}, driver: [ {role} ] }} ] }}"#
        )
    }

    fn refused(role: &str) -> Vec<String> {
        read_sessions_document(&document(role))
            .expect_err("refused")
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// A token that appears is said `Put` and one that goes away `Del`.
    #[test]
    fn a_sample_kind_is_said_as_put_or_del() {
        assert_eq!(kind_word(LivelinessSampleKind::Put), "Put");
        assert_eq!(kind_word(LivelinessSampleKind::Delete), "Del");
    }

    /// The key and the optional history flag are read as written; a flag left out
    /// is absent, which the role reads as false.
    #[test]
    fn the_key_and_the_history_flag_are_read() {
        let plan = read_sessions_document(&document(
            r#"{ role: "liveliness_subscribe", key: "demo/alive/**", history: true },
               { role: "liveliness_subscribe", key: "demo/alive/b" }"#,
        ))
        .expect("passes");
        let driver = &plan.sessions[0].driver;
        assert_eq!(
            driver[0].args,
            Args::of(&[
                ("key", Value::Text("demo/alive/**".into())),
                ("history", Value::Flag(true)),
            ])
        );
        assert_eq!(
            driver[1].args,
            Args::of(&[("key", Value::Text("demo/alive/b".into()))])
        );
        assert_eq!(driver[1].args.flag("history"), None);
        assert!(ROLE.available);
        assert_eq!(ROLE.feature, None);
        assert!(plan
            .build_refusals(&BuildCapabilities::of_this_build())
            .is_empty());
    }

    /// A key missing, a key of another role and a flag of the wrong kind are each
    /// refused by key path, and a build that lists no such role refuses it.
    #[test]
    fn a_missing_key_a_foreign_key_and_a_bad_kind_are_refused() {
        assert_eq!(
            refused(r#"{ role: "liveliness_subscribe", history: true }"#),
            vec!["sessions[0].driver[0].key: required, a keyexpr with no whitespace"]
        );
        assert_eq!(
            refused(r#"{ role: "liveliness_subscribe", key: "demo/a", timeout_ms: 5 }"#),
            vec!["sessions[0].driver[0].timeout_ms: not a key of the `liveliness_subscribe` role"]
        );
        assert_eq!(
            refused(r#"{ role: "liveliness_subscribe", key: "demo/a", history: "yes" }"#),
            vec!["sessions[0].driver[0].history: must be true or false"]
        );
        let plan = read_sessions_document(&document(
            r#"{ role: "liveliness_subscribe", key: "demo/a" }"#,
        ))
        .expect("passes");
        let without = BuildCapabilities {
            driver_roles: Vec::new(),
            ..BuildCapabilities::of_this_build()
        };
        let got: Vec<String> = plan
            .build_refusals(&without)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            got,
            vec![
                "sessions[0].driver[0].role: the `liveliness_subscribe` role is not played \
                 by this version"
            ]
        );
    }
}
