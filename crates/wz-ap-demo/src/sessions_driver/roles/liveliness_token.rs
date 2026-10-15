// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `liveliness_token`: declare a liveliness token on `key` and hold it.
//!
//! The token is the thing the peer's liveliness subscribers and gets see, so it
//! lives exactly as long as this task: aborting the task at the session's end
//! drops the handle, and the drop retracts the token on the wire.

use wz::runtime_tokio::session::LivelinessOptions;

use crate::sessions_driver::{Ctx, KeyDef, KeyKind, Play, RoleDef};

pub(crate) static ROLE: RoleDef = RoleDef::played(
    "liveliness_token",
    &[KeyDef::required("key", KeyKind::Keyexpr)],
    play,
);

fn play(ctx: Ctx) -> Play {
    Box::pin(run(ctx))
}

async fn run(ctx: Ctx) {
    let key = ctx.text("key");
    match ctx
        .session
        .declare_token(key.clone(), LivelinessOptions::default())
    {
        Ok(_held) => {
            ctx.say.line(&format!("declared key={key}"));
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

    /// The token's key is read as written, and every build plays the role.
    #[test]
    fn the_key_is_read_and_every_build_plays_the_role() {
        let plan = read_sessions_document(&document(
            r#"{ role: "liveliness_token", key: "demo/alive/a", after_ms: 5 }"#,
        ))
        .expect("passes");
        let entry = &plan.sessions[0].driver[0];
        assert_eq!(entry.word, "liveliness_token");
        assert_eq!(entry.after_ms, 5);
        assert_eq!(
            entry.args,
            Args::of(&[("key", Value::Text("demo/alive/a".into()))])
        );
        assert!(ROLE.available);
        assert_eq!(ROLE.feature, None);
        assert!(plan
            .build_refusals(&BuildCapabilities::of_this_build())
            .is_empty());
    }

    /// A key missing, a key of another role and a key of the wrong kind are each
    /// refused by key path, and a build that lists no such role refuses it.
    #[test]
    fn a_missing_key_a_foreign_key_and_a_bad_kind_are_refused() {
        assert_eq!(
            refused(r#"{ role: "liveliness_token" }"#),
            vec!["sessions[0].driver[0].key: required, a keyexpr with no whitespace"]
        );
        assert_eq!(
            refused(r#"{ role: "liveliness_token", key: "demo/a", history: true }"#),
            vec!["sessions[0].driver[0].history: not a key of the `liveliness_token` role"]
        );
        assert_eq!(
            refused(r#"{ role: "liveliness_token", key: "demo/a", timeout_ms: 5 }"#),
            vec!["sessions[0].driver[0].timeout_ms: not a key of the `liveliness_token` role"]
        );
        assert_eq!(
            refused(r#"{ role: "liveliness_token", key: "demo a" }"#),
            vec!["sessions[0].driver[0].key: required, a keyexpr with no whitespace"]
        );
        let plan =
            read_sessions_document(&document(r#"{ role: "liveliness_token", key: "demo/a" }"#))
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
                "sessions[0].driver[0].role: the `liveliness_token` role is not played by \
                 this version"
            ]
        );
    }
}
