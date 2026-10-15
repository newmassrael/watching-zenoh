// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `liveliness_get`: ask which tokens on `key` are alive now, once, and print a
//! line per token and one when the answer is complete.

use wz::runtime_tokio::session::LivelinessGetOptions;

use crate::sessions_driver::{Ctx, KeyDef, KeyKind, Play, RoleDef};

/// How long a `liveliness_get` waits for its answer when the document names no
/// timeout; the same wait a `get` takes.
pub(crate) const DEFAULT_TIMEOUT_MS: u64 = 3_000;

pub(crate) static ROLE: RoleDef = RoleDef::played(
    "liveliness_get",
    &[
        KeyDef::required("key", KeyKind::Keyexpr),
        KeyDef::defaulted("timeout_ms", KeyKind::Millis, DEFAULT_TIMEOUT_MS),
    ],
    play,
);

fn play(ctx: Ctx) -> Play {
    Box::pin(run(ctx))
}

async fn run(ctx: Ctx) {
    let key = ctx.text("key");
    let (replies, finals) = (ctx.say.clone(), ctx.say.clone());
    let timeout =
        u32::try_from(ctx.int("timeout_ms").unwrap_or(DEFAULT_TIMEOUT_MS)).unwrap_or(u32::MAX);
    let asked = ctx.session.liveliness_get(
        key.clone(),
        LivelinessGetOptions::default().with_timeout_ms(timeout),
        move |reply| replies.line(&format!("reply key={}", reply.keyexpr())),
        move |_interest_id| finals.line("final"),
    );
    match asked {
        Ok(_) => {
            ctx.say.line(&format!("asked key={key}"));
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

    /// The key and the timeout are read as written, a timeout left out takes the
    /// default, and every build plays the role.
    #[test]
    fn the_key_and_the_timeout_are_read_and_the_timeout_defaults() {
        let plan = read_sessions_document(&document(
            r#"{ role: "liveliness_get", key: "demo/alive/**", timeout_ms: 9, after_ms: 4 },
               { role: "liveliness_get", key: "demo/alive/b" }"#,
        ))
        .expect("passes");
        let driver = &plan.sessions[0].driver;
        assert_eq!(driver[0].after_ms, 4);
        assert_eq!(
            driver[0].args,
            Args::of(&[
                ("key", Value::Text("demo/alive/**".into())),
                ("timeout_ms", Value::Int(9)),
            ])
        );
        assert_eq!(driver[1].args.int("timeout_ms"), Some(DEFAULT_TIMEOUT_MS));
        assert!(ROLE.available);
        assert_eq!(ROLE.feature, None);
        assert!(plan
            .build_refusals(&BuildCapabilities::of_this_build())
            .is_empty());
    }

    /// A key missing, a key of another role and a timeout of the wrong kind are
    /// each refused by key path, and a build that lists no such role refuses it.
    #[test]
    fn a_missing_key_a_foreign_key_and_a_bad_kind_are_refused() {
        assert_eq!(
            refused(r#"{ role: "liveliness_get", timeout_ms: 5 }"#),
            vec!["sessions[0].driver[0].key: required, a keyexpr with no whitespace"]
        );
        assert_eq!(
            refused(r#"{ role: "liveliness_get", key: "demo/a", history: true }"#),
            vec!["sessions[0].driver[0].history: not a key of the `liveliness_get` role"]
        );
        assert_eq!(
            refused(r#"{ role: "liveliness_get", key: "demo/a", timeout_ms: 0 }"#),
            vec!["sessions[0].driver[0].timeout_ms: must be a positive integer"]
        );
        assert_eq!(
            refused(r#"{ role: "liveliness_get", key: "demo/a", timeout_ms: "soon" }"#),
            vec!["sessions[0].driver[0].timeout_ms: must be a positive integer"]
        );
        let plan =
            read_sessions_document(&document(r#"{ role: "liveliness_get", key: "demo/a" }"#))
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
                "sessions[0].driver[0].role: the `liveliness_get` role is not played by this \
                 version"
            ]
        );
    }
}
