// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `get`: ask `key` once and print each reply, waiting at most `timeout_ms`.

use wz::runtime_tokio::session::QueryOptions;

use crate::sessions_driver::{Ctx, KeyDef, KeyKind, Play, RoleDef};

/// How long a `get` waits for its replies when the document names no timeout.
pub(crate) const DEFAULT_TIMEOUT_MS: u64 = 3_000;

pub(crate) static ROLE: RoleDef = RoleDef::played(
    "get",
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
    let asked = ctx.session.query(
        &key,
        QueryOptions::default().with_timeout_ms(timeout),
        move |reply| {
            replies.line(&format!(
                "reply key={} kind={:?} bytes={}",
                reply.keyexpr(),
                reply.kind(),
                reply.payload().len()
            ));
        },
        move |_rid| finals.line("final"),
    );
    match asked {
        Ok(_) => {
            ctx.say.line(&format!("asked key={key}"));
            ctx.hold().await;
        }
        Err(e) => ctx.say.line(&format!("refused key={key}: {e}")),
    }
}
