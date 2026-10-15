// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `publish`: put `payload` under `key` every `period_ms`, `count` times (until
//! the process stops when `count` is absent).

use std::time::Duration;

use wz::runtime_tokio::sample::SampleKind;

use crate::sessions_driver::{Ctx, KeyDef, KeyKind, Play, RoleDef};

pub(crate) static ROLE: RoleDef = RoleDef::played(
    "publish",
    &[
        KeyDef::required("key", KeyKind::Keyexpr),
        KeyDef::required("payload", KeyKind::Text),
        KeyDef::required("period_ms", KeyKind::Millis),
        KeyDef::optional("count", KeyKind::Count),
    ],
    play,
);

fn play(ctx: Ctx) -> Play {
    Box::pin(run(ctx))
}

async fn run(ctx: Ctx) {
    let key = ctx.text("key");
    let payload = ctx.text("payload");
    let period = Duration::from_millis(ctx.int("period_ms").unwrap_or(1));
    let count = ctx.int("count");
    let mut sent = 0u64;
    while count.map_or(true, |n| sent < n) {
        ctx.emit(&key, SampleKind::Put, payload.as_bytes());
        sent += 1;
        tokio::time::sleep(period).await;
    }
    ctx.say.line(&format!("done key={key} count={sent}"));
}
