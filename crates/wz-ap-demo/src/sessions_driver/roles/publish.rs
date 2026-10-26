// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `publish`: put a payload under `key` as a stream (`super::super::stream`): every `period_ms`
//! or at `rate_per_s` sends a second, the payload written (`payload`, `payload_hex`) or made
//! (`payload_bytes`, `fill`, `seed`), until `count` sends or `duration_ms` has passed, or until
//! the process stops when neither is named.
//!
//! The n-th send is due n gaps after the first, whatever the earlier ones cost, and a send that
//! falls behind by more than a gap is not followed by a burst: the deadlines it passed are counted
//! and said on the `done` line, so a run that could not keep its rate says so.

use std::time::Duration;

use tokio::time::Instant;
use wz::runtime_tokio::sample::SampleKind;

use crate::sessions_driver::stream::{self, FILLS};
use crate::sessions_driver::{Ctx, KeyDef, KeyKind, Play, RoleDef};

pub(crate) static ROLE: RoleDef = RoleDef::played(
    "publish",
    &[
        KeyDef::required("key", KeyKind::Keyexpr),
        KeyDef::optional("payload", KeyKind::Text),
        KeyDef::optional("payload_hex", KeyKind::Hex),
        KeyDef::optional("payload_bytes", KeyKind::Count),
        KeyDef::optional("fill", KeyKind::Word(FILLS)),
        KeyDef::optional("seed", KeyKind::Integer),
        KeyDef::optional("period_ms", KeyKind::Millis),
        KeyDef::optional("rate_per_s", KeyKind::Decimal),
        KeyDef::optional("count", KeyKind::Count),
        KeyDef::optional("duration_ms", KeyKind::Millis),
    ],
    play,
)
.checked(stream::check);

fn play(ctx: Ctx) -> Play {
    Box::pin(run(ctx))
}

async fn run(ctx: Ctx) {
    let key = ctx.text("key");
    let payload = stream::payload(ctx.args());
    let mut schedule = stream::schedule(ctx.args());
    let count = ctx.int("count");
    let duration = ctx.int("duration_ms").map(Duration::from_millis);
    let mut bytes = vec![0u8; payload.len()];
    let start = Instant::now();
    let mut sent = 0u64;
    loop {
        if count.is_some_and(|n| sent >= n) {
            break;
        }
        let due = Duration::from_nanos(schedule.due());
        if duration.is_some_and(|d| due >= d) {
            break;
        }
        tokio::time::sleep_until(start + due).await;
        payload.write(sent, &mut bytes);
        ctx.emit(&key, SampleKind::Put, &bytes);
        sent += 1;
        let elapsed = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        schedule.sent(elapsed);
    }
    ctx.say.line(&format!(
        "done key={key} count={sent} skipped={}",
        schedule.skipped()
    ));
}
