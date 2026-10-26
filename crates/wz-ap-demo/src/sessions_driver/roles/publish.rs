// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `publish`: put a payload under `key` as a stream (`super::super::stream`): every `period_ms`
//! or at `rate_per_s` sends a second under its `arrivals` process, the payload written (`payload`,
//! `payload_hex`) or made (`payload_bytes`, `fill`, `seed`), until `count` sends or `duration_ms`
//! has passed, or until the process stops when neither is named.
//!
//! The n-th send is due at its own deadline, whatever the earlier ones cost, and a send that falls
//! behind is not followed by a burst: the deadlines it passed are counted and said on the `done`
//! line, so a run that could not keep its rate says so.

use wz::runtime_tokio::sample::SampleKind;

use crate::sessions_driver::stream::{self, stream_keys};
use crate::sessions_driver::{Ctx, KeyDef, KeyKind, Play, RoleDef};

pub(crate) static ROLE: RoleDef =
    RoleDef::played("publish", stream_keys!(), play).checked(stream::check);

fn play(ctx: Ctx) -> Play {
    Box::pin(run(ctx))
}

async fn run(ctx: Ctx) {
    let key = ctx.text("key");
    stream::run(&ctx, &key, |bytes| ctx.emit(&key, SampleKind::Put, bytes)).await;
}
