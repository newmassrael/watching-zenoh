// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `subscribe`: hold a subscriber on `key`, printing each sample.

use wz::runtime_tokio::session::SubscribeOptions;

use crate::sessions_driver::{Ctx, KeyDef, KeyKind, Play, RoleDef};

pub(crate) static ROLE: RoleDef = RoleDef::played(
    "subscribe",
    &[KeyDef::required("key", KeyKind::Keyexpr)],
    play,
);

fn play(ctx: Ctx) -> Play {
    Box::pin(run(ctx))
}

async fn run(ctx: Ctx) {
    let key = ctx.text("key");
    let say = ctx.say.clone();
    let declared =
        ctx.session
            .declare_subscriber(key.clone(), SubscribeOptions::default(), move |sample| {
                say.line(&format!(
                    "sample key={} kind={:?} bytes={}",
                    sample.keyexpr(),
                    sample.kind(),
                    sample.payload().len()
                ));
            });
    match declared {
        Ok(_held) => {
            ctx.say.line(&format!("declared key={key}"));
            ctx.hold().await;
        }
        Err(e) => ctx.say.line(&format!("refused key={key}: {e}")),
    }
}
