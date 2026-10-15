// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `answer`: hold a queryable on `key` that answers every query with `reply`.

use wz::runtime_tokio::session::QueryableOptions;

use crate::sessions_driver::{Ctx, KeyDef, KeyKind, Play, RoleDef};

pub(crate) static ROLE: RoleDef = RoleDef::played(
    "answer",
    &[
        KeyDef::required("key", KeyKind::Keyexpr),
        KeyDef::required("reply", KeyKind::Text),
    ],
    play,
);

fn play(ctx: Ctx) -> Play {
    Box::pin(run(ctx))
}

async fn run(ctx: Ctx) {
    let key = ctx.text("key");
    let reply = ctx.text("reply");
    let say = ctx.say.clone();
    let declared = ctx.session.declare_queryable(
        key.clone(),
        QueryableOptions::default(),
        move |query, responder| {
            responder.reply(reply.as_bytes());
            say.line(&format!(
                "replied key={} bytes={}",
                query.keyexpr(),
                reply.len()
            ));
        },
    );
    match declared {
        Ok(_held) => {
            ctx.say.line(&format!("declared key={key}"));
            ctx.hold().await;
        }
        Err(e) => ctx.say.line(&format!("refused key={key}: {e}")),
    }
}
