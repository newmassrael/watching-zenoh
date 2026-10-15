// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `delete`: delete `key` once.

use wz::runtime_tokio::sample::SampleKind;

use crate::sessions_driver::{Ctx, KeyDef, KeyKind, Play, RoleDef};

pub(crate) static ROLE: RoleDef =
    RoleDef::played("delete", &[KeyDef::required("key", KeyKind::Keyexpr)], play);

fn play(ctx: Ctx) -> Play {
    Box::pin(async move {
        ctx.emit(&ctx.text("key"), SampleKind::Del, &[]);
    })
}
