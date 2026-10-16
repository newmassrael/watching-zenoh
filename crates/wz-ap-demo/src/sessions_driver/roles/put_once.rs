// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `put`: put `payload` under `key` once.
//!
//! The file is not called `put.rs` because a citation of that name in the store
//! already means the C ABI's `put.rs`, and a second tracked file of the name
//! would make every such citation ambiguous.

use wz::runtime_tokio::sample::SampleKind;

use crate::sessions_driver::{Ctx, KeyDef, KeyKind, Play, RoleDef};

pub(crate) static ROLE: RoleDef = RoleDef::played(
    "put",
    &[
        KeyDef::required("key", KeyKind::Keyexpr),
        KeyDef::required("payload", KeyKind::Text),
    ],
    play,
);

fn play(ctx: Ctx) -> Play {
    Box::pin(async move {
        ctx.emit(
            &ctx.text("key"),
            SampleKind::Put,
            ctx.text("payload").as_bytes(),
        );
    })
}
