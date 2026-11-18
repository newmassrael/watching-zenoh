// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The declaration watch, which this engine does not carry: a watch of any kind is refused by
//! name rather than taken and never told anything, and the sink it was handed is let go of.

use std::sync::Arc;

use wz_capi_port::{DeclPlane, DeclWatchEvent, DeclWatchRefused, DeclWatchSink, SessionEngine};

use super::{open, CatchAll, Router};

#[test]
fn a_declaration_watch_is_refused_by_name_and_holds_nothing() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);
    let sink: DeclWatchSink = Arc::new(|_: DeclWatchEvent<'_>| {});

    for plane in [
        DeclPlane::Subscribers,
        DeclPlane::Queryables,
        DeclPlane::Tokens,
    ] {
        assert_eq!(
            engine.declare_decl_watch(plane, Arc::clone(&sink)),
            Err(DeclWatchRefused::NotProvided),
            "{plane:?}"
        );
    }
    assert_eq!(
        Arc::strong_count(&sink),
        1,
        "the engine kept no sink of a watch it refused"
    );
    assert!(
        !engine.undeclare_decl_watch(1),
        "no watch is held to undeclare"
    );
}
