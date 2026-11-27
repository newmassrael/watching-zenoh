// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The reassembly Routers of a session whose read steps each face's pump itself: each face holds
//! one of its own and lends it where that face's pump alone looks for it, so the faces' chains
//! never meet, whichever threads read the faces.

use wz_session_core::WhatAmI;

use super::{client_config, config_zid, open_with, Engine};
use crate::{CoopConfig, EngineHold};

/// A session that listens on a loopback port the kernel picks and dials nothing, not stepped: its
/// face table holds the dial role's row and one row for each face it may take beside it.
fn listening() -> EngineHold<Engine> {
    open_with(CoopConfig {
        whatami: WhatAmI::Peer,
        zid: config_zid(0xa6),
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        max_faces: 2,
        ..client_config()
    })
}

/// While a face lends its Router for a step, no other face's pump finds a Router lent where it
/// looks: a read that steps another face's pump on another thread meanwhile is lent that face's
/// Router, never this one. Turned red by a place the faces share (`DirectFace::init_at` handed the
/// session's place, as each face was before it had a cell of its own).
#[test]
fn a_faces_router_is_lent_where_its_own_pump_alone_looks() {
    let engine = listening();
    let rows = engine.direct_faces().0;
    assert!(
        rows >= 2,
        "CONTROL: the face table holds a row beside the dial role's"
    );
    for row in 0..rows {
        assert_eq!(
            engine.faces_lent_beside(row),
            Some(0),
            "another face's pump finds row {row}'s Router"
        );
    }
    assert_eq!(
        engine.faces_lent_beside(rows),
        None,
        "a row past the table lends nothing"
    );
}
