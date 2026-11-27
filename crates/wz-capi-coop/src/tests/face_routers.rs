// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The reassembly Routers of a session whose read steps each face's pump itself: each face holds
//! one of its own and lends it where that face's pump alone looks for it, so the faces' chains
//! never meet, whichever threads read the faces.

use wz_session_core::WhatAmI;

use super::sim::{Sim, SimEngine};
use super::{config_zid, CatchAll};
use crate::{CoopConfig, EngineHold};

/// The simulation's seed: the session here draws nothing it reads, so any seed is the run.
const SEED: u64 = 0xa6;

/// A peer that dials the router stand-in, opened in the simulated world and not stepped past its
/// open: a build that takes faces beside the dial role's lays its face table out for the faces
/// its config allows, so the table holds the dial role's row and one row for each face it may
/// take beside it.
fn peer(sim: &Sim) -> EngineHold<SimEngine> {
    sim.open(CoopConfig {
        whatami: WhatAmI::Peer,
        zid: config_zid(0xa6),
        max_faces: 2,
        ..sim.config()
    })
}

/// While a face lends its Router for a step, no other face's pump finds a Router lent where it
/// looks: a read that steps another face's pump on another thread meanwhile is lent that face's
/// Router, never this one. Turned red by a place the faces share (`DirectFace::init_at` handed the
/// session's place, as each face was before it had a cell of its own).
#[test]
fn a_faces_router_is_lent_where_its_own_pump_alone_looks() {
    let sim = Sim::new(SEED);
    let _router = sim.stand_in(CatchAll::None);
    let engine = peer(&sim);
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
