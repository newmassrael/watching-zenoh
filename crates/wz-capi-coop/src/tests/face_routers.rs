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

/// Each face's Router holds that face's chains alone, keyed by their channel: a fragment that
/// names another peer continues the chain open on its channel in the face's Router, while the chain
/// of the same channel in another face's Router stands apart; and a face's lost link ends every
/// chain of the face's Router, whatever peer it names, and none of another face's. Turned red by a
/// Router keyed by peer where each face holds its own (`RouterPeers` chosen by `listen` again),
/// or by Routers the faces share.
#[test]
fn each_faces_router_keys_its_chains_by_channel_and_ends_them_alone() {
    use wz_session_core::extfragment::FragmentMarkers;
    use wz_session_core::qos::Priority;
    use wz_session_core::reassembly_dispatch::{Fragment, IngestOutcome};

    const DIAL_PEER: &[u8] = &[0x5a; 16];
    const TAKEN_PEER: &[u8] = &[0x5b; 16];
    let sim = Sim::new(SEED);
    let _router = sim.stand_in(CatchAll::None);
    let engine = peer(&sim);
    assert!(
        engine.direct_faces().0 >= 2,
        "CONTROL: the face table holds a row beside the dial role's"
    );
    // One fragment of the reliable channel's chain at `sn`, the last of it where `more` is 0,
    // naming `peer`, rejoined by the Router of the face at `row`.
    let ingest = |row: usize, peer: &'static [u8], sn: u64, more: u8, payload: &'static [u8]| {
        engine
            .with_face_chain_router(row, |router, now_ms| {
                let mut got = None;
                let outcome = router.ingest(
                    Fragment {
                        peer_key: peer,
                        reliable: true,
                        sn,
                        more,
                        payload,
                        priority: Priority::DEFAULT,
                        markers: FragmentMarkers::NONE,
                    },
                    wz_session_core::sn::mask_from_res(0x02),
                    now_ms,
                    |message| got = Some(message.to_vec()),
                );
                (outcome, got)
            })
            .expect("the row holds a face")
    };
    assert_eq!(ingest(0, DIAL_PEER, 1, 1, b"dial ").0, IngestOutcome::Begun);
    assert_eq!(
        ingest(1, TAKEN_PEER, 1, 1, b"taken ").0,
        IngestOutcome::Begun,
        "the same channel's chain begins in the other face's Router"
    );
    assert_eq!(
        ingest(1, DIAL_PEER, 2, 0, b"whole"),
        (IngestOutcome::Reassembled, Some(b"taken whole".to_vec())),
        "a fragment naming another peer continues the face's chain on its channel"
    );
    assert_eq!(
        ingest(1, TAKEN_PEER, 3, 1, b"again").0,
        IngestOutcome::Begun
    );
    assert_eq!(
        engine.with_face_chain_router(0, |router, _| router.abort_peer(DIAL_PEER)),
        Some(1),
        "the dial role's lost link ends its face's one chain"
    );
    assert_eq!(
        engine.with_face_chain_router(1, |router, _| router.active_chains()),
        Some(1),
        "the other face's chain stands"
    );
    assert_eq!(
        engine.with_face_chain_router(1, |router, _| router.abort_peer(DIAL_PEER)),
        Some(1),
        "a lost link ends every chain of its face's Router, whatever peer it names"
    );
}
