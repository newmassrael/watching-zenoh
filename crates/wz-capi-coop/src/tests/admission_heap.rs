// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a listening session's link admission allocates once the session is open: nothing. The
//! admission its links ask while their handshakes run reserves, when the session opens, a row for
//! each link the session may hold, and each link keeps the node it names in place, so a link
//! taken off a port and admitted, two links to one node that cross, and a link past the rows take
//! no memory of the heap. The allocations counted are the calling thread's.

use std::sync::Arc;

use wz_session_core::link_admission::LinkLease;
use wz_session_core::session_zid::SessionZid;
use wz_session_core::WhatAmI;

use super::redial_heap::counted;
use super::{client_config, config_zid, open_with};
use crate::CoopConfig;

/// A node whose zid is lower than the session's (`0xa1` four times) in either `link-tie-order`.
const LOWER: [u8; 1] = [0x01];

/// The zid of the `at`-th node that dials the session: none is `LOWER`, as each has a second
/// byte that is not zero.
fn dialler(at: usize) -> [u8; 4] {
    let at = u32::try_from(at).expect("a session's links fit in 32 bits");
    at.saturating_add(0x100).to_le_bytes()
}

/// A listening session's admission, asked as its links' handshakes ask it, admits a link from
/// each of as many nodes as it has rows, refuses the one past them, and judges two links to one
/// node that cross (the session dials a node that dials it at once: the link the lower zid
/// dialled supersedes the other), all with no memory of the heap. Turned red by an admission
/// whose rows grow when a link takes one, by a judgement that collects the links it supersedes
/// in memory of its own, or by a lease that copies the node it names out of the handshake.
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn a_listening_sessions_admission_takes_no_memory_once_it_is_open() {
    let config = CoopConfig {
        whatami: WhatAmI::Peer,
        zid: config_zid(0xa1),
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        ..client_config()
    };
    let rows = crate::arena::links_of(&config).expect("a session the build admits");
    let engine = open_with(config);
    let admission = engine.link_admission();
    let spelled = |bytes: &[u8]| SessionZid::new(bytes).expect("a zid");
    let zids: Vec<SessionZid> = (0..rows).map(|at| spelled(&dialler(at))).collect();
    let past = spelled(&dialler(rows));
    let lower = spelled(&LOWER);
    let mut held = Vec::with_capacity(rows);
    let mut admitted = 0usize;
    let mut past_refused = false;
    let mut crossing = (false, false, false, None);

    let allocations = counted(|| {
        for zid in &zids {
            let mut lease = LinkLease::new(Arc::clone(&admission), false);
            if lease.reserve(Some(zid)) {
                admitted += 1;
            }
            held.push(lease);
        }
        let mut refused = LinkLease::new(Arc::clone(&admission), false);
        past_refused = !refused.reserve(Some(&past));
        drop(refused);
        held.clear();

        let mut dial = LinkLease::new(Arc::clone(&admission), true);
        let dial_reserved = dial.reserve(Some(&lower));
        let mut inbound = LinkLease::new(Arc::clone(&admission), false);
        let inbound_admitted = inbound.reserve(Some(&lower));
        crossing = (
            dial_reserved,
            inbound_admitted,
            dial.confirm(),
            inbound.node(),
        );
    });

    assert_eq!(
        allocations, 0,
        "admitting, judging and refusing links takes no memory of the heap"
    );
    assert_eq!(
        admitted, rows,
        "CONTROL: a link from each of as many nodes as the rows is admitted"
    );
    assert!(past_refused, "CONTROL: the link past the rows is refused");
    assert_eq!(
        crossing,
        (true, true, false, Some(lower)),
        "CONTROL: the lower node's link supersedes the session's dial, and names its node"
    );
}
