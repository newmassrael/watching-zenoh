// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a listening session's link admission allocates once the session is open: nothing. The
//! admission its links ask while their handshakes run reserves, when the session opens, a row for
//! each link the session may hold, and each link keeps the node it names in place, so a link
//! taken off a port and admitted, two links to one node that cross, and a link past the rows take
//! no memory of the heap. The allocations counted are the calling thread's.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use wz_session_core::link_admission::{LinkAdmission, LinkLease};
use wz_session_core::session_zid::SessionZid;
use wz_session_core::WhatAmI;

use super::redial_heap::counted;
use super::{client_config, config_zid, open_with};
use crate::{CoopConfig, EngineHold};

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
    let config = listening();
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
            let mut lease = LinkLease::placed(admission, false);
            if lease.reserve(Some(zid)) {
                admitted += 1;
            }
            held.push(lease);
        }
        let mut refused = LinkLease::placed(admission, false);
        past_refused = !refused.reserve(Some(&past));
        drop(refused);
        held.clear();

        let mut dial = LinkLease::placed(admission, true);
        let dial_reserved = dial.reserve(Some(&lower));
        let mut inbound = LinkLease::placed(admission, false);
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

/// A session that listens on the host's loopback, at a port the host picks.
fn listening() -> CoopConfig {
    CoopConfig {
        whatami: WhatAmI::Peer,
        zid: config_zid(0xa1),
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        ..client_config()
    }
}

/// A listening session's admission lies in the session's own arena. Turned red by an admission
/// made anywhere but the place its plan laid out for it.
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn a_listening_sessions_admission_lies_in_its_own_arena() {
    let engine = open_with(listening());
    let admission = engine.link_admission();
    let at = core::ptr::from_ref::<dyn LinkAdmission>(&*admission).cast::<u8>();
    assert!(engine.arena_holds(at), "the admission lies in the arena");
}

/// Marks its drop in the flag it names.
struct Dropped(Arc<AtomicBool>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// No task of a session outlives its engine, though a handle of the session's set is kept past
/// it: a task that holds the set, a lease of the session's admission and a flag is dropped by the
/// engine's drop, its lease giving its token back to the admission the engine still holds. Turned
/// red by an engine whose drop leaves its tasks to the set's last handle, which a handle kept by
/// a task, or by the program, never is.
#[test]
#[cfg_attr(miri, ignore = "the interpreter has no host sockets")]
fn a_sessions_tasks_go_with_its_engine_though_a_handle_of_its_set_is_kept() {
    let engine = open_with(listening());
    let set = engine.local_set();
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = Dropped(Arc::clone(&dropped));
    let lease = LinkLease::placed(engine.link_admission(), false);
    let kept = set.clone();
    let task = set.spawn_local(async move {
        let _kept = kept;
        let _lease = lease;
        let _guard = guard;
        core::future::pending::<()>().await;
    });
    assert!(
        !task.is_finished(),
        "CONTROL: a cell of the session's table took the task"
    );
    assert!(
        !dropped.load(Ordering::Relaxed),
        "CONTROL: the task stays while the session stands"
    );
    assert_eq!(
        EngineHold::holders(&engine),
        1,
        "CONTROL: the test holds the engine's last handle"
    );
    drop(engine);
    assert!(
        dropped.load(Ordering::Relaxed),
        "the engine's drop dropped the task"
    );
    assert!(task.is_finished(), "its handle reads the drop");
    assert_eq!(
        set.live_local_task_count(),
        0,
        "no task of the session is left"
    );
}
