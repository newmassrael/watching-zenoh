// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The input a link has not yet been admitted to give.
//!
//! A session that listens keeps one face for each remote zid, and decides it in the link's
//! handshake (`wz_session_core::link_admission`), so a link that completes its handshake is the
//! session's link to its node. The link's task runs in the session's local set and reads frames as
//! fast as the set is run, so the peer's first frames after the handshake would be dispatched to
//! the session's tables before the engine has brought the face up and told its watchers.
//! [`AdmissionGate`] stands between the task and the link and gives the task nothing once the
//! handshake is complete, until the engine has brought the face up (`CoopEngine::bring_up`). What
//! the peer sent meanwhile stays queued in the link, and is read in order after.
//!
//! The handshake itself is read through: the gate shuts when the session is established, which is
//! after the frame that completed the handshake was dispatched, and not before.

use core::cell::Cell;

use wz_runtime_coop::session_drive::{SessionDatagramLink, WaitOn};
use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::sync::{LockKind, Shared};
use wz_runtime_coop::ClockSource;
use wz_session_core::link::{BoxedLinkDriver, LostCause, RxFrame};

/// `pump`, which gives the session nothing from the moment `actions` is established until the
/// gate is granted ([`Self::grant`]). The gate keeps whether it was granted itself: it lies in the
/// link's cell of the session's table, and the engine's wire for the link holds a handle on that
/// cell, so a link made after the open takes no memory of the heap for its admission. `K` is how
/// the session's runtime holds what it lends the link's session.
pub(crate) struct AdmissionGate<P, C: ClockSource + 'static, K: LockKind = Shared> {
    pump: P,
    actions: SessionHandle<C, dyn BoxedLinkDriver, K>,
    admitted: Cell<bool>,
}

impl<P, C: ClockSource + 'static, K: LockKind> AdmissionGate<P, C, K> {
    pub(crate) fn new(pump: P, actions: SessionHandle<C, dyn BoxedLinkDriver, K>) -> Self {
        Self {
            pump,
            actions,
            admitted: Cell::new(false),
        }
    }

    /// The link is admitted: its input reaches the session from here on.
    pub(crate) fn grant(&self) {
        self.admitted.set(true);
    }

    /// Whether the link's input is held back: its handshake is complete and the engine has not
    /// admitted it.
    fn shut(&self) -> bool {
        !self.admitted.get() && self.actions.is_established()
    }
}

impl<P: SessionDatagramLink, C: ClockSource + 'static, K: LockKind> SessionDatagramLink
    for AdmissionGate<P, C, K>
{
    fn service(&self) {
        self.pump.service()
    }

    fn service_within(&self, max_wait_ms: u64) {
        self.pump.service_within(max_wait_ms)
    }

    fn uses_wake_budget(&self) -> bool {
        self.pump.uses_wake_budget()
    }

    fn try_recv(&self) -> Option<RxFrame> {
        if self.shut() {
            return None;
        }
        self.pump.try_recv()
    }

    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        if self.shut() {
            return false;
        }
        self.pump.recv_with(f)
    }

    /// A link that ended is told to the session after what it queued before the end was read, and
    /// what it queued is held back: the end waits with it.
    fn lost(&self) -> Option<LostCause> {
        if self.shut() {
            return None;
        }
        self.pump.lost()
    }

    // What the link dropped was dropped whatever the gate holds back: it is counted as it is.
    fn take_rx_dropped(&self) -> usize {
        self.pump.take_rx_dropped()
    }

    fn holds_input(&self) -> bool {
        self.pump.holds_input()
    }

    fn waits_for_buffer(&self) -> bool {
        self.pump.waits_for_buffer()
    }

    // The gate holds back input only: what the session owes the stack is written whatever it
    // holds, and the owner's wait wakes for it.
    fn owes_write(&self) -> bool {
        self.pump.owes_write()
    }

    fn write_owed_now(&self) {
        self.pump.write_owed_now()
    }

    /// The rest of a datagram already read is held back with the link's next one.
    fn takes_input(&self) -> bool {
        !self.shut() && self.pump.takes_input()
    }

    fn keeps_input(&self) -> bool {
        self.pump.keeps_input()
    }

    fn keep(&self) {
        self.pump.keep()
    }

    fn lends_until_next_receive(&self) -> bool {
        self.pump.lends_until_next_receive()
    }

    fn input_wait(&self) -> Option<WaitOn> {
        self.pump.input_wait()
    }

    // The gate holds back input only: what the session sends goes out whether or not the link
    // is admitted, so its room is the link's.
    fn room_wait(&self) -> Option<WaitOn> {
        self.pump.room_wait()
    }
}

/// Two sessions on an in-memory network and one thread, so that what a link has given the session
/// at each step is the test's to see and no socket's timing decides it.
#[cfg(all(test, feature = "std"))]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};

    use wz_runtime_coop::session_drive::{
        spawn_session, Locator, OpenedLink, SessionDriveConfig, SessionLinks, SessionRole,
    };
    use wz_runtime_coop::session_runtime::new_session_actions;
    use wz_runtime_coop::{CoopLocalSet, CoopRuntime, CoopTime};
    use wz_runtime_posix::PosixEntropy;
    use wz_session_core::locality::Locality;
    use wz_session_core::observer::ApplicationLayerObserver;
    use wz_session_core::session_timeouts::SessionTimeouts;
    use wz_session_core::sink::{BoxedSink, SampleView};
    use wz_session_core::WhatAmI;
    use wz_session_mcu::app_layer::dispatch_to;
    use wz_session_mcu::memory::{MemoryLinks, MemoryNetwork};

    use super::*;
    use crate::tests::params;

    const ACCEPTOR: [u8; 4] = [10, 0, 0, 1];
    const INITIATOR: [u8; 4] = [10, 0, 0, 2];

    #[derive(Clone, Default)]
    struct Frozen;

    impl ClockSource for Frozen {
        fn now_us(&self) -> u64 {
            0
        }
    }

    fn config(role: SessionRole) -> SessionDriveConfig {
        SessionDriveConfig {
            timeouts: SessionTimeouts::from_build(),
            role,
            max_iters: None,
        }
    }

    /// The initiator puts the moment its handshake completes, and the acceptor's link is read
    /// through a gate: the handshake completes through it, the put waits in the link, and is
    /// delivered once the link is admitted. A link that is let go of unadmitted delivers nothing.
    #[test]
    fn a_link_gives_the_session_nothing_between_its_handshake_and_its_admission() {
        let net = MemoryNetwork::new();
        let runtime = CoopRuntime::try_new(Frozen).expect("the heap has room");
        let local = CoopLocalSet::new(&runtime);

        let OpenedLink { sink, pump } = MemoryLinks::new(net.clone(), ACCEPTOR)
            .open_acceptor(7447)
            .expect("bind the acceptor's end");
        let acceptor =
            new_session_actions(sink, params(WhatAmI::Peer, 0xa1), CoopTime::new(&runtime))
                .expect("the heap has room");
        let heard = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let observer = Rc::new(RefCell::new(ApplicationLayerObserver::new()));
        let into = heard.clone();
        observer
            .borrow_mut()
            .register_subscriber(
                "demo/**",
                Locality::Any,
                BoxedSink::new(move |sample: &dyn SampleView| {
                    into.lock().unwrap().push(sample.payload().to_vec());
                }),
            )
            .expect("the acceptor's subscriber");
        let gate = Rc::new(AdmissionGate::new(pump, acceptor.clone()));
        let _acceptor_task = spawn_session(
            &local,
            gate.clone(),
            acceptor.clone(),
            wz_runtime_coop::session_runtime::SessionEntropy::new(PosixEntropy),
            CoopTime::new(&runtime),
            config(SessionRole::Acceptor),
            dispatch_to(observer, acceptor.clone()),
        );

        let OpenedLink { sink, pump } = MemoryLinks::new(net, INITIATOR)
            .open_initiator(Locator::udp(std::net::SocketAddr::from((ACCEPTOR, 7447))))
            .expect("open the initiator's end");
        let initiator =
            new_session_actions(sink, params(WhatAmI::Client, 0xc1), CoopTime::new(&runtime))
                .expect("the heap has room");
        let _initiator_task = spawn_session(
            &local,
            pump,
            initiator.clone(),
            wz_runtime_coop::session_runtime::SessionEntropy::new(PosixEntropy),
            CoopTime::new(&runtime),
            config(SessionRole::Initiator),
            dispatch_to(
                Rc::new(RefCell::new(ApplicationLayerObserver::new())),
                initiator.clone(),
            ),
        );

        for _ in 0..64 {
            local.run_until_idle();
            if acceptor.is_established() && initiator.is_established() {
                break;
            }
        }
        assert!(
            acceptor.is_established() && initiator.is_established(),
            "the handshake completes through the gate"
        );

        initiator
            .send_push_literal("demo/x", b"first", true)
            .expect("a put the link carries");
        for _ in 0..16 {
            local.run_until_idle();
        }
        assert!(
            heard.lock().unwrap().is_empty(),
            "the acceptor's link gave the session a put before it was admitted"
        );

        gate.grant();
        for _ in 0..16 {
            local.run_until_idle();
        }
        assert_eq!(
            *heard.lock().unwrap(),
            [b"first".to_vec()],
            "the put waited in the link and is delivered once, in order, after the admission"
        );
    }

    /// Making a link's gate and admitting it allocates nothing: the gate keeps its admission in
    /// itself, which lies where the gate does (the link's cell of the session's table), so a link
    /// a listening session takes after its open takes no memory of the heap for it. Turned red by
    /// an admission kept in a cell of the heap that the gate and the engine's wire share.
    #[test]
    fn a_gate_and_its_admission_take_no_memory_of_the_heap() {
        let runtime = CoopRuntime::try_new(Frozen).expect("the heap has room");
        let OpenedLink { sink, pump } = MemoryLinks::new(MemoryNetwork::new(), ACCEPTOR)
            .open_acceptor(7447)
            .expect("bind the acceptor's end");
        let acceptor =
            new_session_actions(sink, params(WhatAmI::Peer, 0xa1), CoopTime::new(&runtime))
                .expect("the heap has room");
        let mut made = None;
        let allocations = crate::tests::redial_heap::counted(|| {
            let gate = AdmissionGate::new(pump, acceptor.clone());
            gate.grant();
            made = Some(gate);
        });
        assert_eq!(
            allocations, 0,
            "the gate and its admission allocate nothing"
        );
        assert!(
            made.is_some_and(|gate| gate.admitted.get()),
            "CONTROL: the gate made is admitted"
        );
    }

    /// A gate answers what its link dropped by asking the link. Turned red by a gate that answers
    /// it itself (the trait's provided form) instead of passing the question on.
    #[test]
    fn a_gate_answers_what_its_link_dropped() {
        struct Dropping(Cell<usize>);

        impl SessionDatagramLink for Dropping {
            fn service(&self) {}

            fn try_recv(&self) -> Option<RxFrame> {
                None
            }

            fn take_rx_dropped(&self) -> usize {
                self.0.replace(0)
            }
        }

        let runtime = CoopRuntime::try_new(Frozen).expect("the heap has room");
        let OpenedLink { sink, .. } = MemoryLinks::new(MemoryNetwork::new(), ACCEPTOR)
            .open_acceptor(7447)
            .expect("bind the acceptor's end");
        let acceptor =
            new_session_actions(sink, params(WhatAmI::Peer, 0xa1), CoopTime::new(&runtime))
                .expect("the heap has room");
        let gate = AdmissionGate::new(Dropping(Cell::new(2)), acceptor);
        assert_eq!(gate.take_rx_dropped(), 2, "the link's drops");
        assert_eq!(gate.take_rx_dropped(), 0, "a take empties the count");
    }
}
