// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The input a link has not yet been admitted to give.
//!
//! A session that listens keeps one face for each remote zid, and decides it when a handshake
//! completes (`CoopEngine::admit`). The link's task runs in the session's local set and reads
//! frames as fast as the set is run, so a link that is about to be refused would have its
//! first frames dispatched to the session's tables before the decision. [`AdmissionGate`] stands
//! between the task and the link and gives the task nothing once the handshake is complete, until
//! the engine has admitted the link. What the peer sent meanwhile stays queued in the link, and is
//! read in order after the admission. A link that is refused is dropped with it unread.
//!
//! The handshake itself is read through: the gate shuts when the session is established, which is
//! after the frame that completed the handshake was dispatched, and not before.

use alloc::rc::Rc;
use core::cell::Cell;

use wz_runtime_coop::session_drive::{LinkReadiness, SessionDatagramLink};
use wz_runtime_coop::ClockSource;
use wz_session_core::link::{LostCause, RxFrame};
use wz_session_mcu::dial::McuActions;

use crate::prelude::*;

/// Whether the engine has admitted a link: shared between the gate the link's task reads through
/// and the engine's wire for that link, which opens it.
#[derive(Clone, Default)]
pub(crate) struct Admitted(Rc<Cell<bool>>);

impl Admitted {
    /// The link is admitted: its input reaches the session from here on.
    pub(crate) fn grant(&self) {
        self.0.set(true);
    }

    fn granted(&self) -> bool {
        self.0.get()
    }
}

/// `pump`, which gives the session nothing from the moment `actions` is established until
/// `admitted` is granted.
pub(crate) struct AdmissionGate<P, C: ClockSource + 'static> {
    pump: P,
    actions: Rc<McuActions<C>>,
    admitted: Admitted,
}

impl<P, C: ClockSource + 'static> AdmissionGate<P, C> {
    pub(crate) fn new(pump: P, actions: Rc<McuActions<C>>, admitted: Admitted) -> Self {
        Self {
            pump,
            actions,
            admitted,
        }
    }

    /// Whether the link's input is held back: its handshake is complete and the engine has not
    /// admitted it.
    fn shut(&self) -> bool {
        !self.admitted.granted() && self.actions.is_established()
    }
}

impl<P: SessionDatagramLink, C: ClockSource + 'static> SessionDatagramLink for AdmissionGate<P, C> {
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

    fn holds_input(&self) -> bool {
        self.pump.holds_input()
    }

    fn readiness(&self) -> Option<Box<dyn LinkReadiness>> {
        self.pump.readiness()
    }
}

/// Two sessions on an in-memory network and one thread, so that what a link has given the session
/// at each step is the test's to see and no socket's timing decides it.
#[cfg(all(test, feature = "std"))]
mod tests {
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    use wz_runtime_coop::session_drive::{
        spawn_session, IpEndpoint, Locator, OpenedLink, SessionDriveConfig, SessionLinks,
        SessionRole,
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
            timeouts: SessionTimeouts::spec_defaults(),
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
        let runtime = CoopRuntime::new(Frozen);
        let local = CoopLocalSet::new(&runtime);

        let OpenedLink { sink, pump } = MemoryLinks::new(net.clone(), ACCEPTOR)
            .open_acceptor(7447)
            .expect("bind the acceptor's end");
        let acceptor = new_session_actions(
            sink,
            params(WhatAmI::Peer, 0xa1),
            CoopTime::new(&runtime),
            PosixEntropy,
        );
        let admitted = Admitted::default();
        let heard = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let observer = Rc::new(RefCell::new(ApplicationLayerObserver::new()));
        let into = heard.clone();
        observer
            .borrow_mut()
            .subscribers
            .register_sink(
                "demo/**",
                Locality::Any,
                BoxedSink::new(move |sample: &dyn SampleView| {
                    into.lock().unwrap().push(sample.payload().to_vec());
                }),
            )
            .expect("the acceptor's subscriber");
        let _acceptor_task = spawn_session(
            &local,
            Rc::new(AdmissionGate::new(pump, acceptor.clone(), admitted.clone())),
            acceptor.clone(),
            CoopTime::new(&runtime),
            config(SessionRole::Acceptor),
            dispatch_to(observer, acceptor.clone()),
        );

        let OpenedLink { sink, pump } = MemoryLinks::new(net, INITIATOR)
            .open_initiator(Locator::udp(IpEndpoint {
                addr: ACCEPTOR,
                port: 7447,
            }))
            .expect("open the initiator's end");
        let initiator = new_session_actions(
            sink,
            params(WhatAmI::Client, 0xc1),
            CoopTime::new(&runtime),
            PosixEntropy,
        );
        let _initiator_task = spawn_session(
            &local,
            pump,
            initiator.clone(),
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

        admitted.grant();
        for _ in 0..16 {
            local.run_until_idle();
        }
        assert_eq!(
            *heard.lock().unwrap(),
            [b"first".to_vec()],
            "the put waited in the link and is delivered once, in order, after the admission"
        );
    }
}
