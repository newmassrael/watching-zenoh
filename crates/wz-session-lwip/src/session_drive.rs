// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `run_session` — the synchronous MCU session drive loop, on lwIP.
//!
//! R2915 — the loop itself is `wz_runtime_coop::session_drive`, generic over
//! the network stack. This module is lwIP's side of that seam:
//! [`LwipSessionLink`] implements `SessionDatagramLink` (pump lwIP's input
//! path; take a datagram from the [`LwipUdpDriver`] and retarget replies to
//! its source), and [`run_session`] / [`session_task`] / [`spawn_session`]
//! keep the lwIP-typed signatures every existing caller writes, building the
//! link and handing it to the shared loop.

use alloc::rc::Rc;
use core::ops::Deref;

use wz_link_lwip::LwipLink;
use wz_runtime_coop::session_drive::{self as coop_drive, SessionDatagramLink};
pub use wz_runtime_coop::session_drive::{SessionDriveConfig, SessionRole};
use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopRuntime, CoopTime};
use wz_session_core::driver_loop::{DriverOutcome, IterationEvent};
use wz_session_core::link::RxFrame;
use wz_session_core::session_actions::SessionLinkActions;

#[cfg(test)]
use wz_session_core::session_timeouts::SessionTimeouts;

use crate::driver::LwipUdpDriver;

/// lwIP's [`SessionDatagramLink`]: the `NO_SYS` stack is pumped from the
/// loop's own thread, and inbound datagrams come off the session socket the
/// [`LwipUdpDriver`] shares with the outbound send seam.
///
/// Generic over the link handle `L` rather than borrowing `&LwipLink`,
/// because the two drivers hold the link differently: the synchronous loop
/// borrows one off the caller's stack (`&LwipLink`), while a spawned task
/// must be `'static` and therefore owns a share (`Rc<LwipLink>`). A
/// `Deref<Target = LwipLink>` bound admits both at no runtime cost.
pub struct LwipSessionLink<L: Deref<Target = LwipLink>> {
    link: L,
    driver: Rc<LwipUdpDriver>,
}

impl<L: Deref<Target = LwipLink>> LwipSessionLink<L> {
    /// Pair the lwIP link whose input path is pumped with the driver whose
    /// socket carries the session.
    pub fn new(link: L, driver: Rc<LwipUdpDriver>) -> Self {
        Self { link, driver }
    }
}

impl<L: Deref<Target = LwipLink>> SessionDatagramLink for LwipSessionLink<L> {
    fn service(&self) {
        // Drive the lwIP input path (loopback / QEMU shape). Real-NIC
        // deploys drive netif input from the RX ISR instead of
        // poll_loopback (carry tail).
        self.link.poll_loopback();
        self.link.check_timeouts();
    }

    fn try_recv(&self) -> Option<RxFrame> {
        let dg = self.driver.try_recv()?;
        // Reply to whoever just spoke (the acceptor reply path).
        self.driver.set_peer(dg.src_addr, dg.src_port);
        Some(RxFrame::new(dg.data.as_slice().to_vec()))
    }

    // The datagram is lent where the session socket's receive queue holds it:
    // no heap copy, and no slot-sized value on the stack under the dispatch.
    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        self.driver.recv_with(f)
    }
}

/// The shared pump, over an lwIP link held as `L`.
pub type SessionPump<C, L> = coop_drive::SessionPump<C, LwipSessionLink<L>>;

/// Drive one logical session over the lwIP link to a terminal FSM state (or
/// the `config.max_iters` cap) — `wz_runtime_coop::session_drive::run_session`
/// over [`LwipSessionLink`].
///
/// - `link` — the [`LwipLink`]; `poll_loopback` + `check_timeouts` drive the
///   lwIP input path each tick. This is the loopback / QEMU shape — a real
///   multi-NIC deploy drives netif input from the RX ISR instead (carry tail).
/// - `driver` — the concrete [`LwipUdpDriver`] (for `try_recv` + `set_peer`);
///   the same object lives inside `actions` as `Rc<dyn BoxedLinkDriver>` for
///   the outbound send seam.
///
/// The other parameters are the shared loop's.
pub fn run_session<C, F>(
    runtime: &CoopRuntime<C>,
    link: &LwipLink,
    driver: &Rc<LwipUdpDriver>,
    actions: &Rc<SessionLinkActions<CoopRuntime<C>, CoopTime<C>>>,
    clock: &CoopTime<C>,
    config: SessionDriveConfig,
    on_event: F,
) -> DriverOutcome
where
    C: ClockSource,
    F: FnMut(IterationEvent<'_>),
{
    coop_drive::run_session(
        runtime,
        LwipSessionLink::new(link, driver.clone()),
        actions,
        clock,
        config,
        on_event,
    )
}

/// The MCU session AS A TASK over lwIP — the shared `session_task` over
/// [`LwipSessionLink`]. Takes `Rc<LwipLink>` where [`run_session`] takes
/// `&LwipLink`: a spawned task outlives the call that created it, so it must
/// own its share of the link.
pub async fn session_task<C, F>(
    runtime: CoopRuntime<C>,
    link: Rc<LwipLink>,
    driver: Rc<LwipUdpDriver>,
    actions: Rc<SessionLinkActions<CoopRuntime<C>, CoopTime<C>>>,
    clock: CoopTime<C>,
    config: SessionDriveConfig,
    on_event: F,
) -> DriverOutcome
where
    C: ClockSource,
    F: FnMut(IterationEvent<'_>),
{
    coop_drive::session_task(
        runtime,
        LwipSessionLink::new(link, driver),
        actions,
        clock,
        config,
        on_event,
    )
    .await
}

/// Spawn one MCU session over lwIP onto `local` and return its join handle —
/// the shared `spawn_session` over [`LwipSessionLink`].
pub fn spawn_session<C, F>(
    local: &CoopLocalSet<C>,
    link: Rc<LwipLink>,
    driver: Rc<LwipUdpDriver>,
    actions: Rc<SessionLinkActions<CoopRuntime<C>, CoopTime<C>>>,
    clock: CoopTime<C>,
    config: SessionDriveConfig,
    on_event: F,
) -> CoopLocalJoinHandle<DriverOutcome>
where
    C: ClockSource + 'static,
    F: FnMut(IterationEvent<'_>) + 'static,
{
    coop_drive::spawn_session(
        local,
        LwipSessionLink::new(link, driver),
        actions,
        clock,
        config,
        on_event,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::rc::Rc;
    use alloc::vec;
    use core::cell::RefCell;

    use wz_link_lwip::ipv4_addr_loopback;
    use wz_link_lwip::rx_sockets::bind_session_rx;
    use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome};
    use wz_session_core::reliability::Reliability;
    use wz_session_core::session_actions::SessionLinkActions;
    use wz_session_core::session_init_params::SessionInitParams;
    use wz_session_core::signing_key::SigningKey;
    use wz_session_core::WhatAmI;

    use crate::driver::{LwipUdpDriver, SharedSessionSocket};

    /// Frozen host clock — `now_us` is constant, so no handshake / lease
    /// deadline ever elapses (`now_ms >= deadline_ms` stays false). Keeps
    /// the loop-machinery check deterministic (terminates on max_iters, not
    /// on a timing race).
    #[derive(Clone, Default)]
    struct FrozenClock;
    impl ClockSource for FrozenClock {
        fn now_us(&self) -> u64 {
            0
        }
    }

    fn test_params() -> SessionInitParams {
        SessionInitParams {
            version: 0x05,
            whatami: WhatAmI::Peer,
            zid: vec![0x01, 0x02, 0x03, 0x04],
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 1024,
            lease_ms: 10_000,
            initial_sn: 0,
            cookie: vec![0u8; 16],
            tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
            cookie_signing_key: SigningKey::new(vec![7u8; 32]).expect(">=32-byte key"),
        }
    }

    /// Stage 4b integration smoke. lwIP under NO_SYS=1 is a process-global
    /// single-init resource (a second `lwip_init` aborts "netif already
    /// added") while cargo runs a binary's tests on parallel threads. R311lu
    /// resolved the R71-deferred harness: this test and the multicast_drive
    /// loop test now share wz-link-lwip's `lwip_test_link` init-once +
    /// serialized handle (exposed via its `test-support` dev-feature), so two
    /// lwIP-touching tests coexist in one binary. Hold `_serial` for the test
    /// body; drive the input path through the returned link.
    #[test]
    fn mcu_session_shell_drives_over_lwip() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();

        // (1) Outbound seam: LwipUdpDriver::send_blocking -> LwipUdpSocket::
        // send_to -> lwIP loopback -> LwipUdpDriver::try_recv. The adapter
        // drives a real datagram round trip over the shared socket.
        {
            let port: u16 = 7450;
            let socket: SharedSessionSocket = Rc::new(RefCell::new(
                bind_session_rx(&link, port).expect("bind session rx"),
            ));
            let driver = LwipUdpDriver::new(socket, ipv4_addr_loopback(), port);

            let payload: &[u8] = b"stage4b wz-session-lwip driver send";
            // R2371 — the MCU driver reports its outcome too, and a refusal here
            // (pbuf exhaustion, dead netif) would otherwise surface only as the
            // loopback receive below finding nothing.
            std::assert_eq!(
                driver.send_blocking(payload, Reliability::Reliable),
                LinkSendOutcome::Sent,
                "the lwIP driver accepted the datagram"
            );
            link.poll_loopback();
            link.check_timeouts();

            let dg = driver.try_recv().expect("loopback datagram delivered");
            std::assert_eq!(&dg.data[..], payload);
            std::assert_eq!(dg.src_port, port);
        }

        // (2) The full loop machinery composes over the live CoopRuntime +
        // the real SessionLinkActions + the LwipUdpDriver: an acceptor with
        // no inbound peer and a frozen clock ticks the sync loop and returns
        // IterationLimit (no deadline fires, no final state reached). The
        // real session machinery runs on the MCU profile through a live
        // socket; the real-wire acceptor handshake e2e is Stage 5.
        {
            let port: u16 = 7451;
            let socket: SharedSessionSocket = Rc::new(RefCell::new(
                bind_session_rx(&link, port).expect("bind session rx"),
            ));
            let driver = Rc::new(LwipUdpDriver::new(socket, ipv4_addr_loopback(), port));

            let runtime = CoopRuntime::new(FrozenClock);
            let clock = CoopTime::new(&runtime);
            let driver_sink: Rc<dyn BoxedLinkDriver> = driver.clone();
            // R311ja — `R = CoopRuntime<FrozenClock>` annotated: `new_generic`
            // returns the non-injective `R::ActionsHandle<T>` (lwIP `Rc`), so
            // the `Rc<dyn _>` driver arg cannot back-infer `R`.
            let actions =
                SessionLinkActions::<CoopRuntime<FrozenClock>, CoopTime<FrozenClock>>::new_generic(
                    driver_sink,
                    test_params(),
                    clock.clone(),
                );

            let outcome = run_session(
                &runtime,
                &link,
                &driver,
                &actions,
                &clock,
                SessionDriveConfig {
                    timeouts: SessionTimeouts::spec_defaults(),
                    role: SessionRole::Acceptor,
                    max_iters: Some(32),
                },
                |_event| {},
            );
            std::assert_eq!(outcome, DriverOutcome::IterationLimit);
        }
    }

    /// R2915 — the lwIP link's half of the loop seam retargets replies to the
    /// datagram it hands over. The acceptor learns its peer from the InitSyn
    /// this way, so a link that dequeued without retargeting would answer the
    /// placeholder it was built with and no handshake would complete.
    #[test]
    fn the_lwip_session_link_retargets_replies_to_the_datagram_it_hands_over() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();

        let (session_port, speaker_port): (u16, u16) = (7454, 7455);
        let socket: SharedSessionSocket = Rc::new(RefCell::new(
            bind_session_rx(&link, session_port).expect("bind session rx"),
        ));
        // Built pointing at a placeholder, as an acceptor is.
        let driver = Rc::new(LwipUdpDriver::new(socket, ipv4_addr_loopback(), 1));
        let session_link = LwipSessionLink::new(&link, driver.clone());

        let speaker: SharedSessionSocket = Rc::new(RefCell::new(
            bind_session_rx(&link, speaker_port).expect("bind speaker"),
        ));
        let payload: &[u8] = b"InitSyn stand-in";
        speaker
            .borrow_mut()
            .send_to(ipv4_addr_loopback(), session_port, payload)
            .expect("speaker sends");

        session_link.service();
        let frame = session_link
            .try_recv()
            .expect("the datagram is handed over");
        std::assert_eq!(&frame.bytes[..], payload);
        std::assert_eq!(driver.peer(), (ipv4_addr_loopback(), speaker_port));
        std::assert!(session_link.try_recv().is_none(), "one datagram, one frame");
    }

    /// R2364 — the MCU session runs AS A TASK on the cooperative executor.
    ///
    /// This is the fact `runtime-coop`'s residual said did not exist: the
    /// session bundle is `Rc`-backed and therefore `!Send`, so
    /// `Runtime::spawn` (which requires `F: Send`) could never take it, and
    /// there was no spawn call site anywhere in the MCU session stack — the
    /// session ran as a caller-owned loop that CALLED `run_until_idle`
    /// instead of running inside it.
    ///
    /// What is asserted, in the order that makes each one load-bearing:
    ///
    /// 1. The session occupies a live slot in the executor's local pool.
    ///    A caller-driven pump can never make that count non-zero — it is
    ///    the direct witness of "hosted BY the executor".
    /// 2. It advances ONE iteration per executor pass, and only when the
    ///    executor is pumped. With `max_iters = 1` the first pass runs the
    ///    single permitted iteration and yields; the task is still
    ///    unfinished. The second pass hits the cap and completes it. A task
    ///    that ran a private loop to completion, or one that was never
    ///    scheduled at all, both fail this.
    /// 3. Its outcome is the same value the synchronous driver produces
    ///    from the same config — the two drivers share one sequence
    ///    (`SessionPump::step`), so they must agree.
    /// 4. The slot is vacated on completion.
    /// 5. A `Send` task spawned through the ordinary `Runtime::spawn` also
    ///    advances under the local set's pump, i.e. one pump call really
    ///    does drive both pools (the module contract `CoopLocalSet`
    ///    documents).
    #[test]
    fn mcu_session_runs_as_a_task_on_the_cooperative_executor() {
        use core::cell::Cell;
        use wz_runtime_coop::CoopLocalSet;
        use wz_runtime_core::Runtime;

        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let link = Rc::new(link);

        let make_session = |port: u16| {
            let socket: SharedSessionSocket = Rc::new(RefCell::new(
                bind_session_rx(&link, port).expect("bind session rx"),
            ));
            let driver = Rc::new(LwipUdpDriver::new(socket, ipv4_addr_loopback(), port));
            let runtime = CoopRuntime::new(FrozenClock);
            let clock = CoopTime::new(&runtime);
            let driver_sink: Rc<dyn BoxedLinkDriver> = driver.clone();
            let actions =
                SessionLinkActions::<CoopRuntime<FrozenClock>, CoopTime<FrozenClock>>::new_generic(
                    driver_sink,
                    test_params(),
                    clock.clone(),
                );
            (runtime, clock, driver, actions)
        };

        // The reference value: the synchronous driver, one permitted
        // iteration. Assertion 3 compares against this rather than against a
        // literal, so the two drivers are pinned to each other.
        let sync_outcome = {
            let (runtime, clock, driver, actions) = make_session(7452);
            run_session(
                &runtime,
                &link,
                &driver,
                &actions,
                &clock,
                SessionDriveConfig {
                    timeouts: SessionTimeouts::spec_defaults(),
                    role: SessionRole::Acceptor,
                    max_iters: Some(1),
                },
                |_event| {},
            )
        };

        let (runtime, clock, driver, actions) = make_session(7453);
        let local = CoopLocalSet::new(&runtime);

        // Assertion 5's probe: an ordinary `Send` task on the shared pool,
        // spawned through the unchanged `Runtime` contract.
        let send_task_ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let send_task_flag = send_task_ran.clone();
        let _send_handle = runtime.spawn(async move {
            send_task_flag.store(true, std::sync::atomic::Ordering::Release);
        });

        // The `!Send` observer: an `Rc<Cell<_>>` capture would not compile
        // under `Runtime::spawn`. It compiles here, which is the bound this
        // whole module exists to drop.
        let iterations = Rc::new(Cell::new(0usize));
        let iterations_in_task = iterations.clone();

        let handle = spawn_session(
            &local,
            link.clone(),
            driver.clone(),
            actions,
            clock,
            SessionDriveConfig {
                timeouts: SessionTimeouts::spec_defaults(),
                role: SessionRole::Acceptor,
                max_iters: Some(1),
            },
            move |_event| {
                iterations_in_task.set(iterations_in_task.get() + 1);
            },
        );

        // (1) Hosted by the executor, and (2) not yet advanced — spawning
        // queues the task, it does not run it.
        std::assert_eq!(local.live_local_task_count(), 1);
        std::assert!(!handle.is_finished());

        // (2) One pass, one iteration. The task consumed its single
        // permitted iteration and yielded back rather than running on.
        local.run_until_idle();
        std::assert_eq!(local.live_local_task_count(), 1);
        std::assert!(
            !handle.is_finished(),
            "one executor pass must advance the session exactly one \
             iteration, not run it to completion"
        );

        // (5) One pump drove the shared pool too.
        std::assert!(
            send_task_ran.load(std::sync::atomic::Ordering::Acquire),
            "CoopLocalSet::run_until_idle must drive the runtime's Send \
             pool as well as its own local tasks"
        );

        // The second pass reaches the iteration cap and the task completes.
        local.run_until_idle();
        std::assert!(handle.is_finished());

        // (3) + (4).
        let task_outcome = local
            .block_on_local(handle)
            .expect("session task completed without being aborted");
        std::assert_eq!(task_outcome, sync_outcome);
        std::assert_eq!(task_outcome, DriverOutcome::IterationLimit);
        std::assert_eq!(local.live_local_task_count(), 0);

        // The observer never fired (frozen clock, no inbound traffic), which
        // is why assertion 2 counts executor passes rather than events.
        std::assert_eq!(iterations.get(), 0);
    }

    /// ARCHITECTURE section 9.1 on the MCU profile, the two ends joined: the real
    /// session encodes a push straight into the pbuf the real lwIP driver lends,
    /// and the datagram that comes out is the one the same session makes through a
    /// driver that lends nothing. Each end is pinned alone (the session against a
    /// fake lender, the driver against hand-made frames); this is the join, where
    /// the headroom the driver grants must be the room the session's encode starts
    /// after.
    #[cfg(feature = "codec-push")]
    #[test]
    fn a_push_encoded_into_the_lent_pbuf_is_the_datagram_a_copying_driver_sends() {
        /// The same driver with the lend taken away: every default method.
        struct NoLend(Rc<LwipUdpDriver>);
        impl BoxedLinkDriver for NoLend {
            fn send_blocking(&self, bytes: &[u8], reliability: Reliability) -> LinkSendOutcome {
                self.0.send_blocking(bytes, reliability)
            }
            fn open_blocking(&self) {}
            fn close_blocking(&self) {}
        }

        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let payload: &[u8] = b"joined at both ends";

        let push_through = |driver_sink: Rc<dyn BoxedLinkDriver>| {
            let runtime = CoopRuntime::new(FrozenClock);
            let clock = CoopTime::new(&runtime);
            let actions =
                SessionLinkActions::<CoopRuntime<FrozenClock>, CoopTime<FrozenClock>>::new_generic(
                    driver_sink,
                    test_params(),
                    clock,
                );
            actions
                .send_push_literal("home/lent", payload, true)
                .expect("push");
        };
        let delivered = |driver: &LwipUdpDriver| {
            link.poll_loopback();
            link.check_timeouts();
            let mut out = vec![];
            while let Some(dg) = driver.try_recv() {
                out.push(dg.data[..].to_vec());
            }
            out
        };

        /// The real driver behind a count of which door each frame used: the
        /// datagram is the same either way, so without it a lend that quietly fell
        /// back to the copying send would pass and prove nothing about the join.
        struct Doors {
            inner: Rc<LwipUdpDriver>,
            by_slot: core::cell::Cell<usize>,
            by_bytes: core::cell::Cell<usize>,
        }
        impl BoxedLinkDriver for Doors {
            fn send_blocking(&self, bytes: &[u8], reliability: Reliability) -> LinkSendOutcome {
                self.by_bytes.set(self.by_bytes.get() + 1);
                self.inner.send_blocking(bytes, reliability)
            }
            fn open_blocking(&self) {}
            fn close_blocking(&self) {}
            fn tx_slot_acquire(
                &self,
                want: usize,
                priority: wz_session_core::qos::Priority,
            ) -> Option<wz_session_core::link::TxSlotGrant> {
                self.inner.tx_slot_acquire(want, priority)
            }
            fn tx_slot_storage(&self, slot: wz_session_core::link::TxSlot) -> (*mut u8, usize) {
                self.inner.tx_slot_storage(slot)
            }
            fn tx_slot_send(
                &self,
                slot: wz_session_core::link::TxSlot,
                start: usize,
                len: usize,
                reliability: Reliability,
                priority: wz_session_core::qos::Priority,
            ) -> LinkSendOutcome {
                self.by_slot.set(self.by_slot.get() + 1);
                self.inner
                    .tx_slot_send(slot, start, len, reliability, priority)
            }
            fn tx_slot_abort(&self, slot: wz_session_core::link::TxSlot) {
                self.inner.tx_slot_abort(slot)
            }
        }

        let lending = Rc::new(LwipUdpDriver::new(
            Rc::new(RefCell::new(
                bind_session_rx(&link, 7490).expect("bind lending"),
            )),
            ipv4_addr_loopback(),
            7490,
        ));
        let doors = Rc::new(Doors {
            inner: lending.clone(),
            by_slot: Default::default(),
            by_bytes: Default::default(),
        });
        push_through(doors.clone());
        std::assert_eq!(
            (doors.by_slot.get(), doors.by_bytes.get()),
            (1, 0),
            "the push went through the lent pbuf and not the copying send"
        );
        let lent = delivered(&lending);

        let copying = Rc::new(LwipUdpDriver::new(
            Rc::new(RefCell::new(
                bind_session_rx(&link, 7491).expect("bind copying"),
            )),
            ipv4_addr_loopback(),
            7491,
        ));
        push_through(Rc::new(NoLend(copying.clone())));
        let copied = delivered(&copying);

        std::assert_eq!(lent.len(), 1, "one push is one datagram");
        std::assert_eq!(lent, copied, "the same datagram either way");
        std::assert!(
            lent[0].windows(payload.len()).any(|w| w == payload),
            "and it carries the payload"
        );
        std::assert_eq!(
            wz_link_lwip::tx_payloads_out(),
            0,
            "nothing is left out of lwIP's hands"
        );
    }
}
