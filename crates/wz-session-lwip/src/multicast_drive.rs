// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `run_multicast_session` — the synchronous MCU multicast drive loop.
//!
//! The MCU analog of
//! [`wz_runtime_tokio::multicast_glue::drive_multicast_session`], minus the
//! `tokio::select!`: a cooperative single-task polling loop, the same shape as
//! [`crate::session_drive::run_session`] (the unicast MCU loop) but driving the
//! engine-free [`MulticastDispatcher`] instead of the unicast FSM engine. Every
//! decision PRIMITIVE is the shared `wz_session_core` SSOT (JOIN encode /
//! decode / validate, the §3.2 peer-table arithmetic, the §2.3 per-channel SN
//! gate); this function is only the loop STRUCTURE that sequences them on the
//! lwIP profile.
//!
//! ## What it owns (the §3.1 Running parallel concerns, busy-poll form)
//!
//! - **JoinEmit** — multicasts a periodic JOIN beacon every
//!   [`MulticastParams::join_interval_ms`] (the handshake-free transport's
//!   self-advertisement; there is no separate keepalive, so the periodic JOIN
//!   IS the liveness beacon). The MCU mirror of the AP loop's JOIN arm.
//! - **RxDispatch** — classifies each inbound datagram by its transport MID and
//!   attributes it by the datagram SOURCE ADDRESS (Frame / KeepAlive / Close
//!   carry no zid on the wire, exactly like zenoh-pico `_z_find_peer_entry`):
//!   JOIN -> validate + [`MulticastDispatcher::ingest_join`]; Frame -> the
//!   per-peer SN gate + the observer fan; KeepAlive ->
//!   [`MulticastDispatcher::refresh_by_src`]; Close ->
//!   [`MulticastDispatcher::close_by_src`].
//! - **PeerSweep** — evicts peers past their advertised lease via
//!   [`MulticastDispatcher::sweep`] on the `tick_ms` cadence.
//!
//! ## Data plane (Frame -> observer)
//!
//! An inbound `T_MID_FRAME` from a live peer is decoded, admitted against that
//! peer's per-channel SN gate, and its NetworkMessage batch fanned to the
//! caller's `on_event` observer as an [`IterationEvent::Poll`] carrying a
//! [`DriverLoopOutcome::FramePayload`] — the SAME event shape the unicast
//! `run_session` loop and the AP `drive_multicast_session` loop fan, so one
//! `ApplicationLayerObserver` routes both transports' data identically.
//!
//! ## Not yet here (R311lt foundation; follow-on increments)
//!
//! - **TX publish seam** — the application-side data emit (the MCU mirror of
//!   the AP loop's `outbound` channel + `MulticastTxItem`). This foundation
//!   emits only the JOIN beacon; an app `z_put` / queryable reply / liveliness
//!   declare over the group is the next increment (the no-alloc MCU TX variant
//!   the carry deferred until the loop shaped it — now it has).
//! - **Fragment RX/TX** — the `reassembly` / `transport-fragmentation` arms the
//!   AP loop carries (R311kn / R311ko).
//! - **`MulticastOutcome::LinkLost`** — the MCU poll loop has no link-loss
//!   event (a silent group is an empty `try_recv`), so it returns only
//!   `Stopped` / `IterationLimit`.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use wz_link_lwip::rx_sockets::{SessionMulticastRxSocket, SESSION_MULTICAST_RX_SLOT_SIZE};
use wz_link_lwip::{Datagram, LwipLink};
use wz_runtime_core::TimeSource;
use wz_runtime_lwip::{ClockSource, LwipRuntime, LwipTime};
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::multicast_dispatch::MulticastDispatcher;
use wz_session_core::multicast_join::encode_join;
use wz_session_core::multicast_params::{MulticastDriveConfig, MulticastOutcome};
use wz_session_core::multicast_rx::{dispatch_multicast_inbound, MulticastRxNext};
// R311ly — the shared TX emit SSOT (the AP loop calls the same). MulticastTxItem
// is the unconditional pull-seam item type (uninhabited without a TX body
// codec); multicast_tx_emit exists only when codec-push inhabits it.
#[cfg(feature = "codec-push")]
use wz_session_core::multicast_tx::multicast_tx_emit;
use wz_session_core::multicast_tx::MulticastTxItem;
use wz_session_core::session_fsm_multicast::SessionFsmMulticastState;
use wz_session_core::sn::{self, TxSn};

/// The MCU multicast I/O seam: a [`SessionMulticastRxSocket`] (joined to the
/// group at bind) plus the group `(addr, port)` the loop multicasts to. The
/// multicast mirror of [`crate::driver::LwipUdpDriver`] (which carries the
/// retargetable unicast peer): here the destination is the fixed group, so the
/// loop owns the socket exclusively (no `Rc<RefCell>` — single-task, one
/// consumer) and `send_to_group` / `try_recv` are direct `&mut` calls.
pub struct LwipMulticastDriver {
    socket: SessionMulticastRxSocket,
    group: u32,
    port: u16,
}

impl LwipMulticastDriver {
    /// Wrap a bound multicast socket with its group destination. `group` /
    /// `port` are the locator the JOIN beacon + data frames multicast to —
    /// the same `(group, port)` passed to
    /// [`wz_link_lwip::rx_sockets::bind_session_multicast_rx`] so TX and the
    /// joined RX membership match.
    pub fn new(socket: SessionMulticastRxSocket, group: u32, port: u16) -> Self {
        Self {
            socket,
            group,
            port,
        }
    }

    /// Multicast one datagram to the group. Best-effort like the AP loop's
    /// JOIN / data emit (a failed send is non-fatal — the next cadence
    /// retries); the `LinkError` is dropped.
    pub fn send_to_group(&mut self, bytes: &[u8]) {
        let _ = self.socket.send_to(self.group, self.port, bytes);
    }

    /// Non-blocking dequeue of one inbound multicast datagram (the caller must
    /// have driven the lwIP input path via `LwipLink::poll_loopback` / netif RX
    /// first). Carries the datagram's source address for §3.2 peer
    /// attribution.
    pub fn try_recv(&mut self) -> Option<Datagram<SESSION_MULTICAST_RX_SLOT_SIZE>> {
        self.socket.try_recv()
    }
}

/// The §3.2 peer key for an inbound multicast datagram: its source address.
/// Frame / KeepAlive / Close carry no zid on the wire, so — exactly like
/// zenoh-pico `_z_find_peer_entry(addr)` — every inbound message is attributed
/// by `(src_addr, src_port)`. The `src_addr` is lwIP's network-order `u32`;
/// the exact dotted-quad interpretation is irrelevant here because the
/// [`SocketAddr`] is used only as an opaque equality key (a given peer's
/// datagrams always carry the same `src_addr`).
fn peer_key(src_addr: u32, src_port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(src_addr)), src_port)
}

/// Drive a multicast session over the lwIP link: bring the dispatcher up
/// (Idle -> Running), then own the §3.1 Running concerns (periodic JOIN emit,
/// RX classify -> dispatch + the Frame data plane, lease sweep) until the
/// session leaves Running or `cfg.max_iters` is reached.
///
/// Parameters:
/// - `dispatcher` — the engine-free [`MulticastDispatcher`] (the §3.1 session
///   FSM + the §3.2 per-peer table); `MAX_PEERS` is the bounded peer-table
///   capacity.
/// - `cfg` — the shared [`MulticastDriveConfig`] (protocol `params`, the
///   `tick_ms` sweep cadence, the test-only `max_iters` budget).
/// - `runtime` / `link` — the lwIP runtime + link pumped each tick
///   (`run_until_idle` + `poll_loopback` + `check_timeouts`), the loopback /
///   QEMU shape (a real-NIC deploy drives netif input from the RX ISR instead).
///   The loop derives its monotonic clock from `runtime` directly: unlike the
///   unicast [`run_session`](crate::session_drive::run_session) (which takes an
///   external clock so its epoch matches the R263 actions clock-clone), the
///   multicast loop has no actions bundle, so the runtime is its only time
///   source and a separate `clock` parameter would just be a redundant
///   re-derivation of `LwipTime::new(runtime)`.
/// - `driver` — the [`LwipMulticastDriver`] (group socket: JOIN/data TX +
///   inbound `try_recv`).
/// - `on_event` — the per-iteration observer (`Poll` with the decoded
///   `FramePayload` batch the application dispatches).
/// - `next_tx` — the application TX pull-seam (R311ly): each iteration the loop
///   drains pending outbound items ([`MulticastTxItem`], e.g. a `z_put` Push)
///   and frames each via the shared `multicast_tx_emit` SSOT before the pump, so
///   the datagrams ride the same `run_until_idle` as the JOIN beacon. The MCU
///   mirror of the AP loop's `outbound` mpsc receiver; the busy-poll loop pulls
///   rather than `select!`s. Without a TX body codec the item is uninhabited and
///   the seam is inert (a publish-free / RX-only node passes `|| None`).
pub fn run_multicast_session<C, F, G, const MAX_PEERS: usize>(
    dispatcher: &mut MulticastDispatcher<MAX_PEERS>,
    cfg: MulticastDriveConfig<'_>,
    runtime: &LwipRuntime<C>,
    link: &LwipLink,
    driver: &mut LwipMulticastDriver,
    mut on_event: F,
    mut next_tx: G,
) -> MulticastOutcome
where
    C: ClockSource,
    F: FnMut(IterationEvent<'_>),
    G: FnMut() -> Option<MulticastTxItem>,
{
    // Destructure into the same local names the body uses (the shared
    // parameter-object SSOT; R311ls/R311lt).
    let MulticastDriveConfig {
        params,
        tick_ms,
        max_iters,
    } = cfg;

    // The loop's monotonic clock, derived from the runtime it pumps (R311ly):
    // the dispatcher's stamps all come from this one source, so there is no
    // external epoch to match (contrast the unicast run_session's R263 clock).
    let clock = LwipTime::new(runtime);

    // Idle -> LinkOpening -> Running.
    dispatcher.create();
    dispatcher.notify_link_ready();

    // The TX mint state (per-channel next SN). The JOIN beacon advertises the
    // live values (an immutable borrow); the codec-push TX drain mints from here
    // per data frame, so the binding is `mut` only when that path compiles.
    #[cfg(feature = "codec-push")]
    let mut tx_sn = TxSn::new(sn::mask_from_res(params.seq_num_res));
    #[cfg(not(feature = "codec-push"))]
    let tx_sn = TxSn::new(sn::mask_from_res(params.seq_num_res));
    // Emit the first JOIN beacon immediately, then every join_interval_ms; the
    // sweep runs on its own tick_ms cadence (the busy-poll equivalents of the
    // AP loop's JOIN-due check + select! sweep tick).
    let mut next_join_ms = clock.now_monotonic_ms();
    let mut next_sweep_ms = clock.now_monotonic_ms();
    let mut iter: usize = 0;

    loop {
        if dispatcher.session_state() != SessionFsmMulticastState::Running {
            return MulticastOutcome::Stopped;
        }
        if let Some(limit) = max_iters {
            if iter >= limit {
                return MulticastOutcome::IterationLimit;
            }
            iter += 1;
        }

        let now = clock.now_monotonic_ms();
        // JoinEmit: multicast the self-advertising JOIN beacon when due.
        if now >= next_join_ms {
            let dgram = encode_join(params, &tx_sn);
            driver.send_to_group(&dgram);
            next_join_ms = now.saturating_add(params.join_interval_ms);
        }

        // TxData: drain the application's pending outbound items, framing each
        // through the shared multicast_tx_emit SSOT (the same the AP loop calls)
        // and multicasting it to the group. Drained right after the JOIN beacon
        // so the datagrams ride THIS iteration's run_until_idle. send_to_group is
        // best-effort (multicast UDP); the SSOT's per-variant reliability flag is
        // inert here (the MCU group socket takes no reliability arg).
        #[cfg(feature = "codec-push")]
        while let Some(item) = next_tx() {
            for dgram in multicast_tx_emit(item, &mut tx_sn, params).datagrams {
                driver.send_to_group(&dgram);
            }
        }
        // No TX body codec: MulticastTxItem is uninhabited, so next_tx can only
        // yield None; call it to keep the seam used (it stays in the signature for
        // the RX-only build) and consume the unconstructable item type-correctly.
        #[cfg(not(feature = "codec-push"))]
        if let Some(item) = next_tx() {
            match item {}
        }

        // Drive the lwIP input path (loopback / QEMU shape) + the runtime task
        // pool + deadline-keyed timers. Real-NIC deploys drive netif input from
        // the RX ISR instead of poll_loopback.
        link.poll_loopback();
        link.check_timeouts();
        runtime.run_until_idle();

        // Inbound datagram? Classify + dispatch, then loop promptly for the
        // next (the busy-poll equivalent of the AP loop's RX select arm).
        if let Some(dg) = driver.try_recv() {
            let src = peer_key(dg.src_addr, dg.src_port);
            let bytes = dg.data.as_slice();
            // R311lv — the shared RxDispatch SSOT (JOIN admit / Frame
            // admit-and-fan / KeepAlive refresh) — the same `wz_session_core`
            // primitive the AP loop drives, so the §3.1 classify lives in one
            // home. This foundation owns no reassembly Router, so the
            // out-of-order-chain + Fragment tails are dropped (a fragment is
            // dropped exactly as pico does with fragmentation off; both arrive
            // with the MCU reassembly increment); Close is the only tail it
            // acts on.
            match dispatch_multicast_inbound(dispatcher, params, bytes, src, now, &mut on_event) {
                MulticastRxNext::Done
                | MulticastRxNext::FrameOutOfOrder { .. }
                | MulticastRxNext::Fragment => {}
                MulticastRxNext::Close => {
                    dispatcher.close_by_src(src);
                }
            }
            continue;
        }

        // PeerSweep: evict peers past their advertised lease on the tick_ms
        // cadence (idempotent; sweeping more often only sharpens eviction).
        if now >= next_sweep_ms {
            dispatcher.sweep(now);
            next_sweep_ms = now.saturating_add(tick_ms);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_link_lwip::lwip_test_link;
    use wz_link_lwip::rx_sockets::{bind_session_multicast_rx, SESSION_MULTICAST_GROUP_DEFAULT};
    use wz_session_core::multicast_dispatch::MulticastConfig;
    use wz_session_core::multicast_params::MulticastParams;

    /// Frozen host clock — `now_us` is constant, so no JOIN-interval / lease
    /// deadline ever advances past a peer's admit time. Keeps the drive-loop
    /// integration test deterministic (terminates on max_iters; the admitted
    /// peer is never swept), the same shape as session_drive's `FrozenClock`.
    #[derive(Clone, Default)]
    struct FrozenClock;
    impl ClockSource for FrozenClock {
        fn now_us(&self) -> u64 {
            0
        }
    }

    /// A multicast params fixture (the AP multicast_glue test's shape): a peer
    /// JOIN built with one `zid` is admitted by a loop running another.
    fn params(zid: &[u8]) -> MulticastParams {
        MulticastParams {
            version: 0x09,
            whatami: 0x01, // PEER (wire form)
            zid: zid.to_vec(),
            lease_ms: 5_000,
            join_interval_ms: 1,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size: 2_048,
        }
    }

    /// The §3.2 peer key is a stable, collision-free function of the datagram
    /// source: equal `(src_addr, src_port)` -> equal key (so a peer's
    /// successive datagrams attribute to one entry); a differing addr OR port
    /// -> a distinct key (so two peers never alias). lwIP-free (pure
    /// arithmetic), so it runs without the init-once link harness.
    #[test]
    fn peer_key_is_a_stable_collision_free_source_key() {
        let a = peer_key(0x7F00_0001, 7446);
        std::assert_eq!(a, peer_key(0x7F00_0001, 7446), "same source -> same key");
        std::assert_ne!(a, peer_key(0x7F00_0002, 7446), "differing addr -> distinct");
        std::assert_ne!(a, peer_key(0x7F00_0001, 7447), "differing port -> distinct");
    }

    /// R311lu — the drive loop end-to-end over a real lwIP multicast socket: a
    /// peer's JOIN (a zid distinct from ours), injected onto the group, is
    /// delivered by `poll_loopback` to the loop's `try_recv`, classified as
    /// `T_MID_JOIN`, validated, and admitted into the dispatcher's peer table —
    /// while our own JOIN beacon echoes back and is own-zid-filtered. Shares
    /// the `lwip_test_link` init-once harness with `session_drive`'s test (one
    /// `lwip_init` per binary). A distinct port (7449) from the scout (7446) /
    /// unicast (7447) / link-tier multicast (7448) tests; the harness mutex
    /// serialises the lwIP group membership.
    #[test]
    fn run_multicast_session_admits_a_peer_over_loopback() {
        let (_serial, link) = lwip_test_link();
        let group = SESSION_MULTICAST_GROUP_DEFAULT;
        let port: u16 = 7449;
        let mut socket = bind_session_multicast_rx(&link, group, port).expect("bind + join group");

        // Inject a PEER's JOIN (distinct zid) onto the group BEFORE wrapping
        // the socket in the driver — it queues in lwIP, and the loop's first
        // poll_loopback delivers it to try_recv ahead of our own beacon echo.
        let peer = params(&[0x01, 0x02, 0x03, 0x04]);
        let peer_join = encode_join(&peer, &TxSn::new(sn::mask_from_res(peer.seq_num_res)));
        socket
            .send_to(group, port, &peer_join)
            .expect("inject peer JOIN");

        let mut driver = LwipMulticastDriver::new(socket, group, port);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let runtime = LwipRuntime::new(FrozenClock);
        let self_params = params(&[0xAA, 0xBB, 0xCC, 0xDD]);

        let outcome = run_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &self_params,
                tick_ms: 5,
                max_iters: Some(12),
            },
            &runtime,
            &link,
            &mut driver,
            |_event| {},
            // RX-only: no application TX. Under the no-codec C1m build the item
            // is uninhabited, so this is the only well-typed seam value.
            || None,
        );

        std::assert_eq!(outcome, MulticastOutcome::IterationLimit);
        std::assert_eq!(
            dispatcher.active_peers(),
            1,
            "the inbound JOIN admitted the peer (our own beacon is zid-filtered)"
        );

        link.leave_multicast_group(group).expect("leave group");
    }

    /// R311ly — the multicast TX seam end-to-end over real lwIP: a `z_put` Push
    /// queued on the loop's `next_tx` pull-seam is framed by the shared
    /// `multicast_tx_emit` SSOT, multicast to the group, and (via multicast
    /// loopback) delivered back to the loop's own socket. To OBSERVE it as an
    /// admitted data frame we pre-admit a peer at our own loopback source: a JOIN
    /// with a DISTINCT zid (so it is not own-zid-filtered), injected from our
    /// socket, creates a peer entry keyed by (src_addr, src_port); the echoed
    /// Push Frame (zid-less, attributed by source) then matches that entry,
    /// passes the SN gate (SN 0 against the JOIN's advertised next_sn 0), and
    /// fans to `on_event`. Shares the lwip_test_link harness; a distinct port
    /// (7452) from the peer-admit (7449) / link-tier (7448) tests.
    #[cfg(feature = "codec-push")]
    #[test]
    fn run_multicast_session_publishes_a_put_over_loopback() {
        use wz_session_core::driver_loop::DriverLoopOutcome;
        use wz_session_core::multicast_tx::multicast_put_literal;
        use wz_session_core::network_message::NetworkMessage;

        let (_serial, link) = lwip_test_link();
        let group = SESSION_MULTICAST_GROUP_DEFAULT;
        let port: u16 = 7452;
        let mut socket = bind_session_multicast_rx(&link, group, port).expect("bind + join group");

        // Pre-admit a peer at OUR loopback source: a JOIN with a zid distinct
        // from ours (so it is admitted, not own-zid-filtered) advertising
        // next_sn 0 on a fresh ring. Injected before wrapping the socket so the
        // loop's first poll delivers it ahead of our own beacon / Push echo,
        // creating the (src_addr, src_port) peer entry the echoed Push matches.
        let other = params(&[0x01, 0x02, 0x03, 0x04]);
        let other_join = encode_join(&other, &TxSn::new(sn::mask_from_res(other.seq_num_res)));
        socket
            .send_to(group, port, &other_join)
            .expect("inject peer JOIN");

        let mut driver = LwipMulticastDriver::new(socket, group, port);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let runtime = LwipRuntime::new(FrozenClock);
        let self_params = params(&[0xAA, 0xBB, 0xCC, 0xDD]);

        // One queued Put on the reliable channel (pico Z_RELIABILITY_DEFAULT);
        // the pull-seam yields it once, then None (the loop keeps serving RX +
        // JOIN). Frozen clock + bounded max_iters keep the round trip
        // deterministic (no-flaky).
        let mut pending = Some(multicast_put_literal("demo/mc", b"tx-half").expect("build put"));

        let mut saw_push = false;
        let outcome = run_multicast_session(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &self_params,
                tick_ms: 5,
                max_iters: Some(16),
            },
            &runtime,
            &link,
            &mut driver,
            |event| {
                if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) =
                    event
                {
                    if messages
                        .iter()
                        .any(|m| matches!(m, NetworkMessage::Push(_)))
                    {
                        saw_push = true;
                    }
                }
            },
            || pending.take(),
        );

        std::assert_eq!(outcome, MulticastOutcome::IterationLimit);
        std::assert!(
            saw_push,
            "the queued Put was framed by multicast_tx_emit, multicast to the \
             group, echoed back, admitted at our source, and observed as a Push"
        );

        link.leave_multicast_group(group).expect("leave group");
    }
}
