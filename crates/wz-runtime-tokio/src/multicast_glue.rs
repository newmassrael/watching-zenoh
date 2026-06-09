// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Round C — multicast transport <-> multicast-link drive loop.
//!
//! The AP host loop that drives the engine-free
//! [`MulticastDispatcher`](wz_session_core::multicast_dispatch::MulticastDispatcher)
//! (the session-fsm §3.1 session-level FSM + the §3.2 per-peer table,
//! landed in wz-session-core) against a real UDP-multicast link. This is
//! the multicast sibling of [`crate::scouting_glue`]; the same engine-free
//! split applies — the dispatcher owns the protocol FSMs + the peer-table
//! arithmetic, and this loop owns the socket IO + the clock.
//!
//! ## What the loop owns (the §3.1 Running parallel concerns)
//!
//! §3.1 describes Running as three parallel regions; the SCE surface has no
//! `<parallel>`, so (as the dispatcher's module docs record) the host loop
//! realises them:
//! - **JoinEmit** — multicasts a periodic JOIN beacon every
//!   [`MulticastParams::join_interval_ms`]. JOIN is the handshake-free
//!   transport's self-advertisement (the multicast analogue of INIT+OPEN);
//!   there is no separate keepalive, so the periodic JOIN IS the liveness
//!   beacon.
//! - **RxDispatch** — classifies each inbound datagram by its transport MID
//!   and attributes it by the datagram SOURCE ADDRESS (carried on the
//!   [`RxFrame`](wz_session_core::link::RxFrame), populated by the multicast
//!   `UdpDriver`): JOIN -> [`ingest_join`](MulticastDispatcher::ingest_join)
//!   (admit / refresh by addr, record zid); Frame / KeepAlive ->
//!   [`refresh_by_src`](MulticastDispatcher::refresh_by_src); Close ->
//!   [`close_by_src`](MulticastDispatcher::close_by_src).
//! - **PeerSweep** — evicts peers past their lease via
//!   [`MulticastDispatcher::sweep`].
//!
//! ## RX attribution: by source address (zenoh-pico parity)
//!
//! Frame / KeepAlive / Close carry NO sender zid on the wire, so — exactly
//! like zenoh-pico (`_z_find_peer_entry(addr)`) — every inbound message is
//! attributed to a peer by its datagram source address. JOIN additionally
//! carries the announcer's zid, recorded as the peer's protocol identity.
//! The `RxFrame.src` field carries the address; a non-multicast link leaves
//! it `None` and such messages are ignored here. (Delivering a Frame's
//! PAYLOAD to the application — multicast pub/sub — is a separate layer
//! above this transport attribution.)
//!
//! ## Stop
//!
//! The loop runs until the link is lost (`LinkEvent::Lost` ->
//! [`MulticastOutcome::LinkLost`]) or the test iteration budget is reached.
//! A graceful `multicast.stop` (the §3.1 Running -> Stopped event) needs a
//! shutdown signal threaded into the `select!`; that is a deferred
//! follow-up (Round C drives until link loss).

use sce_forge_runtime::codec::SceCursor;

use wz_codecs::join::Join;
use wz_codecs::wire_const;
use wz_session_core::link::{LinkEvent, LostCause, TxFrame};
use wz_session_core::multicast_dispatch::MulticastDispatcher;
use wz_session_core::multicast_params::MulticastParams;
use wz_session_core::reliability::Reliability;
use wz_session_core::session_fsm_multicast::SessionFsmMulticastState;

use wz_runtime_core::TimeSource;

use crate::LinkDriver;

/// Frame a minimal multicast JOIN datagram for `params`:
/// `[T_MID_JOIN][version][cbyte][zid][lease vle][next_sn_r vle][next_sn_be vle]`.
///
/// "Minimal" = no `sn_res` / `batch_size` resolution negotiation (the
/// `join` codec's `S`-flag optionals are absent, encoded with `s = 0`), so
/// the header carries no high flags. Richer JOIN options (resolution
/// negotiation) are a zenoh-interop follow-up; this is the self-advertising
/// beacon body. The body codec omits the MID byte, so it is prepended here
/// (mirror of [`crate::scouting_glue`]'s `scout_emit`).
pub fn encode_join(params: &MulticastParams) -> Vec<u8> {
    let zid = &params.zid;
    let mut join = Join::new();
    join.version = params.version;
    join.set_whatami(params.whatami);
    if !zid.is_empty() {
        join.set_zid_len_m1((zid.len() - 1) as u8);
        join.zid = zid.as_slice();
    }
    join.lease = params.lease_ms;
    // A fresh announcer starts both channel sequence numbers at 0; tracking
    // the live TX sequence is a data-plane follow-up (no data frames yet).
    join.next_sn_reliable = 0;
    join.next_sn_best_effort = 0;
    let body = join.encode_to_vec(0);

    let mut dgram = Vec::with_capacity(1 + body.len());
    dgram.push(wire_const::T_MID_JOIN);
    dgram.extend_from_slice(&body);
    dgram
}

/// If `bytes` is a multicast JOIN datagram, decode it and return the
/// announcer's zid (a sub-slice borrow of `bytes`). Returns `None` for a
/// non-JOIN MID or a malformed body. The returned zid is fed straight to
/// [`MulticastDispatcher::ingest_join`].
pub fn decode_join_zid(bytes: &[u8]) -> Option<&[u8]> {
    let header = *bytes.first()?;
    if header & 0x1f != wire_const::T_MID_JOIN {
        return None;
    }
    // The `join` codec gates its optional sn_res / batch_size on `s & 0x01`,
    // so project the wire S flag (header bit 6, `FLAG_T_JOIN_S` = 0x40, per
    // zenoh-pico transport.h:61) to that bit. A minimal JOIN clears S so
    // `s` is 0, but project from the named flag (not a raw shift) so a
    // future richer JOIN decodes correctly — header bit 5 is the distinct
    // `_Z_FLAG_T_JOIN_T` timestamp flag, NOT S, so a `header >> 5` shift
    // would read the wrong bit.
    let s = u8::from(header & wire_const::FLAG_T_JOIN_S != 0);
    let mut cursor = SceCursor::new(&bytes[1..]);
    match Join::decode(&mut cursor, s) {
        Ok(join) => Some(join.zid),
        Err(_) => None,
    }
}

/// Outcome of one [`drive_multicast_session`] run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MulticastOutcome {
    /// The session left Running (e.g. a pre-stopped dispatcher).
    Stopped,
    /// The multicast link was lost.
    LinkLost(LostCause),
    /// The bounded iteration budget was exhausted (test guard).
    IterationLimit,
}

/// Drive a multicast session: bring the link up, then own the §3.1 Running
/// concerns (periodic JOIN emit, RX classify -> dispatch, lease sweep)
/// until the link is lost or `max_iters` is reached.
///
/// `max_iters` bounds the select loop for tests; production passes `None`.
/// `tick_ms` is the scheduler cadence (the JOIN interval + lease are
/// spec-sourced from `params` / the dispatcher config, not duplicated
/// here). The loop owns the monotonic clock (the engine-free FSMs bind
/// `NoOpHal` and arm no timer — same split as [`crate::scouting_glue`]).
pub async fn drive_multicast_session<D, T, const MAX_PEERS: usize>(
    dispatcher: &mut MulticastDispatcher<MAX_PEERS>,
    params: &MulticastParams,
    driver: &mut D,
    clock: &T,
    max_iters: Option<usize>,
    tick_ms: u64,
) -> MulticastOutcome
where
    D: LinkDriver,
    T: TimeSource,
{
    // Idle -> LinkOpening -> Running.
    dispatcher.create();
    dispatcher.notify_link_ready();

    // Emit the first JOIN beacon immediately, then every join_interval_ms.
    let mut next_join_ms = clock.now_monotonic_ms();

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

        // JoinEmit: multicast the self-advertising JOIN beacon when due.
        let now = clock.now_monotonic_ms();
        if now >= next_join_ms {
            let dgram = encode_join(params);
            let frame = TxFrame { bytes: &dgram };
            // Best-effort: a failed multicast send is non-fatal (the next
            // cadence retries), so unlike the scout path there is no
            // tx-failed transition to drive.
            let _ = driver.send(&frame, Reliability::BestEffort).await;
            next_join_ms = now.saturating_add(params.join_interval_ms);
        }

        tokio::select! {
            event = driver.poll_event() => match event {
                LinkEvent::Rx(rx) => {
                    // RxDispatch: every multicast message is attributed by its
                    // datagram SOURCE ADDRESS (the peer key — Frame / KeepAlive
                    // / Close carry no zid on the wire). A multicast UdpDriver
                    // always carries the src; without it (a non-multicast link)
                    // nothing can be attributed, so the message is ignored.
                    if let Some(src) = rx.src {
                        let now = clock.now_monotonic_ms();
                        match rx.bytes.first().map(|h| h & 0x1f) {
                            Some(wire_const::T_MID_JOIN) => {
                                // A JOIN announces its zid; admit / refresh the
                                // peer at this address. Filter our own zid: with
                                // multicast loopback on our beacon echoes back,
                                // and a node is not its own peer.
                                if let Some(zid) = decode_join_zid(&rx.bytes) {
                                    if zid != params.zid.as_slice() {
                                        dispatcher.ingest_join(zid, src, now);
                                    }
                                }
                            }
                            Some(wire_const::T_MID_FRAME)
                            | Some(wire_const::T_MID_KEEP_ALIVE) => {
                                // Any data / liveness message refreshes the
                                // sender's lease (robustness if its JOINs are
                                // lost). Delivering the Frame PAYLOAD to the
                                // app (multicast pub/sub) is a separate layer.
                                dispatcher.refresh_by_src(src, now);
                            }
                            Some(wire_const::T_MID_CLOSE) => {
                                // Graceful departure (the Close carries no zid,
                                // so it is attributed by source address).
                                dispatcher.close_by_src(src);
                            }
                            _ => {}
                        }
                    }
                }
                LinkEvent::Lost { cause } => {
                    dispatcher.notify_link_lost();
                    return MulticastOutcome::LinkLost(cause);
                }
                LinkEvent::Ready => {}
            },
            _ = clock.sleep(tick_ms) => {
                // PeerSweep: evict peers past their lease. Swept every tick
                // (>= the §3.1 lease/3 cadence; sweeping more often only
                // sharpens eviction, and sweep is idempotent).
                dispatcher.sweep(clock.now_monotonic_ms());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::collections::VecDeque;

    use wz_session_core::link::RxFrame;
    use wz_session_core::multicast_dispatch::MulticastConfig;
    use wz_session_core::multicast_peer::MulticastPeerState;

    use crate::runtime_impl::TokioTime;

    /// A distinct peer source address (the addr-keyed peer-table primary key).
    fn src(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    fn params(zid: &[u8]) -> MulticastParams {
        MulticastParams {
            version: 0x09,
            whatami: 0x01, // PEER (wire form)
            zid: zid.to_vec(),
            lease_ms: 5_000,
            join_interval_ms: 1,
        }
    }

    /// `encode_join` frames a minimal JOIN whose MID is `T_MID_JOIN` and
    /// whose body round-trips back to the announcer zid through
    /// `decode_join_zid`.
    #[test]
    fn encode_join_round_trips_zid() {
        let zid = [0xAA, 0xBB, 0xCC, 0xDD];
        let dgram = encode_join(&params(&zid));
        assert_eq!(dgram[0], wire_const::T_MID_JOIN);
        assert_eq!(decode_join_zid(&dgram), Some(&zid[..]));
    }

    /// `decode_join_zid` rejects a datagram whose MID is not `T_MID_JOIN`.
    #[test]
    fn decode_rejects_non_join_mid() {
        // A T_MID_KEEP_ALIVE (0x04) datagram, not a JOIN.
        let dgram = [wire_const::T_MID_KEEP_ALIVE, 0x00];
        assert_eq!(decode_join_zid(&dgram), None);
        assert_eq!(decode_join_zid(&[]), None);
    }

    /// A richer JOIN with the S flag set (sn_res + batch_size present) still
    /// yields the announcer zid: the `s`-flag projection reads bit 6
    /// (`FLAG_T_JOIN_S`), so the optional fields stay aligned and the body
    /// decodes whole.
    #[test]
    fn decode_join_with_s_flag_extracts_zid() {
        use wz_codecs::join::Join;
        let zid = [0x11, 0x22, 0x33];
        let mut join = Join::new();
        join.version = 0x09;
        join.set_whatami(0x01);
        join.set_zid_len_m1((zid.len() - 1) as u8);
        join.zid = &zid;
        join.sn_res = Some(0x00);
        join.batch_size = Some(0xFFFF);
        join.lease = 5_000;
        let body = join.encode_to_vec(1); // s=1: sn_res + batch_size written
        let mut dgram = std::vec![wire_const::T_MID_JOIN | wire_const::FLAG_T_JOIN_S];
        dgram.extend_from_slice(&body);
        assert_eq!(decode_join_zid(&dgram), Some(&zid[..]));
    }

    /// A fake in-memory link driver: replays queued inbound datagrams,
    /// captures sent frames, and (once drained) parks so the loop falls to
    /// the sweep tick. Lets the async drive loop be exercised deterministically
    /// without a real multicast socket (mirrors how the scouting unit tests
    /// cover the deterministic logic; the real-socket path is Layer M).
    struct FakeDriver {
        /// Queued inbound datagrams, each with its source address (the
        /// multicast peer key).
        inbound: VecDeque<(Vec<u8>, SocketAddr)>,
        sent: Vec<Vec<u8>>,
        lost: bool,
    }

    impl FakeDriver {
        fn with(inbound: impl IntoIterator<Item = (Vec<u8>, SocketAddr)>) -> Self {
            Self {
                inbound: inbound.into_iter().collect(),
                sent: Vec::new(),
                lost: false,
            }
        }
    }

    impl LinkDriver for FakeDriver {
        async fn open(&mut self) -> std::io::Result<()> {
            Ok(())
        }
        async fn send(
            &mut self,
            frame: &TxFrame<'_>,
            _reliability: Reliability,
        ) -> std::io::Result<()> {
            self.sent.push(frame.bytes.to_vec());
            Ok(())
        }
        async fn close(&mut self) -> std::io::Result<()> {
            Ok(())
        }
        async fn poll_event(&mut self) -> LinkEvent {
            if self.lost {
                return LinkEvent::Lost {
                    cause: LostCause::PeerClosed,
                };
            }
            if let Some((dg, src)) = self.inbound.pop_front() {
                // A multicast datagram carries its source address.
                return LinkEvent::Rx(RxFrame::with_src(dg, src));
            }
            // Drained: never resolve so `select!` always takes the sweep
            // tick, advancing the loop to its iteration budget.
            core::future::pending().await
        }
    }

    /// The drive loop admits a peer from an inbound JOIN (keyed by its source
    /// address) and emits its own JOIN beacon.
    #[tokio::test]
    async fn drive_loop_admits_join_peer_and_emits_beacon() {
        let peer_b = [0x01, 0x02, 0x03, 0x04];
        let mut driver = FakeDriver::with([(encode_join(&params(&peer_b)), src(2))]);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let clock = TokioTime::new();

        let outcome = drive_multicast_session(
            &mut dispatcher,
            &params(&[0xAA, 0xBB, 0xCC, 0xDD]), // self
            &mut driver,
            &clock,
            Some(5),
            5,
        )
        .await;

        assert_eq!(outcome, MulticastOutcome::IterationLimit);
        // The inbound JOIN admitted peer B (queryable by zid and by src).
        assert_eq!(dispatcher.active_peers(), 1);
        assert_eq!(
            dispatcher.peer_state(&peer_b),
            Some(MulticastPeerState::Active)
        );
        assert_eq!(
            dispatcher.peer_state_by_src(src(2)),
            Some(MulticastPeerState::Active)
        );
        // At least one self JOIN beacon was multicast, MID-framed correctly.
        assert!(!driver.sent.is_empty(), "expected >= 1 JOIN beacon");
        assert_eq!(driver.sent[0][0], wire_const::T_MID_JOIN);
    }

    /// An inbound Close (attributed by source address) evicts the peer.
    #[tokio::test]
    async fn drive_loop_evicts_peer_on_close() {
        let peer_b = [0x01, 0x02, 0x03, 0x04];
        // First a JOIN from peer B's address admits it, then a Close from the
        // SAME address evicts it — the Close carries no zid, so it is keyed
        // by source address.
        let mut driver = FakeDriver::with([
            (encode_join(&params(&peer_b)), src(2)),
            (std::vec![wire_const::T_MID_CLOSE, 0x00], src(2)),
        ]);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let clock = TokioTime::new();

        let outcome = drive_multicast_session(
            &mut dispatcher,
            &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
            &mut driver,
            &clock,
            Some(8),
            5,
        )
        .await;

        assert_eq!(outcome, MulticastOutcome::IterationLimit);
        assert_eq!(dispatcher.active_peers(), 0, "Close must evict the peer");
    }

    /// A lost link returns `LinkLost` and clears the peer table (§3.1).
    #[tokio::test]
    async fn drive_loop_returns_link_lost() {
        let mut driver = FakeDriver {
            inbound: VecDeque::new(),
            sent: Vec::new(),
            lost: true,
        };
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let clock = TokioTime::new();

        let outcome = drive_multicast_session(
            &mut dispatcher,
            &params(&[0xAA, 0xBB, 0xCC, 0xDD]),
            &mut driver,
            &clock,
            Some(5),
            5,
        )
        .await;

        assert!(matches!(outcome, MulticastOutcome::LinkLost(_)));
        assert_eq!(
            dispatcher.session_state(),
            SessionFsmMulticastState::Stopped
        );
        assert_eq!(dispatcher.active_peers(), 0);
    }

    /// Our own JOIN echoed back by multicast loopback does NOT admit us as a
    /// peer — a node is not its own peer (own-zid filter).
    #[tokio::test]
    async fn drive_loop_filters_own_join_echo() {
        let self_zid = [0xAA, 0xBB, 0xCC, 0xDD];
        // The inbound JOIN carries OUR zid (the loopback echo of our beacon).
        let mut driver = FakeDriver::with([(encode_join(&params(&self_zid)), src(9))]);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let clock = TokioTime::new();

        let outcome = drive_multicast_session(
            &mut dispatcher,
            &params(&self_zid),
            &mut driver,
            &clock,
            Some(5),
            5,
        )
        .await;

        assert_eq!(outcome, MulticastOutcome::IterationLimit);
        assert_eq!(dispatcher.active_peers(), 0, "own JOIN must not self-admit");
    }
}
