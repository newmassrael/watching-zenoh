// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Stage 3 — runtime-agnostic drive-loop dispatch core.
//!
//! `dispatch_link_event` is the synchronous body of
//! `wz-runtime-tokio::poll_and_dispatch_one` lifted out of the AP shell: it
//! takes an already-polled `LinkEvent` (the one `.await` — `driver.poll_event()`
//! — stays in the tokio async wrapper) and drives the engine-free session FSM,
//! returning the typed `DriverLoopOutcome`. Generic over `R: SessionRuntime` /
//! `T: TimeSource` so the lwIP MCU sync loop (Stage 4) dispatches through the
//! same SSOT the tokio loop does.
//!
//! `report_outcome_reassembling` drives the const-generic reassembly pool on a
//! `Fragment` outcome and re-enters `parse_frame_payload` on chain completion;
//! generic over the pool dims + runtime so the AP (32/65536) and MCU (4/4096)
//! profiles share one ingest path. The peer ZID (the §2.3 chain key) is read
//! from `actions.inbound_peer_zid` through `R::with_mutex_mut` (the AP
//! `std::sync::Mutex` and the MCU `critical_section` mutex behind one seam).

use sce_rust_runtime::Engine;

use wz_runtime_core::TimeSource;

use crate::driver_loop::DriverLoopOutcome;
use crate::inbound::inbound_to_fsm_event;
use crate::lease::LeaseCheckOutcome;
use crate::link::{LinkEvent, SessionRuntime};
// `InboundParseError` is named only as `::Codec(..)` in the codec-frame `Frame`
// arm (and the reassembly re-parse, which implies codec-frame); the `Err(err)`
// arm passes the value without naming the type.
#[cfg(feature = "codec-frame")]
use crate::parse_error::InboundParseError;
use crate::session_actions::{SessionActionsBinding, SessionLinkActions};
use crate::session_fsm_unicast::SessionFsmUnicastPolicy;
// `InboundFrame` is named by the ungated `Unknown` match arm; the codec-gated
// arms (`Frame` / `KeepAlive` / `Fragment` / `Init` / `Open` / `Close`) reuse it.
use crate::inbound::InboundFrame;
// parse_frame_payload backs the codec-frame `Frame` arm only.
#[cfg(feature = "codec-frame")]
use crate::network_message::parse_frame_payload;

/// Drive one already-polled `LinkEvent` through the inbound chain so the
/// engine-free session FSM advances. The synchronous core of
/// `wz-runtime-tokio::poll_and_dispatch_one` (whose sole `.await` —
/// `driver.poll_event()` — stays in the tokio async wrapper). Generic over the
/// runtime so the lwIP MCU loop dispatches through the same SSOT.
pub fn dispatch_link_event<R: SessionRuntime, T: TimeSource>(
    event: LinkEvent,
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
) -> DriverLoopOutcome {
    use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
    match event {
        LinkEvent::Ready => {
            engine.process_event(E::LinkOpened);
            DriverLoopOutcome::AdvancedFsm
        }
        LinkEvent::Lost { cause } => {
            engine.process_event(E::LinkLost);
            DriverLoopOutcome::LinkLost(cause)
        }
        LinkEvent::Rx(rx) => match actions.handle_inbound(&rx.bytes) {
            Ok(frame) => match inbound_to_fsm_event(&frame) {
                Some(event) => {
                    // R311il — §2.7 dispatcher admission pre-classify. The
                    // accept-side caps (half-open + token bucket on
                    // init_syn; cookie HMAC on open_syn) depend on HOST
                    // state, not on the triggering frame's wire payload, so
                    // the engine-free FSM carries no `cond=` for them — the
                    // dispatcher evaluates admission and injects the event
                    // only when it passes. Denial drops silently: no Close
                    // frame, no FSM advance (anti-amplification per the §2.7
                    // trust-class matrix). Engine-free successor of the
                    // retired Lua `cond="cookie_valid()"` transition guard.
                    let admit = match event {
                        E::InitSynReceived => {
                            actions.half_open_cap_available() && actions.accept_rate_token()
                        }
                        E::OpenSynReceived => actions.cookie_valid(),
                        _ => true,
                    };
                    if !admit {
                        return DriverLoopOutcome::SideEffectOnly;
                    }
                    engine.process_event(event);
                    DriverLoopOutcome::AdvancedFsm
                }
                None => match frame {
                    #[cfg(feature = "codec-frame")]
                    InboundFrame::Frame {
                        reliable,
                        sn,
                        payload,
                        has_ext,
                        extensions,
                    } => match parse_frame_payload(&payload) {
                        Ok(messages) => DriverLoopOutcome::FramePayload {
                            reliable,
                            sn,
                            messages,
                            has_ext,
                            extensions,
                        },
                        Err(codec_err) => {
                            engine.process_event(E::FramingError);
                            DriverLoopOutcome::ParseError(InboundParseError::Codec(codec_err))
                        }
                    },
                    #[cfg(feature = "codec-keep-alive")]
                    InboundFrame::KeepAlive { .. } => DriverLoopOutcome::SideEffectOnly,
                    // R311im — surface the decoded fragment to the drive
                    // loop, which owns the stateful ReassemblyDispatcher +
                    // clock. This pure helper cannot reassemble (no slot
                    // pool, no `now_ms`), so it hands the fragment up.
                    #[cfg(feature = "reassembly")]
                    InboundFrame::Fragment {
                        reliable,
                        sn,
                        more,
                        payload,
                        has_ext,
                        extensions,
                    } => DriverLoopOutcome::Fragment {
                        reliable,
                        sn,
                        more,
                        payload,
                        has_ext,
                        extensions,
                    },
                    #[cfg(feature = "codec-init-body")]
                    InboundFrame::Init { .. } => {
                        unreachable!("inbound_to_fsm_event None branch is Frame/KeepAlive only")
                    }
                    #[cfg(feature = "codec-open-body")]
                    InboundFrame::Open { .. } => {
                        unreachable!("inbound_to_fsm_event None branch is Frame/KeepAlive only")
                    }
                    #[cfg(feature = "codec-close")]
                    InboundFrame::Close { .. } => {
                        unreachable!("inbound_to_fsm_event None branch is Frame/KeepAlive only")
                    }
                    InboundFrame::Unknown { .. } => {
                        // inbound_to_fsm_event projects these to Some(event),
                        // so the outer Some arm handled them — this branch
                        // is unreachable.
                        unreachable!("inbound_to_fsm_event None branch is Frame/KeepAlive only")
                    }
                },
            },
            Err(err) => {
                engine.process_event(E::FramingError);
                DriverLoopOutcome::ParseError(err)
            }
        },
    }
}

/// R77/R84 — compare the session's lease baseline against `params.lease` and
/// inject `SessionFsmUnicastEvent::LeaseExpired` when the window has elapsed,
/// so the session-fsm `lease.expired -> Closing(Expired)` transition fires.
/// Generic over `R: SessionRuntime` so the AP tokio loop and the lwIP MCU sync
/// loop share one lease comparator (Stage 4 SSOT). The two baseline stamps are
/// read through `R::with_mutex_mut` — the AP `std::sync::Mutex` and the MCU
/// `critical_section` mutex behind one seam; the reads are SEQUENTIAL, never
/// nested, so the non-reentrant MCU mutex is safe.
///
/// Baseline (R84) = `max(established_at, last_inbound_keepalive_at)`: the
/// KeepAlive stamp resets the window per peer ping, the established stamp covers
/// the pre-first-KeepAlive window so the lease has a defined start at Established
/// entry (session-fsm §2.5). Both `None` -> `NoBaseline` (no FSM mutation).
///
/// `now_ms` is parameterised for test determinism; production callers pass
/// `clock.now_monotonic_ms()` (the same epoch [`SessionLinkActions::clock`]
/// carries). `params.lease_in_seconds` selects the unit per the `_Z_FLAG_T_OPEN_T`
/// wire semantics; seconds are scaled to ms before the `>=` so the arithmetic
/// stays on the `u64` ms scale of the stamps (R294).
pub fn check_lease_deadline<R: SessionRuntime, T: TimeSource>(
    actions: &SessionLinkActions<R, T>,
    engine: &mut Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>>,
    now_ms: u64,
) -> LeaseCheckOutcome {
    use crate::session_fsm_unicast::SessionFsmUnicastEvent as E;
    let lease_ms = if actions.params.lease_in_seconds {
        actions.params.lease.saturating_mul(1000)
    } else {
        actions.params.lease
    };
    let keepalive = R::with_mutex_mut(&actions.last_inbound_keepalive_at, |g| *g);
    let established = R::with_mutex_mut(&actions.established_at, |g| *g);
    let baseline = match (established, keepalive) {
        (None, None) => None,
        (Some(e), None) => Some(e),
        (None, Some(k)) => Some(k),
        (Some(e), Some(k)) => Some(e.max(k)),
    };
    match baseline {
        None => LeaseCheckOutcome::NoBaseline,
        Some(stamp_ms) if now_ms.saturating_sub(stamp_ms) >= lease_ms => {
            engine.process_event(E::LeaseExpired);
            LeaseCheckOutcome::Expired
        }
        Some(_) => LeaseCheckOutcome::WithinLease,
    }
}

/// Build a session [`Engine`] over the generated engine-free
/// [`SessionFsmUnicastPolicy`], parameterised over a [`SessionActionsBinding`]
/// wrapping a clone of `actions`. Generic over `R: SessionRuntime` so the AP
/// tokio loop and the lwIP MCU sync loop construct the FSM engine the same way
/// (Stage 4b SSOT — wz-runtime-tokio's `new_session_engine<T>` delegates here).
/// The caller retains `actions` (to read trace / observe link state) and drives
/// the returned engine with `dispatch_link_event` / `check_lease_deadline`.
pub fn new_session_engine<R: SessionRuntime, T: TimeSource>(
    actions: &R::ActionsHandle<T>,
) -> Engine<SessionFsmUnicastPolicy<SessionActionsBinding<R, T>>> {
    // `SessionActionsBinding.inner` is private to this crate; construct through
    // the pub `::new` constructor (mirrors the AP `new_session_engine`).
    let binding = SessionActionsBinding::new(actions.clone());
    Engine::new(SessionFsmUnicastPolicy::new(binding))
}

// ── reassembly-pool drive (reassembly-gated; `reassembly` implies `codec-frame`,
//    so `parse_frame_payload` above is in scope here too) ──
#[cfg(feature = "reassembly")]
use crate::driver_loop::{IterationEvent, ReassemblyDropReason};
#[cfg(feature = "reassembly")]
use crate::reassembly_dispatch::{
    AbortReason, Fragment as ReassemblyFragment, IngestOutcome, ReassemblyDispatcher, RefuseReason,
};
#[cfg(feature = "reassembly")]
use alloc::vec::Vec;

/// Report one driver-loop outcome, additionally driving the reassembly pool
/// when the outcome is a `Fragment`. On chain completion the reassembled bytes
/// re-enter `parse_frame_payload`, so the application's per-MID dispatch sees a
/// reassembled message exactly as it sees a `T_MID_FRAME` payload; the
/// resulting `FramePayload` (or `ParseError`) is reported as a second
/// `IterationEvent::Poll`. Non-terminal ingests (Begun / Continued / Aborted /
/// Refused) report only the `Fragment` outcome. The peer ZID (the §2.3 chain
/// key) is read from `actions.inbound_peer_zid` through `R::with_mutex_mut`.
///
/// Generic over the pool dims (`SLOTS` / `CAP`) so the AP (32 / 65536) and MCU
/// (4 / 4096) profiles share one ingest path; the AP host passes its
/// `TokioReassembly`, the MCU loop its `LwipReassembly`.
#[cfg(feature = "reassembly")]
pub fn report_outcome_reassembling<R, T, const SLOTS: usize, const CAP: usize, F>(
    outcome: &DriverLoopOutcome,
    reasm: &mut ReassemblyDispatcher<SLOTS, CAP>,
    actions: &SessionLinkActions<R, T>,
    now_ms: u64,
    on_event: &mut F,
) where
    R: SessionRuntime,
    T: TimeSource,
    F: FnMut(IterationEvent<'_>),
{
    on_event(IterationEvent::Poll(outcome));
    let DriverLoopOutcome::Fragment {
        reliable,
        sn,
        more,
        payload,
        ..
    } = outcome
    else {
        return;
    };
    // The negotiated SN ring mask resolves BEFORE the peer-ZID guard:
    // `negotiated_sn_mask` takes the `inbound_peer_init_caps` mutex, and the
    // guard below documents that nothing inside it re-enters a session mutex
    // slot — hoisting keeps the two scopes disjoint instead of weakening
    // that invariant to "only disjoint slots nest".
    let sn_mask = actions.negotiated_sn_mask();
    // The peer ZID guard must wrap the whole `ingest` call: the completion
    // closure borrows `zid` for the chain-key lookup. `with_mutex_mut` scopes
    // that borrow to the closure (the AP std mutex and the MCU critical_section
    // mutex behind one seam); the non-reentrant MCU mutex is safe because
    // `ingest` does not re-enter the session's mutex slots.
    let mut completed: Option<DriverLoopOutcome> = None;
    let ingest_outcome = R::with_mutex_mut(&actions.inbound_peer_zid, |zid_slot| {
        let zid: &[u8] = zid_slot.as_deref().unwrap_or(&[]);
        reasm.ingest(
            ReassemblyFragment {
                zid,
                reliable: *reliable,
                sn: *sn,
                more: u8::from(*more),
                payload: payload.as_slice(),
            },
            sn_mask,
            now_ms,
            |msg| {
                completed = Some(match parse_frame_payload(msg) {
                    Ok(messages) => DriverLoopOutcome::FramePayload {
                        reliable: *reliable,
                        sn: *sn,
                        messages,
                        // The reassembled bytes are the inner NetworkMessage
                        // batch; transport ext chains were per-fragment, so the
                        // reassembled message carries none.
                        has_ext: false,
                        extensions: Vec::new(),
                    },
                    Err(codec_err) => {
                        DriverLoopOutcome::ParseError(InboundParseError::Codec(codec_err))
                    }
                });
            },
        )
    });
    if let Some(o) = completed {
        on_event(IterationEvent::Poll(&o));
    }
    // A terminal non-completion ingest — an out-of-order / capacity-overflow
    // Abort, or a per-peer-quota / pool-exhaustion Refusal — is otherwise
    // silent. Surface it (mapped to the feature-independent observer reason)
    // so the application can observe a malformed or abusive fragment stream
    // (the drop counterpart of the FramePayload completion).
    let drop_reason = match ingest_outcome {
        IngestOutcome::Aborted(AbortReason::OutOfOrder) => Some(ReassemblyDropReason::OutOfOrder),
        IngestOutcome::Aborted(AbortReason::CapacityOverflow) => {
            Some(ReassemblyDropReason::CapacityOverflow)
        }
        IngestOutcome::Refused(RefuseReason::PeerQuota) => Some(ReassemblyDropReason::PeerQuota),
        IngestOutcome::Refused(RefuseReason::PoolExhausted) => {
            Some(ReassemblyDropReason::PoolExhausted)
        }
        IngestOutcome::Begun | IngestOutcome::Continued | IngestOutcome::Reassembled => None,
    };
    if let Some(reason) = drop_reason {
        on_event(IterationEvent::ReassemblyDropped(reason));
    }
}

/// Run one reassembly deadline sweep and report the eviction count.
///
/// The shared SSOT both drive loops call once per iteration in place of a
/// bare [`ReassemblyDispatcher::sweep`]: it aborts + reclaims every chain
/// whose `reassembly_timeout_ms` deadline has elapsed at `now_ms`, then — if
/// any chain timed out — raises a single [`IterationEvent::ReassemblyTimeout`]
/// carrying the count so the observer sees the eviction (the sweep itself is
/// otherwise silent). A zero-eviction sweep reports nothing, so the steady
/// state stays event-free.
///
/// Generic over the pool dims so the AP (32 / 65536) and MCU (4 / 4096)
/// profiles share one path, exactly as [`report_outcome_reassembling`] does
/// for the ingest side.
#[cfg(feature = "reassembly")]
pub fn sweep_reporting<const SLOTS: usize, const CAP: usize, F>(
    reasm: &mut ReassemblyDispatcher<SLOTS, CAP>,
    now_ms: u64,
    on_event: &mut F,
) where
    F: FnMut(IterationEvent<'_>),
{
    let timed_out = reasm.sweep(now_ms);
    if timed_out > 0 {
        on_event(IterationEvent::ReassemblyTimeout(timed_out));
    }
}
