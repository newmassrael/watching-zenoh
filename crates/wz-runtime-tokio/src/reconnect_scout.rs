// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2376 (open-debt item 15, `session-reconnect`) — the RE-SCOUTING reopen
//! plan: the `ReconnectTargets` implementation for a client that was never
//! given an endpoint.
//!
//! # What was missing, and where
//!
//! pico's reopen task does not re-dial an address. It re-enters `_z_open`
//! against the retained config (`vendor/zenoh-pico/src/net/session.c`), and
//! that function has two branches: with configured locators it opens
//! `locators[0]`, and with none it calls `_z_locators_by_scout` — which scouts,
//! takes the FIRST Hello, and copies ALL of that Hello's locators — then loops
//! them "until we successfully open one".
//!
//! wz reached the same first session by a different route and then diverged.
//! `--scout` resolved ONE locator out of a Hello and handed it to the
//! supervisor as though the operator had typed it, so `--scout --reconnect`
//! (both shipped, both reachable in the demo binary) re-dialed that one address
//! for the rest of the process. A peer that came back at a different address —
//! the ordinary case for a restarted node on DHCP, and the entire reason
//! discovery exists — was never found again, because nothing scouted twice.
//!
//! # Why the actions are rebuilt every cycle
//!
//! `ScoutingActions::scouted_hellos` is an ACCUMULATOR: `record_hello_and_emit`
//! pushes and nothing clears it, which is right for a survey (the demo's
//! `--scout` reports every responder it saw across its budget) and wrong here.
//! Reusing one binding would let a Hello from the window BEFORE the outage
//! answer the window after it — the supervisor would dial the dead peer's old
//! address forever and report success at doing so, which is the defect this
//! module exists to remove, reintroduced one layer up. A fresh binding per
//! cycle is also what pico does: `_z_scout_inner` allocates its hello list per
//! call and frees it at the end of `_z_locators_by_scout`.
//!
//! The SOCKET is not rebuilt. The group membership is the expensive, failable
//! half (a join can fail on a multi-homed host), and it is exactly the half
//! that does not go stale.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use wz_session_core::reconnect::ReconnectLocator;

use crate::reconnect::ReconnectTargets;
use crate::runtime_impl::TokioTime;
use crate::scouting_glue::{
    drive_scouting_until_resolved, new_scouting_engine, ScoutOutcome, ScoutParams, ScoutingActions,
};
use crate::session_open::plan_endpoint;
use crate::UdpDriver;

/// The re-scouting reopen plan: one active-scouting cycle per reopen attempt,
/// yielding the locators the answering Hello advertised.
///
/// Holds the bound multicast socket for the supervisor's lifetime and rebuilds
/// the scouting FSM per cycle — see the module doc for why that split is the
/// load-bearing part.
pub struct ScoutedGroup {
    /// The joined scouting socket. `tokio`'s mutex rather than `std`'s because
    /// the guard is held across the `await` that drives the cycle.
    driver: tokio::sync::Mutex<UdpDriver>,
    /// The Scout this plan re-emits. Cloned into a fresh [`ScoutingActions`]
    /// each cycle, so the identity a reconnect announces is the one the first
    /// open announced (a responder logging the scouter sees one zid).
    params: ScoutParams,
    clock: TokioTime,
    tick_interval_ms: u64,
    /// Bounded only by tests; production passes `None` and lets the scouting
    /// window terminate the cycle.
    max_iters: Option<usize>,
    /// The group this plan scouts, for [`ReconnectTargets::describe`].
    label: String,
}

impl ScoutedGroup {
    /// Retain `driver` (a socket already joined to the scouting group) as the
    /// re-scouting plan for a reconnect supervisor.
    ///
    /// `params.exit_on_first` is FORCED on rather than trusted from the caller,
    /// and pico is why: `_z_locators_by_scout` passes `true` to
    /// `_z_scout_inner`, so the reopen path takes the first responder and does
    /// not survey. A caller that handed a survey binding here would get a plan
    /// whose every attempt waits out the full window even when a peer answered
    /// immediately — a reconnect latency regression with no visible cause.
    pub fn new(
        driver: UdpDriver,
        mut params: ScoutParams,
        clock: TokioTime,
        tick_interval_ms: u64,
        label: impl Into<String>,
    ) -> Self {
        params.exit_on_first = true;
        Self {
            driver: tokio::sync::Mutex::new(driver),
            params,
            clock,
            tick_interval_ms,
            max_iters: None,
            label: label.into(),
        }
    }

    /// Bound the cycle's iteration count — the test guard. Production leaves it
    /// `None`, exactly as the demo's own scouting loop does.
    pub fn with_max_iters(mut self, max_iters: Option<usize>) -> Self {
        self.max_iters = max_iters;
        self
    }

    /// Narrow one Hello's advertised locator strings to the reconnectable
    /// subset, preserving WIRE ORDER — pico's `_z_string_svec_copy` keeps the
    /// Hello's order and its open loop walks it front to back, so the peer's
    /// own preference is what decides which address is tried first.
    ///
    /// A locator this build cannot reconnect (a `serial/...` arm) is DROPPED
    /// rather than surfaced as an error: the Hello is the peer's advertisement
    /// of everything it listens on, and one unusable entry among several is not
    /// a failed scout. Dropping every entry leaves an empty list, which the
    /// supervisor already reads as "nobody usable answered" and retries.
    fn reconnectable(locators: &[String]) -> Vec<ReconnectLocator> {
        locators
            .iter()
            .filter_map(|raw| ReconnectLocator::try_from(plan_endpoint(raw).ok()?).ok())
            .collect()
    }
}

impl ReconnectTargets for ScoutedGroup {
    fn candidates<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Vec<ReconnectLocator>> + Send + 'a>> {
        Box::pin(async move {
            // Fresh binding per cycle — the accumulator trap in the module doc.
            let actions = Arc::new(ScoutingActions::new(self.params.clone()));
            let mut engine = new_scouting_engine(&actions);
            let mut driver = self.driver.lock().await;
            let outcome = drive_scouting_until_resolved(
                &mut *driver,
                &actions,
                &mut engine,
                &self.clock,
                self.max_iters,
                self.tick_interval_ms,
            )
            .await;
            drop(driver);
            match outcome {
                ScoutOutcome::Discovered(_) => {
                    // The FIRST Hello, all of its locators — pico's
                    // `_z_locators_by_scout` verbatim. `Discovered` is raised BY
                    // `record_hello_and_emit`, so a non-empty `hellos` here is
                    // guaranteed by the same action that produced the outcome;
                    // the `else` arm below is unreachable rather than defensive,
                    // and says so instead of unwrapping.
                    let hellos = actions.scouted_hellos();
                    match hellos.first() {
                        Some(hello) => {
                            let candidates = Self::reconnectable(&hello.locators);
                            if candidates.is_empty() {
                                // Upstream warns and continues at the same
                                // point (`autoconnect_all`'s
                                // `hello.locators.is_empty()` arm): a peer that
                                // advertised no dialable address is a real
                                // peer, so this is an ordinary retry, not a
                                // fault.
                                log::info!(
                                    "wz reconnect: {} answered with no reconnectable locator; \
                                     scouting again",
                                    self.label
                                );
                            }
                            candidates
                        }
                        None => Vec::new(),
                    }
                }
                // pico's `_Z_ERR_SCOUT_NO_RESULTS`. The supervisor turns an
                // empty list into `OpenError::NoTargets`, which its transient
                // set admits, so the backoff applies and the next attempt
                // scouts again.
                ScoutOutcome::TimedOut
                | ScoutOutcome::LinkLost(_)
                | ScoutOutcome::IterationLimit => Vec::new(),
            }
        })
    }

    fn describe(&self) -> String {
        format!("re-scouted group {}", self.label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The narrowing keeps the Hello's ORDER, which is what makes the failover
    /// try the peer's preferred address first.
    #[test]
    fn reconnectable_preserves_wire_order() {
        let got = ScoutedGroup::reconnectable(&[
            "tcp/10.0.0.1:7447".to_string(),
            "tcp/10.0.0.2:7447".to_string(),
        ]);
        assert_eq!(got.len(), 2, "both locators are reconnectable");
        assert_eq!(
            got,
            vec![
                ReconnectLocator::try_from(plan_endpoint("tcp/10.0.0.1:7447").unwrap()).unwrap(),
                ReconnectLocator::try_from(plan_endpoint("tcp/10.0.0.2:7447").unwrap()).unwrap(),
            ],
            "wire order decides which address the reopen loop tries first"
        );
    }

    /// A Hello that advertises an address this build cannot RECONNECT loses
    /// that entry and keeps the rest — the "one unusable entry is not a failed
    /// scout" rule, asserted rather than described.
    #[test]
    fn reconnectable_drops_the_unreconnectable_and_keeps_the_rest() {
        let got = ScoutedGroup::reconnectable(&[
            "serial//dev/ttyUSB0".to_string(),
            "tcp/10.0.0.2:7447".to_string(),
        ]);
        assert_eq!(
            got,
            vec![ReconnectLocator::try_from(plan_endpoint("tcp/10.0.0.2:7447").unwrap()).unwrap()],
            "the serial arm is dropped, the tcp one survives"
        );
    }

    /// Every entry unusable is an EMPTY list, not a partial one — the input the
    /// supervisor reads as `NoTargets` and retries. Distinguished from the test
    /// above so a change that started erroring on the first bad entry (rather
    /// than dropping it) fails exactly one of the two.
    #[test]
    fn reconnectable_yields_empty_when_nothing_is_dialable() {
        assert!(
            ScoutedGroup::reconnectable(&["serial//dev/ttyUSB0".to_string()]).is_empty(),
            "no reconnectable locator means no candidate, which the supervisor retries"
        );
        assert!(
            ScoutedGroup::reconnectable(&["not a locator at all".to_string()]).is_empty(),
            "an unparseable advertisement is dropped, not propagated"
        );
    }
}
