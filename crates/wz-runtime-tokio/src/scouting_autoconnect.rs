// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2141 (open-debt item 223) — the MULTICAST-SCOUTING autoconnect: scout the
//! group, and DIAL every node whose Hello the
//! [`wz_routing_graph::AutoConnect`] policy admits.
//!
//! This is the wz counterpart of zenoh's `Runtime::autoconnect_all`
//! (`zenoh/src/net/runtime/orchestrator.rs`), and it is the half of multicast
//! scouting wz did not have. What it closes, precisely: the two config keys
//! `scouting/multicast/autoconnect` and `scouting/multicast/autoconnect_strategy`
//! reached nothing, so a wz node on a multicast group could answer scouts
//! (R311y846's responder) and could resolve ONE dial target for a one-shot
//! session (`--scout`, R311y428), but could not do what a stock zenoh peer does
//! by default: keep scouting, and open a session to each admitted node that
//! answers.
//!
//! # The item's own diagnosis was wrong, and the correction is load-bearing
//!
//! Open-debt item 223 states the gap as "a wz that ANSWERED a Scout never dials
//! the node that asked". Measured against the pinned checkout, upstream does not
//! do that either: `Runtime::responder` replies with a Hello and dials nothing,
//! while `autoconnect_all` is a SEPARATE task under the same `tokio::select!`
//! that SCOUTS — with the policy's own matcher as the Scout's `what` — and dials
//! whoever answers ITS scout. [`crate::scouting_responder`]'s module doc already
//! recorded that split and cited both functions.
//!
//! So the trigger for a dial is not "I answered someone"; it is "someone
//! answered ME, and my policy admits their role and zid". Getting that backwards
//! would have produced a node that dials every stranger that probes the group —
//! the opposite of a policy — which is why the module is written against the
//! Hello and not against the Scout.
//!
//! # Where the decision lives, and why it is not in the loop
//!
//! [`autoconnect_verdict`] is a pure function of (policy, Hello). It has no
//! socket, no channel and no clock, so every reason NOT to dial is a value a
//! test can assert instead of a log line it can only read — the same split
//! [`crate::scouting_responder`] makes for the answering direction, and for the
//! same reason. [`serve_autoconnect`] owns the IO: it re-drives the scouting
//! cycle, drains the Hellos, applies the verdict, and posts a
//! [`DialIntent`] for each admitted node.
//!
//! # Why a channel and not a dial
//!
//! The same reason the gossip plane uses one: the task that owns the scouting
//! socket is not the task that owns the in-flight-open set, and the accept loop
//! is where a dial is deduplicated against faces already held. Upstream calls
//! `connect_peer` inline from `autoconnect_all` because its runtime spawns a task
//! per dial; wz routes the intent back to its single drive loop. The intent
//! carries [`DialIntentOrigin::MulticastScout`] so the loop's counters can say
//! which plane moved — see [`DialIntentOrigin`].
//!
//! # Survey mode, not exit-on-first
//!
//! `--scout` resolves ONE locator and returns, so it drives the FSM with
//! `ScoutParams::exit_on_first` set. This one must see EVERY responder in the
//! window, so it clears the flag and reads
//! [`ScoutingActions::scouted_hellos`] after each cycle — the arm that records
//! all of them. Upstream's `autoconnect_all` has the same shape: its
//! `Runtime::scout` callback returns `Loop::Continue` unconditionally, so the
//! scout never stops at the first Hello.

use std::collections::BTreeSet;
use std::sync::Arc;

use sce_rust_runtime::Engine;
use wz_routing_graph::{AutoConnect, Zid};

use wz_runtime_core::TimeSource;

use crate::accept_loop::{DialIntent, DialIntentOrigin, DialIntentSender};
use crate::scouting_glue::{
    drive_scouting_until_resolved, ScoutActionsBinding, ScoutOutcome, ScoutedHello, ScoutingActions,
};
use crate::LinkDriver;
use wz_session_core::scouting::ScoutingPolicy;

/// What the policy decided about one decoded Hello.
///
/// Every arm is a REASON rather than a bare `bool`, because the operator question
/// behind this subsystem is "why did my node not connect to the peer I can see on
/// the group", and the answers call for different actions: a
/// [`NoLocators`](Self::NoLocators) means the peer is findable but not dialable
/// (it bound an unspecified address), an [`UnknownRole`](Self::UnknownRole) means
/// its Hello carried a role byte this build does not understand, and a
/// [`PolicyDeclined`](Self::PolicyDeclined) means the operator's own
/// `autoconnect` / `autoconnect_strategy` said no.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoconnectVerdict {
    /// Dial it — the role is admitted and the tie-break passed.
    Dial(DialIntent),
    /// The Hello advertised no locator, so there is nothing to dial. Upstream
    /// warns and continues at exactly this point (`autoconnect_all`'s
    /// `hello.locators.is_empty()` arm) rather than treating it as an error: a
    /// peer that advertised no address is a real peer.
    NoLocators,
    /// The Hello's `cbyte` named no role this build knows, so the role matcher
    /// has nothing to test. Kept DISTINCT from `PolicyDeclined` because it is not
    /// the operator's policy that refused — `ScoutedHello::whatami` is an
    /// `Option` for the same reason ("the peer said something we do not
    /// understand" must not read as "the peer said peer").
    UnknownRole,
    /// The policy refused: either the role is outside the matcher, or the
    /// per-target [`AutoConnectStrategy`](wz_routing_graph::AutoConnectStrategy)
    /// tie-break declined. The refusing role is carried so a report can name it.
    PolicyDeclined {
        /// The role the Hello claimed.
        whatami: wz_codecs::whatami::WhatAmI,
    },
}

/// The gate, as a pure function of the policy and one decoded Hello — zenoh
/// `autoconnect_all`'s loop body, minus the socket.
///
/// Mirrors that body's ORDER, which is load-bearing: upstream checks the locators
/// FIRST and only then consults `should_autoconnect`, so a locator-less Hello is
/// reported as locator-less even when the policy would also have refused it. A
/// reader that asked the policy first would report the less actionable of two
/// true reasons.
pub fn autoconnect_verdict(policy: &AutoConnect, hello: &ScoutedHello) -> AutoconnectVerdict {
    if hello.locators.is_empty() {
        return AutoconnectVerdict::NoLocators;
    }
    let Some(whatami) = hello.whatami else {
        return AutoconnectVerdict::UnknownRole;
    };
    if !policy.should_autoconnect(Zid::from_slice(&hello.zid), whatami) {
        return AutoconnectVerdict::PolicyDeclined { whatami };
    }
    AutoconnectVerdict::Dial(DialIntent {
        zid: hello.zid.clone(),
        locators: hello.locators.clone(),
        origin: DialIntentOrigin::MulticastScout,
    })
}

/// What one turn of [`serve_autoconnect`] did — reported so a caller can log it
/// and a test can count it.
#[derive(Debug)]
pub enum AutoconnectStep {
    /// A dial intent was posted for this peer.
    Dialing {
        /// The peer's zid (trimmed wire bytes).
        zid: Vec<u8>,
        /// The locators the intent carries.
        locators: Vec<String>,
    },
    /// A Hello was seen and NOT dialed; `why` is which gate refused.
    Skipped {
        /// The peer's zid (trimmed wire bytes).
        zid: Vec<u8>,
        /// The verdict, never [`AutoconnectVerdict::Dial`].
        why: AutoconnectVerdict,
    },
    /// One scouting cycle finished. `hellos` is the running total of DISTINCT
    /// peers seen, so a flat count across cycles is visibly "nobody new" rather
    /// than indistinguishable from "nobody at all".
    Cycle {
        /// The cycle's outcome as the scouting FSM reported it.
        outcome: ScoutOutcome,
        /// How many distinct peer zids have been seen since the loop started.
        peers: usize,
    },
    /// The scouting link is gone; the loop is over.
    LinkLost,
}

/// What [`serve_autoconnect`] decides with, as one value.
///
/// The four fields that are not the scouting MACHINERY: the machinery (link
/// driver, actions, engine, clock) is what a scouting cycle needs and is shared
/// with [`drive_scouting_until_resolved`]; this is what makes the cycle an
/// AUTOCONNECT rather than a survey. Bundled because a caller sets it once and
/// the loop reads it every cycle — and because nine positional arguments is a
/// signature whose call sites cannot be read.
pub struct AutoconnectPlan<'a> {
    /// The role + per-target tie-break gate. zenoh's `AutoConnect::multicast`,
    /// built from `scouting/multicast/autoconnect{,_strategy}`.
    pub policy: &'a AutoConnect,
    /// Where an admitted responder's [`DialIntent`] goes — the accept loop's
    /// channel, shared with the gossip plane and told apart by
    /// [`DialIntentOrigin`].
    pub dial_tx: &'a DialIntentSender,
    /// Bounds the loop for tests exactly as
    /// [`drive_scouting_until_resolved`]'s `max_iters` does. Production passes
    /// `None` and the task runs for the process's life, which is what upstream's
    /// `spawn_abortable(autoconnect_all(..))` is.
    pub max_cycles: Option<usize>,
    /// The select cadence inside one cycle. Bounds how promptly the WINDOW's
    /// expiry is noticed, never the discovery latency — a Hello races it.
    pub tick_interval_ms: u64,
}

/// Scout the group and post a [`DialIntent`] for every admitted responder, until
/// the link dies or [`AutoconnectPlan::max_cycles`] is reached.
///
/// # The dedup, and why it is HERE as well as in the loop
///
/// A responder answers every cycle, and [`ScoutingActions`] accumulates its
/// Hellos across cycles, so without a dedup a peer would be re-intended once per
/// cycle forever. The accept loop already refuses to open a second face to a zid
/// it holds (`dial_decision`'s `AlreadyHeld`), so nothing would BREAK — but the
/// channel is unbounded and the producer is a timer, which is the shape that
/// grows without bound between two correct components. Deduping on the zid here
/// keeps the intent stream proportional to the mesh rather than to uptime.
///
/// It is a `BTreeSet` of zids and NOT a "dialed successfully" set on purpose: if
/// the dial fails, re-scouting is not the recovery path — the accept loop's own
/// retry schedule is — and re-posting an intent would race it.
pub async fn serve_autoconnect<D, T, F>(
    driver: &mut D,
    actions: &Arc<ScoutingActions>,
    engine: &mut Engine<ScoutingPolicy<ScoutActionsBinding>>,
    clock: &T,
    plan: AutoconnectPlan<'_>,
    mut on_step: F,
) where
    D: LinkDriver,
    T: TimeSource,
    F: FnMut(AutoconnectStep),
{
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut cycles: usize = 0;
    loop {
        if let Some(limit) = plan.max_cycles {
            if cycles >= limit {
                return;
            }
            cycles += 1;
        }
        let outcome = drive_scouting_until_resolved(
            driver,
            actions,
            engine,
            clock,
            None,
            plan.tick_interval_ms,
        )
        .await;
        // Every Hello the cycle recorded, in arrival order. `exit_on_first` is
        // clear for this loop's params (see the module doc), so this is the whole
        // window rather than its first entry.
        for hello in actions.scouted_hellos() {
            if !seen.insert(hello.zid.clone()) {
                continue;
            }
            match autoconnect_verdict(plan.policy, &hello) {
                AutoconnectVerdict::Dial(intent) => {
                    let (zid, locators) = (intent.zid.clone(), intent.locators.clone());
                    // An `Err` means the accept loop is gone (shutdown), so the
                    // intent is dropped — the same non-blocking, non-fatal send
                    // the gossip plane makes.
                    if plan.dial_tx.send(intent).is_ok() {
                        on_step(AutoconnectStep::Dialing { zid, locators });
                    }
                }
                why => on_step(AutoconnectStep::Skipped {
                    zid: hello.zid.clone(),
                    why,
                }),
            }
        }
        let ended = matches!(outcome, ScoutOutcome::LinkLost(_));
        on_step(AutoconnectStep::Cycle {
            outcome,
            peers: seen.len(),
        });
        if ended {
            on_step(AutoconnectStep::LinkLost);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use wz_codecs::whatami::{WhatAmI, WhatAmIMatcher};
    use wz_routing_graph::{AutoConnectStrategies, AutoConnectStrategy};

    fn hello(zid: &[u8], whatami: Option<WhatAmI>, locators: &[&str]) -> ScoutedHello {
        ScoutedHello {
            version: 0x09,
            whatami,
            zid: zid.to_vec(),
            locators: locators.iter().map(|l| String::from(*l)).collect(),
        }
    }

    /// The zenoh PEER default for `scouting/multicast/autoconnect`
    /// (`DEFAULT_CONFIG.json5`: `peer: ["router", "peer"]`).
    fn peer_default(zid: &[u8]) -> AutoConnect {
        AutoConnect::new(
            Zid::from_slice(zid),
            WhatAmIMatcher::empty().router().peer(),
            AutoConnectStrategy::Always,
        )
    }

    /// A Hello from an admitted role with a locator becomes a dial intent
    /// carrying the peer's OWN zid and locators, tagged as a multicast discovery.
    #[test]
    fn an_admitted_responder_becomes_a_multicast_origin_dial_intent() {
        let policy = peer_default(&[0x01]);
        let verdict = autoconnect_verdict(
            &policy,
            &hello(&[0xAA, 0xBB], Some(WhatAmI::Router), &["tcp/10.0.0.7:7447"]),
        );
        assert_eq!(
            verdict,
            AutoconnectVerdict::Dial(DialIntent {
                zid: vec![0xAA, 0xBB],
                locators: vec![String::from("tcp/10.0.0.7:7447")],
                origin: DialIntentOrigin::MulticastScout,
            })
        );
    }

    /// Each refusal is its OWN verdict, and the three are told apart by the gate
    /// that fired rather than lumped into one "no".
    #[test]
    fn every_reason_not_to_dial_is_its_own_verdict() {
        let policy = peer_default(&[0x01]);
        // Locator-less: checked BEFORE the policy, upstream's order. The role here
        // is one the policy would ALSO refuse (client), so a reader that asked the
        // policy first would answer `PolicyDeclined` and this pins the order.
        assert_eq!(
            autoconnect_verdict(&policy, &hello(&[0xAA], Some(WhatAmI::Client), &[])),
            AutoconnectVerdict::NoLocators
        );
        // A role byte no role maps to — not the operator's policy refusing.
        assert_eq!(
            autoconnect_verdict(&policy, &hello(&[0xAA], None, &["tcp/10.0.0.7:7447"])),
            AutoconnectVerdict::UnknownRole
        );
        // Outside the matcher: the zenoh peer default admits router|peer, never a
        // client.
        assert_eq!(
            autoconnect_verdict(
                &policy,
                &hello(&[0xAA], Some(WhatAmI::Client), &["tcp/10.0.0.7:7447"])
            ),
            AutoconnectVerdict::PolicyDeclined {
                whatami: WhatAmI::Client
            }
        );
    }

    /// An EMPTY matcher — `autoconnect: []`, which is what a stock ROUTER's
    /// config resolves to — dials nobody, whatever answers.
    #[test]
    fn an_empty_matcher_declines_every_responder() {
        let policy = AutoConnect::disabled(Zid::from_slice(&[0x01]));
        assert!(!policy.is_enabled());
        for w in [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client] {
            assert_eq!(
                autoconnect_verdict(&policy, &hello(&[0xAA], Some(w), &["tcp/10.0.0.7:7447"])),
                AutoconnectVerdict::PolicyDeclined { whatami: w }
            );
        }
    }

    /// The TARGET-DEPENDENT strategy reaches the verdict: the same responder zid
    /// is dialed as a router and declined as a peer.
    ///
    /// R2141 — this is item 223's design half, seen from the consuming end. The
    /// gate function takes the WHOLE policy, so a policy that had flattened the
    /// per-target table (every wz `AutoConnect` before this round) answers both
    /// legs alike and one of the two assertions fails.
    #[test]
    fn a_per_target_strategy_splits_the_verdict_for_one_responder() {
        let policy = AutoConnect::with_strategies(
            // The LESSER zid, so `greater-zid` must decline.
            Zid::from_slice(&[0x03]),
            WhatAmIMatcher::empty().router().peer(),
            AutoConnectStrategies::PerTarget {
                to_router: Some(AutoConnectStrategy::Always),
                to_peer: Some(AutoConnectStrategy::GreaterZid),
                to_client: None,
            },
        );
        let as_router = hello(&[0x09], Some(WhatAmI::Router), &["tcp/10.0.0.7:7447"]);
        let as_peer = hello(&[0x09], Some(WhatAmI::Peer), &["tcp/10.0.0.7:7447"]);
        assert!(matches!(
            autoconnect_verdict(&policy, &as_router),
            AutoconnectVerdict::Dial(_)
        ));
        assert_eq!(
            autoconnect_verdict(&policy, &as_peer),
            AutoconnectVerdict::PolicyDeclined {
                whatami: WhatAmI::Peer
            }
        );
    }
}
