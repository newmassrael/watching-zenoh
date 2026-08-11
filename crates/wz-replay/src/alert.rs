// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y716 ([REDACTED-REQ]) — the analyzer's verdict, DELIVERED.
//!
//! # What was missing, exactly
//!
//! The content has existed for many rounds: a capture's verdict, and since
//! R311y716 the named reasons behind it. What did not exist was a way for that
//! judgement to reach anyone who is not looking at a terminal. An operator
//! learns their deployment is dropping frames when they next decide to run the
//! tool, which is the wrong way round -- the tool should tell them.
//!
//! # Why here rather than in `wz-analyze`
//!
//! Two reasons, and the first is decisive: `wz-replay` DEPENDS on `wz-analyze`,
//! so a delivery path inside the analyzer that reached this crate's session
//! machinery would be a dependency cycle. The second is that it belongs here
//! anyway. This crate's own header calls it "the analyzer's ACTIVE half" --
//! every crate below it observes, and this one is the one that acts. A
//! notification is an action.
//!
//! # Why it goes out over zenoh
//!
//! Because the deployment being watched is already running one. An alert
//! published onto the bus lands wherever that deployment's operators already
//! look, needs no second transport in a workspace whose whole subject is this
//! one, and is witnessed end-to-end by a real peer decoding a real sample --
//! which an exit code or a log line cannot be.
//!
//! # Silence is deliberate, and it is not the whole story
//!
//! Nothing is published when the capture is clean. An alert channel that fires
//! on every run trains its readers to ignore it, which is worse than no channel
//! at all. What is NOT silent is the tool: it always prints its verdict, so
//! "nothing was sent" and "nothing ran" never look alike to the person who
//! typed the command.

use wz_analyze::Outcome;
use wz_capture::report::VerdictReason;

use crate::{Plan, PlannedEmission, TimingSource};

/// Where an alert goes when the operator names no key expression.
///
/// A CONSTANT rather than an inline default, because it is the string a
/// subscriber on the other side has to have been told: changing it is a
/// consumer-visible change and should be one edit that a reader can find.
pub const DEFAULT_KEYEXPR: &str = "wz/alert";

/// One notification: what to say, and where to say it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    /// The key expression it goes out under.
    pub keyexpr: String,
    /// The reasons, in the order the verdict named them.
    pub reasons: Vec<VerdictReason>,
    /// The bytes that go on the wire.
    pub payload: Vec<u8>,
}

/// The alert this outcome warrants, or `None` when there is nothing to say.
///
/// `None` and not an empty alert: a caller must not be able to publish a
/// notification that says nothing, and an `Option` is the only shape in which
/// "there is nothing to report" cannot be accidentally sent.
pub fn alert_for(outcome: &Outcome, keyexpr: &str) -> Option<Alert> {
    if outcome.reasons.is_empty() {
        return None;
    }
    Some(Alert {
        keyexpr: keyexpr.to_string(),
        reasons: outcome.reasons.clone(),
        payload: payload_of(outcome).into_bytes(),
    })
}

/// The alert body: the verdict, its reasons, and the decryption figures that
/// qualify them.
///
/// JSON because the report beside it is JSON and a subscriber should not have
/// to learn a second encoding for the same workspace's output. Hand-written for
/// the reason `wz-capture` writes its own: this crate's payload is four fields
/// and a list, and a serialisation dependency to emit it would be charged to
/// every consumer of the plan half, which has none.
fn payload_of(outcome: &Outcome) -> String {
    let mut s = String::from("{\"complete\":false,\"reasons\":[");
    for (i, r) in outcome.reasons.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('"');
        s.push_str(r.name());
        s.push('"');
    }
    s.push_str(&format!(
        "],\"decrypted_flows\":{},\"undecrypted_flows\":{}}}",
        outcome.decrypted_flows, outcome.undecrypted_flows
    ));
    s
}

/// The page an operator sees before anything is sent.
///
/// Printed whether or not there is a destination, and whether or not there is
/// an alert, on the rule `render` follows for a plan: what is about to go out
/// is shown FIRST, and the value shown is the value that goes.
pub fn render(alert: Option<&Alert>, connect: Option<&str>) -> String {
    let mut s = String::new();
    match alert {
        None => {
            s.push_str("alert: none -- this capture is complete\n");
        }
        Some(a) => {
            s.push_str(&format!(
                "alert: {} reason(s) on {}\n",
                a.reasons.len(),
                a.keyexpr
            ));
            for r in &a.reasons {
                s.push_str(&format!("  {}\n", r.name()));
            }
            s.push_str(&format!("  payload: {} byte(s)\n", a.payload.len()));
        }
    }
    match (alert, connect) {
        // The two silences a reader must be able to tell apart: nothing to
        // send, and nowhere to send it.
        (Some(_), None) => s.push_str("  NOT SENT -- no --connect destination\n"),
        (None, Some(to)) => s.push_str(&format!("  nothing sent to {to}\n")),
        _ => {}
    }
    s
}

/// The alert as a one-emission [`Plan`], which is what the live sink plays.
///
/// Reusing the replay path rather than opening a second session of its own: the
/// dialling, the handshake, the drive loop and the teardown order are all
/// settled there and were measured into their current shape (R311y702). A
/// second copy would be a second set of those decisions.
pub fn as_plan(alert: &Alert) -> Plan {
    Plan {
        emissions: vec![PlannedEmission {
            delay_millis: 0,
            keyexpr: alert.keyexpr.clone(),
            payload: alert.payload.clone(),
            captured_len: alert.payload.len(),
            mutated: false,
            // DECLARED, and it is not a formality: an alert's timing comes from
            // the moment it is raised, never from the capture it is about. A
            // `Measured` here would claim the wire chose to send it.
            timing: TimingSource::Declared,
        }],
        ..Plan::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(reasons: &[VerdictReason]) -> Outcome {
        Outcome {
            complete: reasons.is_empty(),
            reasons: reasons.to_vec(),
            decrypted_flows: 1,
            undecrypted_flows: 2,
            key_log_connections: 0,
            foreign_secrets_blocks: 0,
        }
    }

    /// A clean capture raises nothing, and the tool still says so.
    ///
    /// Both halves matter: an alert channel that fires on every run is ignored,
    /// and a tool that goes silent when it found nothing is indistinguishable
    /// from one that did not run.
    #[test]
    fn a_complete_capture_raises_no_alert_and_the_page_says_so() {
        assert_eq!(alert_for(&outcome(&[]), DEFAULT_KEYEXPR), None);
        let page = render(None, None);
        assert!(page.contains("alert: none"), "{page}");
        assert!(
            render(None, Some("tcp/h:7447")).contains("nothing sent to tcp/h:7447"),
            "a destination with nothing to send must be distinguishable from \
             no destination"
        );
    }

    /// The reasons reach the payload BY NAME, which is the whole content of the
    /// notification.
    ///
    /// An alert saying only "incomplete" sends its reader back to the tool they
    /// were trying not to have to run.
    #[test]
    fn the_alert_carries_the_reasons_the_verdict_named() {
        let a = alert_for(
            &outcome(&[VerdictReason::PacketsSkipped, VerdictReason::SnMissing]),
            "site/alerts",
        )
        .expect("an incomplete capture raises one");
        assert_eq!(
            a.keyexpr, "site/alerts",
            "the operator's key, not the default"
        );
        let body = String::from_utf8(a.payload.clone()).expect("utf-8");
        assert_eq!(
            body,
            "{\"complete\":false,\"reasons\":[\"packets_skipped\",\"sn_missing\"],\
             \"decrypted_flows\":1,\"undecrypted_flows\":2}"
        );
        let page = render(Some(&a), None);
        assert!(
            page.contains("packets_skipped") && page.contains("sn_missing"),
            "{page}"
        );
        assert!(
            page.contains("NOT SENT"),
            "an alert with nowhere to go must say it did not go: {page}"
        );
    }

    /// The plan an alert becomes is ONE emission with no delay in front of it.
    ///
    /// A delay would be read off a capture's clock, and an alert is not about
    /// when the traffic happened -- it is about now.
    #[test]
    fn an_alert_becomes_one_immediate_emission() {
        let a = alert_for(&outcome(&[VerdictReason::GapsForced]), DEFAULT_KEYEXPR).expect("raised");
        let plan = as_plan(&a);
        assert_eq!(plan.emissions.len(), 1);
        let e = &plan.emissions[0];
        assert_eq!(e.delay_millis, 0, "an alert waits for nothing");
        assert_eq!(e.keyexpr, DEFAULT_KEYEXPR);
        assert_eq!(e.payload, a.payload);
        assert!(!e.mutated, "an alert is not a fuzzed sample");
        assert_eq!(e.timing, TimingSource::Declared);
        // The plan's own floors are zero: an alert is BUILT, never extracted
        // from a capture, so nothing about it could have gone unread.
        assert_eq!(
            (plan.unresolved, plan.undecodable, plan.unreachable),
            (0, 0, 0)
        );
    }
}
