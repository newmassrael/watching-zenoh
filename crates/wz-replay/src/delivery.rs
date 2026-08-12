// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y750 (carry N3) — DELIVERY: where an alert goes, and what happens when
//! it does not arrive.
//!
//! # What was missing
//!
//! R311y716 gave the analyzer's verdict a way out of the terminal, and carry N3
//! recorded what that first shape could not do: "one transport, one destination,
//! no retry -- right for a capture-file tool, wrong for a watchdog". The
//! transport half is a settled decision and stays one (see [`crate::alert`] for
//! why it goes out over the deployment's own bus). The other two halves are not
//! decisions, they are gaps, and they are the ones a watchdog is judged on: a
//! single dial that loses a TCP race takes the alert with it, and an operator
//! who named one router has no way to say "and the other one".
//!
//! # Why the attempt is injected
//!
//! [`deliver`] takes the send and the wait as parameters. That is not a testing
//! convenience bolted on afterwards — it is what lets the RETRY SCHEDULE be a
//! measured property rather than an argued one. A test drives a destination that
//! fails twice and succeeds on the third try, and asserts the attempt count, the
//! order destinations were tried in, and that the tool waited between tries and
//! not after the last one. None of that is observable through a real socket
//! without a network, and all of it is what N3 is about.
//!
//! It also keeps this module in the crate's UNGATED half: a build without the
//! `live` feature can still say what delivery WOULD do, exactly as [`crate::alert`]
//! can still say what would be sent.

/// How hard one destination is tried before it is called lost.
///
/// `attempts` counts the FIRST try, so `1` is the pre-R311y750 behaviour and is
/// a legitimate choice; `0` is not, which is why it cannot be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    attempts: u32,
    backoff_millis: u64,
}

impl Default for RetryPolicy {
    /// Three tries, half a second apart.
    ///
    /// Chosen for the failure this exists for — a dial that loses a race with a
    /// router still coming up — and NOT presented as measured: no deployment in
    /// this tree has been observed recovering on try two. It is a default that
    /// costs at most a second before the tool gives up and says so, which is the
    /// property that made it safe to pick without a measurement.
    fn default() -> Self {
        Self {
            attempts: 3,
            backoff_millis: 500,
        }
    }
}

impl RetryPolicy {
    /// A policy, or `None` when it would send nothing.
    ///
    /// Zero attempts is REFUSED rather than clamped. A watchdog configured to
    /// try zero times reports "0 of 1 delivered" and exits non-zero for a reason
    /// that has nothing to do with the network, and the operator would read that
    /// as an outage. This workspace's rule for a lower layer that would silently
    /// degrade is to turn it into a refusal at the layer a person types into.
    pub fn new(attempts: u32, backoff_millis: u64) -> Option<Self> {
        if attempts == 0 {
            return None;
        }
        Some(Self {
            attempts,
            backoff_millis,
        })
    }

    /// Tries allowed per destination, counting the first.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Milliseconds waited BETWEEN tries.
    pub fn backoff_millis(&self) -> u64 {
        self.backoff_millis
    }
}

/// What became of one destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivered {
    /// The locator as the operator wrote it.
    pub destination: String,
    /// Tries actually made — never zero, and less than the policy's allowance
    /// when the first or second try succeeded.
    pub attempts_made: u32,
    /// Emissions sent, or the reason the last try gave.
    pub outcome: Result<usize, String>,
}

/// Every destination's outcome, in the order the operator named them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeliveryReport {
    /// One entry per destination.
    pub deliveries: Vec<Delivered>,
}

impl DeliveryReport {
    /// Destinations the alert reached.
    pub fn delivered(&self) -> usize {
        self.deliveries.iter().filter(|d| d.outcome.is_ok()).count()
    }

    /// Destinations the alert did not reach after every allowed try.
    pub fn failed(&self) -> usize {
        self.deliveries.len() - self.delivered()
    }

    /// Whether every destination the operator named was reached.
    ///
    /// The exit code keys on this rather than on "at least one", and the choice
    /// is deliberate: a redundant destination that is down IS a fault, and a
    /// watchdog that returns success while half its fan-out is unreachable has
    /// taught its reader to ignore the one signal it exists to give.
    pub fn all_delivered(&self) -> bool {
        !self.deliveries.is_empty() && self.failed() == 0
    }
}

/// Try every destination, retrying each per `policy`, and report all of them.
///
/// `attempt` sends to one locator and returns the emissions sent or the reason
/// it could not. `wait` is handed the backoff in milliseconds; it is called
/// BETWEEN tries of the same destination and never after the last one, so a
/// policy of one attempt never waits at all.
///
/// A destination that fails every try does NOT stop the others: the whole point
/// of naming two routers is that one of them being unreachable is the case the
/// second one is for.
pub fn deliver<A, W>(
    destinations: &[String],
    policy: RetryPolicy,
    mut attempt: A,
    mut wait: W,
) -> DeliveryReport
where
    A: FnMut(&str) -> Result<usize, String>,
    W: FnMut(u64),
{
    let mut deliveries = Vec::new();
    for destination in destinations {
        let mut made = 0;
        let mut last: Result<usize, String> = Err("no attempt was made".to_string());
        while made < policy.attempts {
            if made > 0 {
                wait(policy.backoff_millis);
            }
            made += 1;
            last = attempt(destination);
            if last.is_ok() {
                break;
            }
        }
        deliveries.push(Delivered {
            destination: destination.clone(),
            attempts_made: made,
            outcome: last,
        });
    }
    DeliveryReport { deliveries }
}

/// The page an operator sees after delivery.
///
/// Every destination gets a line whether or not it worked, on the same rule
/// [`crate::alert::render`] follows: a silence a reader has to interpret is the
/// thing being removed.
pub fn render(report: &DeliveryReport) -> String {
    let mut s = format!(
        "delivery: {} of {} destination(s)\n",
        report.delivered(),
        report.deliveries.len()
    );
    for d in &report.deliveries {
        match &d.outcome {
            Ok(sent) => s.push_str(&format!(
                "  {} -- {} emission(s) after {} attempt(s)\n",
                d.destination, sent, d.attempts_made
            )),
            Err(why) => s.push_str(&format!(
                "  {} -- FAILED after {} attempt(s): {}\n",
                d.destination, d.attempts_made, why
            )),
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn dests(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    /// Zero attempts is refused, and one attempt is the old behaviour.
    #[test]
    fn a_policy_that_would_send_nothing_cannot_be_built() {
        assert_eq!(RetryPolicy::new(0, 500), None);
        let one = RetryPolicy::new(1, 500).expect("one try is a real policy");
        assert_eq!(one.attempts(), 1);
        assert_eq!(RetryPolicy::default().attempts(), 3);
    }

    /// The retry SCHEDULE, measured: a destination that fails twice is tried a
    /// third time, and the tool waited exactly twice.
    ///
    /// This case alone does NOT pin where the waits fall — a loop written
    /// "try, then wait" also waits twice here, because the third try succeeds
    /// and breaks before its wait. The trailing wait only becomes visible on a
    /// destination that fails EVERY try, which is why
    /// [`an_unreachable_destination_does_not_stop_the_reachable_ones`] counts
    /// waits too. Written down because the weaker assertion looked sufficient.
    #[test]
    fn a_destination_is_retried_and_the_waits_fall_between_the_tries() {
        let tries = RefCell::new(0u32);
        let waits: RefCell<Vec<u64>> = RefCell::new(Vec::new());
        let report = deliver(
            &dests(&["tcp/a:7447"]),
            RetryPolicy::new(3, 250).expect("policy"),
            |_| {
                let mut n = tries.borrow_mut();
                *n += 1;
                if *n < 3 {
                    Err("connection refused".to_string())
                } else {
                    Ok(1)
                }
            },
            |ms| waits.borrow_mut().push(ms),
        );
        assert_eq!(*tries.borrow(), 3, "it must keep trying until it succeeds");
        assert_eq!(
            *waits.borrow(),
            vec![250, 250],
            "two waits for three tries -- a wait after the LAST try is dead time"
        );
        assert_eq!(report.deliveries[0].attempts_made, 3);
        assert_eq!(report.deliveries[0].outcome, Ok(1));
        assert!(report.all_delivered());
    }

    /// A success on the first try neither retries nor waits.
    #[test]
    fn a_destination_that_answers_at_once_is_not_retried() {
        let tries = RefCell::new(0u32);
        let waits = RefCell::new(0u32);
        let report = deliver(
            &dests(&["tcp/a:7447"]),
            RetryPolicy::default(),
            |_| {
                *tries.borrow_mut() += 1;
                Ok(1)
            },
            |_| *waits.borrow_mut() += 1,
        );
        assert_eq!(*tries.borrow(), 1);
        assert_eq!(*waits.borrow(), 0, "nothing to wait for");
        assert_eq!(report.deliveries[0].attempts_made, 1);
    }

    /// One destination failing does not take the others with it, and the report
    /// says which one it was.
    ///
    /// THE DISCRIMINATOR is the ORDER: the unreachable destination is in the
    /// middle, so an implementation that stops at the first failure delivers to
    /// one destination instead of two, and a `delivered() == 1` assertion alone
    /// could not tell that from "only one was named".
    ///
    /// It also carries the TRAILING-WAIT assertion, which needs a destination
    /// that fails every try: two tries here means exactly ONE wait, and a loop
    /// written "try, then wait" spends a second one after the final failure —
    /// backoff charged to a destination it has already given up on.
    #[test]
    fn an_unreachable_destination_does_not_stop_the_reachable_ones() {
        let seen: RefCell<Vec<String>> = RefCell::new(Vec::new());
        let waits: RefCell<Vec<u64>> = RefCell::new(Vec::new());
        let report = deliver(
            &dests(&["tcp/a:7447", "tcp/down:7447", "tcp/b:7447"]),
            RetryPolicy::new(2, 10).expect("policy"),
            |to| {
                seen.borrow_mut().push(to.to_string());
                if to.contains("down") {
                    Err("no route to host".to_string())
                } else {
                    Ok(1)
                }
            },
            |ms| waits.borrow_mut().push(ms),
        );
        assert_eq!(
            *waits.borrow(),
            vec![10],
            "one wait, and it falls BETWEEN the failing destination's two tries \
             -- a wait after the last one is backoff spent on a lost cause",
        );
        assert_eq!(
            *seen.borrow(),
            dests(&["tcp/a:7447", "tcp/down:7447", "tcp/down:7447", "tcp/b:7447"]),
            "each destination in the order named, and the failing one twice",
        );
        assert_eq!(report.delivered(), 2);
        assert_eq!(report.failed(), 1);
        assert!(
            !report.all_delivered(),
            "a named destination that was not reached is a fault, not a detail",
        );

        let page = render(&report);
        assert!(page.contains("delivery: 2 of 3 destination(s)"), "{page}");
        assert!(
            page.contains("tcp/down:7447 -- FAILED after 2 attempt(s): no route to host"),
            "the page must name the destination, the tries and the reason: {page}",
        );
        assert!(
            page.contains("tcp/a:7447 -- 1 emission(s) after 1 attempt(s)"),
            "{page}",
        );
    }

    /// No destinations is not "all delivered".
    ///
    /// The empty case reaches `all_delivered` through the CLI's own "nowhere to
    /// send it" path, and a vacuous `true` there would report success for an
    /// alert that never left the process.
    #[test]
    fn nowhere_to_send_is_not_success() {
        let report = deliver(&[], RetryPolicy::default(), |_| Ok(1), |_| {});
        assert!(!report.all_delivered());
        assert_eq!(report.delivered(), 0);
        assert_eq!(report.failed(), 0);
    }
}
