// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y700 ([REDACTED-REQ] / [REDACTED-REQ] / [REDACTED-REQ]) — REPLAY: a capture, sent again.
//!
//! ## Why this re-publishes rather than re-sending bytes
//!
//! "Re-encode a captured packet into a NEW SESSION" is the requirement, and the
//! re-encoding is not decoration. A zenoh message carries session-scoped state:
//! a transport sequence number the peer gates on, a keyexpr numeric id that
//! means whatever the sender DECLARED it to mean on that session, a batch size
//! the two ends negotiated. Bytes lifted off one session and pushed onto
//! another are refused by a conforming peer, and worse, MAY be accepted with a
//! keyexpr id that resolves to a different topic.
//!
//! So a replay recovers what the application actually said — a key expression
//! and a payload — and says it again through a normal session, which mints its
//! own sequence numbers and declares its own ids. That is the only re-injection
//! that means the same thing on the second wire as it did on the first.
//!
//! ## Why the sink is a trait
//!
//! Spacing a plan in time ([REDACTED-REQ]) and mutating a payload ([REDACTED-REQ]) are
//! decisions, and a decision that can only be observed by putting packets on a
//! wire is a decision nobody tests. Both are values here, computed by pure
//! functions, and the emission is a trait a test can record. The live sink is
//! the binary's, where the session runtime lives.

use wz_analyze::{Sample, Samples};

/// R311y702 ([REDACTED-REQ]) — the LIVE sink, behind the `live` feature.
///
/// The trait above is the seam and this is its production implementation: a
/// dialled session and a real Put per emission. Feature-gated so the plan half
/// stays buildable without the session runtime's dependency graph; see this
/// crate's `Cargo.toml` for why the CLI REFUSES `--connect` when it is off
/// rather than falling back to a dry run.
/// R311y716 ([REDACTED-REQ]) — the analyzer's verdict as a NOTIFICATION.
///
/// UNGATED, unlike [`live`] which delivers it: deciding whether a capture
/// warrants an alert, and what that alert says, is a pure function of an
/// [`wz_analyze::Outcome`] and belongs to the plan half this crate keeps
/// buildable without the session runtime. A caller on a build with `live` off
/// can still ask what would have been sent -- and is REFUSED if it tries to
/// send it, which is the rule `--connect` already follows.
pub mod alert;

/// R311y750 (carry N3) — WHERE the alert goes, and what happens when it does
/// not arrive.
///
/// UNGATED for the same reason [`alert`] is: which destinations were tried, how
/// often, and with what waits between is a pure function of a policy and an
/// injected send. Keeping it out of [`live`] is what makes the retry schedule a
/// measured property instead of one argued from the code.
pub mod delivery;

#[cfg(feature = "live")]
pub mod live;

/// The pacing of a plan (how fast it is played back, and where each gap came from) and the
/// mutation of its payloads, re-exported at the paths they have always had: they are the
/// workload's (`wz-workload`), which the traffic driver of `wz-ap-demo` plays too, and their
/// meaning did not change with the move. The C ABI over this crate (`wz-capi-replay`) names them
/// here.
pub use wz_workload::mutation::{Mutation, MutationOutcome};
pub use wz_workload::pacing::{Pacing, Schedule, ScheduleError, Timing, TimingSource};

/// The word a rendering prints for a pacing source, or nothing for the ordinary declared case --
/// which is what a reader who did not ask for capture timing should not have to read on every row.
fn timing_note(source: TimingSource) -> &'static str {
    match source {
        TimingSource::Declared => "",
        TimingSource::Measured => " (capture)",
        TimingSource::Unmeasurable => " (declared -- no capture time for this pair)",
    }
}

/// R311y704 — why a PLAN was refused, as opposed to a schedule.
///
/// Separate from [`ScheduleError`] because the two are answerable at different
/// times: a speed of zero is wrong the moment it is typed, and a plan that runs
/// too long is only knowable once the samples are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanTooLong {
    /// What the plan would take.
    pub total_millis: u64,
    /// The ceiling it exceeded.
    pub limit_millis: u64,
    /// How many emissions it holds -- the number an operator changes with
    /// `--select` or `--side` when they meet this.
    pub emissions: usize,
}

impl core::fmt::Display for PlanTooLong {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "this plan would take {} ms ({} emission(s)), over the \
             --max-total of {} ms. Narrow it with --select / --side, raise \
             --speed, or raise --max-total",
            self.total_millis, self.emissions, self.limit_millis
        )
    }
}

/// Where a replay's samples go.
///
/// A trait so the ENGINE can be driven by a test. The live implementation lives
/// in the binary beside the session runtime; nothing in this library opens a
/// socket.
pub trait Sink {
    /// Wait `delay_millis`, then send `payload` under `keyexpr`.
    ///
    /// The delay is the SINK's to honour because only it knows what a clock is
    /// here: the live one sleeps on the session's, and a recording one records
    /// the number and moves on. An engine that slept itself would make every
    /// test take as long as the capture.
    fn emit(&mut self, delay_millis: u64, keyexpr: &str, payload: &[u8]) -> Result<(), String>;
}

/// A plan: what will be sent, in order, with what delay and what mutation.
///
/// Built before anything is sent so a caller can print it (`--dry-run`) and get
/// exactly what a live run would do. A dry run computed by a different path
/// would be a second opinion about the caller's own command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedEmission {
    /// Milliseconds to wait before this one.
    pub delay_millis: u64,
    /// The key expression it goes out under.
    pub keyexpr: String,
    /// The bytes, AFTER mutation.
    pub payload: Vec<u8>,
    /// How many bytes the capture held, before mutation.
    pub captured_len: usize,
    /// Whether the mutation changed anything.
    pub mutated: bool,
    /// R311y703 (RP4) — which clock [`Self::delay_millis`] came from.
    pub timing: TimingSource,
}

/// What a whole replay will do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// The emissions, in order.
    pub emissions: Vec<PlannedEmission>,
    /// Samples the capture held whose keyexpr could not be read, carried
    /// through from [`wz_analyze::Samples`] so a plan states its own floor.
    pub unresolved: usize,
    /// Messages the capture held that could not be read at all.
    pub undecodable: usize,
    /// R311y701 (RP2) — datagram messages the extraction could not REACH. The
    /// third leg of the same floor, and it exists because the datagram half of
    /// a capture is walked by a second read of the file rather than out of
    /// retained bytes.
    pub unreachable: usize,
    /// R311y701 (RP3) — samples the capture DID hold that this [`Selection`]
    /// left out.
    ///
    /// A plan with no emissions is otherwise the same page whether the capture
    /// held nothing or the selector took nothing, and those send a reader to
    /// opposite places: one is traffic to go and find, the other is a pattern
    /// to fix. The distinction is exactly the one `PayloadDecoding::NoRule`
    /// draws one crate over.
    pub excluded: usize,
}

impl Plan {
    /// Total wall-clock the plan will take, which is the number a caller
    /// checks before starting one.
    pub fn duration_millis(&self) -> u64 {
        self.emissions
            .iter()
            .map(|e| e.delay_millis)
            .fold(0u64, u64::saturating_add)
    }

    /// How many emissions carry bytes the mutation changed.
    pub fn mutated(&self) -> usize {
        self.emissions.iter().filter(|e| e.mutated).count()
    }

    /// R311y704 — this plan, if it fits the schedule's whole-plan ceiling.
    ///
    /// Asked of the PLAN rather than enforced inside `plan()` for the reason
    /// `--dry-run` exists: an operator who hits this must be able to SEE the
    /// plan that was too long, and a builder that refused to produce one would
    /// leave them with a number and no listing.
    pub fn within(&self, schedule: Schedule) -> Result<(), PlanTooLong> {
        let Some(limit) = schedule.max_total_millis else {
            return Ok(());
        };
        let total = self.duration_millis();
        if total <= limit {
            return Ok(());
        }
        Err(PlanTooLong {
            total_millis: total,
            limit_millis: limit,
            emissions: self.emissions.len(),
        })
    }
}

/// R311y701 (RP3) — WHICH of a capture's samples a replay takes.
///
/// # Why the two narrowings travel as one value
///
/// R311y700 took the keyexpr selector as a bare argument, and this round adds a
/// second axis. Two `Option`s side by side at a call site are two things a
/// caller can transpose, and the arity only grows — the same argument
/// `RowAt` settled for the renderers in R311y688.
///
/// # Why `side` exists at all
///
/// [`Sample::direction`] was recorded in R311y700 and read by NOBODY: the field
/// was carried through the extraction, into the plan's input, and never
/// consulted. A capture holds both halves of a conversation, and re-publishing
/// both means re-publishing the peer's replies as though this node had said
/// them — which is not a replay of a client, it is a fabrication of a server.
/// So the field acquires the consumer it was recorded for.
#[derive(Debug, Clone, Copy, Default)]
pub struct Selection<'a> {
    /// Only samples whose keyexpr matches, in zenoh's own dialect (`demo/**`
    /// covers `demo/a`). `None` takes every topic.
    pub keyexpr: Option<&'a str>,
    /// Only samples that travelled this way. `None` takes both halves.
    pub side: Option<wz_session_core::passive::Direction>,
}

impl Selection<'_> {
    /// Does this selection take that sample?
    fn takes(&self, sample: &Sample) -> bool {
        if let Some(side) = self.side {
            if sample.direction != side {
                return false;
            }
        }
        match self.keyexpr {
            None => true,
            Some(pattern) => {
                let chunks: Vec<&str> = pattern.split('/').collect();
                wz_session_core::keyexpr_match::keyexpr_pattern_matches(&chunks, &sample.keyexpr)
            }
        }
    }
}

/// Build the plan for these samples.
///
/// Narrowing here rather than at emit time is what makes the plan the whole
/// truth about a run.
pub fn plan(
    samples: &Samples,
    schedule: Schedule,
    mutation: Mutation,
    selection: Selection<'_>,
) -> Plan {
    let mut emissions = Vec::new();
    let mut excluded = 0usize;
    // R311y703 (RP4) — the previous TAKEN sample's capture time, not the
    // previous sample's. A selector that drops the message between two kept
    // ones widens the real interval, and reproducing the narrower one would
    // play a conversation that never happened at that pace.
    //
    // Round 2441 (open-debt item 693) — that anchor and the saturating
    // subtraction over it now live in [`Pacing`], because the C ABI paces
    // capture times a caller already holds and cannot build a `Samples` to get
    // here. Feeding only the TAKEN samples into the walk is what keeps the
    // sentence above true: `excluded` never reaches it.
    let mut pacing = Pacing::new(schedule);
    for sample in &samples.items {
        if !selection.takes(sample) {
            excluded += 1;
            continue;
        }
        let (delay_millis, timing) = pacing.next(sample.captured_at_millis);
        let outcome = mutation.apply(&sample.payload);
        emissions.push(PlannedEmission {
            delay_millis,
            keyexpr: sample.keyexpr.clone(),
            payload: outcome.payload,
            captured_len: sample.payload.len(),
            mutated: outcome.changed,
            timing,
        });
    }
    Plan {
        emissions,
        unresolved: samples.unresolved,
        undecodable: samples.undecodable,
        unreachable: samples.unreachable,
        excluded,
    }
}

/// Play a plan into a sink.
///
/// Stops at the FIRST failure and says which emission it was, rather than
/// carrying on: a peer that refused one sample will refuse the rest, and a
/// replay that reported "12 of 40 sent" without saying where it stopped leaves
/// the reader to guess.
pub fn play(plan: &Plan, sink: &mut dyn Sink) -> Result<usize, (usize, String)> {
    for (index, emission) in plan.emissions.iter().enumerate() {
        sink.emit(emission.delay_millis, &emission.keyexpr, &emission.payload)
            .map_err(|why| (index, why))?;
    }
    Ok(plan.emissions.len())
}

/// Render a plan the way `--dry-run` prints it.
pub fn render(plan: &Plan) -> String {
    let mut out = format!(
        "replay: {} emission(s), {} ms total, {} mutated\n",
        plan.emissions.len(),
        plan.duration_millis(),
        plan.mutated()
    );
    // R311y704 — WHOSE clock the measured gaps came from, said once at the top
    // and only when at least one gap actually used it.
    //
    // A packet's timestamp is when the CAPTURING host saw it, not when the
    // publisher sent it. On a loopback or same-host capture the two are close;
    // across a link they are a network apart, and a reader reproducing "the
    // application's cadence" from a tap several hops away is reproducing the
    // tap's view of it. R311y703 built this pacing and nothing said so at the
    // point a reader chooses it -- the same shape as a report printing a total
    // without saying it is a floor.
    if plan
        .emissions
        .iter()
        .any(|e| e.timing == TimingSource::Measured)
    {
        out.push_str(
            "  gaps marked (capture) are intervals the CAPTURING host recorded, \
             which is when it SAW each packet rather than when the publisher \
             sent it\n",
        );
    }
    if plan.unresolved > 0 {
        out.push_str(&format!(
            "  {} message(s) carried a payload whose keyexpr is a numeric id \
             this reader cannot resolve, so they are NOT in this plan\n",
            plan.unresolved
        ));
    }
    if plan.undecodable > 0 {
        out.push_str(&format!(
            "  {} message(s) could not be read at all\n",
            plan.undecodable
        ));
    }
    // R311y701 (RP2) — the datagram half's own floor, named separately because
    // it is a disagreement between two reads of the capture rather than a
    // message this walker does not understand.
    if plan.unreachable > 0 {
        out.push_str(&format!(
            "  {} datagram message(s) could not be reached in the capture's own \
             bytes on a second read\n",
            plan.unreachable
        ));
    }
    // R311y701 (RP3) — what the SELECTOR left out, so an empty plan is never
    // mistaken for an empty capture.
    if plan.excluded > 0 {
        out.push_str(&format!(
            "  {} sample(s) the capture held are not in this plan because the \
             selection did not take them\n",
            plan.excluded
        ));
    }
    for (index, emission) in plan.emissions.iter().enumerate() {
        out.push_str(&format!(
            "  {index}: +{} ms `{}` {} byte(s){}\n",
            emission.delay_millis,
            emission.keyexpr,
            emission.payload.len(),
            if emission.mutated {
                format!(" MUTATED (was {})", emission.captured_len)
            } else {
                String::new()
            }
        ));
        // R311y703 (RP4) — appended rather than folded into the line above so
        // the declared case reads exactly as it always did: a reader who did
        // not ask for capture timing gets no new words on any row.
        let note = timing_note(emission.timing);
        if !note.is_empty() {
            out.pop();
            out.push_str(note);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests;
