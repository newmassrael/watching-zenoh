// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

/// R311y700 ([REDACTED-REQ]) — how fast the plan is played back.
///
/// # Why a capture's own timing is not simply reused
///
/// A capture records when a packet was SEEN, and this crate's samples carry a
/// framing coordinate rather than a clock: on a stream link a message's anchor
/// is a byte offset, so there is no per-message time to scale. Pretending
/// otherwise would produce a schedule that looks precise and is invented.
///
/// So the schedule is DECLARED: a gap between samples, scaled by a speed. A
/// caller who wants the capture's own timing supplies the gap they measured;
/// one who wants a burst asks for zero. Both are honest, and neither claims to
/// reproduce a clock the input did not carry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Schedule {
    /// Milliseconds between consecutive samples at speed 1.0.
    pub gap_millis: u64,
    /// The multiplier. 2.0 plays twice as fast (half the gaps); 0.5 half as
    /// fast. Zero and below are refused by [`Self::checked`] rather than
    /// producing an infinite or negative delay.
    pub speed: f64,
    /// A ceiling on any one delay, so a large gap and a slow speed cannot
    /// produce a replay that appears to hang.
    pub max_gap_millis: Option<u64>,
}

impl Default for Schedule {
    /// One sample every 100 ms at speed 1.0, capped at ten seconds.
    fn default() -> Self {
        Self {
            gap_millis: 100,
            speed: 1.0,
            max_gap_millis: Some(10_000),
        }
    }
}

/// Why a schedule was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleError {
    /// A speed of zero or less. Refused rather than clamped: a caller who typed
    /// `--speed 0` meant something, and neither "as fast as possible" nor
    /// "never" is obviously it.
    SpeedNotPositive,
    /// A speed that is not a number at all.
    SpeedNotFinite,
}

impl core::fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SpeedNotPositive => write!(f, "speed must be greater than zero"),
            Self::SpeedNotFinite => write!(f, "speed must be a finite number"),
        }
    }
}

impl Schedule {
    /// This schedule, if it is one that can be played.
    pub fn checked(self) -> Result<Self, ScheduleError> {
        if !self.speed.is_finite() {
            return Err(ScheduleError::SpeedNotFinite);
        }
        if self.speed <= 0.0 {
            return Err(ScheduleError::SpeedNotPositive);
        }
        Ok(self)
    }

    /// The delay BEFORE the sample at `index`. Zero for the first.
    ///
    /// Saturating rather than wrapping at every step: a gap and a speed a
    /// caller can type must not be able to produce a delay of nearly forever
    /// through an arithmetic edge.
    pub fn delay_before(&self, index: usize) -> u64 {
        if index == 0 {
            return 0;
        }
        let scaled = (self.gap_millis as f64) / self.speed;
        let millis = if scaled.is_finite() && scaled >= 0.0 {
            // `as u64` saturates at the type's bounds for an out-of-range
            // float, which is the behaviour wanted here and is worth naming
            // because it was UB before Rust 1.45.
            scaled.round() as u64
        } else {
            u64::MAX
        };
        match self.max_gap_millis {
            Some(cap) => millis.min(cap),
            None => millis,
        }
    }
}

/// R311y700 ([REDACTED-REQ]) — what a fuzzing run does to a payload.
///
/// # Why the mutations are named and seeded rather than random
///
/// A fuzzing run that cannot be repeated is a bug report nobody can act on. So
/// every mutation here is a pure function of the payload and the parameters,
/// and the seeded one is a named generator rather than the thread's entropy.
/// A reader who sees a peer fall over reruns the same command and gets the same
/// bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    /// Send it as captured.
    None,
    /// Flip one bit. `at` is a BIT index; a payload shorter than that is left
    /// alone rather than extended, and [`MutationOutcome`] says so.
    FlipBit { at: usize },
    /// Keep the first `to` bytes. Longer payloads are cut; shorter ones are
    /// left alone.
    Truncate { to: usize },
    /// Append `count` bytes derived from the seed, which is how a length field
    /// that is not checked gets found.
    Extend { count: usize, seed: u64 },
    /// Rewrite every byte from a seeded generator, keeping the length. The
    /// blunt one, and the one that finds a parser that trusts its input.
    Scramble { seed: u64 },
}

/// What a mutation did, so a replay can report it rather than only perform it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationOutcome {
    /// The bytes to send.
    pub payload: Vec<u8>,
    /// Whether the payload actually changed. `false` for [`Mutation::None`] and
    /// for a mutation whose target was outside this payload — the second is the
    /// case a caller must be able to see, because a fuzzing run that silently
    /// changed nothing looks exactly like one that found nothing.
    pub changed: bool,
}

/// A small deterministic generator. SplitMix64, chosen because it is four lines
/// and its constants are in its own definition rather than remembered from a
/// table this crate cannot check.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

impl Mutation {
    /// Apply this mutation.
    pub fn apply(&self, payload: &[u8]) -> MutationOutcome {
        let mut out = payload.to_vec();
        let changed = match *self {
            Self::None => false,
            Self::FlipBit { at } => {
                let byte = at / 8;
                match out.get_mut(byte) {
                    None => false,
                    Some(slot) => {
                        *slot ^= 1u8 << (at % 8);
                        true
                    }
                }
            }
            Self::Truncate { to } => {
                if to < out.len() {
                    out.truncate(to);
                    true
                } else {
                    false
                }
            }
            Self::Extend { count, seed } => {
                if count == 0 {
                    false
                } else {
                    let mut state = seed;
                    out.extend((0..count).map(|_| splitmix64(&mut state) as u8));
                    true
                }
            }
            Self::Scramble { seed } => {
                if out.is_empty() {
                    false
                } else {
                    let mut state = seed;
                    let before = out.clone();
                    for slot in &mut out {
                        *slot = splitmix64(&mut state) as u8;
                    }
                    out != before
                }
            }
        };
        MutationOutcome {
            payload: out,
            changed,
        }
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
}

/// Build the plan for these samples.
///
/// `select` narrows by key expression using zenoh's own dialect; `None` takes
/// everything. Narrowing here rather than at emit time is what makes the plan
/// the whole truth about a run.
pub fn plan(
    samples: &Samples,
    schedule: Schedule,
    mutation: Mutation,
    select: Option<&str>,
) -> Plan {
    let mut emissions = Vec::new();
    for sample in samples.items.iter().filter(|s| covered(select, s)) {
        let outcome = mutation.apply(&sample.payload);
        emissions.push(PlannedEmission {
            delay_millis: schedule.delay_before(emissions.len()),
            keyexpr: sample.keyexpr.clone(),
            payload: outcome.payload,
            captured_len: sample.payload.len(),
            mutated: outcome.changed,
        });
    }
    Plan {
        emissions,
        unresolved: samples.unresolved,
        undecodable: samples.undecodable,
    }
}

/// Does the selector cover this sample's key expression?
fn covered(select: Option<&str>, sample: &Sample) -> bool {
    match select {
        None => true,
        Some(pattern) => {
            let chunks: Vec<&str> = pattern.split('/').collect();
            wz_session_core::keyexpr_match::keyexpr_pattern_matches(&chunks, &sample.keyexpr)
        }
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
    }
    out
}

#[cfg(test)]
mod tests;
