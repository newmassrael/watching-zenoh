// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y713 (§B1) — the exit a flow takes when no further byte of it is coming.
//!
//! # Why this is a module and not three lines at each call site
//!
//! A flow leaves the dissection through more than one door — the capture ends
//! ([`crate::Dissection::finish`]), or the flow cap evicts the least recently
//! active one, on either table. Every door owes the same obligations, and the
//! obligations were written as PROSE beside each door. Four rounds found the
//! same shape of omission at a door somebody had just built:
//!
//! - R311y612 forced the framing decision at `finish` and not at eviction.
//! - R311y649 did the same for [`crate::Framing::Undecided`], again only at
//!   `finish`; R311y650 moved both behind one verb because of it.
//! - R311y656 found that an evicted flow's half-assembled chains were counted
//!   by nothing at all.
//! - R311y713 measured the fourth: an evicted flow never forced its OPEN GAP,
//!   so every byte that had arrived behind the hole left with it undecoded —
//!   `an_evicted_flow_forces_its_open_gap` fails by exactly that message
//!   against the code this module replaced.
//!
//! Prose beside a door cannot stop the fifth door being built wrong, so the
//! obligations are a type here instead:
//!
//! - A flow can only leave a table through [`FlowTable::take`], which hands
//!   back an [`Exiting`] — `#[must_use]`, not convertible back into the flow,
//!   and its destructor asserts it was consumed.
//! - The only consumer is [`ExitCarry::absorb_stream`] /
//!   [`ExitCarry::absorb_datagram`], which performs [`ExitingFlow::perform_exit`]
//!   before harvesting a single counter.
//! - The carried counters are PRIVATE TO THIS MODULE. `lib.rs` cannot add to
//!   them at all, so a future exit site cannot record the partial accounting
//!   that is the failure this module exists to end: either it goes through the
//!   verb and owes nothing, or it has nothing to write to.
//!
//! Rust has no linear types, so "consumed" is enforced by [`Drop`] rather than
//! by the compiler. That is a real gate and not a comment: dropping an
//! `Exiting` unconsumed panics, and `an_unretired_flow_is_a_panic` is the
//! probe that shows it does.

use core::ops::{Deref, DerefMut};

use alloc::vec::Vec;

use wz_session_core::chain_loss::ChainLoss;

use crate::{
    add_sn, add_ws, tls, ByteResidue, DatagramDissection, Direction, FlowDissection, FramingHealth,
    StreamTally,
};

/// What performing a flow's exit obligations turned up.
///
/// Returned rather than accumulated in place because the two exits route the
/// same numbers to different counters: the end of a capture is not a loss and
/// an eviction is, so `finish` books chains under
/// [`crate::Dissection::abandoned_chains`] and this module books them under
/// [`crate::Dissection::evicted_chains`]. See the doc on `expired_chains` for
/// why the three are counted apart at all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ExitTally {
    /// Gaps stepped over because no further packet is coming.
    pub(crate) gaps_forced: usize,
    /// Half-assembled message chains given up on, and the bytes in them.
    pub(crate) chains: ChainLoss,
}

/// A flow that can be told no further byte of it will be read.
///
/// Implemented once per flow table, and the two implementations differ in
/// exactly what the two kinds of flow can be holding — which is the reason
/// this is a trait rather than a function with a `match`: a datagram flow has
/// no assembler to force and no framing to settle, and a shared body would
/// have to ask which kind it held at every line.
///
/// `residue` is deliberately NOT on this trait: both flow types already carry
/// an inherent `residue()` and an inherent method wins name resolution, so a
/// trait copy would be a method nothing ever calls — which is how the compiler
/// reported it.
pub(crate) trait ExitingFlow {
    /// Perform every obligation this flow owes on its way out.
    fn perform_exit(&mut self) -> ExitTally;
}

impl ExitingFlow for FlowDissection {
    fn perform_exit(&mut self) -> ExitTally {
        let mut tally = ExitTally::default();
        // 1. THE OPEN GAPS. A gap is stepped over on patience — a count of
        //    later segments on the same direction — and an exit is the one
        //    fact patience cannot supply: no later segment is coming. Bytes
        //    that arrived behind the hole are decodable and, until this ran at
        //    every exit, an evicted flow took them with it undecoded.
        for direction in [Direction::A, Direction::B] {
            loop {
                let before = self.assembler(direction).len();
                let asm = match direction {
                    Direction::A => &mut self.low_to_high,
                    Direction::B => &mut self.high_to_low,
                };
                if asm.force_oldest_gap().is_none() {
                    break;
                }
                tally.gaps_forced += 1;
                self.deliver_from(direction, before);
            }
        }
        // 2. THE FRAMING DECISION. A flow still deciding what it is must be
        //    reported rather than held: bytes held for a verdict that never
        //    comes are bytes reported as absent. Runs AFTER the gap forcing,
        //    because what the forcing delivered is evidence the verdict wants.
        self.settle_on_exit();
        // 3. THE OPEN CHAINS. The framing decision and the reassembler are two
        //    different things the flow was in the middle of, and settling the
        //    first does not reach the second.
        tally.chains = self.session.abandon_open_chains_counting();
        // R311y713 (§B6) — on the flow's own ledger as well as the caller's.
        // A flow that leaves is the last moment anything can say it was THIS
        // flow that was mid-message.
        self.chain_loss.absorb(tally.chains);
        tally
    }
}

impl ExitingFlow for DatagramDissection {
    fn perform_exit(&mut self) -> ExitTally {
        // A datagram flow has no assembler and no framing — the two
        // obligations above are not skipped here, they do not exist. What it
        // does have is chains, because a datagram flow is where fragments
        // actually arrive.
        let chains = self.session.abandon_open_chains_counting();
        self.chain_loss.absorb(chains);
        ExitTally {
            gaps_forced: 0,
            chains,
        }
    }
}

/// A flow that has LEFT its table and has not yet been accounted for.
///
/// Constructible only by [`FlowTable::take`] and consumable only by
/// [`ExitCarry`], so "removed from the table" and "accounted for" cannot come
/// apart. See the module docs for why that is worth a type.
#[must_use = "a flow removed from its table must be retired through ExitCarry, \
              or its counters leave the dissection with it"]
#[derive(Debug)]
pub(crate) struct Exiting<F: ExitingFlow>(Option<F>);

impl<F: ExitingFlow> Drop for Exiting<F> {
    fn drop(&mut self) {
        // `#[must_use]` catches the value being ignored outright; this catches
        // it being bound and then dropped, which is what a hand-written exit
        // site actually looks like. debug-only: a release consumer of this
        // library must not abort over a counter, and every gate that reads
        // this crate runs in debug.
        debug_assert!(
            self.0.is_none(),
            "a flow left its table without being retired: its gaps, framing, \
             chains and counters have all been dropped on the floor"
        );
    }
}

/// A flow table whose only removal is an accounted one.
///
/// A thin wrapper over [`Vec`] that deliberately does NOT re-export `remove`,
/// `drain`, `retain`, `pop` or `clear`: reading and appending are ordinary, and
/// taking a flow out is the act this module exists to constrain. The deref to
/// a slice keeps every read site — indexing, iteration, `len` — unchanged.
#[derive(Debug)]
pub(crate) struct FlowTable<F: ExitingFlow> {
    rows: Vec<F>,
}

impl<F: ExitingFlow> Default for FlowTable<F> {
    fn default() -> Self {
        Self { rows: Vec::new() }
    }
}

impl<F: ExitingFlow> FlowTable<F> {
    /// Append a newly observed flow.
    pub(crate) fn push(&mut self, flow: F) {
        self.rows.push(flow);
    }

    /// Remove the flow at `idx`, obliging the caller to retire it.
    pub(crate) fn take(&mut self, idx: usize) -> Exiting<F> {
        Exiting(Some(self.rows.remove(idx)))
    }
}

/// `for flow in &table` — the borrowing halves of `Vec`'s iteration, which a
/// deref to a slice does not supply on its own. Deliberately NOT the owning
/// `IntoIterator`: consuming the table by value would be one more way for a
/// flow to leave unaccounted.
impl<'a, F: ExitingFlow> IntoIterator for &'a FlowTable<F> {
    type Item = &'a F;
    type IntoIter = core::slice::Iter<'a, F>;

    fn into_iter(self) -> Self::IntoIter {
        self.rows.iter()
    }
}

impl<'a, F: ExitingFlow> IntoIterator for &'a mut FlowTable<F> {
    type Item = &'a mut F;
    type IntoIter = core::slice::IterMut<'a, F>;

    fn into_iter(self) -> Self::IntoIter {
        self.rows.iter_mut()
    }
}

impl<F: ExitingFlow> Deref for FlowTable<F> {
    type Target = [F];

    fn deref(&self) -> &[F] {
        &self.rows
    }
}

impl<F: ExitingFlow> DerefMut for FlowTable<F> {
    fn deref_mut(&mut self) -> &mut [F] {
        &mut self.rows
    }
}

/// Everything the flows that have LEFT the dissection are still owed.
///
/// Every field is private to this module and there is no `&mut` accessor. That
/// is the enforcement: `lib.rs` can read these totals and cannot add to them,
/// so the only way a number gets in here is through a full retirement.
///
/// A flow is either live or counted here, never both — which is why each
/// reader in `lib.rs` starts from this value and then walks the live tables.
#[derive(Debug, Default)]
pub(crate) struct ExitCarry {
    streams: StreamTally,
    sessions: FramingHealth,
    encrypted: tls::EncryptedTotals,
    residue: ByteResidue,
    chains: ChainLoss,
    messages: usize,
    flows: usize,
}

impl ExitCarry {
    /// Retire a stream flow: obligations first, then every counter it held.
    pub(crate) fn absorb_stream(&mut self, mut gone: Exiting<FlowDissection>) {
        let mut flow = gone.0.take().expect("an Exiting is consumed once");
        // BEFORE any counter below is read. R311y713: the forcing this
        // performs can decode messages and move loss counters, so harvesting
        // first would carry the numbers the flow had before it finished
        // leaving.
        let tally = flow.perform_exit();
        self.chains.absorb(tally.chains);
        // The ENCRYPTED census, which is a finding and not a loss tally: an
        // evicted encrypted flow otherwise took the whole "this capture is
        // unreadable and here is how much of it" statement with it.
        if let Some(e) = flow.encrypted() {
            self.encrypted.add_flow(&e.per_direction);
        }
        // The MESSAGES it decoded, including any the exit above just
        // recovered. A count of what this reader saw must never walk
        // backwards, which is the direction a recycled slot moves it.
        self.messages += flow.frames.len();
        self.streams.add_assembler(&flow.low_to_high);
        self.streams.add_assembler(&flow.high_to_low);
        add_ws(&mut self.sessions, flow.ws_accounting());
        // The SESSION counters, which live inside `PassiveSession` rather than
        // on an assembler, so the assembler carry above does not reach them.
        for dir in [Direction::A, Direction::B] {
            let r = flow.session.resync_accounting(dir);
            self.sessions.desyncs += r.desyncs;
            self.sessions.recoveries += r.recoveries;
            self.sessions.resync_skipped_bytes += r.skipped_bytes;
            self.sessions.reserved_headers += flow.session.reserved_headers(dir);
            self.sessions.undefined_mandatory_exts += flow.session.undefined_mandatory_exts(dir);
            self.sessions.unaccounted_batch_bytes += flow.session.unaccounted_batch_bytes(dir);
            add_sn(&mut self.sessions, flow.session.sn_accounting(dir));
        }
        // R311y713 — and the BYTE RESIDUE, which R311y709 added to both flow
        // tables and to no carry. Measured, not assumed: without this line a
        // capture that evicts a flow reports less unfed residue than it
        // recovered, and the residue gate reads a healthier tree than it has.
        self.residue.absorb(flow.residue());
        self.flows += 1;
    }

    /// Retire a datagram flow. Fewer counters, same rule.
    pub(crate) fn absorb_datagram(&mut self, mut gone: Exiting<DatagramDissection>) {
        let mut flow = gone.0.take().expect("an Exiting is consumed once");
        self.chains.absorb(flow.perform_exit().chains);
        // R311y713 — the datagram table's frames were counted by nobody: the
        // stream path has carried `messages` since R311y666 and this one never
        // did, so `decoded_messages` walked backwards whenever a MULTICAST
        // slot recycled. Same defect, one table over, found by writing the two
        // retirements next to each other.
        self.messages += flow.frames.len();
        // `resync_accounting` is deliberately absent: a datagram flow has no
        // framing to lose, which is why `framing_health` does not read it
        // there either.
        for dir in [Direction::A, Direction::B] {
            self.sessions.reserved_headers += flow.session.reserved_headers(dir);
            self.sessions.undefined_mandatory_exts += flow.session.undefined_mandatory_exts(dir);
            self.sessions.unaccounted_batch_bytes += flow.session.unaccounted_batch_bytes(dir);
            add_sn(&mut self.sessions, flow.session.sn_accounting(dir));
        }
        self.residue.absorb(flow.residue());
        self.flows += 1;
    }

    /// The assembler counters of every retired flow.
    pub(crate) fn streams(&self) -> StreamTally {
        self.streams
    }

    /// Their session-level framing counters.
    pub(crate) fn sessions(&self) -> FramingHealth {
        self.sessions
    }

    /// Their TLS record census.
    pub(crate) fn encrypted(&self) -> tls::EncryptedTotals {
        self.encrypted
    }

    /// Their recovered-against-fed byte counts.
    pub(crate) fn residue(&self) -> ByteResidue {
        self.residue
    }

    /// Chains they were still assembling when they left.
    pub(crate) fn chains(&self) -> usize {
        self.chains.chains
    }

    /// R311y713 (§B7) — and the bytes those chains had already gathered.
    pub(crate) fn chain_bytes(&self) -> u64 {
        self.chains.bytes
    }

    /// Transport messages they had decoded.
    pub(crate) fn messages(&self) -> usize {
        self.messages
    }

    /// How many flows have been retired — the eviction count itself.
    pub(crate) fn flows(&self) -> usize {
        self.flows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Dissection, DissectionLimits};

    /// R311y713 (§B1) — the Drop guard is a gate, and this is its probe.
    ///
    /// Without it `Exiting` would be a comment: a future exit site could take a
    /// flow out of the table, decide it had nothing worth carrying, and let it
    /// fall — the exact failure four rounds have each found once. `#[must_use]`
    /// does not catch that shape, because the value IS bound.
    #[test]
    #[should_panic(expected = "without being retired")]
    fn an_unretired_flow_is_a_panic() {
        let mut d = Dissection::with_limits(DissectionLimits::default());
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            0,
            &crate::datagram_tests::tcp_packet(
                1000,
                &[1, 0, wz_session_core::wire_const::T_MID_KEEP_ALIVE],
            ),
        );
        assert_eq!(d.flows().len(), 1, "the fixture must produce one flow");
        drop(d.take_stream_flow_for_test(0));
    }

    /// And the retired path does not fire it — a guard that panicked either way
    /// would be indistinguishable from a broken one.
    #[test]
    fn a_retired_flow_is_not() {
        let mut carry = ExitCarry::default();
        let mut d = Dissection::with_limits(DissectionLimits::default());
        d.push_packet(
            crate::link::LINKTYPE_ETHERNET,
            0,
            &crate::datagram_tests::tcp_packet(
                1000,
                &[1, 0, wz_session_core::wire_const::T_MID_KEEP_ALIVE],
            ),
        );
        carry.absorb_stream(d.take_stream_flow_for_test(0));
        assert_eq!(carry.flows(), 1);
        assert_eq!(carry.messages(), 1, "the flow's decoded message is carried");
    }
}
