// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y589 — WHERE a reassembly chain's bytes land, as a seam.
//!
//! [`crate::reassembly_dispatch`] owns the chain FSM, the SN arithmetic, the
//! per-peer quota and the deadline clock. None of that says anything about the
//! STORAGE the fragments accumulate into, and until this module the two were
//! welded: every chain staged into a `BoundedVec<u8, CAP>`, whose `alloc`
//! backing is a growable `Vec` (`crate::bounded` — `CAP` is advisory there and
//! the dispatcher re-checks it explicitly).
//!
//! That is the right default for a general AP deploy and the wrong one for a
//! deterministic one. A `preset-ap-full` node is the AUTOSAR-adjacent profile:
//! it wants its reassembly arena reserved at startup, so a chain cannot fail on
//! an allocator under load and the resident cost is a number known before the
//! first packet. Those are different DEPLOY decisions over the same protocol,
//! which is precisely what a trait is for.
//!
//! ## Why the seam is the POOL and not the buffer
//!
//! The obvious shape — a trait for one chain's buffer — cannot express the
//! interesting implementation. A reserved arena is shared across chains: a
//! per-chain object would either own a private arena (defeating the reservation)
//! or borrow a shared one (a lifetime the dispatcher's `[Slot; SLOTS]` array
//! cannot hold). So the trait is over the ARENA, and a chain holds an opaque
//! [`ChainStaging::Chain`] handle the arena hands out and takes back.
//!
//! This is also what makes the implementation on the other side of the seam a
//! real consumer of the SCE-generated `sce:kind="buffer-pool"` FSM
//! (`out/wz-runtime-tokio/reassembly_pool_ap.rs`): that FSM's author-facing API
//! is exactly `acquire -> write -> read -> return` over a shared slot table, and
//! its phantom-typed `Slot<S>` makes the illegal orders a compile error rather
//! than a runtime check. The seam's four methods are that lifecycle.
//!
//! ## The bound is the trait's, not the caller's
//!
//! [`ChainStaging::append`] returns `Err` when the chain would exceed `CAP`.
//! That check lives HERE rather than at the dispatcher's call site because the
//! two backings have different reasons for it: the heap backing needs an
//! explicit comparison (its `Vec` would happily grow past `CAP` and defeat the
//! §5.M pool-exhaustion defence), while a reserved-arena backing gets it from
//! the slot's own width. A caller-side check would be correct for one and
//! redundant-but-harmless for the other, which is how a bound drifts.

/// Why an arena refused bytes.
///
/// A named type rather than `Err(())` — which is what the pre-seam private
/// helper returned and what Layer C1bq's clippy arm rejected the moment the
/// signature became public (`clippy::result_unit_err`). The lint is right for a
/// reason beyond style: this is the arena's only refusal TODAY, and a `()`
/// would have to be widened at every implementation and call site on the day a
/// reserved arena grows a second one.
///
/// An `enum` rather than the unit struct written first: `#[non_exhaustive]` on
/// a unit struct makes it unconstructible outside this crate, so
/// `wz-runtime-tokio`'s arena could not return its own refusal (E0423, caught by
/// the same lane). On an enum the attribute means what was wanted — a new
/// variant is not a breaking change, and existing ones stay constructible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StagingError {
    /// The chain's total would exceed `CAP`.
    ChainCapExceeded,
}

/// The arena a reassembly Router stages its chains into.
///
/// `SLOTS` and `CAP` are the Router's own dims, restated here so an
/// implementation can refuse dims it cannot serve (see
/// [`ChainStaging::new`]) rather than silently serving fewer chains than the
/// Router will ask for.
pub trait ChainStaging<const SLOTS: usize, const CAP: usize> {
    /// One chain's staging handle. Opaque to the Router, which only ever
    /// passes it back to the arena that produced it.
    ///
    /// It is NOT `Copy` or `Clone` on purpose: for a reserved arena the handle
    /// IS the reservation, and duplicating it would let two chains write the
    /// same bytes.
    type Chain;

    /// Build the arena.
    ///
    /// An implementation that cannot serve `SLOTS` chains of `CAP` bytes must
    /// fail here — at construction, where a deploy can see it — rather than by
    /// returning `None` from [`Self::acquire`] later, which the Router would
    /// report as ordinary pool exhaustion and a peer could trigger at will.
    fn new() -> Self;

    /// Reserve staging for a chain that is starting. `None` = the arena is
    /// full.
    ///
    /// The Router picks its own free slot first, so with a well-dimensioned
    /// arena this cannot fail. It is fallible anyway because "well-dimensioned"
    /// is an invariant between two numbers, and an invariant with no failure
    /// path is one nobody notices breaking.
    fn acquire(&mut self) -> Option<Self::Chain>;

    /// Return a chain's staging. Consumes the handle.
    fn release(&mut self, chain: Self::Chain);

    /// Append `payload` to `chain`.
    ///
    /// [`StagingError::ChainCapExceeded`] when the chain's total would exceed `CAP` — the
    /// chain is aborted by the caller and its staging released.
    fn append(&mut self, chain: &mut Self::Chain, payload: &[u8]) -> Result<(), StagingError>;

    /// The bytes staged into `chain` so far, in arrival order.
    fn bytes<'a>(&'a self, chain: &'a Self::Chain) -> &'a [u8];

    /// How many chains the arena can still serve. Observability only — the
    /// Router never branches on it.
    ///
    /// It exists so a test can state the invariant that ties the two free
    /// counts together (`Router.active_chains() + arena.available() == SLOTS`),
    /// which is the one assertion that catches a LEAKED handle. A leak is
    /// otherwise invisible: the Router's own slot is freed either way, and the
    /// arena only runs dry `SLOTS` chains later, in an unrelated test.
    ///
    /// Every implementation must report the live figure, including one whose
    /// storage cannot actually run out. A backing that answered `SLOTS`
    /// unconditionally would make the invariant vacuous on itself — and it is
    /// the DEFAULT backing that most needs the leak check, because it is the one
    /// every Router in the tree runs.
    fn available(&self) -> usize;
}

/// The default arena: one growable heap buffer per chain, allocated on demand.
///
/// This is what every Router did before the seam existed, preserved exactly —
/// including the explicit `CAP` comparison, which is load-bearing rather than
/// belt-and-braces. On the `alloc` backing `BoundedVec::push` never fails
/// (`crate::bounded` documents `CAP` as advisory there), so without the
/// comparison an AP Router would grow a chain past `slot_size` without limit
/// and the §5.M malicious-peer pool-exhaustion defence would be absent on the
/// only profile that has an allocator to exhaust.
///
/// Idle cost is zero and a chain's cost is what it actually staged, which is the
/// right trade for a general deploy and the wrong one for a deterministic
/// deploy. `preset-ap-full` takes the other trade behind `runtime-zero-copy`.
pub struct HeapStaging<const SLOTS: usize, const CAP: usize> {
    /// Handles currently out. The bytes live in the handles, so this counter is
    /// the arena's ENTIRE state — it buys nothing but the leak check in
    /// [`ChainStaging::available`], and that is reason enough: this is the
    /// backing every Router in the tree runs, so an accounting bug in the
    /// dispatcher's acquire/release pairing shows up here or nowhere.
    outstanding: usize,
}

/// One chain's heap staging. The bytes live in the handle, so an idle chain
/// costs nothing and a live one costs what it actually staged.
pub struct HeapChain<const CAP: usize> {
    buf: crate::bounded::BoundedVec<u8, CAP>,
}

impl<const SLOTS: usize, const CAP: usize> ChainStaging<SLOTS, CAP> for HeapStaging<SLOTS, CAP> {
    type Chain = HeapChain<CAP>;

    fn new() -> Self {
        Self { outstanding: 0 }
    }

    fn acquire(&mut self) -> Option<Self::Chain> {
        if self.outstanding >= SLOTS {
            return None;
        }
        self.outstanding += 1;
        Some(HeapChain {
            buf: crate::bounded::BoundedVec::new(),
        })
    }

    fn release(&mut self, _chain: Self::Chain) {
        self.outstanding = self.outstanding.saturating_sub(1);
    }

    fn append(&mut self, chain: &mut Self::Chain, payload: &[u8]) -> Result<(), StagingError> {
        if chain.buf.len().saturating_add(payload.len()) > CAP {
            return Err(StagingError::ChainCapExceeded);
        }
        for &b in payload {
            chain
                .buf
                .push(b)
                .map_err(|_| StagingError::ChainCapExceeded)?;
        }
        Ok(())
    }

    fn bytes<'a>(&'a self, chain: &'a Self::Chain) -> &'a [u8] {
        &chain.buf
    }

    fn available(&self) -> usize {
        SLOTS.saturating_sub(self.outstanding)
    }
}
