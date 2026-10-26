// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The workload a node or a driver plays: what it sends over time, apart from what it is.
//!
//! The model is the load generator's: a stream of sends is an arrival process (when) times a
//! payload generator (what) times a stop condition, and a recorded sequence is played with a
//! pacing of its own. Each part is a pure value here, so the interpreter that plays it (the
//! traffic driver of `wz-ap-demo`, the replay tool, a fixed-memory node) only waits and sends.
//!
//! * [`arrivals`]: a rate written as a decimal, the gap it gives, and the periodic schedule of
//!   absolute deadlines that does not drift and does not burst to catch up.
//! * [`payload`]: the bytes of the n-th send, from a fill rule.
//! * [`pacing`]: the delay before each emission of a recorded sequence (the declared gap or the
//!   interval the capture recorded, scaled by a speed and capped), and where it came from.
//! * [`mutation`]: what a fuzzing run does to a payload, each a pure function of the payload and
//!   its parameters, with SplitMix64 as the one generator.
//!
//! The pacing and the mutation were the replay tool's (`wz-replay`), which re-exports them at its
//! own paths; their meaning is unchanged by the move, and the byte vectors in [`mutation`] hold it.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod arrivals;
pub mod mutation;
pub mod pacing;
pub mod payload;
