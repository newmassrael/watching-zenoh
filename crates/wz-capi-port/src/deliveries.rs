// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What "inside a callback" means to an engine: the thread asking delivers for that engine now.
//!
//! An undeclaration that waits for the callback it retracts to be let go of
//! ([`crate::SessionEngine::undeclare_subscriber`]) must not wait where the call it waits for may
//! be below it on its own stack, or may itself be waiting for this thread: that is a thread inside
//! a delivery of the same engine, and only there can the wait close a cycle. A callback of another
//! engine is no delivery of this one, so an undeclaration made from inside it waits; skipping the
//! wait there would hand the program back a callback still running. Every engine answers the one
//! question the same way, whatever it keeps to answer it.

/// The deliveries of one engine, as the thread that asks sees them.
pub trait EngineDeliveries {
    /// Whether this thread delivers for this engine now: a callback the engine hands out (a
    /// sample, a liveliness change, a query, a reply, a matching status) runs below on its stack,
    /// or the engine hands one out from there. An undeclaration of the engine made where this holds
    /// does not wait for a call of its callback to end.
    fn delivers_here(&self) -> bool;
}
