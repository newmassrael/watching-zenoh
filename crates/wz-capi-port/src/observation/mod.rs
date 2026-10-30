// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the doors of the observation plane do, for every C ABI and every engine
//! (`docs/observation-plane.md`).
//!
//! The four instruments (the clock a program registers, the event log, the supervisor and the
//! resource snapshot) are wz's own: no upstream library has a counterpart, so a C program reaches
//! them through doors that each ABI names for itself (`wz_ext_*` in the pico ABI, `wz_capi_c_*`
//! in the zenoh-c one). The doors are thin on purpose. A door checks its pointers, calls the
//! function here and turns the answer into its ABI's result code; what the instrument does is
//! written once, so the ABIs cannot come to disagree about it.
//!
//! It is here, in the port, and not in an engine's crate, because an instrument is the node's and
//! not a session's: the cooperative engine, which has no `wz-capi-core`, hosts the same four.
//!
//! This module has no `z_` name, no `#[no_mangle]` and no result code, for the reason the rest of
//! this crate has none: both ABIs typedef their result to `int8_t` and then disagree about the
//! values, so returning one ABI's constant from shared code would be a wrong-code bug in the
//! other. A refusal is a [`Refusal`], and each ABI maps it.
//!
//! The callbacks a program hands in are the exception that proves the rule: their C signatures
//! are the same in every ABI (a function pointer taking the program's own `void *`), so the types
//! are named here, once, and each ABI's header spells them under its own prefix.

#[cfg(feature = "clock-source")]
pub mod clock;
#[cfg(feature = "event-ring")]
pub mod events;
#[cfg(feature = "resource-snapshot")]
pub mod snapshot;
#[cfg(feature = "supervision")]
pub mod supervision;

/// Why a door refused. The door turns it into its ABI's code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// An argument is not one the door takes: a handle that is not registered, an event or a
    /// checkpoint that does not exist, a timeout out of range.
    Invalid,
    /// A bounded thing has no room: the clocks are all registered, a full log refused an event, or
    /// the program's buffer is smaller than the record.
    Full,
    /// There is nothing to give yet, or the instrument would not do it now: no snapshot has been
    /// taken, a checkpoint that cannot be stopped.
    Unavailable,
}
