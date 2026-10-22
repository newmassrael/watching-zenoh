// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A state machine built under a session id that is a constant of this tree.
//!
//! SCE's generated constructors take the id a host names for a machine and refuse a text
//! that is not an XML Nmtoken (`SessionIdRefusal`). Every id this crate passes is a
//! constant, so the refusal cannot be met, and the call sites said so with
//! `.expect("... is a constant Nmtoken")`.
//!
//! `expect` formats the error it is handed. `SessionIdRefusal` carries the offending
//! `char` and prints it with `{:?}`, so each such `expect` linked `char`'s `Debug`, the
//! Unicode tables behind it (`grapheme_extend`) and the refusal's own messages into the
//! image: about 2.5 KB of text on the multicast image, for a branch no run can take. The
//! refusal is dropped here without being formatted, and the stop names the machine.

use sce_rust_runtime::helpers::session_id::SessionIdRefusal;

/// The machine `built` constructed, or a stop naming `what` when the constant id was
/// refused (which no constant of this tree can be).
#[inline]
pub fn built_under_constant_id<T>(built: Result<T, SessionIdRefusal>, what: &'static str) -> T {
    match built {
        Ok(machine) => machine,
        Err(_) => constant_id_refused(what),
    }
}

/// The stop is one call out of line, so the success path carries no message.
#[cold]
#[inline(never)]
fn constant_id_refused(what: &'static str) -> ! {
    panic!("{what}: the session id is a constant of this tree and was refused")
}
