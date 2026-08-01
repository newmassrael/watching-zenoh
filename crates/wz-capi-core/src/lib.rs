// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The ABI-neutral session model every wz C ABI sits on.
//!
//! ## Why this crate exists
//!
//! wz exports more than one C ABI. §5.27 `api-compat-pico` is zenoh-pico's;
//! `api-compat-c` is zenoh-c's. They are genuinely different ABIs — different
//! entry symbols, different type footprints (pico's owned session is 16 bytes,
//! zenoh-c's is 8), different ownership macros — over ONE session model:
//!
//! - a REGISTRY of per-face wz sessions, because a C session is "one session, N
//!   peers" while a wz unicast `Session` is exactly one peer;
//! - a DECLARATION SSOT replayed onto each face as it comes up, which is what
//!   makes declare-before-peer work;
//! - one OS thread per session running a tokio runtime that drives the whole
//!   lifecycle, because a C `z_open` returns while the read/lease work must
//!   continue in the background.
//!
//! That model used to live inside `wz-capi-pico`. Adding the second ABI made it
//! a choice between duplicating the model and generalising it, and duplicating
//! would have copied exactly the parts that are hardest to get right: the
//! race-free close (the stop latch is set BEFORE the notify, because a `Notify`
//! permit is single-use and `notify_waiters` would drop the wakeup) and the
//! drop-outside-the-lock discipline (releasing the last closure reference runs a
//! C `drop(context)`, which is allowed to re-enter the session). A second copy
//! would have drifted, and no test in the second crate could have seen it.
//!
//! ## What was ABI-specific, and how it was inverted
//!
//! One thing: the registry stored the C closure TYPES and called
//! `make_*_callback` to turn them into wz callbacks. That pointed the dependency
//! upward — a neutral model reaching into one specific ABI's closure shape.
//!
//! It is inverted through the three factory aliases in [`faces`]
//! ([`SubscriberSink`](faces::SubscriberSink),
//! [`LivelinessSink`](faces::LivelinessSink),
//! [`QueryableSink`](faces::QueryableSink)): the shim hands in something that
//! MINTS a callback, and nothing here learns what it closes over. A factory
//! rather than a ready-made callback because a callback is needed once per FACE
//! — every declaration is replayed onto each new face.
//!
//! The C drop semantics are unchanged by that: the factory owns whatever the
//! shim captured, so the last factory released still runs the C
//! `drop(context)`, which is why every release stays outside the registry lock.
//!
//! ## What is NOT here
//!
//! Anything with a `z_` in its name. No owned/loaned/moved structs, no
//! `#[no_mangle]`, no result codes — [`drive::OpenError`] exists precisely
//! because both ABIs typedef `z_result_t` to `int8_t` and then disagree about
//! the values, so returning one ABI's constant from shared code would be a
//! wrong-code bug in the other.

pub mod drive;
pub mod faces;
