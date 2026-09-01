// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` — a zenoh-c-compatible C ABI over the wz AP session.
//!
//! ## What "drop-in" means here, and how it is checked
//!
//! A program written for zenoh-c, compiled against UPSTREAM's unmodified
//! `zenoh.h`, links this cdylib and runs. Nothing in this crate ships a header;
//! zenoh-c's is cbindgen OUTPUT, so it IS the ABI, and a wz-authored header would
//! make the claim untestable by construction. (Its sibling `wz-capi-pico` shipped
//! its own header in R1 and deferred the exact layout match — a route this crate
//! deliberately does not take.)
//!
//! Two things are therefore checked by artifacts wz does not own:
//!
//! - the C compiler and linker, against upstream's header and an upstream
//!   PROGRAM;
//! - the real `libzenohc.so`, as a REFERENCE arm — the same binary, linked
//!   against upstream's implementation, must behave the same.
//!
//! The reference arm is what this crate has and its sibling does not. Upstream's
//! examples establish that the program is REPRESENTATIVE (it calls what a real
//! program calls, not what wz happens to export); the reference arm establishes
//! that wz's answers are EQUIVALENT, which linking alone cannot show.
//!
//! ## Slice 1
//!
//! The scope is an upstream PROGRAM, not a symbol list: `examples/z_put.c` links
//! and runs. The 12 symbols it needs were measured with `nm -u`, and that
//! distinction earned its keep immediately — a list drafted by hand beforehand
//! had four symbols zenoh-c never calls and was missing three it does, including
//! [`zc_init_log_from_env_or`](log::zc_init_log_from_env_or), which nothing about
//! implementing a put would suggest.
//!
//! Of the 29 upstream examples, 22 compile against this installation's header
//! (the other 7 need `Z_FEATURE_SHARED_MEMORY` / unstable APIs the installed
//! `libzenohc.so` was not built with — a property of the oracle build, not of
//! wz), and their union is 156 distinct symbols. This slice implements the
//! smallest complete one. The lane REPORTS the ratio every run, so partial
//! coverage stays visible rather than implied.
//!
//! ## The session model is shared, not copied
//!
//! Everything below the ABI — the face registry, the declaration SSOT replayed
//! per face, the drive thread and its race-free close — is
//! [`wz_capi_core`](wz_capi_core), the same code the zenoh-pico ABI runs on. Two
//! ABIs, one model; see that crate's docs for why duplicating it was the worse
//! option.

// zenoh-c's type names are snake_case (`z_sample_kind_t`,
// `z_closure_sample_callback_t`); reproducing the ABI names VERBATIM is the
// whole claim of this crate, so the camel-case convention does not apply to its
// surface. Its sibling `wz-capi-pico` carries the same allow for the same
// reason. Until R311y500 the crate compiled without it by accident — every
// snake_case name it had came out of `define_opaque!`, and the lint does not
// fire on macro-generated identifiers — so this is not a relaxation of what was
// being enforced.
#![allow(non_camel_case_types)]

pub mod abi;
// WHERE each footprint in `abi` comes from, as data rather than as a comment.
// Separate module because the two answer different questions and rot at
// different rates: `abi` is the layout, this is its provenance, and only the
// latter is checked against upstream's own declaration of the correspondence.
pub mod abi_origin;
// The `ze_advanced_*` plane is `#if defined(Z_FEATURE_UNSTABLE_API)` in
// upstream's header, so it exists on the unstable arms and nowhere else. The
// `cfg` mirrors upstream's `#if` rather than exporting symbols a program
// compiled against the no-unstable header could never name — and it is what
// makes the layout table's unstable half measurable, since on that arm there is
// no upstream size to compare against.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
pub mod advanced;
pub mod bytes;
pub mod config;
pub mod encoding;
mod ffi;
pub mod get;
pub mod handlers;
pub mod keyexpr;
pub mod liveliness;
pub mod log;
pub mod matching;
pub mod platform;
pub mod publisher;
pub mod put;
pub mod querier;
pub mod query;
pub mod result;
pub mod sample;
pub mod scout;
pub mod serde;
pub mod session;
// The SHM provider / buffer plane is
// `#if (defined(Z_FEATURE_SHARED_MEMORY) && defined(Z_FEATURE_UNSTABLE_API))`
// upstream, so it carries the same two-feature gate. On any other arm its
// symbols would name types no header declares.
#[cfg(all(
    feature = "zenoh-c-shared-memory",
    not(feature = "zenoh-c-no-unstable-api")
))]
pub mod shm;
pub mod slice;
/// R311y563 — the zenoh-c `source_info` owned family (§5.27): the
/// `z_owned_source_info_t` / loaned / moved trio plus its seven functions, and
/// what the six option structs' `source_info` fields were waiting on.
///
/// UNSTABLE-gated, because upstream gates every one of them: the option fields
/// sit behind `#if defined(Z_FEATURE_UNSTABLE_API)` and so do
/// `z_source_info_new` / `_id` / `_sn` / `_loan` / `_drop` /
/// `z_internal_source_info_*` / `z_sample_source_info`
/// (`zenoh_commons.h:4410, 5189-5223`). The y536 rule — a symbol's cfg is the
/// OR of every arm that uses it — read forwards: every user here is gated, so
/// the module is.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
pub mod source_info;
pub mod string;
pub mod sub;
pub mod sync;
/// R311y568 — the THREAD family (`z_owned_task_t` and its four operations), the
/// last of upstream's C-shaped concurrency helpers this crate did not export.
/// Its mutex and condvar siblings are [`crate::sync`].
pub mod task;
pub mod timestamp;
/// R311y573 — zenoh-ext's DEPRECATED standalone families
/// (`ze_publication_cache` / `ze_querying_subscriber`). Upstream declares BOTH
/// behind `#if defined(Z_FEATURE_UNSTABLE_API)` (`zenoh_commons.h:6083,6101,
/// 6120,6350-6371,6400-6435,6727-6737`) and its archive build exports neither,
/// so this module carries the same gate. Without it wz would OVER-export 18
/// symbols on the no-unstable arm — the direction R311y570's reverse census
/// exists to catch, and the y536 rule read forwards: every user of the option
/// structs' unstable fields is gated, so the module is.
#[cfg(not(feature = "zenoh-c-no-unstable-api"))]
pub mod zenoh_ext;
pub mod zid;
