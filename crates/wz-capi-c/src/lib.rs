// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
pub mod bytes;
pub mod config;
mod ffi;
pub mod keyexpr;
pub mod log;
pub mod platform;
pub mod put;
pub mod result;
pub mod sample;
pub mod session;
pub mod string;
pub mod sub;
