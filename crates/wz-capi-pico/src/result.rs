// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `z_result_t` — the pico return-code type.
//!
//! zenoh-pico declares `typedef int8_t z_result_t;`
//! (`include/zenoh-pico/utils/result.h:35`), with `Z_OK = 0`
//! (`_Z_RES_OK = 0`) and `_Z_ERR_GENERIC = -128` / `_Z_ERR_NULL = -127`.
//! Every exported function returning a status returns this `i8`, so a C
//! caller's `if (z_open(...) < 0)` check works unchanged.

/// The pico status type: `int8_t`.
pub type ZResult = i8;

/// Success. Matches pico `Z_OK` / `_Z_RES_OK`.
pub const Z_OK: ZResult = 0;

/// Generic failure. Matches pico `_Z_ERR_GENERIC` (`utils/result.h:101`).
pub const Z_ERR_GENERIC: ZResult = -128;

/// A required argument was NULL. Matches pico `_Z_ERR_NULL`
/// (`utils/result.h:100`).
pub const Z_ERR_NULL: ZResult = -127;

/// An argument was non-NULL but otherwise invalid (bad UTF-8, malformed
/// endpoint string, etc.). Round 1 collapses the pico fine-grained error
/// taxonomy onto this single "invalid argument" code; exact per-call code
/// parity is a follow-up refinement.
pub const Z_ERR_INVALID: ZResult = -1;

/// A reply keyexpr is not covered by the query it answers. Matches pico
/// `_Z_ERR_KEYEXPR_NOT_MATCH` (`utils/result.h:63`) EXACTLY, rather than
/// collapsing onto [`Z_ERR_INVALID`]: this is the one code a queryable is
/// expected to branch on (`z_query_reply` is the only place pico raises it,
/// `src/net/primitives.c:439`), so a C program that checks for it must see it.
pub const Z_ERR_KEYEXPR_NOT_MATCH: ZResult = -108;
