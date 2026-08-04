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

/// A channel `recv` found the channel closed and drained. Matches pico
/// `_Z_RES_CHANNEL_CLOSED` / `Z_CHANNEL_DISCONNECTED` = 1
/// (`utils/result.h:40-41`).
///
/// POSITIVE, unlike every error below: pico's channel loop is
/// `while (z_recv(..) == Z_OK)`, so a channel that ends must not read as a
/// failure to a caller testing `< 0`.
pub const Z_RES_CHANNEL_CLOSED: ZResult = 1;

/// A channel `try_recv` found the channel open but empty. Matches pico
/// `_Z_RES_CHANNEL_NODATA` / `Z_CHANNEL_NODATA` = 2 (`utils/result.h:42-43`).
pub const Z_RES_CHANNEL_NODATA: ZResult = 2;

/// Generic failure. Matches pico `_Z_ERR_GENERIC` (`utils/result.h:101`).
pub const Z_ERR_GENERIC: ZResult = -128;

/// A refcount increment passed pico's lazy `INT32_MAX` bound. Matches pico
/// `_Z_ERR_OVERFLOW` (`utils/result.h:96`).
pub const Z_ERR_OVERFLOW: ZResult = -74;

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
