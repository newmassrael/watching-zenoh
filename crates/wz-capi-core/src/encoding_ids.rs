// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The zenoh ENCODING id table, and the two conversions every ABI needs over it, RE-EXPORTED
//! rather than held here.
//!
//! The table index IS the wire value. It is a property of the zenoh protocol, not of either C
//! ABI: `zenoh-pico`'s `ENCODING_VALUES_ID_TO_STR` (`src/api/encoding.c:89`) and zenoh-c's
//! `Encoding` constants agree on it entry for entry, because a publisher on one and a subscriber
//! on the other have to mean the same thing by id 4. Two transcriptions of one wire table is
//! exactly the shape that drifts silently, so there is one, and every caller reads it.
//!
//! Both halves lived here and both moved down. R311y617 moved the table to
//! [`wz_codecs::encoding_ids`], so a `no_std` consumer (`wz-capture`'s payload sub-decoder) can
//! name the encoding a Put declares. The conversions and [`EncodingDialect`] moved to
//! [`wz_session_core::encoding_hint`], beside the
//! [`EncodingHint`](wz_session_core::sample::EncodingHint) they build, so the pico ABI
//! over the cooperative engine (`docs/capi-pico-on-coop-engine.md`) reaches them without the
//! tokio engine this crate sits on.
//!
//! These are re-exports and NOT copies: the pico oracle
//! (`wz-capi-pico/tests/pico_pure_function_oracle.rs`, which walks every entry through the real
//! `libzenohpico.so`) must keep pinning the constant every consumer actually reads.

pub use wz_codecs::encoding_ids::{
    lookup_id, ENCODING_ID_DEFAULT, ENCODING_ID_TO_STR, ENCODING_ID_UNKNOWN, SCHEMA_SEPARATOR,
};
pub use wz_session_core::encoding_hint::{
    hint_from_parts, hint_from_str, hint_from_str_in, hint_to_string, hint_to_string_in,
    EncodingDialect,
};
