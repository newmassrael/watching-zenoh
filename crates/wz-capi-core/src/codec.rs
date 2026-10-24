// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The VLE (`zint`) integer codec both C ABIs serialize with, RE-EXPORTED from
//! [`wz_codecs::vle`] rather than held here.
//!
//! It lived here as the one implementation both ABIs call, and moved down to `wz-codecs` for the
//! reason the encoding id table did (R311y617): this crate sits on the tokio engine, and the pico
//! ABI over the cooperative engine (`docs/capi-pico-on-coop-engine.md`) has to reach the codec
//! without it. This is a re-export and NOT a copy: a second encoder whose only job is to agree
//! with a wire format is the shape that drifts silently.

pub use wz_codecs::vle::{decode_zint, encode_zint, zint_len, VLE_LEN};
