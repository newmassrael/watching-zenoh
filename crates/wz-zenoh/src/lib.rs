// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The public Rust API of the pinned `zenoh` crate (1.10.1), over watching-zenoh.
//!
//! A program that depends on `zenoh` switches to this crate by changing its dependency to
//! `zenoh = { package = "wz-zenoh", version = "1.10.1" }` and nothing else (inventory atom
//! `api-compat-rust`). Every public path here is upstream's, and only upstream's: the surface is
//! held to the one rustdoc JSON gives for upstream at the pin by
//! `scripts/lib/rust_api_surface.py`, which refuses a path upstream does not have and counts the
//! paths still missing. Nothing is public yet; each slice of the API arrives whole, with the
//! upstream examples that exercise it.
