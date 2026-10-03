// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host-portable subset of the zenohd interop corpus.
//!
//! This crate has no code of its own: Cargo needs a package to have a library
//! target, and the tests are in `tests/`. The harness they use is
//! `wz_integration_tests::common`, deliberately not copied here. See `Cargo.toml`
//! for why the tests live in a crate of their own.
