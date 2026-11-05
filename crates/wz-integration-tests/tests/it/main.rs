// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The integration tests of this crate, as ONE test executable.
//!
//! Every file of `files/` was a `tests/<name>.rs` of its own and so an executable of its own,
//! linked against the whole dependency tree; they are modules of this one now, and the test of a
//! file is `files::<name>::<test>` (`cargo test --test it files::<name>::` runs one file). The
//! files that must be their own process (a global allocator, a `[[test]]` table) stay in `tests/`.
//! See `scripts/lib/merge_tests.py`.

mod files;
