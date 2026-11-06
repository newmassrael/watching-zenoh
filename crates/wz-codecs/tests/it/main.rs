// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The integration tests of this crate, as ONE test executable.
//!
//! Every file of `files/` was a test file of `tests/` and so an executable of its own,
//! linked against the whole dependency tree; they are modules of this one now, and the test of a
//! file is `files::<name>::<test>` (`cargo test --test it files::<name>::` runs one file). The
//! files that must be their own process (a global allocator, a test table that sets more than the
//! features a file requires) stay in `tests/`. A file that required features carries them as an
//! inner `cfg` attribute at its top. See `scripts/lib/merge_tests.py`.

mod files;
