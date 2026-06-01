// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Sample kind discriminant (`SampleKind`).
//!
//! R311gb-2 — hoisted out of the `alloc`-gated [`crate::sample`] module
//! to an unconditional home: it is a pure `Copy` enum (no allocation), and
//! the no-alloc [`crate::sink::SampleView`] accessor contract needs to
//! name it on every profile (`SampleView::kind`). [`crate::sample`]
//! re-exports it (`pub use crate::sample_kind::SampleKind`) so existing
//! `crate::sample::SampleKind` paths are unaffected. Sibling rationale to
//! [`crate::reliability`] (hoisted at R226 for the same reason).

/// Sample kind discriminant. Numeric values match zenoh-pico's
/// `z_sample_kind_t` (`vendor/zenoh-pico/include/zenoh-pico/api/constants.h`
/// lines 165-167) so any future wire-side extension that carries the
/// kind byte can serialize via `as u8` without translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum SampleKind {
    /// The sample carries data — the publisher called Put. zenoh-pico:
    /// `Z_SAMPLE_KIND_PUT`. R232 — designated `#[default]` so
    /// containers that derive `Default` and embed a `SampleKind` (e.g.
    /// `PublishOptions`) initialise the publish-the-common-case shape
    /// without a manual `impl Default`.
    #[default]
    Put = 0,
    /// The sample marks a key deletion — the publisher called Delete.
    /// zenoh-pico: `Z_SAMPLE_KIND_DELETE`.
    Del = 1,
}
