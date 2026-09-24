// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The connection-retry period: how long a failed dial waits before the next
//! attempt, and how that wait grows.
//!
//! R2830 — the one transcription of zenoh's `ConnectionRetryConf` now lives in
//! `wz_session_core::retry_period`, because the MCU connection manager
//! re-dials on the same schedule and a second copy is exactly what this
//! module existed to prevent. It is re-exported here unchanged, so every path
//! that named `crate::retry_period::RetryPolicy` / `RetryPeriod` — the client
//! reconnect supervisor, the router peer auto-reconnect, the multicast
//! re-join, `session_open`, the config — names the same types as before. The
//! schedule's documentation and tests moved with it.

pub use wz_session_core::retry_period::{RetryPeriod, RetryPolicy};
