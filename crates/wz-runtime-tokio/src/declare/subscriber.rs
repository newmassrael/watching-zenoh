// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311do / di-15 — `RemoteSubscriberRegistry` migrated to
//! `wz-session-core::declare::subscriber`. This file is the AP-side
//! re-export shell: it re-exports the public surface so consumers
//! continue to write
//! `wz_runtime_tokio::declare::RemoteSubscriberRegistry` (via the
//! parent module's `pub use`) across the reorg.
//!
//! R311ds — the behavioural `#[cfg(test)] mod tests` block migrated to
//! wz-session-core next to the registry code (R311dr-wider-tests carry
//! closure); this shell now carries no test-only code.

pub use wz_session_core::declare::subscriber::{
    DeclSubscriberCallback, RemoteSubscriberRegistry, UndeclSubscriberCallback,
};
