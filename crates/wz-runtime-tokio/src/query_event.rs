// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311dx — the consumer-facing query callback wrappers (`QueryEvent` +
//! `ReplyEmitter`) migrated to `wz-session-core::query_event`. This file
//! is the AP-side re-export shell: it re-exports the public surface so
//! consumers continue to write `wz_runtime_tokio::query_event::QueryEvent`
//! etc. across the reorg. Both wrappers are always-nameable in every
//! feature subset (a `query-queryable`-OFF `PhantomData` arm keeps the
//! structs well-formed); see the migrated module's doc-comment for the
//! wrapper design rationale + the no-op fall-through on the
//! `query-queryable`-OFF build.

pub use wz_session_core::query_event::{QueryEvent, ReplyEmitter};
