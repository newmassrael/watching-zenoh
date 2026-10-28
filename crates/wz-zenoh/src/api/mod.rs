//
// Copyright (c) 2024 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh 1.10.1, file
// src/api/mod.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1). Only the modules of the
// slices that have landed are declared here.

/// The number an entity declared on a session is known by.
pub(crate) type Id = u32;

// R3706: `SampleBuilder::qos` and the timestamp instrumentation trait are used by the builders of a
// reply and of the timestamp stack, which are slices Z3 and Z6b of docs/zenoh-api-on-the-engine.md.
#[allow(dead_code)]
pub(crate) mod builders;
pub(crate) mod bytes;
// R3681: the token's users, the builders of `get` that take it, are slice Z3 of
// docs/zenoh-api-on-the-engine.md; until they land the helpers upstream calls from there are unused.
#[allow(dead_code)]
pub(crate) mod cancellation;
// R3688: the notifier's user, `Session::config`, is slice Z1 of docs/zenoh-api-on-the-engine.md;
// until it lands a build without `unstable`, which exports the notifier, holds it unused.
#[allow(dead_code)]
pub(crate) mod config;
pub(crate) mod encoding;
// R3699: the builder of `get` is slice Z3 of docs/zenoh-api-on-the-engine.md; until it lands the
// helpers upstream calls from there (`set_on_drop`, `call_with_message`, and `CallbackParameter`
// outside `internal`) are unused. The builder of `declare_subscriber` has used the rest since Z2c.
#[allow(dead_code)]
pub(crate) mod handlers;
pub(crate) mod info;
pub(crate) mod liveliness;
pub(crate) mod matching;
pub(crate) mod publisher;
pub(crate) mod querier;
pub(crate) mod query;
pub(crate) mod queryable;
// R3706: the sample's remaining user, the reply, is slice Z3; until it lands the constructor from a
// frame (`from_push`) has no caller.
#[allow(dead_code)]
pub(crate) mod sample;
// R3702: the session declares and undeclares a key since slice Z2a, and the builders of a
// publication and a subscription use what a key puts on the wire since Z2b and Z2c; `to_wire_local`
// is used by the builder of `get`, slice Z3, so until then it has no caller.
#[allow(dead_code)]
pub(crate) mod key_expr;
pub(crate) mod scouting;
#[cfg(feature = "shared-memory")]
pub(crate) mod shm;
// R3702: the selector's users, the builders of `get` and the querier, are slice Z3.
#[allow(dead_code)]
pub(crate) mod selector;
pub(crate) mod session;
pub(crate) mod subscriber;
// R3706: the instrumentation of a frame at a node (`push_ts_interception`) is slice Z6b.
#[cfg(feature = "unstable")]
#[allow(dead_code)]
pub(crate) mod timestamp_stack;
