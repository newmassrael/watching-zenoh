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
// R3699: the handlers' users, the builders of `declare_subscriber` and `get`, are slices Z2 and Z3 of
// docs/zenoh-api-on-the-engine.md; until they land the helpers upstream calls from there
// (`set_on_drop`, `call_with_message`, and `locked` and `CallbackParameter` outside `internal`) are
// unused.
#[allow(dead_code)]
pub(crate) mod handlers;
// R3702: the session's declaration of a key (`declare`, `to_wire`) and `KeyExprUndeclaration::new`
// are slice Z1 of docs/zenoh-api-on-the-engine.md, and the anchor is implemented there; until then
// the functions that take it have no caller.
#[allow(dead_code)]
pub(crate) mod key_expr;
// R3702: the selector's users, the builders of `get` and the querier, are slice Z3.
#[allow(dead_code)]
pub(crate) mod selector;
pub(crate) mod session;
