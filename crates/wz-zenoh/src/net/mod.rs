//
// Copyright (c) 2023 ZettaScale Technology
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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh 1.10.2, file
// src/net/mod.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2). Only the module that a
// public item of the crate is re-exported from is kept; the routing, the primitives and the
// protocol of upstream's `net` are the engine's (docs/zenoh-api-on-the-engine.md, slice Z7a).

//! What upstream names `zenoh::net`, which the crate does not publish: the path a public item of
//! the crate is re-exported from, so that the surface the crate states says the same thing.

#[doc(hidden)]
pub mod runtime;
