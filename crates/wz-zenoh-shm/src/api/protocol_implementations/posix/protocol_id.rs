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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-shm 1.10.2, file
// src/api/protocol_implementations/posix/protocol_id.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

use crate::api::common::types::ProtocolID;

/// Protocol identifier to use when creating ShmProvider
#[zenoh_macros::unstable_doc]
pub const POSIX_PROTOCOL_ID: ProtocolID = 0;
