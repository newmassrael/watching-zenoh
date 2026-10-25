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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-shm 1.10.1, file
// src/api/client/shm_segment.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

use std::fmt::Debug;

use zenoh_result::ZResult;

use crate::api::common::types::ChunkID;

/// ShmSegment - RAII interface to interact with particular shared memory segment
#[zenoh_macros::unstable_doc]
pub trait ShmSegment: Debug + Send + Sync {
    /// Obtain the actual region of memory identified by it's id
    #[zenoh_macros::unstable_doc]
    fn map(&self, chunk: ChunkID) -> ZResult<*mut u8>;
}
