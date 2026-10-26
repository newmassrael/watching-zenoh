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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh 1.10.1, file
// src/lib.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1). Only the parts of that file
// that the landed slices need are here: the crate documentation, the modules and the re-exports
// arrive with the slices that give them something to describe.
#![cfg_attr(docsrs, feature(doc_cfg))]
// The documentation kept from upstream links to modules that later slices bring, so a link may not
// resolve until then (docs/zenoh-api-on-the-engine.md, section 6).
#![allow(rustdoc::broken_intra_doc_links)]

// The macros of `zenoh-result` (`bail!`, `zerror!`), which the configuration and the cancellation
// token of the `unstable` arm use; upstream takes them, and those of `zenoh-core`, for the whole
// crate, and each joins here with the first slice that calls it, so that a build that calls none
// does not carry an unused import.
#[macro_use]
extern crate zenoh_result;

mod api;

pub use zenoh_core::{Resolvable, Resolve, Wait};
/// A Zenoh error.
pub use zenoh_result::Error;
/// A Zenoh result.
pub use zenoh_result::ZResult as Result;
#[doc(inline)]
pub use zenoh_util::{init_log_from_env_or, try_init_log_from_env};

// Upstream's root also re-exports `scout`, `open` and `Session`, which arrive with the slices that
// give them a body.
#[doc(inline)]
pub use crate::config::Config;

/// # Payload primitives and encoding
///
/// The [`ZBytes`](crate::bytes::ZBytes) type is Zenoh's representation of raw byte data.
/// It provides mechanisms for zero-copy creation and access (`From<Vec<u8>>` and
/// [`ZBytes::slices`](crate::bytes::ZBytes::slices)), as well as methods for sequential
/// reading/writing ([`ZBytes::reader`](crate::bytes::ZBytes::reader), [`ZBytes::writer`](crate::bytes::ZBytes::writer)).
///
/// The `zenoh-ext` crate provides serialization and deserialization of basic types and structures for `ZBytes` via
/// [`z_serialize`](../../zenoh_ext/fn.z_serialize.html) and
/// [`z_deserialize`](../../zenoh_ext/fn.z_deserialize.html).
///
/// The module also provides the [`Encoding`](crate::bytes::Encoding) enum to specify the encoding of the payload.
///
/// # Examples
///
/// ### Creating ZBytes
/// ```
/// # #[tokio::main]
/// # async fn main() {
/// let zbytes = zenoh::bytes::ZBytes::from("Hello, world!");
/// # assert_eq!(zbytes.try_to_string().unwrap(), "Hello, world!");
/// # }
/// ```
///
/// ### Converting `ZBytes` to `String`
/// ```
/// # #[tokio::main]
/// # async fn main() {
/// # let zbytes = zenoh::bytes::ZBytes::from("Hello, world!");
/// let s = zbytes.try_to_string().unwrap();
/// assert_eq!(s, "Hello, world!");
/// # }
/// ```
///
/// ### Converting `ZBytes` to `Vec<u8>`
/// ```
/// # #[tokio::main]
/// # async fn main() {
/// # let zbytes = zenoh::bytes::ZBytes::from("Hello, world!");
/// let vec = zbytes.to_bytes();
/// assert_eq!(vec.as_ref(), b"Hello, world!");
/// # }
/// ```
pub mod bytes {
    pub use crate::api::{
        bytes::{OptionZBytes, ZBytes, ZBytesReader, ZBytesSliceIterator, ZBytesWriter},
        encoding::Encoding,
    };
}

/// Shared memory.
#[zenoh_macros::unstable]
#[cfg(feature = "shared-memory")]
pub mod shm {
    pub use zenoh_shm::api::{
        buffer::{
            traits::{
                BufferRelayoutError, OwnedShmBuf, ResideInShm, ShmBuf, ShmBufIntoImmut, ShmBufMut,
                ShmBufUnsafeMut,
            },
            typed::Typed,
            zshm::{zshm, ZShm},
            zshmmut::{zshmmut, ZShmMut},
        },
        cleanup::cleanup_orphaned_shm_segments,
        client::{shm_client::ShmClient, shm_segment::ShmSegment},
        client_storage::{ShmClientStorage, GLOBAL_CLIENT_STORAGE},
        common::{
            types::{ChunkID, ProtocolID, PtrInSegment, SegmentID},
            with_id::WithProtocolID,
        },
        protocol_implementations::posix::{
            posix_shm_client::PosixShmClient, posix_shm_provider_backend::*,
            posix_shm_provider_backend_binary_heap::*, posix_shm_provider_backend_buddy::*,
            posix_shm_provider_backend_talc::*,
        },
        provider::{
            chunk::{AllocatedChunk, ChunkDescriptor},
            memory_layout::{MemoryLayout, TypedLayout},
            shm_provider::{
                AllocBuilder, AllocPolicy, AsyncAllocPolicy, BlockOn, ConstBool, ConstPolicy,
                ConstUsize, Deallocate, Defragment, GarbageCollect, JustAlloc, PolicyValue,
                PrecomputedLayout, SafePolicy, ShmProvider, ShmProviderBuilder,
            },
            shm_provider_backend::ShmProviderBackend,
            types::{
                AllocAlignment, ChunkAllocResult, ZAllocError, ZLayoutAllocError, ZLayoutError,
            },
        },
    };

    // R3673: upstream's module ends with `pub use crate::net::runtime::ShmProviderState;`, the state
    // of a session's provider, which belongs to the session and so to slice Z7 of
    // docs/zenoh-api-on-the-engine.md; it joins this module there.
}

/// Functionality for interrupting queries.
#[zenoh_macros::unstable]
pub mod cancellation {
    pub use crate::api::cancellation::CancellationToken;
    #[cfg(feature = "internal")]
    pub use crate::api::cancellation::{SyncGroup, SyncGroupNotifier};
}

/// # Configuration to pass to [`open`] and [`scout`] functions and associated constants.
///
/// The [`Config`] object contains all parameters necessary to configure
/// a Zenoh session or the scouting process. Usually a configuration file is stored in the json or
/// yaml format and loaded using the [`Config::from_file`](crate::config::Config::from_file) method.
/// It's also possible to read or
/// modify individual elements of the `Config` with the
/// [`Config::insert_json5`](crate::config::Config::insert_json5)
/// and [`Config::get_json`](crate::config::Config::get_json) methods.
///
/// An example configuration file is available in the [`Config`] documentation section
/// and in the Zenoh repository as
/// [DEFAULT_CONFIG.json5](https://github.com/eclipse-zenoh/zenoh/blob/release/1.0.0/DEFAULT_CONFIG.json5)
///
/// # Example
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// use zenoh::config::Config;
/// use serde_json::json;
/// let mut config = Config::from_file("path/to/config.json5").unwrap();
/// config.insert_json5("scouting/multicast/enabled", &json!(false).to_string()).unwrap();
/// let session = zenoh::open(config).await.unwrap();
/// # }
pub mod config {
    pub use zenoh_config::{EndPoint, EndPoints, Locator, WhatAmI, WhatAmIMatcher, ZenohId};

    pub use crate::api::config::Config;
    #[zenoh_macros::unstable]
    pub use crate::api::config::Notifier;
}
