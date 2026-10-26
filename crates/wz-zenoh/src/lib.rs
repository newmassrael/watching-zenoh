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

// The macros of `zenoh-core` (`zlock!`, `zconfigurable!`), which the handlers and the size of the
// channel they read use, and those of `zenoh-result` (`bail!`, `zerror!`), which the configuration,
// the handlers and the cancellation token of the `unstable` arm use; upstream takes them for the
// whole crate, and each joins here with the first slice that calls it, so that a build that calls
// none does not carry an unused import.
#[macro_use]
extern crate zenoh_core;
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

/// # Callback handler trait.
///
/// Zenoh allows two ways to get sequential data from Zenoh primitives, like
/// [`Subscriber`](crate::pubsub::Subscriber) or [`Query`](crate::query::Query)
///
/// 1. **Callback functions**: the user provides a callback function that is called with each
///    incoming sample.
///
/// 2. **Channels**: the user provides a channel that buffers incoming samples, and the user
///    retrieves samples from the channel when needed.
///
/// # ⚠️ Important Note
///
/// > **Warning**: The callback function is called in the context of the Zenoh runtime.
/// > Calling zenoh network operations from the callback (e.g., making queries)
/// > may lead to deadlocks and other unexpected behaviors.
/// >
/// > The Rust type system is not used to prevent calling zenoh network operations
/// > from the callback for two reasons:
/// > - this would be too restrictive for multithreaded scenarios
/// > - this may change in future releases in any direction: immediate crash or allowing
/// >  this behavior.
///
/// Below are the details of how channels work in Zenoh.
///
/// Under the hood, the sequential data from a primitive is always passed to a callback function.
/// However, to simplify using channels, Zenoh provides the
/// [`IntoHandler`](crate::handlers::IntoHandler) trait,
/// which returns a pair: a callback which pushes data to the channel and a "handler"
/// which allows retrieving data from the channel.
///
/// The method [`with`](crate::pubsub::SubscriberBuilder::with) accepts any type that
/// implements the `IntoHandler` trait and extracts the callback and handler from it.
/// The Zenoh object calls the callback with each incoming sample.
///
/// The handler is also stored in the Zenoh object. It's completely opaque to the Zenoh object;
/// it's just made available to the user via the [`handler`](crate::pubsub::Subscriber::handler) method
/// or by dereferencing, allowing the user to call the handler's methods directly on the
/// `Subscriber` or `Query` object.
/// This is syntactic sugar that allows the user not to care about the separate channel object.
///
/// The example of using channels is shown below.
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// # let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// let subscriber = session.declare_subscriber("key/expression")
///    .with(zenoh::handlers::RingChannel::new(10))
///   .await.unwrap();
/// while let Ok(sample) = subscriber.recv_async().await {
///    println!("Received: {:?}", sample);
/// }
/// # }
/// ```
///
/// Note that this code is equivalent to the following one, where the channel
/// and the callback are created explicitly.
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// # let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// use zenoh::handlers::IntoHandler;
/// let (callback, mut ring_channel_handler)
///    = zenoh::handlers::RingChannel::new(10).into_handler();
/// let subscriber = session.declare_subscriber("key/expression")
///    .with((callback, ())) // or simply .callback(callback)
///   .await.unwrap();
/// while let Ok(sample) = ring_channel_handler.recv_async().await {
///    println!("Received: {:?}", sample);
/// }
/// # }
/// ```
///
/// Obviously, the callback can also be defined manually, without using a channel, and passed
/// to the [`callback`](crate::pubsub::SubscriberBuilder::callback) method.
/// In this case, the handler type is `()`, and no additional methods, like `recv_async`, are available on the
/// subscriber object.
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// # let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// let subscriber = session.declare_subscriber("key/expression")
///    .callback(|sample| {
///        println!("Received: {:?}", sample);
///    }).await.unwrap();
/// # }
/// ```
///
pub mod handlers {
    #[zenoh_macros::internal]
    pub use crate::api::handlers::locked;
    #[zenoh_macros::internal]
    pub use crate::api::handlers::CallbackParameter;
    pub use crate::api::handlers::{
        Callback, CallbackDrop, DefaultHandler, FifoChannel, FifoChannelHandler, IntoHandler,
        RingChannel, RingChannelHandler,
    };
    /// The module contains helper types and traits necessary to work with FIFO channels
    pub mod fifo {
        pub use crate::api::handlers::{
            Drain, FifoChannel, FifoChannelHandler, IntoIter, Iter, RecvFut, RecvStream, TryIter,
        };
    }
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
