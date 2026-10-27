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

// Upstream's root also re-exports `scout`, which arrives with slice Z5.
#[doc(inline)]
pub use crate::{
    config::Config,
    session::{open, Session},
};

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

/// # Key Expressions
///
/// [Key expressions](https://github.com/eclipse-zenoh/roadmap/blob/main/rfcs/ALL/Key%20Expressions.md) are Zenoh's address space.
///
/// In Zenoh, operations are performed on keys. To allow addressing multiple keys with a single operation, Zenoh uses Key Expressions (KEs).
/// KEs are a small language that expresses sets of keys through a glob-like syntax.
///
/// These semantics can be a bit difficult to implement, so this module provides the following facilities:
///
/// # Storing Key Expressions
/// This module provides three ways to store strings that have been validated to respect the KE syntax:
/// - [`keyexpr`](crate::key_expr::keyexpr) is the equivalent of a [`str`],
/// - [`OwnedKeyExpr`](crate::key_expr::OwnedKeyExpr) works like an [`std::sync::Arc<str>`],
/// - [`KeyExpr`](crate::key_expr::KeyExpr) works like a [`std::borrow::Cow<str>`], but also stores some additional context internal to Zenoh to optimize
///   routing and network usage.
///
/// The key expression object can be created using the [`KeyExpr::new`](crate::key_expr::KeyExpr::new) method,
/// which validates the syntax of the provided string.
/// The [`KeyExpr::from_str_unchecked`](crate::key_expr::KeyExpr::from_str_unchecked) method allows to
/// accelerate the creation of key expressions when the user can guarantee that the provided string
/// respects the KE syntax. There is also the
/// [`Session::declare_keyexpr`](crate::session::Session::declare_keyexpr) method, which not only
/// declares the key expression, but also informs the Zenoh network of its existence, which can
/// accelerate routing.
///
/// All of these types implement [`Deref`](std::ops::Deref) to [`keyexpr`](crate::key_expr::keyexpr), which notably has methods to check whether a given key expression
/// [`intersects`](crate::key_expr::keyexpr::intersects) with another, or whether it [`includes`](crate::key_expr::keyexpr::includes) another.
///
/// # Tying values to Key Expressions
/// When storing values tied to Key Expressions, you might want something more specialized than a [`HashMap`](std::collections::HashMap) to respect
/// Key Expression semantics with high performance.
///
/// Enter [`KeTrees`](crate::key_expr::keyexpr_tree). These are data structures built to store KE–value pairs in a manner that supports the set semantics of KEs.
///
/// # Building and parsing Key Expressions
/// A common issue in REST APIs is assigning meaning to sections of the URL and respecting that API in a convenient manner.
/// The same issue arises naturally when designing a KE space, and [`KeFormat`](crate::key_expr::format::KeFormat) was designed to help with this,
/// both in constructing and parsing KEs that fit the formats you've defined.
///
/// [`kedefine`](crate::key_expr::format::kedefine) also lets you define formats at compile time, enabling a more performant—and, more importantly, safer and more convenient—use of said formats,
/// as the [`keformat`](crate::key_expr::format::keformat) and [`kewrite`](crate::key_expr::format::kewrite) macros will tell you if you're attempting to set fields of the format that do not exist.
///
/// # Example
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// let sensor = zenoh::key_expr::KeyExpr::new("robot/sensor").unwrap();
/// let sensor_temp = sensor.join("temp").unwrap();
/// let sensors = sensor.join("**").unwrap();
/// assert!(sensors.includes(&sensor_temp));
/// # }
/// ```
pub mod key_expr {
    #[zenoh_macros::unstable]
    pub mod keyexpr_tree {
        pub use zenoh_keyexpr::keyexpr_tree::{
            impls::KeyedSetProvider,
            support::{NonWild, UnknownWildness},
            IKeyExprTree, IKeyExprTreeMut, KeBoxTree,
        };
    }
    #[zenoh_macros::unstable]
    pub use zenoh_keyexpr::SetIntersectionLevel;
    pub use zenoh_keyexpr::{
        canon::Canonize, keyexpr, nonwild_keyexpr, OwnedKeyExpr, OwnedNonWildKeyExpr,
    };

    pub use crate::api::key_expr::{KeyExpr, KeyExprUndeclaration};
    // keyexpr format macro support
    #[zenoh_macros::unstable]
    pub mod format {
        pub use zenoh_keyexpr::format::*;
        pub use zenoh_macros::{ke, kedefine, keformat, kewrite};
        pub mod macro_support {
            pub use zenoh_keyexpr::format::macro_support::*;
        }
    }
}

/// # Query/reply primitives
///
/// This module provides the query/reply API of Zenoh. Of it, the selector, its parameters and the
/// time range they carry are here; the rest of the module arrives with the slices that give a
/// query, a queryable and a reply a body.
///
/// The selector syntax is a key expression followed by a question mark and the list of parameters in
/// the format "name=value" separated by ';'. For example `key/expression?param1=value1;param2=value2`.
pub mod query {
    pub use zenoh_protocol::core::Parameters;
    #[zenoh_macros::unstable]
    pub use zenoh_util::time_range::{TimeBound, TimeExpr, TimeRange};

    pub use crate::api::selector::Selector;
    #[zenoh_macros::unstable]
    pub use crate::api::selector::ZenohParameters;
}

/// # Sample primitives
///
/// The [`Sample`](crate::sample::Sample) structure is the data unit received
/// by [`Subscriber`](crate::pubsub::Subscriber) or [`Querier`](crate::query::Querier)
/// or [`Session::get`]. It contains the payload and all metadata associated with the data.
///
/// The module contains the definitions of the `Sample` itself, definitions of
/// types of its fields, and builders to create the sample.
///
/// In practice, users do not need to create samples manually, as they are created
/// by the Zenoh runtime when data is published or replied to a query. But sometimes
/// it's useful to create samples, for example, for the simulation of data reception,
/// so the [`SampleBuilder`](crate::sample::SampleBuilder) is provided.
///
/// The [`SampleFields`](crate::sample::SampleFields) structure contains `Sample`
/// fields as public members, unlike the `Sample` itself where fields are private.
/// This allows deconstructing a sample to fields without cloning, which is more efficient
/// than using getter methods.
pub mod sample {
    #[zenoh_macros::unstable]
    pub use crate::api::sample::{SourceInfo, SourceSn};
    pub use crate::api::{
        builders::sample::{
            SampleBuilder, SampleBuilderAny, SampleBuilderDelete, SampleBuilderPut,
        },
        sample::{Locality, Sample, SampleFields, SampleKind},
    };
}

/// # Quality of service primitives
///
/// This module provides types and enums to configure the quality of service (QoS) of Zenoh
/// operations, such as reliability and congestion control.
/// These parameters can be set via the corresponding builder methods, e.g.,
/// [`reliability`](crate::pubsub::PublisherBuilder::reliability),
/// [`priority`](crate::pubsub::PublisherBuilder::priority) or
/// [`congestion_control`](crate::pubsub::PublisherBuilder::congestion_control).
///
/// # Example
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// # let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// let publisher = session.declare_publisher("key/expression")
///   .reliability(zenoh::qos::Reliability::Reliable)
///   .priority(zenoh::qos::Priority::InteractiveHigh)
///   .congestion_control(zenoh::qos::CongestionControl::Block)
///   .await.unwrap();
/// # }
///
pub mod qos {
    pub use zenoh_protocol::core::CongestionControl;
    #[zenoh_macros::unstable]
    pub use zenoh_protocol::core::Reliability;

    pub use crate::api::publisher::Priority;
}

/// Timestamp instrumentation for Zenoh messages.
///
/// Timestamp instrumentation allows you to track the temporal path of a message
/// as it travels through the Zenoh topology. By enabling one or more
/// *interception points*, timestamps are recorded at each matching node and
/// accumulated into a **timestamp stack** carried alongside the message.
///
/// # Interception Points
///
/// | Point | Where recorded | Meaning |
/// |-------|---------------|---------|
/// | [`Send`](crate::timestamp_stack::InterceptionPoint::Send) | Data source | Message leaves the application |
/// | [`Route`](crate::timestamp_stack::InterceptionPoint::Route) | Routing layer of any instance | Message transits the routing layer |
/// | [`Receive`](crate::timestamp_stack::InterceptionPoint::Receive) | Data receiver | Message arrives at the application |
///
/// Records are appended in traversal order. For example, in a routed
/// client→router→client topology with all three points enabled, a subscriber
/// will receive a stack ordered: `Send → Route → Route → Route → Receive`.
///
/// # Timestamp Sources
///
/// By default, each interception point records a Zenoh [UHLC] timestamp.
/// Alternatively, you can register a custom callback on the session via
/// [`OpenBuilder::with_timestamp_callback`](crate::api::builders::session::OpenBuilder::with_timestamp_callback)
/// to produce arbitrary timestamp formats.
///
/// # Usage
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// use zenoh::timestamp_stack::{
///     InstrumentationTimestamp, InterceptionPoint, TimestampInstrumentationBuilder,
/// };
///
/// // Build an instrumentation config: record at send and receive.
/// let instr = TimestampInstrumentationBuilder::new()
///     .set_send(true)
///     .set_receive(true)
///     .build()
///     .unwrap();
///
/// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// let publisher = session.declare_publisher("key/expr").await.unwrap();
/// let subscriber = session.declare_subscriber("key/expr").await.unwrap();
///
/// publisher
///     .put("payload")
///     .timestamp_instrumentation(instr)
///     .await
///     .unwrap();
///
/// let sample = subscriber.recv_async().await.unwrap();
/// if let Some(stack) = sample.timestamp_stack() {
///     for record in stack.records() {
///         println!("{:?} at {:?}", record.point(), record.timestamp());
///     }
/// }
/// # }
/// ```
///
/// [UHLC]: https://github.com/eclipse-zenoh/uhlc-rs
#[zenoh_macros::unstable]
pub mod timestamp_stack {
    pub use crate::api::timestamp_stack::{
        InstrumentationTimestamp, InterceptionPoint, TimestampContext, TimestampInstrumentation,
        TimestampInstrumentationBuilder, TimestampStack, TimestampStackRecord,
    };
}

/// What zenoh's own crates and the language bindings reach into. Of it the traits of the builders
/// are here, which the builders of a sample implement; the rest (the runtime, the plugins, the
/// helpers re-exported from the family's crates) arrives with the slices that give them a body.
#[zenoh_macros::internal]
pub mod internal {
    pub mod traits {
        pub use crate::api::builders::sample::{
            EncodingBuilderTrait, QoSBuilderTrait, SampleBuilderTrait, TimestampBuilderTrait,
            TimestampInstrumentationBuilderTrait,
        };
    }
}

/// Timestamp support
///
/// Each [`Sample`](crate::sample::Sample) has an optional [`Timestamp`](crate::time::Timestamp) associated with it.
/// The timestamp can be set using the
/// [`PublicationBuilder::timestamp`](crate::pubsub::PublicationBuilder::timestamp) method when performing a
/// [`put`](crate::pubsub::Publisher::put) operation or by
/// [`ReplyBuilder::timestamp`](crate::query::ReplyBuilder::timestamp) when replying to a query with
/// [`reply`](crate::query::Query::reply).
///
/// The timestamp consists of the time value itself and a unique
/// [clock](https://docs.rs/uhlc/latest/uhlc/) identifier. Each
/// [`Session`] has its own clock. The [`new_timestamp`](crate::session::Session::new_timestamp)
/// method can be used to create a new timestamp with the session's identifier.
///
/// # Examples
/// Sending a value with a timestamp
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// # use zenoh::time::Timestamp;
/// # let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// # let publisher = session.declare_publisher("key/expression").await.unwrap();
/// let timestamp = session.new_timestamp();
/// publisher.put("value").timestamp(timestamp).await.unwrap();
/// # }
/// ```
///
/// Receiving a value with a timestamp
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// # let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// # let subscriber = session.declare_subscriber("key/expression").await.unwrap();
/// while let Ok(sample) = subscriber.recv_async().await {
///     if let Some(timestamp) = sample.timestamp() {
///         println!("Received value with timestamp: {}", timestamp.to_string_rfc3339_lossy());
///     }
/// }
/// # }
/// ```
pub mod time {
    pub use zenoh_protocol::core::{Timestamp, TimestampId, NTP64};
}

/// # Publish/subscribe primitives
///
/// The builders of a publication and of a publisher. Of upstream's module the publisher, the
/// subscriber, their undeclarations and the builders that resolve into them arrive with slices Z2c
/// and Z2d (docs/zenoh-api-on-the-engine.md).
pub mod pubsub {
    pub use crate::api::builders::publisher::{
        PublicationBuilder, PublicationBuilderDelete, PublicationBuilderPut, PublisherBuilder,
    };
}

/// # Zenoh [`Session`] and associated types
///
/// The [`Session`] is the main component of Zenoh. It holds the zenoh runtime object,
/// which maintains the state of the connection of the node to the Zenoh network.
///
/// The session allows declaring other zenoh entities like publishers, subscribers, queriers, queryables, etc.
/// and keeps them functioning. Closing the session will close all associated entities.
///
/// The session is cloneable so it's easy to share it between tasks and threads. Each clone of the
/// session is an `Arc` to the internal session object, so cloning is cheap and fast.
///
/// A Zenoh session is instantiated using [`zenoh::open`](crate::open)
/// with parameters specified in the [`Config`] object.
///
/// Of this module the identifiers of a session and of its entities are here; the session itself,
/// its builders and its information arrive with slice Z1 of docs/zenoh-api-on-the-engine.md.
pub mod session {
    #[zenoh_macros::unstable]
    pub use zenoh_config::wrappers::EntityGlobalId;
    pub use zenoh_config::wrappers::ZenohId;
    #[zenoh_macros::unstable]
    pub use zenoh_protocol::core::EntityId;

    // Of upstream's module the builder of a get, the link and transport events and `WeakSession`
    // arrive with the slices Z3 and Z6a.
    pub use crate::api::{
        builders::{
            close::CloseBuilder,
            info::{PeersZenohIdBuilder, RoutersZenohIdBuilder, ZenohIdBuilder},
            publisher::{SessionDeleteBuilder, SessionPutBuilder},
            session::OpenBuilder,
        },
        info::SessionInfo,
        session::{open, Session, SessionClosedError, Undeclarable},
    };
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
