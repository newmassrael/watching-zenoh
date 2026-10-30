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
// src/net/runtime/mod.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2). Only
// `ShmProviderState` is kept, over the receiver the provider is made behind in `api::shm`; the
// runtime of upstream is the engine's (docs/zenoh-api-on-the-engine.md, slice Z7a).

//! The state of the shared memory provider of a session (upstream's `net::runtime`, which the
//! crate re-exports as `zenoh::shm::ShmProviderState`).

use std::{future::Future, sync::Arc};

use zenoh_core::{Resolvable, Wait};
use zenoh_shm::api::{
    protocol_implementations::posix::posix_shm_provider_backend::PosixShmProviderBackend,
    provider::shm_provider::ShmProvider,
};

/// State of current lazily-initialized [`ShmProvider`](ShmProvider) associated with the session.
#[derive(Debug)]
pub enum ShmProviderState {
    /// The configuration of the session does not ask for a provider.
    Disabled,
    /// The provider is being made, on a thread of its own; resolve this to wait for it.
    Initializing(flume::Receiver<Option<Arc<ShmProvider<PosixShmProviderBackend>>>>),
    /// The provider is there.
    Ready(Arc<ShmProvider<PosixShmProviderBackend>>),
    /// The provider could not be made.
    Error,
}

impl ShmProviderState {
    /// The provider if it is [`Ready`](ShmProviderState::Ready) and `None` in any other state,
    /// without waiting for it.
    pub fn into_option(self) -> <Self as Resolvable>::To {
        match self {
            ShmProviderState::Ready(provider) => Some(provider),
            _ => None,
        }
    }
}

impl Resolvable for ShmProviderState {
    type To = Option<Arc<ShmProvider<PosixShmProviderBackend>>>;
}

impl Wait for ShmProviderState {
    fn wait(self) -> <Self as Resolvable>::To {
        match self {
            ShmProviderState::Ready(provider) => Some(provider),
            ShmProviderState::Initializing(receiver) => receiver.recv().ok().flatten(),
            ShmProviderState::Disabled | ShmProviderState::Error => None,
        }
    }
}

impl std::future::IntoFuture for ShmProviderState {
    type Output = <Self as Resolvable>::To;
    type IntoFuture =
        std::pin::Pin<Box<dyn Future<Output = <Self as std::future::IntoFuture>::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            match self {
                ShmProviderState::Ready(provider) => Some(provider),
                ShmProviderState::Initializing(receiver) => {
                    receiver.recv_async().await.ok().flatten()
                }
                ShmProviderState::Disabled | ShmProviderState::Error => None,
            }
        })
    }
}
