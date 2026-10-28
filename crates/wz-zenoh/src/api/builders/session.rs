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
// src/api/builders/session.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1). Without the
// option that belongs to a later slice (`with_shm_clients`, slice Z7) and without `init`, the
// plugins' door to a runtime that another session already holds, which is `internal` and names a
// runtime this crate does not have (docs/zenoh-api-on-the-engine.md, slice Z1).

#[cfg(feature = "shared-memory")]
use std::sync::Arc;
use std::{
    fmt,
    future::{IntoFuture, Ready},
};

use zenoh_core::{Resolvable, Wait};
use zenoh_result::ZResult;
#[cfg(feature = "shared-memory")]
use zenoh_shm::api::client_storage::ShmClientStorage;

use crate::api::session::Session;
#[cfg(feature = "unstable")]
use crate::api::timestamp_stack::{GetTimestampCallback, TimestampContext};

/// A builder returned by [`crate::open`] used to open a zenoh [`Session`].
///
/// # Examples
/// ```
/// # #[tokio::main]
/// # async fn main() {
///
/// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// # }
/// ```
#[must_use = "Resolvables do nothing unless you resolve them using `.await` or `zenoh::Wait::wait`"]
pub struct OpenBuilder<TryIntoConfig>
where
    TryIntoConfig: std::convert::TryInto<crate::config::Config> + Send + 'static,
    <TryIntoConfig as std::convert::TryInto<crate::config::Config>>::Error: std::fmt::Debug,
{
    config: TryIntoConfig,
    #[cfg(feature = "shared-memory")]
    shm_clients: Option<Arc<ShmClientStorage>>,
    #[cfg(feature = "unstable")]
    timestamp_callback: Option<GetTimestampCallback>,
}

impl<TryIntoConfig> fmt::Debug for OpenBuilder<TryIntoConfig>
where
    TryIntoConfig: std::convert::TryInto<crate::config::Config> + Send + 'static,
    <TryIntoConfig as std::convert::TryInto<crate::config::Config>>::Error: std::fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("OpenBuilder");
        debug.field("config", &"..");
        debug.finish()
    }
}

impl<TryIntoConfig> OpenBuilder<TryIntoConfig>
where
    TryIntoConfig: std::convert::TryInto<crate::config::Config> + Send + 'static,
    <TryIntoConfig as std::convert::TryInto<crate::config::Config>>::Error: std::fmt::Debug,
{
    pub(crate) fn new(config: TryIntoConfig) -> Self {
        Self {
            config,
            #[cfg(feature = "shared-memory")]
            shm_clients: None,
            #[cfg(feature = "unstable")]
            timestamp_callback: None,
        }
    }
}

#[cfg(feature = "shared-memory")]
impl<TryIntoConfig> OpenBuilder<TryIntoConfig>
where
    TryIntoConfig: std::convert::TryInto<crate::config::Config> + Send + 'static,
    <TryIntoConfig as std::convert::TryInto<crate::config::Config>>::Error: std::fmt::Debug,
{
    /// Open the session with `shm_clients`, the clients that read the shared memory segments of
    /// the peers, in place of the global storage of the process.
    ///
    /// The session of this crate negotiates no shared memory with its peers yet, so no segment is
    /// read through them: the session keeps them for the transport that will (see slice Z7 of
    /// `docs/zenoh-api-on-the-engine.md`).
    pub fn with_shm_clients(mut self, shm_clients: Arc<ShmClientStorage>) -> Self {
        self.shm_clients = Some(shm_clients);
        self
    }
}

#[cfg(feature = "unstable")]
impl<TryIntoConfig> OpenBuilder<TryIntoConfig>
where
    TryIntoConfig: std::convert::TryInto<crate::config::Config> + Send + 'static,
    <TryIntoConfig as std::convert::TryInto<crate::config::Config>>::Error: std::fmt::Debug,
{
    /// Set a custom timestamp callback for timestamp stack instrumentation.
    ///
    /// The callback will be called at each interception point (Send, Route, Receive)
    /// when the timestamp stack feature is activated.
    ///
    /// If no callback is provided, the default UHLC timestamp generation will be used.
    #[zenoh_macros::unstable]
    pub fn with_timestamp_callback<F: Fn(TimestampContext) -> Vec<u8> + Send + Sync + 'static>(
        mut self,
        cb: F,
    ) -> Self {
        self.timestamp_callback = Some(Box::new(cb));
        self
    }
}

impl<TryIntoConfig> Resolvable for OpenBuilder<TryIntoConfig>
where
    TryIntoConfig: std::convert::TryInto<crate::config::Config> + Send + 'static,
    <TryIntoConfig as std::convert::TryInto<crate::config::Config>>::Error: std::fmt::Debug,
{
    type To = ZResult<Session>;
}

impl<TryIntoConfig> Wait for OpenBuilder<TryIntoConfig>
where
    TryIntoConfig: std::convert::TryInto<crate::config::Config> + Send + 'static,
    <TryIntoConfig as std::convert::TryInto<crate::config::Config>>::Error: std::fmt::Debug,
{
    fn wait(self) -> <Self as Resolvable>::To {
        let config: crate::config::Config = self
            .config
            .try_into()
            .map_err(|e| zerror!("Invalid Zenoh configuration {:?}", &e))?;
        Session::open(
            config,
            #[cfg(feature = "unstable")]
            self.timestamp_callback,
            #[cfg(feature = "shared-memory")]
            self.shm_clients,
        )
    }
}

impl<TryIntoConfig> IntoFuture for OpenBuilder<TryIntoConfig>
where
    TryIntoConfig: std::convert::TryInto<crate::config::Config> + Send + 'static,
    <TryIntoConfig as std::convert::TryInto<crate::config::Config>>::Error: std::fmt::Debug,
{
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Ready<<Self as Resolvable>::To>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(self.wait())
    }
}
