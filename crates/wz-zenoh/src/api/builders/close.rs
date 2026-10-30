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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh 1.10.2, file
// src/api/builders/close.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2). Without the
// builder that runs a close in the background and its join handle, which upstream declares for the
// `internal` feature together with `unstable` and no arm of the surface gate reaches, and without
// the branch that panics on the two releases of the compiler (1.85.0 and 1.85.1) whose
// thread-local storage cannot be used at exit, which upstream's build script detects and which this
// workspace's compiler is newer than (docs/zenoh-api-on-the-engine.md, slice Z1).

use std::{
    fmt,
    future::{Future, IntoFuture},
    pin::Pin,
    time::Duration,
};

use async_trait::async_trait;
use zenoh_core::{Resolvable, Wait};
use zenoh_result::ZResult;
use zenoh_runtime::ZRuntime;

/// A builder for close operations, returned by the
/// [`Session::close`](crate::Session::close) method.
// NOTE: `Closeable` is only pub(crate) because it is a zenoh-internal trait, so we don't
// care about the `private_bounds` lint in this particular case.
#[allow(private_bounds)]
#[must_use = "Resolvables do nothing unless you resolve them using `.await` or `zenoh::Wait::wait`"]
pub struct CloseBuilder<TCloseable: Closeable> {
    closee: TCloseable::TClosee,
    timeout: Duration,
    close_args: <TCloseable::TClosee as Closee>::CloseArgs,
}

impl<TCloseable: Closeable> fmt::Debug for CloseBuilder<TCloseable> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloseBuilder")
            .field("closee", &"..")
            .field("timeout", &self.timeout)
            .field("close_args", &"..")
            .finish()
    }
}

// NOTE: `Closeable` is only pub(crate) because it is a zenoh-internal trait, so we don't
// care about the `private_bounds` lint in this particular case.
#[allow(private_bounds)]
impl<TCloseable: Closeable> CloseBuilder<TCloseable> {
    pub(crate) fn new(closeable: &'_ TCloseable) -> Self {
        Self {
            closee: closeable.get_closee(),
            timeout: Duration::from_secs(10),
            close_args: <TCloseable::TClosee as Closee>::CloseArgs::default(),
        }
    }
}

impl<TCloseable: Closeable> Resolvable for CloseBuilder<TCloseable> {
    type To = ZResult<()>;
}

impl<TCloseable: Closeable> Wait for CloseBuilder<TCloseable> {
    fn wait(self) -> Self::To {
        let future = self.into_future();
        match tokio::runtime::Handle::try_current() {
            Ok(_) => {
                tracing::trace!("tokio TLS available, closing closeable directly");
                ZRuntime::Net.block_in_place(future)
            }
            Err(e) if e.is_missing_context() => {
                tracing::trace!("tokio TLS is just missing, closing closeable directly");
                ZRuntime::Net.block_in_place(future)
            }
            Err(_) => {
                let evaluate = move || {
                    // NOTE: tracing logger also panics if used inside atexit() handler!!!
                    tracing::trace!(
                        "tokio TLS NOT available, closing closeable in separate thread"
                    );
                    ZRuntime::Net.block_in_place(future)
                };
                std::thread::spawn(evaluate)
                    .join()
                    .expect("Error spawning atexit-safe thread")
            }
        }
    }
}

impl<TCloseable: Closeable> IntoFuture for CloseBuilder<TCloseable> {
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Pin<Box<dyn Future<Output = <Self as IntoFuture>::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(
            async move {
                if tokio::time::timeout(self.timeout, self.closee.close_inner(self.close_args))
                    .await
                    .is_err()
                {
                    bail!("close operation timed out!")
                }
                Ok(())
            }
            .into_future(),
        )
    }
}

#[async_trait]
pub(crate) trait Closee: Send + Sync + 'static {
    type CloseArgs: Default + Send + Sync;
    async fn close_inner(&self, close_arg: Self::CloseArgs);
}

pub(crate) trait Closeable {
    type TClosee: Closee;
    fn get_closee(&self) -> Self::TClosee;
}

impl CloseBuilder<crate::Session> {
    #[zenoh_macros::internal_or_unstable]
    /// Block in undeclare operation until all currently running zenoh entities' callbacks (if any) return.
    pub fn wait_callbacks(mut self) -> Self {
        self.close_args.wait_callbacks = true;
        self
    }
}
