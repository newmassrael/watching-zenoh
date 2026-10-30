//
// Copyright (c) 2025 ZettaScale Technology
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
// src/api/builders/info_transport.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2). The
// builders hold the session they ask and not a runtime, because a session here is a handle over an
// engine (docs/zenoh-api-on-the-engine.md, decision D3), and a listener is declared through the
// session (`WeakSession::declare_transport_events_listener_inner`), which answers with the id of
// the listener and not with the entry of a table.

use std::future::{IntoFuture, Ready};

use tracing::error;
use zenoh_core::{Resolvable, Wait};
use zenoh_result::ZResult;

use crate::api::{
    cancellation::SyncGroup,
    handlers::{locked, Callback, DefaultHandler, IntoHandler},
    info::{Transport, TransportEvent},
    session::{UndeclarableSealed, WeakSession},
    Id,
};

/// A builder returned by [`SessionInfo::transports()`](crate::session::SessionInfo::transports).
///
/// The builder creates an iterator over the established [`Transport`](crate::session::Transport)s
/// of the session: one for each zenoh node it is connected to.
///
/// # Examples
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// let transports = session.info().transports().await;
/// for transport in transports {
///     println!("Transport: zid={}, whatami={:?}", transport.zid(), transport.whatami());
/// }
/// # }
/// ```
#[must_use = "Resolvables do nothing unless you resolve them using `.await` or `zenoh::Wait::wait`"]
pub struct TransportsBuilder<'a> {
    session: &'a WeakSession,
}

impl std::fmt::Debug for TransportsBuilder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TransportsBuilder").field(&"..").finish()
    }
}

impl<'a> TransportsBuilder<'a> {
    pub(crate) fn new(session: &'a WeakSession) -> Self {
        Self { session }
    }
}

impl Resolvable for TransportsBuilder<'_> {
    type To = Box<dyn Iterator<Item = Transport> + Send + Sync>;
}

impl Wait for TransportsBuilder<'_> {
    fn wait(self) -> Self::To {
        self.session.transports()
    }
}

impl IntoFuture for TransportsBuilder<'_> {
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Ready<<Self as Resolvable>::To>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(self.wait())
    }
}

pub(crate) struct TransportEventsListenerInner {
    pub(crate) session: WeakSession,
    pub(crate) id: Id,
    pub(crate) undeclare_on_drop: bool,
}

impl std::fmt::Debug for TransportEventsListenerInner {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("TransportEventsListenerInner")
            .field("id", &self.id)
            .field("undeclare_on_drop", &self.undeclare_on_drop)
            .finish()
    }
}

/// A listener that sends notifications when transport lifecycle events occur.
///
/// Call [`undeclare()`](TransportEventsListener::undeclare) to stop receiving events.
///
/// # Examples
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// use zenoh::sample::SampleKind;
///
/// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// let events = session.info()
///     .transport_events_listener()
///     .history(true)
///     .with(flume::bounded(32))
///     .await
///     .expect("Failed to declare transport events listener");
///
/// while let Ok(event) = events.recv_async().await {
///     match event.kind() {
///         SampleKind::Put => println!("Transport opened: {}", event.transport().zid()),
///         SampleKind::Delete => println!("Transport closed"),
///     }
/// }
///
/// // Cleanup
/// events.undeclare().await.unwrap();
/// # }
/// ```
pub struct TransportEventsListener<Handler> {
    pub(crate) inner: TransportEventsListenerInner,
    pub(crate) handler: Handler,
    pub(crate) callback_sync_group: SyncGroup,
}

impl<Handler> std::fmt::Debug for TransportEventsListener<Handler> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportEventsListener")
            .field("inner", &self.inner)
            .field("handler", &"..")
            .field("callback_sync_group", &self.callback_sync_group)
            .finish()
    }
}

impl<Handler> TransportEventsListener<Handler> {
    /// Undeclare the listener and stop receiving events.
    ///
    /// # Examples
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() {
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let events = session.info()
    ///     .transport_events_listener()
    ///     .with(flume::bounded(32))
    ///     .await
    ///     .expect("Failed to declare transport events listener");
    /// events.undeclare().await.unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn undeclare(self) -> TransportEventsListenerUndeclaration<Handler>
    where
        Handler: Send,
    {
        self.undeclare_inner(())
    }

    fn undeclare_impl(&mut self) -> ZResult<()> {
        // Set flag first to avoid double panic
        self.inner.undeclare_on_drop = false;
        self.inner
            .session
            .undeclare_transport_events_listener_inner(self.inner.id)
    }

    /// Returns a reference to this listener's handler.
    /// A handler is anything that implements [`IntoHandler`](crate::handlers::IntoHandler).
    /// The default handler is [`DefaultHandler`](crate::handlers::DefaultHandler).
    pub fn handler(&self) -> &Handler {
        &self.handler
    }

    /// Returns a mutable reference to this listener's handler.
    /// A handler is anything that implements [`IntoHandler`](crate::handlers::IntoHandler).
    /// The default handler is [`DefaultHandler`](crate::handlers::DefaultHandler).
    pub fn handler_mut(&mut self) -> &mut Handler {
        &mut self.handler
    }

    #[zenoh_macros::internal]
    pub fn set_background(&mut self, background: bool) {
        self.inner.undeclare_on_drop = !background;
    }
}

impl<Handler> Drop for TransportEventsListener<Handler> {
    fn drop(&mut self) {
        if self.inner.undeclare_on_drop {
            if let Err(error) = self.undeclare_impl() {
                error!(error);
            }
        }
    }
}

impl<Handler: Send> UndeclarableSealed<()> for TransportEventsListener<Handler> {
    type Undeclaration = TransportEventsListenerUndeclaration<Handler>;

    fn undeclare_inner(self, _: ()) -> Self::Undeclaration {
        TransportEventsListenerUndeclaration {
            listener: self,
            wait_callbacks: false,
        }
    }
}

impl<Handler> std::ops::Deref for TransportEventsListener<Handler> {
    type Target = Handler;

    fn deref(&self) -> &Self::Target {
        &self.handler
    }
}

impl<Handler> std::ops::DerefMut for TransportEventsListener<Handler> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handler
    }
}

/// A [`Resolvable`] returned by [`TransportEventsListener::undeclare`]
pub struct TransportEventsListenerUndeclaration<Handler> {
    listener: TransportEventsListener<Handler>,
    wait_callbacks: bool,
}

impl<Handler> std::fmt::Debug for TransportEventsListenerUndeclaration<Handler> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportEventsListenerUndeclaration")
            .field("listener", &self.listener)
            .field("wait_callbacks", &self.wait_callbacks)
            .finish()
    }
}

impl<Handler> TransportEventsListenerUndeclaration<Handler> {
    #[zenoh_macros::internal_or_unstable]
    /// Block in undeclare operation until all currently running instances of transport events listener callback (if any) return.
    pub fn wait_callbacks(mut self) -> Self {
        self.wait_callbacks = true;
        self
    }
}

impl<Handler> Resolvable for TransportEventsListenerUndeclaration<Handler> {
    type To = ZResult<()>;
}

impl<Handler> Wait for TransportEventsListenerUndeclaration<Handler> {
    fn wait(mut self) -> <Self as Resolvable>::To {
        self.listener.undeclare_impl()?;
        if self.wait_callbacks {
            self.listener.callback_sync_group.wait();
        }
        Ok(())
    }
}

impl<Handler> IntoFuture for TransportEventsListenerUndeclaration<Handler> {
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Ready<<Self as Resolvable>::To>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(self.wait())
    }
}

/// A builder returned by [`SessionInfo::transport_events_listener()`](crate::session::SessionInfo::transport_events_listener).
///
/// The builder creates a [`TransportEventsListener`](crate::session::TransportEventsListener) which sends
/// notifications when [`Transport`](crate::session::Transport)s are opened or closed.
///
/// # Examples
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// use zenoh::sample::SampleKind;
///
/// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// let events = session.info()
///     .transport_events_listener()
///     .history(true)
///     .with(flume::bounded(32))
///     .await
///     .expect("Failed to declare transport events listener");
///
/// while let Ok(event) = events.recv_async().await {
///     match event.kind() {
///         SampleKind::Put => println!("Transport opened: {}", event.transport().zid()),
///         SampleKind::Delete => println!("Transport closed"),
///     }
/// }
/// # }
/// ```
#[must_use = "Resolvables do nothing unless you resolve them using `.await` or `zenoh::Wait::wait`"]
pub struct TransportEventsListenerBuilder<'a, Handler, const BACKGROUND: bool = false> {
    session: &'a WeakSession,
    handler: Handler,
    history: bool,
}

impl<Handler, const BACKGROUND: bool> std::fmt::Debug
    for TransportEventsListenerBuilder<'_, Handler, BACKGROUND>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportEventsListenerBuilder")
            .field("session", &"..")
            .field("handler", &"..")
            .field("history", &self.history)
            .field("background", &BACKGROUND)
            .finish()
    }
}

impl<'a> TransportEventsListenerBuilder<'a, DefaultHandler> {
    pub(crate) fn new(session: &'a WeakSession) -> Self {
        Self {
            session,
            handler: DefaultHandler::default(),
            history: false,
        }
    }
}

impl<'a, Handler> TransportEventsListenerBuilder<'a, Handler> {
    /// Enable history.
    ///
    /// Send events for existing transports before live events.
    pub fn history(mut self, enabled: bool) -> Self {
        self.history = enabled;
        self
    }

    /// Use a custom handler (channel, callback, etc.)
    pub fn with<H>(self, handler: H) -> TransportEventsListenerBuilder<'a, H>
    where
        H: IntoHandler<TransportEvent>,
    {
        TransportEventsListenerBuilder {
            session: self.session,
            handler,
            history: self.history,
        }
    }

    /// Provide a callback to handle events
    pub fn callback<F>(
        self,
        callback: F,
    ) -> TransportEventsListenerBuilder<'a, Callback<TransportEvent>>
    where
        F: Fn(TransportEvent) + Send + Sync + 'static,
    {
        self.with(Callback::from(callback))
    }

    /// Provide a mutable callback which is never called concurrently. If the callback can be accepted by
    /// [`callback`](Self::callback), prefer using that instead for better performance.
    pub fn callback_mut<F>(
        self,
        callback: F,
    ) -> TransportEventsListenerBuilder<'a, Callback<TransportEvent>>
    where
        F: FnMut(TransportEvent) + Send + Sync + 'static,
    {
        self.callback(locked(callback))
    }
}

impl<'a> TransportEventsListenerBuilder<'a, Callback<TransportEvent>> {
    /// Run the listener in the background, automatically dropping the handler when done.
    ///
    /// # Examples
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() {
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// session.info()
    ///     .transport_events_listener()
    ///     .callback(|event| println!("Transport event: {:?}", event.kind()))
    ///     .background()
    ///     .await
    ///     .expect("Failed to declare background transport events listener");
    /// # }
    /// ```
    pub fn background(self) -> TransportEventsListenerBuilder<'a, Callback<TransportEvent>, true> {
        TransportEventsListenerBuilder {
            session: self.session,
            handler: self.handler,
            history: self.history,
        }
    }
}

impl<Handler> Resolvable for TransportEventsListenerBuilder<'_, Handler>
where
    Handler: IntoHandler<TransportEvent> + Send,
    Handler::Handler: Send,
{
    type To = ZResult<TransportEventsListener<Handler::Handler>>;
}

impl<Handler> Wait for TransportEventsListenerBuilder<'_, Handler>
where
    Handler: IntoHandler<TransportEvent> + Send,
    Handler::Handler: Send,
{
    fn wait(self) -> Self::To {
        let callback_sync_group = self.session.callback_group();
        let (callback, handler) = self.handler.into_handler();
        let id = self.session.declare_transport_events_listener_inner(
            callback,
            self.history,
            callback_sync_group.notifier(),
        )?;

        Ok(TransportEventsListener {
            inner: TransportEventsListenerInner {
                session: self.session.clone(),
                id,
                undeclare_on_drop: true,
            },
            handler,
            callback_sync_group,
        })
    }
}

impl<Handler> IntoFuture for TransportEventsListenerBuilder<'_, Handler>
where
    Handler: IntoHandler<TransportEvent> + Send,
    Handler::Handler: Send,
{
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Ready<<Self as Resolvable>::To>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(self.wait())
    }
}

impl Resolvable for TransportEventsListenerBuilder<'_, Callback<TransportEvent>, true> {
    type To = ZResult<()>;
}

impl Wait for TransportEventsListenerBuilder<'_, Callback<TransportEvent>, true> {
    fn wait(self) -> <Self as Resolvable>::To {
        self.session
            .declare_transport_events_listener_inner(self.handler, self.history, None)?;
        Ok(())
    }
}

impl IntoFuture for TransportEventsListenerBuilder<'_, Callback<TransportEvent>, true> {
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Ready<<Self as Resolvable>::To>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(self.wait())
    }
}
