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
// src/api/builders/info_links.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2). The
// builders hold the session they ask and not a runtime, because a session here is a handle over an
// engine (docs/zenoh-api-on-the-engine.md, decision D3), and a listener is declared through the
// session (`WeakSession::declare_link_events_listener_inner`), which answers with the id of the
// listener and not with the entry of a table.

use std::future::{IntoFuture, Ready};

use tracing::error;
use zenoh_core::{Resolvable, Wait};
use zenoh_result::ZResult;

use crate::api::{
    cancellation::SyncGroup,
    handlers::{locked, Callback, DefaultHandler, IntoHandler},
    info::{Link, LinkEvent, Transport},
    session::{UndeclarableSealed, WeakSession},
    Id,
};

/// A builder returned by [`SessionInfo::links()`](crate::session::SessionInfo::links).
///
/// The builder creates an iterator over the established [`Link`](crate::session::Link)s
/// within the session.
/// Multiple [`Link`](crate::session::Link) can be established between two zenoh nodes within
/// the same [`Transport`](crate::session::Transport).
/// By default all links are returned, but you can filter them by transport using
/// the [`transport()`](LinksBuilder::transport) method.
///
/// # Examples
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// let links = session.info().links().await;
/// for link in links {
///     println!("Link: {} -> {}", link.src(), link.dst());
/// }
/// # }
/// ```
#[must_use = "Resolvables do nothing unless you resolve them using `.await` or `zenoh::Wait::wait`"]
pub struct LinksBuilder<'a> {
    session: &'a WeakSession,
    transport: Option<Transport>,
}

impl std::fmt::Debug for LinksBuilder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinksBuilder")
            .field("session", &"..")
            .field("transport", &self.transport)
            .finish()
    }
}

impl<'a> LinksBuilder<'a> {
    pub(crate) fn new(session: &'a WeakSession) -> Self {
        Self {
            session,
            transport: None,
        }
    }

    /// Filter links by transport.
    ///
    /// # Examples
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() {
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let transports = session.info().transports().await;
    /// if let Some(transport) = transports.into_iter().next() {
    ///     let links = session.info().links().transport(transport).await;
    ///     for link in links {
    ///         println!("Link: {} -> {}", link.src(), link.dst());
    ///     }
    /// }
    /// # }
    /// ```
    pub fn transport(mut self, transport: Transport) -> Self {
        self.transport = Some(transport);
        self
    }
}

impl Resolvable for LinksBuilder<'_> {
    type To = Box<dyn Iterator<Item = Link> + Send + Sync>;
}

impl Wait for LinksBuilder<'_> {
    fn wait(self) -> Self::To {
        self.session.links(self.transport.as_ref())
    }
}

impl IntoFuture for LinksBuilder<'_> {
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Ready<<Self as Resolvable>::To>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(self.wait())
    }
}

pub(crate) struct LinkEventsListenerInner {
    pub(crate) session: WeakSession,
    pub(crate) id: Id,
    pub(crate) undeclare_on_drop: bool,
}

impl std::fmt::Debug for LinkEventsListenerInner {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("LinkEventsListenerInner")
            .field("id", &self.id)
            .field("undeclare_on_drop", &self.undeclare_on_drop)
            .finish()
    }
}

/// A listener that sends notifications when link lifecycle events occur.
///
/// Call [`undeclare()`](LinkEventsListener::undeclare) to stop receiving events.
///
/// # Examples
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// use zenoh::sample::SampleKind;
///
/// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// let listener = session.info()
///     .link_events_listener()
///     .history(true)
///     .with(flume::bounded(32))
///     .await
///     .expect("Failed to declare link events listener");
///
/// while let Ok(event) = listener.recv_async().await {
///     match event.kind() {
///         SampleKind::Put => println!("Link added: {} -> {}",
///             event.link().src(), event.link().dst()),
///         SampleKind::Delete => println!("Link removed"),
///     }
/// }
///
/// // Cleanup
/// listener.undeclare().await.unwrap();
/// # }
/// ```
pub struct LinkEventsListener<Handler> {
    pub(crate) inner: LinkEventsListenerInner,
    pub(crate) handler: Handler,
    pub(crate) callback_sync_group: SyncGroup,
}

impl<Handler> std::fmt::Debug for LinkEventsListener<Handler> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkEventsListener")
            .field("inner", &self.inner)
            .field("handler", &"..")
            .field("callback_sync_group", &self.callback_sync_group)
            .finish()
    }
}

impl<Handler> LinkEventsListener<Handler> {
    /// Undeclare the listener and stop receiving events.
    ///
    /// # Examples
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() {
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let listener = session.info()
    ///     .link_events_listener()
    ///     .with(flume::bounded(32))
    ///     .await
    ///     .expect("Failed to declare link events listener");
    /// listener.undeclare().await.unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn undeclare(self) -> LinkEventsListenerUndeclaration<Handler>
    where
        Handler: Send,
    {
        self.undeclare_inner(())
    }

    fn undeclare_impl(&mut self) -> ZResult<()> {
        // Set flag first to avoid double panic
        self.inner.undeclare_on_drop = false;
        // Call session's undeclare method with the stored id
        self.inner
            .session
            .undeclare_link_events_listener_inner(self.inner.id)
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

impl<Handler> Drop for LinkEventsListener<Handler> {
    fn drop(&mut self) {
        if self.inner.undeclare_on_drop {
            if let Err(error) = self.undeclare_impl() {
                error!(error);
            }
        }
    }
}

impl<Handler: Send> UndeclarableSealed<()> for LinkEventsListener<Handler> {
    type Undeclaration = LinkEventsListenerUndeclaration<Handler>;

    fn undeclare_inner(self, _: ()) -> Self::Undeclaration {
        LinkEventsListenerUndeclaration {
            listener: self,
            wait_callbacks: false,
        }
    }
}

impl<Handler> std::ops::Deref for LinkEventsListener<Handler> {
    type Target = Handler;

    fn deref(&self) -> &Self::Target {
        &self.handler
    }
}

impl<Handler> std::ops::DerefMut for LinkEventsListener<Handler> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handler
    }
}

/// A [`Resolvable`] returned by [`LinkEventsListener::undeclare`]
pub struct LinkEventsListenerUndeclaration<Handler> {
    listener: LinkEventsListener<Handler>,
    wait_callbacks: bool,
}

impl<Handler> std::fmt::Debug for LinkEventsListenerUndeclaration<Handler> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkEventsListenerUndeclaration")
            .field("listener", &self.listener)
            .field("wait_callbacks", &self.wait_callbacks)
            .finish()
    }
}

impl<Handler> Resolvable for LinkEventsListenerUndeclaration<Handler> {
    type To = ZResult<()>;
}

impl<Handler> LinkEventsListenerUndeclaration<Handler> {
    #[zenoh_macros::internal_or_unstable]
    /// Block in undeclare operation until all currently running instances of link events listener callback (if any) return.
    pub fn wait_callbacks(mut self) -> Self {
        self.wait_callbacks = true;
        self
    }
}

impl<Handler> Wait for LinkEventsListenerUndeclaration<Handler> {
    fn wait(mut self) -> <Self as Resolvable>::To {
        self.listener.undeclare_impl()?;
        if self.wait_callbacks {
            self.listener.callback_sync_group.wait();
        }
        Ok(())
    }
}

impl<Handler> IntoFuture for LinkEventsListenerUndeclaration<Handler> {
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Ready<<Self as Resolvable>::To>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(self.wait())
    }
}

/// A builder returned by [`SessionInfo::link_events_listener()`](crate::session::SessionInfo::link_events_listener).
///
/// The builder creates a [`LinkEventsListener`](crate::session::LinkEventsListener) which sends notifications
/// when new [`Link`](crate::session::Link) are created or removed.
///
/// # Examples
/// ```no_run
/// # #[tokio::main]
/// # async fn main() {
/// use zenoh::sample::SampleKind;
///
/// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// let listener = session.info()
///     .link_events_listener()
///     .history(true)
///     .with(flume::bounded(32))
///     .await
///     .expect("Failed to declare link events listener");
///
/// while let Ok(event) = listener.recv_async().await {
///     match event.kind() {
///         SampleKind::Put => println!("Link added: {} -> {}",
///             event.link().src(), event.link().dst()),
///         SampleKind::Delete => println!("Link removed"),
///     }
/// }
/// # }
/// ```
#[must_use = "Resolvables do nothing unless you resolve them using `.await` or `zenoh::Wait::wait`"]
pub struct LinkEventsListenerBuilder<'a, Handler, const BACKGROUND: bool = false> {
    session: &'a WeakSession,
    handler: Handler,
    history: bool,
    transport: Option<Transport>,
}

impl<Handler, const BACKGROUND: bool> std::fmt::Debug
    for LinkEventsListenerBuilder<'_, Handler, BACKGROUND>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkEventsListenerBuilder")
            .field("session", &"..")
            .field("handler", &"..")
            .field("history", &self.history)
            .field("transport", &self.transport)
            .field("background", &BACKGROUND)
            .finish()
    }
}

impl<'a> LinkEventsListenerBuilder<'a, DefaultHandler> {
    pub(crate) fn new(session: &'a WeakSession) -> Self {
        Self {
            session,
            handler: DefaultHandler::default(),
            history: false,
            transport: None,
        }
    }
}

impl<'a, Handler> LinkEventsListenerBuilder<'a, Handler> {
    /// Enable history.
    ///
    /// Send events for existing links before live events.
    pub fn history(mut self, enabled: bool) -> Self {
        self.history = enabled;
        self
    }

    /// Use a custom handler (channel, callback, etc.)
    pub fn with<H>(self, handler: H) -> LinkEventsListenerBuilder<'a, H>
    where
        H: IntoHandler<LinkEvent>,
    {
        LinkEventsListenerBuilder {
            session: self.session,
            handler,
            history: self.history,
            transport: self.transport,
        }
    }

    /// Filter link events by transport.
    ///
    /// # Examples
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() {
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let transports = session.info().transports().await;
    /// if let Some(transport) = transports.into_iter().next() {
    ///     let listener = session.info()
    ///         .link_events_listener()
    ///         .transport(transport)
    ///         .with(flume::bounded(32))
    ///         .await;
    /// }
    /// # }
    /// ```
    pub fn transport(mut self, transport: Transport) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Provide a callback to handle events
    pub fn callback<F>(self, callback: F) -> LinkEventsListenerBuilder<'a, Callback<LinkEvent>>
    where
        F: Fn(LinkEvent) + Send + Sync + 'static,
    {
        self.with(Callback::from(callback))
    }

    /// Provide a mutable callback which is never called concurrently. If the callback can be accepted by
    /// [`callback`](Self::callback), prefer using that instead for better performance.
    pub fn callback_mut<F>(self, callback: F) -> LinkEventsListenerBuilder<'a, Callback<LinkEvent>>
    where
        F: FnMut(LinkEvent) + Send + Sync + 'static,
    {
        self.callback(locked(callback))
    }
}

impl<'a> LinkEventsListenerBuilder<'a, Callback<LinkEvent>> {
    /// Run the listener in the background, automatically dropping the handler when done.
    ///
    /// # Examples
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() {
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// session.info()
    ///     .link_events_listener()
    ///     .callback(|event| println!("Link event: {:?}", event.kind()))
    ///     .background()
    ///     .await
    ///     .expect("Failed to declare background link events listener");
    /// # }
    /// ```
    pub fn background(self) -> LinkEventsListenerBuilder<'a, Callback<LinkEvent>, true> {
        LinkEventsListenerBuilder {
            session: self.session,
            handler: self.handler,
            history: self.history,
            transport: self.transport,
        }
    }
}

impl<Handler> Resolvable for LinkEventsListenerBuilder<'_, Handler>
where
    Handler: IntoHandler<LinkEvent> + Send,
    Handler::Handler: Send,
{
    type To = ZResult<LinkEventsListener<Handler::Handler>>;
}

impl<Handler> Wait for LinkEventsListenerBuilder<'_, Handler>
where
    Handler: IntoHandler<LinkEvent> + Send,
    Handler::Handler: Send,
{
    fn wait(self) -> Self::To {
        let callback_sync_group = self.session.callback_group();
        let (callback, handler) = self.handler.into_handler();
        let id = self.session.declare_link_events_listener_inner(
            callback,
            self.history,
            self.transport,
            callback_sync_group.notifier(),
        )?;

        Ok(LinkEventsListener {
            inner: LinkEventsListenerInner {
                session: self.session.clone(),
                id,
                undeclare_on_drop: true,
            },
            handler,
            callback_sync_group,
        })
    }
}

impl<Handler> IntoFuture for LinkEventsListenerBuilder<'_, Handler>
where
    Handler: IntoHandler<LinkEvent> + Send,
    Handler::Handler: Send,
{
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Ready<<Self as Resolvable>::To>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(self.wait())
    }
}

impl Resolvable for LinkEventsListenerBuilder<'_, Callback<LinkEvent>, true> {
    type To = ZResult<()>;
}

impl Wait for LinkEventsListenerBuilder<'_, Callback<LinkEvent>, true> {
    fn wait(self) -> <Self as Resolvable>::To {
        self.session.declare_link_events_listener_inner(
            self.handler,
            self.history,
            self.transport,
            None,
        )?;
        Ok(())
    }
}

impl IntoFuture for LinkEventsListenerBuilder<'_, Callback<LinkEvent>, true> {
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Ready<<Self as Resolvable>::To>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(self.wait())
    }
}
