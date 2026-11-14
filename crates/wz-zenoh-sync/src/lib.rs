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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-sync 1.10.2, file
// src/lib.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

//! ⚠️ WARNING ⚠️
//!
//! This module is intended for Zenoh's internal use.
//!
//! [Click here for Zenoh's documentation](https://docs.rs/zenoh/latest/zenoh)
//!
//! The synchronisation primitives of the zenoh family (`zenoh-sync` 1.10.2), over watching-zenoh:
//! upstream's by name, version, library name and public paths (inventory atom `api-compat-rust`).
//! Two of upstream's items are not copied as they are, and each says why where it is:
//! [`get_mut_unchecked`] refuses a shared `Arc` where upstream's hands out an aliased `&mut`, and
//! [`Mvar`] counts a waiting taker or putter while it waits, where upstream's subtracts one it never
//! added when the value was there at once.
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures::FutureExt;

pub mod event;
pub use event::*;

pub mod fifo_queue;
pub use fifo_queue::*;

pub mod lifo_queue;
pub use lifo_queue::*;

pub mod object_pool;
pub use object_pool::*;

pub mod mvar;
pub use mvar::*;

pub mod condition;
pub use condition::*;

pub mod signal;
pub use signal::*;

pub mod cache;
pub use cache::*;

/// The value an `Arc` holds, mutably, for the one holder of it.
///
/// Upstream's reads through the `Arc`'s pointer whoever else holds it, which gives a `&mut` that
/// may alias another holder's reference, behaviour the language leaves undefined. This one is the
/// same call for a holder that is the only one, and panics, with the reason, for an `Arc` that is
/// shared: it never hands out a reference that aliases.
pub fn get_mut_unchecked<T>(arc: &mut std::sync::Arc<T>) -> &mut T {
    std::sync::Arc::get_mut(arc)
        .expect("get_mut_unchecked: the Arc is shared, so no `&mut` to its value is sound")
}

/// An alias for `Pin<Box<dyn Future<Output = T> + Send>>`.
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct PinBoxFuture<T>(Pin<Box<dyn Future<Output = T> + Send>>);

impl<T> std::fmt::Debug for PinBoxFuture<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PinBoxFuture").field(&"..").finish()
    }
}

impl<T> Future for PinBoxFuture<T> {
    type Output = T;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_unpin(cx)
    }
}

#[inline]
pub fn pinbox<T>(fut: impl Future<Output = T> + Send + 'static) -> PinBoxFuture<T> {
    PinBoxFuture(Box::pin(fut))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{get_mut_unchecked, pinbox};

    #[test]
    fn the_one_holder_of_an_arc_gets_its_value_mutably() {
        let mut held = Arc::new(3_u8);
        *get_mut_unchecked(&mut held) += 1;
        assert_eq!(*held, 4);
    }

    #[test]
    #[should_panic(expected = "the Arc is shared")]
    fn a_shared_arc_is_refused() {
        let mut held = Arc::new(3_u8);
        let _other = held.clone();
        let _ = get_mut_unchecked(&mut held);
    }

    #[tokio::test]
    async fn a_boxed_future_is_the_future_it_boxes() {
        assert_eq!(pinbox(async { 5_u8 }).await, 5);
    }
}
