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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-core 1.10.2, file
// src/lib.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

//! The resolve traits and the helper macros of the zenoh family (`zenoh-core` 1.10.2), over
//! watching-zenoh.
//!
//! This crate is upstream's by name, version, library name and public surface (inventory atom
//! `api-compat-rust`). A builder of the family is resolved by awaiting it, or by [`Wait::wait`] in a
//! synchronous context; [`Resolvable`], [`Wait`] and [`Resolve`] are the traits that say so, and the
//! crates that implement them for their own builders (`zenoh`, `zenoh-ext`) meet this one.

pub use lazy_static::lazy_static;
pub mod macros;

use std::future::{Future, IntoFuture, Ready};

// Re-exports after moving ZError/ZResult to zenoh-result
pub use zenoh_result::{bail, to_zerror, zerror};
/// The contents of `zenoh-result`, under the name this crate has always exposed them by.
pub mod zresult {
    pub use zenoh_result::*;
}
pub use zresult::{Error, ZResult as Result};

/// A resolvable execution, either sync or async.
pub trait Resolvable {
    /// What resolving it gives.
    type To: Sized;
}

/// Trick used to mark `<Resolve as IntoFuture>::IntoFuture` bound as Send.
#[doc(hidden)]
pub trait IntoSendFuture: Resolvable {
    type IntoFuture: Future<Output = Self::To> + Send;
}

impl<T> IntoSendFuture for T
where
    T: Resolvable + IntoFuture<Output = Self::To>,
    T::IntoFuture: Send,
{
    type IntoFuture = T::IntoFuture;
}

/// Synchronous execution of a resolvable.
pub trait Wait: Resolvable {
    /// Synchronously execute and wait.
    fn wait(self) -> Self::To;
}

/// Zenoh's trait for resolving builder patterns.
///
/// Builder patterns in Zenoh can be resolved by awaiting them, in async context,
/// and [`Wait::wait`] in sync context.
/// We advise to prefer the usage of asynchronous execution, and to use synchronous one with caution
#[must_use = "Resolvables do nothing unless you resolve them using `.await` or `zenoh::Wait::wait`"]
pub trait Resolve<Output>:
    Resolvable<To = Output>
    + Wait
    + IntoSendFuture
    + IntoFuture<IntoFuture = <Self as IntoSendFuture>::IntoFuture, Output = Output>
    + Send
{
}

impl<T, Output> Resolve<Output> for T where
    T: Resolvable<To = Output>
        + Wait
        + IntoSendFuture
        + IntoFuture<IntoFuture = <Self as IntoSendFuture>::IntoFuture, Output = Output>
        + Send
{
}

/// A closure to wait on: resolving it runs the closure.
#[must_use = "Resolvables do nothing unless you resolve them using `.await` or `zenoh::Wait::wait`"]
pub struct ResolveClosure<C, To>(C)
where
    To: Sized + Send,
    C: FnOnce() -> To + Send;

impl<C, To> std::fmt::Debug for ResolveClosure<C, To>
where
    To: Sized + Send,
    C: FnOnce() -> To + Send,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ResolveClosure").field(&"..").finish()
    }
}

impl<C, To> ResolveClosure<C, To>
where
    To: Sized + Send,
    C: FnOnce() -> To + Send,
{
    /// A resolvable that runs `c`.
    pub fn new(c: C) -> Self {
        Self(c)
    }
}

impl<C, To> Resolvable for ResolveClosure<C, To>
where
    To: Sized + Send,
    C: FnOnce() -> To + Send,
{
    type To = To;
}

impl<C, To> IntoFuture for ResolveClosure<C, To>
where
    To: Sized + Send,
    C: FnOnce() -> To + Send,
{
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Ready<<Self as Resolvable>::To>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(self.wait())
    }
}

impl<C, To> Wait for ResolveClosure<C, To>
where
    To: Sized + Send,
    C: FnOnce() -> To + Send,
{
    fn wait(self) -> <Self as Resolvable>::To {
        self.0()
    }
}

/// A future to wait on: awaiting it is the future, and `wait` blocks on it on the application
/// runtime of `zenoh-runtime`.
#[must_use = "Resolvables do nothing unless you resolve them using `.await` or `zenoh::Wait::wait`"]
pub struct ResolveFuture<F, To>(F)
where
    To: Sized + Send,
    F: Future<Output = To> + Send;

impl<F, To> std::fmt::Debug for ResolveFuture<F, To>
where
    To: Sized + Send,
    F: Future<Output = To> + Send,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ResolveFuture").field(&"..").finish()
    }
}

impl<F, To> ResolveFuture<F, To>
where
    To: Sized + Send,
    F: Future<Output = To> + Send,
{
    /// A resolvable that is `f`.
    pub fn new(f: F) -> Self {
        Self(f)
    }
}

impl<F, To> Resolvable for ResolveFuture<F, To>
where
    To: Sized + Send,
    F: Future<Output = To> + Send,
{
    type To = To;
}

impl<F, To> IntoFuture for ResolveFuture<F, To>
where
    To: Sized + Send,
    F: Future<Output = To> + Send,
{
    type Output = To;
    type IntoFuture = F;

    fn into_future(self) -> Self::IntoFuture {
        self.0
    }
}

impl<F, To> Wait for ResolveFuture<F, To>
where
    To: Sized + Send,
    F: Future<Output = To> + Send,
{
    fn wait(self) -> <Self as Resolvable>::To {
        zenoh_runtime::ZRuntime::Application.block_in_place(self.0)
    }
}

pub use zenoh_result::{likely, unlikely};

/// Re-definitions of inaccessible [`std`] items for MSRV compatibility.
///
/// These definitions are likely to cause `incompatible_msrv` warnings from clippy,
/// see <https://github.com/rust-lang/rust-clippy/issues/12280>.
pub mod polyfill {
    // NOTE: `Option::is_none_or` was stabilized in 1.82.0 > 1.75.0
    /// `Option::is_none_or`.
    #[allow(clippy::wrong_self_convention)]
    pub trait OptionExt<T>: Sized {
        /// Whether this is `None`, or `f` holds of what it contains.
        fn is_none_or(self, f: impl FnOnce(T) -> bool) -> bool;
    }

    impl<T> OptionExt<T> for Option<T> {
        fn is_none_or(self, f: impl FnOnce(T) -> bool) -> bool {
            match self {
                None => true,
                Some(x) => f(x),
            }
        }
    }
}

/// Asserts that the LHS expression implies the RHS expression.
///
/// Note that in logic, `p ⟹ q` is equivalent to `¬p ∨ q` (i.e. `!p || q`).
#[macro_export]
macro_rules! debug_assert_implies {
    ($lhs:expr, $rhs:expr) => {
        debug_assert!(!$lhs || $rhs)
    };
}

/// Panics with the given message in debug mode or logs an error otherwise.
#[macro_export]
macro_rules! bug {
    ($msg:literal) => {
        if cfg!(debug_assertions) {
            assert!(false, $msg);
        } else {
            tracing::error!(target: "zenoh::bug", $msg);
        }
    };
}
