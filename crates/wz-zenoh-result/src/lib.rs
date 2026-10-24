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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-result 1.10.1, file
// src/lib.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

//! The result and error types of the zenoh family (`zenoh-result` 1.10.1), over watching-zenoh.
//!
//! This crate is upstream's by name, version, library name and public surface (inventory atom
//! `api-compat-rust`): a Rust user replaces it with a `[patch.crates-io]` entry, and every crate of
//! the dependency graph then meets one `Error`, one `ZError` and one `zerror!`. What is public here
//! is exactly what rustdoc JSON gives for upstream at the pin, held by
//! `scripts/lib/rust_api_surface.py`; a wz-only door is never here (C10).
//!
//! The crate is `no_std` without its `std` feature, as upstream's is, because the family's `no_std`
//! crates depend on it that way. Without `std` it carries its own error trait ([`IError`]) in the
//! place of `std::error::Error`; with `std`, [`IError`] is `std::error::Error`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::boxed::Box;
use core::fmt;

use anyhow::Error as AnyError;

// ── branch hints ────────────────────────────────────────────────────────────

/// A call to this function marks the path that contains it as unlikely to run.
#[cold]
pub const fn cold() {}

/// `b`, with the hint that it is usually true.
pub const fn likely(b: bool) -> bool {
    if !b {
        cold()
    }
    b
}

/// `b`, with the hint that it is usually false.
pub const fn unlikely(b: bool) -> bool {
    if b {
        cold()
    }
    b
}

// ── the error trait ─────────────────────────────────────────────────────────

/// What `std::error::Error` is when `std` is available, and a trait of this crate's own when it is
/// not (the standard library's moved into `core` after the toolchains this family still builds on).
#[cfg(not(feature = "std"))]
pub trait IError: fmt::Display + fmt::Debug + core::any::Any {}

/// `downcast_ref` and `is` for each of the three trait objects a boxed error takes, as
/// `dyn std::error::Error` has them. `IError: Any`, so the `TypeId` a `dyn IError` reports is the
/// concrete type's, and a cast to `T` is sound exactly when the two are equal.
#[cfg(not(feature = "std"))]
macro_rules! downcasts_of_ierror {
    ($($object:ty),+) => {$(
        impl $object {
            /// Whether the error behind this object is a `T`.
            pub fn is<T: 'static>(&self) -> bool {
                core::any::Any::type_id(self) == core::any::TypeId::of::<T>()
            }
            /// The error behind this object as a `T`, when it is one.
            pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
                // SAFETY: the `TypeId` of the concrete type was just compared to `T`'s.
                self.is::<T>().then(|| unsafe { &*(self as *const Self as *const T) })
            }
        }
    )+};
}

#[cfg(not(feature = "std"))]
downcasts_of_ierror!(dyn IError, dyn IError + Send, dyn IError + Send + Sync);

#[cfg(feature = "std")]
pub use std::error::Error as IError;

/// Any error, boxed: what every fallible function of the family returns.
pub type Error = Box<dyn IError + Send + Sync + 'static>;

/// `Result` with the family's [`Error`].
pub type ZResult<T> = core::result::Result<T, Error>;

// ── ZError ──────────────────────────────────────────────────────────────────

/// An `i8` that is below zero: the error number of a [`ZError`].
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NegativeI8(i8);

impl NegativeI8 {
    /// `v` as a `NegativeI8`. Panics when `v` is not below zero.
    pub const fn new(v: i8) -> Self {
        if v >= 0 {
            panic!("Non-negative value used in NegativeI8")
        }
        NegativeI8(v)
    }

    /// The value.
    pub const fn get(self) -> i8 {
        self.0
    }

    /// The lowest value, which is the error number of an error that was given none.
    pub const MIN: Self = Self::new(i8::MIN);
}

/// An error with the place it was raised at, an error number and an optional cause.
pub struct ZError {
    error: AnyError,
    file: &'static str,
    line: u32,
    errno: NegativeI8,
    source: Option<Error>,
}

// Upstream states `Send` and `Sync` of `ZError` by hand, and rustdoc lists a stated impl as surface
// where it lists a derived one as nothing (`scripts/lib/rust_api_surface.py` reads the stated ones),
// so the two impls are here too. They add nothing the fields do not already give, and the check
// below is what keeps them sound: it fails to compile the day a field is not `Send + Sync`, which
// is the day these two lines would have become a lie.
const _: () = {
    const fn send_and_sync<T: Send + Sync>() {}
    send_and_sync::<AnyError>();
    send_and_sync::<Option<Error>>();
};

// SAFETY: every field is `Send + Sync`, which the assertion above checks at compile time.
unsafe impl Send for ZError {}
// SAFETY: as for `Send`.
unsafe impl Sync for ZError {}

impl ZError {
    /// An error raised at `file`:`line` with `errno` and no cause. The [`zerror!`] macro fills in
    /// the place.
    pub fn new<E: Into<AnyError>>(
        error: E,
        file: &'static str,
        line: u32,
        errno: NegativeI8,
    ) -> ZError {
        ZError {
            error: error.into(),
            file,
            line,
            errno,
            source: None,
        }
    }

    /// This error with `source` as its cause.
    pub fn set_source<S: Into<Error>>(mut self, source: S) -> Self {
        self.source = Some(source.into());
        self
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ZError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}

#[cfg(not(feature = "std"))]
impl IError for ZError {}

impl fmt::Debug for ZError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for ZError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}:{}.", self.error, self.file, self.line)?;
        if let Some(cause) = &self.source {
            write!(f, " - Caused by {}", *cause)?;
        }
        Ok(())
    }
}

#[cfg(not(feature = "std"))]
impl From<ZError> for Error {
    fn from(value: ZError) -> Self {
        Box::new(value)
    }
}

// ── ShmError ────────────────────────────────────────────────────────────────

/// A [`ZError`] raised by shared memory.
#[derive(Debug)]
pub struct ShmError(pub ZError);

#[cfg(feature = "std")]
impl std::error::Error for ShmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(&self.0)
    }
}

#[cfg(not(feature = "std"))]
impl IError for ShmError {}

impl fmt::Display for ShmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(not(feature = "std"))]
impl From<ShmError> for Error {
    fn from(value: ShmError) -> Self {
        Box::new(value)
    }
}

// ── ErrNo ───────────────────────────────────────────────────────────────────

/// The error number of an error.
pub trait ErrNo {
    /// The number: a [`ZError`]'s own, and [`NegativeI8::MIN`] for any other error.
    fn errno(&self) -> NegativeI8;
}

impl ErrNo for ZError {
    fn errno(&self) -> NegativeI8 {
        self.errno
    }
}

impl ErrNo for ShmError {
    fn errno(&self) -> NegativeI8 {
        self.0.errno
    }
}

/// `ErrNo` for each boxed error object: the number of the `ZError` behind it, or the lowest.
macro_rules! errno_of_object {
    ($($object:ty),+) => {$(
        impl ErrNo for $object {
            fn errno(&self) -> NegativeI8 {
                match self.downcast_ref::<ZError>() {
                    Some(e) => e.errno(),
                    None => NegativeI8::new(i8::MIN),
                }
            }
        }
    )+};
}

#[cfg(feature = "std")]
errno_of_object!(
    dyn std::error::Error,
    dyn std::error::Error + Send,
    dyn std::error::Error + Send + Sync
);

#[cfg(not(feature = "std"))]
errno_of_object!(dyn IError, dyn IError + Send, dyn IError + Send + Sync);

// ── macros ──────────────────────────────────────────────────────────────────

pub use anyhow::anyhow;

/// A [`ZError`] raised where the macro is written. The forms, in the order they are tried:
/// `zerror!((errno) source => "format", args..)`, `zerror!((errno) "literal")`,
/// `zerror!((errno) expr)`, `zerror!((errno) "format", args..)`, and the same four without the
/// `(errno)`, which then is [`NegativeI8::MIN`].
#[macro_export]
macro_rules! zerror {
    (($errno:expr) $source: expr => $($t: tt)*) => {
        $crate::ZError::new($crate::anyhow!($($t)*), file!(), line!(), $crate::NegativeI8::new($errno as i8)).set_source($source)
    };
    (($errno:expr) $t: literal) => {
        $crate::ZError::new($crate::anyhow!($t), file!(), line!(), $crate::NegativeI8::new($errno as i8))
    };
    (($errno:expr) $t: expr) => {
        $crate::ZError::new($t, file!(), line!(), $crate::NegativeI8::new($errno as i8))
    };
    (($errno:expr) $($t: tt)*) => {
        $crate::ZError::new($crate::anyhow!($($t)*), file!(), line!(), $crate::NegativeI8::new($errno as i8))
    };
    ($source: expr => $($t: tt)*) => {
        $crate::ZError::new($crate::anyhow!($($t)*), file!(), line!(), $crate::NegativeI8::MIN).set_source($source)
    };
    ($t: literal) => {
        $crate::ZError::new($crate::anyhow!($t), file!(), line!(), $crate::NegativeI8::MIN)
    };
    ($t: expr) => {
        $crate::ZError::new($t, file!(), line!(), $crate::NegativeI8::MIN)
    };
    ($($t: tt)*) => {
        $crate::ZError::new($crate::anyhow!($($t)*), file!(), line!(), $crate::NegativeI8::MIN)
    };
}

/// Returns early from the function with the [`zerror!`] built from the arguments.
#[macro_export]
macro_rules! bail {
    ($($t: tt)*) => {
        return Err($crate::zerror!($($t)*).into())
    };
}

/// A closure that turns any error into `Err` of a [`zerror!`] with it as the cause. `zerror!` is
/// named without a path, so the caller has it in scope, as upstream's macro requires.
#[macro_export]
macro_rules! to_zerror {
    ($kind:ident, $descr:expr) => {
        |e| Err(zerror!($kind, $descr, e))
    };
}
