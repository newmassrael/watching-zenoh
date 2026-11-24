// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The lock a plane of the session keeps its state under. A plane is reached from under the
//! session's lock and from the deliveries that run with no lock held, so it holds its state under a
//! lock of its own; which lock that is (an OS mutex on a host, a critical section on a target) is
//! the engine's port's, which this crate does not name, so the engine names it as a
//! [`LockFamily`].

/// The locks an engine keeps a plane's state under.
pub trait LockFamily {
    /// A lock over a value of `T`.
    type Lock<T>;

    /// `value`, under a lock.
    fn new<T>(value: T) -> Self::Lock<T>;

    /// `f` on the value under `lock`, which is held for the length of the call.
    fn with<T, R>(lock: &Self::Lock<T>, f: impl FnOnce(&mut T) -> R) -> R;
}
