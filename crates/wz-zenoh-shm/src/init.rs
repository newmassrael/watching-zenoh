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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-shm 1.10.1, file
// src/init.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

/// Raise `RLIMIT_NOFILE` soft limit to hard limit.
///
/// Call from SHM segment fan-in: [create], [open], [ensure_not_persistent]; not [init].
/// Covers eager/lazy and direct/indirect SHM use.
/// Idempotent (through [Once]); Unix-only, no-op elsewhere and in tests.
///
/// [create]: crate::shm::Segment::create
/// [open]: crate::shm::Segment::open
/// [ensure_not_persistent]: crate::shm::Segment::ensure_not_persistent
/// [init]: crate::init::init
/// [Once]: std::sync::Once
pub(crate) fn raise_nofile_soft_limit_to_hard_limit_once() {
    #[cfg(all(unix, not(test), not(feature = "test")))]
    {
        static RAISE_NOFILE_LIMIT: std::sync::Once = std::sync::Once::new();

        RAISE_NOFILE_LIMIT.call_once(|| {
            if let Err(error) = rlimit::increase_nofile_limit(u64::MAX) {
                tracing::warn!("failed to raise NOFILE soft limit to hard limit: {error}");
            }
        });
    }
}
