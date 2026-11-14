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
// src/api/admin.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2). The chunks the keys of the
// admin space are made of, apart from the module that serves the space: that module is the unstable
// part of this crate, and upstream exposes the chunks at its root with `internal` alone, which the
// ecosystem's advanced publisher and subscriber build their keys from.

use zenoh_keyexpr::keyexpr;
use zenoh_macros::ke;

// `ke!` writes its paths from `zenoh`, as the crate of a user of the macro; this is that crate.
use crate as zenoh;

#[cfg(any(feature = "internal", feature = "unstable"))]
pub static KE_AT: &keyexpr = ke!("@");
#[cfg(any(feature = "internal", feature = "unstable"))]
pub static KE_ADV_PREFIX: &keyexpr = ke!("@adv");
#[cfg(any(feature = "internal", feature = "unstable"))]
pub static KE_PUB: &keyexpr = ke!("pub");
#[cfg(feature = "internal")]
pub static KE_SUB: &keyexpr = ke!("sub");
#[cfg(any(feature = "internal", feature = "unstable"))]
pub static KE_EMPTY: &keyexpr = ke!("_");
#[cfg(feature = "internal")]
pub static KE_STAR: &keyexpr = ke!("*");
#[cfg(any(feature = "internal", feature = "unstable"))]
pub static KE_STARSTAR: &keyexpr = ke!("**");

#[cfg(all(test, feature = "internal"))]
mod tests {
    #[test]
    fn the_chunks_at_the_root_are_upstreams() {
        let chunks = [
            (crate::KE_AT, "@"),
            (crate::KE_ADV_PREFIX, "@adv"),
            (crate::KE_PUB, "pub"),
            (crate::KE_SUB, "sub"),
            (crate::KE_EMPTY, "_"),
            (crate::KE_STAR, "*"),
            (crate::KE_STARSTAR, "**"),
        ];
        for (chunk, text) in chunks {
            assert_eq!(chunk.as_str(), text);
        }
        // The key the advanced publisher declares its token on is made of them.
        let key = crate::KE_ADV_PREFIX / crate::KE_PUB / crate::KE_STARSTAR;
        assert_eq!(key.as_str(), "@adv/pub/**");
    }
}
