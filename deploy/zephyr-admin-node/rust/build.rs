// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The image's axes as `cfg`s, derived from the Cargo features that select them.
//!
//! The image is chosen along axes (`deploy/wz-config.toml`: the network backend, the role and the
//! storage), and what the declaration hands cargo is a set of features that already combine
//! them: `fixed-client` is the client node on the fixed storage, `fixed-memory` the admin node on
//! it, `client-node` the client on the heap, and `heap` the admin node on it. Features only add
//! code, so they stay as they are, and a build outside Zephyr (a test, clippy) still works from
//! them alone. What the source asks is an axis, and this file answers it once:
//!
//! | cfg | the axis it states | the features that turn it on |
//! | --- | --- | --- |
//! | `storage_fixed` | the node's tables are statics, the slot profile | `fixed-memory`, `fixed-client` |
//! | `role_client` | the node built is a client of a router | `fixed-client`; `client-node` on the heap |
//! | `role_admin` | the node built is the admin node | `fixed-memory`; `admin-node` on the heap |
//!
//! A role is the role of the node that is BUILT. The fixed storage wins over the heap's: with the
//! default `heap` feature left on beside `fixed-client` (the census-only build, which has an
//! allocator so that it links) the node is the fixed client, and the admin node `heap` brings
//! is not built, so `role_admin` is off there.
//!
//! Whether the Rust image has an allocator is NOT an alias. `extern crate alloc` and the image's
//! allocator are gated on `any(feature = "heap", feature = "client-node")` in `lib.rs`, because the
//! no-allocator link gate (`scripts/lib/no_allocator_link_gate.py`) proves a fixed image has none by
//! evaluating exactly that `cfg` against the features of each gated build, and it cannot evaluate a
//! `cfg` this script defines: the proof must not depend on a rule written twice.
//!
//! The network backend is already one feature per option (`net-zephyr-sockets`,
//! `net-lwip-mac`), so the source tests it directly. The combinations that make no node are
//! refused in `lib.rs` by `compile_error!`, as before.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let on = |feature: &str| {
        let name = format!("CARGO_FEATURE_{}", feature.to_uppercase().replace('-', "_"));
        std::env::var_os(name).is_some()
    };
    let storage_fixed = on("fixed-memory") || on("fixed-client");
    let aliases = [
        ("storage_fixed", storage_fixed),
        (
            "role_client",
            on("fixed-client") || (!storage_fixed && on("client-node")),
        ),
        (
            "role_admin",
            on("fixed-memory") || (!storage_fixed && on("admin-node")),
        ),
    ];
    for (name, enabled) in aliases {
        println!("cargo:rustc-check-cfg=cfg({name})");
        if enabled {
            println!("cargo:rustc-cfg={name}");
        }
    }
}
