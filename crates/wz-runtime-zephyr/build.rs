// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The IP families the image's Zephyr build has, as `cfg`s of this crate.
//!
//! An image's Kconfig decides whether Zephyr's stack has IPv4 (`CONFIG_NET_IPV4`) and IPv6
//! (`CONFIG_NET_IPV6`), and which family the node's own address is (`CONFIG_WZ_NODE_IPV6`). The
//! board's build hands the three to cargo as environment (`deploy/zephyr-common/
//! wz_zephyr_board.cmake`: `WZ_NET_IPV4`, `WZ_NET_IPV6`, `WZ_NODE_IPV6`, each `1` or `0`), as it
//! hands the tick rate. Read here, they are `cfg`s, so what calls into one family (the MLD
//! membership, the board's address hook of that family) is compiled only into an image whose stack
//! has it: a symbol it would reference does not exist in an image built without.
//!
//! A build that names none (a host test of this crate, a `cargo check`) is an IPv4 image.

fn main() {
    println!("cargo::rerun-if-env-changed=WZ_NET_IPV4");
    println!("cargo::rerun-if-env-changed=WZ_NET_IPV6");
    println!("cargo::rerun-if-env-changed=WZ_NODE_IPV6");
    println!("cargo::rustc-check-cfg=cfg(wz_net_ipv4)");
    println!("cargo::rustc-check-cfg=cfg(wz_net_ipv6)");
    println!("cargo::rustc-check-cfg=cfg(wz_node_ipv6)");
    let on = |name: &str| std::env::var(name).is_ok_and(|value| value == "1");
    // IPv4 is the stack's unless the build says it is not (`CONFIG_NET_IPV4=n`, `WZ_NET_IPV4=0`):
    // what the board's IPv4 address hook is compiled against exists only then.
    if std::env::var("WZ_NET_IPV4").as_deref() != Ok("0") {
        println!("cargo::rustc-cfg=wz_net_ipv4");
    }
    // The node's own address can be IPv6 only where the stack has IPv6; Kconfig holds the two
    // together (`WZ_NODE_IPV6` depends on `NET_IPV6`), and so does this.
    let node_ipv6 = on("WZ_NODE_IPV6");
    if on("WZ_NET_IPV6") || node_ipv6 {
        println!("cargo::rustc-cfg=wz_net_ipv6");
    }
    if node_ipv6 {
        println!("cargo::rustc-cfg=wz_node_ipv6");
    }
}
