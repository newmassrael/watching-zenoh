// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The one statement of which builds hold the staged handshake extension chains, as the cfg
//! `wz_ext_chains` every use reads. The rule and its tests are `src/ext_chains_cfg.rs`.

#[path = "src/ext_chains_cfg.rs"]
mod ext_chains_cfg;

fn on(feature: &str) -> bool {
    std::env::var_os(feature).is_some()
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/ext_chains_cfg.rs");
    println!("cargo:rustc-check-cfg=cfg(wz_ext_chains)");
    let build = ext_chains_cfg::ExtChainFeatures {
        fixed_storage: on("CARGO_FEATURE_SESSION_FIXED_STORAGE"),
        tx_lend_only: on("CARGO_FEATURE_TX_LEND_ONLY"),
        unicast_accept: on("CARGO_FEATURE_SESSION_UNICAST_ACCEPT"),
        qos: on("CARGO_FEATURE_TRANSPORT_QOS"),
        extshm: on("CARGO_FEATURE_SESSION_EXTSHM"),
        extauth: on("CARGO_FEATURE_SESSION_EXTAUTH"),
        multilink: on("CARGO_FEATURE_TRANSPORT_MULTILINK"),
        lowlatency: on("CARGO_FEATURE_TRANSPORT_LOWLATENCY"),
        extcompression: on("CARGO_FEATURE_SESSION_EXTCOMPRESSION"),
        init_body: on("CARGO_FEATURE_CODEC_INIT_BODY"),
        open_body: on("CARGO_FEATURE_CODEC_OPEN_BODY"),
    };
    if build.holds_chains() {
        println!("cargo:rustc-cfg=wz_ext_chains");
    }
}
