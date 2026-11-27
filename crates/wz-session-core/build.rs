// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The one statement of which builds hold the staged handshake extension chains, as the cfg
//! `wz_ext_chains` every use reads. The rule and its tests are `src/ext_chains_cfg.rs`.
//!
//! It also states which items of `link::SessionRuntime` this build declares, as the metadata
//! keys of `links = "wz_session_core"`: a crate that implements the trait reads them as
//! `DEP_WZ_SESSION_CORE_<KEY>` (`1` declared, `0` not) and binds the items on what they say.
//! A feature of the implementing crate cannot say it: Cargo unifies this crate's features across
//! the graph, so any crate in it can turn on what declares the items. Whether this build answers a
//! peer's Interest (`interest-answer`) is stated the same way, as `interest_answer`, for an engine
//! that compiles its own half of the answer beside this crate's.

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

    // `SessionRuntime::EntropyDraw` and `SessionRuntime::ActionsHandle`, declared in
    // `src/link.rs` under the cfg this states.
    let session_unicast = on("CARGO_FEATURE_SESSION_UNICAST");
    let unicast_runtime_items = on("CARGO_FEATURE_STORAGE_PROFILE") && session_unicast;
    // `SessionRuntime::wrap_actions`: absent under `session-slot`, where a slot hands the
    // handle out and no runtime makes one of a bundle by value.
    let wrap_actions =
        on("CARGO_FEATURE_ALLOC") && session_unicast && !on("CARGO_FEATURE_SESSION_SLOT");
    // The one statement of both facts: this crate's own declarations read them as cfgs, and an
    // implementing crate as metadata, so the two cannot disagree.
    println!("cargo:rustc-check-cfg=cfg(wz_unicast_runtime_items)");
    println!("cargo:rustc-check-cfg=cfg(wz_wrap_actions)");
    if unicast_runtime_items {
        println!("cargo:rustc-cfg=wz_unicast_runtime_items");
    }
    if wrap_actions {
        println!("cargo:rustc-cfg=wz_wrap_actions");
    }
    println!(
        "cargo:unicast_runtime_items={}",
        u8::from(unicast_runtime_items)
    );
    println!("cargo:wrap_actions={}", u8::from(wrap_actions));
    println!(
        "cargo:interest_answer={}",
        u8::from(on("CARGO_FEATURE_INTEREST_ANSWER"))
    );
}
