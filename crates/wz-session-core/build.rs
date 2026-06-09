// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! wz-session-core build.rs — codegens the engine-free statecharts.
//!
//! Three SCE-generated statecharts are hosted in wz-session-core (the
//! AP/MCU-shared core crate), each behind its own feature gate:
//!   - `sources/network/reassembly_slot.scxml` (feature `reassembly`) —
//!     the per-slot transport reassembly FSM (Tier B).
//!   - `sources/session/scouting.scxml` (feature `scouting-active`) —
//!     the active Scout/Hello discovery FSM (R311ik).
//!   - `sources/session/session_fsm_unicast.scxml` (feature
//!     `session-unicast`) — the unicast session FSM (R311il).
//!
//! All three are fully script-engine-free: every effect is a
//! `<sce:action>` native host-trait call, so the emitted `*Policy<A>`
//! carries no `IScriptEngine` and compiles `#![no_std]` (proven by the
//! sce-rust-runtime no_std CI lane). Unlike the Lua-bound FSMs of older
//! rounds, there is no script-name audit here: `<sce:action>` binds to a
//! generated `*Actions` trait whose implementation is checked at compile
//! time by the Rust type system — an unimplemented action cannot link.
//!
//! Codegen is per-feature elidable (a build without the gating feature
//! neither invokes sce-codegen nor includes the emitted module). The
//! sce-codegen invocation + emit post-processing live once in the shared
//! `wz-codegen-build` build-dependency.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let reassembly = std::env::var("CARGO_FEATURE_REASSEMBLY").is_ok();
    let scouting_active = std::env::var("CARGO_FEATURE_SCOUTING_ACTIVE").is_ok();
    let session_unicast = std::env::var("CARGO_FEATURE_SESSION_UNICAST").is_ok();
    let session_multicast = std::env::var("CARGO_FEATURE_SESSION_MULTICAST").is_ok();

    // Elidable: skip the sce-codegen lookup entirely when no statechart
    // feature is active.
    if !reassembly && !scouting_active && !session_unicast && !session_multicast {
        return;
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set by cargo"));
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set by cargo"),
    );
    let codegen = wz_codegen_build::Codegen::from_manifest(&manifest_dir);

    if reassembly {
        let resource_dir = manifest_dir
            .join("../../sources/network")
            .canonicalize()
            .expect("canonicalize sources/network");
        println!("cargo:rerun-if-changed={}", resource_dir.display());
        // The statechart imports fragment_chunk_schema.scxml (an
        // event-schema kind) via a relative `<sce:import>`; sce-codegen
        // resolves it from resource_dir, so only the statechart stem is
        // emitted.
        codegen.emit_statechart("reassembly_slot", &resource_dir, &out_dir);
    }

    if scouting_active {
        let resource_dir = manifest_dir
            .join("../../sources/session")
            .canonicalize()
            .expect("canonicalize sources/session");
        println!("cargo:rerun-if-changed={}", resource_dir.display());
        codegen.emit_statechart("scouting", &resource_dir, &out_dir);
    }

    if session_unicast {
        let resource_dir = manifest_dir
            .join("../../sources/session")
            .canonicalize()
            .expect("canonicalize sources/session");
        println!("cargo:rerun-if-changed={}", resource_dir.display());
        codegen.emit_statechart("session_fsm_unicast", &resource_dir, &out_dir);
    }

    if session_multicast {
        let resource_dir = manifest_dir
            .join("../../sources/session")
            .canonicalize()
            .expect("canonicalize sources/session");
        println!("cargo:rerun-if-changed={}", resource_dir.display());
        // Two engine-free statecharts: the session-LEVEL lifecycle
        // (Idle/LinkOpening/Running/Stopped) and the per-peer membership
        // FSM (Free/Discovered/Active/Expired), driven one-per-peer by the
        // `multicast_dispatch` Router (the §3.1 / §3.2 split).
        codegen.emit_statechart("session_fsm_multicast", &resource_dir, &out_dir);
        codegen.emit_statechart("multicast_peer", &resource_dir, &out_dir);
    }
}
