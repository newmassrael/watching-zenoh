// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! # wz-capi-pico-ext
//!
//! The doors of the additional features of the pico C ABI (`wz_ext_e2e_*`,
//! `wz_ext_stream_supervisor_*`, `wz_ext_instance_keyer_*`, `wz_ext_replay_*`,
//! `wz_ext_message_catalog_*`, `wz_ext_message_payload_*` and `wz_ext_additional_interface`) as a
//! library of their own, which runs over the core library (`wz-capi-pico` built with
//! `--cfg wz_additional_apart`) and reaches it through C only.
//!
//! Nothing here is written for this library. The doors are the core crate's own files, compiled
//! again: `crates/wz-capi-pico/src/<door>.rs`. They name the core as `crate::<module>::<item>`,
//! and `scripts/lib/layer_direction_gate.py` holds every such name to an item of the C ABI or of
//! the extension interface, so each resolves here to its declaration in [`core_view`], an import
//! from the core library. The result codes are the core's file too, and the panic guard
//! (`crate::ffi`) is the core's boundary helper, compiled here for this library as the core
//! compiles it for itself.
//!
//! The contract across the boundary is the hourglass the extension interface states
//! (`crates/wz-capi-pico/src/ext_interface.rs`, `docs/capi-pico-additional-library.md`): handles
//! are opaque, each library frees what it allocated, no object of a language runtime crosses, and
//! the interface's version is asked, at load time by the function named by its major version and at
//! run time by `wz_ext_additional_interface`.

// pico's and wz's C type names are snake_case; the doors keep them verbatim, as the core does.
#![allow(non_camel_case_types)]
// Every export has the pico C ABI's one safety contract, as the core's crate root states.
#![allow(clippy::missing_safety_doc)]

// The core's result codes: its file, constants only, so both libraries answer the same numbers.
#[path = "../../wz-capi-pico/src/result.rs"]
pub mod result;

// The panic guard of an export and the thread-crossing pointer, compiled here as the core compiles
// them. Which of them a build uses is its doors' choice, so one it does not use is not a defect.
#[allow(dead_code)]
#[path = "../../wz-capi-pico/src/ffi/boundary.rs"]
mod ffi;

pub mod core_view;
#[cfg(feature = "event-ring")]
pub use core_view::event_log;
pub use core_view::{abi, bytes, ext_interface, keyexpr, session};
#[cfg(feature = "replay-cache")]
pub use core_view::{decl_watch, get, get_to_peer, pubsub, query, zid};

// The doors, gated as the core's crate root gates them.
#[cfg(any(
    feature = "e2e-sender",
    feature = "e2e-receiver",
    feature = "e2e-supervision",
    feature = "instance-key",
    feature = "message-catalog",
    feature = "replay-cache"
))]
#[path = "../../wz-capi-pico/src/additional.rs"]
pub mod additional;
#[cfg(any(
    feature = "e2e-sender",
    feature = "e2e-receiver",
    feature = "instance-key",
    feature = "message-payload"
))]
#[path = "../../wz-capi-pico/src/e2e.rs"]
mod e2e;
#[cfg(feature = "e2e-receiver")]
#[path = "../../wz-capi-pico/src/e2e_receiver.rs"]
pub mod e2e_receiver;
#[cfg(feature = "e2e-sender")]
#[path = "../../wz-capi-pico/src/e2e_sender.rs"]
pub mod e2e_sender;
#[cfg(feature = "instance-key")]
#[path = "../../wz-capi-pico/src/instance_key.rs"]
pub mod instance_key;
#[cfg(feature = "message-catalog")]
#[path = "../../wz-capi-pico/src/message_catalog.rs"]
pub mod message_catalog;
#[cfg(feature = "message-payload")]
#[path = "../../wz-capi-pico/src/message_payload.rs"]
pub mod message_payload;
#[cfg(any(feature = "instance-key", feature = "message-payload"))]
#[path = "../../wz-capi-pico/src/proto_file.rs"]
pub mod proto_file;
#[cfg(feature = "replay-cache")]
#[path = "../../wz-capi-pico/src/replay_publisher.rs"]
pub mod replay_publisher;
#[cfg(feature = "replay-cache")]
#[path = "../../wz-capi-pico/src/replay_subscriber.rs"]
pub mod replay_subscriber;
#[cfg(feature = "e2e-supervision")]
#[path = "../../wz-capi-pico/src/stream_supervision.rs"]
pub mod stream_supervision;
