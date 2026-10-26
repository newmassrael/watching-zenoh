// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The advanced subscriber's rules (atom 5.25), with no runtime in them: what it is asked for
//! ([`options`]), the per-source ordering machine and the listeners it reports holes to
//! ([`state`]), and what is read and written around the gets it asks ([`plans`]).
//!
//! The subscriber is a per-source ordering and de-duplication machine over the `SourceInfo`
//! sequence numbers an advanced publisher stamps, with a recovery half (`advanced-recovery`: a
//! forward gap is buffered and a `_sn`-range get is asked of the publisher's `@adv` cache, the
//! heartbeat beacon and a periodic re-ask catching a lost last sample) and a history half
//! (`advanced-history`: a startup get over `<key_expr>/@adv/**`, and one for each publisher that
//! appears later). A host declares the entities, issues the gets the machine asks for and runs
//! its periodic jobs: the tokio runtime through `wz-runtime-tokio`, which re-exports this module
//! at the paths it has always had, and the cooperative engine behind the pico C ABI.
//!
//! This module is a directory with a `mod.rs` and not a file beside the crate's other modules
//! because a file named `advanced_subscriber.rs` is also the tokio host's, and a bare mention of
//! that name in a record would then name two files.

pub mod options;
pub mod plans;
pub mod state;

#[cfg(feature = "advanced-history")]
pub use options::HistoryConfig;
#[cfg(feature = "advanced-recovery")]
pub use options::RecoveryConfig;
pub use options::{
    AdvancedSubscriberOptions, DeclarationForms, EntityForm, FormsHandle, SubscriberDetection,
};
#[cfg(feature = "advanced-history")]
pub use plans::history_selector;
#[cfg(feature = "advanced-recovery")]
pub use plans::{
    parse_heartbeat_source, recovered_sample_from_reply, recovery_query_timeout_ms,
    AdvPublisherSource, PendingGets,
};
#[cfg(feature = "advanced-recovery")]
pub use state::RecoveryRequest;
pub use state::{Miss, MissHandlers, SampleMissListener, State};
