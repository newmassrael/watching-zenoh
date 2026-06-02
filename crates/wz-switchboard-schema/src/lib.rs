// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![no_std]

//! R311gp gc-3a — the serde model of `wz-switchboard.yaml`.
//!
//! The switchboard is the Anti-Corruption-Layer table that maps a zenoh
//! keyexpr pattern to an SCXML *domain* event (see
//! [`wz_session_core::switchboard`](https://docs.rs) for the runtime
//! adapter). The mapping is a deploy/wire concern — it names zenoh
//! keyexprs — so it lives in a wz-owned sidecar, never inside the SCXML
//! (`sce:*` attributes are forbidden by the Mesh Path B SCXML-purity
//! rule) and never inside SCE's `deploy.yaml` (which is vendor-agnostic;
//! leaking zenoh keyexprs there would breach the ACL in the other
//! direction).
//!
//! This crate is the single definition of the sidecar's shape, shared by
//! both binders so they cannot drift:
//!  - **MCU / static** — [`wz-switchboard-codegen`] reads it at build
//!    time and emits a closed `keyexpr -> event` match (no heap), with
//!    every [`Binding::event`] cross-checked against the target machine's
//!    `external_ingress_events` (forge-ast.v1, W3C SCXML 3.12.1
//!    event-descriptor matching).
//!  - **AP / dynamic** — a future `wz-runtime-tokio` seam deserializes it
//!    at startup to populate
//!    `wz_session_core::switchboard::SwitchboardRegistry`.
//!
//! The model derives serde traits but pulls no format backend: the YAML
//! reader (or, in tests, a JSON round-trip) is selected at each
//! consumer's I/O boundary.
//!
//! [`wz-switchboard-codegen`]: https://docs.rs

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// A whole `wz-switchboard.yaml` document: the target machine plus its
/// ordered keyexpr -> event binding rows.
///
/// `deny_unknown_fields` makes a typo'd top-level key a hard parse error
/// rather than a silently-ignored field — fail-fast at the I/O boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwitchboardSpec {
    /// The SCXML machine stem this switchboard targets (e.g.
    /// `"sensor_monitor"`, matching `sources/**/sensor_monitor.scxml`).
    ///
    /// The generator cross-checks this against the compiled machine's
    /// `name` (forge-ast.v1 `ast.document.name`), so a sidecar
    /// accidentally paired with the wrong machine fails the build instead
    /// of validating its events against the wrong `external_ingress_events`
    /// set.
    pub machine: String,
    /// keyexpr-pattern -> domain-event rows, consulted in declaration
    /// order. Every row whose pattern matches an inbound sample's resolved
    /// keyexpr injects its event (mirrors
    /// `SwitchboardRegistry::dispatch`'s every-matching-row-fires
    /// semantics).
    pub bindings: Vec<Binding>,
}

/// One keyexpr-pattern -> domain-event row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    /// A zenoh keyexpr pattern with chunk wildcards (`*` single chunk,
    /// `**` zero-or-more chunks, `$*` intra-chunk substring). The
    /// generator canonicalizes + validates this at build time
    /// (`wz_session_core::keyexpr_canon::canonize_keyexpr`, the same
    /// canonicalizer the runtime registry uses), so the stored chunks
    /// agree byte-for-byte with the wire form a peer emits.
    pub keyexpr: String,
    /// The SCXML domain event injected (with empty `_event.data` on the
    /// signal path) when an inbound sample's resolved keyexpr matches
    /// [`Binding::keyexpr`]. Cross-checked at build time against the
    /// machine's `external_ingress_events` per W3C SCXML 3.12.1
    /// event-descriptor matching; an event the machine never accepts is a
    /// build error.
    pub event: String,
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    // Structural round-trip via a format-agnostic backend (serde_json):
    // proves the derive shape without pinning the YAML backend, which is a
    // consumer-side I/O choice. The field names asserted here ARE the
    // wz-switchboard.yaml contract.
    #[test]
    fn spec_round_trips_through_serde() {
        let spec = SwitchboardSpec {
            machine: "sensor_monitor".to_string(),
            bindings: vec![
                Binding {
                    keyexpr: "home/*/temp".to_string(),
                    event: "temp_update".to_string(),
                },
                Binding {
                    keyexpr: "home/livingroom/humidity".to_string(),
                    event: "humidity_update".to_string(),
                },
            ],
        };

        let json = serde_json::to_string(&spec).expect("serialize");
        let back: SwitchboardSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(spec, back);
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        // deny_unknown_fields: a typo'd key fails the parse rather than
        // silently dropping a binding the author intended.
        let json = r#"{"machine":"m","bindings":[],"bidnings":[]}"#;
        let parsed: Result<SwitchboardSpec, _> = serde_json::from_str(json);
        assert!(parsed.is_err());
    }

    #[test]
    fn binding_field_names_are_keyexpr_and_event() {
        let json = r#"{"machine":"m","bindings":[{"keyexpr":"a/b","event":"e"}]}"#;
        let spec: SwitchboardSpec = serde_json::from_str(json).expect("deserialize");
        assert_eq!(spec.bindings.len(), 1);
        assert_eq!(spec.bindings[0].keyexpr, "a/b");
        assert_eq!(spec.bindings[0].event, "e");
    }
}
