// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
///
/// The presence of [`Binding::codec`] selects the path:
///  - **absent (signal)** — the matched sample injects `event` with an
///    empty `_event.data` via the [`EventInjector`] port
///    (`Engine::raise_external_by_name`). The wire payload is ignored.
///  - **present (value)** — the matched sample's payload bytes are decoded
///    by the named forge codec into the machine's typed
///    `<Machine><Variant>Payload` struct and injected via the generated
///    `<Machine>Inject::raise_<event>(payload)` seam (SCE
///    `Engine::raise_external_typed`), so a no_std MCU transition guard
///    reads `_event.data.<field>` natively. The generator cross-checks the
///    codec's decoded fields against the event's `EventSchema` and gates
///    the value path on the machine's `typed_inject_events` set.
///
/// [`EventInjector`]: https://docs.rs/wz-session-core
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
    /// The SCXML domain event injected when an inbound sample's resolved
    /// keyexpr matches [`Binding::keyexpr`]. Cross-checked at build time
    /// against the machine's `external_ingress_events` per W3C SCXML
    /// 3.12.1 event-descriptor matching; an event the machine never
    /// accepts is a build error. For a value binding (see
    /// [`Binding::codec`]) it must additionally be a member of the
    /// machine's `typed_inject_events` set (an event with a generated
    /// `raise_<event>` typed-inject seam).
    pub event: String,
    /// The forge codec kind that decodes the wire payload into the event's
    /// typed `_event.data` (a `sce:kind="codec"` document, compiled by the
    /// consumer's build the same way the zenoh wire codecs are). `None`
    /// makes this a **signal** binding (empty `_event.data`); `Some(name)`
    /// makes it a **value** binding whose decoded struct is field-mapped
    /// into `<Machine><Variant>Payload`. The generator verifies the codec's
    /// decoded fields are a superset of the event's `EventSchema` fields
    /// (name + type), so the wire format and the datamodel view cannot
    /// drift — wz owns this pairing (SCE pairs neither: codec and
    /// EventSchema are independent forge kinds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codec: Option<String>,
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
                    codec: None,
                },
                Binding {
                    keyexpr: "home/livingroom/humidity".to_string(),
                    event: "humidity_update".to_string(),
                    codec: None,
                },
            ],
        };

        let json = serde_json::to_string(&spec).expect("serialize");
        let back: SwitchboardSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(spec, back);
    }

    // A value binding carries a `codec`; round-trips through serde and the
    // signal binding (no `codec`) omits the field entirely
    // (skip_serializing_if), so existing signal-only sidecars stay
    // byte-stable.
    #[test]
    fn value_binding_round_trips_and_signal_omits_codec() {
        let spec = SwitchboardSpec {
            machine: "sensor_monitor".to_string(),
            bindings: vec![
                Binding {
                    keyexpr: "home/*/temp".to_string(),
                    event: "temp_update".to_string(),
                    codec: Some("temp_payload".to_string()),
                },
                Binding {
                    keyexpr: "home/door".to_string(),
                    event: "door_opened".to_string(),
                    codec: None,
                },
            ],
        };

        let json = serde_json::to_string(&spec).expect("serialize");
        // signal binding omits the codec key; value binding carries it.
        assert!(json.contains(r#""codec":"temp_payload""#));
        assert_eq!(json.matches(r#""codec""#).count(), 1);

        let back: SwitchboardSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(spec, back);
        assert_eq!(back.bindings[0].codec.as_deref(), Some("temp_payload"));
        assert_eq!(back.bindings[1].codec, None);
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
