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
//!  - **AP / dynamic** — a host deserializes it at startup and hands the
//!    parsed model to `SwitchboardRegistry::apply_spec`, which is where
//!    the row-kind mapping lives (R2714). Only the DESERIALIZE is the
//!    host's; the mapping is not, because a host that writes its own
//!    turns this document back into a suggestion.
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
    /// R2714 — rows that address the SESSION's own lifecycle rather than
    /// [`SwitchboardSpec::machine`].
    ///
    /// A SECOND SECTION rather than a third flavour of [`Binding`], because
    /// what differs is not the payload shape but WHICH MACHINE the row
    /// targets. Every row under `bindings` is validated against
    /// `machine`'s `external_ingress_events`; a lifecycle verb belongs to
    /// the session FSM, which every profile already has and no sidecar
    /// names. Putting these in `bindings` would ask the generator to
    /// validate a session event against an application machine, where it
    /// correctly does not exist.
    ///
    /// Defaulted, so every document written before this section existed
    /// parses unchanged — and `deny_unknown_fields` still rejects a typo.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lifecycle: Vec<LifecycleBinding>,
    /// Open-debt item 900 — the local SESSION these rows bind to, by its
    /// `sessions[].name` in the deploy machine. A program may hold several
    /// sessions (a client session towards a router beside a peer session in a
    /// multicast group), and every declare runs on one session's handle, so a
    /// sidecar for such a program has to say whose traffic it is.
    ///
    /// Optional ONLY when the machine has exactly one session;
    /// [`SwitchboardSpec::bound_session`] is the rule. Defaulted and skipped
    /// when absent, so every sidecar written before this key parses and
    /// re-serializes byte for byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

/// Why a sidecar's [`SwitchboardSpec::session`] does not pick one of the
/// machine's sessions. Each names the `session` key it is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionBindError {
    /// `session` names a session the machine does not have.
    NoSuchSession {
        /// The name the sidecar gave.
        named: String,
    },
    /// `session` is omitted while the machine has several sessions (or none),
    /// so the rows have no one session to belong to.
    Unnamed {
        /// How many sessions the machine has.
        sessions: usize,
    },
}

impl core::fmt::Display for SessionBindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SessionBindError::NoSuchSession { named } => write!(
                f,
                "session: `{named}` is not the name of one of the machine's sessions"
            ),
            SessionBindError::Unnamed { sessions } => write!(
                f,
                "session: required, because the machine has {sessions} sessions \
                 (it may be omitted only when there is exactly one)"
            ),
        }
    }
}

impl SwitchboardSpec {
    /// The session these rows bind to, among `session_names` (the deploy
    /// machine's `sessions[].name`, in any order).
    ///
    /// A named session must be one of them. An omitted `session` binds the
    /// machine's only session, and is refused when there is not exactly one:
    /// guessing among several would route a row's traffic through whichever
    /// session happened to come first.
    pub fn bound_session<'a>(
        &'a self,
        session_names: &[&'a str],
    ) -> Result<&'a str, SessionBindError> {
        match &self.session {
            Some(named) => session_names
                .iter()
                .copied()
                .find(|n| *n == named.as_str())
                .ok_or_else(|| SessionBindError::NoSuchSession {
                    named: named.clone(),
                }),
            None => match session_names {
                [only] => Ok(only),
                _ => Err(SessionBindError::Unnamed {
                    sessions: session_names.len(),
                }),
            },
        }
    }
}

/// One keyexpr-pattern -> session-lifecycle-verb row.
///
/// A distinct type from [`Binding`] rather than a `Binding` with a
/// convention about its fields: a lifecycle row has no `codec` and can
/// never have one, because a command's subject travels in its KEYEXPR
/// (`@/<zid>/<whatami>/session/<verb>/<peer-zid>`) and not in its payload.
/// Reusing `Binding` would make `codec: Some(..)` on a lifecycle row
/// representable and then need a rule forbidding it; two fields make the
/// state unrepresentable instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleBinding {
    /// The keyexpr pattern a deployment exposes the verb on. wz ships no
    /// default row: which key a node answers on is the deployment's
    /// choice, which is the whole reason this is a document and not a
    /// constant.
    pub keyexpr: String,
    /// The session machine's domain event this row raises (e.g.
    /// `session.close`). The ARRIVING keyexpr travels with it, so the
    /// authority that admits or refuses the command can name its subject.
    pub event: String,
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
            lifecycle: Vec::new(),
            session: None,
        };

        let json = serde_json::to_string(&spec).expect("serialize");
        let back: SwitchboardSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(spec, back);
    }

    // R2714 — a document written before the `lifecycle` section existed still
    // deserializes, and an empty section still serializes away. Both halves are
    // asserted because both are what keep every sidecar in the tree valid: the
    // default is what lets the old documents parse, and
    // `skip_serializing_if` is what keeps them byte-stable when re-emitted.
    #[test]
    fn a_document_without_a_lifecycle_section_still_parses_and_stays_byte_stable() {
        let json =
            r#"{"machine":"thermostat","bindings":[{"keyexpr":"home/*/reset","event":"reset"}]}"#;
        let spec: SwitchboardSpec = serde_json::from_str(json).expect("deserialize");
        assert!(spec.lifecycle.is_empty());

        let back = serde_json::to_string(&spec).expect("serialize");
        assert_eq!(back, json, "an empty lifecycle section adds no key");
    }

    // And a lifecycle row round-trips with the two fields it has -- no `codec`
    // key exists on it at all, which is the unrepresentable state this type
    // buys over reusing `Binding`.
    #[test]
    fn lifecycle_binding_round_trips() {
        let spec = SwitchboardSpec {
            machine: "sensor_monitor".to_string(),
            bindings: Vec::new(),
            lifecycle: vec![LifecycleBinding {
                keyexpr: "@/wz/session/close/*".to_string(),
                event: "session.close".to_string(),
            }],
            session: None,
        };

        let json = serde_json::to_string(&spec).expect("serialize");
        assert!(json.contains(r#""lifecycle":[{"keyexpr":"@/wz/session/close/*""#));
        assert!(!json.contains("codec"));
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
            lifecycle: Vec::new(),
            session: None,
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

    // Open-debt item 900 — the `session` key: it parses, round-trips, and stays
    // out of a document that does not set it (the byte-stability test above
    // covers that half for every old sidecar).
    #[test]
    fn a_session_key_round_trips() {
        let json = r#"{"machine":"m","bindings":[],"session":"to_router"}"#;
        let spec: SwitchboardSpec = serde_json::from_str(json).expect("deserialize");
        assert_eq!(spec.session.as_deref(), Some("to_router"));
        assert_eq!(serde_json::to_string(&spec).expect("serialize"), json);
    }

    // The binding rule, each arm against the machine's session list: a named
    // session must exist; an omitted one binds the only session and is refused
    // among several (or none), and every refusal names the `session` key.
    #[test]
    fn the_session_binds_to_one_of_the_machines_sessions() {
        let named: SwitchboardSpec =
            serde_json::from_str(r#"{"machine":"m","bindings":[],"session":"group"}"#)
                .expect("deserialize");
        let unnamed: SwitchboardSpec =
            serde_json::from_str(r#"{"machine":"m","bindings":[]}"#).expect("deserialize");
        let two = ["to_router", "group"];

        assert_eq!(named.bound_session(&two), Ok("group"));
        assert_eq!(unnamed.bound_session(&["only"]), Ok("only"));

        let missing = named.bound_session(&["to_router"]).unwrap_err();
        assert_eq!(
            missing,
            SessionBindError::NoSuchSession {
                named: "group".to_string()
            }
        );
        let ambiguous = unnamed.bound_session(&two).unwrap_err();
        assert_eq!(ambiguous, SessionBindError::Unnamed { sessions: 2 });
        assert_eq!(
            unnamed.bound_session(&[]).unwrap_err(),
            SessionBindError::Unnamed { sessions: 0 }
        );
        for refusal in [missing, ambiguous] {
            assert!(refusal.to_string().starts_with("session: "), "{refusal}");
        }
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
