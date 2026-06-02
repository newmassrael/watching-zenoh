// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311gp gc-3a — the MCU static switchboard generator (pure library).
//!
//! Turns a [`SwitchboardSpec`] (parsed `wz-switchboard.yaml`) plus a
//! machine's forge-ast.v1 facts into the source of a closed, no-heap
//! `keyexpr -> SCXML domain-event` dispatch function. Two responsibilities,
//! both performed against the facts the SCE compiler already derived:
//!
//! 1. **Validation.** Every [`Binding::event`] must be an event the target
//!    machine actually accepts from outside. SCE publishes that closed set
//!    as `external_ingress_events` in the forge-ast.v1 envelope and
//!    documents it (`docs/SCE_FORGE_AST.md` §8) as *the* event-injection
//!    contract: "a transport switchboard mapping a pub/sub key to a domain
//!    event validates its targets against `external_ingress_events`, not
//!    `events` … drift-proof because SCE owns the reserved-family filter".
//!    We honour that exactly — the check is W3C SCXML 3.12.1 event-
//!    descriptor matching against `external_ingress_events` (so a machine
//!    that catches a family with a prefix descriptor still accepts a
//!    concrete injected name), and an event no descriptor accepts is a
//!    build error, not a silently-ignored runtime no-op.
//!
//! 2. **Emission.** Each binding's keyexpr is canonicalized with
//!    [`wz_session_core::keyexpr_canon::canonize_keyexpr`] — the SAME
//!    canonicalizer the runtime [`SwitchboardRegistry`] uses, so the
//!    static (MCU) and dynamic (AP) stored chunk forms cannot diverge —
//!    then emitted as a `&'static str` chunk literal matched by the shared
//!    no-alloc [`wz_session_core::keyexpr_match::keyexpr_pattern_matches`].
//!    The emitted function mirrors `SwitchboardRegistry::dispatch`:
//!    every matching row fires in declaration order; the signal path
//!    injects an empty `_event.data` (the typed value path is gc-3b).
//!
//! [`SwitchboardSpec`]: wz_switchboard_schema::SwitchboardSpec
//! [`Binding::event`]: wz_switchboard_schema::Binding::event
//! [`SwitchboardRegistry`]: wz_session_core::switchboard

use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;
use wz_switchboard_schema::SwitchboardSpec;

/// forge-ast.v1 wire version this generator understands. The envelope's
/// top-level `v` is checked against this so a future non-additive bump
/// surfaces as a clear error instead of a silently-misread field.
pub const SUPPORTED_FORGE_AST_VERSION: u32 = 1;

/// The subset of a compiled machine's forge-ast.v1 facts the generator
/// needs. Parsed from the envelope SCE emits with `sce-codegen … --emit-ast`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineFacts {
    /// `ast.document.name` — the machine's SCXML `name`. Cross-checked
    /// against [`SwitchboardSpec::machine`] so a sidecar paired with the
    /// wrong machine fails the build.
    pub name: String,
    /// `ast.document.external_ingress_events` — the closed set of event
    /// descriptors the machine accepts as external input, reserved
    /// families (`error.*`, `done.*`, …) already filtered out by SCE.
    pub external_ingress_events: BTreeSet<String>,
}

// ---- forge-ast.v1 deserialization (statechart subset) --------------------
//
// The envelope is `{ v, sce_producer_version?, ast: { document, … } }`.
// We deserialize only what we consume and let serde ignore every other
// field of the ~50-key SCXMLModel projection.

#[derive(Deserialize)]
struct Envelope {
    v: u32,
    ast: Ast,
}

#[derive(Deserialize)]
struct Ast {
    document: Document,
}

#[derive(Deserialize)]
struct Document {
    kind: String,
    #[serde(default)]
    name: String,
    // Omitted from the envelope when empty (schema:
    // skip_serializing_if = "BTreeSet::is_empty"), so default to empty.
    #[serde(default)]
    external_ingress_events: BTreeSet<String>,
}

/// Errors the generator can return. All are build-time failures the
/// developer must fix in either the SCXML or the `wz-switchboard.yaml`.
#[derive(Debug)]
pub enum CodegenError {
    /// The forge-ast JSON could not be deserialized.
    Json(serde_json::Error),
    /// The envelope's `v` is not [`SUPPORTED_FORGE_AST_VERSION`].
    UnsupportedAstVersion(u32),
    /// `ast.document.kind` is not `"statechart"` (the switchboard targets a
    /// state machine, not a forge codec/transform document).
    NotStatechart(String),
    /// The sidecar's `machine` does not match the compiled machine's name.
    MachineMismatch {
        /// Value declared in `wz-switchboard.yaml`.
        spec: String,
        /// Actual `ast.document.name` of the compiled machine.
        machine: String,
    },
    /// A binding maps to an event the machine never accepts as external
    /// input (no `external_ingress_events` descriptor matches it per W3C
    /// SCXML 3.12.1).
    UnknownEvent {
        /// The offending [`Binding::event`].
        event: String,
        /// The machine whose contract rejected it.
        machine: String,
        /// The machine's accepted descriptors (sorted), for the fix hint.
        available: Vec<String>,
    },
    /// A binding's keyexpr is not canonicalizable (e.g. an empty chunk or a
    /// malformed wildcard). The build-time generator is strict where the
    /// runtime registry merely warns: a bad pattern in a sidecar is a
    /// defect to fix, not to tolerate.
    Keyexpr {
        /// The offending [`Binding::keyexpr`].
        keyexpr: String,
        /// The canonicalizer's diagnostic.
        reason: String,
    },
}

impl fmt::Display for CodegenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodegenError::Json(e) => write!(f, "forge-ast.v1 JSON parse failed: {e}"),
            CodegenError::UnsupportedAstVersion(v) => write!(
                f,
                "forge-ast envelope version {v} is unsupported \
                 (this generator understands v{SUPPORTED_FORGE_AST_VERSION})"
            ),
            CodegenError::NotStatechart(kind) => write!(
                f,
                "forge-ast document kind is `{kind}`, expected `statechart` \
                 (the switchboard targets an SCXML state machine)"
            ),
            CodegenError::MachineMismatch { spec, machine } => write!(
                f,
                "wz-switchboard.yaml targets machine `{spec}` but the compiled \
                 machine is `{machine}` — the sidecar is paired with the wrong machine"
            ),
            CodegenError::UnknownEvent {
                event,
                machine,
                available,
            } => write!(
                f,
                "switchboard event `{event}` is not in machine `{machine}`'s \
                 external_ingress_events (no W3C SCXML 3.12.1 descriptor accepts it). \
                 Machine accepts: [{}]",
                available.join(", ")
            ),
            CodegenError::Keyexpr { keyexpr, reason } => write!(
                f,
                "switchboard keyexpr `{keyexpr}` is not canonicalizable: {reason}"
            ),
        }
    }
}

impl std::error::Error for CodegenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CodegenError::Json(e) => Some(e),
            _ => None,
        }
    }
}

/// Parse the forge-ast.v1 JSON SCE emits for a statechart into the subset
/// of facts the generator needs.
///
/// Rejects a non-v1 envelope and a non-statechart document up front so the
/// later [`generate`] call only ever sees well-formed machine facts.
pub fn parse_machine_facts(forge_ast_json: &str) -> Result<MachineFacts, CodegenError> {
    let envelope: Envelope = serde_json::from_str(forge_ast_json).map_err(CodegenError::Json)?;
    if envelope.v != SUPPORTED_FORGE_AST_VERSION {
        return Err(CodegenError::UnsupportedAstVersion(envelope.v));
    }
    let document = envelope.ast.document;
    if document.kind != "statechart" {
        return Err(CodegenError::NotStatechart(document.kind));
    }
    Ok(MachineFacts {
        name: document.name,
        external_ingress_events: document.external_ingress_events,
    })
}

/// W3C SCXML 3.12.1 event-descriptor matching: does `descriptor` accept the
/// concrete event name `name`?
///
/// A descriptor matches a name when its dot-separated token string is an
/// exact match or a token-boundary prefix of the name's tokens. A trailing
/// `.*` on the descriptor is the spec's optional sugar for the prefix form
/// and is stripped before comparison. This is exactly the rule SCE's
/// `external_ingress_events` set is curated for (it already excludes the
/// reserved families and the bare wildcard), so the switchboard never
/// re-implements the platform-event taxonomy.
fn event_descriptor_matches(descriptor: &str, name: &str) -> bool {
    let descriptor = descriptor.strip_suffix(".*").unwrap_or(descriptor);
    if descriptor == name {
        return true;
    }
    // Token-boundary prefix: `name` is `descriptor` followed by `.<rest>`.
    match name.strip_prefix(descriptor) {
        Some(rest) => rest.starts_with('.'),
        None => false,
    }
}

/// Emit a Rust string literal for `s`, escaping `\` and `"` so an arbitrary
/// (already-validated) keyexpr chunk or event name embeds safely.
fn rust_string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// Generate the closed `dispatch_switchboard` function source for `spec`,
/// validated against `facts`.
///
/// Validation order per binding: machine pairing first (whole-spec), then
/// for each binding the event is checked against the machine's
/// `external_ingress_events` (W3C 3.12.1), then the keyexpr is
/// canonicalized. Any failure aborts with a [`CodegenError`]; on success
/// the returned `String` is ready to `include!` from a consumer build's
/// `OUT_DIR`.
pub fn generate(spec: &SwitchboardSpec, facts: &MachineFacts) -> Result<String, CodegenError> {
    if spec.machine != facts.name {
        return Err(CodegenError::MachineMismatch {
            spec: spec.machine.clone(),
            machine: facts.name.clone(),
        });
    }

    let mut arms = String::new();
    for binding in &spec.bindings {
        // 1. Event must be accepted by the machine's external-ingress contract.
        let accepted = facts
            .external_ingress_events
            .iter()
            .any(|descriptor| event_descriptor_matches(descriptor, &binding.event));
        if !accepted {
            return Err(CodegenError::UnknownEvent {
                event: binding.event.clone(),
                machine: facts.name.clone(),
                available: facts.external_ingress_events.iter().cloned().collect(),
            });
        }

        // 2. Canonicalize the keyexpr with the runtime's own canonicalizer
        //    (shared SSOT) so the static chunks match the wire form.
        let canonical = wz_session_core::keyexpr_canon::canonize_keyexpr(&binding.keyexpr)
            .map_err(|e| CodegenError::Keyexpr {
                keyexpr: binding.keyexpr.clone(),
                reason: e.to_string(),
            })?;

        // 3. Emit the match arm. &'static str chunk literal -> no heap.
        let chunk_literals: Vec<String> = canonical.split('/').map(rust_string_literal).collect();
        let event_literal = rust_string_literal(&binding.event);
        arms.push_str(&format!(
            "\n    // {canonical} -> {event}\n    \
             if wz_session_core::keyexpr_match::keyexpr_pattern_matches(&[{chunks}], target_keyexpr) {{\n        \
             injector.inject({event_literal}, \"\");\n        \
             injected += 1;\n    }}\n",
            canonical = canonical,
            event = binding.event,
            chunks = chunk_literals.join(", "),
            event_literal = event_literal,
        ));
    }

    Ok(format!(
        "// @generated by wz-switchboard-codegen (R311gp gc-3a) -- DO NOT EDIT.\n\
         //\n\
         // Static keyexpr -> SCXML domain-event switchboard for machine\n\
         // {machine:?}. Closed match, no heap: &'static str chunk literals over\n\
         // the shared no-alloc matcher. Signal path only (empty _event.data;\n\
         // the typed value path is gc-3b). Regenerate by editing the source\n\
         // wz-switchboard.yaml and rebuilding.\n\
         \n\
         /// Dispatch a resolved inbound keyexpr against the static switchboard\n\
         /// for machine {machine:?}, injecting each matched domain event in\n\
         /// declaration order. Returns the number of events injected. Mirrors\n\
         /// `wz_session_core::switchboard::SwitchboardRegistry::dispatch`.\n\
         pub fn dispatch_switchboard(\n    \
         target_keyexpr: &str,\n    \
         injector: &mut dyn wz_session_core::switchboard::EventInjector,\n\
         ) -> usize {{\n    \
         let mut injected = 0usize;\n\
         {arms}    \
         injected\n\
         }}\n",
        machine = spec.machine,
        arms = arms,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_switchboard_schema::Binding;

    // A minimal forge-ast.v1 statechart envelope, shaped per
    // docs/SCE_FORGE_AST.md §8, carrying just the fields the generator
    // reads. `events` is the kitchen-sink union (includes a reserved
    // family) to prove we validate against external_ingress_events, NOT
    // events.
    fn facts_json(name: &str, ingress: &[&str]) -> String {
        let ingress_arr = ingress
            .iter()
            .map(|e| format!("{e:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        // `events` is the kitchen-sink union (always carries a reserved
        // family); `external_ingress_events` is the curated subset. Build
        // both without a trailing comma so the empty-ingress case stays
        // valid JSON.
        let events_arr = if ingress_arr.is_empty() {
            "\"error.execution\"".to_string()
        } else {
            format!("\"error.execution\", {ingress_arr}")
        };
        format!(
            r#"{{
                "v": 1,
                "sce_producer_version": "0.1.0",
                "ast": {{
                    "document": {{
                        "kind": "statechart",
                        "name": "{name}",
                        "events": [{events_arr}],
                        "external_ingress_events": [{ingress_arr}]
                    }}
                }}
            }}"#
        )
    }

    fn binding(keyexpr: &str, event: &str) -> Binding {
        Binding {
            keyexpr: keyexpr.to_string(),
            event: event.to_string(),
        }
    }

    fn spec(machine: &str, bindings: Vec<Binding>) -> SwitchboardSpec {
        SwitchboardSpec {
            machine: machine.to_string(),
            bindings,
        }
    }

    // ---- parse_machine_facts ----

    #[test]
    fn parses_statechart_facts() {
        let facts = parse_machine_facts(&facts_json("sensor_monitor", &["temp_update", "go"]))
            .expect("parse");
        assert_eq!(facts.name, "sensor_monitor");
        assert!(facts.external_ingress_events.contains("temp_update"));
        assert!(facts.external_ingress_events.contains("go"));
        // `events`-only reserved families never enter the ingress set.
        assert!(!facts.external_ingress_events.contains("error.execution"));
    }

    #[test]
    fn rejects_non_v1_envelope() {
        let json = r#"{"v":2,"ast":{"document":{"kind":"statechart","name":"m"}}}"#;
        assert!(matches!(
            parse_machine_facts(json),
            Err(CodegenError::UnsupportedAstVersion(2))
        ));
    }

    #[test]
    fn rejects_non_statechart_document() {
        let json = r#"{"v":1,"ast":{"document":{"kind":"codec","name":"frame"}}}"#;
        assert!(matches!(
            parse_machine_facts(json),
            Err(CodegenError::NotStatechart(k)) if k == "codec"
        ));
    }

    #[test]
    fn missing_external_ingress_events_is_empty_set() {
        let json = r#"{"v":1,"ast":{"document":{"kind":"statechart","name":"m"}}}"#;
        let facts = parse_machine_facts(json).expect("parse");
        assert!(facts.external_ingress_events.is_empty());
    }

    // ---- event_descriptor_matches (W3C SCXML 3.12.1) ----

    #[test]
    fn descriptor_matching_rules() {
        // Exact match.
        assert!(event_descriptor_matches("temp_update", "temp_update"));
        // Token-boundary prefix: descriptor `sensor` accepts `sensor.temp`.
        assert!(event_descriptor_matches("sensor", "sensor.temp"));
        assert!(event_descriptor_matches("sensor", "sensor.temp.high"));
        // Trailing `.*` sugar is equivalent to the prefix form.
        assert!(event_descriptor_matches("sensor.*", "sensor.temp"));
        // NOT a token boundary: `sensor` must not accept `sensorboard`.
        assert!(!event_descriptor_matches("sensor", "sensorboard"));
        // Reverse direction never matches.
        assert!(!event_descriptor_matches("sensor.temp", "sensor"));
        assert!(!event_descriptor_matches("a", "b"));
    }

    // ---- generate: validation rejections ----

    #[test]
    fn rejects_machine_mismatch() {
        let facts = parse_machine_facts(&facts_json("real_machine", &["go"])).unwrap();
        let s = spec("wrong_machine", vec![binding("a/b", "go")]);
        assert!(matches!(
            generate(&s, &facts),
            Err(CodegenError::MachineMismatch { .. })
        ));
    }

    #[test]
    fn rejects_event_not_in_external_ingress() {
        let facts = parse_machine_facts(&facts_json("m", &["temp_update"])).unwrap();
        let s = spec("m", vec![binding("home/temp", "not_an_event")]);
        match generate(&s, &facts) {
            Err(CodegenError::UnknownEvent {
                event,
                machine,
                available,
            }) => {
                assert_eq!(event, "not_an_event");
                assert_eq!(machine, "m");
                assert_eq!(available, vec!["temp_update".to_string()]);
            }
            other => panic!("expected UnknownEvent, got {other:?}"),
        }
    }

    #[test]
    fn accepts_event_via_prefix_descriptor() {
        // Machine catches the `sensor` family with one prefix descriptor;
        // a binding injecting the concrete `sensor.temp` is accepted.
        let facts = parse_machine_facts(&facts_json("m", &["sensor"])).unwrap();
        let s = spec("m", vec![binding("home/temp", "sensor.temp")]);
        let out = generate(&s, &facts).expect("generate");
        assert!(out.contains("injector.inject(\"sensor.temp\", \"\");"));
    }

    #[test]
    fn rejects_non_canonical_keyexpr() {
        let facts = parse_machine_facts(&facts_json("m", &["go"])).unwrap();
        // An empty chunk (`a//b`) is not canonicalizable.
        let s = spec("m", vec![binding("a//b", "go")]);
        assert!(matches!(
            generate(&s, &facts),
            Err(CodegenError::Keyexpr { .. })
        ));
    }

    // ---- generate: golden emission ----

    #[test]
    fn golden_two_binding_signal_switchboard() {
        let facts = parse_machine_facts(&facts_json(
            "sensor_monitor",
            &["temp_update", "humidity_update"],
        ))
        .unwrap();
        let s = spec(
            "sensor_monitor",
            vec![
                binding("home/*/temp", "temp_update"),
                binding("home/livingroom/humidity", "humidity_update"),
            ],
        );

        let out = generate(&s, &facts).expect("generate");

        let expected = "\
// @generated by wz-switchboard-codegen (R311gp gc-3a) -- DO NOT EDIT.
//
// Static keyexpr -> SCXML domain-event switchboard for machine
// \"sensor_monitor\". Closed match, no heap: &'static str chunk literals over
// the shared no-alloc matcher. Signal path only (empty _event.data;
// the typed value path is gc-3b). Regenerate by editing the source
// wz-switchboard.yaml and rebuilding.

/// Dispatch a resolved inbound keyexpr against the static switchboard
/// for machine \"sensor_monitor\", injecting each matched domain event in
/// declaration order. Returns the number of events injected. Mirrors
/// `wz_session_core::switchboard::SwitchboardRegistry::dispatch`.
pub fn dispatch_switchboard(
    target_keyexpr: &str,
    injector: &mut dyn wz_session_core::switchboard::EventInjector,
) -> usize {
    let mut injected = 0usize;

    // home/*/temp -> temp_update
    if wz_session_core::keyexpr_match::keyexpr_pattern_matches(&[\"home\", \"*\", \"temp\"], target_keyexpr) {
        injector.inject(\"temp_update\", \"\");
        injected += 1;
    }

    // home/livingroom/humidity -> humidity_update
    if wz_session_core::keyexpr_match::keyexpr_pattern_matches(&[\"home\", \"livingroom\", \"humidity\"], target_keyexpr) {
        injector.inject(\"humidity_update\", \"\");
        injected += 1;
    }
    injected
}
";
        assert_eq!(out, expected);
    }

    #[test]
    fn empty_switchboard_emits_constant_zero_dispatch() {
        let facts = parse_machine_facts(&facts_json("m", &[])).unwrap();
        let out = generate(&spec("m", vec![]), &facts).expect("generate");
        assert!(out.contains("pub fn dispatch_switchboard("));
        assert!(out.contains("let mut injected = 0usize;"));
        // No arms emitted.
        assert!(!out.contains("keyexpr_pattern_matches"));
    }
}
