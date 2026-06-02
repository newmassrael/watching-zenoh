// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! gc-3a/gc-3b — the MCU static switchboard generator (pure library).
//!
//! Turns a [`SwitchboardSpec`] (parsed `wz-switchboard.yaml`) plus a
//! machine's forge-ast.v1 facts into the source of a closed, no-heap
//! `keyexpr -> SCXML domain-event` dispatch function. A binding is either a
//! **signal** row (no `codec`; injects an empty `_event.data`) or a **value**
//! row (a `codec` names the wire decoder; injects a typed `_event.data` via
//! the machine's generated `<Machine>Inject::raise_<event>` seam). Two
//! responsibilities, both performed against the facts the SCE compiler
//! already derived:
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
//!    every matching row fires in declaration order. A signal row injects an
//!    empty `_event.data`; a value row decodes the wire payload with its
//!    forge codec and calls the typed `<Machine>Inject::raise_<event>` seam,
//!    gated on the machine's `typed_inject_events` set and cross-checked so
//!    the codec's decoded fields are a superset of the event's `EventSchema`.
//!    A switchboard with any value row dispatches over `&mut Engine<P>`; a
//!    signal-only switchboard keeps the `&mut dyn EventInjector` port.
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
    /// `ast.document.typed_inject_events` — the subset of
    /// [`Self::external_ingress_events`] whose events carry a generated
    /// `<Machine>Inject::raise_<event>(payload)` typed value-inject seam
    /// (their transition guard lowered to a native typed `_event.data`
    /// comparison; a non-enum schema — primitive plus scalar string/bytes
    /// fields, no script engine). A switchboard
    /// **value** binding's event MUST be a member — an event absent here has
    /// no typed value path (only the signal path), so the generator gates on
    /// this set rather than re-deriving SCE's native-lowering eligibility.
    pub typed_inject_events: BTreeSet<String>,
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
    // forge-ast.v1 (pin c16811a9b): the subset of external_ingress_events
    // whose events have a generated `<Machine>Inject::raise_<event>` typed
    // value-inject seam (guard lowered to native `_event.data.<field>`).
    // Omitted when empty (skip_serializing_if), so default to empty.
    #[serde(default)]
    typed_inject_events: BTreeSet<String>,
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
    /// A value binding (one carrying a `codec`) targets an event the machine
    /// has no typed value-inject seam for: the event is accepted as external
    /// input but its `_event.data` stays on the dynamic baseline (not in
    /// `typed_inject_events`). Such a binding can only be a signal binding —
    /// drop its `codec` or give the machine a native typed guard.
    EventNotTypedInject {
        /// The offending [`Binding::event`].
        event: String,
        /// The machine whose contract rejected it.
        machine: String,
        /// The machine's typed-inject events (sorted), for the fix hint.
        available: Vec<String>,
    },
    /// A value binding's event has no imported `EventSchema` among the facts
    /// supplied to [`generate`] — its typed payload shape is unknown, so the
    /// decoded value cannot be field-mapped. (The consumer build must emit
    /// the EventSchema document's forge-ast and pass it in.)
    MissingEventSchema {
        /// The [`Binding::event`] whose schema was not supplied.
        event: String,
    },
    /// A value binding names a `codec` with no matching [`CodecFacts`] among
    /// the facts supplied to [`generate`] — the wire decoder is unknown.
    CodecNotFound {
        /// The [`Binding::codec`] name that was not supplied.
        codec: String,
        /// The value binding's event, for the fix hint.
        event: String,
    },
    /// The named codec does not decode a field the event's `EventSchema`
    /// declares (by id + SCE type) — the wire format and the `_event.data`
    /// view disagree, so the typed payload cannot be populated. wz owns this
    /// pairing; fix the codec or the EventSchema so the codec's decoded
    /// fields are a superset of the schema's.
    SchemaFieldNotInCodec {
        /// The value binding's event.
        event: String,
        /// The codec that was expected to cover the field.
        codec: String,
        /// The EventSchema field id absent (or type-mismatched) in the codec.
        field: String,
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
            CodegenError::EventNotTypedInject {
                event,
                machine,
                available,
            } => write!(
                f,
                "switchboard value binding event `{event}` has no typed value-inject \
                 seam on machine `{machine}` (not in typed_inject_events — its \
                 `_event.data` stays on the dynamic baseline). Make it a signal \
                 binding (drop `codec`) or give the machine a native typed guard. \
                 Machine's typed-inject events: [{}]",
                available.join(", ")
            ),
            CodegenError::MissingEventSchema { event } => write!(
                f,
                "switchboard value binding event `{event}` has no imported EventSchema \
                 among the supplied facts — its typed payload shape is unknown"
            ),
            CodegenError::CodecNotFound { codec, event } => write!(
                f,
                "switchboard value binding for event `{event}` names codec `{codec}` \
                 but no such codec was supplied to the generator"
            ),
            CodegenError::SchemaFieldNotInCodec {
                event,
                codec,
                field,
            } => write!(
                f,
                "switchboard value binding event `{event}`: codec `{codec}` does not \
                 decode EventSchema field `{field}` (by id + SCE type) — the wire \
                 format and the `_event.data` view disagree"
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
        typed_inject_events: document.typed_inject_events,
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

/// Canonical SCE type of a field as it appears in forge-ast `sce_type`.
///
/// A primitive (`uint8`…`float64`/`bool`/`string`/`bytes`) serializes as a
/// lowercase string; an enum-typed field is a non-primitive object. A
/// native-eligible EventSchema (the only kind reachable on the value path)
/// has primitive-only fields, so [`SceType::NonPrimitive`] only ever shows up
/// on a codec field and is unequal to any schema field — which the
/// field-superset cross-check surfaces as a mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SceType {
    /// A primitive, by its canonical lowercase name (`"float64"`, `"bool"`…).
    Primitive(String),
    /// Any non-primitive (e.g. `enum:<alias>`) — opaque to the value path.
    NonPrimitive,
}

/// The expression that moves a codec-decoded field into the typed
/// `<Machine><Variant>Payload` struct's owned field. `expr` is the decoded
/// access (e.g. `"decoded.sensor_id"`).
///
/// SCE decodes a scalar `string` / `bytes` codec field as a **borrowed** view
/// — `&'a str` / `&'a [u8]`, the lifetime tied to the wire buffer
/// (`sce-build` generator: `(Rust, String) => "&'a str"`,
/// `(Rust, Bytes) => "&'a [u8]"`). The native-lowered payload struct, by
/// contrast, holds the field **owned** — `String` / `Vec<u8>`, no lifetime: it
/// derives `Clone + Default` and the engine queues it past the buffer's life.
/// `.into()` bridges the two (`<&str as Into<String>>` /
/// `<&[u8] as Into<Vec<u8>>>`), the target inferred from the struct field's
/// known type — so no `alloc` / `std` path is named and the one shared helper
/// compiles on both the AP (std) and the MCU (`no_std` + `alloc`) tiers. A
/// primitive (`Copy`) field needs no conversion and moves verbatim, keeping the
/// primitive-only golden byte-identical.
fn owned_field_move(sce_type: &SceType, expr: &str) -> String {
    match sce_type {
        SceType::Primitive(p) if p == "string" || p == "bytes" => format!("{expr}.into()"),
        _ => expr.to_string(),
    }
}

/// One field of an EventSchema or a codec document: its id and SCE type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldFact {
    /// The field id (`_event.data.<id>` on the schema side; the decoded
    /// struct field name on the codec side — the two must agree by name).
    pub id: String,
    /// The canonical SCE type, for the codec-superset-of-schema cross-check.
    pub sce_type: SceType,
}

/// The facts a [`generate`] value binding needs about one imported
/// `EventSchema`: the event it constrains and its typed `_event.data` fields.
/// Parsed from the EventSchema forge-ast document (`kind = "event-schema"`)
/// the consumer build emits alongside the statechart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventSchemaFacts {
    /// The SCXML event this schema constrains (matches [`Binding::event`]).
    pub event_name: String,
    /// The typed fields exposed via `_event.data.<field>`, in declaration
    /// order (the order the generated payload struct literal emits).
    pub fields: Vec<FieldFact>,
}

/// The facts a [`generate`] value binding needs about its wire `codec`: the
/// codec kind name, the Rust module path the consumer generated it under, and
/// its decoded fields (for the superset cross-check). Parsed from the codec
/// forge-ast document (`kind = "codec"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecFacts {
    /// The codec kind name (matches [`Binding::codec`]).
    pub name: String,
    /// Rust path to the module the consumer's build generated this codec
    /// into (e.g. `"temp_payload"` for a sibling `mod temp_payload`). The
    /// decoded struct is `{module_path}::{PascalCase(name)}`.
    pub module_path: String,
    /// The codec's decoded struct fields (must be a superset of the event's
    /// EventSchema fields by id + SCE type).
    pub fields: Vec<FieldFact>,
}

// ---- forge-ast field deserialization (shared by EventSchema + codec) ------

#[derive(Deserialize)]
struct FieldEnvelope {
    v: u32,
    ast: FieldAst,
}

#[derive(Deserialize)]
struct FieldAst {
    document: FieldDocument,
}

#[derive(Deserialize)]
struct FieldDocument {
    kind: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    event_name: String,
    #[serde(default)]
    fields: Vec<ForgeFieldRepr>,
}

#[derive(Deserialize)]
struct ForgeFieldRepr {
    id: String,
    // A primitive `sce_type` is a bare JSON string (`"float64"`); an
    // enum-typed field is an object. We only distinguish the two.
    sce_type: serde_json::Value,
}

impl ForgeFieldRepr {
    fn into_fact(self) -> FieldFact {
        let sce_type = match self.sce_type {
            serde_json::Value::String(s) => SceType::Primitive(s),
            _ => SceType::NonPrimitive,
        };
        FieldFact {
            id: self.id,
            sce_type,
        }
    }
}

fn parse_field_doc(json: &str, expect_kind: &str) -> Result<FieldDocument, CodegenError> {
    let envelope: FieldEnvelope = serde_json::from_str(json).map_err(CodegenError::Json)?;
    if envelope.v != SUPPORTED_FORGE_AST_VERSION {
        return Err(CodegenError::UnsupportedAstVersion(envelope.v));
    }
    let document = envelope.ast.document;
    if document.kind != expect_kind {
        return Err(CodegenError::NotStatechart(document.kind));
    }
    Ok(document)
}

/// Parse an `EventSchema` forge-ast document into the facts the value path
/// needs. Rejects a non-v1 envelope or a non-`event-schema` document.
pub fn parse_event_schema_facts(forge_ast_json: &str) -> Result<EventSchemaFacts, CodegenError> {
    let document = parse_field_doc(forge_ast_json, "event-schema")?;
    Ok(EventSchemaFacts {
        event_name: document.event_name,
        fields: document
            .fields
            .into_iter()
            .map(ForgeFieldRepr::into_fact)
            .collect(),
    })
}

/// Parse a `codec` forge-ast document into the facts the value path needs.
/// `module_path` is the Rust module the consumer's build generated the codec
/// under (a layout choice not carried in the AST). Rejects a non-v1 envelope
/// or a non-`codec` document.
pub fn parse_codec_facts(
    forge_ast_json: &str,
    module_path: impl Into<String>,
) -> Result<CodecFacts, CodegenError> {
    let document = parse_field_doc(forge_ast_json, "codec")?;
    Ok(CodecFacts {
        name: document.name,
        module_path: module_path.into(),
        fields: document
            .fields
            .into_iter()
            .map(ForgeFieldRepr::into_fact)
            .collect(),
    })
}

// ---- SCE naming-filter mirrors (gc-3b SCE-converged design) ---------------
//
// forge-ast.v1 is language-neutral: it publishes the *set* of typed-inject
// events (`typed_inject_events`) but NOT the Rust codegen identifiers, which
// SCE derives from two published naming filters (sce-build/src/filters.rs).
// We mirror those two filters here so the generated `raise_<event>` call and
// `<Machine><Variant>Payload` struct name match SCE's emission byte-for-byte.
// A drift in either filter surfaces as a loud wz compile error (an undefined
// method / type), never a silent mis-inject — and the unit tests below pin
// the contract. (Mirroring two standard case transforms is contract
// consumption, not the Event/Payload-union mangling the switchboard ACL
// exists to prevent — that stays encapsulated in SCE's `<Machine>Inject`.)

/// Mirror of SCE `to_pascal_case`: split on `.` / `_` / `-`, capitalize the
/// first char of each part (rest verbatim), concat. Names the event-enum
/// variant and the `{machine}{Variant}Payload` struct.
fn to_pascal_case(name: &str) -> String {
    if name.is_empty() {
        return "Empty".to_string();
    }
    name.split(['.', '_', '-'])
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// Mirror of SCE `to_snake_case`: `.`/`-` -> `_`, insert `_` before an
/// uppercase preceded by a lowercase/digit, then lowercase. Names the
/// generated inject method `raise_<event>`.
fn to_snake_case(name: &str) -> String {
    if name.is_empty() {
        return "empty".to_string();
    }
    let replaced: String = name
        .chars()
        .map(|c| if c == '.' || c == '-' { '_' } else { c })
        .collect();
    let chars: Vec<char> = replaced.chars().collect();
    let mut result = String::with_capacity(replaced.len() + 4);
    for (i, &ch) in chars.iter().enumerate() {
        if i > 0 && ch.is_ascii_uppercase() {
            let prev = chars[i - 1];
            if prev.is_ascii_lowercase() || prev.is_ascii_digit() {
                result.push('_');
            }
        }
        result.push(ch);
    }
    result.to_lowercase()
}

/// Inputs to [`generate`]: the switchboard spec, the target machine's facts,
/// and — for value bindings — the imported EventSchemas, the wire codecs, and
/// the Rust module path the consumer generated the machine under.
pub struct GenInput<'a> {
    /// The parsed `wz-switchboard.yaml`.
    pub spec: &'a SwitchboardSpec,
    /// The target machine's forge-ast facts (incl. `typed_inject_events`).
    pub facts: &'a MachineFacts,
    /// EventSchema facts for the value bindings' events (looked up by
    /// `event_name`). Empty for a signal-only switchboard.
    pub schemas: &'a [EventSchemaFacts],
    /// Codec facts for the value bindings' codecs (looked up by `name`).
    /// Empty for a signal-only switchboard.
    pub codecs: &'a [CodecFacts],
    /// Rust path to the SCE-generated machine module (holds `{Machine}Policy`,
    /// `{Machine}{Variant}Payload`, the `{Machine}Inject` trait). Unused by a
    /// signal-only switchboard, which never names the machine's types.
    pub machine_module: &'a str,
}

/// Generate the closed `dispatch_switchboard` function source for the spec in
/// `input`, validated against the machine + schema + codec facts.
///
/// The switchboard has two row kinds, chosen per [`Binding::codec`]:
///  - **signal** (no codec) — injects the event with an empty `_event.data`.
///  - **value** (codec present) — decodes the wire payload and injects a typed
///    `_event.data` via the machine's generated `<Machine>Inject` seam.
///
/// A switchboard with at least one value row emits a dispatch over
/// `&mut Engine<{Machine}Policy>` (the typed path needs the concrete engine);
/// a signal-only switchboard keeps the `&mut dyn EventInjector` port (no SCE
/// runtime dependency), byte-identical to the gc-3a shape.
///
/// Validation per binding: machine pairing (whole-spec); event accepted as
/// external input (W3C 3.12.1); for a value row additionally — event in
/// `typed_inject_events`, an EventSchema supplied, the codec supplied, and the
/// codec's decoded fields a superset of the schema's (id + SCE type); then the
/// keyexpr canonicalizes. Any failure aborts with a [`CodegenError`]; on
/// success the returned `String` is ready to `include!` from a consumer's
/// `OUT_DIR`.
pub fn generate(input: &GenInput) -> Result<String, CodegenError> {
    let spec = input.spec;
    let facts = input.facts;
    if spec.machine != facts.name {
        return Err(CodegenError::MachineMismatch {
            spec: spec.machine.clone(),
            machine: facts.name.clone(),
        });
    }

    let has_value = spec.bindings.iter().any(|b| b.codec.is_some());
    let machine_pascal = to_pascal_case(&facts.name);
    let machine_module = input.machine_module;

    let mut arms = String::new();
    // Per-value-event SSOT: the decode + typed `raise_<event>` body is emitted
    // ONCE as a free helper `inject_<event>`, shared by the static
    // `dispatch_switchboard` arms (MCU) and the generated `{Machine}Injector`
    // value seam (AP dynamic registry). `seen_value_events` dedups it across
    // multiple keyexpr bindings that target the same value event.
    let mut value_helpers = String::new();
    let mut injector_value_arms = String::new();
    let mut seen_value_events: BTreeSet<String> = BTreeSet::new();
    for binding in &spec.bindings {
        // Every binding's event must be accepted as external input (W3C 3.12.1).
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

        // Canonicalize the keyexpr with the runtime's own canonicalizer
        // (shared SSOT) so the static chunks match the wire form.
        let canonical = wz_session_core::keyexpr_canon::canonize_keyexpr(&binding.keyexpr)
            .map_err(|e| CodegenError::Keyexpr {
                keyexpr: binding.keyexpr.clone(),
                reason: e.to_string(),
            })?;
        let chunks = canonical
            .split('/')
            .map(rust_string_literal)
            .collect::<Vec<_>>()
            .join(", ");

        match &binding.codec {
            // ---- signal row ------------------------------------------------
            None => {
                let inject = if has_value {
                    // Value-bearing dispatch threads the concrete engine.
                    format!(
                        "engine.raise_external_by_name({}, \"\");",
                        rust_string_literal(&binding.event)
                    )
                } else {
                    format!(
                        "injector.inject({}, \"\");",
                        rust_string_literal(&binding.event)
                    )
                };
                arms.push_str(&format!(
                    "\n    // {canonical} -> {event} (signal)\n    \
                     if wz_session_core::keyexpr_match::keyexpr_pattern_matches(&[{chunks}], target_keyexpr) {{\n        \
                     {inject}\n        \
                     injected += 1;\n    }}\n",
                    canonical = canonical,
                    event = binding.event,
                    chunks = chunks,
                    inject = inject,
                ));
            }
            // ---- value row -------------------------------------------------
            Some(codec_name) => {
                // Gate on the machine's typed-inject seam set (SSOT for
                // native-lowering eligibility — never re-derived here).
                let typed = facts
                    .typed_inject_events
                    .iter()
                    .any(|descriptor| event_descriptor_matches(descriptor, &binding.event));
                if !typed {
                    return Err(CodegenError::EventNotTypedInject {
                        event: binding.event.clone(),
                        machine: facts.name.clone(),
                        available: facts.typed_inject_events.iter().cloned().collect(),
                    });
                }
                let schema = input
                    .schemas
                    .iter()
                    .find(|s| s.event_name == binding.event)
                    .ok_or_else(|| CodegenError::MissingEventSchema {
                        event: binding.event.clone(),
                    })?;
                let codec = input
                    .codecs
                    .iter()
                    .find(|c| &c.name == codec_name)
                    .ok_or_else(|| CodegenError::CodecNotFound {
                        codec: codec_name.clone(),
                        event: binding.event.clone(),
                    })?;
                // wz owns the codec<->schema pairing: every schema field must
                // be decoded by the codec under the same id + SCE type, so the
                // wire format and the `_event.data` view cannot drift.
                for sf in &schema.fields {
                    let covered = codec
                        .fields
                        .iter()
                        .any(|cf| cf.id == sf.id && cf.sce_type == sf.sce_type);
                    if !covered {
                        return Err(CodegenError::SchemaFieldNotInCodec {
                            event: binding.event.clone(),
                            codec: codec.name.clone(),
                            field: sf.id.clone(),
                        });
                    }
                }

                let variant = to_pascal_case(&binding.event);
                let snake = to_snake_case(&binding.event);
                let method = format!("raise_{snake}");
                let helper = format!("inject_{snake}");
                let codec_struct =
                    format!("{}::{}", codec.module_path, to_pascal_case(&codec.name));
                // The static-match arm is now a call to the shared per-event
                // helper (so the decode body lives in exactly one place — see
                // `value_helpers` below). `&&` short-circuits: the helper (which
                // decodes + injects) runs only on a keyexpr match, and the row
                // counts only when the bytes decode.
                arms.push_str(&format!(
                    "\n    // {canonical} -> {event} (value via {codec})\n    \
                     if wz_session_core::keyexpr_match::keyexpr_pattern_matches(&[{chunks}], target_keyexpr)\n        \
                     && {helper}(payload, engine)\n    {{\n        \
                     injected += 1;\n    }}\n",
                    canonical = canonical,
                    event = binding.event,
                    codec = codec.name,
                    chunks = chunks,
                    helper = helper,
                ));

                // Emit the helper + injector value arm once per unique event.
                if seen_value_events.insert(binding.event.clone()) {
                    // Field moves in schema declaration order (each on its own
                    // line at 12-space indent inside the struct literal). A
                    // scalar string/bytes field decodes borrowed (`&str` /
                    // `&[u8]`) but the payload struct holds it owned (`String` /
                    // `Vec<u8>`), so `owned_field_move` threads the `.into()`;
                    // primitive fields move verbatim.
                    let field_moves = schema
                        .fields
                        .iter()
                        .map(|f| {
                            let mv = owned_field_move(&f.sce_type, &format!("decoded.{}", f.id));
                            format!("\n            {id}: {mv},", id = f.id, mv = mv)
                        })
                        .collect::<String>();
                    value_helpers.push_str(&format!(
                        "\n/// Decode the wire payload for `{event}` with the `{codec}` forge codec\n\
                         /// and inject the typed `_event.data` via the generated\n\
                         /// `{machine_pascal}Inject::{method}` seam. Returns whether the bytes decoded.\n\
                         /// Shared SSOT for the static `dispatch_switchboard` arm and the\n\
                         /// `{machine_pascal}Injector` value seam (one decode body, both profiles).\n\
                         fn {helper}(\n    \
                         payload: &[u8],\n    \
                         engine: &mut ::sce_rust_runtime::Engine<{machine_module}::{machine_pascal}Policy>,\n\
                         ) -> bool {{\n    \
                         let mut cursor = ::sce_forge_runtime::codec::SceCursor::new(payload);\n    \
                         if let Ok(decoded) = {codec_struct}::decode(&mut cursor) {{\n        \
                         engine.{method}({machine_module}::{machine_pascal}{variant}Payload {{{field_moves}\n        \
                         }});\n        \
                         true\n    \
                         }} else {{\n        \
                         false\n    \
                         }}\n\
                         }}\n",
                        event = binding.event,
                        codec = codec.name,
                        helper = helper,
                        method = method,
                        machine_module = machine_module,
                        machine_pascal = machine_pascal,
                        variant = variant,
                        codec_struct = codec_struct,
                        field_moves = field_moves,
                    ));
                    injector_value_arms.push_str(&format!(
                        "            {event} => {helper}(payload, self.engine),\n",
                        event = rust_string_literal(&binding.event),
                        helper = helper,
                    ));
                }
            }
        }
    }

    if has_value {
        Ok(format!(
            "// @generated by wz-switchboard-codegen (gc-3b) -- DO NOT EDIT.\n\
             //\n\
             // Static + dynamic keyexpr -> SCXML domain-event switchboard for machine\n\
             // {machine:?}. Signal rows inject an empty _event.data\n\
             // (Engine::raise_external_by_name); value rows decode the wire payload with\n\
             // a forge codec and inject the typed _event.data via the generated\n\
             // <Machine>Inject::raise_<event> seam. The per-event decode body is emitted\n\
             // ONCE as an `inject_<event>` helper, shared by:\n\
             //   - `dispatch_switchboard` -- the closed no-heap MCU static match;\n\
             //   - `{machine_pascal}Injector` -- the EventInjector the AP dynamic\n\
             //     SwitchboardRegistry threads (one guard semantics across profiles).\n\
             // Regenerate by editing the source wz-switchboard.yaml and rebuilding.\n\
             \n\
             use {machine_module}::{machine_pascal}Inject;\n\
             {value_helpers}\n\
             /// Per-machine value-capable [`EventInjector`] for the AP dynamic\n\
             /// [`SwitchboardRegistry`]: a transient `&mut Engine` view (constructed\n\
             /// at the dispatch site, mirroring the bridge `EngineInjector`) that\n\
             /// resolves a value event's codec ↔ payload binding the registry's\n\
             /// type-erased rows cannot carry. Signal rows fall through to\n\
             /// `raise_external_by_name`.\n\
             ///\n\
             /// [`EventInjector`]: wz_session_core::switchboard::EventInjector\n\
             /// [`SwitchboardRegistry`]: wz_session_core::switchboard::SwitchboardRegistry\n\
             pub struct {machine_pascal}Injector<'e> {{\n    \
             engine: &'e mut ::sce_rust_runtime::Engine<{machine_module}::{machine_pascal}Policy>,\n\
             }}\n\
             \n\
             impl<'e> {machine_pascal}Injector<'e> {{\n    \
             /// Wrap a borrowed engine as the value-capable injector port.\n    \
             pub fn new(\n        \
             engine: &'e mut ::sce_rust_runtime::Engine<{machine_module}::{machine_pascal}Policy>,\n    \
             ) -> Self {{\n        \
             Self {{ engine }}\n    \
             }}\n\
             }}\n\
             \n\
             impl wz_session_core::switchboard::EventInjector for {machine_pascal}Injector<'_> {{\n    \
             fn inject(&mut self, event_name: &str, event_data: &str) {{\n        \
             self.engine.raise_external_by_name(event_name, event_data);\n    \
             }}\n\
             \n    \
             fn inject_value(&mut self, event_name: &str, payload: &[u8]) -> bool {{\n        \
             match event_name {{\n\
             {injector_value_arms}            \
             _ => false,\n        \
             }}\n    \
             }}\n\
             }}\n\
             \n\
             /// Dispatch a resolved inbound keyexpr against the static switchboard\n\
             /// for machine {machine:?}, injecting each matched domain event in\n\
             /// declaration order. Returns the number of events injected. `payload`\n\
             /// is the inbound sample's wire bytes (read only by value rows).\n\
             pub fn dispatch_switchboard(\n    \
             target_keyexpr: &str,\n    \
             payload: &[u8],\n    \
             engine: &mut ::sce_rust_runtime::Engine<{machine_module}::{machine_pascal}Policy>,\n\
             ) -> usize {{\n    \
             let mut injected = 0usize;\n\
             {arms}    \
             injected\n\
             }}\n",
            machine = spec.machine,
            machine_module = machine_module,
            machine_pascal = machine_pascal,
            value_helpers = value_helpers,
            injector_value_arms = injector_value_arms,
            arms = arms,
        ))
    } else {
        Ok(format!(
            "// @generated by wz-switchboard-codegen (gc-3b) -- DO NOT EDIT.\n\
             //\n\
             // Static keyexpr -> SCXML domain-event switchboard for machine\n\
             // {machine:?}. Closed match, no heap: &'static str chunk literals over\n\
             // the shared no-alloc matcher. Signal path only (empty _event.data) —\n\
             // this switchboard declares no value bindings, so it keeps the\n\
             // dyn EventInjector port. Regenerate by editing the source\n\
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
            codec: None,
        }
    }

    fn spec(machine: &str, bindings: Vec<Binding>) -> SwitchboardSpec {
        SwitchboardSpec {
            machine: machine.to_string(),
            bindings,
        }
    }

    // A statechart envelope that also carries `typed_inject_events` (the
    // typed value-inject seam subset, pin c16811a9b). `typed` ⊆ `ingress`.
    fn facts_json_typed(name: &str, ingress: &[&str], typed: &[&str]) -> String {
        let arr = |xs: &[&str]| {
            xs.iter()
                .map(|e| format!("{e:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let events = if ingress.is_empty() {
            "\"error.execution\"".to_string()
        } else {
            format!("\"error.execution\", {}", arr(ingress))
        };
        format!(
            r#"{{
                "v": 1,
                "ast": {{
                    "document": {{
                        "kind": "statechart",
                        "name": "{name}",
                        "events": [{events}],
                        "external_ingress_events": [{ingress}],
                        "typed_inject_events": [{typed}]
                    }}
                }}
            }}"#,
            ingress = arr(ingress),
            typed = arr(typed),
        )
    }

    // An EventSchema forge-ast document carrying just the fields the value
    // path reads (`event_name` + `fields[{id, sce_type}]`).
    fn schema_json(event_name: &str, fields: &[(&str, &str)]) -> String {
        let fields_arr = fields
            .iter()
            .map(|(id, ty)| format!(r#"{{"id":"{id}","sce_type":"{ty}","direction":"in"}}"#))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            r#"{{"v":1,"ast":{{"document":{{"kind":"event-schema","name":"{event_name}_schema","event_name":"{event_name}","fields":[{fields_arr}]}}}}}}"#
        )
    }

    // A codec forge-ast document with the same field shape.
    fn codec_json(name: &str, fields: &[(&str, &str)]) -> String {
        let fields_arr = fields
            .iter()
            .map(|(id, ty)| format!(r#"{{"id":"{id}","sce_type":"{ty}","direction":"in"}}"#))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            r#"{{"v":1,"ast":{{"document":{{"kind":"codec","name":"{name}","fields":[{fields_arr}]}}}}}}"#
        )
    }

    fn value_binding(keyexpr: &str, event: &str, codec: &str) -> Binding {
        Binding {
            keyexpr: keyexpr.to_string(),
            event: event.to_string(),
            codec: Some(codec.to_string()),
        }
    }

    // Signal-only generate (gc-3a shape): empty schema/codec facts.
    fn gen_signal(spec: &SwitchboardSpec, facts: &MachineFacts) -> Result<String, CodegenError> {
        generate(&GenInput {
            spec,
            facts,
            schemas: &[],
            codecs: &[],
            machine_module: "machine",
        })
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
            gen_signal(&s, &facts),
            Err(CodegenError::MachineMismatch { .. })
        ));
    }

    #[test]
    fn rejects_event_not_in_external_ingress() {
        let facts = parse_machine_facts(&facts_json("m", &["temp_update"])).unwrap();
        let s = spec("m", vec![binding("home/temp", "not_an_event")]);
        match gen_signal(&s, &facts) {
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
        let out = gen_signal(&s, &facts).expect("generate");
        assert!(out.contains("injector.inject(\"sensor.temp\", \"\");"));
    }

    #[test]
    fn rejects_non_canonical_keyexpr() {
        let facts = parse_machine_facts(&facts_json("m", &["go"])).unwrap();
        // An empty chunk (`a//b`) is not canonicalizable.
        let s = spec("m", vec![binding("a//b", "go")]);
        assert!(matches!(
            gen_signal(&s, &facts),
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

        let out = gen_signal(&s, &facts).expect("generate");

        let expected = "\
// @generated by wz-switchboard-codegen (gc-3b) -- DO NOT EDIT.
//
// Static keyexpr -> SCXML domain-event switchboard for machine
// \"sensor_monitor\". Closed match, no heap: &'static str chunk literals over
// the shared no-alloc matcher. Signal path only (empty _event.data) —
// this switchboard declares no value bindings, so it keeps the
// dyn EventInjector port. Regenerate by editing the source
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

    // home/*/temp -> temp_update (signal)
    if wz_session_core::keyexpr_match::keyexpr_pattern_matches(&[\"home\", \"*\", \"temp\"], target_keyexpr) {
        injector.inject(\"temp_update\", \"\");
        injected += 1;
    }

    // home/livingroom/humidity -> humidity_update (signal)
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
        let out = gen_signal(&spec("m", vec![]), &facts).expect("generate");
        assert!(out.contains("pub fn dispatch_switchboard("));
        assert!(out.contains("let mut injected = 0usize;"));
        // No arms emitted.
        assert!(!out.contains("keyexpr_pattern_matches"));
    }

    // ---- naming-filter mirrors (pin the SCE contract) ----

    #[test]
    fn naming_filters_match_sce_emission() {
        // These outputs must equal SCE's to_pascal_case / to_snake_case
        // (sce-build/src/filters.rs) — a drift is a loud wz compile error.
        assert_eq!(to_pascal_case("temp_update"), "TempUpdate");
        assert_eq!(to_pascal_case("job.completed"), "JobCompleted");
        assert_eq!(to_pascal_case("sensor_monitor"), "SensorMonitor");
        assert_eq!(to_pascal_case("door-opened"), "DoorOpened");
        assert_eq!(to_snake_case("temp_update"), "temp_update");
        assert_eq!(to_snake_case("job.completed"), "job_completed");
        assert_eq!(to_snake_case("door-opened"), "door_opened");
    }

    // ---- parse_event_schema_facts / parse_codec_facts ----

    #[test]
    fn parses_event_schema_and_codec_facts() {
        let s =
            parse_event_schema_facts(&schema_json("temp_update", &[("temperature", "float64")]))
                .expect("schema");
        assert_eq!(s.event_name, "temp_update");
        assert_eq!(
            s.fields,
            vec![FieldFact {
                id: "temperature".to_string(),
                sce_type: SceType::Primitive("float64".to_string()),
            }]
        );

        let c = parse_codec_facts(
            &codec_json(
                "temp_payload",
                &[("temperature", "float64"), ("seq", "uint32")],
            ),
            "temp_payload",
        )
        .expect("codec");
        assert_eq!(c.name, "temp_payload");
        assert_eq!(c.module_path, "temp_payload");
        assert_eq!(c.fields.len(), 2);

        // A non-`event-schema` document is rejected on the schema parse path.
        assert!(matches!(
            parse_event_schema_facts(&codec_json("x", &[])),
            Err(CodegenError::NotStatechart(k)) if k == "codec"
        ));
    }

    // ---- generate: value-path golden ----

    #[test]
    fn golden_mixed_value_and_signal_switchboard() {
        let facts = parse_machine_facts(&facts_json_typed(
            "sensor_monitor",
            &["temp_update", "door_opened"],
            &["temp_update"],
        ))
        .unwrap();
        let schema =
            parse_event_schema_facts(&schema_json("temp_update", &[("temperature", "float64")]))
                .unwrap();
        // Codec decodes a superset: the schema field plus an extra wire field.
        let codec = parse_codec_facts(
            &codec_json(
                "temp_payload",
                &[("temperature", "float64"), ("seq", "uint32")],
            ),
            "temp_payload",
        )
        .unwrap();
        let s = spec(
            "sensor_monitor",
            vec![
                value_binding("home/*/temp", "temp_update", "temp_payload"),
                binding("home/door", "door_opened"),
            ],
        );

        let out = generate(&GenInput {
            spec: &s,
            facts: &facts,
            schemas: &[schema],
            codecs: &[codec],
            machine_module: "sensor_monitor",
        })
        .expect("generate");

        let expected = "\
// @generated by wz-switchboard-codegen (gc-3b) -- DO NOT EDIT.
//
// Static + dynamic keyexpr -> SCXML domain-event switchboard for machine
// \"sensor_monitor\". Signal rows inject an empty _event.data
// (Engine::raise_external_by_name); value rows decode the wire payload with
// a forge codec and inject the typed _event.data via the generated
// <Machine>Inject::raise_<event> seam. The per-event decode body is emitted
// ONCE as an `inject_<event>` helper, shared by:
//   - `dispatch_switchboard` -- the closed no-heap MCU static match;
//   - `SensorMonitorInjector` -- the EventInjector the AP dynamic
//     SwitchboardRegistry threads (one guard semantics across profiles).
// Regenerate by editing the source wz-switchboard.yaml and rebuilding.

use sensor_monitor::SensorMonitorInject;

/// Decode the wire payload for `temp_update` with the `temp_payload` forge codec
/// and inject the typed `_event.data` via the generated
/// `SensorMonitorInject::raise_temp_update` seam. Returns whether the bytes decoded.
/// Shared SSOT for the static `dispatch_switchboard` arm and the
/// `SensorMonitorInjector` value seam (one decode body, both profiles).
fn inject_temp_update(
    payload: &[u8],
    engine: &mut ::sce_rust_runtime::Engine<sensor_monitor::SensorMonitorPolicy>,
) -> bool {
    let mut cursor = ::sce_forge_runtime::codec::SceCursor::new(payload);
    if let Ok(decoded) = temp_payload::TempPayload::decode(&mut cursor) {
        engine.raise_temp_update(sensor_monitor::SensorMonitorTempUpdatePayload {
            temperature: decoded.temperature,
        });
        true
    } else {
        false
    }
}

/// Per-machine value-capable [`EventInjector`] for the AP dynamic
/// [`SwitchboardRegistry`]: a transient `&mut Engine` view (constructed
/// at the dispatch site, mirroring the bridge `EngineInjector`) that
/// resolves a value event's codec ↔ payload binding the registry's
/// type-erased rows cannot carry. Signal rows fall through to
/// `raise_external_by_name`.
///
/// [`EventInjector`]: wz_session_core::switchboard::EventInjector
/// [`SwitchboardRegistry`]: wz_session_core::switchboard::SwitchboardRegistry
pub struct SensorMonitorInjector<'e> {
    engine: &'e mut ::sce_rust_runtime::Engine<sensor_monitor::SensorMonitorPolicy>,
}

impl<'e> SensorMonitorInjector<'e> {
    /// Wrap a borrowed engine as the value-capable injector port.
    pub fn new(
        engine: &'e mut ::sce_rust_runtime::Engine<sensor_monitor::SensorMonitorPolicy>,
    ) -> Self {
        Self { engine }
    }
}

impl wz_session_core::switchboard::EventInjector for SensorMonitorInjector<'_> {
    fn inject(&mut self, event_name: &str, event_data: &str) {
        self.engine.raise_external_by_name(event_name, event_data);
    }

    fn inject_value(&mut self, event_name: &str, payload: &[u8]) -> bool {
        match event_name {
            \"temp_update\" => inject_temp_update(payload, self.engine),
            _ => false,
        }
    }
}

/// Dispatch a resolved inbound keyexpr against the static switchboard
/// for machine \"sensor_monitor\", injecting each matched domain event in
/// declaration order. Returns the number of events injected. `payload`
/// is the inbound sample's wire bytes (read only by value rows).
pub fn dispatch_switchboard(
    target_keyexpr: &str,
    payload: &[u8],
    engine: &mut ::sce_rust_runtime::Engine<sensor_monitor::SensorMonitorPolicy>,
) -> usize {
    let mut injected = 0usize;

    // home/*/temp -> temp_update (value via temp_payload)
    if wz_session_core::keyexpr_match::keyexpr_pattern_matches(&[\"home\", \"*\", \"temp\"], target_keyexpr)
        && inject_temp_update(payload, engine)
    {
        injected += 1;
    }

    // home/door -> door_opened (signal)
    if wz_session_core::keyexpr_match::keyexpr_pattern_matches(&[\"home\", \"door\"], target_keyexpr) {
        engine.raise_external_by_name(\"door_opened\", \"\");
        injected += 1;
    }
    injected
}
";
        assert_eq!(out, expected);
    }

    // ---- generate: value injector emission + helper dedup (SSOT) ----

    #[test]
    fn value_switchboard_emits_injector_and_helper() {
        let facts = parse_machine_facts(&facts_json_typed("m", &["temp_update"], &["temp_update"]))
            .unwrap();
        let s = spec(
            "m",
            vec![value_binding("home/temp", "temp_update", "temp_payload")],
        );
        let schemas =
            [parse_event_schema_facts(&schema_json("temp_update", &[("t", "float64")])).unwrap()];
        let codecs = [parse_codec_facts(
            &codec_json("temp_payload", &[("t", "float64")]),
            "temp_payload",
        )
        .unwrap()];
        let out = generate(&value_input(&s, &facts, &schemas, &codecs)).expect("generate");

        // The per-machine injector the AP dynamic registry threads.
        assert!(out.contains("pub struct MInjector<'e>"));
        assert!(out.contains("impl wz_session_core::switchboard::EventInjector for MInjector<'_>"));
        // Signal seam delegates to raise_external_by_name.
        assert!(out.contains("self.engine.raise_external_by_name(event_name, event_data);"));
        // Value seam matches event name to the shared helper.
        assert!(out.contains("\"temp_update\" => inject_temp_update(payload, self.engine),"));
        // The shared decode helper is emitted (one body, both profiles).
        assert!(out.contains("fn inject_temp_update(\n"));
        // The static arm calls the same helper (no inline decode duplicated).
        assert!(out.contains("&& inject_temp_update(payload, engine)\n"));
        assert!(!out.contains("SceCursor::new(payload);\n        if let Ok(decoded)"));
    }

    #[test]
    fn two_value_bindings_same_event_share_one_helper() {
        // Two keyexprs route to the SAME value event: the decode helper and the
        // injector match arm are emitted ONCE (dedup), but each keyexpr keeps
        // its own static dispatch arm.
        let facts = parse_machine_facts(&facts_json_typed("m", &["temp_update"], &["temp_update"]))
            .unwrap();
        let s = spec(
            "m",
            vec![
                value_binding("home/*/temp", "temp_update", "temp_payload"),
                value_binding("office/temp", "temp_update", "temp_payload"),
            ],
        );
        let schemas =
            [parse_event_schema_facts(&schema_json("temp_update", &[("t", "float64")])).unwrap()];
        let codecs = [parse_codec_facts(
            &codec_json("temp_payload", &[("t", "float64")]),
            "temp_payload",
        )
        .unwrap()];
        let out = generate(&value_input(&s, &facts, &schemas, &codecs)).expect("generate");

        assert_eq!(
            out.matches("fn inject_temp_update(\n").count(),
            1,
            "one helper"
        );
        assert_eq!(
            out.matches("\"temp_update\" => inject_temp_update(payload, self.engine),")
                .count(),
            1,
            "one injector arm"
        );
        assert_eq!(
            out.matches("&& inject_temp_update(payload, engine)\n")
                .count(),
            2,
            "two static dispatch arms (one per keyexpr)"
        );
    }

    // ---- generate: borrowed string/bytes field owned-conversion ----

    #[test]
    fn value_string_and_bytes_fields_convert_to_owned() {
        // A schema mixing a primitive (`celsius_centi`), a borrowed-decoded
        // string (`sensor_id`), and a borrowed-decoded bytes (`raw`) field.
        // The primitive guard keeps the event in typed_inject_events; the
        // string/bytes fields ride along in the payload struct and must be
        // moved owned (`.into()`), while the primitive moves verbatim.
        let facts = parse_machine_facts(&facts_json_typed("m", &["temp_update"], &["temp_update"]))
            .unwrap();
        let s = spec(
            "m",
            vec![value_binding("home/temp", "temp_update", "temp_payload")],
        );
        let fields = &[
            ("celsius_centi", "uint16"),
            ("sensor_id", "string"),
            ("raw", "bytes"),
        ];
        let schemas = [parse_event_schema_facts(&schema_json("temp_update", fields)).unwrap()];
        let codecs =
            [parse_codec_facts(&codec_json("temp_payload", fields), "temp_payload").unwrap()];
        let out = generate(&value_input(&s, &facts, &schemas, &codecs)).expect("generate");

        // Primitive moves verbatim (Copy out of the borrowed struct).
        assert!(out.contains("celsius_centi: decoded.celsius_centi,"));
        // Borrowed string/bytes views are deep-copied into the owned payload
        // fields via `.into()` (`&str -> String`, `&[u8] -> Vec<u8>`).
        assert!(out.contains("sensor_id: decoded.sensor_id.into(),"));
        assert!(out.contains("raw: decoded.raw.into(),"));
        // No `.into()` is sprayed onto the primitive (would trip
        // clippy::useless_conversion and drift the primitive golden).
        assert!(!out.contains("celsius_centi: decoded.celsius_centi.into(),"));
    }

    // ---- generate: value-path validation rejections ----

    fn value_input<'a>(
        spec: &'a SwitchboardSpec,
        facts: &'a MachineFacts,
        schemas: &'a [EventSchemaFacts],
        codecs: &'a [CodecFacts],
    ) -> GenInput<'a> {
        GenInput {
            spec,
            facts,
            schemas,
            codecs,
            machine_module: "m",
        }
    }

    #[test]
    fn value_event_not_in_typed_inject_is_rejected() {
        // Event is external-ingress but NOT a typed-inject seam.
        let facts = parse_machine_facts(&facts_json_typed("m", &["temp_update"], &[])).unwrap();
        let s = spec(
            "m",
            vec![value_binding("home/temp", "temp_update", "temp_payload")],
        );
        let schemas =
            [parse_event_schema_facts(&schema_json("temp_update", &[("t", "float64")])).unwrap()];
        let codecs = [parse_codec_facts(
            &codec_json("temp_payload", &[("t", "float64")]),
            "temp_payload",
        )
        .unwrap()];
        assert!(matches!(
            generate(&value_input(&s, &facts, &schemas, &codecs)),
            Err(CodegenError::EventNotTypedInject { .. })
        ));
    }

    #[test]
    fn value_missing_event_schema_is_rejected() {
        let facts = parse_machine_facts(&facts_json_typed("m", &["temp_update"], &["temp_update"]))
            .unwrap();
        let s = spec(
            "m",
            vec![value_binding("home/temp", "temp_update", "temp_payload")],
        );
        let codecs = [parse_codec_facts(
            &codec_json("temp_payload", &[("t", "float64")]),
            "temp_payload",
        )
        .unwrap()];
        assert!(matches!(
            generate(&value_input(&s, &facts, &[], &codecs)),
            Err(CodegenError::MissingEventSchema { .. })
        ));
    }

    #[test]
    fn value_codec_not_found_is_rejected() {
        let facts = parse_machine_facts(&facts_json_typed("m", &["temp_update"], &["temp_update"]))
            .unwrap();
        let s = spec(
            "m",
            vec![value_binding("home/temp", "temp_update", "temp_payload")],
        );
        let schemas =
            [parse_event_schema_facts(&schema_json("temp_update", &[("t", "float64")])).unwrap()];
        assert!(matches!(
            generate(&value_input(&s, &facts, &schemas, &[])),
            Err(CodegenError::CodecNotFound { .. })
        ));
    }

    #[test]
    fn value_codec_missing_schema_field_is_rejected() {
        let facts = parse_machine_facts(&facts_json_typed("m", &["temp_update"], &["temp_update"]))
            .unwrap();
        let s = spec(
            "m",
            vec![value_binding("home/temp", "temp_update", "temp_payload")],
        );
        // Schema needs `temperature: float64`; codec decodes a differently-named
        // (or differently-typed) field -> superset check fails.
        let schemas =
            [
                parse_event_schema_facts(&schema_json(
                    "temp_update",
                    &[("temperature", "float64")],
                ))
                .unwrap(),
            ];
        let codecs = [parse_codec_facts(
            &codec_json("temp_payload", &[("temperature", "int32")]),
            "temp_payload",
        )
        .unwrap()];
        match generate(&value_input(&s, &facts, &schemas, &codecs)) {
            Err(CodegenError::SchemaFieldNotInCodec {
                event,
                codec,
                field,
            }) => {
                assert_eq!(event, "temp_update");
                assert_eq!(codec, "temp_payload");
                assert_eq!(field, "temperature");
            }
            other => panic!("expected SchemaFieldNotInCodec, got {other:?}"),
        }
    }
}
