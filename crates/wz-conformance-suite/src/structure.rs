// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The structure the abstract test suite is written to: its test configurations, its test
//! purposes, the abstract service primitives the upper tester offers, and the test management
//! protocol that carries them (docs/conformance-suite.md sections 7 and 8).
//!
//! None of it says how a test is executed; that is the abstract test suite's, in the SCE test
//! profile. What is held here is that each part names only what exists: a purpose names
//! requirements, a configuration and primitives that exist; a selection names support items of
//! the PICS; a primitive's parameters and the protocol's fields have one key each; and the
//! protocol has the messages its rules speak of.

use std::collections::BTreeSet;

use serde::Deserialize;

use crate::selection::{is_item_id, Selection};
use crate::{AnswerKind, Suite, FORMAT_VERSION};

/// The format names this module reads.
pub const CONFIGURATIONS_FORMAT: &str = "wz-conformance-configurations";
pub const PURPOSES_FORMAT: &str = "wz-conformance-purposes";
pub const ASP_FORMAT: &str = "wz-conformance-asp";
pub const TMP_FORMAT: &str = "wz-conformance-tmp";

/// The committed configurations, `conformance/suite/configurations.toml`.
pub const CONFIGURATIONS: &str = include_str!("../../../conformance/suite/configurations.toml");

/// The committed purpose files, by their path under `conformance/suite/`.
pub const PURPOSE_FILES: &[(&str, &str)] = &[
    (
        "purposes/transport.toml",
        include_str!("../../../conformance/suite/purposes/transport.toml"),
    ),
    (
        "purposes/network.toml",
        include_str!("../../../conformance/suite/purposes/network.toml"),
    ),
];

/// The committed primitives, `conformance/suite/asp.toml`.
pub const ASP: &str = include_str!("../../../conformance/suite/asp.toml");

/// The committed test management protocol, `conformance/suite/tmp.toml`.
pub const TMP: &str = include_str!("../../../conformance/suite/tmp.toml");

/// The messages the protocol's rules name, which the protocol must therefore have.
const RULE_MESSAGES: &[&str] = &[
    "hello",
    "hello-reply",
    "command",
    "confirm",
    "indication",
    "reset",
];

/// A zenoh role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Client,
    Peer,
    Router,
}

/// The kind of link a lower tester component is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkKind {
    Stream,
    Datagram,
    Multicast,
}

/// Which end of the link a lower tester component is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum End {
    Dials,
    Accepts,
    Group,
}

/// One lower tester component of a configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LowerComponent {
    pub name: String,
    pub role: Role,
    pub link: LinkKind,
    pub end: End,
}

/// One test configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub id: String,
    pub summary: String,
    pub iut: Role,
    pub selection: Option<String>,
    pub lower: Vec<LowerComponent>,
}

/// The configurations file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationFile {
    pub format: String,
    pub format_version: u32,
    #[serde(rename = "configuration")]
    pub configurations: Vec<Configuration>,
}

/// One test purpose.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Purpose {
    pub id: String,
    pub requirements: Vec<String>,
    pub configuration: String,
    pub selection: Option<String>,
    pub primitives: Vec<String>,
    pub with: String,
    pub when: String,
    pub then: String,
}

/// One file of test purposes.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurposeFile {
    pub format: String,
    pub format_version: u32,
    pub part: String,
    #[serde(rename = "purpose")]
    pub purposes: Vec<Purpose>,
}

/// Whether a primitive is asked of the upper tester or reported by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrimitiveKind {
    Request,
    Indication,
}

/// The type of a primitive's parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParameterType {
    Uint,
    Int,
    Bool,
    Text,
    Bytes,
    Keyexpr,
    Handle,
    Enum,
    Duration,
}

/// A parameter of a primitive or of a compound procedure.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Parameter {
    pub key: u64,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ParameterType,
    #[serde(default)]
    pub values: Vec<String>,
    #[serde(default)]
    pub optional: bool,
}

/// One abstract service primitive.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Primitive {
    pub id: String,
    pub code: u64,
    pub kind: PrimitiveKind,
    pub selection: Option<String>,
    pub summary: String,
    pub parameters: Vec<Parameter>,
}

/// The primitives file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AspFile {
    pub format: String,
    pub format_version: u32,
    #[serde(rename = "primitive")]
    pub primitives: Vec<Primitive>,
}

/// Which tester sends a protocol message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    Lower,
    Upper,
}

/// The type of a protocol message's field, as a CBOR data item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    Uint,
    Int,
    Bool,
    Text,
    Bytes,
    Map,
    /// A map from a primitive's parameter keys to their values.
    Params,
}

/// A field of a protocol message.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub key: u64,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: FieldType,
    #[serde(default)]
    pub optional: bool,
}

/// A protocol message.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub name: String,
    pub kind: u64,
    pub from: Side,
    pub fields: Vec<Field>,
}

/// A result a confirm carries.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultCode {
    pub code: u64,
    pub name: String,
    pub summary: Option<String>,
}

/// A compound stimulus the upper tester runs locally.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Procedure {
    pub code: u64,
    pub name: String,
    pub summary: String,
    pub parameters: Vec<Parameter>,
}

/// The test management protocol.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TmpFile {
    pub format: String,
    pub format_version: u32,
    pub version: u64,
    pub encoding: String,
    pub stream_length_prefix: String,
    #[serde(rename = "message")]
    pub messages: Vec<Message>,
    #[serde(rename = "result")]
    pub results: Vec<ResultCode>,
    #[serde(rename = "procedure", default)]
    pub procedures: Vec<Procedure>,
}

/// The configurations, the purposes, the primitives and the protocol.
#[derive(Debug, Clone)]
pub struct Structure {
    pub configurations: ConfigurationFile,
    pub purposes: Vec<(String, PurposeFile)>,
    pub asp: AspFile,
    pub tmp: TmpFile,
}

impl Structure {
    /// Reads the structure from the texts of its files; a text not of its format's shape is
    /// refused with the file's name.
    pub fn parse(
        configurations: &str,
        purpose_files: &[(&str, &str)],
        asp: &str,
        tmp: &str,
    ) -> Result<Structure, String> {
        let mut purposes = Vec::new();
        for (name, text) in purpose_files {
            let file: PurposeFile = toml::from_str(text).map_err(|e| format!("{name}: {e}"))?;
            purposes.push(((*name).to_string(), file));
        }
        Ok(Structure {
            configurations: toml::from_str(configurations)
                .map_err(|e| format!("configurations.toml: {e}"))?,
            purposes,
            asp: toml::from_str(asp).map_err(|e| format!("asp.toml: {e}"))?,
            tmp: toml::from_str(tmp).map_err(|e| format!("tmp.toml: {e}"))?,
        })
    }

    /// The structure as committed in `conformance/suite/`.
    pub fn committed() -> Result<Structure, String> {
        Structure::parse(CONFIGURATIONS, PURPOSE_FILES, ASP, TMP)
    }

    /// Every purpose of every file, in file order.
    pub fn all_purposes(&self) -> impl Iterator<Item = &Purpose> {
        self.purposes.iter().flat_map(|(_, f)| f.purposes.iter())
    }
}

fn format_check(out: &mut Vec<String>, at: &str, format: &str, version: u32, want: &str) {
    if format != want || version != FORMAT_VERSION {
        out.push(format!(
            "{at}: format {format} version {version}, not {want} version {FORMAT_VERSION}"
        ));
    }
}

fn id_check<'a>(out: &mut Vec<String>, at: &str, id: &'a str, seen: &mut BTreeSet<&'a str>) {
    if !is_item_id(id) {
        out.push(format!(
            "{at}: the id is not upper-case words joined by single hyphens, the first not PICS"
        ));
    }
    if !seen.insert(id) {
        out.push(format!("{at}: the id is stated twice"));
    }
}

fn selection_check(out: &mut Vec<String>, at: &str, text: &str, suite: &Suite) {
    match Selection::parse(text) {
        Err(e) => out.push(format!("{at}: selection {text:?} does not parse: {e}")),
        Ok(selection) => {
            for id in selection.items() {
                match suite.pics_item(id) {
                    None => out.push(format!("{at}: selection names {id}, which is no PICS item")),
                    Some(item) if item.answer != AnswerKind::Support => out.push(format!(
                        "{at}: selection names {id}, which is answered with a value"
                    )),
                    Some(_) => {}
                }
            }
        }
    }
}

fn nonempty(out: &mut Vec<String>, at: &str, field: &str, text: &str) {
    if text.trim().is_empty() {
        out.push(format!("{at}: {field} is empty"));
    }
}

fn parameters_check(out: &mut Vec<String>, at: &str, parameters: &[Parameter]) {
    let mut keys = BTreeSet::new();
    let mut names = BTreeSet::new();
    for p in parameters {
        if p.key == 0 {
            out.push(format!("{at}: parameter {} has key 0", p.name));
        }
        if !keys.insert(p.key) {
            out.push(format!("{at}: parameter key {} is used twice", p.key));
        }
        if !names.insert(p.name.as_str()) {
            out.push(format!("{at}: parameter {} is named twice", p.name));
        }
        match (p.kind == ParameterType::Enum, p.values.is_empty()) {
            (true, true) => out.push(format!("{at}: enum parameter {} has no values", p.name)),
            (false, false) => out.push(format!(
                "{at}: parameter {} has values but is not an enum",
                p.name
            )),
            _ => {}
        }
    }
}

/// Every violation of the structure, against itself and against the requirements and the PICS.
pub fn check_structure(suite: &Suite, structure: &Structure) -> Vec<String> {
    let mut out = Vec::new();
    let configurations = &structure.configurations;
    format_check(
        &mut out,
        "configurations.toml",
        &configurations.format,
        configurations.format_version,
        CONFIGURATIONS_FORMAT,
    );
    let mut seen = BTreeSet::new();
    for c in &configurations.configurations {
        let at = format!("configurations.toml: {}", c.id);
        id_check(&mut out, &at, &c.id, &mut seen);
        nonempty(&mut out, &at, "summary", &c.summary);
        if let Some(selection) = &c.selection {
            selection_check(&mut out, &at, selection, suite);
        }
        if c.lower.is_empty() {
            out.push(format!("{at}: has no lower tester component"));
        }
        let mut names = BTreeSet::new();
        for lt in &c.lower {
            if !names.insert(lt.name.as_str()) {
                out.push(format!("{at}: component {} is named twice", lt.name));
            }
            if (lt.link == LinkKind::Multicast) != (lt.end == End::Group) {
                out.push(format!(
                    "{at}: component {} is on a multicast link exactly when it is a group member",
                    lt.name
                ));
            }
        }
    }
    let configuration_ids: BTreeSet<&str> = configurations
        .configurations
        .iter()
        .map(|c| c.id.as_str())
        .collect();

    let asp = &structure.asp;
    format_check(
        &mut out,
        "asp.toml",
        &asp.format,
        asp.format_version,
        ASP_FORMAT,
    );
    let mut seen = BTreeSet::new();
    let mut codes = BTreeSet::new();
    for p in &asp.primitives {
        let at = format!("asp.toml: {}", p.id);
        id_check(&mut out, &at, &p.id, &mut seen);
        nonempty(&mut out, &at, "summary", &p.summary);
        if p.code == 0 || !codes.insert(p.code) {
            out.push(format!("{at}: code {} is zero or used twice", p.code));
        }
        if let Some(selection) = &p.selection {
            selection_check(&mut out, &at, selection, suite);
        }
        parameters_check(&mut out, &at, &p.parameters);
    }
    let primitive_ids: BTreeSet<&str> = asp.primitives.iter().map(|p| p.id.as_str()).collect();

    let requirement_ids: BTreeSet<&str> = suite.all_requirements().map(|r| r.id.as_str()).collect();
    let mut seen = BTreeSet::new();
    for (name, file) in &structure.purposes {
        format_check(
            &mut out,
            name,
            &file.format,
            file.format_version,
            PURPOSES_FORMAT,
        );
        for tp in &file.purposes {
            let at = format!("{name}: {}", tp.id);
            id_check(&mut out, &at, &tp.id, &mut seen);
            if tp.requirements.is_empty() {
                out.push(format!("{at}: names no requirement"));
            }
            for id in &tp.requirements {
                if !requirement_ids.contains(id.as_str()) {
                    out.push(format!("{at}: names {id}, which is no requirement"));
                }
            }
            if !configuration_ids.contains(tp.configuration.as_str()) {
                out.push(format!(
                    "{at}: runs in {}, which is no configuration",
                    tp.configuration
                ));
            }
            if let Some(selection) = &tp.selection {
                selection_check(&mut out, &at, selection, suite);
            }
            for id in &tp.primitives {
                if !primitive_ids.contains(id.as_str()) {
                    out.push(format!("{at}: uses {id}, which is no primitive"));
                }
            }
            nonempty(&mut out, &at, "with", &tp.with);
            nonempty(&mut out, &at, "when", &tp.when);
            nonempty(&mut out, &at, "then", &tp.then);
        }
    }

    let tmp = &structure.tmp;
    format_check(
        &mut out,
        "tmp.toml",
        &tmp.format,
        tmp.format_version,
        TMP_FORMAT,
    );
    if tmp.encoding != "cbor" {
        out.push(format!("tmp.toml: encoding is {}, not cbor", tmp.encoding));
    }
    if tmp.stream_length_prefix != "u32-be" {
        out.push(format!(
            "tmp.toml: stream_length_prefix is {}, not u32-be",
            tmp.stream_length_prefix
        ));
    }
    let mut names = BTreeSet::new();
    let mut kinds = BTreeSet::new();
    for m in &tmp.messages {
        let at = format!("tmp.toml: message {}", m.name);
        if !names.insert(m.name.as_str()) {
            out.push(format!("{at}: is named twice"));
        }
        if m.kind == 0 || !kinds.insert(m.kind) {
            out.push(format!("{at}: kind {} is zero or used twice", m.kind));
        }
        let mut keys = BTreeSet::new();
        for f in &m.fields {
            if f.key == 0 || !keys.insert(f.key) {
                out.push(format!(
                    "{at}: field {} has key {}, zero (the kind's) or used twice",
                    f.name, f.key
                ));
            }
        }
    }
    for wanted in RULE_MESSAGES {
        if !names.contains(wanted) {
            out.push(format!(
                "tmp.toml: has no message {wanted}, which its rules name"
            ));
        }
    }
    let mut result_codes = BTreeSet::new();
    for r in &tmp.results {
        if !result_codes.insert(r.code) {
            out.push(format!("tmp.toml: result code {} is used twice", r.code));
        }
    }
    if !tmp.results.iter().any(|r| r.code == 0 && r.name == "ok") {
        out.push("tmp.toml: result 0 is not ok".to_string());
    }
    let mut procedure_codes = BTreeSet::new();
    for p in &tmp.procedures {
        let at = format!("tmp.toml: procedure {}", p.name);
        if p.code == 0 || !procedure_codes.insert(p.code) {
            out.push(format!("{at}: code {} is zero or used twice", p.code));
        }
        nonempty(&mut out, &at, "summary", &p.summary);
        parameters_check(&mut out, &at, &p.parameters);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edit(base: &str, from: &str, to: &str) -> String {
        assert!(base.contains(from), "the file holds no {from:?}");
        base.replacen(from, to, 1)
    }

    fn violations(configurations: &str, purposes: &str, asp: &str, tmp: &str) -> Vec<String> {
        let suite = Suite::committed().unwrap();
        let structure = Structure::parse(
            configurations,
            &[("purposes/transport.toml", purposes)],
            asp,
            tmp,
        )
        .expect("the edited files read");
        check_structure(&suite, &structure)
    }

    fn transport() -> &'static str {
        PURPOSE_FILES[0].1
    }

    fn refused(found: &[String], needle: &str) {
        assert!(
            found.iter().any(|v| v.contains(needle)),
            "no violation says {needle:?}: {found:?}"
        );
    }

    #[test]
    fn the_committed_structure_holds() {
        let suite = Suite::committed().unwrap();
        let structure = Structure::committed().unwrap();
        let found = check_structure(&suite, &structure);
        assert!(found.is_empty(), "{found:#?}");
        assert!(structure.all_purposes().next().is_some());
    }

    #[test]
    fn a_purpose_names_what_exists() {
        let p = edit(
            transport(),
            "requirements = [\"B-INIT-5\"",
            "requirements = [\"B-NONE-1\"",
        );
        refused(
            &violations(CONFIGURATIONS, &p, ASP, TMP),
            "names B-NONE-1, which is no requirement",
        );

        let p = edit(
            transport(),
            "configuration = \"CF-UC-IUT-DIALS\"",
            "configuration = \"CF-NONE\"",
        );
        refused(
            &violations(CONFIGURATIONS, &p, ASP, TMP),
            "runs in CF-NONE, which is no configuration",
        );

        let p = edit(
            transport(),
            "primitives = [\"SESSION-OPEN\"]",
            "primitives = [\"SESSION-JUMP\"]",
        );
        refused(
            &violations(CONFIGURATIONS, &p, ASP, TMP),
            "uses SESSION-JUMP, which is no primitive",
        );

        let p = edit(transport(), "id = \"TP-INIT-2\"", "id = \"TP-INIT-1\"");
        refused(
            &violations(CONFIGURATIONS, &p, ASP, TMP),
            "TP-INIT-1: the id is stated twice",
        );
    }

    #[test]
    fn a_selection_names_support_items() {
        let c = edit(
            CONFIGURATIONS,
            "selection = \"T-MCAST\"",
            "selection = \"T-LEASE\"",
        );
        refused(
            &violations(&c, transport(), ASP, TMP),
            "selection names T-LEASE, which is answered with a value",
        );

        let a = edit(ASP, "selection = \"N-QUERYABLE\"", "selection = \"N-NONE\"");
        refused(
            &violations(CONFIGURATIONS, transport(), &a, TMP),
            "selection names N-NONE, which is no PICS item",
        );
    }

    #[test]
    fn a_configuration_is_consistent() {
        let c = edit(
            CONFIGURATIONS,
            "link = \"multicast\", end = \"group\"",
            "link = \"stream\", end = \"group\"",
        );
        refused(
            &violations(&c, transport(), ASP, TMP),
            "on a multicast link exactly when it is a group member",
        );

        let c = edit(CONFIGURATIONS, "name = \"lt2\"", "name = \"lt1\"");
        refused(
            &violations(&c, transport(), ASP, TMP),
            "component lt1 is named twice",
        );
    }

    #[test]
    fn a_primitive_has_one_code_and_one_key_per_parameter() {
        let a = edit(ASP, "code = 2\n", "code = 1\n");
        refused(
            &violations(CONFIGURATIONS, transport(), &a, TMP),
            "code 1 is zero or used twice",
        );

        let a = edit(
            ASP,
            "{ key = 3, name = \"listen\"",
            "{ key = 2, name = \"listen\"",
        );
        refused(
            &violations(CONFIGURATIONS, transport(), &a, TMP),
            "parameter key 2 is used twice",
        );

        let a = edit(
            ASP,
            "type = \"enum\", values = [\"client\", \"peer\", \"router\"]",
            "type = \"enum\"",
        );
        refused(
            &violations(CONFIGURATIONS, transport(), &a, TMP),
            "enum parameter mode has no values",
        );

        let a = edit(
            ASP,
            "{ key = 2, name = \"connect\", type = \"text\"",
            "{ key = 2, name = \"connect\", type = \"text\", values = [\"x\"]",
        );
        refused(
            &violations(CONFIGURATIONS, transport(), &a, TMP),
            "has values but is not an enum",
        );
    }

    #[test]
    fn the_protocol_is_cbor_with_the_messages_its_rules_name() {
        let t = edit(TMP, "encoding = \"cbor\"", "encoding = \"json\"");
        refused(
            &violations(CONFIGURATIONS, transport(), ASP, &t),
            "encoding is json, not cbor",
        );

        let t = edit(TMP, "name = \"reset\"", "name = \"restart\"");
        refused(
            &violations(CONFIGURATIONS, transport(), ASP, &t),
            "has no message reset",
        );

        let t = edit(TMP, "kind = 2\n", "kind = 1\n");
        refused(
            &violations(CONFIGURATIONS, transport(), ASP, &t),
            "kind 1 is zero or used twice",
        );

        let t = edit(
            TMP,
            "{ key = 2, name = \"suite\"",
            "{ key = 0, name = \"suite\"",
        );
        refused(
            &violations(CONFIGURATIONS, transport(), ASP, &t),
            "zero (the kind's) or used twice",
        );

        let t = edit(TMP, "code = 0\nname = \"ok\"", "code = 0\nname = \"fine\"");
        refused(
            &violations(CONFIGURATIONS, transport(), ASP, &t),
            "result 0 is not ok",
        );
    }

    #[test]
    fn an_unknown_field_does_not_read() {
        let t = edit(TMP, "encoding = \"cbor\"", "encodng = \"cbor\"");
        let err = Structure::parse(CONFIGURATIONS, PURPOSE_FILES, ASP, &t).unwrap_err();
        assert!(err.starts_with("tmp.toml:"), "{err}");
    }
}
