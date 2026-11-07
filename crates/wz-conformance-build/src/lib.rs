// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The conformance digest of the build a build script runs in (docs/build-configuration.md,
//! decision C15).
//!
//! # What it is
//!
//! `wz_config.py` prints a build's conformance statement: every capability its ABI exports with
//! whether the build has it, every limit and policy with its value, and a digest of those values
//! alone (`statement_digest`). A tester handed the statement must be able to ask the library it
//! talks to whether it is that build. [`emit`] answers the statement's questions for the build it
//! runs in and writes the digest where the library includes it, and the library hands it out
//! through its C ABI.
//!
//! # Where the answers come from
//!
//! From the three sources the code itself is compiled from, so the digest describes what was
//! compiled and not what someone meant to build:
//!
//! - a capability is supported when the package's cargo feature of that id is on
//!   (`CARGO_FEATURE_<ID>`, which cargo sets from the same resolution as `cfg(feature)`);
//! - a limit is the decimal `WZ_LIMIT_<NAME>` the build's environment states, else its default,
//!   read by the rule `wz-session-core`'s `limit` reads it with;
//! - a policy is the `WZ_POLICY_<NAME>` value the environment states, else upstream's, read by
//!   the rule of `policy_choice` and `policy_bool`.
//!
//! A value the code would refuse to compile with is refused here too, in the same words, so a
//! digest never describes a build that cannot exist. The questions, their order and their
//! defaults are the declaration's, generated into `items_generated.rs` by
//! `wz_config.py --emit rust-conformance-items` and held to it by `--check`.
//!
//! # The digest
//!
//! SHA-256 over the canonical JSON `wz_config.py` hashes: the object with the keys `abi`, `arm`
//! (`[switch, on]` pairs: the layout switches that are not capabilities, which select the arm
//! of the C types a program allocates), `capabilities` (`[id, supported]` pairs),
//! `catalog_version`, `format`, `format_version`,
//! `limits` (`[id, value]`) and `policies` (`[id, value]`), keys sorted, no whitespace. Every word
//! in it is a declaration word (`wz_config.rust_word`), so no escaping arises; one that would
//! need it is refused rather than escaped differently from the other side. The fixture test below
//! and the selftest arm of `wz_config.py` assert the same digest of the same fixture, so the two
//! writers of this form cannot drift apart unseen.
//!
//! The fixture holds the form; `statement_vectors.json` holds the reading. It lists builds over the
//! declaration's whole domain: each capability and layout switch alone, each limit off its
//! default, each policy value, and seeded random mixes. Each comes with the digest `wz_config.py`
//! states for it (`--emit statement-vectors`, held by `--check`). The test reproduces each through
//! [`of_build`], from the same features and environment a build script would see.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

#[path = "items_generated.rs"]
mod items;

/// What a statement states of one build: the words and numbers its digest is taken over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement<'a> {
    /// The statement's `format`.
    pub format: &'a str,
    /// The statement's `format_version`.
    pub format_version: u32,
    /// The declaration's `catalog_version`.
    pub catalog_version: u32,
    /// The ABI the build is of: `core`, `pico` or `c`.
    pub abi: &'a str,
    /// Every layout switch of the ABI that is not a capability, in declared order, on or off.
    pub arm: Vec<(&'a str, bool)>,
    /// Every capability the ABI exports, in declared order, with whether the build has it.
    pub capabilities: Vec<(&'a str, bool)>,
    /// Every limit, in declared order, with its value.
    pub limits: Vec<(&'a str, u64)>,
    /// Every policy, in declared order, with its value.
    pub policies: Vec<(&'a str, String)>,
}

impl Statement<'_> {
    /// The canonical JSON the digest is taken over.
    pub fn canonical_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\"abi\":");
        push_word(&mut out, self.abi);
        out.push_str(",\"arm\":");
        push_flags(&mut out, &self.arm);
        out.push_str(",\"capabilities\":");
        push_flags(&mut out, &self.capabilities);
        let _ = write!(out, ",\"catalog_version\":{}", self.catalog_version);
        out.push_str(",\"format\":");
        push_word(&mut out, self.format);
        let _ = write!(out, ",\"format_version\":{}", self.format_version);
        out.push_str(",\"limits\":[");
        for (i, (id, value)) in self.limits.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('[');
            push_word(&mut out, id);
            let _ = write!(out, ",{value}]");
        }
        out.push_str("],\"policies\":[");
        for (i, (id, value)) in self.policies.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('[');
            push_word(&mut out, id);
            out.push(',');
            push_word(&mut out, value);
            out.push(']');
        }
        out.push_str("]}");
        out
    }

    /// `sha256:` and the lowercase hex SHA-256 of [`Statement::canonical_json`].
    pub fn digest(&self) -> String {
        let hash = Sha256::digest(self.canonical_json().as_bytes());
        let mut out = String::from("sha256:");
        for byte in hash {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

/// A JSON array of `[word, bool]` pairs.
fn push_flags(out: &mut String, flags: &[(&str, bool)]) {
    out.push('[');
    for (i, (id, on)) in flags.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('[');
        push_word(out, id);
        out.push_str(if *on { ",true]" } else { ",false]" });
    }
    out.push(']');
}

/// A JSON string of a declaration word. A word outside the declaration's alphabet is refused:
/// the other writer of this form does not escape either.
fn push_word(out: &mut String, word: &str) {
    assert!(
        !word.is_empty()
            && word
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-')),
        "{word:?} is not a declaration word"
    );
    out.push('"');
    out.push_str(word);
    out.push('"');
}

/// A limit's value as `wz-session-core` reads `WZ_LIMIT_<NAME>`: decimal digits only.
fn limit_value(env_name: &str, stated: Option<&str>, default: u64) -> u64 {
    let Some(text) = stated else {
        return default;
    };
    assert!(!text.is_empty(), "a WZ_LIMIT_* value is empty ({env_name})");
    let mut value = 0u64;
    for digit in text.bytes() {
        assert!(
            digit.is_ascii_digit(),
            "a WZ_LIMIT_* value is not a decimal number ({env_name}={text})"
        );
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(digit - b'0')))
            .unwrap_or_else(|| panic!("a WZ_LIMIT_* value is out of range ({env_name}={text})"));
    }
    value
}

/// A policy's value as `wz-session-core` reads `WZ_POLICY_<NAME>`: one of its values, exactly.
fn policy_value(env_name: &str, stated: Option<&str>, values: &[&str], upstream: &str) -> String {
    let Some(text) = stated else {
        return upstream.to_owned();
    };
    assert!(
        values.contains(&text),
        "a WZ_POLICY_* value is not one of its policy's choices ({env_name}={text}; {values:?})"
    );
    text.to_owned()
}

/// The statement of a build of `abi`: `has_feature` says whether the package's cargo feature of
/// a capability id or layout switch is on, and `stated` gives the build environment's value of a
/// name, if any.
///
/// # Panics
///
/// On an ABI the declaration does not name, and on a limit or policy value the code would refuse
/// to compile with.
pub fn of_build(
    abi: &'static str,
    has_feature: impl Fn(&str) -> bool,
    stated: impl Fn(&str) -> Option<String>,
) -> Statement<'static> {
    assert!(
        items::CAPABILITIES
            .iter()
            .any(|(_, abis)| abis.contains(&abi)),
        "{abi:?} is not an ABI of the declaration"
    );
    Statement {
        format: items::FORMAT,
        format_version: items::FORMAT_VERSION,
        catalog_version: items::CATALOG_VERSION,
        abi,
        arm: items::ARM
            .iter()
            .filter(|(_, abis)| abis.contains(&abi))
            .map(|(id, _)| (*id, has_feature(id)))
            .collect(),
        capabilities: items::CAPABILITIES
            .iter()
            .filter(|(_, abis)| abis.contains(&abi))
            .map(|(id, _)| (*id, has_feature(id)))
            .collect(),
        limits: items::LIMITS
            .iter()
            .map(|(id, env_name, default)| {
                (
                    *id,
                    limit_value(env_name, stated(env_name).as_deref(), *default),
                )
            })
            .collect(),
        policies: items::POLICIES
            .iter()
            .map(|(id, env_name, values, upstream)| {
                (
                    *id,
                    policy_value(env_name, stated(env_name).as_deref(), values, upstream),
                )
            })
            .collect(),
    }
}

/// The environment name cargo gives a build script for a feature of its package.
fn feature_env(id: &str) -> String {
    format!(
        "CARGO_FEATURE_{}",
        id.to_ascii_uppercase().replace('-', "_")
    )
}

/// For a build script of a C ABI crate of `abi`: write `conformance_digest.rs` into `OUT_DIR`,
/// for the crate to `include!`, and tell cargo to run again when a limit or policy changes.
///
/// The file holds `CONFORMANCE_DIGEST`, the digest as a C string, and two lists for the crate's
/// own tests: the features this script read as on, capabilities and layout switches
/// (`STATED_FEATURES`), and the same names with `cfg!(feature = ...)` as the crate was compiled
/// (`COMPILED_FEATURES`). A test that compares them shows the script read the build the crate is.
///
/// # Panics
///
/// As [`of_build`]; and when `OUT_DIR` is not set or the file cannot be written, which is a
/// build script run outside cargo.
pub fn emit(abi: &'static str) {
    for (_, env_name, _) in items::LIMITS {
        println!("cargo:rerun-if-env-changed={env_name}");
    }
    for (_, env_name, _, _) in items::POLICIES {
        println!("cargo:rerun-if-env-changed={env_name}");
    }
    let statement = of_build(
        abi,
        |id| env::var_os(feature_env(id)).is_some(),
        |name| match env::var(name) {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => panic!("{name} is not UTF-8"),
        },
    );
    let mut text = String::new();
    text.push_str(
        "// Written by wz-conformance-build for this build; see its crate documentation.\n\n",
    );
    text.push_str(
        "/// The conformance digest of this build (docs/build-configuration.md, decision C15).\n",
    );
    let _ = writeln!(
        text,
        "pub const CONFORMANCE_DIGEST: &core::ffi::CStr = c\"{}\";",
        statement.digest()
    );
    let features: Vec<(&str, bool)> = statement
        .arm
        .iter()
        .chain(&statement.capabilities)
        .copied()
        .collect();
    text.push_str("\n#[cfg(test)]\npub(crate) const STATED_FEATURES: &[(&str, bool)] = &[\n");
    for (id, on) in &features {
        let _ = writeln!(text, "    (\"{id}\", {on}),");
    }
    text.push_str("];\n\n#[cfg(test)]\npub(crate) const COMPILED_FEATURES: &[(&str, bool)] = &[\n");
    for (id, _) in &features {
        let _ = writeln!(text, "    (\"{id}\", cfg!(feature = \"{id}\")),");
    }
    text.push_str("];\n");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"))
        .join("conformance_digest.rs");
    fs::write(&out, text).unwrap_or_else(|e| panic!("writing {}: {e}", out.display()));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture `wz_config.py --selftest` digests too ("the build script's digest form ...").
    /// Both sides assert this one value, so a change to either writer of the canonical form fails
    /// on its own side.
    fn fixture() -> Statement<'static> {
        Statement {
            format: "wz-conformance-statement",
            format_version: 1,
            catalog_version: 7,
            abi: "pico",
            arm: vec![("x-arm", true)],
            capabilities: vec![("a-cap", true), ("b-cap", false)],
            limits: vec![("L_ONE", 256), ("L_TWO", 0)],
            policies: vec![("p-one", "on".into()), ("p-two", "os-default".into())],
        }
    }

    #[test]
    fn the_fixture_has_the_canonical_form_and_digest_wz_config_gives_it() {
        assert_eq!(
            fixture().canonical_json(),
            "{\"abi\":\"pico\",\"arm\":[[\"x-arm\",true]],\
             \"capabilities\":[[\"a-cap\",true],[\"b-cap\",false]],\
             \"catalog_version\":7,\"format\":\"wz-conformance-statement\",\"format_version\":1,\
             \"limits\":[[\"L_ONE\",256],[\"L_TWO\",0]],\
             \"policies\":[[\"p-one\",\"on\"],[\"p-two\",\"os-default\"]]}"
        );
        assert_eq!(
            fixture().digest(),
            "sha256:f503a3f077f1fd6a8b6fd97ae6281ba9bb81e628f2680ce70ab248a31fd51387"
        );
    }

    /// Every build `wz_config.py --emit statement-vectors` states has, read the way a build script
    /// reads it, the digest the statement gives it. The test also requires that every name a
    /// vector states is one `of_build` asked for. A name nobody reads would let a vector state
    /// nothing and pass.
    #[test]
    fn every_statement_vector_has_the_digest_wz_config_states_for_it() {
        use std::cell::RefCell;

        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../statement_vectors.json"))
                .expect("statement_vectors.json is JSON");
        let vectors = doc["vectors"].as_array().expect("the file lists vectors");
        assert!(!vectors.is_empty(), "the file lists no vector");
        let mut wrong = Vec::new();
        for v in vectors {
            let case = v["case"].as_str().expect("a vector names its case");
            let abi = ["core", "pico", "c"]
                .into_iter()
                .find(|abi| v["abi"] == *abi)
                .unwrap_or_else(|| panic!("{case}: an ABI the declaration does not name"));
            let features: Vec<&str> = v["features"]
                .as_array()
                .expect("a vector lists its features")
                .iter()
                .map(|f| f.as_str().expect("a feature is a word"))
                .collect();
            let env = v["env"]
                .as_object()
                .expect("a vector states its environment");
            let asked = RefCell::new(Vec::new());
            let statement = of_build(
                abi,
                |id| features.contains(&id),
                |name| {
                    asked.borrow_mut().push(name.to_owned());
                    env.get(name)
                        .map(|value| value.as_str().expect("a value is text").to_owned())
                },
            );
            let unread: Vec<&String> = env
                .keys()
                .filter(|name| !asked.borrow().contains(*name))
                .collect();
            assert!(
                unread.is_empty(),
                "{abi} {case}: the build script reads no {unread:?}"
            );
            let want = v["digest"].as_str().expect("a vector has a digest");
            if statement.digest() != want {
                wrong.push(format!(
                    "{abi} {case}: {} where wz_config.py states {want}; read as {}",
                    statement.digest(),
                    statement.canonical_json()
                ));
            }
        }
        assert!(
            wrong.is_empty(),
            "{} of {} vectors differ:\n{}",
            wrong.len(),
            vectors.len(),
            wrong.join("\n")
        );
    }

    #[test]
    fn the_zenoh_c_abi_states_its_layout_arm_and_the_pico_abi_has_none() {
        let c = of_build("c", |_| false, |_| None);
        assert!(!c.arm.is_empty());
        assert_eq!(c.arm.len(), items::ARM.len());
        let arm_on = of_build("c", |id| c.arm.iter().any(|(a, _)| *a == id), |_| None);
        assert!(arm_on.arm.iter().all(|(_, on)| *on));
        assert_ne!(arm_on.digest(), c.digest());
        assert!(of_build("pico", |_| true, |_| None).arm.is_empty());
    }

    #[test]
    fn a_build_that_states_nothing_has_every_default_and_upstreams_policies() {
        let s = of_build("pico", |_| false, |_| None);
        assert!(s
            .limits
            .iter()
            .zip(items::LIMITS)
            .all(|((_, v), (_, _, d))| v == d));
        assert!(s
            .policies
            .iter()
            .zip(items::POLICIES)
            .all(|((_, v), (_, _, _, upstream))| v == upstream));
        assert!(s.capabilities.iter().all(|(_, on)| !on));
        assert!(s.arm.iter().all(|(_, on)| !on));
    }

    #[test]
    fn a_statement_lists_the_capabilities_of_its_abi_only() {
        for abi in ["core", "pico", "c"] {
            let s = of_build(abi, |_| true, |_| None);
            let want: Vec<&str> = items::CAPABILITIES
                .iter()
                .filter(|(_, abis)| abis.contains(&abi))
                .map(|(id, _)| *id)
                .collect();
            assert_eq!(
                s.capabilities.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
                want
            );
        }
    }

    #[test]
    fn a_stated_limit_and_policy_are_read_and_change_the_digest() {
        let (limit_id, limit_env, default) = items::LIMITS[0];
        let (policy_id, policy_env, values, upstream) = items::POLICIES[0];
        let other = *values
            .iter()
            .find(|v| **v != upstream)
            .expect("a policy has two values");
        let base = of_build("c", |_| false, |_| None);
        let moved = of_build(
            "c",
            |_| false,
            |name| {
                if name == limit_env {
                    Some((default + 1).to_string())
                } else if name == policy_env {
                    Some(other.to_owned())
                } else {
                    None
                }
            },
        );
        assert!(moved.limits.contains(&(limit_id, default + 1)));
        assert!(moved.policies.contains(&(policy_id, other.to_owned())));
        assert_ne!(base.digest(), moved.digest());
    }

    #[test]
    #[should_panic(expected = "not a decimal number")]
    fn a_limit_that_is_not_decimal_is_refused_as_the_code_refuses_it() {
        limit_value("WZ_LIMIT_X", Some("0x10"), 1);
    }

    #[test]
    #[should_panic(expected = "is empty")]
    fn an_empty_limit_is_refused() {
        limit_value("WZ_LIMIT_X", Some(""), 1);
    }

    #[test]
    #[should_panic(expected = "not one of its policy's choices")]
    fn a_policy_value_outside_its_choices_is_refused() {
        policy_value("WZ_POLICY_X", Some("maybe"), &["off", "on"], "off");
    }

    #[test]
    #[should_panic(expected = "not an ABI of the declaration")]
    fn an_abi_the_declaration_does_not_name_is_refused() {
        of_build("rust", |_| false, |_| None);
    }

    #[test]
    fn a_feature_is_read_from_cargos_name_for_it() {
        assert_eq!(
            feature_env("multicast-transport"),
            "CARGO_FEATURE_MULTICAST_TRANSPORT"
        );
    }
}
