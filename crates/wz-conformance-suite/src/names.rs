// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! How a proforma id is spelled where the abstract test suite reads it.
//!
//! The SCE test profile takes a PICS support item as a feature of the suite's feature model, and
//! its TTCN-3 export writes each feature as the module parameter `PICS_<NAME>`: the feature's name
//! upper-cased with each hyphen an underscore. A feature's name is lower-case words joined by
//! hyphens. A PICS value item and a PIXIT item are module parameters of the suite, whose ids are
//! TTCN-3 identifiers: an ASCII letter, then letters, digits and underscores.
//!
//! A proforma id is upper-case words joined by hyphens, so each of the three spellings is one
//! rule, and none loses anything: lower-casing a support item gives its feature, and writing each
//! hyphen as an underscore gives a module parameter. Being upper-case, no spelling is a TTCN-3
//! keyword or a predefined function's name, all of which are lower-case.
//!
//! The one way two ids could still be spelled alike is through the prefix the export puts on a
//! feature: a value or PIXIT item `PICS-T-X` would be the module parameter `PICS_T_X`, which is
//! also the parameter of the feature of a support item `T-X`. So no id starts with the word
//! `PICS` ([`is_proforma_id`]); the word elsewhere in an id is spelled nowhere else and is
//! allowed. The export refuses a written name that collides with a name it makes, too, but the
//! id is where the collision starts, so it is refused there first.

/// The word the export puts in front of a feature's module parameter.
const FEATURE_PREFIX: &str = "PICS";

/// Whether `id` is a proforma id: upper-case letters and digits in words joined by single
/// hyphens, the first word starting with a letter and not `PICS`.
pub fn is_proforma_id(id: &str) -> bool {
    is_feature_name(&id.to_ascii_lowercase())
        && !id.chars().any(|c| c.is_ascii_lowercase())
        && id.split('-').next() != Some(FEATURE_PREFIX)
}

/// The feature a PICS support item is in the suite's feature model.
pub fn feature_name(id: &str) -> String {
    id.to_ascii_lowercase()
}

/// The module parameter the TTCN-3 export writes for a PICS support item's feature.
pub fn feature_parameter(id: &str) -> String {
    format!("PICS_{}", id.replace('-', "_"))
}

/// The module parameter a PICS value item or a PIXIT item is in the suite.
pub fn module_parameter(id: &str) -> String {
    id.replace('-', "_")
}

/// Whether `name` is a feature name: lower-case letters and digits in words joined by hyphens,
/// the first word starting with a letter.
pub fn is_feature_name(name: &str) -> bool {
    let mut words = name.split('-');
    let first_ok = words.next().is_some_and(|w| {
        w.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            && w.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    });
    first_ok
        && words.all(|w| {
            !w.is_empty()
                && w.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
}

/// Whether `name` is a TTCN-3 identifier: an ASCII letter, then ASCII letters, digits and
/// underscores.
pub fn is_ttcn3_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{AnswerKind, Suite};

    #[test]
    fn the_spellings_follow_the_profile() {
        assert_eq!(feature_name("T-UNICAST"), "t-unicast");
        assert_eq!(feature_parameter("T-UNICAST"), "PICS_T_UNICAST");
        assert_eq!(module_parameter("T-FSN-RES"), "T_FSN_RES");
        assert_eq!(module_parameter("X-TMP-CHANNEL"), "X_TMP_CHANNEL");
    }

    #[test]
    fn an_id_does_not_start_with_the_feature_prefix() {
        // The collision the rule prevents: the value item would be spelled as the feature is.
        assert_eq!(
            module_parameter("PICS-T-UNICAST"),
            feature_parameter("T-UNICAST")
        );
        assert!(!is_proforma_id("PICS-T-UNICAST"));
        assert!(!is_proforma_id("PICS"));
        // Elsewhere in an id the word is spelled nowhere else.
        assert!(is_proforma_id("T-PICS"));
        assert!(is_proforma_id("T-PICS-X"));
        assert!(is_proforma_id("PICSX-T"));
        assert!(!is_proforma_id("t-unicast"));
        assert!(!is_proforma_id("T--UNICAST"));
    }

    #[test]
    fn the_name_grammars_refuse_what_they_must() {
        assert!(is_feature_name("t-unicast"));
        assert!(is_feature_name("n2-query"));
        assert!(!is_feature_name("T-UNICAST"));
        assert!(!is_feature_name("t--unicast"));
        assert!(!is_feature_name("t-"));
        assert!(!is_feature_name("2-t"));
        assert!(!is_feature_name(""));
        assert!(is_ttcn3_identifier("T_FSN_RES"));
        assert!(!is_ttcn3_identifier("T-FSN-RES"));
        assert!(!is_ttcn3_identifier("_T"));
        assert!(!is_ttcn3_identifier(""));
    }

    #[test]
    fn every_committed_id_is_spelled_by_the_existing_names() {
        let suite = Suite::committed().unwrap();
        let mut made = BTreeSet::new();
        for item in &suite.pics.items {
            let name = match item.answer {
                AnswerKind::Support => {
                    let feature = feature_name(&item.id);
                    assert!(is_feature_name(&feature), "{} as {feature}", item.id);
                    assert_eq!(feature.to_ascii_uppercase(), item.id, "lossless");
                    feature_parameter(&item.id)
                }
                AnswerKind::Value => module_parameter(&item.id),
            };
            assert!(is_ttcn3_identifier(&name), "{} as {name}", item.id);
            assert!(made.insert(name.clone()), "{name} is made twice");
        }
        for item in &suite.pixit.items {
            let name = module_parameter(&item.id);
            assert!(is_ttcn3_identifier(&name), "{} as {name}", item.id);
            assert!(made.insert(name.clone()), "{name} is made twice");
        }
    }
}
