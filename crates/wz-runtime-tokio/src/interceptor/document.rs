// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The config document's interceptor keys, compiled into the rules that enforce them.
//!
//! `low_pass_filter` and `downsampling` are read into feature-independent echo types
//! ([`crate::zenoh_config::LowPassFilterConf`], [`crate::zenoh_config::DownsamplingItemConf`])
//! because the reader must read one document to one set of values in every build. The
//! enforcement types ([`crate::interceptor::low_pass::LowPassRule`],
//! [`crate::interceptor::downsampling::DownsamplingRule`])
//! live behind features. This module is the one place the document's spelling becomes the
//! enforcement type, so the two consumers of it cannot compile the same key two ways:
//!
//!   * `WzConfig::apply_one_key`, which compiles a key at a time for the router and the admin
//!     write plane, and
//!   * [`InterceptorConfig::from_node_config`], which compiles a node's whole document for a
//!     session that is not a router (the C ABI).
//!
//! The compile is a pure function of the document. `None` from a rule compiler means the reader
//! and this compiler disagree about a literal the reader had already validated; callers treat it
//! as the assertion it is and refuse, rather than unwrapping in a running node.

use super::{InterceptorConfig, InterceptorFlow};
use crate::zenoh_config::ZenohNodeConfig;

/// The flows a `downsampling` or `low_pass_filter` item governs: the ones it names, or BOTH when
/// it names none.
///
/// The reader keeps an omitted `flows` as an empty list (upstream's `None`), and upstream reads
/// `None` as ingress and egress (`low_pass.rs` `get_or_insert`, `downsampling.rs` `unwrap_or`). A
/// rule compiled with the empty list governs no flow, and `for_flow` then installs nothing, so a
/// document that left `flows` out (the usual form) was honoured by the reader and did nothing at
/// all.
#[cfg(any(feature = "access-quota", feature = "access-downsampling"))]
pub(crate) fn flows_or_both(flows: Vec<InterceptorFlow>) -> Vec<InterceptorFlow> {
    if flows.is_empty() {
        InterceptorFlow::ALL.to_vec()
    } else {
        flows
    }
}

/// `low_pass_filter` items as enforcement rules, or `None` when a literal the reader validated
/// is not one this compiler knows.
#[cfg(feature = "access-quota")]
pub(crate) fn low_pass_rules(
    confs: &[crate::zenoh_config::LowPassFilterConf],
) -> Option<Vec<super::low_pass::LowPassRule>> {
    let mut rules = Vec::with_capacity(confs.len());
    for conf in confs {
        let messages = conf
            .messages
            .iter()
            .map(|m| super::low_pass::LowPassMessage::from_upstream_str(m))
            .collect::<Option<Vec<_>>>()?;
        let flows = conf
            .flows
            .iter()
            .map(|f| InterceptorFlow::from_upstream_str(f))
            .collect::<Option<Vec<_>>>()?;
        let links = conf
            .link_protocols
            .iter()
            .map(|l| wz_session_core::link::InterceptorLink::from_upstream_str(l))
            .collect::<Option<Vec<_>>>()?;
        rules.push(super::low_pass::LowPassRule {
            key_exprs: conf.key_exprs.clone(),
            max_payload_size: conf.size_limit as usize,
            messages,
            flows: flows_or_both(flows),
            link_protocols: links,
            interfaces: conf.interfaces.clone(),
        });
    }
    Some(rules)
}

/// `downsampling` items as enforcement rules. One item carries N rate rules and the axes they
/// share; each becomes one wz rule with those axes copied onto it, which is upstream's own shape
/// (the subject and kind selectors sit on the item and only the rate varies per rule).
#[cfg(feature = "access-downsampling")]
pub(crate) fn downsampling_rules(
    items: &[crate::zenoh_config::DownsamplingItemConf],
) -> Option<Vec<super::downsampling::DownsamplingRule>> {
    let mut rules = Vec::new();
    for item in items {
        let messages = item
            .messages
            .iter()
            .map(|m| super::downsampling::DownsamplingMessage::from_upstream_str(m))
            .collect::<Option<Vec<_>>>()?;
        let flows = item
            .flows
            .iter()
            .map(|f| InterceptorFlow::from_upstream_str(f))
            .collect::<Option<Vec<_>>>()?;
        let links = item
            .link_protocols
            .iter()
            .map(|l| wz_session_core::link::InterceptorLink::from_upstream_str(l))
            .collect::<Option<Vec<_>>>()?;
        for rule in &item.rules {
            rules.push(super::downsampling::DownsamplingRule {
                key_exprs: vec![rule.key_expr.clone()],
                // `0.0` is DROP-ALL and a negative or non-finite rate is no throttle; both live
                // in this one function, so the compiler does not restate either edge.
                min_interval: super::downsampling::interval_from_freq(rule.freq),
                messages: messages.clone(),
                flows: flows_or_both(flows.clone()),
                link_protocols: links.clone(),
                interfaces: item.interfaces.clone(),
            });
        }
    }
    Some(rules)
}

/// Why a node's document could not become an interceptor config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptorCompileError {
    /// The `access_control` subtree is one upstream refuses to start on (a policy naming a rule
    /// or subject that does not exist, a blank username, and so on).
    #[cfg(feature = "access-acl")]
    AccessControl(crate::zenoh_config::AclCompileError),
    /// `low_pass_filter` held a literal the reader had validated and this compiler does not know:
    /// the two have drifted.
    #[cfg(feature = "access-quota")]
    LowPassFilter,
    /// `downsampling`, likewise.
    #[cfg(feature = "access-downsampling")]
    Downsampling,
}

impl core::fmt::Display for InterceptorCompileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            #[cfg(feature = "access-acl")]
            Self::AccessControl(e) => write!(f, "access_control cannot be compiled: {e:?}"),
            #[cfg(feature = "access-quota")]
            Self::LowPassFilter => f.write_str("low_pass_filter holds a literal wz does not know"),
            #[cfg(feature = "access-downsampling")]
            Self::Downsampling => f.write_str("downsampling holds a literal wz does not know"),
        }
    }
}

impl std::error::Error for InterceptorCompileError {}

impl InterceptorConfig {
    /// The interceptors a node's whole document asks for, or an error naming the key that could
    /// not be compiled. An empty config (no key stated, or `access_control` disabled) is the
    /// answer for a node that wants none: [`InterceptorConfig::is_inert`] says so.
    pub fn from_node_config(node: &ZenohNodeConfig) -> Result<Self, InterceptorCompileError> {
        let mut config = Self::default();
        let _ = &node;
        #[cfg(feature = "access-acl")]
        {
            config.acl = crate::zenoh_config::acl_config_from_inputs(&node.access_control)
                .map_err(InterceptorCompileError::AccessControl)?
                .map(wz_access_control::AclPolicy::new);
        }
        #[cfg(feature = "access-downsampling")]
        {
            config.downsampling = downsampling_rules(&node.downsampling)
                .ok_or(InterceptorCompileError::Downsampling)?;
        }
        #[cfg(feature = "access-quota")]
        {
            config.low_pass = low_pass_rules(&node.low_pass_filter)
                .ok_or(InterceptorCompileError::LowPassFilter)?;
        }
        Ok(config)
    }

    /// Whether this config asks for no interception at all, so a caller can keep every fast path
    /// it has for a node that wants none.
    pub fn is_inert(&self) -> bool {
        #[allow(unused_mut)]
        let mut inert = true;
        #[cfg(feature = "access-acl")]
        {
            inert &= self.acl.is_none();
        }
        #[cfg(feature = "access-downsampling")]
        {
            inert &= self.downsampling.is_empty();
        }
        #[cfg(feature = "access-quota")]
        {
            inert &= self.low_pass.is_empty();
        }
        inert
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(document: &str) -> ZenohNodeConfig {
        ZenohNodeConfig::from_json5(document)
            .expect("a document a real zenohd starts on")
            .config
    }

    #[test]
    fn a_document_that_states_no_interceptor_is_inert() {
        let config = InterceptorConfig::from_node_config(&node(r#"{ mode: "peer" }"#)).unwrap();
        assert!(config.is_inert());
    }

    #[cfg(feature = "access-quota")]
    #[test]
    fn a_low_pass_filter_compiles_to_a_rule_with_its_size_limit() {
        let config = InterceptorConfig::from_node_config(&node(
            r#"{ low_pass_filter: [ { messages: ["put"], key_exprs: ["demo/**"],
                                      size_limit: 8192 } ] }"#,
        ))
        .unwrap();
        assert!(!config.is_inert());
        assert_eq!(config.low_pass.len(), 1);
        assert_eq!(config.low_pass[0].max_payload_size, 8192);
        assert_eq!(config.low_pass[0].key_exprs, vec!["demo/**".to_owned()]);
        assert_eq!(config.low_pass[0].flows, InterceptorFlow::ALL.to_vec());
    }

    #[cfg(feature = "access-downsampling")]
    #[test]
    fn a_downsampling_item_expands_to_one_rule_per_rate() {
        let config = InterceptorConfig::from_node_config(&node(
            r#"{ downsampling: [ { messages: ["put"],
                                   rules: [ { key_expr: "a/**", freq: 1.0 },
                                            { key_expr: "b/**", freq: 2.0 } ] } ] }"#,
        ))
        .unwrap();
        assert_eq!(config.downsampling.len(), 2);
        assert_eq!(config.downsampling[0].key_exprs, vec!["a/**".to_owned()]);
        assert_eq!(config.downsampling[1].key_exprs, vec!["b/**".to_owned()]);
    }

    #[cfg(feature = "access-acl")]
    #[test]
    fn access_control_stated_as_disabled_compiles_to_no_policy() {
        let config = InterceptorConfig::from_node_config(&node(
            r#"{ access_control: { enabled: false, default_permission: "deny" } }"#,
        ))
        .unwrap();
        assert!(
            config.is_inert(),
            "a disabled ACL installs nothing, whatever its default"
        );
    }
}
