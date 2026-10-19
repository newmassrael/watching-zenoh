// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The policy a node's config states for the traffic of its sessions, held by the node and
//! installed on each of its faces before the first frame is read.
//!
//! `access_control`, `low_pass_filter` and `downsampling` are keys a stock zenoh node enforces on
//! what it sends and what it is sent. This crate read them into the node's config and then
//! dropped them at `z_open`: the ACL was refused outright, and the other two were accepted and
//! ignored, which is the worse of the two answers for a rate limit an operator relies on.
//!
//! # Pay for use
//!
//! A node that states no policy is [`NodePolicy::is_inert`], and every fast path this crate has
//! stays exactly as it was. A node that states one turns off, for ITS sessions only, what would
//! step around the policy: the plain-put receive lane (a frame of puts reported as places in the
//! datagram, which no per-message verdict can read) and the plain-put send lane (a frame written
//! without building the message the verdict reads). The general paths take their place.
//!
//! # Why the type exists in every build
//!
//! The same reason [`crate::node_auth::NodeAuth`] does: it is a field of the node's open
//! parameters, which the zenoh-pico ABI fills in too, and a field that existed only under the
//! feature would break that ABI's literal in any build that also built zenoh-c's.

#[cfg(feature = "interceptors")]
use wz_runtime_tokio::interceptor::document::InterceptorCompileError;
#[cfg(feature = "interceptors")]
use wz_runtime_tokio::interceptor::{InterceptorConfig, InterceptorSink};
#[cfg(feature = "interceptors")]
use wz_runtime_tokio::zenoh_config::ZenohNodeConfig;

/// The interceptors one node holds.
#[derive(Clone, Default)]
pub struct NodePolicy {
    /// `Some` only when the config asks for something: an inert policy is `None`, so asking
    /// whether the node has one is a pointer test on the data path.
    #[cfg(feature = "interceptors")]
    config: Option<InterceptorConfig>,
}

impl NodePolicy {
    /// Whether the node states no policy at all.
    pub fn is_inert(&self) -> bool {
        #[cfg(feature = "interceptors")]
        {
            self.config.is_none()
        }
        #[cfg(not(feature = "interceptors"))]
        {
            true
        }
    }

    /// The policy a node's document states, or the key that could not be compiled.
    #[cfg(feature = "interceptors")]
    pub fn from_node_config(node: &ZenohNodeConfig) -> Result<Self, InterceptorCompileError> {
        let config = InterceptorConfig::from_node_config(node)?;
        Ok(Self {
            config: (!config.is_inert()).then_some(config),
        })
    }

    /// Install the policy on `session`, both flows, replacing what it held. A no-op for an
    /// inert policy.
    #[cfg(feature = "interceptors")]
    pub fn install_on(&self, sink: &dyn InterceptorSink) {
        if let Some(config) = &self.config {
            sink.set_interceptors(config.clone());
        }
    }
}

#[cfg(all(test, feature = "interceptors"))]
mod tests {
    use super::*;

    fn node(document: &str) -> ZenohNodeConfig {
        ZenohNodeConfig::from_json5(document)
            .expect("a document a real zenohd starts on")
            .config
    }

    #[test]
    fn a_document_that_states_no_policy_is_inert() {
        let policy = NodePolicy::from_node_config(&node(r#"{ mode: "peer" }"#)).unwrap();
        assert!(policy.is_inert());
    }

    #[test]
    fn a_size_cap_alone_is_a_policy() {
        let policy = NodePolicy::from_node_config(&node(
            r#"{ low_pass_filter: [ { messages: ["put"], key_exprs: ["a/**"], size_limit: 4 } ] }"#,
        ))
        .unwrap();
        assert!(!policy.is_inert());
    }

    #[test]
    fn a_disabled_acl_is_not_a_policy() {
        let policy = NodePolicy::from_node_config(&node(
            r#"{ access_control: { enabled: false, default_permission: "deny" } }"#,
        ))
        .unwrap();
        assert!(policy.is_inert());
    }

    #[test]
    fn the_default_is_inert_in_every_build() {
        assert!(NodePolicy::default().is_inert());
    }
}
