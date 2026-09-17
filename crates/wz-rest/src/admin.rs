// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The bridge's OWN plugin identity on the adminspace — the wz analogue of
//! `zenoh-plugin-rest`'s `RunningPluginTrait::adminspace_getter`
//! (`plugins/zenoh-plugin-rest/src/lib.rs` @ `fn adminspace_getter<'a>(`).
//!
//! ## Why this lives here and not in the answerer
//!
//! Upstream's REST plugin is self-describing: the adminspace does not know what
//! a plugin has to say about itself, it hands the plugin its own status key and
//! replies whatever the plugin returns (`zenoh/src/net/runtime/adminspace.rs`
//! @ `adminspace_getter`). wz keeps that division with a different mechanism —
//! the subsystem that owns the state owns its rendering, and the host folds the
//! record into the `&[AdminPlugin]` slice it already rebuilds per GET. This
//! module is the rest bridge's half of that, exactly as
//! [`RuntimeStorageManager::admin_status_leaves`] is the storage manager's.
//!
//! ## What binds `Started` to actually serving
//!
//! A record is minted from [`RestAdmin`], which holds the LIVE bound address and
//! is filled by [`serve_on_with_admin`](crate::serve_on_with_admin) at the
//! moment it starts accepting — and cleared when that accept loop returns.
//! [`RestAdmin::plugin_record`] answers `None` until then. So a host cannot
//! report `Started`, or a stale port, for a bridge that is not serving: the
//! state is read off the same thing that does the work rather than off a flag
//! the host remembers to set. That is the counterpart of the storage host's
//! `!manager.is_empty()`, which is likewise read from the manager and not from
//! a bool the caller maintains.
//!
//! [`RuntimeStorageManager::admin_status_leaves`]:
//!     wz_runtime_tokio::storage_manager_service::RuntimeStorageManager::admin_status_leaves

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// The plugin id this bridge reports itself under — zenoh's own
/// `RestPlugin::DEFAULT_NAME` (`plugins/zenoh-plugin-rest/src/lib.rs`
/// @ `const DEFAULT_NAME: &'static str = "rest";`), so a client that reads a
/// zenoh node's `plugins/**` and a wz node's finds the bridge under the same
/// key. Named here rather than at the fold site: the id is the registry key,
/// and a host that spells it itself can spell it differently from the record.
pub const PLUGIN_ID: &str = "rest";

/// The live serving state of one bridge, shared between the accept loop that
/// owns it and the admin handler that reports it.
///
/// Cheap to clone (one `Arc`); a host keeps a clone for its admin closure and
/// hands another to [`serve_on_with_admin`](crate::serve_on_with_admin).
///
/// The handle itself is ALWAYS compiled, so `serve_on_with_admin`'s signature
/// is stable across the feature toggle. Only
/// [`plugin_record`](Self::plugin_record) and
/// [`status_leaves`](Self::status_leaves) sit behind
/// `adminspace-plugins-handlers`, and that gate is FORCED rather than chosen:
/// they name `AdminPlugin`, which lives in `wz_session_core::adminspace`, and
/// that whole module is `#[cfg(feature = "adminspace-core")]`
/// (`wz-session-core/src/lib.rs` @ `pub mod adminspace;`). This crate's feature
/// composes it through wz-runtime-tokio's.
///
/// ⚠ THAT WAS ESTABLISHED BY REMOVING THE GATE AND FAILING TO BUILD, after a
/// grep for `pub mod adminspace` printed the `pub mod` line and not the `#[cfg]`
/// on the line above it, and the conclusion "the module is ungated" was drawn
/// from the printed line alone. The attributes inside the module — `AdminPlugin`
/// and friends really are outside the `adminspace-plugins-handlers` `#[cfg]`
/// blocks — are what made the wrong reading plausible: they are ungated WITHIN a
/// gated module, so reading them says nothing about reaching them. Recorded
/// because the repair is not "grep more carefully" but "ask the compiler", which
/// is the only reader that resolves a path.
#[derive(Clone, Default)]
pub struct RestAdmin {
    addr: Arc<Mutex<Option<SocketAddr>>>,
}

impl RestAdmin {
    /// A handle for a bridge that is not serving yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The address this bridge is currently accepting on, or `None` when it is
    /// not serving.
    pub fn serving_addr(&self) -> Option<SocketAddr> {
        *self.addr.lock().expect("rest admin addr poisoned")
    }

    /// Mark the bridge as serving on `addr` until the returned guard drops.
    /// Private: the only legitimate minter is the accept loop, which is what
    /// makes `Started` mean "accepting" rather than "someone said so".
    pub(crate) fn serving(&self, addr: SocketAddr) -> ServingGuard {
        *self.addr.lock().expect("rest admin addr poisoned") = Some(addr);
        ServingGuard {
            slot: Arc::clone(&self.addr),
        }
    }

    /// This bridge's admin sub-tree below
    /// `@/<zid>/<whatami>/status/plugins/rest`, or `None` when the bridge is
    /// not serving.
    ///
    /// Upstream's getter pushes exactly two responses
    /// (`plugins/zenoh-plugin-rest/src/lib.rs` @ `fn adminspace_getter<'a>(`),
    /// and R2680 RAN a `zenohd v1.10.0` carrying the real plugin cdylib and
    /// read them back rather than inferring them from that source:
    ///
    /// ```text
    /// .../status/plugins/rest/version -> "v1.10.0"
    /// .../status/plugins/rest/port    -> {"__config__":null,"__path__":null,
    ///                                     "__plugin__":null,"__required__":true,
    ///                                     "http_port":"[::]:18099",
    ///                                     "max_block_thread_num":50,
    ///                                     "work_thread_num":2}
    /// ```
    ///
    /// - `version` — the plugin's `GIT_VERSION`, a bare JSON string. A
    ///   statically composed wz subsystem has no version of its own, so this is
    ///   the node build version, the same substitution `storage_manager` makes.
    /// - `port` — despite the key, the body is the plugin's whole CONFIG object
    ///   (`Response::new(port_key, (&self.0).into())`, where `self.0` is the
    ///   `Config` and `impl From<&Config> for serde_json::Value` serializes all
    ///   of it).
    ///
    /// ## The divergences, named rather than hidden
    ///
    /// wz emits `http_port` and nothing else.
    ///
    /// **The address is the LIVE bound one.** Upstream's is the CONFIGURED one,
    /// which the run above makes visible and a source read does not: the node
    /// was given `plugins/rest/http_port:"18099"` and the leaf answered
    /// `"[::]:18099"` — the visitor's expansion of a bare port to
    /// `Ipv6Addr::UNSPECIFIED`, not an address anything resolved. A wz host may
    /// serve on port 0, where the configured value answers `:0` and says
    /// nothing; reporting what the listener is really on is the same question
    /// answered usefully.
    ///
    /// **The two thread knobs are OMITTED, not `null`.** They size a
    /// plugin-LOCAL async runtime (`WORKER_THREAD_NUM.store(conf.work_thread_num,
    /// ..)` in upstream's `start`), and this bridge has none — it spawns on the
    /// node's own `WzRuntime` tiers, which the crate docs already record as the
    /// deliberate difference. A `null` would claim the knob exists and is
    /// unset. Omitting follows the rule this surface already states for
    /// `AdminPlugin::version`: what the node cannot introspect is left out
    /// rather than answered empty. The four `__`-prefixed fields are a dlopen
    /// plugin loader's, and wz has no plugin loader to describe.
    ///
    /// ⚠ The ORDER the two leaves come back in is NOT a contract and is not
    /// asserted anywhere: the run above returned `port`, `version`, `__path__`,
    /// which is the query's reply-collection order rather than the getter's
    /// push order. Only the keys and the bodies are pinned.
    #[cfg(feature = "adminspace-plugins-handlers")]
    pub fn status_leaves(
        &self,
        version: &str,
    ) -> Option<Vec<wz_session_core::adminspace::AdminPluginStatusLeaf>> {
        self.serving_addr().map(|addr| status_leaves(version, addr))
    }

    /// This bridge as one entry of the node's plugin registry, `Started` with
    /// its sub-tree attached — or `None` when it is not serving.
    ///
    /// Fold the `Some` into the `&[AdminPlugin]` slice an admin host rebuilds
    /// per GET (`Session::declare_adminspace_with_live_inputs`), REPLACING the
    /// `Loaded` entry `compiled_plugins` contributes for the same id. A host
    /// that does not serve the bridge folds nothing and the registry keeps
    /// reporting `rest` as compiled-in-but-not-running, which is what it is.
    #[cfg(feature = "adminspace-plugins-handlers")]
    pub fn plugin_record(&self, version: &str) -> Option<wz_session_core::adminspace::AdminPlugin> {
        use wz_session_core::adminspace::{AdminPlugin, AdminPluginState};

        let addr = self.serving_addr()?;
        Some(
            AdminPlugin::wz_static(
                PLUGIN_ID,
                PLUGIN_ID,
                Some(version),
                AdminPluginState::Started,
            )
            .with_status_leaves(status_leaves(version, addr)),
        )
    }
}

/// Clears the serving address when the accept loop returns, so a bridge that
/// stopped stops being reported. Drop-scoped rather than an explicit clear at
/// the loop's exit: the loop returns on the listener's error path too, and a
/// clear that only runs on the tidy path is the shape that leaves a stale
/// `Started` behind.
pub(crate) struct ServingGuard {
    slot: Arc<Mutex<Option<SocketAddr>>>,
}

impl Drop for ServingGuard {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.slot.lock() {
            *slot = None;
        }
    }
}

/// The two leaves, rendered. Free function so the bodies can be asserted
/// without a live listener.
#[cfg(feature = "adminspace-plugins-handlers")]
fn status_leaves(
    version: &str,
    addr: SocketAddr,
) -> Vec<wz_session_core::adminspace::AdminPluginStatusLeaf> {
    use wz_session_core::adminspace::AdminPluginStatusLeaf;

    let mut version_json = String::new();
    wz_session_core::json::escape_into(version, &mut version_json);

    // `{"http_port":"<addr>"}` — the key upstream renames `addr` to
    // (`#[serde(rename = "http_port", ..)]`), and `SocketAddr` serializes as a
    // string there too, so the one field wz answers is byte-shaped like
    // upstream's.
    let mut port_json = String::from("{\"http_port\":");
    let mut addr_json = String::new();
    wz_session_core::json::escape_into(&addr.to_string(), &mut addr_json);
    port_json.push_str(&addr_json);
    port_json.push('}');

    vec![
        AdminPluginStatusLeaf::new("version", version_json),
        AdminPluginStatusLeaf::new("port", port_json),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "127.0.0.1:8000".parse().expect("fixture addr")
    }

    // The whole point of the handle: `Started` is not a thing a host asserts,
    // it is a thing the accept loop holds. Dropping the guard — which is what
    // the loop returning does — must take the record away again.
    #[test]
    fn a_record_exists_only_while_the_guard_is_held() {
        let admin = RestAdmin::new();
        assert_eq!(admin.serving_addr(), None, "not serving yet");
        {
            let _guard = admin.serving(addr());
            assert_eq!(admin.serving_addr(), Some(addr()), "serving");
        }
        assert_eq!(admin.serving_addr(), None, "the loop returned");
    }

    #[cfg(feature = "adminspace-plugins-handlers")]
    #[test]
    fn the_record_is_absent_until_the_bridge_serves() {
        use wz_session_core::adminspace::AdminPluginState;

        let admin = RestAdmin::new();
        assert!(
            admin.plugin_record("9.9.9").is_none(),
            "a bridge that is not accepting reports no Started record"
        );
        let _guard = admin.serving(addr());
        let rec = admin.plugin_record("9.9.9").expect("serving -> a record");
        assert_eq!(rec.id, PLUGIN_ID);
        assert_eq!(rec.name, PLUGIN_ID);
        assert_eq!(rec.version.as_deref(), Some("9.9.9"));
        assert_eq!(rec.state, AdminPluginState::Started);
        assert_eq!(
            rec.path,
            wz_session_core::adminspace::WZ_STATIC_PLUGIN_PATH,
            "a compiled-in subsystem, not a dlopen .so"
        );
    }

    // The bodies, against the pin. Upstream serves `version` then `port`, and
    // the `port` body is the config object keyed `http_port` — not the bare
    // port number the key suggests.
    #[cfg(feature = "adminspace-plugins-handlers")]
    #[test]
    fn the_leaves_carry_upstreams_keys_and_the_live_address() {
        let leaves = status_leaves("0.1.0", addr());
        assert_eq!(leaves.len(), 2, "upstream returns exactly two responses");
        assert_eq!(leaves[0].suffix, "version");
        assert_eq!(leaves[0].json_body, "\"0.1.0\"");
        assert_eq!(leaves[1].suffix, "port");
        assert_eq!(leaves[1].json_body, "{\"http_port\":\"127.0.0.1:8000\"}");
    }

    // The address is the one the bridge is ACCEPTING on. A host that asked for
    // port 0 must not see 0 reported back, which is the case where reporting
    // the configured address instead of the live one is silently useless.
    #[cfg(feature = "adminspace-plugins-handlers")]
    #[test]
    fn the_port_body_reports_the_resolved_address_not_the_requested_one() {
        let admin = RestAdmin::new();
        let _guard = admin.serving("127.0.0.1:47111".parse().expect("bound addr"));
        let leaves = admin.status_leaves("0.1.0").expect("serving -> leaves");
        assert_eq!(leaves[1].json_body, "{\"http_port\":\"127.0.0.1:47111\"}");
    }
}
