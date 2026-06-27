// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y39 — the typed wz runtime config SSOT (§5.23 config introspection).
//!
//! [`WzConfig`] is the TYPED union of wz runtime settings — the
//! beyond-zenoh answer to zenoh's stringly `serde_json::Value` config
//! blob (`zenoh-config api/config.rs`). Illegal config states are
//! unrepresentable by construction: a field is a real Rust type
//! (`WhatAmI`, `u16`, [`InterceptorConfig`]), not a JSON pointer into an
//! untyped tree.
//!
//! Two classes of setting, the distinction this first slice draws:
//!
//! * **read-at-open** — `whatami` / `batch_size` / `lease_ms` are
//!   negotiated and FIXED by the 4-way handshake
//!   ([`SessionInitParams`](wz_session_core::session_init_params::SessionInitParams));
//!   the config mirrors them for introspection (the admin surface reads
//!   them) but a post-open change cannot take effect without
//!   re-handshaking, so the config never re-applies them. These are
//!   populated once via [`WzConfig::from_init_params`].
//! * **live** — the interceptor / access-control config
//!   ([`InterceptorConfig`]: ACL, downsampling, low-pass) is the subset
//!   zenoh genuinely runtime-mutates (its config `Notifier` rebuilds the
//!   interceptor factories on a config diff). wz drives it the same way:
//!   [`WzConfig::reconfigure_interceptors`] mutates the typed config and,
//!   under `config-mutate-runtime`, re-installs the chain on the live
//!   [`LinkstateForwarder`] so the change takes effect at runtime.
//!
//! `config-mutate-runtime` is the inert-vs-driven toggle: OFF, a config
//! mutation is stored but never re-applied (an inert mirror — the thing
//! the §5.23 design rejects); ON, the mutation re-drives the forwarder
//! (config-DRIVEN — never a hollow mirror). The toggle existing IS the
//! proof the config is load-bearing.
//!
//! Deferred §5.23 layers (this slice is the typed-config foundation, not
//! the whole admin-mutate stack): the JSON-pointer config tree + change
//! `Notifier` + list-key-by-id merge semantics (the full
//! `config-mutate-runtime` engine), the admin `PUT config/<key>` wire
//! exposure (`adminspace-write`), and the universal (non-router)
//! read-at-open fields beyond the three mirrored here.

#[cfg(feature = "routing-peer")]
use crate::interceptor::InterceptorConfig;
#[cfg(feature = "routing-peer")]
use crate::linkstate_forward::LinkstateForwarder;
use wz_codecs::whatami::WhatAmI;
use wz_session_core::session_init_params::SessionInitParams;

/// The typed wz runtime config SSOT — see the module doc. The read-at-open
/// fields are `pub` (introspection-readable); the live `interceptors`
/// field is private so every mutation routes through
/// [`Self::reconfigure_interceptors`] (the re-apply seam), never a bare
/// field write that would silently desync the config from the forwarder.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct WzConfig {
    /// This node's role, read-at-open from the handshake. Mirrored for
    /// introspection; never re-applied (a role change needs a new session).
    pub whatami: WhatAmI,
    /// The EFFECTIVE per-link batch budget (bytes), read-at-open. Mirrors
    /// `SessionInitParams::effective_batch_size` (the `0`-unset sentinel is
    /// already resolved); handshake-fixed, never re-applied.
    pub batch_size: u16,
    /// Session lease (milliseconds), read-at-open from the handshake;
    /// handshake-fixed, never re-applied.
    pub lease_ms: u64,
    /// The LIVE interceptor / access-control config. Private: mutate via
    /// [`Self::reconfigure_interceptors`] so the forwarder stays in sync.
    #[cfg(feature = "routing-peer")]
    interceptors: InterceptorConfig,
}

impl WzConfig {
    /// A config with default (empty) settings — `whatami = Peer`,
    /// `batch_size = 0`, `lease_ms = 0`, no interceptors. The
    /// feature-independent base constructor (signature-stable: the live
    /// interceptor field defaults in, never a constructor parameter).
    pub fn new() -> Self {
        Self::default()
    }

    /// Populate the read-at-open mirror from the handshake params — the
    /// "the session reads the config at open" leg. The live interceptor
    /// config is left at its current value (it is not a handshake param).
    pub fn from_init_params(params: &SessionInitParams) -> Self {
        Self {
            whatami: params.whatami,
            batch_size: params.effective_batch_size(),
            lease_ms: params.lease_ms,
            ..Self::default()
        }
    }

    /// R311y40 — the admin-GET JSON view of the read-at-open config mirror
    /// (the `@/<zid>/<whatami>/config` reply, the §5.23 "admin surface READS
    /// config" leg; zenoh exposes config at `@/<zid>/<whatami>/config/**`).
    /// Alphabetical keys (`batch_size` / `lease_ms` / `whatami`), matching the
    /// serde_json-BTreeMap order the other §5.23 emitters (`AdminLocalData`)
    /// use. The LIVE interceptor config is a deferred layer — it is not in
    /// this view until the production WzConfig-holds-the-forwarder wiring
    /// lands (registered as a §5.23 caveat).
    pub fn to_admin_json(&self) -> String {
        format!(
            r#"{{"batch_size":{},"lease_ms":{},"whatami":"{}"}}"#,
            self.batch_size,
            self.lease_ms,
            self.whatami.to_str()
        )
    }

    /// The current live interceptor / access-control config.
    #[cfg(feature = "routing-peer")]
    pub fn interceptors(&self) -> &InterceptorConfig {
        &self.interceptors
    }

    /// Builder-style initial interceptor config (consumed at setup).
    #[cfg(feature = "routing-peer")]
    pub fn with_interceptors(mut self, interceptors: InterceptorConfig) -> Self {
        self.interceptors = interceptors;
        self
    }

    /// The config-DRIVEN initial install: drive `fwd` from this config's
    /// interceptor settings. Called once at routing setup — the same
    /// `set_interceptors` seam the live reconfigure re-uses, so setup and
    /// runtime go through ONE code path.
    #[cfg(feature = "routing-peer")]
    pub fn install_interceptors(&self, fwd: &LinkstateForwarder) {
        fwd.set_interceptors(self.interceptors.clone());
    }

    /// Runtime reconfigure of the live interceptor config: store the new
    /// typed value and, under `config-mutate-runtime`, RE-INSTALL it on the
    /// live `fwd` so the change takes effect immediately (the forwarder's
    /// admit/deny verdict flips on the next message). This is the
    /// config-DRIVEN leg the §5.23 design demands.
    ///
    /// `config-mutate-runtime` OFF: the new value is stored (the typed
    /// config stays the introspection SSOT) but NOT re-applied — an inert
    /// mirror, the build that opts out of runtime reconfiguration. The
    /// signature is feature-stable either way.
    #[cfg(feature = "routing-peer")]
    pub fn reconfigure_interceptors(
        &mut self,
        interceptors: InterceptorConfig,
        fwd: &LinkstateForwarder,
    ) {
        self.interceptors = interceptors;
        #[cfg(feature = "config-mutate-runtime")]
        fwd.set_interceptors(self.interceptors.clone());
        #[cfg(not(feature = "config-mutate-runtime"))]
        let _ = fwd;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_admin_json_is_typed_alphabetical() {
        // R311y40 — the config GET reply shape: TYPED fields, serde_json-BTreeMap
        // alphabetical key order (batch_size / lease_ms / whatami), whatami as the
        // zenoh role string. The read-at-open mirror; the live interceptor config
        // is a deferred layer not in this view.
        let c = WzConfig {
            whatami: WhatAmI::Router,
            batch_size: 65535,
            lease_ms: 10_000,
            ..WzConfig::new()
        };
        assert_eq!(
            c.to_admin_json(),
            r#"{"batch_size":65535,"lease_ms":10000,"whatami":"router"}"#
        );
    }
}
