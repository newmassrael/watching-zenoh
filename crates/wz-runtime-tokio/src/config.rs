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
//!   forwarder via the [`InterceptorSink`](crate::interceptor::InterceptorSink)
//!   seam (the production impl is
//!   [`LinkstateForwarder`](crate::linkstate_forward::LinkstateForwarder)) so
//!   the change takes effect at runtime.
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
//! `config-mutate-runtime` engine), and the universal (non-router)
//! read-at-open fields beyond the three mirrored here. (The admin
//! `PUT config/<key>` wire — `adminspace-write` — landed in R311y51, gated
//! by `permissions.write`; the config-GET read view is complete as of R311y54.)

#[cfg(feature = "routing-peer")]
use crate::interceptor::{InterceptorConfig, InterceptorSink};
use wz_codecs::whatami::WhatAmI;
use wz_session_core::session_init_params::SessionInitParams;

/// The typed wz runtime config SSOT — see the module doc. The read-at-open
/// fields are `pub` (introspection-readable); the live `interceptors`
/// field is private so every mutation routes through
/// [`Self::reconfigure_interceptors`] (the re-apply seam), never a bare
/// field write that would silently desync the config from the forwarder.
#[derive(Debug, Clone)]
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
    /// The LIVE adminspace permissions (zenoh `adminspace.permissions`, the
    /// `PermissionsConf` read/write pair). The SECOND runtime-mutable typed slice
    /// after [`Self::interceptors`], and it is here for the same reason: zenoh
    /// re-reads `conf.adminspace.permissions()` from the LIVE config on EVERY admin
    /// request — the GET gate at `net/runtime/adminspace.rs:456-457` and the
    /// config-WRITE gate at `:394-396` both take the config lock inside the handler,
    /// so a runtime config change (which upstream's own admin PUT can perform) flips
    /// the gate for the very next request. A permit captured by value at host-setup
    /// time cannot do that, which is why the two gates read this field per request
    /// rather than a captured bool.
    ///
    /// Private, like `interceptors`: mutate via [`Self::set_admin_permissions`] so
    /// the "one live config instance, read per request" invariant is structural.
    /// Default = zenoh's `PermissionsConf::default` (read `true`, write `false`).
    #[cfg(feature = "adminspace-core")]
    admin_permissions: wz_session_core::adminspace::AdminSpacePermissions,
    /// R311y205 (transport-multilink) — the EMBEDDER-facing max number of physical
    /// links this node aggregates into ONE logical unicast session (zenoh
    /// `TransportManager` `unicast.max_links`). Default `1` = single-link,
    /// byte-identical to today. `active <=> cfg-toggle`: the field only exists
    /// under `transport-multilink`, and even then stays INERT unless set `> 1`
    /// (`1` = the single-link degenerate path).
    ///
    /// This is a faithful structural mirror of zenoh, not a divergence. zenoh splits
    /// `max_links` across two layers: the CONFIG surface `unicast.max_links`
    /// (`commons/zenoh-config`, `TransportUnicastConf`) is UNCONDITIONAL and defaults
    /// to `1`, while the COMPILE-TIME gate lives in the transport-manager's INTERNAL
    /// field (`io/zenoh-transport/src/unicast/manager.rs`, under `#[cfg(feature =
    /// "transport_multilink")]`), which is populated from the config value inside a
    /// `#[cfg]` block and activates the multilink establishment at `> 1`
    /// (`MultiLink::make(.., max_links > 1)`). wz collapses those two layers into this
    /// ONE `WzConfig` field and gates IT — faithful to zenoh's manager-layer gate,
    /// defaulting to `1` like the config surface.
    ///
    /// R311y213 — the `WzConfig.max_links -> FaceSources.max_links` mapping is now
    /// live in the reference peer runner (`wz-ap-demo`'s `run_peer`), which sets this
    /// field via [`Self::with_max_links`] from `--max-links` and hands the SAME
    /// `WzConfig` instance to both the aggregation loop and the `--config-queryable`
    /// admin handler, so there is ONE budget source, not a second (a structural
    /// no-desync). R311y473 made it GET-OBSERVABLE too: `to_admin_json` renders
    /// `max_links`, so the budget is readable over the wire and not only off a
    /// startup log line. `peer_loop` reads the activation
    /// knob off [`FaceSources::max_links`](crate::accept_loop::FaceSources) (the
    /// zid-registry join at `Step::Opened`); the runner bridges the two. (Until
    /// R311y213 this note claimed no such runner could exist because a
    /// `transport-multilink` × `session-reconnect` `compile_error!` XOR blocked the
    /// default reconnect runners; that XOR was removed in R311y211, making the
    /// mapping runner reachable.)
    #[cfg(feature = "transport-multilink")]
    pub max_links: usize,
    /// R311y216 (transport-qos) — the EMBEDDER-facing "this deploy offers the QoS
    /// transport toward its peers" knob (zenoh `unicast.is_qos`,
    /// `commons/zenoh-config` `TransportUnicastConf`, read into the establishment
    /// state at `manager.config.unicast.is_qos`). Default `false` = single-conduit,
    /// byte-identical to a pre-QoS session. `active <=> cfg-toggle`: the field only
    /// exists under `transport-qos`, and even then a session negotiates QoS only
    /// when BOTH this offer AND the peer's `ext_qos` offer are set (the symmetric
    /// `&=` AND at [`crate::session_open`] / `SessionLinkActions::set_qos_offer`).
    ///
    /// This is a faithful mirror of zenoh's config surface, not a divergence.
    /// zenoh reads `unicast.is_qos` per-manager (uniform across a manager's
    /// sessions); wz stages it per-session via the `*_with_qos` open entrypoints,
    /// a superset (one qos session + one non-qos session under one node), while
    /// each individual session still negotiates faithfully. Like `max_links`, this
    /// field is the config surface: the single-link `*_with_qos` entrypoints take
    /// the offer directly, while the reference peer runner bridges `WzConfig.qos ->
    /// FaceSources.qos -> the `*_with_multilink` entrypoints` (R311y218 delivered
    /// the demo `--qos` reader over the multilink path; per-face priority-band
    /// segregation is R311y219). R311y473 — `to_admin_json` renders it (as with
    /// `max_links`), as the node's OFFER rather than the negotiated outcome.
    #[cfg(feature = "transport-qos")]
    pub qos: bool,
    /// session-extqos (R311y506) — the QoS METADATA this node declares for its
    /// links: the priority band it serves and/or the reliability class, zenoh's
    /// endpoint `prio=` / `rel=` metadata (`Metadata::PRIORITIES` /
    /// `Metadata::RELIABILITY`, `core/endpoint.rs:196-197`) read into
    /// `State::QoS { .. }` by `StateOpen::new` / `StateAccept::new`.
    ///
    /// `None` (the default) keeps the presence-only UNIT `QoS` ext on the wire —
    /// byte-identical to a `transport-qos`-only node. `Some` switches the emit to
    /// the z64 `QoSLink` and arms the DIRECTIONAL containment, which can REFUSE a
    /// peer: an acceptor demands the initiator's band be a subset of its own, an
    /// initiator demands the acceptor's be a superset of its own. That refusal is
    /// zenoh's, not a wz addition, and it is what makes the band an interop
    /// contract rather than a hint.
    ///
    /// Meaningful only alongside [`Self::qos`] — zenoh reaches the endpoint
    /// metadata only inside the `is_qos` arm of `State::new`, and the wz emit seam
    /// applies the same guard, so metadata on a non-QoS node is inert.
    #[cfg(feature = "session-extqos")]
    pub qos_link: Option<wz_session_core::extqos::QosLinkState>,
}

impl Default for WzConfig {
    /// The base config — `whatami = Peer`, `batch_size = 0`, `lease_ms = 0`, no
    /// interceptors, admin permissions at zenoh's `PermissionsConf` default
    /// (read `true`, write `false`), `max_links = 1`, `qos = false`. A hand-written impl (not
    /// derived) so the `transport-multilink` `max_links` defaults to `1` (the
    /// single-link degenerate path), not the `usize` `Default` of `0`; every other
    /// field keeps its type `Default` (`qos` = `false`, byte-identical to a pre-QoS
    /// session), so the derived and hand-written impls agree on the pre-multilink
    /// fields.
    fn default() -> Self {
        Self {
            whatami: WhatAmI::default(),
            batch_size: 0,
            lease_ms: 0,
            #[cfg(feature = "routing-peer")]
            interceptors: InterceptorConfig::default(),
            #[cfg(feature = "adminspace-core")]
            admin_permissions: wz_session_core::adminspace::AdminSpacePermissions::default(),
            #[cfg(feature = "transport-multilink")]
            max_links: 1,
            #[cfg(feature = "transport-qos")]
            qos: false,
            #[cfg(feature = "session-extqos")]
            qos_link: None,
        }
    }
}

/// R311y205 (transport-multilink) — the per-link reliability preference the
/// dial / accept path attaches to a physical link so the aggregation core
/// segregates traffic classes across the aggregated links (the wz analogue of
/// zenoh's per-channel `select`): the reliable channel prefers the `Reliable`
/// link, the best-effort channel the `BestEffort` link, `Any` (default) the
/// failover pool.
///
/// IMPL-2b — re-exported from the no_std session kernel, where
/// [`LinkState`](wz_session_core::session_actions::LinkState) actually stores it
/// (the reliability-routed `select_link` reads it), so the AP config surface and
/// the kernel agree by construction (ONE type, no conversion at the
/// `set_link_reliability_pref` seam).
#[cfg(feature = "transport-multilink")]
pub use wz_session_core::session_actions::LinkReliabilityPref;

/// R311y217 (transport-multilink + transport-qos) — the per-link QoS-priority band
/// the dial / accept path attaches to a physical link so the aggregation core pins
/// each `(priority, reliability)` conduit to ONE link (the priority tier of
/// zenoh's per-channel `select`). Re-exported from the no_std session kernel where
/// [`LinkState`](wz_session_core::session_actions::LinkState) stores it, so the AP
/// config surface and the kernel agree by construction (ONE type, no conversion at
/// the `set_link_priority_range` seam).
///
/// R311y506 — the gate WIDENED to `transport-qos` alone, following the kernel
/// type it re-exports. The band has a SECOND consumer now: it is also the body of
/// the `init::ext::QoSLink` establishment ext (`session-extqos`), which needs no
/// multilink. Upstream uses one `PriorityRange` for both, and so does wz.
#[cfg(feature = "transport-qos")]
pub use wz_session_core::session_actions::LinkPriorityRange;

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

    /// R311y40 — the admin-GET JSON view of the config (the
    /// `@/<zid>/<whatami>/config` reply). BEYOND-ZENOH (R311y42 correction):
    /// zenoh's `@/<zid>/<whatami>/config/**` is a write-only subscriber (PUT ->
    /// `insert_json5`); zenoh has NO admin config-READ, so this typed read is a wz
    /// superset, not a mirror. Alphabetical keys, matching the serde_json-BTreeMap
    /// order the other §5.23 emitters (`AdminLocalData`) use.
    ///
    /// R311y49/y50 — the LIVE ACL is now in this view: under `routing-peer` +
    /// `access-acl`, `acl_default` (the policy's base verdict `"allow"`/`"deny"`)
    /// and `acl_deny` (the denied-keyexpr summary array) carry the access-control
    /// state. This makes a runtime config-write reconfigure GET-OBSERVABLE (the
    /// read-path counterpart to the data-plane drop): after a `config/acl-deny` PUT
    /// the admin GET shows the new deny list, closing the R311y45 read-at-open
    /// caveat on the read path too. `acl_default` is REQUIRED for faithfulness — a
    /// bare `acl_deny:[]` on a DEFAULT-DENY policy would read as "open" (the exact
    /// opposite of the truth); the pair disambiguates. `batch_size` / `lease_ms` /
    /// `whatami` remain the handshake-fixed read-at-open mirror.
    ///
    /// R311y53 — the interceptor view is complete on the rate/size axes:
    /// `downsampling` (under `access-downsampling`) and `low_pass` (under
    /// `access-quota`) emit the LIVE rule arrays (`{key_exprs, min_interval_ms}` /
    /// `{key_exprs, max_payload_size}`). These are startup-config introspection
    /// (only `acl-deny` is runtime-reconfigurable via config-write so far).
    ///
    /// R311y54 — the ACL view is now complete too: `acl_rules` is the FULL per-rule
    /// dump (each `{flow, key_exprs, messages, permission, subject}`), the detail
    /// complement to the `acl_deny` summary (which stays the quick-glance denied-
    /// keyexpr list). The §5.23 config-GET view now mirrors the entire live
    /// interceptor config; no introspection axis remains deferred.
    ///
    /// R311y50 — built from an ordered (alphabetical) (key, value-json) list rather
    /// than a hand-spliced `format!`, so a new field is "push a pair where it
    /// sorts" with no per-field comma bookkeeping (the prior trailing-comma-prepend
    /// only worked for one leading optional key and broke for the deferred
    /// `downsampling`/`sessions` fields, which sort mid-object). String values go
    /// through the shared [`wz_session_core::json::escape_into`] SSOT escaper.
    pub fn to_admin_json(&self) -> String {
        // (key, value-json) pairs, present-only; sorted alphabetically below, so the
        // order they are assembled in does not matter.
        //
        // R311y474 — the three UNCONDITIONAL fields seed the vector rather than
        // being pushed after the cfg-gated ones. Same output (the sort follows), but
        // it is now the type that says which fields every build carries, and it
        // retires a REAL clippy::vec_init_then_push failure that Layer C1bb was
        // already red on: with `Vec::new()` first, a feature combo in which several
        // gated pushes expand back-to-back (transport-multilink + transport-qos was
        // enough) leaves clippy looking at a plain push chain it wants folded into
        // `vec![..]` — a suggestion the code CANNOT take, because under another combo
        // those very pushes are absent. Seeding the vector removes the cause instead
        // of silencing the lint.
        let mut whatami = String::new();
        wz_session_core::json::escape_into(self.whatami.to_str(), &mut whatami);
        let mut fields: Vec<(&str, String)> = vec![
            ("batch_size", self.batch_size.to_string()),
            ("lease_ms", self.lease_ms.to_string()),
            ("whatami", whatami),
        ];

        // acl_default / acl_deny — the LIVE ACL view, present only on a build that
        // can carry an interceptor ACL. With no ACL the node admits all, so the
        // base verdict is "allow" and the deny list is empty.
        #[cfg(all(feature = "routing-peer", feature = "access-acl"))]
        {
            use wz_access_control::{Permission, SubjectSelector};
            use wz_session_core::zid_hex::zid_to_zenoh_hex;
            let default_perm = self
                .interceptors
                .acl
                .as_ref()
                .map(|a| a.default_permission())
                .unwrap_or(Permission::Allow);
            // R311y54 — via the Permission::as_str SSOT (shared with acl_rules).
            let mut v = String::new();
            wz_session_core::json::escape_into(default_perm.as_str(), &mut v);
            fields.push(("acl_default", v));

            // R311y60 — the denied-keyexpr summary via the json::push_str_array
            // SSOT (the array bracket/comma bookkeeping lives in one place beside
            // escape_into); empty when no ACL.
            let deny_keys = self
                .interceptors
                .acl
                .as_ref()
                .map(|a| a.deny_key_exprs())
                .unwrap_or_default();
            let mut deny = String::new();
            wz_session_core::json::push_str_array(deny_keys, &mut deny);
            fields.push(("acl_deny", deny));

            // R311y54 — acl_rules: the FULL per-rule dump (the detail complement to
            // the acl_deny summary), one object per rule with keys ALPHABETICAL
            // (flow, key_exprs, messages, permission, subject). subject is "any" or
            // the peer's zid hex; enums via the wz-access-control as_str SSOTs; the
            // key_exprs / messages string arrays via the json::push_str_array SSOT.
            let mut rules_json = String::from("[");
            if let Some(acl) = &self.interceptors.acl {
                for (i, rule) in acl.rules().iter().enumerate() {
                    if i > 0 {
                        rules_json.push(',');
                    }
                    rules_json.push_str("{\"flow\":");
                    wz_session_core::json::escape_into(rule.flow.as_str(), &mut rules_json);
                    rules_json.push_str(",\"key_exprs\":");
                    wz_session_core::json::push_str_array(&rule.key_exprs, &mut rules_json);
                    rules_json.push_str(",\"messages\":");
                    wz_session_core::json::push_str_array(
                        rule.messages.iter().map(|m| m.as_str()),
                        &mut rules_json,
                    );
                    rules_json.push_str(",\"permission\":");
                    wz_session_core::json::escape_into(rule.permission.as_str(), &mut rules_json);
                    rules_json.push_str(",\"subject\":");
                    let subject = match &rule.subject {
                        SubjectSelector::Any => String::from("any"),
                        SubjectSelector::Zid(z) => zid_to_zenoh_hex(z.as_slice()),
                    };
                    wz_session_core::json::escape_into(&subject, &mut rules_json);
                    rules_json.push('}');
                }
            }
            rules_json.push(']');
            fields.push(("acl_rules", rules_json));
        }

        // downsampling — the LIVE rate-limit rules (each `{key_exprs, min_interval_ms}`),
        // the §5.23 introspection of the access-downsampling interceptor slice. Present
        // only under access-downsampling; an empty array means no rule is installed.
        #[cfg(all(feature = "routing-peer", feature = "access-downsampling"))]
        {
            let mut ds = String::from("[");
            for (i, rule) in self.interceptors.downsampling.iter().enumerate() {
                if i > 0 {
                    ds.push(',');
                }
                ds.push_str("{\"key_exprs\":");
                wz_session_core::json::push_str_array(&rule.key_exprs, &mut ds);
                ds.push_str(",\"min_interval_ms\":");
                ds.push_str(&rule.min_interval.as_millis().to_string());
                ds.push('}');
            }
            ds.push(']');
            fields.push(("downsampling", ds));
        }

        // low_pass — the LIVE per-key payload-size caps (each `{key_exprs,
        // max_payload_size}`), the introspection of the access-quota interceptor
        // slice. Present only under access-quota; an empty array means no rule.
        #[cfg(all(feature = "routing-peer", feature = "access-quota"))]
        {
            let mut lp = String::from("[");
            for (i, rule) in self.interceptors.low_pass.iter().enumerate() {
                if i > 0 {
                    lp.push(',');
                }
                lp.push_str("{\"key_exprs\":");
                wz_session_core::json::push_str_array(&rule.key_exprs, &mut lp);
                lp.push_str(",\"max_payload_size\":");
                lp.push_str(&rule.max_payload_size.to_string());
                lp.push('}');
            }
            lp.push(']');
            fields.push(("low_pass", lp));
        }

        // R311y473 — max_links: the EFFECTIVE aggregation budget, closing the
        // "structural no-desync but not GET-observable" caveat R311y213 left on
        // this field. It is the config half of transport-multilink's S5 residual:
        // the runtime half is the per-link `sessions[].links` array the admin
        // `local_data` now renders. An operator could previously only read the
        // budget off a startup LOG LINE, which is not a wire surface.
        #[cfg(feature = "transport-multilink")]
        fields.push(("max_links", self.max_links.to_string()));

        // R311y473 — qos: the same treatment for the transport-qos offer, whose
        // doc-comment carried the identical "to_admin_json does not render it (as
        // with max_links)" caveat. This is the OFFER this node makes, not the
        // negotiated outcome (QoS engages only if the peer offers too).
        #[cfg(feature = "transport-qos")]
        fields.push(("qos", self.qos.to_string()));

        // session-extqos (R311y506) — the declared QoS link metadata, rendered as
        // zenoh's own endpoint-metadata spelling (`prio=start-end`, `rel=0|1`) so
        // an operator reading the adminspace sees the SAME string they would put
        // on a zenoh endpoint. Absent when nothing is declared, which is the
        // UNIT-ext-on-the-wire case.
        #[cfg(feature = "session-extqos")]
        let qos_link_rendered = self.qos_link.map(|s| {
            let mut parts: Vec<String> = Vec::new();
            if let Some(p) = s.priorities {
                parts.push(format!(
                    "prio={}-{}",
                    p.start().wire_byte(),
                    p.end().wire_byte()
                ));
            }
            if let Some(r) = s.reliability {
                parts.push(format!("rel={}", r as u8));
            }
            format!("\"{}\"", parts.join(";"))
        });
        #[cfg(feature = "session-extqos")]
        if let Some(rendered) = qos_link_rendered.as_deref() {
            fields.push(("qos_link", rendered.to_string()));
        }

        // serde_json-BTreeMap alphabetical key order. R311y53 — an explicit sort (vs
        // the prior push-in-order assumption) so a new field is just "push it" with no
        // position bookkeeping (downsampling/low_pass sort MID-object, between
        // batch_size and lease_ms / lease_ms and whatami).
        fields.sort_by(|a, b| a.0.cmp(b.0));

        let mut out = String::from("{");
        for (i, (key, value)) in fields.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('"');
            out.push_str(key);
            out.push_str("\":");
            out.push_str(value);
        }
        out.push('}');
        out
    }

    /// Builder-style initial interceptor config (consumed at setup).
    #[cfg(feature = "routing-peer")]
    pub fn with_interceptors(mut self, interceptors: InterceptorConfig) -> Self {
        self.interceptors = interceptors;
        self
    }

    /// R311y213 (transport-multilink) — set the aggregated-link budget (the
    /// `unicast.max_links` analogue), consumed at setup. The builder twin of the
    /// `pub max_links` field, mirroring [`Self::with_interceptors`]: the reference
    /// peer runner chains it onto `from_init_params(..).with_interceptors(..)` so the
    /// ONE `WzConfig` it hands to both the aggregation loop and the admin surface
    /// carries the effective budget (no post-construction field poke that could
    /// desync a shared config). `1` = single-link (the `Default`).
    #[cfg(feature = "transport-multilink")]
    pub fn with_max_links(mut self, max_links: usize) -> Self {
        self.max_links = max_links;
        self
    }

    /// R311y216 (transport-qos) — offer the QoS transport toward this node's
    /// peers (zenoh `unicast.is_qos`), consumed at setup. The builder twin of the
    /// `pub qos` field, mirroring [`Self::with_max_links`]: a caller reads this to
    /// select the `*_with_qos` open entrypoint. `false` = single-conduit (the
    /// `Default`, byte-identical to a pre-QoS session). QoS engages only when the
    /// peer also offers `ext_qos` (the symmetric `&=` AND at open).
    #[cfg(feature = "transport-qos")]
    pub fn with_qos(mut self, qos: bool) -> Self {
        self.qos = qos;
        self
    }

    /// session-extqos (R311y506) — declare this node's QoS link metadata (the
    /// priority band / reliability class it serves), the builder twin of the
    /// `pub qos_link` field. Also turns [`Self::qos`] ON, because the metadata is
    /// meaningless without the offer that carries it: zenoh reads the endpoint
    /// metadata only inside the `is_qos` arm of `State::new`, so a band declared
    /// on a NoQoS node would be silently dropped rather than negotiated. Making
    /// the implication structural here means a caller cannot express that
    /// no-op combination by accident.
    #[cfg(feature = "session-extqos")]
    pub fn with_qos_link(mut self, qos_link: wz_session_core::extqos::QosLinkState) -> Self {
        self.qos_link = Some(qos_link);
        self.qos = true;
        self
    }

    /// R311y48 (§5.23 Phase 3b) — read the live interceptor config. The
    /// read accessor symmetric with the private `interceptors` field's write
    /// path ([`Self::reconfigure_interceptors`]): a partial config-write (e.g.
    /// `config/acl-deny`, which sets only the ACL slice) clones THIS to preserve
    /// the unrelated interceptors (downsampling, low-pass), mutates the one slice,
    /// and re-applies the merged whole — so a write to one config key never
    /// silently drops the others. Borrowing, not cloning: the caller clones only
    /// when it intends to mutate-and-reapply.
    #[cfg(feature = "routing-peer")]
    pub fn interceptors(&self) -> &InterceptorConfig {
        &self.interceptors
    }

    /// The config-DRIVEN initial install: drive `sink` from this config's
    /// interceptor settings. Called once at routing setup — the same
    /// [`InterceptorSink::set_interceptors`] seam the live reconfigure re-uses,
    /// so setup and runtime go through ONE code path. `sink` is the abstract
    /// interceptor target (the production impl is the `LinkstateForwarder`); the
    /// trait seam is what lets the §5.23 combined node compose the config-drive
    /// surface without depending on the concrete forwarder type.
    #[cfg(feature = "routing-peer")]
    pub fn install_interceptors(&self, sink: &dyn InterceptorSink) {
        sink.set_interceptors(self.interceptors.clone());
    }

    /// Runtime reconfigure of the live interceptor config: store the new
    /// typed value and, under `config-mutate-runtime`, RE-INSTALL it on the
    /// live `sink` so the change takes effect immediately (the forwarder's
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
        sink: &dyn InterceptorSink,
    ) {
        self.interceptors = interceptors;
        #[cfg(feature = "config-mutate-runtime")]
        sink.set_interceptors(self.interceptors.clone());
        #[cfg(not(feature = "config-mutate-runtime"))]
        let _ = sink;
    }

    /// Builder-style initial adminspace permissions (consumed at setup) — the
    /// admin twin of [`Self::with_interceptors`]. A host builds ONE `WzConfig`
    /// carrying its startup permits and hands it to both the admin GET host and
    /// the config-WRITE host, so there is one permit source, not two.
    #[cfg(feature = "adminspace-core")]
    pub fn with_admin_permissions(
        mut self,
        permissions: wz_session_core::adminspace::AdminSpacePermissions,
    ) -> Self {
        self.admin_permissions = permissions;
        self
    }

    /// Read the LIVE adminspace permissions — the accessor an admin host calls
    /// INSIDE its per-request handler, which is the whole point of the field.
    /// Returns by value (the type is two `bool`s and `Copy`), so a handler holding
    /// a shared cell borrows it for the read alone and never across a reply.
    ///
    /// Feed the result to [`admin_read_permit`](crate::admin_read_permit) /
    /// [`admin_write_permit`](crate::admin_write_permit) — the cfg resolvers that
    /// turn the value into the effective permit — rather than reading the fields
    /// directly, so a build with the gate compiled out stays permissive at exactly
    /// one place.
    #[cfg(feature = "adminspace-core")]
    pub fn admin_permissions(&self) -> wz_session_core::adminspace::AdminSpacePermissions {
        self.admin_permissions
    }

    /// Runtime reconfigure of the live adminspace permissions — the admin-permit
    /// twin of [`Self::reconfigure_interceptors`], and the mutation that makes the
    /// gate genuinely live: the next admin request re-reads this value.
    ///
    /// Unlike the interceptor slice this needs NO sink and no
    /// `config-mutate-runtime` arm. The distinction is real rather than an
    /// omission: an interceptor change must be PUSHED into a forwarder that
    /// compiled its chain, whereas the permits are PULLED by each gate on every
    /// request (zenoh does the same — it takes the config lock inside the handler,
    /// `net/runtime/adminspace.rs:394` and `:456`), so storing the new value IS
    /// applying it. There is consequently no inert-mirror arm to opt out of.
    #[cfg(feature = "adminspace-core")]
    pub fn set_admin_permissions(
        &mut self,
        permissions: wz_session_core::adminspace::AdminSpacePermissions,
    ) {
        self.admin_permissions = permissions;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // R311y40/y49/y50/y53 — the config GET reply shape: TYPED fields, serde_json-
    // BTreeMap alphabetical key order, whatami as the zenoh role string. The emitted
    // key set depends on the access-* features, so the byte-exact assertion is split
    // per feature combo (each gated to EXACTLY the build that emits that shape, so no
    // never-run branch and no wrong assertion under an un-CI'd partial combo). The
    // empty-config shape: acl => acl_default:"allow"/acl_deny:[]; downsampling/low_pass
    // => empty arrays; always batch_size/lease_ms/whatami — sorted alphabetically.
    fn router_config() -> WzConfig {
        WzConfig {
            whatami: WhatAmI::Router,
            batch_size: 65535,
            lease_ms: 10_000,
            ..WzConfig::new()
        }
    }

    // R311y473 — the seven exact-string tests below pin the ACCESS axis, and each
    // is gated to exactly the build emitting its shape. They now also exclude the
    // two TRANSPORT-axis keys (`max_links` / `qos`), which are orthogonal to
    // access and would otherwise multiply seven assertions by four. The combo that
    // carries all of them — the preset-ap-full shape — gets its own exact pin in
    // `to_admin_json_ap_full_shape_alphabetical`, so no shipped combo is left
    // without one.
    #[cfg(all(
        not(any(
            feature = "access-acl",
            feature = "access-downsampling",
            feature = "access-quota"
        )),
        not(feature = "transport-multilink"),
        not(feature = "transport-qos")
    ))]
    #[test]
    fn to_admin_json_base_alphabetical() {
        // No access interceptor feature: just the 3 read-at-open keys.
        assert_eq!(
            router_config().to_admin_json(),
            r#"{"batch_size":65535,"lease_ms":10000,"whatami":"router"}"#
        );
    }

    #[cfg(all(
        feature = "routing-peer",
        feature = "access-acl",
        not(feature = "access-downsampling"),
        not(feature = "access-quota"),
        not(feature = "transport-multilink"),
        not(feature = "transport-qos")
    ))]
    #[test]
    fn to_admin_json_acl_only_alphabetical() {
        // access-acl only: acl_default/acl_deny/acl_rules lead (all sort before
        // batch_size). Empty policy -> empty deny + empty rules arrays.
        assert_eq!(
            router_config().to_admin_json(),
            r#"{"acl_default":"allow","acl_deny":[],"acl_rules":[],"batch_size":65535,"lease_ms":10000,"whatami":"router"}"#
        );
    }

    // R311y453 — the FOUR combinations of {acl, downsampling, quota} that had NO
    // assertion at all. The comment above claims the split covers every build
    // that emits a shape, but 4 of the 8 subsets fell through every gate:
    // downsampling-only, quota-only, acl+downsampling and acl+quota. The visible
    // symptom was a `router_config is never used` dead-code error under a single
    // access knob with `--all-targets` (recorded as a pre-existing defect in the
    // R311y452 carry, uncovered by any lane because C1y clippies each knob
    // LIB-only); the actual defect is the coverage hole the dead helper was
    // pointing at. Closing the hole is what removes the warning — an `#[allow]`
    // would have silenced the messenger.
    #[cfg(all(
        feature = "routing-peer",
        feature = "access-downsampling",
        not(feature = "access-acl"),
        not(feature = "access-quota"),
        not(feature = "transport-multilink"),
        not(feature = "transport-qos")
    ))]
    #[test]
    fn to_admin_json_downsampling_only_alphabetical() {
        // downsampling sorts between batch_size and lease_ms.
        assert_eq!(
            router_config().to_admin_json(),
            r#"{"batch_size":65535,"downsampling":[],"lease_ms":10000,"whatami":"router"}"#
        );
    }

    #[cfg(all(
        feature = "routing-peer",
        feature = "access-quota",
        not(feature = "access-acl"),
        not(feature = "access-downsampling"),
        not(feature = "transport-multilink"),
        not(feature = "transport-qos")
    ))]
    #[test]
    fn to_admin_json_quota_only_alphabetical() {
        // low_pass sorts between lease_ms and whatami.
        assert_eq!(
            router_config().to_admin_json(),
            r#"{"batch_size":65535,"lease_ms":10000,"low_pass":[],"whatami":"router"}"#
        );
    }

    #[cfg(all(
        feature = "routing-peer",
        feature = "access-acl",
        feature = "access-downsampling",
        not(feature = "access-quota"),
        not(feature = "transport-multilink"),
        not(feature = "transport-qos")
    ))]
    #[test]
    fn to_admin_json_acl_and_downsampling_alphabetical() {
        assert_eq!(
            router_config().to_admin_json(),
            r#"{"acl_default":"allow","acl_deny":[],"acl_rules":[],"batch_size":65535,"downsampling":[],"lease_ms":10000,"whatami":"router"}"#
        );
    }

    #[cfg(all(
        feature = "routing-peer",
        feature = "access-acl",
        feature = "access-quota",
        not(feature = "access-downsampling"),
        not(feature = "transport-multilink"),
        not(feature = "transport-qos")
    ))]
    #[test]
    fn to_admin_json_acl_and_quota_alphabetical() {
        assert_eq!(
            router_config().to_admin_json(),
            r#"{"acl_default":"allow","acl_deny":[],"acl_rules":[],"batch_size":65535,"lease_ms":10000,"low_pass":[],"whatami":"router"}"#
        );
    }

    #[cfg(all(
        feature = "routing-peer",
        feature = "access-acl",
        feature = "access-downsampling",
        feature = "access-quota",
        not(feature = "transport-multilink"),
        not(feature = "transport-qos")
    ))]
    #[test]
    fn to_admin_json_full_access_alphabetical() {
        // The full routing-peer access set (the wz-ap-demo build): acl_rules sorts
        // after acl_deny; downsampling between batch_size and lease_ms; low_pass
        // between lease_ms and whatami.
        assert_eq!(
            router_config().to_admin_json(),
            r#"{"acl_default":"allow","acl_deny":[],"acl_rules":[],"batch_size":65535,"downsampling":[],"lease_ms":10000,"low_pass":[],"whatami":"router"}"#
        );
    }

    /// R311y473 — the preset-ap-full config shape: the full access set PLUS the two
    /// transport-axis keys. This combo previously had NO exact-string pin (the seven
    /// access-axis tests all exclude it now that `max_links` / `qos` land), and it
    /// is the shape wz-ap-demo actually ships, so it gets one here.
    ///
    /// `max_links` sorts between `lease_ms` and `qos`, `qos` between `max_links` and
    /// `whatami` — both mid-object, which is exactly the position bookkeeping the
    /// R311y50 sorted-pairs rewrite exists to make free.
    #[cfg(all(
        feature = "routing-peer",
        feature = "access-acl",
        feature = "access-downsampling",
        feature = "access-quota",
        feature = "transport-multilink",
        feature = "transport-qos"
    ))]
    #[test]
    fn to_admin_json_ap_full_shape_alphabetical() {
        assert_eq!(
            router_config().to_admin_json(),
            r#"{"acl_default":"allow","acl_deny":[],"acl_rules":[],"batch_size":65535,"downsampling":[],"lease_ms":10000,"low_pass":[],"max_links":1,"qos":false,"whatami":"router"}"#
        );
    }

    /// R311y473 — `max_links` in the admin body tracks the BUILDER, not a constant.
    ///
    /// A presence assertion alone would pass against a hard-coded `1`, which is also
    /// the default — so the load-bearing leg is that `with_max_links(2)` moves it.
    /// This is the config half of closing transport-multilink's S5 residual: before
    /// it, the aggregation budget was readable only off a startup log line, and
    /// R311y213's "ONE budget source" was a structural claim with no wire surface to
    /// check it against.
    #[cfg(feature = "transport-multilink")]
    #[test]
    fn to_admin_json_max_links_tracks_the_builder() {
        let base = router_config().to_admin_json();
        assert!(
            base.contains(r#""max_links":1"#),
            "the default budget is the single-link 1, rendered: {base}"
        );
        let aggregating = router_config().with_max_links(2).to_admin_json();
        assert!(
            aggregating.contains(r#""max_links":2"#),
            "with_max_links(2) must be GET-observable, not just structurally held: {aggregating}"
        );
    }

    /// R311y473 — the `qos` twin of
    /// [`to_admin_json_max_links_tracks_the_builder`]: the rendered value follows
    /// `with_qos`, and it is this node's OFFER (a session negotiates QoS only when
    /// the peer offers too, so the admin body must not be read as the outcome).
    #[cfg(feature = "transport-qos")]
    #[test]
    fn to_admin_json_qos_tracks_the_builder() {
        assert!(
            router_config().to_admin_json().contains(r#""qos":false"#),
            "the default offer is false (byte-identical to a pre-QoS session)"
        );
        let offered = router_config().with_qos(true).to_admin_json();
        assert!(
            offered.contains(r#""qos":true"#),
            "with_qos(true) must be GET-observable: {offered}"
        );
    }

    #[cfg(all(
        feature = "routing-peer",
        feature = "access-downsampling",
        feature = "access-quota"
    ))]
    #[test]
    fn to_admin_json_renders_downsampling_and_low_pass_rules() {
        use crate::interceptor::InterceptorFlow;
        use crate::linkstate_forward::{
            DownsamplingMessage, DownsamplingRule, LowPassMessage, LowPassRule,
        };
        use std::time::Duration;
        let mut c = router_config();
        c.interceptors.downsampling = vec![DownsamplingRule {
            key_exprs: vec!["mesh/data".to_string()],
            min_interval: Duration::from_millis(250),
            messages: DownsamplingMessage::ALL.to_vec(),
            flows: InterceptorFlow::ALL.to_vec(),
            link_protocols: Vec::new(),
            interfaces: Vec::new(),
        }];
        c.interceptors.low_pass = vec![LowPassRule {
            key_exprs: vec!["mesh/bulk".to_string()],
            max_payload_size: 1024,
            messages: LowPassMessage::ALL.to_vec(),
            flows: InterceptorFlow::ALL.to_vec(),
            link_protocols: Vec::new(),
            interfaces: Vec::new(),
        }];
        let json = c.to_admin_json();
        assert!(
            json.contains(r#""downsampling":[{"key_exprs":["mesh/data"],"min_interval_ms":250}]"#),
            "downsampling rule not rendered: {json}"
        );
        assert!(
            json.contains(r#""low_pass":[{"key_exprs":["mesh/bulk"],"max_payload_size":1024}]"#),
            "low_pass rule not rendered: {json}"
        );
    }

    #[cfg(all(feature = "routing-peer", feature = "access-acl"))]
    #[test]
    fn to_admin_json_renders_full_acl_rules() {
        // R311y54 — the full per-rule dump: subject/flow/messages/permission +
        // key_exprs, keys alphabetical within each rule object. The acl_deny summary
        // still reflects the deny keyexpr (the two views coexist: detail + summary).
        use wz_access_control::{
            AclConfig, AclFlow, AclMessage, AclPolicy, AclRule, Permission, SubjectSelector,
        };
        let mut c = router_config();
        c.interceptors.acl = Some(AclPolicy::new(AclConfig {
            default_permission: Permission::Allow,
            rules: vec![AclRule {
                subject: SubjectSelector::Any,
                key_exprs: vec!["mesh/data".to_string()],
                messages: vec![AclMessage::Put, AclMessage::Delete],
                flow: AclFlow::Ingress,
                permission: Permission::Deny,
                link_protocols: Vec::new(),
                interfaces: Vec::new(),
            }],
        }));
        let json = c.to_admin_json();
        assert!(
            json.contains(
                r#""acl_rules":[{"flow":"ingress","key_exprs":["mesh/data"],"messages":["put","delete"],"permission":"deny","subject":"any"}]"#
            ),
            "acl_rules not rendered: {json}"
        );
        assert!(
            json.contains(r#""acl_deny":["mesh/data"]"#),
            "acl_deny summary not rendered: {json}"
        );
    }

    /// The adminspace permits are a LIVE slice of the config, like the interceptors
    /// — a `set` is visible to the very next read, and the read is what an admin
    /// host does per request. This pins the config half of the live gate; the
    /// behavioural half (a revoke denying the next GET on an already-declared
    /// queryable) is `declare_adminspace_live_permit_source_flips_the_gate_at_runtime`.
    ///
    /// The assertions go through `admin_read_permit` / `admin_write_permit` rather
    /// than the struct fields, because those resolvers are where "the gate compiled
    /// out" is decided: with the gate off the permit is `true` regardless of the
    /// stored value, and asserting the field would claim a denial the build does not
    /// perform.
    #[cfg(feature = "adminspace-core")]
    #[test]
    fn admin_permissions_are_a_live_config_slice() {
        use wz_session_core::adminspace::AdminSpacePermissions;

        // Default = zenoh's PermissionsConf (read true, write false).
        let mut cfg = WzConfig::new();
        assert_eq!(cfg.admin_permissions(), AdminSpacePermissions::default());

        // Setup-time builder.
        cfg = cfg.with_admin_permissions(AdminSpacePermissions {
            read: false,
            write: true,
        });
        assert!(!cfg.admin_permissions().read);
        assert!(cfg.admin_permissions().write);

        // Runtime mutation — the seam a config-write / operator control drives.
        cfg.set_admin_permissions(AdminSpacePermissions {
            read: true,
            write: false,
        });
        assert!(cfg.admin_permissions().read);
        assert!(!cfg.admin_permissions().write);

        // Resolved through the cfg sites both gates use, in BOTH directions.
        #[cfg(feature = "adminspace-read")]
        {
            assert!(crate::admin_read_permit(&cfg.admin_permissions()));
            cfg.set_admin_permissions(AdminSpacePermissions {
                read: false,
                write: false,
            });
            assert!(!crate::admin_read_permit(&cfg.admin_permissions()));
        }
        #[cfg(feature = "adminspace-write")]
        {
            assert!(!crate::admin_write_permit(&cfg.admin_permissions()));
            cfg.set_admin_permissions(AdminSpacePermissions {
                read: false,
                write: true,
            });
            assert!(crate::admin_write_permit(&cfg.admin_permissions()));
        }
    }
}
