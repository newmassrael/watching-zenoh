// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The spans of upstream's routing code, opened where a session of this node registers what a
//! face told it.
//!
//! The router forwarder opens them for the declarations it registers
//! (`router_forward::routing_spans`); a client or a peer node has no forwarder, and registers
//! what its link says in the observer of its session (`RemoteSubscriberRegistry` and
//! `RemoteQueryableRegistry`), which hands each declaration to the sinks installed on it. This
//! module is what such a sink calls. Upstream's `register_subscriber{self, res}` /
//! `register_queryable{self, res}` run in the hat of the node's north region inside
//! `demux{zid, src}`, the `zid` being the node's own
//! (`zenoh/src/net/primitives/demux.rs` @ `tracing::debug_span!(`), and its test of its regions
//! counts those events by that zid (`zenoh/tests/regions/main.rs` @ `pub mod predicates_ext`).
//!
//! The crate that owns the registries stays free of `tracing` (it builds without an allocator
//! or a standard library); the runtime, which has both, is where the span is opened.

/// The session of the node `zid_hex` registered a declaration of `keyexpr` that its link told
/// it: a subscriber, or a queryable when `queryable`. The one event is upstream's `ret` of the
/// instrumented function.
pub(crate) fn registered(zid_hex: &str, queryable: bool, keyexpr: &str) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    let _demux = tracing::debug_span!("demux", zid = %zid_hex, src = 0u64).entered();
    // `self` is recorded through `Display`, as the router's spans record the region (upstream's
    // `region` is not a string): its test reads a debug object, which a plain `&str` is not.
    let _register = if queryable {
        tracing::debug_span!("register_queryable", self = %"north", res = %keyexpr).entered()
    } else {
        tracing::debug_span!("register_subscriber", self = %"north", res = %keyexpr).entered()
    };
    tracing::debug!(r#return = true);
}
