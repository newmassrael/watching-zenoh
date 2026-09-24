// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2828 (§5.23 `adminspace-write`) — an MCU node HOSTS upstream's
//! `connect/endpoints` config write.
//!
//! `wz_session_core::admin_connect` decides a write; this module is where a
//! running node receives one. It registers, on the node's application-layer
//! observer (`crate::app_layer`), a subscriber for the node's own config
//! space, `@/<zid>/<whatami>/config/**` — the key upstream's admin space
//! subscribes to — and applies each verdict to a
//! [`crate::admin_host::ConnectControl`] the rest of
//! the firmware reads: the dial layer takes the endpoint list from it, and a
//! host can change the permit on it.
//!
//! ## Why the control is `'static`
//!
//! A subscriber callback must be `Send` (the observer's registry is shared
//! with the AP, where it is), and the MCU session bundle is `Rc` because
//! `alloc::sync::Arc` does not exist on ARMv6-M. A node's connection control
//! lives as long as the firmware does, so it is a `&'static` behind a
//! `critical_section::Mutex`: `Send + Sync` on every target, no `Arc`, and the
//! same primitive the cooperative runtime already locks with.
//!
//! ## What a refused write changes: nothing
//!
//! The verdict is decided into scratch storage, and only `Replace` or `Remove`
//! touches the live list. A denied, malformed or over-long write leaves the
//! node holding exactly the sessions it held;
//! [`crate::admin_host::ConnectControl::last_outcome`] is where the refusal
//! can be read, since upstream only logs it.

use alloc::string::String;
use core::cell::RefCell;

use critical_section::Mutex;
use wz_session_core::admin_config_space::write_config_space_pattern;
use wz_session_core::admin_connect::{
    parse_connect_endpoints_write, ConfigWriteBody, ConnectEndpoints, ConnectWriteOutcome,
};
use wz_session_core::observer::ApplicationLayerObserver;
use wz_session_core::sample_kind::SampleKind;
use wz_session_core::sink::SampleView;

struct State {
    permit_write: bool,
    live: ConnectEndpoints,
    generation: u32,
    last: Option<ConnectWriteOutcome>,
}

/// A node's runtime connection control: the endpoints it should hold
/// sessions with, and whether a remote config write may change them.
pub struct ConnectControl {
    state: Mutex<RefCell<State>>,
}

impl ConnectControl {
    /// A control with no endpoints yet. `permit_write` is the node's
    /// `adminspace.permissions.write`; upstream's default is `false`.
    ///
    /// `const`, so firmware can place it in a `static`.
    pub const fn new(permit_write: bool) -> Self {
        Self {
            state: Mutex::new(RefCell::new(State {
                permit_write,
                live: ConnectEndpoints::new(),
                generation: 0,
                last: None,
            })),
        }
    }

    /// Change the write permit at runtime, as upstream's
    /// `adminspace/permissions/write` does.
    pub fn set_write_permit(&self, permit: bool) {
        critical_section::with(|cs| self.state.borrow(cs).borrow_mut().permit_write = permit);
    }

    /// The endpoint list and the generation it was written at. The generation
    /// moves on every applied write, so a dial layer that remembers the last
    /// one it acted on knows when to act again.
    pub fn endpoints(&self) -> (u32, ConnectEndpoints) {
        critical_section::with(|cs| {
            let s = self.state.borrow(cs).borrow();
            (s.generation, s.live.clone())
        })
    }

    /// The verdict on the most recent write this node received, applied or
    /// not. `None` before the first.
    pub fn last_outcome(&self) -> Option<ConnectWriteOutcome> {
        critical_section::with(|cs| self.state.borrow(cs).borrow().last.clone())
    }

    /// A permitted PUT of `payload` on this node's own key, for tests of the
    /// layers that read the control.
    #[cfg(test)]
    pub(crate) fn apply_for_test(&self, payload: &[u8]) {
        self.apply(
            "a1b2",
            "peer",
            "@/a1b2/peer/config/connect/endpoints",
            ConfigWriteBody::Put(payload),
        );
    }

    fn apply(&self, zid_hex: &str, whatami: &str, keyexpr: &str, body: ConfigWriteBody<'_>) {
        let mut scratch = ConnectEndpoints::new();
        critical_section::with(|cs| {
            let mut s = self.state.borrow(cs).borrow_mut();
            let outcome = parse_connect_endpoints_write(
                zid_hex,
                whatami,
                keyexpr,
                body,
                s.permit_write,
                &mut scratch,
            );
            match outcome {
                ConnectWriteOutcome::Replace => {
                    s.live = scratch;
                    s.generation = s.generation.wrapping_add(1);
                }
                ConnectWriteOutcome::Remove => {
                    s.live.clear();
                    s.generation = s.generation.wrapping_add(1);
                }
                _ => {}
            }
            s.last = Some(outcome);
        });
    }
}

/// R2829 — the control IS the config the `config` leg of the admin GET
/// reports, so a host that wrote `connect/endpoints` can read it back at
/// `@/<zid>/<whatami>/config`. Keys are spelled as upstream's config document
/// spells them; only the part this node holds is present.
#[cfg(feature = "adminspace-core")]
impl crate::admin_status::ConfigView for ConnectControl {
    fn write_config_json(&self, out: &mut String) {
        let (permit_write, list) = critical_section::with(|cs| {
            let s = self.state.borrow(cs).borrow();
            (s.permit_write, s.live.clone())
        });
        out.push_str(r#"{"connect":{"endpoints":"#);
        push_connect_endpoints(&list, out);
        out.push_str(r#"},"adminspace":{"permissions":{"write":"#);
        out.push_str(if permit_write { "true" } else { "false" });
        out.push_str("}}}");
    }
}

/// R2846 (ZA-2929) — the control is also what `status/connect` reads: the
/// write permit, and the verdict on the last write, so a refused write is
/// reported in the node's own words instead of only leaving the list as it
/// was. Each verdict is its variant's name; a malformed value adds where the
/// parse stopped and what it expected there.
#[cfg(feature = "adminspace-core")]
impl crate::admin_status::ConnectStatusSource for ConnectControl {
    fn write_permit(&self) -> bool {
        critical_section::with(|cs| self.state.borrow(cs).borrow().permit_write)
    }

    fn write_last_write_json(&self, out: &mut String) {
        use core::fmt::Write as _;
        let verdict = match self.last_outcome() {
            None => {
                out.push_str("null");
                return;
            }
            Some(ConnectWriteOutcome::Malformed(e)) => {
                out.push_str(r#"{"verdict":"malformed","offset":"#);
                let _ = write!(out, "{}", e.offset);
                out.push_str(r#","expected":"#);
                wz_session_core::json::escape_into(e.expected, out);
                out.push('}');
                return;
            }
            Some(ConnectWriteOutcome::NotThisSpace) => "not_this_space",
            Some(ConnectWriteOutcome::AmbiguousSpaceAddress) => "ambiguous_space_address",
            Some(ConnectWriteOutcome::Denied) => "denied",
            Some(ConnectWriteOutcome::OtherKey) => "other_key",
            Some(ConnectWriteOutcome::TooMany) => "too_many",
            Some(ConnectWriteOutcome::EndpointTooLong) => "endpoint_too_long",
            Some(ConnectWriteOutcome::NotAnEndpoint) => "not_an_endpoint",
            Some(ConnectWriteOutcome::Replace) => "replace",
            Some(ConnectWriteOutcome::Remove) => "remove",
        };
        out.push_str(r#"{"verdict":"#);
        wz_session_core::json::escape_into(verdict, out);
        out.push('}');
    }
}

/// R2841 — the endpoint list as upstream serializes its `EndPoints`: a bare
/// entry as a string, a group as `{"strategy":…,"locators":[…]}` (the derive on
/// its `Locators`, strategy in camelCase), so what was written reads back in
/// the form it was written, an empty group included.
#[cfg(feature = "adminspace-core")]
fn push_connect_endpoints(list: &[wz_session_core::admin_connect::ConnectEntry], out: &mut String) {
    // R2843 — the entry type is named HERE, not in the module's `use` list:
    // this function is its only user and exists only under `adminspace-core`,
    // so a module-scope import was unused in an `adminspace-write`-only build
    // and Layer C1m failed it under `-D warnings` (hosted run 35989144794).
    use wz_session_core::json::{escape_into, push_str_array};
    out.push('[');
    let mut i = 0;
    while i < list.len() {
        if i > 0 {
            out.push(',');
        }
        match list[i].group {
            None => {
                escape_into(list[i].as_str(), out);
                i += 1;
            }
            Some(group) => {
                out.push_str(r#"{"strategy":"#);
                escape_into(group.strategy.as_str(), out);
                out.push_str(r#","locators":"#);
                let start = i;
                while i < list.len() && list[i].group.map(|g| g.index) == Some(group.index) {
                    i += 1;
                }
                push_str_array(
                    list[start..i]
                        .iter()
                        .map(|e| e.as_str())
                        .filter(|s| !s.is_empty()),
                    out,
                );
                out.push('}');
            }
        }
    }
    out.push(']');
}

/// Subscribe `observer` to the config space of the node `zid_hex` /
/// `whatami` and apply every write it receives to `control`.
///
/// A PUT is decided as a replace and a DEL as a remove, the two sample kinds
/// there are.
pub fn host_connect_writes(
    observer: &mut ApplicationLayerObserver,
    zid_hex: &str,
    whatami: &str,
    control: &'static ConnectControl,
) {
    let mut pattern = String::new();
    // Writing into a `String` cannot fail.
    let _ = write_config_space_pattern(&mut pattern, zid_hex, whatami);
    let zid_hex = String::from(zid_hex);
    let whatami = String::from(whatami);
    observer
        .subscribers
        .register(pattern, move |sample: &dyn SampleView| {
            let body = match sample.kind() {
                SampleKind::Put => ConfigWriteBody::Put(sample.payload()),
                SampleKind::Del => ConfigWriteBody::Del,
            };
            control.apply(&zid_hex, &whatami, sample.keyexpr(), body);
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec;
    use alloc::vec::Vec;

    use wz_codecs::push::{Push, PushVariant};
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;
    use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
    use wz_session_core::network_message::NetworkMessage;

    const ZID: &str = "a1b2";
    const KEY: &str = "@/a1b2/peer/config/connect/endpoints";

    fn put(key: &str, payload: &[u8]) -> NetworkMessage {
        let mut push = Push {
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                    id: 0,
                    suffix_len: Some(key.len() as u64),
                    suffix: Some(key),
                }),
            },
            ..Push::default()
        };
        if let PushVariant::CodecZenohMsgPut(ref mut msg) = push.body {
            msg.payload_len = payload.len() as u64;
            msg.payload = payload;
        }
        NetworkMessage::Push(Box::new(push.try_into_owned().unwrap()))
    }

    fn deliver(observer: &mut ApplicationLayerObserver, message: NetworkMessage) {
        let outcome = DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![message],
            has_ext: false,
            extensions: Vec::new(),
        };
        observer.dispatch_event(IterationEvent::Poll(&outcome));
    }

    fn live(control: &ConnectControl) -> (u32, Vec<String>) {
        let (generation, list) = control.endpoints();
        (
            generation,
            list.iter().map(|e| String::from(e.as_str())).collect(),
        )
    }

    /// The node hosts the write exactly as upstream gates it: refused under the
    /// default permit (and the live list untouched), applied once granted, and a
    /// later refused write leaves the applied list standing.
    #[test]
    fn a_config_write_reaches_the_control_through_the_nodes_subscriber() {
        static CONTROL: ConnectControl = ConnectControl::new(false);
        let mut observer = ApplicationLayerObserver::new();
        host_connect_writes(&mut observer, ZID, "peer", &CONTROL);

        // Default permit: denied, nothing moves.
        deliver(&mut observer, put(KEY, br#"["tcp/10.0.0.9:7447"]"#));
        std::assert_eq!(CONTROL.last_outcome(), Some(ConnectWriteOutcome::Denied));
        std::assert_eq!(live(&CONTROL), (0, Vec::new()));

        // Granted: the list is replaced and the generation moves.
        CONTROL.set_write_permit(true);
        deliver(&mut observer, put(KEY, br#"["tcp/10.0.0.9:7447"]"#));
        std::assert_eq!(CONTROL.last_outcome(), Some(ConnectWriteOutcome::Replace));
        std::assert_eq!(live(&CONTROL), (1, vec![String::from("tcp/10.0.0.9:7447")]));

        // A malformed write is refused and the applied list stands.
        deliver(&mut observer, put(KEY, b"[7]"));
        std::assert!(matches!(
            CONTROL.last_outcome(),
            Some(ConnectWriteOutcome::Malformed(_))
        ));
        std::assert_eq!(live(&CONTROL), (1, vec![String::from("tcp/10.0.0.9:7447")]));

        // Another node's config space never reaches this subscriber.
        deliver(
            &mut observer,
            put("@/ffff/peer/config/connect/endpoints", b"[]"),
        );
        std::assert!(matches!(
            CONTROL.last_outcome(),
            Some(ConnectWriteOutcome::Malformed(_))
        ));
    }

    /// R2846 (ZA-2929) — the verdict on the last write, as `status/connect`
    /// reports it: `null` before the first, each refusal by its own name, a
    /// malformed value with where it stopped and what it expected.
    #[cfg(feature = "adminspace-core")]
    #[test]
    fn the_last_write_is_reported_in_the_nodes_words() {
        use crate::admin_status::ConnectStatusSource;

        static CONTROL: ConnectControl = ConnectControl::new(false);
        let mut observer = ApplicationLayerObserver::new();
        host_connect_writes(&mut observer, ZID, "peer", &CONTROL);
        let last = || {
            let mut out = String::new();
            CONTROL.write_last_write_json(&mut out);
            out
        };

        // Before any write there is no verdict to report.
        std::assert_eq!(last(), "null");
        // Writes off: the refusal names itself, and the permit reads false.
        deliver(&mut observer, put(KEY, br#"["tcp/10.0.0.9:7447"]"#));
        std::assert_eq!(last(), r#"{"verdict":"denied"}"#);
        std::assert!(!CONTROL.write_permit());
        // A malformed value says where the parse stopped and what it wanted.
        CONTROL.set_write_permit(true);
        deliver(&mut observer, put(KEY, b"[7]"));
        std::assert_eq!(
            last(),
            r#"{"verdict":"malformed","offset":1,"expected":"an endpoint string or a locators object"}"#
        );
        deliver(&mut observer, put(KEY, br#"["tcp/10.0.0.9:7447"]"#));
        std::assert_eq!(last(), r#"{"verdict":"replace"}"#);
    }

    /// R2829 — what the admin GET's `config` leg reads back is the list the
    /// control holds, in upstream's key spelling, and it follows a write.
    #[cfg(feature = "adminspace-core")]
    #[test]
    fn the_config_leg_reads_back_the_written_list() {
        use crate::admin_status::ConfigView;

        static CONTROL: ConnectControl = ConnectControl::new(true);
        let mut observer = ApplicationLayerObserver::new();
        host_connect_writes(&mut observer, ZID, "peer", &CONTROL);

        let read = || {
            let mut out = String::new();
            CONTROL.write_config_json(&mut out);
            out
        };
        std::assert_eq!(
            read(),
            r#"{"connect":{"endpoints":[]},"adminspace":{"permissions":{"write":true}}}"#
        );
        deliver(&mut observer, put(KEY, br#"["tcp/10.0.0.9:7447"]"#));
        std::assert_eq!(
            read(),
            r#"{"connect":{"endpoints":["tcp/10.0.0.9:7447"]},"adminspace":{"permissions":{"write":true}}}"#
        );

        // R2841 — groups read back in upstream's object form, empty ones too.
        deliver(
            &mut observer,
            put(
                KEY,
                br#"["tcp/a:1", { strategy: "allOf", locators: ["tcp/b:1", "tcp/b:2"] },
                    { strategy: "oneOf", locators: [] }]"#,
            ),
        );
        std::assert_eq!(
            read(),
            r#"{"connect":{"endpoints":["tcp/a:1",{"strategy":"allOf","locators":["tcp/b:1","tcp/b:2"]},{"strategy":"oneOf","locators":[]}]},"adminspace":{"permissions":{"write":true}}}"#
        );
    }
}
