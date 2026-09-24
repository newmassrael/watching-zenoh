// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2829 (§5.23 `adminspace-core`) — an MCU node ANSWERS upstream's admin GET.
//!
//! A host reads a zenoh node's state with a GET on `@/<zid>/<whatami>`: the
//! reply is the node's `local_data` JSON, whose `sessions` array lists the
//! peers it holds a session with
//! (`zenoh/src/net/runtime/adminspace.rs` @ `transports.push(transport_unicast_to_json(&transport));`,
//! each entry of the array the reply carries as `sessions`).
//! For ZA-2898 that is how a host reads back the
//! effect of a `connect/endpoints` write, and how it tells a node that is
//! alive and refused from one that did not answer at all.
//!
//! Nothing new answers it. [`crate::admin_status::host_admin_queryable`]
//! registers, on the node's application-layer observer, a queryable for
//! `@/<zid>/<whatami>/**` — the key upstream declares its admin queryable
//! on — and hands every query to `wz_session_core::adminspace::
//! answer_admin_query`, the answerer the AP's Session and routing hosts
//! already share, so an MCU's reply is byte-for-byte what theirs would be for
//! the same state. The MCU runs with a heap, so there is no reason to write a
//! second emitter for it.
//!
//! What the node supplies is its state: [`crate::admin_status::NodeStatus`]
//! holds the sessions (the dial layer updates them) and the read permit, and a
//! [`crate::admin_status::ConfigView`] — the connection control, when the node
//! hosts the write surface — supplies the `config` leg, so a host can GET
//! `@/<zid>/<whatami>/config` and read back the endpoint list it wrote.

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use critical_section::Mutex;
use wz_session_core::adminspace::{
    admin_queryable_key, answer_admin_query, AdminAnswerCtx, AdminSession,
};
use wz_session_core::observer::ApplicationLayerObserver;

/// What the `config` leg of the admin GET answers from. The node's
/// connection control implements it when the write surface is compiled in;
/// a node without one answers an empty object.
pub trait ConfigView {
    /// Write this node's config document, as JSON, into `out`.
    fn write_config_json(&self, out: &mut String);
}

/// Who the node is, as the `local_data` leg reports it.
pub struct NodeIdentity {
    /// The node's zid in zenoh hex form.
    pub zid_hex: String,
    /// The node's role string (`WhatAmI::to_str`).
    pub whatami: &'static str,
    /// The version string the node reports.
    pub version: String,
    /// The locators the node listens on.
    pub locators: Vec<String>,
}

struct StatusState {
    sessions: Vec<AdminSession>,
    permit_read: bool,
}

/// The node state its admin GET reports, kept where both the session layer
/// and the queryable reach it.
pub struct NodeStatus {
    state: Mutex<RefCell<StatusState>>,
}

impl NodeStatus {
    /// No sessions yet. `permit_read` is the node's
    /// `adminspace.permissions.read`; upstream's default is `true`.
    ///
    /// `const`, so firmware can place it in a `static`.
    pub const fn new(permit_read: bool) -> Self {
        Self {
            state: Mutex::new(RefCell::new(StatusState {
                sessions: Vec::new(),
                permit_read,
            })),
        }
    }

    /// Replace the sessions the node reports.
    pub fn set_sessions(&self, sessions: Vec<AdminSession>) {
        critical_section::with(|cs| self.state.borrow(cs).borrow_mut().sessions = sessions);
    }

    /// Change the read permit at runtime, as upstream's
    /// `adminspace/permissions/read` does.
    pub fn set_read_permit(&self, permit: bool) {
        critical_section::with(|cs| self.state.borrow(cs).borrow_mut().permit_read = permit);
    }

    fn snapshot(&self) -> (bool, Vec<AdminSession>) {
        critical_section::with(|cs| {
            let s = self.state.borrow(cs).borrow();
            (s.permit_read, s.sessions.clone())
        })
    }
}

/// Register the node's admin queryable on `observer`.
///
/// Every GET under `@/<zid>/<whatami>` is answered by `answer_admin_query`
/// from `status` and, for the `config` leg, from `config` (an empty object
/// when `None`). A denied read answers nothing, and the query is still
/// terminated, which is upstream's behaviour.
pub fn host_admin_queryable(
    observer: &mut ApplicationLayerObserver,
    identity: NodeIdentity,
    status: &'static NodeStatus,
    config: Option<&'static (dyn ConfigView + Sync)>,
) {
    let pattern = admin_queryable_key(&identity.zid_hex, identity.whatami);
    observer.queryables.register(pattern, move |query, out| {
        let (read, sessions) = status.snapshot();
        let mut config_json = String::new();
        match config {
            Some(view) => view.write_config_json(&mut config_json),
            None => config_json.push_str("{}"),
        }
        let ctx = AdminAnswerCtx {
            zid_hex: &identity.zid_hex,
            whatami: identity.whatami,
            version: &identity.version,
            locators: &identity.locators,
            read,
            stats: None,
        };
        let _ = answer_admin_query(query, out, &ctx, &sessions, &[], &[], &config_json);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::rc::Rc;
    use alloc::vec;

    use wz_codecs::query::Query;
    use wz_codecs::request::{Request, RequestVariant};
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;
    use wz_link_lwip::ipv4_addr_loopback;
    use wz_link_lwip::rx_sockets::bind_session_rx;
    use wz_runtime_coop::{ClockSource, CoopRuntime, CoopTime};
    use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
    use wz_session_core::link::BoxedLinkDriver;
    use wz_session_core::network_message::NetworkMessage;
    use wz_session_core::session_actions::SessionLinkActions;
    use wz_session_core::session_init_params::SessionInitParams;
    use wz_session_core::signing_key::SigningKey;
    use wz_session_core::WhatAmI;

    use crate::app_layer::dispatch_to;
    use crate::driver::{LwipUdpDriver, SharedSessionSocket};

    #[derive(Clone, Default)]
    struct FrozenClock;
    impl ClockSource for FrozenClock {
        fn now_us(&self) -> u64 {
            0
        }
    }

    struct FixedConfig;
    impl ConfigView for FixedConfig {
        fn write_config_json(&self, out: &mut String) {
            out.push_str(r#"{"connect":{"endpoints":["tcp/10.0.0.9:7447"]}}"#);
        }
    }

    fn get(key: &str, rid: u64) -> DriverLoopOutcome {
        let request = Request {
            rid,
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                    id: 0,
                    suffix_len: Some(key.len() as u64),
                    suffix: Some(key),
                }),
            },
            body: RequestVariant::CodecZenohQuery(Query::default()),
            ..Request::default()
        };
        DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Request(Box::new(
                request.try_into_owned().unwrap(),
            ))],
            has_ext: false,
            extensions: Vec::new(),
        }
    }

    /// The node answers upstream's admin GET on a real lwIP link with the
    /// shared answerer: the root leg carries `sessions` and the peer the status
    /// holds, the `config` leg carries what the config view wrote, and a denied
    /// read puts neither on the wire. The CONTROL is the same GET before the
    /// queryable exists.
    #[test]
    fn the_admin_get_is_answered_from_the_nodes_status() {
        static STATUS: NodeStatus = NodeStatus::new(true);
        static CONFIG: FixedConfig = FixedConfig;

        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let (node_port, peer_port): (u16, u16) = (7481, 7482);
        let node_socket: SharedSessionSocket = Rc::new(RefCell::new(
            bind_session_rx(&link, node_port).expect("bind node socket"),
        ));
        let peer_socket: SharedSessionSocket = Rc::new(RefCell::new(
            bind_session_rx(&link, peer_port).expect("bind peer socket"),
        ));
        let driver = Rc::new(LwipUdpDriver::new(
            node_socket,
            ipv4_addr_loopback(),
            peer_port,
        ));
        let peer = LwipUdpDriver::new(peer_socket, ipv4_addr_loopback(), node_port);
        let runtime = CoopRuntime::new(FrozenClock);
        let clock = CoopTime::new(&runtime);
        let sink: Rc<dyn BoxedLinkDriver> = driver.clone();
        let actions =
            SessionLinkActions::<CoopRuntime<FrozenClock>, CoopTime<FrozenClock>>::new_generic(
                sink,
                SessionInitParams {
                    version: 0x05,
                    whatami: WhatAmI::Peer,
                    zid: vec![0xa1, 0xb2],
                    seq_num_res: 2,
                    req_id_res: 2,
                    batch_size: 1024,
                    lease_ms: 10_000,
                    initial_sn: 0,
                    cookie: vec![0u8; 16],
                    cookie_signing_key: SigningKey::new(vec![7u8; 32]).expect("key"),
                },
                clock,
            );
        let observer = Rc::new(RefCell::new(ApplicationLayerObserver::new()));
        let mut on_event = dispatch_to(observer.clone(), actions.clone());

        // Whether any datagram the peer received carries `needle`.
        let wire_has = |needle: &[u8]| {
            link.poll_loopback();
            link.check_timeouts();
            let mut seen = false;
            while let Some(dg) = peer.try_recv() {
                seen |= dg.data.windows(needle.len()).any(|w| w == needle);
            }
            seen
        };

        // CONTROL: no queryable, no local_data on the wire.
        on_event(IterationEvent::Poll(&get("@/b2a1/peer", 1)));
        std::assert!(!wire_has(b"\"sessions\""));

        STATUS.set_sessions(vec![AdminSession {
            peer_zid_hex: String::from("c3d4"),
            whatami: Some(String::from("router")),
            ..AdminSession::default()
        }]);
        host_admin_queryable(
            &mut observer.borrow_mut(),
            NodeIdentity {
                zid_hex: String::from("b2a1"),
                whatami: "peer",
                version: String::from("wz-test"),
                locators: vec![String::from("udp/127.0.0.1:7481")],
            },
            &STATUS,
            Some(&CONFIG),
        );

        on_event(IterationEvent::Poll(&get("@/b2a1/peer", 2)));
        std::assert!(wire_has(b"\"sessions\""), "local_data left on the wire");

        on_event(IterationEvent::Poll(&get("@/b2a1/peer", 3)));
        std::assert!(wire_has(b"c3d4"), "the status's peer is in sessions");

        on_event(IterationEvent::Poll(&get("@/b2a1/peer/config", 4)));
        std::assert!(wire_has(b"tcp/10.0.0.9:7447"), "the config leg read back");

        STATUS.set_read_permit(false);
        on_event(IterationEvent::Poll(&get("@/b2a1/peer", 5)));
        std::assert!(!wire_has(b"\"sessions\""), "a denied read answers nothing");
    }
}
