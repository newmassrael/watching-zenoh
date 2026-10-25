// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R3014 — the HOST facets of multicast, witnessed with wz's own two drivers and
//! nothing else: a datagram that `UdpDriver::bind_multicast_tx` sends to a group
//! reaches a `UdpDriver::bind_multicast` member on the same host.
//!
//! The fuller multicast tests (`scouting_multicast_loopback`,
//! `multicast_pubsub_loopback`) exercise wz's scouting and session logic over a
//! group and say nothing OS-specific that this does not; they also build raw
//! sockets of their own, so they cannot be pointed at another interface without
//! editing each one. This is the narrow witness of what DOES differ per host,
//! the part of the multicast plane that is a conversation with the kernel: the
//! bind with port reuse, the membership, the loopback, the egress pin, the send.
//!
//! Which interface carries it is the one thing that differs by host, and that is
//! a MEASUREMENT, not a preference. The hosted runners were asked, before wz
//! touched anything, what a plain socket does with a send to `224.0.0.224`:
//!
//!   * Linux: a send with no interface pinned works, and so does one pinned to
//!     the default route's address.
//!   * Windows: the same two work. A send pinned to `127.0.0.1` FAILS with
//!     `WinError 10051` (the loopback adapter does not carry multicast), so
//!     loopback is not an option there and the default interface is the witness.
//!   * macOS: a send with no interface pinned FAILS with `EHOSTUNREACH`, and so
//!     does one pinned to the default route's address, although the routing table
//!     holds a multicast route for exactly that interface. Only a send pinned to
//!     `127.0.0.1` works. A plain Python process failed the same way, so it is
//!     not wz: it is macOS's local-network privacy denying the real interface to a
//!     process the runner's daemon spawned. Upstream, which leaves the interface
//!     to the OS the same way, would be denied identically, and the pin that
//!     reaches the network is the one thing a hosted macOS runner cannot grant.
//!
//! So macOS uses `lo0` and the other hosts keep the default, and what this does
//! NOT prove on macOS is multicast over a real interface; no hosted runner can.
//!
//! Opt-in (`#[ignore]`), like every multicast e2e here: whether a host can join
//! and loop a group is an environment fact, and the lane that runs it says so.

#![cfg(all(
    feature = "transport-multicast",
    feature = "locator-iface",
    feature = "transport-link-udp"
))]

use std::net::Ipv4Addr;
use std::time::Duration;

use wz_runtime_tokio::policy::MulticastLoopback;
use wz_runtime_tokio::{LinkDriver, LinkEvent, McastSocketConfig, Reliability, TxFrame, UdpDriver};

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 224);
// A multicast group is machine-wide, so two tests on one (group, port) read each
// other's datagrams whenever the scheduler overlaps them. This port is in the
// 17xxx range the scouting tests moved to after exactly that collision, and no
// other test binds it: `multicast_address_collision_gate.py` is what says so, and
// it refused the first choice here (7453, already the qos test's).
const PORT: u16 = 17490;
const PAYLOAD: &[u8] = b"wz-multicast-host-roundtrip";
// The `multicast-loopback` policy's `off` witness has its own (group, port) for the same
// reason: it must not read the datagrams of the test above, nor they its own.
const PORT_LOOPBACK_OFF: u16 = 17491;
const QUIET_PAYLOAD: &[u8] = b"wz-multicast-host-loopback-off";
const CONTROL_PAYLOAD: &[u8] = b"wz-multicast-host-loopback-control";

/// The interface this host's witness uses; see the module doc for the measurement
/// behind each arm.
fn host_iface() -> Option<&'static str> {
    if cfg!(target_os = "macos") {
        Some("lo0")
    } else {
        None
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "multicast loopback e2e; opt-in like Layer M, run by the Platform lane"]
async fn a_datagram_sent_to_the_group_reaches_a_member_on_the_same_host() {
    // The `multicast-loopback` policy named `on`: the witness is that a member of the
    // group on the sender's own host hears it, which is the operating system's setting
    // on most hosts and is not on every one.
    let cfg = McastSocketConfig {
        iface: host_iface(),
        loopback: MulticastLoopback::On,
        ..McastSocketConfig::default()
    };

    let mut member = UdpDriver::bind_multicast(GROUP, PORT, cfg)
        .await
        .expect("a group member binds and joins on this host");
    let mut sender = UdpDriver::bind_multicast_tx(GROUP, PORT, cfg)
        .await
        .expect("a send-only group socket binds on this host");

    // A pin is a setsockopt, and one that returned Ok is not yet evidence: the
    // value the kernel kept is. Read back what the sender leaves by.
    if host_iface().is_some() {
        assert_eq!(
            sender
                .multicast_egress_v4()
                .expect("the kernel reports the egress interface"),
            Ipv4Addr::LOCALHOST,
            "the sender must be pinned to the interface the host witness uses"
        );
    }

    sender
        .send(&TxFrame { bytes: PAYLOAD }, Reliability::BestEffort)
        .await
        .expect("a send to the group leaves this host's interface");

    // Another member of the group may speak first on a shared port, so read until
    // OUR datagram arrives or the budget ends; a datagram that is not ours is not
    // a failure, only not the answer.
    let arrived = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let LinkEvent::Rx(frame) = member.poll_event().await {
                if frame.bytes.as_slice() == PAYLOAD {
                    return;
                }
            }
        }
    })
    .await;
    assert!(
        arrived.is_ok(),
        "the datagram a member's own host sent to the group did not come back to it"
    );
}

/// The `multicast-loopback` policy named `off`, against the control that makes the
/// absence mean something. Two senders on this host send to one group, a member of it
/// listens: the sender whose loopback is `off` is not heard, and the one whose loopback is
/// `on` is. The member hearing the control is what shows it was able to hear the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "multicast loopback e2e; opt-in like Layer M, run by the Platform lane"]
async fn a_sender_whose_loopback_is_off_is_not_heard_by_a_member_on_its_host() {
    let member_cfg = McastSocketConfig {
        iface: host_iface(),
        loopback: MulticastLoopback::On,
        ..McastSocketConfig::default()
    };
    let mut member = UdpDriver::bind_multicast(GROUP, PORT_LOOPBACK_OFF, member_cfg)
        .await
        .expect("a group member binds and joins on this host");
    let mut quiet = UdpDriver::bind_multicast_tx(
        GROUP,
        PORT_LOOPBACK_OFF,
        McastSocketConfig {
            loopback: MulticastLoopback::Off,
            ..member_cfg
        },
    )
    .await
    .expect("a send-only group socket with loopback off binds on this host");
    let mut loud = UdpDriver::bind_multicast_tx(GROUP, PORT_LOOPBACK_OFF, member_cfg)
        .await
        .expect("a send-only group socket with loopback on binds on this host");

    // The quiet sender goes first, so a datagram it did deliver would be read before the
    // control behind it on the same host.
    quiet
        .send(
            &TxFrame {
                bytes: QUIET_PAYLOAD,
            },
            Reliability::BestEffort,
        )
        .await
        .expect("a send to the group leaves this host's interface");
    loud.send(
        &TxFrame {
            bytes: CONTROL_PAYLOAD,
        },
        Reliability::BestEffort,
    )
    .await
    .expect("a send to the group leaves this host's interface");

    let mut heard_the_quiet_one = false;
    let control = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let LinkEvent::Rx(frame) = member.poll_event().await {
                if frame.bytes.as_slice() == QUIET_PAYLOAD {
                    heard_the_quiet_one = true;
                } else if frame.bytes.as_slice() == CONTROL_PAYLOAD {
                    return;
                }
            }
        }
    })
    .await;
    assert!(
        control.is_ok(),
        "the control datagram, sent with loopback on, did not reach the member: the host \
         cannot witness the policy"
    );
    // A datagram still in flight after the control would be as much a delivery.
    let _ = tokio::time::timeout(Duration::from_millis(300), async {
        loop {
            if let LinkEvent::Rx(frame) = member.poll_event().await {
                heard_the_quiet_one |= frame.bytes.as_slice() == QUIET_PAYLOAD;
            }
        }
    })
    .await;
    assert!(
        !heard_the_quiet_one,
        "a sender whose multicast-loopback policy is off was heard by a member on its own host"
    );
}
