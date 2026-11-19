// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A group member's fragment is staged from where its datagram lies on the
//! profile that keeps no heap (`dispatch_multicast_inbound_reassembling`, which
//! takes the in-place ingest when the library is built without `alloc`).
//!
//! An integration test and not a unit test of `multicast_rx`: the library
//! compiles without `alloc` while this test crate keeps `std`, so the one
//! build that reaches the in-place path is not held hostage by the crate's
//! unit-test modules, which name the heap unconditionally. The entry point is
//! the public one a drive loop that keeps no heap calls.
//!
//! Compiles empty with `alloc` (the owned ingest is the heap profile's, and its
//! own tests cover it) and without the multicast receive and fragmentation
//! features.
#![cfg(all(
    not(feature = "alloc"),
    feature = "storage-profile",
    feature = "session-multicast",
    feature = "codec-join",
    feature = "codec-frame",
    feature = "codec-close",
    feature = "reassembly",
    feature = "transport-fragmentation"
))]

use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use wz_codecs::whatami::WhatAmI;
use wz_codecs::wire_const::{FLAG_T_FRAGMENT_M, FLAG_T_FRAGMENT_R, T_MID_FRAGMENT};
use wz_session_core::driver_loop::{IterationEvent, ReassemblyDropReason};
use wz_session_core::extfragment::FRAGMENT_FIRST_EXT_ID;
use wz_session_core::multicast_dispatch::{MulticastConfig, MulticastDispatcher};
use wz_session_core::multicast_join::{encode_join_into_slice, JOIN_MAX_BYTES};
use wz_session_core::multicast_params::{zid_vec, GroupJoinRule, MulticastParams};
use wz_session_core::multicast_rx::dispatch_multicast_inbound_reassembling;
use wz_session_core::reassembly_dispatch::{ReassemblyConfig, ReassemblyDispatcher};
use wz_session_core::session_init_params::{LinkRxConf, TxQueueConf};
use wz_session_core::sn::{mask_from_res, MulticastTxConduits};

const PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 7447);

fn params(zid: &[u8]) -> MulticastParams {
    MulticastParams {
        whatami: WhatAmI::Peer,
        zid: zid_vec(zid),
        lease_ms: 5_000,
        join_interval_ms: 1,
        seq_num_res: 0x02,
        req_id_res: 0x02,
        batch_size: 2_048,
        is_qos: false,
        compression: false,
        tx_queue: TxQueueConf::of_policy(&wz_session_core::policy::SessionPolicy::defaults()),
        link_rx: LinkRxConf::default(),
        join_rule: GroupJoinRule::Pico,
        max_sessions: None,
        policy: wz_session_core::policy::SessionPolicy::defaults(),
    }
}

/// The `Z` flag of a transport header: an extension chain follows the SN.
const FLAG_Z: u8 = 0x80;
/// The `0x2 First` marker, the one extension of a chain's first fragment.
const FIRST: u8 = FRAGMENT_FIRST_EXT_ID;

/// A reliable fragment at `sn` (one VLE byte), `First`-marked when `first`,
/// with more to follow when `more`.
fn fragment(sn: u8, first: bool, more: bool, payload: u8) -> Vec<u8> {
    let mut header = T_MID_FRAGMENT | FLAG_T_FRAGMENT_R;
    if more {
        header |= FLAG_T_FRAGMENT_M;
    }
    if first {
        header |= FLAG_Z;
        vec![header, sn, FIRST, payload]
    } else {
        vec![header, sn, payload]
    }
}

/// A member that restarts a chain reaches the observer as ONE dropped
/// chain, `Superseded`, on the profile that reads fragments in place: the
/// first fragment of one chain, then a whole chain whose `0x2 First` ends
/// it.
#[test]
fn a_restarted_member_chain_is_reported_dropped_once_in_place() {
    let local = params(&[0x11; 4]);
    let mut d = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
    assert!(d.create().open());
    assert!(!d.notify_link_ready().release());
    let mut r: ReassemblyDispatcher<4, 256> =
        ReassemblyDispatcher::new(ReassemblyConfig::new(2, 5_000));

    // The member's beacon, which announces the marker contract.
    let peer = params(&[0x22; 4]);
    let mut beacon = [0u8; JOIN_MAX_BYTES];
    let len = encode_join_into_slice(
        &peer,
        &MulticastTxConduits::new(mask_from_res(peer.seq_num_res)),
        &mut beacon,
    )
    .expect("a JOIN fits JOIN_MAX_BYTES");
    dispatch_multicast_inbound_reassembling(
        &mut d,
        &mut r,
        &local,
        &beacon[..len],
        PEER,
        0,
        &mut |_| {},
        &(),
    );
    assert!(d.peer_index_by_src(PEER).is_some());

    let mut drops: Vec<ReassemblyDropReason> = Vec::new();
    for (i, dgram) in [
        fragment(0, true, true, 0xAA),
        fragment(1, true, true, 0xBB),
        fragment(2, false, false, 0xCC),
    ]
    .iter()
    .enumerate()
    {
        dispatch_multicast_inbound_reassembling(
            &mut d,
            &mut r,
            &local,
            dgram,
            PEER,
            1 + i as u64,
            &mut |event| {
                if let IterationEvent::ReassemblyDropped(reason) = event {
                    drops.push(reason);
                }
            },
            &(),
        );
    }
    assert_eq!(drops, [ReassemblyDropReason::Superseded]);
    assert_eq!(r.active_chains(), 0, "the restarted chain completed");
}
