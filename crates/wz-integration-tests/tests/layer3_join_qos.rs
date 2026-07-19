// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop — the QoS-mode JOIN (`transport-qos`), the per-priority
//! SN-conduit variant `layer3_join.rs` explicitly deferred ("the QoS mode that
//! splits into 8 per-priority pairs is a separate codec variant that lands in a
//! later round when QoS becomes part of the Layer 3 catalog").
//!
//! ## What binds the claim (`transport-qos`, not `codec-join`)
//!
//! `codec-join` (the plain single-conduit JOIN body) is already proven; what is
//! unique to `transport-qos` is the per-`(priority, reliability)` SN conduit
//! advertisement that rides a JOIN QoS-SN extension. wz's `encode_join`, under
//! `#[cfg(feature = "transport-qos")]` and a runtime `is_qos` offer, writes the
//! `{0,0}` DECOY base next_sn (mirroring zenoh `multicast/link.rs:487`) + the
//! transport-message `Z` header flag + the hand-rolled QoS-SN ext
//! (`[0x51][VLE(len)][Priority::NUM * 2 VLE SNs]`, `write_join_qos_ext` in
//! `wz-session-core::multicast_join`). This test byte-compares that whole qos
//! JOIN against zenoh-pico's real C `_z_join_encode` with `_next_sn._is_qos =
//! true`, which encodes the same `_Z_MSG_EXT_ID_JOIN_QOS` ZBUF ext (0x51,
//! transport.c:71-83). RED (binds to the transport-qos code): neuter
//! `write_join_qos_ext` (or the `is_qos` gate) so the ext is dropped/corrupted ->
//! the bytes diverge from pico while a plain-mode JOIN still matches.
//!
//! ## The union-alias base (why priority Control carries {0,0})
//!
//! pico's `_z_conduit_sn_list_t._val` is a C union: `_plain` and `_qos[0]` alias
//! at offset 0. `_z_join_encode` writes the base next_sn from `_val._plain`
//! (transport.c:64-65) = `_qos[0]`, then the per-priority ext from
//! `_qos[0..NUM]`. wz writes an INDEPENDENT `{0,0}` decoy base. For byte-parity
//! the two bases must agree, so this fixture leaves the Control (priority 0)
//! conduit at `{0,0}` (unminted) and mints DISTINCT SNs into priorities 1..7 —
//! the 14 non-trivial per-priority SNs are what prove the ext wire is
//! byte-faithful.
//!
//! Links the vendored zenoh-pico C library like the other `layer3_*` codec
//! tests, so it runs in Layer C1 on every push (NOT `#[ignore]`d).

use wz_codecs::whatami::WhatAmI;
use wz_codecs::wire_const;
use wz_session_core::multicast_join::encode_join;
use wz_session_core::multicast_params::MulticastParams;
use wz_session_core::qos::Priority;
use wz_session_core::sn::MulticastTxConduits;

use zenoh_pico_sys::{
    _z_conduit_sn_list_t, _z_conduit_sn_list_t__bindgen_ty_1, _z_coundit_sn_t, _z_id_t,
    _z_join_encode, _z_t_msg_join_t, _z_wbuf_clear, _z_wbuf_make, _z_wbuf_to_zbuf, _z_zbuf_clear,
    z_whatami_t,
};

/// zenoh-pico `z_whatami_t` for a Peer — `_z_whatami_to_uint8(0x02)` yields the
/// same 2-bit JOIN cbyte wire form as wz's `WhatAmI::Peer.to_wire()` (= 0b01);
/// the existing `layer3_join.rs` fixtures rely on the same correspondence.
const WHATAMI_PEER: z_whatami_t = 0x02;

fn pack_zid(payload: &[u8]) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..payload.len()].copy_from_slice(payload);
    id
}

/// Encode the QoS JOIN with pico's real C `_z_join_encode` and prepend the MID
/// byte (wz's `encode_join` emits the full datagram `[flags|MID][body...]`, while
/// `_z_join_encode` emits only the body starting at `version`).
fn pico_encode_qos_join(
    params: &MulticastParams,
    flags: u8,
    per_priority: &[(u64, u64); Priority::NUM],
) -> Vec<u8> {
    // SAFETY: standard wbuf-extract path (mirrors layer3_join.rs). The qos union
    // member `_qos` is fully written for all NUM priorities; `_is_qos = true`
    // selects the per-priority encode arm. `_patch = 0` (= _Z_NO_PATCH) keeps the
    // ext-chain MORE bit clear so the QoS ext header is a bare 0x51.
    unsafe {
        let mut qos = [_z_coundit_sn_t {
            _reliable: 0,
            _best_effort: 0,
        }; Priority::NUM];
        for (i, (r, be)) in per_priority.iter().enumerate() {
            qos[i] = _z_coundit_sn_t {
                _reliable: *r as usize,
                _best_effort: *be as usize,
            };
        }
        let next_sn = _z_conduit_sn_list_t {
            _val: _z_conduit_sn_list_t__bindgen_ty_1 { _qos: qos },
            _is_qos: true,
        };
        let msg = _z_t_msg_join_t {
            _zid: _z_id_t {
                id: pack_zid(&params.zid),
            },
            // pico divides by 1000 inside the encoder when the T flag is set, so
            // pass the raw milliseconds and let its own projection run.
            _lease: params.lease_ms as usize,
            _next_sn: next_sn,
            _batch_size: params.batch_size,
            _whatami: WHATAMI_PEER,
            _req_id_res: params.req_id_res,
            _seq_num_res: params.seq_num_res,
            _version: params.version,
            _patch: 0,
        };
        let mut wbf = _z_wbuf_make(256, false);
        let ret = _z_join_encode(&mut wbf, flags, &msg);
        assert_eq!(ret, 0, "_z_join_encode(qos) failed");
        let mut zbf = _z_wbuf_to_zbuf(&wbf);
        let body = std::slice::from_raw_parts(zbf._ios._buf, zbf._ios._w_pos).to_vec();
        _z_zbuf_clear(&mut zbf);
        _z_wbuf_clear(&mut wbf);

        let mut out = Vec::with_capacity(1 + body.len());
        out.push(flags | wire_const::T_MID_JOIN);
        out.extend_from_slice(&body);
        out
    }
}

/// wz's per-priority QoS-SN JOIN (`transport-qos`) is byte-identical to
/// zenoh-pico's `_z_join_encode` with `_is_qos = true` — the §5.4 `transport-qos`
/// cross-impl codec-parity witness for the multicast JOIN QoS-SN extension.
// wz-proves: transport-qos codec-parity partial
#[test]
fn layer3_join_qos_sn_ext_byte_equals_pico() {
    // A large ring mask so the small mint counts below never wrap; the advertised
    // next_sn then equals the mint count, and we read the exact values back for
    // the pico reference (so both encoders see identical logical inputs).
    let mask = (1u64 << 32) - 1;
    let mut tx = MulticastTxConduits::new(mask);

    // Leave Control (priority 0) at {0,0} (the union-alias base decoy match).
    // Mint DISTINCT SNs into priorities 1..7 so the QoS-SN ext carries 14
    // non-trivial values — the load-bearing per-priority fidelity witness.
    let non_control = [
        Priority::RealTime,
        Priority::InteractiveHigh,
        Priority::InteractiveLow,
        Priority::DataHigh,
        Priority::Data,
        Priority::DataLow,
        Priority::Background,
    ];
    for prio in non_control {
        let p = prio as usize; // 1..=7
        for _ in 0..p {
            tx.mint(prio, true);
        }
        for _ in 0..(p + 16) {
            tx.mint(prio, false);
        }
    }

    let per = tx.advertise_per_priority();
    let per_priority: [(u64, u64); Priority::NUM] =
        core::array::from_fn(|i| (per[i].next_reliable, per[i].next_best_effort));
    // Sanity: Control is the {0,0} base decoy; the rest are distinct and non-zero.
    assert_eq!(
        per_priority[Priority::Control as usize],
        (0, 0),
        "Control conduit must stay the {{0,0}} decoy base"
    );
    for prio in non_control {
        assert_ne!(
            per_priority[prio as usize],
            (0, 0),
            "priority {prio:?} must carry a minted per-priority SN"
        );
    }

    let params = MulticastParams {
        version: 0x08,
        whatami: WhatAmI::Peer,
        zid: vec![0x01, 0x02, 0x03],
        // whole seconds -> the T flag rides (lease in seconds on the wire).
        lease_ms: 8000,
        join_interval_ms: 1000,
        // protocol defaults -> join_advertises_caps() == false -> no S flag / no
        // sn_res + batch_size body, so only the T (lease) and Z (qos) flags ride.
        seq_num_res: 0x02,
        req_id_res: 0x02,
        batch_size: 8192,
        is_qos: true,
    };
    assert!(
        !params.join_advertises_caps(),
        "fixture uses protocol defaults so the S flag stays clear"
    );

    let wz = encode_join(&params, &tx);

    let flags = wire_const::FLAG_T_JOIN_T | wire_const::FLAG_T_Z;
    let pico = pico_encode_qos_join(&params, flags, &per_priority);

    assert_eq!(
        wz, pico,
        "qos JOIN must match zenoh-pico byte-for-byte;\n wz  ={wz:02x?}\n pico={pico:02x?}"
    );
    // The QoS-SN ext header (0x51 = id 0x1 | M | ENC_ZBUF) must be on the wire.
    assert!(
        wz.contains(&0x51),
        "the qos JOIN must carry the 0x51 QoS-SN extension header"
    );
}
