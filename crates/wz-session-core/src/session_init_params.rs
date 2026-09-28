// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ej — per-deploy session handshake parameters lifted from
//! `wz-runtime-tokio::session_glue`.
//!
//! `SessionInitParams` is the bundle of codec field values that drive
//! the 4-way handshake + close (version / whatami / zid / resolutions /
//! batch size / lease / cookie + signing key). It is a pure owned value
//! type — alloc-gated (it holds `Vec<u8>` zid + cookie and a
//! [`crate::signing_key::SigningKey`]) with no codec / async / tokio
//! coupling, so it belongs on the runtime-agnostic side: an MCU profile
//! drives the session FSM with the same typed params as the tokio AP
//! profile. This move was unblocked by R311ei lifting `SigningKey` into
//! this crate (the field's type now resolves here). `session_glue.rs`
//! keeps a `pub use` re-export so the `crate::session_glue::SessionInitParams`
//! callsites (the `SessionLinkActions::params` field, `session.rs`,
//! `wz-ap-demo`, and the `fixture_session_init_params` test-support
//! builder) resolve unchanged. A DP3 leaf out of `session_glue.rs`.

use alloc::vec::Vec;

use wz_codecs::whatami::WhatAmI;

use crate::signing_key::SigningKey;

/// Per-deploy parameters that drive the codec field values for the
/// 4-way handshake + close. Production callers source these from
/// `deploy.yaml`; tests pass fixed values for reproducible wire bytes.
#[derive(Debug, Clone)]
pub struct SessionInitParams {
    /// Protocol version (zenoh: 0x05 at the time of writing).
    pub version: u8,
    /// This node's role (Router / Peer / Client). The handshake encoder
    /// projects it to the 2-bit INIT / OPEN cbyte wire form via
    /// [`WhatAmI::to_wire`] (`_z_whatami_to_uint8`, transport.c:31-37) at
    /// the codec edge — the typed role is stored, not a pre-encoded byte,
    /// so the API-vs-wire form is no longer ambiguous across call sites.
    pub whatami: WhatAmI,
    /// ZenohID — 1..=16 bytes. The codec encodes the length in the
    /// high 4 bits of `cbyte` as `zid_len - 1`.
    pub zid: Vec<u8>,
    /// Sequence-number resolution (0..=3 → 8 / 16 / 32 / 64-bit).
    pub seq_num_res: u8,
    /// Request-id resolution (0..=3).
    pub req_id_res: u8,
    /// Per-link batch size (bytes). Transport.h documents 1..=65535.
    /// `0` is wz's INTERNAL "unset" sentinel — it must never reach the
    /// wire; every advertisement / comparison reads
    /// [`Self::effective_batch_size`] (R311kj).
    pub batch_size: u16,
    /// Lease duration in milliseconds — ALWAYS milliseconds on both
    /// sides (R311ku; the pre-ku shape was a raw wire value plus a
    /// `lease_in_seconds` unit flag every consumer had to project).
    /// The OPEN encoder derives the `_Z_FLAG_T_OPEN_T` wire form itself
    /// ([`crate::lease::lease_to_wire`]): a whole-second value rides the
    /// wire compacted to seconds under T=1, exactly like zenoh-pico's
    /// `_z_t_msg_make_open_syn/_ack` (definitions/transport.c:196-214).
    pub lease_ms: u64,
    /// Initial sequence number for the reliable channel (VLE-encoded
    /// inside the open body).
    pub initial_sn: u64,
    /// Cookie material exchanged on the InitAck → OpenSyn echo path.
    ///
    /// On the Initiator side this is the bytes received in the
    /// peer's InitAck; the Initiator re-emits them verbatim in the
    /// OpenSyn frame so the peer can MAC-verify ownership of the
    /// session start.
    ///
    /// On the Accepting side this field is only the FALLBACK: the live
    /// mint is `generate_cookie_hmac_sha256(cookie_signing_key, peer_zid,
    /// cookie_nonce)` per RFC §5.M, and it is what an initiator's echo is
    /// checked against. R311y813 made the per-handshake nonce a required
    /// input, so an acceptor's emitted cookie is NOT reproducible from this
    /// bundle alone — a test that wants to predict it reads the nonce off
    /// `SessionLinkActions::cookie_nonce` (a code span, not a link: the
    /// accessor shares its name with the slot it reads). This
    /// field reaches the wire only where no peer zid or no nonce is known,
    /// and in that state `cookie_valid` admits nothing.
    pub cookie: Vec<u8>,

    /// Per-process secret key used by the Accepting side to MAC the
    /// outbound cookie. Constructed via `SigningKey::new(bytes)` so
    /// length validation (>= 32 bytes per RFC §5.M) + drop-time
    /// zeroize are enforced by the type. Initiator side does not
    /// consume this field; the cookie value flows inbound from the
    /// peer's InitAck instead.
    pub cookie_signing_key: SigningKey,

    /// R2924 — the session's outbound queue configuration: upstream's
    /// `transport/link/tx/queue` sizes and congestion waits. Not a codec
    /// value, unlike the fields above; it rides here because this bundle is
    /// the one per-session carrier every open path — dial, accept, reconnect,
    /// the C ABI and the MCU acceptor — already hands to the session.
    pub tx_queue: TxQueueConf,
}

/// R2923 — how long a DROPPABLE message waits for room on its conduit's link
/// before it is dropped, in microseconds: upstream's default
/// `transport/link/tx/queue/congestion_control/drop/wait_before_drop`
/// (`commons/zenoh-config/src/defaults.rs` @ `wait_before_drop: 1000,`).
pub const WAIT_BEFORE_DROP_US: u64 = 1_000;

/// R2923 — how long a BLOCKING message waits for room before the session is
/// closed as unresponsive, in microseconds: upstream's default
/// `transport/link/tx/queue/congestion_control/block/wait_before_close`
/// (`commons/zenoh-config/src/defaults.rs` @ `wait_before_close: 5000000,`).
pub const WAIT_BEFORE_CLOSE_US: u64 = 5_000_000;

/// R2924 — a session's outbound queue configuration: upstream's
/// `transport/link/tx/queue` section as far as a session acts on it — the
/// per-priority queue sizes its links' writer queues take at Established
/// ([`crate::link::TxQueueShape`]), and the two congestion waits its senders
/// spend before dropping a message or closing the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxQueueConf {
    /// Batches each priority's queue holds, by `Priority` wire byte.
    pub sizes: [usize; crate::qos::Priority::NUM],
    /// `congestion_control/drop/wait_before_drop`, in microseconds.
    pub wait_before_drop_us: u64,
    /// R2926 — `congestion_control/drop/max_wait_before_drop_fragments`, in
    /// microseconds: how far the fragments of a droppable chain may extend
    /// its deadline, all together.
    pub max_wait_before_drop_fragments_us: u64,
    /// `congestion_control/block/wait_before_close`, in microseconds.
    pub wait_before_close_us: u64,
}

/// R2926 — upstream's default
/// `transport/link/tx/queue/congestion_control/drop/max_wait_before_drop_fragments`
/// (`commons/zenoh-config/src/defaults.rs` @ `max_wait_before_drop_fragments: 50000,`).
pub const MAX_WAIT_BEFORE_DROP_FRAGMENTS_US: u64 = 50_000;

impl Default for TxQueueConf {
    fn default() -> Self {
        Self {
            sizes: [crate::link::TxQueueShape::DEFAULT_SIZE; crate::qos::Priority::NUM],
            wait_before_drop_us: WAIT_BEFORE_DROP_US,
            max_wait_before_drop_fragments_us: MAX_WAIT_BEFORE_DROP_FRAGMENTS_US,
            wait_before_close_us: WAIT_BEFORE_CLOSE_US,
        }
    }
}

/// R2924 — a queue size outside upstream's accepted range, which upstream's
/// config validator refuses (`QueueSizeConf::MIN..=QueueSizeConf::MAX`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxQueueSizeOutOfRange {
    /// The `Priority` wire byte whose size was out of range.
    pub priority_byte: u8,
    /// The size given.
    pub size: usize,
}

impl TxQueueConf {
    /// zenoh-pico's transmit model: a DROP message waits for room as long as a
    /// BLOCK one does.
    ///
    /// pico has no bounded outbound queue. Its `_z_transport_tx_send_n_msg`
    /// drops a `Z_CONGESTION_CONTROL_DROP` message only when the transport's TX
    /// mutex is already held (`vendor/zenoh-pico/src/transport/common/tx.c` @
    /// `ret = _z_transport_tx_mutex_lock(ztc, cong_ctrl == Z_CONGESTION_CONTROL_BLOCK);`),
    /// and otherwise writes on the calling thread, blocking in the socket write.
    /// A full socket therefore slows a pico put and never drops it. wz's queue
    /// is bounded, so the nearest equivalent is a drop deadline no shorter than
    /// the close deadline: the sender waits for the writer as pico's would wait
    /// for the socket, and a peer that never drains is still bounded by
    /// `wait_before_close`.
    pub const fn pico() -> Self {
        Self {
            sizes: [crate::link::TxQueueShape::DEFAULT_SIZE; crate::qos::Priority::NUM],
            wait_before_drop_us: WAIT_BEFORE_CLOSE_US,
            max_wait_before_drop_fragments_us: 0,
            wait_before_close_us: WAIT_BEFORE_CLOSE_US,
        }
    }

    /// Refuse a size outside `1..=16`, as upstream's config does.
    pub fn validate(&self) -> Result<(), TxQueueSizeOutOfRange> {
        use crate::link::TxQueueShape;
        for (byte, &size) in self.sizes.iter().enumerate() {
            if !(TxQueueShape::MIN_SIZE..=TxQueueShape::MAX_SIZE).contains(&size) {
                return Err(TxQueueSizeOutOfRange {
                    priority_byte: byte as u8,
                    size,
                });
            }
        }
        Ok(())
    }

    /// The shape a link of a session with this configuration takes at
    /// Established, given whether the session negotiated QoS and the link's
    /// negotiated batch MTU.
    pub const fn shape(&self, qos: bool, batch_bytes: usize) -> crate::link::TxQueueShape {
        crate::link::TxQueueShape {
            sizes: self.sizes,
            qos,
            batch_bytes,
        }
    }
}

impl SessionInitParams {
    /// R311kj — the EFFECTIVE advertised batch budget: `0` is wz's
    /// internal "unset" sentinel and must never reach the wire — a
    /// zenoh-pico peer adopts a literal 0 verbatim
    /// (unicast/transport.c:135-136) and sizes a 0-byte TX wbuf from it
    /// (transport.c:47-49), bricking the session. The single accessor
    /// every advertisement and own-side comparison reads:
    /// `encode_init`'s wire write, `init_ack_params`' capping min, the
    /// R311kc InitAck validator's own side, and
    /// `negotiated_batch_mtu`'s own arm — so the wire value and every
    /// comparison against it stay one value (the R311kd zero-sentinel
    /// patched only the wz<->wz MTU consult; this closes the wire
    /// emission itself).
    pub fn effective_batch_size(&self) -> u16 {
        match self.batch_size {
            0 => 65535,
            n => n,
        }
    }
}

// `SessionInitParams` carries no test-only methods. The deterministic
// fixture builder (formerly `for_test`) lives in the
// `wz-runtime-tokio-test-support` sibling crate (R71) so production
// builds carry no test-only code path. `SessionInitParams`
// intentionally has no `Default` impl — production callers MUST source
// every field from `deploy.yaml` (or another configured source), and
// the fixture stays behind the test-support crate boundary.
