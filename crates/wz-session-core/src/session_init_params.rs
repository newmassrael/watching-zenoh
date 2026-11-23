// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ej — per-deploy session handshake parameters lifted from
//! `wz-runtime-tokio::session_glue`.
//!
//! `SessionInitParams` is the bundle of codec field values that drive
//! the 4-way handshake + close (version / whatami / zid / resolutions /
//! batch size / lease / cookie + signing key). It is a pure owned value
//! type — alloc-gated (it holds a `Vec<u8>` cookie and a
//! [`crate::signing_key::SigningKey`]) with no codec / async / tokio
//! coupling, so it belongs on the runtime-agnostic side: an MCU profile
//! drives the session FSM with the same typed params as the tokio AP
//! profile. This move was unblocked by R311ei lifting `SigningKey` into
//! this crate (the field's type now resolves here). `session_glue.rs`
//! keeps a `pub use` re-export so the `crate::session_glue::SessionInitParams`
//! callsites (the `SessionLinkActions::params` field, `session.rs`,
//! `wz-ap-demo`, and the `fixture_session_init_params` test-support
//! builder) resolve unchanged. A DP3 leaf out of `session_glue.rs`.

#[cfg(not(any(feature = "session-slot", feature = "limits-lent-at-open")))]
use alloc::vec::Vec;

use wz_codecs::whatami::WhatAmI;

use crate::limits::SessionLimits;
use crate::policy::SessionPolicy;
use crate::signing_key::SigningKey;

pub use crate::session_zid::{SessionZid, ZidError, ZID_MAX};

/// The longest cookie a session keeps on the `session-slot` profile, in bytes: the build's
/// `HANDSHAKE_COOKIE_BYTES` limit, 176 unless it says otherwise. It is the node's own bound and not
/// the codec's: the INIT body declares a cookie of up to [`COOKIE_FIELD_MAX`] (`sce:max-size` of the
/// generated `InitBody`) and the OPEN body declares none, so a cookie the decoder accepts may be
/// longer than this: the in-place read refuses it (`inbound::read_control`), and the fixed form
/// keeps none (see [`session_bytes`]). The growable profile keeps any length and does not read it.
pub const COOKIE_MAX: usize = crate::caps::HANDSHAKE_COOKIE_BYTES;

/// The capacity the generated `InitBody` declares for its cookie field
/// (`sce:max-size="65535"` in sources/codecs/init_body.scxml): the most [`COOKIE_MAX`] may be, since
/// the cookie an INIT acknowledgement delivers is the one an OPEN echoes. The OPEN body's own cookie
/// field has no bound (its source says so: upstream reads it with the length of a slice).
pub const COOKIE_FIELD_MAX: usize = 65535;

// The cookie bound is refused when the build is made, not when a handshake meets a cookie that does
// not fit: above the INIT field's capacity it buys nothing, and below the widest cookie this node
// issues itself a fixed-memory acceptor could not keep the cookie its own peer echoes, so no session
// it accepted would be admitted.
const _: () = assert!(
    COOKIE_MAX >= 1 && COOKIE_MAX <= COOKIE_FIELD_MAX,
    "HANDSHAKE_COOKIE_BYTES is in 1..=65535, the INIT cookie field's capacity"
);
#[cfg(all(
    any(feature = "session-slot", feature = "limits-lent-at-open"),
    feature = "session-unicast-accept"
))]
const _: () = assert!(
    COOKIE_MAX >= crate::accept_cookie::ACCEPT_COOKIE_MAX_BYTES,
    "HANDSHAKE_COOKIE_BYTES is at least the widest cookie an accepting node issues"
);

/// Bytes a session keeps for the length of one handshake: a zid, a cookie.
///
/// A growable vector on the heap profile. An array of `N` bytes held in the session's own
/// storage, where a value that does not fit is refused rather than grown into, on the heap-free
/// per-session profile (`session-slot`, fixed-memory step S5) and on a build whose limits are its
/// build's values (`limits-lent-at-open`, the cooperative C library): a session there holds no
/// handshake byte on the heap.
#[cfg(not(any(feature = "session-slot", feature = "limits-lent-at-open")))]
pub type SessionBytes<const N: usize> = Vec<u8>;
/// See the growable form of this alias.
#[cfg(any(feature = "session-slot", feature = "limits-lent-at-open"))]
pub type SessionBytes<const N: usize> = heapless::Vec<u8, N>;

/// Copy `src` into session bytes, or `None` when `N` cannot hold it (which only
/// the fixed form can say: the growable one always fits).
pub fn session_bytes<const N: usize>(src: &[u8]) -> Option<SessionBytes<N>> {
    #[cfg(not(any(feature = "session-slot", feature = "limits-lent-at-open")))]
    {
        Some(src.to_vec())
    }
    #[cfg(any(feature = "session-slot", feature = "limits-lent-at-open"))]
    {
        heapless::Vec::from_slice(src).ok()
    }
}

/// A zid for [`SessionInitParams::zid`] from bytes the caller wrote itself.
/// Panics when `src` is not one to [`ZID_MAX`] bytes or is all zero: a zid the
/// wire cannot carry is a construction mistake there, not a runtime condition. A
/// zid that arrives from configuration or from the wire is made with
/// [`SessionZid::new`], whose refusal the caller reports.
pub fn zid_bytes(src: &[u8]) -> SessionZid {
    // The refusal is not formatted: it is a construction mistake whose rule the message states,
    // and formatting it would link `ZidError`'s `Debug` and the formatter's struct writer into
    // every MCU image that names its zid (about 490 bytes of text on thumbv7m).
    match SessionZid::new(src) {
        Ok(zid) => zid,
        Err(_) => panic!("a zid is 1 to 16 bytes, not all zero"),
    }
}

/// A cookie for [`SessionInitParams::cookie`], written the same way on every
/// profile. Panics when `src` is longer than [`COOKIE_MAX`].
pub fn cookie_bytes(src: &[u8]) -> SessionBytes<COOKIE_MAX> {
    session_bytes::<COOKIE_MAX>(src).expect("a cookie the node sets is at most COOKIE_MAX bytes")
}

/// Per-deploy parameters that drive the codec field values for the
/// 4-way handshake + close. Production callers source these from
/// `deploy.yaml`; tests pass fixed values for reproducible wire bytes.
///
/// # No protocol version here
///
/// The version an Init announces is the protocol's
/// ([`wz_codecs::wire_const::PROTOCOL_VERSION`]), and the encoder writes it
/// without asking. Upstream holds it the same way: its transport manager's
/// version is set to `zenoh_protocol::VERSION` and no builder method moves it.
/// A field here let tests announce a version no zenoh speaks, and once an
/// acceptor refuses a foreign version that is a node that cannot be dialled.
#[derive(Debug, Clone)]
pub struct SessionInitParams {
    /// This node's role (Router / Peer / Client). The handshake encoder
    /// projects it to the 2-bit INIT / OPEN cbyte wire form via
    /// [`WhatAmI::to_wire`] (`_z_whatami_to_uint8`, transport.c:31-37) at
    /// the codec edge — the typed role is stored, not a pre-encoded byte,
    /// so the API-vs-wire form is no longer ambiguous across call sites.
    pub whatami: WhatAmI,
    /// ZenohID, one to sixteen bytes by its type, so a session is refused an
    /// invalid zid where its parameters are made and never later. The codec
    /// encodes the length in the high 4 bits of `cbyte` as `zid_len - 1`.
    pub zid: SessionZid,
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
    /// How often the session's keepalive speaks for it on an idle link: a
    /// share of a lease, upstream's `transport/link/tx/keep_alive` and
    /// zenoh-pico's `Z_TRANSPORT_LEASE_EXPIRE_FACTOR`. See [`KeepAliveConf`].
    pub keep_alive: KeepAliveConf,
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
    pub cookie: SessionBytes<COOKIE_MAX>,

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
    /// The session's inbound link configuration: upstream's
    /// `transport/link/rx` block as far as a session acts on it. It rides here
    /// for the reason [`Self::tx_queue`] does.
    pub link_rx: LinkRxConf,
    /// The value of every policy this session's machines read: the snapshot its creator resolved
    /// for it, starting from [`SessionPolicy::defaults`]. A machine of the session reads a policy
    /// here and never from the build. It rides here for the reason [`Self::tx_queue`] does; the
    /// queue's own policy values ([`TxQueueConf::of_snapshot`]) are derived from the same
    /// snapshot by the creator.
    pub policy: SessionPolicy,
    /// The value of every limit this session's tables are held to: the snapshot its creator
    /// resolved for it, starting from [`SessionLimits::defaults`]. A table of the session reads its
    /// bound here and never from the build. It rides here for the reason [`Self::tx_queue`] does.
    /// Where the build allows each limit one value the snapshot holds no byte, and a field of no
    /// size adds no padding to the bundle: its alignment is a `usize`'s, under the `u64` fields'.
    pub limits: SessionLimits,
}

/// Upstream's default `transport/link/rx/max_message_size`, 1 GiB
/// (`commons/zenoh-config/src/defaults.rs` @ `max_message_size: 2_usize.pow(30),`).
pub const RX_MAX_MESSAGE_SIZE: usize = 1 << 30;

/// A session's inbound link configuration: upstream's `transport/link/rx`
/// section as far as a session acts on it.
///
/// `max_message_size` is the largest message the session rejoins from
/// fragments, in bytes. The rule is upstream's: a fragment whose bytes would
/// take the chain past it ends the chain
/// (`io/zenoh-transport/src/common/defragmentation.rs` @
/// `if new_len > self.capacity {`). A message that arrives whole in one frame
/// is never measured against it, so `0` rejoins no chain and still delivers
/// every unfragmented message.
///
/// The reassembly pool a host is built with is a second bound beside this one,
/// and the smaller of the two is what holds: a value above the pool's slot can
/// only be read as the slot.
///
/// `buffer_size` is the read storage each stream link pools, in bytes: the
/// link keeps `buffer_size / mtu` buffers of one frame each, and at least one,
/// as upstream's RX task does
/// (`io/zenoh-transport/src/unicast/lowlatency/link.rs` @ `let mut n = rx_buffer_size / mtu;`).
/// A frame read while every pooled buffer is still held gets storage of its
/// own, so the value bounds what is reused and never what is received.
///
/// `tcp_mtu` is how a link over a TCP connection (TCP, and TLS over it) sizes
/// its MTU, the largest batch it reads and the one it sends: the session
/// advertises no larger a batch, divides `buffer_size` by the smaller of it
/// and the negotiated batch, and fragments to it. It is not a key of the
/// document; the ABI states it, zenoh's rule for the zenoh-c ABI and the Rust
/// API, zenoh-pico's for the pico ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkRxConf {
    /// `transport/link/rx/buffer_size`, in bytes.
    pub buffer_size: usize,
    /// `transport/link/rx/max_message_size`, in bytes.
    pub max_message_size: usize,
    /// How a link over a TCP connection sizes its MTU.
    pub tcp_mtu: TcpLinkMtu,
    /// What an opening session does with an InitAck that names a larger batch
    /// than its InitSyn advertised.
    pub wider_init_ack_batch: WiderInitAckBatch,
}

/// Upstream's default `transport/link/rx/buffer_size`, one batch of the
/// widest size (`commons/zenoh-config/src/defaults.rs` @ `buffer_size: BatchSize::MAX as usize,`).
pub const RX_BUFFER_SIZE: usize = u16::MAX as usize;

impl Default for LinkRxConf {
    fn default() -> Self {
        Self {
            buffer_size: RX_BUFFER_SIZE,
            max_message_size: RX_MAX_MESSAGE_SIZE,
            tcp_mtu: TcpLinkMtu::HalfMssMultiple,
            wider_init_ack_batch: WiderInitAckBatch::Adopt,
        }
    }
}

pub use crate::peer_init_caps::WiderInitAckBatch;

/// How a link over a TCP connection sizes its MTU: the two rules wz's presets
/// differ by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpLinkMtu {
    /// zenoh's: the widest batch less the IP header of the connection's local
    /// address (40 bytes for IPv4, 60 for IPv6), and on unix down to the
    /// largest multiple of half the connection's MSS below that
    /// (`io/zenoh-links/zenoh-link-tcp/src/unicast.rs` @
    /// `let mss = socket.mss().unwrap_or(mtu as u32) / 2;`; the TLS link reads
    /// the same of its TCP socket). A number of the host and the connection:
    /// on a Linux loopback the accepting socket reads an MSS of 32,768 before
    /// any data, which gives 49,152.
    HalfMssMultiple,
    /// zenoh-pico's: the widest batch, whatever the connection
    /// (`vendor/zenoh-pico/src/link/unicast/tcp.c` @ `// Maximum MTU for TCP`).
    Widest,
}

/// What a TCP connection's MSS read gave, for [`TcpLinkMtu::mtu`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpMss {
    /// The read gave this many bytes.
    Read(u32),
    /// The platform reads one and the read failed: zenoh then takes the MTU
    /// before the MSS is applied as the MSS.
    Failed,
    /// The platform reads none (zenoh reads it on unix only), so the MTU stays
    /// at the header rule.
    Unread,
}

impl TcpLinkMtu {
    /// The MTU of a connection whose local address is IPv6 when `v6`, and
    /// whose MSS read gave `mss`.
    ///
    /// One divergence: an MSS of 0 or 1 halves to 0, on which zenoh's search
    /// for the multiple never ends; here it leaves the MTU at the header rule.
    pub fn mtu(self, v6: bool, mss: TcpMss) -> usize {
        const WIDEST: u32 = u16::MAX as u32;
        match self {
            Self::Widest => WIDEST as usize,
            Self::HalfMssMultiple => {
                let mtu = WIDEST - if v6 { 60 } else { 40 };
                let half = match mss {
                    TcpMss::Read(mss) => mss / 2,
                    TcpMss::Failed => mtu / 2,
                    TcpMss::Unread => return mtu as usize,
                };
                if half == 0 {
                    return mtu as usize;
                }
                let mut multiple = half;
                while multiple + half < mtu {
                    multiple += half;
                }
                mtu.min(multiple) as usize
            }
        }
    }
}

/// Upstream's default `transport/link/tx/keep_alive`, keepalives in one lease
/// (`commons/zenoh-config/src/defaults.rs` @ `keep_alive: 4,`).
pub const KEEP_ALIVE_PER_LEASE: u32 = 4;

/// zenoh-pico's default `Z_TRANSPORT_LEASE_EXPIRE_FACTOR`
/// (`vendor/zenoh-pico/CMakeLists.txt` @
/// `set(Z_TRANSPORT_LEASE_EXPIRE_FACTOR 3 CACHE STRING "Default session lease expire factor.")`).
pub const PICO_LEASE_EXPIRE_FACTOR: u32 = 3;

/// Which lease a keepalive interval is a share of.
///
/// The two originals divide different leases. zenoh divides the lease the
/// session itself was configured with, whatever the peer advertised
/// (`io/zenoh-transport/src/unicast/universal/transport.rs` @
/// `let keep_alive = self.manager.config.unicast.lease`). zenoh-pico divides
/// the lease the session adopted at its handshake, the smaller of its own and
/// the peer's (`vendor/zenoh-pico/src/transport/unicast/transport.c` @
/// `param->_lease = (oam._body._open._lease < Z_TRANSPORT_LEASE) ? oam._body._open._lease : Z_TRANSPORT_LEASE;`),
/// which every task of the transport then reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseBasis {
    /// The lease this session advertises: zenoh's.
    Own,
    /// The lease the session adopted, the smaller of the two advertised:
    /// zenoh-pico's.
    Adopted,
}

/// How often a session's keepalive speaks on an idle link: every lease of
/// `basis`, divided by `per_lease`.
///
/// It is the transmit side of liveness. The peer closes a session it has heard
/// nothing from for its lease, so a session that sends nothing else sends a
/// keepalive whenever it has been silent for one interval, and the peer hears
/// about `per_lease` of them in each lease. Upstream configures it as
/// `transport/link/tx/keep_alive` (4 by default) and zenoh-pico builds it in as
/// `Z_TRANSPORT_LEASE_EXPIRE_FACTOR` (3 by default); the two also divide
/// different leases ([`LeaseBasis`]), so each interface states both halves.
///
/// `Default` is the cadence every wz session kept before this was a value:
/// the adopted lease in three, which is zenoh-pico's. The zenoh interface
/// states zenoh's own, [`Self::ZENOH`], and a node that honours the key
/// `transport/link/tx/keep_alive` builds it from the key; a router's
/// capacity model still reads the three it was calibrated on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepAliveConf {
    /// Keepalives in one lease; at least 1 (a config stating 0 is refused
    /// before it reaches a session, as upstream's division by it would fail).
    pub per_lease: u32,
    /// Which lease is divided.
    pub basis: LeaseBasis,
}

impl Default for KeepAliveConf {
    fn default() -> Self {
        Self::PICO
    }
}

impl KeepAliveConf {
    /// zenoh-pico's keepalive at its default factor.
    pub const PICO: Self = Self::pico(PICO_LEASE_EXPIRE_FACTOR);

    /// zenoh's keepalive at its default `transport/link/tx/keep_alive`.
    pub const ZENOH: Self = Self::zenoh(KEEP_ALIVE_PER_LEASE);

    /// zenoh's keepalive: `per_lease` of them in the session's own lease.
    pub const fn zenoh(per_lease: u32) -> Self {
        Self {
            per_lease,
            basis: LeaseBasis::Own,
        }
    }

    /// zenoh-pico's keepalive: the adopted lease divided by `factor`.
    pub const fn pico(factor: u32) -> Self {
        Self {
            per_lease: factor,
            basis: LeaseBasis::Adopted,
        }
    }

    /// The interval, in milliseconds, for a session whose own lease is
    /// `own_ms` and whose adopted lease is `adopted_ms`. Never 0, so a
    /// degenerate lease does not spin the emitter; a `per_lease` of 0 reads as 1.
    pub const fn interval_ms(&self, own_ms: u64, adopted_ms: u64) -> u64 {
        let lease = match self.basis {
            LeaseBasis::Own => own_ms,
            LeaseBasis::Adopted => adopted_ms,
        };
        let per_lease = if self.per_lease == 0 {
            1
        } else {
            self.per_lease as u64
        };
        let interval = lease / per_lease;
        if interval == 0 {
            1
        } else {
            interval
        }
    }
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
    /// The `tx-no-progress-deadline` policy: a second bound on a BLOCKING message, in
    /// microseconds with no fragment of it going out ([`crate::tx_deadline::PushDeadline`]).
    /// The total wait, `wait_before_close_us`, still ends the message, and a fragment out
    /// starts this window again without making the total longer: the message is given up
    /// on at whichever bound comes first. `None`, upstream's behaviour, is the total wait
    /// alone. A window past the total wait is refused ([`Self::validate`]).
    pub no_progress_us: Option<u64>,
    /// The `tx-expiry-keeps-session` policy: what a blocking message that found no room in
    /// its deadline costs. `false`, upstream's behaviour, closes the session as unresponsive
    /// and tells the sender nothing. `true` drops the message, reports the transport as not
    /// available, and keeps the session open, until as many in a row as `TX_EXPIRY_CLOSE_AFTER`
    /// of the session's snapshot ([`SessionInitParams::limits`]) close it after all.
    pub expiry_keeps_session: bool,
    /// `batching/enabled`: whether the session stages its messages into an open frame per
    /// conduit that the link's writer flushes when it falls idle, so that a burst leaves in few
    /// large frames. `false` sends every message as a frame of its own as soon as it is staged,
    /// which is what upstream's pipeline does with batching off: it moves each serialized
    /// batch out at once (`io/zenoh-transport/src/common/pipeline.rs` @
    /// `if !self.batching || $msg.is_express() {`). Upstream's default is `true`.
    pub batching: bool,
    /// `batching/time_limit`, in microseconds (the key states milliseconds): the longest a link's
    /// writer holds an open batch back while producers keep adding to it
    /// ([`crate::link::TxPipeline::batching_time_limit_us`]). The writer's own bound,
    /// [`crate::link::BATCHING_TIME_LIMIT_US`], when the configuration states none.
    pub batching_time_limit_us: u64,
    /// `allocation/mode`: whether a link's queue allocates the batches its lanes may hold when
    /// it is shaped at Established, or the first time each is wanted. Upstream's default is the
    /// second.
    pub allocation: crate::link::QueueAllocation,
    /// What a message that may be dropped does when another sender holds the conduit (or the
    /// session) it would be staged on: a blocking sender holds it across its own wait for room,
    /// up to `wait_before_close`. The profile's, not a key of a zenoh configuration.
    pub held_drop: HeldDrop,
}

/// What a droppable message does when the conduit it would be staged on is held by another
/// sender ([`TxQueueConf::held_drop`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeldDrop {
    /// Ask the link for room without the conduit, out of the message's own `wait_before_drop`,
    /// and drop it when there is none in that time: zenoh bounds a droppable message's whole wait
    /// so (`commons/zenoh-config/src/defaults.rs` @ `wait_before_drop: 1000,`).
    WaitForRoom,
    /// Drop it at once, asking the link nothing: zenoh-pico's dropping send tries the transport's
    /// lock and drops the message when it is held
    /// (`vendor/zenoh-pico/src/transport/common/tx.c` @
    /// `ret = _z_transport_tx_mutex_lock(ztc, cong_ctrl == Z_CONGESTION_CONTROL_BLOCK);`).
    DropAtOnce,
}

/// R2926 — upstream's default
/// `transport/link/tx/queue/congestion_control/drop/max_wait_before_drop_fragments`
/// (`commons/zenoh-config/src/defaults.rs` @ `max_wait_before_drop_fragments: 50000,`).
pub const MAX_WAIT_BEFORE_DROP_FRAGMENTS_US: u64 = 50_000;

/// The `tx-no-progress-deadline` policy of `policy`, in the form [`TxQueueConf::no_progress_us`]
/// carries it: the window of `TX_NO_PROGRESS_WINDOW_US` as `limits` holds it when the policy is
/// on, and none (upstream's behaviour) when it is off.
const fn no_progress_us(policy: &SessionPolicy, limits: &SessionLimits) -> Option<u64> {
    if policy.tx_no_progress_deadline() {
        Some(limits.tx_no_progress_window_us() as u64)
    } else {
        None
    }
}

/// `PICO_TX_QUEUE_SIZE` as `limits` holds it, as the size of a queue: upstream's
/// `MIN_SIZE..=MAX_SIZE`, the nearest end for a value outside it, so that no snapshot can make the
/// configuration the session refuses at `validate`.
const fn pico_queue_size(limits: &SessionLimits) -> usize {
    use crate::link::TxQueueShape;
    let size = limits.pico_tx_queue_size();
    if size < TxQueueShape::MIN_SIZE {
        TxQueueShape::MIN_SIZE
    } else if size > TxQueueShape::MAX_SIZE {
        TxQueueShape::MAX_SIZE
    } else {
        size
    }
}

/// Why a [`TxQueueConf`] is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxQueueConfError {
    /// A queue size outside upstream's accepted range.
    SizeOutOfRange(TxQueueSizeOutOfRange),
    /// A no-progress window that is zero, which can never be met, or longer than the total
    /// wait, which could never be the bound that comes first.
    NoProgressWindow {
        /// The window asked for, in microseconds.
        window_us: u64,
        /// The total wait it is held against, `wait_before_close_us`.
        total_us: u64,
    },
}

impl From<TxQueueSizeOutOfRange> for TxQueueConfError {
    fn from(size: TxQueueSizeOutOfRange) -> Self {
        Self::SizeOutOfRange(size)
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
    /// Upstream's queue sizes and waits, with the two policies the queue carries
    /// (`tx-no-progress-deadline`, `tx-expiry-keeps-session`) as `policy` holds them: the queue a
    /// creator builds beside the snapshots it hands the session in [`SessionInitParams::policy`]
    /// and [`SessionInitParams::limits`], whose `TX_NO_PROGRESS_WINDOW_US` is the window.
    pub const fn of_snapshot(policy: &SessionPolicy, limits: &SessionLimits) -> Self {
        Self {
            no_progress_us: no_progress_us(policy, limits),
            expiry_keeps_session: policy.tx_expiry_keeps_session(),
            ..Self::upstream()
        }
    }

    /// Upstream's queue sizes and waits, with the two policies the queue carries at upstream's
    /// behaviour: no window but the total wait, and an expiry that closes the session.
    ///
    /// This is the queue a zenoh configuration's `transport/link/tx/queue` section describes
    /// before any session holds it, and the queue of a push that is never made to wait. A
    /// session's queue is built with [`Self::of_snapshot`] from the snapshots it is handed,
    /// which is where the two policies and the window are decided.
    pub const fn upstream() -> Self {
        Self {
            sizes: [crate::link::TxQueueShape::DEFAULT_SIZE; crate::qos::Priority::NUM],
            wait_before_drop_us: WAIT_BEFORE_DROP_US,
            max_wait_before_drop_fragments_us: MAX_WAIT_BEFORE_DROP_FRAGMENTS_US,
            wait_before_close_us: WAIT_BEFORE_CLOSE_US,
            no_progress_us: None,
            expiry_keeps_session: false,
            batching: true,
            batching_time_limit_us: crate::link::BATCHING_TIME_LIMIT_US,
            allocation: crate::link::QueueAllocation::Lazy,
            held_drop: HeldDrop::WaitForRoom,
        }
    }

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
    ///
    /// The lock half of that send is kept as it is: a DROP message whose conduit another sender
    /// holds is dropped at once, with nothing asked of the link ([`HeldDrop::DropAtOnce`]). The
    /// long drop deadline is the socket's half, the wait of a sender that holds the conduit.
    ///
    /// The queue holds `PICO_TX_QUEUE_SIZE` batches per priority and not upstream's two: a put of
    /// pico writes on its own thread, where here a second thread writes, and a lane of four
    /// frames of 1 KiB made the two wait for each other after every four.
    ///
    /// The two policies the queue carries are taken from `policy`, and the queue size and the
    /// window of `tx-no-progress-deadline` from `limits`, the two snapshots of the session the
    /// queue is built for.
    pub const fn pico_of_snapshot(policy: &SessionPolicy, limits: &SessionLimits) -> Self {
        Self {
            sizes: [pico_queue_size(limits); crate::qos::Priority::NUM],
            wait_before_drop_us: WAIT_BEFORE_CLOSE_US,
            max_wait_before_drop_fragments_us: 0,
            wait_before_close_us: WAIT_BEFORE_CLOSE_US,
            no_progress_us: no_progress_us(policy, limits),
            expiry_keeps_session: policy.tx_expiry_keeps_session(),
            batching: true,
            batching_time_limit_us: crate::link::BATCHING_TIME_LIMIT_US,
            allocation: crate::link::QueueAllocation::Lazy,
            held_drop: HeldDrop::DropAtOnce,
        }
    }

    /// Refuse a size outside `1..=16`, as upstream's config does, and a no-progress window
    /// that is zero or longer than the total wait.
    pub fn validate(&self) -> Result<(), TxQueueConfError> {
        use crate::link::TxQueueShape;
        for (byte, &size) in self.sizes.iter().enumerate() {
            if !(TxQueueShape::MIN_SIZE..=TxQueueShape::MAX_SIZE).contains(&size) {
                return Err(TxQueueSizeOutOfRange {
                    priority_byte: byte as u8,
                    size,
                }
                .into());
            }
        }
        if let Some(window_us) = self.no_progress_us {
            if window_us == 0 || window_us > self.wait_before_close_us {
                return Err(TxQueueConfError::NoProgressWindow {
                    window_us,
                    total_us: self.wait_before_close_us,
                });
            }
        }
        Ok(())
    }

    /// The shape a link of a session with this configuration takes at
    /// Established, given whether the session negotiated QoS, the link's
    /// negotiated batch MTU, and the session's configured batch size, the unit
    /// a lane's bound counts in ([`crate::link::TxQueueShape::queue_unit_bytes`]).
    /// The unit is never less than the batch MTU.
    pub const fn shape(
        &self,
        qos: bool,
        batch_bytes: usize,
        configured_batch_bytes: usize,
    ) -> crate::link::TxQueueShape {
        crate::link::TxQueueShape {
            sizes: self.sizes,
            qos,
            batch_bytes,
            queue_unit_bytes: if configured_batch_bytes > batch_bytes {
                configured_batch_bytes
            } else {
                batch_bytes
            },
            pipeline: crate::link::TxPipeline {
                batching_time_limit_us: self.batching_time_limit_us,
                allocation: self.allocation,
            },
        }
    }
}

impl SessionInitParams {
    /// R311kj — the EFFECTIVE advertised batch budget: `0` is wz's
    /// internal "unset" sentinel and must never reach the wire — a
    /// zenoh-pico peer adopts a literal 0 verbatim
    /// (unicast/transport.c:135-136) and sizes a 0-byte TX wbuf from it
    /// (transport.c:47-49), bricking the session. The configured half of
    /// what a session advertises: `SessionLinkActions::own_batch_advertisement`
    /// caps it by the link's receive capacity, and that capped value is what
    /// every advertisement and own-side comparison reads (the Init wire
    /// write, `init_ack_params`' capping min, the R311kc InitAck validator's
    /// own side, and `negotiated_batch_mtu`'s own arm) — so the wire value
    /// and every comparison against it stay one value (the R311kd
    /// zero-sentinel patched only the wz<->wz MTU consult; this closes the
    /// wire emission itself).
    pub fn effective_batch_size(&self) -> u16 {
        match self.batch_size {
            0 => 65535,
            n => n,
        }
    }
}

#[cfg(test)]
mod shape_tests {
    use super::TxQueueConf;

    /// Upstream's queue under the build defaults' policies.
    fn zenoh_queue() -> TxQueueConf {
        TxQueueConf::of_snapshot(
            &crate::policy::SessionPolicy::defaults(),
            &crate::limits::SessionLimits::BUILD,
        )
    }

    /// A lane is bounded in the session's configured batch size, so a link
    /// that sends datagrams does not shrink it to two datagrams; and a
    /// configured size below what the link sends never lowers the unit under
    /// the batch the link really sends.
    #[test]
    fn a_lane_is_counted_in_the_configured_batch_and_never_below_the_links() {
        let conf = zenoh_queue();
        let udp = conf.shape(true, 1450, 65535);
        assert_eq!((udp.batch_bytes, udp.queue_unit_bytes), (1450, 65535));
        let small = conf.shape(true, 2048, 1024);
        assert_eq!((small.batch_bytes, small.queue_unit_bytes), (2048, 2048));
    }

    /// The batching bound a session is configured with is the one its links' writers are
    /// handed at Established, and a session configured with none hands them the writer's own.
    #[test]
    fn the_batching_bound_reaches_the_shape_a_link_takes() {
        let bare = zenoh_queue().shape(true, 65535, 65535);
        assert_eq!(bare.pipeline, crate::link::TxPipeline::DEFAULT);
        assert_eq!(
            bare.pipeline.batching_time_limit_us,
            crate::link::BATCHING_TIME_LIMIT_US
        );
        let configured = TxQueueConf {
            batching_time_limit_us: 3_000,
            allocation: crate::link::QueueAllocation::Init,
            ..zenoh_queue()
        };
        let shaped = configured.shape(true, 65535, 65535).pipeline;
        assert_eq!(shaped.batching_time_limit_us, 3_000);
        assert_eq!(shaped.allocation, crate::link::QueueAllocation::Init);
    }
}

#[cfg(test)]
mod tcp_mtu_tests {
    use super::{TcpLinkMtu, TcpMss};

    /// zenoh's rule over the MSS values a Linux loopback reads: the accepting socket's 32,768
    /// before any data, the dialling socket's 32,741, and an Ethernet path's 1,440 over IPv6.
    #[test]
    fn zenohs_rule_rounds_down_to_a_multiple_of_half_the_mss() {
        let rule = TcpLinkMtu::HalfMssMultiple;
        assert_eq!(rule.mtu(false, TcpMss::Read(32_768)), 49_152);
        assert_eq!(rule.mtu(false, TcpMss::Read(32_741)), 65_480);
        assert_eq!(rule.mtu(true, TcpMss::Read(1_440)), 64_800);
    }

    /// The header alone where no MSS is read, half the header rule's MTU where the read failed,
    /// and the header alone for an MSS that halves to nothing.
    #[test]
    fn zenohs_rule_without_an_mss_keeps_to_the_header() {
        let rule = TcpLinkMtu::HalfMssMultiple;
        assert_eq!(rule.mtu(false, TcpMss::Unread), 65_495);
        assert_eq!(rule.mtu(true, TcpMss::Unread), 65_475);
        assert_eq!(rule.mtu(false, TcpMss::Failed), 65_494);
        assert_eq!(rule.mtu(false, TcpMss::Read(1)), 65_495);
    }

    /// zenoh-pico's rule is the widest batch whatever the connection reads.
    #[test]
    fn picos_rule_is_the_widest_batch() {
        for mss in [
            TcpMss::Read(32_768),
            TcpMss::Read(1_440),
            TcpMss::Failed,
            TcpMss::Unread,
        ] {
            assert_eq!(TcpLinkMtu::Widest.mtu(false, mss), 65_535);
            assert_eq!(TcpLinkMtu::Widest.mtu(true, mss), 65_535);
        }
    }
}

#[cfg(test)]
mod keep_alive_tests {
    use super::{KeepAliveConf, PICO_LEASE_EXPIRE_FACTOR};

    /// The two originals divide different leases by different numbers, and a session built for
    /// one is not the other when the peer advertises a shorter lease than its own: zenoh keeps
    /// its own lease's share, zenoh-pico the adopted (smaller) lease's.
    #[test]
    fn zenoh_divides_its_own_lease_and_pico_the_adopted_one() {
        let (own, adopted) = (10_000, 4_000);
        assert_eq!(KeepAliveConf::ZENOH.interval_ms(own, adopted), 2_500);
        assert_eq!(KeepAliveConf::PICO.interval_ms(own, adopted), 1_333);
        // Control: with no shorter peer lease the two bases agree on the lease, so the
        // difference above is the basis and the number, not the arithmetic.
        assert_eq!(KeepAliveConf::pico(4).interval_ms(10_000, 10_000), 2_500);
        assert_eq!(KeepAliveConf::zenoh(3).interval_ms(10_000, 10_000), 3_333);
    }

    /// What no session was given is what every wz session kept: pico's cadence.
    #[test]
    fn the_default_is_the_cadence_wz_sessions_kept_before_it_was_a_value() {
        assert_eq!(KeepAliveConf::default(), KeepAliveConf::PICO);
        assert_eq!(KeepAliveConf::PICO.per_lease, PICO_LEASE_EXPIRE_FACTOR);
        assert_ne!(KeepAliveConf::default(), KeepAliveConf::ZENOH);
        // The capacity model, which compiles without this module, divides by its own constant;
        // it is the default's, or the bounds it computes are for another cadence.
        assert_eq!(
            u64::from(KeepAliveConf::default().per_lease),
            crate::lease::LEASE_EXPIRE_FACTOR
        );
    }

    /// The interval is never zero (the emitter would spin on it), and a count of zero reads as
    /// one rather than dividing by it.
    #[test]
    fn a_degenerate_lease_or_count_never_gives_a_zero_interval() {
        assert_eq!(KeepAliveConf::pico(3).interval_ms(0, 0), 1);
        assert_eq!(KeepAliveConf::zenoh(4).interval_ms(2, 2), 1);
        assert_eq!(KeepAliveConf::zenoh(0).interval_ms(10_000, 10_000), 10_000);
    }
}

#[cfg(test)]
mod cookie_bound_tests {
    use super::{session_bytes, COOKIE_FIELD_MAX, COOKIE_MAX};

    /// `COOKIE_FIELD_MAX` is the capacity the INIT body declares for its cookie, read from its
    /// source, so a codec that changed it would fail here and not leave the bound's ceiling a copy of
    /// a number that moved. The OPEN body's cookie has no bound: its source carries no `max-size` on
    /// the field, which is why the ceiling is the INIT body's.
    #[test]
    fn the_ceiling_is_the_capacity_the_init_body_declares() {
        let sources = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sources/codecs");
        let open =
            std::fs::read_to_string(sources.join("open_body.scxml")).expect("open body source");
        let at = open
            .find("sce:length-field=\"cookie_len\"")
            .expect("the open cookie field");
        let element = &open[open[..at].rfind('<').unwrap()..at + open[at..].find("/>").unwrap()];
        assert!(
            !element.contains("sce:max-size"),
            "the OPEN cookie field now has a bound: {element:?}"
        );
        let init =
            std::fs::read_to_string(sources.join("init_body.scxml")).expect("init body source");
        // The element that carries the cookie's length field, whole: its attributes may run over
        // several lines.
        let at = init
            .find("sce:length-field=\"cookie_len\"")
            .expect("init_body.scxml declares no cookie_len field");
        let start = init[..at]
            .rfind('<')
            .expect("the field is inside an element");
        let end = at + init[at..].find("/>").expect("the element is closed");
        let element = &init[start..end];
        assert!(
            element.contains(&std::format!("sce:max-size=\"{COOKIE_FIELD_MAX}\"")),
            "init_body.scxml: the cookie field is {element:?}, not {COOKIE_FIELD_MAX} bytes"
        );
    }

    /// The build's bound is in range (the build refuses one that is not), and the fixed form keeps a
    /// cookie that fits and none that does not, where the growable form keeps any.
    #[test]
    fn a_cookie_longer_than_the_buffer_is_not_kept_on_the_fixed_profile() {
        assert!((1..=COOKIE_FIELD_MAX).contains(&COOKIE_MAX));
        assert!(session_bytes::<8>(&[7; 8]).is_some());
        let too_long = session_bytes::<8>(&[7; 9]);
        #[cfg(any(feature = "session-slot", feature = "limits-lent-at-open"))]
        assert!(too_long.is_none());
        #[cfg(not(any(feature = "session-slot", feature = "limits-lent-at-open")))]
        assert_eq!(too_long.map(|b| b.len()), Some(9));
    }
}

#[cfg(test)]
mod no_progress_tests {
    use super::{TxQueueConf, TxQueueConfError, WAIT_BEFORE_CLOSE_US};
    use crate::limits::SessionLimits;
    use crate::policy::SessionPolicy;

    /// Upstream's queue under the build defaults' policies.
    fn zenoh_queue() -> TxQueueConf {
        TxQueueConf::of_snapshot(
            &SessionPolicy::defaults(),
            &crate::limits::SessionLimits::BUILD,
        )
    }

    /// The pico ABI's queue under the build defaults' policies.
    fn pico_queue() -> TxQueueConf {
        TxQueueConf::pico_of_snapshot(
            &SessionPolicy::defaults(),
            &crate::limits::SessionLimits::BUILD,
        )
    }

    fn conf(no_progress_us: Option<u64>) -> TxQueueConf {
        TxQueueConf {
            no_progress_us,
            ..zenoh_queue()
        }
    }

    /// The build with no policy states is upstream's: the total wait alone, and a blocking
    /// message that finds no room closes the session.
    #[test]
    fn a_build_that_states_no_policy_is_upstreams_behaviour() {
        assert_eq!(zenoh_queue().no_progress_us, None);
        assert!(!zenoh_queue().expiry_keeps_session);
        assert_eq!(pico_queue().no_progress_us, None);
        assert!(!pico_queue().expiry_keeps_session);
    }

    /// A droppable message behind a held conduit: zenoh's profile waits for room out of
    /// `wait_before_drop`, pico's drops it at once, as its try-lock does.
    #[test]
    fn each_profile_states_what_a_held_conduit_costs_a_droppable_message() {
        use super::HeldDrop;
        assert_eq!(TxQueueConf::upstream().held_drop, HeldDrop::WaitForRoom);
        assert_eq!(zenoh_queue().held_drop, HeldDrop::WaitForRoom);
        assert_eq!(pico_queue().held_drop, HeldDrop::DropAtOnce);
    }

    /// Upstream's queue is the queue of a snapshot whose two queue policies are upstream's
    /// behaviour, whatever the build states for them: the policies are the snapshot's alone, and
    /// every other number is the same in both.
    #[test]
    fn upstreams_queue_holds_upstreams_behaviour_and_the_queues_own_numbers() {
        let upstream = TxQueueConf::upstream();
        assert_eq!(upstream.no_progress_us, None);
        assert!(!upstream.expiry_keeps_session);
        assert_eq!(
            TxQueueConf {
                no_progress_us: zenoh_queue().no_progress_us,
                expiry_keeps_session: zenoh_queue().expiry_keeps_session,
                ..upstream
            },
            zenoh_queue()
        );
    }

    /// The two policies the queue carries are read from the snapshot it is built from, not from
    /// the build: a snapshot with both on gives the window and keeps the session, and one with
    /// both off gives neither. A build whose domain leaves a value out has nothing to select, and
    /// the case is skipped there.
    #[test]
    fn the_queue_carries_the_policies_of_the_snapshot_it_is_built_from() {
        use crate::policy::{TxExpiryKeepsSession, TxNoProgressDeadline};
        use crate::policy_binding::PolicyValue;
        let wide = !TxNoProgressDeadline::DOMAIN.is_singleton()
            && !TxExpiryKeepsSession::DOMAIN.is_singleton();
        if !wide {
            return;
        }
        let mut on = SessionPolicy::defaults();
        on.select_tx_no_progress_deadline(TxNoProgressDeadline::On)
            .expect("the domain holds both values");
        on.select_tx_expiry_keeps_session(TxExpiryKeepsSession::On)
            .expect("the domain holds both values");
        let mut off = on;
        off.select_tx_no_progress_deadline(TxNoProgressDeadline::Off)
            .expect("the domain holds both values");
        off.select_tx_expiry_keeps_session(TxExpiryKeepsSession::Off)
            .expect("the domain holds both values");
        let window = Some(crate::caps::TX_NO_PROGRESS_WINDOW_US as u64);
        for queue in [
            TxQueueConf::of_snapshot(&on, &crate::limits::SessionLimits::BUILD),
            TxQueueConf::pico_of_snapshot(&on, &crate::limits::SessionLimits::BUILD),
        ] {
            assert_eq!(queue.no_progress_us, window);
            assert!(queue.expiry_keeps_session);
        }
        for queue in [
            TxQueueConf::of_snapshot(&off, &crate::limits::SessionLimits::BUILD),
            TxQueueConf::pico_of_snapshot(&off, &crate::limits::SessionLimits::BUILD),
        ] {
            assert_eq!(queue.no_progress_us, None);
            assert!(!queue.expiry_keeps_session);
        }
        // Everything else is the queue's own, whatever the snapshot says.
        assert_eq!(
            TxQueueConf::of_snapshot(&on, &crate::limits::SessionLimits::BUILD).sizes,
            TxQueueConf::of_snapshot(&off, &crate::limits::SessionLimits::BUILD).sizes
        );
    }

    /// `PICO_TX_QUEUE_SIZE` with nothing stated: the pico queue holds the build's size for every
    /// priority, the queue it held while it read the build's constant.
    #[test]
    fn pico_tx_queue_size_with_nothing_stated_holds_the_builds_value() {
        let queue =
            TxQueueConf::pico_of_snapshot(&SessionPolicy::defaults(), &SessionLimits::defaults());
        let size = crate::caps::PICO_TX_QUEUE_SIZE.clamp(
            crate::link::TxQueueShape::MIN_SIZE,
            crate::link::TxQueueShape::MAX_SIZE,
        );
        assert!(queue.sizes.iter().all(|&s| s == size));
        assert_eq!(queue, pico_queue());
    }

    /// `PICO_TX_QUEUE_SIZE` stated: the pico queue holds the stated size for every priority, and
    /// nothing else of the queue moves with it. A build that keeps the build's value alone refuses
    /// the statement itself.
    #[test]
    fn pico_tx_queue_size_stated_is_the_size_the_queue_holds() {
        let build = crate::caps::PICO_TX_QUEUE_SIZE;
        let other = if build > 1 { build - 1 } else { build + 1 };
        let mut limits = SessionLimits::defaults();
        if let Err(refused) = limits.select_pico_tx_queue_size(other) {
            assert!(refused.domain.is_singleton(), "{other} is inside 1..=16");
            assert_eq!(limits, SessionLimits::defaults());
            return;
        }
        let queue = TxQueueConf::pico_of_snapshot(&SessionPolicy::defaults(), &limits);
        assert!(queue.sizes.iter().all(|&s| s == other));
        assert_eq!(
            TxQueueConf {
                sizes: pico_queue().sizes,
                ..queue
            },
            pico_queue()
        );
    }

    /// The pico ABI's queue is the declared `PICO_TX_QUEUE_SIZE` for every priority, upstream's
    /// range holds it, and every other configuration keeps upstream's default of two.
    #[test]
    fn the_pico_queue_is_the_declared_size_and_the_rest_keep_upstreams_default() {
        let pico = pico_queue();
        let size = crate::caps::PICO_TX_QUEUE_SIZE.clamp(
            crate::link::TxQueueShape::MIN_SIZE,
            crate::link::TxQueueShape::MAX_SIZE,
        );
        assert!(pico.sizes.iter().all(|&s| s == size));
        assert_eq!(pico.validate(), Ok(()));
        assert!(zenoh_queue()
            .sizes
            .iter()
            .all(|&s| s == crate::link::TxQueueShape::DEFAULT_SIZE));
    }

    /// The window is held against the total wait: none, zero and past-the-total are refused,
    /// and one as long as the total, and one microsecond, are not.
    #[test]
    fn a_window_is_refused_when_it_is_zero_or_longer_than_the_total_wait() {
        assert_eq!(conf(None).validate(), Ok(()));
        assert_eq!(conf(Some(1)).validate(), Ok(()));
        assert_eq!(conf(Some(WAIT_BEFORE_CLOSE_US)).validate(), Ok(()));
        let refused = |window_us| {
            Err(TxQueueConfError::NoProgressWindow {
                window_us,
                total_us: WAIT_BEFORE_CLOSE_US,
            })
        };
        assert_eq!(conf(Some(0)).validate(), refused(0));
        assert_eq!(
            conf(Some(WAIT_BEFORE_CLOSE_US + 1)).validate(),
            refused(WAIT_BEFORE_CLOSE_US + 1)
        );
    }

    /// The total wait the window is held against is the configured one, not the default.
    #[test]
    fn the_window_is_held_against_the_configured_total_wait() {
        let tight = TxQueueConf {
            wait_before_close_us: 500,
            no_progress_us: Some(501),
            ..zenoh_queue()
        };
        assert_eq!(
            tight.validate(),
            Err(TxQueueConfError::NoProgressWindow {
                window_us: 501,
                total_us: 500
            })
        );
    }

    /// A queue size outside the range is still refused, now as a variant of the error.
    #[test]
    fn a_size_out_of_range_is_still_refused() {
        let mut sizes = zenoh_queue().sizes;
        sizes[0] = 0;
        let bad = TxQueueConf {
            sizes,
            ..zenoh_queue()
        };
        assert!(matches!(
            bad.validate(),
            Err(TxQueueConfError::SizeOutOfRange(_))
        ));
    }
}

// `SessionInitParams` carries no test-only methods. The deterministic
// fixture builder (formerly `for_test`) lives in the
// `wz-runtime-tokio-test-support` sibling crate (R71) so production
// builds carry no test-only code path. `SessionInitParams`
// intentionally has no `Default` impl — production callers MUST source
// every field from `deploy.yaml` (or another configured source), and
// the fixture stays behind the test-support crate boundary.
