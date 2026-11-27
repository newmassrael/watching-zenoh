// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What one transport transmits with: the conduits its messages are framed in and the sequence
//! numbers its frames carry, which zenoh-pico keeps in the state every transport shares
//! (`_z_transport_common_t`) and sends with by one function whatever the transport
//! (`vendor/zenoh-pico/src/transport/common/tx.c` @ `static z_result_t _z_transport_tx_send_n_msg_inner(`).
//!
//! Held apart from the session around it so that a transport that is not a unicast session holds
//! the same state and is written by the same walk. What its emit counts is part of it too: the
//! wire counters, the registry partition its links' cells are in and the refusals of a lend-only
//! send. The link a frame leaves by is not: a session's core is shared by every link of an
//! aggregate, so it cannot own one binding's link, and what a link compresses is the link's. The
//! walk borrows the links with the state for each send ([`TxRoute`]).
//!
//! The conduits' own types are defined here with the state that holds them: the stage of each
//! conduit ([`BatchTx`]), the windows over them, the frame numbers ([`FrameTxConduits`]), the
//! counts of where frames were written, and the values the walk hands between its steps.

use crate::link::SessionRuntime;
use crate::qos::Priority;
use crate::session_actions::LinkState;

/// The transmit state of one transport.
pub struct TransportTx<R: SessionRuntime> {
    /// One lock per conduit, and the windows over them. A sender holds its conduit's lock from the
    /// mint of a frame's sequence number to the frame's emit, so the order of the numbers is the
    /// order on the wire, and a fragment chain stays whole on it.
    pub(crate) conduits: TxConduits<R>,
    /// The next sequence number of each conduit and reliability channel. Raw and monotonic: the
    /// wire value is masked to the negotiated ring where it is minted, so the counter's own wrap
    /// is the ring's successor too. The first frame takes the initial number the Open announced.
    pub(crate) frame_sn: FrameTxConduits<R::Word>,
    /// R311y9 — the transport's wire byte and message counters, on the atomics of their own: what
    /// it sends, counted where a frame is handed to its link, and what it receives, counted where
    /// [`crate::drive::dispatch_link_event`] reads a unit. Read through
    /// `SessionLinkActions::stats_report`.
    #[cfg(feature = "transport-stats")]
    pub stats: crate::stats::TransportStats,
    /// R2825 — the transport's partition of the node's stats registry: the labelled families the
    /// metrics document is written from, its links' cells among them. Under a lock of its own,
    /// which a counting call takes alone; the host copies it into its registry when it answers a
    /// query and once more when the session closes
    /// ([`crate::stats_registry::StatsRegistry::set_transport_metrics`]), so no message ever
    /// takes a node-wide lock.
    #[cfg(feature = "transport-stats")]
    metrics: R::Mutex<crate::stats_registry::TransportMetrics>,
    /// Fixed-memory step S4 — the sends a lend-only transport refused for want of a slot
    /// (`TxRefusalCounts::no_slot`) and as past its budget (`TxRefusalCounts::oversize`): a word
    /// each, counted where the refusal is raised and read by a host whenever it asks.
    #[cfg(feature = "tx-lend-only")]
    refused_no_slot: R::Word,
    #[cfg(feature = "tx-lend-only")]
    refused_oversize: R::Word,
    /// R2238 (open-debt item 580) — how many more `T_MID_FRAGMENT` messages
    /// this transport may put on the wire. Each fragment of a chain draws ONE
    /// credit through `Self::take_fragment_credit` as it is emitted;
    /// when the draw fails the chain is abandoned and the send reports
    /// [`crate::send_wire_error::SendWireError::FragmentTxBudgetExhausted`].
    ///
    /// This is wz's answer to the finite batch pool upstream fragments
    /// against (`common/pipeline.rs`, `zgetbatch_rets!`), and the reason wz
    /// needed one at all: with an unbounded writer channel
    /// (`wz-runtime-tokio/src/serial_pipeline.rs`, `link_pipeline.rs` and
    /// their siblings all take `mpsc::unbounded_channel`) and a
    /// build-the-whole-chain-first encoder, there was no state in which some
    /// fragments had been sent and the rest could not be — so there was no
    /// place to report a chain abandon from, whatever the encoder could
    /// spell. The budget is what makes that state REACHABLE, and reaching it
    /// deterministically is what a gate can assert on.
    ///
    /// ⚠ It is a SESSION-wide resource, not a per-chain allowance, and the
    /// distinction is load-bearing rather than stylistic. A per-chain
    /// allowance would be knowable before the walk began, and the honest
    /// implementation of it would be a pre-check that refuses the whole
    /// message and emits nothing — which never reaches the mid-chain state
    /// at all. Shared, the credit another sender takes between two of this
    /// chain's fragments is not predictable from inside the chain, so the
    /// walk must stream and find out, exactly as upstream's does.
    ///
    /// The stop fragment itself does NOT draw a credit: it is the abandon
    /// NOTICE, not chain payload, and a budget that could not afford to say
    /// it had run out would leave the peer holding the buffer this whole
    /// mechanism exists to release. Upstream draws its stop batch outside
    /// the pool for the same reason (`WBatch::new_ephemeral`).
    ///
    /// `usize::MAX` (the default) means "unbounded" and is never decremented,
    /// so a host that never calls
    /// [`set_fragment_tx_budget`](crate::session_actions::SessionLinkActions::set_fragment_tx_budget)
    /// keeps the pre-existing behavior byte for byte.
    ///
    /// Under a lock and not an atomic: ARMv6-M has no `target_has_atomic = "ptr"`.
    #[cfg(all(feature = "transport-fragmentation", feature = "tx-fragment-credit"))]
    fragment_credit: R::Mutex<usize>,
    /// The shape the transport's links' queues took when it was established
    /// (`SessionInitParams::tx_queue`'s `shape`), which a sender that may not wait asks before it
    /// begins a fragment chain: a chain longer than its lane holds is not begun. `None` until the
    /// transport's send limits are settled, when no data frame is sent.
    #[cfg(all(
        feature = "tx-probe",
        feature = "transport-fragmentation",
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "declare-interest",
            feature = "liveliness-token",
        )
    ))]
    lanes: R::Mutex<Option<crate::link::TxQueueShape>>,
}

impl<R: SessionRuntime> TransportTx<R> {
    /// Every conduit empty and its window closed, every channel at `initial_sn`, nothing
    /// counted, and the registry's cells in `metrics`, the partition the transport's first link
    /// was opened in.
    pub fn new(
        initial_sn: u64,
        #[cfg(feature = "transport-stats")] metrics: crate::stats_registry::TransportMetrics,
    ) -> Self {
        Self {
            conduits: TxConduits::new(),
            frame_sn: FrameTxConduits::new(initial_sn),
            #[cfg(feature = "transport-stats")]
            stats: crate::stats::TransportStats::default(),
            #[cfg(feature = "transport-stats")]
            metrics: R::new_mutex(metrics),
            #[cfg(feature = "tx-lend-only")]
            refused_no_slot: <R::Word as crate::runtime_cell::WordCell>::new(0),
            #[cfg(feature = "tx-lend-only")]
            refused_oversize: <R::Word as crate::runtime_cell::WordCell>::new(0),
            // Unbounded until a host declares a budget.
            #[cfg(all(feature = "transport-fragmentation", feature = "tx-fragment-credit"))]
            fragment_credit: R::new_mutex(usize::MAX),
            #[cfg(all(
                feature = "tx-probe",
                feature = "transport-fragmentation",
                any(
                    feature = "codec-push",
                    feature = "codec-request",
                    feature = "codec-response",
                    feature = "codec-response-final",
                    feature = "declare-keyexpr",
                    feature = "declare-subscriber",
                    feature = "declare-queryable",
                    feature = "declare-token",
                    feature = "declare-interest",
                    feature = "liveliness-token",
                )
            ))]
            lanes: R::new_mutex(None),
        }
    }

    /// Back to the state [`Self::new`] builds, for a session that opens its transport again. A
    /// frame open in a lent slot is given back to its lender by the caller first: the lender is a
    /// link, which this state does not hold. The counters are kept: they are the session's whole
    /// history, which a reopen continues.
    #[cfg(feature = "session-reconnect")]
    pub(crate) fn reset(&self, initial_sn: u64) {
        self.conduits.reset();
        self.frame_sn.reset(initial_sn);
    }

    /// Declare how many more fragments this transport may send, or `usize::MAX` for no bound;
    /// it both sets and refills the credit.
    #[cfg(all(feature = "transport-fragmentation", feature = "tx-fragment-credit"))]
    pub(crate) fn set_fragment_credit(&self, fragments: usize) {
        R::with_mutex_mut(&self.fragment_credit, |slot| *slot = fragments);
    }

    /// The fragments this transport may still send, `usize::MAX` when no bound was declared.
    #[cfg(all(feature = "transport-fragmentation", feature = "tx-fragment-credit"))]
    pub(crate) fn fragment_credit(&self) -> usize {
        R::with_mutex_mut(&self.fragment_credit, |slot| *slot)
    }

    /// Draw ONE fragment credit, reporting whether it was available. The unbounded default
    /// (`usize::MAX`) always succeeds and is never decremented, so an unconfigured transport can
    /// neither run out nor count itself down into a false exhaustion. Gated as its one caller,
    /// the fragment walk, is: fragmentation with no sender compiles no walk.
    #[cfg(all(
        feature = "transport-fragmentation",
        feature = "tx-fragment-credit",
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "declare-interest",
            feature = "liveliness-token",
        )
    ))]
    pub(crate) fn take_fragment_credit(&self) -> bool {
        R::with_mutex_mut(&self.fragment_credit, |slot| {
            if *slot == usize::MAX {
                return true;
            }
            if *slot == 0 {
                return false;
            }
            // Not zero, checked above.
            *slot = slot.wrapping_sub(1);
            true
        })
    }

    /// Record the shape the transport's links' queues take, once its send limits are settled.
    #[cfg(all(
        feature = "tx-probe",
        feature = "transport-fragmentation",
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "declare-interest",
            feature = "liveliness-token",
        )
    ))]
    pub(crate) fn shape_lanes(&self, shape: crate::link::TxQueueShape) {
        R::with_mutex_mut(&self.lanes, |lanes| *lanes = Some(shape));
    }

    /// The bytes the queue a frame of `priority` goes to holds before it refuses one
    /// ([`crate::link::TxQueueShape::lane_bytes`]); no bound before the shape is recorded.
    #[cfg(all(
        feature = "tx-probe",
        feature = "transport-fragmentation",
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "declare-interest",
            feature = "liveliness-token",
        )
    ))]
    pub(crate) fn lane_bytes(&self, priority: crate::qos::Priority) -> usize {
        R::with_mutex_mut(&self.lanes, |lanes| {
            lanes.map_or(usize::MAX, |shape| shape.lane_bytes(priority))
        })
    }

    /// The transport's registry partition, lent to `f` under its lock. `f` takes no other lock.
    #[cfg(feature = "transport-stats")]
    #[inline]
    pub(crate) fn metrics<U>(
        &self,
        f: impl FnOnce(&mut crate::stats_registry::TransportMetrics) -> U,
    ) -> U {
        R::with_mutex_mut(&self.metrics, f)
    }

    /// R2825 — record on `link`'s cells in this transport's partition. A link without a slot
    /// records nothing (see [`crate::session_actions::LinkState::stats_slot`]).
    #[cfg(feature = "transport-stats")]
    pub(crate) fn record_on_link(
        &self,
        link: &crate::session_actions::LinkState<R>,
        record: impl FnOnce(
            &mut crate::stats_registry::TransportMetrics,
            crate::stats_registry::LinkSlot,
        ),
    ) {
        let Some(slot) = R::with_mutex_mut(&link.stats_slot, |slot| *slot) else {
            return;
        };
        self.metrics(|metrics| record(metrics, slot));
    }

    /// R311y205 (transport-multilink IMPL-2b-iii) — emit a wire batch on ONE specific link: mark
    /// THAT link's line as spoken (per-link keepalive suppression), apply the link's
    /// compression, hand the bytes to its driver, and count the write on this transport. The
    /// single seam every send of a session funnels through (the reliability-routed data send and
    /// the per-link keepalive and close), so every TX path stamps the link it actually used.
    ///
    /// R311y516 — the establishment codecs are ROLE-CONJOINED: both funnels into this seam are
    /// themselves role-gated, so an establishment codec with neither unicast role reaches it from
    /// nowhere.
    #[cfg(any(
        all(
            any(feature = "codec-init-body", feature = "codec-open-body"),
            any(feature = "session-unicast-open", feature = "session-unicast-accept")
        ),
        feature = "codec-close",
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-interest",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "liveliness-token",
        feature = "transport-batching",
        feature = "transport-keepalive",
    ))]
    // Out of line: every send path ends here, and a copy inlined into each of them cost more
    // than the call.
    #[inline(never)]
    pub(crate) fn emit_on_link(
        &self,
        link: &crate::session_actions::LinkState<R>,
        bytes: &[u8],
        lent: Option<&mut crate::tx_lease::TxLease<'_, R::Driver>>,
        reliability: crate::reliability::Reliability,
        priority: crate::qos::Priority,
        // The frame carries no sequence number and may overtake what the link has queued
        // (`BoxedLinkDriver::send_urgent`); only the keepalive says so.
        urgent: bool,
    ) {
        // ARCHITECTURE section 9.1 — when the caller encoded the frame into a
        // slot THIS link lent (`lent`), the frame IS that slot's bytes, `bytes`
        // is empty, and the slot is handed to the link instead of a copy of it.
        // Every other step is shared: the stamp, the compression decision that
        // needs the bytes, the stats and the link-liveness disposition below,
        // which is why the lent send is a parameter of this seam and not a
        // second one that would have to repeat them.
        use crate::tx_buf::TxBuf;
        let frame: &[u8] = match &lent {
            Some(slot) => slot.as_slice(),
            None => bytes,
        };
        // The keepalive asks whether the LINE spoke in its tick. A driver that writes inline
        // spoke at the hand-over, so every frame marks it. A driver with a queue speaks later,
        // when its writer gets to the frame, and says so itself
        // ([`BoxedLinkDriver::ms_since_wire_write`], which `keepalive_wake_deadline` reads):
        // only a control frame marks here, and a data frame waiting in the queue is not activity
        // the peer can hear.
        //
        // A frame of a class the link carries apart ([`BoxedLinkDriver::carries_apart`]) is
        // not the link's line speaking: the peer leases that carriage on its own, the driver
        // reports its writes per class, and a mark here would hold the link's own keepalive
        // back while its streams are silent.
        #[cfg(all(feature = "transport-keepalive", feature = "link-wire-reports"))]
        {
            let driver = link.link_driver();
            if !crate::link::BoxedLinkDriver::carries_apart(driver, reliability)
                && (priority == crate::qos::Priority::Control
                    || !crate::link::BoxedLinkDriver::reports_wire_writes(driver))
            {
                link.spoke
                    .store(true, core::sync::atomic::Ordering::Relaxed);
            }
        }
        // Without `link-wire-reports` no driver has a queue or a carriage apart to report, so
        // every frame handed over is the line speaking.
        #[cfg(all(feature = "transport-keepalive", not(feature = "link-wire-reports")))]
        link.spoke
            .store(true, core::sync::atomic::Ordering::Relaxed);

        // R2371 (`transport-stats`) — charge ONE wire write to the counters, on
        // the side the driver's `LinkSendOutcome` puts it.
        //
        // A write the driver ACCEPTED is one transport message of `wire_bytes`
        // on the wire; a write it REFUSED reached no wire at all, so it charges
        // `n_dropped` and leaves `bytes` / `t_msgs` alone — `bytes` is a counter
        // of SENT bytes, and counting a refused write there would make the two
        // disagree about the same event.
        //
        // The `1` is not a magic number: one call of this is one wire write, and
        // one wire write is one transport message in this tree (see the
        // `crate::stats` module docs on `t_msgs`). The byte figure travels with
        // it because `StatDrop` takes both and only the LowPass arm reads the
        // bytes — upstream's shape, kept rather than special-cased here.
        //
        // A CLOSURE rather than a method, deliberately: its only caller is this
        // seam, whose `#[cfg]` is a seventeen-feature union. As a method it
        // needed that union copied verbatim to stay alive in exactly the same
        // builds, and the copy went stale immediately — Layer C1m's no_std lwip
        // build compiles neither, and `-D dead-code` caught the method there.
        // A closure is scoped to the seam by construction, so the two cannot
        // drift apart at all.
        //
        // R2825 — a SENT write also counts on this link's registry cells
        // (`bytes`, `transport_message`), upstream's `LinkStats` pair. A refused
        // write reached no wire and upstream has no registry family for a
        // driver's refusal, so only the JSON `n_dropped` above sees it.
        let count_tx_wire = |_wire_bytes: usize, _outcome: crate::link::LinkSendOutcome| {
            #[cfg(feature = "transport-stats")]
            match _outcome {
                crate::link::LinkSendOutcome::Sent => {
                    self.stats.inc_tx(_wire_bytes);
                    self.record_on_link(link, |metrics, slot| {
                        let tx = crate::stats_registry::StatsDirection::Tx;
                        metrics.inc_bytes(tx, slot, _wire_bytes as u64);
                        metrics.inc_transport_message(tx, slot, 1);
                    });
                }
                crate::link::LinkSendOutcome::Dropped(_) => {
                    self.stats
                        .inc_tx_drop(crate::stats::StatDrop::Transport, 1, _wire_bytes)
                }
            }
        };
        // R2423 (open-debt item 688) — a REFUSED write also has a LIVENESS
        // meaning, and until this round nothing read it. `WriterGone` is
        // produced by SEVEN production drivers — five tokio pipelines
        // (stream, udp, ws, serial, quic-datagram), the accept-side glue, and
        // the lwIP driver; the eighth, `wz-capi-core`'s `InertLinkDriver`, feeds
        // no channel and so has no writer to lose. The two remaining impls are
        // the reconnect seam's FORWARDING wrappers (`SwappableLink` and
        // `LocalSwappableLink` in `crate::reconnect`), and their forwarding is
        // what makes this disposition reach the case that needs it most: a
        // RECONNECTING session is the likeliest one to be holding a dead
        // writer, and if either wrapper had swallowed the inner outcome the
        // gate could never learn about it there. R2371 made them forward for
        // the sibling reason — a swallowed drop would have made `n_dropped`
        // read zero for exactly those sessions.
        //
        // Every one of those refusals was consumed ONLY by the counter above,
        // which is
        // `transport-stats`-gated. On a DEFAULT build the drop was therefore
        // observed by nothing at all, while
        // [`LinkDropCause::WriterGone`]'s own doc said the writes keep dropping
        // "until the session notices the link is down" — a clause naming a
        // mechanism that did not exist.
        //
        // What that cost: the F2 gate ([`Self::session_send_available`]) exists
        // so a data send "rejects typed rather than vanishing into a dead writer
        // channel", but it reads ESTABLISHMENT state only. A sealed writer
        // (`WriterHandle`'s drop, R2367) is a second way for that channel to die
        // and the gate could not see it, so between the seal and the FSM's
        // terminal every send returned success while reaching no wire —
        // `declare_subscriber` answered `Ok` for a subscription whose `Declare`
        // never left the host. wz's REST bridge then served `200 OK` on an SSE
        // stream that could only ever carry keepalives, which is what a consumer
        // reported against a genuine zenohd on 2026-09-07.
        //
        // The disposition is per-cause and the match is EXHAUSTIVE on purpose: a
        // later variant cannot inherit "counted, then ignored" by default, it has
        // to be decided here (`link_drop_disposition_gate.py` grades that the
        // decision is also WITNESSED, exhaustiveness being a decision and not a
        // proof that either arm fires).
        let dispose = |outcome: crate::link::LinkSendOutcome| {
            let crate::link::LinkSendOutcome::Dropped(cause) = outcome else {
                return;
            };
            match cause {
                // TERMINAL for this link: the writer task is gone, so every
                // later write drops identically. Closing the per-link F2 gate is
                // what makes the NEXT send reject typed. Per-link, so a
                // `transport-multilink` session fails the send OVER to a
                // surviving link (`session_send_available` ORs the set) instead
                // of emitting into a dead one.
                crate::link::LinkDropCause::WriterGone => {
                    link.transport_available.close();
                }
                // NOT terminal, and deliberately not gated: one frame exceeded
                // what this link can put in a single write. The link is healthy
                // and the next, smaller write succeeds — closing the gate here
                // would turn a single oversize frame into a dead session.
                crate::link::LinkDropCause::Oversize => {}
                // NOT terminal either: the link had no buffer to give for this
                // frame at this moment. Its pool refills as frames are written,
                // so the next send finds a slot; closing the gate would turn a
                // dry pool into a dead session. (The lend-only profile raises
                // this itself, before a write; a driver that can take a write
                // only into a buffer of its own may report it here.)
                crate::link::LinkDropCause::NoTxSlot => {}
            }
        };
        // transport-compression — once compression is ACTIVE, every
        // post-establishment batch is lz4-wrapped here (the wz analogue of
        // zenoh's finalize-then-write-to-link), and the link layer then
        // length-frames the [BatchHeader][payload] (zenoh's
        // [length][header][payload]). Every condition — negotiated,
        // post-establishment, and NOT on a lean lowlatency link — lives in
        // `compresses_batches`, which the RX un-wrap consults too so the two
        // directions cannot disagree. R311y434 added the lowlatency conjunct: wz
        // used to wrap OUTSIDE the lean encode, which no zenoh peer can read.
        //
        // Fixed-memory step S4 -- the compressed copy of a frame is built in a
        // vector, and the lend-only profile has no heap to build it on and no
        // second slot to build it in: the frame is not sent (the lent slot is
        // dropped unsent when this call returns, which gives it back to its
        // link), counted as a refusal. An image that turns `tx-lend-only` on
        // does not negotiate compression; this arm is what keeps a build that
        // has both honest about it.
        #[cfg(all(feature = "transport-compression", feature = "tx-lend-only"))]
        if link.compresses_batches() {
            let _ = self.refuse(crate::link::LinkDropCause::NoTxSlot);
            return;
        }
        #[cfg(all(feature = "transport-compression", not(feature = "tx-lend-only")))]
        if link.compresses_batches() {
            // A lent slot is NOT sent here: the wire bytes are the compressed
            // copy, so the slot goes back to its link before the copy is
            // handed over, which a link that copies bytes into a slot of its
            // own may need it for.
            let wrapped = crate::compression::compress_batch(frame);
            if let Some(slot) = lent {
                slot.give_back();
            }
            // transport-stats — count the ACTUAL wire bytes (post-compression).
            let driver = link.link_driver();
            let outcome = if urgent {
                crate::link::BoxedLinkDriver::send_urgent(driver, &wrapped, reliability)
            } else {
                crate::link::BoxedLinkDriver::send_prioritized(
                    driver,
                    &wrapped,
                    reliability,
                    priority,
                )
            };
            count_tx_wire(wrapped.len(), outcome);
            dispose(outcome);
            return;
        }
        let wire_len = frame.len();
        let outcome = match lent {
            // The slot the frame was encoded into goes to the link as it is.
            Some(slot) => slot.hand_over(reliability, priority),
            None if urgent => {
                crate::link::BoxedLinkDriver::send_urgent(link.link_driver(), bytes, reliability)
            }
            None => crate::link::BoxedLinkDriver::send_prioritized(
                link.link_driver(),
                bytes,
                reliability,
                priority,
            ),
        };
        count_tx_wire(wire_len, outcome);
        dispose(outcome);
    }

    /// Fixed-memory step S4 — the answer of a lend-only send the link took no slot for: the
    /// cause, counted ([`Self::refusals`]) and, under `transport-stats`, as the dropped
    /// transport message it is, so a dry pool is visible and never silent. Returns `cause` so a
    /// sender hands it on in one expression.
    ///
    /// `WriterGone` is not a refusal the transport raises (a driver's writer is gone: the emit's
    /// disposition closes the gate on it) and is not counted as one.
    #[cfg(all(
    feature = "tx-lend-only",
    any(
        all(
            any(feature = "codec-init-body", feature = "codec-open-body"),
            any(feature = "session-unicast-open", feature = "session-unicast-accept")
        ),
        feature = "codec-close",
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
        feature = "transport-batching",
        // The compression arm of `emit_on_link`, which is compiled where
        // that seam is (its union, which `transport-keepalive` joins).
        all(
            feature = "transport-compression",
            feature = "transport-keepalive"
        ),
    )
))]
    // Out of line, as the emit is: every lend-only refusal reaches it.
    #[inline(never)]
    pub(crate) fn refuse(&self, cause: crate::link::LinkDropCause) -> crate::link::LinkDropCause {
        let word = match cause {
            crate::link::LinkDropCause::NoTxSlot => Some(&self.refused_no_slot),
            crate::link::LinkDropCause::Oversize => Some(&self.refused_oversize),
            crate::link::LinkDropCause::WriterGone => None,
        };
        if let Some(word) = word {
            crate::runtime_cell::WordCell::fetch_add(
                word,
                1,
                core::sync::atomic::Ordering::Relaxed,
            );
        }
        #[cfg(feature = "transport-stats")]
        self.stats
            .inc_tx_drop(crate::stats::StatDrop::Transport, 1, 0);
        cause
    }

    /// Fixed-memory step S4 — the sends this lend-only transport refused, by cause: see
    /// [`TxRefusalCounts`]. Each count wraps at its width, as a counter a host diffs does.
    #[cfg(feature = "tx-lend-only")]
    pub fn refusals(&self) -> TxRefusalCounts {
        let read = |word: &R::Word| {
            crate::runtime_cell::WordCell::load(word, core::sync::atomic::Ordering::Relaxed) as u32
        };
        TxRefusalCounts {
            no_slot: read(&self.refused_no_slot),
            oversize: read(&self.refused_oversize),
        }
    }
}

/// One transport's transmit state with the links its frames leave by, borrowed for a send: the
/// routing of the walk is this value's, and the walk is one body a build whatever made it.
///
/// A unicast session makes it of its core's state, its binding's own link and, when it aggregates
/// links, the core's set of them; nothing in it is a session's. No invariant binds the three: each
/// is a borrow its maker holds already, so they are its fields.
pub struct TxRoute<'a, R: SessionRuntime> {
    /// The transmit state the frames are numbered, staged and counted in.
    pub tx: &'a TransportTx<R>,
    /// The link a frame leaves by when no set routes it, and every per-link control message's.
    pub own: &'a LinkState<R>,
    /// An aggregated session's links, from which each conduit's link is chosen
    /// (`TxRoute::select_link`); empty while the session drives one link.
    #[cfg(feature = "transport-multilink")]
    pub links: &'a std::sync::Mutex<alloc::vec::Vec<R::Shared<LinkState<R>>>>,
}

impl<R: SessionRuntime> TxRoute<'_, R> {
    /// Reliability-routed link selection — the wz mirror of zenoh's per-channel
    /// `select` (`unicast/universal/tx.rs`): pick, among the ALIVE links of the
    /// aggregation set, the one preferring `reliability`'s channel; failing that,
    /// the first alive link (homogeneous / failover). `None` when the set is
    /// EMPTY (a single-link, non-aggregating session — [`Self::send_wire`] then
    /// uses `self.own`) OR when every link is dead (the send then falls through
    /// to `self.own`, whose F2 gate rejects it typed). Reads each link's
    /// `transport_available` (liveness) + its reliability class
    /// (`LinkState::reliability`) under their mutexes.
    ///
    /// R311y205 (slice-1 MF-E) — gated on the EXACT codec union of its sole caller
    /// [`Self::send_wire`]: codec-close + transport-keepalive are EXCLUDED (those
    /// TX paths route through `send_wire_this_link`, not `send_wire`, so a build
    /// with ONLY codec-close / transport-keepalive has no `select_link` caller and
    /// must not carry the dead seam — the same cfg-skew class run-ci caught for
    /// `send_wire`). It names `Reliability` (codec-union-gated import), so a
    /// `transport-multilink`-only build with no data-send codec omits it too.
    #[cfg(all(
        feature = "transport-multilink",
        any(
            feature = "codec-init-body",
            feature = "codec-open-body",
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-interest",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "liveliness-token",
            feature = "transport-batching",
        )
    ))]
    fn select_link(
        &self,
        reliability: crate::reliability::Reliability,
        priority: crate::qos::Priority,
    ) -> Option<R::Shared<LinkState<R>>> {
        let links = self
            .links
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if links.is_empty() {
            return None;
        }
        // A non-qos build carries no per-link priority band, so selection degrades
        // to the reliability-only 2-tier (byte-identical to pre-y217); `priority`
        // is then unused (workspace warnings=deny).
        #[cfg(not(feature = "transport-qos"))]
        let _ = priority;
        let mut first_alive: Option<&R::Shared<LinkState<R>>> = None;
        // partial tier: a reliability-pref match with NO covering priority band
        // (in a non-qos build this IS the pre-y217 "preferred" tier).
        let mut partial: Option<&R::Shared<LinkState<R>>> = None;
        // full tier (qos only): reliability-pref match AND the band contains the
        // priority; keep the SMALLEST band (most specific), ties -> first-seen.
        #[cfg(feature = "transport-qos")]
        let mut full: Option<(&R::Shared<LinkState<R>>, usize)> = None;
        for l in links.iter() {
            if !l.transport_available.is_open() {
                continue;
            }
            if first_alive.is_none() {
                first_alive = Some(l);
            }
            if l.reliability() != Some(reliability) {
                // Wrong reliability class -> only ever a first-alive fallback,
                // zenoh's concrete-reliability primacy: a non-matching link can
                // never be a full/partial pick. A link with no class at all (a
                // driver that names no kind, nothing declared) lands here too.
                continue;
            }
            // Reliability matches. In a qos build a covering band promotes this
            // link to the full tier.
            #[cfg(feature = "transport-qos")]
            if let Some(band) = R::with_mutex_mut(&l.priority_range, |r| *r) {
                if band.contains(priority) {
                    let width = band.width();
                    // Strict `>` (zenoh tx.rs:56): a later equal-width band does
                    // NOT displace the incumbent, so ties resolve to first-seen =
                    // a stable, non-flapping pin (one-conduit=one-link).
                    if full.is_none_or(|(_, prev)| prev > width) {
                        full = Some((l, width));
                    }
                    continue;
                }
            }
            // partial: reliability matches, no covering band.
            if partial.is_none() {
                partial = Some(l);
            }
        }
        #[cfg(feature = "transport-qos")]
        let selected = full.map(|(l, _)| l).or(partial).or(first_alive);
        #[cfg(not(feature = "transport-qos"))]
        let selected = partial.or(first_alive);
        selected.cloned()
    }

    /// R311kw — the one wire-emit seam: mark the link's line as spoken in its
    /// keepalive tick and forward to the link driver. Every production TX path routes
    /// here (handshake t_msg senders, CLOSE, Frame / Fragment emits, the
    /// batch flush) so the keepalive emitter's idle window sees EVERY
    /// send — zenoh-pico parity: `_z_transport_tx_send_t_msg` /
    /// `_send_n_msg_inner` set `_transmitted = true` for every sender
    /// (common/tx.c:98/153); a TX path that bypassed the seam would
    /// make the emitter inject a redundant KeepAlive after real traffic.
    /// The stamp is read outside the slot closure (R294 discipline) and
    /// the slot guard drops before the blocking send so the
    /// non-reentrant MCU mutex never spans link IO.
    ///
    /// cfg = the union of the routed emit bodies (the `Reliability`
    /// import union above): the handshake / close encoders, the
    /// frame_encode consumer-plane union, the batch flush, and the
    /// keepalive emitter. A build with no active wire-emit body must
    /// not carry the dead seam (CI denies warnings on the minimal MCU
    /// lanes).
    // R311y205 — codec-close / transport-keepalive are NOT in this union: the
    // close + keepalive + link-close TX paths route through
    // [`Self::send_wire_this_link`] (per-link control, not reliability-routed),
    // so a build that enables ONLY codec-close / transport-keepalive (e.g. a
    // bare `transport-multicast` MCU lane) has no `send_wire` caller and must
    // not compile the dead seam. `emit_on_link` keeps the full union (both
    // send_wire and send_wire_this_link funnel through it).
    //
    // R311y516 — the establishment codecs are ROLE-CONJOINED here for the same
    // reason one level over: `codec-init-body` / `codec-open-body` describe a
    // CODEC, not an emit. The four senders that route INIT/OPEN through this
    // seam — `send_init_syn` / `send_open_syn` (`session-unicast-open`) and
    // `send_init_ack_with_cookie` / `send_open_ack`
    // (`session-unicast-accept`) — each carry a role conjunct of their own, so
    // a build with an establishment codec and NEITHER role encodes nothing and
    // must not compile the dead seam (`--features session-extqos,
    // codec-init-body` was the combination that reded `-D warnings`).
    //
    // Fixed-memory step S4 — `not(tx-lend-only)`: the lend-only profile has no
    // byte door for a frame built elsewhere. Every message it sends is written
    // into a slot the link lends and leaves through `emit_on_link` directly (the
    // keep-alive, a one-byte constant, through `send_wire_this_link`).
    #[cfg(all(
        not(feature = "tx-lend-only"),
        any(
            all(
                any(feature = "codec-init-body", feature = "codec-open-body"),
                any(feature = "session-unicast-open", feature = "session-unicast-accept")
            ),
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-interest",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "liveliness-token",
            feature = "transport-batching",
        )
    ))]
    pub(crate) fn send_wire(
        &self,
        bytes: &[u8],
        reliability: crate::reliability::Reliability,
        priority: crate::qos::Priority,
    ) {
        // R311y205 (transport-multilink IMPL-2b-iii) — reliability-routed data
        // send: an AGGREGATING session (`select_link` -> Some) emits on the
        // reliability-pref link (else first alive = failover) from the shared
        // link set — the wz mirror of zenoh's per-channel `select`; a SINGLE-link
        // session (empty set -> None) and every NON-feature build emit on this
        // route's own link, byte-identical to today. Keepalive / close
        // are per-link and bypass routing ([`Self::send_wire_this_link`]).
        //
        // R311y217 — `priority` is the SECOND routing key: `select_link` pins each
        // `(priority, reliability)` conduit to one link. Callers MUST pass the
        // priority of the FRAME being emitted (for a batch flush that is the open
        // frame's `batch.priority`, NOT the triggering message's priority — else
        // one conduit splits across links and the peer's per-conduit RX SN gate
        // drops the reorder). A non-multilink build never routes, so the key is
        // unused there.
        //
        // R2919 — and in every build it is the key the link's writer orders its
        // queue by (`BoxedLinkDriver::send_prioritized`).
        #[cfg(feature = "transport-multilink")]
        if let Some(target) = self.select_link(reliability, priority) {
            self.tx
                .emit_on_link(&target, bytes, None, reliability, priority, false);
            return;
        }
        self.tx
            .emit_on_link(self.own, bytes, None, reliability, priority, false);
    }

    /// R311y205 (transport-multilink IMPL-2b-iii) — emit on THIS binding's own
    /// link, bypassing reliability routing. Keepalive and CLOSE are per-link
    /// control (zenoh keepalives each link on its own timer; a link-only close
    /// targets that link), so they must reach the physical link the drive loop
    /// monitors — NOT the reliability-selected data link. At N=1 identical to
    /// [`Self::send_wire`].
    ///
    /// R2919 — `priority` is the lane the link's writer queues the frame on,
    /// and the two callers differ on purpose, as zenoh's do: a keepalive goes
    /// at `crate::qos::Priority::Control` (zenoh's tx task writes it directly, ahead of any
    /// queued batch — `io/zenoh-transport/src/unicast/universal/link.rs`
    /// @ `let n = link.send(&message, Some(crate::qos::Priority::Control)).await?;`), and a
    /// close at `Priority::Background`, BEHIND everything already queued, so
    /// the data a caller sent before closing leaves before the close does
    /// (`io/zenoh-transport/src/unicast/universal/transport.rs`
    /// @ `p.push_transport_message(msg, Priority::Background);`).
    // Fixed-memory step S4 — under `tx-lend-only` a close leaves through
    // `send_control_lent`, so this byte door is the close's alone; the keep-alive
    // leaves through `send_wire_urgent_this_link`.
    // `send_link_close` (multilink) reaches it whichever the profile.
    #[cfg(all(
        feature = "codec-close",
        any(not(feature = "tx-lend-only"), feature = "transport-multilink"),
    ))]
    pub(crate) fn send_wire_this_link(
        &self,
        bytes: &[u8],
        reliability: crate::reliability::Reliability,
        priority: crate::qos::Priority,
    ) {
        self.tx
            .emit_on_link(self.own, bytes, None, reliability, priority, false);
    }

    /// [`Self::send_wire_this_link`] for a message that may overtake what the link has queued
    /// ([`BoxedLinkDriver::send_urgent`](crate::link::BoxedLinkDriver::send_urgent)): the keepalive, which carries no sequence number.
    #[cfg(feature = "transport-keepalive")]
    pub(crate) fn send_wire_urgent_this_link(
        &self,
        bytes: &[u8],
        reliability: crate::reliability::Reliability,
    ) {
        self.tx.emit_on_link(
            self.own,
            bytes,
            None,
            reliability,
            crate::qos::Priority::Control,
            true,
        );
    }

    /// R2923 — run `f` on the link a `(reliability, priority)` conduit's frames
    /// are written to: the one [`Self::send_wire`] routes them to, so a
    /// question asked of it (is there room, count this message) is asked of
    /// the link the frame will actually take. An aggregating session picks it
    /// from its link set; a single-link session and every non-multilink build
    /// has only its own link.
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    ))]
    pub(crate) fn with_conduit_link<O>(
        &self,
        reliability: crate::reliability::Reliability,
        priority: crate::qos::Priority,
        f: impl FnOnce(&LinkState<R>) -> O,
    ) -> O {
        #[cfg(feature = "transport-multilink")]
        if let Some(target) = self.select_link(reliability, priority) {
            return f(&target);
        }
        #[cfg(not(feature = "transport-multilink"))]
        let _ = (reliability, priority);
        f(self.own)
    }

    /// Whether [`Self::send_wire`] would put a `(reliability, priority)` frame
    /// on `link`: the same routing, asked as a question.
    #[cfg(all(feature = "transport-batching", feature = "transport-tx-lend"))]
    pub(crate) fn conduit_routes_to(
        &self,
        link: &LinkState<R>,
        reliability: crate::reliability::Reliability,
        priority: crate::qos::Priority,
    ) -> bool {
        #[cfg(feature = "transport-multilink")]
        if let Some(target) = self.select_link(reliability, priority) {
            return core::ptr::eq(&*target, link);
        }
        #[cfg(not(feature = "transport-multilink"))]
        let _ = (reliability, priority);
        core::ptr::eq(self.own, link)
    }

    /// ARCHITECTURE section 9.1 -- run `f` on the link that records `slot` as
    /// conduit `idx`'s lent batch slot, or on `None` when no link does (the link
    /// that lent it has gone). The record is left as it is: `f` clears it when it
    /// settles the slot.
    ///
    /// The holder is found by WHERE the record is, never by a remembered name: this
    /// binding's own link first, which is one read of its record, then (an
    /// aggregated session) every link of the set, the binding that opened the
    /// frame being free to be another one.
    #[cfg(all(feature = "transport-batching", feature = "transport-tx-lend"))]
    pub(crate) fn with_batch_holder<O>(
        &self,
        idx: usize,
        slot: crate::link::TxSlot,
        f: impl FnOnce(Option<&LinkState<R>>) -> O,
    ) -> O {
        let own = self.own;
        if own
            .batch_slots
            .get(idx)
            .is_some_and(|record| record.holds(slot))
        {
            return f(Some(own));
        }
        #[cfg(feature = "transport-multilink")]
        {
            let found = self
                .links
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .find(|l| {
                    l.batch_slots
                        .get(idx)
                        .is_some_and(|record| record.holds(slot))
                })
                .cloned();
            if let Some(link) = found {
                return f(Some(&*link));
            }
        }
        f(None)
    }

    /// ARCHITECTURE section 9.1 -- close the frame open in a lent slot: send the
    /// slot as the frame, on its own conduit (the frame's R flag and the
    /// conduit's band). The flush paths' half of the append that keeps it open.
    #[cfg(all(feature = "transport-batching", feature = "transport-tx-lend"))]
    fn close_lent_batch(&self, batch: &mut BatchTx, idx: usize, priority: crate::qos::Priority) {
        use crate::tx_buf::TxBuf;
        batch.stage.count = 0;
        let Some(open) = batch.stage.lent.take() else {
            return;
        };
        let lend = &mut batch.lend;
        self.with_batch_holder(idx, open.slot(), |found| {
            let Some(link) = found else {
                // The link that lent the slot has gone and gave it back as it went.
                lend.lost = lend.lost.wrapping_add(1);
                return;
            };
            let _ = link
                .batch_slots
                .get(idx)
                .and_then(crate::session_actions::LentRecord::take);
            // SAFETY: `link` recorded the slot for this conduit until the line above, and every
            // send or abort of a conduit's lent slot clears the record first, under the
            // conduit's lock, which the caller holds (`batch`).
            let mut slot = unsafe { crate::tx_lease::TxLease::pick_up(link.link_driver(), open) };
            let channel = crate::frame_encode::frame_wire_reliability(slot.as_slice());
            self.send_lent_batch(link, &mut slot, channel, priority, lend);
        });
    }

    /// ARCHITECTURE section 9.1 -- send a closed batch frame that lives in a
    /// slot `link` lent. When the conduit still routes to that link the slot is
    /// handed over as it is (`TransportTx::emit_on_link`, the one emit seam): the flush
    /// copies nothing. When it does not (an aggregated session moved the conduit
    /// to another link meanwhile), the frame is copied out, the slot goes back
    /// to its lender, and the bytes take the route the heap stage's frame would
    /// take (`TxRoute::send_wire`), counted `moved_to_heap`.
    ///
    /// The lease is borrowed and settled here, handed over or given back, so its drop where the
    /// caller picked it up finds nothing to give back. Taken by value it would be copied whole into
    /// a second lease on the send of every message that does not join the open frame.
    #[cfg(all(feature = "transport-batching", feature = "transport-tx-lend"))]
    pub(crate) fn send_lent_batch(
        &self,
        link: &LinkState<R>,
        slot: &mut crate::tx_lease::TxLease<'_, R::Driver>,
        channel: crate::reliability::Reliability,
        priority: crate::qos::Priority,
        lend: &mut BatchLendCounts,
    ) {
        #[cfg(not(feature = "tx-lend-only"))]
        use crate::tx_buf::TxBuf;
        if self.conduit_routes_to(link, channel, priority) {
            self.tx
                .emit_on_link(link, &[], Some(slot), channel, priority, false);
            return;
        }
        // Fixed-memory step S4 — the conduit now routes to another link, which
        // can send only a slot IT lent, and the heap copy that stood in for one is
        // not available under `tx-lend-only`: the frame is given up, counted as
        // lost and as a refusal. (Only an aggregating session gets here, and
        // `transport-multilink` is outside what the lend-only profile covers.)
        #[cfg(feature = "tx-lend-only")]
        {
            slot.give_back();
            lend.lost = lend.lost.wrapping_add(1);
            let _ = self.tx.refuse(crate::link::LinkDropCause::NoTxSlot);
            let _ = (channel, priority);
        }
        #[cfg(not(feature = "tx-lend-only"))]
        {
            let bytes = slot.as_slice().to_vec();
            slot.give_back();
            lend.moved_to_heap = lend.moved_to_heap.wrapping_add(1);
            self.send_wire(&bytes, channel, priority);
        }
    }

    /// Send the frame open in one conduit, under that conduit's lock (`batch`): the body of
    /// the walks of `SessionLinkActions::flush_open_batch` and
    /// `SessionLinkActions::try_flush_open_batch`, and of a send that finds a frame open it does
    /// not join. Out of line: that send is every message's, and the frame is open there only
    /// while replies are held or a window is drained.
    #[cfg(feature = "transport-batching")]
    #[inline(never)]
    pub(crate) fn flush_conduit(
        &self,
        idx: usize,
        priority: crate::qos::Priority,
        batch: &mut BatchTx,
    ) {
        // Lowered before the frame is taken, under the lock that keeps a control message from
        // being staged in between: whatever control message the mark stood for leaves here.
        #[cfg(feature = "transport-qos")]
        if idx == TxConduits::<R>::conduit_index(crate::qos::Priority::Control) {
            self.tx.conduits.control_taken();
        }
        // ARCHITECTURE section 9.1 -- a frame open in a lent slot leaves
        // as that slot, with nothing copied.
        //
        // Fixed-memory step S4 — under `tx-lend-only` no frame is staged
        // on the heap, so a conduit with no lent frame open has nothing
        // to drain, and this is all the drain there is.
        #[cfg(feature = "tx-lend-only")]
        if batch.stage.lent.is_some() {
            self.close_lent_batch(batch, idx, priority);
        }
        #[cfg(all(feature = "transport-tx-lend", not(feature = "tx-lend-only")))]
        if batch.stage.lent.is_some() {
            self.close_lent_batch(batch, idx, priority);
            return;
        }
        #[cfg(not(feature = "tx-lend-only"))]
        {
            let stage = &mut batch.stage;
            if stage.buf.is_empty() {
                return;
            }
            stage.count = 0;
            let frame = core::mem::take(&mut stage.buf);
            let channel = crate::frame_encode::frame_wire_reliability(&frame);
            // Route each frame by its OWN conduit (y217 #3) — this drain path
            // carries no caller priority, so the band comes from the walk.
            self.send_wire(&frame, channel, priority);
        }
    }

    /// Send the frames open in the conduits whose index `takes` answers `true` for, in
    /// ascending band, each under its own lock: waited for when `wait`, and otherwise taken only
    /// if free. Whether every conduit walked was taken and drained; a conduit whose lock a
    /// sender held is left as it was.
    // One body for every walk: generic over the predicate it was one inlined copy per caller.
    #[cfg(feature = "transport-batching")]
    #[inline(never)]
    pub(crate) fn drain_conduits(&self, takes: &dyn Fn(usize) -> bool, wait: bool) -> bool {
        let mut every_conduit = true;
        for idx in (0..TX_CONDUITS).filter(|&idx| takes(idx)) {
            // The walk is over BANDS, not slots: the index names a priority and
            // the priority selects its conduit, so the drain and the staging
            // seam agree by construction on which conduit is which.
            let priority = TxConduits::<R>::conduit_priority(idx);
            let conduit = self.tx.conduits.conduit(priority);
            let drain = |batch: &mut BatchTx| self.flush_conduit(idx, priority, batch);
            if wait {
                R::with_mutex_mut(conduit, drain);
            } else {
                // `None`: held by a sender, who will ask again. Nothing is open in this call's
                // view of that conduit that the sender's own call does not own.
                every_conduit &= R::try_with_mutex_mut(conduit, drain).is_some();
            }
        }
        every_conduit
    }

    /// Send the batches open in slots `link` lent, each as its conduit's flush sends it
    /// ([`Self::flush_conduit`]), under that conduit's lock taken only if free: the caller holds
    /// its own conduit's, and a conduit a sender holds is that sender's to send. Whether any
    /// conduit was taken, so a slot may have come back.
    #[cfg(all(
        feature = "transport-batching",
        feature = "transport-tx-lend",
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "declare-interest",
            feature = "liveliness-token",
        )
    ))]
    fn send_open_lent_batches(&self, link: &LinkState<R>) -> bool {
        let mut taken = false;
        for (idx, record) in link.batch_slots.iter().enumerate() {
            if !record.is_held() {
                continue;
            }
            let priority = TxConduits::<R>::conduit_priority(idx);
            taken |= R::try_with_mutex_mut(self.tx.conduits.conduit(priority), |batch| {
                self.flush_conduit(idx, priority, batch)
            })
            .is_some();
        }
        taken
    }

    /// ARCHITECTURE section 9.1 -- a slot `link` lends for one frame or control message of this
    /// session, the lend of every message the session encodes into a slot. A conduit keeps the
    /// slot of its open batch across the calls of a window, so a link may find every slot held by
    /// batches that could leave now while another conduit has a frame to open: those batches are
    /// sent first, out of their band's turn (each conduit's frames keep their own SN order), and
    /// the slot that frees is lent. `None` only when the link has none even then, which a link
    /// that lends [`crate::link::SESSION_TX_SLOTS`] of its own never answers.
    #[cfg(all(
        feature = "transport-tx-lend",
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "declare-interest",
            feature = "liveliness-token",
            all(
                feature = "tx-lend-only",
                any(
                    all(
                        any(feature = "codec-init-body", feature = "codec-open-body"),
                        any(feature = "session-unicast-open", feature = "session-unicast-accept")
                    ),
                    feature = "codec-close",
                )
            ),
        )
    ))]
    pub(crate) fn lease_on<'l>(
        &self,
        link: &'l LinkState<R>,
        want: usize,
        priority: crate::qos::Priority,
    ) -> Option<crate::tx_lease::TxLease<'l, R::Driver>> {
        let driver = link.link_driver();
        if let Some(slot) = crate::tx_lease::TxLease::acquire(driver, want, priority) {
            return Some(slot);
        }
        // With one conduit the only batch a link can hold open is the caller's, whose lock it
        // holds: there is nothing else to send. A build that sends no data opens no batch.
        #[cfg(all(
            feature = "transport-batching",
            any(
                feature = "codec-push",
                feature = "codec-request",
                feature = "codec-response",
                feature = "codec-response-final",
                feature = "declare-keyexpr",
                feature = "declare-subscriber",
                feature = "declare-queryable",
                feature = "declare-token",
                feature = "declare-interest",
                feature = "liveliness-token",
            )
        ))]
        if TX_CONDUITS > 1 && self.send_open_lent_batches(link) {
            return crate::tx_lease::TxLease::acquire(driver, want, priority);
        }
        None
    }

    /// The lend of one transport message written whole into a slot `link` lends, a frame the
    /// batch window never keeps open (a lean frame, a fragment) or a handshake or close message:
    /// the slot asked for ([`Self::lease_on`]), `write` putting the message into it, and the
    /// slot sent through `TransportTx::emit_on_link`. A link that lent no slot is `Lend::NoSlot`; a
    /// message `write` refused, a slot too short for it among the reasons, is `Lend::Refused`,
    /// and the lease's drop gives the slot back unsent.
    ///
    /// Out of line, with the message's writer a trait object: every such send is this one body,
    /// and none carries the lend, the refusal and the emit again.
    #[cfg(any(
        all(
            feature = "transport-tx-lend",
            any(feature = "transport-lowlatency", feature = "transport-fragmentation"),
            any(
                feature = "codec-push",
                feature = "codec-request",
                feature = "codec-response",
                feature = "codec-response-final",
                feature = "declare-keyexpr",
                feature = "declare-subscriber",
                feature = "declare-queryable",
                feature = "declare-token",
                feature = "declare-interest",
                feature = "liveliness-token",
            )
        ),
        all(
            feature = "tx-lend-only",
            any(
                all(
                    any(feature = "codec-init-body", feature = "codec-open-body"),
                    any(feature = "session-unicast-open", feature = "session-unicast-accept")
                ),
                feature = "codec-close",
            )
        ),
    ))]
    #[inline(never)]
    pub(crate) fn send_lent_on(
        &self,
        link: &LinkState<R>,
        reliability: crate::reliability::Reliability,
        priority: crate::qos::Priority,
        want: usize,
        write: &dyn LentWrite,
    ) -> Lend<sce_forge_runtime::codec::CodecError> {
        // Lent from where `acquire` wrote it, as `write_n_msg` lends its slot.
        let mut lent = self.lease_on(link, want, priority);
        let Some(slot) = lent.as_mut() else {
            return Lend::NoSlot;
        };
        if let Err(why) = write.write_lent(&mut *slot) {
            return Lend::Refused(why);
        }
        self.tx
            .emit_on_link(link, &[], Some(slot), reliability, priority, false);
        Lend::Sent
    }

    /// The lend for a path that writes its own frame (a lean frame, a fragment): the link
    /// `send_wire` would route to lends the slot ([`Self::send_lent_on`]). A `Frame`'s lend is
    /// `Self::write_n_msg`.
    ///
    /// `write` answers whether the slot now holds a frame to send. `Err(why)`
    /// abandons the slot (the lease's drop gives it back) and the caller encodes
    /// on the heap, so the answer is also how a path says "this frame does not
    /// fit, or must be cut up", in its own words (`Lend::Refused`); a link
    /// that lent no slot at all is `Lend::NoSlot`. The decision belongs to the
    /// path, and the slot, the routing and the single send funnel do not.
    #[cfg(all(
        feature = "transport-tx-lend",
        any(feature = "transport-lowlatency", feature = "transport-fragmentation"),
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "declare-interest",
            feature = "liveliness-token",
        )
    ))]
    pub(crate) fn send_lent(
        &self,
        reliability: crate::reliability::Reliability,
        priority: crate::qos::Priority,
        want: usize,
        write: &dyn LentWrite,
    ) -> Lend<sce_forge_runtime::codec::CodecError> {
        self.with_conduit_link(reliability, priority, |link| {
            self.send_lent_on(link, reliability, priority, want, write)
        })
    }

    /// Whether the link a frame of `reliability` and `priority` leaves by stayed full for what is
    /// left of `deadline`, which the ask spends. A sender that holds the room (`reserved`, see
    /// `DispatchStage::Reserved`) asks nothing: asking would count its own promise against the
    /// lane and find it full when it is exactly full enough. One body for every ask a send makes
    /// before its frame takes an SN.
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    ))]
    pub(crate) fn congested_within(
        &self,
        reliability: crate::reliability::Reliability,
        priority: crate::qos::Priority,
        reserved: bool,
        deadline: &mut crate::tx_deadline::PushDeadline,
    ) -> bool {
        if reserved {
            return false;
        }
        // The room of the queue this message's class leaves by: a best-effort message on a link
        // that carries it apart never waits for its streams' room.
        let answer = self.with_conduit_link(reliability, priority, |link| {
            link.link_driver()
                .wait_for_room_for(reliability, priority, deadline.ask())
        });
        deadline.spend(answer.waited_us);
        answer.room == crate::link::LinkRoom::Congested
    }

    /// The frame one message goes into, in one body from the open frame to the answer, for every
    /// build. In the batch window (`in_window`) the message first joins the frame its conduit
    /// holds open, in a lent slot or, in a build with a heap, on the heap, which needs no room
    /// check; a frame it does not join, of the other reliability or with no room left for it, is
    /// sent, once, rolled back to the messages it held, and a fresh one opens. To open one, the
    /// conduit's link is asked for room out of `emit`'s deadline (none when the sender holds it,
    /// `reserved`) and, with `transport-tx-lend`, for a slot: of the whole batch budget for a
    /// window's frame and for every frame of a lend-only build, of the message's worst case for a
    /// frame a build with a heap sends whole. The SN is minted once a slot is lent, and the frame
    /// is written into the slot held to the budget, kept open for the messages after it in the
    /// window or sent at once. A message past the budget leaves as a chain of lent fragments. A
    /// frame no slot takes (none lent, one short of the frame, or without fragmentation one past
    /// the budget) is written on the heap by a build that has one, its SN given back and minted
    /// again there, and refused by a lend-only build, which has no answer in the heap; a message
    /// its encoder refuses is refused in either, and an SN minted for a frame that does not leave
    /// is given back.
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    ))]
    #[inline(never)]
    pub(crate) fn write_n_msg(
        &self,
        batch: &mut BatchTx,
        in_window: bool,
        priority: crate::qos::Priority,
        reserved: bool,
        mut emit: FrameEmit,
        encode_body: &dyn crate::tx_buf::WireWrite,
    ) -> Result<UnicastPush, crate::send_wire_error::SendWireError> {
        let reliability = crate::reliability::Reliability::from_reliable_bool(emit.reliable);
        // The frame the conduit holds open in a lent slot takes a message of its reliability while
        // the budget it was held to has room, which it had when it opened. A message of the other
        // reliability, or one the frame has no room left for, sends it, once, rolled back to the
        // messages it held, and opens the next frame below.
        #[cfg(all(feature = "transport-batching", feature = "transport-tx-lend"))]
        if in_window {
            if let Some(open) = batch.stage.lent.take() {
                use crate::tx_buf::TxBuf;
                let idx = TxConduits::<R>::conduit_index(priority);
                // Found where it was put down, under the conduit's lock the caller holds: no other
                // lock is taken and the driver is asked nothing. Its lender is this binding's own
                // link for every session but an aggregated one whose conduit moved.
                let joined = self.with_batch_holder(idx, open.slot(), |found| {
                    let Some(link) = found else {
                        // No link records the slot: the link that lent it has gone and gave it
                        // back as it went, and the open frame with it.
                        batch.stage.count = 0;
                        batch.lend.lost = batch.lend.lost.wrapping_add(1);
                        return false;
                    };
                    // SAFETY: `link` records the slot for this conduit, so it lent it, and every
                    // send or abort of a conduit's lent slot clears the record first, under the
                    // conduit's lock, which the caller holds (`batch`): the slot is still lent and
                    // unsettled.
                    let mut slot =
                        unsafe { crate::tx_lease::TxLease::pick_up(link.link_driver(), open) };
                    let open_channel = crate::frame_encode::frame_wire_reliability(slot.as_slice());
                    if open_channel == reliability {
                        let wpos = slot.len();
                        let appended = {
                            let mut sink = crate::tx_buf::TxSink::new(&mut slot);
                            encode_body.write_body(&mut sink).is_ok()
                        };
                        if appended {
                            batch.stage.count = batch.stage.count.saturating_add(1);
                            batch.stage.lent = Some(slot.keep_open());
                            return true;
                        }
                        slot.truncate(wpos);
                    }
                    let _ = link
                        .batch_slots
                        .get(idx)
                        .and_then(crate::session_actions::LentRecord::take);
                    batch.stage.count = 0;
                    self.send_lent_batch(link, &mut slot, open_channel, priority, &mut batch.lend);
                    false
                });
                if joined {
                    return Ok(UnicastPush::Pushed);
                }
            }
        }
        // The same for a frame open on the heap, which a lent slot did not take when it opened.
        // The frame's own R flag names the conduit it leaves on (R311y222): a frame never mixes
        // the two, as zenoh's per-(priority, reliability) frame does not
        // (`zenoh-codec` `CurrentFrame`/`NewFrame`), where zenoh-pico appends a message of either
        // reliability to whatever frame is open (`tx.c` `_z_transport_tx_send_n_msg_inner`).
        #[cfg(all(feature = "transport-batching", not(feature = "tx-lend-only")))]
        if in_window && !batch.stage.buf.is_empty() {
            let stage = &mut batch.stage;
            let open_channel = crate::frame_encode::frame_wire_reliability(&stage.buf);
            if open_channel == reliability {
                let wpos = stage.buf.len();
                let appended = {
                    let mut sink = crate::tx_buf::TxSink::new(&mut stage.buf);
                    encode_body.write_body(&mut sink)
                };
                if let Err(refused) = appended {
                    // The body refused its message: its partial bytes are rolled back and the
                    // frame open before it stays as it was.
                    stage.buf.truncate(wpos);
                    return Err(crate::send_wire_error::SendWireError::Codec(refused));
                }
                if stage.buf.len() <= emit.mtu {
                    // One more message than the frame held, which holds at most a batch.
                    stage.count = stage.count.saturating_add(1);
                    return Ok(UnicastPush::Pushed);
                }
                // Overflow (zenoh-pico's `_z_transport_tx_batch_overflow`): rolled back, and
                // the frame leaves before the next opens.
                stage.buf.truncate(wpos);
            }
            let prev = core::mem::take(&mut stage.buf);
            stage.count = 0;
            self.send_wire(&prev, open_channel, priority);
        }
        if self.congested_within(reliability, priority, reserved, &mut emit.deadline) {
            return Ok(UnicastPush::Congested);
        }
        // A build without batching opens no window, and has no open frame to join.
        #[cfg(not(feature = "transport-batching"))]
        let in_window = {
            let _ = in_window;
            false
        };
        // A build that neither batches nor lends reads it nowhere else.
        #[cfg(not(any(feature = "transport-batching", feature = "transport-tx-lend")))]
        let _ = in_window;
        // Why a window's frame is staged on the heap, counted once it is.
        #[cfg(all(
            feature = "transport-batching",
            feature = "transport-tx-lend",
            not(feature = "tx-lend-only")
        ))]
        let mut heap_why = HeapStage::NoSlot;
        // A lend-only build asks for the whole budget for every frame, as zenoh-pico's batch is the
        // budget whatever it carries, so nothing measures a message before it is written; a build
        // with a heap asks that for a window's frame, which grows to it, and the message's worst
        // case for a frame sent whole.
        #[cfg(feature = "tx-lend-only")]
        let want = emit.mtu;
        #[cfg(all(feature = "transport-tx-lend", not(feature = "tx-lend-only")))]
        let want = if in_window {
            emit.mtu
        } else {
            // The widest prefix and a possible ext_qos, as the heap frame reserves.
            emit.worst_case_payload.saturating_add(1 + 10 + 2)
        };
        // A window in its conduit's band, a frame sent whole on the conduit its ext_qos names, as
        // the heap frame's send does.
        #[cfg(feature = "transport-tx-lend")]
        let lend_priority = if in_window {
            priority
        } else {
            emit.ext_qos.unwrap_or(crate::qos::Priority::DEFAULT)
        };
        // The SN is minted where the frame is written, once a slot was lent: a link that lent none
        // leaves it unminted, and a frame that does not leave gives it back below.
        #[cfg(feature = "transport-tx-lend")]
        let mut minted: Option<crate::sn::Sn> = None;
        #[cfg(feature = "transport-tx-lend")]
        let lent = self.with_conduit_link(reliability, lend_priority, |link| {
            use sce_forge_runtime::codec::CodecError;
            // Lent from where `acquire` wrote it: bound out of its `Option` it would be copied
            // first.
            let mut lease = self.lease_on(link, want, lend_priority);
            let Some(slot) = lease.as_mut() else {
                return FrameLend::Heap;
            };
            // A window's frame grows across calls up to the whole budget, which a shorter slot
            // would close earlier than the budget does: refused before an SN is minted for it.
            if in_window && slot.capacity() < emit.mtu {
                #[cfg(all(feature = "transport-batching", not(feature = "tx-lend-only")))]
                {
                    heap_why = HeapStage::ShortSlot;
                }
                return FrameLend::Heap;
            }
            // Over a slot that holds the whole budget a frame that crosses it is past the budget;
            // over a shorter one the slot is what is short.
            let whole_budget = slot.capacity() >= emit.mtu;
            let sn = self.tx.frame_sn.mint(priority, emit.reliable, emit.sn_mask);
            minted = Some(sn);
            // Held to the budget, so a message past it is refused where it crosses it and its
            // payload is not copied in; a window kept open keeps the hold for what is appended.
            slot.hold_to(emit.mtu);
            let written = crate::frame_encode::encode_frame_envelope_into(
                slot,
                crate::sn::to_wire(sn),
                crate::frame_encode::frame_flags(emit.reliable),
                emit.ext_qos,
                crate::tx_buf::wire_body(encode_body),
            );
            match written {
                Ok(()) => {}
                Err(CodecError::BufferOverflow) if whole_budget => return FrameLend::PastMtu,
                Err(CodecError::BufferOverflow) => return FrameLend::Heap,
                // An encoder's refusal in a window's slot takes the oversize path, which measures
                // the message again and answers the refusal (`emit_fragments_encoded`).
                Err(_) if in_window => return FrameLend::PastMtu,
                Err(refused) => return FrameLend::Refused(refused),
            }
            #[cfg(feature = "transport-batching")]
            if in_window {
                let idx = TxConduits::<R>::conduit_index(priority);
                if let Some(stale) = link
                    .batch_slots
                    .get(idx)
                    .and_then(crate::session_actions::LentRecord::take)
                {
                    // A record with no open frame naming it: the stage and the link disagree,
                    // which the shared conduit lock rules out. Give the slot back rather than
                    // lose it, and say so.
                    link.link_driver().tx_slot_abort(stale);
                    batch.lend.lost = batch.lend.lost.wrapping_add(1);
                }
                batch.lend.slot_frames = batch.lend.slot_frames.wrapping_add(1);
                // A link whose slots come from a pool the session's other links share keeps none
                // past this message while the pool has no other free: the frame leaves now with
                // this message alone, as the window's flush would send it, and the next link that
                // asks for a slot finds one.
                #[cfg(feature = "session-unicast-accept")]
                let keeps = link.link_driver().tx_slot_spare();
                #[cfg(not(feature = "session-unicast-accept"))]
                let keeps = true;
                if keeps {
                    let open = lease.take().map(crate::tx_lease::TxLease::keep_open);
                    if let (Some(record), Some(open)) = (link.batch_slots.get(idx), open.as_ref()) {
                        record.hold(open.slot());
                    }
                    batch.stage.lent = open;
                    batch.stage.count = 1;
                    return FrameLend::Sent;
                }
                batch.stage.count = 0;
            }
            self.tx
                .emit_on_link(link, &[], Some(slot), reliability, lend_priority, false);
            FrameLend::Sent
        });
        #[cfg(feature = "transport-tx-lend")]
        if let Some(sn) = minted {
            emit.sn = sn;
        }
        // A window counts its own opening (above); a frame sent whole is counted here.
        #[cfg(feature = "transport-tx-lend")]
        if lent == FrameLend::Sent && !in_window {
            batch.frame_lend.slot_frames = batch.frame_lend.slot_frames.wrapping_add(1);
        }
        #[cfg(feature = "tx-lend-only")]
        {
            match lent {
                FrameLend::Sent => Ok(UnicastPush::Pushed),
                #[cfg(feature = "transport-fragmentation")]
                FrameLend::PastMtu => self.emit_fragments_encoded(batch, encode_body, emit),
                #[cfg(not(feature = "transport-fragmentation"))]
                FrameLend::PastMtu => {
                    // What only a fragment chain reads is unread here, as in
                    // `emit_frame_or_fragments` without fragmentation.
                    let _ = (
                        emit.sn,
                        emit.sn_mask,
                        emit.max_reassembly_bytes,
                        emit.deadline,
                    );
                    // The frame took the SN it was written with before it crossed the budget:
                    // given back, as a refused encode's is, or the conduit's next frame leaves a
                    // gap in a reliable channel that no frame fills.
                    self.tx.frame_sn.unmint(priority, emit.reliable);
                    Err(crate::send_wire_error::SendWireError::LinkRefused(
                        self.tx.refuse(crate::link::LinkDropCause::Oversize),
                    ))
                }
                // No slot, or one short of the frame. A slot that was lent and then found short
                // took the SN its frame was written with, which is given back, as a refused
                // encode's is, so the conduit's next frame carries it: kept, it would be a gap in a
                // reliable channel that no frame fills. A link that lent none took no SN.
                FrameLend::Heap => {
                    if minted.is_some() {
                        self.tx.frame_sn.unmint(priority, emit.reliable);
                    }
                    Err(crate::send_wire_error::SendWireError::LinkRefused(
                        self.tx.refuse(crate::link::LinkDropCause::NoTxSlot),
                    ))
                }
                // Refused before a byte left: the SN minted for it is given back.
                FrameLend::Refused(refused) => {
                    self.tx.frame_sn.unmint(priority, emit.reliable);
                    Err(crate::send_wire_error::SendWireError::Codec(refused))
                }
            }
        }
        #[cfg(all(feature = "transport-tx-lend", not(feature = "tx-lend-only")))]
        match lent {
            FrameLend::Sent => return Ok(UnicastPush::Pushed),
            #[cfg(feature = "transport-fragmentation")]
            FrameLend::PastMtu => return self.emit_fragments_encoded(batch, encode_body, emit),
            // Refused before a byte left: the SN minted for it is given back.
            FrameLend::Refused(refused) => {
                self.tx.frame_sn.unmint(priority, emit.reliable);
                return Err(crate::send_wire_error::SendWireError::Codec(refused));
            }
            // Written on the heap below, under the SN given back here, which is the one the heap
            // frame mints: nothing else takes one while the conduit's lock is held.
            _ => {
                if minted.is_some() {
                    self.tx.frame_sn.unmint(priority, emit.reliable);
                }
                if !in_window {
                    batch.frame_lend.heap_frames = batch.frame_lend.heap_frames.wrapping_add(1);
                }
            }
        }
        // The heap frame, for every frame no lent slot took: under the conduit's lock the SN is
        // minted, the frame written and emitted (zenoh-pico's TX mutex, R311kf).
        #[cfg(not(feature = "tx-lend-only"))]
        {
            emit.sn = self.tx.frame_sn.mint(priority, emit.reliable, emit.sn_mask);
            #[cfg(feature = "transport-batching")]
            if in_window {
                let stage = &mut batch.stage;
                // +2 for a possible ext_qos ([0x31][VLE(priority)]) that begin_frame may append
                // (symmetric with encode_frame_envelope).
                stage
                    .buf
                    .reserve(emit.worst_case_payload.saturating_add(1 + 10 + 2));
                let staged = match crate::frame_encode::begin_frame(
                    &mut stage.buf,
                    crate::sn::to_wire(emit.sn),
                    crate::frame_encode::frame_flags(emit.reliable),
                    emit.ext_qos,
                ) {
                    Ok(()) => {
                        let mut sink = crate::tx_buf::TxSink::new(&mut stage.buf);
                        encode_body.write_body(&mut sink)
                    }
                    Err(refused) => Err(refused),
                };
                if let Err(refused) = staged {
                    // The body refused its message: the frame it opened is dropped whole and its
                    // SN given back, before a byte left.
                    stage.buf.clear();
                    stage.count = 0;
                    self.tx.frame_sn.unmint(priority, emit.reliable);
                    return Err(crate::send_wire_error::SendWireError::Codec(refused));
                }
                if stage.buf.len() > emit.mtu {
                    // The message alone is past the budget, which no batch carries: it leaves by
                    // the oversize path, still under the lock, and the stage is left empty, so a
                    // refusal there stages nothing for a later flush to send half of.
                    let frame = core::mem::take(&mut stage.buf);
                    stage.count = 0;
                    return self.emit_frame_or_fragments(batch, &frame, emit);
                }
                stage.count = 1;
                #[cfg(feature = "transport-tx-lend")]
                batch.lend.count_heap(heap_why);
                return Ok(UnicastPush::Pushed);
            }
            let wire = match crate::frame_encode::encode_frame_envelope(
                crate::sn::to_wire(emit.sn),
                crate::frame_encode::frame_flags(emit.reliable),
                emit.worst_case_payload,
                emit.ext_qos,
                crate::tx_buf::wire_body(encode_body),
            ) {
                Ok(wire) => wire,
                // The body refused its message: refused before a byte left, with its SN given
                // back.
                Err(refused) => {
                    self.tx.frame_sn.unmint(priority, emit.reliable);
                    return Err(crate::send_wire_error::SendWireError::Codec(refused));
                }
            };
            self.emit_frame_or_fragments(batch, &wire, emit)
        }
    }

    /// R311jq — terminal emit for one already-encoded outbound frame:
    /// send as-is when it fits `mtu`, else re-frame the network-message
    /// body as a `T_MID_FRAGMENT` chain (zenoh-pico
    /// `_z_transport_tx_send_fragment` parity). Shared by the immediate
    /// path and the batching oversize arm so the fragment decision stays
    /// in one place.
    ///
    /// The FRAME body is the tail after the 1-byte header + `VLE(sn)`;
    /// slice it rather than re-encoding (`vle_width` = base-128 width of
    /// `sn`). The oversize FRAME's already-minted `sn` IS the first
    /// fragment's SN; the chain reserves only the `count - 1` follow-on SNs
    /// (`fragment_body` projects the walk onto the ring of `sn_mask`, R311kb),
    /// so the chunk SNs are ring-consecutive from `sn` with NO skipped SN
    /// (R311y206 — matching zenoh `pipeline.rs` + the
    /// `multicast_frame_or_fragments` twin; the pre-y206 code discarded `sn`
    /// and reserved a fresh block, leaving a 1-SN wire gap). The caller's `sn`
    /// mint and this follow-on reserve both run inside the one conduit-lock
    /// hold, so the split reservation is atomic w.r.t. a concurrent sender
    /// (the reassembly dispatcher aborts a non-consecutive chain).
    ///
    /// Fixed-memory step S4 — the heap frame's terminal emit: under
    /// `tx-lend-only` there is no heap frame to emit, so the function is not
    /// compiled (its callers are the heap arms, which are not either).
    #[cfg(all(
        not(feature = "tx-lend-only"),
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "declare-interest",
            feature = "liveliness-token",
        )
    ))]
    fn emit_frame_or_fragments(
        &self,
        batch: &mut BatchTx,
        frame: &[u8],
        emit: FrameEmit,
    ) -> Result<UnicastPush, crate::send_wire_error::SendWireError> {
        let FrameEmit {
            ext_qos,
            sn,
            reliable,
            mtu,
            ..
        } = emit;
        let reliability = if reliable {
            crate::reliability::Reliability::Reliable
        } else {
            crate::reliability::Reliability::BestEffort
        };
        #[cfg(feature = "transport-fragmentation")]
        {
            if frame.len() > mtu {
                // R311y215 — strip the frame's own ext_qos (if any) along with the
                // header + VLE(sn): the fragments re-frame their OWN ext_qos,
                // so `body` must be ONLY the NetworkMessage batch (else the stale
                // `[0x31][priority]` prepends to the reassembled batch and breaks
                // the peer's parse_frame_payload).
                let body =
                    crate::frame_encode::frame_wire_body(frame, crate::sn::to_wire(sn), ext_qos);
                return self.emit_fragment_chain(
                    batch,
                    crate::frame_encode::FragmentBody::Bytes(body),
                    body.len(),
                    emit,
                );
            }
        }
        // Without fragmentation a frame past the budget leaves whole, so what
        // only a chain reads is unread here.
        #[cfg(not(feature = "transport-fragmentation"))]
        let _ = (
            batch,
            sn,
            mtu,
            emit.sn_mask,
            emit.max_reassembly_bytes,
            emit.deadline,
        );
        // The frame's conduit reconstructed from its own ext_qos (`Some(p)` iff
        // `p != DEFAULT`, else `None -> DEFAULT`) — the same key the SN mint used.
        self.send_wire(
            frame,
            reliability,
            ext_qos.unwrap_or(crate::qos::Priority::DEFAULT),
        );
        Ok(UnicastPush::Pushed)
    }

    /// ARCHITECTURE section 9.1 -- the oversize message cut into a chain WITHOUT
    /// being written out whole: `encode_body` is measured (nothing is written),
    /// and each fragment is then encoded straight into a slot the conduit's link
    /// lends, the encoder keeping only that fragment's range of the message
    /// (`frame_encode::write_fragment`). A message moves once, from the
    /// application into the slots that leave, where the heap form moved it into
    /// a frame vector and again into a vector per fragment.
    ///
    /// The chain is the heap chain byte for byte -- the same plan, the same head
    /// writer, the same SN walk -- and every rule of the heap chain (the cap, the
    /// fragment budget, the room before each further fragment, the stop
    /// fragment) is [`Self::emit_fragment_chain`]'s, shared. Reached only once a
    /// lent slot of the whole budget has refused the frame, so `emit.sn` is
    /// minted and the frame is known to be past `emit.mtu`.
    #[cfg(all(
        feature = "transport-fragmentation",
        feature = "transport-tx-lend",
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "declare-interest",
            feature = "liveliness-token",
        )
    ))]
    // Cold and out of line: a message past the budget is the rare send, and inlined into each of
    // its three callers the chain's walk would be copied into the hot frame writers with it.
    #[cold]
    #[inline(never)]
    fn emit_fragments_encoded(
        &self,
        batch: &mut BatchTx,
        encode_body: &dyn crate::tx_buf::WireWrite,
        emit: FrameEmit,
    ) -> Result<UnicastPush, crate::send_wire_error::SendWireError> {
        let encode: &crate::frame_encode::BodyEncoder<'_> = encode_body;
        // An encoder that refuses its message (a field past its codec bound) reaches here too:
        // the slot of an open window answers its refusal as a message past the budget. It is
        // refused typed, before a byte leaves, with the SN the caller minted for it given back,
        // as `emit_fragment_chain` gives it back for a message past the reassembly cap.
        let body_len = match crate::tx_buf::try_encoded_len(encode) {
            Ok(len) => len,
            Err(refused) => {
                self.tx.frame_sn.unmint(
                    emit.ext_qos.unwrap_or(crate::qos::Priority::DEFAULT),
                    emit.reliable,
                );
                return Err(crate::send_wire_error::SendWireError::Codec(refused));
            }
        };
        self.emit_fragment_chain(
            batch,
            crate::frame_encode::FragmentBody::Encoded(encode),
            body_len,
            emit,
        )
    }

    /// The fragment chain of a `body_len`-byte message, whichever form the
    /// message is in ([`crate::frame_encode::FragmentBody`]): the bytes of a
    /// heap frame, or the encoder a lent chain re-runs per fragment. One walk,
    /// so the two forms cannot differ in anything but where the bytes are
    /// written.
    #[cfg(all(
        feature = "transport-fragmentation",
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "declare-interest",
            feature = "liveliness-token",
        )
    ))]
    // Out of line, so the heap frame's emit and the lent entry share one walk.
    #[cold]
    #[inline(never)]
    fn emit_fragment_chain(
        &self,
        batch: &mut BatchTx,
        body: crate::frame_encode::FragmentBody<'_>,
        body_len: usize,
        emit: FrameEmit,
    ) -> Result<UnicastPush, crate::send_wire_error::SendWireError> {
        let FrameEmit {
            ext_qos,
            sn,
            reliable,
            mtu,
            sn_mask,
            max_reassembly_bytes,
            deadline,
            ..
        } = emit;
        let reliability = crate::reliability::Reliability::from_reliable_bool(reliable);
        // The conduit the follow-on SNs reserve on IS the frame's conduit:
        // `ext_qos = Some(p)` iff the effective priority `p != DEFAULT`
        // (dispatch_network_message_at), and a DEFAULT frame carries `None`,
        // so `ext_qos.unwrap_or(DEFAULT)` reconstructs the effective
        // priority exactly (no separate param — keeps the arg count sane).
        let priority = ext_qos.unwrap_or(crate::qos::Priority::DEFAULT);
        // `body` is EXACTLY what a receiver stages: the chunks below
        // carry it and nothing else, and the reassembler rejoins them
        // into it. So it is the right unit to test against the slot
        // cap — the framed `frame` would over-count by the header the
        // fragments strip, and the caller's payload would under-count
        // by the network-message envelope they keep.
        //
        // Refuse before the follow-on SN reserve and before the first
        // `send_wire`, so NO wire bytes leave and the chain reserves
        // none of the `count - 1` follow-on SNs.
        //
        // The caller minted `sn` before it could know the encoded length,
        // and gives it back here: the conduit's lock has been held since
        // that mint, so it is still the last one, and the next frame on
        // the channel must carry it again. Left spent it is a 1-SN hole
        // in the reliable ring, which the half-window check of a peer
        // that does not tolerate it (zenoh-pico: the session closes at
        // the next frame) turns into a lost session, while the caller
        // was told only that this one message failed.
        if body_len > max_reassembly_bytes {
            self.tx.frame_sn.unmint(priority, reliable);
            return Err(crate::send_wire_error::SendWireError::ExceedsReassemblyCap);
        }
        // R311y215 — a QoS chain carries an ext_qos on every fragment, so
        // the count (which the follow-on SN reserve below must match) uses
        // the same qos budget the `fragment_body` chunker does.
        // R2238 (open-debt item 580) — the chain STREAMS: one fragment
        // is built, paid for out of the session's finite fragment TX
        // budget, and written, and only then is the next one built.
        //
        // The pre-R2238 code reserved `count - 1` follow-on SNs up
        // front and then walked a `Vec` the encoder had already
        // materialised whole. Both halves of that are now per-fragment,
        // and the SN policy is UNCHANGED by it: the oversize frame's
        // already-minted `sn` IS the first fragment's SN and each
        // further fragment reserves exactly one more, so the chain
        // stays ring-consecutive from `sn` with no skipped SN
        // (R311y206; zenoh `io/zenoh-transport/src/common/pipeline.rs`
        // @ `fn on_next_fragment` reuses
        // the frame SN slot and the `multicast_frame_or_fragments`
        // twin does the same). Reserving as we go rather than in
        // advance is not a weakening: the whole walk runs inside the
        // one conduit-lock hold, which is what made the split
        // reservation atomic w.r.t. a concurrent sender in the first
        // place. What it BUYS is that an abandoned chain reserves
        // only the SNs it actually put on the wire, instead of
        // punching a `count`-wide hole in the conduit's ring.
        //
        // R311y215 — every reserve is on the SAME (priority, reliable)
        // conduit the first fragment minted from (the base-mint +
        // reserve MUST share one conduit key, else conduit[priority]
        // under-advances and reuses an SN).
        //
        // ARCHITECTURE section 9.1 — the PLAN walks the chain and each
        // fragment is written by `Self::send_fragment`, into a lent slot
        // where the link lends one and on the heap where it does not.
        let mut plan = crate::frame_encode::FragmentPlan::new(body_len, mtu, sn, sn_mask, ext_qos);
        // A sender that may not wait can send a chain only when the lane holds the whole of it
        // at once. A chain is wire-atomic: it is not put down at the fragment the lane fills at
        // and picked up again later, so a chain the lane cannot hold would be begun, abandoned
        // at the same fragment and begun again, for ever, by a sender that asks for room
        // without waiting. Every fragment but the last has to find the lane under its bound
        // with the ones before it queued, and a fragment weighs at most `mtu`. Refused here, in
        // the way the cap above is: before a byte leaves and before a follow-on SN is reserved,
        // with the SN of this message given back; the sender sends it waiting. The chain that
        // fits may still find the lane full and is abandoned and put down for later, which is
        // what a probe does with a frame. A probe exists with `tx-probe`.
        #[cfg(feature = "tx-probe")]
        if deadline.is_probe() {
            let before_last = plan
                .remaining_fragments()
                .saturating_sub(1)
                .saturating_mul(mtu);
            if before_last >= self.tx.lane_bytes(priority) {
                self.tx.frame_sn.unmint(priority, reliable);
                return Ok(UnicastPush::Chain);
            }
        }
        let mut emitted = 0usize;
        let mut deadline = deadline;
        // A chain abandoned once some of it is on the wire ends in one place: the stop fragment
        // at the SN the abandoned fragment would have had, reserved first unless the fragment
        // reserved it already, and the answer the abandon gives.
        let (stop_sn, reserve_stop, abandoned) = loop {
            // The span is taken before the draw, so its SN names the fragment
            // this iteration is about to send — which is also the SN
            // the stop fragment takes if the draw fails, keeping the
            // conduit's ring gapless across the abandon. The plan is not read
            // again once a draw fails.
            let Some(span) = plan.next_span() else {
                return Ok(UnicastPush::Pushed);
            };
            let this_sn = span.sn;
            // R2926 — each further fragment waits for room against the
            // message's ONE deadline, as upstream's chain waits for a
            // batch per fragment (`io/zenoh-transport/src/common/pipeline.rs`
            // @ `// Otherwise, an ephemeral batch is created to send the stop fragment`).
            // The first fragment's room was asked before its SN was
            // minted. A chain that runs out mid-way is abandoned the way
            // a spent fragment budget abandons it just below: the stop
            // fragment, outside the queue's bound as upstream's
            // ephemeral batch is outside its pool, and the message is a
            // congestion drop. A chain whose every frame's room the sender reserved asks for
            // none: that room is the sender's, and asking would count its own promise.
            if emitted > 0 && !deadline.is_covered() {
                let answer = self.with_conduit_link(reliability, priority, |link| {
                    link.link_driver()
                        .wait_for_room_for(reliability, priority, deadline.ask())
                });
                deadline.spend(answer.waited_us);
                if answer.room == crate::link::LinkRoom::Congested {
                    // (A stop marker the link lends no slot for is lost, and the
                    // peer's staged chain with it: there is nothing more to send
                    // it on a profile that has no heap frame to fall back to.)
                    break (this_sn, true, Ok(UnicastPush::Congested));
                }
            }
            #[cfg(feature = "tx-fragment-credit")]
            if !self.tx.take_fragment_credit() {
                if emitted == 0 {
                    // Nothing left this session, and nothing has left
                    // for THIS message: there is no chain for a peer to
                    // be holding, so no marker is due. Upstream's
                    // equivalent arm restores the SN and writes nothing
                    // (`common/pipeline.rs`, `ext_first.is_some()`), and
                    // so does this: `sn` is the last mint under the
                    // conduit's lock, as for `ExceedsReassemblyCap` above.
                    self.tx.frame_sn.unmint(priority, reliable);
                    return Err(crate::send_wire_error::SendWireError::FragmentTxBudgetExhausted);
                }
                // Fragments are already on the wire and the peer is
                // staging them. Tell it to stop — the marker is the
                // abandon NOTICE, not chain payload, so it is drawn
                // OUTSIDE the budget (upstream's ephemeral stop batch
                // is outside its pool for the same reason). It does
                // spend an SN, which zenoh's receive-side `SeqNum::roll`
                // requires of every accepted transport message.
                break (
                    this_sn,
                    true,
                    Err(crate::send_wire_error::SendWireError::FragmentTxBudgetExhausted),
                );
            }
            if emitted > 0 {
                self.tx.frame_sn.reserve_next(priority, reliable);
            }
            // Every fragment rides the frame's conduit (`priority`
            // reconstructed above == the SN-mint conduit) so the whole
            // chain pins to one link (y217 one-conduit=one-link).
            // The heap form of a fragment cannot be refused, so this `?` is
            // vacuous there.
            #[cfg(not(feature = "tx-lend-only"))]
            self.send_fragment(batch, &span, body, reliable, ext_qos)?;
            // Fixed-memory step S4 — under `tx-lend-only` a fragment the link
            // lends no slot for ends the chain: the fragments already on the
            // wire are followed by the stop marker (which draws the SN this
            // fragment would have had, reserved above), so the peer releases
            // what it staged, and the message is refused, counted.
            #[cfg(feature = "tx-lend-only")]
            if let Err(refused) = self.send_fragment(batch, &span, body, reliable, ext_qos) {
                if emitted == 0 {
                    return Err(refused);
                }
                break (this_sn, false, Err(refused));
            }
            emitted = emitted.saturating_add(1);
            deadline.next_fragment();
        };
        #[cfg(feature = "tx-fragment-credit")]
        {
            if reserve_stop {
                self.tx.frame_sn.reserve_next(priority, reliable);
            }
            let _ = self.send_fragment(
                batch,
                &crate::frame_encode::FragmentSpan::stop(stop_sn),
                body,
                reliable,
                ext_qos,
            );
        }
        // Without the stop fragment the chain ends where it was cut, as zenoh-pico's does when a
        // fragment's write fails: nothing more of it leaves, and the peer lets go of what it
        // staged when the next chain begins. The sequence number of the fragment that did not
        // leave is given back where it was reserved, so the conduit's ring has no gap.
        #[cfg(not(feature = "tx-fragment-credit"))]
        {
            let _ = stop_sn;
            if !reserve_stop {
                self.tx.frame_sn.unmint(priority, reliable);
            }
        }
        abandoned
    }

    /// Put ONE fragment of a chain on its conduit's link: written straight into
    /// a slot that link lends when it lends one that holds the fragment, else
    /// written on the heap and sent through the byte door. The bytes are the
    /// same either way (`frame_encode::write_fragment` writes both); where they
    /// went is counted on the conduit ([`FragmentLendCounts`]).
    ///
    /// The conduit is the frame's: `ext_qos` reconstructs its priority as the
    /// SN mint did, so every fragment of a chain is lent by, and sent on, the
    /// one link the conduit is routed to.
    #[cfg(all(
        feature = "transport-fragmentation",
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "declare-interest",
            feature = "liveliness-token",
        )
    ))]
    // Out of line: the chain writes a fragment from its loop and its stop marker from one body.
    #[inline(never)]
    fn send_fragment(
        &self,
        batch: &mut BatchTx,
        span: &crate::frame_encode::FragmentSpan,
        body: crate::frame_encode::FragmentBody<'_>,
        reliable: bool,
        ext_qos: Option<crate::qos::Priority>,
    ) -> Result<(), crate::send_wire_error::SendWireError> {
        let reliability = crate::reliability::Reliability::from_reliable_bool(reliable);
        let priority = ext_qos.unwrap_or(crate::qos::Priority::DEFAULT);
        // Fixed-memory step S4 — under `tx-lend-only` no slot, or one the
        // fragment does not fit, is a refusal, and the fragment is not written on
        // the heap.
        #[cfg(feature = "tx-lend-only")]
        {
            let write = lent_write(|slot| {
                crate::frame_encode::write_fragment(slot, span, body, reliable, ext_qos)
            });
            match self.send_lent(reliability, priority, span.wire_bound(), &write) {
                Lend::Sent => {
                    let counts = &mut batch.frag_lend;
                    counts.slot_fragments = counts.slot_fragments.wrapping_add(1);
                    Ok(())
                }
                Lend::NoSlot | Lend::Refused(_) => {
                    Err(crate::send_wire_error::SendWireError::LinkRefused(
                        self.tx.refuse(crate::link::LinkDropCause::NoTxSlot),
                    ))
                }
            }
        }
        #[cfg(not(feature = "tx-lend-only"))]
        {
            #[cfg(feature = "transport-tx-lend")]
            {
                // A fragment the slot cannot hold gives the slot back (the
                // lease's drop) and is written on the heap below.
                let write = lent_write(|slot| {
                    crate::frame_encode::write_fragment(slot, span, body, reliable, ext_qos)
                });
                let lent = self.send_lent(reliability, priority, span.wire_bound(), &write);
                let counts = &mut batch.frag_lend;
                match lent {
                    Lend::Sent => {
                        counts.slot_fragments = counts.slot_fragments.wrapping_add(1);
                        return Ok(());
                    }
                    Lend::NoSlot => counts.heap_no_slot = counts.heap_no_slot.wrapping_add(1),
                    Lend::Refused(_) => {
                        counts.heap_short_slot = counts.heap_short_slot.wrapping_add(1)
                    }
                }
            }
            #[cfg(not(feature = "transport-tx-lend"))]
            let _ = batch;
            let mut wire = alloc::vec::Vec::with_capacity(span.wire_bound());
            // The vector refuses no write, but the body can refuse itself (an encoder that composes
            // its message as it writes it), as it does in a slot: refused before a byte leaves.
            crate::frame_encode::write_fragment(&mut wire, span, body, reliable, ext_qos)?;
            self.send_wire(&wire, reliability, priority);
            Ok(())
        }
    }
}

impl<R: SessionRuntime> core::fmt::Debug for TransportTx<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransportTx")
            .field("conduits", &self.conduits)
            .finish_non_exhaustive()
    }
}

/// R311jp — TX batching accumulator state (zenoh-pico
/// `_z_transport_common_t::{_batch_state,_batch_count}` plus the shared TX
/// `_wbuf`, `Z_FEATURE_BATCHING` parity). `active == false` (the default)
/// preserves the pre-A3 per-message flush behavior. While active, `buf`
/// holds the OPEN outbound `T_MID_FRAME` — transport header byte +
/// `VLE(sn)` + N appended network-message bodies; an empty `buf` means no
/// frame is open yet. `count` mirrors pico's batch counter for
/// observability and tests; the flush trigger is the byte budget
/// (`params.batch_size`), never the count.
///
/// R311kf — the struct (and the lock around it) is UNGATED: the lock
/// doubles as the TX-ORDER serialization lock (pico holds its TX mutex
/// across SN mint + wire write for every sender, common/tx.c:273-305),
/// which every build needs — with `transport-batching` off only the lock
/// role remains (as of R311y835 that is ALL that remains — the staging
/// buffer used to ride the OFF build too, at three words).
///
/// R311y835 — the single open frame became one stage per `Priority` conduit,
/// and the drain walks them in ASCENDING priority. See
/// `TxConduits::conduit` for why that is the whole of temporal priority.
///
/// R2920 — ONE conduit's TX state, and its lock is that conduit's TX-ORDER
/// lock. It used to be the whole session's: one `tx_mutex` guarded every
/// priority's stage and serialized every sender, so a sender held on one
/// conduit held every other conduit with it. zenoh locks per priority
/// (`io/zenoh-transport/src/common/pipeline.rs`
/// @ `// Each priority queue has its own Mutex`), and nothing needs more: a
/// conduit's SN ring, its open frame and its fragment chains are its own,
/// and no invariant spans two conduits. That independence is what lets a
/// congested low-priority conduit wait for its link without stalling a
/// higher-priority one.
#[derive(Debug, Default)]
pub struct BatchTx {
    /// This conduit's open frame. Without `transport-batching` nothing stages
    /// and the field is gone, leaving `BatchTx` its TX-ORDER lock role alone.
    #[cfg(feature = "transport-batching")]
    pub(crate) stage: BatchStage,
    /// Where this conduit's batch frames were staged, counted. Cumulative: a
    /// reopen resets the stage and keeps these, as it keeps the action trace.
    #[cfg(all(feature = "transport-batching", feature = "transport-tx-lend"))]
    pub(crate) lend: BatchLendCounts,
    /// Where this conduit's fragments were written, counted. Cumulative, as
    /// `lend` is.
    #[cfg(all(feature = "transport-fragmentation", feature = "transport-tx-lend"))]
    pub(crate) frag_lend: FragmentLendCounts,
    /// Where this conduit's frames sent whole, outside a batch window, were
    /// written, counted. Cumulative, as `lend` is.
    #[cfg(feature = "transport-tx-lend")]
    pub(crate) frame_lend: FrameLendCounts,
}

impl BatchTx {
    /// The stage back to its initial state, the counts kept. The reopen
    /// path's, and gated as it is.
    #[cfg(feature = "session-reconnect")]
    fn reset(&mut self) {
        #[cfg(feature = "transport-batching")]
        {
            self.stage = BatchStage::default();
        }
    }
}

/// ARCHITECTURE section 9.1 -- where a session's batch frames were staged, by
/// count of frames opened (the answer of
/// [`SessionLinkActions::batch_lend_counts`](crate::session_actions::SessionLinkActions::batch_lend_counts)).
///
/// With `transport-tx-lend` a batch frame is opened in a slot its conduit's link
/// lends, held across the calls of the window and sent as that slot, so a flush
/// copies nothing. When the link lends no slot that can hold a whole batch, the
/// frame is staged on the heap exactly as without the feature, and the reason is
/// counted here, so a link that never lends, a pool that has run dry and a slot
/// too small for the negotiated batch are each visible and none is silent.
#[cfg(all(feature = "transport-batching", feature = "transport-tx-lend"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BatchLendCounts {
    /// Batch frames opened in a lent slot and sent as that slot.
    pub slot_frames: u32,
    /// Batch frames staged on the heap because the link lent no slot: it lends
    /// none (every driver that has not opted in), or every slot is out.
    pub heap_no_slot: u32,
    /// Batch frames staged on the heap because the slot lent could not hold the
    /// negotiated batch budget, so a frame built in it would close earlier than
    /// the heap frame and put different bytes on the wire.
    pub heap_short_slot: u32,
    /// Open frames copied out of their slot onto the heap because the conduit
    /// stopped routing to the link that lent it (an aggregated session moved the
    /// conduit to another link, or the lender left the link set).
    pub moved_to_heap: u32,
    /// Open frames lost because the slot holding them could no longer be found
    /// on the link that lent it (the link went while the frame was open), or,
    /// on a lend-only session, could not follow its conduit to another link.
    pub lost: u32,
}

/// Fixed-memory step S4 -- the sends a LEND-ONLY session (`tx-lend-only`)
/// refused, by [`LinkDropCause`](crate::link::LinkDropCause) (the answer of
/// [`SessionLinkActions::tx_refusals`](crate::session_actions::SessionLinkActions::tx_refusals)).
///
/// The profile has no heap frame to fall back on, so a send for which the link
/// lends no usable slot does not happen, and the session says so here instead
/// of being silent: the count is the signal a dry pool has no other way to give.
/// Each is one message (a handshake message, a close, a data frame, a fragment)
/// that never reached the wire.
#[cfg(feature = "tx-lend-only")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TxRefusalCounts {
    /// The link lent no slot for the frame: both of the driver's slots were out,
    /// its pool was dry, or the slot it lent was shorter than the frame
    /// ([`LinkDropCause::NoTxSlot`](crate::link::LinkDropCause::NoTxSlot)).
    pub no_slot: u32,
    /// The frame is past the link's budget and, there being no heap to cut it up
    /// in (or fragmentation being off), cannot leave
    /// ([`LinkDropCause::Oversize`](crate::link::LinkDropCause::Oversize)).
    pub oversize: u32,
}

/// ARCHITECTURE section 9.1 -- where a session's FRAGMENTS were written, by
/// count of fragments sent (the answer of
/// [`SessionLinkActions::fragment_lend_counts`](crate::session_actions::SessionLinkActions::fragment_lend_counts)).
///
/// With `transport-tx-lend` a message past the batch budget is cut into a
/// chain whose fragments are each encoded straight into a slot the conduit's
/// link lends, one fragment per slot: the message is never written out whole.
/// A fragment for which the link lends no usable slot is written on the heap
/// and sent through the byte door, the same bytes, and the reason is counted
/// here, so a dry pool is visible and never silent.
#[cfg(all(feature = "transport-fragmentation", feature = "transport-tx-lend"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FragmentLendCounts {
    /// Fragments (the stop fragment included) written into a lent slot and
    /// sent as that slot.
    pub slot_fragments: u32,
    /// Fragments written on the heap because the link lent no slot: it lends
    /// none, or every slot is out.
    pub heap_no_slot: u32,
    /// Fragments written on the heap because the slot lent could not hold the
    /// fragment.
    pub heap_short_slot: u32,
}

#[cfg(all(feature = "transport-fragmentation", feature = "transport-tx-lend"))]
impl FragmentLendCounts {
    fn add(&mut self, other: &Self) {
        self.slot_fragments = self.slot_fragments.wrapping_add(other.slot_fragments);
        self.heap_no_slot = self.heap_no_slot.wrapping_add(other.heap_no_slot);
        self.heap_short_slot = self.heap_short_slot.wrapping_add(other.heap_short_slot);
    }
}

/// ARCHITECTURE section 9.1 -- where a session's frames sent whole were written,
/// by count of frames (the answer of [`SessionLinkActions::frame_lend_counts`](crate::session_actions::SessionLinkActions::frame_lend_counts)).
///
/// A message that no batch window takes (the window is closed, or batching is
/// off) leaves as a frame of its own, and with `transport-tx-lend` that frame is
/// encoded straight into a slot the conduit's link lends. When the link lends no
/// slot that holds it, the frame is built on the heap as without the feature,
/// and that is counted here beside the frames that left as a slot, so a send
/// path that never lends is visible as the batch and fragment paths are.
#[cfg(feature = "transport-tx-lend")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameLendCounts {
    /// Frames encoded into a lent slot and sent as that slot.
    pub slot_frames: u32,
    /// Frames built on the heap: the link lent no slot, every slot was out, the
    /// slot was short, or (without fragmentation) the frame is past the budget.
    /// Always zero under `tx-lend-only`, which refuses such a send instead.
    pub heap_frames: u32,
}

#[cfg(feature = "transport-tx-lend")]
impl FrameLendCounts {
    fn add(&mut self, other: &Self) {
        self.slot_frames = self.slot_frames.wrapping_add(other.slot_frames);
        self.heap_frames = self.heap_frames.wrapping_add(other.heap_frames);
    }
}

/// What one lend came to (`SessionLinkActions::send_lent_on`): the message left
/// as the slot, the link lent no slot, or the writer refused the slot it was lent
/// for a reason of its own.
#[cfg(any(
    all(
        feature = "transport-tx-lend",
        any(feature = "transport-lowlatency", feature = "transport-fragmentation"),
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "declare-interest",
            feature = "liveliness-token",
        )
    ),
    all(
        feature = "tx-lend-only",
        any(
            all(
                any(feature = "codec-init-body", feature = "codec-open-body"),
                any(feature = "session-unicast-open", feature = "session-unicast-accept")
            ),
            feature = "codec-close",
        )
    ),
))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lend<E> {
    /// Sent as the slot.
    Sent,
    /// No slot was lent.
    NoSlot,
    /// A slot was lent and given back unsent, for this reason.
    Refused(E),
}

/// What writes one message into the slot a lend is given (`TxRoute::send_lent_on`),
/// handed over as a trait object so the lend is one body whatever the message. A trait of its
/// own and not `dyn Fn`: a closure's `dyn Fn` table also holds its `FnOnce` shim, which
/// carries a second copy of the writer's body.
#[cfg(any(
    all(
        feature = "transport-tx-lend",
        any(feature = "transport-lowlatency", feature = "transport-fragmentation"),
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "declare-interest",
            feature = "liveliness-token",
        )
    ),
    all(
        feature = "tx-lend-only",
        any(
            all(
                any(feature = "codec-init-body", feature = "codec-open-body"),
                any(feature = "session-unicast-open", feature = "session-unicast-accept")
            ),
            feature = "codec-close",
        )
    ),
))]
pub(crate) trait LentWrite {
    /// Write the message into `buf`, or refuse it.
    fn write_lent(
        &self,
        buf: &mut crate::tx_buf::EncodeBuf<'_>,
    ) -> Result<(), sce_forge_runtime::codec::CodecError>;
}

#[cfg(any(
    all(
        feature = "transport-tx-lend",
        any(feature = "transport-lowlatency", feature = "transport-fragmentation"),
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "declare-interest",
            feature = "liveliness-token",
        )
    ),
    all(
        feature = "tx-lend-only",
        any(
            all(
                any(feature = "codec-init-body", feature = "codec-open-body"),
                any(feature = "session-unicast-open", feature = "session-unicast-accept")
            ),
            feature = "codec-close",
        )
    ),
))]
impl<F> LentWrite for F
where
    F: Fn(&mut crate::tx_buf::EncodeBuf<'_>) -> Result<(), sce_forge_runtime::codec::CodecError>,
{
    fn write_lent(
        &self,
        buf: &mut crate::tx_buf::EncodeBuf<'_>,
    ) -> Result<(), sce_forge_runtime::codec::CodecError> {
        self(buf)
    }
}

/// `write` as a [`LentWrite`]: a closure handed to a lend is written here, where its argument's
/// type comes from the bound, and not where a `dyn LentWrite` is expected, which names none.
#[cfg(any(
    all(
        feature = "transport-tx-lend",
        any(feature = "transport-lowlatency", feature = "transport-fragmentation"),
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "declare-interest",
            feature = "liveliness-token",
        )
    ),
    all(
        feature = "tx-lend-only",
        any(
            all(
                any(feature = "codec-init-body", feature = "codec-open-body"),
                any(feature = "session-unicast-open", feature = "session-unicast-accept")
            ),
            feature = "codec-close",
        )
    ),
))]
pub(crate) fn lent_write<F>(write: F) -> F
where
    F: Fn(&mut crate::tx_buf::EncodeBuf<'_>) -> Result<(), sce_forge_runtime::codec::CodecError>,
{
    write
}

/// What putting one frame into a slot its link lends came to
/// (`TxRoute::write_n_msg`).
#[cfg(all(
    feature = "transport-tx-lend",
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    )
))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameLend {
    /// The frame left as the slot.
    Sent,
    /// The frame is past the batch budget: nothing was sent and the slot is
    /// back. With fragmentation the message leaves as a chain of lent
    /// fragments; without it, as one frame from the heap.
    PastMtu,
    /// Nothing was sent: no slot, or a slot too short to say; encode on the
    /// heap as before.
    Heap,
    /// Nothing was sent: the message's own encoder refused it, which no other
    /// buffer would answer otherwise.
    Refused(sce_forge_runtime::codec::CodecError),
}

#[cfg(all(feature = "transport-batching", feature = "transport-tx-lend"))]
impl BatchLendCounts {
    fn add(&mut self, other: &Self) {
        self.slot_frames = self.slot_frames.wrapping_add(other.slot_frames);
        self.heap_no_slot = self.heap_no_slot.wrapping_add(other.heap_no_slot);
        self.heap_short_slot = self.heap_short_slot.wrapping_add(other.heap_short_slot);
        self.moved_to_heap = self.moved_to_heap.wrapping_add(other.moved_to_heap);
        self.lost = self.lost.wrapping_add(other.lost);
    }
}

/// The caller's window, `zp_batch_start` .. `zp_batch_stop` (`_Z_BATCHING_ACTIVE` /
/// `_Z_BATCHING_IDLE`): a bit of [`TxConduits`]'s word of windows.
#[cfg(feature = "transport-batching")]
pub(crate) const WINDOW_CALLER: u64 = 1;
/// The link's writer pulls what the conduits stage ([`BoxedLinkDriver::set_idle_flush`](crate::link::BoxedLinkDriver::set_idle_flush)), so its
/// window is open for as long as the session lives and no caller opens or closes it. A bit of its
/// own: `zp_batch_stop` closes the window the caller opened and must not close this one.
#[cfg(feature = "transport-batching")]
const WINDOW_LINK: u64 = 1 << 1;
/// The face's read holds the replies it sends in their conduits' open frames
/// ([`SessionLinkActions::hold_replies`](crate::session_actions::SessionLinkActions::hold_replies)). Joined by replies alone: every other message is sent
/// at once, after what the replies left open, so a hold opens no window for them.
#[cfg(feature = "transport-batching")]
pub(crate) const WINDOW_REPLIES: u64 = 1 << 2;
/// Whether a face's read holds its replies at all (`query-replies-with-final`): read as a constant,
/// so a build without it raises no hold and its replies' conduits are never held.
#[cfg(feature = "transport-batching")]
pub(crate) const REPLIES_HOLD: bool = cfg!(feature = "query-replies-with-final");
/// One drain under way of a window just closed, counted above the window bits: while one is, a
/// frame the window left open may still stand in a conduit the drain has not reached.
#[cfg(feature = "transport-batching")]
const WINDOW_DRAINING: u64 = 1 << 3;

/// Whether a message joins its conduit's open frame under `windows` (one read of the word):
/// inside the caller's or the link's window, or, for a `reply`, inside the hold of the replies.
/// Gated as the emit chokepoint that reads it.
#[cfg(all(
    feature = "transport-batching",
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    )
))]
pub(crate) fn window_joins(windows: u64, reply: bool) -> bool {
    windows & (WINDOW_CALLER | WINDOW_LINK) != 0 || (reply && windows & WINDOW_REPLIES != 0)
}

/// Whether a conduit may hold a frame open under `windows` that a message joining none sends
/// before itself: a window is open, or the drain of one just closed is under way. With none, no
/// conduit holds a frame open, so such a message reads no conduit's frame for it.
#[cfg(all(
    feature = "transport-batching",
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    )
))]
pub(crate) fn window_may_hold_open(windows: u64) -> bool {
    windows != 0
}

/// Open (`open`) or close the window `bit` of `word`, leaving the others as they are: whether
/// this call changed it, so of two that open it at once one is told it did. Out of line, as
/// [`begin_drain`] is.
#[cfg(feature = "transport-batching")]
#[inline(never)]
fn set_window<W: crate::runtime_cell::WordCell>(word: &W, bit: u64, open: bool) -> bool {
    let mut seen = word.load(core::sync::atomic::Ordering::SeqCst);
    loop {
        if (seen & bit != 0) == open {
            return false;
        }
        let next = if open { seen | bit } else { seen & !bit };
        match word.compare_exchange(
            seen,
            next,
            core::sync::atomic::Ordering::SeqCst,
            core::sync::atomic::Ordering::SeqCst,
        ) {
            Ok(_) => return true,
            Err(now) => seen = now,
        }
    }
}

/// Close the window `bit` of `word` and count a drain under way, in one write, so a message
/// that reads the window closed reads the drain too, and sends a frame the drain has not reached
/// before itself. The drain's end is [`end_drain`]. Out of line: every closer of a window calls
/// it, and a copy of its loop in each cost more than the call.
#[cfg(feature = "transport-batching")]
#[inline(never)]
fn begin_drain<W: crate::runtime_cell::WordCell>(word: &W, bit: u64) {
    let mut seen = word.load(core::sync::atomic::Ordering::SeqCst);
    loop {
        let next = (seen & !bit).wrapping_add(WINDOW_DRAINING);
        match word.compare_exchange(
            seen,
            next,
            core::sync::atomic::Ordering::SeqCst,
            core::sync::atomic::Ordering::SeqCst,
        ) {
            Ok(_) => return,
            Err(now) => seen = now,
        }
    }
}

/// End a drain [`begin_drain`] counted.
#[cfg(feature = "transport-batching")]
fn end_drain<W: crate::runtime_cell::WordCell>(word: &W) {
    word.fetch_sub(WINDOW_DRAINING, core::sync::atomic::Ordering::SeqCst);
}

/// Close the window `bit` of `word` and run `drain`, which sends what it left open, counted as
/// a drain under way from the close to the drain's end.
#[cfg(feature = "transport-batching")]
fn close_and_drain<W: crate::runtime_cell::WordCell>(word: &W, bit: u64, drain: impl FnOnce()) {
    begin_drain(word, bit);
    drain();
    end_drain(word);
}

/// R2920 — the session's TX conduits: one [`BatchTx`] behind its own lock
/// per priority (one in all, without `transport-qos`), and the batching
/// windows they share.
pub struct TxConduits<R: SessionRuntime> {
    /// The face's send windows, a bit each in one word, so a message's send reads every one of
    /// them with one load: the caller's ([`WINDOW_CALLER`]), the link's writer's
    /// ([`WINDOW_LINK`]) and the hold of the replies ([`WINDOW_REPLIES`]), with the drains under
    /// way of a window just closed counted above them ([`WINDOW_DRAINING`]). The runtime's word
    /// rather than a field of a conduit, because a window spans every conduit and no conduit's
    /// lock may stand for the others.
    #[cfg(feature = "transport-batching")]
    window: R::Word,
    /// A control message was left in the Control conduit's open frame, for the control messages
    /// after it to join, and a message staged on another conduit is to follow that frame out.
    /// Raised by the sender of the control message once it has staged it, lowered under the
    /// Control conduit's lock when that frame is taken: raised with nothing open costs the next
    /// sender one flush of an empty conduit, while lowered with a frame open would let data pass
    /// a declaration staged before it, which is the order this is kept for.
    #[cfg(all(feature = "transport-batching", feature = "transport-qos"))]
    control_open: R::Flag,
    conduits: [R::Mutex<BatchTx>; TX_CONDUITS],
    /// Per conduit, whether a SENDER holds it: one staging its message, writing its frame or
    /// waiting for room for it ([`SenderInside`]). A conduit is also held by what is not a
    /// sender (the writer's flush of what is staged, a drain), and that holder lets go once it
    /// has written. zenoh-pico's dropping send gives up only on a transmit lock another send
    /// holds (`vendor/zenoh-pico/src/transport/common/tx.c` @
    /// `ret = _z_transport_tx_mutex_lock(ztc, cong_ctrl == Z_CONGESTION_CONTROL_BLOCK);`), so a
    /// profile that drops at once (`HeldDrop::DropAtOnce`) reads this to tell the two apart.
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    ))]
    sending: [R::Flag; TX_CONDUITS],
}

/// A sender inside its conduit, marked for as long as this lives: set when the sender has taken
/// the conduit's lock, cleared when it lets go, also when its staging unwinds.
///
/// Both stores and the one load are `Relaxed`. The flag carries no data: its one reader, a
/// droppable send whose try of the conduit's lock just failed, reads nothing else through it, and
/// what it does next (drop the message, or try the lock again) reads the conduit only under the
/// lock, whose own acquire and release order that. The flag's place in the holding is kept by the
/// lock too: the mark is made after the lock is taken and the clear before it is let go, so the
/// lock's acquire keeps the mark after the previous holder's clear, and its release keeps the
/// clear before the next holder's mark. A reader that sees the flag late spins once more, or drops
/// the message as zenoh-pico's try-lock does when it loses to a sender that is just leaving, and
/// a stronger ordering would change neither: no ordering makes a store visible sooner. The flag
/// is the runtime's (`R::Flag`): a cell where the senders are one task, which orders nothing.
#[cfg(any(
    feature = "codec-push",
    feature = "codec-request",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "declare-keyexpr",
    feature = "declare-subscriber",
    feature = "declare-queryable",
    feature = "declare-token",
    feature = "declare-interest",
    feature = "liveliness-token",
))]
pub(crate) struct SenderInside<'a, F: crate::runtime_cell::FlagCell>(&'a F);

#[cfg(any(
    feature = "codec-push",
    feature = "codec-request",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "declare-keyexpr",
    feature = "declare-subscriber",
    feature = "declare-queryable",
    feature = "declare-token",
    feature = "declare-interest",
    feature = "liveliness-token",
))]
impl<'a, F: crate::runtime_cell::FlagCell> SenderInside<'a, F> {
    pub(crate) fn mark(flag: &'a F) -> Self {
        flag.store(true, core::sync::atomic::Ordering::Relaxed);
        Self(flag)
    }
}

#[cfg(any(
    feature = "codec-push",
    feature = "codec-request",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "declare-keyexpr",
    feature = "declare-subscriber",
    feature = "declare-queryable",
    feature = "declare-token",
    feature = "declare-interest",
    feature = "liveliness-token",
))]
impl<F: crate::runtime_cell::FlagCell> Drop for SenderInside<'_, F> {
    fn drop(&mut self) {
        self.0.store(false, core::sync::atomic::Ordering::Relaxed);
    }
}

/// The number of TX conduits, sized by the build's priority space.
/// `transport-qos` is `alloc`-required by construction (a host/AP knob, never
/// an MCU no-alloc one); the OFF build keeps the single conduit it always had.
/// Named where a link reads it too ([`crate::link::SESSION_TX_SLOTS`]).
pub(crate) const TX_CONDUITS: usize = crate::link::SESSION_TX_CONDUITS;

// The Control barrier of the send and its `control_open` mark are compiled with `transport-qos`
// alone: on one conduit a control message and the data staged around it share one frame order,
// so there is no other conduit to drain ahead of it and no frame of its own to follow out.
#[cfg(not(feature = "transport-qos"))]
const _: () = assert!(TX_CONDUITS == 1);

/// The entry of `rows`, one per conduit, that `priority` rides: its own under `transport-qos`,
/// where the wire priority is the conduit, and the single one otherwise. Gated as its readers
/// (`TxConduits::sender_flag` and `TxConduits::conduit`) are.
#[cfg(any(
    feature = "codec-push",
    feature = "codec-request",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "declare-keyexpr",
    feature = "declare-subscriber",
    feature = "declare-queryable",
    feature = "declare-token",
    feature = "declare-interest",
    feature = "liveliness-token",
    feature = "transport-batching",
))]
fn conduit_row<T>(rows: &[T; TX_CONDUITS], priority: Priority) -> &T {
    #[cfg(feature = "transport-qos")]
    {
        priority.of(rows)
    }
    #[cfg(not(feature = "transport-qos"))]
    {
        let _ = priority;
        let [only] = rows;
        only
    }
}

impl<R: SessionRuntime> TxConduits<R> {
    fn new() -> Self {
        Self {
            #[cfg(feature = "transport-batching")]
            window: <R::Word as crate::runtime_cell::WordCell>::new(0),
            #[cfg(all(feature = "transport-batching", feature = "transport-qos"))]
            control_open: <R::Flag as crate::runtime_cell::FlagCell>::new(false),
            // A blocking sender keeps its conduit while it waits for room (a chain's fragments
            // keep their sequence numbers), and a probe takes it without waiting
            // (`DispatchStage::Probe`): the lock is one held across a wait for an event.
            conduits: core::array::from_fn(|_| R::new_mutex_held_across_waits(BatchTx::default())),
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-request",
                feature = "codec-response",
                feature = "codec-response-final",
                feature = "declare-keyexpr",
                feature = "declare-subscriber",
                feature = "declare-queryable",
                feature = "declare-token",
                feature = "declare-interest",
                feature = "liveliness-token",
            ))]
            sending: core::array::from_fn(|_| {
                <R::Flag as crate::runtime_cell::FlagCell>::new(false)
            }),
        }
    }

    /// Whether a sender holds the conduit `priority` rides: the conduit's `sending` flag.
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    ))]
    pub(crate) fn sender_flag(&self, priority: Priority) -> &R::Flag {
        conduit_row(&self.sending, priority)
    }

    /// The conduit `priority` rides. With `transport-qos` this is zenoh's
    /// `TransmissionPipeline::stage_in[priority]`
    /// (`io/zenoh-transport/src/common/pipeline.rs`) — each priority
    /// accumulates INDEPENDENTLY, which is what makes the drain order a real
    /// scheduling decision rather than arrival order. Before R311y835 wz held
    /// one frame and flushed it whenever the priority changed, so a Background
    /// message staged first left the link BEFORE a RealTime message staged
    /// second: the wire carried the ext_qos band while the schedule ignored it.
    ///
    /// Without `transport-qos` there is one conduit and every priority indexes
    /// it. The same holds inside a `transport-qos` build on a session that did
    /// NOT negotiate QoS, because `SessionLinkActions::dispatch_network_message_at`
    /// forces `Priority::DEFAULT` there before reaching this seam.
    ///
    /// Gated on the union of its two callers' gates: the emit chokepoint's
    /// (`dispatch_network_message_at`) and the batch drain's.
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
        feature = "transport-batching",
    ))]
    pub(crate) fn conduit(&self, priority: Priority) -> &R::Mutex<BatchTx> {
        conduit_row(&self.conduits, priority)
    }

    /// `priority` -> conduit index. The wire priority byte IS the index under
    /// `transport-qos` (`Priority::wire_byte`, 0..=7 ascending from `Control`),
    /// so index order IS wire-priority order and the ascending walk in
    /// `SessionLinkActions::flush_open_batch` is zenoh's strict-priority
    /// drain (`pipeline.rs` pulls `for prio in 0..NUM_PRIO`). Off the feature
    /// every priority collapses onto the single conduit.
    // Its readers are the batching paths of a build that sends network messages (the dispatch and
    // `write_n_msg`, under the one list of message features both read, and the express flush
    // within it) and `flush_conduit`'s Control mark under `transport-qos`.
    #[cfg(all(
        feature = "transport-batching",
        any(
            feature = "transport-qos",
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "declare-interest",
            feature = "liveliness-token",
        )
    ))]
    pub(crate) const fn conduit_index(priority: Priority) -> usize {
        #[cfg(feature = "transport-qos")]
        {
            priority.wire_byte() as usize
        }
        #[cfg(not(feature = "transport-qos"))]
        {
            let _ = priority;
            0
        }
    }

    /// The `Priority` conduit index `idx` carries — the inverse of
    /// `Self::conduit_index`, used by the drain to route each flushed frame by
    /// its OWN conduit (y217 #3: splitting one conduit across links would trip
    /// the peer's per-conduit RX SN gate).
    #[cfg(feature = "transport-batching")]
    pub(crate) const fn conduit_priority(idx: usize) -> Priority {
        #[cfg(feature = "transport-qos")]
        {
            Priority::from_wire(idx as u8)
        }
        #[cfg(not(feature = "transport-qos"))]
        {
            let _ = idx;
            Priority::DEFAULT
        }
    }

    /// Read by the emit chokepoint's window arm only, so gated as it is.
    #[cfg(all(
        feature = "transport-batching",
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "declare-interest",
            feature = "liveliness-token",
        )
    ))]
    pub(crate) fn is_active(&self) -> bool {
        self.windows() & (WINDOW_CALLER | WINDOW_LINK) != 0
    }

    /// The face's windows as they stand (the `window` field), in one load.
    #[cfg(feature = "transport-batching")]
    pub(crate) fn windows(&self) -> u64 {
        crate::runtime_cell::WordCell::load(&self.window, core::sync::atomic::Ordering::SeqCst)
    }

    /// Open (`open`) or close the window `bit`, the others left as they are: whether this call
    /// changed it.
    #[cfg(feature = "transport-batching")]
    pub(crate) fn set_window(&self, bit: u64, open: bool) -> bool {
        set_window(&self.window, bit, open)
    }

    /// Close the window `bit` and run `drain`, which sends what it left open, counted as a drain
    /// under way from the close to the drain's end.
    #[cfg(feature = "transport-batching")]
    pub(crate) fn close_and_drain(&self, bit: u64, drain: impl FnOnce()) {
        close_and_drain(&self.window, bit, drain);
    }

    #[cfg(feature = "transport-batching")]
    pub(crate) fn set_active(&self, active: bool) {
        self.set_window(WINDOW_CALLER, active);
    }

    /// The link pulls the staged frames itself ([`WINDOW_LINK`]). Read where
    /// [`Self::is_active`] is, by the emit chokepoint, and by the caller's stop
    /// ([`SessionLinkActions::batch_stop`](crate::session_actions::SessionLinkActions::batch_stop)), which asks such a link for the flush.
    #[cfg(feature = "transport-batching")]
    pub(crate) fn is_auto(&self) -> bool {
        self.windows() & WINDOW_LINK != 0
    }

    #[cfg(feature = "transport-batching")]
    pub(crate) fn set_auto(&self, auto: bool) {
        self.set_window(WINDOW_LINK, auto);
    }

    /// Whether the face's read holds its replies ([`WINDOW_REPLIES`]). Gated as the conduit of a
    /// reply that reads it (`SessionLinkActions::reply_conduit`).
    #[cfg(all(
        feature = "transport-batching",
        any(
            feature = "codec-response-final",
            all(
                feature = "codec-response",
                any(feature = "storage-profile", feature = "alloc")
            )
        )
    ))]
    pub(crate) fn replies_held(&self) -> bool {
        self.windows() & WINDOW_REPLIES != 0
    }

    /// The caller's window alone (`zp_batch_start` .. `zp_batch_stop`), without the link's.
    /// While it is open the conduits hold what they stage until it is drained the ways pico
    /// drains it: an overflow, an express message, a transport message such as a keepalive,
    /// or the caller's flush or stop (`vendor/zenoh-pico/src/transport/common/tx.c` @
    /// `static z_result_t _z_transport_tx_send_n_msg_inner(`). The writer's flush at idle is
    /// not one of them, so the writer reads this to know when to stay its hand.
    #[cfg(feature = "transport-batching")]
    pub(crate) fn caller_window_open(&self) -> bool {
        self.windows() & WINDOW_CALLER != 0
    }

    /// Raise the `control_open` mark: read and raised where [`Self::is_auto`] is read, by the
    /// emit chokepoint only, and lowered by the drain of the Control conduit.
    #[cfg(all(
        feature = "transport-batching",
        feature = "transport-qos",
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "declare-interest",
            feature = "liveliness-token",
        )
    ))]
    pub(crate) fn leave_control_open(&self) {
        crate::runtime_cell::FlagCell::store(
            &self.control_open,
            true,
            core::sync::atomic::Ordering::SeqCst,
        );
    }

    /// Whether a control message may still be in the Control conduit's open frame (the
    /// `control_open` mark).
    #[cfg(all(
        feature = "transport-batching",
        feature = "transport-qos",
        any(
            feature = "codec-push",
            feature = "codec-request",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "declare-keyexpr",
            feature = "declare-subscriber",
            feature = "declare-queryable",
            feature = "declare-token",
            feature = "declare-interest",
            feature = "liveliness-token",
        )
    ))]
    pub(crate) fn control_left_open(&self) -> bool {
        crate::runtime_cell::FlagCell::load(
            &self.control_open,
            core::sync::atomic::Ordering::SeqCst,
        )
    }

    /// Lower the `control_open` mark: called with the Control conduit's lock held, as its open
    /// frame is taken.
    #[cfg(all(feature = "transport-batching", feature = "transport-qos"))]
    fn control_taken(&self) {
        crate::runtime_cell::FlagCell::store(
            &self.control_open,
            false,
            core::sync::atomic::Ordering::SeqCst,
        );
    }

    /// Every conduit back to its initial state, the window closed. The
    /// reopen path's (`reset_for_reopen`), and gated as that arm is.
    #[cfg(feature = "session-reconnect")]
    fn reset(&self) {
        #[cfg(feature = "transport-batching")]
        self.set_active(false);
        for conduit in &self.conduits {
            R::with_mutex_mut(conduit, BatchTx::reset);
        }
        #[cfg(all(feature = "transport-batching", feature = "transport-qos"))]
        self.control_taken();
    }

    /// Where the conduits' batch frames were staged, summed over them: in a lent slot, or on the
    /// heap and why.
    #[cfg(all(feature = "transport-batching", feature = "transport-tx-lend"))]
    pub(crate) fn batch_lend_counts(&self) -> BatchLendCounts {
        let mut sum = BatchLendCounts::default();
        for conduit in &self.conduits {
            R::with_mutex_mut(conduit, |batch| sum.add(&batch.lend));
        }
        sum
    }

    /// Where the conduits' fragments were written, summed over them: in a lent slot, or on the
    /// heap and why.
    #[cfg(all(feature = "transport-fragmentation", feature = "transport-tx-lend"))]
    pub(crate) fn fragment_lend_counts(&self) -> FragmentLendCounts {
        let mut sum = FragmentLendCounts::default();
        for conduit in &self.conduits {
            R::with_mutex_mut(conduit, |batch| sum.add(&batch.frag_lend));
        }
        sum
    }

    /// Where the conduits' frames sent whole, outside a batch window, were written, summed over
    /// them: in a lent slot, or on the heap.
    #[cfg(feature = "transport-tx-lend")]
    pub(crate) fn frame_lend_counts(&self) -> FrameLendCounts {
        let mut sum = FrameLendCounts::default();
        for conduit in &self.conduits {
            R::with_mutex_mut(conduit, |batch| sum.add(&batch.frame_lend));
        }
        sum
    }
}

impl<R: SessionRuntime> core::fmt::Debug for TxConduits<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TxConduits")
            .field("conduits", &self.conduits.len())
            .finish_non_exhaustive()
    }
}

/// R311y835 — ONE priority conduit's staged outbound frame: the transport
/// header byte + `VLE(sn)` + N appended network-message bodies, plus pico's
/// batch counter for observability. An empty `buf` means no frame is open on
/// this conduit. Was `BatchTx`'s inline `buf` / `count` pair, lifted into a
/// value so the eight conduits can be an array rather than eight fields.
#[cfg(feature = "transport-batching")]
#[derive(Debug, Default)]
pub(crate) struct BatchStage {
    /// The open outbound frame bytes when the frame is staged on the heap
    /// (empty = no heap frame open). Fixed-memory step S4 -- absent under
    /// `tx-lend-only`, where no frame is ever staged on the heap: the open
    /// frame is in a lent slot or there is none.
    #[cfg(not(feature = "tx-lend-only"))]
    pub(crate) buf: alloc::vec::Vec<u8>,
    /// Network messages absorbed into the open frame. The flush trigger is
    /// the byte budget (`params.batch_size`), never this count.
    pub(crate) count: usize,
    /// ARCHITECTURE section 9.1 -- the open frame, when it lives in a slot a link
    /// lent rather than in `buf` (which is then empty): the slot with where its
    /// memory is, kept here between the calls that fill it, so an append takes no
    /// other lock and asks the driver nothing. Which link lent it is recorded on
    /// that link (`LinkState::batch_slots`, at this conduit's index), because only
    /// that link can send or abort it, a record kept there is found by where it
    /// is and not by a name that could come to mean another link, and a link that
    /// goes gives back what it still records. The two are set and cleared
    /// together, under this conduit's lock, and the record is what says the slot
    /// here is still lent ([`crate::tx_lease::TxLease::pick_up`]).
    #[cfg(feature = "transport-tx-lend")]
    pub(crate) lent: Option<crate::tx_lease::OpenSlot>,
}

#[cfg(feature = "transport-batching")]
impl BatchStage {
    /// Whether a frame is open on this conduit, in a lent slot or on the heap. Read where a
    /// message that joins no window may find one open (`window_may_hold_open`), and compiled
    /// where that is.
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    ))]
    pub(crate) fn is_open(&self) -> bool {
        #[cfg(feature = "transport-tx-lend")]
        if self.lent.is_some() {
            return true;
        }
        #[cfg(not(feature = "tx-lend-only"))]
        if !self.buf.is_empty() {
            return true;
        }
        false
    }
}

/// Why a batch frame was opened on the heap and not in a lent slot (the
/// heap-stage reasons of [`BatchLendCounts`]). Gated, as the item below is, on the data path
/// that opens a batch frame on the heap, which a lend-only build has none of.
#[cfg(all(
    feature = "transport-batching",
    feature = "transport-tx-lend",
    not(feature = "tx-lend-only"),
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    )
))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeapStage {
    /// The link lent no slot.
    NoSlot,
    /// The slot lent was smaller than the batch budget.
    ShortSlot,
}

#[cfg(all(
    feature = "transport-batching",
    feature = "transport-tx-lend",
    not(feature = "tx-lend-only"),
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    )
))]
impl BatchLendCounts {
    /// Count a batch frame staged on the heap.
    fn count_heap(&mut self, why: HeapStage) {
        match why {
            HeapStage::NoSlot => self.heap_no_slot = self.heap_no_slot.wrapping_add(1),
            HeapStage::ShortSlot => self.heap_short_slot = self.heap_short_slot.wrapping_add(1),
        }
    }
}

/// R311y214 — the unicast outbound Frame SN generator, SPLIT per
/// reliability channel: the shared twin of the plain-`u64` multicast
/// [`crate::sn::TxSn`] (which the single-task multicast drive loop mints
/// under no lock), over the runtime's word (`W`, `SessionRuntime::Word`):
/// atomic where the senders are threads, a cell where they are one task.
/// Both zenoh and zenoh-pico split the TX SN by
/// reliability even at one priority conduit: zenoh's non-QoS
/// `TransportPriorityTx { reliable, best_effort }` still holds two
/// generators (`io/zenoh-transport/src/common/priority.rs`), and pico's
/// `_z_transport_tx_get_sn(ztc, reliability)` mints from
/// `_sn_tx_reliable` / `_sn_tx_best_effort` (`src/transport/common/tx.c:52-59`).
/// wz's prior single shared `AtomicU64` was a divergence from BOTH: a
/// reliable and a best-effort Frame drew from ONE ring, so each channel
/// saw a gapped (but forward) SN cadence the peer's per-channel
/// `_z_sn_precedes` gate merely tolerated. Splitting makes each channel a
/// contiguous ring from `initial_sn`, matching pico exactly. Both channels
/// seed from the one `params.initial_sn` (the OpenSyn/OpenAck origin) and
/// share the negotiated ring mask. The mint stays lock-free (every mint
/// site already runs under its conduit's TX lock; the atomic additionally keeps a
/// straggling reset from reordering — the SeqCst contract the reset store
/// pairs with). R311y215 arrays this per `Priority` conduit behind
/// `transport-qos`.
#[derive(Debug)]
pub struct ConduitTxSn<W: crate::runtime_cell::WordCell> {
    /// Next SN for the reliable channel (pico `_sn_tx_reliable`).
    reliable: W,
    /// Next SN for the best-effort channel (pico `_sn_tx_best_effort`).
    best_effort: W,
}

impl<W: crate::runtime_cell::WordCell> ConduitTxSn<W> {
    /// Seed both channels at `initial_sn` (the OpenSyn/OpenAck origin) so
    /// the first Frame on either channel is exactly `initial_sn` — the peer
    /// seeds its per-channel RX gate one before this ([`crate::sn::RxSn::seed`]).
    pub fn new(initial_sn: u64) -> Self {
        Self {
            reliable: W::new(initial_sn),
            best_effort: W::new(initial_sn),
        }
    }

    /// Mint the next SN on `reliable`'s channel as a ring position of
    /// `mask`, advancing that channel one step (the shared twin of
    /// [`crate::sn::TxSn::mint`]). Masking a raw monotonic `fetch_add` IS
    /// the ring walk — `(n + 1) & mask` is the ring successor of `n & mask`
    /// across the `u64` boundary too, and the low bits of the count
    /// ([`crate::sn::from_wire`]) hold every ring the build runs.
    pub fn mint(&self, reliable: bool, mask: crate::sn::Sn) -> crate::sn::Sn {
        let slot = if reliable {
            &self.reliable
        } else {
            &self.best_effort
        };
        crate::sn::from_wire(slot.fetch_add(1, core::sync::atomic::Ordering::SeqCst)) & mask
    }

    /// Reserve (burn) one SN on `reliable`'s channel WITHOUT returning it —
    /// the fragment-chain follow-on walk reserves `count - 1` SNs after the
    /// first fragment's already-minted `sn` so the chain is ring-consecutive
    /// on its own channel (R311y206).
    pub fn reserve_next(&self, reliable: bool) {
        let slot = if reliable {
            &self.reliable
        } else {
            &self.best_effort
        };
        slot.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }

    /// Give back the SN the LAST mint on `reliable`'s channel handed out, for a
    /// send that was refused before any byte of it left: the channel's next
    /// frame then carries that SN again, and the peer sees no gap.
    ///
    /// Only correct for the caller that minted it and still holds the conduit's
    /// TX lock, so no other mint can have followed; every mint site does, and
    /// this is called nowhere else. Upstream does the same when a message gives
    /// up before its first fragment: it restores the SN and writes nothing.
    pub fn unmint(&self, reliable: bool) {
        let slot = if reliable {
            &self.reliable
        } else {
            &self.best_effort
        };
        slot.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
    }

    /// Re-seed BOTH channels to `initial_sn` on reopen (the fresh-rebuild
    /// path). SeqCst pairs with `mint` / `reserve_next` so the store cannot
    /// reorder against a straggling in-flight mint.
    pub fn reset(&self, initial_sn: u64) {
        self.reliable
            .store(initial_sn, core::sync::atomic::Ordering::SeqCst);
        self.best_effort
            .store(initial_sn, core::sync::atomic::Ordering::SeqCst);
    }
}

/// R311y215 (transport-qos) — the outbound Frame SN generators: ONE
/// [`ConduitTxSn`] per `Priority` conduit when `transport-qos` compiles (zenoh
/// `priority_tx: Arc<[TransportPriorityTx]>`, `universal/transport.rs`), else the
/// single R311y214 conduit. The array SHAPE is compile-time behind the feature
/// so an MCU no-alloc build never sizes a heap array by the runtime `is_qos`
/// flag; at runtime a non-QoS session mints only `conduit[Priority::DEFAULT]`
/// (the send seam forces `priority = Data` when `!is_qos()`), leaving the other
/// conduits idle. Every conduit is seeded from the one `initial_sn` (zenoh seeds
/// each `TransportPriorityTx` from the single `config.tx_initial_sn`).
///
/// The one-conduit-per-`(priority,reliability)` gate is what makes a multilink
/// priority-select SAFE (R311y216): `select_link` pins one conduit to one link,
/// so a reliable+high and a reliable+low Frame ride SEPARATE SN rings gated on
/// SEPARATE RX conduits — no cross-link stale-drop. Splitting ONE conduit across
/// links (a load-balancer) would reintroduce the hazard and is forbidden.
pub struct FrameTxConduits<W: crate::runtime_cell::WordCell> {
    #[cfg(feature = "transport-qos")]
    conduits: [ConduitTxSn<W>; Priority::NUM],
    #[cfg(not(feature = "transport-qos"))]
    conduit: ConduitTxSn<W>,
}

impl<W: crate::runtime_cell::WordCell> FrameTxConduits<W> {
    /// Seed every conduit at `initial_sn` (the OpenSyn/OpenAck origin).
    pub fn new(initial_sn: u64) -> Self {
        Self {
            #[cfg(feature = "transport-qos")]
            conduits: core::array::from_fn(|_| ConduitTxSn::new(initial_sn)),
            #[cfg(not(feature = "transport-qos"))]
            conduit: ConduitTxSn::new(initial_sn),
        }
    }

    /// The `(priority)` conduit — `conduits[priority]` under `transport-qos`,
    /// the single conduit otherwise (priority ignored, no cfg-skew).
    #[inline]
    fn select(&self, _priority: Priority) -> &ConduitTxSn<W> {
        #[cfg(feature = "transport-qos")]
        {
            _priority.of(&self.conduits)
        }
        #[cfg(not(feature = "transport-qos"))]
        {
            &self.conduit
        }
    }

    /// Mint the next SN for `(priority, reliable)` — see [`ConduitTxSn::mint`].
    pub fn mint(&self, priority: Priority, reliable: bool, mask: crate::sn::Sn) -> crate::sn::Sn {
        self.select(priority).mint(reliable, mask)
    }

    /// Reserve one follow-on SN on `(priority, reliable)` — the fragment walk.
    pub fn reserve_next(&self, priority: Priority, reliable: bool) {
        self.select(priority).reserve_next(reliable);
    }

    /// Give back the SN the last mint on `(priority, reliable)` handed out, for a
    /// send refused before any byte of it left — see [`ConduitTxSn::unmint`].
    pub fn unmint(&self, priority: Priority, reliable: bool) {
        self.select(priority).unmint(reliable);
    }

    /// Re-seed EVERY conduit to `initial_sn` on reopen.
    pub fn reset(&self, initial_sn: u64) {
        #[cfg(feature = "transport-qos")]
        for c in &self.conduits {
            c.reset(initial_sn);
        }
        #[cfg(not(feature = "transport-qos"))]
        self.conduit.reset(initial_sn);
    }
}

/// R2923 / R2926 — what the unicast dispatch found when it put a message on its conduit's link:
/// the message is on the link's queue, or no room was found within its deadline (a congestion
/// drop), or it is a chain of fragments that the sender asked not to wait for.
///
/// The multicast queue's own [`crate::tx_deadline::PushOutcome`] has the first two and cannot
/// meet the third, which is why the third is not there: a result a caller of the multicast
/// queue could be handed and never is would be an arm each of them has to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(
    feature = "codec-push",
    feature = "codec-request",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "declare-keyexpr",
    feature = "declare-subscriber",
    feature = "declare-queryable",
    feature = "declare-token",
    feature = "declare-interest",
    feature = "liveliness-token",
))]
pub(crate) enum UnicastPush {
    /// The message is on the link's queue.
    Pushed,
    /// No room was found within the message's deadline.
    Congested,
    /// The message is a chain of fragments and the sender asked not to wait
    /// (`PushDeadline::probe`): nothing was sent, and the sequence number the message took was
    /// given back.
    ///
    /// A chain is wire-atomic, so it cannot be put down half way and picked up again: the peer is
    /// told to drop what it staged. A sender that may not wait for room between two fragments
    /// would send the first of them, find the lane full at the next, abandon the chain and begin
    /// it again at the next notice, for ever, if the lane cannot hold the chain whole, since
    /// every try gets as far as the lane is deep and no further. Such a message is the caller's
    /// to send with a wait; a chain the lane can hold whole is probed like a frame.
    ///
    /// Only a build that fragments has a chain to refuse, and only one with `alloc` has a
    /// sender that may not wait (`DispatchStage::Probe`).
    #[cfg(all(feature = "alloc", feature = "transport-fragmentation"))]
    Chain,
}

/// The per-frame context `TxRoute::emit_frame_or_fragments`
/// needs to decide between one frame and a fragment chain, and to route
/// whichever it emits.
///
/// Grouped rather than passed as six positional arguments: they are ONE
/// decision's inputs, they are resolved together at the top of
/// `dispatch_network_message_at` (before the conduit lock is taken), and they travel
/// together to both call sites. All `Copy`, so the grouping is free.
///
/// Carries the SAME feature gate as
/// `TxRoute::emit_frame_or_fragments`, its only consumer: a
/// build with none of these codecs (the lwIP MCU profiles reach it) emits
/// no network message at all, and an ungated struct is dead code the
/// workspace's `-D warnings` rejects.
#[cfg(any(
    feature = "codec-push",
    feature = "codec-request",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "declare-keyexpr",
    feature = "declare-subscriber",
    feature = "declare-queryable",
    feature = "declare-token",
    feature = "declare-interest",
    feature = "liveliness-token",
))]
#[derive(Clone, Copy)]
pub(crate) struct FrameEmit {
    /// The frame's own `ext_qos` — `Some(p)` iff the effective priority is
    /// non-DEFAULT, which is also how the emit reconstructs the SN conduit.
    pub(crate) ext_qos: Option<Priority>,
    /// The already-minted Frame SN. A fragment chain reuses it as the FIRST
    /// fragment's SN (R311y206) rather than re-minting a block.
    pub(crate) sn: crate::sn::Sn,
    /// Reliable vs best-effort — selects the conduit and the frame's R flag.
    pub(crate) reliable: bool,
    /// The outbound budget one frame may occupy; over it, the message
    /// fragments (or is emitted as-is when fragmentation is compiled out).
    pub(crate) mtu: usize,
    /// The negotiated SN ring the chain's follow-on SNs walk.
    pub(crate) sn_mask: crate::sn::Sn,
    /// This profile's reassembly cap — a chain longer than this is refused,
    /// because no same-profile peer could rejoin it. `usize::MAX` = no cap.
    pub(crate) max_reassembly_bytes: usize,
    /// R2926 — the message's congestion deadline, what is left of it after the
    /// ask for the first frame's room: a fragment chain asks again before each
    /// further fragment, against the same deadline.
    pub(crate) deadline: crate::tx_deadline::PushDeadline,
    /// The bound the message's codec gives its bytes: a heap frame reserves it, and a frame
    /// sent whole asks a slot of it. A lend-only build measures nothing.
    #[cfg(not(feature = "tx-lend-only"))]
    pub(crate) worst_case_payload: usize,
}
#[cfg(test)]
mod conduit_tx_sn_tests {
    use super::ConduitTxSn;
    use crate::sn::{mask_from_res, to_wire};
    use core::cell::Cell;

    /// A channel's count runs past 32 bits on a long session, and what it mints is still the
    /// count's position on the ring in either word: the 28-bit ring wraps to 0 where the count
    /// crosses 2^32, and the channel steps on from there.
    #[test]
    fn a_count_past_32_bits_mints_its_ring_position_in_either_word() {
        let mask = mask_from_res(0x02);
        let tx = ConduitTxSn::<Cell<u64>>::new(u64::from(u32::MAX));
        assert_eq!(to_wire(tx.mint(true, mask)), 0x0FFF_FFFF);
        assert_eq!(
            to_wire(tx.mint(true, mask)),
            0,
            "the count crossed 2^32 at the seam"
        );
        assert_eq!(to_wire(tx.mint(true, mask)), 1);
        assert_eq!(
            to_wire(tx.mint(false, mask)),
            0x0FFF_FFFF,
            "the other channel did not move"
        );
    }
}

#[cfg(all(
    test,
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    )
))]
mod sender_inside_tests {
    use super::SenderInside;
    use core::sync::atomic::{AtomicBool, Ordering};

    /// The flag is raised for exactly as long as the sender is inside: what a droppable send that
    /// finds the conduit held reads to tell a sender from the writer's flush.
    #[test]
    fn the_flag_is_raised_while_a_sender_is_inside_and_lowered_when_it_leaves() {
        let flag = AtomicBool::new(false);
        {
            let _inside = SenderInside::mark(&flag);
            assert!(flag.load(Ordering::Relaxed), "raised inside");
        }
        assert!(!flag.load(Ordering::Relaxed), "lowered once it leaves");
    }

    /// A staging that unwinds lowers the flag too: a sender that panicked inside its conduit does
    /// not leave every later droppable send dropped behind a sender that is gone.
    #[test]
    fn a_sender_that_unwinds_lowers_the_flag() {
        let flag = AtomicBool::new(false);
        let unwound = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
            let _inside = SenderInside::mark(&flag);
            assert!(flag.load(Ordering::Relaxed));
            panic!("the staging unwinds");
        }));
        assert!(unwound.is_err(), "CONTROL: the staging did unwind");
        assert!(!flag.load(Ordering::Relaxed), "lowered on the unwind");
    }

    /// The flag of a runtime of one task, a cell, is raised and lowered as the atomic one is.
    #[test]
    fn a_cell_flag_is_raised_while_a_sender_is_inside_and_lowered_when_it_leaves() {
        let flag = core::cell::Cell::new(false);
        {
            let _inside = SenderInside::mark(&flag);
            assert!(flag.get(), "raised inside");
        }
        assert!(!flag.get(), "lowered once it leaves");
    }
}

#[cfg(all(test, feature = "transport-batching"))]
mod window_word_tests {
    use super::{close_and_drain, set_window, WINDOW_CALLER, WINDOW_DRAINING, WINDOW_REPLIES};
    use core::sync::atomic::{AtomicU64, Ordering};

    /// A window opens once and closes once, and the others stand as they were: of two that open it
    /// at once one is told it did, so a hold is let go of by the one that raised it. Turned red by
    /// a change that answers it changed the bit when it was already so, or one that writes over
    /// another bit.
    #[test]
    fn a_window_opens_and_closes_once_beside_the_others() {
        let word = AtomicU64::new(WINDOW_CALLER);
        assert!(set_window(&word, WINDOW_REPLIES, true), "opened");
        assert!(!set_window(&word, WINDOW_REPLIES, true), "open already");
        assert_eq!(word.load(Ordering::SeqCst), WINDOW_CALLER | WINDOW_REPLIES);
        assert!(set_window(&word, WINDOW_REPLIES, false), "closed");
        assert!(!set_window(&word, WINDOW_REPLIES, false), "closed already");
        assert_eq!(
            word.load(Ordering::SeqCst),
            WINDOW_CALLER,
            "the caller's window stands"
        );
    }

    /// While a closed window is drained, the word reads the window closed and a drain under way,
    /// so a message joining no window still finds a frame may be open; once the drain ends the word
    /// reads nothing open. Turned red by a close that does not count its drain, or a drain that is
    /// never taken off the count.
    #[test]
    fn a_drain_is_counted_from_the_close_to_its_end() {
        let word = AtomicU64::new(WINDOW_REPLIES);
        let during = core::cell::Cell::new(0);
        close_and_drain(&word, WINDOW_REPLIES, || {
            during.set(word.load(Ordering::SeqCst));
        });
        assert_eq!(
            during.get(),
            WINDOW_DRAINING,
            "closed, with its drain counted"
        );
        assert_eq!(word.load(Ordering::SeqCst), 0, "nothing open once drained");
    }

    /// Two drains under way at once are two counts, and the first to end leaves the second's: a
    /// frame the second has not reached is still sent first. Turned red by a count of one bit.
    #[test]
    fn two_drains_under_way_are_counted_apart() {
        let word = AtomicU64::new(WINDOW_CALLER | WINDOW_REPLIES);
        let inner = core::cell::Cell::new(0);
        close_and_drain(&word, WINDOW_CALLER, || {
            close_and_drain(&word, WINDOW_REPLIES, || {
                inner.set(word.load(Ordering::SeqCst));
            });
        });
        assert_eq!(inner.get(), 2 * WINDOW_DRAINING, "both drains counted");
        assert_eq!(word.load(Ordering::SeqCst), 0);
    }

    /// The word of a runtime of one task, a cell, opens, closes and counts as the atomic one does.
    #[test]
    fn a_cell_word_keeps_its_windows_as_the_atomic_one() {
        let word = core::cell::Cell::new(0u64);
        assert!(set_window(&word, WINDOW_CALLER, true));
        let during = core::cell::Cell::new(0);
        close_and_drain(&word, WINDOW_CALLER, || during.set(word.get()));
        assert_eq!(during.get(), WINDOW_DRAINING);
        assert_eq!(word.get(), 0);
    }
}

#[cfg(all(
    test,
    feature = "transport-batching",
    any(
        feature = "codec-push",
        feature = "codec-request",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "declare-keyexpr",
        feature = "declare-subscriber",
        feature = "declare-queryable",
        feature = "declare-token",
        feature = "declare-interest",
        feature = "liveliness-token",
    )
))]
mod window_join_tests {
    use super::{
        window_joins, window_may_hold_open, WINDOW_CALLER, WINDOW_DRAINING, WINDOW_LINK,
        WINDOW_REPLIES,
    };

    /// Every message joins the caller's and the link's window; the hold of the replies is joined
    /// by a reply alone; with nothing open nothing joins. Turned red by a hold that a message which
    /// is not a reply joins, or a window a message does not join.
    #[test]
    fn a_message_joins_the_windows_it_belongs_to() {
        for open in [WINDOW_CALLER, WINDOW_LINK] {
            assert!(window_joins(open, false), "any message joins {open}");
            assert!(window_joins(open, true), "a reply joins {open}");
        }
        assert!(window_joins(WINDOW_REPLIES, true), "a reply joins the hold");
        assert!(
            !window_joins(WINDOW_REPLIES, false),
            "what is not a reply does not"
        );
        assert!(!window_joins(0, true), "nothing open, nothing joined");
        assert!(
            !window_joins(WINDOW_DRAINING, true),
            "a drain is no window to join"
        );
    }

    /// A frame may be open while any window is or a drain is under way, and only then: with the
    /// word clear a message reads no conduit's frame. Turned red by a word that reads clear with a
    /// drain under way.
    #[test]
    fn a_frame_may_be_open_only_while_a_window_or_a_drain_is() {
        assert!(!window_may_hold_open(0), "nothing open");
        for word in [WINDOW_CALLER, WINDOW_LINK, WINDOW_REPLIES, WINDOW_DRAINING] {
            assert!(window_may_hold_open(word), "{word} may leave a frame open");
        }
    }
}
