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

use crate::link::SessionRuntime;
#[cfg(feature = "tx-lend-only")]
use crate::session_actions::TxRefusalCounts;
use crate::session_actions::{FrameTxConduits, LinkState, TxConduits};

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
    fn close_lent_batch(
        &self,
        batch: &mut crate::session_actions::BatchTx,
        idx: usize,
        priority: crate::qos::Priority,
    ) {
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
        lend: &mut crate::session_actions::BatchLendCounts,
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
        batch: &mut crate::session_actions::BatchTx,
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
        for idx in (0..crate::session_actions::TX_CONDUITS).filter(|&idx| takes(idx)) {
            // The walk is over BANDS, not slots: the index names a priority and
            // the priority selects its conduit, so the drain and the staging
            // seam agree by construction on which conduit is which.
            let priority = TxConduits::<R>::conduit_priority(idx);
            let conduit = self.tx.conduits.conduit(priority);
            let drain = |batch: &mut crate::session_actions::BatchTx| {
                self.flush_conduit(idx, priority, batch)
            };
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
        if crate::session_actions::TX_CONDUITS > 1 && self.send_open_lent_batches(link) {
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
        write: &dyn crate::session_actions::LentWrite,
    ) -> crate::session_actions::Lend<sce_forge_runtime::codec::CodecError> {
        // Lent from where `acquire` wrote it, as `write_n_msg` lends its slot.
        let mut lent = self.lease_on(link, want, priority);
        let Some(slot) = lent.as_mut() else {
            return crate::session_actions::Lend::NoSlot;
        };
        if let Err(why) = write.write_lent(&mut *slot) {
            return crate::session_actions::Lend::Refused(why);
        }
        self.tx
            .emit_on_link(link, &[], Some(slot), reliability, priority, false);
        crate::session_actions::Lend::Sent
    }

    /// The lend for a path that writes its own frame (a lean frame, a fragment): the link
    /// `send_wire` would route to lends the slot ([`Self::send_lent_on`]). A `Frame`'s lend is
    /// `SessionLinkActions::write_n_msg`.
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
        write: &dyn crate::session_actions::LentWrite,
    ) -> crate::session_actions::Lend<sce_forge_runtime::codec::CodecError> {
        self.with_conduit_link(reliability, priority, |link| {
            self.send_lent_on(link, reliability, priority, want, write)
        })
    }
}

impl<R: SessionRuntime> core::fmt::Debug for TransportTx<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransportTx")
            .field("conduits", &self.conduits)
            .finish_non_exhaustive()
    }
}
