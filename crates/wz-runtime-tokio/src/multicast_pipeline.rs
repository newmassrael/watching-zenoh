// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2931 — a multicast group's transmission pipeline, pushed onto by its
//! PRODUCERS.
//!
//! Upstream's producer pushes a message into the link's pipeline on its own
//! thread and waits there for room
//! (`io/zenoh-transport/src/multicast/tx.rs` @ `fn schedule_on_link(&self, msg: NetworkMessageRef) -> ZResult<bool> {`):
//! it reads the transport's link, clones the pipeline out of it, and pushes;
//! with no link it drops the message. The pipeline holds one stage per
//! priority, each with its own sequence numbers and its own lock, so a band
//! that waits for room holds no other band
//! (`io/zenoh-transport/src/common/pipeline.rs` @ `pub(crate) fn push_network_message(`).
//!
//! Until this round a wz producer (an application's publish, the router's
//! group sink, the reply sink) handed its message to the drive loop over an
//! unbounded channel, and the loop pushed. So a blocking publish never
//! blocked, and the channel in front of the bounded lanes had no bound at all.
//! [`MulticastTxProducer`] is the handle a producer holds instead: its
//! [`push`](MulticastTxProducer::push) mints, asks for room and enqueues on the
//! caller's own thread, under the lock of the one conduit the message rides.
//!
//! The drive loop owns the other side, `MulticastTxPlane`: it attaches a
//! link's pipeline to the producer when the link comes up, starts the transmit
//! task that writes the lanes, counts what was pushed and what was written,
//! advertises the conduits as WRITTEN in its JOIN, and detaches the pipeline
//! when the link goes. A push while nothing is attached is dropped, as
//! upstream drops one while the transport has no link; a group face that
//! rejoins attaches a new pipeline to the same producer.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, RwLock};

use wz_session_core::multicast_params::MulticastParams;
use wz_session_core::multicast_tx::MulticastTxItem;
use wz_session_core::qos::Priority;
use wz_session_core::sn::{self, MulticastTxConduits};

use crate::multicast_glue::{MulticastDatagramSender, MulticastLinkDriver, MulticastStatsRecorder};

/// Per sending priority, in queue order: the `(reliable, sn)` each queued
/// datagram carries, `None` for a JOIN or a Close, which carry no SN.
type Queued = VecDeque<Option<(bool, u64)>>;

/// One conduit's stage: the SNs it mints and the record of what it queued.
/// The record lives beside the minter, under the same lock, because the two
/// must agree on queue order: a datagram is minted, enqueued and recorded in
/// one hold of the lock.
///
/// A build with no TX body codec mints nothing (`MulticastTxItem` is
/// uninhabited), so its stages keep only the record of the JOINs and Closes
/// the loop queues.
struct Stage {
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    ))]
    sn: wz_session_core::sn::TxSn,
    queued: Queued,
}

impl Stage {
    fn new(mask: u64) -> Mutex<Self> {
        #[cfg(not(any(
            feature = "codec-push",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "liveliness-token"
        )))]
        let _ = mask;
        Mutex::new(Self {
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-response",
                feature = "codec-response-final",
                feature = "liveliness-token"
            ))]
            sn: wz_session_core::sn::TxSn::new(mask),
            queued: VecDeque::new(),
        })
    }
}

/// Every conduit's stage, shared by the producers and the plane.
type Stages = [Mutex<Stage>; Priority::NUM];

/// A fresh stage per conduit, every ring at 0 (the JOIN advertisement makes
/// any start valid).
fn new_stages(mask: u64) -> Arc<Stages> {
    Arc::new(std::array::from_fn(|_| Stage::new(mask)))
}

/// Why [`MulticastTxProducer::push`] did not put a message on a pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MulticastTxRefused {
    /// No link is attached: the message is dropped, as upstream's multicast
    /// transport drops one while it has no link.
    Unlinked,
    /// The group's egress namespace could not be applied to the message (its
    /// namespaced key expression exceeds what the codec carries). It is
    /// dropped rather than sent under its bare key expression.
    Namespace,
}

/// One attached link's pipeline, as producers push onto it.
struct Link {
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    ))]
    params: MulticastParams,
    lanes: crate::writer_queue::OutboundTx,
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    ))]
    stages: Arc<Stages>,
    /// What each push did, for the plane to count: the stats recorder is the
    /// loop's, borrowed, and cannot be reached from a producer's thread.
    /// `None` on a [`MulticastTxTap`], where nothing counts.
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    ))]
    pushed: Option<
        tokio::sync::mpsc::UnboundedSender<(
            wz_session_core::multicast_tx::MulticastTxTally,
            wz_session_core::tx_deadline::PushOutcome,
        )>,
    >,
    /// §5.21 routing-namespace — the group's egress prefix, taken from the
    /// dispatcher when the link was attached (`MulticastDispatcher::set_namespace`
    /// is called before bring-up), so egress and every per-peer ingress still
    /// derive from one value.
    #[cfg(feature = "routing-namespace")]
    namespace: Option<wz_session_core::keyexpr_prefix::OwnedNonWildKeyExpr>,
}

struct Shared {
    link: RwLock<Option<Arc<Link>>>,
    linked: tokio::sync::watch::Sender<bool>,
}

/// The handle a multicast group's producers push through: an application's
/// session, the router's group sink, and the reply sink. Cloneable; every
/// clone pushes onto whichever pipeline is attached.
#[derive(Clone)]
pub struct MulticastTxProducer {
    shared: Arc<Shared>,
}

impl Default for MulticastTxProducer {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MulticastTxProducer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MulticastTxProducer")
            .field("linked", &self.is_linked())
            .finish()
    }
}

impl MulticastTxProducer {
    /// A producer with no link attached yet.
    pub fn new() -> Self {
        let (linked, _) = tokio::sync::watch::channel(false);
        Self {
            shared: Arc::new(Shared {
                link: RwLock::new(None),
                linked,
            }),
        }
    }

    /// Whether a link's pipeline is attached right now.
    pub fn is_linked(&self) -> bool {
        self.shared
            .link
            .read()
            .expect("multicast producer poisoned")
            .is_some()
    }

    /// Wait until a link's pipeline is attached: a push made before then is
    /// dropped.
    pub async fn linked(&self) {
        let mut linked = self.shared.linked.subscribe();
        let _ = linked.wait_for(|linked| *linked).await;
    }

    /// Push `item` onto the attached pipeline, on the caller's thread: ask its
    /// conduit for room within the message's deadline, and only then mint and
    /// enqueue. `Ok(Congested)` is a message that found no room, which a
    /// multicast transport drops and counts, blocking or not.
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    ))]
    pub fn push(
        &self,
        item: MulticastTxItem,
    ) -> Result<wz_session_core::tx_deadline::PushOutcome, MulticastTxRefused> {
        // Read the link, clone the pipeline out, and let the read go before
        // pushing, as upstream's schedule does: a producer waiting for room
        // must not hold off the loop attaching or detaching.
        let link = self
            .shared
            .link
            .read()
            .expect("multicast producer poisoned")
            .clone();
        match link {
            Some(link) => link.push(item),
            None => {
                log::trace!("multicast message dropped: the group has no link");
                Err(MulticastTxRefused::Unlinked)
            }
        }
    }

    /// No TX body codec: [`MulticastTxItem`] is uninhabited, so nothing can be
    /// pushed.
    #[cfg(not(any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    )))]
    pub fn push(
        &self,
        item: MulticastTxItem,
    ) -> Result<wz_session_core::tx_deadline::PushOutcome, MulticastTxRefused> {
        match item {}
    }

    fn attach(&self, link: Arc<Link>) {
        let mut slot = self
            .shared
            .link
            .write()
            .expect("multicast producer poisoned");
        assert!(
            slot.is_none(),
            "a multicast producer is attached to one link at a time"
        );
        *slot = Some(link);
        drop(slot);
        self.shared.linked.send_replace(true);
    }

    /// Detach `ours`, if it is still the attached link: a plane dropped after a
    /// later one attached must not take the later one's link away.
    fn detach(&self, ours: &Arc<Link>) {
        let mut slot = self
            .shared
            .link
            .write()
            .expect("multicast producer poisoned");
        if slot.as_ref().is_some_and(|link| Arc::ptr_eq(link, ours)) {
            *slot = None;
            drop(slot);
            self.shared.linked.send_replace(false);
        }
    }
}

#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "liveliness-token"
))]
impl Link {
    fn push(
        &self,
        item: MulticastTxItem,
    ) -> Result<wz_session_core::tx_deadline::PushOutcome, MulticastTxRefused> {
        use wz_session_core::multicast_tx::{
            multicast_tx_conduit, multicast_tx_push, MulticastTxConduit, MulticastTxTally,
        };
        #[cfg_attr(not(feature = "routing-namespace"), allow(unused_mut))]
        let mut item = item;
        // §5.21 routing-namespace — the one egress chokepoint every producer's
        // message passes. Nothing is relayed onto a multicast group by this
        // path (handshake-free multicast has no forwarder face here), so
        // decorating here re-namespaces nothing forwarded.
        #[cfg(feature = "routing-namespace")]
        if let Some(ns) = self.namespace.as_ref() {
            if wz_session_core::namespace::apply_egress_multicast_item(ns, &mut item).is_err() {
                return Err(MulticastTxRefused::Namespace);
            }
        }
        let tally = MulticastTxTally::of(&item);
        let band = multicast_tx_conduit(&item, &self.params);
        let mut stage = self.stages[band as usize]
            .lock()
            .expect("multicast stage poisoned");
        let Stage { sn, queued } = &mut *stage;
        let outcome = multicast_tx_push(
            item,
            &mut MulticastTxConduit::new(band, sn),
            &self.params,
            &self.params.tx_queue,
            &mut StageQueue {
                lanes: &self.lanes,
                queued,
            },
        );
        drop(stage);
        if let Some(pushed) = self.pushed.as_ref() {
            let _ = pushed.send((tally, outcome));
        }
        Ok(outcome)
    }
}

/// One conduit's lane, as [`multicast_tx_push`](wz_session_core::multicast_tx::multicast_tx_push)
/// pushes onto it while its stage is held.
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "liveliness-token"
))]
struct StageQueue<'a> {
    lanes: &'a crate::writer_queue::OutboundTx,
    queued: &'a mut Queued,
}

#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "liveliness-token"
))]
impl wz_session_core::multicast_tx::MulticastTxQueue for StageQueue<'_> {
    fn wait_for_room(
        &mut self,
        priority: Priority,
        wait: wz_session_core::link::RoomWait,
    ) -> wz_session_core::link::RoomAnswer {
        self.lanes.link_room(priority, wait)
    }

    fn enqueue(&mut self, datagram: wz_session_core::multicast_tx::MulticastTxDatagram) {
        let wz_session_core::multicast_tx::MulticastTxDatagram {
            priority,
            reliable,
            sn,
            bytes,
        } = datagram;
        // A closed queue is a finished link: the datagram is lost with it.
        if self.lanes.send(priority, bytes).is_ok() {
            self.queued.push_back(Some((reliable, sn)));
        }
    }
}

/// R2929 / R2931 — the drive loop's side of one link's pipeline: the lanes'
/// transmit task, the counts of what producers pushed and what the task
/// wrote, and the conduits as written, which the JOIN beacon advertises.
///
/// The lanes are shaped from the group's `TxQueueConf`, per priority in units
/// of the group batch, one lane when the group runs no QoS. A receiver
/// re-seeds its expected SN from every JOIN (`MulticastDispatcher::ingest_join_qos`,
/// as zenoh-pico does), and a JOIN written on the Control lane passes data
/// still queued behind it; had it advertised the minted SNs, the receiver
/// would drop that data as stale when it came. So each stage keeps, in queue
/// order, the SN each queued datagram carries, and [`Self::on_wire`] moves as
/// the transmit task reports each one written.
pub(crate) struct MulticastTxPlane {
    producer: MulticastTxProducer,
    /// The attached pipeline's lanes; dropped at [`Self::finish`] so the
    /// transmit task ends once the last in-flight push lets go of them.
    link: Option<Arc<Link>>,
    stages: Arc<Stages>,
    /// Each datagram the transmit task is done with: the priority it was sent
    /// at, and its size when it was written (`None` when the write failed).
    written: tokio::sync::mpsc::UnboundedReceiver<(Priority, Option<usize>)>,
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        feature = "liveliness-token"
    ))]
    pushed: tokio::sync::mpsc::UnboundedReceiver<(
        wz_session_core::multicast_tx::MulticastTxTally,
        wz_session_core::tx_deadline::PushOutcome,
    )>,
    /// `None` once [`Self::finish`] has joined it.
    writer: Option<tokio::task::JoinHandle<()>>,
    on_wire: MulticastTxConduits,
}

impl MulticastTxPlane {
    /// Shape a pipeline for `params`, start the transmit task over `driver`'s
    /// send half on the TX subsystem, as upstream starts its multicast TX task,
    /// and attach the pipeline to `producer`.
    pub(crate) fn open<D: MulticastLinkDriver>(
        producer: &MulticastTxProducer,
        driver: &D,
        params: &MulticastParams,
        #[cfg(feature = "routing-namespace")] namespace: Option<
            &wz_session_core::keyexpr_prefix::OwnedNonWildKeyExpr,
        >,
    ) -> Self {
        let (lanes, mut queued) = crate::writer_queue::outbound_channel();
        lanes.reshape(
            params
                .tx_queue
                .shape(params.is_qos, usize::from(params.batch_size)),
        );
        let sender = match driver.datagram_sender() {
            Ok(sender) => Some(sender),
            Err(e) => {
                log::warn!("multicast link has no send half ({e}); nothing it queues is sent");
                None
            }
        };
        let (report, written) = tokio::sync::mpsc::unbounded_channel();
        let writer = crate::runtime_pool::WzRuntime::Tx.spawn(async move {
            while let Some((priority, datagram)) = queued.recv_tagged().await {
                // Best-effort, as every multicast send is: a datagram the
                // socket refuses is not counted and is not retried. It is
                // still REPORTED, as done with: the record of what each queued
                // datagram carries is in queue order, and a datagram left
                // unreported would shift every later report onto the wrong one.
                let wrote = match sender.as_ref() {
                    Some(sender) => sender.send(&datagram).await.is_ok(),
                    None => false,
                };
                let _ = report.send((priority, wrote.then_some(datagram.len())));
            }
        });
        let mask = sn::mask_from_res(params.seq_num_res);
        let stages = new_stages(mask);
        #[cfg(any(
            feature = "codec-push",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "liveliness-token"
        ))]
        let (pushed_tx, pushed) = tokio::sync::mpsc::unbounded_channel();
        let link = Arc::new(Link {
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-response",
                feature = "codec-response-final",
                feature = "liveliness-token"
            ))]
            params: params.clone(),
            lanes,
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-response",
                feature = "codec-response-final",
                feature = "liveliness-token"
            ))]
            stages: stages.clone(),
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-response",
                feature = "codec-response-final",
                feature = "liveliness-token"
            ))]
            pushed: Some(pushed_tx),
            #[cfg(feature = "routing-namespace")]
            namespace: namespace.cloned(),
        });
        producer.attach(link.clone());
        Self {
            producer: producer.clone(),
            link: Some(link),
            stages,
            written,
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-response",
                feature = "codec-response-final",
                feature = "liveliness-token"
            ))]
            pushed,
            writer: Some(writer),
            on_wire: MulticastTxConduits::new(mask),
        }
    }

    /// The conduits as written: what the JOIN advertises.
    pub(crate) fn on_wire(&self) -> &MulticastTxConduits {
        &self.on_wire
    }

    /// Queue a datagram that carries no SN — a JOIN or a Close — on the
    /// Control lane, without asking for room: the transmit task writes the
    /// highest lane first, and upstream's TX task writes its JOIN beside the
    /// pipeline rather than through it
    /// (`io/zenoh-transport/src/multicast/link.rs` @ `async fn tx_task(`).
    /// The Control stage is held while it is queued, so the record keeps the
    /// lane's order against a producer pushing at Control.
    pub(crate) fn enqueue_control(&self, datagram: Vec<u8>) {
        let Some(link) = self.link.as_ref() else {
            return;
        };
        let control = Priority::Control;
        let mut stage = self.stages[control as usize]
            .lock()
            .expect("multicast stage poisoned");
        if link.lanes.send(control, datagram).is_ok() {
            stage.queued.push_back(None);
        }
    }

    /// Count what producers pushed and what the transmit task wrote so far,
    /// and move the written conduits past each SN written. Within one sending
    /// priority the lanes are FIFO, so the report for a priority names the
    /// oldest datagram queued at it.
    pub(crate) fn record<R: MulticastStatsRecorder + ?Sized>(&mut self, stats: &R) {
        #[cfg(any(
            feature = "codec-push",
            feature = "codec-response",
            feature = "codec-response-final",
            feature = "liveliness-token"
        ))]
        while let Ok((tally, outcome)) = self.pushed.try_recv() {
            // A network message is counted as sent only once pushed, and as a
            // congestion drop otherwise, as upstream's multicast schedule
            // counts it; each datagram is one transport message, counted
            // below once written.
            match outcome {
                wz_session_core::tx_deadline::PushOutcome::Pushed => {
                    stats.network_message_sent(&tally)
                }
                wz_session_core::tx_deadline::PushOutcome::Congested => {
                    stats.network_message_dropped(&tally)
                }
            }
        }
        while let Ok((priority, bytes)) = self.written.try_recv() {
            if let Some(bytes) = bytes {
                stats.datagram_sent(bytes, 1);
            }
            // A datagram whose write failed is done with too: its SN will
            // never arrive, and advertising past it keeps a receiver from
            // expecting it.
            let front = self.stages[priority as usize]
                .lock()
                .expect("multicast stage poisoned")
                .queued
                .pop_front();
            if let Some(Some((reliable, sn))) = front {
                self.on_wire.written(priority, reliable, sn);
            }
        }
    }

    /// End the link's pipeline: detach it so no producer pushes onto it any
    /// more, let the transmit task write what the lanes hold, and count it. A
    /// departing Close queued just before is therefore on the wire when the
    /// loop returns.
    pub(crate) async fn finish<R: MulticastStatsRecorder + ?Sized>(mut self, stats: &R) {
        // The lanes end when the last holder lets go: this plane now, and a
        // producer that read the link before the detach once its push returns.
        if let Some(link) = self.link.take() {
            self.producer.detach(&link);
        }
        if let Some(writer) = self.writer.take() {
            if let Err(e) = writer.await {
                log::error!("multicast transmit task did not join cleanly: {e}");
            }
        }
        self.record(stats);
    }
}

/// A pipeline attached to a producer with no link under it: its holder reads
/// the datagrams the producer's pushes queue, in the order a transmit task
/// would write them. What a push produces can then be read without a socket —
/// by a test of a producer (a session's publish, the router's group sink), or
/// by a host that carries the group's datagrams itself.
///
/// Nothing counts or advertises what is read here: the JOIN beacon and the
/// transport counts are the drive loop's, and there is none.
pub struct MulticastTxTap {
    lanes: crate::writer_queue::OutboundRx,
    /// The stages' records of what they queued, consumed as the tap reads, as
    /// a transmit task's reports consume them.
    stages: Arc<Stages>,
}

impl MulticastTxTap {
    /// A producer with a pipeline for `params` attached, and the tap on it.
    pub fn attach(params: &MulticastParams) -> (MulticastTxProducer, Self) {
        let producer = MulticastTxProducer::new();
        let (lanes, rx) = crate::writer_queue::outbound_channel();
        lanes.reshape(
            params
                .tx_queue
                .shape(params.is_qos, usize::from(params.batch_size)),
        );
        let mask = sn::mask_from_res(params.seq_num_res);
        let stages = new_stages(mask);
        producer.attach(Arc::new(Link {
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-response",
                feature = "codec-response-final",
                feature = "liveliness-token"
            ))]
            params: params.clone(),
            lanes,
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-response",
                feature = "codec-response-final",
                feature = "liveliness-token"
            ))]
            stages: stages.clone(),
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-response",
                feature = "codec-response-final",
                feature = "liveliness-token"
            ))]
            pushed: None,
            #[cfg(feature = "routing-namespace")]
            namespace: None,
        }));
        (producer, Self { lanes: rx, stages })
    }

    /// The next datagram a push put on the lanes, if any.
    pub fn try_next(&mut self) -> Option<Vec<u8>> {
        let (priority, datagram) = self.lanes.try_recv_tagged()?;
        self.stages[priority as usize]
            .lock()
            .expect("multicast stage poisoned")
            .queued
            .pop_front();
        Some(datagram)
    }
}

impl Drop for MulticastTxPlane {
    /// A loop that is dropped rather than finished (its future cancelled)
    /// still takes its pipeline off the producer, so later pushes are dropped
    /// as unlinked instead of queueing on lanes nobody writes.
    fn drop(&mut self) {
        if let Some(link) = self.link.take() {
            self.producer.detach(&link);
        }
    }
}

// R2931 — the producer's push against a pipeline whose lanes nobody drains (a
// tap that is never read is a link that has stopped writing). A reply
// terminator carries its own congestion control, so one item shape gives both
// a droppable and a blocking message.
#[cfg(all(test, feature = "codec-response-final"))]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use wz_session_core::qos::CongestionControl;
    use wz_session_core::sample::QosLevel;
    use wz_session_core::session_init_params::TxQueueConf;
    use wz_session_core::tx_deadline::PushOutcome;

    const CLOSE_WAIT: Duration = Duration::from_millis(300);

    fn params(is_qos: bool) -> MulticastParams {
        MulticastParams {
            version: 0x09,
            whatami: wz_session_core::WhatAmI::Peer,
            zid: vec![1, 2, 3, 4],
            lease_ms: 5_000,
            join_interval_ms: 100,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size: 64,
            is_qos,
            tx_queue: TxQueueConf {
                // One batch per lane: a few frames fill it.
                sizes: [1; Priority::NUM],
                wait_before_drop_us: 1_000,
                wait_before_close_us: CLOSE_WAIT.as_micros() as u64,
                ..TxQueueConf::default()
            },
        }
    }

    fn terminal(priority: Priority, congestion: CongestionControl) -> MulticastTxItem {
        MulticastTxItem::ResponseFinal {
            request_id: 1,
            qos: QosLevel::from_parts(priority, congestion, false),
        }
    }

    /// Push droppable messages at `priority` until one finds no room.
    fn fill(producer: &MulticastTxProducer, priority: Priority) {
        for _ in 0..64 {
            if producer.push(terminal(priority, CongestionControl::Drop))
                == Ok(PushOutcome::Congested)
            {
                return;
            }
        }
        panic!("the lane never filled");
    }

    /// A blocking message on a full lane waits for room for its whole
    /// `wait_before_close` on the pushing thread, and only then is a
    /// congestion drop — upstream's blocking put on a stalled multicast link.
    /// A droppable one on the same lane is answered at once. Before R2931 the
    /// producer handed the message to an unbounded channel and returned, so
    /// a blocking publish never blocked.
    #[test]
    fn a_blocking_push_waits_on_its_own_thread_before_it_is_dropped() {
        let (producer, _tap) = MulticastTxTap::attach(&params(false));
        fill(&producer, Priority::DEFAULT);

        let started = Instant::now();
        let outcome = producer.push(terminal(Priority::DEFAULT, CongestionControl::Block));
        let waited = started.elapsed();
        assert_eq!(outcome, Ok(PushOutcome::Congested));
        assert!(
            waited >= CLOSE_WAIT,
            "a blocking push returned after {waited:?}, before its {CLOSE_WAIT:?}"
        );

        let started = Instant::now();
        let outcome = producer.push(terminal(Priority::DEFAULT, CongestionControl::Drop));
        assert_eq!(outcome, Ok(PushOutcome::Congested));
        assert!(
            started.elapsed() < CLOSE_WAIT / 3,
            "a droppable push on a congested lane does not wait"
        );
    }

    /// A band waiting for room holds only its own conduit: while a blocking
    /// push waits on the full Data lane, a push on RealTime, whose lane has
    /// room, goes through at once — upstream holds one priority's stage while
    /// it waits (`io/zenoh-transport/src/common/pipeline.rs` @ `pub(crate) fn push_network_message(`).
    #[cfg(feature = "transport-qos")]
    #[test]
    fn a_band_waiting_for_room_does_not_hold_another() {
        let (producer, _tap) = MulticastTxTap::attach(&params(true));
        fill(&producer, Priority::DEFAULT);

        let waiting = producer.clone();
        let blocked = std::thread::spawn(move || {
            waiting.push(terminal(Priority::DEFAULT, CongestionControl::Block))
        });
        // Let the blocking push take its stage and start waiting.
        std::thread::sleep(CLOSE_WAIT / 6);

        let started = Instant::now();
        let outcome = producer.push(terminal(Priority::RealTime, CongestionControl::Drop));
        let took = started.elapsed();
        assert_eq!(
            outcome,
            Ok(PushOutcome::Pushed),
            "the RealTime lane has room"
        );
        assert!(
            took < CLOSE_WAIT / 3,
            "a RealTime push waited {took:?} behind a blocked Data push"
        );
        assert_eq!(
            blocked.join().expect("blocked pusher"),
            Ok(PushOutcome::Congested)
        );
    }

    /// Nothing attached: a push is dropped as unlinked, as upstream drops one
    /// while its transport has no link.
    #[test]
    fn a_push_with_no_link_attached_is_dropped() {
        let producer = MulticastTxProducer::new();
        assert!(!producer.is_linked());
        assert_eq!(
            producer.push(terminal(Priority::DEFAULT, CongestionControl::Drop)),
            Err(MulticastTxRefused::Unlinked)
        );
    }
}
