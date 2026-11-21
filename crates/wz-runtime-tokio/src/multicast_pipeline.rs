// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2937 — a multicast group's transmission pipeline, pushed onto by its
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
        any(feature = "liveliness-token", feature = "declare-subscriber")
    ))]
    sn: wz_session_core::sn::TxSn,
    /// The conduit's open frame while the group's batch window is open
    /// ([`MulticastTxProducer::batch_start`]), under the lock that mints its SN.
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        any(feature = "liveliness-token", feature = "declare-subscriber")
    ))]
    window: wz_session_core::multicast_tx::MulticastBatch,
    queued: Queued,
}

impl Stage {
    fn new(mask: u64) -> Mutex<Self> {
        #[cfg(not(any(
            feature = "codec-push",
            feature = "codec-response",
            feature = "codec-response-final",
            any(feature = "liveliness-token", feature = "declare-subscriber")
        )))]
        let _ = mask;
        Mutex::new(Self {
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-response",
                feature = "codec-response-final",
                any(feature = "liveliness-token", feature = "declare-subscriber")
            ))]
            sn: wz_session_core::sn::TxSn::new(mask),
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-response",
                feature = "codec-response-final",
                any(feature = "liveliness-token", feature = "declare-subscriber")
            ))]
            window: wz_session_core::multicast_tx::MulticastBatch::new(),
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

/// R3264 — the lanes a group's pipeline is built over: the datagram queue,
/// under `runtime-zero-copy` a two-class transmit pool whose budgets follow the
/// group's shape (`OutboundTx::reshape`), into whose slots a push encodes each
/// datagram (`StageQueue::enqueue_lent`). The ONE constructor the drive loop's
/// pipeline and [`MulticastTxTap::attach_pooled`] share, so what the tap proves
/// is the queue the drive loop writes from.
fn pipeline_lanes() -> (
    crate::writer_queue::OutboundTx,
    crate::writer_queue::OutboundRx,
) {
    crate::writer_queue::datagram_outbound_channel()
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
        any(feature = "liveliness-token", feature = "declare-subscriber")
    ))]
    params: MulticastParams,
    lanes: crate::writer_queue::OutboundTx,
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        any(feature = "liveliness-token", feature = "declare-subscriber")
    ))]
    stages: Arc<Stages>,
    /// Per stage, whether a PUSH holds it ([`SenderInside`]): a stage is also held by what is not
    /// one (the window's flush, a transmit report settling its records), which lets go once done,
    /// and a profile that drops at once drops only behind a push, as pico's try-lock fails only
    /// on a lock another send holds.
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        any(feature = "liveliness-token", feature = "declare-subscriber")
    ))]
    senders: [std::sync::atomic::AtomicBool; Priority::NUM],
    /// What each push did, for the plane to count: the stats recorder is the
    /// loop's, borrowed, and cannot be reached from a producer's thread.
    /// `None` on a [`MulticastTxTap`], where nothing counts.
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        any(feature = "liveliness-token", feature = "declare-subscriber")
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
    /// A JOIN asked for ahead of the beacon's cadence ([`MulticastTxProducer::request_join`]).
    /// A `Notify` keeps one permit, so requests made before the loop looks fold into one JOIN.
    join_now: tokio::sync::Notify,
    /// What runs right after each JOIN is queued ([`MulticastTxProducer::set_after_join`]).
    after_join: RwLock<Option<AfterJoin>>,
    /// Whether the batch window is open ([`MulticastTxProducer::batch_start`]): the producer's,
    /// not the link's, so a group face that rejoins keeps it. Read by a push under its conduit's
    /// lock, which is what lets the window's close flush every conduit with nothing left open
    /// behind it (see [`MulticastTxProducer::batch_stop`]).
    window_open: std::sync::atomic::AtomicBool,
}

/// What a group's loop runs right after it queues a JOIN, on the loop's own thread
/// ([`MulticastTxProducer::set_after_join`]).
pub type AfterJoin = Arc<dyn Fn() + Send + Sync>;

/// A [`MulticastTxProducer`] that does not keep it alive ([`MulticastTxProducer::downgrade`]).
#[derive(Clone)]
pub struct WeakMulticastTxProducer {
    shared: std::sync::Weak<Shared>,
}

impl WeakMulticastTxProducer {
    /// The producer, while anything else still holds it.
    pub fn upgrade(&self) -> Option<MulticastTxProducer> {
        self.shared
            .upgrade()
            .map(|shared| MulticastTxProducer { shared })
    }
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
                join_now: tokio::sync::Notify::new(),
                after_join: RwLock::new(None),
                window_open: std::sync::atomic::AtomicBool::new(false),
            }),
        }
    }

    /// Open the batch window (zenoh-pico `zp_batch_start` on a multicast transport): from now on
    /// a message joins its conduit's open frame instead of leaving as a datagram of its own,
    /// until the frame fills, an express message takes it, or the window is flushed or closed
    /// (`vendor/zenoh-pico/src/transport/common/tx.c` @ `static z_result_t _z_transport_tx_send_n_msg_inner(`).
    /// Opening an open window changes nothing.
    pub fn batch_start(&self) {
        self.shared
            .window_open
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Send every conduit's open frame now and keep the window open (zenoh-pico
    /// `zp_batch_flush`).
    pub fn batch_flush(&self) {
        if let Some(link) = self.attached() {
            link.flush_window();
        }
    }

    /// Close the batch window and send every conduit's open frame (zenoh-pico `zp_batch_stop`).
    ///
    /// Closed BEFORE the flush, as pico stops batching before it sends the batch: a push reads
    /// the window under its conduit's lock, so one that read it open had its message in that
    /// conduit's frame before the flush below takes the lock, and one that takes the lock after
    /// the flush reads it closed and sends its message alone.
    pub fn batch_stop(&self) {
        self.shared
            .window_open
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.batch_flush();
    }

    /// The attached link's pipeline, read and let go of at once (see [`Self::push`]).
    fn attached(&self) -> Option<Arc<Link>> {
        self.shared
            .link
            .read()
            .expect("multicast producer poisoned")
            .clone()
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

    /// Ask the group's loop to send its JOIN now rather than at the beacon's next turn, as
    /// pico's `zp_send_join` sends one on the caller's word
    /// (`vendor/zenoh-pico/src/transport/common/lease.c` @ `z_result_t _z_send_join(`). The
    /// loop then keeps its cadence from that JOIN. A request while no loop runs is kept for
    /// the next one.
    pub fn request_join(&self) {
        self.shared.join_now.notify_one();
    }

    /// A JOIN was asked for ([`Self::request_join`]); what the group's loop waits on beside
    /// its link.
    pub(crate) async fn join_requested(&self) {
        self.shared.join_now.notified().await;
    }

    /// Run `after` right after each JOIN the group's loop queues, on the loop's thread, in place
    /// of any earlier one. What is sent from it leaves after that JOIN: the JOIN is queued on the
    /// Control lane before it runs, and the transmit task writes the highest lane first. It is
    /// how a member answers an interest as zenoh-pico does, a JOIN first so that a sender that
    /// has not admitted it yet does admit it before the answer
    /// (`vendor/zenoh-pico/src/session/interest.c` @ `// Push a join in case it's a new node`).
    pub fn set_after_join(&self, after: AfterJoin) {
        *self
            .shared
            .after_join
            .write()
            .expect("multicast producer poisoned") = Some(after);
    }

    /// A handle that does not keep this producer alive, for a hook the producer itself holds.
    pub fn downgrade(&self) -> WeakMulticastTxProducer {
        WeakMulticastTxProducer {
            shared: Arc::downgrade(&self.shared),
        }
    }

    /// Run the hook [`Self::set_after_join`] installed, if any, cloned out of its lock first.
    pub(crate) fn run_after_join(&self) {
        let after = self
            .shared
            .after_join
            .read()
            .expect("multicast producer poisoned")
            .clone();
        if let Some(after) = after {
            after();
        }
    }

    /// Push `item` onto the attached pipeline, on the caller's thread: ask its
    /// conduit for room within the message's deadline, and only then mint and
    /// enqueue. `Ok(Congested)` is a message that found no room, which a
    /// multicast transport drops and counts, blocking or not.
    #[cfg(any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-response-final",
        any(feature = "liveliness-token", feature = "declare-subscriber")
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
            Some(link) => link.push(item, &self.shared.window_open),
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
        any(feature = "liveliness-token", feature = "declare-subscriber")
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
    any(feature = "liveliness-token", feature = "declare-subscriber")
))]
impl Link {
    fn push(
        &self,
        item: MulticastTxItem,
        window_open: &std::sync::atomic::AtomicBool,
    ) -> Result<wz_session_core::tx_deadline::PushOutcome, MulticastTxRefused> {
        use wz_session_core::multicast_tx::{
            multicast_tx_conduit, multicast_tx_droppable, multicast_tx_push,
            multicast_tx_push_batched, MulticastTxConduit, MulticastTxTally,
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
        // A droppable push does not wait for its stage as a blocking one does: a blocking push
        // holds its stage across its own wait for room, up to `wait_before_close`, and a stage
        // taken by waiting would hold the droppable push behind it as long, as the unicast
        // dispatch's conduit would (`SessionLinkActions::dispatch_network_message_at`). What a
        // held stage costs it instead is the queue profile's (`droppable_stage`).
        let mut conf = self.params.tx_queue;
        let sender = &self.senders[band as usize];
        let stage = if multicast_tx_droppable(&item, &self.params) {
            droppable_stage(&self.stages[band as usize], sender, &mut conf, |wait| {
                self.lanes.link_room(band, wait)
            })
        } else {
            Ok(self.stages[band as usize]
                .lock()
                .expect("multicast stage poisoned"))
        };
        let mut stage = match stage {
            Ok(stage) => stage,
            Err(dropped) => {
                if let Some(pushed) = self.pushed.as_ref() {
                    let _ = pushed.send((tally, dropped));
                }
                return Ok(dropped);
            }
        };
        let inside = SenderInside::mark(sender);
        let Stage { sn, window, queued } = &mut *stage;
        let mut queue = StageQueue {
            lanes: &self.lanes,
            queued,
        };
        // Read under the conduit's lock: see `Shared::window_open`.
        let outcome = if window_open.load(std::sync::atomic::Ordering::SeqCst) {
            multicast_tx_push_batched(
                item,
                &mut MulticastTxConduit::new(band, sn),
                &self.params,
                &conf,
                &mut queue,
                window,
            )
        } else {
            // A frame a window left open leaves ahead of the message, which keeps its order.
            window.flush(band, &self.params, &mut queue);
            multicast_tx_push(
                item,
                &mut MulticastTxConduit::new(band, sn),
                &self.params,
                &conf,
                &mut queue,
            )
        };
        // Unmarked before the stage is let go: a push that then finds it held finds a holder
        // that is not one and waits for it, where the other order would drop it behind none.
        drop(inside);
        drop(stage);
        if let Some(pushed) = self.pushed.as_ref() {
            let _ = pushed.send((tally, outcome));
        }
        Ok(outcome)
    }

    /// Put every conduit's open frame on the lanes, each under its own conduit's lock, the
    /// most urgent conduit first, as the unicast window drains.
    fn flush_window(&self) {
        for (index, stage) in self.stages.iter().enumerate() {
            let mut stage = stage.lock().expect("multicast stage poisoned");
            let Stage { window, queued, .. } = &mut *stage;
            window.flush(
                Priority::from_wire(index as u8),
                &self.params,
                &mut StageQueue {
                    lanes: &self.lanes,
                    queued,
                },
            );
        }
    }
}

/// A push inside its stage, marked for as long as this lives.
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    any(feature = "liveliness-token", feature = "declare-subscriber")
))]
struct SenderInside<'a>(&'a std::sync::atomic::AtomicBool);

#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    any(feature = "liveliness-token", feature = "declare-subscriber")
))]
impl<'a> SenderInside<'a> {
    fn mark(flag: &'a std::sync::atomic::AtomicBool) -> Self {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        Self(flag)
    }
}

#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    any(feature = "liveliness-token", feature = "declare-subscriber")
))]
impl Drop for SenderInside<'_> {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The stage of a droppable push: taken when it is free. While another holds it, what the push
/// does is the queue profile's (`TxQueueConf::held_drop`): zenoh's asks the lane for room itself
/// with `ask`, without the stage and out of its `wait_before_drop`, and is a congestion drop
/// (`PushOutcome::Congested`) when there is none within it, while room means the holder is about
/// to let go and the stage is tried again; pico's is dropped at once, asking nothing, when the
/// holder is another push (`sender`), as pico's try-lock fails only on a lock another send holds
/// (`PushOutcome::Held`, which its sender is told of), and waits for a holder that is not one.
/// What the waits spent comes off `conf`'s `wait_before_drop_us`, so the push spends one deadline
/// in all.
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    any(feature = "liveliness-token", feature = "declare-subscriber")
))]
fn droppable_stage<'a>(
    stage: &'a Mutex<Stage>,
    sender: &std::sync::atomic::AtomicBool,
    conf: &mut wz_session_core::session_init_params::TxQueueConf,
    mut ask: impl FnMut(wz_session_core::link::RoomWait) -> wz_session_core::link::RoomAnswer,
) -> Result<std::sync::MutexGuard<'a, Stage>, wz_session_core::tx_deadline::PushOutcome> {
    use wz_session_core::link::{LinkRoom, RoomWait};
    use wz_session_core::session_init_params::HeldDrop;
    use wz_session_core::tx_deadline::PushOutcome;
    loop {
        match stage.try_lock() {
            Ok(stage) => return Ok(stage),
            Err(std::sync::TryLockError::Poisoned(_)) => panic!("multicast stage poisoned"),
            Err(std::sync::TryLockError::WouldBlock) => {}
        }
        if conf.held_drop == HeldDrop::DropAtOnce {
            // Only behind another push (`sender`); a holder that is not one lets go once done.
            if sender.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(PushOutcome::Held);
            }
            std::hint::spin_loop();
            continue;
        }
        let answer = ask(RoomWait::Drop {
            wait_us: conf.wait_before_drop_us,
        });
        conf.wait_before_drop_us = conf.wait_before_drop_us.saturating_sub(answer.waited_us);
        if answer.room == LinkRoom::Congested {
            return Err(PushOutcome::Congested);
        }
        std::hint::spin_loop();
    }
}

/// No TX body codec: no message is ever pushed, so no window frame is ever open.
#[cfg(not(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    any(feature = "liveliness-token", feature = "declare-subscriber")
)))]
impl Link {
    fn flush_window(&self) {}
}

/// One conduit's lane, as [`multicast_tx_push`](wz_session_core::multicast_tx::multicast_tx_push)
/// pushes onto it while its stage is held.
#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    any(feature = "liveliness-token", feature = "declare-subscriber")
))]
struct StageQueue<'a> {
    lanes: &'a crate::writer_queue::OutboundTx,
    queued: &'a mut Queued,
}

#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    any(feature = "liveliness-token", feature = "declare-subscriber")
))]
impl StageQueue<'_> {
    /// A control-plane datagram is a barrier between the data queued before it and after it, as
    /// on a unicast link (`BoxedLinkDriver::tx_fence`): the lanes serve their priorities in
    /// strict order, so without this a declaration queued behind a put on the group would leave
    /// first, and an undeclaration could reach the members before the puts that name what it
    /// undeclares. What the other lanes hold now leaves before the control datagram does; a
    /// group that runs no QoS has the one lane, which keeps its own order, and ignores it.
    fn hold_control_behind_queued(&self, priority: Priority) {
        if priority == Priority::Control {
            self.lanes.fence();
        }
    }
}

#[cfg(any(
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-response-final",
    any(feature = "liveliness-token", feature = "declare-subscriber")
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
        self.hold_control_behind_queued(priority);
        // A closed queue is a finished link: the datagram is lost with it.
        if self.lanes.send(priority, bytes).is_ok() {
            self.queued.push_back(Some((reliable, sn)));
        }
    }

    // R3264 — ARCHITECTURE section 9.1: the datagram is encoded straight into a
    // slot of the link's transmit pool. The small class is tried first, since
    // most datagrams fit it and the frame's size is known only once written;
    // a frame that does not fit is given the slot `want` asks for. The slot's
    // place in the lane is the order it was lent in, which is the SN order of
    // this conduit, because the conduit's stage is held for the whole push.
    #[cfg(feature = "runtime-zero-copy")]
    fn enqueue_lent(
        &mut self,
        priority: Priority,
        reliable: bool,
        sn: u64,
        want: usize,
        fill: &mut dyn FnMut(&mut wz_session_core::tx_buf::SliceTxBuf<'_>) -> bool,
    ) -> bool {
        self.hold_control_behind_queued(priority);
        let small = crate::session_tx_pool_ap_small::SLOT_SIZE;
        let tries = [want.min(small), want];
        let tries = if tries[0] == tries[1] {
            &tries[..1]
        } else {
            &tries[..]
        };
        for &need in tries {
            let Some(lend) = self.lanes.lend(priority, need) else {
                return false;
            };
            // SAFETY: the lend is this push's alone until it is committed or
            // given back, and `capacity` bytes from `base` lie in its slot.
            let region = unsafe { std::slice::from_raw_parts_mut(lend.base(), lend.capacity()) };
            let mut slot = wz_session_core::tx_buf::SliceTxBuf::new(region);
            if fill(&mut slot) {
                let len = wz_session_core::tx_buf::TxBuf::len(&slot);
                if self.lanes.commit(lend, len).is_ok() {
                    self.queued.push_back(Some((reliable, sn)));
                }
                // Committed or lost with a closed link: either way the datagram
                // is the queue's, as `enqueue` treats a closed queue.
                return true;
            }
            self.lanes.abort_lend(lend);
        }
        false
    }
}

/// R2929 / R2937 — the drive loop's side of one link's pipeline: the lanes'
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
/// What a group's writers note of each datagram they are done with: its priority, and its size
/// when it was written (`None` when the write failed). The transmit task notes each one it
/// writes and a producer each one it writes from its own thread ([`GroupInline`]), through this
/// one function, so the plane counts and advertises the conduits from one record however a
/// datagram left. The plane pops its record of the oldest datagram queued at the priority for
/// each note, so what a note says is how many left, never which.
#[derive(Clone)]
struct GroupWrites {
    report: tokio::sync::mpsc::UnboundedSender<(Priority, Option<usize>)>,
}

impl GroupWrites {
    fn written(&self, priority: Priority, len: Option<usize>) {
        // The plane is gone with its link: there is nobody to count for.
        let _ = self.report.send((priority, len));
    }
}

/// A group link's own way to write one datagram from a producer's thread
/// ([`MulticastLinkDriver::inline_sender`](crate::multicast_glue::MulticastLinkDriver::inline_sender)),
/// noting each datagram it writes as the transmit task notes its own ([`GroupWrites`]). A
/// datagram it cannot write now, or whose write fails, is left to the transmit task, which
/// writes it, or fails it, and notes it.
struct GroupInline {
    sink: Arc<dyn crate::writer_queue::InlineWrite>,
    writes: GroupWrites,
}

impl crate::writer_queue::InlineWrite for GroupInline {
    fn try_write(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.sink.try_write(buf)
    }

    fn datagrams(&self) -> bool {
        true
    }

    fn wrote(&self, priority: Priority, len: usize) {
        self.writes.written(priority, Some(len));
    }
}

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
        any(feature = "liveliness-token", feature = "declare-subscriber")
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
        // Open-debt item 911 — what the link can carry bounds what is framed for it; the
        // group's batch, which the JOIN advertises, is left to the drive loop's own params.
        let framed;
        let params = match driver.frame_budget() {
            Some(budget) if budget < params.batch_size => {
                framed = MulticastParams {
                    batch_size: budget,
                    ..params.clone()
                };
                &framed
            }
            _ => params,
        };
        let (lanes, mut queued) = pipeline_lanes();
        // A multicast group sends the configured batch, so the batch the link
        // sends and the batch a lane is counted in are the same number.
        lanes.reshape(params.tx_queue.shape(
            params.is_qos,
            usize::from(params.batch_size),
            usize::from(params.batch_size),
        ));
        let sender = match driver.datagram_sender() {
            Ok(sender) => Some(sender),
            Err(e) => {
                log::warn!("multicast link has no send half ({e}); nothing it queues is sent");
                None
            }
        };
        let (report, written) = tokio::sync::mpsc::unbounded_channel();
        let writes = GroupWrites { report };
        let mut pacing = group_writer_pacing::<crate::datagram_pacing::OfBuild>(params);
        // A producer writes its own datagram from its own thread when the link has a way to
        // (`MulticastLinkDriver::inline_sender`) and the writer paces nothing: a paced writer's
        // wait is its own, and a datagram written past it would pass the pace.
        {
            use crate::datagram_pacing::Pacing;
            if !pacing.paces() {
                if let Some(sink) = driver.inline_sender() {
                    lanes.set_inline_write(Arc::new(GroupInline {
                        sink,
                        writes: writes.clone(),
                    }));
                }
            }
        }
        let writer = crate::runtime_pool::WzRuntime::Tx.spawn(async move {
            // R3264 — a pooled datagram is a slot of the link's transmit pool:
            // started as the send begins, home through the completion edge once
            // the send has returned.
            use crate::datagram_pacing::Pacing;
            while let Some((priority, mut datagram)) = queued.recv_wire_tagged().await {
                // The `datagram-fragment-pacing` policy: a fragment past the burst waits here, in
                // the writer, so the producers that queued it are held only by the lane's room.
                pacing.before(&datagram, tokio::time::sleep).await;
                // Best-effort, as every multicast send is: a datagram the
                // socket refuses is not counted and is not retried. It is
                // still REPORTED, as done with: the record of what each queued
                // datagram carries is in queue order, and a datagram left
                // unreported would shift every later report onto the wrong one.
                datagram.begin_write();
                let wrote = match sender.as_ref() {
                    Some(sender) => sender.send(&datagram).await.is_ok(),
                    None => false,
                };
                let len = datagram.len();
                pacing.wrote();
                if wrote {
                    queued.recycle_wire(datagram);
                } else {
                    // Dropped: a refused send has ended too (completed, failed).
                    drop(datagram);
                }
                writes.written(priority, wrote.then_some(len));
            }
        });
        let mask = sn::mask_from_res(params.seq_num_res);
        let stages = new_stages(mask);
        #[cfg(any(
            feature = "codec-push",
            feature = "codec-response",
            feature = "codec-response-final",
            any(feature = "liveliness-token", feature = "declare-subscriber")
        ))]
        let (pushed_tx, pushed) = tokio::sync::mpsc::unbounded_channel();
        let link = Arc::new(Link {
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-response",
                feature = "codec-response-final",
                any(feature = "liveliness-token", feature = "declare-subscriber")
            ))]
            params: params.clone(),
            lanes,
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-response",
                feature = "codec-response-final",
                any(feature = "liveliness-token", feature = "declare-subscriber")
            ))]
            stages: stages.clone(),
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-response",
                feature = "codec-response-final",
                any(feature = "liveliness-token", feature = "declare-subscriber")
            ))]
            senders: std::array::from_fn(|_| std::sync::atomic::AtomicBool::new(false)),
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-response",
                feature = "codec-response-final",
                any(feature = "liveliness-token", feature = "declare-subscriber")
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
                any(feature = "liveliness-token", feature = "declare-subscriber")
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

    /// A JOIN was asked for through this plane's producer
    /// ([`MulticastTxProducer::request_join`]).
    pub(crate) async fn join_requested(&self) {
        self.producer.join_requested().await;
    }

    /// Run the producer's after-JOIN hook ([`MulticastTxProducer::set_after_join`]).
    pub(crate) fn after_join(&self) {
        self.producer.run_after_join();
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
        // The frames a batch window holds open leave first, as zenoh-pico sends its batch
        // before a transport message
        // (`vendor/zenoh-pico/src/transport/common/tx.c` @ `static z_result_t _z_transport_tx_send_t_msg_inner(`).
        link.flush_window();
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
            any(feature = "liveliness-token", feature = "declare-subscriber")
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
                // A push dropped behind a held stage is a congestion drop as well, which the
                // pico profile tells its sender of.
                wz_session_core::tx_deadline::PushOutcome::Congested
                | wz_session_core::tx_deadline::PushOutcome::Held => {
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
    /// Per priority, the datagrams read whose stage record is not consumed yet
    /// ([`Self::settle_records`]).
    unsettled: [usize; Priority::NUM],
}

impl MulticastTxTap {
    /// A producer with a pipeline for `params` attached, and the tap on it.
    ///
    /// The tap's lanes are the HEAP queue: a reader that drains at its own pace
    /// keeps the byte bound it always had. [`Self::attach_pooled`] is the same
    /// over the transmit pool the drive loop's pipeline uses.
    pub fn attach(params: &MulticastParams) -> (MulticastTxProducer, Self) {
        Self::attach_over(params, crate::writer_queue::outbound_channel())
    }

    /// R3264 — [`Self::attach`] over the lanes the drive loop's pipeline builds
    /// (`pipeline_lanes`, the pooled datagram queue under `runtime-zero-copy`),
    /// so what a push puts on them can be read as the slots it lies in
    /// ([`Self::try_next_wire`]).
    #[cfg(feature = "runtime-zero-copy")]
    pub fn attach_pooled(params: &MulticastParams) -> (MulticastTxProducer, Self) {
        Self::attach_over(params, pipeline_lanes())
    }

    fn attach_over(
        params: &MulticastParams,
        (lanes, rx): (
            crate::writer_queue::OutboundTx,
            crate::writer_queue::OutboundRx,
        ),
    ) -> (MulticastTxProducer, Self) {
        let producer = MulticastTxProducer::new();
        lanes.reshape(params.tx_queue.shape(
            params.is_qos,
            usize::from(params.batch_size),
            usize::from(params.batch_size),
        ));
        let mask = sn::mask_from_res(params.seq_num_res);
        let stages = new_stages(mask);
        producer.attach(Arc::new(Link {
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-response",
                feature = "codec-response-final",
                any(feature = "liveliness-token", feature = "declare-subscriber")
            ))]
            params: params.clone(),
            lanes,
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-response",
                feature = "codec-response-final",
                any(feature = "liveliness-token", feature = "declare-subscriber")
            ))]
            stages: stages.clone(),
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-response",
                feature = "codec-response-final",
                any(feature = "liveliness-token", feature = "declare-subscriber")
            ))]
            senders: std::array::from_fn(|_| std::sync::atomic::AtomicBool::new(false)),
            #[cfg(any(
                feature = "codec-push",
                feature = "codec-response",
                feature = "codec-response-final",
                any(feature = "liveliness-token", feature = "declare-subscriber")
            ))]
            pushed: None,
            #[cfg(feature = "routing-namespace")]
            namespace: None,
        }));
        (
            producer,
            Self {
                lanes: rx,
                stages,
                unsettled: [0; Priority::NUM],
            },
        )
    }

    /// The next datagram a push put on the lanes, if any.
    pub fn try_next(&mut self) -> Option<Vec<u8>> {
        self.try_next_wire()
            .map(crate::writer_queue::WireFrame::into_vec)
    }

    /// R3264 — [`Self::try_next`] as the frame the lanes hold: on a pooled tap,
    /// the slot of the link's transmit pool the push encoded it into, which goes
    /// home when it is dropped (or handed back with [`Self::written`]).
    pub fn try_next_wire(&mut self) -> Option<crate::writer_queue::WireFrame> {
        self.settle_records();
        let (priority, datagram) = self.lanes.try_recv_wire_tagged()?;
        self.unsettled[priority as usize] += 1;
        self.settle_records();
        Some(datagram)
    }

    /// Consume the records of the datagrams read so far, from every stage that
    /// is not held at this moment. A stage is held for the whole of a push, and
    /// a push on a pooled queue may be WAITING for the slot of a datagram this
    /// tap has just read: taking the stage's lock here would then wait for the
    /// push while the push waits for the reader to write what it holds. The
    /// record is bookkeeping, so one that cannot be consumed now is consumed by
    /// a later read, in the order the datagrams were read.
    fn settle_records(&mut self) {
        for (priority, owed) in self.unsettled.iter_mut().enumerate() {
            while *owed > 0 {
                let Ok(mut stage) = self.stages[priority].try_lock() else {
                    break;
                };
                stage.queued.pop_front();
                *owed -= 1;
            }
        }
    }

    /// R3264 — the holder has written `datagram` out, as a transmit task does:
    /// its slot goes home through the completion edge, counted as written.
    pub fn written(&self, mut datagram: crate::writer_queue::WireFrame) {
        datagram.begin_write();
        self.lanes.recycle_wire(datagram);
    }

    /// R3264 — what the lanes' transmit pool has done and how many slots are
    /// free, by the pool's own count; `None` on a heap tap.
    #[cfg(feature = "runtime-zero-copy")]
    pub fn tx_pool_stats(&self) -> Option<(crate::link_tx_pool::TxPoolStats, usize, usize)> {
        self.lanes.tx_pool_stats()
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

/// The pacing of a group's transmit task: `P`'s, for the `datagram-fragment-pacing` value of the
/// snapshot the group's parameters carry. [`OfBuild`](crate::datagram_pacing::OfBuild) is the
/// writer's in production; a test names the pacing it observes.
fn group_writer_pacing<P: crate::datagram_pacing::Pacing>(params: &MulticastParams) -> P {
    P::of_policy(&params.policy)
}

#[cfg(test)]
mod inline_write_tests {
    use super::*;
    use crate::writer_queue::InlineWrite;

    /// A link that takes every datagram whole, at once.
    struct TakesAll;

    impl InlineWrite for TakesAll {
        fn try_write(&self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn datagrams(&self) -> bool {
            true
        }
    }

    /// A datagram a producer writes from its own thread is noted to the plane as the transmit
    /// task notes each datagram it writes: its priority and its size, through the one
    /// [`GroupWrites`] the plane reads.
    #[test]
    fn a_datagram_written_by_its_producer_is_noted_as_the_transmit_task_notes_one() {
        let (lanes, _queued) = pipeline_lanes();
        let (report, mut written) = tokio::sync::mpsc::unbounded_channel();
        lanes.set_inline_write(Arc::new(GroupInline {
            sink: Arc::new(TakesAll),
            writes: GroupWrites { report },
        }));

        lanes.send(Priority::Data, vec![7u8; 5]).expect("open");

        assert_eq!(
            written.try_recv().ok(),
            Some((Priority::Data, Some(5))),
            "written on the producer's thread and noted at once"
        );
        assert!(written.try_recv().is_err(), "once");
    }
}

#[cfg(test)]
mod writer_pacing_tests {
    use super::*;
    use crate::datagram_pacing::ByPolicy;
    use wz_session_core::policy::{DatagramFragmentPacing, SessionPolicy};
    use wz_session_core::session_init_params::{LinkRxConf, TxQueueConf};

    fn params(policy: SessionPolicy) -> MulticastParams {
        MulticastParams {
            whatami: wz_session_core::WhatAmI::Peer,
            zid: [1, 2, 3, 4].into(),
            lease_ms: 5_000,
            join_interval_ms: 100,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size: 2_048,
            is_qos: false,
            compression: false,
            tx_queue: TxQueueConf::of_snapshots(
                &policy,
                &wz_session_core::limits::SessionLimits::BUILD,
            ),
            link_rx: LinkRxConf::default(),
            join_rule: wz_session_core::multicast_params::GroupJoinRule::Pico,
            max_sessions: None,
            policy,
        }
    }

    /// A group's transmit task paces as the snapshot its parameters carry says, not as the
    /// build's default does: each value the domain allows is selected and observed on a writer
    /// that holds both.
    #[test]
    fn a_group_writer_paces_as_its_parameters_snapshot_says() {
        for (value, paced) in [
            (DatagramFragmentPacing::On, true),
            (DatagramFragmentPacing::Off, false),
        ] {
            let mut policy = SessionPolicy::defaults();
            if policy.select_datagram_fragment_pacing(value).is_err() {
                continue;
            }
            let pacing: ByPolicy = group_writer_pacing(&params(policy));
            assert_eq!(pacing.is_paced(), paced, "{value:?}");
        }
    }
}

// R2937 — the producer's push against a pipeline whose lanes nobody drains (a
// tap that is never read is a link that has stopped writing). A reply
// terminator carries its own congestion control, so one item shape gives both
// a droppable and a blocking message.
#[cfg(all(test, feature = "codec-response-final"))]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use wz_session_core::qos::CongestionControl;
    use wz_session_core::sample::QosLevel;
    use wz_session_core::session_init_params::{LinkRxConf, TxQueueConf};
    use wz_session_core::tx_deadline::PushOutcome;

    const CLOSE_WAIT: Duration = Duration::from_millis(300);

    fn params(is_qos: bool) -> MulticastParams {
        MulticastParams {
            whatami: wz_session_core::WhatAmI::Peer,
            zid: [1, 2, 3, 4].into(),
            lease_ms: 5_000,
            join_interval_ms: 100,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size: 64,
            is_qos,
            compression: false,
            tx_queue: TxQueueConf {
                // One batch per lane: a few frames fill it.
                sizes: [1; Priority::NUM],
                wait_before_drop_us: 1_000,
                wait_before_close_us: CLOSE_WAIT.as_micros() as u64,
                ..TxQueueConf::of_snapshots(
                    &wz_session_core::policy::SessionPolicy::defaults(),
                    &wz_session_core::limits::SessionLimits::BUILD,
                )
            },
            link_rx: LinkRxConf::default(),
            join_rule: wz_session_core::multicast_params::GroupJoinRule::Pico,
            max_sessions: None,
            policy: wz_session_core::policy::SessionPolicy::defaults(),
        }
    }

    fn terminal(priority: Priority, congestion: CongestionControl) -> MulticastTxItem {
        MulticastTxItem::ResponseFinal {
            request_id: 1,
            qos: QosLevel::from_parts(priority, congestion, false),
        }
    }

    /// The number of network messages in one `T_MID_FRAME` datagram.
    fn messages_in(datagram: &[u8]) -> usize {
        let wz_session_core::inbound::InboundFrame::Frame { payload, .. } =
            wz_session_core::inbound::parse_inbound(datagram).expect("a frame")
        else {
            panic!("the datagram is a T_MID_FRAME");
        };
        wz_session_core::network_message::parse_frame_payload(&payload)
            .expect("its messages")
            .len()
    }

    /// While the producer's batch window is open, the messages of one conduit are held in one
    /// frame and leave as ONE datagram when the window closes; with it closed, each message is
    /// a datagram of its own.
    #[test]
    fn a_window_sends_a_conduits_messages_as_one_datagram_when_it_closes() {
        let (producer, mut tap) = MulticastTxTap::attach(&params(false));
        producer.batch_start();
        for _ in 0..3 {
            assert_eq!(
                producer.push(terminal(Priority::DEFAULT, CongestionControl::Drop)),
                Ok(PushOutcome::Pushed)
            );
        }
        assert!(tap.try_next().is_none(), "held while the window is open");

        producer.batch_stop();

        let datagram = tap.try_next().expect("the window's frame");
        assert_eq!(messages_in(&datagram), 3, "all three, in one frame");
        assert!(tap.try_next().is_none(), "one datagram");

        assert_eq!(
            producer.push(terminal(Priority::DEFAULT, CongestionControl::Drop)),
            Ok(PushOutcome::Pushed)
        );
        let alone = tap.try_next().expect("sent at once with the window closed");
        assert_eq!(messages_in(&alone), 1);
    }

    /// A flush sends the window's frame and keeps the window open: the next message waits for
    /// the next flush.
    #[test]
    fn a_flush_sends_the_open_frame_and_keeps_the_window() {
        let (producer, mut tap) = MulticastTxTap::attach(&params(false));
        producer.batch_start();
        assert_eq!(
            producer.push(terminal(Priority::DEFAULT, CongestionControl::Drop)),
            Ok(PushOutcome::Pushed)
        );

        producer.batch_flush();

        assert_eq!(messages_in(&tap.try_next().expect("flushed")), 1);
        assert_eq!(
            producer.push(terminal(Priority::DEFAULT, CongestionControl::Drop)),
            Ok(PushOutcome::Pushed)
        );
        assert!(tap.try_next().is_none(), "the window is still open");
        producer.batch_stop();
        assert!(
            tap.try_next().is_some(),
            "and its frame leaves when it closes"
        );
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
    /// A droppable one on the same lane is answered at once. Before R2937 the
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

    /// Wait until another thread holds `band`'s stage.
    fn until_held(tap: &MulticastTxTap, band: Priority) {
        let started = Instant::now();
        while tap.stages[band as usize].try_lock().is_ok() {
            assert!(
                started.elapsed() < CLOSE_WAIT / 2,
                "the blocking push never took its stage"
            );
            std::thread::yield_now();
        }
    }

    /// A droppable push does not wait for the stage a blocking push holds across its wait for
    /// room: it asks the lane itself, without the stage, and on the full lane it is a congestion
    /// drop within its own `wait_before_drop` while the blocking push still waits. zenoh bounds a
    /// droppable push by `wait_before_drop`
    /// (`commons/zenoh-config/src/defaults.rs` @ `wait_before_drop: 1000,`); its pipeline holds the
    /// stage across the blocking wait
    /// (`io/zenoh-transport/src/common/pipeline.rs` @ `let mut queue = zlock!(self.stage_in[idx]);`),
    /// and a push that queued behind it would wait out the blocking one's `wait_before_close`.
    #[test]
    fn a_droppable_push_behind_a_blocking_one_is_dropped_within_its_own_wait() {
        let (producer, tap) = MulticastTxTap::attach(&params(false));
        fill(&producer, Priority::DEFAULT);
        let waiting = producer.clone();
        let blocked = std::thread::spawn(move || {
            waiting.push(terminal(Priority::DEFAULT, CongestionControl::Block))
        });
        until_held(&tap, Priority::DEFAULT);

        let started = Instant::now();
        let outcome = producer.push(terminal(Priority::DEFAULT, CongestionControl::Drop));
        let took = started.elapsed();
        assert_eq!(outcome, Ok(PushOutcome::Congested));
        assert!(
            !blocked.is_finished(),
            "the droppable push returned only once the blocking one let go of its stage"
        );
        assert!(
            took < CLOSE_WAIT / 3,
            "a droppable push waited {took:?} behind a blocking one"
        );
        assert_eq!(
            blocked.join().expect("blocked pusher"),
            Ok(PushOutcome::Congested)
        );
    }

    /// Under the pico profile a droppable push whose stage another push holds is dropped at once,
    /// as pico's try-lock drops it, and the lane is asked nothing; under zenoh's the same push
    /// asks the lane for room out of its own `wait_before_drop`.
    #[test]
    fn under_the_pico_profile_a_droppable_push_behind_a_held_stage_asks_nothing() {
        use wz_session_core::link::{LinkRoom, RoomAnswer, RoomWait};
        use wz_session_core::policy::SessionPolicy;
        let stage = Stage::new(0xff);
        let _held = stage.lock().expect("stage");
        // The holder is another push.
        let sender = std::sync::atomic::AtomicBool::new(true);
        let mut asked = Vec::new();

        // Answered as congested, so a push that asked would end here too and show in `asked`.
        let mut pico = TxQueueConf::pico_of_snapshots(
            &SessionPolicy::defaults(),
            &wz_session_core::limits::SessionLimits::BUILD,
        );
        let taken = droppable_stage(&stage, &sender, &mut pico, |wait| {
            asked.push(wait);
            RoomAnswer::at_once(LinkRoom::Congested)
        });
        assert!(
            matches!(taken, Err(PushOutcome::Held)),
            "a stage another push holds drops the push at once, and its sender is told"
        );
        assert!(asked.is_empty(), "the lane was asked {asked:?}");

        let mut zenoh = TxQueueConf {
            wait_before_drop_us: 1_000,
            ..TxQueueConf::of_snapshots(
                &SessionPolicy::defaults(),
                &wz_session_core::limits::SessionLimits::BUILD,
            )
        };
        let taken = droppable_stage(&stage, &sender, &mut zenoh, |wait| {
            asked.push(wait);
            RoomAnswer {
                room: LinkRoom::Congested,
                waited_us: 1_000,
            }
        });
        assert!(
            matches!(taken, Err(PushOutcome::Congested)),
            "no room within the wait is a congestion drop, answered as sent"
        );
        assert_eq!(
            asked,
            [RoomWait::Drop { wait_us: 1_000 }],
            "CONTROL: zenoh's profile asks the lane, out of `wait_before_drop`"
        );
    }

    /// Under the pico profile a stage held by what is not a push (a flush, a transmit report) is
    /// waited for, not dropped behind: pico's try-lock fails only on a lock another send holds.
    /// The push takes the stage once the holder lets go, having asked the lane nothing.
    #[test]
    fn under_the_pico_profile_a_droppable_push_waits_for_a_holder_that_is_not_a_push() {
        use wz_session_core::link::{LinkRoom, RoomAnswer};
        use wz_session_core::policy::SessionPolicy;
        let stage = std::sync::Arc::new(Stage::new(0xff));
        let (taken_tx, taken_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = {
            let stage = std::sync::Arc::clone(&stage);
            std::thread::spawn(move || {
                let _held = stage.lock().expect("stage");
                taken_tx.send(()).expect("the test waits");
                // Bounded, so a push that never returns cannot hold the test past it.
                let _ = release_rx.recv_timeout(Duration::from_secs(3));
            })
        };
        taken_rx.recv().expect("the holder took the stage");
        let not_a_push = std::sync::atomic::AtomicBool::new(false);
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(CLOSE_WAIT / 6);
            let _ = release_tx.send(());
        });
        let started = Instant::now();
        let mut asked = 0usize;
        let mut pico = TxQueueConf::pico_of_snapshots(
            &SessionPolicy::defaults(),
            &wz_session_core::limits::SessionLimits::BUILD,
        );
        let taken = droppable_stage(&stage, &not_a_push, &mut pico, |_| {
            asked += 1;
            RoomAnswer::at_once(LinkRoom::Congested)
        });
        assert!(
            taken.is_ok(),
            "the push waited for the holder and took the stage"
        );
        assert!(
            started.elapsed() >= CLOSE_WAIT / 12,
            "the push did not wait for the holder"
        );
        drop(taken);
        assert_eq!(asked, 0, "the lane was asked for room");
        releaser.join().expect("the releaser");
        holder.join().expect("the holder");
    }

    /// Under the pico profile a droppable push whose stage a blocking push holds, waiting for room
    /// on the full lane, is answered `Held`, which its sender is told of, where a congestion drop
    /// is answered `Congested`, which a multicast put answers as sent; the blocking push still
    /// waits out its own deadline.
    #[test]
    fn under_the_pico_profile_a_push_behind_another_push_is_answered_held() {
        use wz_session_core::policy::SessionPolicy;
        let mut pico = params(false);
        pico.tx_queue = TxQueueConf {
            sizes: [1; Priority::NUM],
            // `fill` pushes droppable messages until one finds no room, each within this wait.
            wait_before_drop_us: 1_000,
            wait_before_close_us: CLOSE_WAIT.as_micros() as u64,
            ..TxQueueConf::pico_of_snapshots(
                &SessionPolicy::defaults(),
                &wz_session_core::limits::SessionLimits::BUILD,
            )
        };
        let (producer, tap) = MulticastTxTap::attach(&pico);
        fill(&producer, Priority::DEFAULT);
        let waiting = producer.clone();
        let blocked = std::thread::spawn(move || {
            waiting.push(terminal(Priority::DEFAULT, CongestionControl::Block))
        });
        until_held(&tap, Priority::DEFAULT);

        let started = Instant::now();
        let outcome = producer.push(terminal(Priority::DEFAULT, CongestionControl::Drop));
        let took = started.elapsed();
        assert_eq!(outcome, Ok(PushOutcome::Held));
        assert!(
            took < CLOSE_WAIT / 3,
            "a push behind another push waited {took:?}"
        );
        assert!(
            !blocked.is_finished(),
            "CONTROL: the blocking push still held the stage"
        );
        assert_eq!(
            blocked.join().expect("blocked pusher"),
            Ok(PushOutcome::Congested)
        );
    }

    /// A held stage alone is not congestion: while its lane has room, a droppable push waits for
    /// the holder to let go and is then pushed, as it would be had it found the stage free.
    #[test]
    fn a_droppable_push_whose_lane_has_room_waits_for_a_held_stage() {
        let (producer, tap) = MulticastTxTap::attach(&params(false));
        let held = tap.stages[Priority::DEFAULT as usize]
            .lock()
            .expect("stage");
        let pushing = producer.clone();
        let pushed = std::thread::spawn(move || {
            pushing.push(terminal(Priority::DEFAULT, CongestionControl::Drop))
        });
        // Many times the push's `wait_before_drop`: a push that took the held stage for
        // congestion would be back by now.
        std::thread::sleep(CLOSE_WAIT / 6);
        assert!(
            !pushed.is_finished(),
            "a droppable push returned while its stage was held and its lane had room"
        );
        drop(held);
        assert_eq!(
            pushed.join().expect("droppable pusher"),
            Ok(PushOutcome::Pushed)
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

    /// A control datagram queued behind data leaves behind it: the lanes serve their priorities
    /// in strict order, so the Control lane would send the later datagram first, and a
    /// declaration or an undeclaration would pass the data queued before it. The fence the push
    /// raises holds the Control lane until that data is gone.
    #[cfg(feature = "transport-qos")]
    #[test]
    fn a_control_datagram_leaves_behind_the_data_queued_before_it() {
        let (producer, mut tap) = MulticastTxTap::attach(&params(true));
        assert_eq!(
            producer.push(terminal(Priority::DEFAULT, CongestionControl::Drop)),
            Ok(PushOutcome::Pushed)
        );
        assert_eq!(
            producer.push(terminal(Priority::Control, CongestionControl::Drop)),
            Ok(PushOutcome::Pushed)
        );

        let first = tap.lanes.try_recv_wire_tagged().expect("the data datagram");
        let second = tap
            .lanes
            .try_recv_wire_tagged()
            .expect("the control datagram");
        assert_eq!(
            (first.0, second.0),
            (Priority::DEFAULT, Priority::Control),
            "the control datagram was queued last and leaves last"
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
