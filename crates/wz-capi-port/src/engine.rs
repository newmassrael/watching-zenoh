// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a C ABI asks of a session's engine: [`SessionEngine`].
//!
//! The operations are those a single-threaded zenoh-pico client makes — publish, declare and
//! retract a subscriber, hold and release a key expression declaration, watch whether a peer
//! matches, filter writes nobody would receive, open and flush a batch — spelled in this crate's
//! vocabulary and session-core's types, so the ABI that calls them names no engine. An engine
//! implements the trait; an ABI holds `Arc<dyn SessionEngine>` and reaches the engine through
//! nothing else (`docs/capi-pico-on-coop-engine.md`, decision D1).
//!
//! The queryable joined when the cooperative engine answered queries, the get (over
//! session-core's `QueryOptions`) when it asked them, and the liveliness token and subscriber
//! when it held and heard them, the liveliness get when it asked for the ones alive, and the
//! faces (the snapshot of each and the watch of their coming and going) when a connectivity
//! plane and an admin space read them; a capability no second engine has yet (scouting, the
//! advanced publisher) is not here: an ABI module that needs one still names its engine, and
//! joins this trait when a second engine implements it.

use alloc::string::String;
use alloc::vec::Vec;

use wz_session_core::declare_form::{InterestForm, RetractionKey};
use wz_session_core::face::{FaceEventSink, FaceSnapshot};
use wz_session_core::link_restriction::LinkRestriction;
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::{PlainPutParams, PublishOptions};
use wz_session_core::query_options::QueryOptions;
use wz_session_core::sample::TimestampHint;
use wz_session_core::session_zid::SessionZid;
use wz_session_core::wire_id::{EntityId, ExprId};

use crate::cancellation::CancellableFan;
use crate::decl_watch::{DeclPlane, DeclWatchId, DeclWatchRefused, DeclWatchSink};
use crate::held_key::SessionKeys;
use crate::peers::PeerIdentity;
use crate::{
    FanoutError, FilterId, FilterPlane, FilteredPut, LinksNotHonoured, LivelinessSink, MatchId,
    MatchingSink, QblId, QueryableSink, Refusal, ReplyCallback, SubId, SubscriberSink, Tick,
    TickerId, TokenId, WireKey,
};

/// Why [`SessionEngine::redeclare`] told no peer anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeclareRefusal {
    /// The engine keeps no record of what the session declared, so it has nothing to send again.
    Unsupported,
    /// The session is closed.
    Closed,
}

/// The operations a C ABI's client surface makes on one session, whatever engine runs it.
///
/// Every method takes `&self`: an engine is shared between the C session handle and every entity
/// declared on it (a publisher, a subscriber, a declared key expression each hold it), and the
/// C program may call in from any thread. Releases run outside the engine's locks, so a C
/// `drop(context)` reached from one may re-enter the session.
pub trait SessionEngine: Send + Sync + 'static {
    /// Whether the session has been closed. Every operation after that answers as a closed
    /// session does: nothing is sent and nothing is declared.
    fn is_closed(&self) -> bool;

    /// The session's own zid, as its handshake carries it.
    fn session_zid(&self) -> SessionZid;

    /// The session's own zid, zero-padded to 16 bytes: [`Self::session_zid`] in the form a
    /// C ABI's id holds, so the two cannot disagree.
    fn zid(&self) -> [u8; 16] {
        self.session_zid().to_padded()
    }

    /// The engine's own clock, in whole milliseconds since an epoch of its choosing: monotonic,
    /// and the one its periodic jobs ([`Self::start_ticker`]) and its deadlines run on. A caller
    /// that measures how long ago it last heard of something (a source's retention, say) reads it
    /// here and compares two readings of this one engine, never with another clock.
    fn now_ms(&self) -> u64;

    /// A fresh entity id, for the source info and the global id of what the C program declares,
    /// from the one space every declaration of the session is numbered from; `None` once the
    /// session has handed out every `u32` id, rather than an id a live entity may still hold
    /// (`wz_session_core::wire_id::next_u32_id`).
    fn next_entity_id(&self) -> Option<EntityId>;

    /// The established peer with the least key at or past `from`, and its key: its zid and the
    /// role it announced, the role in its 2-bit wire form (0 router, 1 peer, 2 client), so the
    /// split between zenoh-pico's `z_info_routers_zid` and `z_info_peers_zid` is made at the ABI,
    /// where pico makes it. A link whose handshake has not completed is not listed.
    ///
    /// One peer a call, so a reader copies each identity out with nothing of the session held and
    /// acts on it (a C callback) after: [`crate::each_peer`] walks them, asking from `0` and then
    /// from each key answered plus one. The key is the engine's own. Where it is stable for the
    /// life of a peer's link, a walk reads each peer that stands throughout it once; where it is a
    /// position, a peer that goes during the walk may hide the one after it from that walk.
    fn next_peer(&self, from: u64) -> Option<(u64, PeerIdentity)>;

    /// The member with the least key at or past `from` of the multicast groups the session
    /// joined, and its key: its zid, as its group's member table holds it, whatever role it
    /// announced. zenoh-pico lists each of them as a peer of its multicast transport
    /// (`vendor/zenoh-pico/src/transport/multicast.c` @ `void _zp_multicast_fetch_zid(`). A
    /// group's members are not [`Self::next_peer`]'s, whose split by role is a link's. Read one at
    /// a time as [`Self::next_peer`] is ([`crate::each_group_member`]). An engine that joins no
    /// group has none, the provided answer.
    fn next_group_member(&self, from: u64) -> Option<(u64, SessionZid)> {
        let _ = from;
        None
    }

    /// Ask every multicast group the session joined to send its JOIN now, between two beacons,
    /// which then keeps its cadence from it (zenoh-pico's `zp_send_join`): how many groups were
    /// asked. An engine that joins no group asks none, the provided answer.
    fn send_join_on_groups(&self) -> usize {
        0
    }

    /// A snapshot of every established face: the peer's identity and the negotiated booleans of
    /// its transport, and the links under it. One entry for each transport a connectivity plane
    /// lists, a joined group's members included where the engine joins groups. A face whose
    /// handshake has not completed is not listed, as with [`Self::peer_identities`]. An engine
    /// built without the connectivity plane lists none, which is the provided answer.
    fn face_snapshots(&self) -> Vec<FaceSnapshot> {
        Vec::new()
    }

    /// Tell `sink` each time a face comes up or goes down, from now on, and answer the id that
    /// stops it ([`Self::unwatch_faces`]). The sink runs where the session hands out its
    /// callbacks and never under the session's lock, so it may reach back into the session. An
    /// engine built without the connectivity plane tells nobody of anything, which is the
    /// provided answer.
    fn watch_faces(&self, sink: FaceEventSink) -> u64 {
        let _ = sink;
        0
    }

    /// Stop the face watch `id`: `true` when one was registered under it.
    fn unwatch_faces(&self, id: u64) -> bool {
        let _ = id;
        false
    }

    /// Tell `sink` what the peers of the session declare and retract of the kind `plane` names,
    /// on every link the session holds and every link that comes up later, until
    /// [`Self::undeclare_decl_watch`] is called with the id answered ([`crate::decl_watch`]).
    /// An engine that does not watch refuses by name, which is the provided answer: a watch that
    /// was taken and never told anything would read as peers that declare nothing.
    fn declare_decl_watch(
        &self,
        plane: DeclPlane,
        sink: DeclWatchSink,
    ) -> Result<DeclWatchId, DeclWatchRefused> {
        let _ = (plane, sink);
        Err(DeclWatchRefused::NotProvided)
    }

    /// Stop the declaration watch `id` and let go of its sink: `true` when one was declared under
    /// it. A call in flight finishes; none starts after this returns.
    fn undeclare_decl_watch(&self, id: DeclWatchId) -> bool {
        let _ = id;
        false
    }

    /// Whether a link of the session may name a key otherwise than the [`WireKey`] an ABI hands
    /// over: the session holds key ids every node of the deployment shares, or a key-wire form
    /// other than `declared` is the session's or a link's. Each link then names the key as its
    /// own form says ([`wire_on_link`](crate::wire_on_link)), so an ABI that would send a
    /// declared id straight to every link (a declared publisher's plain put) goes the general
    /// way instead. The provided answer is no, an engine with none of it.
    #[cfg(feature = "shared-key-ids")]
    fn names_keys_by_link(&self) -> bool {
        false
    }

    /// The graph of each region the node's admin space answers a `linkstate` query for, as text
    /// by the region's name. An engine that holds no such graph lists none, which is the
    /// provided answer.
    fn linkstate_regions(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    /// The locators this node's listeners actually got, without the loopback ones: where a
    /// neighbour can dial it. A node that listens on nothing, and an engine that listens on
    /// nothing at all, has none, which is the provided answer.
    fn listen_locators(&self) -> Vec<String> {
        Vec::new()
    }

    /// The next timestamp off this node's clock, strictly after the one before, or `None` for a
    /// node that holds no clock, which is the provided answer.
    fn node_timestamp(&self) -> Option<TimestampHint> {
        None
    }

    /// What the session's receive path has counted: the transport messages and how they were
    /// spaced, over every link under it, for the node's resource snapshot. `None` from an engine
    /// built without the `resource-snapshot` feature, which is the provided answer, and from one
    /// with no counter; a reader asks again for each snapshot and takes windows by subtraction,
    /// since every count is cumulative.
    fn message_reading(&self) -> Option<wz_session_core::resource_snapshot::BuildMessageReading> {
        None
    }

    /// Tell the peer of every link that is up everything the session holds again (its
    /// subscriptions, queryables, tokens and interests), as a link that has just come up is told,
    /// at the pace the session's snapshot states. The count of links told. An engine that keeps
    /// no record of what it declared answers [`RedeclareRefusal::Unsupported`], the provided
    /// answer.
    fn redeclare(&self) -> Result<usize, RedeclareRefusal> {
        Err(RedeclareRefusal::Unsupported)
    }

    /// Whether any connected peer is a ROUTER — zenoh-pico's `_z_session_has_router_peer`, the
    /// condition under which a peer-mode session sends Interests at all.
    fn has_router_peer(&self) -> bool;

    /// Publish `payload` on `keyexpr`, naming it on the wire as `wire` says, with `opts`. The
    /// count of deliveries, or why nothing could have carried it.
    fn publish_on_wire_all(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError>;

    /// Whether some peer negotiated shared memory, so that a payload put into shared memory is
    /// sent to someone as a descriptor. The provided answer is no, which is right for an engine
    /// with none.
    #[cfg(feature = "transport-shm")]
    fn has_shm_peer(&self) -> bool {
        false
    }

    /// [`Self::publish_on_wire_all`] for a payload that is a buffer of shared memory some owner of
    /// a segment holds: a peer that negotiated shared memory is sent the buffer's descriptor and
    /// any other the bytes it holds, and a subscriber of this session is handed the buffer. The
    /// provided answer is the bytes, which is right for an engine with no shared memory.
    #[cfg(feature = "transport-shm")]
    fn publish_shm_on_wire_all(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        payload: wz_session_core::extshm::ShmSendHandle,
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        self.publish_on_wire_all(keyexpr, wire, payload.bytes(), opts)
    }

    /// Declare a subscriber on `keyexpr`, announced as `wire`, receiving what `allowed_origin`
    /// admits through callbacks `sink` mints. `retraction` is the key its undeclaration names
    /// beside its id, when the declaring ABI's reference library names one.
    ///
    /// Refused, with `sink` let go of, nothing declared and nothing sent, as every declaration
    /// of the port is: [`Refusal::NoEntityId`] once the session has handed out every declaration
    /// id it can put on the wire, rather than an id a live declaration may still hold being
    /// handed out again; a full table, a key the session cannot hold, or a closed session.
    fn declare_subscriber_on_wire(
        &self,
        keyexpr: &str,
        wire: WireKey,
        allowed_origin: Locality,
        retraction: Option<RetractionKey>,
        sink: SubscriberSink,
    ) -> Result<SubId, Refusal>;

    /// Retract subscriber `id`. Retracting one already retracted does nothing.
    fn undeclare_subscriber(&self, id: SubId);

    /// Hold a declaration of `keyexpr`, declaring it if no one holds it yet: its mapping id.
    /// Refused when the session has no id left to give ([`Refusal::NoEntityId`]), no row or key
    /// room left, or is closed; and with [`Refusal::NotBuilt`] by an engine that names every key
    /// whole and holds no declaration.
    fn acquire_keyexpr(&self, keyexpr: &str) -> Result<ExprId, Refusal>;

    /// Let go of one hold on declaration `mapping_id`; the last one retracts it.
    fn release_keyexpr(&self, mapping_id: ExprId);

    /// The key expression declarations the session holds, `(id, keyexpr)` in declaration order.
    fn keyexpr_declarations(&self) -> Vec<(ExprId, String)>;

    /// Where the C ABI's objects keep their keys when the session keeps a key arena: each text
    /// once, in a block every holder counts, shared with any key of the same text the arena keeps.
    /// `None`, the provided answer, from an engine that keeps none, whose callers keep a copy of
    /// their own.
    fn key_arena(&self) -> Option<&dyn SessionKeys> {
        None
    }

    /// Tell `sink` whether anything a write filter on `plane` counts matches `keyexpr`, now and
    /// each time that changes: a peer's subscriber, or its queryable (only a complete one when
    /// `plane` requires it); with `count_local`, the session's own too. It counts what that
    /// filter counts, because zenoh-pico's matching listener is its entity's write filter's
    /// callback (`vendor/zenoh-pico/src/api/api.c` @
    /// `_z_matching_listener_register(&_listener_id, _Z_RC_IN_VAL(&sess_rc), &querier->_filter.ctx,`)
    /// and zenoh's querier asks for complete queryables when its target is `ALL_COMPLETE`.
    ///
    /// A refused listener answers why, with `sink` already let go of and nothing asked of a peer:
    /// the caller has no listener to retract.
    fn declare_matching_listener(
        &self,
        plane: FilterPlane,
        keyexpr: &str,
        sink: MatchingSink,
        count_local: bool,
    ) -> Result<MatchId, Refusal>;

    /// [`Self::declare_matching_listener`] for an entity whose `locality` says whose declarations
    /// count: the peers' (`Remote`), the session's own (`SessionLocal`), or both (`Any`), as
    /// upstream's matching status reads an entity by the destination it was declared with. A
    /// listener of the session's own entities alone asks no peer. [`Refusal::NotBuilt`] from an
    /// engine with no such listener in this build, which is the provided answer.
    fn declare_matching_listener_in(
        &self,
        plane: FilterPlane,
        keyexpr: &str,
        sink: MatchingSink,
        locality: Locality,
    ) -> Result<MatchId, Refusal> {
        let _ = (plane, keyexpr, sink, locality);
        Err(Refusal::NotBuilt)
    }

    /// Whether anything `plane` counts matches `keyexpr`, from the declarations `locality` admits,
    /// read now: the one-shot twin of [`Self::declare_matching_listener_in`], which never says
    /// otherwise than its listener last did. `None` from an engine with no such status in this
    /// build, which is the provided answer.
    fn matching_status(
        &self,
        plane: FilterPlane,
        keyexpr: &str,
        locality: Locality,
    ) -> Option<bool> {
        let _ = (plane, keyexpr, locality);
        None
    }

    /// Stop the matching listener `id`.
    fn undeclare_matching_listener(&self, id: MatchId);

    /// Declare a write filter on `keyexpr` (named on the wire as `wire`) that counts the
    /// declarations `plane` names, asking the peers as `ask` says or not at all; with
    /// `count_local`, the session's own entities count too.
    ///
    /// The filter's Interest takes the session's next entity id whether it is sent or not, as
    /// zenoh-pico's does (`vendor/zenoh-pico/src/net/primitives.c` @
    /// `intr._id = _z_get_entity_id(zn);`), so it is refused once the session has handed out every
    /// id ([`Self::next_entity_id`]): a filter that could not ask would hold every write back. A
    /// refused filter answers why, with nothing held, asked or numbered.
    fn declare_write_filter(
        &self,
        plane: FilterPlane,
        keyexpr: &str,
        wire: &WireKey,
        ask: Option<InterestForm>,
        count_local: bool,
    ) -> Result<FilterId, Refusal>;

    /// Whether filter `id` says nothing matches, so a write is not sent (zenoh-pico's
    /// `_z_write_filter_active`).
    fn write_filter_active(&self, id: FilterId) -> bool;

    /// Whether filter `id` holds a write back on this session: it says nothing matches and the
    /// session has no group a write must reach regardless.
    fn write_filter_holds_back(&self, id: FilterId) -> bool;

    /// Drop write filter `id`.
    fn undeclare_write_filter(&self, id: FilterId);

    /// Send a plain Put through write filter `filter` on the declared key `mapping_id` (or the
    /// literal `keyexpr` when it is `0`), sent from `params`.
    fn put_plain_filtered(
        &self,
        filter: FilterId,
        keyexpr: &str,
        mapping_id: ExprId,
        payload: &[u8],
        params: &PlainPutParams,
    ) -> FilteredPut;

    /// Whether the session has a transport to carry a batch window: a face, or a listener that
    /// takes one. This is zenoh-pico's `_z_transport_get_common` being non-NULL, which its three
    /// `zp_batch_*` answer `_Z_ERR_TRANSPORT_NOT_AVAILABLE` for when it is not (a client whose
    /// link is gone, until it reconnects). The provided answer is `true`, for an engine with no
    /// notion of a session without a transport.
    fn has_transport(&self) -> bool {
        true
    }

    /// Open a batch window on the session's links (zenoh-pico `zp_batch_start`): how many opened.
    fn batch_start_all(&self) -> usize;

    /// Flush the open batch windows (zenoh-pico `zp_batch_flush`): how many flushed.
    fn batch_flush_all(&self) -> usize;

    /// Close the batch windows, sending what they hold (zenoh-pico `zp_batch_stop`): how many
    /// closed.
    fn batch_stop_all(&self) -> usize;

    /// Declare a queryable on `keyexpr`, announced as `wire` (`complete` as its declaration says),
    /// answering the queries `allowed_origin` admits through callbacks `sink` mints. `retraction`
    /// is the key its undeclaration names beside its id, when the declaring ABI's reference
    /// library names one. Refused as [`Self::declare_subscriber_on_wire`] is, and with
    /// [`Refusal::NotBuilt`] by an engine with no queryable in this build, which is the provided
    /// answer.
    fn declare_queryable_on_wire(
        &self,
        keyexpr: &str,
        wire: WireKey,
        complete: bool,
        allowed_origin: Locality,
        retraction: Option<RetractionKey>,
        sink: QueryableSink,
    ) -> Result<QblId, Refusal> {
        let _ = (keyexpr, wire, complete, allowed_origin, retraction, sink);
        Err(Refusal::NotBuilt)
    }

    /// Retract queryable `id`. Retracting one already retracted, or one never declared, does
    /// nothing.
    fn undeclare_queryable(&self, id: QblId) {
        let _ = id;
    }

    /// Ask which liveliness tokens are alive on `keyexpr` (named on the wire as `wire`): one leg
    /// per peer the engine reaches, each ended by its peer's DeclFinal, `timeout_ms` (`0` is the
    /// platform default, never none) or the loss of its link. Its replies are token
    /// declarations, with the token's key as the reply's. `leg` and `fan` are as
    /// [`Self::get_on_wire`]'s: `leg` mints each leg's [`ReplyCallback`], whose drop is that
    /// leg's end, and `fan` is told of each leg as it is issued. The number of legs issued, `0`
    /// for a get that reached nobody; refused as [`Self::get_on_wire`] is, and with
    /// [`Refusal::NotBuilt`] by an engine with no liveliness get in this build, which is the
    /// provided answer.
    fn liveliness_get_on_wire(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        timeout_ms: u32,
        fan: Option<&CancellableFan>,
        leg: &mut dyn FnMut() -> ReplyCallback,
    ) -> Result<usize, Refusal> {
        let _ = (keyexpr, wire, timeout_ms, fan, leg);
        Err(Refusal::NotBuilt)
    }

    /// Declare a liveliness token on `keyexpr`, announced as `wire`, to every peer the session
    /// reaches now and later. `retraction` is the key its undeclaration names beside its id,
    /// when the declaring ABI's reference library names one. Refused as
    /// [`Self::declare_subscriber_on_wire`] is, and with [`Refusal::NotBuilt`] by an engine with
    /// no liveliness in this build, which is the provided answer.
    fn declare_liveliness_token_on_wire(
        &self,
        keyexpr: &str,
        wire: WireKey,
        retraction: Option<RetractionKey>,
    ) -> Result<TokenId, Refusal> {
        let _ = (keyexpr, wire, retraction);
        Err(Refusal::NotBuilt)
    }

    /// Retract token `id`, which tells the peers' liveliness subscribers it is gone. Retracting
    /// one already retracted, or one never declared, does nothing.
    fn undeclare_liveliness_token(&self, id: TokenId) {
        let _ = id;
    }

    /// Subscribe to the liveliness tokens the peers hold on `keyexpr`, asking for them as `wire`
    /// names it, through callbacks `sink` mints; with `history`, the tokens already alive are
    /// delivered first. It is a subscriber like any other to retract
    /// ([`Self::undeclare_subscriber`]): the ids are one space. Refused as
    /// [`Self::declare_subscriber_on_wire`] is, and with [`Refusal::NotBuilt`] by an engine with
    /// no liveliness in this build, which is the provided answer.
    fn declare_liveliness_subscriber_on_wire(
        &self,
        keyexpr: &str,
        wire: WireKey,
        history: bool,
        sink: LivelinessSink,
    ) -> Result<SubId, Refusal> {
        let _ = (keyexpr, wire, history, sink);
        Err(Refusal::NotBuilt)
    }

    /// Ask a query on `keyexpr` (named on the wire as `wire`) with `opts`: one leg per peer the
    /// engine reaches, and one to the session's own queryables where `opts` admits them. `leg`
    /// mints each leg's [`ReplyCallback`], whose drop is that leg's end, so a get is over when
    /// the last callback it minted is dropped. `fan`, when the get can be cancelled, is told of
    /// each leg as it is issued ([`CancellableFan::record`]), and a fan cancelled while the
    /// legs are issued stops the issuing.
    ///
    /// The number of legs issued, `0` for a get that reached nobody (its destination admits
    /// nobody, or no link is up), which is over at once. A refused get issued no leg (`leg` was
    /// not called) and sent nothing, and answers why: the session is closed; a peer or queryable it
    /// had to ask found no room in the table that holds the session's pending gets
    /// ([`Refusal::TableFull`]; where some found room, the legs that found it are issued); the
    /// query states what this engine does not carry out ([`Refusal::NotHonoured`]: a set of links,
    /// or the one node it is addressed to, which asked of every link would widen it); or the engine
    /// has no requesting end in this build ([`Refusal::NotBuilt`], the provided answer).
    fn get_on_wire(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        opts: &QueryOptions,
        fan: Option<&CancellableFan>,
        leg: &mut dyn FnMut() -> ReplyCallback,
    ) -> Result<usize, Refusal> {
        let _ = (keyexpr, wire, opts, fan, leg);
        Err(Refusal::NotBuilt)
    }

    /// [`Self::get_on_wire`] for a query whose VALUE is a buffer of shared memory some owner of a
    /// segment holds, as upstream's `get(..).payload(shm_buf)`: a peer that negotiated shared
    /// memory is sent the buffer's descriptor, any other its bytes, and a queryable of this
    /// session is handed the buffer. The value is `value` under the encoding `opts` name, and not
    /// `opts`' payload. The provided answer asks with the bytes, which is right for an engine with
    /// no shared memory, and is what [`Self::publish_shm_on_wire_all`]'s is for a publication.
    #[cfg(feature = "transport-shm")]
    fn get_shm_on_wire(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        opts: &QueryOptions,
        value: wz_session_core::extshm::ShmSendHandle,
        fan: Option<&CancellableFan>,
        leg: &mut dyn FnMut() -> ReplyCallback,
    ) -> Result<usize, Refusal> {
        let mut opts = opts.clone();
        opts.payload = Some(value.bytes().to_vec());
        self.get_on_wire(keyexpr, wire, &opts, fan, leg)
    }

    // The operations below state a set of links (policy `entity-link-restriction`), which each
    // engine decides: the provided answers are those of an engine that does not number its links,
    // which refuses a set by name ([`LinksNotHonoured`]) and makes the call of its no-set twin for
    // no set. An engine that honours a set overrides them. The policy itself is the entry point's
    // to apply, by the session's snapshot (`LinkRestriction::admit_by`), before a set reaches an
    // engine.

    /// [`Self::declare_subscriber_on_wire`] limited to the links of `links`: declared to the nodes
    /// behind those links only. A set the engine cannot honour is refused as that statement
    /// ([`Refusal::NotHonoured`]), and nothing is declared.
    fn declare_subscriber_on_link_set(
        &self,
        keyexpr: &str,
        wire: WireKey,
        allowed_origin: Locality,
        links: LinkRestriction,
        retraction: Option<RetractionKey>,
        sink: SubscriberSink,
    ) -> Result<SubId, Refusal> {
        LinksNotHonoured::unless_unrestricted(links)?;
        self.declare_subscriber_on_wire(keyexpr, wire, allowed_origin, retraction, sink)
    }

    /// [`Self::declare_queryable_on_wire`] limited to the links of `links`, as
    /// [`Self::declare_subscriber_on_link_set`] limits a subscriber.
    #[allow(clippy::too_many_arguments)]
    fn declare_queryable_on_link_set(
        &self,
        keyexpr: &str,
        wire: WireKey,
        complete: bool,
        allowed_origin: Locality,
        links: LinkRestriction,
        retraction: Option<RetractionKey>,
        sink: QueryableSink,
    ) -> Result<QblId, Refusal> {
        LinksNotHonoured::unless_unrestricted(links)?;
        self.declare_queryable_on_wire(keyexpr, wire, complete, allowed_origin, retraction, sink)
    }

    /// [`Self::declare_liveliness_token_on_wire`] limited to the links of `links`: announced to
    /// the nodes behind those links only.
    fn declare_liveliness_token_on_link_set(
        &self,
        keyexpr: &str,
        wire: WireKey,
        links: LinkRestriction,
        retraction: Option<RetractionKey>,
    ) -> Result<TokenId, Refusal> {
        LinksNotHonoured::unless_unrestricted(links)?;
        self.declare_liveliness_token_on_wire(keyexpr, wire, retraction)
    }

    /// [`Self::declare_liveliness_subscriber_on_wire`] limited to the links of `links`: its
    /// interest is declared to the nodes behind those links only.
    fn declare_liveliness_subscriber_on_link_set(
        &self,
        keyexpr: &str,
        wire: WireKey,
        history: bool,
        links: LinkRestriction,
        sink: LivelinessSink,
    ) -> Result<SubId, Refusal> {
        LinksNotHonoured::unless_unrestricted(links)?;
        self.declare_liveliness_subscriber_on_wire(keyexpr, wire, history, sink)
    }

    /// [`Self::liveliness_get_on_wire`] limited to the links of `links`: asked of the nodes behind
    /// those links only. A set the engine cannot honour is refused as that statement
    /// ([`Refusal::NotHonoured`]), and no leg is issued (`leg` is not called).
    fn liveliness_get_on_link_set(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        timeout_ms: u32,
        links: LinkRestriction,
        fan: Option<&CancellableFan>,
        leg: &mut dyn FnMut() -> ReplyCallback,
    ) -> Result<usize, Refusal> {
        LinksNotHonoured::unless_unrestricted(links)?;
        self.liveliness_get_on_wire(keyexpr, wire, timeout_ms, fan, leg)
    }

    /// Run `tick` every `period_ms` on the engine's own clock, until it answers `false` or
    /// [`Self::stop_ticker`] is called with the id returned. At least a millisecond: a shorter
    /// period is raised to it, so a job cannot make the engine spin.
    ///
    /// The first run is one period after the call, and each next one a period after the previous
    /// run ended, so a slow tick is not run again at once to catch up. A tick runs outside the
    /// engine's locks and never alongside itself. WHERE it runs is the engine's: a runtime that
    /// has tasks runs it in one; the cooperative engine runs it from the call that steps the
    /// session, so a tick is as late as the program is slow to step. Refused when the session's
    /// table of jobs is full or the session is closed, and with [`Refusal::NotBuilt`] by an
    /// engine with no periodic jobs in this build, which is the provided answer.
    fn start_ticker(&self, period_ms: u64, tick: Tick) -> Result<TickerId, Refusal> {
        let _ = (period_ms, tick);
        Err(Refusal::NotBuilt)
    }

    /// End the periodic job `id`. A tick already running is not interrupted, and none starts
    /// after this returns. Ending one already ended, or one never started, does nothing.
    fn stop_ticker(&self, id: TickerId) {
        let _ = id;
    }
}
