// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The transport's part of a session ([`TransportState`]): its links, the ports it listens on
//! and the groups it joined, and the reads and refusals that touch nothing else of the session.
//! What a link coming up or going does to the session's tables, its replay and its watchers is
//! the session's to carry out ([`Core`]).

use super::*;
use wz_runtime_coop::face_life::{FaceRole, Turn};
#[cfg(feature = "listen")]
use wz_runtime_coop::faces::Accepted;
use wz_runtime_coop::faces::FaceRead;
use wz_runtime_coop::session_drive::PendingDial;
#[cfg(feature = "queryable")]
use wz_session_core::response_sink::ResponseSink;
use wz_session_mcu::dial::parse_locator;

/// The transport's part of [`Core`]: the session's links and what their handshakes and
/// receives are handed.
pub(super) struct TransportState<L: SessionLinks + 'static, C: ClockSource + 'static> {
    /// Whether the links' pool of outbound slots is smaller than the links (`TX_POOL_SLOTS`), so
    /// that a link may find every slot held by another link's frame its stream has not finished:
    /// a publish that may not be dropped then waits for a slot with nothing of the session held
    /// ([`CoopEngine::publish_to_link`]).
    #[cfg(feature = "listen")]
    pub(super) tx_pool_short: bool,
    /// The session's faces, the dial role's first, which is never removed, then the others in the
    /// order they came, over the network their links are opened on: the faces' links, the dials
    /// under way, the ports listened on and a read's waits are the driver's
    /// (`wz_runtime_coop::faces`). What is declared is declared over each face, and a get is
    /// asked of each.
    pub(super) links: LinkSupervisor<L, Face<C, L>>,
    /// The texts of the endpoints the session dials and listens on, written once when it opened
    /// into rows of its arena: a dial and a port name their endpoint by its row, and the config's
    /// copies went with the open.
    pub(super) endpoints: EndpointTexts,
    /// The multicast groups the session joined, each a face of its own (`group`).
    #[cfg(feature = "group")]
    pub(super) groups: Vec<GroupFace<L::Waits>>,
    /// The zid in its wire form, which every handshake of the session announces.
    pub(super) wire_zid: SessionZid,
    /// The session's say on a link to a node it holds a link to, asked while the link's handshake
    /// runs (`install_link_admission`, `listen`).
    #[cfg(feature = "listen")]
    pub(super) admission: Arc<dyn LinkAdmission>,
    /// The cells each link's gates are placed in when the session makes the link (`LinkGate`),
    /// lent from the arena; none for a plan that laid out none.
    pub(super) gate_cells: Option<LentByteCells>,
    /// The cells each link's actions are placed in when the session makes the link, lent from the
    /// arena; none for a plan that laid out none.
    pub(super) actions_cells: Option<LentByteCells>,
    /// The key-wire form of each link the session opens: the session's, and the one stated for an
    /// endpoint apart from it (`shared-key-ids`).
    #[cfg(feature = "shared-key-ids")]
    pub(super) key_forms: LinkKeyForms,
    /// The one reassembly Router of the session, which its links share: its chains are keyed by
    /// their peers, and staged in the session's buffers for them, each claimed by a chain while it
    /// is open, lent from the arena (`ArenaPlan::reassembly`). The session sweeps it and ends a
    /// lost peer's chains; its links' receives reach it only while [`Core::run_tasks`] lends it.
    pub(super) router: SessionReassembly,
    /// Where the session lends its Router to its links' receives, each link's task holding the
    /// place: lent for the length of a pass of the tasks and at no other time.
    pub(super) lend: RouterLend<SessionReassembly>,
}

/// What a step reads of a face and decides for it ([`TransportState::face_step`]): the face's
/// value, what the session does about its link, and the answer of its dial when one was asked.
pub(super) struct FaceStep<P> {
    pub(super) life: FaceLife,
    pub(super) effect: FaceEffect,
    pub(super) answer: DialAnswer<P>,
}

/// A dial of one of the session's endpoints, asked once as it is begun
/// ([`TransportState::dial_row`]).
pub(super) enum DialRow<D, P> {
    /// Not answered yet: the steps that follow ask it.
    Pending(Dial<D>),
    /// Answered at once: the link it made, or why it was refused.
    Answered(Result<OpenedLink<P>, LinkOpenError>),
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> TransportState<L, C> {
    /// The dial role's face, which the session holds for its whole life.
    pub(super) fn dial(&self) -> &Face<C, L> {
        &self.links.faces()[0]
    }

    /// The actions of every face whose link is up, which is what the session sends through. A
    /// face whose link is dialled or waits to be is not among them: what is declared then is
    /// declared when it comes up.
    pub(super) fn ups(&self) -> impl Iterator<Item = &SessionHandle<C>> {
        self.links
            .faces()
            .iter()
            .filter_map(|face| match &face.link {
                Link::Up(wire) => Some(&wire.actions),
                _ => None,
            })
    }

    /// [`Self::ups`], each with the id of its face.
    pub(super) fn ups_by_id(&self) -> impl Iterator<Item = (FaceId, &SessionHandle<C>)> {
        self.links
            .faces()
            .iter()
            .filter_map(|face| match &face.link {
                Link::Up(wire) => Some((face.id, &wire.actions)),
                _ => None,
            })
    }

    /// The face of the least id past `after` (any, for none) whose link is up, when `remote`:
    /// how a get walks the faces it asks one at a time, taking the session's lock for each and
    /// keeping no list of them. A face that comes up during the walk with a greater id is asked
    /// too, and one that goes is not.
    #[cfg(feature = "query")]
    pub(super) fn next_up_face(&self, remote: bool, after: Option<FaceId>) -> Option<FaceId> {
        if !remote {
            return None;
        }
        self.links
            .faces()
            .iter()
            .filter(|face| matches!(face.link, Link::Up(_)))
            .map(|face| face.id)
            .filter(|id| match after {
                Some(after) => *id > after,
                None => true,
            })
            .min()
    }

    /// The group of the least id past `after` (any, for none) the session asks queries of
    /// (`GroupDeclarations::asks_queries`), when `remote`: how a get walks its groups as it walks
    /// its faces ([`Self::next_up_face`]).
    #[cfg(all(feature = "query", feature = "group"))]
    pub(super) fn next_group_to_ask(&self, remote: bool, after: Option<FaceId>) -> Option<FaceId> {
        if !remote {
            return None;
        }
        self.groups
            .iter()
            .filter(|group| group.declarations().asks_queries())
            .map(GroupFace::id)
            .filter(|id| match after {
                Some(after) => *id > after,
                None => true,
            })
            .min()
    }

    /// The actions of face `id` while its link is up.
    #[cfg(feature = "query")]
    pub(super) fn up_actions(&self, id: FaceId) -> Option<&SessionHandle<C>> {
        self.links.faces().iter().find_map(|face| match &face.link {
            Link::Up(wire) if face.id == id => Some(&wire.actions),
            _ => None,
        })
    }

    /// Where an answer to a query that came in under `generation` goes: the link of that
    /// generation while it is up, or the group the query came on while its session runs
    /// (`group`). Either is the sink a reply and a Final are sent through.
    #[cfg(feature = "queryable")]
    pub(super) fn answer_route(&self, generation: u64) -> Option<&dyn ResponseSink> {
        #[cfg(feature = "group")]
        if let Some(group) = self
            .groups
            .iter()
            .find(|group| group.answers_as(generation))
        {
            return Some(group.replies() as &dyn ResponseSink);
        }
        self.links.faces().iter().find_map(|face| match &face.link {
            Link::Up(wire) if wire.generation == generation => {
                Some(&*wire.actions as &dyn ResponseSink)
            }
            _ => None,
        })
    }

    /// Write on its group what the answers to a query that came in under `generation` put on the
    /// group's stage, on this thread, as a put on the group is written by the thread that puts it.
    /// Nothing is done for a query that came in on a link.
    #[cfg(all(feature = "queryable", feature = "group"))]
    pub(super) fn write_answers(&self, generation: u64) {
        if let Some(group) = self
            .groups
            .iter()
            .find(|group| group.answers_as(generation))
        {
            group.write_staged();
        }
    }

    /// Begin a dial of `endpoint`, which the network answers later
    /// (`SessionLinks::begin_initiator`). [`OpenError::Unreachable`] when the endpoint does not
    /// parse or the network refuses the dial at once.
    /// Out of line: the dial role and a face added by the program each begin a dial.
    #[inline(never)]
    pub(super) fn begin_dial(&self, endpoint: &str) -> Result<L::Dial, OpenError> {
        let to = parse_locator(endpoint).map_err(|refused| {
            OpenError::Unreachable(EndpointRefusal::new(endpoint, Refusal::Locator(refused)))
        })?;
        self.links.begin_dial(to).map_err(|refused| {
            OpenError::Unreachable(EndpointRefusal::new(endpoint, Refusal::Link(refused)))
        })
    }

    /// The text of the endpoint a dial reaches: the session's, by its row, or the one the dial
    /// named; empty for none.
    pub(super) fn endpoint_text<'a>(&'a self, endpoint: Option<&'a DialEndpoint>) -> &'a str {
        endpoint.map_or("", |endpoint| endpoint.text(&self.endpoints))
    }

    /// A link to `endpoint` refused for want of a cell of the session's tables, as one past the
    /// stack's buffers is. Out of line: each part of a link a cell holds is refused by it.
    #[cold]
    #[inline(never)]
    pub(super) fn cells_exhausted(&self, endpoint: Option<&DialEndpoint>) -> OpenError {
        OpenError::Unreachable(EndpointRefusal::new(
            self.endpoint_text(endpoint),
            Refusal::Link(LinkOpenError::Exhausted),
        ))
    }

    /// The node a handshake that is over reached, when another face holds it or brings a link to
    /// it up: what the dial role's face stands by for. Read before the link's task is ended.
    #[cfg(feature = "listen")]
    pub(super) fn stood_by(&self, at: usize, id: FaceId, turn: &Turn) -> Option<SessionZid> {
        if !matches!(turn, Turn::HandshakeOver { .. }) {
            return None;
        }
        self.links.held_node(at, id)
    }

    /// A session that takes no face besides its dial never finds its node held by another.
    #[cfg(not(feature = "listen"))]
    pub(super) fn stood_by(&self, _at: usize, _id: FaceId, _turn: &Turn) -> Option<SessionZid> {
        None
    }

    /// Whether the session holds a transport, as zenoh-pico's `_z_transport_get_common` finds
    /// one: a link that is up, a port it listens on (a peer's unicast transport stands before any
    /// peer comes), or a group it joined. A client whose router went away holds none until a dial
    /// of it succeeds again.
    pub(super) fn holds_transport(&self) -> bool {
        #[cfg(feature = "group")]
        if !self.groups.is_empty() {
            return true;
        }
        self.ups().next().is_some() || self.listens()
    }

    /// Whether the session listens on any port.
    pub(super) fn listens(&self) -> bool {
        self.links.listens()
    }

    /// Listen on every endpoint the config lists. [`OpenError::Listen`] for the first that does
    /// not parse, that the network opens no listener for, or whose port is taken; a build without
    /// `listen` answers every endpoint so.
    pub(super) fn listen_on_config(&mut self) -> Result<(), OpenError> {
        #[cfg(feature = "listen")]
        for row in 0..self.endpoints.listens() {
            let endpoint = self.endpoints.listen_text(row);
            let refused = |why| OpenError::Listen(EndpointRefusal::new(endpoint, why));
            let at =
                parse_listen_locator(endpoint).map_err(|why| refused(Refusal::Locator(why)))?;
            // The key-wire form of a link taken on the port is the one stated for its endpoint
            // (`shared-key-ids`), which the port names by its row.
            #[cfg(feature = "shared-key-ids")]
            let named = Some(row);
            #[cfg(not(feature = "shared-key-ids"))]
            let named = None;
            self.links
                .listen(at, named)
                .map_err(|why| refused(Refusal::Link(why)))?;
        }
        #[cfg(not(feature = "listen"))]
        if self.endpoints.listens() > 0 {
            return Err(OpenError::Listen(EndpointRefusal::new(
                self.endpoints.listen_text(0),
                Refusal::ListeningNotBuilt,
            )));
        }
        Ok(())
    }

    /// Tell each group the session joined of an entity it declared, as each group's declarations
    /// say (`group`).
    #[cfg(feature = "group")]
    pub(super) fn announce_to_groups(&self, entity: GroupEntity<'_>) {
        for group in &self.groups {
            group.announce(entity);
        }
    }

    /// Tell each group the session joined that the entity `entity` it was told of is retracted
    /// (`group`).
    #[cfg(feature = "group")]
    pub(super) fn retract_from_groups(&self, entity: EntityId) {
        for group in &self.groups {
            group.retract(entity);
        }
    }

    /// The row at cursor `at` of the links of the faces that stand, in the order
    /// [`Self::standing_faces`] lists them, read in place: a unicast face's ends and a group
    /// member's are written into the row with nothing allocated.
    #[cfg(feature = "connectivity")]
    pub(super) fn face_link_at(&self, at: usize) -> Option<FaceLinkRow> {
        let mut at = at;
        for face in self.links.faces() {
            let Link::Up(wire) = &face.link else {
                continue;
            };
            if !wire.actions.is_established() {
                continue;
            }
            // Past this face's links the cursor moves on by them; within them it is the row.
            match at.checked_sub(FaceLinkRow::links_of(&*wire.actions)) {
                Some(rest) => at = rest,
                None => return FaceLinkRow::of_actions(&*wire.actions, at),
            }
        }
        #[cfg(feature = "group")]
        for group in &self.groups {
            match at.checked_sub(group.member_rows()) {
                Some(rest) => at = rest,
                None => return group.member_row(at),
            }
        }
        None
    }

    /// The faces that stand: those whose links have completed their handshakes.
    #[cfg(feature = "connectivity")]
    pub(super) fn standing_faces(&self) -> Vec<FaceSnapshot> {
        let links = self
            .links
            .faces()
            .iter()
            .filter_map(|face| match &face.link {
                Link::Up(wire) if wire.actions.is_established() => {
                    FaceSnapshot::of_actions(&*wire.actions)
                }
                _ => None,
            });
        // And each member of a group the session joined, a transport of its own as both
        // upstreams report it (`group`).
        #[cfg(feature = "group")]
        let links = links.chain(self.groups.iter().flat_map(GroupFace::member_snapshots));
        links.collect()
    }

    /// Whether a link of the session holds input it has already taken from its stack, or a group
    /// took a datagram its next step reads: what makes a read's wait none ([`Self::idle_wait`]).
    pub(super) fn holds_input(&self) -> bool {
        #[cfg(feature = "group")]
        if self.groups.iter().any(GroupFace::took_input) {
            return true;
        }
        self.links.holds_input()
    }

    /// Whether the dial role's face has what an open waits for: its link is up, or the node it
    /// reached is held by another face (`Link::Held`, with `listen`).
    pub(super) fn dial_settled(&self) -> bool {
        match self.dial().link {
            Link::Up(_) => true,
            #[cfg(feature = "listen")]
            Link::Held { .. } => true,
            _ => false,
        }
    }

    /// What became of the link of the face at `at`, numbered `id`, read off it at `now_us`, and
    /// what the face does about it (`FaceLife`), `redials` when the session dials its endpoints
    /// again: the session carries it out, with the answer of the dial when one was asked. A dial
    /// that is over is let go of here, with what it held for its link (a socket, the link's
    /// buffers), before the face is dialled anew.
    // Always inlined: its one caller held these values in its own frame.
    #[inline(always)]
    pub(super) fn face_step(
        &mut self,
        at: usize,
        id: FaceId,
        redials: bool,
        now_us: u64,
    ) -> FaceStep<L::Pump> {
        let role = if id == DIAL_FACE {
            FaceRole::Dial
        } else {
            FaceRole::Taken
        };
        let FaceRead {
            phase,
            signals,
            answer,
        } = self.links.read_face(at, id);
        let life = FaceLife::new(id, role, phase);
        let turn = life.turn(now_us, signals);
        if matches!(turn, Turn::DialOver { .. }) {
            self.links.put_link(at, Link::Waiting { at_us: now_us });
        }
        let stood_by = self.stood_by(at, id, &turn);
        let effect = life.effect(turn, redials, stood_by);
        FaceStep {
            life,
            effect,
            answer,
        }
    }

    /// End the handshake of the face at `at` that failed, and say why: the Close its peer sent,
    /// its task's end, or its deadline. Its task is told to stop, and ends in the session's next
    /// pass of its tasks, before [`Self::handshake_failed`] lets the link go.
    pub(super) fn end_handshake(&self, at: usize) -> Refusal {
        let why = Refusal::from(self.links.handshake_end(at));
        self.links.abort_link(at);
        why
    }

    /// Let go of the link of the face at `at`, whose handshake failed for `why` and whose task
    /// ended, the face waiting from `now_us`: the reason the face's next step (`then`) goes on
    /// with, which names the endpoint dialled last when the face dials the next one.
    // Always inlined: its one caller held these values in its own frame.
    #[inline(always)]
    pub(super) fn handshake_failed(
        &mut self,
        at: usize,
        then: &Next,
        why: Refusal,
        now_us: u64,
    ) -> OpenError {
        self.links.put_link(at, Link::Waiting { at_us: now_us });
        match then {
            Next::DialFrom { from } => OpenError::Unreachable(EndpointRefusal::new(
                self.endpoints.dial_text(from.saturating_sub(1)),
                why,
            )),
            _ => OpenError::NoEndpoint,
        }
    }

    /// Begin a dial of the session's endpoint at row `at` and ask it once: one the network has not
    /// answered yet is handed back under way, and one answered at once with its answer.
    /// [`OpenError::Unreachable`] when the endpoint does not parse or the network refuses the
    /// dial at once.
    // Always inlined: its one caller held these values in its own frame.
    #[inline(always)]
    pub(super) fn dial_row(&self, at: usize) -> Result<DialRow<L::Dial, L::Pump>, OpenError> {
        let mut pending = self.begin_dial(self.endpoints.dial_text(at))?;
        // A dial that answered has handed out all it held (the socket, the link's buffers, the
        // program's link), and keeps only handles that own nothing, so it is let go of here,
        // before its link is opened, with nothing to observe: every stack's dial takes those out
        // as it answers (`Dialled`, `ip_stack::IpDial`, `app_link::AppDial`).
        Ok(match pending.poll() {
            None => DialRow::Pending(Dial::new(DialEndpoint::Listed(at), pending)),
            Some(answer) => DialRow::Answered(answer),
        })
    }

    /// End the chains the peer of the face at `at` has under way in the session's Router, as its
    /// link is lost: the Router the session's links share would otherwise splice the fragments of
    /// the peer's next link onto them.
    pub(super) fn end_peer_chains(&mut self, at: usize) {
        let peer = self
            .links
            .faces()
            .get(at)
            .and_then(|face| face.link.wire())
            .and_then(|wire| wire.actions.peer_zid());
        if let Some(zid) = peer {
            self.router.abort_peer(&zid);
        }
    }

    /// The next connection that waits on the ports the session listens on, from port `*at` on,
    /// with the endpoint its port is stated for. A port that had no socket or buffer for one just
    /// now is passed, and looked at again on the next step; one that is broken for good is let
    /// go of, and the port after it is at `*at` then. `None` once every port was looked at.
    #[cfg(feature = "listen")]
    // Always inlined: its one caller held these values in its own frame.
    #[inline(always)]
    pub(super) fn next_accepted(
        &mut self,
        at: &mut usize,
    ) -> Option<(OpenedLink<L::Pump>, Option<DialEndpoint>)> {
        while let Some(accepted) = self.links.accept_at(*at) {
            match accepted {
                Accepted::Link(opened, endpoint) => return Some((opened, endpoint)),
                Accepted::Idle => *at += 1,
                Accepted::Broken => {}
            }
        }
        None
    }
}
