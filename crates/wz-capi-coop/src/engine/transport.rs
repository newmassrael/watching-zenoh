// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The transport's part of a session is the runtime's (`wz_runtime_coop::transport`), over this
//! engine's records of a face and of a group: what each names of them is here. What a link coming
//! up or going does to the session's tables, its replay and its watchers is the session's to carry
//! out ([`Core`]).

use super::*;

/// The transport's part of [`Core`]: the session's links and what their handshakes and
/// receives are handed, over this engine's faces and groups.
pub(super) type TransportState<L, C> = wz_runtime_coop::transport::TransportState<Face<C, L>>;

/// A face of this engine names the transport's types: its clock, its network, its link's session
/// and the group a session joins (`group`).
impl<C: ClockSource + 'static, L: CoopLinks + 'static> TransportFaces for Face<C, L> {
    type Clock = C;
    type Lock = SessionLock;
    type Links = L;
    type Session = LinkSession<C>;
    type Wire = FaceLink<C, L>;
    type Face = Self;
    // A build that takes no face beside its dial role's holds that one alone, so its walks over
    // the faces are one face and no place is looked up (`crate::arena::TAKES_FACES`).
    #[cfg(any(feature = "listen", feature = "group"))]
    type Places = wz_runtime_coop::faces::ManyFaces<Self>;
    #[cfg(not(any(feature = "listen", feature = "group")))]
    type Places = wz_runtime_coop::faces::OneFace<Self>;
    #[cfg(feature = "group")]
    type Group = GroupFace<L::Waits>;
    type RouterPlace = super::RouterPlace;
    #[cfg(wz_round)]
    type Router = SessionReassembly;
    // The Router lies beside the one link the read steps itself, apart from the session's state
    // (`super::direct`).
    #[cfg(not(wz_round))]
    type Router = ();
}

/// What the session tells the groups it joined of its entities (`group`): this engine's, since
/// an entity is told in the words of its declarations.
#[cfg(feature = "group")]
pub(super) trait TellGroups {
    /// Tell each group the session joined of an entity it declared, as each group's declarations
    /// say (`group`).
    fn announce_to_groups(&self, entity: GroupEntity<'_>);

    /// Tell each group the session joined that the entity `entity` it was told of is retracted
    /// (`group`).
    fn retract_from_groups(&self, entity: EntityId);
}

#[cfg(feature = "group")]
impl<L: CoopLinks + 'static, C: ClockSource + 'static> TellGroups for TransportState<L, C> {
    fn announce_to_groups(&self, entity: GroupEntity<'_>) {
        for group in &self.groups {
            group.announce(entity);
        }
    }

    fn retract_from_groups(&self, entity: EntityId) {
        for group in &self.groups {
            group.retract(entity);
        }
    }
}
