// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2864 (open-debt item 751) — the region-keyed STRUCTURE the pin's routing
//! plane is built on, ported before anything routes on it.
//!
//! The pin keys every routing table by
//! [`Region`](wz_session_core::extbound::Region): a node builds one HAT per
//! region it serves, and a face is owned by the hat of the region it landed in
//! (`zenoh/src/net/routing/dispatcher/tables.rs`
//! @ `pub hats: RegionMap<Box<dyn HatTrait + Send + Sync>>,`). wz's routers
//! still carry the 1.5.0 shape — two link-state nets classified by the
//! remote's whatami, with per-keyexpr master election bridging them — and the
//! owner's 2026-09-21 decision is to follow the pin. The ORDER is part of that
//! decision: election holds up cross-mesh loop-freedom today, so the region
//! model is built first and routing moves onto it before election is removed.
//!
//! This module is that first step and changes no wire behaviour: the map, the
//! set of regions a node on the `Auto` gateway preset builds, and which kind of
//! hat serves each one.

use wz_session_core::extbound::{Bound, Region};
use wz_session_core::WhatAmI;

/// A map from [`Region`] to `D`, as the pin's `RegionMap`
/// (`zenoh/src/net/routing/dispatcher/region.rs` @ `pub(crate) struct RegionMap<D> {`).
///
/// Dense, with the pin's index layout: `North` = 0, `Local` = 1, and
/// `South { id, mode }` = `2 + 3 * id + {Router: 0, Peer: 1, Client: 2}`.
/// Iteration therefore visits regions in the same order upstream's does, which
/// matters to anything that folds over them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionMap<D> {
    buf: Vec<Option<D>>,
}

impl<D> Default for RegionMap<D> {
    fn default() -> Self {
        Self { buf: Vec::new() }
    }
}

impl<D> RegionMap<D> {
    pub fn get(&self, region: &Region) -> Option<&D> {
        self.buf
            .get(region_to_index(region))
            .and_then(|o| o.as_ref())
    }

    pub fn get_mut(&mut self, region: &Region) -> Option<&mut D> {
        self.buf
            .get_mut(region_to_index(region))
            .and_then(|o| o.as_mut())
    }

    /// Insert, returning the value the region held before.
    pub fn insert(&mut self, region: Region, value: D) -> Option<D> {
        let idx = region_to_index(&region);
        if self.buf.len() < idx + 1 {
            self.buf.resize_with(idx + 1, || None);
        }
        self.buf[idx].replace(value)
    }

    pub fn iter(&self) -> impl Iterator<Item = (Region, &D)> {
        self.buf
            .iter()
            .enumerate()
            .filter_map(|(i, v)| v.as_ref().map(|v| (index_to_region(i), v)))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (Region, &mut D)> {
        self.buf
            .iter_mut()
            .enumerate()
            .filter_map(|(i, v)| v.as_mut().map(|v| (index_to_region(i), v)))
    }

    pub fn regions(&self) -> impl Iterator<Item = Region> + '_ {
        self.iter().map(|(region, _)| region)
    }

    pub fn values(&self) -> impl Iterator<Item = &D> {
        self.buf.iter().filter_map(|v| v.as_ref())
    }

    /// The region's value, and every OTHER region's — the pin's
    /// `partition_mut`, which is how a new transport's face is handed to the
    /// hat that owns its region alongside every other hat
    /// (`zenoh/src/net/routing/gateway.rs` @ `let (owner_hat, other_hats) = tables`).
    /// `None` when `region` holds nothing.
    pub fn partition_mut(&mut self, region: &Region) -> Option<(&mut D, RegionMap<&mut D>)> {
        let target = region_to_index(region);
        let mut main = None;
        let mut others = RegionMap {
            buf: Vec::with_capacity(self.buf.len()),
        };
        for (i, v) in self.buf.iter_mut().enumerate() {
            if i == target {
                main = v.as_mut();
                others.buf.push(None);
            } else {
                others.buf.push(v.as_mut());
            }
        }
        Some((main?, others))
    }
}

impl<D> FromIterator<(Region, D)> for RegionMap<D> {
    fn from_iter<T: IntoIterator<Item = (Region, D)>>(iter: T) -> Self {
        let mut map = Self::default();
        for (region, value) in iter {
            map.insert(region, value);
        }
        map
    }
}

fn region_to_index(region: &Region) -> usize {
    match region {
        Region::North => 0,
        Region::Local => 1,
        Region::South { id, mode } => {
            2 + 3 * id
                + match mode {
                    WhatAmI::Router => 0,
                    WhatAmI::Peer => 1,
                    WhatAmI::Client => 2,
                }
        }
    }
}

fn index_to_region(idx: usize) -> Region {
    match idx {
        0 => Region::North,
        1 => Region::Local,
        n => Region::South {
            id: (n - 2) / 3,
            mode: match (n - 2) % 3 {
                0 => WhatAmI::Router,
                1 => WhatAmI::Peer,
                _ => WhatAmI::Client,
            },
        },
    }
}

/// The regions a node of `mode` builds a hat for on the `Auto` gateway preset,
/// which is every wz node (`gateway/south` is not a key wz honours), in the
/// pin's order (`zenoh/src/net/routing/gateway.rs`
/// @ `GatewaySouthConf::Preset(GatewayPresetConf::Auto) => match mode {`):
/// `North` first, then the default south subregions the mode serves, then
/// `Local`.
pub fn auto_regions(mode: WhatAmI) -> Vec<Region> {
    let mut regions = vec![Region::North];
    match mode {
        WhatAmI::Router => {
            regions.push(Region::default_south(WhatAmI::Client));
            regions.push(Region::default_south(WhatAmI::Peer));
        }
        WhatAmI::Peer => regions.push(Region::default_south(WhatAmI::Client)),
        WhatAmI::Client => {}
    }
    regions.push(Region::Local);
    regions
}

/// The four hats the pin ships (`zenoh/src/net/routing/hat/`: `broker`,
/// `client`, `peer`, `router`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HatKind {
    /// A north-bound client's view: everything goes to its router or peer.
    Client,
    /// The hat that serves a SOUTH client region, `Local` included.
    Broker,
    Peer,
    Router,
}

/// Which hat serves `region` on a node of `node_mode`, as the pin chooses it
/// (`zenoh/src/net/routing/gateway.rs` @ `match (region.bound(), region.mode().unwrap_or(mode)) {`):
/// `North` takes the node's own mode, a subregion takes the mode it holds.
pub fn hat_kind(region: &Region, node_mode: WhatAmI) -> HatKind {
    match (region.bound(), region.mode().unwrap_or(node_mode)) {
        (Bound::North, WhatAmI::Client) => HatKind::Client,
        (Bound::South, WhatAmI::Client) => HatKind::Broker,
        (_, WhatAmI::Peer) => HatKind::Peer,
        (_, WhatAmI::Router) => HatKind::Router,
    }
}

/// R2879 (open-debt item 751, step 5) — what the inter-region filter asks of
/// the hats: each region's gateway view, as the pin's `HatTrait` answers it
/// (`zenoh/src/net/routing/hat/mod.rs` @ `fn gateways_of(&self, tables: &TablesData, zid: &ZenohIdProto) -> Option<Vec<ZenohIdProto>>;`).
///
/// `None` is "this hat has no gateway view": a broker hat answers `None`, and
/// a mesh hat answers `None` for a node it does not know.
pub trait GatewayView<Z> {
    /// The gateways `zid` advertises a link to, in `region`'s hat.
    fn gateways_of(&self, region: Region, zid: &Z) -> Option<Vec<Z>>;
    /// Every gateway of `region`'s hat.
    fn gateways(&self, region: Region) -> Option<Vec<Z>>;
}

/// R2879 (open-debt item 751, step 5) — the pin's decision whether a `Push` or
/// a `Request` crosses a region boundary on one egress
/// (`zenoh/src/net/routing/dispatcher/tables.rs` @ `pub(crate) struct InterRegionFilter<'a> {`).
///
/// Loop-freedom between regions is carried by this and by nothing else: of
/// the gateways that could carry a message across a boundary, exactly one —
/// the largest zid — does.
#[derive(Debug, Clone, Copy)]
pub struct InterRegionFilter<'a, Z> {
    /// The region the message arrived from.
    pub src: Region,
    /// The region of the egress.
    pub dst: Region,
    /// The node that ORIGINATED the message, when the source region can name
    /// it; the pin's `src_zid`.
    pub src_zid: Option<&'a Z>,
    /// The neighbour the message arrived from; the pin's `fwd_zid`.
    pub fwd_zid: Option<&'a Z>,
    /// The neighbour the egress sends to; the pin's `dst_zid`.
    pub dst_zid: Option<&'a Z>,
}

impl<Z: Ord> InterRegionFilter<'_, Z> {
    /// `false` when the message must not take this egress, as the pin's
    /// `InterRegionFilter::resolve` decides it, arm for arm.
    pub fn resolve(&self, self_zid: &Z, view: &impl GatewayView<Z>) -> bool {
        // Same side of the boundary: nothing crosses, nothing to filter.
        if self.src.bound() == self.dst.bound() {
            return true;
        }
        // Down from the north the candidates are the DESTINATION's gateways;
        // up from the south they are the FORWARDER's, since a gateway source
        // cannot also be linked to itself
        // (`zenoh/src/net/routing/dispatcher/tables.rs` @ `// NOTE(regions): in this case, we cannot have a link with`).
        let gwys = match self.src.bound() {
            Bound::North => match self.dst_zid {
                Some(dst_zid) => view.gateways_of(self.dst, dst_zid),
                None => view.gateways(self.dst),
            },
            Bound::South => match self.fwd_zid {
                Some(fwd_zid) => view.gateways_of(self.src, fwd_zid),
                None => view.gateways(self.src),
            },
        };
        let Some(gwys) = gwys.filter(|g| !g.is_empty()) else {
            return true;
        };
        // The pin reports an unnamed source as a bug and lets the message
        // through; so does this.
        let Some(src_zid) = self.src_zid else {
            log::error!("inter-region filter: the message's source is unknown");
            return true;
        };
        // A gateway source already reached this boundary itself.
        if gwys.contains(src_zid) {
            return false;
        }
        gwys.iter().max() == Some(self_zid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use WhatAmI::{Client, Peer, Router};

    /// The pin's own `region_indexes` round-trip, plus the layout it documents.
    #[test]
    fn region_indexes_round_trip_in_the_pins_layout() {
        let regions = [
            Region::North,
            Region::Local,
            Region::South {
                id: 0,
                mode: Router,
            },
            Region::South { id: 3, mode: Peer },
            Region::South {
                id: 35,
                mode: Client,
            },
        ];
        for region in regions {
            assert_eq!(region, index_to_region(region_to_index(&region)));
        }
        assert_eq!(region_to_index(&Region::South { id: 1, mode: Peer }), 6);
        assert_eq!(
            region_to_index(&Region::South {
                id: 0,
                mode: Client
            }),
            4
        );
    }

    #[test]
    fn a_region_map_holds_one_value_per_region_and_iterates_in_index_order() {
        let mut map: RegionMap<&str> = [
            (Region::Local, "local"),
            (Region::default_south(Peer), "peers"),
            (Region::North, "north"),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            map.regions().collect::<Vec<_>>(),
            [Region::North, Region::Local, Region::default_south(Peer)]
        );
        assert_eq!(map.get(&Region::default_south(Client)), None);
        assert_eq!(map.insert(Region::North, "again"), Some("north"));
        assert_eq!(map.values().count(), 3);
    }

    #[test]
    fn partition_separates_the_owner_from_every_other_region() {
        let mut map: RegionMap<u32> = auto_regions(Router).into_iter().zip(0..).collect();
        let (owner, others) = map
            .partition_mut(&Region::default_south(Peer))
            .expect("a router builds the peer subregion");
        *owner += 100;
        assert_eq!(
            others.regions().collect::<Vec<_>>(),
            [Region::North, Region::Local, Region::default_south(Client)]
        );
        assert_eq!(map.get(&Region::default_south(Peer)), Some(&102));
        assert!(map
            .partition_mut(&Region::South { id: 7, mode: Peer })
            .is_none());
    }

    /// The pin's Auto arm, one line per mode (the citation is on [`auto_regions`]).
    #[test]
    fn auto_regions_are_the_pins_per_mode() {
        assert_eq!(
            auto_regions(Router),
            [
                Region::North,
                Region::default_south(Client),
                Region::default_south(Peer),
                Region::Local
            ]
        );
        assert_eq!(
            auto_regions(Peer),
            [Region::North, Region::default_south(Client), Region::Local]
        );
        assert_eq!(auto_regions(Client), [Region::North, Region::Local]);
    }

    /// Every hat an Auto node builds, and the hat the pin gives it: a router
    /// runs the router hat only on North (routers), a peer hat for the peers
    /// south of it, and broker hats for clients.
    #[test]
    fn each_auto_region_gets_the_pins_hat() {
        let hats = |mode| {
            auto_regions(mode)
                .iter()
                .map(|r| hat_kind(r, mode))
                .collect::<Vec<_>>()
        };
        use HatKind::{Broker, Client as ClientHat, Peer as PeerHat, Router as RouterHat};
        assert_eq!(hats(Router), [RouterHat, Broker, PeerHat, Broker]);
        assert_eq!(hats(Peer), [PeerHat, Broker, Broker]);
        assert_eq!(hats(Client), [ClientHat, Broker]);
    }

    // ── R2879 (item 751, step 5): the inter-region filter, arm by arm ──

    const PEERS: Region = Region::default_south(Peer);
    const CLIENTS: Region = Region::default_south(Client);

    /// A gateway view: per region, `(node, the gateways it links to)` pairs and
    /// the region's gateway set; a region absent from `regions` has none (the
    /// broker hat's `None`).
    struct View {
        regions: Vec<(Region, Vec<NodeGateways>, Vec<u8>)>,
    }

    /// A node and the gateways it links to.
    type NodeGateways = (u8, Vec<u8>);

    impl GatewayView<u8> for View {
        fn gateways_of(&self, region: Region, zid: &u8) -> Option<Vec<u8>> {
            let (_, links, _) = self.regions.iter().find(|(r, _, _)| *r == region)?;
            links.iter().find(|(n, _)| n == zid).map(|(_, g)| g.clone())
        }
        fn gateways(&self, region: Region) -> Option<Vec<u8>> {
            let (_, _, all) = self.regions.iter().find(|(r, _, _)| *r == region)?;
            Some(all.clone())
        }
    }

    /// Two gateways 1 and 2 of one south peer region, and a peer 9 linked to
    /// both: the pin's multiple-gateway topology.
    fn two_gateways() -> View {
        View {
            regions: vec![(
                PEERS,
                vec![(9, vec![1, 2]), (1, vec![]), (2, vec![])],
                vec![1, 2],
            )],
        }
    }

    fn filter<'a>(
        src: Region,
        dst: Region,
        src_zid: Option<&'a u8>,
        fwd_zid: Option<&'a u8>,
        dst_zid: Option<&'a u8>,
    ) -> InterRegionFilter<'a, u8> {
        InterRegionFilter {
            src,
            dst,
            src_zid,
            fwd_zid,
            dst_zid,
        }
    }

    /// Up from the south, of the gateways the forwarder links to only the
    /// largest carries the message across: exactly one crossing.
    #[test]
    fn upstream_only_the_largest_gateway_of_the_forwarder_crosses() {
        let view = two_gateways();
        let up = filter(PEERS, Region::North, Some(&9), Some(&9), None);
        assert!(!up.resolve(&1, &view), "gateway 1 is not the largest");
        assert!(up.resolve(&2, &view), "gateway 2 is");
    }

    /// Down from the north, the candidates are the DESTINATION's gateways, so
    /// the choice is per egress neighbour.
    #[test]
    fn downstream_the_candidates_are_the_destinations_gateways() {
        let view = View {
            regions: vec![(PEERS, vec![(8, vec![1]), (9, vec![1, 2])], vec![1, 2])],
        };
        let to = |dst: &'static u8| filter(Region::North, PEERS, Some(&5), Some(&5), Some(dst));
        assert!(to(&8).resolve(&1, &view), "8 links to gateway 1 alone");
        assert!(
            !to(&9).resolve(&1, &view),
            "9 also links to the larger gateway 2"
        );
        assert!(to(&9).resolve(&2, &view));
    }

    /// A source that is itself one of the candidate gateways crossed on its
    /// own; nobody else carries it.
    #[test]
    fn a_gateway_source_is_not_carried_again() {
        let view = two_gateways();
        let from_gateway = filter(PEERS, Region::North, Some(&1), Some(&9), None);
        assert!(
            !from_gateway.resolve(&2, &view),
            "even the largest gateway drops it"
        );
    }

    /// No boundary, no filter; and no gateway view, or an empty one, passes.
    #[test]
    fn the_filter_passes_what_it_has_no_boundary_or_no_view_for() {
        let view = two_gateways();
        assert!(
            filter(PEERS, CLIENTS, Some(&9), Some(&9), None).resolve(&1, &view),
            "south to south"
        );
        assert!(
            filter(CLIENTS, Region::North, Some(&7), Some(&7), None).resolve(&1, &view),
            "a broker hat has no gateway view"
        );
        assert!(
            filter(PEERS, Region::North, Some(&9), Some(&3), None).resolve(&1, &view),
            "a forwarder the hat does not know has no view"
        );
        let empty = View {
            regions: vec![(PEERS, vec![(9, vec![])], vec![])],
        };
        assert!(filter(PEERS, Region::North, Some(&9), Some(&9), None).resolve(&1, &empty));
    }

    /// No named neighbour falls back to the region's whole gateway set, and an
    /// unnamed source passes, as the pin does after reporting it.
    #[test]
    fn unnamed_neighbours_fall_back_and_an_unnamed_source_passes() {
        let view = two_gateways();
        let up = filter(PEERS, Region::North, Some(&9), None, None);
        assert!(!up.resolve(&1, &view) && up.resolve(&2, &view));
        let down = filter(Region::North, PEERS, Some(&5), Some(&5), None);
        assert!(!down.resolve(&1, &view) && down.resolve(&2, &view));
        assert!(filter(PEERS, Region::North, None, Some(&9), None).resolve(&1, &view));
    }
}
