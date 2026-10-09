// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Which region a remote lands in when the node PARTITIONS its south: the pin's
//! `compute_transient_region_of`, `compute_transient_bound_of` and
//! `compute_region_of`, whole (`zenoh/src/net/runtime/region.rs`
//! @ `pub(crate) fn compute_region_of(`).
//!
//! [`crate::extbound::region_and_bound_of`] answers the same question for a node
//! on the `auto` preset, where no remote is ever assigned a subregion by a rule
//! and only the first three arms of the pin's match are reachable. This module
//! is the whole match, with the rules: a node whose south is a list of
//! subregions puts each remote in the first subregion whose filters match it, or
//! in the north region when none does.
//!
//! The decision is a pure function of four things: the node's mode, its
//! partition, what is known of the remote ([`crate::region_partition::RemoteFacts`]) and the bound the
//! remote announced on its Open (`None` when it announced none). It is built
//! and witnessed before anything routes on it, which is the order the region
//! model itself was built in. The routing layer that would act on a custom
//! partition does not exist yet, so nothing calls this on a live session.
//!
//! ## What the filters match, as the pin does it
//!
//! `zenoh/src/net/runtime/region.rs` @ `fn is_match(filter: Option<&[GatewayFiltersConf]>, peer: &TransportPeer) -> bool {`
//! * a subregion with no filter list matches every remote; an EMPTY list matches
//!   none;
//! * within a list, ANY filter matching is a match, and a filter matches when
//!   ALL of its present fields do (`zids`, `interfaces`, `modes`,
//!   `region_names`), then `negated` inverts that verdict;
//! * `interfaces` is checked over every interface of every link of the remote
//!   with `all`, so a remote that reports no interface at all satisfies any
//!   interface filter. That is upstream's reading and it is kept.

use alloc::string::String;
use alloc::vec::Vec;

use wz_codecs::whatami::{WhatAmI, WhatAmIMatcher};

use crate::extbound::{Bound, Region};

/// What a node's south is: the one preset, or a list of subregions
/// (`commons/zenoh-config/src/gateway.rs` @ `pub enum GatewaySouthConf {`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum SouthPartition {
    /// Remotes are placed by the two modes alone
    /// ([`crate::extbound::region_and_bound_of`]).
    #[default]
    Auto,
    /// Subregion `i` is `subregions[i]`; a remote is assigned the first one whose
    /// filters match it.
    Custom(Vec<SouthSubregion>),
}

/// One south subregion's membership rule
/// (`commons/zenoh-config/src/gateway.rs` @ `pub struct GatewayExplicitSouthConf {`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SouthSubregion {
    /// `None` matches every remote, an empty list matches none.
    pub filters: Option<Vec<RegionFilter>>,
}

/// One filter of a subregion
/// (`commons/zenoh-config/src/gateway.rs` @ `pub struct GatewayFiltersConf {`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegionFilter {
    /// The roles the remote may have.
    pub modes: Option<WhatAmIMatcher>,
    /// Interface names; the remote's interfaces must ALL be among them.
    pub interfaces: Option<Vec<String>>,
    /// The remote's zid, as its wire bytes, must be one of these.
    pub zids: Option<Vec<Vec<u8>>>,
    /// The remote's announced region name must be one of these.
    pub region_names: Option<Vec<String>>,
    /// Invert the verdict of the fields above.
    pub negated: bool,
}

/// What the node knows of a remote when it places it: the fields the pin's
/// filters read off a `TransportPeer`.
#[derive(Clone, Copy, Debug)]
pub struct RemoteFacts<'a> {
    pub zid: &'a [u8],
    pub whatami: WhatAmI,
    /// The region name the remote announced on establishment, if it did.
    pub region_name: Option<&'a str>,
    /// Every interface of every link of the remote, flattened.
    pub interfaces: &'a [&'a str],
}

/// Why a remote cannot be placed: each is a `bail!` of the pin's
/// `compute_region_of` or `compute_transient_region_of`, with its message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionError {
    /// A router remote matched a subregion of a node that is not a router.
    RouterSubregionOfNonRouter,
    /// The remote announced we are north of it, our config does not make it a
    /// gateway, and the auto preset would not put it north of us either.
    RemoteCustomConflictsWithAuto,
    /// The remote announced we are south of it, but the auto preset puts it south
    /// of us.
    AutoConflictsWithCustom,
    /// Both ends put the other in the north region, with different modes.
    NorthNorth { mode: WhatAmI, remote: WhatAmI },
    /// Both ends put the other in a subregion.
    SouthSouth,
    /// Two clients meet in the north region.
    ClientClient,
}

impl core::fmt::Display for RegionError {
    /// The pin's own text.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RouterSubregionOfNonRouter => f.write_str(
                "Router regions cannot be subregions of non-router regions (unsupported)",
            ),
            Self::RemoteCustomConflictsWithAuto => {
                f.write_str("Remote's custom configuration conflicts with auto preset")
            }
            Self::AutoConflictsWithCustom => {
                f.write_str("Remote's auto preset conflicts with custom configuration")
            }
            Self::NorthNorth { mode, remote } => {
                write!(f, "North-north {mode}-{remote} configuration (invalid)")
            }
            Self::SouthSouth => f.write_str("South-south configuration (invalid)"),
            Self::ClientClient => f.write_str("North-north client-client configuration (invalid)"),
        }
    }
}

/// `is_match` for one subregion's filter list.
fn matches_filters(filters: Option<&[RegionFilter]>, remote: &RemoteFacts<'_>) -> bool {
    let Some(filters) = filters else {
        return true;
    };
    filters.iter().any(|filter| {
        let value = filter
            .zids
            .as_ref()
            .map_or(true, |zids| zids.iter().any(|z| z.as_slice() == remote.zid))
            && filter.interfaces.as_ref().map_or(true, |ifaces| {
                remote
                    .interfaces
                    .iter()
                    .all(|i| ifaces.iter().any(|name| name == i))
            })
            && filter
                .modes
                .as_ref()
                .map_or(true, |modes| modes.matches(remote.whatami))
            && filter.region_names.as_ref().map_or(true, |names| {
                remote
                    .region_name
                    .is_some_and(|rn| names.iter().any(|n| n == rn))
            });
        if filter.negated {
            !value
        } else {
            value
        }
    })
}

/// `compute_transient_region_of`: the region a node's own rules put the remote
/// in, or `None` when it has no rule (the `auto` preset).
///
/// `zenoh/src/net/runtime/region.rs` @ `fn compute_transient_region_of(`.
pub fn transient_region_of(
    mode: WhatAmI,
    partition: &SouthPartition,
    remote: &RemoteFacts<'_>,
) -> Result<Option<Region>, RegionError> {
    let SouthPartition::Custom(subregions) = partition else {
        return Ok(None);
    };
    match subregions
        .iter()
        .position(|s| matches_filters(s.filters.as_deref(), remote))
    {
        Some(id) => {
            if remote.whatami == WhatAmI::Router && mode != WhatAmI::Router {
                return Err(RegionError::RouterSubregionOfNonRouter);
            }
            Ok(Some(Region::South {
                id,
                mode: remote.whatami,
            }))
        }
        None => Ok(Some(Region::North)),
    }
}

/// `compute_transient_bound_of`: the bound this node announces for the remote on
/// its Open, in the `RemoteBound` extension, or `None` when it announces none.
/// A node on the `auto` preset announces none.
///
/// `zenoh/src/net/runtime/region.rs` @ `pub(crate) fn compute_transient_bound_of(`.
pub fn transient_bound_of(
    mode: WhatAmI,
    partition: &SouthPartition,
    remote: &RemoteFacts<'_>,
) -> Result<Option<Bound>, RegionError> {
    Ok(transient_region_of(mode, partition, remote)?.map(|region| region.bound()))
}

/// `compute_region_of`, whole: the region this node places the remote in and the
/// remote's own bound, given the bound the remote announced for us on its Open.
///
/// `zenoh/src/net/runtime/region.rs` @ `pub(crate) fn compute_region_of(`.
pub fn region_of(
    mode: WhatAmI,
    partition: &SouthPartition,
    remote: &RemoteFacts<'_>,
    transient_remote_bound: Option<Bound>,
) -> Result<(Region, Bound), RegionError> {
    let remote_mode = remote.whatami;
    let transient_region = transient_region_of(mode, partition, remote)?;
    let auto = || crate::extbound::auto_region(mode, remote_mode).ok_or(RegionError::ClientClient);

    match (
        transient_region.map(|region| (region, region.bound())),
        transient_remote_bound,
    ) {
        (None, None) => auto(),
        (None, Some(Bound::South)) => Ok((Region::North, Bound::South)),
        (Some((region, Bound::South)), None) => Ok((region, Bound::North)),
        (None, Some(Bound::North)) => {
            // Not configured to be a gateway, nor does the auto mode put the
            // remote in the north region: the pin refuses rather than invent a
            // subregion for it.
            let (auto_region, auto_remote_bound) = auto()?;
            if !auto_remote_bound.is_north() {
                Err(RegionError::RemoteCustomConflictsWithAuto)
            } else {
                Ok((auto_region, Bound::North))
            }
        }
        (Some((_, Bound::North)), None) => {
            let (auto_region, auto_remote_bound) = auto()?;
            if auto_region.bound().is_south() {
                Err(RegionError::AutoConflictsWithCustom)
            } else {
                Ok((Region::North, auto_remote_bound))
            }
        }
        (Some((_, Bound::North)), Some(Bound::North)) => {
            if mode != remote_mode {
                Err(RegionError::NorthNorth {
                    mode,
                    remote: remote_mode,
                })
            } else {
                Ok((Region::North, Bound::North))
            }
        }
        (Some((_, Bound::South)), Some(Bound::South)) => Err(RegionError::SouthSouth),
        // The two ends agree on a boundary between them (ours north and theirs
        // south, or the other way): the node's own rule places the remote, and
        // the remote's announcement is its bound.
        (Some((region, _)), Some(bound)) => Ok((region, bound)),
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;
    use WhatAmI::{Client, Peer, Router};

    const ZID_A: [u8; 4] = [0xaa; 4];
    const ZID_B: [u8; 4] = [0xbb; 4];

    fn facts<'a>(zid: &'a [u8], whatami: WhatAmI) -> RemoteFacts<'a> {
        RemoteFacts {
            zid,
            whatami,
            region_name: None,
            interfaces: &[],
        }
    }

    fn only(filter: RegionFilter) -> SouthSubregion {
        SouthSubregion {
            filters: Some(vec![filter]),
        }
    }

    fn by_zid(zid: &[u8]) -> RegionFilter {
        RegionFilter {
            zids: Some(vec![zid.to_vec()]),
            ..RegionFilter::default()
        }
    }

    fn by_mode(modes: WhatAmIMatcher) -> RegionFilter {
        RegionFilter {
            modes: Some(modes),
            ..RegionFilter::default()
        }
    }

    /// A subregion whose filter list is this one filter.
    fn passes(filter: &RegionFilter, remote: &RemoteFacts<'_>) -> bool {
        matches_filters(Some(core::slice::from_ref(filter)), remote)
    }

    // ── the filters, field by field ──

    /// No filter list matches every remote; an empty list matches none.
    #[test]
    fn a_missing_filter_list_matches_everyone_and_an_empty_one_nobody() {
        let r = facts(&ZID_A, Peer);
        assert!(matches_filters(None, &r));
        assert!(!matches_filters(Some(&[]), &r));
    }

    /// Any filter of the list may match.
    #[test]
    fn a_remote_matching_any_one_filter_matches_the_list() {
        let r = facts(&ZID_B, Peer);
        let list = [by_zid(&ZID_A), by_zid(&ZID_B)];
        assert!(matches_filters(Some(&list), &r));
        assert!(!matches_filters(Some(&list[..1]), &r));
    }

    /// All fields of one filter must match, not any of them.
    #[test]
    fn every_present_field_of_a_filter_must_match() {
        let both = RegionFilter {
            zids: Some(vec![ZID_A.to_vec()]),
            modes: Some(WhatAmIMatcher::empty().client()),
            ..RegionFilter::default()
        };
        assert!(passes(&both, &facts(&ZID_A, Client)));
        assert!(
            !passes(&both, &facts(&ZID_A, Peer)),
            "right zid, wrong mode"
        );
        assert!(
            !passes(&both, &facts(&ZID_B, Client)),
            "right mode, wrong zid"
        );
    }

    /// `modes` is a set of roles.
    #[test]
    fn the_modes_field_is_a_role_set() {
        let rp = by_mode(WhatAmIMatcher::empty().router().peer());
        assert!(passes(&rp, &facts(&ZID_A, Router)));
        assert!(passes(&rp, &facts(&ZID_A, Peer)));
        assert!(!passes(&rp, &facts(&ZID_A, Client)));
    }

    /// `region_names` needs the remote to have announced a name among them.
    #[test]
    fn the_region_names_field_needs_an_announced_name() {
        let f = RegionFilter {
            region_names: Some(vec!["lab".to_string()]),
            ..RegionFilter::default()
        };
        let named = |name| RemoteFacts {
            region_name: name,
            ..facts(&ZID_A, Peer)
        };
        assert!(passes(&f, &named(Some("lab"))));
        assert!(!passes(&f, &named(Some("plant"))));
        assert!(
            !passes(&f, &named(None)),
            "a remote that announced no name is in no named region"
        );
    }

    /// `interfaces` is an ALL over the remote's interfaces, so a remote that
    /// reports none satisfies any interface filter. That is upstream's reading.
    #[test]
    fn the_interfaces_field_requires_all_of_the_remotes_interfaces() {
        let f = RegionFilter {
            interfaces: Some(vec!["lo".to_string(), "eth0".to_string()]),
            ..RegionFilter::default()
        };
        let on = |ifaces: &'static [&'static str]| RemoteFacts {
            interfaces: ifaces,
            ..facts(&ZID_A, Peer)
        };
        assert!(passes(&f, &on(&["lo"])));
        assert!(passes(&f, &on(&["lo", "eth0"])));
        assert!(
            !passes(&f, &on(&["lo", "wlan0"])),
            "one interface outside the list is enough to fail"
        );
        assert!(
            passes(&f, &on(&[])),
            "no interface is vacuously all of them"
        );
    }

    /// `negated` inverts the verdict of the fields.
    #[test]
    fn negation_inverts_a_filters_verdict() {
        let not_a = RegionFilter {
            negated: true,
            ..by_zid(&ZID_A)
        };
        assert!(!passes(&not_a, &facts(&ZID_A, Peer)));
        assert!(passes(&not_a, &facts(&ZID_B, Peer)));
    }

    // ── the transient region and bound ──

    /// On the `auto` preset there is no rule, so no region and no announced bound.
    #[test]
    fn the_auto_preset_has_no_transient_region_or_bound() {
        for mode in [Router, Peer, Client] {
            for remote in [Router, Peer, Client] {
                let r = facts(&ZID_A, remote);
                assert_eq!(
                    transient_region_of(mode, &SouthPartition::Auto, &r),
                    Ok(None)
                );
                assert_eq!(
                    transient_bound_of(mode, &SouthPartition::Auto, &r),
                    Ok(None)
                );
            }
        }
    }

    /// The first matching subregion wins, carries the remote's own mode, and a
    /// remote no subregion matches is in the north region.
    #[test]
    fn a_remote_is_in_the_first_matching_subregion_or_the_north() {
        let partition = SouthPartition::Custom(vec![
            only(by_zid(&ZID_A)),
            only(by_mode(WhatAmIMatcher::empty().peer())),
        ]);
        let region = |zid: &[u8], mode| transient_region_of(Router, &partition, &facts(zid, mode));
        assert_eq!(
            region(&ZID_A, Peer),
            Ok(Some(Region::South { id: 0, mode: Peer })),
            "matches both; the first wins"
        );
        assert_eq!(
            region(&ZID_B, Peer),
            Ok(Some(Region::South { id: 1, mode: Peer }))
        );
        assert_eq!(
            region(&ZID_A, Client),
            Ok(Some(Region::South {
                id: 0,
                mode: Client
            })),
            "the subregion holds the remote's own mode"
        );
        assert_eq!(region(&ZID_B, Client), Ok(Some(Region::North)));
        assert_eq!(
            transient_bound_of(Router, &partition, &facts(&ZID_B, Peer)),
            Ok(Some(Bound::South))
        );
        assert_eq!(
            transient_bound_of(Router, &partition, &facts(&ZID_B, Client)),
            Ok(Some(Bound::North))
        );
    }

    /// A router remote may be put in a subregion only by a router.
    #[test]
    fn a_router_remote_is_a_subregion_member_only_of_a_router() {
        let partition = SouthPartition::Custom(vec![SouthSubregion::default()]);
        let r = facts(&ZID_A, Router);
        assert_eq!(
            transient_region_of(Router, &partition, &r),
            Ok(Some(Region::South {
                id: 0,
                mode: Router
            }))
        );
        for mode in [Peer, Client] {
            assert_eq!(
                transient_region_of(mode, &partition, &r),
                Err(RegionError::RouterSubregionOfNonRouter)
            );
        }
    }

    // ── compute_region_of, arm by arm ──

    fn custom_south_peers() -> SouthPartition {
        SouthPartition::Custom(vec![only(by_mode(WhatAmIMatcher::empty().peer()))])
    }

    /// Arm `(None, None)`: no rule and no announcement, the auto table.
    #[test]
    fn arm_no_rule_and_no_announcement_is_the_auto_table() {
        for mode in [Router, Peer, Client] {
            for remote in [Router, Peer, Client] {
                let got = region_of(mode, &SouthPartition::Auto, &facts(&ZID_A, remote), None);
                let want = crate::extbound::region_and_bound_of(mode, remote, None)
                    .ok_or(RegionError::ClientClient);
                assert_eq!(got, want, "{mode:?} <- {remote:?}");
            }
        }
    }

    /// The `auto` preset reduces to [`crate::extbound::region_and_bound_of`] for
    /// every announced bound as well, so there is one answer for a node without
    /// rules.
    #[test]
    fn the_auto_preset_agrees_with_the_auto_only_function_for_every_bound() {
        for mode in [Router, Peer, Client] {
            for remote in [Router, Peer, Client] {
                for bound in [None, Some(Bound::North), Some(Bound::South)] {
                    let got =
                        region_of(mode, &SouthPartition::Auto, &facts(&ZID_A, remote), bound).ok();
                    assert_eq!(
                        got,
                        crate::extbound::region_and_bound_of(mode, remote, bound),
                        "{mode:?} <- {remote:?}, announced {bound:?}"
                    );
                }
            }
        }
    }

    /// Arm `(None, Some(South))`: the remote calls us south, so it is north of us.
    #[test]
    fn arm_a_remote_that_calls_us_south_is_north() {
        assert_eq!(
            region_of(
                Router,
                &SouthPartition::Auto,
                &facts(&ZID_A, Peer),
                Some(Bound::South)
            ),
            Ok((Region::North, Bound::South))
        );
    }

    /// Arm `(Some(South), None)`: our rule puts it in a subregion, it announced
    /// nothing, so it is in that subregion and north-bound.
    #[test]
    fn arm_our_rule_puts_it_south_and_it_announced_nothing() {
        assert_eq!(
            region_of(Router, &custom_south_peers(), &facts(&ZID_A, Peer), None),
            Ok((Region::South { id: 0, mode: Peer }, Bound::North))
        );
    }

    /// Arm `(None, Some(North))`: no rule of ours, the remote calls us north. The
    /// auto table must agree the remote is north-bound, else the pin refuses.
    #[test]
    fn arm_a_remote_calling_us_north_must_agree_with_the_auto_table() {
        assert_eq!(
            region_of(
                Router,
                &SouthPartition::Auto,
                &facts(&ZID_A, Peer),
                Some(Bound::North)
            ),
            Ok((Region::default_south(Peer), Bound::North)),
            "the auto table puts a peer south of a router with the remote north-bound"
        );
        assert_eq!(
            region_of(
                Client,
                &SouthPartition::Auto,
                &facts(&ZID_A, Router),
                Some(Bound::North)
            ),
            Err(RegionError::RemoteCustomConflictsWithAuto),
            "the auto table calls a router north of a client, remote bound south"
        );
    }

    /// Arm `(Some(North), None)`: our rule puts it north. The auto table must not
    /// put it in a subregion, else the pin refuses.
    #[test]
    fn arm_our_rule_puts_it_north_and_the_auto_table_must_not_put_it_south() {
        let to_north = SouthPartition::Custom(vec![only(by_zid(&ZID_B))]);
        assert_eq!(
            region_of(Peer, &to_north, &facts(&ZID_A, Router), None),
            Ok((Region::North, Bound::South)),
            "a router is north of a peer in the auto table, remote bound south"
        );
        assert_eq!(
            region_of(Router, &to_north, &facts(&ZID_A, Peer), None),
            Err(RegionError::AutoConflictsWithCustom),
            "the auto table would put a peer south of a router"
        );
    }

    /// Arm `(Some(North), Some(North))`: both ends call the other north, which is
    /// valid only between nodes of one mode.
    #[test]
    fn arm_both_ends_north_needs_equal_modes() {
        let to_north = SouthPartition::Custom(vec![only(by_zid(&ZID_B))]);
        assert_eq!(
            region_of(
                Router,
                &to_north,
                &facts(&ZID_A, Router),
                Some(Bound::North)
            ),
            Ok((Region::North, Bound::North))
        );
        assert_eq!(
            region_of(Router, &to_north, &facts(&ZID_A, Peer), Some(Bound::North)),
            Err(RegionError::NorthNorth {
                mode: Router,
                remote: Peer
            })
        );
    }

    /// Arm `(Some(South), Some(South))`: both ends put the other in a subregion.
    #[test]
    fn arm_both_ends_south_is_refused() {
        assert_eq!(
            region_of(
                Router,
                &custom_south_peers(),
                &facts(&ZID_A, Peer),
                Some(Bound::South)
            ),
            Err(RegionError::SouthSouth)
        );
    }

    /// Arms `(Some(North), Some(South))` and `(Some(South), Some(North))`: the two
    /// ends agree on the boundary, the node's rule places the remote and the
    /// remote's announcement is its bound.
    #[test]
    fn arm_the_ends_agree_on_a_boundary() {
        assert_eq!(
            region_of(
                Router,
                &custom_south_peers(),
                &facts(&ZID_A, Peer),
                Some(Bound::North)
            ),
            Ok((Region::South { id: 0, mode: Peer }, Bound::North)),
            "our rule: south; remote: north of it"
        );
        let to_north = SouthPartition::Custom(vec![only(by_zid(&ZID_B))]);
        assert_eq!(
            region_of(Peer, &to_north, &facts(&ZID_A, Router), Some(Bound::South)),
            Ok((Region::North, Bound::South)),
            "our rule: north; remote: south of it"
        );
    }

    /// Two clients in the north region are the pin's `bail!`, from the auto arms.
    #[test]
    fn two_clients_are_refused_in_the_auto_arms() {
        assert_eq!(
            region_of(Client, &SouthPartition::Auto, &facts(&ZID_A, Client), None),
            Err(RegionError::ClientClient)
        );
    }

    /// The refusals carry the pin's own words.
    #[test]
    fn the_refusals_read_as_the_pin_words_them() {
        assert_eq!(
            RegionError::NorthNorth {
                mode: Router,
                remote: Peer
            }
            .to_string(),
            "North-north router-peer configuration (invalid)"
        );
        assert_eq!(
            RegionError::SouthSouth.to_string(),
            "South-south configuration (invalid)"
        );
        assert_eq!(
            RegionError::ClientClient.to_string(),
            "North-north client-client configuration (invalid)"
        );
    }
}
