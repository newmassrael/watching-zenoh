// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the `0x7` REMOTE-BOUND extension on the OPEN messages, and for the
//! region a unicast session lands in — the `region` field of a node's
//! `sessions[]` entry.
//!
//! ## The extension, read at the pin
//!
//! `zenoh` @ `commons/zenoh-protocol/src/transport/open.rs`
//! @ `pub type RemoteBound = zextz64!(0x7, false);` — id `0x7`, Z64 encoding,
//! NOT mandatory, on BOTH `OpenSyn` and `OpenAck`
//! (@ `pub ext_remote_bound: Option<ext::RemoteBound>,`). The sender puts the
//! bound it computed for US; the value is a `Bound` as `u8`.
//!
//! ⚠ The id is `0x7` on the OPEN carrier and `0x7` is also the PATCH id on the
//! INIT carrier ([`crate::extpatch`]). They are different extensions: an id is
//! only meaningful together with the message it was read from, which is why
//! this reader is fed an Open's chain and never an Init's.
//!
//! ## Who sends it, and so what a wz node receives
//!
//! Upstream sends it only when its bound callback answers `Some`
//! (`io/zenoh-transport/src/unicast/establishment/open.rs`
//! @ `let ext_remote_bound = if let Some(callback) = self.ext_remote_bound.as_ref() {`),
//! and that callback is `compute_transient_bound_of`, which answers `None`
//! under the default `gateway/south` preset (`zenoh/src/net/runtime/region.rs`
//! @ `GatewaySouthConf::Preset(GatewayPresetConf::Auto) => Ok(None),`). So a
//! stock peer sends nothing, and a peer configured with south gateways may.
//!
//! wz sends nothing, and that is upstream's answer for wz's configuration:
//! `gateway/south` is not a key wz honours, so a wz node is always on the
//! `Auto` preset, where the callback answers `None`.
//!
//! NOT-THIS-KEY: gateway/south
//!
//! That marker is load-bearing (R2155, open-debt item 541). This module names
//! the key to say what a wz node SENDS in its absence; the mechanism here is
//! the extension's reader and the region a session lands in, which is not the
//! gateway region-partitioning plane the key configures.
//!
//! ## What a present-but-invalid value does
//!
//! It FAILS the handshake. Both receive arms are
//! `Bound::try_from(ext.value as u8).map_err(|e| (e.into(), Some(close::reason::GENERIC)))?`
//! (`io/zenoh-transport/src/unicast/establishment/accept.rs`
//! @ `other_bound: match open_syn.ext_remote_bound {`, and the `open_ack` twin
//! in `open.rs`). The `as u8` TRUNCATES first, so `256` reads as `0` (north)
//! and is admitted; `2` and `257` are refused.

// R2859 — gated: only the rendered `admin_region` needs an allocator. The
// bound, its read and the region computation are allocation-free and compile
// on the no-alloc MCU profile, which is where this import broke the build.
#[cfg(feature = "alloc")]
use alloc::string::String;
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};

use crate::WhatAmI;

/// `open::ext::RemoteBound`'s header: id `0x7`, Z64, M clear.
pub const REMOTE_BOUND_EXT_HEADER: u8 = 0x07 | crate::ext_header::EXT_ENC_Z64;

/// Which side of a region boundary a remote sits on, as the pin's
/// `zenoh_protocol::core::Bound` (`commons/zenoh-protocol/src/core/region.rs`
/// @ `pub enum Bound {`). The discriminants are the wire values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Bound {
    North = 0,
    South = 1,
}

/// A `RemoteBound` value that is neither bound, after upstream's truncation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidBound(pub u8);

impl Bound {
    /// Upstream's `Bound::try_from(value as u8)`: truncate, then 0 or 1.
    pub fn from_wire(value: u64) -> Result<Self, InvalidBound> {
        match value as u8 {
            0 => Ok(Bound::North),
            1 => Ok(Bound::South),
            other => Err(InvalidBound(other)),
        }
    }

    /// Upstream's `Bound::is_north`.
    pub const fn is_north(self) -> bool {
        matches!(self, Bound::North)
    }

    /// Upstream's `Bound::is_south`.
    pub const fn is_south(self) -> bool {
        matches!(self, Bound::South)
    }
}

/// The bound the peer announced on its Open, `Ok(None)` when it announced
/// none, `Err` when the entry is present and invalid — which must refuse the
/// handshake.
///
/// Matched on the extension IDENTITY ([`crate::ext_header::ext_eid`]), so id
/// `0x7` in another encoding is an unknown extension and is skipped, as
/// upstream's codec skips it.
pub fn peer_remote_bound(extensions: &[ExtEntryOwned]) -> Result<Option<Bound>, InvalidBound> {
    let want = crate::ext_header::ext_eid(REMOTE_BOUND_EXT_HEADER);
    for ext in extensions {
        if crate::ext_header::ext_eid(ext.header) != want {
            continue;
        }
        let ExtEntryOwnedVariant::CodecZenohExtZint(z) = &ext.body else {
            continue;
        };
        return Bound::from_wire(z.value).map(Some);
    }
    Ok(None)
}

/// The region a remote lands in, as the pin's `zenoh_protocol::core::Region`
/// (`commons/zenoh-protocol/src/core/region.rs` @ `pub enum Region {`).
///
/// `Local` is upstream's subregion of in-process sessions; a transport never
/// lands there, so nothing in wz constructs it, and it is kept so the type
/// renders every value upstream's does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Region {
    North,
    Local,
    South { id: usize, mode: WhatAmI },
}

impl Region {
    /// `Region::default_south(mode)`: subregion 0 of that mode.
    pub const fn default_south(mode: WhatAmI) -> Self {
        Region::South { id: 0, mode }
    }

    /// Upstream's `Region::bound`: `North` is the main region, and every
    /// subregion (`Local` included) lies south of it.
    pub const fn bound(&self) -> Bound {
        match self {
            Region::North => Bound::North,
            Region::Local | Region::South { .. } => Bound::South,
        }
    }

    /// Upstream's `Region::mode`: the mode of the nodes a subregion holds.
    /// `None` for `North`, whose hat takes the node's OWN mode instead.
    pub const fn mode(&self) -> Option<WhatAmI> {
        match self {
            Region::North => None,
            Region::Local => Some(WhatAmI::Client),
            Region::South { mode, .. } => Some(*mode),
        }
    }
}

impl core::fmt::Display for Region {
    /// Upstream's `Display`: `north`, `local`, `south:<id>:<mode>`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Region::North => f.write_str("north"),
            Region::Local => f.write_str("local"),
            Region::South { id, mode } => write!(f, "south:{id}:{}", mode.to_str()),
        }
    }
}

/// `compute_auto_region` (`zenoh/src/net/runtime/region.rs`
/// @ `fn compute_auto_region(mode: WhatAmI, remote_mode: WhatAmI) -> ZResult<(Region, Bound)> {`):
/// the region of the remote and the remote's bound, from the two modes alone.
/// `None` is upstream's `bail!` for client-client.
pub(crate) fn auto_region(mode: WhatAmI, remote: WhatAmI) -> Option<(Region, Bound)> {
    use WhatAmI::{Client, Peer, Router};
    match (mode, remote) {
        (Router, Peer | Client) | (Peer, Client) => {
            Some((Region::default_south(remote), Bound::North))
        }
        (Router, Router) | (Peer, Peer) => Some((Region::North, Bound::North)),
        (Peer | Client, Router) | (Client, Peer) => Some((Region::North, Bound::South)),
        (Client, Client) => None,
    }
}

/// The region this node places a unicast remote in: `compute_region_of`
/// (`zenoh/src/net/runtime/region.rs` @ `pub(crate) fn compute_region_of(`)
/// for a node on the `Auto` gateway preset, which is every wz node — its
/// transient region is `None`, so only the first three arms of upstream's
/// match are reachable. `None` is each arm's `bail!`, which upstream's
/// `local_data` renders as `"unknown"`.
pub fn region_of(mode: WhatAmI, remote: WhatAmI, remote_bound: Option<Bound>) -> Option<Region> {
    region_and_bound_of(mode, remote, remote_bound).map(|(region, _)| region)
}

/// `compute_region_of` WHOLE, as its return type is: the region this node
/// places the remote in AND the remote's own bound, which is what the pin's
/// `Gateway::new_transport_unicast` stores on the face
/// (`zenoh/src/net/routing/gateway.rs` @ `pub fn new_transport_unicast(`).
/// R2864 (open-debt item 751) — the routing half of the region model reads
/// both; the adminspace row reads only the first, through [`region_of`].
///
/// Only the three arms an `Auto`-preset node reaches are here, as in
/// [`region_of`]; `None` is each arm's `bail!`.
pub fn region_and_bound_of(
    mode: WhatAmI,
    remote: WhatAmI,
    remote_bound: Option<Bound>,
) -> Option<(Region, Bound)> {
    match remote_bound {
        None => auto_region(mode, remote),
        Some(Bound::South) => Some((Region::North, Bound::South)),
        Some(Bound::North) => match auto_region(mode, remote)? {
            (region, Bound::North) => Some((region, Bound::North)),
            (_, Bound::South) => None,
        },
    }
}

/// The region a node of `mode` puts its multicast transport in:
/// `compute_multicast_region` (`zenoh/src/net/runtime/region.rs`
/// @ `pub(crate) fn compute_multicast_region(`). A peer's group is in its own
/// north region and a router's is in the default south PEER region, where the
/// router's unicast peers are too. `None` is the pin's `bail!` for a client,
/// which has no multicast transport.
pub fn multicast_region(mode: WhatAmI) -> Option<Region> {
    match mode {
        WhatAmI::Peer => Some(Region::North),
        WhatAmI::Router => Some(Region::default_south(WhatAmI::Peer)),
        WhatAmI::Client => None,
    }
}

/// The region a node of `mode` places a MEMBER of its multicast group in, and
/// that member's bound: `compute_multicast_region_of`
/// (`zenoh/src/net/runtime/region.rs` @ `pub(crate) fn compute_multicast_region_of(`).
/// Only the three pairs the pin names are placed; every other pair is its
/// `bail!`, which is `None` here, so a router does not take a router on its
/// group as a member at all.
///
/// A router places a peer member in the same region as [`multicast_region`],
/// and a unicast peer lands there too ([`region_of`]). The routing hat of that
/// region relays to its own faces only what came from another region, so a
/// Put that arrives from a group member is not relayed to the router's
/// unicast peers.
pub fn multicast_region_and_bound_of(mode: WhatAmI, remote: WhatAmI) -> Option<(Region, Bound)> {
    match (mode, remote) {
        (WhatAmI::Peer, WhatAmI::Peer) => Some((Region::North, Bound::North)),
        (WhatAmI::Router, WhatAmI::Peer) => {
            Some((Region::default_south(WhatAmI::Peer), Bound::North))
        }
        (WhatAmI::Peer, WhatAmI::Router) => Some((Region::North, Bound::South)),
        _ => None,
    }
}

/// The interest id a node's peer hat acts as if a new face had sent it
/// (`zenoh/src/net/routing/hat/peer/mod.rs` @ `pub(crate) const INITIAL_INTEREST_ID: u32 = 0;`).
///
/// Nothing is sent: upstream's own comment is that "while no interest is sent on the network,
/// peers act as if they received an interest `CurrentFuture` with id `0` and send back a
/// `DeclareFinal` with interest id `0`". That `DeclareFinal` is what the other end's open waits
/// for: a zenoh peer's open holds until the peer connector this message terminates has done so,
/// which wz does not do for its own open (it does not wait on the node it dialled), and
/// zenoh-pico ends its push to an accepted peer with the same message
/// (`vendor/zenoh-pico/src/session/interest.c` @
/// `_Z_RETURN_IF_ERR(_z_interest_send_declare_final(zn, 0, peer));`).
pub const INITIAL_INTEREST_ID: u64 = 0;

/// Whether a node of role `mode` ends the declarations it sends a new face with the
/// `DeclareFinal` of [`INITIAL_INTEREST_ID`]: upstream's
/// `let do_initial_interest = ctx.src_face.region.bound().is_north() && ctx.src_face.remote_bound.is_north();`
/// (`zenoh/src/net/routing/hat/peer/mod.rs` @ `let do_initial_interest =`), in the PEER hat only,
/// so a router's north hat and a client's never do, whatever the pair.
///
/// "Mutually north-bound" is [`region_and_bound_of`] answering `(North, North)`, which for an
/// `Auto`-preset node is exactly a peer meeting a peer: a peer meeting a router lands north but
/// the router's bound toward it is south (a router holds peers in a south region), and a peer
/// meeting a client holds it in a south region. Every other pair is pull mode, where the face
/// asks with an Interest it puts on the wire and is answered to that.
pub fn sends_initial_interest_final(
    mode: WhatAmI,
    remote: WhatAmI,
    remote_bound: Option<Bound>,
) -> bool {
    mode == WhatAmI::Peer
        && matches!(
            region_and_bound_of(mode, remote, remote_bound),
            Some((Region::North, Bound::North))
        )
}

/// The `sessions[].region` string upstream writes: the region, or
/// `"unknown"` where it cannot be computed
/// (`zenoh/src/net/runtime/adminspace.rs`
/// @ `"region": transport_unicast_to_region(transport).map_or_else(|| "unknown".to_string(), |r| r.to_string())`).
///
/// `alloc`-gated with its only caller (`SessionLinkActions::admin_region`,
/// whose module is itself `alloc`-only).
#[cfg(feature = "alloc")]
pub fn admin_region(mode: WhatAmI, remote: Option<WhatAmI>, remote_bound: Option<Bound>) -> String {
    use core::fmt::Write as _;
    let mut out = String::new();
    match remote.and_then(|r| region_of(mode, r, remote_bound)) {
        Some(region) => {
            let _ = write!(out, "{region}");
        }
        None => out.push_str("unknown"),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_codecs::ext_zint::ExtZint;
    use WhatAmI::{Client, Peer, Router};

    fn z64(header: u8, value: u64) -> ExtEntryOwned {
        ExtEntryOwned {
            header,
            body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint { value }),
        }
    }

    /// Every (mode, remote) pair with no bound announced, against
    /// `compute_auto_region`'s table read at the pin.
    #[test]
    fn with_no_bound_the_region_is_the_auto_table() {
        let south = |m| Some(Region::default_south(m));
        let cases = [
            (Router, Router, Some(Region::North)),
            (Router, Peer, south(Peer)),
            (Router, Client, south(Client)),
            (Peer, Router, Some(Region::North)),
            (Peer, Peer, Some(Region::North)),
            (Peer, Client, south(Client)),
            (Client, Router, Some(Region::North)),
            (Client, Peer, Some(Region::North)),
            (Client, Client, None),
        ];
        for (mode, remote, want) in cases {
            assert_eq!(
                region_of(mode, remote, None),
                want,
                "{mode:?} <- {remote:?}"
            );
        }
    }

    /// A remote that calls us south is in our north, whatever the modes:
    /// `(None, Some(Bound::South)) => Ok((Region::North, Bound::South))`.
    #[test]
    fn a_remote_that_calls_us_south_is_north() {
        for mode in [Router, Peer, Client] {
            for remote in [Router, Peer, Client] {
                assert_eq!(
                    region_of(mode, remote, Some(Bound::South)),
                    Some(Region::North)
                );
            }
        }
    }

    /// A remote that calls us north keeps the auto region only where the auto
    /// preset also calls it north; elsewhere upstream bails.
    #[test]
    fn a_remote_that_calls_us_north_must_agree_with_the_auto_preset() {
        assert_eq!(
            region_of(Router, Client, Some(Bound::North)),
            Some(Region::default_south(Client))
        );
        assert_eq!(
            region_of(Peer, Peer, Some(Bound::North)),
            Some(Region::North)
        );
        assert_eq!(region_of(Client, Router, Some(Bound::North)), None);
        assert_eq!(region_of(Client, Client, Some(Bound::North)), None);
    }

    /// `compute_multicast_region`, one line per mode: a peer's group is north,
    /// a router's is the default south peer region, a client has none.
    #[test]
    fn a_nodes_multicast_group_is_in_the_pins_region() {
        assert_eq!(multicast_region(Peer), Some(Region::North));
        assert_eq!(multicast_region(Router), Some(Region::default_south(Peer)));
        assert_eq!(multicast_region(Client), None);
    }

    /// `compute_multicast_region_of`, every pair: three are placed, the other
    /// six are the pin's `bail!`.
    #[test]
    fn a_multicast_member_is_placed_by_the_pins_three_pairs() {
        let placed = multicast_region_and_bound_of;
        assert_eq!(
            placed(Peer, Peer),
            Some((Region::North, Bound::North)),
            "peer-peer"
        );
        assert_eq!(
            placed(Router, Peer),
            Some((Region::default_south(Peer), Bound::North)),
            "a router's group member is a peer in its south peer region"
        );
        assert_eq!(
            placed(Peer, Router),
            Some((Region::North, Bound::South)),
            "peer-router"
        );
        for (mode, remote) in [
            (Router, Router),
            (Router, Client),
            (Peer, Client),
            (Client, Router),
            (Client, Peer),
            (Client, Client),
        ] {
            assert_eq!(placed(mode, remote), None, "{mode:?} <- {remote:?}");
        }
    }

    /// The group's own region and the region of the member a router places in
    /// it are one region, which is why a member's Put is a Put from the region
    /// the router's unicast peers are in.
    #[test]
    fn a_routers_group_member_shares_the_region_of_its_unicast_peers() {
        let group = multicast_region(Router).expect("a router has a group");
        let (member, _) = multicast_region_and_bound_of(Router, Peer).expect("a peer member");
        let unicast_peer = region_of(Router, Peer, None).expect("a unicast peer");
        assert_eq!(group, member);
        assert_eq!(member, unicast_peer);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn regions_render_as_upstream_displays_them() {
        assert_eq!(admin_region(Peer, Some(Client), None), "south:0:client");
        assert_eq!(admin_region(Router, Some(Peer), None), "south:0:peer");
        assert_eq!(admin_region(Peer, Some(Peer), None), "north");
        assert_eq!(admin_region(Client, Some(Client), None), "unknown");
        assert_eq!(admin_region(Peer, None, None), "unknown");
        assert_eq!(alloc::format!("{}", Region::Local), "local");
    }

    /// Absent, both bounds, upstream's truncation, and the refusal.
    #[test]
    fn the_bound_is_read_as_upstream_reads_it() {
        assert_eq!(peer_remote_bound(&[]), Ok(None));
        assert_eq!(
            peer_remote_bound(&[z64(REMOTE_BOUND_EXT_HEADER, 0)]),
            Ok(Some(Bound::North))
        );
        assert_eq!(
            peer_remote_bound(&[z64(REMOTE_BOUND_EXT_HEADER, 1)]),
            Ok(Some(Bound::South))
        );
        assert_eq!(
            peer_remote_bound(&[z64(REMOTE_BOUND_EXT_HEADER, 256)]),
            Ok(Some(Bound::North)),
            "`ext.value as u8` truncates 256 to 0"
        );
        assert_eq!(
            peer_remote_bound(&[z64(REMOTE_BOUND_EXT_HEADER, 2)]),
            Err(InvalidBound(2))
        );
    }

    /// Id `0x7` in another encoding is a different extension.
    #[test]
    fn another_encoding_on_id_seven_is_not_the_bound() {
        let unit = ExtEntryOwned {
            header: 0x07,
            body: ExtEntryOwnedVariant::CodecZenohExtUnit(Default::default()),
        };
        assert_eq!(peer_remote_bound(&[unit]), Ok(None));
    }

    #[test]
    fn the_header_is_id_seven_z64_and_not_mandatory() {
        assert_eq!(crate::ext_header::ext_id(REMOTE_BOUND_EXT_HEADER), 0x07);
        assert!(!crate::ext_header::ext_mandatory(REMOTE_BOUND_EXT_HEADER));
    }

    /// R2864 — `Region::bound` / `Region::mode` as the pin writes them: only
    /// `North` is north, and `Local` is a CLIENT subregion.
    #[test]
    fn a_region_knows_its_bound_and_mode_as_upstream_does() {
        assert_eq!(Region::North.bound(), Bound::North);
        assert_eq!(Region::Local.bound(), Bound::South);
        assert_eq!(Region::default_south(Router).bound(), Bound::South);
        assert_eq!(Region::North.mode(), None);
        assert_eq!(Region::Local.mode(), Some(Client));
        assert_eq!(Region::South { id: 3, mode: Peer }.mode(), Some(Peer));
        assert!(Bound::North.is_north() && !Bound::North.is_south());
        assert!(Bound::South.is_south() && !Bound::South.is_north());
    }

    /// R2864 — the remote bound `compute_region_of` returns alongside the
    /// region, for every pair of modes and every announced bound, and the
    /// region half is exactly [`region_of`].
    #[test]
    fn the_remote_bound_is_returned_with_the_region() {
        // The Auto table's bound column (`compute_auto_region`).
        assert_eq!(
            region_and_bound_of(Router, Peer, None),
            Some((Region::default_south(Peer), Bound::North))
        );
        assert_eq!(
            region_and_bound_of(Router, Router, None),
            Some((Region::North, Bound::North))
        );
        assert_eq!(
            region_and_bound_of(Peer, Router, None),
            Some((Region::North, Bound::South))
        );
        assert_eq!(
            region_and_bound_of(Client, Peer, None),
            Some((Region::North, Bound::South))
        );
        // A remote that calls us south is north of us, and says so.
        assert_eq!(
            region_and_bound_of(Router, Peer, Some(Bound::South)),
            Some((Region::North, Bound::South))
        );
        for mode in [Router, Peer, Client] {
            for remote in [Router, Peer, Client] {
                for bound in [None, Some(Bound::North), Some(Bound::South)] {
                    assert_eq!(
                        region_and_bound_of(mode, remote, bound).map(|(r, _)| r),
                        region_of(mode, remote, bound),
                        "{mode:?} placing {remote:?} announcing {bound:?}"
                    );
                }
            }
        }
    }

    /// R3073 -- the initial interest is the PEER hat's, and only between two north-bound nodes.
    /// Written as the whole table of nine pairs for each of the three bounds a remote can
    /// announce, so a pair that gained the message by accident is a failing row and not a
    /// silent addition.
    #[test]
    fn only_a_peer_meeting_a_north_bound_peer_ends_its_declarations_with_the_final() {
        for mode in [Router, Peer, Client] {
            for remote in [Router, Peer, Client] {
                for bound in [None, Some(Bound::North), Some(Bound::South)] {
                    let want = mode == Peer && remote == Peer && bound != Some(Bound::South);
                    assert_eq!(
                        sends_initial_interest_final(mode, remote, bound),
                        want,
                        "{mode:?} meeting {remote:?} announcing {bound:?}"
                    );
                }
            }
        }
        assert_eq!(INITIAL_INTEREST_ID, 0, "upstream's `INITIAL_INTEREST_ID`");
    }
}
