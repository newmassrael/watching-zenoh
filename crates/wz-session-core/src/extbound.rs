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
fn auto_region(mode: WhatAmI, remote: WhatAmI) -> Option<(Region, Bound)> {
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
    match remote_bound {
        None => auto_region(mode, remote).map(|(region, _)| region),
        Some(Bound::South) => Some(Region::North),
        Some(Bound::North) => match auto_region(mode, remote)? {
            (region, Bound::North) => Some(region),
            (_, Bound::South) => None,
        },
    }
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
}
