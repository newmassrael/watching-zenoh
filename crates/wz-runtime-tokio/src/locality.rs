// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R223 — zenoh-style locality filter for subscribers and queryables.
//!
//! Mirrors zenoh-pico's `z_locality_t`
//! (`vendor/zenoh-pico/include/zenoh-pico/api/constants.h` lines
//! 65-69) and the two `_z_locality_allows_local` /
//! `_z_locality_allows_remote` helpers
//! (`vendor/zenoh-pico/include/zenoh-pico/utils/locality.h` lines
//! 20-40). The semantics are:
//!
//! * [`Locality::Any`] (`Z_LOCALITY_ANY = 0`, default) — fire the
//!   callback for both session-local and remote-origin samples.
//! * [`Locality::SessionLocal`] (`Z_LOCALITY_SESSION_LOCAL = 1`) —
//!   fire only for samples published within the same session.
//! * [`Locality::Remote`] (`Z_LOCALITY_REMOTE = 2`) — fire only for
//!   samples that arrived over the wire from another peer.
//!
//! ## wz dispatch invariant (R223 surface scope)
//!
//! `SubscriberRegistry::dispatch_push` and
//! `QueryableRegistry::dispatch_request` only see records that have
//! already been parsed off the wire — wz does not yet implement
//! local-publish loopback (an application that calls a publisher
//! API does not also see its own sample go through its own
//! subscriber registry). Therefore every record reaching dispatch
//! is "remote" in zenoh-pico's `is_remote=true` sense, and the
//! locality check reduces to [`Locality::allows_remote`].
//!
//! A [`Locality::SessionLocal`]-only subscription registered today
//! will not fire at all. This is the correct partial-implementation
//! shape — the surface matches zenoh-pico so applications written
//! against the canonical API compile against wz, and the local
//! path activates the moment a future round wires up self-publish
//! loopback (carry: not in any current cluster).

/// Locality filter applied to inbound samples before subscriber /
/// queryable callbacks fire.
///
/// Mirrors zenoh-pico's `z_locality_t` enum. Numeric values match
/// (`Any=0`, `SessionLocal=1`, `Remote=2`) so any future wire-side
/// extension that carries the locality byte on a SubInfo extension
/// can serialize via `as u8` without a translation layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Locality {
    /// Allow both session-local and remote-origin samples. zenoh-pico:
    /// `Z_LOCALITY_ANY`. The default for every register call.
    #[default]
    Any = 0,
    /// Allow only samples published within the same session. zenoh-pico:
    /// `Z_LOCALITY_SESSION_LOCAL`. Currently dormant in wz (see module
    /// doc — no self-publish loopback yet).
    SessionLocal = 1,
    /// Allow only samples that arrived over the wire from a remote
    /// peer. zenoh-pico: `Z_LOCALITY_REMOTE`. For wz today this is
    /// equivalent to [`Locality::Any`] since all inbound traffic is
    /// remote, but the two are kept distinct so a future self-publish
    /// loopback round can correctly suppress local-origin samples.
    Remote = 2,
}

impl Locality {
    /// Whether this locality permits firing on a session-local
    /// sample. Mirrors `_z_locality_allows_local`.
    pub fn allows_local(self) -> bool {
        !matches!(self, Locality::Remote)
    }

    /// Whether this locality permits firing on a remote-origin
    /// sample. Mirrors `_z_locality_allows_remote`.
    pub fn allows_remote(self) -> bool {
        !matches!(self, Locality::SessionLocal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_any() {
        assert_eq!(Locality::default(), Locality::Any);
    }

    #[test]
    fn allows_local_truth_table() {
        assert!(Locality::Any.allows_local());
        assert!(Locality::SessionLocal.allows_local());
        assert!(!Locality::Remote.allows_local());
    }

    #[test]
    fn allows_remote_truth_table() {
        assert!(Locality::Any.allows_remote());
        assert!(!Locality::SessionLocal.allows_remote());
        assert!(Locality::Remote.allows_remote());
    }

    #[test]
    fn numeric_repr_matches_zenoh_pico() {
        // zenoh-pico constants.h:
        //   Z_LOCALITY_ANY = 0
        //   Z_LOCALITY_SESSION_LOCAL = 1
        //   Z_LOCALITY_REMOTE = 2
        assert_eq!(Locality::Any as u8, 0);
        assert_eq!(Locality::SessionLocal as u8, 1);
        assert_eq!(Locality::Remote as u8, 2);
    }
}
