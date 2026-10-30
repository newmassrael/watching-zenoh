//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-protocol 1.10.2, file
// src/core/whatami.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

//! What a node is in a zenoh network, and a set of what a scout looks for.

use alloc::string::String;
use core::{convert::TryFrom, fmt, num::NonZeroU8, ops::BitOr, str::FromStr};

use const_format::formatcp;
use serde::ser::SerializeSeq;
use zenoh_result::{bail, ZError};

/// The type of the node in the Zenoh network.
///
/// The zenoh application can work in three different modes: router, peer, and client.
///
/// In the peer mode the application searches for other nodes and establishes direct connections
/// with them. This can work using multicast discovery and by getting gossip information
/// from the initial entry points. The peer mode is the default mode.
///
/// In the client mode the application remains connected to a single connection point, which
/// serves as a gateway to the rest of the network. This mode is useful for constrained
/// devices that cannot afford to maintain multiple connections.
///
/// The router mode is used to run a zenoh router, which is a node that
/// maintains a predefined zenoh network topology. Unlike peers, routers do not
/// discover other nodes by themselves, but rely on static configuration.
///
/// A more detailed explanation of each mode is at [Zenoh Documentation](https://zenoh.io/docs/getting-started/deployment/)
#[repr(u8)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WhatAmI {
    Router = 0b001,
    #[default]
    Peer = 0b010,
    Client = 0b100,
}

impl WhatAmI {
    const STR_R: &'static str = "router";
    const STR_P: &'static str = "peer";
    const STR_C: &'static str = "client";

    const U8_R: u8 = Self::Router as u8;
    const U8_P: u8 = Self::Peer as u8;
    const U8_C: u8 = Self::Client as u8;

    pub const fn to_str(self) -> &'static str {
        match self {
            Self::Router => Self::STR_R,
            Self::Peer => Self::STR_P,
            Self::Client => Self::STR_C,
        }
    }

    #[cfg(feature = "test")]
    #[doc(hidden)]
    pub fn rand() -> Self {
        use rand::prelude::SliceRandom;
        let mut rng = rand::thread_rng();

        *[Self::Router, Self::Peer, Self::Client]
            .choose(&mut rng)
            .unwrap()
    }

    pub const fn is_client(self) -> bool {
        matches!(self, WhatAmI::Client)
    }

    pub const fn is_peer(self) -> bool {
        matches!(self, WhatAmI::Peer)
    }

    pub const fn is_router(self) -> bool {
        matches!(self, WhatAmI::Router)
    }
}

impl TryFrom<u8> for WhatAmI {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            Self::U8_R => Ok(Self::Router),
            Self::U8_P => Ok(Self::Peer),
            Self::U8_C => Ok(Self::Client),
            _ => Err(()),
        }
    }
}

impl FromStr for WhatAmI {
    type Err = ZError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::STR_R => Ok(Self::Router),
            Self::STR_P => Ok(Self::Peer),
            Self::STR_C => Ok(Self::Client),
            _ => bail!(
                "{s} is not a valid WhatAmI value. Valid values are: {}, {}, {}.",
                Self::STR_R,
                Self::STR_P,
                Self::STR_C
            ),
        }
    }
}

impl fmt::Display for WhatAmI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_str())
    }
}

impl From<WhatAmI> for u8 {
    fn from(w: WhatAmI) -> Self {
        w as u8
    }
}

/// The value of a `WhatAmIMatcher` with the bits of `bits` set that are in the matcher's range
/// and the marker bit set, which is what makes it non-zero. A `const fn` cannot unwrap an option
/// on every toolchain the crate builds with, so the one non-zero value is picked by a `match`.
const fn matcher_bits(bits: u8) -> NonZeroU8 {
    match NonZeroU8::new(WhatAmIMatcher::U8_0 | (bits & WhatAmIMatcher::VALID)) {
        Some(value) => value,
        None => unreachable!(),
    }
}

/// A helper type that allows matching combinations of `WhatAmI` values in scouting.
///
/// The [`scout`](crate::scouting::scout) function accepts a `WhatAmIMatcher` to filter the nodes
/// of the specified types. The `WhatAmIMatcher` can be constructed from [`WhatAmI`] values
/// with the `|` operator
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WhatAmIMatcher(NonZeroU8);

impl WhatAmIMatcher {
    // We use the 7th bit for detecting whether the WhatAmIMatcher is non-zero
    const U8_0: u8 = 1 << 7;
    /// The bits a matcher may hold besides the marker: one for each `WhatAmI`.
    const VALID: u8 = WhatAmI::U8_R | WhatAmI::U8_P | WhatAmI::U8_C;
    const U8_R: u8 = Self::U8_0 | WhatAmI::U8_R;
    const U8_P: u8 = Self::U8_0 | WhatAmI::U8_P;
    const U8_C: u8 = Self::U8_0 | WhatAmI::U8_C;
    const U8_R_P: u8 = Self::U8_0 | WhatAmI::U8_R | WhatAmI::U8_P;
    const U8_P_C: u8 = Self::U8_0 | WhatAmI::U8_P | WhatAmI::U8_C;
    const U8_R_C: u8 = Self::U8_0 | WhatAmI::U8_R | WhatAmI::U8_C;
    const U8_R_P_C: u8 = Self::U8_0 | WhatAmI::U8_R | WhatAmI::U8_P | WhatAmI::U8_C;

    /// Creates an empty `WhatAmIMatcher`, which matches no `WhatAmI` values.
    pub const fn empty() -> Self {
        Self(matcher_bits(0))
    }

    /// Creates a `WhatAmIMatcher` matching all [`WhatAmI::Router`] values.
    pub const fn router(self) -> Self {
        Self(matcher_bits(self.0.get() | Self::U8_R))
    }

    /// Creates a `WhatAmIMatcher` matching all [`WhatAmI::Peer`] values.
    pub const fn peer(self) -> Self {
        Self(matcher_bits(self.0.get() | Self::U8_P))
    }

    /// Creates a `WhatAmIMatcher` matching all [`WhatAmI::Client`] values.
    pub const fn client(self) -> Self {
        Self(matcher_bits(self.0.get() | Self::U8_C))
    }

    /// Returns whether the `WhatAmIMatcher` is empty.
    pub const fn is_empty(&self) -> bool {
        self.0.get() == Self::U8_0
    }

    /// Returns whether the `WhatAmIMatcher` matches the given `WhatAmI` value.
    pub const fn matches(&self, w: WhatAmI) -> bool {
        (self.0.get() & w as u8) != 0
    }

    /// Returns a string representation of the `WhatAmIMatcher` as a combination of
    /// `WhatAmI` string representations separated by `|`.
    pub const fn to_str(self) -> &'static str {
        match self.0.get() {
            Self::U8_0 => "",
            Self::U8_R => WhatAmI::STR_R,
            Self::U8_P => WhatAmI::STR_P,
            Self::U8_C => WhatAmI::STR_C,
            Self::U8_R_P => formatcp!("{}|{}", WhatAmI::STR_R, WhatAmI::STR_P),
            Self::U8_R_C => formatcp!("{}|{}", WhatAmI::STR_R, WhatAmI::STR_C),
            Self::U8_P_C => formatcp!("{}|{}", WhatAmI::STR_P, WhatAmI::STR_C),
            Self::U8_R_P_C => formatcp!("{}|{}|{}", WhatAmI::STR_R, WhatAmI::STR_P, WhatAmI::STR_C),

            // No constructor makes another value: `|` with an integer drops the bits that are
            // not a `WhatAmI`'s.
            _ => unreachable!(),
        }
    }

    #[cfg(feature = "test")]
    #[doc(hidden)]
    pub fn rand() -> Self {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let mut waim = WhatAmIMatcher::empty();
        if rng.gen_bool(0.5) {
            waim = waim.router();
        }
        if rng.gen_bool(0.5) {
            waim = waim.peer();
        }
        if rng.gen_bool(0.5) {
            waim = waim.client();
        }
        waim
    }
}

impl TryFrom<u8> for WhatAmIMatcher {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        if v <= Self::VALID {
            Ok(WhatAmIMatcher(matcher_bits(v)))
        } else {
            Err(())
        }
    }
}

impl FromStr for WhatAmIMatcher {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut inner = 0;
        for s in s.split('|') {
            match s.trim() {
                "" => {}
                WhatAmI::STR_R => inner |= WhatAmI::U8_R,
                WhatAmI::STR_P => inner |= WhatAmI::U8_P,
                WhatAmI::STR_C => inner |= WhatAmI::U8_C,
                _ => return Err(()),
            }
        }
        Self::try_from(inner)
    }
}

impl fmt::Display for WhatAmIMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_str())
    }
}

impl From<WhatAmIMatcher> for u8 {
    fn from(w: WhatAmIMatcher) -> u8 {
        w.0.get()
    }
}

/// `matcher | bits`: the union of the matcher and what the integer names. Bits that are not one of
/// the three `WhatAmI` are dropped (upstream keeps them, and then `to_str` panics).
impl<T> BitOr<T> for WhatAmIMatcher
where
    NonZeroU8: BitOr<T, Output = NonZeroU8>,
{
    type Output = Self;

    fn bitor(self, rhs: T) -> Self::Output {
        WhatAmIMatcher(matcher_bits((self.0 | rhs).get()))
    }
}

impl BitOr<WhatAmI> for WhatAmIMatcher {
    type Output = Self;

    fn bitor(self, rhs: WhatAmI) -> Self::Output {
        self | rhs as u8
    }
}

impl BitOr for WhatAmIMatcher {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        self | rhs.0
    }
}

impl BitOr for WhatAmI {
    type Output = WhatAmIMatcher;

    fn bitor(self, rhs: Self) -> Self::Output {
        WhatAmIMatcher(matcher_bits(self as u8 | rhs as u8))
    }
}

impl From<WhatAmI> for WhatAmIMatcher {
    fn from(w: WhatAmI) -> Self {
        WhatAmIMatcher(matcher_bits(w as u8))
    }
}

// Serde
impl serde::Serialize for WhatAmI {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_str())
    }
}

#[derive(Debug)]
pub struct WhatAmIVisitor;

impl<'de> serde::de::Visitor<'de> for WhatAmIVisitor {
    type Value = WhatAmI;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "either '{}', '{}' or '{}'",
            WhatAmI::STR_R,
            WhatAmI::STR_P,
            WhatAmI::STR_C
        )
    }
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        v.parse().map_err(|_| {
            serde::de::Error::unknown_variant(v, &[WhatAmI::STR_R, WhatAmI::STR_P, WhatAmI::STR_C])
        })
    }
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(v)
    }
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&v)
    }
}

impl<'de> serde::Deserialize<'de> for WhatAmI {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(WhatAmIVisitor)
    }
}

impl serde::Serialize for WhatAmIMatcher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let values = [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client]
            .iter()
            .filter(|v| self.matches(**v));
        let mut seq = serializer.serialize_seq(Some(values.clone().count()))?;
        for v in values {
            seq.serialize_element(v)?;
        }
        seq.end()
    }
}

#[derive(Debug)]
pub struct WhatAmIMatcherVisitor;
impl<'de> serde::de::Visitor<'de> for WhatAmIMatcherVisitor {
    type Value = WhatAmIMatcher;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "a list of whatami variants ('{}', '{}', '{}')",
            WhatAmI::STR_R,
            WhatAmI::STR_P,
            WhatAmI::STR_C
        )
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut inner = 0;

        while let Some(s) = seq.next_element::<String>()? {
            match s.as_str() {
                WhatAmI::STR_R => inner |= WhatAmI::U8_R,
                WhatAmI::STR_P => inner |= WhatAmI::U8_P,
                WhatAmI::STR_C => inner |= WhatAmI::U8_C,
                _ => {
                    return Err(serde::de::Error::invalid_value(
                        serde::de::Unexpected::Str(&s),
                        &formatcp!(
                            "one of ('{}', '{}', '{}')",
                            WhatAmI::STR_R,
                            WhatAmI::STR_P,
                            WhatAmI::STR_C
                        ),
                    ))
                }
            }
        }

        Ok(WhatAmIMatcher::try_from(inner)
            .expect("`WhatAmIMatcher` should be valid by construction"))
    }
}

impl<'de> serde::Deserialize<'de> for WhatAmIMatcher {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(WhatAmIMatcherVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_matcher_is_the_union_of_what_it_was_given() {
        let m = WhatAmI::Router | WhatAmI::Client;
        assert!(
            m.matches(WhatAmI::Router) && m.matches(WhatAmI::Client) && !m.matches(WhatAmI::Peer)
        );
        assert_eq!(m.to_str(), "router|client");
        assert!(WhatAmIMatcher::empty().is_empty() && WhatAmIMatcher::empty().to_str().is_empty());
        let all = WhatAmIMatcher::empty().router().peer().client();
        assert_eq!((all.to_str(), u8::from(all)), ("router|peer|client", 0x87));
        assert_eq!(all, m | WhatAmI::Peer);
    }

    #[test]
    fn a_matcher_is_parsed_and_converted() {
        assert_eq!(
            "router | peer".parse::<WhatAmIMatcher>().unwrap().to_str(),
            "router|peer"
        );
        assert!("".parse::<WhatAmIMatcher>().unwrap().is_empty());
        assert!("router|mystery".parse::<WhatAmIMatcher>().is_err());
        assert!(WhatAmIMatcher::try_from(7).is_ok() && WhatAmIMatcher::try_from(8).is_err());
        assert_eq!(WhatAmI::try_from(2), Ok(WhatAmI::Peer));
        assert!(WhatAmI::try_from(3).is_err());
        assert_eq!(u8::from(WhatAmI::Client), 4);
        assert!("gateway"
            .parse::<WhatAmI>()
            .unwrap_err()
            .to_string()
            .contains("not a valid WhatAmI"));
    }

    #[test]
    fn or_with_an_integer_drops_what_is_not_a_node_kind() {
        let m = WhatAmIMatcher::empty() | 0xFFu8;
        assert_eq!(m.to_str(), "router|peer|client");
        assert_eq!(
            WhatAmIMatcher::from(WhatAmI::Peer) | WhatAmI::Client,
            WhatAmI::Peer | WhatAmI::Client
        );
    }
}
