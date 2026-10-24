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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-protocol 1.10.1, file
// src/scouting/mod.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

//! The scouting messages: how a node looks for the others, and how it answers.

pub mod hello;
pub mod scout;

pub use hello::HelloProto;
pub use scout::Scout;

pub mod id {
    // Scouting Messages
    pub const SCOUT: u8 = 0x01;
    pub const HELLO: u8 = 0x02;
}

// Zenoh messages at scouting level
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScoutingBody {
    Scout(Scout),
    Hello(HelloProto),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoutingMessage {
    pub body: ScoutingBody,
}

impl ScoutingMessage {
    #[cfg(feature = "test")]
    #[doc(hidden)]
    pub fn rand() -> Self {
        use rand::Rng;

        let mut rng = rand::thread_rng();

        match rng.gen_range(0..2) {
            0 => ScoutingBody::Scout(Scout::rand()),
            1 => ScoutingBody::Hello(HelloProto::rand()),
            _ => unreachable!(),
        }
        .into()
    }
}

impl From<ScoutingBody> for ScoutingMessage {
    fn from(body: ScoutingBody) -> Self {
        Self { body }
    }
}

impl From<Scout> for ScoutingMessage {
    fn from(scout: Scout) -> Self {
        ScoutingBody::Scout(scout).into()
    }
}

impl From<HelloProto> for ScoutingMessage {
    fn from(hello: HelloProto) -> Self {
        ScoutingBody::Hello(hello).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{WhatAmI, WhatAmIMatcher, ZenohIdProto};

    #[test]
    fn a_message_wraps_either_body_and_converts_from_each() {
        let scout = Scout {
            version: 9,
            what: WhatAmI::Router | WhatAmI::Peer,
            zid: None,
        };
        let hello = HelloProto {
            version: 9,
            whatami: WhatAmI::Client,
            zid: "ab".parse::<ZenohIdProto>().unwrap(),
            locators: vec!["tcp/localhost:7447".parse().unwrap()],
        };
        assert_eq!(
            ScoutingMessage::from(scout.clone()).body,
            ScoutingBody::Scout(scout)
        );
        assert_eq!(
            ScoutingMessage::from(hello.clone()).body,
            ScoutingBody::Hello(hello)
        );
        assert_eq!((id::SCOUT, id::HELLO), (1, 2));
        assert_eq!(
            (
                scout::flag::I,
                scout::flag::Z,
                hello::flag::L,
                hello::flag::Z
            ),
            (8, 128, 32, 128)
        );
        assert!(WhatAmIMatcher::empty().is_empty());
    }
}
