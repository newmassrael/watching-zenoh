// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

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
