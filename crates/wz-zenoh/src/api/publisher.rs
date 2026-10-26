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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh 1.10.1, file
// src/api/publisher.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1). Only the priority of a
// message is here, which the sample and the quality of service read; the publisher, its
// undeclaration, its sink, and the two tests that open a session, arrive with slice Z2 of
// docs/zenoh-api-on-the-engine.md.

use std::convert::TryFrom;

use serde::Deserialize;
use zenoh_config::qos::PriorityConf;

/// Message priority.
///
/// If QoS is enabled in the [`Config`](crate::config::Config) (see the boolean
/// `transport.<transport_type>.qos` parameter),
/// Zenoh keeps one transmission queue per [`Priority`], where all messages in
/// the queue have the same [`Priority`]. These queues are serviced in the order of their assigned
/// [`Priority`] (i.e. from [`Priority::RealTime`] to [`Priority::Background`]).
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Hash, Deserialize)]
#[repr(u8)]
pub enum Priority {
    RealTime = 1,
    InteractiveHigh = 2,
    InteractiveLow = 3,
    DataHigh = 4,
    #[default]
    Data = 5,
    DataLow = 6,
    Background = 7,
}

impl Priority {
    /// Default
    pub const DEFAULT: Self = Self::Data;
    /// The lowest Priority
    #[zenoh_macros::internal]
    pub const MIN: Self = Self::MIN_;
    const MIN_: Self = Self::Background;
    /// The highest Priority
    #[zenoh_macros::internal]
    pub const MAX: Self = Self::MAX_;
    const MAX_: Self = Self::RealTime;
    /// The number of available priorities
    #[zenoh_macros::internal]
    pub const NUM: usize = 1 + Self::MIN_ as usize - Self::MAX_ as usize;
}

impl TryFrom<u8> for Priority {
    type Error = zenoh_result::Error;

    /// A Priority is identified by a numeric value.
    /// The lower the value, the higher the priority.
    /// The higher the value, the lower the priority.
    ///
    /// Allowed values are: 1-7.
    ///
    /// Highest priority: 1
    /// Lowest priority: 7
    fn try_from(priority: u8) -> Result<Self, Self::Error> {
        match priority {
            1 => Ok(Priority::RealTime),
            2 => Ok(Priority::InteractiveHigh),
            3 => Ok(Priority::InteractiveLow),
            4 => Ok(Priority::DataHigh),
            5 => Ok(Priority::Data),
            6 => Ok(Priority::DataLow),
            7 => Ok(Priority::Background),
            unknown => bail!(
                "{} is not a valid priority value. Admitted values are: [{}-{}].",
                unknown,
                Self::MAX_ as u8,
                Self::MIN_ as u8
            ),
        }
    }
}

impl From<PriorityConf> for Priority {
    fn from(value: PriorityConf) -> Self {
        match value {
            PriorityConf::RealTime => Self::RealTime,
            PriorityConf::InteractiveHigh => Self::InteractiveHigh,
            PriorityConf::InteractiveLow => Self::InteractiveLow,
            PriorityConf::DataHigh => Self::DataHigh,
            PriorityConf::Data => Self::Data,
            PriorityConf::DataLow => Self::DataLow,
            PriorityConf::Background => Self::Background,
        }
    }
}

impl From<Priority> for PriorityConf {
    fn from(value: Priority) -> Self {
        match value {
            Priority::RealTime => Self::RealTime,
            Priority::InteractiveHigh => Self::InteractiveHigh,
            Priority::InteractiveLow => Self::InteractiveLow,
            Priority::DataHigh => Self::DataHigh,
            Priority::Data => Self::Data,
            Priority::DataLow => Self::DataLow,
            Priority::Background => Self::Background,
        }
    }
}

type ProtocolPriority = zenoh_protocol::core::Priority;
impl From<Priority> for ProtocolPriority {
    fn from(prio: Priority) -> Self {
        // The Priority in the prelude differs from the Priority in the core protocol only by
        // the missing Control priority. The Control priority is reserved for zenoh's internal use
        // and as such it is not exposed by the zenoh API. Nevertheless, the values of the
        // priorities which are common to the internal and public Priority enums are the same. Therefore,
        // it is possible to safely transmute from the public Priority enum toward the internal
        // Priority enum without risking being in an invalid state.
        // For better robustness, the correctness of the unsafe transmute operation is covered
        // by the unit test below.
        unsafe { std::mem::transmute::<Priority, zenoh_protocol::core::Priority>(prio) }
    }
}

impl TryFrom<ProtocolPriority> for Priority {
    type Error = zenoh_result::Error;
    fn try_from(priority: ProtocolPriority) -> Result<Self, Self::Error> {
        match priority {
            ProtocolPriority::Control => bail!("'Control' is not a valid priority value."),
            ProtocolPriority::RealTime => Ok(Priority::RealTime),
            ProtocolPriority::InteractiveHigh => Ok(Priority::InteractiveHigh),
            ProtocolPriority::InteractiveLow => Ok(Priority::InteractiveLow),
            ProtocolPriority::DataHigh => Ok(Priority::DataHigh),
            ProtocolPriority::Data => Ok(Priority::Data),
            ProtocolPriority::DataLow => Ok(Priority::DataLow),
            ProtocolPriority::Background => Ok(Priority::Background),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "internal")]
    #[test]
    fn priority_from() {
        use std::convert::TryInto;

        use zenoh_protocol::core::Priority as TPrio;

        use super::Priority as APrio;

        for i in APrio::MAX as u8..=APrio::MIN as u8 {
            let p: APrio = i.try_into().unwrap();

            match p {
                APrio::RealTime => assert_eq!(p as u8, TPrio::RealTime as u8),
                APrio::InteractiveHigh => assert_eq!(p as u8, TPrio::InteractiveHigh as u8),
                APrio::InteractiveLow => assert_eq!(p as u8, TPrio::InteractiveLow as u8),
                APrio::DataHigh => assert_eq!(p as u8, TPrio::DataHigh as u8),
                APrio::Data => assert_eq!(p as u8, TPrio::Data as u8),
                APrio::DataLow => assert_eq!(p as u8, TPrio::DataLow as u8),
                APrio::Background => assert_eq!(p as u8, TPrio::Background as u8),
            }

            let t: TPrio = p.into();
            assert_eq!(p as u8, t as u8);
        }
    }
}
