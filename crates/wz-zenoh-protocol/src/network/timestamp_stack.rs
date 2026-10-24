// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

use alloc::vec::Vec;

pub const MAX_STACK_SIZE: usize = 255;

/// Zenoh extension wrapper for the timestamp stack.
///
/// The `const ID: u8` parameter encodes the extension's wire ID, ensuring
/// type-safety across different message contexts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsStackType<const ID: u8> {
    pub ts_stack: TimestampStack,
}

impl<const ID: u8> TsStackType<{ ID }> {
    #[cfg(feature = "test")]
    #[doc(hidden)]
    pub fn rand() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let conf_flags: u8 = rng.gen_range(1..=7);
        let n: usize = rng.gen_range(0..=3);
        let mut stack = Vec::with_capacity(n);
        let points = [
            interception_point::SEND,
            interception_point::ROUTE,
            interception_point::RECEIVE,
        ];
        for _ in 0..n {
            let point = points[rng.gen_range(0..points.len())];
            let is_custom = rng.gen_bool(0.5);
            let flags = point
                | if is_custom {
                    interception_point::IS_CUSTOM_TS
                } else {
                    0
                };
            let ts_len: usize = rng.gen_range(0..=16);
            let timestamp: Vec<u8> = (0..ts_len).map(|_| rng.gen()).collect();
            stack.push(Interception { flags, timestamp });
        }

        Self {
            ts_stack: TimestampStack { conf_flags, stack },
        }
    }
}

/// Bitmask flags indicating which interception points are activated in a timestamp stack.
pub mod interception_point {
    pub const SEND: u8 = 0b0000_0001;
    pub const ROUTE: u8 = 0b0000_0010;
    pub const RECEIVE: u8 = 0b0000_0100;

    /// Bit 7 of the `Interception.flags` field: set when the timestamp was produced by a
    /// user-defined callback (custom format), cleared when it is a standard UHLC timestamp.
    pub const IS_CUSTOM_TS: u8 = 0b1000_0000;
}

/// A single interception record containing the interception point identifier,
/// timestamp format flag, and raw timestamp bytes.
///
/// ```text
/// Flags:
/// - U:     User-defined               If U==1 then the timestamp format is user-defined;
///                                     otherwise it is a standard UHLC timestamp.
/// - X:     Reserved                   Must be 0.
/// - point: Interception point         0b001=SEND, 0b010=ROUTE, 0b100=RECEIVE.
///
///  7 6 5 4 3 2 1 0
/// +-+-+-+-+-+-+-+-+
/// |U|X|X|X|X|point|
/// +---------------+
/// ~   timestamp   ~
/// +---------------+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interception {
    /// Bitfield: interception point id + timestamp format.
    pub flags: u8,
    /// Raw timestamp bytes (format defined by `flags`).
    pub timestamp: Vec<u8>,
}

/// A stack of interception timestamps carried as a message extension.
///
/// ```text
/// Flags:
/// - S: Send            If S==1 then the send interception point is activated.
/// - R: Route           If R==1 then the route interception point is activated.
/// - E: Receive         If E==1 then the receive interception point is activated.
/// - X: Reserved
///  7 6 5 4 3 2 1 0
/// +-+-+-+-+-+-+-+-+
/// |X|X|X|X|X|E|R|S|
/// +---------------+
/// ~  count: zint   ~
/// +---------------+
/// ~ [Interception] ~
/// +---------------+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampStack {
    /// Bitmask of which interception points are activated.
    pub conf_flags: u8,
    /// Ordered list of interceptions collected along the message path.
    pub stack: Vec<Interception>,
}
