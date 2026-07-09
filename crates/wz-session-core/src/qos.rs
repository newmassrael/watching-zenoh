// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ec — QoS packed-byte value types (`Priority` +
//! `CongestionControl`) lifted from `wz-runtime-tokio::session_glue`.
//!
//! These are the two enum components of the zenoh-pico qos packed byte
//! (`_z_n_qos_create` at network.h:84-89) that were not yet migrated —
//! the third, [`crate::reliability::Reliability`], already lives here.
//! Both are pure value types (no_std + no_alloc, `const` wire helpers),
//! so they belong on the runtime-agnostic side: an MCU profile builds a
//! `Request(Query)` with the same typed QoS API as the tokio AP profile.
//! The first DP3 leaf extracted out of `session_glue.rs` toward the
//! runtime-agnostic Session/actions split; `session_glue.rs` keeps a
//! `pub use` re-export so the `crate::session_glue::{Priority,
//! CongestionControl}` callsites (RequestQueryBuilder + tests) resolve
//! unchanged.

/// R121j-1h — mirror of zenoh-pico's `z_priority_t` enum at
/// `vendor/zenoh-pico/include/zenoh-pico/api/constants.h:241-251`.
/// 8 priorities, 0..=7, with `Data` as the default. The wire byte
/// occupies the qos packed byte's low 3 bits per
/// `_z_n_qos_create` at network.h:84-89.
/// `PartialOrd`/`Ord` follow declaration order = the wire values 0..=7
/// (Control smallest .. Background largest), so `PriorityRange` containment
/// (`start <= p <= end`) is a wire-order compare — the same derive zenoh
/// puts on `Priority` (`commons/zenoh-protocol/src/core/mod.rs`). R311y215.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Priority {
    /// `_Z_PRIORITY_CONTROL = 0`. Reserved for internal control
    /// messages in zenoh-pico (the leading-underscore name signals
    /// "implementation detail" upstream); application traffic should
    /// pick one of the public priorities below.
    Control = 0,
    /// `Z_PRIORITY_REAL_TIME = 1`. Highest application priority.
    RealTime = 1,
    /// `Z_PRIORITY_INTERACTIVE_HIGH = 2`.
    InteractiveHigh = 2,
    /// `Z_PRIORITY_INTERACTIVE_LOW = 3`.
    InteractiveLow = 3,
    /// `Z_PRIORITY_DATA_HIGH = 4`.
    DataHigh = 4,
    /// `Z_PRIORITY_DATA = 5` — `Z_PRIORITY_DEFAULT` per the same
    /// constants.h. Pick this when no other priority justifies an
    /// explicit override.
    Data = 5,
    /// `Z_PRIORITY_DATA_LOW = 6`.
    DataLow = 6,
    /// `Z_PRIORITY_BACKGROUND = 7`. Lowest priority.
    Background = 7,
}

impl Priority {
    /// Wire byte value as written into the qos packed byte's low 3
    /// bits. Mirrors the enum literal values verbatim per
    /// `_z_n_qos_create` at network.h:87.
    pub const fn wire_byte(self) -> u8 {
        self as u8
    }

    /// The number of priority levels (zenoh `Priority::NUM`): 8, `Control`
    /// (0) through `Background` (7). The per-(priority,reliability) SN
    /// conduit array is sized by this when `transport-qos` compiles.
    pub const NUM: usize = 8;

    /// The default priority when a message carries no explicit QoS (zenoh
    /// `Priority::DEFAULT` = `Data`, `network/mod.rs`). A Frame at DEFAULT
    /// omits the `ext_qos` transport extension entirely (wire-identical to
    /// a pre-QoS Frame).
    pub const DEFAULT: Priority = Priority::Data;

    /// Inverse of [`Self::wire_byte`]: map a wire byte to its `Priority`.
    /// The 3-bit priority field cannot encode a value > 7, so the
    /// out-of-range arm is unreachable from a conforming wire; it clamps to
    /// [`Self::DEFAULT`] rather than panicking (the permissive-decode arm,
    /// same spirit as `sn::mask_from_res`'s defensive default).
    pub const fn from_wire(byte: u8) -> Priority {
        match byte {
            0 => Priority::Control,
            1 => Priority::RealTime,
            2 => Priority::InteractiveHigh,
            3 => Priority::InteractiveLow,
            4 => Priority::DataHigh,
            5 => Priority::Data,
            6 => Priority::DataLow,
            7 => Priority::Background,
            _ => Priority::DEFAULT,
        }
    }
}

/// R121j-1h — mirror of zenoh-pico's `z_congestion_control_t` enum
/// at `vendor/zenoh-pico/include/zenoh-pico/api/constants.h:216-218`.
/// The wire mapping inverts the enum's integer value: `Block = 1`
/// in zenoh-pico's enum lifts into the `nodrop = 1` bit (bit 3) of
/// the qos packed byte per `_z_n_qos_create` at network.h:86-87.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CongestionControl {
    /// `Z_CONGESTION_CONTROL_DROP = 0` (also `Z_CONGESTION_CONTROL_DEFAULT`).
    /// Messages may be dropped on congestion; nodrop bit cleared.
    Drop,
    /// `Z_CONGESTION_CONTROL_BLOCK = 1`. Producer blocks on
    /// congestion rather than dropping; nodrop bit set.
    Block,
}

impl CongestionControl {
    /// Wire-side `nodrop` bit value (0 for Drop, 1 for Block) that
    /// the qos packed byte's bit 3 carries. Named `wire_bit` rather
    /// than `wire_byte` to keep the boolean semantics legible at the
    /// call site in `RequestQueryBuilder::request_qos_typed`.
    pub const fn wire_bit(self) -> u8 {
        match self {
            Self::Drop => 0,
            Self::Block => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R121j-1h — Priority::wire_byte and CongestionControl::wire_bit
    /// match the zenoh-pico enum literal values verbatim. Decouples
    /// the typed-wrapper test from RequestQueryBuilder so a future
    /// re-use of Priority / CongestionControl (e.g. in a Push-side
    /// QoS setter) inherits the same invariant.
    #[test]
    fn priority_and_congestion_wire_values_match_zenoh_pico_constants() {
        assert_eq!(Priority::Control.wire_byte(), 0);
        assert_eq!(Priority::RealTime.wire_byte(), 1);
        assert_eq!(Priority::InteractiveHigh.wire_byte(), 2);
        assert_eq!(Priority::InteractiveLow.wire_byte(), 3);
        assert_eq!(Priority::DataHigh.wire_byte(), 4);
        assert_eq!(Priority::Data.wire_byte(), 5);
        assert_eq!(Priority::DataLow.wire_byte(), 6);
        assert_eq!(Priority::Background.wire_byte(), 7);

        assert_eq!(CongestionControl::Drop.wire_bit(), 0);
        assert_eq!(CongestionControl::Block.wire_bit(), 1);
    }
}
