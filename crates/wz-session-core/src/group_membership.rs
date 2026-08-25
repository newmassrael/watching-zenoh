// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y97 — `ext-pubsub-group-membership` (§5.25): the no_std data model +
//! the bincode-1.3 wire codec for zenoh-ext's group-membership protocol.
//!
//! A faithful, byte-exact mirror of zenoh-ext `group.rs`'s
//! `bincode::serialize` wire. zenoh-ext lets a set of peers form a named
//! group and track its live membership (the "view"): each member announces
//! itself with a [`GroupNetEvent::Join`] on a shared event key
//! (`zenoh/ext/net/group/<gid>/evt`), refreshes its lease with periodic
//! [`GroupNetEvent::KeepAlive`] beacons, and serves its own [`Member`]
//! record from a per-member queryable (`zenoh/ext/net/group/<gid>/<mid>`)
//! so a peer that hears a beacon from an unknown member can `get` its
//! details. The live [`Group`] + the four handlers (join announce,
//! keep-alive, watchdog lease-sweep, query answer) are the AP-only tokio
//! half in `wz-runtime-tokio`; this crate owns the portable data + wire so
//! the wire contract is unit-testable without a runtime.
//!
//! ## Wire format (byte-identical to zenoh-ext's `bincode::serialize`)
//!
//! zenoh-ext derives `serde::{Serialize, Deserialize}` on its event +
//! member structs and renders them with the `bincode::serialize` free
//! function — i.e. bincode 1.3's default config: little-endian, fixed-int
//! (no varint), `u32` enum-variant indices, `u64` length prefixes. The
//! group payloads use these bincode shapes:
//!
//! - **enum** ([`GroupNetEvent`], [`MemberLiveliness`]): a `u32` LE variant
//!   index, then the variant's fields concatenated.
//! - **`String`** (a member id / info): a `u64` LE length then the UTF-8
//!   bytes. zenoh-ext's `mid` is an `OwnedKeyExpr`, which serializes as its
//!   inner `Arc<str>` (owned.rs:34-41) and deserializes `try_from = "String"`
//!   — i.e. byte-identical to a plain `String`.
//! - **`Option<String>`** (the optional info): a single `0` / `1` tag byte,
//!   then the `String` only for `Some`.
//! - **`Duration`** (the lease): the std serde impl renders it as a struct
//!   `{ secs: u64, nanos: u32 }`, so bincode emits a `u64` LE seconds then a
//!   `u32` LE sub-second nanos.
//! - **`f32`** (the refresh ratio): 4 IEEE-754 little-endian bytes.
//!
//! The codec reuses the shared multi-consumer bincode-1.3 widths
//! ([`crate::wire_bincode`]) and layers its group-only shapes (`f32`, the std
//! `Duration` struct) on them; it is pinned to the real `bincode` 1.3 by the
//! `#[cfg(test)]` oracle below (a serde mirror of zenoh-ext's structs
//! serialized with the exact default config, asserted byte-for-byte).
//!
//! ## Faithful omissions
//!
//! - zenoh-ext's `Member` carries a `#[serde(skip)] priority: Priority`
//!   field used only to set the local event publisher's QoS priority; being
//!   `serde(skip)` it never reaches the wire, so it is NOT part of this data
//!   model (the runtime sets publish QoS separately). The five wire fields
//!   (`mid`, `info`, `liveliness`, `lease`, `refresh_ratio`) are exhaustive.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use crate::wire_bincode::{
    push_option_string, push_string, push_u32, push_u64, read_len_prefixed_bytes, read_u32,
    read_u8, Reader, WireError,
};

/// The default member lease before it is considered expired without a
/// refreshing keep-alive (zenoh-ext `DEFAULT_LEASE`, group.rs:40).
pub const DEFAULT_LEASE: Duration = Duration::from_secs(18);

/// The default keep-alive period as a fraction of the lease: a member
/// re-announces every `lease * refresh_ratio` so a refresh always arrives
/// before the lease elapses (zenoh-ext `VIEW_REFRESH_LEASE_RATIO`,
/// group.rs:39).
pub const VIEW_REFRESH_LEASE_RATIO: f32 = 0.75;

/// How a member's liveliness is asserted. Mirror of zenoh-ext
/// `MemberLiveliness` (group.rs:92-97). `Auto` spawns the background
/// keep-alive beacon; `Manual` leaves the assertion to the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberLiveliness {
    /// The group runtime emits the periodic keep-alive automatically.
    Auto,
    /// The user is responsible for asserting liveliness.
    Manual,
}

/// A group member's self-description, exchanged on join and served from its
/// per-member queryable. Mirror of zenoh-ext `Member` (group.rs:99-162)
/// minus the `serde(skip)` `priority` (a local-only QoS field that never
/// reaches the wire).
#[derive(Clone, Debug, PartialEq)]
pub struct Member {
    /// The member id — a non-wild key expression string. zenoh-ext types it
    /// as `OwnedKeyExpr`; wz keeps the canonical string and validates the
    /// non-wild constraint at the runtime `Group::join` boundary.
    pub mid: String,
    /// Optional free-form member info.
    pub info: Option<String>,
    /// Whether liveliness is asserted automatically or manually.
    pub liveliness: MemberLiveliness,
    /// The lease: how long this member stays in a peer's view without a
    /// refreshing keep-alive.
    pub lease: Duration,
    /// The keep-alive period as a fraction of the lease.
    pub refresh_ratio: f32,
}

impl Member {
    /// A member with `mid` and the zenoh-ext defaults (`Auto` liveliness,
    /// an 18s lease, a 0.75 refresh ratio, no info). The builder methods
    /// override individual fields. Validation of the non-wild keyexpr
    /// constraint lives at the runtime `Group::join` boundary (mirroring
    /// zenoh-ext, which validates both the member id and the group id when
    /// the group is joined).
    pub fn new(mid: impl Into<String>) -> Self {
        Self {
            mid: mid.into(),
            info: None,
            liveliness: MemberLiveliness::Auto,
            lease: DEFAULT_LEASE,
            refresh_ratio: VIEW_REFRESH_LEASE_RATIO,
        }
    }

    /// The member id.
    pub fn id(&self) -> &str {
        &self.mid
    }

    /// Set the optional info string (builder).
    pub fn info(mut self, i: impl Into<String>) -> Self {
        self.info = Some(i.into());
        self
    }

    /// Set the lease (builder).
    pub fn lease(mut self, d: Duration) -> Self {
        self.lease = d;
        self
    }

    /// Set the liveliness mode (builder).
    pub fn liveliness(mut self, l: MemberLiveliness) -> Self {
        self.liveliness = l;
        self
    }

    /// Set the keep-alive refresh ratio (builder).
    pub fn refresh_ratio(mut self, r: f32) -> Self {
        self.refresh_ratio = r;
        self
    }
}

/// A group net-event as it travels on the event key. Mirror of zenoh-ext's
/// internal `GroupNetEvent` (group.rs:73-79): the three messages the group
/// publishes/receives on `zenoh/ext/net/group/<gid>/evt`. zenoh-ext wraps
/// the two id-only events in one-field `LeaveEvent` / `KeepAliveEvent`
/// structs; on the bincode wire a single-field tuple/struct is just its
/// field, so the wz `String` payload is byte-identical.
#[derive(Clone, Debug, PartialEq)]
pub enum GroupNetEvent {
    /// A member announces (or re-announces, on an unknown-member query
    /// answer) itself: the full [`Member`] record. Variant index `0`.
    Join(Member),
    /// A member leaves the group: its id. Variant index `1`.
    Leave(String),
    /// A member refreshes its lease: its id. Variant index `2`.
    KeepAlive(String),
}

/// Failure decoding a group-membership wire structure from bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupDecodeError {
    /// The buffer ended before a fixed-width field could be read.
    UnexpectedEof,
    /// A length prefix exceeds the bytes that remain — corrupt or hostile.
    LengthOverflow,
    /// Bytes remained after a complete structure was decoded.
    TrailingBytes,
    /// An `Option` discriminant byte that was neither `0` nor `1`.
    BadOptionTag(u8),
    /// A string field whose bytes are not valid UTF-8.
    BadUtf8,
    /// A `Duration` sub-second nanos field `>= 1_000_000_000` — a value the
    /// std serde `Duration` never emits, so a corrupt/hostile buffer.
    BadDurationNanos(u32),
    /// A [`GroupNetEvent`] / [`MemberLiveliness`] enum tag with no known
    /// variant.
    UnknownVariant(u32),
}

impl From<WireError> for GroupDecodeError {
    fn from(e: WireError) -> Self {
        match e {
            WireError::UnexpectedEof => Self::UnexpectedEof,
            WireError::LengthOverflow => Self::LengthOverflow,
        }
    }
}

const NANOS_PER_SEC: u32 = 1_000_000_000;

// ---- encode (the push side, layered on the shared bincode-1.3 cursor) ----
//
// `push_u32` / `push_string` / `push_option_string` are the shared
// multi-consumer widths ([`crate::wire_bincode`]); the group-only composite
// shapes (`f32`, the std `Duration` struct) layer on them here.

/// Append a bincode `f32`: 4 IEEE-754 little-endian bytes.
fn push_f32(out: &mut Vec<u8>, v: f32) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// Append a bincode std `Duration`: a `u64` LE seconds then a `u32` LE
/// sub-second nanos (the std serde `Duration` struct shape `{ secs, nanos }`).
fn push_duration(out: &mut Vec<u8>, d: Duration) {
    push_u64(out, d.as_secs());
    push_u32(out, d.subsec_nanos());
}

fn push_member(out: &mut Vec<u8>, m: &Member) {
    push_string(out, &m.mid);
    push_option_string(out, m.info.as_deref());
    push_u32(
        out,
        match m.liveliness {
            MemberLiveliness::Auto => 0,
            MemberLiveliness::Manual => 1,
        },
    );
    push_duration(out, m.lease);
    push_f32(out, m.refresh_ratio);
}

/// Encode one bare [`Member`] to the bincode wire bytes (the per-member
/// query-reply body — zenoh-ext `bincode::serialize(&state.local_member)`,
/// group.rs:238).
pub fn encode_member(m: &Member) -> Vec<u8> {
    let mut out = Vec::new();
    push_member(&mut out, m);
    out
}

/// Encode one [`GroupNetEvent`] to the bincode wire bytes (the event-key
/// payload — zenoh-ext `bincode::serialize(&evt)`, group.rs:189/392).
pub fn encode_net_event(e: &GroupNetEvent) -> Vec<u8> {
    let mut out = Vec::new();
    match e {
        GroupNetEvent::Join(m) => {
            push_u32(&mut out, 0);
            push_member(&mut out, m);
        }
        GroupNetEvent::Leave(mid) => {
            push_u32(&mut out, 1);
            push_string(&mut out, mid);
        }
        GroupNetEvent::KeepAlive(mid) => {
            push_u32(&mut out, 2);
            push_string(&mut out, mid);
        }
    }
    out
}

// ---- decode (the group's domain reads over the shared `Reader`) ----
//
// The structural widths (`read_u8` / `read_u32` / the length-guarded
// `read_len_prefixed_bytes`) are the shared bincode-1.3 SSOT
// ([`crate::wire_bincode`]); these add the group's domain shapes (an `f32`, a
// std `Duration`, the `Member` / event structs) and map a domain failure (bad
// UTF-8, an out-of-range `Option` tag, illegal `Duration` nanos) to
// [`GroupDecodeError`]. They are free fns, not inherent `Reader` methods,
// because the aligner codec already adds inherent reads to the shared `Reader`
// and same-named inherent methods would collide when both features compile.

fn read_f32(r: &mut Reader) -> Result<f32, GroupDecodeError> {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(r.read_bytes(4)?);
    Ok(f32::from_le_bytes(bytes))
}

fn read_string(r: &mut Reader) -> Result<String, GroupDecodeError> {
    // The shared `read_len_prefixed_bytes` is the SSOT length guard (the guard
    // that had drifted from the aligner's copy); the group layers UTF-8
    // validation on the returned slice.
    core::str::from_utf8(read_len_prefixed_bytes(r)?)
        .map(String::from)
        .map_err(|_| GroupDecodeError::BadUtf8)
}

fn read_option_string(r: &mut Reader) -> Result<Option<String>, GroupDecodeError> {
    match read_u8(r)? {
        0 => Ok(None),
        1 => Ok(Some(read_string(r)?)),
        other => Err(GroupDecodeError::BadOptionTag(other)),
    }
}

fn read_duration(r: &mut Reader) -> Result<Duration, GroupDecodeError> {
    let secs = r.read_u64()?;
    let nanos = read_u32(r)?;
    if nanos >= NANOS_PER_SEC {
        return Err(GroupDecodeError::BadDurationNanos(nanos));
    }
    Ok(Duration::new(secs, nanos))
}

fn read_member(r: &mut Reader) -> Result<Member, GroupDecodeError> {
    let mid = read_string(r)?;
    let info = read_option_string(r)?;
    let liveliness = match read_u32(r)? {
        0 => MemberLiveliness::Auto,
        1 => MemberLiveliness::Manual,
        other => return Err(GroupDecodeError::UnknownVariant(other)),
    };
    let lease = read_duration(r)?;
    let refresh_ratio = read_f32(r)?;
    Ok(Member {
        mid,
        info,
        liveliness,
        lease,
        refresh_ratio,
    })
}

/// Decode one bare [`Member`] from the bincode wire bytes; rejects trailing
/// bytes.
pub fn decode_member(bytes: &[u8]) -> Result<Member, GroupDecodeError> {
    let mut r = Reader::new(bytes);
    let m = read_member(&mut r)?;
    if r.remaining() != 0 {
        return Err(GroupDecodeError::TrailingBytes);
    }
    Ok(m)
}

/// Decode one [`GroupNetEvent`] from the bincode wire bytes; rejects trailing
/// bytes and unknown variant tags.
pub fn decode_net_event(bytes: &[u8]) -> Result<GroupNetEvent, GroupDecodeError> {
    let mut r = Reader::new(bytes);
    let evt = match read_u32(&mut r)? {
        0 => GroupNetEvent::Join(read_member(&mut r)?),
        1 => GroupNetEvent::Leave(read_string(&mut r)?),
        2 => GroupNetEvent::KeepAlive(read_string(&mut r)?),
        other => return Err(GroupDecodeError::UnknownVariant(other)),
    };
    if r.remaining() != 0 {
        return Err(GroupDecodeError::TrailingBytes);
    }
    Ok(evt)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The bincode-1.3 ground-truth oracle: serde mirrors of zenoh-ext's
    // structs with the EXACT field order + types, serialized with the
    // `bincode::serialize` free function (default config, the same call
    // zenoh-ext makes). Asserting the hand-rolled bytes equal these proves
    // wire compatibility with zenoh-ext without running zenoh. `OwnedKeyExpr`
    // is mirrored as `String` because it serializes as its inner `Arc<str>`
    // (owned.rs:34-41) and deserializes `try_from = "String"`.
    mod oracle {
        use serde::{Deserialize, Serialize};
        use std::string::String;
        use std::time::Duration;

        #[derive(Serialize, Deserialize)]
        pub enum MemberLiveliness {
            Auto,
            Manual,
        }

        #[derive(Serialize, Deserialize)]
        pub struct Member {
            pub mid: String,
            pub info: Option<String>,
            pub liveliness: MemberLiveliness,
            pub lease: Duration,
            pub refresh_ratio: f32,
        }

        // zenoh-ext wraps the id-only events in single-field structs; bincode
        // renders a single-field struct as just its field, so mirroring them
        // as the bare field reproduces the identical bytes.
        #[derive(Serialize, Deserialize)]
        pub enum GroupNetEvent {
            Join(Member),
            Leave(String),
            KeepAlive(String),
        }
    }

    fn sample_member() -> Member {
        Member::new("a/b/member1")
            .info("node-info")
            .lease(Duration::from_millis(12_500))
            .refresh_ratio(0.6)
    }

    fn oracle_member(m: &Member) -> oracle::Member {
        oracle::Member {
            mid: m.mid.clone(),
            info: m.info.clone(),
            liveliness: match m.liveliness {
                MemberLiveliness::Auto => oracle::MemberLiveliness::Auto,
                MemberLiveliness::Manual => oracle::MemberLiveliness::Manual,
            },
            lease: m.lease,
            refresh_ratio: m.refresh_ratio,
        }
    }

    #[test]
    fn member_wire_matches_bincode_oracle() {
        for m in [
            sample_member(),
            Member::new("g/m").liveliness(MemberLiveliness::Manual),
            // no info -> the `None` Option path (single 0 byte)
            Member {
                mid: "x".into(),
                info: None,
                liveliness: MemberLiveliness::Auto,
                lease: DEFAULT_LEASE,
                refresh_ratio: VIEW_REFRESH_LEASE_RATIO,
            },
        ] {
            let ours = encode_member(&m);
            let oracle = bincode::serialize(&oracle_member(&m)).unwrap();
            assert_eq!(ours, oracle, "member wire diverges from bincode for {m:?}");
            assert_eq!(decode_member(&ours), Ok(m), "member round-trips");
        }
    }

    #[test]
    fn net_event_wire_matches_bincode_oracle() {
        let join = GroupNetEvent::Join(sample_member());
        let leave = GroupNetEvent::Leave("g/m2".into());
        let keep = GroupNetEvent::KeepAlive("g/m3".into());

        let oracle_for = |e: &GroupNetEvent| match e {
            GroupNetEvent::Join(m) => {
                bincode::serialize(&oracle::GroupNetEvent::Join(oracle_member(m))).unwrap()
            }
            GroupNetEvent::Leave(mid) => {
                bincode::serialize(&oracle::GroupNetEvent::Leave(mid.clone())).unwrap()
            }
            GroupNetEvent::KeepAlive(mid) => {
                bincode::serialize(&oracle::GroupNetEvent::KeepAlive(mid.clone())).unwrap()
            }
        };

        for e in [join, leave, keep] {
            let ours = encode_net_event(&e);
            assert_eq!(ours, oracle_for(&e), "net-event wire diverges for {e:?}");
            assert_eq!(decode_net_event(&ours), Ok(e), "net-event round-trips");
        }
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = encode_member(&sample_member());
        bytes.push(0xFF);
        assert_eq!(decode_member(&bytes), Err(GroupDecodeError::TrailingBytes));
    }

    #[test]
    fn decode_rejects_unknown_event_variant() {
        let mut bytes = Vec::new();
        push_u32(&mut bytes, 7); // no such GroupNetEvent variant
        assert_eq!(
            decode_net_event(&bytes),
            Err(GroupDecodeError::UnknownVariant(7))
        );
    }

    #[test]
    fn decode_rejects_truncated_buffer() {
        let full = encode_member(&sample_member());
        // Drop the trailing f32 (refresh_ratio) -> short read.
        assert_eq!(
            decode_member(&full[..full.len() - 2]),
            Err(GroupDecodeError::UnexpectedEof)
        );
    }

    #[test]
    fn decode_rejects_bad_duration_nanos() {
        // Hand-build a member with nanos == 1e9 (never emitted by std serde).
        let mut bytes = Vec::new();
        push_string(&mut bytes, "m");
        push_option_string(&mut bytes, None);
        push_u32(&mut bytes, 0); // Auto
        push_u64(&mut bytes, 1); // secs
        push_u32(&mut bytes, NANOS_PER_SEC); // illegal nanos
        push_f32(&mut bytes, 0.75);
        assert_eq!(
            decode_member(&bytes),
            Err(GroupDecodeError::BadDurationNanos(NANOS_PER_SEC))
        );
    }
}
