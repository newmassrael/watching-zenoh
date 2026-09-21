// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2762 — the per-extension ACCEPT STATE seam: what an extension hands the
//! acceptor's cookie, and takes back from it.
//!
//! ## Why a seam rather than more cookie fields
//!
//! zenoh's acceptor can hold nothing between InitAck and OpenSyn because its
//! cookie carries the negotiated state, and it carries that state because
//! EVERY establishment extension owns a serialisable accept-state type plus
//! its codec pair. Ten of them do: patch, multilink, compression, qos,
//! region_name, shm auth, lowlatency, usrpwd, the auth mux and pubkey. Its
//! `Cookie` is then a struct over those types and its codec delegates —
//! `io/zenoh-transport/src/unicast/establishment/cookie.rs` @ `pub(crate) struct Cookie`.
//!
//! This tree spells `StateAccept` in prose and implements it nowhere, so a
//! carrier here can only reach the state that happens to sit in a slot it can
//! read. Adding fields to the carrier one at a time treats the symptom: the
//! thing that is missing is the per-extension type, which is what this module
//! introduces.
//!
//! ## Fixed sinks, because the profile that needs this most has no allocator
//!
//! (Crate-ABSOLUTE below, and so is the `PatchAcceptState` reference, for the
//! reason `crate::entropy`'s own note records as `debt-carry-N13`: this module
//! carries BOTH an outer `///` on its `pub mod` line in `lib.rs` and this
//! inner `//!`, rustdoc MERGES the two, and it resolves the result in the
//! PARENT scope — where a bare `AcceptState` is not in scope. Layer C1bz is
//! the only gate that reaches this class, and it caught both.)
//!
//! [`crate::accept_state::AcceptState`] is written against `SceSink` and
//! `SceCursor` rather than
//! against `Vec<u8>`, and this module is NOT `alloc`-gated. Those are the same
//! decision. A fixed sink raises `CodecError::BufferOverflow` where a growable
//! one returns `Ok` — `backends/rust/forge-runtime/src/codec.rs` @ `fn write_bytes`
//! — which is how the generated codecs serve the Heap and Inline storage
//! profiles from one body of code. The Inline profile is exactly where the
//! cookie's declared capacity is HARD rather than advisory, so a seam that
//! could only be expressed with an allocator would be absent from the only
//! profile that cannot negotiate about its size.
//!
//! ## The encoding is wz's own, and that is not a divergence
//!
//! The cookie payload is PRIVATE: an initiator receives opaque bytes and
//! echoes them back, so nothing off this node parses them. Upstream is
//! therefore the oracle for WHICH state has to survive the boundary and not
//! for how it is written, and copying its byte layout would lose information
//! wz keeps. [`crate::accept_state::PatchAcceptState`] is the first instance
//! — see its own note.
//!
//! ## What the cookie carries, and what it still does not (R2774)
//!
//! The five states `NegotiatedExtensions` groups ride the cookie, and the
//! acceptor rebuilds them at OpenSyn and does not hold them in between.
//! R2777 closed one more: the QoS priority band and reliability now ride
//! inside `QosAcceptState`. What upstream's cookie carries and this acceptor
//! still holds is read off upstream's cookie STRUCT rather than off a list
//! of extensions, because the list R2774 wrote from a walk of the extensions
//! missed one —
//! `io/zenoh-transport/src/unicast/establishment/cookie.rs` @ `pub(crate) struct Cookie {`.
//! Against that struct four things remained. R2779 closed the auth states
//! (the usrpwd nonce and the pubkey challenge ride `AuthAcceptState`) and
//! R2780 the peer's announced region name (`RegionAcceptState`), and R2782
//! the cookie's head -- the peer's zid, role and sizing caps, which rode the
//! cookie already and are now let go after InitAck as well. One remains,
//! held by the object that owns it: the multilink public key with its
//! challenge. Upstream's shm accept state is EMPTY, so shm is not among
//! them —
//! `io/zenoh-transport/src/unicast/establishment/ext/shm/auth.rs` @ `pub(crate) type StateAccept = StateOpen;`
//! and its codec writes nothing.

use sce_forge_runtime::codec::{CodecError, SceCursor, SceSink};

use crate::extregion::{RegionName, MAX_REGION_NAME_LEN};
use crate::qos::Priority;
use crate::reliability::Reliability;

/// One extension's accept state, in the form the acceptor's cookie carries.
///
/// The shape mirrors the generated codecs rather than inventing a second
/// idiom: `encode` appends to a sink, `decode` reads through a cursor with
/// `peek_slice` / `advance`, and both surface `CodecError`.
///
/// Implementors encode a FIXED, self-delimiting number of bytes. There is no
/// length prefix and no tag: the cookie's own codec knows which states it
/// wrote and in what order, exactly as zenoh's `Cookie` codec delegates to
/// each extension in a fixed order rather than discovering them on the wire.
pub trait AcceptState: Sized {
    /// The exact number of bytes [`AcceptState::encode`] appends, whatever
    /// this state carries.
    ///
    /// R2765 — the sentence above said "a FIXED number of bytes" and nothing
    /// could read it. A carrier that delegates to several of these has to
    /// know its own length before it parses anything, so the width has to be
    /// a value rather than a promise; as a promise it was also the kind of
    /// claim this tree has been bitten by, an asserted binding with no
    /// binding. `the_declared_width_is_what_each_state_writes` holds every
    /// implementor to it.
    const WIDTH: usize;

    /// Append this state to `sink`.
    ///
    /// A fixed-capacity sink reports `CodecError::BufferOverflow` here rather
    /// than growing, which is the error a caller assembling a cookie for the
    /// Inline profile has to be able to see.
    fn encode<S: SceSink>(&self, sink: &mut S) -> Result<(), CodecError>;

    /// Read this state from `cursor`, advancing it past the bytes consumed.
    ///
    /// A cursor that runs out reports `CodecError`; an implementor never
    /// partially advances and then fails, because the cookie's decode has no
    /// way to rewind.
    fn decode(cursor: &mut SceCursor<'_>) -> Result<Self, CodecError>;
}

/// The protocol-patch level this session negotiated, or its absence.
///
/// ## Why this is an `Option` where upstream's is a plain byte
///
/// zenoh's is `io/zenoh-transport/src/unicast/establishment/ext/patch.rs` @ `pub(crate) struct StateAccept`,
/// one `PatchType` with no presence term, because it folds "nothing
/// negotiated" into the value `PatchType::NONE`. wz keeps the two apart and
/// has a reader that depends on the difference:
/// `crates/wz-session-core/src/session_actions.rs` @ `pub fn patch_was_negotiated`
/// separates "the peer announced patch 0" from "no Init has been seen", and
/// its own note says those mean different things to anything reporting on a
/// session it did not establish — the passive-dissection consumer.
///
/// So the wz state is strictly richer here, and encoding it in upstream's
/// shape would be a lossy conversion made in the name of fidelity. A cookie
/// that carried the folded byte would let a rebuilt acceptor answer
/// `patch_was_negotiated() == false` after a handshake that did negotiate.
///
/// ## Two bytes, and no sentinel
///
/// A presence byte then the level. The level occupies the whole `u8` range,
/// so there is no spare value to mean "absent" — and a sentinel would be the
/// shape R2567 removed from the usrpwd credential source, where emptiness
/// stood in for a type and read as "configured to reject everybody".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PatchAcceptState(pub Option<u8>);

impl PatchAcceptState {
    /// The presence byte for a state that carries a level.
    const PRESENT: u8 = 1;
    /// The presence byte for a state that does not.
    const ABSENT: u8 = 0;
}

impl AcceptState for PatchAcceptState {
    const WIDTH: usize = 2;

    fn encode<S: SceSink>(&self, sink: &mut S) -> Result<(), CodecError> {
        match self.0 {
            Some(level) => {
                sink.write_u8(Self::PRESENT)?;
                sink.write_u8(level)
            }
            // The second byte is written even when absent, so the state's
            // width does not depend on its content: a fixed width is what
            // lets the cookie's codec read its members in order without a
            // length prefix.
            None => {
                sink.write_u8(Self::ABSENT)?;
                sink.write_u8(0)
            }
        }
    }

    fn decode(cursor: &mut SceCursor<'_>) -> Result<Self, CodecError> {
        let raw = cursor.peek_slice(2)?;
        let present = raw[0];
        let level = raw[1];
        cursor.advance(2)?;
        // TOTAL on the presence byte: anything non-zero reads as present.
        // Not laxity -- there is no third case to report. A cookie this node
        // did not write is refused by its MAC before any of this runs, so a
        // byte outside {0, 1} cannot arrive on an authenticated payload, and
        // inventing an error for it would mean inventing a `CodecError`
        // variant in a pinned upstream crate for a state that cannot occur.
        // zenoh's own patch decode is total for the same reason --
        // `io/zenoh-transport/src/unicast/establishment/ext/patch.rs` @ `let patch = PatchType::new(raw);`
        // takes whatever byte it read.
        if present == Self::ABSENT {
            Ok(Self(None))
        } else {
            Ok(Self(Some(level)))
        }
    }
}

/// Declare one extension's accept state for a capability whose whole
/// negotiated state is a single bool.
///
/// DISTINCT TYPES rather than one reused flag type, and a macro rather than
/// hand-written copies — both halves are the structure upstream
/// has. `io/zenoh-transport/src/unicast/establishment/ext/lowlatency.rs` @
/// `pub(crate) struct StateAccept` and its compression sibling are separate
/// one-bool types with separate codecs, and
/// `io/zenoh-transport/src/unicast/establishment/cookie.rs` @
/// `pub(crate) struct Cookie` names each by its own field. One shared type
/// would put the carrier back in charge of deciding which POSITION means
/// which extension, which is the coupling this seam exists to remove — it is
/// the bitset the cookie had, spelled differently.
macro_rules! flag_accept_state {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub struct $name(pub bool);

        impl AcceptState for $name {
            const WIDTH: usize = 1;

            fn encode<S: SceSink>(&self, sink: &mut S) -> Result<(), CodecError> {
                sink.write_u8(u8::from(self.0))
            }

            fn decode(cursor: &mut SceCursor<'_>) -> Result<Self, CodecError> {
                let raw = cursor.peek_slice(1)?;
                let set = raw[0] != 0;
                cursor.advance(1)?;
                // TOTAL on the byte, for the reason `PatchAcceptState::decode`
                // gives at length: the MAC refuses a payload this node did not
                // write before any of this runs, so a byte outside {0, 1}
                // cannot arrive, and upstream's own bool decode is total too
                // (`io/zenoh-transport/src/unicast/establishment/ext/lowlatency.rs`
                // @ `let is_lowlatency = is_lowlatency == 1`).
                Ok(Self(set))
            }
        }
    };
}

/// What this session negotiated for QoS: nothing, or QoS together with the
/// priority band and reliability class it settled on.
///
/// R2777 — this was a bool, and a bool is NARROWER than what wz negotiates.
/// Under `session-extqos` the band and the reliability are merged too, and
/// the acceptor reads the merged band after establishment, so a cookie that
/// carried only the bool left the band held between InitAck and OpenSyn.
/// The shape is now upstream's own:
/// `io/zenoh-transport/src/unicast/establishment/ext/qos.rs` @ `enum State {`
/// is `NoQoS | QoS { reliability, priorities }`, one state with two arms,
/// and it is what upstream's cookie carries for this extension.
///
/// The band is held as a `Priority` PAIR and the class as a `Reliability`,
/// not as `LinkPriorityRange` or `QosLinkState`: those are gated on
/// `transport-qos` and `session-extqos`, and this module is ungated by
/// design so that its members are unconditional and only their values are.
/// A build without the feature writes `NoQos`, which is what it negotiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QosAcceptState {
    /// QoS was not negotiated.
    #[default]
    NoQos,
    /// QoS was negotiated, with the band and class the merge settled on.
    Qos {
        /// The negotiated priority band, lowest priority value first, or
        /// none when neither side declared one.
        priorities: Option<(Priority, Priority)>,
        /// The negotiated reliability class, or none when neither side
        /// declared one.
        reliability: Option<Reliability>,
    },
}

impl QosAcceptState {
    /// The tag byte for `NoQos`.
    const NO_QOS: u8 = 0;
    /// The tag byte for `Qos`.
    const QOS: u8 = 1;

    /// QoS negotiated with neither a band nor a class declared — the whole
    /// state of a build that negotiates the capability without
    /// `session-extqos`.
    pub const BARE: Self = Self::Qos {
        priorities: None,
        reliability: None,
    };

    /// Whether QoS was negotiated at all.
    pub fn negotiated(&self) -> bool {
        matches!(self, Self::Qos { .. })
    }
}

impl AcceptState for QosAcceptState {
    /// Tag, band presence, band start, band end, class presence, class.
    const WIDTH: usize = 6;

    fn encode<S: SceSink>(&self, sink: &mut S) -> Result<(), CodecError> {
        // Every byte is written whatever the arm, so the width does not
        // depend on the content -- the rule `PatchAcceptState::encode` states.
        let (tag, priorities, reliability) = match *self {
            Self::NoQos => (Self::NO_QOS, None, None),
            Self::Qos {
                priorities,
                reliability,
            } => (Self::QOS, priorities, reliability),
        };
        sink.write_u8(tag)?;
        match priorities {
            Some((start, end)) => {
                sink.write_u8(1)?;
                sink.write_u8(start.wire_byte())?;
                sink.write_u8(end.wire_byte())?;
            }
            None => {
                sink.write_u8(0)?;
                sink.write_u8(0)?;
                sink.write_u8(0)?;
            }
        }
        match reliability {
            Some(class) => {
                sink.write_u8(1)?;
                sink.write_u8(class as u8)
            }
            None => {
                sink.write_u8(0)?;
                sink.write_u8(0)
            }
        }
    }

    fn decode(cursor: &mut SceCursor<'_>) -> Result<Self, CodecError> {
        let raw = cursor.peek_slice(Self::WIDTH)?;
        let (tag, band_present, start, end, class_present, class) =
            (raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]);
        cursor.advance(Self::WIDTH)?;
        // TOTAL on every byte, for the reason `PatchAcceptState::decode` gives
        // at length: the MAC refuses a payload this node did not write before
        // any of this runs. `Priority::from_wire` and the class mapping are
        // total already, so no byte needs an error this codec cannot name.
        if tag == Self::NO_QOS {
            return Ok(Self::NoQos);
        }
        Ok(Self::Qos {
            priorities: (band_present != 0)
                .then(|| (Priority::from_wire(start), Priority::from_wire(end))),
            reliability: (class_present != 0)
                .then(|| Reliability::from_reliable_bool(class == Reliability::Reliable as u8)),
        })
    }
}

flag_accept_state! {
    /// Whether this session negotiated shared memory.
    ///
    /// R2774 corrected what this note used to say on BOTH counts. Upstream's
    /// shm accept state carries no challenge — it is the empty `StateOpen`,
    /// `io/zenoh-transport/src/unicast/establishment/ext/shm/auth.rs` @ `pub(crate) type StateAccept = StateOpen;`
    /// — and wz's shm DOES authenticate, by the challenge exchange
    /// `crate::extshm::ShmAuthDispatch` runs. Neither side needs the
    /// challenge in the cookie: the acceptor answers the initiator's at
    /// InitAck and checks its own at OpenSyn against a node-local value.
    /// So the one thing that must survive the boundary is the outcome.
    ShmAcceptState
}

flag_accept_state! {
    /// Whether this session negotiated the lowlatency transport shape.
    ///
    /// The one-bool shape is upstream's too:
    /// `io/zenoh-transport/src/unicast/establishment/ext/lowlatency.rs` @
    /// `pub(crate) struct StateAccept`.
    LowlatencyAcceptState
}

flag_accept_state! {
    /// Whether this session negotiated payload compression.
    ///
    /// `io/zenoh-transport/src/unicast/establishment/ext/compression.rs` @
    /// `pub(crate) struct StateAccept` is the same one-bool shape.
    CompressionAcceptState
}

/// The per-handshake challenges the auth methods issued at InitAck and must
/// check at OpenSyn: one per method upstream's auth mux knows.
///
/// R2779 — upstream's is one state per configured method,
/// `io/zenoh-transport/src/unicast/establishment/ext/auth/mod.rs` @ `pub(crate) struct StateAccept {`,
/// and each carries exactly one `u64` across the boundary: usrpwd its nonce,
/// `io/zenoh-transport/src/unicast/establishment/ext/auth/usrpwd.rs` @ `pub(crate) struct StateAccept {`,
/// and pubkey its challenge, the only field its codec writes. So this is two
/// optional `u64`s, and absence is the fact upstream's `Option` states: that
/// method issued no challenge in this handshake.
///
/// KEYED BY METHOD, not by position in the dispatch. The dispatch is an open
/// list and upstream's mux is not, so a method outside the two has no member
/// here; `crate::auth_dispatch::AuthDispatch` leaves such a method holding its
/// own state rather than dropping what nothing could return.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuthAcceptState {
    /// The pubkey method's challenge, or none.
    pub pubkey: Option<u64>,
    /// The usrpwd method's nonce, or none.
    pub usrpwd: Option<u64>,
}

impl AuthAcceptState {
    /// One slot's width: a presence byte, then the value.
    const SLOT: usize = 9;

    /// Presence byte then eight little-endian bytes, the shape
    /// `PatchAcceptState` has and for its reason: every `u64` is a possible
    /// challenge, so no value is left over to mean "none".
    fn encode_slot<S: SceSink>(slot: Option<u64>, sink: &mut S) -> Result<(), CodecError> {
        let (present, value) = match slot {
            Some(v) => (1u8, v),
            None => (0u8, 0),
        };
        sink.write_u8(present)?;
        for b in value.to_le_bytes() {
            sink.write_u8(b)?;
        }
        Ok(())
    }

    /// The inverse, over exactly `Self::SLOT` bytes. Total, for the reason
    /// `PatchAcceptState::decode` gives: the MAC has refused anything this
    /// node did not write before a byte here is read.
    fn decode_slot(raw: &[u8]) -> Option<u64> {
        let mut value = [0u8; 8];
        value.copy_from_slice(&raw[1..Self::SLOT]);
        (raw[0] != 0).then(|| u64::from_le_bytes(value))
    }
}

impl AcceptState for AuthAcceptState {
    /// Two slots of a presence byte and a `u64`.
    const WIDTH: usize = 2 * Self::SLOT;

    fn encode<S: SceSink>(&self, sink: &mut S) -> Result<(), CodecError> {
        Self::encode_slot(self.pubkey, sink)?;
        Self::encode_slot(self.usrpwd, sink)
    }

    fn decode(cursor: &mut SceCursor<'_>) -> Result<Self, CodecError> {
        let raw = cursor.peek_slice(Self::WIDTH)?;
        let state = Self {
            pubkey: Self::decode_slot(&raw[..Self::SLOT]),
            usrpwd: Self::decode_slot(&raw[Self::SLOT..]),
        };
        cursor.advance(Self::WIDTH)?;
        Ok(state)
    }
}

/// The region name the PEER announced on its InitSyn, or none.
///
/// R2780 — upstream carries it in its cookie as the region extension's
/// accept state,
/// `io/zenoh-transport/src/unicast/establishment/ext/region_name.rs` @ `pub(crate) struct StateAccept(State);`,
/// whose one field is `other_region_name`, and hands it out after OpenSyn.
/// wz admitted it off the InitSyn into `peer_region` and held it there
/// across InitAck.
///
/// Held as the name's BYTES — a length and a fixed array — rather than as a
/// `RegionName`, because the group is `Copy + Eq` and `RegionName` is
/// neither: its no-alloc carrier implements no `Eq`, which that type's own
/// note records. A constructed value only ever holds a name `RegionName`
/// admitted, so the way back to one cannot fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RegionAcceptState {
    /// The name's length; zero when there is none. Region names are
    /// non-empty by upstream's own rule, so zero is not a length a name can
    /// have, and upstream's codec uses the empty string for "none" too.
    len: u8,
    /// The name's bytes, zero past `len`.
    bytes: [u8; MAX_REGION_NAME_LEN],
}

impl RegionAcceptState {
    /// The state for a peer that announced `name`, or none.
    pub fn new(name: Option<&RegionName>) -> Self {
        let mut state = Self::default();
        if let Some(name) = name {
            let raw = name.as_str().as_bytes();
            state.len = raw.len() as u8;
            state.bytes[..raw.len()].copy_from_slice(raw);
        }
        state
    }

    /// The announced name, or none.
    pub fn name(&self) -> Option<RegionName> {
        if self.len == 0 {
            return None;
        }
        // Only `new` and `decode` construct a present state, and both admit
        // exactly what `RegionName::new` admits, so neither arm below is
        // reachable; `ok()` rather than a panic keeps a future constructor
        // that forgot the rule a refusal.
        core::str::from_utf8(&self.bytes[..self.len as usize])
            .ok()
            .and_then(|s| RegionName::new(s).ok())
    }
}

impl AcceptState for RegionAcceptState {
    /// A length byte, then the name padded to the longest one upstream
    /// admits, so the width does not depend on the name.
    const WIDTH: usize = 1 + MAX_REGION_NAME_LEN;

    fn encode<S: SceSink>(&self, sink: &mut S) -> Result<(), CodecError> {
        sink.write_u8(self.len)?;
        for b in self.bytes {
            sink.write_u8(b)?;
        }
        Ok(())
    }

    fn decode(cursor: &mut SceCursor<'_>) -> Result<Self, CodecError> {
        let raw = cursor.peek_slice(Self::WIDTH)?;
        let len = raw[0] as usize;
        // Checked here rather than trusted, although the MAC has already
        // refused any payload this node did not write: `name` promises that
        // a present state is a name, and that promise is kept at the one
        // place a state is built from bytes.
        if len > MAX_REGION_NAME_LEN {
            return Err(CodecError::TooManyElements);
        }
        if len > 0 {
            let text =
                core::str::from_utf8(&raw[1..1 + len]).map_err(|_| CodecError::InvalidUtf8)?;
            RegionName::new(text).map_err(|_| CodecError::InvalidUtf8)?;
        }
        let mut bytes = [0u8; MAX_REGION_NAME_LEN];
        bytes[..len].copy_from_slice(&raw[1..1 + len]);
        cursor.advance(Self::WIDTH)?;
        Ok(Self {
            len: len as u8,
            bytes,
        })
    }
}

/// Every extension state the acceptor's cookie carries, as ONE value in the
/// codec's order.
///
/// R2774 — before this was a type, the set was spelled four times: the mint
/// read five slots, the codec wrote five states and read them back, and the
/// rebuild wrote five slots. Four spellings of one set drift one member at a
/// time, and in the direction nothing reports: a state minted and never
/// rebuilt, or rebuilt and never released, passes every witness that does
/// not happen to touch that member. Now the codec belongs to this type, and
/// the session writes its slots from one value whether that value came off
/// the wire or out of this node's offer.
///
/// Upstream's `Cookie` holds the same states flat
/// (`io/zenoh-transport/src/unicast/establishment/cookie.rs` @ `pub(crate) struct Cookie`)
/// and has no need to name the group, because its acceptor drops the whole
/// `State` at InitAck —
/// `io/zenoh-transport/src/unicast/establishment/accept.rs` @ `type SendInitAckIn = (State, SendInitAckIn);`
/// takes it by value. wz's slots outlive the handshake, so wz has a second
/// writer upstream does not: the one that returns them to the offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NegotiatedExtensions {
    /// Whether QoS was negotiated.
    pub qos: QosAcceptState,
    /// Whether shared memory was negotiated.
    pub shm: ShmAcceptState,
    /// The challenges the auth methods issued (R2779). Not an outcome, and
    /// in the group anyway: it crosses the same boundary, is released after
    /// InitAck and rebuilt at OpenSyn by the same one writer, and upstream's
    /// cookie holds it among the extension states, after shm.
    pub auth: AuthAcceptState,
    /// Whether the lowlatency transport shape was negotiated.
    pub lowlatency: LowlatencyAcceptState,
    /// Whether payload compression was negotiated.
    pub compression: CompressionAcceptState,
    /// The negotiated protocol-patch level, or its absence.
    pub patch: PatchAcceptState,
    /// The region name the peer announced (R2780). Like `auth`, not an
    /// outcome of a negotiation and in the group anyway, for the same
    /// reason: same boundary, same one writer, and upstream's cookie holds
    /// it among its extension states, last.
    pub region: RegionAcceptState,
}

impl AcceptState for NegotiatedExtensions {
    const WIDTH: usize = QosAcceptState::WIDTH
        + ShmAcceptState::WIDTH
        + AuthAcceptState::WIDTH
        + LowlatencyAcceptState::WIDTH
        + CompressionAcceptState::WIDTH
        + PatchAcceptState::WIDTH
        + RegionAcceptState::WIDTH;

    fn encode<S: SceSink>(&self, sink: &mut S) -> Result<(), CodecError> {
        self.qos.encode(sink)?;
        self.shm.encode(sink)?;
        self.auth.encode(sink)?;
        self.lowlatency.encode(sink)?;
        self.compression.encode(sink)?;
        self.patch.encode(sink)?;
        self.region.encode(sink)
    }

    // A struct expression evaluates its fields in the order they are
    // written, so this reads in exactly the order `encode` wrote.
    fn decode(cursor: &mut SceCursor<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            qos: QosAcceptState::decode(cursor)?,
            shm: ShmAcceptState::decode(cursor)?,
            auth: AuthAcceptState::decode(cursor)?,
            lowlatency: LowlatencyAcceptState::decode(cursor)?,
            compression: CompressionAcceptState::decode(cursor)?,
            patch: PatchAcceptState::decode(cursor)?,
            region: RegionAcceptState::decode(cursor)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sce_forge_runtime::codec::SliceSink;

    /// Encode through a BOUNDED sink, which is the profile this seam exists
    /// for: `SliceSink` is the one that can report a capacity failure.
    fn round_trip(state: PatchAcceptState) -> (PatchAcceptState, usize) {
        let mut buf = [0u8; 8];
        let written = {
            let mut sink = SliceSink::new(&mut buf);
            state
                .encode(&mut sink)
                .expect("8 bytes fits a 2-byte state");
            sink.position()
        };
        let mut cursor = SceCursor::new(&buf[..written]);
        let back = PatchAcceptState::decode(&mut cursor).expect("what we just wrote decodes");
        (back, written)
    }

    #[test]
    fn a_negotiated_level_survives_the_round_trip() {
        let (back, _) = round_trip(PatchAcceptState(Some(1)));
        assert_eq!(back, PatchAcceptState(Some(1)));
    }

    #[test]
    fn an_absent_level_survives_the_round_trip() {
        let (back, _) = round_trip(PatchAcceptState(None));
        assert_eq!(back, PatchAcceptState(None));
    }

    /// THE DISCRIMINATOR. "No Init has been seen" and "the peer announced
    /// patch 0" are different facts, and
    /// `crates/wz-session-core/src/session_actions.rs` @ `pub fn patch_was_negotiated`
    /// is the reader that tells them apart. Folding this state into upstream's
    /// presence-free byte would make both encode identically, and this is the
    /// test that reds when someone does.
    #[test]
    fn an_absent_level_is_not_a_zero_level() {
        let mut absent = [0u8; 8];
        let mut zero = [0u8; 8];
        let (a_len, z_len) = {
            let mut a = SliceSink::new(&mut absent);
            PatchAcceptState(None).encode(&mut a).unwrap();
            let mut z = SliceSink::new(&mut zero);
            PatchAcceptState(Some(0)).encode(&mut z).unwrap();
            (a.position(), z.position())
        };
        assert_ne!(
            absent[..a_len],
            zero[..z_len],
            "an absent level and a negotiated level 0 must not share an encoding -- \
             a rebuilt acceptor would answer patch_was_negotiated() wrongly"
        );

        let (back_absent, _) = round_trip(PatchAcceptState(None));
        let (back_zero, _) = round_trip(PatchAcceptState(Some(0)));
        assert_eq!(back_absent, PatchAcceptState(None));
        assert_eq!(back_zero, PatchAcceptState(Some(0)));
    }

    /// The width does not depend on the content, which is what lets a cookie
    /// read its members in a fixed order with no length prefix.
    #[test]
    fn the_state_is_two_bytes_whatever_it_carries() {
        let (_, absent) = round_trip(PatchAcceptState(None));
        let (_, present) = round_trip(PatchAcceptState(Some(0xFF)));
        assert_eq!(absent, 2);
        assert_eq!(present, 2);
    }

    /// A bounded sink REPORTS rather than truncating. This is the behaviour
    /// the Inline profile depends on: a cookie that does not fit must fail
    /// loudly at the assembling caller, not arrive short.
    #[test]
    fn a_sink_too_small_reports_rather_than_truncating() {
        let mut buf = [0u8; 1];
        let mut sink = SliceSink::new(&mut buf);
        assert!(
            PatchAcceptState(Some(3)).encode(&mut sink).is_err(),
            "a 2-byte state must not claim success against a 1-byte sink"
        );
    }

    /// A cursor with fewer bytes than the state needs reports instead of
    /// reading past its end.
    #[test]
    fn a_short_cursor_reports_rather_than_reading_past_its_end() {
        let bytes = [PatchAcceptState::PRESENT];
        let mut cursor = SceCursor::new(&bytes);
        assert!(PatchAcceptState::decode(&mut cursor).is_err());
    }

    /// Round-trip one state through a bounded sink and report what it wrote.
    ///
    /// Generic over the trait rather than written per type, because what is
    /// being checked is the TRAIT's contract: encode appends a fixed width,
    /// decode consumes exactly that, and the value survives. A per-type copy
    /// would let a new implementor be added with none of it checked.
    fn width_check<T: AcceptState + PartialEq + core::fmt::Debug>(state: T) -> usize {
        // Sized from the widest implementor rather than written down, so a
        // member added to the group cannot outgrow the check silently.
        let mut buf = [0u8; NegotiatedExtensions::WIDTH];
        let written = {
            let mut sink = SliceSink::new(&mut buf);
            state
                .encode(&mut sink)
                .expect("the group's width fits every state here");
            sink.position()
        };
        let mut cursor = SceCursor::new(&buf[..written]);
        let back = T::decode(&mut cursor).expect("what we just wrote decodes");
        assert_eq!(back, state, "the round trip must return what it was given");
        assert_eq!(
            cursor.remaining(),
            0,
            "decode must consume exactly what encode wrote"
        );
        written
    }

    /// WHAT BINDS `AcceptState::WIDTH` TO THE CODE. The constant is what a
    /// carrier sizes itself from before it parses anything, so a value that
    /// disagreed with `encode` would make the carrier's own length check
    /// consistent and wrong together — the round trip could not catch it,
    /// because both sides would use the same wrong number.
    ///
    /// Every implementor appears here, and the two-valued ones appear twice:
    /// a width that depended on content is exactly what the fixed-order,
    /// no-length-prefix layout cannot survive.
    #[test]
    fn the_declared_width_is_what_each_state_writes() {
        assert_eq!(width_check(PatchAcceptState(None)), PatchAcceptState::WIDTH);
        assert_eq!(
            width_check(PatchAcceptState(Some(0xFF))),
            PatchAcceptState::WIDTH
        );
        for arm in qos_arms() {
            assert_eq!(width_check(arm), QosAcceptState::WIDTH);
        }
        assert_eq!(width_check(ShmAcceptState(true)), ShmAcceptState::WIDTH);
        assert_eq!(width_check(ShmAcceptState(false)), ShmAcceptState::WIDTH);
        for arm in auth_arms() {
            assert_eq!(width_check(arm), AuthAcceptState::WIDTH);
        }
        for arm in region_arms() {
            assert_eq!(width_check(arm), RegionAcceptState::WIDTH);
        }
        assert_eq!(
            width_check(LowlatencyAcceptState(true)),
            LowlatencyAcceptState::WIDTH
        );
        assert_eq!(
            width_check(LowlatencyAcceptState(false)),
            LowlatencyAcceptState::WIDTH
        );
        assert_eq!(
            width_check(CompressionAcceptState(true)),
            CompressionAcceptState::WIDTH
        );
        assert_eq!(
            width_check(CompressionAcceptState(false)),
            CompressionAcceptState::WIDTH
        );
        assert_eq!(
            width_check(NegotiatedExtensions::default()),
            NegotiatedExtensions::WIDTH
        );
    }

    /// Each member of the group survives ALONE.
    ///
    /// One case per member, each setting only that member away from its
    /// default. A fixture that set every member the same way could not see a
    /// decode that read them in a different order than `encode` wrote them —
    /// the swap would hand every field back a value of the same shape.
    #[test]
    fn each_negotiated_member_survives_on_its_own() {
        let base = NegotiatedExtensions::default();
        let cases = [
            NegotiatedExtensions {
                qos: QosAcceptState::Qos {
                    priorities: None,
                    reliability: None,
                },
                ..base
            },
            NegotiatedExtensions {
                shm: ShmAcceptState(true),
                ..base
            },
            NegotiatedExtensions {
                auth: AuthAcceptState {
                    pubkey: Some(7),
                    usrpwd: None,
                },
                ..base
            },
            NegotiatedExtensions {
                lowlatency: LowlatencyAcceptState(true),
                ..base
            },
            NegotiatedExtensions {
                compression: CompressionAcceptState(true),
                ..base
            },
            NegotiatedExtensions {
                patch: PatchAcceptState(Some(1)),
                ..base
            },
            NegotiatedExtensions {
                region: RegionAcceptState::new(Some(&RegionName::new("eu").unwrap())),
                ..base
            },
        ];
        for case in cases {
            assert_ne!(case, base, "ANTI-VACUITY: each case moves one member");
            assert_eq!(width_check(case), NegotiatedExtensions::WIDTH);
        }
    }

    /// A flag state carries BOTH answers distinguishably.
    ///
    /// Anti-vacuity for the round trip above: a state that encoded a constant
    /// would satisfy every `width_check` call and carry nothing.
    ///
    /// ⚠ THE OTHER HALF OF THIS CLAIM IS COMPILE-TIME AND CANNOT BE A TEST:
    /// that the flag states are distinct TYPES, so a carrier cannot read one
    /// into another's field. Substituting `LowlatencyAcceptState` for
    /// `ShmAcceptState` does not compile, and a test asserting that would have
    /// to not compile either.
    #[test]
    fn a_flag_state_carries_both_answers() {
        let mut set = [0u8; 4];
        let mut clear = [0u8; 4];
        let (s_len, c_len) = {
            let mut s = SliceSink::new(&mut set);
            ShmAcceptState(true).encode(&mut s).unwrap();
            let mut c = SliceSink::new(&mut clear);
            ShmAcceptState(false).encode(&mut c).unwrap();
            (s.position(), c.position())
        };
        assert_ne!(
            set[..s_len],
            clear[..c_len],
            "a negotiated flag and a refused one must not share an encoding"
        );
    }

    /// Every distinguishable QoS outcome, including the two pairs a lossy
    /// encoding would merge: QoS WITHOUT a band against no QoS at all, and a
    /// declared best-effort class against no declared class.
    fn qos_arms() -> [QosAcceptState; 6] {
        [
            QosAcceptState::NoQos,
            QosAcceptState::Qos {
                priorities: None,
                reliability: None,
            },
            QosAcceptState::Qos {
                priorities: Some((Priority::RealTime, Priority::Data)),
                reliability: None,
            },
            QosAcceptState::Qos {
                priorities: None,
                reliability: Some(Reliability::BestEffort),
            },
            QosAcceptState::Qos {
                priorities: None,
                reliability: Some(Reliability::Reliable),
            },
            QosAcceptState::Qos {
                priorities: Some((Priority::Control, Priority::Background)),
                reliability: Some(Reliability::Reliable),
            },
        ]
    }

    /// R2777 — every QoS arm survives, and no two share an encoding.
    ///
    /// The pairwise check is what the round trip alone cannot give: an
    /// encoding that wrote `Qos { None, None }` as the `NoQos` bytes would
    /// round-trip each arm to ITSELF only if decode guessed right, and the
    /// two are exactly the outcomes a bool used to fold together.
    #[test]
    fn every_qos_arm_survives_and_no_two_share_an_encoding() {
        let mut seen: [[u8; QosAcceptState::WIDTH]; 6] = [[0; QosAcceptState::WIDTH]; 6];
        for (i, arm) in qos_arms().into_iter().enumerate() {
            assert_eq!(width_check(arm), QosAcceptState::WIDTH);
            let mut sink = SliceSink::new(&mut seen[i]);
            arm.encode(&mut sink).expect("fits");
        }
        for i in 0..seen.len() {
            for j in (i + 1)..seen.len() {
                assert_ne!(
                    seen[i], seen[j],
                    "QoS arms {i} and {j} share an encoding -- a rebuilt \
                     acceptor could not tell them apart"
                );
            }
        }
    }

    /// Every auth state that must stay distinguishable, and none of them
    /// SYMMETRIC: a fixture that put one value in both slots could not see a
    /// decode that read them back swapped.
    fn auth_arms() -> [AuthAcceptState; 6] {
        [
            AuthAcceptState::default(),
            AuthAcceptState {
                pubkey: Some(0),
                usrpwd: None,
            },
            AuthAcceptState {
                pubkey: None,
                usrpwd: Some(0),
            },
            AuthAcceptState {
                pubkey: Some(0x0102_0304_0506_0708),
                usrpwd: None,
            },
            AuthAcceptState {
                pubkey: None,
                usrpwd: Some(0x0102_0304_0506_0708),
            },
            AuthAcceptState {
                pubkey: Some(u64::MAX),
                usrpwd: Some(1),
            },
        ]
    }

    /// R2779 — every auth arm survives, and no two share an encoding.
    ///
    /// The pairs that matter are the ones a lossy encoding would merge: a
    /// challenge of ZERO against no challenge (zero is a value a source can
    /// draw, so it cannot mean "absent"), and the same challenge in the pubkey
    /// slot against the usrpwd slot (a rebuilt acceptor would hand it to the
    /// wrong method, which then refuses a correct OpenSyn).
    #[test]
    fn every_auth_arm_survives_and_no_two_share_an_encoding() {
        let mut seen = [[0u8; AuthAcceptState::WIDTH]; 6];
        for (i, arm) in auth_arms().into_iter().enumerate() {
            assert_eq!(width_check(arm), AuthAcceptState::WIDTH);
            let mut sink = SliceSink::new(&mut seen[i]);
            arm.encode(&mut sink).expect("fits");
        }
        for i in 0..seen.len() {
            for j in (i + 1)..seen.len() {
                assert_ne!(
                    seen[i], seen[j],
                    "auth arms {i} and {j} share an encoding -- a rebuilt \
                     acceptor could not tell them apart"
                );
            }
        }
    }

    /// No region, the shortest name, a name of a different length, and the
    /// longest name upstream admits.
    fn region_arms() -> [RegionAcceptState; 4] {
        [
            RegionAcceptState::default(),
            RegionAcceptState::new(Some(&RegionName::new("a").unwrap())),
            RegionAcceptState::new(Some(&RegionName::new("eu-west").unwrap())),
            RegionAcceptState::new(Some(
                &RegionName::new(&"z".repeat(MAX_REGION_NAME_LEN)).unwrap(),
            )),
        ]
    }

    /// R2780 — every region arm survives as the SAME NAME, and no two share
    /// an encoding.
    ///
    /// The round trip in `width_check` compares the states; this compares the
    /// names they give back, which is what the rebuilt acceptor reads.
    #[test]
    fn every_region_arm_survives_as_the_same_name() {
        let names = [None, Some("a"), Some("eu-west")];
        for (arm, name) in region_arms().into_iter().zip(names) {
            assert_eq!(width_check(arm), RegionAcceptState::WIDTH);
            assert_eq!(arm.name().as_ref().map(RegionName::as_str), name);
        }
        let longest = region_arms()[3].name().expect("the longest name is a name");
        assert_eq!(longest.as_str().len(), MAX_REGION_NAME_LEN);

        let mut seen = [[0u8; RegionAcceptState::WIDTH]; 4];
        for (i, arm) in region_arms().into_iter().enumerate() {
            let mut sink = SliceSink::new(&mut seen[i]);
            arm.encode(&mut sink).expect("fits");
        }
        for i in 0..seen.len() {
            for j in (i + 1)..seen.len() {
                assert_ne!(
                    seen[i], seen[j],
                    "region arms {i} and {j} share an encoding"
                );
            }
        }
    }

    /// A length byte past the longest name is refused rather than read past
    /// the name's array.
    #[test]
    fn a_region_length_past_the_longest_name_is_refused() {
        let mut raw = [0u8; RegionAcceptState::WIDTH];
        raw[0] = (MAX_REGION_NAME_LEN + 1) as u8;
        let mut cursor = SceCursor::new(&raw);
        assert!(RegionAcceptState::decode(&mut cursor).is_err());
    }

    /// A flag state's cursor runs out rather than reading past its end.
    #[test]
    fn a_short_cursor_refuses_a_flag_state_too() {
        let empty: [u8; 0] = [];
        let mut cursor = SceCursor::new(&empty);
        assert!(LowlatencyAcceptState::decode(&mut cursor).is_err());
    }
}
