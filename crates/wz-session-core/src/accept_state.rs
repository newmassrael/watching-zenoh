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
//! Against that struct four things remain, held by the objects that own
//! them: the auth states (the usrpwd nonce and the pubkey challenge), the
//! multilink public key with its challenge, the peer's announced region
//! name, and the cookie's head fields, which ride the cookie but are also
//! still kept in their slots. Upstream's shm accept state is EMPTY, so shm
//! is not among them —
//! `io/zenoh-transport/src/unicast/establishment/ext/shm/auth.rs` @ `pub(crate) type StateAccept = StateOpen;`
//! and its codec writes nothing.

use sce_forge_runtime::codec::{CodecError, SceCursor, SceSink};

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
    /// Whether the lowlatency transport shape was negotiated.
    pub lowlatency: LowlatencyAcceptState,
    /// Whether payload compression was negotiated.
    pub compression: CompressionAcceptState,
    /// The negotiated protocol-patch level, or its absence.
    pub patch: PatchAcceptState,
}

impl AcceptState for NegotiatedExtensions {
    const WIDTH: usize = QosAcceptState::WIDTH
        + ShmAcceptState::WIDTH
        + LowlatencyAcceptState::WIDTH
        + CompressionAcceptState::WIDTH
        + PatchAcceptState::WIDTH;

    fn encode<S: SceSink>(&self, sink: &mut S) -> Result<(), CodecError> {
        self.qos.encode(sink)?;
        self.shm.encode(sink)?;
        self.lowlatency.encode(sink)?;
        self.compression.encode(sink)?;
        self.patch.encode(sink)
    }

    // A struct expression evaluates its fields in the order they are
    // written, so this reads in exactly the order `encode` wrote.
    fn decode(cursor: &mut SceCursor<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            qos: QosAcceptState::decode(cursor)?,
            shm: ShmAcceptState::decode(cursor)?,
            lowlatency: LowlatencyAcceptState::decode(cursor)?,
            compression: CompressionAcceptState::decode(cursor)?,
            patch: PatchAcceptState::decode(cursor)?,
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

    /// A flag state's cursor runs out rather than reading past its end.
    #[test]
    fn a_short_cursor_refuses_a_flag_state_too() {
        let empty: [u8; 0] = [];
        let mut cursor = SceCursor::new(&empty);
        assert!(LowlatencyAcceptState::decode(&mut cursor).is_err());
    }
}
