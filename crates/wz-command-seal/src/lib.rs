// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A lifecycle command sealed by its commander: decision D17 of
//! `docs/session-lifecycle-intent.md`, object security in place of channel security.
//!
//! A channel proves its next hop only, so a command that crossed a router arrives with the
//! router's key, which stands for every commander behind it. A sealed command carries its own
//! proof: a COSE_Sign1 (RFC 9052, section 4) whose payload is the verb, the commanded node's zid,
//! the object and a counter, signed with ES256 by the commander's key, which the object carries.
//! The node derives the commander's zid from that key ([`zid_of_point`]), so the name needs no
//! authority between key and name, and a counter per commander that only rises refuses a replay
//! ([`ReplayWindow`]). This is OSCORE's model (RFC 8613, sections 3 and 7.4) for one object: the
//! router carries it and holds no authority over it. The format is `docs/command-seal.md`.
//!
//! [`open_sealed`] is what a node calls, or [`verify_sealed`] and then [`Verified::take`] when it
//! judges the commander before it takes the counter; [`seal`] is what a commander or a test
//! calls. All run without an allocator. The signature primitives are ports ([`Es256`], [`Es256Signer`]), so a
//! node verifies with what its own TLS library links; the host's are `ring`'s (feature `ring`).

#![no_std]
// Total functions in release code: no panic is reachable from the bytes a node is sent.
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::arithmetic_side_effects
    )
)]

#[cfg(test)]
extern crate std;

mod cbor;
mod fresh;
mod key;
mod replay;
#[cfg(feature = "ring")]
mod ring_es256;

use cbor::{Reader, Writer, MAJOR_ARRAY, MAJOR_BSTR, MAJOR_MAP, MAJOR_NINT, MAJOR_TAG, MAJOR_UINT};
pub use fresh::{Freshness, Restart};
pub use key::{
    point_of_spki, spki_of_point, zid_of_point, zid_of_spki, Zid, COORDINATE_LEN, P256_SPKI_LEN,
    P256_SPKI_PREFIX, POINT_LEN, UNCOMPRESSED, ZID_LEN,
};
pub use replay::ReplayWindow;
#[cfg(feature = "ring")]
pub use ring_es256::{RingEs256, RingSigner};

/// The length of an ES256 signature: r and s, 32 bytes each, big-endian (RFC 9053, section 2.1).
pub const SIGNATURE_LEN: usize = 64;

/// The most bytes a sealed command takes: a reset whose generation and counter need eight bytes
/// each and that carries an echo. A buffer this long holds every command [`seal`] writes.
pub const MAX_SEALED_LEN: usize = 233;

/// The length of an echo: the value a node hands a commander it holds no counter for, which the
/// commander's next command carries (RFC 8613, appendix B.1.2; RFC 9175, section 2).
pub const ECHO_LEN: usize = 16;

/// An echo, as a node draws it and a command carries it.
pub type Echo = [u8; ECHO_LEN];

/// The COSE_Sign1 tag (RFC 9052, section 2).
const COSE_SIGN1_TAG: u64 = 18;

/// The context string of a COSE_Sign1's Sig_structure (RFC 9052, section 4.4).
const SIGNATURE1_CONTEXT: &str = "Signature1";

/// The protected header's length: every item in it has a fixed size.
const PROTECTED_LEN: usize = 83;

/// The longest payload: a reset whose generation and counter need eight bytes each, with an echo.
const MAX_PAYLOAD_LEN: usize = 77;

/// The longest Sig_structure: the context, both headers' strings, the empty external data and
/// the longest payload.
const MAX_TO_BE_SIGNED_LEN: usize = 177;

/// A COSE label or value that is a small integer, as its CBOR head.
type Int = (u8, u64);

/// `alg` (RFC 9052, section 3.1).
const LABEL_ALG: Int = (MAJOR_UINT, 1);
/// `kccs`: a CWT Claims Set holding a COSE_Key in a `cnf` claim (RFC 9528, section 3.5.2).
const LABEL_KCCS: Int = (MAJOR_UINT, 14);
/// The `cnf` claim (RFC 8747, section 3.1).
const CLAIM_CNF: Int = (MAJOR_UINT, 8);
/// The `COSE_Key` member of a `cnf` claim (RFC 8747, section 3.2).
const CNF_COSE_KEY: Int = (MAJOR_UINT, 1);
/// `kty`, `crv`, `x` and `y` of an EC2 COSE_Key (RFC 9052, section 7.1; RFC 9053, section
/// 7.1.1), in the order the deterministic encoding sorts them.
const KEY_KTY: Int = (MAJOR_UINT, 1);
const KEY_CRV: Int = (MAJOR_NINT, 0);
const KEY_X: Int = (MAJOR_NINT, 1);
const KEY_Y: Int = (MAJOR_NINT, 2);
/// ES256, `-7` (RFC 9053, section 2.1).
const ALG_ES256: Int = (MAJOR_NINT, 6);
/// The EC2 key type (RFC 9053, section 7.1).
const KTY_EC2: Int = (MAJOR_UINT, 2);
/// The P-256 curve (RFC 9053, section 7.1).
const CRV_P256: Int = (MAJOR_UINT, 1);

/// Why a sealed command was refused, or could not be sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// The bytes are not the format: an item of another kind or count where the format has one,
    /// a map's keys in another order, an unknown verb, a generation on a verb that takes none or
    /// none on a reset, a zid not of sixteen bytes, or bytes after the object.
    Malformed,
    /// Well-formed CBOR, but not its deterministic encoding (RFC 8949, section 4.2.1): an
    /// argument longer than its value needs, or an indefinite length.
    NonCanonical,
    /// The protected header names an algorithm other than ES256.
    Algorithm,
    /// The key is not an uncompressed P-256 key in an EC2 COSE_Key, or a signer has no such key.
    Key,
    /// The command is for another node.
    WrongNode,
    /// The signature does not verify under the key the object carries.
    BadSignature,
    /// The counter is not above the last one taken from this commander.
    Replay {
        /// The last counter taken from the commander.
        last: u64,
    },
    /// The node holds counters for as many commanders as it has room for, and this commander is
    /// not one of them.
    WindowFull,
    /// The node holds no counter for this commander and the command does not carry the echo the
    /// node drew when it started, so it may be a command sealed before the node last started: the
    /// commander repeats it, under a new counter, carrying `echo` (RFC 8613, appendix B.1.2).
    EchoRequired {
        /// The echo the repeated command carries.
        echo: Echo,
    },
    /// The buffer given to [`seal`] cannot hold the object.
    BufferTooSmall,
    /// The signer did not sign.
    Signer,
}

impl core::fmt::Display for SealError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed => f.write_str("not a sealed command"),
            Self::NonCanonical => f.write_str("not the deterministic encoding"),
            Self::Algorithm => f.write_str("an algorithm other than ES256"),
            Self::Key => f.write_str("not an uncompressed P-256 key"),
            Self::WrongNode => f.write_str("a command for another node"),
            Self::BadSignature => f.write_str("the signature does not verify"),
            Self::Replay { last } => write!(f, "a replay: the last counter taken is {last}"),
            Self::WindowFull => f.write_str("no room for another commander's counter"),
            Self::EchoRequired { .. } => f.write_str("the command must carry the node's echo"),
            Self::BufferTooSmall => f.write_str("the buffer cannot hold the sealed command"),
            Self::Signer => f.write_str("the signer did not sign"),
        }
    }
}

/// The verb a command asks, by the word a lifecycle key spells it with. The passive open is a
/// verb of its own because the key spells it apart (`open/passive`), and a command that bound
/// only the word `open` could be carried to the other mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// Hold the peer by dialling it.
    Open,
    /// Hold the peer by waiting for its own session.
    OpenPassive,
    /// Close every session with the peer and withdraw it from the intent.
    Close,
    /// Close every session with the peer once per generation.
    Reset,
    /// Read what the node holds for the peer.
    Status,
}

impl Verb {
    /// Every verb.
    pub const ALL: [Self; 5] = [
        Self::Open,
        Self::OpenPassive,
        Self::Close,
        Self::Reset,
        Self::Status,
    ];

    /// The word the payload carries.
    pub const fn word(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::OpenPassive => "open_passive",
            Self::Close => "close",
            Self::Reset => "reset",
            Self::Status => "status",
        }
    }

    /// The verb `word` names, or `None` for a word that is no verb.
    pub fn of_word(word: &[u8]) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|verb| verb.word().as_bytes() == word)
    }

    /// Whether the object of this verb carries a generation: a reset's, and no other's.
    pub const fn takes_generation(self) -> bool {
        matches!(self, Self::Reset)
    }
}

/// What a verb acts on: the peer, and a reset's generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Object {
    /// The peer the verb acts on.
    pub peer: Zid,
    /// The generation of a reset; `None` for every other verb.
    pub generation: Option<u64>,
}

/// A command as its commander writes it, before it is sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Command {
    /// The verb.
    pub verb: Verb,
    /// The node commanded.
    pub node: Zid,
    /// What the verb acts on.
    pub object: Object,
    /// The commander's counter, above every one it sealed before.
    pub counter: u64,
    /// The echo the node handed the commander, when the command repeats one the node refused
    /// for want of it ([`SealError::EchoRequired`]); `None` otherwise.
    pub echo: Option<Echo>,
}

/// A sealed command a node opened: who commanded what.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sealed {
    /// The zid of the key that signed the command.
    pub commander: Zid,
    /// The verb.
    pub verb: Verb,
    /// What the verb acts on.
    pub object: Object,
    /// The counter the node took.
    pub counter: u64,
    /// The echo the command carried, if any.
    pub echo: Option<Echo>,
}

/// Verifies ES256: ECDSA over P-256 with SHA-256 (RFC 9053, section 2.1).
///
/// A port because a node verifies with the primitives it already links: `ring` on a host
/// (`RingEs256`, feature `ring`), the TLS library's on a fixed-memory node.
pub trait Es256 {
    /// Whether `signature` (r then s, 32 bytes each, big-endian) is an ES256 signature of
    /// `message` by the key `point` (an uncompressed point, `0x04`, x, y). The message is
    /// hashed here, with SHA-256. A point that is not on the curve verifies nothing.
    fn verify(
        &self,
        point: &[u8; POINT_LEN],
        message: &[u8],
        signature: &[u8; SIGNATURE_LEN],
    ) -> bool;
}

/// Signs ES256 with one key.
pub trait Es256Signer {
    /// The key's uncompressed point.
    fn point(&self) -> [u8; POINT_LEN];
    /// The ES256 signature of `message` (r then s), or `None` if the signer could not sign.
    fn sign(&self, message: &[u8]) -> Option<[u8; SIGNATURE_LEN]>;
}

/// Open the sealed command `bytes` sent to the node `this_node`: who commanded what.
///
/// Refused, in this order: bytes that are not the format or not its deterministic encoding, an
/// algorithm other than ES256, a key that is not P-256, a command for another node, a signature
/// that does not verify, and a counter the window does not take. The counter is taken only from a
/// command whose signature verified, so a forged object moves no commander's counter.
///
/// [`verify_sealed`] and [`Verified::take`] are the same two steps apart, for a node that
/// judges the commander between them.
pub fn open_sealed<E, const N: usize>(
    bytes: &[u8],
    this_node: &Zid,
    window: &mut ReplayWindow<N>,
    es256: &E,
) -> Result<Sealed, SealError>
where
    E: Es256 + ?Sized,
{
    verify_sealed(bytes, this_node, es256)?.take(window)
}

/// A sealed command whose signature verified and whose counter is not taken yet.
///
/// Anyone can make a key and seal a command its own signature verifies, so a node that took the
/// counter of every verified command would give a slot of its window to every key that writes
/// to it, and a full window refuses the commanders it grants. A node judges the commander first
/// and takes the counter of a command it permits; one it refuses takes no slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a verified command is not fresh until its counter is taken"]
pub struct Verified {
    sealed: Sealed,
}

impl Verified {
    /// Who commanded what, as the object says. Not yet fresh: a replay verifies as well as the
    /// first copy did.
    pub const fn sealed(&self) -> &Sealed {
        &self.sealed
    }

    /// Take the counter from the window: the command, unless the counter is not above the
    /// commander's last or the window has no room for the commander.
    pub fn take<const N: usize>(self, window: &mut ReplayWindow<N>) -> Result<Sealed, SealError> {
        window.accept(&self.sealed.commander, self.sealed.counter)?;
        Ok(self.sealed)
    }
}

/// Verify the sealed command `bytes` sent to the node `this_node`, taking no counter: the
/// refusals of [`open_sealed`] but the replay window's.
pub fn verify_sealed<E>(bytes: &[u8], this_node: &Zid, es256: &E) -> Result<Verified, SealError>
where
    E: Es256 + ?Sized,
{
    let parts = parse(bytes)?;
    if parts.command.node != *this_node {
        return Err(SealError::WrongNode);
    }
    let mut to_be_signed = [0u8; MAX_TO_BE_SIGNED_LEN];
    let len = write_to_be_signed(parts.protected, parts.payload, &mut to_be_signed)
        .map_err(|_| SealError::Malformed)?;
    let message = to_be_signed.get(..len).ok_or(SealError::Malformed)?;
    if !es256.verify(&parts.point, message, &parts.signature) {
        return Err(SealError::BadSignature);
    }
    Ok(Verified {
        sealed: Sealed {
            commander: zid_of_point(&parts.point),
            verb: parts.command.verb,
            object: parts.command.object,
            counter: parts.command.counter,
            echo: parts.command.echo,
        },
    })
}

/// Seal `command` with `signer`'s key into `out`: how many bytes the sealed command took.
///
/// Refused as [`SealError::Malformed`] for a command whose generation does not match its verb
/// (a reset carries one, no other verb does), as [`SealError::Key`] for a signer whose point is
/// not uncompressed, and as [`SealError::BufferTooSmall`] when `out` cannot hold the object
/// ([`MAX_SEALED_LEN`] always can).
pub fn seal<S>(command: &Command, signer: &S, out: &mut [u8]) -> Result<usize, SealError>
where
    S: Es256Signer + ?Sized,
{
    if command.verb.takes_generation() != command.object.generation.is_some() {
        return Err(SealError::Malformed);
    }
    let point = signer.point();
    let mut protected = [0u8; PROTECTED_LEN];
    let protected_len = write_protected(&point, &mut protected)?;
    let protected = protected.get(..protected_len).ok_or(SealError::Malformed)?;
    let mut payload = [0u8; MAX_PAYLOAD_LEN];
    let payload_len = write_payload(command, &mut payload)?;
    let payload = payload.get(..payload_len).ok_or(SealError::Malformed)?;
    let mut to_be_signed = [0u8; MAX_TO_BE_SIGNED_LEN];
    let len = write_to_be_signed(protected, payload, &mut to_be_signed)?;
    let message = to_be_signed.get(..len).ok_or(SealError::Malformed)?;
    let signature = signer.sign(message).ok_or(SealError::Signer)?;
    write_sign1(protected, payload, &signature, out)
}

/// The parts of a COSE_Sign1 that was read: the strings as sent, which the Sig_structure takes
/// as they are, and what they say.
struct Parts<'a> {
    protected: &'a [u8],
    payload: &'a [u8],
    point: [u8; POINT_LEN],
    command: Command,
    signature: [u8; SIGNATURE_LEN],
}

/// Read a COSE_Sign1: tag 18, then `[protected, unprotected, payload, signature]`. The
/// unprotected header is empty, because everything the node reads is signed.
fn parse(bytes: &[u8]) -> Result<Parts<'_>, SealError> {
    let mut reader = Reader::new(bytes);
    reader.expect((MAJOR_TAG, COSE_SIGN1_TAG))?;
    reader.expect((MAJOR_ARRAY, 4))?;
    let protected = reader.bstr()?;
    let point = read_protected(protected)?;
    reader.expect((MAJOR_MAP, 0))?;
    let payload = reader.bstr()?;
    let command = read_payload(payload)?;
    let signature = reader.bstr_array::<SIGNATURE_LEN>()?;
    reader.end()?;
    Ok(Parts {
        protected,
        payload,
        point,
        command,
        signature,
    })
}

/// Read the protected header, `{1: -7, 14: {8: {1: COSE_Key}}}`: the algorithm and the key.
fn read_protected(bytes: &[u8]) -> Result<[u8; POINT_LEN], SealError> {
    let mut reader = Reader::new(bytes);
    reader.expect((MAJOR_MAP, 2))?;
    reader.expect(LABEL_ALG)?;
    match reader.head()? {
        ALG_ES256 => {}
        (MAJOR_UINT | MAJOR_NINT, _) => return Err(SealError::Algorithm),
        _ => return Err(SealError::Malformed),
    }
    reader.expect(LABEL_KCCS)?;
    reader.expect((MAJOR_MAP, 1))?;
    reader.expect(CLAIM_CNF)?;
    reader.expect((MAJOR_MAP, 1))?;
    reader.expect(CNF_COSE_KEY)?;
    reader.expect((MAJOR_MAP, 4))?;
    reader.expect(KEY_KTY)?;
    if reader.head()? != KTY_EC2 {
        return Err(SealError::Key);
    }
    reader.expect(KEY_CRV)?;
    if reader.head()? != CRV_P256 {
        return Err(SealError::Key);
    }
    reader.expect(KEY_X)?;
    let x = read_coordinate(&mut reader)?;
    reader.expect(KEY_Y)?;
    let y = read_coordinate(&mut reader)?;
    reader.end()?;
    Ok(point_of(&x, &y))
}

/// One coordinate of an EC2 key: a byte string of 32 bytes. A `y` written as a sign bit (a
/// compressed point) is refused: the zid is the hash of the uncompressed key.
fn read_coordinate(reader: &mut Reader<'_>) -> Result<[u8; COORDINATE_LEN], SealError> {
    if reader.head()? != (MAJOR_BSTR, COORDINATE_LEN as u64) {
        return Err(SealError::Key);
    }
    reader.raw_array::<COORDINATE_LEN>()
}

/// The uncompressed point of `x` and `y`.
fn point_of(x: &[u8; COORDINATE_LEN], y: &[u8; COORDINATE_LEN]) -> [u8; POINT_LEN] {
    let mut point = [0u8; POINT_LEN];
    let (tag, coordinates) = point.split_at_mut(1);
    let (into_x, into_y) = coordinates.split_at_mut(COORDINATE_LEN);
    tag.copy_from_slice(&[UNCOMPRESSED]);
    into_x.copy_from_slice(x);
    into_y.copy_from_slice(y);
    point
}

/// Read the payload, `[verb, node, [peer, generation or null], counter]`, with the echo as a
/// fifth item when the command carries one.
fn read_payload(bytes: &[u8]) -> Result<Command, SealError> {
    let mut reader = Reader::new(bytes);
    let echoed = match reader.head()? {
        (MAJOR_ARRAY, 4) => false,
        (MAJOR_ARRAY, 5) => true,
        _ => return Err(SealError::Malformed),
    };
    let verb = Verb::of_word(reader.tstr()?).ok_or(SealError::Malformed)?;
    let node = reader.bstr_array::<ZID_LEN>()?;
    reader.expect((MAJOR_ARRAY, 2))?;
    let peer = reader.bstr_array::<ZID_LEN>()?;
    let generation = reader.uint_or_null()?;
    let counter = reader.uint()?;
    let echo = if echoed {
        Some(reader.bstr_array::<ECHO_LEN>()?)
    } else {
        None
    };
    reader.end()?;
    if verb.takes_generation() != generation.is_some() {
        return Err(SealError::Malformed);
    }
    Ok(Command {
        verb,
        node,
        object: Object { peer, generation },
        counter,
        echo,
    })
}

fn write_protected(point: &[u8; POINT_LEN], out: &mut [u8]) -> Result<usize, SealError> {
    let (tag, coordinates) = point.split_first().ok_or(SealError::Key)?;
    if *tag != UNCOMPRESSED {
        return Err(SealError::Key);
    }
    let (x, y) = coordinates
        .split_at_checked(COORDINATE_LEN)
        .ok_or(SealError::Key)?;
    let mut writer = Writer::new(out);
    writer.head((MAJOR_MAP, 2))?;
    writer.head(LABEL_ALG)?;
    writer.head(ALG_ES256)?;
    writer.head(LABEL_KCCS)?;
    writer.head((MAJOR_MAP, 1))?;
    writer.head(CLAIM_CNF)?;
    writer.head((MAJOR_MAP, 1))?;
    writer.head(CNF_COSE_KEY)?;
    writer.head((MAJOR_MAP, 4))?;
    writer.head(KEY_KTY)?;
    writer.head(KTY_EC2)?;
    writer.head(KEY_CRV)?;
    writer.head(CRV_P256)?;
    writer.head(KEY_X)?;
    writer.bstr(x)?;
    writer.head(KEY_Y)?;
    writer.bstr(y)?;
    Ok(writer.len())
}

fn write_payload(command: &Command, out: &mut [u8]) -> Result<usize, SealError> {
    let mut writer = Writer::new(out);
    let items = if command.echo.is_some() { 5 } else { 4 };
    writer.head((MAJOR_ARRAY, items))?;
    writer.tstr(command.verb.word())?;
    writer.bstr(&command.node)?;
    writer.head((MAJOR_ARRAY, 2))?;
    writer.bstr(&command.object.peer)?;
    match command.object.generation {
        Some(generation) => writer.head((MAJOR_UINT, generation))?,
        None => writer.null()?,
    }
    writer.head((MAJOR_UINT, command.counter))?;
    if let Some(echo) = &command.echo {
        writer.bstr(echo)?;
    }
    Ok(writer.len())
}

/// The Sig_structure of a COSE_Sign1 (RFC 9052, section 4.4): `["Signature1", protected,
/// external_aad, payload]`, with no external data.
fn write_to_be_signed(
    protected: &[u8],
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, SealError> {
    let mut writer = Writer::new(out);
    writer.head((MAJOR_ARRAY, 4))?;
    writer.tstr(SIGNATURE1_CONTEXT)?;
    writer.bstr(protected)?;
    writer.bstr(&[])?;
    writer.bstr(payload)?;
    Ok(writer.len())
}

fn write_sign1(
    protected: &[u8],
    payload: &[u8],
    signature: &[u8; SIGNATURE_LEN],
    out: &mut [u8],
) -> Result<usize, SealError> {
    let mut writer = Writer::new(out);
    writer.head((MAJOR_TAG, COSE_SIGN1_TAG))?;
    writer.head((MAJOR_ARRAY, 4))?;
    writer.bstr(protected)?;
    writer.head((MAJOR_MAP, 0))?;
    writer.bstr(payload)?;
    writer.bstr(signature)?;
    Ok(writer.len())
}

#[cfg(test)]
mod tests;
