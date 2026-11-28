// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A lifecycle query that carries a sealed command (decision D17 of
//! `docs/session-lifecycle-intent.md`, the format `docs/command-seal.md`): what the in-band entry
//! point of either profile does with the query's attachment before and after the reference monitor
//! judges it.
//!
//! The order, the same on both profiles: the object is verified against this node's zid, it must
//! be the request its key names (the verb, the peer, a reset's generation), and it must be fresh
//! (its counter above its commander's last, and the node's echo carried by a commander the node
//! holds no counter for); then the monitor judges the request with the commander the key proved,
//! `Commander::Sealed`, and only a permit takes the counter ([`SealedNode`] gives the monitor the
//! admission that takes it), before any effect. A query whose attachment fails any of it is
//! refused by name, in a document of the lifecycle verbs' words ([`SealRefused::write_json`]),
//! and is never judged as the commander of the link it came over: a sealed command that fails is a
//! claim that failed, not an absent one. A query with no attachment is judged as it always was.
//!
//! A router forwards a query's attachment as it received it: upstream's router clones the request
//! body, which holds the attachment (`zenoh/src/net/routing/dispatcher/queries.rs` @
//! `payload: msg.payload.clone(),`; `commons/zenoh-protocol/src/zenoh/query.rs` @
//! `pub ext_attachment: Option<ext::AttachmentType>,`), and wz's router clones the whole request
//! and rewrites only its source, key and id (`crates/wz-runtime-tokio/src/router_forward.rs` @
//! `let mut carrier = request.clone();`).

use crate::lifecycle_monitor::{Admission, Monitor};
use crate::lifecycle_node::{Command, Generation, LifecycleNode, Verb, Zid};
use crate::lifecycle_wire::{CloseOrder, MachineReport, OpenMode, OpenOutcome, SessionLinks};
use crate::text_out::TextOut;

#[cfg(feature = "sealed-commands")]
pub use wz_command_seal as seal;

/// The bytes of an echo, as a refusal hands it out.
pub const ECHO_BYTES: usize = 16;

#[cfg(feature = "sealed-commands")]
const _: () = assert!(ECHO_BYTES == seal::ECHO_LEN);

/// Why a lifecycle query that carried a sealed command was refused before the monitor judged it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealRefused {
    /// The node verifies no sealed command: built without `sealed-commands`, or its entry point
    /// was given no verifier.
    NotVerified,
    /// The sealed command is not the request its key names: another verb, peer or generation.
    NotTheRequest,
    /// The attachment is not a sealed command.
    Malformed,
    /// The sealed command is not in its deterministic encoding.
    NonCanonical,
    /// The sealed command is signed with an algorithm other than ES256.
    Algorithm,
    /// The sealed command's key is not an uncompressed P-256 key.
    Key,
    /// The sealed command is for another node.
    WrongNode,
    /// The sealed command's signature does not verify under the key it carries.
    BadSignature,
    /// The command's counter is not above the last one taken from its commander.
    Replay {
        /// The last counter taken from the commander.
        last: u64,
    },
    /// The node has no room for another commander's counter.
    WindowFull,
    /// The node holds no counter for the commander and the command does not carry the echo the
    /// node drew when it last started: the commander repeats the command, under a new counter,
    /// carrying `echo` (RFC 8613, appendix B.1.2).
    EchoRequired {
        /// The echo the repeated command carries.
        echo: [u8; ECHO_BYTES],
    },
}

impl SealRefused {
    /// The reason, as a refusal document says it.
    pub const fn words(self) -> &'static str {
        match self {
            Self::NotVerified => "this node verifies no sealed command",
            Self::NotTheRequest => "the sealed command is not the request its key names",
            Self::Malformed => "the attachment is not a sealed command",
            Self::NonCanonical => "the sealed command is not in its deterministic encoding",
            Self::Algorithm => "the sealed command is signed with an algorithm other than ES256",
            Self::Key => "the key of the sealed command is not an uncompressed P-256 key",
            Self::WrongNode => "the sealed command is for another node",
            Self::BadSignature => "the signature of the sealed command does not verify",
            Self::Replay { .. } => {
                "the counter of the sealed command is not above its commander's last"
            }
            Self::WindowFull => "this node has no room for another commander's counter",
            Self::EchoRequired { .. } => "the sealed command must carry this node's echo",
        }
    }

    /// The refusal document: `{"verdict":"refused","reason":"..."}` as every lifecycle verb
    /// refuses, with the commander's last counter beside a replay (`"last":N`) and the echo beside
    /// its challenge (`"echo":"<32 lowercase hex digits>"`, the echo's bytes in order).
    pub fn write_json<W: TextOut + ?Sized>(&self, out: &mut W) {
        out.push_str("{\"verdict\":\"refused\",\"reason\":\"");
        out.push_str(self.words());
        out.push('"');
        match self {
            Self::Replay { last } => {
                out.push_str(",\"last\":");
                out.push_u64(*last);
            }
            Self::EchoRequired { echo } => {
                out.push_str(",\"echo\":\"");
                for byte in echo {
                    for nibble in [byte.checked_shr(4).unwrap_or(0), byte & 0x0f] {
                        out.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
                    }
                }
                out.push('"');
            }
            _ => {}
        }
        out.push('}');
    }
}

#[cfg(feature = "sealed-commands")]
impl From<seal::SealError> for SealRefused {
    fn from(error: seal::SealError) -> Self {
        use seal::SealError;
        match error {
            // The two refusals of sealing, which opening never answers.
            SealError::Malformed | SealError::BufferTooSmall | SealError::Signer => Self::Malformed,
            SealError::NonCanonical => Self::NonCanonical,
            SealError::Algorithm => Self::Algorithm,
            SealError::Key => Self::Key,
            SealError::WrongNode => Self::WrongNode,
            SealError::BadSignature => Self::BadSignature,
            SealError::Replay { last } => Self::Replay { last },
            SealError::WindowFull => Self::WindowFull,
            SealError::EchoRequired { echo } => Self::EchoRequired { echo },
        }
    }
}

/// A node's verifier of sealed commands: its zid, its ES256 and its freshness. A port, because
/// each profile keeps the freshness where its state lives (in the heap node's queries, in a static
/// behind a critical section on the fixed node) and verifies with the signature code it links.
/// Without `sealed-commands` it has no method, and a node verifies nothing.
pub trait SealVerifier {
    /// Verify `bytes` as a sealed command to this node, taking no counter.
    #[cfg(feature = "sealed-commands")]
    fn verify(&self, bytes: &[u8]) -> Result<seal::Verified, SealRefused>;

    /// Whether the command would be taken ([`seal::Freshness::check`]), taking nothing.
    #[cfg(feature = "sealed-commands")]
    fn check(&self, sealed: &seal::Sealed) -> Result<(), SealRefused>;

    /// Take the command's counter ([`seal::Freshness::take`]).
    #[cfg(feature = "sealed-commands")]
    fn take(&self, verified: seal::Verified) -> Result<seal::Sealed, SealRefused>;
}

/// The verifier of a node whose queries are answered one at a time on one thread (the heap
/// profile's `LifecycleQueries`): its zid, its ES256 and its freshness, in a cell.
#[cfg(feature = "sealed-commands")]
pub struct SealedCommands<E, const N: usize> {
    node: Zid,
    es256: E,
    fresh: core::cell::RefCell<seal::Freshness<N>>,
}

#[cfg(feature = "sealed-commands")]
impl<E, const N: usize> SealedCommands<E, N> {
    /// The verifier of the node `node`, verifying with `es256`, fresh as `fresh` says: after a
    /// start, [`seal::Freshness::echo`] with an echo drawn from the host's entropy.
    pub const fn new(node: Zid, es256: E, fresh: seal::Freshness<N>) -> Self {
        Self {
            node,
            es256,
            fresh: core::cell::RefCell::new(fresh),
        }
    }
}

#[cfg(feature = "sealed-commands")]
impl<E: seal::Es256, const N: usize> SealVerifier for SealedCommands<E, N> {
    fn verify(&self, bytes: &[u8]) -> Result<seal::Verified, SealRefused> {
        seal::verify_sealed(bytes, &self.node, &self.es256).map_err(SealRefused::from)
    }

    fn check(&self, sealed: &seal::Sealed) -> Result<(), SealRefused> {
        self.fresh
            .try_borrow()
            .map_err(|_| SealRefused::NotVerified)?
            .check(sealed)
            .map_err(SealRefused::from)
    }

    fn take(&self, verified: seal::Verified) -> Result<seal::Sealed, SealRefused> {
        self.fresh
            .try_borrow_mut()
            .map_err(|_| SealRefused::NotVerified)?
            .take(verified)
            .map_err(SealRefused::from)
    }
}

/// What the attachment of a lifecycle query makes of its commander.
pub enum Claimed<'v> {
    /// No attachment: the commander is whom the link proved, as it always was.
    Channel,
    /// A sealed command, verified, the request its key names and fresh: the commander is the zid
    /// of its key, and the node is judged through [`SealedNode`] with [`SealedClaim::admission`].
    Sealed(SealedClaim<'v>),
    /// Refused before the monitor: the reply is this refusal's document.
    Refused(SealRefused),
}

/// A sealed command an entry point verified: its commander and the admission that takes its
/// counter once the monitor permits it. Without `sealed-commands` none is ever made.
pub struct SealedClaim<'v> {
    #[cfg(feature = "sealed-commands")]
    commander: Zid,
    #[cfg(feature = "sealed-commands")]
    admission: SealAdmission<'v>,
    #[cfg(not(feature = "sealed-commands"))]
    never: core::convert::Infallible,
    #[cfg(not(feature = "sealed-commands"))]
    verifier: core::marker::PhantomData<&'v ()>,
}

impl SealedClaim<'_> {
    /// The zid of the key the command was signed with: the subject the monitor judges.
    #[cfg(feature = "sealed-commands")]
    pub fn commander(&self) -> &Zid {
        &self.commander
    }

    /// The zid of the key the command was signed with: the subject the monitor judges.
    #[cfg(not(feature = "sealed-commands"))]
    pub fn commander(&self) -> &Zid {
        let _ = self.verifier;
        match self.never {}
    }

    /// What takes the command's counter once the monitor permits it.
    #[cfg(feature = "sealed-commands")]
    pub fn admission(&self) -> &dyn Admission {
        &self.admission
    }

    /// What takes the command's counter once the monitor permits it.
    #[cfg(not(feature = "sealed-commands"))]
    pub fn admission(&self) -> &dyn Admission {
        match self.never {}
    }
}

/// Read the attachment of a lifecycle query that asks `command`: no attachment is the link's
/// commander; an attachment is a sealed command, opened with `verifier`, and refused by name when
/// the node has no verifier or the command is not verified, not the request or not fresh.
pub fn claim<'v>(
    attachment: Option<&[u8]>,
    command: &Command<'_>,
    verifier: Option<&'v dyn SealVerifier>,
) -> Claimed<'v> {
    let Some(bytes) = attachment else {
        return Claimed::Channel;
    };
    #[cfg(feature = "sealed-commands")]
    {
        if let Some(verifier) = verifier {
            return opened(bytes, command, verifier);
        }
    }
    #[cfg(not(feature = "sealed-commands"))]
    let _ = (bytes, command, verifier);
    Claimed::Refused(SealRefused::NotVerified)
}

#[cfg(feature = "sealed-commands")]
fn opened<'v>(bytes: &[u8], command: &Command<'_>, verifier: &'v dyn SealVerifier) -> Claimed<'v> {
    let verified = match verifier.verify(bytes) {
        Ok(verified) => verified,
        Err(refused) => return Claimed::Refused(refused),
    };
    let sealed = *verified.sealed();
    if !is_the_request(command, &sealed) {
        return Claimed::Refused(SealRefused::NotTheRequest);
    }
    if let Err(refused) = verifier.check(&sealed) {
        return Claimed::Refused(refused);
    }
    Claimed::Sealed(SealedClaim {
        commander: sealed.commander,
        admission: SealAdmission {
            verifier,
            verified: core::cell::Cell::new(Some(verified)),
        },
    })
}

/// Whether `sealed` is the request `command` asks: the verb with its open mode, the peer the key
/// spells, and a reset's generation. A router must not carry a sealed command onto another key.
#[cfg(feature = "sealed-commands")]
fn is_the_request(command: &Command<'_>, sealed: &seal::Sealed) -> bool {
    use seal::Verb as Sealed;
    let (verb, peer, generation) = match *command {
        Command::Open {
            peer,
            mode: OpenMode::Dial,
        } => (Sealed::Open, peer, None),
        Command::Open {
            peer,
            mode: OpenMode::Passive,
        } => (Sealed::OpenPassive, peer, None),
        Command::Close { peer } => (Sealed::Close, peer, None),
        Command::Reset { peer, generation } => (Sealed::Reset, peer, Some(generation)),
        Command::Status { peer } => (Sealed::Status, peer, None),
    };
    let generation = match generation {
        Some(text) => match text.parse::<u64>() {
            Ok(number) => Some(number),
            Err(_) => return false,
        },
        None => None,
    };
    verb == sealed.verb
        && generation == sealed.object.generation
        && crate::credential_identity::zid_from_key_text(peer) == Some(sealed.object.peer)
}

/// Takes a verified command's counter when the monitor permits its commander, once.
#[cfg(feature = "sealed-commands")]
struct SealAdmission<'v> {
    verifier: &'v dyn SealVerifier,
    verified: core::cell::Cell<Option<seal::Verified>>,
}

#[cfg(feature = "sealed-commands")]
impl Admission for SealAdmission<'_> {
    fn admit(
        &self,
        _request: &crate::lifecycle_monitor::Request<'_>,
    ) -> Result<(), crate::lifecycle_monitor::Refusal> {
        let refused = crate::lifecycle_monitor::Refusal::NotFresh;
        let verified = self.verified.take().ok_or(refused)?;
        self.verifier
            .take(verified)
            .map(|_| ())
            .map_err(|_| refused)
    }
}

/// A stand-in for ES256 in the tests of an entry point: the signature of a message is its SHA-256
/// twice over, which a change to any signed byte breaks, and a point names a commander as a key
/// does. It proves nothing about anyone, so it is compiled only for tests.
#[cfg(all(feature = "sealed-commands", any(test, feature = "lifecycle-contract")))]
pub mod witness {
    use super::seal::{
        seal, zid_of_point, Command, Es256, Es256Signer, SealError, MAX_SEALED_LEN, POINT_LEN,
        SIGNATURE_LEN, UNCOMPRESSED,
    };
    use super::Zid;
    use sha2::{Digest, Sha256};

    /// Verifies what [`DigestSigner`] signs.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct DigestEs256;

    impl Es256 for DigestEs256 {
        fn verify(
            &self,
            _point: &[u8; POINT_LEN],
            message: &[u8],
            signature: &[u8; SIGNATURE_LEN],
        ) -> bool {
            *signature == digest_twice(message)
        }
    }

    /// A commander whose point is `0x04` and then 64 bytes of its value: one value, one zid.
    #[derive(Debug, Clone, Copy)]
    pub struct DigestSigner(pub u8);

    impl DigestSigner {
        /// The zid a node derives for this commander.
        pub fn commander(&self) -> Zid {
            zid_of_point(&self.point())
        }

        /// `command` sealed by this commander, and its length.
        pub fn sealed(
            &self,
            command: &Command,
        ) -> Result<([u8; MAX_SEALED_LEN], usize), SealError> {
            let mut out = [0u8; MAX_SEALED_LEN];
            let len = seal(command, self, &mut out)?;
            Ok((out, len))
        }
    }

    impl Es256Signer for DigestSigner {
        fn point(&self) -> [u8; POINT_LEN] {
            let mut point = [self.0; POINT_LEN];
            if let Some(tag) = point.first_mut() {
                *tag = UNCOMPRESSED;
            }
            point
        }

        fn sign(&self, message: &[u8]) -> Option<[u8; SIGNATURE_LEN]> {
            Some(digest_twice(message))
        }
    }

    fn digest_twice(message: &[u8]) -> [u8; SIGNATURE_LEN] {
        let digest = Sha256::digest(message);
        let mut out = [0u8; SIGNATURE_LEN];
        for (into, byte) in out.iter_mut().zip(digest.iter().chain(digest.iter())) {
            *into = *byte;
        }
        out
    }
}

/// A node judged for a sealed command: `node` itself, with a monitor that admits the command
/// through `admission` (decision D17). Every effect and read is the node's own.
pub struct SealedNode<'n, N: ?Sized> {
    node: &'n N,
    admission: &'n dyn Admission,
}

impl<'n, N: ?Sized> SealedNode<'n, N> {
    /// `node`, its monitor admitting through `admission`.
    pub fn new(node: &'n N, admission: &'n dyn Admission) -> Self {
        Self { node, admission }
    }
}

impl<N: LifecycleNode + ?Sized> LifecycleNode for SealedNode<'_, N> {
    fn binds(&self, verb: Verb) -> bool {
        self.node.binds(verb)
    }

    fn monitor(&self) -> Monitor<'_> {
        self.node.monitor().with_admission(self.admission)
    }

    fn open(&self, peer: &Zid, mode: OpenMode) -> OpenOutcome {
        self.node.open(peer, mode)
    }

    fn withdraw(&self, peer: &Zid) {
        self.node.withdraw(peer);
    }

    fn order_close(&self, peer: &Zid) -> CloseOrder {
        self.node.order_close(peer)
    }

    fn take_generation(&self, peer: &Zid, generation: u64) -> Generation {
        self.node.take_generation(peer, generation)
    }

    fn links(&self, peer: &Zid) -> SessionLinks {
        self.node.links(peer)
    }

    fn read_machines(&self, peer: &Zid, read: &mut dyn FnMut(&[MachineReport<'_>])) {
        self.node.read_machines(peer, read);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text_out::FixedText;

    fn document(refused: SealRefused) -> FixedText<256> {
        let mut out = FixedText::new();
        refused.write_json(&mut out);
        out
    }

    /// A refusal is the lifecycle verbs' refusal document, with the last counter beside a replay
    /// and the echo's bytes in order, two lowercase hex digits each, beside its challenge.
    #[test]
    fn a_refusal_is_the_verbs_refusal_document_with_what_the_commander_needs() {
        assert_eq!(
            document(SealRefused::NotVerified).prefix(),
            "{\"verdict\":\"refused\",\"reason\":\"this node verifies no sealed command\"}"
        );
        assert_eq!(
            document(SealRefused::Replay { last: 41 }).prefix(),
            "{\"verdict\":\"refused\",\"reason\":\"the counter of the sealed command is not \
             above its commander's last\",\"last\":41}"
        );
        let mut echo = [0u8; ECHO_BYTES];
        for (at, byte) in (0u8..).zip(echo.iter_mut()) {
            *byte = at * 17;
        }
        assert_eq!(
            document(SealRefused::EchoRequired { echo }).prefix(),
            "{\"verdict\":\"refused\",\"reason\":\"the sealed command must carry this node's \
             echo\",\"echo\":\"00112233445566778899aabbccddeeff\"}"
        );
    }

    /// No attachment is the link's commander; an attachment with no verifier to open it is
    /// refused, whichever build this is.
    #[test]
    fn an_attachment_with_no_verifier_is_refused_and_none_is_the_channel() {
        let command = Command::Close { peer: "c3d4" };
        assert!(matches!(claim(None, &command, None), Claimed::Channel));
        assert!(matches!(
            claim(Some(&[0xd2, 0x84]), &command, None),
            Claimed::Refused(SealRefused::NotVerified)
        ));
    }
}
